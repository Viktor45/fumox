//! Public subscription endpoints.
//!
//! `GET /sub/{token|slug}` serves a profile, `GET /src/{token|slug}` a
//! single source. Output format is fixed by the profile (`?format=` is
//! forbidden); only 200 responses are cached, and the full
//! outcome table is implemented:
//!
//! - recoverable source errors (`network`, `http_server`) → serve the DB
//!   snapshot as stale + `X-Fumox-Stale: true`, no cutoff;
//! - unrecoverable `http_client` → the upstream status code, not cached;
//! - `parse_error` → stale snapshot or empty output + `X-Fumox-Warning:
//!   parse-error`;
//! - every proxy quarantined/removed → empty valid output +
//!   `X-Fumox-Warning: all-proxies-quarantined`.

use crate::admin::auth::RateLimiter;
use crate::admin::fmt_rfc3339_utc;
use crate::cache::{Caches, InlineClaim, InlineOutcome, Rendered};
use crate::pipeline::{self, Candidate, CompiledPipeline, PipelineIssue};
use axum::Router;
use axum::body::Body;
use axum::extract::{ConnectInfo, Path, Query, Request, State};
use axum::http::{HeaderName, HeaderValue, StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use base64::Engine;
use fumox_core::db::DbPool;
use fumox_core::geo::GeoResolver;
use fumox_core::models::{ErrorClass, OutputFormat, Profile, ProxyStatus, Source};
use fumox_core::repo::{fetch_log, profiles, proxies, sources};
use std::collections::HashMap;
use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

/// Upper bound on how long a rendered subscription body is served from the
/// processed cache as fresh, in seconds.
///
/// A source TTL answers a different question: how often to re-download the
/// upstream feed, and the admin form accepts up to a day. Health is owned by
/// another process: `fumox-probe` moves rows between tiers, and the server
/// only hears about it when the next ingest invalidates the rendering. Left
/// unbounded, a node the probe just retired keeps being served for a whole
/// TTL. The window is therefore fixed and short, the same reasoning (and the
/// same value) as `alive_export::EXPORT_TTL_SECS`: long enough to collapse a
/// burst of client downloads into one render, far shorter than a probe cycle.
/// A stale entry is still served immediately (stale-while-revalidate), so
/// this costs one background re-render per window, never a 5xx.
const RENDER_FRESHNESS_CAP_SECS: i64 = 30;

/// Deadline for one inline (cache-miss) render, and the same deadline a
/// waiter gives the leader it is waiting behind. Generous next to a real
/// render (milliseconds on a warm database) and short enough that a render
/// wedged on the write lock answers instead of holding every request for
/// that key open.
const WAIT_FOR_LEADER: Duration = Duration::from_secs(30);

/// Shared state of the public listener.
#[derive(Clone)]
pub struct AppState {
    pub pool: DbPool,
    pub caches: Caches,
    pub geo: Arc<GeoResolver>,
    /// Public-listener rate limiters (`[server].rate_limit` /
    /// `[server].auth_fail_rate_limit`).
    pub limits: PublicRateLimits,
    /// CIDRs of reverse proxies whose `X-Forwarded-For` / RFC 7239 `Forwarded:
    /// for=…` are honored for the per-IP rate-limit key. Empty = never honor
    /// forwarded headers (any caller can otherwise spoof the key).
    pub trusted_cidrs: Vec<ipnet::IpNet>,
    /// Hostnames / IPs allowed to reach the public listener. Empty = accept
    /// any host (today's behavior); setting this locks the alive-export
    /// endpoint to the operator's own hostname.
    pub allowed_hosts: Vec<String>,
    /// Row ceiling of one `/export/alive` / `/export/ready` body
    /// (`[server].export_max_rows`). The two links have no upstream cap of
    /// their own, so this is the only thing bounding one public request.
    pub export_max_rows: u32,
}

/// Per-IP rate limiters of the public listener: a generous ceiling for
/// every request and a strict one for failed access-token checks (HTTP
/// 403), the brute-force signal for protected profiles.
#[derive(Clone)]
pub struct PublicRateLimits {
    all: Arc<RateLimiter>,
    auth_failures: Arc<RateLimiter>,
}

impl PublicRateLimits {
    pub(crate) fn new(all: u64, auth_failures: u64) -> Self {
        let window = Duration::from_secs(60);
        Self {
            all: Arc::new(RateLimiter::new(all, window)),
            auth_failures: Arc::new(RateLimiter::new(auth_failures, window)),
        }
    }

    /// Build from the `[server]` configuration block.
    pub fn from_config(config: &fumox_core::config::ServerConfig) -> Self {
        Self {
            all: Arc::new(RateLimiter::new(
                u64::from(config.rate_limit.limit),
                config.rate_limit.window,
            )),
            auth_failures: Arc::new(RateLimiter::new(
                u64::from(config.auth_fail_rate_limit.limit),
                config.auth_fail_rate_limit.window,
            )),
        }
    }

    /// For paths that never cross the middleware (in-process previews):
    /// counters that can never trip.
    pub fn unlimited() -> Self {
        Self::new(u64::MAX, u64::MAX)
    }
}

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/sub/{id}", get(serve_sub))
        .route("/src/{id}", get(serve_src))
        .route("/export/alive/{token}", get(crate::alive_export::serve))
        .route(
            "/export/ready/{token}",
            get(crate::alive_export::serve_ready),
        )
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            public_rate_limit,
        ))
        .with_state(state)
}

/// The complete public application: the subscription surface plus the
/// liveness endpoint.
///
/// `/healthz` is added *after* the rate-limit layer on purpose: an
/// exhausted public window must not make an orchestrator's probe answer
/// 429 and restart a healthy instance. Kept as one function so the
/// layering is testable without binding listeners.
/// `health_pool` is a pool reserved for `/healthz` alone, not the render
/// pool. The liveness answer must not depend on render load: a saturated
/// pool is this process's own load, and an orchestrator reads 503 as
/// "restart me", so sharing the pool turns a busy minute into a restart
/// loop. The dedicated pool holds one connection and is only ever asked
/// `SELECT 1`.
pub fn public_app(state: AppState, health_pool: DbPool) -> Router {
    router(state).route(
        "/healthz",
        get(move || {
            let pool = health_pool.clone();
            async move { healthz(pool).await }
        }),
    )
}

/// Liveness probe: 200 while the database answers a trivial query, 503
/// once it does not. Deliberately shallow: a stalled scheduler or a quiet
/// pool is not process liveness, an unwritable or unreachable database is
/// the one dependency the whole surface shares. The scheduler's own
/// liveness is recorded under `meta.server_cycle` for the admin panel.
///
/// A short acquire timeout, because this answer is read by an
/// orchestrator that restarts the instance on 503. Waiting out sqlx's
/// default 30 s to then say "unavailable" is the worst of both: the probe
/// is what a restart is triggered by, so it must distinguish "the database
/// is gone" from "the render pool is busy", and the busy case is this
/// process's own load, not a fault worth restarting over.
async fn healthz(pool: DbPool) -> Response {
    const ACQUIRE_TIMEOUT: Duration = Duration::from_secs(2);
    match tokio::time::timeout(ACQUIRE_TIMEOUT, sqlx::query("SELECT 1").fetch_one(&pool)).await {
        Ok(Ok(_)) => (StatusCode::OK, "ok\n").into_response(),
        Ok(Err(error)) => {
            tracing::error!(error = %error, "/healthz database check failed");
            (StatusCode::SERVICE_UNAVAILABLE, "database unavailable\n").into_response()
        }
        Err(_) => {
            tracing::warn!(
                timeout_secs = ACQUIRE_TIMEOUT.as_secs(),
                "/healthz gave up waiting for a pool connection; \
                 reporting the instance busy rather than down"
            );
            (StatusCode::SERVICE_UNAVAILABLE, "database busy\n").into_response()
        }
    }
}

/// Per-IP limiting: every request counts against `[server].rate_limit`, a 403
/// additionally against `[server].auth_fail_rate_limit`, and an exhausted
/// window answers 429. Requests without `ConnectInfo<SocketAddr>` pass
/// uncounted.
async fn public_rate_limit(State(state): State<AppState>, req: Request, next: Next) -> Response {
    let Some(connect) = req.extensions().get::<ConnectInfo<SocketAddr>>().cloned() else {
        return next.run(req).await;
    };
    let ip =
        crate::admin::auth::client_key(connect.0, req.headers(), &state.trusted_cidrs).to_string();
    if !state.limits.all.allow(&ip).await {
        return error_response(
            StatusCode::TOO_MANY_REQUESTS,
            "too many requests, try again later",
        );
    }
    let response = next.run(req).await;
    if response.status() == StatusCode::FORBIDDEN && !state.limits.auth_failures.allow(&ip).await {
        // The failure window rejected the request, give the hit back to the
        // generous window so one brute-force attempt does not cost the
        // caller two windows.
        state.limits.all.refund(&ip).await;
        return error_response(
            StatusCode::TOO_MANY_REQUESTS,
            "too many failed access attempts, try again later",
        );
    }
    response
}

/// Non-cacheable error reply bubbling up from rendering.
#[derive(Debug)]
struct ErrorReply {
    status: StatusCode,
    message: String,
    /// Whether the cached entry for this key must be dropped when a
    /// background re-render fails this way. True for the unrecoverable
    /// `http_client` outcome (SPEC §10.2: the upstream status code is
    /// served), false when the failure is a transient server-side one where
    /// the last good snapshot is still the best answer.
    drop_cached: bool,
}

impl ErrorReply {
    fn internal(err: impl std::fmt::Display) -> Self {
        tracing::error!(error = %err, "serving failed");
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            message: "internal server error".to_string(),
            drop_cached: false,
        }
    }

    /// A corrupted pipeline config should be impossible (validated at save
    /// time); if it happens anyway, report it as a server error.
    fn corrupted_pipeline(target: &str, errors: &[PipelineIssue]) -> Self {
        tracing::error!(target, errors = ?errors, "stored pipeline config failed validation");
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            message: "internal server error".to_string(),
            drop_cached: false,
        }
    }

    /// The source answered with an unrecoverable client error: the upstream
    /// status is the answer, and a cached snapshot must not keep masking it.
    fn upstream_unavailable(status: StatusCode, message: String) -> Self {
        Self {
            status,
            message,
            drop_cached: true,
        }
    }
}

async fn serve_sub(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Query(params): Query<HashMap<String, String>>,
    headers: axum::http::HeaderMap,
) -> Response {
    if params.contains_key("format") {
        return error_response(
            StatusCode::BAD_REQUEST,
            "the ?format= parameter is not supported: the output format is fixed by the profile",
        );
    }
    let profile = match profiles::resolve_token(&state.pool, &id).await {
        Ok(Some(profile)) => profile,
        Ok(None) => return error_response(StatusCode::NOT_FOUND, "profile not found"),
        Err(err) => {
            tracing::error!(error = %err, "profile lookup failed");
            return error_response(StatusCode::INTERNAL_SERVER_ERROR, "internal server error");
        }
    };
    if !profile.enabled {
        return error_response(StatusCode::NOT_FOUND, "profile not found");
    }
    // Optional per-profile access token: query parameter or
    // Authorization: Bearer. NULL means the endpoint is public.
    if let Some(required) = &profile.access_token {
        let provided = params
            .get("token")
            .cloned()
            .or_else(|| bearer_token(&headers));
        // Constant-time comparison: the token is a secret checked on the
        // public listener.
        let ok = provided
            .as_deref()
            .is_some_and(|provided| crate::admin::auth::ct_eq(provided, required));
        if !ok {
            return error_response(StatusCode::FORBIDDEN, "access token is missing or invalid");
        }
    }

    let key = format!("sub:{}", profile.id);
    let render_state = state.clone();
    let render_profile = profile.clone();
    let sources_state = state.clone();
    let sources_profile = profile.clone();
    serve_cached(
        &state,
        key,
        move || {
            let state = sources_state.clone();
            let profile = sources_profile.clone();
            async move { member_source_ids(&state, &profile.id).await }
        },
        move || {
            let state = render_state.clone();
            let profile = render_profile.clone();
            async move { render_sub(&state, &profile).await }
        },
    )
    .await
}

async fn serve_src(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Query(params): Query<HashMap<String, String>>,
) -> Response {
    if params.contains_key("format") {
        return error_response(
            StatusCode::BAD_REQUEST,
            "the ?format= parameter is not supported",
        );
    }
    let source = match sources::resolve_token(&state.pool, &id).await {
        Ok(Some(source)) => source,
        Ok(None) => return error_response(StatusCode::NOT_FOUND, "source not found"),
        Err(err) => {
            tracing::error!(error = %err, "source lookup failed");
            return error_response(StatusCode::INTERNAL_SERVER_ERROR, "internal server error");
        }
    };
    if !source.enabled {
        return error_response(StatusCode::NOT_FOUND, "source not found");
    }

    let key = format!("src:{}", source.id);
    let render_state = state.clone();
    let render_source = source.clone();
    let source_id = source.id.clone();
    serve_cached(
        &state,
        key,
        move || {
            let source_id = source_id.clone();
            async move { vec![source_id] }
        },
        move || {
            let state = render_state.clone();
            let source = render_source.clone();
            async move { render_src(&state, &source).await }
        },
    )
    .await
}

/// Source ids a profile's rendering can draw from, used to scope the cache's
/// generation bookkeeping for a cold render (see
/// [`Caches::begin_inline_render`]). A superset of what the render actually
/// touches is fine: the render skips disabled or vanished members itself.
///
/// Only consulted on a cache miss: the resolution is a second, indexed read
/// that a cache hit never pays.
async fn member_source_ids(state: &AppState, profile_id: &str) -> Vec<String> {
    match profiles::get_sources(&state.pool, profile_id).await {
        Ok(links) => links.into_iter().map(|(source_id, _)| source_id).collect(),
        Err(err) => {
            // The render itself is about to read the same table and will
            // fail with the same error; nothing is stored either way.
            tracing::error!(error = %err, "profile members lookup failed");
            Vec::new()
        }
    }
}

/// Cache lookup with stale-while-revalidate: a fresh entry is
/// served as-is; a stale one is served immediately while a background
/// re-render refreshes the entry; a miss renders inline, single-flighted
/// through the cache's inline-render claim. Only 200 responses are stored.
async fn serve_cached<F, Fut, S, SFut>(
    state: &AppState,
    key: String,
    key_sources: S,
    make_render: F,
) -> Response
where
    F: Fn() -> Fut + Send + 'static,
    Fut: Future<Output = Result<Rendered, ErrorReply>> + Send + 'static,
    // `key_sources`: the sources the render draws from, resolved on the cold
    // path only. The inline-render claim is scoped to them, so an ingest of
    // an unrelated source cannot refuse this key's put.
    S: FnOnce() -> SFut,
    SFut: Future<Output = Vec<String>>,
{
    let now = fumox_core::models::now_ts();
    if let Some(rendered) = state.caches.processed_get(&key).await {
        if rendered.is_fresh(now) {
            return to_response(&rendered);
        }
        if let Some(claim) = state.caches.try_start_revalidate(&key).await {
            let state = state.clone();
            let key = key.clone();
            let generation = claim.generation();
            tokio::spawn(async move {
                // The claim is released when `claim` drops, panic included.
                let _claim = claim;
                match make_render().await {
                    Ok(rendered) => {
                        // An invalidation that landed while this render ran
                        // supersedes it: storing pre-change data with a full
                        // TTL would resurrect the very staleness the
                        // invalidation ended.
                        if state
                            .caches
                            .processed_put_guarded(&key, Arc::new(rendered), generation)
                            .await
                            .is_none()
                        {
                            tracing::debug!(
                                key = %key,
                                "revalidation result dropped: the key was invalidated while rendering"
                            );
                        }
                    }
                    Err(err) => {
                        // An unrecoverable upstream answer is the endpoint's
                        // answer now: drop the snapshot so the next request
                        // re-renders and returns the upstream status instead
                        // of the last good body with frozen headers.
                        if err.drop_cached {
                            state.caches.processed_invalidate(&key).await;
                        }
                        tracing::warn!(key = %key, status = %err.status, "revalidation failed");
                    }
                }
            });
        }
        return to_response(&rendered);
    }

    // Cold key: claim the render so a burst of requests on a
    // just-invalidated key runs one render instead of one per request.
    // The leader renders; a waiter wakes when the leader's claim ends and
    // serves the stored entry, claiming its own render only when the
    // leader stored none. A leader that *failed* publishes the failure, so
    // a broken upstream costs one render rather than one per waiter.
    // Claiming before rendering stays mandatory for the same reason as
    // before: this key has no entry, so without the claim an invalidation
    // landing now would not see it and the put below would store
    // pre-change rows as fresh for a full TTL.
    //
    // The claim's sources are resolved once, here: the waiter loop can run
    // several times and the lookup is a database query.
    let claim_sources = key_sources().await;
    let claim = loop {
        match state
            .caches
            .begin_inline_render(&key, claim_sources.clone())
            .await
        {
            InlineClaim::Leader(claim) => break claim,
            InlineClaim::Wait(mut ended) => {
                // The leader's guard drop is the wake-up. The channel then
                // carries what the leader did, and keeps it after the
                // close, so a wake on close still reads the verdict.
                if tokio::time::timeout(WAIT_FOR_LEADER, ended.changed())
                    .await
                    .is_err()
                {
                    // A leader this slow is wedged (blocked on the write
                    // lock, say). Answering beats parking the connection
                    // for as long as the leader lives.
                    tracing::warn!(key = %key, "inline render leader did not finish in time");
                    return error_response(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "render in progress, try again",
                    );
                }
                match ended.borrow_and_update().clone() {
                    InlineOutcome::Failed { status, message } => {
                        return error_response(
                            StatusCode::from_u16(status).unwrap_or(StatusCode::BAD_GATEWAY),
                            &message,
                        );
                    }
                    InlineOutcome::Stored => {}
                }
                if let Some(rendered) = state.caches.processed_get(&key).await
                    && rendered.is_fresh(fumox_core::models::now_ts())
                {
                    return to_response(&rendered);
                }
            }
        }
    };
    let generation = claim.generation();
    // The leader gets the same deadline as its waiters: without one it can
    // hold the claim (and every waiter behind it) for as long as the render
    // blocks.
    let rendered = match tokio::time::timeout(WAIT_FOR_LEADER, make_render()).await {
        Ok(Ok(rendered)) => rendered,
        Ok(Err(err)) => {
            claim.fail(err.status.as_u16(), err.message.clone());
            drop(claim);
            return error_response(err.status, &err.message);
        }
        Err(_) => {
            claim.fail(
                StatusCode::SERVICE_UNAVAILABLE.as_u16(),
                "render timed out".to_string(),
            );
            drop(claim);
            return error_response(StatusCode::SERVICE_UNAVAILABLE, "render timed out");
        }
    };
    let rendered = Arc::new(rendered);
    let cached = if rendered.status == 200 {
        let stored = state
            .caches
            .processed_put_guarded(&key, rendered.clone(), generation)
            .await;
        if stored.is_none() {
            tracing::debug!(
                key = %key,
                "inline render not cached: the key was invalidated while rendering"
            );
        }
        stored
    } else {
        None
    };
    drop(claim);
    to_response(cached.as_ref().unwrap_or(&rendered))
}

/// Render a profile: per-source merged pipelines (each capped by its own
/// `limit.count`) → merge → dedup → sort → profile-level cap → encode,
/// with the serving outcome policy.
async fn render_sub(state: &AppState, profile: &Profile) -> Result<Rendered, ErrorReply> {
    let links = profiles::get_sources(&state.pool, &profile.id)
        .await
        .map_err(ErrorReply::internal)?;

    // Load member sources in profile order; disabled or vanished sources
    // drop out of the output.
    let mut members: Vec<(Source, CompiledPipeline)> = Vec::new();
    for (source_id, _position) in links {
        let Some(source) = sources::get(&state.pool, &source_id)
            .await
            .map_err(ErrorReply::internal)?
        else {
            continue;
        };
        if !source.enabled {
            continue;
        }
        let merged = pipeline::merge_configs(source.pipeline.as_ref(), profile.pipeline.as_ref());
        let compiled = CompiledPipeline::from_json(merged.as_ref()).map_err(|errors| {
            ErrorReply::corrupted_pipeline(&format!("sub:{}", profile.id), &errors)
        })?;
        members.push((source, compiled));
    }

    // An unrecoverable source error short-circuits the whole profile to
    // the upstream status code, not cached.
    for (source, _) in &members {
        if source.error_class == Some(ErrorClass::HttpClient) {
            let upstream = last_http_status(state, &source.id).await.unwrap_or(502);
            return Err(ErrorReply::upstream_unavailable(
                StatusCode::from_u16(upstream).unwrap_or(StatusCode::BAD_GATEWAY),
                format!(
                    "source \"{}\" unavailable: {}",
                    source.name,
                    source.last_error.as_deref().unwrap_or("HTTP client error")
                ),
            ));
        }
    }

    let profile_pipeline =
        CompiledPipeline::from_json(profile.pipeline.as_ref()).map_err(|errors| {
            ErrorReply::corrupted_pipeline(&format!("sub:{}", profile.id), &errors)
        })?;

    let source_ids: Vec<String> = members.iter().map(|(s, _)| s.id.clone()).collect();
    let rows = proxies::list_with_source(&state.pool, &source_ids)
        .await
        .map_err(ErrorReply::internal)?;
    let mut by_source: HashMap<String, Vec<proxies::ProxyRow>> = HashMap::new();
    for linked in rows {
        by_source
            .entry(linked.source_id)
            .or_default()
            .push(linked.proxy);
    }

    // Profile-level country allowlist: when the profile lists
    // countries, only proxies whose stored geo fact matches are served.
    // Proxies without a determined country stay out while the filter is
    // active, "only these countries" means confirmed facts, not guesses.
    let allowed_countries: Option<std::collections::HashSet<String>> =
        if profile.countries.is_empty() {
            None
        } else {
            Some(
                profile
                    .countries
                    .iter()
                    .map(|code| code.trim().to_ascii_uppercase())
                    .filter(|code| !code.is_empty())
                    .collect(),
            )
        };

    let mut all: Vec<Candidate> = Vec::new();
    let mut loaded_statuses: Vec<ProxyStatus> = Vec::new();
    let mut any_stale = false;
    let mut any_parse_error = false;

    for (position, (source, compiled)) in members.iter().enumerate() {
        match source.error_class {
            None => {}
            Some(ErrorClass::Network) | Some(ErrorClass::HttpServer) => any_stale = true,
            Some(ErrorClass::ParseError) => any_parse_error = true,
            Some(ErrorClass::HttpClient) => unreachable!("handled above"),
        }
        let rows = by_source.remove(&source.id).unwrap_or_default();
        let mut candidates = rows_to_candidates(rows, position as i64);
        if let Some(allowed) = &allowed_countries {
            candidates.retain(|c| {
                c.geo_country
                    .as_deref()
                    .is_some_and(|code| allowed.contains(&code.to_ascii_uppercase()))
            });
        }
        loaded_statuses.extend(candidates.iter().map(|c| c.status));
        // Full per-source run, not just the per-source steps: the source's
        // own `limit.count` caps that source's contribution, and the
        // profile-level cap is applied again to the merged list below.
        // Running the cap only in the sort-winning `finalize` would make a
        // source's limit conditional on that same source also setting an
        // explicit `sort`, while `/src` (one source, one `apply`) always
        // honoured it.
        all.extend(compiled.apply(candidates, &state.geo).await);
    }
    // "All proxies quarantined/removed" verdict: the profile
    // does hold proxies, but every one of them was dropped by a health
    // filter. Only the two hidden tiers count: `ready` is a served tier, a
    // verified proxy is not part of the "everything is hidden" story (and
    // neither is a proxy a `filter`/ASN/drop rule removed, which is a
    // configuration fact the operator reads in the pipeline, not a health
    // one).
    let all_quarantined = !loaded_statuses.is_empty()
        && all.is_empty()
        && loaded_statuses
            .iter()
            .all(|status| matches!(status, ProxyStatus::Quarantine | ProxyStatus::Removed));

    // Global sort: the profile's explicit `sort` wins, otherwise the first
    // source (in profile order) that set one, otherwise source order.
    let source_sort = members
        .iter()
        .find(|(_, compiled)| compiled.sort_explicit)
        .map(|(source, _)| source)
        .filter(|_| !profile_pipeline.sort_explicit)
        .and_then(|source| source.pipeline.as_ref())
        .and_then(|pipeline| pipeline.get("sort"))
        .cloned();
    // The post-merge step runs with the profile's own pipeline, plus that
    // sort section: `finalize` caps the list it is given, and a cap that
    // reached the merged list from a *source* pipeline would truncate every
    // other source's proxies too. Each source's cap was already applied to
    // that source's own contribution by `apply` above.
    let finalizer = CompiledPipeline::from_json(
        finalize_config(profile.pipeline.as_ref(), source_sort).as_ref(),
    )
    .map_err(|errors| ErrorReply::corrupted_pipeline(&format!("sub:{}", profile.id), &errors))?;
    finalizer.finalize(&mut all);

    // The metadata block goes only into plain uri_list output: base64 blobs
    // must stay decodable to a bare list (the block would double-encode as
    // base64 text), and structured formats have their own document shape.
    let interval_hours: u64 = update_interval_hours(&members).parse().unwrap_or(1);
    let (body, content_type) = encode(&all, profile.output_format, || {
        url_list_header_block(&profile.name, interval_hours, all.len())
    });

    let mut extra_headers: Vec<(String, String)> = vec![
        ("profile-title".to_string(), profile.name.clone()),
        (
            "profile-update-interval".to_string(),
            update_interval_hours(&members),
        ),
    ];
    if any_stale {
        extra_headers.push(("X-Fumox-Stale".to_string(), "true".to_string()));
    }
    if any_parse_error {
        extra_headers.push(("X-Fumox-Warning".to_string(), "parse-error".to_string()));
    } else if all_quarantined {
        extra_headers.push((
            "X-Fumox-Warning".to_string(),
            "all-proxies-quarantined".to_string(),
        ));
    }

    let min_ttl = members
        .iter()
        .map(|(s, _)| s.cache_ttl_seconds)
        .min()
        .unwrap_or(60)
        .max(1);
    Ok(Rendered {
        status: 200,
        body: body.into(),
        content_type,
        extra_headers,
        fresh_until: fumox_core::models::now_ts() + min_ttl.min(RENDER_FRESHNESS_CAP_SECS),
        source_ids,
    })
}

/// Render a single source for `/src/{id}`: the source's own pipeline,
/// always the plain URI-list format.
async fn render_src(state: &AppState, source: &Source) -> Result<Rendered, ErrorReply> {
    if source.error_class == Some(ErrorClass::HttpClient) {
        let upstream = last_http_status(state, &source.id).await.unwrap_or(502);
        return Err(ErrorReply::upstream_unavailable(
            StatusCode::from_u16(upstream).unwrap_or(StatusCode::BAD_GATEWAY),
            format!(
                "source \"{}\" unavailable: {}",
                source.name,
                source.last_error.as_deref().unwrap_or("HTTP client error")
            ),
        ));
    }

    let compiled = CompiledPipeline::from_json(source.pipeline.as_ref())
        .map_err(|errors| ErrorReply::corrupted_pipeline(&format!("src:{}", source.id), &errors))?;

    let rows = proxies::list_with_source(&state.pool, std::slice::from_ref(&source.id))
        .await
        .map_err(ErrorReply::internal)?;
    let mut candidates =
        rows_to_candidates(rows.into_iter().map(|linked| linked.proxy).collect(), 0);
    // /src serves only health-checked, currently-live proxies: rows that
    // were never probed (unknown), quarantined or removed stay out even
    // when the pipeline's health filter would let them through. `ready`
    // (the tunnel-verified tier) is a live tier too, a verified proxy
    // must not vanish from client output the
    // moment T2 promotes it.
    candidates.retain(|c| matches!(c.status, ProxyStatus::Alive | ProxyStatus::Ready));
    let out = compiled.apply(candidates, &state.geo).await;

    // Same ttl-derived interval rule as the sub profile: whole hours
    // rounded up from the source TTL, at least 1.
    let interval_hours = (source.cache_ttl_seconds.max(1) + 3599) / 3600;
    let (body, content_type) = encode(&out, OutputFormat::UriList, || {
        url_list_header_block(&source.name, interval_hours as u64, out.len())
    });

    let mut extra_headers: Vec<(String, String)> = Vec::new();
    match source.error_class {
        None => {}
        Some(ErrorClass::Network) | Some(ErrorClass::HttpServer) => {
            extra_headers.push(("X-Fumox-Stale".to_string(), "true".to_string()));
        }
        Some(ErrorClass::ParseError) => {
            extra_headers.push(("X-Fumox-Warning".to_string(), "parse-error".to_string()));
        }
        Some(ErrorClass::HttpClient) => unreachable!("handled above"),
    }

    Ok(Rendered {
        status: 200,
        body: body.into(),
        content_type,
        extra_headers,
        fresh_until: fumox_core::models::now_ts()
            + source.cache_ttl_seconds.clamp(1, RENDER_FRESHNESS_CAP_SECS),
        source_ids: vec![source.id.clone()],
    })
}

/// In-process preview of a profile's output for the admin card ,
/// renders exactly what `/sub` would serve, without an
/// HTTP round trip to self, and returns the first `max_lines` lines.
/// Base64 output is decoded so the preview stays readable.
pub(crate) async fn preview_sub(
    state: &AppState,
    profile: &Profile,
    max_lines: usize,
) -> Result<Vec<String>, String> {
    let rendered = render_sub(state, profile).await.map_err(|e| e.message)?;
    let text = if profile.output_format == OutputFormat::Base64 {
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(&rendered.body)
            .unwrap_or_else(|_| rendered.body.to_vec());
        String::from_utf8_lossy(&decoded).into_owned()
    } else {
        String::from_utf8_lossy(&rendered.body).into_owned()
    };
    Ok(text.lines().take(max_lines).map(str::to_string).collect())
}

/// Map DB rows to pipeline candidates; corrupt rows are logged and skipped
/// (errors never abort a rendering).
fn rows_to_candidates(rows: Vec<proxies::ProxyRow>, source_position: i64) -> Vec<Candidate> {
    let mut candidates = Vec::with_capacity(rows.len());
    for row in rows {
        let entry = match row.to_entry() {
            Ok(entry) => entry,
            Err(err) => {
                tracing::warn!(proxy_id = row.id, error = %err, "skipping corrupt proxy row");
                continue;
            }
        };
        let status = match row.status.parse::<ProxyStatus>() {
            Ok(status) => status,
            Err(err) => {
                tracing::warn!(proxy_id = row.id, error = %err, "skipping proxy with unknown status");
                continue;
            }
        };
        candidates.push(Candidate {
            entry,
            source_position,
            status,
            latency_ms: row.latency_ms,
            geo_country: row.geo_country.clone(),
            geo_asn: row.geo_asn.clone(),
        });
    }
    candidates
}

/// Serialize candidates into the profile's output format. The
/// `header_block` closure supplies the url_list metadata comments; it is
/// only invoked (and only prepended) for the plain uri_list format.
fn encode(
    candidates: &[Candidate],
    format: OutputFormat,
    mut header_block: impl FnMut() -> String,
) -> (Vec<u8>, String) {
    match format {
        OutputFormat::UriList => {
            // The block already ends with a newline; empty candidate lists
            // yield just the block itself (with `nodes count: 0`).
            let body = match header_block() {
                block if block.is_empty() => uri_lines(candidates),
                block => format!("{block}{}", uri_lines(candidates)),
            };
            (body.into_bytes(), "text/plain; charset=utf-8".to_string())
        }
        OutputFormat::Base64 => (
            base64::engine::general_purpose::STANDARD
                .encode(uri_lines(candidates).as_bytes())
                .into_bytes(),
            "text/plain; charset=utf-8".to_string(),
        ),
        OutputFormat::Clash => {
            let entries: Vec<fumox_core::models::ProxyEntry> =
                candidates.iter().map(|c| c.entry.clone()).collect();
            (
                fumox_core::formats::clash::encode_clash(&entries).into_bytes(),
                "text/yaml; charset=utf-8".to_string(),
            )
        }
        OutputFormat::SingBox => {
            let entries: Vec<fumox_core::models::ProxyEntry> =
                candidates.iter().map(|c| c.entry.clone()).collect();
            (
                fumox_core::formats::singbox::encode_singbox(&entries).into_bytes(),
                "application/json; charset=utf-8".to_string(),
            )
        }
    }
}

/// Canonical URI lines, one per candidate (input of uri_list/base64 output).
fn uri_lines(candidates: &[Candidate]) -> String {
    let mut lines: Vec<String> = Vec::with_capacity(candidates.len());
    for candidate in candidates {
        lines.push(fumox_core::parsers::serialize(&candidate.entry));
    }
    lines.join("\n")
}

/// Metadata header block prefixed to every plain url_list output (`/sub`
/// with uri_list format, `/src`, the alive export): the HTTP headers
/// `profile-title`/`profile-update-interval` carry the same facts, but a
/// copy-pasted or downloaded file loses them, the comment lines survive.
/// Key names follow the de-facto subscription-header convention (mihomo,
/// Stash, subconverter); URI-list parsers skip `#` lines, so the block is
/// inert for clients (and for another fumox consuming it as a source).
pub(crate) fn url_list_header_block(title: &str, interval_hours: u64, count: usize) -> String {
    // Title comes from a user-editable name: kill newlines so a crafted
    // name cannot inject forged comment lines into the output.
    let title = title.replace(['\n', '\r'], " ");
    let timestamp = fmt_rfc3339_utc(fumox_core::models::now_ts());
    format!(
        "# profile-title: {title}\n\
         # profile-update-interval: {interval_hours}\n\
         # nodes count: {count}\n\
         # generated by: fumox {} at {timestamp}\n",
        env!("CARGO_PKG_VERSION"),
    )
}

/// The pipeline config the merged-list `finalize` step runs with: the
/// profile's own config, plus the `sort` section of the source that won the
/// sort contest when the profile does not set one.
///
/// Rebuilt from JSON rather than reusing the winning source's compiled
/// pipeline: `finalize` dedups, sorts *and* applies `limit.count`, and a
/// source's cap must bound that source's own contribution (applied by
/// `apply` per source), not the whole merged profile. The remaining sections
/// are inert in `finalize`.
fn finalize_config(
    profile_pipeline: Option<&serde_json::Value>,
    source_sort: Option<serde_json::Value>,
) -> Option<serde_json::Value> {
    // The profile's config was already validated above (`profile_pipeline`),
    // so it is either absent, `null` or an object here.
    let mut config = match profile_pipeline {
        None | Some(serde_json::Value::Null) => serde_json::json!({ "version": 1 }),
        Some(value) => value.clone(),
    };
    if let Some(sort) = source_sort
        && let Some(map) = config.as_object_mut()
    {
        map.insert("sort".to_string(), sort);
    }
    Some(config)
}

/// `profile-update-interval` in whole hours (mihomo convention), rounded
/// up from the shortest member-source TTL, at least 1.
fn update_interval_hours(members: &[(Source, CompiledPipeline)]) -> String {
    let min_ttl = members
        .iter()
        .map(|(s, _)| s.cache_ttl_seconds)
        .min()
        .unwrap_or(3600)
        .max(1);
    // Whole hours rounded up, at least one.
    let hours = (min_ttl + 3599) / 3600;
    hours.to_string()
}

/// The upstream HTTP status of the source's latest fetch attempt, for the
/// "return the original code" policy.
async fn last_http_status(state: &AppState, source_id: &str) -> Option<u16> {
    let rows = fetch_log::recent_for_source(&state.pool, source_id, 1)
        .await
        .ok()?;
    let status = rows.first()?.http_status?;
    u16::try_from(status).ok()
}

fn bearer_token(headers: &axum::http::HeaderMap) -> Option<String> {
    let value = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    value.strip_prefix("Bearer ").map(str::to_string)
}

pub(crate) fn to_response(rendered: &Rendered) -> Response {
    let mut response = (
        StatusCode::from_u16(rendered.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
        Body::from(rendered.body.clone()),
    )
        .into_response();
    if let Ok(value) = HeaderValue::from_bytes(rendered.content_type.as_bytes()) {
        response.headers_mut().insert(header::CONTENT_TYPE, value);
    }
    for (name, value) in &rendered.extra_headers {
        let (Ok(name), Ok(value)) = (
            HeaderName::from_bytes(name.as_bytes()),
            HeaderValue::from_bytes(value.as_bytes()),
        ) else {
            continue;
        };
        response.headers_mut().insert(name, value);
    }
    response
}

pub(crate) fn error_response(status: StatusCode, message: &str) -> Response {
    (
        status,
        [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
        format!("{message}\n"),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Bytes;
    use axum::http::Request;
    use fumox_core::models::{OutputFormat, Param, ProxyEntry, Scheme};
    use fumox_core::repo::sources::FetchOutcome;
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    async fn test_state() -> AppState {
        state_with_limits(PublicRateLimits::unlimited()).await
    }

    /// A state whose public rate limiters use the given window sizes, with
    /// the backing pool returned so tests can close or probe it directly.
    async fn state_and_pool_with_limits(limits: PublicRateLimits) -> (AppState, DbPool) {
        let dir =
            std::env::temp_dir().join(format!("fumox-serve-test-{}", fumox_core::models::new_id()));
        std::fs::create_dir_all(&dir).unwrap();
        let cfg = fumox_core::config::DatabaseConfig {
            path: dir.join("test.db"),
            ..Default::default()
        };
        let pool = fumox_core::db::connect_pool(&cfg).await.unwrap();
        fumox_core::db::migrate(&pool).await.unwrap();
        let geo_cfg = fumox_core::config::GeoConfig {
            enabled: false,
            ..Default::default()
        };
        (
            AppState {
                pool: pool.clone(),
                caches: Caches::new(),
                geo: Arc::new(GeoResolver::new(&geo_cfg)),
                limits,
                trusted_cidrs: Vec::new(),
                allowed_hosts: Vec::new(),
                export_max_rows: fumox_core::config::ServerConfig::default().export_max_rows,
            },
            pool,
        )
    }

    /// A state whose public rate limiters use the given window sizes.
    async fn state_with_limits(limits: PublicRateLimits) -> AppState {
        state_and_pool_with_limits(limits).await.0
    }

    /// Perform one GET carrying a peer-address extension, the public
    /// rate-limit middleware keys on it. The extension is inserted exactly
    /// the way `into_make_service_with_connect_info` does in production
    /// (`ConnectInfo<SocketAddr>`), so the test fails if the middleware
    /// ever reads the wrong extension type again.
    async fn get_with_ip(app: Router, uri: &str, ip: &str) -> StatusCode {
        let mut request = Request::builder().uri(uri).body(Body::empty()).unwrap();
        request.extensions_mut().insert(ConnectInfo(
            format!("{ip}:1").parse::<SocketAddr>().unwrap(),
        ));
        app.oneshot(request).await.unwrap().status()
    }

    /// Requests without connect info (embedded runtimes) must pass through
    /// uncounted: with a ceiling of 1, three extension-less requests all
    /// reach the handler instead of tripping the limiter.
    #[tokio::test]
    async fn requests_without_connect_info_pass_through_uncounted() {
        let state = state_with_limits(PublicRateLimits::new(1, 1)).await;
        let app = router(state);
        for _ in 0..3 {
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .uri("/sub/missing")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::NOT_FOUND);
        }
    }

    /// `/healthz` sits outside the public rate-limit layer: an exhausted
    /// window must not make an orchestrator's probe answer 429 and restart
    /// a healthy instance.
    #[tokio::test]
    async fn healthz_stays_outside_the_public_rate_limit() {
        let (state, pool) = state_and_pool_with_limits(PublicRateLimits::new(1, 1)).await;
        let app = public_app(state, pool);
        // Exhaust the single-request window from one IP.
        assert_eq!(
            get_with_ip(app.clone(), "/sub/missing", "10.0.0.1").await,
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            get_with_ip(app.clone(), "/sub/missing", "10.0.0.1").await,
            StatusCode::TOO_MANY_REQUESTS
        );
        assert_eq!(
            get_with_ip(app, "/healthz", "10.0.0.1").await,
            StatusCode::OK
        );
    }

    /// The probe reports 503 once the database stops answering; a 200 on a
    /// dead pool would let an orchestrator keep routing traffic here.
    #[tokio::test]
    async fn healthz_goes_red_when_the_database_is_closed() {
        let (state, pool) = state_and_pool_with_limits(PublicRateLimits::unlimited()).await;
        let app = public_app(state, pool.clone());
        assert_eq!(
            get_with_ip(app.clone(), "/healthz", "10.0.0.1").await,
            StatusCode::OK
        );
        pool.close().await;
        assert_eq!(
            get_with_ip(app, "/healthz", "10.0.0.1").await,
            StatusCode::SERVICE_UNAVAILABLE
        );
    }

    /// A cold burst must collapse into one render: the first request claims
    /// the key, the rest wait for its guard and serve the stored entry.
    #[tokio::test]
    async fn concurrent_cold_requests_share_one_render() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let state = test_state().await;
        let renders = Arc::new(AtomicUsize::new(0));
        let mut tasks = tokio::task::JoinSet::new();
        for _ in 0..8 {
            let state = state.clone();
            let renders = renders.clone();
            tasks.spawn(async move {
                let counter = renders;
                serve_cached(
                    &state,
                    "sub:cold-burst".to_string(),
                    || async { Vec::<String>::new() },
                    move || {
                        let counter = counter.clone();
                        async move {
                            counter.fetch_add(1, Ordering::SeqCst);
                            tokio::time::sleep(Duration::from_millis(50)).await;
                            Ok(Rendered {
                                status: 200,
                                body: Bytes::from_static(b"one-body"),
                                content_type: "text/plain".to_string(),
                                extra_headers: Vec::new(),
                                fresh_until: fumox_core::models::now_ts() + 300,
                                source_ids: Vec::new(),
                            })
                        }
                    },
                )
                .await
                .status()
            });
        }
        while let Some(joined) = tasks.join_next().await {
            assert_eq!(joined.unwrap(), StatusCode::OK);
        }
        assert_eq!(
            renders.load(Ordering::SeqCst),
            1,
            "a burst on a missing key must run exactly one render"
        );
    }

    /// A failing cold render must not be retried once per waiter. The
    /// leader publishes its failure, so the burst costs one render and
    /// every request gets the leader's status.
    #[tokio::test]
    async fn a_failing_cold_render_costs_one_attempt_not_one_per_waiter() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let state = test_state().await;
        let renders = Arc::new(AtomicUsize::new(0));
        let mut tasks = tokio::task::JoinSet::new();
        for _ in 0..8 {
            let state = state.clone();
            let renders = renders.clone();
            tasks.spawn(async move {
                let counter = renders;
                serve_cached(
                    &state,
                    "sub:failing-burst".to_string(),
                    || async { Vec::<String>::new() },
                    move || {
                        let counter = counter.clone();
                        async move {
                            counter.fetch_add(1, Ordering::SeqCst);
                            tokio::time::sleep(Duration::from_millis(50)).await;
                            Err(ErrorReply::upstream_unavailable(
                                StatusCode::BAD_GATEWAY,
                                "upstream is down".to_string(),
                            ))
                        }
                    },
                )
                .await
                .status()
            });
        }
        while let Some(joined) = tasks.join_next().await {
            assert_eq!(joined.unwrap(), StatusCode::BAD_GATEWAY);
        }
        assert_eq!(
            renders.load(Ordering::SeqCst),
            1,
            "a failing cold render must be attempted once, not once per waiter"
        );
    }

    #[tokio::test]
    async fn public_rate_limit_caps_requests_per_ip() {
        let state = state_with_limits(PublicRateLimits::new(2, 1_000_000)).await;
        let app = router(state);
        assert_eq!(
            get_with_ip(app.clone(), "/sub/missing", "10.0.0.1").await,
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            get_with_ip(app.clone(), "/sub/missing", "10.0.0.1").await,
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            get_with_ip(app.clone(), "/sub/missing", "10.0.0.1").await,
            StatusCode::TOO_MANY_REQUESTS
        );
        // Another IP has its own window.
        assert_eq!(
            get_with_ip(app, "/sub/missing", "10.0.0.2").await,
            StatusCode::NOT_FOUND
        );
    }

    #[tokio::test]
    async fn failed_access_token_checks_are_limited() {
        let state = state_with_limits(PublicRateLimits::new(1_000_000, 2)).await;
        let profile = make_profile(&state, "profLim000000", &[]).await;
        sqlx::query("UPDATE profiles SET access_token = 'secret' WHERE id = ?")
            .bind(&profile.id)
            .execute(&state.pool)
            .await
            .unwrap();
        let app = router(state);

        let uri = format!("/sub/{}?token=wrong", profile.id);
        assert_eq!(
            get_with_ip(app.clone(), &uri, "10.1.1.1").await,
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            get_with_ip(app.clone(), &uri, "10.1.1.1").await,
            StatusCode::FORBIDDEN
        );
        // The failure window is exhausted: 429 instead of another 403.
        assert_eq!(
            get_with_ip(app.clone(), &uri, "10.1.1.1").await,
            StatusCode::TOO_MANY_REQUESTS
        );
        // A correct token is not a failure and still serves.
        assert_eq!(
            get_with_ip(
                app,
                &format!("/sub/{}?token=secret", profile.id),
                "10.1.1.2"
            )
            .await,
            StatusCode::OK
        );
    }

    /// A 429 from the strict failure window must refund its hit in the
    /// generous window: brute-forcing the token may exhaust the failure
    /// budget, but must not also eat into the plain request ceiling.
    #[tokio::test]
    async fn failure_window_429_does_not_burn_the_generous_window() {
        // both limits are small and equal, so the refund is observable:
        // without it the third request (rejected by the failure window)
        // would have also consumed the third slot of the generous window.
        let state = state_with_limits(PublicRateLimits::new(3, 2)).await;
        let profile = make_profile(&state, "profRef000000", &[]).await;
        sqlx::query("UPDATE profiles SET access_token = 'secret' WHERE id = ?")
            .bind(&profile.id)
            .execute(&state.pool)
            .await
            .unwrap();
        let app = router(state);

        let bad = format!("/sub/{}?token=wrong", profile.id);
        let ok = format!("/sub/{}?token=secret", profile.id);
        // Two failed checks: each counted in both windows, both allowed.
        assert_eq!(
            get_with_ip(app.clone(), &bad, "10.2.2.2").await,
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            get_with_ip(app.clone(), &bad, "10.2.2.2").await,
            StatusCode::FORBIDDEN
        );
        // Third failure: the failure window is done, 429, and the hit it
        // consumed in the generous window comes back.
        assert_eq!(
            get_with_ip(app.clone(), &bad, "10.2.2.2").await,
            StatusCode::TOO_MANY_REQUESTS
        );
        // The generous window still has its slots: a correct token serves.
        assert_eq!(
            get_with_ip(app.clone(), &ok, "10.2.2.2").await,
            StatusCode::OK
        );
    }

    fn entry(name: &str, host: &str, port: u16) -> ProxyEntry {
        ProxyEntry {
            scheme: Scheme::Vless,
            name: name.to_string(),
            host: host.to_string(),
            port,
            credential: "3e4d70e5-7ec9-48f9-a4e0-48c44c6063fd".to_string(),
            params: vec![Param {
                key: "security".to_string(),
                value: "reality".to_string(),
                known: true,
            }],
            raw_path: String::new(),
            raw_line: String::new(),
        }
    }

    async fn make_source(state: &AppState, id: &str) -> Source {
        let now = fumox_core::models::now_ts();
        let source = Source {
            id: id.to_string(),
            slug: None,
            name: format!("source {id}"),
            url: "https://example.com/list".to_string(),
            enabled: true,
            encoding: Default::default(),
            input_format: None,
            protocols: None,
            cache_ttl_seconds: 3600,
            tags: None,
            pipeline: None,
            headers: None,
            ip_family: None,
            created_at: now,
            updated_at: now,
            last_fetched_at: None,
            last_error: None,
            error_class: None,
        };
        sources::create(&state.pool, &source).await.unwrap();
        source
    }

    async fn make_profile(state: &AppState, id: &str, source_ids: &[&str]) -> Profile {
        let now = fumox_core::models::now_ts();
        let profile = Profile {
            id: id.to_string(),
            slug: None,
            access_token: None,
            name: format!("Profile {id}"),
            output_format: Default::default(),
            pipeline: None,
            countries: Vec::new(),
            enabled: true,
            created_at: now,
            updated_at: now,
        };
        profiles::create(&state.pool, &profile).await.unwrap();
        let composition: Vec<(String, i64)> = source_ids
            .iter()
            .enumerate()
            .map(|(idx, source_id)| (source_id.to_string(), idx as i64))
            .collect();
        profiles::set_sources(&state.pool, id, &composition)
            .await
            .unwrap();
        profile
    }

    async fn ingest(state: &AppState, source_id: &str, entries: &[ProxyEntry]) {
        // Test helper: no drop rules anywhere, linger allowed.
        proxies::reconcile_source(
            &state.pool,
            source_id,
            entries,
            &[],
            fumox_core::models::now_ts(),
            true,
        )
        .await
        .unwrap();
    }

    /// Perform one GET and return (status, headers, body text).
    async fn get(app: Router, uri: &str) -> (StatusCode, axum::http::HeaderMap, String) {
        let response = app
            .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
            .await
            .unwrap();
        let status = response.status();
        let headers = response.headers().clone();
        let body = response.into_body().collect().await.unwrap().to_bytes();
        (status, headers, String::from_utf8_lossy(&body).into_owned())
    }

    fn header_str<'a>(headers: &'a axum::http::HeaderMap, name: &str) -> Option<&'a str> {
        headers.get(name).and_then(|v| v.to_str().ok())
    }

    /// Proxy lines of a url_list body: everything that is not one of the
    /// leading `#` metadata comments.
    fn proxy_lines(body: &str) -> usize {
        body.lines().filter(|l| !l.starts_with('#')).count()
    }

    #[tokio::test]
    async fn sub_serves_merged_deduped_output() {
        let state = test_state().await;
        make_source(&state, "srcA0000000").await;
        make_source(&state, "srcB0000000").await;
        make_profile(&state, "profA0000000", &["srcA0000000", "srcB0000000"]).await;
        // The same server advertised by both sources plus one unique each.
        ingest(
            &state,
            "srcA0000000",
            &[
                entry("dup", "h1.example.com", 443),
                entry("a-only", "h2.example.com", 443),
            ],
        )
        .await;
        ingest(
            &state,
            "srcB0000000",
            &[
                entry("dup renamed", "h1.example.com", 443),
                entry("b-only", "h3.example.com", 443),
            ],
        )
        .await;

        let (status, headers, body) = get(router(state), "/sub/profA0000000").await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            header_str(&headers, "profile-title"),
            Some("Profile profA0000000")
        );
        assert_eq!(header_str(&headers, "profile-update-interval"), Some("1"));
        // The metadata comment block documents the file: title, interval,
        // the number of lines actually served, version and render time.
        let lines: Vec<&str> = body.lines().collect();
        assert!(
            lines.contains(&"# profile-title: Profile profA0000000"),
            "{body:?}"
        );
        assert!(lines.contains(&"# profile-update-interval: 1"), "{body:?}");
        assert!(lines.contains(&"# nodes count: 3"), "{body:?}");
        assert!(
            lines
                .iter()
                .any(|l| l.starts_with("# generated by: fumox ") && l.contains(" at ")),
            "{body:?}"
        );
        // 4 comment lines + 3 proxy lines.
        assert_eq!(lines.len(), 7, "duplicate must collapse: {body:?}");
        assert!(body.contains("h1.example.com:443"));
        assert!(body.contains("h2.example.com:443"));
        assert!(body.contains("h3.example.com:443"));
        // The shared fingerprint is a single DB row; reconciliation is
        // last-writer-wins for the name, and serving emits it exactly once.
        let dup_count = body.matches("h1.example.com:443").count();
        assert_eq!(dup_count, 1, "duplicate must appear once: {body:?}");
    }

    #[tokio::test]
    async fn profile_country_filter_follows_stored_geo_facts() {
        let state = test_state().await;
        make_source(&state, "srcA0000000").await;
        make_profile(&state, "profA0000000", &["srcA0000000"]).await;
        // Three proxies: confirmed US, confirmed DE, and one whose country
        // was never determined (no geo stamp at all).
        ingest(
            &state,
            "srcA0000000",
            &[
                entry("us", "us1.example.com", 443),
                entry("de", "de1.example.com", 443),
                entry("geoless", "xx.example.com", 443),
            ],
        )
        .await;
        for (host, country) in [
            ("us1.example.com", Some("US")),
            ("de1.example.com", Some("DE")),
            ("xx.example.com", None),
        ] {
            sqlx::query("UPDATE proxies SET status = 'alive', geo_country = ? WHERE host = ?")
                .bind(country)
                .bind(host)
                .execute(&state.pool)
                .await
                .unwrap();
        }

        // No allowlist: every proxy passes, including the geoless one.
        let (status, _, body) = get(router(state.clone()), "/sub/profA0000000").await;
        assert_eq!(status, StatusCode::OK);
        for host in ["us1", "de1", "xx"] {
            assert!(
                body.contains(&format!("{host}.example.com:443")),
                "{body:?}"
            );
        }

        // Only the confirmed US fact matches; the geoless proxy is not a
        // "US" proxy, so it stays out too.
        let mut profile = profiles::get(&state.pool, "profA0000000")
            .await
            .unwrap()
            .unwrap();
        profile.countries = vec!["US".into()];
        profile.updated_at = fumox_core::models::now_ts();
        profiles::update(&state.pool, &profile).await.unwrap();
        // Saved means immediately effective: the admin invalidates the /sub
        // cache on every profile save.
        state.caches.invalidate_profile(&profile.id).await;
        let (status, _, body) = get(router(state.clone()), "/sub/profA0000000").await;
        assert_eq!(status, StatusCode::OK);
        assert!(body.contains("us1.example.com:443"), "{body:?}");
        assert!(!body.contains("de1.example.com"), "{body:?}");
        assert!(!body.contains("xx.example.com"), "{body:?}");

        // Changing the list changes the output, codes are case-insensitive.
        profile.countries = vec!["de".into()];
        profile.updated_at = fumox_core::models::now_ts();
        profiles::update(&state.pool, &profile).await.unwrap();
        state.caches.invalidate_profile(&profile.id).await;
        let (status, _, body) = get(router(state), "/sub/profA0000000").await;
        assert_eq!(status, StatusCode::OK);
        assert!(body.contains("de1.example.com:443"), "{body:?}");
        assert!(!body.contains("us1.example.com"), "{body:?}");
        assert!(!body.contains("xx.example.com"), "{body:?}");
    }

    #[tokio::test]
    async fn unknown_or_disabled_profile_is_404() {
        let state = test_state().await;
        make_source(&state, "srcA0000000").await;
        let mut profile = make_profile(&state, "profA0000000", &["srcA0000000"]).await;
        profile.enabled = false;
        profiles::update(&state.pool, &profile).await.unwrap();

        let (status, _, _) = get(router(state.clone()), "/sub/doesnotexist0").await;
        assert_eq!(status, StatusCode::NOT_FOUND);

        let (status, _, _) = get(router(state), "/sub/profA0000000").await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn access_token_is_enforced() {
        let state = test_state().await;
        make_source(&state, "srcA0000000").await;
        let mut profile = make_profile(&state, "profA0000000", &["srcA0000000"]).await;
        profile.access_token = Some("secret-token".to_string());
        profiles::update(&state.pool, &profile).await.unwrap();
        ingest(&state, "srcA0000000", &[entry("a", "h1.example.com", 443)]).await;

        let (status, _, _) = get(router(state.clone()), "/sub/profA0000000").await;
        assert_eq!(status, StatusCode::FORBIDDEN);

        let (status, _, _) =
            get(router(state.clone()), "/sub/profA0000000?token=wrong-token").await;
        assert_eq!(status, StatusCode::FORBIDDEN);

        let (status, _, _) = get(
            router(state.clone()),
            "/sub/profA0000000?token=secret-token",
        )
        .await;
        assert_eq!(status, StatusCode::OK);

        let request = Request::builder()
            .uri("/sub/profA0000000")
            .header("Authorization", "Bearer secret-token")
            .body(Body::empty())
            .unwrap();
        let response = router(state).oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn format_query_param_is_rejected() {
        let state = test_state().await;
        make_source(&state, "srcA0000000").await;
        make_profile(&state, "profA0000000", &["srcA0000000"]).await;
        let (status, _, _) = get(router(state), "/sub/profA0000000?format=clash").await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn slug_resolves_like_token() {
        let state = test_state().await;
        make_source(&state, "srcA0000000").await;
        let mut profile = make_profile(&state, "profA0000000", &["srcA0000000"]).await;
        profile.slug = Some("ru-free".to_string());
        profiles::update(&state.pool, &profile).await.unwrap();
        ingest(&state, "srcA0000000", &[entry("a", "h1.example.com", 443)]).await;

        let (status, _, body) = get(router(state), "/sub/ru-free").await;
        assert_eq!(status, StatusCode::OK);
        assert!(body.contains("h1.example.com"));
    }

    #[tokio::test]
    async fn all_quarantined_produces_warning_and_empty_body() {
        let state = test_state().await;
        make_source(&state, "srcA0000000").await;
        make_profile(&state, "profA0000000", &["srcA0000000"]).await;
        ingest(&state, "srcA0000000", &[entry("a", "h1.example.com", 443)]).await;
        sqlx::query("UPDATE proxies SET status = 'quarantine'")
            .execute(&state.pool)
            .await
            .unwrap();

        let (status, headers, body) = get(router(state), "/sub/profA0000000").await;
        assert_eq!(status, StatusCode::OK);
        // No proxy lines survive; the metadata block still documents the
        // (empty) output with nodes count 0.
        assert!(
            body.lines().all(|l| l.starts_with('#')),
            "no proxy lines expected: {body:?}"
        );
        assert!(body.contains("# nodes count: 0"), "{body:?}");
        assert_eq!(
            header_str(&headers, "x-fumox-warning"),
            Some("all-proxies-quarantined")
        );
    }

    /// The quarantine warning must mean "everything is quarantined": a
    /// pipeline filter that hides every proxy is a configuration fact, and
    /// `ready` is a served tier to begin with, so neither may report a
    /// health problem the operator would chase in the wrong place.
    #[tokio::test]
    async fn a_filter_that_hides_every_ready_proxy_is_not_a_quarantine_warning() {
        let state = test_state().await;
        make_source(&state, "srcA0000000").await;
        let mut profile = make_profile(&state, "profA0000000", &["srcA0000000"]).await;
        profile.pipeline = Some(serde_json::json!({
            "version": 1,
            "filter": { "protocols": ["trojan"] }
        }));
        profiles::update(&state.pool, &profile).await.unwrap();
        ingest(
            &state,
            "srcA0000000",
            &[
                entry("a", "h1.example.com", 443),
                entry("b", "h2.example.com", 443),
            ],
        )
        .await;
        // Tunnel-verified tier: nothing is quarantined or removed here.
        sqlx::query("UPDATE proxies SET status = 'ready'")
            .execute(&state.pool)
            .await
            .unwrap();

        let (status, headers, body) = get(router(state), "/sub/profA0000000").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(proxy_lines(&body), 0, "{body:?}");
        assert_eq!(
            header_str(&headers, "x-fumox-warning"),
            None,
            "a filter is not a quarantine: {body:?}"
        );
    }

    #[tokio::test]
    async fn recoverable_source_error_serves_stale_with_header() {
        let state = test_state().await;
        make_source(&state, "srcA0000000").await;
        make_profile(&state, "profA0000000", &["srcA0000000"]).await;
        ingest(&state, "srcA0000000", &[entry("a", "h1.example.com", 443)]).await;
        sources::record_fetch_outcome(
            &state.pool,
            "srcA0000000",
            &FetchOutcome::Failure {
                at: fumox_core::models::now_ts(),
                error: "connection timed out",
                class: ErrorClass::Network,
            },
        )
        .await
        .unwrap();

        let (status, headers, body) = get(router(state), "/sub/profA0000000").await;
        assert_eq!(status, StatusCode::OK);
        assert!(
            body.contains("h1.example.com"),
            "stale snapshot must be served"
        );
        assert_eq!(header_str(&headers, "x-fumox-stale"), Some("true"));
    }

    #[tokio::test]
    async fn http_client_error_returns_upstream_code() {
        let state = test_state().await;
        make_source(&state, "srcA0000000").await;
        make_profile(&state, "profA0000000", &["srcA0000000"]).await;
        fetch_log::insert(
            &state.pool,
            &fetch_log::FetchLogEntry {
                source_id: "srcA0000000",
                fetched_at: fumox_core::models::now_ts(),
                ok: false,
                http_status: Some(404),
                bytes: None,
                proxies_found: None,
                error: Some("Not Found"),
                error_class: Some(ErrorClass::HttpClient),
            },
        )
        .await
        .unwrap();
        sources::record_fetch_outcome(
            &state.pool,
            "srcA0000000",
            &FetchOutcome::Failure {
                at: fumox_core::models::now_ts(),
                error: "HTTP 404",
                class: ErrorClass::HttpClient,
            },
        )
        .await
        .unwrap();

        let (status, _, _) = get(router(state), "/sub/profA0000000").await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    /// A cached snapshot must not outlive an unrecoverable upstream error:
    /// the re-render of a stale entry fails with the same `http_client`
    /// verdict the cold path answers, and while the stale body kept being
    /// served the documented "return the upstream status code" contract
    /// never took effect.
    #[tokio::test]
    async fn failed_revalidation_drops_the_cached_snapshot() {
        let state = test_state().await;
        make_source(&state, "srcA0000000").await;
        make_profile(&state, "profA0000000", &["srcA0000000"]).await;
        ingest(&state, "srcA0000000", &[entry("a", "h1.example.com", 443)]).await;

        // Cold render: a 200 with a full TTL is cached.
        let (status, _, body) = get(router(state.clone()), "/sub/profA0000000").await;
        assert_eq!(status, StatusCode::OK);
        assert!(body.contains("h1.example.com"), "{body:?}");

        // Age the entry so the next request takes the stale-while-revalidate
        // path and spawns a background re-render.
        let cached = state
            .caches
            .processed_get("sub:profA0000000")
            .await
            .expect("the cold render is cached");
        state
            .caches
            .processed_put(
                "sub:profA0000000",
                Rendered {
                    status: cached.status,
                    body: cached.body.clone(),
                    content_type: cached.content_type.clone(),
                    extra_headers: cached.extra_headers.clone(),
                    fresh_until: 0,
                    source_ids: cached.source_ids.clone(),
                },
            )
            .await;

        // The source goes down with an unrecoverable client error.
        fetch_log::insert(
            &state.pool,
            &fetch_log::FetchLogEntry {
                source_id: "srcA0000000",
                fetched_at: fumox_core::models::now_ts(),
                ok: false,
                http_status: Some(404),
                bytes: None,
                proxies_found: None,
                error: Some("Not Found"),
                error_class: Some(ErrorClass::HttpClient),
            },
        )
        .await
        .unwrap();
        sources::record_fetch_outcome(
            &state.pool,
            "srcA0000000",
            &FetchOutcome::Failure {
                at: fumox_core::models::now_ts(),
                error: "HTTP 404",
                class: ErrorClass::HttpClient,
            },
        )
        .await
        .unwrap();

        // This request is already in flight on the stale snapshot; the
        // background re-render must drop it.
        let (status, _, _) = get(router(state.clone()), "/sub/profA0000000").await;
        assert_eq!(status, StatusCode::OK);
        for _ in 0..200 {
            if state
                .caches
                .processed_get("sub:profA0000000")
                .await
                .is_none()
            {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        assert!(
            state
                .caches
                .processed_get("sub:profA0000000")
                .await
                .is_none(),
            "a failed re-render with an unrecoverable upstream error must drop the entry"
        );

        // The next request is the cold path again: the upstream status.
        let (status, _, _) = get(router(state), "/sub/profA0000000").await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    /// A source's `limit.count` must cap that source's contribution to
    /// `/sub` on its own. The cap used to be taken from whichever pipeline
    /// won the sort contest, so a limit-only source was served in full and
    /// only started counting once the same source also set a `sort`.
    #[tokio::test]
    async fn source_limit_applies_with_and_without_an_explicit_sort() {
        for sort in [None, Some(serde_json::json!({ "by": "name" }))] {
            let state = test_state().await;
            let mut source = make_source(&state, "srcA0000000").await;
            let mut pipeline = serde_json::json!({ "version": 1, "limit": { "count": 1 } });
            if let Some(sort) = sort.clone() {
                pipeline["sort"] = sort;
            }
            source.pipeline = Some(pipeline);
            sources::update(&state.pool, &source).await.unwrap();
            make_profile(&state, "profA0000000", &["srcA0000000"]).await;
            ingest(
                &state,
                "srcA0000000",
                &[
                    entry("a", "h1.example.com", 443),
                    entry("b", "h2.example.com", 443),
                    entry("c", "h3.example.com", 443),
                ],
            )
            .await;
            // /src serves the live tiers only, probe the three rows first.
            sqlx::query("UPDATE proxies SET status = 'alive'")
                .execute(&state.pool)
                .await
                .unwrap();

            let label = format!("sort={sort:?}");
            let (status, _, body) = get(router(state.clone()), "/sub/profA0000000").await;
            assert_eq!(status, StatusCode::OK, "{label}");
            assert_eq!(proxy_lines(&body), 1, "/sub, {label}: {body:?}");

            // The same config on the single-source endpoint, the reference
            // behaviour the profile path has to match.
            let (status, _, body) = get(router(state), "/src/srcA0000000").await;
            assert_eq!(status, StatusCode::OK, "{label}");
            assert_eq!(proxy_lines(&body), 1, "/src, {label}: {body:?}");
        }
    }

    /// The profile-level cap still applies to the merged list: a source
    /// without a limit of its own cannot outgrow the profile's.
    #[tokio::test]
    async fn profile_limit_caps_the_merged_list() {
        let state = test_state().await;
        let mut source = make_source(&state, "srcA0000000").await;
        source.pipeline = Some(serde_json::json!({ "version": 1 }));
        sources::update(&state.pool, &source).await.unwrap();
        let mut profile = make_profile(&state, "profA0000000", &["srcA0000000"]).await;
        profile.pipeline = Some(serde_json::json!({
            "version": 1,
            "limit": { "count": 2 }
        }));
        profiles::update(&state.pool, &profile).await.unwrap();
        ingest(
            &state,
            "srcA0000000",
            &[
                entry("a", "h1.example.com", 443),
                entry("b", "h2.example.com", 443),
                entry("c", "h3.example.com", 443),
            ],
        )
        .await;

        let (status, _, body) = get(router(state), "/sub/profA0000000").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(proxy_lines(&body), 2, "{body:?}");
    }

    /// A source's `limit.count` bounds that source's own contribution, not
    /// the merged profile. The cap used to be carried into the post-merge
    /// `finalize` by whichever pipeline won the sort contest, so a source
    /// that set both a `sort` and a `limit` silently truncated every other
    /// source's proxies out of `/sub` as well.
    #[tokio::test]
    async fn source_limit_does_not_truncate_the_other_sources() {
        let state = test_state().await;
        // Source A: explicit sort *and* a cap of 2 over 3 proxies.
        let mut a = make_source(&state, "srcA0000000").await;
        a.pipeline = Some(serde_json::json!({
            "version": 1,
            "sort": { "by": "name" },
            "limit": { "count": 2 }
        }));
        sources::update(&state.pool, &a).await.unwrap();
        // Source B: no cap of its own.
        let mut b = make_source(&state, "srcB0000000").await;
        b.pipeline = Some(serde_json::json!({ "version": 1 }));
        sources::update(&state.pool, &b).await.unwrap();
        make_profile(&state, "profA0000000", &["srcA0000000", "srcB0000000"]).await;
        ingest(
            &state,
            "srcA0000000",
            &[
                entry("a1", "h1.example.com", 443),
                entry("a2", "h2.example.com", 443),
                entry("a3", "h3.example.com", 443),
            ],
        )
        .await;
        ingest(
            &state,
            "srcB0000000",
            &[
                entry("b1", "h4.example.com", 443),
                entry("b2", "h5.example.com", 443),
                entry("b3", "h6.example.com", 443),
            ],
        )
        .await;
        sqlx::query("UPDATE proxies SET status = 'alive'")
            .execute(&state.pool)
            .await
            .unwrap();

        let (status, _, body) = get(router(state), "/sub/profA0000000").await;
        assert_eq!(status, StatusCode::OK);
        // 2 from A (its own cap) + 3 from B.
        assert_eq!(proxy_lines(&body), 5, "{body:?}");
        for host in ["h4", "h5", "h6"] {
            assert!(
                body.contains(&format!("{host}.example.com:443")),
                "source B must not be truncated away: {body:?}"
            );
        }
    }

    /// Health is owned by another process: the probe daemon moves rows
    /// between tiers, and the server only hears about it at the next
    /// ingest, a window of one *source* TTL, a full day at the maximum the
    /// admin form accepts. A rendered body must therefore not claim to be
    /// fresh for longer than the same short bound `/export/alive` uses.
    #[tokio::test]
    async fn rendered_output_is_not_fresh_for_a_whole_source_ttl() {
        let state = test_state().await;
        let mut source = make_source(&state, "srcA0000000").await;
        source.cache_ttl_seconds = 86_400;
        sources::update(&state.pool, &source).await.unwrap();
        make_profile(&state, "profA0000000", &["srcA0000000"]).await;
        ingest(&state, "srcA0000000", &[entry("a", "h1.example.com", 443)]).await;
        sqlx::query("UPDATE proxies SET status = 'alive'")
            .execute(&state.pool)
            .await
            .unwrap();

        for (key, uri) in [
            ("sub:profA0000000", "/sub/profA0000000"),
            ("src:srcA0000000", "/src/srcA0000000"),
        ] {
            let (status, _, body) = get(router(state.clone()), uri).await;
            assert_eq!(status, StatusCode::OK, "{uri}");
            assert!(body.contains("h1.example.com"), "{uri}: {body:?}");
            let cached = state
                .caches
                .processed_get(key)
                .await
                .expect("the cold render is cached");
            // Read the clock *after* the render: `fresh_until` is
            // `now_ts() + cap` as computed inside it, so a stamp taken
            // before the request would only hold while both calls land in
            // the same second.
            let after = fumox_core::models::now_ts();
            assert!(
                cached.fresh_until <= after + RENDER_FRESHNESS_CAP_SECS,
                "{uri}: a retired proxy would stay served for {} s, the health bound is {RENDER_FRESHNESS_CAP_SECS}",
                cached.fresh_until - after
            );
        }
    }

    #[tokio::test]
    async fn parse_error_sets_warning_header() {
        let state = test_state().await;
        make_source(&state, "srcA0000000").await;
        make_profile(&state, "profA0000000", &["srcA0000000"]).await;
        ingest(&state, "srcA0000000", &[entry("a", "h1.example.com", 443)]).await;
        sources::record_fetch_outcome(
            &state.pool,
            "srcA0000000",
            &FetchOutcome::Failure {
                at: fumox_core::models::now_ts(),
                error: "no proxies recognized",
                class: ErrorClass::ParseError,
            },
        )
        .await
        .unwrap();

        let (status, headers, body) = get(router(state), "/sub/profA0000000").await;
        assert_eq!(status, StatusCode::OK);
        assert!(
            body.contains("h1.example.com"),
            "stale snapshot must be served"
        );
        assert_eq!(header_str(&headers, "x-fumox-warning"), Some("parse-error"));
    }

    #[tokio::test]
    async fn base64_profile_wraps_uri_list() {
        let state = test_state().await;
        make_source(&state, "srcA0000000").await;
        let mut profile = make_profile(&state, "profA0000000", &["srcA0000000"]).await;
        profile.output_format = OutputFormat::Base64;
        profiles::update(&state.pool, &profile).await.unwrap();
        ingest(&state, "srcA0000000", &[entry("a", "h1.example.com", 443)]).await;

        let (status, _, body) = get(router(state), "/sub/profA0000000").await;
        assert_eq!(status, StatusCode::OK);
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(body.trim())
            .expect("body must be valid base64");
        let text = String::from_utf8(decoded).unwrap();
        assert!(text.contains("vless://"), "{text:?}");
        assert!(text.contains("h1.example.com:443"));
    }

    #[tokio::test]
    async fn src_endpoint_serves_single_source() {
        let state = test_state().await;
        make_source(&state, "srcA0000000").await;
        ingest(
            &state,
            "srcA0000000",
            &[
                entry("a", "h1.example.com", 443),
                entry("u", "h2.example.com", 443),
            ],
        )
        .await;
        // Only the first proxy passed the health check; the second stays
        // unknown (never probed).
        sqlx::query("UPDATE proxies SET status = 'alive' WHERE host = 'h1.example.com'")
            .execute(&state.pool)
            .await
            .unwrap();

        let (status, _, body) = get(router(state.clone()), "/src/srcA0000000").await;
        assert_eq!(status, StatusCode::OK);
        assert!(body.contains("h1.example.com"));
        // alive-only endpoint: untested proxies are not served.
        assert!(!body.contains("h2.example.com"));

        let (status, _, _) = get(router(state), "/src/missing00000").await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn alive_export_is_404_before_initialization() {
        let state = test_state().await;
        let (status, _, _) = get(router(state), "/export/alive/anything0000").await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn alive_export_link_serves_only_alive_proxies() {
        let state = test_state().await;
        make_source(&state, "srcA0000000").await;
        ingest(
            &state,
            "srcA0000000",
            &[
                entry("a", "h1.example.com", 443),
                entry("q", "h2.example.com", 443),
                entry("u", "h3.example.com", 443),
            ],
        )
        .await;
        sqlx::query("UPDATE proxies SET status = 'alive' WHERE host = 'h1.example.com'")
            .execute(&state.pool)
            .await
            .unwrap();
        sqlx::query("UPDATE proxies SET status = 'quarantine' WHERE host = 'h2.example.com'")
            .execute(&state.pool)
            .await
            .unwrap();

        let token = crate::alive_export::ensure_token(&state.pool)
            .await
            .unwrap();
        let (status, _, body) = get(router(state.clone()), &format!("/export/alive/{token}")).await;
        assert_eq!(status, StatusCode::OK);
        assert!(body.contains("h1.example.com"), "{body:?}");
        // Quarantined and never-probed proxies stay out.
        assert!(!body.contains("h2.example.com"), "{body:?}");
        assert!(!body.contains("h3.example.com"), "{body:?}");

        // An unknown token is an ordinary 404: the endpoint does not
        // disclose whether the link ever existed.
        let (status, _, _) = get(router(state.clone()), "/export/alive/zzzzzzzzzzzz").await;
        assert_eq!(status, StatusCode::NOT_FOUND);

        // The download variant attaches a dated file name.
        let (_, headers, _) = get(
            router(state.clone()),
            &format!("/export/alive/{token}?download=1"),
        )
        .await;
        let disposition = header_str(&headers, "content-disposition").unwrap_or_default();
        assert!(
            disposition.starts_with("attachment; filename=\"fumox-alive-"),
            "{disposition}"
        );

        // Rotating the token kills the old link immediately.
        let fresh = crate::alive_export::rotate_token(&state.pool)
            .await
            .unwrap();
        assert_ne!(fresh, token);
        let (status, _, _) = get(router(state.clone()), &format!("/export/alive/{token}")).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        let (status, _, body) = get(router(state), &format!("/export/alive/{fresh}")).await;
        assert_eq!(status, StatusCode::OK);
        assert!(body.contains("h1.example.com"), "{body:?}");
    }

    /// The ready export link: the same shared
    /// token, but only the tunnel-verified `ready` tier is served, an
    /// `alive` (unverified) proxy stays out, and rotation kills both links.
    #[tokio::test]
    async fn ready_export_link_serves_only_the_verified_tier() {
        let state = test_state().await;
        make_source(&state, "srcA0000000").await;
        ingest(
            &state,
            "srcA0000000",
            &[
                entry("plain", "h1.example.com", 443),
                entry("verified", "h2.example.com", 443),
            ],
        )
        .await;
        sqlx::query("UPDATE proxies SET status = 'alive' WHERE host = 'h1.example.com'")
            .execute(&state.pool)
            .await
            .unwrap();
        sqlx::query("UPDATE proxies SET status = 'ready' WHERE host = 'h2.example.com'")
            .execute(&state.pool)
            .await
            .unwrap();

        let token = crate::alive_export::ensure_token(&state.pool)
            .await
            .unwrap();
        let (status, _, body) = get(router(state.clone()), &format!("/export/ready/{token}")).await;
        assert_eq!(status, StatusCode::OK);
        assert!(body.contains("export/ready"), "title block: {body:?}");
        assert!(body.contains("h2.example.com"), "{body:?}");
        // The plain alive tier stays out, the links are disjoint.
        assert!(!body.contains("h1.example.com"), "{body:?}");

        // The same token opens the alive link with the complementary set.
        let (status, _, body) = get(router(state.clone()), &format!("/export/alive/{token}")).await;
        assert_eq!(status, StatusCode::OK);
        assert!(body.contains("h1.example.com"), "{body:?}");
        assert!(!body.contains("h2.example.com"), "{body:?}");

        // An unknown token is the same ordinary 404.
        let (status, _, _) = get(router(state.clone()), "/export/ready/zzzzzzzzzzzz").await;
        assert_eq!(status, StatusCode::NOT_FOUND);

        // Rotation kills both links, one secret, one rotation.
        let fresh = crate::alive_export::rotate_token(&state.pool)
            .await
            .unwrap();
        let (status, _, _) = get(router(state.clone()), &format!("/export/ready/{token}")).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        let (status, _, body) = get(router(state), &format!("/export/ready/{fresh}")).await;
        assert_eq!(status, StatusCode::OK);
        assert!(body.contains("h2.example.com"), "{body:?}");
    }

    #[test]
    fn url_list_header_block_sanitizes_and_formats() {
        // Newlines in a crafted profile name must not inject forged
        // comment lines into the output.
        let block = url_list_header_block("evil\n# nodes count: 999", 6, 42);
        let lines: Vec<&str> = block.lines().collect();
        assert_eq!(
            lines[0], "# profile-title: evil # nodes count: 999",
            "{block:?}"
        );
        assert_eq!(lines[1], "# profile-update-interval: 6");
        assert_eq!(lines[2], "# nodes count: 42");
        assert!(
            lines[3].starts_with("# generated by: fumox ")
                && lines[3].contains(" at ")
                && lines[3].ends_with('Z'),
            "{block:?}"
        );
    }

    #[tokio::test]
    async fn url_list_header_block_on_all_three_endpoints() {
        let state = test_state().await;
        make_source(&state, "srcA0000000").await;
        make_profile(&state, "profA0000000", &["srcA0000000"]).await;
        ingest(
            &state,
            "srcA0000000",
            &[
                entry("a", "h1.example.com", 443),
                entry("b", "h2.example.com", 443),
            ],
        )
        .await;
        // Both proxies alive: they appear in /sub, /src and the alive export.
        sqlx::query("UPDATE proxies SET status = 'alive'")
            .execute(&state.pool)
            .await
            .unwrap();
        let token = crate::alive_export::ensure_token(&state.pool)
            .await
            .unwrap();

        let app = router(state);
        for (uri, title, count) in [
            ("/sub/profA0000000", "Profile profA0000000", "2"),
            ("/src/srcA0000000", "source srcA0000000", "2"),
            (&format!("/export/alive/{token}"), "export/alive", "2"),
        ] {
            let (status, _, body) = get(app.clone(), uri).await;
            assert_eq!(status, StatusCode::OK, "{uri}");
            let lines: Vec<&str> = body.lines().collect();
            assert_eq!(
                lines[0],
                format!("# profile-title: {title}"),
                "{uri}: {body:?}"
            );
            assert_eq!(lines[1], "# profile-update-interval: 1", "{uri}: {body:?}");
            assert_eq!(
                lines[2],
                format!("# nodes count: {count}"),
                "{uri}: {body:?}"
            );
            assert!(
                lines[3].starts_with("# generated by: fumox "),
                "{uri}: {body:?}"
            );
            // The proxy lines follow after the block.
            assert_eq!(lines.len(), 6, "{uri}: {body:?}");
        }
    }

    #[tokio::test]
    async fn src_interval_rounds_ttl_up_to_whole_hours() {
        let state = test_state().await;
        let mut source = make_source(&state, "srcA0000000").await;
        // 90 minutes → 2 hours (rounded up, never 0).
        source.cache_ttl_seconds = 5400;
        sources::update(&state.pool, &source).await.unwrap();
        ingest(&state, "srcA0000000", &[entry("a", "h1.example.com", 443)]).await;
        sqlx::query("UPDATE proxies SET status = 'alive'")
            .execute(&state.pool)
            .await
            .unwrap();

        let (status, _, body) = get(router(state), "/src/srcA0000000").await;
        assert_eq!(status, StatusCode::OK);
        assert!(body.contains("# profile-update-interval: 2"), "{body:?}");
    }

    #[tokio::test]
    async fn processed_cache_serves_snapshot_until_invalidated() {
        let state = test_state().await;
        make_source(&state, "srcA0000000").await;
        make_profile(&state, "profA0000000", &["srcA0000000"]).await;
        ingest(&state, "srcA0000000", &[entry("a", "h1.example.com", 443)]).await;

        let (_, _, first) = get(router(state.clone()), "/sub/profA0000000").await;

        // A new proxy lands in the DB, but the fresh cache entry wins.
        ingest(&state, "srcA0000000", &[entry("b", "h9.example.com", 443)]).await;
        let (_, _, cached) = get(router(state.clone()), "/sub/profA0000000").await;
        assert_eq!(first, cached);
        assert!(!cached.contains("h9.example.com"));

        // Admin save handlers invalidate on change; the next render sees it.
        state.caches.invalidate_profile("profA0000000").await;
        let (_, _, refreshed) = get(router(state), "/sub/profA0000000").await;
        assert!(refreshed.contains("h9.example.com"));
    }

    #[tokio::test]
    async fn source_pipeline_filters_protocols() {
        let state = test_state().await;
        let mut source = make_source(&state, "srcA0000000").await;
        source.pipeline = Some(serde_json::json!({
            "version": 1,
            "filter": { "protocols": ["trojan"] }
        }));
        sources::update(&state.pool, &source).await.unwrap();
        make_profile(&state, "profA0000000", &["srcA0000000"]).await;
        let mut trojan = entry("t", "h2.example.com", 443);
        trojan.scheme = Scheme::Trojan;
        trojan.credential = "password".to_string();
        trojan.params.clear();
        ingest(
            &state,
            "srcA0000000",
            &[entry("v", "h1.example.com", 443), trojan],
        )
        .await;

        let (status, _, body) = get(router(state), "/sub/profA0000000").await;
        assert_eq!(status, StatusCode::OK);
        assert!(body.contains("trojan://"));
        assert!(!body.contains("vless://"));
    }

    #[tokio::test]
    async fn clash_profile_serves_yaml() {
        let state = test_state().await;
        make_source(&state, "srcA0000000").await;
        let mut profile = make_profile(&state, "profA0000000", &["srcA0000000"]).await;
        profile.output_format = OutputFormat::Clash;
        profiles::update(&state.pool, &profile).await.unwrap();
        // Two servers sharing a name (collision → auto-suffix) plus an
        // unsupported tuic entry that must be skipped.
        let mut tuic = entry("t", "h3.example.com", 443);
        tuic.scheme = Scheme::Tuic;
        ingest(
            &state,
            "srcA0000000",
            &[
                entry("a", "h1.example.com", 443),
                entry("a", "h2.example.com", 443),
                tuic,
            ],
        )
        .await;

        let (status, headers, body) = get(router(state), "/sub/profA0000000").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            header_str(&headers, "content-type"),
            Some("text/yaml; charset=utf-8")
        );
        let parsed: serde_norway::Value =
            serde_norway::from_str(&body).expect("body must be valid YAML");
        let proxies = parsed["proxies"]
            .as_sequence()
            .expect("proxies must be a list");
        assert_eq!(proxies.len(), 2, "tuic must be skipped: {body:?}");
        assert_eq!(proxies[0]["type"].as_str(), Some("vless"));
        assert_eq!(proxies[0]["name"].as_str(), Some("a"));
        assert_eq!(proxies[1]["name"].as_str(), Some("a (2)"));
        assert_eq!(proxies[0]["server"].as_str(), Some("h1.example.com"));
    }

    #[tokio::test]
    async fn singbox_profile_serves_json() {
        let state = test_state().await;
        make_source(&state, "srcA0000000").await;
        let mut profile = make_profile(&state, "profA0000000", &["srcA0000000"]).await;
        profile.output_format = OutputFormat::SingBox;
        profiles::update(&state.pool, &profile).await.unwrap();
        ingest(
            &state,
            "srcA0000000",
            &[
                entry("a", "h1.example.com", 443),
                entry("a", "h2.example.com", 443),
            ],
        )
        .await;

        let (status, headers, body) = get(router(state), "/sub/profA0000000").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            header_str(&headers, "content-type"),
            Some("application/json; charset=utf-8")
        );
        let parsed: serde_json::Value =
            serde_json::from_str(&body).expect("body must be valid JSON");
        let outbounds = parsed["outbounds"]
            .as_array()
            .expect("outbounds must be an array");
        assert_eq!(outbounds.len(), 2, "{body:?}");
        assert_eq!(outbounds[0]["type"].as_str(), Some("vless"));
        assert_eq!(outbounds[0]["tag"].as_str(), Some("a"));
        assert_eq!(outbounds[1]["tag"].as_str(), Some("a (2)"));
        assert_eq!(outbounds[0]["server"].as_str(), Some("h1.example.com"));
    }

    #[tokio::test]
    async fn all_quarantined_structured_formats_serve_empty_valid_config() {
        for (format, kind) in [
            (OutputFormat::Clash, "clash"),
            (OutputFormat::SingBox, "singbox"),
        ] {
            let state = test_state().await;
            make_source(&state, "srcA0000000").await;
            let mut profile = make_profile(&state, "profA0000000", &["srcA0000000"]).await;
            profile.output_format = format;
            profiles::update(&state.pool, &profile).await.unwrap();
            ingest(&state, "srcA0000000", &[entry("a", "h1.example.com", 443)]).await;
            sqlx::query("UPDATE proxies SET status = 'quarantine'")
                .execute(&state.pool)
                .await
                .unwrap();

            let (status, headers, body) = get(router(state), "/sub/profA0000000").await;
            assert_eq!(status, StatusCode::OK, "{kind}");
            assert_eq!(
                header_str(&headers, "x-fumox-warning"),
                Some("all-proxies-quarantined"),
                "{kind}"
            );
            match kind {
                "clash" => {
                    let parsed: serde_norway::Value =
                        serde_norway::from_str(&body).expect("valid YAML");
                    assert!(
                        parsed["proxies"].as_sequence().unwrap().is_empty(),
                        "{body:?}"
                    );
                }
                _ => {
                    let parsed: serde_json::Value =
                        serde_json::from_str(&body).expect("valid JSON");
                    assert!(
                        parsed["outbounds"].as_array().unwrap().is_empty(),
                        "{body:?}"
                    );
                }
            }
        }
    }
}
