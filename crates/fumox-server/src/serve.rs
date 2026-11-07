//! Public subscription endpoints.
//!
//! `GET /sub/{token|slug}` serves a profile, `GET /src/{token|slug}` a
//! single source, `GET /export/alive/{token}` and `GET /export/ready/{token}`
//! the two alive tiers (see [`crate::alive_export`]), and `GET /healthz`
//! (added by [`public_app`]) is the liveness probe. Output format is fixed
//! by the profile (`?format=` is forbidden); only 200 responses are cached,
//! and the full outcome table is implemented:
//!
//! - recoverable source errors (`network`, `http_server`) → serve the DB
//!   snapshot as stale + `X-Fumox-Stale: true`, no cutoff;
//! - unrecoverable `http_client` → the upstream status code, not cached;
//! - `parse_error` → stale snapshot or empty output + `X-Fumox-Warning:
//!   parse-error`;
//! - every proxy quarantined/removed → empty valid output +
//!   `X-Fumox-Warning: all-proxies-quarantined`;
//! - entries the output format cannot express (a scheme without a
//!   counterpart in the target format) → the output plus
//!   `X-Fumox-Warning: incompatible-entries-skipped` and the count in
//!   `X-Fumox-Skipped`.

// The freshness cap lives once, next to the cache it governs: the same
// window `/sub`, `/src` and the alive exports serve under.
use crate::cache::{Caches, InlineClaim, InlineOutcome, RENDER_FRESHNESS_CAP_SECS, Rendered};
use crate::pipeline::{self, Candidate, CompiledPipeline, PipelineIssue};
use crate::security::{ClientKeySource, RateLimiter, client_key, fmt_rfc3339_utc};
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
use std::sync::{Arc, LazyLock, Mutex};
use std::time::{Duration, Instant};

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
    /// Which forwarding header the trusted proxy writes. Only the named
    /// header is read; `None` honors none, so the peer address is the
    /// client even when a trusted proxy is configured.
    pub trusted_header: fumox_core::config::TrustedHeader,
    /// Hosts allowed to reach the public listener, canonicalized once at
    /// construction ([`crate::host_gate::HostAllowlist`]). Empty = accept
    /// any host; setting this locks the alive-export endpoint to the
    /// operator's own hostname.
    pub allowed_hosts: crate::host_gate::HostAllowlist,
    /// The settings of the two export links: the row ceiling of one body
    /// (`[server].export_max_rows`) and the capability token, kept in
    /// process memory (the admin panel shares the instance, so a rotation
    /// reaches both listeners at once).
    pub export: crate::alive_export::ExportState,
}

impl AppState {
    /// Assemble the shared state of the public listener from its
    /// dependencies. The single construction site for `AppState` (the
    /// startup wiring in `main` and the admin panel's in-process preview
    /// (`admin::handlers::profiles`) both go through it), so the two can
    /// never drift apart on how the listener is configured.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        pool: DbPool,
        caches: Caches,
        geo: Arc<GeoResolver>,
        limits: PublicRateLimits,
        trusted_cidrs: Vec<ipnet::IpNet>,
        trusted_header: fumox_core::config::TrustedHeader,
        allowed_hosts: Vec<String>,
        export: crate::alive_export::ExportState,
    ) -> Self {
        Self {
            pool,
            caches,
            geo,
            limits,
            trusted_cidrs,
            trusted_header,
            // The raw config list is canonicalized exactly once, here at
            // the single construction site: the gate compares the request
            // host against a ready list, never re-canonicalizing it.
            allowed_hosts: crate::host_gate::HostAllowlist::new(&allowed_hosts),
            export,
        }
    }

    /// The in-process preview state of the admin panel (the profile card
    /// renders exactly what `/sub` would serve without crossing the
    /// public listener): the owner's pool, caches, geo resolver and
    /// export state, fresh unlimited rate-limit counters (never consulted
    /// in-process) and no trusted proxies. Built next to the fields it
    /// fills, so the preview cannot drift from the wiring [`Self::new`]
    /// documents.
    pub fn for_preview(owner: &crate::admin::AdminState) -> Self {
        Self::new(
            owner.pool.clone(),
            owner.caches.clone(),
            owner.geo.clone(),
            PublicRateLimits::unlimited(),
            Vec::new(),
            fumox_core::config::TrustedHeader::None,
            Vec::new(),
            crate::alive_export::ExportState::new(
                owner.server().export_max_rows,
                owner.export_token.clone(),
            ),
        )
    }
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
/// `health_pool` is a [`HealthPool`]: a pool reserved for `/healthz`
/// alone, proven by its type.
pub fn public_app(state: AppState, health_pool: HealthPool) -> Router {
    let geo = state.geo.clone();
    let pool = health_pool.pool().clone();
    router(state).route(
        "/healthz",
        get(move || {
            let pool = pool.clone();
            let geo = geo.clone();
            async move { healthz(pool, geo).await }
        }),
    )
}

/// A pool reserved for `/healthz` alone, not the render pool. The
/// liveness answer must not depend on render load: a saturated pool is
/// this process's own load, and an orchestrator reads 503 as
/// "restart me", so sharing the pool turns a busy minute into a restart
/// loop. The dedicated pool holds one connection and is only ever asked
/// `SELECT 1`.
///
/// The type proves the pool's provenance: the only constructor takes a
/// [`fumox_core::config::DatabaseConfig`] and forces one connection, so a
/// call site cannot hand the render pool over by accident.
#[derive(Clone)]
pub struct HealthPool(DbPool);

impl HealthPool {
    /// Build the dedicated `/healthz` pool: the deployment's database,
    /// one connection, whatever `[database].max_connections` says.
    pub async fn dedicated(
        config: &fumox_core::config::DatabaseConfig,
    ) -> fumox_core::Result<Self> {
        let mut config = config.clone();
        config.max_connections = 1;
        Ok(Self(fumox_core::db::connect_pool(&config).await?))
    }

    /// The inner pool: `/healthz`'s `SELECT 1` runs on it; the tests hold
    /// its single connection or close it outright.
    pub(crate) fn pool(&self) -> &DbPool {
        &self.0
    }
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
///
/// The second line names the geo state: geo enrichment is optional, so a
/// missing database is not a fault of the process, but the operator has to
/// be able to tell "off", "no databases" and "degraded" apart without
/// reading the log.
async fn healthz(pool: DbPool, geo: Arc<GeoResolver>) -> Response {
    const ACQUIRE_TIMEOUT: Duration = Duration::from_secs(2);
    let geo_line = format!("geo: {}\n", geo.state().as_str());
    match tokio::time::timeout(ACQUIRE_TIMEOUT, sqlx::query("SELECT 1").fetch_one(&pool)).await {
        Ok(Ok(_)) => (StatusCode::OK, format!("ok\n{geo_line}")).into_response(),
        Ok(Err(error)) => {
            tracing::error!(error = %error, "/healthz database check failed");
            (
                StatusCode::SERVICE_UNAVAILABLE,
                format!("database unavailable\n{geo_line}"),
            )
                .into_response()
        }
        Err(_) => {
            tracing::warn!(
                timeout_secs = ACQUIRE_TIMEOUT.as_secs(),
                "/healthz gave up waiting for a pool connection; \
                 reporting the instance busy rather than down"
            );
            (
                StatusCode::SERVICE_UNAVAILABLE,
                format!("database busy\n{geo_line}"),
            )
                .into_response()
        }
    }
}

/// Per-IP limiting: every request counts against `[server].rate_limit`, a 403
/// additionally against `[server].auth_fail_rate_limit`, and an exhausted
/// window answers 429. Requests without `ConnectInfo<SocketAddr>` pass
/// uncounted.
async fn public_rate_limit(State(state): State<AppState>, req: Request, next: Next) -> Response {
    let Some(connect) = req.extensions().get::<ConnectInfo<SocketAddr>>().cloned() else {
        // Once per process: such a request cannot be keyed per IP, so the
        // per-IP ceilings are inactive for it. Embedded runtimes never
        // carry the extension, and one line per request would be noise.
        warn_missing_connect_info_once();
        return next.run(req).await;
    };
    let (key, source) = client_key(
        connect.0,
        req.headers(),
        &state.trusted_cidrs,
        state.trusted_header,
    );
    let ip = key.to_string();
    // A key that degraded to the peer despite a declared header and a
    // trusted proxy ([`ClientKeySource::PeerFallback`]) puts everything
    // behind that peer into one bucket: say so once per window, the
    // condition holds for every request the window covers.
    if source == ClientKeySource::PeerFallback {
        crate::security::warn_shared_peer_bucket(&ip, state.limits.all.window());
    }
    if let Err(retry_after) = state.limits.all.check(&ip).await {
        // Warn once per client key per window, debug after: a scraping
        // burst must be visible without one line per 429. The client key
        // is the only identity named — no token, no query string.
        if should_warn_rate_limit(&ip) {
            tracing::warn!(client = %ip, "public rate-limit window exhausted");
        } else {
            tracing::debug!(client = %ip, "public rate-limit window exhausted");
        }
        return error_response_with_retry(
            StatusCode::TOO_MANY_REQUESTS,
            "too many requests, try again later",
            retry_after,
        );
    }
    let response = next.run(req).await;
    if let Some(check) = response.extensions().get::<AuthFailure>().copied() {
        // A failed secret check on a public route (profile access token,
        // source access token, export capability token): warn once per
        // client key per window, debug after: the same coalescing the
        // shared warn registry gives the host gate, so a token-guessing
        // campaign is visible without one log line per request. The client
        // key is logged, never the rejected token value.
        if should_warn_auth_failure(&ip) {
            tracing::warn!(client = %ip, check = check.0, "public secret check failed");
        } else {
            tracing::debug!(client = %ip, check = check.0, "public secret check failed");
        }
    }
    if response.status() == StatusCode::FORBIDDEN
        && let Some(retry_after) = state.limits.auth_failures.check(&ip).await.err()
    {
        // The failure window rejected the request, give the hit back to the
        // generous window so one brute-force attempt does not cost the
        // caller two windows.
        state.limits.all.refund(&ip).await;
        tracing::warn!(
            client = %ip,
            "auth-failure rate limit window exhausted; rejecting the request"
        );
        return error_response_with_retry(
            StatusCode::TOO_MANY_REQUESTS,
            "too many failed access attempts, try again later",
            retry_after,
        );
    }
    response
}

/// Response extension a handler attaches when it rejected a request on a
/// secret check (`/sub` access token, export capability token). The public
/// rate-limit middleware reads it to log the failure with the client key it
/// already computed: the handlers never see the peer address, so they
/// cannot log one. The value names the check that failed; the checked
/// token itself is never logged.
#[derive(Debug, Clone, Copy)]
pub(crate) struct AuthFailure(pub(crate) &'static str);

/// Window within which a repeated auth failure from the same client key
/// stays at debug level. The failure paths sit on public routes, so the log
/// line has to serve two opposite extremes: a token-guessing campaign
/// against `/sub` or `/export` must be visible immediately, while it must
/// not get one warn per request.
const AUTH_FAIL_WARN_WINDOW: Duration = Duration::from_secs(3_600);

/// Distinct client keys kept in the registry, bounding the memory a flood
/// of distinct keys could pin. Hitting this count does not silence new
/// keys: it bounds tracking, not warnings (see
/// [`crate::security::WarnRegistry::should_warn`]).
const AUTH_FAIL_MAX_TRACKED: usize = 1_024;

/// Warns this registry may emit per [`AUTH_FAIL_WARN_WINDOW`]. Past it,
/// failures drop to debug, but the clients the window swallowed are named
/// in a summary when the window rolls over.
const AUTH_FAIL_MAX_WARNS: u32 = 64;

/// Per-client warn registry for failed secret checks on the public
/// listener, the shared bounded registry of
/// [`crate::security::WarnRegistry`] keyed by client key — the same
/// deduplication the host gate's `alive_export::HOST_REJECT_LOG` runs.
static AUTH_FAIL_LOG: LazyLock<Mutex<crate::security::WarnRegistry>> = LazyLock::new(|| {
    Mutex::new(crate::security::WarnRegistry::new(
        AUTH_FAIL_WARN_WINDOW,
        AUTH_FAIL_MAX_TRACKED,
        AUTH_FAIL_MAX_WARNS,
    ))
});

/// Whether a failed secret check from `client` should be logged at warn
/// rather than debug (see [`crate::security::WarnRegistry::should_warn`]).
/// Logs the window summary when one came due, before the verdict for the
/// request in hand.
fn should_warn_auth_failure(client: &str) -> bool {
    let (warn, summary) = AUTH_FAIL_LOG
        .lock()
        .unwrap_or_else(|poison| poison.into_inner())
        .should_warn(client, Instant::now());
    if let Some(summary) = summary {
        let named = summary.suppressed.first().cloned().unwrap_or_default();
        tracing::warn!(
            "public auth failures: {} dropped to debug this window, \
             first suppressed client {named}",
            summary.suppressed_total
        );
    }
    warn
}

/// Window and caps of the shared-window rejection log: the same shape as
/// the auth-failure registry, because the two refusals read the same way
/// in the log (a flood must be visible once, not per request).
const RATE_LIMIT_WARN_WINDOW: Duration = AUTH_FAIL_WARN_WINDOW;
const RATE_LIMIT_MAX_TRACKED: usize = AUTH_FAIL_MAX_TRACKED;
const RATE_LIMIT_MAX_WARNS: u32 = AUTH_FAIL_MAX_WARNS;

/// Per-client warn registry for refusals by the shared public window
/// (`[server].rate_limit`), see [`should_warn_rate_limit`].
static RATE_LIMIT_LOG: LazyLock<Mutex<crate::security::WarnRegistry>> = LazyLock::new(|| {
    Mutex::new(crate::security::WarnRegistry::new(
        RATE_LIMIT_WARN_WINDOW,
        RATE_LIMIT_MAX_TRACKED,
        RATE_LIMIT_MAX_WARNS,
    ))
});

/// Whether one more refusal of `client` by the shared window should be
/// logged at warn rather than debug: warn once per client key per window,
/// debug after, so a scraping burst is visible without one line per 429.
/// The registry's window is the limiter's own horizon: a refusal means
/// nothing outside it.
fn should_warn_rate_limit(client: &str) -> bool {
    let (warn, summary) = RATE_LIMIT_LOG
        .lock()
        .unwrap_or_else(|poison| poison.into_inner())
        .should_warn(client, Instant::now());
    if let Some(summary) = summary {
        let named = summary.suppressed.first().cloned().unwrap_or_default();
        tracing::warn!(
            "public rate-limit refusals: {} dropped to debug this window, \
             first suppressed client {named}",
            summary.suppressed_total
        );
    }
    warn
}

/// Set once per process, so a request arriving without
/// `ConnectInfo<SocketAddr>` warns about the inactive per-IP rate limiting
/// exactly once instead of once per request: embedded runtimes never carry
/// the extension, so every request of such a deployment would repeat the
/// same line forever.
static MISSING_CONNECT_INFO_WARNED: LazyLock<std::sync::atomic::AtomicBool> =
    LazyLock::new(|| std::sync::atomic::AtomicBool::new(false));

/// Warn once per process that a request came in without
/// `ConnectInfo<SocketAddr>`: the per-IP rate limiting is inactive for it.
/// Returns whether this call emitted the warning (the first one does).
fn warn_missing_connect_info_once() -> bool {
    let first = !MISSING_CONNECT_INFO_WARNED.swap(true, std::sync::atomic::Ordering::SeqCst);
    if first {
        tracing::warn!("public request without ConnectInfo: per-IP rate limiting is inactive");
    }
    first
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
    /// A database read failed mid-render. `target` names the cache key the
    /// render was building (`sub:{profile_id}` / `src:{source_id}`), the
    /// same identifier the cache and the invalidations use, so a log line
    /// can be tied to the endpoint it broke.
    fn internal(target: &str, err: impl std::fmt::Display) -> Self {
        tracing::error!(target, error = %err, "serving failed");
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
        // The message names the source and its last error, so the reply the
        // subscriber sees is traceable from the log without a request id.
        tracing::warn!(status = %status, "upstream unavailable: serving the upstream status");
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
    // Authorization: Bearer. NULL means the endpoint is public. The row
    // holds the token's hash, so the presented token is hashed and
    // compared in constant time.
    if let Some(required) = &profile.access_token {
        let provided = params
            .get("token")
            .cloned()
            .or_else(|| bearer_token(&headers));
        let ok = provided
            .as_deref()
            .is_some_and(|provided| fumox_core::token::verify(provided, required));
        if !ok {
            let mut response =
                error_response(StatusCode::FORBIDDEN, "access token is missing or invalid");
            // Flag the failure for the public rate-limit middleware, which
            // logs it with the client key it computed; this handler never
            // sees the peer address, and the token value is never logged.
            response
                .extensions_mut()
                .insert(AuthFailure("profile access token"));
            return response;
        }
    }

    let key = Caches::profile_key(&profile.id);
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
    headers: axum::http::HeaderMap,
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
    // Optional per-source access token, the `/src` twin of the profile
    // check in `serve_sub`: query parameter or Authorization: Bearer, NULL
    // means the endpoint is public. A profile's token guards `/sub` only
    // and does not extend here — the source row carries its own secret.
    if let Some(required) = &source.access_token {
        let provided = params
            .get("token")
            .cloned()
            .or_else(|| bearer_token(&headers));
        let ok = provided
            .as_deref()
            .is_some_and(|provided| fumox_core::token::verify(provided, required));
        if !ok {
            let mut response =
                error_response(StatusCode::FORBIDDEN, "access token is missing or invalid");
            // Flag the failure for the public rate-limit middleware, which
            // logs it with the client key it computed; the token value is
            // never logged.
            response
                .extensions_mut()
                .insert(AuthFailure("source access token"));
            return response;
        }
    }

    let key = Caches::source_key(&source.id);
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
    // The cold-render horizon: the miss event below reports how long the
    // one real render took, so an operator can tell an expensive render
    // (log shows "miss") from a hot path ("hit"/"stale" only).
    let serve_started = Instant::now();
    let now = fumox_core::models::now_ts();
    if let Some(rendered) = state.caches.processed_get(&key).await {
        if rendered.is_fresh(now) {
            tracing::debug!(
                key = %key,
                elapsed_ms = serve_started.elapsed().as_millis() as u64,
                outcome = "hit",
                "subscription served from the processed cache"
            );
            return to_response(&rendered);
        }
        if let Some(claim) = state.caches.try_start_revalidate(&key).await {
            let state = state.clone();
            let key = key.clone();
            let generation = claim.generation();
            tokio::spawn(async move {
                // The claim is released when `claim` drops, panic included.
                let _claim = claim;
                // The same deadline the leader of an inline render gets: a
                // background re-render that wedges must not hold the claim
                // forever, or the key would never be revalidated again.
                match tokio::time::timeout(WAIT_FOR_LEADER, make_render()).await {
                    Ok(Ok(rendered)) => {
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
                    Ok(Err(err)) => {
                        // An unrecoverable upstream answer is the endpoint's
                        // answer now: drop the snapshot so the next request
                        // re-renders and returns the upstream status instead
                        // of the last good body with frozen headers.
                        if err.drop_cached {
                            state.caches.processed_invalidate(&key).await;
                        }
                        tracing::warn!(key = %key, status = %err.status, "revalidation failed");
                    }
                    Err(_) => {
                        // The claim drops with the task, so the next request
                        // can start a revalidation again.
                        tracing::warn!(
                            key = %key,
                            deadline_secs = WAIT_FOR_LEADER.as_secs(),
                            "revalidation timed out; the cached snapshot stays until the next attempt"
                        );
                    }
                }
            });
        }
        tracing::debug!(
            key = %key,
            elapsed_ms = serve_started.elapsed().as_millis() as u64,
            outcome = "stale",
            "stale snapshot served while a re-render runs"
        );
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
            // A render of this key failed a moment ago: its verdict is the
            // answer, a second render would fail the same way.
            InlineClaim::Failed { status, message } => {
                let status = StatusCode::from_u16(status).unwrap_or(StatusCode::BAD_GATEWAY);
                return retryable_render_error(status, &message);
            }
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
                    return error_response_with_retry(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "render in progress, try again",
                        RENDER_RETRY_AFTER_SECS,
                    );
                }
                match ended.borrow_and_update().clone() {
                    InlineOutcome::Failed { status, message } => {
                        let status =
                            StatusCode::from_u16(status).unwrap_or(StatusCode::BAD_GATEWAY);
                        return retryable_render_error(status, &message);
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
        Ok(Ok(rendered)) => {
            tracing::info!(
                key = %key,
                elapsed_ms = serve_started.elapsed().as_millis() as u64,
                outcome = "miss",
                "cold render completed"
            );
            rendered
        }
        Ok(Err(err)) => {
            tracing::warn!(key = %key, status = %err.status, "inline render failed");
            claim.fail(err.status.as_u16(), err.message.clone());
            drop(claim);
            return retryable_render_error(err.status, &err.message);
        }
        Err(_) => {
            tracing::warn!(
                key = %key,
                deadline_secs = WAIT_FOR_LEADER.as_secs(),
                "inline render timed out"
            );
            claim.fail(
                StatusCode::SERVICE_UNAVAILABLE.as_u16(),
                "render timed out".to_string(),
            );
            drop(claim);
            return error_response_with_retry(
                StatusCode::SERVICE_UNAVAILABLE,
                "render timed out",
                RENDER_RETRY_AFTER_SECS,
            );
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
        .map_err(|err| ErrorReply::internal(&format!("sub:{}", profile.id), err))?;

    // Load member sources in profile order with one `WHERE id IN (...)`
    // read: the per-member indexed fetch this replaced ran one query per
    // source, on the public serving path once per cold render. Disabled or
    // vanished sources drop out of the output.
    let member_ids: Vec<&str> = links
        .iter()
        .map(|(source_id, _)| source_id.as_str())
        .collect();
    let loaded = sources::get_many(&state.pool, &member_ids)
        .await
        .map_err(|err| ErrorReply::internal(&format!("sub:{}", profile.id), err))?;
    let mut members: Vec<(Source, Arc<CompiledPipeline>)> = Vec::new();
    for (source_id, _position) in links {
        let Some(source) = loaded.get(&source_id) else {
            continue;
        };
        if !source.enabled {
            continue;
        }
        let merged = pipeline::merge_configs(source.pipeline.as_ref(), profile.pipeline.as_ref());
        let compiled = CompiledPipeline::from_json_cached(merged.as_ref()).map_err(|errors| {
            ErrorReply::corrupted_pipeline(&format!("sub:{}", profile.id), &errors)
        })?;
        members.push((source.clone(), compiled));
    }

    // An unrecoverable source error short-circuits the whole profile to
    // the upstream status code, not cached.
    for (source, _) in &members {
        if source.error_class == Some(ErrorClass::HttpClient) {
            return Err(upstream_unavailable_reply(state, source).await);
        }
    }

    let profile_pipeline =
        CompiledPipeline::from_json_cached(profile.pipeline.as_ref()).map_err(|errors| {
            ErrorReply::corrupted_pipeline(&format!("sub:{}", profile.id), &errors)
        })?;

    let source_ids: Vec<String> = members.iter().map(|(s, _)| s.id.clone()).collect();
    let rows = proxies::list_with_source(&state.pool, &source_ids)
        .await
        .map_err(|err| ErrorReply::internal(&format!("sub:{}", profile.id), err))?;
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
    let mut skipped = SkippedRows::default();

    for (position, (source, compiled)) in members.iter().enumerate() {
        match source.error_class {
            None => {}
            Some(ErrorClass::Network) | Some(ErrorClass::HttpServer) => any_stale = true,
            // The last payload could not be stored: what is served is
            // older than the feed, exactly like an unreachable upstream.
            Some(ErrorClass::Storage) => any_stale = true,
            Some(ErrorClass::ParseError) => any_parse_error = true,
            Some(ErrorClass::HttpClient) => unreachable!("handled above"),
        }
        let rows = by_source.remove(&source.id).unwrap_or_default();
        let mut candidates = rows_to_candidates(rows, position as i64, &mut skipped);
        // The tiers the source holds before the country filter, the same
        // pre-filter bookkeeping `render_src` does: the "everything is
        // hidden" verdict below is about the sources' health, so proxies a
        // country allowlist removed must not make an alive source look
        // quarantined (nor a quarantined one look healthy).
        loaded_statuses.extend(candidates.iter().map(|c| c.status));
        if let Some(allowed) = &allowed_countries {
            pipeline::retain_allowed_countries(&mut candidates, allowed);
        }
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
        .find(|(_, compiled)| compiled.sort_explicit())
        .map(|(source, _)| source)
        .filter(|_| !profile_pipeline.sort_explicit())
        .and_then(|source| source.pipeline.as_ref())
        .and_then(|pipeline| pipeline.get("sort"))
        .cloned();
    // The post-merge step runs with the profile's own pipeline, plus that
    // sort section: `finalize` caps the list it is given, and a cap that
    // reached the merged list from a *source* pipeline would truncate every
    // other source's proxies too. Each source's cap was already applied to
    // that source's own contribution by `apply` above.
    let finalizer = CompiledPipeline::from_json_cached(
        finalize_config(profile.pipeline.as_ref(), source_sort).as_ref(),
    )
    .map_err(|errors| ErrorReply::corrupted_pipeline(&format!("sub:{}", profile.id), &errors))?;
    finalizer.finalize(&mut all);

    // The metadata block goes only into plain uri_list output: base64 blobs
    // must stay decodable to a bare list (the block would double-encode as
    // base64 text), and structured formats have their own document shape.
    let interval_hours: u64 = update_interval_hours(&members).parse().unwrap_or(1);
    let (body, content_type, skipped_entries) = encode(&all, profile.output_format, || {
        url_list_header_block(&profile.name, Some(interval_hours), all.len())
    });

    // The name is user input and becomes an HTTP header value: kill line
    // breaks so a crafted name cannot split the header (the body block
    // applies the same sanitisation).
    let mut extra_headers: Vec<(String, String)> = vec![
        (
            "profile-title".to_string(),
            profile.name.replace(['\n', '\r'], " "),
        ),
        (
            "profile-update-interval".to_string(),
            update_interval_hours(&members),
        ),
    ];
    if any_stale {
        extra_headers.push(("X-Fumox-Stale".to_string(), "true".to_string()));
    }
    let mut warnings: Vec<&str> = Vec::new();
    if any_parse_error {
        warnings.push("parse-error");
    } else if all_quarantined {
        warnings.push("all-proxies-quarantined");
    }
    if skipped_entries > 0 {
        warnings.push("incompatible-entries-skipped");
    }
    if !warnings.is_empty() {
        extra_headers.push(("X-Fumox-Warning".to_string(), warnings.join(", ")));
    }
    if skipped_entries > 0 {
        extra_headers.push(("X-Fumox-Skipped".to_string(), skipped_entries.to_string()));
    }
    skipped.log();

    // The shortest member TTL bounds how long a cached render stays
    // fresh; the freshness cap is smaller than every fallback in
    // [`min_member_ttl`], so the empty-member case lands on the cap the
    // way the former inline 60-second default did.
    let min_ttl = min_member_ttl(&members);
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
        return Err(upstream_unavailable_reply(state, source).await);
    }

    let compiled = CompiledPipeline::from_json_cached(source.pipeline.as_ref())
        .map_err(|errors| ErrorReply::corrupted_pipeline(&format!("src:{}", source.id), &errors))?;

    let rows = proxies::list_with_source(&state.pool, std::slice::from_ref(&source.id))
        .await
        .map_err(|err| ErrorReply::internal(&format!("src:{}", source.id), err))?;
    let mut skipped = SkippedRows::default();
    let mut candidates = rows_to_candidates(
        rows.into_iter().map(|linked| linked.proxy).collect(),
        0,
        &mut skipped,
    );
    // The tiers the source holds before the live-tier filter: the
    // "everything is hidden" verdict is about the source's health, not
    // about what a filter removed.
    let loaded_statuses: Vec<ProxyStatus> = candidates.iter().map(|c| c.status).collect();
    // /src serves only health-checked, currently-live proxies: rows that
    // were never probed (unknown), quarantined or removed stay out even
    // when the pipeline's health filter would let them through. `ready`
    // (the tunnel-verified tier) is a live tier too, a verified proxy
    // must not vanish from client output the
    // moment T2 promotes it.
    candidates.retain(|c| matches!(c.status, ProxyStatus::Alive | ProxyStatus::Ready));
    let out = compiled.apply(candidates, &state.geo).await;

    // The same verdict /sub reports: the source holds proxies, but every
    // one of them is out of the live tiers.
    let all_quarantined = !loaded_statuses.is_empty()
        && out.is_empty()
        && loaded_statuses
            .iter()
            .all(|status| matches!(status, ProxyStatus::Quarantine | ProxyStatus::Removed));

    // Same ttl-derived interval rule as the sub profile: whole hours
    // rounded up from the source TTL, at least 1.
    let interval_hours = whole_hours(source.cache_ttl_seconds);
    let (body, content_type, skipped_entries) = encode(&out, OutputFormat::UriList, || {
        url_list_header_block(&source.name, Some(interval_hours as u64), out.len())
    });

    let mut extra_headers: Vec<(String, String)> = Vec::new();
    let mut warnings: Vec<&str> = Vec::new();
    match source.error_class {
        None => {}
        Some(ErrorClass::Network) | Some(ErrorClass::HttpServer) => {
            extra_headers.push(("X-Fumox-Stale".to_string(), "true".to_string()));
        }
        // The stored rows are older than the feed: the output is stale,
        // the upstream is fine.
        Some(ErrorClass::Storage) => {
            extra_headers.push(("X-Fumox-Stale".to_string(), "true".to_string()));
        }
        Some(ErrorClass::ParseError) => {
            warnings.push("parse-error");
        }
        Some(ErrorClass::HttpClient) => unreachable!("handled above"),
    }
    if all_quarantined {
        warnings.push("all-proxies-quarantined");
    }
    if skipped_entries > 0 {
        warnings.push("incompatible-entries-skipped");
    }
    if !warnings.is_empty() {
        extra_headers.push(("X-Fumox-Warning".to_string(), warnings.join(", ")));
    }
    if skipped_entries > 0 {
        extra_headers.push(("X-Fumox-Skipped".to_string(), skipped_entries.to_string()));
    }
    skipped.log();

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

/// Proxy rows that could not be turned into a candidate.
///
/// A corrupt row is skipped instead of failing the whole render, but a
/// skipped row is a row the subscriber does not get. The count and the
/// first reason are summarized in one line per render: a feed full of
/// broken rows must not produce one log line per row.
#[derive(Default)]
struct SkippedRows {
    count: u64,
    first_id: Option<i64>,
    first_error: Option<String>,
}

impl SkippedRows {
    fn note(&mut self, proxy_id: i64, error: &str) {
        self.count += 1;
        if self.first_id.is_none() {
            self.first_id = Some(proxy_id);
            self.first_error = Some(error.to_string());
        }
    }

    /// One summary line for the whole render.
    fn log(&self) {
        if self.count == 0 {
            return;
        }
        tracing::warn!(
            skipped = self.count,
            first_proxy_id = self.first_id.unwrap_or_default(),
            first_error = self.first_error.as_deref().unwrap_or_default(),
            "proxy rows skipped during rendering"
        );
    }
}

/// Map DB rows to pipeline candidates; corrupt rows are counted and
/// skipped (errors never abort a rendering).
fn rows_to_candidates(
    rows: Vec<proxies::ProxyRow>,
    source_position: i64,
    skipped: &mut SkippedRows,
) -> Vec<Candidate> {
    let mut candidates = Vec::with_capacity(rows.len());
    for row in rows {
        let entry = match row.to_entry() {
            Ok(entry) => entry,
            Err(err) => {
                skipped.note(row.id, &err.to_string());
                continue;
            }
        };
        let status = match row.status.parse::<ProxyStatus>() {
            Ok(status) => status,
            Err(err) => {
                skipped.note(row.id, &err.to_string());
                continue;
            }
        };
        candidates.push(Candidate {
            entry,
            source_position,
            status,
            latency_ms: row.latency_ms,
            geo_country: row.geo_country.clone(),
            // The stored `AS{n}` spelling parses exactly once, here: the
            // pipeline compares plain numbers downstream.
            geo_asn: row.geo_asn.as_deref().and_then(pipeline::asn_number),
        });
    }
    candidates
}

/// Serialize candidates into the profile's output format. The
/// `header_block` closure supplies the url_list metadata comments; it is
/// only invoked (and only prepended) for the plain uri_list format.
///
/// The third value is the number of entries the format cannot express
/// (see [`fumox_core::formats::skipped_count`]). The response says so
/// instead of quietly serving a shorter list than the pipeline
/// produced.
fn encode(
    candidates: &[Candidate],
    format: OutputFormat,
    mut header_block: impl FnMut() -> String,
) -> (Vec<u8>, String, usize) {
    let entries: Vec<fumox_core::models::ProxyEntry> =
        candidates.iter().map(|c| c.entry.clone()).collect();
    let skipped = fumox_core::formats::skipped_count(format, &entries);
    match format {
        OutputFormat::UriList => {
            // The block already ends with a newline; empty candidate lists
            // yield just the block itself (with `nodes count: 0`).
            let body = match header_block() {
                block if block.is_empty() => uri_lines(candidates),
                block => format!("{block}{}", uri_lines(candidates)),
            };
            (
                body.into_bytes(),
                "text/plain; charset=utf-8".to_string(),
                skipped,
            )
        }
        OutputFormat::Base64 => (
            base64::engine::general_purpose::STANDARD
                .encode(uri_lines(candidates).as_bytes())
                .into_bytes(),
            "text/plain; charset=utf-8".to_string(),
            skipped,
        ),
        OutputFormat::Clash => {
            let body = fumox_core::formats::clash::encode_clash(&entries);
            // The count inside the document too: a YAML comment is inert
            // for the parsers and survives a copy-pasted file, where the
            // response headers are long gone.
            let body = if skipped > 0 {
                format!("# skipped: {skipped} (unsupported scheme)\n{body}")
            } else {
                body
            };
            (
                body.into_bytes(),
                "text/yaml; charset=utf-8".to_string(),
                skipped,
            )
        }
        OutputFormat::SingBox => (
            fumox_core::formats::singbox::encode_singbox(&entries).into_bytes(),
            "application/json; charset=utf-8".to_string(),
            skipped,
        ),
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
/// `interval_hours` is the TTL-derived update schedule; `None` omits the
/// interval line — the exports have no TTL to derive one from, and
/// advertising a made-up schedule would mislead the client.
pub(crate) fn url_list_header_block(
    title: &str,
    interval_hours: Option<u64>,
    count: usize,
) -> String {
    // Title comes from a user-editable name: kill newlines so a crafted
    // name cannot inject forged comment lines into the output.
    let title = title.replace(['\n', '\r'], " ");
    let timestamp = fmt_rfc3339_utc(fumox_core::models::now_ts());
    let interval = interval_hours
        .map(|hours| format!("# profile-update-interval: {hours}\n"))
        .unwrap_or_default();
    format!(
        "# profile-title: {title}\n\
         {interval}\
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

/// The shortest member-source cache TTL in seconds, at least 1; a
/// profile with no member sources has no TTL to take the minimum of and
/// falls back to one hour. Both the render freshness window and the
/// `profile-update-interval` derive from this single computation over
/// the same members list.
fn min_member_ttl(members: &[(Source, Arc<CompiledPipeline>)]) -> i64 {
    members
        .iter()
        .map(|(s, _)| s.cache_ttl_seconds)
        .min()
        .unwrap_or(3600)
        .max(1)
}

/// Whole hours (mihomo convention), rounded up from a TTL in seconds, at
/// least 1. The one ceil-division every interval computation shares.
fn whole_hours(ttl_seconds: i64) -> i64 {
    (ttl_seconds.max(1) + 3599) / 3600
}

/// `profile-update-interval` in whole hours (mihomo convention), rounded
/// up from the shortest member-source TTL, at least 1.
fn update_interval_hours(members: &[(Source, Arc<CompiledPipeline>)]) -> String {
    whole_hours(min_member_ttl(members)).to_string()
}

/// The upstream HTTP status of the source's latest fetch attempt, for the
/// "return the original code" policy.
///
/// `None` means the real status is unknown (the fetch log could not be
/// read, or the last attempt recorded no HTTP status); the caller then
/// substitutes 502. That substitution is a guess, so it is logged: an
/// operator reading the log sees why the answer is 502 and not 404.
async fn last_http_status(state: &AppState, source_id: &str) -> Option<u16> {
    let rows = match fetch_log::recent_for_source(&state.pool, source_id, 1).await {
        Ok(rows) => rows,
        Err(err) => {
            tracing::warn!(
                source_id,
                error = %err,
                "the upstream status is unknown: the fetch log could not be read"
            );
            return None;
        }
    };
    let Some(status) = rows.first().and_then(|row| row.http_status) else {
        tracing::warn!(
            source_id,
            "the upstream status is unknown: the last fetch attempt recorded no HTTP status"
        );
        return None;
    };
    u16::try_from(status).ok()
}

/// The reply for a source whose last fetch failed with an unrecoverable
/// client error: the upstream status is the answer, and a cached snapshot
/// must not keep masking it.
///
/// Shared by `/sub` and `/src` so both classify the failure the same way.
async fn upstream_unavailable_reply(state: &AppState, source: &Source) -> ErrorReply {
    let upstream = last_http_status(state, &source.id).await.unwrap_or(502);
    ErrorReply::upstream_unavailable(
        StatusCode::from_u16(upstream).unwrap_or(StatusCode::BAD_GATEWAY),
        format!(
            "source \"{}\" unavailable: {}",
            source.name,
            source.last_error.as_deref().unwrap_or("HTTP client error")
        ),
    )
}

/// The token of an `Authorization: Bearer <token>` header.
///
/// The scheme is compared case-insensitively (RFC 7235 makes the scheme
/// case-insensitive, and clients spell it `bearer` as often as `Bearer`);
/// the token itself is taken as is, since it is compared verbatim against
/// the stored hash.
fn bearer_token(headers: &axum::http::HeaderMap) -> Option<String> {
    let value = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    let (scheme, token) = value.split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("bearer") {
        return None;
    }
    let token = token.trim();
    (!token.is_empty()).then(|| token.to_string())
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

/// [`error_response`] with a `Retry-After` header in whole seconds. The
/// refusals a client can do nothing about but wait (an exhausted rate-limit
/// window, a render still in progress) name the horizon, so a well-behaved
/// client backs off instead of spinning on the same instant.
pub(crate) fn error_response_with_retry(
    status: StatusCode,
    message: &str,
    retry_after_secs: u64,
) -> Response {
    let mut response = error_response(status, message);
    response
        .headers_mut()
        .insert(header::RETRY_AFTER, HeaderValue::from(retry_after_secs));
    response
}

/// Seconds a client is told to wait before retrying a 503 that came from
/// the render machinery (`render in progress` / `render timed out`): a few
/// seconds, far under [`WAIT_FOR_LEADER`], because the next attempt may
/// find the leader finished and the entry stored.
const RENDER_RETRY_AFTER_SECS: u64 = 5;

/// A published render failure served to a waiter: a 503 verdict
/// (`render timed out`) is retryable and names the horizon, any other
/// status is the upstream's answer and carries nothing extra.
fn retryable_render_error(status: StatusCode, message: &str) -> Response {
    if status == StatusCode::SERVICE_UNAVAILABLE {
        return error_response_with_retry(status, message, RENDER_RETRY_AFTER_SECS);
    }
    error_response(status, message)
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

    async fn test_state() -> (fumox_core::tempdir_lite::TempDir, AppState) {
        state_with_limits(PublicRateLimits::unlimited()).await
    }

    /// A state whose public rate limiters use the given window sizes, with
    /// the backing pool returned so tests can close or probe it directly.
    /// The scratch directory comes back too: the `TempDir` guard removes
    /// it on drop, so the binding has to outlive the test (`let (_dir,
    /// state) = …`), the same contract every core/admin test helper uses.
    async fn state_and_pool_with_limits(
        limits: PublicRateLimits,
    ) -> (fumox_core::tempdir_lite::TempDir, AppState, DbPool) {
        let dir = fumox_core::tempdir_lite::TempDir::new("serve-test");
        let cfg = fumox_core::config::DatabaseConfig {
            path: dir.path().join("test.db"),
            ..Default::default()
        };
        let pool = fumox_core::db::connect_pool(&cfg).await.unwrap();
        fumox_core::db::migrate(&pool).await.unwrap();
        let geo_cfg = fumox_core::config::GeoConfig {
            enabled: false,
            ..Default::default()
        };
        (
            dir,
            AppState::new(
                pool.clone(),
                Caches::new(),
                Arc::new(GeoResolver::new(&geo_cfg)),
                limits,
                Vec::new(),
                fumox_core::config::TrustedHeader::None,
                Vec::new(),
                crate::alive_export::ExportState::new(
                    fumox_core::config::ServerConfig::default().export_max_rows,
                    crate::alive_export::TokenCache::new(),
                ),
            ),
            pool,
        )
    }

    /// A state whose public rate limiters use the given window sizes.
    async fn state_with_limits(
        limits: PublicRateLimits,
    ) -> (fumox_core::tempdir_lite::TempDir, AppState) {
        let (dir, state, _pool) = state_and_pool_with_limits(limits).await;
        (dir, state)
    }

    /// A public app plus the dedicated `/healthz` pool over the same temp
    /// database, for the tests that exercise the liveness endpoint.
    async fn healthz_app(
        limits: PublicRateLimits,
    ) -> (
        fumox_core::tempdir_lite::TempDir,
        Router,
        DbPool,
        HealthPool,
    ) {
        let (dir, state, pool) = state_and_pool_with_limits(limits).await;
        let cfg = fumox_core::config::DatabaseConfig {
            path: dir.path().join("healthz.db"),
            ..Default::default()
        };
        let health = HealthPool::dedicated(&cfg).await.unwrap();
        let app = public_app(state, health.clone());
        (dir, app, pool, health)
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

    /// The same request, but the answer body instead of the status.
    async fn body_with_ip(app: Router, uri: &str, ip: &str) -> String {
        let mut request = Request::builder().uri(uri).body(Body::empty()).unwrap();
        request.extensions_mut().insert(ConnectInfo(
            format!("{ip}:1").parse::<SocketAddr>().unwrap(),
        ));
        let response = app.oneshot(request).await.unwrap();
        let bytes = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        String::from_utf8(bytes.to_vec()).unwrap()
    }

    /// Requests without connect info (embedded runtimes) must pass through
    /// uncounted: with a ceiling of 1, three extension-less requests all
    /// reach the handler instead of tripping the limiter.
    #[tokio::test]
    async fn requests_without_connect_info_pass_through_uncounted() {
        let (_dir, state) = state_with_limits(PublicRateLimits::new(1, 1)).await;
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
        let (_dir, app, _pool, _health) = healthz_app(PublicRateLimits::new(1, 1)).await;
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
        let (_dir, app, _pool, health) = healthz_app(PublicRateLimits::unlimited()).await;
        assert_eq!(
            get_with_ip(app.clone(), "/healthz", "10.0.0.1").await,
            StatusCode::OK
        );
        health.pool().close().await;
        assert_eq!(
            get_with_ip(app, "/healthz", "10.0.0.1").await,
            StatusCode::SERVICE_UNAVAILABLE
        );
    }

    /// A busy dedicated pool must read as 503 within the probe's own
    /// timeout, not hang: with one connection held, the acquire timeout
    /// (2 s) is what stops the answer, far under sqlx's default 30 s —
    /// the wait an orchestrator would read as a hang and answer with a
    /// restart anyway.
    #[tokio::test]
    async fn healthz_answers_503_when_the_dedicated_pool_is_busy() {
        let (_dir, app, _pool, health) = healthz_app(PublicRateLimits::unlimited()).await;
        // Hold the pool's only connection: the probe must not queue.
        let _held = health.pool().acquire().await.unwrap();
        let started = std::time::Instant::now();
        assert_eq!(
            get_with_ip(app, "/healthz", "10.0.0.1").await,
            StatusCode::SERVICE_UNAVAILABLE
        );
        assert!(
            started.elapsed() < Duration::from_secs(3),
            "the busy answer must come from the 2 s acquire timeout, took {:?}",
            started.elapsed()
        );
    }

    /// The answer names the geo state: geo enrichment is optional, but the
    /// operator has to be able to tell "off", "no databases" and "degraded"
    /// apart without reading the log.
    #[tokio::test]
    async fn healthz_names_the_geo_state() {
        let (_dir, app, _pool, _health) = healthz_app(PublicRateLimits::unlimited()).await;
        let body = body_with_ip(app, "/healthz", "10.0.0.1").await;
        assert!(
            body.starts_with("ok\n"),
            "the first line is the verdict: {body:?}"
        );
        assert!(
            body.contains("geo: off"),
            "the geo state must be named: {body:?}"
        );
    }

    /// A cold burst must collapse into one render: the first request claims
    /// the key, the rest wait for its guard and serve the stored entry.
    #[tokio::test]
    async fn concurrent_cold_requests_share_one_render() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let (_dir, state) = test_state().await;
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
        let (_dir, state) = test_state().await;
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
        let (_dir, state) = state_with_limits(PublicRateLimits::new(2, 1_000_000)).await;
        let app = router(state);
        assert_eq!(
            get_with_ip(app.clone(), "/sub/missing", "10.0.0.1").await,
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            get_with_ip(app.clone(), "/sub/missing", "10.0.0.1").await,
            StatusCode::NOT_FOUND
        );
        let mut request = Request::builder()
            .uri("/sub/missing")
            .body(Body::empty())
            .unwrap();
        request
            .extensions_mut()
            .insert(ConnectInfo("10.0.0.1:1".parse::<SocketAddr>().unwrap()));
        let response = app.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        // The refusal names its horizon: the seconds left of the window,
        // so a well-behaved client backs off instead of spinning.
        let retry_after = response
            .headers()
            .get(header::RETRY_AFTER)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<u64>().ok())
            .expect("a 429 must carry Retry-After");
        assert!(retry_after > 0, "the window is not over yet");
        // Another IP has its own window.
        assert_eq!(
            get_with_ip(app, "/sub/missing", "10.0.0.2").await,
            StatusCode::NOT_FOUND
        );
    }

    #[tokio::test]
    async fn failed_access_token_checks_are_limited() {
        let (_dir, state) = state_with_limits(PublicRateLimits::new(1_000_000, 2)).await;
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
        let (_dir, state) = state_with_limits(PublicRateLimits::new(3, 2)).await;
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

    /// End-to-end check that the shared `client_key` helper plumbs through
    /// the public router's `trusted_cidrs`: the mirror of the admin
    /// router's `rate_limit_uses_xff_ip_for_trusted_peer`, for the
    /// deployment where a reverse proxy sits in front of `/sub` exactly
    /// like in front of `/admin`. The claimed client IP a trusted proxy
    /// appended (the right-most XFF entry) drives the per-IP windows: two
    /// claimed clients behind the same trusted peer get independent
    /// auth-failure windows, and a client-forged XFF prefix cannot open a
    /// fresh one.
    ///
    /// The operator declares the header the proxy writes; without that
    /// declaration the claim is the client's own text and the peer is the
    /// key.
    #[tokio::test]
    async fn public_rate_limit_uses_xff_ip_for_trusted_peer() {
        let (_dir, mut state, _pool) =
            state_and_pool_with_limits(PublicRateLimits::new(1_000_000, 2)).await;
        state.trusted_cidrs = vec!["2.2.2.2/32".parse().unwrap()];
        state.trusted_header = fumox_core::config::TrustedHeader::Xff;
        let profile = make_profile(&state, "profXff000000", &[]).await;
        sqlx::query("UPDATE profiles SET access_token = 'secret' WHERE id = ?")
            .bind(&profile.id)
            .execute(&state.pool)
            .await
            .unwrap();
        let app = router(state);
        let uri = format!("/sub/{}?token=wrong", profile.id);

        // One GET whose peer sits inside the trusted CIDR and whose
        // X-Forwarded-For carries the claim, exactly what a trusted proxy
        // forwards. The extension is inserted the way
        // `into_make_service_with_connect_info` does in production.
        let send = |app: Router, xff: &str| {
            let mut request = Request::builder().uri(&uri).body(Body::empty()).unwrap();
            request
                .headers_mut()
                .insert("x-forwarded-for", xff.parse().unwrap());
            request
                .extensions_mut()
                .insert(ConnectInfo::<SocketAddr>("2.2.2.2:41000".parse().unwrap()));
            async move { app.oneshot(request).await.unwrap().status() }
        };

        // The two window slots of claimed client 1.2.3.4, then 429.
        assert_eq!(send(app.clone(), "1.2.3.4").await, StatusCode::FORBIDDEN);
        assert_eq!(send(app.clone(), "1.2.3.4").await, StatusCode::FORBIDDEN);
        assert_eq!(
            send(app.clone(), "1.2.3.4").await,
            StatusCode::TOO_MANY_REQUESTS
        );

        // Same trusted peer, different claimed client: a fresh window.
        assert_eq!(send(app.clone(), "5.5.5.5").await, StatusCode::FORBIDDEN);

        // Append-mode proxy: the trusted proxy appends the client IP it
        // observed to whatever prefix the client sent, so the header is
        // "<forged>, 9.9.9.9" and the right-most non-trusted entry keys
        // the window. Two failures exhaust that window...
        assert_eq!(
            send(app.clone(), "1.2.3.4, 9.9.9.9").await,
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            send(app.clone(), "6.6.6.6, 9.9.9.9").await,
            StatusCode::FORBIDDEN
        );
        // ...and re-forging the prefix yet again cannot reset it: the key
        // is still what the proxy appended, not the client-chosen text.
        assert_eq!(
            send(app, "7.7.7.7, 9.9.9.9").await,
            StatusCode::TOO_MANY_REQUESTS
        );
    }

    /// The failed-secret-check marker must ride on exactly the responses
    /// the public rate-limit middleware logs from: a wrong profile access
    /// token (403) and a wrong export capability token (404). A missing
    /// profile is not a secret failure and must not be marked, and a
    /// passing check carries no marker.
    #[tokio::test]
    async fn auth_failures_are_marked_for_the_rate_limit_middleware() {
        let (_dir, state) = test_state().await;
        make_source(&state, "srcA0000000").await;
        let mut profile = make_profile(&state, "profMark000000", &["srcA0000000"]).await;
        profile.access_token = Some("secret".to_string());
        profiles::update(&state.pool, &profile).await.unwrap();
        // Seed the export token so the wrong-token branch below is the
        // comparison failure, not a missing `meta` row (both answer 404,
        // only the first is an auth failure).
        let _export_token = state.export.token.current(&state.pool).await.unwrap();
        let app = router(state);

        let marked = |response: Response| {
            response
                .extensions()
                .get::<AuthFailure>()
                .map(|check| check.0)
        };

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/sub/profMark000000?token=wrong")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_eq!(marked(response), Some("profile access token"));

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/export/alive/wrong-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert_eq!(marked(response), Some("export capability token"));

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/sub/missing000000")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert_eq!(marked(response), None);

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/sub/profMark000000?token=secret")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(marked(response), None);
    }

    /// A fresh shared registry with the auth-failure parameters, the shape
    /// the production static is built with.
    fn auth_fail_registry() -> crate::security::WarnRegistry {
        crate::security::WarnRegistry::new(
            AUTH_FAIL_WARN_WINDOW,
            AUTH_FAIL_MAX_TRACKED,
            AUTH_FAIL_MAX_WARNS,
        )
    }

    /// One warn per client key per window, then debug: a token-guessing
    /// campaign must be visible without mirroring every request into the
    /// log.
    #[test]
    fn auth_fail_log_warns_once_per_client_per_window() {
        let mut log = auth_fail_registry();
        let t0 = Instant::now();
        assert!(log.should_warn("10.0.0.1", t0).0);
        assert!(!log.should_warn("10.0.0.1", t0).0);
        assert!(!log.should_warn("10.0.0.1", t0 + Duration::from_secs(60)).0);
        assert!(
            log.should_warn("10.0.0.1", t0 + Duration::from_secs(3_601))
                .0
        );
    }

    /// A flood of distinct client keys must stop producing warns at the
    /// per-window budget instead of turning the log into a mirror of the
    /// campaign, the tracked set stays bounded, and the first key the
    /// window swallowed is named at the rollover.
    #[test]
    fn auth_fail_log_is_bounded_under_a_flood() {
        let mut log = auth_fail_registry();
        let t0 = Instant::now();
        let warned = (0..AUTH_FAIL_MAX_TRACKED + 100)
            .filter(|i| log.should_warn(&format!("10.0.{i}.1"), t0).0)
            .count();
        // The per-window budget caps the warns, not the tracked set.
        assert_eq!(warned, AUTH_FAIL_MAX_WARNS as usize);
        assert_eq!(log.len_tracked(), AUTH_FAIL_MAX_TRACKED);
        // A tracked key stays quiet inside its window and warns again once
        // it has rolled over, handing back the summary that names what the
        // window swallowed.
        let (warn, summary) = log.should_warn("10.0.0.1", t0 + Duration::from_secs(3_601));
        assert!(warn);
        let summary = summary.expect("a window that suppressed keys must summarise them");
        let named = summary.suppressed.join(", ");
        assert!(named.contains("10.0.64.1"), "summary: {named:?}");
    }

    /// The missing-ConnectInfo warning never repeats: whatever test (or
    /// startup path) consumes the process's first call, every call after
    /// it is silent, so an embedded runtime does not mirror all of its
    /// traffic into the log.
    #[test]
    fn missing_connect_info_never_warns_twice() {
        warn_missing_connect_info_once();
        for _ in 0..3 {
            assert!(
                !warn_missing_connect_info_once(),
                "the warning must not repeat within one process"
            );
        }
    }

    /// A refusal by the shared window warns once per client key per
    /// window, then drops to debug (the same registry contract as the
    /// auth-failure log): a scraping burst stays visible without one line
    /// per 429.
    #[test]
    fn rate_limit_refusals_warn_once_per_client() {
        let mut log = crate::security::WarnRegistry::new(
            RATE_LIMIT_WARN_WINDOW,
            RATE_LIMIT_MAX_TRACKED,
            RATE_LIMIT_MAX_WARNS,
        );
        let t0 = Instant::now();
        assert!(log.should_warn("10.9.9.1", t0).0);
        assert!(!log.should_warn("10.9.9.1", t0).0);
        assert!(!log.should_warn("10.9.9.1", t0 + Duration::from_secs(600)).0);
        // A second client has its own window.
        assert!(log.should_warn("10.9.9.2", t0 + Duration::from_secs(600)).0);
        // And the first one warns again after the window rolled over.
        assert!(
            log.should_warn("10.9.9.1", t0 + Duration::from_secs(3_601))
                .0
        );
    }

    /// The per-window budget covers the aged branch too: a client that
    /// comes back after its own window elapsed spends the same budget as
    /// a new one, so a campaign that rotates through a small set of
    /// clients cannot out-warn the budget by waiting.
    #[test]
    fn auth_fail_log_budget_covers_the_aged_branch() {
        let mut log = auth_fail_registry();
        let t0 = Instant::now();
        // The first failure opens the window.
        assert!(log.should_warn("10.0.0.1", t0).0);
        // A second client, seen inside the same window.
        assert!(log.should_warn("10.0.0.2", t0 + Duration::from_secs(60)).0);

        // The next window opens: the client above is aged now.
        let t1 = t0 + Duration::from_secs(AUTH_FAIL_WARN_WINDOW.as_secs() + 1);
        assert!(log.should_warn("10.0.0.1", t1).0);
        // Spend the budget of the new window.
        for i in 0..(AUTH_FAIL_MAX_WARNS - 1) {
            assert!(log.should_warn(&format!("10.1.{i}.1"), t1).0);
        }
        assert_eq!(log.warns_emitted(), AUTH_FAIL_MAX_WARNS);

        // The aged client comes back while that window still holds: the
        // aged branch must respect the budget like every other branch.
        let t2 = t0 + Duration::from_secs(60 + AUTH_FAIL_WARN_WINDOW.as_secs() + 1);
        assert!(
            !log.should_warn("10.0.0.2", t2).0,
            "the aged branch must respect the warn budget"
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
                bare: false,
            }],
            raw_path: String::new(),
            raw_line: String::new(),
            canonical: None,
        }
    }

    /// The same entry under a scheme the structured formats cannot
    /// express.
    fn entry_with_scheme(scheme: Scheme, name: &str, host: &str, port: u16) -> ProxyEntry {
        let mut entry = entry(name, host, port);
        entry.scheme = scheme;
        entry
    }

    async fn make_source(state: &AppState, id: &str) -> Source {
        let now = fumox_core::models::now_ts();
        let source = Source {
            id: id.to_string(),
            slug: None,
            access_token: None,
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
            include_unknown_country: false,
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
        profiles::replace_sources(&state.pool, id, &composition)
            .await
            .unwrap();
        profile
    }

    /// `make_profile` plus a non-default output format, stored the way
    /// the admin save path writes it: the format is part of the profile
    /// before the first request renders it.
    async fn make_profile_with_format(
        state: &AppState,
        id: &str,
        source_ids: &[&str],
        format: OutputFormat,
    ) -> Profile {
        let mut profile = make_profile(state, id, source_ids).await;
        profile.output_format = format;
        profiles::update(&state.pool, &profile).await.unwrap();
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
            fumox_core::ingest::IngestPolicy::from_drop_gate(false),
        )
        .await
        .unwrap();
    }

    /// Move the proxies of one host — or every proxy at once when `host`
    /// is `None` — into `status`, standing in for the probe daemon that
    /// owns the column in production. The call sites used to hand-write
    /// the same UPDATE with a string status; the typed helper keeps the
    /// `ProxyStatus` → column mapping in one place.
    async fn set_status(state: &AppState, host: Option<&str>, status: ProxyStatus) {
        let query = match host {
            Some(host) => sqlx::query("UPDATE proxies SET status = ? WHERE host = ?")
                .bind(status.as_str())
                .bind(host),
            None => sqlx::query("UPDATE proxies SET status = ?").bind(status.as_str()),
        };
        query.execute(&state.pool).await.unwrap();
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

    /// The shared member-TTL / whole-hours helpers keep the values the
    /// former inline copies produced: the shortest member TTL wins, the
    /// empty member list falls back to one hour, hours round up, and
    /// render_sub's freshness cap sits below every fallback so the
    /// empty-profile fresh_until is unchanged.
    #[test]
    fn min_member_ttl_and_whole_hours_match_the_inline_predecessors() {
        fn source(ttl: i64) -> Source {
            let now = fumox_core::models::now_ts();
            Source {
                id: "ttl-src".to_string(),
                slug: None,
                access_token: None,
                name: "ttl source".to_string(),
                url: "https://example.com/list".to_string(),
                enabled: true,
                encoding: Default::default(),
                input_format: None,
                protocols: None,
                cache_ttl_seconds: ttl,
                tags: None,
                pipeline: None,
                headers: None,
                ip_family: None,
                created_at: now,
                updated_at: now,
                last_fetched_at: None,
                last_error: None,
                error_class: None,
            }
        }
        let members = |ttls: &[i64]| -> Vec<(Source, Arc<CompiledPipeline>)> {
            ttls.iter()
                .map(|&ttl| (source(ttl), Arc::new(CompiledPipeline::default())))
                .collect()
        };

        // The shortest member TTL wins; a non-positive TTL clamps to 1.
        assert_eq!(min_member_ttl(&members(&[7200, 1800, 3600])), 1800);
        assert_eq!(min_member_ttl(&members(&[0, 7200])), 1);
        // An empty member list falls back to the one-hour default.
        assert_eq!(min_member_ttl(&members(&[])), 3600);

        // Whole hours round up, at least one (the /src formula).
        assert_eq!(whole_hours(3600), 1);
        assert_eq!(whole_hours(1), 1);
        assert_eq!(whole_hours(0), 1);
        assert_eq!(whole_hours(3601), 2);
        // The /sub interval string over the same members list.
        assert_eq!(update_interval_hours(&members(&[7200, 1800])), "1");
        assert_eq!(update_interval_hours(&members(&[7201])), "3");
        assert_eq!(update_interval_hours(&members(&[])), "1");

        // render_sub's fresh_until uses the raw seconds under the 30 s
        // cap: the empty-member fallback (3600) caps to the same 30 s the
        // former inline 60-second default produced.
        assert_eq!(
            min_member_ttl(&members(&[])).min(RENDER_FRESHNESS_CAP_SECS),
            30
        );
    }

    /// Proxy lines of a url_list body: everything that is not one of the
    /// leading `#` metadata comments.
    fn proxy_lines(body: &str) -> usize {
        body.lines().filter(|l| !l.starts_with('#')).count()
    }

    #[tokio::test]
    async fn sub_serves_merged_deduped_output() {
        let (_dir, state) = test_state().await;
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

        let (status, headers, body) = get(router(state.clone()), "/sub/profA0000000").await;

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

        // A disabled member drops out of the merged output entirely: the
        // profile keeps serving, from its remaining sources only.
        let mut b = sources::get(&state.pool, "srcB0000000")
            .await
            .unwrap()
            .unwrap();
        b.enabled = false;
        b.updated_at = fumox_core::models::now_ts();
        sources::update_settings(&state.pool, &b).await.unwrap();
        // Saved means immediately effective: the save invalidates the /sub
        // cache, the same way the admin handler does.
        state.caches.invalidate_profile("profA0000000").await;
        let (status, _, body) = get(router(state), "/sub/profA0000000").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(proxy_lines(&body), 2, "srcA only: {body:?}");
        assert!(body.contains("h1.example.com:443"), "{body:?}");
        assert!(body.contains("h2.example.com:443"), "{body:?}");
        assert!(
            !body.contains("h3.example.com"),
            "the disabled source's proxies are not served: {body:?}"
        );
    }

    #[tokio::test]
    async fn profile_country_filter_follows_stored_geo_facts() {
        let (_dir, state) = test_state().await;
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
            set_status(&state, Some(host), ProxyStatus::Alive).await;
            sqlx::query("UPDATE proxies SET geo_country = ? WHERE host = ?")
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

    /// The quarantine verdict is a health fact, not a filter fact: a
    /// country allowlist that happens to keep only a quarantined row (the
    /// healthy rows sit outside the allowlist) must not report
    /// "all-proxies-quarantined" — the operator would chase the wrong
    /// thing. The statuses are therefore read before the country filter.
    #[tokio::test]
    async fn a_country_filter_that_keeps_only_a_quarantined_row_is_not_a_quarantine_warning() {
        let (_dir, state) = test_state().await;
        make_source(&state, "srcA0000000").await;
        let mut profile = make_profile(&state, "profA0000000", &["srcA0000000"]).await;
        profile.countries = vec!["US".into()];
        profiles::update(&state.pool, &profile).await.unwrap();
        ingest(
            &state,
            "srcA0000000",
            &[
                entry("de", "de1.example.com", 443),
                entry("us", "us1.example.com", 443),
            ],
        )
        .await;
        set_status(&state, Some("de1.example.com"), ProxyStatus::Alive).await;
        set_status(&state, Some("us1.example.com"), ProxyStatus::Quarantine).await;
        sqlx::query("UPDATE proxies SET geo_country = 'DE' WHERE host = 'de1.example.com'")
            .execute(&state.pool)
            .await
            .unwrap();
        sqlx::query("UPDATE proxies SET geo_country = 'US' WHERE host = 'us1.example.com'")
            .execute(&state.pool)
            .await
            .unwrap();

        let (status, headers, body) = get(router(state), "/sub/profA0000000").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(proxy_lines(&body), 0, "{body:?}");
        assert_eq!(
            header_str(&headers, "x-fumox-warning"),
            None,
            "the alive row is merely outside the allowlist: {body:?}"
        );
    }

    /// The profile title becomes an HTTP header value: a crafted name
    /// cannot split the header with an embedded line break, the same
    /// sanitisation the body's comment block applies.
    #[tokio::test]
    async fn a_line_break_in_the_profile_title_cannot_split_the_header() {
        let (_dir, state) = test_state().await;
        make_source(&state, "srcA0000000").await;
        let mut profile = make_profile(&state, "profA0000000", &["srcA0000000"]).await;
        profile.name = "evil\n# nodes count: 999".to_string();
        profiles::update(&state.pool, &profile).await.unwrap();
        ingest(&state, "srcA0000000", &[entry("a", "h1.example.com", 443)]).await;

        let (status, headers, _) = get(router(state), "/sub/profA0000000").await;
        assert_eq!(status, StatusCode::OK);
        let title = header_str(&headers, "profile-title").expect("the title must be served");
        assert_eq!(title, "evil # nodes count: 999", "{title:?}");
    }

    #[tokio::test]
    async fn unknown_or_disabled_profile_is_404() {
        let (_dir, state) = test_state().await;
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
        let (_dir, state) = test_state().await;
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
        let response = router(state.clone()).oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        // The scheme is case-insensitive: the token itself is not.
        let request = Request::builder()
            .uri("/sub/profA0000000")
            .header("Authorization", "bearer secret-token")
            .body(Body::empty())
            .unwrap();
        let response = router(state.clone()).oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        // Another scheme is not a bearer token at all.
        let request = Request::builder()
            .uri("/sub/profA0000000")
            .header("Authorization", "Basic secret-token")
            .body(Body::empty())
            .unwrap();
        let response = router(state).oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    /// The source's own access token guards `/src`, the twin of the
    /// profile check above: without (or with a wrong) token the endpoint
    /// answers 403 and marks the failure for the rate-limit middleware,
    /// with the right token it serves the live tiers. The tokens are
    /// independent: a profile token on the same source does not open
    /// `/src`.
    #[tokio::test]
    async fn source_access_token_is_enforced() {
        let (_dir, state) = test_state().await;
        make_source(&state, "srcA0000000").await;
        make_profile(&state, "profA0000000", &["srcA0000000"]).await;
        // The stored form is the hash, exactly what the admin save path
        // writes: the endpoint compares the hash of what was presented.
        sqlx::query("UPDATE sources SET access_token = ? WHERE id = ?")
            .bind(fumox_core::token::hash("secret-token"))
            .bind("srcA0000000")
            .execute(&state.pool)
            .await
            .unwrap();
        ingest(&state, "srcA0000000", &[entry("a", "h1.example.com", 443)]).await;
        // /src serves the live tiers only.
        set_status(&state, None, ProxyStatus::Alive).await;

        let (status, _, _) = get(router(state.clone()), "/src/srcA0000000").await;
        assert_eq!(status, StatusCode::FORBIDDEN);

        let (status, _, _) = get(router(state.clone()), "/src/srcA0000000?token=wrong-token").await;
        assert_eq!(status, StatusCode::FORBIDDEN);

        let (status, _, body) =
            get(router(state.clone()), "/src/srcA0000000?token=secret-token").await;
        assert_eq!(status, StatusCode::OK);
        assert!(body.contains("h1.example.com:443"), "{body:?}");

        let request = Request::builder()
            .uri("/src/srcA0000000")
            .header("Authorization", "Bearer secret-token")
            .body(Body::empty())
            .unwrap();
        let response = router(state.clone()).oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        // A source token set through the admin hash path verifies the
        // same way: the stored form is a hash, not the secret.
        let stored = sources::get(&state.pool, "srcA0000000")
            .await
            .unwrap()
            .unwrap();
        assert!(
            fumox_core::token::is_hashed(stored.access_token.as_deref().unwrap_or("")),
            "the token must be stored as a hash"
        );
    }

    #[tokio::test]
    async fn format_query_param_is_rejected() {
        let (_dir, state) = test_state().await;
        make_source(&state, "srcA0000000").await;
        make_profile(&state, "profA0000000", &["srcA0000000"]).await;
        let (status, _, _) = get(router(state.clone()), "/sub/profA0000000?format=clash").await;
        assert_eq!(status, StatusCode::BAD_REQUEST);

        // The single-source endpoint refuses it the same way.
        let (status, _, _) = get(router(state), "/src/srcA0000000?format=clash").await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn slug_resolves_like_token() {
        let (_dir, state) = test_state().await;
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
        let (_dir, state) = test_state().await;
        make_source(&state, "srcA0000000").await;
        make_profile(&state, "profA0000000", &["srcA0000000"]).await;
        ingest(&state, "srcA0000000", &[entry("a", "h1.example.com", 443)]).await;
        set_status(&state, None, ProxyStatus::Quarantine).await;

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
        let (_dir, state) = test_state().await;
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
        set_status(&state, None, ProxyStatus::Ready).await;

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
        let (_dir, state) = test_state().await;
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
        let (_dir, state) = test_state().await;
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
            fetch_log::FetchTiming::default(),
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
        let (_dir, state) = test_state().await;
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
            .processed_put_unguarded(
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
            fetch_log::FetchTiming::default(),
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
            let (_dir, state) = test_state().await;
            let mut source = make_source(&state, "srcA0000000").await;
            let mut pipeline = serde_json::json!({ "version": 1, "limit": { "count": 1 } });
            if let Some(sort) = sort.clone() {
                pipeline["sort"] = sort;
            }
            source.pipeline = Some(pipeline);
            sources::update_settings(&state.pool, &source)
                .await
                .unwrap();
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
            set_status(&state, None, ProxyStatus::Alive).await;

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
        let (_dir, state) = test_state().await;
        let mut source = make_source(&state, "srcA0000000").await;
        source.pipeline = Some(serde_json::json!({ "version": 1 }));
        sources::update_settings(&state.pool, &source)
            .await
            .unwrap();
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
        let (_dir, state) = test_state().await;
        // Source A: explicit sort *and* a cap of 2 over 3 proxies.
        let mut a = make_source(&state, "srcA0000000").await;
        a.pipeline = Some(serde_json::json!({
            "version": 1,
            "sort": { "by": "name" },
            "limit": { "count": 2 }
        }));
        sources::update_settings(&state.pool, &a).await.unwrap();
        // Source B: no cap of its own.
        let mut b = make_source(&state, "srcB0000000").await;
        b.pipeline = Some(serde_json::json!({ "version": 1 }));
        sources::update_settings(&state.pool, &b).await.unwrap();
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
        set_status(&state, None, ProxyStatus::Alive).await;

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
        let (_dir, state) = test_state().await;
        let mut source = make_source(&state, "srcA0000000").await;
        source.cache_ttl_seconds = 86_400;
        sources::update_settings(&state.pool, &source)
            .await
            .unwrap();
        make_profile(&state, "profA0000000", &["srcA0000000"]).await;
        ingest(&state, "srcA0000000", &[entry("a", "h1.example.com", 443)]).await;
        set_status(&state, None, ProxyStatus::Alive).await;

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
        let (_dir, state) = test_state().await;
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
        let (_dir, state) = test_state().await;
        make_source(&state, "srcA0000000").await;
        make_profile_with_format(
            &state,
            "profA0000000",
            &["srcA0000000"],
            OutputFormat::Base64,
        )
        .await;
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
        let (_dir, state) = test_state().await;
        make_source(&state, "srcA0000000").await;
        make_source(&state, "srcB0000000").await;
        ingest(
            &state,
            "srcA0000000",
            &[
                entry("a", "h1.example.com", 443),
                entry("u", "h2.example.com", 443),
            ],
        )
        .await;
        // A second source: its proxy belongs to another feed and must not
        // leak into this source's output.
        ingest(&state, "srcB0000000", &[entry("b", "h3.example.com", 443)]).await;
        // Only the first proxy passed the health check; the second stays
        // unknown (never probed).
        set_status(&state, Some("h1.example.com"), ProxyStatus::Alive).await;
        set_status(&state, Some("h3.example.com"), ProxyStatus::Alive).await;

        let (status, _, body) = get(router(state.clone()), "/src/srcA0000000").await;
        assert_eq!(status, StatusCode::OK);
        assert!(body.contains("h1.example.com"));
        // alive-only endpoint: untested proxies are not served.
        assert!(!body.contains("h2.example.com"));
        // Another source's proxy is not this source's output.
        assert!(!body.contains("h3.example.com"), "{body:?}");

        let (status, _, body) = get(router(state.clone()), "/src/srcB0000000").await;
        assert_eq!(status, StatusCode::OK);
        assert!(body.contains("h3.example.com"), "{body:?}");
        assert!(!body.contains("h1.example.com"), "{body:?}");

        let (status, _, _) = get(router(state), "/src/missing00000").await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    /// A source whose proxies have never been probed serves the
    /// documented empty feed: 200 with `nodes count: 0` and no proxy
    /// lines — "untested" is out of the live tiers, not an error.
    #[tokio::test]
    async fn an_untested_source_serves_an_empty_body_with_nodes_count_zero() {
        let (_dir, state) = test_state().await;
        make_source(&state, "srcA0000000").await;
        ingest(&state, "srcA0000000", &[entry("a", "h1.example.com", 443)]).await;
        // No status update: every proxy is still untested.

        let (status, _, body) = get(router(state), "/src/srcA0000000").await;
        assert_eq!(status, StatusCode::OK);
        assert!(body.contains("# nodes count: 0"), "{body:?}");
        assert_eq!(proxy_lines(&body), 0, "{body:?}");
    }

    /// The single-source endpoint reports the same verdict as the profile
    /// one: a source whose proxies are all out of the live tiers is a
    /// health fact, not an empty feed.
    #[tokio::test]
    async fn an_all_quarantined_source_warns_on_the_src_endpoint() {
        let (_dir, state) = test_state().await;
        make_source(&state, "srcA0000000").await;
        ingest(&state, "srcA0000000", &[entry("a", "h1.example.com", 443)]).await;
        set_status(&state, None, ProxyStatus::Quarantine).await;

        let (status, headers, body) = get(router(state), "/src/srcA0000000").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            header_str(&headers, "x-fumox-warning"),
            Some("all-proxies-quarantined")
        );
        assert_eq!(proxy_lines(&body), 0, "{body:?}");
    }

    #[tokio::test]
    async fn alive_export_is_404_before_initialization() {
        let (_dir, state) = test_state().await;
        let (status, _, _) = get(router(state), "/export/alive/anything0000").await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    /// The tail both export-tier tests assert: an unknown token is an
    /// ordinary 404, and one rotation kills the old link while the
    /// fresh one keeps serving. Returns the rotated token so the caller
    /// can still assert on the fresh link's body.
    async fn assert_token_lifecycle(state: &AppState, path_prefix: &str, token: &str) -> String {
        let app = router(state.clone());
        // An unknown token is an ordinary 404: the endpoint does not
        // disclose whether the link ever existed.
        let (status, _, _) = get(app.clone(), &format!("{path_prefix}/zzzzzzzzzzzz")).await;
        assert_eq!(status, StatusCode::NOT_FOUND);

        // Rotating the token kills the old link immediately.
        let fresh = state.export.token.rotate(&state.pool).await.unwrap();
        assert_ne!(fresh, token);
        let (status, _, _) = get(app.clone(), &format!("{path_prefix}/{token}")).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        let (status, _, _) = get(app, &format!("{path_prefix}/{fresh}")).await;
        assert_eq!(status, StatusCode::OK);
        fresh
    }

    #[tokio::test]
    async fn alive_export_link_serves_only_alive_proxies() {
        let (_dir, state) = test_state().await;
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
        set_status(&state, Some("h1.example.com"), ProxyStatus::Alive).await;
        set_status(&state, Some("h2.example.com"), ProxyStatus::Quarantine).await;

        let token = state.export.token.current(&state.pool).await.unwrap();
        let (status, _, body) = get(router(state.clone()), &format!("/export/alive/{token}")).await;
        assert_eq!(status, StatusCode::OK);
        assert!(body.contains("h1.example.com"), "{body:?}");
        // Quarantined and never-probed proxies stay out.
        assert!(!body.contains("h2.example.com"), "{body:?}");
        assert!(!body.contains("h3.example.com"), "{body:?}");

        // The ready link is the other tier: the quarantined and the
        // never-probed hosts stay out of it too.
        let (status, _, body) = get(router(state.clone()), &format!("/export/ready/{token}")).await;
        assert_eq!(status, StatusCode::OK);
        assert!(!body.contains("h2.example.com"), "{body:?}");
        assert!(!body.contains("h3.example.com"), "{body:?}");

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

        // Unknown token and rotation: the shared lifecycle tail.
        let fresh = assert_token_lifecycle(&state, "/export/alive", &token).await;
        let (status, _, body) = get(router(state), &format!("/export/alive/{fresh}")).await;
        assert_eq!(status, StatusCode::OK);
        assert!(body.contains("h1.example.com"), "{body:?}");
    }

    /// The ready export link: the same shared
    /// token, but only the tunnel-verified `ready` tier is served, an
    /// `alive` (unverified) proxy stays out, and rotation kills both links.
    #[tokio::test]
    async fn ready_export_link_serves_only_the_verified_tier() {
        let (_dir, state) = test_state().await;
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
        set_status(&state, Some("h1.example.com"), ProxyStatus::Alive).await;
        set_status(&state, Some("h2.example.com"), ProxyStatus::Ready).await;

        let token = state.export.token.current(&state.pool).await.unwrap();
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

        // The download variant attaches a dated file name.
        let (_, headers, _) = get(
            router(state.clone()),
            &format!("/export/ready/{token}?download=1"),
        )
        .await;
        let disposition = header_str(&headers, "content-disposition").unwrap_or_default();
        assert!(
            disposition.starts_with("attachment; filename=\"fumox-ready-"),
            "{disposition}"
        );

        // Unknown token and rotation: the shared lifecycle tail.
        let fresh = assert_token_lifecycle(&state, "/export/ready", &token).await;
        let (status, _, body) = get(router(state), &format!("/export/ready/{fresh}")).await;
        assert_eq!(status, StatusCode::OK);
        assert!(body.contains("h2.example.com"), "{body:?}");
    }

    #[test]
    fn url_list_header_block_sanitizes_and_formats() {
        // Newlines in a crafted profile name must not inject forged
        // comment lines into the output.
        let block = url_list_header_block("evil\n# nodes count: 999", Some(6), 42);
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
        // No interval to advertise: the line is left out entirely rather
        // than claiming a schedule that does not exist.
        let bare = url_list_header_block("plain", None, 7);
        assert!(
            !bare.contains("profile-update-interval"),
            "an export-style block must not claim an update interval: {bare:?}"
        );
        assert!(bare.contains("# nodes count: 7"), "{bare:?}");
    }

    #[tokio::test]
    async fn url_list_header_block_on_every_render_endpoint() {
        let (_dir, state) = test_state().await;
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
        // One proxy per tier: /sub and /src serve both live tiers, the two
        // exports are disjoint, so every endpoint's block documents its own
        // output.
        set_status(&state, Some("h1.example.com"), ProxyStatus::Alive).await;
        set_status(&state, Some("h2.example.com"), ProxyStatus::Ready).await;
        let token = state.export.token.current(&state.pool).await.unwrap();

        let app = router(state);
        for (uri, title, count) in [
            ("/sub/profA0000000", "Profile profA0000000", "2"),
            ("/src/srcA0000000", "source srcA0000000", "2"),
            (&format!("/export/alive/{token}"), "export/alive", "1"),
            (&format!("/export/ready/{token}"), "export/ready", "1"),
        ] {
            let (status, _, body) = get(app.clone(), uri).await;
            assert_eq!(status, StatusCode::OK, "{uri}");
            // The title line is the one that differs between the
            // endpoints; the exact format of the block's remaining lines
            // is url_list_header_block_sanitizes_and_formats's business.
            let lines: Vec<&str> = body.lines().collect();
            assert_eq!(
                lines[0],
                format!("# profile-title: {title}"),
                "{uri}: {body:?}"
            );
            assert_eq!(
                proxy_lines(&body),
                count.parse::<usize>().unwrap(),
                "{uri}: {body:?}"
            );
        }
    }

    #[tokio::test]
    async fn src_interval_rounds_ttl_up_to_whole_hours() {
        let (_dir, state) = test_state().await;
        let mut source = make_source(&state, "srcA0000000").await;
        // 90 minutes → 2 hours (rounded up, never 0).
        source.cache_ttl_seconds = 5400;
        sources::update_settings(&state.pool, &source)
            .await
            .unwrap();
        ingest(&state, "srcA0000000", &[entry("a", "h1.example.com", 443)]).await;
        set_status(&state, None, ProxyStatus::Alive).await;

        let (status, _, body) = get(router(state), "/src/srcA0000000").await;
        assert_eq!(status, StatusCode::OK);
        assert!(body.contains("# profile-update-interval: 2"), "{body:?}");
    }

    #[tokio::test]
    async fn processed_cache_serves_snapshot_until_invalidated() {
        let (_dir, state) = test_state().await;
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
        let (_dir, state) = test_state().await;
        let mut source = make_source(&state, "srcA0000000").await;
        source.pipeline = Some(serde_json::json!({
            "version": 1,
            "filter": { "protocols": ["trojan"] }
        }));
        sources::update_settings(&state.pool, &source)
            .await
            .unwrap();
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

    /// Both structured formats serve their own document shape: the
    /// content type matches, two servers sharing a name come out with
    /// the auto-suffix collision break, and the unsupported tuic entry —
    /// whose skip is asserted in this one place — does not grow a broken
    /// record: the document stays valid instead.
    #[tokio::test]
    async fn structured_profile_formats_serve_their_document_shape() {
        for (format, content_type, shape_key) in [
            (OutputFormat::Clash, "text/yaml; charset=utf-8", "proxies"),
            (
                OutputFormat::SingBox,
                "application/json; charset=utf-8",
                "outbounds",
            ),
        ] {
            let kind = format.as_str();
            let (_dir, state) = test_state().await;
            make_source(&state, "srcA0000000").await;
            make_profile_with_format(&state, "profA0000000", &["srcA0000000"], format).await;
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
            assert_eq!(status, StatusCode::OK, "{kind}");
            assert_eq!(
                header_str(&headers, "content-type"),
                Some(content_type),
                "{kind}"
            );
            assert!(
                !body.contains("h3.example.com"),
                "tuic must be skipped: {kind}: {body:?}"
            );
            // (name/tag, type, server) of every record, read from the
            // format's own document shape.
            let records: Vec<(String, String, String)> = match format {
                OutputFormat::Clash => {
                    let parsed: serde_norway::Value =
                        serde_norway::from_str(&body).expect("body must be valid YAML");
                    parsed[shape_key]
                        .as_sequence()
                        .expect("proxies must be a list")
                        .iter()
                        .map(|r| {
                            (
                                r["name"].as_str().unwrap_or_default().to_string(),
                                r["type"].as_str().unwrap_or_default().to_string(),
                                r["server"].as_str().unwrap_or_default().to_string(),
                            )
                        })
                        .collect()
                }
                OutputFormat::SingBox => {
                    let parsed: serde_json::Value =
                        serde_json::from_str(&body).expect("body must be valid JSON");
                    parsed[shape_key]
                        .as_array()
                        .expect("outbounds must be an array")
                        .iter()
                        .map(|r| {
                            (
                                r["tag"].as_str().unwrap_or_default().to_string(),
                                r["type"].as_str().unwrap_or_default().to_string(),
                                r["server"].as_str().unwrap_or_default().to_string(),
                            )
                        })
                        .collect()
                }
                // The table covers the structured formats only.
                OutputFormat::UriList | OutputFormat::Base64 => unreachable!(),
            };
            assert_eq!(records.len(), 2, "tuic must be skipped: {kind}: {body:?}");
            assert_eq!(records[0].0, "a", "{kind}: {body:?}");
            assert_eq!(records[0].1, "vless", "{kind}: {body:?}");
            assert_eq!(records[0].2, "h1.example.com", "{kind}: {body:?}");
            // The name collision is broken by the auto-suffix in both shapes.
            assert_eq!(records[1].0, "a (2)", "{kind}: {body:?}");
            assert_eq!(records[1].1, "vless", "{kind}: {body:?}");
        }
    }

    /// Every output format answers an all-quarantined profile with its
    /// own valid, proxy-free document and the quarantine warning header.
    #[tokio::test]
    async fn all_quarantined_structured_formats_serve_empty_valid_config() {
        for format in OutputFormat::all() {
            let kind = format.as_str();
            let (_dir, state) = test_state().await;
            make_source(&state, "srcA0000000").await;
            make_profile_with_format(&state, "profA0000000", &["srcA0000000"], *format).await;
            ingest(&state, "srcA0000000", &[entry("a", "h1.example.com", 443)]).await;
            set_status(&state, None, ProxyStatus::Quarantine).await;

            let (status, headers, body) = get(router(state), "/sub/profA0000000").await;
            assert_eq!(status, StatusCode::OK, "{kind}");
            assert_eq!(
                header_str(&headers, "x-fumox-warning"),
                Some("all-proxies-quarantined"),
                "{kind}"
            );
            // Dispatch on the enum itself: a new OutputFormat variant has
            // to answer here too, the missing arm is a compile error.
            match *format {
                OutputFormat::Clash => {
                    let parsed: serde_norway::Value =
                        serde_norway::from_str(&body).expect("valid YAML");
                    assert!(
                        parsed["proxies"].as_sequence().unwrap().is_empty(),
                        "{kind}: {body:?}"
                    );
                }
                OutputFormat::SingBox => {
                    let parsed: serde_json::Value =
                        serde_json::from_str(&body).expect("valid JSON");
                    assert!(
                        parsed["outbounds"].as_array().unwrap().is_empty(),
                        "{kind}: {body:?}"
                    );
                }
                OutputFormat::Base64 => {
                    // The blob must stay decodable to a bare list: decode
                    // it and make sure the quarantine left no proxy line.
                    let decoded = base64::engine::general_purpose::STANDARD
                        .decode(body.trim())
                        .expect("body must be valid base64");
                    let text = String::from_utf8(decoded).unwrap();
                    assert!(!text.contains("://"), "{kind}: {text:?}");
                }
                OutputFormat::UriList => {
                    assert!(body.contains("# nodes count: 0"), "{kind}: {body:?}");
                    assert!(body.lines().all(|l| l.starts_with('#')), "{kind}: {body:?}");
                }
            }
        }
    }

    /// A format that cannot express an entry must say so: the response
    /// names the warning and the count, and the document carries the
    /// count as a comment for a file that was copied out of the browser.
    #[tokio::test]
    async fn a_clash_profile_reports_the_entries_it_cannot_express() {
        let (_dir, state) = test_state().await;
        make_source(&state, "srcA0000000").await;
        make_profile_with_format(
            &state,
            "profA0000000",
            &["srcA0000000"],
            OutputFormat::Clash,
        )
        .await;
        ingest(
            &state,
            "srcA0000000",
            &[
                entry("a", "h1.example.com", 443),
                entry_with_scheme(Scheme::Naive, "n", "h2.example.com", 443),
            ],
        )
        .await;

        let (status, headers, body) = get(router(state), "/sub/profA0000000").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            header_str(&headers, "x-fumox-warning"),
            Some("incompatible-entries-skipped")
        );
        assert_eq!(header_str(&headers, "x-fumox-skipped"), Some("1"));
        assert!(
            body.starts_with("# skipped: 1 (unsupported scheme)"),
            "{body:?}"
        );
        // The entry the format can express is still served.
        assert!(body.contains("h1.example.com"), "{body:?}");
    }

    /// The stale verdict and the upstream status code are the same on both
    /// public endpoints: a source that is down is reported the same way
    /// whether the subscriber reads the profile or the source.
    #[tokio::test]
    async fn a_recoverable_error_serves_stale_on_both_endpoints() {
        for uri in ["/sub/profA0000000", "/src/srcA0000000"] {
            let (_dir, state) = test_state().await;
            make_source(&state, "srcA0000000").await;
            make_profile(&state, "profA0000000", &["srcA0000000"]).await;
            ingest(&state, "srcA0000000", &[entry("a", "h1.example.com", 443)]).await;
            // The live tiers are what the endpoints serve.
            set_status(&state, None, ProxyStatus::Alive).await;
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

            let (status, headers, body) = get(router(state), uri).await;
            assert_eq!(status, StatusCode::OK, "{uri}");
            assert!(body.contains("h1.example.com"), "{uri}: {body:?}");
            assert_eq!(header_str(&headers, "x-fumox-stale"), Some("true"), "{uri}");
        }
    }

    /// The unrecoverable verdict is the upstream's status code on both
    /// endpoints: a subscriber that reads the source directly must not be
    /// served a snapshot the profile endpoint has already given up on.
    #[tokio::test]
    async fn an_unrecoverable_error_answers_the_upstream_code_on_both_endpoints() {
        for uri in ["/sub/profA0000000", "/src/srcA0000000"] {
            let (_dir, state) = test_state().await;
            make_source(&state, "srcA0000000").await;
            make_profile(&state, "profA0000000", &["srcA0000000"]).await;
            ingest(&state, "srcA0000000", &[entry("a", "h1.example.com", 443)]).await;
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
                fetch_log::FetchTiming::default(),
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

            let (status, _, _) = get(router(state), uri).await;
            assert_eq!(status, StatusCode::NOT_FOUND, "{uri}");
        }
    }

    /// A successful revalidation replaces the cached snapshot: the stale
    /// body is served while the background render runs, and the entry
    /// holds the new content afterwards.
    #[tokio::test]
    async fn a_successful_revalidation_replaces_the_cached_snapshot() {
        let (_dir, state) = test_state().await;
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
            .processed_put_unguarded(
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

        // A new proxy arrives while the snapshot is stale.
        ingest(
            &state,
            "srcA0000000",
            &[
                entry("a", "h1.example.com", 443),
                entry("b", "h2.example.com", 443),
            ],
        )
        .await;

        // The stale snapshot is served immediately; the revalidation runs
        // in the background.
        let (status, _, body) = get(router(state.clone()), "/sub/profA0000000").await;
        assert_eq!(status, StatusCode::OK);
        assert!(body.contains("h1.example.com"), "{body:?}");
        assert!(
            !body.contains("h2.example.com"),
            "the stale body is served: {body:?}"
        );

        // The background render replaces the entry with the new content.
        let mut refreshed = None;
        for _ in 0..200 {
            let entry = state.caches.processed_get("sub:profA0000000").await;
            if let Some(entry) = entry
                && String::from_utf8_lossy(&entry.body).contains("h2.example.com")
            {
                refreshed = Some(entry);
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        let refreshed = refreshed.expect("the revalidation must replace the snapshot");
        assert!(
            String::from_utf8_lossy(&refreshed.body).contains("h2.example.com"),
            "{:?}",
            String::from_utf8_lossy(&refreshed.body)
        );
    }

    /// A leader that never finishes must not park the waiters behind it:
    /// the waiter answers "render in progress" when its own deadline
    /// passes, and the client retries.
    #[tokio::test(start_paused = true)]
    async fn a_wedged_render_leader_answers_render_in_progress() {
        let state = state_without_a_database();
        // A claim that is taken and never released: the leader is stuck.
        let claim = state
            .caches
            .begin_inline_render("sub:profA0000000", Vec::new())
            .await;
        assert!(matches!(claim, InlineClaim::Leader(_)));
        let _claim = claim;

        let response = serve_cached(
            &state,
            "sub:profA0000000".to_string(),
            || async { Vec::new() },
            || async { unreachable!("the waiter must not render") },
        )
        .await;
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        let retry_after = response
            .headers()
            .get(header::RETRY_AFTER)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<u64>().ok())
            .expect("a retryable 503 must carry Retry-After");
        assert!(retry_after > 0);
        let body = body_of(response).await;
        assert!(body.contains("render in progress"), "{body:?}");
    }

    /// A leader whose render outruns the deadline answers "render timed
    /// out" and lets the next request render again; the verdict is
    /// remembered for a moment, so a burst behind a broken upstream costs
    /// one render rather than one per waiter.
    #[tokio::test(start_paused = true)]
    async fn an_overrunning_render_answers_render_timed_out() {
        let state = state_without_a_database();
        let key = "sub:profA0000000";
        let renders = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let started = Arc::new(tokio::sync::Notify::new());

        let leader_state = state.clone();
        let leader_renders = renders.clone();
        let leader_started = started.clone();
        let leader = tokio::spawn(async move {
            serve_cached(
                &leader_state,
                key.to_string(),
                || async { Vec::new() },
                move || {
                    let renders = leader_renders.clone();
                    let started = leader_started.clone();
                    async move {
                        renders.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                        started.notify_one();
                        tokio::time::sleep(Duration::from_secs(WAIT_FOR_LEADER.as_secs() * 2))
                            .await;
                        Ok(Rendered {
                            status: 200,
                            body: Bytes::new(),
                            content_type: "text/plain; charset=utf-8".to_string(),
                            extra_headers: Vec::new(),
                            fresh_until: 0,
                            source_ids: Vec::new(),
                        })
                    }
                },
            )
            .await
        });
        started.notified().await;

        // The next request is the leader's waiter: it must not render on
        // its own, and it must not hang past the leader's verdict.
        let waiter_state = state.clone();
        let waiter = tokio::spawn(async move {
            serve_cached(
                &waiter_state,
                key.to_string(),
                || async { Vec::new() },
                || async { unreachable!("the waiter must not render") },
            )
            .await
        });

        let leader_response = leader.await.unwrap();
        assert_eq!(leader_response.status(), StatusCode::SERVICE_UNAVAILABLE);
        let leader_body = body_of(leader_response).await;
        assert!(leader_body.contains("render timed out"), "{leader_body:?}");

        let waiter_response = waiter.await.unwrap();
        assert_eq!(waiter_response.status(), StatusCode::SERVICE_UNAVAILABLE);
        let waiter_body = body_of(waiter_response).await;
        assert!(waiter_body.contains("render timed out"), "{waiter_body:?}");

        // The failed render's verdict is repeated instead of the same
        // failing render running again.
        let next_state = state.clone();
        let next = tokio::spawn(async move {
            serve_cached(
                &next_state,
                key.to_string(),
                || async { Vec::new() },
                || async { unreachable!("the failed verdict must be repeated") },
            )
            .await
        });
        let next_response = next.await.unwrap();
        assert_eq!(next_response.status(), StatusCode::SERVICE_UNAVAILABLE);
        let next_body = body_of(next_response).await;
        assert!(next_body.contains("render timed out"), "{next_body:?}");
        assert_eq!(
            renders.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "one render, not one per waiter"
        );
    }

    /// A state without a database. The paused clock of the timeout tests
    /// breaks the pool's acquire timeout: the timer fires in virtual time
    /// while the real I/O is still in flight. The tests that use it never
    /// query the database.
    fn state_without_a_database() -> AppState {
        let pool = fumox_core::db::DbPool::connect_lazy("sqlite::memory:").unwrap();
        let geo_cfg = fumox_core::config::GeoConfig {
            enabled: false,
            ..Default::default()
        };
        AppState::new(
            pool,
            Caches::new(),
            Arc::new(GeoResolver::new(&geo_cfg)),
            PublicRateLimits::unlimited(),
            Vec::new(),
            fumox_core::config::TrustedHeader::None,
            Vec::new(),
            crate::alive_export::ExportState::new(
                fumox_core::config::ServerConfig::default().export_max_rows,
                crate::alive_export::TokenCache::new(),
            ),
        )
    }

    /// The body of a response, as text.
    async fn body_of(response: Response) -> String {
        let bytes = axum::body::to_bytes(response.into_body(), 64 * 1024)
            .await
            .unwrap();
        String::from_utf8_lossy(&bytes).into_owned()
    }
}
