//! Public «all alive» / «all ready» export links (owner request, 2026-08-29;
//! the ready tier).
//!
//! `GET /export/alive/{token}` serves every currently-`alive` proxy that is
//! still linked to a source as a plain url_list, so the link can be pasted
//! straight into a client or used as an upstream source by another fumox.
//! `GET /export/ready/{token}` is the verified twin: it ships only the
//! `ready` tier, proxies whose latest T2 tunnel check succeeded. The tiers
//! are disjoint: alive = T1-alive without a fresh successful T2; ready =
//! the same proxy plus a confirmed tunnel.
//!
//! Both links share one capability token, a `nanoid(12)` generated on first
//! startup and kept in the `meta` table, the links are stable across
//! restarts, and the admin Import/Export screen displays them and can
//! rotate the token (both links die immediately: one secret, one rotation,
//! a shared fate by design).
//!
//! These are dedicated endpoints rather than synthetic source rows: a real
//! source would be picked up by the fetch scheduler, editable in the admin
//! CRUD, selectable into profiles and included in the config export, each
//! of which would need special-casing. The token in `meta` has none of
//! those interactions.
//!
//! Both links render the tier, so the body is cached for
//! [`EXPORT_TTL_SECS`] and served from the shared processed cache in
//! between, the same acceleration `/sub` and `/src` use. Unlike those two
//! endpoints the export has no source TTL to inherit and no invalidation
//! trigger (the probe owns the tiers), so a short fixed window bounds the
//! work per request while the tier can lag a status change by at most that
//! window. An expired entry is re-rendered inline, never served stale: a
//! download is a snapshot by definition and a quietly outdated one is worse
//! than a slow request.
//!
//! The window is a cache TTL, and the render behind a cold or expired
//! entry is single-flighted: a burst landing exactly on the boundary
//! renders once, the rest wait for the fresh entry. The database pool caps
//! how many *different* tiers render at the same time.
//!
//! The window bounds the *rate*; `[server].export_max_rows` bounds the
//! *size*.
//! `/sub` and `/src` inherit a per-source or per-profile cap from the
//! profile pipeline, these two links have no upstream cap, so without one
//! the render, the serialization and the response body all grow with the
//! whole tier on a public cacheable URL. The cap is applied in the SQL of
//! the backing query and only after the host and token gates.
//! A body the cap cut says so twice: the body carries a `# truncated:`
//! line, and the response carries `X-Fumox-Export-Total` (the size of the
//! tier) and `X-Fumox-Export-Truncated: true`, so a client that only has
//! the headers still tells a full list from a truncated one.

use crate::cache::{InlineClaim, Rendered};
use crate::host_gate;
use crate::serve::{self, AppState};
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::Response;
use fumox_core::db::DbPool;
use fumox_core::repo;
use fumox_core::repo::proxies;
use fumox_core::repo::proxies::ProxyRow;
use std::collections::HashMap;
use std::sync::{Arc, LazyLock, Mutex};
use std::time::{Duration, Instant};

/// `meta` key holding the capability token shared by both export links.
pub(crate) const TOKEN_KEY: &str = "alive_export_token";

/// How long a rendered export body is served from the processed cache.
/// The exports carry no per-source TTL, and the probe (not an ingest) is
/// what moves rows between tiers, so the window is fixed and short: long
/// enough to collapse a burst of downloads into one query, far shorter than
/// a probe cycle. One definition with the subscription endpoints: the same
/// [`crate::cache::RENDER_FRESHNESS_CAP_SECS`].
const EXPORT_TTL_SECS: i64 = crate::cache::RENDER_FRESHNESS_CAP_SECS;

/// How long a waiter queues behind the leader of an export render before
/// rendering the body itself. Kept a separate constant well under the
/// cache TTL above: the render is one bounded query, so this only ever
/// fires when the leader is stuck, and a waiter that renders itself still
/// finishes long before a client waiting on the cached window would.
const EXPORT_RENDER_DEADLINE: std::time::Duration = std::time::Duration::from_secs(5);

/// The two export tiers. A typed enum rather than a route string: the
/// backing queries and the response labels select on it exhaustively, so
/// adding a tier is a compiler-checked change, and no wildcard arm can
/// silently fold an unknown tier into the alive query.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Tier {
    /// `GET /export/alive/{token}`: T1-alive proxies without a fresh
    /// successful T2.
    Alive,
    /// `GET /export/ready/{token}`: proxies whose latest T2 tunnel check
    /// succeeded.
    Ready,
}

impl Tier {
    /// The tier's name in the cache key, the download file name and the
    /// logs — the fixed route literal.
    fn as_str(self) -> &'static str {
        match self {
            Tier::Alive => "alive",
            Tier::Ready => "ready",
        }
    }
}

/// The capability token shared by both export links, kept in process
/// memory.
///
/// `meta` stays the source of truth across restarts; the copy here spares
/// the public export endpoint a database read on every request. The admin
/// panel and the public listener share one instance, so a rotation is seen
/// by both at once — a rotation that only reached the panel would leave the
/// old link working on the public endpoint.
#[derive(Clone, Default)]
pub struct TokenCache {
    token: Arc<tokio::sync::RwLock<Option<String>>>,
}

impl TokenCache {
    pub fn new() -> Self {
        Self::default()
    }

    /// The token the export links are checked against. The stored one is
    /// read on the first call and kept in memory afterwards; a missing row
    /// is created on the spot.
    pub async fn current(&self, pool: &DbPool) -> fumox_core::Result<String> {
        if let Some(token) = self.token.read().await.clone() {
            return Ok(token);
        }
        let mut guard = self.token.write().await;
        if let Some(token) = guard.as_ref() {
            return Ok(token.clone());
        }
        let token = match repo::meta_get(pool, TOKEN_KEY).await? {
            Some(token) => token,
            None => {
                let token = fumox_core::models::new_id();
                repo::meta_set(pool, TOKEN_KEY, &token).await?;
                token
            }
        };
        *guard = Some(token.clone());
        Ok(token)
    }

    /// Issue a fresh token; both export links stop working immediately.
    pub async fn rotate(&self, pool: &DbPool) -> fumox_core::Result<String> {
        let token = fumox_core::models::new_id();
        repo::meta_set(pool, TOKEN_KEY, &token).await?;
        *self.token.write().await = Some(token.clone());
        Ok(token)
    }
}

/// The settings of the two export links, grouped so they travel through
/// [`crate::serve::AppState`] as one field: the row ceiling of one body
/// and the capability token the links check. The token is kept in process
/// memory (see [`TokenCache`]), so a rotation reaches both listeners at
/// once.
#[derive(Clone)]
pub struct ExportState {
    /// Row ceiling of one `/export/alive` / `/export/ready` body
    /// (`[server].export_max_rows`). The two links have no upstream cap of
    /// their own, so this is the only thing bounding one public request.
    pub max_rows: u32,
    /// The capability token shared by both links.
    pub token: TokenCache,
}

impl ExportState {
    pub fn new(max_rows: u32, token: TokenCache) -> Self {
        Self { max_rows, token }
    }
}

/// UTC calendar date for export file names (shared with the config export).
pub(crate) fn export_date() -> String {
    const FMT: &[time::format_description::FormatItem<'static>] =
        time::macros::format_description!("[year]-[month]-[day]");
    time::OffsetDateTime::now_utc()
        .format(FMT)
        .unwrap_or_else(|_| "export".to_string())
}

/// Window within which a repeated host-gate rejection stays at debug
/// level. The gate runs before the token check on a public route, so the
/// log line has to serve two opposite extremes: a misconfigured allowlist
/// (the operator's own domain missing) must be visible immediately, while
/// a scan sweeping random `Host` headers must not get one warn per
/// request.
const HOST_REJECT_WARN_WINDOW: Duration = Duration::from_secs(3_600);

/// Distinct rejected hosts kept in the registry, bounding the memory a
/// flood of distinct random hosts could pin. Hitting this count does not
/// silence new hosts: it bounds tracking, not warnings (see
/// [`crate::security::WarnRegistry::should_warn`]).
const HOST_REJECT_MAX_TRACKED: usize = 1_024;

/// Warns this registry may emit per [`HOST_REJECT_WARN_WINDOW`]. Past it,
/// rejections drop to debug, but the hosts the window swallowed are named
/// in a summary when the window rolls over.
const HOST_REJECT_MAX_WARNS: u32 = 64;

/// Per-host warn registry for the host gate, the shared bounded registry
/// of [`crate::security::WarnRegistry`] keyed by host.
static HOST_REJECT_LOG: LazyLock<Mutex<crate::security::WarnRegistry>> = LazyLock::new(|| {
    Mutex::new(crate::security::WarnRegistry::new(
        HOST_REJECT_WARN_WINDOW,
        HOST_REJECT_MAX_TRACKED,
        HOST_REJECT_MAX_WARNS,
    ))
});

/// Whether a host-gate rejection should be logged at warn rather than
/// debug (see [`HostRejectLog::should_warn`]). Logs the window summary when
/// one came due, before the verdict for the request in hand.
fn should_warn_host_reject(host: &str, now: Instant) -> bool {
    let (warn, summary) = HOST_REJECT_LOG
        .lock()
        .unwrap_or_else(|poison| poison.into_inner())
        .should_warn(host, now);
    if let Some(summary) = summary {
        let named = summary.suppressed.join(", ");
        let unnamed = summary.suppressed_total - summary.suppressed.len() as u64;
        let mut message = format!(
            "host-gate rejections: {} dropped to debug this window, \
             suppressed hosts: {named}",
            summary.suppressed_total
        );
        if unnamed > 0 {
            message.push_str(&format!(", and {unnamed} more"));
        }
        tracing::warn!(message);
    }
    warn
}

/// `GET /export/alive/{token}`, the url_list of all alive proxies, or 404
/// for an unknown token (the endpoint does not disclose whether the link
/// ever existed). `?download=1` attaches the body as a file.
pub async fn serve(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(token): Path<String>,
    Query(params): Query<HashMap<String, String>>,
) -> Response {
    serve_tier(state, headers, token, params, Tier::Alive).await
}

/// `GET /export/ready/{token}`, the url_list of all ready (T2-verified)
/// proxies, the tunnel-verified twin of [`serve()`].
pub async fn serve_ready(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(token): Path<String>,
    Query(params): Query<HashMap<String, String>>,
) -> Response {
    serve_tier(state, headers, token, params, Tier::Ready).await
}

/// Shared body of both export links. `tier` selects the backing query and
/// the response labels; it is a fixed route variant ([`Tier`]), never
/// user input.
async fn serve_tier(
    state: AppState,
    headers: HeaderMap,
    token: String,
    params: HashMap<String, String>,
    tier: Tier,
) -> Response {
    // Origin check first (before token check): the response on rejection is
    // identical to a wrong token (404 "link not found") so probing cannot
    // distinguish "bad host" from "bad token".
    if let Err(err) = host_gate::validate_request_host(&headers, &state.allowed_hosts) {
        let host = headers
            .get(header::HOST)
            .and_then(|value| value.to_str().ok())
            .unwrap_or("<missing>");
        if should_warn_host_reject(host, Instant::now()) {
            tracing::warn!(
                host,
                error = %err,
                "alive-export: host rejected by the allowlist"
            );
        } else {
            tracing::debug!(host, error = %err, "alive-export: host rejected by the allowlist");
        }
        return serve::error_response(StatusCode::NOT_FOUND, "link not found");
    }
    let expected = match state.export.token.current(&state.pool).await {
        Ok(expected) => expected,
        Err(err) => {
            tracing::error!(error = %err, "export token lookup failed");
            return serve::error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal server error",
            );
        }
    };
    // Constant-time comparison: the token is a public capability link.
    if !crate::security::ct_eq(&expected, &token) {
        let mut response = serve::error_response(StatusCode::NOT_FOUND, "link not found");
        // Flag the failure for the public rate-limit middleware, which
        // logs it with the client key it computed (this handler never sees
        // the peer address); the token value itself is never logged.
        response
            .extensions_mut()
            .insert(serve::AuthFailure("export capability token"));
        return response;
    }
    // The ?format= refusal comes after both gates: a request the host gate
    // or the token rejected answers with the gate's own 404, so the 400
    // (the one visible feature difference) is only reachable with a valid
    // token.
    if params.contains_key("format") {
        return serve::error_response(
            StatusCode::BAD_REQUEST,
            "the ?format= parameter is not supported: the export is always a plain url_list",
        );
    }

    let rendered = match cached_render(&state, tier).await {
        Ok(rendered) => rendered,
        Err(err) => {
            tracing::error!(tier = tier.as_str(), error = %err, "export render failed");
            return serve::error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal server error",
            );
        }
    };

    let mut response = serve::to_response(&rendered);
    if params.contains_key("download") {
        let date = export_date();
        // ASCII-only value (fixed prefix + calendar date), try_from cannot fail.
        if let Ok(value) = header::HeaderValue::try_from(format!(
            "attachment; filename=\"fumox-{}-{date}.txt\"",
            tier.as_str()
        )) {
            response
                .headers_mut()
                .insert(header::CONTENT_DISPOSITION, value);
        }
    }
    response
}

/// Processed-cache key of one export tier.
fn cache_key(tier: Tier) -> String {
    format!("export:{}", tier.as_str())
}

/// The rendered export body, cached for [`EXPORT_TTL_SECS`].
///
/// "Cached for the window" is the guarantee; a burst that observes the
/// expired entry is single-flighted through the cache's inline-render
/// claim: the first requester renders, the rest wake when its claim ends
/// and serve the fresh entry (or re-render, when the leader stored none).
/// The exports deliberately never serve a stale body, not even to a
/// waiter, so only the claim is shared, never a half-rendered body.
///
/// The claim carries no sources and the put is not generation-guarded: an
/// export rendering answers only from proxy statuses and its entry sits
/// outside per-source invalidation (see `source_ids` in [`render_tier`]),
/// so no invalidation can ever supersede a fill.
///
/// The row cap is applied here, *after* the host and token gates in
/// [`serve_tier`]: a rejected request must not be able to tell a capped
/// render from a full one, and it must not cost a query at all.
async fn cached_render(state: &AppState, tier: Tier) -> Result<Arc<Rendered>, fumox_core::Error> {
    let key = cache_key(tier);
    // An expired entry falls through to the re-render below rather than
    // serving a stale download.
    if let Some(cached) = state.caches.processed_get(&key).await
        && cached.is_fresh(fumox_core::models::now_ts())
    {
        return Ok(cached);
    }
    // Single-flight, but for one round only. A waiter gives the leader
    // [`EXPORT_RENDER_DEADLINE`] and then renders itself rather than
    // queueing behind a leader that is not finishing, which is what an
    // unbounded `changed().await` did. Export keys carry an empty
    // `source_ids`, so no per-source invalidation can race the put and the
    // claim is here purely to collapse a download burst.
    match state.caches.begin_inline_render(&key, Vec::new()).await {
        InlineClaim::Leader(claim) => {
            let rendered = render_tier(&state.pool, tier, state.export.max_rows).await?;
            let stored = state.caches.processed_put_unguarded(&key, rendered).await;
            drop(claim);
            Ok(stored)
        }
        InlineClaim::Wait(mut ended) => {
            match tokio::time::timeout(EXPORT_RENDER_DEADLINE, ended.changed()).await {
                Ok(_) => {
                    if let Some(cached) = state.caches.processed_get(&key).await
                        && cached.is_fresh(fumox_core::models::now_ts())
                    {
                        return Ok(cached);
                    }
                }
                Err(_) => {
                    // The leader did not finish inside the deadline: this
                    // request renders on its own. The line says so, because
                    // a leader that never ends turns every waiter into a
                    // render of its own.
                    tracing::warn!(
                        tier = tier.as_str(),
                        "export render single-flight deadline exceeded, rendering independently"
                    );
                }
            }
            let rendered = render_tier(&state.pool, tier, state.export.max_rows).await?;
            Ok(state.caches.processed_put_unguarded(&key, rendered).await)
        }
        InlineClaim::Failed { .. } => {
            // The export render never publishes a verdict (a failing
            // export fails its own request instead), so this branch is
            // unreachable today. It renders independently rather than
            // answering with a verdict that belongs to another endpoint.
            let rendered = render_tier(&state.pool, tier, state.export.max_rows).await?;
            Ok(state.caches.processed_put_unguarded(&key, rendered).await)
        }
    }
}

/// Read the tier and serialize it as a url_list, bounded to `limit` rows
/// in SQL ([`cached_render`] passes the configured
/// `[server].export_max_rows`). Same metadata
/// comments as `/sub` and `/src` (they document the file when the HTTP
/// headers are lost to a copy-paste), except the interval: the exports
/// have no fetch TTL to derive an update schedule from and the probe owns
/// the tiers, so the block carries no interval hint at all rather than a
/// made-up one.
///
/// The `nodes count` header reports how many rows this body carries, which
/// is *not* the same as how many the tier holds: a capped render reports the
/// cap. A truncated body therefore says so in its own header — the tier
/// size is looked up in the same request and written into the body, so a
/// download states what it left out instead of looking like a complete
/// tier.
///
/// The same two facts travel as response headers, because a body that
/// left the browser has no headers left: `X-Fumox-Export-Total` names the
/// size of the tier and `X-Fumox-Export-Truncated: true` marks a body the
/// cap cut. A client therefore tells a full list from a truncated one
/// without parsing the `nodes count` comment.
async fn render_tier(pool: &DbPool, tier: Tier, limit: u32) -> Result<Rendered, fumox_core::Error> {
    // The backing query clamps the limit to at least one row; the
    // comparison below has to count with the same number.
    let limit = limit.max(1);
    let rows: Vec<ProxyRow> = match tier {
        Tier::Ready => proxies::list_ready(pool, limit).await?,
        Tier::Alive => proxies::list_alive(pool, limit).await?,
    };
    let mut lines: Vec<String> = Vec::with_capacity(rows.len());
    let mut skipped: Vec<i64> = Vec::new();
    for row in rows {
        match row.to_entry() {
            Ok(entry) => lines.push(fumox_core::parsers::serialize(&entry)),
            Err(_) => skipped.push(row.id),
        }
    }
    // One line for the whole render: a tier of thousands of corrupt rows
    // would otherwise write thousands of warnings into the log.
    if !skipped.is_empty() {
        let examples: Vec<i64> = skipped.iter().take(5).copied().collect();
        tracing::warn!(
            tier = tier.as_str(),
            skipped = skipped.len(),
            examples = ?examples,
            "corrupt proxy rows skipped in export render"
        );
    }
    let mut header =
        serve::url_list_header_block(&format!("export/{}", tier.as_str()), None, lines.len());
    // The tier size is looked up in the same request: a body that holds
    // exactly the cap may be truncated or may be the whole tier, and only
    // the size tells the two apart.
    let total = match tier {
        Tier::Ready => proxies::count_ready(pool).await?,
        Tier::Alive => proxies::count_alive(pool).await?,
    };
    let mut extra_headers = vec![("X-Fumox-Export-Total".to_string(), total.to_string())];
    if total > i64::from(limit) {
        header.push_str(&format!(
            "# truncated: showing {limit} of {total} — raise [server].export_max_rows\n"
        ));
        extra_headers.push(("X-Fumox-Export-Truncated".to_string(), "true".to_string()));
        warn_truncation(tier.as_str(), limit, total);
    }
    let body = format!("{header}{}", lines.join("\n"));
    Ok(Rendered {
        status: 200,
        body: body.into_bytes().into(),
        content_type: "text/plain; charset=utf-8".to_string(),
        extra_headers,
        fresh_until: fumox_core::models::now_ts() + EXPORT_TTL_SECS,
        // No source contributed to this rendering, so the per-source
        // invalidation must never touch the export entries.
        source_ids: Vec::new(),
    })
}

/// When a tier is larger than the cap, the render says so once per
/// window: the export is rendered once per [`EXPORT_TTL_SECS`] anyway, but
/// a leader that times out renders a second time, and a warning per
/// render would turn one oversized tier into a log stream.
fn warn_truncation(tier: &str, cap: u32, total: i64) {
    static LAST_WARNING: LazyLock<Mutex<HashMap<String, Instant>>> =
        LazyLock::new(|| Mutex::new(HashMap::new()));
    let now = Instant::now();
    let mut last = LAST_WARNING
        .lock()
        .unwrap_or_else(|poison| poison.into_inner());
    if let Some(previous) = last.get(tier)
        && now.duration_since(*previous) < Duration::from_secs(EXPORT_TTL_SECS as u64)
    {
        return;
    }
    last.insert(tier.to_string(), now);
    tracing::warn!(tier, cap, total, "export render truncated at the row cap");
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt;

    /// The shipped default of `[server].export_max_rows`, spelled the way
    /// production gets it so a test that pins a different cap is visibly
    /// deviating from the config rather than from a literal.
    fn default_cap() -> u32 {
        fumox_core::config::ServerConfig::default().export_max_rows
    }

    /// Bootstrap a fresh app + persist a known alive-export token into the
    /// `meta` table so the test can address `/export/alive/{token}` without
    /// rotating. The state comes back too, for tests that inspect the
    /// processed cache behind the export. `export_max_rows` is the
    /// `[server]` row ceiling the endpoint renders with.
    async fn app_with_token(
        allowed_hosts: Vec<String>,
        export_max_rows: u32,
    ) -> (axum::Router, String, AppState) {
        let dir =
            std::env::temp_dir().join(format!("fumox-alive-test-{}", fumox_core::models::new_id()));
        std::fs::create_dir_all(&dir).unwrap();
        let cfg = fumox_core::config::DatabaseConfig {
            path: dir.join("test.db"),
            ..Default::default()
        };
        let pool = fumox_core::db::connect_pool(&cfg).await.unwrap();
        fumox_core::db::migrate(&pool).await.unwrap();

        let token = "abcdef123456".to_string();
        fumox_core::repo::meta_set(&pool, TOKEN_KEY, &token)
            .await
            .unwrap();

        let state = crate::serve::AppState::new(
            pool,
            crate::cache::Caches::new(),
            std::sync::Arc::new(fumox_core::geo::GeoResolver::new(
                &fumox_core::config::GeoConfig {
                    enabled: false,
                    ..Default::default()
                },
            )),
            crate::serve::PublicRateLimits::unlimited(),
            Vec::new(),
            fumox_core::config::TrustedHeader::None,
            allowed_hosts,
            ExportState::new(export_max_rows, TokenCache::new()),
        );
        let app = crate::serve::router(state.clone());
        (app, token, state)
    }

    /// One GET of an export link with an explicit `Host` header (`None`
    /// sends none, the deny-by-default case), body as text. The one
    /// driver of every host-gate test, so the request shape exists once.
    async fn get_with_host(
        app: &axum::Router,
        uri: &str,
        host: Option<&str>,
    ) -> (StatusCode, String) {
        let mut request = Request::builder().uri(uri);
        if let Some(host) = host {
            request = request.header(header::HOST, host);
        }
        let response = app
            .clone()
            .oneshot(request.body(Body::empty()).unwrap())
            .await
            .unwrap();
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
            .await
            .unwrap();
        (status, String::from_utf8_lossy(&bytes).into_owned())
    }

    /// One GET of an export link without a `Host` header, body as text.
    async fn get(app: axum::Router, uri: &str) -> (StatusCode, String) {
        get_with_host(&app, uri, None).await
    }

    #[tokio::test]
    async fn non_allowlisted_host_returns_404_even_with_valid_token() {
        let (app, token, _state) =
            app_with_token(vec!["vpn.example.com".to_string()], default_cap()).await;
        let (status, body) = get_with_host(
            &app,
            &format!("/export/alive/{token}"),
            Some("evil.example"),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        // Identical body to a wrong-token response so probing cannot
        // distinguish the two.
        assert_eq!(body, "link not found\n");
    }

    #[tokio::test]
    async fn allowlisted_host_returns_200() {
        let (app, token, _state) =
            app_with_token(vec!["vpn.example.com".to_string()], default_cap()).await;
        let (status, _) = get_with_host(
            &app,
            &format!("/export/alive/{token}"),
            Some("vpn.example.com"),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
    }

    /// Deny-by-default: a request with no `Host` header must be rejected
    /// when an allowlist is configured, and the response body must match
    /// the wrong-token response byte-for-byte so probing cannot
    /// distinguish "missing host" from "wrong token".
    #[tokio::test]
    async fn missing_host_with_allowlist_returns_404_with_identical_body() {
        let (app, token, _state) =
            app_with_token(vec!["vpn.example.com".to_string()], default_cap()).await;
        let (status, body) = get_with_host(&app, &format!("/export/alive/{token}"), None).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(body, "link not found\n");
    }

    /// Two distinct failure modes (bad host vs bad token) must yield
    /// byte-identical responses, same status, same body, same
    /// Content-Type, so an attacker cannot probe the link to learn
    /// whether the host check or the token check rejected the request.
    /// This test drives the raw responses because the Content-Type header
    /// is part of the equality; [`get_with_host`] returns status + body.
    #[tokio::test]
    async fn bad_host_and_bad_token_return_byte_equal_bodies_and_content_type() {
        let (app, token, _state) =
            app_with_token(vec!["vpn.example.com".to_string()], default_cap()).await;
        let valid = format!("/export/alive/{token}");

        // Bad host, valid token.
        let bad_host_req = Request::builder()
            .method("GET")
            .uri(&valid)
            .header(header::HOST, "evil.example")
            .body(Body::empty())
            .unwrap();
        let bad_host_resp = app.clone().oneshot(bad_host_req).await.unwrap();

        // Valid host, bad token.
        let bad_token_req = Request::builder()
            .method("GET")
            .uri("/export/alive/wrong")
            .header(header::HOST, "vpn.example.com")
            .body(Body::empty())
            .unwrap();
        let bad_token_resp = app.oneshot(bad_token_req).await.unwrap();

        assert_eq!(bad_host_resp.status(), bad_token_resp.status());
        assert_eq!(bad_host_resp.status(), StatusCode::NOT_FOUND);
        assert_eq!(
            bad_host_resp.headers().get(header::CONTENT_TYPE),
            bad_token_resp.headers().get(header::CONTENT_TYPE)
        );
        let bad_host_body = axum::body::to_bytes(bad_host_resp.into_body(), 1024)
            .await
            .unwrap();
        let bad_token_body = axum::body::to_bytes(bad_token_resp.into_body(), 1024)
            .await
            .unwrap();
        assert_eq!(bad_host_body, bad_token_body);
    }

    /// Operator ergonomics: a host written in mixed case in the allowlist
    /// must still match a request whose Host header arrives in a different
    /// case (canonicalization lowercases before comparison).
    #[tokio::test]
    async fn case_mismatch_in_allowlist_succeeds() {
        let (app, token, _state) =
            app_with_token(vec!["vpn.example.com".to_string()], default_cap()).await;
        let (status, _) = get_with_host(
            &app,
            &format!("/export/alive/{token}"),
            Some("VPN.EXAMPLE.COM"),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
    }

    /// The `?format=` refusal sits behind both gates: a request a gate
    /// rejects answers with the gate's own 404 ("link not found"), so the
    /// parameter cannot be probed through a rejection, and the 400 — the
    /// one visible feature difference — is reachable only with a valid
    /// token.
    #[tokio::test]
    async fn format_query_refusal_sits_behind_the_host_and_token_gates() {
        let (app, token, _state) =
            app_with_token(vec!["vpn.example.com".to_string()], default_cap()).await;
        // Bad host: the host gate answers first, 404.
        let (status, body) = get_with_host(
            &app,
            "/export/alive/anything?format=json",
            Some("evil.example"),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(body, "link not found\n");
        // Valid host, wrong token: the token gate answers, also 404.
        let (status, body) = get_with_host(
            &app,
            "/export/alive/wrong?format=json",
            Some("vpn.example.com"),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(body, "link not found\n");
        // Only a valid token gets as far as the 400.
        let (status, body) = get_with_host(
            &app,
            &format!("/export/alive/{token}?format=json"),
            Some("vpn.example.com"),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(body.contains("not supported"), "{body:?}");
    }

    /// The export body is a full read + re-serialize of the whole tier, so
    /// it is rendered once per window and served from the processed cache
    /// afterwards, like `/sub` and `/src` next to it. Marking a live proxy
    /// dead in the database must not change the body until the window
    /// expires: without the cache every request re-read the tier.
    #[tokio::test]
    async fn export_body_is_rendered_once_per_window() {
        let (app, token, state) = app_with_token(Vec::new(), default_cap()).await;
        let source = fumox_core::models::Source {
            id: "srcA0000000".to_string(),
            slug: None,
            access_token: None,
            name: "source".to_string(),
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
            created_at: fumox_core::models::now_ts(),
            updated_at: fumox_core::models::now_ts(),
            last_fetched_at: None,
            last_error: None,
            error_class: None,
        };
        fumox_core::repo::sources::create(&state.pool, &source)
            .await
            .unwrap();
        let entry = fumox_core::models::ProxyEntry {
            scheme: fumox_core::models::Scheme::Vless,
            name: "a".to_string(),
            host: "h1.example.com".to_string(),
            port: 443,
            credential: "3e4d70e5-7ec9-48f9-a4e0-48c44c6063fd".to_string(),
            params: Vec::new(),
            raw_path: String::new(),
            raw_line: String::new(),
            canonical: None,
        };
        fumox_core::repo::proxies::reconcile_source(
            &state.pool,
            &source.id,
            std::slice::from_ref(&entry),
            &[],
            fumox_core::models::now_ts(),
            fumox_core::ingest::IngestPolicy::from_drop_gate(false),
        )
        .await
        .unwrap();
        sqlx::query("UPDATE proxies SET status = 'alive'")
            .execute(&state.pool)
            .await
            .unwrap();

        let uri = format!("/export/alive/{token}");
        let (status, first) = get(app.clone(), &uri).await;
        assert_eq!(status, StatusCode::OK);
        assert!(first.contains("h1.example.com"), "{first:?}");
        assert!(
            state.caches.processed_get("export:alive").await.is_some(),
            "the rendered export must be cached under its own key"
        );

        // The proxy dies; inside the window the cached body is served.
        sqlx::query("UPDATE proxies SET status = 'quarantine'")
            .execute(&state.pool)
            .await
            .unwrap();
        let (status, cached) = get(app.clone(), &uri).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(cached, first, "the window must serve one rendering");

        // Past the window the tier is re-read: a download is never served
        // stale.
        state
            .caches
            .processed_put_unguarded(
                "export:alive",
                Rendered {
                    status: 200,
                    body: first.into_bytes().into(),
                    content_type: "text/plain; charset=utf-8".to_string(),
                    extra_headers: Vec::new(),
                    fresh_until: 0,
                    source_ids: Vec::new(),
                },
            )
            .await;
        let (status, fresh) = get(app, &uri).await;
        assert_eq!(status, StatusCode::OK);
        assert!(!fresh.contains("h1.example.com"), "{fresh:?}");
    }

    /// The window bounds the render *rate*, not its *size*: the backing
    /// query used to be an unbounded `SELECT p.*` + `fetch_all`, and
    /// every row was serialized into the body, so a large pool turned one
    /// public request into an unbounded read, an unbounded render and an
    /// unbounded body. The cap is applied in the SQL of the backing query
    /// (a `LIMIT ?`, not a post-read truncate), it truncates the stable
    /// id order, and the `nodes count` header reports what the body
    /// actually carries so a truncated download documents itself.
    #[tokio::test]
    async fn export_body_is_capped_in_sql() {
        let pool = fumox_core::db::connect_pool(&fumox_core::config::DatabaseConfig {
            path: std::env::temp_dir()
                .join(format!("fumox-alive-cap-{}", fumox_core::models::new_id()))
                .join("test.db"),
            ..Default::default()
        })
        .await
        .unwrap();
        fumox_core::db::migrate(&pool).await.unwrap();
        // Five linked alive rows, ids 1..5.
        seed_alive_tier(&pool, "srcC0000000", 5).await;

        // Under the cap the whole tier is served.
        let full = render_tier(&pool, Tier::Alive, 100).await.unwrap();
        let full_body = String::from_utf8(full.body.to_vec()).unwrap();
        assert!(full_body.contains("# nodes count: 5"), "{full_body:?}");
        assert!(full_body.contains("tier5.example.com"), "{full_body:?}");

        // At the cap the body is truncated, and it truncates the stable id
        // order: the two lowest ids, not an arbitrary slice.
        let capped = render_tier(&pool, Tier::Alive, 2).await.unwrap();
        let body = String::from_utf8(capped.body.to_vec()).unwrap();
        assert!(body.contains("# nodes count: 2"), "{body:?}");
        assert!(body.contains("tier1.example.com"), "{body:?}");
        assert!(body.contains("tier2.example.com"), "{body:?}");
        assert!(!body.contains("tier3.example.com"), "{body:?}");

        // The admin badge stays uncapped: the operator must be able to
        // see that the tier is bigger than what the export ships.
        assert_eq!(proxies::count_alive(&pool).await.unwrap(), 5);
    }

    /// A body that hits the cap says so: the tier size is written into the
    /// header, so a download states what it left out instead of looking
    /// like a complete tier.
    #[tokio::test]
    async fn a_truncated_export_states_what_it_left_out() {
        let pool = fumox_core::db::connect_pool(&fumox_core::config::DatabaseConfig {
            path: std::env::temp_dir()
                .join(format!(
                    "fumox-alive-trunc-{}",
                    fumox_core::models::new_id()
                ))
                .join("test.db"),
            ..Default::default()
        })
        .await
        .unwrap();
        fumox_core::db::migrate(&pool).await.unwrap();
        seed_alive_tier(&pool, "srcF0000000", 5).await;

        // Under the cap: the whole tier ships and says nothing about a
        // truncation that did not happen.
        let full = render_tier(&pool, Tier::Alive, 100).await.unwrap();
        let body = String::from_utf8(full.body.to_vec()).unwrap();
        assert!(!body.contains("truncated"), "{body:?}");

        // Exactly the tier size: nothing was left out, so nothing is
        // announced.
        let exact = render_tier(&pool, Tier::Alive, 5).await.unwrap();
        let body = String::from_utf8(exact.body.to_vec()).unwrap();
        assert!(!body.contains("truncated"), "{body:?}");

        // At the cap with a larger tier: the body names the cap, the tier
        // size and the setting to raise.
        let capped = render_tier(&pool, Tier::Alive, 2).await.unwrap();
        let body = String::from_utf8(capped.body.to_vec()).unwrap();
        assert!(body.contains("# truncated: showing 2 of 5"), "{body:?}");
        assert!(body.contains("[server].export_max_rows"), "{body:?}");
    }

    /// The same two facts travel as response headers: a body that left
    /// the browser has no headers left, and a client must be able to tell
    /// a full list from a truncated one without parsing the `nodes count`
    /// comment.
    #[tokio::test]
    async fn a_truncated_export_marks_itself_in_the_headers() {
        // Capped: the flag and the size of the tier travel with the body.
        let (app, token, state) = app_with_token(Vec::new(), 2).await;
        seed_alive_tier(&state.pool, "srcH0000000", 5).await;
        let response = app
            .oneshot(
                Request::builder()
                    .uri(format!("/export/alive/{token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get("x-fumox-export-truncated").unwrap(),
            "true"
        );
        assert_eq!(response.headers().get("x-fumox-export-total").unwrap(), "5");

        // The whole tier: no truncation flag, but the size is still there.
        let (app, token, state) = app_with_token(Vec::new(), 500_000).await;
        seed_alive_tier(&state.pool, "srcI0000000", 5).await;
        let response = app
            .oneshot(
                Request::builder()
                    .uri(format!("/export/alive/{token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert!(
            response.headers().get("x-fumox-export-truncated").is_none(),
            "a whole tier must not be marked as truncated"
        );
        assert_eq!(response.headers().get("x-fumox-export-total").unwrap(), "5");
    }

    /// Rows that cannot be rendered are skipped, and the render says so in
    /// one line: a tier of thousands of corrupt rows would otherwise write
    /// thousands of warnings into the log.
    #[tokio::test]
    async fn corrupt_rows_are_skipped_and_reported_once() {
        let pool = fumox_core::db::connect_pool(&fumox_core::config::DatabaseConfig {
            path: std::env::temp_dir()
                .join(format!(
                    "fumox-alive-corrupt-{}",
                    fumox_core::models::new_id()
                ))
                .join("test.db"),
            ..Default::default()
        })
        .await
        .unwrap();
        fumox_core::db::migrate(&pool).await.unwrap();
        seed_alive_tier(&pool, "srcG0000000", 2).await;
        // Two rows that cannot be turned into an entry: an unknown scheme
        // and params JSON the converter cannot decode. (An out-of-range
        // port used to be the second class; the schema CHECK, migration
        // 0018, makes such rows unstorable.)
        for (fingerprint, scheme, params) in [
            ("fp-bad-1", "nosuchscheme", None),
            ("fp-bad-2", "vless", Some("{oops")),
        ] {
            sqlx::query(
                "INSERT INTO proxies (fingerprint, scheme, name, host, port, credential, params, status, created_at, updated_at)
                 VALUES (?1, ?2, 'n', 'bad.example.com', 443, 'c', ?3, 'alive', 1, 1)",
            )
            .bind(fingerprint)
            .bind(scheme)
            .bind(params)
            .execute(&pool)
            .await
            .unwrap();
            sqlx::query(
                "INSERT INTO proxy_source_links (proxy_id, source_id, seen_at)
                 SELECT id, 'srcG0000000', 1 FROM proxies WHERE fingerprint = ?1",
            )
            .bind(fingerprint)
            .execute(&pool)
            .await
            .unwrap();
        }

        let captured = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let make_writer = captured.clone();
        struct Captured(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);
        impl std::io::Write for Captured {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                self.0.lock().unwrap().extend_from_slice(buf);
                Ok(buf.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let subscriber = tracing_subscriber::fmt()
            .with_ansi(false)
            .with_max_level(tracing::Level::WARN)
            .with_writer(move || Captured(std::sync::Arc::clone(&make_writer)))
            .finish();
        let _guard = tracing::subscriber::set_default(subscriber);

        let rendered = render_tier(&pool, Tier::Alive, 100).await.unwrap();
        let body = String::from_utf8(rendered.body.to_vec()).unwrap();
        // The good rows still ship.
        assert!(body.contains("tier1.example.com"), "{body:?}");
        assert!(!body.contains("bad.example.com"), "{body:?}");

        let log = String::from_utf8(captured.lock().unwrap().clone()).unwrap();
        let lines = log
            .lines()
            .filter(|line| line.contains("corrupt proxy rows skipped in export render"))
            .count();
        assert_eq!(lines, 1, "one line for the whole render: {log}");
        assert!(log.contains("skipped=2"), "{log}");
    }

    /// Five linked `alive` rows under one source, ids 1..5.
    async fn seed_alive_tier(pool: &fumox_core::db::DbPool, source_id: &str, count: i64) {
        sqlx::query(
            "INSERT INTO sources (id, name, url, enabled, encoding, cache_ttl_seconds, created_at, updated_at)
             VALUES (?1, 'tier', 'https://example.com', 1, 'auto', 3600, 1, 1)",
        )
        .bind(source_id)
        .execute(pool)
        .await
        .unwrap();
        for i in 1..=count {
            sqlx::query(
                "INSERT INTO proxies (fingerprint, scheme, name, host, port, credential, status, created_at, updated_at)
                 VALUES (?1, 'vless', 'n', ?2, 443, 'c', 'alive', 1, 1)",
            )
            .bind(format!("fp-tier-{i}"))
            .bind(format!("tier{i}.example.com"))
            .execute(pool)
            .await
            .unwrap();
            sqlx::query(
                "INSERT INTO proxy_source_links (proxy_id, source_id, seen_at) VALUES (?1, ?2, 1)",
            )
            .bind(i)
            .bind(source_id)
            .execute(pool)
            .await
            .unwrap();
        }
    }

    /// The ceiling is an operator setting, not a constant: `[server].export_max_rows`
    /// is what the link renders with, so an operator whose tier exceeds the
    /// shipped 50 000 raises it in `config/app.toml` (or via
    /// `FUMOX_SERVER__EXPORT_MAX_ROWS`) and gets the whole tier. With the
    /// cap hard-coded, both a lowered and a raised setting were ignored and
    /// the body always carried up to 50 000 rows.
    #[tokio::test]
    async fn export_cap_follows_the_configured_setting() {
        // Lowered: the body is truncated to the configured ceiling.
        let (app, token, state) = app_with_token(Vec::new(), 2).await;
        seed_alive_tier(&state.pool, "srcD0000000", 5).await;
        let (status, body) = get(app, &format!("/export/alive/{token}")).await;
        assert_eq!(status, StatusCode::OK);
        assert!(body.contains("# nodes count: 2"), "{body:?}");
        assert!(body.contains("tier1.example.com"), "{body:?}");
        assert!(!body.contains("tier3.example.com"), "{body:?}");

        // Raised above the tier: the same five rows all ship, so the
        // setting is not a hard-coded 50 000 in disguise.
        let (app, token, state) = app_with_token(Vec::new(), 500_000).await;
        seed_alive_tier(&state.pool, "srcE0000000", 5).await;
        let (status, body) = get(app, &format!("/export/alive/{token}")).await;
        assert_eq!(status, StatusCode::OK);
        assert!(body.contains("# nodes count: 5"), "{body:?}");
        assert!(body.contains("tier5.example.com"), "{body:?}");
    }

    /// The cap lives behind the gates, not in front of them: a request
    /// rejected by the host gate (or a wrong token) must not be able to
    /// distinguish a capped render from a full one, and must not cost a
    /// render at all. The cap is enforced inside `cached_render`, which
    /// both gate branches return before reaching.
    #[tokio::test]
    async fn cap_is_applied_after_the_host_and_token_gates() {
        let (app, token, _state) =
            app_with_token(vec!["vpn.example.com".to_string()], default_cap()).await;
        // The tier is empty here, so a leak would be a body difference,
        // not a count: what is asserted is that both rejection paths keep
        // the byte-identical "link not found" body they had before the
        // cap existed, i.e. the cap added no new observable on them.
        for (uri, host) in [
            (format!("/export/alive/{token}"), Some("evil.example")),
            (
                "/export/alive/wrong-token".to_string(),
                Some("vpn.example.com"),
            ),
        ] {
            let (status, body) = get_with_host(&app, &uri, host).await;
            assert_eq!(status, StatusCode::NOT_FOUND, "{uri}");
            assert_eq!(body, "link not found\n", "{uri}");
        }
    }

    /// `meta` is the source of truth across restarts: a token written
    /// there directly (a restart, or a hand-seeded deployment) is what a
    /// cold [`TokenCache`] serves, and a rotation is what a second cold
    /// cache picks up afterwards.
    #[tokio::test]
    async fn the_token_cache_picks_up_a_preexisting_meta_token() {
        let (_app, _token, state) = app_with_token(Vec::new(), default_cap()).await;
        fumox_core::repo::meta_set(&state.pool, TOKEN_KEY, "existing")
            .await
            .unwrap();

        // A cold cache reads the stored token instead of minting its own.
        let cache = TokenCache::new();
        assert_eq!(
            cache.current(&state.pool).await.unwrap(),
            "existing",
            "a preexisting meta token must survive the cache's first read"
        );

        // Rotation replaces it, and a second cold cache (the restart
        // case) picks up the rotated value from `meta`.
        let rotated = cache.rotate(&state.pool).await.unwrap();
        let fresh = TokenCache::new();
        assert_eq!(fresh.current(&state.pool).await.unwrap(), rotated);
    }

    /// The wait branch of the single-flight: a request that arrives while
    /// the leader holds the claim wakes when the claim ends and serves the
    /// fresh entry the leader stored, without rendering its own copy.
    #[tokio::test]
    async fn a_waiter_serves_the_entry_the_leader_stored() {
        let (app, token, state) = app_with_token(Vec::new(), default_cap()).await;
        // The tier is empty on purpose: the body below is the leader's
        // entry, and an independent (empty-tier) render would not carry
        // it, so the assertion really pins the wait path.
        let claim = match state
            .caches
            .begin_inline_render("export:alive", Vec::new())
            .await
        {
            InlineClaim::Leader(claim) => claim,
            InlineClaim::Wait(_) => panic!("a fresh cache must hand out the leader claim"),
            InlineClaim::Failed { .. } => panic!("a fresh cache has no failure verdict"),
        };
        let uri = format!("/export/alive/{token}");
        let waiter = tokio::spawn(async move { get_with_host(&app, &uri, None).await });
        // Give the request time to reach the claim: without the pause it
        // could arrive after the drop below and render independently.
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        // The leader finishes: a fresh entry goes in, then the claim ends
        // and every waiter wakes.
        state
            .caches
            .processed_put_unguarded(
                "export:alive",
                Rendered {
                    status: 200,
                    body: b"the-leaders-entry.example\n".to_vec().into(),
                    content_type: "text/plain; charset=utf-8".to_string(),
                    extra_headers: Vec::new(),
                    fresh_until: fumox_core::models::now_ts() + EXPORT_TTL_SECS,
                    source_ids: Vec::new(),
                },
            )
            .await;
        drop(claim);
        let (status, body) = tokio::time::timeout(std::time::Duration::from_secs(5), waiter)
            .await
            .expect("the waiter must finish within 5s")
            .unwrap();
        assert_eq!(status, StatusCode::OK);
        assert!(
            body.contains("the-leaders-entry.example"),
            "the waiter must serve the entry the leader stored: {body:?}"
        );
    }

    /// A fresh shared registry with the host-gate parameters, the shape
    /// the production static is built with.
    fn host_reject_registry() -> crate::security::WarnRegistry {
        crate::security::WarnRegistry::new(
            HOST_REJECT_WARN_WINDOW,
            HOST_REJECT_MAX_TRACKED,
            HOST_REJECT_MAX_WARNS,
        )
    }

    /// One warn per rejected host per window, then debug: a misconfigured
    /// allowlist must be visible without mirroring every request of the
    /// operator's own traffic into the log.
    #[test]
    fn host_reject_warns_once_per_host_per_window() {
        let mut log = host_reject_registry();
        let t0 = Instant::now();
        assert!(log.should_warn("warn-once.example", t0).0);
        assert!(!log.should_warn("warn-once.example", t0).0);
        assert!(
            !log.should_warn("warn-once.example", t0 + Duration::from_secs(60))
                .0
        );
        assert!(
            log.should_warn("warn-once.example", t0 + Duration::from_secs(3_601))
                .0
        );
    }

    /// A flood of distinct fresh hosts must stop producing warns at the
    /// per-window budget instead of turning the log into a mirror of the
    /// scan, and the hosts it swallowed are named when the window rolls.
    #[test]
    fn host_reject_log_is_bounded_under_a_flood() {
        let mut log = host_reject_registry();
        let t0 = Instant::now();
        let warned = (0..HOST_REJECT_MAX_TRACKED + 100)
            .filter(|i| log.should_warn(&format!("flood-{i}.example"), t0).0)
            .count();
        // The per-window budget caps the warns, not the tracked set: the
        // log must not mirror the scan.
        assert_eq!(warned, HOST_REJECT_MAX_WARNS as usize);
        assert_eq!(log.len_tracked(), HOST_REJECT_MAX_TRACKED);
        // A tracked host stays quiet inside its window...
        assert!(!log.should_warn("flood-0.example", t0).0);
        // ...and warns again once the window has rolled over, handing back
        // the summary that names what the window swallowed.
        let (warn, summary) = log.should_warn("flood-0.example", t0 + Duration::from_secs(3_601));
        assert!(warn);
        let summary = summary.expect("a window that suppressed hosts must summarise them");
        let named = summary.suppressed.join(", ");
        assert!(named.contains("flood-64.example"), "summary: {named:?}");
    }

    /// The registry must not let a flood of tracked hosts hide the one that
    /// matters: the operator's own domain, rejected on every request under
    /// a misconfigured allowlist. It arrives after the budget is spent and
    /// still has to be named.
    #[test]
    fn a_misconfigured_allowlist_is_still_named_after_a_flood() {
        let mut log = host_reject_registry();
        let t0 = Instant::now();
        for i in 0..HOST_REJECT_MAX_WARNS {
            assert!(log.should_warn(&format!("flood-{i}.example"), t0).0);
        }
        // Budget spent: this one is suppressed, not warned...
        let (warn, _) = log.should_warn("operator.example", t0);
        assert!(!warn);
        // ...and the rollover summary is what surfaces it.
        let (warn, summary) = log.should_warn("operator.example", t0 + Duration::from_secs(3_601));
        assert!(warn);
        let named = summary.map(|s| s.suppressed.join(", ")).unwrap_or_default();
        assert!(
            named.contains("operator.example"),
            "the suppressed host must be named, got {named:?}"
        );
    }

    /// The tracked set stays bounded no matter how many distinct hosts
    /// arrive, which is the memory half of the cap.
    #[test]
    fn tracking_stays_bounded_across_windows() {
        let mut log = host_reject_registry();
        let t0 = Instant::now();
        for i in 0..HOST_REJECT_MAX_TRACKED * 3 {
            log.should_warn(&format!("h-{i}.example"), t0);
            assert!(log.len_tracked() <= HOST_REJECT_MAX_TRACKED);
        }
    }

    /// The per-window budget covers a host that comes back after its own
    /// quiet window: a flood of *repeat* visitors must not be able to
    /// spend the window's warns either.
    #[test]
    fn a_returning_host_does_not_bypass_the_window_budget() {
        let mut log = host_reject_registry();
        let t0 = Instant::now();
        // A host that warns early in the window.
        assert!(log.should_warn("repeat.example", t0).0);
        // The window budget is spent by the other hosts.
        for i in 0..HOST_REJECT_MAX_WARNS - 1 {
            assert!(log.should_warn(&format!("flood-{i}.example"), t0).0);
        }
        // The window rolls over and is spent again by other hosts.
        let t1 = t0 + Duration::from_secs(3_601);
        for i in 0..HOST_REJECT_MAX_WARNS {
            assert!(log.should_warn(&format!("second-{i}.example"), t1).0);
        }
        // The host that warned before comes back after its own quiet
        // window: it must not warn past the budget.
        let (warn, _) = log.should_warn("repeat.example", t1 + Duration::from_secs(1));
        assert!(!warn, "a returning host must not spend the window's warns");
    }
}
