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

use crate::admin::host_gate;
use crate::cache::{InlineClaim, Rendered};
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
/// a probe cycle.
const EXPORT_TTL_SECS: i64 = 30;

/// How long a waiter queues behind the leader of an export render before
/// rendering the body itself. The render is one bounded query, so this only
/// ever fires when the leader is stuck.
const EXPORT_RENDER_DEADLINE: std::time::Duration = std::time::Duration::from_secs(30);

/// The current token, generating and persisting one on first use. Called
/// from `main` at startup; every later call is a single meta read.
pub async fn ensure_token(pool: &DbPool) -> fumox_core::Result<String> {
    if let Some(token) = repo::meta_get(pool, TOKEN_KEY).await? {
        return Ok(token);
    }
    let token = fumox_core::models::new_id();
    repo::meta_set(pool, TOKEN_KEY, &token).await?;
    Ok(token)
}

/// Issue a fresh token; both export links stop working immediately.
pub async fn rotate_token(pool: &DbPool) -> fumox_core::Result<String> {
    let token = fumox_core::models::new_id();
    repo::meta_set(pool, TOKEN_KEY, &token).await?;
    Ok(token)
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
/// [`HostRejectLog::should_warn`]).
const HOST_REJECT_MAX_TRACKED: usize = 1_024;

/// Warns this registry may emit per [`HOST_REJECT_WARN_WINDOW`]. Past it,
/// rejections drop to debug, but the first suppressed host of the window
/// is named in a summary when the window rolls over.
const HOST_REJECT_MAX_WARNS: u32 = 64;

/// Per-host warn registry for the host gate, see
/// [`HostRejectLog::should_warn`].
static HOST_REJECT_LOG: LazyLock<Mutex<HostRejectLog>> =
    LazyLock::new(|| Mutex::new(HostRejectLog::default()));

#[derive(Default)]
struct HostRejectLog {
    seen: HashMap<String, Instant>,
    /// Start of the current warn window, and how much of
    /// [`HOST_REJECT_MAX_WARNS`] it has spent.
    window_start: Option<Instant>,
    warns_emitted: u32,
    /// First host the window could not warn about, kept so the rollover
    /// summary can name it.
    suppressed: Option<String>,
    /// Suppressed hosts in the current window, for the rollover count.
    suppressed_total: u64,
}

impl HostRejectLog {
    /// Roll the window over if it has elapsed. Returns a summary to log
    /// when the window that just closed had suppressed hosts.
    fn roll_window(&mut self, now: Instant) -> Option<String> {
        let Some(start) = self.window_start else {
            // First rejection ever: open the window, report nothing.
            self.window_start = Some(now);
            return None;
        };
        if now.duration_since(start) < HOST_REJECT_WARN_WINDOW {
            return None;
        }
        let suppressed = self.suppressed.take();
        let total = std::mem::take(&mut self.suppressed_total);
        self.warns_emitted = 0;
        self.window_start = Some(now);
        suppressed.map(|host| {
            format!(
                "host-gate rejections: {total} dropped to debug this window, \
                 first suppressed host {host}"
            )
        })
    }

    /// `true` when this rejection of `host` should warn, plus a summary to
    /// log when a window rolls over (see [`Self::roll_window`]).
    ///
    /// Three rules, in order: a host already warned inside the window is
    /// quiet; a host past [`HOST_REJECT_MAX_WARNS`] for the window is quiet
    /// but remembered for the summary; otherwise it warns. The per-window
    /// budget is what stops a scan sweeping random `Host` headers from
    /// mirroring itself into the log, and the summary is what stops a
    /// misconfigured allowlist from going unseen: the operator's own domain
    /// is rejected on every request under a broken allowlist, so even as
    /// the hundred-and-first host of a busy hour it is named once at the
    /// rollover.
    fn should_warn(&mut self, host: &str, now: Instant) -> (bool, Option<String>) {
        let summary = self.roll_window(now);
        if let Some(first) = self.seen.get(host) {
            if now.duration_since(*first) < HOST_REJECT_WARN_WINDOW {
                return (false, summary);
            }
            self.seen.insert(host.to_string(), now);
            return (true, summary);
        }
        if self.seen.len() >= HOST_REJECT_MAX_TRACKED {
            // Bound the map, not the warnings: drop the oldest entry.
            if let Some(oldest) = self
                .seen
                .iter()
                .min_by_key(|(_, first)| **first)
                .map(|(host, _)| host.clone())
            {
                self.seen.remove(&oldest);
            }
        }
        self.seen.insert(host.to_string(), now);
        if self.warns_emitted >= HOST_REJECT_MAX_WARNS {
            self.suppressed.get_or_insert_with(|| host.to_string());
            self.suppressed_total += 1;
            return (false, summary);
        }
        self.warns_emitted += 1;
        (true, summary)
    }
}

/// Whether a host-gate rejection should be logged at warn rather than
/// debug (see [`HostRejectLog::should_warn`]). Logs the window summary when
/// one came due, before the verdict for the request in hand.
fn should_warn_host_reject(host: &str, now: Instant) -> bool {
    let (warn, summary) = HOST_REJECT_LOG
        .lock()
        .unwrap_or_else(|poison| poison.into_inner())
        .should_warn(host, now);
    if let Some(summary) = summary {
        tracing::warn!(summary);
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
    serve_tier(state, headers, token, params, "alive").await
}

/// `GET /export/ready/{token}`, the url_list of all ready (T2-verified)
/// proxies, the tunnel-verified twin of [`serve()`].
pub async fn serve_ready(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(token): Path<String>,
    Query(params): Query<HashMap<String, String>>,
) -> Response {
    serve_tier(state, headers, token, params, "ready").await
}

/// Shared body of both export links. `tier` is a fixed route literal
/// ("alive" | "ready") that selects the backing query and the response
/// labels, it never carries user input.
async fn serve_tier(
    state: AppState,
    headers: HeaderMap,
    token: String,
    params: HashMap<String, String>,
    tier: &str,
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
    if params.contains_key("format") {
        return serve::error_response(
            StatusCode::BAD_REQUEST,
            "the ?format= parameter is not supported: the export is always a plain url_list",
        );
    }
    let expected = match repo::meta_get(&state.pool, TOKEN_KEY).await {
        Ok(Some(expected)) => expected,
        Ok(None) => return serve::error_response(StatusCode::NOT_FOUND, "link not found"),
        Err(err) => {
            tracing::error!(error = %err, "export token lookup failed");
            return serve::error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal server error",
            );
        }
    };
    // Constant-time comparison: the token is a public capability link.
    if !crate::admin::auth::ct_eq(&expected, &token) {
        return serve::error_response(StatusCode::NOT_FOUND, "link not found");
    }

    let rendered = match cached_render(&state, tier).await {
        Ok(rendered) => rendered,
        Err(err) => {
            tracing::error!(error = %err, "export render failed");
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
            "attachment; filename=\"fumox-{tier}-{date}.txt\""
        )) {
            response
                .headers_mut()
                .insert(header::CONTENT_DISPOSITION, value);
        }
    }
    response
}

/// Processed-cache key of one export tier.
fn cache_key(tier: &str) -> String {
    format!("export:{tier}")
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
async fn cached_render(state: &AppState, tier: &str) -> Result<Arc<Rendered>, fumox_core::Error> {
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
            let rendered = render_tier(&state.pool, tier, state.export_max_rows).await?;
            let stored = state.caches.processed_put(&key, rendered).await;
            drop(claim);
            Ok(stored)
        }
        InlineClaim::Wait(mut ended) => {
            if tokio::time::timeout(EXPORT_RENDER_DEADLINE, ended.changed())
                .await
                .is_ok()
                && let Some(cached) = state.caches.processed_get(&key).await
                && cached.is_fresh(fumox_core::models::now_ts())
            {
                return Ok(cached);
            }
            let rendered = render_tier(&state.pool, tier, state.export_max_rows).await?;
            Ok(state.caches.processed_put(&key, rendered).await)
        }
    }
}

/// Read the tier and serialize it as a url_list, bounded to `limit` rows
/// in SQL ([`cached_render`] passes the configured
/// `[server].export_max_rows`). Same metadata
/// comments as `/sub` and `/src` (they document the file when the HTTP
/// headers are lost to a copy-paste); the exports have no fetch TTL to
/// derive an interval from, so they advertise the shortest sensible one:
/// 1 hour.
///
/// The `nodes count` header reports how many rows this body carries, which
/// is *not* the same as how many the tier holds: a capped render reports the
/// cap. The body itself carries no truncation marker, so a download cannot
/// be distinguished from a complete one without comparing that number with
/// the uncapped tier count shown in the admin panel.
async fn render_tier(pool: &DbPool, tier: &str, limit: u32) -> Result<Rendered, fumox_core::Error> {
    let rows: Vec<ProxyRow> = match tier {
        "ready" => proxies::list_ready(pool, limit).await?,
        _ => proxies::list_alive(pool, limit).await?,
    };
    let mut lines: Vec<String> = Vec::with_capacity(rows.len());
    for row in rows {
        match row.to_entry() {
            Ok(entry) => lines.push(fumox_core::parsers::serialize(&entry)),
            Err(err) => {
                tracing::warn!(proxy_id = row.id, error = %err, "skipping corrupt proxy row");
            }
        }
    }
    let header = serve::url_list_header_block(&format!("export/{tier}"), 1, lines.len());
    let body = format!("{header}{}", lines.join("\n"));
    Ok(Rendered {
        status: 200,
        body: body.into_bytes().into(),
        content_type: "text/plain; charset=utf-8".to_string(),
        extra_headers: Vec::new(),
        fresh_until: fumox_core::models::now_ts() + EXPORT_TTL_SECS,
        // No source contributed to this rendering, so the per-source
        // invalidation must never touch the export entries.
        source_ids: Vec::new(),
    })
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

        let state = crate::serve::AppState {
            pool,
            caches: crate::cache::Caches::new(),
            geo: std::sync::Arc::new(fumox_core::geo::GeoResolver::new(
                &fumox_core::config::GeoConfig {
                    enabled: false,
                    ..Default::default()
                },
            )),
            limits: crate::serve::PublicRateLimits::unlimited(),
            trusted_cidrs: Vec::new(),
            allowed_hosts,
            export_max_rows,
        };
        let app = crate::serve::router(state.clone());
        (app, token, state)
    }

    /// One GET of an export link, body as text.
    async fn get(app: axum::Router, uri: &str) -> (StatusCode, String) {
        let response = app
            .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
            .await
            .unwrap();
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
            .await
            .unwrap();
        (status, String::from_utf8_lossy(&bytes).into_owned())
    }

    #[tokio::test]
    async fn non_allowlisted_host_returns_404_even_with_valid_token() {
        let (app, token, _state) =
            app_with_token(vec!["vpn.example.com".to_string()], default_cap()).await;
        let request = Request::builder()
            .method("GET")
            .uri(format!("/export/alive/{token}"))
            .header(header::HOST, "evil.example")
            .body(Body::empty())
            .unwrap();
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        // Identical body to a wrong-token response so probing cannot
        // distinguish the two.
        let body = response.into_body();
        let bytes = axum::body::to_bytes(body, 1024).await.unwrap();
        let text = String::from_utf8_lossy(&bytes);
        assert_eq!(text, "link not found\n");
    }

    #[tokio::test]
    async fn allowlisted_host_returns_200() {
        let (app, token, _state) =
            app_with_token(vec!["vpn.example.com".to_string()], default_cap()).await;
        let request = Request::builder()
            .method("GET")
            .uri(format!("/export/alive/{token}"))
            .header(header::HOST, "vpn.example.com")
            .body(Body::empty())
            .unwrap();
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    /// Deny-by-default: a request with no `Host` header must be rejected
    /// when an allowlist is configured, and the response body must match
    /// the wrong-token response byte-for-byte so probing cannot
    /// distinguish "missing host" from "wrong token".
    #[tokio::test]
    async fn missing_host_with_allowlist_returns_404_with_identical_body() {
        let (app, token, _state) =
            app_with_token(vec!["vpn.example.com".to_string()], default_cap()).await;
        let request = Request::builder()
            .method("GET")
            .uri(format!("/export/alive/{token}"))
            .body(Body::empty())
            .unwrap();
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        let bytes = axum::body::to_bytes(response.into_body(), 1024)
            .await
            .unwrap();
        assert_eq!(String::from_utf8_lossy(&bytes), "link not found\n");
    }

    /// Two distinct failure modes (bad host vs bad token) must yield
    /// byte-identical responses, same status, same body, same
    /// Content-Type, so an attacker cannot probe the link to learn
    /// whether the host check or the token check rejected the request.
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
        let request = Request::builder()
            .method("GET")
            .uri(format!("/export/alive/{token}"))
            .header(header::HOST, "VPN.EXAMPLE.COM")
            .body(Body::empty())
            .unwrap();
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    /// The host gate must run before the `?format=` branch, a malformed
    /// format on a rejected host must not widen the response to 400 or
    /// 500 (both would tell the attacker the host was checked at all).
    #[tokio::test]
    async fn format_query_with_bad_host_returns_404_not_500() {
        let (app, _token, _state) =
            app_with_token(vec!["vpn.example.com".to_string()], default_cap()).await;
        let request = Request::builder()
            .method("GET")
            .uri("/export/alive/anything?format=json")
            .header(header::HOST, "evil.example")
            .body(Body::empty())
            .unwrap();
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        let bytes = axum::body::to_bytes(response.into_body(), 1024)
            .await
            .unwrap();
        assert_eq!(String::from_utf8_lossy(&bytes), "link not found\n");
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
        };
        fumox_core::repo::proxies::reconcile_source(
            &state.pool,
            &source.id,
            std::slice::from_ref(&entry),
            &[],
            fumox_core::models::now_ts(),
            true,
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
            .processed_put(
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
        sqlx::query(
            "INSERT INTO sources (id, name, url, enabled, encoding, cache_ttl_seconds, created_at, updated_at)
             VALUES ('srcC0000000', 'cap', 'https://example.com', 1, 'auto', 3600, 1, 1)",
        )
        .execute(&pool)
        .await
        .unwrap();
        // Five linked alive rows, ids 1..5.
        for i in 1..=5i64 {
            sqlx::query(
                "INSERT INTO proxies (fingerprint, scheme, name, host, port, credential, status, created_at, updated_at)
                 VALUES (?, 'vless', 'n', ?, 443, 'c', 'alive', 1, 1)",
            )
            .bind(format!("fp-cap-{i}"))
            .bind(format!("cap{i}.example.com"))
            .execute(&pool)
            .await
            .unwrap();
            sqlx::query(
                "INSERT INTO proxy_source_links (proxy_id, source_id, seen_at)
                 VALUES (?, 'srcC0000000', 1)",
            )
            .bind(i)
            .execute(&pool)
            .await
            .unwrap();
        }

        // Under the cap the whole tier is served.
        let full = render_tier(&pool, "alive", 100).await.unwrap();
        let full_body = String::from_utf8(full.body.to_vec()).unwrap();
        assert!(full_body.contains("# nodes count: 5"), "{full_body:?}");
        assert!(full_body.contains("cap5.example.com"), "{full_body:?}");

        // At the cap the body is truncated, and it truncates the stable id
        // order: the two lowest ids, not an arbitrary slice.
        let capped = render_tier(&pool, "alive", 2).await.unwrap();
        let body = String::from_utf8(capped.body.to_vec()).unwrap();
        assert!(body.contains("# nodes count: 2"), "{body:?}");
        assert!(body.contains("cap1.example.com"), "{body:?}");
        assert!(body.contains("cap2.example.com"), "{body:?}");
        assert!(!body.contains("cap3.example.com"), "{body:?}");

        // The admin badge stays uncapped: the operator must be able to
        // see that the tier is bigger than what the export ships.
        assert_eq!(proxies::count_alive(&pool).await.unwrap(), 5);
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
            (format!("/export/alive/{token}"), "evil.example"),
            ("/export/alive/wrong-token".to_string(), "vpn.example.com"),
        ] {
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .uri(&uri)
                        .header(header::HOST, host)
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::NOT_FOUND, "{uri}");
            let bytes = axum::body::to_bytes(response.into_body(), 1024)
                .await
                .unwrap();
            assert_eq!(String::from_utf8_lossy(&bytes), "link not found\n");
        }
    }

    /// One warn per rejected host per window, then debug: a misconfigured
    /// allowlist must be visible without mirroring every request of the
    /// operator's own traffic into the log.
    #[test]
    fn host_reject_warns_once_per_host_per_window() {
        let mut log = HostRejectLog::default();
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
        let mut log = HostRejectLog::default();
        let t0 = Instant::now();
        let warned = (0..HOST_REJECT_MAX_TRACKED + 100)
            .filter(|i| log.should_warn(&format!("flood-{i}.example"), t0).0)
            .count();
        // The per-window budget caps the warns, not the tracked set: the
        // log must not mirror the scan.
        assert_eq!(warned, HOST_REJECT_MAX_WARNS as usize);
        assert_eq!(log.seen.len(), HOST_REJECT_MAX_TRACKED);
        // A tracked host stays quiet inside its window...
        assert!(!log.should_warn("flood-0.example", t0).0);
        // ...and warns again once the window has rolled over, handing back
        // the summary that names what the window swallowed.
        let (warn, summary) = log.should_warn("flood-0.example", t0 + Duration::from_secs(3_601));
        assert!(warn);
        let summary = summary.expect("a window that suppressed hosts must summarise them");
        assert!(summary.contains("flood-64.example"), "summary: {summary}");
    }

    /// The registry must not let a flood of tracked hosts hide the one that
    /// matters: the operator's own domain, rejected on every request under
    /// a misconfigured allowlist. It arrives after the budget is spent and
    /// still has to be named.
    #[test]
    fn a_misconfigured_allowlist_is_still_named_after_a_flood() {
        let mut log = HostRejectLog::default();
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
        let summary = summary.unwrap_or_default();
        assert!(
            summary.contains("operator.example"),
            "the suppressed host must be named, got {summary:?}"
        );
    }

    /// The tracked set stays bounded no matter how many distinct hosts
    /// arrive, which is the memory half of the cap.
    #[test]
    fn tracking_stays_bounded_across_windows() {
        let mut log = HostRejectLog::default();
        let t0 = Instant::now();
        for i in 0..HOST_REJECT_MAX_TRACKED * 3 {
            log.should_warn(&format!("h-{i}.example"), t0);
            assert!(log.seen.len() <= HOST_REJECT_MAX_TRACKED);
        }
    }
}
