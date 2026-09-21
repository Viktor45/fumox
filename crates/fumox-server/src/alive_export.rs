//! Public «all alive» / «all ready» export links (owner request, 2026-08-29;
//! the ready tier).
//!
//! `GET /export/alive/{token}` serves every currently-`alive` proxy that is
//! still linked to a source as a plain url_list, so the link can be pasted
//! straight into a client or used as an upstream source by another fumox.
//! `GET /export/ready/{token}` is the verified twin: it ships only the
//! `ready` tier — proxies whose latest T2 tunnel check succeeded. The tiers
//! are disjoint: alive = T1-alive without a fresh successful T2; ready =
//! the same proxy plus a confirmed tunnel.
//!
//! Both links share one capability token, a `nanoid(12)` generated on first
//! startup and kept in the `meta` table — the links are stable across
//! restarts — and the admin Import/Export screen displays them and can
//! rotate the token (both links die immediately: one secret, one rotation,
//! a shared fate by design).
//!
//! These are dedicated endpoints rather than synthetic source rows: a real
//! source would be picked up by the fetch scheduler, editable in the admin
//! CRUD, selectable into profiles and included in the config export — each
//! of which would need special-casing. The token in `meta` has none of
//! those interactions.

use crate::admin::host_gate;
use crate::serve::{self, AppState};
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use fumox_core::db::DbPool;
use fumox_core::repo;
use fumox_core::repo::proxies;
use fumox_core::repo::proxies::ProxyRow;
use std::collections::HashMap;

/// `meta` key holding the capability token shared by both export links.
pub(crate) const TOKEN_KEY: &str = "alive_export_token";

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

/// `GET /export/alive/{token}` — the url_list of all alive proxies, or 404
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

/// `GET /export/ready/{token}` — the url_list of all ready (T2-verified)
/// proxies, the tunnel-verified twin of [`serve`].
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
/// labels — it never carries user input.
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
        tracing::debug!(error = %err, "alive-export: host not in allowlist");
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

    let rows: Result<Vec<ProxyRow>, _> = match tier {
        "ready" => proxies::list_ready(&state.pool).await,
        _ => proxies::list_alive(&state.pool).await,
    };
    let rows = match rows {
        Ok(rows) => rows,
        Err(err) => {
            tracing::error!(error = %err, "export query failed");
            return serve::error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal server error",
            );
        }
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

    // Same url_list metadata comments as /sub and /src (they document the
    // file when the HTTP headers are lost to a copy-paste). The exports
    // have no fetch TTL to derive an interval from, so they advertise the
    // shortest sensible one: 1 hour.
    let header = serve::url_list_header_block(&format!("export/{tier}"), 1, lines.len());
    let mut response = (StatusCode::OK, format!("{header}{}", lines.join("\n"))).into_response();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        header::HeaderValue::from_static("text/plain; charset=utf-8"),
    );
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

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt;

    /// Bootstrap a fresh app + persist a known alive-export token into the
    /// `meta` table so the test can address `/export/alive/{token}` without
    /// rotating.
    async fn app_with_token(allowed_hosts: Vec<String>) -> (axum::Router, String) {
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
            refresh_tx: {
                let (tx, _rx) = tokio::sync::mpsc::unbounded_channel();
                tx
            },
            limits: crate::serve::PublicRateLimits::unlimited(),
            trusted_cidrs: Vec::new(),
            allowed_hosts,
        };
        let app = crate::serve::router(state);
        (app, token)
    }

    #[tokio::test]
    async fn non_allowlisted_host_returns_404_even_with_valid_token() {
        let (app, token) = app_with_token(vec!["vpn.example.com".to_string()]).await;
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
        let (app, token) = app_with_token(vec!["vpn.example.com".to_string()]).await;
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
        let (app, token) = app_with_token(vec!["vpn.example.com".to_string()]).await;
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
    /// byte-identical responses — same status, same body, same
    /// Content-Type — so an attacker cannot probe the link to learn
    /// whether the host check or the token check rejected the request.
    #[tokio::test]
    async fn bad_host_and_bad_token_return_byte_equal_bodies_and_content_type() {
        let (app, token) = app_with_token(vec!["vpn.example.com".to_string()]).await;
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
        let (app, token) = app_with_token(vec!["vpn.example.com".to_string()]).await;
        let request = Request::builder()
            .method("GET")
            .uri(format!("/export/alive/{token}"))
            .header(header::HOST, "VPN.EXAMPLE.COM")
            .body(Body::empty())
            .unwrap();
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    /// The host gate must run before the `?format=` branch — a malformed
    /// format on a rejected host must not widen the response to 400 or
    /// 500 (both would tell the attacker the host was checked at all).
    #[tokio::test]
    async fn format_query_with_bad_host_returns_404_not_500() {
        let (app, _token) = app_with_token(vec!["vpn.example.com".to_string()]).await;
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
}
