//! Public «all alive» / «all ready» export links (owner request, 2026-08-29;
//! the ready tier, owner decision 2026-09-10).
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

use crate::serve::{self, AppState};
use axum::extract::{Path, Query, State};
use axum::http::{StatusCode, header};
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
    Path(token): Path<String>,
    Query(params): Query<HashMap<String, String>>,
) -> Response {
    serve_tier(state, token, params, "alive").await
}

/// `GET /export/ready/{token}` — the url_list of all ready (T2-verified)
/// proxies, the tunnel-verified twin of [`serve`].
pub async fn serve_ready(
    State(state): State<AppState>,
    Path(token): Path<String>,
    Query(params): Query<HashMap<String, String>>,
) -> Response {
    serve_tier(state, token, params, "ready").await
}

/// Shared body of both export links. `tier` is a fixed route literal
/// ("alive" | "ready") that selects the backing query and the response
/// labels — it never carries user input.
async fn serve_tier(
    state: AppState,
    token: String,
    params: HashMap<String, String>,
    tier: &str,
) -> Response {
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
    // Constant-time comparison: the token is a public capability link
    // (security audit, 2026-08-30).
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
