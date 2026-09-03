//! Public «all alive proxies» export link (owner request, 2026-08-29).
//!
//! `GET /export/alive/{token}` serves every currently-alive proxy that is
//! still linked to a source as a plain url_list, so the link can be pasted
//! straight into a client or used as an upstream source by another fumox.
//! The capability token is a `nanoid(12)` generated on first startup and
//! kept in the `meta` table — the link is stable across restarts — and the
//! admin Import/Export screen displays it and can rotate it (the previous
//! link dies immediately).
//!
//! This is a dedicated endpoint rather than a synthetic source row: a real
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
use std::collections::HashMap;

/// `meta` key holding the capability token of the export link.
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

/// Issue a fresh token; the previous export link stops working immediately.
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
            tracing::error!(error = %err, "alive export token lookup failed");
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

    let rows = match proxies::list_alive(&state.pool).await {
        Ok(rows) => rows,
        Err(err) => {
            tracing::error!(error = %err, "alive export query failed");
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
    // file when the HTTP headers are lost to a copy-paste). The export has
    // no fetch TTL to derive an interval from, so it advertises the
    // shortest sensible one: 1 hour.
    let header = serve::url_list_header_block("export/alive", 1, lines.len());
    let mut response = (StatusCode::OK, format!("{header}{}", lines.join("\n"))).into_response();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        header::HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    if params.contains_key("download") {
        let date = export_date();
        // ASCII-only value (fixed prefix + calendar date), try_from cannot fail.
        if let Ok(value) = header::HeaderValue::try_from(format!(
            "attachment; filename=\"fumox-alive-{date}.txt\""
        )) {
            response
                .headers_mut()
                .insert(header::CONTENT_DISPOSITION, value);
        }
    }
    response
}
