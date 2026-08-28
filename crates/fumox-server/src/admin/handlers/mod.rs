//! Admin screen handlers. Read queries specific to the admin UI live here
//! (joins and aggregates the typed repository layer doesn't model); shared
//! mutations go through `fumox_core::repo`.

mod import_export;
mod logs;
mod probe;
mod profiles;
mod proxies;
mod sources;

pub use import_export::*;
pub use logs::*;
pub use probe::*;
pub use profiles::*;
pub use proxies::*;
pub use sources::*;

use crate::admin::AdminState;
use crate::admin::i18n::{Lang, impl_i18n};
use crate::admin::render_html;
use crate::admin::theme::{self, Theme};
use askama::Template;
use axum::extract::State;
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Redirect, Response};

/// Dashboard (ADMIN_PLAN §4.1): aggregate counters, recent source errors
/// and the latest fetch attempts.
#[derive(Template)]
#[template(path = "dashboard.html")]
struct DashboardTemplate {
    lang: Lang,
    /// `(code, native name)` pairs for the topbar language switcher.
    langs: Vec<(String, String)>,
    /// Active interface theme (rendered as `data-theme` on `<html>`).
    theme: Theme,
    active: &'static str,
    csrf: String,
    sources_total: i64,
    sources_enabled: i64,
    sources_with_errors: i64,
    profiles_total: i64,
    proxy_counts: Vec<(String, i64)>,
    fetch_total_24h: i64,
    fetch_ok_24h: i64,
    recent_errors: Vec<SourceErrorRow>,
    recent_fetches: Vec<RecentFetch>,
}

#[derive(Debug, sqlx::FromRow)]
struct SourceErrorRow {
    id: String,
    name: String,
    error_class: Option<String>,
    last_error: Option<String>,
    last_fetched_at: Option<i64>,
}

#[derive(Debug, sqlx::FromRow)]
struct RecentFetch {
    source_id: String,
    source_name: Option<String>,
    fetched_at: i64,
    ok: i64,
    http_status: Option<i64>,
    bytes: Option<i64>,
    proxies_found: Option<i64>,
    error_class: Option<String>,
}

// Formatting helpers exposed to the dashboard template. askama passes
// call arguments by reference, so every helper takes &T.
impl DashboardTemplate {
    fn ts(&self, ts: &i64) -> String {
        fmt_ts(*ts)
    }
    fn opt_ts(&self, ts: &Option<i64>) -> String {
        ts.map(fmt_ts).unwrap_or_else(|| "—".into())
    }
    fn bytes(&self, n: &Option<i64>) -> String {
        n.map(|n| fmt_bytes(&self.lang, n))
            .unwrap_or_else(|| "—".into())
    }
    fn proxy_total(&self) -> i64 {
        self.proxy_counts.iter().map(|(_, count)| count).sum()
    }
}

impl_i18n!(DashboardTemplate);

pub async fn dashboard(State(state): State<AdminState>, headers: HeaderMap) -> Response {
    let lang = state.locales.lang_from_headers(&headers);
    let theme = theme::from_headers(&headers);
    let pool = &state.pool;

    let (src_total, src_enabled, src_errors): (i64, i64, i64) = match sqlx::query_as(
        "SELECT COUNT(*), COALESCE(SUM(enabled), 0),
                COALESCE(SUM(error_class IS NOT NULL), 0) FROM sources",
    )
    .fetch_one(pool)
    .await
    {
        Ok(row) => row,
        Err(err) => return server_error(lang, &err),
    };

    let profiles_total: i64 = match sqlx::query_scalar("SELECT COUNT(*) FROM profiles")
        .fetch_one(pool)
        .await
    {
        Ok(count) => count,
        Err(err) => return server_error(lang, &err),
    };

    let proxy_counts = match fumox_core::repo::proxies::count_by_status(pool).await {
        Ok(counts) => counts,
        Err(err) => return server_error(lang, &err),
    };

    let day_ago = fumox_core::models::now_ts() - 86_400;
    let (fetch_total_24h, fetch_ok_24h): (i64, i64) = match sqlx::query_as(
        "SELECT COUNT(*), COALESCE(SUM(ok), 0) FROM fetch_log WHERE fetched_at > ?",
    )
    .bind(day_ago)
    .fetch_one(pool)
    .await
    {
        Ok(row) => row,
        Err(err) => return server_error(lang, &err),
    };

    let recent_errors: Vec<SourceErrorRow> = match sqlx::query_as(
        "SELECT id, name, error_class, last_error, last_fetched_at FROM sources
         WHERE error_class IS NOT NULL
         ORDER BY COALESCE(last_fetched_at, 0) DESC LIMIT 10",
    )
    .fetch_all(pool)
    .await
    {
        Ok(rows) => rows,
        Err(err) => return server_error(lang, &err),
    };

    let recent_fetches: Vec<RecentFetch> = match sqlx::query_as(
        "SELECT f.source_id, s.name AS source_name, f.fetched_at, f.ok, f.http_status,
                f.bytes, f.proxies_found, f.error_class
         FROM fetch_log f LEFT JOIN sources s ON s.id = f.source_id
         ORDER BY f.fetched_at DESC, f.id DESC LIMIT 15",
    )
    .fetch_all(pool)
    .await
    {
        Ok(rows) => rows,
        Err(err) => return server_error(lang, &err),
    };

    render_html(
        lang.clone(),
        &DashboardTemplate {
            lang,
            langs: state.locales.choices().to_vec(),
            theme,
            active: "dashboard",
            csrf: state.csrf_for(&headers),
            sources_total: src_total,
            sources_enabled: src_enabled,
            sources_with_errors: src_errors,
            profiles_total,
            proxy_counts,
            fetch_total_24h,
            fetch_ok_24h,
            recent_errors,
            recent_fetches,
        },
        StatusCode::OK,
    )
}

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

/// Format a Unix timestamp as UTC `YYYY-MM-DD HH:MM:SS` (ADMIN_PLAN §13.17).
pub fn fmt_ts(ts: i64) -> String {
    const FMT: &[time::format_description::FormatItem<'static>] =
        time::macros::format_description!("[year]-[month]-[day] [hour]:[minute]:[second]");
    match time::OffsetDateTime::from_unix_timestamp(ts) {
        Ok(dt) => dt.format(FMT).unwrap_or_else(|_| ts.to_string()),
        Err(_) => ts.to_string(),
    }
}

/// Human-readable byte size for fetch logs (units follow the UI language).
pub fn fmt_bytes(lang: &Lang, bytes: i64) -> String {
    let units: [&str; 4] = [
        lang.t("common.unit_b"),
        lang.t("common.unit_kb"),
        lang.t("common.unit_mb"),
        lang.t("common.unit_gb"),
    ];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < units.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} {}", units[0])
    } else {
        format!("{value:.1} {}", units[unit])
    }
}

/// Credential masking for lists and forms (ADMIN_PLAN §3): first three
/// characters plus a fixed tail; short values are hidden entirely.
pub fn mask_secret(value: &str) -> String {
    if value.is_empty() {
        return String::new();
    }
    if value.chars().count() <= 3 {
        return "••••".to_string();
    }
    let prefix: String = value.chars().take(3).collect();
    format!("{prefix}…••••")
}

/// Flag emoji for a stored ISO country code.
pub fn flag_for(country: &Option<String>) -> String {
    country
        .as_deref()
        .and_then(fumox_core::geo::flag_emoji)
        .unwrap_or_default()
}

/// Standard 500 for unexpected DB failures.
pub fn server_error(lang: Lang, err: &impl std::fmt::Display) -> Response {
    tracing::error!(error = %err, "admin handler failed");
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
        format!("{}\n", lang.t("err.internal")),
    )
        .into_response()
}

/// 404 page for unknown entities; `what_key` selects the translated noun.
pub fn not_found(lang: Lang, what_key: &str) -> Response {
    (
        StatusCode::NOT_FOUND,
        [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
        format!("{}\n", lang.t(what_key)),
    )
        .into_response()
}

/// Response for a mutating action: HTMX callers receive the fragment plus
/// a toast event; plain browsers are redirected back.
pub fn action_response(
    is_htmx: bool,
    redirect_to: &str,
    fragment_html: String,
    toast: &str,
) -> Response {
    if is_htmx {
        let mut response = (
            StatusCode::OK,
            [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
            fragment_html,
        )
            .into_response();
        if let Ok(value) = HeaderValue::from_str(&format!(
            "{{\"toast\": {{\"message\": \"{}\", \"level\": \"ok\"}}}}",
            toast.replace('"', "'")
        )) {
            response.headers_mut().insert("HX-Trigger", value);
        }
        response
    } else {
        Redirect::to(redirect_to).into_response()
    }
}

fn is_htmx(headers: &HeaderMap) -> bool {
    headers.get("HX-Request").is_some()
}

/// Parse the `_csrf`-less business fields of a urlencoded form; used by
/// handlers that receive the raw body as a string map.
pub type FormMap = std::collections::HashMap<String, String>;

/// Pagination window used across list screens.
pub const PAGE_SIZE: i64 = 50;
pub const MAX_PAGE_SIZE: i64 = 200;

/// Clamp a requested page size into the allowed range.
pub fn clamp_limit(requested: Option<i64>) -> i64 {
    requested.unwrap_or(PAGE_SIZE).clamp(1, MAX_PAGE_SIZE)
}

/// Build the pagination context: `(page number, is current)` pairs to
/// render. Templates iterate without any arithmetic of their own.
pub fn pagination_pages(page: i64, total: i64, per_page: i64) -> Vec<(i64, bool)> {
    let pages = ((total + per_page - 1) / per_page).max(1);
    (1..=pages).map(|p| (p, p == page)).collect()
}

/// Fetch the source list for form selects (id + name), enabled first.
pub async fn all_sources_for_selects(
    pool: &fumox_core::db::DbPool,
) -> Result<Vec<(String, String, bool)>, fumox_core::Error> {
    let list = fumox_core::repo::sources::list(pool, false).await?;
    Ok(list
        .into_iter()
        .map(|s| (s.id.clone(), s.name.clone(), s.enabled))
        .collect())
}
