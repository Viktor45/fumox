//! Admin screen handlers. Read queries specific to the admin UI live here
//! (joins and aggregates the typed repository layer doesn't model); shared
//! mutations go through `fumox_core::repo`.

mod import_export;
mod logs;
mod pipeline;
mod probe;
mod profiles;
mod proxies;
mod sources;

pub use import_export::*;
pub use logs::*;
pub use pipeline::*;
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
        fmt_ts_element(*ts)
    }
    fn opt_ts(&self, ts: &Option<i64>) -> String {
        fmt_opt_ts_element(*ts)
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

/// Format a Unix timestamp as UTC `YYYY-MM-DD HH:MM:SS` (ADMIN_PLAN §13.1,
/// decision 17). This text is the no-JS fallback inside [`fmt_ts_element`].
pub fn fmt_ts(ts: i64) -> String {
    const FMT: &[time::format_description::FormatItem<'static>] =
        time::macros::format_description!("[year]-[month]-[day] [hour]:[minute]:[second]");
    match time::OffsetDateTime::from_unix_timestamp(ts) {
        Ok(dt) => dt.format(FMT).unwrap_or_else(|_| ts.to_string()),
        Err(_) => ts.to_string(),
    }
}

/// RFC 3339 UTC form for the `datetime` attribute of a `<time>` element.
fn fmt_ts_attr(ts: i64) -> String {
    const FMT: &[time::format_description::FormatItem<'static>] =
        time::macros::format_description!("[year]-[month]-[day]T[hour]:[minute]:[second]Z");
    match time::OffsetDateTime::from_unix_timestamp(ts) {
        Ok(dt) => dt.format(FMT).unwrap_or_else(|_| ts.to_string()),
        Err(_) => ts.to_string(),
    }
}

/// Render a Unix timestamp as a `<time class="ts">` element (ADMIN_PLAN
/// §13.1, decision 22): the `datetime` attribute carries the UTC instant in
/// RFC 3339 form, the text keeps the UTC `YYYY-MM-DD HH:MM:SS` fallback. The
/// admin JS (base.html) rewrites the text into the user's timezone and
/// re-runs after every HTMX swap; without JS the UTC text stays readable.
/// The output is HTML — templates must render it through askama's `| safe`.
/// Only server-generated digits and punctuation are interpolated, so it is
/// safe to trust.
pub fn fmt_ts_element(ts: i64) -> String {
    format!(
        "<time class=\"ts\" datetime=\"{}\">{}</time>",
        fmt_ts_attr(ts),
        fmt_ts(ts)
    )
}

/// [`fmt_ts_element`] for optional timestamps; `None` renders the em dash
/// used across the admin tables (plain text, no element).
pub fn fmt_opt_ts_element(ts: Option<i64>) -> String {
    ts.map(fmt_ts_element).unwrap_or_else(|| "—".into())
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

/// Percent-encode a string into unreserved ASCII so it can travel inside a
/// response header. Header bytes are decoded by the browser as Latin-1
/// (isomorphic decode), so raw UTF-8 — e.g. a Russian toast message — would
/// arrive as mojibake; percent-encoded UTF-8 survives the wire intact and is
/// restored client-side with `decodeURIComponent`.
fn header_safe(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.as_bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(*byte as char)
            }
            other => out.push_str(&format!("%{other:02X}")),
        }
    }
    out
}

/// Response for a mutating action: HTMX callers receive the fragment plus
/// a toast event; plain browsers are redirected back. The toast message
/// rides in the `HX-Trigger` header percent-encoded ([`header_safe`]).
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
        let payload = format!(
            "{{\"toast\": {{\"message\": \"{}\", \"level\": \"ok\"}}}}",
            header_safe(toast)
        );
        response.headers_mut().insert(
            "HX-Trigger",
            HeaderValue::from_str(&payload).expect("header_safe output is visible ASCII"),
        );
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fmt_ts_element_carries_utc_datetime_and_fallback_text() {
        // 1_700_000_000 == 2023-11-14 22:13:20 UTC.
        let html = fmt_ts_element(1_700_000_000);
        assert_eq!(
            html,
            "<time class=\"ts\" datetime=\"2023-11-14T22:13:20Z\">2023-11-14 22:13:20</time>"
        );

        assert_eq!(fmt_opt_ts_element(None), "—");
        assert_eq!(
            fmt_opt_ts_element(Some(1_700_000_000)),
            "<time class=\"ts\" datetime=\"2023-11-14T22:13:20Z\">2023-11-14 22:13:20</time>"
        );

        // Out-of-range timestamps fall back to the raw number in both forms.
        assert_eq!(
            fmt_ts_element(i64::MAX),
            format!("<time class=\"ts\" datetime=\"{0}\">{0}</time>", i64::MAX)
        );
    }

    #[test]
    fn toast_header_is_ascii_and_decodes_to_the_message() {
        // Russian text (raw UTF-8 would mojibake in a Latin-1 header) plus
        // JSON-breaking characters.
        let message = "источник включён — \"quote\" \\ backslash";
        let response = action_response(true, "/admin/sources/x", String::new(), message);

        let header = response
            .headers()
            .get("HX-Trigger")
            .expect("HX-Trigger must be set")
            .to_str()
            .expect("header must be visible ASCII")
            .to_string();

        // Undo the percent-encoding exactly like the admin JS does.
        let bytes: Vec<u8> = {
            let mut out = Vec::new();
            let mut rest = header.as_bytes();
            while !rest.is_empty() {
                if rest[0] == b'%' && rest.len() >= 3 {
                    out.push(
                        u8::from_str_radix(std::str::from_utf8(&rest[1..3]).unwrap(), 16).unwrap(),
                    );
                    rest = &rest[3..];
                } else {
                    out.push(rest[0]);
                    rest = &rest[1..];
                }
            }
            out
        };
        let decoded = String::from_utf8(bytes).unwrap();
        assert!(decoded.contains(&format!("\"message\": \"{message}\"")));
    }

    #[test]
    fn plain_browser_gets_a_redirect_without_toast_header() {
        let response = action_response(false, "/admin/sources", String::new(), "готово");
        assert!(response.headers().get("HX-Trigger").is_none());
        assert_eq!(response.status(), axum::http::StatusCode::SEE_OTHER);
    }
}
