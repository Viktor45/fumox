//! Admin screen handlers. Read queries specific to the admin UI live here
//! (joins and aggregates the typed repository layer doesn't model); shared
//! mutations go through `fumox_core::repo`.

mod import_export;
mod logs;
mod pipeline;
mod probe;
mod profiles;
mod proxies;
mod settings;
mod sources;

pub use import_export::*;
pub use logs::*;
pub use pipeline::*;
pub use probe::*;
pub use profiles::*;
pub use proxies::*;
pub use settings::*;
pub use sources::*;

use crate::admin::AdminState;
use crate::admin::i18n::{Lang, impl_i18n};
use crate::admin::render_html;
use crate::admin::theme::{self, Theme};
use askama::Template;
use axum::extract::State;
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Redirect, Response};
use fumox_core::models::Scheme;

/// Dashboard (ADMIN_PLAN §4.1; merged with the former statistics screen,
/// owner decision 2026-09-10): aggregate counters, source errors (the
/// operator's most actionable block, rendered first), per-source health,
/// probe summary, latency aggregates, ingest dynamics and the
/// protocol/country splits.
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
    /// Per-source health counters (the former stats screen table).
    sources: Vec<SourceStatRow>,
    top_alive: Vec<TopAliveRow>,
    schemes: Vec<SchemeSplitRow>,
    countries: Vec<CountrySplitRow>,
    /// `(min, avg, median)` latency of alive proxies with a measurement.
    latency_min: Option<i64>,
    latency_avg: Option<i64>,
    latency_median: Option<i64>,
    /// `(total probes in 24h, successful probes in 24h)`.
    probes_total_24h: i64,
    probes_ok_24h: i64,
    /// Counters of the probe summary panel.
    unprobeable: i64,
    quarantine_second_chance: i64,
    in_quarantine: i64,
    never_checked: i64,
    /// Ingest dynamics: `(day start ts, created proxies)` for the last
    /// 7 days, oldest first, zero-filled for gap days.
    ingest_days: Vec<(i64, i64)>,
    /// Largest per-day value of `ingest_days` (bar scale).
    ingest_max: i64,
}

#[derive(Debug, sqlx::FromRow)]
struct SourceErrorRow {
    id: String,
    name: String,
    error_class: Option<String>,
    last_error: Option<String>,
    last_fetched_at: Option<i64>,
}

/// Row of the per-source health table (the former stats screen).
#[derive(Debug, sqlx::FromRow)]
struct SourceStatRow {
    id: String,
    name: String,
    enabled: i64,
    alive: i64,
    ready: i64,
    quarantine: i64,
    unknown: i64,
    removed: i64,
    total: i64,
    /// Oldest `created_at` among this source's alive proxies.
    oldest_alive_at: Option<i64>,
    /// Distinct protocol schemes this source has ever yielded.
    schemes: i64,
    /// Number of countries among this source's alive proxies.
    countries: i64,
}

/// One row of the "longest-living alive proxies" top.
#[derive(Debug, sqlx::FromRow)]
struct TopAliveRow {
    id: i64,
    name: String,
    scheme: String,
    host: String,
    port: i64,
    latency_ms: Option<i64>,
    geo_country: Option<String>,
    created_at: i64,
    /// GROUP_CONCAT of source names, comma-joined (a proxy seen by several
    /// sources lists them all).
    source_names: String,
}

/// One row of the protocol distribution (`scheme` is NOT NULL).
#[derive(Debug, sqlx::FromRow)]
struct SchemeSplitRow {
    value: String,
    alive: i64,
    ready: i64,
    quarantine: i64,
    unknown: i64,
    removed: i64,
    total: i64,
}

/// One row of the country distribution (`geo_country` may be NULL).
#[derive(Debug, sqlx::FromRow)]
struct CountrySplitRow {
    value: Option<String>,
    alive: i64,
    ready: i64,
    quarantine: i64,
    unknown: i64,
    removed: i64,
    total: i64,
}

/// One point of the 7-day ingest chart: `(day start, proxies created)`.
#[derive(Debug, sqlx::FromRow)]
struct IngestDayRow {
    day: i64,
    created: i64,
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
    fn proxy_total(&self) -> i64 {
        self.proxy_counts.iter().map(|(_, count)| count).sum()
    }
    fn flag(&self, country: &Option<String>) -> String {
        flag_for(country)
    }
    /// Percentage of `part` relative to `whole` (0 when whole is 0).
    fn pct(&self, part: &i64, whole: &i64) -> i64 {
        if *whole == 0 { 0 } else { (part * 100) / whole }
    }
    /// Width in percent of one distribution bar (relative to the largest
    /// bucket of its group); 1 is the floor so non-zero counts stay visible.
    fn bar_width(&self, count: &i64, max: &i64) -> i64 {
        if *max <= 0 || *count <= 0 {
            0
        } else {
            (*count * 100 / max).max(1)
        }
    }
    /// Truncate long display names (the full name is on the proxy card).
    fn short_name(&self, name: &str) -> String {
        let count = name.chars().count();
        if count <= 60 {
            name.to_string()
        } else {
            let truncated: String = name.chars().take(59).collect();
            format!("{truncated}…")
        }
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

    // Per-source health counters (single aggregate over the join table).
    let sources: Vec<SourceStatRow> = match sqlx::query_as(
        "SELECT s.id, s.name, s.enabled,
                COALESCE(SUM(p.status = 'alive'), 0)     AS alive,
                COALESCE(SUM(p.status = 'ready'), 0)     AS ready,
                COALESCE(SUM(p.status = 'quarantine'), 0) AS quarantine,
                COALESCE(SUM(p.status = 'unknown'), 0)   AS unknown,
                COALESCE(SUM(p.status = 'removed'), 0)    AS removed,
                COUNT(DISTINCT p.id)                      AS total,
                MIN(CASE WHEN p.status = 'alive' THEN p.created_at END) AS oldest_alive_at,
                COUNT(DISTINCT p.scheme)                  AS schemes,
                COUNT(DISTINCT CASE WHEN p.status = 'alive' THEN p.geo_country END) AS countries
         FROM sources s
         LEFT JOIN proxy_source_links l ON l.source_id = s.id
         LEFT JOIN proxies p ON p.id = l.proxy_id
         GROUP BY s.id
         ORDER BY alive DESC, total DESC, s.name COLLATE NOCASE",
    )
    .fetch_all(pool)
    .await
    {
        Ok(rows) => rows,
        Err(err) => return server_error(lang, &err),
    };

    // Longest-living alive proxies: oldest `created_at` first — the ones
    // that have been in the base the longest while still alive.
    let top_alive: Vec<TopAliveRow> = match sqlx::query_as(
        "SELECT p.id, p.name, p.scheme, p.host, p.port, p.latency_ms, p.geo_country,
                p.created_at,
                COALESCE(GROUP_CONCAT(s.name, ', '), '') AS source_names
         FROM proxies p
         JOIN proxy_source_links l ON l.proxy_id = p.id
         JOIN sources s ON s.id = l.source_id
         WHERE p.status = 'alive'
         GROUP BY p.id
         ORDER BY p.created_at ASC, p.id ASC
         LIMIT 10",
    )
    .fetch_all(pool)
    .await
    {
        Ok(rows) => rows,
        Err(err) => return server_error(lang, &err),
    };

    let schemes = match scheme_split(pool).await {
        Ok(rows) => rows,
        Err(err) => return server_error(lang, &err),
    };
    let countries = match country_split(pool).await {
        Ok(rows) => rows,
        Err(err) => return server_error(lang, &err),
    };

    // Latency aggregates over alive proxies with a measurement. The
    // median has no SQLite builtin and is computed separately below.
    let (latency_min, latency_avg): (Option<i64>, Option<i64>) = match sqlx::query_as(
        "SELECT MIN(latency_ms), CAST(AVG(latency_ms) AS INTEGER) FROM proxies
         WHERE status = 'alive' AND latency_ms IS NOT NULL",
    )
    .fetch_one(pool)
    .await
    {
        Ok(row) => row,
        Err(err) => return server_error(lang, &err),
    };
    // Median: SQLite has no built-in; the middle element(s) are picked
    // with window functions over the alive-with-latency set and averaged
    // (odd count: one element, even count: the mean of the two middle).
    let latency_median = match sqlx::query_scalar::<_, Option<i64>>(
        "WITH ordered AS (
             SELECT latency_ms, ROW_NUMBER() OVER (ORDER BY latency_ms) AS rn,
                    COUNT(*) OVER () AS n
             FROM proxies WHERE status = 'alive' AND latency_ms IS NOT NULL
         )
         SELECT CAST(AVG(latency_ms) AS INTEGER) FROM ordered
         WHERE rn IN ((n + 1) / 2, (n + 2) / 2)",
    )
    .fetch_one(pool)
    .await
    {
        Ok(median) => median,
        Err(err) => return server_error(lang, &err),
    };

    // Probe success rate over the last 24 hours.
    let (probes_total_24h, probes_ok_24h): (i64, i64) = match sqlx::query_as(
        "SELECT COUNT(*), COALESCE(SUM(ok), 0) FROM probe_results
         WHERE checked_at > ? AND probe_kind != 'speed'",
    )
    .bind(day_ago)
    .fetch_one(pool)
    .await
    {
        Ok(row) => row,
        Err(err) => return server_error(lang, &err),
    };

    // Probe summary counters.
    let (in_quarantine, quarantine_second_chance, never_checked): (i64, i64, i64) =
        match sqlx::query_as(
            "SELECT COALESCE(SUM(status = 'quarantine'), 0),
                    COALESCE(SUM(status = 'quarantine' AND ladder_step = 0), 0),
                    COALESCE(SUM(last_checked_at IS NULL), 0)
             FROM proxies WHERE status != 'removed'",
        )
        .fetch_one(pool)
        .await
        {
            Ok(row) => row,
            Err(err) => return server_error(lang, &err),
        };

    // Unprobeable schemes (tuic/mieru stay `unknown` forever, SPEC §8.5).
    let unprobeable_schemes: Vec<&'static str> = Scheme::all()
        .iter()
        .filter(|scheme| !scheme.is_probeable())
        .map(|scheme| scheme.as_str())
        .collect();
    let placeholders = vec!["?"; unprobeable_schemes.len()].join(", ");
    let unprobeable_sql = format!("SELECT COUNT(*) FROM proxies WHERE scheme IN ({placeholders})");
    let unprobeable = {
        let mut query = sqlx::query_scalar::<_, i64>(sqlx::AssertSqlSafe(unprobeable_sql.as_str()));
        for scheme in &unprobeable_schemes {
            query = query.bind(scheme);
        }
        match query.fetch_one(pool).await {
            Ok(count) => count,
            Err(err) => return server_error(lang, &err),
        }
    };

    // Ingest dynamics: proxies created per day over the last 7 days,
    // zero-filled for gap days (the chart must not silently skip a day).
    let rows: Vec<IngestDayRow> = match sqlx::query_as(
        "SELECT (created_at / 86400) * 86400 AS day, COUNT(*) AS created
         FROM proxies
         WHERE created_at >= ?
         GROUP BY day ORDER BY day",
    )
    .bind(day_ago - 6 * 86_400)
    .fetch_all(pool)
    .await
    {
        Ok(rows) => rows,
        Err(err) => return server_error(lang, &err),
    };
    let now = fumox_core::models::now_ts();
    let first_day = (now / 86_400) * 86_400 - 6 * 86_400;
    let mut ingest_days: Vec<(i64, i64)> = Vec::with_capacity(7);
    for offset in 0..7 {
        let day = first_day + offset * 86_400;
        let created = rows
            .iter()
            .find(|row| row.day == day)
            .map_or(0, |row| row.created);
        ingest_days.push((day, created));
    }
    let ingest_max = ingest_days
        .iter()
        .map(|(_, count)| *count)
        .max()
        .unwrap_or(0);

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
            sources,
            top_alive,
            schemes,
            countries,
            latency_min,
            latency_avg,
            latency_median,
            probes_total_24h,
            probes_ok_24h,
            unprobeable,
            quarantine_second_chance,
            in_quarantine,
            never_checked,
            ingest_days,
            ingest_max,
        },
        StatusCode::OK,
    )
}

/// Grouped health counters per scheme, largest bucket first (`scheme` is
/// never NULL, so the value binds to a plain `String`).
async fn scheme_split(
    pool: &fumox_core::db::DbPool,
) -> Result<Vec<SchemeSplitRow>, fumox_core::Error> {
    Ok(sqlx::query_as::<_, SchemeSplitRow>(
        "SELECT scheme AS value,
                COALESCE(SUM(status = 'alive'), 0)     AS alive,
                COALESCE(SUM(status = 'ready'), 0)     AS ready,
                COALESCE(SUM(status = 'quarantine'), 0) AS quarantine,
                COALESCE(SUM(status = 'unknown'), 0)   AS unknown,
                COALESCE(SUM(status = 'removed'), 0)   AS removed,
                COUNT(*)                               AS total
         FROM proxies
         GROUP BY scheme
         ORDER BY total DESC, value ASC",
    )
    .fetch_all(pool)
    .await?)
}

/// Grouped health counters per country, largest bucket first; proxies
/// without a resolved country land in the trailing NULL bucket.
async fn country_split(
    pool: &fumox_core::db::DbPool,
) -> Result<Vec<CountrySplitRow>, fumox_core::Error> {
    Ok(sqlx::query_as::<_, CountrySplitRow>(
        "SELECT geo_country AS value,
                COALESCE(SUM(status = 'alive'), 0)     AS alive,
                COALESCE(SUM(status = 'ready'), 0)     AS ready,
                COALESCE(SUM(status = 'quarantine'), 0) AS quarantine,
                COALESCE(SUM(status = 'unknown'), 0)   AS unknown,
                COALESCE(SUM(status = 'removed'), 0)   AS removed,
                COUNT(*)                               AS total
         FROM proxies
         GROUP BY geo_country
         ORDER BY total DESC, value IS NULL, value ASC",
    )
    .fetch_all(pool)
    .await?)
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
pub(super) fn header_safe(value: &str) -> String {
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
    action_response_with_level(is_htmx, redirect_to, fragment_html, toast, "ok")
}

/// [`action_response`] with a rejected toast: same shape, but the toast
/// carries level `error` so the client renders it with the error style.
/// Used when a form-driven action fails validation and the browser path
/// still lands back on the list.
pub fn action_response_err(
    is_htmx: bool,
    redirect_to: &str,
    fragment_html: String,
    toast: &str,
) -> Response {
    action_response_with_level(is_htmx, redirect_to, fragment_html, toast, "error")
}

fn action_response_with_level(
    is_htmx: bool,
    redirect_to: &str,
    fragment_html: String,
    toast: &str,
    level: &str,
) -> Response {
    if is_htmx {
        let mut response = (
            StatusCode::OK,
            [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
            fragment_html,
        )
            .into_response();
        let payload = format!(
            "{{\"toast\": {{\"message\": \"{}\", \"level\": \"{level}\"}}}}",
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

/// Query parameters that keep duplicates and their original order.
///
/// [`FormMap`] is a `HashMap`, so a repeating key silently collapses to the
/// last value — which broke the proxy list's multi-select status filter
/// (`?status=alive&status=quarantine` filtered on one status only; security
/// audit, 2026-09-05). Screens with a multi-select filter extract this.
#[derive(Debug, Default, serde::Deserialize)]
#[serde(transparent)]
pub struct QueryPairs(Vec<(String, String)>);

impl QueryPairs {
    /// First value for `key`, matching `HashMap::get` for single-valued
    /// parameters.
    pub fn get(&self, key: &str) -> Option<&String> {
        self.0.iter().find(|(k, _)| k == key).map(|(_, v)| v)
    }

    /// Every value for a repeating `key`, in query-string order.
    pub fn all<'a>(&'a self, key: &'a str) -> impl Iterator<Item = &'a String> + 'a {
        self.0.iter().filter(move |(k, _)| k == key).map(|(_, v)| v)
    }
}

/// Pagination window used across list screens.
pub const PAGE_SIZE: i64 = 50;
pub const MAX_PAGE_SIZE: i64 = 200;

/// Field/count caps for admin-stored input (security audit v2, 2026-09-09,
/// F7/F8). A single POST is bounded by the CSRF buffer (1 MiB) and the
/// router-wide `DefaultBodyLimit`; these caps keep what actually reaches
/// SQLite — and every later re-render of it — proportionate to what the
/// forms legitimately hold.
pub mod caps {
    /// Source/profile URL length (matches the fetcher's `MAX_URL_LEN`).
    pub const URL: usize = 2048;
    /// Stored pipeline JSON, in bytes.
    pub const PIPELINE_BYTES: usize = 64 * 1024;
    /// One profile access token.
    pub const ACCESS_TOKEN: usize = 128;
    /// Minimum length for an access token accepted from an *import file*
    /// (a fresh form entry may be shorter at the admin's own risk; a
    /// third-party template must not plant guessable tokens, F8).
    pub const IMPORT_TOKEN_MIN: usize = 16;
    /// Tags per source.
    pub const TAGS: usize = 20;
    /// One tag.
    pub const TAG_BYTES: usize = 100;
    /// Country codes per profile.
    pub const COUNTRIES: usize = 64;
    /// Header lines per source.
    pub const HEADER_LINES: usize = 32;
    /// Total bytes of all header key/value text per source.
    pub const HEADER_BYTES: usize = 8 * 1024;
    /// Sources or profiles accepted by one import request.
    pub const IMPORT_ROWS: usize = 500;
    /// URLs DNS-vetted per import request; the rest are re-vetted at fetch
    /// time (the fetch path re-vets every request anyway).
    pub const IMPORT_DNS_VET: usize = 25;
}

/// Clamp a requested page size into the allowed range.
pub fn clamp_limit(requested: Option<i64>) -> i64 {
    requested.unwrap_or(PAGE_SIZE).clamp(1, MAX_PAGE_SIZE)
}

/// SQL `OFFSET` for a 1-based page number.
///
/// `page` comes from the query string and is only clamped from below, so the
/// plain `(page - 1) * per_page` overflowed on `?page=9223372036854775807`:
/// a debug build panicked inside the handler, and release wrapped to a
/// negative offset (security audit, 2026-09-05). Saturating instead yields an
/// offset past the end, i.e. an empty page.
pub fn page_offset(page: i64, per_page: i64) -> i64 {
    page.saturating_sub(1).saturating_mul(per_page)
}

/// Build the pagination context: `(page number, is current)` pairs to
/// render, with gaps encoded as `(0, false)` sentinel rows the templates
/// print as `…`. Templates iterate without any arithmetic of their own.
///
/// The window is first/last plus ±2 around the current page, so the render
/// cost is bounded (~9 links) no matter how large the table is: with a
/// million-row `fetch_log` and `per_page=1` the old `1..=pages` loop
/// emitted a million `<a>` tags per request (security audit v2,
/// 2026-09-09, F9).
pub fn pagination_pages(page: i64, total: i64, per_page: i64) -> Vec<(i64, bool)> {
    let per_page = per_page.max(1);
    // Stable ceiling division (i64::div_ceil is not stable on this
    // toolchain); `total` is a COUNT and non-negative.
    let pages = (total.max(0) + per_page - 1) / per_page.max(1);
    let pages = pages.max(1);
    let current = page.clamp(1, pages);
    const SPAN: i64 = 2;

    let mut wanted: Vec<i64> = Vec::new();
    let push = |p: i64, wanted: &mut Vec<i64>| {
        if (1..=pages).contains(&p) && !wanted.contains(&p) {
            wanted.push(p);
        }
    };
    push(1, &mut wanted);
    for p in (current - SPAN)..=(current + SPAN) {
        push(p, &mut wanted);
    }
    push(pages, &mut wanted);
    wanted.sort_unstable();

    let mut out: Vec<(i64, bool)> = Vec::with_capacity(wanted.len() * 2);
    let mut previous: Option<i64> = None;
    for p in wanted {
        if let Some(prev) = previous
            && p > prev + 1
        {
            out.push((0, false)); // gap marker
        }
        out.push((p, p == current));
        previous = Some(p);
    }
    out
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

    /// `?page=i64::MAX` overflowed the offset multiply: a debug build panicked
    /// inside the handler (security audit, 2026-09-05).
    #[test]
    fn page_offset_saturates_instead_of_overflowing() {
        assert_eq!(page_offset(1, 50), 0);
        assert_eq!(page_offset(3, 50), 100);
        assert_eq!(page_offset(i64::MAX, MAX_PAGE_SIZE), i64::MAX);
        assert_eq!(page_offset(i64::MIN, MAX_PAGE_SIZE), i64::MIN);
    }

    /// The pagination window is bounded no matter how many pages the table
    /// has: a million-row `fetch_log` at `per_page=1` used to render a
    /// million links per request (security audit v2, 2026-09-09, F9).
    #[test]
    fn pagination_pages_render_a_bounded_window() {
        // Deep inside a huge table: first, current±2, last, with gaps.
        let window = pagination_pages(500_000, 1_000_000, 1);
        assert_eq!(
            window,
            vec![
                (1, false),
                (0, false), // gap
                (499_998, false),
                (499_999, false),
                (500_000, true),
                (500_001, false),
                (500_002, false),
                (0, false), // gap
                (1_000_000, false),
            ]
        );
        // The render is bounded: ~9 elements for any page count.
        assert!(window.len() <= 9);

        // Near the start the window is contiguous up to current±2, then a
        // gap, then the last page.
        let window = pagination_pages(3, 100, 10);
        assert_eq!(
            window,
            vec![
                (1, false),
                (2, false),
                (3, true),
                (4, false),
                (5, false),
                (0, false), // gap before the last page
                (10, false),
            ]
        );

        // When current±2 already reaches the last page, no gap appears.
        let window = pagination_pages(4, 50, 10);
        assert_eq!(
            window,
            vec![(1, false), (2, false), (3, false), (4, true), (5, false)]
        );

        // A single page renders nothing (the templates check len > 1).
        assert_eq!(pagination_pages(1, 7, 50), vec![(1, true)]);
        // A page beyond the end clamps to the last page; the window then
        // covers everything up to it — no gap needed for four pages.
        let window = pagination_pages(i64::MAX, 40, 10);
        assert_eq!(window, vec![(1, false), (2, false), (3, false), (4, true)]);
    }

    /// A `HashMap` keeps only the last value of a repeating key, which broke
    /// the proxy list's multi-select status filter.
    #[test]
    fn query_pairs_keep_every_value_of_a_repeating_key() {
        use axum::extract::Query;

        let uri: axum::http::Uri =
            "/admin/proxies?status=unknown&status=alive&page=2&status=quarantine"
                .parse()
                .expect("uri parses");
        let Query(pairs) = Query::<QueryPairs>::try_from_uri(&uri).expect("query parses");
        assert_eq!(
            pairs.all("status").collect::<Vec<_>>(),
            vec!["unknown", "alive", "quarantine"]
        );
        // Single-valued lookups keep HashMap-like semantics.
        assert_eq!(pairs.get("page").map(String::as_str), Some("2"));
        assert_eq!(pairs.get("missing"), None);

        // The old FormMap behavior, for contrast: last value wins.
        let Query(map) = Query::<FormMap>::try_from_uri(&uri).expect("query parses");
        assert_eq!(map.get("status").map(String::as_str), Some("quarantine"));
    }
}
