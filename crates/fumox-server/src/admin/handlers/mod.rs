//! Admin screen handlers. The list screens and card reads go through the
//! typed `fumox_core::repo` layer (their dynamic filters live there, in
//! one place); the dashboard's cross-table aggregates are the remaining
//! read queries specific to the admin UI, and shared mutations go through
//! `fumox_core::repo`.

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
use crate::admin::pipeline_editor::BuilderState;
use crate::admin::presentation::{fmt_day_element, fmt_day_plain};
use crate::admin::render_html;
use crate::admin::theme::{self, Theme};
use crate::fetcher;
use crate::pipeline::{CompiledPipeline, PipelineIssue};
use askama::Template;
use axum::extract::State;
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Redirect, Response};

use crate::admin::dash_top_n::{self, DashTopN};
use fumox_core::models::ProxyStatus;

/// Dashboard (merged with the former statistics screen,
/// aggregate counters, source errors (the
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
    /// Age in seconds of the last scheduler sweep start (stamped into
    /// `meta.server_cycle` in `scheduler::sweep`), rendered as a sub-line
    /// of the fetches card. `None` until the first sweep ever ran. A
    /// stamp that exists but does not parse is a different fact: it sets
    /// [`Self::server_cycle_corrupt`] instead of collapsing into the
    /// clean "no sweep yet" state.
    server_cycle_age_secs: Option<i64>,
    /// The `server_cycle` stamp exists but does not parse: a cut-short
    /// write or a format the reader does not know. Rendered as its own
    /// "corrupt" state, so a broken stamp is never read as "no sweep yet".
    server_cycle_corrupt: bool,
    recent_errors: Vec<SourceErrorRow>,
    /// The source-errors read failed: the block renders empty with an
    /// inline note instead of failing the whole page (the rest of the
    /// dashboard is independent of that one query).
    recent_errors_unavailable: bool,
    /// Per-source health counters (the former stats screen table).
    sources: Vec<SourceStatRow>,
    /// The per-source health read failed; same degradation as
    /// [`Self::recent_errors_unavailable`].
    sources_unavailable: bool,
    top_alive: Vec<TopAliveRow>,
    schemes: Vec<SchemeSplitRow>,
    countries: Vec<CountrySplitRow>,
    /// `(min, avg, median)` latency of alive proxies with a measurement.
    latency_min: Option<i64>,
    latency_avg: Option<i64>,
    latency_median: Option<i64>,
    /// `(total probes in 24h, successful probes in 24h)`. Speed probes
    /// are excluded: they measure transfer bandwidth, not liveness, so
    /// they are not a check that can succeed or fail.
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
    /// Configurable Top-N from the `fumox_dash_top_n` cookie, drives the
    /// `recent_errors`, `top_alive`, `top_failures` widgets and the country
    /// split's display cap.
    top_n: DashTopN,
    /// Top failure reasons (error message, hit count) over the last 24h,
    /// ordered by hit count descending. Populated by
    /// `fumox_core::repo::probe::top_failure_reasons`.
    top_failures: Vec<(String, i64)>,
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
    unknown: i64,
    alive: i64,
    ready: i64,
    quarantine: i64,
    removed: i64,
    total: i64,
    /// Oldest `created_at` among this source's ready proxies.
    oldest_ready_at: Option<i64>,
}

/// One row of the "longest-living ready (T2-verified) proxies" top.
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
// call arguments by reference, so every helper takes &T. The timestamp
// helpers (`ts`, `opt_ts`) come from `impl_i18n!`.
impl DashboardTemplate {
    /// Calendar day of an ingest-chart bucket, date only (the chart's
    /// columns are midnight UTC and a timestamp does not fit them).
    fn day(&self, ts: &i64) -> String {
        fmt_day_element(*ts)
    }
    /// The same day as plain text, for the `aria-label` of a chart column
    /// (an attribute must not carry the `<time>` element).
    fn day_plain(&self, ts: &i64) -> String {
        fmt_day_plain(*ts)
    }
    fn proxy_total(&self) -> i64 {
        self.proxy_counts.iter().map(|(_, count)| count).sum()
    }
    fn flag(&self, country: &Option<String>) -> String {
        flag_for(country)
    }
    /// Percentage of `part` relative to `whole` (0 when whole is 0).
    fn pct(&self, part: &i64, whole: &i64) -> i64 {
        pct_of(*part, *whole)
    }
    /// Width in percent of one distribution bar (relative to the largest
    /// bucket of its group); 1 is the floor so non-zero counts stay visible.
    fn bar_width(&self, count: &i64, max: &i64) -> i64 {
        bar_width_of(*count, *max)
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

/// Percentage of `part` relative to `whole` (0 when whole is 0). The
/// arithmetic of [`DashboardTemplate::pct`], free so it is testable
/// without a template instance.
fn pct_of(part: i64, whole: i64) -> i64 {
    if whole == 0 { 0 } else { (part * 100) / whole }
}

/// Width in percent of one distribution bar (relative to the largest
/// bucket of its group); 1 is the floor so non-zero counts stay visible.
/// The arithmetic of [`DashboardTemplate::bar_width`], free so it is
/// testable without a template instance.
fn bar_width_of(count: i64, max: i64) -> i64 {
    if max <= 0 || count <= 0 {
        0
    } else {
        (count * 100 / max).max(1)
    }
}

impl_i18n!(DashboardTemplate);

pub async fn dashboard(State(state): State<AdminState>, headers: HeaderMap) -> Response {
    let started = std::time::Instant::now();
    let lang = state.locales.lang_from_headers(&headers);
    // `dashboard_inner` carries the `?`-style flow and answers either the
    // rendered model or the finished error response; the only match on
    // the error path stays here.
    let template = match dashboard_inner(&state, &headers, &lang).await {
        Ok(template) => template,
        Err(response) => return response,
    };
    // One timing line per render: a slow dashboard is visible in the log
    // without reproducing it.
    tracing::debug!(
        elapsed_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
        "dashboard rendered"
    );
    render_html(lang.clone(), "dashboard.html", &template, StatusCode::OK)
}

/// The dashboard's reads. Every fallible step maps its error to the
/// finished 500 response with the name of the failed query in the log,
/// so the `?`s below stay one-liners; the two widgets the operator
/// triages from (source errors, per-source health) degrade on their own
/// instead ([`DashboardTemplate::recent_errors_unavailable`]).
#[allow(clippy::result_large_err)] // the Err is a finished Response, by design
async fn dashboard_inner(
    state: &AdminState,
    headers: &HeaderMap,
    lang: &Lang,
) -> Result<DashboardTemplate, Response> {
    let theme = theme::from_headers(headers);
    let top_n = dash_top_n::from_headers(headers);
    let pool = &state.pool;

    // One read transaction for the whole screen: every counter and every
    // list below is read from the same snapshot, so a proxy that changes
    // state between two queries cannot make the page contradict itself.
    // The transaction also holds one connection instead of taking one per
    // query.
    let mut tx = pool
        .begin()
        .await
        .map_err(|err| server_error(state, headers, "dashboard.begin", &err))?;

    let (src_total, src_enabled, src_errors): (i64, i64, i64) = sqlx::query_as(
        "SELECT COUNT(*), COALESCE(SUM(enabled), 0),
                COALESCE(SUM(error_class IS NOT NULL), 0) FROM sources",
    )
    .fetch_one(&mut *tx)
    .await
    .map_err(|err| server_error(state, headers, "dashboard.sources", &err))?;

    let profiles_total: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM profiles")
        .fetch_one(&mut *tx)
        .await
        .map_err(|err| server_error(state, headers, "dashboard.profiles", &err))?;

    // The proxy counters come from one grouped pass over the table, so
    // the breakdown by status and the scalar counters cannot disagree.
    let aggregates = fumox_core::repo::proxies::status_aggregates(&mut *tx)
        .await
        .map_err(|err| server_error(state, headers, "dashboard.status_aggregates", &err))?;
    let proxy_counts = aggregates.counts.clone();

    let day_ago = fumox_core::models::now_ts() - 86_400;
    let (fetch_total_24h, fetch_ok_24h): (i64, i64) =
        fumox_core::repo::fetch_log::success_counts_since(&mut *tx, day_ago)
            .await
            .map_err(|err| server_error(state, headers, "dashboard.fetch_24h", &err))?;

    // The two widgets the operator triages from degrade independently: a
    // failed read leaves the block empty with an inline note instead of
    // taking the whole screen down.
    let (recent_errors, recent_errors_unavailable): (Vec<SourceErrorRow>, bool) =
        match sqlx::query_as(
            "SELECT id, name, error_class, last_error, last_fetched_at FROM sources
             WHERE error_class IS NOT NULL
             ORDER BY COALESCE(last_fetched_at, 0) DESC LIMIT ?",
        )
        .bind(top_n.as_i64())
        .fetch_all(&mut *tx)
        .await
        {
            Ok(rows) => (rows, false),
            Err(err) => {
                tracing::warn!(error = %err, "the dashboard source-errors widget failed to load");
                (Vec::new(), true)
            }
        };

    // Per-source health counters (single aggregate over the join table).
    let (sources, sources_unavailable): (Vec<SourceStatRow>, bool) = match source_health_split(
        &mut *tx,
    )
    .await
    {
        Ok(rows) => (rows, false),
        Err(err) => {
            tracing::warn!(error = %err, "the dashboard per-source health widget failed to load");
            (Vec::new(), true)
        }
    };

    // Longest-living ready proxies: oldest `created_at` first, the
    // tunnel-verified tier (`ready`) is a strict subset of `alive`, set
    // only by a successful T2, so showing the top-N there surfaces the
    // proxies that have stayed end-to-end working the longest. The tier
    // is bound like every status value on this screen: no inline status
    // literal survives in the dashboard's SQL. The picked ids come from
    // a CTE, so the LIMIT applies before the source-links fan-out joins
    // in their names.
    let top_alive: Vec<TopAliveRow> = sqlx::query_as(
        "WITH picked AS (
             SELECT id FROM proxies WHERE status = ?
             ORDER BY created_at ASC, id ASC LIMIT ?
         )
         SELECT p.id, p.name, p.scheme, p.host, p.port, p.latency_ms, p.geo_country,
                p.created_at,
                COALESCE(GROUP_CONCAT(s.name, ', '), '') AS source_names
         FROM picked
         JOIN proxies p ON p.id = picked.id
         JOIN proxy_source_links l ON l.proxy_id = p.id
         JOIN sources s ON s.id = l.source_id
         GROUP BY p.id
         ORDER BY p.created_at ASC, p.id ASC",
    )
    .bind(ProxyStatus::Ready.as_str())
    .bind(top_n.as_i64())
    .fetch_all(&mut *tx)
    .await
    .map_err(|err| server_error(state, headers, "dashboard.top_alive", &err))?;

    let schemes = scheme_split(&mut *tx)
        .await
        .map_err(|err| server_error(state, headers, "dashboard.scheme_split", &err))?;
    let countries = country_split(&mut *tx, top_n.as_i64())
        .await
        .map_err(|err| server_error(state, headers, "dashboard.country_split", &err))?;

    // Latency of the live pool (`alive` and `ready`): the same set the
    // dashboard's other widgets count. SQLite has no median builtin, so
    // the median is a separate window-function query.
    let (latency_min, latency_avg) = (aggregates.latency_min, aggregates.latency_avg);
    let latency_median = fumox_core::repo::proxies::latency_median(&mut *tx)
        .await
        .map_err(|err| server_error(state, headers, "dashboard.latency_median", &err))?;

    // Probe success rate over the last 24 hours. Speed probes are
    // excluded (see `probe::success_counts_since`): they measure
    // transfer bandwidth, not liveness.
    let (probes_total_24h, probes_ok_24h): (i64, i64) =
        fumox_core::repo::probe::success_counts_since(&mut *tx, day_ago)
            .await
            .map_err(|err| server_error(state, headers, "dashboard.probes_24h", &err))?;

    // Top failure reasons over the rolling 24h window, the operator's
    // most actionable signal after the source-errors block at the top:
    // "what kind of probe failure is happening most often right now?"
    let top_failures: Vec<(String, i64)> =
        fumox_core::repo::probe::top_failure_reasons(&mut *tx, day_ago, top_n.as_i64())
            .await
            .map_err(|err| server_error(state, headers, "dashboard.top_failures", &err))?;

    // Ingest dynamics: proxies created per day over the last 7 days,
    // zero-filled for gap days (the chart must not silently skip a day).
    let rows: Vec<IngestDayRow> = sqlx::query_as(
        "SELECT (created_at / 86400) * 86400 AS day, COUNT(*) AS created
         FROM proxies
         WHERE created_at >= ?
         GROUP BY day ORDER BY day",
    )
    .bind(day_ago - 6 * 86_400)
    .fetch_all(&mut *tx)
    .await
    .map_err(|err| server_error(state, headers, "dashboard.ingest_days", &err))?;
    let now = fumox_core::models::now_ts();
    let ingest_days = fill_ingest_days(&rows, now);
    let ingest_max = ingest_days
        .iter()
        .map(|(_, count)| *count)
        .max()
        .unwrap_or(0);

    // Age of the scheduler's last sweep (the stamp is written at sweep
    // start, so a hung sweep shows as aging). A negative clock skew clamps
    // to zero rather than rendering "-3 s". A stamp that does not parse
    // is its own "corrupt" state, not the clean "no sweep yet".
    let server_cycle_raw =
        fumox_core::repo::meta_get(&mut *tx, fumox_core::repo::probe::meta::SERVER_CYCLE_KEY)
            .await
            .map_err(|err| server_error(state, headers, "dashboard.server_cycle", &err))?;
    let (server_cycle_age_secs, server_cycle_corrupt) = match server_cycle_raw {
        Some(raw) => match raw.parse::<i64>() {
            Ok(ts) => (Some((now - ts).max(0)), false),
            Err(_) => {
                tracing::warn!(
                    key = fumox_core::repo::probe::meta::SERVER_CYCLE_KEY,
                    raw_len = raw.len(),
                    "unparseable server cycle stamp"
                );
                (None, true)
            }
        },
        None => (None, false),
    };

    tx.commit()
        .await
        .map_err(|err| server_error(state, headers, "dashboard.commit", &err))?;

    Ok(DashboardTemplate {
        lang: lang.clone(),
        langs: state.locales.choices().to_vec(),
        theme,
        active: "dashboard",
        csrf: state.csrf_for(headers),
        sources_total: src_total,
        sources_enabled: src_enabled,
        sources_with_errors: src_errors,
        profiles_total,
        proxy_counts,
        fetch_total_24h,
        fetch_ok_24h,
        server_cycle_age_secs,
        server_cycle_corrupt,
        recent_errors,
        recent_errors_unavailable,
        sources,
        sources_unavailable,
        top_alive,
        schemes,
        countries,
        latency_min,
        latency_avg,
        latency_median,
        probes_total_24h,
        probes_ok_24h,
        unprobeable: aggregates.unprobeable,
        quarantine_second_chance: aggregates.quarantine_second_chance,
        in_quarantine: aggregates.in_quarantine,
        never_checked: aggregates.never_checked,
        ingest_days,
        ingest_max,
        top_n,
        top_failures,
    })
}

/// The 7-day ingest series, oldest first, zero-filled for gap days: a
/// day with no creations must still render as an empty column, not be
/// skipped silently.
fn fill_ingest_days(rows: &[IngestDayRow], now: i64) -> Vec<(i64, i64)> {
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
    ingest_days
}

/// The per-status SUM columns the split queries select: one bound
/// `COALESCE(SUM(...), 0)` per status, aliased with the status name the
/// row structs and the dashboard template key on. Generated from
/// [`ProxyStatus::all`], so a new status joins every split instead of
/// silently dropping out of the buckets (the bucket-sum test in this
/// module fails until the row struct grows the matching column).
fn status_sum_sql(column: &str) -> String {
    ProxyStatus::all()
        .iter()
        .map(|status| format!("COALESCE(SUM({column} = ?), 0) AS {}", status.as_str()))
        .collect::<Vec<_>>()
        .join(", ")
}

/// Per-source health counters (single aggregate over the join table).
/// The status literals travel as bound parameters: the SUM predicate set
/// is generated from `ProxyStatus::all()`, so a new status joins the
/// table instead of silently dropping out of the buckets.
async fn source_health_split<'e, E>(executor: E) -> Result<Vec<SourceStatRow>, fumox_core::Error>
where
    E: sqlx::Executor<'e, Database = sqlx::Sqlite>,
{
    let status_sums = status_sum_sql("p.status");
    let mut query = sqlx::query_as::<_, SourceStatRow>(sqlx::AssertSqlSafe(format!(
        "SELECT s.id, s.name, s.enabled,
                {status_sums},
                COUNT(DISTINCT p.id) AS total,
                MIN(CASE WHEN p.status = ? THEN p.created_at END) AS oldest_ready_at
         FROM sources s
         LEFT JOIN proxy_source_links l ON l.source_id = s.id
         LEFT JOIN proxies p ON p.id = l.proxy_id
         GROUP BY s.id
         ORDER BY alive DESC, total DESC, s.name COLLATE NOCASE",
    )));
    for status in ProxyStatus::all() {
        query = query.bind(status.as_str());
    }
    Ok(query
        .bind(ProxyStatus::Ready.as_str())
        .fetch_all(executor)
        .await?)
}

/// Grouped health counters per scheme, largest bucket first (`scheme` is
/// never NULL, so the value binds to a plain `String`).
async fn scheme_split<'e, E>(executor: E) -> Result<Vec<SchemeSplitRow>, fumox_core::Error>
where
    E: sqlx::Executor<'e, Database = sqlx::Sqlite>,
{
    let status_sums = status_sum_sql("status");
    let mut query = sqlx::query_as::<_, SchemeSplitRow>(sqlx::AssertSqlSafe(format!(
        "SELECT scheme AS value,
                {status_sums},
                COUNT(*) AS total
         FROM proxies
         GROUP BY scheme
         ORDER BY total DESC, value ASC",
    )));
    for status in ProxyStatus::all() {
        query = query.bind(status.as_str());
    }
    Ok(query.fetch_all(executor).await?)
}

/// Grouped health counters per country, largest bucket first; proxies
/// without a resolved country land in the trailing NULL bucket. `limit`
/// caps the rows returned by the SQL (the dashboard widget uses it to
/// match the operator's configurable Top-N setting).
async fn country_split<'e, E>(
    executor: E,
    limit: i64,
) -> Result<Vec<CountrySplitRow>, fumox_core::Error>
where
    E: sqlx::Executor<'e, Database = sqlx::Sqlite>,
{
    let status_sums = status_sum_sql("status");
    let mut query = sqlx::query_as::<_, CountrySplitRow>(sqlx::AssertSqlSafe(format!(
        "SELECT geo_country AS value,
                {status_sums},
                COUNT(*) AS total
         FROM proxies
         GROUP BY geo_country
         ORDER BY total DESC, value IS NULL, value ASC
         LIMIT ?",
    )));
    for status in ProxyStatus::all() {
        query = query.bind(status.as_str());
    }
    Ok(query.bind(limit).fetch_all(executor).await?)
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

/// A byte count that may not be there, as the cards render it: the
/// formatted size, or the neutral `common.na` placeholder for a reading
/// the row does not carry. One definition for every card and fragment,
/// so the empty state cannot drift between them.
pub(super) fn fmt_opt_bytes(lang: &Lang, bytes: Option<i64>) -> String {
    bytes
        .map(|bytes| fmt_bytes(lang, bytes))
        .unwrap_or_else(|| lang.t("common.na").to_string())
}

/// The tail every masked secret ends with. It marks a value as a mask,
/// so a form can tell a mask from a typed secret.
pub const MASK_TAIL: &str = "••••";

/// Credential masking for lists and forms: first three
/// characters plus a fixed tail; short values are hidden entirely.
pub fn mask_secret(value: &str) -> String {
    if value.is_empty() {
        return String::new();
    }
    if value.chars().count() <= 3 {
        return MASK_TAIL.to_string();
    }
    let prefix: String = value.chars().take(3).collect();
    format!("{prefix}…{MASK_TAIL}")
}

/// Flag emoji for a stored ISO country code.
pub fn flag_for(country: &Option<String>) -> String {
    country
        .as_deref()
        .and_then(fumox_core::geo::flag_emoji)
        .unwrap_or_default()
}

/// Short correlation id of one admin 500: 8 hex characters, enough to
/// grep the log for the exact failure behind a message the operator
/// saw, and to tell two failures apart.
fn error_id() -> String {
    use std::sync::atomic::{AtomicU32, Ordering};
    static SEQUENCE: AtomicU32 = AtomicU32::new(0);
    // Sub-second clock plus a process-wide sequence (mixed with a fixed
    // odd constant, so two ids never collide by cancellation): no crypto
    // is wanted here, only uniqueness within the deployment's log.
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0u32, |d| d.subsec_nanos());
    let seq = SEQUENCE.fetch_add(1, Ordering::Relaxed);
    format!("{:08x}", nanos ^ seq.wrapping_mul(0x9E37_79B9))
}

/// Standard 500 for unexpected failures. `ctx` names the read or write
/// that failed, so the log line says which query broke without the
/// reader reverse-engineering the call stack, and `error_id` ties the
/// line to the response the operator saw. The shape follows the client:
/// an HTMX request keeps the 500 (htmx does not swap error bodies, so
/// the page survives) with the failure delivered as an error toast
/// through `HX-Trigger`; a plain browser gets the error page in the
/// common layout, with the correlation id and a way back to the panel.
pub fn server_error(
    state: &AdminState,
    headers: &HeaderMap,
    ctx: &str,
    err: &impl std::fmt::Display,
) -> Response {
    let lang = state.locales.lang_from_headers(headers);
    let id = error_id();
    tracing::error!(error_id = %id, query = ctx, error = %err, "admin handler failed");
    if is_htmx(headers) {
        let message = lang.t("err.internal").to_string();
        let mut response = (
            StatusCode::INTERNAL_SERVER_ERROR,
            [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
            format!("{message}\n{}\n", lang.t("err.error_id").replace("{}", &id)),
        )
            .into_response();
        response
            .headers_mut()
            .insert("HX-Trigger", toast_trigger("error", &message));
        return response;
    }
    render_html(
        lang.clone(),
        "error.html",
        &ErrorPage {
            lang,
            langs: state.locales.choices().to_vec(),
            theme: theme::from_headers(headers),
            active: "error",
            csrf: state.csrf_for(headers),
            error_id: id,
        },
        StatusCode::INTERNAL_SERVER_ERROR,
    )
}

/// Error page in the common layout: what a plain browser gets instead of
/// a bare text 500 (see [`server_error`]).
#[derive(Template)]
#[template(path = "error.html")]
struct ErrorPage {
    lang: Lang,
    langs: Vec<(String, String)>,
    theme: Theme,
    active: &'static str,
    csrf: String,
    /// The correlation id the log line carries (see [`error_id`]).
    error_id: String,
}

impl_i18n!(ErrorPage);

/// Why a submitted form could not be turned into a model.
#[derive(Debug)]
pub(super) enum FormError {
    /// Per-field errors, shown next to the fields.
    Validation(Vec<(String, String)>),
    /// The row behind the form could not be read: a missing entity or a
    /// database failure. Neither is a form error, so neither is rendered
    /// as one.
    Server(fumox_core::Error),
}

/// The response for a form whose row could not be read: a missing entity
/// is a 404, a database failure is a 500.
///
/// The two used to travel as one (`Option::None` for both), so a broken
/// database answered "not found" and a client could not tell a deleted
/// row from a failed query. `not_found_key` doubles as the log context:
/// it already names the entity the read was for.
pub(super) fn row_error_response(
    state: &AdminState,
    headers: &HeaderMap,
    err: &fumox_core::Error,
    not_found_key: &str,
) -> Response {
    match err {
        fumox_core::Error::NotFound(_) => {
            not_found(state.locales.lang_from_headers(headers), not_found_key)
        }
        other => server_error(state, headers, not_found_key, other),
    }
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
/// (isomorphic decode), so raw UTF-8, e.g. a Russian toast message, would
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
        response
            .headers_mut()
            .insert("HX-Trigger", toast_trigger(level, toast));
        response
    } else {
        // Plain-browser path: an HTMX-only toast would be lost here, so
        // the message rides back on the redirect URL and the layout shows
        // it once on load (see base.html).
        flash_redirect(redirect_to, toast, level)
    }
}

/// Redirect carrying one toast for the plain-browser path.
///
/// The message rides in a response header, not in the URL: the
/// middleware in `crate::admin` moves it into the session's slot and
/// strips the header, so the text never reaches the browser, the address
/// bar or the history. The page asks for it once after the redirect.
pub(super) fn flash_redirect(redirect_to: &str, toast: &str, level: &str) -> Response {
    let mut response = Redirect::to(redirect_to).into_response();
    let headers = response.headers_mut();
    headers.insert(
        crate::admin::flash::FLASH_HEADER,
        HeaderValue::from_str(&header_safe(toast)).expect("header_safe output is visible ASCII"),
    );
    headers.insert(
        crate::admin::flash::FLASH_LEVEL_HEADER,
        HeaderValue::from_str(level).expect("the flash level is a plain word"),
    );
    response
}

/// `HX-Trigger` value for one toast. The message is percent-encoded for
/// the same reason as [`header_safe`] (header bytes are Latin-1 on the
/// wire, raw UTF-8 would mojibake) and because a raw `"` in the message
/// would break the JSON envelope.
pub(super) fn toast_trigger(level: &str, message: &str) -> HeaderValue {
    let payload = format!(
        "{{\"toast\": {{\"message\": \"{}\", \"level\": \"{level}\"}}}}",
        header_safe(message)
    );
    HeaderValue::from_str(&payload).expect("header_safe output is visible ASCII")
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
/// last value, which broke the proxy list's multi-select status filter
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

/// Field/count caps for admin-stored input. A single POST is bounded by
/// the CSRF buffer (1 MiB) and the
/// router-wide `DefaultBodyLimit`; these caps keep what actually reaches
/// SQLite, and every later re-render of it, proportionate to what the
/// forms legitimately hold.
pub mod caps {
    /// Source/profile URL length (matches the fetcher's `MAX_URL_LEN`).
    pub const URL: usize = 2048;
    /// Stored pipeline JSON, in bytes.
    pub const PIPELINE_BYTES: usize = 64 * 1024;
    /// Source/profile display name, in characters.
    pub const NAME_MAX: usize = 200;
    /// Shortest cache TTL a source may carry, in seconds.
    pub const TTL_MIN: i64 = 60;
    /// Longest cache TTL a source may carry, in seconds.
    pub const TTL_MAX: i64 = 86_400;
    /// One profile access token.
    pub const ACCESS_TOKEN: usize = 128;
    /// Minimum length of an access token, in characters. The profile
    /// form and the import path apply the same floor: the token guards a
    /// public endpoint, so a guessable one is refused (F8).
    pub const TOKEN_MIN: usize = 16;
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
    /// Size of one import document (the JSON payload), in bytes.
    ///
    /// The payload travels inside a urlencoded form, where every byte may
    /// cost three (`"` → `%22`), so the 1 MiB transport limit still holds
    /// for the largest accepted document (256 KiB → 768 KiB encoded).
    pub const IMPORT_BODY_BYTES: usize = 256 * 1024;
    /// URLs DNS-vetted per import request; the rest are re-vetted at fetch
    /// time (the fetch path re-vets every request anyway).
    pub const IMPORT_DNS_VET: usize = 25;
    /// Overall deadline of the DNS-vetting window of one import.
    ///
    /// The per-URL timeout alone does not bound the window: 25 lookups of
    /// the per-URL timeout each add up. This caps the total time the
    /// request may spend on name resolution.
    pub const IMPORT_DNS_WINDOW: std::time::Duration = std::time::Duration::from_secs(30);
}

/// Slug rules shared by the source and profile forms and the import
/// validation: starts alphanumeric, then `[A-Za-z0-9_-]`, total length
/// 2–64. Compiled once; the form paths used to rebuild it on every
/// validation call.
static SLUG_RE: std::sync::LazyLock<regex::Regex> = std::sync::LazyLock::new(|| {
    regex::Regex::new(r"^[A-Za-z0-9][A-Za-z0-9_-]{1,63}$").expect("valid slug regex")
});

/// The id of a repo row: what the shared slug-uniqueness check compares
/// against the row being edited. Both slug tables (`sources`, `profiles`)
/// key their rows by a string id.
trait RowId {
    fn row_id(&self) -> &str;
}

impl RowId for fumox_core::models::Source {
    fn row_id(&self) -> &str {
        &self.id
    }
}

impl RowId for fumox_core::models::Profile {
    fn row_id(&self) -> &str {
        &self.id
    }
}

/// Validate the optional `slug` field shared by the source and profile
/// forms: format rules ([`SLUG_RE`]), then uniqueness. `lookup` resolves
/// the row of one slug table already holding the value; the future is
/// built eagerly but only awaited after the format check passes, and a DB
/// error counts as "free" (a slug that sneaks through still fails the
/// table's UNIQUE constraint at save time, as before). A row that is not
/// `existing_id` (the row being edited) means the slug is taken. Empty
/// input yields `None`; problems are pushed as `slug`-field errors.
async fn validate_slug<T, F>(
    slug_raw: &str,
    existing_id: Option<&str>,
    lang: &Lang,
    errors: &mut Vec<(String, String)>,
    lookup: F,
) -> Option<String>
where
    F: std::future::Future<Output = fumox_core::Result<Option<T>>>,
    T: RowId,
{
    if slug_raw.is_empty() {
        return None;
    }
    if let Err(message) = validate_slug_format(slug_raw, lang) {
        errors.push(("slug".into(), message));
        return Some(slug_raw.to_string());
    }
    match lookup.await {
        Ok(Some(other)) if other.row_id() != existing_id.unwrap_or_default() => {
            errors.push(("slug".into(), lang.t("val.slug_taken").into()));
        }
        Ok(_) => {}
        // A DB failure counts as "free" (the slug still fails the table's
        // UNIQUE constraint at save time), but a persistently broken
        // lookup must stay visible instead of silently disabling the
        // check.
        Err(err) => {
            tracing::warn!(error = %err, "slug uniqueness lookup failed, skipping check");
        }
    }
    Some(slug_raw.to_string())
}

/// Shared field validators.
///
/// The source form, the profile form and the import path enforce the
/// same rules, so a configuration file cannot plant an object the form
/// would refuse (and the other way round). Each validator answers with
/// the localized message: the form attaches it to its field, the import
/// prefixes it with the offending row.
///
/// Validate a display name: not empty, at most [`caps::NAME_MAX`]
/// characters.
pub(super) fn validate_name(name: &str, lang: &Lang) -> Result<(), String> {
    let trimmed = name.trim();
    if trimmed.is_empty() {
        return Err(lang.t("val.required").into());
    }
    if trimmed.chars().count() > caps::NAME_MAX {
        return Err(lang
            .t("val.field_too_long")
            .replace("{}", &caps::NAME_MAX.to_string()));
    }
    Ok(())
}

/// Validate a cache TTL: within [`caps::TTL_MIN`]..=[`caps::TTL_MAX`].
pub(super) fn validate_ttl(seconds: i64, lang: &Lang) -> Result<(), String> {
    if (caps::TTL_MIN..=caps::TTL_MAX).contains(&seconds) {
        Ok(())
    } else {
        Err(ttl_range_message(lang))
    }
}

/// The localized TTL-range message with the actual bounds substituted:
/// the numbers live next to [`caps::TTL_MIN`] / [`caps::TTL_MAX`], the
/// catalogs carry only `{min}` / `{max}` placeholders, so a cap change
/// cannot leave a stale range in the error text.
pub(super) fn ttl_range_message(lang: &Lang) -> String {
    lang.t_named(
        "val.ttl_range",
        &[
            ("min", caps::TTL_MIN.to_string()),
            ("max", caps::TTL_MAX.to_string()),
        ],
    )
}

/// Validate a slug's format (the uniqueness check is per table and stays
/// with the caller).
pub(super) fn validate_slug_format(slug: &str, lang: &Lang) -> Result<(), String> {
    if SLUG_RE.is_match(slug) {
        Ok(())
    } else {
        Err(lang.t("val.slug_format").into())
    }
}

/// Validate an access token: at most [`caps::ACCESS_TOKEN`] bytes and
/// only the unreserved ASCII the serve link embeds unescaped.
pub(super) fn validate_token(token: &str, lang: &Lang) -> Result<(), String> {
    if token.len() > caps::ACCESS_TOKEN {
        return Err(lang
            .t("val.field_too_long")
            .replace("{}", &caps::ACCESS_TOKEN.to_string()));
    }
    if !token
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '~'))
    {
        return Err(lang.t("val.token_format").into());
    }
    Ok(())
}

/// Validate a tag list: at most [`caps::TAGS`] tags, each at most
/// [`caps::TAG_BYTES`] bytes.
pub(super) fn validate_tags(tags: &[String], lang: &Lang) -> Result<(), String> {
    if tags.len() > caps::TAGS {
        return Err(lang
            .t("val.too_many_tags")
            .replace("{}", &caps::TAGS.to_string()));
    }
    if tags.iter().any(|tag| tag.len() > caps::TAG_BYTES) {
        return Err(lang
            .t("val.field_too_long")
            .replace("{}", &caps::TAG_BYTES.to_string()));
    }
    Ok(())
}

/// Validate a header map: at most [`caps::HEADER_LINES`] entries, at most
/// [`caps::HEADER_BYTES`] bytes in total, and every name/value the HTTP
/// layer would accept.
pub(super) fn validate_header_map(
    headers: &std::collections::BTreeMap<String, String>,
    lang: &Lang,
) -> Result<(), String> {
    if headers.len() > caps::HEADER_LINES {
        return Err(lang
            .t("val.too_many_headers")
            .replace("{}", &caps::HEADER_LINES.to_string()));
    }
    let total: usize = headers.iter().map(|(k, v)| k.len() + v.len()).sum();
    if total > caps::HEADER_BYTES {
        return Err(lang
            .t("val.headers_too_long")
            .replace("{}", &caps::HEADER_BYTES.to_string()));
    }
    for (key, value) in headers {
        if axum::http::HeaderName::try_from(key.as_str()).is_err()
            || axum::http::HeaderValue::try_from(value.as_str()).is_err()
        {
            return Err(lang.t("val.header_invalid").replace("{}", key));
        }
    }
    Ok(())
}

/// Validate a country allowlist and return it normalized (uppercase,
/// without repeats): at most [`caps::COUNTRIES`] codes, each parsed by
/// the shared [`fumox_core::models::CountryCode`] rule (exactly two ASCII
/// letters), so a code the forms accept cannot be refused by the import
/// path or the cleanup forms, and the other way round.
pub(super) fn validate_countries(countries: &[String], lang: &Lang) -> Result<Vec<String>, String> {
    let mut normalized: Vec<String> = Vec::with_capacity(countries.len());
    for code in countries {
        let code = code.trim();
        if code.is_empty() {
            continue;
        }
        let Some(upper) = fumox_core::models::CountryCode::parse(code) else {
            return Err(lang.t("val.country_format").replace("{}", code));
        };
        let upper = upper.as_str().to_string();
        if !normalized.contains(&upper) {
            normalized.push(upper);
        }
    }
    if normalized.len() > caps::COUNTRIES {
        return Err(lang
            .t("val.too_many_countries")
            .replace("{}", &caps::COUNTRIES.to_string()));
    }
    Ok(normalized)
}

/// Compact size of a pipeline document, the measure both form builders
/// apply to the *generated* JSON and the import path to every stored
/// document: the stored JSON is re-rendered into every edit form and
/// recompiled by the preview, so a form or a file could otherwise plant a
/// pipeline up to the 1 MiB body limit (16× the form cap).
///
/// The raw form mode and the import path measure the same document: the
/// compact JSON, which is what the database stores. The textarea of the
/// raw mode holds the pretty rendering of that document, and a pretty
/// text is longer than the compact one, so measuring the text instead
/// would refuse documents the import accepts and reject them again on
/// every later save.
fn pipeline_size(pipeline: &serde_json::Value) -> usize {
    serde_json::to_string(pipeline).map_or(usize::MAX, |text| text.len())
}

/// Validate + build the stored pipeline value from the shared pipeline
/// widget fields (`pipeline_mode`, the widget rows, the raw `pipeline`
/// textarea) of the source and profile forms. In builder mode the JSON is
/// generated from the widget fields server-side (a stale `pipeline`
/// textarea, if any, is ignored); in raw mode the textarea is the input,
/// as before. Problems are pushed onto `errors` as `pipeline`-field
/// messages; `None` means no stored pipeline (or one that failed
/// validation).
fn pipeline_from_form(
    form: &[(String, String)],
    lang: &Lang,
    errors: &mut Vec<(String, String)>,
) -> Option<serde_json::Value> {
    // The last value of a repeated key wins — the same semantics as
    // `FormMap`.
    let get = |key: &str| -> String {
        form.iter()
            .rev()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.trim().to_string())
            .unwrap_or_default()
    };
    if get("pipeline_mode") == "builder" {
        let emitted = BuilderState::from_form(form).emit()?;
        // The field issues name the input to fix, the validator reads the
        // document without the values the typed schema could not hold:
        // one unreadable value must not mask the problems in the rest of
        // the pipeline.
        let issues = emitted.issues().to_vec();
        // The builder carries its own wording of the oversize message:
        // the fix is to drop widget rows, not to shorten a text field.
        pipeline_document(
            emitted.document(),
            emitted.readable(),
            issues,
            lang,
            errors,
            "val.pipeline_builder_too_long",
        )
    } else {
        let pipeline_raw = get("pipeline");
        if pipeline_raw.trim().is_empty() {
            None
        } else {
            match serde_json::from_str::<serde_json::Value>(&pipeline_raw) {
                Ok(value) => pipeline_document(
                    &value,
                    &value,
                    Vec::new(),
                    lang,
                    errors,
                    "val.pipeline_too_long",
                ),
                Err(err) => {
                    errors.push((
                        "pipeline".into(),
                        lang.t("val.invalid_json").replace("{}", &err.to_string()),
                    ));
                    None
                }
            }
        }
    }
}

/// The tail both form modes share: the cap is measured on the compact
/// JSON first — the stored form, the same measure the import path
/// applies, so a document of an accepted size is not refused again on
/// every later save — and an oversized document is refused before the
/// validator reads it, symmetric in both modes. Then the document is
/// compiled and every issue lands on the `pipeline` field. `readable`
/// is what the validator reads (the builder strips the values its typed
/// schema cannot hold); `issues` carries the field issues collected
/// before the compile pass; `too_long_key` is the mode's own wording of
/// the oversize message.
fn pipeline_document(
    value: &serde_json::Value,
    readable: &serde_json::Value,
    issues: Vec<PipelineIssue>,
    lang: &Lang,
    errors: &mut Vec<(String, String)>,
    too_long_key: &str,
) -> Option<serde_json::Value> {
    if pipeline_size(value) > caps::PIPELINE_BYTES {
        errors.push((
            "pipeline".into(),
            lang.t(too_long_key)
                .replace("{}", &caps::PIPELINE_BYTES.to_string()),
        ));
        return None;
    }
    let mut issues = issues;
    if let Err(found) = CompiledPipeline::from_json(Some(readable)) {
        issues.extend(found);
    }
    if !issues.is_empty() {
        for issue in issues {
            errors.push(("pipeline".into(), lang.t_args(issue.key, &issue.args)));
        }
        return None;
    }
    Some(value.clone())
}

/// Render a typed URL problem in the panel language. The fetcher layer
/// returns [`fetcher::UrlProblem`] variants and knows no catalog keys;
/// this is the only place that maps them onto the `val.url_*` section of
/// the locales (the source form and the import validation render it).
fn url_problem_message(lang: &Lang, problem: &fetcher::UrlProblem) -> String {
    let (key, args): (&'static str, Vec<String>) = match problem {
        fetcher::UrlProblem::TooLong(limit) => ("val.url_too_long", vec![limit.to_string()]),
        fetcher::UrlProblem::Invalid(message) => ("val.url_invalid", vec![message.clone()]),
        fetcher::UrlProblem::Scheme(scheme) => ("val.url_scheme", vec![scheme.clone()]),
        fetcher::UrlProblem::NoHost => ("val.url_no_host", Vec::new()),
        fetcher::UrlProblem::Ssrf { reason, .. } => ("val.url_ssrf", vec![reason.clone()]),
    };
    lang.t_args(key, &args)
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
/// negative offset. Saturating instead yields an
/// offset past the end, i.e. an empty page.
pub fn page_offset(page: i64, per_page: i64) -> i64 {
    page.saturating_sub(1).saturating_mul(per_page)
}

/// One element of the shared pagination strip ([`_pagination.html`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PageLink {
    /// The page the element leads to. For a gap marker this is the first
    /// page the window hides: the dots are a link to it, so a page the
    /// window skips is one click away, not unreachable.
    pub page: i64,
    /// Whether the element is the page the user is on (a span with
    /// `aria-current`, not a link).
    pub current: bool,
    /// Whether the element is a gap marker (`…`) between two runs of
    /// page numbers.
    pub gap: bool,
}

/// Build the pagination context: the [`PageLink`] elements to render.
/// Templates iterate without any arithmetic of their own.
///
/// The window is first/last plus ±2 around the current page, so the render
/// cost is bounded (~9 links) no matter how large the table is: with a
/// million-row `fetch_log` and `per_page=1` the old `1..=pages` loop
/// emitted a million `<a>` tags per request.
pub fn pagination_pages(page: i64, total: i64, per_page: i64) -> Vec<PageLink> {
    // Callers pass a clamped size (`clamp_limit`), so the divisor is at
    // least 1; saturating keeps the sum from overflowing on a huge COUNT.
    let per_page = per_page.max(1);
    // Stable ceiling division (i64::div_ceil is not stable on this
    // toolchain); `total` is a COUNT and non-negative.
    let pages = total.max(0).saturating_add(per_page - 1) / per_page;
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

    let mut out: Vec<PageLink> = Vec::with_capacity(wanted.len() * 2);
    let mut previous: Option<i64> = None;
    for p in wanted {
        if let Some(prev) = previous
            && p > prev + 1
        {
            out.push(PageLink {
                page: prev + 1,
                current: false,
                gap: true,
            });
        }
        out.push(PageLink {
            page: p,
            current: p == current,
            gap: false,
        });
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
    fn toast_header_is_ascii_and_decodes_to_the_message() {
        // Russian text (raw UTF-8 would mojibake in a Latin-1 header) plus
        // JSON-breaking characters.
        let message = "источник включён, \"quote\" \\ backslash";
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
        // The toast rides in a response header, not in the URL: the
        // redirect target stays clean, so nothing of the message ends up
        // in the address bar or the history.
        let location = response
            .headers()
            .get(header::LOCATION)
            .expect("plain path must redirect")
            .to_str()
            .unwrap();
        assert_eq!(location, "/admin/sources");
        let flash = response
            .headers()
            .get(crate::admin::flash::FLASH_HEADER)
            .expect("the toast must ride along")
            .to_str()
            .unwrap();
        // Percent-encoded so the wire stays ASCII.
        assert_eq!(flash, "%D0%B3%D0%BE%D1%82%D0%BE%D0%B2%D0%BE");
        assert!(
            response
                .headers()
                .get(crate::admin::flash::FLASH_LEVEL_HEADER)
                .is_some()
        );
    }

    /// The redirect target keeps its own query parameters: the flash
    /// does not touch the URL at all.
    #[test]
    fn flash_redirect_keeps_the_target_query() {
        let response = flash_redirect("/admin/proxies?page=2", "done", "error");
        let location = response
            .headers()
            .get(header::LOCATION)
            .expect("flash_redirect must carry a Location")
            .to_str()
            .unwrap();
        assert_eq!(location, "/admin/proxies?page=2");
        assert_eq!(
            response
                .headers()
                .get(crate::admin::flash::FLASH_LEVEL_HEADER)
                .unwrap(),
            "error"
        );
    }

    /// `?page=i64::MAX` overflowed the offset multiply: a debug build panicked
    /// inside the handler.
    #[test]
    fn page_offset_saturates_instead_of_overflowing() {
        assert_eq!(page_offset(1, 50), 0);
        assert_eq!(page_offset(3, 50), 100);
        assert_eq!(page_offset(i64::MAX, MAX_PAGE_SIZE), i64::MAX);
        assert_eq!(page_offset(i64::MIN, MAX_PAGE_SIZE), i64::MIN);
    }

    /// The dashboard's percent/bar arithmetic at the boundaries: zero
    /// whole, and the 1%-floor that keeps a non-zero bar visible while
    /// zero counts stay zero.
    #[test]
    fn pct_and_bar_width_hold_at_the_boundaries() {
        assert_eq!(pct_of(1, 0), 0);
        assert_eq!(pct_of(1, 4), 25);
        assert_eq!(bar_width_of(1, 100), 1);
        assert_eq!(bar_width_of(0, 100), 0);
        assert_eq!(bar_width_of(100, 0), 0);
    }

    /// The ingest series is seven pairs oldest-first, contiguous by day;
    /// a day without creations is zero, not skipped, and the bar scale
    /// takes the largest value of the series.
    #[test]
    fn ingest_days_are_oldest_first_and_zero_filled() {
        let now = 10 * 86_400 + 3_600; // mid of the last day
        let today = 10 * 86_400;
        // Rows for today and two days ago; yesterday has no row at all.
        let rows = [
            IngestDayRow {
                day: today - 2 * 86_400,
                created: 5,
            },
            IngestDayRow {
                day: today,
                created: 9,
            },
        ];
        let days = fill_ingest_days(&rows, now);
        assert_eq!(days.len(), 7);
        // Oldest first, one calendar day per pair.
        assert_eq!(days[0].0, today - 6 * 86_400);
        assert_eq!(days[6].0, today);
        for pair in days.windows(2) {
            assert_eq!(pair[1].0, pair[0].0 + 86_400);
        }
        // The skipped day is zero; the present days carry their counts.
        assert_eq!(days[4], (today - 2 * 86_400, 5));
        assert_eq!(days[5], (today - 86_400, 0));
        assert_eq!(days[6], (today, 9));
        // The bar scale is the maximum of the series.
        let ingest_max = days.iter().map(|(_, count)| *count).max().unwrap_or(0);
        assert_eq!(ingest_max, 9);
    }

    /// The pagination window is bounded no matter how many pages the table
    /// has: a million-row `fetch_log` at `per_page=1` used to render a
    /// million links per request.
    #[test]
    fn pagination_pages_render_a_bounded_window() {
        // Deep inside a huge table: first, current±2, last, with gaps.
        // A gap's `page` is the first page the window hides (the dots
        // are a link to it).
        let window = pagination_pages(500_000, 1_000_000, 1);
        assert_eq!(
            window,
            vec![
                PageLink {
                    page: 1,
                    current: false,
                    gap: false
                },
                PageLink {
                    page: 2,
                    current: false,
                    gap: true
                },
                PageLink {
                    page: 499_998,
                    current: false,
                    gap: false
                },
                PageLink {
                    page: 499_999,
                    current: false,
                    gap: false
                },
                PageLink {
                    page: 500_000,
                    current: true,
                    gap: false
                },
                PageLink {
                    page: 500_001,
                    current: false,
                    gap: false
                },
                PageLink {
                    page: 500_002,
                    current: false,
                    gap: false
                },
                PageLink {
                    page: 500_003,
                    current: false,
                    gap: true
                },
                PageLink {
                    page: 1_000_000,
                    current: false,
                    gap: false
                },
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
                PageLink {
                    page: 1,
                    current: false,
                    gap: false
                },
                PageLink {
                    page: 2,
                    current: false,
                    gap: false
                },
                PageLink {
                    page: 3,
                    current: true,
                    gap: false
                },
                PageLink {
                    page: 4,
                    current: false,
                    gap: false
                },
                PageLink {
                    page: 5,
                    current: false,
                    gap: false
                },
                PageLink {
                    page: 6,
                    current: false,
                    gap: true
                }, // before the last page
                PageLink {
                    page: 10,
                    current: false,
                    gap: false
                },
            ]
        );

        // When current±2 already reaches the last page, no gap appears.
        let window = pagination_pages(4, 50, 10);
        assert_eq!(
            window,
            vec![
                PageLink {
                    page: 1,
                    current: false,
                    gap: false
                },
                PageLink {
                    page: 2,
                    current: false,
                    gap: false
                },
                PageLink {
                    page: 3,
                    current: false,
                    gap: false
                },
                PageLink {
                    page: 4,
                    current: true,
                    gap: false
                },
                PageLink {
                    page: 5,
                    current: false,
                    gap: false
                },
            ]
        );

        // A single page renders nothing (the templates check len > 1).
        assert_eq!(
            pagination_pages(1, 7, 50),
            vec![PageLink {
                page: 1,
                current: true,
                gap: false
            }]
        );
        // A page beyond the end clamps to the last page; the window then
        // covers everything up to it, no gap needed for four pages.
        let window = pagination_pages(i64::MAX, 40, 10);
        assert_eq!(
            window,
            vec![
                PageLink {
                    page: 1,
                    current: false,
                    gap: false
                },
                PageLink {
                    page: 2,
                    current: false,
                    gap: false
                },
                PageLink {
                    page: 3,
                    current: false,
                    gap: false
                },
                PageLink {
                    page: 4,
                    current: true,
                    gap: false
                },
            ]
        );
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

    /// The language the shared form-validation helpers translate with: the
    /// embedded catalogs, without touching a locales directory.
    fn test_lang() -> Lang {
        crate::admin::i18n::Locales::load(std::path::Path::new("/nonexistent")).default_lang()
    }

    /// The shared pipeline form validation: raw mode takes the textarea
    /// verbatim, reports broken JSON as a `pipeline`-field error and
    /// stores a well-formed document as-is.
    #[test]
    fn pipeline_from_form_accepts_raw_json_and_reports_bad_input() {
        let lang = test_lang();

        // No mode field = raw mode; an empty textarea stores no pipeline.
        let mut errors = Vec::new();
        assert_eq!(pipeline_from_form(&[], &lang, &mut errors), None);
        assert!(errors.is_empty(), "{errors:?}");

        // A well-formed minimal document is accepted verbatim.
        let form = vec![("pipeline".to_string(), r#"{"version": 1}"#.to_string())];
        let mut errors = Vec::new();
        let pipeline = pipeline_from_form(&form, &lang, &mut errors);
        assert!(errors.is_empty(), "{errors:?}");
        assert_eq!(
            pipeline.as_ref(),
            Some(&serde_json::json!({ "version": 1 }))
        );

        // Broken JSON is reported on the pipeline field (the message
        // carries the localized prefix plus the serde detail).
        let form = vec![("pipeline".to_string(), "{oops".to_string())];
        let mut errors = Vec::new();
        assert_eq!(pipeline_from_form(&form, &lang, &mut errors), None);
        assert_eq!(errors.len(), 1, "{errors:?}");
        assert_eq!(errors[0].0, "pipeline");
        assert!(errors[0].1.contains("key must be a string"), "{errors:?}");

        // The cap fires on the compact JSON, the measure the import path
        // applies: a document whose compact form is over `PIPELINE_BYTES`
        // is refused, and the message names the limit.
        let oversized = serde_json::json!({
            "version": 1,
            "rename": [{
                "match": "x".repeat(caps::PIPELINE_BYTES),
                "replace": "y",
                "target": "name",
            }],
        });
        let form = vec![("pipeline".to_string(), oversized.to_string())];
        let mut errors = Vec::new();
        assert_eq!(pipeline_from_form(&form, &lang, &mut errors), None);
        assert!(
            errors
                .iter()
                .any(|(field, message)| field == "pipeline" && message.contains("65536")),
            "{errors:?}"
        );

        // A document that fits is accepted in its pretty rendering too:
        // the text field is longer than the compact measure, and the two
        // must not disagree.
        let fits = serde_json::json!({
            "version": 1,
            "rename": [{
                "match": "chrome",
                "replace": "firefox",
                "target": "name",
            }],
        });
        let form = vec![("pipeline".to_string(), fits.to_string())];
        let mut errors = Vec::new();
        assert_eq!(
            pipeline_from_form(&form, &lang, &mut errors),
            Some(fits.clone()),
            "{errors:?}"
        );
        assert!(errors.is_empty(), "{errors:?}");
    }

    /// Builder mode: an empty widget emits nothing, a filled row is
    /// generated server-side into the stored JSON, and the generated
    /// document is held to the same cap (measured compact, via
    /// `pipeline_size`).
    #[test]
    fn pipeline_from_form_builds_from_widget_rows_in_builder_mode() {
        let lang = test_lang();

        // No widget rows: the generated document is only `{"version": 1}`,
        // which the builder drops (nothing configured).
        let form = vec![("pipeline_mode".to_string(), "builder".to_string())];
        let mut errors = Vec::new();
        assert_eq!(pipeline_from_form(&form, &lang, &mut errors), None);
        assert!(errors.is_empty(), "{errors:?}");

        // One rename row generates a stored pipeline.
        let form: Vec<(String, String)> = [
            ("pipeline_mode", "builder"),
            ("ped_rename_0_match", "chrome"),
            ("ped_rename_0_replace", "firefox"),
            ("ped_rename_0_target", "param"),
            ("ped_rename_0_key", "fp"),
        ]
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
        let mut errors = Vec::new();
        let pipeline = pipeline_from_form(&form, &lang, &mut errors);
        assert!(errors.is_empty(), "{errors:?}");
        let pipeline = pipeline.expect("a filled widget row must store a pipeline");
        assert_eq!(pipeline["rename"][0]["match"], "chrome");

        // The builder ignores a stale raw textarea, as before.
        let form: Vec<(String, String)> = [
            ("pipeline_mode", "builder"),
            ("pipeline", "{oops"),
            ("ped_rename_0_match", "chrome"),
            ("ped_rename_0_replace", "firefox"),
            ("ped_rename_0_target", "param"),
            ("ped_rename_0_key", "fp"),
        ]
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
        let mut errors = Vec::new();
        assert!(pipeline_from_form(&form, &lang, &mut errors).is_some());
        assert!(
            errors.is_empty(),
            "the stale textarea must be ignored: {errors:?}"
        );

        // Enough rename rows to push the generated compact JSON past the
        // cap: the document is refused with the builder's own wording of
        // the limit (the fix is to drop widget rows), like the raw mode
        // refuses an oversized textarea.
        let mut form: Vec<(String, String)> =
            vec![("pipeline_mode".to_string(), "builder".to_string())];
        for i in 0..256usize {
            form.push((format!("ped_rename_{i}_match"), "x".repeat(300)));
            form.push((format!("ped_rename_{i}_replace"), "y".to_string()));
            form.push((format!("ped_rename_{i}_target"), "name".to_string()));
        }
        let mut errors = Vec::new();
        assert_eq!(pipeline_from_form(&form, &lang, &mut errors), None);
        assert!(
            errors
                .iter()
                .any(|(field, message)| field == "pipeline" && message.contains("65536")),
            "{errors:?}"
        );
    }

    /// A mistyped cap is reported from the field that holds it, and the
    /// rest of the pipeline is still checked: one unreadable value must
    /// not mask the problems around it.
    #[test]
    fn pipeline_from_form_reports_a_mistyped_cap_from_the_field() {
        let lang = test_lang();
        let form: Vec<(String, String)> = [
            ("pipeline_mode", "builder"),
            ("ped_limit", "set"),
            ("ped_limit_count", "many"),
        ]
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
        let mut errors = Vec::new();
        assert_eq!(pipeline_from_form(&form, &lang, &mut errors), None);
        assert_eq!(errors.len(), 1, "{errors:?}");
        assert_eq!(errors[0].0, "pipeline");
        assert!(errors[0].1.contains("many"), "{errors:?}");
    }

    /// The slug rules are shared and compiled once: the same format rules
    /// the import path applies, matched against a `LazyLock` regex.
    #[test]
    fn slug_re_holds_the_shared_format_rules() {
        assert!(SLUG_RE.is_match("ab"));
        assert!(SLUG_RE.is_match("a-b_c9"));
        assert!(!SLUG_RE.is_match("a")); // too short
        assert!(!SLUG_RE.is_match("-ab")); // must start alphanumeric
        assert!(!SLUG_RE.is_match("a b")); // space outside the charset
        assert!(!SLUG_RE.is_match(&"a".repeat(65))); // too long
        assert!(SLUG_RE.is_match(&"a".repeat(64)));
    }

    /// The uniqueness half of the shared slug validation, against a stub
    /// lookup: the row found is free when it is the row being edited,
    /// taken when it belongs to another row, and a failed lookup counts
    /// as free (the table's UNIQUE constraint still holds at save time).
    #[tokio::test]
    async fn validate_slug_judges_uniqueness_from_the_lookup_row() {
        struct Row(&'static str);
        impl RowId for Row {
            fn row_id(&self) -> &str {
                self.0
            }
        }
        let found =
            |row: Option<Row>| std::future::ready::<fumox_core::Result<Option<Row>>>(Ok(row));
        let lang = test_lang();

        // The row found is the row being edited: no error.
        let mut errors = Vec::new();
        let slug = validate_slug(
            "same",
            Some("row-1"),
            &lang,
            &mut errors,
            found(Some(Row("row-1"))),
        )
        .await;
        assert_eq!(slug, Some("same".to_string()));
        assert!(errors.is_empty(), "{errors:?}");

        // The row found belongs to another row: the slug is taken.
        let mut errors = Vec::new();
        validate_slug(
            "taken",
            Some("row-1"),
            &lang,
            &mut errors,
            found(Some(Row("row-2"))),
        )
        .await;
        assert_eq!(
            errors,
            vec![("slug".to_string(), lang.t("val.slug_taken").to_string())]
        );

        // The lookup itself failed: no error, the save re-checks.
        let mut errors = Vec::new();
        validate_slug(
            "any",
            Some("row-1"),
            &lang,
            &mut errors,
            std::future::ready::<fumox_core::Result<Option<Row>>>(Err(fumox_core::Error::Config(
                "db down".into(),
            ))),
        )
        .await;
        assert!(errors.is_empty(), "{errors:?}");
    }

    /// The credential mask is a fixed shape: three leading characters
    /// plus a fixed tail, a short value hidden entirely. The prefix is
    /// counted in characters, so a non-ASCII secret keeps three of them
    /// and never splits one in half.
    #[test]
    fn mask_secret_keeps_a_three_character_prefix() {
        assert_eq!(mask_secret(""), "");
        assert_eq!(mask_secret("abc"), "••••");
        assert_eq!(mask_secret("abcd"), "abc…••••");
        assert_eq!(mask_secret("abcdef"), "abc…••••");
        assert_eq!(mask_secret("ключ"), "клю…••••");
        assert_eq!(mask_secret("日本語のトークン"), "日本語…••••");
        assert_eq!(mask_secret("鍵"), "••••");
    }

    /// The split aggregates bucket every proxy status: the per-status SUM
    /// predicates are generated from `ProxyStatus::all()`, so a row's
    /// buckets always sum to its total. A status missing from the
    /// predicates (or a row struct missing the column) breaks the sum
    /// here instead of silently disappearing from the dashboard.
    #[tokio::test]
    async fn the_dashboard_splits_bucket_every_status() {
        let (_dir, state) = crate::admin::test_admin_state(
            fumox_core::config::AdminConfig::default(),
            Default::default(),
        )
        .await;
        let pool = state.pool.clone();

        // One proxy of every status, split over two schemes and two
        // countries, all linked to one source (the per-source table joins
        // through the links).
        sqlx::query(
            "INSERT INTO sources (id, name, url, enabled, created_at, updated_at)
             VALUES ('src-1', 'one', 'https://one.example/list', 1, 1, 1)",
        )
        .execute(&pool)
        .await
        .unwrap();
        for (index, status) in ProxyStatus::all().iter().enumerate() {
            sqlx::query(
                "INSERT INTO proxies (fingerprint, scheme, name, host, port, credential, status, geo_country, created_at, updated_at)
                 VALUES (?, ?, ?, 'h.example.com', 443, 'c', ?, ?, 1, 1)",
            )
            .bind(format!("fp-{index}"))
            .bind(if index % 2 == 0 { "vless" } else { "ss" })
            .bind(format!("p-{index}"))
            .bind(status.as_str())
            .bind(if index % 2 == 0 { "DE" } else { "FR" })
            .execute(&pool)
            .await
            .unwrap();
            sqlx::query(
                "INSERT INTO proxy_source_links (proxy_id, source_id, seen_at)
                 VALUES ((SELECT id FROM proxies WHERE fingerprint = ?), 'src-1', 1)",
            )
            .bind(format!("fp-{index}"))
            .execute(&pool)
            .await
            .unwrap();
        }

        let scheme_bucket = |row: &SchemeSplitRow, status: &str| match status {
            "unknown" => row.unknown,
            "alive" => row.alive,
            "ready" => row.ready,
            "quarantine" => row.quarantine,
            "removed" => row.removed,
            other => unreachable!("every ProxyStatus needs a bucket column: {other}"),
        };
        let country_bucket = |row: &CountrySplitRow, status: &str| match status {
            "unknown" => row.unknown,
            "alive" => row.alive,
            "ready" => row.ready,
            "quarantine" => row.quarantine,
            "removed" => row.removed,
            other => unreachable!("every ProxyStatus needs a bucket column: {other}"),
        };
        let source_bucket = |row: &SourceStatRow, status: &str| match status {
            "unknown" => row.unknown,
            "alive" => row.alive,
            "ready" => row.ready,
            "quarantine" => row.quarantine,
            "removed" => row.removed,
            other => unreachable!("every ProxyStatus needs a bucket column: {other}"),
        };

        let schemes = scheme_split(&pool).await.unwrap();
        for row in &schemes {
            let bucketed: i64 = ProxyStatus::all()
                .iter()
                .map(|status| scheme_bucket(row, status.as_str()))
                .sum();
            assert_eq!(
                bucketed, row.total,
                "scheme {} must bucket every proxy",
                row.value
            );
        }
        let countries = country_split(&pool, i64::MAX).await.unwrap();
        for row in &countries {
            let bucketed: i64 = ProxyStatus::all()
                .iter()
                .map(|status| country_bucket(row, status.as_str()))
                .sum();
            assert_eq!(
                bucketed, row.total,
                "country {:?} must bucket every proxy",
                row.value
            );
        }
        let sources = source_health_split(&pool).await.unwrap();
        assert_eq!(sources.len(), 1);
        for row in &sources {
            let bucketed: i64 = ProxyStatus::all()
                .iter()
                .map(|status| source_bucket(row, status.as_str()))
                .sum();
            assert_eq!(
                bucketed, row.total,
                "source {} must bucket every proxy",
                row.name
            );
            // The oldest-ready stamp rides the same bound parameters.
            assert!(row.oldest_ready_at.is_some(), "{row:?}");
        }
        // One proxy per status: every bucket holds exactly one across
        // the split rows.
        for status in ProxyStatus::all() {
            let counted: i64 = schemes
                .iter()
                .map(|row| scheme_bucket(row, status.as_str()))
                .sum();
            assert_eq!(
                counted,
                1,
                "status {} must land in a bucket",
                status.as_str()
            );
        }
    }

    /// The dashboard's SQL carries no status string literals: every
    /// status value is generated from `ProxyStatus::all()` and bound as a
    /// parameter, so a new status cannot be missed by a query the enum
    /// does not know about.
    #[test]
    fn the_dashboard_sql_carries_no_status_literals() {
        let source = include_str!("mod.rs");
        for status in ProxyStatus::all() {
            for predicate in [
                format!("status = '{}'", status.as_str()),
                format!("status IN ('{}'", status.as_str()),
            ] {
                assert!(
                    !source.contains(&predicate),
                    "the dashboard SQL must bind {predicate:?}, not inline it"
                );
            }
        }
    }
}
