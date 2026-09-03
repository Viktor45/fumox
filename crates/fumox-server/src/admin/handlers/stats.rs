//! Statistics screen (ADMIN_PLAN §4.1b): proxy health broken down by
//! source, the longest-living alive proxies, protocol/country splits,
//! latency aggregates, 7-day ingest dynamics and a probe summary. Every
//! number is computed in SQL (aggregation happens in the database, never
//! in Rust loops over unbounded row sets).

use super::{fmt_ts_element, server_error};
use crate::admin::AdminState;
use crate::admin::i18n::impl_i18n;
use crate::admin::render_html;
use crate::admin::theme::{self, Theme};
use askama::Template;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::Response;
use fumox_core::models::Scheme;

/// Row of the per-source table: health counters for one source.
#[derive(Debug, sqlx::FromRow)]
struct SourceStatRow {
    id: String,
    name: String,
    enabled: i64,
    alive: i64,
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

#[derive(Template)]
#[template(path = "stats.html")]
struct StatsTemplate {
    lang: crate::admin::i18n::Lang,
    langs: Vec<(String, String)>,
    theme: Theme,
    active: &'static str,
    csrf: String,
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

impl StatsTemplate {
    fn ts(&self, ts: &i64) -> String {
        fmt_ts_element(*ts)
    }
    fn opt_ts(&self, ts: &Option<i64>) -> String {
        super::fmt_opt_ts_element(*ts)
    }
    fn flag(&self, country: &Option<String>) -> String {
        super::flag_for(country)
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

impl_i18n!(StatsTemplate);

pub async fn stats(State(state): State<AdminState>, headers: HeaderMap) -> Response {
    let lang = state.locales.lang_from_headers(&headers);
    let theme = theme::from_headers(&headers);
    let pool = &state.pool;

    // Per-source health counters (single aggregate over the join table).
    let sources = match sqlx::query_as::<_, SourceStatRow>(
        "SELECT s.id, s.name, s.enabled,
                COALESCE(SUM(p.status = 'alive'), 0)     AS alive,
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
    let top_alive = match sqlx::query_as::<_, TopAliveRow>(
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

    // Protocol and country distributions (alive share per bucket).
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

    let day_ago = fumox_core::models::now_ts() - 86_400;

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
                    COALESCE(SUM(status = 'quarantine' AND second_chance_at IS NOT NULL), 0),
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
    let rows = match sqlx::query_as::<_, IngestDayRow>(
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
        &StatsTemplate {
            lang,
            langs: state.locales.choices().to_vec(),
            theme,
            active: "stats",
            csrf: state.csrf_for(&headers),
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
