//! Proxy browser (ADMIN_PLAN §4.4): server-side filtered and paginated
//! list (thousands of rows — never "show all"), detail card with masked
//! credential, lifecycle timeline, probe history and source links, and the
//! manual "reset status" action (ADMIN_PLAN §8).

use super::{
    FormMap, action_response, clamp_limit, flag_for, fmt_opt_ts_element, fmt_ts_element, is_htmx,
    mask_secret, not_found, pagination_pages, server_error,
};
use crate::admin::AdminState;
use crate::admin::i18n::{Lang, impl_i18n};
use crate::admin::render_html;
use crate::admin::theme::{self, Theme};
use askama::Template;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::Response;
use fumox_core::models::Scheme;
use fumox_core::repo::proxies;

/// Recognized sort orders of the list screen (whitelist — the value is
/// interpolated into SQL, so anything else falls back to the default).
const SORT_UPDATED: &str = "p.updated_at DESC, p.id DESC";
const SORT_LATENCY: &str = "p.latency_ms IS NULL ASC, p.latency_ms ASC, p.id DESC";
const SORT_NAME: &str = "p.name COLLATE NOCASE ASC, p.id DESC";

// ---------------------------------------------------------------------------
// List
// ---------------------------------------------------------------------------

#[derive(Debug, sqlx::FromRow)]
struct ProxyListRow {
    id: i64,
    scheme: String,
    name: String,
    host: String,
    port: i64,
    status: String,
    latency_ms: Option<i64>,
    geo_country: Option<String>,
}

#[derive(Template)]
#[template(path = "proxies/list.html")]
struct ProxiesListTemplate {
    lang: Lang,
    langs: Vec<(String, String)>,
    theme: Theme,
    active: &'static str,
    csrf: String,
    rows: Vec<ProxyListRow>,
    total: i64,
    pages: Vec<(i64, bool)>,
    per_page: i64,
    f_statuses: Vec<String>,
    f_scheme: String,
    f_country: String,
    f_source: String,
    f_q: String,
    f_sort: String,
    all_statuses: Vec<(&'static str, bool)>,
    all_schemes: Vec<(String, bool)>,
    countries: Vec<String>,
    sources: Vec<(String, String, bool)>,
}

impl ProxiesListTemplate {
    fn flag(&self, country: &Option<String>) -> String {
        flag_for(country)
    }

    /// tuic/mieru cannot be probed and stay `unknown` forever (SPEC §8.5).
    fn unprobeable(&self, scheme: &str) -> bool {
        scheme
            .parse::<Scheme>()
            .is_ok_and(|scheme| !scheme.is_probeable())
    }

    /// Truncate long display names (the full name is on the card).
    fn short_name(&self, name: &str) -> String {
        let count = name.chars().count();
        if count <= 60 {
            name.to_string()
        } else {
            let truncated: String = name.chars().take(59).collect();
            format!("{truncated}…")
        }
    }

    /// Preserve the current filters in pagination links.
    fn query_suffix(&self) -> String {
        let mut parts: Vec<String> = Vec::new();
        for status in &self.f_statuses {
            parts.push(format!("status={}", urlencoding(status)));
        }
        if !self.f_scheme.is_empty() {
            parts.push(format!("scheme={}", urlencoding(&self.f_scheme)));
        }
        if !self.f_country.is_empty() {
            parts.push(format!("country={}", urlencoding(&self.f_country)));
        }
        if !self.f_source.is_empty() {
            parts.push(format!("source={}", urlencoding(&self.f_source)));
        }
        if !self.f_q.is_empty() {
            parts.push(format!("q={}", urlencoding(&self.f_q)));
        }
        if !self.f_sort.is_empty() && self.f_sort != "updated" {
            parts.push(format!("sort={}", urlencoding(&self.f_sort)));
        }
        if parts.is_empty() {
            String::new()
        } else {
            format!("&{}", parts.join("&"))
        }
    }

    fn country_selected(&self, country: &str) -> bool {
        self.f_country == country
    }

    fn source_selected(&self, id: &str) -> bool {
        self.f_source == id
    }
}

impl_i18n!(ProxiesListTemplate);

fn urlencoding(value: &str) -> String {
    percent_encoding::utf8_percent_encode(value, percent_encoding::NON_ALPHANUMERIC).to_string()
}

pub async fn proxies_list(
    State(state): State<AdminState>,
    headers: HeaderMap,
    Query(params): Query<FormMap>,
) -> Response {
    let lang = state.locales.lang_from_headers(&headers);
    let theme = theme::from_headers(&headers);
    // `status` may repeat (multi-select); the rest are single-valued.
    let f_statuses: Vec<String> = params
        .iter()
        .filter(|(k, _)| k.as_str() == "status")
        .map(|(_, v)| v.clone())
        .filter(|v| ["unknown", "alive", "quarantine", "removed"].contains(&v.as_str()))
        .collect();
    let f_scheme = params.get("scheme").cloned().unwrap_or_default();
    let f_country = params.get("country").cloned().unwrap_or_default();
    let f_source = params.get("source").cloned().unwrap_or_default();
    let f_q = params.get("q").cloned().unwrap_or_default();
    let f_sort = params
        .get("sort")
        .cloned()
        .unwrap_or_else(|| "updated".into());
    let page: i64 = params
        .get("page")
        .and_then(|v| v.parse().ok())
        .unwrap_or(1)
        .max(1);
    let per_page = clamp_limit(params.get("per_page").and_then(|v| v.parse().ok()));

    let order = match f_sort.as_str() {
        "latency" => SORT_LATENCY,
        "name" => SORT_NAME,
        _ => SORT_UPDATED,
    };

    let mut clauses: Vec<String> = Vec::new();
    let mut binds: Vec<String> = Vec::new();
    if !f_statuses.is_empty() {
        clauses.push(format!(
            "p.status IN ({})",
            vec!["?"; f_statuses.len()].join(", ")
        ));
        binds.extend(f_statuses.iter().cloned());
    }
    if !f_scheme.is_empty() {
        clauses.push("p.scheme = ?".into());
        binds.push(f_scheme.clone());
    }
    if !f_country.is_empty() {
        clauses.push("p.geo_country = ?".into());
        binds.push(f_country.clone());
    }
    if !f_source.is_empty() {
        clauses.push(
            "EXISTS (SELECT 1 FROM proxy_source_links l
                      WHERE l.proxy_id = p.id AND l.source_id = ?)"
                .into(),
        );
        binds.push(f_source.clone());
    }
    if !f_q.is_empty() {
        clauses.push("(p.host LIKE ? OR p.name LIKE ?)".into());
        binds.push(format!("%{f_q}%"));
        binds.push(format!("%{f_q}%"));
    }
    let where_sql = if clauses.is_empty() {
        String::new()
    } else {
        format!(" WHERE {}", clauses.join(" AND "))
    };

    let total: i64 = {
        let sql = format!("SELECT COUNT(*) FROM proxies p{where_sql}");
        let mut query = sqlx::query_scalar(&sql);
        for value in &binds {
            query = query.bind(value);
        }
        match query.fetch_one(&state.pool).await {
            Ok(total) => total,
            Err(err) => return server_error(lang, &err),
        }
    };

    let rows: Vec<ProxyListRow> = {
        let sql = format!(
            "SELECT p.id, p.scheme, p.name, p.host, p.port, p.status, p.latency_ms, p.geo_country
             FROM proxies p{where_sql}
             ORDER BY {order}
             LIMIT ? OFFSET ?"
        );
        let mut query = sqlx::query_as::<_, ProxyListRow>(&sql);
        for value in &binds {
            query = query.bind(value);
        }
        query = query.bind(per_page).bind((page - 1) * per_page);
        match query.fetch_all(&state.pool).await {
            Ok(rows) => rows,
            Err(err) => return server_error(lang, &err),
        }
    };

    let countries: Vec<String> = sqlx::query_scalar(
        "SELECT DISTINCT geo_country FROM proxies
         WHERE geo_country IS NOT NULL ORDER BY geo_country",
    )
    .fetch_all(&state.pool)
    .await
    .unwrap_or_default();

    let sources = match super::all_sources_for_selects(&state.pool).await {
        Ok(sources) => sources,
        Err(err) => return server_error(lang, &err),
    };

    render_html(
        lang.clone(),
        &ProxiesListTemplate {
            lang,
            langs: state.locales.choices().to_vec(),
            theme,
            active: "proxies",
            csrf: state.csrf_for(&headers),
            all_statuses: [
                ("unknown", f_statuses.iter().any(|s| s == "unknown")),
                ("alive", f_statuses.iter().any(|s| s == "alive")),
                ("quarantine", f_statuses.iter().any(|s| s == "quarantine")),
                ("removed", f_statuses.iter().any(|s| s == "removed")),
            ]
            .to_vec(),
            all_schemes: Scheme::all()
                .iter()
                .map(|scheme| (scheme.as_str().to_string(), scheme.as_str() == f_scheme))
                .collect(),
            rows,
            total,
            pages: pagination_pages(page, total, per_page),
            per_page,
            f_statuses,
            f_scheme,
            f_country,
            f_source,
            f_q,
            f_sort,
            countries,
            sources,
        },
        StatusCode::OK,
    )
}

// ---------------------------------------------------------------------------
// Card
// ---------------------------------------------------------------------------

#[derive(Debug, sqlx::FromRow)]
struct ProbeHistoryRow {
    checked_at: i64,
    ok: i64,
    latency_ms: Option<i64>,
    error: Option<String>,
    probe_kind: String,
}

#[derive(Debug, sqlx::FromRow)]
struct LinkRow {
    source_id: String,
    seen_at: i64,
    name: Option<String>,
}

#[derive(Template)]
#[template(path = "proxies/detail.html")]
struct ProxyDetailTemplate {
    lang: Lang,
    langs: Vec<(String, String)>,
    theme: Theme,
    active: &'static str,
    csrf: String,
    proxy: proxies::ProxyRow,
    credential_display: String,
    revealed: bool,
    params_display: String,
    unknown_params_display: String,
    lifecycle: Vec<(String, String)>,
    probes: Vec<ProbeHistoryRow>,
    links: Vec<LinkRow>,
    unprobeable: bool,
}

impl ProxyDetailTemplate {
    fn ts(&self, ts: &i64) -> String {
        fmt_ts_element(*ts)
    }
    fn flag(&self, country: &Option<String>) -> String {
        flag_for(country)
    }
}

impl_i18n!(ProxyDetailTemplate);

/// Pretty-print a stored params JSON column; corrupt JSON is shown verbatim
/// rather than hiding the problem.
fn pretty_params(column: &Option<String>) -> String {
    column
        .as_deref()
        .filter(|text| !text.is_empty())
        .map(|text| {
            serde_json::from_str::<serde_json::Value>(text)
                .ok()
                .and_then(|value| serde_json::to_string_pretty(&value).ok())
                .unwrap_or_else(|| text.to_string())
        })
        .unwrap_or_default()
}

pub async fn proxy_detail(
    State(state): State<AdminState>,
    Path(id): Path<i64>,
    headers: HeaderMap,
    Query(params): Query<FormMap>,
) -> Response {
    let lang = state.locales.lang_from_headers(&headers);
    let theme = theme::from_headers(&headers);
    let proxy = match proxies::get_by_id(&state.pool, id).await {
        Ok(Some(proxy)) => proxy,
        Ok(None) => return not_found(lang, "err.proxy_not_found"),
        Err(err) => return server_error(lang, &err),
    };

    // Credentials are masked everywhere except behind the explicit
    // `?reveal=1` on this card (ADMIN_PLAN §3).
    let revealed = params.get("reveal").map(|v| v == "1").unwrap_or(false);
    let credential_display = if revealed {
        proxy.credential.clone()
    } else {
        mask_secret(&proxy.credential)
    };

    // Every value is server-generated (statuses, counters, timestamps,
    // numbers) — the template renders them with askama's `| safe` so the
    // timestamp entries can carry their `<time>` elements.
    let lifecycle: Vec<(String, String)> = vec![
        (lang.t("common.status").into(), proxy.status.clone()),
        (lang.t("px.fail_count").into(), proxy.fail_count.to_string()),
        (
            lang.t("common.created").into(),
            fmt_ts_element(proxy.created_at),
        ),
        (
            lang.t("common.updated").into(),
            fmt_ts_element(proxy.updated_at),
        ),
        (
            lang.t("px.last_check").into(),
            fmt_opt_ts_element(proxy.last_checked_at),
        ),
        (
            lang.t("px.last_success").into(),
            fmt_opt_ts_element(proxy.last_alive_at),
        ),
        (
            lang.t("px.quarantined_since").into(),
            fmt_opt_ts_element(proxy.quarantined_at),
        ),
        (
            lang.t("px.second_chance").into(),
            fmt_opt_ts_element(proxy.second_chance_at),
        ),
        (
            lang.t("px.recheck_15m").into(),
            fmt_opt_ts_element(proxy.recheck_15m_at),
        ),
        (
            lang.t("px.recheck_30m").into(),
            fmt_opt_ts_element(proxy.recheck_30m_at),
        ),
        (
            lang.t("px.recheck_1h").into(),
            fmt_opt_ts_element(proxy.recheck_1h_at),
        ),
        (
            lang.t("px.removed").into(),
            fmt_opt_ts_element(proxy.removed_at),
        ),
        (
            lang.t("common.latency").into(),
            proxy
                .latency_ms
                .map(|ms| format!("{ms} {}", lang.t("common.ms")))
                .unwrap_or_else(|| "—".into()),
        ),
        (
            lang.t("px.speed").into(),
            proxy
                .speed_mbps
                .map(|mbps| format!("{mbps:.1} {}", lang.t("px.speed_unit")))
                .unwrap_or_else(|| "—".into()),
        ),
    ];

    let probes: Vec<ProbeHistoryRow> = match fetch_probe_history(&state.pool, id).await {
        Ok(rows) => rows,
        Err(err) => return server_error(lang, &err),
    };

    let links: Vec<LinkRow> = match sqlx::query_as(
        "SELECT l.source_id, l.seen_at, s.name
         FROM proxy_source_links l LEFT JOIN sources s ON s.id = l.source_id
         WHERE l.proxy_id = ?
         ORDER BY l.seen_at DESC",
    )
    .bind(id)
    .fetch_all(&state.pool)
    .await
    {
        Ok(rows) => rows,
        Err(err) => return server_error(lang, &err),
    };

    // Unprobeable badge (SPEC §8.5): the schemes the daemon cannot check
    // stay `unknown`; the tooltip text itself is the px.unprobeable_title
    // catalog entry (admin-facing text must not reference design docs).
    let unprobeable = proxy
        .scheme
        .parse::<Scheme>()
        .is_ok_and(|scheme| !scheme.is_probeable());

    render_html(
        lang.clone(),
        &ProxyDetailTemplate {
            lang,
            langs: state.locales.choices().to_vec(),
            theme,
            active: "proxies",
            csrf: state.csrf_for(&headers),
            params_display: pretty_params(&proxy.params),
            unknown_params_display: pretty_params(&proxy.unknown_params),
            credential_display,
            revealed,
            proxy,
            lifecycle,
            probes,
            links,
            unprobeable,
        },
        StatusCode::OK,
    )
}

// ---------------------------------------------------------------------------
// Probe history fragment (live refresh, ADMIN_PLAN §4.4)
// ---------------------------------------------------------------------------

/// Standalone fragment template for the probe history table; the same
/// markup is `{% include %}`d into the full card, so the initial render and
/// every live refresh stay byte-identical.
#[derive(Template)]
#[template(path = "proxies/_history.html")]
struct ProbeHistoryFragment {
    lang: Lang,
    probes: Vec<ProbeHistoryRow>,
}

impl ProbeHistoryFragment {
    fn ts(&self, ts: &i64) -> String {
        fmt_ts_element(*ts)
    }
}

impl_i18n!(ProbeHistoryFragment);

/// The last 20 probe attempts for one proxy, newest first.
async fn fetch_probe_history(
    pool: &fumox_core::db::DbPool,
    id: i64,
) -> Result<Vec<ProbeHistoryRow>, fumox_core::Error> {
    let rows = sqlx::query_as(
        "SELECT checked_at, ok, latency_ms, error, probe_kind
         FROM probe_results WHERE proxy_id = ?
         ORDER BY checked_at DESC, id DESC LIMIT 20",
    )
    .bind(id)
    .fetch_all(pool)
    .await?;
    Ok(rows)
}

/// Live probe-history fragment polled by the proxy card every few seconds.
pub async fn proxy_probe_history(
    State(state): State<AdminState>,
    Path(id): Path<i64>,
    headers: HeaderMap,
) -> Response {
    let lang = state.locales.lang_from_headers(&headers);
    if matches!(proxies::get_by_id(&state.pool, id).await, Ok(None)) {
        return not_found(lang, "err.proxy_not_found");
    }
    let probes = match fetch_probe_history(&state.pool, id).await {
        Ok(rows) => rows,
        Err(err) => return server_error(lang, &err),
    };
    render_html(
        lang.clone(),
        &ProbeHistoryFragment { lang, probes },
        StatusCode::OK,
    )
}

// ---------------------------------------------------------------------------
// Purge removed (ADMIN_PLAN §13.16)
// ---------------------------------------------------------------------------

/// Physically delete every `removed` proxy (and, via cascade, its links and
/// probe history). Guarded by a confirmation dialog in the UI.
pub async fn proxies_purge_removed(
    State(state): State<AdminState>,
    headers: HeaderMap,
) -> Response {
    let lang = state.locales.lang_from_headers(&headers);
    let deleted = match proxies::purge_removed(&state.pool).await {
        Ok(deleted) => deleted,
        Err(err) => return server_error(lang, &err),
    };
    tracing::info!(deleted, "purged removed proxies");
    let fragment = format!(
        "<span class=\"badge on\">{}</span>",
        lang.t("px.purged_rows").replace("{}", &deleted.to_string())
    );
    action_response(
        is_htmx(&headers),
        "/admin/proxies",
        fragment,
        &lang
            .t("px.purged_toast")
            .replace("{}", &deleted.to_string()),
    )
}

// ---------------------------------------------------------------------------
// Actions
// ---------------------------------------------------------------------------

/// Manual "reset status" (ADMIN_PLAN §8): back to a pristine `unknown`,
/// the probe daemon picks the proxy up on its next cycle.
pub async fn proxy_reset(
    State(state): State<AdminState>,
    Path(id): Path<i64>,
    headers: HeaderMap,
) -> Response {
    let lang = state.locales.lang_from_headers(&headers);
    match proxies::reset_status(&state.pool, id).await {
        Ok(true) => {}
        Ok(false) => return not_found(lang, "err.proxy_not_found"),
        Err(err) => return server_error(lang, &err),
    }
    tracing::info!(proxy_id = id, "proxy status reset");
    action_response(
        is_htmx(&headers),
        &format!("/admin/proxies/{id}"),
        r#"<span class="badge unknown">unknown</span>"#.to_string(),
        lang.t("px.reset_toast"),
    )
}
