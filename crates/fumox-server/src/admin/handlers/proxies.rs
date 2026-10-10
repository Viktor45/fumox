//! Proxy browser: server-side filtered and paginated
//! list (thousands of rows, never "show all"), detail card with lifecycle
//! timeline, probe history and source links, and the manual "reset status"
//! action.

use super::{
    QueryPairs, action_response, action_response_err, clamp_limit, flag_for, fmt_opt_ts_element,
    fmt_ts_element, is_htmx, not_found, page_offset, pagination_pages, server_error,
};
use crate::admin::AdminState;
use crate::admin::i18n::{Lang, impl_i18n};
use crate::admin::render_html;
use crate::admin::theme::{self, Theme};
use askama::Template;
use axum::extract::{Form, Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::Response;
use fumox_core::models::{Scheme, now_ts};
use fumox_core::repo::probe as probe_repo;
use fumox_core::repo::proxies::{
    self, CheckCoverage, ProxyLinkRow, ProxyListFilter, ProxyListOrder, ProxyListRow,
};

// List

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
    /// Count of `removed` rows (unfiltered); the purge dialog shows it so
    /// the destructive confirm does not hide its blast radius.
    removed_count: i64,
    pages: Vec<(i64, bool)>,
    per_page: i64,
    f_statuses: Vec<String>,
    f_scheme: String,
    f_country: String,
    f_source: String,
    f_q: String,
    f_sort: String,
    /// Active coverage bucket ("" = no filter).
    f_coverage: String,
    all_statuses: Vec<(String, bool)>,
    all_schemes: Vec<(String, bool)>,
    countries: Vec<String>,
    sources: Vec<(String, String, bool)>,
}

impl ProxiesListTemplate {
    fn flag(&self, country: &Option<String>) -> String {
        flag_for(country)
    }

    /// tuic/mieru cannot be probed and stay `unknown` forever.
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

    /// Whether any filter narrows the list; drives the empty-state
    /// "clear filters" link (sorting alone never hides rows).
    fn filters_active(&self) -> bool {
        !self.f_statuses.is_empty()
            || !self.f_scheme.is_empty()
            || !self.f_country.is_empty()
            || !self.f_source.is_empty()
            || !self.f_q.is_empty()
            || !self.f_coverage.is_empty()
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
        if !self.f_coverage.is_empty() {
            parts.push(format!("coverage={}", urlencoding(&self.f_coverage)));
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

    /// Whether a coverage-bucket option of the filter dropdown is active.
    fn coverage_selected(&self, bucket: &str) -> bool {
        self.f_coverage == bucket
    }

    /// The "Checks" cell of one row: which probe tiers have history.
    fn checks_cell(&self, row: &ProxyListRow) -> String {
        match (row.t1_checked, row.t2_checked) {
            (true, true) => "T1+T2".to_string(),
            (true, false) => "T1".to_string(),
            (false, true) => "T2".to_string(),
            // Same placeholder the timestamp cells use, a bare comma here
            // read as a typo.
            (false, false) => "–".to_string(),
        }
    }
}

impl_i18n!(ProxiesListTemplate);

fn urlencoding(value: &str) -> String {
    percent_encoding::utf8_percent_encode(value, percent_encoding::NON_ALPHANUMERIC).to_string()
}

pub async fn proxies_list(
    State(state): State<AdminState>,
    headers: HeaderMap,
    Query(params): Query<QueryPairs>,
) -> Response {
    let lang = state.locales.lang_from_headers(&headers);
    let theme = theme::from_headers(&headers);
    // `status` may repeat (multi-select); the rest are single-valued. This
    // needs QueryPairs, a HashMap would keep only the last value.
    let f_statuses: Vec<String> = params
        .all("status")
        .filter(|v| ["unknown", "alive", "ready", "quarantine", "removed"].contains(&v.as_str()))
        .cloned()
        .collect();
    let f_scheme = params.get("scheme").cloned().unwrap_or_default();
    let f_country = params.get("country").cloned().unwrap_or_default();
    let f_source = params.get("source").cloned().unwrap_or_default();
    let f_q = params.get("q").cloned().unwrap_or_default();
    let f_sort = params
        .get("sort")
        .cloned()
        .unwrap_or_else(|| "updated".into());
    // Coverage bucket: a garbage value means "no filter", the same
    // tolerance the scheme/country selects show; the bucket whitelist and
    // its SQL fragments live in the repo's `CheckCoverage`.
    let f_coverage = params
        .get("coverage")
        .cloned()
        .unwrap_or_default()
        .to_ascii_lowercase();
    let coverage = CheckCoverage::from_bucket(&f_coverage);
    let f_coverage = coverage
        .map(|bucket| bucket.as_str().to_string())
        .unwrap_or_default();
    let page: i64 = params
        .get("page")
        .and_then(|v| v.parse().ok())
        .unwrap_or(1)
        .max(1);
    let per_page = clamp_limit(params.get("per_page").and_then(|v| v.parse().ok()));

    // The filter clause set lives once in the repo (`ProxyListFilter`):
    // count and rows below apply exactly the same clauses, and every
    // value flows through a bind.
    let filter = ProxyListFilter {
        statuses: f_statuses.clone(),
        scheme: f_scheme.clone(),
        country: f_country.clone(),
        source_id: f_source.clone(),
        query: f_q.clone(),
        coverage,
    };
    let order = ProxyListOrder::from_param(&f_sort);

    let total: i64 = match proxies::count_filtered(&state.pool, &filter).await {
        Ok(total) => total,
        Err(err) => return server_error(lang, &err),
    };

    // The purge dialog acts on every `removed` row regardless of the
    // active filters, so the count it shows is unfiltered too.
    let removed_count: i64 = match proxies::count_removed(&state.pool).await {
        Ok(count) => count,
        Err(err) => return server_error(lang, &err),
    };

    let rows: Vec<ProxyListRow> = match proxies::list_filtered(
        &state.pool,
        &filter,
        order,
        per_page,
        page_offset(page, per_page),
    )
    .await
    {
        Ok(rows) => rows,
        Err(err) => return server_error(lang, &err),
    };

    let countries: Vec<String> = proxies::distinct_countries(&state.pool)
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
                (
                    "unknown".to_string(),
                    f_statuses.iter().any(|s| s == "unknown"),
                ),
                ("alive".to_string(), f_statuses.iter().any(|s| s == "alive")),
                ("ready".to_string(), f_statuses.iter().any(|s| s == "ready")),
                (
                    "quarantine".to_string(),
                    f_statuses.iter().any(|s| s == "quarantine"),
                ),
                (
                    "removed".to_string(),
                    f_statuses.iter().any(|s| s == "removed"),
                ),
            ]
            .to_vec(),
            all_schemes: Scheme::all()
                .iter()
                .map(|scheme| (scheme.as_str().to_string(), scheme.as_str() == f_scheme))
                .collect(),
            rows,
            total,
            removed_count,
            pages: pagination_pages(page, total, per_page),
            per_page,
            f_statuses,
            f_scheme,
            f_country,
            f_source,
            f_q,
            f_sort,
            f_coverage,
            countries,
            sources,
        },
        StatusCode::OK,
    )
}

// Card

#[derive(Template)]
#[template(path = "proxies/detail.html")]
struct ProxyDetailTemplate {
    lang: Lang,
    langs: Vec<(String, String)>,
    theme: Theme,
    active: &'static str,
    csrf: String,
    proxy: proxies::ProxyRow,
    params_display: String,
    unknown_params_display: String,
    lifecycle: Vec<(String, String)>,
    probes: Vec<probe_repo::ProbeHistoryRow>,
    links: Vec<ProxyLinkRow>,
    unprobeable: bool,
}

impl ProxyDetailTemplate {
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
) -> Response {
    let lang = state.locales.lang_from_headers(&headers);
    let theme = theme::from_headers(&headers);
    let mut proxy = match proxies::get_by_id(&state.pool, id).await {
        Ok(Some(proxy)) => proxy,
        Ok(None) => return not_found(lang, "err.proxy_not_found"),
        Err(err) => return server_error(lang, &err),
    };

    // Opening the card refreshes the geo facts from every available
    // GeoLite2 database (City/ASN included), no button to click.
    refresh_geo(&state, &mut proxy).await;

    // Every value is server-generated (statuses, counters, timestamps,
    // numbers), the template renders them with askama's `| safe` so the
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
            if proxy.ladder_step < 1 {
                lang.t("probe.step_second_chance").to_string()
            } else {
                lang.t_args("probe.step_recheck", &[proxy.ladder_step.to_string()])
            },
            fmt_opt_ts_element(proxy.ladder_at),
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
                .unwrap_or_else(|| ",".into()),
        ),
        (
            lang.t("px.speed").into(),
            proxy
                .speed_mbps
                .map(|mbps| format!("{mbps:.1} {}", lang.t("px.speed_unit")))
                .unwrap_or_else(|| ",".into()),
        ),
    ];

    let probes: Vec<probe_repo::ProbeHistoryRow> =
        match probe_repo::recent_for_proxy(&state.pool, id, 20).await {
            Ok(rows) => rows,
            Err(err) => return server_error(lang, &err),
        };

    let links: Vec<ProxyLinkRow> = match proxies::links_with_source_name(&state.pool, id).await {
        Ok(rows) => rows,
        Err(err) => return server_error(lang, &err),
    };

    // Unprobeable badge: the schemes the daemon cannot check
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
            proxy,
            lifecycle,
            probes,
            links,
            unprobeable,
        },
        StatusCode::OK,
    )
}

// Probe history fragment (live refresh)

/// Standalone fragment template for the probe history table; the same
/// markup is `{% include %}`d into the full card, so the initial render and
/// every live refresh stay byte-identical.
#[derive(Template)]
#[template(path = "proxies/_history.html")]
struct ProbeHistoryFragment {
    lang: Lang,
    probes: Vec<probe_repo::ProbeHistoryRow>,
}

impl_i18n!(ProbeHistoryFragment);

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
    let probes = match probe_repo::recent_for_proxy(&state.pool, id, 20).await {
        Ok(rows) => rows,
        Err(err) => return server_error(lang, &err),
    };
    render_html(
        lang.clone(),
        &ProbeHistoryFragment { lang, probes },
        StatusCode::OK,
    )
}

// Purge removed

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

// Bulk cleanup
//
// Every action below transitions rows into the terminal `removed` status ,
// they never delete. The physical cleanup stays the single «purge removed»
// button, so each action is reversible via the per-proxy «reset status»
// until purged.

/// Shared tail of the parameterless cleanup handlers: run the repo
/// transition, log it and answer with the count badge + toast.
macro_rules! bulk_cleanup_handler {
    ($name:ident, $repo_fn:ident, $log_msg:literal) => {
        pub async fn $name(State(state): State<AdminState>, headers: HeaderMap) -> Response {
            let lang = state.locales.lang_from_headers(&headers);
            let moved = match proxies::$repo_fn(&state.pool).await {
                Ok(moved) => moved,
                Err(err) => return server_error(lang, &err),
            };
            tracing::info!(moved, $log_msg);
            let fragment = format!(
                "<span class=\"badge removed\">{}</span>",
                lang.t("px.cleanup_moved_rows")
                    .replace("{}", &moved.to_string())
            );
            action_response(
                is_htmx(&headers),
                "/admin/proxies",
                fragment,
                &lang
                    .t("px.cleanup_moved_toast")
                    .replace("{}", &moved.to_string()),
            )
        }
    };
}

bulk_cleanup_handler!(
    proxies_quarantine_to_removed,
    quarantine_to_removed,
    "moved quarantined proxies to removed"
);
bulk_cleanup_handler!(
    proxies_remove_alive_no_country,
    remove_alive_without_country,
    "removed alive proxies without country"
);
bulk_cleanup_handler!(
    proxies_remove_unprobeable,
    remove_unprobeable_unknown,
    "removed unprobeable unknown proxies"
);

/// Normalize an AS number typed into the cleanup form: accepts both
/// `24940` and `AS24940`, returns the bare digits. `None` when the input
/// is not a plain AS number (empty, non-digits, too long).
fn normalize_asn(input: &str) -> Option<String> {
    let trimmed = input.trim();
    let digits = trimmed
        .strip_prefix("AS")
        .or_else(|| trimmed.strip_prefix("as"))
        .unwrap_or(trimmed);
    if !digits.is_empty() && digits.len() <= 10 && digits.bytes().all(|b| b.is_ascii_digit()) {
        Some(digits.to_string())
    } else {
        None
    }
}

/// Move every `alive` proxy of one autonomous system into `removed`
/// (cleanup panel). The form field `asn` accepts `24940` and `AS24940`.
pub async fn proxies_remove_alive_by_asn(
    State(state): State<AdminState>,
    headers: HeaderMap,
    Form(form): Form<Vec<(String, String)>>,
) -> Response {
    let lang = state.locales.lang_from_headers(&headers);
    let raw = form
        .iter()
        .find(|(k, _)| k == "asn")
        .map(|(_, v)| v.as_str())
        .unwrap_or_default();
    let Some(asn) = normalize_asn(raw) else {
        tracing::info!("cleanup by ASN rejected: invalid input");
        return action_response_err(
            is_htmx(&headers),
            "/admin/proxies",
            String::new(),
            lang.t("val.asn_format"),
        );
    };
    let moved = match proxies::remove_alive_by_asn(&state.pool, &asn).await {
        Ok(moved) => moved,
        Err(err) => return server_error(lang, &err),
    };
    tracing::info!(asn = %asn, moved, "removed alive proxies by ASN");
    let fragment = format!(
        "<span class=\"badge removed\">{}</span>",
        lang.t("px.cleanup_asn_rows")
            .replace("{}", &moved.to_string())
            .replace("{asn}", &asn),
    );
    action_response(
        is_htmx(&headers),
        "/admin/proxies",
        fragment,
        &lang
            .t("px.cleanup_moved_toast")
            .replace("{}", &moved.to_string()),
    )
}

/// Move every `alive` proxy of one country into `removed` (cleanup panel).
/// The form field `country` must be a 2-letter ISO code offered by the
/// country dropdown.
pub async fn proxies_remove_alive_by_country(
    State(state): State<AdminState>,
    headers: HeaderMap,
    Form(form): Form<Vec<(String, String)>>,
) -> Response {
    let lang = state.locales.lang_from_headers(&headers);
    let raw = form
        .iter()
        .find(|(k, _)| k == "country")
        .map(|(_, v)| v.as_str())
        .unwrap_or_default();
    let code = raw.trim().to_ascii_uppercase();
    if code.len() != 2 || !code.bytes().all(|b| b.is_ascii_alphabetic()) {
        tracing::info!("cleanup by country rejected: invalid input");
        return action_response_err(
            is_htmx(&headers),
            "/admin/proxies",
            String::new(),
            &lang.t("val.country_format").replace("{}", &code),
        );
    }
    let moved = match proxies::remove_alive_by_country(&state.pool, &code).await {
        Ok(moved) => moved,
        Err(err) => return server_error(lang, &err),
    };
    tracing::info!(country = %code, moved, "removed alive proxies by country");
    let fragment = format!(
        "<span class=\"badge removed\">{}</span>",
        lang.t("px.cleanup_country_rows")
            .replace("{}", &moved.to_string())
            .replace("{country}", &code),
    );
    action_response(
        is_htmx(&headers),
        "/admin/proxies",
        fragment,
        &lang
            .t("px.cleanup_moved_toast")
            .replace("{}", &moved.to_string()),
    )
}

// Bulk revival
//
// Every action below moves rows *back* to `unknown`, the inverse of the
// cleanup panel. Revived ids are enqueued into `probe_requests` so the probe
// daemon picks them up on its next cycle (the same handoff the ingest path
// uses for `[ingest].removed_as_unknown`).

/// Hand-off budget for the bulk revivals: a fixed, generous cap so the
/// operator's `[ingest].refresh_check_limit` cannot silently disable the
/// hand-off (`0` disables the *ingest* queue, and reusing it here used to
/// turn every revival click into a success toast that enqueued nothing).
/// The cap matches the configured ceiling of the ingest knob
/// (`[ingest].refresh_check_limit` accepts 0..=10 000); ids beyond it are
/// not lost, they simply wait in the random sample as before.
const REVIVE_ENQUEUE_LIMIT: u32 = 10_000;

/// Enqueue revived ids for priority probing. Failures are logged and
/// never fail the revival: the proxy sits in the random sample until
/// `select_t1_candidates` happens to draw it. The reverse is not true
///, `enqueue_checks` silently drops ids whose status drifted away
/// from `unknown`, so a successful enqueue is a stronger guarantee
/// than a missed one.
async fn enqueue_revived(state: &AdminState, ids: &[i64]) {
    if ids.is_empty() {
        return;
    }
    if let Err(err) =
        probe_repo::enqueue_checks(&state.pool, ids, REVIVE_ENQUEUE_LIMIT, now_ts()).await
    {
        tracing::warn!(error = %err, "failed to enqueue revived proxies");
    }
}

/// Shared tail of the parameterless revival handlers: run the repo
/// transition (which returns the revived ids), enqueue them for
/// priority probing, log the count, answer with the badge + toast.
macro_rules! bulk_revival_handler {
    ($name:ident, $repo_fn:ident, $log_msg:literal, $rows_key:literal) => {
        pub async fn $name(State(state): State<AdminState>, headers: HeaderMap) -> Response {
            let lang = state.locales.lang_from_headers(&headers);
            let ids = match proxies::$repo_fn(&state.pool, now_ts()).await {
                Ok(ids) => ids,
                Err(err) => return server_error(lang, &err),
            };
            let revived = ids.len();
            tracing::info!(revived, $log_msg);
            enqueue_revived(&state, &ids).await;
            let fragment = format!(
                "<span class=\"badge unknown\">{}</span>",
                lang.t($rows_key).replace("{}", &revived.to_string())
            );
            action_response(
                is_htmx(&headers),
                "/admin/proxies",
                fragment,
                &lang
                    .t("px.revive_moved_toast")
                    .replace("{}", &revived.to_string()),
            )
        }
    };
}

bulk_revival_handler!(
    proxies_revive_removed_no_history,
    revive_removed_without_probe_history,
    "revived removed proxies without probe history",
    "px.revive_no_history_rows"
);
bulk_revival_handler!(
    proxies_revive_quarantine,
    revive_quarantine,
    "revived quarantined proxies to unknown",
    "px.revive_quarantine_rows"
);

/// Move every `removed` proxy of one autonomous system back to
/// `unknown` (revival panel). The form field `asn` accepts `24940`
/// and `AS24940`; the canonical `AS{n}` form is built once before the
/// SQL.
pub async fn proxies_revive_removed_by_asn(
    State(state): State<AdminState>,
    headers: HeaderMap,
    Form(form): Form<Vec<(String, String)>>,
) -> Response {
    let lang = state.locales.lang_from_headers(&headers);
    let raw = form
        .iter()
        .find(|(k, _)| k == "asn")
        .map(|(_, v)| v.as_str())
        .unwrap_or_default();
    let Some(asn) = normalize_asn(raw) else {
        tracing::info!("revival by ASN rejected: invalid input");
        return action_response_err(
            is_htmx(&headers),
            "/admin/proxies",
            String::new(),
            lang.t("val.asn_format"),
        );
    };
    let ids = match proxies::revive_removed_by_asn(&state.pool, &asn, now_ts()).await {
        Ok(ids) => ids,
        Err(err) => return server_error(lang, &err),
    };
    let revived = ids.len();
    tracing::info!(asn = %asn, revived, "revived removed proxies by ASN");
    enqueue_revived(&state, &ids).await;
    let fragment = format!(
        "<span class=\"badge unknown\">{}</span>",
        lang.t("px.revive_asn_rows")
            .replace("{}", &revived.to_string())
            .replace("{asn}", &asn),
    );
    action_response(
        is_htmx(&headers),
        "/admin/proxies",
        fragment,
        &lang
            .t("px.revive_moved_toast")
            .replace("{}", &revived.to_string()),
    )
}

/// Move every `removed` proxy of one country back to `unknown` (revival
/// panel). The form field `country` must be a 2-letter ISO code offered
/// by the country dropdown.
pub async fn proxies_revive_removed_by_country(
    State(state): State<AdminState>,
    headers: HeaderMap,
    Form(form): Form<Vec<(String, String)>>,
) -> Response {
    let lang = state.locales.lang_from_headers(&headers);
    let raw = form
        .iter()
        .find(|(k, _)| k == "country")
        .map(|(_, v)| v.as_str())
        .unwrap_or_default();
    let code = raw.trim().to_ascii_uppercase();
    if code.len() != 2 || !code.bytes().all(|b| b.is_ascii_alphabetic()) {
        tracing::info!("revival by country rejected: invalid input");
        return action_response_err(
            is_htmx(&headers),
            "/admin/proxies",
            String::new(),
            &lang.t("val.country_format").replace("{}", &code),
        );
    }
    let ids = match proxies::revive_removed_by_country(&state.pool, &code, now_ts()).await {
        Ok(ids) => ids,
        Err(err) => return server_error(lang, &err),
    };
    let revived = ids.len();
    tracing::info!(country = %code, revived, "revived removed proxies by country");
    enqueue_revived(&state, &ids).await;
    let fragment = format!(
        "<span class=\"badge unknown\">{}</span>",
        lang.t("px.revive_country_rows")
            .replace("{}", &revived.to_string())
            .replace("{country}", &code),
    );
    action_response(
        is_htmx(&headers),
        "/admin/proxies",
        fragment,
        &lang
            .t("px.revive_moved_toast")
            .replace("{}", &revived.to_string()),
    )
}

// Actions

/// The `#status-badge` swap fragment for a row an action left alone,
/// same shape the detail template renders: the form's `hx-target` points
/// at the wrapper, so a refusal has to answer with it or the button dies.
/// The class is picked from the status value, never interpolated.
fn status_badge(lang: &Lang, status: &str) -> String {
    let (class, key) = match status {
        "alive" => ("alive", "common.status_alive"),
        "ready" => ("ready", "common.status_ready"),
        "quarantine" => ("quarantine", "common.status_quarantine"),
        "removed" => ("removed", "common.status_removed"),
        _ => ("unknown", "common.status_unknown"),
    };
    format!(
        r#"<span id="status-badge" aria-live="polite" aria-atomic="true"><span class="badge {class}">{}</span></span>"#,
        lang.t(key)
    )
}

/// Manual "reset status": back to a pristine `unknown`,
/// the probe daemon picks the proxy up on its next cycle.
pub async fn proxy_reset(
    State(state): State<AdminState>,
    Path(id): Path<i64>,
    headers: HeaderMap,
) -> Response {
    let lang = state.locales.lang_from_headers(&headers);
    match proxies::reset_status(&state.pool, id).await {
        Ok(true) => {}
        // `false` is a gone row or one no probe lane can reach; only the first is a 404.
        Ok(false) => match proxies::get_by_id(&state.pool, id).await {
            Ok(Some(row)) => {
                tracing::info!(
                    proxy_id = id,
                    status = %row.status,
                    "proxy status reset refused: no probe lane can reach the row"
                );
                return action_response_err(
                    is_htmx(&headers),
                    &format!("/admin/proxies/{id}"),
                    status_badge(&lang, &row.status),
                    lang.t("px.reset_unreachable"),
                );
            }
            Ok(None) => return not_found(lang, "err.proxy_not_found"),
            Err(err) => return server_error(lang, &err),
        },
        Err(err) => return server_error(lang, &err),
    }
    tracing::info!(proxy_id = id, "proxy status reset");
    action_response(
        is_htmx(&headers),
        &format!("/admin/proxies/{id}"),
        // The wrapper id must survive the swap: the form's hx-target points
        // at it, so losing it kills the button for every subsequent click.
        // The aria attributes keep the initial template's announcements.
        format!(
            r#"<span id="status-badge" aria-live="polite" aria-atomic="true"><span class="badge unknown">{}</span></span>"#,
            lang.t("common.status_unknown"),
        ),
        lang.t("px.reset_toast"),
    )
}

/// Refresh the geo facts of one proxy (Country, City, ASN, every GeoLite2
/// database in `[geo].db_dir` contributes, the same merge the pipeline
/// resolver uses). Called while rendering the card, so opening the page is
/// enough and no button is needed. A host that does not resolve keeps its
/// stored facts, an empty stamp must never wipe them; the resolver's
/// DNS+lookup cache makes repeat opens cheap.
async fn refresh_geo(state: &AdminState, proxy: &mut proxies::ProxyRow) {
    if !state.geo_full.is_active() {
        return;
    }
    let Some(info) = state.geo_full.resolve(&proxy.host).await else {
        return;
    };
    let stamp = proxies::GeoStamp::from_info(&info);
    if let Err(err) = proxies::update_geo_full(&state.pool, proxy.id, &stamp, &info.ip).await {
        tracing::warn!(proxy_id = proxy.id, error = %err, "card geo refresh failed");
        return;
    }
    tracing::debug!(proxy_id = proxy.id, host = %proxy.host, "card geo refreshed");
    merge_geo_stamp(proxy, &stamp);
    proxy.resolved_ip = Some(info.ip);
}

/// Overwrite a field only when the stamp carries it: a partial stamp
/// must not turn a stored country or city into `None`.
fn merge_geo_stamp(proxy: &mut proxies::ProxyRow, stamp: &proxies::GeoStamp) {
    if let Some(country) = &stamp.country {
        proxy.geo_country = Some(country.clone());
    }
    if let Some(city) = &stamp.city {
        proxy.geo_city = Some(city.clone());
    }
    if let Some(asn) = &stamp.asn {
        proxy.geo_asn = Some(asn.clone());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A card row as the database hands it over: the stored geo facts are
    /// whatever the ingest path resolved.
    fn card_row(country: Option<&str>, city: Option<&str>, asn: Option<&str>) -> proxies::ProxyRow {
        proxies::ProxyRow {
            id: 1,
            fingerprint: "fp".into(),
            scheme: "vless".into(),
            name: "n".into(),
            host: "h1.example.com".into(),
            port: 443,
            credential: "uuid".into(),
            params: None,
            unknown_params: None,
            raw_line: None,
            geo_country: country.map(str::to_string),
            geo_city: city.map(str::to_string),
            geo_asn: asn.map(str::to_string),
            resolved_ip: None,
            status: "unknown".into(),
            fail_count: 0,
            last_checked_at: None,
            last_alive_at: None,
            quarantined_at: None,
            ladder_at: None,
            ladder_step: 0,
            removed_at: None,
            latency_ms: None,
            speed_mbps: None,
            last_t2_failed_at: None,
            created_at: 1,
            updated_at: 1,
        }
    }

    /// The card is rendered from this `ProxyRow`, never re-read from the
    /// database, so the refresh must not turn a stored fact into `None` on
    /// the struct either. The resolver merges the databases with an
    /// `any`-hit, so a partial stamp is an ordinary outcome: an ASN-only
    /// hit (a City record that decodes with an empty country, as for the
    /// Cloudflare `104.16.0.0/12` block) must keep the country and city the
    /// card shows, exactly as `update_geo_full`'s `COALESCE` keeps them in
    /// the database.
    #[test]
    fn a_partial_stamp_does_not_clear_the_rendered_geo_fields() {
        let mut row = card_row(Some("US"), Some("New York"), None);
        merge_geo_stamp(
            &mut row,
            &proxies::GeoStamp {
                country: None,
                city: None,
                asn: Some("AS13335".into()),
            },
        );
        assert_eq!(
            row.geo_country.as_deref(),
            Some("US"),
            "an ASN-only stamp must not render an empty Country over a stored 'US'"
        );
        assert_eq!(
            row.geo_city.as_deref(),
            Some("New York"),
            "an ASN-only stamp must not render an empty City over a stored one"
        );
        assert_eq!(
            row.geo_asn.as_deref(),
            Some("AS13335"),
            "the ASN the lookup did resolve is shown"
        );
    }

    /// A stamp that does carry the fields still refreshes them.
    #[test]
    fn a_full_stamp_refreshes_the_rendered_geo_fields() {
        let mut row = card_row(Some("US"), Some("New York"), Some("AS13335"));
        merge_geo_stamp(
            &mut row,
            &proxies::GeoStamp {
                country: Some("DE".into()),
                city: Some("Frankfurt".into()),
                asn: Some("AS24940".into()),
            },
        );
        assert_eq!(row.geo_country.as_deref(), Some("DE"));
        assert_eq!(row.geo_city.as_deref(), Some("Frankfurt"));
        assert_eq!(row.geo_asn.as_deref(), Some("AS24940"));
    }

    /// The workspace `config/` directory with the gitignored GeoLite2 files
    /// (the test skips itself when it is empty, CI runs without them), the
    /// same fixture convention as the resolver tests in `fumox-core::geo`.
    fn workspace_db_dir() -> Option<std::path::PathBuf> {
        let dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../config");
        let has_any = ["GeoLite2-City.mmdb", "GeoLite2-ASN.mmdb"]
            .iter()
            .any(|name| dir.join(name).is_file());
        has_any.then(|| dir.canonicalize().unwrap())
    }

    /// An admin state on a throwaway database, with the card resolver
    /// pointed at the workspace GeoLite2 files. `None` when none are
    /// present.
    async fn geo_card_state() -> Option<AdminState> {
        let db_dir = workspace_db_dir()?;
        let dir = std::env::temp_dir().join(format!("fumox-card-test-{}", now_ts()));
        std::fs::create_dir_all(&dir).unwrap();
        let pool = fumox_core::db::connect_pool(&fumox_core::config::DatabaseConfig {
            path: dir.join("test.db"),
            ..Default::default()
        })
        .await
        .unwrap();
        fumox_core::db::migrate(&pool).await.unwrap();
        let (refresh_tx, refresh_rx) = tokio::sync::mpsc::unbounded_channel();
        std::mem::forget(refresh_rx); // keep the channel open for sends
        let config = fumox_core::AppConfig::default();
        let fetcher =
            crate::fetcher::Fetcher::new(config.fetch.clone(), false, config.geo.dns_timeout());
        let mut state = AdminState::new(
            pool,
            crate::cache::Caches::new(),
            std::sync::Arc::new(fumox_core::geo::GeoResolver::new(&Default::default())),
            refresh_tx,
            crate::scheduler::SchedulerState::new(1),
            crate::events::EventBus::new(),
            fetcher,
            config,
            fumox_core::config::ResolvedConfigPath::Missing,
        );
        state.geo_full = std::sync::Arc::new(fumox_core::geo::FullResolver::from_dir(
            &fumox_core::config::GeoConfig {
                db_dir,
                ..Default::default()
            },
        ));
        state.geo_full.is_active().then_some(state)
    }

    /// The card end to end: opening it refreshes the geo facts, and for a
    /// host whose lookup only yields an ASN the row the template renders
    /// must keep its stored country and city, on the struct *and* in the
    /// database. Skipped without the GeoLite2 files, and on a database
    /// build that does not reproduce the ASN-only shape.
    #[tokio::test]
    async fn card_refresh_keeps_stored_geo_when_the_lookup_only_yields_an_asn() {
        let Some(state) = geo_card_state().await else {
            eprintln!("skipping: no GeoLite2 databases in workspace config/");
            return;
        };
        // A literal address from the Cloudflare block: the City record
        // decodes with an empty country there, the ASN record hits.
        let host = "104.16.0.1";
        let Some(info) = state.geo_full.resolve(host).await else {
            eprintln!("skipping: {host} not covered by the local GeoLite2 files");
            return;
        };
        if info.country_code.is_some() || info.asn.is_none() {
            eprintln!("skipping: local databases no longer give an ASN-only stamp: {info:?}");
            return;
        }
        let (id,): (i64,) = sqlx::query_as(
            "INSERT INTO proxies
                 (fingerprint, scheme, name, host, port, credential,
                  geo_country, geo_city, created_at, updated_at)
             VALUES ('fp-card', 'vless', 'n', ?, 443, 'uuid', 'US', 'New York', 1, 1)
             RETURNING id",
        )
        .bind(host)
        .fetch_one(&state.pool)
        .await
        .unwrap();

        let mut row = proxies::get_by_id(&state.pool, id).await.unwrap().unwrap();
        refresh_geo(&state, &mut row).await;

        // What the card renders: a `-` here would hide a country the row
        // still holds.
        assert_eq!(
            row.geo_country.as_deref(),
            Some("US"),
            "the card must keep showing the stored country"
        );
        assert_eq!(row.geo_city.as_deref(), Some("New York"));
        assert!(row.geo_asn.is_some(), "the resolved ASN is shown");
        assert_eq!(row.resolved_ip.as_deref(), Some(host));
        // And the database kept them too.
        let stored = proxies::get_by_id(&state.pool, id).await.unwrap().unwrap();
        assert_eq!(stored.geo_country.as_deref(), Some("US"));
        assert_eq!(stored.geo_city.as_deref(), Some("New York"));
    }

    /// Admin state with `[ingest].refresh_check_limit = 0`: the operator
    /// setting that documents "0 disables the queue" for *ingest*. Built
    /// by hand (the `test_admin_state` helper fixes the default config)
    /// with the same shape as the geo card fixture above.
    async fn no_ingest_queue_state() -> AdminState {
        let dir = std::env::temp_dir().join(format!("fumox-revive-test-{}", now_ts()));
        std::fs::create_dir_all(&dir).unwrap();
        let pool = fumox_core::db::connect_pool(&fumox_core::config::DatabaseConfig {
            path: dir.join("test.db"),
            ..Default::default()
        })
        .await
        .unwrap();
        fumox_core::db::migrate(&pool).await.unwrap();
        let (refresh_tx, refresh_rx) = tokio::sync::mpsc::unbounded_channel();
        std::mem::forget(refresh_rx); // keep the channel open for sends
        let mut config = fumox_core::AppConfig::default();
        config.ingest.refresh_check_limit = 0;
        let fetcher = crate::fetcher::Fetcher::new(
            config.fetch.clone(),
            config.admin.allow_private_urls,
            config.geo.dns_timeout(),
        );
        AdminState::new(
            pool,
            crate::cache::Caches::new(),
            std::sync::Arc::new(fumox_core::geo::GeoResolver::new(&Default::default())),
            refresh_tx,
            crate::scheduler::SchedulerState::new(1),
            crate::events::EventBus::new(),
            fetcher,
            config,
            fumox_core::config::ResolvedConfigPath::Missing,
        )
    }

    /// A revival must hand its rows to the probe queue even when the
    /// operator disabled the ingest queue: reusing the ingest-only
    /// `refresh_check_limit` knob here used to make every revival click
    /// report success while enqueueing nothing (`0` disables the queue).
    #[tokio::test]
    async fn revival_enqueues_even_when_the_ingest_queue_is_disabled() {
        let state = no_ingest_queue_state().await;
        assert_eq!(
            state.ingest().refresh_check_limit,
            0,
            "the fixture must simulate the disabled ingest queue"
        );

        // One `removed` row linked to a source (the fixture mirrors the
        // probe repo's queue tests: the link FK needs the source row).
        sqlx::query(
            "INSERT OR IGNORE INTO sources (id, name, url, enabled, cache_ttl_seconds, created_at, updated_at)
             VALUES ('srcA0000000', 's', 'https://example.com', 1, 3600, 1, 1)",
        )
        .execute(&state.pool)
        .await
        .unwrap();
        let (id,): (i64,) = sqlx::query_as(
            "INSERT INTO proxies (fingerprint, scheme, name, host, port, credential, status, geo_country, created_at, updated_at)
             VALUES ('fp-revive', 'trojan', 'n', 'h', 443, 'c', 'removed', 'DE', 1, 1)
             RETURNING id",
        )
        .fetch_one(&state.pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO proxy_source_links (proxy_id, source_id, seen_at) VALUES (?, 'srcA0000000', 1)",
        )
        .bind(id)
        .execute(&state.pool)
        .await
        .unwrap();

        // The exact pair of calls every revival handler makes: the repo
        // transition moves the row to `unknown` and returns its id, then
        // the hand-off enqueues it for priority probing.
        let ids = proxies::revive_removed_by_country(&state.pool, "DE", now_ts())
            .await
            .unwrap();
        assert_eq!(ids, vec![id], "the revival must cover the removed row");
        enqueue_revived(&state, &ids).await;

        let (queued,): (i64,) =
            sqlx::query_as("SELECT COUNT(*) FROM probe_requests WHERE proxy_id = ?")
                .bind(id)
                .fetch_one(&state.pool)
                .await
                .unwrap();
        assert_eq!(
            queued, 1,
            "the revival hand-off must enqueue despite refresh_check_limit = 0"
        );
    }
}
