//! Proxy browser: server-side filtered and paginated
//! list (thousands of rows, never "show all"), detail card with lifecycle
//! timeline, probe history and source links, and the manual "reset status"
//! action.

use super::{
    QueryPairs, action_response, action_response_err, clamp_limit, flag_for, is_htmx, mask_secret,
    not_found, server_error,
};
use crate::admin::AdminState;
use crate::admin::i18n::{Lang, impl_i18n};
use crate::admin::presentation::{fmt_opt_ts_element, fmt_ts_element};
use crate::admin::render_html;
use crate::admin::theme::{self, Theme};
use crate::redact::{REDACTED, is_sensitive_param, mask_query, userinfo_span};
use askama::Template;
use axum::extract::{ConnectInfo, Form, Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::Response;
use std::net::SocketAddr;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use fumox_core::models::{ProxyStatus, Scheme, now_ts};
use fumox_core::repo::probe as probe_repo;
use fumox_core::repo::proxies::{
    self, CheckCoverage, ProxyLinkRow, ProxyListCursor, ProxyListDirection, ProxyListFilter,
    ProxyListOrder, ProxyListPage, ProxyListRow,
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
    /// Count of rows without a source link (unfiltered); no feed reaches
    /// them and no probe lane can pick them up.
    detached_count: i64,
    /// Link to the first page of the list; `None` while the first page
    /// is shown.
    nav_first: Option<String>,
    /// Link to the page before this one; `None` while the first page is
    /// shown.
    nav_prev: Option<String>,
    /// Link to the page after this one; `None` on the last page.
    nav_next: Option<String>,
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

// Keyset cursor
//
// The browser pages with a cursor instead of a page number: the link to
// the next page carries the sort key of the last row of the current
// one, so the database seeks straight to it instead of walking over
// every row the page skips. The cursor travels as one opaque token, so
// a display name (which may hold any character) cannot break the query
// string.

/// The token of one cursor: `side|tag|id|value`, base64url-encoded.
///
/// The name is the last field, so a name that holds a `|` survives the
/// split. The value of the latency tag is empty for an unmeasured row.
fn encode_list_cursor(cursor: &ProxyListCursor, direction: ProxyListDirection) -> String {
    let side = match direction {
        ProxyListDirection::Forward => 'f',
        ProxyListDirection::Backward => 'b',
    };
    let (tag, id, value) = match cursor {
        ProxyListCursor::Updated { updated_at, id } => ('u', *id, updated_at.to_string()),
        ProxyListCursor::Latency { latency_ms, id } => (
            'l',
            *id,
            latency_ms.map(|ms| ms.to_string()).unwrap_or_default(),
        ),
        ProxyListCursor::Name { name, id } => ('n', *id, name.clone()),
    };
    URL_SAFE_NO_PAD.encode(format!("{side}|{tag}|{id}|{value}"))
}

/// The cursor a token carries, or `None` for a token this browser did
/// not write. A damaged token is not an error: the list falls back to
/// its first page.
fn decode_list_cursor(token: &str) -> Option<(ProxyListCursor, ProxyListDirection)> {
    let raw = URL_SAFE_NO_PAD.decode(token).ok()?;
    let payload = String::from_utf8(raw).ok()?;
    let mut parts = payload.splitn(4, '|');
    let side = parts.next()?;
    let tag = parts.next()?;
    let id: i64 = parts.next()?.parse().ok()?;
    let value = parts.next()?;
    let direction = match side {
        "f" => ProxyListDirection::Forward,
        "b" => ProxyListDirection::Backward,
        _ => return None,
    };
    let cursor = match tag {
        "u" => ProxyListCursor::Updated {
            updated_at: value.parse().ok()?,
            id,
        },
        "l" => ProxyListCursor::Latency {
            latency_ms: if value.is_empty() {
                None
            } else {
                Some(value.parse().ok()?)
            },
            id,
        },
        "n" => ProxyListCursor::Name {
            name: value.to_string(),
            id,
        },
        _ => return None,
    };
    Some((cursor, direction))
}

/// The filter and sort parameters of the current view as a query-string
/// suffix (empty when nothing narrows the list). The pagination links
/// carry them, so a filtered list stays filtered while it is paged.
fn list_query_suffix(filter: &ProxyListFilter, order: ProxyListOrder) -> String {
    let mut parts: Vec<String> = Vec::new();
    for status in &filter.statuses {
        parts.push(format!("status={}", urlencoding(status)));
    }
    if !filter.scheme.is_empty() {
        parts.push(format!("scheme={}", urlencoding(&filter.scheme)));
    }
    if !filter.country.is_empty() {
        parts.push(format!("country={}", urlencoding(&filter.country)));
    }
    if !filter.source_id.is_empty() {
        parts.push(format!("source={}", urlencoding(&filter.source_id)));
    }
    if !filter.query.is_empty() {
        parts.push(format!("q={}", urlencoding(&filter.query)));
    }
    if let Some(bucket) = filter.coverage {
        parts.push(format!("coverage={}", urlencoding(bucket.as_str())));
    }
    if order != ProxyListOrder::Updated {
        parts.push(format!("sort={}", urlencoding(order.as_param())));
    }
    if parts.is_empty() {
        String::new()
    } else {
        format!("&{}", parts.join("&"))
    }
}

/// The link to one page of the browser: the cursor token of the page
/// (absent for the first page) and the parameters of the current view.
fn list_page_link(
    suffix: &str,
    per_page: i64,
    cursor: Option<&ProxyListCursor>,
    direction: ProxyListDirection,
) -> String {
    let mut link = format!("/admin/proxies?per_page={per_page}");
    if let Some(cursor) = cursor {
        // The base64url alphabet needs no escaping in a query string.
        link.push_str(&format!("&cur={}", encode_list_cursor(cursor, direction)));
    }
    link.push_str(suffix);
    link
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
    //
    // The whitelist is the status vocabulary of the core model: a value
    // outside it is not a filter, it is a typo or a probe at the URL, and
    // it is logged instead of being silently dropped.
    let requested_statuses = params.all("status").cloned().collect::<Vec<String>>();
    let mut rejected: Vec<&str> = Vec::new();
    let f_statuses: Vec<String> = requested_statuses
        .iter()
        .filter(|value| {
            if value.parse::<ProxyStatus>().is_ok() {
                true
            } else {
                rejected.push(value.as_str());
                false
            }
        })
        .cloned()
        .collect();
    if !rejected.is_empty() {
        tracing::warn!(
            rejected = ?rejected,
            "proxy list filter carries unknown status values"
        );
    }
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

    // The cursor of the requested page. A token of another sort is not a
    // position in this one, so the list falls back to its first page
    // instead of paging from a key that means nothing here.
    let requested = params
        .get("cur")
        .and_then(|token| decode_list_cursor(token))
        .filter(|(cursor, _)| order.accepts_cursor(cursor));
    let page = requested.as_ref().map(|(cursor, direction)| ProxyListPage {
        cursor: cursor.clone(),
        direction: *direction,
    });

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

    // Rows without a source link: no feed reaches them and no probe
    // lane can pick them up. The panel names them, so the operator can
    // see how much of the table is detached.
    let detached_count: i64 = match proxies::count_detached(&state.pool).await {
        Ok(count) => count,
        Err(err) => return server_error(lang, &err),
    };

    // The side of the cursor the page takes: a page reached backwards
    // holds the rows right before the cursor, a page reached forwards
    // the rows right after it.
    let backward = page
        .as_ref()
        .is_some_and(|page| page.direction == ProxyListDirection::Backward);

    // One row more than the page holds: the extra row says whether a
    // further page exists without a second count.
    let mut rows: Vec<ProxyListRow> = match proxies::list_filtered(
        &state.pool,
        &filter,
        order,
        per_page + 1,
        page.as_ref(),
    )
    .await
    {
        Ok(rows) => rows,
        Err(err) => return server_error(lang, &err),
    };
    let has_more = rows.len() as i64 > per_page;
    if backward && has_more {
        // The rows closest to the cursor come last, so the over-fetched
        // row is the farthest one: the page keeps the rows right before
        // the cursor, and the extra row stays the proof that the table
        // holds more of them.
        rows.remove(0);
    }
    rows.truncate(per_page as usize);

    // The neighbours of the page: a page reached forwards has a
    // predecessor as soon as it is not the first one, a page reached
    // backwards has a successor even when the table ends there.
    let first_cursor = rows.first().map(|row| row.cursor(order));
    let last_cursor = rows.last().map(|row| row.cursor(order));
    let (prev, next) = if backward {
        (
            // Further back only when the table holds rows before this
            // page.
            if has_more {
                first_cursor
                    .as_ref()
                    .map(|cursor| (cursor.clone(), ProxyListDirection::Backward))
            } else {
                None
            },
            // Forwards again: the rows after this page.
            last_cursor
                .as_ref()
                .map(|cursor| (cursor.clone(), ProxyListDirection::Forward)),
        )
    } else {
        (
            if page.is_some() {
                first_cursor
                    .as_ref()
                    .map(|cursor| (cursor.clone(), ProxyListDirection::Backward))
            } else {
                None
            },
            if has_more {
                last_cursor
                    .as_ref()
                    .map(|cursor| (cursor.clone(), ProxyListDirection::Forward))
            } else {
                None
            },
        )
    };

    let suffix = list_query_suffix(&filter, order);
    let nav_first = page
        .is_some()
        .then(|| list_page_link(&suffix, per_page, None, ProxyListDirection::Forward));
    let nav_prev = prev
        .as_ref()
        .map(|(cursor, direction)| list_page_link(&suffix, per_page, Some(cursor), *direction));
    let nav_next = next
        .as_ref()
        .map(|(cursor, direction)| list_page_link(&suffix, per_page, Some(cursor), *direction));

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
            all_statuses: ProxyStatus::all()
                .iter()
                .map(|status| {
                    (
                        status.as_str().to_string(),
                        f_statuses.iter().any(|s| s == status.as_str()),
                    )
                })
                .collect(),
            all_schemes: Scheme::all()
                .iter()
                .map(|scheme| (scheme.as_str().to_string(), scheme.as_str() == f_scheme))
                .collect(),
            rows,
            total,
            removed_count,
            detached_count,
            nav_first,
            nav_prev,
            nav_next,
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
    /// The credential of the row with its secret masked; the panel never
    /// renders the stored value.
    credential_display: String,
    params_display: String,
    unknown_params_display: String,
    /// The stored subscription line with its secrets masked.
    raw_line_display: Option<String>,
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

/// The credential of a proxy row as the panel shows it: the secret
/// masked.
///
/// A credential is either `user:pass` (the socks/http style) or a single
/// secret (the uuid of a vless line): with no colon there is no account
/// name to keep, and the whole value is the secret.
fn mask_credential(credential: &str) -> String {
    if credential.is_empty() {
        return String::new();
    }
    match credential.split_once(':') {
        Some((user, password)) => format!("{user}:{}", mask_secret(password)),
        None => mask_secret(credential),
    }
}

/// A proxy line as the panel shows it: the credential of the userinfo
/// masked and the value of every credential-bearing query pair redacted.
fn mask_proxy_line(line: &str) -> String {
    let masked = match userinfo_span(line) {
        Some((start, end)) => {
            let userinfo = &line[start..end];
            format!(
                "{}{}{}",
                &line[..start],
                mask_credential(userinfo),
                &line[end..]
            )
        }
        None => line.to_string(),
    };
    mask_query(&masked)
}

/// The value of every credential-bearing parameter replaced by the
/// redaction marker; the parameters themselves are the diagnostics.
fn mask_param_values(value: &serde_json::Value) -> serde_json::Value {
    match value {
        serde_json::Value::Object(map) => serde_json::Value::Object(
            map.iter()
                .map(|(key, value)| {
                    let value = if is_sensitive_param(key) {
                        serde_json::Value::String(REDACTED.to_string())
                    } else {
                        mask_param_values(value)
                    };
                    (key.clone(), value)
                })
                .collect(),
        ),
        other => other.clone(),
    }
}

/// Pretty-print a stored params JSON column with the secrets masked;
/// corrupt JSON is shown verbatim rather than hiding the problem.
fn pretty_params(column: &Option<String>) -> String {
    column
        .as_deref()
        .filter(|text| !text.is_empty())
        .map(|text| {
            serde_json::from_str::<serde_json::Value>(text)
                .ok()
                .map(|value| mask_param_values(&value))
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
    let proxy = match proxies::get_by_id(&state.pool, id).await {
        Ok(Some(proxy)) => proxy,
        Ok(None) => return not_found(lang, "err.proxy_not_found"),
        Err(err) => return server_error(lang, &err),
    };

    // Opening the card refreshes the geo facts from every available
    // GeoLite2 database (City/ASN included), no button to click. The
    // lookup runs in the background: the card renders the stored facts
    // now and shows the fresh ones on the next open.
    refresh_geo(&state, proxy.id, &proxy.host);

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
            credential_display: mask_credential(&proxy.credential),
            params_display: pretty_params(&proxy.params),
            unknown_params_display: pretty_params(&proxy.unknown_params),
            raw_line_display: proxy.raw_line.as_deref().map(mask_proxy_line),
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
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> Response {
    let lang = state.locales.lang_from_headers(&headers);
    let deleted = match proxies::purge_removed(&state.pool).await {
        Ok(deleted) => deleted,
        Err(err) => return server_error(lang, &err),
    };
    // The peer names who ran the destructive action: the purge cannot be
    // undone.
    tracing::info!(deleted, peer = %peer, "purged removed proxies");
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
        pub async fn $name(
            State(state): State<AdminState>,
            ConnectInfo(peer): ConnectInfo<SocketAddr>,
            headers: HeaderMap,
        ) -> Response {
            let lang = state.locales.lang_from_headers(&headers);
            let moved = match proxies::$repo_fn(&state.pool).await {
                Ok(moved) => moved,
                Err(err) => return server_error(lang, &err),
            };
            tracing::info!(moved, peer = %peer, $log_msg);
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
bulk_cleanup_handler!(
    proxies_remove_detached,
    remove_detached,
    "removed proxies without a source link"
);

/// Normalize an AS number typed into the cleanup form: accepts both
/// `24940` and `AS24940`, returns the canonical `AS{n}` text the
/// `geo_asn` column stores. `None` when the input is not a plain AS
/// number (empty, non-digits, too long).
fn normalize_asn(input: &str) -> Option<String> {
    fumox_core::geo::canonical_asn(input)
}

/// Move every `alive` proxy of one autonomous system into `removed`
/// (cleanup panel). The form field `asn` accepts `24940` and `AS24940`.
pub async fn proxies_remove_alive_by_asn(
    State(state): State<AdminState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
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
    tracing::info!(asn = %asn, moved, peer = %peer, "removed alive proxies by ASN");
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
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
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
    tracing::info!(country = %code, moved, peer = %peer, "removed alive proxies by country");
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
        pub async fn $name(
            State(state): State<AdminState>,
            ConnectInfo(peer): ConnectInfo<SocketAddr>,
            headers: HeaderMap,
        ) -> Response {
            let lang = state.locales.lang_from_headers(&headers);
            let outcome = match proxies::$repo_fn(&state.pool, now_ts()).await {
                Ok(outcome) => outcome,
                Err(err) => return server_error(lang, &err),
            };
            let revived = outcome.revived;
            tracing::info!(revived, peer = %peer, $log_msg);
            enqueue_revived(&state, &outcome.ids).await;
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
    proxies_revive_removed_never_checked,
    revive_removed_never_checked,
    "revived removed proxies that were never checked",
    "px.revive_never_checked_rows"
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
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
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
    let outcome = match proxies::revive_removed_by_asn(&state.pool, &asn, now_ts()).await {
        Ok(outcome) => outcome,
        Err(err) => return server_error(lang, &err),
    };
    let revived = outcome.revived;
    tracing::info!(asn = %asn, revived, peer = %peer, "revived removed proxies by ASN");
    enqueue_revived(&state, &outcome.ids).await;
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
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
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
    let outcome = match proxies::revive_removed_by_country(&state.pool, &code, now_ts()).await {
        Ok(outcome) => outcome,
        Err(err) => return server_error(lang, &err),
    };
    let revived = outcome.revived;
    tracing::info!(country = %code, revived, peer = %peer, "revived removed proxies by country");
    enqueue_revived(&state, &outcome.ids).await;
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
///
/// The badge vocabulary is the status model of the core: a value outside
/// it is not a status, and the badge falls back to `unknown`.
fn status_badge(lang: &Lang, status: &str) -> String {
    let (class, key) = match status.parse::<ProxyStatus>() {
        Ok(ProxyStatus::Alive) => ("alive", "common.status_alive"),
        Ok(ProxyStatus::Ready) => ("ready", "common.status_ready"),
        Ok(ProxyStatus::Quarantine) => ("quarantine", "common.status_quarantine"),
        Ok(ProxyStatus::Removed) => ("removed", "common.status_removed"),
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
/// resolver uses) and store them.
///
/// The lookup runs in the background: a DNS timeout must not hold the
/// response of the card that triggered it, and the card renders the
/// stored facts right away. A host that does not resolve keeps its stored
/// facts, an empty stamp must never wipe them; the resolver's DNS+lookup
/// cache (negative results included) makes repeat opens cheap.
///
/// The handle is returned for the callers that want to wait for the
/// write; the request path drops it and the task runs detached.
fn refresh_geo(state: &AdminState, proxy_id: i64, host: &str) -> tokio::task::JoinHandle<()> {
    if !state.geo_full.is_active() {
        return tokio::spawn(async {});
    }
    let pool = state.pool.clone();
    let resolver = state.geo_full.clone();
    let host = host.to_string();
    tokio::spawn(async move {
        let Some(info) = resolver.resolve(&host).await else {
            return;
        };
        let stamp = proxies::GeoStamp::from_info(&info);
        if let Err(err) = proxies::update_geo_full(&pool, proxy_id, &stamp, &info.ip).await {
            tracing::warn!(proxy_id, error = %err, "card geo refresh failed");
            return;
        }
        tracing::debug!(proxy_id, host = %host, "card geo refreshed");
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The credential of a proxy card is a secret: the card shows the
    /// mask, never the stored value. A `user:pass` credential keeps the
    /// account name (it tells the operator which account it is); a
    /// credential without a colon is a single secret (the uuid of a
    /// vless line) and is masked whole.
    #[test]
    fn the_credential_is_masked() {
        assert_eq!(mask_credential("user:secret123"), "user:sec…••••");
        assert_eq!(mask_credential("a-very-long-uuid"), "a-v…••••");
        // A short credential is hidden entirely.
        assert_eq!(mask_credential("ab:cd"), "ab:••••");
        // No credential, no mask.
        assert_eq!(mask_credential(""), "");
    }

    /// The stored subscription line carries the credential in its
    /// userinfo and the token in its query: the card shows both masked.
    #[test]
    fn the_raw_line_is_masked() {
        let line = "vless://user:secret123@example.com:443?token=ABC&type=ws#node";
        let masked = mask_proxy_line(line);
        assert!(!masked.contains("secret123"), "{masked}");
        assert!(!masked.contains("ABC"), "{masked}");
        // The parts that are not secrets survive: they are the
        // diagnostics of the line.
        assert!(masked.contains("vless://user:"), "{masked}");
        assert!(masked.contains("@example.com:443"), "{masked}");
        assert!(masked.contains("type=ws"), "{masked}");
        assert!(masked.contains("token=[redacted]"), "{masked}");
    }

    /// The parameters of a proxy row are a JSON blob; the credential-
    /// bearing ones are redacted and the rest survive.
    #[test]
    fn the_secret_parameters_are_redacted() {
        let params = serde_json::json!({
            "password": "secret",
            "username": "user",
            "tls": {"sni": "example.com"},
            "nested": {"api_key": "ABC"},
        });
        let masked = mask_param_values(&params);
        assert_eq!(masked["password"], serde_json::json!("[redacted]"));
        assert_eq!(masked["username"], serde_json::json!("user"));
        assert_eq!(masked["nested"]["api_key"], serde_json::json!("[redacted]"));
        assert_eq!(masked["tls"]["sni"], serde_json::json!("example.com"));
    }

    /// The pretty-printed parameters of the card carry the same masks:
    /// the JSON blob is rendered from the masked value, not from the
    /// stored one.
    #[test]
    fn the_pretty_printed_parameters_are_masked() {
        let column = serde_json::json!({"password": "secret", "host": "example.com"}).to_string();
        let pretty = pretty_params(&Some(column));
        assert!(!pretty.contains("secret"), "{pretty}");
        assert!(pretty.contains("example.com"), "{pretty}");
        // A corrupt column is shown verbatim: hiding the problem would
        // leave the operator without a clue.
        assert_eq!(
            pretty_params(&Some("not json".to_string())),
            "not json".to_string()
        );
    }

    /// The cursor token is the whole contract between the browser and
    /// the database: the sort key of the row a page resumes from and the
    /// side of it the page takes.
    #[test]
    fn the_cursor_token_round_trips() {
        let cursors = [
            ProxyListCursor::Updated {
                updated_at: 42,
                id: 7,
            },
            ProxyListCursor::Latency {
                latency_ms: Some(120),
                id: 7,
            },
            // An unmeasured row has no latency to carry.
            ProxyListCursor::Latency {
                latency_ms: None,
                id: 7,
            },
            // A name may hold anything, including the separator of the
            // token's own payload.
            ProxyListCursor::Name {
                name: "node | 7: ru".into(),
                id: 7,
            },
        ];
        for cursor in cursors {
            for direction in [ProxyListDirection::Forward, ProxyListDirection::Backward] {
                let token = encode_list_cursor(&cursor, direction);
                assert!(
                    !token.contains(['|', '&', '=', ' ', '+', '/']),
                    "the token must survive a query string: {token}"
                );
                assert_eq!(
                    decode_list_cursor(&token),
                    Some((cursor.clone(), direction)),
                    "the token must decode back into its cursor"
                );
            }
        }
    }

    /// A token this browser did not write is not a position in the
    /// list: the list falls back to its first page instead of failing.
    #[test]
    fn a_damaged_cursor_token_is_refused() {
        // Valid base64, but not a cursor payload.
        for token in ["", "!!!", "Zm9v"] {
            assert!(
                decode_list_cursor(token).is_none(),
                "{token} must not decode into a cursor"
            );
        }
        // The id is not a number.
        assert!(decode_list_cursor("f|u|x|1").is_none());
        // The side and the tag are not known.
        assert!(decode_list_cursor("x|u|1|1").is_none());
        assert!(decode_list_cursor("f|q|1|1").is_none());
        // The value is missing.
        assert!(decode_list_cursor("f|u|1").is_none());
    }

    /// A cursor of another sort is not a position in this order: the
    /// list falls back to its first page instead of paging from a key
    /// that means nothing here.
    #[test]
    fn a_cursor_of_another_sort_is_not_a_position_here() {
        let updated = ProxyListCursor::Updated {
            updated_at: 1,
            id: 2,
        };
        assert!(ProxyListOrder::Updated.accepts_cursor(&updated));
        assert!(!ProxyListOrder::Latency.accepts_cursor(&updated));
        assert!(!ProxyListOrder::Name.accepts_cursor(&updated));
    }

    /// The page links carry the cursor and the filters of the current
    /// view, so a filtered list stays filtered while it is paged.
    #[test]
    fn the_page_links_carry_the_cursor_and_the_filters() {
        let filter = ProxyListFilter {
            statuses: vec!["alive".into()],
            scheme: String::new(),
            country: "DE".into(),
            source_id: String::new(),
            query: "node one".into(),
            coverage: Some(CheckCoverage::T1Only),
        };
        let suffix = list_query_suffix(&filter, ProxyListOrder::Latency);
        assert_eq!(
            suffix, "&status=alive&country=DE&q=node%20one&coverage=t1%5Fonly&sort=latency",
            "the filters and the sort travel with the link"
        );

        let cursor = ProxyListCursor::Latency {
            latency_ms: Some(30),
            id: 5,
        };
        let link = list_page_link(&suffix, 25, Some(&cursor), ProxyListDirection::Forward);
        assert!(
            link.starts_with("/admin/proxies?per_page=25&cur="),
            "{link}"
        );
        assert!(link.ends_with(&suffix), "{link}");
        let token = link
            .split("cur=")
            .nth(1)
            .and_then(|rest| rest.split('&').next())
            .unwrap();
        assert_eq!(
            decode_list_cursor(token),
            Some((cursor, ProxyListDirection::Forward)),
            "the link must carry the cursor it was built from"
        );

        // The first page carries no cursor at all.
        assert_eq!(
            list_page_link(&suffix, 25, None, ProxyListDirection::Forward),
            format!("/admin/proxies?per_page=25{suffix}")
        );
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

    /// A throwaway directory per call: the tests of one binary run in
    /// parallel, and a second-resolution timestamp would hand two tests
    /// the same database file.
    fn unique_dir(label: &str) -> std::path::PathBuf {
        static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("fumox-{label}-{}-{n}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// An admin state on a throwaway database, with the card resolver
    /// pointed at the workspace GeoLite2 files. `None` when none are
    /// present.
    async fn geo_card_state() -> Option<AdminState> {
        let db_dir = workspace_db_dir()?;
        let dir = unique_dir("card-test");
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
            crate::fetcher::Fetcher::new(config.fetch.clone(), false, config.ssrf_dns_timeout());
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
            crate::alive_export::TokenCache::new(),
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

        let row = proxies::get_by_id(&state.pool, id).await.unwrap().unwrap();
        // The refresh runs in the background: the test waits for the
        // write it triggers.
        refresh_geo(&state, id, &row.host).await.unwrap();

        // What the next card renders: the row the refresh wrote. A `-`
        // here would hide a country the row still holds.
        let card = proxies::get_by_id(&state.pool, id).await.unwrap().unwrap();
        assert_eq!(
            card.geo_country.as_deref(),
            Some("US"),
            "the card must keep showing the stored country"
        );
        assert_eq!(card.geo_city.as_deref(), Some("New York"));
        // And the row gained the resolved facts.
        assert!(card.geo_asn.is_some(), "the resolved ASN is stored");
        assert_eq!(card.resolved_ip.as_deref(), Some(host));
    }

    /// Admin state with `[ingest].refresh_check_limit = 0`: the operator
    /// setting that documents "0 disables the queue" for *ingest*. Built
    /// by hand (the `test_admin_state` helper fixes the default config)
    /// with the same shape as the geo card fixture above.
    async fn no_ingest_queue_state() -> AdminState {
        let dir = unique_dir("revive-test");
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
            config.ssrf_dns_timeout(),
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
            crate::alive_export::TokenCache::new(),
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
        let outcome = proxies::revive_removed_by_country(&state.pool, "DE", now_ts())
            .await
            .unwrap();
        assert_eq!(
            outcome.ids,
            vec![id],
            "the revival must cover the removed row"
        );
        assert_eq!(outcome.revived, 1, "one row was revived");
        enqueue_revived(&state, &outcome.ids).await;

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

    /// The handler itself, not only the repo calls behind it: the form
    /// field `country` must reach the revival and the revived row must
    /// end up in `probe_requests` (the queue the probe daemon reads).
    #[tokio::test]
    async fn the_country_revival_handler_enqueues_the_revived_rows() {
        let state = no_ingest_queue_state().await;
        sqlx::query(
            "INSERT OR IGNORE INTO sources (id, name, url, enabled, cache_ttl_seconds, created_at, updated_at)
             VALUES ('srcB0000000', 's', 'https://example.com', 1, 3600, 1, 1)",
        )
        .execute(&state.pool)
        .await
        .unwrap();
        let (id,): (i64,) = sqlx::query_as(
            "INSERT INTO proxies (fingerprint, scheme, name, host, port, credential, status, geo_country, created_at, updated_at)
             VALUES ('fp-revive-country', 'trojan', 'n', 'h', 443, 'c', 'removed', 'DE', 1, 1)
             RETURNING id",
        )
        .fetch_one(&state.pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO proxy_source_links (proxy_id, source_id, seen_at) VALUES (?, 'srcB0000000', 1)",
        )
        .bind(id)
        .execute(&state.pool)
        .await
        .unwrap();

        let response = proxies_revive_removed_by_country(
            State(state.clone()),
            ConnectInfo("127.0.0.1:41000".parse().unwrap()),
            HeaderMap::new(),
            Form(vec![("country".to_string(), "DE".to_string())]),
        )
        .await;
        assert_eq!(
            response.status(),
            StatusCode::SEE_OTHER,
            "the plain-browser path answers with a redirect"
        );

        let (status,): (String,) = sqlx::query_as("SELECT status FROM proxies WHERE id = ?")
            .bind(id)
            .fetch_one(&state.pool)
            .await
            .unwrap();
        assert_eq!(status, "unknown", "the removed row must be revived");

        let (queued,): (i64,) =
            sqlx::query_as("SELECT COUNT(*) FROM probe_requests WHERE proxy_id = ?")
                .bind(id)
                .fetch_one(&state.pool)
                .await
                .unwrap();
        assert_eq!(
            queued, 1,
            "the handler must hand the revived row to the probe queue"
        );
    }
}
