//! Global fetch journal screen: `fetch_log` across all
//! sources with ok/error, error-class and source filters plus pagination.
//! Probe history intentionally has no page of its own, it lives on the
//! proxy card.

use super::{
    FormMap, PageLink, clamp_limit, fmt_bytes, page_offset, pagination_pages, server_error,
};
use crate::admin::AdminState;
use crate::admin::i18n::{Lang, impl_i18n};
use crate::admin::render_html;
use crate::admin::theme::{self, Theme};
use askama::Template;
use axum::extract::{Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::Response;
use fumox_core::repo::fetch_log::{self, FetchLogFilter, FetchLogListRow};

#[derive(Template)]
#[template(path = "logs/fetch.html")]
struct FetchLogsTemplate {
    lang: Lang,
    langs: Vec<(String, String)>,
    theme: Theme,
    active: &'static str,
    csrf: String,
    rows: Vec<FetchLogListRow>,
    total: i64,
    pages: Vec<PageLink>,
    /// The clamped current page and the last page of the strip: the
    /// `_pagination.html` strip bounds its prev/next step links with
    /// them.
    page: i64,
    pages_count: i64,
    per_page: i64,
    f_result: String,
    f_class: String,
    f_source: String,
    sources: Vec<(String, String, bool)>,
    /// Every error class the schema knows, preselected where it matches
    /// the current `class` filter. Derived from `ErrorClass::all()`, so
    /// a new class is filterable the moment it exists.
    error_classes: Vec<(String, bool)>,
}

impl FetchLogsTemplate {
    fn bytes(&self, n: &Option<i64>) -> String {
        n.map(|bytes| fmt_bytes(&self.lang, bytes))
            .unwrap_or_else(|| ",".into())
    }

    fn source_selected(&self, id: &str) -> bool {
        self.f_source == id
    }

    /// Preserve the current filters in pagination links.
    fn query_suffix(&self) -> String {
        filter_query_suffix(&self.f_result, &self.f_class, &self.f_source)
    }
}

/// Add one filter to a query string: the value is percent-encoded, so a
/// filter with a special character travels through the link without
/// changing the meaning of the rest of it.
fn push_param(parts: &mut Vec<String>, key: &str, value: &str) {
    if value.is_empty() {
        return;
    }
    parts.push(format!(
        "{key}={}",
        percent_encoding::utf8_percent_encode(value, percent_encoding::NON_ALPHANUMERIC)
    ));
}

/// The query that carries the current filters into the next page.
///
/// Every filter goes through [`push_param`]: the values come from the
/// query string, so an unencoded one would let a crafted filter value
/// change the pagination link's own parameters.
fn filter_query_suffix(result: &str, class: &str, source: &str) -> String {
    let mut parts: Vec<String> = Vec::new();
    push_param(&mut parts, "result", result);
    push_param(&mut parts, "class", class);
    push_param(&mut parts, "source", source);
    if parts.is_empty() {
        String::new()
    } else {
        format!("&{}", parts.join("&"))
    }
}

impl_i18n!(FetchLogsTemplate);

/// The `ok` half of [`FetchLogFilter`] from the `result` query parameter:
/// `ok` keeps only the successful fetches, `error` only the failures,
/// anything else (including an absent parameter) filters nothing.
fn result_ok_filter(result: &str) -> Option<bool> {
    match result {
        "ok" => Some(true),
        "error" => Some(false),
        _ => None,
    }
}

pub async fn fetch_logs(
    State(state): State<AdminState>,
    headers: HeaderMap,
    Query(params): Query<FormMap>,
) -> Response {
    let lang = state.locales.lang_from_headers(&headers);
    let theme = theme::from_headers(&headers);
    let f_result = params.get("result").cloned().unwrap_or_default();
    let f_class = params.get("class").cloned().unwrap_or_default();
    let f_source = params.get("source").cloned().unwrap_or_default();
    let page: i64 = params
        .get("page")
        .and_then(|v| v.parse().ok())
        .unwrap_or(1)
        .max(1);
    let per_page = clamp_limit(params.get("per_page").and_then(|v| v.parse().ok()));

    // The filter clause set lives once in the repo (`FetchLogFilter`):
    // count and rows below apply exactly the same clauses, and every
    // value flows through a bind.
    let filter = FetchLogFilter {
        ok: result_ok_filter(&f_result),
        error_class: f_class.clone(),
        source_id: f_source.clone(),
    };

    let total: i64 = match fetch_log::count_filtered(&state.pool, &filter).await {
        Ok(total) => total,
        Err(err) => return server_error(&state, &headers, "logs.fetch", &err),
    };
    // A page past the last one renders the last non-empty page instead of
    // an empty table: a stale pagination link or a hand-typed ?page=999
    // must not look like "the journal is empty".
    let pages_count = ((total + per_page - 1) / per_page).max(1);
    let page = page.min(pages_count);

    // The rows and the source selects are independent reads, issued
    // together. The count has to land first: the clamp above reads its
    // total before the page query can be placed.
    let (rows, sources) = tokio::join!(
        fetch_log::list_page(&state.pool, &filter, per_page, page_offset(page, per_page)),
        super::all_sources_for_selects(&state.pool),
    );
    let rows: Vec<FetchLogListRow> = match rows {
        Ok(rows) => rows,
        Err(err) => return server_error(&state, &headers, "logs.fetch", &err),
    };
    let sources = match sources {
        Ok(sources) => sources,
        Err(err) => return server_error(&state, &headers, "logs.fetch", &err),
    };
    let mut error_classes: Vec<(String, bool)> = fumox_core::models::ErrorClass::all()
        .iter()
        .map(|class| (class.as_str().to_string(), class.as_str() == f_class))
        .collect();
    // A filter value the schema does not know (an old link, a hand-typed
    // ?class=) filters the rows below all the same; it must also stay
    // visible as the selected option of the select it is set in.
    if !f_class.is_empty() && !error_classes.iter().any(|(class, _)| class == &f_class) {
        error_classes.push((f_class.clone(), true));
    }

    render_html(
        lang.clone(),
        "logs/fetch.html",
        &FetchLogsTemplate {
            lang,
            langs: state.locales.choices().to_vec(),
            theme,
            active: "logs",
            csrf: state.csrf_for(&headers),
            rows,
            total,
            pages: pagination_pages(page, total, per_page),
            page,
            pages_count,
            per_page,
            f_result,
            f_class,
            f_source,
            sources,
            error_classes,
        },
        StatusCode::OK,
    )
}

#[cfg(test)]
mod tests {
    use super::{filter_query_suffix, result_ok_filter};

    /// Every filter of the pagination link is percent-encoded: a value
    /// with a special character cannot change the parameters of the link
    /// it travels in.
    #[test]
    fn the_pagination_link_encodes_every_filter() {
        // No filter: no suffix at all.
        assert_eq!(filter_query_suffix("", "", ""), "");
        // The ordinary case: the filters travel as they are.
        assert_eq!(
            filter_query_suffix("ok", "network", "src1"),
            "&result=ok&class=network&source=src1"
        );
        // A value with a special character is encoded, not dropped and
        // not pasted in raw.
        assert_eq!(
            filter_query_suffix("ok", "a&b=c", "src 1"),
            "&result=ok&class=a%26b%3Dc&source=src%201"
        );
        // An empty filter is left out, the others still travel.
        assert_eq!(filter_query_suffix("", "network", ""), "&class=network");
    }

    /// The `result` query parameter maps onto the filter's `ok` half:
    /// exactly the two known words filter, everything else — including
    /// the empty string — filters nothing instead of matching one of the
    /// two buckets by accident.
    #[test]
    fn the_result_filter_accepts_exactly_ok_and_error() {
        assert_eq!(result_ok_filter("ok"), Some(true));
        assert_eq!(result_ok_filter("error"), Some(false));
        assert_eq!(result_ok_filter(""), None);
        assert_eq!(result_ok_filter("OK"), None);
        assert_eq!(result_ok_filter("failed"), None);
    }
}
