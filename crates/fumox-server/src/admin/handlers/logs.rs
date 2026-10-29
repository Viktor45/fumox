//! Global fetch journal screen: `fetch_log` across all
//! sources with ok/error, error-class and source filters plus pagination.
//! Probe history intentionally has no page of its own, it lives on the
//! proxy card.

use super::{FormMap, clamp_limit, fmt_bytes, page_offset, pagination_pages, server_error};
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
    pages: Vec<(i64, bool)>,
    per_page: i64,
    f_result: String,
    f_class: String,
    f_source: String,
    sources: Vec<(String, String, bool)>,
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
        ok: match f_result.as_str() {
            "ok" => Some(true),
            "error" => Some(false),
            _ => None,
        },
        error_class: f_class.clone(),
        source_id: f_source.clone(),
    };

    let total: i64 = match fetch_log::count_filtered(&state.pool, &filter).await {
        Ok(total) => total,
        Err(err) => return server_error(lang, &err),
    };

    let rows: Vec<FetchLogListRow> =
        match fetch_log::list_page(&state.pool, &filter, per_page, page_offset(page, per_page))
            .await
        {
            Ok(rows) => rows,
            Err(err) => return server_error(lang, &err),
        };

    let sources = match super::all_sources_for_selects(&state.pool).await {
        Ok(sources) => sources,
        Err(err) => return server_error(lang, &err),
    };

    render_html(
        lang.clone(),
        &FetchLogsTemplate {
            lang,
            langs: state.locales.choices().to_vec(),
            theme,
            active: "logs",
            csrf: state.csrf_for(&headers),
            rows,
            total,
            pages: pagination_pages(page, total, per_page),
            per_page,
            f_result,
            f_class,
            f_source,
            sources,
        },
        StatusCode::OK,
    )
}

#[cfg(test)]
mod tests {
    use super::filter_query_suffix;

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
}
