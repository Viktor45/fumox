//! Global fetch journal screen: `fetch_log` across all
//! sources with ok/error, error-class and source filters plus keyset
//! pagination. Probe history intentionally has no page of its own, it
//! lives on the proxy card.

use super::{FormMap, clamp_limit, fmt_bytes, server_error};
use crate::admin::AdminState;
use crate::admin::i18n::{Lang, impl_i18n};
use crate::admin::render_html;
use crate::admin::theme::{self, Theme};
use askama::Template;
use axum::extract::{Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::Response;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use fumox_core::repo::fetch_log::{
    self, FetchLogCursor, FetchLogDirection, FetchLogFilter, FetchLogListRow, FetchLogPage,
};

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
    /// The keyset navigation of the page: the links to the first, the
    /// previous and the next page; `None` when that page does not exist
    /// (the shared `_cursor_nav.html` renders the strip only then).
    nav_first: Option<String>,
    nav_prev: Option<String>,
    nav_next: Option<String>,
    f_result: String,
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

// Keyset cursor
//
// The browser pages with a cursor instead of a page number: the link to
// the next page carries the `(fetched_at, id)` of the last row of the
// current one, so the database seeks straight to it instead of walking
// over every row the page skips. The cursor travels as one opaque
// base64url token, the same way the proxy browser's does. The source
// card's log pages by the same token, so the codec lives here next to
// the journal read it pages.

/// The token of one journal cursor: `side|fetched_at|id`, base64url-encoded.
pub(super) fn encode_fetch_cursor(cursor: FetchLogCursor, direction: FetchLogDirection) -> String {
    let side = match direction {
        FetchLogDirection::Forward => 'f',
        FetchLogDirection::Backward => 'b',
    };
    URL_SAFE_NO_PAD.encode(format!("{side}|{}|{}", cursor.fetched_at, cursor.id))
}

/// The cursor a token carries, or `None` for a token this browser did
/// not write: a damaged token is not an error, the journal falls back to
/// its first page.
pub(super) fn decode_fetch_cursor(token: &str) -> Option<(FetchLogCursor, FetchLogDirection)> {
    let raw = URL_SAFE_NO_PAD.decode(token).ok()?;
    let payload = String::from_utf8(raw).ok()?;
    let mut parts = payload.splitn(3, '|');
    let side = parts.next()?;
    let fetched_at: i64 = parts.next()?.parse().ok()?;
    let id: i64 = parts.next()?.parse().ok()?;
    let direction = match side {
        "f" => FetchLogDirection::Forward,
        "b" => FetchLogDirection::Backward,
        _ => return None,
    };
    Some((FetchLogCursor { fetched_at, id }, direction))
}

/// The link to one page of the journal: the cursor token of the page
/// (absent for the first page) and the parameters of the current view.
/// `base` is the page's list path — the global screen and the source
/// card share the cursor but not the route.
pub(super) fn journal_page_link(
    base: &str,
    per_page: i64,
    suffix: &str,
    page: Option<(FetchLogCursor, FetchLogDirection)>,
) -> String {
    let mut link = format!("{base}?per_page={per_page}");
    if let Some((cursor, direction)) = page {
        // The base64url alphabet needs no escaping in a query string.
        link.push_str(&format!("&cur={}", encode_fetch_cursor(cursor, direction)));
    }
    link.push_str(suffix);
    link
}

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
    let per_page = clamp_limit(params.get("per_page").and_then(|v| v.parse().ok()));

    // The cursor of the requested page. A token of another sort is not a
    // position in this one, so the journal falls back to its first page
    // instead of paging from a key that means nothing here.
    let page = params
        .get("cur")
        .and_then(|token| decode_fetch_cursor(token))
        .map(|(cursor, direction)| FetchLogPage { cursor, direction });

    // The filter clause set lives once in the repo (`FetchLogFilter`):
    // count and rows below apply exactly the same clauses, and every
    // value flows through a bind.
    let filter = FetchLogFilter {
        ok: result_ok_filter(&f_result),
        error_class: f_class.clone(),
        source_id: f_source.clone(),
    };

    // The three reads are independent — the count only feeds the header's
    // total, it does not place the page — so one `try_join!` runs them
    // concurrently and keeps one error site for their identical handlers.
    // The rows over-fetch by one: the extra row says whether a further
    // page exists without a second count.
    let (total, mut rows, sources) = match tokio::try_join!(
        fetch_log::count_filtered(&state.pool, &filter),
        fetch_log::list_page(&state.pool, &filter, per_page + 1, page.as_ref()),
        super::all_sources_for_selects(&state.pool),
    ) {
        Ok(reads) => reads,
        Err(err) => return server_error(&state, &headers, "logs.fetch", &err),
    };

    // The side of the cursor the page takes: a page reached backwards
    // holds the rows right before the cursor, a page reached forwards
    // the rows right after it.
    let backward = page
        .as_ref()
        .is_some_and(|page| page.direction == FetchLogDirection::Backward);

    let has_more = rows.len() as i64 > per_page;
    if backward && has_more {
        // The rows closest to the cursor come last, so the over-fetched
        // row is the farthest one: the page keeps the rows right before
        // the cursor, and the extra row stays the proof that the journal
        // holds more of them.
        rows.remove(0);
    }
    rows.truncate(per_page as usize);

    // The neighbours of the page: a page reached forwards has a
    // predecessor as soon as it is not the first one, a page reached
    // backwards has a successor even when the journal ends there.
    let first_cursor = rows.first().map(|row| FetchLogCursor {
        fetched_at: row.fetched_at,
        id: row.id,
    });
    let last_cursor = rows.last().map(|row| FetchLogCursor {
        fetched_at: row.fetched_at,
        id: row.id,
    });
    let (prev, next) = if backward {
        (
            // Further back only when the journal holds rows before this
            // page.
            if has_more {
                first_cursor.map(|cursor| (cursor, FetchLogDirection::Backward))
            } else {
                None
            },
            // Forwards again: the rows after this page.
            last_cursor.map(|cursor| (cursor, FetchLogDirection::Forward)),
        )
    } else {
        (
            if page.is_some() {
                first_cursor.map(|cursor| (cursor, FetchLogDirection::Backward))
            } else {
                None
            },
            if has_more {
                last_cursor.map(|cursor| (cursor, FetchLogDirection::Forward))
            } else {
                None
            },
        )
    };

    let suffix = filter_query_suffix(&f_result, &f_class, &f_source);
    let nav_first = page
        .is_some()
        .then(|| journal_page_link("/admin/logs/fetch", per_page, &suffix, None));
    let nav_prev = prev.map(|(cursor, direction)| {
        journal_page_link(
            "/admin/logs/fetch",
            per_page,
            &suffix,
            Some((cursor, direction)),
        )
    });
    let nav_next = next.map(|(cursor, direction)| {
        journal_page_link(
            "/admin/logs/fetch",
            per_page,
            &suffix,
            Some((cursor, direction)),
        )
    });

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
            nav_first,
            nav_prev,
            nav_next,
            f_result,
            f_source,
            sources,
            error_classes,
        },
        StatusCode::OK,
    )
}

#[cfg(test)]
mod tests {
    use super::{
        FetchLogCursor, FetchLogDirection, URL_SAFE_NO_PAD, decode_fetch_cursor,
        encode_fetch_cursor, filter_query_suffix, result_ok_filter,
    };
    use base64::Engine;

    /// The cursor token round-trips, and a token this browser did not
    /// write decodes to nothing: the journal falls back to its first page
    /// instead of paging from a key that means nothing here.
    #[test]
    fn the_cursor_token_round_trips_and_rejects_damaged_ones() {
        let cursor = FetchLogCursor {
            fetched_at: 1_700_000_000,
            id: 42,
        };
        for direction in [FetchLogDirection::Forward, FetchLogDirection::Backward] {
            let (decoded, side) =
                decode_fetch_cursor(&encode_fetch_cursor(cursor, direction)).unwrap();
            assert_eq!(decoded, cursor);
            assert_eq!(side, direction);
        }
        // Not base64 at all, then base64 of a payload with an unknown
        // side, a non-numeric second and a non-numeric timestamp.
        assert_eq!(decode_fetch_cursor("garbage"), None);
        assert_eq!(decode_fetch_cursor(""), None);
        assert_eq!(decode_fetch_cursor(&URL_SAFE_NO_PAD.encode("x|1|2")), None);
        assert_eq!(
            decode_fetch_cursor(&URL_SAFE_NO_PAD.encode("f|abc|2")),
            None
        );
        assert_eq!(
            decode_fetch_cursor(&URL_SAFE_NO_PAD.encode("f|1|abc")),
            None
        );
    }

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
