//! Global fetch journal screen: `fetch_log` across all
//! sources with ok/error, error-class and source filters plus keyset
//! pagination. Probe history intentionally has no page of its own, it
//! lives on the proxy card.

use super::{FormMap, clamp_limit, fmt_opt_bytes, server_error};
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
        fmt_opt_bytes(&self.lang, *n)
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

/// The body and the navigation neighbours of a keyset page, from the
/// over-fetched row list the repo read — the shared shape of the global
/// journal, the source card's log and the proxy browser, so a fix to the
/// edge cases lands in all three or in none.
///
/// The rows over-fetch by one: the extra row says whether a further page
/// exists without a second count. The side of the cursor the page takes
/// decides what to drop: a page reached backwards holds the rows right
/// before the cursor, the rows closest to it come last, so the
/// over-fetched row is the farthest one and leaves from the front. The
/// neighbours follow the same asymmetry: a page reached forwards has a
/// predecessor as soon as it is not the first one, a page reached
/// backwards has a successor even when the list ends there.
pub(super) fn keyset_page<T, C>(
    rows: &mut Vec<T>,
    paged: bool,
    backward: bool,
    per_page: i64,
    cursor_of: impl Fn(&T) -> C,
) -> (Option<C>, Option<C>) {
    let has_more = rows.len() as i64 > per_page;
    if backward && has_more {
        rows.remove(0);
    }
    rows.truncate(per_page as usize);
    let first_cursor = rows.first().map(&cursor_of);
    let last_cursor = rows.last().map(&cursor_of);
    if backward {
        (
            // Further back only when the list holds rows before this page.
            if has_more { first_cursor } else { None },
            // Forwards again: the rows after this page.
            last_cursor,
        )
    } else {
        (
            if paged { first_cursor } else { None },
            if has_more { last_cursor } else { None },
        )
    }
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

    // The page body and its neighbours, the shape shared with the source
    // card's log and the proxy browser (`keyset_page`).
    let (prev_cursor, next_cursor) =
        keyset_page(&mut rows, page.is_some(), backward, per_page, |row| {
            FetchLogCursor {
                fetched_at: row.fetched_at,
                id: row.id,
            }
        });
    let prev = prev_cursor.map(|cursor| (cursor, FetchLogDirection::Backward));
    let next = next_cursor.map(|cursor| (cursor, FetchLogDirection::Forward));

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
        FetchLogCursor, FetchLogDirection, FetchLogsTemplate, Theme, URL_SAFE_NO_PAD,
        decode_fetch_cursor, encode_fetch_cursor, filter_query_suffix, keyset_page,
        result_ok_filter,
    };
    use crate::admin::i18n::Locales;
    use base64::Engine;
    use std::path::Path;

    /// The shared page assembly, case by case: the over-fetched row is
    /// dropped from the front on a backwards page, the page body is
    /// truncated to `per_page`, and the neighbours follow the
    /// backward/forward asymmetry — a forward page has no predecessor
    /// when it is the first one and no successor when the over-fetch saw
    /// nothing, a backwards page has a successor even when the list ends
    /// there.
    #[test]
    fn the_keyset_page_trims_the_overfetch_and_places_the_neighbours() {
        let case = |count: usize, paged: bool, backward: bool, per_page: i64| {
            let mut rows: Vec<usize> = (0..count).collect();
            let (prev, next) = keyset_page(&mut rows, paged, backward, per_page, |&row| row);
            (rows, prev, next)
        };
        // First forward page: no predecessor, a successor while the
        // over-fetch saw one.
        assert_eq!(case(4, false, false, 3), (vec![0, 1, 2], None, Some(2)));
        // A later forward page: the over-fetch saw nothing more.
        assert_eq!(case(3, true, false, 3), (vec![0, 1, 2], Some(0), None));
        // A page reached backwards keeps the rows right before the
        // cursor: the over-fetched row is the farthest one.
        assert_eq!(case(4, true, true, 3), (vec![1, 2, 3], Some(1), Some(3)));
        // A backwards page with nothing further back still has a
        // successor.
        assert_eq!(case(2, true, true, 3), (vec![0, 1], None, Some(1)));
    }

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

    /// A journal row without a byte count shows the neutral `common.na`
    /// placeholder, the same one every other card renders through
    /// `fmt_opt_bytes` — never a bare comma, which reads as markup, not
    /// as a missing value. A present size still goes through the shared
    /// byte formatter.
    #[test]
    fn the_bytes_cell_shows_the_neutral_placeholder_when_the_size_is_missing() {
        let lang = Locales::load(Path::new("/nonexistent-locales-dir")).resolve("en");
        let template = FetchLogsTemplate {
            lang,
            langs: Vec::new(),
            theme: Theme::default(),
            active: "",
            csrf: String::new(),
            rows: Vec::new(),
            total: 0,
            nav_first: None,
            nav_prev: None,
            nav_next: None,
            f_result: String::new(),
            f_source: String::new(),
            sources: Vec::new(),
            error_classes: Vec::new(),
        };
        assert_eq!(template.bytes(&None), template.lang.t("common.na"));
        assert_eq!(template.bytes(&Some(2048)), "2.0 KB");
    }
}
