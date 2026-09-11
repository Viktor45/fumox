//! Configurable Top-N selector for the dashboard widgets.
//!
//! The choice is persisted in a plain `fumox_dash_top_n` cookie, mirroring
//! the language and theme cookies: the server reads the value from each
//! request, and the `?n=…` setter redirects back to the originating admin
//! page with a fresh `Set-Cookie`. Mirrors the `fumox_theme` pattern from
//! `theme.rs`.
//!
//! The only recognised values are `[5, 10, 15, 25, 50]` — anything else
//! (including `0`, negative numbers, non-numeric) collapses to the default
//! `10`. The dashboard widgets respect this limit when paging
//! `recent_errors`, `top_alive`, `top_failures`, and the country split.

use axum::extract::Query;
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use std::collections::HashMap;

/// Cookie name. Plain (not signed): the value only controls how many rows a
/// widget renders, never a security boundary.
pub const TOP_N_COOKIE: &str = "fumox_dash_top_n";

/// Cookie lifetime: one year, matching the language and theme cookies.
const TOP_N_MAX_AGE_SECS: u64 = 365 * 24 * 3600;

/// Allowed values for the picker. Order does not have to match the menu
/// order — the picker template iterates `ALLOWED` in declaration order.
pub const ALLOWED: &[i64] = &[5, 10, 15, 25, 50];

/// Default Top-N when the cookie is missing, garbled, or carries an
/// out-of-list value.
pub const DEFAULT: i64 = 10;

/// Strongly-typed wrapper so handler code cannot accidentally compare an
/// `i64` against the wrong domain. Callers pass `as_i64()` into SQL `LIMIT`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DashTopN(i64);

impl DashTopN {
    /// Build from a raw cookie value (parsed and validated against `ALLOWED`).
    pub fn parse(raw: &str) -> Self {
        let raw = raw.trim();
        if let Ok(n) = raw.parse::<i64>()
            && ALLOWED.contains(&n)
        {
            return DashTopN(n);
        }
        DashTopN(DEFAULT)
    }

    /// Numeric value, ready to bind to a SQL `LIMIT`.
    pub fn as_i64(self) -> i64 {
        self.0
    }
}

impl Default for DashTopN {
    fn default() -> Self {
        DashTopN(DEFAULT)
    }
}

/// Read the cookie value from a `HeaderMap`. Returns the default when the
/// cookie is missing or invalid.
pub fn from_headers(headers: &HeaderMap) -> DashTopN {
    for cookie_header in headers.get_all(header::COOKIE).iter() {
        let Ok(text) = cookie_header.to_str() else {
            continue;
        };
        for pair in text.split(';') {
            if let Some((name, value)) = pair.trim().split_once('=')
                && name.trim() == TOP_N_COOKIE
            {
                return DashTopN::parse(value.trim());
            }
        }
    }
    DashTopN::default()
}

/// `Set-Cookie` value persisting the choice.
pub fn top_n_cookie(value: DashTopN) -> String {
    format!(
        "{TOP_N_COOKIE}={}; Path=/; HttpOnly; SameSite=Lax; Max-Age={TOP_N_MAX_AGE_SECS}",
        value.as_i64()
    )
}

/// Top-N picker setter: persists the choice in the cookie and redirects back
/// to `next` (validated by `super::admin_next` — admin-surface paths only,
/// no open redirect, no control characters). Mounted outside the auth/CSRF
/// layers so the picker also works on a freshly installed system before the
/// operator has logged in.
pub async fn set_top_n(Query(params): Query<HashMap<String, String>>) -> Response {
    let n = DashTopN::parse(params.get("n").map(String::as_str).unwrap_or(""));
    let next = super::admin_next(&params);
    (
        StatusCode::SEE_OTHER,
        [
            (header::SET_COOKIE, top_n_cookie(n)),
            (header::LOCATION, next),
        ],
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_recognizes_allowed_values() {
        for n in ALLOWED {
            assert_eq!(DashTopN::parse(&n.to_string()).as_i64(), *n);
        }
    }

    #[test]
    fn parse_falls_back_to_default_for_invalid_input() {
        assert_eq!(DashTopN::parse("").as_i64(), DEFAULT);
        assert_eq!(DashTopN::parse("  ").as_i64(), DEFAULT);
        assert_eq!(DashTopN::parse("7").as_i64(), DEFAULT);
        assert_eq!(DashTopN::parse("100").as_i64(), DEFAULT);
        assert_eq!(DashTopN::parse("0").as_i64(), DEFAULT);
        assert_eq!(DashTopN::parse("-5").as_i64(), DEFAULT);
        assert_eq!(DashTopN::parse("abc").as_i64(), DEFAULT);
    }

    #[test]
    fn parse_tolerates_surrounding_whitespace() {
        assert_eq!(DashTopN::parse(" 25 ").as_i64(), 25);
        assert_eq!(DashTopN::parse("\t15\n").as_i64(), 15);
    }

    #[test]
    fn reading_the_cookie_from_request_headers() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::COOKIE,
            "other=1; fumox_dash_top_n=25; fumox_lang=en"
                .parse()
                .unwrap(),
        );
        assert_eq!(from_headers(&headers).as_i64(), 25);

        headers.insert(header::COOKIE, "fumox_dash_top_n=5".parse().unwrap());
        assert_eq!(from_headers(&headers).as_i64(), 5);

        // Garbled value falls back to the default.
        headers.insert(header::COOKIE, "fumox_dash_top_n=999".parse().unwrap());
        assert_eq!(from_headers(&headers).as_i64(), DEFAULT);

        // No cookie at all also yields the default.
        let empty = HeaderMap::new();
        assert_eq!(from_headers(&empty).as_i64(), DEFAULT);
    }

    #[test]
    fn top_n_cookie_round_trip() {
        let c = top_n_cookie(DashTopN(15));
        assert!(c.starts_with("fumox_dash_top_n=15;"));
        assert!(c.contains("HttpOnly"));
        assert!(c.contains("SameSite=Lax"));
        assert!(c.contains("Path=/"));
        assert!(c.contains("Max-Age=31536000"));
    }
}
