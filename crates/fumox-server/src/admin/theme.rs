//! Interface theme selection (day/night). The choice is persisted in a
//! plain `fumox_theme` cookie, mirroring the language cookie pattern in
//! `i18n.rs`: the server renders the selected theme as `data-theme` on
//! `<html>`, so switching works without JavaScript.

use axum::extract::Query;
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use std::collections::HashMap;

/// Theme cookie name.
pub const THEME_COOKIE: &str = "fumox_theme";
/// Cookie lifetime: one year, same as the language cookie.
const THEME_MAX_AGE_SECS: u64 = 365 * 24 * 3600;

/// Interface theme. The stylesheet maps every color through CSS custom
/// properties and flips the palette on `[data-theme="dark"]`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Theme {
    /// Day theme (the default).
    #[default]
    Light,
    /// Night theme.
    Dark,
}

impl Theme {
    /// Value rendered on `<html data-theme="...">` and in the cookie.
    pub fn as_str(self) -> &'static str {
        match self {
            Theme::Light => "light",
            Theme::Dark => "dark",
        }
    }

    pub fn is_dark(self) -> bool {
        matches!(self, Theme::Dark)
    }

    pub fn is_light(self) -> bool {
        matches!(self, Theme::Light)
    }

    /// Parse a cookie or query value; anything unrecognized falls back to
    /// the light theme.
    pub fn parse(value: &str) -> Theme {
        match value.trim() {
            "dark" => Theme::Dark,
            _ => Theme::Light,
        }
    }
}

/// Read the selected theme from the `fumox_theme` cookie (light when the
/// cookie is absent).
pub fn from_headers(headers: &axum::http::HeaderMap) -> Theme {
    for cookie_header in headers.get_all(header::COOKIE).iter() {
        let Ok(text) = cookie_header.to_str() else {
            continue;
        };
        for pair in text.split(';') {
            if let Some((name, value)) = pair.trim().split_once('=')
                && name.trim() == THEME_COOKIE
            {
                return Theme::parse(value.trim());
            }
        }
    }
    Theme::Light
}

/// `Set-Cookie` value persisting the theme choice.
pub fn theme_cookie(theme: Theme) -> String {
    format!(
        "{THEME_COOKIE}={}; Path=/; HttpOnly; SameSite=Lax; Max-Age={THEME_MAX_AGE_SECS}",
        theme.as_str()
    )
}

/// Theme switch: persists the choice in the `fumox_theme` cookie and
/// redirects back to `next` (restricted to `/admin` paths, so no open
/// redirect). Mounted outside the auth/CSRF layers so it also works on the
/// login screen.
pub async fn set_theme(Query(params): Query<HashMap<String, String>>) -> Response {
    let theme = params
        .get("theme")
        .map(|value| Theme::parse(value))
        .unwrap_or_default();
    let next = params
        .get("next")
        .map(String::as_str)
        .filter(|next| next.starts_with("/admin"))
        .unwrap_or("/admin");
    (
        StatusCode::SEE_OTHER,
        [
            (header::SET_COOKIE, theme_cookie(theme)),
            (header::LOCATION, next.to_string()),
        ],
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_recognizes_dark_and_defaults_to_light() {
        assert_eq!(Theme::parse("dark"), Theme::Dark);
        assert_eq!(Theme::parse(" dark "), Theme::Dark);
        assert_eq!(Theme::parse("light"), Theme::Light);
        assert_eq!(Theme::parse(""), Theme::Light);
        assert_eq!(Theme::parse("blue"), Theme::Light);
    }

    #[test]
    fn reading_the_theme_from_cookie_headers() {
        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            header::COOKIE,
            "other=1; fumox_theme=dark; fumox_lang=en".parse().unwrap(),
        );
        assert_eq!(from_headers(&headers), Theme::Dark);

        headers.insert(header::COOKIE, "fumox_theme=light".parse().unwrap());
        assert_eq!(from_headers(&headers), Theme::Light);

        // No cookie (or a garbled one) means the light theme.
        assert_eq!(from_headers(&axum::http::HeaderMap::new()), Theme::Light);
        let mut garbled = axum::http::HeaderMap::new();
        garbled.insert(header::COOKIE, "fumox_theme=neon".parse().unwrap());
        assert_eq!(from_headers(&garbled), Theme::Light);
    }

    #[test]
    fn theme_cookie_format() {
        let cookie = theme_cookie(Theme::Dark);
        assert!(cookie.starts_with("fumox_theme=dark;"));
        assert!(cookie.contains("HttpOnly"));
        assert!(cookie.contains("SameSite=Lax"));
    }
}
