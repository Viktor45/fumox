//! Interface theme selection (day/night/auto). The choice is persisted in
//! a plain `fumox_theme` cookie, mirroring the language cookie pattern in
//! `i18n.rs`: the server renders the selected theme as `data-theme` on
//! `<html>`, so switching works without JavaScript. `auto` (the default,
//! also what an unrecognized cookie value degrades to) follows the OS
//! setting through a `prefers-color-scheme` media query in
//! `static/app.css`; an explicit choice in the cookie pins it.

use axum::extract::Form;
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use std::collections::HashMap;

/// Theme cookie name.
pub const THEME_COOKIE: &str = "fumox_theme";

/// Interface theme. `Auto` is the default and follows the OS
/// `prefers-color-scheme`; the stylesheet maps every color through CSS
/// custom properties and flips the palette on `[data-theme="dark"]`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Theme {
    /// Follow the OS setting (the default).
    #[default]
    Auto,
    /// Day theme.
    Light,
    /// Night theme.
    Dark,
}

impl Theme {
    /// Value rendered on `<html data-theme="...">` and in the cookie.
    pub fn as_str(self) -> &'static str {
        match self {
            Theme::Auto => "auto",
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

    /// Parse a cookie or form value; anything unrecognized falls back to
    /// `auto`, the system preference.
    pub fn parse(value: &str) -> Theme {
        match value.trim() {
            "light" => Theme::Light,
            "dark" => Theme::Dark,
            _ => Theme::Auto,
        }
    }
}

/// Read the selected theme from the `fumox_theme` cookie (`auto` — the
/// system preference — when the cookie is absent or garbled).
pub fn from_headers(headers: &axum::http::HeaderMap) -> Theme {
    super::cookie_value(headers, THEME_COOKIE)
        .map(Theme::parse)
        .unwrap_or_default()
}

/// `Set-Cookie` value persisting the theme choice (shared builder in
/// `super`, the one source of the attributes and the lifetime).
pub fn theme_cookie(theme: Theme) -> String {
    super::preference_cookie(THEME_COOKIE, theme.as_str())
}

/// Theme switch: persists the choice in the `fumox_theme` cookie and
/// redirects back to `next` (restricted to `/admin` paths, so no open
/// redirect). Endpoint: `/admin/set-theme`, an authenticated POST under
/// the auth+CSRF nest (see the route group in `super::router`). The login
/// screen has no session yet and switches through `?theme=` on the login
/// form instead (`auth::login_form`), which sets the same cookie
/// server-side. A request without a `theme` field is answered with the
/// bare redirect: no choice made, no cookie pinned.
pub async fn set_theme(Form(params): Form<HashMap<String, String>>) -> Response {
    let Some(value) = params.get("theme") else {
        return (
            StatusCode::SEE_OTHER,
            [(header::LOCATION, super::admin_next(&params))],
        )
            .into_response();
    };
    let theme = Theme::parse(value);
    let next = super::admin_next(&params);
    (
        StatusCode::SEE_OTHER,
        [
            (header::SET_COOKIE, theme_cookie(theme)),
            (header::LOCATION, next),
        ],
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_recognizes_light_and_dark_and_defaults_to_auto() {
        assert_eq!(Theme::parse("light"), Theme::Light);
        assert_eq!(Theme::parse(" light "), Theme::Light);
        assert_eq!(Theme::parse("dark"), Theme::Dark);
        assert_eq!(Theme::parse(" dark "), Theme::Dark);
        // Anything else — an absent value, a garbled one — follows the
        // system preference instead of pinning a palette.
        assert_eq!(Theme::parse(""), Theme::Auto);
        assert_eq!(Theme::parse("blue"), Theme::Auto);
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

        // No cookie (or a garbled one) means the system preference.
        assert_eq!(from_headers(&axum::http::HeaderMap::new()), Theme::Auto);
        let mut garbled = axum::http::HeaderMap::new();
        garbled.insert(header::COOKIE, "fumox_theme=neon".parse().unwrap());
        assert_eq!(from_headers(&garbled), Theme::Auto);
    }

    #[test]
    fn theme_cookie_format() {
        let cookie = theme_cookie(Theme::Dark);
        assert!(cookie.starts_with("fumox_theme=dark;"));
        assert!(cookie.contains("HttpOnly"));
        assert!(cookie.contains("SameSite=Lax"));
        assert!(cookie.contains("Path=/"));
        assert!(cookie.contains("Max-Age=31536000"));
    }
}
