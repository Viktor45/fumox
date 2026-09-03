//! Admin panel protection: HMAC-signed session cookies, CSRF tokens and
//! per-IP rate limiting (ADMIN_PLAN §3).
//!
//! The session key is derived from `[admin].token`, so rotating the token
//! instantly revokes every session (ADMIN_PLAN §13.1, decision 2). The
//! panel is single-user by design; there is no user table.

use crate::admin::AdminState;
use crate::admin::i18n::{self, Lang};
use crate::admin::theme::{self, Theme};
use askama::Template;
use axum::extract::{ConnectInfo, Form, Query, Request, State};
use axum::http::{Method, StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Redirect, Response};
use hmac::{Hmac, KeyInit, Mac};
use moka::future::Cache;
use sha2::Sha256;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

/// Session cookie name.
pub const SESSION_COOKIE: &str = "fumox_session";
/// Upper bound for buffered POST bodies (CSRF inspection).
const MAX_BODY_BYTES: usize = 1 << 20;

/// Derive a 32-byte key from the admin token and a purpose tag.
pub fn derive_key(purpose: &[u8], token: &str) -> Vec<u8> {
    use sha2::Digest;
    let mut hasher = sha2::Sha256::new();
    hasher.update(purpose);
    hasher.update(b"|");
    hasher.update(token.as_bytes());
    hasher.finalize().to_vec()
}

fn mac_hex(key: &[u8], message: &str) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(message.as_bytes());
    let bytes = mac.finalize().into_bytes();
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

/// Constant-time string equality (cookie/CSRF comparison). Also used for
/// the public capability-token checks (`/sub` access token, alive-export
/// link) so every secret comparison goes through one implementation.
pub(crate) fn ct_eq(a: &str, b: &str) -> bool {
    let (ab, bb) = (a.as_bytes(), b.as_bytes());
    if ab.len() != bb.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in ab.iter().zip(bb) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Mint a session cookie value: `{expires_unix}.{hmac(expires_unix)}`.
pub fn issue_session(key: &[u8], ttl: Duration) -> String {
    let expires = fumox_core::models::now_ts() + ttl.as_secs() as i64;
    format!("{expires}.{}", mac_hex(key, &expires.to_string()))
}

/// Verify a session cookie value; returns the expiry timestamp when valid.
pub fn verify_session(key: &[u8], value: &str) -> Option<i64> {
    let (expires, provided) = value.split_once('.')?;
    let expires_ts: i64 = expires.parse().ok()?;
    if expires_ts <= fumox_core::models::now_ts() {
        return None;
    }
    ct_eq(&mac_hex(key, expires), provided).then_some(expires_ts)
}

/// CSRF token bound to the session cookie value; deterministic, so no
/// server-side storage is needed.
pub fn csrf_token(csrf_key: &[u8], session_value: &str) -> String {
    mac_hex(csrf_key, session_value)
}

/// Extract the session cookie from `Cookie` headers.
pub fn session_cookie_value(headers: &axum::http::HeaderMap) -> Option<String> {
    for cookie_header in headers.get_all(header::COOKIE).iter() {
        let Ok(text) = cookie_header.to_str() else {
            continue;
        };
        for pair in text.split(';') {
            if let Some((name, value)) = pair.trim().split_once('=')
                && name.trim() == SESSION_COOKIE
            {
                return Some(value.trim().to_string());
            }
        }
    }
    None
}

/// Fixed-window per-key rate limiter: counters live in a moka cache with
/// TTL = window, so expiry resets the window.
pub struct RateLimiter {
    counters: Cache<String, Arc<AtomicU64>>,
    limit: u64,
}

impl RateLimiter {
    pub fn new(limit: u64, window: Duration) -> Self {
        Self {
            counters: Cache::builder()
                .max_capacity(100_000)
                .time_to_live(window)
                .build(),
            limit,
        }
    }

    /// Count one hit for `key`; `true` while under the limit.
    pub async fn allow(&self, key: &str) -> bool {
        // moka's future cache expects a future (not a closure) as the init.
        let init = async { Ok::<_, std::convert::Infallible>(Arc::new(AtomicU64::new(0))) };
        let Ok(counter) = self.counters.try_get_with(key.to_string(), init).await else {
            return true; // cache hiccup must not lock the admin out
        };
        counter.fetch_add(1, Ordering::Relaxed) < self.limit
    }
}

/// Outermost admin middleware: per-IP rate limiting. Login gets the hard
/// limit, everything else the soft one (ADMIN_PLAN §3).
pub async fn rate_limit(
    State(state): State<AdminState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    req: Request,
    next: Next,
) -> Response {
    let ip = addr.ip().to_string();
    let is_login = req.method() == Method::POST && req.uri().path() == "/admin/login";
    let limiter = if is_login {
        state.login_limiter.clone()
    } else {
        state.admin_limiter.clone()
    };
    if !limiter.allow(&ip).await {
        tracing::warn!(ip = %ip, path = %req.uri(), "admin rate limit exceeded");
        let lang = state.locales.lang_from_headers(req.headers());
        return (
            StatusCode::TOO_MANY_REQUESTS,
            [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
            format!("{}\n", lang.t("err.rate_limited")),
        )
            .into_response();
    }
    next.run(req).await
}

/// Authentication gate for `/admin/*` (except login/static). Browsers are
/// redirected; HTMX requests get an `HX-Redirect` so the whole page
/// transitions to the login screen.
pub async fn require_auth(State(state): State<AdminState>, req: Request, next: Next) -> Response {
    let authenticated = session_cookie_value(req.headers())
        .and_then(|value| verify_session(&state.session_key, &value))
        .is_some();
    if authenticated {
        return next.run(req).await;
    }
    if req.headers().get("HX-Request").is_some() {
        return (StatusCode::UNAUTHORIZED, [("HX-Redirect", "/admin/login")]).into_response();
    }
    Redirect::to("/admin/login").into_response()
}

/// CSRF protection for every admin POST: the `_csrf` form field must match
/// the token derived from the session cookie. The body is buffered,
/// inspected and re-attached so handlers still see it.
pub async fn csrf_protect(State(state): State<AdminState>, req: Request, next: Next) -> Response {
    if req.method() != Method::POST {
        return next.run(req).await;
    }
    let lang = state.locales.lang_from_headers(req.headers());
    let session = session_cookie_value(req.headers()).unwrap_or_default();
    let expected = csrf_token(&state.csrf_key, &session);

    let (parts, body) = req.into_parts();
    let Ok(bytes) = axum::body::to_bytes(body, MAX_BODY_BYTES).await else {
        return plain(StatusCode::BAD_REQUEST, lang.t("err.body_too_large"));
    };
    let provided = form_field(&bytes, "_csrf").unwrap_or_default();
    let req = Request::from_parts(parts, axum::body::Body::from(bytes));

    if !ct_eq(&expected, &provided) {
        tracing::warn!(path = %req.uri(), "CSRF check failed");
        return plain(StatusCode::FORBIDDEN, lang.t("err.csrf_failed"));
    }
    next.run(req).await
}

#[derive(serde::Deserialize)]
pub struct LoginForm {
    #[serde(default)]
    token: String,
}

#[derive(Template)]
#[template(path = "login.html")]
struct LoginTemplate {
    lang: Lang,
    /// `(code, native name)` pairs for the language switcher.
    langs: Vec<(String, String)>,
    /// Active interface theme (rendered as `data-theme` on `<html>`).
    theme: Theme,
    error: Option<String>,
}

i18n::impl_i18n!(LoginTemplate);

/// Login screen. The `?lang=` query parameter selects the UI language and
/// persists it in the `fumox_lang` cookie; without it the cookie decides
/// (Russian by default).
pub async fn login_form(
    State(state): State<AdminState>,
    headers: axum::http::HeaderMap,
    Query(params): Query<HashMap<String, String>>,
) -> Response {
    let (lang, set_cookie) = match params.get("lang") {
        Some(value) => {
            let lang = state.locales.resolve(value);
            let cookie = i18n::lang_cookie(lang.code());
            (lang, Some(cookie))
        }
        None => (state.locales.lang_from_headers(&headers), None),
    };
    let template = LoginTemplate {
        langs: state.locales.choices().to_vec(),
        theme: theme::from_headers(&headers),
        lang,
        error: None,
    };
    let mut response = crate::admin::render_html(template.lang.clone(), &template, StatusCode::OK);
    if let Some(cookie) = set_cookie
        && let Ok(value) = cookie.parse()
    {
        response.headers_mut().insert(header::SET_COOKIE, value);
    }
    response
}

pub async fn login_submit(
    State(state): State<AdminState>,
    headers: axum::http::HeaderMap,
    Form(form): Form<LoginForm>,
) -> Response {
    let lang = state.locales.lang_from_headers(&headers);
    // The empty token disables the panel entirely; never match it.
    if !state.admin.token.is_empty() && ct_eq(&form.token, &state.admin.token) {
        let ttl = state.session_ttl();
        let value = issue_session(&state.session_key, ttl);
        let mut cookie = format!(
            "{SESSION_COOKIE}={value}; Path=/; HttpOnly; SameSite=Lax; Max-Age={}",
            ttl.as_secs()
        );
        if state.admin.secure_cookies {
            cookie.push_str("; Secure");
        }
        tracing::info!("admin logged in");
        return (
            StatusCode::SEE_OTHER,
            [
                (header::SET_COOKIE, cookie),
                (header::LOCATION, "/admin".to_string()),
            ],
        )
            .into_response();
    }
    tracing::warn!("failed admin login attempt");
    let error = lang.t("login.bad_token").to_string();
    let template = LoginTemplate {
        langs: state.locales.choices().to_vec(),
        theme: theme::from_headers(&headers),
        lang,
        error: Some(error),
    };
    crate::admin::render_html(
        template.lang.clone(),
        &template,
        StatusCode::UNPROCESSABLE_ENTITY,
    )
}

/// Language switch: persists the choice in the `fumox_lang` cookie and
/// redirects back to `next` (restricted to `/admin` paths, so no open
/// redirect). Mounted outside the auth/CSRF layers so it works pre-auth.
pub async fn set_lang(
    State(state): State<AdminState>,
    Query(params): Query<HashMap<String, String>>,
) -> Response {
    let lang = params
        .get("lang")
        .map(|value| state.locales.resolve(value))
        .unwrap_or_else(|| state.locales.default_lang());
    let next = params
        .get("next")
        .map(String::as_str)
        .filter(|next| next.starts_with("/admin"))
        .unwrap_or("/admin");
    (
        StatusCode::SEE_OTHER,
        [
            (header::SET_COOKIE, i18n::lang_cookie(lang.code())),
            (header::LOCATION, next.to_string()),
        ],
    )
        .into_response()
}

pub async fn logout() -> Response {
    let cookie = format!("{SESSION_COOKIE}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0");
    (
        StatusCode::SEE_OTHER,
        [
            (header::SET_COOKIE, cookie),
            (header::LOCATION, "/admin/login".to_string()),
        ],
    )
        .into_response()
}

/// Find a urlencoded form field in a buffered body.
fn form_field(bytes: &[u8], name: &str) -> Option<String> {
    let text = std::str::from_utf8(bytes).ok()?;
    for pair in text.split('&') {
        let Some((key, value)) = pair.split_once('=') else {
            continue;
        };
        if percent_decode(key) == name {
            return Some(percent_decode(value));
        }
    }
    None
}

fn percent_decode(s: &str) -> String {
    percent_encoding::percent_decode_str(s)
        .decode_utf8_lossy()
        .into_owned()
}

fn plain(status: StatusCode, message: &str) -> Response {
    (
        status,
        [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
        format!("{message}\n"),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_round_trip_and_expiry() {
        let key = derive_key(b"test", "token");
        let value = issue_session(&key, Duration::from_secs(3600));
        assert!(verify_session(&key, &value).is_some());

        // Expired cookie is rejected.
        let expired = format!(
            "{}.{}",
            fumox_core::models::now_ts() - 10,
            mac_hex(&key, &(fumox_core::models::now_ts() - 10).to_string())
        );
        assert!(verify_session(&key, &expired).is_none());

        // Tampered signature is rejected.
        let mut tampered = value.clone();
        tampered.pop();
        assert!(verify_session(&key, &tampered).is_none());

        // A different key (rotated token) revokes the session.
        let other = derive_key(b"test", "rotated");
        assert!(verify_session(&other, &value).is_none());
    }

    #[test]
    fn csrf_token_depends_on_session() {
        let key = derive_key(b"csrf", "token");
        let a = csrf_token(&key, "session-a");
        let b = csrf_token(&key, "session-b");
        assert_ne!(a, b);
        assert_eq!(a, csrf_token(&key, "session-a"));
    }

    #[test]
    fn cookie_header_parsing() {
        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            header::COOKIE,
            "other=1; fumox_session=abc.def; third=x".parse().unwrap(),
        );
        assert_eq!(session_cookie_value(&headers).as_deref(), Some("abc.def"));
        assert_eq!(session_cookie_value(&axum::http::HeaderMap::new()), None);
    }

    #[test]
    fn form_field_extraction() {
        let body = b"_csrf=abc123&name=foo%20bar&empty=";
        assert_eq!(form_field(body, "_csrf").as_deref(), Some("abc123"));
        assert_eq!(form_field(body, "name").as_deref(), Some("foo bar"));
        assert_eq!(form_field(body, "empty").as_deref(), Some(""));
        assert_eq!(form_field(body, "missing"), None);
    }

    #[tokio::test]
    async fn rate_limiter_enforces_limit_then_resets() {
        let limiter = RateLimiter::new(3, Duration::from_secs(60));
        assert!(limiter.allow("ip1").await);
        assert!(limiter.allow("ip1").await);
        assert!(limiter.allow("ip1").await);
        assert!(!limiter.allow("ip1").await);
        // Other keys are independent.
        assert!(limiter.allow("ip2").await);
    }
}
