//! Admin panel protection: HMAC-signed session cookies, CSRF tokens and
//! per-IP rate limiting.
//!
//! The session key is derived from `[admin].token`, so rotating the token
//! across a restart instantly revokes every session. On top of it, a
//! server-side revocation epoch (a counter in the `meta` table) is mixed
//! into every session MAC and bumped on logout, so a copied cookie dies
//! there too instead of working until the TTL. The
//! panel is single-user by design; there is no user table.

use crate::admin::AdminState;
use crate::admin::i18n::{self, Lang};
use crate::admin::theme::{self, Theme};
use crate::security::{client_key, ct_eq};
use askama::Template;
use axum::extract::{ConnectInfo, Form, Query, Request, State};
use axum::http::{HeaderMap, Method, StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Redirect, Response};
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use std::collections::HashMap;
use std::net::SocketAddr;
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
    use std::fmt::Write as _;
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(message.as_bytes());
    let bytes = mac.finalize().into_bytes();
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(out, "{b:02x}");
    }
    out
}

/// `meta` key holding the session-revocation epoch, written by
/// [`revoke_all_sessions`].
const SESSION_EPOCH_KEY: &str = "admin_session_epoch";

/// The current session-revocation epoch, persisted in `meta`. Session
/// cookies are MACed over this value ([`epoch_session_key`]), so bumping
/// it invalidates every cookie minted before the bump without touching
/// `[admin].token`. 0 until the first bump (nothing has been revoked yet).
///
/// Read on every session check instead of cached per process: one indexed
/// SELECT on the tiny `meta` table is noise next to a panel request, and a
/// per-process cache would go stale against the source of truth the moment
/// anything but this process writes the row. A read error yields 0 without
/// failing the request — a stricter epoch, never a looser one, so live
/// cookies either verify as usual or fail closed (the panel is useless
/// with the database down anyway).
async fn session_epoch(pool: &fumox_core::db::DbPool) -> u64 {
    match fumox_core::repo::meta_get(pool, SESSION_EPOCH_KEY).await {
        Ok(Some(value)) => value.trim().parse().unwrap_or(0),
        Ok(None) => 0,
        Err(err) => {
            tracing::warn!(error = %err, "cannot read the session epoch; failing closed to 0");
            0
        }
    }
}

/// Bump the session-revocation epoch in `meta`: every cookie minted before
/// this call stops verifying. Called on logout and when the settings
/// screen rotates `[admin].token` (the session key itself is frozen at
/// startup, so the epoch is the only revocation that survives a
/// mid-run credential change). Returns `false` when the bump could not be
/// persisted (database error); the caller then still clears the cookie,
/// but a copy of it keeps working until the TTL or the next successful
/// bump.
pub(crate) async fn revoke_all_sessions(pool: &fumox_core::db::DbPool) -> bool {
    match fumox_core::repo::meta_increment(pool, SESSION_EPOCH_KEY).await {
        Ok(_) => true,
        Err(err) => {
            tracing::error!(
                error = %err,
                "cannot persist the session-epoch bump; cleared-cookie copies may stay valid"
            );
            false
        }
    }
}

/// Mix the revocation epoch into the effective session key with
/// `HMAC(session_key, epoch_be_bytes)`: a bump changes the effective key,
/// so every cookie minted before it stops verifying even though
/// `[admin].token` — and with it the stored session key — did not change.
/// This also rejects pre-epoch cookies, which MACed the bare session key:
/// they match no epoch, so upgrading costs one re-login.
fn epoch_session_key(key: &[u8], epoch: u64) -> Vec<u8> {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(&epoch.to_be_bytes());
    mac.finalize().into_bytes().to_vec()
}

/// Mint a session cookie value: `{expires_unix}.{hmac(epoch, expires_unix)}`
/// over the epoch-mixed session key. `epoch` must be the value
/// [`session_epoch`] returned for the request that issues the cookie.
pub fn issue_session(key: &[u8], ttl: Duration, epoch: u64) -> String {
    let expires = fumox_core::models::now_ts() + ttl.as_secs() as i64;
    format!(
        "{expires}.{}",
        mac_hex(&epoch_session_key(key, epoch), &expires.to_string())
    )
}

/// Verify a session cookie value; returns the expiry timestamp when valid.
/// `epoch` must be the current server-side epoch: a cookie minted under an
/// older one — before a logout bump — is rejected here.
pub fn verify_session(key: &[u8], value: &str, epoch: u64) -> Option<i64> {
    let (expires, provided) = value.split_once('.')?;
    let expires_ts: i64 = expires.parse().ok()?;
    if expires_ts <= fumox_core::models::now_ts() {
        return None;
    }
    ct_eq(&mac_hex(&epoch_session_key(key, epoch), expires), provided).then_some(expires_ts)
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

/// Trimmed header value as UTF-8, or nothing. Empty values carry no
/// signal either way.
fn header_str<'a>(headers: &'a HeaderMap, name: &'static str) -> Option<&'a str> {
    headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|v| !v.is_empty())
}

/// `(host, port)` of a `host[:port]` authority, IPv6-bracket aware.
/// `None` for anything outside that grammar — unparsable means "cannot
/// establish same-origin", which callers treat as the cross-site direction.
fn authority_parts(authority: &str) -> Option<(&str, Option<u16>)> {
    let authority = authority.trim();
    if let Some(rest) = authority.strip_prefix('[') {
        let end = rest.find(']')?;
        let (host, after) = (&rest[..end], &rest[end + 1..]);
        let port = after.strip_prefix(':').and_then(|p| p.parse().ok());
        return Some((host, port));
    }
    match authority.rsplit_once(':') {
        // host:port — the port side must be digits, else this is a bare
        // (unbracketed, technically illegal) IPv6 literal.
        Some((host, port))
            if !host.is_empty()
                && !host.contains(':')
                && !port.is_empty()
                && port.bytes().all(|b| b.is_ascii_digit()) =>
        {
            Some((host, Some(port.parse::<u16>().ok()?)))
        }
        _ => Some((authority, None)),
    }
}

/// Ports match when equal, or when one side is absent and the other spells
/// the scheme default: origin serialization omits default ports while a
/// proxy-written `Host` may spell them out.
fn same_port(a: Option<u16>, b: Option<u16>) -> bool {
    match (a, b) {
        (Some(x), Some(y)) => x == y,
        (None, None) => true,
        (None, Some(p)) | (Some(p), None) => p == 80 || p == 443,
    }
}

/// Same request authority, comparing host names case-insensitively. An
/// unparsable authority on either side cannot establish same-origin.
fn same_authority(a: &str, b: &str) -> bool {
    match (authority_parts(a), authority_parts(b)) {
        (Some((host_a, port_a)), Some((host_b, port_b))) => {
            host_a.eq_ignore_ascii_case(host_b) && same_port(port_a, port_b)
        }
        _ => false,
    }
}

/// Positive evidence that the request was issued from a cross-site context
/// — a web page on another origin driving the operator's browser.
///
/// Primary signal: the Fetch Metadata `Sec-Fetch-Site` header, set by the
/// browser itself and not forgeable from page scripts. Any value that is
/// not positively `cross-site` (same-origin, same-site, none, absent)
/// keeps the count-everything behavior. A cross-site *top-level GET
/// navigation* (`Sec-Fetch-Mode: navigate`, `Sec-Fetch-Dest: document`)
/// is the one cross-site shape that is not hostile: the operator following
/// a link from another page, cookie attached via SameSite=Lax, ending up
/// on the panel. It is processed and counted like a same-origin request.
///
/// Without Fetch Metadata (older browsers) the `Origin` header decides:
/// cross-origin GET navigations carry no Origin, so an Origin here is a
/// POST or a CORS-mode fetch — never a plain link click. `Origin: null`
/// (sandboxed frame, opaque origin) and an unparsable mismatch count as
/// cross-site. The comparison inherits the panel's existing assumption
/// that any reverse proxy preserves the `Host` header (`host_gate`,
/// `serve_base` build on it).
///
/// Absence of all signals — curl, health checks, monitoring — is not
/// evidence and never rejects.
fn cross_site_context(method: &Method, headers: &HeaderMap) -> bool {
    if let Some(site) = header_str(headers, "sec-fetch-site") {
        if !site.eq_ignore_ascii_case("cross-site") {
            return false;
        }
        return !(method == Method::GET
            && header_str(headers, "sec-fetch-mode")
                .is_some_and(|m| m.eq_ignore_ascii_case("navigate"))
            && header_str(headers, "sec-fetch-dest")
                .is_some_and(|d| d.eq_ignore_ascii_case("document")));
    }
    let Some(origin) = header_str(headers, "origin") else {
        return false;
    };
    if origin.eq_ignore_ascii_case("null") {
        return true;
    }
    // Origin is scheme://host[:port] only; scheme is not comparable against
    // the scheme-less Host header and a scheme mismatch alone never makes a
    // same-host request hostile.
    let Some((_, authority)) = origin.split_once("://") else {
        return true;
    };
    let authority = authority.split(['/', '?']).next().unwrap_or(authority);
    match header_str(headers, "host") {
        Some(host) => !same_authority(authority, host),
        None => true,
    }
}

/// Outermost admin middleware: per-IP rate limiting. Login gets the hard
/// limit, everything else the soft one.
///
/// `/admin/static/*` (the vendored CSS/htmx assets) and HEAD requests are
/// exempt: they carry no state and answer identically for everyone, but
/// each would otherwise burn the same per-IP window as a panel action, a
/// page referencing them re-opens after a burst of fragment loads could be
/// pushed to 429 by asset fetches alone, and an anonymous passer-by could
/// exhaust someone else's NAT-shared window with cheap GETs of the CSS.
///
/// Cross-site requests are rejected *without counting*: the windows exist
/// to cap the operator's own panel usage and login brute-force, and before
/// this gate any web page the operator visited could pin their IP at the
/// 429 ceiling with auto-issued cross-site requests. Same-site and
/// same-origin requests keep counting.
pub async fn rate_limit(
    State(state): State<AdminState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    req: Request,
    next: Next,
) -> Response {
    let path = req.uri().path();
    if req.method() == Method::HEAD || path.starts_with("/admin/static/") {
        return next.run(req).await;
    }
    if cross_site_context(req.method(), req.headers()) {
        tracing::warn!(path = %path, "cross-site admin request rejected without counting");
        let lang = state.locales.lang_from_headers(req.headers());
        return plain(StatusCode::FORBIDDEN, lang.t("err.cross_site"));
    }
    let ip = client_key(addr, req.headers(), &state.trusted_cidrs).to_string();
    let is_login = req.method() == Method::POST && path == "/admin/login";
    let limiter = if is_login {
        state.login_limiter.clone()
    } else {
        state.admin_limiter.clone()
    };
    if !limiter.allow(&ip).await {
        tracing::warn!(ip = %ip, path = %path, "admin rate limit exceeded");
        let lang = state.locales.lang_from_headers(req.headers());
        return (
            StatusCode::TOO_MANY_REQUESTS,
            [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
            format!("{}\n", lang.t("err.rate_limited")),
        )
            .into_response();
    }
    // The failed-login attribution below runs after `req` is consumed;
    // keep owned copies of the request identity for it.
    let method = req.method().clone();
    let path = path.to_owned();
    let response = next.run(req).await;
    // A rejected response was already punished by a stricter limiter (the
    // login one) or is not this layer's business at all: the outer window
    // must not pay for it twice.
    if response.status() == StatusCode::TOO_MANY_REQUESTS {
        limiter.refund(&ip).await;
    }
    // A failed login is the panel's primary brute-force audit signal, but
    // the handler never sees the client address (it extracts no
    // ConnectInfo). Attribute the 422 it renders to its source here, where
    // the per-IP key is already computed; the 429 warn above only covers
    // the exhausted-window case.
    if is_login && response.status() == StatusCode::UNPROCESSABLE_ENTITY {
        tracing::warn!(ip = %ip, method = %method, path = %path, "failed admin login attempt");
    }
    response
}

/// Authentication gate for `/admin/*` (except login/static). Browsers are
/// redirected; HTMX requests get an `HX-Redirect` so the whole page
/// transitions to the login screen.
pub async fn require_auth(State(state): State<AdminState>, req: Request, next: Next) -> Response {
    let epoch = session_epoch(&state.pool).await;
    let authenticated = session_cookie_value(req.headers())
        .and_then(|value| verify_session(&state.session_key, &value, epoch))
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
    // The empty token disables the panel entirely; never match it. The
    // token comes from the live config, so a value saved on the settings
    // screen is enforced on the next login without a restart.
    let admin = state.admin();
    if !admin.token.is_empty() && ct_eq(&form.token, &admin.token) {
        let ttl = state.session_ttl();
        let epoch = session_epoch(&state.pool).await;
        let value = issue_session(&state.session_key, ttl, epoch);
        let mut cookie = format!(
            "{SESSION_COOKIE}={value}; Path=/; HttpOnly; SameSite=Lax; Max-Age={}",
            ttl.as_secs()
        );
        if admin.secure_cookies {
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
/// redirects back to `next` (validated by `super::admin_next`, admin-surface
/// paths only, no open redirect). Mounted outside the auth/CSRF layers so it
/// works pre-auth.
pub async fn set_lang(
    State(state): State<AdminState>,
    Query(params): Query<HashMap<String, String>>,
) -> Response {
    let lang = params
        .get("lang")
        .map(|value| state.locales.resolve(value))
        .unwrap_or_else(|| state.locales.default_lang());
    let next = super::admin_next(&params);
    (
        StatusCode::SEE_OTHER,
        [
            (header::SET_COOKIE, i18n::lang_cookie(lang.code())),
            (header::LOCATION, next),
        ],
    )
        .into_response()
}

/// Log out: clear the cookie *and* bump the server-side session epoch, so
/// the exact cookie value — and every other cookie minted under the same
/// epoch, a stolen copy included — stops verifying immediately instead of
/// working until the TTL. The handler is mounted inside the protected
/// nest, so only an authenticated POST carrying the CSRF token can spend a
/// bump. One global epoch, one bump: logging out in one browser also ends
/// any other browser's session — the accepted cost for a single-user panel
/// whose only alternative is leaving every session irrevocable.
pub async fn logout(State(state): State<AdminState>) -> Response {
    revoke_all_sessions(&state.pool).await;
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
    use tower::ServiceExt;

    const TOKEN: &str = "test-admin-token";

    #[test]
    fn session_round_trip_and_expiry() {
        let key = derive_key(b"test", "token");
        let value = issue_session(&key, Duration::from_secs(3600), 0);
        assert!(verify_session(&key, &value, 0).is_some());

        // Expired cookie is rejected.
        let expired = format!(
            "{}.{}",
            fumox_core::models::now_ts() - 10,
            mac_hex(
                &epoch_session_key(&key, 0),
                &(fumox_core::models::now_ts() - 10).to_string()
            )
        );
        assert!(verify_session(&key, &expired, 0).is_none());

        // Tampered signature is rejected.
        let mut tampered = value.clone();
        tampered.pop();
        assert!(verify_session(&key, &tampered, 0).is_none());

        // A different key (rotated token) revokes the session.
        let other = derive_key(b"test", "rotated");
        assert!(verify_session(&other, &value, 0).is_none());
    }

    /// f18: the epoch is server-side revocation state. A bump between issue
    /// and verify kills the cookie even though the token — and with it the
    /// session key — is unchanged, in either direction, and a pre-epoch
    /// cookie (MACed over the bare session key, the format before the epoch
    /// existed) verifies under no epoch at all.
    #[test]
    fn epoch_bump_revokes_the_session_without_a_token_change() {
        let key = derive_key(b"test", "token");
        let value = issue_session(&key, Duration::from_secs(3600), 3);
        assert!(verify_session(&key, &value, 3).is_some());
        assert!(
            verify_session(&key, &value, 4).is_none(),
            "a cookie from before the bump must not verify under the new epoch"
        );
        assert!(
            verify_session(&key, &value, 2).is_none(),
            "an older epoch must not verify either"
        );

        // Pre-epoch cookie shape: HMAC over the bare session key.
        let expires = fumox_core::models::now_ts() + 3600;
        let legacy = format!("{expires}.{}", mac_hex(&key, &expires.to_string()));
        assert!(
            verify_session(&key, &legacy, 0).is_none(),
            "pre-epoch cookies must not survive the epoch scheme"
        );
    }

    /// f18 end to end: logout bumps the persisted epoch, so the cookie the
    /// browser held — a stolen copy included — stops authenticating, and a
    /// fresh login under the new epoch works again.
    /// Build a request with the `ConnectInfo` extension the rate limiter
    /// extracts; a real listener attaches it via
    /// `into_make_service_with_connect_info`.
    fn request(
        method: &str,
        uri: &str,
        body: &str,
        cookie: Option<&str>,
    ) -> axum::extract::Request {
        let mut builder = axum::http::Request::builder()
            .method(method)
            .uri(uri)
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .extension(ConnectInfo::<SocketAddr>(
                "127.0.0.1:41000".parse().unwrap(),
            ));
        if let Some(cookie) = cookie {
            builder = builder.header(header::COOKIE, cookie);
        }
        builder
            .body(axum::body::Body::from(body.to_string()))
            .unwrap()
    }

    /// The `name=value` pair of the session `Set-Cookie` header.
    fn cookie_from(response: &axum::response::Response) -> String {
        response
            .headers()
            .get(header::SET_COOKIE)
            .unwrap()
            .to_str()
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .to_string()
    }

    /// The bare value of a `name=value` cookie pair.
    fn cookie_value(pair: &str) -> &str {
        pair.split_once('=').unwrap().1
    }

    #[tokio::test]
    async fn logout_bumps_the_epoch_and_revokes_the_session() {
        let (_dir, state) = crate::admin::test_admin_state(
            fumox_core::config::AdminConfig {
                enabled: true,
                token: TOKEN.to_string(),
                ..Default::default()
            },
            Default::default(),
        )
        .await;
        let app = crate::admin::router(state.clone());

        let response = app
            .clone()
            .oneshot(request(
                "POST",
                "/admin/login",
                &format!("token={TOKEN}"),
                None,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        let cookie = cookie_from(&response);

        // The session authenticates.
        let response = app
            .clone()
            .oneshot(request("GET", "/admin", "", Some(&cookie)))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        // Logout, carrying the CSRF token the login form ships.
        let csrf = csrf_token(&state.csrf_key, cookie_value(&cookie));
        let response = app
            .clone()
            .oneshot(request(
                "POST",
                "/admin/logout",
                &format!("_csrf={csrf}"),
                Some(&cookie),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SEE_OTHER);

        // The old cookie no longer authenticates.
        let response = app
            .clone()
            .oneshot(request("GET", "/admin", "", Some(&cookie)))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        assert_eq!(
            response.headers().get(header::LOCATION).unwrap(),
            "/admin/login"
        );

        // The bump is persisted, so it outlives the process that made it.
        let stored = fumox_core::repo::meta_get(&state.pool, SESSION_EPOCH_KEY)
            .await
            .unwrap();
        assert_eq!(stored.as_deref(), Some("1"));

        // A fresh login under the bumped epoch authenticates again.
        let response = app
            .clone()
            .oneshot(request(
                "POST",
                "/admin/login",
                &format!("token={TOKEN}"),
                None,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        let fresh = cookie_from(&response);
        let response = app
            .oneshot(request("GET", "/admin", "", Some(&fresh)))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    /// f18 end to end, token-change path: rotating `[admin].token` through
    /// the settings screen bumps the persisted epoch, so the cookie the
    /// browser held — a stolen copy included — stops authenticating even
    /// though the startup-frozen session key did not change, while a save
    /// that leaves the token untouched neither bumps nor logs the
    /// operator out. A fresh login under the rotated token works again.
    #[tokio::test]
    async fn token_rotation_through_settings_bumps_the_epoch_and_revokes_the_session() {
        // The settings editor writes back to this scratch file, and the
        // live config is refreshed from it after every save.
        let config_dir = fumox_core::tempdir_lite::TempDir::new("settings-rotate");
        let config_path = config_dir.path().join("app.toml");
        std::fs::write(
            &config_path,
            "[server]\nbind = \"0.0.0.0:8080\"\n[admin]\nenabled = true\ntoken = \"test-admin-token\"\n[probe]\nfail_limit = 3\n",
        )
        .unwrap();
        let (_dir, mut state) = crate::admin::test_admin_state(
            fumox_core::config::AdminConfig {
                enabled: true,
                token: TOKEN.to_string(),
                ..Default::default()
            },
            Default::default(),
        )
        .await;
        state.config_path = fumox_core::config::ResolvedConfigPath::Loaded(config_path);
        state.config_writable = fumox_core::config_writer::is_writable(config_dir.path());
        let app = crate::admin::router(state.clone());

        let response = app
            .clone()
            .oneshot(request(
                "POST",
                "/admin/login",
                &format!("token={TOKEN}"),
                None,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        let cookie = cookie_from(&response);

        // A save that leaves the token unchanged must neither bump the
        // epoch nor revoke the session performing it.
        let csrf = csrf_token(&state.csrf_key, cookie_value(&cookie));
        let response = app
            .clone()
            .oneshot(request(
                "POST",
                "/admin/settings/update",
                &format!("admin.token={TOKEN}&_csrf={csrf}"),
                Some(&cookie),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        let stored = fumox_core::repo::meta_get(&state.pool, SESSION_EPOCH_KEY)
            .await
            .unwrap();
        assert_eq!(stored, None, "an unchanged token must not bump the epoch");
        let response = app
            .clone()
            .oneshot(request("GET", "/admin", "", Some(&cookie)))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        // Rotate the token through the settings screen.
        const ROTATED: &str = "rotated-admin-token";
        let response = app
            .clone()
            .oneshot(request(
                "POST",
                "/admin/settings/update",
                &format!("admin.token={ROTATED}&_csrf={csrf}"),
                Some(&cookie),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SEE_OTHER);

        // The old cookie no longer authenticates.
        let response = app
            .clone()
            .oneshot(request("GET", "/admin", "", Some(&cookie)))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        assert_eq!(
            response.headers().get(header::LOCATION).unwrap(),
            "/admin/login"
        );

        // The bump is persisted, so it outlives the process that made it.
        let stored = fumox_core::repo::meta_get(&state.pool, SESSION_EPOCH_KEY)
            .await
            .unwrap();
        assert_eq!(stored.as_deref(), Some("1"));

        // The rotation landed in the live config: the old token is dead,
        // the rotated one logs in and the fresh session authenticates.
        let response = app
            .clone()
            .oneshot(request(
                "POST",
                "/admin/login",
                &format!("token={TOKEN}"),
                None,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
        let response = app
            .clone()
            .oneshot(request(
                "POST",
                "/admin/login",
                &format!("token={ROTATED}"),
                None,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        let fresh = cookie_from(&response);
        let response = app
            .oneshot(request("GET", "/admin", "", Some(&fresh)))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    /// f19: the cross-site verdict per header shape. Every "false" keeps
    /// the old count-and-process behavior; every "true" rejects without
    /// counting.
    #[test]
    fn cross_site_context_classification() {
        let get = Method::GET;
        let post = Method::POST;
        let none = HeaderMap::new();

        // No signals at all (curl, health checks): not cross-site.
        assert!(!cross_site_context(&get, &none));

        // Fetch Metadata, non-cross-site values keep counting.
        let site = |value: &str| {
            let mut h = HeaderMap::new();
            h.insert("sec-fetch-site", value.parse().unwrap());
            h
        };
        assert!(!cross_site_context(&get, &site("same-origin")));
        assert!(!cross_site_context(&get, &site("same-site")));
        assert!(!cross_site_context(&get, &site("none")));
        assert!(!cross_site_context(&post, &site("same-origin")));

        // Cross-site fetch/XHR and subresource loads: reject.
        let cross_fetch = |mode: &str, dest: &str| {
            let mut h = HeaderMap::new();
            h.insert("sec-fetch-site", "cross-site".parse().unwrap());
            h.insert("sec-fetch-mode", mode.parse().unwrap());
            h.insert("sec-fetch-dest", dest.parse().unwrap());
            h
        };
        assert!(cross_site_context(&get, &cross_fetch("cors", "empty")));
        assert!(cross_site_context(&get, &cross_fetch("no-cors", "image")));
        // An iframe navigation is not a top-level one.
        assert!(cross_site_context(&get, &cross_fetch("navigate", "iframe")));
        // A cross-site form POST navigation is the CSRF shape, even though
        // it navigates a top-level document.
        assert!(cross_site_context(
            &post,
            &cross_fetch("navigate", "document")
        ));
        // Metadata ships as a set: a cross-site claim without mode/dest is
        // not exempted as a navigation.
        let mut h = HeaderMap::new();
        h.insert("sec-fetch-site", "cross-site".parse().unwrap());
        assert!(cross_site_context(&get, &h));

        // The one exempt shape: the operator following a link from another
        // page, a top-level GET navigation.
        assert!(!cross_site_context(
            &get,
            &cross_fetch("navigate", "document")
        ));

        // Origin fallback (no Fetch Metadata, older browsers).
        let mut h = HeaderMap::new();
        h.insert("origin", "https://panel.example.com".parse().unwrap());
        h.insert("host", "panel.example.com".parse().unwrap());
        assert!(!cross_site_context(&post, &h), "matching origin counts");

        // Default-port spelling differences are the same origin.
        let mut h = HeaderMap::new();
        h.insert("origin", "https://panel.example.com".parse().unwrap());
        h.insert("host", "panel.example.com:443".parse().unwrap());
        assert!(!cross_site_context(&post, &h));
        let mut h = HeaderMap::new();
        h.insert("origin", "http://localhost:8081".parse().unwrap());
        h.insert("host", "localhost:8081".parse().unwrap());
        assert!(!cross_site_context(&post, &h));
        // Host names compare case-insensitively.
        let mut h = HeaderMap::new();
        h.insert("origin", "https://Panel.Example.com".parse().unwrap());
        h.insert("host", "panel.example.com".parse().unwrap());
        assert!(!cross_site_context(&post, &h));
        // Bracketed IPv6 literals with ports.
        let mut h = HeaderMap::new();
        h.insert("origin", "http://[::1]:8081".parse().unwrap());
        h.insert("host", "[::1]:8081".parse().unwrap());
        assert!(!cross_site_context(&post, &h));

        // A different origin (host or effective port) is cross-site.
        let mut h = HeaderMap::new();
        h.insert("origin", "https://evil.example".parse().unwrap());
        h.insert("host", "panel.example.com".parse().unwrap());
        assert!(cross_site_context(&post, &h));
        let mut h = HeaderMap::new();
        h.insert("origin", "https://panel.example.com:8443".parse().unwrap());
        h.insert("host", "panel.example.com:8081".parse().unwrap());
        assert!(cross_site_context(&post, &h));
        // `Origin: null` (sandboxed frame) and unparsable origins.
        let mut h = HeaderMap::new();
        h.insert("origin", "null".parse().unwrap());
        h.insert("host", "panel.example.com".parse().unwrap());
        assert!(cross_site_context(&post, &h));
        let mut h = HeaderMap::new();
        h.insert("origin", "evil.example".parse().unwrap());
        h.insert("host", "panel.example.com".parse().unwrap());
        assert!(cross_site_context(&post, &h));
        // Origin without a Host to compare against: cannot establish
        // same-origin.
        let mut h = HeaderMap::new();
        h.insert("origin", "https://panel.example.com".parse().unwrap());
        assert!(cross_site_context(&post, &h));
    }

    /// f19 end to end: cross-site requests are rejected without charging
    /// the per-IP window, same-origin requests keep counting, and only a
    /// top-level GET navigation from another site is processed and counted.
    #[tokio::test]
    async fn cross_site_requests_do_not_burn_the_rate_limit_window() {
        let (_dir, state) = crate::admin::test_admin_state(
            fumox_core::config::AdminConfig {
                enabled: true,
                token: TOKEN.to_string(),
                rate_limit: fumox_core::config::RateLimit::new(2, Duration::from_secs(60)),
                login_rate_limit: fumox_core::config::RateLimit::new(100, Duration::from_secs(60)),
                ..Default::default()
            },
            Default::default(),
        )
        .await;
        let app = crate::admin::router(state);

        // An attacker page hammering the panel from the operator's browser:
        // every request is rejected and none of them touches the window.
        let cross_fetch = || {
            let mut req = request("GET", "/admin/login", "", None);
            let headers = req.headers_mut();
            headers.insert("sec-fetch-site", "cross-site".parse().unwrap());
            headers.insert("sec-fetch-mode", "cors".parse().unwrap());
            headers.insert("sec-fetch-dest", "empty".parse().unwrap());
            req
        };
        for _ in 0..5 {
            let response = app.clone().oneshot(cross_fetch()).await.unwrap();
            assert_eq!(response.status(), StatusCode::FORBIDDEN);
        }

        // Same-origin-shaped requests keep counting: the window is 2.
        let counted = || request("GET", "/admin/login", "", None);
        assert_eq!(
            app.clone().oneshot(counted()).await.unwrap().status(),
            StatusCode::OK
        );
        assert_eq!(
            app.clone().oneshot(counted()).await.unwrap().status(),
            StatusCode::OK
        );
        assert_eq!(
            app.clone().oneshot(counted()).await.unwrap().status(),
            StatusCode::TOO_MANY_REQUESTS
        );

        // Still 403, not 429: the cross-site requests never shared the
        // window they would have exhausted.
        let response = app.clone().oneshot(cross_fetch()).await.unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);

        // The navigation exemption only exempts from *rejection*, not from
        // counting: a top-level cross-site GET lands in the exhausted
        // window like any other request.
        let mut navigation = request("GET", "/admin/login", "", None);
        let headers = navigation.headers_mut();
        headers.insert("sec-fetch-site", "cross-site".parse().unwrap());
        headers.insert("sec-fetch-mode", "navigate".parse().unwrap());
        headers.insert("sec-fetch-dest", "document".parse().unwrap());
        let response = app.clone().oneshot(navigation).await.unwrap();
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    }

    /// f19 on the login window: only genuine login attempts consume it.
    /// A cross-site POST carrying an unrelated Origin is rejected at the
    /// rate-limit layer (the CSRF layer would reject it later, but the
    /// window must not pay), while a same-origin POST — the form the panel
    /// itself renders — counts and succeeds.
    #[tokio::test]
    async fn cross_site_login_post_does_not_consume_the_login_window() {
        let (_dir, state) = crate::admin::test_admin_state(
            fumox_core::config::AdminConfig {
                enabled: true,
                token: TOKEN.to_string(),
                ..Default::default()
            },
            Default::default(),
        )
        .await;
        let app = crate::admin::router(state);

        let evil = || {
            let mut req = request("POST", "/admin/login", "token=guess", None);
            let headers = req.headers_mut();
            headers.insert("origin", "https://evil.example".parse().unwrap());
            headers.insert("host", "panel.example.com".parse().unwrap());
            req
        };
        for _ in 0..10 {
            let response = app.clone().oneshot(evil()).await.unwrap();
            assert_eq!(response.status(), StatusCode::FORBIDDEN);
        }

        // The genuine form: same-origin POST counts once and succeeds with
        // the full login window behind it.
        let mut genuine = request("POST", "/admin/login", &format!("token={TOKEN}"), None);
        let headers = genuine.headers_mut();
        headers.insert("origin", "https://panel.example.com".parse().unwrap());
        headers.insert("host", "panel.example.com".parse().unwrap());
        let response = app.oneshot(genuine).await.unwrap();
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
    }

    /// A failed login is attributed to its source: the 422 the login
    /// handler renders is logged at warn with the per-IP key (the handler
    /// itself never sees the client address), while a successful login
    /// does not emit the failed-login line.
    #[tokio::test]
    async fn failed_login_attempt_is_logged_with_the_client_ip() {
        let (_dir, state) = crate::admin::test_admin_state(
            fumox_core::config::AdminConfig {
                enabled: true,
                token: TOKEN.to_string(),
                ..Default::default()
            },
            Default::default(),
        )
        .await;
        let app = crate::admin::router(state);

        // A writer funneling the subscriber's output into a shared buffer
        // (same trick as `fumox_core::logging` and the scheduler tests).
        struct Captured(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);
        impl std::io::Write for Captured {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                self.0.lock().unwrap().extend_from_slice(buf);
                Ok(buf.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let captured = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let make_writer = captured.clone();
        let subscriber = tracing_subscriber::fmt()
            .with_ansi(false)
            .with_max_level(tracing::Level::INFO)
            .with_writer(move || Captured(std::sync::Arc::clone(&make_writer)))
            .finish();
        let _guard = tracing::subscriber::set_default(subscriber);
        crate::admin::stabilize_callsite_interests();
        // A call site whose first execution predates this test may already
        // be cached as `never`; re-evaluate every call site against the
        // now-multi-dispatcher registry so the lines below are observable.
        tracing::callsite::rebuild_interest_cache();

        // A wrong token renders the 422 the middleware attributes.
        let response = app
            .clone()
            .oneshot(request("POST", "/admin/login", "token=wrong-guess", None))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
        // A correct token logs in; no failed-login line for it.
        let response = app
            .oneshot(request(
                "POST",
                "/admin/login",
                &format!("token={TOKEN}"),
                None,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        let logs = String::from_utf8(captured.lock().unwrap().clone()).unwrap();
        assert!(
            logs.contains("admin logged in"),
            "the successful login must still be logged: {logs}"
        );
        assert!(
            logs.lines()
                .any(|line| line.contains("failed admin login attempt")
                    && line.contains("ip=127.0.0.1")
                    && line.contains("method=POST")
                    && line.contains("path=/admin/login")),
            "the failed login must be logged with the client key: {logs}"
        );
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
}
