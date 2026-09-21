//! Admin panel protection: HMAC-signed session cookies, CSRF tokens and
//! per-IP rate limiting.
//!
//! The session key is derived from `[admin].token`, so rotating the token
//! instantly revokes every session. The
//! panel is single-user by design; there is no user table.

use crate::admin::AdminState;
use crate::admin::i18n::{self, Lang};
use crate::admin::theme::{self, Theme};
use askama::Template;
use axum::extract::{ConnectInfo, Form, Query, Request, State};
use axum::http::{HeaderMap, Method, StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Redirect, Response};
use hmac::{Hmac, KeyInit, Mac};
use moka::future::Cache;
use sha2::Sha256;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

/// Session cookie name.
pub const SESSION_COOKIE: &str = "fumox_session";

/// Compute the per-IP rate-limit key for the incoming request.
///
/// The two early-return conditions stay as two distinct code paths (a single
/// combined `if` would let a "trusted proxy, peer is the trusted CIDR" case
/// fall through to header inspection when `trusted_cidrs` is empty by
/// accident — easy bug, hard to catch in review).
///
/// 1. No trusted proxies configured ⇒ never honor forwarded headers.
/// 2. Peer is not in any trusted CIDR ⇒ the header is untrusted.
/// 3. Trusted peer: walk XFF left-to-right, take the first non-trusted IP.
/// 4. Same left-to-right trust walk on RFC 7239 `Forwarded: for=…`.
/// 5. Nothing usable: fall back to the peer IP.
pub fn client_key(peer: SocketAddr, headers: &HeaderMap, trusted_cidrs: &[ipnet::IpNet]) -> IpAddr {
    // 1. No trusted proxies configured ⇒ never honor forwarded headers.
    if trusted_cidrs.is_empty() {
        return peer.ip();
    }
    // 2. Peer is not in any trusted CIDR ⇒ header is untrusted.
    if !trusted_cidrs.iter().any(|net| net.contains(&peer.ip())) {
        return peer.ip();
    }
    // 3. Trusted peer: walk XFF left-to-right, take the first non-trusted IP.
    if let Some(ip) = walk_xff(headers, trusted_cidrs) {
        return ip;
    }
    // 4. Same left-to-right trust walk on RFC 7239 Forwarded: for=…
    if let Some(ip) = walk_forwarded(headers, trusted_cidrs) {
        return ip;
    }
    // 5. Nothing usable.
    peer.ip()
}

/// Walk `X-Forwarded-For` left-to-right: the left-most entry is the
/// originating client per RFC 6. Take the first entry that parses as an IP
/// AND is not in any trusted CIDR.
fn walk_xff(headers: &HeaderMap, trusted_cidrs: &[ipnet::IpNet]) -> Option<IpAddr> {
    let value = headers.get("x-forwarded-for")?.to_str().ok()?;
    for raw in value.split(',') {
        let candidate = raw.trim();
        let Ok(ip) = candidate.parse::<IpAddr>() else {
            continue;
        };
        if !trusted_cidrs.iter().any(|net| net.contains(&ip)) {
            return Some(ip);
        }
    }
    None
}

/// Walk RFC 7239 `Forwarded: for=…` left-to-right (originating client first
/// per §4). Bracket-strip IPv6 literals; skip `for=_hidden` and `for=unknown`.
fn walk_forwarded(headers: &HeaderMap, trusted_cidrs: &[ipnet::IpNet]) -> Option<IpAddr> {
    let value = headers.get(axum::http::header::FORWARDED)?.to_str().ok()?;
    for raw in value.split(',') {
        let entry = raw.trim();
        // Each Forwarded element is a `;`-separated list of parameters.
        for param in entry.split(';') {
            let param = param.trim();
            let Some(value) = param.strip_prefix("for=") else {
                continue;
            };
            let value = strip_obfuscation(value.trim_matches('"'));
            if value == "_hidden" || value.eq_ignore_ascii_case("unknown") {
                break;
            }
            let value = value
                .strip_prefix('[')
                .and_then(|v| v.strip_suffix(']'))
                .unwrap_or(value);
            let Ok(ip) = value.parse::<IpAddr>() else {
                continue;
            };
            if !trusted_cidrs.iter().any(|net| net.contains(&ip)) {
                return Some(ip);
            }
        }
    }
    None
}

/// Strip RFC 7239 §6.3 obfuscation (`for=_hidden`, `for=unknown`) and
/// surrounding quotes; returns the inner value.
fn strip_obfuscation(value: &str) -> &str {
    value
        .strip_prefix('"')
        .and_then(|v| v.strip_suffix('"'))
        .unwrap_or(value)
}
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

    /// Give one hit back to `key`'s window: the outer middleware counts
    /// every request up front, but a deeper rate-limiting layer may reject
    /// the very same request too — without the refund the outer window pays
    /// for hits the inner limiter already punished. Saturating: a refund for a key whose counter already
    /// expired with its window (or never existed) must never wrap below
    /// zero — the wrap would blacklist the key for the whole window.
    pub async fn refund(&self, key: &str) {
        let init = async { Ok::<_, std::convert::Infallible>(Arc::new(AtomicU64::new(0))) };
        if let Ok(counter) = self.counters.try_get_with(key.to_string(), init).await {
            let _ = counter.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |hits| {
                Some(hits.saturating_sub(1))
            });
        }
    }
}

/// Outermost admin middleware: per-IP rate limiting. Login gets the hard
/// limit, everything else the soft one.
///
/// `/admin/static/*` (the vendored CSS/htmx assets) and HEAD requests are
/// exempt: they carry no state and answer identically for everyone, but
/// each would otherwise burn the same per-IP window as a panel action — a
/// page referencing them re-opens after a burst of fragment loads could be
/// pushed to 429 by asset fetches alone, and an anonymous passer-by could
/// exhaust someone else's NAT-shared window with cheap GETs of the CSS.
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
    let response = next.run(req).await;
    // A rejected response was already punished by a stricter limiter (the
    // login one) or is not this layer's business at all: the outer window
    // must not pay for it twice.
    if response.status() == StatusCode::TOO_MANY_REQUESTS {
        limiter.refund(&ip).await;
    }
    response
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
/// redirects back to `next` (validated by `super::admin_next` — admin-surface
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

    /// A refunded hit opens the window slot it consumed: a request that passed this limiter but was rejected by
    /// a deeper one must not cost this window anything.
    #[tokio::test]
    async fn rate_limiter_refund_returns_the_hit_to_the_window() {
        let limiter = RateLimiter::new(2, Duration::from_secs(60));
        // One request counted here, rejected deeper — the refund leaves
        // the window exactly as it was before the request arrived.
        assert!(limiter.allow("ip1").await);
        limiter.refund("ip1").await;

        // The full quota is still available.
        assert!(limiter.allow("ip1").await);
        assert!(limiter.allow("ip1").await);
        assert!(!limiter.allow("ip1").await);

        // Refunding a key that was never counted is a no-op, not a credit:
        // a below-zero wrap (fetch_sub on 0) would blacklist the key for
        // the whole window instead.
        limiter.refund("never-seen").await;
        assert!(limiter.allow("never-seen").await);
        assert!(limiter.allow("never-seen").await);
        assert!(!limiter.allow("never-seen").await);
    }

    fn trusted_v4() -> Vec<ipnet::IpNet> {
        vec!["2.2.2.2/32".parse().unwrap()]
    }

    fn peer() -> SocketAddr {
        "2.2.2.2:41000".parse().unwrap()
    }

    fn xff(value: &str) -> axum::http::HeaderMap {
        let mut h = HeaderMap::new();
        h.insert("x-forwarded-for", value.parse().unwrap());
        h
    }

    fn fwd(value: &str) -> axum::http::HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(header::FORWARDED, value.parse().unwrap());
        h
    }

    #[test]
    fn empty_trusted_list_never_honors_forwarded_headers() {
        // Even with XFF claiming 1.2.3.4, an unconfigured trust list must
        // not let the header influence the rate-limit key — peer wins.
        let h = xff("1.2.3.4");
        assert_eq!(client_key(peer(), &h, &[]), peer().ip());
        let h = fwd("for=1.2.3.4;proto=https");
        assert_eq!(client_key(peer(), &h, &[]), peer().ip());
    }

    #[test]
    fn trusted_peer_with_single_xff_hop_returns_that_ip() {
        let h = xff("1.2.3.4");
        assert_eq!(
            client_key(peer(), &h, &trusted_v4()),
            "1.2.3.4".parse::<IpAddr>().unwrap()
        );
    }

    #[test]
    fn trusted_peer_with_chain_walks_past_trusted_hops_left_to_right() {
        // The trusted proxy is at the right; the originating client is at
        // the left. Per RFC 6 the left-most is the originating client.
        let h = xff("1.1.1.1, 2.2.2.2");
        assert_eq!(
            client_key(peer(), &h, &trusted_v4()),
            "1.1.1.1".parse::<IpAddr>().unwrap()
        );
    }

    #[test]
    fn chain_with_all_trusted_entries_falls_back_to_peer() {
        // Both hops are inside the trusted CIDR — walking past them all
        // leaves nothing usable, so the peer wins.
        let h = xff("2.2.2.2, 2.2.2.2");
        assert_eq!(client_key(peer(), &h, &trusted_v4()), peer().ip());
    }

    #[test]
    fn untrusted_peer_ignores_xff_and_keeps_peer() {
        let untrusted_peer: SocketAddr = "9.9.9.9:41000".parse().unwrap();
        let h = xff("1.2.3.4");
        assert_eq!(
            client_key(untrusted_peer, &h, &trusted_v4()),
            untrusted_peer.ip()
        );
    }

    #[test]
    fn trusted_peer_with_rfc7239_forwarded_returns_first_untrusted_for() {
        let h = fwd("for=1.2.3.4;proto=https");
        assert_eq!(
            client_key(peer(), &h, &trusted_v4()),
            "1.2.3.4".parse::<IpAddr>().unwrap()
        );
    }

    #[test]
    fn forwarded_for_hidden_falls_back_to_peer() {
        let h = fwd("for=_hidden");
        assert_eq!(client_key(peer(), &h, &trusted_v4()), peer().ip());
    }

    #[test]
    fn forwarded_walks_left_to_right_past_trusted_for_entries() {
        // The originating client is on the left (for=1.1.1.1); the trusted
        // proxy is on the right (for=2.2.2.2). Per RFC 7239 §4 the walk
        // must skip the trusted one and return 1.1.1.1.
        let h = fwd("for=1.1.1.1, for=2.2.2.2");
        assert_eq!(
            client_key(peer(), &h, &trusted_v4()),
            "1.1.1.1".parse::<IpAddr>().unwrap()
        );
    }

    #[test]
    fn forwarded_with_bracketed_ipv6_literal_is_bracket_stripped() {
        let h = fwd("for=[2001:db8::1];proto=https");
        assert_eq!(
            client_key(peer(), &h, &trusted_v4()),
            "2001:db8::1".parse::<IpAddr>().unwrap()
        );
    }

    /// RFC 7239 §4 does not pin parameter ordering. A non-`for=` parameter
    /// appearing before the `for=` must not abort the walk — only the `for=`
    /// parameter is load-bearing for the originating-client lookup. The
    /// audit's reported shape was `Forwarded: proto=https;for=1.2.3.4` and
    /// the pre-fix code bailed at `proto=https` (`?` on `strip_prefix`).
    #[test]
    fn walk_forwarded_takes_first_for_param_regardless_of_position() {
        let h = fwd("proto=https;for=1.2.3.4");
        assert_eq!(
            client_key(peer(), &h, &trusted_v4()),
            "1.2.3.4".parse::<IpAddr>().unwrap()
        );
        // Also pin a chain shape with a non-`for=` parameter in the same
        // entry to make sure the loop walks the whole `;`-separated list.
        let h = fwd("for=1.2.3.4;by=2.2.2.2;proto=https");
        assert_eq!(
            client_key(peer(), &h, &trusted_v4()),
            "1.2.3.4".parse::<IpAddr>().unwrap()
        );
    }
}
