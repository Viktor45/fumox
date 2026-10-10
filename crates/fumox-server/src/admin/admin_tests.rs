use super::*;
use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{Request, StatusCode, header};
use http_body_util::BodyExt;
use std::net::SocketAddr;
use tower::ServiceExt;

const TOKEN: &str = "test-admin-token";

#[test]
fn serve_base_uses_host_header_and_public_port() {
    let bind: SocketAddr = "0.0.0.0:8080".parse().unwrap();
    let peer: SocketAddr = "127.0.0.1:41000".parse().unwrap();
    let mut h = HeaderMap::new();
    h.insert(header::HOST, "vpn.example.com:8081".parse().unwrap());
    assert_eq!(
        serve_base(bind, peer, &h, &[], &[]).unwrap(),
        "http://vpn.example.com:8080"
    );

    // Host without a port.
    let mut h = HeaderMap::new();
    h.insert(header::HOST, "vpn.example.com".parse().unwrap());
    assert_eq!(
        serve_base(bind, peer, &h, &[], &[]).unwrap(),
        "http://vpn.example.com:8080"
    );

    // IPv6 keeps its brackets; the admin port is stripped.
    let mut h = HeaderMap::new();
    h.insert(header::HOST, "[::1]:8081".parse().unwrap());
    assert_eq!(
        serve_base(bind, peer, &h, &[], &[]).unwrap(),
        "http://[::1]:8080"
    );

    // No Host header: loopback for an unspecified bind address,
    // the bound IP itself when it is specific.
    assert_eq!(
        serve_base(bind, peer, &HeaderMap::new(), &[], &[]).unwrap(),
        "http://127.0.0.1:8080"
    );
    let bind: SocketAddr = "192.168.1.5:8080".parse().unwrap();
    assert_eq!(
        serve_base(bind, peer, &HeaderMap::new(), &[], &[]).unwrap(),
        "http://192.168.1.5:8080"
    );
}

#[test]
fn serve_base_switches_to_https_behind_tls_proxy() {
    let bind: SocketAddr = "0.0.0.0:8080".parse().unwrap();
    let trusted_peer: SocketAddr = "2.2.2.2:41000".parse().unwrap();
    let untrusted_peer: SocketAddr = "9.9.9.9:41000".parse().unwrap();
    let trusted: Vec<ipnet::IpNet> = vec!["2.2.2.2/32".parse().unwrap()];

    // Empty allowlist: the forwarded header is *always* ignored, the
    // safe default the empty `[admin].trust_proxy_ips` config advertises.
    let mut h = HeaderMap::new();
    h.insert(header::HOST, "vpn.example.com".parse().unwrap());
    h.insert(
        header::HeaderName::from_static("x-forwarded-proto"),
        "https".parse().unwrap(),
    );
    assert_eq!(
        serve_base(bind, trusted_peer, &h, &[], &[]).unwrap(),
        "http://vpn.example.com:8080",
        "empty allowlist must not honor forwarded headers"
    );

    // Trusted peer + X-Forwarded-Proto: https ⇒ https.
    let mut h = HeaderMap::new();
    h.insert(header::HOST, "vpn.example.com".parse().unwrap());
    h.insert(
        header::HeaderName::from_static("x-forwarded-proto"),
        "https".parse().unwrap(),
    );
    assert_eq!(
        serve_base(bind, trusted_peer, &h, &trusted, &[]).unwrap(),
        "https://vpn.example.com:8080",
        "trusted peer + XFP=https ⇒ https"
    );

    // Untrusted peer: the forwarded header is dropped, scheme is http.
    let mut h = HeaderMap::new();
    h.insert(header::HOST, "vpn.example.com".parse().unwrap());
    h.insert(
        header::HeaderName::from_static("x-forwarded-proto"),
        "https".parse().unwrap(),
    );
    assert_eq!(
        serve_base(bind, untrusted_peer, &h, &trusted, &[]).unwrap(),
        "http://vpn.example.com:8080",
        "untrusted peer + XFP=https ⇒ http (header dropped)"
    );

    // Trusted peer + RFC 7239 Forwarded: proto=https ⇒ https.
    let mut h = HeaderMap::new();
    h.insert(header::HOST, "vpn.example.com".parse().unwrap());
    h.insert(
        header::FORWARDED,
        "for=10.0.0.1;proto=https".parse().unwrap(),
    );
    assert_eq!(
        serve_base(bind, trusted_peer, &h, &trusted, &[]).unwrap(),
        "https://vpn.example.com:8080",
        "trusted peer + RFC 7239 Forwarded proto=https ⇒ https"
    );

    // Trusted peer + explicit X-Forwarded-Proto: http ⇒ http wins.
    let mut h = HeaderMap::new();
    h.insert(header::HOST, "vpn.example.com".parse().unwrap());
    h.insert(
        header::HeaderName::from_static("x-forwarded-proto"),
        "http".parse().unwrap(),
    );
    assert_eq!(
        serve_base(bind, trusted_peer, &h, &trusted, &[]).unwrap(),
        "http://vpn.example.com:8080",
        "explicit XFP=http wins"
    );

    // Default-port strip on :443 still applies for the trusted-https
    // branch.
    let mut h = HeaderMap::new();
    h.insert(header::HOST, "vpn.example.com".parse().unwrap());
    h.insert(
        header::HeaderName::from_static("x-forwarded-proto"),
        "https".parse().unwrap(),
    );
    let bind_443: SocketAddr = "0.0.0.0:443".parse().unwrap();
    assert_eq!(
        serve_base(bind_443, trusted_peer, &h, &trusted, &[]).unwrap(),
        "https://vpn.example.com",
        "default-port strip on :443"
    );

    // Allowlist set: non-matching host ⇒ Err.
    let allowed = vec!["vpn.example.com".to_string()];
    let mut h = HeaderMap::new();
    h.insert(header::HOST, "evil.example".parse().unwrap());
    assert!(serve_base(bind, trusted_peer, &h, &trusted, &allowed).is_err());
}

/// Direct unit tests for `request_is_https`. These pin the trust gate
/// without going through `serve_base` / host_header parsing, every
/// assertion is "given this peer + these headers + this allowlist,
/// `request_is_https` returns X".
fn xfp_https() -> HeaderMap {
    let mut h = HeaderMap::new();
    h.insert(
        header::HeaderName::from_static("x-forwarded-proto"),
        "https".parse().unwrap(),
    );
    h
}
fn xfp_http() -> HeaderMap {
    let mut h = HeaderMap::new();
    h.insert(
        header::HeaderName::from_static("x-forwarded-proto"),
        "http".parse().unwrap(),
    );
    h
}
fn fwd_proto_https() -> HeaderMap {
    let mut h = HeaderMap::new();
    h.insert(
        header::FORWARDED,
        "for=10.0.0.1;proto=https".parse().unwrap(),
    );
    h
}
fn trusted_v4() -> Vec<ipnet::IpNet> {
    vec!["2.2.2.2/32".parse().unwrap()]
}
fn trusted_peer() -> SocketAddr {
    "2.2.2.2:41000".parse().unwrap()
}
fn untrusted_peer() -> SocketAddr {
    "9.9.9.9:41000".parse().unwrap()
}

#[test]
fn request_is_https_empty_allowlist_never_honors_xfp() {
    assert!(!request_is_https(trusted_peer(), &xfp_https(), &[]));
}

#[test]
fn request_is_https_empty_allowlist_never_honors_forwarded_proto() {
    assert!(!request_is_https(trusted_peer(), &fwd_proto_https(), &[]));
}

#[test]
fn request_is_https_trusted_peer_honors_xfp() {
    assert!(request_is_https(
        trusted_peer(),
        &xfp_https(),
        &trusted_v4()
    ));
}

#[test]
fn request_is_https_trusted_peer_honors_forwarded_proto() {
    assert!(request_is_https(
        trusted_peer(),
        &fwd_proto_https(),
        &trusted_v4()
    ));
}

#[test]
fn request_is_https_untrusted_peer_drops_xfp() {
    assert!(!request_is_https(
        untrusted_peer(),
        &xfp_https(),
        &trusted_v4()
    ));
}

#[test]
fn request_is_https_trusted_peer_with_explicit_http_stays_http() {
    assert!(!request_is_https(
        trusted_peer(),
        &xfp_http(),
        &trusted_v4()
    ));
}

/// `parse_trusted_cidrs` builds the `X-Forwarded-For` / `Forwarded: for=`
/// trust list that BOTH per-IP rate limiters (admin and public) and the
/// `request_is_https` scheme detection key on. Its failure mode is
/// deliberate fail-closed design: an unparsable entry is logged and
/// dropped, never defaulted into trust. These tests pin that contract,
/// because the failure is silent by construction — a dropped entry
/// degrades per-IP rate limiting to peer-IP keying and turns the
/// X-Forwarded-Proto scheme detection off, with no error beyond a
/// startup log line.
#[test]
fn parse_trusted_cidrs_keeps_valid_entries_including_bare_ips() {
    // A bare IP is a valid entry: `ipnet` reads it as a host prefix,
    // and the settings form hint advertises "one CIDR or IP per line".
    let parsed = parse_trusted_cidrs(&[
        "10.0.0.0/8".to_string(),
        "192.168.1.1".to_string(),
        "fd00::/8".to_string(),
    ]);
    assert_eq!(
        parsed,
        vec![
            "10.0.0.0/8".parse().unwrap(),
            "192.168.1.1/32".parse().unwrap(),
            "fd00::/8".parse().unwrap(),
        ],
        "valid entries must survive in order, a bare IP as its host prefix"
    );
}

#[test]
fn parse_trusted_cidrs_drops_unparsable_entries_without_inventing_trust() {
    let parsed = parse_trusted_cidrs(&[
        "10.0.0.0/33".to_string(), // /33 is out of range for IPv4
        "not-a-cidr".to_string(),
        "192.168.0.0/16".to_string(),
    ]);
    assert_eq!(
        parsed,
        vec!["192.168.0.0/16".parse().unwrap()],
        "only the valid entry survives; the dropped ones must not widen trust"
    );
}

#[test]
fn parse_trusted_cidrs_of_nothing_or_all_bad_is_an_empty_trust_list() {
    // Empty config: never honor forwarded headers, the safe default.
    assert!(parse_trusted_cidrs(&[]).is_empty());
    // Every entry unparsable: the trust list must come out empty (fail
    // closed), not partially defaulted.
    assert!(
        parse_trusted_cidrs(&[
            "10.0.0.0/33".to_string(),
            "  ".to_string(),
            "nonsense".to_string(),
        ])
        .is_empty()
    );
}

fn admin_config(admin_limit: u32) -> fumox_core::config::AdminConfig {
    fumox_core::config::AdminConfig {
        enabled: true,
        token: TOKEN.to_string(),
        // Skip DNS vetting of source URLs in tests (no network needed);
        // static URL validation still runs.
        allow_private_urls: true,
        rate_limit: fumox_core::config::RateLimit::new(
            admin_limit,
            std::time::Duration::from_secs(60),
        ),
        login_rate_limit: fumox_core::config::RateLimit::new(
            100,
            std::time::Duration::from_secs(60),
        ),
        ..Default::default()
    }
}

async fn test_state(admin_limit: u32) -> (fumox_core::tempdir_lite::TempDir, AdminState) {
    test_admin_state(admin_config(admin_limit), Default::default()).await
}

/// The serve links are built against the same `[admin].allowed_hosts`
/// the router gates the request with. The two lists are independent
/// config, so validating the link against `[server].allowed_hosts` let a
/// host that passed the edge gate reach the handler and be turned into
/// a 500 by the three pages that render a serve link.
#[tokio::test]
async fn serve_base_validates_against_the_admin_host_allowlist() {
    let mut admin = admin_config(10);
    admin.allowed_hosts = vec!["panel.example.com".to_string()];
    let server = fumox_core::config::ServerConfig {
        allowed_hosts: vec!["vpn.example.com".to_string()],
        ..Default::default()
    };
    let (_dir, state) = test_admin_state(admin, server).await;
    let peer: SocketAddr = "127.0.0.1:41000".parse().unwrap();

    // The host the panel was opened on builds its serve link even when
    // the public listener gates on a different list.
    let mut headers = HeaderMap::new();
    headers.insert(header::HOST, "panel.example.com".parse().unwrap());
    assert_eq!(
        state.serve_base(peer, &headers).unwrap(),
        "http://panel.example.com:8080"
    );

    // A host the panel does not allow builds nothing.
    let mut headers = HeaderMap::new();
    headers.insert(header::HOST, "vpn.example.com".parse().unwrap());
    assert!(state.serve_base(peer, &headers).is_err());
}

/// End to end through the router: a Host that passes the admin gate
/// renders the serve-link pages instead of the 500 all three callers
/// used to return from `build_serve_link_host`. Both allowlists
/// configured, and pointing at different hosts, is the ordinary
/// operator setup that made this the normal outcome.
#[tokio::test]
async fn serve_link_pages_render_for_an_admin_allowlisted_host() {
    let mut admin = admin_config(1000);
    admin.allowed_hosts = vec!["panel.example.com".to_string()];
    let server = fumox_core::config::ServerConfig {
        allowed_hosts: vec!["vpn.example.com".to_string()],
        ..Default::default()
    };
    let (_dir, state) = test_admin_state(admin, server).await;
    let app = router(state);

    let with_host = |method: &str, uri: &str, body: &str, cookie: Option<&str>| {
        let mut r = request(method, uri, body, cookie);
        r.headers_mut()
            .insert(header::HOST, "panel.example.com".parse().unwrap());
        r
    };

    let response = app
        .clone()
        .oneshot(with_host(
            "POST",
            "/admin/login",
            &format!("token={TOKEN}"),
            None,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let cookie = response
        .headers()
        .get(header::SET_COOKIE)
        .unwrap()
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_string();

    let response = app
        .oneshot(with_host("GET", "/admin/import", "", Some(&cookie)))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let html = response.into_body().collect().await.unwrap().to_bytes();
    let html = String::from_utf8_lossy(&html);
    assert!(
        html.contains("http://panel.example.com:8080/export/alive/"),
        "the export link must be built from the panel's own host: {html:.400}"
    );
    // The remaining tradeoff, recorded in `serve_base`: the link is not
    // rewritten to the host the public listener does allow, so with the
    // two lists pointing at different hosts that link 404s on click.
    // The page itself must render. That is the half this fixes.
    assert!(
        !html.contains("vpn.example.com"),
        "the link must not be silently swapped for another host: {html:.400}"
    );
}

async fn test_state_with_admin(
    admin: AdminConfig,
) -> (fumox_core::tempdir_lite::TempDir, AdminState) {
    test_admin_state(admin, Default::default()).await
}

/// Build a request with the ConnectInfo extension the rate limiter
/// needs; a real listener attaches it via
/// `into_make_service_with_connect_info`.
fn request(method: &str, uri: &str, body: &str, cookie: Option<&str>) -> Request<Body> {
    let mut builder = Request::builder()
        .method(method)
        .uri(uri)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .extension(ConnectInfo::<SocketAddr>(
            "127.0.0.1:41000".parse().unwrap(),
        ));
    if let Some(cookie) = cookie {
        builder = builder.header(header::COOKIE, cookie);
    }
    builder.body(Body::from(body.to_string())).unwrap()
}

/// The `HX-Trigger` payload carries its message percent-encoded
/// (the browser header is decoded as Latin-1), so a test that wants
/// to read the toast text decodes it first.
fn percent_decode(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let hex = std::str::from_utf8(&bytes[i + 1..i + 3]).expect("ascii percent escape");
            out.push(u8::from_str_radix(hex, 16).expect("valid percent escape"));
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out).expect("decoded payload is utf-8")
}

async fn login(app: &axum::Router) -> String {
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
    let set_cookie = response
        .headers()
        .get(header::SET_COOKIE)
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    assert!(set_cookie.starts_with(&format!("{}=", auth::SESSION_COOKIE)));
    assert!(set_cookie.contains("HttpOnly"));
    // The cookie value is everything up to the first ';'.
    set_cookie.split(';').next().unwrap().to_string()
}

fn csrf_for(state: &AdminState, cookie: &str) -> String {
    let session = cookie
        .split_once('=')
        .map(|(_, value)| value.to_string())
        .unwrap_or_default();
    auth::csrf_token(&state.csrf_key, &session)
}

#[tokio::test]
async fn unauthenticated_browsers_are_redirected_to_login() {
    let (_dir, state) = test_state(1000).await;
    let app = router(state);
    let response = app
        .oneshot(request("GET", "/admin", "", None))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        response.headers().get(header::LOCATION).unwrap(),
        "/admin/login"
    );
}

#[tokio::test]
async fn unauthenticated_htmx_gets_hx_redirect() {
    let (_dir, state) = test_state(1000).await;
    let app = router(state);
    let mut req = request("GET", "/admin/sources", "", None);
    req.headers_mut()
        .insert("HX-Request", "true".parse().unwrap());
    let response = app.oneshot(req).await.unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        response.headers().get("HX-Redirect").unwrap(),
        "/admin/login"
    );
}

#[tokio::test]
async fn login_flow_grants_access_and_wrong_token_does_not() {
    let (_dir, state) = test_state(1000).await;
    let app = router(state.clone());

    // Wrong token: re-render the form with 422, no session.
    let response = app
        .clone()
        .oneshot(request("POST", "/admin/login", "token=nope", None))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    assert!(response.headers().get(header::SET_COOKIE).is_none());

    // Correct token: session cookie and access to the dashboard.
    let cookie = login(&app).await;
    let response = app
        .clone()
        .oneshot(request("GET", "/admin", "", Some(&cookie)))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let html = response.into_body().collect().await.unwrap().to_bytes();
    let html = String::from_utf8_lossy(&html);
    assert!(html.contains("Обзор"));

    // Security headers are present on every admin response.
    let response = app
        .oneshot(request("GET", "/admin/login", "", None))
        .await
        .unwrap();
    assert_eq!(
        response.headers().get(header::X_FRAME_OPTIONS).unwrap(),
        "DENY"
    );
    assert_eq!(
        response
            .headers()
            .get(header::X_CONTENT_TYPE_OPTIONS)
            .unwrap(),
        "nosniff"
    );
    assert_eq!(
        response
            .headers()
            .get(header::CONTENT_SECURITY_POLICY)
            .unwrap(),
        security::CONTENT_SECURITY_POLICY
    );
}

#[tokio::test]
async fn secure_cookies_flag_adds_secure_to_session_cookie() {
    let mut admin = admin_config(100);
    admin.secure_cookies = true;
    let (_dir, state) = test_state_with_admin(admin).await;
    let app = router(state);
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
    let cookie = response
        .headers()
        .get(header::SET_COOKIE)
        .unwrap()
        .to_str()
        .unwrap();
    assert!(cookie.contains("HttpOnly"), "cookie: {cookie}");
    assert!(cookie.ends_with("; Secure"), "cookie: {cookie}");
}

#[tokio::test]
async fn post_without_csrf_is_rejected() {
    let (_dir, state) = test_state(1000).await;
    let pool = state.pool.clone();
    let app = router(state.clone());
    let cookie = login(&app).await;

    let source = fumox_core::models::Source {
        id: "srcA0000000".into(),
        slug: None,
        name: "s".into(),
        url: "https://example.com".into(),
        enabled: true,
        encoding: Default::default(),
        input_format: None,
        protocols: None,
        cache_ttl_seconds: 3600,
        tags: None,
        pipeline: None,
        headers: None,
        ip_family: None,
        created_at: 1,
        updated_at: 1,
        last_fetched_at: None,
        last_error: None,
        error_class: None,
    };
    fumox_core::repo::sources::create(&pool, &source)
        .await
        .unwrap();

    // No _csrf field at all.
    let response = app
        .clone()
        .oneshot(request(
            "POST",
            "/admin/sources/srcA0000000/toggle",
            "",
            Some(&cookie),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    // A forged token does not pass either.
    let response = app
        .clone()
        .oneshot(request(
            "POST",
            "/admin/sources/srcA0000000/toggle",
            "_csrf=forged",
            Some(&cookie),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    // The genuine token (derived from the session cookie) passes.
    let csrf = csrf_for(&state, &cookie);
    let response = app
        .clone()
        .oneshot(request(
            "POST",
            "/admin/sources/srcA0000000/toggle",
            &format!("_csrf={csrf}"),
            Some(&cookie),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let reloaded = fumox_core::repo::sources::get(&pool, "srcA0000000")
        .await
        .unwrap()
        .unwrap();
    assert!(!reloaded.enabled); // was true, toggled to false
}

/// Logout is a state-changing POST, so it lives inside the protected
/// nest: a cross-site form POST carrying the operator's cookie but no
/// `_csrf` must not clear the session, and a cookie-less POST must not
/// reach the handler at all.
#[tokio::test]
async fn logout_requires_session_and_csrf() {
    let (_dir, state) = test_state(1000).await;
    let app = router(state.clone());
    let cookie = login(&app).await;

    // A cross-site form POST: session cookie present, no _csrf, no
    // Origin the server could check. Must not clear the session.
    let response = app
        .clone()
        .oneshot(request("POST", "/admin/logout", "", Some(&cookie)))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert!(
        response.headers().get(header::SET_COOKIE).is_none(),
        "a CSRF-less logout must not send a cookie-clearing Set-Cookie"
    );

    // Without a session the request never reaches the handler.
    let response = app
        .clone()
        .oneshot(request("POST", "/admin/logout", "", None))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        response.headers().get(header::LOCATION).unwrap(),
        "/admin/login"
    );
    assert!(response.headers().get(header::SET_COOKIE).is_none());

    // The form in `base.html` ships the genuine token: it works.
    let csrf = csrf_for(&state, &cookie);
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
    let cleared = response.headers().get(header::SET_COOKIE).unwrap();
    let cleared = cleared.to_str().unwrap();
    assert!(cleared.contains("Max-Age=0"), "cookie: {cleared}");
}

/// M3: an over-cap body must be rejected
/// by the body-limit middleware before the CSRF layer runs. Anything
/// from `DefaultBodyLimit::max(1 MiB)` (a `413 Payload Too Large`) is
/// acceptable; a `400` from the CSRF layer's own `to_bytes` cap is
/// also acceptable. What is *not* acceptable: the request slipping
/// through to a `403` CSRF failure, that would mean the binary body
/// was parsed as urlencoded and silently treated as a missing `_csrf`.
#[tokio::test]
async fn oversized_binary_body_is_rejected_before_csrf() {
    let (_dir, state) = test_state(1000).await;
    let app = router(state.clone());
    let cookie = login(&app).await;
    let csrf = csrf_for(&state, &cookie);

    // 1 MiB + 1 byte of arbitrary binary, invalid UTF-8 too, so even
    // if the CSRF layer ran, it could not match `_csrf` against it.
    let mut body = Vec::with_capacity((1 << 20) + 1);
    body.extend_from_slice(&vec![0xFFu8; (1 << 20) + 1]);

    let mut req = Request::builder()
        .method("POST")
        .uri("/admin/sources/srcA0000000/toggle")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header(header::COOKIE, &cookie)
        .body(Body::from(body))
        .unwrap();
    req.extensions_mut().insert(ConnectInfo::<SocketAddr>(
        "127.0.0.1:41000".parse().unwrap(),
    ));

    let response = app.oneshot(req).await.unwrap();
    let status = response.status();
    assert!(
        status == StatusCode::PAYLOAD_TOO_LARGE || status == StatusCode::BAD_REQUEST,
        "oversized binary body must be rejected before CSRF, got {status}"
    );
    assert_ne!(
        status,
        StatusCode::FORBIDDEN,
        "binary body must not be parsed as urlencoded and silently fail CSRF"
    );

    // The genuine CSRF token is in the body already, even if a
    // hypothetical parser guessed it, the body cap is the only
    // load-bearing protection.
    let _ = csrf;
}

#[tokio::test]
async fn rate_limit_kicks_in_past_the_soft_limit() {
    let (_dir, state) = test_state(3).await;
    let app = router(state.clone());
    let cookie = login(&app).await;
    for _ in 0..3 {
        let response = app
            .clone()
            .oneshot(request("GET", "/admin", "", Some(&cookie)))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }
    let response = app
        .oneshot(request("GET", "/admin", "", Some(&cookie)))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
}

/// End-to-end check that the shared `client_key` helper plumbs through
/// `AdminState::trusted_cidrs`: a trusted proxy's `X-Forwarded-For` claim
/// must drive the per-IP rate-limit key, so the same claimed client IP
/// fills its window while a different claim against the same peer stays
/// unblocked. The claim that counts is the entry a trusted proxy
/// appended (right-most), not the client-supplied left-most prefix.
#[tokio::test]
async fn rate_limit_uses_xff_ip_for_trusted_peer() {
    let (_dir, mut state) = test_state(1).await;
    state.trusted_cidrs = vec!["2.2.2.2/32".parse().unwrap()];
    let app = router(state.clone());
    let cookie = login(&app).await;

    let req_with_xff = |xff: &str| {
        let mut r = request("GET", "/admin", "", Some(&cookie));
        r.headers_mut()
            .insert("x-forwarded-for", xff.parse().unwrap());
        // Override the ConnectInfo peer to a trusted CIDR address.
        r.extensions_mut()
            .insert(ConnectInfo::<SocketAddr>("2.2.2.2:41000".parse().unwrap()));
        r
    };

    // 1 of 1 window slots for claimed client 1.2.3.4.
    let response = app.clone().oneshot(req_with_xff("1.2.3.4")).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let response = app.clone().oneshot(req_with_xff("1.2.3.4")).await.unwrap();
    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);

    // Same trusted peer, different claimed client: fresh window.
    let response = app.clone().oneshot(req_with_xff("5.5.5.5")).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    // Append-mode proxy (security review f2): the client sends its own
    // XFF prefix and the trusted proxy appends the observed client IP,
    // so the header is "<client-forged>, 9.9.9.9". The right-most
    // non-trusted entry, what the proxy appended, must key the
    // window, and re-forging the prefix must not open a new one.
    let response = app
        .clone()
        .oneshot(req_with_xff("1.2.3.4, 9.9.9.9"))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let response = app
        .clone()
        .oneshot(req_with_xff("1.2.3.4, 9.9.9.9"))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);

    // The old left-to-right walk keyed on the forged left-most entry,
    // every forged prefix got a fresh window and the login cap was
    // void. The prefix is now ignored: same key, same exhausted window.
    let response = app
        .clone()
        .oneshot(req_with_xff("6.6.6.6, 9.9.9.9"))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
}

/// `[admin].allowed_hosts` is enforced at the edge of the admin router
/// (security review f3): a Host outside the allowlist is rejected with
/// 400 before auth or rate limiting, on every route including the
/// login form, while an allowlisted host serves normally. The port
/// suffix and letter case are canonicalized away by the gate.
#[tokio::test]
async fn admin_allowed_hosts_gates_every_route_at_the_edge() {
    let mut admin = admin_config(1000);
    admin.allowed_hosts = vec!["panel.example.com".to_string()];
    let (_dir, state) = test_state_with_admin(admin).await;
    let app = router(state);

    let req_with_host = |host: &str| {
        let mut r = request("GET", "/admin/login", "", None);
        r.headers_mut().insert(header::HOST, host.parse().unwrap());
        r
    };

    let response = app
        .clone()
        .oneshot(req_with_host("evil.example"))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    let response = app
        .clone()
        .oneshot(req_with_host("Panel.Example.com:8081"))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    // A missing Host header is rejected whenever an allowlist is set
    // (deny by default), the gate's canonical empty host.
    let response = app
        .oneshot(request("GET", "/admin/login", "", None))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

/// Vendored assets and HEAD requests bypass the admin rate limiter:
/// they must stay servable even after the
/// per-IP window is exhausted, a page hit by 429 still needs its CSS
/// to render the rate-limit message.
#[tokio::test]
async fn static_assets_and_head_bypass_the_rate_limit() {
    let (_dir, state) = test_state(2).await;
    let app = router(state);

    // Burn the window with plain GETs of the panel root.
    assert_eq!(
        app.clone()
            .oneshot(request("GET", "/admin/login", "", None))
            .await
            .unwrap()
            .status(),
        StatusCode::OK
    );
    assert_eq!(
        app.clone()
            .oneshot(request("GET", "/admin/login", "", None))
            .await
            .unwrap()
            .status(),
        StatusCode::OK
    );
    assert_eq!(
        app.clone()
            .oneshot(request("GET", "/admin/login", "", None))
            .await
            .unwrap()
            .status(),
        StatusCode::TOO_MANY_REQUESTS
    );

    // The window is exhausted, yet the assets and a HEAD still serve.
    for uri in ["/admin/static/app.css", "/admin/static/htmx.min.js"] {
        let response = app
            .clone()
            .oneshot(request("GET", uri, "", None))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK, "{uri}");
    }
    let response = app
        .oneshot(request("HEAD", "/admin/login", "", None))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn list_screens_render_for_an_authenticated_session() {
    let (_dir, state) = test_state(1000).await;
    let app = router(state.clone());
    let cookie = login(&app).await;
    for path in [
        "/admin/sources",
        "/admin/sources/new",
        "/admin/profiles",
        "/admin/profiles/new",
        "/admin/proxies",
        "/admin/logs/fetch",
        "/admin/import",
    ] {
        let response = app
            .clone()
            .oneshot(request("GET", path, "", Some(&cookie)))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK, "path {path}");
    }
}

#[tokio::test]
async fn source_headers_with_control_characters_are_rejected() {
    let (_dir, state) = test_state(1000).await;
    let app = router(state.clone());
    let cookie = login(&app).await;
    let csrf = csrf_for(&state, &cookie);

    // A control byte inside a header value is refused by the HTTP layer;
    // the form must reject it up front.
    let body = format!(
        "_csrf={csrf}&name=Hdr&url=https%3A%2F%2Fexample.com%2Fsub&cache_ttl_seconds=3600&headers=X-Token%3A%20abc%0Ddef"
    );
    let response = app
        .oneshot(request("POST", "/admin/sources/new", &body, Some(&cookie)))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    assert!(
        fumox_core::repo::sources::list(&state.pool, false)
            .await
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn source_form_validation_rejects_bad_input() {
    let (_dir, state) = test_state(1000).await;
    let app = router(state.clone());
    let cookie = login(&app).await;
    let csrf = csrf_for(&state, &cookie);

    // Missing name and url, bad slug and TTL.
    let body = format!("_csrf={csrf}&slug=-bad&url=ftp://x&cache_ttl_seconds=5");
    let response = app
        .clone()
        .oneshot(request("POST", "/admin/sources/new", &body, Some(&cookie)))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    let html = response.into_body().collect().await.unwrap().to_bytes();
    let html = String::from_utf8_lossy(&html);
    assert!(html.contains("обязательное поле"));
    assert!(
        fumox_core::repo::sources::list(&state.pool, false)
            .await
            .unwrap()
            .is_empty()
    );

    // An unknown IP family is rejected as well.
    let body = format!(
        "_csrf={csrf}&name=Family&url=https%3A%2F%2Fexample.com%2Fsub&ip_family=ipx6&cache_ttl_seconds=3600"
    );
    let response = app
        .clone()
        .oneshot(request("POST", "/admin/sources/new", &body, Some(&cookie)))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    assert!(
        fumox_core::repo::sources::list(&state.pool, false)
            .await
            .unwrap()
            .is_empty()
    );

    // A valid submission creates the source and redirects to the card;
    // the pinned IP family is persisted.
    let body = format!(
        "_csrf={csrf}&name=Test&slug=test&url=https%3A%2F%2Fexample.com%2Fsub&ip_family=ipv6&cache_ttl_seconds=3600&enabled=1"
    );
    let response = app
        .oneshot(request("POST", "/admin/sources/new", &body, Some(&cookie)))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let created = fumox_core::repo::sources::get_by_slug(&state.pool, "test")
        .await
        .unwrap();
    assert!(created.is_some());
    assert_eq!(
        created.unwrap().ip_family,
        Some(fumox_core::models::IpFamily::Ipv6)
    );
}

/// F7: unbounded form fields used to be
/// stored verbatim, a megabyte pipeline or a hundred tags degraded
/// every later render. The caps reject the submission.
#[tokio::test]
async fn oversized_form_fields_are_rejected() {
    let (_dir, state) = test_state(1000).await;
    let app = router(state.clone());
    let cookie = login(&app).await;
    let csrf = csrf_for(&state, &cookie);

    // The test config allows private URLs, so vet_url short-circuits to
    // static validation and the URL length cap is what fires here.
    let long_url = format!("https://example.com/{}", "x".repeat(3000));
    let body = urlencoded(&[
        ("_csrf", &csrf),
        ("name", "Caps"),
        ("url", &long_url),
        ("cache_ttl_seconds", "3600"),
    ]);
    let response = app
        .clone()
        .oneshot(request("POST", "/admin/sources/new", &body, Some(&cookie)))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    assert!(
        fumox_core::repo::sources::list(&state.pool, false)
            .await
            .unwrap()
            .is_empty()
    );

    // A pipeline over the byte cap is rejected even when it is valid JSON.
    let huge_pipeline = format!(
        "{{\"version\":1,\"rename\":[{{\"match\":\"{}\",\"replace\":\"x\"}}]}}",
        "a".repeat(70_000)
    );
    let body = urlencoded(&[
        ("_csrf", &csrf),
        ("name", "Caps"),
        ("url", "https://example.com/sub"),
        ("cache_ttl_seconds", "3600"),
        ("pipeline_mode", "raw"),
        ("pipeline", &huge_pipeline),
    ]);
    let response = app
        .clone()
        .oneshot(request("POST", "/admin/sources/new", &body, Some(&cookie)))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    assert!(
        fumox_core::repo::sources::list(&state.pool, false)
            .await
            .unwrap()
            .is_empty()
    );

    // Too many tags.
    let tags: String = (0..30)
        .map(|i| format!("tag{i}"))
        .collect::<Vec<_>>()
        .join(",");
    let body = urlencoded(&[
        ("_csrf", &csrf),
        ("name", "Caps"),
        ("url", "https://example.com/sub"),
        ("cache_ttl_seconds", "3600"),
        ("tags", &tags),
    ]);
    let response = app
        .clone()
        .oneshot(request("POST", "/admin/sources/new", &body, Some(&cookie)))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    assert!(
        fumox_core::repo::sources::list(&state.pool, false)
            .await
            .unwrap()
            .is_empty()
    );
}

/// F8: a profile token outside the
/// URL-safe alphabet is rejected by the form.
#[tokio::test]
async fn profile_token_validation_caps_and_charset() {
    let (_dir, state) = test_state(1000).await;
    let app = router(state.clone());
    let cookie = login(&app).await;
    let csrf = csrf_for(&state, &cookie);

    // A token with spaces is not URL-safe: rejected.
    let body = urlencoded(&[
        ("_csrf", &csrf),
        ("name", "T"),
        ("output_format", "uri_list"),
        ("access_token", "not url safe"),
    ]);
    let response = app
        .clone()
        .oneshot(request("POST", "/admin/profiles/new", &body, Some(&cookie)))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    assert!(
        fumox_core::repo::profiles::list(&state.pool, false)
            .await
            .unwrap()
            .is_empty()
    );

    // A long but valid token passes the form (length capped at 128).
    let token = "a".repeat(128);
    let body = urlencoded(&[
        ("_csrf", &csrf),
        ("name", "T"),
        ("output_format", "uri_list"),
        ("access_token", &token),
        ("enabled", "1"),
    ]);
    let response = app
        .oneshot(request("POST", "/admin/profiles/new", &body, Some(&cookie)))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
}

#[tokio::test]
async fn url_validation_errors_follow_the_panel_language() {
    let (_dir, state) = test_state(1000).await;
    let app = router(state.clone());
    let cookie = login(&app).await;
    let csrf = csrf_for(&state, &cookie);
    let body = format!("_csrf={csrf}&name=Bad&url=ftp://x&cache_ttl_seconds=3600");

    // Default UI language: the localized sentence wraps the offending
    // scheme as a technical payload.
    let response = app
        .clone()
        .oneshot(request("POST", "/admin/sources/new", &body, Some(&cookie)))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    let html = String::from_utf8_lossy(&response.into_body().collect().await.unwrap().to_bytes())
        .into_owned();
    assert!(html.contains("поддерживаются только http/https"), "{html}");

    // Same submission with the panel switched to English via the
    // language cookie.
    let en_cookie = format!("{cookie}; {}=en", i18n::LANG_COOKIE);
    let response = app
        .oneshot(request(
            "POST",
            "/admin/sources/new",
            &body,
            Some(&en_cookie),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    let html = String::from_utf8_lossy(&response.into_body().collect().await.unwrap().to_bytes())
        .into_owned();
    assert!(
        html.contains("only http/https URLs are supported"),
        "{html}"
    );
    assert!(!html.contains("поддерживаются только"), "{html}");
    assert!(
        fumox_core::repo::sources::list(&state.pool, false)
            .await
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn import_page_shows_alive_link_and_rotation_replaces_it() {
    let (_dir, state) = test_state(1000).await;
    let app = router(state.clone());
    let cookie = login(&app).await;
    let csrf = csrf_for(&state, &cookie);

    // The export screen displays the absolute alive-export link with
    // its (first-visit generated) token.
    let response = app
        .clone()
        .oneshot(request("GET", "/admin/import", "", Some(&cookie)))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let html = response.into_body().collect().await.unwrap().to_bytes();
    let html = String::from_utf8_lossy(&html).into_owned();
    let token = html
        .split("/export/alive/")
        .nth(1)
        .and_then(|rest| rest.split('"').next())
        .expect("the page must show the alive export link")
        .to_string();
    assert_eq!(token.len(), 12, "nanoid token, got {token:?}");

    // Rotation issues a fresh token and returns to the screen.
    let body = format!("_csrf={csrf}");
    let response = app
        .oneshot(request(
            "POST",
            "/admin/import/alive-token",
            &body,
            Some(&cookie),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SEE_OTHER);

    let stored: Option<String> =
        fumox_core::repo::meta_get(&state.pool, crate::alive_export::TOKEN_KEY)
            .await
            .unwrap();
    assert_eq!(stored.as_deref().map(str::len), Some(12));
    assert_ne!(stored.as_deref(), Some(token.as_str()));
}

#[tokio::test]
async fn profile_form_persists_and_validates_country_filter() {
    let (_dir, state) = test_state(1000).await;
    let app = router(state.clone());
    let cookie = login(&app).await;
    let csrf = csrf_for(&state, &cookie);

    // "XX1" is not a 2-letter ISO code: the form re-renders with 422
    // and nothing is written.
    let body = format!("_csrf={csrf}&name=Countries&countries=DE%2C%20XX1");
    let response = app
        .clone()
        .oneshot(request("POST", "/admin/profiles/new", &body, Some(&cookie)))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    let html = response.into_body().collect().await.unwrap().to_bytes();
    let html = String::from_utf8_lossy(&html);
    assert!(html.contains("XX1"), "bad code must be reported: {html:?}");
    assert!(
        fumox_core::repo::profiles::list(&state.pool, false)
            .await
            .unwrap()
            .is_empty()
    );

    // A valid submission normalizes case and drops duplicates.
    let body = format!(
        "_csrf={csrf}&name=Countries&output_format=uri_list&countries=de%2C%20US%2C%20de&enabled=1"
    );
    let response = app
        .clone()
        .oneshot(request("POST", "/admin/profiles/new", &body, Some(&cookie)))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let profiles = fumox_core::repo::profiles::list(&state.pool, false)
        .await
        .unwrap();
    assert_eq!(profiles.len(), 1);
    assert_eq!(
        profiles[0].countries,
        vec!["DE".to_string(), "US".to_string()]
    );

    // The card lists the active allowlist.
    let response = app
        .oneshot(request(
            "GET",
            &format!("/admin/profiles/{}", profiles[0].id),
            "",
            Some(&cookie),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let html = response.into_body().collect().await.unwrap().to_bytes();
    let html = String::from_utf8_lossy(&html);
    assert!(html.contains("DE, US"), "card shows the filter: {html:?}");
}

/// The `ready` tier surfaces everywhere the statuses are listed:
/// the proxy browser filter, the stats
/// splits and the export screen's ready link.
#[tokio::test]
async fn ready_tier_is_filterable_and_exported() {
    let (_dir, state) = test_state(1000).await;
    let pool = state.pool.clone();

    sqlx::query(
            "INSERT INTO proxies (fingerprint, scheme, name, host, port, credential, status, created_at, updated_at)
             VALUES ('fp-ready-1', 'vless', 'verified-one', 'r1.example.com', 443, 'c', 'ready', 1, 1),
                    ('fp-alive-1', 'vless', 'plain-one', 'r2.example.com', 443, 'c', 'alive', 1, 1)",
        )
        .execute(&pool)
        .await
        .unwrap();

    let app = router(state);
    let cookie = login(&app).await;

    // The browser filter selects the ready tier only.
    let response = app
        .clone()
        .oneshot(request(
            "GET",
            "/admin/proxies?status=ready",
            "",
            Some(&cookie),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let html = response.into_body().collect().await.unwrap().to_bytes();
    let html = String::from_utf8_lossy(&html);
    assert!(html.contains("verified-one"), "{html}");
    assert!(!html.contains("plain-one"), "{html}");
    // The filter dropdown carries the ready checkbox.
    assert!(html.contains("value=\"ready\""), "{html}");

    // The dashboard counts the ready bucket per scheme.
    let response = app
        .clone()
        .oneshot(request("GET", "/admin", "", Some(&cookie)))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let html = response.into_body().collect().await.unwrap().to_bytes();
    let html = String::from_utf8_lossy(&html);
    assert!(html.contains("status=ready"), "{html}");

    // The export screen shows the ready link with the shared token and
    // its own count.
    let response = app
        .clone()
        .oneshot(request("GET", "/admin/import", "", Some(&cookie)))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let html = response.into_body().collect().await.unwrap().to_bytes();
    let html = String::from_utf8_lossy(&html);
    assert!(html.contains("/export/ready/"), "{html}");
    assert!(html.contains("готовые"), "the ready column title: {html}");

    // The card's own badge chain carries the ready tier too, so a
    // T2-verified proxy does not render as «unknown».
    let ready_id: i64 = sqlx::query_scalar("SELECT id FROM proxies WHERE status = 'ready'")
        .fetch_one(&pool)
        .await
        .unwrap();
    let response = app
        .clone()
        .oneshot(request(
            "GET",
            &format!("/admin/proxies/{ready_id}"),
            "",
            Some(&cookie),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let html = response.into_body().collect().await.unwrap().to_bytes();
    let html = String::from_utf8_lossy(&html);
    assert!(html.contains("badge ready"), "card badge: {html}");
    assert!(
        !html.contains("badge unknown"),
        "a ready proxy must not render the unknown badge: {html}"
    );
}

#[tokio::test]
async fn unknown_entities_are_404() {
    let (_dir, state) = test_state(1000).await;
    let app = router(state.clone());
    let cookie = login(&app).await;
    for path in [
        "/admin/sources/doesnotexist",
        "/admin/profiles/doesnotexist",
        "/admin/proxies/42",
    ] {
        let response = app
            .clone()
            .oneshot(request("GET", path, "", Some(&cookie)))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND, "path {path}");
    }
}

/// The Profiles list shows a per-row count of **ready** proxies
/// reachable through the profile's sources, i.e. the set
/// `/sub/{slug}` would emit right now. Pre-ready statuses (`alive`,
/// `quarantine`, `unknown`) and terminal `removed` are excluded.
/// Proxies reachable only through sources **not** in the profile are
/// excluded. A proxy reachable through more than one profile source
/// is counted once (`DISTINCT px.id`).
#[tokio::test]
async fn profiles_list_shows_ready_proxy_count_per_row() {
    let (_dir, state) = test_state(1000).await;
    let pool = state.pool.clone();
    let now = fumox_core::models::now_ts();

    // Profile with one source. A second source exists in the DB but
    // is not attached to the profile, proxies reachable only through
    // that source must not show up in the count.
    sqlx::query(
        "INSERT INTO profiles (id, name, output_format, enabled, created_at, updated_at)
             VALUES ('p-ready', 'ready-count', 'uri_list', 1, ?, ?)",
    )
    .bind(now)
    .bind(now)
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO sources (id, name, url, enabled, cache_ttl_seconds, created_at, updated_at)
             VALUES ('s-in',  'in',  'http://in.example/list', 1, 3600, ?, ?),
                    ('s-out', 'out', 'http://out.example/list', 1, 3600, ?, ?)",
    )
    .bind(now)
    .bind(now)
    .bind(now)
    .bind(now)
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(
            "INSERT INTO profile_sources (profile_id, source_id, position) VALUES ('p-ready', 's-in', 0)",
        )
        .execute(&pool)
        .await
        .unwrap();

    // Proxies reachable through `s-in` (in the profile): two ready,
    // one alive, one quarantine, one unknown, one removed. Only the
    // two ready rows contribute to the count.
    for (fp, host_no, status) in [
        ("fp-r1", 1i64, "ready"),
        ("fp-r2", 2, "ready"),
        ("fp-a1", 3, "alive"),
        ("fp-q1", 4, "quarantine"),
        ("fp-u1", 5, "unknown"),
        ("fp-m1", 6, "removed"),
    ] {
        sqlx::query(
                "INSERT INTO proxies (fingerprint, scheme, name, host, port, credential, status, created_at, updated_at)
                 VALUES (?, 'vless', ?, ?, 1, 'c', ?, ?, ?)",
            )
            .bind(fp)
            .bind(fp)            // name reuses the fingerprint for the row label
            .bind(format!("h{host_no}.example"))
            .bind(status)
            .bind(now)
            .bind(now)
            .execute(&pool)
            .await
            .unwrap();
    }

    // One extra ready proxy reachable only through `s-out` (not in the
    // profile). Must not count toward the profile's total.
    sqlx::query(
            "INSERT INTO proxies (fingerprint, scheme, name, host, port, credential, status, created_at, updated_at)
             VALUES ('fp-x1', 'vless', 'x1', 'hx.example', 1, 'c', 'ready', ?, ?)",
        )
        .bind(now)
        .bind(now)
        .execute(&pool)
        .await
        .unwrap();

    // And one ready proxy reachable through **both** sources, it must
    // be counted once (DISTINCT px.id).
    sqlx::query(
            "INSERT INTO proxies (fingerprint, scheme, name, host, port, credential, status, created_at, updated_at)
             VALUES ('fp-both', 'vless', 'both', 'hb.example', 1, 'c', 'ready', ?, ?)",
        )
        .bind(now)
        .bind(now)
        .execute(&pool)
        .await
        .unwrap();

    sqlx::query(
        "INSERT INTO proxy_source_links (proxy_id, source_id, seen_at)
             SELECT p.id, s.id, ? FROM proxies p CROSS JOIN sources s
             WHERE (p.fingerprint = 'fp-r1' AND s.id = 's-in')
                OR (p.fingerprint = 'fp-r2' AND s.id = 's-in')
                OR (p.fingerprint = 'fp-a1' AND s.id = 's-in')
                OR (p.fingerprint = 'fp-q1' AND s.id = 's-in')
                OR (p.fingerprint = 'fp-u1' AND s.id = 's-in')
                OR (p.fingerprint = 'fp-m1' AND s.id = 's-in')
                OR (p.fingerprint = 'fp-x1' AND s.id = 's-out')
                OR (p.fingerprint = 'fp-both' AND s.id IN ('s-in', 's-out'))",
    )
    .bind(now)
    .execute(&pool)
    .await
    .unwrap();

    let app = router(state);
    let cookie = login(&app).await;
    let response = app
        .oneshot(request("GET", "/admin/profiles", "", Some(&cookie)))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let html = response.into_body().collect().await.unwrap().to_bytes();
    let html = String::from_utf8_lossy(&html);

    // Profile "ready-count" row: 2 ready + 1 ready (in both sources,
    // counted once) = 3. The alive/quarantine/unknown/removed rows
    // and the proxy reachable only through `s-out` are excluded.
    assert!(
        html.contains(">ready-count<"),
        "profile row missing: {html}"
    );
    // Sources count is 1 (only `s-in` is attached). Proxies count is
    // 3 (the ready-only count). They sit in two adjacent
    // `<td class="num">` cells, the same pattern the rest of the
    // table uses.
    let needle = "<td class=\"num\">1</td>\n            <td class=\"num\">3</td>";
    assert!(
        html.contains(needle),
        "expected sources_count=1 and proxies_count=3 adjacent: {html}"
    );
}

#[tokio::test]
async fn probe_screen_shows_heartbeat_meow_and_quarantine_queue() {
    let (_dir, state) = test_state(1000).await;
    let pool = state.pool.clone();
    let now = fumox_core::models::now_ts();

    // Daemon heartbeat and meow contact stamps from meta.
    fumox_core::repo::meta_set(
        &pool,
        "probe_heartbeat",
        &format!(r#"{{"ts":{now},"pid":4242,"version":"0.1.0"}}"#),
    )
    .await
    .unwrap();
    fumox_core::repo::meta_set(&pool, "meow_last_ok", &now.to_string())
        .await
        .unwrap();

    // One quarantined proxy with a scheduled second chance: the
    // ladder stamp is `quarantined_at + 12 h + [0, 4 h) jitter`
    // (proxies.rs), so 1 h in quarantine puts it ~13 h out.
    sqlx::query(
        "INSERT INTO proxies (fingerprint, scheme, name, host, port, credential, status,
                                  quarantined_at, ladder_at, created_at, updated_at)
             VALUES ('fp-q1', 'vless', 'sick-proxy', 'q.example.com', 443, 'c', 'quarantine',
                     ?, ?, 1, 1)",
    )
    .bind(now - 3600)
    .bind(now + 43_200)
    .execute(&pool)
    .await
    .unwrap();

    let app = router(state);
    let cookie = login(&app).await;
    let response = app
        .oneshot(request("GET", "/admin/probe", "", Some(&cookie)))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let html = response.into_body().collect().await.unwrap().to_bytes();
    let html = String::from_utf8_lossy(&html);
    assert!(html.contains("Тестер"));
    assert!(html.contains("4242")); // pid from the heartbeat
    assert!(html.contains("sick-proxy")); // quarantine queue row
    assert!(html.contains("q.example.com"));
    // Every timestamp renders as a <time> element: RFC 3339 UTC in the
    // datetime attribute, the UTC text as the no-JS fallback (the admin
    // JS in base.html rewrites it into the user's timezone).
    assert!(html.contains("<time class=\"ts\" datetime=\""), "{html}");
    assert!(html.contains("Z\">"), "{html}");
    assert!(html.contains("</time>"), "{html}");
    // The "Quarantined (queue)" card uses the real status breakdown,
    // not the truncated 50-row queue: with one quarantined proxy the
    // number is 1.
    assert!(
        html.contains("\"num\">1</div>\n    <div class=\"label\">"),
        "expected quarantine_count=1 to be rendered as the card number: {html}"
    );
}

/// Regression: the quarantine card must show the true population count
/// even when the on-screen queue is truncated to 50 rows. Previously
/// the card showed `queue.len()` (always <= 50), which underreported
/// the population.
#[tokio::test]
async fn probe_quarantine_card_reflects_true_count_not_queue_len() {
    let (_dir, state) = test_state(1000).await;
    let pool = state.pool.clone();
    let now = fumox_core::models::now_ts();

    // 60 quarantined proxies, enough to overflow the LIMIT 50 on the
    // queue view. The card must still read 60.
    for i in 0..60 {
        sqlx::query(
            "INSERT INTO proxies (fingerprint, scheme, name, host, port, credential, status,
                                      quarantined_at, ladder_at, created_at, updated_at)
                 VALUES (?, 'vless', ?, ?, 443, 'c', 'quarantine',
                         ?, ?, 1, 1)",
        )
        .bind(format!("fp-q-{i}"))
        .bind(format!("q{i}"))
        .bind(format!("h{i}.example.com"))
        .bind(now - 3600)
        .bind(now + 43_200 + i)
        .execute(&pool)
        .await
        .unwrap();
    }

    let app = router(state);
    let cookie = login(&app).await;
    let response = app
        .oneshot(request("GET", "/admin/probe", "", Some(&cookie)))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let html = response.into_body().collect().await.unwrap().to_bytes();
    let html = String::from_utf8_lossy(&html);
    // True population (60) wins over the truncated queue (50).
    assert!(
        html.contains("\"num\">60</div>"),
        "expected quarantine card to render the true count of 60: {html}"
    );
    assert!(
        !html.contains("\"num\">50</div>"),
        "card must not render the truncated queue length 50: {html}"
    );
    // The truncation hint is shown only when the count overflows 50.
    // The default language in tests is Russian, so look for the
    // translated substring; either locale would be acceptable.
    assert!(
        html.contains("ближайшие 50 из 50") || html.contains("nearest 50 of 50"),
        "expected truncation hint when quarantine_count > 50: {html}"
    );
}

/// The probe screen's coverage panel partitions the population by
/// check-history buckets and each counter deep-links into the filtered
/// proxy browser.
#[tokio::test]
async fn probe_screen_shows_check_coverage() {
    let (_dir, state) = test_state(1000).await;
    let pool = state.pool.clone();

    sqlx::query(
            "INSERT INTO proxies (fingerprint, scheme, name, host, port, credential, status, created_at, updated_at)
             VALUES ('fp-cv-none', 'vless', 'never-probed', 'h0.example.com', 443, 'c', 'unknown', 1, 1),
                    ('fp-cv-t1', 'vless', 'tcp-only', 'h1.example.com', 443, 'c', 'alive', 1, 1),
                    ('fp-cv-both', 'vless', 'fully-checked', 'h2.example.com', 443, 'c', 'alive', 1, 1)",
        )
        .execute(&pool)
        .await
        .unwrap();
    // One T1 attempt for tcp-only, T1 + T2 for fully-checked; a probe
    // attempt needs its proxy id (rowid order of the insert above).
    sqlx::query(
        "INSERT INTO probe_results (proxy_id, checked_at, ok, latency_ms, error, probe_kind)
             SELECT id, 1, 1, 10, NULL, 'tcp' FROM proxies WHERE fingerprint = 'fp-cv-t1'",
    )
    .execute(&pool)
    .await
    .unwrap();
    for kind in ["tls", "t2"] {
        sqlx::query(
            "INSERT INTO probe_results (proxy_id, checked_at, ok, latency_ms, error, probe_kind)
                 SELECT id, 1, 1, 10, NULL, ? FROM proxies WHERE fingerprint = 'fp-cv-both'",
        )
        .bind(kind)
        .execute(&pool)
        .await
        .unwrap();
    }

    let app = router(state);
    let cookie = login(&app).await;
    let response = app
        .oneshot(request("GET", "/admin/probe", "", Some(&cookie)))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let html = response.into_body().collect().await.unwrap().to_bytes();
    let html = String::from_utf8_lossy(&html);
    // Panel title, bucket labels and one link per bucket.
    assert!(html.contains("Покрытие проверками"), "{html}");
    for label in ["Без проверок", "Только T1", "Только T2", "T1 и T2"] {
        assert!(html.contains(label), "missing bucket label {label}: {html}");
    }
    for bucket in ["none", "t1_only", "t2_only", "both"] {
        assert!(
            html.contains(&format!("?coverage={bucket}\"")),
            "missing link for {bucket}: {html}"
        );
    }
}

/// A handful of quarantined rows (well below `sample_size × 20`)
/// means no heuristic fires; with the default 60-min target the
/// queue fits comfortably, so the page renders the green "fits the
/// target" banner.
#[tokio::test]
async fn probe_screen_shows_ok_banner_when_queue_fits_target() {
    let (_dir, state) = test_state(1000).await;
    let pool = state.pool.clone();
    let now = fumox_core::models::now_ts();

    // The rows are due for a check, so the cycle can retire them,
    // and a row is only due that early if it has been in quarantine
    // at least the second-chance window: the stamp is
    // `quarantined_at + 12 h + [0, 4 h) jitter` (proxies.rs), so
    // 15 h in quarantine with the check just past is a pair the
    // daemon produces, where `now - 3600` / `now - 1` is not.
    for i in 0..5 {
        sqlx::query(
            "INSERT INTO proxies (fingerprint, scheme, name, host, port, credential, status,
                                      quarantined_at, ladder_at, created_at, updated_at)
                 VALUES (?, 'vless', ?, ?, 443, 'c', 'quarantine', ?, ?, 1, 1)",
        )
        .bind(format!("fp-ok-{i}"))
        .bind(format!("q{i}"))
        .bind(format!("h{i}.example"))
        .bind(now - 54_000)
        .bind(now - 1)
        .execute(&pool)
        .await
        .unwrap();
    }

    let app = router(state);
    let cookie = login(&app).await;
    let html = render_get_html(&app, "/admin/probe", &cookie).await;

    assert!(
        html.contains("flash ok") && html.contains("backlog-banner"),
        "green ok banner expected: {html}"
    );
    assert!(
        html.contains("Очередь проверки: в норме"),
        "level label missing: {html}"
    );
    // 5 quarantined and 5 due: retire = min(50, 5) = 5 per cycle,
    // lane = ceil(5/8) x 20s = 20s <= the 60s interval, so one
    // cycle drains the queue - 1 min, well inside the 60-min
    // default target.
    assert!(
        html.contains("осушение за ~1 мин"),
        "current drain not mentioned: {html}"
    );
    assert!(
        html.contains("цель: 60 мин"),
        "target not mentioned: {html}"
    );
    // No warning or danger variants on this page.
    assert!(
        !html.contains("flash warning") && !html.contains("flash danger"),
        "no warning/danger expected: {html}"
    );
    assert!(
        !html.contains("Рекомендации"),
        "no recommendations block expected: {html}"
    );
}

/// With the target tightened so low that even the smallest queue
/// cannot drain in time, no hard heuristic trips but the page must
/// still show a warning banner with the `drain_over_target` factor
/// and a recommendation.
#[tokio::test]
async fn probe_screen_warns_when_drain_exceeds_target() {
    let (_dir, state) = test_state(1000).await;
    // The backlog target now lives in the single live config view:
    // write a file that tightens it and refresh, the same path a
    // settings save takes.
    let dir = fumox_core::tempdir_lite::TempDir::new("probe-drain");
    let path = dir.path().join("app.toml");
    // The login check reads the live config, so the refreshed file
    // must carry the test token: a config file without `[admin]`
    // loads the built-in default and the login below would 422.
    std::fs::write(
        &path,
        format!("[probe]\nbacklog_target_drain_minutes = 1\n\n[admin]\ntoken = \"{TOKEN}\"\n"),
    )
    .unwrap();
    state
        .refresh_live_config(&path)
        .expect("file we just wrote must load cleanly");
    let pool = state.pool.clone();
    let now = fumox_core::models::now_ts();

    // 51 rows *due*: retire = min(50, 51) = 50, lane =
    // ceil(50/8) x 20s = 140s > the 60s interval, so the period
    // is 140s and 2 cycles take 5 min against the 1-min target.
    // None of the hard heuristic thresholds fire at this size, so
    // the banner is driven by the soft drain-vs-target check.
    for i in 0..51 {
        sqlx::query(
            "INSERT INTO proxies (fingerprint, scheme, name, host, port, credential, status,
                                      quarantined_at, ladder_at, created_at, updated_at)
                 VALUES (?, 'vless', ?, ?, 443, 'c', 'quarantine', ?, ?, 1, 1)",
        )
        .bind(format!("fp-tight-{i}"))
        .bind(format!("t{i}"))
        .bind(format!("h{i}.example"))
        .bind(now - 54_000)
        .bind(now - 1)
        .execute(&pool)
        .await
        .unwrap();
    }

    let app = router(state);
    let cookie = login(&app).await;
    let html = render_get_html(&app, "/admin/probe", &cookie).await;

    assert!(
        html.contains("flash warning") && html.contains("backlog-banner"),
        "warning banner expected when target unreachable: {html}"
    );
    assert!(
        !html.contains("flash danger"),
        "danger banner is not warranted at this size: {html}"
    );
    assert!(html.contains("Очередь проверки:"), "title missing: {html}");
    assert!(
        html.contains("drain_over_target") || html.contains("превышает цель"),
        "drain_over_target factor missing: {html}"
    );
    assert!(
        html.contains("Рекомендации"),
        "recommendations block expected: {html}"
    );
}

/// `quarantine_count > sample_size × 20` lights the `deep_queue`
/// factor and, when drain time exceeds the target, surfaces a
/// concrete `[probe].sample_size` recommendation.
#[tokio::test]
async fn probe_screen_warns_on_deep_queue_with_recommendation() {
    let (_dir, state) = test_state(1000).await;
    let pool = state.pool.clone();
    let now = fumox_core::models::now_ts();

    // 4000 quarantined rows, all due (ladder_at <= now), and 15 h
    // into quarantine so that pair is one the ladder produces: a
    // fresh quarantine is stamped 12-16 h out, a row cannot be due
    // one hour in. With the defaults (sample_size=50,
    // concurrency=8, connect+tls=20s) the quarantine lane takes
    // ceil(50/8) x 20s = 140s, past the 60s interval, so the period
    // is 140s and 80 cycles take 187 min - over the 60-min target,
    // so recommendations show.
    sqlx::query(
        "INSERT INTO proxies
                 (fingerprint, scheme, name, host, port, credential, status,
                  quarantined_at, ladder_at, created_at, updated_at)
             SELECT 'fp-deep-' || x, 'vless', 'd' || x, 'h' || x || '.example',
                    443, 'c', 'quarantine', ?, ?, 1, 1
             FROM (WITH RECURSIVE seq(n) AS (SELECT 1 UNION ALL SELECT n+1 FROM seq WHERE n < 4000)
                   SELECT n AS x FROM seq)",
    )
    .bind(now - 54_000)
    .bind(now - 1)
    .execute(&pool)
    .await
    .unwrap();

    let app = router(state);
    let cookie = login(&app).await;
    let html = render_get_html(&app, "/admin/probe", &cookie).await;

    assert!(
        html.contains("flash warning") && html.contains("backlog-banner"),
        "warning banner expected: {html}"
    );
    assert!(html.contains("Очередь проверки:"), "title missing: {html}");
    assert!(
        html.contains("В карантине 4000"),
        "deep_queue factor missing: {html}"
    );
    assert!(
        html.contains("Рекомендации для осушения за ~60 мин"),
        "recs head missing: {html}"
    );
    // required_sample = ceil(4000 × 140 / 3600) = 156, capped by the
    // 4000 rows that can be due. The label is localized.
    assert!(
        html.contains("[probe].sample_size = 156"),
        "sample_size recommendation missing or wrong: {html}"
    );
    assert!(
        html.contains("(сейчас 50)"),
        "current value should appear in the localized rec: {html}"
    );
    // Chained on that sample: ceil(156/52) x 20s = 60s, which fits
    // the 60s period, so applying both recs keeps the cycle on
    // schedule.
    assert!(
        html.contains("[probe].concurrency = 52"),
        "concurrency recommendation missing or wrong: {html}"
    );
}

/// One quarantined row that's older than `queue_stale_days × 0.8`
/// triggers a `danger` banner with the `stale_oldest` factor.
#[tokio::test]
async fn probe_screen_danger_on_stale_oldest_row() {
    let (_dir, state) = test_state(1000).await;
    let pool = state.pool.clone();
    let now = fumox_core::models::now_ts();

    sqlx::query(
        "INSERT INTO proxies (fingerprint, scheme, name, host, port, credential, status,
                                  quarantined_at, ladder_at, created_at, updated_at)
             VALUES ('fp-stale-1', 'vless', 'stale', 's.example', 443, 'c', 'quarantine',
                     ?, ?, 1, 1)",
    )
    .bind(now - 30 * 86_400) // 30 days ago
    .bind(now - 1) // its check came due long ago; the ladder re-stamps it
    .execute(&pool)
    .await
    .unwrap();

    let app = router(state);
    let cookie = login(&app).await;
    let html = render_get_html(&app, "/admin/probe", &cookie).await;

    assert!(
        html.contains("flash danger") && html.contains("backlog-banner"),
        "danger banner expected: {html}"
    );
    assert!(
        html.contains("устаревает после 7"),
        "stale_oldest factor with limit=7 missing: {html}"
    );
}

/// 300 quarantined rows that are all *due now* trip the
/// `due_overflow` heuristic (300 > 50 × 5). The total is below
/// the `deep_queue` threshold, so only `due_overflow` should fire.
#[tokio::test]
async fn probe_screen_warns_on_due_overflow() {
    let (_dir, state) = test_state(1000).await;
    let pool = state.pool.clone();
    let now = fumox_core::models::now_ts();

    sqlx::query(
        "INSERT INTO proxies
                 (fingerprint, scheme, name, host, port, credential, status,
                  quarantined_at, ladder_at, created_at, updated_at)
             SELECT 'fp-due-' || x, 'vless', 'd' || x, 'h' || x || '.example',
                    443, 'c', 'quarantine', ?, ?, 1, 1
             FROM (WITH RECURSIVE seq(n) AS (SELECT 1 UNION ALL SELECT n+1 FROM seq WHERE n < 300)
                   SELECT n AS x FROM seq)",
    )
    .bind(now - 54_000)
    .bind(now - 1)
    .execute(&pool)
    .await
    .unwrap();

    let app = router(state);
    let cookie = login(&app).await;
    let html = render_get_html(&app, "/admin/probe", &cookie).await;

    assert!(html.contains("backlog-banner"), "banner expected: {html}");
    assert!(
        html.contains("Готово к проверке 300"),
        "due_overflow factor missing: {html}"
    );
    assert!(
        html.contains("за цикл берётся 50"),
        "sample value in due_overflow missing: {html}"
    );
    // Drain time at 300/50 × 60s = 6 min, comfortably below the
    // 60-min target, no recommendations block.
    assert!(
        !html.contains("Рекомендации"),
        "no recs expected at this depth: {html}"
    );
}

/// A queue the ladder has not released yet is not a queue that
/// needs draining. 800 quarantined rows whose `ladder_at` is in the
/// future (a fresh quarantine is stamped 12-16 h out) make the
/// cycle pick up nothing, so the banner says so instead of
/// estimating a drain it cannot support or recommending a knob
/// that would change nothing. 800 rows is under the `deep_queue`
/// threshold, so the idle wording is the only state on offer.
#[tokio::test]
async fn probe_screen_drain_figure_ignores_rows_that_are_not_due() {
    let (_dir, state) = test_state(1000).await;
    let pool = state.pool.clone();
    let now = fumox_core::models::now_ts();

    sqlx::query(
        "INSERT INTO proxies
                 (fingerprint, scheme, name, host, port, credential, status,
                  quarantined_at, ladder_at, created_at, updated_at)
             SELECT 'fp-notdue-' || x, 'vless', 'n' || x, 'h' || x || '.example',
                    443, 'c', 'quarantine', ?, ?, 1, 1
             FROM (WITH RECURSIVE seq(n) AS (SELECT 1 UNION ALL SELECT n+1 FROM seq WHERE n < 800)
                   SELECT n AS x FROM seq)",
    )
    .bind(now - 3600)
    .bind(now + 43_200)
    .execute(&pool)
    .await
    .unwrap();

    let app = router(state);
    let cookie = login(&app).await;
    let html = render_get_html(&app, "/admin/probe", &cookie).await;

    assert!(html.contains("backlog-banner"), "banner expected: {html}");
    assert!(
        html.contains("за цикл не берётся ни одной строки"),
        "all_idle factor missing: {html}"
    );
    assert!(
        html.contains("800 в карантине"),
        "quarantine count missing from the idle line: {html}"
    );
    assert!(
        !html.contains("drain_over_target") && !html.contains("превышает цель"),
        "no drain figure exists to exceed the target: {html}"
    );
    assert!(
        !html.contains("Рекомендации"),
        "no knob can drain a queue that is not due: {html}"
    );
}

/// No heartbeat for 600 s (> `heartbeat_interval_secs × 3 = 90 s`)
/// trips the `heartbeat_dead` danger factor.
#[tokio::test]
async fn probe_screen_warns_on_dead_heartbeat() {
    let (_dir, state) = test_state(1000).await;
    let pool = state.pool.clone();
    let now = fumox_core::models::now_ts();

    fumox_core::repo::meta_set(
        &pool,
        "probe_heartbeat",
        &format!(r#"{{"ts":{},"pid":1,"version":"x"}}"#, now - 600),
    )
    .await
    .unwrap();

    let app = router(state);
    let cookie = login(&app).await;
    let html = render_get_html(&app, "/admin/probe", &cookie).await;

    assert!(
        html.contains("flash danger") && html.contains("backlog-banner"),
        "danger banner expected: {html}"
    );
    // The age is recomputed from the wall clock at render time
    // (handlers/probe.rs), so assert a range, not an exact string.
    let secs = regex::Regex::new(r"Heartbeat тестера отсутствует (\d+) с")
        .expect("valid regex")
        .captures(&html)
        .and_then(|caps| caps.get(1))
        .map(|m| m.as_str().parse::<i64>().unwrap())
        .unwrap_or_else(|| panic!("heartbeat_dead factor missing: {html}"));
    assert!(
        (600..=660).contains(&secs),
        "heartbeat age {secs} s outside the seeded 600 s window: {html}"
    );
}

/// GET helper, runs a request through the router and returns the
/// collected body as a UTF-8 string. The probe tests only need the
/// body, so this trims the boilerplate around `oneshot` /
/// `into_body().collect()`.
async fn render_get_html(app: &axum::Router, uri: &str, cookie: &str) -> String {
    let response = app
        .clone()
        .oneshot(request("GET", uri, "", Some(cookie)))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    String::from_utf8_lossy(&body).into_owned()
}

/// The proxy browser filters by check-coverage bucket and renders the
/// Checks column; a garbage bucket value degrades to "no filter".
#[tokio::test]
async fn proxies_list_filters_by_check_coverage() {
    let (_dir, state) = test_state(1000).await;
    let pool = state.pool.clone();

    // Four proxies, one per bucket.
    sqlx::query(
            "INSERT INTO proxies (fingerprint, scheme, name, host, port, credential, status, created_at, updated_at)
             VALUES ('fp-l-none', 'vless', 'untouched', 'h0.example.com', 443, 'c', 'unknown', 1, 1),
                    ('fp-l-t1', 'vless', 'tcp-only', 'h1.example.com', 443, 'c', 'unknown', 1, 1),
                    ('fp-l-t2', 'vless', 'tunnel-only', 'h2.example.com', 443, 'c', 'unknown', 1, 1),
                    ('fp-l-both', 'vless', 'fully-checked', 'h3.example.com', 443, 'c', 'unknown', 1, 1)",
        )
        .execute(&pool)
        .await
        .unwrap();
    for (fingerprint, kind) in [
        ("fp-l-t1", "tcp"),
        ("fp-l-t2", "t2"),
        ("fp-l-both", "tcp"),
        ("fp-l-both", "t2"),
    ] {
        sqlx::query(
            "INSERT INTO probe_results (proxy_id, checked_at, ok, latency_ms, error, probe_kind)
                 SELECT id, 1, 1, 10, NULL, ? FROM proxies WHERE fingerprint = ?",
        )
        .bind(kind)
        .bind(fingerprint)
        .execute(&pool)
        .await
        .unwrap();
    }

    let app = router(state);
    let cookie = login(&app).await;

    // Every bucket selects exactly its proxy; a garbage bucket value is
    // tolerated (no filter, all four rows).
    for (query, expect, absent) in [
        ("?coverage=none", "untouched", "tcp-only"),
        ("?coverage=t1_only", "tcp-only", "untouched"),
        ("?coverage=t2_only", "tunnel-only", "untouched"),
        ("?coverage=both", "fully-checked", "untouched"),
        ("?coverage=everything", "fully-checked", "no-such-proxy"),
    ] {
        let response = app
            .clone()
            .oneshot(request(
                "GET",
                &format!("/admin/proxies{query}"),
                "",
                Some(&cookie),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK, "query {query}");
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        let html = String::from_utf8_lossy(&bytes);
        assert!(html.contains(expect), "{expect} missing for {query}");
        assert!(!html.contains(absent), "{absent} leaked into {query}");
    }

    // The Checks column marks a proxy with both tiers in its history.
    let response = app
        .oneshot(request(
            "GET",
            "/admin/proxies?coverage=both",
            "",
            Some(&cookie),
        ))
        .await
        .unwrap();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let html = String::from_utf8_lossy(&bytes);
    assert!(html.contains("T1+T2"), "the Checks column: {html}");
}

/// The settings screen renders every state-machine section with the
/// configured values and the restart banner.
#[tokio::test]
async fn settings_screen_shows_effective_config_sections() {
    let (_dir, state) = test_state(1000).await;
    let probe = state.probe();
    let ingest = state.ingest();
    let meow = state.meow();
    let retention = state.retention();
    let fetch = state.fetch();
    let database = state.database();
    let admin = state.admin();
    let log = state.log();
    let app = router(state);
    let cookie = login(&app).await;
    let response = app
        .oneshot(request("GET", "/admin/settings", "", Some(&cookie)))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let html = response.into_body().collect().await.unwrap().to_bytes();
    let html = String::from_utf8_lossy(&html);
    // Owner-process badges and the config-file banner.
    assert!(html.contains("config/app.toml"), "{html}");
    assert!(html.contains("probe"), "{html}");
    assert!(html.contains("server"), "{html}");
    // The configured ladder renders as the localized sentence (the
    // default UI language is Russian), including the second chance, the
    // first delay and the terminal removal step.
    assert!(html.contains("Второй шанс"), "{html}");
    assert!(html.contains("15 мин"), "{html}");
    assert!(html.contains("удаление"), "{html}");
    // Sections exist.
    for key_value in [
        probe.fail_limit.to_string(),
        probe.sample_size.to_string(),
        ingest.refresh_check_limit.to_string(),
        meow.backoff_max_secs.to_string(),
        retention.probe_results_days.to_string(),
    ] {
        assert!(html.contains(&key_value), "missing {key_value}: {html}");
    }
    // The full `[ingest]` trio: the revived-row toggle is shown with its
    // localized label next to the effective value.
    assert!(
        html.contains("Возвращать удаленные прокси"),
        "the removed_as_unknown label: {html}"
    );
    assert!(
        html.contains(&ingest.removed_as_unknown.to_string()),
        "{html}"
    );
    // The `[fetch]` panel: the localized title, the User-Agent and the
    // human-readable response cap.
    assert!(html.contains("Загрузка по HTTP"), "the fetch panel: {html}");
    assert!(html.contains(fetch.user_agent.as_str()), "{html}");
    assert!(html.contains(fetch.ip_family.as_str()), "{html}");
    assert!(html.contains("10 MiB"), "{html}");
    // The remaining sections render with their localized titles; the
    // rate limits come back in the canonical config form.
    for title in [
        "Публичный слушатель",
        "База данных",
        "Гео-обогащение",
        "Админка",
        "Уровни консольных логов",
    ] {
        assert!(html.contains(title), "missing panel {title}: {html}");
    }
    assert!(
        html.contains("Соединяться с приватными адресами"),
        "the allow_private_targets label: {html}"
    );
    assert!(html.contains("300/min"), "public rate limit: {html}");
    assert!(
        html.contains(database.busy_timeout_ms.to_string().as_str()),
        "{html}"
    );
    assert!(html.contains(log.server.as_str()), "{html}");
    // The admin token is a secret, it must never reach the page.
    assert!(!html.contains(&admin.token), "token leaked: {html}");
}

/// Two sources with proxies in every status plus probe history; the
/// dashboard (the former stats screen merged in) must render the
/// per-source health counters, the
/// longest-living top and the 24h probe success rate, with the
/// source-errors block above everything else and no "recent fetches"
/// table anymore.
#[tokio::test]
async fn dashboard_aggregates_stats_and_leads_with_source_errors() {
    let (_dir, state) = test_state(1000).await;
    let pool = state.pool.clone();
    let now = fumox_core::models::now_ts();
    for id in ["srcS0000001", "srcS0000002"] {
        let source = fumox_core::models::Source {
            id: id.into(),
            slug: None,
            name: format!("source {id}"),
            url: "https://example.com/sub".into(),
            enabled: true,
            encoding: Default::default(),
            input_format: None,
            protocols: None,
            cache_ttl_seconds: 3600,
            tags: None,
            pipeline: None,
            headers: None,
            ip_family: None,
            created_at: now,
            updated_at: now,
            last_fetched_at: None,
            last_error: None,
            error_class: None,
        };
        fumox_core::repo::sources::create(&pool, &source)
            .await
            .unwrap();
    }

    // (fingerprint, source, status, age seconds, latency, country)
    let rows = [
        (
            "fp-veteran",
            "srcS0000001",
            "alive",
            500_000,
            Some(90),
            Some("DE"),
        ),
        (
            "fp-veteran-ready",
            "srcS0000001",
            "ready",
            500_000,
            Some(80),
            Some("DE"),
        ),
        (
            "fp-fast",
            "srcS0000001",
            "alive",
            4_000,
            Some(15),
            Some("DE"),
        ),
        (
            "fp-sick",
            "srcS0000001",
            "quarantine",
            100_000,
            None,
            Some("US"),
        ),
        ("fp-new", "srcS0000001", "unknown", 600, None, None),
        (
            "fp-dead",
            "srcS0000001",
            "removed",
            900_000,
            None,
            Some("US"),
        ),
        ("fp-tuic", "srcS0000002", "unknown", 50_000, None, None),
    ];
    for (fp, source, status, age, latency, country) in rows {
        sqlx::query(
            "INSERT INTO proxies (fingerprint, scheme, name, host, port, credential,
                                      status, latency_ms, geo_country, created_at, updated_at)
                 VALUES (?, ?, ?, 'h.example.com', 443, 'c', ?, ?, ?, ?, ?)",
        )
        .bind(fp)
        .bind(if fp == "fp-tuic" { "tuic" } else { "vless" })
        .bind(fp)
        .bind(status)
        .bind(latency)
        .bind(country)
        .bind(now - age)
        .bind(now)
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO proxy_source_links (proxy_id, source_id, seen_at)
                 SELECT id, ?, ? FROM proxies WHERE fingerprint = ?",
        )
        .bind(source)
        .bind(now)
        .bind(fp)
        .execute(&pool)
        .await
        .unwrap();
    }

    // Probe history: 2 ok + 1 fail over the last hour.
    for (ok, latency) in [(1, Some(90)), (1, Some(120)), (0, None)] {
        let proxy_id: i64 =
            sqlx::query_scalar("SELECT id FROM proxies WHERE fingerprint = 'fp-veteran'")
                .fetch_one(&pool)
                .await
                .unwrap();
        sqlx::query(
            "INSERT INTO probe_results (proxy_id, checked_at, ok, latency_ms, probe_kind)
                 VALUES (?, ?, ?, ?, 'tcp')",
        )
        .bind(proxy_id)
        .bind(now - 600)
        .bind(ok)
        .bind(latency)
        .execute(&pool)
        .await
        .unwrap();
    }

    let app = router(state);
    let cookie = login(&app).await;
    let response = app
        .clone()
        .oneshot(request("GET", "/admin", "", Some(&cookie)))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let html = response.into_body().collect().await.unwrap().to_bytes();
    let html = String::from_utf8_lossy(&html).into_owned();

    // The merged page renders every former stats panel.
    assert!(html.contains("Обзор"), "{html}");
    assert!(html.contains("Прокси по источникам"), "{html}");
    assert!(html.contains("Самые готовые прокси"), "{html}");
    // The new Top-N picker renders the default 10 selected.
    assert!(html.contains("Показать топ:"), "{html}");
    // The new Top Failure Reasons panel renders even when empty.
    assert!(html.contains("Топ причин отказов"), "{html}");
    // The "recent fetches" table is gone from the dashboard; the
    // source-errors block leads the screen.
    let errors_at = html.find("Источники с ошибками").expect("errors block");
    let stats_at = html.find("Прокси по источникам").expect("per-source block");
    assert!(errors_at < stats_at, "source errors must render first");
    assert!(!html.contains("Последние загрузки"), "{html}");
    // Per-source counters: source 1 has 2 alive, source 2 has 1 unknown.
    assert!(html.contains("source srcS0000001"), "{html}");
    assert!(html.contains("source srcS0000002"), "{html}");
    // Probe success rate: 2/3.
    assert!(html.contains("2 / 3"), "{html}");
    // The veteran (oldest alive) tops the longevity list.
    assert!(html.contains("fp-veteran"), "{html}");
    // Unprobeable counter includes the tuic proxy.
    assert!(html.contains("непроверяемых (tuic/mieru): 1"), "{html}");
    // Both latencies feed the min/avg card.
    assert!(html.contains("мин: 15"), "{html}");
    assert!(html.contains("ср: 52"), "{html}");
}

/// Proxy-card geo refresh: opening the
/// card resolves the host against every GeoLite2 database in the
/// workspace `config/` and stores the country/city/ASN facts plus the
/// resolved IP; without them the card renders the stored facts as-is
/// (and never wipes them). Skipped in CI (no .mmdb files there).
#[tokio::test]
async fn proxy_card_refreshes_geo_facts_on_open() {
    // The workspace config/ directory with the gitignored .mmdb files;
    // when absent (CI) the test exercises the no-databases degradation.
    let db_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../config")
        .canonicalize()
        .unwrap();
    let geo_cfg = fumox_core::config::GeoConfig {
        enabled: false, // pipeline resolver stays inactive, irrelevant here
        db_dir: db_dir.clone(),
        ..Default::default()
    };

    // Build the state directly (test_state pins db_dir to "config"
    // relative to the crate working directory).
    let dir = fumox_core::tempdir_lite::TempDir::new("admin-geo");
    let db_cfg = fumox_core::config::DatabaseConfig {
        path: dir.path().join("test.db"),
        ..Default::default()
    };
    let pool = fumox_core::db::connect_pool(&db_cfg).await.unwrap();
    fumox_core::db::migrate(&pool).await.unwrap();
    let (refresh_tx, refresh_rx) = tokio::sync::mpsc::unbounded_channel();
    std::mem::forget(refresh_rx);
    let config = fumox_core::AppConfig {
        admin: admin_config(1000),
        geo: geo_cfg,
        ..Default::default()
    };
    let fetcher = Fetcher::new(
        config.fetch.clone(),
        config.admin.allow_private_urls,
        config.geo.dns_timeout(),
    );
    let state = AdminState::new(
        pool.clone(),
        crate::cache::Caches::new(),
        Arc::new(GeoResolver::new(&fumox_core::config::GeoConfig {
            enabled: false,
            ..Default::default()
        })),
        refresh_tx,
        SchedulerState::new(1),
        EventBus::new(),
        fetcher,
        config,
        ResolvedConfigPath::Missing,
    );
    let has_dbs = state.geo_full.is_active();

    let now = fumox_core::models::now_ts();
    sqlx::query(
        "INSERT INTO proxies (fingerprint, scheme, name, host, port, credential,
                                  status, created_at, updated_at)
             VALUES ('fp-geo-8.8.8.8', 'vless', 'geo-test', '8.8.8.8', 443, 'c', 'unknown', ?, ?)",
    )
    .bind(now)
    .bind(now)
    .execute(&pool)
    .await
    .unwrap();
    let id: i64 = sqlx::query_scalar("SELECT id FROM proxies WHERE host = '8.8.8.8'")
        .fetch_one(&pool)
        .await
        .unwrap();

    // Opening the card is the whole interaction, no button, no POST.
    let app = router(state);
    let cookie = login(&app).await;
    let response = app
        .clone()
        .oneshot(request(
            "GET",
            &format!("/admin/proxies/{id}"),
            "",
            Some(&cookie),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let html = response.into_body().collect().await.unwrap().to_bytes();
    let html = String::from_utf8_lossy(&html).into_owned();
    // The geography block renders (the card, not a swap fragment).
    assert!(
        html.contains("px.geography") || html.contains("География"),
        "{html}"
    );
    assert!(!html.contains("resolve-geo"), "the button is gone: {html}");

    let row = fumox_core::repo::proxies::get_by_id(&pool, id)
        .await
        .unwrap()
        .expect("proxy row");
    if has_dbs {
        // The resolver had the databases: the row now carries the
        // country, the resolved IP and ASN facts, and the card shows
        // them.
        assert_eq!(row.geo_country.as_deref(), Some("US"));
        assert_eq!(row.resolved_ip.as_deref(), Some("8.8.8.8"));
        let asn = row
            .geo_asn
            .clone()
            .expect("ASN database present, ASN expected");
        assert!(asn.starts_with("AS"), "asn format: {asn}");
        assert!(html.contains("AS"), "card shows the ASN: {html}");
        assert!(html.contains("8.8.8.8"), "card shows the IP: {html}");
    } else {
        // Without the databases the card renders the stored facts
        // (none here) and never wipes anything.
        assert_eq!(row.geo_country, None);
    }
}

#[tokio::test]
async fn purge_removed_deletes_only_removed_proxies() {
    let (_dir, state) = test_state(1000).await;
    let pool = state.pool.clone();
    for (fp, status) in [("fp-dead", "removed"), ("fp-live", "alive")] {
        sqlx::query(
                "INSERT INTO proxies (fingerprint, scheme, name, host, port, credential, status, created_at, updated_at)
                 VALUES (?, 'vless', 'n', 'h.example.com', 443, 'c', ?, 1, 1)",
            )
            .bind(fp)
            .bind(status)
            .execute(&pool)
            .await
            .unwrap();
    }

    let app = router(state.clone());
    let cookie = login(&app).await;
    let csrf = csrf_for(&state, &cookie);
    let response = app
        .oneshot(request(
            "POST",
            "/admin/proxies/purge-removed",
            &format!("_csrf={csrf}"),
            Some(&cookie),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SEE_OTHER);

    let remaining: Vec<(String,)> =
        sqlx::query_as("SELECT fingerprint FROM proxies ORDER BY fingerprint")
            .fetch_all(&pool)
            .await
            .unwrap();
    assert_eq!(remaining, vec![("fp-live".to_string(),)]);
}

/// Seed one proxy row for the bulk-cleanup tests; returns its id.
async fn seed_cleanup_proxy(
    pool: &fumox_core::db::DbPool,
    fp: &str,
    scheme: &str,
    status: &str,
    geo_country: Option<&str>,
    geo_asn: Option<&str>,
) -> i64 {
    let (id,): (i64,) = sqlx::query_as(
        "INSERT INTO proxies
                 (fingerprint, scheme, name, host, port, credential, params,
                  unknown_params, raw_line, geo_country, geo_asn,
                  status, fail_count, quarantined_at, ladder_step, created_at, updated_at)
             VALUES (?, ?, ?, ?, 443, '', '{}', '{}', '', ?, ?, ?, 0, NULL, 0, 1, 1)
             RETURNING id",
    )
    .bind(fp)
    .bind(scheme)
    .bind(fp)
    .bind(format!("{fp}.example.com"))
    .bind(geo_country)
    .bind(geo_asn)
    .bind(status)
    .fetch_one(pool)
    .await
    .unwrap();
    id
}

async fn status_by_fp(pool: &fumox_core::db::DbPool, fp: &str) -> String {
    let (status,): (String,) = sqlx::query_as("SELECT status FROM proxies WHERE fingerprint = ?")
        .bind(fp)
        .fetch_one(pool)
        .await
        .unwrap();
    status
}

#[tokio::test]
async fn quarantine_to_removed_moves_only_quarantined_rows() {
    let (_dir, state) = test_state(1000).await;
    let pool = state.pool.clone();
    seed_cleanup_proxy(&pool, "fp-q", "vless", "quarantine", Some("DE"), None).await;
    seed_cleanup_proxy(&pool, "fp-a", "vless", "alive", Some("DE"), None).await;
    seed_cleanup_proxy(&pool, "fp-r", "vless", "removed", Some("DE"), None).await;

    let app = router(state.clone());
    let cookie = login(&app).await;
    let csrf = csrf_for(&state, &cookie);
    let response = app
        .oneshot(request(
            "POST",
            "/admin/proxies/quarantine-to-removed",
            &format!("_csrf={csrf}"),
            Some(&cookie),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SEE_OTHER);

    assert_eq!(status_by_fp(&pool, "fp-q").await, "removed");
    assert_eq!(status_by_fp(&pool, "fp-a").await, "alive");
    assert_eq!(status_by_fp(&pool, "fp-r").await, "removed");
    let (removed_at,): (Option<i64>,) =
        sqlx::query_as("SELECT removed_at FROM proxies WHERE fingerprint = 'fp-q'")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(removed_at.is_some(), "removed_at must be stamped");
}

/// A reconcile-retired row is refused by the repo (no source link,
/// so no probe lane can reach it), and the answer used to be a 404
/// telling the operator the proxy does not exist. It exists: it is
/// on the screen the click came from. The refusal is reported as a
/// rejected action, the row is left exactly as it was, and a row that
/// really is gone still 404s.
#[tokio::test]
async fn reset_of_a_row_no_probe_lane_can_reach_is_reported_not_called_missing() {
    let (_dir, state) = test_state(1000).await;
    let pool = state.pool.clone();
    // No proxy_source_links row: reconciliation retired it, so every
    // lane's link predicate filters it out.
    sqlx::query(
        "INSERT INTO proxies (fingerprint, scheme, name, host, port, credential,
                                  status, quarantined_at, created_at, updated_at)
             VALUES ('fp-orphan', 'vless', 'n', 'orphan.example.com', 443, 'c',
                     'quarantine', 111, 1, 1)",
    )
    .execute(&pool)
    .await
    .unwrap();
    let id: i64 = sqlx::query_scalar("SELECT id FROM proxies WHERE fingerprint = 'fp-orphan'")
        .fetch_one(&pool)
        .await
        .unwrap();

    let app = router(state.clone());
    let cookie = login(&app).await;
    let csrf = csrf_for(&state, &cookie);
    let session = format!("{cookie}; fumox_lang=en");
    let mut req = request(
        "POST",
        &format!("/admin/proxies/{id}/reset"),
        &format!("_csrf={csrf}"),
        Some(&session),
    );
    req.headers_mut()
        .insert("HX-Request", "true".parse().unwrap());
    let response = app.clone().oneshot(req).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let trigger = response
        .headers()
        .get("HX-Trigger")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_string();
    assert!(trigger.contains("\"level\": \"error\""), "{trigger}");
    // The toast rides percent-encoded, so compare on the decoded text:
    // the message must be the refusal, not `proxy not found`.
    let toast = percent_decode(&trigger);
    let en = state.locales.resolve("en");
    assert!(toast.contains(en.t("px.reset_unreachable")), "{toast}");
    assert!(!toast.contains("proxy not found"), "{toast}");
    // The status the click was refused for is the one that stays.
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let body = String::from_utf8_lossy(&body).into_owned();
    assert!(body.contains("badge quarantine"), "{body}");
    let (status, quarantined_at): (String, Option<i64>) =
        sqlx::query_as("SELECT status, quarantined_at FROM proxies WHERE id = ?")
            .bind(id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(status, "quarantine");
    assert_eq!(quarantined_at, Some(111), "the row must be untouched");

    // A row that is genuinely gone is still a 404.
    let mut req = request(
        "POST",
        &format!("/admin/proxies/{}/reset", id + 1000),
        &format!("_csrf={csrf}"),
        Some(&session),
    );
    req.headers_mut()
        .insert("HX-Request", "true".parse().unwrap());
    let response = app.oneshot(req).await.unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn cleanup_htmx_answer_carries_toast_and_fragment() {
    let (_dir, state) = test_state(1000).await;
    let pool = state.pool.clone();
    seed_cleanup_proxy(&pool, "fp-q", "vless", "quarantine", None, None).await;

    let app = router(state.clone());
    let cookie = login(&app).await;
    let csrf = csrf_for(&state, &cookie);
    let mut req = request(
        "POST",
        "/admin/proxies/quarantine-to-removed",
        &format!("_csrf={csrf}"),
        Some(&cookie),
    );
    req.headers_mut()
        .insert("HX-Request", "true".parse().unwrap());
    let response = app.oneshot(req).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let trigger = response
        .headers()
        .get("HX-Trigger")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_string();
    assert!(trigger.contains("\"level\": \"ok\""), "{trigger}");
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let body = String::from_utf8_lossy(&body).into_owned();
    assert!(body.contains("badge removed"), "{body}");

    assert_eq!(status_by_fp(&pool, "fp-q").await, "removed");
}

#[tokio::test]
async fn cleanup_by_asn_validates_input_and_matches_stored_format() {
    let (_dir, state) = test_state(1000).await;
    let pool = state.pool.clone();
    seed_cleanup_proxy(
        &pool,
        "fp-ashet",
        "vless",
        "alive",
        Some("DE"),
        Some("AS24940"),
    )
    .await;
    seed_cleanup_proxy(
        &pool,
        "fp-asno",
        "vless",
        "alive",
        Some("DE"),
        Some("AS9009"),
    )
    .await;

    let app = router(state.clone());
    let cookie = login(&app).await;
    let csrf = csrf_for(&state, &cookie);

    // Invalid input: nothing changes, the HTMX toast reports the error.
    let mut req = request(
        "POST",
        "/admin/proxies/remove-alive-by-asn",
        &format!("_csrf={csrf}&asn=not-a-number"),
        Some(&cookie),
    );
    req.headers_mut()
        .insert("HX-Request", "true".parse().unwrap());
    let response = app.clone().oneshot(req).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let trigger = response
        .headers()
        .get("HX-Trigger")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_string();
    assert!(trigger.contains("\"level\": \"error\""), "{trigger}");
    assert_eq!(status_by_fp(&pool, "fp-ashet").await, "alive");

    // Bare number and AS prefix both work.
    for asn in ["24940", "AS24940"] {
        let response = app
            .clone()
            .oneshot(request(
                "POST",
                "/admin/proxies/remove-alive-by-asn",
                &format!("_csrf={csrf}&asn={asn}"),
                Some(&cookie),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
    }
    assert_eq!(status_by_fp(&pool, "fp-ashet").await, "removed");
    assert_eq!(status_by_fp(&pool, "fp-asno").await, "alive");

    // The badge fragment must substitute the catalog's {asn} into "AS{asn}".
    seed_cleanup_proxy(
        &pool,
        "fp-asfrag",
        "vless",
        "alive",
        Some("DE"),
        Some("AS3333"),
    )
    .await;
    let mut req = request(
        "POST",
        "/admin/proxies/remove-alive-by-asn",
        &format!("_csrf={csrf}&asn=3333"),
        Some(&cookie),
    );
    req.headers_mut()
        .insert("HX-Request", "true".parse().unwrap());
    let response = app.oneshot(req).await.unwrap();
    let body = String::from_utf8_lossy(
        response
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .as_ref(),
    )
    .into_owned();
    assert!(
        body.contains("AS3333"),
        "fragment must name the ASN: {body}"
    );
    assert!(!body.contains("AS{n}"), "placeholder leaked: {body}");
    assert_eq!(status_by_fp(&pool, "fp-asfrag").await, "removed");
}

#[tokio::test]
async fn cleanup_by_country_validates_input_and_targets_alive_only() {
    let (_dir, state) = test_state(1000).await;
    let pool = state.pool.clone();
    seed_cleanup_proxy(&pool, "fp-dea", "vless", "alive", Some("DE"), None).await;
    seed_cleanup_proxy(&pool, "fp-deq", "vless", "quarantine", Some("DE"), None).await;
    seed_cleanup_proxy(&pool, "fp-usa", "vless", "alive", Some("US"), None).await;

    let app = router(state.clone());
    let cookie = login(&app).await;
    let csrf = csrf_for(&state, &cookie);

    // Invalid input (empty country from the dropdown's placeholder).
    let response = app
        .clone()
        .oneshot(request(
            "POST",
            "/admin/proxies/remove-alive-by-country",
            &format!("_csrf={csrf}&country="),
            Some(&cookie),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert_eq!(status_by_fp(&pool, "fp-dea").await, "alive");

    let response = app
        .clone()
        .oneshot(request(
            "POST",
            "/admin/proxies/remove-alive-by-country",
            &format!("_csrf={csrf}&country=de"),
            Some(&cookie),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert_eq!(status_by_fp(&pool, "fp-dea").await, "removed");
    assert_eq!(status_by_fp(&pool, "fp-deq").await, "quarantine");
    assert_eq!(status_by_fp(&pool, "fp-usa").await, "alive");
}

#[tokio::test]
async fn cleanup_no_country_and_unprobeable_target_their_groups() {
    let (_dir, state) = test_state(1000).await;
    let pool = state.pool.clone();
    seed_cleanup_proxy(&pool, "fp-noc", "vless", "alive", None, None).await;
    seed_cleanup_proxy(&pool, "fp-hasc", "vless", "alive", Some("US"), None).await;
    seed_cleanup_proxy(&pool, "fp-tuic", "tuic", "unknown", None, None).await;
    seed_cleanup_proxy(&pool, "fp-mieru", "mieru", "unknown", None, None).await;
    seed_cleanup_proxy(&pool, "fp-vlessu", "vless", "unknown", None, None).await;
    // tuic-alive carries a country so the no-country action above
    // cannot touch it, it must survive both actions.
    seed_cleanup_proxy(&pool, "fp-tuica", "tuic", "alive", Some("US"), None).await;

    let app = router(state.clone());
    let cookie = login(&app).await;
    let csrf = csrf_for(&state, &cookie);

    let response = app
        .clone()
        .oneshot(request(
            "POST",
            "/admin/proxies/remove-alive-no-country",
            &format!("_csrf={csrf}"),
            Some(&cookie),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert_eq!(status_by_fp(&pool, "fp-noc").await, "removed");
    assert_eq!(status_by_fp(&pool, "fp-hasc").await, "alive");

    let response = app
        .oneshot(request(
            "POST",
            "/admin/proxies/remove-unprobeable",
            &format!("_csrf={csrf}"),
            Some(&cookie),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert_eq!(status_by_fp(&pool, "fp-tuic").await, "removed");
    assert_eq!(status_by_fp(&pool, "fp-mieru").await, "removed");
    assert_eq!(status_by_fp(&pool, "fp-vlessu").await, "unknown");
    assert_eq!(status_by_fp(&pool, "fp-tuica").await, "alive");
}

#[tokio::test]
async fn dry_run_parses_source_without_writing_anything() {
    use axum::routing::get;

    // Mock subscription endpoint.
    let mock = axum::Router::new().route(
        "/sub",
        get(|| async { "vless://uuid@1.2.3.4:443?security=reality#A\ntrojan://pw@h:443#B\n" }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, mock).await.unwrap();
    });

    let (_dir, state) = test_state(1000).await;
    let pool = state.pool.clone();
    let now = fumox_core::models::now_ts();
    let source = fumox_core::models::Source {
        id: "srcD0000000".into(),
        slug: None,
        name: "dry".into(),
        url: format!("http://{addr}/sub"),
        enabled: true,
        encoding: Default::default(),
        input_format: None,
        protocols: None,
        cache_ttl_seconds: 3600,
        tags: None,
        pipeline: None,
        headers: None,
        ip_family: None,
        created_at: now,
        updated_at: now,
        last_fetched_at: None,
        last_error: None,
        error_class: None,
    };
    fumox_core::repo::sources::create(&pool, &source)
        .await
        .unwrap();

    let app = router(state.clone());
    let cookie = login(&app).await;
    let csrf = csrf_for(&state, &cookie);

    // HTMX path (HX-Request header): the result panel is swapped into
    // #dryrun-target as before.
    let htmx_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/admin/sources/srcD0000000/dry-run")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .header("HX-Request", "true")
                .header(header::COOKIE, &cookie)
                .extension(ConnectInfo::<SocketAddr>(
                    "127.0.0.1:41000".parse().unwrap(),
                ))
                .body(Body::from(format!("_csrf={csrf}")))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(htmx_response.status(), StatusCode::OK);
    let html = htmx_response
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes();
    let html = String::from_utf8_lossy(&html);
    assert!(html.contains("успех"));
    assert!(html.contains("1.2.3.4")); // sample line preview

    // Plain-browser path (no HX-Request header): the bare fragment would
    // be a chrome-less page, so the action redirects back to the source
    // card and carries the outcome as flash parameters.
    let response = app
        .oneshot(request(
            "POST",
            "/admin/sources/srcD0000000/dry-run",
            &format!("_csrf={csrf}"),
            Some(&cookie),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let location = response
        .headers()
        .get(header::LOCATION)
        .unwrap()
        .to_str()
        .unwrap();
    assert!(
        location.starts_with("/admin/sources/srcD0000000?flash="),
        "{location}"
    );
    assert!(location.contains("flash_level=ok"), "{location}");

    // Nothing was written: no proxies, no fetch_log entries.
    let (proxy_count,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM proxies")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(proxy_count, 0);
    let (log_count,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM fetch_log")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(log_count, 0);
}

/// The stream forwards bus events verbatim: publishing a fetch event
/// after the connection opens must reach it. The endpoint renders no
/// periodic database snapshots any more (nothing consumed them), so
/// the bus event is the only payload asserted here.
#[tokio::test]
async fn sse_stream_forwards_bus_events() {
    let (_dir, state) = test_state(1000).await;
    let events = state.events.clone();
    let app = router(state.clone());
    let cookie = login(&app).await;

    let response = app
        .oneshot(request("GET", "/admin/events", "", Some(&cookie)))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let content_type = response
        .headers()
        .get(header::CONTENT_TYPE)
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    assert!(
        content_type.starts_with("text/event-stream"),
        "{content_type}"
    );

    let mut body = response.into_body();
    let mut buf = Vec::new();
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);

    // A published fetch event reaches the open stream.
    events.publish(
        "fetch.done",
        serde_json::json!({"source_id": "srcA0000000", "ok": true}),
    );
    loop {
        let frame = tokio::time::timeout_at(deadline, body.frame())
            .await
            .expect("timed out waiting for the fetch.done frame")
            .unwrap()
            .unwrap();
        if let Some(chunk) = frame.data_ref() {
            buf.extend_from_slice(chunk);
        }
        let text = String::from_utf8_lossy(&buf).to_string();
        if text.contains("fetch.done") && text.contains("srcA0000000") {
            break;
        }
    }
}

// Interface language (i18n)

#[tokio::test]
async fn dashboard_defaults_to_russian_and_follows_the_language_cookie() {
    let (_dir, state) = test_state(1000).await;
    let app = router(state);
    let cookie = login(&app).await;

    // No language cookie: Russian, the default.
    let response = app
        .clone()
        .oneshot(request("GET", "/admin", "", Some(&cookie)))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let html = response.into_body().collect().await.unwrap().to_bytes();
    let html = String::from_utf8_lossy(&html);
    assert!(html.contains("lang=\"ru\""));
    assert!(html.contains("Обзор"));

    // With fumox_lang=en the same page renders in English.
    let response = app
        .oneshot(request(
            "GET",
            "/admin",
            "",
            Some(&format!("{cookie}; fumox_lang=en")),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let html = response.into_body().collect().await.unwrap().to_bytes();
    let html = String::from_utf8_lossy(&html);
    assert!(html.contains("lang=\"en\""));
    assert!(html.contains("Dashboard"));
    assert!(!html.contains("Обзор"));
}

#[tokio::test]
async fn login_screen_language_selection_sets_the_cookie() {
    let (_dir, state) = test_state(1000).await;
    let app = router(state);

    // ?lang=en renders English and persists the choice.
    let response = app
        .clone()
        .oneshot(request("GET", "/admin/login?lang=en", "", None))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let set_cookie = response
        .headers()
        .get(header::SET_COOKIE)
        .expect("language cookie is set")
        .to_str()
        .unwrap()
        .to_string();
    assert!(set_cookie.starts_with("fumox_lang=en;"));
    assert!(set_cookie.contains("HttpOnly"));
    let html = response.into_body().collect().await.unwrap().to_bytes();
    let html = String::from_utf8_lossy(&html);
    assert!(html.contains("lang=\"en\""));
    assert!(html.contains("Access token"));

    // ?lang=ru switches back to Russian.
    let response = app
        .clone()
        .oneshot(request("GET", "/admin/login?lang=ru", "", None))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let set_cookie = response
        .headers()
        .get(header::SET_COOKIE)
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    assert!(set_cookie.starts_with("fumox_lang=ru;"));
    let html = response.into_body().collect().await.unwrap().to_bytes();
    let html = String::from_utf8_lossy(&html);
    assert!(html.contains("Токен доступа"));

    // Without a parameter or cookie the screen stays Russian and sets
    // no language cookie.
    let response = app
        .oneshot(request("GET", "/admin/login", "", None))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert!(response.headers().get(header::SET_COOKIE).is_none());
    let html = response.into_body().collect().await.unwrap().to_bytes();
    let html = String::from_utf8_lossy(&html);
    assert!(html.contains("lang=\"ru\""));
}

#[tokio::test]
async fn set_lang_redirects_with_cookie_and_guards_the_next_param() {
    let (_dir, state) = test_state(1000).await;
    let app = router(state);

    // Valid next: back to the requested admin page with the new cookie.
    let response = app
        .clone()
        .oneshot(request(
            "GET",
            "/admin/set-lang?lang=en&next=/admin/proxies",
            "",
            None,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        response.headers().get(header::LOCATION).unwrap(),
        "/admin/proxies"
    );
    assert!(
        response
            .headers()
            .get(header::SET_COOKIE)
            .unwrap()
            .to_str()
            .unwrap()
            .starts_with("fumox_lang=en;")
    );

    // External next values are dropped: the redirect stays inside /admin.
    let response = app
        .clone()
        .oneshot(request(
            "GET",
            "/admin/set-lang?lang=ru&next=https://evil.example.com",
            "",
            None,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert_eq!(response.headers().get(header::LOCATION).unwrap(), "/admin");

    // Unknown language values fall back to Russian.
    let response = app
        .oneshot(request("GET", "/admin/set-lang?lang=fr", "", None))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert!(
        response
            .headers()
            .get(header::SET_COOKIE)
            .unwrap()
            .to_str()
            .unwrap()
            .starts_with("fumox_lang=ru;")
    );
}

/// H4: an attacker-controlled `lang=`
/// must never reach `Set-Cookie`, `Location`, or any other header. The
/// `lang_cookie` builder only ever sees a code that came out of
/// `Locales::resolve`, which falls back to the default catalog code ,
/// a fixed literal in the locales TOML, never the raw input.
#[tokio::test]
async fn attacker_controlled_lang_does_not_leak_into_any_response_header() {
    let (_dir, state) = test_state(1000).await;
    let app = router(state);

    // Every value is percent-encoded so the request URI stays valid;
    // the server still sees the raw bytes after decoding.
    for uri in [
        "/admin/set-lang?lang=%3Cscript%3Ealert(1)%3C%2Fscript%3E",
        "/admin/set-lang?lang=foo%0D%0ASet-Cookie:%20pwned",
        "/admin/login?lang=en%00%2Fadmin%2Fexport",
        "/admin/login?lang=..%2F..%2Fetc%2Fpasswd",
        "/admin/set-lang?lang=&next=https://evil.example.com",
    ] {
        let response = app
            .clone()
            .oneshot(request("GET", uri, "", None))
            .await
            .unwrap();
        // The cookie must always be a fixed catalog code with the
        // standard attributes; the Location is constrained to /admin or
        // to an absolute internal path from `next`.
        let set_cookie = response
            .headers()
            .get(header::SET_COOKIE)
            .map(|v| v.to_str().unwrap().to_string())
            .unwrap_or_default();
        assert!(
            set_cookie.is_empty()
                || set_cookie.starts_with("fumox_lang=ru;")
                || set_cookie.starts_with("fumox_lang=en;"),
            "untrusted value leaked into Set-Cookie for {uri}: {set_cookie:?}"
        );
        assert!(
            !set_cookie.contains("<script>"),
            "raw input reached the cookie for {uri}: {set_cookie:?}"
        );
        assert!(
            !set_cookie.contains("pwned"),
            "header injection reached the cookie for {uri}: {set_cookie:?}"
        );
        if let Some(location) = response.headers().get(header::LOCATION) {
            let value = location.to_str().unwrap();
            assert!(
                !value.contains("evil.example.com"),
                "open redirect via next for {uri}: {value:?}"
            );
        }
    }
}

// Interface theme (day/night)

#[tokio::test]
async fn pages_default_to_light_and_follow_the_theme_cookie() {
    let (_dir, state) = test_state(1000).await;
    let app = router(state);
    let cookie = login(&app).await;

    // No theme cookie: the day theme.
    let response = app
        .clone()
        .oneshot(request("GET", "/admin", "", Some(&cookie)))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let html = response.into_body().collect().await.unwrap().to_bytes();
    let html = String::from_utf8_lossy(&html);
    assert!(html.contains("data-theme=\"light\""));

    // With fumox_theme=dark the same page renders the night theme.
    let response = app
        .clone()
        .oneshot(request(
            "GET",
            "/admin",
            "",
            Some(&format!("{cookie}; fumox_theme=dark")),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let html = response.into_body().collect().await.unwrap().to_bytes();
    let html = String::from_utf8_lossy(&html);
    assert!(html.contains("data-theme=\"dark\""));

    // The login screen honors the same cookie.
    let response = app
        .oneshot(request("GET", "/admin/login", "", Some("fumox_theme=dark")))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let html = response.into_body().collect().await.unwrap().to_bytes();
    let html = String::from_utf8_lossy(&html);
    assert!(html.contains("data-theme=\"dark\""));
}

#[tokio::test]
async fn set_theme_redirects_with_cookie_and_guards_the_next_param() {
    let (_dir, state) = test_state(1000).await;
    let app = router(state);

    // Valid next: back to the requested admin page with the new cookie.
    let response = app
        .clone()
        .oneshot(request(
            "GET",
            "/admin/set-theme?theme=dark&next=/admin/proxies",
            "",
            None,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        response.headers().get(header::LOCATION).unwrap(),
        "/admin/proxies"
    );
    assert!(
        response
            .headers()
            .get(header::SET_COOKIE)
            .unwrap()
            .to_str()
            .unwrap()
            .starts_with("fumox_theme=dark;")
    );

    // External next values are dropped: the redirect stays inside /admin.
    let response = app
        .clone()
        .oneshot(request(
            "GET",
            "/admin/set-theme?theme=light&next=https://evil.example.com",
            "",
            None,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert_eq!(response.headers().get(header::LOCATION).unwrap(), "/admin");

    // Unknown theme values fall back to the light theme.
    let response = app
        .oneshot(request("GET", "/admin/set-theme?theme=neon", "", None))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert!(
        response
            .headers()
            .get(header::SET_COOKIE)
            .unwrap()
            .to_str()
            .unwrap()
            .starts_with("fumox_theme=light;")
    );
}

// Dashboard Top-N picker

#[tokio::test]
async fn set_dash_top_n_redirects_with_cookie_and_guards_next() {
    let (_dir, state) = test_state(1000).await;
    let app = router(state);

    // Valid next: back to the requested admin page with the new cookie.
    let response = app
        .clone()
        .oneshot(request(
            "GET",
            "/admin/set-dash-top-n?n=25&next=/admin",
            "",
            None,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert_eq!(response.headers().get(header::LOCATION).unwrap(), "/admin");
    let cookie = response
        .headers()
        .get(header::SET_COOKIE)
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    assert!(
        cookie.starts_with("fumox_dash_top_n=25;"),
        "cookie: {cookie}"
    );

    // External `next` values are dropped: redirect stays inside /admin.
    let response = app
        .clone()
        .oneshot(request(
            "GET",
            "/admin/set-dash-top-n?n=15&next=https://evil.example.com",
            "",
            None,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert_eq!(response.headers().get(header::LOCATION).unwrap(), "/admin");

    // A percent-decoded CR/LF inside `next` (invalid Location header
    // value, axum would answer 500) falls back to /admin as well.
    let response = app
        .clone()
        .oneshot(request(
            "GET",
            "/admin/set-dash-top-n?n=10&next=%2Fadmin%0D%0Ax",
            "",
            None,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert_eq!(response.headers().get(header::LOCATION).unwrap(), "/admin");

    // Out-of-list values fall back to the default 10.
    for bad in ["999", "0", "-5", "abc"] {
        let response = app
            .clone()
            .oneshot(request(
                "GET",
                &format!("/admin/set-dash-top-n?n={bad}"),
                "",
                None,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        let cookie = response
            .headers()
            .get(header::SET_COOKIE)
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();
        assert!(
            cookie.starts_with("fumox_dash_top_n=10;"),
            "bad={bad} cookie: {cookie}"
        );
    }
}

#[tokio::test]
async fn dashboard_top_n_cookie_is_respected_by_widgets() {
    // Seed enough source errors (12) and alive proxies (12) that top_n=5
    // truncates both lists, proving the cookie flows through the handler
    // into the SQL LIMIT parameters.
    let (_dir, state) = test_state(1000).await;
    let pool = state.pool.clone();
    let now = fumox_core::models::now_ts();
    for idx in 0..12 {
        let id = format!("srcT{idx:07}");
        fumox_core::repo::sources::create(&pool, &test_source(&id, &format!("slug-topn-{idx}")))
            .await
            .unwrap();
        sqlx::query("UPDATE sources SET error_class = 'network', last_error = 'fail', last_fetched_at = ? WHERE id = ?")
                .bind(now - idx as i64)
                .bind(&id)
                .execute(&pool)
                .await
                .unwrap();
    }

    let app = router(state);
    let cookie = login(&app).await;

    // With top_n=5, the source-errors block must show exactly 5 rows
    // and the picker selects "5". Scope the count to the recent-errors
    // panel because src IDs also appear in the per-source table.
    let response = app
        .clone()
        .oneshot(request(
            "GET",
            "/admin",
            "",
            Some(&format!("{cookie}; fumox_dash_top_n=5")),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let html = String::from_utf8_lossy(
        response
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .as_ref(),
    )
    .into_owned();
    assert!(html.contains("Источники с ошибками"));
    let errors_panel_end = html
        .find("Прокси по источникам")
        .expect("per-source table heading must render after errors");
    let errors_html = &html[..errors_panel_end];
    // The first 5 source IDs (most recent last_fetched_at) are the
    // top 5, they MUST show up in the errors panel; the remaining
    // IDs MUST NOT show up here. The seed assigns `last_fetched_at =
    // now - idx`, so the most recent is srcT0000000 (idx=0),
    // descending to srcT0000011 (idx=11).
    for idx in 0..5 {
        assert!(
            errors_html.contains(&format!("srcT{idx:07}")),
            "errors panel should include srcT{idx:07}"
        );
    }
    for idx in 5..12 {
        assert!(
            !errors_html.contains(&format!("srcT{idx:07}")),
            "errors panel should NOT include srcT{idx:07}"
        );
    }
    // The picker selects the current value.
    assert!(
        html.contains(r#"<option value="5" selected"#),
        "5 should be the selected option"
    );

    // Default behaviour (no top-n cookie): top_n=10, the picker
    // shows "10" selected and the errors panel renders ≤10 rows.
    let response = app
        .oneshot(request("GET", "/admin", "", Some(&cookie)))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let html = String::from_utf8_lossy(
        response
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .as_ref(),
    )
    .into_owned();
    assert!(
        html.contains(r#"<option value="10" selected"#),
        "10 should be the selected option when the cookie is absent"
    );
}

#[tokio::test]
async fn dashboard_renders_top_failures_panel() {
    // Empty repo: the panel renders an "no failures" placeholder.
    let (_dir, state) = test_state(1000).await;
    let app = router(state);
    let cookie = login(&app).await;
    let response = app
        .oneshot(request("GET", "/admin", "", Some(&cookie)))
        .await
        .unwrap();
    let html = String::from_utf8_lossy(
        response
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .as_ref(),
    )
    .into_owned();
    assert!(
        html.contains("Топ причин отказов"),
        "panel heading must render"
    );
    assert!(
        html.contains("Отказов проверок за последние 24 ч нет."),
        "empty-state copy must render"
    );
}

// Configuration import/export (Phase 4)

/// A minimal enabled source fixture for repo writes.
fn test_source(id: &str, slug: &str) -> fumox_core::models::Source {
    let now = fumox_core::models::now_ts();
    fumox_core::models::Source {
        id: id.into(),
        slug: Some(slug.into()),
        name: format!("source {slug}"),
        url: "https://example.com/sub".into(),
        enabled: true,
        encoding: Default::default(),
        input_format: None,
        protocols: None,
        cache_ttl_seconds: 3600,
        tags: None,
        pipeline: None,
        headers: None,
        ip_family: None,
        created_at: now,
        updated_at: now,
        last_fetched_at: None,
        last_error: None,
        error_class: None,
    }
}

/// URL-encode `(key, value)` pairs into a form body.
fn urlencoded(pairs: &[(&str, &str)]) -> String {
    pairs
        .iter()
        .map(|(k, v)| {
            format!(
                "{}={}",
                percent_encoding::utf8_percent_encode(k, percent_encoding::NON_ALPHANUMERIC),
                percent_encoding::utf8_percent_encode(v, percent_encoding::NON_ALPHANUMERIC)
            )
        })
        .collect::<Vec<_>>()
        .join("&")
}

/// One source + one profile that references it (both with slugs).
async fn io_fixture(state: &AdminState) {
    let now = fumox_core::models::now_ts();
    let source = fumox_core::models::Source {
        id: "srcX0000000".into(),
        slug: Some("exp-src".into()),
        name: "export source".into(),
        url: "https://example.com/sub".into(),
        enabled: true,
        encoding: Default::default(),
        input_format: None,
        protocols: None,
        cache_ttl_seconds: 3600,
        tags: Some(vec!["tag1".into()]),
        pipeline: None,
        headers: None,
        ip_family: None,
        created_at: now,
        updated_at: now,
        last_fetched_at: None,
        last_error: None,
        error_class: None,
    };
    fumox_core::repo::sources::create(&state.pool, &source)
        .await
        .unwrap();
    let profile = fumox_core::models::Profile {
        id: "profX0000000".into(),
        slug: Some("exp-prof".into()),
        access_token: Some("tok-0123456789abcdef".into()),
        name: "export profile".into(),
        output_format: fumox_core::models::OutputFormat::Clash,
        pipeline: None,
        countries: Vec::new(),
        enabled: true,
        created_at: now,
        updated_at: now,
    };
    fumox_core::repo::profiles::create(&state.pool, &profile)
        .await
        .unwrap();
    fumox_core::repo::profiles::set_sources(
        &state.pool,
        "profX0000000",
        &[("srcX0000000".into(), 0)],
    )
    .await
    .unwrap();
}

async fn export_body(app: &axum::Router, cookie: &str) -> String {
    let response = app
        .clone()
        .oneshot(request("GET", "/admin/export", "", Some(cookie)))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    String::from_utf8(bytes.to_vec()).unwrap()
}

#[tokio::test]
async fn export_downloads_configuration_as_attachment() {
    let (_dir, state) = test_state(1000).await;
    io_fixture(&state).await;
    let app = router(state);
    let cookie = login(&app).await;

    let response = app
        .clone()
        .oneshot(request("GET", "/admin/export", "", Some(&cookie)))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let content_type = response
        .headers()
        .get(header::CONTENT_TYPE)
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    assert!(
        content_type.starts_with("application/json"),
        "{content_type}"
    );
    let disposition = response
        .headers()
        .get(header::CONTENT_DISPOSITION)
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    assert!(
        disposition.starts_with("attachment; filename=\"fumox-config-"),
        "{disposition}"
    );

    let payload = export_body(&app, &cookie).await;
    let parsed: serde_json::Value = serde_json::from_str(&payload).unwrap();
    assert_eq!(parsed["version"], 1);
    assert_eq!(parsed["sources"][0]["ref"], "srcX0000000");
    assert_eq!(parsed["sources"][0]["slug"], "exp-src");
    assert_eq!(parsed["profiles"][0]["slug"], "exp-prof");
    assert_eq!(parsed["profiles"][0]["output_format"], "clash");
    assert_eq!(
        parsed["profiles"][0]["access_token"],
        "tok-0123456789abcdef"
    );
    assert_eq!(
        parsed["profiles"][0]["sources"],
        serde_json::json!(["srcX0000000"])
    );
}

#[tokio::test]
async fn import_creates_new_objects_and_remaps_composition() {
    // Export from one database…
    let (_dir, exporter) = test_state(1000).await;
    io_fixture(&exporter).await;
    let export_app = router(exporter);
    let export_cookie = login(&export_app).await;
    let payload = export_body(&export_app, &export_cookie).await;

    // …and import it into a fresh one.
    let (_dir, state) = test_state(1000).await;
    let pool = state.pool.clone();
    let app = router(state.clone());
    let cookie = login(&app).await;
    let csrf = csrf_for(&state, &cookie);
    let body = urlencoded(&[("_csrf", &csrf), ("payload", &payload)]);
    let response = app
        .oneshot(request("POST", "/admin/import", &body, Some(&cookie)))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let html = response.into_body().collect().await.unwrap().to_bytes();
    let html = String::from_utf8_lossy(&html);
    assert!(html.contains("Импорт завершён"), "{html}");

    // Fresh ids, slugs preserved (clean DB), composition remapped.
    let sources = fumox_core::repo::sources::list(&pool, false).await.unwrap();
    assert_eq!(sources.len(), 1);
    let new_source = &sources[0];
    assert_ne!(new_source.id, "srcX0000000");
    assert_eq!(new_source.slug.as_deref(), Some("exp-src"));
    assert_eq!(new_source.tags.as_deref(), Some(&["tag1".to_string()][..]));

    let profiles = fumox_core::repo::profiles::list(&pool, false)
        .await
        .unwrap();
    assert_eq!(profiles.len(), 1);
    let new_profile = &profiles[0];
    assert_ne!(new_profile.id, "profX0000000");
    assert_eq!(new_profile.slug.as_deref(), Some("exp-prof"));
    assert_eq!(
        new_profile.access_token.as_deref(),
        Some("tok-0123456789abcdef")
    );
    let composition = fumox_core::repo::profiles::get_sources(&pool, &new_profile.id)
        .await
        .unwrap();
    assert_eq!(composition, vec![(new_source.id.clone(), 0)]);
}

#[tokio::test]
async fn import_slug_collision_creates_objects_without_slug() {
    let (_dir, state) = test_state(1000).await;
    io_fixture(&state).await; // occupies exp-src / exp-prof
    let pool = state.pool.clone();
    let app = router(state.clone());
    let cookie = login(&app).await;
    let payload = export_body(&app, &cookie).await;

    let csrf = csrf_for(&state, &cookie);
    let body = urlencoded(&[("_csrf", &csrf), ("payload", &payload)]);
    let response = app
        .oneshot(request("POST", "/admin/import", &body, Some(&cookie)))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let html = response.into_body().collect().await.unwrap().to_bytes();
    let html = String::from_utf8_lossy(&html);
    assert!(html.contains("Предупреждения"), "{html}");

    // Two sources now; the imported one lost its slug to the collision.
    let sources = fumox_core::repo::sources::list(&pool, false).await.unwrap();
    assert_eq!(sources.len(), 2);
    let imported = sources.iter().find(|s| s.id != "srcX0000000").unwrap();
    assert_eq!(imported.slug, None);
    let profiles = fumox_core::repo::profiles::list(&pool, false)
        .await
        .unwrap();
    assert_eq!(profiles.len(), 2);
    let imported_profile = profiles.iter().find(|p| p.id != "profX0000000").unwrap();
    assert_eq!(imported_profile.slug, None);
}

#[tokio::test]
async fn import_rejects_bad_version_and_invalid_fields_without_writes() {
    let (_dir, state) = test_state(1000).await;
    let pool = state.pool.clone();
    let app = router(state.clone());
    let cookie = login(&app).await;
    let csrf = csrf_for(&state, &cookie);

    // Unsupported version → 422.
    let v2 = r#"{"version":2,"exported_at":0,"sources":[],"profiles":[]}"#;
    let body = urlencoded(&[("_csrf", &csrf), ("payload", v2)]);
    let response = app
        .clone()
        .oneshot(request("POST", "/admin/import", &body, Some(&cookie)))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);

    // Non-http(s) URL → 422.
    let bad_url = r#"{"version":1,"exported_at":0,"sources":[{"ref":"r1","name":"s","url":"ftp://x","enabled":true,"encoding":"auto","cache_ttl_seconds":3600}],"profiles":[]}"#;
    let body = urlencoded(&[("_csrf", &csrf), ("payload", bad_url)]);
    let response = app
        .clone()
        .oneshot(request("POST", "/admin/import", &body, Some(&cookie)))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);

    // TTL out of range → 422.
    let bad_ttl = r#"{"version":1,"exported_at":0,"sources":[{"ref":"r1","name":"s","url":"https://example.com","enabled":true,"encoding":"auto","cache_ttl_seconds":5}],"profiles":[]}"#;
    let body = urlencoded(&[("_csrf", &csrf), ("payload", bad_ttl)]);
    let response = app
        .clone()
        .oneshot(request("POST", "/admin/import", &body, Some(&cookie)))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);

    // All-or-nothing: nothing was written by any of the attempts.
    assert!(
        fumox_core::repo::sources::list(&pool, false)
            .await
            .unwrap()
            .is_empty()
    );
    assert!(
        fumox_core::repo::profiles::list(&pool, false)
            .await
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn import_requires_auth_and_csrf() {
    let (_dir, state) = test_state(1000).await;
    let app = router(state.clone());
    let cookie = login(&app).await;
    let payload = r#"{"version":1,"exported_at":0,"sources":[],"profiles":[]}"#;
    let body = urlencoded(&[("payload", payload)]);

    // Missing CSRF token → 403.
    let response = app
        .clone()
        .oneshot(request("POST", "/admin/import", &body, Some(&cookie)))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    // Unauthenticated browser POST → redirected to the login screen.
    let response = app
        .oneshot(request("POST", "/admin/import", &body, None))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        response.headers().get(header::LOCATION).unwrap(),
        "/admin/login"
    );
}

// Pipeline builder

#[tokio::test]
async fn pipeline_builder_endpoints_require_auth_and_csrf() {
    let (_dir, state) = test_state(1000).await;
    let app = router(state.clone());
    let cookie = login(&app).await;
    let body = urlencoded(&[("ped_sort", "1"), ("ped_sort_by", "name")]);

    for uri in [
        "/admin/pipeline/preview",
        "/admin/pipeline/mode",
        "/admin/pipeline/preset",
        "/admin/pipeline/rows",
    ] {
        // Missing CSRF token → 403.
        let response = app
            .clone()
            .oneshot(request("POST", uri, &body, Some(&cookie)))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN, "{uri}");

        // Unauthenticated browser POST → redirected to the login screen.
        let response = app
            .clone()
            .oneshot(request("POST", uri, &body, None))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SEE_OTHER, "{uri}");
    }
}

#[tokio::test]
async fn pipeline_preview_generates_and_validates_json() {
    let (_dir, state) = test_state(1000).await;
    let app = router(state.clone());
    let cookie = login(&app).await;
    let csrf = csrf_for(&state, &cookie);

    // A valid configuration: the fragment carries the generated JSON and
    // the ok badge.
    let body = urlencoded(&[
        ("_csrf", &csrf),
        ("ped_filter", "1"),
        ("ped_filter_protocols", "vless"),
        ("ped_filter_protocols", "trojan"),
        ("ped_forbid_insecure", "1"),
        ("ped_sort", "1"),
        ("ped_sort_by", "latency"),
        ("ped_sort_desc", "1"),
    ]);
    let response = app
        .clone()
        .oneshot(request(
            "POST",
            "/admin/pipeline/preview",
            &body,
            Some(&cookie),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let html = response.into_body().collect().await.unwrap().to_bytes();
    let html = String::from_utf8_lossy(&html);
    assert!(html.contains("&#34;version&#34;: 1"), "{html}");
    assert!(html.contains("&#34;filter&#34;"), "{html}");
    assert!(html.contains("&#34;latency&#34;"), "{html}");
    assert!(html.contains("JSON валиден"), "{html}");

    // A bad regex: the error is localized (default language is Russian).
    let body = urlencoded(&[
        ("_csrf", &csrf),
        ("ped_rename_0_match", "("),
        ("ped_rename_0_replace", "x"),
    ]);
    let response = app
        .clone()
        .oneshot(request(
            "POST",
            "/admin/pipeline/preview",
            &body,
            Some(&cookie),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let html = response.into_body().collect().await.unwrap().to_bytes();
    let html = String::from_utf8_lossy(&html);
    assert!(html.contains("некорректный regex"), "{html}");
    assert!(!html.contains("JSON валиден"), "{html}");

    // The English panel gets English text.
    let en_cookie = format!("{cookie}; {}=en", i18n::LANG_COOKIE);
    let response = app
        .oneshot(request(
            "POST",
            "/admin/pipeline/preview",
            &body,
            Some(&en_cookie),
        ))
        .await
        .unwrap();
    let html = response.into_body().collect().await.unwrap().to_bytes();
    let html = String::from_utf8_lossy(&html);
    assert!(html.contains("invalid regex"), "{html}");
    assert!(!html.contains("некорректный"), "{html}");
}

#[tokio::test]
async fn pipeline_preview_shows_the_empty_state() {
    let (_dir, state) = test_state(1000).await;
    let app = router(state.clone());
    let cookie = login(&app).await;
    let csrf = csrf_for(&state, &cookie);
    let body = urlencoded(&[("_csrf", &csrf)]);

    let response = app
        .oneshot(request(
            "POST",
            "/admin/pipeline/preview",
            &body,
            Some(&cookie),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let html = response.into_body().collect().await.unwrap().to_bytes();
    let html = String::from_utf8_lossy(&html);
    assert!(html.contains("конвейер останется пустым"), "{html}");
}

#[tokio::test]
async fn pipeline_mode_switches_between_builder_and_raw() {
    let (_dir, state) = test_state(1000).await;
    let app = router(state.clone());
    let cookie = login(&app).await;
    let csrf = csrf_for(&state, &cookie);

    // Builder → raw: the generated JSON lands in the textarea; the mode
    // field flips to "raw" so the save reads the textarea.
    let body = urlencoded(&[
        ("_csrf", &csrf),
        ("ped_filter", "1"),
        ("ped_filter_protocols", "vless"),
    ]);
    let response = app
        .clone()
        .oneshot(request(
            "POST",
            "/admin/pipeline/mode?to=raw",
            &body,
            Some(&cookie),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let html = response.into_body().collect().await.unwrap().to_bytes();
    let html = String::from_utf8_lossy(&html);
    assert!(
        html.contains(r#"name="pipeline_mode" value="raw""#),
        "{html}"
    );
    assert!(html.contains("id=\"pipeline-field\""), "{html}");
    assert!(html.contains("&#34;filter&#34;"), "{html}");
    assert!(!html.contains("ped_filter_protocols"), "{html}");

    // Raw → builder with a representable JSON: prefilled fields, no
    // warning.
    let body = urlencoded(&[
        ("_csrf", &csrf),
        (
            "pipeline",
            "{ \"version\": 1, \"sort\": { \"by\": \"name\" } }",
        ),
    ]);
    let response = app
        .clone()
        .oneshot(request(
            "POST",
            "/admin/pipeline/mode?to=builder",
            &body,
            Some(&cookie),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let html = response.into_body().collect().await.unwrap().to_bytes();
    let html = String::from_utf8_lossy(&html);
    assert!(
        html.contains(r#"name="pipeline_mode" value="builder""#),
        "{html}"
    );
    assert!(html.contains(r#"<option value="name" selected>"#), "{html}");
    assert!(
        !html.contains("невозможно представить в конструкторе"),
        "{html}"
    );

    // Raw → builder with an unparseable JSON: stays raw with the warning.
    let body = urlencoded(&[
        ("_csrf", &csrf),
        ("pipeline", "{ \"version\": 1, \"bogus\": true }"),
    ]);
    let response = app
        .oneshot(request(
            "POST",
            "/admin/pipeline/mode?to=builder",
            &body,
            Some(&cookie),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let html = response.into_body().collect().await.unwrap().to_bytes();
    let html = String::from_utf8_lossy(&html);
    assert!(
        html.contains(r#"name="pipeline_mode" value="raw""#),
        "{html}"
    );
    assert!(
        html.contains("невозможно представить в конструкторе"),
        "{html}"
    );
}

#[tokio::test]
async fn pipeline_preset_renders_the_ready_made_state() {
    let (_dir, state) = test_state(1000).await;
    let app = router(state.clone());
    let cookie = login(&app).await;
    let csrf = csrf_for(&state, &cookie);
    let body = urlencoded(&[("_csrf", &csrf)]);

    // "Only verified": unknown excluded, builder mode with a valid
    // preview of the preset.
    let response = app
        .clone()
        .oneshot(request(
            "POST",
            "/admin/pipeline/preset?name=workers",
            &body,
            Some(&cookie),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let html = response.into_body().collect().await.unwrap().to_bytes();
    let html = String::from_utf8_lossy(&html);
    assert!(html.contains(r#"value="builder""#), "{html}");
    assert!(
        html.contains(r#"id="ped-status-unknown" checked"#),
        "{html}"
    );
    assert!(
        html.contains(r#"id="ped-status-quarantine" checked"#),
        "{html}"
    );
    assert!(!html.contains(r#"id="ped-status-alive" checked"#), "{html}");
    assert!(html.contains("JSON валиден"), "{html}");

    // "Blank": nothing checked, the NULL preview.
    let response = app
        .clone()
        .oneshot(request(
            "POST",
            "/admin/pipeline/preset?name=blank",
            &body,
            Some(&cookie),
        ))
        .await
        .unwrap();
    let html = response.into_body().collect().await.unwrap().to_bytes();
    let html = String::from_utf8_lossy(&html);
    assert!(html.contains("конвейер останется пустым"), "{html}");

    // The profile flavor keeps the tri-state radios.
    let response = app
        .clone()
        .oneshot(request(
            "POST",
            "/admin/pipeline/preset?name=workers&profile=1",
            &body,
            Some(&cookie),
        ))
        .await
        .unwrap();
    let html = response.into_body().collect().await.unwrap().to_bytes();
    let html = String::from_utf8_lossy(&html);
    assert!(html.contains(r#"name="ped_health" value="set""#), "{html}");
    assert!(html.contains("наследовать"), "{html}");
}

#[tokio::test]
async fn pipeline_rows_add_and_drop_keep_the_other_lines() {
    let (_dir, state) = test_state(1000).await;
    let app = router(state.clone());
    let cookie = login(&app).await;
    let csrf = csrf_for(&state, &cookie);

    // A fresh widget shows one empty typing line.
    let body = urlencoded(&[("_csrf", &csrf)]);
    let response = app
        .clone()
        .oneshot(request(
            "POST",
            "/admin/pipeline/rows",
            &body,
            Some(&cookie),
        ))
        .await
        .unwrap();
    let html = response.into_body().collect().await.unwrap().to_bytes();
    let html = String::from_utf8_lossy(&html);
    assert!(html.contains("ped_rename_0_match"), "{html}");

    // Adding a line re-renders both; dropping the first renumbers the
    // second to index 0 with its value intact.
    let two_rows = urlencoded(&[
        ("_csrf", &csrf),
        ("ped_rename_0_match", "first"),
        ("ped_rename_1_match", "second"),
    ]);
    let response = app
        .clone()
        .oneshot(request(
            "POST",
            "/admin/pipeline/rows",
            &two_rows,
            Some(&cookie),
        ))
        .await
        .unwrap();
    let html = response.into_body().collect().await.unwrap().to_bytes();
    let html = String::from_utf8_lossy(&html);
    assert!(html.contains("ped_rename_0_match"), "{html}");
    assert!(html.contains("ped_rename_1_match"), "{html}");

    // Dropping the first line renumbers the second to index 0 with its
    // value intact; `remove` travels in the query string exactly like
    // the htmx button's hx-post URL.
    let response = app
        .clone()
        .oneshot(request(
            "POST",
            "/admin/pipeline/rows?remove=0",
            &two_rows,
            Some(&cookie),
        ))
        .await
        .unwrap();
    let html = response.into_body().collect().await.unwrap().to_bytes();
    let html = String::from_utf8_lossy(&html);
    assert!(html.contains("ped_rename_0_match"), "{html}");
    assert!(!html.contains("ped_rename_1_"), "{html}");
    assert!(html.contains(r#"value="second""#), "{html}");

    // The drop section has its own container: adding a discard line
    // re-renders only `ped_drop_*` rows and never touches rename ones.
    let drop_row = urlencoded(&[
        ("_csrf", &csrf),
        ("ped_rename_0_match", "keepme"),
        ("ped_drop_0_match", "\\.cn$"),
    ]);
    let response = app
        .clone()
        .oneshot(request(
            "POST",
            "/admin/pipeline/rows?section=drop",
            &drop_row,
            Some(&cookie),
        ))
        .await
        .unwrap();
    let html = response.into_body().collect().await.unwrap().to_bytes();
    let html = String::from_utf8_lossy(&html);
    assert!(html.contains(r#"value="\.cn$""#), "{html}");
    assert!(html.contains("section=drop&amp;remove=0"), "{html}");
    assert!(!html.contains("ped_rename_"), "{html}");
}

#[tokio::test]
async fn pipeline_rows_renders_asn_mode_when_target_changes() {
    // Switching a drop row's target to `asn` via the rows endpoint
    // re-renders that row in ASN-mode (only the `asns` input, no
    // `match`/`flags`/`key`); reverting flips the row back. This is
    // the endpoint every `hx-trigger="change"` on a target select
    // fires, the round-trip must produce the right row layout.
    let (_dir, state) = test_state(1000).await;
    let app = router(state.clone());
    let cookie = login(&app).await;
    let csrf = csrf_for(&state, &cookie);

    // Start in regex mode (target=host, match=\\.ua).
    let regex_form = urlencoded(&[
        ("_csrf", &csrf),
        ("ped_drop_0_match", "\\.ua"),
        ("ped_drop_0_target", "host"),
    ]);
    let response = app
        .clone()
        .oneshot(request(
            "POST",
            "/admin/pipeline/rows?section=drop",
            &regex_form,
            Some(&cookie),
        ))
        .await
        .unwrap();
    let html = String::from_utf8_lossy(&response.into_body().collect().await.unwrap().to_bytes())
        .into_owned();
    assert!(html.contains(r#"name="ped_drop_0_match""#), "{html}");
    assert!(!html.contains(r#"name="ped_drop_0_asns""#), "{html}");

    // Switch the same row to target=asn with asns=24940, the
    // response must carry only the ASN-mode row (no `match` field).
    let asn_form = urlencoded(&[
        ("_csrf", &csrf),
        ("ped_drop_0_match", "\\.ua"),
        ("ped_drop_0_target", "asn"),
        ("ped_drop_0_asns", "24940"),
    ]);
    let response = app
        .clone()
        .oneshot(request(
            "POST",
            "/admin/pipeline/rows?section=drop",
            &asn_form,
            Some(&cookie),
        ))
        .await
        .unwrap();
    let html = String::from_utf8_lossy(&response.into_body().collect().await.unwrap().to_bytes())
        .into_owned();
    assert!(
        html.contains(r#"name="ped_drop_0_asns" value="24940""#),
        "{html}"
    );
    assert!(
        !html.contains(r#"name="ped_drop_0_match""#),
        "ASN-mode row must not carry a match input: {html}"
    );
    assert!(
        !html.contains(r#"name="ped_drop_0_flags""#),
        "ASN-mode row must not carry a flags input: {html}"
    );
    assert!(
        !html.contains(r#"name="ped_drop_0_key""#),
        "ASN-mode row must not carry a param key: {html}"
    );

    // The same round-trip preserves a sibling row in regex mode ,
    // changing one row's target must not silently rewrite others.
    let mixed_form = urlencoded(&[
        ("_csrf", &csrf),
        ("ped_drop_0_target", "asn"),
        ("ped_drop_0_asns", "24940, AS13335"),
        ("ped_drop_1_match", "\\.cn$"),
        ("ped_drop_1_target", "host"),
    ]);
    let response = app
        .clone()
        .oneshot(request(
            "POST",
            "/admin/pipeline/rows?section=drop",
            &mixed_form,
            Some(&cookie),
        ))
        .await
        .unwrap();
    let html = String::from_utf8_lossy(&response.into_body().collect().await.unwrap().to_bytes())
        .into_owned();
    assert!(html.contains(r#"name="ped_drop_0_asns""#), "{html}");
    assert!(
        html.contains(r#"name="ped_drop_1_match" value="\.cn$""#),
        "{html}"
    );
    assert!(html.contains(r#"name="ped_drop_1_target""#), "{html}");
}

#[tokio::test]
async fn pipeline_rows_render_query_does_not_append() {
    // The change-trigger on a target select calls the rows endpoint
    // with `?render=1`, the round-trip must NOT append a fresh empty
    // row, otherwise every target switch would grow the row count by
    // one. The explicit `+` button keeps its append behaviour.
    let (_dir, state) = test_state(1000).await;
    let app = router(state.clone());
    let cookie = login(&app).await;
    let csrf = csrf_for(&state, &cookie);

    // One existing drop row.
    let form = urlencoded(&[
        ("_csrf", &csrf),
        ("ped_drop_0_match", "\\.ua"),
        ("ped_drop_0_target", "host"),
    ]);
    // No `?render=1`, the legacy `+`-button semantics: append.
    let response = app
        .clone()
        .oneshot(request(
            "POST",
            "/admin/pipeline/rows?section=drop",
            &form,
            Some(&cookie),
        ))
        .await
        .unwrap();
    let html = String::from_utf8_lossy(&response.into_body().collect().await.unwrap().to_bytes())
        .into_owned();
    assert!(
        html.contains(r#"name="ped_drop_1_match""#),
        "expected an appended row: {html}"
    );

    // With `?render=1`, round-trip without append.
    let response = app
        .clone()
        .oneshot(request(
            "POST",
            "/admin/pipeline/rows?section=drop&render=1",
            &form,
            Some(&cookie),
        ))
        .await
        .unwrap();
    let html = String::from_utf8_lossy(&response.into_body().collect().await.unwrap().to_bytes())
        .into_owned();
    assert!(html.contains(r#"name="ped_drop_0_match""#), "{html}");
    assert!(
        !html.contains(r#"name="ped_drop_1_match""#),
        "render=1 must not append: {html}"
    );
}

#[tokio::test]
async fn source_form_saves_the_builder_state_as_pipeline_json() {
    let (_dir, state) = test_state(1000).await;
    let app = router(state.clone());
    let cookie = login(&app).await;
    let csrf = csrf_for(&state, &cookie);

    // Builder mode on the source form: the JSON is generated from the
    // widget fields server-side; a stale `pipeline` field is ignored.
    // `ped_forbid_insecure`/`ped_geo_enabled` ride along exactly as a
    // browser submits the rendered widget (every checkbox present).
    let body = urlencoded(&[
        ("_csrf", &csrf),
        ("name", "Builder"),
        ("url", "https://example.com/sub"),
        ("cache_ttl_seconds", "3600"),
        ("pipeline_mode", "builder"),
        ("ped_filter", "1"),
        ("ped_filter_protocols", "vless"),
        ("ped_forbid_insecure", "1"),
        ("ped_geo_enabled", "1"),
        ("ped_sort", "1"),
        ("ped_sort_by", "name"),
        ("pipeline", "{ \"version\": 1, \"bogus\": true }"),
    ]);
    let response = app
        .clone()
        .oneshot(request("POST", "/admin/sources/new", &body, Some(&cookie)))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SEE_OTHER, "{cookie}");
    let sources = fumox_core::repo::sources::list(&state.pool, false)
        .await
        .unwrap();
    let created = sources
        .iter()
        .find(|s| s.name == "Builder")
        .expect("source created");
    assert_eq!(
        created.pipeline.as_ref().unwrap(),
        &serde_json::json!({
            "version": 1,
            "filter": { "protocols": ["vless"] },
            "sort": { "by": "name" }
        })
    );

    // Builder mode with nothing configured → NULL (not `{}`).
    let body = urlencoded(&[
        ("_csrf", &csrf),
        ("name", "Empty builder"),
        ("url", "https://example.com/sub"),
        ("cache_ttl_seconds", "3600"),
        ("pipeline_mode", "builder"),
    ]);
    let response = app
        .clone()
        .oneshot(request("POST", "/admin/sources/new", &body, Some(&cookie)))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let sources = fumox_core::repo::sources::list(&state.pool, false)
        .await
        .unwrap();
    let created = sources
        .iter()
        .find(|s| s.name == "Empty builder")
        .expect("source created");
    assert!(created.pipeline.is_none());

    // Builder mode with a bad field: 422 with the localized error and
    // the widget reopened in builder mode with the typed values.
    let body = urlencoded(&[
        ("_csrf", &csrf),
        ("name", "Bad builder"),
        ("url", "https://example.com/sub"),
        ("cache_ttl_seconds", "3600"),
        ("pipeline_mode", "builder"),
        ("ped_filter", "1"),
        ("ped_filter_protocols", "quantum"),
    ]);
    let response = app
        .clone()
        .oneshot(request("POST", "/admin/sources/new", &body, Some(&cookie)))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    let html = response.into_body().collect().await.unwrap().to_bytes();
    let html = String::from_utf8_lossy(&html);
    assert!(html.contains("неизвестный протокол"), "{html}");
    assert!(
        html.contains(r#"name="pipeline_mode" value="builder""#),
        "{html}"
    );
    assert!(
        html.contains(r#"value="quantum" id="ped-proto-quantum" checked"#),
        "{html}"
    );
    assert!(!sources.iter().any(|s| s.name == "Bad builder"));
}

#[tokio::test]
async fn profile_form_saves_tri_state_sections() {
    let (_dir, state) = test_state(1000).await;
    let app = router(state.clone());
    let cookie = login(&app).await;
    let csrf = csrf_for(&state, &cookie);

    // Profile flavor of the widget: "set" on health with its values,
    // "defaults" on geo (an explicit reset), everything else inherited.
    let body = urlencoded(&[
        ("_csrf", &csrf),
        ("name", "TriState"),
        ("output_format", "uri_list"),
        ("pipeline_mode", "builder"),
        ("ped_health", "set"),
        ("ped_health_exclude", "alive"),
        ("ped_health_exclude", "unknown"),
        ("ped_geo", "defaults"),
        ("ped_sort", "skip"),
    ]);
    let response = app
        .clone()
        .oneshot(request("POST", "/admin/profiles/new", &body, Some(&cookie)))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let profiles = fumox_core::repo::profiles::list(&state.pool, false)
        .await
        .unwrap();
    let created = profiles
        .iter()
        .find(|p| p.name == "TriState")
        .expect("profile created");
    assert_eq!(
        created.pipeline.as_ref().unwrap(),
        &serde_json::json!({
            "version": 1,
            "geo": {},
            "health": { "exclude_statuses": ["alive", "unknown"] }
        })
    );

    // The tri-state survives a reopen: the edit form carries the radios
    // in their saved positions.
    let response = app
        .clone()
        .oneshot(request(
            "GET",
            &format!("/admin/profiles/{}/edit", created.id),
            "",
            Some(&cookie),
        ))
        .await
        .unwrap();
    let html = response.into_body().collect().await.unwrap().to_bytes();
    let html = String::from_utf8_lossy(&html);
    assert!(html.contains(r#"id="ped-geo-defaults" checked"#), "{html}");
    assert!(html.contains(r#"id="ped-health-set" checked"#), "{html}");
    assert!(html.contains(r#"id="ped-status-alive" checked"#), "{html}");
    assert!(
        html.contains(r#"id="ped-status-unknown" checked"#),
        "{html}"
    );
    assert!(html.contains("переопределяет разделы"), "{html}");

    // Rename "defaults" is the explicit `[]` reset.
    let body = urlencoded(&[
        ("_csrf", &csrf),
        ("name", "Rename reset"),
        ("output_format", "uri_list"),
        ("pipeline_mode", "builder"),
        ("ped_rename", "defaults"),
        ("ped_rename_0_match", "typed but skipped"),
    ]);
    let response = app
        .clone()
        .oneshot(request("POST", "/admin/profiles/new", &body, Some(&cookie)))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let profiles = fumox_core::repo::profiles::list(&state.pool, false)
        .await
        .unwrap();
    let created = profiles
        .iter()
        .find(|p| p.name == "Rename reset")
        .expect("profile created");
    assert_eq!(
        created.pipeline.as_ref().unwrap(),
        &serde_json::json!({ "version": 1, "rename": [] })
    );
}

#[tokio::test]
async fn source_edit_form_prefills_the_builder_from_the_pipeline() {
    let (_dir, state) = test_state(1000).await;
    let app = router(state.clone());
    let cookie = login(&app).await;

    // A source whose pipeline the builder fully understands.
    let source = fumox_core::models::Source {
        pipeline: Some(serde_json::json!({
            "version": 1,
            "filter": { "protocols": ["vless"] },
            "sort": { "by": "name", "desc": true }
        })),
        ..test_source("srcBuilder0001", "builder-ok")
    };
    fumox_core::repo::sources::create(&state.pool, &source)
        .await
        .unwrap();

    let response = app
        .clone()
        .oneshot(request(
            "GET",
            &format!("/admin/sources/{}/edit", source.id),
            "",
            Some(&cookie),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let html = response.into_body().collect().await.unwrap().to_bytes();
    let html = String::from_utf8_lossy(&html);
    // Builder mode by default, filter section set, vless selected (but
    // not trojan), sort by name descending. The filter section now uses
    // the tri-state radios (post-fix); `ped-filter-set` carries the
    // checked marker for the source form.
    assert!(
        html.contains(r#"name="pipeline_mode" value="builder""#),
        "{html}"
    );
    assert!(html.contains(r#"id="ped-filter-set" checked"#), "{html}");
    assert!(
        html.contains(r#"name="ped_filter_protocols" value="vless" id="ped-proto-vless" checked"#),
        "{html}"
    );
    assert!(!html.contains("ped-proto-trojan\" checked"), "{html}");
    assert!(html.contains(r#"<option value="name" selected>"#), "{html}");
    assert!(html.contains(r#"id="ped-sort-desc" checked"#), "{html}");
    // No raw-mode warning: the pipeline is fully representable.
    assert!(
        !html.contains("невозможно представить в конструкторе"),
        "{html}"
    );

    // A pipeline the builder cannot represent: raw-mode warning instead
    // of a prefill, the JSON itself kept in the textarea.
    let source = fumox_core::models::Source {
        pipeline: Some(serde_json::json!({ "version": 1, "bogus": true })),
        ..test_source("srcBuilder0002", "builder-raw")
    };
    fumox_core::repo::sources::create(&state.pool, &source)
        .await
        .unwrap();
    let response = app
        .oneshot(request(
            "GET",
            &format!("/admin/sources/{}/edit", source.id),
            "",
            Some(&cookie),
        ))
        .await
        .unwrap();
    let html = response.into_body().collect().await.unwrap().to_bytes();
    let html = String::from_utf8_lossy(&html);
    assert!(
        html.contains("невозможно представить в конструкторе"),
        "{html}"
    );
    assert!(
        html.contains(r#"name="pipeline_mode" value="raw""#),
        "{html}"
    );
    assert!(html.contains("&#34;bogus&#34;"), "{html}");
}

/// The fetch journal tables (full page, source-card fragment and the
/// dashboard's recent fetches) carry the `journal` class: their columns
/// stay single-line while the error column keeps wrapping via
/// `.cell-wrap` (a long error message must not re-flow the row).
#[tokio::test]
async fn fetch_journal_tables_keep_columns_single_line() {
    let (_dir, state) = test_state(1000).await;
    let pool = state.pool.clone();
    let source = test_source("srcJournal000", "journal");
    fumox_core::repo::sources::create(&pool, &source)
        .await
        .unwrap();
    let now = fumox_core::models::now_ts();
    for entry in [
        fumox_core::repo::fetch_log::FetchLogEntry {
            source_id: &source.id,
            fetched_at: now,
            ok: true,
            http_status: Some(200),
            bytes: Some(1024),
            proxies_found: Some(42),
            error: None,
            error_class: None,
        },
        fumox_core::repo::fetch_log::FetchLogEntry {
            source_id: &source.id,
            fetched_at: now - 60,
            ok: false,
            http_status: None,
            bytes: None,
            proxies_found: None,
            error: Some(
                "error sending request for url (https://example.com/sub/): \
                     operation timed out waiting on connection \
                     operation timed out waiting on connection",
            ),
            error_class: Some(fumox_core::models::ErrorClass::Network),
        },
    ] {
        fumox_core::repo::fetch_log::insert(&pool, &entry)
            .await
            .unwrap();
    }

    let app = router(state.clone());
    let cookie = login(&app).await;
    // Every page below renders the journal table, so the wrapping error cell is asserted on each.
    for (path, check_error_cell) in [
        ("/admin/logs/fetch", true),
        (&format!("/admin/sources/{}/log", source.id), true),
        (&format!("/admin/sources/{}", source.id), true),
    ] {
        let response = app
            .clone()
            .oneshot(request("GET", path, "", Some(&cookie)))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK, "path {path}");
        let html = response.into_body().collect().await.unwrap().to_bytes();
        let html = String::from_utf8_lossy(&html);
        assert!(
            html.contains(r#"<table class="data journal">"#),
            "journal table missing on {path}"
        );
        // Every data table sits in a horizontal scroll container so a
        // narrow viewport scrolls the table, never the page.
        assert!(
            html.contains(r#"<div class="table-scroll">"#),
            "table-scroll wrapper missing on {path}"
        );
        // The error column keeps its wrapping cell; other columns are
        // single-line through the table class.
        if check_error_cell {
            assert!(
                html.contains(r#"<span class="cell-wrap">"#),
                "wrapping error cell missing on {path}"
            );
        }
    }

    // The source card's log is live: it polls the same fragment the
    // page renders inline and refreshes on fetch.done/fetch.failed.
    let response = app
        .oneshot(request(
            "GET",
            &format!("/admin/sources/{}", source.id),
            "",
            Some(&cookie),
        ))
        .await
        .unwrap();
    let html = response.into_body().collect().await.unwrap().to_bytes();
    let html = String::from_utf8_lossy(&html);
    assert!(
        html.contains(&format!(r#"hx-get="/admin/sources/{}/log""#, source.id)),
        "log-live polling missing on the source card"
    );
}

/// Regression: after `settings_update` writes the form,
/// `refresh_live_config` must swap the file into the single live
/// view so `state.live()` and the typed accessors see the new
/// values, not the startup snapshot.
#[tokio::test]
async fn live_config_refresh_picks_up_post_save_state() {
    let (_dir, state) = test_state(1000).await;

    // The starting snapshot reflects `AppConfig::default()`; the
    // toggle is *off* and the public listener sits on 8080.
    assert!(!state.live().ingest.drop_gate);
    assert!(!state.ingest().drop_gate);
    assert_eq!(state.server().bind.port(), 8080);

    // Drop a config file on disk that flips the bool and rebinds
    // the public listener. The file is missing fields the defaults
    // supply (`probe.*`, `meow.*`, `database.*`, …), `figment`
    // fills them in via the `Serialized::defaults` layer.
    let dir = fumox_core::tempdir_lite::TempDir::new("live-refresh");
    let path = dir.path().join("app.toml");
    std::fs::write(
        &path,
        "[ingest]\ndrop_gate = true\n[server]\nbind = \"127.0.0.1:9999\"\n",
    )
    .unwrap();

    state
        .refresh_live_config(&path)
        .expect("file we just wrote must load cleanly");

    // The live figment-merged view reflects the file.
    let live = state.live();
    assert!(live.ingest.drop_gate, "live.ingest.drop_gate");
    assert_eq!(live.server.bind.port(), 9999, "live.server.bind");
    // Figment-merged defaults are written back into the in-memory view.
    assert_eq!(
        live.probe.fail_limit,
        fumox_core::config::ProbeConfig::default().fail_limit
    );
    assert_eq!(
        live.fetch.user_agent,
        fumox_core::config::FetchConfig::default().user_agent
    );

    // The typed accessors read the same live view: there is no
    // second, frozen copy for a handler to read by mistake, so every
    // consumer sees the post-save state.
    assert!(state.ingest().drop_gate, "state.ingest().drop_gate");
    assert_eq!(state.server().bind.port(), 9999, "state.server().bind");

    // The genuinely startup-frozen values stay put: the socket is
    // still bound to 8080, and the HMAC keys/limiters derived at
    // startup are plain fields, not config reads. Re-binding the
    // listener and silently invalidating sessions would be a
    // footgun, which is why they are explicit.
    assert_eq!(
        state.server_bind.port(),
        8080,
        "server_bind stays startup-frozen"
    );
}
