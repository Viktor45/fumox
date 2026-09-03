//! Admin panel: SSR (askama) + HTMX, served on a dedicated loopback
//! listener (ADMIN_PLAN §2). Multilingual UI (Russian default, English and
//! any number of extra languages from external TOML catalogs, switchable on
//! the login screen) with day/night themes, no frontend build step, static
//! assets vendored into the binary.

pub mod auth;
mod handlers;
pub mod i18n;
pub(crate) mod pipeline_editor;
pub mod security;
pub mod theme;

use crate::cache::Caches;
use crate::events::EventBus;
use crate::fetcher::Fetcher;
use crate::scheduler::SchedulerState;
use askama::Template;
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Redirect, Response};
use fumox_core::config::{AdminConfig, MeowConfig, ProbeConfig, RetentionConfig};
use fumox_core::db::DbPool;
use fumox_core::geo::GeoResolver;
use i18n::Lang;
use std::net::SocketAddr;
use std::sync::Arc;

/// Shared state for every admin handler.
#[derive(Clone)]
pub struct AdminState {
    pub pool: DbPool,
    pub caches: Caches,
    pub geo: Arc<GeoResolver>,
    /// On-demand enrichment over every GeoLite2 database in `[geo].db_dir`
    /// (admin proxy-card "resolve City/ASN" action). Opened lazily on first
    /// use — the files are large and the action is rare.
    pub geo_full: Arc<fumox_core::geo::FullResolver>,
    /// Immediate-refresh channel into the scheduler (source ids).
    pub refresh_tx: tokio::sync::mpsc::UnboundedSender<String>,
    /// Scheduler handle: in-flight status for "обновить сейчас" fragments.
    pub scheduler: SchedulerState,
    /// Event bus feeding the SSE endpoint (`/admin/events`).
    pub events: EventBus,
    /// HTTP fetcher shared with the scheduler; reused by dry-run so the
    /// SSRF vetting is exactly the same code path (ADMIN_PLAN §13.11).
    pub fetcher: Fetcher,
    /// The `[admin]` configuration block (token, rate limits, TTL).
    pub admin: AdminConfig,
    /// Public subscription listener (`[server].bind`); its port builds the
    /// serve links shown on the source/profile cards.
    pub server_bind: SocketAddr,
    /// Read-only probe/meow/retention settings shown on `/admin/probe`
    /// (ADMIN_PLAN §4.5).
    pub probe: ProbeConfig,
    pub meow: MeowConfig,
    pub retention: RetentionConfig,
    /// HMAC key for session cookies, derived from the admin token so that
    /// rotating the token revokes every existing session (ADMIN_PLAN §13.1).
    pub session_key: Vec<u8>,
    /// HMAC key for CSRF tokens (independent from the session key).
    pub csrf_key: Vec<u8>,
    /// Per-IP rate limiter for `POST /admin/login`.
    pub login_limiter: Arc<auth::RateLimiter>,
    /// Per-IP rate limiter for the rest of `/admin/*`.
    pub admin_limiter: Arc<auth::RateLimiter>,
    /// UI message catalogs, loaded once at startup from `[admin].locales_dir`
    /// with the shipped ru/en catalogs embedded as fallback.
    pub locales: Arc<i18n::Locales>,
}

impl AdminState {
    // Aggregates every shared dependency of the admin handlers; the breadth
    // is inherent to a constructor wired once at startup.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        pool: DbPool,
        caches: Caches,
        geo: Arc<GeoResolver>,
        refresh_tx: tokio::sync::mpsc::UnboundedSender<String>,
        scheduler: SchedulerState,
        events: EventBus,
        fetcher: Fetcher,
        config: fumox_core::AppConfig,
    ) -> Self {
        let session_key = auth::derive_key(b"fumox-admin-session", &config.admin.token);
        let csrf_key = auth::derive_key(b"fumox-admin-csrf", &config.admin.token);
        let login_limiter = Arc::new(auth::RateLimiter::new(
            u64::from(config.admin.login_rate_limit.limit),
            config.admin.login_rate_limit.window,
        ));
        let admin_limiter = Arc::new(auth::RateLimiter::new(
            u64::from(config.admin.rate_limit.limit),
            config.admin.rate_limit.window,
        ));
        let locales = Arc::new(i18n::Locales::load(std::path::Path::new(
            &config.admin.locales_dir,
        )));
        let geo_full = Arc::new(fumox_core::geo::FullResolver::from_dir(&config.geo));
        Self {
            pool,
            caches,
            geo,
            geo_full,
            refresh_tx,
            scheduler,
            events,
            fetcher,
            admin: config.admin.clone(),
            server_bind: config.server.bind,
            probe: config.probe.clone(),
            meow: config.meow.clone(),
            retention: config.retention.clone(),
            session_key,
            csrf_key,
            login_limiter,
            admin_limiter,
            locales,
        }
    }

    /// Base URL for the serve links shown on the source/profile cards:
    /// the host the admin panel was opened on (Host header) with the
    /// public port from `[server].bind`, https when the admin request
    /// itself arrived over https (see `request_is_https`).
    fn serve_base(&self, headers: &HeaderMap) -> String {
        serve_base(self.server_bind, headers)
    }

    /// Session TTL as a duration.
    fn session_ttl(&self) -> std::time::Duration {
        std::time::Duration::from_secs(u64::from(self.admin.session_ttl_hours) * 3600)
    }

    /// CSRF token for the current session cookie (empty when no session).
    fn csrf_for(&self, headers: &axum::http::HeaderMap) -> String {
        let session = auth::session_cookie_value(headers).unwrap_or_default();
        auth::csrf_token(&self.csrf_key, &session)
    }
}

/// Build the admin router. Mounted only when the panel is active
/// (enabled + non-empty token); otherwise the listener serves 404.
pub fn router(state: AdminState) -> axum::Router {
    use axum::routing::{get, post};

    // Middleware execution is outside-in: `require_auth` (added last) runs
    // first, then CSRF, then the handler.
    let protected = axum::Router::new()
        .route("/", get(handlers::dashboard))
        .route("/sources", get(handlers::sources_list))
        .route(
            "/sources/new",
            get(handlers::source_form).post(handlers::source_create),
        )
        .route("/sources/{id}", get(handlers::source_detail))
        .route(
            "/sources/{id}/edit",
            get(handlers::source_edit_form).post(handlers::source_update),
        )
        .route("/sources/{id}/toggle", post(handlers::source_toggle))
        .route("/sources/{id}/refresh", post(handlers::source_refresh))
        .route(
            "/sources/{id}/refresh-status",
            get(handlers::source_refresh_status),
        )
        .route("/sources/{id}/delete", post(handlers::source_delete))
        .route("/sources/{id}/log", get(handlers::source_log))
        .route("/sources/{id}/dry-run", post(handlers::source_dry_run))
        .route("/profiles", get(handlers::profiles_list))
        .route(
            "/profiles/new",
            get(handlers::profile_form).post(handlers::profile_create),
        )
        .route("/profiles/{id}", get(handlers::profile_detail))
        .route(
            "/profiles/{id}/edit",
            get(handlers::profile_edit_form).post(handlers::profile_update),
        )
        .route("/profiles/{id}/toggle", post(handlers::profile_toggle))
        .route("/profiles/{id}/delete", post(handlers::profile_delete))
        .route("/proxies", get(handlers::proxies_list))
        .route(
            "/proxies/purge-removed",
            post(handlers::proxies_purge_removed),
        )
        .route("/proxies/{id}", get(handlers::proxy_detail))
        .route("/proxies/{id}/reset", post(handlers::proxy_reset))
        .route(
            "/proxies/{id}/probe-history",
            get(handlers::proxy_probe_history),
        )
        .route("/logs/fetch", get(handlers::fetch_logs))
        .route("/probe", get(handlers::probe_overview))
        .route("/stats", get(handlers::stats))
        // Pipeline builder widget (PIPELINE.md §3): server-side generation
        // and validation inside the same auth+CSRF envelope as every POST.
        .route("/pipeline/preview", post(handlers::pipeline_preview))
        .route("/pipeline/mode", post(handlers::pipeline_mode))
        .route("/pipeline/preset", post(handlers::pipeline_preset))
        .route("/pipeline/rows", post(handlers::pipeline_rows))
        .route("/export", get(handlers::export_config))
        .route(
            "/import",
            get(handlers::import_form).post(handlers::import_submit),
        )
        .route("/import/alive-token", post(handlers::rotate_alive_token))
        .route("/events", get(handlers::events_stream))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            auth::csrf_protect,
        ))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            auth::require_auth,
        ));

    // axum's nesting matches `/admin` but not `/admin/`; the trailing-slash
    // variant is a plain redirect to the canonical entry point.
    axum::Router::new()
        .nest("/admin", protected)
        .route("/admin/", get(|| async { Redirect::to("/admin") }))
        .route(
            "/admin/login",
            get(auth::login_form).post(auth::login_submit),
        )
        .route("/admin/logout", post(auth::logout))
        .route("/admin/set-lang", get(auth::set_lang))
        .route("/admin/set-theme", get(theme::set_theme))
        .route("/admin/static/app.css", get(static_css))
        .route("/admin/static/htmx.min.js", get(static_htmx))
        .layer(axum::middleware::from_fn(security::headers))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            auth::rate_limit,
        ))
        .with_state(state)
}

/// Render an askama template into an HTML response; template errors are a
/// server bug and become a logged 500.
pub fn render_html(lang: Lang, template: &impl Template, status: StatusCode) -> Response {
    match template.render() {
        Ok(html) => (
            status,
            [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
            html,
        )
            .into_response(),
        Err(err) => {
            tracing::error!(error = %err, "template rendering failed");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
                format!("<h1>500</h1><p>{}</p>", lang.t("err.render_failed")),
            )
                .into_response()
        }
    }
}

/// Vendored stylesheet (ADMIN_PLAN §11, §13.13).
async fn static_css() -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "text/css; charset=utf-8")],
        include_str!("../../static/app.css"),
    )
}

/// Vendored htmx (fixed version, no CDN — works offline).
async fn static_htmx() -> impl IntoResponse {
    (
        [(
            header::CONTENT_TYPE,
            "application/javascript; charset=utf-8",
        )],
        include_str!("../../static/htmx.min.js"),
    )
}

/// Build the base URL of the public subscription endpoints from the
/// public listener address and the request's `Host` header: the host the
/// admin panel was opened on, with the public port from `[server].bind`.
/// The default port (80/443 matching the scheme) is omitted.
fn serve_base(bind: SocketAddr, headers: &HeaderMap) -> String {
    let scheme = if request_is_https(headers) {
        "https"
    } else {
        "http"
    };
    let host = host_from_headers(bind, headers);
    let default_port =
        (scheme == "http" && bind.port() == 80) || (scheme == "https" && bind.port() == 443);
    if default_port {
        format!("{scheme}://{host}")
    } else {
        format!("{scheme}://{host}:{}", bind.port())
    }
}

/// Hostname for serve links: the host part of the request's `Host` header
/// (admin port stripped, IPv6 brackets kept); without a usable header, the
/// bound IP — unless it is unspecified, then loopback.
fn host_from_headers(bind: SocketAddr, headers: &HeaderMap) -> String {
    match headers.get(header::HOST).and_then(|v| v.to_str().ok()) {
        Some(h) if !h.is_empty() => {
            if let Some(rest) = h.strip_prefix('[') {
                format!("[{}]", rest.split(']').next().unwrap_or(rest))
            } else {
                h.rsplit_once(':')
                    .map_or_else(|| h.to_string(), |(host, _)| host.to_string())
            }
        }
        _ => {
            let ip = bind.ip();
            if ip.is_unspecified() {
                "127.0.0.1".to_string()
            } else if ip.is_ipv6() {
                format!("[{ip}]")
            } else {
                ip.to_string()
            }
        }
    }
}

/// True when the admin request itself arrived over https through a
/// TLS-terminating reverse proxy: `X-Forwarded-Proto: https` (de facto
/// standard) or an RFC 7239 `Forwarded: proto=https` element. Fumox never
/// terminates TLS itself, so without such a header the scheme is http.
fn request_is_https(headers: &HeaderMap) -> bool {
    headers
        .get("x-forwarded-proto")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.split(',').any(|p| p.trim().eq_ignore_ascii_case("https")))
        || headers
            .get(header::FORWARDED)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| {
                v.to_ascii_lowercase()
                    .split([',', ';'])
                    .any(|p| p.trim().trim_start_matches("proto=") == "https")
            })
}

#[cfg(test)]
mod tests {
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
        let mut h = HeaderMap::new();
        h.insert(header::HOST, "vpn.example.com:8081".parse().unwrap());
        assert_eq!(serve_base(bind, &h), "http://vpn.example.com:8080");

        // Host without a port.
        let mut h = HeaderMap::new();
        h.insert(header::HOST, "vpn.example.com".parse().unwrap());
        assert_eq!(serve_base(bind, &h), "http://vpn.example.com:8080");

        // IPv6 keeps its brackets; the admin port is stripped.
        let mut h = HeaderMap::new();
        h.insert(header::HOST, "[::1]:8081".parse().unwrap());
        assert_eq!(serve_base(bind, &h), "http://[::1]:8080");

        // No Host header: loopback for an unspecified bind address,
        // the bound IP itself when it is specific.
        assert_eq!(serve_base(bind, &HeaderMap::new()), "http://127.0.0.1:8080");
        let bind: SocketAddr = "192.168.1.5:8080".parse().unwrap();
        assert_eq!(
            serve_base(bind, &HeaderMap::new()),
            "http://192.168.1.5:8080"
        );
    }

    #[test]
    fn serve_base_switches_to_https_behind_tls_proxy() {
        let bind: SocketAddr = "0.0.0.0:8080".parse().unwrap();

        let mut h = HeaderMap::new();
        h.insert(header::HOST, "vpn.example.com".parse().unwrap());
        h.insert(
            header::HeaderName::from_static("x-forwarded-proto"),
            "https".parse().unwrap(),
        );
        assert_eq!(serve_base(bind, &h), "https://vpn.example.com:8080");

        // RFC 7239 Forwarded header.
        let mut h = HeaderMap::new();
        h.insert(header::HOST, "vpn.example.com".parse().unwrap());
        h.insert(
            header::FORWARDED,
            "for=10.0.0.1;proto=https".parse().unwrap(),
        );
        assert_eq!(serve_base(bind, &h), "https://vpn.example.com:8080");

        // Explicit http stays http.
        let mut h = HeaderMap::new();
        h.insert(header::HOST, "vpn.example.com".parse().unwrap());
        h.insert(
            header::HeaderName::from_static("x-forwarded-proto"),
            "http".parse().unwrap(),
        );
        assert_eq!(serve_base(bind, &h), "http://vpn.example.com:8080");

        // A default port matching the scheme is omitted from the URL.
        let mut h = HeaderMap::new();
        h.insert(header::HOST, "vpn.example.com".parse().unwrap());
        h.insert(
            header::HeaderName::from_static("x-forwarded-proto"),
            "https".parse().unwrap(),
        );
        let bind: SocketAddr = "0.0.0.0:443".parse().unwrap();
        assert_eq!(serve_base(bind, &h), "https://vpn.example.com");
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

    async fn test_state(admin_limit: u32) -> AdminState {
        test_state_with_admin(admin_config(admin_limit)).await
    }

    async fn test_state_with_admin(admin: AdminConfig) -> AdminState {
        let dir =
            std::env::temp_dir().join(format!("fumox-admin-test-{}", fumox_core::models::new_id()));
        std::fs::create_dir_all(&dir).unwrap();
        let cfg = fumox_core::config::DatabaseConfig {
            path: dir.join("test.db"),
            ..Default::default()
        };
        let pool = fumox_core::db::connect_pool(&cfg).await.unwrap();
        fumox_core::db::migrate(&pool).await.unwrap();
        let (refresh_tx, refresh_rx) = tokio::sync::mpsc::unbounded_channel();
        std::mem::forget(refresh_rx); // keep the channel open for sends
        let geo_cfg = fumox_core::config::GeoConfig {
            enabled: false,
            ..Default::default()
        };
        let config = fumox_core::AppConfig {
            admin,
            ..Default::default()
        };
        let fetcher = Fetcher::new(config.fetch.clone(), config.admin.allow_private_urls);
        AdminState::new(
            pool,
            crate::cache::Caches::new(),
            Arc::new(GeoResolver::new(&geo_cfg)),
            refresh_tx,
            SchedulerState::new(1),
            EventBus::new(),
            fetcher,
            config,
        )
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
        let state = test_state(1000).await;
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
        let state = test_state(1000).await;
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
        let state = test_state(1000).await;
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
        assert!(html.contains("Дашборд"));

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
        let state = test_state_with_admin(admin).await;
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
        let state = test_state(1000).await;
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

    #[tokio::test]
    async fn rate_limit_kicks_in_past_the_soft_limit() {
        let state = test_state(3).await;
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

    #[tokio::test]
    async fn list_screens_render_for_an_authenticated_session() {
        let state = test_state(1000).await;
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
            "/admin/stats",
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
        let state = test_state(1000).await;
        let app = router(state.clone());
        let cookie = login(&app).await;
        let csrf = csrf_for(&state, &cookie);

        // A control byte inside a header value is refused by the HTTP layer;
        // the form must reject it up front (security audit, 2026-08-30).
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
        let state = test_state(1000).await;
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

    #[tokio::test]
    async fn url_validation_errors_follow_the_panel_language() {
        let state = test_state(1000).await;
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
        let html =
            String::from_utf8_lossy(&response.into_body().collect().await.unwrap().to_bytes())
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
        let html =
            String::from_utf8_lossy(&response.into_body().collect().await.unwrap().to_bytes())
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
        let state = test_state(1000).await;
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
        let state = test_state(1000).await;
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

    #[tokio::test]
    async fn unknown_entities_are_404() {
        let state = test_state(1000).await;
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

    #[tokio::test]
    async fn probe_screen_shows_heartbeat_meow_and_quarantine_queue() {
        let state = test_state(1000).await;
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

        // One quarantined proxy with a scheduled second chance.
        sqlx::query(
            "INSERT INTO proxies (fingerprint, scheme, name, host, port, credential, status,
                                  quarantined_at, second_chance_at, created_at, updated_at)
             VALUES ('fp-q1', 'vless', 'sick-proxy', 'q.example.com', 443, 'c', 'quarantine',
                     ?, ?, 1, 1)",
        )
        .bind(now - 3600)
        .bind(now + 86_400)
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
        assert!(html.contains("Probe"));
        assert!(html.contains("4242")); // pid from the heartbeat
        assert!(html.contains("sick-proxy")); // quarantine queue row
        assert!(html.contains("q.example.com"));
        // Every timestamp renders as a <time> element: RFC 3339 UTC in the
        // datetime attribute, the UTC text as the no-JS fallback (the admin
        // JS in base.html rewrites it into the user's timezone).
        assert!(html.contains("<time class=\"ts\" datetime=\""), "{html}");
        assert!(html.contains("Z\">"), "{html}");
        assert!(html.contains("</time>"), "{html}");
    }

    /// Two sources with proxies in every status plus probe history; the
    /// stats screen must render the per-source health counters, the
    /// longest-living top and the 24h probe success rate.
    #[tokio::test]
    async fn stats_screen_aggregates_per_source_and_top_alive() {
        let state = test_state(1000).await;
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
            .oneshot(request("GET", "/admin/stats", "", Some(&cookie)))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let html = response.into_body().collect().await.unwrap().to_bytes();
        let html = String::from_utf8_lossy(&html).into_owned();

        // The page and its panels render.
        assert!(html.contains("Статистика"), "{html}");
        assert!(html.contains("Прокси по источникам"), "{html}");
        assert!(html.contains("Топ-10 самых живых прокси"), "{html}");
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

    /// Proxy-card geo refresh (SPEC §6, on-demand City/ASN): opening the
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
            enabled: false, // pipeline resolver stays inactive — irrelevant here
            db_dir: db_dir.clone(),
            ..Default::default()
        };

        // Build the state directly (test_state pins db_dir to "config"
        // relative to the crate working directory).
        let dir =
            std::env::temp_dir().join(format!("fumox-admin-geo-{}", fumox_core::models::new_id()));
        std::fs::create_dir_all(&dir).unwrap();
        let db_cfg = fumox_core::config::DatabaseConfig {
            path: dir.join("test.db"),
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
        let fetcher = Fetcher::new(config.fetch.clone(), config.admin.allow_private_urls);
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

        // Opening the card is the whole interaction — no button, no POST.
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
                .expect("ASN database present — ASN expected");
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
        let state = test_state(1000).await;
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

        let state = test_state(1000).await;
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
        let response = app
            .oneshot(request(
                "POST",
                "/admin/sources/srcD0000000/dry-run",
                &format!("_csrf={csrf}"),
                Some(&cookie),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let html = response.into_body().collect().await.unwrap().to_bytes();
        let html = String::from_utf8_lossy(&html);
        assert!(html.contains("успех"));
        assert!(html.contains("1.2.3.4")); // sample line preview

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

    #[tokio::test]
    async fn sse_stream_emits_stats_and_fetch_events() {
        let state = test_state(1000).await;
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

        // The initial probe.stats snapshot arrives immediately.
        loop {
            let frame = tokio::time::timeout_at(deadline, body.frame())
                .await
                .expect("timed out waiting for the initial SSE frame")
                .unwrap()
                .unwrap();
            if let Some(chunk) = frame.data_ref() {
                buf.extend_from_slice(chunk);
            }
            if String::from_utf8_lossy(&buf).contains("probe.stats") {
                break;
            }
        }

        // A published fetch event reaches the same open stream.
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

    // -----------------------------------------------------------------
    // Interface language (i18n)
    // -----------------------------------------------------------------

    #[tokio::test]
    async fn dashboard_defaults_to_russian_and_follows_the_language_cookie() {
        let state = test_state(1000).await;
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
        assert!(html.contains("Дашборд"));

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
        assert!(!html.contains("Дашборд"));
    }

    #[tokio::test]
    async fn login_screen_language_selection_sets_the_cookie() {
        let state = test_state(1000).await;
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
        let state = test_state(1000).await;
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

    // -----------------------------------------------------------------
    // Interface theme (day/night)
    // -----------------------------------------------------------------

    #[tokio::test]
    async fn pages_default_to_light_and_follow_the_theme_cookie() {
        let state = test_state(1000).await;
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
        let state = test_state(1000).await;
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

    // -----------------------------------------------------------------
    // Configuration import/export (Phase 4)
    // -----------------------------------------------------------------

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
            access_token: Some("tok".into()),
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
        let state = test_state(1000).await;
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
        assert_eq!(parsed["profiles"][0]["access_token"], "tok");
        assert_eq!(
            parsed["profiles"][0]["sources"],
            serde_json::json!(["srcX0000000"])
        );
    }

    #[tokio::test]
    async fn import_creates_new_objects_and_remaps_composition() {
        // Export from one database…
        let exporter = test_state(1000).await;
        io_fixture(&exporter).await;
        let export_app = router(exporter);
        let export_cookie = login(&export_app).await;
        let payload = export_body(&export_app, &export_cookie).await;

        // …and import it into a fresh one.
        let state = test_state(1000).await;
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
        assert_eq!(new_profile.access_token.as_deref(), Some("tok"));
        let composition = fumox_core::repo::profiles::get_sources(&pool, &new_profile.id)
            .await
            .unwrap();
        assert_eq!(composition, vec![(new_source.id.clone(), 0)]);
    }

    #[tokio::test]
    async fn import_slug_collision_creates_objects_without_slug() {
        let state = test_state(1000).await;
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
        let state = test_state(1000).await;
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
        let state = test_state(1000).await;
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

    // -----------------------------------------------------------------
    // Pipeline builder (PIPELINE.md, ADMIN_PLAN §13.1 decision 26)
    // -----------------------------------------------------------------

    #[tokio::test]
    async fn pipeline_builder_endpoints_require_auth_and_csrf() {
        let state = test_state(1000).await;
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
        let state = test_state(1000).await;
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
            ("ped_normalize", "1"),
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
        let state = test_state(1000).await;
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
        assert!(html.contains("pipeline останется пустым"), "{html}");
    }

    #[tokio::test]
    async fn pipeline_mode_switches_between_builder_and_raw() {
        let state = test_state(1000).await;
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
        assert!(!html.contains("конструктор не представляет"), "{html}");

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
        assert!(html.contains("конструктор не представляет"), "{html}");
    }

    #[tokio::test]
    async fn pipeline_preset_renders_the_ready_made_state() {
        let state = test_state(1000).await;
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
        assert!(html.contains("pipeline останется пустым"), "{html}");

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
        let state = test_state(1000).await;
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
        // value intact; `drop` travels in the query string exactly like the
        // htmx button's hx-post URL.
        let response = app
            .oneshot(request(
                "POST",
                "/admin/pipeline/rows?drop=0",
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
    }

    #[tokio::test]
    async fn source_form_saves_the_builder_state_as_pipeline_json() {
        let state = test_state(1000).await;
        let app = router(state.clone());
        let cookie = login(&app).await;
        let csrf = csrf_for(&state, &cookie);

        // Builder mode on the source form: the JSON is generated from the
        // widget fields server-side; a stale `pipeline` field is ignored.
        // `ped_normalize`/`ped_geo_enabled` ride along exactly as a browser
        // submits the rendered widget (every checkbox present).
        let body = urlencoded(&[
            ("_csrf", &csrf),
            ("name", "Builder"),
            ("url", "https://example.com/sub"),
            ("cache_ttl_seconds", "3600"),
            ("pipeline_mode", "builder"),
            ("ped_filter", "1"),
            ("ped_filter_protocols", "vless"),
            ("ped_normalize", "1"),
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
        let state = test_state(1000).await;
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
        let state = test_state(1000).await;
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
        // not trojan), sort by name descending.
        assert!(
            html.contains(r#"name="pipeline_mode" value="builder""#),
            "{html}"
        );
        assert!(
            html.contains(r#"name="ped_filter" value="1" id="ped-filter" checked"#),
            "{html}"
        );
        assert!(
            html.contains(
                r#"name="ped_filter_protocols" value="vless" id="ped-proto-vless" checked"#
            ),
            "{html}"
        );
        assert!(!html.contains("ped-proto-trojan\" checked"), "{html}");
        assert!(html.contains(r#"<option value="name" selected>"#), "{html}");
        assert!(html.contains(r#"id="ped-sort-desc" checked"#), "{html}");
        // No raw-mode warning: the pipeline is fully representable.
        assert!(!html.contains("конструктор не представляет"), "{html}");

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
        assert!(html.contains("конструктор не представляет"), "{html}");
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
        let state = test_state(1000).await;
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
        // The dashboard's recent-fetches table has no error column at all,
        // so the wrapping cell is only asserted where the column exists.
        // The source card renders the same _log fragment inline, so it
        // carries the journal table too.
        for (path, check_error_cell) in [
            ("/admin/logs/fetch", true),
            (&format!("/admin/sources/{}/log", source.id), true),
            (&format!("/admin/sources/{}", source.id), true),
            ("/admin", false),
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
}
