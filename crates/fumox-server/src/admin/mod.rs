//! Admin panel: SSR (askama) + HTMX, served on a dedicated loopback
//! listener. Multilingual UI (Russian default, English and
//! any number of extra languages from external TOML catalogs, switchable on
//! the login screen) with day/night themes, no frontend build step, static
//! assets vendored into the binary.

pub mod auth;
mod dash_top_n;
mod handlers;
pub mod i18n;
pub(crate) mod pipeline_editor;
pub mod security;
pub mod theme;

use crate::cache::Caches;
use crate::events::EventBus;
use crate::fetcher::Fetcher;
use crate::host_gate;
use crate::scheduler::SchedulerState;
use crate::security::RateLimiter;
use askama::Template;
use axum::extract::{Request, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Redirect, Response};
use fumox_core::config::{
    AdminConfig, DatabaseConfig, FetchConfig, GeoConfig, IngestConfig, LogConfig, MeowConfig,
    ProbeConfig, ResolvedConfigPath, RetentionConfig, ServerConfig,
};
use fumox_core::config_writer::is_writable;
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
    /// On-demand enrichment for the proxy card over every GeoLite2 database
    /// in `[geo].db_dir`, an instance independent of the pipeline resolver
    /// (own cache), unaffected by `[geo].enabled` gating the pipeline.
    pub geo_full: Arc<fumox_core::geo::FullResolver>,
    /// Immediate-refresh channel into the scheduler (source ids).
    pub refresh_tx: tokio::sync::mpsc::UnboundedSender<String>,
    /// Scheduler handle: in-flight status for *Refresh now* fragments.
    pub scheduler: SchedulerState,
    /// Event bus feeding the SSE endpoint (`/admin/events`).
    pub events: EventBus,
    /// HTTP fetcher shared with the scheduler; reused by dry-run so the
    /// SSRF vetting is exactly the same code path.
    pub fetcher: Fetcher,
    /// Public subscription listener (`[server].bind`); its port builds the
    /// serve links shown on the source/profile cards. Startup-frozen on
    /// purpose: the listener is already bound to this socket, a mid-run
    /// config change could not rebind it anyway.
    pub server_bind: SocketAddr,
    /// HMAC key for session cookies, derived from the admin token so that
    /// rotating the token revokes every existing session.
    pub session_key: Vec<u8>,
    /// HMAC key for CSRF tokens (independent from the session key).
    pub csrf_key: Vec<u8>,
    /// Per-IP rate limiter for `POST /admin/login`.
    pub login_limiter: Arc<RateLimiter>,
    /// Per-IP rate limiter for the rest of `/admin/*`.
    pub admin_limiter: Arc<RateLimiter>,
    /// CIDRs of reverse proxies whose `X-Forwarded-For` / RFC 7239 `Forwarded:
    /// for=…` are honored for the admin per-IP rate-limit key. Empty = never
    /// honor forwarded headers.
    pub trusted_cidrs: Vec<ipnet::IpNet>,
    /// UI message catalogs, loaded once at startup from `[admin].locales_dir`
    /// with the shipped ru/en catalogs embedded as fallback.
    pub locales: Arc<i18n::Locales>,
    /// TOML file actually merged at startup. `Loaded(path)` means an
    /// editable file exists; `Missing` means the server is running on
    /// built-in defaults and there is no file on disk yet. The admin
    /// panel *Edit settings* page writes back to this path.
    pub config_path: ResolvedConfigPath,
    /// Cached answer to `is_writable(config_path)`. Computed once at
    /// startup, covers the "parent directory writable, file missing"
    /// case so the *Create from defaults* button can still appear.
    pub config_writable: bool,
    /// Figment-merged config (defaults → file → `FUMOX_*` env), the
    /// single source of config truth for every handler. Refreshed after
    /// every successful `settings_update` / `settings_create` so every
    /// read through [`AdminState::live`] or the typed accessors
    /// (`admin()`, `server()`, …) sees the post-save state instead of a
    /// startup snapshot. ENV overrides keep their priority because
    /// `load()` re-merges them on every refresh. The values that are
    /// genuinely startup-frozen (the HMAC keys, the rate limiters,
    /// `server_bind`) are explicit fields above, not config reads.
    pub live_config: Arc<std::sync::RwLock<fumox_core::AppConfig>>,
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
        config_path: ResolvedConfigPath,
    ) -> Self {
        let session_key = auth::derive_key(b"fumox-admin-session", &config.admin.token);
        let csrf_key = auth::derive_key(b"fumox-admin-csrf", &config.admin.token);
        let login_limiter = Arc::new(RateLimiter::new(
            u64::from(config.admin.login_rate_limit.limit),
            config.admin.login_rate_limit.window,
        ));
        let admin_limiter = Arc::new(RateLimiter::new(
            u64::from(config.admin.rate_limit.limit),
            config.admin.rate_limit.window,
        ));
        let locales = Arc::new(i18n::Locales::load(std::path::Path::new(
            &config.admin.locales_dir,
        )));
        let geo_full = Arc::new(fumox_core::geo::FullResolver::from_dir(&config.geo));
        let trusted_cidrs = parse_trusted_cidrs(&config.admin.trust_proxy_ips);
        // The *Edit settings* page writes to this exact path; compute
        // writability once so the button state and the read-only banner
        // stay in sync. `Missing` means the file is absent on disk and
        // we fall back to checking the default's parent directory so
        // the *Create from defaults* button can still be offered.
        let config_writable = match &config_path {
            ResolvedConfigPath::Loaded(p) => is_writable(p),
            ResolvedConfigPath::Missing => {
                is_writable(std::path::Path::new(fumox_core::DEFAULT_CONFIG_PATH))
            }
        };
        Self {
            pool,
            caches,
            geo,
            geo_full,
            refresh_tx,
            scheduler,
            events,
            fetcher,
            server_bind: config.server.bind,
            session_key,
            csrf_key,
            login_limiter,
            admin_limiter,
            trusted_cidrs,
            locales,
            config_path,
            config_writable,
            live_config: Arc::new(std::sync::RwLock::new(config)),
        }
    }

    /// Snapshot of the latest figment-merged config. Cheap: clones the
    /// held `AppConfig`. Handlers that need several blocks at once read
    /// from this; for a single block the typed accessors below clone
    /// less.
    pub fn live(&self) -> fumox_core::AppConfig {
        self.live_config
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }

    // Typed accessors over the live config. Every handler reads through
    // one of these (or `live()`), so a value saved on the settings screen
    // is visible immediately; there is no second, frozen copy to get out
    // of sync. Values that must NOT move mid-run (the HMAC keys, the
    // rate limiters, `server_bind`) are plain fields, not accessors.

    /// The live `[admin]` block (token, rate limits, TTL).
    pub fn admin(&self) -> AdminConfig {
        self.live().admin
    }

    /// The live `[server]` block (public listener).
    pub fn server(&self) -> ServerConfig {
        self.live().server
    }

    /// The live `[database]` block.
    pub fn database(&self) -> DatabaseConfig {
        self.live().database
    }

    /// The live `[fetch]` block (HTTP fetching knobs).
    pub fn fetch(&self) -> FetchConfig {
        self.live().fetch
    }

    /// The live `[ingest]` block.
    pub fn ingest(&self) -> IngestConfig {
        self.live().ingest
    }

    /// The live `[geo]` block (the `geo: Arc<GeoResolver>` field is the
    /// live resolver, not the config).
    pub fn geo_config(&self) -> GeoConfig {
        self.live().geo
    }

    /// The live `[probe]` block.
    pub fn probe(&self) -> ProbeConfig {
        self.live().probe
    }

    /// The live `[meow]` block.
    pub fn meow(&self) -> MeowConfig {
        self.live().meow
    }

    /// The live `[retention]` block.
    pub fn retention(&self) -> RetentionConfig {
        self.live().retention
    }

    /// The live `[log]` block (console log levels).
    pub fn log(&self) -> LogConfig {
        self.live().log
    }

    /// Reload the on-disk config via the figment merge
    /// (defaults → TOML → `FUMOX_*` env) and swap it into the live
    /// view. Cheap (a single small file read); called from
    /// `settings_update` and `settings_create` after every successful
    /// write so subsequent GETs render the fresh values. Returns the
    /// underlying `config::Error` so the caller can surface it through
    /// a banner; the in-memory view is left untouched on failure.
    pub fn refresh_live_config(&self, path: &std::path::Path) -> fumox_core::Result<()> {
        let loaded = fumox_core::config::load(Some(path))?;
        let mut guard = self
            .live_config
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        *guard = loaded.config;
        Ok(())
    }

    /// Base URL for the serve links shown on the source/profile cards:
    /// the host the admin panel was opened on (Host header) with the
    /// public port from `[server].bind`, https when the admin request
    /// itself arrived over https (see `request_is_https`).
    ///
    /// The link is validated against `[admin].allowed_hosts`, the same
    /// list `enforce_allowed_hosts` gates the request with, so a host that
    /// reaches a handler can never be turned into a 500 by the three
    /// callers that render a serve link (sources, profiles, Import/Export).
    ///
    /// One fail mode is removed, not both. The public listener gates on its
    /// own `[server].allowed_hosts` (see `alive_export::serve_tier`), so
    /// when an operator allowlists a panel host that is not on the public
    /// list, the link is still built from the panel's own host and the
    /// public listener answers 404 "link not found" when it is clicked.
    /// Gating on both lists instead would only move the failure: `Err`
    /// reaches handlers that render a hard 500 through `server_error`, and
    /// those call sites live outside this module. The 500 is the worse of
    /// the two, it breaks the whole page, not just one link, so the
    /// panel list wins and the 404-on-click tradeoff is recorded here
    /// instead of being silently dropped.
    fn serve_base(
        &self,
        peer: SocketAddr,
        headers: &HeaderMap,
    ) -> Result<String, host_gate::HostRejected> {
        serve_base(
            self.server_bind,
            peer,
            headers,
            &self.trusted_cidrs,
            &self.admin().allowed_hosts,
        )
    }

    /// Session TTL as a duration.
    fn session_ttl(&self) -> std::time::Duration {
        std::time::Duration::from_secs(u64::from(self.admin().session_ttl_hours) * 3600)
    }

    /// CSRF token for the current session cookie (empty when no session).
    fn csrf_for(&self, headers: &axum::http::HeaderMap) -> String {
        let session = auth::session_cookie_value(headers).unwrap_or_default();
        auth::csrf_token(&self.csrf_key, &session)
    }
}

/// Validated `?next=` target shared by the preference setters (`set-lang`,
/// `set-theme`, `set-dash-top-n`): the redirect must stay on the admin
/// surface and must not carry control characters, a percent-decoded CR/LF
/// (e.g. `next=%2Fadmin%0D%0Ax`) would make the `Location` header value
/// invalid and axum answers 500 instead of redirecting. Anything invalid
/// falls back to `/admin`.
pub(crate) fn admin_next(params: &std::collections::HashMap<String, String>) -> String {
    params
        .get("next")
        .map(String::as_str)
        .filter(|next| next.starts_with("/admin") && !next.chars().any(|c| c.is_ascii_control()))
        .unwrap_or("/admin")
        .to_string()
}

/// One entry of the trusted-proxy list: an explicit CIDR (`10.0.0.0/8`)
/// or a bare address (`192.168.1.1`, read as its `/32` / `/128` host
/// prefix — what the settings form hint advertises). `None` when the
/// entry is unparsable; the caller decides whether to refuse it (the
/// settings save path) or log-and-drop it (the startup load below).
pub(crate) fn parse_trusted_cidr_entry(entry: &str) -> Option<ipnet::IpNet> {
    match entry.parse::<ipnet::IpNet>() {
        Ok(net) => Some(net),
        // `ipnet`'s `FromStr` demands an explicit `/prefix`, so a bare
        // address falls back to the host prefix. Both rate limiters and
        // the settings editor must see the same contract, which is why
        // the two parse through this one helper.
        Err(_) => entry
            .parse::<std::net::IpAddr>()
            .ok()
            .map(ipnet::IpNet::from),
    }
}

/// Parse the operator-supplied list of trusted-proxy CIDRs. Bad entries
/// are logged and dropped, a typo'd CIDR must never silently widen the
/// trust boundary. Bare IPs are valid entries (see
/// [`parse_trusted_cidr_entry`]): without that fallback the settings
/// form's "one CIDR or IP per line" hint was a lie and a
/// hint-conforming entry was silently emptied here at every restart,
/// degrading per-IP rate limiting to peer-IP keying and switching the
/// X-Forwarded-Proto scheme detection off.
pub(crate) fn parse_trusted_cidrs(raw: &[String]) -> Vec<ipnet::IpNet> {
    raw.iter()
        .filter_map(|s| {
            parse_trusted_cidr_entry(s).or_else(|| {
                tracing::warn!(cidr = %s, "ignoring invalid trust_proxy_ips entry");
                None
            })
        })
        .collect()
}

/// Outermost admin middleware: enforce `[admin].allowed_hosts` at the
/// edge, before rate limiting, auth, CSRF or any handler runs. An empty
/// allowlist is a no-op (accept any host), the behavior for deployments
/// that never configured the list.
///
/// The setting is documented as "hostnames / IPs allowed to reach the
/// admin listener" and editable on the settings screen, but the
/// request-time gate only ever ran for the public listener's alive-export
/// links and the serve-link builder, no admin request passed through it
/// (security review f3). Gating here also removes the inconsistent fail
/// mode where a non-matching Host was served by every page except the
/// three that render serve links, which answered 500 from
/// `build_serve_link_host`: a host that reaches a handler is now always
/// allowlisted.
async fn enforce_allowed_hosts(
    State(state): State<AdminState>,
    req: Request,
    next: Next,
) -> Response {
    if let Err(err) = host_gate::validate_request_host(req.headers(), &state.admin().allowed_hosts)
    {
        tracing::warn!(error = %err, path = %req.uri().path(), "admin request host rejected");
        return (
            StatusCode::BAD_REQUEST,
            [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
            "request Host header is not allowed for the admin panel\n",
        )
            .into_response();
    }
    next.run(req).await
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
        // Bulk cleanup transitions: literal
        // action segments must be registered before the `/{id}` routes.
        .route(
            "/proxies/quarantine-to-removed",
            post(handlers::proxies_quarantine_to_removed),
        )
        .route(
            "/proxies/remove-alive-no-country",
            post(handlers::proxies_remove_alive_no_country),
        )
        .route(
            "/proxies/remove-alive-by-asn",
            post(handlers::proxies_remove_alive_by_asn),
        )
        .route(
            "/proxies/remove-alive-by-country",
            post(handlers::proxies_remove_alive_by_country),
        )
        .route(
            "/proxies/remove-unprobeable",
            post(handlers::proxies_remove_unprobeable),
        )
        // Bulk revival: inverse of cleanup, moves rows back to `unknown`.
        // Literal segments must precede `/{id}` for the same reason.
        .route(
            "/proxies/revive-removed-by-country",
            post(handlers::proxies_revive_removed_by_country),
        )
        .route(
            "/proxies/revive-removed-by-asn",
            post(handlers::proxies_revive_removed_by_asn),
        )
        .route(
            "/proxies/revive-removed-no-history",
            post(handlers::proxies_revive_removed_no_history),
        )
        .route(
            "/proxies/revive-quarantine",
            post(handlers::proxies_revive_quarantine),
        )
        .route("/proxies/{id}", get(handlers::proxy_detail))
        .route("/proxies/{id}/reset", post(handlers::proxy_reset))
        .route(
            "/proxies/{id}/probe-history",
            get(handlers::proxy_probe_history),
        )
        .route("/logs/fetch", get(handlers::fetch_logs))
        .route("/probe", get(handlers::probe_overview))
        .route("/settings", get(handlers::settings_overview))
        .route("/settings/edit", get(handlers::settings_edit))
        .route("/settings/create", post(handlers::settings_create))
        .route("/settings/update", post(handlers::settings_update))
        // Pipeline builder widget: server-side generation
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
        // Logout is a state-changing POST like every other one: the session
        // it clears is the panel's only authentication, and an attacker
        // page that can auto-submit a cross-site form to `/admin/logout`
        // signs the operator out at will. Mounted inside the nest so both
        // `require_auth` and `csrf_protect` run; the form in `base.html`
        // already ships the `_csrf` field the layer checks.
        .route("/logout", post(auth::logout))
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
        .route("/admin/set-lang", get(auth::set_lang))
        .route("/admin/set-theme", get(theme::set_theme))
        .route("/admin/set-dash-top-n", get(dash_top_n::set_top_n))
        .route("/admin/static/app.css", get(static_css))
        .route("/admin/static/htmx.min.js", get(static_htmx))
        // Router-wide request-body cap:
        // the CSRF layer already buffers POSTs at 1 MiB; this gives every
        // other extractor the same bound instead of relying on that
        // coincidence.
        .layer(axum::extract::DefaultBodyLimit::max(1 << 20))
        .layer(axum::middleware::from_fn(security::headers))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            auth::rate_limit,
        ))
        // Added last = outermost: a request whose Host is not allowlisted
        // is rejected before it can burn a rate-limit window or reach any
        // handler (see `enforce_allowed_hosts`).
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            enforce_allowed_hosts,
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

/// Vendored stylesheet.
async fn static_css() -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "text/css; charset=utf-8")],
        include_str!("../../static/app.css"),
    )
}

/// Vendored htmx (fixed version, no CDN, works offline).
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
fn serve_base(
    bind: SocketAddr,
    peer: SocketAddr,
    headers: &HeaderMap,
    trusted_cidrs: &[ipnet::IpNet],
    allowed_hosts: &[String],
) -> Result<String, host_gate::HostRejected> {
    let scheme = if request_is_https(peer, headers, trusted_cidrs) {
        "https"
    } else {
        "http"
    };
    let host = host_gate::build_serve_link_host(bind, headers, allowed_hosts)?;
    let default_port =
        (scheme == "http" && bind.port() == 80) || (scheme == "https" && bind.port() == 443);
    Ok(if default_port {
        format!("{scheme}://{host}")
    } else {
        format!("{scheme}://{host}:{}", bind.port())
    })
}

/// True when the admin request itself arrived over https through a
/// TLS-terminating reverse proxy: `X-Forwarded-Proto: https` (de facto
/// standard) or an RFC 7239 `Forwarded: proto=https` element. Fumox never
/// terminates TLS itself, so without such a header the scheme is http.
///
/// The header is only honored when the peer's source IP falls inside one of
/// the configured `trusted_cidrs`, mirroring the trust gate that
/// `crate::security::client_key` uses for the per-IP rate-limit key, so the URL-scheme
/// decision and the rate-limit key agree on what "peer" means. Empty
/// `trusted_cidrs` ⇒ never honor forwarded headers (the safe default the
/// empty `[admin].trust_proxy_ips` config advertises).
fn request_is_https(peer: SocketAddr, headers: &HeaderMap, trusted_cidrs: &[ipnet::IpNet]) -> bool {
    // 1. No trusted proxies configured ⇒ never honor forwarded headers.
    if trusted_cidrs.is_empty() {
        return false;
    }
    // 2. Peer is not in any trusted CIDR ⇒ header is untrusted.
    if !trusted_cidrs.iter().any(|net| net.contains(&peer.ip())) {
        return false;
    }
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

/// Keep ≥2 dispatchers permanently alive in tracing's global dispatcher
/// registry, for the log-capturing test modules (auth, scheduler): a call
/// site's interest is cached against the dispatchers live at its FIRST
/// execution, and when the registry holds fewer than two, tracing consults
/// the *registering thread's* thread-local default — in a parallel test
/// suite usually no subscriber at all — so call sites get cached as
/// `Interest::never` and their events go silently nowhere for the rest of
/// the process (an intermittent failure that depends purely on test
/// scheduling). With the registry permanently multi-dispatcher, every
/// registration is evaluated against all live dispatchers and lands on
/// `Interest::sometimes`, so capture tests always see their lines. Runtime
/// dispatch is unaffected: threads without a scoped default still resolve
/// to the empty global default and drop their events as before.
///
/// Call once before the first capture; the two subscribers leak on
/// purpose — the permanently-live registrars are the point.
#[cfg(test)]
pub(crate) fn stabilize_callsite_interests() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        for _ in 0..2 {
            let subscriber = tracing_subscriber::fmt()
                .with_ansi(false)
                .with_max_level(tracing::Level::INFO)
                .with_writer(std::io::sink)
                .finish();
            std::mem::forget(tracing::Dispatch::new(subscriber));
        }
    });
}

/// Admin state on a throwaway migrated database, for the admin test
/// modules (this file, handlers/profiles, handlers/import_export): they all
/// need the same wiring, an empty dependency set on a fresh pool, and
/// differ only in the config served. The database lives in a scoped temp
/// directory: keep the returned guard in scope
/// (`let (_dir, state) = test_admin_state(...).await`) and it is removed
/// with everything inside when the guard drops.
#[cfg(test)]
pub(crate) async fn test_admin_state(
    admin: AdminConfig,
    server: ServerConfig,
) -> (fumox_core::tempdir_lite::TempDir, AdminState) {
    let dir = fumox_core::tempdir_lite::TempDir::new("admin");
    let pool = fumox_core::db::connect_pool(&DatabaseConfig {
        path: dir.path().join("test.db"),
        ..Default::default()
    })
    .await
    .unwrap();
    fumox_core::db::migrate(&pool).await.unwrap();
    let (refresh_tx, refresh_rx) = tokio::sync::mpsc::unbounded_channel();
    std::mem::forget(refresh_rx); // keep the channel open for sends
    let geo_cfg = GeoConfig {
        enabled: false,
        ..Default::default()
    };
    let config = fumox_core::AppConfig {
        admin,
        server,
        ..Default::default()
    };
    let fetcher = Fetcher::new(
        config.fetch.clone(),
        config.admin.allow_private_urls,
        config.geo.dns_timeout(),
    );
    (
        dir,
        AdminState::new(
            pool,
            crate::cache::Caches::new(),
            std::sync::Arc::new(GeoResolver::new(&geo_cfg)),
            refresh_tx,
            SchedulerState::new(1),
            EventBus::new(),
            fetcher,
            config,
            ResolvedConfigPath::Missing,
        ),
    )
}

#[cfg(test)]
#[path = "admin_tests.rs"]
mod tests;
