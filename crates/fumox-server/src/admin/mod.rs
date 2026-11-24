//! Admin panel: SSR (askama) + HTMX on a dedicated loopback listener.
//! Russian default UI, extra languages from external TOML catalogs,
//! day/night themes, no frontend build step (static assets vendored).

pub mod auth;
mod dash_top_n;
mod flash;
mod handlers;
pub mod i18n;
pub(crate) mod pipeline_editor;
pub(crate) mod presentation;
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
    NetworkConfig, ProbeConfig, ResolvedConfigPath, RetentionConfig, ServerConfig, TrustedHeader,
};
use fumox_core::config_writer::{Writability, is_writable};
use fumox_core::db::DbPool;
use fumox_core::geo::GeoResolver;
use i18n::Lang;
use std::net::SocketAddr;
use std::sync::Arc;

/// Ceiling of the admin panel's rate-limit counters, in keys. High on
/// purpose: the compact keys and small client set cost little memory, and
/// a flood of distinct addresses must not evict a real operator's counter.
const ADMIN_LIMITER_MAX_KEYS: u64 = 250_000;

#[derive(Clone)]
pub struct AdminState {
    pub pool: DbPool,
    pub caches: Caches,
    pub geo: Arc<GeoResolver>,
    /// On-demand enrichment for the proxy card over every GeoLite2 database
    /// in `[geo].db_dir`: separate from the pipeline resolver (own cache),
    /// unaffected by `[geo].enabled`.
    pub geo_full: Arc<fumox_core::geo::FullResolver>,
    /// Immediate-refresh channel into the scheduler (source ids). Bounded:
    /// a send that does not fit is refused (`try_send`), not parked.
    pub refresh_tx: tokio::sync::mpsc::Sender<String>,
    /// Scheduler handle: in-flight status for *Refresh now* fragments.
    pub scheduler: SchedulerState,
    /// Event bus feeding the SSE endpoint (`/admin/events`).
    pub events: EventBus,
    /// HTTP fetcher shared with the scheduler; reused by dry-run so the
    /// SSRF vetting is exactly the same code path.
    pub fetcher: Fetcher,
    /// Public subscription listener (`[server].bind`); its port builds the
    /// serve links. Startup-frozen: the socket is already bound, a mid-run
    /// config change could not rebind it anyway.
    pub server_bind: SocketAddr,
    /// Per-IP rate limiter for `POST /admin/login`.
    pub login_limiter: Arc<RateLimiter>,
    /// Per-IP rate limiter for the rest of `/admin/*`.
    pub admin_limiter: Arc<RateLimiter>,
    /// CIDRs of reverse proxies whose `X-Forwarded-For` / RFC 7239 `Forwarded:
    /// for=…` are honored for the admin per-IP rate-limit key. Empty = never
    /// honor forwarded headers.
    pub trusted_cidrs: Vec<ipnet::IpNet>,
    /// The forwarding header the trusted proxy writes; only that header is
    /// read. `None` honors none, so the peer address stays the client.
    pub trusted_header: TrustedHeader,
    /// The panel's Host allowlist (`[admin].allowed_hosts`), canonicalized
    /// once per config load (startup and every save), never per request.
    /// Shared lock like `live_config`: [`AdminState::refresh_live_config`]
    /// swaps the snapshot so the gate follows the operator's save.
    pub host_allowlist: Arc<std::sync::RwLock<host_gate::HostAllowlist>>,
    /// UI message catalogs, loaded once at startup from `[admin].locales_dir`
    /// with the shipped ru/en catalogs embedded as fallback.
    pub locales: Arc<i18n::Locales>,
    /// TOML file actually merged at startup; `Missing` means the server
    /// runs on built-in defaults. The *Edit settings* page writes back
    /// to this path.
    pub config_path: ResolvedConfigPath,
    /// Cached answer to `is_writable(config_path)`. Computed once at
    /// startup, covers the "parent directory writable, file missing"
    /// case so the *Create from defaults* button can still appear.
    pub config_writable: bool,
    /// Figment-merged config (defaults → file → `FUMOX_*` env), the single
    /// source of config truth, refreshed after every successful
    /// `settings_update` / `settings_create` so [`AdminState::live`] and
    /// the typed accessors see the post-save state (ENV overrides keep
    /// their priority: `load()` re-merges them). Startup-frozen values
    /// (the HMAC keys, the rate limiters, `server_bind`) are plain fields
    /// above, not config reads.
    pub live_config: Arc<std::sync::RwLock<fumox_core::AppConfig>>,
    /// Capability token of the export links, shared with the public
    /// listener so a rotation here reaches it at once.
    pub export_token: crate::alive_export::TokenCache,
    /// Row counts of the two journals, cached for a minute: the retention
    /// card renders them and two COUNT scans need not run per render.
    pub journal_counts: crate::cache::JournalCounts,
    /// Pending one-shot toast messages of the plain-browser path, keyed
    /// by the session. The message never travels through the URL.
    pub flashes: flash::FlashStore,
}

impl AdminState {
    // Aggregates every shared dependency of the admin handlers; the breadth
    // is inherent to a constructor wired once at startup.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        pool: DbPool,
        caches: Caches,
        geo: Arc<GeoResolver>,
        refresh_tx: tokio::sync::mpsc::Sender<String>,
        scheduler: SchedulerState,
        events: EventBus,
        fetcher: Fetcher,
        config: fumox_core::AppConfig,
        config_path: ResolvedConfigPath,
        export_token: crate::alive_export::TokenCache,
    ) -> Self {
        let login_limiter = Arc::new(RateLimiter::with_capacity(
            u64::from(config.admin.login_rate_limit.limit),
            config.admin.login_rate_limit.window,
            ADMIN_LIMITER_MAX_KEYS,
        ));
        let admin_limiter = Arc::new(RateLimiter::with_capacity(
            u64::from(config.admin.rate_limit.limit),
            config.admin.rate_limit.window,
            ADMIN_LIMITER_MAX_KEYS,
        ));
        let locales = Arc::new(i18n::Locales::load(std::path::Path::new(
            &config.admin.locales_dir,
        )));
        let geo_full = Arc::new(fumox_core::geo::FullResolver::from_dir(&config.geo));
        let trusted_cidrs = parse_trusted_cidrs(&config.admin.trust_proxy_ips);
        // Writability computed once so the button state and the read-only
        // banner stay in sync; `Missing` falls back to the default's parent
        // directory so *Create from defaults* is still offered
        let config_writable = match &config_path {
            ResolvedConfigPath::Loaded(p) => {
                matches!(is_writable(p), Ok(Writability::Writable))
            }
            ResolvedConfigPath::Missing => matches!(
                is_writable(std::path::Path::new(fumox_core::DEFAULT_CONFIG_PATH)),
                Ok(Writability::Writable)
            ),
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
            login_limiter,
            admin_limiter,
            trusted_cidrs,
            trusted_header: config.admin.trust_proxy_header,
            host_allowlist: Arc::new(std::sync::RwLock::new(host_gate::HostAllowlist::new(
                &config.admin.allowed_hosts,
            ))),
            locales,
            config_path,
            config_writable,
            live_config: Arc::new(std::sync::RwLock::new(config)),
            export_token,
            journal_counts: crate::cache::JournalCounts::new(std::time::Duration::from_secs(60)),
            flashes: flash::FlashStore::new(),
        }
    }

    /// Snapshot of the latest figment-merged config. Cheap: clones the
    /// held `AppConfig`. The typed accessors below read their block out of
    /// this same clone, so they cost the same as an explicit `live()` call.
    pub fn live(&self) -> fumox_core::AppConfig {
        self.live_config
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }

    // Handlers read config through these (or `live()`), so a value saved
    // on the settings screen is visible immediately; there is no frozen
    // copy to drift. Values that must NOT move mid-run (the HMAC keys,
    // the rate limiters, `server_bind`) are plain fields, not accessors

    /// The live `[admin]` block (token, rate limits, TTL).
    pub fn admin(&self) -> AdminConfig {
        self.live().admin
    }

    /// Borrow the canonicalized allowlist for the duration of the call:
    /// never re-canonicalized or cloned per request.
    pub fn host_allowlist(&self) -> std::sync::RwLockReadGuard<'_, host_gate::HostAllowlist> {
        self.host_allowlist
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// The live admin token, read without cloning the whole config.
    pub fn admin_token(&self) -> String {
        self.live_config
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .admin
            .token
            .clone()
    }

    /// HMAC key for the session cookies, derived from the live token on
    /// every use: a token rotated through the settings screen must change
    /// the effective key at once, not at the next restart. One SHA-256 is
    /// noise next to the revocation-epoch read every request does anyway.
    pub fn session_key(&self) -> [u8; 32] {
        auth::derive_key(b"fumox-admin-session", &self.admin_token())
    }

    /// HMAC key for the CSRF tokens, derived from the live token like
    /// [`AdminState::session_key`] but with its own purpose tag, so the
    /// two keys never coincide.
    pub fn csrf_key(&self) -> [u8; 32] {
        auth::derive_key(b"fumox-admin-csrf", &self.admin_token())
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

    /// The live `[network]` block (the DNS resolution timeout of the
    /// source fetcher, plus the speed/trace measurement endpoints).
    pub fn network(&self) -> NetworkConfig {
        self.live().network
    }

    /// Reload the on-disk config via the figment merge (defaults → TOML →
    /// `FUMOX_*` env) and swap it into the live view. Called after every
    /// successful `settings_update` / `settings_create`. Returns the
    /// underlying `config::Error` for the caller's banner; the in-memory
    /// view is untouched on failure.
    pub fn refresh_live_config(&self, path: &std::path::Path) -> fumox_core::Result<()> {
        let loaded = fumox_core::config::load(Some(path))?;
        // The same warning the startup path prints: an operator who
        // moved the panel onto a public address through the settings
        // form has to learn that the cookie now travels in clear text
        if loaded.config.admin.insecure_cookies_on_a_public_bind() {
            tracing::warn!(
                bind = %loaded.config.admin.bind,
                "admin session cookie is not marked Secure while the panel listens on a public \
                 address: the session token travels in clear text"
            );
        }
        // Rebuild the canonicalized allowlist so the gate follows the
        // save without re-canonicalizing per request
        let allowlist = host_gate::HostAllowlist::new(&loaded.config.admin.allowed_hosts);
        let mut guard = self
            .live_config
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        *guard = loaded.config;
        drop(guard);
        *self
            .host_allowlist
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = allowlist;
        Ok(())
    }

    /// Base URL for the serve links on the source/profile cards: the host
    /// the panel was opened on with the public port from `[server].bind`,
    /// https when the admin request itself arrived over https.
    ///
    /// The host is validated against `[admin].allowed_hosts`, the same
    /// list `enforce_allowed_hosts` gates with, so a host that reaches a
    /// handler can never 500 the serve-link callers. The public listener
    /// gates on its own `[server].allowed_hosts` instead, so a panel host
    /// missing there yields a 404 "link not found" on click, not a 500:
    /// gating on both lists would only move the failure to an `Err` that
    /// handlers outside this module turn into a page-breaking 500.
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
            self.trusted_header,
            &self.host_allowlist(),
        )
    }

    fn session_ttl(&self) -> std::time::Duration {
        std::time::Duration::from_secs(u64::from(self.admin().session_ttl_hours) * 3600)
    }

    /// CSRF token for the current session cookie (empty when no session).
    fn csrf_for(&self, headers: &axum::http::HeaderMap) -> String {
        let session = auth::session_cookie_value(headers).unwrap_or_default();
        auth::csrf_token(&self.csrf_key(), &session)
    }
}

/// Lifetime of the UI-preference cookies (`fumox_lang`, `fumox_theme`,
/// `fumox_dash_top_n`): one year. One constant for all three, so the
/// cookies cannot drift apart (they are the same kind of choice).
pub(crate) const PREF_COOKIE_MAX_AGE_SECS: u64 = 365 * 24 * 3600;

/// Value of the first cookie named `name` across the `Cookie` headers,
/// `None` when absent. The one cookie scanner of the panel: the language,
/// theme, Top-N and session readers parse only their own value on top of it.
pub(crate) fn cookie_value<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    for header_value in headers.get_all(header::COOKIE) {
        let Ok(text) = header_value.to_str() else {
            continue;
        };
        for pair in text.split(';') {
            if let Some((candidate, value)) = pair.trim().split_once('=')
                && candidate.trim() == name
            {
                return Some(value.trim());
            }
        }
    }
    None
}

/// `Set-Cookie` value persisting a UI preference: HttpOnly, SameSite=Lax,
/// one-year lifetime ([`PREF_COOKIE_MAX_AGE_SECS`]).
pub(crate) fn preference_cookie(name: &str, value: &str) -> String {
    format!("{name}={value}; Path=/; HttpOnly; SameSite=Lax; Max-Age={PREF_COOKIE_MAX_AGE_SECS}")
}

/// Validated `?next=` target shared by the preference setters (`set-lang`,
/// `set-theme`, `set-dash-top-n`): admin-surface paths only, no control
/// characters (a percent-decoded CR/LF such as `next=%2Fadmin%0D%0Ax` makes
/// the `Location` header invalid and axum answers 500). Anything invalid
/// falls back to `/admin`.
pub(crate) fn admin_next(params: &std::collections::HashMap<String, String>) -> String {
    admin_next_value(params.get("next").map(String::as_str))
}

/// The same validation for a `next` value that arrived outside a query
/// map (the login form's hidden field).
pub(crate) fn admin_next_value(next: Option<&str>) -> String {
    next.filter(|next| next.starts_with("/admin") && !next.chars().any(|c| c.is_ascii_control()))
        .unwrap_or("/admin")
        .to_string()
}

/// One trusted-proxy list entry: an explicit CIDR (`10.0.0.0/8`) or a
/// bare address (`192.168.1.1`, read as its `/32` / `/128` host prefix,
/// what the settings form hint advertises). `None` when unparsable;
/// callers refuse it (settings save) or log-and-drop it (startup load).
pub(crate) fn parse_trusted_cidr_entry(entry: &str) -> Option<ipnet::IpNet> {
    match entry.parse::<ipnet::IpNet>() {
        Ok(net) => Some(net),
        // `ipnet`'s `FromStr` demands an explicit `/prefix`, so a bare
        // address falls back to the host prefix; both rate limiters and
        // the settings editor parse through this one helper for one contract
        Err(_) => entry
            .parse::<std::net::IpAddr>()
            .ok()
            .map(ipnet::IpNet::from),
    }
}

/// Parse the operator-supplied trusted-proxy CIDR list. Bad entries are
/// logged and dropped: a typo'd CIDR must never silently widen the trust
/// boundary. Bare IPs are valid entries (see [`parse_trusted_cidr_entry`]);
/// without that fallback a hint-conforming entry was silently emptied at
/// every restart, degrading per-IP rate limiting to peer-IP keying and
/// switching the scheme detection off.
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
/// allowlist is a no-op (accept any host). This also removes the
/// inconsistent fail mode where a non-matching Host was served by every
/// page except the three that render serve links, which answered 500 from
/// `build_serve_link_host`: a host that reaches a handler is always
/// allowlisted.
///
/// A request through a proxy in the operator's trust list is also judged
/// by the host the proxy forwarded (`X-Forwarded-Host` or RFC 7239
/// `Forwarded: host=`), since such a proxy rewrites `Host` to its own
/// upstream name. The forwarded host is read only from a trusted peer and
/// only from the header family the operator declared ([`TrustedHeader`]):
/// a client talking to the panel directly can write those headers itself.
async fn enforce_allowed_hosts(
    State(state): State<AdminState>,
    req: Request,
    next: Next,
) -> Response {
    // The whole judgment happens under the allowlist guard, and the guard
    // is dropped before the `await` below: a std `RwLock` guard is not
    // `Send`, and holding it across the next middleware's future would
    // make this middleware's future non-`Send` too (axum refuses to
    // layer it). Only the outcome crosses the boundary
    let rejected: Option<host_gate::HostRejected> = {
        let allowed = state.host_allowlist();
        if allowed.is_empty() {
            None
        } else {
            let peer = req
                .extensions()
                .get::<axum::extract::ConnectInfo<SocketAddr>>()
                .map(|info| info.0);
            let trusted_peer = peer.is_some_and(|peer| {
                state
                    .trusted_cidrs
                    .iter()
                    .any(|net| net.contains(&peer.ip()))
            });
            let forwarded_ok = trusted_peer
                && host_gate::validate_forwarded_host(
                    req.headers(),
                    &allowed,
                    state.trusted_header,
                )
                .is_ok();
            match host_gate::validate_request_host(req.headers(), &allowed) {
                Ok(()) => None,
                Err(_) if forwarded_ok => None,
                Err(err) => Some(err),
            }
        }
    };
    if let Some(err) = rejected {
        tracing::warn!(error = %err, path = %req.uri().path(), "admin request host rejected");
        let lang = state.locales.lang_from_headers(req.headers());
        let host = req
            .headers()
            .get(header::HOST)
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default()
            .to_string();
        let setting = "[admin].allowed_hosts".to_string();
        return (
            StatusCode::BAD_REQUEST,
            [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
            format!(
                "{}\n",
                lang.t_named(
                    "err.host_not_allowed",
                    &[("host", host), ("setting", setting)]
                )
            ),
        )
            .into_response();
    }
    next.run(req).await
}

/// Park the toast of a plain-browser action in the session's slot. The
/// handler can only attach the message to its redirect as a response
/// header (a redirect carries no session state); this middleware moves it
/// into the session's store and strips the header, so the text never
/// reaches the browser or the URL.
async fn capture_flash(State(state): State<AdminState>, req: Request, next: Next) -> Response {
    let session = auth::session_cookie_value(req.headers()).unwrap_or_default();
    let mut response = next.run(req).await;
    let headers = response.headers_mut();
    let message = headers.remove(flash::FLASH_HEADER);
    let level = headers.remove(flash::FLASH_LEVEL_HEADER);
    if let Some(message) = message {
        let message = message.to_str().unwrap_or_default().to_string();
        let level = level
            .and_then(|value| value.to_str().ok().map(flash::FlashLevel::from_header))
            .unwrap_or(flash::FlashLevel::Ok);
        state.flashes.put(&session, message, level);
    }
    response
}

/// The pending toast of the session, handed out once. The plain-browser
/// path has no `HX-Trigger` header to carry the message across the
/// redirect, so the page asks for it here.
async fn take_flash(State(state): State<AdminState>, headers: HeaderMap) -> Response {
    let session = auth::session_cookie_value(&headers).unwrap_or_default();
    match state.flashes.take(&session) {
        Some((message, level)) => (
            StatusCode::OK,
            [(header::CONTENT_TYPE, "application/json; charset=utf-8")],
            // Built by serde_json, so the body is valid JSON whatever a
            // producer parked in the store. The message itself stays
            // percent-encoded (see `header_safe`): a response header is
            // Latin-1 on the wire and the client decodes it back
            serde_json::json!({ "message": message, "level": level.as_str() }).to_string(),
        )
            .into_response(),
        None => StatusCode::NO_CONTENT.into_response(),
    }
}

/// Sources and profiles CRUD (list, form, detail, per-entity actions),
/// merged into [`protected_router`].
fn source_profile_routes() -> axum::Router<AdminState> {
    use axum::routing::{get, post};

    axum::Router::new()
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
}

/// Proxy inventory (list, detail, bulk cleanup/revival), merged into
/// [`protected_router`].
fn proxy_routes() -> axum::Router<AdminState> {
    use axum::routing::{get, post};

    axum::Router::new()
        .route("/proxies", get(handlers::proxies_list))
        .route(
            "/proxies/purge-removed",
            post(handlers::proxies_purge_removed),
        )
        // Bulk cleanup transitions; literal action segments must be
        // registered before the `/{id}` routes
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
        .route(
            "/proxies/remove-detached",
            post(handlers::proxies_remove_detached),
        )
        // Bulk revival moves rows back to `unknown`; literal segments must
        // precede `/{id}` for the same reason
        .route(
            "/proxies/revive-removed-by-country",
            post(handlers::proxies_revive_removed_by_country),
        )
        .route(
            "/proxies/revive-removed-by-asn",
            post(handlers::proxies_revive_removed_by_asn),
        )
        .route(
            "/proxies/revive-removed-never-checked",
            post(handlers::proxies_revive_removed_never_checked),
        )
        .route(
            "/proxies/revive-quarantine",
            post(handlers::proxies_revive_quarantine),
        )
        .route("/proxies/{id}", get(handlers::proxy_detail))
        .route("/proxies/{id}/reset", post(handlers::proxy_reset))
        .route(
            "/proxies/{id}/measure-speed",
            post(handlers::proxy_measure_speed),
        )
        .route(
            "/proxies/{id}/probe-history",
            get(handlers::proxy_probe_history),
        )
}

/// Journals, probe overview, settings, pipeline builder, import/export,
/// SSE, the toast endpoint and the UI-preference setters, merged into
/// [`protected_router`].
fn admin_content_routes() -> axum::Router<AdminState> {
    use axum::routing::{get, post};

    axum::Router::new()
        .route("/logs/fetch", get(handlers::fetch_logs))
        .route("/probe", get(handlers::probe_overview))
        .route("/settings", get(handlers::settings_overview))
        .route("/settings/edit", get(handlers::settings_edit))
        .route("/settings/create", post(handlers::settings_create))
        .route("/settings/update", post(handlers::settings_update))
        // Pipeline builder: generation and validation inside the same
        // auth+CSRF envelope as every POST
        .route("/pipeline/preview", post(handlers::pipeline_preview))
        .route("/pipeline/mode", post(handlers::pipeline_mode))
        .route("/pipeline/preset", post(handlers::pipeline_preset))
        .route("/pipeline/rows", post(handlers::pipeline_rows))
        .route("/export", get(handlers::export_config))
        .route(
            "/import",
            get(handlers::import_form).post(handlers::import_submit),
        )
        // Token rotation gets its own confirmation page stating the
        // consequences before the capability is revoked
        .route(
            "/import/alive-token",
            get(handlers::rotate_alive_token_form).post(handlers::rotate_alive_token),
        )
        .route("/events", get(handlers::events_stream))
        .route("/flash", get(take_flash))
        // The UI-preference setters (language, theme, dashboard Top-N) are
        // state-changing POSTs under the same auth+CSRF envelope: a
        // cross-site page that could auto-issue the request would pin its
        // cookie choices over the operator's (the browser stores the
        // answer's `Set-Cookie` even for a mere navigation, which SameSite
        // cannot prevent). The forms in `base.html` and `dashboard.html`
        // ship the `_csrf` field. The login screen has no session yet and
        // chooses via `?lang=` / `?theme=` on the login form, which sets
        // the same cookies server-side (`auth::login_form`)
        .route("/set-lang", post(i18n::set_lang))
        .route("/set-theme", post(theme::set_theme))
        .route("/set-dash-top-n", post(dash_top_n::set_top_n))
        // Logout is a state-changing POST: the session it clears is the
        // panel's only authentication, and an attacker page that can
        // auto-submit a cross-site form to `/admin/logout` signs the
        // operator out at will. Mounted inside the nest so `require_auth`
        // and `csrf_protect` run; the `base.html` form ships `_csrf`
        .route("/logout", post(auth::logout))
}

/// The `/admin/*` surface behind auth: the merged route groups wrapped in
/// the CSRF and authentication layers.
fn protected_router(state: &AdminState) -> axum::Router<AdminState> {
    // Middleware execution is outside-in: `require_auth` (added last) runs
    // first, then CSRF, then the handler
    source_profile_routes()
        .merge(proxy_routes())
        .merge(admin_content_routes())
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            auth::csrf_protect,
        ))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            auth::require_auth,
        ))
}

/// Build the admin router. Mounted only when the panel is active
/// (enabled + non-empty token); otherwise the listener serves 404.
pub fn router(state: AdminState) -> axum::Router {
    use axum::routing::get;

    // axum's nesting matches `/admin` but not `/admin/`; the trailing-slash
    // variant is a plain redirect to the canonical entry point
    axum::Router::new()
        .nest("/admin", protected_router(&state))
        .route("/admin/", get(|| async { Redirect::to("/admin") }))
        .route(
            "/admin/login",
            get(auth::login_form).post(auth::login_submit),
        )
        .route("/admin/static/app.css", get(static_css))
        .route("/admin/static/app.js", get(static_app_js))
        .route("/admin/static/htmx.min.js", get(static_htmx))
        // Router-wide body cap: the CSRF layer already buffers POSTs at
        // 1 MiB; give every other extractor the same bound instead of
        // relying on that coincidence
        .layer(axum::extract::DefaultBodyLimit::max(auth::MAX_BODY_BYTES))
        .layer(axum::middleware::from_fn(security::headers))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            capture_flash,
        ))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            auth::rate_limit,
        ))
        // Added last = outermost: a request whose Host is not allowlisted
        // is rejected before it can burn a rate-limit window or reach any
        // handler (see `enforce_allowed_hosts`)
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            enforce_allowed_hosts,
        ))
        .with_state(state)
}

/// Render an askama template into an HTML response; template errors are a
/// server bug and become a logged 500. `name` (template path or rendering
/// route) is recorded in the error log so the bug names its page.
pub fn render_html(
    lang: Lang,
    name: &'static str,
    template: &impl Template,
    status: StatusCode,
) -> Response {
    html_response(lang, name, status, template.render())
}

/// Shape a rendered HTML body into a response; a rendering failure is a
/// server bug and becomes a logged 500 with the minimal error document.
/// Shared by [`render_html`] and the pipeline fragment endpoints so full
/// pages and `#ped-*` fragments cannot drift into different shapes or
/// error paths. `name` is recorded in the error log like
/// [`render_html`]'s.
pub fn html_response(
    lang: Lang,
    name: &str,
    status: StatusCode,
    rendered: Result<String, askama::Error>,
) -> Response {
    match rendered {
        Ok(html) => (
            status,
            [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
            html,
        )
            .into_response(),
        Err(err) => {
            tracing::error!(template = %name, error = %err, "template rendering failed");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
                // A bare fragment would leave the browser in quirks mode
                // with no language or title; the operator needs a way back
                format!(
                    "<!doctype html><html lang=\"{}\"><head><meta charset=\"utf-8\">\
                     <title>500</title></head><body><h1>500</h1><p>{}</p>\
                     <p><a href=\"/admin\">{}</a></p></body></html>",
                    lang.code(),
                    lang.t("err.render_failed"),
                    lang.t("err.render_hint"),
                ),
            )
                .into_response()
        }
    }
}

/// `Cache-Control` of the vendored static assets (`/admin/static/*`):
/// cacheable by the operator's browser, never by a shared intermediary.
/// Dynamic answers keep the middleware's blanket `no-store`
/// (`security::headers` skips a response that carries its own value).
const STATIC_CACHE_CONTROL: &str = "private, max-age=3600";

async fn static_css() -> impl IntoResponse {
    (
        [
            (header::CONTENT_TYPE, "text/css; charset=utf-8"),
            (header::CACHE_CONTROL, STATIC_CACHE_CONTROL),
        ],
        include_str!("../../static/app.css"),
    )
}

/// The panel's script, served as a file so the content-security policy
/// does not have to allow inline scripts.
async fn static_app_js() -> impl IntoResponse {
    (
        [
            (
                header::CONTENT_TYPE,
                "application/javascript; charset=utf-8",
            ),
            (header::CACHE_CONTROL, STATIC_CACHE_CONTROL),
        ],
        include_str!("../../static/app.js"),
    )
}

/// Vendored htmx (fixed version, no CDN, works offline).
async fn static_htmx() -> impl IntoResponse {
    (
        [
            (
                header::CONTENT_TYPE,
                "application/javascript; charset=utf-8",
            ),
            (header::CACHE_CONTROL, STATIC_CACHE_CONTROL),
        ],
        include_str!("../../static/htmx.min.js"),
    )
}

/// Build the base URL of the public subscription endpoints from the
/// request's authority: the host the admin panel was opened on (`Host`
/// header, behind a trusted proxy) and the port of that same authority.
/// The default port (80/443 matching the scheme) is omitted.
fn serve_base(
    bind: SocketAddr,
    peer: SocketAddr,
    headers: &HeaderMap,
    trusted_cidrs: &[ipnet::IpNet],
    trusted_header: TrustedHeader,
    allowed_hosts: &host_gate::HostAllowlist,
) -> Result<String, host_gate::HostRejected> {
    let scheme = if request_is_https(peer, headers, trusted_cidrs, trusted_header) {
        "https"
    } else {
        "http"
    };
    let link = host_gate::build_serve_link_host(bind, headers, allowed_hosts)?;
    if !link.from_header {
        // The link names the bind address because the request carried no
        // usable `Host` header (a stripping proxy, an HTTP/1.0 client);
        // the link may still work, the operator just cannot tell where
        tracing::warn!("serve-link built from bind fallback, Host header unusable");
    }
    // Scheme and port must describe one authority. Behind a trusted proxy
    // the `Host` header is that authority: its port when spelled, the
    // scheme's default otherwise (a `https` link to a portless Host must
    // not grow the panel's `[server].bind` port). Without a trusted proxy
    // or a usable `Host` header the public listener is the panel, so the
    // `[server].bind` port is used
    let trusted = trusted_cidrs.iter().any(|net| net.contains(&peer.ip()));
    let port = if trusted && link.from_header {
        link.port
    } else {
        Some(bind.port())
    };
    let default_port =
        |port: u16| (scheme == "http" && port == 80) || (scheme == "https" && port == 443);
    Ok(match port {
        Some(port) if !default_port(port) => format!("{scheme}://{}:{}", link.host, port),
        _ => format!("{scheme}://{}", link.host),
    })
}

/// True when the admin request arrived over https through a TLS-terminating
/// reverse proxy (`X-Forwarded-Proto: https` or RFC 7239
/// `Forwarded: proto=https`). Fumox never terminates TLS itself, so
/// without such a header the scheme is http.
///
/// The header is honored only when the peer IP falls inside a configured
/// `trusted_cidrs` entry (mirroring `crate::security::client_key` so the
/// scheme decision and the rate-limit key agree on what "peer" means) and
/// only from the header the operator declared ([`TrustedHeader`]): a
/// scheme hint from an undeclared header is text the client chose. Empty
/// `trusted_cidrs` never honors forwarded headers.
fn request_is_https(
    peer: SocketAddr,
    headers: &HeaderMap,
    trusted_cidrs: &[ipnet::IpNet],
    trusted_header: TrustedHeader,
) -> bool {
    if trusted_cidrs.is_empty() {
        return false;
    }
    if !trusted_cidrs.iter().any(|net| net.contains(&peer.ip())) {
        return false;
    }
    if trusted_header == TrustedHeader::None {
        return false;
    }
    (trusted_header.honors_xff()
        && headers
            .get("x-forwarded-proto")
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| v.split(',').any(|p| p.trim().eq_ignore_ascii_case("https"))))
        || (trusted_header.honors_forwarded()
            && headers
                .get(header::FORWARDED)
                .and_then(|v| v.to_str().ok())
                .is_some_and(|v| {
                    v.to_ascii_lowercase()
                        .split([',', ';'])
                        .any(|p| p.trim().trim_start_matches("proto=") == "https")
                }))
}

/// Admin state on a throwaway migrated database for the admin test
/// modules; they share the wiring and differ only in the config served.
/// The temp directory is removed when the returned guard drops, so keep
/// it in scope (`let (_dir, state) = test_admin_state(...).await`).
#[cfg(test)]
pub(crate) async fn test_admin_state(
    admin: AdminConfig,
    server: ServerConfig,
) -> (fumox_core::tempdir_lite::TempDir, AdminState) {
    test_admin_state_with_geo(admin, server, None).await
}

/// [`test_admin_state`] with the card resolver pointed at a specific
/// GeoLite2 directory (`None` keeps the built-in default): the geo-card
/// fixtures read the workspace `.mmdb` files the default path misses.
#[cfg(test)]
pub(crate) async fn test_admin_state_with_geo(
    admin: AdminConfig,
    server: ServerConfig,
    geo_db_dir: Option<std::path::PathBuf>,
) -> (fumox_core::tempdir_lite::TempDir, AdminState) {
    let mut geo = GeoConfig {
        enabled: false,
        ..Default::default()
    };
    if let Some(db_dir) = geo_db_dir {
        geo.db_dir = db_dir;
    }
    admin_state_on_tmp_db(fumox_core::AppConfig {
        admin,
        server,
        geo,
        ..Default::default()
    })
    .await
}

/// [`test_admin_state`] wiring on a caller-supplied config, for fixtures
/// that need a non-default knob. Keep the returned guard in scope while
/// the pool is in use.
#[cfg(test)]
pub(crate) async fn admin_state_on_tmp_db(
    config: fumox_core::AppConfig,
) -> (fumox_core::tempdir_lite::TempDir, AdminState) {
    let dir = fumox_core::tempdir_lite::TempDir::new("admin");
    let pool = fumox_core::db::connect_pool(&DatabaseConfig {
        path: dir.path().join("test.db"),
        ..Default::default()
    })
    .await
    .unwrap();
    fumox_core::db::migrate(&pool).await.unwrap();
    let (refresh_tx, refresh_rx) =
        tokio::sync::mpsc::channel(crate::scheduler::REFRESH_CHANNEL_CAP);
    std::mem::forget(refresh_rx); // keep the channel open for sends
    let fetcher = Fetcher::new(
        config.fetch.clone(),
        config.admin.allow_private_urls,
        config.ssrf_dns_timeout(),
    );
    (
        dir,
        AdminState::new(
            pool,
            crate::cache::Caches::new(),
            std::sync::Arc::new(GeoResolver::new(&config.geo)),
            refresh_tx,
            SchedulerState::new(1),
            EventBus::new(),
            fetcher,
            config,
            ResolvedConfigPath::Missing,
            crate::alive_export::TokenCache::new(),
        ),
    )
}

/// A string the way askama's HTML escaper renders it (the escaper every
/// template interpolation applies): rendered-text assertions compare
/// against this form, not the raw form the page must never print.
#[cfg(test)]
pub(crate) fn askama_html_escape(text: &str) -> String {
    askama::filters::escape(text, askama::filters::Html)
        .expect("askama's escape filter is infallible")
        .to_string()
}

/// Build a request with the `ConnectInfo` extension the rate limiter
/// extracts; a real listener attaches it via
/// `into_make_service_with_connect_info`.
#[cfg(test)]
pub(crate) fn request(method: &str, uri: &str, body: &str, cookie: Option<&str>) -> Request {
    let mut builder = Request::builder()
        .method(method)
        .uri(uri)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .extension(axum::extract::ConnectInfo::<SocketAddr>(
            "127.0.0.1:41000".parse().unwrap(),
        ));
    if let Some(cookie) = cookie {
        builder = builder.header(header::COOKIE, cookie);
    }
    builder
        .body(axum::body::Body::from(body.to_string()))
        .unwrap()
}

/// The `name=value` pair of a `Set-Cookie` header: everything up to the
/// first attribute separator.
#[cfg(test)]
pub(crate) fn cookie_from(response: &axum::response::Response) -> String {
    response
        .headers()
        .get(header::SET_COOKIE)
        .expect("the response must set a cookie")
        .to_str()
        .expect("the cookie is header-safe")
        .split(';')
        .next()
        .unwrap()
        .to_string()
}

#[cfg(test)]
#[path = "admin_tests.rs"]
mod tests;

#[cfg(test)]
mod template_contracts;
