//! fumox-server, public subscription endpoints and the admin panel.
//!
//! Loads configuration, opens the database, runs the background source
//! refresh scheduler, serves `/sub` and `/src` on the public listener and
//! the SSR admin panel on a separate loopback listener,
//! and shuts down gracefully on SIGINT/SIGTERM.

mod admin;
mod alive_export;
mod cache;
mod events;
mod fetcher;
mod geo_backfill;
mod geo_download;
mod host_gate;
mod ingest;
mod pipeline;
mod redact;
mod scheduler;
mod security;
mod serve;

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use clap::Parser;

use crate::cache::Caches;
use crate::fetcher::Fetcher;
use crate::scheduler::SchedulerState;

/// How long the listeners may take to drain after a shutdown signal.
///
/// The graceful shutdown waits for the open connections, and some of them
/// never end on their own: the admin panel holds an SSE stream, and a
/// client may be downloading a large export. Without a deadline the
/// process waits forever and the orchestrator kills it, which skips the
/// drain and the shutdown log below.
const SHUTDOWN_DRAIN_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Parser)]
#[command(name = "fumox-server", version, about = "Fumox subscription server")]
struct Cli {
    /// Path to the TOML config file (outranks FUMOX_CONFIG; the default
    /// location is config/app.toml if present).
    #[arg(short, long)]
    config: Option<PathBuf>,

    /// Probe the running server's /healthz and exit 0 when it answers 200,
    /// 1 otherwise. Used as the container healthcheck: the runtime image
    /// ships no curl or wget, and the binary already has an HTTP client.
    #[arg(long)]
    health_check: bool,

    /// Print the resolved configuration as TOML and exit. The values are
    /// the effective ones: the file merged under the environment, which
    /// wins. The admin token is redacted.
    #[arg(long)]
    print_config: bool,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Before anything builds an HTTP client: reqwest is compiled without a
    // crypto provider, so one has to be installed first.
    fumox_core::tls::install_crypto_provider();

    let cli = Cli::parse();
    let loaded = fumox_core::config::load(cli.config.as_deref())?;
    let config = loaded.config;

    if cli.print_config {
        print!("{}", fumox_core::config::dump(&config)?);
        return Ok(());
    }

    // Before tracing, the pool and the migrations: a probe must not make
    // any of that side effect happen just to be measured. It reports the
    // server's readiness, and migrations complete before the listeners
    // bind, so a 200 here means the schema is current.
    if cli.health_check {
        return match probe_healthz(config.server.bind).await {
            Ok(()) => Ok(()),
            Err(error) => {
                eprintln!("/healthz did not answer 200: {error}");
                std::process::exit(1);
            }
        };
    }

    fumox_core::logging::init_tracing(config.log.server);

    // Security audit (2026-08-30): the panel is only reachable with a
    // token the operator set. An empty token and the historical
    // "change-me" placeholder both mean "panel off" (see
    // `AdminConfig::is_active`), so the listener is never started for
    // them; say which mode this is, since "the admin URL answers 404" is
    // otherwise indistinguishable from a routing mistake.
    if config.admin.enabled && !config.admin.is_active() {
        tracing::warn!(
            bind = %config.admin.bind,
            "admin panel is disabled: set admin.token (or FUMOX_ADMIN__TOKEN) to enable it"
        );
    }
    // A panel that listens on a public address and sends its session
    // cookie without `Secure` hands the token to everyone on the path.
    if config.admin.insecure_cookies_on_a_public_bind() {
        tracing::warn!(
            bind = %config.admin.bind,
            "admin session cookie is not marked Secure while the panel listens on a public \
             address: the session token travels in clear text; set admin.secure_cookies = true \
             behind an HTTPS front, or bind the panel to a loopback address"
        );
    }

    for warning in startup_warnings(&config) {
        tracing::warn!("{warning}");
    }

    // The loader cannot log (its own level comes from the config); report
    // the file actually used once tracing is up.
    match &loaded.path {
        fumox_core::config::ResolvedConfigPath::Loaded(file) => {
            tracing::info!(config = %file.display(), "config file loaded");
        }
        fumox_core::config::ResolvedConfigPath::Missing => {
            tracing::info!(
                "no config file found (looked at {} or {}); using built-in defaults",
                fumox_core::config::CONFIG_PATH_ENV,
                fumox_core::DEFAULT_CONFIG_PATH
            );
        }
    }

    // A save that died between creating its temporary file and renaming
    // it leaves a copy of the config behind, and the config carries
    // `[admin].token`. The leftovers of writers that are gone are
    // removed here, on the only start that can produce them.
    let config_dir = match &loaded.path {
        fumox_core::config::ResolvedConfigPath::Loaded(file) => {
            file.parent().map(Path::to_path_buf)
        }
        fumox_core::config::ResolvedConfigPath::Missing => {
            Path::new(fumox_core::DEFAULT_CONFIG_PATH)
                .parent()
                .map(Path::to_path_buf)
        }
    };
    if let Some(dir) = config_dir {
        fumox_core::config_writer::cleanup_stale_tmp_files(&dir);
    }

    // figment layers `FUMOX_*` variables over the file (config.rs, `Env::
    // prefixed("FUMOX_")`); count them so a surprise override is at least
    // attributable; names and values stay out of the log. The resolved
    // database path is otherwise only visible on /admin/settings.
    let env_overrides = std::env::vars()
        .filter(|(key, _)| key.starts_with("FUMOX_"))
        .count();
    tracing::info!(
        path = %config.database.path.display(),
        env_overrides,
        "database configured"
    );

    let pool = fumox_core::db::connect_pool(&config.database).await?;
    fumox_core::db::migrate_with(
        &pool,
        fumox_core::db::ChecksumRepair::from_config(config.database.allow_checksum_repair),
    )
    .await?;
    // The public «all alive» export link: the capability token is
    // generated on first startup; it persists in `meta`, so the link is
    // stable across restarts until rotated from the admin panel. The
    // token itself is kept in process memory as well, so the public
    // endpoint does not read the database on every request; the panel and
    // the listener share the instance, so a rotation reaches both.
    let export_token = alive_export::TokenCache::new();
    export_token.current(&pool).await?;

    // Profile access tokens are stored as hashes. A row written before
    // that still holds the token in plain text, so it is rewritten in
    // place on the first start after the upgrade.
    let hashed = fumox_core::repo::profiles::hash_legacy_tokens(&pool).await?;
    if hashed > 0 {
        tracing::info!(count = hashed, "profile access tokens hashed");
    }

    // The fingerprint version is part of the pre-image, so a change of the
    // canonical form changes every key: the rows written before the change
    // keep keys the ingest no longer produces. They are recomputed once,
    // on the first start after the upgrade, before the first ingest — the
    // rows that describe the same node twice are merged into one.
    match fumox_core::repo::proxies::ensure_fingerprint_version(&pool).await? {
        Some(stats) => {
            tracing::info!(
                version = fumox_core::fingerprint::FINGERPRINT_VERSION,
                rewritten = stats.rewritten,
                merged = stats.merged,
                "stored fingerprints recomputed"
            );
        }
        None => {
            tracing::info!(
                version = fumox_core::fingerprint::FINGERPRINT_VERSION,
                "stored fingerprints are current"
            );
        }
    }

    // Best-effort GeoLite2 database download into [geo].db_dir: fetch what
    // is missing, broken or older than a month.
    //
    // The download runs in its own task and the listeners are bound
    // without waiting for it: a mirror must not keep the public surface
    // dark. The resolver asks the process-wide registry for the databases
    // on every lookup, so a file that lands later is picked up without a
    // restart. The budget is how long startup waits for the file
    // afterwards, not how long the download may run.
    let geo_config = config.clone();
    let geo_download =
        tokio::spawn(async move { geo_download::ensure_geo_databases(&geo_config).await });
    if config.geo.startup_download_budget_secs
        > fumox_core::config::MAX_STARTUP_DOWNLOAD_BUDGET_SECS
    {
        tracing::warn!(
            configured = config.geo.startup_download_budget_secs,
            capped = fumox_core::config::MAX_STARTUP_DOWNLOAD_BUDGET_SECS,
            "[geo].startup_download_budget_secs is above the cap; the effective budget is the cap"
        );
    }

    // Background source refresh loop: fetch → parse → reconcile → journal.
    let fetcher = Fetcher::new(
        config.fetch.clone(),
        config.admin.allow_private_urls,
        config.ssrf_dns_timeout(),
    );
    let scheduler_state = SchedulerState::new(config.fetch.max_concurrency);
    let caches = Caches::new();
    let geo = Arc::new(fumox_core::geo::GeoResolver::new(&config.geo));
    // Push updates to the admin panel over SSE; the
    // scheduler publishes fetch lifecycle events onto this bus.
    let events = events::EventBus::new();
    // The admin panel sends source ids over this channel for an immediate
    // refresh; the sender lives in the serving state, the receiver drives
    // the scheduler loop.
    let (refresh_tx, refresh_rx) = tokio::sync::mpsc::unbounded_channel::<String>();
    let scheduler_task = tokio::spawn(scheduler::run(
        scheduler::IngestEnv {
            pool: pool.clone(),
            fetcher: fetcher.clone(),
            caches: caches.clone(),
            geo: geo.clone(),
            settings: ingest::IngestSettings {
                refresh_check_limit: config.ingest.refresh_check_limit,
                drop_gate: config.ingest.drop_gate,
                removed_as_unknown: config.ingest.removed_as_unknown,
            },
            budget: scheduler::ingest_budget(&config.fetch),
        },
        scheduler_state.clone(),
        events.clone(),
        refresh_rx,
        // The retention windows come from the config this process booted
        // with: the entry point is the only place that knows which file
        // that was.
        scheduler::ServerRetention::from_config(&config),
    ));

    // Public listener: /sub/{id}, /src/{id} and /export/alive/{token}.
    //
    // `/healthz` gets a pool of its own, one connection, so its answer does
    // not queue behind renders. An orchestrator reads 503 as "restart me",
    // and a busy render pool is this process's own load, not a fault.
    let mut health_cfg = config.database.clone();
    health_cfg.max_connections = 1;
    let health_pool = fumox_core::db::connect_pool(&health_cfg).await?;

    let state = serve::AppState::new(
        pool.clone(),
        caches.clone(),
        geo.clone(),
        serve::PublicRateLimits::from_config(&config.server),
        admin::parse_trusted_cidrs(&config.server.trust_proxy_ips),
        config.server.trust_proxy_header,
        config.server.allowed_hosts.clone(),
        config.server.export_max_rows,
        export_token.clone(),
    );
    let app = serve::public_app(state, health_pool.clone());

    // Admin listener: a separate loopback interface. With
    // an empty token or enabled=false the panel is inert, the listener
    // still binds and answers 404 to everything.
    let admin_router = if config.admin.is_active() {
        let admin_state = admin::AdminState::new(
            pool.clone(),
            caches.clone(),
            geo.clone(),
            refresh_tx.clone(),
            scheduler_state.clone(),
            events.clone(),
            fetcher.clone(),
            config.clone(),
            loaded.path.clone(),
            export_token.clone(),
        );
        tracing::info!(bind = %config.admin.bind, "admin panel listening");
        admin::router(admin_state)
    } else {
        tracing::info!("admin panel disabled (empty token or enabled=false)");
        axum::Router::new()
    };

    let listener = tokio::net::TcpListener::bind(config.server.bind).await?;
    let admin_listener = tokio::net::TcpListener::bind(config.admin.bind).await?;
    tracing::info!(bind = %config.server.bind, "fumox-server listening");

    // The listeners are bound; the download still runs. Give it its
    // budget, then look at the geo state: a profile that filters by
    // country cannot serve anything without the country facts, and a
    // GeoIP failure must not stay silent.
    await_geo_within_budget(geo_download, config.geo.startup_download_budget()).await;
    if config.geo.enabled && profiles_require_country(&pool).await? && !geo.state().has_country() {
        anyhow::bail!(
            "a profile filters by country, but no GeoLite2 City database is available \
             (geo state: {}, directory: {}); put the database into the directory, \
             point [geo].db_dir at it, or drop the country allowlist",
            geo.state().as_str(),
            config.geo.db_dir.display(),
        );
    }
    // Fill the geo columns of proxies ingested before a database existed
    // (background: never blocks startup), bounded like the geo download
    // above by the configured startup budget. It runs after the download
    // had its budget, so it sees the database that just landed.
    tokio::spawn(geo_backfill::backfill_missing_geo_within_budget(
        pool.clone(),
        geo.clone(),
        config.geo.startup_download_budget(),
    ));

    // The public rate limiter also keys requests by peer address.
    //
    // The graceful shutdown waits for the open connections to finish, and
    // the admin panel holds an SSE stream that never ends on its own. The
    // wait therefore has a deadline — and the deadline starts when the
    // signal arrives, not when the listeners start.
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let mut public_server = axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(wait_for_shutdown(shutdown_rx.clone()))
    .into_future();
    let mut admin_server = axum::serve(
        admin_listener,
        admin_router.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(wait_for_shutdown(shutdown_rx.clone()))
    .into_future();

    // Drain the background scheduler even when a listener failed: the
    // `?` used to return here first, so a bind error skipped the drain and
    // the process exited with the scheduler's in-flight fetches unnamed.
    let serving = tokio::select! {
        // A listener that fails ends the wait right away.
        result = async {
            tokio::try_join!(&mut public_server, &mut admin_server).map(|_| ())
        } => result,
        () = shutdown_signal() => {
            // The listeners stop accepting and drain what they have.
            // The drain is bounded: an SSE stream or a slow download
            // never ends on its own, and an orchestrator kills the
            // process at its own grace period anyway — with the drain
            // below skipped, since it sits behind the wait.
            let _ = shutdown_tx.send(true);
            drain_listeners(SHUTDOWN_DRAIN_TIMEOUT, async {
                tokio::try_join!(&mut public_server, &mut admin_server).map(|_| ())
            })
            .await
        }
    };
    // The listeners are done: their sockets close here rather than at the
    // end of the process, so nothing new arrives during the scheduler
    // drain below.
    drop(public_server);
    drop(admin_server);

    // Dropping `refresh_tx` (the admin router's clone went with its
    // server) closes the channel, and the loop treats that as its
    // shutdown signal. The await is bounded so a wedged loop cannot hold
    // the process past its shutdown.
    drop(refresh_tx);
    match tokio::time::timeout(Duration::from_secs(5), scheduler_task).await {
        Ok(Ok(())) => {}
        Ok(Err(err)) => tracing::warn!(error = %err, "scheduler task ended with a join error"),
        Err(_) => tracing::warn!("scheduler task did not stop within 5 s; abandoning it"),
    }
    // In-flight fetches are detached tasks and cannot be awaited here;
    // name what is being abandoned so a gap in an upstream's log or in
    // `fetch_log` has an explanation in this one.
    let abandoned = scheduler_state.in_flight_ids().await;
    if !abandoned.is_empty() {
        tracing::warn!(
            count = abandoned.len(),
            sources = ?abandoned,
            "shutdown: fetches in flight are abandoned mid-request"
        );
    }

    tracing::info!("shutdown complete");
    serving?;
    Ok(())
}

/// GET the local public listener's `/healthz` and accept only 200. The
/// probe carries no token, which is the point: the endpoint is the one
/// unauthenticated route on the public listener.
async fn probe_healthz(bind: SocketAddr) -> anyhow::Result<()> {
    let url = health_probe_url(bind);
    // reqwest is compiled without a crypto provider and panics when a
    // client is built before one is installed.
    fumox_core::tls::install_crypto_provider();
    reqwest::Client::builder()
        .timeout(Duration::from_secs(3))
        .build()?
        .get(&url)
        .send()
        .await?
        .error_for_status()?;
    Ok(())
}

/// The address the health probe must use for a listener bound to `bind`.
///
/// A bind that names an address is the one the operator chose, and it is
/// reachable from the machine itself, so the probe uses exactly that
/// address. A wildcard is not a usable destination, so the loopback
/// stands in for it — the IPv6 loopback for an IPv6 wildcard, the IPv4
/// one for an IPv4 wildcard, because the two wildcards are different
/// sockets.
fn health_probe_addr(bind: SocketAddr) -> SocketAddr {
    let ip = match bind.ip() {
        IpAddr::V4(v4) if v4.is_unspecified() => IpAddr::V4(Ipv4Addr::LOCALHOST),
        IpAddr::V6(v6) if v6.is_unspecified() => IpAddr::V6(Ipv6Addr::LOCALHOST),
        ip => ip,
    };
    SocketAddr::new(ip, bind.port())
}

/// The URL of the local public listener's `/healthz`, derived from the
/// bind address. The address is rendered by `SocketAddr`, so an IPv6
/// address keeps its square brackets.
fn health_probe_url(bind: SocketAddr) -> String {
    format!("http://{}/healthz", health_probe_addr(bind))
}

/// Wait for the listeners to drain, but no longer than `deadline`.
///
/// A graceful shutdown waits for the open connections, and some of them
/// never end on their own: the admin panel holds an SSE stream, and a
/// client may be downloading a large export. The wait is therefore
/// bounded; a drain that runs over its deadline is abandoned with a
/// warning, and the connections are dropped with the listeners.
async fn drain_listeners<F>(deadline: Duration, drain: F) -> std::io::Result<()>
where
    F: std::future::Future<Output = std::io::Result<()>>,
{
    match tokio::time::timeout(deadline, drain).await {
        Ok(result) => result,
        Err(_) => {
            tracing::warn!(
                deadline_secs = deadline.as_secs(),
                "listeners did not finish draining within the deadline; \
                 the open connections are dropped"
            );
            Ok(())
        }
    }
}

/// Resolve when the shared shutdown flag flips to true.
///
/// The flag is a watch channel rather than a signal handler of its own:
/// both listeners wait on it, and the flag keeps its value, so a
/// listener that starts polling late still sees the shutdown.
async fn wait_for_shutdown(mut rx: tokio::sync::watch::Receiver<bool>) {
    if *rx.borrow_and_update() {
        return;
    }
    while rx.changed().await.is_ok() {
        if *rx.borrow_and_update() {
            return;
        }
    }
}

/// Wait for the GeoLite2 download task, but no longer than `budget`. On
/// elapse the handle drops, which detaches the task rather than aborting it;
/// the install is an atomic rename, so a late finish never exposes a partial
/// file.
async fn await_geo_within_budget(task: tokio::task::JoinHandle<()>, budget: Duration) {
    match tokio::time::timeout(budget, task).await {
        Ok(Ok(())) => {}
        Ok(Err(err)) => {
            tracing::warn!(error = %err, "GeoLite2 download task failed")
        }
        Err(_) if budget.is_zero() => {}
        Err(_) => tracing::warn!(
            budget_secs = budget.as_secs(),
            "GeoLite2 download still running at the startup budget; \
             the listeners are already bound and the download continues in \
             the background"
        ),
    }
}

/// Whether an enabled profile filters by country.
///
/// A country allowlist matches confirmed facts only: a proxy without a
/// determined country stays out. Without the City database the
/// subscription is empty, whatever the feed holds, so such a profile needs
/// the databases to be there.
async fn profiles_require_country(pool: &fumox_core::db::DbPool) -> anyhow::Result<bool> {
    let profiles = fumox_core::repo::profiles::list(pool, true).await?;
    Ok(profiles.iter().any(|profile| !profile.countries.is_empty()))
}

/// The configuration mistakes that change what the server accepts but
/// are invisible until a request is refused. Each one is worth a line
/// at startup: the operator reads the log once, the requests keep working.
///
/// - A non-empty `allowed_hosts` list turns the Host header into a gate:
///   a request with any other Host is refused (400 on the admin panel,
///   404 on the public listener).
/// - `trust_proxy_ips` without `trust_proxy_header` trusts the proxy's
///   *address* but reads none of its headers: the per-IP rate-limit key
///   is the proxy's own address, so every client behind one proxy shares
///   a single window.
fn startup_warnings(config: &fumox_core::AppConfig) -> Vec<String> {
    let mut warnings = Vec::new();
    if !config.admin.allowed_hosts.is_empty() {
        warnings.push(format!(
            "the admin panel now accepts only these Host values: {}",
            config.admin.allowed_hosts.join(", ")
        ));
    }
    if !config.server.allowed_hosts.is_empty() {
        warnings.push(format!(
            "the public listener now accepts only these Host values: {}",
            config.server.allowed_hosts.join(", ")
        ));
    }
    for (section, cidrs, header) in [
        (
            "server",
            &config.server.trust_proxy_ips,
            config.server.trust_proxy_header,
        ),
        (
            "admin",
            &config.admin.trust_proxy_ips,
            config.admin.trust_proxy_header,
        ),
    ] {
        if !cidrs.is_empty() && header == fumox_core::config::TrustedHeader::None {
            warnings.push(format!(
                "[{section}].trust_proxy_ips is set but [{section}].trust_proxy_header is \
                 \"none\": no forwarding header is read, so every client behind the proxy shares \
                 the proxy's own rate-limit window; set [{section}].trust_proxy_header to the \
                 header the proxy writes"
            ));
        }
    }
    warnings
}

/// Resolves when the process receives SIGINT (Ctrl-C) or SIGTERM.
async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to install Ctrl-C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to install SIGTERM handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        () = ctrl_c => {},
        () = terminate => {},
    }
    tracing::info!("shutdown signal received, draining connections");
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A stalled GeoLite2 download must not keep the listeners from
    /// binding: the wait gives up at the budget and leaves the task
    /// running. Before the budget was bounded, two slow mirrors held
    /// `/healthz` unreachable for the sum of their per-file budgets.
    #[tokio::test]
    async fn a_stalled_geo_download_does_not_hold_startup() {
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(async move {
            let _ = started_tx.send(());
            // Far longer than the budget below.
            tokio::time::sleep(Duration::from_secs(3_600)).await;
        });
        started_rx.await.unwrap();

        let budget = Duration::from_millis(100);
        let began = std::time::Instant::now();
        await_geo_within_budget(task, budget).await;
        let elapsed = began.elapsed();

        assert!(
            elapsed < Duration::from_secs(1),
            "waited {elapsed:?}, expected to give up at {budget:?}"
        );
    }

    /// The normal path: a download that finishes inside the budget is
    /// awaited to completion, so a working mirror still gets its files in
    /// before the resolver opens them.
    #[tokio::test]
    async fn a_finished_geo_download_is_awaited() {
        let (done_tx, done_rx) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(20)).await;
            let _ = done_tx.send(());
        });
        await_geo_within_budget(task, Duration::from_secs(5)).await;
        // The task ran to its end rather than being abandoned.
        done_rx.await.unwrap();
    }

    /// A profile that filters by country needs the country facts: without
    /// them the subscription is empty, so the startup refuses to run. A
    /// profile without an allowlist does not need them.
    #[tokio::test]
    async fn a_country_allowlist_makes_the_profiles_require_geo() {
        let dir = std::env::temp_dir().join(format!(
            "fumox-profiles-require-geo-{}",
            fumox_core::models::new_id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let pool = fumox_core::db::connect_pool(&fumox_core::config::DatabaseConfig {
            path: dir.join("test.db"),
            ..Default::default()
        })
        .await
        .unwrap();
        fumox_core::db::migrate(&pool).await.unwrap();

        assert!(
            !profiles_require_country(&pool).await.unwrap(),
            "an installation without profiles needs no geo"
        );

        let now = fumox_core::models::now_ts();
        let mut profile = fumox_core::models::Profile {
            id: "prof00000001".into(),
            slug: None,
            access_token: None,
            name: "p".into(),
            output_format: Default::default(),
            pipeline: None,
            countries: Vec::new(),
            include_unknown_country: false,
            enabled: true,
            created_at: now,
            updated_at: now,
        };
        fumox_core::repo::profiles::create(&pool, &profile)
            .await
            .unwrap();
        assert!(
            !profiles_require_country(&pool).await.unwrap(),
            "a profile without an allowlist needs no geo"
        );

        profile.countries = vec!["US".into()];
        fumox_core::repo::profiles::update(&pool, &profile)
            .await
            .unwrap();
        assert!(
            profiles_require_country(&pool).await.unwrap(),
            "a country allowlist needs the country facts"
        );

        // A disabled profile is not served, so it does not hold the
        // startup hostage.
        profile.enabled = false;
        fumox_core::repo::profiles::update(&pool, &profile)
            .await
            .unwrap();
        assert!(
            !profiles_require_country(&pool).await.unwrap(),
            "a disabled profile is not served"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    /// The drain after a shutdown signal must have a deadline: an SSE
    /// stream never ends on its own, and a wait without a bound keeps
    /// the process alive until the orchestrator kills it — which skips
    /// the drain and the shutdown log that sit behind the wait.
    #[tokio::test(start_paused = true)]
    async fn a_stuck_drain_is_abandoned_at_the_deadline() {
        let began = tokio::time::Instant::now();
        let result = drain_listeners(
            Duration::from_secs(10),
            std::future::pending::<std::io::Result<()>>(),
        )
        .await;
        assert!(result.is_ok(), "an abandoned drain is not a failure");
        assert_eq!(began.elapsed(), Duration::from_secs(10));
    }

    /// The health probe must reach the listener the operator configured.
    /// A bind that names an address is probed at exactly that address; a
    /// wildcard is not a destination, so the loopback stands in for it —
    /// the IPv6 loopback for an IPv6 wildcard, the IPv4 one for an IPv4
    /// wildcard.
    #[test]
    fn the_health_probe_follows_the_bind_address() {
        let cases = [
            (
                SocketAddr::from(([0, 0, 0, 0], 8080)),
                SocketAddr::from(([127, 0, 0, 1], 8080)),
            ),
            (
                SocketAddr::from(([10, 1, 2, 3], 9000)),
                SocketAddr::from(([10, 1, 2, 3], 9000)),
            ),
            (
                SocketAddr::from(([0, 0, 0, 0, 0, 0, 0, 0], 8080)),
                SocketAddr::from(([0, 0, 0, 0, 0, 0, 0, 1], 8080)),
            ),
            (
                SocketAddr::from(([0xfd00, 0, 0, 0, 0, 0, 0, 1], 8080)),
                SocketAddr::from(([0xfd00, 0, 0, 0, 0, 0, 0, 1], 8080)),
            ),
        ];
        for (bind, expected) in cases {
            assert_eq!(health_probe_addr(bind), expected, "bind {bind}");
        }

        // An IPv6 address keeps its square brackets in the URL.
        let v6 = SocketAddr::from(([0, 0, 0, 0, 0, 0, 0, 0], 8080));
        assert_eq!(health_probe_url(v6), "http://[::1]:8080/healthz");
        let v4 = SocketAddr::from(([127, 0, 0, 1], 8080));
        assert_eq!(health_probe_url(v4), "http://127.0.0.1:8080/healthz");
    }

    /// The probe accepts only 200: a listener that answers something else
    /// is not ready, and the healthcheck must fail rather than pass on a
    /// redirect or an error page.
    #[tokio::test]
    async fn the_health_probe_accepts_only_200() {
        let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let addr = listener.local_addr().unwrap();
        let app = axum::Router::new().route("/healthz", axum::routing::get(|| async { "ok" }));
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        probe_healthz(addr)
            .await
            .expect("a 200 is a healthy answer");
        server.abort();
    }

    /// A listener that answers 404 is not healthy: the probe must fail
    /// instead of accepting the answer.
    #[tokio::test]
    async fn the_health_probe_rejects_a_non_200() {
        let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let addr = listener.local_addr().unwrap();
        let app = axum::Router::new().route("/other", axum::routing::get(|| async { "ok" }));
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        assert!(
            probe_healthz(addr).await.is_err(),
            "a 404 must fail the healthcheck"
        );
        server.abort();
    }

    /// A non-empty allowlist is a gate the operator cannot see from the
    /// outside: until a request is refused, the panel looks the same as
    /// without one. The startup names the accepted hosts.
    #[test]
    fn an_allowlist_is_named_at_startup() {
        let mut config = fumox_core::AppConfig::default();
        assert!(
            startup_warnings(&config).is_empty(),
            "the defaults gate nothing"
        );

        config.admin.allowed_hosts = vec!["panel.example.com".into()];
        let warnings = startup_warnings(&config);
        assert_eq!(warnings.len(), 1, "{warnings:?}");
        assert!(warnings[0].contains("panel.example.com"), "{warnings:?}");
        assert!(warnings[0].contains("admin panel"), "{warnings:?}");

        config.server.allowed_hosts = vec!["public.example.com".into()];
        let warnings = startup_warnings(&config);
        assert_eq!(warnings.len(), 2, "{warnings:?}");
        assert!(warnings[1].contains("public.example.com"), "{warnings:?}");
    }

    /// Trusted proxies without a declaration are a silent
    /// misconfiguration: the proxy's address becomes the rate-limit key
    /// of every client behind it.
    #[test]
    fn a_trusted_proxy_without_a_declared_header_is_named_at_startup() {
        let mut config = fumox_core::AppConfig::default();
        config.server.trust_proxy_ips = vec!["10.0.0.0/8".into()];
        let warnings = startup_warnings(&config);
        assert_eq!(warnings.len(), 1, "{warnings:?}");
        assert!(warnings[0].contains("trust_proxy_header"), "{warnings:?}");

        // With the declaration the warning is gone: the operator said
        // which header the proxy writes.
        config.server.trust_proxy_header = fumox_core::config::TrustedHeader::Xff;
        assert!(startup_warnings(&config).is_empty());

        // A trusted proxy with no allowlist of its own needs no
        // declaration: nothing reads its headers.
        config.server.trust_proxy_ips.clear();
        config.server.trust_proxy_header = fumox_core::config::TrustedHeader::None;
        assert!(startup_warnings(&config).is_empty());
    }
}
