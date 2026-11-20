//! fumox-server, public subscription endpoints and the admin panel:
//! loads configuration, opens the database, runs the background source
//! refresh scheduler, serves `/sub` and `/src` on the public listener and
//! the SSR admin panel on a separate loopback listener, and shuts down
//! gracefully on SIGINT/SIGTERM.

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
#[cfg(test)]
mod test_support;

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use clap::Parser;

use crate::cache::Caches;
use crate::fetcher::Fetcher;
use crate::scheduler::SchedulerState;

/// How long the listeners may take to drain after a shutdown signal.
/// Some connections never end on their own (the admin SSE stream, a large
/// export download); without a deadline the process waits forever and the
/// orchestrator kills it, skipping the drain and the shutdown log.
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
    /// The bind address comes from the same config the server reads, so
    /// the probe needs the same `--config`/FUMOX_CONFIG the server was
    /// started with.
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
    let cli = Cli::parse();
    let Some(loaded) =
        fumox_core::bootstrap::load_or_print(cli.config.as_deref(), cli.print_config)?
    else {
        return Ok(());
    };
    let config = loaded.config;

    // Before tracing, the pool and the migrations: a probe must not make
    // any of that side effect happen. Migrations complete before the
    // listeners bind, so a 200 here means the schema is current
    if cli.health_check {
        return run_health_check(config.server.bind).await;
    }

    fumox_core::logging::init_tracing(config.log.server);
    log_admin_posture_warnings(&config);
    for warning in startup_warnings(&config) {
        tracing::warn!("{warning}");
    }

    fumox_core::bootstrap::report_config_file(&loaded.path);
    cleanup_config_tmp_leftovers(&loaded.path);
    fumox_core::bootstrap::report_database(&config);

    let pool = fumox_core::db::connect_pool(&config.database).await?;
    fumox_core::db::migrate_with(
        &pool,
        fumox_core::db::ChecksumRepair::from_config(config.database.allow_checksum_repair),
    )
    .await?;

    // The capability token for the public «all alive» export link is
    // generated on first startup and persists in `meta`, so the link is
    // stable across restarts until rotated from the admin panel. Kept in
    // process memory too, so the public endpoint does not read the
    // database per request; the panel and the listener share the
    // instance, so a rotation reaches both
    let export_token = alive_export::TokenCache::new();
    export_token.current(&pool).await?;
    run_legacy_data_upgrades(&pool).await?;

    let geo_download = spawn_geo_download(&config);

    // Background source refresh loop: fetch → parse → reconcile → journal
    let fetcher = Fetcher::new(
        config.fetch.clone(),
        config.admin.allow_private_urls,
        config.ssrf_dns_timeout(),
    );
    let scheduler_state = SchedulerState::new(config.fetch.max_concurrency);
    let caches = Caches::new();
    let geo = Arc::new(fumox_core::geo::GeoResolver::new(&config.geo));
    // Push updates to the admin panel over SSE; the
    // scheduler publishes fetch lifecycle events onto this bus
    let events = events::EventBus::new();
    // The admin panel sends source ids over this channel for an immediate
    // refresh; the sender lives in the serving state, the receiver drives
    // the scheduler loop. Bounded with `try_send` on the sender side: a
    // flood of clicks is dropped instead of piling up behind a wedged
    // loop
    let (refresh_tx, refresh_rx) =
        tokio::sync::mpsc::channel::<String>(scheduler::REFRESH_CHANNEL_CAP);
    let scheduler_task = tokio::spawn(scheduler::run(
        scheduler_ingest_env(&pool, &config, &fetcher, &caches, &geo),
        scheduler_state.clone(),
        events.clone(),
        refresh_rx,
        // The retention windows come from the config this process booted
        // with: the entry point is the only place that knows which file
        // that was
        scheduler::ServerRetention::from_config(&config),
    ));

    let app = build_public_app(&pool, &config, &caches, &geo, &export_token).await?;

    // Admin listener: a separate loopback interface. With an empty token
    // or enabled=false the panel is inert, the listener still binds and
    // answers 404 to everything
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

    // Every exit behind the startup needs the whole scheduler run at once:
    // the refresh channel's sender, the loop's task handle and the shared
    // state its in-flight fetches are marked on move together into the
    // drain (see `finish_shutdown`)
    let scheduler_run = SchedulerRun {
        refresh_tx,
        task: scheduler_task,
        state: scheduler_state,
    };
    run_listeners(
        &pool,
        &config,
        &geo,
        geo_download,
        app,
        admin_router,
        scheduler_run,
    )
    .await?;
    Ok(())
}

/// The scheduler run the process is driving, owned as one unit because
/// every exit behind the startup needs all of it: the refresh channel's
/// sender (the admin panel and the serving state hold clones), the loop's
/// task handle and the shared state its in-flight fetches are marked on.
/// Closing the channel and waiting for the loop is [`finish_shutdown`].
struct SchedulerRun {
    refresh_tx: tokio::sync::mpsc::Sender<String>,
    task: tokio::task::JoinHandle<()>,
    state: SchedulerState,
}

/// The one completion every exit behind the startup takes: close the
/// scheduler's refresh channel, wait (bounded) for the loop to stop, name
/// the in-flight fetches that are being abandoned, and log the completion
/// line. Called both after the listeners end (a shutdown signal, or a
/// listener that failed) and when a bind fails, so no exit path skips
/// the drain.
async fn finish_shutdown(scheduler_run: SchedulerRun) {
    // Dropping the last sender closes the channel (the admin router's
    // clone went with its server, or was dropped by the caller), and the
    // loop treats that as its shutdown signal
    drop(scheduler_run.refresh_tx);
    await_scheduler_stop(scheduler_run.task).await;
    warn_abandoned_fetches(&scheduler_run.state).await;

    tracing::info!("shutdown complete");
}

/// Wait, bounded, for the scheduler loop to stop after its channel closed.
/// The await cannot hold the process past its shutdown: past the deadline
/// a wedged loop is abandoned with a warning, and a loop that ended in an
/// unwind is a warning too, not a crash of the shutdown itself.
async fn await_scheduler_stop(task: tokio::task::JoinHandle<()>) {
    match tokio::time::timeout(Duration::from_secs(5), task).await {
        Ok(Ok(())) => {}
        Ok(Err(err)) => tracing::warn!(error = %err, "scheduler task ended with a join error"),
        Err(_) => tracing::warn!("scheduler task did not stop within 5 s; abandoning it"),
    }
}

/// Name the in-flight fetches the shutdown is abandoning, so a gap in an
/// upstream's log or in `fetch_log` has an explanation in this one. They
/// are detached tasks and cannot be awaited here.
async fn warn_abandoned_fetches(state: &SchedulerState) {
    let abandoned = state.in_flight_ids().await;
    if !abandoned.is_empty() {
        tracing::warn!(
            count = abandoned.len(),
            sources = ?abandoned,
            "shutdown: fetches in flight are abandoned mid-request"
        );
    }
}

/// Exit 0 when the running server answers 200 on `/healthz`, print the
/// probe URL and exit 1 otherwise. The URL, not the bare endpoint: the
/// address the probe derived from the bind is the first thing to compare
/// against the listener the server actually opened.
async fn run_health_check(bind: SocketAddr) -> anyhow::Result<()> {
    match probe_healthz(bind).await {
        Ok(()) => Ok(()),
        Err(error) => {
            eprintln!("{} did not answer 200: {error}", health_probe_url(bind));
            std::process::exit(1);
        }
    }
}

/// GET the local public listener's `/healthz` and accept only 200. The
/// probe carries no token, which is the point: the endpoint is the one
/// unauthenticated route on the public listener.
async fn probe_healthz(bind: SocketAddr) -> anyhow::Result<()> {
    let url = health_probe_url(bind);
    // reqwest is compiled without a crypto provider and panics when a
    // client is built before one is installed
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
/// stands in for it: the IPv6 loopback for an IPv6 wildcard, the IPv4
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

/// Bind the public and the admin listener at once. Both binds are
/// attempted (the tuple shape the caller cleans up after), and when both
/// fail the public bind's error wins: it is the address the clients come
/// to, so the reported error names it first.
async fn bind_listeners(
    server_bind: SocketAddr,
    admin_bind: SocketAddr,
) -> std::io::Result<(tokio::net::TcpListener, tokio::net::TcpListener)> {
    match (
        tokio::net::TcpListener::bind(server_bind).await,
        tokio::net::TcpListener::bind(admin_bind).await,
    ) {
        (Ok(listener), Ok(admin_listener)) => Ok((listener, admin_listener)),
        (Err(error), _) | (_, Err(error)) => Err(error),
    }
}

/// The completion a startup failure behind the scheduler spawn takes:
/// log the error, release the admin router (it holds the refresh
/// channel's other sender, so dropping it lets the scheduler see the
/// close rather than the timeout), run the shared drain (see
/// [`finish_shutdown`]), and hand the error back for the exit value.
async fn abort_startup(
    message: &'static str,
    error: anyhow::Error,
    admin_router: axum::Router,
    scheduler_run: SchedulerRun,
) -> anyhow::Error {
    tracing::error!(error = %error, "{message}");
    drop(admin_router);
    finish_shutdown(scheduler_run).await;
    error
}

/// The public router: `/sub/{id}`, `/src/{id}`, `/export/alive/{token}`
/// and `/export/ready/{token}`.
///
/// `/healthz` gets a pool of its own, one connection, so its answer does
/// not queue behind renders. An orchestrator reads 503 as "restart me",
/// and a busy render pool is this process's own load, not a fault. The
/// type (`serve::HealthPool`) is what proves the pool stays dedicated.
async fn build_public_app(
    pool: &fumox_core::db::DbPool,
    config: &fumox_core::AppConfig,
    caches: &Caches,
    geo: &Arc<fumox_core::geo::GeoResolver>,
    export_token: &alive_export::TokenCache,
) -> anyhow::Result<axum::Router> {
    let health_pool = serve::HealthPool::dedicated(&config.database).await?;
    let state = serve::AppState::new(
        pool.clone(),
        caches.clone(),
        geo.clone(),
        serve::PublicRateLimits::from_config(&config.server),
        admin::parse_trusted_cidrs(&config.server.trust_proxy_ips),
        config.server.trust_proxy_header,
        config.server.allowed_hosts.clone(),
        alive_export::ExportState::new(config.server.export_max_rows, export_token.clone()),
    );
    Ok(serve::public_app(state, health_pool))
}

/// Wait for the listeners to drain, but no longer than `deadline`: an
/// SSE stream or a slow download never ends on its own, so a drain that
/// runs over its deadline is abandoned with a warning and the
/// connections are dropped with the listeners.
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

/// Serve both listeners until a shutdown signal or a listener failure
/// ends the wait, then close the sockets and take the shared completion:
/// the scheduler drain (see [`finish_shutdown`]) and the serving outcome.
async fn serve_until_shutdown(
    listener: tokio::net::TcpListener,
    admin_listener: tokio::net::TcpListener,
    app: axum::Router,
    admin_router: axum::Router,
    scheduler_run: SchedulerRun,
) -> anyhow::Result<()> {
    // The deadline starts when the signal arrives, not when the listeners
    // start. The wait needs the bound: the admin panel holds an SSE
    // stream that never ends on its own
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

    // A listener's error surfaces only at the end, after the shared
    // completion below (the same drain the failed binds take, so no exit
    // path skips it)
    let serving = tokio::select! {
        // A listener that fails ends the wait right away
        result = async {
            tokio::try_join!(&mut public_server, &mut admin_server).map(|_| ())
        } => result.map_err(anyhow::Error::from),
        result = shutdown_signal() => {
            // The listeners stop accepting and drain what they have. The
            // drain is bounded (an SSE stream or a slow download never
            // ends on its own, and an orchestrator kills the process at
            // its own grace period anyway, skipping the drain behind the
            // wait). The signal handlers were installed before the wait,
            // so a failure there is a startup error, not a received
            // signal: the listeners stop the same way either way, and the
            // installation error outranks the drain result as the exit
            // value
            let _ = shutdown_tx.send(true);
            let drained = drain_listeners(SHUTDOWN_DRAIN_TIMEOUT, async {
                tokio::try_join!(&mut public_server, &mut admin_server).map(|_| ())
            })
            .await
            .map_err(anyhow::Error::from);
            result.and(drained)
        }
    };
    // The listeners are done: their sockets close here rather than at the
    // end of the process, so nothing new arrives during the scheduler
    // drain below
    drop(public_server);
    drop(admin_server);

    finish_shutdown(scheduler_run).await;
    serving
}

/// Bind the listeners, run the geo startup gate, and serve until the
/// process stops. Neither gate shortcuts with `?`: both route their
/// failures through [`abort_startup`], the one completion every exit
/// behind the startup takes.
async fn run_listeners(
    pool: &fumox_core::db::DbPool,
    config: &fumox_core::AppConfig,
    geo: &Arc<fumox_core::geo::GeoResolver>,
    geo_download: tokio::task::JoinHandle<()>,
    app: axum::Router,
    admin_router: axum::Router,
    scheduler_run: SchedulerRun,
) -> anyhow::Result<()> {
    let (listener, admin_listener) =
        match bind_listeners(config.server.bind, config.admin.bind).await {
            Ok(pair) => pair,
            Err(error) => {
                return Err(abort_startup(
                    "cannot bind the listeners",
                    error.into(),
                    admin_router,
                    scheduler_run,
                )
                .await);
            }
        };
    tracing::info!(bind = %config.server.bind, "fumox-server listening");

    // The listeners are bound; the download still runs. Give it its
    // budget, then look at the geo state: a profile that filters by
    // country cannot serve anything without the country facts, and a
    // GeoIP failure must not stay silent
    await_geo_within_budget(geo_download, config.geo.startup_download_budget()).await;
    // The gate does not shortcut with `?`: a refusal behind the binds and
    // the scheduler spawn takes the same completion as the failed bind
    // above, so the error is reported after the exit line rather than in
    // place of it
    if let Err(error) = geo_startup_gate(pool, config, geo).await {
        return Err(abort_startup(
            "cannot serve the profiles that filter by country",
            error,
            admin_router,
            scheduler_run,
        )
        .await);
    }
    // Fill the geo columns of proxies ingested before a database existed
    // (background: never blocks startup), bounded like the geo download
    // above by the configured startup budget. It runs after the download
    // had its budget, so it sees the database that just landed
    tokio::spawn(geo_backfill::backfill_missing_geo_within_budget(
        pool.clone(),
        geo.clone(),
        config.geo.startup_download_budget(),
    ));

    serve_until_shutdown(listener, admin_listener, app, admin_router, scheduler_run).await
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

/// The last startup gate: a profile that filters by country cannot serve
/// anything without the country facts, and a GeoIP failure must not stay
/// silent. Both the gate verdict and the profile read behind it fail
/// here, and both happen behind the binds and the scheduler spawn, so
/// the caller routes a refusal through the shared completion (see
/// [`finish_shutdown`]), like every exit behind the startup.
async fn geo_startup_gate(
    pool: &fumox_core::db::DbPool,
    config: &fumox_core::AppConfig,
    geo: &fumox_core::geo::GeoResolver,
) -> anyhow::Result<()> {
    if config.geo.enabled && profiles_require_country(pool).await? && !geo.state().has_country() {
        anyhow::bail!(
            "a profile filters by country, but no GeoLite2 City database is available \
             (geo state: {}, directory: {}); put the database into the directory, \
             point [geo].db_dir at it, or drop the country allowlist",
            geo.state().as_str(),
            config.geo.db_dir.display(),
        );
    }
    Ok(())
}

/// The admin panel's security posture, said before any request arrives.
///
/// The panel is only reachable with a token the operator set; an empty
/// token and the historical "change-me" placeholder both mean "panel
/// off" (see `AdminConfig::is_active`), so the listener is never started
/// for them. Say which mode this is, since "the admin URL answers 404"
/// is otherwise indistinguishable from a routing mistake. A panel on a
/// public address sending its session cookie without `Secure` hands the
/// token to everyone on the path.
fn log_admin_posture_warnings(config: &fumox_core::AppConfig) {
    if config.admin.enabled && !config.admin.is_active() {
        tracing::warn!(
            bind = %config.admin.bind,
            "admin panel is disabled: set admin.token (or FUMOX_ADMIN__TOKEN) to enable it"
        );
    }
    if config.admin.insecure_cookies_on_a_public_bind() {
        tracing::warn!(
            bind = %config.admin.bind,
            "admin session cookie is not marked Secure while the panel listens on a public \
             address: the session token travels in clear text; set admin.secure_cookies = true \
             behind an HTTPS front, or bind the panel to a loopback address"
        );
    }
}

/// A save that died between creating its temporary file and renaming
/// it leaves a copy of the config behind, and the config carries
/// `[admin].token`. The leftovers of writers that are gone are
/// removed here, on the only start that can produce them.
fn cleanup_config_tmp_leftovers(path: &fumox_core::config::ResolvedConfigPath) {
    let config_dir = match path {
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
}

/// The one-time rewrites of rows written by older versions, run between
/// the schema migration and the first ingest: legacy plain-text access
/// tokens are hashed, and fingerprint keys an older canonical form
/// produced are recomputed. Each upgrade is a step of its own; see them
/// for what they rewrite and when.
async fn run_legacy_data_upgrades(pool: &fumox_core::db::DbPool) -> anyhow::Result<()> {
    hash_legacy_profile_tokens(pool).await?;
    recompute_stored_fingerprints(pool).await?;
    Ok(())
}

/// Profile access tokens are stored as hashes. A row written before
/// that still holds the token in plain text, so it is rewritten in
/// place on the first start after the upgrade.
async fn hash_legacy_profile_tokens(pool: &fumox_core::db::DbPool) -> anyhow::Result<()> {
    let hashed = fumox_core::repo::profiles::hash_legacy_tokens(pool).await?;
    if hashed > 0 {
        tracing::info!(count = hashed, "profile access tokens hashed");
    }
    Ok(())
}

/// The fingerprint version is part of the pre-image, so a change of the
/// canonical form changes every key: the rows written before the change
/// keep keys the ingest no longer produces. They are recomputed once,
/// on the first start after the upgrade, before the first ingest (the
/// rows that describe the same node twice are merged into one).
async fn recompute_stored_fingerprints(pool: &fumox_core::db::DbPool) -> anyhow::Result<()> {
    match fumox_core::repo::proxies::ensure_fingerprint_version(pool).await? {
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
    Ok(())
}

/// Best-effort GeoLite2 database download into [geo].db_dir: fetch what
/// is missing, broken or older than a month.
///
/// The download runs in its own task and the listeners are bound
/// without waiting for it: a mirror must not keep the public surface
/// dark. The resolver asks the process-wide registry for the databases
/// on every lookup, so a file that lands later is picked up without a
/// restart. The budget is how long startup waits for the file
/// afterwards, not how long the download may run.
fn spawn_geo_download(config: &fumox_core::AppConfig) -> tokio::task::JoinHandle<()> {
    let geo_config = config.clone();
    let download =
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
    download
}

/// The shared environment the scheduler's ingestion tasks run with,
/// cloned out of the state main built for the whole process.
fn scheduler_ingest_env(
    pool: &fumox_core::db::DbPool,
    config: &fumox_core::AppConfig,
    fetcher: &Fetcher,
    caches: &Caches,
    geo: &Arc<fumox_core::geo::GeoResolver>,
) -> scheduler::IngestEnv {
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
    }
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
///
/// The handlers are installed before the wait, so a failed installation
/// is an error the caller reports like any other startup failure, not a
/// panic inside the shutdown path.
async fn shutdown_signal() -> anyhow::Result<()> {
    let ctrl_c = tokio::signal::ctrl_c();

    #[cfg(unix)]
    let terminate = {
        let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .map_err(|error| anyhow::anyhow!("failed to install SIGTERM handler: {error}"))?;
        async move {
            sigterm.recv().await;
        }
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        result = ctrl_c => {
            result.map_err(|error| anyhow::anyhow!("failed to install Ctrl-C handler: {error}"))?
        }
        () = terminate => {},
    }
    tracing::info!("shutdown signal received, draining connections");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A stalled GeoLite2 download must not keep the listeners from
    /// binding: the wait gives up at the budget and leaves the task
    /// running.
    #[tokio::test]
    async fn a_stalled_geo_download_does_not_hold_startup() {
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(async move {
            let _ = started_tx.send(());
            // Far longer than the budget below
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
        // The task ran to its end rather than being abandoned
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
        // startup hostage
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
    /// stream never ends on its own, and a wait without a bound keeps the
    /// process alive until the orchestrator kills it, skipping the drain
    /// and the shutdown log that sit behind the wait.
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

    /// Fresh migrated SQLite in a scoped temp directory (the shape the
    /// probe tests keep): the guard in scope removes the directory when
    /// it drops.
    async fn temp_pool() -> (fumox_core::tempdir_lite::TempDir, fumox_core::db::DbPool) {
        let dir = fumox_core::tempdir_lite::TempDir::new("server-gate");
        let pool = fumox_core::db::connect_pool(&fumox_core::config::DatabaseConfig {
            path: dir.path().join("test.db"),
            ..Default::default()
        })
        .await
        .unwrap();
        fumox_core::db::migrate(&pool).await.unwrap();
        (dir, pool)
    }

    /// Seed one enabled profile with the given country allowlist.
    async fn seed_profile(pool: &fumox_core::db::DbPool, countries: Vec<String>) {
        let now = fumox_core::models::now_ts();
        let profile = fumox_core::models::Profile {
            id: format!("prof{}", fumox_core::models::new_id()),
            slug: None,
            access_token: None,
            name: "p".into(),
            output_format: Default::default(),
            pipeline: None,
            countries,
            include_unknown_country: false,
            enabled: true,
            created_at: now,
            updated_at: now,
        };
        fumox_core::repo::profiles::create(pool, &profile)
            .await
            .unwrap();
    }

    /// The startup geo gate refuses when an enabled profile filters by
    /// country and the country facts are missing: the subscription would
    /// come out empty, whatever the feed holds.
    #[tokio::test]
    async fn the_geo_startup_gate_refuses_without_the_country_facts() {
        let (_dir, pool) = temp_pool().await;
        seed_profile(&pool, vec!["US".into()]).await;

        let config = fumox_core::AppConfig::default();
        let geo = Arc::new(fumox_core::geo::GeoResolver::new(&config.geo));
        assert!(
            !geo.state().has_country(),
            "the test needs an installation without GeoLite2 databases"
        );

        let error = geo_startup_gate(&pool, &config, &geo)
            .await
            .expect_err("a country allowlist without the facts must refuse");
        assert!(error.to_string().contains("filters by country"), "{error}");
    }

    /// Nothing needs the facts (no enabled profile, or no allowlist on
    /// any), so the gate passes and startup goes on. A broken profile
    /// read is an error like any other startup failure, not a pass.
    #[tokio::test]
    async fn the_geo_startup_gate_passes_when_nothing_needs_the_facts() {
        let (_dir, pool) = temp_pool().await;
        let config = fumox_core::AppConfig::default();
        let geo = Arc::new(fumox_core::geo::GeoResolver::new(&config.geo));

        assert!(
            geo_startup_gate(&pool, &config, &geo).await.is_ok(),
            "an installation without profiles needs no geo"
        );

        seed_profile(&pool, Vec::new()).await;
        assert!(
            geo_startup_gate(&pool, &config, &geo).await.is_ok(),
            "a profile without an allowlist needs no geo"
        );

        // The gate reads the profiles table behind `?`: a failed read
        // must surface, not silently count as "nothing needs the facts"
        sqlx::query("DROP TABLE profiles")
            .execute(&pool)
            .await
            .unwrap();
        assert!(geo_startup_gate(&pool, &config, &geo).await.is_err());
    }

    /// The health probe must reach the listener the operator configured.
    /// A bind that names an address is probed at exactly that address; a
    /// wildcard is not a destination, so the loopback stands in for it
    /// (the IPv6 loopback for an IPv6 wildcard, the IPv4 one for an IPv4
    /// wildcard).
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

        // An IPv6 address keeps its square brackets in the URL
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
        // which header the proxy writes
        config.server.trust_proxy_header = fumox_core::config::TrustedHeader::Xff;
        assert!(startup_warnings(&config).is_empty());

        // A trusted proxy with no allowlist of its own needs no
        // declaration: nothing reads its headers
        config.server.trust_proxy_ips.clear();
        config.server.trust_proxy_header = fumox_core::config::TrustedHeader::None;
        assert!(startup_warnings(&config).is_empty());
    }
}
