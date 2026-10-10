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
mod scheduler;
mod security;
mod serve;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use clap::Parser;

use crate::cache::Caches;
use crate::fetcher::Fetcher;
use crate::scheduler::SchedulerState;

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
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let loaded = fumox_core::config::load(cli.config.as_deref())?;
    let config = loaded.config;

    // Before tracing, the pool and the migrations: a probe must not make
    // any of that side effect happen just to be measured. It reports the
    // server's readiness, and migrations complete before the listeners
    // bind, so a 200 here means the schema is current.
    if cli.health_check {
        return match probe_healthz(config.server.bind.port()).await {
            Ok(()) => Ok(()),
            Err(error) => {
                eprintln!("/healthz did not answer 200: {error}");
                std::process::exit(1);
            }
        };
    }

    fumox_core::logging::init_tracing(config.log.server);

    // Security audit (2026-08-30): running the panel with the built-in
    // default token is almost certainly a misconfiguration, say so loudly.
    if config.admin.is_active() && config.admin.token == fumox_core::config::DEFAULT_ADMIN_TOKEN {
        tracing::warn!(
            "admin token equals the built-in default; \
             set [admin].token (or FUMOX_ADMIN__TOKEN) before exposing the panel"
        );
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
    fumox_core::db::migrate(&pool).await?;
    // The public «all alive» export link: generate the
    // capability token on first startup; it persists in `meta`, so the
    // link is stable across restarts until rotated from the admin panel.
    alive_export::ensure_token(&pool).await?;

    // Best-effort GeoLite2 database download into [geo].db_dir: fetch what
    // is missing, broken or older than a month. It runs before the geo
    // resolver opens the files, but only for `[geo].startup_download_budget_secs`:
    // two slow mirrors must not hold `/healthz` and the whole public surface
    // hostage for the sum of their per-file download budgets. Past the budget
    // the task keeps running detached (the file is installed atomically, so
    // the resolver and a later start never see a partial one) and this process
    // simply runs without geo enrichment until the next start.
    let geo_config = config.clone();
    await_geo_within_budget(
        tokio::spawn(async move { geo_download::ensure_geo_databases(&geo_config).await }),
        config.geo.startup_download_budget(),
    )
    .await;

    // Background source refresh loop: fetch → parse → reconcile → journal.
    let fetcher = Fetcher::new(
        config.fetch.clone(),
        config.admin.allow_private_urls,
        config.geo.dns_timeout(),
    );
    let scheduler_state = SchedulerState::new(config.fetch.max_concurrency);
    let caches = Caches::new();
    let geo = Arc::new(fumox_core::geo::GeoResolver::new(&config.geo));
    // Fill the geo columns of proxies ingested before a database existed
    // (background: never blocks startup), bounded like the geo download
    // above by the configured startup budget.
    tokio::spawn(geo_backfill::backfill_missing_geo_within_budget(
        pool.clone(),
        geo.clone(),
        config.geo.startup_download_budget(),
    ));
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
        },
        scheduler_state.clone(),
        events.clone(),
        refresh_rx,
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
        config.server.allowed_hosts.clone(),
        config.server.export_max_rows,
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

    // The public rate limiter also keys requests by peer address.
    let public_server = axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal());
    let admin_server = axum::serve(
        admin_listener,
        admin_router.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal());

    // Drain the background scheduler even when a listener failed: the
    // `?` used to return here first, so a bind error skipped the drain and
    // the process exited with the scheduler's in-flight fetches unnamed.
    let serving = tokio::try_join!(public_server, admin_server);

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
async fn probe_healthz(port: u16) -> anyhow::Result<()> {
    let url = format!("http://127.0.0.1:{port}/healthz");
    reqwest::Client::builder()
        .timeout(Duration::from_secs(3))
        .build()?
        .get(&url)
        .send()
        .await?
        .error_for_status()?;
    Ok(())
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
        Err(_) => tracing::warn!(
            budget_secs = budget.as_secs(),
            "GeoLite2 download still running at the startup budget; \
             starting without it, the download continues in the background"
        ),
    }
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
}
