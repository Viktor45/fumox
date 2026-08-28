//! fumox-server — public subscription endpoints and the admin panel.
//!
//! Loads configuration, opens the database, runs the background source
//! refresh scheduler, serves `/sub` and `/src` on the public listener and
//! the SSR admin panel on a separate loopback listener (ADMIN_PLAN §2),
//! and shuts down gracefully on SIGINT/SIGTERM.

mod admin;
mod cache;
mod events;
mod fetcher;
mod ingest;
mod pipeline;
mod scheduler;
mod serve;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use axum::routing::get;
use clap::Parser;

use crate::cache::Caches;
use crate::fetcher::Fetcher;
use crate::scheduler::SchedulerState;

#[derive(Parser)]
#[command(name = "fumox-server", version, about = "Fumox subscription server")]
struct Cli {
    /// Path to the TOML config file (defaults to config/app.toml if present).
    #[arg(short, long)]
    config: Option<PathBuf>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    fumox_core::logging::init_tracing();

    let config = fumox_core::AppConfig::load(cli.config.as_deref())?;
    let pool = fumox_core::db::connect_pool(&config.database).await?;
    fumox_core::db::migrate(&pool).await?;

    // Background source refresh loop: fetch → parse → reconcile → journal.
    let fetcher = Fetcher::new(config.fetch.clone(), config.admin.allow_private_urls);
    let scheduler_state = SchedulerState::new(config.fetch.max_concurrency);
    let caches = Caches::new();
    let geo = Arc::new(fumox_core::geo::GeoResolver::new(&config.geo));
    // Push updates to the admin panel over SSE (ADMIN_PLAN §9); the
    // scheduler publishes fetch lifecycle events onto this bus.
    let events = events::EventBus::new();
    // The admin panel sends source ids over this channel for an immediate
    // refresh; the sender lives in the serving state, the receiver drives
    // the scheduler loop.
    let (refresh_tx, refresh_rx) = tokio::sync::mpsc::unbounded_channel::<String>();
    tokio::spawn(scheduler::run(
        pool.clone(),
        fetcher.clone(),
        caches.clone(),
        scheduler_state.clone(),
        events.clone(),
        refresh_rx,
    ));

    // Public listener: /sub/{id} and /src/{id}.
    let state = serve::AppState {
        pool: pool.clone(),
        caches: caches.clone(),
        geo: geo.clone(),
        refresh_tx: refresh_tx.clone(),
    };
    let app = serve::router(state).route("/healthz", get(|| async { "ok\n" }));

    // Admin listener (ADMIN_PLAN §2): a separate loopback interface. With
    // an empty token or enabled=false the panel is inert — the listener
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

    // The rate limiter keys requests by peer address, so the admin service
    // must expose ConnectInfo<SocketAddr> to its middleware.
    let public_server = axum::serve(listener, app).with_graceful_shutdown(shutdown_signal());
    let admin_server = axum::serve(
        admin_listener,
        admin_router.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal());

    tokio::try_join!(public_server, admin_server)?;

    tracing::info!("shutdown complete");
    Ok(())
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
