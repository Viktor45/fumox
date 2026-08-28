//! fumox-probe — health-check daemon (SPEC §8).
//!
//! Every scheduling cycle runs three passes:
//!
//! 1. **Quarantine dues** — second chances and recheck-ladder steps whose
//!    scheduled moment has arrived (SPEC §8.3a);
//! 2. **T1** — a random sample of TCP-connect / TLS-handshake checks over
//!    the `unknown`/`alive` population (SPEC §8.1, §8.3);
//! 3. **T2** — real tunnel checks for `alive` proxies through the meow-rs
//!    REST API (SPEC §8.2), skipped with backoff when meow-rs is down.
//!
//! All lifecycle state lives in SQLite, so the daemon is restart-safe:
//! after a restart it simply resumes the schedules persisted in the DB.

mod clash;
mod meow;
mod t1;

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicI64, Ordering};
use std::time::Duration;

use clap::Parser;
use fumox_core::AppConfig;
use fumox_core::db::DbPool;
use fumox_core::models::{Scheme, now_ts};
use fumox_core::repo::probe::ProbeResultEntry;
use fumox_core::repo::{fetch_log, meta_set, probe as probe_repo, proxies};
use meow::{DelayOutcome, MeowClient};
use tokio::sync::Semaphore;

/// Initial and capped backoff applied when meow-rs stops responding.
const MEOW_BACKOFF_INITIAL_SECS: i64 = 60;
const MEOW_BACKOFF_MAX_SECS: i64 = 15 * 60;

#[derive(Parser)]
#[command(name = "fumox-probe", version, about = "Fumox health-check daemon")]
struct Cli {
    /// Path to the TOML config file (defaults to config/app.toml if present).
    #[arg(short, long)]
    config: Option<PathBuf>,
}

/// Shared daemon state, cheap to clone into spawned check tasks.
struct Context {
    pool: DbPool,
    config: AppConfig,
    meow: MeowClient,
    /// Earliest unix second at which T2 may be retried after meow-rs
    /// becomes unavailable (exponential backoff, capped).
    meow_retry_at: AtomicI64,
    /// Current meow-rs backoff length in seconds.
    meow_backoff_secs: AtomicI64,
}

impl Context {
    fn new(config: AppConfig, pool: DbPool) -> Self {
        let meow = MeowClient::new(&config.meow);
        Self {
            pool,
            config,
            meow,
            meow_retry_at: AtomicI64::new(0),
            meow_backoff_secs: AtomicI64::new(MEOW_BACKOFF_INITIAL_SECS),
        }
    }

    /// Push the next T2 retry further into the future (capped exponential).
    fn backoff_meow(&self) {
        let backoff = self.meow_backoff_secs.load(Ordering::Relaxed);
        let next = (backoff * 2).min(MEOW_BACKOFF_MAX_SECS);
        self.meow_backoff_secs.store(next, Ordering::Relaxed);
        self.meow_retry_at
            .store(now_ts() + backoff, Ordering::Relaxed);
    }

    /// meow-rs answered — clear the backoff.
    fn meow_recovered(&self) {
        self.meow_backoff_secs
            .store(MEOW_BACKOFF_INITIAL_SECS, Ordering::Relaxed);
        self.meow_retry_at.store(0, Ordering::Relaxed);
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    fumox_core::logging::init_tracing();

    let config = AppConfig::load(cli.config.as_deref())?;
    let pool = fumox_core::db::connect_pool(&config.database).await?;
    fumox_core::db::migrate(&pool).await?;

    tracing::info!(
        cycle_secs = config.probe.cycle_interval_secs,
        sample_size = config.probe.sample_size,
        fail_limit = config.probe.fail_limit,
        concurrency = config.probe.concurrency,
        "fumox-probe started"
    );

    let ctx = Arc::new(Context::new(config, pool));
    tokio::select! {
        result = run(ctx) => result?,
        () = shutdown_signal() => {},
    }

    tracing::info!("shutdown complete");
    Ok(())
}

/// Main scheduling loop: heartbeat and retention run on their own timers,
/// probe cycles on the configured period. Errors are logged, never fatal —
/// a bad cycle must not take down the daemon.
async fn run(ctx: Arc<Context>) -> anyhow::Result<()> {
    tokio::spawn(heartbeat_loop(ctx.clone()));
    tokio::spawn(retention_loop(ctx.clone()));

    let period = Duration::from_secs(ctx.config.probe.cycle_interval_secs.max(1));
    let mut ticker = tokio::time::interval(period);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        ticker.tick().await;
        if let Err(error) = run_cycle(ctx.clone()).await {
            tracing::error!(%error, "probe cycle failed");
        }
    }
}

/// One scheduling cycle: quarantine dues first (they are time-sensitive),
/// then the T1 sample, then the T2 batch.
async fn run_cycle(ctx: Arc<Context>) -> anyhow::Result<()> {
    let now = now_ts();
    let quarantine = probe_due_quarantine(ctx.clone(), now).await?;
    let t1_checked = probe_t1_sample(ctx.clone()).await?;
    let t2_checked = probe_t2_batch(ctx).await?;
    tracing::info!(
        quarantine_checked = quarantine,
        t1_checked,
        t2_checked,
        "probe cycle done"
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// T1: random connectivity sample
// ---------------------------------------------------------------------------

/// Probe a random sample of `unknown`/`alive` proxies (SPEC §8.3).
async fn probe_t1_sample(ctx: Arc<Context>) -> anyhow::Result<usize> {
    let candidates = proxies::select_t1_candidates(&ctx.pool, ctx.config.probe.sample_size).await?;
    if candidates.is_empty() {
        return Ok(0);
    }

    let semaphore = Arc::new(Semaphore::new(ctx.config.probe.concurrency.max(1)));
    let mut tasks = tokio::task::JoinSet::new();
    for candidate in candidates {
        let Ok(scheme) = candidate.scheme.parse::<Scheme>() else {
            tracing::warn!(id = candidate.id, scheme = %candidate.scheme, "unknown scheme, skipped");
            continue;
        };
        let Ok(port) = u16::try_from(candidate.port) else {
            tracing::warn!(
                id = candidate.id,
                port = candidate.port,
                "port out of range, skipped"
            );
            continue;
        };
        let kind = t1::check_kind(scheme, candidate.params.as_deref());
        let (ctx, semaphore) = (ctx.clone(), semaphore.clone());
        tasks.spawn(async move {
            let _permit = semaphore
                .acquire_owned()
                .await
                .expect("semaphore never closed");
            perform_t1_check(&ctx, candidate.id, &candidate.host, port, kind).await;
        });
    }
    Ok(collect_tasks(&mut tasks).await)
}

/// Run one T1 check and apply the outcome to the lifecycle: journal the
/// attempt into `probe_results`, then move the state machine.
async fn perform_t1_check(ctx: &Context, id: i64, host: &str, port: u16, kind: t1::CheckKind) {
    let connect_timeout = Duration::from_secs(ctx.config.probe.connect_timeout_secs.max(1));
    let tls_timeout = Duration::from_secs(ctx.config.probe.tls_timeout_secs.max(1));
    let outcome = t1::run(host, port, kind, connect_timeout, tls_timeout).await;
    let now = now_ts();

    match outcome {
        Ok(elapsed) => {
            let latency = i64::try_from(elapsed.as_millis()).unwrap_or(i64::MAX);
            journal(
                ctx,
                ProbeResultEntry {
                    proxy_id: id,
                    checked_at: now,
                    ok: true,
                    latency_ms: Some(latency),
                    error: None,
                    probe_kind: kind.as_str(),
                },
            )
            .await;
            if let Err(error) = proxies::check_succeeded(&ctx.pool, id, now, Some(latency)).await {
                tracing::warn!(id, %error, "failed to record T1 success");
            }
        }
        Err(reason) => {
            journal(
                ctx,
                ProbeResultEntry {
                    proxy_id: id,
                    checked_at: now,
                    ok: false,
                    latency_ms: None,
                    error: Some(&reason),
                    probe_kind: kind.as_str(),
                },
            )
            .await;
            apply_regular_failure(ctx, id, now).await;
        }
    }
}

/// Bump the fail counter, quarantining when the consecutive-failure limit
/// is reached (SPEC §8.3).
async fn apply_regular_failure(ctx: &Context, id: i64, now: i64) {
    let probe = &ctx.config.probe;
    let min_secs = i64::try_from(probe.second_chance_min_hours * 3600).unwrap_or(i64::MAX);
    let spread_secs = i64::try_from(probe.second_chance_spread_hours * 3600).unwrap_or(0);
    match proxies::check_failed(&ctx.pool, id, now, probe.fail_limit, min_secs, spread_secs).await {
        Ok(proxies::Transition::Quarantined) => {
            tracing::info!(id, "proxy quarantined after consecutive failures")
        }
        Ok(_) => {}
        Err(error) => tracing::warn!(id, %error, "failed to record T1 failure"),
    }
}

// ---------------------------------------------------------------------------
// Quarantine: second chances and the recheck ladder (SPEC §8.3a)
// ---------------------------------------------------------------------------

/// Re-check quarantined proxies whose scheduled moment has arrived.
async fn probe_due_quarantine(ctx: Arc<Context>, now: i64) -> anyhow::Result<usize> {
    let due = proxies::select_due_quarantine(&ctx.pool, now, ctx.config.probe.sample_size).await?;
    if due.is_empty() {
        return Ok(0);
    }

    let semaphore = Arc::new(Semaphore::new(ctx.config.probe.concurrency.max(1)));
    let mut tasks = tokio::task::JoinSet::new();
    for row in due {
        let Ok(scheme) = row.scheme.parse::<Scheme>() else {
            tracing::warn!(id = row.id, scheme = %row.scheme, "unknown scheme in quarantine, skipped");
            continue;
        };
        let Ok(port) = u16::try_from(row.port) else {
            tracing::warn!(
                id = row.id,
                port = row.port,
                "port out of range in quarantine, skipped"
            );
            continue;
        };
        let stage = row.stage();
        let kind = t1::check_kind(scheme, row.params.as_deref());
        let (ctx, semaphore) = (ctx.clone(), semaphore.clone());
        tasks.spawn(async move {
            let _permit = semaphore
                .acquire_owned()
                .await
                .expect("semaphore never closed");
            perform_quarantine_check(&ctx, row.id, &row.host, port, kind, stage).await;
        });
    }
    Ok(collect_tasks(&mut tasks).await)
}

/// One quarantine re-check: success revives the proxy with a clean slate;
/// failure advances the ladder (+15m/+30m/+1h) or removes the proxy after
/// the third failed recheck (SPEC §8.3a steps 3–5).
async fn perform_quarantine_check(
    ctx: &Context,
    id: i64,
    host: &str,
    port: u16,
    kind: t1::CheckKind,
    stage: proxies::QuarantineStage,
) {
    let connect_timeout = Duration::from_secs(ctx.config.probe.connect_timeout_secs.max(1));
    let tls_timeout = Duration::from_secs(ctx.config.probe.tls_timeout_secs.max(1));
    let outcome = t1::run(host, port, kind, connect_timeout, tls_timeout).await;
    let now = now_ts();

    match outcome {
        Ok(elapsed) => {
            let latency = i64::try_from(elapsed.as_millis()).unwrap_or(i64::MAX);
            journal(
                ctx,
                ProbeResultEntry {
                    proxy_id: id,
                    checked_at: now,
                    ok: true,
                    latency_ms: Some(latency),
                    error: None,
                    probe_kind: kind.as_str(),
                },
            )
            .await;
            match proxies::check_succeeded(&ctx.pool, id, now, Some(latency)).await {
                Ok(_) => tracing::info!(id, ?stage, "quarantined proxy revived"),
                Err(error) => tracing::warn!(id, %error, "failed to record quarantine success"),
            }
        }
        Err(reason) => {
            journal(
                ctx,
                ProbeResultEntry {
                    proxy_id: id,
                    checked_at: now,
                    ok: false,
                    latency_ms: None,
                    error: Some(&reason),
                    probe_kind: kind.as_str(),
                },
            )
            .await;
            match proxies::quarantine_check_failed(&ctx.pool, id, now, stage).await {
                Ok(proxies::Transition::Removed) => {
                    tracing::info!(id, "proxy removed after three failed rechecks")
                }
                Ok(_) => tracing::debug!(id, ?stage, "quarantine recheck failed, ladder advanced"),
                Err(error) => tracing::warn!(id, %error, "failed to advance quarantine ladder"),
            }
        }
    }
}

// ---------------------------------------------------------------------------
// T2: real tunnel checks through meow-rs (SPEC §8.2)
// ---------------------------------------------------------------------------

/// Generate a Clash batch, reload meow-rs, and delay-test every proxy
/// through a real tunnel. meow-rs unavailability aborts the pass with
/// backoff and leaves proxy statuses untouched.
async fn probe_t2_batch(ctx: Arc<Context>) -> anyhow::Result<usize> {
    let now = now_ts();
    if now < ctx.meow_retry_at.load(Ordering::Relaxed) {
        tracing::debug!("meow-rs in backoff, T2 skipped");
        return Ok(0);
    }

    let rows = proxies::select_t2_candidates(&ctx.pool, ctx.config.probe.sample_size).await?;
    let batch: Vec<_> = rows
        .into_iter()
        .filter(|row| row.scheme.parse::<Scheme>().is_ok_and(clash::is_supported))
        .collect();
    if batch.is_empty() {
        return Ok(0);
    }

    // Cheap liveness check first: no point rewriting the config file when
    // the service is down anyway.
    if let Err(error) = ctx.meow.ping().await {
        tracing::warn!(%error, "meow-rs unavailable, T2 skipped with backoff");
        ctx.backoff_meow();
        return Ok(0);
    }

    let yaml = clash::generate(&batch)?;
    let config_path = &ctx.config.meow.config_path;
    if let Some(parent) = config_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(config_path, yaml)?;

    if let Err(error) = ctx.meow.reload_config(config_path).await {
        tracing::warn!(%error, "meow-rs unavailable, T2 skipped with backoff");
        ctx.backoff_meow();
        return Ok(0);
    }
    ctx.meow_recovered();
    if let Err(error) = meta_set(&ctx.pool, "meow_last_ok", &now_ts().to_string()).await {
        tracing::warn!(%error, "failed to stamp meow_last_ok");
    }

    let fail_limit = ctx.config.probe.fail_limit;
    let min_secs =
        i64::try_from(ctx.config.probe.second_chance_min_hours * 3600).unwrap_or(i64::MAX);
    let spread_secs =
        i64::try_from(ctx.config.probe.second_chance_spread_hours * 3600).unwrap_or(0);

    let semaphore = Arc::new(Semaphore::new(ctx.config.probe.concurrency.max(1)));
    let mut tasks = tokio::task::JoinSet::new();
    for row in batch {
        let (ctx, semaphore) = (ctx.clone(), semaphore.clone());
        tasks.spawn(async move {
            let _permit = semaphore
                .acquire_owned()
                .await
                .expect("semaphore never closed");
            let name = clash::proxy_name(row.id);
            let now = now_ts();
            match ctx.meow.check_delay(&name).await {
                DelayOutcome::Ok(delay) => {
                    let latency = i64::try_from(delay).unwrap_or(i64::MAX);
                    journal(
                        &ctx,
                        ProbeResultEntry {
                            proxy_id: row.id,
                            checked_at: now,
                            ok: true,
                            latency_ms: Some(latency),
                            error: None,
                            probe_kind: "t2",
                        },
                    )
                    .await;
                    if let Err(error) =
                        proxies::check_succeeded(&ctx.pool, row.id, now, Some(latency)).await
                    {
                        tracing::warn!(id = row.id, %error, "failed to record T2 success");
                    }
                }
                DelayOutcome::ProxyFailed(message) => {
                    journal(
                        &ctx,
                        ProbeResultEntry {
                            proxy_id: row.id,
                            checked_at: now,
                            ok: false,
                            latency_ms: None,
                            error: Some(&message),
                            probe_kind: "t2",
                        },
                    )
                    .await;
                    match proxies::check_failed(
                        &ctx.pool,
                        row.id,
                        now,
                        fail_limit,
                        min_secs,
                        spread_secs,
                    )
                    .await
                    {
                        Ok(proxies::Transition::Quarantined) => {
                            tracing::info!(id = row.id, "proxy quarantined after T2 failures")
                        }
                        Ok(_) => {}
                        Err(error) => {
                            tracing::warn!(id = row.id, %error, "failed to record T2 failure")
                        }
                    }
                }
                DelayOutcome::ServiceUnavailable(error) => {
                    // meow-rs itself is having problems mid-batch: stop
                    // penalizing proxies and back off.
                    tracing::warn!(%error, "meow-rs became unavailable mid-batch, aborting T2");
                    ctx.backoff_meow();
                }
            }
        });
    }
    Ok(collect_tasks(&mut tasks).await)
}

// ---------------------------------------------------------------------------
// Background maintenance
// ---------------------------------------------------------------------------

/// Periodically upsert `probe_heartbeat` into `meta` so the admin panel can
/// tell the daemon is alive (ADMIN_PLAN §4.5).
async fn heartbeat_loop(ctx: Arc<Context>) {
    let period = Duration::from_secs(ctx.config.probe.heartbeat_interval_secs.max(5));
    let mut ticker = tokio::time::interval(period);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        ticker.tick().await;
        let payload = serde_json::json!({
            "ts": now_ts(),
            "pid": std::process::id(),
            "version": env!("CARGO_PKG_VERSION"),
        });
        if let Err(error) = meta_set(&ctx.pool, "probe_heartbeat", &payload.to_string()).await {
            tracing::warn!(%error, "failed to write probe heartbeat");
        }
    }
}

/// History rotation (SPEC §12): `probe_results` and `fetch_log` older than
/// the configured windows are purged once at startup and then periodically.
async fn retention_loop(ctx: Arc<Context>) {
    run_retention(&ctx).await;

    let period = Duration::from_secs(ctx.config.probe.retention_interval_secs.max(60));
    let mut ticker = tokio::time::interval(period);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        ticker.tick().await;
        run_retention(&ctx).await;
    }
}

async fn run_retention(ctx: &Context) {
    let now = now_ts();
    let probe_cutoff = now - i64::from(ctx.config.retention.probe_results_days) * 86_400;
    let fetch_cutoff = now - i64::from(ctx.config.retention.fetch_log_days) * 86_400;

    match probe_repo::purge_before(&ctx.pool, probe_cutoff).await {
        Ok(0) => {}
        Ok(deleted) => tracing::info!(deleted, "rotated probe_results"),
        Err(error) => tracing::warn!(%error, "probe_results rotation failed"),
    }
    match fetch_log::purge_before(&ctx.pool, fetch_cutoff).await {
        Ok(0) => {}
        Ok(deleted) => tracing::info!(deleted, "rotated fetch_log"),
        Err(error) => tracing::warn!(%error, "fetch_log rotation failed"),
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Journal one probe attempt; a failed write is logged but does not stop
/// the state machine (the lifecycle transition is the source of truth).
async fn journal(ctx: &Context, entry: ProbeResultEntry<'_>) {
    if let Err(error) = probe_repo::insert(&ctx.pool, &entry).await {
        tracing::warn!(id = entry.proxy_id, %error, "failed to journal probe result");
    }
}

/// Await all spawned check tasks; returns how many completed. Panics are
/// reported as warnings — one bad task must not kill the cycle.
async fn collect_tasks(tasks: &mut tokio::task::JoinSet<()>) -> usize {
    let mut completed = 0;
    while let Some(result) = tasks.join_next().await {
        match result {
            Ok(()) => completed += 1,
            Err(error) => tracing::warn!(%error, "probe task panicked"),
        }
    }
    completed
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
    tracing::info!("shutdown signal received");
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::extract::Path;
    use axum::routing::{get, put};
    use axum::{Json, Router};

    /// Fresh migrated SQLite in a temp directory.
    async fn temp_pool() -> DbPool {
        let dir =
            std::env::temp_dir().join(format!("fumox-probe-test-{}", fumox_core::models::new_id()));
        std::fs::create_dir_all(&dir).unwrap();
        let cfg = fumox_core::config::DatabaseConfig {
            path: dir.join("test.db"),
            ..Default::default()
        };
        let pool = fumox_core::db::connect_pool(&cfg).await.unwrap();
        fumox_core::db::migrate(&pool).await.unwrap();
        pool
    }

    /// Seed a linked proxy row; returns its id.
    async fn seed_proxy(pool: &DbPool, scheme: &str, host: &str, port: u16, status: &str) -> i64 {
        sqlx::query(
            "INSERT OR IGNORE INTO sources (id, name, url, enabled, encoding, cache_ttl_seconds, created_at, updated_at)
             VALUES ('srcT0000000', 'probe-test', 'https://example.com', 1, 'auto', 3600, 1, 1)",
        )
        .execute(pool)
        .await
        .unwrap();
        let (id,): (i64,) = sqlx::query_as(
            "INSERT INTO proxies (fingerprint, scheme, name, host, port, credential, status, created_at, updated_at)
             VALUES (?, ?, 'n', ?, ?, 'c', ?, 1, 1)
             RETURNING id",
        )
        .bind(format!("fp-{}", fumox_core::models::new_id()))
        .bind(scheme)
        .bind(host)
        .bind(i64::from(port))
        .bind(status)
        .fetch_one(pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO proxy_source_links (proxy_id, source_id, seen_at) VALUES (?, 'srcT0000000', 1)",
        )
        .bind(id)
        .execute(pool)
        .await
        .unwrap();
        id
    }

    fn test_config(fail_limit: u32, meow_addr: &str, meow_config: PathBuf) -> AppConfig {
        AppConfig {
            probe: fumox_core::config::ProbeConfig {
                cycle_interval_secs: 60,
                sample_size: 50,
                fail_limit,
                connect_timeout_secs: 2,
                tls_timeout_secs: 2,
                concurrency: 4,
                heartbeat_interval_secs: 30,
                // Deterministic second chance: exactly +24h, no jitter.
                second_chance_min_hours: 24,
                second_chance_spread_hours: 0,
                retention_interval_secs: 86400,
            },
            meow: fumox_core::config::MeowConfig {
                api_addr: meow_addr.into(),
                config_path: meow_config,
                test_url: "http://cp.cloudflare.com".into(),
                timeout_secs: 3,
            },
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn t1_cycle_promotes_live_proxy_and_quarantines_dead_one() {
        let pool = temp_pool().await;

        // One proxy points at a live listener, the other at a closed port.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let live_port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            loop {
                let (mut socket, _) = match listener.accept().await {
                    Ok(ok) => ok,
                    Err(_) => break,
                };
                tokio::spawn(async move {
                    use tokio::io::AsyncWriteExt;
                    let _ = socket.shutdown().await;
                });
            }
        });
        let dead = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let dead_port = dead.local_addr().unwrap().port();
        drop(dead);

        let live = seed_proxy(&pool, "vless", "127.0.0.1", live_port, "unknown").await;
        let dying = seed_proxy(&pool, "vless", "127.0.0.1", dead_port, "unknown").await;

        // meow-rs is absent: T2 must be skipped without touching statuses.
        let config = test_config(
            2,
            "127.0.0.1:1",
            std::env::temp_dir().join("fumox-probe-test-meow.yaml"),
        );
        let ctx = Arc::new(Context::new(config, pool.clone()));

        // Cycle 1: live proxy becomes alive, dead one collects fail #1.
        run_cycle(ctx.clone()).await.unwrap();
        let row = proxies::get_by_id(&pool, live).await.unwrap().unwrap();
        assert_eq!(row.status, "alive");
        assert!(row.latency_ms.is_some());
        let row = proxies::get_by_id(&pool, dying).await.unwrap().unwrap();
        assert_eq!(row.status, "unknown");
        assert_eq!(row.fail_count, 1);

        // Cycle 2: fail limit reached → quarantine with a scheduled second
        // chance exactly 24h out (zero spread configured).
        run_cycle(ctx.clone()).await.unwrap();
        let row = proxies::get_by_id(&pool, dying).await.unwrap().unwrap();
        assert_eq!(row.status, "quarantine");
        assert_eq!(row.fail_count, 2);
        let quarantined_at = row.quarantined_at.unwrap();
        assert_eq!(row.second_chance_at, Some(quarantined_at + 86_400));

        // The live proxy stayed alive through both cycles, and every attempt
        // was journaled.
        let row = proxies::get_by_id(&pool, live).await.unwrap().unwrap();
        assert_eq!(row.status, "alive");
        let (ok_count,): (i64,) =
            sqlx::query_as("SELECT COUNT(*) FROM probe_results WHERE proxy_id = ? AND ok = 1")
                .bind(live)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert!(ok_count >= 2);
        let (fail_count,): (i64,) =
            sqlx::query_as("SELECT COUNT(*) FROM probe_results WHERE proxy_id = ? AND ok = 0")
                .bind(dying)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(fail_count, 2);
        let (kinds,): (String,) =
            sqlx::query_as("SELECT DISTINCT probe_kind FROM probe_results WHERE proxy_id = ?")
                .bind(live)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(kinds, "tcp");
    }

    #[tokio::test]
    async fn t2_cycle_distinguishes_bad_credential_from_live_proxy() {
        let pool = temp_pool().await;

        // Mock meow-rs: proxy 1 tunnels fine, proxy 2 fails with a
        // credential-style error.
        let app = Router::new()
            .route(
                "/version",
                get(|| async { Json(serde_json::json!({"version":"mock"})) }),
            )
            .route("/configs", put(|| async { Json(serde_json::json!({})) }))
            .route(
                "/proxies/{name}/delay",
                get(|Path(name): Path<String>| async move {
                    if name == "fumox-1" {
                        (
                            axum::http::StatusCode::OK,
                            Json(serde_json::json!({"delay": 42})),
                        )
                    } else {
                        (
                            axum::http::StatusCode::BAD_REQUEST,
                            Json(serde_json::json!({"message":"invalid credential"})),
                        )
                    }
                }),
            );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let meow_addr = listener.local_addr().unwrap().to_string();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        // Both proxies already passed T1 (alive); both point at a live
        // listener so the T1 pass of the cycle stays green and only T2
        // differentiates them.
        let tcp = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let tcp_port = tcp.local_addr().unwrap().port();
        tokio::spawn(async move {
            loop {
                let (mut socket, _) = match tcp.accept().await {
                    Ok(ok) => ok,
                    Err(_) => break,
                };
                tokio::spawn(async move {
                    use tokio::io::AsyncWriteExt;
                    let _ = socket.shutdown().await;
                });
            }
        });
        let good = seed_proxy(&pool, "vless", "127.0.0.1", tcp_port, "alive").await;
        assert_eq!(good, 1);
        let bad = seed_proxy(&pool, "vless", "127.0.0.1", tcp_port, "alive").await;
        assert_eq!(bad, 2);

        let config_path = std::env::temp_dir().join(format!(
            "fumox-probe-test-{}.yaml",
            fumox_core::models::new_id()
        ));
        let config = test_config(3, &meow_addr, config_path.clone());
        let ctx = Arc::new(Context::new(config, pool.clone()));

        run_cycle(ctx).await.unwrap();

        // The generated Clash config reached the disk with both proxies.
        let yaml = std::fs::read_to_string(&config_path).unwrap();
        assert!(yaml.contains("fumox-1"));
        assert!(yaml.contains("fumox-2"));

        // Good proxy: T2 confirmed it, latency from the tunnel test.
        let row = proxies::get_by_id(&pool, good).await.unwrap().unwrap();
        assert_eq!(row.status, "alive");
        assert_eq!(row.fail_count, 0);
        assert_eq!(row.latency_ms, Some(42));

        // Bad proxy: port is open (T1 green) but the tunnel failed —
        // exactly the case T2 exists for.
        let row = proxies::get_by_id(&pool, bad).await.unwrap().unwrap();
        assert_eq!(row.fail_count, 1);
        let (error,): (String,) = sqlx::query_as(
            "SELECT error FROM probe_results
             WHERE proxy_id = ? AND probe_kind = 't2' AND ok = 0
             ORDER BY checked_at DESC LIMIT 1",
        )
        .bind(bad)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert!(error.contains("invalid credential"));

        // meow_last_ok was stamped.
        let stamp = fumox_core::repo::meta_get(&pool, "meow_last_ok")
            .await
            .unwrap();
        assert!(stamp.is_some());
    }

    #[tokio::test]
    async fn quarantine_due_check_runs_after_second_chance_and_removes_after_ladder() {
        let pool = temp_pool().await;

        // Dead port: every recheck will fail.
        let dead = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let dead_port = dead.local_addr().unwrap().port();
        drop(dead);
        let id = seed_proxy(&pool, "vless", "127.0.0.1", dead_port, "quarantine").await;

        // Second chance already due (in the past).
        sqlx::query("UPDATE proxies SET quarantined_at = 100, second_chance_at = 200 WHERE id = ?")
            .bind(id)
            .execute(&pool)
            .await
            .unwrap();

        let config = test_config(
            2,
            "127.0.0.1:1",
            std::env::temp_dir().join("fumox-probe-test-meow.yaml"),
        );
        let ctx = Arc::new(Context::new(config, pool.clone()));

        // Each cycle advances one ladder step; the due moment is always in
        // the past, so consecutive cycles walk the whole ladder.
        run_cycle(ctx.clone()).await.unwrap();
        let row = proxies::get_by_id(&pool, id).await.unwrap().unwrap();
        assert_eq!(row.status, "quarantine");
        assert!(row.recheck_15m_at.is_some());
        sqlx::query("UPDATE proxies SET recheck_15m_at = 300 WHERE id = ?")
            .bind(id)
            .execute(&pool)
            .await
            .unwrap();

        run_cycle(ctx.clone()).await.unwrap();
        let row = proxies::get_by_id(&pool, id).await.unwrap().unwrap();
        assert!(row.recheck_30m_at.is_some());
        sqlx::query("UPDATE proxies SET recheck_30m_at = 400 WHERE id = ?")
            .bind(id)
            .execute(&pool)
            .await
            .unwrap();

        run_cycle(ctx.clone()).await.unwrap();
        let row = proxies::get_by_id(&pool, id).await.unwrap().unwrap();
        assert!(row.recheck_1h_at.is_some());
        sqlx::query("UPDATE proxies SET recheck_1h_at = 500 WHERE id = ?")
            .bind(id)
            .execute(&pool)
            .await
            .unwrap();

        run_cycle(ctx).await.unwrap();
        let row = proxies::get_by_id(&pool, id).await.unwrap().unwrap();
        assert_eq!(row.status, "removed");
        assert!(row.removed_at.is_some());
    }
}
