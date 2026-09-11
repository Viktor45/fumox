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
//!    The batch is recency-prioritized: proxies without a single T2
//!    attempt first, then the ones whose last T2 check is the oldest
//!    (owner decision 2026-09-06).
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

/// `probe_results.probe_kind` of the tunnel check (DATABASE.md).
const T2_KIND: &str = "t2";

#[derive(Parser)]
#[command(name = "fumox-probe", version, about = "Fumox health-check daemon")]
struct Cli {
    /// Path to the TOML config file (outranks FUMOX_CONFIG; the default
    /// location is config/app.toml if present).
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
        let backoff_initial =
            i64::try_from(config.meow.backoff_initial_secs.max(1)).unwrap_or(i64::MAX);
        Self {
            pool,
            config,
            meow,
            meow_retry_at: AtomicI64::new(0),
            meow_backoff_secs: AtomicI64::new(backoff_initial),
        }
    }

    /// Push the next T2 retry further into the future (capped exponential).
    fn backoff_meow(&self) {
        let backoff = self.meow_backoff_secs.load(Ordering::Relaxed);
        let max = i64::try_from(self.config.meow.backoff_max_secs).unwrap_or(i64::MAX);
        let next = backoff.saturating_mul(2).min(max);
        self.meow_backoff_secs.store(next, Ordering::Relaxed);
        self.meow_retry_at
            .store(now_ts().saturating_add(backoff), Ordering::Relaxed);
    }

    /// meow-rs answered — clear the backoff.
    fn meow_recovered(&self) {
        let initial =
            i64::try_from(self.config.meow.backoff_initial_secs.max(1)).unwrap_or(i64::MAX);
        self.meow_backoff_secs.store(initial, Ordering::Relaxed);
        self.meow_retry_at.store(0, Ordering::Relaxed);
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let config = AppConfig::load(cli.config.as_deref())?;
    fumox_core::logging::init_tracing(config.log.probe);

    // The loader cannot log (its own level comes from the config); report
    // the file actually used once tracing is up.
    match fumox_core::config::resolve_config_path(cli.config.as_deref()) {
        Ok(fumox_core::config::ResolvedConfigPath::Loaded(file)) => {
            tracing::info!(config = %file.display(), "config file loaded");
        }
        Ok(fumox_core::config::ResolvedConfigPath::Missing) => {
            tracing::info!(
                "no config file found (looked at {} or {}); using built-in defaults",
                fumox_core::config::CONFIG_PATH_ENV,
                fumox_core::DEFAULT_CONFIG_PATH
            );
        }
        Err(already_reported) => {
            // load() failed on the same resolution a moment ago — this
            // arm is unreachable, but a misreported startup is worse than
            // a redundant line.
            tracing::warn!(%already_reported, "config file resolution failed");
        }
    }
    let pool = fumox_core::db::connect_pool(&config.database).await?;
    fumox_core::db::migrate(&pool).await?;

    tracing::info!(
        cycle_secs = config.probe.cycle_interval_secs,
        sample_size = config.probe.sample_size,
        fail_limit = config.probe.fail_limit,
        concurrency = config.probe.concurrency,
        recheck_delays_secs = ?config.probe.recheck_delays_secs,
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
/// then the priority queue (fresh proxies, SPEC §8.3), then the T1 sample
/// and the T2 batch.
async fn run_cycle(ctx: Arc<Context>) -> anyhow::Result<()> {
    let now = now_ts();
    let quarantine = probe_due_quarantine(ctx.clone(), now).await?;
    let queued_checked = probe_queued_checks(ctx.clone()).await?;
    let t1_checked = probe_t1_sample(ctx.clone()).await?;
    let t2_checked = probe_t2_batch(ctx).await?;
    tracing::info!(
        quarantine_checked = quarantine,
        queued_checked,
        t1_checked,
        t2_checked,
        "probe cycle done"
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// T1: random connectivity sample
// ---------------------------------------------------------------------------

/// Priority lane (SPEC §8.3): T1 checks the server enqueued at source
/// refresh time for freshly inserted proxies. Drained newest first, capped
/// by the same per-cycle quota as the random sample. Requests are claimed
/// (deleted) up-front, so a mid-batch crash cannot turn them into an
/// endless retry loop; anything not yet covered falls back to the random
/// sample below.
async fn probe_queued_checks(ctx: Arc<Context>) -> anyhow::Result<usize> {
    let candidates =
        probe_repo::select_queued_checks(&ctx.pool, ctx.config.probe.sample_size).await?;
    if candidates.is_empty() {
        return Ok(0);
    }
    let ids: Vec<i64> = candidates.iter().map(|c| c.id).collect();
    probe_repo::claim_checks(&ctx.pool, &ids).await?;
    run_t1_checks(ctx, candidates).await
}

/// Probe a random sample of `unknown`/`alive` proxies (SPEC §8.3).
async fn probe_t1_sample(ctx: Arc<Context>) -> anyhow::Result<usize> {
    let candidates = proxies::select_t1_candidates(&ctx.pool, ctx.config.probe.sample_size).await?;
    if candidates.is_empty() {
        return Ok(0);
    }
    run_t1_checks(ctx, candidates).await
}

/// Run concurrent T1 checks for the candidates and apply each outcome to
/// the lifecycle.
async fn run_t1_checks(
    ctx: Arc<Context>,
    candidates: Vec<proxies::T1Candidate>,
) -> anyhow::Result<usize> {
    let semaphore = Arc::new(Semaphore::new(ctx.config.probe.concurrency.max(1)));
    let mut tasks = tokio::task::JoinSet::new();
    let mut blocked = 0usize;
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
        let vetted = match vet_target_addrs(&ctx, &candidate.host).await {
            Ok(addrs) => addrs,
            Err(reason) => {
                tracing::warn!(id = candidate.id, %reason, "probe target blocked by the private-address policy, journaled as a failed check");
                apply_vet_block(&ctx, candidate.id, kind.as_str(), &reason).await;
                blocked += 1;
                continue;
            }
        };
        let (ctx, semaphore) = (ctx.clone(), semaphore.clone());
        tasks.spawn(async move {
            // `acquire_owned` is infallible: the semaphore lives in this
            // scope and is only dropped after `collect_tasks` joins every
            // spawned task, so it cannot close while a task is awaiting a
            // permit. No `.expect` panic, no M2 risk (security audit,
            // 2026-09-10).
            let _permit = match semaphore.acquire_owned().await {
                Ok(permit) => permit,
                Err(_) => return,
            };
            let target = t1::Target {
                host: &candidate.host,
                port,
                kind,
                vetted: &vetted,
            };
            perform_t1_check(&ctx, candidate.id, &target).await;
        });
    }
    let done = collect_tasks(&mut tasks).await;
    Ok(done + blocked)
}

/// SSRF gate for every dial target (security audit v2, 2026-09-09, F1):
/// proxy hosts come from remote feeds, so each candidate must pass the
/// shared address policy before the daemon opens a connection to it —
/// loopback, RFC1918, link-local (cloud metadata), CGNAT and unique-local
/// addresses are refused unless `[probe].allow_private_targets` is set.
///
/// Async because the underlying DNS lookup is async — keeping the call
/// async end-to-end means the runtime worker is never blocked while the
/// OS resolver runs (security audit, 2026-09-10, L1).
async fn vet_target(ctx: &Context, host: &str) -> Result<(), String> {
    fumox_core::ssrf::vet_probe_host(host, ctx.config.probe.allow_private_targets).await
}

/// Same gate as [`vet_target`], returning the vetted addresses: T1 dials
/// those exact IPs instead of re-resolving the hostname, so a rebinding
/// DNS answer cannot steer the connect elsewhere between vet and dial.
async fn vet_target_addrs(ctx: &Context, host: &str) -> Result<Vec<std::net::IpAddr>, String> {
    fumox_core::ssrf::vet_probe_host_addrs(host, ctx.config.probe.allow_private_targets).await
}

/// A vet-refused target is a *failed check*, not a skip (owner decision,
/// 2026-09-10): the policy blocks exactly what a dead proxy looks like —
/// unresolvable names and internal addresses — so the attempt is journaled
/// into `probe_results` with the refusal reason and the fail ladder runs.
/// Silently skipping these let blocked rows clog the head of the T2
/// recency queue forever (they never got a t2 row to advance past).
/// The journal write is best-effort, as everywhere else: the lifecycle
/// transition is the source of truth.
async fn apply_vet_block(ctx: &Context, id: i64, probe_kind: &str, reason: &str) {
    let error = format!("blocked by the private-address policy: {reason}");
    journal(
        ctx,
        ProbeResultEntry {
            proxy_id: id,
            checked_at: now_ts(),
            ok: false,
            latency_ms: None,
            error: Some(&error),
            probe_kind,
        },
    )
    .await;
    apply_regular_failure(ctx, id, now_ts()).await;
}

/// Run one T1 check and apply the outcome to the lifecycle: journal the
/// attempt into `probe_results`, then move the state machine. `vetted`
/// carries the SSRF-approved dial addresses (see [`vet_target_addrs`]).
async fn perform_t1_check(ctx: &Context, id: i64, target: &t1::Target<'_>) {
    let connect_timeout = Duration::from_secs(ctx.config.probe.connect_timeout_secs.max(1));
    let tls_timeout = Duration::from_secs(ctx.config.probe.tls_timeout_secs.max(1));
    let outcome = t1::run(target, connect_timeout, tls_timeout).await;
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
                    probe_kind: target.kind.as_str(),
                },
            )
            .await;
            // Strict T2 priority (owner decision 2026-08-29, SPEC §8.3): a
            // T1 success must not wipe the fail counter accumulated from T2
            // tunnel failures — the counter clears only via a T2 success or
            // the quarantine ladder. Conservative on lookup errors: keep it.
            let reset = match probe_repo::last_failed_kind(&ctx.pool, id).await {
                Ok(kind) => kind.as_deref() != Some(T2_KIND),
                Err(error) => {
                    tracing::warn!(id, %error, "last-failure lookup failed; keeping fail counter");
                    false
                }
            };
            if let Err(error) = proxies::check_succeeded(
                &ctx.pool,
                id,
                now,
                Some(latency),
                reset,
                // A T1 success targets the plain tier; a `ready` row keeps
                // its verification (only a failed T2 demotes it).
                fumox_core::models::ProxyStatus::Alive,
            )
            .await
            {
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
                    probe_kind: target.kind.as_str(),
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
    let min_secs =
        i64::try_from(probe.second_chance_min_hours.saturating_mul(3600)).unwrap_or(i64::MAX);
    let spread_secs =
        i64::try_from(probe.second_chance_spread_hours.saturating_mul(3600)).unwrap_or(0);
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
    let mut blocked = 0usize;
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
        let kind = t1::check_kind(scheme, row.params.as_deref());
        let vetted = match vet_target_addrs(&ctx, &row.host).await {
            Ok(addrs) => addrs,
            Err(reason) => {
                tracing::warn!(id = row.id, %reason, "quarantine target blocked by the private-address policy, journaled as a failed recheck");
                apply_quarantine_vet_block(
                    &ctx,
                    row.id,
                    t1::check_kind(scheme, row.params.as_deref()).as_str(),
                    row.ladder_step,
                    &reason,
                )
                .await;
                blocked += 1;
                continue;
            }
        };
        let step = row.ladder_step;
        let delays = ctx.config.probe.recheck_delays_secs.clone();
        let (ctx, semaphore) = (ctx.clone(), semaphore.clone());
        tasks.spawn(async move {
            // The semaphore lives in this scope until `collect_tasks`
            // returns; a closed semaphore here is structurally impossible
            // (security audit, 2026-09-10, M2).
            let _permit = match semaphore.acquire_owned().await {
                Ok(permit) => permit,
                Err(_) => return,
            };
            let target = t1::Target {
                host: &row.host,
                port,
                kind,
                vetted: &vetted,
            };
            perform_quarantine_check(&ctx, row.id, &target, step, &delays).await;
        });
    }
    let done = collect_tasks(&mut tasks).await;
    Ok(done + blocked)
}

/// The quarantine-ladder counterpart of [`apply_vet_block`]: a vet-refused
/// recheck is a failed recheck (owner decision, 2026-09-10) — journaled
/// with the refusal reason, the ladder advances (or the proxy is removed
/// after the last configured step).
async fn apply_quarantine_vet_block(
    ctx: &Context,
    id: i64,
    probe_kind: &str,
    step: i64,
    reason: &str,
) {
    let error = format!("blocked by the private-address policy: {reason}");
    journal(
        ctx,
        ProbeResultEntry {
            proxy_id: id,
            checked_at: now_ts(),
            ok: false,
            latency_ms: None,
            error: Some(&error),
            probe_kind,
        },
    )
    .await;
    let delays = ctx.config.probe.recheck_delays_secs.clone();
    match proxies::quarantine_check_failed(&ctx.pool, id, now_ts(), step, &delays).await {
        Ok(proxies::Transition::Removed) => {
            tracing::info!(id, "proxy removed after the final failed recheck")
        }
        Ok(_) => tracing::debug!(id, step, "quarantine recheck failed, ladder advanced"),
        Err(error) => tracing::warn!(id, %error, "failed to advance quarantine ladder"),
    }
}

/// One quarantine re-check: success revives the proxy with a clean slate;
/// failure advances the configured ladder or removes the proxy after the
/// last configured recheck failed (SPEC §8.3a steps 3–5). `vetted` carries
/// the SSRF-approved dial addresses (see [`vet_target_addrs`]).
async fn perform_quarantine_check(
    ctx: &Context,
    id: i64,
    target: &t1::Target<'_>,
    step: i64,
    delays: &[i64],
) {
    let connect_timeout = Duration::from_secs(ctx.config.probe.connect_timeout_secs.max(1));
    let tls_timeout = Duration::from_secs(ctx.config.probe.tls_timeout_secs.max(1));
    let outcome = t1::run(target, connect_timeout, tls_timeout).await;
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
                    probe_kind: target.kind.as_str(),
                },
            )
            .await;
            // The revival check is T1 (TCP/TLS), so the proxy returns to the
            // plain `alive` tier; the next successful T2 promotes it to
            // `ready` (owner decision, 2026-09-10).
            let revived = proxies::check_succeeded(
                &ctx.pool,
                id,
                now,
                Some(latency),
                true,
                fumox_core::models::ProxyStatus::Alive,
            )
            .await;
            match revived {
                Ok(_) => tracing::info!(id, step, "quarantined proxy revived"),
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
                    probe_kind: target.kind.as_str(),
                },
            )
            .await;
            match proxies::quarantine_check_failed(&ctx.pool, id, now, step, delays).await {
                Ok(proxies::Transition::Removed) => {
                    tracing::info!(id, "proxy removed after the final failed recheck")
                }
                Ok(_) => tracing::debug!(id, step, "quarantine recheck failed, ladder advanced"),
                Err(error) => tracing::warn!(id, %error, "failed to advance quarantine ladder"),
            }
        }
    }
}

// ---------------------------------------------------------------------------
// T2: real tunnel checks through meow-rs (SPEC §8.2)
// ---------------------------------------------------------------------------

/// Generate a Clash batch, reload meow-rs, and delay-test every proxy
/// through a real tunnel.
///
/// Success is strict (owner decision, 2026-09-10): only a tunnel that came
/// up *and* answered with a measured `delay` counts — anything else the
/// engine reports is a failure. A meow-rs outage is likewise a *failed*
/// check for every proxy that was due one (journaled as
/// `probe_kind='t2'`, fail ladder runs): a silent skip left the head of
/// the recency queue pinned for as long as the engine was down, and an
/// operator could not tell an outage from an empty pool. The cycle still
/// backs off so a dead meow-rs is not hammered every minute.
async fn probe_t2_batch(ctx: Arc<Context>) -> anyhow::Result<usize> {
    let now = now_ts();
    if now < ctx.meow_retry_at.load(Ordering::Relaxed) {
        tracing::debug!("meow-rs in backoff, T2 skipped");
        return Ok(0);
    }

    let rows = proxies::select_t2_candidates(&ctx.pool, ctx.config.probe.sample_size).await?;
    // Vet every candidate before anything touches meow-rs. A refused target
    // is a *failed* t2 check (owner decision, 2026-09-10), not a skip: the
    // policy blocks unresolvable names and internal addresses, and a skip
    // left such rows at the head of the recency queue forever (they never
    // got a t2 row, so the selector re-served them every cycle).
    let mut batch: Vec<_> = Vec::with_capacity(rows.len());
    let fail_limit = ctx.config.probe.fail_limit;
    let min_secs = i64::try_from(
        ctx.config
            .probe
            .second_chance_min_hours
            .saturating_mul(3600),
    )
    .unwrap_or(i64::MAX);
    let spread_secs = i64::try_from(
        ctx.config
            .probe
            .second_chance_spread_hours
            .saturating_mul(3600),
    )
    .unwrap_or(0);
    let mut blocked = 0usize;
    for row in rows {
        let scheme = row.scheme.parse::<Scheme>().ok();
        if !scheme.is_some_and(clash::is_supported) {
            continue;
        }
        match vet_target(&ctx, &row.host).await {
            Ok(()) => batch.push(row),
            Err(reason) => {
                tracing::warn!(id = row.id, %reason, "T2 target blocked by the private-address policy, journaled as a failed check");
                blocked += 1;
                journal_and_fail(
                    &ctx,
                    row.id,
                    &format!("blocked by the private-address policy: {reason}"),
                )
                .await;
            }
        }
    }
    if batch.is_empty() {
        tracing::info!(blocked, "T2 batch empty after vetting");
        return Ok(blocked);
    }

    // Cheap liveness check first: no point rewriting the config file when
    // the service is down anyway. An outage here fails the whole batch on
    // the ladder (owner decision, 2026-09-10) and backs off.
    if let Err(error) = ctx.meow.ping().await {
        tracing::warn!(%error, "meow-rs unavailable, T2 batch failed with backoff");
        ctx.backoff_meow();
        journal_engine_failure(&ctx, &batch, &format!("meow-rs unavailable: {error}")).await;
        return Ok(batch.len() + blocked);
    }

    let (yaml, included) = clash::generate(&batch)?;
    let config_path = &ctx.config.meow.config_path;
    if let Some(parent) = config_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    // The YAML carries every proxy credential of the batch in plain text —
    // same exposure as the SQLite database, same 0600 answer (the DB chmod
    // rationale lives in fumox-core/src/db.rs). The mode is set at creation
    // time so the file is never briefly world-readable.
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(config_path)?;
        file.write_all(yaml.as_bytes())?;
    }
    #[cfg(not(unix))]
    std::fs::write(config_path, yaml)?;

    if let Err(error) = ctx.meow.reload_config(config_path).await {
        tracing::warn!(%error, "meow-rs unavailable, T2 batch failed with backoff");
        ctx.backoff_meow();
        journal_engine_failure(&ctx, &batch, &format!("meow-rs unavailable: {error}")).await;
        return Ok(batch.len() + blocked);
    }
    ctx.meow_recovered();
    if let Err(error) = meta_set(&ctx.pool, "meow_last_ok", &now_ts().to_string()).await {
        tracing::warn!(%error, "failed to stamp meow_last_ok");
    }

    let semaphore = Arc::new(Semaphore::new(ctx.config.probe.concurrency.max(1)));
    // Set by the first task to see the engine fail mid-batch: every proxy
    // still due a check in this batch then gets an aborted-failure record
    // without hammering a dying meow-rs with further requests.
    let aborted = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let mut tasks = tokio::task::JoinSet::new();
    for row in batch {
        // Rows that never made it into the generated config (their entry
        // could not be serialized, `clash::generate` skipped them) must get
        // the real reason journaled — routing them through the engine would
        // produce a misleading "proxy not found" failure.
        if !included.contains(&row.id) {
            journal_and_fail(
                &ctx,
                row.id,
                "proxy entry cannot be serialized for the T2 engine config",
            )
            .await;
            continue;
        }
        let (ctx, semaphore) = (ctx.clone(), semaphore.clone());
        let aborted = aborted.clone();
        tasks.spawn(async move {
            // The semaphore lives in this scope until `collect_tasks`
            // returns; a closed semaphore here is structurally impossible
            // (security audit, 2026-09-10, M2).
            let _permit = match semaphore.acquire_owned().await {
                Ok(permit) => permit,
                Err(_) => return,
            };
            if aborted.load(std::sync::atomic::Ordering::Relaxed) {
                journal_and_fail(
                    &ctx,
                    row.id,
                    "aborted: meow-rs became unavailable mid-batch",
                )
                .await;
                return;
            }
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
                            probe_kind: T2_KIND,
                        },
                    )
                    .await;
                    // A successful T2 is the tunnel-verified tier (owner
                    // decision, 2026-09-10): the proxy becomes `ready`.
                    if let Err(error) = proxies::check_succeeded(
                        &ctx.pool,
                        row.id,
                        now,
                        Some(latency),
                        true,
                        fumox_core::models::ProxyStatus::Ready,
                    )
                    .await
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
                            probe_kind: T2_KIND,
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
                    // The engine failed mid-batch: from this moment the
                    // whole batch is failed on the ladder (owner decision,
                    // 2026-09-10) — this record included — and the rest of
                    // the tasks journal an aborted-failure without calling
                    // meow-rs again. Back off regardless of which task saw
                    // it first (idempotent).
                    tracing::warn!(%error, "meow-rs became unavailable mid-batch, failing the rest of the T2 batch");
                    aborted.store(true, std::sync::atomic::Ordering::Relaxed);
                    ctx.backoff_meow();
                    journal_and_fail(
                        &ctx,
                        row.id,
                        &format!("meow-rs unavailable mid-batch: {error}"),
                    )
                    .await;
                }
            }
        });
    }
    let done = collect_tasks(&mut tasks).await;
    Ok(done + blocked)
}

/// Journal one failed T2 attempt and run the fail ladder (owner decision,
/// 2026-09-10): a proxy that could not get its tunnel check — whether the
/// tunnel itself failed, the target was vet-refused, or meow-rs was down —
/// receives a `probe_kind='t2'` failure record, which is also what moves
/// it forward in the recency queue.
async fn journal_and_fail(ctx: &Context, id: i64, reason: &str) {
    let now = now_ts();
    journal(
        ctx,
        ProbeResultEntry {
            proxy_id: id,
            checked_at: now,
            ok: false,
            latency_ms: None,
            error: Some(reason),
            probe_kind: T2_KIND,
        },
    )
    .await;
    let probe = &ctx.config.probe;
    let min_secs =
        i64::try_from(probe.second_chance_min_hours.saturating_mul(3600)).unwrap_or(i64::MAX);
    let spread_secs =
        i64::try_from(probe.second_chance_spread_hours.saturating_mul(3600)).unwrap_or(0);
    if let Err(error) =
        proxies::check_failed(&ctx.pool, id, now, probe.fail_limit, min_secs, spread_secs).await
    {
        tracing::warn!(id, %error, "failed to record T2 failure");
    }
}

/// Fail every proxy of a batch on the ladder with the same engine-outage
/// reason (owner decision, 2026-09-10): a meow-rs outage at ping/reload
/// time means every due proxy went unverified this cycle — an unrecorded
/// skip is indistinguishable from an empty pool and pins the head of the
/// recency queue for the whole outage.
async fn journal_engine_failure(ctx: &Context, batch: &[proxies::ProxyRow], reason: &str) {
    for row in batch {
        journal_and_fail(ctx, row.id, reason).await;
    }
    tracing::warn!(proxies = batch.len(), "T2 batch failed by engine outage");
}

// ---------------------------------------------------------------------------
// Background maintenance
// ---------------------------------------------------------------------------

/// Cutoff timestamp for a retention window of `days`. A zero window would
/// wipe the whole history on every cycle, so it is clamped to one day
/// (security audit, 2026-08-30).
fn retention_cutoff(now: i64, days: u32) -> i64 {
    now - i64::from(days.max(1)) * 86_400
}

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
    let probe_cutoff = retention_cutoff(now, ctx.config.retention.probe_results_days);
    let fetch_cutoff = retention_cutoff(now, ctx.config.retention.fetch_log_days);

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
    // Priority queue housekeeping (SPEC §8.3): requests whose proxy already
    // left `unknown`, and stale leftovers from an offline probe.
    match probe_repo::purge_settled_checks(&ctx.pool).await {
        Ok(0) => {}
        Ok(deleted) => tracing::debug!(deleted, "dropped settled probe_requests"),
        Err(error) => tracing::warn!(%error, "probe_requests cleanup failed"),
    }
    let stale_days = ctx.config.probe.queue_stale_days.max(1) as i64;
    let queue_cutoff = now - stale_days * 86_400;
    match probe_repo::purge_requests_before(&ctx.pool, queue_cutoff).await {
        Ok(0) => {}
        Ok(deleted) => tracing::info!(deleted, "rotated stale probe_requests"),
        Err(error) => tracing::warn!(%error, "probe_requests rotation failed"),
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

    #[test]
    fn zero_retention_window_is_clamped_to_one_day() {
        assert_eq!(retention_cutoff(100_000, 0), 100_000 - 86_400);
        assert_eq!(retention_cutoff(100_000, 7), 100_000 - 7 * 86_400);
    }

    /// F1 (security audit v2, 2026-09-09) + owner decision 2026-09-10: with
    /// the default policy the daemon must refuse to *dial* loopback feed
    /// targets — but the refusal itself is now a journaled failed check
    /// (the fail ladder runs), so a blocked proxy cannot clog the queues
    /// forever. A live loopback listener stays untouched, and the blocked
    /// proxy collects a failure record instead of silence.
    #[tokio::test]
    async fn private_targets_are_not_dialed_by_default() {
        let pool = temp_pool().await;

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let live_port = listener.local_addr().unwrap().port();
        let hit = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let hit_clone = hit.clone();
        tokio::spawn(async move {
            loop {
                let (socket, _) = match listener.accept().await {
                    Ok(ok) => ok,
                    Err(_) => break,
                };
                hit_clone.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                drop(socket);
            }
        });
        let id = seed_proxy(&pool, "vless", "127.0.0.1", live_port, "unknown").await;

        // Default config: allow_private_targets = false; fail_limit = 1, so
        // a single vet refusal must quarantine the proxy right away.
        let mut config = test_config(
            1,
            "127.0.0.1:1",
            std::env::temp_dir().join("fumox-probe-test-meow.yaml"),
        );
        config.probe.allow_private_targets = false;
        let ctx = Arc::new(Context::new(config, pool.clone()));

        run_cycle(ctx).await.unwrap();

        // The listener saw no connection.
        assert_eq!(hit.load(std::sync::atomic::Ordering::Relaxed), 0);
        // The refusal is journaled as a failed check...
        let (attempts, error, kind): (i64, String, String) = sqlx::query_as(
            "SELECT COUNT(*), COALESCE(MAX(error), ''), COALESCE(MAX(probe_kind), '')
             FROM probe_results WHERE proxy_id = ? AND ok = 0",
        )
        .bind(id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(attempts, 1, "the vet refusal must be journaled");
        assert!(
            error.contains("blocked by the private-address policy"),
            "{error}"
        );
        assert_eq!(kind, "tcp");
        // ...and the fail ladder ran: fail_limit reached → quarantine.
        let row = proxies::get_by_id(&pool, id).await.unwrap().unwrap();
        assert_eq!(row.status, "quarantine");
        assert_eq!(row.fail_count, 1);
        assert!(row.ladder_at.is_some());
    }

    /// The T2 counterpart (owner decision, 2026-09-10): a vet-refused T2
    /// candidate is journaled as a failed `t2` check even when meow-rs is
    /// completely down — the journal row is what un-sticks the head of the
    /// recency queue (the selector orders by the last t2 attempt).
    #[tokio::test]
    async fn t2_vet_block_is_journaled_even_without_meow() {
        let pool = temp_pool().await;

        // A private host that would never pass the gate; the proxy is
        // `alive`, and the T1 pass blocks it too (same policy, same host)
        // — so the cycle must journal both a failed tcp and a failed t2
        // attempt. A high fail_limit keeps the row out of quarantine so
        // both lanes get to record their refusal.
        let id = seed_proxy(&pool, "vless", "127.0.0.1", 1, "alive").await;

        // meow-rs is unreachable on a closed port.
        let mut config = test_config(
            3,
            "127.0.0.1:1",
            std::env::temp_dir().join("fumox-probe-test-meow.yaml"),
        );
        config.probe.allow_private_targets = false;
        let ctx = Arc::new(Context::new(config, pool.clone()));

        run_cycle(ctx).await.unwrap();

        // The failed t2 row exists — exactly what keeps the recency
        // selector moving past blocked rows.
        let (t2_rows, error): (i64, String) = sqlx::query_as(
            "SELECT COUNT(*), COALESCE(MAX(error), '') FROM probe_results
             WHERE proxy_id = ? AND ok = 0 AND probe_kind = 't2'",
        )
        .bind(id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(t2_rows, 1, "the T2 refusal must be journaled as t2");
        assert!(
            error.contains("blocked by the private-address policy"),
            "{error}"
        );
        // The T1 lane recorded its own refusal as well, and the fail
        // counter saw both.
        let row = proxies::get_by_id(&pool, id).await.unwrap().unwrap();
        assert_eq!(row.status, "alive");
        assert_eq!(row.fail_count, 2);
    }

    /// Owner decision 2026-09-10, engine-failure branch 1: meow answers
    /// /version but rejects the config reload — every proxy of the batch
    /// gets a journaled failed t2 check (outage reason, fail ladder) and
    /// the recency queue head cannot pin during the outage.
    #[tokio::test]
    async fn t2_engine_failure_at_reload_fails_the_batch() {
        let pool = temp_pool().await;

        // Mock meow-rs: /version alive, /configs broken.
        let app = Router::new()
            .route(
                "/version",
                get(|| async { Json(serde_json::json!({"version":"mock"})) }),
            )
            .route(
                "/configs",
                put(|| async {
                    (
                        axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                        Json(serde_json::json!({"message":"reload failed"})),
                    )
                }),
            );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let meow_addr = listener.local_addr().unwrap().to_string();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        // Two due proxies: both must receive the outage failure.
        let a = seed_proxy(&pool, "vless", "127.0.0.1", 443, "alive").await;
        let b = seed_proxy(&pool, "trojan", "127.0.0.1", 443, "alive").await;
        let config_path = std::env::temp_dir().join(format!(
            "fumox-probe-test-{}.yaml",
            fumox_core::models::new_id()
        ));
        let mut config = test_config(3, &meow_addr, config_path.clone());
        config.probe.allow_private_targets = true;
        let ctx = Arc::new(Context::new(config, pool.clone()));

        run_cycle(ctx.clone()).await.unwrap();

        for id in [a, b] {
            let (kind, error): (String, String) = sqlx::query_as(
                "SELECT probe_kind, COALESCE(error, '') FROM probe_results
                 WHERE proxy_id = ? AND ok = 0 ORDER BY id DESC LIMIT 1",
            )
            .bind(id)
            .fetch_one(&pool)
            .await
            .unwrap();
            assert_eq!(kind, "t2", "the reload outage must be journaled as t2");
            assert!(error.contains("meow-rs unavailable"), "id {id}: {error}");
            let row = proxies::get_by_id(&pool, id).await.unwrap().unwrap();
            // Both lanes failed: the T1 dial (nothing listens on 443) and
            // the journaled engine outage — fail_count counts both.
            assert_eq!(row.fail_count, 2);
        }

        // The meow backoff is armed: a second immediate cycle sleeps
        // silently instead of re-failing the pool (checked against the
        // same ctx, whose retry gate now points into the future).
        assert!(
            fumox_core::models::now_ts()
                < ctx.meow_retry_at.load(std::sync::atomic::Ordering::Relaxed),
            "the reload outage must arm the meow backoff"
        );
    }

    /// Owner decision 2026-09-10, engine-failure branch 2: meow dies
    /// mid-batch — the first delay request sees the failure, the rest of
    /// the batch gets aborted-failure records without further meow calls.
    #[tokio::test]
    async fn t2_engine_failure_mid_batch_aborts_the_rest() {
        let pool = temp_pool().await;

        // Mock meow-rs: healthy /version and /configs, but every delay
        // request answers 500 (the engine is broken for real checks).
        let app = Router::new()
            .route(
                "/version",
                get(|| async { Json(serde_json::json!({"version":"mock"})) }),
            )
            .route("/configs", put(|| async { Json(serde_json::json!({})) }))
            .route(
                "/proxies/{name}/delay",
                get(|| async {
                    (
                        axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                        Json(serde_json::json!({"message":"engine exploded"})),
                    )
                }),
            );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let meow_addr = listener.local_addr().unwrap().to_string();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let a = seed_proxy(&pool, "vless", "127.0.0.1", 443, "alive").await;
        let b = seed_proxy(&pool, "trojan", "127.0.0.1", 443, "alive").await;
        let config_path = std::env::temp_dir().join(format!(
            "fumox-probe-test-{}.yaml",
            fumox_core::models::new_id()
        ));
        let mut config = test_config(3, &meow_addr, config_path);
        config.probe.allow_private_targets = true;
        let ctx = Arc::new(Context::new(config, pool.clone()));

        run_cycle(ctx).await.unwrap();

        // Every proxy of the batch carries a journaled t2 failure: one
        // with the mid-batch reason, the other with the aborted marker —
        // both are engine-outage texts, not proxy-dead texts.
        let mut aborted = 0;
        let mut mid_batch = 0;
        for id in [a, b] {
            let (error,): (String,) = sqlx::query_as(
                "SELECT COALESCE(error, '') FROM probe_results
                 WHERE proxy_id = ? AND ok = 0 AND probe_kind = 't2'",
            )
            .bind(id)
            .fetch_one(&pool)
            .await
            .unwrap();
            assert!(
                error.contains("meow-rs unavailable mid-batch")
                    || error.contains("aborted: meow-rs became unavailable"),
                "id {id}: {error}"
            );
            if error.starts_with("aborted:") {
                aborted += 1;
            } else {
                mid_batch += 1;
            }
            let row = proxies::get_by_id(&pool, id).await.unwrap().unwrap();
            // Both lanes failed: the T1 dial (nothing listens on 443) and
            // the engine failure — fail_count counts both.
            assert_eq!(row.fail_count, 2);
        }
        // With concurrency 4 both requests may race past the aborted flag;
        // the invariant is only that every proxy got a failure record.
        assert_eq!(aborted + mid_batch, 2);
    }

    /// The `ready` tier is demoted by every failed T2 outcome (owner
    /// decision, 2026-09-10) — here, by the meow outage itself: the proxy
    /// was due a tunnel check, the engine was down, so the verification
    /// no longer holds.
    #[tokio::test]
    async fn ready_is_demoted_by_engine_outage() {
        let pool = temp_pool().await;

        let id = seed_proxy(&pool, "vless", "127.0.0.1", 443, "ready").await;

        // No meow-rs at all: the ping fails and the batch (this proxy)
        // gets journaled engine failures.
        let mut config = test_config(
            3,
            "127.0.0.1:1",
            std::env::temp_dir().join("fumox-probe-test-meow.yaml"),
        );
        config.probe.allow_private_targets = true;
        let ctx = Arc::new(Context::new(config, pool.clone()));

        run_cycle(ctx).await.unwrap();

        let row = proxies::get_by_id(&pool, id).await.unwrap().unwrap();
        assert_eq!(
            row.status, "alive",
            "an unverified-by-outage proxy loses the ready tier"
        );
        let (error,): (String,) = sqlx::query_as(
            "SELECT COALESCE(error, '') FROM probe_results
             WHERE proxy_id = ? AND probe_kind = 't2' AND ok = 0",
        )
        .bind(id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert!(error.contains("meow-rs unavailable"), "{error}");
    }

    /// A vet-refused T2 target loses the ready tier as well: the check it
    /// was due could not run, and (as everywhere) the refusal is a failed
    /// check on the ladder.
    #[tokio::test]
    async fn ready_is_demoted_by_vet_block() {
        let pool = temp_pool().await;

        let id = seed_proxy(&pool, "vless", "127.0.0.1", 1, "ready").await;

        let mut config = test_config(
            3,
            "127.0.0.1:1",
            std::env::temp_dir().join("fumox-probe-test-meow.yaml"),
        );
        config.probe.allow_private_targets = false;
        let ctx = Arc::new(Context::new(config, pool.clone()));

        run_cycle(ctx).await.unwrap();

        let row = proxies::get_by_id(&pool, id).await.unwrap().unwrap();
        assert_eq!(
            row.status, "alive",
            "the vet refusal demotes the ready tier"
        );
        let (kind, error): (String, String) = sqlx::query_as(
            "SELECT probe_kind, COALESCE(error, '') FROM probe_results
             WHERE proxy_id = ? AND probe_kind = 't2' AND ok = 0",
        )
        .bind(id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(kind, "t2");
        assert!(
            error.contains("blocked by the private-address policy"),
            "{error}"
        );
    }

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
                // The tests dial loopback listeners, which the default policy
                // refuses (security audit v2, F1).
                allow_private_targets: true,
                connect_timeout_secs: 2,
                tls_timeout_secs: 2,
                concurrency: 4,
                heartbeat_interval_secs: 30,
                // Deterministic second chance: exactly +24h, no jitter.
                second_chance_min_hours: 24,
                second_chance_spread_hours: 0,
                // Default ladder: +15m, +30m, +1h.
                recheck_delays_secs: vec![900, 1800, 3600],
                queue_stale_days: 7,
                retention_interval_secs: 86400,
            },
            meow: fumox_core::config::MeowConfig {
                api_addr: meow_addr.into(),
                config_path: meow_config,
                test_url: vec!["http://cp.cloudflare.com".to_string()],
                timeout_secs: 3,
                backoff_initial_secs: 60,
                backoff_max_secs: 900,
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

        // meow-rs is absent: its T2 lane fails the due proxies on the
        // ladder (owner decision, 2026-09-10) — the live proxy collects
        // one engine-outage failure per cycle, not a silent skip.
        let config = test_config(
            2,
            "127.0.0.1:1",
            std::env::temp_dir().join("fumox-probe-test-meow.yaml"),
        );
        let ctx = Arc::new(Context::new(config, pool.clone()));

        // Cycle 1: live proxy becomes alive (T1), dead one collects fail #1
        // (T1); after promotion the live one enters the T2 batch, where the
        // engine outage records its own failure (fail_limit=2 not reached).
        run_cycle(ctx.clone()).await.unwrap();
        let row = proxies::get_by_id(&pool, live).await.unwrap().unwrap();
        assert_eq!(row.status, "alive");
        assert!(row.latency_ms.is_some());
        assert_eq!(row.fail_count, 1, "the meow outage must fail the T2 lane");
        let row = proxies::get_by_id(&pool, dying).await.unwrap().unwrap();
        assert_eq!(row.status, "unknown");
        assert_eq!(row.fail_count, 1);
        // The engine failure is journaled with the outage reason.
        let (error,): (String,) = sqlx::query_as(
            "SELECT COALESCE(error, '') FROM probe_results
             WHERE proxy_id = ? AND probe_kind = 't2' AND ok = 0",
        )
        .bind(live)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert!(error.contains("meow-rs unavailable"), "{error}");

        // Cycle 2: fail limit reached → quarantine with a scheduled second
        // chance exactly 24h out (zero spread configured).
        run_cycle(ctx.clone()).await.unwrap();
        let row = proxies::get_by_id(&pool, dying).await.unwrap().unwrap();
        assert_eq!(row.status, "quarantine");
        assert_eq!(row.fail_count, 2);
        let quarantined_at = row.quarantined_at.unwrap();
        assert_eq!(row.ladder_at, Some(quarantined_at + 86_400));
        assert_eq!(row.ladder_step, 0);

        // The live proxy stayed alive: cycle 2 hit the meow backoff window
        // (60s after the cycle-1 outage), so T2 slept silently — the
        // outage is journaled once per backoff window, not every cycle.
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
        let (kinds,): (i64,) = sqlx::query_as(
            "SELECT COUNT(DISTINCT probe_kind) FROM probe_results WHERE proxy_id = ? AND ok = 1",
        )
        .bind(live)
        .fetch_one(&pool)
        .await
        .unwrap();
        // Only the T1 lane succeeded (the T2 attempts ended in the
        // journaled engine outage).
        assert_eq!(kinds, 1);
        let (t1_kind,): (String,) = sqlx::query_as(
            "SELECT DISTINCT probe_kind FROM probe_results WHERE proxy_id = ? AND ok = 1",
        )
        .bind(live)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(t1_kind, "tcp");
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

        // Good proxy: T2 confirmed the tunnel — it reaches the
        // tunnel-verified `ready` tier (owner decision, 2026-09-10),
        // latency from the tunnel test.
        let row = proxies::get_by_id(&pool, good).await.unwrap().unwrap();
        assert_eq!(row.status, "ready");
        assert_eq!(row.fail_count, 0);
        assert_eq!(row.latency_ms, Some(42));

        // Bad proxy: port is open (T1 green) but the tunnel failed —
        // exactly the case T2 exists for. It stays in the plain tier with
        // the fail counted.
        let row = proxies::get_by_id(&pool, bad).await.unwrap().unwrap();
        assert_eq!(row.status, "alive");
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

    /// Strict T2 priority (owner decision 2026-08-29): a tunnel-dead proxy
    /// that keeps passing T1 must still reach quarantine — the T1 success of
    /// every cycle must not wipe the fail counter accumulated by T2.
    #[tokio::test]
    async fn t1_success_cannot_rescue_proxies_failing_t2() {
        let pool = temp_pool().await;

        // meow-rs mock: EVERY delay check fails with a credential error.
        let app = Router::new()
            .route(
                "/version",
                get(|| async { Json(serde_json::json!({"version":"mock"})) }),
            )
            .route("/configs", put(|| async { Json(serde_json::json!({})) }))
            .route(
                "/proxies/{name}/delay",
                get(|| async {
                    (
                        axum::http::StatusCode::BAD_REQUEST,
                        Json(serde_json::json!({"message":"invalid credential"})),
                    )
                }),
            );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let meow_addr = listener.local_addr().unwrap().to_string();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        // The proxy passes T1 (open port) but fails T2 every cycle.
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
        let bad = seed_proxy(&pool, "vless", "127.0.0.1", tcp_port, "alive").await;

        let config_path = std::env::temp_dir().join(format!(
            "fumox-probe-test-{}.yaml",
            fumox_core::models::new_id()
        ));
        let config = test_config(3, &meow_addr, config_path.clone());
        let ctx = Arc::new(Context::new(config, pool.clone()));

        // Cycle 1: T1 success (no failures yet — counter resets), T2 fail → 1.
        // Cycle 2: T1 success must NOT touch the T2 counter, T2 fail → 2.
        for cycle in 1..=2i64 {
            run_cycle(ctx.clone()).await.unwrap();
            let row = proxies::get_by_id(&pool, bad).await.unwrap().unwrap();
            assert_eq!(row.status, "alive");
            assert_eq!(row.fail_count, cycle);
        }

        // Cycle 3: the third T2 failure reaches the limit → quarantine.
        run_cycle(ctx.clone()).await.unwrap();
        let row = proxies::get_by_id(&pool, bad).await.unwrap().unwrap();
        assert_eq!(row.status, "quarantine");
        assert_eq!(row.fail_count, 3);
        assert!(row.ladder_at.is_some());

        // Quarantined rows are sampled by nothing (T1 takes unknown/alive,
        // T2 takes alive; the second chance is ~24h out): further cycles
        // leave the proxy alone — no T1 success can revive it.
        run_cycle(ctx).await.unwrap();
        let row = proxies::get_by_id(&pool, bad).await.unwrap().unwrap();
        assert_eq!(row.status, "quarantine");
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
        sqlx::query("UPDATE proxies SET quarantined_at = 100, ladder_at = 200, ladder_step = 0 WHERE id = ?")
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
        assert_eq!(row.ladder_step, 1);
        assert!(row.ladder_at.is_some());
        sqlx::query("UPDATE proxies SET ladder_at = 300 WHERE id = ?")
            .bind(id)
            .execute(&pool)
            .await
            .unwrap();

        run_cycle(ctx.clone()).await.unwrap();
        let row = proxies::get_by_id(&pool, id).await.unwrap().unwrap();
        assert_eq!(row.ladder_step, 2);
        sqlx::query("UPDATE proxies SET ladder_at = 400 WHERE id = ?")
            .bind(id)
            .execute(&pool)
            .await
            .unwrap();

        run_cycle(ctx.clone()).await.unwrap();
        let row = proxies::get_by_id(&pool, id).await.unwrap().unwrap();
        assert_eq!(row.ladder_step, 3);
        sqlx::query("UPDATE proxies SET ladder_at = 500 WHERE id = ?")
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
