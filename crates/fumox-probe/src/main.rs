//! fumox-probe, health-check daemon.
//!
//! Every scheduling cycle runs four passes:
//!
//! 1. **Quarantine dues**, second chances and recheck-ladder steps whose
//!    scheduled moment has arrived;
//! 2. **Priority queue**, T1 checks the server enqueued at source refresh
//!    time for freshly inserted proxies, drained newest first and capped
//!    by the same per-cycle quota as the T1 sample;
//! 3. **T1**, a random sample of TCP-connect / TLS-handshake checks over
//!    the `unknown`/`alive` population;
//! 4. **T2**, real tunnel checks for `alive` proxies through the meow-rs
//!    REST API, skipped with backoff when meow-rs is down.
//!    The batch is recency-prioritized: proxies without a single T2
//!    attempt first, then the ones whose last T2 check is the oldest.
//!
//! All lifecycle state lives in SQLite, so the daemon is restart-safe:
//! after a restart it simply resumes the schedules persisted in the DB.

mod clash;
mod meow;
mod t1;

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicUsize, Ordering};
use std::time::Duration;

use clap::Parser;
use fumox_core::AppConfig;
use fumox_core::db::DbPool;
use fumox_core::models::{Scheme, now_ts};
use fumox_core::repo::probe::ProbeResultEntry;
use fumox_core::repo::{fetch_log, meta_set, probe as probe_repo, proxies};
use meow::{DelayOutcome, MeowClient};
use tokio::sync::Semaphore;

/// `probe_results.probe_kind` of the tunnel check.
const T2_KIND: &str = "t2";

/// Number of consecutive in-batch `ServiceUnavailable` outcomes that
/// escalate from "per-request blip" to "engine outage". Below this, every
/// task still contacts meow-rs; at-or-above, the rest of the batch is
/// skipped via the `aborted` flag and `backoff_meow` is engaged. Three
/// is a deliberately tight floor: a single transport blip on one request
/// does not abort a batch, but any pattern that survives retry and ping
/// verification on three tasks in a row is a real engine problem.
const MEOW_ABORT_THRESHOLD: usize = 3;

/// Per-batch decision state shared across the parallel T2 tasks. Replaces
/// the previous `Arc<AtomicBool>`: a single `ServiceUnavailable` no longer
/// drops the whole batch, only a sustained pattern of consecutive
/// failures does.
struct BatchGuard {
    consecutive: AtomicUsize,
    aborted: AtomicBool,
    threshold: usize,
}

impl BatchGuard {
    fn new(threshold: usize) -> Self {
        Self {
            consecutive: AtomicUsize::new(0),
            aborted: AtomicBool::new(false),
            threshold,
        }
    }

    /// Record one failure. Returns `true` iff this call crossed the
    /// threshold and is the first to flip `aborted`, the caller backs
    /// off meow on that exact transition, never again within the batch.
    fn record_failure(&self) -> bool {
        let n = self.consecutive.fetch_add(1, Ordering::Relaxed) + 1;
        if n >= self.threshold && !self.aborted.swap(true, Ordering::Relaxed) {
            return true;
        }
        false
    }

    /// Record a successful or proxy-failed outcome. Resets the consecutive
    /// counter so a recovered engine immediately gets a fresh budget.
    fn record_recovered(&self) {
        self.consecutive.store(0, Ordering::Relaxed);
    }

    fn is_aborted(&self) -> bool {
        self.aborted.load(Ordering::Relaxed)
    }
}

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

    /// meow-rs answered, clear the backoff.
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
    let loaded = fumox_core::config::load(cli.config.as_deref())?;
    let config = loaded.config;
    fumox_core::logging::init_tracing(config.log.probe);

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
    // figment layers `FUMOX_*` variables over the file; count them so a
    // surprise override is at least attributable; names and values stay
    // out of the log. The resolved database path matters here as much as
    // on the server: pointing the probe at a different file than the
    // server would otherwise be invisible until the journals diverge.
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
/// probe cycles on the configured period. Errors are logged, never fatal ,
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
/// then the priority queue (fresh proxies), then the T1 sample
/// and the T2 batch.
///
/// The lanes that run later skip the rows an earlier lane already gave a
/// verdict, because both sides of each overlap draw from the same
/// population and both charge `fail_count` through `check_failed`:
///
/// * The random sample skips the rows the queue lane just covered — both
///   draw from the same `unknown` population and claiming a request only
///   deletes its queue row, so without the hand-off one dead proxy in both
///   selections collected two `fail_count` steps from this single cycle
///   and quarantined in half the cycles `fail_limit` promises.
/// * The T2 batch skips the rows the T1 sample just covered — `alive` rows
///   are in both selections, and a dead one drawn by both lanes quarantined
///   in one cycle at `fail_limit = 2`.
///
/// A skipped row loses nothing: the queue's leftovers fall to the sample,
/// and a T1-covered `alive` row is the head of the next cycle's T2 batch
/// (the batch orders by the oldest last T2 check).
async fn run_cycle(ctx: Arc<Context>) -> anyhow::Result<()> {
    let now = now_ts();
    let quarantine = probe_due_quarantine(ctx.clone(), now).await?;
    let queued = probe_queued_checks(ctx.clone()).await?;
    let t1 = probe_t1_sample(ctx.clone(), &queued.claimed).await?;
    let t2 = probe_t2_batch(ctx, &t1.claimed).await?;
    tracing::info!(
        quarantine_checked = quarantine,
        queued_checked = queued.checked,
        t1_checked = t1.checked,
        t2_checked = t2.checked,
        t2_aborted = t2.aborted,
        t2_skipped = t2.skipped,
        "probe cycle done"
    );
    Ok(())
}

/// What one lane covered: `checked` is how many verdicts it produced (for
/// the cycle log), `claimed` the rows the lane took for itself this cycle —
/// the queue lane's up-front claims (verdict or not), the random sample's
/// verdict rows. `run_cycle` hands each lane's `claimed` to the lane that
/// runs next, so one proxy is never judged twice in a single cycle.
struct LaneOutcome {
    checked: usize,
    claimed: Vec<i64>,
}

impl LaneOutcome {
    fn empty() -> Self {
        Self {
            checked: 0,
            claimed: Vec::new(),
        }
    }
}

/// Priority lane: T1 checks the server enqueued at source
/// refresh time for freshly inserted proxies. Drained newest first, capped
/// by the same per-cycle quota as the random sample. Requests are claimed
/// (deleted) up-front, so a mid-batch crash cannot turn them into an
/// endless retry loop; anything not yet covered falls back to the random
/// sample below.
async fn probe_queued_checks(ctx: Arc<Context>) -> anyhow::Result<LaneOutcome> {
    let candidates =
        probe_repo::select_queued_checks(&ctx.pool, ctx.config.probe.sample_size).await?;
    if candidates.is_empty() {
        return Ok(LaneOutcome::empty());
    }
    let ids: Vec<i64> = candidates.iter().map(|c| c.id).collect();
    probe_repo::claim_checks(&ctx.pool, &ids).await?;
    let checked = run_t1_checks(ctx, candidates).await?;
    Ok(LaneOutcome {
        checked: checked.checked,
        claimed: ids,
    })
}

/// Probe a random sample of `unknown`/`alive` proxies, minus the rows
/// `already_checked` covered earlier in this cycle (the queue lane, see
/// [`run_cycle`]). The sample is a random draw with a quota, so dropping
/// the overlap simply leaves the cycle with a slightly smaller one.
/// Returns the rows it gave a verdict, the hand-off the T2 batch of the
/// same cycle skips (see [`probe_t2_batch`]).
async fn probe_t1_sample(
    ctx: Arc<Context>,
    already_checked: &[i64],
) -> anyhow::Result<LaneOutcome> {
    let candidates = proxies::select_t1_candidates(&ctx.pool, ctx.config.probe.sample_size).await?;
    if candidates.is_empty() {
        return Ok(LaneOutcome::empty());
    }
    let covered: std::collections::HashSet<i64> = already_checked.iter().copied().collect();
    let candidates: Vec<proxies::T1Candidate> = candidates
        .into_iter()
        .filter(|c| !covered.contains(&c.id))
        .collect();
    if candidates.is_empty() {
        return Ok(LaneOutcome::empty());
    }
    run_t1_checks(ctx, candidates).await
}

/// Run concurrent T1 checks for the candidates and apply each outcome to
/// the lifecycle. Returns the verdict count plus the ids of every row a
/// verdict was produced for (vet-refused rows included, rows skipped for
/// an unknown scheme or an out-of-range port not — they were not judged).
async fn run_t1_checks(
    ctx: Arc<Context>,
    candidates: Vec<proxies::T1Candidate>,
) -> anyhow::Result<LaneOutcome> {
    let semaphore = Arc::new(Semaphore::new(ctx.config.probe.concurrency.max(1)));
    let mut tasks = tokio::task::JoinSet::new();
    let mut blocked = 0usize;
    let mut checked_ids: Vec<i64> = Vec::new();
    // Parse and port checks come first so the vetting pass below only
    // covers rows that can actually be dialed.
    let mut ready: Vec<(proxies::T1Candidate, t1::CheckKind, u16)> = Vec::new();
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
        ready.push((candidate, kind, port));
    }
    let hosts: Vec<String> = ready.iter().map(|(c, _, _)| c.host.clone()).collect();
    for ((candidate, kind, port), verdict) in ready.into_iter().zip(vet_hosts(&ctx, &hosts).await) {
        let vetted = match verdict {
            Ok(addrs) => {
                checked_ids.push(candidate.id);
                addrs
            }
            Err(reason) => {
                tracing::warn!(id = candidate.id, %reason, "probe target blocked by the private-address policy, journaled as a failed check");
                apply_vet_block(&ctx, candidate.id, kind.as_str(), &reason).await;
                checked_ids.push(candidate.id);
                blocked += 1;
                continue;
            }
        };
        let (ctx, semaphore) = (ctx.clone(), semaphore.clone());
        tasks.spawn(async move {
            // `acquire_owned` is infallible: the semaphore lives in this
            // scope and is only dropped after `collect_tasks` joins every
            // spawned task, so it cannot close while a task is awaiting a
            // permit. No `.expect` panic, no deadlock risk.
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
    Ok(LaneOutcome {
        checked: done + blocked,
        claimed: checked_ids,
    })
}

/// SSRF gate for every dial target:
/// proxy hosts come from remote feeds, so each candidate must pass the
/// shared address policy before the daemon opens a connection to it ,
/// loopback, RFC1918, link-local (cloud metadata), CGNAT and unique-local
/// addresses are refused unless `[probe].allow_private_targets` is set.
///
/// Async because the underlying DNS lookup is async, keeping the call
/// async end-to-end means the runtime worker is never blocked while the
/// OS resolver runs.
async fn vet_target_addrs(ctx: &Context, host: &str) -> Result<Vec<std::net::IpAddr>, String> {
    fumox_core::ssrf::vet_probe_host_addrs(
        host,
        ctx.config.probe.allow_private_targets,
        ctx.config.geo.dns_timeout(),
    )
    .await
}

/// Vet every host concurrently, preserving the input order. Each vetting
/// pass is a DNS lookup bounded by `dns_timeout` (5 s by default), the
/// lanes used to run these serially in their select loops before spawning
/// any check, so a batch full of dead names queued one timeout per
/// candidate ahead of every real verdict while the check semaphore sat
/// idle. Concurrency is bounded by `probe.concurrency`, the same budget
/// the checks themselves run under.
async fn vet_hosts(
    ctx: &Arc<Context>,
    hosts: &[String],
) -> Vec<Result<Vec<std::net::IpAddr>, String>> {
    let semaphore = Arc::new(Semaphore::new(ctx.config.probe.concurrency.max(1)));
    let mut tasks = tokio::task::JoinSet::new();
    for (index, host) in hosts.iter().enumerate() {
        let (ctx, semaphore) = (ctx.clone(), semaphore.clone());
        let host = host.clone();
        tasks.spawn(async move {
            let _permit = match semaphore.acquire_owned().await {
                Ok(permit) => permit,
                // Structurally impossible: the semaphore lives in this
                // scope and cannot close before the join loop below.
                Err(_) => return (index, Err("vetting lane closed".to_string())),
            };
            (index, vet_target_addrs(&ctx, &host).await)
        });
    }
    let mut verdicts: Vec<Option<Result<Vec<std::net::IpAddr>, String>>> =
        (0..hosts.len()).map(|_| None).collect();
    while let Some(joined) = tasks.join_next().await {
        match joined {
            Ok((index, verdict)) => verdicts[index] = Some(verdict),
            Err(error) => tracing::warn!(%error, "vetting task panicked"),
        }
    }
    verdicts
        .into_iter()
        .map(|verdict| {
            // A panicked task leaves a hole; refusing the target keeps the
            // row on the ordinary fail ladder instead of buffering it.
            verdict.unwrap_or_else(|| Err("vetting task panicked".to_string()))
        })
        .collect()
}

/// A vet-refused target is a *failed check*, not a skip: the policy blocks exactly what a dead proxy looks like ,
/// unresolvable names and internal addresses, so the attempt is journaled
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
            // Strict T2 priority: a
            // T1 success must not wipe the fail counter accumulated from T2
            // tunnel failures, the counter clears only via a T2 success or
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
/// is reached.
async fn apply_regular_failure(ctx: &Context, id: i64, now: i64) {
    let probe = &ctx.config.probe;
    let min_secs =
        i64::try_from(probe.second_chance_min_hours.saturating_mul(3600)).unwrap_or(i64::MAX);
    let spread_secs =
        i64::try_from(probe.second_chance_spread_hours.saturating_mul(3600)).unwrap_or(0);
    // T1 failure: a closed TCP/TLS port says nothing about the tunnel and
    // must not trigger the T1-suppression flag, see `proxies::check_failed`,
    // which takes an explicit `mark_t2_failed` argument for that reason.
    match proxies::check_failed(
        &ctx.pool,
        id,
        now,
        probe.fail_limit,
        min_secs,
        spread_secs,
        false,
    )
    .await
    {
        Ok(proxies::Transition::Quarantined) => {
            tracing::info!(id, "proxy quarantined after consecutive failures")
        }
        Ok(_) => {}
        Err(error) => tracing::warn!(id, %error, "failed to record T1 failure"),
    }
}

/// Re-check quarantined proxies whose scheduled moment has arrived.
///
/// Two lanes: [`proxies::T2_REVIVAL_SCHEMES`] rows revive via the meow-rs
/// tunnel check ([`revive_quarantined_via_t2`]) — a T1 connect cannot succeed
/// against a QUIC port — everything else walks the TCP/TLS ladder below.
async fn probe_due_quarantine(ctx: Arc<Context>, now: i64) -> anyhow::Result<usize> {
    let t2_due =
        proxies::select_due_quarantine_t2(&ctx.pool, now, ctx.config.probe.sample_size).await?;
    let revived = revive_quarantined_via_t2(ctx.clone(), t2_due).await?;
    let due = proxies::select_due_quarantine(&ctx.pool, now, ctx.config.probe.sample_size).await?;
    if due.is_empty() {
        return Ok(revived);
    }

    let semaphore = Arc::new(Semaphore::new(ctx.config.probe.concurrency.max(1)));
    let mut tasks = tokio::task::JoinSet::new();
    let mut blocked = 0usize;
    // Parse and port checks first: the vetting pass only covers rows that
    // can actually be dialed.
    let mut ready: Vec<(proxies::DueQuarantine, t1::CheckKind, u16)> = Vec::new();
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
        ready.push((row, kind, port));
    }
    let hosts: Vec<String> = ready.iter().map(|(r, _, _)| r.host.clone()).collect();
    for ((row, kind, port), verdict) in ready.into_iter().zip(vet_hosts(&ctx, &hosts).await) {
        let vetted = match verdict {
            Ok(addrs) => addrs,
            Err(reason) => {
                tracing::warn!(id = row.id, %reason, "quarantine target blocked by the private-address policy, journaled as a failed recheck");
                apply_quarantine_vet_block(&ctx, row.id, kind.as_str(), row.ladder_step, &reason)
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
            // returns; a closed semaphore here is structurally impossible.
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
    Ok(done + blocked + revived)
}

/// T2 revival lane for the quarantined rows T1 cannot judge
/// ([`proxies::T2_REVIVAL_SCHEMES`]): their second chance is a real tunnel
/// check through meow-rs. Success revives into the `ready` tier, an
/// authoritative tunnel failure advances the recheck ladder, a meow-rs
/// fault is journaled unverified and leaves the row due — an outage must
/// not retire a healthy proxy (see [`journal_engine_fault`]). Returns the
/// number of rows this lane processed.
async fn revive_quarantined_via_t2(
    ctx: Arc<Context>,
    due: Vec<proxies::ProxyRow>,
) -> anyhow::Result<usize> {
    if due.is_empty() {
        return Ok(0);
    }
    let now = now_ts();
    if now < ctx.meow_retry_at.load(Ordering::Relaxed) {
        tracing::debug!("meow-rs in backoff, quarantine revival skipped");
        return Ok(0);
    }

    // The SSRF gate first: a refused target is a failed recheck, as in the T1 lane.
    let hosts: Vec<String> = due.iter().map(|row| row.host.clone()).collect();
    let mut checked = 0usize;
    let mut batch: Vec<proxies::ProxyRow> = Vec::with_capacity(due.len());
    let mut pins: std::collections::HashMap<String, std::net::IpAddr> =
        std::collections::HashMap::new();
    for (row, verdict) in due.into_iter().zip(vet_hosts(&ctx, &hosts).await) {
        match verdict {
            Ok(vetted) => {
                if let Some(ip) =
                    fumox_core::ssrf::pick_vetted(&vetted, fumox_core::models::IpFamily::Any)
                {
                    pins.insert(row.host.clone(), ip);
                }
                batch.push(row);
            }
            Err(reason) => {
                tracing::warn!(id = row.id, %reason, "quarantine revival target blocked by the private-address policy, journaled as a failed recheck");
                apply_quarantine_vet_block(&ctx, row.id, T2_KIND, row.ladder_step, &reason).await;
                checked += 1;
            }
        }
    }
    if batch.is_empty() {
        return Ok(checked);
    }

    // Cheap liveness check first: an outage here stamps the batch unverified
    // (no ladder charge) and backs off.
    if let Err(error) = ctx.meow.ping().await {
        tracing::warn!(%error, "meow-rs unavailable, quarantine revival failed with backoff");
        ctx.backoff_meow();
        for row in &batch {
            journal_engine_fault(&ctx, row.id, &format!("meow-rs unavailable: {error}")).await;
            checked += 1;
        }
        return Ok(checked);
    }

    let (yaml, included) = clash::generate(&batch, &pins, ctx.config.meow.ipv6)?;
    write_meow_config(&ctx.config.meow.config_path, &yaml)?;
    if let Err(error) = ctx.meow.reload_config(&ctx.config.meow.config_path).await {
        tracing::warn!(%error, "meow-rs unavailable, quarantine revival failed with backoff");
        ctx.backoff_meow();
        for row in &batch {
            journal_engine_fault(&ctx, row.id, &format!("meow-rs unavailable: {error}")).await;
            checked += 1;
        }
        return Ok(checked);
    }
    ctx.meow_recovered();
    if let Err(error) = meta_set(
        &ctx.pool,
        probe_repo::meta::MEOW_LAST_OK_KEY,
        &now_ts().to_string(),
    )
    .await
    {
        tracing::warn!(%error, "failed to stamp meow_last_ok");
    }

    let delays = ctx.config.probe.recheck_delays_secs.clone();
    let semaphore = Arc::new(Semaphore::new(ctx.config.probe.concurrency.max(1)));
    let mut tasks = tokio::task::JoinSet::new();
    for row in batch {
        // A recheck that cannot run (entry failed to serialize) is a failed recheck.
        if !included.contains(&row.id) {
            let now = now_ts();
            journal(
                &ctx,
                ProbeResultEntry {
                    proxy_id: row.id,
                    checked_at: now,
                    ok: false,
                    latency_ms: None,
                    error: Some("proxy entry cannot be serialized for the T2 engine config"),
                    probe_kind: T2_KIND,
                },
            )
            .await;
            match proxies::quarantine_check_failed(&ctx.pool, row.id, now, row.ladder_step, &delays)
                .await
            {
                Ok(proxies::Transition::Removed) => {
                    tracing::info!(id = row.id, "proxy removed after the final failed recheck")
                }
                Ok(_) => {
                    tracing::debug!(
                        id = row.id,
                        step = row.ladder_step,
                        "quarantine revival failed, ladder advanced"
                    )
                }
                Err(error) => {
                    tracing::warn!(id = row.id, %error, "failed to advance quarantine ladder")
                }
            }
            checked += 1;
            continue;
        }
        let (ctx, semaphore) = (ctx.clone(), semaphore.clone());
        let delays = delays.clone();
        tasks.spawn(async move {
            // The semaphore lives in this scope until `collect_tasks`
            // returns; a closed semaphore here is structurally impossible.
            let _permit = match semaphore.acquire_owned().await {
                Ok(permit) => permit,
                Err(_) => return,
            };
            perform_quarantine_t2_check(&ctx, &row, &delays).await;
        });
    }
    Ok(checked + collect_tasks(&mut tasks).await)
}

/// One T2 revival check for a quarantined row; the outcome contract is
/// [`revive_quarantined_via_t2`]'s.
async fn perform_quarantine_t2_check(ctx: &Context, row: &proxies::ProxyRow, delays: &[i64]) {
    let name = clash::proxy_name(row.id);
    let now = now_ts();
    let outcome = ctx
        .meow
        .check_delay_with_retry(&name, 2, Duration::from_millis(100))
        .await;
    match outcome {
        DelayOutcome::Ok(delay) => {
            let latency = i64::try_from(delay).unwrap_or(i64::MAX);
            journal(
                ctx,
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
            match proxies::check_succeeded(
                &ctx.pool,
                row.id,
                now,
                Some(latency),
                true,
                fumox_core::models::ProxyStatus::Ready,
            )
            .await
            {
                Ok(_) => tracing::info!(
                    id = row.id,
                    "quarantined proxy revived via the T2 tunnel check"
                ),
                Err(error) => {
                    tracing::warn!(id = row.id, %error, "failed to record quarantine revival")
                }
            }
        }
        DelayOutcome::ProxyFailed(message) => {
            journal(
                ctx,
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
            match proxies::quarantine_check_failed(&ctx.pool, row.id, now, row.ladder_step, delays)
                .await
            {
                Ok(proxies::Transition::Removed) => {
                    tracing::info!(id = row.id, "proxy removed after the final failed recheck")
                }
                Ok(_) => {
                    tracing::debug!(
                        id = row.id,
                        step = row.ladder_step,
                        "quarantine revival failed, ladder advanced"
                    )
                }
                Err(error) => {
                    tracing::warn!(id = row.id, %error, "failed to advance quarantine ladder")
                }
            }
        }
        DelayOutcome::ServiceUnavailable(error) => {
            // Not a verdict: the row stays due, the ladder is untouched.
            journal_engine_fault(ctx, row.id, &format!("meow-rs unavailable: {error}")).await;
        }
    }
}

/// The quarantine-ladder counterpart of [`apply_vet_block`]: a vet-refused
/// recheck is a failed recheck, journaled
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
/// last configured recheck failed. `vetted` carries
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
            // `ready`.
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

/// What one T2 batch produced, for the cycle log. `checked` counts rows
/// that got a real verdict (an engine contact or a policy refusal, both
/// journaled); `aborted` counts rows an engine-wide outage kept away from
/// meow-rs (ping/reload failure or the mid-batch guard); `skipped` counts
/// rows `clash::generate` could not serialize. Folding the aborted rows
/// into `checked` made an outage cycle read as a healthy batch in exactly
/// the situation the counter is watched for.
#[derive(Default)]
struct T2Outcome {
    checked: usize,
    aborted: usize,
    skipped: usize,
}

/// Per-task result of the T2 batch. `Checked` contacted the engine (any
/// verdict); `Aborted` took the guard's early return without a request.
#[derive(Clone, Copy)]
enum T2Task {
    Checked,
    Aborted,
}

/// Write the generated Clash YAML of one meow-rs batch (a T2 batch or a
/// quarantine revival batch) to `meow.config_path`.
///
/// The YAML carries every proxy credential in plain text, same exposure as
/// the SQLite database, same 0600 answer (the DB chmod rationale lives in
/// fumox-core/src/db.rs). The mode is set at creation so the file is never
/// briefly world-readable, and re-asserted on the open fd: a pre-existing
/// file keeps its old mode through `create` alone and must be corrected.
fn write_meow_config(path: &std::path::Path, yaml: &str) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)?;
        // fchmod on the open fd, no path re-resolution between check and use.
        file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
        file.write_all(yaml.as_bytes())?;
    }
    #[cfg(not(unix))]
    std::fs::write(path, yaml)?;
    Ok(())
}

/// Generate a Clash batch, reload meow-rs, and delay-test every proxy
/// through a real tunnel.
///
/// `already_checked` carries the ids the T1 lanes gave a verdict this
/// cycle (see [`run_cycle`]); those rows are dropped from the batch, a
/// dead one drawn by both lanes would otherwise collect one `fail_count`
/// step from each and quarantine in half the cycles `fail_limit`
/// promises. Dropping the overlap simply leaves the recency-prioritized
/// batch slightly smaller; the dropped rows are the head of the next
/// cycle's batch anyway.
///
/// Success is strict: only a tunnel that came
/// up *and* answered with a measured `delay` counts, anything else the
/// engine reports is a failure. A meow-rs outage is *not* charged to the
/// proxies: every proxy that was due one is journaled
/// (as `probe_kind='t2'`, the record that un-sticks the recency queue)
/// and stamped as unverified, but its own fail budget and the quarantine
/// path stay untouched, so an outage cannot retire a healthy pool
/// ([`journal_engine_fault`]). The cycle still
/// backs off so a dead meow-rs is not hammered every minute.
async fn probe_t2_batch(ctx: Arc<Context>, already_checked: &[i64]) -> anyhow::Result<T2Outcome> {
    let now = now_ts();
    if now < ctx.meow_retry_at.load(Ordering::Relaxed) {
        tracing::debug!("meow-rs in backoff, T2 skipped");
        return Ok(T2Outcome::default());
    }

    let rows = proxies::select_t2_candidates(&ctx.pool, ctx.config.probe.sample_size).await?;
    // The hand-off from the T1 lanes: their verdict rows are already
    // judged, re-judging them here would double-charge the fail ladder.
    let covered: std::collections::HashSet<i64> = already_checked.iter().copied().collect();
    let rows: Vec<proxies::ProxyRow> = rows
        .into_iter()
        .filter(|row| !covered.contains(&row.id))
        .collect();
    // Vet every candidate before anything touches meow-rs. A refused target
    // is a *failed* t2 check, not a skip: the
    // policy blocks unresolvable names and internal addresses, and a skip
    // left such rows at the head of the recency queue forever (they never
    // got a t2 row, so the selector re-served them every cycle).
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
    let mut pins: std::collections::HashMap<String, std::net::IpAddr> =
        std::collections::HashMap::new();
    let mut to_vet: Vec<proxies::ProxyRow> = Vec::new();
    for row in rows {
        let scheme = row.scheme.parse::<Scheme>().ok();
        if !scheme.is_some_and(clash::is_supported) {
            continue;
        }
        to_vet.push(row);
    }
    let hosts: Vec<String> = to_vet.iter().map(|row| row.host.clone()).collect();
    let mut batch: Vec<proxies::ProxyRow> = Vec::with_capacity(to_vet.len());
    for (row, verdict) in to_vet.into_iter().zip(vet_hosts(&ctx, &hosts).await) {
        match verdict {
            Ok(vetted) => {
                if let Some(ip) =
                    fumox_core::ssrf::pick_vetted(&vetted, fumox_core::models::IpFamily::Any)
                {
                    // The probe batch is deduplicated by `row.id` upstream
                    // (`proxies::select_t2_candidates`), so two rows that
                    // share a hostname overwrite the same pin map entry ,
                    // operator intent is unambiguous and the result is the
                    // same vetted IP.
                    pins.insert(row.host.clone(), ip);
                }
                batch.push(row);
            }
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
        return Ok(T2Outcome {
            checked: blocked,
            ..T2Outcome::default()
        });
    }

    // Cheap liveness check first: no point rewriting the config file when
    // the service is down anyway. An outage here stamps the whole batch
    // unverified (no fail budget) and backs off.
    if let Err(error) = ctx.meow.ping().await {
        tracing::warn!(%error, "meow-rs unavailable, T2 batch failed with backoff");
        ctx.backoff_meow();
        journal_engine_failure(&ctx, &batch, &format!("meow-rs unavailable: {error}")).await;
        return Ok(T2Outcome {
            checked: blocked,
            aborted: batch.len(),
            skipped: 0,
        });
    }

    let (yaml, included) = clash::generate(&batch, &pins, ctx.config.meow.ipv6)?;
    let config_path = &ctx.config.meow.config_path;
    write_meow_config(config_path, &yaml)?;

    if let Err(error) = ctx.meow.reload_config(config_path).await {
        tracing::warn!(%error, "meow-rs unavailable, T2 batch failed with backoff");
        ctx.backoff_meow();
        journal_engine_failure(&ctx, &batch, &format!("meow-rs unavailable: {error}")).await;
        return Ok(T2Outcome {
            checked: blocked,
            aborted: batch.len(),
            skipped: 0,
        });
    }
    ctx.meow_recovered();
    if let Err(error) = meta_set(
        &ctx.pool,
        probe_repo::meta::MEOW_LAST_OK_KEY,
        &now_ts().to_string(),
    )
    .await
    {
        tracing::warn!(%error, "failed to stamp meow_last_ok");
    }
    stamp_meow_memory(&ctx).await;

    let semaphore = Arc::new(Semaphore::new(ctx.config.probe.concurrency.max(1)));
    // Set by the first task to see the engine fail mid-batch: every proxy
    // still due a check in this batch then gets an aborted-failure record
    // without hammering a dying meow-rs with further requests.
    let batch_guard = Arc::new(BatchGuard::new(MEOW_ABORT_THRESHOLD));
    let mut tasks = tokio::task::JoinSet::new();
    let mut skipped = 0usize;
    for row in batch {
        // Rows that never made it into the generated config (their entry
        // could not be serialized, `clash::generate` skipped them) must get
        // the real reason journaled, routing them through the engine would
        // produce a misleading "proxy not found" failure.
        if !included.contains(&row.id) {
            journal_and_fail(
                &ctx,
                row.id,
                "proxy entry cannot be serialized for the T2 engine config",
            )
            .await;
            skipped += 1;
            continue;
        }
        let (ctx, semaphore) = (ctx.clone(), semaphore.clone());
        let batch_guard = batch_guard.clone();
        tasks.spawn(async move {
            // The semaphore lives in this scope until `collect_tasks`
            // returns; a closed semaphore here is structurally impossible.
            let _permit = match semaphore.acquire_owned().await {
                Ok(permit) => permit,
                // Structurally impossible, and counted as aborted rather
                // than checked so an impossible close cannot inflate the
                // real-check counter.
                Err(_) => return T2Task::Aborted,
            };
            if batch_guard.is_aborted() {
                journal_engine_fault(
                    &ctx,
                    row.id,
                    "aborted: meow-rs became unavailable mid-batch",
                )
                .await;
                return T2Task::Aborted;
            }
            let name = clash::proxy_name(row.id);
            let now = now_ts();
            // Retry transient `ServiceUnavailable` (transport blip, one
            // malformed payload, single 5xx on a flapping connection):
            // re-asking the same request absorbs most of them and keeps
            // them off the abort counter, which is now reserved for
            // patterns the engine cannot recover from within the cycle.
            let outcome = ctx
                .meow
                .check_delay_with_retry(&name, 2, Duration::from_millis(100))
                .await;
            match outcome {
                DelayOutcome::Ok(delay) => {
                    batch_guard.record_recovered();
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
                    // The engine answered authoritatively, the proxy's
                    // tunnel died, but the engine itself is alive. Reset
                    // the consecutive counter so a single 4xx never
                    // poisons the abort budget for the rest of the batch.
                    batch_guard.record_recovered();
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
                        true,
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
                    // Two paths reach here: (a) the retry budget was
                    // exhausted, meaning meow answered badly twice in a
                    // row for the same proxy, and (b) the failure was
                    // already bad enough that retrying would just delay
                    // the verdict (5xx with no transport layer involved).
                    // Either way, the request itself is settled, the
                    // question is whether the engine as a whole is down.
                    // A cheap `/version` ping distinguishes the two: if
                    // meow is alive, this is a per-request blip that
                    // does not justify aborting the batch; if meow is
                    // down, the consecutive counter (and the abort flag
                    // once it crosses the threshold) reflects a real
                    // outage.
                    let engine_alive = ctx.meow.ping().await.is_ok();
                    if engine_alive {
                        tracing::debug!(
                            id = row.id,
                            %error,
                            "meow-rs answered /version after a failed delay check; treating as per-request blip"
                        );
                        journal_and_fail(
                            &ctx,
                            row.id,
                            &format!("meow-rs transient error: {error}"),
                        )
                        .await;
                    } else {
                        if batch_guard.record_failure() {
                            // Threshold crossed exactly once per batch;
                            // subsequent failures find the flag already
                            // set and skip the backoff. Idempotent.
                            tracing::warn!(
                                consecutive = MEOW_ABORT_THRESHOLD,
                                %error,
                                "meow-rs became unavailable mid-batch, failing the rest of the T2 batch"
                            );
                            ctx.backoff_meow();
                        }
                        journal_engine_fault(
                            &ctx,
                            row.id,
                            &format!("meow-rs unavailable mid-batch: {error}"),
                        )
                        .await;
                    }
                }
            }
            T2Task::Checked
        });
    }
    // The counters the cycle log prints, kept honest during an outage:
    // only tasks that reached `T2Task::Checked` are real engine contacts,
    // the guard's early returns count as aborted and serialize skips as
    // skipped, never folded into `checked`.
    let mut checked = blocked;
    let mut aborted = 0usize;
    while let Some(result) = tasks.join_next().await {
        match result {
            Ok(T2Task::Checked) => checked += 1,
            Ok(T2Task::Aborted) => aborted += 1,
            Err(error) => tracing::warn!(%error, "T2 check task panicked"),
        }
    }
    Ok(T2Outcome {
        checked,
        aborted,
        skipped,
    })
}

/// Journal one failed T2 attempt and run the fail ladder: a proxy that got
/// a verdict, whether the tunnel itself failed or the target was vet-refused,
/// receives a `probe_kind='t2'` failure record, which is also what moves it
/// forward in the recency queue.
///
/// The remaining caller is the per-request blip branch, where the engine
/// answered its liveness ping but the delay endpoint failed for this one
/// proxy. That verdict is charged against the fail budget like any other;
/// a meow-rs that is alive to `GET /version` but broken on every delay
/// request is charged this way for the whole batch.
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
    if let Err(error) = proxies::check_failed(
        &ctx.pool,
        id,
        now,
        probe.fail_limit,
        min_secs,
        spread_secs,
        // T2-side failure (the caller is `journal_and_fail`, which is only
        // invoked from T2 paths): stamp the suppression flag so the T1
        // selector skips this proxy until its next T2 succeeds.
        true,
    )
    .await
    {
        tracing::warn!(id, %error, "failed to record T2 failure");
    }
}

/// Journal one T2 attempt that never happened because the engine was down
/// and stamp the row as *unverified*, not as *failed*.
///
/// An engine outage journals the attempt (so the recency queue keeps
/// moving) and stamps last_t2_failed_at plus the ready -> alive demote,
/// but never charges the proxy's fail budget.
async fn journal_engine_fault(ctx: &Context, id: i64, reason: &str) {
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
    if let Err(error) = proxies::check_engine_unavailable(&ctx.pool, id, now).await {
        tracing::warn!(id, %error, "failed to stamp the T2 engine fault");
    }
}

/// Stamp every proxy of a batch with the same engine-outage reason: a
/// meow-rs outage at ping/reload time means every due proxy went
/// unverified this cycle, and an unrecorded skip is indistinguishable from
/// an empty pool (and pins the head of the recency queue for the whole
/// outage). No fail budget is charged, see [`journal_engine_fault`].
async fn journal_engine_failure(ctx: &Context, batch: &[proxies::ProxyRow], reason: &str) {
    for row in batch {
        journal_engine_fault(ctx, row.id, reason).await;
    }
    tracing::warn!(proxies = batch.len(), "T2 batch failed by engine outage");
}

/// Cutoff timestamp for a retention window of `days`. A zero window would
/// wipe the whole history on every cycle, so it is clamped to one day.
fn retention_cutoff(now: i64, days: u32) -> i64 {
    now - i64::from(days.max(1)) * 86_400
}

/// Publish the proxy kernel's RSS for the admin panel.
///
/// Purely observational: failures touch neither the fail ladder nor the
/// backoff. Only cycles that reload meow-rs refresh it, so a stale number
/// means "no T2 batch ran lately", not "the kernel shrank".
async fn stamp_meow_memory(ctx: &Context) {
    match ctx.meow.memory().await {
        Ok(mem) => {
            let payload = probe_repo::meta::MeowMemory {
                rss_bytes: mem.rss_bytes,
                os_limit_bytes: mem.os_limit_bytes,
                ts: now_ts(),
            };
            if let Err(error) = meta_set(
                &ctx.pool,
                probe_repo::meta::MEOW_MEMORY_KEY,
                &meta_json(&payload),
            )
            .await
            {
                tracing::debug!(%error, "failed to stamp meow_memory");
            }
        }
        Err(error) => tracing::debug!(%error, "meow-rs /memory unavailable"),
    }
}

/// Serialize a meta payload into its on-wire JSON. The payload structs in
/// [`fumox_core::repo::probe::meta`] hold only JSON-native field types, so
/// serialization cannot fail; the expectation documents that rather than
/// guards a real risk.
fn meta_json(payload: &impl serde::Serialize) -> String {
    serde_json::to_string(payload).expect("meta payload holds only JSON-native fields")
}

/// Build the `probe_heartbeat` payload. `interval_secs` is the daemon's
/// effective beat period and `cycle_interval_secs` its effective cycle
/// period: the admin panel thresholds staleness against the schedules the
/// daemon actually runs, since server and probe may read different config
/// files (see [`heartbeat_loop`]). The shape is the shared
/// [`fumox_core::repo::probe::meta::Heartbeat`] contract.
fn heartbeat_payload(interval_secs: u64, cycle_interval_secs: u64) -> String {
    meta_json(&probe_repo::meta::Heartbeat {
        ts: now_ts(),
        pid: std::process::id(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        interval_secs: Some(interval_secs),
        cycle_interval_secs: Some(cycle_interval_secs),
    })
}

/// Periodically upsert `probe_heartbeat` into `meta` so the admin panel can
/// tell the daemon is alive. The payload carries the daemon's effective
/// beat and cycle periods: server and probe may read different config files
/// (or a different env overlay), so the panel must threshold against the
/// schedule actually running, not against its own copy of the config.
async fn heartbeat_loop(ctx: Arc<Context>) {
    let period = Duration::from_secs(ctx.config.probe.heartbeat_interval_secs.max(5));
    let cycle_secs = ctx.config.probe.cycle_interval_secs.max(1);
    let mut ticker = tokio::time::interval(period);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        ticker.tick().await;
        let payload = heartbeat_payload(period.as_secs(), cycle_secs);
        if let Err(error) = meta_set(&ctx.pool, probe_repo::meta::HEARTBEAT_KEY, &payload).await {
            tracing::warn!(%error, "failed to write probe heartbeat");
        }
    }
}

/// History rotation: `probe_results` and `fetch_log` older than
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

    let mut deleted_probe = 0u64;
    let mut deleted_fetch = 0u64;
    let mut deleted_requests = 0u64;
    match probe_repo::purge_before(&ctx.pool, probe_cutoff).await {
        Ok(0) => {}
        Ok(deleted) => {
            deleted_probe = deleted;
            tracing::info!(deleted, "rotated probe_results");
        }
        Err(error) => tracing::warn!(%error, "probe_results rotation failed"),
    }
    match fetch_log::purge_before(&ctx.pool, fetch_cutoff).await {
        Ok(0) => {}
        Ok(deleted) => {
            deleted_fetch = deleted;
            tracing::info!(deleted, "rotated fetch_log");
        }
        Err(error) => tracing::warn!(%error, "fetch_log rotation failed"),
    }
    // Priority queue housekeeping: requests whose proxy already
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
        Ok(deleted) => {
            deleted_requests = deleted;
            tracing::info!(deleted, "rotated stale probe_requests");
        }
        Err(error) => tracing::warn!(%error, "probe_requests rotation failed"),
    }
    // Stamp the run so /admin/probe can surface it: the info lines above
    // are not a surface an operator looks at, and a probe daemon that
    // stopped rotating would otherwise grow both journals with nothing
    // saying so.
    let stamp = probe_repo::meta::LastRotation {
        ts: now_ts(),
        probe_results: deleted_probe,
        fetch_log: deleted_fetch,
        probe_requests: deleted_requests,
    };
    if let Err(error) = meta_set(
        &ctx.pool,
        probe_repo::meta::LAST_ROTATION_KEY,
        &meta_json(&stamp),
    )
    .await
    {
        tracing::warn!(%error, "failed to stamp last_rotation");
    }
}

/// Journal one probe attempt; a failed write is logged at error level but
/// does not stop the state machine (the lifecycle transition is the source
/// of truth). Error level because a drop means the history row for a
/// verdict that *did* land is gone for good, and a burst of these is the
/// only symptom when the database is locked or unwritable.
async fn journal(ctx: &Context, entry: ProbeResultEntry<'_>) {
    if let Err(error) = probe_repo::insert(&ctx.pool, &entry).await {
        tracing::error!(id = entry.proxy_id, %error, "failed to journal probe result");
    }
}

/// Await all spawned check tasks; returns how many completed. Panics are
/// reported as warnings, one bad task must not kill the cycle.
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
#[path = "main_tests.rs"]
mod tests;
