//! fumox-probe, health-check daemon.
//!
//! Each cycle runs four passes: quarantine dues, the priority queue for
//! freshly inserted proxies, the T1 sample (TCP-connect / TLS-handshake
//! over `unknown`/`alive`), and the T2 tunnel batch through the meow-rs
//! REST API (recency-prioritized, skipped with backoff when meow-rs is
//! down).
//!
//! All proxy lifecycle state (status, fail counters, quarantine
//! schedules) lives in SQLite, so the daemon is restart-safe: a restart
//! resumes the schedules persisted in the DB. The meow-rs backoff gate is
//! mirrored into the `meta` table for the same reason (see [`Context::new`]).

mod clash;
mod meow;
mod speed;
mod t1;

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicUsize, Ordering};
use std::time::Duration;

use clap::Parser;
use fumox_core::AppConfig;
use fumox_core::db::DbPool;
use fumox_core::models::{ProxyEntry, Scheme, now_ts};
use fumox_core::repo::probe::{
    ProbeResultEntry, SPEED_KIND, T2_KIND, T2_UNVERIFIED_KIND, TRACE_KIND,
};
use fumox_core::repo::{meta_get, meta_set, probe as probe_repo, proxies, retention};
use meow::{DelayOutcome, MeowClient};
use speed::{Attempt, AttemptValue};
use tokio::sync::Semaphore;

/// In-batch `ServiceUnavailable` outcomes (each already survived the
/// per-request retry) that escalate from "per-request blip" to "engine
/// outage": at or above, the rest of the batch skips meow-rs via the
/// `aborted` flag and the backoff is armed when the batch ends. Three is
/// a deliberately tight floor.
const MEOW_ABORT_THRESHOLD: usize = 3;

/// Per-request blips (the engine answers `/version` but the delay check
/// fails) one batch may collect before the backoff is armed at batch end.
/// A blip never charges the proxy; a *run* of them is engine-side (a
/// blocked test endpoint, a broken configuration) and must not be charged
/// to the proxies either.
const MEOW_BLIP_THRESHOLD: usize = 3;

/// Fixed journal text of the guard's early return: aborted rows skip the
/// engine before the batch-level liveness ping classifies them
/// (see [`run_tunnel_reload`]).
const MEOW_ABORT_REASON: &str = "meow-rs became unavailable mid-batch";

/// Per-batch decision state shared across the parallel tunnel tasks. Every
/// outcome first runs the per-request retry; what survives it is a
/// confirmed engine-unavailable event. At `MEOW_ABORT_THRESHOLD` events
/// the abort flag goes up and the tasks behind it skip the engine,
/// journaling [`MEOW_ABORT_REASON`]; the one batch-level liveness ping at
/// the end (see [`run_tunnel_reload`]) then classifies the collected
/// outcomes and arms the backoff once.
struct BatchGuard {
    unavailable: AtomicUsize,
    aborted: AtomicBool,
    threshold: usize,
}

impl BatchGuard {
    fn new(threshold: usize) -> Self {
        Self {
            unavailable: AtomicUsize::new(0),
            aborted: AtomicBool::new(false),
            threshold,
        }
    }

    /// Record one confirmed engine-unavailable outcome; the counter never
    /// resets, so a flapping engine still reaches the threshold.
    fn record_unavailable(&self) {
        let count = self.unavailable.fetch_add(1, Ordering::Relaxed) + 1;
        if count >= self.threshold {
            self.aborted.store(true, Ordering::Relaxed);
        }
    }

    fn is_aborted(&self) -> bool {
        self.aborted.load(Ordering::Relaxed)
    }

    fn unavailable(&self) -> usize {
        self.unavailable.load(Ordering::Relaxed)
    }
}

/// The T2 verdicts of one batch, collected while the checks run and
/// settled when the batch is over. The fail ladder is charged only when
/// the batch produced at least one success: a batch in which *every*
/// tunnel failed says more about the test endpoint than about the proxies,
/// and is stamped unverified the way a meow-rs outage is.
struct T2Verdicts {
    successes: AtomicUsize,
    failures: std::sync::Mutex<Vec<T2Failure>>,
    /// Rows the engine never judged, kept until the batch-level liveness
    /// ping classifies them at the end of the batch.
    unavailable: std::sync::Mutex<Vec<(i64, String)>>,
}

/// One failed tunnel check, kept until the batch is over.
struct T2Failure {
    id: i64,
    now: i64,
    /// The quarantine ladder step of the row, for the revival batches. The
    /// regular T2 batch has none.
    ladder_step: Option<i64>,
}

impl T2Verdicts {
    fn new() -> Self {
        Self {
            successes: AtomicUsize::new(0),
            failures: std::sync::Mutex::new(Vec::new()),
            unavailable: std::sync::Mutex::new(Vec::new()),
        }
    }

    fn record_success(&self) {
        self.successes.fetch_add(1, Ordering::Relaxed);
    }

    fn record_failure(&self, failure: T2Failure) {
        self.failures
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .push(failure);
    }

    /// Collect one `ServiceUnavailable` outcome for the batch-level
    /// liveness ping once the checks are done.
    fn record_unavailable(&self, id: i64, error: String) {
        self.unavailable
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .push((id, error));
    }

    fn successes(&self) -> usize {
        self.successes.load(Ordering::Relaxed)
    }

    fn take_failures(&self) -> Vec<T2Failure> {
        std::mem::take(
            &mut *self
                .failures
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner()),
        )
    }

    fn take_unavailable(&self) -> Vec<(i64, String)> {
        std::mem::take(
            &mut *self
                .unavailable
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner()),
        )
    }
}

/// The wall-clock budget of one probe cycle: three quarters of the period
/// (the rest is the gap between cycles). A cycle that runs longer overlaps
/// the next one, so every lane asks the budget before it starts a check.
#[derive(Clone)]
struct CycleBudget {
    deadline: tokio::time::Instant,
}

impl CycleBudget {
    fn new(period: Duration) -> Self {
        let budget = period.mul_f64(0.75).max(Duration::from_secs(1));
        Self {
            deadline: tokio::time::Instant::now() + budget,
        }
    }

    fn expired(&self) -> bool {
        tokio::time::Instant::now() >= self.deadline
    }

    fn remaining_ms(&self) -> u64 {
        self.deadline
            .saturating_duration_since(tokio::time::Instant::now())
            .as_millis() as u64
    }
}

/// The check quota of one group of lanes. `probe.sample_size` is the
/// number of proxies a cycle checks, but every lane applying it on its
/// own could run several times that, so the lanes of a group (the
/// quarantine drain, the coverage lanes, the tunnel lanes) share one
/// quota.
struct CycleQuota {
    total: usize,
    remaining: AtomicUsize,
}

impl CycleQuota {
    fn new(total: usize) -> Self {
        Self {
            total,
            remaining: AtomicUsize::new(total),
        }
    }
    /// Take up to `want` checks for the *first* lane of the group: at
    /// most half the quota, so the second lane still gets a share.
    fn take_first(&self, want: usize) -> usize {
        let cap = (self.total / 2).max(1);
        self.take(want.min(cap))
    }

    fn take(&self, want: usize) -> usize {
        let left = want;
        loop {
            let current = self.remaining.load(Ordering::Relaxed);
            if current == 0 || left == 0 {
                return 0;
            }
            let take = left.min(current);
            match self.remaining.compare_exchange(
                current,
                current - take,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => return take,
                Err(_) => continue,
            }
        }
    }

    fn remaining(&self) -> usize {
        self.remaining.load(Ordering::Relaxed)
    }
}

fn as_limit(quota: usize) -> u32 {
    u32::try_from(quota).unwrap_or(u32::MAX)
}

/// The addresses the hosts of a cycle resolved to. A host is resolved
/// once per cycle (a feed full of rows on one host used to spend one DNS
/// lookup per row), and the T2 batch of a cycle reuses what the T1 lanes
/// vetted.
#[derive(Default)]
struct CycleVet {
    resolved: std::sync::Mutex<std::collections::HashMap<String, std::sync::Arc<VetVerdict>>>,
}

/// The verdict of one host: the vetted addresses, or the reason the
/// address policy refused it.
type VetVerdict = Result<Vec<std::net::IpAddr>, String>;

impl CycleVet {
    fn get(&self, host: &str) -> Option<std::sync::Arc<VetVerdict>> {
        self.resolved
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .get(host)
            .cloned()
    }

    fn put(&self, host: &str, verdict: std::sync::Arc<VetVerdict>) {
        self.resolved
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .insert(host.to_string(), verdict);
    }
}

/// The state the lanes of one cycle share.
struct Cycle {
    budget: CycleBudget,
    /// The quota of the quarantine drain (the recheck ladder).
    quarantine: CycleQuota,
    /// The quota of the coverage lanes (the priority queue and the random sample).
    coverage: CycleQuota,
    /// The quota of the tunnel lanes (the quarantine revival and the T2 batch).
    tunnel: CycleQuota,
    vetted: CycleVet,
}

impl Cycle {
    fn new(config: &AppConfig) -> Self {
        let size = config.probe.sample_size as usize;
        Self {
            budget: CycleBudget::new(Duration::from_secs(config.probe.cycle_interval_secs.max(1))),
            quarantine: CycleQuota::new(size),
            coverage: CycleQuota::new(size),
            tunnel: CycleQuota::new(size),
            vetted: CycleVet::default(),
        }
    }
}

#[derive(Parser)]
#[command(name = "fumox-probe", version, about = "Fumox health-check daemon")]
struct Cli {
    /// Path to the TOML config file (outranks FUMOX_CONFIG; the default
    /// location is config/app.toml if present).
    #[arg(short, long)]
    config: Option<PathBuf>,

    /// Print the resolved configuration as TOML and exit: the effective
    /// values (file merged under the environment, which wins), the admin
    /// token redacted.
    #[arg(long)]
    print_config: bool,
}

/// Shared daemon state, cheap to clone into spawned check tasks.
struct Context {
    pool: DbPool,
    config: AppConfig,
    meow: MeowClient,
    /// Earliest unix second at which T2 may be retried after meow-rs
    /// becomes unavailable (exponential backoff, capped). The atomic is
    /// the in-memory working copy: mirrored into the `meta` table
    /// ([`probe_repo::meta::MEOW_RETRY_AT_KEY`]) on every change and
    /// restored from there by [`Context::new`], so a restart resumes the
    /// saved pause instead of resetting it.
    meow_retry_at: AtomicI64,
    /// Current meow-rs backoff length in seconds; persisted next to
    /// `meow_retry_at`, see that field.
    meow_backoff_secs: AtomicI64,
}

impl Context {
    async fn new(config: AppConfig, pool: DbPool) -> Result<Self, String> {
        let meow = MeowClient::new(&config.meow)?;
        let backoff_initial =
            i64::try_from(config.meow.backoff_initial_secs.max(1)).unwrap_or(i64::MAX);
        // A restart resumes the saved meow-rs pause instead of hammering a
        // still-down engine on its first cycle; missing keys are a fresh
        // start
        let (retry_at, backoff) = match restore_meow_backoff(&pool).await {
            Ok(restored) => restored,
            Err(error) => {
                tracing::warn!(
                    %error,
                    "cannot read the saved meow backoff state, starting from the configured initial"
                );
                (0, backoff_initial)
            }
        };
        // A saved length below the configured initial has nothing to say
        // (an older daemon wrote it before a config change, say): the
        // configured initial is the floor
        let backoff = backoff.max(backoff_initial);
        Ok(Self {
            pool,
            config,
            meow,
            meow_retry_at: AtomicI64::new(retry_at),
            meow_backoff_secs: AtomicI64::new(backoff),
        })
    }

    /// Push the next T2 retry further into the future (capped exponential)
    /// and mirror the state into `meta`, so a restart resumes the pause.
    async fn backoff_meow(&self) {
        let backoff = self.meow_backoff_secs.load(Ordering::Relaxed);
        let max = i64::try_from(self.config.meow.backoff_max_secs).unwrap_or(i64::MAX);
        let next = backoff.saturating_mul(2).min(max);
        self.meow_backoff_secs.store(next, Ordering::Relaxed);
        let retry_at = now_ts().saturating_add(backoff);
        self.meow_retry_at.store(retry_at, Ordering::Relaxed);
        tracing::warn!(
            backoff_secs = backoff,
            retry_at,
            next_backoff_secs = next,
            "meow-rs backoff engaged, the T2 lanes are paused"
        );
        persist_meow_backoff(&self.pool, retry_at, next).await;
    }

    /// meow-rs answered, clear the backoff (and its persisted copy).
    async fn meow_recovered(&self) {
        let initial =
            i64::try_from(self.config.meow.backoff_initial_secs.max(1)).unwrap_or(i64::MAX);
        let previous = self.meow_backoff_secs.swap(initial, Ordering::Relaxed);
        let retry_at = self.meow_retry_at.swap(0, Ordering::Relaxed);
        // The backoff only grows past its initial length on an outage, so
        // an unchanged length means nothing to recover from
        if previous > initial {
            tracing::info!(
                backoff_secs = initial,
                previous_backoff_secs = previous,
                retry_at,
                "meow-rs recovered, the T2 lanes run again"
            );
        }
        persist_meow_backoff(&self.pool, 0, initial).await;
    }
}

/// Read the persisted meow-rs backoff state: `(retry_at, backoff_secs)`.
/// Missing keys mean "no outage on record". A stamp that does not parse
/// reads as absent too, loudly: it gates the T2 lanes, and its silent
/// loss would send a restarted daemon at a still-down engine.
async fn restore_meow_backoff(pool: &DbPool) -> fumox_core::Result<(i64, i64)> {
    let retry_at = match meta_get(pool, probe_repo::meta::MEOW_RETRY_AT_KEY).await? {
        Some(text) => parse_backoff_stamp(probe_repo::meta::MEOW_RETRY_AT_KEY, &text),
        None => 0,
    };
    let backoff = match meta_get(pool, probe_repo::meta::MEOW_BACKOFF_SECS_KEY).await? {
        Some(text) => parse_backoff_stamp(probe_repo::meta::MEOW_BACKOFF_SECS_KEY, &text),
        None => 0,
    };
    Ok((retry_at, backoff))
}

/// Parse one persisted backoff stamp. A value that does not parse reads
/// as zero and is logged with its key: a damaged row or a manual edit
/// must not turn into an invisible reset of the gate.
fn parse_backoff_stamp(key: &str, text: &str) -> i64 {
    match text.parse::<i64>() {
        Ok(value) => value,
        Err(_) => {
            tracing::warn!(
                key,
                value = %sanitize_reason(text),
                "saved meow backoff state does not parse, treating it as absent"
            );
            0
        }
    }
}

/// Mirror the backoff state into `meta`, best effort: the gate itself is
/// the in-memory atomic, so a failed mirror costs at most a resumed
/// contact attempt on the next restart.
async fn persist_meow_backoff(pool: &DbPool, retry_at: i64, backoff_secs: i64) {
    let outcome = async {
        meta_set(
            pool,
            probe_repo::meta::MEOW_RETRY_AT_KEY,
            &retry_at.to_string(),
        )
        .await?;
        meta_set(
            pool,
            probe_repo::meta::MEOW_BACKOFF_SECS_KEY,
            &backoff_secs.to_string(),
        )
        .await
    }
    .await;
    if let Err(error) = outcome {
        tracing::warn!(%error, "failed to persist the meow backoff state");
    }
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

    fumox_core::logging::init_tracing(config.log.probe);

    fumox_core::bootstrap::report_config_file(&loaded.path);
    // The resolved database path matters here as much as on the server:
    // a probe pointed at a different file would stay invisible until the
    // journals diverge
    fumox_core::bootstrap::report_database(&config);

    // The probe shares the database file with the server but owns only the
    // health status of a proxy: its connections run behind an authorizer
    // that denies every other write, and the pool applies the schema
    // before those connections exist
    let pool = fumox_core::db::connect_probe_pool(&config.database).await?;

    tracing::info!(
        cycle_secs = config.probe.cycle_interval_secs,
        sample_size = config.probe.sample_size,
        fail_limit = config.probe.fail_limit,
        concurrency = config.probe.concurrency,
        recheck_delays_secs = ?config.probe.recheck_delays_secs,
        "fumox-probe started"
    );

    let ctx = Arc::new(
        Context::new(config, pool)
            .await
            .map_err(|error| anyhow::anyhow!("{error}"))?,
    );
    // The controller address is vetted before the first cycle: a name that
    // resolves into public address space would carry the bearer token to
    // the internet. The vetting repeats before every tunnel batch
    // (`run_t2_tunnel_batch`), so a name that starts resolving into public
    // space mid-run stops the batches instead of leaking
    ctx.meow
        .verify_address(ctx.config.ssrf_dns_timeout())
        .await
        .map_err(|error| anyhow::anyhow!("{error}"))?;
    // The config path is where meow-rs reads its own configuration from:
    // it has to be absolute and its directory has to exist, or the batch
    // fails on every cycle with a write error instead of a clear startup
    // message
    validate_meow_config_path(&ctx.config.meow.config_path)?;

    tokio::select! {
        result = run(ctx) => result?,
        result = shutdown_signal() => result?,
    }

    tracing::info!("shutdown complete");
    Ok(())
}

/// Check the path the probe writes meow-rs' configuration to: the engine
/// resolves it in its own filesystem, so a relative path is meaningless
/// there even though the probe could write it. The parent directory is
/// created here, so an unwritable location is reported at startup instead
/// of on every cycle.
fn validate_meow_config_path(path: &std::path::Path) -> anyhow::Result<()> {
    if !path.is_absolute() {
        anyhow::bail!(
            "meow.config_path {} is not absolute: the engine resolves the path in its own \
             filesystem",
            path.display()
        );
    }
    let parent = path.parent().unwrap_or_else(|| std::path::Path::new("/"));
    std::fs::create_dir_all(parent).map_err(|error| {
        anyhow::anyhow!(
            "meow.config_path {} is not usable: its directory {} cannot be created: {error}",
            path.display(),
            parent.display()
        )
    })?;
    Ok(())
}

/// Main scheduling loop: heartbeat and retention on their own timers,
/// probe cycles on the configured period. Errors are logged, never fatal:
/// a bad cycle must not take down the daemon.
async fn run(ctx: Arc<Context>) -> anyhow::Result<()> {
    tokio::spawn(heartbeat_loop(ctx.clone()));
    tokio::spawn(retention_loop(ctx.clone()));

    let period = Duration::from_secs(ctx.config.probe.cycle_interval_secs.max(1));
    let mut ticker = tokio::time::interval(period);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        ticker.tick().await;
        // The cycle gets the period as its deadline: two overlapping
        // cycles would charge the same rows twice. Lanes stop at 75% of
        // the period (see [`CycleBudget`]); this is the hard backstop for
        // a hung lane
        match tokio::time::timeout(period, run_cycle(ctx.clone())).await {
            Ok(Ok(())) => {}
            Ok(Err(error)) => tracing::error!(%error, "probe cycle failed"),
            Err(_) => tracing::error!(
                period_secs = period.as_secs(),
                "probe cycle exceeded its period and was aborted"
            ),
        }
    }
}

/// One scheduling cycle: quarantine dues first (they are time-sensitive),
/// then the priority queue (fresh proxies), then the T1 sample and the
/// T2 batch.
///
/// The lanes that run later skip the rows an earlier lane already gave a
/// verdict (the hand-off), because both sides of each overlap draw from
/// the same population and both charge `fail_count` through
/// `check_failed`: a row drawn by two lanes would collect two `fail_count`
/// steps in one cycle and quarantine in half the cycles `fail_limit`
/// promises. A skipped row loses nothing: the queue's leftovers fall to
/// the sample, and a T1-covered `alive` row is the head of the next
/// cycle's T2 batch (the batch orders by the oldest last T2 check).
async fn run_cycle(ctx: Arc<Context>) -> anyhow::Result<()> {
    let started = tokio::time::Instant::now();
    let cycle = Arc::new(Cycle::new(&ctx.config));
    let now = now_ts();
    // The queue depth before the cycle: a queue that does not drain is
    // invisible in the counters below (quota checked, queue grew anyway)
    let queue_before = probe_repo::queue_depth(&ctx.pool).await.unwrap_or(0);

    // Lanes are independent: a lane that fails is logged and skipped, the
    // rest of the cycle still runs
    let quarantine_started = tokio::time::Instant::now();
    let quarantine = run_lane(
        "quarantine",
        probe_due_quarantine(ctx.clone(), now, cycle.clone()),
    )
    .await;
    let quarantine_ms = quarantine_started.elapsed().as_millis() as u64;

    let queued_started = tokio::time::Instant::now();
    let queued = run_lane("queue", probe_queued_checks(ctx.clone(), cycle.clone())).await;
    let queued_ms = queued_started.elapsed().as_millis() as u64;

    // The rows the lanes before the T2 batch judged: the hand-off that
    // keeps one proxy from being judged twice per cycle. The quarantine
    // lane joins it so a revived row is not tunnel-checked twice in one
    // cycle
    let mut judged = quarantine.claimed.clone();
    judged.extend_from_slice(&queued.claimed);

    let t1_started = tokio::time::Instant::now();
    let t1 = run_lane("t1", probe_t1_sample(ctx.clone(), &judged, cycle.clone())).await;
    let t1_ms = t1_started.elapsed().as_millis() as u64;
    judged.extend_from_slice(&t1.claimed);

    let t2_started = tokio::time::Instant::now();
    let t2 = run_lane("t2", probe_t2_batch(ctx.clone(), &judged, cycle.clone())).await;
    let t2_ms = t2_started.elapsed().as_millis() as u64;

    let queue_after = probe_repo::queue_depth(&ctx.pool).await.unwrap_or(0);
    tracing::info!(
        quarantine_checked = quarantine.checked,
        quarantine_engine_faults = quarantine.engine_faults,
        quarantine_deferred = quarantine.deferred,
        queued_checked = queued.checked,
        queued_blocked = queued.blocked,
        queued_deferred = queued.deferred,
        t1_checked = t1.checked,
        t1_blocked = t1.blocked,
        t1_deferred = t1.deferred,
        t2_checked = t2.checked,
        t2_blocked = t2.blocked,
        t2_aborted = t2.aborted,
        t2_skipped = t2.skipped,
        t2_deferred = t2.deferred,
        t2_engine_faults = t2.engine_faults,
        queue_depth_before = queue_before,
        queue_depth_after = queue_after,
        cycle_ms = started.elapsed().as_millis() as u64,
        quarantine_ms,
        queued_ms,
        t1_ms,
        t2_ms,
        budget_ms = cycle.budget.remaining_ms(),
        budget_exhausted = cycle.budget.expired(),
        quota_remaining =
            cycle.quarantine.remaining() + cycle.coverage.remaining() + cycle.tunnel.remaining(),
        "probe cycle done"
    );
    Ok(())
}

async fn run_lane<T: Default>(
    stage: &'static str,
    lane: impl std::future::Future<Output = anyhow::Result<T>>,
) -> T {
    match lane.await {
        Ok(value) => value,
        Err(error) => {
            tracing::error!(stage, error = ?error, "probe lane failed");
            T::default()
        }
    }
}

/// What one lane covered. `checked` is the verdict count (for the cycle
/// log); `claimed` the rows the lane took for itself this cycle, handed to
/// the lane that runs next so one proxy is never judged twice per cycle
/// (the queue lane claims up-front, the sample claims its verdict rows).
///
/// `blocked` counts the rows the private-address policy refused. They are
/// part of `checked` (a refusal is a failed check and the fail ladder
/// runs), but counted separately: a lane whose verdicts are mostly
/// refusals is a policy problem, not a health problem.
///
/// `deferred` counts the rows the cycle budget did not cover: not a
/// verdict, not charged, not journaled, the next cycle picks them up.
/// `engine_faults` counts the rows the engine never judged (the tunnel
/// lanes only); they are journaled unverified and never charged.
#[derive(Default)]
struct LaneOutcome {
    checked: usize,
    blocked: usize,
    engine_faults: usize,
    deferred: usize,
    claimed: Vec<i64>,
}

impl LaneOutcome {
    fn empty() -> Self {
        Self::default()
    }
}

/// Priority lane: T1 checks the server enqueued at source refresh time for
/// freshly inserted proxies, drained newest first under the coverage quota
/// (shared with the random sample below). Requests are claimed (deleted)
/// up-front, so a mid-batch crash cannot turn them into an endless retry
/// loop; leftovers fall back to the random sample below.
async fn probe_queued_checks(ctx: Arc<Context>, cycle: Arc<Cycle>) -> anyhow::Result<LaneOutcome> {
    // First lane of the coverage group: half the quota, so the random
    // sample still gets a share
    let quota = cycle
        .coverage
        .take_first(ctx.config.probe.sample_size as usize);
    let candidates = probe_repo::select_queued_checks(&ctx.pool, as_limit(quota)).await?;
    if candidates.is_empty() {
        return Ok(LaneOutcome::empty());
    }
    let ids: Vec<i64> = candidates.iter().map(|c| c.id).collect();
    probe_repo::claim_checks(&ctx.pool, &ids).await?;
    let mut checked = run_t1_checks(ctx, candidates, cycle, T1Lane::Regular).await?;
    checked.claimed = ids;
    Ok(checked)
}

/// Probe a random sample of `unknown`/`alive` proxies, minus the rows
/// `already_checked` covered earlier this cycle (see [`run_cycle`]).
/// Dropping the overlap simply leaves the sample slightly smaller.
/// Returns the rows it gave a verdict: the hand-off the T2 batch of the
/// same cycle skips (see [`probe_t2_batch`]).
async fn probe_t1_sample(
    ctx: Arc<Context>,
    already_checked: &[i64],
    cycle: Arc<Cycle>,
) -> anyhow::Result<LaneOutcome> {
    let quota = cycle.coverage.take(ctx.config.probe.sample_size as usize);
    let candidates = proxies::select_t1_candidates(&ctx.pool, as_limit(quota)).await?;
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
    run_t1_checks(ctx, candidates, cycle, T1Lane::Regular).await
}

/// Upper bound of an externally sourced reason in a log line or a journal
/// row (bytes, escapes included): long enough for real engine or policy
/// messages, short enough that one crafted value cannot flood either.
const MAX_REASON_LEN: usize = 300;

/// Replace every control character of an externally sourced text with a
/// visible escape and cap the length. Feed- and engine-controlled texts
/// (a stored scheme, a host, the body of a delay-test error) used to
/// reach the log and `probe_results.error` verbatim: a crafted value
/// could forge log lines or park a terminal in a weird mode. The
/// replacement keeps the reason readable (a `\r` becomes `\u{d}`) and
/// bounded, and the same cleaned text goes to both sinks, so the log line
/// and the journal row never disagree.
fn sanitize_reason(text: &str) -> String {
    let mut cleaned = String::with_capacity(text.len().min(MAX_REASON_LEN));
    let mut truncated = false;
    for character in text.chars() {
        let escaped = if character.is_control() {
            format!("\\u{{{:x}}}", character as u32)
        } else {
            character.to_string()
        };
        if cleaned.len() + escaped.len() > MAX_REASON_LEN {
            truncated = true;
            break;
        }
        cleaned.push_str(&escaped);
    }
    if truncated {
        cleaned.push('…');
    }
    cleaned
}

/// The second-chance window of the fail ladder, in seconds: the minimum
/// wait and the jitter spread, both clamped for the SQL binds. Written
/// once because three lanes read the same pair.
fn second_chance_bounds(probe: &fumox_core::config::ProbeConfig) -> (i64, i64) {
    let min_secs =
        i64::try_from(probe.second_chance_min_hours.saturating_mul(3600)).unwrap_or(i64::MAX);
    let spread_secs =
        i64::try_from(probe.second_chance_spread_hours.saturating_mul(3600)).unwrap_or(0);
    (min_secs, spread_secs)
}

/// The fields of a candidate row the shared T1 pipeline reads: the queue
/// lane, the random sample and the quarantine recheck keep their row
/// types and share the pipeline (see [`run_t1_checks`]).
trait T1Source {
    fn probe_id(&self) -> i64;
    fn probe_scheme(&self) -> &str;
    fn probe_host(&self) -> &str;
    fn probe_port(&self) -> i64;
    /// The entry the stored columns describe; `Err` when the stored
    /// parameters do not parse.
    fn probe_entry(&self) -> fumox_core::Result<ProxyEntry>;
    /// The quarantine ladder step the row waits on; `None` outside the
    /// quarantine lane.
    fn ladder_step(&self) -> Option<i64> {
        None
    }
}

impl T1Source for proxies::T1Candidate {
    fn probe_id(&self) -> i64 {
        self.id
    }
    fn probe_scheme(&self) -> &str {
        &self.scheme
    }
    fn probe_host(&self) -> &str {
        &self.host
    }
    fn probe_port(&self) -> i64 {
        self.port
    }
    fn probe_entry(&self) -> fumox_core::Result<ProxyEntry> {
        self.to_entry()
    }
}

impl T1Source for proxies::DueQuarantine {
    fn probe_id(&self) -> i64 {
        self.id
    }
    fn probe_scheme(&self) -> &str {
        &self.scheme
    }
    fn probe_host(&self) -> &str {
        &self.host
    }
    fn probe_port(&self) -> i64 {
        self.port
    }
    fn probe_entry(&self) -> fumox_core::Result<ProxyEntry> {
        self.to_entry()
    }
    fn ladder_step(&self) -> Option<i64> {
        Some(self.ladder_step)
    }
}

/// Which T1 lane a batch belongs to: names the aggregated refusal line and
/// picks the failure handler and the skip-warning wording.
#[derive(Clone, Copy, PartialEq, Eq)]
enum T1Lane {
    /// The coverage lanes (priority queue, random sample): a failure
    /// charges the regular fail ladder.
    Regular,
    /// The quarantine recheck: a failure advances the recheck ladder step
    /// the row sits on.
    Quarantine,
}

impl T1Lane {
    fn refusals_lane(self) -> &'static str {
        match self {
            T1Lane::Regular => "T1",
            T1Lane::Quarantine => "quarantine recheck",
        }
    }

    /// What happens to a row this lane skips (an unknown scheme, an
    /// out-of-range port, unparseable parameters): on the quarantine lane
    /// the skip is a failed recheck, the row can never converge otherwise,
    /// so the ladder advances; on the regular lanes a skipped row simply
    /// stays due.
    fn skip_note(self) -> &'static str {
        match self {
            T1Lane::Regular => "the row stays due and is retried every cycle",
            T1Lane::Quarantine => {
                "the recheck ladder advances, removal after the last configured step"
            }
        }
    }
}

/// Run concurrent T1 checks for the candidates and apply each outcome to
/// the lifecycle. The shared body of the three T1 lanes: parse and port
/// gates, the check kind, the vetting pass, the spawned checks and the
/// counters are written once here; the lanes differ in their row types
/// and in the failure handler (see [`T1Lane`]). Returns the verdict count
/// plus the ids of every row a verdict was produced for, vet-refused rows
/// included and on the quarantine lane also the gate skips (whose skip is
/// a failed recheck; on the regular lanes a skipped row stays due).
async fn run_t1_checks<R: T1Source + Send + Sync + 'static>(
    ctx: Arc<Context>,
    candidates: Vec<R>,
    cycle: Arc<Cycle>,
    lane: T1Lane,
) -> anyhow::Result<LaneOutcome> {
    let semaphore = Arc::new(Semaphore::new(ctx.config.probe.concurrency.max(1)));
    // Parse and port gates first, so the vetting pass below only covers
    // rows that can actually be dialed
    let T1Gated {
        ready,
        mut checked_ids,
        rejected,
    } = gate_t1_candidates(&ctx, candidates, lane).await;
    let (mut tasks, blocked, refusals) =
        spawn_t1_checks(ctx, cycle, lane, semaphore, ready, &mut checked_ids).await;
    // A task that ran returns the id it judged; a task the budget deferred
    // returns nothing and is counted apart (no verdict, no charge)
    let mut checked = blocked + rejected;
    let mut deferred = 0usize;
    while let Some(result) = tasks.join_next().await {
        match result {
            Ok(Some(id)) => {
                checked += 1;
                checked_ids.push(id);
            }
            Ok(None) => deferred += 1,
            Err(error) => tracing::warn!(%error, "T1 check task panicked"),
        }
    }
    log_refusals(lane.refusals_lane(), blocked, &refusals);
    Ok(LaneOutcome {
        checked,
        blocked,
        engine_faults: 0,
        deferred,
        claimed: checked_ids,
    })
}

/// The rows of one T1 batch that passed the parse and port gates, plus
/// the verdicts the gates themselves produced: on the quarantine lane a
/// skip is a failed recheck and counts into the hand-off (see
/// [`run_t1_checks`]).
struct T1Gated<R> {
    /// The rows that can be dialed: the candidate, its check kind, the
    /// clamped port and the SNI the handshake presents.
    ready: Vec<(R, t1::CheckKind, u16, Option<String>)>,
    /// Ids of the rows a verdict was produced for so far: gate skips, vet
    /// refusals, judged rows (see [`run_t1_checks`]).
    checked_ids: Vec<i64>,
    /// How many quarantine-lane skips there are; a regular-lane skip is
    /// no verdict.
    rejected: usize,
}

impl<R> T1Gated<R> {
    fn new() -> Self {
        Self {
            ready: Vec::new(),
            checked_ids: Vec::new(),
            rejected: 0,
        }
    }

    /// Journal one gate skip on the quarantine lane, where the skip is a
    /// failed recheck; a regular-lane skip stays due and is not counted.
    async fn skip(
        &mut self,
        ctx: &Context,
        id: i64,
        ladder_step: Option<i64>,
        lane: T1Lane,
        reason: &str,
    ) {
        if let T1Lane::Quarantine = lane {
            reject_unverifiable_quarantine_row(ctx, id, ladder_step.unwrap_or(0), reason).await;
            self.rejected += 1;
            self.checked_ids.push(id);
        }
    }
}

/// Apply the parse and port gates to every candidate: a skipped row gets
/// a warn line naming the next step, and on the quarantine lane the skip
/// is a journaled failed recheck.
async fn gate_t1_candidates<R: T1Source>(
    ctx: &Context,
    candidates: Vec<R>,
    lane: T1Lane,
) -> T1Gated<R> {
    let mut gated = T1Gated::new();
    for candidate in candidates {
        let id = candidate.probe_id();
        let (scheme, port, entry) = match gate_t1_row(&candidate) {
            Ok(parts) => parts,
            Err(skip) => {
                report_gate_skip(&mut gated, ctx, id, &candidate, lane, skip).await;
                continue;
            }
        };
        let kind = t1::check_kind(scheme, &entry);
        // The name the handshake presents: the node's own SNI, else the
        // stored host
        let server_name = fumox_core::params::sni(&entry);
        gated.ready.push((candidate, kind, port, server_name));
    }
    gated
}

/// One parse/port gate refusal of a T1 candidate: the row cannot be
/// dialed at all.
enum GateSkip {
    UnknownScheme(String),
    PortOutOfRange(i64),
    UnparseableParameters,
}

impl GateSkip {
    fn reason(&self) -> String {
        match self {
            GateSkip::UnknownScheme(scheme) => {
                format!("unknown scheme: {}", sanitize_reason(scheme))
            }
            GateSkip::PortOutOfRange(port) => format!("port out of range: {port}"),
            GateSkip::UnparseableParameters => "stored parameters do not parse".to_string(),
        }
    }
}

/// Apply the parse and port gates to one candidate: `Ok` carries the
/// scheme, the clamped port and the parsed entry; `Err` names the gate
/// that refused the row.
fn gate_t1_row<R: T1Source>(candidate: &R) -> Result<(Scheme, u16, ProxyEntry), GateSkip> {
    let scheme = candidate
        .probe_scheme()
        .parse::<Scheme>()
        .map_err(|_| GateSkip::UnknownScheme(candidate.probe_scheme().to_string()))?;
    let port = u16::try_from(candidate.probe_port())
        .map_err(|_| GateSkip::PortOutOfRange(candidate.probe_port()))?;
    let entry = candidate
        .probe_entry()
        .map_err(|_| GateSkip::UnparseableParameters)?;
    Ok((scheme, port, entry))
}

/// Report one gate skip with its lane-specific note, and journal it on
/// the quarantine lane where the skip is a failed recheck (see
/// [`T1Gated::skip`]).
async fn report_gate_skip<R: T1Source>(
    gated: &mut T1Gated<R>,
    ctx: &Context,
    id: i64,
    candidate: &R,
    lane: T1Lane,
    skip: GateSkip,
) {
    warn_gate_skip(id, lane.skip_note(), &skip);
    let reason = skip.reason();
    gated
        .skip(ctx, id, candidate.ladder_step(), lane, &reason)
        .await;
}

fn warn_gate_skip(id: i64, note: &'static str, skip: &GateSkip) {
    match skip {
        GateSkip::UnknownScheme(scheme) => {
            tracing::warn!(
                id,
                scheme = %sanitize_reason(scheme),
                "unknown scheme, skipped; {note}"
            );
        }
        GateSkip::PortOutOfRange(port) => {
            tracing::warn!(id, port, "port out of range, skipped; {note}");
        }
        GateSkip::UnparseableParameters => {
            tracing::warn!(id, "stored parameters do not parse, skipped; {note}");
        }
    }
}

/// Vet the dial hosts of a gated T1 batch and spawn one check task per
/// vet-passed row. A vet refusal is journaled as a failed check on the
/// lane's own ladder (see [`apply_t1_vet_block`]) and its id joins the
/// hand-off. Returns the tasks, the refusal count and the aggregated
/// refusal reasons (see [`log_refusals`]).
async fn spawn_t1_checks<R: T1Source + Send + Sync + 'static>(
    ctx: Arc<Context>,
    cycle: Arc<Cycle>,
    lane: T1Lane,
    semaphore: Arc<Semaphore>,
    ready: Vec<(R, t1::CheckKind, u16, Option<String>)>,
    checked_ids: &mut Vec<i64>,
) -> (
    tokio::task::JoinSet<Option<i64>>,
    usize,
    std::collections::HashMap<String, usize>,
) {
    let hosts: Vec<String> = ready
        .iter()
        .map(|(candidate, _, _, _)| candidate.probe_host().to_string())
        .collect();
    let mut tasks = tokio::task::JoinSet::new();
    let mut blocked = 0usize;
    let mut refusals: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
    for ((candidate, kind, port, server_name), verdict) in ready
        .into_iter()
        .zip(vet_hosts(&ctx, &hosts, &cycle.vetted).await)
    {
        let id = candidate.probe_id();
        let vetted = match verdict {
            Ok(addrs) => addrs,
            Err(reason) => {
                // Per row a debug line; the batch reports the refusals in
                // one aggregated warning below
                let reason = sanitize_reason(&reason);
                tracing::debug!(
                    lane = lane.refusals_lane(),
                    id,
                    %reason,
                    "probe target blocked by the private-address policy, journaled as a failed check"
                );
                *refusals.entry(reason.clone()).or_insert(0) += 1;
                apply_t1_vet_block(
                    &ctx,
                    id,
                    kind.as_str(),
                    candidate.ladder_step().unwrap_or(0),
                    &reason,
                    lane,
                )
                .await;
                checked_ids.push(id);
                blocked += 1;
                continue;
            }
        };
        let step = candidate.ladder_step();
        let delays = ctx.config.probe.recheck_delays_secs.clone();
        let (ctx, semaphore) = (ctx.clone(), semaphore.clone());
        let budget = cycle.budget.clone();
        tasks.spawn(async move {
            // `acquire_owned` is infallible: the semaphore lives in this
            // scope and is dropped only after the join loop below awaits
            // every spawned task, so it cannot close while a task awaits
            // a permit
            let _permit = match semaphore.acquire_owned().await {
                Ok(permit) => permit,
                Err(_) => return None,
            };
            // The budget may have expired while this task waited for its
            // turn: the row is not checked, not charged, not journaled
            if budget.expired() {
                return None;
            }
            let target = t1::Target {
                host: candidate.probe_host(),
                server_name: server_name.as_deref(),
                port,
                kind,
                vetted: &vetted,
            };
            run_t1_lane_check(&ctx, id, &target, step.unwrap_or(0), &delays, lane).await;
            Some(id)
        });
    }
    (tasks, blocked, refusals)
}

async fn run_t1_lane_check(
    ctx: &Context,
    id: i64,
    target: &t1::Target<'_>,
    step: i64,
    delays: &[i64],
    lane: T1Lane,
) {
    match lane {
        T1Lane::Regular => perform_t1_check(ctx, id, target).await,
        T1Lane::Quarantine => perform_quarantine_check(ctx, id, target, step, delays).await,
    }
}

/// Apply a vet refusal on the lane's own ladder: a failed regular check,
/// or an advanced recheck ladder on the quarantine lane.
async fn apply_t1_vet_block(
    ctx: &Context,
    id: i64,
    probe_kind: &str,
    step: i64,
    reason: &str,
    lane: T1Lane,
) {
    match lane {
        T1Lane::Regular => apply_vet_block(ctx, id, probe_kind, reason).await,
        T1Lane::Quarantine => apply_quarantine_vet_block(ctx, id, probe_kind, step, reason).await,
    }
}

/// Report the private-address refusals of one batch in a single line: a
/// feed full of internal targets produces one refusal per row, and a
/// warning each drowned the batch summary the operator reads.
fn log_refusals(lane: &str, blocked: usize, refusals: &std::collections::HashMap<String, usize>) {
    if blocked == 0 {
        return;
    }
    let mut reasons: Vec<(&String, &usize)> = refusals.iter().collect();
    reasons.sort_by(|a, b| b.1.cmp(a.1).then_with(|| a.0.cmp(b.0)));
    tracing::warn!(
        lane,
        blocked,
        reasons = ?reasons,
        "probe targets refused by the private-address policy, journaled as failed checks"
    );
}

/// SSRF gate for every dial target: proxy hosts come from remote feeds, so
/// each candidate must pass the shared address policy before the daemon
/// opens a connection to it. Loopback, RFC1918, link-local (cloud
/// metadata), CGNAT and unique-local addresses are refused unless
/// `[probe].allow_private_targets` is set.
///
/// Async because the DNS lookup is async: the runtime worker is never
/// blocked while the OS resolver runs.
async fn vet_target_addrs(ctx: &Context, host: &str) -> Result<Vec<std::net::IpAddr>, String> {
    fumox_core::ssrf::vet_probe_host_addrs(
        host,
        ctx.config.probe.allow_private_targets,
        ctx.config.ssrf_dns_timeout(),
    )
    .await
}

/// Vet every host concurrently, preserving the input order.
///
/// A host is resolved once per cycle: the rows of a feed often share their
/// host, and the T2 batch of a cycle reuses what the T1 lanes of the same
/// cycle vetted. Each vetting pass is a DNS lookup bounded by `dns_timeout`
/// (5 s by default); concurrency is bounded by `probe.concurrency`, the
/// same budget the checks themselves run under.
async fn vet_hosts(ctx: &Arc<Context>, hosts: &[String], cache: &CycleVet) -> Vec<VetVerdict> {
    let mut unique: Vec<String> = Vec::with_capacity(hosts.len());
    let mut positions: std::collections::HashMap<&str, usize> = std::collections::HashMap::new();
    let mut rows: Vec<usize> = Vec::with_capacity(hosts.len());
    for host in hosts {
        let index = *positions.entry(host.as_str()).or_insert_with(|| {
            unique.push(host.clone());
            unique.len() - 1
        });
        rows.push(index);
    }

    let mut pending: Vec<(usize, String)> = Vec::new();
    let mut verdicts: Vec<Option<std::sync::Arc<VetVerdict>>> =
        (0..unique.len()).map(|_| None).collect();
    for (index, host) in unique.iter().enumerate() {
        match cache.get(host) {
            Some(verdict) => verdicts[index] = Some(verdict),
            None => pending.push((index, host.clone())),
        }
    }

    if !pending.is_empty() {
        let semaphore = Arc::new(Semaphore::new(ctx.config.probe.concurrency.max(1)));
        let mut tasks = tokio::task::JoinSet::new();
        for (index, host) in pending {
            let (ctx, semaphore) = (ctx.clone(), semaphore.clone());
            tasks.spawn(async move {
                let _permit = match semaphore.acquire_owned().await {
                    Ok(permit) => permit,
                    // Structurally impossible: the semaphore lives in this
                    // scope and cannot close before the join loop below
                    Err(_) => return (index, Err("vetting lane closed".to_string())),
                };
                (index, vet_target_addrs(&ctx, &host).await)
            });
        }
        while let Some(joined) = tasks.join_next().await {
            match joined {
                Ok((index, verdict)) => {
                    let verdict = std::sync::Arc::new(verdict);
                    cache.put(&unique[index], verdict.clone());
                    verdicts[index] = Some(verdict);
                }
                Err(error) => tracing::warn!(%error, "vetting task panicked"),
            }
        }
    }

    rows.into_iter()
        .map(|index| {
            // A panicked task leaves a hole; refusing the target keeps the
            // row on the ordinary fail ladder instead of buffering it
            match verdicts[index].as_deref() {
                Some(Ok(addrs)) => Ok(addrs.clone()),
                Some(Err(reason)) => Err(reason.clone()),
                None => Err("vetting task panicked".to_string()),
            }
        })
        .collect()
}

/// A vet-refused target is a *failed check*, not a skip: the policy blocks
/// exactly what a dead proxy looks like (unresolvable names, internal
/// addresses), so the attempt is journaled into `probe_results` with the
/// refusal reason and the fail ladder runs. Silently skipping these let
/// blocked rows clog the head of the T2 recency queue forever (they never
/// got a t2 row to advance past). The journal write is best-effort: the
/// lifecycle transition is the source of truth.
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

/// The TCP-connect and TLS-handshake timeouts of one T1 probe, each
/// clamped to at least one second.
fn t1_timeouts(probe: &fumox_core::config::ProbeConfig) -> (Duration, Duration) {
    (
        Duration::from_secs(probe.connect_timeout_secs.max(1)),
        Duration::from_secs(probe.tls_timeout_secs.max(1)),
    )
}

/// Run one T1 check and apply the outcome to the lifecycle: journal the
/// attempt into `probe_results`, then move the state machine. `vetted`
/// carries the SSRF-approved dial addresses (see [`vet_target_addrs`]).
async fn perform_t1_check(ctx: &Context, id: i64, target: &t1::Target<'_>) {
    let (connect_timeout, tls_timeout) = t1_timeouts(&ctx.config.probe);
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
            // the quarantine ladder. Conservative on lookup errors: keep it
            // `t2_unverified` counts as a T2-tier attempt too: the row was
            // never judged, so an earlier T2 failure may still be unpaid
            let reset = match probe_repo::last_failed_kind(&ctx.pool, id).await {
                Ok(kind) => !kind.as_deref().is_some_and(probe_repo::is_t2_kind),
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
                // its verification (only a failed T2 demotes it)
                fumox_core::models::ProxyStatus::Alive,
            )
            .await
            {
                tracing::warn!(id, %error, "failed to record T1 success");
            }
        }
        Err(reason) => {
            // The reason names the dial target and the handshake error,
            // both feed-controlled: sanitize before it reaches the log
            // and the journal
            let reason = sanitize_reason(&reason);
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

async fn apply_regular_failure(ctx: &Context, id: i64, now: i64) {
    let probe = &ctx.config.probe;
    let (min_secs, spread_secs) = second_chance_bounds(probe);
    // A closed TCP/TLS port says nothing about the tunnel, so the
    // T1-suppression flag stays off (see `proxies::check_failed`, which
    // takes an explicit `mark_t2_failed` argument for that reason)
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
/// tunnel check ([`revive_quarantined_via_t2`]), a T1 connect cannot
/// succeed against a QUIC port; everything else walks the shared T1
/// pipeline (see [`run_t1_checks`]). Returns the counters of both lanes
/// plus the ids every verdict was produced for, the hand-off the T1 and
/// T2 lanes of the same cycle skip (see [`run_cycle`]).
async fn probe_due_quarantine(
    ctx: Arc<Context>,
    now: i64,
    cycle: Arc<Cycle>,
) -> anyhow::Result<LaneOutcome> {
    // First lane of the tunnel group: half the quota, so the regular T2
    // batch of the cycle still gets a share
    let revival_quota = cycle
        .tunnel
        .take_first(ctx.config.probe.sample_size as usize);
    let t2_due = proxies::select_due_quarantine_t2(&ctx.pool, now, as_limit(revival_quota)).await?;
    let revived = revive_quarantined_via_t2(ctx.clone(), t2_due, cycle.clone()).await?;
    // The recheck ladder has its own quota: the quarantine drain is what
    // the admin panel reports and must not compete with the coverage lanes
    let recheck_quota = cycle.quarantine.take(ctx.config.probe.sample_size as usize);
    let due = proxies::select_due_quarantine(&ctx.pool, now, as_limit(recheck_quota)).await?;
    let rechecked = run_t1_checks(ctx, due, cycle, T1Lane::Quarantine).await?;
    let mut claimed = rechecked.claimed;
    claimed.extend_from_slice(&revived.claimed);
    Ok(LaneOutcome {
        checked: rechecked.checked + revived.checked,
        blocked: rechecked.blocked + revived.blocked,
        engine_faults: rechecked.engine_faults + revived.engine_faults,
        deferred: rechecked.deferred + revived.deferred,
        claimed,
    })
}

/// T2 revival lane for the quarantined rows T1 cannot judge
/// ([`proxies::T2_REVIVAL_SCHEMES`]): their second chance is a real tunnel
/// check through meow-rs. Success revives into the `ready` tier, an
/// authoritative tunnel failure advances the recheck ladder, a meow-rs
/// fault is journaled unverified and leaves the row due: an outage must
/// not retire a healthy proxy (see [`journal_engine_fault`]). Returns the
/// counters of the batch plus the ids of every row it judged, the
/// hand-off the T1 and T2 lanes of the same cycle skip.
async fn revive_quarantined_via_t2(
    ctx: Arc<Context>,
    due: Vec<proxies::ProxyRow>,
    cycle: Arc<Cycle>,
) -> anyhow::Result<LaneOutcome> {
    if due.is_empty() {
        return Ok(LaneOutcome::empty());
    }
    let now = now_ts();
    if now < ctx.meow_retry_at.load(Ordering::Relaxed) {
        tracing::debug!(
            retry_at = ctx.meow_retry_at.load(Ordering::Relaxed),
            backoff_secs = ctx.meow_backoff_secs.load(Ordering::Relaxed),
            "meow-rs in backoff, quarantine revival skipped"
        );
        return Ok(LaneOutcome::empty());
    }
    let outcome = run_t2_tunnel_batch(ctx, due, cycle, TunnelLane::Revival).await?;
    // A row the guard kept away from the engine was still journaled
    // (unverified), so it shows in `checked` next to the verdict rows
    Ok(LaneOutcome {
        checked: outcome.checked + outcome.aborted,
        blocked: outcome.blocked,
        engine_faults: outcome.engine_faults,
        deferred: outcome.deferred,
        claimed: outcome.claimed,
    })
}

/// The tunnel lanes of the cycle: they share the whole batch machinery
/// (vetting, required-field validation, engine-config preparation with
/// the split retry, reload, spawned checks, batch-end fault
/// classification) and differ only in the two handlers (a vet refusal, a
/// record the config cannot carry) and in how a settled tunnel failure is
/// charged.
#[derive(Clone, Copy)]
enum TunnelLane {
    /// The regular T2 batch: a tunnel failure charges the regular fail
    /// ladder and stamps the T2 suppression flag.
    T2 {
        fail_limit: u32,
        min_secs: i64,
        spread_secs: i64,
    },
    /// The quarantine revival: a tunnel failure advances the recheck
    /// ladder step the row sits on.
    Revival,
}

impl TunnelLane {
    fn refusals_lane(self) -> &'static str {
        match self {
            TunnelLane::T2 { .. } => "T2",
            TunnelLane::Revival => "quarantine revival",
        }
    }
}

/// What one tunnel batch (regular T2, a quarantine revival, or one split
/// half of either) produced. `checked` counts rows that got a real verdict
/// (an engine contact or a policy refusal, both journaled); `aborted` rows
/// the mid-batch guard kept away from meow-rs; `skipped` rows the config
/// could not carry; `blocked` the private-address refusals;
/// `engine_faults` rows the engine never judged (journaled unverified,
/// never charged); `deferred` rows the cycle budget spent. `claimed`
/// carries the ids of the judged rows: the hand-off the lanes of the same
/// cycle skip.
#[derive(Default)]
struct TunnelOutcome {
    checked: usize,
    aborted: usize,
    skipped: usize,
    blocked: usize,
    engine_faults: usize,
    deferred: usize,
    claimed: Vec<i64>,
}

impl TunnelOutcome {
    fn merge(&mut self, other: TunnelOutcome) {
        self.checked += other.checked;
        self.aborted += other.aborted;
        self.skipped += other.skipped;
        self.blocked += other.blocked;
        self.engine_faults += other.engine_faults;
        self.deferred += other.deferred;
        self.claimed.extend(other.claimed);
    }
}

/// Per-task result of a tunnel batch. `Judged` contacted the engine and
/// carries the id for the hand-off; `Ran` contacted the engine but it
/// never judged the row (classified by the one batch-level ping);
/// `Aborted` took the guard's early return without a request; `Deferred`
/// was never started, the cycle ran out of budget.
#[derive(Clone, Copy)]
enum TunnelTask {
    Judged(i64),
    Ran,
    Aborted,
    Deferred,
}

/// The tunnel batch runner shared by the regular T2 batch and the
/// quarantine revival (see [`TunnelLane`]): vet → validate → generate →
/// write → reload → spawn → collect.
async fn run_t2_tunnel_batch(
    ctx: Arc<Context>,
    due: Vec<proxies::ProxyRow>,
    cycle: Arc<Cycle>,
    lane: TunnelLane,
) -> anyhow::Result<TunnelOutcome> {
    // The SSRF gate first: a refused target is a failed check, as in the T1 lanes
    let (batch, pins, blocked, mut claimed) =
        vet_tunnel_batch(&ctx, due, lane, &cycle.vetted).await;

    // The engine refuses a config whose proxy lacks its credential, and
    // one such record voids the whole batch at `PUT /configs`: validate
    // the required fields here and reject the record on the lane's own
    // ladder instead of handing it to the engine
    let (batch, skipped, skipped_ids) = validate_tunnel_batch(&ctx, batch, lane).await;
    claimed.extend(skipped_ids);
    if batch.is_empty() {
        return Ok(TunnelOutcome {
            checked: blocked,
            blocked,
            skipped,
            claimed,
            ..TunnelOutcome::default()
        });
    }

    // The controller name is re-vetted like the batch targets above
    // (`vet_hosts`): DNS changes while the daemon runs, and a name that
    // has started resolving into public address space must not receive
    // the bearer token every request below carries. A refused batch is an
    // engine fault, not a proxy verdict
    if let Err(error) = ctx.meow.verify_address(ctx.config.ssrf_dns_timeout()).await {
        tracing::warn!(
            %error,
            "meow-rs controller host no longer vetted, the tunnel batch failed with backoff"
        );
        ctx.backoff_meow().await;
        journal_engine_failure(
            &ctx,
            &batch,
            &format!("meow-rs controller address refused: {error}"),
        )
        .await;
        return Ok(TunnelOutcome {
            checked: blocked,
            aborted: batch.len(),
            blocked,
            skipped,
            engine_faults: batch.len(),
            claimed,
            ..TunnelOutcome::default()
        });
    }

    // Cheap liveness check first: no point rewriting the config file when
    // the service is down. An outage stamps the whole batch unverified
    // (no fail budget) and backs off
    if let Err(error) = ctx.meow.alive().await {
        let error = sanitize_reason(&error);
        tracing::warn!(%error, "meow-rs unavailable, the tunnel batch failed with backoff");
        ctx.backoff_meow().await;
        journal_engine_failure(&ctx, &batch, &format!("meow-rs unavailable: {error}")).await;
        return Ok(TunnelOutcome {
            checked: blocked,
            aborted: batch.len(),
            blocked,
            skipped,
            engine_faults: batch.len(),
            claimed,
            ..TunnelOutcome::default()
        });
    }

    let mut outcome = run_tunnel_reload(ctx, batch, &pins, cycle, lane).await?;
    outcome.checked += blocked;
    outcome.blocked = blocked;
    outcome.skipped += skipped;
    outcome.claimed.extend(claimed);
    Ok(outcome)
}

/// Vet the dial targets of a tunnel batch and split it into vet-passed
/// rows (with their pinned vetted address) and vet-refused rows, journaled
/// as a failed check on the lane's own ladder (see
/// [`charge_tunnel_vet_refusal`]). Returns the batch, the vetted address
/// pins, the refusal count and the refused ids (the cycle hand-off).
async fn vet_tunnel_batch(
    ctx: &Arc<Context>,
    due: Vec<proxies::ProxyRow>,
    lane: TunnelLane,
    cache: &CycleVet,
) -> (
    Vec<proxies::ProxyRow>,
    std::collections::HashMap<String, std::net::IpAddr>,
    usize,
    Vec<i64>,
) {
    let hosts: Vec<String> = due.iter().map(|row| row.host.clone()).collect();
    let mut pins: std::collections::HashMap<String, std::net::IpAddr> =
        std::collections::HashMap::new();
    let mut batch: Vec<proxies::ProxyRow> = Vec::with_capacity(due.len());
    let mut refused_ids: Vec<i64> = Vec::new();
    let mut blocked = 0usize;
    let mut refusals: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
    for (row, verdict) in due.into_iter().zip(vet_hosts(ctx, &hosts, cache).await) {
        match verdict {
            Ok(vetted) => {
                if let Some(ip) =
                    fumox_core::ssrf::pick_vetted(&vetted, fumox_core::models::IpFamily::Any)
                {
                    // The batch is deduplicated by `row.id` upstream
                    // (`proxies::select_t2_candidates`), so two rows that
                    // share a hostname overwrite the same pin entry
                    pins.insert(row.host.clone(), ip);
                }
                batch.push(row);
            }
            Err(reason) => {
                let reason = sanitize_reason(&reason);
                tracing::debug!(id = row.id, %reason, "tunnel target blocked by the private-address policy, journaled as a failed check");
                *refusals.entry(reason.clone()).or_insert(0) += 1;
                charge_tunnel_vet_refusal(ctx, row.id, row.ladder_step, &reason, lane).await;
                refused_ids.push(row.id);
                blocked += 1;
            }
        }
    }
    log_refusals(lane.refusals_lane(), blocked, &refusals);
    (batch, pins, blocked, refused_ids)
}

async fn charge_tunnel_vet_refusal(
    ctx: &Context,
    id: i64,
    ladder_step: i64,
    reason: &str,
    lane: TunnelLane,
) {
    match lane {
        TunnelLane::T2 { .. } => {
            journal_and_fail(
                ctx,
                id,
                &format!("blocked by the private-address policy: {reason}"),
            )
            .await;
        }
        TunnelLane::Revival => {
            apply_quarantine_vet_block(ctx, id, T2_KIND, ladder_step, reason).await;
        }
    }
}

/// Validate the required fields of a tunnel batch: the engine refuses a
/// config whose proxy lacks its credential, and one such record voids the
/// whole batch at `PUT /configs`. A record the config cannot carry is
/// rejected on the lane's own ladder (see [`charge_tunnel_record`]), the
/// rest goes to the engine. Returns the validated rows, the skip count
/// and the skipped ids (the hand-off).
async fn validate_tunnel_batch(
    ctx: &Context,
    batch: Vec<proxies::ProxyRow>,
    lane: TunnelLane,
) -> (Vec<proxies::ProxyRow>, usize, Vec<i64>) {
    let mut skipped = 0usize;
    let mut skipped_ids: Vec<i64> = Vec::new();
    let mut validated: Vec<proxies::ProxyRow> = Vec::with_capacity(batch.len());
    for row in batch {
        let Some(problem) = row
            .to_entry()
            .ok()
            .and_then(|entry| clash::required_field_problem(&entry))
        else {
            validated.push(row);
            continue;
        };
        skipped += 1;
        skipped_ids.push(row.id);
        let reason = format!("proxy entry cannot run in the tunnel engine config: {problem}");
        charge_tunnel_record(ctx, row.id, row.ladder_step, &reason, lane).await;
    }
    (validated, skipped, skipped_ids)
}

async fn charge_tunnel_record(
    ctx: &Context,
    id: i64,
    ladder_step: i64,
    reason: &str,
    lane: TunnelLane,
) {
    match lane {
        TunnelLane::T2 { .. } => journal_and_fail(ctx, id, reason).await,
        TunnelLane::Revival => reject_quarantine_record(ctx, id, ladder_step, reason).await,
    }
}

/// Prepare the engine config of one (sub-)batch, reload the engine, and
/// run the checks of the batch. A `PUT /configs` refusal splits the batch
/// in half and retries each half: the probe cannot know which record the
/// engine objected to, and one bad record must not void the verdicts of
/// the rest. The recursion bottoms out at a single row, journaled
/// unverified with the reload error, so a split costs at most log2(n)
/// reload attempts. A genuinely down engine never gets this far (the
/// liveness gate above refuses the batch).
async fn run_tunnel_reload(
    ctx: Arc<Context>,
    batch: Vec<proxies::ProxyRow>,
    pins: &std::collections::HashMap<String, std::net::IpAddr>,
    cycle: Arc<Cycle>,
    lane: TunnelLane,
) -> anyhow::Result<TunnelOutcome> {
    let generated = match prepare_engine_config(&ctx, &batch, pins, lane) {
        Ok(generated) => generated,
        Err(error) => return Ok(fail_tunnel_batch_prepare(&ctx, batch, error).await),
    };
    let included = generated.included;
    // The lanes the speed plan rendered; a lane whose delay check fails
    // simply goes unused this cycle
    let speed_lanes: std::collections::HashMap<i64, u16> =
        generated.speed_lanes.into_iter().collect();
    if !speed_lanes.is_empty() {
        tracing::debug!(
            lanes = speed_lanes.len(),
            "speed measurement listeners rendered into the batch config"
        );
    }

    if let Err(error) = ctx.meow.reload_config(&ctx.config.meow.config_path).await {
        return split_or_abort_reload(ctx, batch, pins, cycle, lane, error).await;
    }
    stamp_reload_success(&ctx).await;

    // The per-batch decision state: confirmed engine-unavailable events
    // escalate to an abort (see [`BatchGuard`])
    let state = BatchState {
        guard: Arc::new(BatchGuard::new(MEOW_ABORT_THRESHOLD)),
        verdicts: Arc::new(T2Verdicts::new()),
        // Rows the engine never judged (an outage, a refused request or a
        // run of blips), journaled unverified and never charged: the count
        // that tells an engine fault from a dying proxy in the cycle log
        engine_faults: Arc::new(AtomicUsize::new(0)),
        // One test URL for the whole batch, so the verdicts are about the
        // same endpoint
        test_url: ctx.meow.batch_test_url().to_string(),
        // The pinned-listener ports of the speed measurement;
        // empty when speed is disabled or the lane is not T2
        speed_lanes: Arc::new(speed_lanes),
    };
    tracing::debug!(test_url = %state.test_url, "tunnel batch test URL");
    let (tasks, skipped, skipped_ids) =
        spawn_tunnel_checks(&ctx, cycle, lane, batch, &included, &state).await;
    let (checked, aborted, deferred, judged) = collect_tunnel_results(tasks).await;

    classify_unavailable_outcomes(&ctx, &state).await;
    // The batch is over: charge the failed tunnels (or not, when the test
    // endpoint is the suspect), the way the lane's ladder reads them
    match lane {
        TunnelLane::T2 {
            fail_limit,
            min_secs,
            spread_secs,
        } => {
            settle_t2_failures(
                &ctx,
                &state.verdicts,
                &state.test_url,
                fail_limit,
                min_secs,
                spread_secs,
            )
            .await;
        }
        TunnelLane::Revival => {
            settle_revival_failures(&ctx, &state.verdicts, &state.test_url).await
        }
    }
    let mut claimed = skipped_ids;
    claimed.extend(judged);
    Ok(TunnelOutcome {
        checked,
        aborted,
        skipped,
        blocked: 0,
        engine_faults: state.engine_faults.load(Ordering::Relaxed),
        deferred,
        claimed,
    })
}

/// The per-batch decision state of one running tunnel batch, shared with
/// every spawned check task and read again when the batch is over (the
/// outcome classification, the ladder settlement, the cycle log).
struct BatchState {
    guard: Arc<BatchGuard>,
    verdicts: Arc<T2Verdicts>,
    engine_faults: Arc<AtomicUsize>,
    test_url: String,
    /// The pinned-listener ports of the speed measurement, per proxy id.
    /// The plan already caps the lanes at
    /// `[network].speed_concurrency`, so the downloads need no semaphore of
    /// their own.
    speed_lanes: Arc<std::collections::HashMap<i64, u16>>,
}

/// The engine never sees the batch: the rows are journaled unverified (no
/// ladder charge) and the lane backs off, the same treatment as a failed
/// reload.
async fn fail_tunnel_batch_prepare(
    ctx: &Context,
    batch: Vec<proxies::ProxyRow>,
    error: anyhow::Error,
) -> TunnelOutcome {
    let error = sanitize_reason(&error.to_string());
    tracing::warn!(%error, "meow-rs config could not be prepared, the tunnel batch failed with backoff");
    ctx.backoff_meow().await;
    journal_engine_failure(
        ctx,
        &batch,
        &format!("meow-rs config could not be prepared: {error}"),
    )
    .await;
    TunnelOutcome {
        aborted: batch.len(),
        engine_faults: batch.len(),
        ..TunnelOutcome::default()
    }
}

/// Handle a refused config reload: split the batch in half and retry each
/// half (see [`run_tunnel_reload`]), or journal the single row unverified
/// with the reload error and back off.
async fn split_or_abort_reload(
    ctx: Arc<Context>,
    batch: Vec<proxies::ProxyRow>,
    pins: &std::collections::HashMap<String, std::net::IpAddr>,
    cycle: Arc<Cycle>,
    lane: TunnelLane,
    error: String,
) -> anyhow::Result<TunnelOutcome> {
    if batch.len() > 1 {
        let error = sanitize_reason(&error);
        tracing::warn!(
            rows = batch.len(),
            %error,
            "meow-rs refused the config reload, splitting the batch in half"
        );
        let mid = batch.len() / 2;
        // Boxed: the recursion depth is the log2 of the batch size, but
        // the future's size must not depend on itself
        let mut halves = Box::pin(run_tunnel_reload(
            ctx.clone(),
            batch[..mid].to_vec(),
            pins,
            cycle.clone(),
            lane,
        ))
        .await?;
        halves.merge(
            Box::pin(run_tunnel_reload(
                ctx,
                batch[mid..].to_vec(),
                pins,
                cycle,
                lane,
            ))
            .await?,
        );
        return Ok(halves);
    }
    let error = sanitize_reason(&error);
    tracing::warn!(%error, "meow-rs unavailable, the tunnel batch failed with backoff");
    ctx.backoff_meow().await;
    journal_engine_failure(&ctx, &batch, &format!("meow-rs unavailable: {error}")).await;
    Ok(TunnelOutcome {
        aborted: batch.len(),
        engine_faults: batch.len(),
        ..TunnelOutcome::default()
    })
}

async fn stamp_reload_success(ctx: &Context) {
    ctx.meow_recovered().await;
    if let Err(error) = meta_set(
        &ctx.pool,
        probe_repo::meta::MEOW_LAST_OK_KEY,
        &now_ts().to_string(),
    )
    .await
    {
        tracing::warn!(%error, "failed to stamp meow_last_ok");
    }
    stamp_meow_memory(ctx).await;
}

/// Spawn one tunnel check task per row that made it into the generated
/// config. A row the config preparation skipped (its entry could not be
/// serialized) must get the real reason journaled: routing it through the
/// engine would produce a misleading "proxy not found" failure. Returns
/// the tasks, the skip count and the skipped ids.
async fn spawn_tunnel_checks(
    ctx: &Arc<Context>,
    cycle: Arc<Cycle>,
    lane: TunnelLane,
    batch: Vec<proxies::ProxyRow>,
    included: &[i64],
    state: &BatchState,
) -> (tokio::task::JoinSet<TunnelTask>, usize, Vec<i64>) {
    let semaphore = Arc::new(Semaphore::new(ctx.config.probe.concurrency.max(1)));
    let mut tasks = tokio::task::JoinSet::new();
    let mut skipped = 0usize;
    let mut skipped_ids: Vec<i64> = Vec::new();
    for row in batch {
        if !included.contains(&row.id) {
            let reason = "proxy entry cannot be serialized for the T2 engine config";
            charge_tunnel_record(ctx, row.id, row.ladder_step, reason, lane).await;
            skipped += 1;
            skipped_ids.push(row.id);
            continue;
        }
        let (ctx, semaphore) = (ctx.clone(), semaphore.clone());
        let guard = state.guard.clone();
        let verdicts = state.verdicts.clone();
        let engine_faults = state.engine_faults.clone();
        let test_url = state.test_url.clone();
        let budget = cycle.budget.clone();
        let step = row.ladder_step;
        let id = row.id;
        // The pinned listener of the row's speed lane, when the plan gave
        // it one; the measurement only runs for a tunnel the delay check
        // just verified
        let measure = state
            .speed_lanes
            .get(&id)
            .map(|port| (*port, budget.clone()));
        tasks.spawn(async move {
            // The semaphore lives in this scope until the join loop below
            // returns, so a close here is structurally impossible; counted
            // as aborted rather than checked so it cannot inflate the
            // real-check counter
            let _permit = match semaphore.acquire_owned().await {
                Ok(permit) => permit,
                Err(_) => return TunnelTask::Aborted,
            };
            // Out of budget while this task waited: the row is not checked,
            // not charged, not journaled
            if budget.expired() {
                return TunnelTask::Deferred;
            }
            if guard.is_aborted() {
                engine_faults.fetch_add(1, Ordering::Relaxed);
                journal_engine_fault(&ctx, id, &format!("aborted: {MEOW_ABORT_REASON}")).await;
                return TunnelTask::Aborted;
            }
            perform_tunnel_check(
                &ctx,
                id,
                Some(step),
                &test_url,
                &verdicts,
                &guard,
                &engine_faults,
                measure,
            )
            .await
        });
    }
    (tasks, skipped, skipped_ids)
}

/// Join the spawned tunnel tasks and count the outcomes: only tasks that
/// reached the engine count as real contacts, the guard's early returns
/// as aborted and budget-spent rows as deferred, never folded into
/// `checked`. Returns the counters plus the ids the tasks judged (the
/// cycle hand-off).
async fn collect_tunnel_results(
    mut tasks: tokio::task::JoinSet<TunnelTask>,
) -> (usize, usize, usize, Vec<i64>) {
    let mut checked = 0usize;
    let mut aborted = 0usize;
    let mut deferred = 0usize;
    let mut judged: Vec<i64> = Vec::new();
    while let Some(result) = tasks.join_next().await {
        match result {
            Ok(TunnelTask::Judged(id)) => {
                checked += 1;
                judged.push(id);
            }
            Ok(TunnelTask::Ran) => checked += 1,
            Ok(TunnelTask::Aborted) => aborted += 1,
            Ok(TunnelTask::Deferred) => deferred += 1,
            Err(error) => tracing::warn!(%error, "tunnel check task panicked"),
        }
    }
    (checked, aborted, deferred, judged)
}

/// Classify the rows the engine never judged with one liveness ping for
/// the whole batch: a down engine failed all of them (an outage), an
/// answering engine hit per-request blips. The backoff is armed exactly
/// once, on the escalation.
async fn classify_unavailable_outcomes(ctx: &Context, state: &BatchState) {
    let unavailable = state.verdicts.take_unavailable();
    if unavailable.is_empty() {
        return;
    }
    let engine_down = ctx.meow.alive().await.is_err();
    for (id, error) in &unavailable {
        let error = sanitize_reason(error);
        let reason = if engine_down {
            format!("meow-rs unavailable mid-batch: {error}")
        } else {
            format!("meow-rs transient error: {error}")
        };
        journal_engine_fault(ctx, *id, &reason).await;
    }
    if engine_down {
        if state.guard.unavailable() >= MEOW_ABORT_THRESHOLD {
            tracing::warn!(
                unavailable = state.guard.unavailable(),
                "meow-rs was unavailable for the threshold number of checks, \
                 treating the tunnel batch as an engine fault"
            );
            ctx.backoff_meow().await;
        }
    } else if unavailable.len() >= MEOW_BLIP_THRESHOLD {
        tracing::warn!(
            blips = unavailable.len(),
            "meow-rs failed the threshold number of delay checks, \
             treating the tunnel batch as an engine fault"
        );
        ctx.backoff_meow().await;
    }
}

/// One tunnel check of the shared runner (a regular T2 check or a
/// quarantine revival check; see [`TunnelLane`]). `ladder_step` is the
/// row's quarantine ladder step (`None` outside the revival lane); it
/// only decides how a failure is charged, the check itself is the same.
/// `measure` carries the pinned-listener port and the cycle budget of the
/// speed measurement that follows a verified tunnel (`None` =
/// delay-only). Returns the [`TunnelTask`] the join loop counts.
// The eight parameters are the shared runner's own context (the batch
// guard, the verdicts, the engine-fault counter) plus the row's identity;
// bundling them into a struct would move the same names one call down
#[allow(clippy::too_many_arguments)]
async fn perform_tunnel_check(
    ctx: &Context,
    id: i64,
    ladder_step: Option<i64>,
    test_url: &str,
    verdicts: &T2Verdicts,
    guard: &BatchGuard,
    engine_faults: &AtomicUsize,
    measure: Option<(u16, CycleBudget)>,
) -> TunnelTask {
    let name = clash::proxy_name(id);
    let now = now_ts();
    // Retry transient `ServiceUnavailable` (transport blip, one malformed
    // payload, a single 5xx on a flapping connection): re-asking absorbs
    // most of them and keeps them off the engine-fault counter, which is
    // reserved for patterns the engine cannot recover from within the cycle
    match ctx
        .meow
        .check_delay_with_retry(&name, test_url, 2, Duration::from_millis(100))
        .await
    {
        DelayOutcome::Ok(delay) => {
            verdicts.record_success();
            let latency = i64::try_from(delay).unwrap_or(i64::MAX);
            journal(
                ctx,
                ProbeResultEntry {
                    proxy_id: id,
                    checked_at: now,
                    ok: true,
                    latency_ms: Some(latency),
                    error: None,
                    probe_kind: T2_KIND,
                },
            )
            .await;
            // A successful T2 is the tunnel-verified tier (owner decision,
            // 2026-09-10): the proxy becomes `ready`
            if let Err(error) = proxies::check_succeeded(
                &ctx.pool,
                id,
                now,
                Some(latency),
                true,
                fumox_core::models::ProxyStatus::Ready,
            )
            .await
            {
                tracing::warn!(id, %error, "failed to record the tunnel success");
            }
            if ladder_step.is_some() {
                tracing::info!(id, "quarantined proxy revived via the T2 tunnel check");
            }
            // The tunnel just verified itself: the measurement rides the
            // same task while the listener is hot
            if let Some((port, budget)) = measure {
                measure_speed_and_trace(ctx, id, port, budget).await;
            }
            TunnelTask::Judged(id)
        }
        DelayOutcome::ProxyFailed(message) => {
            // The engine answered authoritatively: the tunnel died, the
            // engine is alive
            let message = sanitize_reason(&message);
            journal(
                ctx,
                ProbeResultEntry {
                    proxy_id: id,
                    checked_at: now,
                    ok: false,
                    latency_ms: None,
                    error: Some(&message),
                    probe_kind: T2_KIND,
                },
            )
            .await;
            // The ladder is charged when the batch is over, not here: a
            // batch in which every tunnel failed is a verdict about the
            // test endpoint, not about the rows
            verdicts.record_failure(T2Failure {
                id,
                now,
                ladder_step,
            });
            TunnelTask::Judged(id)
        }
        DelayOutcome::ServiceUnavailable(error) => {
            // Not a verdict: collected and classified by the one liveness
            // ping after the batch (see [`run_tunnel_reload`]). An engine
            // that cannot run the test is not evidence about the tunnel,
            // so the row is journaled as *unverified*
            // ([`journal_engine_fault`]) and its fail budget stays
            // untouched
            engine_faults.fetch_add(1, Ordering::Relaxed);
            guard.record_unavailable();
            verdicts.record_unavailable(id, error);
            TunnelTask::Ran
        }
    }
}

/// The measurement of one delay-verified tunnel: the trace fetch
/// first, then the speed download, both through the row's pinned
/// listener. Both are diagnostics (owner decision, 2026-11-21: the speed
/// is a metric, never a verdict): a failed attempt journals its reason and
/// leaves the previous facts, the status machine and the fail budget
/// untouched. A failed trace skips the download for this cycle — a tunnel
/// that cannot carry a few hundred bytes will not carry the payload
/// either, and the row keeps its stale `speed_at` for the next batch.
async fn measure_speed_and_trace(ctx: &Context, id: i64, port: u16, budget: CycleBudget) {
    let meow_cfg = &ctx.config.meow;
    let network_cfg = &ctx.config.network;
    let Some(proxy_addr) = speed::listener_addr(&meow_cfg.api_addr, port) else {
        tracing::warn!(
            id,
            api_addr = %meow_cfg.api_addr,
            "cannot derive the pinned listener address from meow.api_addr, the measurement is skipped"
        );
        return;
    };
    let now = now_ts();

    if !network_cfg.trace_fields.is_empty() {
        match speed::fetch_trace(
            &network_cfg.trace_url,
            &network_cfg.trace_fields,
            &proxy_addr,
        )
        .await
        {
            Attempt {
                ok: true,
                value: AttemptValue::Trace(facts),
                ..
            } => {
                journal(
                    ctx,
                    ProbeResultEntry {
                        proxy_id: id,
                        checked_at: now,
                        ok: true,
                        latency_ms: None,
                        error: None,
                        probe_kind: TRACE_KIND,
                    },
                )
                .await;
                if let Err(error) = proxies::trace_succeeded(&ctx.pool, id, now, &facts).await {
                    tracing::warn!(id, %error, "failed to stamp the trace facts");
                }
            }
            Attempt { error, .. } => {
                let error =
                    sanitize_reason(&error.unwrap_or_else(|| "unknown trace failure".to_string()));
                tracing::debug!(id, %error, "trace fetch through the pinned listener failed");
                journal(
                    ctx,
                    ProbeResultEntry {
                        proxy_id: id,
                        checked_at: now,
                        ok: false,
                        latency_ms: None,
                        error: Some(&error),
                        probe_kind: TRACE_KIND,
                    },
                )
                .await;
                return;
            }
        }
    }

    // Out of budget while the trace ran: the measurement waits for the
    // next cycle (the stale `speed_at` keeps the row due)
    if budget.expired() {
        tracing::debug!(id, "cycle budget spent before the speed download");
        return;
    }
    let ceiling = Duration::from_secs(network_cfg.speed_time_ceiling_secs.max(1));
    match speed::measure_speed(
        &network_cfg.speed_url,
        network_cfg.speed_bytes,
        ceiling,
        &proxy_addr,
    )
    .await
    {
        Attempt {
            ok: true,
            value: AttemptValue::Speed(mbps),
            ..
        } => {
            journal(
                ctx,
                ProbeResultEntry {
                    proxy_id: id,
                    checked_at: now_ts(),
                    ok: true,
                    latency_ms: None,
                    error: None,
                    probe_kind: SPEED_KIND,
                },
            )
            .await;
            if let Err(error) = proxies::speed_succeeded(&ctx.pool, id, now_ts(), mbps).await {
                tracing::warn!(id, %error, "failed to stamp the speed measurement");
            } else {
                tracing::debug!(id, mbps, "speed measured through the pinned listener");
            }
        }
        Attempt { error, .. } => {
            let error =
                sanitize_reason(&error.unwrap_or_else(|| "unknown speed failure".to_string()));
            tracing::debug!(id, %error, "speed download through the pinned listener failed");
            journal(
                ctx,
                ProbeResultEntry {
                    proxy_id: id,
                    checked_at: now_ts(),
                    ok: false,
                    latency_ms: None,
                    error: Some(&error),
                    probe_kind: SPEED_KIND,
                },
            )
            .await;
        }
    }
}

/// A record the engine config cannot carry is a failed recheck: the
/// ladder advances (or the proxy is removed after the last configured
/// step).
async fn reject_quarantine_record(ctx: &Context, id: i64, step: i64, reason: &str) {
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
    let delays = ctx.config.probe.recheck_delays_secs.clone();
    match proxies::quarantine_check_failed(&ctx.pool, id, now, step, &delays).await {
        Ok(proxies::Transition::Removed) => {
            tracing::info!(id, "proxy removed after the final failed recheck")
        }
        Ok(_) => tracing::debug!(id, step, "quarantine revival failed, ladder advanced"),
        Err(error) => tracing::warn!(id, %error, "failed to advance quarantine ladder"),
    }
}

/// Advance the recheck ladder for the failed revival checks of a finished
/// batch, unless no check succeeded and more than one tunnel failed: a
/// batch in which every tunnel failed is a verdict about the test
/// endpoint, so the rows stay due and are retried when the endpoint
/// answers again.
async fn settle_revival_failures(ctx: &Context, verdicts: &T2Verdicts, test_url: &str) {
    let failures = verdicts.take_failures();
    if failures.is_empty() {
        return;
    }
    if endpoint_suspect(verdicts, failures.len()) {
        tracing::warn!(
            failures = failures.len(),
            test_url = %test_url,
            "every T2 revival check failed the tunnel: the test endpoint is suspect, \
             the quarantine ladder was not advanced"
        );
        return;
    }
    // The whole batch advances in one transaction
    let rows: Vec<(i64, i64, i64)> = failures
        .iter()
        .map(|failure| (failure.id, failure.now, failure.ladder_step.unwrap_or(0)))
        .collect();
    advance_quarantine_ladder_batch(&ctx.pool, &rows, &ctx.config.probe.recheck_delays_secs).await;
}

/// Whether the batch verdicts say "the test endpoint, not the proxies":
/// no check of the batch succeeded while more than one tunnel failed. The
/// proxies sit behind different exits, and an endpoint that is blocked or
/// degraded on those exits is indistinguishable from a dead tunnel in
/// meow-rs' answer.
fn endpoint_suspect(verdicts: &T2Verdicts, failures: usize) -> bool {
    verdicts.successes() == 0 && failures > 1
}

/// Advance the recheck ladder of a finished batch's failed revivals in one
/// transaction, logging each removal.
async fn advance_quarantine_ladder_batch(pool: &DbPool, rows: &[(i64, i64, i64)], delays: &[i64]) {
    match proxies::quarantine_check_failed_batch(pool, rows, delays).await {
        Ok(transitions) => {
            for (id, transition) in transitions {
                log_ladder_transition(id, transition);
            }
        }
        Err(error) => tracing::warn!(%error, "failed to advance quarantine ladder"),
    }
}

fn log_ladder_transition(id: i64, transition: proxies::Transition) {
    match transition {
        proxies::Transition::Removed => {
            tracing::info!(id, "proxy removed after the final failed recheck")
        }
        _ => tracing::debug!(id, "quarantine revival failed, ladder advanced"),
    }
}

/// Advance the recheck ladder of one failed recheck (a T1 recheck, a
/// vet-refused recheck, a row the stored data cannot describe): the proxy
/// is removed after the last configured step.
async fn advance_recheck_ladder(ctx: &Context, id: i64, now: i64, step: i64, delays: &[i64]) {
    match proxies::quarantine_check_failed(&ctx.pool, id, now, step, delays).await {
        Ok(proxies::Transition::Removed) => {
            tracing::info!(id, "proxy removed after the final failed recheck")
        }
        Ok(_) => tracing::debug!(id, step, "quarantine recheck failed, ladder advanced"),
        Err(error) => tracing::warn!(id, %error, "failed to advance quarantine ladder"),
    }
}

/// The quarantine-ladder counterpart of [`apply_vet_block`]: a
/// vet-refused recheck is a failed recheck, the ladder advances (or the
/// proxy is removed after the last configured step).
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
    advance_recheck_ladder(ctx, id, now_ts(), step, &delays).await;
}

/// A row the stored data cannot describe can never be checked, so leaving
/// it due would spend the quarantine quota every cycle on a verdict it
/// can never get. The skip is a failed recheck instead: journaled, the
/// ladder advances (or the proxy is removed after the last configured
/// step), the same verdict as [`reject_quarantine_record`] and
/// [`apply_quarantine_vet_block`].
async fn reject_unverifiable_quarantine_row(ctx: &Context, id: i64, step: i64, reason: &str) {
    journal(
        ctx,
        ProbeResultEntry {
            proxy_id: id,
            checked_at: now_ts(),
            ok: false,
            latency_ms: None,
            error: Some(reason),
            // A skipped row never reached a socket, so the T1 family kind
            // stands in and `error` names the real defect
            probe_kind: t1::CheckKind::Tcp.as_str(),
        },
    )
    .await;
    let delays = ctx.config.probe.recheck_delays_secs.clone();
    advance_recheck_ladder(ctx, id, now_ts(), step, &delays).await;
}

/// One quarantine re-check: success revives the proxy with a clean slate;
/// failure advances the configured ladder or removes the proxy after the
/// last configured step. `vetted` carries the SSRF-approved dial
/// addresses (see [`vet_target_addrs`]).
async fn perform_quarantine_check(
    ctx: &Context,
    id: i64,
    target: &t1::Target<'_>,
    step: i64,
    delays: &[i64],
) {
    let (connect_timeout, tls_timeout) = t1_timeouts(&ctx.config.probe);
    let outcome = t1::run(target, connect_timeout, tls_timeout).await;
    let now = now_ts();

    match outcome {
        Ok(elapsed) => {
            record_revival_success(ctx, id, target.kind.as_str(), now, elapsed, step).await;
        }
        Err(reason) => {
            // The reason names the dial target and the handshake error,
            // both feed-controlled: sanitize before the log and the journal
            let reason = sanitize_reason(&reason);
            record_recheck_failure(ctx, id, target.kind.as_str(), now, &reason, step, delays).await;
        }
    }
}

/// Journal the successful recheck and revive the proxy. The revival check
/// is T1 (TCP/TLS), so the proxy returns to the plain `alive` tier; the
/// next successful T2 promotes it to `ready`.
async fn record_revival_success(
    ctx: &Context,
    id: i64,
    probe_kind: &str,
    now: i64,
    elapsed: Duration,
    step: i64,
) {
    let latency = i64::try_from(elapsed.as_millis()).unwrap_or(i64::MAX);
    journal(
        ctx,
        ProbeResultEntry {
            proxy_id: id,
            checked_at: now,
            ok: true,
            latency_ms: Some(latency),
            error: None,
            probe_kind,
        },
    )
    .await;
    match proxies::check_succeeded(
        &ctx.pool,
        id,
        now,
        Some(latency),
        true,
        fumox_core::models::ProxyStatus::Alive,
    )
    .await
    {
        Ok(_) => tracing::info!(id, step, "quarantined proxy revived"),
        Err(error) => tracing::warn!(id, %error, "failed to record quarantine success"),
    }
}

/// Journal the failed recheck and advance the configured ladder (see
/// [`advance_recheck_ladder`]).
async fn record_recheck_failure(
    ctx: &Context,
    id: i64,
    probe_kind: &str,
    now: i64,
    reason: &str,
    step: i64,
    delays: &[i64],
) {
    journal(
        ctx,
        ProbeResultEntry {
            proxy_id: id,
            checked_at: now,
            ok: false,
            latency_ms: None,
            error: Some(reason),
            probe_kind,
        },
    )
    .await;
    advance_recheck_ladder(ctx, id, now, step, delays).await;
}

/// What one T2 batch produced, for the cycle log. `checked` counts rows
/// that got a real verdict (an engine contact or a policy refusal, both
/// journaled); `aborted` rows an engine-wide outage kept away from meow-rs
/// (ping/reload failure or the mid-batch guard); `skipped` rows the config
/// preparation could not serialize; `blocked` the private-address
/// refusals (part of `checked`, but counted apart: mostly refusals is a
/// policy problem, not a health problem); `engine_faults` rows the engine
/// never judged, journaled unverified and never charged, the counter that
/// tells "the engine was down" from "the proxies are dying"; `deferred`
/// rows the cycle budget spent, not charged and not journaled.
#[derive(Default)]
struct T2Outcome {
    checked: usize,
    aborted: usize,
    skipped: usize,
    blocked: usize,
    engine_faults: usize,
    deferred: usize,
}

/// Write the generated Clash YAML of one meow-rs batch (a T2 batch or a
/// quarantine revival batch) to `meow.config_path`.
///
/// The YAML carries every proxy credential in plain text (same exposure
/// as the SQLite database), so the file is written the hard way: a
/// temporary file in the *same* directory (rename is only atomic within
/// one filesystem), created exclusively with `O_NOFOLLOW` so a planted
/// name cannot be written through, mode 0640 set via `fchmod` on the
/// open descriptor (a umask can only make it stricter, and the file is
/// never briefly readable), fsynced, then renamed onto the target so the
/// engine reads either the old or the new config, never a half-written
/// one. The rename does not follow a symlink either, it replaces it.
///
/// 0640, not 0600: the file lives in a volume shared with the meow-rs
/// container, which runs under a different uid (the proxy kernel gets no
/// access to the database) and reads the config through the shared group.
///
/// On a platform without POSIX modes there is no `fchmod` equivalent: the
/// file is created exclusively and renamed into place, and access is
/// governed by the ACL of the directory it lives in.
fn write_meow_config(path: &std::path::Path, yaml: &str) -> anyhow::Result<()> {
    let parent = path.parent().unwrap_or_else(|| std::path::Path::new("/"));
    std::fs::create_dir_all(parent).map_err(|error| {
        anyhow::anyhow!(
            "cannot create the meow config directory {}: {error}",
            parent.display()
        )
    })?;
    check_config_dir(parent)?;

    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("meow.yaml");
    // The temporary file lives next to the target, so the rename is atomic
    let temp = parent.join(format!(".{name}.{}.tmp", fumox_core::models::new_id()));

    let written = write_config_file(&temp, yaml);
    if let Err(error) = written {
        let _ = std::fs::remove_file(&temp);
        return Err(error);
    }
    std::fs::rename(&temp, path).map_err(|error| {
        let _ = std::fs::remove_file(&temp);
        anyhow::anyhow!(
            "cannot move the meow config into place at {}: {error}",
            path.display()
        )
    })?;
    sync_dir(parent);
    Ok(())
}

/// Write the config content into the temporary file, with the restricted
/// mode.
fn write_config_file(temp: &std::path::Path, yaml: &str) -> anyhow::Result<()> {
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            // `create_new` is `O_CREAT|O_EXCL`: an existing name (a
            // symlink, a hard link, another process' file) is a hard error
            // instead of a truncation
            .create_new(true)
            .mode(0o640)
            .custom_flags(libc::O_NOFOLLOW)
            .open(temp)
            .map_err(|error| {
                anyhow::anyhow!(
                    "cannot create the meow config file {}: {error}",
                    temp.display()
                )
            })?;
        // fchmod on the open fd: no path re-resolution between check and
        // use, and the umask is ignored, so the mode is exactly 0640
        file.set_permissions(std::fs::Permissions::from_mode(0o640))
            .map_err(|error| {
                anyhow::anyhow!(
                    "cannot restrict the mode of the meow config file {}: {error}",
                    temp.display()
                )
            })?;
        file.write_all(yaml.as_bytes()).map_err(|error| {
            anyhow::anyhow!(
                "cannot write the meow config file {}: {error}",
                temp.display()
            )
        })?;
        file.sync_all().map_err(|error| {
            anyhow::anyhow!(
                "cannot flush the meow config file {} to disk: {error}",
                temp.display()
            )
        })?;
    }
    #[cfg(not(unix))]
    {
        use std::io::Write;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(temp)
            .map_err(|error| {
                anyhow::anyhow!(
                    "cannot create the meow config file {}: {error}",
                    temp.display()
                )
            })?;
        file.write_all(yaml.as_bytes()).map_err(|error| {
            anyhow::anyhow!(
                "cannot write the meow config file {}: {error}",
                temp.display()
            )
        })?;
        file.sync_all().map_err(|error| {
            anyhow::anyhow!(
                "cannot flush the meow config file {} to disk: {error}",
                temp.display()
            )
        })?;
    }
    Ok(())
}

/// Refuse a config directory that every local user may write to.
///
/// The file mode protects the credentials against a *reader*; a
/// world-writable directory defeats the writer as well: another user can
/// replace the file between the write and the rename, or plant a name the
/// probe then writes through. The sticky bit (`/tmp`) is the exception, it
/// keeps the entries of different users apart.
fn check_config_dir(dir: &std::path::Path) -> anyhow::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let meta = std::fs::metadata(dir).map_err(|error| {
            anyhow::anyhow!(
                "cannot inspect the meow config directory {}: {error}",
                dir.display()
            )
        })?;
        let mode = meta.permissions().mode();
        if mode & 0o002 != 0 && mode & 0o1000 == 0 {
            anyhow::bail!(
                "the meow config directory {} is world-writable: another local user could \
                 replace the config file",
                dir.display()
            );
        }
    }
    Ok(())
}

/// Flush the directory entry of a renamed file, so the rename survives a
/// crash. Best effort: a filesystem that refuses to open the directory
/// (or a platform without directories) must not fail the write.
fn sync_dir(dir: &std::path::Path) {
    #[cfg(unix)]
    if let Ok(handle) = std::fs::File::open(dir) {
        let _ = handle.sync_all();
    }
    #[cfg(not(unix))]
    let _ = dir;
}

/// The engine records of one batch. A row whose stored parameters do not
/// parse yields no record and stays out of the returned list, so the
/// caller journals it as an entry that cannot be serialized instead of
/// feeding the engine a proxy it would report as not found.
fn engine_records(
    batch: &[proxies::ProxyRow],
    pins: &std::collections::HashMap<String, std::net::IpAddr>,
) -> Vec<clash::BatchRow> {
    batch
        .iter()
        .filter_map(|row| {
            Some(clash::BatchRow {
                id: row.id,
                entry: row.to_entry().ok()?,
                vetted: pins.get(&row.host).copied(),
            })
        })
        .collect()
}

/// Prepare the engine configuration of one batch: generate the Clash YAML
/// (with the pinned speed-measurement listeners of [`speed_plan`]) and
/// write it to `meow.config_path`. A failure here means the engine never
/// sees the batch; the callers treat it like a failed reload (rows
/// journaled unverified, never charged, and the T2 lanes back off).
fn prepare_engine_config(
    ctx: &Context,
    batch: &[proxies::ProxyRow],
    pins: &std::collections::HashMap<String, std::net::IpAddr>,
    lane: TunnelLane,
) -> anyhow::Result<clash::GeneratedBatch> {
    let generated = clash::generate(
        &engine_records(batch, pins),
        ctx.config.meow.ipv6,
        &speed_plan(ctx, batch, lane),
    )
    .map_err(|error| anyhow::anyhow!("cannot generate the meow config: {error}"))?;
    write_meow_config(&ctx.config.meow.config_path, &generated.yaml)?;
    Ok(generated)
}

/// The speed-measurement plan of one T2 batch: the rows whose
/// last measurement is stale enough to re-measure, capped at
/// `[network].speed_concurrency` lanes so the ports and the parallel
/// downloads both stay inside their bounds. Only the regular T2 lane
/// measures — a quarantine revival is about getting the row back into the
/// rotation, not about measuring it (owner decision, 2026-11-21: measure
/// the delay-passers of the T2 batch).
fn speed_plan(ctx: &Context, batch: &[proxies::ProxyRow], lane: TunnelLane) -> clash::SpeedPlan {
    if !ctx.config.network.speed_enabled || !matches!(lane, TunnelLane::T2 { .. }) {
        return clash::SpeedPlan::empty();
    }
    let interval = ctx.config.network.speed_interval_secs as i64;
    let now = now_ts();
    let due: std::collections::HashSet<i64> = batch
        .iter()
        .filter(|row| {
            row.speed_at
                .is_none_or(|at| now.saturating_sub(at) >= interval)
        })
        .map(|row| row.id)
        .collect();
    clash::SpeedPlan {
        due,
        port_base: ctx.config.network.speed_listener_port_base,
        max_lanes: ctx.config.network.speed_concurrency,
    }
}

/// Generate a Clash batch, reload meow-rs, and delay-test every proxy
/// through a real tunnel.
///
/// `already_checked` carries the ids the lanes before this one gave a
/// verdict this cycle (see [`run_cycle`]); those rows are dropped, a dead
/// one drawn by two lanes would otherwise collect one `fail_count` step
/// from each and quarantine in half the cycles `fail_limit` promises.
/// Dropping the overlap leaves the recency-prioritized batch slightly
/// smaller; the dropped rows are the head of the next cycle's batch
/// anyway.
///
/// Success is strict: only a tunnel that came up *and* answered with a
/// measured `delay` counts. A meow-rs outage is *not* charged to the
/// proxies: every proxy that was due one is journaled (as
/// `probe_kind='t2_unverified'`, the record that un-sticks the recency
/// queue) and stamped unverified, but its own fail budget and the
/// quarantine path stay untouched, so an outage cannot retire a healthy
/// pool (see [`journal_engine_fault`]). The cycle still backs off so a
/// dead meow-rs is not hammered every minute.
async fn probe_t2_batch(
    ctx: Arc<Context>,
    already_checked: &[i64],
    cycle: Arc<Cycle>,
) -> anyhow::Result<T2Outcome> {
    let now = now_ts();
    if now < ctx.meow_retry_at.load(Ordering::Relaxed) {
        tracing::debug!(
            retry_at = ctx.meow_retry_at.load(Ordering::Relaxed),
            backoff_secs = ctx.meow_backoff_secs.load(Ordering::Relaxed),
            "meow-rs in backoff, T2 skipped"
        );
        return Ok(T2Outcome::default());
    }

    let quota = cycle.tunnel.take(ctx.config.probe.sample_size as usize);
    let rows = proxies::select_t2_candidates(&ctx.pool, as_limit(quota)).await?;
    let covered: std::collections::HashSet<i64> = already_checked.iter().copied().collect();
    let rows: Vec<proxies::ProxyRow> = rows
        .into_iter()
        .filter(|row| !covered.contains(&row.id))
        .collect();
    // The core mapping is the authority on what meow-rs can tunnel: a
    // scheme it cannot express has no T2 verdict at all, and vetting such
    // a row would charge it for a check that could never run
    let mut candidates: Vec<proxies::ProxyRow> = Vec::new();
    for row in rows {
        let Ok(scheme) = row.scheme.parse::<Scheme>() else {
            continue;
        };
        if !fumox_core::formats::clash::is_supported(scheme) {
            continue;
        }
        candidates.push(row);
    }
    let fail_limit = ctx.config.probe.fail_limit;
    let (min_secs, spread_secs) = second_chance_bounds(&ctx.config.probe);
    let lane = TunnelLane::T2 {
        fail_limit,
        min_secs,
        spread_secs,
    };
    let outcome = run_t2_tunnel_batch(ctx, candidates, cycle, lane).await?;
    Ok(T2Outcome {
        checked: outcome.checked,
        blocked: outcome.blocked,
        aborted: outcome.aborted,
        skipped: outcome.skipped,
        engine_faults: outcome.engine_faults,
        deferred: outcome.deferred,
    })
}

/// Charge the fail ladder for the failed tunnels of a finished batch, or
/// not, depending on what the rest of the batch did.
///
/// A batch with *no* success and more than one tunnel failed is a verdict
/// about the test endpoint, not the proxies: meow-rs answers a blocked or
/// degraded endpoint exactly like a dead tunnel, and charging the ladder
/// would empty a healthy pool because of one bad endpoint. Such a batch
/// stamps the rows unverified, the way a meow-rs outage does.
///
/// A single failure is charged: one proxy that cannot reach the endpoint
/// is a verdict about that proxy, and the ladder is the only thing that
/// retires it.
async fn settle_t2_failures(
    ctx: &Context,
    verdicts: &T2Verdicts,
    test_url: &str,
    fail_limit: u32,
    min_secs: i64,
    spread_secs: i64,
) {
    let failures = verdicts.take_failures();
    if failures.is_empty() {
        return;
    }
    if endpoint_suspect(verdicts, failures.len()) {
        tracing::warn!(
            failures = failures.len(),
            test_url = %test_url,
            "every T2 check of the batch failed the tunnel: the test endpoint is suspect, \
             the proxies were not charged"
        );
        stamp_batch_unverified(&ctx.pool, &failures).await;
        return;
    }
    charge_t2_failures(&ctx.pool, &failures, fail_limit, min_secs, spread_secs).await;
}

/// Stamp the rows of a suspect batch unverified: no verdict was possible,
/// so no fail budget is charged.
async fn stamp_batch_unverified(pool: &DbPool, failures: &[T2Failure]) {
    let ids: Vec<i64> = failures.iter().map(|failure| failure.id).collect();
    if let Err(error) = proxies::check_engine_unavailable_batch(pool, &ids, now_ts()).await {
        tracing::warn!(%error, "failed to stamp the T2 engine fault");
    }
}

/// Charge the regular fail ladder of the whole batch in one transaction
/// (the per-row version took the write lock per failed tunnel), logging
/// the quarantines.
async fn charge_t2_failures(
    pool: &DbPool,
    failures: &[T2Failure],
    fail_limit: u32,
    min_secs: i64,
    spread_secs: i64,
) {
    let ids: Vec<i64> = failures.iter().map(|failure| failure.id).collect();
    match proxies::check_failed_batch(
        pool,
        &ids,
        now_ts(),
        fail_limit,
        min_secs,
        spread_secs,
        true,
    )
    .await
    {
        Ok(transitions) => {
            for (id, transition) in transitions {
                if transition == proxies::Transition::Quarantined {
                    tracing::info!(id, "proxy quarantined after T2 failures");
                }
            }
        }
        Err(error) => tracing::warn!(%error, "failed to record the T2 failures"),
    }
}

/// Journal one failed T2 attempt and run the fail ladder: a proxy that got
/// a verdict, whether the tunnel itself failed or the target was
/// vet-refused, receives a `probe_kind='t2'` failure record, which is
/// also what moves it forward in the recency queue.
///
/// The callers are the two refusals that are not about the endpoint: a
/// target the private-address policy blocked and an entry that could not
/// be serialized for the engine config. Both are a verdict about the
/// proxy itself, so they are charged right away.
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
    let (min_secs, spread_secs) = second_chance_bounds(probe);
    if let Err(error) = proxies::check_failed(
        &ctx.pool,
        id,
        now,
        probe.fail_limit,
        min_secs,
        spread_secs,
        // T2-side failure: stamp the suppression flag so the T1 selector
        // skips this proxy until its next T2 succeeds
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
/// An outage journals the attempt (as `probe_kind='t2_unverified'`, the
/// record that un-sticks the recency queue) and stamps last_t2_failed_at
/// plus the ready -> alive demote, but never charges the fail budget. The
/// kind is the point: a `t2` row means "the tunnel was judged and
/// failed", a `t2_unverified` row means "no verdict was possible".
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
            probe_kind: T2_UNVERIFIED_KIND,
        },
    )
    .await;
    if let Err(error) = proxies::check_engine_unavailable(&ctx.pool, id, now).await {
        tracing::warn!(id, %error, "failed to stamp the T2 engine fault");
    }
}

/// Stamp every proxy of a batch with the same engine-outage reason: a
/// meow-rs outage at ping/reload time means every due proxy went
/// unverified this cycle, and an unrecorded skip is indistinguishable
/// from an empty pool (and pins the head of the recency queue for the
/// whole outage). No fail budget is charged, see [`journal_engine_fault`].
async fn journal_engine_failure(ctx: &Context, batch: &[proxies::ProxyRow], reason: &str) {
    let now = now_ts();
    // Journaled in one statement, stamped in one transaction: a hundred
    // round trips would keep the cycle running long after the engine was
    // gone
    let entries: Vec<ProbeResultEntry<'_>> = batch
        .iter()
        .map(|row| ProbeResultEntry {
            proxy_id: row.id,
            checked_at: now,
            ok: false,
            latency_ms: None,
            error: Some(reason),
            probe_kind: T2_UNVERIFIED_KIND,
        })
        .collect();
    if let Err(error) = probe_repo::insert_many(&ctx.pool, &entries).await {
        tracing::error!(%error, "failed to journal the T2 engine outage");
    }
    let ids: Vec<i64> = batch.iter().map(|row| row.id).collect();
    stamp_batch_engine_unavailable(&ctx.pool, ids, now).await;
    tracing::warn!(proxies = batch.len(), "T2 batch failed by engine outage");
}

async fn stamp_batch_engine_unavailable(pool: &DbPool, ids: Vec<i64>, now: i64) {
    if let Err(error) = proxies::check_engine_unavailable_batch(pool, &ids, now).await {
        tracing::warn!(%error, "failed to stamp the T2 engine outage");
    }
}

/// Publish the proxy kernel's RSS for the admin panel. Purely
/// observational: failures touch neither the fail ladder nor the backoff.
/// Only cycles that reload meow-rs refresh it, so a stale number means
/// "no T2 batch ran lately", not "the kernel shrank".
async fn stamp_meow_memory(ctx: &Context) {
    match ctx.meow.memory().await {
        Ok(mem) => stamp_meow_memory_payload(ctx, &mem).await,
        Err(error) => tracing::debug!(%error, "meow-rs /memory unavailable"),
    }
}

/// Serialize and stamp one `/memory` answer; best effort, like the other
/// meta stamps (see [`stamp_meow_memory`]).
async fn stamp_meow_memory_payload(ctx: &Context, mem: &meow::MeowMemory) {
    let payload = probe_repo::meta::MeowMemory {
        rss_bytes: mem.rss_bytes,
        os_limit_bytes: mem.os_limit_bytes,
        ts: now_ts(),
    };
    match meta_json(&payload) {
        Ok(json) => {
            if let Err(error) = meta_set(&ctx.pool, probe_repo::meta::MEOW_MEMORY_KEY, &json).await
            {
                tracing::debug!(%error, "failed to stamp meow_memory");
            }
        }
        Err(error) => tracing::debug!(%error, "failed to serialize meow_memory"),
    }
}

/// Serialize a meta payload into its on-wire JSON. The payload structs in
/// [`fumox_core::repo::probe::meta`] hold only JSON-native field types, so
/// this cannot fail in practice; the error is propagated instead of
/// panicking.
fn meta_json(payload: &impl serde::Serialize) -> anyhow::Result<String> {
    serde_json::to_string(payload)
        .map_err(|error| anyhow::anyhow!("cannot serialize the meta payload: {error}"))
}

/// Build the `probe_heartbeat` payload. `interval_secs` is the daemon's
/// effective beat period and `cycle_interval_secs` its effective cycle
/// period: the admin panel thresholds staleness against the schedules the
/// daemon actually runs, since server and probe may read different config
/// files (see [`heartbeat_loop`]). The shape is the shared
/// [`fumox_core::repo::probe::meta::Heartbeat`] contract.
fn heartbeat_payload(interval_secs: u64, cycle_interval_secs: u64) -> anyhow::Result<String> {
    meta_json(&probe_repo::meta::Heartbeat {
        ts: now_ts(),
        pid: std::process::id(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        interval_secs: Some(interval_secs),
        cycle_interval_secs: Some(cycle_interval_secs),
    })
}

/// Periodically upsert `probe_heartbeat` into `meta` so the admin panel
/// can tell the daemon is alive. The payload carries the daemon's
/// effective beat and cycle periods: server and probe may read different
/// config files, so the panel must threshold against the schedule actually
/// running, not against its own copy of the config.
async fn heartbeat_loop(ctx: Arc<Context>) {
    let period = Duration::from_secs(ctx.config.probe.heartbeat_interval_secs.max(5));
    let cycle_secs = ctx.config.probe.cycle_interval_secs.max(1);
    let mut ticker = tokio::time::interval(period);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        ticker.tick().await;
        let payload = match heartbeat_payload(period.as_secs(), cycle_secs) {
            Ok(payload) => payload,
            Err(error) => {
                tracing::warn!(%error, "failed to serialize the probe heartbeat");
                continue;
            }
        };
        if let Err(error) = meta_set(&ctx.pool, probe_repo::meta::HEARTBEAT_KEY, &payload).await {
            tracing::warn!(%error, "failed to write probe heartbeat");
        }
    }
}

/// History rotation: `probe_results` and `fetch_log` older than
/// the configured windows are purged once at startup and then periodically.
/// The ticker starts a full period out, so the startup purge is not
/// immediately repeated by the first tick.
async fn retention_loop(ctx: Arc<Context>) {
    run_retention(&ctx).await;

    let period = Duration::from_secs(ctx.config.probe.retention_interval_secs.max(60));
    let mut ticker = tokio::time::interval_at(tokio::time::Instant::now() + period, period);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        ticker.tick().await;
        run_retention(&ctx).await;
    }
}

async fn run_retention(ctx: &Context) {
    let now = now_ts();

    // The daemon's own table first: the server never writes `probe_results`
    let (deleted_probe, failure) = purge_probe_results(
        &ctx.pool,
        now,
        u64::from(ctx.config.retention.probe_results_days),
    )
    .await;

    // The journals both binaries write, with the windows and the clamp of
    // the shared sweep: a server-only deployment runs the same one
    let windows = retention::RetentionWindows {
        fetch_log_days: ctx.config.retention.fetch_log_days,
        queue_stale_days: ctx.config.probe.queue_stale_days,
    };
    let outcome = retention::sweep_shared_journals(&ctx.pool, &windows, now).await;
    let mut failure = failure;
    if let Some(error) = &outcome.error {
        failure.get_or_insert_with(|| error.clone());
    }

    stamp_last_rotation(ctx, failure, deleted_probe, &outcome).await;
}

/// Purge `probe_results` older than the configured window. Returns the
/// deleted row count plus the first failure of the run: the stamp below
/// carries it, so a failed rotation is visible instead of silent.
async fn purge_probe_results(pool: &DbPool, now: i64, days: u64) -> (u64, Option<String>) {
    match probe_repo::purge_before(pool, retention::cutoff(now, days)).await {
        Ok(0) => (0, None),
        Ok(deleted) => {
            tracing::info!(deleted, "rotated probe_results");
            (deleted, None)
        }
        Err(error) => {
            tracing::warn!(%error, "probe_results rotation failed");
            (0, Some(format!("probe_results: {error}")))
        }
    }
}

/// Stamp the run so /admin/probe can surface it: the info lines above
/// are not a surface an operator looks at, and a probe daemon that
/// stopped rotating would otherwise grow both journals with nothing
/// saying so. A failed run keeps the `ts` of the last *successful*
/// one: the age of the stamp is the "retention last succeeded" signal,
/// and the `ok`/`error` pair says why it is stale.
async fn stamp_last_rotation(
    ctx: &Context,
    failure: Option<String>,
    deleted_probe: u64,
    outcome: &retention::RetentionOutcome,
) {
    let stamp = probe_repo::meta::LastRotation {
        ts: if failure.is_none() {
            now_ts()
        } else {
            previous_rotation_ts(&ctx.pool).await
        },
        probe_results: deleted_probe,
        fetch_log: outcome.fetch_log,
        probe_requests: outcome.probe_requests,
        ok: failure.is_none(),
        error: failure,
    };
    match meta_json(&stamp) {
        Ok(payload) => {
            if let Err(error) =
                meta_set(&ctx.pool, probe_repo::meta::LAST_ROTATION_KEY, &payload).await
            {
                tracing::warn!(%error, "failed to stamp last_rotation");
            }
        }
        Err(error) => tracing::warn!(%error, "failed to serialize the last_rotation stamp"),
    }
}

/// The `ts` of the last rotation stamp, for a failed run to keep: the age
/// of the stamp is the "last successful rotation" signal and must not
/// advance over a failure. A missing (or unparseable) stamp reads as 0.
async fn previous_rotation_ts(pool: &DbPool) -> i64 {
    match meta_get(pool, probe_repo::meta::LAST_ROTATION_KEY).await {
        Ok(Some(raw)) => serde_json::from_str::<probe_repo::meta::LastRotation>(&raw)
            .map(|stamp| stamp.ts)
            .unwrap_or(0),
        _ => 0,
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

/// Resolves when the process receives SIGINT (Ctrl-C) or SIGTERM. A
/// handler that cannot be installed is an error, not a panic: the daemon
/// fails its startup the way any other setup failure does.
async fn shutdown_signal() -> anyhow::Result<()> {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .map_err(|error| anyhow::anyhow!("failed to install Ctrl-C handler: {error}"))
    };

    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .map_err(|error| anyhow::anyhow!("failed to install SIGTERM handler: {error}"))?
            .recv()
            .await;
        Ok::<(), anyhow::Error>(())
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<anyhow::Result<()>>();

    tokio::select! {
        result = ctrl_c => result?,
        result = terminate => result?,
    }
    tracing::info!("shutdown signal received");
    Ok(())
}

#[cfg(test)]
#[path = "main_tests.rs"]
mod tests;
