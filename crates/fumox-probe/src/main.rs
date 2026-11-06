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
//! All proxy lifecycle state (status, fail counters, quarantine
//! schedules) lives in SQLite, so the daemon is restart-safe: after a
//! restart it simply resumes the schedules persisted in the DB. The
//! meow-rs backoff gate is mirrored into the `meta` table for the same
//! reason (see [`Context::new`]).

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
use fumox_core::models::{ProxyEntry, Scheme, now_ts};
use fumox_core::repo::probe::{ProbeResultEntry, T2_KIND, T2_UNVERIFIED_KIND};
use fumox_core::repo::{meta_get, meta_set, probe as probe_repo, proxies, retention};
use meow::{DelayOutcome, MeowClient};
use tokio::sync::Semaphore;

/// Number of in-batch `ServiceUnavailable` outcomes (each of which
/// already survived the per-request retry) that escalate from
/// "per-request blip" to "engine outage". Below this, every task still
/// contacts meow-rs; at-or-above, the rest of the batch is skipped via
/// the `aborted` flag and the backoff is armed at the end of the batch.
/// Three is a deliberately tight floor: a single transport blip on one
/// request does not abort a batch, but three tasks in a row whose
/// retries were all refused point at a real engine problem. The count is
/// cumulative: a successful outcome used to reset it, and an engine that
/// flapped (down, recovered, down again) never reached the threshold.
const MEOW_ABORT_THRESHOLD: usize = 3;

/// How many per-request blips (the engine answers `/version` but the
/// delay check fails) one batch may collect before the test path itself
/// counts as broken and the backoff is armed when the batch ends.
///
/// A blip is not a verdict about the proxy, so it never charges one. A
/// *run* of them is a different matter: the engine answers but cannot
/// run the tunnel test, which is an engine-side problem (a blocked test
/// endpoint, a broken configuration) and must not be charged to the
/// proxies either.
const MEOW_BLIP_THRESHOLD: usize = 3;

/// The text the rows the guard's early return journals with. It is fixed
/// because the aborted rows skip the engine before the one batch-level
/// liveness ping classifies the collected outcomes (see the join loop of
/// [`run_tunnel_reload`]).
const MEOW_ABORT_REASON: &str = "meow-rs became unavailable mid-batch";

/// Per-batch decision state shared across the parallel tunnel tasks. A
/// single `ServiceUnavailable` does not drop the whole batch: every
/// outcome first runs the per-request retry, and what survives it is a
/// confirmed engine-unavailable event. The events are counted by an
/// `AtomicUsize` that nothing resets — a successful outcome used to
/// clear the counter, and an engine that flapped (down, recovered, down
/// again) never reached the threshold within one batch. At
/// `MEOW_ABORT_THRESHOLD` events the abort flag goes up and the tasks
/// behind it skip the engine; the one batch-level liveness ping at the
/// end (see [`run_tunnel_reload`]) then classifies the collected
/// outcomes — an outage or per-request blips — and arms the backoff once.
struct BatchGuard {
    /// Confirmed engine-unavailable outcomes of the batch, cumulative.
    unavailable: AtomicUsize,
    /// Set once `unavailable` reaches `threshold`: the tasks behind it
    /// skip the engine and journal [`MEOW_ABORT_REASON`].
    aborted: AtomicBool,
    /// The event count that flips `aborted`.
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

    /// Record one confirmed engine-unavailable outcome. The counter never
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

    /// How many confirmed engine-unavailable outcomes the batch collected.
    fn unavailable(&self) -> usize {
        self.unavailable.load(Ordering::Relaxed)
    }
}

/// The T2 verdicts of one batch, collected while the checks run and
/// settled when the batch is over.
///
/// The fail ladder is charged only when the batch produced at least one
/// success. A batch in which *every* tunnel failed says more about the
/// test endpoint than about the proxies: the proxies sit behind different
/// exits, and an endpoint that is blocked or degraded on those exits is
/// indistinguishable from a dead tunnel in meow-rs' answer. Charging the
/// ladder then would empty a healthy pool because of one bad endpoint, so
/// such a batch is stamped unverified instead, the way a meow-rs outage
/// is.
struct T2Verdicts {
    successes: AtomicUsize,
    failures: std::sync::Mutex<Vec<T2Failure>>,
    /// The rows the engine never judged (a `ServiceUnavailable` outcome
    /// that survived the per-request retry), kept until the one
    /// batch-level liveness ping classifies them at the end of the batch.
    unavailable: std::sync::Mutex<Vec<(i64, String)>>,
}

/// One failed tunnel check, kept until the batch is over.
struct T2Failure {
    /// The proxy the check was about.
    id: i64,
    /// When the check ran; the ladder stamps its own timestamps.
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

    /// Collect one `ServiceUnavailable` outcome; the batch classifies
    /// them all with a single ping once the checks are done.
    fn record_unavailable(&self, id: i64, error: String) {
        self.unavailable
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .push((id, error));
    }

    fn successes(&self) -> usize {
        self.successes.load(Ordering::Relaxed)
    }

    /// The failures of the batch, ready to be charged (or not).
    fn take_failures(&self) -> Vec<T2Failure> {
        std::mem::take(
            &mut *self
                .failures
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner()),
        )
    }

    /// The rows the engine never judged, ready to be classified.
    fn take_unavailable(&self) -> Vec<(i64, String)> {
        std::mem::take(
            &mut *self
                .unavailable
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner()),
        )
    }
}

/// The wall-clock budget of one probe cycle.
///
/// The cycle has to fit into its period: a cycle that runs longer than
/// the interval overlaps the next one, and the daemon ends up with
/// several cycles in flight. The budget is three quarters of the period
/// (the rest is the gap between two cycles), and every lane asks it
/// before it starts a check.
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

    /// Whether the budget is spent.
    fn expired(&self) -> bool {
        tokio::time::Instant::now() >= self.deadline
    }

    /// What is left of the budget, in milliseconds.
    fn remaining_ms(&self) -> u64 {
        self.deadline
            .saturating_duration_since(tokio::time::Instant::now())
            .as_millis() as u64
    }
}

/// The check quota of one group of lanes.
///
/// `probe.sample_size` is documented as the number of proxies a cycle
/// checks, but every lane applied it on its own, so a cycle could run
/// five times the configured number of checks while the throughput the
/// admin panel reports matched none of them. The lanes now share one
/// quota per group of work: the quarantine drain, the coverage lanes
/// (the priority queue and the random sample) and the tunnel lanes
/// (the quarantine revival and the T2 batch).
struct CycleQuota {
    /// The size of the quota (`probe.sample_size`).
    total: usize,
    /// What the group may still run.
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
    /// most half of the quota, so the second lane of the group still
    /// gets a chance when the first one is saturated.
    fn take_first(&self, want: usize) -> usize {
        let cap = (self.total / 2).max(1);
        self.take(want.min(cap))
    }

    /// Take up to `want` checks for a later lane of the group.
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

    /// What the group may still run.
    fn remaining(&self) -> usize {
        self.remaining.load(Ordering::Relaxed)
    }
}

/// The row limit of a selector, from a quota.
fn as_limit(quota: usize) -> u32 {
    u32::try_from(quota).unwrap_or(u32::MAX)
}

/// The addresses the hosts of a cycle resolved to.
///
/// A host is resolved once per cycle: the lanes of a cycle ask for the
/// same hosts over and over (a feed full of rows on one host used to
/// spend one DNS lookup per row), and the T2 batch of a cycle reuses
/// what the T1 lanes of the same cycle already vetted.
#[derive(Default)]
struct CycleVet {
    resolved: std::sync::Mutex<std::collections::HashMap<String, std::sync::Arc<VetVerdict>>>,
}

/// The verdict of one host: the vetted addresses, or the reason the
/// address policy refused it.
type VetVerdict = Result<Vec<std::net::IpAddr>, String>;

impl CycleVet {
    /// The verdict of a host, if this cycle already resolved it.
    fn get(&self, host: &str) -> Option<std::sync::Arc<VetVerdict>> {
        self.resolved
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .get(host)
            .cloned()
    }

    /// Remember the verdict of a host for the rest of the cycle.
    fn put(&self, host: &str, verdict: std::sync::Arc<VetVerdict>) {
        self.resolved
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .insert(host.to_string(), verdict);
    }
}

/// The state the lanes of one cycle share: the wall-clock budget, the
/// check quotas and the hosts resolved so far.
struct Cycle {
    /// The wall-clock budget of the cycle.
    budget: CycleBudget,
    /// The quota of the quarantine drain (the recheck ladder).
    quarantine: CycleQuota,
    /// The quota of the coverage lanes (the priority queue and the random sample).
    coverage: CycleQuota,
    /// The quota of the tunnel lanes (the quarantine revival and the T2 batch).
    tunnel: CycleQuota,
    /// The hosts resolved so far.
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

    /// Print the resolved configuration as TOML and exit. The values are
    /// the effective ones: the file merged under the environment, which
    /// wins. The admin token is redacted.
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
    /// the in-memory working copy: the value is mirrored into the `meta`
    /// table ([`probe_repo::meta::MEOW_RETRY_AT_KEY`]) on every change and
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
        // A restart resumes the saved meow-rs pause: the backoff state is
        // mirrored into `meta` on every change, so a daemon that comes
        // back mid-backoff does not hammer a still-down engine on its
        // first cycle. Missing keys are a fresh start.
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
        // configured initial is the floor.
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
        // The backoff only grows past its initial length when a lane hit
        // an outage, so an unchanged length means there was nothing to
        // recover from and the event would be pure noise.
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
/// Missing keys mean "no outage on record" and restore the defaults.
async fn restore_meow_backoff(pool: &DbPool) -> fumox_core::Result<(i64, i64)> {
    let retry_at = match meta_get(pool, probe_repo::meta::MEOW_RETRY_AT_KEY).await? {
        Some(text) => text.parse::<i64>().unwrap_or(0),
        None => 0,
    };
    let backoff = match meta_get(pool, probe_repo::meta::MEOW_BACKOFF_SECS_KEY).await? {
        Some(text) => text.parse::<i64>().unwrap_or(0),
        None => 0,
    };
    Ok((retry_at, backoff))
}

/// Mirror the backoff state into `meta`; best effort, the way the other
/// meta stamps are. The gate itself is the in-memory atomic, so a failed
/// mirror costs at most a resumed contact attempt on the next restart.
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
    // The probe shares the database file with the server but owns only
    // the health status of a proxy. Its connections run behind an
    // authorizer that denies every other write, and the pool applies
    // the schema before those connections exist.
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
    // The controller address is vetted before the first cycle: a name
    // that resolves into public address space would carry the bearer
    // token to the internet, and the probe would have to be restarted
    // after every such change.
    ctx.meow
        .verify_address(ctx.config.ssrf_dns_timeout())
        .await
        .map_err(|error| anyhow::anyhow!("{error}"))?;
    // The generated config path is where meow-rs reads its own
    // configuration from: it has to be absolute (the engine resolves it
    // in its own filesystem, not in the probe's) and its directory has
    // to exist, or the batch would fail on every cycle with a write
    // error instead of a clear startup message.
    validate_meow_config_path(&ctx.config.meow.config_path)?;

    tokio::select! {
        result = run(ctx) => result?,
        () = shutdown_signal() => {},
    }

    tracing::info!("shutdown complete");
    Ok(())
}

/// Check the path the probe writes meow-rs' configuration to.
///
/// The path is passed to the engine as an absolute path in *its*
/// filesystem, so a relative one is meaningless to the engine even though
/// the probe could write it. The parent directory is created here, so an
/// unwritable location is reported at startup instead of on every cycle.
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
        // The cycle gets the period as its deadline. A cycle that runs
        // over it would overlap the next one, and two cycles in parallel
        // charge the same rows twice. The lanes themselves stop at 75% of
        // the period (see [`CycleBudget`]); this is the hard backstop for
        // a lane that hangs.
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
/// then the priority queue (fresh proxies), then the T1 sample
/// and the T2 batch.
///
/// The lanes that run later skip the rows an earlier lane already gave a
/// verdict, because both sides of each overlap draw from the same
/// population and both charge `fail_count` through `check_failed`:
///
/// * The random sample skips the rows the queue lane just covered: both
///   draw from the same `unknown` population and claiming a request only
///   deletes its queue row, so without the hand-off one dead proxy in both
///   selections collected two `fail_count` steps from this single cycle
///   and quarantined in half the cycles `fail_limit` promises.
/// * The T2 batch skips the rows the T1 sample just covered: `alive` rows
///   are in both selections, and a dead one drawn by both lanes quarantined
///   in one cycle at `fail_limit = 2`.
///
/// A skipped row loses nothing: the queue's leftovers fall to the sample,
/// and a T1-covered `alive` row is the head of the next cycle's T2 batch
/// (the batch orders by the oldest last T2 check).
async fn run_cycle(ctx: Arc<Context>) -> anyhow::Result<()> {
    let started = tokio::time::Instant::now();
    let cycle = Arc::new(Cycle::new(&ctx.config));
    let now = now_ts();
    // The queue depth before the cycle starts: the number of entries
    // waiting for their first check. A queue that does not drain is
    // invisible in the counters below (the cycle checked its quota, the
    // queue grew anyway).
    let queue_before = probe_repo::queue_depth(&ctx.pool).await.unwrap_or(0);

    // The lanes are independent of each other: a lane that fails is
    // logged and skipped, the other lanes of the cycle still run. A
    // broken lane used to cancel the whole cycle, so a single failing
    // write left the fleet unprobed until the next cycle.
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

    // The rows the lanes before the T2 batch judged, the hand-off that
    // keeps one proxy from being judged twice per cycle. The quarantine
    // lane joins the hand-off: a row it revived (its status leaves
    // `quarantine`) used to sit in the same cycle's T2 selection and was
    // tunnel-checked twice within one cycle.
    let mut judged = quarantine.claimed.clone();
    judged.extend_from_slice(&queued.claimed);

    let t1_started = tokio::time::Instant::now();
    let t1 = run_lane("t1", probe_t1_sample(ctx.clone(), &judged, cycle.clone())).await;
    let t1_ms = t1_started.elapsed().as_millis() as u64;
    judged.extend_from_slice(&t1.claimed);

    let t2_started = tokio::time::Instant::now();
    let t2 = run_lane("t2", probe_t2_batch(ctx.clone(), &judged, cycle.clone())).await;
    let t2_ms = t2_started.elapsed().as_millis() as u64;

    // The queue depth after the cycle: what is left of the entries that
    // waited for their first check when the cycle started.
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

/// Run one lane of the cycle.
///
/// A lane that fails is logged with its whole error chain and the name
/// of the lane, and the cycle continues with the other lanes.
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

/// What one lane covered: `checked` is how many verdicts it produced (for
/// the cycle log), `claimed` the rows the lane took for itself this cycle:
/// the queue lane's up-front claims (verdict or not), the random sample's
/// verdict rows. `run_cycle` hands each lane's `claimed` to the lane that
/// runs next, so one proxy is never judged twice in a single cycle.
///
/// `blocked` counts the rows the private-address policy refused. They are
/// part of `checked` (a refusal is a failed check and the fail ladder
/// runs), but they are counted separately as well: a lane whose verdicts
/// are mostly refusals is a policy problem, not a health problem, and
/// folding the two together hid it.
///
/// `deferred` counts the rows the cycle did not check because its
/// wall-clock budget was spent. A deferred row is not a verdict: it is
/// not charged, not journaled, and the next cycle picks it up.
///
/// `engine_faults` counts the rows the lane never judged because the
/// engine was unavailable (the tunnel lanes only); they are journaled
/// unverified and never charged.
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

/// Priority lane: T1 checks the server enqueued at source
/// refresh time for freshly inserted proxies. Drained newest first, capped
/// by the coverage quota of the cycle (shared with the random sample
/// below). Requests are claimed (deleted) up-front, so a mid-batch crash
/// cannot turn them into an endless retry loop; anything not yet covered
/// falls back to the random sample below.
async fn probe_queued_checks(ctx: Arc<Context>, cycle: Arc<Cycle>) -> anyhow::Result<LaneOutcome> {
    // The queue is the first lane of the coverage group: it may claim at
    // most half of that quota, so the random sample still gets a share
    // when the queue is full.
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
/// `already_checked` covered earlier in this cycle (the quarantine lane
/// and the queue lane, see [`run_cycle`]). The sample is a random draw
/// with a quota, so dropping the overlap simply leaves the cycle with a
/// slightly smaller one. Returns the rows it gave a verdict, the hand-off
/// the T2 batch of the same cycle skips (see [`probe_t2_batch`]).
async fn probe_t1_sample(
    ctx: Arc<Context>,
    already_checked: &[i64],
    cycle: Arc<Cycle>,
) -> anyhow::Result<LaneOutcome> {
    // What is left of the coverage quota after the queue lane took its
    // share.
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
/// row (in bytes, escapes included): long enough for every real engine or
/// policy message, short enough that one crafted value cannot flood
/// either.
const MAX_REASON_LEN: usize = 300;

/// Replace every control character of an externally sourced text with a
/// visible escape and cap the length.
///
/// Feed- and engine-controlled texts (a stored scheme, a host, the body
/// of a delay-test error) used to reach the log and `probe_results.error`
/// verbatim: a crafted value could forge log lines or park a terminal in
/// a weird mode. The replacement keeps the reason readable — a `\r`
/// becomes a visible `\u{d}` — and bounded (`MAX_REASON_LEN`, escapes
/// included), and the same cleaned text goes to both sinks, so the log
/// line and the journal row never disagree.
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

/// The fields of a candidate row the shared T1 pipeline reads. The queue
/// lane, the random sample and the quarantine recheck keep their row
/// types and share the pipeline written once around them (see
/// [`run_t1_checks`]).
trait T1Source {
    /// The proxy id the verdicts map back to.
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

/// Which T1 lane a batch belongs to: the lane names the aggregated
/// refusal line and picks the failure handler and the wording of the
/// skip warnings.
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
    /// The lane tag of the aggregated refusal line.
    fn refusals_lane(self) -> &'static str {
        match self {
            T1Lane::Regular => "T1",
            T1Lane::Quarantine => "quarantine recheck",
        }
    }

    /// What happens to a row this lane skips (an unknown scheme, an
    /// out-of-range port, unparseable parameters): the log names the next
    /// step, not just the drop.
    fn skip_note(self) -> &'static str {
        match self {
            T1Lane::Regular => "the row stays due and is retried every cycle",
            T1Lane::Quarantine => "the row keeps its ladder step and is retried every cycle",
        }
    }
}

/// Run concurrent T1 checks for the candidates and apply each outcome to
/// the lifecycle. The shared body of the three T1 lanes (queue, sample,
/// quarantine recheck): parse and port gates, the check kind, the vetting
/// pass, the spawned checks and the counters are written once here; the
/// lanes differ in their row types and in the failure handler (see
/// [`T1Lane`]). Returns the verdict count plus the ids of every row a
/// verdict was produced for (vet-refused rows included, rows skipped for
/// an unknown scheme or an out-of-range port not: they were not judged).
async fn run_t1_checks<R: T1Source + Send + Sync + 'static>(
    ctx: Arc<Context>,
    candidates: Vec<R>,
    cycle: Arc<Cycle>,
    lane: T1Lane,
) -> anyhow::Result<LaneOutcome> {
    let semaphore = Arc::new(Semaphore::new(ctx.config.probe.concurrency.max(1)));
    // Parse and port checks come first so the vetting pass below only
    // covers rows that can actually be dialed.
    let mut ready: Vec<(R, t1::CheckKind, u16, Option<String>)> = Vec::new();
    for candidate in candidates {
        let id = candidate.probe_id();
        let Ok(scheme) = candidate.probe_scheme().parse::<Scheme>() else {
            tracing::warn!(
                id,
                scheme = %sanitize_reason(candidate.probe_scheme()),
                "unknown scheme, skipped; {}",
                lane.skip_note()
            );
            continue;
        };
        let Ok(port) = u16::try_from(candidate.probe_port()) else {
            tracing::warn!(
                id,
                port = candidate.probe_port(),
                "port out of range, skipped; {}",
                lane.skip_note()
            );
            continue;
        };
        let Ok(entry) = candidate.probe_entry() else {
            tracing::warn!(
                id,
                "stored parameters do not parse, skipped; {}",
                lane.skip_note()
            );
            continue;
        };
        let kind = t1::check_kind(scheme, &entry);
        // The name the handshake presents: the node's own SNI when it
        // carries one, else the stored host.
        let server_name = fumox_core::params::sni(&entry);
        ready.push((candidate, kind, port, server_name));
    }
    let hosts: Vec<String> = ready
        .iter()
        .map(|(candidate, _, _, _)| candidate.probe_host().to_string())
        .collect();
    let mut tasks = tokio::task::JoinSet::new();
    let mut blocked = 0usize;
    let mut refusals: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
    // The ids of the rows a verdict was produced for: the hand-off to the
    // lane that runs next. A row the budget deferred is not in it, the
    // next lane may still pick it up.
    let mut checked_ids: Vec<i64> = Vec::new();
    for ((candidate, kind, port, server_name), verdict) in ready
        .into_iter()
        .zip(vet_hosts(&ctx, &hosts, &cycle.vetted).await)
    {
        let id = candidate.probe_id();
        let vetted = match verdict {
            Ok(addrs) => addrs,
            Err(reason) => {
                // Per row: a debug line, the batch reports the refusals
                // in one aggregated warning below.
                let reason = sanitize_reason(&reason);
                tracing::debug!(
                    lane = lane.refusals_lane(),
                    id,
                    %reason,
                    "probe target blocked by the private-address policy, journaled as a failed check"
                );
                *refusals.entry(reason.clone()).or_insert(0) += 1;
                match lane {
                    T1Lane::Regular => {
                        apply_vet_block(&ctx, id, kind.as_str(), &reason).await;
                    }
                    T1Lane::Quarantine => {
                        apply_quarantine_vet_block(
                            &ctx,
                            id,
                            kind.as_str(),
                            candidate.ladder_step().unwrap_or(0),
                            &reason,
                        )
                        .await;
                    }
                }
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
            // scope and is only dropped after the join loop below awaits
            // every spawned task, so it cannot close while a task is
            // awaiting a permit. No `.expect` panic, no deadlock risk.
            let _permit = match semaphore.acquire_owned().await {
                Ok(permit) => permit,
                Err(_) => return None,
            };
            // The cycle may have spent its budget while this task waited
            // for its turn: the row is not checked, not charged and not
            // journaled, the next cycle picks it up.
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
            match lane {
                T1Lane::Regular => perform_t1_check(&ctx, id, &target).await,
                T1Lane::Quarantine => {
                    perform_quarantine_check(&ctx, id, &target, step.unwrap_or(0), &delays).await
                }
            }
            Some(id)
        });
    }
    // The verdicts the batch produced: a task that ran returns the id it
    // judged, a task the budget deferred returns nothing and is counted
    // apart (it is not a verdict and not a charge).
    let mut checked = blocked;
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

/// Report the private-address refusals of one batch in a single line.
///
/// The per-row line is a debug entry: a feed full of internal targets
/// produces one refusal per row, and a warning each drowned the batch
/// summary the operator actually reads.
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
        ctx.config.ssrf_dns_timeout(),
    )
    .await
}

/// Vet every host concurrently, preserving the input order.
///
/// A host is resolved once per cycle: the rows of a feed often share
/// their host, and every row used to spend a DNS lookup of its own. The
/// verdict of a host the cycle already resolved is reused, so the T2
/// batch of a cycle reuses what the T1 lanes of the same cycle vetted.
///
/// Each vetting pass is a DNS lookup bounded by `dns_timeout` (5 s by default), the
/// lanes used to run these serially in their select loops before spawning
/// any check, so a batch full of dead names queued one timeout per
/// candidate ahead of every real verdict while the check semaphore sat
/// idle. Concurrency is bounded by `probe.concurrency`, the same budget
/// the checks themselves run under.
async fn vet_hosts(ctx: &Arc<Context>, hosts: &[String], cache: &CycleVet) -> Vec<VetVerdict> {
    // The unique hosts of the batch and the position of every row in it.
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

    // The hosts this cycle has not resolved yet.
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
                    // scope and cannot close before the join loop below.
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
            // row on the ordinary fail ladder instead of buffering it.
            match verdicts[index].as_deref() {
                Some(Ok(addrs)) => Ok(addrs.clone()),
                Some(Err(reason)) => Err(reason.clone()),
                None => Err("vetting task panicked".to_string()),
            }
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
            // `t2_unverified` counts as a T2-tier attempt too: the row was
            // never judged, so an earlier T2 failure may still be unpaid.
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
                // its verification (only a failed T2 demotes it).
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
            // and the journal.
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

/// Bump the fail counter, quarantining when the consecutive-failure limit
/// is reached.
async fn apply_regular_failure(ctx: &Context, id: i64, now: i64) {
    let probe = &ctx.config.probe;
    let (min_secs, spread_secs) = second_chance_bounds(probe);
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
/// tunnel check ([`revive_quarantined_via_t2`]): a T1 connect cannot succeed
/// against a QUIC port; everything else walks the shared T1 pipeline (see
/// [`run_t1_checks`]). Returns the counters of both lanes plus the ids
/// every verdict was produced for — the hand-off the T1 and T2 lanes of
/// the same cycle skip (see [`run_cycle`]).
async fn probe_due_quarantine(
    ctx: Arc<Context>,
    now: i64,
    cycle: Arc<Cycle>,
) -> anyhow::Result<LaneOutcome> {
    // The revival lane is the first lane of the tunnel group: it may
    // claim at most half of that quota, so the regular T2 batch of the
    // cycle still gets a share.
    let revival_quota = cycle
        .tunnel
        .take_first(ctx.config.probe.sample_size as usize);
    let t2_due = proxies::select_due_quarantine_t2(&ctx.pool, now, as_limit(revival_quota)).await?;
    let revived = revive_quarantined_via_t2(ctx.clone(), t2_due, cycle.clone()).await?;
    // The recheck ladder has its own quota: the drain of the quarantine
    // is the one number the admin panel reports, and it must not
    // compete with the coverage lanes for it.
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
/// counters of the batch plus the ids of every row it judged — the
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
    // The counters the cycle log prints: a row the guard kept away from
    // the engine was still journaled (unverified), so it shows in
    // `checked` next to the verdict rows, the way this lane always
    // counted.
    Ok(LaneOutcome {
        checked: outcome.checked + outcome.aborted,
        blocked: outcome.blocked,
        engine_faults: outcome.engine_faults,
        deferred: outcome.deferred,
        claimed: outcome.claimed,
    })
}

/// The tunnel lanes of the cycle: they share the whole batch machinery
/// (the vetting pass, the required-field validation, the engine-config
/// preparation with the split retry, the reload, the spawned checks, the
/// batch-end fault classification) and differ only in the two handlers (a
/// vet refusal, a record the config cannot carry) and in how a settled
/// tunnel failure is charged.
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
    /// The lane tag of the aggregated refusal line.
    fn refusals_lane(self) -> &'static str {
        match self {
            TunnelLane::T2 { .. } => "T2",
            TunnelLane::Revival => "quarantine revival",
        }
    }
}

/// What one tunnel batch (the regular T2 batch, a quarantine revival, or
/// one split half of either) produced. `checked` counts rows that got a
/// real verdict (an engine contact or a policy refusal, both journaled);
/// `aborted` counts rows the mid-batch guard kept away from meow-rs;
/// `skipped` counts rows the config could not carry; `blocked` counts the
/// private-address refusals; `engine_faults` counts rows the engine never
/// judged (journaled unverified, never charged); `deferred` counts the
/// rows the cycle budget spent. `claimed` carries the ids of the judged
/// rows: the hand-off the lanes of the same cycle skip.
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
    /// Fold the outcome of one split half into this one.
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
/// the row carries a verdict (the id rides along for the batch's
/// hand-off); `Ran` contacted the engine but the engine never judged the
/// row (a `ServiceUnavailable` outcome, classified by the one batch-level
/// ping); `Aborted` took the guard's early return without a request;
/// `Deferred` was never started because the cycle ran out of budget.
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
    // The SSRF gate first: a refused target is a failed check, as in the T1 lanes.
    let hosts: Vec<String> = due.iter().map(|row| row.host.clone()).collect();
    let mut blocked = 0usize;
    let mut refusals: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
    let mut pins: std::collections::HashMap<String, std::net::IpAddr> =
        std::collections::HashMap::new();
    let mut batch: Vec<proxies::ProxyRow> = Vec::with_capacity(due.len());
    let mut claimed: Vec<i64> = Vec::new();
    for (row, verdict) in due
        .into_iter()
        .zip(vet_hosts(&ctx, &hosts, &cycle.vetted).await)
    {
        match verdict {
            Ok(vetted) => {
                if let Some(ip) =
                    fumox_core::ssrf::pick_vetted(&vetted, fumox_core::models::IpFamily::Any)
                {
                    // The batch is deduplicated by `row.id` upstream
                    // (`proxies::select_t2_candidates`), so two rows that
                    // share a hostname overwrite the same pin map entry:
                    // operator intent is unambiguous and the result is
                    // the same vetted IP.
                    pins.insert(row.host.clone(), ip);
                }
                batch.push(row);
            }
            Err(reason) => {
                let reason = sanitize_reason(&reason);
                tracing::debug!(id = row.id, %reason, "tunnel target blocked by the private-address policy, journaled as a failed check");
                *refusals.entry(reason.clone()).or_insert(0) += 1;
                match lane {
                    TunnelLane::T2 { .. } => {
                        journal_and_fail(
                            &ctx,
                            row.id,
                            &format!("blocked by the private-address policy: {reason}"),
                        )
                        .await;
                    }
                    TunnelLane::Revival => {
                        apply_quarantine_vet_block(&ctx, row.id, T2_KIND, row.ladder_step, &reason)
                            .await;
                    }
                }
                claimed.push(row.id);
                blocked += 1;
            }
        }
    }
    log_refusals(lane.refusals_lane(), blocked, &refusals);

    // The engine refuses a config whose proxy lacks its credential, and
    // one such record used to void the whole batch at `PUT /configs`:
    // validate the required fields here and reject the record on the
    // lane's own ladder instead of handing it to the engine.
    let mut skipped = 0usize;
    let mut validated: Vec<proxies::ProxyRow> = Vec::with_capacity(batch.len());
    for row in batch {
        let problem = row
            .to_entry()
            .ok()
            .and_then(|entry| clash::required_field_problem(&entry));
        match problem {
            Some(problem) => {
                skipped += 1;
                claimed.push(row.id);
                let reason =
                    format!("proxy entry cannot run in the tunnel engine config: {problem}");
                match lane {
                    TunnelLane::T2 { .. } => journal_and_fail(&ctx, row.id, &reason).await,
                    TunnelLane::Revival => {
                        reject_quarantine_record(&ctx, row.id, row.ladder_step, &reason).await
                    }
                }
            }
            None => validated.push(row),
        }
    }
    let batch = validated;
    if batch.is_empty() {
        return Ok(TunnelOutcome {
            checked: blocked,
            blocked,
            skipped,
            claimed,
            ..TunnelOutcome::default()
        });
    }

    // Cheap liveness check first: no point rewriting the config file when
    // the service is down anyway. An outage here stamps the whole batch
    // unverified (no fail budget) and backs off.
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

/// Prepare the engine config of one (sub-)batch, reload the engine, and
/// run the checks of the batch. A `PUT /configs` refusal splits the batch
/// in half and retries each half on its own: the probe cannot know which
/// record the engine objected to, and one bad record must not void the
/// verdicts of the rest. The recursion bottoms out at a single row, which
/// is journaled unverified with the reload error. A genuinely down engine
/// never gets this far (the liveness gate above refuses the batch), so a
/// split costs at most log2(n) reload attempts.
async fn run_tunnel_reload(
    ctx: Arc<Context>,
    batch: Vec<proxies::ProxyRow>,
    pins: &std::collections::HashMap<String, std::net::IpAddr>,
    cycle: Arc<Cycle>,
    lane: TunnelLane,
) -> anyhow::Result<TunnelOutcome> {
    let included = match prepare_engine_config(&ctx, &batch, pins) {
        Ok(included) => included,
        Err(error) => {
            // The engine never sees the batch: the rows are journaled
            // unverified (no ladder charge) and the lane backs off, the
            // same treatment as a failed reload.
            let error = sanitize_reason(&error.to_string());
            tracing::warn!(%error, "meow-rs config could not be prepared, the tunnel batch failed with backoff");
            ctx.backoff_meow().await;
            journal_engine_failure(
                &ctx,
                &batch,
                &format!("meow-rs config could not be prepared: {error}"),
            )
            .await;
            return Ok(TunnelOutcome {
                aborted: batch.len(),
                engine_faults: batch.len(),
                ..TunnelOutcome::default()
            });
        }
    };

    if let Err(error) = ctx.meow.reload_config(&ctx.config.meow.config_path).await {
        if batch.len() > 1 {
            let error = sanitize_reason(&error);
            tracing::warn!(
                rows = batch.len(),
                %error,
                "meow-rs refused the config reload, splitting the batch in half"
            );
            let mid = batch.len() / 2;
            // Boxed: the recursion depth is the log2 of the batch size,
            // but the future's size must not depend on itself.
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
        return Ok(TunnelOutcome {
            aborted: batch.len(),
            engine_faults: batch.len(),
            ..TunnelOutcome::default()
        });
    }
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
    stamp_meow_memory(&ctx).await;

    let semaphore = Arc::new(Semaphore::new(ctx.config.probe.concurrency.max(1)));
    // The per-batch decision state: the confirmed engine-unavailable
    // events escalate to an abort (see [`BatchGuard`]), and the one
    // batch-level liveness ping below classifies the collected outcomes
    // once the checks are done.
    let batch_guard = Arc::new(BatchGuard::new(MEOW_ABORT_THRESHOLD));
    let verdicts = Arc::new(T2Verdicts::new());
    // The rows the engine never judged: an outage, a refused request or a
    // run of blips. They are journaled unverified and never charged, and
    // the count is what tells an engine fault apart from a dying proxy in
    // the cycle log.
    let engine_faults = Arc::new(AtomicUsize::new(0));
    // One test URL for the whole batch: every check asks the same
    // endpoint, so a batch is internally consistent and the log line
    // below names the endpoint the verdicts are about.
    let test_url = ctx.meow.cycle_test_url().to_string();
    tracing::debug!(test_url = %test_url, "tunnel batch test URL");
    let mut tasks = tokio::task::JoinSet::new();
    let mut skipped = 0usize;
    let mut claimed: Vec<i64> = Vec::new();
    for row in batch {
        // Rows that never made it into the generated config (their entry
        // could not be serialized, the config preparation skipped them)
        // must get the real reason journaled, routing them through the
        // engine would produce a misleading "proxy not found" failure.
        if !included.contains(&row.id) {
            let reason = "proxy entry cannot be serialized for the T2 engine config";
            match lane {
                TunnelLane::T2 { .. } => journal_and_fail(&ctx, row.id, reason).await,
                TunnelLane::Revival => {
                    reject_quarantine_record(&ctx, row.id, row.ladder_step, reason).await
                }
            }
            skipped += 1;
            claimed.push(row.id);
            continue;
        }
        let (ctx, semaphore) = (ctx.clone(), semaphore.clone());
        let batch_guard = batch_guard.clone();
        let verdicts = verdicts.clone();
        let engine_faults = engine_faults.clone();
        let test_url = test_url.clone();
        let budget = cycle.budget.clone();
        let step = row.ladder_step;
        let id = row.id;
        tasks.spawn(async move {
            // The semaphore lives in this scope until the join loop below
            // returns; a closed semaphore here is structurally impossible.
            let _permit = match semaphore.acquire_owned().await {
                Ok(permit) => permit,
                // Structurally impossible, and counted as aborted rather
                // than checked so an impossible close cannot inflate the
                // real-check counter.
                Err(_) => return TunnelTask::Aborted,
            };
            // The cycle ran out of budget while this task waited for its
            // turn: the row is not checked, not charged and not
            // journaled, the next cycle picks it up.
            if budget.expired() {
                return TunnelTask::Deferred;
            }
            if batch_guard.is_aborted() {
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
                &batch_guard,
                &engine_faults,
            )
            .await
        });
    }
    // The counters the cycle log prints, kept honest during an outage:
    // only tasks that reached the engine are real contacts, the guard's
    // early returns count as aborted and serialize skips as skipped,
    // never folded into `checked`.
    let mut checked = 0usize;
    let mut aborted = 0usize;
    let mut deferred = 0usize;
    while let Some(result) = tasks.join_next().await {
        match result {
            Ok(TunnelTask::Judged(id)) => {
                checked += 1;
                claimed.push(id);
            }
            Ok(TunnelTask::Ran) => checked += 1,
            Ok(TunnelTask::Aborted) => aborted += 1,
            Ok(TunnelTask::Deferred) => deferred += 1,
            Err(error) => tracing::warn!(%error, "tunnel check task panicked"),
        }
    }

    // The rows the engine never judged are classified by one liveness
    // ping for the whole batch: a down engine failed all of them (an
    // outage), an answering engine hit per-request blips. One ping
    // replaces the per-task probes the `ServiceUnavailable` path used to
    // make, and the backoff is armed exactly once, on the escalation.
    let unavailable = verdicts.take_unavailable();
    if !unavailable.is_empty() {
        let engine_down = ctx.meow.alive().await.is_err();
        for (id, error) in &unavailable {
            let error = sanitize_reason(error);
            if engine_down {
                journal_engine_fault(
                    &ctx,
                    *id,
                    &format!("meow-rs unavailable mid-batch: {error}"),
                )
                .await;
            } else {
                journal_engine_fault(&ctx, *id, &format!("meow-rs transient error: {error}")).await;
            }
        }
        if engine_down {
            if batch_guard.unavailable() >= MEOW_ABORT_THRESHOLD {
                tracing::warn!(
                    unavailable = batch_guard.unavailable(),
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

    // The batch is over: charge the failed tunnels (or not, when the test
    // endpoint is the suspect), the way the lane's ladder reads them.
    match lane {
        TunnelLane::T2 {
            fail_limit,
            min_secs,
            spread_secs,
        } => {
            settle_t2_failures(
                &ctx,
                &verdicts,
                &test_url,
                fail_limit,
                min_secs,
                spread_secs,
            )
            .await;
        }
        TunnelLane::Revival => settle_revival_failures(&ctx, &verdicts, &test_url).await,
    }
    Ok(TunnelOutcome {
        checked,
        aborted,
        skipped,
        blocked: 0,
        engine_faults: engine_faults.load(Ordering::Relaxed),
        deferred,
        claimed,
    })
}

/// One tunnel check of the shared runner (a regular T2 check or a
/// quarantine revival check; see [`TunnelLane`]): the outcome contract is
/// the runner's. `ladder_step` is the row's quarantine ladder step (`None`
/// outside the revival lane); it only decides how a failure is charged,
/// the check itself is the same. Returns the [`TunnelTask`] the join loop
/// counts.
async fn perform_tunnel_check(
    ctx: &Context,
    id: i64,
    ladder_step: Option<i64>,
    test_url: &str,
    verdicts: &T2Verdicts,
    guard: &BatchGuard,
    engine_faults: &AtomicUsize,
) -> TunnelTask {
    let name = clash::proxy_name(id);
    let now = now_ts();
    // Retry transient `ServiceUnavailable` (transport blip, one malformed
    // payload, single 5xx on a flapping connection): re-asking the same
    // request absorbs most of them and keeps them off the engine-fault
    // counter, which is reserved for patterns the engine cannot recover
    // from within the cycle.
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
            // 2026-09-10): the proxy becomes `ready`.
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
            TunnelTask::Judged(id)
        }
        DelayOutcome::ProxyFailed(message) => {
            // The engine answered authoritatively, the proxy's tunnel
            // died, but the engine itself is alive.
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
            // test endpoint, not about the rows.
            verdicts.record_failure(T2Failure {
                id,
                now,
                ladder_step,
            });
            TunnelTask::Judged(id)
        }
        DelayOutcome::ServiceUnavailable(error) => {
            // Not a verdict: the row is collected and classified by the
            // one liveness ping after the batch (see the join loop of
            // [`run_tunnel_reload`]). Neither outcome charges the proxy:
            // an engine that cannot run the test is not evidence about
            // the tunnel, so the row is journaled as *unverified*
            // ([`journal_engine_fault`]) and its fail budget stays
            // untouched.
            engine_faults.fetch_add(1, Ordering::Relaxed);
            guard.record_unavailable();
            verdicts.record_unavailable(id, error);
            TunnelTask::Ran
        }
    }
}

/// The revival lane's counterpart of [`journal_and_fail`]: a record the
/// engine config cannot carry is a failed recheck, the ladder advances
/// (or the proxy is removed after the last configured step).
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
/// endpoint, so the rows stay where they are and are retried when the
/// endpoint answers again.
async fn settle_revival_failures(ctx: &Context, verdicts: &T2Verdicts, test_url: &str) {
    let failures = verdicts.take_failures();
    if failures.is_empty() {
        return;
    }
    if verdicts.successes() == 0 && failures.len() > 1 {
        tracing::warn!(
            failures = failures.len(),
            test_url = %test_url,
            "every T2 revival check failed the tunnel: the test endpoint is suspect, \
             the quarantine ladder was not advanced"
        );
        return;
    }
    // The ladder of the whole batch advances in one transaction.
    let rows: Vec<(i64, i64, i64)> = failures
        .iter()
        .map(|failure| (failure.id, failure.now, failure.ladder_step.unwrap_or(0)))
        .collect();
    match proxies::quarantine_check_failed_batch(
        &ctx.pool,
        &rows,
        &ctx.config.probe.recheck_delays_secs,
    )
    .await
    {
        Ok(transitions) => {
            for (id, transition) in transitions {
                match transition {
                    proxies::Transition::Removed => {
                        tracing::info!(id, "proxy removed after the final failed recheck")
                    }
                    _ => tracing::debug!(id, "quarantine revival failed, ladder advanced"),
                }
            }
        }
        Err(error) => tracing::warn!(%error, "failed to advance quarantine ladder"),
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
            // The reason names the dial target and the handshake error,
            // both feed-controlled: sanitize before it reaches the log
            // and the journal.
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
/// rows the config preparation could not serialize. Folding the aborted rows
/// into `checked` made an outage cycle read as a healthy batch in exactly
/// the situation the counter is watched for.
///
/// `blocked` counts the private-address refusals of the batch. They are
/// part of `checked` (a refusal is a failed check and the fail ladder
/// runs), but a batch whose verdicts are mostly refusals is a policy
/// problem, not a health problem.
///
/// `engine_faults` counts the rows the engine never judged: an outage,
/// a refused request or a run of blips. They are journaled unverified
/// and never charged, so the counter is the one an operator watches to
/// tell "the engine was down" from "the proxies are dying".
#[derive(Default)]
struct T2Outcome {
    checked: usize,
    aborted: usize,
    skipped: usize,
    blocked: usize,
    engine_faults: usize,
    /// The rows the cycle did not check because its wall-clock budget was
    /// spent. They are not charged and not journaled.
    deferred: usize,
}

/// Write the generated Clash YAML of one meow-rs batch (a T2 batch or a
/// quarantine revival batch) to `meow.config_path`.
///
/// The YAML carries every proxy credential in plain text, same exposure as
/// the SQLite database, so the file is written the hard way:
///
/// * the content goes into a temporary file in the *same* directory
///   (`rename` is only atomic within one filesystem), created
///   exclusively (`create_new`) and without following a symlink
///   (`O_NOFOLLOW`): a name planted in the directory cannot be written
///   through, and the temporary file is never world-readable;
/// * the mode is set on the open descriptor (`fchmod`), so a umask can
///   only make it stricter, and the file is never briefly readable by
///   anyone else;
/// * the temporary file is fsynced and then renamed onto the target: the
///   engine reads either the old or the new config, never a half-written
///   one, and a crash in between leaves the old file in place. The
///   rename does not follow a symlink either, it replaces it.
///
/// 0640, not 0600: the file lives in a volume shared with the meow-rs
/// container, which runs under a different uid (the proxy kernel gets no
/// access to the database) and reads the config through the shared group.
/// The group is the only reader besides the owner, so the credentials stay
/// out of reach of every other user on the host.
///
/// On a platform without POSIX modes there is no equivalent of `fchmod`:
/// the file is created exclusively and renamed into place, and access is
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
    // The temporary file lives next to the target (same filesystem, so the
    // rename is atomic) and carries the credentials only for the duration
    // of the write.
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
            // `create_new` is `O_CREAT|O_EXCL`: the file must not exist
            // yet, so an existing name (a symlink, a hard link, another
            // process' file) is a hard error instead of a truncation.
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
        // fchmod on the open fd, no path re-resolution between check and
        // use. It ignores the umask, so the mode is exactly 0640.
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

/// Flush the directory entry of a renamed file, so the rename itself
/// survives a crash. Best effort: a filesystem that refuses to open the
/// directory for reading (or a platform without directories) must not
/// fail the write.
fn sync_dir(dir: &std::path::Path) {
    #[cfg(unix)]
    if let Ok(handle) = std::fs::File::open(dir) {
        let _ = handle.sync_all();
    }
    #[cfg(not(unix))]
    let _ = dir;
}

/// The engine records of one batch: the storage row → entry conversion is
/// the calling layer's job, the config writer in [`clash`] only formats.
/// A row whose stored parameters do not parse yields no record and stays
/// out of the returned list, so the caller journals it as an entry that
/// cannot be serialized instead of feeding the engine a proxy it would
/// report as not found.
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
/// and write it to `meow.config_path`.
///
/// A failure here means the engine will never see the batch. Both callers
/// treat it like a failed reload: the rows are journaled unverified (never
/// charged) and the T2 lanes back off.
fn prepare_engine_config(
    ctx: &Context,
    batch: &[proxies::ProxyRow],
    pins: &std::collections::HashMap<String, std::net::IpAddr>,
) -> anyhow::Result<Vec<i64>> {
    let (yaml, included) = clash::generate(&engine_records(batch, pins), ctx.config.meow.ipv6)
        .map_err(|error| anyhow::anyhow!("cannot generate the meow config: {error}"))?;
    write_meow_config(&ctx.config.meow.config_path, &yaml)?;
    Ok(included)
}

/// Generate a Clash batch, reload meow-rs, and delay-test every proxy
/// through a real tunnel.
///
/// `already_checked` carries the ids the lanes before this one (the
/// quarantine lane and the T1 lanes) gave a verdict this cycle (see
/// [`run_cycle`]); those rows are dropped from the batch, a dead one drawn
/// by both lanes would otherwise collect one `fail_count` step from each
/// and quarantine in half the cycles `fail_limit` promises. Dropping the
/// overlap simply leaves the recency-prioritized batch slightly smaller;
/// the dropped rows are the head of the next cycle's batch anyway.
///
/// Success is strict: only a tunnel that came
/// up *and* answered with a measured `delay` counts, anything else the
/// engine reports is a failure. A meow-rs outage is *not* charged to the
/// proxies: every proxy that was due one is journaled
/// (as `probe_kind='t2_unverified'`, the record that un-sticks the recency
/// queue) and stamped as unverified, but its own fail budget and the
/// quarantine path stay untouched, so an outage cannot retire a healthy
/// pool ([`journal_engine_fault`]). The cycle still
/// backs off so a dead meow-rs is not hammered every minute.
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

    // What is left of the tunnel quota after the quarantine revival lane
    // took its share.
    let quota = cycle.tunnel.take(ctx.config.probe.sample_size as usize);
    let rows = proxies::select_t2_candidates(&ctx.pool, as_limit(quota)).await?;
    // The hand-off from the lanes before this one (the quarantine lane
    // and the T1 lanes): their verdict rows are already judged,
    // re-judging them here would double-charge the fail ladder.
    let covered: std::collections::HashSet<i64> = already_checked.iter().copied().collect();
    let rows: Vec<proxies::ProxyRow> = rows
        .into_iter()
        .filter(|row| !covered.contains(&row.id))
        .collect();
    // The core mapping is the authority on what meow-rs can tunnel: a
    // scheme it cannot express has no T2 verdict at all, and vetting such
    // a row would charge it for a check that could never run.
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
/// A batch in which *no* check succeeded and more than one tunnel failed is
/// not a verdict about the proxies: it is a verdict about the test
/// endpoint. meow-rs answers a blocked or degraded endpoint exactly like
/// a dead tunnel, the proxies sit behind different exits, and charging
/// the ladder then would empty a healthy pool because of one bad
/// endpoint. Such a batch stamps the rows unverified instead, the way a
/// meow-rs outage does.
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
    if verdicts.successes() == 0 && failures.len() > 1 {
        tracing::warn!(
            failures = failures.len(),
            test_url = %test_url,
            "every T2 check of the batch failed the tunnel: the test endpoint is suspect, \
             the proxies were not charged"
        );
        let ids: Vec<i64> = failures.iter().map(|failure| failure.id).collect();
        if let Err(error) = proxies::check_engine_unavailable_batch(&ctx.pool, &ids, now_ts()).await
        {
            tracing::warn!(%error, "failed to stamp the T2 engine fault");
        }
        return;
    }
    // The ladder of the whole batch is charged in one transaction: the
    // per-row version took the write lock once per failed tunnel.
    let ids: Vec<i64> = failures.iter().map(|failure| failure.id).collect();
    let transitions = match proxies::check_failed_batch(
        &ctx.pool,
        &ids,
        now_ts(),
        fail_limit,
        min_secs,
        spread_secs,
        true,
    )
    .await
    {
        Ok(transitions) => transitions,
        Err(error) => {
            tracing::warn!(%error, "failed to record the T2 failures");
            return;
        }
    };
    for (id, transition) in transitions {
        if transition == proxies::Transition::Quarantined {
            tracing::info!(id, "proxy quarantined after T2 failures");
        }
    }
}

/// Journal one failed T2 attempt and run the fail ladder: a proxy that got
/// a verdict, whether the tunnel itself failed or the target was vet-refused,
/// receives a `probe_kind='t2'` failure record, which is also what moves it
/// forward in the recency queue.
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
/// An engine outage journals the attempt (as `probe_kind='t2_unverified'`,
/// the record that un-sticks the recency queue) and stamps last_t2_failed_at
/// plus the ready -> alive demote, but never charges the proxy's fail
/// budget. The kind is the point: a `t2` row means "the tunnel was judged
/// and failed", an `t2_unverified` row means "no verdict was possible".
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
/// unverified this cycle, and an unrecorded skip is indistinguishable from
/// an empty pool (and pins the head of the recency queue for the whole
/// outage). No fail budget is charged, see [`journal_engine_fault`].
async fn journal_engine_failure(ctx: &Context, batch: &[proxies::ProxyRow], reason: &str) {
    let now = now_ts();
    // The batch is journaled in one statement and stamped in one
    // transaction: an outage hits every due row of the batch, and a
    // hundred round trips would keep the cycle running long after the
    // engine was gone.
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
    if let Err(error) = proxies::check_engine_unavailable_batch(&ctx.pool, &ids, now).await {
        tracing::warn!(%error, "failed to stamp the T2 engine outage");
    }
    tracing::warn!(proxies = batch.len(), "T2 batch failed by engine outage");
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
    // The first failure of the run, if any purge errored: the stamp below
    // carries it, so a failed rotation is visible instead of silent.
    let mut failure: Option<String> = None;

    // The daemon's own table first: `probe_results` is the daemon's
    // alone, the server never writes it.
    let mut deleted_probe = 0u64;
    match probe_repo::purge_before(
        &ctx.pool,
        retention::cutoff(now, u64::from(ctx.config.retention.probe_results_days)),
    )
    .await
    {
        Ok(0) => {}
        Ok(deleted) => {
            deleted_probe = deleted;
            tracing::info!(deleted, "rotated probe_results");
        }
        Err(error) => {
            tracing::warn!(%error, "probe_results rotation failed");
            failure = Some(format!("probe_results: {error}"));
        }
    }

    // The journals both binaries write, with the windows and the clamp
    // of the shared sweep: a server-only deployment runs the same one.
    let windows = retention::RetentionWindows {
        fetch_log_days: ctx.config.retention.fetch_log_days,
        queue_stale_days: ctx.config.probe.queue_stale_days,
    };
    let outcome = retention::sweep_shared_journals(&ctx.pool, &windows, now).await;
    if let Some(error) = &outcome.error {
        failure.get_or_insert_with(|| error.clone());
    }

    // Stamp the run so /admin/probe can surface it: the info lines above
    // are not a surface an operator looks at, and a probe daemon that
    // stopped rotating would otherwise grow both journals with nothing
    // saying so. A failed run keeps the `ts` of the last *successful*
    // one: the age of the stamp is the "retention last succeeded" signal,
    // and the `ok`/`error` pair says why it is stale.
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

/// The `ts` of the last rotation stamp, for a failed run to keep: the age
/// of the stamp is the "last successful rotation" signal and must not
/// advance over a failure. A missing (or unparseable) stamp reads as 0,
/// the honest "never succeeded".
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
