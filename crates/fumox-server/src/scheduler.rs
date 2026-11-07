//! Background source refresh loop.
//!
//! Every sweep (30 s) the scheduler picks enabled sources whose
//! `cache_ttl_seconds` has elapsed since `last_fetched_at` and ingests them
//! concurrently, bounded by a semaphore (`[fetch].max_concurrency`). A
//! source whose last attempt failed is additionally held back by a growing
//! backoff, so a permanently dead URL is not asked again on every tick (see
//! [`is_due`]).
//! The admin panel can request an immediate refresh through the mpsc
//! channel; a per-source in-flight guard prevents duplicate fetches
//! and always bypasses the backoff.
//!
//! Every ingestion runs under an overall budget ([`ingest_budget`]): the
//! wait for a concurrency permit, the fetch and the reconcile share it,
//! so a source that hangs cannot pin a permit and an in-flight mark for
//! the life of the process.
//!
//! The loop also owns the server's journal retention: `fetch_log` and
//! `probe_requests` are swept on the `[probe].retention_interval_secs`
//! cadence with the same windows the probe daemon's retention loop derives
//! from the config, so a server-only deployment (no daemon) stays
//! retention-bounded too (see [`retention_sweep`]).

use crate::cache::Caches;
use crate::events::{EventBus, FETCH_DONE, FETCH_FAILED, FETCH_QUEUED, FETCH_STARTED};
use crate::fetcher::Fetcher;
use crate::ingest;
use fumox_core::db::DbPool;
use fumox_core::geo::GeoResolver;
use fumox_core::models::{Source, now_ts};
use fumox_core::repo::{fetch_log, probe, sources};
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use tokio::sync::{Mutex, Semaphore};
use tokio::task::JoinSet;

/// How often the scheduler looks for sources due for a refresh.
const SWEEP_INTERVAL: Duration = Duration::from_secs(30);

/// How often the periodic geo backfill runs, and one pass's budget.
///
/// The startup pass gets one shot per boot; this is the retry for a host
/// whose DNS came back or a half-filled stamp. It runs detached and never
/// overlaps itself: two concurrent walks of the same rows would only
/// duplicate the resolver's work.
const GEO_BACKFILL_INTERVAL: Duration = Duration::from_secs(6 * 3600);
const GEO_BACKFILL_BUDGET: Duration = Duration::from_secs(300);

/// Delay before a source whose last fetch failed is retried, doubled per
/// consecutive failure and capped at [`FAILURE_BACKOFF_MAX_SECS`]. A dead URL
/// (401/403/404, dead DNS, a feed that no longer parses) does not become
/// healthy because it was asked again 30 s later, and the fetcher has no
/// internal backoff of its own for the non-recoverable classes.
const FAILURE_BACKOFF_BASE_SECS: i64 = 60;

/// Ceiling of the failure backoff: 3600 s = 120× the 30 s sweep — long
/// enough to stop hammering a dead URL, short enough that a quietly
/// recovered source is re-asked within the hour.
const FAILURE_BACKOFF_MAX_SECS: i64 = 3_600;

/// How many journal rows one source's failure history is read from: enough
/// to reach the backoff ceiling, the journal is retention-bounded anyway.
const FAILURE_HISTORY_ROWS: i64 = 8;

/// Minimum spacing between two *forced* refreshes of one source. The
/// in-flight guard only deduplicates concurrent fetches, so back-to-back
/// *Refresh now* clicks (a double-click, a fragment that re-posts) would
/// otherwise fetch the same URL twice in a row; the earlier of two close
/// requests stands.
const FORCED_REFRESH_MIN_INTERVAL_SECS: i64 = 5;

/// Capacity of the *Refresh now* channel. The loop dispatches a queued id
/// with one database lookup and a spawn, so a handful of slots is ample;
/// bounded means a flood of clicks or a wedged loop cannot grow the queue
/// without limit — a send that does not fit is dropped by the caller
/// (`try_send`), not parked behind the flood.
pub(crate) const REFRESH_CHANNEL_CAP: usize = 64;

/// What the fetch journal says about the most recent attempts of one source.
#[derive(Debug, Clone, Copy)]
struct FailureHistory {
    /// `fetched_at` of the newest journal row, successful or not.
    last_attempt_at: i64,
    /// Attempts that failed in a row, counted from the newest row backwards.
    consecutive_failures: u32,
}

/// The journal's verdict about one source's recent attempts.
#[derive(Debug, Clone, Copy)]
enum History {
    /// The journal holds rows for the source.
    Known(FailureHistory),
    /// The journal holds nothing for it: never fetched, or every row was
    /// purged by the retention sweep.
    Empty,
    /// The journal could not be read. The source is held back: a source
    /// whose history cannot be judged must not be fetched on every
    /// sweep, and a broken database must not turn into a storm of
    /// upstream requests.
    Unreadable,
}

/// Delay before retrying a source that has just failed `consecutive_failures`
/// times in a row.
fn failure_backoff_secs(consecutive_failures: u32) -> i64 {
    let exponent = consecutive_failures.min(16) as i64;
    FAILURE_BACKOFF_BASE_SECS
        .saturating_mul(1i64 << exponent)
        .min(FAILURE_BACKOFF_MAX_SECS)
}

/// Whether the source's ordinary TTL cadence has elapsed since its last
/// successful fetch. The freshness question itself is
/// [`ingest::source_is_fresh`], the same predicate the ingest's fetch
/// short-circuit asks, so the two can never drift apart.
fn ttl_due(source: &Source, now: i64) -> bool {
    !ingest::source_is_fresh(now, source.last_fetched_at, source.cache_ttl_seconds)
}

/// Whether a source whose last attempts failed may be retried now: the
/// backoff has to have elapsed since the last attempt.
///
/// An admin edit lands in `updated_at` (a failed fetch leaves it alone),
/// so a source whose configuration was just corrected is retried without
/// waiting out a backoff earned by the old configuration.
fn backoff_elapsed(source: &Source, now: i64, history: &FailureHistory) -> bool {
    if history.consecutive_failures == 0 {
        return true;
    }
    if source.updated_at > history.last_attempt_at {
        return true;
    }
    now.saturating_sub(history.last_attempt_at)
        >= failure_backoff_secs(history.consecutive_failures)
}

/// Whether a source is due for a fetch at `now`: its ordinary TTL
/// cadence, and, when its last attempt failed, only once the backoff has
/// elapsed.
///
/// The TTL check alone is not enough. `last_fetched_at` is documented as the
/// last *successful* fetch and a failure leaves it NULL, so a source that
/// never worked (or whose feed broke) is due on every single sweep: one
/// upstream request per [`SWEEP_INTERVAL`] for the whole lifetime of the
/// deployment. A source that once succeeded is no better off: the old
/// stamp stays, and `now - ts >= ttl` keeps holding once it expires.
fn is_due(source: &Source, now: i64, history: &History) -> bool {
    if !ttl_due(source, now) {
        return false;
    }
    match history {
        // The journal could not be read: the source waits for a sweep
        // that can read it.
        History::Unreadable => false,
        History::Empty => true,
        History::Known(history) => backoff_elapsed(source, now, history),
    }
}

/// Read the recent attempts of one source.
///
/// An empty journal is not a failure: the source was never fetched, or
/// the retention sweep purged its rows, and the caller falls back to the
/// plain TTL cadence. A read that *fails* is a different thing: the
/// source is held back and the failure is logged, because a source that
/// cannot be judged is not a source that may be fetched.
async fn failure_history(pool: &DbPool, source_id: &str) -> History {
    let rows = match fetch_log::recent_for_source(pool, source_id, FAILURE_HISTORY_ROWS).await {
        Ok(rows) => rows,
        Err(error) => {
            tracing::warn!(
                source = %source_id,
                error = %error,
                "scheduler: cannot read the fetch history; the source is held back"
            );
            return History::Unreadable;
        }
    };
    let Some(newest) = rows.first() else {
        return History::Empty;
    };
    let consecutive_failures = rows.iter().take_while(|row| row.ok == 0).count() as u32;
    History::Known(FailureHistory {
        last_attempt_at: newest.fetched_at,
        consecutive_failures,
    })
}

/// The unix time the source's next attempt is due at, computed exactly the
/// way the sweep's due check computes it: the newest journal attempt plus
/// the backoff its consecutive failures earned (capped at
/// [`FAILURE_BACKOFF_MAX_SECS`]). `None` when the last attempt succeeded —
/// the plain TTL cadence applies and there is no retry to wait out — or
/// the journal cannot be judged.
///
/// The admin source page shows this next to the last error: an operator
/// staring at a dead feed must be able to tell "the scheduler gave up"
/// from "the retry is scheduled".
pub(crate) async fn next_retry_at(pool: &DbPool, source_id: &str) -> Option<i64> {
    match failure_history(pool, source_id).await {
        History::Known(history) if history.consecutive_failures > 0 => Some(
            history
                .last_attempt_at
                .saturating_add(failure_backoff_secs(history.consecutive_failures)),
        ),
        _ => None,
    }
}

/// The sources that are due for a fetch, in the order the sweep found
/// them.
///
/// The journal is consulted only for a source that passes the TTL check
/// *and* whose recorded verdict says the last attempt failed: a source
/// that is not due yet costs no query, and neither does a healthy one.
async fn due_sources<F, Fut>(sources: Vec<Source>, now: i64, mut history_of: F) -> Vec<Source>
where
    F: FnMut(String) -> Fut,
    Fut: std::future::Future<Output = History>,
{
    let mut due = Vec::new();
    for source in sources {
        if !ttl_due(&source, now) {
            continue;
        }
        let history = if source.error_class.is_some() {
            history_of(source.id.clone()).await
        } else {
            History::Empty
        };
        if is_due(&source, now, &history) {
            due.push(source);
        } else if let History::Known(history) = &history {
            tracing::debug!(
                source = %source.id,
                consecutive_failures = history.consecutive_failures,
                "scheduler sweep: backing off a failing source"
            );
        }
    }
    due
}

/// Shared scheduler state: the concurrency semaphore, the map of
/// currently fetching source ids to the moment their refresh started, and
/// the map of source ids to the moment their last *forced* refresh was
/// accepted.
#[derive(Clone)]
pub struct SchedulerState {
    semaphore: Arc<Semaphore>,
    in_flight: Arc<Mutex<HashMap<String, i64>>>,
    forced_at: Arc<Mutex<HashMap<String, i64>>>,
}

impl SchedulerState {
    pub fn new(max_concurrency: usize) -> Self {
        Self {
            semaphore: Arc::new(Semaphore::new(max_concurrency.max(1))),
            in_flight: Arc::new(Mutex::new(HashMap::new())),
            forced_at: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Whether a *forced* refresh of the source may start now: a request
    /// spaced less than [`FORCED_REFRESH_MIN_INTERVAL_SECS`] after the
    /// previously accepted one is refused, the earlier of the two stands.
    /// An accepted request stamps `now` as that source's last forced
    /// refresh.
    async fn allow_forced_refresh(&self, source_id: &str, now: i64) -> bool {
        let mut forced = self.forced_at.lock().await;
        match forced.get(source_id) {
            Some(&last) if now.saturating_sub(last) < FORCED_REFRESH_MIN_INTERVAL_SECS => false,
            _ => {
                forced.insert(source_id.to_string(), now);
                true
            }
        }
    }

    /// Try to mark a source as in-flight, returning a guard that clears the
    /// mark on drop; `None` when the source already is in flight.
    ///
    /// Releasing through `Drop` rather than an explicit call matters: tokio
    /// mutexes do not poison, so a panic anywhere in `ingest_source` used to
    /// unwind past the release and pin the id in `in_flight` forever, that
    /// source could never be refreshed again until a restart, and the
    /// `JoinSet` sweep swallows the `JoinError` silently.
    async fn acquire_source(&self, source_id: &str) -> Option<InFlightGuard> {
        let inserted = {
            let mut guard = self.in_flight.lock().await;
            // `insert` hands back the previous value: `None` means the
            // source was not in flight and now is.
            guard.insert(source_id.to_string(), now_ts()).is_none()
        };
        inserted.then(|| InFlightGuard {
            in_flight: self.in_flight.clone(),
            source_id: source_id.to_string(),
        })
    }

    /// Whether a refresh of the source is pending or running (admin status
    /// fragment). The mark spans the whole spawn-to-outcome window,
    /// including the wait for a `[fetch].max_concurrency` permit: the
    /// status fragment stops polling once this turns `false`, so a queued
    /// *Refresh now* must not look finished while its task still sits on
    /// the semaphore. The SSE stream carries the narrower signal:
    /// `fetch.queued` only while the task actually waits for a permit,
    /// `fetch.started` once a request can actually go out.
    pub async fn is_in_flight(&self, source_id: &str) -> bool {
        self.in_flight.lock().await.contains_key(source_id)
    }

    /// When the in-flight refresh of the source started, as a unix
    /// timestamp; `None` when no refresh is running.
    ///
    /// The admin status fragment shows the elapsed time, so a refresh that
    /// takes minutes looks like what it is instead of a spinner that never
    /// resolves.
    pub async fn in_flight_since(&self, source_id: &str) -> Option<i64> {
        self.in_flight.lock().await.get(source_id).copied()
    }

    /// Source ids currently marked in flight. The shutdown path names
    /// them in the log: their tasks are detached, so whatever is still
    /// here when `main` returns is dropped by runtime teardown, and a
    /// bare "shutdown complete" would hide that.
    pub async fn in_flight_ids(&self) -> Vec<String> {
        self.in_flight.lock().await.keys().cloned().collect()
    }
}

/// Clears the in-flight mark of one source when dropped, including while a
/// panic unwinds the ingest task.
struct InFlightGuard {
    in_flight: Arc<Mutex<HashMap<String, i64>>>,
    source_id: String,
}

impl Drop for InFlightGuard {
    fn drop(&mut self) {
        // `Drop` cannot await; the lock is only ever held for a set
        // insert/remove, so blocking on it here cannot deadlock.
        let source_id = std::mem::take(&mut self.source_id);
        if let Ok(mut guard) = self.in_flight.try_lock() {
            guard.remove(&source_id);
            return;
        }
        // Contended: hand the removal to the runtime rather than block.
        let in_flight = self.in_flight.clone();
        tokio::spawn(async move {
            in_flight.lock().await.remove(&source_id);
        });
    }
}

/// Shared resources every ingestion task needs; cheap to clone per task.
#[derive(Clone)]
pub struct IngestEnv {
    pub pool: DbPool,
    pub fetcher: Fetcher,
    pub caches: Caches,
    pub geo: Arc<GeoResolver>,
    /// Fixed ingest settings (`[ingest].refresh_check_limit`,
    /// `[ingest].drop_gate`).
    pub settings: crate::ingest::IngestSettings,
    /// The overall ceiling for one ingestion (see [`ingest_budget`]).
    pub budget: Duration,
}

/// The overall ceiling for one ingestion: the wait for a concurrency
/// permit, the fetch, the parse and the reconcile share it.
///
/// The fetch's own worst case is one attempt (connect plus read) times
/// the number of attempts, capped by the fetcher's own budget; the
/// headroom covers the wait for a permit and the database work. An
/// ingestion that exceeds the ceiling is abandoned: the permit and the
/// in-flight mark are released and the attempt is reported as failed,
/// so a source that hangs cannot pin a permit for the life of the
/// process.
pub(crate) fn ingest_budget(config: &fumox_core::config::FetchConfig) -> Duration {
    let attempts = u64::from(config.max_retries) + 1;
    let fetch = (config.connect_timeout_secs + config.read_timeout_secs).saturating_mul(attempts);
    let fetch = fetch.min(crate::fetcher::MAX_FETCH_BUDGET.as_secs());
    Duration::from_secs(fetch).saturating_add(INGEST_BUDGET_HEADROOM)
}

/// The headroom of [`ingest_budget`] on top of the fetch's worst case.
const INGEST_BUDGET_HEADROOM: Duration = Duration::from_secs(120);

/// Resets an overlap flag when the detached task holding it ends, on the
/// normal path and on unwind alike. A panic inside `sweep` would
/// otherwise strand `sweeping == true` and silently stop all future
/// sweeps (same for the geo backfill's own flag).
struct SweepGuard(Arc<AtomicBool>);

impl Drop for SweepGuard {
    fn drop(&mut self) {
        self.0.store(false, Ordering::SeqCst);
    }
}

/// The overlap slot of a background pass: a tick that arrives while the
/// previous pass still holds the slot is skipped, and the ticks skipped
/// in a row are counted.
///
/// The count is what tells the operator that the scheduler runs behind
/// its cadence: a skipped tick is a source that waited longer than the
/// interval.
struct SweepSlot {
    running: Arc<AtomicBool>,
    skipped: u32,
}

impl SweepSlot {
    fn new() -> Self {
        Self {
            running: Arc::new(AtomicBool::new(false)),
            skipped: 0,
        }
    }

    /// Take the slot for a pass. `false` when the previous pass still
    /// holds it; the skipped ticks are counted and the count starts over
    /// with the next pass that gets the slot.
    fn take(&mut self) -> bool {
        if self.running.swap(true, Ordering::SeqCst) {
            self.skipped += 1;
            return false;
        }
        self.skipped = 0;
        true
    }

    /// How many ticks were skipped in a row.
    fn skipped(&self) -> u32 {
        self.skipped
    }

    /// The flag the pass's guard releases when it ends.
    fn flag(&self) -> Arc<AtomicBool> {
        self.running.clone()
    }
}

/// Retention windows the scheduler enforces itself, read once at startup.
///
/// The probe daemon runs the full retention loop, but the two binaries are
/// independent and a server-only deployment (a state the architecture
/// explicitly allows, the panel warning about a missing daemon rather than
/// refusing to work) writes a `fetch_log` row per fetch attempt and
/// enqueues `probe_requests` per refresh with nothing draining them. The
/// scheduler therefore sweeps exactly the two tables the server itself
/// writes with the same cutoffs the daemon's loop derives from the config
/// (`[retention].fetch_log_days`, `[probe].queue_stale_days`), so a
/// deployment without the daemon stays retention-bounded and a deployment
/// with one merely repeats idempotent deletes. `probe_results` stays the
/// daemon's alone: the server never writes it.
#[derive(Debug, Clone, Copy)]
pub(crate) struct ServerRetention {
    /// `[retention].fetch_log_days`.
    fetch_log_days: u32,
    /// `[probe].queue_stale_days`.
    queue_stale_days: u64,
    /// `[retention].removed_proxies_days`: the TTL purge of the `removed`
    /// proxies, the one pass the daemon must never run (its authorizer
    /// denies proxy deletion). `0` disables the purge.
    removed_proxies_days: u32,
    /// `[probe].retention_interval_secs`: how often the sweep runs.
    interval_secs: u64,
}

impl ServerRetention {
    /// The windows the process booted with. The config is loaded once by
    /// the entry point, which is also the only place that knows the
    /// `--config` flag; the scheduler reads the windows from there
    /// instead of parsing the process arguments a second time.
    pub(crate) fn from_config(config: &fumox_core::config::AppConfig) -> Self {
        Self {
            fetch_log_days: config.retention.fetch_log_days,
            queue_stale_days: config.probe.queue_stale_days,
            removed_proxies_days: config.retention.removed_proxies_days,
            interval_secs: config.probe.retention_interval_secs,
        }
    }
}

/// One server-side retention pass: `fetch_log` and `probe_requests` older
/// than the configured windows, plus queue rows whose proxy already left
/// the `unknown` state. The server-side mirror of the probe daemon's
/// retention loop for the two tables the server itself writes; the sweep
/// itself lives in `fumox_core::repo::retention`, so both deployments
/// share the windows, the clamp and the order of the purges.
async fn retention_sweep(pool: &DbPool, retention: &ServerRetention) {
    let now = fumox_core::models::now_ts();
    let windows = fumox_core::repo::retention::RetentionWindows {
        fetch_log_days: retention.fetch_log_days,
        queue_stale_days: retention.queue_stale_days,
    };
    let outcome = fumox_core::repo::retention::sweep_shared_journals(pool, &windows, now).await;

    // The TTL purge of the `removed` proxies is the server's alone (see
    // `retention::purge_stale_removed_proxies`): the delete is content
    // deletion the daemon's authorizer denies. A zero window leaves the
    // tier untouched.
    let mut error = outcome.error;
    let mut proxies_deleted = 0u64;
    match fumox_core::repo::retention::purge_stale_removed_proxies(
        pool,
        u64::from(retention.removed_proxies_days),
        now,
    )
    .await
    {
        Ok(0) => {}
        Ok(deleted) => {
            proxies_deleted = deleted;
            tracing::info!(deleted, "rotated removed proxies");
        }
        Err(err) => {
            tracing::warn!(error = %err, "removed-proxies rotation failed");
            error.get_or_insert(format!("proxies: {err}"));
        }
    }

    // Stamp the run under the server's own key, so /admin/probe surfaces
    // it even without the daemon. `last_rotation` stays the daemon's: the
    // server never touches `probe_results`, and overwriting the daemon's
    // stamp with a zeroed `probe_results` counter read as "the daemon
    // rotated" in a deployment that has none. A failed pass keeps the
    // stamp of the last successful one (`ok: false` with the error text,
    // see `ServerRetentionStamp`); the purge failures are collected
    // across both passes, so a full wipe-out cannot advance the "last
    // good" ts.
    let stamp = probe::meta::ServerRetentionStamp {
        ts: if error.is_none() {
            now
        } else {
            previous_retention_ts(pool).await
        },
        fetch_log: outcome.fetch_log,
        probe_requests: outcome.probe_requests,
        proxies: proxies_deleted,
        ok: error.is_none(),
        error,
    };
    if let Err(error) = fumox_core::repo::meta_set(
        pool,
        probe::meta::SERVER_RETENTION_KEY,
        &serde_json::to_string(&stamp).expect("meta payload holds only JSON-native fields"),
    )
    .await
    {
        tracing::debug!(error = %error, "server retention: cannot stamp server_retention");
    }
}

/// The `ts` of the last server retention stamp, for a failed pass to
/// keep: the age of the stamp is the "last successful sweep" signal and
/// must not advance over a failure. A missing (or unparseable) stamp
/// reads as 0, the honest "never succeeded".
async fn previous_retention_ts(pool: &DbPool) -> i64 {
    match fumox_core::repo::meta_get(pool, probe::meta::SERVER_RETENTION_KEY).await {
        Ok(Some(raw)) => serde_json::from_str::<probe::meta::ServerRetentionStamp>(&raw)
            .map(|stamp| stamp.ts)
            .unwrap_or(0),
        _ => 0,
    }
}

/// Run the scheduler until the process shuts down.
///
/// `refresh_rx` carries source ids that must be refreshed immediately
/// (admin *Refresh now*). The channel is bounded and the sender uses
/// `try_send`, so a request that does not fit is dropped by the caller
/// instead of piling up here.
pub async fn run(
    env: IngestEnv,
    state: SchedulerState,
    events: EventBus,
    mut refresh_rx: tokio::sync::mpsc::Receiver<String>,
    retention: ServerRetention,
) {
    // Server-side journal retention on its own cadence (see
    // [`retention_sweep`]). The first tick of a tokio interval is
    // immediate, matching the daemon's run-at-startup, so a server-only
    // deployment sheds an accumulated backlog at boot; the sweep runs
    // detached, like the fetch sweep, so its bounded deletes do not hold
    // the refresh channel.
    tracing::debug!(
        fetch_log_days = retention.fetch_log_days,
        queue_stale_days = retention.queue_stale_days,
        interval_secs = retention.interval_secs,
        "scheduler retention windows"
    );
    let mut retention_tick =
        tokio::time::interval(Duration::from_secs(retention.interval_secs.max(60)));
    retention_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    let mut tick = tokio::time::interval(SWEEP_INTERVAL);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    // The first tick is immediate, repeating the startup pass `main` already
    // spawned; consume it so the retry starts one full interval later.
    let mut geo_backfill_tick = tokio::time::interval(GEO_BACKFILL_INTERVAL);
    geo_backfill_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    geo_backfill_tick.tick().await;
    let mut geo_backfilling = SweepSlot::new();
    let mut retention_sweeping = SweepSlot::new();
    // A sweep drains its whole JoinSet, so a slow source would otherwise
    // hold the loop for the length of that fetch and park a *Refresh now*
    // behind it: the refresh would not even be marked in flight, and the
    // status fragment the panel polls would report the previous fetch as
    // the finished one. The sweep therefore runs detached, and the slot
    // keeps two sweeps from overlapping.
    let mut sweeping = SweepSlot::new();
    loop {
        tokio::select! {
            _ = tick.tick() => {
                if !sweeping.take() {
                    tracing::warn!(
                        skipped_ticks = sweeping.skipped(),
                        "scheduler sweep still running; the tick is skipped"
                    );
                    continue;
                }
                let env = env.clone();
                let state = state.clone();
                let events = events.clone();
                let sweeping_done = SweepGuard(sweeping.flag());
                let handle = tokio::spawn(async move {
                    let _guard = sweeping_done;
                    sweep(&env, &state, &events).await;
                });
                watch_task(handle, "scheduler sweep");
            }
            _ = retention_tick.tick() => {
                if !retention_sweeping.take() {
                    tracing::debug!(
                        skipped_ticks = retention_sweeping.skipped(),
                        "scheduler retention sweep still running; skipping this tick"
                    );
                    continue;
                }
                let pool = env.pool.clone();
                let guard = SweepGuard(retention_sweeping.flag());
                let handle = tokio::spawn(async move {
                    let _guard = guard;
                    retention_sweep(&pool, &retention).await;
                });
                watch_task(handle, "scheduler retention sweep");
            }
            _ = geo_backfill_tick.tick() => {
                if !geo_backfilling.take() {
                    tracing::debug!(
                        skipped_ticks = geo_backfilling.skipped(),
                        "geo backfill: previous pass still running, skipping this tick"
                    );
                    continue;
                }
                let pool = env.pool.clone();
                let geo = Arc::clone(&env.geo);
                let guard = SweepGuard(geo_backfilling.flag());
                let handle = tokio::spawn(async move {
                    let _guard = guard;
                    crate::geo_backfill::backfill_missing_geo_within_budget(
                        pool,
                        geo,
                        GEO_BACKFILL_BUDGET,
                    )
                    .await;
                });
                watch_task(handle, "geo backfill");
            }
            maybe_id = refresh_rx.recv() => {
                let Some(source_id) = maybe_id else {
                    break; // channel closed, shutting down
                };
                dispatch_refresh(&env, &state, &events, &source_id).await;
            }
        }
    }
}

/// Watch a detached task and report its panic. The handle is awaited by a
/// watcher task: a panic inside the work would otherwise disappear into
/// the runtime, and a background job that dies silently is a job that
/// never runs again.
fn watch_task(handle: tokio::task::JoinHandle<()>, what: &'static str) {
    tokio::spawn(async move {
        if let Err(error) = handle.await {
            tracing::warn!(error = %error, task = what, "background task panicked");
        }
    });
}

/// Handle one *Refresh now* id from the admin panel: look the row up and spawn
/// the ingest. A stale panel id is a warning, a failed lookup an error naming
/// the source: a broken database must not masquerade as "unknown source".
async fn dispatch_refresh(
    env: &IngestEnv,
    state: &SchedulerState,
    events: &EventBus,
    source_id: &str,
) {
    match sources::get(&env.pool, source_id).await {
        // Explicit "refresh now": always hit the network — unless a
        // forced refresh of the same source was accepted moments ago.
        // The in-flight guard only deduplicates concurrent fetches, so
        // the spacing here is what keeps back-to-back requests from
        // fetching the same URL twice in a row.
        Ok(Some(source)) => {
            if !state
                .allow_forced_refresh(&source.id, fumox_core::models::now_ts())
                .await
            {
                tracing::debug!(
                    source = %source.id,
                    "forced refresh throttled: the previous one is too recent"
                );
                return;
            }
            spawn_refresh(env, state, events, source);
        }
        Ok(None) => {
            tracing::warn!(source = %source_id, "refresh requested for unknown source");
        }
        Err(err) => {
            tracing::error!(
                source = %source_id,
                error = %err,
                "refresh requested: cannot look up the source"
            );
        }
    }
}

/// Run one *Refresh now* ingest in the background and report a panic.
///
/// The panel waits for the outcome event, so a task that dies without one
/// leaves the refresh spinning in the browser forever: the panic is
/// reported as a failed fetch.
fn spawn_refresh(env: &IngestEnv, state: &SchedulerState, events: &EventBus, source: Source) {
    let source_id = source.id.clone();
    let handle = spawn_ingest(env, state, events, source, true);
    let events = events.clone();
    tokio::spawn(async move {
        if let Err(error) = handle.await {
            tracing::warn!(
                source = %source_id,
                error = %error,
                "refresh now: ingest task panicked"
            );
            events.publish(
                FETCH_FAILED,
                serde_json::json!({
                    "source_id": source_id,
                    "ok": false,
                    "error_class": "panic",
                }),
            );
        }
    });
}

/// One scheduler sweep: ingest every enabled source that is due.
async fn sweep(env: &IngestEnv, state: &SchedulerState, events: &EventBus) {
    // Stamped at the start, not the end: the age of this stamp is "time
    // since the loop last got a sweep underway", so a sweep hung inside
    // its own body ages the stamp instead of looking healthy.
    let started_at = fumox_core::models::now_ts();
    if let Err(err) = fumox_core::repo::meta_set(
        &env.pool,
        fumox_core::repo::probe::meta::SERVER_CYCLE_KEY,
        &started_at.to_string(),
    )
    .await
    {
        tracing::warn!(error = %err, "scheduler sweep: cannot stamp server_cycle");
    }

    let due = match sources::list(&env.pool, true).await {
        Ok(all) => {
            let now = fumox_core::models::now_ts();
            let pool = env.pool.clone();
            due_sources(all, now, move |id| {
                let pool = pool.clone();
                async move { failure_history(&pool, &id).await }
            })
            .await
        }
        Err(err) => {
            tracing::error!(error = %err, "scheduler sweep: cannot list sources");
            return;
        }
    };
    if due.is_empty() {
        return;
    }
    tracing::debug!(count = due.len(), "scheduler sweep: sources due");

    let mut tasks = JoinSet::new();
    for source in due {
        let source_id = source.id.clone();
        let handle = spawn_ingest(env, state, events, source, false);
        // The id travels with the handle so a JoinError (a panic in
        // the ingest task) names the source that died instead of
        // vanishing into `is_some()`.
        tasks.spawn(async move { (source_id, handle.await) });
    }
    while let Some(joined) = tasks.join_next().await {
        match joined {
            Ok((_source_id, Ok(()))) => {}
            Ok((source_id, Err(err))) => {
                tracing::warn!(error = %err, source = %source_id, "scheduler sweep: ingest task panicked");
            }
            Err(err) => {
                tracing::warn!(error = %err, "scheduler sweep: sweep task itself failed");
            }
        }
    }
}

/// Spawn one ingestion task and return its join handle; the handle always
/// resolves, even when the attempt turns out to be a duplicate.
///
/// The in-flight mark is taken inside the spawned task: a duplicate spawn
/// for a source that is already being fetched exits there without
/// fetching and without publishing any event, and the caller learns of it
/// only through the handle finishing. Callers that must not lose a
/// request to the mark check [`SchedulerState::is_in_flight`] first.
///
/// Event order: `fetch.queued` only when the task actually has to wait
/// for a concurrency permit, `fetch.started` once a permit is in hand and
/// the fetch can actually go out, then the outcome event. Under
/// `[fetch].max_concurrency` saturation the queued window can span many
/// sweeps, and the panel's "fetching" notion must not start before any
/// request is made.
fn spawn_ingest(
    env: &IngestEnv,
    state: &SchedulerState,
    events: &EventBus,
    source: Source,
    force: bool,
) -> tokio::task::JoinHandle<()> {
    let env = env.clone();
    let state = state.clone();
    let events = events.clone();
    let source_id = source.id.clone();

    // The in-flight guard is acquired atomically (mutex + set insert) inside
    // the spawned task; a duplicate spawn for the same source returns early.
    let fut = async move {
        let IngestEnv {
            pool,
            fetcher,
            caches,
            geo,
            settings,
            budget,
        } = env;
        let Some(in_flight) = state.acquire_source(&source_id).await else {
            tracing::debug!(source = %source_id, "source already fetching; skipping");
            return;
        };
        let started = std::time::Instant::now();
        // The permit wait and the fetch share one ceiling: a source that
        // hangs, or a permit that never comes, must not pin the mark and
        // the slot for the life of the process.
        let attempt = tokio::time::timeout(budget, async {
            // A free permit means the fetch is not queued at all: it starts
            // right away and only `fetch.started` is published. Only a task
            // that really has to wait announces itself as `fetch.queued`,
            // so a sweep that starts a batch of sources at once cannot
            // flood the event stream with queue announcements nothing
            // waits on. Under `[fetch].max_concurrency` saturation the
            // queued window can span many sweeps, and the panel's notion
            // of "fetching" must not include that wait: `fetch.started`
            // fires only once a permit is in hand.
            let permit = match state.semaphore.clone().try_acquire_owned() {
                Ok(permit) => permit,
                Err(_) => {
                    events.publish(FETCH_QUEUED, serde_json::json!({ "source_id": source_id }));
                    match state.semaphore.clone().acquire_owned().await {
                        Ok(permit) => permit,
                        Err(_) => return None, // semaphore closed during shutdown
                    }
                }
            };
            // The row may have changed while this task waited for the
            // permit: an admin edit (a new URL, new headers) must be
            // honored, not fetched from the snapshot the sweep captured. A
            // source deleted in the meantime is not fetched at all — the
            // fetch would only write rows for a source that no longer
            // exists.
            let source = match sources::get(&pool, &source_id).await {
                Ok(Some(fresh)) => {
                    if fresh.updated_at != source.updated_at {
                        tracing::debug!(
                            source = %source_id,
                            "refresh: the source row changed while queued; fetching the fresh one"
                        );
                    }
                    fresh
                }
                Ok(None) => {
                    tracing::debug!(
                        source = %source_id,
                        "refresh: the source row is gone; skipping the fetch"
                    );
                    return None;
                }
                Err(err) => {
                    tracing::warn!(
                        source = %source_id,
                        error = %err,
                        "refresh: cannot re-read the source row; fetching the snapshot"
                    );
                    source
                }
            };
            events.publish(FETCH_STARTED, serde_json::json!({ "source_id": source_id }));
            let outcome =
                ingest::ingest_source(&pool, &fetcher, &geo, settings, &source, force).await;
            drop(permit);
            Some(outcome)
        })
        .await;
        match attempt {
            Ok(Some(outcome)) => {
                drop(in_flight);
                match outcome {
                    ingest::IngestOutcome::Ok {
                        proxies_found,
                        dropped,
                        stats,
                        duration_ms,
                    } => {
                        // New/changed/removed rows → every rendered output containing
                        // this source is stale. Drop them now so clients see the fresh
                        // data immediately instead of waiting out the processed TTL.
                        // When nothing changed the renderings stay valid.
                        if stats.inserted + stats.updated + stats.removed > 0 {
                            caches.invalidate_processed_for_source(&source_id).await;
                        }
                        events.publish(
                            FETCH_DONE,
                            serde_json::json!({
                                "source_id": source_id,
                                "ok": true,
                                "proxies_found": proxies_found,
                                "dropped": dropped,
                                "duration_ms": duration_ms,
                            }),
                        );
                        tracing::info!(
                            source = %source_id,
                            proxies_found,
                            dropped,
                            inserted = stats.inserted,
                            updated = stats.updated,
                            removed = stats.removed,
                            duration_ms,
                            "source ingested"
                        );
                    }
                    failed @ (ingest::IngestOutcome::FetchFailed { .. }
                    | ingest::IngestOutcome::ParseFailed { .. }
                    | ingest::IngestOutcome::StorageFailed { .. }) => {
                        // Every failure branch funnels into one publication:
                        // the `fetch.failed` payload holds the same field
                        // set whichever branch produced it, the branches
                        // differ only in the values.
                        let FailureReport {
                            error_class,
                            message,
                            http_status,
                            level,
                            duration_ms,
                        } = failure_report(&failed)
                            .expect("a failed outcome always carries its report");
                        // One log site for every failure branch: a storage
                        // fault is this process's own (an error), the
                        // upstream faults are warnings.
                        if level == tracing::Level::ERROR {
                            tracing::error!(
                                source = %source_id,
                                error_class = %error_class,
                                error = %message,
                                duration_ms,
                                "source ingest failed"
                            );
                        } else {
                            tracing::warn!(
                                source = %source_id,
                                error_class = %error_class,
                                error = %message,
                                duration_ms,
                                "source ingest failed"
                            );
                        }
                        events.publish(
                            FETCH_FAILED,
                            serde_json::json!({
                                "source_id": source_id,
                                "ok": false,
                                "error_class": error_class,
                                "message": message,
                                "http_status": http_status,
                                "duration_ms": duration_ms,
                            }),
                        );
                    }
                }
            }
            Ok(None) => {
                // The semaphore is closed (the process is shutting down), or
                // the source row vanished while the fetch was queued: a
                // quiet exit, nothing to report the panel.
                drop(in_flight);
            }
            Err(_) => {
                // The ceiling is gone. The permit (if it was taken) and the
                // in-flight mark are released when the abandoned future is
                // dropped.
                drop(in_flight);
                let duration_ms = started.elapsed().as_millis() as i64;
                tracing::warn!(
                    source = %source_id,
                    budget_secs = budget.as_secs(),
                    duration_ms,
                    "source ingest exceeded its budget; the attempt was abandoned"
                );
                events.publish(
                    FETCH_FAILED,
                    serde_json::json!({
                        "source_id": source_id,
                        "ok": false,
                        "error_class": "timeout",
                        "duration_ms": duration_ms,
                    }),
                );
            }
        }
    };
    tokio::spawn(fut)
}

/// The report of a failed outcome: the `error_class` the event carries,
/// the human-readable message, the HTTP status when the server answered
/// one, the log level and the measured duration. Every failure branch
/// (`FetchFailed`, `ParseFailed`, `StorageFailed`) funnels into one
/// `fetch.failed` publication through [`failure_report`]: the payload
/// holds the same field set whichever branch produced it, the branches
/// differ only in these values.
struct FailureReport {
    error_class: &'static str,
    message: String,
    http_status: Option<u16>,
    level: tracing::Level,
    duration_ms: i64,
}

/// The [`FailureReport`] of a failed outcome; `None` when it succeeded.
fn failure_report(outcome: &ingest::IngestOutcome) -> Option<FailureReport> {
    let (error_class, message, http_status, level, duration_ms) = match outcome {
        ingest::IngestOutcome::FetchFailed {
            failure,
            duration_ms,
        } => (
            failure.error_class().as_str(),
            failure.to_string(),
            failure.http_status(),
            tracing::Level::WARN,
            *duration_ms,
        ),
        ingest::IngestOutcome::ParseFailed {
            message,
            duration_ms,
        } => (
            "parse_error",
            message.clone(),
            None,
            tracing::Level::WARN,
            *duration_ms,
        ),
        ingest::IngestOutcome::StorageFailed {
            message,
            duration_ms,
        } => (
            "storage",
            message.clone(),
            None,
            tracing::Level::ERROR,
            *duration_ms,
        ),
        ingest::IngestOutcome::Ok { .. } => return None,
    };
    Some(FailureReport {
        error_class,
        message,
        http_status,
        level,
        duration_ms,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::Event;
    use fumox_core::config::{DatabaseConfig, FetchConfig, GeoConfig};
    use fumox_core::geo::GeoResolver;
    use fumox_core::models::Source;
    use std::net::SocketAddr;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    /// Wait for the `fetch.started` event of one source, failing the test
    /// when it does not arrive inside the window.
    async fn await_fetch_started(
        rx: &mut tokio::sync::broadcast::Receiver<Event>,
        source_id: &str,
    ) {
        let wait = async {
            loop {
                let event = rx.recv().await.expect("event bus stays open");
                if event.name == "fetch.started" && event.data["source_id"] == source_id {
                    return;
                }
            }
        };
        tokio::time::timeout(Duration::from_secs(10), wait)
            .await
            .unwrap_or_else(|_| panic!("{source_id}: fetch.started did not arrive in time"));
    }

    fn test_source(id: &str, url: String, ttl: i64, last_fetched_at: Option<i64>) -> Source {
        Source {
            id: id.to_string(),
            slug: None,
            access_token: None,
            name: id.to_string(),
            url,
            enabled: true,
            encoding: Default::default(),
            input_format: None,
            protocols: None,
            cache_ttl_seconds: ttl,
            tags: None,
            pipeline: None,
            headers: None,
            ip_family: None,
            created_at: fumox_core::models::now_ts(),
            updated_at: fumox_core::models::now_ts(),
            last_fetched_at,
            last_error: None,
            error_class: None,
        }
    }

    /// A *Refresh now* asked for while a sweep is still running must start
    /// at once. The loop used to await the sweep inline and the sweep
    /// drains its whole `JoinSet`, so the refresh sat in the channel until
    /// every due source had finished: it was neither fetched nor marked
    /// in flight, and the status fragment the panel polls reported the
    /// previous fetch as the finished one.
    #[tokio::test]
    async fn refresh_now_is_not_parked_behind_a_running_sweep() {
        // A source host that accepts connections and never answers, so the
        // sweep stays busy for the whole test.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((mut socket, _)) = listener.accept().await {
                tokio::spawn(async move {
                    use tokio::io::AsyncReadExt;
                    let mut buf = [0u8; 1024];
                    let _ = socket.read(&mut buf).await;
                    // No response, and the socket stays open: the fetch is
                    // still waiting when the test is done with it.
                    std::future::pending::<()>().await;
                });
            }
        });

        let dir =
            std::env::temp_dir().join(format!("fumox-sched-test-{}", fumox_core::models::new_id()));
        std::fs::create_dir_all(&dir).unwrap();
        let pool = fumox_core::db::connect_pool(&DatabaseConfig {
            path: dir.join("test.db"),
            ..Default::default()
        })
        .await
        .unwrap();
        fumox_core::db::migrate(&pool).await.unwrap();

        // Due for the very first sweep (no fetch yet), so the sweep picks
        // it up and blocks on it.
        let slow = test_source("srcSlow0000", format!("http://{addr}/hang"), 0, None);
        // Not due (fetched just now): only an explicit refresh starts it.
        let fast = test_source(
            "srcFast0000",
            format!("http://{addr}/ok"),
            3600,
            Some(fumox_core::models::now_ts()),
        );
        sources::create(&pool, &slow).await.unwrap();
        sources::create(&pool, &fast).await.unwrap();

        let fetch_config = FetchConfig {
            // Long enough that no fetch gives up inside the test window.
            read_timeout_secs: 120,
            connect_timeout_secs: 5,
            max_retries: 0,
            ..Default::default()
        };
        let (env, state, events) = test_env(pool.clone(), fetch_config).await;
        let mut rx = events.subscribe();
        let (refresh_tx, refresh_rx) =
            tokio::sync::mpsc::channel(crate::scheduler::REFRESH_CHANNEL_CAP);
        let scheduler = tokio::spawn(run(
            env,
            state,
            events.clone(),
            refresh_rx,
            test_retention(),
        ));

        // The first interval tick is immediate, the sweep starts the slow
        // source and stays on it.
        await_fetch_started(&mut rx, "srcSlow0000").await;

        // A refresh arriving mid-sweep must be picked up right away.
        refresh_tx.send("srcFast0000".to_string()).await.unwrap();
        await_fetch_started(&mut rx, "srcFast0000").await;
        scheduler.abort();
    }

    /// Capture the tracing output of a test: the lines are funnelled
    /// into a shared buffer the test can read.
    ///
    /// The call-site-interest caveat is the same as in the auth logging
    /// test: a call site first executed under another test's empty
    /// dispatcher caches as `never` for the whole process, so the
    /// registry is pinned to multi-dispatcher and the interests are
    /// rebuilt.
    fn capture_logs(
        level: tracing::Level,
    ) -> (
        tracing::subscriber::DefaultGuard,
        Arc<std::sync::Mutex<Vec<u8>>>,
    ) {
        struct Captured(Arc<std::sync::Mutex<Vec<u8>>>);
        impl std::io::Write for Captured {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                self.0.lock().unwrap().extend_from_slice(buf);
                Ok(buf.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let captured = Arc::new(std::sync::Mutex::new(Vec::new()));
        let make_writer = captured.clone();
        let subscriber = tracing_subscriber::fmt()
            .with_ansi(false)
            .with_max_level(level)
            .with_writer(move || Captured(Arc::clone(&make_writer)))
            .finish();
        let guard = tracing::subscriber::set_default(subscriber);
        crate::test_support::stabilize_callsite_interests();
        tracing::callsite::rebuild_interest_cache();
        (guard, captured)
    }

    /// A database failure while looking up a *Refresh now* target must be logged
    /// as an error naming the source, not folded into the "unknown source" warning.
    #[tokio::test]
    async fn refresh_lookup_failure_is_logged_as_an_error() {
        let pool = test_pool().await;
        let (env, state, events) = test_env(pool.clone(), test_fetch_config()).await;
        // The only way to reach the `Err` arm deterministically: a pool
        // that answers nothing anymore.
        env.pool.close().await;

        // The filter only lets ERROR through, so any output at all proves
        // the failure was logged as an error.
        let (_guard, captured) = capture_logs(tracing::Level::ERROR);

        dispatch_refresh(&env, &state, &events, "srcLost0000").await;

        let logs = String::from_utf8(captured.lock().unwrap().clone()).unwrap();
        assert!(
            !logs.is_empty(),
            "a failed lookup must be reported at ERROR level"
        );
        assert!(
            logs.contains("srcLost0000"),
            "the error must name the requested source: {logs}"
        );
        assert!(
            !logs.contains("unknown source"),
            "a database failure must not be mislabeled as an unknown source: {logs}"
        );
    }

    /// A local upstream that answers every request with 401 (a permanently
    /// dead URL: wrong credentials, a vanished feed) and counts the requests
    /// it received.
    async fn dead_upstream() -> (SocketAddr, Arc<AtomicUsize>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let hits = Arc::new(AtomicUsize::new(0));
        let counter = hits.clone();
        tokio::spawn(async move {
            while let Ok((mut socket, _)) = listener.accept().await {
                let counter = counter.clone();
                tokio::spawn(async move {
                    use tokio::io::{AsyncReadExt, AsyncWriteExt};
                    let mut buf = [0u8; 1024];
                    let _ = socket.read(&mut buf).await;
                    counter.fetch_add(1, Ordering::SeqCst);
                    let _ = socket
                        .write_all(
                            b"HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                        )
                        .await;
                });
            }
        });
        (addr, hits)
    }

    /// The fetch config the scheduler tests default to: short timeouts and
    /// no retries — a 401 is not recoverable, and the fetch policy must not
    /// mask the scheduler's own cadence with its retries.
    fn test_fetch_config() -> FetchConfig {
        FetchConfig {
            read_timeout_secs: 10,
            connect_timeout_secs: 5,
            max_retries: 0,
            ..Default::default()
        }
    }

    /// Build the shared ingest environment around `pool` with the fetch
    /// config the caller wants (the fetcher, the ingest budget derived
    /// from the same config, the disabled geo resolver); everything else
    /// is the wiring every scheduler test shares.
    async fn test_env(
        pool: DbPool,
        fetch_config: FetchConfig,
    ) -> (IngestEnv, SchedulerState, EventBus) {
        let budget = ingest_budget(&fetch_config);
        let env = IngestEnv {
            pool,
            fetcher: Fetcher::new(fetch_config, true, Duration::from_secs(5)),
            caches: Caches::new(),
            geo: Arc::new(GeoResolver::new(&GeoConfig {
                enabled: false,
                ..Default::default()
            })),
            settings: crate::ingest::IngestSettings {
                refresh_check_limit: 0,
                drop_gate: false,
                removed_as_unknown: false,
            },
            budget,
        };
        (env, SchedulerState::new(4), EventBus::new())
    }

    /// The retention windows the scheduler enforces in the tests: the
    /// shipped defaults, with a sweep interval the test never waits for
    /// and the `removed`-proxy purge off (its behavior has a dedicated
    /// test of its own).
    fn test_retention() -> ServerRetention {
        ServerRetention {
            fetch_log_days: 30,
            queue_stale_days: 7,
            removed_proxies_days: 0,
            interval_secs: 60,
        }
    }

    async fn test_pool() -> DbPool {
        let dir =
            std::env::temp_dir().join(format!("fumox-sched-test-{}", fumox_core::models::new_id()));
        std::fs::create_dir_all(&dir).unwrap();
        let pool = fumox_core::db::connect_pool(&DatabaseConfig {
            path: dir.join("test.db"),
            ..Default::default()
        })
        .await
        .unwrap();
        fumox_core::db::migrate(&pool).await.unwrap();
        pool
    }

    /// A source whose URL is permanently dead must stop being hammered by
    /// the 30 s sweep. The failure is journalled but `last_fetched_at` stays
    /// NULL (the column is "last *successful* fetch"), so the TTL check
    /// alone calls the source due forever and one upstream request per sweep
    /// went out for the whole lifetime of the deployment.
    #[tokio::test]
    async fn a_dead_source_is_not_refetched_on_every_sweep() {
        let (addr, hits) = dead_upstream().await;
        let pool = test_pool().await;
        sources::create(
            &pool,
            &test_source("srcDead000", format!("http://{addr}/list"), 3600, None),
        )
        .await
        .unwrap();
        let (env, state, events) = test_env(pool.clone(), test_fetch_config()).await;

        sweep(&env, &state, &events).await;
        assert_eq!(
            hits.load(Ordering::SeqCst),
            1,
            "the first sweep fetches a never-fetched source"
        );
        let source = sources::get(&pool, "srcDead000").await.unwrap().unwrap();
        assert!(
            source.last_fetched_at.is_none(),
            "a failed fetch does not count as a successful one"
        );
        assert_eq!(
            source.error_class,
            Some(fumox_core::models::ErrorClass::HttpClient)
        );

        // The sweep stamps its cycle, so the panel can tell a live loop
        // from a wedged one: the stamp is the sweep's start, as a plain
        // unix second.
        let cycle = fumox_core::repo::meta_get(&pool, probe::meta::SERVER_CYCLE_KEY)
            .await
            .unwrap()
            .expect("the sweep stamps server_cycle");
        let cycle: i64 = cycle.parse().expect("server_cycle is a unix second");
        assert!(
            (fumox_core::models::now_ts() - cycle).abs() < 60,
            "the stamp must read as the sweep that just ran: {cycle}"
        );

        // The next tick (30 s later) must not go out to a URL that just
        // answered 401; the backoff is the throttle.
        sweep(&env, &state, &events).await;
        assert_eq!(
            hits.load(Ordering::SeqCst),
            1,
            "a dead upstream must not be hit again on the very next sweep"
        );

        // A healthy source is untouched by any of this: the backoff only
        // applies to a source whose last attempt failed.
        sources::create(
            &pool,
            &test_source("srcOk00000", format!("http://{addr}/ok"), 0, None),
        )
        .await
        .unwrap();
        sources::record_fetch_outcome(
            &pool,
            "srcOk00000",
            &sources::FetchOutcome::Success {
                at: fumox_core::models::now_ts(),
            },
        )
        .await
        .unwrap();
        sweep(&env, &state, &events).await;
        assert_eq!(
            hits.load(Ordering::SeqCst),
            2,
            "a source due by its TTL is still fetched on every sweep"
        );
    }

    /// The backoff has to grow, or a permanently dead source is merely
    /// throttled to a request a minute instead of one every 30 s, and it has
    /// to be capped, or a source that recovers stays dark for days.
    #[test]
    fn failure_backoff_grows_and_is_capped() {
        assert_eq!(failure_backoff_secs(1), 120);
        assert_eq!(failure_backoff_secs(2), 240);
        assert_eq!(failure_backoff_secs(5), 1920);
        assert_eq!(failure_backoff_secs(6), FAILURE_BACKOFF_MAX_SECS);
        assert_eq!(failure_backoff_secs(40), FAILURE_BACKOFF_MAX_SECS);
        // Never below the base, never longer than the cap, never a hammer.
        assert!(failure_backoff_secs(1) > SWEEP_INTERVAL.as_secs() as i64);
    }

    #[tokio::test]
    async fn in_flight_guard_is_exclusive() {
        let state = SchedulerState::new(4);
        let first = state.acquire_source("src1").await;
        assert!(first.is_some());
        assert!(state.acquire_source("src1").await.is_none());
        assert!(state.acquire_source("src2").await.is_some());
        drop(first);
        assert!(state.acquire_source("src1").await.is_some());
    }

    /// The in-flight mark carries the moment the refresh started, so
    /// the admin panel can show how long the running refresh has been
    /// going.
    #[tokio::test]
    async fn the_in_flight_mark_carries_the_start_time() {
        let state = SchedulerState::new(4);
        assert!(state.in_flight_since("src1").await.is_none());
        let guard = state.acquire_source("src1").await;
        assert!(guard.is_some());
        let started = state
            .in_flight_since("src1")
            .await
            .expect("a running refresh carries its start time");
        assert!(
            started <= now_ts() && started > now_ts() - 60,
            "the start time must be now: {started}"
        );
        // Another source has its own mark.
        assert!(state.in_flight_since("src2").await.is_none());
        drop(guard);
        assert!(state.in_flight_since("src1").await.is_none());
    }

    /// A panic in the ingest task must not pin the source as in-flight
    /// forever.
    #[tokio::test]
    async fn in_flight_guard_survives_a_panicking_task() {
        let state = SchedulerState::new(4);
        let task_state = state.clone();
        let handle = tokio::spawn(async move {
            let _guard = task_state
                .acquire_source("src1")
                .await
                .expect("first acquire succeeds");
            panic!("ingest blew up");
        });
        assert!(handle.await.is_err(), "the task is expected to panic");

        // The `Drop` path may hand the removal to the runtime, so yield.
        for _ in 0..10 {
            if !state.is_in_flight("src1").await {
                break;
            }
            tokio::task::yield_now().await;
        }
        assert!(
            !state.is_in_flight("src1").await,
            "unwinding must release the in-flight mark"
        );
        assert!(state.acquire_source("src1").await.is_some());
    }

    /// A panic inside `sweep` must not strand the overlap flag: a flag
    /// stuck at `true` silently disables every future sweep.
    #[test]
    fn sweep_guard_resets_the_flag_on_unwind() {
        let flag = Arc::new(AtomicBool::new(true));
        let guard = SweepGuard(flag.clone());
        let panicked = std::thread::spawn(move || {
            let _guard = guard;
            panic!("sweep blew up");
        })
        .join()
        .is_err();
        assert!(panicked, "the thread is expected to panic");
        assert!(
            !flag.load(Ordering::SeqCst),
            "unwinding must release the sweep-overlap flag"
        );
    }

    /// The due-check table: the TTL cadence, the failure backoff and the
    /// admin-edit escape.
    ///
    /// `updated_at` is set explicitly: a source that was just edited is
    /// retried without waiting out a backoff, and the table has to say
    /// so in both directions.
    #[test]
    fn the_due_check_follows_the_ttl_and_the_backoff() {
        let now = 1_000_000i64;
        let table_source = |ttl: i64, last_fetched_at: Option<i64>, updated_at: i64| {
            let mut source = test_source(
                "srcTable00",
                "https://example.com/sub".into(),
                ttl,
                last_fetched_at,
            );
            source.updated_at = updated_at;
            source
        };
        let failed_once = |last_attempt_at: i64| {
            History::Known(FailureHistory {
                consecutive_failures: 1,
                last_attempt_at,
            })
        };

        // Never fetched: due.
        assert!(is_due(
            &table_source(3600, None, now - 1000),
            now,
            &History::Empty
        ));
        // Fetched ten seconds ago, the TTL is an hour: not due.
        assert!(!is_due(
            &table_source(3600, Some(now - 10), now - 1000),
            now,
            &History::Empty
        ));
        // The TTL has elapsed: due.
        assert!(is_due(
            &table_source(3600, Some(now - 3600), now - 1000),
            now,
            &History::Empty
        ));

        // One failure in a row: the backoff is 120 s. Sixty seconds
        // after the attempt the source is held back, 121 seconds after
        // it the retry is due.
        assert!(!is_due(
            &table_source(3600, Some(now - 3600), now - 1000),
            now,
            &failed_once(now - 60)
        ));
        assert!(is_due(
            &table_source(3600, Some(now - 3600), now - 1000),
            now,
            &failed_once(now - 121)
        ));

        // An edit after the last attempt releases the source from the
        // backoff: the old configuration earned it, the new one did not.
        assert!(is_due(
            &table_source(3600, Some(now - 3600), now - 5),
            now,
            &failed_once(now - 60)
        ));

        // A history that could not be read holds the source back: a
        // source that cannot be judged is not a source to fetch.
        assert!(!is_due(
            &table_source(3600, None, now - 1000),
            now,
            &History::Unreadable
        ));
    }

    /// The journal is consulted only for a source that passes the TTL
    /// check and whose recorded verdict says the last attempt failed: a
    /// source that is not due yet costs no query, and neither does a
    /// healthy one.
    #[tokio::test]
    async fn the_history_is_read_only_for_the_sources_that_pass_the_ttl_check() {
        let now = fumox_core::models::now_ts();
        let mut not_due = test_source(
            "srcFresh000",
            "https://example.com/sub".into(),
            3600,
            Some(now - 10),
        );
        not_due.error_class = Some(fumox_core::models::ErrorClass::HttpClient);
        let healthy = test_source(
            "srcHealth00",
            "https://example.com/sub".into(),
            3600,
            Some(now - 7200),
        );
        let mut failing = test_source(
            "srcFail0000",
            "https://example.com/sub".into(),
            3600,
            Some(now - 7200),
        );
        failing.error_class = Some(fumox_core::models::ErrorClass::HttpClient);

        let reads = Arc::new(AtomicUsize::new(0));
        let counter = reads.clone();
        let due = due_sources(vec![not_due, healthy, failing], now, move |_id| {
            let counter = counter.clone();
            async move {
                counter.fetch_add(1, Ordering::SeqCst);
                History::Empty
            }
        })
        .await;

        assert_eq!(
            reads.load(Ordering::SeqCst),
            1,
            "only the failing source costs a query"
        );
        assert_eq!(
            due.len(),
            2,
            "the healthy source and the failing one are past their TTL"
        );
        assert!(
            !due.iter().any(|source| source.id == "srcFresh000"),
            "a source that is not due yet stays out"
        );
    }

    /// A journal that cannot be read is not a journal that says "fetch":
    /// the source is held back, and the failure is logged with the name
    /// of the source.
    #[tokio::test]
    async fn an_unreadable_history_holds_the_source_back_and_is_logged() {
        let pool = test_pool().await;
        pool.close().await;

        let (_guard, captured) = capture_logs(tracing::Level::WARN);
        let history = failure_history(&pool, "srcLost0000").await;
        assert!(
            matches!(history, History::Unreadable),
            "a failed read must not look like an empty journal"
        );

        let logs = String::from_utf8(captured.lock().unwrap().clone()).unwrap();
        assert!(
            logs.contains("cannot read the fetch history"),
            "the read failure must be reported: {logs}"
        );
        assert!(
            logs.contains("srcLost0000"),
            "the report must name the source: {logs}"
        );

        let source = test_source("srcLost0000", "https://example.com/sub".into(), 0, None);
        assert!(
            !is_due(&source, fumox_core::models::now_ts(), &History::Unreadable),
            "a source whose history cannot be read is held back"
        );
    }

    /// The failure history counts from the *newest* journal row, on the
    /// real pool: a success newer than the failures resets the streak and
    /// carries `last_attempt_at` (a source that recovered is not still
    /// backed off), a failure newer than the success keeps the streak at
    /// one — and the due check agrees with the backoff that streak
    /// implies.
    #[tokio::test]
    async fn the_failure_history_counts_from_the_newest_row() {
        let pool = test_pool().await;
        let now = fumox_core::models::now_ts();
        // The journal rows reference the source: the row must exist first.
        sources::create(
            &pool,
            &test_source("srcHist0000", "https://example.com/sub".into(), 3600, None),
        )
        .await
        .unwrap();
        let row = |fetched_at: i64, ok: bool| fetch_log::FetchLogEntry {
            source_id: "srcHist0000",
            fetched_at,
            ok,
            http_status: None,
            bytes: None,
            proxies_found: None,
            error: None,
            error_class: None,
        };
        // Two failures, then a success newer than both.
        fetch_log::insert(
            &pool,
            &row(now - 300, false),
            fetch_log::FetchTiming::default(),
        )
        .await
        .unwrap();
        fetch_log::insert(
            &pool,
            &row(now - 200, false),
            fetch_log::FetchTiming::default(),
        )
        .await
        .unwrap();
        fetch_log::insert(
            &pool,
            &row(now - 100, true),
            fetch_log::FetchTiming::default(),
        )
        .await
        .unwrap();
        let History::Known(recovered) = failure_history(&pool, "srcHist0000").await else {
            panic!("the journal holds rows for the source");
        };
        assert_eq!(
            recovered.consecutive_failures, 0,
            "a success resets the failure streak"
        );
        assert_eq!(
            recovered.last_attempt_at,
            now - 100,
            "last_attempt_at is the newest row's fetched_at"
        );
        assert!(
            is_due(
                &test_source("srcHist0000", "https://example.com/sub".into(), 3600, None),
                now,
                &History::Known(recovered)
            ),
            "a recovered source is due by its plain TTL cadence"
        );

        // The reverse order: a failure newer than the success.
        fetch_log::insert(
            &pool,
            &row(now - 50, false),
            fetch_log::FetchTiming::default(),
        )
        .await
        .unwrap();
        let History::Known(failing) = failure_history(&pool, "srcHist0000").await else {
            panic!("the journal holds rows for the source");
        };
        assert_eq!(
            failing.consecutive_failures, 1,
            "the newest row failed, the streak restarts at one"
        );
        assert_eq!(failing.last_attempt_at, now - 50);

        // The due check defers to that backoff: ten seconds after the
        // failed attempt (backoff 120 s) the source is held back, past
        // the backoff it is due again. `updated_at` predates the attempt,
        // so the admin-edit escape does not fire.
        let mut source = test_source(
            "srcHist0000",
            "https://example.com/sub".into(),
            3600,
            Some(now - 7200),
        );
        source.updated_at = now - 7200;
        assert!(
            !is_due(&source, now - 40, &History::Known(failing)),
            "ten seconds after a failure the backoff still holds"
        );
        assert!(
            is_due(&source, now + 71, &History::Known(failing)),
            "121 seconds after a failure the retry is due"
        );
    }

    /// The time the source page shows next to the last error: the newest
    /// journal attempt plus the backoff its streak earned, capped at the
    /// ceiling — seven consecutive failures read as "within the hour", not
    /// "tomorrow" — and cleared entirely by a success.
    #[tokio::test]
    async fn the_next_retry_time_grows_with_the_streak_and_is_capped() {
        let pool = test_pool().await;
        sources::create(
            &pool,
            &test_source("srcRetry000", "https://example.com/sub".into(), 3600, None),
        )
        .await
        .unwrap();
        let now = fumox_core::models::now_ts();
        let row = |fetched_at: i64, ok: bool| fetch_log::FetchLogEntry {
            source_id: "srcRetry000",
            fetched_at,
            ok,
            http_status: None,
            bytes: None,
            proxies_found: None,
            error: None,
            error_class: None,
        };
        // One failure: the retry is the base backoff after it.
        fetch_log::insert(
            &pool,
            &row(now - 300, false),
            fetch_log::FetchTiming::default(),
        )
        .await
        .unwrap();
        assert_eq!(
            next_retry_at(&pool, "srcRetry000").await,
            Some(now - 300 + 120)
        );

        // A second failure doubles the wait; the streak counts from the
        // newest row.
        fetch_log::insert(
            &pool,
            &row(now - 100, false),
            fetch_log::FetchTiming::default(),
        )
        .await
        .unwrap();
        assert_eq!(
            next_retry_at(&pool, "srcRetry000").await,
            Some(now - 100 + 240)
        );

        // Past the ceiling the answer is the ceiling: 60 s × 2⁷ is an
        // hour, no matter how long the streak grows.
        for offset in [90, 80, 70, 60, 50] {
            fetch_log::insert(
                &pool,
                &row(now - offset, false),
                fetch_log::FetchTiming::default(),
            )
            .await
            .unwrap();
        }
        assert_eq!(
            next_retry_at(&pool, "srcRetry000").await,
            Some(now - 50 + FAILURE_BACKOFF_MAX_SECS)
        );

        // A success clears the hint: the plain TTL cadence applies.
        fetch_log::insert(
            &pool,
            &row(now - 5, true),
            fetch_log::FetchTiming::default(),
        )
        .await
        .unwrap();
        assert_eq!(next_retry_at(&pool, "srcRetry000").await, None);
    }

    /// An ingestion that exceeds its budget is abandoned: the permit and
    /// the in-flight mark are released, and the panel is told the fetch
    /// failed instead of waiting for an outcome that never comes.
    #[tokio::test]
    async fn an_ingest_that_exceeds_its_budget_is_abandoned() {
        // A source host that accepts connections and never answers.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((mut socket, _)) = listener.accept().await {
                tokio::spawn(async move {
                    use tokio::io::AsyncReadExt;
                    let mut buf = [0u8; 1024];
                    let _ = socket.read(&mut buf).await;
                    std::future::pending::<()>().await;
                });
            }
        });

        let pool = test_pool().await;
        // The row must exist: after the permit the ingest re-reads it, and
        // a source that is gone is skipped instead of fetched.
        sources::create(
            &pool,
            &test_source("srcHung000", format!("http://{addr}/hang"), 0, None),
        )
        .await
        .unwrap();
        let (mut env, state, events) = test_env(pool, test_fetch_config()).await;
        env.budget = Duration::from_millis(500);
        let mut rx = events.subscribe();

        spawn_ingest(
            &env,
            &state,
            &events,
            test_source("srcHung000", format!("http://{addr}/hang"), 0, None),
            false,
        );

        let mut started = false;
        let failed = tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                let event = rx.recv().await.expect("event bus stays open");
                if event.name == "fetch.started" {
                    started = true;
                }
                if event.name == "fetch.failed" {
                    return event;
                }
            }
        })
        .await
        .expect("the budget expiry is reported");
        assert!(started, "the request went out before the budget expired");
        assert_eq!(failed.data["source_id"], "srcHung000");
        assert_eq!(failed.data["error_class"], "timeout");

        for _ in 0..10 {
            if !state.is_in_flight("srcHung000").await {
                break;
            }
            tokio::task::yield_now().await;
        }
        assert!(
            !state.is_in_flight("srcHung000").await,
            "the abandoned attempt releases the in-flight mark"
        );
        assert_eq!(
            state.semaphore.available_permits(),
            4,
            "the abandoned attempt releases the concurrency permit"
        );
    }

    /// A pass that overlaps the previous one is skipped, and the skipped
    /// ticks are counted: the count is what tells the operator that the
    /// scheduler runs behind its cadence.
    #[test]
    fn an_overlapping_pass_is_skipped_and_counted() {
        let mut slot = SweepSlot::new();
        assert!(slot.take(), "the first pass takes the slot");
        assert!(!slot.take(), "the second pass overlaps");
        assert_eq!(slot.skipped(), 1);
        assert!(!slot.take());
        assert_eq!(slot.skipped(), 2);

        // The slot is released when the pass ends; the count starts over.
        slot.flag().store(false, Ordering::SeqCst);
        assert!(slot.take(), "the slot is free again");
        assert_eq!(slot.skipped(), 0, "a pass that runs resets the counter");
    }

    /// One minimal `proxies` row for the `probe_requests` FK; returns its id.
    async fn test_proxy(pool: &DbPool, fingerprint: &str) -> i64 {
        let (id,): (i64,) = sqlx::query_as(
            "INSERT INTO proxies (fingerprint, scheme, name, host, port, credential,
                                  created_at, updated_at)
             VALUES (?, 'vless', 'n', 'h', 443, 'c', 1, 1) RETURNING id",
        )
        .bind(fingerprint)
        .fetch_one(pool)
        .await
        .unwrap();
        id
    }

    /// A server-only deployment (no probe daemon) still writes a `fetch_log`
    /// row per fetch attempt and enqueues `probe_requests` per refresh, with
    /// nothing draining either. The scheduler's own retention sweep must
    /// shed both past the same windows the daemon's loop enforces, keep
    /// everything inside them, drop queue rows whose proxy already left
    /// `unknown`, and stamp the rotation the panel shows.
    #[tokio::test]
    async fn server_retention_sweep_purges_old_journal_and_queue_rows() {
        let pool = test_pool().await;
        sources::create(
            &pool,
            &test_source("srcRotat000", "https://example.com/sub".into(), 3600, None),
        )
        .await
        .unwrap();

        let now = fumox_core::models::now_ts();
        let day = 86_400i64;
        for (fetched_at, ok) in [(now - 40 * day, false), (now - day, true)] {
            fetch_log::insert(
                &pool,
                &fetch_log::FetchLogEntry {
                    source_id: "srcRotat000",
                    fetched_at,
                    ok,
                    http_status: None,
                    bytes: None,
                    proxies_found: None,
                    error: None,
                    error_class: None,
                },
                fetch_log::FetchTiming::default(),
            )
            .await
            .unwrap();
        }

        let fresh_proxy = test_proxy(&pool, "fp-fresh").await;
        let stale_proxy = test_proxy(&pool, "fp-stale").await;
        let settled_proxy = test_proxy(&pool, "fp-settled").await;
        sqlx::query("UPDATE proxies SET status = 'alive' WHERE id = ?")
            .bind(settled_proxy)
            .execute(&pool)
            .await
            .unwrap();
        // Two rows in the `removed` tier: one past the TTL window, one
        // inside it — the purge takes only the first.
        let purged_proxy = test_proxy(&pool, "fp-purged").await;
        let kept_proxy = test_proxy(&pool, "fp-kept").await;
        sqlx::query("UPDATE proxies SET status = 'removed', removed_at = ? WHERE id = ?")
            .bind(now - 30 * day)
            .bind(purged_proxy)
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("UPDATE proxies SET status = 'removed', removed_at = ? WHERE id = ?")
            .bind(now)
            .bind(kept_proxy)
            .execute(&pool)
            .await
            .unwrap();
        for (proxy_id, requested_at) in [
            (fresh_proxy, now),
            (stale_proxy, now - 30 * day),
            (settled_proxy, now),
        ] {
            sqlx::query("INSERT INTO probe_requests (proxy_id, requested_at) VALUES (?, ?)")
                .bind(proxy_id)
                .bind(requested_at)
                .execute(&pool)
                .await
                .unwrap();
        }

        let retention = ServerRetention {
            fetch_log_days: 30,
            queue_stale_days: 7,
            removed_proxies_days: 7,
            interval_secs: 60,
        };
        retention_sweep(&pool, &retention).await;

        assert_eq!(
            fetch_log::count_all(&pool).await.unwrap(),
            1,
            "the row inside the window stays, the one past it goes"
        );
        let (queued,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM probe_requests")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(
            queued, 1,
            "the fresh request stays, the stale and the settled ones go"
        );
        let (removed,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM proxies WHERE id IN (?, ?)")
            .bind(purged_proxy)
            .bind(kept_proxy)
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(
            removed, 1,
            "the removed row past the TTL window is gone, the fresh one stays"
        );
        let (alive,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM proxies WHERE id = ?")
            .bind(settled_proxy)
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(alive, 1, "the purge never touches a live row");

        let stamp = fumox_core::repo::meta_get(&pool, probe::meta::SERVER_RETENTION_KEY)
            .await
            .unwrap()
            .expect("the sweep stamps its run under the server's own key");
        let stamp: probe::meta::ServerRetentionStamp = serde_json::from_str(&stamp).unwrap();
        assert_eq!(stamp.fetch_log, 1);
        assert_eq!(stamp.probe_requests, 2);
        assert_eq!(stamp.proxies, 1);
        assert!(stamp.ok, "the pass ran to completion");

        // The daemon's stamp is untouched: `last_rotation` stays the
        // daemon's, its `probe_results` counter is not zeroed by a
        // server-side pass that never touches that table.
        let daemon = probe::meta::LastRotation {
            ts: now - 30,
            probe_results: 7,
            fetch_log: 0,
            probe_requests: 0,
            ok: true,
            error: None,
        };
        fumox_core::repo::meta_set(
            &pool,
            probe::meta::LAST_ROTATION_KEY,
            &serde_json::to_string(&daemon).expect("meta payload holds only JSON-native fields"),
        )
        .await
        .unwrap();
        retention_sweep(&pool, &retention).await;
        let after = fumox_core::repo::meta_get(&pool, probe::meta::LAST_ROTATION_KEY)
            .await
            .unwrap()
            .expect("the daemon's stamp survives");
        let after: probe::meta::LastRotation = serde_json::from_str(&after).unwrap();
        assert_eq!(
            after, daemon,
            "the server pass must not rewrite last_rotation"
        );

        // A zero window is clamped to one day, so a row that was just
        // written survives the pass: the clamp is what keeps a
        // misconfigured window from wiping the whole journal.
        fetch_log::insert(
            &pool,
            &fetch_log::FetchLogEntry {
                source_id: "srcRotat000",
                fetched_at: now,
                ok: true,
                http_status: None,
                bytes: None,
                proxies_found: None,
                error: None,
                error_class: None,
            },
            fetch_log::FetchTiming::default(),
        )
        .await
        .unwrap();
        let retention = ServerRetention {
            fetch_log_days: 0,
            queue_stale_days: 7,
            removed_proxies_days: 0,
            interval_secs: 60,
        };
        retention_sweep(&pool, &retention).await;
        let (fresh,): (i64,) =
            sqlx::query_as("SELECT COUNT(*) FROM fetch_log WHERE fetched_at = ?")
                .bind(now)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(fresh, 1, "a row written now survives a zero-day window");
    }

    /// A purge that fails (a SQLite busy from a competing writer, say)
    /// must not read as a fresh successful rotation: the stamp keeps the
    /// `ts` of the last successful pass, says `ok: false` with the error
    /// text, and counts nothing. The panel can then show "the sweep has
    /// not succeeded lately" instead of a green "rotated just now".
    #[tokio::test]
    async fn a_failed_retention_pass_does_not_look_like_a_fresh_rotation() {
        let pool = test_pool().await;
        // A first, successful pass stamps the last-good ts (an empty
        // database: nothing to purge, the stamp is still written).
        retention_sweep(&pool, &test_retention()).await;
        let good = fumox_core::repo::meta_get(&pool, probe::meta::SERVER_RETENTION_KEY)
            .await
            .unwrap()
            .expect("the successful pass stamps its run");
        let good: probe::meta::ServerRetentionStamp = serde_json::from_str(&good).unwrap();
        assert!(good.ok);

        // Every DELETE from fetch_log now aborts, the way a busy database
        // fails individual statements — while meta and the other tables
        // keep working, so the stamp itself is still writable. An old row
        // past the window gives the DELETE something to trip over.
        sources::create(
            &pool,
            &test_source("srcRotat000", "https://example.com/sub".into(), 3600, None),
        )
        .await
        .unwrap();
        fetch_log::insert(
            &pool,
            &fetch_log::FetchLogEntry {
                source_id: "srcRotat000",
                fetched_at: fumox_core::models::now_ts() - 40 * 86_400,
                ok: true,
                http_status: None,
                bytes: None,
                proxies_found: None,
                error: None,
                error_class: None,
            },
            fetch_log::FetchTiming::default(),
        )
        .await
        .unwrap();
        sqlx::query(
            "CREATE TRIGGER fetch_log_no_delete BEFORE DELETE ON fetch_log
             BEGIN SELECT RAISE(ABORT, 'simulated busy'); END;",
        )
        .execute(&pool)
        .await
        .unwrap();

        retention_sweep(&pool, &test_retention()).await;
        let stamp = fumox_core::repo::meta_get(&pool, probe::meta::SERVER_RETENTION_KEY)
            .await
            .unwrap()
            .expect("the failed pass still reports itself");
        let stamp: probe::meta::ServerRetentionStamp = serde_json::from_str(&stamp).unwrap();
        assert!(!stamp.ok, "a failed pass must not read as successful");
        assert!(
            stamp
                .error
                .as_deref()
                .is_some_and(|error| error.contains("fetch_log")),
            "the stamp names the purge that failed: {:?}",
            stamp.error
        );
        assert_eq!(
            stamp.ts, good.ts,
            "a failed pass keeps the ts of the last successful one"
        );
        assert_eq!(stamp.fetch_log, 0, "nothing was purged");
    }

    /// A local upstream that answers every request with the same 200 body
    /// and counts the requests it received. Reads the request out before
    /// answering, like a real HTTP server (see `ingest::ingest_env` for
    /// why the extra care keeps fetch counts stable).
    async fn ok_upstream(body: &'static str) -> (SocketAddr, Arc<AtomicUsize>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let hits = Arc::new(AtomicUsize::new(0));
        let counter = hits.clone();
        tokio::spawn(async move {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            while let Ok((mut sock, _)) = listener.accept().await {
                let counter = counter.clone();
                tokio::spawn(async move {
                    let mut received = Vec::with_capacity(1024);
                    loop {
                        let mut scratch = [0u8; 1024];
                        match sock.read(&mut scratch).await {
                            Ok(0) | Err(_) => break,
                            Ok(n) => {
                                received.extend_from_slice(&scratch[..n]);
                                if received.windows(4).any(|w| w == b"\r\n\r\n")
                                    || received.len() >= 16 * 1024
                                {
                                    break;
                                }
                            }
                        }
                    }
                    counter.fetch_add(1, Ordering::SeqCst);
                    let head = format!(
                        "HTTP/1.1 200 OK\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                        body.len()
                    );
                    let _ = sock.write_all(head.as_bytes()).await;
                    let _ = sock.write_all(body.as_bytes()).await;
                });
            }
        });
        (addr, hits)
    }

    /// Seed a rendered output that names the source, the way a served
    /// `/sub/{profile}` rendering would.
    async fn seed_rendering(caches: &Caches, key: &str, source_id: &str) {
        caches
            .processed_put_unguarded(
                key,
                crate::cache::Rendered {
                    status: 200,
                    body: axum::body::Bytes::from_static(b"stale rendering"),
                    content_type: "text/plain; charset=utf-8".into(),
                    extra_headers: Vec::new(),
                    fresh_until: fumox_core::models::now_ts() + 3_600,
                    source_ids: vec![source_id.to_string()],
                },
            )
            .await;
    }

    /// The ingest outcome decides the renderings' fate: a reconcile that
    /// changed rows (`inserted + updated + removed > 0`) drops every
    /// rendered output containing the source, an ingest that changed
    /// nothing (the freshness short-circuit, all-zero stats) keeps them.
    /// The decision lives in `spawn_ingest`, so both branches of its
    /// condition are pinned here: a regression that flips the condition
    /// or misreads the stats now fails instead of passing silently.
    #[tokio::test]
    async fn a_data_changing_ingest_drops_renderings_and_a_quiet_one_keeps_them() {
        let (addr, hits) =
            ok_upstream("vless://11111111-1111-1111-1111-111111111111@1.2.3.4:443#A\n").await;
        let pool = test_pool().await;
        let source = test_source("srcCache000", format!("http://{addr}/sub"), 3600, None);
        sources::create(&pool, &source).await.unwrap();
        let (env, state, events) = test_env(pool.clone(), test_fetch_config()).await;
        let key = "sub:profCache0";

        // Changed rows: the first reconcile inserts the proxy.
        seed_rendering(&env.caches, key, &source.id).await;
        spawn_ingest(&env, &state, &events, source.clone(), false)
            .await
            .expect("the ingest task does not panic");
        assert_eq!(hits.load(Ordering::SeqCst), 1, "the first ingest fetches");
        assert!(
            env.caches.processed_get(key).await.is_none(),
            "an ingest that inserted rows must drop renderings containing the source"
        );

        // Nothing changed: the freshness short-circuit answers with
        // all-zero stats without touching the network, and the rendering
        // stays valid. The row is handed over exactly as a sweep would
        // (the scheduler re-reads every sweep, the freshness guard inside
        // the ingest is the row-level second check).
        let fresh = test_source(
            "srcCache000",
            format!("http://{addr}/sub"),
            3600,
            Some(fumox_core::models::now_ts()),
        );
        seed_rendering(&env.caches, key, &source.id).await;
        spawn_ingest(&env, &state, &events, fresh, false)
            .await
            .expect("the ingest task does not panic");
        assert_eq!(
            hits.load(Ordering::SeqCst),
            1,
            "a fresh row short-circuits without a fetch"
        );
        assert!(
            env.caches.processed_get(key).await.is_some(),
            "an ingest that changed nothing must keep the rendering"
        );
    }

    /// `fetch.started` must not fire before a concurrency permit is in
    /// hand: under `[fetch].max_concurrency` saturation the spawned task
    /// waits on the semaphore while already marked in-flight, and the
    /// "fetching" notion has to begin with the request, not the queue
    /// entry. The wait is announced as `fetch.queued` instead; the
    /// in-flight mark still spans the whole window, so a duplicate
    /// *Refresh now* stays dropped.
    #[tokio::test]
    async fn fetch_started_waits_for_the_concurrency_permit() {
        let (addr, _hits) = dead_upstream().await;
        let url = format!("http://{addr}/sub");
        let pool = test_pool().await;
        sources::create(&pool, &test_source("srcQueue000", url.clone(), 0, None))
            .await
            .unwrap();
        let (env, _idle_state, events) = test_env(pool, test_fetch_config()).await;
        // One permit, and the test holds it: the spawned task must queue.
        let state = SchedulerState::new(1);
        let mut rx = events.subscribe();

        // The only permit is held by the test, so the spawned task queues.
        let permit = state.semaphore.clone().acquire_owned().await.unwrap();
        spawn_ingest(
            &env,
            &state,
            &events,
            test_source("srcQueue000", url.clone(), 0, None),
            false,
        );

        // The queue announcement proves the in-flight mark is taken
        // (acquire_source runs before the semaphore wait). A duplicate
        // spawn is dropped by that mark inside its own task: it exits
        // without publishing anything, so no second `fetch.queued` may
        // appear while the first refresh is still queued.
        let queued = rx.recv().await.expect("event bus stays open");
        assert_eq!(queued.name, "fetch.queued");
        assert_eq!(queued.data["source_id"], "srcQueue000");
        spawn_ingest(
            &env,
            &state,
            &events,
            test_source("srcQueue000", url, 0, None),
            false,
        )
        .await
        .expect("the duplicate task does not panic");
        assert!(
            state.is_in_flight("srcQueue000").await,
            "a queued refresh is marked in flight"
        );
        let duplicate_published = tokio::time::timeout(Duration::from_millis(200), rx.recv()).await;
        assert!(
            duplicate_published.is_err(),
            "the duplicate must exit silently while the first refresh is queued, \
             got {duplicate_published:?}"
        );

        let started_early = tokio::time::timeout(Duration::from_millis(200), async {
            loop {
                let event = rx.recv().await.expect("event bus stays open");
                if event.name == "fetch.started" {
                    return event;
                }
            }
        })
        .await;
        assert!(
            started_early.is_err(),
            "fetch.started must wait for the permit, got {started_early:?}"
        );

        drop(permit);
        await_fetch_started(&mut rx, "srcQueue000").await;
    }

    /// Wait for the next event with the given name, failing the test when
    /// it does not arrive inside the window.
    async fn await_event(
        rx: &mut tokio::sync::broadcast::Receiver<Event>,
        name: &'static str,
    ) -> Event {
        let wait = async {
            loop {
                let event = rx.recv().await.expect("event bus stays open");
                if event.name == name {
                    return event;
                }
            }
        };
        tokio::time::timeout(Duration::from_secs(10), wait)
            .await
            .unwrap_or_else(|_| panic!("{name} did not arrive in time"))
    }

    /// The classified upstream failure publishes the full `fetch.failed`
    /// field set: the source id, the error class, the failure text and the
    /// HTTP status the server answered.
    #[tokio::test]
    async fn fetch_failed_payload_names_the_source_and_the_error() {
        let (addr, _hits) = dead_upstream().await;
        let pool = test_pool().await;
        sources::create(
            &pool,
            &test_source("srcFailP000", format!("http://{addr}/sub"), 0, None),
        )
        .await
        .unwrap();
        let (env, state, events) = test_env(pool, test_fetch_config()).await;
        let mut rx = events.subscribe();

        spawn_ingest(
            &env,
            &state,
            &events,
            test_source("srcFailP000", format!("http://{addr}/sub"), 0, None),
            false,
        )
        .await
        .expect("the ingest task does not panic");

        let failed = await_event(&mut rx, "fetch.failed").await;
        assert_eq!(failed.data["source_id"], "srcFailP000");
        assert_eq!(failed.data["ok"], false);
        assert_eq!(
            failed.data["error_class"],
            fumox_core::models::ErrorClass::HttpClient.as_str()
        );
        assert!(
            failed.data["message"]
                .as_str()
                .is_some_and(|m| !m.is_empty()),
            "the payload carries the failure text: {failed:?}"
        );
        assert_eq!(
            failed.data["http_status"].as_u64(),
            Some(401),
            "the payload carries the status the server answered"
        );
        assert!(
            failed.data["duration_ms"].is_i64(),
            "the attempt was measured"
        );
    }

    /// An unparseable payload publishes `fetch.failed` with the same field
    /// set, `error_class` pinned to `parse_error` and no HTTP status beyond
    /// the 200 that delivered the body.
    #[tokio::test]
    async fn fetch_failed_payload_for_an_unparseable_payload_is_parse_error() {
        let (addr, _hits) = ok_upstream("this is not a subscription").await;
        let pool = test_pool().await;
        sources::create(
            &pool,
            &test_source("srcParse000", format!("http://{addr}/sub"), 0, None),
        )
        .await
        .unwrap();
        let (env, state, events) = test_env(pool, test_fetch_config()).await;
        let mut rx = events.subscribe();

        spawn_ingest(
            &env,
            &state,
            &events,
            test_source("srcParse000", format!("http://{addr}/sub"), 0, None),
            false,
        )
        .await
        .expect("the ingest task does not panic");

        let failed = await_event(&mut rx, "fetch.failed").await;
        assert_eq!(failed.data["source_id"], "srcParse000");
        assert_eq!(failed.data["error_class"], "parse_error");
        assert!(
            failed.data["message"]
                .as_str()
                .is_some_and(|m| !m.is_empty()),
            "the payload carries the parse message: {failed:?}"
        );
        assert_eq!(
            failed.data["http_status"],
            serde_json::Value::Null,
            "the server answered 200, the failure is not an HTTP one"
        );
    }

    /// A successful ingest publishes `fetch.done` with the reconcile
    /// numbers the panel reports.
    #[tokio::test]
    async fn fetch_done_payload_reports_the_reconcile() {
        let (addr, _hits) =
            ok_upstream("vless://11111111-1111-1111-1111-111111111111@1.2.3.4:443#A\n").await;
        let pool = test_pool().await;
        sources::create(
            &pool,
            &test_source("srcDoneP00", format!("http://{addr}/sub"), 0, None),
        )
        .await
        .unwrap();
        let (env, state, events) = test_env(pool, test_fetch_config()).await;
        let mut rx = events.subscribe();

        spawn_ingest(
            &env,
            &state,
            &events,
            test_source("srcDoneP00", format!("http://{addr}/sub"), 0, None),
            false,
        )
        .await
        .expect("the ingest task does not panic");

        let done = await_event(&mut rx, "fetch.done").await;
        assert_eq!(done.data["source_id"], "srcDoneP00");
        assert_eq!(done.data["ok"], true);
        assert_eq!(done.data["proxies_found"], 1);
        assert_eq!(done.data["dropped"], 0);
        assert!(done.data["duration_ms"].is_i64());
    }

    /// A second *Refresh now* for the same source inside the minimum
    /// interval is dropped at dispatch: the in-flight guard only covers
    /// concurrent fetches, the spacing is what keeps back-to-back requests
    /// from fetching the same URL twice in a row.
    #[tokio::test]
    async fn a_forced_refresh_closer_than_the_minimum_interval_is_dropped() {
        let (addr, hits) =
            ok_upstream("vless://11111111-1111-1111-1111-111111111111@1.2.3.4:443#A\n").await;
        let pool = test_pool().await;
        sources::create(
            &pool,
            &test_source("srcThr0000", format!("http://{addr}/sub"), 0, None),
        )
        .await
        .unwrap();
        let (env, state, events) = test_env(pool, test_fetch_config()).await;
        let mut rx = events.subscribe();

        dispatch_refresh(&env, &state, &events, "srcThr0000").await;
        dispatch_refresh(&env, &state, &events, "srcThr0000").await;

        // The first forced refresh fetches and completes.
        let done = await_event(&mut rx, "fetch.done").await;
        assert_eq!(done.data["source_id"], "srcThr0000");

        // The throttled one never announces itself and never fetches.
        let quiet = tokio::time::timeout(Duration::from_millis(300), rx.recv()).await;
        assert!(
            quiet.is_err(),
            "the throttled refresh must publish nothing: {quiet:?}"
        );
        assert_eq!(
            hits.load(Ordering::SeqCst),
            1,
            "only the first request went out"
        );
    }

    /// A source row that changed while the fetch was queued is honored:
    /// after the permit the ingest re-reads the row and fetches the fresh
    /// URL, not the snapshot the spawn captured. The edit's `updated_at`
    /// is what the re-read keys on.
    #[tokio::test]
    async fn a_queued_fetch_picks_up_an_edited_source_row() {
        // The URL the admin edits in: answers with a valid body. The URL
        // the row was created with has nothing listening, so the old
        // snapshot would fail instead of completing.
        let (fresh_addr, hits) =
            ok_upstream("vless://11111111-1111-1111-1111-111111111111@1.2.3.4:443#A\n").await;
        let pool = test_pool().await;
        sources::create(
            &pool,
            &test_source("srcEditQ000", "http://127.0.0.1:9/sub".into(), 0, None),
        )
        .await
        .unwrap();
        let (env, state, events) = test_env(pool.clone(), test_fetch_config()).await;
        let mut rx = events.subscribe();

        // Every permit is held by the test: the spawned task queues.
        let mut permits = Vec::new();
        for _ in 0..state.semaphore.available_permits() {
            permits.push(state.semaphore.clone().acquire_owned().await.unwrap());
        }
        spawn_ingest(
            &env,
            &state,
            &events,
            test_source("srcEditQ000", "http://127.0.0.1:9/sub".into(), 0, None),
            false,
        );
        let queued = await_event(&mut rx, "fetch.queued").await;
        assert_eq!(queued.data["source_id"], "srcEditQ000");

        // The admin edit lands while the task sits on the semaphore.
        sqlx::query("UPDATE sources SET url = ?, updated_at = ? WHERE id = ?")
            .bind(format!("http://{fresh_addr}/sub"))
            .bind(fumox_core::models::now_ts())
            .bind("srcEditQ000")
            .execute(&pool)
            .await
            .unwrap();

        drop(permits);
        let done = await_event(&mut rx, "fetch.done").await;
        assert_eq!(done.data["source_id"], "srcEditQ000");
        assert_eq!(
            hits.load(Ordering::SeqCst),
            1,
            "the fetch went to the URL the row carries now"
        );
    }
}
