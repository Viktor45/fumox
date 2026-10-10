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
//! The loop also owns the server's journal retention: `fetch_log` and
//! `probe_requests` are swept on the `[probe].retention_interval_secs`
//! cadence with the same windows the probe daemon's retention loop derives
//! from the config, so a server-only deployment (no daemon) stays
//! retention-bounded too (see [`retention_sweep`]).

use crate::cache::Caches;
use crate::events::EventBus;
use crate::fetcher::Fetcher;
use crate::ingest;
use fumox_core::db::DbPool;
use fumox_core::geo::GeoResolver;
use fumox_core::models::Source;
use fumox_core::repo::{fetch_log, probe, sources};
use std::collections::HashSet;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use tokio::sync::{Mutex, Semaphore};
use tokio::task::JoinSet;

/// How often the scheduler looks for sources due for a refresh.
const SWEEP_INTERVAL: Duration = Duration::from_secs(30);

/// Delay before a source whose last fetch failed is retried, doubled per
/// consecutive failure and capped at [`FAILURE_BACKOFF_MAX_SECS`]. A dead URL
/// (401/403/404, dead DNS, a feed that no longer parses) does not become
/// healthy because it was asked again 30 s later, and the fetcher has no
/// internal backoff of its own for the non-recoverable classes.
const FAILURE_BACKOFF_BASE_SECS: i64 = 60;

/// Ceiling of the failure backoff: still three orders of magnitude below the
/// 30 s sweep, and still far below the smallest sensible operator patience
/// for a source that quietly recovered.
const FAILURE_BACKOFF_MAX_SECS: i64 = 3_600;

/// How many journal rows one source's failure history is read from: enough
/// to reach the backoff ceiling, the journal is retention-bounded anyway.
const FAILURE_HISTORY_ROWS: i64 = 8;

/// What the fetch journal says about the most recent attempts of one source.
#[derive(Debug, Clone, Copy)]
struct FailureHistory {
    /// `fetched_at` of the newest journal row, successful or not.
    last_attempt_at: i64,
    /// Attempts that failed in a row, counted from the newest row backwards.
    consecutive_failures: u32,
}

/// Delay before retrying a source that has just failed `consecutive_failures`
/// times in a row.
fn failure_backoff_secs(consecutive_failures: u32) -> i64 {
    let exponent = consecutive_failures.min(16) as i64;
    FAILURE_BACKOFF_BASE_SECS
        .saturating_mul(1i64 << exponent)
        .min(FAILURE_BACKOFF_MAX_SECS)
}

/// Whether a source is due for a fetch at `now`: its ordinary TTL cadence,
/// and, when its last attempt failed, only once the backoff has elapsed.
///
/// The TTL check alone is not enough. `last_fetched_at` is documented as the
/// last *successful* fetch and a failure leaves it NULL, so a source that
/// never worked (or whose feed broke) is due on every single sweep: one
/// upstream request per [`SWEEP_INTERVAL`] for the whole lifetime of the
/// deployment. A source that once succeeded is no better off: the old
/// stamp stays, and `now - ts >= ttl` keeps holding once it expires.
fn is_due(source: &Source, now: i64, history: Option<&FailureHistory>) -> bool {
    let ttl_due = match source.last_fetched_at {
        None => true,
        Some(ts) => now.saturating_sub(ts) >= source.cache_ttl_seconds,
    };
    if !ttl_due {
        return false;
    }
    let Some(history) = history else {
        return true;
    };
    if history.consecutive_failures == 0 {
        return true;
    }
    // An admin edit lands in `updated_at` (a failed fetch leaves it alone),
    // so a source whose configuration was just corrected is retried without
    // waiting out a backoff earned by the old configuration.
    if source.updated_at > history.last_attempt_at {
        return true;
    }
    now.saturating_sub(history.last_attempt_at)
        >= failure_backoff_secs(history.consecutive_failures)
}

/// Read the recent attempts of one source, or `None` when the journal holds
/// nothing for it (never fetched, or every row was purged by retention):
/// the caller then falls back to the plain TTL cadence.
async fn failure_history(pool: &DbPool, source_id: &str) -> Option<FailureHistory> {
    let rows = fetch_log::recent_for_source(pool, source_id, FAILURE_HISTORY_ROWS)
        .await
        .ok()?;
    let newest = rows.first()?;
    let consecutive_failures = rows.iter().take_while(|row| row.ok == 0).count() as u32;
    Some(FailureHistory {
        last_attempt_at: newest.fetched_at,
        consecutive_failures,
    })
}

/// Shared scheduler state: the concurrency semaphore and the set of
/// currently fetching source ids.
#[derive(Clone)]
pub struct SchedulerState {
    semaphore: Arc<Semaphore>,
    in_flight: Arc<Mutex<HashSet<String>>>,
}

impl SchedulerState {
    pub fn new(max_concurrency: usize) -> Self {
        Self {
            semaphore: Arc::new(Semaphore::new(max_concurrency.max(1))),
            in_flight: Arc::new(Mutex::new(HashSet::new())),
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
            guard.insert(source_id.to_string())
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
    /// the semaphore. The SSE stream carries the narrower signal —
    /// `fetch.queued` at spawn, `fetch.started` once a request can actually
    /// go out.
    pub async fn is_in_flight(&self, source_id: &str) -> bool {
        self.in_flight.lock().await.contains(source_id)
    }

    /// Source ids currently marked in flight. The shutdown path names
    /// them in the log: their tasks are detached, so whatever is still
    /// here when `main` returns is dropped by runtime teardown, and a
    /// bare "shutdown complete" would hide that.
    pub async fn in_flight_ids(&self) -> Vec<String> {
        self.in_flight.lock().await.iter().cloned().collect()
    }
}

/// Clears the in-flight mark of one source when dropped, including while a
/// panic unwinds the ingest task.
struct InFlightGuard {
    in_flight: Arc<Mutex<HashSet<String>>>,
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
}

/// Resets the sweep-overlap flag when the detached sweep task ends, on
/// the normal path and on unwind alike. A panic inside `sweep` would
/// otherwise strand `sweeping == true` and silently stop all future
/// sweeps.
struct SweepGuard(Arc<AtomicBool>);

impl Drop for SweepGuard {
    fn drop(&mut self) {
        self.0.store(false, Ordering::SeqCst);
    }
}

/// Retention windows the scheduler enforces itself, read once at startup.
///
/// The probe daemon runs the full retention loop, but the two binaries are
/// independent and a server-only deployment — a state the architecture
/// explicitly allows, the panel warning about a missing daemon rather than
/// refusing to work — writes a `fetch_log` row per fetch attempt and
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
    /// `[probe].retention_interval_secs`: how often the sweep runs.
    interval_secs: u64,
}

impl Default for ServerRetention {
    fn default() -> Self {
        // The built-in defaults, so a failed config re-read below still
        // bounds the tables instead of leaving them unbounded.
        let probe = fumox_core::config::ProbeConfig::default();
        Self {
            fetch_log_days: fumox_core::config::RetentionConfig::default().fetch_log_days,
            queue_stale_days: probe.queue_stale_days,
            interval_secs: probe.retention_interval_secs,
        }
    }
}

/// The config file the process was started with, recovered from the process
/// arguments. The scheduler re-reads the retention windows itself (its
/// caller passes it no config), and the `--config`/`-c` flag is the one
/// config pointer that exists only on the command line: without this scan a
/// deployment started with `--config /etc/fumox/app.toml` would get its
/// retention windows from `FUMOX_CONFIG` or the default location instead.
/// `fumox_core::config::load` re-applies the rest of the documented
/// precedence (`FUMOX_CONFIG`, then the default location) on its own.
fn cli_config_path() -> Option<std::path::PathBuf> {
    config_path_from_args(std::env::args_os().skip(1))
}

/// The pure half of [`cli_config_path`], split out so the flag spellings
/// are testable without touching process state. Mirrors clap's two forms
/// for the server binary's only path flag: `--config <path>` / `-c <path>`
/// and `--config=<path>`.
fn config_path_from_args<I>(args: I) -> Option<std::path::PathBuf>
where
    I: IntoIterator,
    I::Item: Into<std::ffi::OsString>,
{
    let mut args = args.into_iter().map(Into::into);
    while let Some(arg) = args.next() {
        let arg = arg.to_string_lossy();
        if let Some(value) = arg.strip_prefix("--config=") {
            return Some(std::path::PathBuf::from(value));
        }
        if arg == "--config" || arg == "-c" {
            return args.next().map(std::path::PathBuf::from);
        }
    }
    None
}

/// Read the retention windows the scheduler enforces from the same config
/// the process booted with. A failed re-read (the file vanished or was made
/// invalid since startup) falls back to the built-in defaults with a
/// warning: bounded tables on the default windows beat an unswept journal.
fn load_server_retention() -> ServerRetention {
    let path = cli_config_path();
    match fumox_core::config::load(path.as_deref()) {
        Ok(loaded) => ServerRetention {
            fetch_log_days: loaded.config.retention.fetch_log_days,
            queue_stale_days: loaded.config.probe.queue_stale_days,
            interval_secs: loaded.config.probe.retention_interval_secs,
        },
        Err(error) => {
            tracing::warn!(
                error = %error,
                "scheduler: cannot re-read the config for the retention windows; \
                 using the built-in defaults"
            );
            ServerRetention::default()
        }
    }
}

/// One server-side retention pass: `fetch_log` and `probe_requests` older
/// than the configured windows, plus queue rows whose proxy already left
/// the `unknown` state. The server-side mirror of the probe daemon's
/// retention loop for the two tables the server itself writes.
async fn retention_sweep(pool: &DbPool, retention: &ServerRetention) {
    let now = fumox_core::models::now_ts();
    // A zero window would wipe the whole table on every pass; the same
    // clamp the daemon's `retention_cutoff` applies.
    let fetch_cutoff = now - i64::from(retention.fetch_log_days.max(1)) * 86_400;
    let queue_cutoff = now - retention.queue_stale_days.max(1) as i64 * 86_400;

    let mut deleted_fetch_log = 0u64;
    let mut deleted_requests = 0u64;
    match fetch_log::purge_before(pool, fetch_cutoff).await {
        Ok(0) => {}
        Ok(deleted) => {
            deleted_fetch_log = deleted;
            tracing::info!(deleted, "server retention: rotated fetch_log");
        }
        Err(error) => tracing::warn!(error = %error, "server retention: fetch_log rotation failed"),
    }
    // Priority-queue housekeeping, same as the daemon: rows whose proxy no
    // longer needs the priority lane, and stale leftovers from a probe
    // that is offline — or absent.
    match probe::purge_settled_checks(pool).await {
        Ok(0) => {}
        Ok(deleted) => {
            deleted_requests += deleted;
            tracing::debug!(deleted, "server retention: dropped settled probe_requests")
        }
        Err(error) => {
            tracing::warn!(error = %error, "server retention: probe_requests cleanup failed")
        }
    }
    match probe::purge_requests_before(pool, queue_cutoff).await {
        Ok(0) => {}
        Ok(deleted) => {
            deleted_requests += deleted;
            tracing::info!(deleted, "server retention: rotated stale probe_requests");
        }
        Err(error) => {
            tracing::warn!(error = %error, "server retention: probe_requests rotation failed")
        }
    }
    // Stamp the run so /admin/probe surfaces it even without the daemon:
    // the stamp means "a retention pass ran recently", whoever ran it.
    let stamp = probe::meta::LastRotation {
        ts: now,
        probe_results: 0,
        fetch_log: deleted_fetch_log,
        probe_requests: deleted_requests,
    };
    if let Err(error) = fumox_core::repo::meta_set(
        pool,
        probe::meta::LAST_ROTATION_KEY,
        &serde_json::to_string(&stamp).expect("meta payload holds only JSON-native fields"),
    )
    .await
    {
        tracing::debug!(error = %error, "server retention: cannot stamp last_rotation");
    }
}

/// Run the scheduler until the process shuts down.
///
/// `refresh_rx` carries source ids that must be refreshed immediately
/// (admin *Refresh now*).
pub async fn run(
    env: IngestEnv,
    state: SchedulerState,
    events: EventBus,
    mut refresh_rx: tokio::sync::mpsc::UnboundedReceiver<String>,
) {
    // Server-side journal retention on its own cadence (see
    // [`retention_sweep`]). The first tick of a tokio interval is
    // immediate, matching the daemon's run-at-startup, so a server-only
    // deployment sheds an accumulated backlog at boot; running it in this
    // select loop ties the sweep's lifetime to the scheduler's, and the
    // bounded deletes cost the refresh channel a moment at most.
    let retention = load_server_retention();
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
    // A sweep drains its whole JoinSet, so a slow source would otherwise
    // hold the loop for the length of that fetch and park a *Refresh now*
    // behind it: the refresh would not even be marked in flight, and the
    // status fragment the panel polls would report the previous fetch as
    // the finished one. The sweep therefore runs detached, and this flag
    // keeps two sweeps from overlapping.
    let sweeping = Arc::new(AtomicBool::new(false));
    loop {
        tokio::select! {
            _ = tick.tick() => {
                if sweeping.swap(true, Ordering::SeqCst) {
                    tracing::debug!("scheduler sweep still running; skipping this tick");
                    continue;
                }
                let env = env.clone();
                let state = state.clone();
                let events = events.clone();
                let sweeping_done = SweepGuard(sweeping.clone());
                tokio::spawn(async move {
                    let _guard = sweeping_done;
                    sweep(&env, &state, &events).await;
                });
            }
            _ = retention_tick.tick() => {
                retention_sweep(&env.pool, &retention).await;
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

/// Handle one *Refresh now* id from the admin panel: look the row up and spawn
/// the ingest. A stale panel id is a warning, a failed lookup an error naming
/// the source — a broken database must not masquerade as "unknown source".
async fn dispatch_refresh(
    env: &IngestEnv,
    state: &SchedulerState,
    events: &EventBus,
    source_id: &str,
) {
    match sources::get(&env.pool, source_id).await {
        // Explicit "refresh now": always hit the network.
        Ok(Some(source)) => {
            spawn_ingest(env, state, events, source, true);
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
            let mut due = Vec::new();
            for source in all {
                // The journal is only consulted for a source whose recorded
                // verdict says the last attempt failed; a healthy one keeps
                // the plain TTL check and pays no extra query.
                let history = if source.error_class.is_some() {
                    failure_history(&env.pool, &source.id).await
                } else {
                    None
                };
                if is_due(&source, now, history.as_ref()) {
                    due.push(source);
                } else if let Some(history) = history {
                    tracing::debug!(
                        source = %source.id,
                        consecutive_failures = history.consecutive_failures,
                        "scheduler sweep: backing off a failing source"
                    );
                }
            }
            due
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
        if let Some(handle) = spawn_ingest(env, state, events, source, false) {
            // The id travels with the handle so a JoinError (a panic in
            // the ingest task) names the source that died instead of
            // vanishing into `is_some()`.
            tasks.spawn(async move { (source_id, handle.await) });
        }
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

/// Spawn one ingestion task if the source is not already in flight.
/// Returns the join handle, or `None` when skipped.
///
/// Event order: `fetch.queued` at spawn (the in-flight mark is held from
/// here on, so duplicates are dropped), `fetch.started` once a concurrency
/// permit is in hand and the fetch can actually go out, then the outcome
/// event. Under `[fetch].max_concurrency` saturation the queued window can
/// span many sweeps, and the panel's "fetching" notion must not start
/// before any request is made.
fn spawn_ingest(
    env: &IngestEnv,
    state: &SchedulerState,
    events: &EventBus,
    source: Source,
    force: bool,
) -> Option<tokio::task::JoinHandle<()>> {
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
        } = env;
        let Some(in_flight) = state.acquire_source(&source_id).await else {
            tracing::debug!(source = %source_id, "source already fetching; skipping");
            return;
        };
        // Queued, not started: under `[fetch].max_concurrency` saturation a
        // task can sit on the semaphore for a long while before any request
        // is made, and the panel's notion of "fetching" must not include
        // that wait. `fetch.started` therefore fires only once a permit is
        // in hand; `fetch.queued` announces the pending refresh in between
        // (the SSE stream forwards every event, the browser reacts to the
        // names it knows).
        events.publish(
            "fetch.queued",
            serde_json::json!({ "source_id": source_id }),
        );
        let permit = match state.semaphore.clone().acquire_owned().await {
            Ok(permit) => permit,
            Err(_) => return, // semaphore closed during shutdown
        };
        events.publish(
            "fetch.started",
            serde_json::json!({ "source_id": source_id }),
        );
        let outcome =
            ingest::ingest_source(&pool, &fetcher, &caches, &geo, settings, &source, force).await;
        drop(permit);
        drop(in_flight);
        match outcome {
            ingest::IngestOutcome::Ok {
                proxies_found,
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
                    "fetch.done",
                    serde_json::json!({
                        "source_id": source_id,
                        "ok": true,
                        "proxies_found": proxies_found,
                        "duration_ms": duration_ms,
                    }),
                );
                tracing::info!(
                    source = %source_id,
                    proxies_found,
                    inserted = stats.inserted,
                    updated = stats.updated,
                    removed = stats.removed,
                    duration_ms,
                    "source ingested"
                );
            }
            ingest::IngestOutcome::FetchFailed {
                failure,
                duration_ms,
            } => {
                let class = failure.error_class();
                events.publish(
                    "fetch.failed",
                    serde_json::json!({
                        "source_id": source_id,
                        "ok": false,
                        "error_class": class.as_str(),
                        "duration_ms": duration_ms,
                    }),
                );
                tracing::warn!(
                    source = %source_id,
                    error = %failure,
                    duration_ms,
                    "source fetch failed"
                );
            }
            ingest::IngestOutcome::ParseFailed {
                message,
                duration_ms,
            } => {
                events.publish(
                    "fetch.failed",
                    serde_json::json!({
                        "source_id": source_id,
                        "ok": false,
                        "error_class": "parse_error",
                        "duration_ms": duration_ms,
                    }),
                );
                tracing::warn!(
                    source = %source_id,
                    error = %message,
                    duration_ms,
                    "source parse failed"
                );
            }
        }
    };
    Some(tokio::spawn(fut))
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
            ..Default::default()
        };
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
        };
        let events = EventBus::new();
        let mut rx = events.subscribe();
        let (refresh_tx, refresh_rx) = tokio::sync::mpsc::unbounded_channel();
        let scheduler = tokio::spawn(run(env, SchedulerState::new(2), events.clone(), refresh_rx));

        // The first interval tick is immediate, the sweep starts the slow
        // source and stays on it.
        await_fetch_started(&mut rx, "srcSlow0000").await;

        // A refresh arriving mid-sweep must be picked up right away.
        refresh_tx.send("srcFast0000".to_string()).unwrap();
        await_fetch_started(&mut rx, "srcFast0000").await;
        scheduler.abort();
    }

    /// A database failure while looking up a *Refresh now* target must be logged
    /// as an error naming the source, not folded into the "unknown source" warning.
    #[tokio::test]
    async fn refresh_lookup_failure_is_logged_as_an_error() {
        let pool = test_pool().await;
        let (env, state, events) = test_env(pool.clone()).await;
        // The only way to reach the `Err` arm deterministically: a pool
        // that answers nothing anymore.
        env.pool.close().await;

        // A writer funneling the subscriber's output into a shared buffer
        // (same trick as `fumox_core::logging`). The filter only lets ERROR
        // through, so any output at all proves the failure was logged as an error.
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
            .with_max_level(tracing::Level::ERROR)
            .with_writer(move || Captured(Arc::clone(&make_writer)))
            .finish();
        let _guard = tracing::subscriber::set_default(subscriber);
        // Same call-site-interest caveat as the auth logging test: a call
        // site first executed under another test's empty dispatcher caches
        // as `never` for the whole process. Pin the registry to
        // multi-dispatcher and re-evaluate, so the lines this test asserts
        // on are observable through the subscriber above.
        crate::admin::stabilize_callsite_interests();
        tracing::callsite::rebuild_interest_cache();

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

    async fn test_env(pool: DbPool) -> (IngestEnv, SchedulerState, EventBus) {
        let fetch_config = FetchConfig {
            read_timeout_secs: 10,
            connect_timeout_secs: 5,
            // A 401 is not recoverable, the fetch policy must not mask the
            // scheduler's own cadence with its retries.
            max_retries: 0,
            ..Default::default()
        };
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
        };
        (env, SchedulerState::new(4), EventBus::new())
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
        let (env, state, events) = test_env(pool.clone()).await;

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

    /// The `--config`/`-c` flag is the one config pointer that exists only
    /// on the command line, and the scheduler re-reads the retention
    /// windows from the config itself: the flag spellings must be
    /// recovered exactly, everything else is left to `config::load`.
    #[test]
    fn cli_config_flag_is_recovered_from_process_arguments() {
        assert_eq!(
            config_path_from_args(["fumox-server", "--config", "/etc/fumox/app.toml"]),
            Some(std::path::PathBuf::from("/etc/fumox/app.toml"))
        );
        assert_eq!(
            config_path_from_args(["fumox-server", "-c", "app.toml"]),
            Some(std::path::PathBuf::from("app.toml"))
        );
        assert_eq!(
            config_path_from_args(["fumox-server", "--config=app.toml"]),
            Some(std::path::PathBuf::from("app.toml"))
        );
        assert_eq!(config_path_from_args(["fumox-server"]), None);
        assert_eq!(
            config_path_from_args(["fumox-server", "--health-check"]),
            None
        );
        assert_eq!(
            config_path_from_args(Vec::<std::ffi::OsString>::new()),
            None
        );
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

        let stamp = fumox_core::repo::meta_get(&pool, probe::meta::LAST_ROTATION_KEY)
            .await
            .unwrap()
            .expect("the sweep stamps its run");
        let stamp: probe::meta::LastRotation = serde_json::from_str(&stamp).unwrap();
        assert_eq!(stamp.fetch_log, 1);
        assert_eq!(stamp.probe_requests, 2);
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
            .processed_put(
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
    /// condition are pinned here — a regression that flips the condition
    /// or misreads the stats now fails instead of passing silently.
    #[tokio::test]
    async fn a_data_changing_ingest_drops_renderings_and_a_quiet_one_keeps_them() {
        let (addr, hits) =
            ok_upstream("vless://11111111-1111-1111-1111-111111111111@1.2.3.4:443#A\n").await;
        let pool = test_pool().await;
        let source = test_source("srcCache000", format!("http://{addr}/sub"), 3600, None);
        sources::create(&pool, &source).await.unwrap();
        let (env, state, events) = test_env(pool.clone()).await;
        let key = "sub:profCache0";

        // Changed rows: the first reconcile inserts the proxy.
        seed_rendering(&env.caches, key, &source.id).await;
        spawn_ingest(&env, &state, &events, source.clone(), false)
            .expect("the first spawn acquires the in-flight mark")
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
            .expect("spawn succeeds")
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
        let (env, _idle_state, events) = test_env(pool).await;
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
        )
        .expect("the first spawn acquires the in-flight mark");

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
        .expect("the duplicate spawn returns a task")
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
}
