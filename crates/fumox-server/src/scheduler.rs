//! Background source refresh loop.
//!
//! Every sweep (30 s) the scheduler picks enabled sources whose
//! `cache_ttl_seconds` has elapsed since `last_fetched_at` and ingests them
//! concurrently, bounded by a semaphore (`[fetch].max_concurrency`).
//! The admin panel can request an immediate refresh through the mpsc
//! channel; a per-source in-flight guard prevents duplicate fetches
//! (ADMIN_PLAN §5).

use crate::cache::Caches;
use crate::events::EventBus;
use crate::fetcher::Fetcher;
use crate::ingest;
use fumox_core::db::DbPool;
use fumox_core::geo::GeoResolver;
use fumox_core::models::Source;
use fumox_core::repo::sources;
use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{Mutex, Semaphore};
use tokio::task::JoinSet;

/// How often the scheduler looks for sources due for a refresh.
const SWEEP_INTERVAL: Duration = Duration::from_secs(30);

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
    /// unwind past the release and pin the id in `in_flight` forever — that
    /// source could never be refreshed again until a restart, and the
    /// `JoinSet` sweep swallows the `JoinError` silently (security audit,
    /// 2026-09-05).
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

    /// Whether a source is currently being fetched (admin status fragment).
    pub async fn is_in_flight(&self, source_id: &str) -> bool {
        self.in_flight.lock().await.contains(source_id)
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

/// Run the scheduler until the process shuts down.
///
/// `refresh_rx` carries source ids that must be refreshed immediately
/// ("обновить сейчас" from the admin panel).
pub async fn run(
    env: IngestEnv,
    state: SchedulerState,
    events: EventBus,
    mut refresh_rx: tokio::sync::mpsc::UnboundedReceiver<String>,
) {
    let mut tick = tokio::time::interval(SWEEP_INTERVAL);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            _ = tick.tick() => {
                sweep(&env, &state, &events).await;
            }
            maybe_id = refresh_rx.recv() => {
                let Some(source_id) = maybe_id else {
                    break; // channel closed — shutting down
                };
                if let Ok(Some(source)) = sources::get(&env.pool, &source_id).await {
                    // Explicit "refresh now": always hit the network.
                    spawn_ingest(&env, &state, &events, source, true);
                } else {
                    tracing::warn!(source = %source_id, "refresh requested for unknown source");
                }
            }
        }
    }
}

/// One scheduler sweep: ingest every enabled source that is due.
async fn sweep(env: &IngestEnv, state: &SchedulerState, events: &EventBus) {
    let due = match sources::list(&env.pool, true).await {
        Ok(all) => {
            let now = fumox_core::models::now_ts();
            all.into_iter()
                .filter(|source| match source.last_fetched_at {
                    None => true,
                    Some(ts) => now.saturating_sub(ts) >= source.cache_ttl_seconds,
                })
                .collect::<Vec<_>>()
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
        if let Some(handle) = spawn_ingest(env, state, events, source, false) {
            tasks.spawn(handle);
        }
    }
    while tasks.join_next().await.is_some() {}
}

/// Spawn one ingestion task if the source is not already in flight.
/// Returns the join handle, or `None` when skipped.
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
        events.publish(
            "fetch.started",
            serde_json::json!({ "source_id": source_id }),
        );
        let permit = match state.semaphore.clone().acquire_owned().await {
            Ok(permit) => permit,
            Err(_) => return, // semaphore closed during shutdown
        };
        let outcome =
            ingest::ingest_source(&pool, &fetcher, &caches, &geo, settings, &source, force).await;
        drop(permit);
        drop(in_flight);
        match outcome {
            ingest::IngestOutcome::Ok {
                proxies_found,
                stats,
            } => {
                // New/changed/removed rows → every rendered output containing
                // this source is stale. Drop them now so clients see the fresh
                // data immediately instead of waiting out the processed TTL
                // (SPEC §7). When nothing changed the renderings stay valid.
                if stats.inserted + stats.updated + stats.removed > 0 {
                    caches.invalidate_processed_for_source(&source_id).await;
                }
                events.publish(
                    "fetch.done",
                    serde_json::json!({
                        "source_id": source_id,
                        "ok": true,
                        "proxies_found": proxies_found,
                    }),
                );
                tracing::info!(
                    source = %source_id,
                    proxies_found,
                    inserted = stats.inserted,
                    updated = stats.updated,
                    removed = stats.removed,
                    "source ingested"
                );
            }
            ingest::IngestOutcome::FetchFailed { failure } => {
                let class = failure.error_class();
                events.publish(
                    "fetch.failed",
                    serde_json::json!({
                        "source_id": source_id,
                        "ok": false,
                        "error_class": class.as_str(),
                    }),
                );
                tracing::warn!(source = %source_id, error = %failure, "source fetch failed");
            }
            ingest::IngestOutcome::ParseFailed { message } => {
                events.publish(
                    "fetch.failed",
                    serde_json::json!({
                        "source_id": source_id,
                        "ok": false,
                        "error_class": "parse_error",
                    }),
                );
                tracing::warn!(source = %source_id, error = %message, "source parse failed");
            }
        }
    };
    Some(tokio::spawn(fut))
}

#[cfg(test)]
mod tests {
    use super::*;

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
    /// forever (security audit, 2026-09-05).
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
}
