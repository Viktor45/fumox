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

    /// Try to mark a source as in-flight; `false` when it already is.
    async fn acquire_source(&self, source_id: &str) -> bool {
        let mut guard = self.in_flight.lock().await;
        guard.insert(source_id.to_string())
    }

    async fn release_source(&self, source_id: &str) {
        self.in_flight.lock().await.remove(source_id);
    }

    /// Whether a source is currently being fetched (admin status fragment).
    pub async fn is_in_flight(&self, source_id: &str) -> bool {
        self.in_flight.lock().await.contains(source_id)
    }
}

/// Shared resources every ingestion task needs; cheap to clone per task.
#[derive(Clone)]
pub struct IngestEnv {
    pub pool: DbPool,
    pub fetcher: Fetcher,
    pub caches: Caches,
    pub geo: Arc<GeoResolver>,
    /// `[probe].refresh_check_limit`: how many newly inserted proxies per
    /// refresh are enqueued for priority probing (0 disables the queue).
    pub refresh_check_limit: u32,
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
            refresh_check_limit,
        } = env;
        if !state.acquire_source(&source_id).await {
            tracing::debug!(source = %source_id, "source already fetching; skipping");
            return;
        }
        events.publish(
            "fetch.started",
            serde_json::json!({ "source_id": source_id }),
        );
        let permit = match state.semaphore.clone().acquire_owned().await {
            Ok(permit) => permit,
            Err(_) => return, // semaphore closed during shutdown
        };
        let outcome = ingest::ingest_source(
            &pool,
            &fetcher,
            &caches,
            &geo,
            refresh_check_limit,
            &source,
            force,
        )
        .await;
        drop(permit);
        state.release_source(&source_id).await;
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
        assert!(state.acquire_source("src1").await);
        assert!(!state.acquire_source("src1").await);
        assert!(state.acquire_source("src2").await);
        state.release_source("src1").await;
        assert!(state.acquire_source("src1").await);
    }
}
