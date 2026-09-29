//! Background source refresh loop.
//!
//! Every sweep (30 s) the scheduler picks enabled sources whose
//! `cache_ttl_seconds` has elapsed since `last_fetched_at` and ingests them
//! concurrently, bounded by a semaphore (`[fetch].max_concurrency`).
//! The admin panel can request an immediate refresh through the mpsc
//! channel; a per-source in-flight guard prevents duplicate fetches
//!.

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
use std::sync::atomic::{AtomicBool, Ordering};
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
/// (admin *Refresh now*).
pub async fn run(
    env: IngestEnv,
    state: SchedulerState,
    events: EventBus,
    mut refresh_rx: tokio::sync::mpsc::UnboundedReceiver<String>,
) {
    let mut tick = tokio::time::interval(SWEEP_INTERVAL);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    // A sweep drains its whole JoinSet, so a slow source would otherwise
    // hold the loop for the length of that fetch and park a *Refresh now*
    // behind it — the refresh would not even be marked in flight, and the
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
                let sweeping_done = sweeping.clone();
                tokio::spawn(async move {
                    sweep(&env, &state, &events).await;
                    sweeping_done.store(false, Ordering::SeqCst);
                });
            }
            maybe_id = refresh_rx.recv() => {
                let Some(source_id) = maybe_id else {
                    break; // channel closed, shutting down
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
    use crate::events::Event;
    use fumox_core::config::{DatabaseConfig, FetchConfig, GeoConfig};
    use fumox_core::geo::GeoResolver;
    use fumox_core::models::Source;
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
}
