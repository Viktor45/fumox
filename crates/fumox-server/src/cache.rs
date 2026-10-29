//! In-memory cache layer.
//!
//! Acceleration only, SQLite stays the source of truth:
//!
//! **Processed cache**, the rendered subscription output per endpoint
//! key (`sub:{profile_id}` / `src:{source_id}`). Entries carry their
//! own `fresh_until`; a stale entry is still served
//! (stale-while-revalidate) while a background re-render is scheduled.
//!
//! The layer is bounded by *bytes*, not by entry count: one rendered
//! subscription is megabytes, so a count-based ceiling of ten thousand
//! entries is a multi-gigabyte ceiling in practice. The weigher charges
//! every entry its body plus a fixed overhead, so the entry count is
//! bounded too.
//!
//! Freshness of the *underlying data* is not cached at all: it is derived
//! from `sources.last_fetched_at`, the same row the ingest's TTL
//! short-circuit reads (see `ingest::ingest_source`), so the fact "when was
//! this payload fetched" has exactly one home.
//!
//! Only 200 responses are cached; 404/500 must stay fresh.
//! Invalidation happens in the same handler that saves the
//! change: a source change clears every processed entry that contains the
//! source; a profile change clears its processed entry. A successful ingest
//! that reconciled new data clears every processed entry containing the
//! source, so clients see fresh proxies without waiting out the TTL.
//!
//! Every invalidation also bumps that key's generation. A render, the
//! background one of a stale entry or the inline one of a cache miss alike,
//! reads the generation when it starts and its result is dropped when the
//! generation moved meanwhile: that rendering was computed from pre-change
//! rows and must not be stored with a full fresh TTL behind the change that
//! invalidated it. A key with no entry yet (the inline path) is registered
//! with the cache layer for the duration of its render precisely so that
//! invalidations can see it.
//!
//! The generations live outside the evictable cache, in a plain map that
//! is never pruned: a generation that the cache dropped would let a render
//! claimed before the invalidation store its pre-change rows as fresh. The
//! map is bounded by the number of distinct keys the process ever used
//! (one per profile and per source), not by the cache's capacity.
//!
//! Which keys a source touches is answered by a reverse index, not by a
//! scan over the whole cache: the index names the keys a rendering was
//! built from, so an invalidation touches exactly those.

use axum::body::Bytes;
use fumox_core::db::DbPool;
use moka::future::Cache;
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::{Duration, Instant};
use tokio::sync::{Mutex, watch};

/// Safety net so abandoned entries eventually leave the caches even without
/// explicit invalidation (e.g. a deleted source).
const ENTRY_IDLE_LIMIT: Duration = Duration::from_secs(24 * 60 * 60);

/// How long the verdict of a failed inline render stays available for the
/// requests that arrive right after it. They answer from it instead of
/// running the same failing render again: a broken upstream has to cost
/// one render per window, not one render per request. The verdict expires
/// on its own, so a recovered upstream is picked up again.
const FAILED_RENDER_TTL: Duration = Duration::from_secs(5);

/// Memory ceiling of the processed layer, in bytes. One rendered
/// subscription body is megabytes, so the ceiling has to be a byte
/// budget: an entry count would bound nothing.
const PROCESSED_CACHE_BYTES: u64 = 64 * 1024 * 1024;

/// Bytes every entry is charged on top of its body: the key, the extra
/// headers, the source list and the cache bookkeeping. Without it a cache
/// full of tiny bodies would weigh almost nothing and the entry count
/// would be unbounded.
const ENTRY_OVERHEAD_BYTES: u32 = 512;

/// Rendered subscription output (layer 2).
#[derive(Debug)]
pub struct Rendered {
    pub status: u16,
    /// Shared byte body: concurrent responses of one cached rendering clone
    /// a refcount, not the multi-MB payload.
    pub body: Bytes,
    pub content_type: String,
    /// Response headers beyond status/content-type: `profile-title`,
    /// `profile-update-interval`, `X-Fumox-Stale`, `X-Fumox-Warning`.
    pub extra_headers: Vec<(String, String)>,
    /// Unix timestamp until which the entry is considered fresh.
    pub fresh_until: i64,
    /// Sources whose content went into this rendering; used for targeted
    /// invalidation when one of them changes or is re-ingested.
    pub source_ids: Vec<String>,
}

impl Rendered {
    pub fn is_fresh(&self, now: i64) -> bool {
        now < self.fresh_until
    }
}

/// Shared cache handle (cheap to clone, used by serving and admin handlers).
#[derive(Clone)]
pub struct Caches {
    processed: Cache<String, Arc<Rendered>>,
    /// Invalidation counter per processed key, bumped on every invalidation
    /// of that key. Deliberately outside the evictable cache: a generation
    /// the cache dropped would let a render claimed before the invalidation
    /// store its pre-change rows as fresh.
    generations: Arc<StdMutex<HashMap<String, u64>>>,
    /// Which sources a processed key was rendered from, and the other way
    /// round. The index answers an invalidation without a scan over the
    /// whole cache.
    index: Arc<StdMutex<SourceIndex>>,
    /// Processed keys currently being revalidated in the background, keeps
    /// concurrent stale requests from spawning duplicate re-renders.
    revalidating: Arc<Mutex<HashSet<String>>>,
    /// Processed keys currently being rendered inline (the cache-miss path),
    /// mapped to the render's scope: the sources it draws from plus a
    /// wait-channel that wakes the requests which arrived while it runs. Such
    /// a key has no entry yet, so it is invisible to the iteration in
    /// [`Caches::invalidate_processed_for_source`]; the claim is what lets an
    /// invalidation supersede a render that is still running. The source set
    /// keeps that supersession narrow: an ingest of a source this render
    /// cannot touch must not refuse its put.
    inline_rendering: Arc<Mutex<HashMap<String, InlineRenderState>>>,
}

/// Which processed key holds which sources, and the other way round.
///
/// The index is a record of what was rendered, not of what is cached: a
/// key that was invalidated (or evicted by the cache's byte budget) stays
/// in it. Invalidating a key that is no longer cached is a no-op, and
/// dropping the record on the way out would race with a render that
/// stores the same key right afterwards.
#[derive(Default)]
struct SourceIndex {
    /// source id -> the processed keys rendered from it.
    by_source: HashMap<String, HashSet<String>>,
    /// processed key -> the sources it was rendered from.
    by_key: HashMap<String, Vec<String>>,
}

impl SourceIndex {
    /// Record that `key` was rendered from `sources`.
    fn add(&mut self, key: &str, sources: &[String]) {
        if sources.is_empty() {
            return;
        }
        for source in sources {
            self.by_source
                .entry(source.clone())
                .or_default()
                .insert(key.to_string());
        }
        self.by_key.insert(key.to_string(), sources.to_vec());
    }

    /// The processed keys rendered from `source`.
    fn keys_for_source(&self, source: &str) -> Vec<String> {
        self.by_source
            .get(source)
            .map(|keys| keys.iter().cloned().collect())
            .unwrap_or_default()
    }
}

/// Bytes one cache entry costs: its body plus the per-entry overhead.
fn entry_weight(key: &str, rendered: &Rendered) -> u32 {
    let body = u32::try_from(rendered.body.len()).unwrap_or(u32::MAX);
    let key = u32::try_from(key.len()).unwrap_or(u32::MAX);
    body.saturating_add(key)
        .saturating_add(ENTRY_OVERHEAD_BYTES)
}

/// One in-flight inline (cache-miss) render.
struct InlineRenderState {
    /// The sources the render draws from; scopes the claim's invalidation
    /// reach.
    sources: HashSet<String>,
    /// Wake-up for requests that found the claim taken, carrying what the
    /// leader did. Dropping the entry (with the leader's guard) closes it
    /// and resolves every waiter's `changed()`; the last value outlives the
    /// close, so a waiter woken by the close still reads the verdict.
    done: watch::Sender<InlineOutcome>,
    /// When the leader's render failed. A failed render keeps its entry
    /// for [`FAILED_RENDER_TTL`], so the requests that arrive right after
    /// the failure answer from its verdict instead of running the same
    /// failing render again.
    failed_at: Option<Instant>,
}

/// What the leader of an inline render did, published to its waiters so a
/// failing render costs one attempt rather than one per waiter.
#[derive(Clone, Debug, Default)]
pub enum InlineOutcome {
    /// No failure published: the leader either stored an entry or stored
    /// none because an invalidation superseded its put. The waiter decides
    /// by looking at the cache, as it did before outcomes existed.
    #[default]
    Stored,
    /// The leader's render failed. Waiters answer from this instead of
    /// re-running a render that is already known to fail.
    Failed { status: u16, message: String },
}

/// Outcome of [`Caches::begin_inline_render`]: the caller either owns the
/// render, waits for the one already running, or repeats the verdict of a
/// render that just failed.
pub enum InlineClaim {
    /// No render of the key is in flight: the caller renders it and stores
    /// the result through the guard's generation.
    Leader(InlineRenderGuard),
    /// Another render of the key is in flight; awaiting `changed()` on the
    /// receiver resolves when that claim ends, including on unwind. The
    /// channel then carries what the leader did.
    Wait(watch::Receiver<InlineOutcome>),
    /// A render of this key failed a moment ago; its verdict is repeated
    /// instead of running the same failing render again.
    Failed { status: u16, message: String },
}

impl Caches {
    pub fn new() -> Self {
        Self {
            processed: Cache::builder()
                .max_capacity(PROCESSED_CACHE_BYTES)
                .weigher(|key: &String, value: &Arc<Rendered>| entry_weight(key, value))
                .time_to_idle(ENTRY_IDLE_LIMIT)
                .build(),
            generations: Arc::new(StdMutex::new(HashMap::new())),
            index: Arc::new(StdMutex::new(SourceIndex::default())),
            revalidating: Arc::new(Mutex::new(HashSet::new())),
            inline_rendering: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub async fn processed_get(&self, key: &str) -> Option<Arc<Rendered>> {
        self.processed.get(&key.to_string()).await
    }

    pub async fn processed_put(&self, key: &str, rendered: Rendered) -> Arc<Rendered> {
        let arc = Arc::new(rendered);
        self.store(key, arc.clone()).await;
        arc
    }

    /// Put a rendering into the cache and record the sources it was built
    /// from, so an invalidation of one of them finds the key.
    async fn store(&self, key: &str, rendered: Arc<Rendered>) {
        self.processed
            .insert(key.to_string(), rendered.clone())
            .await;
        self.index
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .add(key, &rendered.source_ids);
    }

    /// Store the result of a render that was claimed under `generation` (the
    /// value [`Caches::try_start_revalidate`] or
    /// [`Caches::begin_inline_render`] handed out). Returns the stored entry,
    /// or `None` when an invalidation superseded the rendering.
    ///
    /// A rendering whose generation moved in the meantime was computed from
    /// rows that an invalidation has already superseded: storing it with its
    /// own fresh TTL would serve pre-change data as fresh for a whole TTL,
    /// which is exactly what the invalidation was meant to end. Such a
    /// rendering is dropped instead, the key stays empty and the next
    /// request re-renders inline from the new rows.
    pub async fn processed_put_guarded(
        &self,
        key: &str,
        rendered: Arc<Rendered>,
        generation: u64,
    ) -> Option<Arc<Rendered>> {
        if self.generation(key) != generation {
            return None;
        }
        self.store(key, rendered).await;
        if self.generation(key) != generation {
            // An invalidation landed between the check and the insert and
            // therefore did not see this entry; drop it by hand.
            self.processed_invalidate(key).await;
            return None;
        }
        self.processed_get(key).await
    }

    /// Drop a rendered output and bump its generation, so a render still
    /// in flight for it cannot store behind the invalidation.
    pub async fn processed_invalidate(&self, key: &str) {
        self.bump_generation(key);
        self.processed.invalidate(&key.to_string()).await;
    }

    /// Current invalidation generation of a processed key; 0 = never
    /// invalidated.
    fn generation(&self, key: &str) -> u64 {
        self.generations
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .get(key)
            .copied()
            .unwrap_or(0)
    }

    /// Mark every rendering of `key` produced up to now as superseded.
    ///
    /// The read-modify-write runs under the map's own lock: two
    /// invalidations of the same key (two sources feeding one profile,
    /// ingesting at once) would otherwise read the same generation and
    /// both write G+1, losing a bump and letting a render claimed in
    /// between store pre-change rows as fresh.
    fn bump_generation(&self, key: &str) {
        let mut generations = self
            .generations
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let generation = generations.entry(key.to_string()).or_insert(0);
        *generation += 1;
    }

    /// Every rendered output that contains `source_id` is stale: dropped
    /// (and its generation bumped, superseding renders still in flight).
    /// Used both when a source's configuration changes (the admin save /
    /// toggle / delete) and when an ingest reconciled new rows into it, so
    /// clients see the new data immediately instead of waiting out the
    /// processed TTL. `sources.last_fetched_at`, the freshness marker of
    /// the underlying data, is of course untouched.
    pub async fn invalidate_processed_for_source(&self, source_id: &str) {
        // The index names the keys a rendering of this source produced,
        // so no scan over the whole cache is needed.
        let mut affected = self
            .index
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .keys_for_source(source_id);
        // A key with no entry yet, an inline (cache-miss) render of it
        // running right now, is invisible to the index. Its
        // rendering is still computed from the pre-ingest rows, so its
        // generation has to move too or the put would land behind this
        // invalidation (see [`Caches::processed_put_guarded`]). Only renders
        // that name this source are touched: an unrelated key's cold render
        // stays storable.
        let inline = self.inline_rendering.lock().await;
        affected.extend(
            inline
                .iter()
                .filter(|(_, state)| state.sources.iter().any(|id| id == source_id))
                .map(|(key, _)| key.clone()),
        );
        drop(inline);
        for key in affected {
            self.bump_generation(&key);
            self.processed.invalidate(&key).await;
        }
    }

    /// Profile changed (composition/format/pipeline/enabled): drop its
    /// rendered output.
    pub async fn invalidate_profile(&self, profile_id: &str) {
        self.processed_invalidate(&format!("sub:{profile_id}"))
            .await;
    }

    /// Claim the background revalidation of a key. Returns a guard that
    /// releases the claim on drop, or `None` when another task holds it.
    ///
    /// The guard releases through `Drop` because tokio mutexes do not poison:
    /// a panic in the background re-render used to unwind past the explicit
    /// release and pin the key in `revalidating` forever, so that endpoint
    /// served its stale snapshot and never re-rendered again.
    pub async fn try_start_revalidate(&self, key: &str) -> Option<RevalidateGuard> {
        let inserted = self.revalidating.lock().await.insert(key.to_string());
        if !inserted {
            return None;
        }
        // Read the generation before the caller starts the render, so any
        // invalidation from here on is visible to the put.
        let generation = self.generation(key);
        Some(RevalidateGuard {
            revalidating: self.revalidating.clone(),
            key: key.to_string(),
            generation,
        })
    }

    /// Whether a background re-render is currently claimed for `key`.
    #[cfg(test)]
    pub async fn is_revalidating(&self, key: &str) -> bool {
        self.revalidating.lock().await.contains(key)
    }

    /// Claim an inline render of a key the processed layer does not hold.
    /// The first caller becomes the [`InlineClaim::Leader`] and renders;
    /// every request arriving while that render runs gets an
    /// [`InlineClaim::Wait`] receiver that resolves when the leader's claim
    /// ends. A burst of requests on a cold key therefore runs one render
    /// instead of one per request, and no duplicate rendering is stored.
    ///
    /// The guard also keeps the key visible to
    /// [`Caches::invalidate_processed_for_source`]: without an entry there
    /// is nothing for that call to find, and the pre-change rendering would
    /// be stored as fresh for a full TTL behind the invalidation.
    ///
    /// `source_ids` are the sources the rendering can draw from; they scope
    /// the claim's reach, so an ingest of a source this render cannot touch
    /// leaves its put alone instead of starving the cache of valid fills. A
    /// superset is safe; an empty list is only for keys that never
    /// participate in per-source invalidation (the exports), elsewhere it
    /// makes the claim invisible to every invalidation.
    pub async fn begin_inline_render(&self, key: &str, source_ids: Vec<String>) -> InlineClaim {
        let mut map = self.inline_rendering.lock().await;
        let mut stale_verdict = false;
        if let Some(state) = map.get(key) {
            match state.failed_at {
                // A live render: wait for it.
                None => return InlineClaim::Wait(state.done.subscribe()),
                Some(failed_at) => {
                    let verdict = state.done.borrow().clone();
                    if failed_at.elapsed() < FAILED_RENDER_TTL
                        && let InlineOutcome::Failed { status, message } = verdict
                    {
                        // The render failed a moment ago: its verdict is
                        // the answer, a second render would fail the same
                        // way.
                        return InlineClaim::Failed { status, message };
                    }
                    // The verdict is stale: the key is free again.
                    stale_verdict = true;
                }
            }
        }
        if stale_verdict {
            map.remove(key);
        }
        let (done, _) = watch::channel(InlineOutcome::Stored);
        map.insert(
            key.to_string(),
            InlineRenderState {
                sources: source_ids.into_iter().collect(),
                done,
                failed_at: None,
            },
        );
        drop(map);
        InlineClaim::Leader(InlineRenderGuard {
            inline_rendering: self.inline_rendering.clone(),
            key: key.to_string(),
            generation: self.generation(key),
        })
    }
}

/// Releases one inline-render claim when dropped, including while a panic
/// unwinds the rendering task. The drop also removes the claim's entry, and
/// with it the wait-channel: every [`InlineClaim::Wait`] receiver resolves
/// at that moment.
pub struct InlineRenderGuard {
    inline_rendering: Arc<Mutex<HashMap<String, InlineRenderState>>>,
    key: String,
    /// Invalidation generation of the key at claim time; the rendering this
    /// claim covers may only be stored while it still holds.
    generation: u64,
}

impl InlineRenderGuard {
    /// Generation to hand back to [`Caches::processed_put_guarded`].
    pub fn generation(&self) -> u64 {
        self.generation
    }

    /// Publish a failed render to the claim's waiters, so they answer from
    /// it instead of each re-running a render that is known to fail. Call
    /// this before the guard drops.
    ///
    /// The claim keeps its entry for [`FAILED_RENDER_TTL`] afterwards: the
    /// requests that arrive right after the failure answer from the same
    /// verdict instead of running the same failing render again.
    ///
    /// Best-effort by design: the map lock is only ever held for a set
    /// insert or remove, so losing this race is close to impossible, and a
    /// waiter that misses the verdict simply falls back to claiming the
    /// render itself, which is what it did before outcomes existed.
    pub fn fail(&self, status: u16, message: String) {
        if let Ok(mut map) = self.inline_rendering.try_lock()
            && let Some(state) = map.get_mut(&self.key)
        {
            state.failed_at = Some(Instant::now());
            state
                .done
                .send_replace(InlineOutcome::Failed { status, message });
        }
    }
}

impl Drop for InlineRenderGuard {
    fn drop(&mut self) {
        // Same shape as `RevalidateGuard::drop`: `Drop` cannot await, the
        // lock is only ever held for a set insert/remove, so blocking on it
        // here cannot deadlock.
        let key = std::mem::take(&mut self.key);
        if let Ok(mut guard) = self.inline_rendering.try_lock() {
            // A failed render keeps its entry: the verdict stays available
            // for the requests that arrive right after it, so a broken
            // upstream costs one render per window and not one per
            // request.
            let failed = guard.get(&key).and_then(|state| state.failed_at).is_some();
            if !failed {
                guard.remove(&key);
            }
            return;
        }
        // Contended: hand the removal to the runtime rather than block.
        let inline_rendering = self.inline_rendering.clone();
        tokio::spawn(async move {
            inline_rendering.lock().await.remove(&key);
        });
    }
}

/// Releases one revalidation claim when dropped, including while a panic
/// unwinds the background render task.
pub struct RevalidateGuard {
    revalidating: Arc<Mutex<HashSet<String>>>,
    key: String,
    /// Invalidation generation of the key at claim time; the rendering this
    /// claim covers may only be stored while it still holds.
    generation: u64,
}

impl RevalidateGuard {
    /// Generation to hand back to [`Caches::processed_put_guarded`].
    pub fn generation(&self) -> u64 {
        self.generation
    }
}

impl Drop for RevalidateGuard {
    fn drop(&mut self) {
        // `Drop` cannot await; the lock is only ever held for a set
        // insert/remove, so blocking on it here cannot deadlock.
        let key = std::mem::take(&mut self.key);
        if let Ok(mut guard) = self.revalidating.try_lock() {
            guard.remove(&key);
            return;
        }
        // Contended: hand the removal to the runtime rather than block.
        let revalidating = self.revalidating.clone();
        tokio::spawn(async move {
            revalidating.lock().await.remove(&key);
        });
    }
}

impl Default for Caches {
    fn default() -> Self {
        Self::new()
    }
}

/// The two journal row counts, with the moment they were taken.
type JournalCountEntry = (Instant, (i64, i64));

/// Row counts of the two journals (`probe_results`, `fetch_log`),
/// cached for a minute.
///
/// The retention card compares the current sizes against the last
/// rotation stamp; two COUNT scans of a growing table on every panel
/// render are the most expensive reads on the probe page, and the card
/// does not need second-by-second fresh numbers.
#[derive(Clone)]
pub struct JournalCounts {
    ttl: Duration,
    inner: Arc<StdMutex<Option<JournalCountEntry>>>,
}

impl JournalCounts {
    pub fn new(ttl: Duration) -> Self {
        Self {
            ttl,
            inner: Arc::new(StdMutex::new(None)),
        }
    }

    /// The current counts, counted only when the cached ones expired.
    /// The two counts are independent scans, so they run in parallel.
    pub async fn get(&self, pool: &DbPool) -> anyhow::Result<(i64, i64)> {
        if let Some((at, counts)) = *self.inner.lock().expect("journal counts cache")
            && at.elapsed() < self.ttl
        {
            return Ok(counts);
        }
        let counts = tokio::try_join!(
            fumox_core::repo::probe::count_all(pool),
            fumox_core::repo::fetch_log::count_all(pool),
        )?;
        *self.inner.lock().expect("journal counts cache") = Some((Instant::now(), counts));
        Ok(counts)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rendered(fresh_until: i64, sources: &[&str]) -> Rendered {
        Rendered {
            status: 200,
            body: Bytes::new(),
            content_type: "text/plain".to_string(),
            extra_headers: Vec::new(),
            fresh_until,
            source_ids: sources.iter().map(|s| s.to_string()).collect(),
        }
    }

    /// Claim a cold render, expecting to be its single-flight leader.
    async fn claim_inline(caches: &Caches, key: &str, sources: &[&str]) -> InlineRenderGuard {
        match caches
            .begin_inline_render(key, sources.iter().map(|s| s.to_string()).collect())
            .await
        {
            InlineClaim::Leader(guard) => guard,
            InlineClaim::Wait(_) => panic!("expected to lead the cold render of {key}"),
            InlineClaim::Failed { status, message } => {
                panic!("expected to lead the cold render of {key}, got {status}: {message}")
            }
        }
    }

    /// A source change or a reconciling ingest clears every rendered output
    /// that contains the source; renderings of unrelated sources survive.
    #[tokio::test]
    async fn source_invalidation_clears_dependent_renderings_only() {
        let caches = Caches::new();
        let now = fumox_core::models::now_ts();
        caches
            .processed_put("sub:p1", rendered(now + 60, &["s1", "s2"]))
            .await;
        caches
            .processed_put("src:s1", rendered(now + 60, &["s1"]))
            .await;
        caches
            .processed_put("sub:p2", rendered(now + 60, &["s2"]))
            .await;

        caches.invalidate_processed_for_source("s1").await;

        assert!(caches.processed_get("sub:p1").await.is_none());
        assert!(caches.processed_get("src:s1").await.is_none());
        // Unrelated profile survives.
        assert!(caches.processed_get("sub:p2").await.is_some());
    }

    #[tokio::test]
    async fn invalidate_profile_clears_only_its_entry() {
        let caches = Caches::new();
        let now = fumox_core::models::now_ts();
        caches
            .processed_put("sub:p1", rendered(now + 60, &["s1"]))
            .await;
        caches
            .processed_put("sub:p2", rendered(now + 60, &["s1"]))
            .await;

        caches.invalidate_profile("p1").await;

        assert!(caches.processed_get("sub:p1").await.is_none());
        assert!(caches.processed_get("sub:p2").await.is_some());
    }

    #[tokio::test]
    async fn revalidation_claim_is_exclusive() {
        let caches = Caches::new();
        let first = caches.try_start_revalidate("sub:p1").await;
        assert!(first.is_some());
        assert!(caches.try_start_revalidate("sub:p1").await.is_none());
        drop(first);
        assert!(caches.try_start_revalidate("sub:p1").await.is_some());
    }

    /// A panic in the background re-render must release the claim, otherwise
    /// the endpoint serves its stale snapshot forever.
    #[tokio::test]
    async fn revalidation_claim_survives_a_panicking_task() {
        let caches = Caches::new();
        let task_caches = caches.clone();
        let handle = tokio::spawn(async move {
            let _guard = task_caches
                .try_start_revalidate("sub:p1")
                .await
                .expect("first claim succeeds");
            panic!("render blew up");
        });
        assert!(handle.await.is_err(), "the task is expected to panic");

        for _ in 0..10 {
            if !caches.is_revalidating("sub:p1").await {
                break;
            }
            tokio::task::yield_now().await;
        }
        assert!(
            !caches.is_revalidating("sub:p1").await,
            "unwinding must release the revalidation claim"
        );
        assert!(caches.try_start_revalidate("sub:p1").await.is_some());
    }

    #[test]
    fn freshness_boundary() {
        let now = fumox_core::models::now_ts();
        assert!(rendered(now + 1, &[]).is_fresh(now));
        assert!(!rendered(now, &[]).is_fresh(now));
    }

    /// A background re-render that started before an ingest commits must
    /// not store its pre-commit rendering with a full fresh TTL behind the
    /// ingest's invalidation: without the generation guard the put lands
    /// after `invalidate_processed_for_source` and the old rows are served
    /// as fresh until the TTL expires.
    #[tokio::test]
    async fn revalidation_started_before_an_ingest_does_not_store_its_rendering() {
        let caches = Caches::new();
        let now = fumox_core::models::now_ts();
        caches
            .processed_put("sub:p1", rendered(now - 1, &["s1"]))
            .await;

        // A stale request claims the key and starts re-rendering.
        let claim = caches
            .try_start_revalidate("sub:p1")
            .await
            .expect("stale entry is revalidatable");
        let generation = claim.generation();

        // The ingest commits while the render is still running.
        caches.invalidate_processed_for_source("s1").await;

        let stored = caches
            .processed_put_guarded(
                "sub:p1",
                Arc::new(rendered(now + 3600, &["s1"])),
                generation,
            )
            .await;
        assert!(stored.is_none(), "pre-ingest rendering must be refused");
        assert!(
            caches.processed_get("sub:p1").await.is_none(),
            "the invalidated key must stay empty until it is re-rendered"
        );
    }

    /// An inline (cache-miss) render that started before an ingest commits
    /// must not store its pre-commit rendering with a full fresh TTL behind
    /// the ingest's invalidation either. The key has no entry while that
    /// render runs, so `invalidate_processed_for_source` cannot find it by
    /// iterating the processed layer and its generation stays where it was.
    #[tokio::test]
    async fn inline_render_started_before_an_ingest_does_not_store_its_rendering() {
        let caches = Caches::new();
        let now = fumox_core::models::now_ts();

        // A cache miss: the inline render of an empty key claims it.
        let claim = claim_inline(&caches, "sub:p1", &["s1"]).await;

        // The ingest commits while that render is still running.
        caches.invalidate_processed_for_source("s1").await;

        let stored = caches
            .processed_put_guarded(
                "sub:p1",
                Arc::new(rendered(now + 3600, &["s1"])),
                claim.generation(),
            )
            .await;
        assert!(stored.is_none(), "pre-ingest rendering must be refused");
        assert!(
            caches.processed_get("sub:p1").await.is_none(),
            "the pre-ingest rendering must not be served as fresh for a full TTL"
        );
    }

    /// A cold render no invalidation touched still fills the cache, and the
    /// claim is released so the next miss renders again.
    #[tokio::test]
    async fn inline_render_without_an_invalidation_still_stores() {
        let caches = Caches::new();
        let now = fumox_core::models::now_ts();
        let claim = claim_inline(&caches, "sub:p1", &["s1"]).await;
        let stored = caches
            .processed_put_guarded(
                "sub:p1",
                Arc::new(rendered(now + 3600, &["s1"])),
                claim.generation(),
            )
            .await;
        assert!(stored.is_some());
        drop(claim);
        // Released: a fresh cold render leads again.
        let _ = claim_inline(&caches, "sub:p1", &["s1"]).await;
    }

    /// Concurrent invalidations of one key must each leave their mark: a
    /// lost bump lets a render claimed after the first invalidation store
    /// rows the second one already superseded, for a full TTL.
    #[tokio::test]
    async fn concurrent_invalidations_do_not_lose_a_generation() {
        let caches = Caches::new();
        let mut tasks = tokio::task::JoinSet::new();
        for _ in 0..64 {
            let caches = caches.clone();
            tasks.spawn(async move { caches.processed_invalidate("sub:race").await });
        }
        while tasks.join_next().await.is_some() {}
        assert_eq!(caches.generation("sub:race"), 64);
    }

    /// A request that finds the claim taken must be handed a wake-up that
    /// resolves when the leader's claim ends, and that is what lets the burst
    /// wait for one render instead of running one each. The release must
    /// also happen on unwind (the guard removes the entry in `Drop`).
    #[tokio::test]
    async fn a_taken_claim_hands_waiters_a_wake_up() {
        let caches = Caches::new();
        let leader = claim_inline(&caches, "sub:p1", &["s1"]).await;

        let mut waiter = match caches.begin_inline_render("sub:p1", Vec::new()).await {
            InlineClaim::Wait(rx) => rx,
            InlineClaim::Leader(_) => panic!("a taken claim cannot be led"),
            InlineClaim::Failed { status, message } => {
                panic!("a taken claim cannot carry a verdict: {status}: {message}")
            }
        };
        let parked = tokio::spawn(async move { waiter.changed().await });

        // The leader panics: the guard's `Drop` still releases the claim
        // and closes the channel.
        let crashed = tokio::spawn(async move {
            let _leader = leader;
            tokio::task::yield_now().await;
            panic!("render blew up");
        });
        assert!(crashed.await.is_err());

        let woke = tokio::time::timeout(Duration::from_secs(5), parked)
            .await
            .expect("the waiter must wake when the leader's claim ends")
            .unwrap();
        // Closed channel (no value is ever sent) is the expected wake-up.
        assert!(woke.is_err());
        // The claim is gone: the next arrival leads its own render.
        let _ = claim_inline(&caches, "sub:p1", &["s1"]).await;
    }

    /// An ingest of one source must not discard the in-flight cold render of
    /// a key that has nothing to do with it. Under a busy ingest schedule a
    /// wide blast radius starves the processed cache of perfectly valid
    /// fills: the body is still served, only the put is refused.
    #[tokio::test]
    async fn an_unrelated_ingest_does_not_discard_an_in_flight_render() {
        let caches = Caches::new();
        let now = fumox_core::models::now_ts();
        // A cold render of a profile over "s2", while "s1" gets ingested.
        let claim = claim_inline(&caches, "sub:p1", &["s2"]).await;
        caches.invalidate_processed_for_source("s1").await;

        let stored = caches
            .processed_put_guarded(
                "sub:p1",
                Arc::new(rendered(now + 3600, &["s2"])),
                claim.generation(),
            )
            .await;
        assert!(
            stored.is_some(),
            "an ingest of an unrelated source must not refuse this fill"
        );
    }

    /// The guard must not block a re-render that no invalidation touched:
    /// the common path still fills the cache.
    #[tokio::test]
    async fn revalidation_without_an_invalidation_still_stores() {
        let caches = Caches::new();
        let now = fumox_core::models::now_ts();
        caches
            .processed_put("sub:p1", rendered(now - 1, &["s1"]))
            .await;
        let claim = caches.try_start_revalidate("sub:p1").await.unwrap();
        let stored = caches
            .processed_put_guarded(
                "sub:p1",
                Arc::new(rendered(now + 3600, &["s1"])),
                claim.generation(),
            )
            .await;
        assert!(stored.is_some());
        assert!(caches.processed_get("sub:p1").await.is_some());
    }

    /// The layer is bounded by bytes, not by entry count: one rendered
    /// subscription is megabytes, so a ceiling of ten thousand entries is
    /// a multi-gigabyte ceiling in practice.
    #[tokio::test]
    async fn the_cache_is_bounded_by_bytes() {
        let caches = Caches::new();
        let now = fumox_core::models::now_ts();
        let mut big = rendered(now + 60, &[]);
        big.body = Bytes::from(vec![b'x'; 1024 * 1024]);
        caches.processed_put("sub:big", big).await;
        // The write buffer is applied on demand, so the counters are read
        // after the maintenance pass.
        caches.processed.run_pending_tasks().await;
        assert_eq!(caches.processed.entry_count(), 1);
        assert!(
            caches.processed.weighted_size() >= 1024 * 1024,
            "the cache must weigh the body, not count the entry: {}",
            caches.processed.weighted_size()
        );
    }

    /// Every entry is charged its body plus a fixed overhead, so a cache
    /// full of empty bodies is bounded too.
    #[test]
    fn an_entry_costs_its_body_plus_an_overhead() {
        let mut entry = rendered(0, &[]);
        entry.body = Bytes::from(vec![b'x'; 4096]);
        let weight = entry_weight("sub:p1", &entry);
        assert!(weight >= 4096 + ENTRY_OVERHEAD_BYTES);
        assert!(weight < 4096 + ENTRY_OVERHEAD_BYTES + 64);
    }

    /// The generation counter outlives the entry it guards: a generation
    /// the cache dropped would let a render claimed before the
    /// invalidation store its pre-change rows as fresh.
    #[tokio::test]
    async fn a_generation_outlives_the_entry_it_guards() {
        let caches = Caches::new();
        let now = fumox_core::models::now_ts();
        caches
            .processed_put("sub:p1", rendered(now + 60, &["s1"]))
            .await;
        caches.processed_invalidate("sub:p1").await;
        assert!(caches.processed_get("sub:p1").await.is_none());
        assert_eq!(caches.generation("sub:p1"), 1);
    }

    /// The reverse index names the keys a source was rendered from, so an
    /// invalidation does not have to scan the whole cache.
    #[test]
    fn the_reverse_index_names_the_keys_of_a_source() {
        let mut index = SourceIndex::default();
        index.add("sub:p1", &["s1".to_string(), "s2".to_string()]);
        index.add("sub:p2", &["s2".to_string()]);
        let mut keys = index.keys_for_source("s2");
        keys.sort();
        assert_eq!(keys, vec!["sub:p1".to_string(), "sub:p2".to_string()]);
        assert!(index.keys_for_source("s3").is_empty());
    }

    /// The journal counts are read once per TTL window: a render inside
    /// the window answers from the cache, a render after it counts
    /// again. The two COUNT scans are the most expensive reads on the
    /// probe page, so they must not run per render.
    #[tokio::test]
    async fn the_journal_counts_are_cached_for_the_ttl() {
        let dir = fumox_core::tempdir_lite::TempDir::new("journal-counts");
        let pool = fumox_core::db::connect_pool(&fumox_core::config::DatabaseConfig {
            path: dir.path().join("test.db"),
            ..Default::default()
        })
        .await
        .unwrap();
        fumox_core::db::migrate(&pool).await.unwrap();

        let cache = JournalCounts::new(Duration::from_secs(60));
        assert_eq!(cache.get(&pool).await.unwrap(), (0, 0));

        // A row lands in the journal.
        sqlx::query(
            "INSERT INTO sources (id, name, url, enabled, cache_ttl_seconds, created_at, updated_at)
             VALUES ('srcA0000000', 's', 'https://example.com', 1, 3600, 1, 1)",
        )
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO fetch_log (source_id, fetched_at, ok) VALUES ('srcA0000000', 1, 1)",
        )
        .execute(&pool)
        .await
        .unwrap();

        // Inside the TTL the cached count is served.
        assert_eq!(cache.get(&pool).await.unwrap(), (0, 0));

        // After the TTL the counts are read again.
        let fresh = JournalCounts::new(Duration::ZERO);
        assert_eq!(fresh.get(&pool).await.unwrap(), (0, 1));
    }

    /// An invalidation reaches the keys the index names, and only those:
    /// a rendering of another source survives.
    #[tokio::test]
    async fn an_invalidation_reaches_the_keys_the_index_names() {
        let caches = Caches::new();
        let now = fumox_core::models::now_ts();
        caches
            .processed_put("sub:p1", rendered(now + 60, &["s1"]))
            .await;
        caches
            .processed_put("sub:p2", rendered(now + 60, &["s2"]))
            .await;
        caches.invalidate_processed_for_source("s1").await;
        assert!(caches.processed_get("sub:p1").await.is_none());
        assert!(caches.processed_get("sub:p2").await.is_some());
    }
}
