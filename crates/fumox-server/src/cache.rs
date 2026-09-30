//! In-memory cache layers.
//!
//! Two layers, both acceleration only, SQLite stays the source of truth:
//!
//! 1. **Raw cache**, the last successfully fetched payload per source.
//!    Freshness is `fetched_at + source.cache_ttl_seconds`; a fresh entry
//!    lets an on-demand revalidation skip the HTTP fetch entirely (the DB
//!    is already reconciled from that payload).
//! 2. **Processed cache**, the rendered subscription output per endpoint
//!    key (`sub:{profile_id}` / `src:{source_id}`). Entries carry their
//!    own `fresh_until`; a stale entry is still served
//!    (stale-while-revalidate) while a background re-render is scheduled.
//!
//! Only 200 responses are cached; 404/500 must stay fresh.
//! Invalidation happens in the same handler that saves the
//! change: a source change clears its raw entry plus every processed entry
//! that contains the source; a profile change clears its processed entry. A
//! successful ingest that reconciled new data clears every processed entry
//! containing the source (but keeps the just-written raw snapshot), so clients
//! see fresh proxies without waiting out the TTL.
//!
//! Every invalidation also bumps that key's generation. A render — the
//! background one of a stale entry and the inline one of a cache miss alike
//! — reads the generation when it starts and its result is dropped when the
//! generation moved meanwhile: that rendering was computed from pre-change
//! rows and must not be stored with a full fresh TTL behind the change that
//! invalidated it. A key with no entry yet (the inline path) is registered
//! with the cache layer for the duration of its render precisely so that
//! invalidations can see it.

use crate::fetcher::FetchedPayload;
use moka::future::Cache;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;

/// Safety net so abandoned entries eventually leave the caches even without
/// explicit invalidation (e.g. a deleted source).
const ENTRY_IDLE_LIMIT: Duration = Duration::from_secs(24 * 60 * 60);

/// Raw source payload snapshot (layer 1).
#[derive(Debug)]
pub struct RawSnapshot {
    /// Consumed by the SWR re-parse path (Phase 3 refinement); kept fresh
    /// by [`Caches::raw_is_fresh`] today.
    #[allow(dead_code)]
    pub payload: FetchedPayload,
    pub fetched_at: i64,
}

/// Rendered subscription output (layer 2).
#[derive(Debug)]
pub struct Rendered {
    pub status: u16,
    pub body: Vec<u8>,
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
    raw: Cache<String, Arc<RawSnapshot>>,
    processed: Cache<String, Arc<Rendered>>,
    /// Invalidation counter per processed key, bumped on every invalidation
    /// of that key. Bounded exactly like the processed layer it guards.
    generations: Cache<String, u64>,
    /// Processed keys currently being revalidated in the background, keeps
    /// concurrent stale requests from spawning duplicate re-renders.
    revalidating: Arc<Mutex<HashSet<String>>>,
    /// Processed keys currently being rendered inline (the cache-miss path),
    /// mapped to the sources that render draws from. Such a key has no entry
    /// yet, so it is invisible to the iteration in
    /// [`Caches::invalidate_processed_for_source`]; the claim is what lets an
    /// invalidation supersede a render that is still running. The source set
    /// keeps that supersession narrow: an ingest of a source this render
    /// cannot touch must not refuse its put.
    inline_rendering: Arc<Mutex<HashMap<String, HashSet<String>>>>,
}

impl Caches {
    pub fn new() -> Self {
        Self {
            raw: Cache::builder()
                .max_capacity(1_000)
                .time_to_idle(ENTRY_IDLE_LIMIT)
                .build(),
            processed: Cache::builder()
                .max_capacity(10_000)
                .time_to_idle(ENTRY_IDLE_LIMIT)
                .build(),
            generations: Cache::builder()
                .max_capacity(10_000)
                .time_to_idle(ENTRY_IDLE_LIMIT)
                .build(),
            revalidating: Arc::new(Mutex::new(HashSet::new())),
            inline_rendering: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    // ---- raw layer ----

    pub async fn raw_get(&self, source_id: &str) -> Option<Arc<RawSnapshot>> {
        self.raw.get(&source_id.to_string()).await
    }

    /// Whether the raw snapshot exists and is younger than the source TTL.
    pub async fn raw_is_fresh(&self, source_id: &str, ttl_seconds: i64) -> bool {
        match self.raw_get(source_id).await {
            Some(snapshot) => fumox_core::models::now_ts() - snapshot.fetched_at < ttl_seconds,
            None => false,
        }
    }

    pub async fn raw_put(&self, source_id: &str, payload: FetchedPayload, fetched_at: i64) {
        self.raw
            .insert(
                source_id.to_string(),
                Arc::new(RawSnapshot {
                    payload,
                    fetched_at,
                }),
            )
            .await;
    }

    // ---- processed layer ----

    pub async fn processed_get(&self, key: &str) -> Option<Arc<Rendered>> {
        self.processed.get(&key.to_string()).await
    }

    pub async fn processed_put(&self, key: &str, rendered: Rendered) -> Arc<Rendered> {
        let arc = Arc::new(rendered);
        self.processed.insert(key.to_string(), arc.clone()).await;
        arc
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
        if self.generation(key).await != generation {
            return None;
        }
        self.processed.insert(key.to_string(), rendered).await;
        if self.generation(key).await != generation {
            // An invalidation landed between the check and the insert and
            // therefore did not see this entry; drop it by hand.
            self.processed_invalidate(key).await;
            return None;
        }
        self.processed_get(key).await
    }

    /// Called by the admin save handlers (Phase 2.5).
    #[allow(dead_code)]
    pub async fn processed_invalidate(&self, key: &str) {
        self.bump_generation(key).await;
        self.processed.invalidate(&key.to_string()).await;
    }

    /// Current invalidation generation of a processed key; 0 = never
    /// invalidated.
    async fn generation(&self, key: &str) -> u64 {
        self.generations.get(&key.to_string()).await.unwrap_or(0)
    }

    /// Mark every rendering of `key` produced up to now as superseded.
    async fn bump_generation(&self, key: &str) {
        let key = key.to_string();
        let next = self.generation(&key).await + 1;
        self.generations.insert(key, next).await;
    }

    // ---- invalidation ----

    /// Source changed (url/encoding/input_format/protocols/headers/TTL/
    /// pipeline/enabled): drop its raw snapshot and every rendered output
    /// that contains it.
    #[allow(dead_code)] // wired to the admin source form in Phase 2.5
    pub async fn invalidate_source(&self, source_id: &str) {
        self.raw.invalidate(&source_id.to_string()).await;
        self.invalidate_processed_for_source(source_id).await;
    }

    /// Source data refreshed (a successful ingest reconciled at least one
    /// row): drop every rendered output that contains the source so clients
    /// see the new proxies immediately, and supersede every cold render that
    /// is still running over it. The raw snapshot is kept, the ingest that
    /// triggers this just wrote it.
    pub async fn invalidate_processed_for_source(&self, source_id: &str) {
        let mut affected: Vec<String> = self
            .processed
            .iter()
            .filter(|(_, rendered)| rendered.source_ids.iter().any(|id| id == source_id))
            .map(|(key, _)| (*key).clone())
            .collect();
        // A key with no entry yet — an inline (cache-miss) render of it is
        // running right now — is invisible to the iteration above. Its
        // rendering is still computed from the pre-ingest rows, so its
        // generation has to move too or the put would land behind this
        // invalidation (see [`Caches::processed_put_guarded`]). Only renders
        // that name this source are touched: an unrelated key's cold render
        // stays storable.
        let inline = self.inline_rendering.lock().await;
        affected.extend(
            inline
                .iter()
                .filter(|(_, sources)| sources.iter().any(|id| id == source_id))
                .map(|(key, _)| key.clone()),
        );
        drop(inline);
        for key in affected {
            self.bump_generation(&key).await;
            self.processed.invalidate(&key).await;
        }
    }

    /// Profile changed (composition/format/pipeline/enabled): drop its
    /// rendered output.
    #[allow(dead_code)] // wired to the admin profile form in Phase 2.5
    pub async fn invalidate_profile(&self, profile_id: &str) {
        self.processed_invalidate(&format!("sub:{profile_id}"))
            .await;
    }

    // ---- stale-while-revalidate coordination ----

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
        let generation = self.generation(key).await;
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

    // ---- inline (cache-miss) render coordination ----

    /// Claim an inline render of a key the processed layer does not hold.
    /// Returns a guard carrying the generation the render must still hold to
    /// be storable, or `None` when another render of the same key is already
    /// in flight — a burst of requests on a cold key renders the same body
    /// once for the cache and answers the rest without storing it.
    ///
    /// The guard also keeps the key visible to
    /// [`Caches::invalidate_processed_for_source`]: without an entry there
    /// is nothing for that call to find, and the pre-change rendering would
    /// be stored as fresh for a full TTL behind the invalidation.
    ///
    /// `source_ids` are the sources the rendering can draw from; they scope
    /// the claim's reach, so an ingest of a source this render cannot touch
    /// leaves its put alone instead of starving the cache of valid fills. A
    /// superset is safe, an empty list is not (it would make the claim
    /// invisible to every invalidation).
    pub async fn begin_inline_render(
        &self,
        key: &str,
        source_ids: Vec<String>,
    ) -> Option<InlineRenderGuard> {
        let claimed = self
            .inline_rendering
            .lock()
            .await
            .insert(key.to_string(), source_ids.into_iter().collect())
            .is_none();
        if !claimed {
            return None;
        }
        Some(InlineRenderGuard {
            inline_rendering: self.inline_rendering.clone(),
            key: key.to_string(),
            generation: self.generation(key).await,
        })
    }
}

/// Releases one inline-render claim when dropped, including while a panic
/// unwinds the rendering task.
pub struct InlineRenderGuard {
    inline_rendering: Arc<Mutex<HashMap<String, HashSet<String>>>>,
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
}

impl Drop for InlineRenderGuard {
    fn drop(&mut self) {
        // Same shape as `RevalidateGuard::drop`: `Drop` cannot await, the
        // lock is only ever held for a set insert/remove, so blocking on it
        // here cannot deadlock.
        let key = std::mem::take(&mut self.key);
        if let Ok(mut guard) = self.inline_rendering.try_lock() {
            guard.remove(&key);
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

#[cfg(test)]
mod tests {
    use super::*;

    fn rendered(fresh_until: i64, sources: &[&str]) -> Rendered {
        Rendered {
            status: 200,
            body: Vec::new(),
            content_type: "text/plain".to_string(),
            extra_headers: Vec::new(),
            fresh_until,
            source_ids: sources.iter().map(|s| s.to_string()).collect(),
        }
    }

    fn payload() -> FetchedPayload {
        FetchedPayload {
            http_status: 200,
            bytes: 3,
            body: b"abc".to_vec(),
        }
    }

    #[tokio::test]
    async fn raw_freshness_follows_source_ttl() {
        let caches = Caches::new();
        let now = fumox_core::models::now_ts();
        caches.raw_put("s1", payload(), now - 100).await;
        assert!(caches.raw_is_fresh("s1", 3600).await);
        assert!(!caches.raw_is_fresh("s1", 50).await);
        assert!(!caches.raw_is_fresh("missing", 3600).await);
    }

    #[tokio::test]
    async fn invalidate_source_clears_raw_and_dependent_renderings() {
        let caches = Caches::new();
        let now = fumox_core::models::now_ts();
        caches.raw_put("s1", payload(), now).await;
        caches
            .processed_put("sub:p1", rendered(now + 60, &["s1", "s2"]))
            .await;
        caches
            .processed_put("sub:p2", rendered(now + 60, &["s2"]))
            .await;
        caches
            .processed_put("src:s1", rendered(now + 60, &["s1"]))
            .await;

        caches.invalidate_source("s1").await;

        assert!(caches.raw_get("s1").await.is_none());
        assert!(caches.processed_get("sub:p1").await.is_none());
        assert!(caches.processed_get("src:s1").await.is_none());
        // Unrelated profile survives.
        assert!(caches.processed_get("sub:p2").await.is_some());
    }

    #[tokio::test]
    async fn ingest_invalidation_clears_renderings_but_keeps_raw() {
        let caches = Caches::new();
        let now = fumox_core::models::now_ts();
        caches.raw_put("s1", payload(), now).await;
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

        // The just-ingested raw snapshot stays; dependent renderings go.
        assert!(caches.raw_get("s1").await.is_some());
        assert!(caches.processed_get("sub:p1").await.is_none());
        assert!(caches.processed_get("src:s1").await.is_none());
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
        let claim = caches
            .begin_inline_render("sub:p1", vec!["s1".to_string()])
            .await
            .expect("the first cold render claims the key");

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
        let claim = caches
            .begin_inline_render("sub:p1", vec!["s1".to_string()])
            .await
            .unwrap();
        let stored = caches
            .processed_put_guarded(
                "sub:p1",
                Arc::new(rendered(now + 3600, &["s1"])),
                claim.generation(),
            )
            .await;
        assert!(stored.is_some());
        drop(claim);
        assert!(
            caches
                .begin_inline_render("sub:p1", vec!["s1".to_string()])
                .await
                .is_some(),
            "the claim must be released when the render ends"
        );
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
        let claim = caches
            .begin_inline_render("sub:p1", vec!["s2".to_string()])
            .await
            .expect("the first cold render claims the key");
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
}
