//! In-memory cache layers (SPEC §7).
//!
//! Two layers, both acceleration only — SQLite stays the source of truth:
//!
//! 1. **Raw cache** — the last successfully fetched payload per source.
//!    Freshness is `fetched_at + source.cache_ttl_seconds`; a fresh entry
//!    lets an on-demand revalidation skip the HTTP fetch entirely (the DB
//!    is already reconciled from that payload).
//! 2. **Processed cache** — the rendered subscription output per endpoint
//!    key (`sub:{profile_id}` / `src:{source_id}`). Entries carry their
//!    own `fresh_until`; a stale entry is still served
//!    (stale-while-revalidate) while a background re-render is scheduled.
//!
//! Only 200 responses are cached; 404/500 must stay fresh (SPEC §10.2).
//! Invalidation (ADMIN_PLAN §7) happens in the same handler that saves the
//! change: a source change clears its raw entry plus every processed entry
//! that contains the source; a profile change clears its processed entry. A
//! successful ingest that reconciled new data clears every processed entry
//! containing the source (but keeps the just-written raw snapshot), so clients
//! see fresh proxies without waiting out the TTL.

use crate::fetcher::FetchedPayload;
use moka::future::Cache;
use std::collections::HashSet;
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
    /// Processed keys currently being revalidated in the background — keeps
    /// concurrent stale requests from spawning duplicate re-renders.
    revalidating: Arc<Mutex<HashSet<String>>>,
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
            revalidating: Arc::new(Mutex::new(HashSet::new())),
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

    /// Called by the admin save handlers (Phase 2.5).
    #[allow(dead_code)]
    pub async fn processed_invalidate(&self, key: &str) {
        self.processed.invalidate(&key.to_string()).await;
    }

    // ---- invalidation (ADMIN_PLAN §7) ----

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
    /// see the new proxies immediately. The raw snapshot is kept — the ingest
    /// that triggers this just wrote it.
    pub async fn invalidate_processed_for_source(&self, source_id: &str) {
        let affected: Vec<String> = self
            .processed
            .iter()
            .filter(|(_, rendered)| rendered.source_ids.iter().any(|id| id == source_id))
            .map(|(key, _)| (*key).clone())
            .collect();
        for key in affected {
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

    /// Claim the background revalidation of a key. Returns `true` for the
    /// caller that should perform the re-render.
    pub async fn try_start_revalidate(&self, key: &str) -> bool {
        self.revalidating.lock().await.insert(key.to_string())
    }

    pub async fn finish_revalidate(&self, key: &str) {
        self.revalidating.lock().await.remove(key);
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
        assert!(caches.try_start_revalidate("sub:p1").await);
        assert!(!caches.try_start_revalidate("sub:p1").await);
        caches.finish_revalidate("sub:p1").await;
        assert!(caches.try_start_revalidate("sub:p1").await);
    }

    #[test]
    fn freshness_boundary() {
        let now = fumox_core::models::now_ts();
        assert!(rendered(now + 1, &[]).is_fresh(now));
        assert!(!rendered(now, &[]).is_fresh(now));
    }
}
