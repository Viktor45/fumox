//! Journal retention shared by the server and the probe daemon.
//!
//! Both binaries write `fetch_log` rows (one per fetch attempt) and
//! enqueue `probe_requests` (one per refresh); the daemon additionally
//! owns `probe_results`, which the server never writes. The windows, the
//! clamp and the order of the purges live here, so a server-only
//! deployment and a deployment with a daemon cannot drift apart on what
//! "older than the window" means. The daemon purges its own
//! `probe_results` around this sweep, the server does not (nothing to
//! purge); the mirror image is [`purge_stale_removed_proxies`], which the
//! server alone runs, because the daemon's authorizer forbids proxy
//! deletion.

use crate::db::DbPool;
use crate::repo::{fetch_log, probe, proxies};

/// The retention windows of the journals both binaries write.
#[derive(Debug, Clone, Copy)]
pub struct RetentionWindows {
    /// `[retention].fetch_log_days`.
    pub fetch_log_days: u32,
    /// `[probe].queue_stale_days`.
    pub queue_stale_days: u64,
}

/// What one sweep removed.
#[derive(Debug, Clone, Default)]
pub struct RetentionOutcome {
    pub fetch_log: u64,
    /// Rows dropped from `probe_requests`: the settled ones and the stale
    /// ones together.
    pub probe_requests: u64,
    /// The first failure of the sweep, if a purge errored: the callers
    /// stamp it into `last_rotation`, so the panel can tell a failed
    /// rotation from a quiet one.
    pub error: Option<String>,
}

/// Cutoff timestamp for a window of `days`: the rows older than it go.
/// A zero window would wipe the whole table on every pass, so the window
/// is clamped to one day; the subtraction saturates, so an absurd window
/// from a hand-edited config cuts everything off rather than wrapping
/// around into the future.
pub fn cutoff(now: i64, days: u64) -> i64 {
    let span = i64::try_from(days.max(1))
        .unwrap_or(i64::MAX)
        .saturating_mul(86_400);
    now.saturating_sub(span)
}

/// The `fetch_log` pass of the sweep: the journal rows older than
/// `before` go, the count lands in `outcome.fetch_log`, and the first
/// failure is stamped into `outcome.error`.
async fn rotate_fetch_log(pool: &DbPool, outcome: &mut RetentionOutcome, before: i64) {
    match fetch_log::purge_before(pool, before).await {
        Ok(0) => {}
        Ok(deleted) => {
            outcome.fetch_log = deleted;
            tracing::info!(deleted, "rotated fetch_log");
        }
        Err(error) => {
            tracing::warn!(%error, "fetch_log rotation failed");
            outcome.error.get_or_insert(format!("fetch_log: {error}"));
        }
    }
}

/// The settled pass of the sweep: the queue rows whose proxy already
/// left `unknown` go, and the count accumulates into
/// `outcome.probe_requests`.
async fn drop_settled_probe_requests(pool: &DbPool, outcome: &mut RetentionOutcome) {
    match probe::purge_settled_checks(pool).await {
        Ok(0) => {}
        Ok(deleted) => {
            outcome.probe_requests += deleted;
            tracing::debug!(deleted, "dropped settled probe_requests");
        }
        Err(error) => {
            tracing::warn!(%error, "probe_requests cleanup failed");
            outcome
                .error
                .get_or_insert(format!("probe_requests settled: {error}"));
        }
    }
}

/// The stale pass of the sweep: the queue rows that are simply too old
/// — the leftovers from an offline probe — go, and the count
/// accumulates into `outcome.probe_requests`.
async fn rotate_stale_probe_requests(pool: &DbPool, outcome: &mut RetentionOutcome, before: i64) {
    match probe::purge_requests_before(pool, before).await {
        Ok(0) => {}
        Ok(deleted) => {
            outcome.probe_requests += deleted;
            tracing::info!(deleted, "rotated stale probe_requests");
        }
        Err(error) => {
            tracing::warn!(%error, "probe_requests rotation failed");
            outcome
                .error
                .get_or_insert(format!("probe_requests stale: {error}"));
        }
    }
}

/// Purge the journal rows both binaries write and report what went: the
/// journal first, then the queue rows whose proxy already left the
/// `unknown` state, then the queue rows that are simply too old. A row
/// that is both settled and old is counted once, in the settled pass.
pub async fn sweep_shared_journals(
    pool: &DbPool,
    windows: &RetentionWindows,
    now: i64,
) -> RetentionOutcome {
    let mut outcome = RetentionOutcome::default();
    rotate_fetch_log(
        pool,
        &mut outcome,
        cutoff(now, u64::from(windows.fetch_log_days)),
    )
    .await;
    drop_settled_probe_requests(pool, &mut outcome).await;
    rotate_stale_probe_requests(pool, &mut outcome, cutoff(now, windows.queue_stale_days)).await;
    outcome
}

/// The TTL half of «purge removed»: physically delete the proxies that
/// have sat in the `removed` status for more than `days` days
/// (`[retention].removed_proxies_days`), through the same bounded
/// batches as the admin button ([`proxies::purge_removed_before`]).
///
/// The server runs this next to [`sweep_shared_journals`], and the
/// server alone: a proxy delete is content deletion, and the probe
/// daemon's connections run behind an authorizer that denies
/// `DELETE FROM proxies` (`sqlite_guard`), so the daemon's retention
/// loop must not call this; a daemon-only deployment has no automatic
/// purge, the admin button still does.
///
/// A zero window disables the purge outright, unlike the journal windows
/// (which clamp a zero to one day): `removed` stays reversible until the
/// admin presses the button.
pub async fn purge_stale_removed_proxies(pool: &DbPool, days: u64, now: i64) -> crate::Result<u64> {
    if days == 0 {
        return Ok(0);
    }
    proxies::purge_removed_before(pool, Some(cutoff(now, days))).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::repo::fetch_log::FetchLogEntry;

    /// A zero window is clamped to one day, a normal window is taken as
    /// it is, and an absurd one cuts everything off instead of wrapping
    /// around into the future.
    #[test]
    fn the_cutoff_clamps_a_zero_window() {
        assert_eq!(cutoff(100_000, 0), 100_000 - 86_400);
        assert_eq!(cutoff(100_000, 7), 100_000 - 7 * 86_400);
        assert_eq!(cutoff(100_000, u64::MAX), 100_000 - i64::MAX);
    }

    /// The sweep keeps the rows inside the windows and drops the ones
    /// past them: the journal, the queue rows of a proxy that already
    /// left `unknown`, and the queue rows that are simply too old.
    #[tokio::test]
    async fn the_sweep_keeps_the_rows_inside_the_windows() {
        let (dir, pool) = super::super::tests::temp_pool().await;
        let now = crate::models::now_ts();
        let day = 86_400i64;

        sqlx::query(
            "INSERT INTO sources (id, name, url, enabled, cache_ttl_seconds,
                                  created_at, updated_at)
             VALUES ('srcRet0000', 's', 'https://example.com/sub', 1, 3600, 1, 1)",
        )
        .execute(&pool)
        .await
        .unwrap();
        for (fetched_at, ok) in [(now - 40 * day, false), (now - day, true)] {
            crate::repo::fetch_log::insert(
                &pool,
                &FetchLogEntry {
                    source_id: "srcRet0000",
                    fetched_at,
                    ok,
                    http_status: None,
                    bytes: None,
                    proxies_found: None,
                    error: None,
                    error_class: None,
                },
                crate::repo::fetch_log::FetchTiming::default(),
            )
            .await
            .unwrap();
        }

        async fn insert_proxy(pool: &DbPool, fingerprint: &str) -> i64 {
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
        let fresh = insert_proxy(&pool, "fp-fresh").await;
        let stale = insert_proxy(&pool, "fp-stale").await;
        let settled = insert_proxy(&pool, "fp-settled").await;
        sqlx::query("UPDATE proxies SET status = 'alive' WHERE id = ?")
            .bind(settled)
            .execute(&pool)
            .await
            .unwrap();
        for (proxy_id, requested_at) in [(fresh, now), (stale, now - 30 * day), (settled, now)] {
            sqlx::query("INSERT INTO probe_requests (proxy_id, requested_at) VALUES (?, ?)")
                .bind(proxy_id)
                .bind(requested_at)
                .execute(&pool)
                .await
                .unwrap();
        }

        let windows = RetentionWindows {
            fetch_log_days: 30,
            queue_stale_days: 7,
        };
        let outcome = sweep_shared_journals(&pool, &windows, now).await;
        assert_eq!(outcome.fetch_log, 1, "the row past the window goes");
        assert_eq!(outcome.probe_requests, 2, "the stale and settled rows go");

        let (journal,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM fetch_log")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(journal, 1, "the row inside the window stays");
        let (queued,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM probe_requests")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(queued, 1, "the fresh queue row stays");

        pool.close().await;
        drop(dir);
    }

    /// The `removed`-proxy TTL takes only the rows past the window, never
    /// touches a live row, and the zero window — the opt-out — deletes
    /// nothing at all.
    #[tokio::test]
    async fn the_removed_proxies_ttl_purges_only_the_rows_past_the_window() {
        let (dir, pool) = super::super::tests::temp_pool().await;
        let now = crate::models::now_ts();
        let day = 86_400i64;

        async fn insert_proxy(pool: &DbPool, fingerprint: &str) -> i64 {
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
        let stale = insert_proxy(&pool, "fp-ttl-stale").await;
        let fresh = insert_proxy(&pool, "fp-ttl-fresh").await;
        let alive = insert_proxy(&pool, "fp-ttl-alive").await;
        for (id, removed_at) in [(stale, now - 30 * day), (fresh, now)] {
            sqlx::query("UPDATE proxies SET status = 'removed', removed_at = ? WHERE id = ?")
                .bind(removed_at)
                .bind(id)
                .execute(&pool)
                .await
                .unwrap();
        }
        sqlx::query("UPDATE proxies SET status = 'alive' WHERE id = ?")
            .bind(alive)
            .execute(&pool)
            .await
            .unwrap();

        // The opt-out: a zero window deletes nothing, an off purge must
        // not read as a zero-days one
        let deleted = purge_stale_removed_proxies(&pool, 0, now).await.unwrap();
        assert_eq!(deleted, 0);
        let (rows,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM proxies")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(rows, 3);

        let deleted = purge_stale_removed_proxies(&pool, 7, now).await.unwrap();
        assert_eq!(deleted, 1);
        let (rows,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM proxies")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(rows, 2, "the fresh removed row and the live row stay");
        let (kept,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM proxies WHERE id = ?")
            .bind(fresh)
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(kept, 1);

        pool.close().await;
        drop(dir);
    }
}
