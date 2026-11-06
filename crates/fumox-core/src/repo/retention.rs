//! Journal retention shared by the server and the probe daemon.
//!
//! Both binaries write `fetch_log` rows (one per fetch attempt) and
//! enqueue `probe_requests` (one per refresh); the daemon additionally
//! owns `probe_results`, which the server never writes. The windows, the
//! clamp and the order of the purges live here, so a server-only
//! deployment and a deployment with a daemon cannot drift apart on what
//! "older than the window" means.
//!
//! The daemon purges its own `probe_results` table around this sweep; the
//! server does not, because it has nothing in that table to purge.

use crate::db::DbPool;
use crate::repo::{fetch_log, probe};

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
    /// Rows dropped from `fetch_log`.
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
///
/// A zero window would wipe the whole table on every pass, so the window
/// is clamped to one day. The subtraction saturates: an absurd window
/// from a hand-edited config cuts everything off rather than wrapping
/// around into the future.
pub fn cutoff(now: i64, days: u64) -> i64 {
    let span = i64::try_from(days.max(1))
        .unwrap_or(i64::MAX)
        .saturating_mul(86_400);
    now.saturating_sub(span)
}

/// Purge the journal rows both binaries write and report what went.
///
/// The order is the one the daemon's retention loop has always used: the
/// journal first, then the queue rows whose proxy already left the
/// `unknown` state, then the queue rows that are simply too old. A row
/// that is both settled and old is counted once, in the settled pass.
pub async fn sweep_shared_journals(
    pool: &DbPool,
    windows: &RetentionWindows,
    now: i64,
) -> RetentionOutcome {
    let mut outcome = RetentionOutcome::default();

    match fetch_log::purge_before(pool, cutoff(now, u64::from(windows.fetch_log_days))).await {
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
    // Priority-queue housekeeping: requests whose proxy already left
    // `unknown`, and stale leftovers from an offline probe.
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
    match probe::purge_requests_before(pool, cutoff(now, windows.queue_stale_days)).await {
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
    outcome
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
}
