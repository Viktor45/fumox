//! `probe_results` journal: one row per health-check attempt (T1/T2).
//!
//! Also the probe priority queue (`probe_requests`): the server
//! enqueues freshly ingested `unknown` proxies at source-refresh time and
//! the probe drains the queue at the start of every cycle, newest first,
//! before falling back to the random sample.

use crate::db::DbPool;
use crate::repo::proxies::{T1_EXCLUDED_SCHEMES, T1Candidate};

/// One probe attempt to be journaled.
#[derive(Debug, Clone)]
pub struct ProbeResultEntry<'a> {
    pub proxy_id: i64,
    pub checked_at: i64,
    pub ok: bool,
    /// Measured latency; `None` when the check failed.
    pub latency_ms: Option<i64>,
    /// Failure reason (logged for diagnostics).
    pub error: Option<&'a str>,
    /// `'tcp'` | `'tls'` | `'t2'`.
    pub probe_kind: &'a str,
}

pub async fn insert(pool: &DbPool, entry: &ProbeResultEntry<'_>) -> crate::Result<()> {
    sqlx::query(
        "INSERT INTO probe_results
            (proxy_id, checked_at, ok, latency_ms, error, probe_kind)
         VALUES (?, ?, ?, ?, ?, ?)",
    )
    .bind(entry.proxy_id)
    .bind(entry.checked_at)
    .bind(entry.ok)
    .bind(entry.latency_ms)
    .bind(entry.error)
    .bind(entry.probe_kind)
    .execute(pool)
    .await?;
    Ok(())
}

/// Delete probe history older than the cutoff (retention).
pub async fn purge_before(pool: &DbPool, cutoff: i64) -> crate::Result<u64> {
    let affected = sqlx::query("DELETE FROM probe_results WHERE checked_at < ?")
        .bind(cutoff)
        .execute(pool)
        .await?
        .rows_affected();
    Ok(affected)
}

/// The `probe_kind` of the most recent failed attempt for a proxy, or `None`
/// when it has no failed attempts. Newest first via the
/// `idx_probe_proxy_time` index. Feeds the strict T2-priority rule:
/// a T1 success must not wipe the fail counter accumulated by
/// T2 failures, so the caller needs to know what the last failure was.
pub async fn last_failed_kind(pool: &DbPool, proxy_id: i64) -> crate::Result<Option<String>> {
    let row: Option<(String,)> = sqlx::query_as(
        "SELECT probe_kind FROM probe_results
         WHERE proxy_id = ? AND ok = 0
         ORDER BY checked_at DESC LIMIT 1",
    )
    .bind(proxy_id)
    .fetch_optional(pool)
    .await?;
    Ok(row.map(|(kind,)| kind))
}

/// Aggregate the most common probe failure reasons (`probe_results.error`)
/// over a rolling time window, ordered by hit count descending. Used by the
/// admin dashboard's Top Failure Reasons widget.
///
/// `since_ts` is the lower bound on `checked_at` (Unix seconds, inclusive);
/// `limit` caps the returned rows. Errors with `NULL` reason text are
/// excluded, they are uninformative aggregates of successful probes that
/// stored no diagnostic.
pub async fn top_failure_reasons(
    pool: &DbPool,
    since_ts: i64,
    limit: i64,
) -> crate::Result<Vec<(String, i64)>> {
    let rows: Vec<(String, i64)> = sqlx::query_as(
        "SELECT error, COUNT(*) AS hits FROM probe_results
         WHERE ok = 0 AND error IS NOT NULL AND checked_at >= ?
         GROUP BY error
         ORDER BY hits DESC, error ASC
         LIMIT ?",
    )
    .bind(since_ts)
    .bind(limit)
    .fetch_all(pool)
    .await?;
    Ok(rows)
}

// Priority queue (`probe_requests`)

/// Enqueue up to `limit` of `candidate_ids` for priority checking. Only
/// T1-probeable schemes are accepted (unprobeable schemes would clog the
/// queue forever); the row itself must still be `unknown` and still be
/// linked to a source, the same predicate the drain applies — a row
/// without a link is skipped by every T1 lane, so queueing it would only
/// leave a request nothing will ever consume. Idempotent , an id already
/// queued is left untouched (`INSERT OR IGNORE`). Returns the number of
/// newly queued ids.
pub async fn enqueue_checks(
    pool: &DbPool,
    candidate_ids: &[i64],
    limit: u32,
    now: i64,
) -> crate::Result<u64> {
    let mut queued = 0u64;
    let mut remaining = i64::from(limit);
    // IN-lists are chunked so a huge ingest cannot blow the bound-variable
    // limit; the newest ids (highest rowid) win within the limit. The two
    // only agree if the chunks themselves are walked newest-first: the
    // per-chunk `ORDER BY p.id DESC LIMIT ?` can only see inside its own
    // chunk, so a caller-supplied list longer than 500 (a bulk revival of
    // a whole country/ASN) would otherwise spend the whole limit on the
    // oldest ids and never even look at the newest. Sort a copy descending
    // and chunk that, so the first chunk holds the highest ids; `dedup`
    // then also keeps a repeated id from being enqueued twice across the
    // chunk boundary (`INSERT OR IGNORE` would swallow it anyway, the
    // `remaining` accounting would not).
    let mut newest_first = candidate_ids.to_vec();
    newest_first.sort_unstable_by(|a, b| b.cmp(a));
    newest_first.dedup();
    for chunk in newest_first.chunks(500) {
        if remaining <= 0 {
            break;
        }
        let placeholders = vec!["?"; chunk.len()].join(", ");
        let excluded = vec!["?"; T1_EXCLUDED_SCHEMES.len()].join(", ");
        let sql = format!(
            "INSERT OR IGNORE INTO probe_requests (proxy_id, requested_at)
             SELECT p.id, ? FROM proxies p
             WHERE p.id IN ({placeholders})
               AND p.status = 'unknown'
               AND p.scheme NOT IN ({excluded})
               AND EXISTS (SELECT 1 FROM proxy_source_links l WHERE l.proxy_id = p.id)
             ORDER BY p.id DESC LIMIT ?"
        );
        // sqlx 0.9 SqlSafeStr: the format! only expands `?` placeholder
        // lists, all data flows through .bind().
        let mut query = sqlx::query(sqlx::AssertSqlSafe(sql.as_str())).bind(now);
        for id in chunk {
            query = query.bind(id);
        }
        for scheme in T1_EXCLUDED_SCHEMES {
            query = query.bind(scheme);
        }
        query = query.bind(remaining);
        let inserted = query.execute(pool).await?.rows_affected();
        queued += inserted;
        remaining -= inserted as i64;
    }
    Ok(queued)
}

/// Drain the queue, newest first (fresh proxies check first).
/// Returns candidates that are still `unknown`, still linked to a source,
/// T1-probeable and not under a T2 block (`last_t2_failed_at IS NULL`,
/// the same guard as the random sample — migration 0007: a T2 failure
/// suppresses T1 until the next successful T2, and the T2 recency
/// selector is the only way back); everything else in the queue is
/// skipped here and removed by [`purge_settled_checks`].
pub async fn select_queued_checks(pool: &DbPool, limit: u32) -> crate::Result<Vec<T1Candidate>> {
    let excluded = vec!["?"; T1_EXCLUDED_SCHEMES.len()].join(", ");
    let sql = format!(
        "SELECT q.proxy_id AS id, p.scheme, p.host, p.port, p.params
         FROM probe_requests q
         JOIN proxies p ON p.id = q.proxy_id
         WHERE p.status = 'unknown'
           AND p.scheme NOT IN ({excluded})
           AND p.last_t2_failed_at IS NULL
           AND EXISTS (SELECT 1 FROM proxy_source_links l WHERE l.proxy_id = p.id)
         ORDER BY q.requested_at DESC, q.proxy_id DESC
         LIMIT ?"
    );
    let mut query = sqlx::query_as::<_, T1Candidate>(sqlx::AssertSqlSafe(sql.as_str()));
    for scheme in T1_EXCLUDED_SCHEMES {
        query = query.bind(scheme);
    }
    query = query.bind(i64::from(limit));
    Ok(query.fetch_all(pool).await?)
}

/// Claim the given requests: delete them right before the checks run, so a
/// crash cannot turn a queued id into an endless retry loop. A proxy whose
/// claim was lost still reaches the probe through the random sample.
pub async fn claim_checks(pool: &DbPool, proxy_ids: &[i64]) -> crate::Result<u64> {
    let mut claimed = 0u64;
    for chunk in proxy_ids.chunks(500) {
        let placeholders = vec!["?"; chunk.len()].join(", ");
        let sql = format!("DELETE FROM probe_requests WHERE proxy_id IN ({placeholders})");
        let mut query = sqlx::query(sqlx::AssertSqlSafe(sql.as_str()));
        for id in chunk {
            query = query.bind(id);
        }
        claimed += query.execute(pool).await?.rows_affected();
    }
    Ok(claimed)
}

/// Drop requests for proxies that no longer need the priority lane (already
/// checked by the random path, quarantined or removed). Deleted proxies are
/// removed by the FK cascade.
pub async fn purge_settled_checks(pool: &DbPool) -> crate::Result<u64> {
    let affected = sqlx::query(
        "DELETE FROM probe_requests
         WHERE proxy_id IN (
             SELECT q.proxy_id FROM probe_requests q
             JOIN proxies p ON p.id = q.proxy_id
             WHERE p.status != 'unknown'
         )",
    )
    .execute(pool)
    .await?
    .rows_affected();
    Ok(affected)
}

/// Drop queue entries older than the cutoff (retention for the case when
/// the probe is offline for a long time.
pub async fn purge_requests_before(pool: &DbPool, cutoff: i64) -> crate::Result<u64> {
    let affected = sqlx::query("DELETE FROM probe_requests WHERE requested_at < ?")
        .bind(cutoff)
        .execute(pool)
        .await?
        .rows_affected();
    Ok(affected)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::repo::tests::temp_pool;

    #[tokio::test]
    async fn insert_and_purge_history() {
        let pool = temp_pool().await;
        // probe_results has an FK to proxies; create a minimal row first.
        sqlx::query(
            "INSERT INTO proxies (fingerprint, scheme, name, host, port, credential, created_at, updated_at)
             VALUES ('fp1', 'vless', 'n', 'h', 443, 'c', 1, 1)",
        )
        .execute(&pool)
        .await
        .unwrap();

        insert(
            &pool,
            &ProbeResultEntry {
                proxy_id: 1,
                checked_at: 1000,
                ok: true,
                latency_ms: Some(42),
                error: None,
                probe_kind: "tcp",
            },
        )
        .await
        .unwrap();
        insert(
            &pool,
            &ProbeResultEntry {
                proxy_id: 1,
                checked_at: 2000,
                ok: false,
                latency_ms: None,
                error: Some("timeout"),
                probe_kind: "tls",
            },
        )
        .await
        .unwrap();

        let (count,): (i64,) =
            sqlx::query_as("SELECT COUNT(*) FROM probe_results WHERE proxy_id = 1")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(count, 2);

        assert_eq!(purge_before(&pool, 1500).await.unwrap(), 1);
        let (count,): (i64,) =
            sqlx::query_as("SELECT COUNT(*) FROM probe_results WHERE proxy_id = 1")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(count, 1);
    }

    #[tokio::test]
    async fn last_failed_kind_returns_the_newest_failure() {
        let pool = temp_pool().await;
        let id = insert_proxy(&pool, "fp-kind", "vless", "alive", true).await;

        // No failed attempts yet.
        assert_eq!(last_failed_kind(&pool, id).await.unwrap(), None);

        insert(
            &pool,
            &ProbeResultEntry {
                proxy_id: id,
                checked_at: 1000,
                ok: false,
                latency_ms: None,
                error: Some("timeout"),
                probe_kind: "tcp",
            },
        )
        .await
        .unwrap();
        // A success in between does not hide the failure.
        insert(
            &pool,
            &ProbeResultEntry {
                proxy_id: id,
                checked_at: 1100,
                ok: true,
                latency_ms: Some(30),
                error: None,
                probe_kind: "tcp",
            },
        )
        .await
        .unwrap();
        assert_eq!(
            last_failed_kind(&pool, id).await.unwrap().as_deref(),
            Some("tcp")
        );

        // The newest failure wins, whatever kinds are mixed.
        insert(
            &pool,
            &ProbeResultEntry {
                proxy_id: id,
                checked_at: 2000,
                ok: false,
                latency_ms: None,
                error: Some("invalid credential"),
                probe_kind: "t2",
            },
        )
        .await
        .unwrap();
        assert_eq!(
            last_failed_kind(&pool, id).await.unwrap().as_deref(),
            Some("t2")
        );
        insert(
            &pool,
            &ProbeResultEntry {
                proxy_id: id,
                checked_at: 3000,
                ok: false,
                latency_ms: None,
                error: Some("timeout"),
                probe_kind: "tls",
            },
        )
        .await
        .unwrap();
        assert_eq!(
            last_failed_kind(&pool, id).await.unwrap().as_deref(),
            Some("tls")
        );
    }

    #[tokio::test]
    async fn top_failure_reasons_groups_by_error_and_orders_by_hits() {
        let pool = temp_pool().await;
        let id = insert_proxy(&pool, "fp-fail", "vless", "alive", false).await;

        // Five distinct failure reasons with hit counts 3, 5, 1 plus one
        // NULL (which must be excluded) and one row outside the window.
        let cases: &[(i64, Option<&str>)] = &[
            (100, Some("timeout")),
            (110, Some("timeout")),
            (120, Some("timeout")),
            (200, Some("tls handshake failed")),
            (210, Some("tls handshake failed")),
            (220, Some("tls handshake failed")),
            (230, Some("tls handshake failed")),
            (240, Some("tls handshake failed")),
            (300, Some("reset by peer")),
            // Outside the window:
            (50, Some("timeout")),
            // Excluded (NULL reason):
            (400, None),
        ];
        for (ts, err) in cases {
            insert(
                &pool,
                &ProbeResultEntry {
                    proxy_id: id,
                    checked_at: *ts,
                    ok: false,
                    latency_ms: None,
                    error: *err,
                    probe_kind: "tcp",
                },
            )
            .await
            .unwrap();
        }

        // Window starts at 100; expect 3 distinct reasons, ordered by hits desc
        // then by reason text asc (deterministic tie-break).
        let top = top_failure_reasons(&pool, 100, 10).await.unwrap();
        assert_eq!(
            top,
            vec![
                ("tls handshake failed".to_string(), 5),
                ("timeout".to_string(), 3),
                ("reset by peer".to_string(), 1),
            ]
        );

        // The limit truncates the result regardless of hit counts.
        let top2 = top_failure_reasons(&pool, 100, 2).await.unwrap();
        assert_eq!(top2.len(), 2);
        assert_eq!(top2[0].0, "tls handshake failed");
        assert_eq!(top2[1].0, "timeout");

        // An empty window returns nothing.
        let empty = top_failure_reasons(&pool, 9_999_999, 10).await.unwrap();
        assert!(empty.is_empty());

        // Successful probes do not contribute (their `error` column is NULL).
        insert(
            &pool,
            &ProbeResultEntry {
                proxy_id: id,
                checked_at: 500,
                ok: true,
                latency_ms: Some(20),
                error: None,
                probe_kind: "tcp",
            },
        )
        .await
        .unwrap();
        let after_success = top_failure_reasons(&pool, 100, 10).await.unwrap();
        assert_eq!(after_success.len(), 3); // unchanged
    }

    /// Minimal proxies fixture: rows are linked to a source unless
    /// `unlinked` is true (the link's FK needs the source row to exist).
    async fn insert_proxy(
        pool: &DbPool,
        fingerprint: &str,
        scheme: &str,
        status: &str,
        linked: bool,
    ) -> i64 {
        sqlx::query(
            "INSERT OR IGNORE INTO sources (id, name, url, enabled, cache_ttl_seconds, created_at, updated_at)
             VALUES ('srcA0000000', 's', 'https://example.com', 1, 3600, 1, 1)",
        )
        .execute(pool)
        .await
        .unwrap();
        let (id,): (i64,) = sqlx::query_as(
            "INSERT INTO proxies (fingerprint, scheme, name, host, port, credential, status, created_at, updated_at)
             VALUES (?, ?, 'n', 'h', 443, 'c', ?, 1, 1) RETURNING id",
        )
        .bind(fingerprint)
        .bind(scheme)
        .bind(status)
        .fetch_one(pool)
        .await
        .unwrap();
        if linked {
            sqlx::query("INSERT INTO proxy_source_links (proxy_id, source_id, seen_at) VALUES (?, 'srcA0000000', 1)")
                .bind(id)
                .execute(pool)
                .await
                .unwrap();
        }
        id
    }

    #[tokio::test]
    async fn queue_round_trip_filters_and_prioritizes_newest() {
        let pool = temp_pool().await;
        let trojan = insert_proxy(&pool, "fp-t1", "trojan", "unknown", true).await;
        let vless_old = insert_proxy(&pool, "fp-t2", "vless", "unknown", true).await;
        let tuic = insert_proxy(&pool, "fp-t3", "tuic", "unknown", true).await;
        let alive = insert_proxy(&pool, "fp-t4", "trojan", "alive", true).await;
        let unlinked = insert_proxy(&pool, "fp-t5", "trojan", "unknown", false).await;

        // Older request first, then a fresher one; unprobeable/alive limits.
        enqueue_checks(&pool, &[vless_old, tuic, alive, unlinked], 10, 1000)
            .await
            .unwrap();
        enqueue_checks(&pool, &[trojan], 10, 2000).await.unwrap();

        // Idempotent: re-enqueueing does not duplicate.
        assert_eq!(enqueue_checks(&pool, &[trojan], 10, 3000).await.unwrap(), 0);

        // A row without a source link is not queued at all: no T1 lane
        // would ever drain it, so the request would be dead weight in
        // the table (and the revival paths would report a row the probe
        // cannot reach).
        let (queued_for_unlinked,): (i64,) =
            sqlx::query_as("SELECT COUNT(*) FROM probe_requests WHERE proxy_id = ?")
                .bind(unlinked)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(queued_for_unlinked, 0);

        // Drain: newest first, only unknown+probeable+linked rows.
        let drained = select_queued_checks(&pool, 10).await.unwrap();
        let drained_ids: Vec<i64> = drained.iter().map(|c| c.id).collect();
        assert_eq!(drained_ids, vec![trojan, vless_old]);

        // The limit caps the drain.
        let one = select_queued_checks(&pool, 1).await.unwrap();
        assert_eq!(one.len(), 1);
        assert_eq!(one[0].id, trojan);

        // Claiming removes exactly the drained entries.
        assert_eq!(claim_checks(&pool, &drained_ids).await.unwrap(), 2);
        let left = select_queued_checks(&pool, 10).await.unwrap();
        assert!(left.is_empty());
    }

    /// The priority lane carries the T2 suppression flag too:
    /// migration 0007 puts a proxy under a T2 block "until the next
    /// successful T2", and the T2 recency selector is the only way back.
    /// Without the guard a queued row would leave the block on the next
    /// plain TCP success, re-entering the T1 rotation the flag exists
    /// to keep it out of.
    #[tokio::test]
    async fn queue_drain_skips_rows_under_a_t2_block() {
        let pool = temp_pool().await;
        let free = insert_proxy(&pool, "fp-free", "trojan", "unknown", true).await;
        let blocked = insert_proxy(&pool, "fp-blocked", "trojan", "unknown", true).await;
        sqlx::query("UPDATE proxies SET last_t2_failed_at = 1_000 WHERE id = ?")
            .bind(blocked)
            .execute(&pool)
            .await
            .unwrap();

        enqueue_checks(&pool, &[free, blocked], 10, 2_000)
            .await
            .unwrap();
        let drained: Vec<i64> = select_queued_checks(&pool, 10)
            .await
            .unwrap()
            .iter()
            .map(|c| c.id)
            .collect();
        assert_eq!(drained, vec![free], "the T2-blocked row stays in the queue");
    }

    /// The queue's own contract is "the newest ids win within the limit"
    /// (the daemon drains it newest-first), so that must hold across the
    /// 500-id chunk boundary too, not only inside the first chunk. The
    /// bulk revival handlers hand their whole id list over with a small
    /// limit: a list longer than one chunk (1200 rows is an ordinary
    /// revival population) must still enqueue the highest ids.
    #[tokio::test]
    async fn enqueue_prefers_the_newest_ids_across_chunk_boundaries() {
        let pool = temp_pool().await;
        sqlx::query(
            "INSERT OR IGNORE INTO sources (id, name, url, enabled, cache_ttl_seconds, created_at, updated_at)
             VALUES ('srcA0000000', 's', 'https://example.com', 1, 3600, 1, 1)",
        )
        .execute(&pool)
        .await
        .unwrap();
        // 1200 linked, `unknown`, T1-probeable candidates in one statement
        // (a per-row helper would dominate the runtime of the test).
        sqlx::query(
            "WITH RECURSIVE cnt(x) AS (SELECT 1 UNION ALL SELECT x + 1 FROM cnt WHERE x < 1200)
             INSERT INTO proxies (fingerprint, scheme, name, host, port, credential, status, created_at, updated_at)
             SELECT 'fp-bulk-' || x, 'trojan', 'n', 'h', 443, 'c', 'unknown', 1, 1 FROM cnt",
        )
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO proxy_source_links (proxy_id, source_id, seen_at)
             SELECT id, 'srcA0000000', 1 FROM proxies",
        )
        .execute(&pool)
        .await
        .unwrap();

        let ids: Vec<i64> = sqlx::query_scalar("SELECT id FROM proxies ORDER BY id")
            .fetch_all(&pool)
            .await
            .unwrap();
        assert_eq!(ids.len(), 1200);

        assert_eq!(enqueue_checks(&pool, &ids, 50, 1_000).await.unwrap(), 50);
        let queued: Vec<i64> =
            sqlx::query_scalar("SELECT proxy_id FROM probe_requests ORDER BY proxy_id")
                .fetch_all(&pool)
                .await
                .unwrap();
        assert_eq!(
            queued,
            ids[ids.len() - 50..].to_vec(),
            "the limit must be spent on the highest ids, not on the first chunk"
        );
    }

    #[tokio::test]
    async fn queue_purge_drops_settled_and_stale() {
        let pool = temp_pool().await;
        let fresh_unknown = insert_proxy(&pool, "fp-p1", "trojan", "unknown", true).await;
        let now_alive = insert_proxy(&pool, "fp-p2", "trojan", "unknown", true).await;
        enqueue_checks(&pool, &[fresh_unknown, now_alive], 10, 1000)
            .await
            .unwrap();
        sqlx::query("UPDATE proxies SET status = 'alive' WHERE id = ?")
            .bind(now_alive)
            .execute(&pool)
            .await
            .unwrap();

        // The proxy that left `unknown` drops out; the fresh unknown stays.
        assert_eq!(purge_settled_checks(&pool).await.unwrap(), 1);
        let left = select_queued_checks(&pool, 10).await.unwrap();
        assert_eq!(
            left.iter().map(|c| c.id).collect::<Vec<_>>(),
            vec![fresh_unknown]
        );

        // Retention removes entries older than the cutoff.
        assert_eq!(purge_requests_before(&pool, 2000).await.unwrap(), 1);
        assert!(select_queued_checks(&pool, 10).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn queue_cascade_on_proxy_delete() {
        let pool = temp_pool().await;
        let id = insert_proxy(&pool, "fp-p3", "trojan", "unknown", true).await;
        enqueue_checks(&pool, &[id], 10, 1000).await.unwrap();
        sqlx::query("DELETE FROM proxies WHERE id = ?")
            .bind(id)
            .execute(&pool)
            .await
            .unwrap();
        assert!(select_queued_checks(&pool, 10).await.unwrap().is_empty());
        let (count,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM probe_requests")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(count, 0);
    }
}
