//! `probe_results` journal: one row per health-check attempt (T1/T2).
//!
//! Also the probe priority queue (`probe_requests`): the server
//! enqueues freshly ingested `unknown` proxies at source-refresh time and
//! the probe drains the queue at the start of every cycle, newest first,
//! before falling back to the random sample.

use crate::db::DbPool;
use crate::repo::proxies::{T1_EXCLUDED_SCHEMES, T1Candidate};
use sqlx::FromRow;

// Cross-process `meta` payloads (probe daemon <-> admin panel)

/// Wire contracts of the `meta` stamps the probe daemon and the admin
/// panel exchange: every key name and JSON payload shape is defined once
/// here and used by both the writer (probe daemon, server scheduler) and
/// the reader (admin handlers), so a rename is a compile error on both
/// sides instead of a panel card silently collapsing to `unknown`.
///
/// The on-wire JSON is exactly what the hand-built payloads always were:
/// these types state the existing shapes, they do not change them.
pub mod meta {
    use serde::{Deserialize, Serialize};

    /// `meta` key of the probe daemon heartbeat ([`Heartbeat`], JSON).
    pub const HEARTBEAT_KEY: &str = "probe_heartbeat";
    /// `meta` key of the last successful meow-rs contact (unix seconds
    /// as plain text).
    pub const MEOW_LAST_OK_KEY: &str = "meow_last_ok";
    /// `meta` key of the meow-rs memory stamp ([`MeowMemory`], JSON).
    pub const MEOW_MEMORY_KEY: &str = "meow_memory";
    /// `meta` key of the probe retention stamp ([`LastRotation`], JSON).
    pub const LAST_ROTATION_KEY: &str = "last_rotation";
    /// `meta` key of the server scheduler sweep stamp (unix seconds as
    /// plain text; deliberately not JSON, the reader only needs the age).
    pub const SERVER_CYCLE_KEY: &str = "server_cycle";

    /// `probe_heartbeat`: the daemon's liveness stamp, upserted on every
    /// beat. `interval_secs` and `cycle_interval_secs` are the beat and
    /// cycle periods the daemon actually runs — server and probe may read
    /// different config files, so the panel thresholds staleness against
    /// these rather than its own config copy. Both optional: stamps
    /// written before the fields existed must still parse, the reader
    /// then falls back to its own config.
    #[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
    pub struct Heartbeat {
        pub ts: i64,
        #[serde(default)]
        pub pid: u32,
        #[serde(default = "unknown_version")]
        pub version: String,
        #[serde(default)]
        pub interval_secs: Option<u64>,
        #[serde(default)]
        pub cycle_interval_secs: Option<u64>,
    }

    /// Reader-side stand-in for a stamp that carries no `version`.
    fn unknown_version() -> String {
        "?".to_string()
    }

    /// `meow_memory`: the meow-rs kernel RSS, stamped after every T2
    /// batch that reloaded the engine. Purely observational.
    #[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
    pub struct MeowMemory {
        pub rss_bytes: u64,
        pub os_limit_bytes: u64,
        pub ts: i64,
    }

    /// `last_rotation`: one run of the probe daemon's retention loop,
    /// including runs that deleted nothing, so the age of `ts` is the
    /// "retention is alive" signal.
    #[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
    pub struct LastRotation {
        pub ts: i64,
        #[serde(default)]
        pub probe_results: u64,
        #[serde(default)]
        pub fetch_log: u64,
        #[serde(default)]
        pub probe_requests: u64,
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        /// Round-trip: the writer's payload survives serialize +
        /// deserialize unchanged.
        #[test]
        fn heartbeat_round_trips() {
            let payload = Heartbeat {
                ts: 1_700_000_000,
                pid: 4242,
                version: "0.1.0".to_string(),
                interval_secs: Some(30),
                cycle_interval_secs: Some(60),
            };
            let raw = serde_json::to_string(&payload).unwrap();
            assert_eq!(serde_json::from_str::<Heartbeat>(&raw).unwrap(), payload);
        }

        /// Stamps written by older daemons (no beat/cycle periods) and
        /// hand-written fixtures (no pid/version) must still parse, with
        /// the same fallbacks the previous hand-parsing applied.
        #[test]
        fn heartbeat_parses_legacy_stamps() {
            let hb: Heartbeat =
                serde_json::from_str(r#"{"ts":123,"pid":7,"version":"x"}"#).unwrap();
            assert_eq!(hb.ts, 123);
            assert_eq!(hb.pid, 7);
            assert_eq!(hb.version, "x");
            assert_eq!(hb.interval_secs, None);
            assert_eq!(hb.cycle_interval_secs, None);

            let minimal: Heartbeat = serde_json::from_str(r#"{"ts":5}"#).unwrap();
            assert_eq!(minimal.pid, 0);
            assert_eq!(minimal.version, "?");
        }

        /// A stamp without the queue counter parses (the field was added
        /// later than the other two), and the full payload round-trips.
        #[test]
        fn last_rotation_parses_partial_and_round_trips() {
            let rot: LastRotation =
                serde_json::from_str(r#"{"ts":9,"probe_results":3,"fetch_log":1}"#).unwrap();
            assert_eq!(rot.ts, 9);
            assert_eq!(rot.probe_results, 3);
            assert_eq!(rot.fetch_log, 1);
            assert_eq!(rot.probe_requests, 0);

            let full = LastRotation {
                ts: 9,
                probe_results: 3,
                fetch_log: 1,
                probe_requests: 2,
            };
            let raw = serde_json::to_string(&full).unwrap();
            assert_eq!(serde_json::from_str::<LastRotation>(&raw).unwrap(), full);
        }

        /// The on-wire JSON keeps the key names the hand-built payload
        /// always used.
        #[test]
        fn meow_memory_keeps_the_wire_keys() {
            let mem = MeowMemory {
                rss_bytes: 25_780_224,
                os_limit_bytes: 2_147_483_648,
                ts: 7,
            };
            let raw = serde_json::to_string(&mem).unwrap();
            assert_eq!(
                raw,
                r#"{"rss_bytes":25780224,"os_limit_bytes":2147483648,"ts":7}"#
            );
            assert_eq!(serde_json::from_str::<MeowMemory>(&raw).unwrap(), mem);
        }
    }
}

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

/// Total journal size. Reported on the probe page next to the rotation
/// stamp: a fresh stamp on a table that keeps growing is still a leak.
pub async fn count_all(pool: &DbPool) -> crate::Result<i64> {
    let (count,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM probe_results")
        .fetch_one(pool)
        .await?;
    Ok(count)
}

/// The `probe_kind` of the most recent failed attempt for a proxy, or `None`
/// when it has no failed attempts. Newest first via the
/// `idx_probe_proxy_time` index. Feeds the strict T2-priority rule:
/// a T1 success must not wipe the fail counter accumulated by
/// T2 failures, so the caller needs to know what the last failure was.
///
/// `checked_at` has one-second resolution and the T1 sample and the T2
/// batch of one cycle both journal into it, so two failures can share a
/// timestamp; `id DESC` breaks the tie by insertion order (the column is
/// an `AUTOINCREMENT` primary key), so the newest journaled failure wins
/// deterministically.
pub async fn last_failed_kind(pool: &DbPool, proxy_id: i64) -> crate::Result<Option<String>> {
    let row: Option<(String,)> = sqlx::query_as(
        "SELECT probe_kind FROM probe_results
         WHERE proxy_id = ? AND ok = 0
         ORDER BY checked_at DESC, id DESC LIMIT 1",
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

/// One row of the proxy card's probe history: a preserved check attempt.
#[derive(Debug, FromRow)]
pub struct ProbeHistoryRow {
    pub checked_at: i64,
    pub ok: i64,
    pub latency_ms: Option<i64>,
    pub error: Option<String>,
    pub probe_kind: String,
}

/// The last `limit` probe attempts of one proxy, newest first (proxy card
/// history table). Same rows the daemon journals; the table rotates with
/// `[retention].probe_results_days`, so old attempts disappear from the
/// card exactly as they do from the coverage counters.
pub async fn recent_for_proxy(
    pool: &DbPool,
    proxy_id: i64,
    limit: i64,
) -> crate::Result<Vec<ProbeHistoryRow>> {
    let rows: Vec<ProbeHistoryRow> = sqlx::query_as(
        "SELECT checked_at, ok, latency_ms, error, probe_kind
         FROM probe_results WHERE proxy_id = ?
         ORDER BY checked_at DESC, id DESC LIMIT ?",
    )
    .bind(proxy_id)
    .bind(limit)
    .fetch_all(pool)
    .await?;
    Ok(rows)
}

// Priority queue (`probe_requests`)

/// Enqueue up to `limit` of `candidate_ids` for priority checking. Only
/// T1-probeable schemes are accepted (unprobeable schemes would clog the
/// queue forever); the row itself must still be `unknown` and still be
/// linked to a source, the same predicate the drain applies, a row
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
/// the same guard as the random sample, migration 0007: a T2 failure
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
        let (_dir, pool) = temp_pool().await;
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
        let (_dir, pool) = temp_pool().await;
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

    /// The proxy card history: the newest attempts first, capped, with the
    /// columns the history table renders.
    #[tokio::test]
    async fn recent_for_proxy_returns_the_newest_attempts_capped() {
        let (_dir, pool) = temp_pool().await;
        let id = insert_proxy(&pool, "fp-history", "vless", "alive", true).await;
        for (at, ok, latency, error, kind) in [
            (1000, false, None, Some("timeout"), "tcp"),
            (1100, true, Some(30), None, "tcp"),
            (1200, false, None, Some("invalid credential"), "t2"),
        ] {
            insert(
                &pool,
                &ProbeResultEntry {
                    proxy_id: id,
                    checked_at: at,
                    ok,
                    latency_ms: latency,
                    error,
                    probe_kind: kind,
                },
            )
            .await
            .unwrap();
        }

        let rows = recent_for_proxy(&pool, id, 2).await.unwrap();
        assert_eq!(rows.len(), 2, "the cap holds");
        assert_eq!(rows[0].checked_at, 1200);
        assert_eq!(rows[0].probe_kind, "t2");
        assert_eq!(rows[0].error.as_deref(), Some("invalid credential"));
        assert_eq!(rows[0].ok, 0);
        assert_eq!(rows[1].checked_at, 1100);
        assert_eq!(rows[1].latency_ms, Some(30));

        // Uncapped: everything, oldest last.
        let rows = recent_for_proxy(&pool, id, 20).await.unwrap();
        assert_eq!(
            rows.iter().map(|r| r.checked_at).collect::<Vec<_>>(),
            vec![1200, 1100, 1000]
        );

        // Another proxy's history stays separate.
        let other = insert_proxy(&pool, "fp-history-2", "vless", "alive", true).await;
        assert!(recent_for_proxy(&pool, other, 20).await.unwrap().is_empty());
    }

    /// Two failures journaled in the same second (the T1 sample and the T2
    /// batch of one cycle both run on `alive` proxies) must resolve to the
    /// newest *inserted* row, not to an arbitrary one of the two.
    #[tokio::test]
    async fn last_failed_kind_breaks_same_second_ties_by_insertion_order() {
        let (_dir, pool) = temp_pool().await;

        // t2 journaled after tcp: the tie resolves to t2.
        let first = insert_proxy(&pool, "fp-tie1", "vless", "alive", true).await;
        for (kind, error) in [("tcp", "timeout"), ("t2", "invalid credential")] {
            insert(
                &pool,
                &ProbeResultEntry {
                    proxy_id: first,
                    checked_at: 2000,
                    ok: false,
                    latency_ms: None,
                    error: Some(error),
                    probe_kind: kind,
                },
            )
            .await
            .unwrap();
        }
        assert_eq!(
            last_failed_kind(&pool, first).await.unwrap().as_deref(),
            Some("t2")
        );

        // The mirror order resolves to tcp: the tie-break is insertion
        // order (id DESC), not the probe_kind's own sort order.
        let second = insert_proxy(&pool, "fp-tie2", "vless", "alive", true).await;
        for (kind, error) in [("t2", "invalid credential"), ("tcp", "timeout")] {
            insert(
                &pool,
                &ProbeResultEntry {
                    proxy_id: second,
                    checked_at: 2000,
                    ok: false,
                    latency_ms: None,
                    error: Some(error),
                    probe_kind: kind,
                },
            )
            .await
            .unwrap();
        }
        assert_eq!(
            last_failed_kind(&pool, second).await.unwrap().as_deref(),
            Some("tcp")
        );
    }

    #[tokio::test]
    async fn top_failure_reasons_groups_by_error_and_orders_by_hits() {
        let (_dir, pool) = temp_pool().await;
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
        let (_dir, pool) = temp_pool().await;
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
        let (_dir, pool) = temp_pool().await;
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
        let (_dir, pool) = temp_pool().await;
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
        let (_dir, pool) = temp_pool().await;
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
        let (_dir, pool) = temp_pool().await;
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
