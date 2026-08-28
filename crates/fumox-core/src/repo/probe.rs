//! `probe_results` journal: one row per health-check attempt (T1/T2).

use crate::db::DbPool;

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
    /// `'tcp'` | `'tls'` | `'t2'` (DATABASE.md).
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

/// Delete probe history older than the cutoff (retention, SPEC §12).
pub async fn purge_before(pool: &DbPool, cutoff: i64) -> crate::Result<u64> {
    let affected = sqlx::query("DELETE FROM probe_results WHERE checked_at < ?")
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
}
