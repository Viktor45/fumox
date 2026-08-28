//! `fetch_log` journal: one row per source fetch attempt.

use crate::db::DbPool;
use crate::models::ErrorClass;
use sqlx::FromRow;

#[derive(Debug, Clone, FromRow)]
pub struct FetchLogRow {
    pub id: i64,
    pub source_id: String,
    pub fetched_at: i64,
    pub ok: i64,
    pub http_status: Option<i64>,
    pub bytes: Option<i64>,
    pub proxies_found: Option<i64>,
    pub error: Option<String>,
    pub error_class: Option<String>,
}

/// One fetch attempt to be journaled.
#[derive(Debug, Clone)]
pub struct FetchLogEntry<'a> {
    pub source_id: &'a str,
    pub fetched_at: i64,
    pub ok: bool,
    pub http_status: Option<i64>,
    pub bytes: Option<i64>,
    pub proxies_found: Option<i64>,
    pub error: Option<&'a str>,
    pub error_class: Option<ErrorClass>,
}

pub async fn insert(pool: &DbPool, entry: &FetchLogEntry<'_>) -> crate::Result<()> {
    sqlx::query(
        "INSERT INTO fetch_log
            (source_id, fetched_at, ok, http_status, bytes, proxies_found, error, error_class)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(entry.source_id)
    .bind(entry.fetched_at)
    .bind(entry.ok)
    .bind(entry.http_status)
    .bind(entry.bytes)
    .bind(entry.proxies_found)
    .bind(entry.error)
    .bind(entry.error_class.map(ErrorClass::as_str))
    .execute(pool)
    .await?;
    Ok(())
}

/// Most recent fetches of one source, newest first.
pub async fn recent_for_source(
    pool: &DbPool,
    source_id: &str,
    limit: i64,
) -> crate::Result<Vec<FetchLogRow>> {
    let rows = sqlx::query_as(
        "SELECT * FROM fetch_log WHERE source_id = ? ORDER BY fetched_at DESC, id DESC LIMIT ?",
    )
    .bind(source_id)
    .bind(limit)
    .fetch_all(pool)
    .await?;
    Ok(rows)
}

/// Global journal across all sources, newest first (admin screen).
pub async fn recent_global(pool: &DbPool, limit: i64) -> crate::Result<Vec<FetchLogRow>> {
    let rows = sqlx::query_as("SELECT * FROM fetch_log ORDER BY fetched_at DESC, id DESC LIMIT ?")
        .bind(limit)
        .fetch_all(pool)
        .await?;
    Ok(rows)
}

/// Delete journal entries older than the cutoff (retention, SPEC §12).
pub async fn purge_before(pool: &DbPool, cutoff: i64) -> crate::Result<u64> {
    let affected = sqlx::query("DELETE FROM fetch_log WHERE fetched_at < ?")
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
    async fn insert_and_query_journal() {
        let pool = temp_pool().await;
        // fetch_log has an FK to sources; create the parent row first.
        sqlx::query(
            "INSERT INTO sources (id, name, url, created_at, updated_at)
             VALUES ('srcA0000000', 's', 'https://e.x', 1, 1)",
        )
        .execute(&pool)
        .await
        .unwrap();

        insert(
            &pool,
            &FetchLogEntry {
                source_id: "srcA0000000",
                fetched_at: 1000,
                ok: true,
                http_status: Some(200),
                bytes: Some(2048),
                proxies_found: Some(42),
                error: None,
                error_class: None,
            },
        )
        .await
        .unwrap();
        insert(
            &pool,
            &FetchLogEntry {
                source_id: "srcA0000000",
                fetched_at: 2000,
                ok: false,
                http_status: None,
                bytes: None,
                proxies_found: None,
                error: Some("timeout"),
                error_class: Some(ErrorClass::Network),
            },
        )
        .await
        .unwrap();

        let rows = recent_for_source(&pool, "srcA0000000", 10).await.unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].fetched_at, 2000); // newest first
        assert_eq!(rows[0].error_class.as_deref(), Some("network"));
        assert_eq!(rows[1].proxies_found, Some(42));

        assert_eq!(recent_global(&pool, 10).await.unwrap().len(), 2);
        assert_eq!(purge_before(&pool, 1500).await.unwrap(), 1);
        assert_eq!(recent_global(&pool, 10).await.unwrap().len(), 1);
    }
}
