//! `fetch_log` journal: one row per source fetch attempt.

use super::BindWhereFilter;
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
    /// Measured wall-clock duration of the fetch attempt in milliseconds
    /// (retries and their backoff included); `None` for rows written
    /// without a measurement (older versions, test fixtures).
    pub duration_ms: Option<i64>,
}

/// One fetch attempt to be journaled.
///
/// Deliberately without a duration field: the measurement belongs to the
/// call that made the attempt, so it travels through [`insert_timed`] as
/// its own argument and callers without a measurement keep using
/// [`insert`] unchanged.
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
    insert_timed(pool, entry, None).await
}

/// Journal one fetch attempt together with its measured duration in
/// milliseconds (`fetch_log.duration_ms`).
pub async fn insert_timed(
    pool: &DbPool,
    entry: &FetchLogEntry<'_>,
    duration_ms: Option<i64>,
) -> crate::Result<()> {
    sqlx::query(
        "INSERT INTO fetch_log
            (source_id, fetched_at, ok, http_status, bytes, proxies_found, error, error_class,
             duration_ms)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(entry.source_id)
    .bind(entry.fetched_at)
    .bind(entry.ok)
    .bind(entry.http_status)
    .bind(entry.bytes)
    .bind(entry.proxies_found)
    .bind(entry.error)
    .bind(entry.error_class.map(ErrorClass::as_str))
    .bind(duration_ms)
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

// Admin fetch-journal screen
//
// The dynamic list screen: filter clauses are whitelisted fragments
// assembled through the shared [`super::WhereFilter`], every value flows
// through a bind. The count and the page query share one
// [`FetchLogFilter::where_filter`], so their clause sets cannot drift.

/// One row of the global fetch journal screen, joined with the source
/// display name (`source_name` is NULL when the source row is gone).
#[derive(Debug, Clone, FromRow)]
pub struct FetchLogListRow {
    pub source_id: String,
    pub source_name: Option<String>,
    pub fetched_at: i64,
    pub ok: i64,
    pub http_status: Option<i64>,
    pub bytes: Option<i64>,
    pub proxies_found: Option<i64>,
    pub error: Option<String>,
    pub error_class: Option<String>,
    /// Measured fetch duration in milliseconds; `None` when the row was
    /// written without a measurement.
    pub duration_ms: Option<i64>,
}

/// Filter parameters of the global fetch journal ([`count_filtered`] /
/// [`list_page`]). An empty string or `None` means "no constraint" for
/// that field.
#[derive(Debug, Clone, Default)]
pub struct FetchLogFilter {
    /// `Some(true)` = successful fetches only, `Some(false)` = failures
    /// only.
    pub ok: Option<bool>,
    /// Exact error-class match (`network`, `http`, …).
    pub error_class: String,
    /// Restrict the journal to one source.
    pub source_id: String,
}

impl FetchLogFilter {
    /// The WHERE fragment and bound values shared by [`count_filtered`]
    /// and [`list_page`]: the one place the journal's dynamic clause set
    /// is defined.
    fn where_filter(&self) -> super::WhereFilter {
        let mut wf = super::WhereFilter::new();
        match self.ok {
            Some(true) => wf = wf.clause("f.ok = 1"),
            Some(false) => wf = wf.clause("f.ok = 0"),
            None => {}
        }
        if !self.error_class.is_empty() {
            wf = wf.text("f.error_class = ?", &self.error_class);
        }
        if !self.source_id.is_empty() {
            wf = wf.text("f.source_id = ?", &self.source_id);
        }
        wf
    }
}

/// Count the journal rows the admin screen would show for `filter` — the
/// same clause set [`list_page`] applies.
pub async fn count_filtered(pool: &DbPool, filter: &FetchLogFilter) -> crate::Result<i64> {
    let wf = filter.where_filter();
    let sql = format!("SELECT COUNT(*) FROM fetch_log f{}", wf.sql());
    let count = sqlx::query_scalar::<_, i64>(sqlx::AssertSqlSafe(sql))
        .bind_where_filter(wf.values())
        .fetch_one(pool)
        .await?;
    Ok(count)
}

/// One page of the global journal for `filter`, newest first, joined with
/// the source display name. `offset` is the plain SQL OFFSET.
pub async fn list_page(
    pool: &DbPool,
    filter: &FetchLogFilter,
    limit: i64,
    offset: i64,
) -> crate::Result<Vec<FetchLogListRow>> {
    let wf = filter.where_filter();
    let sql = format!(
        "SELECT f.source_id, s.name AS source_name, f.fetched_at, f.ok,
                f.http_status, f.bytes, f.proxies_found, f.error, f.error_class, f.duration_ms
         FROM fetch_log f LEFT JOIN sources s ON s.id = f.source_id
         {}
         ORDER BY f.fetched_at DESC, f.id DESC
         LIMIT ? OFFSET ?",
        wf.sql()
    );
    let rows = sqlx::query_as::<_, FetchLogListRow>(sqlx::AssertSqlSafe(sql))
        .bind_where_filter(wf.values())
        .bind(limit)
        .bind(offset)
        .fetch_all(pool)
        .await?;
    Ok(rows)
}

/// Total journal rows of one source (source-card pagination).
pub async fn count_for_source(pool: &DbPool, source_id: &str) -> crate::Result<i64> {
    let (count,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM fetch_log WHERE source_id = ?")
        .bind(source_id)
        .fetch_one(pool)
        .await?;
    Ok(count)
}

/// One page of one source's journal, newest first (source-card log).
/// `offset` is the plain SQL OFFSET.
pub async fn list_for_source(
    pool: &DbPool,
    source_id: &str,
    limit: i64,
    offset: i64,
) -> crate::Result<Vec<FetchLogRow>> {
    let rows: Vec<FetchLogRow> = sqlx::query_as(
        "SELECT * FROM fetch_log WHERE source_id = ?
         ORDER BY fetched_at DESC, id DESC LIMIT ? OFFSET ?",
    )
    .bind(source_id)
    .bind(limit)
    .bind(offset)
    .fetch_all(pool)
    .await?;
    Ok(rows)
}

/// Delete journal entries older than the cutoff (retention).
pub async fn purge_before(pool: &DbPool, cutoff: i64) -> crate::Result<u64> {
    let affected = sqlx::query("DELETE FROM fetch_log WHERE fetched_at < ?")
        .bind(cutoff)
        .execute(pool)
        .await?
        .rows_affected();
    Ok(affected)
}

/// Total journal size. Reported on the probe page next to the rotation
/// stamp: a fresh stamp on a table that keeps growing is still a leak.
pub async fn count_all(pool: &DbPool) -> crate::Result<i64> {
    let (count,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM fetch_log")
        .fetch_one(pool)
        .await?;
    Ok(count)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::repo::tests::temp_pool;

    #[tokio::test]
    async fn insert_and_query_journal() {
        let (_dir, pool) = temp_pool().await;
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

    /// The measured fetch duration round-trips through `insert_timed` into
    /// the read-side rows; `insert` (no measurement) leaves the column NULL.
    #[tokio::test]
    async fn duration_round_trips() {
        let (_dir, pool) = temp_pool().await;
        sqlx::query(
            "INSERT INTO sources (id, name, url, created_at, updated_at)
             VALUES ('srcA0000000', 's', 'https://e.x', 1, 1)",
        )
        .execute(&pool)
        .await
        .unwrap();

        let entry = FetchLogEntry {
            source_id: "srcA0000000",
            fetched_at: 1000,
            ok: true,
            http_status: Some(200),
            bytes: Some(10),
            proxies_found: Some(1),
            error: None,
            error_class: None,
        };
        insert(&pool, &entry).await.unwrap();
        insert_timed(&pool, &entry, Some(1234)).await.unwrap();

        // Same fetched_at, so insertion order (id DESC) decides: the newest
        // row is the timed one.
        let rows = recent_for_source(&pool, "srcA0000000", 10).await.unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].duration_ms, Some(1234));
        assert_eq!(rows[1].duration_ms, None);

        let page = list_page(&pool, &FetchLogFilter::default(), 10, 0)
            .await
            .unwrap();
        assert_eq!(page.len(), 2);
        assert_eq!(page[0].duration_ms, Some(1234));
        assert_eq!(page[1].duration_ms, None);
    }

    /// The admin journal screen: count and page apply the same filter
    /// clauses, the source join resolves display names, and the
    /// per-source pagination of the source card works.
    #[tokio::test]
    async fn admin_journal_filters_and_pagination() {
        let (_dir, pool) = temp_pool().await;
        for (id, name) in [("srcA0000000", "Alpha"), ("srcB0000000", "Beta")] {
            sqlx::query(
                "INSERT INTO sources (id, name, url, created_at, updated_at)
                         VALUES (?, ?, 'https://e.x', 1, 1)",
            )
            .bind(id)
            .bind(name)
            .execute(&pool)
            .await
            .unwrap();
        }
        // (fetched_at, source, ok, error_class) — four attempts.
        let rows = [
            (1000, "srcA0000000", 1, None),
            (1001, "srcA0000000", 0, Some("network")),
            (1002, "srcA0000000", 1, None),
            (1003, "srcB0000000", 1, None),
        ];
        for (at, source, ok, class) in rows {
            sqlx::query(
                "INSERT INTO fetch_log (source_id, fetched_at, ok, error_class)
                 VALUES (?, ?, ?, ?)",
            )
            .bind(source)
            .bind(at)
            .bind(ok)
            .bind(class)
            .execute(&pool)
            .await
            .unwrap();
        }

        // Unfiltered: count and page agree, newest first, names resolved.
        let filter = FetchLogFilter::default();
        assert_eq!(count_filtered(&pool, &filter).await.unwrap(), 4);
        let page = list_page(&pool, &filter, 10, 0).await.unwrap();
        assert_eq!(
            page.iter().map(|r| r.fetched_at).collect::<Vec<_>>(),
            vec![1003, 1002, 1001, 1000]
        );
        assert_eq!(page[0].source_name.as_deref(), Some("Beta"));

        // Result filter.
        let filter = FetchLogFilter {
            ok: Some(false),
            ..Default::default()
        };
        assert_eq!(count_filtered(&pool, &filter).await.unwrap(), 1);
        let page = list_page(&pool, &filter, 10, 0).await.unwrap();
        assert_eq!(page[0].fetched_at, 1001);
        let filter = FetchLogFilter {
            ok: Some(true),
            ..Default::default()
        };
        assert_eq!(count_filtered(&pool, &filter).await.unwrap(), 3);

        // Error class and source filters, combined.
        let filter = FetchLogFilter {
            error_class: "network".into(),
            ..Default::default()
        };
        assert_eq!(count_filtered(&pool, &filter).await.unwrap(), 1);
        let filter = FetchLogFilter {
            source_id: "srcA0000000".into(),
            ..Default::default()
        };
        assert_eq!(count_filtered(&pool, &filter).await.unwrap(), 3);
        let filter = FetchLogFilter {
            source_id: "srcA0000000".into(),
            ok: Some(false),
            ..Default::default()
        };
        assert_eq!(count_filtered(&pool, &filter).await.unwrap(), 1);

        // Pagination windows.
        let page = list_page(&pool, &FetchLogFilter::default(), 2, 0)
            .await
            .unwrap();
        assert_eq!(
            page.iter().map(|r| r.fetched_at).collect::<Vec<_>>(),
            vec![1003, 1002]
        );
        let page = list_page(&pool, &FetchLogFilter::default(), 2, 2)
            .await
            .unwrap();
        assert_eq!(
            page.iter().map(|r| r.fetched_at).collect::<Vec<_>>(),
            vec![1001, 1000]
        );

        // Source-card pagination.
        assert_eq!(count_for_source(&pool, "srcA0000000").await.unwrap(), 3);
        let page = list_for_source(&pool, "srcA0000000", 2, 0).await.unwrap();
        assert_eq!(
            page.iter().map(|r| r.fetched_at).collect::<Vec<_>>(),
            vec![1002, 1001]
        );
    }
}
