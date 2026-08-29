//! Repository layer: typed async access to the SQLite schema.
//!
//! Free async functions grouped by table family; every multi-statement
//! operation runs in its own transaction. Rows are mapped onto the domain
//! models from [`crate::models`] manually — the schema stores booleans as
//! integers and structured fields as JSON text, so the mapping is explicit.

pub mod fetch_log;
pub mod probe;
pub mod profiles;
pub mod proxies;
pub mod sources;

use crate::db::DbPool;

/// Read a service key from `meta`.
pub async fn meta_get(pool: &DbPool, key: &str) -> crate::Result<Option<String>> {
    let row: Option<(String,)> = sqlx::query_as("SELECT value FROM meta WHERE key = ?")
        .bind(key)
        .fetch_optional(pool)
        .await?;
    Ok(row.map(|(value,)| value))
}

/// Upsert a service key in `meta`.
pub async fn meta_set(pool: &DbPool, key: &str, value: &str) -> crate::Result<()> {
    sqlx::query(
        "INSERT INTO meta (key, value) VALUES (?, ?)
         ON CONFLICT(key) DO UPDATE SET value = excluded.value",
    )
    .bind(key)
    .bind(value)
    .execute(pool)
    .await?;
    Ok(())
}

/// Serialize a JSON column value, mapping serialization errors into the
/// core error type (in practice unreachable for the values we store).
pub(crate) fn json_to_text(value: &serde_json::Value) -> crate::Result<String> {
    serde_json::to_string(value)
        .map_err(|e| crate::Error::Parse(format!("cannot serialize JSON column: {e}")))
}

/// Parse a JSON column value.
pub(crate) fn text_to_json(text: &str, column: &str) -> crate::Result<serde_json::Value> {
    serde_json::from_str(text)
        .map_err(|e| crate::Error::Parse(format!("corrupt JSON in column {column}: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db;

    pub(crate) async fn temp_pool() -> DbPool {
        let dir = std::env::temp_dir().join(format!("fumox-test-{}", crate::models::new_id()));
        std::fs::create_dir_all(&dir).unwrap();
        let cfg = crate::config::DatabaseConfig {
            path: dir.join("test.db"),
            ..Default::default()
        };
        let pool = db::connect_pool(&cfg).await.unwrap();
        db::migrate(&pool).await.unwrap();
        pool
    }

    #[tokio::test]
    async fn meta_round_trip() {
        let pool = temp_pool().await;
        assert_eq!(meta_get(&pool, "absent").await.unwrap(), None);
        meta_set(&pool, "k", "v1").await.unwrap();
        assert_eq!(meta_get(&pool, "k").await.unwrap().as_deref(), Some("v1"));
        meta_set(&pool, "k", "v2").await.unwrap();
        assert_eq!(meta_get(&pool, "k").await.unwrap().as_deref(), Some("v2"));
    }

    #[tokio::test]
    async fn migrations_create_full_schema() {
        let pool = temp_pool().await;

        let tables: Vec<(String,)> = sqlx::query_as(
            "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY name",
        )
        .fetch_all(&pool)
        .await
        .unwrap();
        let tables: Vec<&str> = tables.iter().map(|(name,)| name.as_str()).collect();
        for expected in [
            "sources",
            "profiles",
            "profile_sources",
            "proxies",
            "proxy_source_links",
            "probe_results",
            "probe_requests",
            "speed_results",
            "fetch_log",
            "meta",
            "_sqlx_migrations",
        ] {
            assert!(tables.contains(&expected), "missing table {expected}");
        }

        let indexes: Vec<(String,)> = sqlx::query_as(
            "SELECT name FROM sqlite_master WHERE type = 'index' AND name LIKE 'idx_%' ORDER BY name",
        )
        .fetch_all(&pool)
        .await
        .unwrap();
        let indexes: Vec<&str> = indexes.iter().map(|(name,)| name.as_str()).collect();
        for expected in [
            "idx_sources_enabled",
            "idx_proxies_status",
            "idx_proxies_hostport",
            "idx_proxies_scheme",
            "idx_proxies_country",
            "idx_links_source",
            "idx_probe_proxy_time",
            "idx_probe_time",
            "idx_probe_requests_time",
            "idx_speed_proxy_time",
            "idx_fetch_source_time",
            "idx_fetch_time",
        ] {
            assert!(indexes.contains(&expected), "missing index {expected}");
        }

        // Schema version is stamped into meta by db::migrate.
        let version = meta_get(&pool, "schema_version").await.unwrap();
        assert_eq!(version.as_deref(), Some("2"));

        // WAL is active on the connection.
        let (journal_mode,): (String,) = sqlx::query_as("PRAGMA journal_mode")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(journal_mode, "wal");
    }
}
