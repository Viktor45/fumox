//! Repository layer: typed async access to the SQLite schema.
//!
//! Free async functions grouped by table family; every multi-statement
//! operation runs in its own transaction. Rows are mapped onto the domain
//! models from [`crate::models`] manually, the schema stores booleans as
//! integers and structured fields as JSON text, so the mapping is explicit.

pub mod fetch_log;
pub mod probe;
pub mod profiles;
pub mod proxies;
pub mod sources;

use crate::db::DbPool;
use sqlx::Sqlite;
use sqlx::sqlite::SqliteArguments;

/// Dynamic WHERE-clause accumulator shared by the admin list filters of
/// this module tree: the single copy of the "whitelist the fragment, bind
/// the value" pattern the admin handlers used to re-implement per screen.
///
/// Every clause is a compile-time constant of this crate (a whitelist
/// bucket or a fixed predicate over one table family); the only
/// caller-controlled content is the text value each clause binds, and
/// those travel through `.bind()`, never into the SQL text. The count and
/// list queries of one family build their clauses through the family's
/// own `where_filter()` method, so clause order and bind order cannot
/// drift apart between the two statements.
#[derive(Debug, Default)]
pub(crate) struct WhereFilter {
    clauses: Vec<String>,
    values: Vec<String>,
}

impl WhereFilter {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Append a clause without bound values (`s.enabled = 1`, an EXISTS
    /// fragment from a whitelist bucket).
    pub(crate) fn clause(mut self, clause: impl Into<String>) -> Self {
        self.clauses.push(clause.into());
        self
    }

    /// Append a clause that binds one text value.
    pub(crate) fn text(mut self, clause: &str, value: impl Into<String>) -> Self {
        self.clauses.push(clause.to_string());
        self.values.push(value.into());
        self
    }

    /// Append one more bound text value without a clause of its own; for
    /// predicates that repeat a value under several `?` placeholders
    /// (`(host LIKE ? OR name LIKE ?)`).
    pub(crate) fn text_value(mut self, value: impl Into<String>) -> Self {
        self.values.push(value.into());
        self
    }

    /// Append an `IN (?, ?, …)` clause over `column`, one placeholder per
    /// element, bound in order. `values` must not be empty: an empty SQL
    /// `IN ()` list is a syntax error, and the family builders only call
    /// this after their own emptiness guard.
    pub(crate) fn text_in(mut self, column: &str, values: &[String]) -> Self {
        let placeholders = vec!["?"; values.len()].join(", ");
        self.clauses.push(format!("{column} IN ({placeholders})"));
        self.values.extend(values.iter().cloned());
        self
    }

    /// The joined WHERE fragment: `""` when no clause was pushed, else
    /// `" WHERE a AND b"`.
    pub(crate) fn sql(&self) -> String {
        if self.clauses.is_empty() {
            String::new()
        } else {
            format!(" WHERE {}", self.clauses.join(" AND "))
        }
    }

    /// The bound values in clause order; each fills the `?` placeholder
    /// of the clause it was pushed with.
    pub(crate) fn values(&self) -> &[String] {
        &self.values
    }
}

/// Apply the bound values of a [`WhereFilter`] to a sqlx query builder,
/// in clause order. A local trait because `bind` is an inherent method
/// returning `Self` on the sibling query constructors (`query_as`,
/// `query_scalar`), which share no interface to call it through. The
/// lifetime parameter ties the values slice to the query's argument
/// lifetime: a bound value must outlive the query it feeds.
pub(crate) trait BindWhereFilter<'a>: Sized {
    fn bind_where_filter(self, values: &'a [String]) -> Self;
}

impl<'q, O> BindWhereFilter<'q> for sqlx::query::QueryAs<'q, Sqlite, O, SqliteArguments> {
    fn bind_where_filter(mut self, values: &'q [String]) -> Self {
        for value in values {
            self = self.bind(value.as_str());
        }
        self
    }
}

impl<'q, O> BindWhereFilter<'q> for sqlx::query::QueryScalar<'q, Sqlite, O, SqliteArguments> {
    fn bind_where_filter(mut self, values: &'q [String]) -> Self {
        for value in values {
            self = self.bind(value.as_str());
        }
        self
    }
}

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

/// Atomically increment an integer counter key in `meta`, creating it at 1
/// when absent, and return the new value. A single upsert, so two
/// concurrent callers each observe their own bump — a `meta_get` +
/// `meta_set` pair would race them onto the same value. A pre-existing
/// non-integer value casts to 0 and self-heals from 1. Stored through the
/// TEXT-affinity column, so `meta_get` still reads the number back as text.
pub async fn meta_increment(pool: &DbPool, key: &str) -> crate::Result<i64> {
    let row: (i64,) = sqlx::query_as(
        "INSERT INTO meta (key, value) VALUES (?, '1')
         ON CONFLICT(key) DO UPDATE SET value = CAST(value AS INTEGER) + 1
         RETURNING CAST(value AS INTEGER)",
    )
    .bind(key)
    .fetch_one(pool)
    .await?;
    Ok(row.0)
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

    /// Fresh migrated pool on a scoped temp database: keep the returned
    /// guard in scope (`let (_dir, pool) = temp_pool().await`) and the
    /// whole directory — database included — is removed when it drops.
    pub(crate) async fn temp_pool() -> (crate::tempdir_lite::TempDir, DbPool) {
        let dir = crate::tempdir_lite::TempDir::new("repo");
        let cfg = crate::config::DatabaseConfig {
            path: dir.path().join("test.db"),
            ..Default::default()
        };
        let pool = db::connect_pool(&cfg).await.unwrap();
        db::migrate(&pool).await.unwrap();
        (dir, pool)
    }

    #[tokio::test]
    async fn meta_round_trip() {
        let (_dir, pool) = temp_pool().await;
        assert_eq!(meta_get(&pool, "absent").await.unwrap(), None);
        meta_set(&pool, "k", "v1").await.unwrap();
        assert_eq!(meta_get(&pool, "k").await.unwrap().as_deref(), Some("v1"));
        meta_set(&pool, "k", "v2").await.unwrap();
        assert_eq!(meta_get(&pool, "k").await.unwrap().as_deref(), Some("v2"));
    }

    #[tokio::test]
    async fn meta_increment_counts_and_bootstraps() {
        let (_dir, pool) = temp_pool().await;
        assert_eq!(meta_increment(&pool, "counter").await.unwrap(), 1);
        assert_eq!(meta_increment(&pool, "counter").await.unwrap(), 2);
        // Keys are independent.
        assert_eq!(meta_increment(&pool, "other").await.unwrap(), 1);
        // A non-integer value casts to 0 and self-heals from 1.
        meta_set(&pool, "corrupt", "not-a-number").await.unwrap();
        assert_eq!(meta_increment(&pool, "corrupt").await.unwrap(), 1);
        // Stored through the TEXT-affinity column: meta_get reads it back.
        assert_eq!(
            meta_get(&pool, "counter").await.unwrap().as_deref(),
            Some("2")
        );
    }

    #[tokio::test]
    async fn migrations_create_full_schema() {
        let (_dir, pool) = temp_pool().await;

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
            "idx_proxies_ladder",
            "idx_probe_t2_last",
            "idx_proxies_t2_block",
            "idx_speed_proxy_time",
            "idx_fetch_source_time",
            "idx_fetch_time",
            "idx_proxies_updated_at",
        ] {
            assert!(indexes.contains(&expected), "missing index {expected}");
        }

        // Schema version is stamped into meta by db::migrate. Bumped to 9
        // by migration 0009 (fetch_log.duration_ms).
        let version = meta_get(&pool, "schema_version").await.unwrap();
        assert_eq!(version.as_deref(), Some("9"));

        // WAL is active on the connection.
        let (journal_mode,): (String,) = sqlx::query_as("PRAGMA journal_mode")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(journal_mode, "wal");
    }

    /// Migration 0005 must carry the old fixed-ladder schedule over to the
    /// generic `ladder_at`/`ladder_step` columns: every quarantined row
    /// keeps its scheduled moment and its ladder position, and the old
    /// columns are gone afterwards.
    #[tokio::test]
    async fn migration_0005_preserves_quarantine_ladder_schedule() {
        use sqlx::migrate::Migrator;
        static MIGRATOR: Migrator = sqlx::migrate!("./migrations");

        let dir = std::env::temp_dir().join(format!("fumox-mig-{}", crate::models::new_id()));
        std::fs::create_dir_all(&dir).unwrap();
        let cfg = crate::config::DatabaseConfig {
            path: dir.join("test.db"),
            ..Default::default()
        };
        let pool = db::connect_pool(&cfg).await.unwrap();

        // Apply the pre-ladder schema (0001..0004) by hand, without the
        // migration stamping, so 0005 can be applied separately below.
        for migration in MIGRATOR.migrations.iter().filter(|m| m.version <= 4) {
            sqlx::raw_sql(migration.sql.clone())
                .execute(&pool)
                .await
                .unwrap();
        }

        // Quarantined rows on every old schedule column, plus an alive row
        // without any schedule.
        sqlx::query(
            "INSERT INTO proxies (fingerprint, scheme, host, port, status,
                                  quarantined_at, second_chance_at, created_at, updated_at)
             VALUES ('fp-sc', 'vless', 'sc.example.com', 443, 'quarantine', 1500, 9000, 1, 1)",
        )
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO proxies (fingerprint, scheme, host, port, status,
                                  quarantined_at, recheck_15m_at, created_at, updated_at)
             VALUES ('fp-r15', 'vless', 'r15.example.com', 443, 'quarantine', 1500, 2400, 1, 1)",
        )
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO proxies (fingerprint, scheme, host, port, status,
                                  quarantined_at, recheck_30m_at, created_at, updated_at)
             VALUES ('fp-r30', 'vless', 'r30.example.com', 443, 'quarantine', 1500, 3300, 1, 1)",
        )
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO proxies (fingerprint, scheme, host, port, status,
                                  quarantined_at, recheck_1h_at, created_at, updated_at)
             VALUES ('fp-r1h', 'vless', 'r1h.example.com', 443, 'quarantine', 1500, 5100, 1, 1)",
        )
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO proxies (fingerprint, scheme, host, port, status, created_at, updated_at)
             VALUES ('fp-alive', 'vless', 'alive.example.com', 443, 'alive', 1, 1)",
        )
        .execute(&pool)
        .await
        .unwrap();

        let fifth = MIGRATOR
            .migrations
            .iter()
            .find(|m| m.version == 5)
            .expect("migration 0005 missing");
        sqlx::raw_sql(fifth.sql.clone())
            .execute(&pool)
            .await
            .unwrap();

        let rows: Vec<(String, Option<i64>, i64)> = sqlx::query_as(
            "SELECT fingerprint, ladder_at, ladder_step FROM proxies ORDER BY fingerprint",
        )
        .fetch_all(&pool)
        .await
        .unwrap();
        let by_fp: std::collections::HashMap<String, (Option<i64>, i64)> = rows
            .into_iter()
            .map(|(fp, at, step)| (fp, (at, step)))
            .collect();
        // second_chance_at → step 0; each recheck column → its step index.
        assert_eq!(by_fp["fp-sc"], (Some(9000), 0));
        assert_eq!(by_fp["fp-r15"], (Some(2400), 1));
        assert_eq!(by_fp["fp-r30"], (Some(3300), 2));
        assert_eq!(by_fp["fp-r1h"], (Some(5100), 3));
        assert_eq!(by_fp["fp-alive"], (None, 0));

        // The old columns are dropped.
        assert!(
            sqlx::query("SELECT second_chance_at FROM proxies")
                .execute(&pool)
                .await
                .is_err()
        );

        pool.close().await;
        let _ = std::fs::remove_dir_all(&dir);
    }
}
