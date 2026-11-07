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
pub mod retention;
pub mod sources;

use crate::db::DbPool;
use sqlx::Sqlite;
use sqlx::sqlite::SqliteArguments;
use std::collections::HashMap;

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
        debug_assert!(
            !values.is_empty(),
            "WhereFilter::text_in requires a non-empty value list"
        );
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
///
/// The executor is generic so the read can join a caller's transaction
/// (the admin dashboard reads every key inside one snapshot) or run on
/// the pool on its own.
pub async fn meta_get<'e, E>(executor: E, key: &str) -> crate::Result<Option<String>>
where
    E: sqlx::Executor<'e, Database = sqlx::Sqlite>,
{
    let row: Option<(String,)> = sqlx::query_as("SELECT value FROM meta WHERE key = ?")
        .bind(key)
        .fetch_optional(executor)
        .await?;
    Ok(row.map(|(value,)| value))
}

/// Read several service keys from `meta` in one query.
///
/// The admin panel reads the four probe stamps on every render; four
/// round trips are four chances to queue behind a write, and none of
/// them depends on another. A key without a row is simply absent from
/// the map, so the caller tells "no record" from "no value" the same
/// way it does with [`meta_get`].
pub async fn meta_get_many<'e, E>(
    executor: E,
    keys: &[&str],
) -> crate::Result<HashMap<String, String>>
where
    E: sqlx::Executor<'e, Database = sqlx::Sqlite>,
{
    if keys.is_empty() {
        return Ok(HashMap::new());
    }
    let mut query = sqlx::QueryBuilder::<Sqlite>::new("SELECT key, value FROM meta WHERE key IN (");
    {
        let mut separated = query.separated(", ");
        for key in keys {
            separated.push_bind(*key);
        }
        separated.push_unseparated(")");
    }
    let rows: Vec<(String, String)> = query.build_query_as().fetch_all(executor).await?;
    Ok(rows.into_iter().collect())
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
/// concurrent callers each observe their own bump: a `meta_get` +
/// `meta_set` pair would race them onto the same value. A pre-existing
/// non-integer value casts to 0 and self-heals from 1 — the heal rewrites
/// the stored text silently, so it is logged with the key and the value it
/// replaced. Stored through the TEXT-affinity column, so `meta_get` still
/// reads the number back as text.
pub async fn meta_increment(pool: &DbPool, key: &str) -> crate::Result<i64> {
    let previous: Option<(String,)> = sqlx::query_as("SELECT value FROM meta WHERE key = ?")
        .bind(key)
        .fetch_optional(pool)
        .await?;
    if let Some((previous,)) = previous
        && previous.parse::<i64>().is_err()
    {
        tracing::warn!(
            key,
            previous_value = %previous,
            "meta_increment: non-integer counter casts to 0 and self-heals from 1"
        );
    }
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

/// Parse a JSON column value. `row_id` names the row the column was read
/// from, so the error points at the broken row instead of just the broken
/// column.
pub(crate) fn text_to_json(
    text: &str,
    column: &str,
    row_id: &str,
) -> crate::Result<serde_json::Value> {
    serde_json::from_str(text).map_err(|e| {
        crate::Error::Parse(format!(
            "corrupt JSON in column {column} of row {row_id}: {e}"
        ))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db;

    /// Fresh migrated pool on a scoped temp database: keep the returned
    /// guard in scope (`let (_dir, pool) = temp_pool().await`) and the
    /// whole directory, database included, is removed when it drops.
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

    /// The upsert is the whole increment: 16 callers firing concurrently
    /// observe 16 distinct values, so a lost update (two callers landing on
    /// the same bump) is impossible by construction.
    #[tokio::test]
    async fn meta_increment_is_atomic_under_concurrent_callers() {
        let (_dir, pool) = temp_pool().await;
        let mut handles = Vec::new();
        for _ in 0..16 {
            let pool = pool.clone();
            handles.push(tokio::spawn(
                async move { meta_increment(&pool, "k").await },
            ));
        }
        let mut values: Vec<i64> = Vec::new();
        for handle in handles {
            values.push(handle.await.unwrap().unwrap());
        }
        values.sort_unstable();
        assert_eq!(
            values,
            (1..=16).collect::<Vec<i64>>(),
            "every caller must observe its own bump"
        );
    }

    /// The `IN`-clause builder: one placeholder per element, values bound
    /// in list order.
    #[test]
    fn where_filter_text_in_binds_every_element() {
        let wf = WhereFilter::new().text_in("col", &["a".into(), "b".into()]);
        assert_eq!(wf.sql(), " WHERE col IN (?, ?)");
        assert_eq!(wf.values(), ["a".to_string(), "b".to_string()].as_slice());
    }

    /// The fragments accumulate in push order, both in the SQL text and in
    /// the bound values.
    #[test]
    fn where_filter_keeps_the_push_order() {
        let wf = WhereFilter::new()
            .clause("s.enabled = 1")
            .text("s.name = ?", "first")
            .text_value("second");
        assert_eq!(wf.sql(), " WHERE s.enabled = 1 AND s.name = ?");
        assert_eq!(
            wf.values(),
            ["first".to_string(), "second".to_string()].as_slice()
        );
    }

    /// A caller-supplied value never enters the SQL text: a value with
    /// quotes travels through the bind, so it cannot change the clause.
    #[test]
    fn where_filter_value_with_quotes_stays_out_of_the_sql_text() {
        let wf = WhereFilter::new().text("s.name = ?", "it's \"quoted\"");
        assert_eq!(wf.sql(), " WHERE s.name = ?");
        assert_eq!(wf.values(), ["it's \"quoted\"".to_string()].as_slice());
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
        // Subset check: a migration adding a table/index must extend these
        // lists — the version assert below is the only tripwire forcing an
        // update here.
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
            "idx_fetch_time_id",
            "idx_fetch_fail",
            "idx_fetch_error_class",
            "idx_proxies_updated_at",
            "idx_proxies_geo_attempt",
            "idx_proxies_last_t2_checked_at",
        ] {
            assert!(indexes.contains(&expected), "missing index {expected}");
        }

        // The denormalised T2 recency stamp is on the proxy row.
        let columns: Vec<(String,)> =
            sqlx::query_as("SELECT name FROM pragma_table_info('proxies')")
                .fetch_all(&pool)
                .await
                .unwrap();
        let columns: Vec<&str> = columns.iter().map(|(name,)| name.as_str()).collect();
        assert!(
            columns.contains(&"last_t2_checked_at"),
            "the proxy row must carry the T2 recency stamp"
        );

        // Schema version is stamped into meta by db::migrate. Bumped to 20
        // by migration 0020 (the fetch journal keyset index, which replaces
        // idx_fetch_time — a strict prefix of the new composite; 0019 was
        // the sources access token).
        let version = meta_get(&pool, "schema_version").await.unwrap();
        assert_eq!(version.as_deref(), Some("20"));

        // The fetch-attempt stamp of migration 0015 is on the source row.
        let source_columns: Vec<(String,)> =
            sqlx::query_as("SELECT name FROM pragma_table_info('sources')")
                .fetch_all(&pool)
                .await
                .unwrap();
        let source_columns: Vec<&str> =
            source_columns.iter().map(|(name,)| name.as_str()).collect();
        assert!(
            source_columns.contains(&"last_attempt_at"),
            "the source row must carry the fetch-attempt stamp"
        );

        // The attempt count of migration 0016 is on the journal row.
        let journal_columns: Vec<(String,)> =
            sqlx::query_as("SELECT name FROM pragma_table_info('fetch_log')")
                .fetch_all(&pool)
                .await
                .unwrap();
        let journal_columns: Vec<&str> = journal_columns
            .iter()
            .map(|(name,)| name.as_str())
            .collect();
        assert!(
            journal_columns.contains(&"attempts"),
            "the journal row must carry the attempt count"
        );

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

        let dir = crate::tempdir_lite::TempDir::new("fumox-mig");
        let cfg = crate::config::DatabaseConfig {
            path: dir.path().join("test.db"),
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
    }

    /// Migration 0018 rebuilds `proxies` with a port range CHECK and drops
    /// the rows a pre-check database could carry with port = 0 (SQLite
    /// cannot add a CHECK to an existing column, so the rebuild copies the
    /// rows the CHECK accepts and leaves the junk behind). The children of
    /// a dropped row go with it — the explicit deletes stand in for the
    /// `ON DELETE CASCADE` the schema declares, which cannot fire while
    /// foreign keys are off — and every valid row keeps its id and its
    /// columns.
    #[tokio::test]
    async fn migration_0018_drops_port_zero_rows_and_installs_the_port_range_check() {
        use sqlx::migrate::Migrator;
        static MIGRATOR: Migrator = sqlx::migrate!("./migrations");

        let dir = crate::tempdir_lite::TempDir::new("fumox-mig");
        let cfg = crate::config::DatabaseConfig {
            path: dir.path().join("test.db"),
            ..Default::default()
        };
        let pool = db::connect_pool(&cfg).await.unwrap();

        // The pre-check schema (0001..0017), applied by hand so the rebuild
        // runs against rows and children that already exist.
        for migration in MIGRATOR.migrations.iter().filter(|m| m.version <= 17) {
            sqlx::raw_sql(migration.sql.clone())
                .execute(&pool)
                .await
                .unwrap();
        }

        sqlx::query(
            "INSERT INTO sources (id, name, url, created_at, updated_at)
             VALUES ('src', 'src', 'https://example.com', 1, 1)",
        )
        .execute(&pool)
        .await
        .unwrap();
        for (fingerprint, port) in [("fp-keep", 443), ("fp-zero", 0)] {
            sqlx::query(
                "INSERT INTO proxies (fingerprint, scheme, host, port, status, created_at, updated_at)
                 VALUES (?1, 'vless', 'h.example.com', ?2, 'unknown', 1, 1)",
            )
            .bind(fingerprint)
            .bind(port)
            .execute(&pool)
            .await
            .unwrap();
        }
        let id_of = async |fp: &str| -> i64 {
            sqlx::query_scalar("SELECT id FROM proxies WHERE fingerprint = ?1")
                .bind(fp)
                .fetch_one(&pool)
                .await
                .unwrap()
        };
        // Both rows carry a source link and a probe result: the kept row's
        // children must survive the rebuild, the dropped row's must not.
        let keep_id = id_of("fp-keep").await;
        let zero_id = id_of("fp-zero").await;
        assert_ne!(keep_id, zero_id, "the fixture rows must get distinct ids");
        for id in [keep_id, zero_id] {
            sqlx::query(
                "INSERT INTO proxy_source_links (proxy_id, source_id, seen_at) VALUES (?1, 'src', 1)",
            )
            .bind(id)
            .execute(&pool)
            .await
            .unwrap();
            sqlx::query(
                "INSERT INTO probe_results (proxy_id, checked_at, ok, probe_kind)
                 VALUES (?1, 1000, 1, 'tcp')",
            )
            .bind(id)
            .execute(&pool)
            .await
            .unwrap();
        }

        let eighteenth = MIGRATOR
            .migrations
            .iter()
            .find(|m| m.version == 18)
            .expect("migration 0018 missing");
        sqlx::raw_sql(eighteenth.sql.clone())
            .execute(&pool)
            .await
            .unwrap();

        // The port-0 row is gone, the valid row survived with its columns.
        let ports: Vec<i64> = sqlx::query_scalar("SELECT port FROM proxies ORDER BY port")
            .fetch_all(&pool)
            .await
            .unwrap();
        assert_eq!(ports, vec![443]);
        let (status, raw_path, ladder_step): (String, Option<String>, i64) = sqlx::query_as(
            "SELECT status, raw_path, ladder_step FROM proxies WHERE fingerprint = 'fp-keep'",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(status, "unknown");
        assert_eq!(
            raw_path, None,
            "the rebuild must preserve the columns it copies"
        );
        assert_eq!(ladder_step, 0);

        // The children of the dropped row are gone, the kept row's are intact.
        for table in ["proxy_source_links", "probe_results"] {
            let kept: i64 = sqlx::query_scalar(sqlx::AssertSqlSafe(format!(
                "SELECT COUNT(*) FROM {table} WHERE proxy_id = ?1"
            )))
            .bind(keep_id)
            .fetch_one(&pool)
            .await
            .unwrap();
            assert_eq!(kept, 1, "{table} of the kept row must survive");
            let dropped: i64 = sqlx::query_scalar(sqlx::AssertSqlSafe(format!(
                "SELECT COUNT(*) FROM {table} WHERE proxy_id = ?1"
            )))
            .bind(zero_id)
            .fetch_one(&pool)
            .await
            .unwrap();
            assert_eq!(dropped, 0, "{table} of the dropped row must go with it");
        }

        // The CHECK is active on the rebuilt table: port 0 is refused, the
        // boundary ports are not.
        let err = sqlx::query(
            "INSERT INTO proxies (fingerprint, scheme, host, port, status, created_at, updated_at)
             VALUES ('fp-new0', 'vless', 'h.example.com', 0, 'unknown', 1, 1)",
        )
        .execute(&pool)
        .await
        .unwrap_err();
        assert!(
            err.to_string().contains("proxies_port_range"),
            "expected the port range CHECK to fire, got: {err}"
        );
        for (fingerprint, port) in [("fp-new1", 1), ("fp-newmax", 65535)] {
            sqlx::query(
                "INSERT INTO proxies (fingerprint, scheme, host, port, status, created_at, updated_at)
                 VALUES (?1, 'vless', 'h.example.com', ?2, 'unknown', 1, 1)",
            )
            .bind(fingerprint)
            .bind(port)
            .execute(&pool)
            .await
            .unwrap();
        }

        pool.close().await;
    }

    /// Migration 0013 backfills the T2 block from the probe history.
    ///
    /// Migration 0007 added `last_t2_failed_at` empty, so every row that
    /// existed then looked like a proxy that had never failed a tunnel
    /// check — the T1 lane kept serving the proxies the probe had already
    /// found untunnellable. The backfill reads the history: the newest T2
    /// attempt decides, and only a failed one stamps the row.
    #[tokio::test]
    async fn migration_0013_backfills_the_t2_block_from_the_probe_history() {
        use sqlx::migrate::Migrator;
        static MIGRATOR: Migrator = sqlx::migrate!("./migrations");

        let dir = crate::tempdir_lite::TempDir::new("fumox-mig");
        let cfg = crate::config::DatabaseConfig {
            path: dir.path().join("test.db"),
            ..Default::default()
        };
        let pool = db::connect_pool(&cfg).await.unwrap();

        // The pre-backfill schema, applied by hand so the backfill can be
        // run against rows that already carry a history.
        for migration in MIGRATOR.migrations.iter().filter(|m| m.version <= 12) {
            sqlx::raw_sql(migration.sql.clone())
                .execute(&pool)
                .await
                .unwrap();
        }

        for (fingerprint, host) in [
            ("fp-failed", "failed.example.com"),
            ("fp-recovered", "recovered.example.com"),
            ("fp-unverified", "unverified.example.com"),
            ("fp-never", "never.example.com"),
        ] {
            sqlx::query(
                "INSERT INTO proxies (fingerprint, scheme, host, port, status, created_at, updated_at)
                 VALUES (?1, 'vless', ?2, 443, 'alive', 1, 1)",
            )
            .bind(fingerprint)
            .bind(host)
            .execute(&pool)
            .await
            .unwrap();
        }
        let id_of = async |fp: &str| -> i64 {
            sqlx::query_scalar("SELECT id FROM proxies WHERE fingerprint = ?1")
                .bind(fp)
                .fetch_one(&pool)
                .await
                .unwrap()
        };

        // A failed T2, then a later successful one: the block was cleared
        // by the success, so the backfill must not stamp it.
        sqlx::query(
            "INSERT INTO probe_results (proxy_id, checked_at, ok, probe_kind)
             VALUES (?1, 1000, 0, 't2'), (?1, 2000, 1, 't2')",
        )
        .bind(id_of("fp-recovered").await)
        .execute(&pool)
        .await
        .unwrap();
        // A failed T2 and nothing since: the block belongs to it.
        sqlx::query(
            "INSERT INTO probe_results (proxy_id, checked_at, ok, probe_kind)
             VALUES (?1, 1000, 0, 't2')",
        )
        .bind(id_of("fp-failed").await)
        .execute(&pool)
        .await
        .unwrap();
        // An unverified attempt (the engine produced no verdict) counts as
        // an attempt and blocks the row.
        sqlx::query(
            "INSERT INTO probe_results (proxy_id, checked_at, ok, probe_kind)
             VALUES (?1, 1500, 0, 't2_unverified')",
        )
        .bind(id_of("fp-unverified").await)
        .execute(&pool)
        .await
        .unwrap();

        let thirteenth = MIGRATOR
            .migrations
            .iter()
            .find(|m| m.version == 13)
            .expect("migration 0013 missing");
        sqlx::raw_sql(thirteenth.sql.clone())
            .execute(&pool)
            .await
            .unwrap();

        let rows: Vec<(String, Option<i64>)> = sqlx::query_as(
            "SELECT fingerprint, last_t2_failed_at FROM proxies ORDER BY fingerprint",
        )
        .fetch_all(&pool)
        .await
        .unwrap();
        let by_fp: std::collections::HashMap<String, Option<i64>> = rows.into_iter().collect();
        assert_eq!(by_fp["fp-failed"], Some(1000));
        assert_eq!(by_fp["fp-unverified"], Some(1500));
        assert_eq!(
            by_fp["fp-recovered"], None,
            "a successful T2 clears the block, the backfill must not restore it"
        );
        assert_eq!(by_fp["fp-never"], None);

        pool.close().await;
    }
}
