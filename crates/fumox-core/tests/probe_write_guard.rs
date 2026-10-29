//! The probe's database access is restricted: it may change the health
//! status of a proxy, not the subscription content.

use fumox_core::config::DatabaseConfig;
use fumox_core::db;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

fn temp_db_path(label: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!("fumox-probe-guard-{label}-{nanos}.db"))
}

fn cleanup_files(path: &PathBuf) {
    let _ = std::fs::remove_file(path);
    let _ = std::fs::remove_file(path.with_extension("db-wal"));
    let _ = std::fs::remove_file(path.with_extension("db-shm"));
}

/// Asserts that the statement is refused by the authorizer.
///
/// `SQLITE_AUTH` (23) is what SQLite reports for a denied statement;
/// its error string is "not authorized".
async fn assert_denied(pool: &db::DbPool, sql: &'static str, label: &str) {
    let error = sqlx::query(sql)
        .execute(pool)
        .await
        .expect_err(&format!("{label} must be refused"));
    let message = error.to_string();
    assert!(
        message.contains("not authorized"),
        "{label} must be refused as unauthorized, got: {message}"
    );
}

#[tokio::test]
async fn the_probe_may_change_the_health_status_but_not_the_content() {
    let path = temp_db_path("content");
    let cfg = DatabaseConfig {
        path: path.clone(),
        ..Default::default()
    };

    // The server's pool owns the content.
    let server = db::connect_pool(&cfg).await.unwrap();
    db::migrate(&server).await.unwrap();
    sqlx::query(
        "INSERT INTO sources (id, name, url, created_at, updated_at)
         VALUES ('src1', 'source', 'https://example.com/list', 0, 0)",
    )
    .execute(&server)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO proxies
             (fingerprint, scheme, name, host, port, credential, created_at, updated_at)
         VALUES ('fp1', 'vless', 'node', 'origin.example', 443, 'secret', 0, 0)",
    )
    .execute(&server)
    .await
    .unwrap();

    // The probe's pool shares the file but not the write access.
    let probe = db::connect_probe_pool(&cfg).await.unwrap();

    // Reading is unrestricted.
    let (host,): (String,) = sqlx::query_as("SELECT host FROM proxies WHERE fingerprint = 'fp1'")
        .fetch_one(&probe)
        .await
        .unwrap();
    assert_eq!(host, "origin.example");

    // The health status is the probe's own.
    sqlx::query(
        "UPDATE proxies SET status = 'alive', fail_count = 1, last_checked_at = 5, updated_at = 5
         WHERE fingerprint = 'fp1'",
    )
    .execute(&probe)
    .await
    .expect("the probe owns the health status of a proxy");

    // The subscription content does not belong to the probe.
    assert_denied(
        &probe,
        "UPDATE proxies SET host = 'evil.example' WHERE fingerprint = 'fp1'",
        "rewriting the host",
    )
    .await;
    assert_denied(
        &probe,
        "UPDATE proxies SET credential = 'stolen' WHERE fingerprint = 'fp1'",
        "rewriting the credential",
    )
    .await;
    assert_denied(
        &probe,
        "UPDATE proxies SET geo_country = 'XX' WHERE fingerprint = 'fp1'",
        "rewriting the geo enrichment",
    )
    .await;
    assert_denied(
        &probe,
        "UPDATE proxies SET params = '{}' WHERE fingerprint = 'fp1'",
        "rewriting the protocol parameters",
    )
    .await;

    // The probe may not add or remove subscription entries either.
    assert_denied(
        &probe,
        "INSERT INTO proxies (fingerprint, scheme, host, port, created_at, updated_at)
         VALUES ('fp2', 'vless', 'injected.example', 443, 0, 0)",
        "adding a proxy",
    )
    .await;
    assert_denied(&probe, "DELETE FROM proxies", "removing a proxy").await;
    assert_denied(
        &probe,
        "UPDATE sources SET url = 'https://evil.example/list' WHERE id = 'src1'",
        "rewriting a source",
    )
    .await;
    assert_denied(
        &probe,
        "DELETE FROM sources WHERE id = 'src1'",
        "removing a source",
    )
    .await;

    // The server's own writes are untouched: the restriction lives on
    // the probe's connections, not on the file.
    sqlx::query("UPDATE proxies SET host = 'renamed.example' WHERE fingerprint = 'fp1'")
        .execute(&server)
        .await
        .expect("the server owns the content");
    let (host,): (String,) = sqlx::query_as("SELECT host FROM proxies WHERE fingerprint = 'fp1'")
        .fetch_one(&server)
        .await
        .unwrap();
    assert_eq!(host, "renamed.example");

    drop(probe);
    drop(server);
    cleanup_files(&path);
}

#[tokio::test]
async fn the_probe_may_write_its_own_bookkeeping() {
    let path = temp_db_path("bookkeeping");
    let cfg = DatabaseConfig {
        path: path.clone(),
        ..Default::default()
    };

    let server = db::connect_pool(&cfg).await.unwrap();
    db::migrate(&server).await.unwrap();
    sqlx::query(
        "INSERT INTO proxies (fingerprint, scheme, host, port, created_at, updated_at)
         VALUES ('fp1', 'vless', 'origin.example', 443, 0, 0)",
    )
    .execute(&server)
    .await
    .unwrap();

    let probe = db::connect_probe_pool(&cfg).await.unwrap();

    sqlx::query(
        "INSERT INTO probe_results (proxy_id, checked_at, ok, probe_kind)
         SELECT id, 10, 1, 'tcp' FROM proxies WHERE fingerprint = 'fp1'",
    )
    .execute(&probe)
    .await
    .expect("the probe writes its own check history");
    sqlx::query("DELETE FROM probe_results WHERE checked_at < 5")
        .execute(&probe)
        .await
        .expect("the probe rotates its own check history");
    sqlx::query(
        "INSERT INTO meta (key, value) VALUES ('probe.heartbeat', '{}')
         ON CONFLICT(key) DO UPDATE SET value = excluded.value",
    )
    .execute(&probe)
    .await
    .expect("the probe writes the service key-value table");
    sqlx::query("DELETE FROM probe_requests")
        .execute(&probe)
        .await
        .expect("the probe drains the request queue");

    // The T2 recency stamp is the probe's own bookkeeping on the proxy
    // row: the journal write path keeps it up to date, so the recency
    // batch can order by it without reading the history.
    sqlx::query("UPDATE proxies SET last_t2_checked_at = 10 WHERE fingerprint = 'fp1'")
        .execute(&probe)
        .await
        .expect("the probe stamps the T2 recency of a proxy");
    let (stamp,): (Option<i64>,) =
        sqlx::query_as("SELECT last_t2_checked_at FROM proxies WHERE fingerprint = 'fp1'")
            .fetch_one(&probe)
            .await
            .unwrap();
    assert_eq!(stamp, Some(10));

    // The same holds for the production write path: journalling a T2
    // attempt refreshes the stamp on the proxy row.
    let (id,): (i64,) = sqlx::query_as("SELECT id FROM proxies WHERE fingerprint = 'fp1'")
        .fetch_one(&probe)
        .await
        .unwrap();
    fumox_core::repo::probe::insert(
        &probe,
        &fumox_core::repo::probe::ProbeResultEntry {
            proxy_id: id,
            checked_at: 20,
            ok: true,
            latency_ms: Some(30),
            error: None,
            probe_kind: fumox_core::repo::probe::T2_KIND,
        },
    )
    .await
    .expect("the probe journals its own tunnel checks");
    let (stamp,): (Option<i64>,) =
        sqlx::query_as("SELECT last_t2_checked_at FROM proxies WHERE fingerprint = 'fp1'")
            .fetch_one(&probe)
            .await
            .unwrap();
    assert_eq!(stamp, Some(20));

    drop(probe);
    drop(server);
    cleanup_files(&path);
}

#[tokio::test]
async fn the_probe_applies_the_schema_before_its_connections_are_restricted() {
    let path = temp_db_path("migrate");
    let cfg = DatabaseConfig {
        path: path.clone(),
        ..Default::default()
    };

    // The probe migrates on startup, before the server may have done
    // it, so the restricted pool applies the schema itself.
    let probe = db::connect_probe_pool(&cfg).await.unwrap();
    let (tables,): (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'proxies'",
    )
    .fetch_one(&probe)
    .await
    .unwrap();
    assert_eq!(tables, 1, "the schema must be in place");

    // The schema is not the probe's to change afterwards.
    assert_denied(
        &probe,
        "CREATE TABLE probe_scratch (id INTEGER PRIMARY KEY)",
        "creating a table",
    )
    .await;

    drop(probe);
    cleanup_files(&path);
}

#[tokio::test]
async fn the_probe_cannot_attach_another_database() {
    let path = temp_db_path("attach");
    let cfg = DatabaseConfig {
        path: path.clone(),
        ..Default::default()
    };
    let server = db::connect_pool(&cfg).await.unwrap();
    db::migrate(&server).await.unwrap();
    let probe = db::connect_probe_pool(&cfg).await.unwrap();

    let error = sqlx::query("ATTACH DATABASE ':memory:' AS side")
        .execute(&probe)
        .await
        .expect_err("attaching another database must be refused");
    assert!(
        error.to_string().contains("not authorized"),
        "attaching must be refused as unauthorized, got: {error}"
    );

    drop(probe);
    drop(server);
    cleanup_files(&path);
}
