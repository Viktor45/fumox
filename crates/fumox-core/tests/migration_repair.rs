//! Migration-repair verification: confirm `db::migrate()` recovers from
//! a checksum mismatch automatically, and that non-`VersionMismatch`
//! errors still surface untouched.

use fumox_core::config::DatabaseConfig;
use fumox_core::db;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

fn temp_db_path(label: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!("fumox-mig-repair-{label}-{nanos}.db"))
}

fn cleanup_files(path: &PathBuf) {
    let _ = std::fs::remove_file(path);
    let _ = std::fs::remove_file(path.with_extension("db-wal"));
    let _ = std::fs::remove_file(path.with_extension("db-shm"));
}

#[tokio::test]
async fn migrate_recovers_from_checksum_mismatch_without_external_help() {
    let path = temp_db_path("auto");
    let cfg = DatabaseConfig {
        path: path.clone(),
        ..Default::default()
    };
    let pool = db::connect_pool(&cfg).await.unwrap();
    // Initial apply: sqlx seeds `_sqlx_migrations` with the SHA-384 of
    // the current files.
    db::migrate(&pool).await.unwrap();

    // Corrupt every stored checksum to force a `VersionMismatch` on the
    // next migrate.
    sqlx::query("UPDATE _sqlx_migrations SET checksum = X'00' WHERE success = 1")
        .execute(&pool)
        .await
        .unwrap();

    // The auto-repair path inside `db::migrate()` must succeed without
    // any external tooling or extra migration files. The schema on disk
    // is unchanged, only the bookkeeping column is rewritten.
    db::migrate(&pool)
        .await
        .expect("migrate must auto-recover from a checksum mismatch");

    // A subsequent run with no corruption is a clean no-op.
    db::migrate(&pool)
        .await
        .expect("migrate must stay clean after auto-repair");

    drop(pool);
    cleanup_files(&path);
}

#[tokio::test]
async fn repair_migration_checksums_is_a_noop_on_clean_db() {
    let path = temp_db_path("noop");
    let cfg = DatabaseConfig {
        path: path.clone(),
        ..Default::default()
    };
    let pool = db::connect_pool(&cfg).await.unwrap();
    db::migrate(&pool).await.unwrap();

    let migrator: sqlx::migrate::Migrator = sqlx::migrate!("./migrations");
    let re_stamped = db::repair_migration_checksums(&pool, &migrator)
        .await
        .unwrap();
    assert!(
        re_stamped.is_empty(),
        "no rows should be touched when checksums already match: {re_stamped:?}"
    );

    drop(pool);
    cleanup_files(&path);
}

/// The self-heal must leave a durable trace. sqlx hashes the whole
/// migration file, so a comment edit and a DDL edit are indistinguishable
/// at the re-stamp: a schema that fell behind the files would otherwise be
/// discovered only by noticing a missing column. `migrate()` therefore
/// records the versions it re-stamped under `meta.migrations_repaired`,
/// which survives the boot log that announced it.
#[tokio::test]
async fn migrate_records_the_repaired_versions_in_meta() {
    let path = temp_db_path("recorded");
    let cfg = DatabaseConfig {
        path: path.clone(),
        ..Default::default()
    };
    let pool = db::connect_pool(&cfg).await.unwrap();
    db::migrate(&pool).await.unwrap();

    let versions: Vec<i64> =
        sqlx::query_scalar("SELECT version FROM _sqlx_migrations ORDER BY version")
            .fetch_all(&pool)
            .await
            .unwrap();
    assert!(
        !versions.is_empty(),
        "pre-condition: migrations must have run"
    );

    sqlx::query("UPDATE _sqlx_migrations SET checksum = X'00' WHERE success = 1")
        .execute(&pool)
        .await
        .unwrap();

    db::migrate(&pool)
        .await
        .expect("migrate must auto-recover from a checksum mismatch");

    let recorded: Option<String> =
        sqlx::query_scalar("SELECT value FROM meta WHERE key = 'migrations_repaired'")
            .fetch_optional(&pool)
            .await
            .unwrap();
    let recorded = recorded.expect(
        "a checksum re-stamp that may hide an unapplied DDL change must be recorded in meta",
    );
    for version in &versions {
        assert!(
            recorded.contains(&version.to_string()),
            "meta.migrations_repaired must name version {version}, got: {recorded}"
        );
    }

    // A clean run must not keep re-announcing a repair that did not happen.
    db::migrate(&pool).await.unwrap();
    let after: String =
        sqlx::query_scalar("SELECT value FROM meta WHERE key = 'migrations_repaired'")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(
        after, recorded,
        "a clean migrate must leave the recorded repair untouched"
    );

    drop(pool);
    cleanup_files(&path);
}

/// The repair is one-directional on purpose: a version the embedded set
/// does not know about belongs to a newer Fumox, and its row is none of
/// this build's business. The `repair_migration_checksums` example states
/// that as a pre-flight check instead of re-stamping what it can and
/// leaving `migrate()` to fail with `VersionMissing`.
#[tokio::test]
async fn repair_leaves_migrations_this_build_does_not_embed_alone() {
    let path = temp_db_path("newer");
    let cfg = DatabaseConfig {
        path: path.clone(),
        ..Default::default()
    };
    let pool = db::connect_pool(&cfg).await.unwrap();
    db::migrate(&pool).await.unwrap();

    sqlx::query(
        "INSERT INTO _sqlx_migrations
             (version, description, installed_on, success, checksum, execution_time)
         VALUES (99, 'from a newer build', '2026-01-01 00:00:00', 1, X'00', 0)",
    )
    .execute(&pool)
    .await
    .unwrap();

    let migrator: sqlx::migrate::Migrator = sqlx::migrate!("./migrations");
    let re_stamped = db::repair_migration_checksums(&pool, &migrator)
        .await
        .unwrap();
    assert!(
        re_stamped.is_empty(),
        "nothing in this build's set disagrees with the stored checksums: {re_stamped:?}"
    );
    let stored: Vec<u8> =
        sqlx::query_scalar("SELECT checksum FROM _sqlx_migrations WHERE version = 99")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(
        stored,
        vec![0u8],
        "the unknown version's row must be left exactly as it was"
    );

    drop(pool);
    cleanup_files(&path);
}

#[tokio::test]
async fn migrate_propagates_non_mismatch_errors_untouched() {
    // The auto-repair only fires for `MigrateError::VersionMismatch`.
    // A pristine DB exercises a different code path (first-time apply);
    // it must not be turned into a repair. We assert the call simply
    // succeeds. The negative case (a dirty DB, a missing file) is
    // covered by sqlx's own tests, not duplicated here.
    let path = temp_db_path("first_run");
    let cfg = DatabaseConfig {
        path: path.clone(),
        ..Default::default()
    };
    let pool = db::connect_pool(&cfg).await.unwrap();
    db::migrate(&pool)
        .await
        .expect("first-time migrate must succeed");
    drop(pool);
    cleanup_files(&path);
}

/// The empty-repair re-raise arm: when `VersionMismatch` fires but the
/// repair rewrites nothing, `migrate()` must surface the *original* error
/// and must not claim a repair it did not make (no
/// `meta.migrations_repaired` breadcrumb).
///
/// The repair's UPDATE is scoped to `success = 1` rows while sqlx's
/// mismatch check compares the version and checksum of every row in
/// `_sqlx_migrations` (the pre-flight dirty check only rejects
/// `success = false`). A row outside that overlap therefore produces a
/// mismatch the repair cannot rewrite, the deterministic stand-in for the
/// concurrent-repair race this arm guards.
#[tokio::test]
async fn migrate_reraises_when_the_mismatch_cannot_be_repaired() {
    let path = temp_db_path("empty-repair");
    let cfg = DatabaseConfig {
        path: path.clone(),
        ..Default::default()
    };
    let pool = db::connect_pool(&cfg).await.unwrap();
    db::migrate(&pool).await.unwrap();

    let version: i64 = sqlx::query_scalar("SELECT MAX(version) FROM _sqlx_migrations")
        .fetch_one(&pool)
        .await
        .unwrap();
    // `success = 2` is neither the dirty check's `false` nor the repair's
    // `1`: the mismatch is visible to sqlx, untouchable by the repair.
    sqlx::query("UPDATE _sqlx_migrations SET checksum = X'00', success = 2 WHERE version = ?")
        .bind(version)
        .execute(&pool)
        .await
        .unwrap();

    let err = db::migrate(&pool)
        .await
        .expect_err("a mismatch the repair cannot rewrite must surface");
    assert!(
        err.to_string()
            .contains("was previously applied but has been modified"),
        "the original VersionMismatch must be re-raised, got: {err}"
    );

    // No repair was performed: the bad checksum survives and the durable
    // breadcrumb must not exist (nothing may claim a repair that did not
    // happen).
    let stored: Vec<u8> =
        sqlx::query_scalar("SELECT checksum FROM _sqlx_migrations WHERE version = ?")
            .bind(version)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(stored, vec![0u8], "the row must be left exactly as it was");
    let recorded: Option<String> =
        sqlx::query_scalar("SELECT value FROM meta WHERE key = 'migrations_repaired'")
            .fetch_optional(&pool)
            .await
            .unwrap();
    assert!(
        recorded.is_none(),
        "an empty repair must not write the breadcrumb: {recorded:?}"
    );

    drop(pool);
    cleanup_files(&path);
}

/// The compiled `repair_migration_checksums` example, next to this test
/// binary in `<target>/debug/examples/`. `cargo test` builds the workspace
/// examples before running the integration tests; a targeted
/// `cargo test --test migration_repair` does not, hence the explicit
/// panic rather than a skip: a silently skipped refusal test is exactly
/// the rot this one exists to prevent.
fn repair_example_bin() -> PathBuf {
    let exe = std::env::current_exe().expect("test executable path");
    // <target>/debug/deps/migration_repair-<hash> → <target>/debug
    let profile_dir = exe
        .parent()
        .and_then(Path::parent)
        .expect("deps/<profile> layout");
    let bin = profile_dir.join("examples").join(format!(
        "repair_migration_checksums{}",
        std::env::consts::EXE_SUFFIX
    ));
    assert!(
        bin.is_file(),
        "the repair example is not built at {}; run \
         `cargo build -p fumox-core --example repair_migration_checksums`",
        bin.display()
    );
    bin
}

fn run_repair_tool(bin: &Path, db_path: &Path) -> std::process::Output {
    std::process::Command::new(bin)
        .arg(db_path)
        .output()
        .expect("the repair example must be executable")
}

/// The tool's own pre-flight, driven as a subprocess because it lives in
/// `main()` of the example: a database carrying an applied version this
/// build does not embed was migrated by a *newer* Fumox, and re-stamping
/// the versions we do know would leave sqlx refusing to start with
/// `VersionMissing(99)` anyway. The tool must refuse, name the version,
/// and touch nothing, or it silently "repairs" a half-understood
/// database.
///
/// The first run over the pristine database is the control: exit 0 there
/// proves the refusal below comes from the extra version, not from the
/// tool failing outright.
#[tokio::test]
async fn the_repair_tool_refuses_a_database_from_a_newer_build() {
    let bin = repair_example_bin();
    let path = temp_db_path("refuse");
    let cfg = DatabaseConfig {
        path: path.clone(),
        ..Default::default()
    };
    let pool = db::connect_pool(&cfg).await.unwrap();
    db::migrate(&pool).await.unwrap();

    // Control: the database is exactly what this build migrates.
    drop(pool);
    let control = run_repair_tool(&bin, &path);
    assert!(
        control.status.success(),
        "the tool must accept a database it fully understands: status {:?}, stderr: {}",
        control.status.code(),
        String::from_utf8_lossy(&control.stderr)
    );

    let pool = db::connect_pool(&cfg).await.unwrap();
    sqlx::query(
        "INSERT INTO _sqlx_migrations
             (version, description, installed_on, success, checksum, execution_time)
         VALUES (99, 'from a newer build', '2026-01-01 00:00:00', 1, X'00', 0)",
    )
    .execute(&pool)
    .await
    .unwrap();
    drop(pool);

    let out = run_repair_tool(&bin, &path);
    assert_eq!(
        out.status.code(),
        Some(1),
        "the refusal must be a non-zero exit, stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("does not embed") && stderr.contains("99"),
        "the message must name the unknown version, got: {stderr}"
    );

    // Refused means untouched: the unknown row still carries its checksum.
    let pool = db::connect_pool(&cfg).await.unwrap();
    let stored: Vec<u8> =
        sqlx::query_scalar("SELECT checksum FROM _sqlx_migrations WHERE version = 99")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(
        stored,
        vec![0u8],
        "a refused run must not re-stamp anything"
    );
    drop(pool);
    cleanup_files(&path);
}
