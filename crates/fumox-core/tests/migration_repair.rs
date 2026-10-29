//! Migration-repair verification: confirm the checksum repair is opt-in
//! (`db::migrate_with`), that the refusal names the version, and that
//! non-`VersionMismatch` errors still surface untouched.

use fumox_core::config::DatabaseConfig;
use fumox_core::db;
use std::collections::{BTreeSet, HashMap};
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
    // The migration lock sidecar.
    let _ = std::fs::remove_file(format!("{}-migrate.lock", path.display()));
}

/// The versions named by the `meta.migrations_repaired` breadcrumb.
///
/// The value is written as `versions=[1,2,3] at <unix time>`. The test
/// compares the *list* it names, not the text: a substring check would
/// accept `1` for a breadcrumb that names `11`, and would accept a
/// breadcrumb that names the right versions twice.
fn parse_repaired_versions(value: &str) -> Vec<i64> {
    let start = value
        .find('[')
        .expect("the breadcrumb carries a versions=[…] list");
    let end = value.find(']').expect("the versions=[…] list is closed");
    value[start + 1..end]
        .split(',')
        .map(str::trim)
        .filter(|part| !part.is_empty())
        .map(|part| {
            part.parse::<i64>()
                .unwrap_or_else(|_| panic!("a repaired version is a number, got: {part}"))
        })
        .collect()
}

async fn repaired_versions(pool: &sqlx::SqlitePool) -> Option<Vec<i64>> {
    let value: Option<String> =
        sqlx::query_scalar("SELECT value FROM meta WHERE key = 'migrations_repaired'")
            .fetch_optional(pool)
            .await
            .unwrap();
    value.map(|value| parse_repaired_versions(&value))
}

/// The stored checksum of every applied migration.
async fn stored_checksums(pool: &sqlx::SqlitePool) -> HashMap<i64, Vec<u8>> {
    let rows: Vec<(i64, Vec<u8>)> =
        sqlx::query_as("SELECT version, checksum FROM _sqlx_migrations ORDER BY version")
            .fetch_all(pool)
            .await
            .unwrap();
    rows.into_iter().collect()
}

/// The checksum the embedded migration set expects for every version.
fn expected_checksums() -> HashMap<i64, Vec<u8>> {
    let migrator: sqlx::migrate::Migrator = sqlx::migrate!("./migrations");
    migrator
        .iter()
        .map(|m| (m.version, m.checksum.as_ref().to_vec()))
        .collect()
}

/// The repair is opt-in. sqlx hashes the whole migration file, so a
/// comment edit and a DDL edit are indistinguishable at the re-stamp, and
/// a silent repair hides a schema that fell behind the files. The default
/// therefore refuses and names the version; the operator decides.
#[tokio::test]
async fn migrate_refuses_a_checksum_mismatch_by_default() {
    let path = temp_db_path("refuse-default");
    let cfg = DatabaseConfig {
        path: path.clone(),
        ..Default::default()
    };
    let pool = db::connect_pool(&cfg).await.unwrap();
    db::migrate(&pool).await.unwrap();

    // Corrupt every stored checksum to force a `VersionMismatch` on the
    // next migrate.
    sqlx::query("UPDATE _sqlx_migrations SET checksum = X'00' WHERE success = 1")
        .execute(&pool)
        .await
        .unwrap();

    let err = db::migrate(&pool)
        .await
        .expect_err("a checksum mismatch must stop the boot by default");
    let message = err.to_string();
    assert!(
        message.contains("a new migration file is needed"),
        "the refusal must say what to do, got: {message}"
    );
    assert!(
        message.contains("was previously applied but has been modified"),
        "the refusal must carry sqlx's own wording, got: {message}"
    );
    assert!(
        message.contains("repair_migration_checksums"),
        "the refusal must name the repair tool, got: {message}"
    );

    // Refused means untouched: the checksums stay broken and no
    // breadcrumb claims a repair that did not happen.
    let stored = stored_checksums(&pool).await;
    let broken = stored.values().filter(|c| c.as_slice() == [0u8]).count();
    assert!(broken > 0, "the refusal must not re-stamp anything");
    assert!(
        repaired_versions(&pool).await.is_none(),
        "a refused migrate must not write the breadcrumb"
    );

    drop(pool);
    cleanup_files(&path);
}

/// With the operator's opt-in the boot recovers on its own: the schema on
/// disk is unchanged, only the bookkeeping column is rewritten.
#[tokio::test]
async fn migrate_recovers_from_a_checksum_mismatch_when_the_operator_opts_in() {
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

    db::migrate_with(&pool, db::ChecksumRepair::Allow)
        .await
        .expect("the opt-in must recover from a checksum mismatch");

    // A subsequent run with no corruption is a clean no-op.
    db::migrate(&pool)
        .await
        .expect("migrate must stay clean after the repair");

    drop(pool);
    cleanup_files(&path);
}

/// The flag travels from the configuration file to the migrator: the
/// shipped `[database].allow_checksum_repair` is the opt-in the boot
/// reads.
#[tokio::test]
async fn the_config_flag_decides_the_repair_policy() {
    assert_eq!(
        db::ChecksumRepair::from_config(false),
        db::ChecksumRepair::Refuse,
        "the default must refuse"
    );
    assert_eq!(
        db::ChecksumRepair::from_config(true),
        db::ChecksumRepair::Allow
    );

    let path = temp_db_path("flag");
    let cfg = DatabaseConfig {
        path: path.clone(),
        allow_checksum_repair: true,
        ..Default::default()
    };
    let pool = db::connect_pool(&cfg).await.unwrap();
    db::migrate(&pool).await.unwrap();
    sqlx::query("UPDATE _sqlx_migrations SET checksum = X'00' WHERE success = 1")
        .execute(&pool)
        .await
        .unwrap();
    db::migrate_with(
        &pool,
        db::ChecksumRepair::from_config(cfg.allow_checksum_repair),
    )
    .await
    .expect("the configured opt-in must recover");

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
///
/// The comparison is on the exact set of versions, not on a substring of
/// the text: a breadcrumb that named `11` would satisfy a check for `1`.
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

    db::migrate_with(&pool, db::ChecksumRepair::Allow)
        .await
        .expect("the opt-in must recover from a checksum mismatch");

    let recorded = repaired_versions(&pool).await.expect(
        "a checksum re-stamp that may hide an unapplied DDL change must be recorded in meta",
    );
    let expected: BTreeSet<i64> = versions.iter().copied().collect();
    assert_eq!(
        recorded.iter().copied().collect::<BTreeSet<i64>>(),
        expected,
        "the breadcrumb must name exactly the repaired versions"
    );
    assert_eq!(
        recorded.len(),
        expected.len(),
        "the breadcrumb must name every version once: {recorded:?}"
    );

    // A clean run must not keep re-announcing a repair that did not happen.
    db::migrate(&pool).await.unwrap();
    let after = repaired_versions(&pool)
        .await
        .expect("the breadcrumb stays");
    assert_eq!(
        after, recorded,
        "a clean migrate must leave the recorded repair untouched"
    );

    drop(pool);
    cleanup_files(&path);
}

/// A partial corruption names one version and one version only. The
/// breadcrumb of a repair that touched every row would hide which file
/// actually changed.
#[tokio::test]
async fn migrate_records_only_the_versions_it_repaired() {
    let path = temp_db_path("partial");
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
    assert!(versions.len() > 1, "pre-condition: more than one migration");
    let broken = versions[0];

    sqlx::query("UPDATE _sqlx_migrations SET checksum = X'00' WHERE version = ?")
        .bind(broken)
        .execute(&pool)
        .await
        .unwrap();

    db::migrate_with(&pool, db::ChecksumRepair::Allow)
        .await
        .expect("the opt-in must recover from a checksum mismatch");

    let recorded = repaired_versions(&pool)
        .await
        .expect("the breadcrumb must exist");
    assert_eq!(
        recorded,
        vec![broken],
        "exactly the repaired version must be named"
    );

    // The other rows were already correct and stay untouched.
    let stored = stored_checksums(&pool).await;
    let expected = expected_checksums();
    for (version, checksum) in &stored {
        assert_eq!(
            Some(checksum.as_slice()),
            expected.get(version).map(|c| c.as_slice()),
            "version {version} must carry the checksum of the file on disk"
        );
    }

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
    // The repair only fires for `MigrateError::VersionMismatch`.
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

    let err = db::migrate_with(&pool, db::ChecksumRepair::Allow)
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
    assert!(
        repaired_versions(&pool).await.is_none(),
        "an empty repair must not write the breadcrumb"
    );

    drop(pool);
    cleanup_files(&path);
}

/// A failed migration is a different failure than a checksum mismatch, and
/// the repair must not touch it: sqlx refuses to start on a dirty row
/// (`success = 0`), because the schema on disk is half-applied and no
/// re-stamp of a checksum can finish it.
///
/// The assertion is on the error variant, not on the message text: the
/// dirty state has to be distinguishable from every other database
/// failure.
#[tokio::test]
async fn migrate_refuses_a_dirty_migration_without_repairing_it() {
    let path = temp_db_path("dirty");
    let cfg = DatabaseConfig {
        path: path.clone(),
        ..Default::default()
    };
    let pool = db::connect_pool(&cfg).await.unwrap();
    db::migrate(&pool).await.unwrap();

    sqlx::query(
        "INSERT INTO _sqlx_migrations
             (version, description, installed_on, success, checksum, execution_time)
         VALUES (99, 'a failed migration', '2026-01-01 00:00:00', 0, X'00', 0)",
    )
    .execute(&pool)
    .await
    .unwrap();

    let err = db::migrate_with(&pool, db::ChecksumRepair::Allow)
        .await
        .expect_err("a dirty migration must stop the boot");
    match err {
        fumox_core::error::Error::Migration(sqlx::migrate::MigrateError::Dirty(version)) => {
            assert_eq!(version, 99, "the dirty version must be named")
        }
        other => panic!("a dirty migration must surface as Dirty, got: {other:?}"),
    }

    // The failed row stays exactly as it was, and no repair is claimed.
    let row: (i64, i64) =
        sqlx::query_as("SELECT success, length(checksum) FROM _sqlx_migrations WHERE version = 99")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(row.0, 0, "the failed row must stay failed");
    assert_eq!(row.1, 1, "the failed row must keep its checksum");
    assert!(
        repaired_versions(&pool).await.is_none(),
        "a dirty migration must not write the breadcrumb"
    );

    drop(pool);
    cleanup_files(&path);
}

/// Two processes that start at the same moment must not apply the same
/// migration twice. sqlx does not lock a SQLite database while it
/// migrates, so the serialisation is Fumox's own: an exclusive lock on a
/// sidecar next to the database file.
///
/// The outcome has to be deterministic — both pools end up migrated, or
/// one of them reports the mismatch it refused to repair — and the
/// bookkeeping must survive it: the checksums are the ones the files
/// hash to, and the breadcrumb names no version twice.
#[tokio::test]
async fn two_pools_migrating_at_once_converge() {
    let path = temp_db_path("concurrent");
    let cfg = DatabaseConfig {
        path: path.clone(),
        ..Default::default()
    };
    let pool_a = db::connect_pool(&cfg).await.unwrap();
    let pool_b = db::connect_pool(&cfg).await.unwrap();
    db::migrate(&pool_a).await.unwrap();

    sqlx::query("UPDATE _sqlx_migrations SET checksum = X'00' WHERE success = 1")
        .execute(&pool_a)
        .await
        .unwrap();

    let (a, b) = tokio::join!(
        db::migrate_with(&pool_a, db::ChecksumRepair::Allow),
        db::migrate_with(&pool_b, db::ChecksumRepair::Allow),
    );

    for outcome in [&a, &b] {
        if let Err(err) = outcome {
            assert!(
                err.to_string()
                    .contains("was previously applied but has been modified"),
                "a concurrent migrate must fail on the mismatch and nothing else, got: {err}"
            );
        }
    }
    assert!(
        a.is_ok() || b.is_ok(),
        "at least one of the two migrators must succeed"
    );

    // Whatever the race decided, the checksums on disk are the ones the
    // files hash to.
    let expected = expected_checksums();
    let stored = stored_checksums(&pool_a).await;
    for (version, checksum) in &stored {
        assert_eq!(
            Some(checksum.as_slice()),
            expected.get(version).map(|c| c.as_slice()),
            "version {version} must carry the checksum of the file on disk"
        );
    }

    // The breadcrumb names the repaired versions, and each of them once.
    let recorded = repaired_versions(&pool_a)
        .await
        .expect("the breadcrumb must exist");
    let applied: BTreeSet<i64> = stored.keys().copied().collect();
    assert_eq!(
        recorded.iter().copied().collect::<BTreeSet<i64>>(),
        applied,
        "the breadcrumb must name exactly the applied versions"
    );
    assert_eq!(
        recorded.len(),
        applied.len(),
        "no version may be named twice: {recorded:?}"
    );

    drop(pool_a);
    drop(pool_b);
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

/// The other half of the pre-flight: a migration this build embeds but
/// the database has never applied. The tool re-stamps checksums, it does
/// not apply migrations, so it must refuse instead of leaving a database
/// that is one migration behind.
#[tokio::test]
async fn the_repair_tool_refuses_a_database_with_an_unapplied_migration() {
    let bin = repair_example_bin();
    let path = temp_db_path("unapplied");
    let cfg = DatabaseConfig {
        path: path.clone(),
        ..Default::default()
    };
    let pool = db::connect_pool(&cfg).await.unwrap();
    db::migrate(&pool).await.unwrap();

    // Drop the row of the last applied migration: the database now sits
    // one migration behind the files.
    let version: i64 = sqlx::query_scalar("SELECT MAX(version) FROM _sqlx_migrations")
        .fetch_one(&pool)
        .await
        .unwrap();
    let before = stored_checksums(&pool).await;
    sqlx::query("DELETE FROM _sqlx_migrations WHERE version = ?")
        .bind(version)
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
        stderr.contains("never been applied"),
        "the message must say the migration was never applied, got: {stderr}"
    );

    // Refused means untouched: the remaining checksums are the ones the
    // files hash to.
    let pool = db::connect_pool(&cfg).await.unwrap();
    let after = stored_checksums(&pool).await;
    let expected = expected_checksums();
    for (version, checksum) in &after {
        assert_eq!(
            Some(checksum.as_slice()),
            expected.get(version).map(|c| c.as_slice()),
            "version {version} must be untouched"
        );
    }
    assert!(
        !after.contains_key(&version),
        "the deleted row must stay deleted"
    );
    assert_eq!(
        after.len(),
        before.len() - 1,
        "no row may be added or removed by a refused run"
    );
    for (version, checksum) in &after {
        assert_eq!(
            before.get(version),
            Some(checksum),
            "version {version} must be untouched"
        );
    }

    drop(pool);
    cleanup_files(&path);
}
