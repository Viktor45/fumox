//! SQLite connection helpers.
//!
//! SQLite in WAL mode is the single shared source of truth between
//! `fumox-server` and `fumox-probe`. Every connection enables WAL, foreign
//! keys and `busy_timeout`, without the latter, concurrent upserts from two
//! processes produce `SQLITE_BUSY` (DATABASE, exploitation notes).

use std::time::Duration;

use sqlx::SqlitePool;
use sqlx::migrate::{MigrateError, Migrator};
use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions, SqliteSynchronous};

use crate::config::DatabaseConfig;

/// Type alias used across repository code.
pub type DbPool = SqlitePool;

/// Opens a connection pool configured for multi-process WAL access.
///
/// `create_new(true).mode(0o600)` sets the 0600 mode atomically, so the file
/// holding the plain-text credentials is never briefly world-readable; on
/// non-Unix this is a no-op and the ACL model governs.
pub async fn connect_pool(cfg: &DatabaseConfig) -> crate::Result<SqlitePool> {
    if cfg.max_connections == 0 {
        // sqlx accepts a zero-sized pool and then fails every acquisition
        // with `PoolTimedOut` after its 30 s acquire timeout, so the
        // misconfiguration surfaces as a startup stall instead of a
        // message naming the offending key. Reject it here, before the
        // pool or the file exists.
        return Err(crate::Error::Config(
            "database.max_connections must be >= 1, got 0 (a zero-sized pool can never hand out a connection)"
                .to_string(),
        ));
    }
    pre_create_db_file(&cfg.path)?;

    // We pre-created the file on Unix (0o600, mode set atomically at
    // create time). On non-Unix platforms we let sqlx create the file via
    // create_if_missing(true); the platform's ACL model governs the
    // resulting file.
    let create_if_missing: bool = {
        #[cfg(unix)]
        {
            false
        }
        #[cfg(not(unix))]
        {
            true
        }
    };
    // The path goes to SQLite as a `PathBuf`, never as a `sqlite:` URL
    // string: sqlx parses that URL as a URI and percent-decodes it, so a
    // path containing `%2F`, `?` or `#` names a different file than the one
    // `pre_create_db_file` just created with mode 0600, the file nobody opens.
    let options = SqliteConnectOptions::new()
        .filename(&cfg.path)
        .create_if_missing(create_if_missing)
        .journal_mode(SqliteJournalMode::Wal)
        // NORMAL is the recommended synchronous mode for WAL: survives a
        // process crash without the per-commit fsync cost of FULL.
        .synchronous(SqliteSynchronous::Normal)
        .foreign_keys(true)
        .busy_timeout(Duration::from_millis(cfg.busy_timeout_ms.into()));

    let pool = SqlitePoolOptions::new()
        .max_connections(cfg.max_connections)
        .connect_with(options)
        .await?;

    restrict_file_permissions(&cfg.path)?;
    Ok(pool)
}

/// On Unix only: ensure the parent directory exists (with mode `0o700` if we
/// just created it) and pre-create the database file with mode `0o600` via
/// `create_new(true)` so a second process racing for the same file fails
/// with `AlreadyExists` instead of inheriting a permissive umask.
///
/// On non-Unix platforms this is a no-op; sqlx creates the file and the
/// platform's ACL model governs.
fn pre_create_db_file(path: &std::path::Path) -> crate::Result<()> {
    #[cfg(unix)]
    {
        use std::io;
        use std::os::unix::fs::OpenOptionsExt;
        use std::os::unix::fs::PermissionsExt;

        if let Some(parent) = path.parent().filter(|p| !p.exists()) {
            std::fs::create_dir_all(parent).map_err(|err| {
                crate::Error::Database(format!(
                    "failed to create database parent dir {}: {err}",
                    parent.display()
                ))
            })?;
            if let Ok(meta) = std::fs::metadata(parent) {
                let mut perms = meta.permissions();
                perms.set_mode(0o700);
                if let Err(err) = std::fs::set_permissions(parent, perms) {
                    // Warn-only: hard-fail would refuse to start when the
                    // parent dir exists with ownership outside the fumox
                    // process (common in /var/lib deployments). Warn makes
                    // the failure visible without an operational disruption.
                    tracing::warn!(
                        path = %parent.display(),
                        mode = 0o700_u32,
                        error = %err,
                        "failed to chmod database parent dir to 0700",
                    );
                }
            }
        }

        if !path.exists() {
            match std::fs::OpenOptions::new()
                .create_new(true)
                .write(true)
                .mode(0o600)
                .open(path)
            {
                Ok(_) => {}
                Err(err) if err.kind() == io::ErrorKind::AlreadyExists => {
                    // Another process won the create race; the existing file
                    // has its mode set already.
                }
                Err(err) => {
                    return Err(crate::Error::Database(format!(
                        "failed to create database file {}: {err}",
                        path.display()
                    )));
                }
            }
        } else {
            // File exists from a previous boot, open read-only to confirm
            // it is accessible, no chmod here (we'd be racing the other
            // process if any).
            let _ = std::fs::OpenOptions::new().read(true).open(path);
        }
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
    Ok(())
}

/// Runs the sqlx migrations embedded in `fumox-core` and mirrors the applied
/// schema version into the `meta` table (DATABASE, exploitation notes).
///
/// `sqlx` rejects startup when a previously-applied migration file has been
/// edited in place: the SHA-384 stored in `_sqlx_migrations.checksum` no
/// longer matches the file. The intended discipline is to never edit an
/// applied migration, every change belongs in a new file. Comment-only
/// edits break this discipline for no gain, so this function catches the
/// specific `VersionMismatch` variant and re-stamps every applied
/// migration's checksum with the on-disk content.
///
/// What the re-stamp does *not* do is apply anything: sqlx never re-runs
/// an already-applied migration, and the SHA-384 covers the whole file, so
/// a comment edit and a DDL edit are indistinguishable at this point. A
/// DDL edit to an applied file therefore leaves the on-disk schema behind
/// the file's contents, and no amount of re-stamping closes that gap, it
/// has to be closed with a new migration file. The repair is consequently
/// never silent: the affected versions are logged at `error` level with
/// that instruction, and recorded in `meta.migrations_repaired` so the
/// fact survives the log. Any other error (dirty state, missing migration,
/// structural mismatch, real DDL failure) is surfaced to the caller
/// untouched.
pub async fn migrate(pool: &SqlitePool) -> crate::Result<()> {
    let migrator: Migrator = sqlx::migrate!("./migrations");
    let mut repaired: Vec<i64> = Vec::new();
    if let Err(error) = migrator.run(pool).await {
        if !matches!(error, MigrateError::VersionMismatch(_)) {
            return Err(error.into());
        }
        // `migrator.iter()` carries the canonical checksums the embedded
        // copy expects. Only applied versions are touched, so the
        // bookkeeping row exists for every version we rewrite.
        repaired = repair_migration_checksums(pool, &migrator).await?;
        if repaired.is_empty() {
            // Nothing was rewritten, so the retry below would fail with the
            // very same error. Report the original mismatch instead of
            // claiming a repair that did not happen.
            return Err(error.into());
        }
        migrator.run(pool).await?;
    }

    let applied: i64 = sqlx::query_scalar("SELECT COALESCE(MAX(version), 0) FROM _sqlx_migrations")
        .fetch_one(pool)
        .await?;

    // The `meta` table is created by the schema migration; before it exists
    // (e.g. an empty migration set) there is nowhere to record the version.
    let meta_exists: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'meta')",
    )
    .fetch_one(pool)
    .await?;

    if meta_exists {
        sqlx::query(
            "INSERT INTO meta (key, value) VALUES ('schema_version', ?)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        )
        .bind(applied.to_string())
        .execute(pool)
        .await?;
    }

    if !repaired.is_empty() {
        record_migration_repair(pool, &repaired).await?;
    }

    Ok(())
}

/// Persist the self-heal under `meta.migrations_repaired` and shout about
/// it. The `meta` row is the part that outlives the process: a boot log is
/// usually long gone by the time an operator wonders why a column they see
/// in a migration file is missing from the schema.
async fn record_migration_repair(pool: &SqlitePool, versions: &[i64]) -> crate::Result<()> {
    let list = versions
        .iter()
        .map(i64::to_string)
        .collect::<Vec<_>>()
        .join(",");
    let since_unix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or_default();
    tracing::error!(
        versions = ?versions,
        "sqlx migration checksum mismatch on already-applied migration(s); \
         the stored SHA-384 was re-stamped from the files and the schema on \
         disk was NOT changed. sqlx never re-runs an applied migration, so if \
         the edit was not comment-only the schema is now behind the files: \
         ship a new migration file for the DDL"
    );
    // Best effort: a failure to write the breadcrumb must not turn a
    // recovered boot into a failed one, the log line above already fired.
    let recorded = sqlx::query(
        "INSERT INTO meta (key, value) VALUES ('migrations_repaired', ?)
         ON CONFLICT(key) DO UPDATE SET value = excluded.value",
    )
    .bind(format!("versions=[{list}] at {since_unix}"))
    .execute(pool)
    .await;
    if let Err(err) = recorded {
        tracing::warn!(
            error = %err,
            "failed to record the migration repair under meta.migrations_repaired"
        );
    }
    Ok(())
}

/// Re-stamp every applied migration's stored SHA-384 with the checksum
/// the embedded `Migrator` derives from the current file content. Used by
/// [`migrate`] to recover from a checksum mismatch (comment-only edits to
/// already-applied migration files), and exposed as a standalone helper so
/// tests, the `repair_migration_checksums` example and ops scripts can
/// trigger the same repair without booting the full server, one
/// implementation, so the guards below cannot drift from the tool's copy.
/// Returns the list of versions whose checksums were actually rewritten:
/// a version whose stored hash already matches is not reported, and a row
/// this build's embedded set does not know about is never touched.
pub async fn repair_migration_checksums(
    pool: &SqlitePool,
    migrator: &Migrator,
) -> crate::Result<Vec<i64>> {
    let applied_versions: Vec<i64> =
        sqlx::query_scalar("SELECT version FROM _sqlx_migrations WHERE success = 1")
            .fetch_all(pool)
            .await?;
    let applied: std::collections::HashSet<i64> = applied_versions.iter().copied().collect();
    let mut re_stamped = Vec::new();
    for migration in migrator.iter() {
        if !applied.contains(&migration.version) {
            // Skip migrations the embedded set knows about that have not
            // been applied yet, the next regular `migrate()` will run them
            // and stamp their checksum at the end. Touching them here
            // would race the migrator's own bookkeeping.
            continue;
        }
        // `WHERE checksum != ?2` keeps the no-op path zero-cost on a clean
        // DB, the row is rewritten exactly when the stored hash disagrees
        // with the on-disk file.
        let rows = sqlx::query(
            "UPDATE _sqlx_migrations
             SET checksum = ?2
             WHERE version = ?1 AND success = 1 AND checksum != ?2",
        )
        .bind(migration.version)
        .bind(&*migration.checksum)
        .execute(pool)
        .await?;
        if rows.rows_affected() == 1 {
            re_stamped.push(migration.version);
        }
    }
    // Force the WAL log through so a second `migrate()` from the same
    // process sees the new values without a checkpoint race. Best-effort: a
    // concurrent reader can make the PASS checkpoint return busy, and the
    // re-stamp is idempotent, so the failure is logged, not fatal.
    //
    // `wal_checkpoint` reports busy as a *row* (`busy, log, checkpointed`),
    // not as an error, so `execute` discarded it and this line could never
    // fire for the case the comment names. Read the row.
    match sqlx::query("PRAGMA wal_checkpoint(PASS)")
        .fetch_one(pool)
        .await
    {
        Ok(row) => {
            let busy: i64 = sqlx::Row::try_get(&row, 0).unwrap_or_default();
            if busy != 0 {
                tracing::debug!("wal_checkpoint(PASS) after migration re-stamp was busy");
            }
        }
        Err(err) => {
            tracing::debug!(error = %err, "wal_checkpoint(PASS) after migration re-stamp failed")
        }
    }
    Ok(re_stamped)
}

/// Test-only switch: when set, the inner `set_permissions` call inside
/// `restrict_file_permissions` short-circuits with a `PermissionDenied`
/// error. The OS only denies chmod when the process lacks ownership of the
/// file, a state tests cannot arrange portably, so this flag is the
/// smallest indirection that exercises the chmod-fail branch. Guarded by a
/// `ChmodFailGuard` whose `Drop` resets it so a panic between `store(true)`
/// and the assertion cannot leak into subsequent tests in the same process.
#[cfg(all(test, unix))]
static SIMULATE_CHMOD_FAIL: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

/// Serializes the chmod-fail test against the two existing chmod-touching
/// tests. `SIMULATE_CHMOD_FAIL` is process-global, and `cargo test` runs
/// `#[tokio::test]`s in parallel by default, without this mutex the
/// `connect_pool_returns_err_when_chmod_fails` test would race the other
/// two and leak a transient `true` into their `connect_pool` calls.
#[cfg(all(test, unix))]
fn chmod_test_mutex() -> &'static tokio::sync::Mutex<()> {
    static MUTEX: std::sync::OnceLock<tokio::sync::Mutex<()>> = std::sync::OnceLock::new();
    MUTEX.get_or_init(|| tokio::sync::Mutex::new(()))
}

/// Confirm the database file is `0600` on Unix; abort with a hard error if
/// the chmod fails so the operator notices a misconfigured database
/// directory instead of running with a world-readable credentials file.
///
/// On non-Unix platforms this is a no-op: NTFS DACLs (or whatever the host
/// uses) govern file access, and `set_permissions` is not available.
fn restrict_file_permissions(path: &std::path::Path) -> crate::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let meta = std::fs::metadata(path).map_err(|err| {
            crate::Error::Database(format!(
                "failed to stat database file {path}: {err}",
                path = path.display()
            ))
        })?;
        let mut perms = meta.permissions();
        perms.set_mode(0o600);
        #[cfg(all(test, unix))]
        if SIMULATE_CHMOD_FAIL.load(std::sync::atomic::Ordering::SeqCst) {
            return Err(crate::Error::Database(format!(
                "failed to set 0600 on database file {path}: permission denied",
                path = path.display()
            )));
        }
        std::fs::set_permissions(path, perms).map_err(|err| {
            crate::Error::Database(format!(
                "failed to set 0600 on database file {path}: {err}",
                path = path.display()
            ))
        })?;
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
    Ok(())
}

#[cfg(all(test, unix))]
mod unix_db_tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;

    /// Each test gets its own scratch dir; the database lives inside it so
    /// the parent-dir creation path is exercised too.
    fn fresh_db_path(label: &str) -> (tempdir_lite::TempDir, PathBuf) {
        let dir = tempdir_lite::TempDir::new(label);
        let path = dir.path().join("fumox.db");
        (dir, path)
    }

    #[tokio::test]
    async fn connect_pool_writes_file_with_mode_0600() {
        let _serial = chmod_test_mutex().lock().await;
        let (_dir, path) = fresh_db_path("db-mode");
        let cfg = DatabaseConfig {
            path: path.clone(),
            busy_timeout_ms: 1000,
            max_connections: 1,
        };
        let _pool = connect_pool(&cfg).await.unwrap();
        let meta = std::fs::metadata(&path).unwrap();
        assert_eq!(meta.permissions().mode() & 0o777, 0o600);
    }

    /// The configured path reaches SQLite verbatim. Interpolating it into
    /// a `sqlite:` URL string and letting sqlx URI-parse the result would
    /// percent-decode it: a database file named `pl%2Fain.db` would be
    /// opened as `pl/ain.db`, a file that does not exist, or worse one
    /// that does and was never chmod'ed to 0600.
    #[tokio::test]
    async fn connect_pool_opens_the_literal_path_without_uri_decoding() {
        let _serial = chmod_test_mutex().lock().await;
        let dir = tempdir_lite::TempDir::new("db-percent-path");
        let path = dir.path().join("pl%2Fain%3Fmode=ro.db");
        let cfg = DatabaseConfig {
            path: path.clone(),
            busy_timeout_ms: 1000,
            max_connections: 1,
        };
        let pool = connect_pool(&cfg).await.unwrap();
        // The file `pre_create_db_file` chmod'ed is the one the pool opened.
        let opened: String =
            sqlx::query_scalar("SELECT file FROM pragma_database_list WHERE name = 'main'")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(
            // SQLite reports the path with symlinks resolved (/var ->
            // /private/var on macOS), so compare the canonical forms.
            std::fs::canonicalize(&opened).unwrap(),
            std::fs::canonicalize(&path).unwrap(),
            "the pool must open the configured path, not a URI-decoded variant of it"
        );
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    /// A zero-sized pool is a config error, not a runtime condition: sqlx
    /// accepts `max_connections(0)` and then fails every acquisition with
    /// `PoolTimedOut` 30 s later, so without this guard a typo in
    /// `[database]` costs the operator a 30 s startup stall and a
    /// `PoolTimedOut` that never names the offending key.
    #[tokio::test]
    async fn connect_pool_rejects_zero_max_connections() {
        let (_dir, path) = fresh_db_path("db-zero-conns");
        let cfg = DatabaseConfig {
            path: path.clone(),
            busy_timeout_ms: 1000,
            max_connections: 0,
        };
        let err = connect_pool(&cfg).await.unwrap_err();
        assert!(
            err.to_string().contains("max_connections"),
            "expected the error to name database.max_connections, got: {err}"
        );
        // Rejected before the pool is built, so the file was never touched.
        assert!(
            !path.exists(),
            "the config error must fire before pre_create_db_file"
        );
    }

    #[tokio::test]
    async fn connect_pool_restores_0600_on_existing_file_with_wrong_mode() {
        let _serial = chmod_test_mutex().lock().await;
        let (_dir, path) = fresh_db_path("db-wrong");
        // Pre-create the file with permissive mode, restrict_file_permissions
        // must succeed (chmod it back to 0600) and the pool must open.
        std::fs::write(&path, b"").unwrap();
        let mut perms = std::fs::metadata(&path).unwrap().permissions();
        perms.set_mode(0o644);
        std::fs::set_permissions(&path, perms).unwrap();

        let cfg = DatabaseConfig {
            path: path.clone(),
            busy_timeout_ms: 1000,
            max_connections: 1,
        };
        let _pool = connect_pool(&cfg).await.unwrap();
        // The chmod-confirmation step brought it back to 0600.
        let meta = std::fs::metadata(&path).unwrap();
        assert_eq!(meta.permissions().mode() & 0o777, 0o600);
    }

    /// Panic-safe RAII handle for `SIMULATE_CHMOD_FAIL`. The Drop resets the
    /// flag so a panic inside the test body cannot leak the chmod-fail mode
    /// into the next test in the same process.
    struct ChmodFailGuard;
    impl Drop for ChmodFailGuard {
        fn drop(&mut self) {
            SIMULATE_CHMOD_FAIL.store(false, std::sync::atomic::Ordering::SeqCst);
        }
    }

    #[tokio::test]
    async fn connect_pool_returns_err_when_chmod_fails() {
        // Lock the test mutex for the full chmod-touching window so the
        // flag can never leak into a concurrently-running chmod test. The
        // ChmodFailGuard's Drop resets the flag itself; the mutex keeps
        // the window tight.
        let _serial = chmod_test_mutex().lock().await;
        let (_dir, path) = fresh_db_path("db-chmod-fail");
        SIMULATE_CHMOD_FAIL.store(true, std::sync::atomic::Ordering::SeqCst);
        let _guard = ChmodFailGuard;

        let cfg = DatabaseConfig {
            path: path.clone(),
            busy_timeout_ms: 1000,
            max_connections: 1,
        };
        let err = connect_pool(&cfg).await.unwrap_err();
        // The Database wrapper for the chmod path is named "set 0600" in
        // `restrict_file_permissions`, pin that wording so a future
        // refactor of the message does not silently break the error
        // contract.
        assert!(
            err.to_string().contains("set 0600"),
            "expected chmod-fail error mentioning `set 0600`, got: {err}",
        );
    }

    /// Pins the atomicity of `OpenOptions::create_new(true).mode(0o600)`:
    /// right after `pre_create_db_file` returns, the file must exist with
    /// mode `0o600`, there is no window during which it exists with a
    /// permissive mode. Reaching `pre_create_db_file` directly avoids the
    /// need for a true concurrent race to exercise the property.
    #[cfg(unix)]
    #[test]
    fn pre_create_db_file_sets_mode_0600_atomically_on_create() {
        let (_dir, path) = fresh_db_path("db-pre-create-mode");
        pre_create_db_file(&path).unwrap();
        let meta = std::fs::metadata(&path).unwrap();
        assert_eq!(meta.permissions().mode() & 0o777, 0o600);
    }

    #[tokio::test]
    async fn parent_dir_gets_mode_0700_when_created() {
        // Locked for symmetry with the chmod-touching tests: this test
        // also calls `connect_pool` and would race
        // `connect_pool_returns_err_when_chmod_fails` for the
        // `SIMULATE_CHMOD_FAIL` flag if it ran in parallel.
        let _serial = chmod_test_mutex().lock().await;
        // Nested fresh path under a non-existent parent; the parent dir
        // creation path in pre_create_db_file should chmod it 0700.
        let dir = tempdir_lite::TempDir::new("db-parent");
        let nested = dir.path().join("a/b/c/fumox.db");
        let cfg = DatabaseConfig {
            path: nested,
            busy_timeout_ms: 1000,
            max_connections: 1,
        };
        let _pool = connect_pool(&cfg).await.unwrap();
        let parent = dir.path().join("a/b/c");
        let meta = std::fs::metadata(&parent).unwrap();
        assert_eq!(meta.permissions().mode() & 0o777, 0o700);
    }
}

#[cfg(all(test, not(unix)))]
mod non_unix_db_tests {
    use super::*;
    use std::path::PathBuf;

    /// Fresh scratch dir per test, mirroring `unix_db_tests::fresh_db_path`
    /// (the existing `tempdir_lite` helper is now compiled on every
    /// platform).
    fn fresh_db_path(label: &str) -> (tempdir_lite::TempDir, PathBuf) {
        let dir = tempdir_lite::TempDir::new(label);
        let path = dir.path().join("fumox.db");
        (dir, path)
    }

    /// Pins the platform split of `create_if_missing`: on non-Unix we ask
    /// sqlx to create the file, so a fresh non-existent path must produce
    /// a populated file at `cfg.path`. Without
    /// `create_if_missing(true)` on non-Unix this `connect_pool` call would
    /// have failed at runtime on a fresh Windows install.
    #[tokio::test]
    async fn connect_pool_creates_file_on_non_unix() {
        let (_dir, path) = fresh_db_path("db-non-unix-create");
        // Pre-condition: the file does not exist yet.
        assert!(!path.exists(), "test pre-condition: file must not exist");

        let cfg = DatabaseConfig {
            path: path.clone(),
            busy_timeout_ms: 1000,
            max_connections: 1,
        };
        let _pool = connect_pool(&cfg).await.unwrap();
        assert!(
            path.exists(),
            "connect_pool must create the file on non-Unix (create_if_missing(true))"
        );
    }

    /// Pins that the post-pool chmod confirmation does not regress on
    /// non-Unix: `restrict_file_permissions` is a no-op there, so a
    /// pre-existing empty file must still let `connect_pool` succeed
    /// without raising a `PermissionDenied`.
    #[tokio::test]
    async fn restrict_file_permissions_is_a_noop_on_non_unix() {
        let (_dir, path) = fresh_db_path("db-non-unix-chmod-noop");
        std::fs::write(&path, b"").unwrap();

        let cfg = DatabaseConfig {
            path: path.clone(),
            busy_timeout_ms: 1000,
            max_connections: 1,
        };
        let _pool = connect_pool(&cfg).await.unwrap();
        assert!(
            path.exists(),
            "pre-existing file must survive connect_pool on non-Unix"
        );
    }
}

/// Minimal scoped-tempdir helper for the test modules of every workspace
/// crate (fumox-core's own db tests, the server's and the probe daemon's):
/// `TempDir::new` creates a fresh `fumox-test-<label>-<pid>-<n>` directory
/// under the system temp dir and `Drop` removes the whole tree, so a test
/// cannot leave its scratch database or config file behind. Deliberately
/// compiled outside `cfg(test)`: the sibling crates' test builds link
/// fumox-core as a plain dependency, where this crate's own `cfg(test)`
/// never applies. It carries no dependencies and has no production call
/// sites (re-exported from the crate root as `fumox_core::tempdir_lite`).
pub mod tempdir_lite {
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    /// Distinguishes concurrent `new` calls inside one process: parallel
    /// tests share the pid, so label + pid alone would not name a unique
    /// directory (and `new` clears its own path first).
    static SEQ: AtomicU64 = AtomicU64::new(0);

    /// A directory that removes itself (recursively) on drop.
    pub struct TempDir {
        path: PathBuf,
    }
    impl TempDir {
        pub fn new(label: &str) -> Self {
            let unique = SEQ.fetch_add(1, Ordering::Relaxed);
            let base = std::env::temp_dir().join(format!(
                "fumox-test-{label}-{}-{}",
                std::process::id(),
                unique
            ));
            let _ = std::fs::remove_dir_all(&base);
            std::fs::create_dir_all(&base).unwrap();
            Self { path: base }
        }
        pub fn path(&self) -> &std::path::Path {
            &self.path
        }
    }
    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }
}

#[cfg(test)]
mod tempdir_tests {
    use super::tempdir_lite::TempDir;

    /// Pins the helper's own contract: a fresh directory that exists while
    /// held and is gone (recursively, with everything a test put inside)
    /// once dropped.
    #[test]
    fn tempdir_removes_its_tree_on_drop() {
        let dir = TempDir::new("selfclean");
        let path = dir.path().to_path_buf();
        let file = path.join("scratch.db");
        std::fs::write(&file, b"x").unwrap();
        assert!(path.is_dir(), "TempDir::new must create the directory");
        assert!(file.is_file(), "the test's own files live inside");
        drop(dir);
        assert!(
            !path.exists(),
            "the scoped tempdir must remove its tree on drop"
        );
    }
}
