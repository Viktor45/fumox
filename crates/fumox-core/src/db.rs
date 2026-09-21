//! SQLite connection helpers.
//!
//! SQLite in WAL mode is the single shared source of truth between
//! `fumox-server` and `fumox-probe`. Every connection enables WAL, foreign
//! keys and `busy_timeout` — without the latter, concurrent upserts from two
//! processes produce `SQLITE_BUSY` (DATABASE, exploitation notes).

use std::str::FromStr;
use std::time::Duration;

use sqlx::SqlitePool;
use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions, SqliteSynchronous};

use crate::config::DatabaseConfig;

/// Type alias used across repository code.
pub type DbPool = SqlitePool;

/// Opens a connection pool configured for multi-process WAL access.
///
/// The database file is created with `0600` permissions on Unix because it
/// stores proxy credentials in plain text (PLAN, gap 11).
///
/// Pre-create race story (Unix):
/// - Process A: pre-creates with `OpenOptions::create_new(true).mode(0o600)`
///   → wins, file born with mode `0o600` atomically.
/// - Process B: tries the same `create_new(true)` → `AlreadyExists` → drops
///   into the "present" branch → opens the existing file with mode already
///   `0o600` (set by A) → `restrict_file_permissions` is a no-op
///   confirmation.
/// - The window during which the file exists without `0o600` is *zero* — the
///   OS sets the mode atomically at create time.
///
/// On non-Unix platforms the pre-create step is a no-op (NTFS DACLs govern
/// file access); the `restrict_file_permissions` confirmation is also a
/// no-op.
pub async fn connect_pool(cfg: &DatabaseConfig) -> crate::Result<SqlitePool> {
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
    let options = SqliteConnectOptions::from_str(&sqlite_url(&cfg.path))?
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
            // File exists from a previous boot — open read-only to confirm
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
pub async fn migrate(pool: &SqlitePool) -> crate::Result<()> {
    sqlx::migrate!("./migrations").run(pool).await?;

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

    Ok(())
}

fn sqlite_url(path: &std::path::Path) -> String {
    format!("sqlite:{}", path.display())
}

/// Test-only switch: when set, the inner `set_permissions` call inside
/// `restrict_file_permissions` short-circuits with a `PermissionDenied`
/// error. The OS only denies chmod when the process lacks ownership of the
/// file — a state tests cannot arrange portably — so this flag is the
/// smallest indirection that exercises the chmod-fail branch. Guarded by a
/// `ChmodFailGuard` whose `Drop` resets it so a panic between `store(true)`
/// and the assertion cannot leak into subsequent tests in the same process.
#[cfg(all(test, unix))]
static SIMULATE_CHMOD_FAIL: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

/// Serializes the chmod-fail test against the two existing chmod-touching
/// tests. `SIMULATE_CHMOD_FAIL` is process-global, and `cargo test` runs
/// `#[tokio::test]`s in parallel by default — without this mutex the
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

    #[tokio::test]
    async fn connect_pool_restores_0600_on_existing_file_with_wrong_mode() {
        let _serial = chmod_test_mutex().lock().await;
        let (_dir, path) = fresh_db_path("db-wrong");
        // Pre-create the file with permissive mode — restrict_file_permissions
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
        // `restrict_file_permissions` — pin that wording so a future
        // refactor of the message does not silently break the error
        // contract.
        assert!(
            err.to_string().contains("set 0600"),
            "expected chmod-fail error mentioning `set 0600`, got: {err}",
        );
    }

    /// Pins the atomicity of `OpenOptions::create_new(true).mode(0o600)`:
    /// right after `pre_create_db_file` returns, the file must exist with
    /// mode `0o600` — there is no window during which it exists with a
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

/// Minimal in-crate tempdir helper so we don't pull a dependency just for
/// the db tests (Unix and non-Unix variants share it).
#[cfg(test)]
mod tempdir_lite {
    use std::path::PathBuf;

    pub struct TempDir {
        path: PathBuf,
    }
    impl TempDir {
        pub fn new(label: &str) -> Self {
            let base =
                std::env::temp_dir().join(format!("fumox-db-test-{label}-{}", std::process::id(),));
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
