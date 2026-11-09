//! SQLite connection helpers.
//!
//! SQLite in WAL mode is the single shared source of truth between
//! `fumox-server` and `fumox-probe`. Every connection enables WAL, foreign
//! keys and `busy_timeout`; without the latter, concurrent upserts from two
//! processes produce `SQLITE_BUSY`, because the busy timeout is what lets
//! one writer wait out another process's open transaction instead of
//! failing on it.

use std::time::Duration;

use sqlx::SqlitePool;
use sqlx::migrate::{MigrateError, Migrator};
use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions, SqliteSynchronous};

use crate::config::{DatabaseConfig, SynchronousMode};

/// Type alias used across repository code.
pub type DbPool = SqlitePool;

/// Which writes a pool's connections may perform.
#[derive(Clone, Copy, PartialEq, Eq)]
enum WriteScope {
    /// Every write is allowed. The server owns the subscription
    /// content and has to be able to write all of it.
    Full,
    /// Only the health status of a proxy may change. See
    /// [`crate::sqlite_guard`].
    ProbeOnly,
}

/// Opens a connection pool configured for multi-process WAL access.
///
/// `create_new(true).mode(0o600)` sets the 0600 mode atomically, so the file
/// holding the plain-text credentials is never briefly world-readable; on
/// non-Unix this is a no-op and the ACL model governs.
pub async fn connect_pool(cfg: &DatabaseConfig) -> crate::Result<SqlitePool> {
    connect_pool_with(cfg, WriteScope::Full).await
}

/// Opens the probe daemon's connection pool.
///
/// The probe shares the database file with the server, but it owns only
/// the health status of a proxy. Its connections run behind an
/// authorizer that denies every other write, so a defect in the probe
/// cannot rewrite the subscription content (hosts, credentials,
/// sources) that the server maintains.
///
/// The schema is applied first, on an unrestricted connection: a
/// migration rewrites the schema and may move rows between tables,
/// which the restricted connections refuse. The probe therefore owns
/// the schema even when it starts before the server does.
pub async fn connect_probe_pool(cfg: &DatabaseConfig) -> crate::Result<SqlitePool> {
    let schema_pool = connect_pool(cfg).await?;
    // The server may be migrating the same file right now: the pod
    // layouts start both processes at once. SQLite serializes the
    // writers, but the loser of that race gets SQLITE_BUSY once the
    // busy timeout is over, and a failed migration would take the probe
    // down. Retry for a while instead — the server finishes, the write
    // lock is free, the migration succeeds.
    let mut attempt = 0;
    loop {
        let outcome = migrate_with(
            &schema_pool,
            ChecksumRepair::from_config(cfg.allow_checksum_repair),
        )
        .await;
        match outcome {
            Ok(()) => break,
            Err(error) => {
                // Only contention is worth waiting for. A checksum
                // mismatch or a broken schema will fail the same way on
                // the next attempt, and retrying it would hide the real
                // reason behind a timeout.
                if !error.is_busy() {
                    drop(schema_pool);
                    return Err(error);
                }
                attempt += 1;
                if attempt >= 10 {
                    drop(schema_pool);
                    return Err(error);
                }
                tracing::warn!(
                    attempt,
                    error = %error,
                    "the schema migration failed, retrying (the server may hold the write lock)"
                );
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            }
        }
    }
    drop(schema_pool);
    connect_pool_with(cfg, WriteScope::ProbeOnly).await
}

async fn connect_pool_with(cfg: &DatabaseConfig, scope: WriteScope) -> crate::Result<SqlitePool> {
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
    // Parent-directory creation, the pre-create of the file itself and the
    // chmod are blocking syscalls; run them off the async worker thread.
    // The 0600 mode has to be in place before SQLite opens the file: the
    // `-wal` and `-shm` sidecars SQLite creates at open time inherit the
    // database file's mode, so a permissive file would spawn permissive
    // sidecars that no later chmod of the main file fixes.
    let path = cfg.path.clone();
    tokio::task::spawn_blocking(move || {
        pre_create_db_file(&path)?;
        restrict_file_permissions(&path)
    })
    .await
    .map_err(|err| {
        crate::Error::Database(format!("the database file preparation task failed: {err}"))
    })??;

    // We pre-created the file on Unix (0o600, mode set atomically at
    // create time, and an already-existing file restored right away). On
    // non-Unix platforms we let sqlx create the file via
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
        // process crash without the per-commit fsync cost of FULL. The
        // level is a deployment decision, so it comes from the config.
        .synchronous(match cfg.synchronous {
            SynchronousMode::Normal => SqliteSynchronous::Normal,
            SynchronousMode::Full => SqliteSynchronous::Full,
        })
        .foreign_keys(true)
        .busy_timeout(Duration::from_millis(cfg.busy_timeout_ms.into()));

    let mut pool_options = SqlitePoolOptions::new().max_connections(cfg.max_connections);
    if scope == WriteScope::ProbeOnly {
        // The authorizer lives on the connection, not on the pool, so it
        // has to be installed on every connection the pool opens —
        // including the ones it grows into later.
        pool_options = pool_options.after_connect(|connection, _meta| {
            Box::pin(async move {
                crate::sqlite_guard::install(connection).await?;
                Ok(())
            })
        });
    }
    let pool = pool_options.connect_with(options).await?;
    tracing::info!(
        path = %cfg.path.display(),
        max_connections = cfg.max_connections,
        busy_timeout_ms = cfg.busy_timeout_ms,
        journal_mode = "wal",
        synchronous = ?cfg.synchronous,
        "database pool opened"
    );

    // WAL keeps the page cache and the write-ahead log in sidecar files
    // next to the database. They hold the same rows as the database
    // itself, so they get the same mode; SQLite creates them lazily, so
    // they may not exist yet at this point. Like the preparation above,
    // the stat/chmod loop is blocking work and stays off the worker
    // thread.
    let path = cfg.path.clone();
    tokio::task::spawn_blocking(move || restrict_sidecar_permissions(&path))
        .await
        .map_err(|err| {
            crate::Error::Database(format!("the database sidecar securing task failed: {err}"))
        })??;
    Ok(pool)
}

/// Ensure the parent directory exists — on every platform — and, on Unix,
/// pre-create the database file with mode `0o600` via `create_new(true)` so
/// a second process racing for the same file fails with `AlreadyExists`
/// instead of inheriting a permissive umask.
///
/// A directory this function creates is tightened to `0o700`: it holds the
/// credentials. A directory that already existed keeps its mode — a
/// container volume or a `/var/lib` deployment owns that mode, and
/// failing the startup over it would take the service down for a
/// property the operator did not ask fumox to enforce. A too-permissive
/// existing directory is reported as a warning instead.
///
/// The path is opened with `O_NOFOLLOW`: a symlink at the database path
/// would otherwise redirect the whole database to a file the operator did
/// not choose, and the `0600` mode would land on the symlink's target
/// instead of on a file of our own.
///
/// On non-Unix platforms only the parent directory is created; sqlx creates
/// the file itself (`create_if_missing(true)`) and the platform's ACL model
/// governs.
fn pre_create_db_file(path: &std::path::Path) -> crate::Result<()> {
    // A missing parent directory fails `sqlx` on every platform, and
    // `create_dir_all` is the portable fix; only the mode bookkeeping
    // around the directory and the file itself is Unix-specific below.
    if let Some(parent) = path.parent().filter(|p| !p.exists()) {
        std::fs::create_dir_all(parent).map_err(|err| {
            crate::Error::Database(format!(
                "failed to create database parent dir for database.path={}: {err}",
                path.display()
            ))
        })?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            // `create_dir_all` applies the process umask to every directory
            // it creates, so the mode is set explicitly afterwards. The
            // directory holds the credentials: nobody else needs to enter
            // it.
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
    } else {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            if let Some(parent) = path.parent() {
                // The directory already exists. If it is group- or
                // world-readable, the credentials file inside it is one
                // directory traversal away from anyone on the host, so say
                // so loudly instead of only tightening the file mode.
                if let Ok(meta) = std::fs::metadata(parent) {
                    let mode = meta.permissions().mode() & 0o777;
                    if mode & 0o077 != 0 {
                        tracing::warn!(
                            path = %parent.display(),
                            mode = format!("{mode:04o}"),
                            "database parent dir is readable by group or others; \
                             chmod it to 0700 to keep the credentials private"
                        );
                    }
                }
            }
        }
    }

    #[cfg(unix)]
    {
        use std::io;
        use std::os::unix::fs::OpenOptionsExt;

        // A symlink at the database path is refused: the operator asked
        // for a database, not for whatever the link points at.
        match std::fs::symlink_metadata(path) {
            Ok(meta) if meta.file_type().is_symlink() => {
                return Err(crate::Error::Database(format!(
                    "database path {} is a symlink; refusing to open it",
                    path.display()
                )));
            }
            Ok(_) => {}
            Err(err) if err.kind() == io::ErrorKind::NotFound => {}
            Err(err) => {
                return Err(crate::Error::Database(format!(
                    "failed to stat database file {}: {err}",
                    path.display()
                )));
            }
        }

        // `O_NOFOLLOW` closes the race between the `symlink_metadata` check
        // above and the open: a symlink swapped in between is rejected by
        // the kernel instead of being followed.
        let mut options = std::fs::OpenOptions::new();
        options
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW);

        match options.open(path) {
            Ok(_) => {}
            Err(err) if err.kind() == io::ErrorKind::AlreadyExists => {
                // Another process won the create race, or the file simply
                // already existed — its mode is not guaranteed. Restore
                // 0600 right here, before SQLite opens the file, so the
                // sidecars it creates at open time inherit the private
                // mode.
                restrict_file_permissions(path)?;
            }
            Err(err) => {
                return Err(crate::Error::Database(format!(
                    "failed to create database file at database.path={}: {err}",
                    path.display()
                )));
            }
        }
    }
    Ok(())
}

/// What a checksum mismatch is allowed to do to the boot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChecksumRepair {
    /// Stop the boot and name the version. The default.
    ///
    /// sqlx hashes the whole migration file, so a comment edit and a DDL
    /// edit are indistinguishable from here, and a re-stamp hides a
    /// schema that fell behind the files just as neatly as it hides a
    /// harmless comment. The operator has to say which one it was.
    Refuse,
    /// Re-stamp the stored checksums from the files on disk and carry
    /// on. Opt-in, for the operator who knows the edit was comment-only.
    Allow,
}

impl ChecksumRepair {
    /// The flag as the config carries it.
    pub const fn from_config(allow: bool) -> Self {
        if allow {
            ChecksumRepair::Allow
        } else {
            ChecksumRepair::Refuse
        }
    }
}

/// The migrations embedded in this build, as a `&'static` handle. One
/// instance: [`migrate_with`] runs it and the checksum repair
/// ([`repair_migration_checksums`]) reads its checksums, so the two can
/// never drift apart, and a caller outside the crate repairs against
/// exactly the set this build would migrate with.
pub fn embedded_migrator() -> &'static Migrator {
    static EMBEDDED: std::sync::OnceLock<Migrator> = std::sync::OnceLock::new();
    EMBEDDED.get_or_init(|| sqlx::migrate!("./migrations"))
}

/// Runs the sqlx migrations embedded in `fumox-core` and mirrors the applied
/// schema version into the `meta` table's `schema_version` key.
///
/// A checksum mismatch stops the boot: see [`migrate_with`] and
/// [`ChecksumRepair`].
pub async fn migrate(pool: &SqlitePool) -> crate::Result<()> {
    migrate_with(pool, ChecksumRepair::Refuse).await
}

/// The migrations, with the checksum policy the caller chose.
///
/// The pool has to be an unrestricted one: the probe's restricted
/// connections refuse the schema changes a migration makes.
/// [`connect_probe_pool`] applies the schema before it opens them.
///
/// The migrations run under an exclusive lock (see [`MigrationLock`]), so
/// two processes starting at the same moment cannot apply the same file
/// twice: sqlx does not lock a SQLite database while it migrates.
///
/// `sqlx` rejects startup when a previously-applied migration file has been
/// edited in place: the SHA-384 stored in `_sqlx_migrations.checksum` no
/// longer matches the file. The intended discipline is to never edit an
/// applied migration, every change belongs in a new file. A comment-only
/// edit breaks that discipline for no gain, but the re-stamp that hides it
/// also hides a DDL edit, so it is not done on its own: with
/// [`ChecksumRepair::Refuse`] the boot stops and names the version, and
/// with [`ChecksumRepair::Allow`] the operator has said that the edit was
/// harmless.
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
pub async fn migrate_with(pool: &SqlitePool, repair: ChecksumRepair) -> crate::Result<()> {
    let migrator = embedded_migrator();
    let _lock = MigrationLock::acquire(pool).await?;

    let mut original: Option<MigrateError> = None;
    let mut busy_attempt = 0u32;
    loop {
        match migrator.run(pool).await {
            Ok(()) => break,
            Err(error) => {
                if let MigrateError::VersionMismatch(version) = &error {
                    let version = *version;
                    if repair == ChecksumRepair::Refuse {
                        return Err(checksum_mismatch_error(version));
                    }
                    // Remember the mismatch: a failure of the retry has to
                    // name both, or the operator sees the symptom without
                    // the cause.
                    if original.is_none() {
                        original = Some(MigrateError::VersionMismatch(version));
                    }
                    // `migrator.iter()` carries the canonical checksums the
                    // embedded set expects. Only applied versions are
                    // touched, so the bookkeeping row exists for every
                    // version we rewrite.
                    let re_stamped = repair_migration_checksums(pool).await?;
                    if re_stamped.is_empty() {
                        // Nothing was rewritten, so the retry below would
                        // fail with the very same error. Report the
                        // original mismatch instead of claiming a repair
                        // that did not happen.
                        return Err(original
                            .take()
                            .map(crate::Error::from)
                            .unwrap_or_else(|| crate::Error::Database(String::new())));
                    }
                    // The breadcrumb and the error log go out *before* the
                    // retry: a crash in the middle of it must still leave
                    // the trace of what was re-stamped.
                    record_migration_repair(pool, &re_stamped).await?;
                    continue;
                }
                let converted: crate::Error = error.into();
                // Contention is the only failure worth waiting for: the
                // other writer finishes and the retry re-reads the applied
                // list.
                if converted.is_busy() {
                    busy_attempt += 1;
                    if busy_attempt <= MIGRATE_BUSY_ATTEMPTS {
                        tokio::time::sleep(busy_backoff(busy_attempt)).await;
                        continue;
                    }
                }
                // A failure after a repair belongs to that repair: name
                // both, or the operator sees the symptom without the
                // cause.
                if let Some(original) = original.take() {
                    return Err(crate::Error::Database(format!(
                        "the checksum repair did not make the migration succeed: {converted}; \
                         original: {original}"
                    )));
                }
                return Err(converted);
            }
        }
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

    tracing::info!(schema_version = applied, "database schema is up to date");

    Ok(())
}

/// How many times a migration is retried while the database is busy.
const MIGRATE_BUSY_ATTEMPTS: u32 = 10;

/// The wait before the first busy retry; every further one doubles, up to
/// the cap.
const MIGRATE_BUSY_BACKOFF: std::time::Duration = std::time::Duration::from_millis(100);
/// The ceiling of the busy backoff.
const MIGRATE_BUSY_BACKOFF_MAX: std::time::Duration = std::time::Duration::from_secs(2);

/// The wait before the next attempt after a busy database.
fn busy_backoff(attempt: u32) -> std::time::Duration {
    let factor = 1u32 << attempt.min(5);
    MIGRATE_BUSY_BACKOFF
        .saturating_mul(factor)
        .min(MIGRATE_BUSY_BACKOFF_MAX)
}

/// The error a refused checksum mismatch produces.
///
/// It names the version, says what a mismatch means, and gives the two
/// ways out: the repair tool, or the opt-in flag.
fn checksum_mismatch_error(version: i64) -> crate::Error {
    crate::Error::Database(format!(
        "applied migration {version} differs from the file — a new migration file is needed. \
         sqlx: migration {version} was previously applied but has been modified. \
         If the edit was comment-only, re-stamp it with \
         `cargo run -p fumox-core --bin repair_migration_checksums -- <database path>`, \
         or start once with [database].allow_checksum_repair = true."
    ))
}

/// The sidecar file that serialises the migrations between the processes
/// that share the database.
const MIGRATION_LOCK_SUFFIX: &str = "-migrate.lock";

/// How many times the lock is retried before the migration gives up.
const MIGRATION_LOCK_ATTEMPTS: u32 = 60;
/// The wait between two attempts at the lock.
const MIGRATION_LOCK_BACKOFF: std::time::Duration = std::time::Duration::from_millis(500);

/// An exclusive, advisory lock that serialises the migrations between the
/// processes that share the database file.
///
/// sqlx does not lock a SQLite database while it migrates — its
/// `Migrate::lock` is a no-op for SQLite — so the server and the probe
/// starting at the same moment can read the applied-migration list at the
/// same time and both try to apply the same file. One of them wins, the
/// other gets SQLITE_BUSY or a duplicate-version error.
///
/// The lock is a `flock` on a sidecar file next to the database: it is
/// advisory, so it serialises the migrators without getting in the way of
/// the readers and writers of the same database. Closing the descriptor
/// releases it, so a crashed process leaves no stale lock behind.
struct MigrationLock {
    /// Kept for its lifetime: the lock is released when the descriptor is
    /// closed.
    _file: std::fs::File,
}

impl MigrationLock {
    /// Take the lock, waiting for the process that holds it to finish its
    /// migration.
    ///
    /// `Ok(None)` means the lock is not available on this system — the
    /// sidecar cannot be created, or the filesystem has no `flock` — and
    /// the migration runs unlocked, which is how it behaved before the
    /// lock existed. `Err` means another process is migrating and did not
    /// finish within the budget.
    async fn acquire(pool: &SqlitePool) -> crate::Result<Option<Self>> {
        let file: Option<String> =
            sqlx::query_scalar("SELECT file FROM pragma_database_list WHERE name = 'main'")
                .fetch_one(pool)
                .await
                .ok();
        let Some(file) = file.filter(|path| !path.is_empty()) else {
            // An in-memory database has no file to lock, and no other
            // process can reach it either.
            return Ok(None);
        };
        let path = sidecar_path(std::path::Path::new(&file), MIGRATION_LOCK_SUFFIX);
        for _attempt in 1..=MIGRATION_LOCK_ATTEMPTS {
            match try_lock(&path) {
                LockAttempt::Taken(handle) => {
                    return Ok(Some(Self { _file: handle }));
                }
                LockAttempt::Contended => {
                    tokio::time::sleep(MIGRATION_LOCK_BACKOFF).await;
                }
                LockAttempt::Unavailable(err) => {
                    tracing::warn!(
                        path = %path.display(),
                        error = %err,
                        "the migration lock is not available, migrating without it"
                    );
                    return Ok(None);
                }
            }
        }
        Err(crate::Error::Database(format!(
            "another process is migrating {}: the migration lock stayed busy for {} s",
            file,
            u64::from(MIGRATION_LOCK_ATTEMPTS) * MIGRATION_LOCK_BACKOFF.as_secs()
        )))
    }
}

/// The outcome of one attempt at the migration lock.
enum LockAttempt {
    /// The lock is held by this process.
    Taken(std::fs::File),
    /// Another process holds it; try again later.
    Contended,
    /// The lock cannot be taken on this system at all.
    Unavailable(std::io::Error),
}

/// Take the exclusive lock on the sidecar, without waiting.
#[cfg(unix)]
fn try_lock(path: &std::path::Path) -> LockAttempt {
    use std::os::unix::fs::OpenOptionsExt;
    use std::os::unix::io::AsRawFd;

    let handle = match std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .mode(0o600)
        // A symlink at the lock path would redirect the lock to a file
        // the operator did not choose.
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
    {
        Ok(handle) => handle,
        Err(err) => return LockAttempt::Unavailable(err),
    };
    let rc = unsafe { libc::flock(handle.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
    if rc == 0 {
        return LockAttempt::Taken(handle);
    }
    let err = std::io::Error::last_os_error();
    match err.raw_os_error() {
        // Someone else holds the lock.
        Some(libc::EWOULDBLOCK) => LockAttempt::Contended,
        // Interrupted by a signal: try again.
        Some(libc::EINTR) => LockAttempt::Contended,
        // The filesystem has no advisory locking at all.
        Some(libc::ENOLCK) | Some(libc::EOPNOTSUPP) => LockAttempt::Unavailable(err),
        _ => LockAttempt::Unavailable(err),
    }
}

/// Advisory locking is a Unix facility; elsewhere the migration runs
/// unlocked.
#[cfg(not(unix))]
fn try_lock(_path: &std::path::Path) -> LockAttempt {
    LockAttempt::Unavailable(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "advisory file locking is not available on this platform",
    ))
}

/// Persist the self-heal under `meta.migrations_repaired` and shout about
/// it. Each repair is appended to the row's value
/// (`versions=[…] at <unix time>; …`), so the row keeps the history of
/// every repair this database saw, not only the latest one. The `meta` row
/// is the part that outlives the process: a boot log is usually long gone
/// by the time an operator wonders why a column they see in a migration
/// file is missing from the schema.
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
    // The value is appended to rather than replaced, so a second repair
    // leaves both events visible in `meta`.
    let recorded = sqlx::query(
        "INSERT INTO meta (key, value) VALUES ('migrations_repaired', ?)
         ON CONFLICT(key) DO UPDATE SET value = meta.value || '; ' || excluded.value",
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

/// Re-stamp every applied migration's stored SHA-384 with the checksum the
/// embedded migrator ([`embedded_migrator`]) derives from the current file
/// content. Used by [`migrate_with`] to recover from a checksum mismatch
/// (comment-only edits to already-applied migration files), and exposed as
/// a standalone helper so tests, the `repair_migration_checksums` utility
/// and ops scripts can trigger the same repair without booting the full
/// server — one implementation, so the guards below cannot drift from the
/// tool's copy. The migrator is always this build's embedded one: a caller
/// cannot hand in a different set and re-stamp against it.
///
/// The read of the stored checksums and the rewrite land in one
/// transaction, carried by a single `UPDATE` with one `CASE` arm per
/// version, so a repair cannot half-land — some rows re-stamped, others
/// not. Returns the list of versions whose checksums were actually
/// rewritten: a version whose stored hash already matches is not reported,
/// and a row this build's embedded set does not know about is never
/// touched.
pub async fn repair_migration_checksums(pool: &SqlitePool) -> crate::Result<Vec<i64>> {
    let mut tx = pool.begin().await?;
    let stored: Vec<(i64, Vec<u8>)> =
        sqlx::query_as("SELECT version, checksum FROM _sqlx_migrations WHERE success = 1")
            .fetch_all(&mut *tx)
            .await?;
    // Only applied versions are touched. A version the embedded set knows
    // about that has not been applied yet is left alone — the next regular
    // `migrate()` will run it and stamp its checksum at the end, and
    // touching it here would race the migrator's own bookkeeping — and a
    // version this set does not know about belongs to a newer build and is
    // none of this repair's business.
    let mismatches = embedded_migrator()
        .iter()
        .filter(|migration| {
            stored.iter().any(|(version, checksum)| {
                *version == migration.version && checksum.as_slice() != &*migration.checksum
            })
        })
        .collect::<Vec<_>>();
    let re_stamped: Vec<i64> = mismatches
        .iter()
        .map(|migration| migration.version)
        .collect();
    if !re_stamped.is_empty() {
        // One `UPDATE` for the whole set: the `CASE` arms pick the checksum
        // each version must carry, the `IN` list scopes the rewrite to the
        // versions the read above found disagreeing.
        let mut sql = String::from("UPDATE _sqlx_migrations SET checksum = CASE version");
        for _ in &mismatches {
            sql.push_str(" WHEN ? THEN ?");
        }
        sql.push_str(" END WHERE success = 1 AND version IN (");
        for index in 0..mismatches.len() {
            if index > 0 {
                sql.push_str(", ");
            }
            sql.push('?');
        }
        sql.push(')');
        let mut update = sqlx::query(sqlx::AssertSqlSafe(sql));
        for migration in &mismatches {
            update = update.bind(migration.version).bind(&*migration.checksum);
        }
        for migration in &mismatches {
            update = update.bind(migration.version);
        }
        update.execute(&mut *tx).await?;
    }
    tx.commit().await?;

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
                // A busy checkpoint leaves the re-stamp in the WAL — still
                // visible to every reader — but an operator who copies only
                // the database file would miss it, so say so loudly.
                tracing::warn!("wal_checkpoint(PASS) after migration re-stamp was busy");
            }
        }
        Err(err) => {
            tracing::warn!(error = %err, "wal_checkpoint(PASS) after migration re-stamp failed")
        }
    }
    Ok(re_stamped)
}

/// Test-only switch, and process-global state: when set, the inner
/// `set_permissions` call inside `restrict_file_permissions` short-circuits
/// with a `PermissionDenied` error. The OS only denies chmod when the
/// process lacks ownership of the file, a state tests cannot arrange
/// portably, so this flag is the smallest indirection that exercises the
/// chmod-fail branch — and because every `connect_pool` call in this
/// process reads it through `restrict_file_permissions`, a leaked `true`
/// would fail unrelated tests; see [`chmod_test_mutex`]. Guarded by a
/// `ChmodFailGuard` whose `Drop` resets it so a panic between `store(true)`
/// and the assertion cannot leak into subsequent tests in the same process.
#[cfg(all(test, unix))]
static SIMULATE_CHMOD_FAIL: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

/// Serializes all tests that call `connect_pool` against the chmod-fail
/// simulation. `SIMULATE_CHMOD_FAIL` is process-global state, and every
/// `connect_pool` call reads it inside `restrict_file_permissions`, while
/// `cargo test` runs `#[tokio::test]`s in parallel by default: without this
/// mutex, `connect_pool_returns_err_when_chmod_fails` could leak a
/// transient `true` into any other test's `connect_pool` call. The tests
/// that hold it are every `connect_pool`-calling test of `unix_db_tests`
/// (`connect_pool_writes_file_with_mode_0600`,
/// `connect_pool_opens_the_literal_path_without_uri_decoding`,
/// `connect_pool_restores_0600_on_existing_file_with_wrong_mode`,
/// `connect_pool_restores_0600_on_the_wal_sidecars`,
/// `a_symlinked_database_path_is_refused`,
/// `connect_pool_returns_err_when_chmod_fails`,
/// `parent_dir_gets_mode_0700_when_created`) and of the platform-neutral
/// `connect_pool_tests`. The flag itself exists only on unix test builds,
/// so the mutex is `cfg(all(test, unix))` too: on other platforms
/// `connect_pool` reads no shared state.
#[cfg(all(test, unix))]
fn chmod_test_mutex() -> &'static tokio::sync::Mutex<()> {
    static MUTEX: std::sync::OnceLock<tokio::sync::Mutex<()>> = std::sync::OnceLock::new();
    MUTEX.get_or_init(|| tokio::sync::Mutex::new(()))
}

/// Confirm the database file is `0600` on Unix; abort with a hard error if
/// the chmod fails so the operator notices a misconfigured database
/// directory instead of running with a world-readable credentials file.
///
/// A file found with a mode other than `0600` is reported at `warn` with
/// the mode that was found (`previous_mode`), so a stray umask or a copy is
/// visible in the boot log without failing the startup over it.
///
/// The mode is set on the file the path resolves to, and the check that
/// follows reads the mode back through the same inode the chmod touched:
/// re-resolving the path would allow a symlink swapped in between to point
/// the chmod at a different file.
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
        let previous_mode = meta.permissions().mode() & 0o777;
        if previous_mode != 0o600 {
            tracing::warn!(
                path = %path.display(),
                previous_mode = format!("{previous_mode:04o}"),
                "database file had permissive mode, restoring 0600"
            );
        }
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

/// Give the WAL sidecars (`-wal`, `-shm`) the same mode as the database.
///
/// They hold the same rows as the database file, so they must not be more
/// readable than it. SQLite creates them lazily, so a sidecar that does
/// not exist yet is skipped instead of failing the startup; a chmod that
/// fails on a sidecar is logged and does not abort the boot, because the
/// database itself is already secured.
fn restrict_sidecar_permissions(path: &std::path::Path) -> crate::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        for suffix in ["-wal", "-shm"] {
            let sidecar = sidecar_path(path, suffix);
            if !sidecar.exists() {
                continue;
            }
            let mut perms = match std::fs::metadata(&sidecar) {
                Ok(meta) => meta.permissions(),
                Err(err) => {
                    tracing::warn!(
                        path = %sidecar.display(),
                        error = %err,
                        "failed to stat database sidecar"
                    );
                    continue;
                }
            };
            perms.set_mode(0o600);
            if let Err(err) = std::fs::set_permissions(&sidecar, perms) {
                tracing::warn!(
                    path = %sidecar.display(),
                    error = %err,
                    "failed to chmod database sidecar to 0600"
                );
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
    Ok(())
}

/// The path of a WAL sidecar (`<db>-wal`, `<db>-shm`).
fn sidecar_path(path: &std::path::Path, suffix: &str) -> std::path::PathBuf {
    let mut name = path.as_os_str().to_os_string();
    name.push(suffix);
    std::path::PathBuf::from(name)
}

/// Test-only helpers shared by every test module of this file:
/// platform-specific and platform-neutral tests alike get their scratch
/// dir from here, so there is one `fresh_db_path` and the platform modules
/// carry only their platform's tests.
#[cfg(test)]
mod db_test_support {
    use super::tempdir_lite;
    use std::path::PathBuf;

    /// Each test gets its own scratch dir; the database lives inside it so
    /// the parent-dir creation path is exercised too.
    pub(super) fn fresh_db_path(label: &str) -> (tempdir_lite::TempDir, PathBuf) {
        let dir = tempdir_lite::TempDir::new(label);
        let path = dir.path().join("fumox.db");
        (dir, path)
    }
}

#[cfg(test)]
mod connect_pool_tests {
    use super::db_test_support::fresh_db_path;
    use super::*;

    /// The connection options are contract, not decoration: a connection
    /// from the pool must carry `foreign_keys` and the configured
    /// `busy_timeout`, the two PRAGMAs every connection enables.
    #[tokio::test]
    async fn every_connection_carries_the_configured_pragmas() {
        // On unix test builds every `connect_pool` call reads the
        // process-global `SIMULATE_CHMOD_FAIL` flag, so hold the same
        // mutex as the chmod tests do (see `chmod_test_mutex`).
        #[cfg(unix)]
        let _serial = chmod_test_mutex().lock().await;
        let (_dir, path) = fresh_db_path("db-pragmas");
        let cfg = DatabaseConfig {
            path: path.clone(),
            busy_timeout_ms: 1234,
            max_connections: 1,
            synchronous: crate::config::SynchronousMode::Normal,
            allow_checksum_repair: false,
        };
        let pool = connect_pool(&cfg).await.unwrap();
        let mut conn = pool.acquire().await.unwrap();
        let foreign_keys: i64 = sqlx::query_scalar("PRAGMA foreign_keys")
            .fetch_one(&mut *conn)
            .await
            .unwrap();
        assert_eq!(
            foreign_keys, 1,
            "foreign keys must be enforced by every pooled connection"
        );
        let busy_timeout: i64 = sqlx::query_scalar("PRAGMA busy_timeout")
            .fetch_one(&mut *conn)
            .await
            .unwrap();
        assert_eq!(
            busy_timeout, 1234,
            "busy_timeout must be the configured database.busy_timeout_ms"
        );
    }

    /// The database file is the shared source of truth: two pools opened
    /// on the same path must both see each other's writes through WAL.
    #[tokio::test]
    async fn two_pools_on_one_file_see_each_others_writes() {
        #[cfg(unix)]
        let _serial = chmod_test_mutex().lock().await;
        let (_dir, path) = fresh_db_path("db-two-pools");
        let cfg = DatabaseConfig {
            path: path.clone(),
            busy_timeout_ms: 1000,
            max_connections: 1,
            synchronous: crate::config::SynchronousMode::Normal,
            allow_checksum_repair: false,
        };
        let pool_a = connect_pool(&cfg).await.unwrap();
        let pool_b = connect_pool(&cfg).await.unwrap();
        sqlx::query("CREATE TABLE shared (id INTEGER PRIMARY KEY, value TEXT)")
            .execute(&pool_a)
            .await
            .unwrap();
        sqlx::query("INSERT INTO shared (value) VALUES ('from-a')")
            .execute(&pool_a)
            .await
            .unwrap();
        let value: String = sqlx::query_scalar("SELECT value FROM shared")
            .fetch_one(&pool_b)
            .await
            .unwrap();
        assert_eq!(
            value, "from-a",
            "the second pool must see the first pool's write"
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
            synchronous: crate::config::SynchronousMode::Normal,
            allow_checksum_repair: false,
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

    /// The durability level is a deployment decision, so it comes from the
    /// config and reaches SQLite.
    #[tokio::test]
    async fn the_synchronous_mode_comes_from_the_config() {
        #[cfg(unix)]
        let _serial = chmod_test_mutex().lock().await;
        let (_dir, path) = fresh_db_path("db-synchronous");
        let cfg = DatabaseConfig {
            path: path.clone(),
            busy_timeout_ms: 1000,
            max_connections: 1,
            synchronous: crate::config::SynchronousMode::Full,
            allow_checksum_repair: false,
        };
        let pool = connect_pool(&cfg).await.unwrap();
        let mode: i64 = sqlx::query_scalar("PRAGMA synchronous")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(mode, 2, "FULL is reported as 2 by SQLite, got {mode}");
    }
}

#[cfg(all(test, unix))]
mod unix_db_tests {
    use super::db_test_support::fresh_db_path;
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[tokio::test]
    async fn connect_pool_writes_file_with_mode_0600() {
        let _serial = chmod_test_mutex().lock().await;
        let (_dir, path) = fresh_db_path("db-mode");
        let cfg = DatabaseConfig {
            path: path.clone(),
            busy_timeout_ms: 1000,
            max_connections: 1,
            synchronous: crate::config::SynchronousMode::Normal,
            allow_checksum_repair: false,
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
            synchronous: crate::config::SynchronousMode::Normal,
            allow_checksum_repair: false,
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

    /// An existing database file with a permissive mode is restored to
    /// `0600` before SQLite opens it — so the `-wal`/`-shm` sidecars
    /// SQLite creates at open time inherit the private mode — and the
    /// restoration is logged at `warn` with the mode that was found.
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

        // The restoration names the mode it found in a `warn!`. The
        // production call site runs inside `spawn_blocking`, whose threads
        // cannot see the thread-local test subscriber, so the call is
        // repeated here on the test thread purely to capture the log line.
        let captured = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let writer = std::sync::Arc::clone(&captured);
        struct CapturedWriter(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);
        impl std::io::Write for CapturedWriter {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                self.0.lock().unwrap().extend_from_slice(buf);
                Ok(buf.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let subscriber = tracing_subscriber::fmt()
            .with_ansi(false)
            .with_max_level(tracing::Level::WARN)
            .with_writer(move || CapturedWriter(std::sync::Arc::clone(&writer)))
            .finish();
        tracing::subscriber::with_default(subscriber, || {
            restrict_file_permissions(&path).unwrap();
        });
        let log = String::from_utf8(captured.lock().unwrap().clone()).unwrap();
        assert!(
            log.contains("had permissive mode"),
            "the permissive-mode restoration must be logged at warn: {log}"
        );
        assert!(
            log.contains("previous_mode=\"0644\""),
            "the log line must carry the mode that was found: {log}"
        );
        assert!(
            log.contains(path.to_str().unwrap()),
            "the log line must name the database file: {log}"
        );

        // Put the permissive mode back: the pool must restore 0600 itself,
        // before it opens the file.
        let mut perms = std::fs::metadata(&path).unwrap().permissions();
        perms.set_mode(0o644);
        std::fs::set_permissions(&path, perms).unwrap();

        let cfg = DatabaseConfig {
            path: path.clone(),
            busy_timeout_ms: 1000,
            max_connections: 1,
            synchronous: crate::config::SynchronousMode::Normal,
            allow_checksum_repair: false,
        };
        let pool = connect_pool(&cfg).await.unwrap();
        // The restore-before-open step brought it back to 0600.
        let meta = std::fs::metadata(&path).unwrap();
        assert_eq!(meta.permissions().mode() & 0o777, 0o600);

        // SQLite created the sidecars while the file was already private,
        // so they carry the same mode.
        sqlx::query("CREATE TABLE wal_probe (id INTEGER PRIMARY KEY)")
            .execute(&pool)
            .await
            .unwrap();
        for suffix in ["-wal", "-shm"] {
            let sidecar = sidecar_path(&path, suffix);
            if !sidecar.exists() {
                continue;
            }
            let mode = std::fs::metadata(&sidecar).unwrap().permissions().mode();
            assert_eq!(
                mode & 0o777,
                0o600,
                "{} must inherit the database's private mode",
                sidecar.display()
            );
        }
    }

    /// The WAL sidecars hold the same rows as the database file, so they
    /// must not be more readable than it.
    #[tokio::test]
    async fn connect_pool_restores_0600_on_the_wal_sidecars() {
        let _serial = chmod_test_mutex().lock().await;
        let (_dir, path) = fresh_db_path("db-sidecar");
        let cfg = DatabaseConfig {
            path: path.clone(),
            busy_timeout_ms: 1000,
            max_connections: 1,
            synchronous: crate::config::SynchronousMode::Normal,
            allow_checksum_repair: false,
        };
        let pool = connect_pool(&cfg).await.unwrap();

        // Force WAL files to exist, then widen their modes the way a
        // stray umask would.
        sqlx::query("CREATE TABLE t (id INTEGER PRIMARY KEY)")
            .execute(&pool)
            .await
            .unwrap();
        let wal = sidecar_path(&path, "-wal");
        let shm = sidecar_path(&path, "-shm");
        for sidecar in [&wal, &shm] {
            if !sidecar.exists() {
                continue;
            }
            let mut perms = std::fs::metadata(sidecar).unwrap().permissions();
            perms.set_mode(0o644);
            std::fs::set_permissions(sidecar, perms).unwrap();
        }

        restrict_sidecar_permissions(&path).unwrap();

        for sidecar in [&wal, &shm] {
            if !sidecar.exists() {
                continue;
            }
            let mode = std::fs::metadata(sidecar).unwrap().permissions().mode();
            assert_eq!(
                mode & 0o777,
                0o600,
                "{} must be as private as the database",
                sidecar.display()
            );
        }
    }

    /// A symlink at the database path would redirect the whole database to
    /// a file the operator did not choose, and the `0600` mode would land
    /// on the link's target instead of on a file of our own.
    #[tokio::test]
    async fn a_symlinked_database_path_is_refused() {
        let _serial = chmod_test_mutex().lock().await;
        let dir = tempdir_lite::TempDir::new("db-symlink");
        let target = dir.path().join("real.db");
        let link = dir.path().join("link.db");
        std::fs::write(&target, b"").unwrap();
        std::os::unix::fs::symlink(&target, &link).unwrap();

        let cfg = DatabaseConfig {
            path: link.clone(),
            busy_timeout_ms: 1000,
            max_connections: 1,
            synchronous: crate::config::SynchronousMode::Normal,
            allow_checksum_repair: false,
        };
        let err = connect_pool(&cfg).await.unwrap_err();
        assert!(
            err.to_string().contains("symlink"),
            "the error must name the reason: {err}"
        );
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
            synchronous: crate::config::SynchronousMode::Normal,
            allow_checksum_repair: false,
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
            synchronous: crate::config::SynchronousMode::Normal,
            allow_checksum_repair: false,
        };
        let _pool = connect_pool(&cfg).await.unwrap();
        let parent = dir.path().join("a/b/c");
        let meta = std::fs::metadata(&parent).unwrap();
        assert_eq!(meta.permissions().mode() & 0o777, 0o700);
    }
}

#[cfg(all(test, not(unix)))]
mod non_unix_db_tests {
    use super::db_test_support::fresh_db_path;
    use super::*;

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
            synchronous: crate::config::SynchronousMode::Normal,
            allow_checksum_repair: false,
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
            synchronous: crate::config::SynchronousMode::Normal,
            allow_checksum_repair: false,
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
        /// Creates a fresh `fumox-test-<label>-<pid>-<n>` directory under
        /// the system temp dir, first removing any leftover tree of the
        /// same name, so the directory the caller gets back is empty.
        ///
        /// # Panics
        ///
        /// Panics when `label` carries a character outside
        /// `[A-Za-z0-9_-]`: the label becomes a path component, and a `..`
        /// or a separator could name a directory outside the system temp
        /// dir. Panics on an I/O error too — the directory cannot be
        /// created, there is nothing the calling test could recover from.
        pub fn new(label: &str) -> Self {
            assert!(
                label
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-'),
                "tempdir label must match [A-Za-z0-9_-], got {label:?}",
            );
            let unique = SEQ.fetch_add(1, Ordering::Relaxed);
            let base = std::env::temp_dir().join(format!(
                "fumox-test-{label}-{}-{}",
                std::process::id(),
                unique
            ));
            let _ = std::fs::remove_dir_all(&base);
            std::fs::create_dir_all(&base).expect("failed to create the test tempdir");
            // The created path stays inside the system temp dir even when
            // TMPDIR itself resolves through a symlink (/var ->
            // /private/var on macOS): compare the canonical forms, the
            // textual ones differ in that case.
            if let (Ok(created), Ok(root)) = (
                std::fs::canonicalize(&base),
                std::fs::canonicalize(std::env::temp_dir()),
            ) {
                assert!(
                    created.starts_with(&root),
                    "tempdir escaped the system temp dir: {created:?} is not under {root:?}",
                );
            }
            Self { path: base }
        }
        /// The path of the directory, valid only while `self` is alive:
        /// `Drop` removes the whole tree under it.
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

    /// A label becomes a path component: `..` or a separator could name a
    /// directory outside the system temp dir, so the label set is
    /// restricted and anything outside it is rejected.
    #[test]
    #[should_panic(expected = "tempdir label")]
    fn tempdir_rejects_a_label_with_dotdot() {
        let _ = TempDir::new("..");
    }

    /// The directory lands inside the system temp dir even when TMPDIR
    /// itself resolves through a symlink (/var -> /private/var on macOS):
    /// the canonical created path must be under the canonical temp root.
    #[test]
    fn tempdir_lands_inside_the_system_temp_dir() {
        let dir = TempDir::new("inside-temp");
        let created = std::fs::canonicalize(dir.path()).unwrap();
        let root = std::fs::canonicalize(std::env::temp_dir()).unwrap();
        assert!(
            created.starts_with(&root),
            "{created:?} must sit inside the system temp dir {root:?}"
        );
    }
}
