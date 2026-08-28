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
pub async fn connect_pool(cfg: &DatabaseConfig) -> crate::Result<SqlitePool> {
    let options = SqliteConnectOptions::from_str(&sqlite_url(&cfg.path))?
        .create_if_missing(true)
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

    restrict_file_permissions(&cfg.path);
    Ok(pool)
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

/// Best-effort `chmod 0600` on the database file (Unix only).
fn restrict_file_permissions(path: &std::path::Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(meta) = std::fs::metadata(path) {
            let mut perms = meta.permissions();
            perms.set_mode(0o600);
            if let Err(err) = std::fs::set_permissions(path, perms) {
                tracing::warn!(path = %path.display(), %err, "failed to set 0600 on database file");
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
}
