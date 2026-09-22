//! One-shot repair for `sqlx::migrate!()` checksum mismatches.
//!
//! Migration files are immutable once applied: sqlx stores the SHA-384 of
//! every migration's content in the `_sqlx_migrations` table, and any
//! post-apply edit to the file fails the next `migrate()` call with
//! "migration N was previously applied but has been modified". The
//! correct long-term answer is to never edit applied migrations — new
//! changes belong in a new migration file.
//!
//! This utility exists for one narrow case: a comment-only edit that
//! changed no DDL (so the schema is byte-identical to what was
//! applied). Running it re-stamps every `_sqlx_migrations.checksum`
//! with the SHA-384 of the current file content. After it finishes,
//! `sqlx::migrate!().run(pool)` succeeds again without touching the
//! schema.
//!
//! Usage:
//!
//! ```text
//! cargo run --example repair_migration_checksums -- /path/to/db.sqlite
//! ```
//!
//! The path defaults to `./fumox.db` (the `DatabaseConfig::default()`
//! location) when no argument is given.

use std::error::Error;
use std::path::PathBuf;

use sqlx::Executor;
use sqlx::migrate::Migrator;
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn Error + Send + Sync>> {
    let path = std::env::args()
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("./fumox.db"));
    if !path.exists() {
        return Err(format!("database file not found: {}", path.display()).into());
    }

    // The macro embeds the migrations at compile time and computes their
    // SHA-384 from the on-disk content of the same files
    // `sqlx::migrate!().run()` uses. Whatever the runtime embedder would
    // compare against is exactly what we have here.
    let migrator: Migrator = sqlx::migrate!("./migrations");

    let options = SqliteConnectOptions::new()
        .filename(&path)
        .create_if_missing(false)
        .read_only(false);
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(options)
        .await?;

    // Pre-flight: every embedded migration must already be applied (we are
    // re-stamping checksums, not applying anything new). A version mismatch
    // means the user's setup is in a state this utility cannot fix.
    let applied_versions: Vec<i64> = sqlx::query_scalar(
        "SELECT version FROM _sqlx_migrations WHERE success = 1 ORDER BY version",
    )
    .fetch_all(&pool)
    .await?;
    let applied: std::collections::HashSet<i64> = applied_versions.iter().copied().collect();
    let embedded_versions: Vec<i64> = migrator.iter().map(|m| m.version).collect();
    let only_in_embedded: Vec<i64> = embedded_versions
        .iter()
        .copied()
        .filter(|v| !applied.contains(v))
        .collect();
    if !only_in_embedded.is_empty() {
        return Err(format!(
            "these migrations have never been applied: {only_in_embedded:?}; \
             run the server once to apply them, then re-run this utility"
        )
        .into());
    }

    let mut updated = 0usize;
    for migration in migrator.iter() {
        let rows = sqlx::query(
            "UPDATE _sqlx_migrations
             SET checksum = ?2
             WHERE version = ?1",
        )
        .bind(migration.version)
        .bind(&*migration.checksum)
        .execute(&pool)
        .await?;
        if rows.rows_affected() == 1 {
            updated += 1;
            println!("  ✓ version {:>3}: checksum re-stamped", migration.version);
        } else if rows.rows_affected() == 0 {
            return Err(format!(
                "no _sqlx_migrations row for version {}; \
                 cannot repair an incomplete state",
                migration.version
            )
            .into());
        }
    }

    pool.execute("PRAGMA wal_checkpoint(TRUNCATE)").await.ok();

    println!(
        "done: {updated} checksum(s) re-stamped in {}; \
         sqlx::migrate!().run() will accept the current files now",
        path.display()
    );
    Ok(())
}