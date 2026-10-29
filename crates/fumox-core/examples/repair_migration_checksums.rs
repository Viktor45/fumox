//! One-shot repair for `sqlx::migrate!()` checksum mismatches.
//!
//! Migration files are immutable once applied: sqlx stores the SHA-384 of
//! every migration's content in the `_sqlx_migrations` table, and any
//! post-apply edit to the file fails the next `migrate()` call with
//! "migration N was previously applied but has been modified". The
//! correct long-term answer is to never edit applied migrations, new
//! changes belong in a new migration file.
//!
//! This utility exists for one narrow case: a comment-only edit that
//! changed no DDL (so the schema is byte-identical to what was
//! applied). Running it re-stamps every `_sqlx_migrations.checksum`
//! with the SHA-384 of the current file content. After it finishes,
//! `sqlx::migrate!().run(pool)` succeeds again without touching the
//! schema.
//!
//! What it cannot do is fix a DDL edit: sqlx never re-runs an applied
//! migration, and the SHA-384 covers the whole file, so the re-stamp
//! hides the difference instead of applying it. A DDL change to an
//! already-applied file needs a new migration file.
//!
//! The database must be fully in sync with this build's embedded set
//! in both directions, a migration this build does not know about
//! means the database was migrated by a newer Fumox, and the tool
//! refuses rather than leaving `migrate()` to fail with
//! `VersionMissing`.
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
    //
    // The whole table is read, not only the successful rows: a failed
    // migration (sqlx's `success = 0`) is a database that stopped halfway
    // through a migration, and re-stamping checksums over it would paper
    // over the half-applied DDL.
    let rows: Vec<(i64, bool)> =
        sqlx::query_as("SELECT version, success FROM _sqlx_migrations ORDER BY version")
            .fetch_all(&pool)
            .await?;
    for (version, success) in &rows {
        if !*success {
            return Err(format!(
                "migration {version} is in a failed/dirty state — fix it before running the utility"
            )
            .into());
        }
    }
    let applied_versions: Vec<i64> = rows.iter().map(|(version, _)| *version).collect();
    let applied: std::collections::HashSet<i64> = applied_versions.iter().copied().collect();
    let embedded_versions: Vec<i64> = migrator.iter().map(|m| m.version).collect();
    let only_in_embedded: Vec<i64> = embedded_versions
        .iter()
        .copied()
        .filter(|v| !applied.contains(v))
        .collect();
    if !only_in_embedded.is_empty() {
        return Err(format!(
            "migration(s) {only_in_embedded:?} were not applied successfully — they have \
             never been applied; run the server once to apply them, then re-run this utility"
        )
        .into());
    }
    // The mirror check. A database carrying a version this build does not
    // embed was migrated by a newer Fumox; re-stamping the versions we do
    // know about would leave sqlx refusing to start with
    // `VersionMissing(<that version>)` anyway, so the tool must say so up
    // front instead of promising a `migrate()` that cannot succeed.
    let only_in_applied: Vec<i64> = applied_versions
        .iter()
        .copied()
        .filter(|v| !embedded_versions.contains(v))
        .collect();
    if !only_in_applied.is_empty() {
        return Err(format!(
            "the database has applied migrations this build does not embed: \
             {only_in_applied:?}; it was migrated by a newer Fumox, downgrade \
             to that build instead of re-stamping checksums"
        )
        .into());
    }

    // The UPDATE itself lives in `db::repair_migration_checksums` so the
    // `success = 1 AND checksum != ?2` guards cannot drift from the copy
    // `db::migrate()` uses: a row that already matches is left alone and
    // not reported as a repair.
    let re_stamped = fumox_core::db::repair_migration_checksums(&pool, &migrator).await?;
    let re_stamped_set: std::collections::HashSet<i64> = re_stamped.iter().copied().collect();
    for migration in migrator.iter() {
        if re_stamped_set.contains(&migration.version) {
            println!("  ✓ version {:>3}: checksum re-stamped", migration.version);
        } else {
            println!(
                "  · version {:>3}: checksum already current",
                migration.version
            );
        }
    }

    // The re-stamp is a write, so it may still sit in the write-ahead log
    // when this process exits. The checkpoint that pushes it into the
    // database file is what makes the repair visible to a reader that opens
    // the file without its own `-wal`. A checkpoint that fails leaves the
    // repair in the log, and a copy of the database file alone would not
    // carry it, so the failure is reported instead of swallowed.
    let checkpoint = sqlx::query("PRAGMA wal_checkpoint(TRUNCATE)")
        .fetch_one(&pool)
        .await;
    match checkpoint {
        Ok(row) => {
            let busy: i64 = sqlx::Row::try_get(&row, 0).unwrap_or_default();
            if busy != 0 {
                return Err(format!(
                    "the write-ahead log could not be checkpointed (busy); the re-stamp is \
                     in {}-wal, so copy the -wal and -shm files as well, or re-run the \
                     utility once nothing else has the database open",
                    path.display()
                )
                .into());
            }
        }
        Err(err) => {
            return Err(format!(
                "the write-ahead log could not be checkpointed: {err}; the re-stamp is in \
                 {}-wal, so copy the -wal and -shm files as well, or re-run the utility once \
                 nothing else has the database open",
                path.display()
            )
            .into());
        }
    }

    println!(
        "done: {} checksum(s) re-stamped in {}",
        re_stamped.len(),
        path.display()
    );
    if !re_stamped.is_empty() {
        println!(
            "note: the re-stamp only rewrites bookkeeping. sqlx never re-runs an \
             applied migration, so if the edit was not comment-only the schema \
             on disk is behind the files, ship a new migration file for the DDL."
        );
    }
    Ok(())
}
