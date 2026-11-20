//! One-shot repair for `sqlx::migrate!()` checksum mismatches.
//!
//! Migration files are immutable once applied: sqlx stores the SHA-384 of
//! every migration's content in `_sqlx_migrations`, and any post-apply
//! edit fails the next `migrate()` with "migration N was previously
//! applied but has been modified". The long-term answer is to never edit
//! applied migrations; this utility exists for one narrow case, a
//! comment-only edit that changed no DDL. Running it re-stamps every
//! `_sqlx_migrations.checksum` with the SHA-384 of the current file
//! content, after which `sqlx::migrate!().run(pool)` succeeds without
//! touching the schema.
//!
//! It cannot fix a DDL edit: sqlx never re-runs an applied migration and
//! the SHA-384 covers the whole file, so the re-stamp hides the
//! difference instead of applying it. A DDL change to an already-applied
//! file needs a new migration file.
//!
//! Usage: `cargo run --bin repair_migration_checksums --
//! /path/to/db.sqlite`; the path defaults to the
//! `DatabaseConfig::default()` location (`fumox.db` in the working
//! directory).

use std::error::Error;
use std::path::PathBuf;

use fumox_core::config::DatabaseConfig;
use fumox_core::db;
use sqlx::migrate::Migrator;

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn Error + Send + Sync>> {
    let path = std::env::args()
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| DatabaseConfig::default().path);
    if !path.exists() {
        return Err(format!("database file not found: {}", path.display()).into());
    }

    // The macro computes the SHA-384 from the on-disk content of the same
    // files `sqlx::migrate!().run()` compares against
    let migrator: Migrator = sqlx::migrate!("./migrations");

    // The pool comes from `db::connect_pool`, the same builder the server
    // and the probe open their pools with (WAL, busy timeout, 0600
    // pre-create): a repair must not open the file with a weaker setup
    let pool = db::connect_pool(&DatabaseConfig {
        path: path.clone(),
        ..Default::default()
    })
    .await?;

    // Pre-flight: the database must already mirror this build's embedded
    // migration set (see `verify_repairable_state`)
    verify_repairable_state(&pool, &migrator).await?;

    // The UPDATE lives in `db::repair_migration_checksums` so its guards
    // (applied and successful rows only, checksums compared against this
    // build's embedded set) cannot drift from the copy `db::migrate()`
    // uses
    let re_stamped = fumox_core::db::repair_migration_checksums(&pool).await?;
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

    // The re-stamp is a write and may still sit in the write-ahead log
    // when this process exits; the checkpoint pushes it into the database
    // file so a reader that opens the file without its own `-wal` sees
    // the repair. A failed checkpoint is reported, not swallowed
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

/// Pre-flight for the re-stamp: every embedded migration must already be
/// applied (we are re-stamping checksums, not applying anything new), and
/// nothing may be applied that this build does not embed. A version
/// mismatch means the user's setup is in a state this utility cannot fix.
///
/// The whole table is read, not only the successful rows: a failed
/// migration (sqlx's `success = 0`) is a database that stopped halfway
/// through a migration, and re-stamping checksums over it would paper
/// over the half-applied DDL.
async fn verify_repairable_state(
    pool: &sqlx::SqlitePool,
    migrator: &Migrator,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    let rows: Vec<(i64, bool)> =
        sqlx::query_as("SELECT version, success FROM _sqlx_migrations ORDER BY version")
            .fetch_all(pool)
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
    // A database carrying a version this build does not embed was
    // migrated by a newer Fumox; re-stamping would leave sqlx refusing to
    // start with `VersionMissing(<that version>)` anyway, so say so up
    // front instead of promising a `migrate()` that cannot succeed
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
    Ok(())
}
