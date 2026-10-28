//! Write restriction for the probe daemon's database connection.
//!
//! SQLite has no roles: every process that opens the file may write
//! every table. The probe only owns the health status of a proxy, but
//! the file it opens is the same one the ingest pipeline writes, so
//! without a guard a defect (or a compromised probe) could rewrite the
//! subscription content itself — the hosts, the credentials, the
//! sources.
//!
//! The restriction is implemented with SQLite's authorizer, the
//! callback SQLite asks before it prepares a statement. It is installed
//! on the probe's connections only, so the server keeps full write
//! access to the same file.
//!
//! The rules are an allow-list: a table the probe has no write business
//! with is denied, so a table added later is denied by default instead
//! of silently becoming writable. The schema is applied before the
//! restricted connections exist (see
//! [`crate::db::connect_probe_pool`]), so the restriction never has to
//! let a migration through.

use std::ffi::{CStr, c_char, c_int, c_void};

use libsqlite3_sys as ffi;
use sqlx::sqlite::SqliteConnection;

/// What the probe may do with one table.
struct TableRule {
    table: &'static str,
    insert: bool,
    update: bool,
    delete: bool,
    drop: bool,
    /// Columns an `UPDATE` may touch. Empty means "every column".
    columns: &'static [&'static str],
}

/// The probe's write surface.
///
/// `proxies` carries the subscription content (host, credential,
/// parameters, geo), so only the health columns are writable. The
/// other tables are the probe's own bookkeeping: the check history,
/// the request queue, the journal it rotates and the service
/// key-value table.
const RULES: &[TableRule] = &[
    TableRule {
        table: "probe_results",
        insert: true,
        update: false,
        delete: true,
        drop: true,
        columns: &[],
    },
    TableRule {
        table: "probe_requests",
        insert: false,
        update: false,
        delete: true,
        drop: true,
        columns: &[],
    },
    TableRule {
        table: "fetch_log",
        insert: false,
        update: false,
        delete: true,
        drop: true,
        columns: &[],
    },
    TableRule {
        table: "meta",
        insert: true,
        update: true,
        delete: true,
        drop: true,
        columns: &[],
    },
    TableRule {
        table: "proxies",
        insert: false,
        update: true,
        delete: false,
        drop: false,
        columns: &[
            "status",
            "fail_count",
            "last_checked_at",
            "last_alive_at",
            "quarantined_at",
            "removed_at",
            "latency_ms",
            "ladder_at",
            "ladder_step",
            "last_t2_failed_at",
            "updated_at",
        ],
    },
];

/// Installs the authorizer on one connection.
///
/// Returns an error instead of leaving the connection unrestricted: a
/// connection that silently lost its guard would be a write hole.
pub(crate) async fn install(connection: &mut SqliteConnection) -> sqlx::Result<()> {
    // `lock_handle` pauses the connection's worker thread and hands out
    // the raw handle, so no statement can be running on it while the
    // authorizer is installed.
    let mut handle = connection.lock_handle().await?;
    let raw = handle.as_raw_handle();
    // SAFETY: the handle is locked, so this thread has exclusive access
    // to the connection, and the authorizer is set on an idle handle.
    let code = unsafe {
        ffi::sqlite3_set_authorizer(raw.as_ptr(), Some(authorizer), std::ptr::null_mut())
    };
    if code != ffi::SQLITE_OK {
        return Err(sqlx::Error::Protocol(format!(
            "failed to install the SQLite authorizer: code {code}"
        )));
    }
    Ok(())
}

/// The authorizer callback.
///
/// Called by SQLite before it prepares a statement. Returning
/// `SQLITE_DENY` aborts the statement with "not authorized"; returning
/// `SQLITE_OK` lets it through.
unsafe extern "C" fn authorizer(
    _context: *mut c_void,
    action: c_int,
    table: *const c_char,
    column: *const c_char,
    database: *const c_char,
    _trigger: *const c_char,
) -> c_int {
    // A temporary database is per-connection scratch space, not the
    // shared subscription store.
    if cstr(database) == Some("temp") {
        return ffi::SQLITE_OK;
    }
    match action {
        ffi::SQLITE_INSERT | ffi::SQLITE_UPDATE | ffi::SQLITE_DELETE => {
            let table = cstr(table).unwrap_or_default();
            if write_allowed(table, action, cstr(column)) {
                ffi::SQLITE_OK
            } else {
                ffi::SQLITE_DENY
            }
        }
        // `ATTACH` would give the connection a second handle on the
        // database file; nothing in the codebase attaches.
        ffi::SQLITE_ATTACH => ffi::SQLITE_DENY,
        // Dropping a table destroys the content the probe may not
        // change.
        ffi::SQLITE_DROP_TABLE => {
            let table = cstr(table).unwrap_or_default();
            if RULES.iter().any(|rule| rule.table == table && rule.drop) {
                ffi::SQLITE_OK
            } else {
                ffi::SQLITE_DENY
            }
        }
        _ => ffi::SQLITE_OK,
    }
}

/// Whether the probe may perform `action` on `table`.
fn write_allowed(table: &str, action: c_int, column: Option<&str>) -> bool {
    // SQLite reserves the `sqlite_` prefix for its own bookkeeping:
    // `sqlite_sequence` holds the AUTOINCREMENT counters, `sqlite_stat1`
    // the `ANALYZE` statistics. SQLite updates them on its own, so
    // refusing them would break the statements the probe is allowed to
    // make. `sqlite_master` is the exception: it holds the schema
    // itself, and a write to it changes what the table looks like.
    if table.starts_with("sqlite_") && table != "sqlite_master" {
        return true;
    }
    let Some(rule) = RULES.iter().find(|rule| rule.table == table) else {
        // Not on the list: the probe has no write business with it.
        return false;
    };
    match action {
        ffi::SQLITE_INSERT => rule.insert,
        ffi::SQLITE_DELETE => rule.delete,
        ffi::SQLITE_UPDATE => {
            if !rule.update {
                return false;
            }
            match column {
                // An `UPDATE` names its columns; a rule without a column
                // list accepts any of them.
                Some(column) => rule.columns.is_empty() || rule.columns.contains(&column),
                None => false,
            }
        }
        _ => false,
    }
}

/// Reads a NUL-terminated string handed over by SQLite.
fn cstr<'a>(value: *const c_char) -> Option<&'a str> {
    if value.is_null() {
        return None;
    }
    // SAFETY: SQLite passes NUL-terminated strings that stay valid for
    // the duration of the callback.
    unsafe { CStr::from_ptr(value) }.to_str().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn content_tables_are_not_writable() {
        for table in [
            "sources",
            "profiles",
            "profile_sources",
            "proxy_source_links",
            "speed_results",
        ] {
            for action in [ffi::SQLITE_INSERT, ffi::SQLITE_UPDATE, ffi::SQLITE_DELETE] {
                assert!(
                    !write_allowed(table, action, Some("id")),
                    "{table} must not be writable"
                );
            }
        }
    }

    #[test]
    fn proxy_content_columns_are_not_writable() {
        for column in [
            "fingerprint",
            "scheme",
            "name",
            "host",
            "port",
            "credential",
            "params",
            "unknown_params",
            "raw_line",
            "geo_country",
            "geo_city",
            "geo_asn",
            "resolved_ip",
            "speed_mbps",
            "created_at",
        ] {
            assert!(
                !write_allowed("proxies", ffi::SQLITE_UPDATE, Some(column)),
                "proxies.{column} must not be writable"
            );
        }
    }

    #[test]
    fn proxy_status_columns_are_writable() {
        for column in [
            "status",
            "fail_count",
            "last_checked_at",
            "last_alive_at",
            "quarantined_at",
            "removed_at",
            "latency_ms",
            "ladder_at",
            "ladder_step",
            "last_t2_failed_at",
            "updated_at",
        ] {
            assert!(
                write_allowed("proxies", ffi::SQLITE_UPDATE, Some(column)),
                "proxies.{column} must be writable"
            );
        }
    }

    #[test]
    fn proxies_cannot_be_inserted_or_deleted() {
        assert!(!write_allowed("proxies", ffi::SQLITE_INSERT, Some("host")));
        assert!(!write_allowed("proxies", ffi::SQLITE_DELETE, None));
    }

    #[test]
    fn probe_bookkeeping_is_writable() {
        assert!(write_allowed(
            "probe_results",
            ffi::SQLITE_INSERT,
            Some("proxy_id")
        ));
        assert!(write_allowed("probe_results", ffi::SQLITE_DELETE, None));
        assert!(write_allowed("probe_requests", ffi::SQLITE_DELETE, None));
        assert!(write_allowed("fetch_log", ffi::SQLITE_DELETE, None));
        assert!(write_allowed("meta", ffi::SQLITE_INSERT, Some("key")));
        assert!(write_allowed("meta", ffi::SQLITE_UPDATE, Some("value")));
    }

    #[test]
    fn sqlite_internals_are_writable_but_the_schema_is_not() {
        // SQLite updates these on its own while the probe's own
        // statements run.
        assert!(write_allowed(
            "sqlite_sequence",
            ffi::SQLITE_UPDATE,
            Some("seq")
        ));
        assert!(write_allowed(
            "sqlite_stat1",
            ffi::SQLITE_INSERT,
            Some("tbl")
        ));
        // The schema is not the probe's to change.
        assert!(!write_allowed(
            "sqlite_master",
            ffi::SQLITE_UPDATE,
            Some("sql")
        ));
    }

    #[test]
    fn unknown_tables_are_not_writable() {
        assert!(!write_allowed(
            "fetch_log_new",
            ffi::SQLITE_INSERT,
            Some("x")
        ));
    }
}
