//! Write restriction for the probe daemon's database connection.
//!
//! SQLite has no roles: every process that opens the file may write every
//! table. The probe only owns the health status of a proxy, but the file it
//! opens is the same one the ingest pipeline writes, so without a guard a
//! defect (or a compromised probe) could rewrite the subscription content
//! itself. Implemented with SQLite's authorizer, installed on the probe's
//! connections only, so the server keeps full write access to the same file.
//!
//! The rules are an allow-list: a table the probe has no write business with
//! is denied, so a table added later is denied by default instead of silently
//! becoming writable. Schema changes are refused outright and a pragma may
//! only be queried; the schema is applied before the restricted connections
//! exist (see [`crate::db::connect_probe_pool`]), so the restriction never
//! has to let a migration through.

use std::ffi::{CStr, c_char, c_int, c_void};

use libsqlite3_sys as ffi;
use sqlx::sqlite::SqliteConnection;

struct TableRule {
    table: &'static str,
    insert: bool,
    update: bool,
    delete: bool,
    drop: bool,
    /// Columns an `UPDATE` may touch. Empty means "every column".
    columns: &'static [&'static str],
}

/// The probe's write surface. `proxies` carries the subscription content
/// (host, credential, parameters, geo), so only the health columns are
/// writable; the other tables are the probe's own bookkeeping.
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
            "last_t2_checked_at",
            "updated_at",
        ],
    },
];

/// Returns an error instead of leaving the connection unrestricted: a
/// connection that silently lost its guard would be a write hole.
pub(crate) async fn install(connection: &mut SqliteConnection) -> sqlx::Result<()> {
    // `lock_handle` pauses the worker thread and hands out the raw handle,
    // so no statement can be running while the authorizer is installed
    let mut handle = connection.lock_handle().await?;
    let raw = handle.as_raw_handle();
    // SAFETY: the handle is locked, so this thread has exclusive access
    // to the connection, and the authorizer is set on an idle handle
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

/// Called by SQLite before it prepares a statement; `SQLITE_DENY` aborts it,
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
    // shared subscription store
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
        // database file; nothing in the codebase attaches
        ffi::SQLITE_ATTACH => ffi::SQLITE_DENY,
        // Dropping a table destroys the content the probe may not
        // change
        ffi::SQLITE_DROP_TABLE => {
            let table = cstr(table).unwrap_or_default();
            if RULES.iter().any(|rule| rule.table == table && rule.drop) {
                ffi::SQLITE_OK
            } else {
                ffi::SQLITE_DENY
            }
        }
        // The schema belongs to the migration that runs before the restricted
        // connections exist, so no DDL has business here. SQLite already
        // refuses most of it on its own (a schema change compiles into
        // `sqlite_master` writes, which `write_allowed` denies); the explicit
        // deny keeps that a property of the guard, not of that detail
        ffi::SQLITE_CREATE_TABLE
        | ffi::SQLITE_CREATE_INDEX
        | ffi::SQLITE_CREATE_TRIGGER
        | ffi::SQLITE_CREATE_VIEW
        | ffi::SQLITE_CREATE_VTABLE
        | ffi::SQLITE_DROP_INDEX
        | ffi::SQLITE_DROP_TRIGGER
        | ffi::SQLITE_DROP_VIEW
        | ffi::SQLITE_DROP_VTABLE
        | ffi::SQLITE_ALTER_TABLE
        | ffi::SQLITE_REINDEX => ffi::SQLITE_DENY,
        // The authorizer hands a pragma over as the table argument (the name)
        // and the column argument (the value, absent for a bare read). A
        // pragma with a value reconfigures what it names, and the ones that
        // name a file property (`journal_mode`, `user_version`) write the
        // shared file itself, outside every table the rules govern
        ffi::SQLITE_PRAGMA => {
            if pragma_allowed(cstr(table).unwrap_or_default(), cstr(column)) {
                ffi::SQLITE_OK
            } else {
                ffi::SQLITE_DENY
            }
        }
        _ => ffi::SQLITE_OK,
    }
}

fn write_allowed(table: &str, action: c_int, column: Option<&str>) -> bool {
    // SQLite reserves the `sqlite_` prefix for its own bookkeeping and
    // updates those tables itself, so refusing them would break statements
    // the probe is allowed to make. `sqlite_master` is the exception: it
    // holds the schema itself
    if table.starts_with("sqlite_") && table != "sqlite_master" {
        return true;
    }
    let Some(rule) = RULES.iter().find(|rule| rule.table == table) else {
        // Not on the list: the probe has no write business with it
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
                // list accepts any of them
                Some(column) => rule.columns.is_empty() || rule.columns.contains(&column),
                None => false,
            }
        }
        _ => false,
    }
}

/// The argument-taking pragmas whose argument is the subject of the question,
/// not a value to set: `PRAGMA table_info(proxies)` reads the columns of
/// `proxies`, it configures nothing.
const PRAGMA_READS: &[&str] = &[
    "table_info",
    "table_xinfo",
    "index_info",
    "index_xinfo",
    "index_list",
    "foreign_key_list",
    "foreign_key_check",
    "function_list",
    "module_list",
    "pragma_list",
    "compile_options",
];

/// Whether the probe may run the pragma `name` with the value `value`. A
/// bare read asks, it does not configure.
fn pragma_allowed(name: &str, value: Option<&str>) -> bool {
    match value {
        None => true,
        Some(_) => PRAGMA_READS.contains(&name),
    }
}

fn cstr<'a>(value: *const c_char) -> Option<&'a str> {
    if value.is_null() {
        return None;
    }
    // SAFETY: SQLite passes NUL-terminated strings that stay valid for
    // the duration of the callback
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
            "last_t2_checked_at",
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

    #[test]
    fn pragma_writes_are_refused_but_reads_are_not() {
        assert!(pragma_allowed("journal_mode", None));
        assert!(pragma_allowed("foreign_keys", None));
        assert!(pragma_allowed("integrity_check", None));
        assert!(!pragma_allowed("user_version", Some("7")));
        assert!(!pragma_allowed("journal_mode", Some("DELETE")));
        assert!(!pragma_allowed("application_id", Some("x")));
        assert!(pragma_allowed("table_info", Some("proxies")));
        assert!(pragma_allowed("index_list", Some("proxies")));
        assert!(!pragma_allowed("wal_checkpoint", Some("TRUNCATE")));
        assert!(!pragma_allowed("busy_timeout", Some("5000")));
    }
}
