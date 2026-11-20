/// Parse/fetch failures are log-and-skip, never panic.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("configuration error: {0}")]
    Config(String),

    #[error("parse error: {0}")]
    Parse(String),

    /// A database failure that is not the driver's: the file could not be
    /// created or secured, or a repository precondition failed.
    #[error("database error: {0}")]
    Database(String),

    /// A failure the driver reported, kept as the original error so a caller
    /// can classify it by the driver's variant (a locked database is
    /// transient, a missing table is not) instead of by the message text.
    #[error("database error: {0}")]
    Sqlx(#[from] sqlx::Error),

    /// Kept apart from [`Error::Database`] so a caller can answer "not found"
    /// instead of "the database failed".
    #[error("not found: {0}")]
    NotFound(String),

    #[error("database migration error: {0}")]
    Migration(#[from] sqlx::migrate::MigrateError),
}

impl Error {
    /// Transient contention over the database file: another process holds
    /// the write lock, or the pool had no connection to hand out.
    ///
    /// Classifies by the driver's variant and SQLite's result code, never the
    /// message text: SQLite localizes it and it has changed between releases.
    pub fn is_busy(&self) -> bool {
        match self {
            Error::Sqlx(err) => sqlx_error_is_busy(err),
            Error::Migration(err) => migrate_error_is_busy(err),
            _ => false,
        }
    }
}

/// SQLITE_BUSY: another connection holds the write lock.
const SQLITE_BUSY: i64 = 5;
/// SQLITE_LOCKED: another connection holds a lock on the table.
const SQLITE_LOCKED: i64 = 6;

/// The driver reports the *extended* result code, whose low byte carries
/// the primary one: SQLITE_BUSY_SNAPSHOT (517) and SQLITE_BUSY_RECOVERY
/// (261) are both SQLITE_BUSY (5).
fn sqlite_code_is_busy(code: &str) -> bool {
    code.trim()
        .parse::<i64>()
        .is_ok_and(|code| matches!(code & 0xff, SQLITE_BUSY | SQLITE_LOCKED))
}

fn sqlx_error_is_busy(err: &sqlx::Error) -> bool {
    match err {
        sqlx::Error::Database(db_err) => {
            db_err.code().is_some_and(|code| sqlite_code_is_busy(&code))
        }
        // The pool had no free connection: the database is busy even
        // though the driver never got to say so
        sqlx::Error::PoolTimedOut => true,
        _ => false,
    }
}

/// The same question for a migration failure.
fn migrate_error_is_busy(err: &sqlx::migrate::MigrateError) -> bool {
    use sqlx::migrate::MigrateError;
    match err {
        MigrateError::Execute(err) => sqlx_error_is_busy(err),
        MigrateError::ExecuteMigration(err, _) => sqlx_error_is_busy(err),
        _ => false,
    }
}

pub type Result<T> = std::result::Result<T, Error>;

impl From<figment::Error> for Error {
    fn from(err: figment::Error) -> Self {
        Error::Config(config_error_summary(&err))
    }
}

/// Reduce a figment error to the offending key path and a value-free kind: the
/// full text quotes source lines and prints values, so a mistyped
/// `admin.token` or a `db.url` carrying a password would leak the secret into
/// the logs.
fn config_error_summary(err: &figment::Error) -> String {
    let path = err.path.join(".");
    let kind = config_error_kind(&err.kind);
    if path.is_empty() {
        kind
    } else {
        format!("{kind} at {path}")
    }
}

fn config_error_kind(kind: &figment::error::Kind) -> String {
    match kind {
        // A parse error quotes the offending source line, secrets included, so
        // only its first line survives: for TOML that is the location, not the
        // content
        figment::error::Kind::Message(message) => message
            .lines()
            .next()
            .unwrap_or_default()
            .trim()
            .chars()
            .take(200)
            .collect(),
        // These kinds name the offending value; the label alone says what was
        // wrong
        figment::error::Kind::InvalidType(..) => "invalid type".into(),
        figment::error::Kind::InvalidValue(..) => "invalid value".into(),
        figment::error::Kind::InvalidLength(..) => "invalid length".into(),
        figment::error::Kind::UnknownVariant(..) => "unknown variant".into(),
        // A field name is a key, not a value
        figment::error::Kind::UnknownField(name, _) => format!("unknown field `{name}`"),
        figment::error::Kind::MissingField(name) => format!("missing field `{name}`"),
        figment::error::Kind::DuplicateField(name) => format!("duplicate field `{name}`"),
        figment::error::Kind::ISizeOutOfRange(_) | figment::error::Kind::USizeOutOfRange(_) => {
            "integer out of range".into()
        }
        figment::error::Kind::Unsupported(_) => "unsupported type".into(),
        figment::error::Kind::UnsupportedKey(..) => "unsupported key type".into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use figment::providers::Format;

    #[test]
    fn a_parse_error_carries_no_value() {
        let secret = "s3cr3t-value";
        let broken = format!("[admin]\ntoken = \"{secret}\n");
        let err = figment::Figment::from(figment::providers::Toml::string(&broken))
            .extract::<serde_json::Value>()
            .expect_err("a broken TOML body must not parse");
        let message = Error::from(err).to_string();
        assert!(
            !message.contains(secret),
            "the config error leaked the value: {message}"
        );
    }

    #[test]
    fn a_type_error_names_the_key_only() {
        #[derive(Debug, serde::Deserialize)]
        #[allow(dead_code)]
        struct Inner {
            token: String,
        }
        #[derive(Debug, serde::Deserialize)]
        #[allow(dead_code)]
        struct Outer {
            admin: Inner,
        }

        let err =
            figment::Figment::from(figment::providers::Toml::string("[admin]\ntoken = 12345\n"))
                .extract::<Outer>()
                .expect_err("a numeric token must not extract into a string field");
        let message = Error::from(err).to_string();
        assert!(
            !message.contains("12345"),
            "the config error leaked the value: {message}"
        );
        assert!(
            message.contains("admin.token"),
            "the config error must name the key: {message}"
        );
    }

    #[test]
    fn a_figment_error_maps_to_the_config_variant() {
        #[derive(Debug, serde::Deserialize)]
        #[allow(dead_code)]
        struct Inner {
            token: String,
        }
        #[derive(Debug, serde::Deserialize)]
        #[allow(dead_code)]
        struct Outer {
            admin: Inner,
        }

        let err =
            figment::Figment::from(figment::providers::Toml::string("[admin]\ntoken = 12345\n"))
                .extract::<Outer>()
                .expect_err("a numeric token must not extract into a string field");
        let error = Error::from(err);
        assert!(matches!(error, Error::Config(_)));
        assert!(error.to_string().starts_with("configuration error: "));
    }

    #[test]
    fn a_driver_error_maps_to_the_sqlx_variant() {
        let error = Error::from(sqlx::Error::RowNotFound);
        assert!(matches!(error, Error::Sqlx(_)));
        assert!(error.to_string().starts_with("database error: "));
    }

    #[test]
    fn every_variant_display_keeps_its_prefix() {
        assert!(
            Error::Config("x".into())
                .to_string()
                .starts_with("configuration error: ")
        );
        assert!(
            Error::Parse("x".into())
                .to_string()
                .starts_with("parse error: ")
        );
        assert!(
            Error::Database("x".into())
                .to_string()
                .starts_with("database error: ")
        );
        assert!(
            Error::Sqlx(sqlx::Error::RowNotFound)
                .to_string()
                .starts_with("database error: ")
        );
        assert!(
            Error::NotFound("x".into())
                .to_string()
                .starts_with("not found: ")
        );
        assert!(
            Error::from(sqlx::migrate::MigrateError::VersionMissing(0))
                .to_string()
                .starts_with("database migration error: ")
        );
    }
}
