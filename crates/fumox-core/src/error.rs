//! Core error type shared across the workspace.

/// Core error enum. Variants are added as functionality lands; keep the
/// log-and-skip principle in mind, parse/fetch failures must never panic.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("configuration error: {0}")]
    Config(String),

    #[error("parse error: {0}")]
    Parse(String),

    #[error("database error: {0}")]
    Database(String),

    /// The row does not exist. Kept apart from [`Error::Database`] so a
    /// caller can answer "not found" instead of "the database failed".
    #[error("not found: {0}")]
    NotFound(String),

    #[error("database migration error: {0}")]
    Migration(#[from] sqlx::migrate::MigrateError),
}

impl From<sqlx::Error> for Error {
    fn from(err: sqlx::Error) -> Self {
        Error::Database(err.to_string())
    }
}

pub type Result<T> = std::result::Result<T, Error>;

impl From<figment::Error> for Error {
    fn from(err: figment::Error) -> Self {
        Error::Config(config_error_summary(&err))
    }
}

/// Reduce a figment error to the path of the offending key and a kind that
/// names no value.
///
/// The full figment text is not safe to keep: a TOML syntax error quotes
/// the offending source line and a type error prints the value, so a
/// mistyped `admin.token` or a `db.url` carrying a password would put the
/// secret into the startup error and from there into the operator's logs.
fn config_error_summary(err: &figment::Error) -> String {
    let path = err.path.join(".");
    let kind = config_error_kind(&err.kind);
    if path.is_empty() {
        kind
    } else {
        format!("{kind} at {path}")
    }
}

/// The value-free description of a figment error kind.
fn config_error_kind(kind: &figment::error::Kind) -> String {
    match kind {
        // A parse error quotes the offending source line, and with it any
        // secret on that line, so only its first line survives: for TOML
        // that is the location, not the content.
        figment::error::Kind::Message(message) => message
            .lines()
            .next()
            .unwrap_or_default()
            .trim()
            .chars()
            .take(200)
            .collect(),
        // These kinds name the offending value; the label alone says what
        // was wrong without repeating it.
        figment::error::Kind::InvalidType(..) => "invalid type".into(),
        figment::error::Kind::InvalidValue(..) => "invalid value".into(),
        figment::error::Kind::InvalidLength(..) => "invalid length".into(),
        figment::error::Kind::UnknownVariant(..) => "unknown variant".into(),
        // A field name is a key, not a value.
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

    /// A config error must name the key and the section, never the value:
    /// the body of the config carries the admin token and the database
    /// password, and a parse error quotes the line it choked on.
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

    /// A type error prints the value it found; the reduction keeps the key
    /// and drops the value.
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
}
