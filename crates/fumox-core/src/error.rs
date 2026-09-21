//! Core error type shared across the workspace.

/// Core error enum. Variants are added as functionality lands; keep the
/// log-and-skip principle in mind — parse/fetch failures must never panic.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("configuration error: {0}")]
    Config(String),

    #[error("parse error: {0}")]
    Parse(String),

    #[error("database error: {0}")]
    Database(String),

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
        Error::Config(err.to_string())
    }
}
