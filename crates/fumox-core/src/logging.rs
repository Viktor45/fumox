//! Tracing initialization shared by all binaries.
//!
//! The filter defaults to the `[log]` level from the config (each binary
//! takes its own key: `server` / `probe`) and can be overridden with the
//! standard `RUST_LOG` environment variable (e.g.
//! `RUST_LOG=fumox_core=debug,info`), which always wins.

use tracing_subscriber::EnvFilter;

use crate::config::LogLevel;

/// Installs the global tracing subscriber. Safe to call once per process.
pub fn init_tracing(level: LogLevel) {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(level.as_str()))
        // Keep sqlx's own chatter at bay unless explicitly requested.
        .add_directive("sqlx::query=warn".parse().expect("valid directive"));

    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(true)
        .init();
}
