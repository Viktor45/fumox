//! Tracing initialization shared by all binaries.
//!
//! The filter defaults to `info` and can be overridden with the standard
//! `RUST_LOG` environment variable (e.g. `RUST_LOG=fumox_core=debug,info`).

use tracing_subscriber::EnvFilter;

/// Installs the global tracing subscriber. Safe to call once per process.
pub fn init_tracing() {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info"))
        // Keep sqlx's own chatter at bay unless explicitly requested.
        .add_directive("sqlx::query=warn".parse().expect("valid directive"));

    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(true)
        .init();
}
