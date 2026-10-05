//! Tracing initialization shared by all binaries.
//!
//! The filter defaults to the `[log]` level from the config (each binary
//! takes its own key: `server` / `probe`) and can be overridden with the
//! standard `RUST_LOG` environment variable (e.g.
//! `RUST_LOG=fumox_core=debug,info`), which always wins — verbatim: the
//! sqlx silencer is added to the fallback only, never layered on `RUST_LOG`.

use tracing_subscriber::EnvFilter;

use crate::config::LogLevel;

/// Installs the global tracing subscriber. Safe to call once per process.
pub fn init_tracing(level: LogLevel) {
    let filter = build_filter(std::env::var("RUST_LOG").ok().as_deref(), level);

    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(true)
        .init();
}

/// The filter for the given `RUST_LOG` value. A set `RUST_LOG` wins
/// **verbatim**: the silencer is deliberately not layered on, because
/// `EnvFilter::add_directive` replaces a same-target directive and would
/// silently undo an operator's `RUST_LOG=sqlx::query=debug`.
///
/// `None`, or a value that does not parse, falls back to the `[log]`
/// level from the config (plus the silencer), so one malformed directive
/// never blinds the whole process.
fn build_filter(rust_log: Option<&str>, level: LogLevel) -> EnvFilter {
    rust_log
        .and_then(|rust_log| EnvFilter::try_new(rust_log).ok())
        .unwrap_or_else(|| fallback_filter(level))
}

fn fallback_filter(level: LogLevel) -> EnvFilter {
    EnvFilter::new(level.as_str())
        .add_directive("sqlx::query=warn".parse().expect("valid directive"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    /// A writer funneling the subscriber's output into a shared buffer,
    /// so a test can tell whether an event made it through the filter.
    struct Captured(Arc<Mutex<Vec<u8>>>);

    impl std::io::Write for Captured {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    /// Reports whether `event` passes `filter`, checked through a real
    /// subscriber: `EnvFilter` has no public "would this event pass?" probe.
    fn event_passes(filter: EnvFilter, event: fn()) -> bool {
        let captured = Arc::new(Mutex::new(Vec::new()));
        let make_writer = Arc::clone(&captured);
        let subscriber = tracing_subscriber::fmt()
            .with_env_filter(filter)
            .with_ansi(false)
            .with_writer(move || Captured(Arc::clone(&make_writer)))
            .finish();
        tracing::subscriber::with_default(subscriber, event);
        !captured.lock().unwrap().is_empty()
    }

    fn event_sqlx_query_debug() {
        tracing::debug!(target: "sqlx::query", "SELECT 1");
    }

    fn event_sqlx_query_warn() {
        tracing::warn!(target: "sqlx::query", "slow query");
    }

    fn event_core_info() {
        tracing::info!(target: "fumox_core::config", "config loaded");
    }

    /// The fallback (no `RUST_LOG`): the config level applies, and the
    /// sqlx silencer keeps sub-WARN query chatter out.
    #[test]
    fn fallback_keeps_config_level_and_silences_sqlx_queries() {
        let filter = || build_filter(None, LogLevel::Info);

        assert!(event_passes(filter(), event_core_info));
        assert!(event_passes(filter(), event_sqlx_query_warn));
        assert!(
            !event_passes(filter(), event_sqlx_query_debug),
            "the sqlx::query=warn silencer must keep DEBUG chatter out of the fallback"
        );
    }

    /// Regression: the silencer used to be chained onto *every* filter, so an
    /// operator's `RUST_LOG=sqlx::query=debug` was silently downgraded to warn.
    #[test]
    fn explicit_rust_log_sqlx_directive_is_not_overridden() {
        let filter = || build_filter(Some("sqlx::query=debug,info"), LogLevel::Info);

        assert!(
            event_passes(filter(), event_sqlx_query_debug),
            "an explicit sqlx::query=debug in RUST_LOG must be honored"
        );
        assert!(event_passes(filter(), event_core_info));
        assert!(event_passes(filter(), event_sqlx_query_warn));
    }

    /// A malformed `RUST_LOG` must not blind the process: it falls back to the
    /// config-level filter (with the silencer), like an unset variable would.
    #[test]
    fn malformed_rust_log_falls_back_to_config_level() {
        let filter = || build_filter(Some("sqlx::query=warning"), LogLevel::Info);

        assert!(event_passes(filter(), event_core_info));
        assert!(!event_passes(filter(), event_sqlx_query_debug));
    }
}
