//! Tracing initialization shared by all binaries.
//!
//! The filter defaults to the `[log]` level from the config (each binary
//! takes its own key: `server` / `probe`) and can be overridden with the
//! standard `RUST_LOG` environment variable (e.g.
//! `RUST_LOG=fumox_core=debug,info`), which always wins verbatim: the
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
/// `None`, an empty/whitespace-only value, or a value that does not parse
/// falls back to the `[log]` level from the config (plus the silencer), so
/// one malformed directive never blinds the whole process. A value that
/// does not parse is reported to stderr before the fallback, so a typo in
/// the environment shows up in the operator's console instead of being
/// swallowed.
fn build_filter(rust_log: Option<&str>, level: LogLevel) -> EnvFilter {
    let Some(value) = rust_log.map(str::trim).filter(|value| !value.is_empty()) else {
        return fallback_filter(level);
    };
    match EnvFilter::try_new(value) {
        Ok(filter) => filter,
        Err(error) => {
            eprintln!("invalid RUST_LOG={value:?}: {error}; falling back to [log] level");
            fallback_filter(level)
        }
    }
}

fn fallback_filter(level: LogLevel) -> EnvFilter {
    // The silencer is spelled straight into the directive list instead of
    // `add_directive(..parse()..)`: both parts are known-valid constants
    // (`LogLevel::as_str` is a closed set), so there is no parse `Result`
    // left to panic on. `EnvFilter::new` parses comma-separated directives
    // in order, and the config level (no target) never collides with the
    // `sqlx::query` target, so the resulting directive set is identical.
    EnvFilter::new(format!("{},sqlx::query=warn", level.as_str()))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Reports whether `event` passes `filter`, checked through a real
    /// subscriber: `EnvFilter` has no public "would this event pass?" probe.
    fn event_passes(filter: EnvFilter, event: fn()) -> bool {
        let (make_writer, captured) = capture::captured_writer();
        let subscriber = tracing_subscriber::fmt()
            .with_env_filter(filter)
            .with_ansi(false)
            .with_writer(make_writer)
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

    /// An empty `RUST_LOG` is an absent one, not a directive set that
    /// switches everything off: a deployment that exports `RUST_LOG=` (or
    /// exports it with an empty value) must still get the configured level.
    #[test]
    fn an_empty_rust_log_falls_back_to_config_level() {
        for value in ["", " ", "\t\n "] {
            let filter = || build_filter(Some(value), LogLevel::Info);

            assert!(
                event_passes(filter(), event_core_info),
                "RUST_LOG={value:?} must not switch the process off"
            );
            assert!(!event_passes(filter(), event_sqlx_query_debug));
        }
    }
}

/// Test-support helper for the log-capturing test modules of the workspace
/// crates (this file's filter tests, `fumox-core::db`, `fumox-core::config_writer`,
/// and the server's admin, scheduler, pipeline and export tests): a writer
/// funneling a tracing subscriber's output into a shared
/// `Arc<Mutex<Vec<u8>>>` buffer the test reads the captured lines back
/// from. Deliberately compiled outside `cfg(test)`: the sibling crates'
/// test builds link fumox-core as a plain dependency, where this crate's
/// own `cfg(test)` never applies (the same reasoning as
/// [`crate::db::tempdir_lite`]). No production call sites.
pub mod capture {
    use std::sync::{Arc, Mutex};

    /// The writer half of [`captured_writer`]: appends everything the
    /// subscriber emits into the shared buffer. Constructed only by
    /// [`captured_writer`]; the field is private.
    pub struct CapturedWriter(Arc<Mutex<Vec<u8>>>);

    impl std::io::Write for CapturedWriter {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            // Poisoned only if a writer panicked mid-write; the captured
            // bytes stay valid, so recover the lock (the workspace-wide
            // discipline) rather than failing the write.
            let mut captured = self
                .0
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            captured.extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    /// A fresh shared buffer plus the make-writer closure for
    /// `tracing_subscriber::fmt().with_writer(..)`: the buffer is what the
    /// test reads the captured lines back from, the closure hands the
    /// subscriber a writer appending into it.
    pub fn captured_writer() -> (impl Fn() -> CapturedWriter, Arc<Mutex<Vec<u8>>>) {
        let captured = Arc::new(Mutex::new(Vec::new()));
        let writer = Arc::clone(&captured);
        (move || CapturedWriter(Arc::clone(&writer)), captured)
    }
}
