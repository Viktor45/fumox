//! Tracing initialization shared by all binaries. The filter defaults to the
//! `[log]` level (each binary its own key: `server` / `probe`) and `RUST_LOG`
//! (e.g. `RUST_LOG=fumox_core=debug,info`) always wins verbatim: the sqlx
//! silencer is added to the fallback only, never layered on `RUST_LOG`.

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

/// A set `RUST_LOG` wins verbatim: the silencer is deliberately not layered
/// on, because `EnvFilter::add_directive` replaces a same-target directive
/// and would silently undo an operator's `RUST_LOG=sqlx::query=debug`.
///
/// `None`, an empty/whitespace-only value, or a value that does not parse
/// falls back to the `[log]` level (plus the silencer); a parse failure is
/// reported to stderr first, so a typo shows up in the operator's console.
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
    // Spelled straight into the directive list instead of
    // `add_directive(..parse()..)`: both parts are known-valid constants
    // (`LogLevel::as_str` is a closed set), so no parse `Result` is left to
    // panic on, and the config level (no target) never collides with the
    // `sqlx::query` target
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
        capture::with_default(subscriber, event);
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

    #[test]
    fn malformed_rust_log_falls_back_to_config_level() {
        let filter = || build_filter(Some("sqlx::query=warning"), LogLevel::Info);

        assert!(event_passes(filter(), event_core_info));
        assert!(!event_passes(filter(), event_sqlx_query_debug));
    }

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

    #[test]
    fn capture_observes_a_callsite_first_seen_on_another_thread() {
        fn emit_marker() {
            tracing::info!(
                target: "fumox_core::logging::tests::parallel_capture",
                "capture marker"
            );
        }

        let (ready_tx, ready_rx) = std::sync::mpsc::channel();
        let (seen_tx, seen_rx) = std::sync::mpsc::channel();
        let capture = std::thread::spawn(move || {
            let (make_writer, captured) = capture::captured_writer();
            let subscriber = tracing_subscriber::fmt()
                .with_ansi(false)
                .with_max_level(tracing::Level::TRACE)
                .with_writer(make_writer)
                .finish();
            capture::with_default(subscriber, || {
                ready_tx.send(()).unwrap();
                seen_rx.recv().unwrap();
                emit_marker();
            });
            String::from_utf8(captured.lock().unwrap().clone()).unwrap()
        });

        ready_rx.recv().unwrap();
        emit_marker();
        seen_tx.send(()).unwrap();
        let log = capture.join().unwrap();
        assert!(
            log.contains("capture marker"),
            "the capture must observe a callsite registered on another thread: {log}"
        );
    }
}

/// Test-support helper for the log-capturing test modules of the workspace
/// crates. Deliberately compiled outside `cfg(test)`: the sibling crates'
/// test builds link fumox-core as a plain dependency, where this crate's own
/// `cfg(test)` never applies (same reasoning as [`crate::db::tempdir_lite`]).
pub mod capture {
    use std::sync::{Arc, Mutex};

    /// Run with a scoped subscriber without parallel tests starving tracing's
    /// process-global callsite cache.
    pub fn with_default<S, T>(subscriber: S, run: impl FnOnce() -> T) -> T
    where
        S: tracing::Subscriber + Send + Sync + 'static,
    {
        stabilize_callsite_interests();
        tracing::subscriber::with_default(subscriber, || {
            tracing::callsite::rebuild_interest_cache();
            run()
        })
    }

    fn stabilize_callsite_interests() {
        static ONCE: std::sync::Once = std::sync::Once::new();
        ONCE.call_once(|| {
            // Two live registrars keep first-seen callsites on subscriber-less
            // threads from being cached as disabled for the whole process.
            for _ in 0..2 {
                let subscriber = tracing_subscriber::fmt()
                    .with_ansi(false)
                    .with_max_level(tracing::Level::INFO)
                    .with_writer(std::io::sink)
                    .finish();
                std::mem::forget(tracing::Dispatch::new(subscriber));
            }
        });
    }

    /// The writer half of [`captured_writer`]: appends everything the
    /// subscriber emits into the shared buffer.
    pub struct CapturedWriter(Arc<Mutex<Vec<u8>>>);

    impl std::io::Write for CapturedWriter {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            // Poisoned only if a writer panicked mid-write; the captured
            // bytes stay valid, so recover the lock rather than failing the
            // write
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
    /// `tracing_subscriber::fmt().with_writer(..)`: the closure hands the
    /// subscriber a writer appending into the buffer the test reads back.
    pub fn captured_writer() -> (impl Fn() -> CapturedWriter, Arc<Mutex<Vec<u8>>>) {
        let captured = Arc::new(Mutex::new(Vec::new()));
        let writer = Arc::clone(&captured);
        (move || CapturedWriter(Arc::clone(&writer)), captured)
    }
}
