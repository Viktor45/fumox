//! Test-only support shared by the log-capturing test modules (`admin`,
//! `scheduler`): the tracing-dispatcher groundwork their `capture_logs`
//! helpers all need.

/// Keep ≥2 dispatchers permanently alive in tracing's global dispatcher
/// registry, for the log-capturing test modules (auth, scheduler): a call
/// site's interest is cached against the dispatchers live at its FIRST
/// execution, and when the registry holds fewer than two, tracing consults
/// the *registering thread's* thread-local default (in a parallel test
/// suite usually no subscriber at all) so call sites get cached as
/// `Interest::never` and their events go silently nowhere for the rest of
/// the process (an intermittent failure that depends purely on test
/// scheduling). With the registry permanently multi-dispatcher, every
/// registration is evaluated against all live dispatchers and lands on
/// `Interest::sometimes`, so capture tests always see their lines. Runtime
/// dispatch is unaffected: threads without a scoped default still resolve
/// to the empty global default and drop their events as before.
///
/// Call once before the first capture; the two subscribers leak on
/// purpose: the permanently-live registrars are the point.
pub(crate) fn stabilize_callsite_interests() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
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
