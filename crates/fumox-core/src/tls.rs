//! TLS crypto provider setup shared by both binaries.
//!
//! rustls 0.23 can carry several crypto providers at once, but a process
//! has exactly one installed as the default. The workspace pins `ring`
//! (see the `rustls` dependency in the root Cargo.toml) and reqwest is
//! built with `rustls-no-provider`, which refuses to build a client
//! until a provider is installed. The provider is therefore installed
//! explicitly at startup, instead of depending on which feature of
//! reqwest happens to be enabled.

use std::sync::OnceLock;

/// Installs the `ring` crypto provider as the process default.
///
/// Idempotent: the second and later calls do nothing. If a provider is
/// already installed, it is kept — replacing it is not possible, and the
/// alternative (a panic at startup) would turn a feature-set mismatch
/// into a crash.
///
/// reqwest panics when a client is built before a provider is
/// installed, so every client construction calls this first. The
/// binaries also call it at startup, before anything else runs.
pub fn install_crypto_provider() {
    static INSTALLED: OnceLock<()> = OnceLock::new();
    INSTALLED.get_or_init(|| {
        if rustls::crypto::ring::default_provider()
            .install_default()
            .is_err()
        {
            // Another provider won the race (or something else installed
            // one before us). It stays: rustls uses the installed one.
            tracing::debug!("a rustls crypto provider was already installed; keeping it");
        }
    });
}
