//! TLS crypto provider setup shared by both binaries. rustls 0.23 can carry
//! several crypto providers but installs one as the process default: the
//! workspace pins `ring` (the `rustls` dependency in the root Cargo.toml)
//! and reqwest is built with `rustls-no-provider`, which refuses to build a
//! client until a provider is installed. It is therefore installed
//! explicitly at startup instead of depending on which reqwest feature
//! happens to be enabled.

use std::sync::OnceLock;

/// Installs the `ring` crypto provider as the process default. Idempotent: a
/// provider that is already installed is kept, because replacing it is not
/// possible and panicking at startup would turn a feature-set mismatch into
/// a crash.
///
/// reqwest panics when a client is built before a provider is installed, so
/// every client construction calls this first.
pub fn install_crypto_provider() {
    static INSTALLED: OnceLock<()> = OnceLock::new();
    INSTALLED.get_or_init(|| {
        if rustls::crypto::ring::default_provider()
            .install_default()
            .is_err()
        {
            // Another provider won the race (or something else installed
            // one before us). It stays: rustls uses the installed one
            tracing::debug!("a rustls crypto provider was already installed; keeping it");
        }
    });
}
