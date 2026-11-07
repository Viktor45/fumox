//! Access-token hashing at rest and constant-time verification.
//!
//! The profile access token guards a public endpoint, so the database
//! keeps only its SHA-256 hash: a copied database file no longer hands
//! out the token itself. The hash is stored in a self-describing form
//! (`sha256$<64 hex>`), so a row written by an older release (the token in
//! plain text) stays distinguishable and keeps working: the two forms are
//! compared by the same entry point, [`verify`].
//!
//! SHA-256 is unsalted, so a leaked database is still open to a
//! dictionary attack on a weak token. That is the deliberate trade-off:
//! a salted hash would need a per-deployment key, and a hash made under
//! one deployment's key cannot be imported into another, which would
//! break the configuration export.

use sha2::{Digest, Sha256};

/// Prefix of a stored token hash.
const PREFIX: &str = "sha256$";

/// Number of hex characters in a SHA-256 digest.
const HEX_LEN: usize = 64;

/// The stored form of a token: `sha256$<64 lowercase hex>`.
pub fn hash(secret: &str) -> String {
    let digest = Sha256::digest(secret.as_bytes());
    let mut out = String::with_capacity(PREFIX.len() + HEX_LEN);
    out.push_str(PREFIX);
    for byte in digest {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

/// Whether `value` is a stored token hash.
pub fn is_hashed(value: &str) -> bool {
    let Some(digest) = value.strip_prefix(PREFIX) else {
        return false;
    };
    digest.len() == HEX_LEN
        && digest
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// The value to store for a token: its hash, unless it already is one.
///
/// Idempotent, so a caller that hands over the stored value (the admin
/// form keeping a token unchanged, an import carrying a hash) writes the
/// same bytes again.
pub fn stored(value: Option<String>) -> Option<String> {
    value.map(|value| {
        if is_hashed(&value) {
            value
        } else {
            hash(&value)
        }
    })
}

/// Whether `presented` is the token behind `stored_value`.
///
/// A hashed row compares the hash of the presented token; a legacy
/// plain-text row compares the values themselves, so a deployment whose
/// rows have not been re-hashed yet keeps serving its subscribers.
pub fn verify(presented: &str, stored_value: &str) -> bool {
    if is_hashed(stored_value) {
        ct_eq(&hash(presented), stored_value)
    } else {
        ct_eq(presented, stored_value)
    }
}

/// Constant-time string equality.
///
/// The loop runs over the longer of the two inputs, treating the missing
/// tail of the shorter one as zero bytes, so the duration does not leak
/// where the inputs agree or how long a common prefix is; the length
/// difference itself is folded into the final verdict instead of
/// short-circuiting before the loop.
pub fn ct_eq(a: &str, b: &str) -> bool {
    let (ab, bb) = (a.as_bytes(), b.as_bytes());
    let mut diff = ab.len() ^ bb.len();
    for i in 0..ab.len().max(bb.len()) {
        let x = ab.get(i).copied().unwrap_or(0);
        let y = bb.get(i).copied().unwrap_or(0);
        diff |= usize::from(x != y);
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A token never reaches the database in plain text, and the stored
    /// form says so: it names the algorithm and carries the digest.
    #[test]
    fn a_token_is_stored_as_a_hash() {
        let stored = hash("supersecret");
        assert!(stored.starts_with(PREFIX));
        assert_eq!(stored.len(), PREFIX.len() + HEX_LEN);
        assert!(is_hashed(&stored));
        assert!(!stored.contains("supersecret"));
    }

    /// Hashing twice is not hashing again: the stored form of a stored
    /// value is the value itself, so the admin form and the import can
    /// hand back what they read without changing the token.
    #[test]
    fn storing_a_hash_keeps_it() {
        let once = stored(Some("supersecret".into())).unwrap();
        let twice = stored(Some(once.clone())).unwrap();
        assert_eq!(once, twice);
        assert!(is_hashed(&once));
    }

    /// The presented token is what counts: the hash of it must match the
    /// stored hash, and a different token must not.
    #[test]
    fn only_the_right_token_verifies() {
        let stored = hash("supersecret");
        assert!(verify("supersecret", &stored));
        assert!(!verify("supersecret2", &stored));
        assert!(!verify("", &stored));
    }

    /// A row written by an older release still holds the token in plain
    /// text; it must keep verifying until it is re-hashed.
    #[test]
    fn a_legacy_plaintext_row_still_verifies() {
        assert!(!is_hashed("supersecret"));
        assert!(verify("supersecret", "supersecret"));
        assert!(!verify("other", "supersecret"));
    }

    /// The hash of the token is what is compared, so the comparison
    /// itself is over two fixed-length values and leaks nothing about the
    /// token's length.
    #[test]
    fn a_hash_never_verifies_against_another_hash() {
        assert!(!verify("supersecret", &hash("other")));
    }

    /// The padded comparison must still reject everything unequal, both a
    /// shared prefix with a longer tail and a differing byte.
    #[test]
    fn a_prefix_match_is_not_a_match() {
        assert!(!ct_eq("supersecret", "supersecret2"));
        assert!(!ct_eq("supersecret2", "supersecret"));
        assert!(!ct_eq("supersecret", "superdsecret"));
        assert!(ct_eq("supersecret", "supersecret"));
    }

    /// Direct unit tests of [`ct_eq`], the comparison every secret check
    /// (cookie/CSRF, capability tokens, this module's [`verify`]) goes
    /// through: equal strings are equal, everything else — a different
    /// length on either side, one differing character at equal length, an
    /// empty string against a non-empty one — is not.
    #[test]
    fn ct_eq_verdicts() {
        // Equal strings, including two empty ones.
        assert!(ct_eq("", ""));
        assert!(ct_eq("supersecret", "supersecret"));
        // Different lengths, either side the longer one.
        assert!(!ct_eq("supersecret", "supersecret2"));
        assert!(!ct_eq("supersecret2", "supersecret"));
        // Empty against non-empty, both directions.
        assert!(!ct_eq("", "supersecret"));
        assert!(!ct_eq("supersecret", ""));
        // Equal length, one differing character, at the head and at the tail.
        assert!(!ct_eq("supersecret", "dupersecret"));
        assert!(!ct_eq("supersecret", "supersecreD"));
    }
}
