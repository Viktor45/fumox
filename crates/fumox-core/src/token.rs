//! The profile access token guards a public endpoint, so the database keeps
//! only its SHA-256 hash: a copied database file no longer hands out the
//! token itself. The stored form is self-describing (`sha256$<64 hex>`), so a
//! legacy plain-text row stays distinguishable and keeps working through the
//! same entry point, [`verify`]. SHA-256 is unsalted, so a leaked database is
//! still open to a dictionary attack on a weak token; a salt would need a
//! per-deployment key, and a hash made under one deployment's key cannot be
//! imported into another, which would break the configuration export.

use sha2::{Digest, Sha256};

const PREFIX: &str = "sha256$";

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
/// Idempotent, so handing back a stored value writes the same bytes again.
pub fn stored(value: Option<String>) -> Option<String> {
    value.map(|value| {
        if is_hashed(&value) {
            value
        } else {
            hash(&value)
        }
    })
}

/// A hashed row compares the hash of the presented token; a legacy plain-text
/// row compares the values themselves, so a deployment whose rows have not
/// been re-hashed yet keeps serving its subscribers.
pub fn verify(presented: &str, stored_value: &str) -> bool {
    if is_hashed(stored_value) {
        ct_eq(&hash(presented), stored_value)
    } else {
        ct_eq(presented, stored_value)
    }
}

/// Constant-time string equality: runs over the longer input with the shorter
/// one zero-padded, so the duration leaks neither the common prefix nor the
/// length; the length difference is folded into the verdict instead of
/// short-circuiting.
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

    #[test]
    fn a_token_is_stored_as_a_hash() {
        let stored = hash("supersecret");
        assert!(stored.starts_with(PREFIX));
        assert_eq!(stored.len(), PREFIX.len() + HEX_LEN);
        assert!(is_hashed(&stored));
        assert!(!stored.contains("supersecret"));
    }

    #[test]
    fn storing_a_hash_keeps_it() {
        let once = stored(Some("supersecret".into())).unwrap();
        let twice = stored(Some(once.clone())).unwrap();
        assert_eq!(once, twice);
        assert!(is_hashed(&once));
    }

    #[test]
    fn only_the_right_token_verifies() {
        let stored = hash("supersecret");
        assert!(verify("supersecret", &stored));
        assert!(!verify("supersecret2", &stored));
        assert!(!verify("", &stored));
    }

    #[test]
    fn a_legacy_plaintext_row_still_verifies() {
        assert!(!is_hashed("supersecret"));
        assert!(verify("supersecret", "supersecret"));
        assert!(!verify("other", "supersecret"));
    }

    /// The comparison is over two fixed-length values and leaks nothing
    /// about the token's length.
    #[test]
    fn a_hash_never_verifies_against_another_hash() {
        assert!(!verify("supersecret", &hash("other")));
    }

    #[test]
    fn a_prefix_match_is_not_a_match() {
        assert!(!ct_eq("supersecret", "supersecret2"));
        assert!(!ct_eq("supersecret2", "supersecret"));
        assert!(!ct_eq("supersecret", "superdsecret"));
        assert!(ct_eq("supersecret", "supersecret"));
    }

    /// Direct unit tests of [`ct_eq`], the comparison every secret check
    /// (cookie/CSRF, capability tokens, [`verify`]) goes through.
    #[test]
    fn ct_eq_verdicts() {
        assert!(ct_eq("", ""));
        assert!(ct_eq("supersecret", "supersecret"));
        assert!(!ct_eq("supersecret", "supersecret2"));
        assert!(!ct_eq("supersecret2", "supersecret"));
        assert!(!ct_eq("", "supersecret"));
        assert!(!ct_eq("supersecret", ""));
        assert!(!ct_eq("supersecret", "dupersecret"));
        assert!(!ct_eq("supersecret", "supersecreD"));
    }
}
