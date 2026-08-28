//! Output formats for served subscriptions (SPEC §10).
//!
//! The pipeline ends with the `encode` step: the deduplicated, sorted
//! candidate list is serialized according to the profile's output format.
//! URI lists and base64 are produced by `serve.rs` directly; structured
//! formats live here.

pub mod clash;
pub mod singbox;

use std::collections::HashSet;

/// Resolve duplicate names by suffixing later occurrences with « (2)»,
/// « (3)» and so on (PLAN gap 14). The first occurrence keeps its name
/// unchanged; suffixes themselves are checked against the taken set, so a
/// literal «name (2)» in the input cannot shadow a generated one.
pub fn dedupe_names<'a>(names: impl IntoIterator<Item = &'a str>) -> Vec<String> {
    let mut taken: HashSet<String> = HashSet::new();
    let mut out: Vec<String> = Vec::new();
    for name in names {
        let mut candidate = name.to_string();
        let mut n: usize = 1;
        while taken.contains(&candidate) {
            n += 1;
            candidate = format!("{name} ({n})");
        }
        taken.insert(candidate.clone());
        out.push(candidate);
    }
    out
}

/// Whether the entry carries a truthy insecure toggle under any of its
/// spelling aliases. Mirrors the alias set of the pipeline's
/// `normalize_params` step, which leaves a lone alias in its original
/// spelling.
pub(crate) fn is_insecure(params: &[crate::models::Param]) -> bool {
    const ALIASES: [&str; 3] = ["insecure", "allowinsecure", "skip-cert-verify"];
    params.iter().any(|p| {
        ALIASES.contains(&p.key.to_ascii_lowercase().as_str())
            && matches!(p.value.trim().to_ascii_lowercase().as_str(), "1" | "true")
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dedupe_keeps_the_first_and_suffixes_the_rest() {
        let out = dedupe_names(["a", "b", "a", "a", "b"]);
        assert_eq!(out, vec!["a", "b", "a (2)", "a (3)", "b (2)"]);
    }

    #[test]
    fn dedupe_does_not_shadow_existing_suffixes() {
        // "a (2)" already present: the duplicate of "a" must become "a (3)".
        let out = dedupe_names(["a (2)", "a", "a"]);
        assert_eq!(out, vec!["a (2)", "a", "a (3)"]);
    }

    #[test]
    fn insecure_detects_every_alias_and_truthy_value() {
        use crate::models::Param;
        let param = |key: &str, value: &str| Param {
            key: key.into(),
            value: value.into(),
            known: true,
        };
        assert!(is_insecure(&[param("allowInsecure", "1")]));
        assert!(is_insecure(&[param("insecure", "true")]));
        assert!(is_insecure(&[param("skip-cert-verify", " TRUE ")]));
        assert!(!is_insecure(&[param("allowInsecure", "0")]));
        assert!(!is_insecure(&[param("sni", "example.com")]));
        assert!(!is_insecure(&[]));
    }
}
