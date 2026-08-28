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

/// Parameter value by case-insensitive key, empty values dropped.
///
/// URI feeds keep values percent-encoded, so the result is leniently
/// decoded (valid `%XX` escapes resolve, garbage passes through); entries
/// from vmess JSON / Clash YAML carry plain values that decode unchanged.
pub(crate) fn param_value(entry: &crate::models::ProxyEntry, key: &str) -> Option<String> {
    let value = entry.param_ignore_case(key)?.trim();
    (!value.is_empty()).then(|| crate::parsers::uri::percent_decode(value))
}

/// Whether the parameter is present with a truthy value (`1`/`true`/`yes`/
/// `on`, case-insensitive) — how Clash YAML booleans land in params.
pub(crate) fn param_truthy(entry: &crate::models::ProxyEntry, key: &str) -> bool {
    entry.param_ignore_case(key).is_some_and(|v| {
        matches!(
            v.trim().to_ascii_lowercase().as_str(),
            "1" | "true" | "yes" | "on"
        )
    })
}

/// Parameter as a list: YAML sequences (Clash-input `alpn: [h2, http/1.1]`)
/// keep their items, plain values split on commas (URI `alpn=h2,http/1.1`).
pub(crate) fn param_list(entry: &crate::models::ProxyEntry, key: &str) -> Option<Vec<String>> {
    let raw = entry.param_ignore_case(key)?.to_string();
    if raw.trim().is_empty() {
        return None;
    }
    if let Ok(serde_norway::Value::Sequence(seq)) = serde_norway::from_str(&raw) {
        let list: Vec<String> = seq
            .into_iter()
            .map(|v| match v {
                serde_norway::Value::String(s) => s,
                other => serde_norway::to_string(&other)
                    .unwrap_or_default()
                    .trim()
                    .to_string(),
            })
            .filter(|s| !s.is_empty())
            .collect();
        return (!list.is_empty()).then_some(list);
    }
    let list: Vec<String> = crate::parsers::uri::percent_decode(&raw)
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect();
    (!list.is_empty()).then_some(list)
}

/// Parameter value parsed back into a YAML mapping. Clash-input entries keep
/// structured fields (`ws-opts`, `reality-opts`, `grpc-opts`, …) as YAML
/// text; this reconstructs them for the output encoders.
pub(crate) fn param_map(
    entry: &crate::models::ProxyEntry,
    key: &str,
) -> Option<serde_norway::Mapping> {
    let raw = entry.param_ignore_case(key)?;
    match serde_norway::from_str(raw.trim()) {
        Ok(serde_norway::Value::Mapping(map)) if !map.is_empty() => Some(map),
        _ => None,
    }
}

/// String lookup inside an optional parsed YAML mapping, trying both the
/// given key and its capitalized spelling (`host` / `Host`).
pub(crate) fn map_str(map: &Option<serde_norway::Mapping>, key: &str) -> Option<String> {
    let map = map.as_ref()?;
    for candidate in [key, &capitalize(key)] {
        if let Some(value) = map.get(candidate).and_then(|v| v.as_str())
            && !value.trim().is_empty()
        {
            return Some(value.trim().to_string());
        }
    }
    None
}

fn capitalize(key: &str) -> String {
    let mut out = key.to_string();
    if let Some(first) = out.get_mut(..1) {
        first.make_ascii_uppercase();
    }
    out
}

/// Resolved transport network: the scheme's native URI key first (`type` for
/// vless/trojan, `net` for vmess — passed by the caller), then the mihomo
/// spelling `network` used by Clash input. Lower-cased.
pub(crate) fn network_of(entry: &crate::models::ProxyEntry, uri_key: &str) -> Option<String> {
    param_value(entry, uri_key)
        .or_else(|| param_value(entry, "network"))
        .map(|v| v.to_ascii_lowercase())
}

/// REALITY public key from URI `pbk` or a Clash-input `reality-opts` block.
pub(crate) fn reality_public_key(entry: &crate::models::ProxyEntry) -> Option<String> {
    param_value(entry, "pbk").or_else(|| map_str(&param_map(entry, "reality-opts"), "public-key"))
}

/// REALITY short id from URI `sid` or a Clash-input `reality-opts` block.
pub(crate) fn reality_short_id(entry: &crate::models::ProxyEntry) -> Option<String> {
    param_value(entry, "sid").or_else(|| map_str(&param_map(entry, "reality-opts"), "short-id"))
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
