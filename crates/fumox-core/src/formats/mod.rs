//! Output formats for served subscriptions.
//!
//! The pipeline ends with the `encode` step: the deduplicated, sorted
//! candidate list is serialized according to the profile's output format.
//! URI lists and base64 are produced by `serve.rs` directly; structured
//! formats live here.
//!
//! The parameter semantics the encoders rely on live in
//! [`crate::params`]: the two encoders and the fingerprint have to read
//! the same spellings, or the emitted document and the deduplication key
//! describe different nodes.

pub mod clash;
pub mod singbox;

use crate::models::{OutputFormat, ProxyEntry};
use std::collections::{HashMap, HashSet};

pub(crate) use crate::params::{
    is_insecure, list as param_list, map_first, map_header, map_list, map_str,
    truthy as param_truthy, value as param_value,
};

/// How many entries an output format cannot represent.
///
/// The structured formats have no counterpart for some schemes and
/// leave exactly those entries out of the document; the plain formats
/// carry every scheme. The count is what the served response reports,
/// so a subscriber can see how much of the list the format could not
/// express instead of silently receiving a shorter one.
pub fn skipped_count(format: OutputFormat, entries: &[ProxyEntry]) -> usize {
    match format {
        OutputFormat::UriList | OutputFormat::Base64 => 0,
        OutputFormat::Clash => entries
            .iter()
            .filter(|entry| !clash::is_supported(entry.scheme))
            .count(),
        OutputFormat::SingBox => entries
            .iter()
            .filter(|entry| !singbox::is_supported(entry.scheme))
            .count(),
    }
}

/// Resolve duplicate names by suffixing later occurrences with « (2)»,
/// « (3)» and so on. The first occurrence keeps its name
/// unchanged; suffixes themselves are checked against the taken set, so a
/// literal «name (2)» in the input cannot shadow a generated one.
///
/// The per-name counter is remembered across occurrences and never rewinds:
/// restarting the probe at 1 for every entry made this O(k²) in the number of
/// proxies sharing a name, and names come straight from an untrusted feed ,
/// 20 000 identical names cost 36 s of CPU inside a `/sub` render (security
/// audit, 2026-09-05).
pub fn dedupe_names<'a>(names: impl IntoIterator<Item = &'a str>) -> Vec<String> {
    let mut taken: HashSet<String> = HashSet::new();
    let mut next_suffix: HashMap<String, usize> = HashMap::new();
    let mut out: Vec<String> = Vec::new();
    for name in names {
        let mut candidate = name.to_string();
        if taken.contains(&candidate) {
            let n = next_suffix.entry(name.to_string()).or_insert(1);
            loop {
                *n += 1;
                candidate = format!("{name} ({n})");
                if !taken.contains(&candidate) {
                    break;
                }
            }
        }
        taken.insert(candidate.clone());
        out.push(candidate);
    }
    out
}

/// Resolved transport network: the scheme's native URI key first (`type` for
/// vless/trojan, `net` for vmess, passed by the caller), then the mihomo
/// spelling `network` used by Clash input. Lower-cased.
pub(crate) fn network_of(entry: &crate::models::ProxyEntry, uri_key: &str) -> Option<String> {
    param_value(entry, uri_key)
        .or_else(|| param_value(entry, "network"))
        .map(|v| v.to_ascii_lowercase())
}

/// The vmess alter id under both spellings (`aid` in URIs and vmess JSON,
/// `alterId` in Clash YAML), as the one type both encoders emit.
///
/// u64, with a negative value read as 0: the Clash encoder parsed `i64` and
/// emitted the negative number verbatim while the sing-box encoder read
/// `u64` and silently zeroed the field, so the two outputs disagreed for one
/// proxy. (An earlier `as u16` cast truncated 65536 to 0 on the sing-box
/// side; the wide type keeps that from coming back.)
pub(crate) fn alter_id(entry: &crate::models::ProxyEntry) -> u64 {
    param_value(entry, "aid")
        .or_else(|| param_value(entry, "alterId"))
        .and_then(|v| match v.parse::<i64>() {
            Ok(n) => u64::try_from(n).ok(),
            // Beyond i64's range a u64 read still succeeds.
            Err(_) => v.parse::<u64>().ok(),
        })
        .unwrap_or(0)
}

/// The `method:password` of an ss credential.
///
/// A missing or empty method is not a cipher mihomo or sing-box can read:
/// the default carries it and what follows the slot stays the password, so
/// a leading `:` never renders an empty `cipher`/`method`. The colon-less
/// fallback only catches rows predating the parse-time canonicalization
/// (see `parsers::clash` `SS_SPEC`).
pub(crate) fn split_ss_credential(credential: &str) -> (&str, &str) {
    match credential.split_once(':') {
        Some((method, password)) if !method.is_empty() => (method, password),
        _ => match credential.rsplit_once(':') {
            Some((_, password)) => (crate::models::DEFAULT_SS_CIPHER, password),
            None => (crate::models::DEFAULT_SS_CIPHER, credential),
        },
    }
}

/// The `user:password` of a socks5 credential: either part may be empty
/// (`":pw"` keeps only the password), and a colon-less credential is all
/// username — no password is invented for it.
pub(crate) fn split_user_password(credential: &str) -> (&str, &str) {
    credential.split_once(':').unwrap_or((credential, ""))
}

/// One name-setting operation over the two value types the encoders emit:
/// the encode skeleton owns the deduplicated name, and each value type
/// keeps it under its own key (`name` for Clash, `tag` for sing-box) in the
/// place the mapper put the entry's original one.
pub(crate) trait Rename {
    fn rename(&mut self, key: &str, name: &str);
}

impl Rename for serde_norway::Value {
    fn rename(&mut self, key: &str, name: &str) {
        if let Some(mapping) = self.as_mapping_mut() {
            mapping.insert(
                serde_norway::Value::String(key.into()),
                serde_norway::Value::String(name.into()),
            );
        }
    }
}

impl Rename for serde_json::Value {
    fn rename(&mut self, key: &str, name: &str) {
        if let Some(object) = self.as_object_mut() {
            object.insert(key.into(), serde_json::Value::String(name.into()));
        }
    }
}

/// The shared skeleton of the structured encoders: keep the entries the
/// mapper can express, suffix duplicate names among them, and hand the
/// mapped values to the format-specific serializer.
///
/// The mapper is the single source of truth on what the format can express:
/// an entry it cannot map is skipped here and counted, so no second list of
/// schemes can drift from the encoders. The two aggregated signals land in
/// tracing — how many entries the format could not carry, and how many
/// names a « (2)» suffix changed.
pub(crate) fn encode_entries<V: Rename>(
    entries: &[ProxyEntry],
    key: &str,
    mut mapper: impl FnMut(&ProxyEntry) -> Option<V>,
) -> Vec<V> {
    let mut mapped: Vec<Option<V>> = entries.iter().map(&mut mapper).collect();
    let kept: Vec<usize> = (0..entries.len())
        .filter(|&i| mapped[i].is_some())
        .collect();
    if kept.len() < entries.len() {
        tracing::debug!(
            total = entries.len(),
            skipped = entries.len() - kept.len(),
            "encode skipped unsupported schemes"
        );
    }
    // The names are deduplicated among the kept entries only: an
    // unsupported entry consumes no name slot.
    let names = dedupe_names(kept.iter().map(|&i| entries[i].name.as_str()));
    let mut renamed = 0;
    for (i, name) in kept.iter().zip(&names) {
        if entries[*i].name != *name {
            renamed += 1;
        }
    }
    if renamed > 0 {
        tracing::debug!(
            entries = kept.len(),
            renamed = renamed,
            "duplicate names suffixed"
        );
    }
    kept.into_iter()
        .zip(names)
        .map(|(i, name)| {
            let mut value = mapped[i]
                .take()
                .expect("a kept entry carries a mapped value");
            if name != entries[i].name {
                value.rename(key, &name);
            }
            value
        })
        .collect()
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
            bare: false,
        };
        let entry = |params: Vec<Param>| crate::models::ProxyEntry {
            scheme: crate::models::Scheme::Trojan,
            name: "n".into(),
            host: "h.example.com".into(),
            port: 443,
            credential: "c".into(),
            params,
            raw_path: String::new(),
            raw_line: String::new(),
            canonical: None,
        };
        assert!(is_insecure(&entry(vec![param("allowInsecure", "1")])));
        assert!(is_insecure(&entry(vec![param("insecure", "true")])));
        assert!(is_insecure(&entry(vec![param(
            "skip-cert-verify",
            " TRUE "
        )])));
        assert!(is_insecure(&entry(vec![param("allow_insecure", "1")])));
        // The yes/on spellings the shared toggle vocabulary accepts: a
        // `allowInsecure=yes` node must be emitted with the insecure marker
        // like an `allowInsecure=1` one, not silently secured on output.
        assert!(is_insecure(&entry(vec![param("allowInsecure", "yes")])));
        assert!(is_insecure(&entry(vec![param("skip-cert-verify", "on")])));
        assert!(!is_insecure(&entry(vec![param("allowInsecure", "0")])));
        assert!(!is_insecure(&entry(vec![param("allow_insecure", "false")])));
        assert!(!is_insecure(&entry(vec![param("insecure", "no")])));
        assert!(!is_insecure(&entry(vec![param("sni", "example.com")])));
        assert!(!is_insecure(&entry(vec![])));
    }
}

/// Test helpers shared by the two encoder test modules and the agreement
/// tests below: entry construction, raw-line parsing, base64, and field
/// access over the two serde value types the encoders emit.
#[cfg(test)]
pub(crate) mod test_util {
    use crate::models::{Param, ProxyEntry, Scheme};

    /// A minimal entry: `example.com:443`, the given credential and params.
    pub(crate) fn entry(scheme: Scheme, credential: &str, params: &[(&str, &str)]) -> ProxyEntry {
        ProxyEntry {
            scheme,
            name: "proxy".into(),
            host: "example.com".into(),
            port: 443,
            credential: credential.into(),
            params: params
                .iter()
                .map(|(k, v)| Param {
                    key: (*k).into(),
                    value: (*v).into(),
                    known: true,
                    bare: false,
                })
                .collect(),
            raw_path: String::new(),
            raw_line: String::new(),
            canonical: None,
        }
    }

    /// Parse a raw subscription line into an entry (panics on failure).
    pub(crate) fn parse(line: &str) -> ProxyEntry {
        match crate::parsers::parse_line(line) {
            crate::parsers::LineOutcome::Parsed(entry) => entry,
            other => panic!("expected parsed entry, got {other:?}"),
        }
    }

    /// Unpadded standard base64, for vmess JSON payloads and ss userinfo.
    pub(crate) fn b64(bytes: &[u8]) -> String {
        base64::Engine::encode(&base64::engine::general_purpose::STANDARD_NO_PAD, bytes)
    }

    /// Field access over the two serde value types the encoders emit: the
    /// Clash tests read a `serde_norway` mapping, the sing-box tests a
    /// `serde_json` object, and the same assertions run against both.
    pub(crate) trait Fields: Sized {
        /// The value under `key`, for the value type the encoder emits.
        fn field<'a>(&'a self, key: &str) -> Option<&'a Self>;

        /// The string value of this value (the inherent `as_str` of each
        /// type, renamed so the trait never shadows it).
        fn str_value(&self) -> Option<&str>;

        /// The string under `key`.
        fn str_field(&self, key: &str) -> Option<&str> {
            self.field(key).and_then(Self::str_value)
        }
    }

    impl Fields for serde_norway::Value {
        fn field<'a>(&'a self, key: &str) -> Option<&'a Self> {
            self.as_mapping().and_then(|m| m.get(key))
        }

        fn str_value(&self) -> Option<&str> {
            self.as_str()
        }
    }

    impl Fields for serde_json::Value {
        fn field<'a>(&'a self, key: &str) -> Option<&'a Self> {
            self.as_object().and_then(|m| m.get(key))
        }

        fn str_value(&self) -> Option<&str> {
            self.as_str()
        }
    }
}

/// The two encoders must describe the same node.
///
/// The review's acceptance check is that they agree on whether a node
/// needs TLS and on the transport they emit: a subscriber who moves a
/// profile from one format to the other must not get a different node.
#[cfg(test)]
mod agreement {
    use super::{clash, singbox, test_util};
    use crate::models::{OutputFormat, ProxyEntry, Scheme};

    fn entry(scheme: Scheme, params: &[(&str, &str)]) -> ProxyEntry {
        test_util::entry(scheme, "secret", params)
    }

    /// Whether the node is TLS-wrapped, as each encoder says it.
    ///
    /// The Clash output carries an explicit `tls` toggle; the trojan
    /// protocol is TLS by definition and mihomo has no toggle for it, so
    /// the trojan node counts as wrapped on that side too.
    fn tls(entry: &ProxyEntry) -> (bool, bool) {
        let clash = clash::entry_to_clash(entry).expect("clash output");
        let singbox = singbox::entry_to_outbound(entry).expect("sing-box output");
        (
            clash.get("tls").and_then(|v| v.as_bool()).unwrap_or(false)
                || entry.scheme == Scheme::Trojan,
            singbox.get("tls").is_some(),
        )
    }

    /// The transport of the node, in the vocabulary both encoders share.
    ///
    /// mihomo spells HTTP/2 `h2` and sing-box `http`; sing-box has a
    /// transport of its own for the HTTP-upgrade WebSocket, which mihomo
    /// spells `ws` plus a flag.
    fn transport(entry: &ProxyEntry) -> (Option<String>, Option<String>) {
        let clash = clash::entry_to_clash(entry).expect("clash output");
        let singbox = singbox::entry_to_outbound(entry).expect("sing-box output");
        let network = clash
            .get("network")
            .and_then(|v| v.as_str())
            .map(|name| match name {
                "h2" => "http".to_string(),
                other => other.to_string(),
            });
        let transport = singbox
            .get("transport")
            .and_then(|t| t.get("type"))
            .and_then(|v| v.as_str())
            .map(|name| match name {
                "httpupgrade" => "ws".to_string(),
                other => other.to_string(),
            });
        (network, transport)
    }

    #[test]
    fn both_encoders_agree_on_tls() {
        for entry in [
            entry(
                Scheme::Vless,
                &[("security", "tls"), ("sni", "s.example.com")],
            ),
            entry(
                Scheme::Vless,
                &[("security", "none"), ("sni", "s.example.com")],
            ),
            entry(Scheme::Vless, &[("sni", "s.example.com")]),
            entry(Scheme::Vless, &[("pbk", "key"), ("sid", "short")]),
            entry(
                Scheme::Vless,
                &[("reality-opts", "public-key: key\nshort-id: short")],
            ),
            entry(Scheme::Vless, &[("tls", "false"), ("sni", "s.example.com")]),
            entry(Scheme::Vmess, &[("tls", "tls")]),
            entry(Scheme::Vmess, &[("tls", "")]),
            entry(Scheme::Trojan, &[("sni", "s.example.com")]),
            entry(Scheme::Trojan, &[]),
        ] {
            let (clash_tls, singbox_tls) = tls(&entry);
            assert_eq!(
                clash_tls, singbox_tls,
                "the encoders disagree about TLS for {entry:?}"
            );
        }
    }

    /// The alter id is read by the shared helper with one type for both
    /// encoders: a negative value used to be emitted verbatim by the Clash
    /// writer (`i64`) and read as 0 by the sing-box one (`u64`).
    #[test]
    fn a_negative_aid_reads_as_zero_in_both_encoders() {
        let e = entry(Scheme::Vmess, &[("aid", "-5")]);
        let clash = clash::entry_to_clash(&e).expect("clash output");
        assert_eq!(clash.get("alterId").and_then(|v| v.as_u64()), Some(0));
        let singbox = singbox::entry_to_outbound(&e).expect("sing-box output");
        assert_eq!(singbox.get("alter_id").and_then(|v| v.as_u64()), Some(0));
    }

    #[test]
    fn both_encoders_agree_on_the_transport() {
        for entry in [
            entry(Scheme::Vless, &[("type", "ws"), ("path", "/ws")]),
            entry(Scheme::Vless, &[("type", "grpc"), ("serviceName", "svc")]),
            entry(Scheme::Vless, &[("type", "h2"), ("host", "h.example.com")]),
            entry(Scheme::Vless, &[("type", "http"), ("path", "/h2")]),
            entry(
                Scheme::Vless,
                &[("type", "tcp"), ("headertype", "http"), ("path", "/h")],
            ),
            entry(Scheme::Vless, &[("type", "httpupgrade"), ("path", "/up")]),
            entry(Scheme::Vmess, &[("net", "ws"), ("path", "/ws")]),
            entry(Scheme::Vless, &[("type", "tcp")]),
        ] {
            let (clash, singbox) = transport(&entry);
            assert_eq!(
                clash, singbox,
                "the encoders disagree about the transport for {entry:?}"
            );
        }
    }

    #[test]
    fn both_encoders_agree_on_the_transport_settings() {
        let ws_entry = entry(
            Scheme::Vless,
            &[("type", "ws"), ("path", "/ws"), ("host", "ws.example.com")],
        );
        let clash = clash::entry_to_clash(&ws_entry).expect("clash output");
        let singbox = singbox::entry_to_outbound(&ws_entry).expect("sing-box output");
        let ws = clash.get("ws-opts").expect("ws-opts").as_mapping().unwrap();
        let transport = singbox.get("transport").expect("transport");
        assert_eq!(
            ws.get(serde_norway::Value::from("path"))
                .and_then(|v| v.as_str()),
            transport.get("path").and_then(|v| v.as_str())
        );
        let headers = ws
            .get(serde_norway::Value::from("headers"))
            .unwrap()
            .as_mapping()
            .unwrap();
        assert_eq!(
            headers
                .get(serde_norway::Value::from("Host"))
                .and_then(|v| v.as_str()),
            transport
                .get("headers")
                .and_then(|h| h.get("Host"))
                .and_then(|v| v.as_str())
        );

        // The gRPC service name travels under two names.
        let grpc_entry = entry(Scheme::Vless, &[("type", "grpc"), ("serviceName", "svc")]);
        let clash = clash::entry_to_clash(&grpc_entry).expect("clash output");
        let singbox = singbox::entry_to_outbound(&grpc_entry).expect("sing-box output");
        let grpc = clash
            .get("grpc-opts")
            .expect("grpc-opts")
            .as_mapping()
            .unwrap();
        assert_eq!(
            grpc.get(serde_norway::Value::from("grpc-service-name"))
                .and_then(|v| v.as_str()),
            singbox
                .get("transport")
                .and_then(|t| t.get("service_name"))
                .and_then(|v| v.as_str())
        );
    }

    #[test]
    fn an_unknown_network_is_a_documented_difference() {
        // sing-box has a closed set of transport types: a transport it does
        // not know makes the whole config fail to start, so it is left out.
        // mihomo may still understand the name, so the Clash writer passes
        // it through. The difference is deliberate, and the two documents
        // are not meant to be identical for such a node.
        let entry = entry(Scheme::Vless, &[("type", "xhttp"), ("path", "/x")]);
        let (clash, singbox) = transport(&entry);
        assert_eq!(clash.as_deref(), Some("xhttp"));
        assert_eq!(singbox, None);
    }

    /// The skipped count the served response reports must be the number
    /// of entries the encoder really left out, not a second list of
    /// schemes that could drift from the encoders'.
    #[test]
    fn the_skipped_count_matches_what_the_encoders_drop() {
        let entries = vec![
            entry(Scheme::Vless, &[]),
            entry(Scheme::Tuic, &[]),
            entry(Scheme::Vmess, &[]),
            entry(Scheme::Snell, &[]),
        ];
        let clash_doc: serde_norway::Value =
            serde_norway::from_str(&clash::encode_clash(&entries)).expect("clash YAML");
        let clash_kept = clash_doc["proxies"].as_sequence().expect("proxies").len();
        let singbox_doc: serde_json::Value =
            serde_json::from_str(&singbox::encode_singbox(&entries)).expect("sing-box JSON");
        let singbox_kept = singbox_doc["outbounds"]
            .as_array()
            .expect("outbounds")
            .len();

        assert_eq!(
            super::skipped_count(OutputFormat::Clash, &entries),
            entries.len() - clash_kept
        );
        assert_eq!(
            super::skipped_count(OutputFormat::SingBox, &entries),
            entries.len() - singbox_kept
        );
        // The plain formats carry every scheme.
        assert_eq!(super::skipped_count(OutputFormat::UriList, &entries), 0);
        assert_eq!(super::skipped_count(OutputFormat::Base64, &entries), 0);
    }
}
