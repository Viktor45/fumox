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

use std::collections::{HashMap, HashSet};

pub(crate) use crate::params::{
    is_insecure, list as param_list, map_first, map_header, map_list, map_str,
    truthy as param_truthy, value as param_value,
};

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
        let entry = |params: Vec<Param>| crate::models::ProxyEntry {
            scheme: crate::models::Scheme::Trojan,
            name: "n".into(),
            host: "h.example.com".into(),
            port: 443,
            credential: "c".into(),
            params,
            raw_path: String::new(),
            raw_line: String::new(),
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

/// The two encoders must describe the same node.
///
/// The review's acceptance check is that they agree on whether a node
/// needs TLS and on the transport they emit: a subscriber who moves a
/// profile from one format to the other must not get a different node.
#[cfg(test)]
mod agreement {
    use super::{clash, singbox};
    use crate::models::{Param, ProxyEntry, Scheme};

    fn entry(scheme: Scheme, params: &[(&str, &str)]) -> ProxyEntry {
        ProxyEntry {
            scheme,
            name: "proxy".into(),
            host: "example.com".into(),
            port: 443,
            credential: "secret".into(),
            params: params
                .iter()
                .map(|(k, v)| Param {
                    key: (*k).into(),
                    value: (*v).into(),
                    known: true,
                })
                .collect(),
            raw_path: String::new(),
            raw_line: String::new(),
        }
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
}
