//! Proxy fingerprinting, the deduplication key (`proxies.fingerprint`).
//!
//! ```text
//! fingerprint = sha256(
//!     scheme "|" escape(normalize(host)) "|" port "|" escape(credential)
//!     "|" canonical(security_params)
//! )
//! ```
//!
//! Every attacker-controlled field is escaped: the host, the credential and
//! the parameter keys and values, so a separator byte coming from feed text
//! cannot move a field boundary inside the pre-image. The scheme and the port
//! are written as they are: a fixed enum literal and a number.
//!
//! The display name and cosmetic parameters (advertising tags, bandwidth
//! caps, timestamps) are deliberately excluded, so the same server advertised
//! under different names collapses into a single row. `fingerprint` is UNIQUE
//! in the schema, which makes reconciliation a natural upsert.

use crate::models::{ProxyEntry, Scheme};
use sha2::{Digest, Sha256};

/// Lower-cased parameter keys that change how a client must connect or
/// authenticate. Only these take part in the fingerprint; everything else is
/// cosmetic. The list covers the MVP schemes (vless, vmess, trojan, ss,
/// hysteria2, tuic, mieru, socks5, naive) and is checked case-insensitively
/// because real feeds mix spellings (`headerType` / `headertype`).
const SECURITY_PARAMS: &[&str] = &[
    // transport / TLS layer
    "security",
    "tls",
    "type",
    "net",
    "headertype",
    "mode",
    "path",
    "host",
    "alpn",
    // REALITY / TLS pinning
    "pbk",
    "publickey",
    "sid",
    "shortid",
    "fp",
    "utls",
    "sni",
    "flow",
    "pinsha256",
    // cipher / credentials extras
    "encryption",
    "scy",
    "obfs",
    "obfs-password",
    "congestion_control",
    "aid",
    // wire encoding
    "packetencoding",
    // cert-verification toggles (aliases, normalized below; the canonical
    // alias list lives in `models::INSECURE_ALIASES`)
    "insecure",
    "allowinsecure",
    "skip-cert-verify",
    "allow_insecure",
    // hysteria2 / quic extras
    "servicename",
    // Clash structured blocks, stored verbatim: they have no URI spelling
    // and each one changes how the client must connect. The Clash fields
    // that *do* have a URI spelling (`servername`, `network`, `ws-path`,
    // `client-fingerprint`, `grpc-service-name`, `fingerprint`) are folded
    // onto it by `canonical_key` and never reach this list under their own
    // name.
    "ws-headers",
    "ws-opts",
    "reality-opts",
];

/// Map a parameter key onto the spelling the fingerprint is keyed by.
///
/// Clash carries its own field names for fields every URI format spells the
/// same way. Left alone, the same node advertised as Clash YAML and as a URI
/// would get two different fingerprints and land in two rows, so the Clash
/// spelling is rewritten to the URI one before the security filter runs.
///
/// The transport is spelled per scheme: the vmess JSON and the sing-box native
/// form both call it `net`, while vless, trojan and the rest call it `type`.
/// Folding it onto one spelling for every scheme would split the vmess forms
/// from each other, so the target key depends on the scheme.
fn canonical_key(scheme: Scheme, key: &str) -> String {
    match key {
        "servername" => "sni",
        "network" if scheme == Scheme::Vmess => "net",
        "network" => "type",
        "ws-path" => "path",
        "client-fingerprint" => "fp",
        "grpc-service-name" => "servicename",
        // Clash's `fingerprint` is the certificate pin (`pinSHA256` in the
        // URI), not the uTLS client hello: that one is `client-fingerprint`.
        "fingerprint" => "pinsha256",
        other => other,
    }
    .to_string()
}

/// Compute the stable deduplication fingerprint of a proxy entry.
///
/// Every attacker-controlled field that reaches the pre-image: the host, the
/// credential and the parameter keys and values, is escaped, so a separator
/// byte inside one of them can never be read as a boundary. The scheme and
/// the port need no escaping: the scheme is a closed enum written as a fixed
/// literal, the port a number by type.
pub fn fingerprint(entry: &ProxyEntry) -> String {
    let mut hasher = Sha256::new();
    hasher.update(entry.scheme.as_str().as_bytes());
    hasher.update(b"|");
    hasher.update(escape(&normalize_host(&entry.host)).as_bytes());
    hasher.update(b"|");
    hasher.update(entry.port.to_string().as_bytes());
    hasher.update(b"|");
    hasher.update(escape(&entry.credential).as_bytes());
    hasher.update(b"|");
    hasher.update(canonical_security_params(entry).as_bytes());
    to_hex(&hasher.finalize())
}

/// Host normalization: lower-case, trailing dots stripped.
///
/// DNS names are case-insensitive and a trailing dot is the same zone, so
/// `Example.COM.` and `example.com` must deduplicate.
pub fn normalize_host(host: &str) -> String {
    host.to_ascii_lowercase().trim_end_matches('.').to_string()
}

/// Canonical form of the security-relevant parameters: keys lower-cased and
/// alias-mapped, insecure-aliases merged, pairs escaped, sorted and joined
/// with `&`.
fn canonical_security_params(entry: &ProxyEntry) -> String {
    let mut pairs: Vec<(String, String)> = entry
        .params
        .iter()
        .filter_map(|param| {
            let key = canonical_key(entry.scheme, &param.key.to_ascii_lowercase());
            if !SECURITY_PARAMS.contains(&key.as_str()) {
                return None;
            }
            normalize_insecure_alias(&key, &param.value)
        })
        .collect();
    pairs.sort();
    pairs
        .iter()
        .map(|(k, v)| format!("{}={}", escape(k), escape(v)))
        .collect::<Vec<_>>()
        .join("&")
}

/// Escape a key or value so the separators around it cannot be forged from
/// inside it.
///
/// Feed text is attacker-controlled and the values reach the pre-image
/// verbatim, so a raw separator byte would move a field boundary:
/// `path=/search` + `host=evil` and the single parameter `host=evil&path=/search`
/// would otherwise produce the same pre-image and the same fingerprint, and a
/// `|` inside a host or a credential would shift the top-level fields the same
/// way. Only bytes outside printable ASCII and the separators (plus `%`, so
/// escaping is reversible) are rewritten.
fn escape(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        match byte {
            b'%' => out.push_str("%25"),
            b'&' => out.push_str("%26"),
            b'=' => out.push_str("%3D"),
            b'|' => out.push_str("%7C"),
            0x21..=0x7e => out.push(byte as char),
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

/// Merge the certificate-verification spellings (`insecure`, `allowInsecure`,
/// `skip-cert-verify`, `allow_insecure`) into a single canonical `insecure`
/// flag.
///
/// A falsy or absent toggle means the same thing (verification on), so falsy
/// values are dropped entirely, `allowInsecure=0`, `insecure=false` and no
/// toggle at all produce identical fingerprints. Folding every spelling onto
/// one flag also lets the same server advertised with different toggle
/// spellings (say a tuic link's `allow_insecure` and a Clash document's
/// `skip-cert-verify`) land on one row.
fn normalize_insecure_alias(key: &str, value: &str) -> Option<(String, String)> {
    if crate::models::INSECURE_ALIASES.contains(&key) {
        return crate::models::is_truthy_toggle(value)
            .then(|| ("insecure".to_string(), "1".to_string()));
    }
    Some((key.to_string(), value.to_string()))
}

fn to_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{Param, Scheme};
    use sha2::{Digest, Sha256};

    fn entry(name: &str, host: &str, params: Vec<Param>) -> ProxyEntry {
        ProxyEntry {
            scheme: Scheme::Vless,
            name: name.to_string(),
            host: host.to_string(),
            port: 443,
            credential: "3e4d70e5-7ec9-48f9-a4e0-48c44c6063fd".to_string(),
            params,
            raw_path: String::new(),
            raw_line: String::new(),
        }
    }

    fn param(key: &str, value: &str) -> Param {
        Param {
            key: key.to_string(),
            value: value.to_string(),
            known: true,
        }
    }

    fn parse_one(line: &str) -> ProxyEntry {
        match crate::parsers::parse_line(line) {
            crate::parsers::LineOutcome::Parsed(entry) => entry,
            other => panic!("expected a parsed entry, got {other:?}"),
        }
    }

    #[test]
    fn name_is_excluded() {
        let a = entry("🇩🇪 Frankfurt | [BL]", "example.com", vec![]);
        let b = entry("completely different name", "example.com", vec![]);
        assert_eq!(fingerprint(&a), fingerprint(&b));
    }

    #[test]
    fn cosmetic_params_are_excluded() {
        let a = entry("n", "example.com", vec![param("telegram", "@channel")]);
        let b = entry("n", "example.com", vec![param("upmbps", "100")]);
        let c = entry("n", "example.com", vec![]);
        assert_eq!(fingerprint(&a), fingerprint(&c));
        assert_eq!(fingerprint(&b), fingerprint(&c));
    }

    #[test]
    fn security_params_are_included() {
        let a = entry("n", "example.com", vec![param("sni", "a.example.com")]);
        let b = entry("n", "example.com", vec![param("sni", "b.example.com")]);
        assert_ne!(fingerprint(&a), fingerprint(&b));
    }

    #[test]
    fn host_is_normalized() {
        let a = entry("n", "Example.COM.", vec![]);
        let b = entry("n", "example.com", vec![]);
        assert_eq!(fingerprint(&a), fingerprint(&b));
    }

    #[test]
    fn port_and_credential_are_sensitive() {
        let base = entry("n", "example.com", vec![]);
        let mut other_port = base.clone();
        other_port.port = 8443;
        assert_ne!(fingerprint(&base), fingerprint(&other_port));

        let mut other_cred = base.clone();
        other_cred.credential = "another-uuid".to_string();
        assert_ne!(fingerprint(&base), fingerprint(&other_cred));
    }

    #[test]
    fn scheme_is_sensitive() {
        let mut trojan = entry("n", "example.com", vec![]);
        trojan.scheme = Scheme::Trojan;
        let vless = entry("n", "example.com", vec![]);
        assert_ne!(fingerprint(&trojan), fingerprint(&vless));
    }

    #[test]
    fn insecure_aliases_collapse() {
        let a = entry("n", "h", vec![param("allowInsecure", "1")]);
        let b = entry("n", "h", vec![param("insecure", "true")]);
        let c = entry("n", "h", vec![param("skip-cert-verify", "1")]);
        let d = entry("n", "h", vec![param("allow_insecure", "1")]);
        assert_eq!(fingerprint(&a), fingerprint(&b));
        assert_eq!(fingerprint(&b), fingerprint(&c));
        // The underscore spelling of sing-box / tuic links dedupes with the
        // rest instead of contributing its own pre-image pair.
        assert_eq!(fingerprint(&c), fingerprint(&d));
    }

    #[test]
    fn falsy_insecure_equals_absent() {
        let absent = entry("n", "h", vec![]);
        let zero = entry("n", "h", vec![param("allowInsecure", "0")]);
        let false_ = entry("n", "h", vec![param("skip-cert-verify", "false")]);
        let underscore = entry("n", "h", vec![param("allow_insecure", "0")]);
        assert_eq!(fingerprint(&absent), fingerprint(&zero));
        assert_eq!(fingerprint(&absent), fingerprint(&false_));
        assert_eq!(fingerprint(&absent), fingerprint(&underscore));

        let truthy = entry("n", "h", vec![param("allowInsecure", "1")]);
        assert_ne!(fingerprint(&absent), fingerprint(&truthy));
    }

    #[test]
    fn param_key_case_is_ignored() {
        let a = entry(
            "n",
            "h",
            vec![param("headerType", "none"), param("SNI", "x")],
        );
        let b = entry(
            "n",
            "h",
            vec![param("headertype", "none"), param("sni", "x")],
        );
        assert_eq!(fingerprint(&a), fingerprint(&b));
    }

    #[test]
    fn canonical_order_is_stable() {
        // Different input order must not change the fingerprint.
        let a = entry(
            "n",
            "h",
            vec![param("type", "ws"), param("security", "none")],
        );
        let b = entry(
            "n",
            "h",
            vec![param("security", "none"), param("type", "ws")],
        );
        assert_eq!(fingerprint(&a), fingerprint(&b));
    }

    #[test]
    fn clash_spellings_are_security_relevant() {
        // Clash keeps its own field names; parsed verbatim they must still
        // reach the dedup key, or two nodes differing only in `servername`
        // collapse and the upsert overwrites one with the other.
        let yaml = concat!(
            "proxies:\n",
            "  - {name: a, type: vless, server: h.example.com, port: 443, uuid: u,",
            "     servername: a.example.com, network: ws, ws-path: /ws,",
            "     client-fingerprint: chrome, grpc-service-name: g}\n",
            "  - {name: b, type: vless, server: h.example.com, port: 443, uuid: u,",
            "     servername: b.example.com, network: ws, ws-path: /ws,",
            "     client-fingerprint: chrome, grpc-service-name: g}\n",
        );
        let parsed = crate::parsers::clash::parse_payload(yaml).unwrap();
        assert_eq!(parsed.entries.len(), 2);
        assert_ne!(
            fingerprint(&parsed.entries[0]),
            fingerprint(&parsed.entries[1])
        );
    }

    #[test]
    fn clash_structured_fields_are_security_relevant() {
        // `ws-headers`, `ws-opts` and `reality-opts` are YAML blocks with no
        // URI spelling; they are kept verbatim and are connection-defining.
        let yaml = concat!(
            "proxies:\n",
            "  - {name: a, type: vless, server: h.example.com, port: 443, uuid: u,",
            "     ws-headers: {Host: a.example.com}}\n",
            "  - {name: b, type: vless, server: h.example.com, port: 443, uuid: u,",
            "     ws-headers: {Host: b.example.com}}\n",
        );
        let parsed = crate::parsers::clash::parse_payload(yaml).unwrap();
        assert_ne!(
            fingerprint(&parsed.entries[0]),
            fingerprint(&parsed.entries[1])
        );

        let yaml = concat!(
            "proxies:\n",
            "  - {name: a, type: vless, server: h.example.com, port: 443, uuid: u,",
            "     reality-opts: {public-key: AAA}}\n",
            "  - {name: b, type: vless, server: h.example.com, port: 443, uuid: u,",
            "     reality-opts: {public-key: BBB}}\n",
        );
        let parsed = crate::parsers::clash::parse_payload(yaml).unwrap();
        assert_ne!(
            fingerprint(&parsed.entries[0]),
            fingerprint(&parsed.entries[1])
        );
    }

    #[test]
    fn clash_and_uri_spellings_agree() {
        // The same node advertised once as Clash YAML and once as a URI must
        // deduplicate together, so the Clash spelling has to canonicalize onto
        // the URI one rather than sitting beside it.
        let yaml = concat!(
            "proxies:\n",
            "  - {name: a, type: vless, server: h.example.com, port: 443, uuid: u,",
            "     network: ws, servername: a.example.com, client-fingerprint: chrome}\n",
        );
        let mut clash = crate::parsers::clash::parse_payload(yaml).unwrap().entries[0].clone();
        let crate::parsers::LineOutcome::Parsed(mut uri) = crate::parsers::parse_line(
            "vless://u@h.example.com:443?type=ws&sni=a.example.com&fp=chrome#a",
        ) else {
            panic!("expected a parsed vless entry");
        };
        clash.name = String::new();
        uri.name = String::new();
        assert_eq!(fingerprint(&clash), fingerprint(&uri));
    }

    #[test]
    fn cert_pin_is_security_relevant() {
        // The pinned certificate decides which servers the client accepts, so
        // two hysteria2 nodes pinning different certificates are different
        // nodes. Left out of the dedup key they shared one row and the
        // upsert silently overwrote one with the other.
        let uri_a = parse_one("hysteria2://pass@h.example.com:443?pinSHA256=AAAA");
        let uri_b = parse_one("hysteria2://pass@h.example.com:443?pinSHA256=BBBB");
        assert_ne!(fingerprint(&uri_a), fingerprint(&uri_b));

        // Clash spells the same field `fingerprint`; it must canonicalize
        // onto the URI spelling instead of sitting beside it, or a node
        // published in both formats lands in two rows.
        let yaml = concat!(
            "proxies:\n",
            "  - {name: a, type: hysteria2, server: h.example.com, port: 443,",
            "     password: pass, fingerprint: AAAA}\n",
            "  - {name: b, type: hysteria2, server: h.example.com, port: 443,",
            "     password: pass, fingerprint: BBBB}\n",
        );
        let parsed = crate::parsers::clash::parse_payload(yaml).unwrap();
        assert_eq!(parsed.entries.len(), 2);
        assert_ne!(
            fingerprint(&parsed.entries[0]),
            fingerprint(&parsed.entries[1])
        );
        assert_eq!(fingerprint(&parsed.entries[0]), fingerprint(&uri_a));
        assert_eq!(fingerprint(&parsed.entries[1]), fingerprint(&uri_b));
    }

    #[test]
    fn clash_and_uri_spellings_agree_for_vmess() {
        // vmess names the transport `net` in the URI JSON and sing-box native
        // form, `network` only in Clash. Folding Clash's spelling onto `type`
        // left the two forms as separate keys, so one vmess server published
        // as Clash YAML and as a vmess:// link got two fingerprints, two rows
        // and two copies in every subscription.
        let yaml = concat!(
            "proxies:\n",
            "  - {name: a, type: vmess, server: h.example.com, port: 443, uuid: u,",
            "     network: ws, servername: a.example.com}\n",
        );
        let mut clash = crate::parsers::clash::parse_payload(yaml).unwrap().entries[0].clone();
        let mut uri = parse_one(concat!(
            "vmess://eyJ2IjoiMiIsInBzIjoiYSIsImFkZCI6ImguZXhhbXBsZS5jb20iLCJwb3J0IjoiNDQz",
            "IiwiaWQiOiJ1IiwibmV0Ijoid3MiLCJzbmkiOiJhLmV4YW1wbGUuY29tIn0="
        ));
        clash.name = String::new();
        uri.name = String::new();
        assert_eq!(fingerprint(&clash), fingerprint(&uri));
    }

    #[test]
    fn separator_bytes_in_values_cannot_forge_a_pair() {
        // Without escaping, `path=/search` + `host=evil` and the single param
        // `host=evil&path=/search` are the same pre-image.
        let split = entry(
            "n",
            "h",
            vec![param("path", "/search"), param("host", "evil")],
        );
        let forged = entry("n", "h", vec![param("host", "evil&path=/search")]);
        assert_ne!(fingerprint(&split), fingerprint(&forged));

        let quoted = entry("n", "h", vec![param("host", "evil&host=other")]);
        let two = entry(
            "n",
            "h",
            vec![param("host", "evil"), param("host", "other")],
        );
        assert_ne!(fingerprint(&quoted), fingerprint(&two));
    }

    #[test]
    fn pipe_in_a_field_cannot_shift_the_pre_image_boundary() {
        // The pre-image is `scheme|host|port|credential|params`, and the host
        // and the credential reach it verbatim (parse_hostport and
        // split_userinfo keep them as written). A `|` inside either one moved
        // a field boundary, so two unrelated malformed lines hashed to the
        // same fingerprint and the upsert kept only the last of them.
        let first = parse_one("vless://x@a|443:1#one");
        let second = parse_one("vless://1|x@a:443#two");
        assert_eq!(first.host, "a|443");
        assert_eq!(first.port, 1);
        assert_eq!(first.credential, "x");
        assert_eq!(second.host, "a");
        assert_eq!(second.port, 443);
        assert_eq!(second.credential, "1|x");
        assert_ne!(fingerprint(&first), fingerprint(&second));

        // The value level behind it: a pipe inside a field is rewritten, and a
        // value without one is untouched, so the common case keeps the
        // documented pre-image byte for byte.
        assert_eq!(escape("a|443"), "a%7C443");
        assert_eq!(escape("1|x"), "1%7Cx");
        assert_eq!(escape("h.example.com"), "h.example.com");
    }

    #[test]
    fn matches_documented_formula() {
        // Lock the composition against accidental drift: the fingerprint must
        // equal sha256 over the documented preimage, field by field.
        let e = entry(
            "ignored",
            "Example.com.",
            vec![
                param("security", "reality"),
                param("pbk", "SbVKqWj1"),
                param("telegram", "@x"),
            ],
        );
        let mut hasher = Sha256::new();
        hasher.update(b"vless|example.com|443|3e4d70e5-7ec9-48f9-a4e0-48c44c6063fd|pbk=SbVKqWj1&security=reality");
        let expected = to_hex(&hasher.finalize());
        assert_eq!(fingerprint(&e), expected);
        assert_eq!(fingerprint(&e).len(), 64);
    }
}
