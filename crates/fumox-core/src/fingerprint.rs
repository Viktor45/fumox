//! Proxy fingerprinting — the deduplication key (`proxies.fingerprint`).
//!
//! ```text
//! fingerprint = sha256(
//!     scheme "|" normalize(host) "|" port "|" credential "|" canonical(security_params)
//! )
//! ```
//!
//! The display name and cosmetic parameters (advertising tags, bandwidth
//! caps, timestamps) are deliberately excluded, so the same server advertised
//! under different names collapses into a single row. `fingerprint` is UNIQUE
//! in the schema, which makes reconciliation a natural upsert.

use crate::models::ProxyEntry;
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
    // cipher / credentials extras
    "encryption",
    "scy",
    "obfs",
    "obfs-password",
    "congestion_control",
    "aid",
    // wire encoding
    "packetencoding",
    // cert-verification toggles (aliases, normalized below)
    "insecure",
    "allowinsecure",
    "skip-cert-verify",
    // hysteria2 / quic extras
    "servicename",
];

/// Compute the stable deduplication fingerprint of a proxy entry.
pub fn fingerprint(entry: &ProxyEntry) -> String {
    let mut hasher = Sha256::new();
    hasher.update(entry.scheme.as_str().as_bytes());
    hasher.update(b"|");
    hasher.update(normalize_host(&entry.host).as_bytes());
    hasher.update(b"|");
    hasher.update(entry.port.to_string().as_bytes());
    hasher.update(b"|");
    hasher.update(entry.credential.as_bytes());
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

/// Canonical form of the security-relevant parameters: keys lower-cased,
/// insecure-aliases merged, pairs sorted and joined with `&`.
fn canonical_security_params(entry: &ProxyEntry) -> String {
    let mut pairs: Vec<(String, String)> = entry
        .params
        .iter()
        .filter_map(|param| {
            let key = param.key.to_ascii_lowercase();
            if !SECURITY_PARAMS.contains(&key.as_str()) {
                return None;
            }
            normalize_insecure_alias(&key, &param.value)
        })
        .collect();
    pairs.sort();
    pairs
        .iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join("&")
}

/// Merge the certificate-verification spellings (`insecure`, `allowInsecure`,
/// `skip-cert-verify`) into a single canonical `insecure` flag.
///
/// A falsy or absent toggle means the same thing (verification on), so falsy
/// values are dropped entirely — `allowInsecure=0`, `insecure=false` and no
/// toggle at all produce identical fingerprints.
fn normalize_insecure_alias(key: &str, value: &str) -> Option<(String, String)> {
    if matches!(key, "insecure" | "allowinsecure" | "skip-cert-verify") {
        let truthy = matches!(value.trim().to_ascii_lowercase().as_str(), "1" | "true");
        return truthy.then(|| ("insecure".to_string(), "1".to_string()));
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
        assert_eq!(fingerprint(&a), fingerprint(&b));
        assert_eq!(fingerprint(&b), fingerprint(&c));
    }

    #[test]
    fn falsy_insecure_equals_absent() {
        let absent = entry("n", "h", vec![]);
        let zero = entry("n", "h", vec![param("allowInsecure", "0")]);
        let false_ = entry("n", "h", vec![param("skip-cert-verify", "false")]);
        assert_eq!(fingerprint(&absent), fingerprint(&zero));
        assert_eq!(fingerprint(&absent), fingerprint(&false_));

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
