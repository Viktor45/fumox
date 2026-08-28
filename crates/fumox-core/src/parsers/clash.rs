//! Clash (mihomo) YAML subscription input.
//!
//! Clash subscriptions carry proxies as structured YAML items under the
//! `proxies:` key. Only the proxy list is consumed; proxy groups and rules
//! are irrelevant to Fumox. Supported item types: `ss`, `trojan`, `vmess`,
//! `hysteria2`, `vless`, `socks5` — items of any other type are skipped and
//! counted, never fatal (log-and-skip principle).
//!
//! Entries parsed from Clash have no source line; their `raw_line` stays
//! empty and output serialization falls back to the canonical URI form of
//! each scheme.

use crate::models::{Param, ProxyEntry, Scheme};
use serde_norway::Value;

/// Per-type knowledge for mapping Clash items onto [`ProxyEntry`].
struct ClashTypeSpec {
    scheme: Scheme,
    /// Credential fields in the order they are joined with `:`.
    credential_fields: &'static [&'static str],
    /// Lower-cased Clash field names recognized as defined parameters.
    known_fields: &'static [&'static str],
}

const SS_SPEC: ClashTypeSpec = ClashTypeSpec {
    scheme: Scheme::Ss,
    credential_fields: &["cipher", "password"],
    known_fields: &["udp", "plugin", "plugin-opts"],
};

const TROJAN_SPEC: ClashTypeSpec = ClashTypeSpec {
    scheme: Scheme::Trojan,
    credential_fields: &["password"],
    known_fields: &[
        "sni",
        "skip-cert-verify",
        "alpn",
        "network",
        "ws-path",
        "ws-headers",
        "fingerprint",
        "udp",
    ],
};

const VMESS_SPEC: ClashTypeSpec = ClashTypeSpec {
    scheme: Scheme::Vmess,
    credential_fields: &["uuid"],
    known_fields: &[
        "alterid",
        "cipher",
        "tls",
        "skip-cert-verify",
        "servername",
        "network",
        "ws-path",
        "ws-headers",
        "ws-opts",
        "h2-opts",
        "http-opts",
        "grpc-service-name",
        "fingerprint",
        "client-fingerprint",
        "udp",
    ],
};

const HYSTERIA2_SPEC: ClashTypeSpec = ClashTypeSpec {
    scheme: Scheme::Hysteria2,
    credential_fields: &["password"],
    known_fields: &[
        "sni",
        "skip-cert-verify",
        "alpn",
        "obfs",
        "obfs-password",
        "fingerprint",
        "ports",
    ],
};

const VLESS_SPEC: ClashTypeSpec = ClashTypeSpec {
    scheme: Scheme::Vless,
    credential_fields: &["uuid"],
    known_fields: &[
        "tls",
        "skip-cert-verify",
        "servername",
        "network",
        "ws-path",
        "ws-headers",
        "ws-opts",
        "flow",
        "reality-opts",
        "client-fingerprint",
        "fingerprint",
        "alpn",
        "udp",
    ],
};

const SOCKS5_SPEC: ClashTypeSpec = ClashTypeSpec {
    scheme: Scheme::Socks5,
    credential_fields: &["username", "password"],
    known_fields: &["udp"],
};

/// Fields consumed structurally and never duplicated into params.
const STRUCTURAL_FIELDS: &[&str] = &["name", "type", "server", "port"];

/// Result of parsing a Clash payload.
pub struct ClashParseResult {
    pub entries: Vec<ProxyEntry>,
    /// Items whose `type` is not supported by the MVP parser set.
    pub unsupported: usize,
    /// Items missing required fields (server/port/type).
    pub invalid: usize,
}

/// Parse a full Clash YAML subscription payload.
pub fn parse_payload(payload: &str) -> Result<ClashParseResult, String> {
    let root: Value =
        serde_norway::from_str(payload).map_err(|e| format!("clash: invalid YAML: {e}"))?;
    let proxies = root
        .get("proxies")
        .and_then(Value::as_sequence)
        .ok_or("clash: no `proxies` list")?;

    let mut result = ClashParseResult {
        entries: Vec::new(),
        unsupported: 0,
        invalid: 0,
    };
    for item in proxies {
        match parse_item(item) {
            Ok(Some(entry)) => result.entries.push(entry),
            Ok(None) => result.unsupported += 1,
            Err(message) => {
                tracing::debug!(error = %message, "skipping malformed clash proxy item");
                result.invalid += 1;
            }
        }
    }
    Ok(result)
}

/// Parse one Clash proxy item. `Ok(None)` means an unsupported type.
fn parse_item(item: &Value) -> Result<Option<ProxyEntry>, String> {
    let map = item
        .as_mapping()
        .ok_or_else(|| "clash: proxy item is not a mapping".to_string())?;

    let type_name = string_field(map, "type")?;
    let spec = match type_name.as_str() {
        "ss" => &SS_SPEC,
        "trojan" => &TROJAN_SPEC,
        "vmess" => &VMESS_SPEC,
        "hysteria2" => &HYSTERIA2_SPEC,
        "vless" => &VLESS_SPEC,
        "socks5" => &SOCKS5_SPEC,
        _ => return Ok(None),
    };

    let name = map
        .get("name")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    let host = string_field(map, "server")?;
    let port = numeric_field(map, "port")?;

    let credential_parts: Vec<String> = spec
        .credential_fields
        .iter()
        .filter_map(|field| map.get(field).map(yaml_to_string))
        .collect();
    let credential = credential_parts.join(":");

    // Everything not consumed structurally or as the credential is kept as
    // a pass-through parameter, so no Clash option is ever lost.
    let params: Vec<Param> = map
        .iter()
        .filter(|(key, _)| {
            let key = key.as_str().unwrap_or_default();
            !STRUCTURAL_FIELDS.contains(&key) && !spec.credential_fields.contains(&key)
        })
        .map(|(key, value)| {
            let key = key.as_str().unwrap_or_default().to_string();
            let lower = key.to_ascii_lowercase();
            Param {
                known: spec.known_fields.contains(&lower.as_str()),
                key,
                value: yaml_to_string(value),
            }
        })
        .collect();

    Ok(Some(ProxyEntry {
        scheme: spec.scheme,
        name,
        host,
        port,
        credential,
        params,
        raw_path: String::new(),
        raw_line: String::new(),
    }))
}

fn string_field(map: &serde_norway::Mapping, key: &str) -> Result<String, String> {
    map.get(key)
        .and_then(Value::as_str)
        .map(str::to_string)
        .ok_or_else(|| format!("clash: missing field {key:?}"))
}

fn numeric_field(map: &serde_norway::Mapping, key: &str) -> Result<u16, String> {
    match map.get(key) {
        Some(Value::Number(n)) => n
            .as_u64()
            .and_then(|v| u16::try_from(v).ok())
            .ok_or_else(|| format!("clash: port out of range: {n}")),
        Some(Value::String(s)) => s
            .trim()
            .parse::<u16>()
            .map_err(|_| format!("clash: invalid port string: {s:?}")),
        _ => Err(format!("clash: missing field {key:?}")),
    }
}

fn yaml_to_string(value: &Value) -> String {
    match value {
        Value::String(s) => s.clone(),
        Value::Number(n) => n.to_string(),
        Value::Bool(b) => b.to_string(),
        Value::Null => String::new(),
        other => serde_norway::to_string(other)
            .unwrap_or_default()
            .trim()
            .to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"
mixed-port: 7890
proxies:
  - name: "🇩🇪 DE-ss"
    type: ss
    server: de.example.com
    port: 8388
    cipher: chacha20-ietf-poly1305
    password: s3cret
    udp: true
  - name: "hy2-node"
    type: hysteria2
    server: hy2.example.com
    port: 443
    password: hy2pass
    sni: hy2.example.com
    skip-cert-verify: true
    obfs: salamander
    obfs-password: of-pass
  - name: legacy-node
    type: snell
    server: 1.2.3.4
    port: 443
    psk: abc
proxy-groups:
  - name: auto
    type: url-test
    proxies: [hy2-node]
"#;

    #[test]
    fn parses_supported_items_and_skips_the_rest() {
        let result = parse_payload(SAMPLE).unwrap();
        assert_eq!(result.entries.len(), 2);
        assert_eq!(result.unsupported, 1); // snell
        assert_eq!(result.invalid, 0);

        let ss = &result.entries[0];
        assert_eq!(ss.scheme, Scheme::Ss);
        assert_eq!(ss.name, "🇩🇪 DE-ss");
        assert_eq!(ss.host, "de.example.com");
        assert_eq!(ss.port, 8388);
        assert_eq!(ss.credential, "chacha20-ietf-poly1305:s3cret");
        assert_eq!(ss.param("udp"), Some("true"));

        let hy2 = &result.entries[1];
        assert_eq!(hy2.scheme, Scheme::Hysteria2);
        assert_eq!(hy2.credential, "hy2pass");
        assert_eq!(hy2.param("obfs"), Some("salamander"));
        assert_eq!(hy2.param("skip-cert-verify"), Some("true"));
        assert!(hy2.params.iter().find(|p| p.key == "sni").unwrap().known);
    }

    #[test]
    fn payload_without_proxies_is_an_error() {
        assert!(parse_payload("mixed-port: 7890\n").is_err());
        assert!(parse_payload(":::").is_err());
    }

    #[test]
    fn malformed_items_are_counted_not_fatal() {
        let yaml = "proxies:\n  - name: broken\n    type: ss\n    server: h\n  - {type: trojan, server: h, port: 443, password: p}\n";
        let result = parse_payload(yaml).unwrap();
        assert_eq!(result.invalid, 1); // first item: no port
        assert_eq!(result.entries.len(), 1);
    }
}
