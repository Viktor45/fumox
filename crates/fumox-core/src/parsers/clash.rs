//! Clash (mihomo) YAML subscription input.
//!
//! Clash subscriptions carry proxies as structured YAML items under the
//! `proxies:` key. Only the proxy list is consumed; proxy groups and rules
//! are irrelevant to Fumox. Supported item types: `ss`, `trojan`, `vmess`,
//! `hysteria2`, `vless`, `socks5`, items of any other type are skipped and
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
    /// Whether an absent *first* credential field keeps its empty slot.
    ///
    /// It must when every part is optional, because the output writers
    /// skip an empty part and read a colon-less credential as no
    /// credential at all (socks5 `username`/`password`). It must not when
    /// the first part is a method with a default: the shadowsocks writers
    /// take the default only for a colon-less credential and would emit an
    /// empty cipher for `":pw"`.
    optional_credential_fields: bool,
    /// Lower-cased Clash field names recognized as defined parameters.
    known_fields: &'static [&'static str],
}

const SS_SPEC: ClashTypeSpec = ClashTypeSpec {
    scheme: Scheme::Ss,
    credential_fields: &["cipher", "password"],
    optional_credential_fields: false,
    known_fields: &["udp", "plugin", "plugin-opts"],
};

const TROJAN_SPEC: ClashTypeSpec = ClashTypeSpec {
    scheme: Scheme::Trojan,
    credential_fields: &["password"],
    optional_credential_fields: false,
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
    optional_credential_fields: false,
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
    optional_credential_fields: false,
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
    optional_credential_fields: false,
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
    // Every part is optional: the writers skip an empty one.
    optional_credential_fields: true,
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
    // Alias references are refused before parsing: the whole payload is
    // attacker-controlled feed content and `serde_norway` re-materializes
    // the anchor's subtree for every reference, an alias bomb amplifies
    // quadratic memory out of a small payload (see `reject_yaml_aliases`).
    super::reject_yaml_aliases(payload).map_err(|e| format!("clash: {e}"))?;
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

    // The credential fields are joined in their declared order, which is
    // the only contract the output writers have: they split on `:` and
    // read a colon-less credential as "no credential at all".
    //   - an absent field *after* the first present one always keeps its
    //     empty slot, or the fields in front of it shift left and are
    //     lost: a socks5 item with only `username` must store
    //     `onlyuser:`, not `onlyuser`;
    //   - an absent *leading* field keeps its slot only when every part
    //     is optional (`optional_credential_fields`), because the writers
    //     then skip the empty part. Shadowsocks reads the first part as
    //     the cipher and takes its default only for a colon-less
    //     credential, so there an absent leading field is dropped and an
    //     ss item with only `password` stores `pw`;
    //   - with nothing present the credential stays empty, so a
    //     single-field scheme without its secret emits no userinfo.
    let fields: Vec<Option<String>> = spec
        .credential_fields
        .iter()
        .map(|field| map.get(field).map(yaml_to_string))
        .collect();
    let first = if spec.optional_credential_fields {
        0
    } else {
        fields.iter().position(Option::is_some).unwrap_or(0)
    };
    let credential = if fields.iter().all(Option::is_none) {
        String::new()
    } else {
        fields[first..]
            .iter()
            .map(|value| value.as_deref().unwrap_or_default())
            .collect::<Vec<_>>()
            .join(":")
    };

    // A YAML scalar may legally contain a line break, but the URI
    // serializers emit these two fields verbatim, one would split this proxy
    // into several output lines and smuggle a foreign scheme past the
    // source's protocol allowlist. Reject the item; the caller counts it.
    // Parameter values are exempt: Clash keeps structured blocks (`ws-opts`,
    // `reality-opts`, …) as multi-line YAML text, so they are sanitized at
    // serialization time instead.
    super::reject_line_breaks("clash: server", &host)?;
    super::reject_line_breaks("clash: credential", &credential)?;

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
    if params.len() > super::uri::MAX_QUERY_PARAMS {
        return Err(format!(
            "clash: item has {} parameters, over the {} cap",
            params.len(),
            super::uri::MAX_QUERY_PARAMS
        ));
    }
    // Field-size cap: Clash params
    // bypass `parse_query`, so the byte cap is enforced here.
    for param in &params {
        if param.key.len() > super::uri::MAX_PARAM_BYTES
            || param.value.len() > super::uri::MAX_PARAM_BYTES
        {
            return Err(format!(
                "clash: field over the {}-byte cap",
                super::uri::MAX_PARAM_BYTES
            ));
        }
    }

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

    /// `credential_fields` are joined positionally, so an absent field
    /// must keep its empty slot. A socks5 item carrying only `username`
    /// was stored as `onlyuser`, a string the output writers — which
    /// split on `:` — read as no credentials at all.
    #[test]
    fn an_absent_credential_field_keeps_its_slot() {
        let yaml =
            "proxies:\n  - {name: s, type: socks5, server: h, port: 1080, username: onlyuser}\n";
        let result = parse_payload(yaml).unwrap();
        assert_eq!(result.entries[0].credential, "onlyuser:");
    }

    /// A leading absent field must not leave an empty slot: the output
    /// writers split on `:` and would read `":pw"` as an empty cipher. A
    /// trailing one must keep its slot, or the writers lose the field in
    /// front of it (`onlyuser` carries no password to recover, and no
    /// username either once the split fails).
    #[test]
    fn a_missing_cipher_keeps_the_password_usable() {
        let yaml = "proxies:\n  - {name: s, type: ss, server: h, port: 8388, password: pw}\n";
        let result = parse_payload(yaml).unwrap();
        assert_eq!(result.entries[0].credential, "pw");
        // The writers fall back to a default method only for a
        // colon-less credential, so this is the shape they can use.
        let clash = crate::formats::clash::entry_to_clash(&result.entries[0]).unwrap();
        assert_eq!(
            clash.get("cipher").and_then(|v| v.as_str()),
            Some("chacha20-ietf-poly1305")
        );
        assert_eq!(clash.get("password").and_then(|v| v.as_str()), Some("pw"));
    }

    /// The mirror of the case above: a socks5 item carrying only a
    /// `password` must keep its empty leading slot, because both writers
    /// skip empty parts (`both parts are optional`, formats/clash.rs:136)
    /// while a colon-less credential is read as no credentials at all.
    #[test]
    fn a_password_only_socks5_keeps_its_credential() {
        let yaml =
            "proxies:\n  - {name: s, type: socks5, server: h, port: 1080, password: onlypass}\n";
        let result = parse_payload(yaml).unwrap();
        let e = &result.entries[0];
        assert_eq!(e.credential, ":onlypass");

        let clash = crate::formats::clash::entry_to_clash(e).unwrap();
        assert!(clash.get("username").is_none());
        assert_eq!(
            clash.get("password").and_then(|v| v.as_str()),
            Some("onlypass")
        );
        let singbox = crate::formats::singbox::entry_to_outbound(e).unwrap();
        assert!(singbox.get("username").is_none());
        assert_eq!(
            singbox.get("password").and_then(|v| v.as_str()),
            Some("onlypass")
        );
    }

    #[test]
    fn malformed_items_are_counted_not_fatal() {
        let yaml = "proxies:\n  - name: broken\n    type: ss\n    server: h\n  - {type: trojan, server: h, port: 443, password: p}\n";
        let result = parse_payload(yaml).unwrap();
        assert_eq!(result.invalid, 1); // first item: no port
        assert_eq!(result.entries.len(), 1);
    }
}
