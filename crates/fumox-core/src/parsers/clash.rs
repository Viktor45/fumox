//! Clash (mihomo) YAML subscription input.
//!
//! Clash subscriptions carry proxies as structured YAML items under the
//! `proxies:` key. Only the proxy list is consumed; proxy groups and rules
//! are irrelevant to Fumox. Supported item types: `ss`, `trojan`, `vmess`,
//! `hysteria2`, `vless`, `socks5`, `snell`, `anytls`; items of any other
//! type are skipped and counted, never fatal (log-and-skip principle).
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
    /// credential at all (socks5 `username`/`password`). It must not for
    /// shadowsocks: a password-only item is canonicalized to
    /// `DEFAULT_SS_CIPHER:password` at parse time (see [`SS_SPEC`]), and an
    /// empty leading slot would read as an empty cipher.
    optional_credential_fields: bool,
    /// Lower-cased Clash field names recognized as defined parameters.
    known_fields: &'static [&'static str],
}

/// The shadowsocks credential glue — the one place the contract is written:
/// `cipher` and `password` join positionally into `method:password`, the
/// shape every reader (the ss serializer, the Clash and sing-box writers,
/// the fingerprint) splits on `:`. A password-only item is canonicalized to
/// [`crate::models::DEFAULT_SS_CIPHER`]`:password` here at parse time, so
/// the readers never re-derive the default themselves and the row merges
/// with its explicit-cipher twin; an item with no credential at all is
/// invalid (ss has no no-auth mode).
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

/// `type: snell`: meow names the secret `psk`; it is a single required
/// credential field, so the stored credential is the bare psk.
const SNELL_SPEC: ClashTypeSpec = ClashTypeSpec {
    scheme: Scheme::Snell,
    credential_fields: &["psk"],
    optional_credential_fields: false,
    known_fields: &[
        "version",
        "mode",
        "reuse",
        "udp",
        "obfs",
        "obfs-host",
        // The nested block a Clash feed spells obfs in; kept known so the
        // Clash writer can re-emit it as a block rather than a scalar.
        "obfs-opts",
    ],
};

/// `type: anytls`: single required `password`, like trojan's.
const ANYTLS_SPEC: ClashTypeSpec = ClashTypeSpec {
    scheme: Scheme::AnyTls,
    credential_fields: &["password"],
    optional_credential_fields: false,
    known_fields: &["sni", "udp", "skip-cert-verify", "insecure"],
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
    /// Items left out because the payload reached the entry cap.
    pub skipped: usize,
}

/// The root of a Clash payload: only `proxies` is consumed. Deserializing
/// into this minimal structure lets serde skip the unknown top-level
/// branches (`proxy-groups`, `rules`, …) without materializing them as
/// `Value` nodes; `deny_unknown_fields` is deliberately not set, a payload
/// with extra keys keeps parsing. A missing or non-sequence `proxies` is a
/// deserialization error.
#[derive(serde::Deserialize)]
struct ClashRoot {
    proxies: Vec<Value>,
}

/// Parse a full Clash YAML subscription payload.
pub fn parse_payload(payload: &str) -> Result<ClashParseResult, String> {
    // Alias references are refused before parsing: the whole payload is
    // attacker-controlled feed content and `serde_norway` re-materializes
    // the anchor's subtree for every reference, an alias bomb amplifies
    // quadratic memory out of a small payload (see `reject_yaml_aliases`).
    super::reject_yaml_aliases(payload).map_err(|e| format!("clash: {e}"))?;
    let root: ClashRoot =
        serde_norway::from_str(payload).map_err(|e| format!("clash: invalid YAML: {e}"))?;

    let mut result = ClashParseResult {
        entries: Vec::new(),
        unsupported: 0,
        invalid: 0,
        skipped: 0,
    };
    for (index, item) in root.proxies.iter().enumerate() {
        if result.entries.len() >= super::MAX_ENTRIES {
            // The cap is reached: the rest of the payload is counted instead
            // of parsed, so the load stays bounded and the truncation shows.
            result.skipped += 1;
            continue;
        }
        match parse_item(item) {
            Ok(Some(entry)) => result.entries.push(entry),
            Ok(None) => result.unsupported += 1,
            Err(message) => {
                tracing::debug!(
                    item = index,
                    error = %message,
                    "skipping malformed clash proxy item"
                );
                result.invalid += 1;
            }
        }
    }
    // One summary line for the whole payload: the element loop only counts
    // its skips, so this is where the truncation becomes visible.
    if result.unsupported > 0 || result.invalid > 0 {
        tracing::warn!(
            entries = result.entries.len(),
            unsupported = result.unsupported,
            invalid = result.invalid,
            "clash payload parsed"
        );
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
        "snell" => &SNELL_SPEC,
        "anytls" => &ANYTLS_SPEC,
        _ => {
            tracing::debug!(
                proxy_type = %super::truncate_utf8(&type_name, 64),
                "skipping unsupported clash proxy type"
            );
            return Ok(None);
        }
    };

    // A number/bool name becomes its literal text, like every parameter
    // value: the name is display data, never worth failing the item.
    let name = map
        .get("name")
        .map(yaml_to_string)
        .filter(|value| !value.is_empty())
        .unwrap_or_default();

    // Every error formed after the name is read carries it: the name is the
    // label an operator finds the broken item by in the feed (the loop
    // index of `parse_payload` does not survive into the log).
    let named = |message: String| match message.strip_prefix("clash: ") {
        Some(rest) => format!("clash: item {name:?}: {rest}"),
        None => format!("clash: item {name:?}: {message}"),
    };
    let host = string_field(map, "server").map_err(named)?;
    if host.is_empty() {
        return Err(named("clash: empty server".into()));
    }
    let host = super::normalize_host(&host);
    let port = numeric_field(map, "port").map_err(named)?;

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
    //     the cipher, so there an absent leading field is dropped and an
    //     ss item with only `password` stores the canonicalized
    //     `chacha20-ietf-poly1305:pw` (see `SS_SPEC`);
    //   - with nothing present the credential stays empty, so a
    //     single-field scheme without its secret emits no userinfo.
    //
    // A field that is present but empty (`null` or an empty scalar) counts as
    // absent: it says nothing about the secret, and treating it as present
    // would keep an empty leading slot (`":pw"`, an empty cipher).
    let fields: Vec<Option<String>> = spec
        .credential_fields
        .iter()
        .map(|field| {
            map.get(field)
                .filter(|value| !matches!(value, Value::Null))
                .map(yaml_to_string)
                .filter(|value| !value.is_empty())
        })
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
    // Shadowsocks canonicalization, the `SS_SPEC` contract: a password-only
    // item stores the default cipher with it, so every reader gets the
    // complete `method:password` shape and the row merges with its
    // explicit-cipher twin; an item with no credential at all is unusable,
    // not a no-auth proxy, and is counted as invalid.
    let credential = if spec.scheme == Scheme::Ss {
        match fields.as_slice() {
            [None, Some(password)] => {
                format!("{}:{password}", crate::models::DEFAULT_SS_CIPHER)
            }
            [None, None] => {
                return Err(named("clash: ss item has no cipher and no password".into()));
            }
            _ => credential,
        }
    } else {
        credential
    };

    // A YAML scalar may legally contain a line break, but the URI
    // serializers emit these two fields verbatim, one would split this proxy
    // into several output lines and smuggle a foreign scheme past the
    // source's protocol allowlist. Reject the item; the caller counts it.
    // Parameter values are exempt: Clash keeps structured blocks (`ws-opts`,
    // `reality-opts`, …) as multi-line YAML text, so they are sanitized at
    // serialization time instead.
    super::reject_line_breaks("clash: server", &host).map_err(named)?;
    super::reject_line_breaks("clash: credential", &credential).map_err(named)?;

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
                bare: false,
            }
        })
        .collect();
    // Field-size cap: Clash
    // params bypass `parse_query`, so the caps are enforced here.
    super::validate_params("clash", &params).map_err(named)?;
    // The host, the credential and the name are persisted verbatim, so they
    // are capped like the parameters.
    super::check_field_size("clash: server", &host).map_err(named)?;
    super::check_field_size("clash: credential", &credential).map_err(named)?;
    super::check_field_size("clash: name", &name).map_err(named)?;

    Ok(Some(super::with_canonical_cache(ProxyEntry {
        scheme: spec.scheme,
        name,
        host,
        port,
        credential,
        params,
        raw_path: String::new(),
        raw_line: String::new(),
        canonical: None,
    })))
}

fn string_field(map: &serde_norway::Mapping, key: &str) -> Result<String, String> {
    match map.get(key) {
        Some(Value::String(s)) => Ok(s.clone()),
        Some(_) => Err(format!("clash: field {key} is not a string")),
        None => Err(format!("clash: missing field {key:?}")),
    }
}

fn numeric_field(map: &serde_norway::Mapping, key: &str) -> Result<u16, String> {
    match map.get(key) {
        Some(Value::Number(n)) => {
            let port = match n.as_u64() {
                Some(v) => u16::try_from(v).ok(),
                // A feed may spell the port as a float (`443.0`): it is
                // accepted when the fraction is zero and it fits u16.
                None => n
                    .as_f64()
                    .filter(|v| v.fract() == 0.0 && *v >= 0.0 && *v <= f64::from(u16::MAX))
                    .map(|v| v as u16),
            };
            // Port 0 is not a dialable endpoint (the schema CHECK, migration
            // 0018, refuses it too), so the item is as invalid as an
            // out-of-range one.
            port.filter(|&p| p != 0)
                .ok_or_else(|| format!("clash: port out of range: {n}"))
        }
        Some(Value::String(s)) => match s.trim().parse::<u16>() {
            // The same zero rejection on the string spelling.
            Ok(0) | Err(_) => Err(format!("clash: invalid port string: {s:?}")),
            Ok(port) => Ok(port),
        },
        Some(_) => Err(format!("clash: field {key} is not numeric")),
        None => Err(format!("clash: missing field {key:?}")),
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
  - name: snell-node
    type: snell
    server: 1.2.3.4
    port: 44046
    psk: snellpsk
    version: 4
    obfs-opts:
      mode: http
      host: bing.com
  - name: anytls-node
    type: anytls
    server: 5.6.7.8
    port: 443
    password: atls-pass
    sni: atls.example.com
    skip-cert-verify: true
  - name: legacy-node
    type: mieru
    server: 9.9.9.9
    port: 443
proxy-groups:
  - name: auto
    type: url-test
    proxies: [hy2-node]
"#;

    #[test]
    fn parses_supported_items_and_skips_the_rest() {
        let result = parse_payload(SAMPLE).unwrap();
        assert_eq!(result.entries.len(), 4);
        assert_eq!(result.unsupported, 1); // mieru
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

        // snell: the psk is the whole credential, and the nested obfs block
        // survives as a mapping the Clash writer can re-emit.
        let snell = &result.entries[2];
        assert_eq!(snell.scheme, Scheme::Snell);
        assert_eq!(snell.host, "1.2.3.4");
        assert_eq!(snell.port, 44046);
        assert_eq!(snell.credential, "snellpsk");
        assert_eq!(snell.param("version"), Some("4"));
        assert!(
            snell
                .params
                .iter()
                .find(|p| p.key == "obfs-opts")
                .unwrap()
                .known
        );

        let anytls = &result.entries[3];
        assert_eq!(anytls.scheme, Scheme::AnyTls);
        assert_eq!(anytls.credential, "atls-pass");
        assert_eq!(anytls.param("sni"), Some("atls.example.com"));
        assert!(
            anytls
                .params
                .iter()
                .find(|p| p.key == "skip-cert-verify")
                .unwrap()
                .known
        );
    }

    #[test]
    fn payload_without_proxies_is_an_error() {
        assert!(parse_payload("mixed-port: 7890\n").is_err());
        assert!(parse_payload(":::").is_err());
    }

    /// `credential_fields` are joined positionally, so an absent field
    /// must keep its empty slot. A socks5 item carrying only `username`
    /// was stored as `onlyuser`, a string the output writers read as no
    /// credentials at all, because they split on `:`.
    #[test]
    fn an_absent_credential_field_keeps_its_slot() {
        let yaml =
            "proxies:\n  - {name: s, type: socks5, server: h, port: 1080, username: onlyuser}\n";
        let result = parse_payload(yaml).unwrap();
        assert_eq!(result.entries[0].credential, "onlyuser:");
    }

    /// The stored host must have one shape whatever the source spelled it:
    /// the URI parser stores the bare literal, so a Clash server written
    /// the URI way (`[2001:db8::1]`) is stored bare too. The fingerprint,
    /// the SSRF vetting and the serializer all read the stored host as an
    /// address.
    #[test]
    fn a_bracketed_ipv6_server_is_stored_bare() {
        let yaml = "proxies:\n  - {name: v6, type: trojan, server: '[2001:db8::1]', port: 443, password: p}\n";
        let result = parse_payload(yaml).unwrap();
        assert_eq!(result.entries.len(), 1);
        assert_eq!(result.entries[0].host, "2001:db8::1");
    }

    #[test]
    fn malformed_items_are_counted_not_fatal() {
        let yaml = "proxies:\n  - name: broken\n    type: ss\n    server: h\n  - {type: trojan, server: h, port: 443, password: p}\n";
        let result = parse_payload(yaml).unwrap();
        assert_eq!(result.invalid, 1); // first item: no port
        assert_eq!(result.entries.len(), 1);
    }

    /// An empty server is not a proxy: it must be counted as invalid instead
    /// of stored as a row whose host is the empty string.
    #[test]
    fn an_empty_server_is_invalid() {
        let yaml = "proxies:\n  - {name: a, type: trojan, server: '', port: 443, password: p}\n";
        let result = parse_payload(yaml).unwrap();
        assert_eq!(result.invalid, 1);
        assert!(result.entries.is_empty());
    }

    /// The host, the credential and the name are stored verbatim on every
    /// row, so they are capped like the parameters.
    #[test]
    fn oversized_fields_are_invalid() {
        let long = "h".repeat(crate::parsers::uri::MAX_PARAM_BYTES + 1);
        for yaml in [
            format!(
                "proxies:\n  - {{name: a, type: trojan, server: {long}, port: 443, password: p}}\n"
            ),
            format!(
                "proxies:\n  - {{name: a, type: trojan, server: h, port: 443, password: {long}}}\n"
            ),
            format!(
                "proxies:\n  - {{name: {long}, type: trojan, server: h, port: 443, password: p}}\n"
            ),
        ] {
            let result = parse_payload(&yaml).unwrap();
            assert_eq!(result.invalid, 1, "{yaml}");
            assert!(result.entries.is_empty());
        }
    }

    /// A credential field that is present but empty says nothing about the
    /// secret: it must count as absent, or it keeps an empty leading slot and
    /// the writers read `":pw"` as an empty cipher. The password-only ss item
    /// comes out canonicalized (see `SS_SPEC`).
    #[test]
    fn an_empty_credential_field_counts_as_absent() {
        for yaml in [
            "proxies:\n  - {name: a, type: ss, server: h, port: 8388, cipher: '', password: pw}\n",
            "proxies:\n  - {name: a, type: ss, server: h, port: 8388, cipher: null, password: pw}\n",
        ] {
            let result = parse_payload(yaml).unwrap();
            assert_eq!(
                result.entries[0].credential, "chacha20-ietf-poly1305:pw",
                "{yaml}"
            );
        }
    }

    /// A shadowsocks item without any credential is unusable, not a no-auth
    /// proxy: it is counted as invalid instead of stored as a row the ss
    /// serializer cannot emit a userinfo for.
    #[test]
    fn an_ss_item_without_a_credential_is_invalid() {
        let yaml = "proxies:\n  - {name: s, type: ss, server: h, port: 8388}\n";
        let result = parse_payload(yaml).unwrap();
        assert_eq!(result.invalid, 1);
        assert!(result.entries.is_empty());
    }

    /// A Clash port may be spelled as a string; it parses like the number
    /// form.
    #[test]
    fn a_clash_port_spelled_as_a_string_parses() {
        let yaml = "proxies:\n  - {name: s, type: trojan, server: h, port: \"443\", password: p}\n";
        let result = parse_payload(yaml).unwrap();
        assert_eq!(result.entries[0].port, 443);
    }

    /// Port 0 is not a dialable endpoint: the item is invalid in either
    /// spelling, not stored with a port no client could connect to.
    #[test]
    fn a_zero_clash_port_is_invalid() {
        for yaml in [
            "proxies:\n  - {name: s, type: trojan, server: h, port: 0, password: p}\n",
            "proxies:\n  - {name: s, type: trojan, server: h, port: \"0\", password: p}\n",
        ] {
            let result = parse_payload(yaml).unwrap();
            assert_eq!(result.entries.len(), 0, "{yaml}");
            assert_eq!(result.invalid, 1, "{yaml}");
        }
    }

    /// The parameter caps apply to Clash items too: they bypass
    /// `parse_query`, so an item over the parameter count cap or carrying an
    /// oversized parameter is invalid, not stored.
    #[test]
    fn oversized_or_too_many_params_are_invalid() {
        let values: String = (0..crate::parsers::uri::MAX_QUERY_PARAMS + 1)
            .map(|i| format!("f{i}: v{i}, "))
            .collect();
        let yaml = format!(
            "proxies:\n  - {{name: n, type: trojan, server: h, port: 443, password: p, {values}}}\n"
        );
        let result = parse_payload(&yaml).unwrap();
        assert_eq!(result.invalid, 1, "over the parameter count cap");
        assert!(result.entries.is_empty());

        let long = "v".repeat(crate::parsers::uri::MAX_PARAM_BYTES + 1);
        let yaml = format!(
            "proxies:\n  - {{name: n, type: trojan, server: h, port: 443, password: p, note: {long}}}\n"
        );
        let result = parse_payload(&yaml).unwrap();
        assert_eq!(result.invalid, 1, "over the byte cap");
        assert!(result.entries.is_empty());
    }

    /// A payload with a pathological number of items stops at the cap, and
    /// the remainder is counted as skipped.
    #[test]
    fn a_payload_with_too_many_items_is_capped() {
        let items: String = (0..crate::parsers::MAX_ENTRIES + 5)
            .map(|i| {
                format!("  - {{name: n{i}, type: trojan, server: h{i}.example.com, port: 443, password: p}}\n")
            })
            .collect();
        let result = parse_payload(&format!("proxies:\n{items}")).unwrap();
        assert_eq!(result.entries.len(), crate::parsers::MAX_ENTRIES);
        assert_eq!(result.skipped, 5);
    }
}
