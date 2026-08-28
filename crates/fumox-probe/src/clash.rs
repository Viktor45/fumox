//! Clash (mihomo) YAML generation for T2 batches (SPEC §8.2).
//!
//! The probe writes this config to `meow.config_path` and asks meow-rs to
//! reload it via `PUT /configs`; every proxy is then delay-tested through a
//! real tunnel. Proxy names are `fumox-{id}` so results map back to DB rows
//! unambiguously.

use fumox_core::models::Scheme;
use fumox_core::repo::proxies::ProxyRow;
use serde_norway::Value;

/// Schemes meow-rs can actually tunnel. naive has no mihomo counterpart and
/// tuic/mieru are unsupported (SPEC §8.5), so they never enter a T2 batch.
pub fn is_supported(scheme: Scheme) -> bool {
    matches!(
        scheme,
        Scheme::Vless
            | Scheme::Vmess
            | Scheme::Trojan
            | Scheme::Ss
            | Scheme::Hysteria2
            | Scheme::Socks5
    )
}

/// Deterministic name of a proxy inside the generated config.
pub fn proxy_name(proxy_id: i64) -> String {
    format!("fumox-{proxy_id}")
}

/// Shorthand for integer YAML scalars.
fn num(value: i64) -> Value {
    Value::Number(value.into())
}

/// Generate the full Clash config for one T2 batch.
///
/// Listener ports are disabled (`0`): meow-rs only needs the proxy
/// definitions to run delay tests. `skip-cert-verify` is set wherever TLS
/// is involved — health checks are not a trust boundary.
pub fn generate(rows: &[ProxyRow]) -> serde_norway::Result<String> {
    let proxies: Vec<Value> = rows.iter().filter_map(proxy_to_value).collect();

    let mut root = serde_norway::Mapping::new();
    root.insert(Value::String("port".into()), num(0));
    root.insert(Value::String("socks-port".into()), num(0));
    root.insert(Value::String("allow-lan".into()), Value::Bool(false));
    root.insert(Value::String("mode".into()), Value::String("rule".into()));
    root.insert(
        Value::String("log-level".into()),
        Value::String("silent".into()),
    );
    root.insert(Value::String("proxies".into()), Value::Sequence(proxies));
    serde_norway::to_string(&Value::Mapping(root))
}

/// Map one DB row onto a Clash proxy definition; returns `None` for
/// unsupported schemes (they are skipped, never fatal — log+skip policy).
fn proxy_to_value(row: &ProxyRow) -> Option<Value> {
    let entry = row.to_entry().ok()?;
    let mut m = serde_norway::Mapping::new();
    let mut put = |key: &str, value: Value| {
        m.insert(Value::String(key.into()), value);
    };

    put("name", Value::String(proxy_name(row.id)));
    put("server", Value::String(entry.host.clone()));
    put("port", num(i64::from(entry.port)));

    match entry.scheme {
        Scheme::Vless => {
            put("type", Value::String("vless".into()));
            put("uuid", Value::String(entry.credential.clone()));
            copy_param(&entry, "flow", "flow", &mut put);
            copy_param(&entry, "sni", "sni", &mut put);
            copy_param(&entry, "fp", "fingerprint", &mut put);
            copy_param(&entry, "pbk", "public-key", &mut put);
            copy_param(&entry, "sid", "short-id", &mut put);
            copy_param(&entry, "network", "network", &mut put);
            copy_param(&entry, "path", "ws-path", &mut put);
            copy_param(&entry, "serviceName", "grpc-service-name", &mut put);
            put("skip-cert-verify", Value::Bool(true));
        }
        Scheme::Vmess => {
            put("type", Value::String("vmess".into()));
            put("uuid", Value::String(entry.credential.clone()));
            let alter_id = entry
                .param("aid")
                .and_then(|v| v.parse::<i64>().ok())
                .unwrap_or(0);
            put("alterId", num(alter_id));
            put(
                "cipher",
                Value::String(entry.param("scy").unwrap_or("auto").to_string()),
            );
            if entry.param("security").unwrap_or_default() == "tls" {
                put("tls", Value::Bool(true));
                if let Some(sni) = entry.param("sni") {
                    put("servername", Value::String(sni.to_string()));
                }
                put("skip-cert-verify", Value::Bool(true));
            }
            copy_param(&entry, "network", "network", &mut put);
            copy_param(&entry, "path", "ws-path", &mut put);
        }
        Scheme::Trojan => {
            put("type", Value::String("trojan".into()));
            put("password", Value::String(entry.credential.clone()));
            copy_param(&entry, "sni", "sni", &mut put);
            put("skip-cert-verify", Value::Bool(true));
        }
        Scheme::Ss => {
            put("type", Value::String("ss".into()));
            // Credential is stored as "method:password".
            let (cipher, password) = entry
                .credential
                .split_once(':')
                .unwrap_or(("chacha20-ietf-poly1305", &entry.credential));
            put("cipher", Value::String(cipher.to_string()));
            put("password", Value::String(password.to_string()));
        }
        Scheme::Hysteria2 => {
            put("type", Value::String("hysteria2".into()));
            put("password", Value::String(entry.credential.clone()));
            copy_param(&entry, "sni", "sni", &mut put);
            put("skip-cert-verify", Value::Bool(true));
        }
        Scheme::Socks5 => {
            put("type", Value::String("socks5".into()));
            // Credential is stored as "user:pass"; both parts are optional.
            if let Some((user, password)) = entry.credential.split_once(':') {
                if !user.is_empty() {
                    put("username", Value::String(user.to_string()));
                }
                if !password.is_empty() {
                    put("password", Value::String(password.to_string()));
                }
            }
        }
        // Unsupported at T2 — filtered by is_supported, guard anyway.
        Scheme::Naive | Scheme::Tuic | Scheme::Mieru => return None,
    }

    Some(Value::Mapping(m))
}

/// Copy a recognized parameter onto the Clash mapping under a (possibly
/// different) destination key when present and non-empty.
fn copy_param(
    entry: &fumox_core::models::ProxyEntry,
    src: &str,
    dst: &str,
    put: &mut impl FnMut(&str, Value),
) {
    if let Some(value) = entry.param(src)
        && !value.is_empty()
    {
        put(dst, Value::String(value.to_string()));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fumox_core::models::{Param, ProxyEntry};

    fn row_from_entry(id: i64, entry: ProxyEntry) -> ProxyRow {
        let known = serde_json::to_string(&entry.known_params_json()).unwrap();
        ProxyRow {
            id,
            fingerprint: format!("fp{id}"),
            scheme: entry.scheme.as_str().to_string(),
            name: entry.name.clone(),
            host: entry.host.clone(),
            port: i64::from(entry.port),
            credential: entry.credential.clone(),
            params: Some(known),
            unknown_params: None,
            raw_line: None,
            geo_country: None,
            geo_city: None,
            geo_asn: None,
            resolved_ip: None,
            status: "alive".into(),
            fail_count: 0,
            last_checked_at: None,
            last_alive_at: None,
            quarantined_at: None,
            second_chance_at: None,
            recheck_15m_at: None,
            recheck_30m_at: None,
            recheck_1h_at: None,
            removed_at: None,
            latency_ms: None,
            speed_mbps: None,
            created_at: 1,
            updated_at: 1,
        }
    }

    fn entry(scheme: Scheme, credential: &str, params: &[(&str, &str)]) -> ProxyEntry {
        ProxyEntry {
            scheme,
            name: "n".into(),
            host: "h.example.com".into(),
            port: 443,
            credential: credential.into(),
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

    #[test]
    fn generates_valid_yaml_with_expected_keys() {
        let rows = vec![
            row_from_entry(
                1,
                entry(
                    Scheme::Vless,
                    "uuid-1",
                    &[
                        ("security", "reality"),
                        ("sni", "s.example.com"),
                        ("pbk", "key"),
                    ],
                ),
            ),
            row_from_entry(2, entry(Scheme::Ss, "aes-256-gcm:secret", &[])),
            row_from_entry(
                3,
                entry(Scheme::Trojan, "pass", &[("sni", "t.example.com")]),
            ),
            row_from_entry(4, entry(Scheme::Hysteria2, "hy-pass", &[])),
            row_from_entry(5, entry(Scheme::Socks5, "user:pw", &[])),
            row_from_entry(
                6,
                entry(
                    Scheme::Vmess,
                    "uuid-2",
                    &[("security", "tls"), ("scy", "aes-128-gcm"), ("aid", "4")],
                ),
            ),
        ];

        let yaml = generate(&rows).unwrap();
        let parsed: serde_norway::Value = serde_norway::from_str(&yaml).unwrap();
        let proxies = parsed["proxies"].as_sequence().unwrap();
        assert_eq!(proxies.len(), 6);

        let vless = &proxies[0];
        assert_eq!(vless["name"].as_str(), Some("fumox-1"));
        assert_eq!(vless["type"].as_str(), Some("vless"));
        assert_eq!(vless["uuid"].as_str(), Some("uuid-1"));
        assert_eq!(vless["sni"].as_str(), Some("s.example.com"));
        assert_eq!(vless["public-key"].as_str(), Some("key"));
        assert_eq!(vless["skip-cert-verify"].as_bool(), Some(true));

        let ss = &proxies[1];
        assert_eq!(ss["type"].as_str(), Some("ss"));
        assert_eq!(ss["cipher"].as_str(), Some("aes-256-gcm"));
        assert_eq!(ss["password"].as_str(), Some("secret"));

        let trojan = &proxies[2];
        assert_eq!(trojan["type"].as_str(), Some("trojan"));
        assert_eq!(trojan["password"].as_str(), Some("pass"));

        let hy2 = &proxies[3];
        assert_eq!(hy2["type"].as_str(), Some("hysteria2"));
        assert_eq!(hy2["password"].as_str(), Some("hy-pass"));

        let socks = &proxies[4];
        assert_eq!(socks["type"].as_str(), Some("socks5"));
        assert_eq!(socks["username"].as_str(), Some("user"));
        assert_eq!(socks["password"].as_str(), Some("pw"));

        let vmess = &proxies[5];
        assert_eq!(vmess["type"].as_str(), Some("vmess"));
        assert_eq!(vmess["uuid"].as_str(), Some("uuid-2"));
        assert_eq!(vmess["alterId"].as_u64(), Some(4));
        assert_eq!(vmess["cipher"].as_str(), Some("aes-128-gcm"));
        assert_eq!(vmess["tls"].as_bool(), Some(true));

        // Listener ports are disabled in the generated config.
        assert_eq!(parsed["port"].as_u64(), Some(0));
        assert_eq!(parsed["socks-port"].as_u64(), Some(0));
    }

    #[test]
    fn unsupported_schemes_are_skipped() {
        assert!(is_supported(Scheme::Vless));
        assert!(is_supported(Scheme::Hysteria2));
        assert!(!is_supported(Scheme::Tuic));
        assert!(!is_supported(Scheme::Mieru));
        assert!(!is_supported(Scheme::Naive));

        let rows = vec![row_from_entry(9, entry(Scheme::Tuic, "c", &[]))];
        let yaml = generate(&rows).unwrap();
        let parsed: serde_norway::Value = serde_norway::from_str(&yaml).unwrap();
        assert!(parsed["proxies"].as_sequence().unwrap().is_empty());
    }
}
