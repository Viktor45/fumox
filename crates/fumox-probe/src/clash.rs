//! Clash (mihomo) YAML generation for T2 batches (SPEC §8.2).
//!
//! The probe writes this config to `meow.config_path` and asks meow-rs to
//! reload it via `PUT /configs`; every proxy is then delay-tested through a
//! real tunnel. Proxy names are `fumox-{id}` so results map back to DB rows
//! unambiguously.

use fumox_core::formats::clash::entry_to_clash_named;
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
/// definitions to run delay tests. Proxy definitions come from the shared
/// core mapping (the same one serving Clash subscriptions); the T2 policy
/// on top is deterministic `fumox-{id}` names.
///
/// Certificate verification is **not** forced off here. Unlike T1, which
/// only times a handshake, T2 builds a real authenticated tunnel and the
/// generated YAML carries the proxy's own credential (uuid / password /
/// `method:password`), so an unverified connection lets an on-path attacker
/// impersonate the server and harvest it. `skip-cert-verify` is therefore
/// emitted by the core mapping only for entries whose own parameters ask for
/// it (security audit, 2026-09-05).
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
    if !is_supported(entry.scheme) {
        return None;
    }
    entry_to_clash_named(&entry, &proxy_name(row.id))
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
            ladder_at: None,
            ladder_step: 0,
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
                entry(
                    Scheme::Trojan,
                    "pass",
                    &[("sni", "t.example.com"), ("type", "ws"), ("path", "/ws")],
                ),
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
        assert_eq!(vless["servername"].as_str(), Some("s.example.com"));
        assert_eq!(vless["reality-opts"]["public-key"].as_str(), Some("key"));
        // No `insecure` parameter on the entry: verification stays on, since
        // T2 sends the credential through the tunnel.
        assert!(vless.get("skip-cert-verify").is_none());

        let ss = &proxies[1];
        assert_eq!(ss["type"].as_str(), Some("ss"));
        assert_eq!(ss["cipher"].as_str(), Some("aes-256-gcm"));
        assert_eq!(ss["password"].as_str(), Some("secret"));

        let trojan = &proxies[2];
        assert_eq!(trojan["type"].as_str(), Some("trojan"));
        assert_eq!(trojan["password"].as_str(), Some("pass"));
        assert_eq!(trojan["network"].as_str(), Some("ws"));
        assert_eq!(trojan["ws-opts"]["path"].as_str(), Some("/ws"));

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

    /// T2 tunnels carry the proxy credential, so certificate verification
    /// follows the entry's own setting instead of being forced off
    /// (security audit, 2026-09-05).
    #[test]
    fn skip_cert_verify_follows_the_entry_and_is_never_forced() {
        let rows = vec![
            row_from_entry(
                1,
                entry(Scheme::Trojan, "pass", &[("sni", "t.example.com")]),
            ),
            row_from_entry(2, entry(Scheme::Trojan, "pass", &[("insecure", "1")])),
            row_from_entry(
                3,
                entry(Scheme::Trojan, "pass", &[("skip-cert-verify", "true")]),
            ),
        ];
        let yaml = generate(&rows).unwrap();
        let parsed: serde_norway::Value = serde_norway::from_str(&yaml).unwrap();
        let proxies = parsed["proxies"].as_sequence().unwrap();

        assert!(
            proxies[0].get("skip-cert-verify").is_none(),
            "verification must stay on for an entry that did not ask to skip it"
        );
        assert_eq!(proxies[1]["skip-cert-verify"].as_bool(), Some(true));
        assert_eq!(proxies[2]["skip-cert-verify"].as_bool(), Some(true));
    }
}
