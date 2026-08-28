//! Clash/Mihomo YAML output (SPEC §10).
//!
//! The emitted document carries only the `proxies:` list; mihomo fills the
//! rest with its defaults. An empty profile yields a valid `proxies: []`
//! document (SPEC §10.2 «пустой валидный конф»).
//!
//! The per-scheme field mapping mirrors the probe's T2 generator
//! (`fumox-probe/src/clash.rs`) with two deliberate differences: names come
//! from the pipeline-renamed entry name (with collision suffixes, PLAN
//! gap 14), and `skip-cert-verify` is emitted only when the entry itself
//! carries a truthy insecure toggle — user subscriptions must not disable
//! certificate checks by fiat.

use crate::models::{ProxyEntry, Scheme};
use serde_norway::Value;

/// Schemes with a mihomo counterpart; everything else is skipped in output
/// (log-and-skip principle, never fatal).
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

/// Map one entry onto a Clash proxy definition using its own name.
/// Returns `None` for unsupported schemes.
pub fn entry_to_clash(entry: &ProxyEntry) -> Option<Value> {
    entry_to_clash_named(entry, &entry.name)
}

/// Map one entry onto a Clash proxy definition under an explicit (already
/// deduplicated) name.
pub fn entry_to_clash_named(entry: &ProxyEntry, name: &str) -> Option<Value> {
    let mut m = serde_norway::Mapping::new();
    let mut put = |key: &str, value: Value| {
        m.insert(Value::String(key.into()), value);
    };

    put("name", Value::String(name.to_string()));
    put("server", Value::String(entry.host.clone()));
    put("port", num(i64::from(entry.port)));

    match entry.scheme {
        Scheme::Vless => {
            put("type", Value::String("vless".into()));
            put("uuid", Value::String(entry.credential.clone()));
            copy_param(entry, "flow", "flow", &mut put);
            copy_param(entry, "sni", "sni", &mut put);
            copy_param(entry, "fp", "fingerprint", &mut put);
            copy_param(entry, "pbk", "public-key", &mut put);
            copy_param(entry, "sid", "short-id", &mut put);
            copy_param(entry, "network", "network", &mut put);
            copy_param(entry, "path", "ws-path", &mut put);
            copy_param(entry, "serviceName", "grpc-service-name", &mut put);
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
                copy_param(entry, "sni", "servername", &mut put);
            }
            copy_param(entry, "network", "network", &mut put);
            copy_param(entry, "path", "ws-path", &mut put);
        }
        Scheme::Trojan => {
            put("type", Value::String("trojan".into()));
            put("password", Value::String(entry.credential.clone()));
            copy_param(entry, "sni", "sni", &mut put);
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
            copy_param(entry, "sni", "sni", &mut put);
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
        Scheme::Naive | Scheme::Tuic | Scheme::Mieru => return None,
    }

    if super::is_insecure(&entry.params) {
        put("skip-cert-verify", Value::Bool(true));
    }

    Some(Value::Mapping(m))
}

/// Encode the final candidate list as a Clash YAML document. Duplicate
/// names are suffixed « (2)», « (3)»… (PLAN gap 14).
pub fn encode_clash(entries: &[ProxyEntry]) -> String {
    let supported: Vec<&ProxyEntry> = entries.iter().filter(|e| is_supported(e.scheme)).collect();
    let names = super::dedupe_names(supported.iter().map(|e| e.name.as_str()));
    let items: Vec<Value> = supported
        .iter()
        .zip(names)
        .filter_map(|(entry, name)| entry_to_clash_named(entry, &name))
        .collect();

    let mut root = serde_norway::Mapping::new();
    root.insert(Value::String("proxies".into()), Value::Sequence(items));
    match serde_norway::to_string(&Value::Mapping(root)) {
        Ok(text) => text,
        Err(err) => {
            tracing::error!(error = %err, "clash YAML serialization failed");
            String::new()
        }
    }
}

fn num(value: i64) -> Value {
    Value::Number(value.into())
}

/// Copy a non-empty parameter onto the mapping under a (possibly different)
/// destination key.
fn copy_param(entry: &ProxyEntry, src: &str, dst: &str, put: &mut impl FnMut(&str, Value)) {
    if let Some(value) = entry.param(src)
        && !value.is_empty()
    {
        put(dst, Value::String(value.to_string()));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::Param;

    fn entry(scheme: Scheme, credential: &str, params: &[(&str, &str)]) -> ProxyEntry {
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
                })
                .collect(),
            raw_path: String::new(),
            raw_line: String::new(),
        }
    }

    fn field<'a>(value: &'a Value, key: &str) -> Option<&'a Value> {
        value.as_mapping().and_then(|m| m.get(key))
    }

    fn str_field<'a>(value: &'a Value, key: &str) -> Option<&'a str> {
        field(value, key).and_then(Value::as_str)
    }

    #[test]
    fn vless_maps_credentials_and_params() {
        let e = entry(
            Scheme::Vless,
            "uuid-1",
            &[
                ("flow", "xtls-rprx-vision"),
                ("sni", "sni.example.com"),
                ("fp", "chrome"),
                ("pbk", "key"),
                ("sid", "short"),
                ("network", "ws"),
                ("path", "/ws"),
                ("serviceName", "svc"),
            ],
        );
        let v = entry_to_clash(&e).unwrap();
        assert_eq!(str_field(&v, "type"), Some("vless"));
        assert_eq!(str_field(&v, "name"), Some("proxy"));
        assert_eq!(str_field(&v, "server"), Some("example.com"));
        assert_eq!(field(&v, "port").and_then(Value::as_u64), Some(443));
        assert_eq!(str_field(&v, "uuid"), Some("uuid-1"));
        assert_eq!(str_field(&v, "flow"), Some("xtls-rprx-vision"));
        assert_eq!(str_field(&v, "sni"), Some("sni.example.com"));
        assert_eq!(str_field(&v, "fingerprint"), Some("chrome"));
        assert_eq!(str_field(&v, "public-key"), Some("key"));
        assert_eq!(str_field(&v, "short-id"), Some("short"));
        assert_eq!(str_field(&v, "network"), Some("ws"));
        assert_eq!(str_field(&v, "ws-path"), Some("/ws"));
        assert_eq!(str_field(&v, "grpc-service-name"), Some("svc"));
        // No insecure toggle on the entry — no skip-cert-verify.
        assert!(field(&v, "skip-cert-verify").is_none());
    }

    #[test]
    fn insecure_toggle_emits_skip_cert_verify() {
        let e = entry(Scheme::Trojan, "pass", &[("allowInsecure", "1")]);
        let v = entry_to_clash(&e).unwrap();
        assert_eq!(
            field(&v, "skip-cert-verify").and_then(Value::as_bool),
            Some(true)
        );
    }

    #[test]
    fn vmess_tls_security_enables_tls_with_servername() {
        let e = entry(
            Scheme::Vmess,
            "uuid-2",
            &[
                ("security", "tls"),
                ("sni", "s.example.com"),
                ("aid", "4"),
                ("scy", "aes-128-gcm"),
            ],
        );
        let v = entry_to_clash(&e).unwrap();
        assert_eq!(str_field(&v, "type"), Some("vmess"));
        assert_eq!(field(&v, "tls").and_then(Value::as_bool), Some(true));
        assert_eq!(str_field(&v, "servername"), Some("s.example.com"));
        assert_eq!(field(&v, "alterId").and_then(Value::as_u64), Some(4));
        assert_eq!(str_field(&v, "cipher"), Some("aes-128-gcm"));
    }

    #[test]
    fn ss_credential_splits_into_cipher_and_password() {
        let e = entry(Scheme::Ss, "aes-256-gcm:secret", &[]);
        let v = entry_to_clash(&e).unwrap();
        assert_eq!(str_field(&v, "cipher"), Some("aes-256-gcm"));
        assert_eq!(str_field(&v, "password"), Some("secret"));
    }

    #[test]
    fn socks5_credential_is_optional_per_part() {
        let e = entry(Scheme::Socks5, "user:pw", &[]);
        let v = entry_to_clash(&e).unwrap();
        assert_eq!(str_field(&v, "username"), Some("user"));
        assert_eq!(str_field(&v, "password"), Some("pw"));
    }

    #[test]
    fn unsupported_schemes_are_skipped() {
        assert!(entry_to_clash(&entry(Scheme::Tuic, "c", &[])).is_none());
        assert!(entry_to_clash(&entry(Scheme::Mieru, "c", &[])).is_none());
        assert!(entry_to_clash(&entry(Scheme::Naive, "c", &[])).is_none());
    }

    #[test]
    fn encode_suffixes_duplicate_names_and_skips_unsupported() {
        let mut a = entry(Scheme::Trojan, "p1", &[]);
        a.name = "dup".into();
        let mut b = entry(Scheme::Trojan, "p2", &[]);
        b.name = "dup".into();
        let skipped = entry(Scheme::Tuic, "p3", &[]);
        let yaml = encode_clash(&[a, skipped, b]);
        assert!(yaml.contains("name: dup\n"), "yaml was: {yaml}");
        assert!(yaml.contains("name: dup (2)"), "yaml was: {yaml}");
        assert!(!yaml.contains("p3"));
    }

    #[test]
    fn encode_empty_is_a_valid_document() {
        let yaml = encode_clash(&[]);
        assert!(yaml.contains("proxies: []"), "yaml was: {yaml}");
    }
}
