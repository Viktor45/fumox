//! sing-box JSON output (SPEC §10).
//!
//! The emitted document carries only the `outbounds` array; sing-box fills
//! the rest with its defaults. An empty profile yields a valid
//! `{"outbounds": []}` document (SPEC §10.2 «пустой валидный конф»).
//! Outbound tags must be unique, so duplicate names get the same « (2)»
//! suffixes as Clash output (PLAN gap 14).

use crate::models::{ProxyEntry, Scheme};
use serde_json::{Map, Value};

/// Schemes with a sing-box counterpart used by Fumox; everything else is
/// skipped in output (log-and-skip principle, never fatal).
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

/// Map one entry onto a sing-box outbound using its own name as the tag.
/// Returns `None` for unsupported schemes.
pub fn entry_to_outbound(entry: &ProxyEntry) -> Option<Value> {
    entry_to_outbound_named(entry, &entry.name)
}

/// Map one entry onto a sing-box outbound under an explicit (already
/// deduplicated) tag.
pub fn entry_to_outbound_named(entry: &ProxyEntry, tag: &str) -> Option<Value> {
    let mut m = Map::new();
    m.insert("tag".into(), Value::String(tag.to_string()));

    match entry.scheme {
        Scheme::Vless => {
            m.insert("type".into(), Value::String("vless".into()));
            m.insert("server".into(), Value::String(entry.host.clone()));
            m.insert("server_port".into(), num(entry.port));
            m.insert("uuid".into(), Value::String(entry.credential.clone()));
            if let Some(flow) = non_empty_param(entry, "flow") {
                m.insert("flow".into(), Value::String(flow.to_string()));
            }
            let reality =
                security_is(entry, "reality") || super::reality_public_key(entry).is_some();
            if let Some(tls) = tls_object(entry, reality || wants_tls(entry), reality) {
                m.insert("tls".into(), tls);
            }
            if let Some(transport) = transport_object(entry, "type") {
                m.insert("transport".into(), transport);
            }
        }
        Scheme::Vmess => {
            m.insert("type".into(), Value::String("vmess".into()));
            m.insert("server".into(), Value::String(entry.host.clone()));
            m.insert("server_port".into(), num(entry.port));
            m.insert("uuid".into(), Value::String(entry.credential.clone()));
            m.insert(
                "security".into(),
                Value::String(entry.param("scy").unwrap_or("auto").to_string()),
            );
            let alter_id = entry
                .param("aid")
                .and_then(|v| v.parse::<u64>().ok())
                .unwrap_or(0);
            m.insert("alter_id".into(), num(alter_id as u16));
            // vmess JSON spells TLS as `tls: "tls"`; Clash input uses the
            // boolean `tls: true`; some feeds spell it `security=tls`.
            let tls = super::param_value(entry, "tls")
                .is_some_and(|v| v.eq_ignore_ascii_case("tls"))
                || super::param_truthy(entry, "tls")
                || security_is(entry, "tls");
            if tls && let Some(tls) = tls_object(entry, true, false) {
                m.insert("tls".into(), tls);
            }
            if let Some(transport) = transport_object(entry, "net") {
                m.insert("transport".into(), transport);
            }
        }
        Scheme::Trojan => {
            m.insert("type".into(), Value::String("trojan".into()));
            m.insert("server".into(), Value::String(entry.host.clone()));
            m.insert("server_port".into(), num(entry.port));
            m.insert("password".into(), Value::String(entry.credential.clone()));
            let reality =
                security_is(entry, "reality") || super::reality_public_key(entry).is_some();
            if let Some(tls) = tls_object(entry, true, reality) {
                m.insert("tls".into(), tls);
            }
            if let Some(transport) = transport_object(entry, "type") {
                m.insert("transport".into(), transport);
            }
        }
        Scheme::Ss => {
            m.insert("type".into(), Value::String("shadowsocks".into()));
            m.insert("server".into(), Value::String(entry.host.clone()));
            m.insert("server_port".into(), num(entry.port));
            // Credential is stored as "method:password".
            let (method, password) = entry
                .credential
                .split_once(':')
                .unwrap_or(("chacha20-ietf-poly1305", &entry.credential));
            m.insert("method".into(), Value::String(method.to_string()));
            m.insert("password".into(), Value::String(password.to_string()));
            // SIP003 plugin: sing-box takes the raw plugin name and the
            // option string after it, e.g. plugin "obfs-local" with
            // plugin_opts "obfs=http;obfs-host=example.com".
            if let Some(raw) = super::param_value(entry, "plugin") {
                let mut parts = raw.splitn(2, ';');
                let name = parts.next().unwrap_or_default().trim().to_string();
                if !name.is_empty() {
                    m.insert("plugin".into(), Value::String(name));
                    if let Some(opts) = parts.next() {
                        let opts = opts.trim().trim_end_matches(';').to_string();
                        if !opts.is_empty() {
                            m.insert("plugin_opts".into(), Value::String(opts));
                        }
                    }
                }
            }
        }
        Scheme::Hysteria2 => {
            m.insert("type".into(), Value::String("hysteria2".into()));
            m.insert("server".into(), Value::String(entry.host.clone()));
            m.insert("server_port".into(), num(entry.port));
            m.insert("password".into(), Value::String(entry.credential.clone()));
            if let Some(tls) = tls_object(entry, true, false) {
                m.insert("tls".into(), tls);
            }
            if let Some(obfs) = non_empty_param(entry, "obfs") {
                let mut o = Map::new();
                o.insert("type".into(), Value::String(obfs.to_string()));
                if let Some(pass) = non_empty_param(entry, "obfs-password") {
                    o.insert("password".into(), Value::String(pass.to_string()));
                }
                m.insert("obfs".into(), Value::Object(o));
            }
            for (out_key, keys) in [
                ("up_mbps", ["upMbps", "up"]),
                ("down_mbps", ["downMbps", "down"]),
            ] {
                if let Some(rate) = keys
                    .iter()
                    .find_map(|k| super::param_value(entry, k))
                    .and_then(|v| {
                        v.trim()
                            .trim_end_matches(|c: char| !c.is_ascii_digit())
                            .parse::<u32>()
                            .ok()
                    })
                {
                    m.insert(out_key.into(), Value::Number(rate.into()));
                }
            }
        }
        Scheme::Socks5 => {
            m.insert("type".into(), Value::String("socks".into()));
            m.insert("server".into(), Value::String(entry.host.clone()));
            m.insert("server_port".into(), num(entry.port));
            // Credential is stored as "user:pass"; both parts are optional.
            if let Some((user, password)) = entry.credential.split_once(':') {
                if !user.is_empty() {
                    m.insert("username".into(), Value::String(user.to_string()));
                }
                if !password.is_empty() {
                    m.insert("password".into(), Value::String(password.to_string()));
                }
            }
            if super::param_truthy(entry, "tls") {
                m.insert("tls".into(), minimal_tls(entry));
            }
        }
        Scheme::Naive | Scheme::Tuic | Scheme::Mieru => return None,
    }

    Some(Value::Object(m))
}

/// Encode the final candidate list as a sing-box config document (pretty
/// JSON). Duplicate tags are suffixed « (2)», « (3)»….
pub fn encode_singbox(entries: &[ProxyEntry]) -> String {
    let supported: Vec<&ProxyEntry> = entries.iter().filter(|e| is_supported(e.scheme)).collect();
    let tags = super::dedupe_names(supported.iter().map(|e| e.name.as_str()));
    let outbounds: Vec<Value> = supported
        .iter()
        .zip(tags)
        .filter_map(|(entry, tag)| entry_to_outbound_named(entry, &tag))
        .collect();

    let mut root = Map::new();
    root.insert("outbounds".into(), Value::Array(outbounds));
    match serde_json::to_string_pretty(&Value::Object(root)) {
        Ok(text) => text,
        Err(err) => {
            tracing::error!(error = %err, "sing-box JSON serialization failed");
            String::new()
        }
    }
}

/// vless/trojan/hysteria2-style entries want a TLS block when the entry
/// advertises TLS or carries SNI/insecure markers.
fn wants_tls(entry: &ProxyEntry) -> bool {
    matches!(entry.param("security").unwrap_or_default(), "tls")
        || non_empty_param(entry, "sni").is_some()
        || super::is_insecure(&entry.params)
}

fn security_is(entry: &ProxyEntry, want: &str) -> bool {
    super::param_value(entry, "security").is_some_and(|v| v.eq_ignore_ascii_case(want))
}

/// Bare TLS object for schemes without the full options (socks5-over-TLS).
fn minimal_tls(entry: &ProxyEntry) -> Value {
    let mut tls = Map::new();
    tls.insert("enabled".into(), Value::Bool(true));
    if let Some(sni) = non_empty_param(entry, "sni") {
        tls.insert("server_name".into(), Value::String(sni.to_string()));
    }
    if super::is_insecure(&entry.params) {
        tls.insert("insecure".into(), Value::Bool(true));
    }
    Value::Object(tls)
}

/// Build the sing-box `tls` object; `enabled` is always true once emitted.
/// `reality` adds the REALITY sub-object with the entry's pbk/sid (URI
/// params or a Clash-input `reality-opts` block).
fn tls_object(entry: &ProxyEntry, enabled: bool, reality: bool) -> Option<Value> {
    if !enabled {
        return None;
    }
    let mut tls = Map::new();
    tls.insert("enabled".into(), Value::Bool(true));
    if let Some(sni) = non_empty_param(entry, "sni") {
        tls.insert("server_name".into(), Value::String(sni.to_string()));
    }
    if super::is_insecure(&entry.params) {
        tls.insert("insecure".into(), Value::Bool(true));
    }
    if let Some(list) = super::param_list(entry, "alpn") {
        tls.insert(
            "alpn".into(),
            Value::Array(list.into_iter().map(Value::String).collect()),
        );
    }
    if let Some(fp) = non_empty_param(entry, "fp") {
        let mut utls = Map::new();
        utls.insert("enabled".into(), Value::Bool(true));
        utls.insert("fingerprint".into(), Value::String(fp.to_string()));
        tls.insert("utls".into(), Value::Object(utls));
    }
    if reality {
        let pbk = super::reality_public_key(entry);
        let sid = super::reality_short_id(entry);
        if pbk.is_some() || sid.is_some() {
            let mut r = Map::new();
            r.insert("enabled".into(), Value::Bool(true));
            if let Some(pbk) = pbk {
                r.insert("public_key".into(), Value::String(pbk));
            }
            if let Some(sid) = sid {
                r.insert("short_id".into(), Value::String(sid));
            }
            tls.insert("reality".into(), Value::Object(r));
        }
    }
    Some(Value::Object(tls))
}

/// Transport block resolved from the entry's native network key (`uri_key`:
/// `type` for vless/trojan URIs, `net` for vmess JSON; the mihomo spelling
/// `network` is accepted as a fallback). sing-box spells both HTTP/2 and
/// HTTP-header transports `http`; `httpupgrade` has its own transport type.
fn transport_object(entry: &ProxyEntry, uri_key: &str) -> Option<Value> {
    let network = super::network_of(entry, uri_key)?;
    let mut t = Map::new();
    match network.as_str() {
        "ws" | "httpupgrade" => {
            t.insert("type".into(), Value::String(network.clone()));
            if let Some(path) = super::param_value(entry, "path") {
                t.insert("path".into(), Value::String(path));
            }
            if let Some(host) = super::param_value(entry, "host") {
                if network == "ws" {
                    let mut headers = Map::new();
                    headers.insert("Host".into(), Value::String(host));
                    t.insert("headers".into(), Value::Object(headers));
                } else {
                    t.insert("host".into(), Value::String(host));
                }
            }
        }
        "grpc" => {
            t.insert("type".into(), Value::String("grpc".into()));
            let mut service = super::param_value(entry, "serviceName");
            if entry.scheme == Scheme::Vmess {
                service = service.or_else(|| super::param_value(entry, "path"));
            }
            if let Some(service) = service {
                t.insert("service_name".into(), Value::String(service));
            }
        }
        "h2" | "http" => {
            t.insert("type".into(), Value::String("http".into()));
            if let Some(host) = super::param_value(entry, "host") {
                let hosts: Vec<Value> = host
                    .split(',')
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .map(|s| Value::String(s.to_string()))
                    .collect();
                t.insert("host".into(), Value::Array(hosts));
            }
            if let Some(path) = super::param_value(entry, "path") {
                t.insert("path".into(), Value::String(path));
            }
        }
        _ => return None,
    }
    Some(Value::Object(t))
}

fn non_empty_param<'a>(entry: &'a ProxyEntry, key: &str) -> Option<&'a str> {
    entry.param(key).filter(|v| !v.is_empty())
}

fn num(value: u16) -> Value {
    Value::Number(u64::from(value).into())
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
        value.as_object().and_then(|m| m.get(key))
    }

    fn str_field<'a>(value: &'a Value, key: &str) -> Option<&'a str> {
        field(value, key).and_then(Value::as_str)
    }

    #[test]
    fn vless_reality_maps_tls_and_transport() {
        let e = entry(
            Scheme::Vless,
            "uuid-1",
            &[
                ("security", "reality"),
                ("sni", "sni.example.com"),
                ("fp", "chrome"),
                ("pbk", "key"),
                ("sid", "short"),
                ("flow", "xtls-rprx-vision"),
                ("network", "grpc"),
                ("serviceName", "svc"),
            ],
        );
        let v = entry_to_outbound(&e).unwrap();
        assert_eq!(str_field(&v, "type"), Some("vless"));
        assert_eq!(str_field(&v, "tag"), Some("proxy"));
        assert_eq!(str_field(&v, "uuid"), Some("uuid-1"));
        assert_eq!(str_field(&v, "flow"), Some("xtls-rprx-vision"));

        let tls = field(&v, "tls").unwrap();
        assert_eq!(field(tls, "enabled").and_then(Value::as_bool), Some(true));
        assert_eq!(str_field(tls, "server_name"), Some("sni.example.com"));
        assert_eq!(
            str_field(field(tls, "utls").unwrap(), "fingerprint"),
            Some("chrome")
        );
        let reality = field(tls, "reality").unwrap();
        assert_eq!(str_field(reality, "public_key"), Some("key"));
        assert_eq!(str_field(reality, "short_id"), Some("short"));

        let transport = field(&v, "transport").unwrap();
        assert_eq!(str_field(transport, "type"), Some("grpc"));
        assert_eq!(str_field(transport, "service_name"), Some("svc"));
    }

    #[test]
    fn trojan_tls_insecure_follows_the_entry_toggle() {
        let plain = entry(Scheme::Trojan, "pass", &[("sni", "t.example.com")]);
        let plain_out = entry_to_outbound(&plain).unwrap();
        let tls = field(&plain_out, "tls").unwrap();
        assert_eq!(str_field(tls, "server_name"), Some("t.example.com"));
        assert!(field(tls, "insecure").is_none());

        let insecure = entry(
            Scheme::Trojan,
            "pass",
            &[("sni", "t.example.com"), ("allowInsecure", "1")],
        );
        let insecure_out = entry_to_outbound(&insecure).unwrap();
        let tls = field(&insecure_out, "tls").unwrap();
        assert_eq!(field(tls, "insecure").and_then(Value::as_bool), Some(true));
    }

    #[test]
    fn shadowsocks_splits_method_and_password() {
        let e = entry(Scheme::Ss, "aes-256-gcm:secret", &[]);
        let v = entry_to_outbound(&e).unwrap();
        assert_eq!(str_field(&v, "type"), Some("shadowsocks"));
        assert_eq!(str_field(&v, "method"), Some("aes-256-gcm"));
        assert_eq!(str_field(&v, "password"), Some("secret"));
    }

    #[test]
    fn vmess_maps_security_and_alter_id() {
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
        let v = entry_to_outbound(&e).unwrap();
        assert_eq!(str_field(&v, "type"), Some("vmess"));
        assert_eq!(str_field(&v, "security"), Some("aes-128-gcm"));
        assert_eq!(field(&v, "alter_id").and_then(Value::as_u64), Some(4));
        let tls = field(&v, "tls").unwrap();
        assert_eq!(str_field(tls, "server_name"), Some("s.example.com"));
    }

    /// Parse a raw subscription line into an entry (panics on failure).
    fn parse(line: &str) -> ProxyEntry {
        match crate::parsers::parse_line(line) {
            crate::parsers::LineOutcome::Parsed(entry) => entry,
            other => panic!("expected parsed entry, got {other:?}"),
        }
    }

    fn b64(json: &str) -> String {
        base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD_NO_PAD,
            json.as_bytes(),
        )
    }

    #[test]
    fn raw_vmess_json_tls_ws_maps_completely() {
        let json = r#"{"v":"2","ps":"n","add":"h.example.com","port":"443","id":"uuid-2","aid":"0","scy":"auto","net":"ws","host":"ws.example.com","path":"/vmess","tls":"tls","sni":"s.example.com"}"#;
        let line = format!("vmess://{}", b64(json));
        let e = parse(&line);
        let v = entry_to_outbound(&e).unwrap();
        // vmess TLS is spelled `tls: "tls"` in the JSON, not `security=tls`.
        let tls = field(&v, "tls").unwrap();
        assert_eq!(field(tls, "enabled").and_then(Value::as_bool), Some(true));
        assert_eq!(str_field(tls, "server_name"), Some("s.example.com"));
        let transport = field(&v, "transport").unwrap();
        assert_eq!(str_field(transport, "type"), Some("ws"));
        assert_eq!(str_field(transport, "path"), Some("/vmess"));
        let headers = field(transport, "headers").unwrap();
        assert_eq!(str_field(headers, "Host"), Some("ws.example.com"));
    }

    #[test]
    fn raw_vless_reality_type_grpc_maps_transport() {
        let line = "vless://uuid-1@h.example.com:443?security=reality&sni=s.example.com&fp=chrome&pbk=pub-key&sid=01ab&type=grpc&serviceName=gr-svc#Name";
        let e = parse(line);
        let v = entry_to_outbound(&e).unwrap();
        let tls = field(&v, "tls").unwrap();
        let reality = field(tls, "reality").unwrap();
        assert_eq!(str_field(reality, "public_key"), Some("pub-key"));
        assert_eq!(str_field(reality, "short_id"), Some("01ab"));
        let transport = field(&v, "transport").unwrap();
        // Network comes from the URI `type` key.
        assert_eq!(str_field(transport, "type"), Some("grpc"));
        assert_eq!(str_field(transport, "service_name"), Some("gr-svc"));
    }

    #[test]
    fn raw_trojan_ws_line_maps_transport() {
        let line = "trojan://pass@h.example.com:443?security=tls&sni=t.example.com&type=ws&host=ws.example.com&path=%2Fws#Name";
        let e = parse(line);
        let v = entry_to_outbound(&e).unwrap();
        let transport = field(&v, "transport").unwrap();
        assert_eq!(str_field(transport, "type"), Some("ws"));
        assert_eq!(str_field(transport, "path"), Some("/ws"));
        let headers = field(transport, "headers").unwrap();
        assert_eq!(str_field(headers, "Host"), Some("ws.example.com"));
    }

    #[test]
    fn raw_ss_line_maps_plugin() {
        let blob = b64("aes-256-gcm:secret");
        let line = format!(
            "ss://{blob}@h.example.com:8388/?plugin=obfs-local%3Bobfs%3Dhttp%3Bobfs-host%3Dob.example.com#Name"
        );
        let e = parse(&line);
        let v = entry_to_outbound(&e).unwrap();
        assert_eq!(str_field(&v, "plugin"), Some("obfs-local"));
        assert_eq!(
            str_field(&v, "plugin_opts"),
            Some("obfs=http;obfs-host=ob.example.com")
        );
    }

    #[test]
    fn raw_hysteria2_line_maps_obfs_and_rates() {
        let line = "hysteria2://hy-pass@h.example.com:443?sni=hy.example.com&obfs=salamander&obfs-password=ob-pass&upMbps=50&downMbps=200&alpn=h3#Name";
        let e = parse(line);
        let v = entry_to_outbound(&e).unwrap();
        let obfs = field(&v, "obfs").unwrap();
        assert_eq!(str_field(obfs, "type"), Some("salamander"));
        assert_eq!(str_field(obfs, "password"), Some("ob-pass"));
        assert_eq!(field(&v, "up_mbps").and_then(Value::as_u64), Some(50));
        assert_eq!(field(&v, "down_mbps").and_then(Value::as_u64), Some(200));
        let tls = field(&v, "tls").unwrap();
        assert_eq!(
            field(tls, "alpn").and_then(Value::as_array).unwrap().len(),
            1
        );
    }

    #[test]
    fn socks_maps_to_socks_type() {
        let e = entry(Scheme::Socks5, "user:pw", &[]);
        let v = entry_to_outbound(&e).unwrap();
        assert_eq!(str_field(&v, "type"), Some("socks"));
        assert_eq!(str_field(&v, "username"), Some("user"));
        assert_eq!(str_field(&v, "password"), Some("pw"));
    }

    #[test]
    fn unsupported_schemes_are_skipped() {
        assert!(entry_to_outbound(&entry(Scheme::Tuic, "c", &[])).is_none());
        assert!(entry_to_outbound(&entry(Scheme::Mieru, "c", &[])).is_none());
        assert!(entry_to_outbound(&entry(Scheme::Naive, "c", &[])).is_none());
    }

    #[test]
    fn encode_suffixes_duplicate_tags() {
        let mut a = entry(Scheme::Trojan, "p1", &[]);
        a.name = "dup".into();
        let mut b = entry(Scheme::Trojan, "p2", &[]);
        b.name = "dup".into();
        let json = encode_singbox(&[a, b]);
        assert!(json.contains("\"tag\": \"dup\""), "json was: {json}");
        assert!(json.contains("\"tag\": \"dup (2)\""), "json was: {json}");
    }

    #[test]
    fn encode_empty_is_a_valid_document() {
        let json = encode_singbox(&[]);
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["outbounds"].as_array().unwrap().len(), 0);
    }
}
