//! Clash/Mihomo YAML output (SPEC §10).
//!
//! The emitted document carries only the `proxies:` list; mihomo fills the
//! rest with its defaults. An empty profile yields a valid `proxies: []`
//! document (SPEC §10.2 «пустой валидный конф»).
//!
//! The mapping follows the mihomo proxy schema: TLS is enabled by
//! `security=tls|reality` (vless/trojan) or the vmess `tls` field, REALITY
//! keys go under `reality-opts`, and transports are emitted as the nested
//! `ws-opts`/`grpc-opts`/`h2-opts`/`http-opts` blocks mihomo actually reads.
//! URI parameters travel under their native keys (`type` for the network of
//! vless/trojan, `net` for vmess), while Clash-input entries already carry
//! the mihomo keys (`network`, `ws-path`, structured YAML opts) — both
//! spellings are accepted everywhere.
//!
//! This is also the mapping used by the probe's T2 generator, which only
//! overrides the name and its always-on `skip-cert-verify`.

use crate::models::{ProxyEntry, Scheme};
use serde_norway::{Mapping, Value};

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
    let mut m = Mapping::new();
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
            let reality = security_is(entry, "reality");
            if security_is(entry, "tls") || reality || super::param_truthy(entry, "tls") {
                put("tls", Value::Bool(true));
                copy_param(entry, "sni", "servername", &mut put);
                copy_param(entry, "servername", "servername", &mut put);
            }
            copy_param(entry, "fp", "client-fingerprint", &mut put);
            put_reality_opts(entry, &mut put);
            put_alpn(entry, &mut put);
            put_transport(entry, "type", &mut put);
        }
        Scheme::Vmess => {
            put("type", Value::String("vmess".into()));
            put("uuid", Value::String(entry.credential.clone()));
            let alter_id = super::param_value(entry, "aid")
                .or_else(|| super::param_value(entry, "alterId"))
                .and_then(|v| v.parse::<i64>().ok())
                .unwrap_or(0);
            put("alterId", num(alter_id));
            let cipher = super::param_value(entry, "scy")
                .or_else(|| super::param_value(entry, "cipher"))
                .unwrap_or_else(|| "auto".into());
            put("cipher", Value::String(cipher));
            // vmess JSON carries TLS in `tls: "tls"`; Clash input uses the
            // boolean `tls: true`; some feeds spell it `security=tls`.
            let tls = super::param_value(entry, "tls")
                .is_some_and(|v| v.eq_ignore_ascii_case("tls"))
                || super::param_truthy(entry, "tls")
                || security_is(entry, "tls");
            if tls {
                put("tls", Value::Bool(true));
                copy_param(entry, "sni", "servername", &mut put);
                copy_param(entry, "servername", "servername", &mut put);
            }
            copy_param(entry, "fp", "client-fingerprint", &mut put);
            copy_param(entry, "client-fingerprint", "client-fingerprint", &mut put);
            put_alpn(entry, &mut put);
            put_transport(entry, "net", &mut put);
        }
        Scheme::Trojan => {
            put("type", Value::String("trojan".into()));
            put("password", Value::String(entry.credential.clone()));
            copy_param(entry, "sni", "sni", &mut put);
            copy_param(entry, "flow", "flow", &mut put);
            copy_param(entry, "fp", "client-fingerprint", &mut put);
            put_reality_opts(entry, &mut put);
            put_alpn(entry, &mut put);
            put_transport(entry, "type", &mut put);
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
            put_ss_plugin(entry, &mut put);
        }
        Scheme::Hysteria2 => {
            put("type", Value::String("hysteria2".into()));
            put("password", Value::String(entry.credential.clone()));
            copy_param(entry, "sni", "sni", &mut put);
            copy_param(entry, "obfs", "obfs", &mut put);
            copy_param(entry, "obfs-password", "obfs-password", &mut put);
            copy_param(entry, "upMbps", "up", &mut put);
            copy_param(entry, "up", "up", &mut put);
            copy_param(entry, "downMbps", "down", &mut put);
            copy_param(entry, "down", "down", &mut put);
            copy_param(entry, "pinSHA256", "fingerprint", &mut put);
            copy_param(entry, "fingerprint", "fingerprint", &mut put);
            copy_param(entry, "ports", "ports", &mut put);
            put_alpn(entry, &mut put);
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
            if super::param_truthy(entry, "tls") {
                put("tls", Value::Bool(true));
            }
        }
        Scheme::Naive | Scheme::Tuic | Scheme::Mieru => return None,
    }

    if super::is_insecure(&entry.params) {
        put("skip-cert-verify", Value::Bool(true));
    }
    // Clash-input entries keep their `udp` toggle; URI feeds don't carry one.
    if super::param_truthy(entry, "udp") {
        put("udp", Value::Bool(true));
    }

    Some(Value::Mapping(m))
}

/// Whether the URI `security` parameter equals `want` (vless/trojan).
fn security_is(entry: &ProxyEntry, want: &str) -> bool {
    super::param_value(entry, "security").is_some_and(|v| v.eq_ignore_ascii_case(want))
}

/// `reality-opts: {public-key, short-id}` from URI `pbk`/`sid` params or a
/// Clash-input `reality-opts` block. Emitted only when at least one key is
/// present — an empty block would make mihomo reject the proxy.
fn put_reality_opts(entry: &ProxyEntry, put: &mut impl FnMut(&str, Value)) {
    let pbk = super::reality_public_key(entry);
    let sid = super::reality_short_id(entry);
    if pbk.is_none() && sid.is_none() {
        return;
    }
    let mut reality = Mapping::new();
    if let Some(pbk) = pbk {
        reality.insert(Value::String("public-key".into()), Value::String(pbk));
    }
    if let Some(sid) = sid {
        reality.insert(Value::String("short-id".into()), Value::String(sid));
    }
    put("reality-opts", Value::Mapping(reality));
}

/// `alpn` as a YAML list (mihomo requires a sequence there).
fn put_alpn(entry: &ProxyEntry, put: &mut impl FnMut(&str, Value)) {
    if let Some(list) = super::param_list(entry, "alpn") {
        put(
            "alpn",
            Value::Sequence(list.into_iter().map(Value::String).collect()),
        );
    }
}

/// Emit `network` plus the transport block mihomo reads for it.
///
/// `uri_key` is the entry's native network key (`type` for vless/trojan
/// URIs, `net` for vmess JSON); the mihomo spelling `network` (Clash input)
/// is accepted as a fallback. Xray-family links spell HTTP/2 as `type=http`
/// and plain-HTTP header obfuscation as `type=tcp&headerType=http`; vmess
/// JSON instead uses `net=http` for the obfuscation, matching mihomo's
/// `network: http` directly. `type=httpupgrade` becomes mihomo's
/// `network: ws` + `ws-opts.v2ray-http-upgrade` (there is no dedicated
/// httpupgrade transport).
fn put_transport(entry: &ProxyEntry, uri_key: &str, put: &mut impl FnMut(&str, Value)) {
    let network =
        match super::param_value(entry, uri_key).or_else(|| super::param_value(entry, "network")) {
            Some(n) => n.to_ascii_lowercase(),
            None => return,
        };
    match network.as_str() {
        "" | "tcp" => {
            // Plain-HTTP header obfuscation: `type=tcp&headerType=http` in
            // URIs, `net: tcp, type: http` in vmess JSON.
            if param_value_is(entry, "headerType", "http")
                || (entry.scheme == Scheme::Vmess && param_value_is(entry, "type", "http"))
            {
                put("network", Value::String("http".into()));
                put_http_opts(entry, put);
            }
        }
        "ws" | "httpupgrade" => {
            put("network", Value::String("ws".into()));
            put_ws_opts(entry, network == "httpupgrade", put);
        }
        "grpc" => {
            put("network", Value::String("grpc".into()));
            put_grpc_opts(entry, put);
        }
        "h2" => {
            put("network", Value::String("h2".into()));
            put_h2_opts(entry, put);
        }
        "http" => {
            if entry.scheme == Scheme::Vmess || param_value_is(entry, "headerType", "http") {
                put("network", Value::String("http".into()));
                put_http_opts(entry, put);
            } else {
                put("network", Value::String("h2".into()));
                put_h2_opts(entry, put);
            }
        }
        // Unknown network spelling (xhttp, kcp, …): pass it through so a
        // capable mihomo can still use it.
        other => put("network", Value::String(other.into())),
    }
}

fn param_value_is(entry: &ProxyEntry, key: &str, want: &str) -> bool {
    super::param_value(entry, key).is_some_and(|v| v.eq_ignore_ascii_case(want))
}

/// `ws-opts: {path, headers: {Host}}` (plus the httpupgrade toggle).
fn put_ws_opts(entry: &ProxyEntry, http_upgrade: bool, put: &mut impl FnMut(&str, Value)) {
    let ws_yaml = super::param_map(entry, "ws-opts");
    let headers_yaml = super::param_map(entry, "ws-headers");
    let path = super::param_value(entry, "path").or_else(|| super::map_str(&ws_yaml, "path"));
    let host = super::param_value(entry, "host")
        .or_else(|| super::map_str(&headers_yaml, "host"))
        .or_else(|| nested_host(&ws_yaml));
    if path.is_none() && host.is_none() && !http_upgrade {
        return;
    }
    let mut ws = Mapping::new();
    if let Some(path) = path {
        ws.insert(Value::String("path".into()), Value::String(path));
    }
    if let Some(host) = host {
        let mut headers = Mapping::new();
        headers.insert(Value::String("Host".into()), Value::String(host));
        ws.insert(Value::String("headers".into()), Value::Mapping(headers));
    }
    if http_upgrade {
        ws.insert(
            Value::String("v2ray-http-upgrade".into()),
            Value::Bool(true),
        );
    }
    put("ws-opts", Value::Mapping(ws));
}

/// `Host` header inside a parsed Clash-input `ws-opts.headers` block.
fn nested_host(ws_yaml: &Option<Mapping>) -> Option<String> {
    let headers = ws_yaml
        .as_ref()?
        .get("headers")
        .and_then(Value::as_mapping)?;
    for key in ["Host", "host"] {
        if let Some(host) = headers.get(key).and_then(Value::as_str)
            && !host.trim().is_empty()
        {
            return Some(host.trim().to_string());
        }
    }
    None
}

/// `grpc-opts: {grpc-service-name}`. vmess JSON carries the gRPC service
/// name in its `path` field, so that is the vmess fallback.
fn put_grpc_opts(entry: &ProxyEntry, put: &mut impl FnMut(&str, Value)) {
    let yaml = super::param_map(entry, "grpc-opts");
    let mut service = super::param_value(entry, "serviceName")
        .or_else(|| super::map_str(&yaml, "grpc-service-name"))
        .or_else(|| super::param_value(entry, "grpc-service-name"));
    if entry.scheme == Scheme::Vmess {
        service = service.or_else(|| super::param_value(entry, "path"));
    }
    if let Some(service) = service {
        let mut grpc = Mapping::new();
        grpc.insert(
            Value::String("grpc-service-name".into()),
            Value::String(service),
        );
        put("grpc-opts", Value::Mapping(grpc));
    }
}

/// `h2-opts: {host: [...], path}`; the URI `host` value may list several.
fn put_h2_opts(entry: &ProxyEntry, put: &mut impl FnMut(&str, Value)) {
    let yaml = super::param_map(entry, "h2-opts");
    let path = super::param_value(entry, "path").or_else(|| super::map_str(&yaml, "path"));
    let hosts = super::param_value(entry, "host")
        .or_else(|| super::map_str(&yaml, "host"))
        .map(|h| {
            h.split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_string)
                .collect::<Vec<_>>()
        })
        .or_else(|| yaml_list(&yaml, "host"));
    if path.is_none() && hosts.is_none() {
        return;
    }
    let mut h2 = Mapping::new();
    if let Some(hosts) = hosts {
        h2.insert(
            Value::String("host".into()),
            Value::Sequence(hosts.into_iter().map(Value::String).collect()),
        );
    }
    if let Some(path) = path {
        h2.insert(Value::String("path".into()), Value::String(path));
    }
    put("h2-opts", Value::Mapping(h2));
}

/// `http-opts: {path: [...], headers: {Host: [...]}}`.
fn put_http_opts(entry: &ProxyEntry, put: &mut impl FnMut(&str, Value)) {
    let path = super::param_value(entry, "path");
    let host = super::param_value(entry, "host");
    if path.is_none() && host.is_none() {
        return;
    }
    let mut http = Mapping::new();
    if let Some(path) = path {
        http.insert(
            Value::String("path".into()),
            Value::Sequence(vec![Value::String(path)]),
        );
    }
    if let Some(host) = host {
        let mut headers = Mapping::new();
        headers.insert(
            Value::String("Host".into()),
            Value::Sequence(vec![Value::String(host)]),
        );
        http.insert(Value::String("headers".into()), Value::Mapping(headers));
    }
    put("http-opts", Value::Mapping(http));
}

/// SIP003 `plugin` parameter → mihomo `plugin` + `plugin-opts`. The plugin
/// name and its `;`-separated options are percent-decoded first.
fn put_ss_plugin(entry: &ProxyEntry, put: &mut impl FnMut(&str, Value)) {
    let raw = match super::param_value(entry, "plugin") {
        Some(p) => p,
        None => return,
    };
    let mut parts = raw.split(';');
    let name = parts.next().unwrap_or_default().trim().to_string();
    if name.is_empty() {
        return;
    }
    let mut kvs: Vec<(String, String)> = Vec::new();
    let mut flags: Vec<String> = Vec::new();
    for part in parts {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        match part.split_once('=') {
            Some((key, value)) => {
                kvs.push((key.trim().to_ascii_lowercase(), value.trim().to_string()))
            }
            None => flags.push(part.to_ascii_lowercase()),
        }
    }
    let kv = |key: &str| kvs.iter().find(|(k, _)| k == key).map(|(_, v)| v.clone());
    let flag = |key: &str| flags.iter().any(|f| f == key);

    match name.as_str() {
        "obfs-local" | "simple-obfs" => {
            put("plugin", Value::String("obfs".into()));
            let mut opts = Mapping::new();
            if let Some(mode) = kv("obfs") {
                opts.insert(Value::String("mode".into()), Value::String(mode));
            }
            if let Some(host) = kv("obfs-host") {
                opts.insert(Value::String("host".into()), Value::String(host));
            }
            put_plugin_opts(opts, put);
        }
        "v2ray-plugin" => {
            put("plugin", Value::String("v2ray-plugin".into()));
            let mut opts = Mapping::new();
            if let Some(mode) = kv("mode") {
                opts.insert(Value::String("mode".into()), Value::String(mode));
            }
            if let Some(host) = kv("host") {
                opts.insert(Value::String("host".into()), Value::String(host));
            }
            if let Some(path) = kv("path") {
                opts.insert(Value::String("path".into()), Value::String(path));
            }
            if flag("tls") {
                opts.insert(Value::String("tls".into()), Value::Bool(true));
            }
            if flag("mux") {
                opts.insert(Value::String("mux".into()), Value::Bool(true));
            }
            if flag("skipverify") {
                opts.insert(Value::String("skip-cert-verify".into()), Value::Bool(true));
            }
            put_plugin_opts(opts, put);
        }
        "shadow-tls" => {
            put("plugin", Value::String("shadow-tls".into()));
            let mut opts = Mapping::new();
            if let Some(host) = kv("host") {
                opts.insert(Value::String("host".into()), Value::String(host));
            }
            if let Some(password) = kv("password") {
                opts.insert(Value::String("password".into()), Value::String(password));
            }
            if let Some(version) = kv("version") {
                let value = match version.parse::<i64>() {
                    Ok(n) => num(n),
                    Err(_) => Value::String(version),
                };
                opts.insert(Value::String("version".into()), value);
            }
            put_plugin_opts(opts, put);
        }
        // Unknown plugin: pass name and raw options through so a capable
        // mihomo (restls, …) can still consume them.
        _ => {
            put("plugin", Value::String(name));
            let mut opts = Mapping::new();
            for (key, value) in kvs {
                opts.insert(Value::String(key), Value::String(value));
            }
            for f in flags {
                opts.insert(Value::String(f), Value::Bool(true));
            }
            put_plugin_opts(opts, put);
        }
    }
}

fn put_plugin_opts(opts: Mapping, put: &mut impl FnMut(&str, Value)) {
    if !opts.is_empty() {
        put("plugin-opts", Value::Mapping(opts));
    }
}

/// List lookup inside an optional parsed YAML mapping.
fn yaml_list(map: &Option<Mapping>, key: &str) -> Option<Vec<String>> {
    let seq = map.as_ref()?.get(key).and_then(Value::as_sequence)?;
    let list: Vec<String> = seq
        .iter()
        .filter_map(Value::as_str)
        .filter(|s| !s.trim().is_empty())
        .map(|s| s.trim().to_string())
        .collect();
    (!list.is_empty()).then_some(list)
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
/// destination key. Lookup is case-insensitive (producers vary the case of
/// e.g. `serviceName`) and the value is leniently percent-decoded.
fn copy_param(entry: &ProxyEntry, src: &str, dst: &str, put: &mut impl FnMut(&str, Value)) {
    if let Some(value) = super::param_value(entry, src) {
        put(dst, Value::String(value));
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

    /// Parse a raw subscription line into an entry (panics on failure).
    fn parse(line: &str) -> ProxyEntry {
        match crate::parsers::parse_line(line) {
            crate::parsers::LineOutcome::Parsed(entry) => entry,
            other => panic!("expected parsed entry, got {other:?}"),
        }
    }

    #[test]
    fn vless_maps_credentials_and_params() {
        let e = entry(
            Scheme::Vless,
            "uuid-1",
            &[
                ("security", "tls"),
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
        // TLS goes through the `tls` toggle + `servername`.
        assert_eq!(field(&v, "tls").and_then(Value::as_bool), Some(true));
        assert_eq!(str_field(&v, "servername"), Some("sni.example.com"));
        assert_eq!(str_field(&v, "client-fingerprint"), Some("chrome"));
        // REALITY keys live under reality-opts, gRPC name under grpc-opts.
        let reality = field(&v, "reality-opts").unwrap().as_mapping().unwrap();
        assert_eq!(
            reality
                .get(Value::from("public-key"))
                .and_then(Value::as_str),
            Some("key")
        );
        assert_eq!(
            reality.get(Value::from("short-id")).and_then(Value::as_str),
            Some("short")
        );
        assert_eq!(str_field(&v, "network"), Some("ws"));
        let ws = field(&v, "ws-opts").unwrap().as_mapping().unwrap();
        assert_eq!(
            ws.get(Value::from("path")).and_then(Value::as_str),
            Some("/ws")
        );
        // No insecure toggle on the entry — no skip-cert-verify.
        assert!(field(&v, "skip-cert-verify").is_none());
    }

    #[test]
    fn raw_vless_tls_ws_line_maps_completely() {
        let line = "vless://uuid-1@h.example.com:443?encryption=none&security=tls&sni=sni.example.com&fp=chrome&type=ws&host=ws.example.com&path=%2Fws%3Fed%3D2560&allowInsecure=1#Name";
        let e = parse(line);
        let v = entry_to_clash(&e).unwrap();
        assert_eq!(field(&v, "tls").and_then(Value::as_bool), Some(true));
        assert_eq!(str_field(&v, "servername"), Some("sni.example.com"));
        assert_eq!(str_field(&v, "client-fingerprint"), Some("chrome"));
        assert_eq!(str_field(&v, "network"), Some("ws"));
        let ws = field(&v, "ws-opts").unwrap().as_mapping().unwrap();
        // `host` param becomes the ws Host header; path is decoded.
        assert_eq!(
            ws.get(Value::from("path")).and_then(Value::as_str),
            Some("/ws?ed=2560")
        );
        let headers = ws
            .get(Value::from("headers"))
            .unwrap()
            .as_mapping()
            .unwrap();
        assert_eq!(
            headers.get(Value::from("Host")).and_then(Value::as_str),
            Some("ws.example.com")
        );
        assert_eq!(
            field(&v, "skip-cert-verify").and_then(Value::as_bool),
            Some(true)
        );
    }

    #[test]
    fn raw_vless_reality_grpc_line_maps_completely() {
        let line = "vless://uuid-1@h.example.com:443?security=reality&sni=s.example.com&fp=chrome&pbk=pub-key&sid=01ab&type=grpc&serviceName=gr-svc&flow=xtls-rprx-vision#Name";
        let e = parse(line);
        let v = entry_to_clash(&e).unwrap();
        assert_eq!(field(&v, "tls").and_then(Value::as_bool), Some(true));
        assert_eq!(str_field(&v, "servername"), Some("s.example.com"));
        let reality = field(&v, "reality-opts").unwrap().as_mapping().unwrap();
        assert_eq!(
            reality
                .get(Value::from("public-key"))
                .and_then(Value::as_str),
            Some("pub-key")
        );
        assert_eq!(
            reality.get(Value::from("short-id")).and_then(Value::as_str),
            Some("01ab")
        );
        assert_eq!(str_field(&v, "network"), Some("grpc"));
        let grpc = field(&v, "grpc-opts").unwrap().as_mapping().unwrap();
        assert_eq!(
            grpc.get(Value::from("grpc-service-name"))
                .and_then(Value::as_str),
            Some("gr-svc")
        );
    }

    #[test]
    fn raw_vless_httpupgrade_becomes_ws_with_upgrade_toggle() {
        let line = "vless://uuid-1@h.example.com:443?security=tls&sni=s.example.com&type=httpupgrade&path=%2Fup&host=up.example.com#Name";
        let e = parse(line);
        let v = entry_to_clash(&e).unwrap();
        assert_eq!(str_field(&v, "network"), Some("ws"));
        let ws = field(&v, "ws-opts").unwrap().as_mapping().unwrap();
        assert_eq!(
            ws.get(Value::from("v2ray-http-upgrade"))
                .and_then(Value::as_bool),
            Some(true)
        );
        assert_eq!(
            ws.get(Value::from("path")).and_then(Value::as_str),
            Some("/up")
        );
    }

    #[test]
    fn raw_vless_tcp_header_http_becomes_http_network() {
        let line = "vless://uuid-1@h.example.com:80?type=tcp&headerType=http&path=%2Fhp&host=hp.example.com#Name";
        let e = parse(line);
        let v = entry_to_clash(&e).unwrap();
        assert_eq!(str_field(&v, "network"), Some("http"));
        let http = field(&v, "http-opts").unwrap().as_mapping().unwrap();
        assert_eq!(
            http.get(Value::from("path"))
                .and_then(Value::as_sequence)
                .unwrap()[0]
                .as_str(),
            Some("/hp")
        );
        // `type=http` alone is Xray's HTTP/2 spelling → h2.
        let line2 = "vless://uuid-1@h.example.com:443?security=tls&type=http&path=%2Fh2&host=a.example.com,b.example.com#Name";
        let e2 = parse(line2);
        let v2 = entry_to_clash(&e2).unwrap();
        assert_eq!(str_field(&v2, "network"), Some("h2"));
        let h2 = field(&v2, "h2-opts").unwrap().as_mapping().unwrap();
        assert_eq!(
            h2.get(Value::from("host"))
                .and_then(Value::as_sequence)
                .unwrap()
                .len(),
            2
        );
    }

    #[test]
    fn raw_vmess_json_tls_ws_maps_completely() {
        let json = r#"{"v":"2","ps":"n","add":"h.example.com","port":"443","id":"uuid-2","aid":"0","scy":"auto","net":"ws","host":"ws.example.com","path":"/vmess","tls":"tls","sni":"s.example.com"}"#;
        let b64 = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD_NO_PAD,
            json.as_bytes(),
        );
        let line = format!("vmess://{b64}");
        let e = parse(&line);
        let v = entry_to_clash(&e).unwrap();
        // vmess TLS is spelled `tls: "tls"` in the JSON, not `security=tls`.
        assert_eq!(field(&v, "tls").and_then(Value::as_bool), Some(true));
        assert_eq!(str_field(&v, "servername"), Some("s.example.com"));
        assert_eq!(str_field(&v, "network"), Some("ws"));
        let ws = field(&v, "ws-opts").unwrap().as_mapping().unwrap();
        assert_eq!(
            ws.get(Value::from("path")).and_then(Value::as_str),
            Some("/vmess")
        );
        let headers = ws
            .get(Value::from("headers"))
            .unwrap()
            .as_mapping()
            .unwrap();
        assert_eq!(
            headers.get(Value::from("Host")).and_then(Value::as_str),
            Some("ws.example.com")
        );
    }

    #[test]
    fn raw_trojan_grpc_line_maps_completely() {
        let line = "trojan://pass@h.example.com:443?security=tls&sni=t.example.com&type=grpc&serviceName=t-svc&fp=chrome&alpn=h2,http/1.1#Name";
        let e = parse(line);
        let v = entry_to_clash(&e).unwrap();
        assert_eq!(str_field(&v, "sni"), Some("t.example.com"));
        assert_eq!(str_field(&v, "client-fingerprint"), Some("chrome"));
        assert_eq!(str_field(&v, "network"), Some("grpc"));
        let grpc = field(&v, "grpc-opts").unwrap().as_mapping().unwrap();
        assert_eq!(
            grpc.get(Value::from("grpc-service-name"))
                .and_then(Value::as_str),
            Some("t-svc")
        );
        let alpn = field(&v, "alpn").and_then(Value::as_sequence).unwrap();
        assert_eq!(alpn.len(), 2);
    }

    #[test]
    fn raw_hysteria2_line_maps_obfs_and_rates() {
        let line = "hysteria2://hy-pass@h.example.com:443?sni=hy.example.com&obfs=salamander&obfs-password=ob-pass&upMbps=50&downMbps=200&pinSHA256=ab12&alpn=h3#Name";
        let e = parse(line);
        let v = entry_to_clash(&e).unwrap();
        assert_eq!(str_field(&v, "sni"), Some("hy.example.com"));
        assert_eq!(str_field(&v, "obfs"), Some("salamander"));
        assert_eq!(str_field(&v, "obfs-password"), Some("ob-pass"));
        assert_eq!(str_field(&v, "up"), Some("50"));
        assert_eq!(str_field(&v, "down"), Some("200"));
        assert_eq!(str_field(&v, "fingerprint"), Some("ab12"));
        assert_eq!(
            field(&v, "alpn")
                .and_then(Value::as_sequence)
                .unwrap()
                .len(),
            1
        );
    }

    #[test]
    fn raw_ss_line_maps_plugin() {
        let blob = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD_NO_PAD,
            b"aes-256-gcm:secret",
        );
        let line = format!(
            "ss://{blob}@h.example.com:8388/?plugin=obfs-local%3Bobfs%3Dhttp%3Bobfs-host%3Dob.example.com#Name"
        );
        let e = parse(&line);
        let v = entry_to_clash(&e).unwrap();
        assert_eq!(str_field(&v, "plugin"), Some("obfs"));
        let opts = field(&v, "plugin-opts").unwrap().as_mapping().unwrap();
        assert_eq!(
            opts.get(Value::from("mode")).and_then(Value::as_str),
            Some("http")
        );
        assert_eq!(
            opts.get(Value::from("host")).and_then(Value::as_str),
            Some("ob.example.com")
        );
    }

    #[test]
    fn raw_ss_line_maps_v2ray_plugin() {
        let blob = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD_NO_PAD,
            b"aes-256-gcm:secret",
        );
        let line = format!(
            "ss://{blob}@h.example.com:8388/?plugin=v2ray-plugin%3Bmode%3Dwebsocket%3Btls%3Bhost%3Dvp.example.com%3Bpath%3D%2Fvp#Name"
        );
        let e = parse(&line);
        let v = entry_to_clash(&e).unwrap();
        assert_eq!(str_field(&v, "plugin"), Some("v2ray-plugin"));
        let opts = field(&v, "plugin-opts").unwrap().as_mapping().unwrap();
        assert_eq!(
            opts.get(Value::from("mode")).and_then(Value::as_str),
            Some("websocket")
        );
        assert_eq!(
            opts.get(Value::from("tls")).and_then(Value::as_bool),
            Some(true)
        );
        assert_eq!(
            opts.get(Value::from("host")).and_then(Value::as_str),
            Some("vp.example.com")
        );
        assert_eq!(
            opts.get(Value::from("path")).and_then(Value::as_str),
            Some("/vp")
        );
    }

    #[test]
    fn clash_input_structured_opts_survive_the_pipeline() {
        let yaml = "proxies:\n  - name: in\n    type: vless\n    server: h.example.com\n    port: 443\n    uuid: uuid-3\n    network: ws\n    tls: true\n    servername: s.example.com\n    ws-opts:\n      path: /ws\n      headers:\n        Host: ws.example.com\n";
        let result = crate::parsers::clash::parse_payload(yaml).unwrap();
        let e = &result.entries[0];
        let v = entry_to_clash(e).unwrap();
        assert_eq!(field(&v, "tls").and_then(Value::as_bool), Some(true));
        assert_eq!(str_field(&v, "servername"), Some("s.example.com"));
        assert_eq!(str_field(&v, "network"), Some("ws"));
        let ws = field(&v, "ws-opts").unwrap().as_mapping().unwrap();
        assert_eq!(
            ws.get(Value::from("path")).and_then(Value::as_str),
            Some("/ws")
        );
        let headers = ws
            .get(Value::from("headers"))
            .unwrap()
            .as_mapping()
            .unwrap();
        assert_eq!(
            headers.get(Value::from("Host")).and_then(Value::as_str),
            Some("ws.example.com")
        );
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
