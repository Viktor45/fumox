//! Clash/Mihomo YAML output.
//!
//! The emitted document carries only the `proxies:` list; mihomo fills the
//! rest with its defaults. An empty profile yields a valid `proxies: []`
//! document.
//!
//! The mapping follows the mihomo proxy schema: TLS is enabled by
//! `security=tls|reality` (vless/trojan) or the vmess `tls` field, REALITY
//! keys go under `reality-opts`, and transports are emitted as the nested
//! `ws-opts`/`grpc-opts`/`h2-opts`/`http-opts` blocks mihomo actually reads.
//! URI parameters travel under their native keys (`type` for the network of
//! vless/trojan, `net` for vmess), while Clash-input entries already carry
//! the mihomo keys (`network`, `ws-path`, structured YAML opts), both
//! spellings are accepted everywhere.
//!
//! This is also the mapping used by the probe's T2 generator, which
//! overrides the name and strips the insecure parameters before calling it.

use crate::models::{ProxyEntry, Scheme};
use crate::params::Blocks;
use serde_norway::{Mapping, Value};

/// Schemes with a mihomo counterpart; everything else is skipped in output
/// (log-and-skip principle, never fatal).
///
/// The mapping below is the authority: this asks it instead of keeping a
/// second list of schemes, so the query and the mapping cannot drift
/// apart. A caller that already holds an entry can simply ask the mapping
/// itself — a `None` means "no mihomo counterpart".
pub fn is_supported(scheme: Scheme) -> bool {
    entry_to_clash_named(&bare_entry(scheme), "").is_some()
}

/// An entry that carries nothing but a scheme, for the support question.
fn bare_entry(scheme: Scheme) -> ProxyEntry {
    ProxyEntry {
        scheme,
        name: String::new(),
        host: String::new(),
        port: 0,
        credential: String::new(),
        params: Vec::new(),
        raw_path: String::new(),
        raw_line: String::new(),
        canonical: None,
    }
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
    // The structured blocks are parsed once for the whole entry and handed
    // to the writers below: every one of them used to re-parse the same
    // feed-controlled YAML text.
    let blocks = Blocks::of(entry);

    put("name", Value::String(name.to_string()));
    put("server", Value::String(entry.host.clone()));
    put("port", num(i64::from(entry.port)));

    match entry.scheme {
        Scheme::Vless => {
            put("type", Value::String("vless".into()));
            put("uuid", Value::String(entry.credential.clone()));
            copy_param(entry, "flow", "flow", &mut put);
            // One shared decision on whether the proxy is wrapped; the
            // sing-box writer asks the same question.
            if crate::params::wants_tls(entry, &blocks) {
                put("tls", Value::Bool(true));
                copy_param(entry, "sni", "servername", &mut put);
                copy_param(entry, "servername", "servername", &mut put);
            }
            copy_param(entry, "fp", "client-fingerprint", &mut put);
            copy_param(entry, "client-fingerprint", "client-fingerprint", &mut put);
            put_reality_opts(entry, &blocks, &mut put);
            put_alpn(entry, &mut put);
            put_transport(entry, "type", &blocks, &mut put);
        }
        Scheme::Vmess => {
            put("type", Value::String("vmess".into()));
            put("uuid", Value::String(entry.credential.clone()));
            // One shared reader, one type (u64, a negative value is 0) for
            // both encoders.
            put("alterId", Value::Number(super::alter_id(entry).into()));
            let cipher = super::param_value(entry, "scy")
                .or_else(|| super::param_value(entry, "cipher"))
                .unwrap_or_else(|| "auto".into());
            put("cipher", Value::String(cipher));
            // vmess JSON carries TLS in `tls: "tls"`; Clash input uses the
            // boolean `tls: true`; some feeds spell it `security=tls`.
            if crate::params::wants_tls(entry, &blocks) {
                put("tls", Value::Bool(true));
                copy_param(entry, "sni", "servername", &mut put);
                copy_param(entry, "servername", "servername", &mut put);
            }
            copy_param(entry, "fp", "client-fingerprint", &mut put);
            copy_param(entry, "client-fingerprint", "client-fingerprint", &mut put);
            put_alpn(entry, &mut put);
            put_transport(entry, "net", &blocks, &mut put);
        }
        Scheme::Trojan => {
            put("type", Value::String("trojan".into()));
            put("password", Value::String(entry.credential.clone()));
            copy_param(entry, "sni", "sni", &mut put);
            copy_param(entry, "flow", "flow", &mut put);
            copy_param(entry, "fp", "client-fingerprint", &mut put);
            copy_param(entry, "client-fingerprint", "client-fingerprint", &mut put);
            put_reality_opts(entry, &blocks, &mut put);
            put_alpn(entry, &mut put);
            put_transport(entry, "type", &blocks, &mut put);
        }
        Scheme::Ss => {
            put("type", Value::String("ss".into()));
            // The shared splitter owns the missing/empty-method fallback
            // (see `parsers::clash` `SS_SPEC` for the parse-time
            // canonicalization).
            let (cipher, password) = super::split_ss_credential(&entry.credential);
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
            // Credential is stored as "user:pass"; both parts are optional,
            // and a colon-less credential is all username (the shared
            // splitter owns the decision).
            let (user, password) = super::split_user_password(&entry.credential);
            if !user.is_empty() {
                put("username", Value::String(user.to_string()));
            }
            if !password.is_empty() {
                put("password", Value::String(password.to_string()));
            }
            if super::param_truthy(entry, "tls") {
                put("tls", Value::Bool(true));
            }
        }
        Scheme::Snell => {
            put("type", Value::String("snell".into()));
            // meow-rs names the secret `psk`; the URI keeps it as the
            // userinfo, so the credential maps straight across.
            put("psk", Value::String(entry.credential.clone()));
            // Omitted entirely when the feed does not say: meow's own
            // default is v4, and writing an explicit default here would
            // pin every entry to a value the operator never chose.
            if let Some(version) = super::param_value(entry, "version") {
                put("version", Value::String(version.to_string()));
            }
            // Only emitted when asked, so a false cannot become "true"
            // through a string round-trip. `udp` comes from the shared
            // tail below, which also covers the Clash-input case.
            if super::param_truthy(entry, "reuse") {
                put("reuse", Value::Bool(true));
            }
            // Both keys pass through verbatim, including the combinations
            // meow rejects (obfs-opts on v6, mode on older). It drops those
            // items rather than failing the config, so the T2 check 404s and
            // charges the proxy, which is the honest verdict.
            if let Some(mode) = super::param_value(entry, "mode") {
                put("mode", Value::String(mode.to_string()));
            }
            // A Clash feed keeps the nested `obfs-opts` block, a URI feed the
            // flat `obfs` / `obfs-host` pair. The flat form wins, as in put_ws_opts.
            let obfs =
                super::param_value(entry, "obfs").or_else(|| super::map_str(&blocks.obfs, "mode"));
            let obfs_host = super::param_value(entry, "obfs-host")
                .or_else(|| super::map_str(&blocks.obfs, "host"));
            if obfs.is_some() || obfs_host.is_some() {
                let mut opts = Mapping::new();
                // meow treats an absent obfs as off, and so do we: only a
                // host without a mode would be ambiguous.
                opts.insert(
                    Value::String("mode".into()),
                    Value::String(obfs.clone().unwrap_or_else(|| "off".to_string())),
                );
                if let Some(host) = obfs_host {
                    opts.insert(Value::String("host".into()), Value::String(host));
                }
                put("obfs-opts", Value::Mapping(opts));
            }
        }
        Scheme::AnyTls => {
            put("type", Value::String("anytls".into()));
            put("password", Value::String(entry.credential.clone()));
            // meow's anytls parser reads `sni` only; it has no
            // client-fingerprint knob, so `fp` is deliberately not mapped.
            copy_param(entry, "sni", "sni", &mut put);
            // skip-cert-verify and udp come from the shared tail below.
        }
        Scheme::Naive | Scheme::Tuic | Scheme::Mieru => return None,
    }

    if super::is_insecure(entry) {
        put("skip-cert-verify", Value::Bool(true));
    }
    // Clash-input entries keep their `udp` toggle; URI feeds don't carry one.
    if super::param_truthy(entry, "udp") {
        put("udp", Value::Bool(true));
    }

    Some(Value::Mapping(m))
}

/// `reality-opts: {public-key, short-id}` from URI `pbk`/`sid` params or a
/// Clash-input `reality-opts` block. Emitted only when at least one key is
/// present, an empty block would make mihomo reject the proxy.
fn put_reality_opts(entry: &ProxyEntry, blocks: &Blocks, put: &mut impl FnMut(&str, Value)) {
    let reality = crate::params::reality(entry, blocks);
    if reality.is_empty() {
        return;
    }
    let mut opts = Mapping::new();
    if let Some(pbk) = reality.public_key {
        opts.insert(Value::String("public-key".into()), Value::String(pbk));
    }
    if let Some(sid) = reality.short_id {
        opts.insert(Value::String("short-id".into()), Value::String(sid));
    }
    put("reality-opts", Value::Mapping(opts));
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
fn put_transport(
    entry: &ProxyEntry,
    uri_key: &str,
    blocks: &Blocks,
    put: &mut impl FnMut(&str, Value),
) {
    let network = match super::network_of(entry, uri_key) {
        Some(n) => n,
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
                put_http_opts(entry, blocks, put);
            }
        }
        "ws" | "httpupgrade" => {
            put("network", Value::String("ws".into()));
            put_ws_opts(entry, blocks, network == "httpupgrade", put);
        }
        "grpc" => {
            put("network", Value::String("grpc".into()));
            put_grpc_opts(entry, blocks, put);
        }
        "h2" => {
            put("network", Value::String("h2".into()));
            put_h2_opts(entry, blocks, put);
        }
        "http" => {
            if entry.scheme == Scheme::Vmess || param_value_is(entry, "headerType", "http") {
                put("network", Value::String("http".into()));
                put_http_opts(entry, blocks, put);
            } else {
                put("network", Value::String("h2".into()));
                put_h2_opts(entry, blocks, put);
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
fn put_ws_opts(
    entry: &ProxyEntry,
    blocks: &Blocks,
    http_upgrade: bool,
    put: &mut impl FnMut(&str, Value),
) {
    let path = super::param_value(entry, "path").or_else(|| super::map_str(&blocks.ws, "path"));
    let host = super::param_value(entry, "host")
        .or_else(|| super::map_str(&blocks.ws_headers, "host"))
        .or_else(|| nested_host(&blocks.ws));
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
///
/// mihomo's `ws-opts.headers` maps a name to one value, so only the first
/// host of a multi-host header survives.
fn nested_host(ws_yaml: &Option<Mapping>) -> Option<String> {
    super::map_header(ws_yaml).and_then(|hosts| hosts.into_iter().next())
}

/// `grpc-opts: {grpc-service-name}`. vmess JSON carries the gRPC service
/// name in its `path` field, so that is the vmess fallback.
fn put_grpc_opts(entry: &ProxyEntry, blocks: &Blocks, put: &mut impl FnMut(&str, Value)) {
    let mut service = super::param_value(entry, "serviceName")
        .or_else(|| super::map_str(&blocks.grpc, "grpc-service-name"))
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
fn put_h2_opts(entry: &ProxyEntry, blocks: &Blocks, put: &mut impl FnMut(&str, Value)) {
    let path = super::param_value(entry, "path").or_else(|| super::map_str(&blocks.h2, "path"));
    // The one "value as a list" helper: the URI `host` splits on commas, the
    // block's `host` keeps its sequence items or splits a scalar the same
    // way (`params::list` / `params::map_list`).
    let hosts = super::param_list(entry, "host").or_else(|| super::map_list(&blocks.h2, "host"));
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
fn put_http_opts(entry: &ProxyEntry, blocks: &Blocks, put: &mut impl FnMut(&str, Value)) {
    let path = super::param_value(entry, "path").or_else(|| super::map_first(&blocks.http, "path"));
    let host = super::param_value(entry, "host")
        .or_else(|| super::map_header(&blocks.http).and_then(|h| h.into_iter().next()));
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

/// Encode the final candidate list as a Clash YAML document. Duplicate
/// names are suffixed « (2)», « (3)»…
pub fn encode_clash(entries: &[ProxyEntry]) -> String {
    let items = super::encode_entries(entries, "name", entry_to_clash);

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
    use crate::formats::test_util::{Fields, b64, entry, parse};

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
        assert_eq!(v.str_field("type"), Some("vless"));
        assert_eq!(v.str_field("name"), Some("proxy"));
        assert_eq!(v.str_field("server"), Some("example.com"));
        assert_eq!(v.field("port").and_then(Value::as_u64), Some(443));
        assert_eq!(v.str_field("uuid"), Some("uuid-1"));
        assert_eq!(v.str_field("flow"), Some("xtls-rprx-vision"));
        // TLS goes through the `tls` toggle + `servername`.
        assert_eq!(v.field("tls").and_then(Value::as_bool), Some(true));
        assert_eq!(v.str_field("servername"), Some("sni.example.com"));
        assert_eq!(v.str_field("client-fingerprint"), Some("chrome"));
        // REALITY keys live under reality-opts, gRPC name under grpc-opts.
        let reality = v.field("reality-opts").unwrap().as_mapping().unwrap();
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
        assert_eq!(v.str_field("network"), Some("ws"));
        let ws = v.field("ws-opts").unwrap().as_mapping().unwrap();
        assert_eq!(
            ws.get(Value::from("path")).and_then(Value::as_str),
            Some("/ws")
        );
        // No insecure toggle on the entry, no skip-cert-verify.
        assert!(v.field("skip-cert-verify").is_none());
    }

    #[test]
    fn raw_vless_tls_ws_line_maps_completely() {
        let line = "vless://uuid-1@h.example.com:443?encryption=none&security=tls&sni=sni.example.com&fp=chrome&type=ws&host=ws.example.com&path=%2Fws%3Fed%3D2560&allowInsecure=1#Name";
        let e = parse(line);
        let v = entry_to_clash(&e).unwrap();
        assert_eq!(v.field("tls").and_then(Value::as_bool), Some(true));
        assert_eq!(v.str_field("servername"), Some("sni.example.com"));
        assert_eq!(v.str_field("client-fingerprint"), Some("chrome"));
        assert_eq!(v.str_field("network"), Some("ws"));
        let ws = v.field("ws-opts").unwrap().as_mapping().unwrap();
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
            v.field("skip-cert-verify").and_then(Value::as_bool),
            Some(true)
        );
    }

    #[test]
    fn raw_vless_reality_grpc_line_maps_completely() {
        let line = "vless://uuid-1@h.example.com:443?security=reality&sni=s.example.com&fp=chrome&pbk=pub-key&sid=01ab&type=grpc&serviceName=gr-svc&flow=xtls-rprx-vision#Name";
        let e = parse(line);
        let v = entry_to_clash(&e).unwrap();
        assert_eq!(v.field("tls").and_then(Value::as_bool), Some(true));
        assert_eq!(v.str_field("servername"), Some("s.example.com"));
        let reality = v.field("reality-opts").unwrap().as_mapping().unwrap();
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
        assert_eq!(v.str_field("network"), Some("grpc"));
        let grpc = v.field("grpc-opts").unwrap().as_mapping().unwrap();
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
        assert_eq!(v.str_field("network"), Some("ws"));
        let ws = v.field("ws-opts").unwrap().as_mapping().unwrap();
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
        assert_eq!(v.str_field("network"), Some("http"));
        let http = v.field("http-opts").unwrap().as_mapping().unwrap();
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
        assert_eq!(v2.str_field("network"), Some("h2"));
        let h2 = v2.field("h2-opts").unwrap().as_mapping().unwrap();
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
        let line = format!("vmess://{}", b64(json.as_bytes()));
        let e = parse(&line);
        let v = entry_to_clash(&e).unwrap();
        // vmess TLS is spelled `tls: "tls"` in the JSON, not `security=tls`.
        assert_eq!(v.field("tls").and_then(Value::as_bool), Some(true));
        assert_eq!(v.str_field("servername"), Some("s.example.com"));
        assert_eq!(v.str_field("network"), Some("ws"));
        let ws = v.field("ws-opts").unwrap().as_mapping().unwrap();
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
        assert_eq!(v.str_field("sni"), Some("t.example.com"));
        assert_eq!(v.str_field("client-fingerprint"), Some("chrome"));
        assert_eq!(v.str_field("network"), Some("grpc"));
        let grpc = v.field("grpc-opts").unwrap().as_mapping().unwrap();
        assert_eq!(
            grpc.get(Value::from("grpc-service-name"))
                .and_then(Value::as_str),
            Some("t-svc")
        );
        let alpn = v.field("alpn").and_then(Value::as_sequence).unwrap();
        assert_eq!(alpn.len(), 2);
    }

    #[test]
    fn raw_hysteria2_line_maps_obfs_and_rates() {
        let line = "hysteria2://hy-pass@h.example.com:443?sni=hy.example.com&obfs=salamander&obfs-password=ob-pass&upMbps=50&downMbps=200&pinSHA256=ab12&alpn=h3#Name";
        let e = parse(line);
        let v = entry_to_clash(&e).unwrap();
        assert_eq!(v.str_field("sni"), Some("hy.example.com"));
        assert_eq!(v.str_field("obfs"), Some("salamander"));
        assert_eq!(v.str_field("obfs-password"), Some("ob-pass"));
        assert_eq!(v.str_field("up"), Some("50"));
        assert_eq!(v.str_field("down"), Some("200"));
        assert_eq!(v.str_field("fingerprint"), Some("ab12"));
        assert_eq!(
            v.field("alpn").and_then(Value::as_sequence).unwrap().len(),
            1
        );
    }

    #[test]
    fn raw_ss_line_maps_plugin() {
        let blob = b64(b"aes-256-gcm:secret");
        let line = format!(
            "ss://{blob}@h.example.com:8388/?plugin=obfs-local%3Bobfs%3Dhttp%3Bobfs-host%3Dob.example.com#Name"
        );
        let e = parse(&line);
        let v = entry_to_clash(&e).unwrap();
        assert_eq!(v.str_field("plugin"), Some("obfs"));
        let opts = v.field("plugin-opts").unwrap().as_mapping().unwrap();
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
        let blob = b64(b"aes-256-gcm:secret");
        let line = format!(
            "ss://{blob}@h.example.com:8388/?plugin=v2ray-plugin%3Bmode%3Dwebsocket%3Btls%3Bhost%3Dvp.example.com%3Bpath%3D%2Fvp#Name"
        );
        let e = parse(&line);
        let v = entry_to_clash(&e).unwrap();
        assert_eq!(v.str_field("plugin"), Some("v2ray-plugin"));
        let opts = v.field("plugin-opts").unwrap().as_mapping().unwrap();
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
        assert_eq!(v.field("tls").and_then(Value::as_bool), Some(true));
        assert_eq!(v.str_field("servername"), Some("s.example.com"));
        assert_eq!(v.str_field("network"), Some("ws"));
        let ws = v.field("ws-opts").unwrap().as_mapping().unwrap();
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
            v.field("skip-cert-verify").and_then(Value::as_bool),
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
        assert_eq!(v.str_field("type"), Some("vmess"));
        assert_eq!(v.field("tls").and_then(Value::as_bool), Some(true));
        assert_eq!(v.str_field("servername"), Some("s.example.com"));
        assert_eq!(v.field("alterId").and_then(Value::as_u64), Some(4));
        assert_eq!(v.str_field("cipher"), Some("aes-128-gcm"));
    }

    #[test]
    fn ss_credential_splits_into_cipher_and_password() {
        let e = entry(Scheme::Ss, "aes-256-gcm:secret", &[]);
        let v = entry_to_clash(&e).unwrap();
        assert_eq!(v.str_field("cipher"), Some("aes-256-gcm"));
        assert_eq!(v.str_field("password"), Some("secret"));
    }

    #[test]
    fn socks5_credential_is_optional_per_part() {
        let e = entry(Scheme::Socks5, "user:pw", &[]);
        let v = entry_to_clash(&e).unwrap();
        assert_eq!(v.str_field("username"), Some("user"));
        assert_eq!(v.str_field("password"), Some("pw"));
    }

    /// A colon-less socks5 credential is all username: no password is
    /// invented for it, in either encoder.
    #[test]
    fn a_colon_less_socks5_credential_is_all_username() {
        let e = entry(Scheme::Socks5, "onlyuser", &[]);
        let v = entry_to_clash(&e).unwrap();
        assert_eq!(v.str_field("username"), Some("onlyuser"));
        assert!(v.field("password").is_none());
    }

    /// The known `shadow-tls` plugin renders typed options: the version is
    /// a number, the way mihomo's shadow-tls reader wants it.
    #[test]
    fn shadow_tls_plugin_renders_typed_opts() {
        let e = entry(
            Scheme::Ss,
            "aes-256-gcm:secret",
            &[("plugin", "shadow-tls;host=h;password=p;version=3")],
        );
        let v = entry_to_clash(&e).unwrap();
        assert_eq!(v.str_field("plugin"), Some("shadow-tls"));
        let opts = v.field("plugin-opts").unwrap().as_mapping().unwrap();
        assert_eq!(
            opts.get(Value::from("host")).and_then(Value::as_str),
            Some("h")
        );
        assert_eq!(
            opts.get(Value::from("password")).and_then(Value::as_str),
            Some("p")
        );
        assert_eq!(
            opts.get(Value::from("version")).and_then(Value::as_i64),
            Some(3)
        );
    }

    /// An unknown plugin passes the name and raw options through so a
    /// capable mihomo (restls, …) can still consume them; bare flags
    /// become booleans.
    #[test]
    fn restls_plugin_passes_through_with_flag_opts() {
        let e = entry(
            Scheme::Ss,
            "aes-256-gcm:secret",
            &[("plugin", "restls;host=h;tls")],
        );
        let v = entry_to_clash(&e).unwrap();
        assert_eq!(v.str_field("plugin"), Some("restls"));
        let opts = v.field("plugin-opts").unwrap().as_mapping().unwrap();
        assert_eq!(
            opts.get(Value::from("host")).and_then(Value::as_str),
            Some("h")
        );
        assert_eq!(
            opts.get(Value::from("tls")).and_then(Value::as_bool),
            Some(true)
        );
    }

    /// A leading empty method must not render an empty `cipher`: the
    /// shared credential splitter falls back to the default cipher and
    /// keeps what follows the slot as the password.
    #[test]
    fn a_leading_colon_ss_credential_does_not_render_an_empty_cipher() {
        let e = entry(Scheme::Ss, ":secret", &[]);
        let v = entry_to_clash(&e).unwrap();
        assert_eq!(
            v.str_field("cipher"),
            Some(crate::models::DEFAULT_SS_CIPHER)
        );
        assert_eq!(v.str_field("password"), Some("secret"));
    }

    /// The socks5 TLS toggle travels in both encoders; the sing-box side
    /// also carries the server name (see the sing-box module's test).
    #[test]
    fn socks5_tls_emits_the_toggle() {
        let e = entry(
            Scheme::Socks5,
            "u:p",
            &[("tls", "true"), ("sni", "s.example.com")],
        );
        let v = entry_to_clash(&e).unwrap();
        assert_eq!(v.field("tls").and_then(Value::as_bool), Some(true));
    }

    /// vmess JSON spells the plain-HTTP header obfuscation
    /// `net: tcp, type: http`: the writer reduces it to its `http`
    /// transport with the path as a one-item list.
    #[test]
    fn raw_vmess_tcp_http_header_maps_to_http_network() {
        let json = r#"{"v":"2","ps":"n","add":"h.example.com","port":"443","id":"uuid-3","aid":"0","scy":"auto","net":"tcp","type":"http","path":"/hp","host":"hp.example.com"}"#;
        let line = format!("vmess://{}", b64(json.as_bytes()));
        let e = parse(&line);
        let v = entry_to_clash(&e).unwrap();
        assert_eq!(v.str_field("network"), Some("http"));
        let http = v.field("http-opts").unwrap().as_mapping().unwrap();
        assert_eq!(
            http.get(Value::from("path"))
                .and_then(Value::as_sequence)
                .unwrap()[0]
                .as_str(),
            Some("/hp")
        );
    }

    // Round-trip tests: a Clash item parsed by `crate::parsers::clash`
    // must render back through the writers below to something meow-rs
    // accepts, otherwise a Clash subscription loses the proxy on every
    // export. They live next to the writers they exercise.

    /// The two schemes must survive a Clash round-trip: a feed entry
    /// parsed to an entry must render back to something meow-rs accepts,
    /// otherwise a Clash subscription would lose them on every export.
    #[test]
    fn snell_and_anytls_round_trip_through_the_clash_writer() {
        let yaml = concat!(
            "proxies:\n",
            "  - {name: s, type: snell, server: 1.2.3.4, port: 44046, psk: psk, ",
            "version: 6, mode: unshaped, reuse: true, ",
            "obfs-opts: {mode: tls, host: bing.com}}\n",
            "  - {name: a, type: anytls, server: 5.6.7.8, port: 443, ",
            "password: pw, sni: a.example.com, skip-cert-verify: true}\n",
        );
        let result = crate::parsers::clash::parse_payload(yaml).unwrap();
        assert_eq!(result.entries.len(), 2);

        let snell = entry_to_clash(&result.entries[0]).unwrap();
        assert_eq!(snell.get("type").and_then(|v| v.as_str()), Some("snell"));
        assert_eq!(snell.get("psk").and_then(|v| v.as_str()), Some("psk"));
        assert_eq!(snell.get("version").and_then(|v| v.as_str()), Some("6"));
        assert_eq!(snell.get("mode").and_then(|v| v.as_str()), Some("unshaped"));
        assert_eq!(snell.get("reuse").and_then(|v| v.as_bool()), Some(true));
        // meow-rs reads obfs as a block; the writer must not flatten it.
        assert_eq!(
            snell
                .get("obfs-opts")
                .and_then(|v| v.get("mode"))
                .and_then(|v| v.as_str()),
            Some("tls")
        );
        assert_eq!(
            snell
                .get("obfs-opts")
                .and_then(|v| v.get("host"))
                .and_then(|v| v.as_str()),
            Some("bing.com")
        );

        let anytls = entry_to_clash(&result.entries[1]).unwrap();
        assert_eq!(anytls.get("type").and_then(|v| v.as_str()), Some("anytls"));
        assert_eq!(anytls.get("password").and_then(|v| v.as_str()), Some("pw"));
        assert_eq!(
            anytls.get("sni").and_then(|v| v.as_str()),
            Some("a.example.com")
        );
        assert_eq!(
            anytls.get("skip-cert-verify").and_then(|v| v.as_bool()),
            Some(true)
        );
    }

    /// A leading absent credential field must not leave an empty slot: the
    /// writers split on `:` and would read `":pw"` as an empty cipher. The
    /// parser drops the slot and canonicalizes the default cipher (see
    /// `parsers::clash` `SS_SPEC`), so [`entry_to_clash`] reads a complete
    /// credential. A trailing one must keep its slot, or the writers lose
    /// the field in front of it (`onlyuser` carries no password to recover,
    /// and no username either once the split fails).
    #[test]
    fn a_missing_cipher_keeps_the_password_usable() {
        let yaml = "proxies:\n  - {name: s, type: ss, server: h, port: 8388, password: pw}\n";
        let result = crate::parsers::clash::parse_payload(yaml).unwrap();
        assert_eq!(result.entries[0].credential, "chacha20-ietf-poly1305:pw");
        let clash = entry_to_clash(&result.entries[0]).unwrap();
        assert_eq!(
            clash.get("cipher").and_then(|v| v.as_str()),
            Some("chacha20-ietf-poly1305")
        );
        assert_eq!(clash.get("password").and_then(|v| v.as_str()), Some("pw"));
    }

    /// The mirror of the case above: a socks5 item carrying only a
    /// `password` must keep its empty leading slot, because the socks5
    /// credential handling in [`entry_to_clash`] (and in
    /// `formats::singbox::entry_to_outbound`) skips empty parts — both
    /// parts are optional — while a colon-less credential is all username
    /// (see `formats::split_user_password`).
    #[test]
    fn a_password_only_socks5_keeps_its_credential() {
        let yaml =
            "proxies:\n  - {name: s, type: socks5, server: h, port: 1080, password: onlypass}\n";
        let result = crate::parsers::clash::parse_payload(yaml).unwrap();
        let e = &result.entries[0];
        assert_eq!(e.credential, ":onlypass");

        let clash = entry_to_clash(e).unwrap();
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
    fn unsupported_schemes_are_skipped() {
        assert!(entry_to_clash(&entry(Scheme::Tuic, "c", &[])).is_none());
        assert!(entry_to_clash(&entry(Scheme::Mieru, "c", &[])).is_none());
        assert!(entry_to_clash(&entry(Scheme::Naive, "c", &[])).is_none());
        // snell/anytls have mapping arms and are meow-tunnelable; a
        // regression here silently strips them from Clash subscriptions.
        assert!(entry_to_clash(&entry(Scheme::Snell, "c", &[])).is_some());
        assert!(entry_to_clash(&entry(Scheme::AnyTls, "c", &[])).is_some());
    }

    #[test]
    fn snell_and_anytls_are_supported_and_rendered() {
        assert!(is_supported(Scheme::Snell));
        assert!(is_supported(Scheme::AnyTls));

        let snell = entry(
            Scheme::Snell,
            "psk-1",
            &[
                ("version", "4"),
                ("obfs", "http"),
                ("obfs-host", "o.example.com"),
            ],
        );
        let v = entry_to_clash(&snell).unwrap();
        assert_eq!(v.str_field("type"), Some("snell"));
        assert_eq!(v.str_field("psk"), Some("psk-1"));
        assert_eq!(v.str_field("version"), Some("4"));
        let obfs = v.field("obfs-opts").unwrap().as_mapping().unwrap();
        assert_eq!(
            obfs.get(Value::from("mode")).and_then(Value::as_str),
            Some("http")
        );
        assert_eq!(
            obfs.get(Value::from("host")).and_then(Value::as_str),
            Some("o.example.com")
        );

        let anytls = entry(
            Scheme::AnyTls,
            "pw-1",
            &[("sni", "a.example.com"), ("skip-cert-verify", "true")],
        );
        let v = entry_to_clash(&anytls).unwrap();
        assert_eq!(v.str_field("type"), Some("anytls"));
        assert_eq!(v.str_field("password"), Some("pw-1"));
        assert_eq!(v.str_field("sni"), Some("a.example.com"));
        assert_eq!(
            v.field("skip-cert-verify").and_then(Value::as_bool),
            Some(true)
        );

        // The end-to-end dispatch must not filter them out either.
        let yaml = encode_clash(&[entry(Scheme::Snell, "psk-2", &[])]);
        let doc: Value = serde_norway::from_str(&yaml).expect("clash YAML");
        let proxies = doc["proxies"].as_sequence().expect("proxies");
        assert_eq!(
            proxies[0].get("type").and_then(Value::as_str),
            Some("snell")
        );
    }

    /// The encode output is read back as YAML and checked on the parsed
    /// structure, the way `formats::tests` checks the skipped count.
    #[test]
    fn encode_suffixes_duplicate_names_and_skips_unsupported() {
        let mut a = entry(Scheme::Trojan, "p1", &[]);
        a.name = "dup".into();
        let mut b = entry(Scheme::Trojan, "p2", &[]);
        b.name = "dup".into();
        let skipped = entry(Scheme::Tuic, "p3", &[]);
        let yaml = encode_clash(&[a, skipped, b]);
        let doc: Value = serde_norway::from_str(&yaml).expect("clash YAML");
        let proxies = doc["proxies"].as_sequence().expect("proxies");
        assert_eq!(proxies.len(), 2, "the unsupported entry must be left out");
        assert_eq!(proxies[0].get("name").and_then(Value::as_str), Some("dup"));
        assert_eq!(
            proxies[1].get("name").and_then(Value::as_str),
            Some("dup (2)")
        );
        // No tuic anywhere: the scheme has no mihomo counterpart.
        assert!(
            proxies
                .iter()
                .all(|p| p.get("type").and_then(Value::as_str) != Some("tuic"))
        );
    }

    #[test]
    fn encode_empty_is_a_valid_document() {
        let yaml = encode_clash(&[]);
        let doc: Value = serde_norway::from_str(&yaml).expect("clash YAML");
        assert!(doc["proxies"].as_sequence().expect("proxies").is_empty());
    }
}
