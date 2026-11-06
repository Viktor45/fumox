//! sing-box JSON output.
//!
//! The emitted document carries only the `outbounds` array; sing-box fills
//! the rest with its defaults. An empty profile yields a valid
//! `{"outbounds": []}` document.
//! Outbound tags must be unique, so duplicate names get the same « (2)»
//! suffixes as Clash output.
//!
//! The supported schemes are vless, vmess, trojan, ss (shadowsocks),
//! hysteria2 and socks5. snell/anytls remain Clash-only — sing-box has no
//! outbound types for them, and guessing a field layout would hand it a
//! config it cannot start.
//!
//! Input fields travel under both spellings where feeds differ (`aid`
//! beside `alterId`, `scy` beside `cipher`, the URI `type` beside the
//! mihomo `network`); the inline comments at each read name them.

use crate::models::{ProxyEntry, Scheme};
use crate::params::Blocks;
use serde_json::{Map, Value};

/// Schemes with a sing-box counterpart; everything else is skipped in
/// output (log-and-skip principle, never fatal).
///
/// The mapping below is the authority: this asks it instead of keeping a
/// second list of schemes, so the query and the mapping cannot drift
/// apart. A caller that already holds an entry can simply ask the mapping
/// itself — a `None` means "no sing-box counterpart".
pub fn is_supported(scheme: Scheme) -> bool {
    entry_to_outbound_named(&bare_entry(scheme), "").is_some()
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
    // The structured blocks are parsed once for the whole entry and handed
    // to the writers below: every one of them used to re-parse the same
    // feed-controlled YAML text.
    let blocks = Blocks::of(entry);

    match entry.scheme {
        Scheme::Vless => {
            m.insert("type".into(), Value::String("vless".into()));
            m.insert("server".into(), Value::String(entry.host.clone()));
            m.insert("server_port".into(), num(entry.port));
            m.insert("uuid".into(), Value::String(entry.credential.clone()));
            if let Some(flow) = super::param_value(entry, "flow") {
                m.insert("flow".into(), Value::String(flow.to_string()));
            }
            let reality = crate::params::is_reality(entry, &blocks);
            let tls = crate::params::wants_tls(entry, &blocks);
            if let Some(tls) = tls_object(entry, &blocks, tls, reality) {
                m.insert("tls".into(), tls);
            }
            if let Some(transport) = transport_object(entry, "type", &blocks) {
                m.insert("transport".into(), transport);
            }
        }
        Scheme::Vmess => {
            m.insert("type".into(), Value::String("vmess".into()));
            m.insert("server".into(), Value::String(entry.host.clone()));
            m.insert("server_port".into(), num(entry.port));
            m.insert("uuid".into(), Value::String(entry.credential.clone()));
            // vmess JSON spells the cipher `scy` and the alter id `aid`, Clash
            // YAML `cipher`/`alterId`; read both or the proxy silently defaults.
            let cipher = super::param_value(entry, "scy")
                .or_else(|| super::param_value(entry, "cipher"))
                .unwrap_or_else(|| "auto".into());
            m.insert("security".into(), Value::String(cipher));
            // One shared reader, one type (u64, a negative value is 0) for
            // both encoders.
            m.insert("alter_id".into(), unsigned(super::alter_id(entry)));
            // vmess JSON spells TLS as `tls: "tls"`; Clash input uses the
            // boolean `tls: true`; some feeds spell it `security=tls`.
            if crate::params::wants_tls(entry, &blocks)
                && let Some(tls) = tls_object(entry, &blocks, true, false)
            {
                m.insert("tls".into(), tls);
            }
            if let Some(transport) = transport_object(entry, "net", &blocks) {
                m.insert("transport".into(), transport);
            }
        }
        Scheme::Trojan => {
            m.insert("type".into(), Value::String("trojan".into()));
            m.insert("server".into(), Value::String(entry.host.clone()));
            m.insert("server_port".into(), num(entry.port));
            m.insert("password".into(), Value::String(entry.credential.clone()));
            let reality = crate::params::is_reality(entry, &blocks);
            // Trojan is TLS by definition: the shared decision says so, and
            // the Clash writer leaves the key out for the same reason.
            if crate::params::wants_tls(entry, &blocks)
                && let Some(tls) = tls_object(entry, &blocks, true, reality)
            {
                m.insert("tls".into(), tls);
            }
            if let Some(transport) = transport_object(entry, "type", &blocks) {
                m.insert("transport".into(), transport);
            }
        }
        Scheme::Ss => {
            m.insert("type".into(), Value::String("shadowsocks".into()));
            m.insert("server".into(), Value::String(entry.host.clone()));
            m.insert("server_port".into(), num(entry.port));
            // Credential is stored as "method:password"; the shared splitter
            // owns the missing/empty-method fallback (see `parsers::clash`
            // `SS_SPEC` for the parse-time canonicalization).
            let (method, password) = super::split_ss_credential(&entry.credential);
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
            if let Some(tls) = tls_object(entry, &blocks, true, false) {
                m.insert("tls".into(), tls);
            }
            if let Some(obfs) = super::param_value(entry, "obfs") {
                let mut o = Map::new();
                o.insert("type".into(), Value::String(obfs.to_string()));
                if let Some(pass) = super::param_value(entry, "obfs-password") {
                    o.insert("password".into(), Value::String(pass.to_string()));
                }
                m.insert("obfs".into(), Value::Object(o));
            }
            // sing-box wants integer rates: the non-digit tail of e.g.
            // "50 Mbps" is trimmed off, and a value left unparseable is
            // dropped entirely instead of shipping a config sing-box
            // rejects. The Clash writer copies the same fields through
            // verbatim (see the `Hysteria2` arm of `entry_to_clash_named`).
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
            // Credential is stored as "user:pass"; both parts are optional,
            // and a colon-less credential is all username (the shared
            // splitter owns the decision).
            let (user, password) = super::split_user_password(&entry.credential);
            if !user.is_empty() {
                m.insert("username".into(), Value::String(user.to_string()));
            }
            if !password.is_empty() {
                m.insert("password".into(), Value::String(password.to_string()));
            }
            if super::param_truthy(entry, "tls") {
                m.insert("tls".into(), minimal_tls(entry));
            }
        }
        // sing-box has no outbound type for either, and guessing a field
        // layout would hand it a config it cannot start. `None` is
        // `filter_map`ped away, so they are left out of the export.
        Scheme::Naive | Scheme::Tuic | Scheme::Mieru | Scheme::Snell | Scheme::AnyTls => {
            return None;
        }
    }

    Some(Value::Object(m))
}

/// Encode the final candidate list as a sing-box config document (pretty
/// JSON). Duplicate tags are suffixed « (2)», « (3)»….
pub fn encode_singbox(entries: &[ProxyEntry]) -> String {
    let outbounds = super::encode_entries(entries, "tag", entry_to_outbound);

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

/// Bare TLS object for schemes without the full options (socks5-over-TLS).
fn minimal_tls(entry: &ProxyEntry) -> Value {
    let mut tls = Map::new();
    tls.insert("enabled".into(), Value::Bool(true));
    if let Some(sni) = crate::params::sni(entry) {
        tls.insert("server_name".into(), Value::String(sni));
    }
    if crate::params::is_insecure(entry) {
        tls.insert("insecure".into(), Value::Bool(true));
    }
    Value::Object(tls)
}

/// Build the sing-box `tls` object; `enabled` is always true once emitted.
/// `reality` adds the REALITY sub-object with the entry's pbk/sid (URI
/// params or a Clash-input `reality-opts` block).
fn tls_object(entry: &ProxyEntry, blocks: &Blocks, enabled: bool, reality: bool) -> Option<Value> {
    if !enabled {
        return None;
    }
    let mut tls = Map::new();
    tls.insert("enabled".into(), Value::Bool(true));
    if let Some(sni) = crate::params::sni(entry) {
        tls.insert("server_name".into(), Value::String(sni));
    }
    if crate::params::is_insecure(entry) {
        tls.insert("insecure".into(), Value::Bool(true));
    }
    if let Some(list) = super::param_list(entry, "alpn") {
        tls.insert(
            "alpn".into(),
            Value::Array(list.into_iter().map(Value::String).collect()),
        );
    }
    // The uTLS client hello under either spelling: the URI family's `fp`
    // and the mihomo `client-fingerprint`.
    if let Some(fp) = crate::params::fingerprint_hint(entry) {
        let mut utls = Map::new();
        utls.insert("enabled".into(), Value::Bool(true));
        utls.insert("fingerprint".into(), Value::String(fp));
        tls.insert("utls".into(), Value::Object(utls));
    }
    if reality {
        let reality = crate::params::reality(entry, blocks);
        if !reality.is_empty() {
            let mut r = Map::new();
            r.insert("enabled".into(), Value::Bool(true));
            if let Some(pbk) = reality.public_key {
                r.insert("public_key".into(), Value::String(pbk));
            }
            if let Some(sid) = reality.short_id {
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
/// the plain-HTTP header transport `http`; `httpupgrade` has its own
/// transport type.
///
/// The blocks of a Clash-input entry are read as well: the same node
/// published as YAML carries its transport in `ws-opts`/`grpc-opts`/
/// `h2-opts` instead of in the flat parameters, and the writer has to
/// describe the same node either way.
fn transport_object(entry: &ProxyEntry, uri_key: &str, blocks: &Blocks) -> Option<Value> {
    let network = super::network_of(entry, uri_key)?;
    let mut t = Map::new();
    match network.as_str() {
        "ws" | "httpupgrade" => {
            t.insert("type".into(), Value::String(network.clone()));
            let path =
                super::param_value(entry, "path").or_else(|| super::map_str(&blocks.ws, "path"));
            if let Some(path) = path {
                t.insert("path".into(), Value::String(path));
            }
            let host = super::param_value(entry, "host")
                .or_else(|| super::map_str(&blocks.ws_headers, "host"))
                .or_else(|| ws_nested_host(blocks));
            if let Some(host) = host {
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
            let mut service = super::param_value(entry, "serviceName")
                .or_else(|| super::map_str(&blocks.grpc, "grpc-service-name"))
                .or_else(|| super::param_value(entry, "grpc-service-name"));
            if entry.scheme == Scheme::Vmess {
                service = service.or_else(|| super::param_value(entry, "path"));
            }
            if let Some(service) = service {
                t.insert("service_name".into(), Value::String(service));
            }
        }
        "h2" | "http" => {
            t.insert("type".into(), Value::String("http".into()));
            put_http_transport(entry, blocks, &mut t);
        }
        // Plain-HTTP header obfuscation: `type=tcp&headerType=http` in
        // URIs, `net: tcp, type: http` in vmess JSON. The Clash writer
        // reduces it to its `http` transport, and the two writers have
        // to describe the same node.
        "tcp" if header_is_http(entry) => {
            t.insert("type".into(), Value::String("http".into()));
            put_http_transport(entry, blocks, &mut t);
        }
        // Plain TCP is sing-box's default: no transport block.
        "tcp" => return None,
        // Unknown network spelling (xhttp, kcp, …): sing-box has a closed
        // set of transport types, so there is nothing to emit and the
        // transport is left out. The Clash writer passes the name through
        // for a capable mihomo instead; the two differ on purpose, a
        // transport sing-box does not know makes the whole config fail to
        // start, while mihomo may still understand the name.
        _ => return None,
    }
    Some(Value::Object(t))
}

/// The host list and the path of the HTTP transports (HTTP/2 and the
/// plain-HTTP header obfuscation).
///
/// The structured blocks are read as well: a Clash-input node carries its
/// HTTP/2 settings in `h2-opts` and its plain-HTTP ones in `http-opts`,
/// and the writer has to describe the same node either way.
fn put_http_transport(entry: &ProxyEntry, blocks: &Blocks, t: &mut Map<String, Value>) {
    let mut hosts: Vec<String> = super::param_value(entry, "host")
        .map(|host| {
            host.split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default();
    if hosts.is_empty() {
        hosts = super::map_list(&blocks.h2, "host")
            .or_else(|| super::map_header(&blocks.http))
            .unwrap_or_default();
    }
    if !hosts.is_empty() {
        t.insert(
            "host".into(),
            Value::Array(hosts.into_iter().map(Value::String).collect()),
        );
    }
    let path = super::param_value(entry, "path")
        .or_else(|| super::map_first(&blocks.h2, "path"))
        .or_else(|| super::map_first(&blocks.http, "path"));
    if let Some(path) = path {
        t.insert("path".into(), Value::String(path));
    }
}

/// Whether the entry asks for the plain-HTTP header obfuscation.
fn header_is_http(entry: &ProxyEntry) -> bool {
    super::param_value(entry, "headertype").is_some_and(|v| v.eq_ignore_ascii_case("http"))
        || (entry.scheme == Scheme::Vmess
            && super::param_value(entry, "type").is_some_and(|v| v.eq_ignore_ascii_case("http")))
}

/// The `Host` header inside a parsed `ws-opts.headers` block.
fn ws_nested_host(blocks: &Blocks) -> Option<String> {
    let hosts = super::map_header(&blocks.ws)?;
    (!hosts.is_empty()).then(|| hosts.join(","))
}

fn num(value: u16) -> Value {
    Value::Number(u64::from(value).into())
}

/// Numeric field that is not a port and must not be narrowed to `u16`.
fn unsigned(value: u64) -> Value {
    Value::Number(value.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::formats::test_util::{Fields, b64, entry, parse};

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
        assert_eq!(v.str_field("type"), Some("vless"));
        assert_eq!(v.str_field("tag"), Some("proxy"));
        assert_eq!(v.str_field("uuid"), Some("uuid-1"));
        assert_eq!(v.str_field("flow"), Some("xtls-rprx-vision"));

        let tls = v.field("tls").unwrap();
        assert_eq!(tls.field("enabled").and_then(Value::as_bool), Some(true));
        assert_eq!(tls.str_field("server_name"), Some("sni.example.com"));
        assert_eq!(
            tls.field("utls").unwrap().str_field("fingerprint"),
            Some("chrome")
        );
        let reality = tls.field("reality").unwrap();
        assert_eq!(reality.str_field("public_key"), Some("key"));
        assert_eq!(reality.str_field("short_id"), Some("short"));

        let transport = v.field("transport").unwrap();
        assert_eq!(transport.str_field("type"), Some("grpc"));
        assert_eq!(transport.str_field("service_name"), Some("svc"));
    }

    /// A Clash YAML item spells the TLS toggle `tls: true` and the SNI
    /// `servername`; neither is a `sni`/`security` parameter, so a vless
    /// proxy that came from Clash YAML used to be re-encoded as a
    /// plaintext outbound with the SNI dropped.
    #[test]
    fn vless_from_clash_input_keeps_tls_and_servername() {
        let yaml = "proxies:\n  - {name: c, type: vless, server: h.example.com, port: 443, \
                    uuid: uuid-1, tls: true, servername: s.example.com, network: ws}\n";
        let result = crate::parsers::clash::parse_payload(yaml).unwrap();
        let e = &result.entries[0];

        let v = entry_to_outbound(e).unwrap();
        let tls = v
            .field("tls")
            .expect("clash `tls: true` must survive the round trip");
        assert_eq!(tls.field("enabled").and_then(Value::as_bool), Some(true));
        assert_eq!(tls.str_field("server_name"), Some("s.example.com"));

        // The Clash writer already read both spellings; the two outputs
        // must not disagree about whether this proxy uses TLS.
        let clash = crate::formats::clash::entry_to_clash(e).unwrap();
        assert_eq!(clash.get("tls").and_then(|v| v.as_bool()), Some(true));
        assert_eq!(
            clash.get("servername").and_then(|v| v.as_str()),
            Some("s.example.com")
        );
    }

    /// A Clash vmess item spells the cipher `cipher` and the alter id
    /// `alterId`; the outbound writer must keep both, not default them.
    #[test]
    fn vmess_from_clash_input_keeps_cipher_and_alter_id() {
        let yaml = "proxies:\n  - {name: c, type: vmess, server: h.example.com, port: 443, \
                    uuid: uuid-2, cipher: aes-128-gcm, alterId: 4}\n";
        let e = &crate::parsers::clash::parse_payload(yaml).unwrap().entries[0];

        let v = entry_to_outbound(e).unwrap();
        assert_eq!(v.str_field("security"), Some("aes-128-gcm"));
        assert_eq!(v.field("alter_id").and_then(Value::as_u64), Some(4));

        // The two writers must agree for the same entry.
        let clash = crate::formats::clash::entry_to_clash(e).unwrap();
        assert_eq!(
            clash
                .get(serde_norway::Value::from("cipher"))
                .and_then(serde_norway::Value::as_str),
            Some("aes-128-gcm")
        );
        assert_eq!(
            clash
                .get(serde_norway::Value::from("alterId"))
                .and_then(serde_norway::Value::as_u64),
            Some(4)
        );
    }

    /// An explicit `tls: false` is the mihomo toggle and outranks the
    /// SNI-implies-TLS rule below: the Clash writer of the same entry
    /// emits no `tls` key at all, and the two outputs must not disagree
    /// about whether this proxy is plaintext.
    #[test]
    fn clash_tls_false_outranks_a_stray_servername() {
        let yaml = "proxies:\n  - {name: c, type: vless, server: h.example.com, port: 443, \
                    uuid: uuid-1, tls: false, servername: s.example.com}\n";
        let result = crate::parsers::clash::parse_payload(yaml).unwrap();
        let e = &result.entries[0];

        assert!(entry_to_outbound(e).unwrap().field("tls").is_none());
        let clash = crate::formats::clash::entry_to_clash(e).unwrap();
        assert!(clash.get("tls").is_none());
    }

    #[test]
    fn trojan_tls_insecure_follows_the_entry_toggle() {
        let plain = entry(Scheme::Trojan, "pass", &[("sni", "t.example.com")]);
        let plain_out = entry_to_outbound(&plain).unwrap();
        let tls = plain_out.field("tls").unwrap();
        assert_eq!(tls.str_field("server_name"), Some("t.example.com"));
        assert!(tls.field("insecure").is_none());

        let insecure = entry(
            Scheme::Trojan,
            "pass",
            &[("sni", "t.example.com"), ("allowInsecure", "1")],
        );
        let insecure_out = entry_to_outbound(&insecure).unwrap();
        let tls = insecure_out.field("tls").unwrap();
        assert_eq!(tls.field("insecure").and_then(Value::as_bool), Some(true));
    }

    #[test]
    fn shadowsocks_splits_method_and_password() {
        let e = entry(Scheme::Ss, "aes-256-gcm:secret", &[]);
        let v = entry_to_outbound(&e).unwrap();
        assert_eq!(v.str_field("type"), Some("shadowsocks"));
        assert_eq!(v.str_field("method"), Some("aes-256-gcm"));
        assert_eq!(v.str_field("password"), Some("secret"));
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
        assert_eq!(v.str_field("type"), Some("vmess"));
        assert_eq!(v.str_field("security"), Some("aes-128-gcm"));
        assert_eq!(v.field("alter_id").and_then(Value::as_u64), Some(4));
        let tls = v.field("tls").unwrap();
        assert_eq!(tls.str_field("server_name"), Some("s.example.com"));
    }

    /// `alter_id` used to go through `as u16`, so 65536 silently became 0
    /// while the Clash encoder emitted 65536 for the same proxy (security
    /// audit, 2026-09-05).
    #[test]
    fn alter_id_above_u16_is_not_truncated() {
        for aid in ["65536", "65537", "4294967296"] {
            let e = entry(Scheme::Vmess, "uuid", &[("aid", aid)]);
            let v = entry_to_outbound(&e).unwrap();
            assert_eq!(
                v.field("alter_id").and_then(Value::as_u64),
                Some(aid.parse::<u64>().unwrap()),
                "aid={aid}"
            );
            // The Clash encoder must agree for the same entry.
            let clash = crate::formats::clash::entry_to_clash(&e).unwrap();
            assert_eq!(
                clash
                    .get(serde_norway::Value::from("alterId"))
                    .and_then(serde_norway::Value::as_u64),
                Some(aid.parse::<u64>().unwrap()),
                "clash disagrees for aid={aid}"
            );
        }
    }

    #[test]
    fn raw_vmess_json_tls_ws_maps_completely() {
        let json = r#"{"v":"2","ps":"n","add":"h.example.com","port":"443","id":"uuid-2","aid":"0","scy":"auto","net":"ws","host":"ws.example.com","path":"/vmess","tls":"tls","sni":"s.example.com"}"#;
        let line = format!("vmess://{}", b64(json.as_bytes()));
        let e = parse(&line);
        let v = entry_to_outbound(&e).unwrap();
        // vmess TLS is spelled `tls: "tls"` in the JSON, not `security=tls`.
        let tls = v.field("tls").unwrap();
        assert_eq!(tls.field("enabled").and_then(Value::as_bool), Some(true));
        assert_eq!(tls.str_field("server_name"), Some("s.example.com"));
        let transport = v.field("transport").unwrap();
        assert_eq!(transport.str_field("type"), Some("ws"));
        assert_eq!(transport.str_field("path"), Some("/vmess"));
        let headers = transport.field("headers").unwrap();
        assert_eq!(headers.str_field("Host"), Some("ws.example.com"));
    }

    #[test]
    fn raw_vless_reality_type_grpc_maps_transport() {
        let line = "vless://uuid-1@h.example.com:443?security=reality&sni=s.example.com&fp=chrome&pbk=pub-key&sid=01ab&type=grpc&serviceName=gr-svc#Name";
        let e = parse(line);
        let v = entry_to_outbound(&e).unwrap();
        let tls = v.field("tls").unwrap();
        let reality = tls.field("reality").unwrap();
        assert_eq!(reality.str_field("public_key"), Some("pub-key"));
        assert_eq!(reality.str_field("short_id"), Some("01ab"));
        let transport = v.field("transport").unwrap();
        // Network comes from the URI `type` key.
        assert_eq!(transport.str_field("type"), Some("grpc"));
        assert_eq!(transport.str_field("service_name"), Some("gr-svc"));
    }

    #[test]
    fn raw_trojan_ws_line_maps_transport() {
        let line = "trojan://pass@h.example.com:443?security=tls&sni=t.example.com&type=ws&host=ws.example.com&path=%2Fws#Name";
        let e = parse(line);
        let v = entry_to_outbound(&e).unwrap();
        let transport = v.field("transport").unwrap();
        assert_eq!(transport.str_field("type"), Some("ws"));
        assert_eq!(transport.str_field("path"), Some("/ws"));
        let headers = transport.field("headers").unwrap();
        assert_eq!(headers.str_field("Host"), Some("ws.example.com"));
    }

    #[test]
    fn raw_ss_line_maps_plugin() {
        let blob = b64("aes-256-gcm:secret".as_bytes());
        let line = format!(
            "ss://{blob}@h.example.com:8388/?plugin=obfs-local%3Bobfs%3Dhttp%3Bobfs-host%3Dob.example.com#Name"
        );
        let e = parse(&line);
        let v = entry_to_outbound(&e).unwrap();
        assert_eq!(v.str_field("plugin"), Some("obfs-local"));
        assert_eq!(
            v.str_field("plugin_opts"),
            Some("obfs=http;obfs-host=ob.example.com")
        );
    }

    #[test]
    fn raw_hysteria2_line_maps_obfs_and_rates() {
        let line = "hysteria2://hy-pass@h.example.com:443?sni=hy.example.com&obfs=salamander&obfs-password=ob-pass&upMbps=50&downMbps=200&alpn=h3#Name";
        let e = parse(line);
        let v = entry_to_outbound(&e).unwrap();
        let obfs = v.field("obfs").unwrap();
        assert_eq!(obfs.str_field("type"), Some("salamander"));
        assert_eq!(obfs.str_field("password"), Some("ob-pass"));
        assert_eq!(v.field("up_mbps").and_then(Value::as_u64), Some(50));
        assert_eq!(v.field("down_mbps").and_then(Value::as_u64), Some(200));
        let tls = v.field("tls").unwrap();
        assert_eq!(
            tls.field("alpn").and_then(Value::as_array).unwrap().len(),
            1
        );
    }

    #[test]
    fn socks_maps_to_socks_type() {
        let e = entry(Scheme::Socks5, "user:pw", &[]);
        let v = entry_to_outbound(&e).unwrap();
        assert_eq!(v.str_field("type"), Some("socks"));
        assert_eq!(v.str_field("username"), Some("user"));
        assert_eq!(v.str_field("password"), Some("pw"));
    }

    /// A colon-less socks5 credential is all username: no password is
    /// invented for it, in either encoder.
    #[test]
    fn a_colon_less_socks5_credential_is_all_username() {
        let e = entry(Scheme::Socks5, "onlyuser", &[]);
        let v = entry_to_outbound(&e).unwrap();
        assert_eq!(v.str_field("username"), Some("onlyuser"));
        assert!(v.field("password").is_none());
    }

    /// A leading empty method must not render an empty `method`: the
    /// shared credential splitter falls back to the default cipher and
    /// keeps what follows the slot as the password.
    #[test]
    fn a_leading_colon_ss_credential_does_not_render_an_empty_method() {
        let e = entry(Scheme::Ss, ":secret", &[]);
        let v = entry_to_outbound(&e).unwrap();
        assert_eq!(
            v.str_field("method"),
            Some(crate::models::DEFAULT_SS_CIPHER)
        );
        assert_eq!(v.str_field("password"), Some("secret"));
    }

    /// The socks5 TLS toggle travels in both encoders; sing-box spells it
    /// as `tls.enabled` and carries the server name along.
    #[test]
    fn socks5_tls_enables_tls_and_carries_the_server_name() {
        let e = entry(
            Scheme::Socks5,
            "u:p",
            &[("tls", "true"), ("sni", "s.example.com")],
        );
        let v = entry_to_outbound(&e).unwrap();
        let tls = v.field("tls").unwrap();
        assert_eq!(tls.field("enabled").and_then(Value::as_bool), Some(true));
        assert_eq!(tls.str_field("server_name"), Some("s.example.com"));
    }

    /// vmess JSON spells the plain-HTTP header obfuscation
    /// `net: tcp, type: http`: sing-box's own transport type for it is
    /// `http`, with the hosts as a list.
    #[test]
    fn raw_vmess_tcp_http_header_maps_to_http_transport() {
        let json = r#"{"v":"2","ps":"n","add":"h.example.com","port":"443","id":"uuid-3","aid":"0","scy":"auto","net":"tcp","type":"http","path":"/hp","host":"hp.example.com"}"#;
        let line = format!("vmess://{}", b64(json.as_bytes()));
        let e = parse(&line);
        let v = entry_to_outbound(&e).unwrap();
        let transport = v.field("transport").unwrap();
        assert_eq!(transport.str_field("type"), Some("http"));
        assert_eq!(transport.str_field("path"), Some("/hp"));
        assert_eq!(
            transport.field("host").and_then(Value::as_array).unwrap()[0].as_str(),
            Some("hp.example.com")
        );
    }

    /// The HTTP-upgrade WebSocket has a transport type of its own: the
    /// host is a transport field there, not a `Host` header like `ws`.
    #[test]
    fn raw_vless_httpupgrade_keeps_its_own_transport_type() {
        let line =
            "vless://u@h:443?security=tls&type=httpupgrade&host=up.example.com&path=%2Fup#Name";
        let e = parse(line);
        let v = entry_to_outbound(&e).unwrap();
        let transport = v.field("transport").unwrap();
        assert_eq!(transport.str_field("type"), Some("httpupgrade"));
        assert_eq!(transport.str_field("host"), Some("up.example.com"));
        assert!(
            transport.field("headers").is_none(),
            "httpupgrade carries the host as a field, not a Host header: {transport:?}"
        );
    }

    #[test]
    fn unsupported_schemes_are_skipped() {
        assert!(entry_to_outbound(&entry(Scheme::Tuic, "c", &[])).is_none());
        assert!(entry_to_outbound(&entry(Scheme::Mieru, "c", &[])).is_none());
        assert!(entry_to_outbound(&entry(Scheme::Naive, "c", &[])).is_none());
        // No sing-box outbound type exists for either: guessing a field
        // layout would hand the client a config it cannot start, so the
        // export leaves them out (each encoder's behaviour matches its own
        // `is_supported`; the two lists intentionally diverge for
        // snell/anytls, see the comment in entry_to_outbound).
        assert!(entry_to_outbound(&entry(Scheme::Snell, "c", &[])).is_none());
        assert!(entry_to_outbound(&entry(Scheme::AnyTls, "c", &[])).is_none());
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
