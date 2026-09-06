//! sing-box / Xray JSON subscription input (SPEC §4).
//!
//! Two JSON dialects share the `outbounds` key and are both accepted:
//!
//! * **sing-box native** — outbounds carry `type`/`server`/`server_port`;
//!   the mapping is the exact inverse of the [`crate::formats::singbox`]
//!   output encoder, so `parse ∘ encode_singbox` round-trips;
//! * **Xray/v2ray-core ("vnext")** — outbounds carry
//!   `protocol`/`settings.vnext`/`streamSettings`. The payload may also be
//!   a bare array of such configs (the v2rayN share format), and the
//!   per-config keys sing-box ignores (`dns`, `routing`, `remarks`, …) are
//!   simply not read.
//!
//! Supported proxy types: vless, vmess, trojan, shadowsocks, hysteria2,
//! socks. Types that are not proxies at all (`selector`, `urltest`,
//! `direct`, `block`, `dns`, `freedom`, `blackhole`, `loopback`) are
//! skipped silently; proxy protocols without a [`ProxyEntry`]
//! representation (`tuic`, `http`, `wireguard`, …) are counted as
//! unsupported. Everything follows the log-and-skip principle: a bad
//! outbound never fails the payload.
//!
//! Fields are flattened onto the same parameter vocabulary the URI parsers
//! use (`sni`, `fp`, `pbk`, `sid`, `alpn`, `path`, `host`, `serviceName`,
//! `type`/`net`, …), so the pipeline, health checks and all three output
//! formats work unchanged. Unmapped identity-relevant fields pass through
//! as parameters under their original names (the Forge principle); pure
//! client-side knobs (`mux`, `sockopt`, `show`, …) are dropped.

use crate::models::{Param, ProxyEntry, Scheme};
use serde_json::{Map, Value};

/// Outbound types that are control/routing plane, not proxies.
const NON_PROXY_TYPES: &[&str] = &[
    // sing-box
    "direct",
    "block",
    "dns",
    "selector",
    "urltest",
    // Xray/v2ray-core
    "freedom",
    "blackhole",
    "loopback",
];

/// Result of parsing a sing-box / Xray JSON payload.
#[derive(Debug, Default)]
pub struct SingBoxParseResult {
    pub entries: Vec<ProxyEntry>,
    /// Proxy protocols recognized but without a `ProxyEntry` representation.
    pub unsupported: usize,
    /// Outbound objects missing required fields or over the parameter cap.
    pub invalid: usize,
}

/// Parse a full sing-box / Xray JSON payload: a root object with an
/// `outbounds` array, or an array of such objects.
pub fn parse_payload(payload: &str) -> Result<SingBoxParseResult, String> {
    let root: Value =
        serde_json::from_str(payload).map_err(|e| format!("sing-box: invalid JSON: {e}"))?;
    let mut result = SingBoxParseResult::default();
    let mut found = false;
    match &root {
        Value::Object(config) => found = harvest(config, &mut result),
        Value::Array(configs) => {
            for config in configs {
                if let Some(config) = config.as_object()
                    && harvest(config, &mut result)
                {
                    found = true;
                }
            }
        }
        _ => return Err("sing-box: payload is neither a JSON object nor an array".to_string()),
    }
    if !found {
        return Err("sing-box: no `outbounds` array".to_string());
    }
    Ok(result)
}

/// Parse one config's `outbounds`; `false` when the config has none.
fn harvest(config: &Map<String, Value>, result: &mut SingBoxParseResult) -> bool {
    let Some(outbounds) = config.get("outbounds").and_then(Value::as_array) else {
        return false;
    };
    for outbound in outbounds {
        parse_outbound(outbound, result);
    }
    true
}

fn parse_outbound(outbound: &Value, result: &mut SingBoxParseResult) {
    let Some(map) = outbound.as_object() else {
        result.invalid += 1;
        return;
    };
    // Dialect: sing-box spells the kind `type`, Xray spells it `protocol`.
    let (kind_key, kind) = if let Some(kind) = map.get("type").and_then(Value::as_str) {
        ("type", kind)
    } else if let Some(kind) = map.get("protocol").and_then(Value::as_str) {
        ("protocol", kind)
    } else {
        result.invalid += 1;
        return;
    };
    if NON_PROXY_TYPES.contains(&kind) {
        return;
    }
    let name = map
        .get("tag")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    let built = match (kind_key, kind) {
        ("type", "vless") => native_vless(map, &name).map(vec1),
        ("type", "vmess") => native_vmess(map, &name).map(vec1),
        ("type", "trojan") => native_trojan(map, &name).map(vec1),
        ("type", "shadowsocks") => native_ss(map, &name).map(vec1),
        ("type", "hysteria2") => native_hysteria2(map, &name).map(vec1),
        ("type", "socks" | "socks5") => native_socks(map, &name).map(vec1),
        ("protocol", "vless") => xray_vless(map, &name),
        ("protocol", "vmess") => xray_vmess(map, &name),
        ("protocol", "trojan") => xray_trojan(map, &name),
        ("protocol", "shadowsocks") => xray_ss(map, &name),
        ("protocol", "socks") => xray_socks(map, &name),
        _ => {
            tracing::debug!(kind, "sing-box: proxy protocol without a representation");
            result.unsupported += 1;
            return;
        }
    };
    match built {
        Ok(entries) => result.entries.extend(entries),
        Err(message) => {
            tracing::debug!(error = %message, "skipping malformed sing-box outbound");
            result.invalid += 1;
        }
    }
}

fn vec1(entry: ProxyEntry) -> Vec<ProxyEntry> {
    vec![entry]
}

// ─────────────────────────────────────────────────────────────────────────
// sing-box native dialect
// ─────────────────────────────────────────────────────────────────────────

fn native_vless(map: &Map<String, Value>, name: &str) -> Result<ProxyEntry, String> {
    let (host, port) = native_endpoint(map)?;
    let credential = required_str(map, "uuid")?;
    let mut params = Vec::new();
    if let Some(flow) = str_field(map, "flow") {
        push_param(&mut params, true, "flow", flow);
    }
    if let Some(tls) = map.get("tls").and_then(Value::as_object) {
        native_tls_params(tls, Some(("security", "tls")), &mut params);
    }
    if let Some(transport) = map.get("transport").and_then(Value::as_object) {
        native_transport_params(transport, "type", &mut params);
    }
    passthrough(
        map,
        &[
            "tag",
            "type",
            "server",
            "server_port",
            "uuid",
            "flow",
            "tls",
            "transport",
        ],
        &mut params,
    );
    finish(Scheme::Vless, name, host, port, credential, params)
}

fn native_vmess(map: &Map<String, Value>, name: &str) -> Result<ProxyEntry, String> {
    let (host, port) = native_endpoint(map)?;
    let credential = required_str(map, "uuid")?;
    let mut params = Vec::new();
    // vmess JSON spells the cipher `security` internally (`scy`) and TLS as
    // `tls: "tls"` — same convention as the vmess URI parser.
    if let Some(scy) = str_field(map, "security") {
        push_param(&mut params, true, "scy", scy);
    }
    if let Some(aid) = map.get("alter_id") {
        push_param(&mut params, true, "aid", json_to_param_value(aid));
    }
    if let Some(tls) = map.get("tls").and_then(Value::as_object) {
        native_tls_params(tls, Some(("tls", "tls")), &mut params);
    }
    if let Some(transport) = map.get("transport").and_then(Value::as_object) {
        native_transport_params(transport, "net", &mut params);
    }
    passthrough(
        map,
        &[
            "tag",
            "type",
            "server",
            "server_port",
            "uuid",
            "security",
            "alter_id",
            "tls",
            "transport",
        ],
        &mut params,
    );
    finish(Scheme::Vmess, name, host, port, credential, params)
}

fn native_trojan(map: &Map<String, Value>, name: &str) -> Result<ProxyEntry, String> {
    let (host, port) = native_endpoint(map)?;
    let credential = required_str(map, "password")?;
    let mut params = Vec::new();
    if let Some(tls) = map.get("tls").and_then(Value::as_object) {
        native_tls_params(tls, Some(("security", "tls")), &mut params);
    }
    if let Some(transport) = map.get("transport").and_then(Value::as_object) {
        native_transport_params(transport, "type", &mut params);
    }
    passthrough(
        map,
        &[
            "tag",
            "type",
            "server",
            "server_port",
            "password",
            "tls",
            "transport",
        ],
        &mut params,
    );
    finish(Scheme::Trojan, name, host, port, credential, params)
}

fn native_ss(map: &Map<String, Value>, name: &str) -> Result<ProxyEntry, String> {
    let (host, port) = native_endpoint(map)?;
    let method = required_str(map, "method")?;
    let password = str_field(map, "password").unwrap_or_default();
    let mut params = Vec::new();
    if let Some(plugin) = str_field(map, "plugin") {
        // Reassembled into the SIP003 string form the pipeline carries.
        let opts = str_field(map, "plugin_opts").unwrap_or_default();
        let value = if opts.is_empty() {
            plugin.to_string()
        } else {
            format!("{plugin};{opts}")
        };
        push_param(&mut params, true, "plugin", value);
    }
    passthrough(
        map,
        &[
            "tag",
            "type",
            "server",
            "server_port",
            "method",
            "password",
            "plugin",
            "plugin_opts",
        ],
        &mut params,
    );
    finish(
        Scheme::Ss,
        name,
        host,
        port,
        format!("{method}:{password}"),
        params,
    )
}

fn native_hysteria2(map: &Map<String, Value>, name: &str) -> Result<ProxyEntry, String> {
    let (host, port) = native_endpoint(map)?;
    let credential = required_str(map, "password")?;
    let mut params = Vec::new();
    if let Some(tls) = map.get("tls").and_then(Value::as_object) {
        native_tls_params(tls, Some(("security", "tls")), &mut params);
    }
    if let Some(obfs) = map.get("obfs").and_then(Value::as_object) {
        if let Some(kind) = str_field(obfs, "type") {
            push_param(&mut params, true, "obfs", kind);
        }
        if let Some(pass) = str_field(obfs, "password") {
            push_param(&mut params, true, "obfs-password", pass);
        }
    }
    for (key, out) in [("up_mbps", "upMbps"), ("down_mbps", "downMbps")] {
        if let Some(rate) = map.get(key).and_then(Value::as_u64) {
            push_param(&mut params, true, out, rate.to_string());
        }
    }
    passthrough(
        map,
        &[
            "tag",
            "type",
            "server",
            "server_port",
            "password",
            "tls",
            "obfs",
            "up_mbps",
            "down_mbps",
        ],
        &mut params,
    );
    finish(Scheme::Hysteria2, name, host, port, credential, params)
}

fn native_socks(map: &Map<String, Value>, name: &str) -> Result<ProxyEntry, String> {
    let (host, port) = native_endpoint(map)?;
    let user = str_field(map, "username").unwrap_or_default();
    let password = str_field(map, "password").unwrap_or_default();
    let mut params = Vec::new();
    if let Some(tls) = map.get("tls").and_then(Value::as_object)
        && tls.get("enabled").and_then(Value::as_bool) == Some(true)
    {
        // The socks5 serializer rebuilds TLS from the bare `tls` toggle.
        push_param(&mut params, true, "tls", "true");
        if let Some(sni) = str_field(tls, "server_name") {
            push_param(&mut params, true, "sni", sni);
        }
        if tls.get("insecure").and_then(Value::as_bool) == Some(true) {
            push_param(&mut params, true, "insecure", "true");
        }
    }
    passthrough(
        map,
        &[
            "tag",
            "type",
            "server",
            "server_port",
            "username",
            "password",
            "tls",
            "version",
        ],
        &mut params,
    );
    finish(
        Scheme::Socks5,
        name,
        host,
        port,
        format!("{user}:{password}"),
        params,
    )
}

/// Map the native `tls` object onto URI-style parameters. `security` is the
/// (key, value) pair spelled for TLS-on: `security=tls` for the URI-family
/// schemes, `tls=tls` for vmess JSON, nothing for socks.
fn native_tls_params(
    tls: &Map<String, Value>,
    security: Option<(&str, &str)>,
    params: &mut Vec<Param>,
) {
    let enabled = tls.get("enabled").and_then(Value::as_bool).unwrap_or(false);
    let reality = tls.get("reality").and_then(Value::as_object);
    let reality_key = reality.and_then(|r| str_field(r, "public_key")).is_some();
    let reality_on = reality_key
        || reality.is_some_and(|r| r.get("enabled").and_then(Value::as_bool) == Some(true));
    if !enabled && !reality_on {
        return;
    }
    match security {
        Some(("security", _)) if reality_on => push_param(params, true, "security", "reality"),
        Some((key, value)) => push_param(params, true, key, value),
        None => {}
    }
    if reality_on && let Some(reality) = reality {
        if let Some(pbk) = str_field(reality, "public_key") {
            push_param(params, true, "pbk", pbk);
        }
        if let Some(sid) = str_field(reality, "short_id") {
            push_param(params, true, "sid", sid);
        }
    }
    if let Some(sni) = str_field(tls, "server_name") {
        push_param(params, true, "sni", sni);
    }
    if tls.get("insecure").and_then(Value::as_bool) == Some(true) {
        push_param(params, true, "insecure", "true");
    }
    if let Some(alpn) = string_or_joined_array(tls.get("alpn")) {
        push_param(params, true, "alpn", alpn);
    }
    if let Some(fp) = tls
        .get("utls")
        .and_then(Value::as_object)
        .and_then(|utls| str_field(utls, "fingerprint"))
    {
        push_param(params, true, "fp", fp);
    }
}

/// Map the native `transport` object onto parameters; `network_key` is
/// `type` for the URI-family schemes, `net` for vmess.
fn native_transport_params(
    transport: &Map<String, Value>,
    network_key: &str,
    params: &mut Vec<Param>,
) {
    let Some(network) = str_field(transport, "type") else {
        return;
    };
    push_param(params, true, network_key, network);
    const CONSUMED: &[&str] = &["type", "path", "host", "headers", "service_name"];
    match network {
        "ws" => {
            if let Some(path) = str_field(transport, "path") {
                push_param(params, true, "path", path);
            }
            if let Some(host) = transport
                .get("headers")
                .and_then(Value::as_object)
                .and_then(|headers| headers.get("Host").and_then(Value::as_str))
            {
                push_param(params, true, "host", host);
            }
        }
        "httpupgrade" => {
            if let Some(path) = str_field(transport, "path") {
                push_param(params, true, "path", path);
            }
            if let Some(host) = str_field(transport, "host") {
                push_param(params, true, "host", host);
            }
        }
        "grpc" => {
            if let Some(service) = str_field(transport, "service_name") {
                push_param(params, true, "serviceName", service);
            }
        }
        "http" | "h2" => {
            if let Some(host) = string_or_joined_array(transport.get("host")) {
                push_param(params, true, "host", host);
            }
            if let Some(path) = str_field(transport, "path") {
                push_param(params, true, "path", path);
            }
        }
        _ => {}
    }
    // Unmapped transport fields (`early_data_header_name`, `max_early_data`,
    // xhttp `extra`, …) pass through under their sing-box names.
    for (key, value) in transport {
        if CONSUMED.contains(&key.as_str()) || value.is_null() {
            continue;
        }
        push_param(params, false, key, json_to_param_value(value));
    }
}

// ─────────────────────────────────────────────────────────────────────────
// Xray/v2ray-core ("vnext") dialect
// ─────────────────────────────────────────────────────────────────────────

fn xray_vless(map: &Map<String, Value>, name: &str) -> Result<Vec<ProxyEntry>, String> {
    let mut entries = Vec::new();
    for vnext in xray_settings_list(map, "vnext")? {
        let (host, port) = xray_endpoint(vnext)?;
        let user = first_object(vnext, "users").ok_or("xray: vless vnext without users")?;
        let credential = str_field(user, "id")
            .ok_or("xray: vless user without id")?
            .to_string();
        let mut params = Vec::new();
        if let Some(flow) = str_field(user, "flow") {
            push_param(&mut params, true, "flow", flow);
        }
        if let Some(encryption) = str_field(user, "encryption")
            && encryption != "none"
        {
            push_param(&mut params, true, "encryption", encryption);
        }
        if let Some(stream) = map.get("streamSettings").and_then(Value::as_object) {
            xray_stream_params(stream, "type", Some(("security", "tls")), &mut params);
        }
        passthrough(map, XRAY_TOP_LEVEL_CONSUMED, &mut params);
        entries.push(finish(Scheme::Vless, name, host, port, credential, params)?);
    }
    Ok(entries)
}

fn xray_vmess(map: &Map<String, Value>, name: &str) -> Result<Vec<ProxyEntry>, String> {
    let mut entries = Vec::new();
    for vnext in xray_settings_list(map, "vnext")? {
        let (host, port) = xray_endpoint(vnext)?;
        let user = first_object(vnext, "users").ok_or("xray: vmess vnext without users")?;
        let credential = str_field(user, "id")
            .ok_or("xray: vmess user without id")?
            .to_string();
        let mut params = Vec::new();
        if let Some(scy) = str_field(user, "security") {
            push_param(&mut params, true, "scy", scy);
        }
        if let Some(aid) = user.get("alterId") {
            push_param(&mut params, true, "aid", json_to_param_value(aid));
        }
        if let Some(encryption) = str_field(user, "encryption")
            && encryption != "none"
        {
            push_param(&mut params, true, "encryption", encryption);
        }
        if let Some(stream) = map.get("streamSettings").and_then(Value::as_object) {
            // vmess JSON spells TLS as `tls: "tls"`.
            xray_stream_params(stream, "net", Some(("tls", "tls")), &mut params);
        }
        passthrough(map, XRAY_TOP_LEVEL_CONSUMED, &mut params);
        entries.push(finish(Scheme::Vmess, name, host, port, credential, params)?);
    }
    Ok(entries)
}

fn xray_trojan(map: &Map<String, Value>, name: &str) -> Result<Vec<ProxyEntry>, String> {
    let mut entries = Vec::new();
    for server in xray_settings_list(map, "servers")? {
        let (host, port) = xray_endpoint(server)?;
        let credential = str_field(server, "password")
            .ok_or("xray: trojan server without password")?
            .to_string();
        let mut params = Vec::new();
        if let Some(stream) = map.get("streamSettings").and_then(Value::as_object) {
            xray_stream_params(stream, "type", Some(("security", "tls")), &mut params);
        }
        passthrough(map, XRAY_TOP_LEVEL_CONSUMED, &mut params);
        entries.push(finish(
            Scheme::Trojan,
            name,
            host,
            port,
            credential,
            params,
        )?);
    }
    Ok(entries)
}

fn xray_ss(map: &Map<String, Value>, name: &str) -> Result<Vec<ProxyEntry>, String> {
    let settings = map.get("settings").and_then(Value::as_object);
    let plugin = settings
        .and_then(|s| s.get("plugin"))
        .and_then(Value::as_str);
    let plugin_opts = settings
        .and_then(|s| s.get("pluginOpts"))
        .and_then(Value::as_str)
        .unwrap_or_default();
    let mut entries = Vec::new();
    for server in xray_settings_list(map, "servers")? {
        let (host, port) = xray_endpoint(server)?;
        let method = str_field(server, "method")
            .ok_or("xray: shadowsocks server without method")?
            .to_string();
        let password = str_field(server, "password").unwrap_or_default();
        let mut params = Vec::new();
        if let Some(plugin) = plugin {
            let value = if plugin_opts.is_empty() {
                plugin.to_string()
            } else {
                format!("{plugin};{plugin_opts}")
            };
            push_param(&mut params, true, "plugin", value);
        }
        passthrough(map, XRAY_TOP_LEVEL_CONSUMED, &mut params);
        entries.push(finish(
            Scheme::Ss,
            name,
            host,
            port,
            format!("{method}:{password}"),
            params,
        )?);
    }
    Ok(entries)
}

fn xray_socks(map: &Map<String, Value>, name: &str) -> Result<Vec<ProxyEntry>, String> {
    let mut entries = Vec::new();
    for server in xray_settings_list(map, "servers")? {
        let host = str_field(server, "address")
            .or_else(|| str_field(server, "addr"))
            .ok_or("xray: socks server without address")?
            .to_string();
        let port = numeric_field(server, "port")?;
        let user = first_object(server, "users");
        let username = user.and_then(|u| str_field(u, "user")).unwrap_or_default();
        let password = user.and_then(|u| str_field(u, "pass")).unwrap_or_default();
        let mut params = Vec::new();
        passthrough(map, XRAY_TOP_LEVEL_CONSUMED, &mut params);
        entries.push(finish(
            Scheme::Socks5,
            name,
            host,
            port,
            format!("{username}:{password}"),
            params,
        )?);
    }
    Ok(entries)
}

/// Outbound keys consumed structurally by every Xray builder; `mux` is a
/// client-side multiplexing knob, not proxy identity.
const XRAY_TOP_LEVEL_CONSUMED: &[&str] = &["tag", "protocol", "settings", "streamSettings", "mux"];

/// Iterate `settings.<field>` (an array of endpoint objects).
fn xray_settings_list<'a>(
    map: &'a Map<String, Value>,
    field: &str,
) -> Result<Vec<&'a Map<String, Value>>, String> {
    let list = map
        .get("settings")
        .and_then(Value::as_object)
        .and_then(|settings| settings.get(field))
        .and_then(Value::as_array)
        .ok_or_else(|| format!("xray: settings.{field} missing"))?;
    Ok(list.iter().filter_map(Value::as_object).collect())
}

fn xray_endpoint(map: &Map<String, Value>) -> Result<(String, u16), String> {
    let host = str_field(map, "address")
        .ok_or("xray: missing `address`")?
        .to_string();
    let port = numeric_field(map, "port")?;
    Ok((host, port))
}

/// Map `streamSettings` onto parameters; `network_key` is `type` for the
/// URI-family schemes, `net` for vmess. `security` is the TLS-on spelling
/// for the scheme (see [`native_tls_params`]).
fn xray_stream_params(
    stream: &Map<String, Value>,
    network_key: &str,
    security: Option<(&str, &str)>,
    params: &mut Vec<Param>,
) {
    let network = str_field(stream, "network").unwrap_or("tcp");
    // TCP is the implicit transport in every dialect; `type=tcp` is stored
    // only when it carries HTTP obfuscation (see the `tcp` arm below).
    if network != "tcp" {
        push_param(params, true, network_key, network);
    }
    match str_field(stream, "security") {
        Some("tls") => {
            if let Some((key, value)) = security {
                push_param(params, true, key, value);
            }
            if let Some(tls) = stream.get("tlsSettings").and_then(Value::as_object) {
                if let Some(sni) = str_field(tls, "serverName") {
                    push_param(params, true, "sni", sni);
                }
                if let Some(fp) = str_field(tls, "fingerprint") {
                    push_param(params, true, "fp", fp);
                }
                if let Some(alpn) = string_or_joined_array(tls.get("alpn")) {
                    push_param(params, true, "alpn", alpn);
                }
                if xray_truthy(tls, "allowInsecure") {
                    push_param(params, true, "insecure", "true");
                }
            }
        }
        Some("reality") => {
            // REALITY is spelled through `security` in the URI family;
            // vmess has no REALITY and keeps its `tls` spelling.
            match security {
                Some(("security", _)) => push_param(params, true, "security", "reality"),
                Some((key, value)) => push_param(params, true, key, value),
                None => {}
            }
            if let Some(reality) = stream.get("realitySettings").and_then(Value::as_object) {
                if let Some(sni) = str_field(reality, "serverName") {
                    push_param(params, true, "sni", sni);
                }
                if let Some(fp) = str_field(reality, "fingerprint") {
                    push_param(params, true, "fp", fp);
                }
                if let Some(pbk) = str_field(reality, "publicKey") {
                    push_param(params, true, "pbk", pbk);
                }
                if let Some(sid) = str_field(reality, "shortId") {
                    push_param(params, true, "sid", sid);
                }
                // `spiderX` is an Xray client-side crawler impersonation
                // knob (like `sockopt`) with no proxy-identity meaning.
                if xray_truthy(reality, "allowInsecure") {
                    push_param(params, true, "insecure", "true");
                }
            }
        }
        _ => {}
    }
    match network {
        "ws" => {
            if let Some(ws) = stream.get("wsSettings").and_then(Value::as_object) {
                if let Some(path) = str_field(ws, "path") {
                    push_param(params, true, "path", path);
                }
                if let Some(host) = ws
                    .get("headers")
                    .and_then(Value::as_object)
                    .and_then(|headers| string_or_joined_array(headers.get("Host")))
                {
                    push_param(params, true, "host", host);
                }
            }
        }
        "grpc" => {
            if let Some(grpc) = stream.get("grpcSettings").and_then(Value::as_object)
                && let Some(service) = str_field(grpc, "serviceName")
            {
                push_param(params, true, "serviceName", service);
            }
        }
        "http" | "h2" => {
            if let Some(http) = stream.get("httpSettings").and_then(Value::as_object) {
                if let Some(host) = string_or_joined_array(http.get("host")) {
                    push_param(params, true, "host", host);
                }
                if let Some(path) = str_field(http, "path") {
                    push_param(params, true, "path", path);
                }
            }
        }
        "httpupgrade" => {
            if let Some(upgrade) = stream.get("httpupgradeSettings").and_then(Value::as_object) {
                if let Some(path) = str_field(upgrade, "path") {
                    push_param(params, true, "path", path);
                }
                if let Some(host) = str_field(upgrade, "host") {
                    push_param(params, true, "host", host);
                }
            }
        }
        "xhttp" | "splithttp" => {
            if let Some(xhttp) = stream.get("xhttpSettings").and_then(Value::as_object) {
                if let Some(host) = str_field(xhttp, "host") {
                    push_param(params, true, "host", host);
                }
                if let Some(path) = str_field(xhttp, "path") {
                    push_param(params, true, "path", path);
                }
                if let Some(mode) = str_field(xhttp, "mode") {
                    push_param(params, true, "mode", mode);
                }
                if let Some(extra) = xhttp.get("extra") {
                    push_param(params, false, "extra", json_to_param_value(extra));
                }
            }
        }
        // TCP with HTTP obfuscation (`header.type: "http"`); plain TCP
        // (`type: "none"` or absent) maps to no parameters at all.
        "tcp" => {
            if let Some(header) = stream
                .get("tcpSettings")
                .and_then(Value::as_object)
                .and_then(|tcp| tcp.get("header"))
                .and_then(Value::as_object)
                && str_field(header, "type") == Some("http")
            {
                push_param(params, true, network_key, "tcp");
                push_param(params, true, "headertype", "http");
                if let Some(request) = header.get("request").and_then(Value::as_object) {
                    if let Some(path) = string_or_joined_array(request.get("path")) {
                        push_param(params, true, "path", path);
                    }
                    if let Some(host) = request
                        .get("headers")
                        .and_then(Value::as_object)
                        .and_then(|headers| string_or_joined_array(headers.get("Host")))
                    {
                        push_param(params, true, "host", host);
                    }
                }
            }
        }
        _ => {}
    }
}

// ─────────────────────────────────────────────────────────────────────────
// Shared helpers
// ─────────────────────────────────────────────────────────────────────────

/// Client-side knobs that describe the local dialer, not the proxy; dropped
/// rather than passed through to keep DB rows and URI output clean.
const CLIENT_SIDE_FIELDS: &[&str] = &["mux", "sockopt"];

fn passthrough(map: &Map<String, Value>, consumed: &[&str], params: &mut Vec<Param>) {
    for (key, value) in map {
        if consumed.contains(&key.as_str())
            || CLIENT_SIDE_FIELDS.contains(&key.as_str())
            || value.is_null()
        {
            continue;
        }
        push_param(params, false, key, json_to_param_value(value));
    }
}

/// Assemble the final entry: reject line breaks (the URI serializers emit
/// these fields verbatim) and enforce the parameter cap.
fn finish(
    scheme: Scheme,
    name: &str,
    host: String,
    port: u16,
    credential: String,
    params: Vec<Param>,
) -> Result<ProxyEntry, String> {
    super::reject_line_breaks("sing-box: server", &host)?;
    super::reject_line_breaks("sing-box: credential", &credential)?;
    if params.len() > super::uri::MAX_QUERY_PARAMS {
        return Err(format!(
            "sing-box: {} parameters, over the {} cap",
            params.len(),
            super::uri::MAX_QUERY_PARAMS
        ));
    }
    Ok(ProxyEntry {
        scheme,
        name: name.to_string(),
        host,
        port,
        credential,
        params,
        raw_path: String::new(),
        raw_line: String::new(),
    })
}

fn native_endpoint(map: &Map<String, Value>) -> Result<(String, u16), String> {
    let host = str_field(map, "server")
        .ok_or("sing-box: missing `server`")?
        .to_string();
    let port = numeric_field(map, "server_port")?;
    Ok((host, port))
}

fn push_param(params: &mut Vec<Param>, known: bool, key: &str, value: impl Into<String>) {
    let value = value.into();
    if value.is_empty() {
        return;
    }
    params.push(Param {
        key: key.to_string(),
        value,
        known,
    });
}

fn str_field<'a>(map: &'a Map<String, Value>, key: &str) -> Option<&'a str> {
    map.get(key)
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
}

fn required_str(map: &Map<String, Value>, key: &str) -> Result<String, String> {
    str_field(map, key)
        .map(str::to_string)
        .ok_or_else(|| format!("sing-box: missing field {key:?}"))
}

fn first_object<'a>(map: &'a Map<String, Value>, key: &str) -> Option<&'a Map<String, Value>> {
    map.get(key)
        .and_then(Value::as_array)
        .and_then(|items| items.first())
        .and_then(Value::as_object)
}

fn numeric_field(map: &Map<String, Value>, key: &str) -> Result<u16, String> {
    match map.get(key) {
        Some(Value::Number(n)) => n
            .as_u64()
            .and_then(|v| u16::try_from(v).ok())
            .ok_or_else(|| format!("sing-box: port out of range: {n}")),
        Some(Value::String(s)) => s
            .trim()
            .parse::<u16>()
            .map_err(|_| format!("sing-box: invalid port string: {s:?}")),
        _ => Err(format!("sing-box: missing field {key:?}")),
    }
}

fn xray_truthy(map: &Map<String, Value>, key: &str) -> bool {
    match map.get(key) {
        Some(Value::Bool(b)) => *b,
        Some(Value::String(s)) => matches!(s.trim().to_ascii_lowercase().as_str(), "true" | "1"),
        _ => false,
    }
}

/// A string, or an array of strings joined with commas (how `alpn`, `host`
/// and tcp-`path` lists flatten onto the URI parameter vocabulary).
fn string_or_joined_array(value: Option<&Value>) -> Option<String> {
    match value? {
        Value::String(s) => (!s.is_empty()).then(|| s.clone()),
        Value::Array(items) => {
            let joined = items
                .iter()
                .filter_map(Value::as_str)
                .filter(|s| !s.is_empty())
                .collect::<Vec<_>>()
                .join(",");
            (!joined.is_empty()).then_some(joined)
        }
        _ => None,
    }
}

fn json_to_param_value(value: &Value) -> String {
    match value {
        Value::String(s) => s.clone(),
        Value::Number(n) => n.to_string(),
        Value::Bool(b) => b.to_string(),
        Value::Null => String::new(),
        other => serde_json::to_string(other).unwrap_or_default(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parsers::{LineOutcome, parse_line, serialize};

    /// Compare entries ignoring `known` flags (they legitimately differ
    /// between the JSON parser and a re-parse from the URI form) and
    /// `raw_line` (struct formats carry none).
    fn assert_same_proxy(a: &ProxyEntry, b: &ProxyEntry) {
        assert_eq!(a.scheme, b.scheme, "scheme");
        assert_eq!(a.name, b.name, "name");
        assert_eq!(a.host, b.host, "host");
        assert_eq!(a.port, b.port, "port");
        assert_eq!(a.credential, b.credential, "credential");
        let pa: Vec<_> = a.params.iter().map(|p| (&p.key, &p.value)).collect();
        let pb: Vec<_> = b.params.iter().map(|p| (&p.key, &p.value)).collect();
        assert_eq!(pa, pb, "params differ");
    }

    fn parse_one(payload: &str) -> ProxyEntry {
        let result = parse_payload(payload).unwrap();
        assert_eq!(result.unsupported, 0);
        assert_eq!(result.invalid, 0);
        assert_eq!(result.entries.len(), 1);
        result.entries.into_iter().next().unwrap()
    }

    /// The strong output→input guarantee: the sing-box encoder output
    /// parses back to a proxy with the same identity, re-encodes to the
    /// identical document (the mapped TLS/transport fields survive — a lost
    /// field would change the document), and the parsed entry itself
    /// round-trips through its URI form unchanged. Parameters the output
    /// schema cannot represent (unknown transports, client-side knobs)
    /// legitimately do not survive the output encoder and are not compared.
    fn assert_output_round_trip(entry: &ProxyEntry) {
        let document = crate::formats::singbox::encode_singbox(std::slice::from_ref(entry));
        let parsed = parse_payload(&document).unwrap();
        assert_eq!(parsed.entries.len(), 1, "{document}");
        let back = &parsed.entries[0];
        assert_eq!(back.scheme, entry.scheme, "scheme");
        assert_eq!(back.host, entry.host, "host");
        assert_eq!(back.port, entry.port, "port");
        assert_eq!(back.credential, entry.credential, "credential");
        assert_eq!(back.name, entry.name, "name");
        assert_eq!(
            crate::formats::singbox::encode_singbox(&parsed.entries),
            document,
            "re-encoded document differs"
        );
        let LineOutcome::Parsed(reparsed) = parse_line(&serialize(back)) else {
            panic!("serialized entry no longer parses: {}", serialize(back));
        };
        assert_same_proxy(&reparsed, back);
    }

    #[test]
    fn native_vless_reality_grpc() {
        let entry = parse_one(
            r#"{"outbounds":[{"type":"vless","tag":"r","server":"h.example.com","server_port":443,
                "uuid":"u1","flow":"xtls-rprx-vision",
                "tls":{"enabled":true,"server_name":"s.example.com","insecure":true,
                       "alpn":["h2","http/1.1"],"utls":{"fingerprint":"chrome"},
                       "reality":{"enabled":true,"public_key":"PBK","short_id":"01ab"}},
                "transport":{"type":"grpc","service_name":"svc"}}]}"#,
        );
        assert_eq!(entry.scheme, Scheme::Vless);
        assert_eq!(entry.host, "h.example.com");
        assert_eq!(entry.port, 443);
        assert_eq!(entry.credential, "u1");
        assert_eq!(entry.name, "r");
        assert_eq!(entry.param("flow"), Some("xtls-rprx-vision"));
        assert_eq!(entry.param("security"), Some("reality"));
        assert_eq!(entry.param("sni"), Some("s.example.com"));
        assert_eq!(entry.param("insecure"), Some("true"));
        assert_eq!(entry.param("alpn"), Some("h2,http/1.1"));
        assert_eq!(entry.param("fp"), Some("chrome"));
        assert_eq!(entry.param("pbk"), Some("PBK"));
        assert_eq!(entry.param("sid"), Some("01ab"));
        assert_eq!(entry.param("type"), Some("grpc"));
        assert_eq!(entry.param("serviceName"), Some("svc"));
        assert_output_round_trip(&entry);
    }

    #[test]
    fn native_vmess_ws_tls() {
        let entry = parse_one(
            r#"{"outbounds":[{"type":"vmess","tag":"m","server":"h.example.com","server_port":8443,
                "uuid":"u2","security":"aes-128-gcm","alter_id":4,
                "tls":{"enabled":true,"server_name":"s.example.com"},
                "transport":{"type":"ws","path":"/ws","headers":{"Host":"ws.example.com"}}}]}"#,
        );
        assert_eq!(entry.scheme, Scheme::Vmess);
        assert_eq!(entry.param("scy"), Some("aes-128-gcm"));
        assert_eq!(entry.param("aid"), Some("4"));
        // vmess JSON spells TLS as `tls: "tls"`.
        assert_eq!(entry.param("tls"), Some("tls"));
        assert_eq!(entry.param("sni"), Some("s.example.com"));
        assert_eq!(entry.param("net"), Some("ws"));
        assert_eq!(entry.param("path"), Some("/ws"));
        assert_eq!(entry.param("host"), Some("ws.example.com"));
        assert_output_round_trip(&entry);
    }

    #[test]
    fn native_ss_hysteria2_socks() {
        let ss = parse_one(
            r#"{"outbounds":[{"type":"shadowsocks","tag":"s","server":"h.example.com","server_port":8388,
                "method":"aes-256-gcm","password":"pw",
                "plugin":"obfs-local","plugin_opts":"obfs=http;obfs-host=ob.example.com"}]}"#,
        );
        assert_eq!(ss.scheme, Scheme::Ss);
        assert_eq!(ss.credential, "aes-256-gcm:pw");
        assert_eq!(
            ss.param("plugin"),
            Some("obfs-local;obfs=http;obfs-host=ob.example.com")
        );
        assert_output_round_trip(&ss);

        let hy2 = parse_one(
            r#"{"outbounds":[{"type":"hysteria2","tag":"h","server":"h.example.com","server_port":443,
                "password":"hp","up_mbps":50,"down_mbps":200,
                "obfs":{"type":"salamander","password":"op"},
                "tls":{"enabled":true,"server_name":"h.example.com"}}]}"#,
        );
        assert_eq!(hy2.scheme, Scheme::Hysteria2);
        assert_eq!(hy2.param("obfs"), Some("salamander"));
        assert_eq!(hy2.param("obfs-password"), Some("op"));
        assert_eq!(hy2.param("upMbps"), Some("50"));
        assert_eq!(hy2.param("downMbps"), Some("200"));
        assert_output_round_trip(&hy2);

        let socks = parse_one(
            r#"{"outbounds":[{"type":"socks","tag":"k","server":"h.example.com","server_port":1080,
                "username":"user","password":"pass",
                "tls":{"enabled":true,"server_name":"h.example.com"}}]}"#,
        );
        assert_eq!(socks.scheme, Scheme::Socks5);
        assert_eq!(socks.credential, "user:pass");
        assert_eq!(socks.param("tls"), Some("true"));
        assert_eq!(socks.param("sni"), Some("h.example.com"));
        assert_output_round_trip(&socks);
    }

    #[test]
    fn native_unknown_fields_pass_through_and_tls_disabled_is_silent() {
        let entry = parse_one(
            r#"{"outbounds":[{"type":"trojan","tag":"t","server":"h.example.com","server_port":443,
                "password":"p","tls":{"enabled":false},
                "multiplex":{"enabled":true,"protocol":"h2mux"},
                "packet_encoding":"packetaddr"}]}"#,
        );
        // TLS off → no security parameter is invented.
        assert_eq!(entry.param("security"), None);
        assert_eq!(entry.param("packet_encoding"), Some("packetaddr"));
        assert_eq!(
            entry.param("multiplex"),
            Some(r#"{"enabled":true,"protocol":"h2mux"}"#)
        );
        // mux/sockopt are client-side and dropped.
        let with_mux = parse_one(
            r#"{"outbounds":[{"type":"trojan","tag":"t","server":"h.example.com","server_port":443,
                "password":"p","sockopt":{"domainStrategy":"UseIP"}}]}"#,
        );
        assert_eq!(with_mux.param("sockopt"), None);
        assert_output_round_trip(&entry);
    }

    #[test]
    fn xray_vless_vnext_tls_xhttp() {
        let entries = parse_payload(
            r#"{"log":{"loglevel":"warning"},"outbounds":[
                {"tag":"proxy","protocol":"vless",
                 "settings":{"vnext":[{"address":"1.2.3.4","port":443,
                    "users":[{"id":"u1","encryption":"none","flow":"xtls-rprx-vision","level":8}]}]},
                 "streamSettings":{"network":"xhttp","security":"tls",
                    "xhttpSettings":{"mode":"auto","host":"at.example.net","path":"/p/","extra":{"xmux":{}}},
                    "tlsSettings":{"serverName":"at.example.net","fingerprint":"qq","alpn":["h2","http/1.1"]}}},
                {"tag":"direct","protocol":"freedom"},
                {"tag":"blocked","protocol":"blackhole"}]}"#,
        )
        .unwrap();
        // freedom/blackhole are not proxies: skipped, not counted.
        assert_eq!(entries.entries.len(), 1);
        assert_eq!(entries.unsupported, 0);
        assert_eq!(entries.invalid, 0);
        let entry = &entries.entries[0];
        assert_eq!(entry.scheme, Scheme::Vless);
        assert_eq!(entry.name, "proxy");
        assert_eq!(entry.host, "1.2.3.4");
        assert_eq!(entry.credential, "u1");
        assert_eq!(entry.param("flow"), Some("xtls-rprx-vision"));
        // encryption=none is the default and not stored.
        assert_eq!(entry.param("encryption"), None);
        assert_eq!(entry.param("security"), Some("tls"));
        assert_eq!(entry.param("sni"), Some("at.example.net"));
        assert_eq!(entry.param("fp"), Some("qq"));
        assert_eq!(entry.param("alpn"), Some("h2,http/1.1"));
        assert_eq!(entry.param("type"), Some("xhttp"));
        assert_eq!(entry.param("mode"), Some("auto"));
        assert_eq!(entry.param("host"), Some("at.example.net"));
        assert_eq!(entry.param("path"), Some("/p/"));
        assert!(entry.param("extra").is_some());
        assert_output_round_trip(entry);
    }

    #[test]
    fn xray_vless_reality_ws_and_array_of_configs() {
        let payload = r#"[
            {"remarks":"cfg1","outbounds":[
                {"tag":"p1","protocol":"vless",
                 "settings":{"vnext":[{"address":"h1.example.com","port":443,
                    "users":[{"id":"u1","encryption":"none","flow":"xtls-rprx-vision"}]}]},
                 "streamSettings":{"network":"ws","security":"reality",
                    "realitySettings":{"serverName":"r.example.com","publicKey":"PBK",
                        "shortId":"bafa","spiderX":"/sp","fingerprint":"firefox","allowInsecure":true},
                    "wsSettings":{"path":"/rutube","headers":{"Host":"rutube.example.net"}}}},
                {"tag":"lb","protocol":"loopback"}]},
            {"remarks":"cfg2","outbounds":[
                {"tag":"p2","protocol":"vless",
                 "settings":{"vnext":[{"address":"h2.example.com","port":8443,
                    "users":[{"id":"u2","encryption":"none"}]}]},
                 "streamSettings":{"network":"tcp","security":"reality",
                    "realitySettings":{"serverName":"r2.example.com","publicKey":"PBK2","shortId":"aa"}}}]}]"#;
        let result = parse_payload(payload).unwrap();
        assert_eq!(result.entries.len(), 2);
        let first = &result.entries[0];
        assert_eq!(first.host, "h1.example.com");
        assert_eq!(first.param("security"), Some("reality"));
        assert_eq!(first.param("pbk"), Some("PBK"));
        assert_eq!(first.param("sid"), Some("bafa"));
        assert_eq!(first.param("fp"), Some("firefox"));
        assert_eq!(first.param("insecure"), Some("true"));
        assert_eq!(first.param("type"), Some("ws"));
        assert_eq!(first.param("path"), Some("/rutube"));
        assert_eq!(first.param("host"), Some("rutube.example.net"));
        // loopback is not a proxy.
        assert_eq!(result.unsupported, 0);
        for entry in &result.entries {
            assert_output_round_trip(entry);
        }
        assert_eq!(result.entries[1].host, "h2.example.com");
    }

    #[test]
    fn xray_vmess_trojan_ss_socks() {
        let vmess = parse_one(
            r#"{"outbounds":[{"tag":"v","protocol":"vmess",
                "settings":{"vnext":[{"address":"h.example.com","port":443,
                    "users":[{"id":"u1","alterId":32,"security":"aes-128-gcm"}]}]},
                "streamSettings":{"network":"tcp","security":"tls",
                    "tlsSettings":{"serverName":"t.example.com"}}}]}"#,
        );
        assert_eq!(vmess.scheme, Scheme::Vmess);
        assert_eq!(vmess.param("aid"), Some("32"));
        assert_eq!(vmess.param("scy"), Some("aes-128-gcm"));
        assert_eq!(vmess.param("tls"), Some("tls"));
        // Bare TCP is the implicit transport and is not stored.
        assert_eq!(vmess.param("net"), None);
        assert_output_round_trip(&vmess);

        let trojan = parse_one(
            r#"{"outbounds":[{"tag":"t","protocol":"trojan",
                "settings":{"servers":[{"address":"h.example.com","port":443,"password":"pw"}]},
                "streamSettings":{"network":"grpc","security":"tls",
                    "grpcSettings":{"serviceName":"svc"}}}]}"#,
        );
        assert_eq!(trojan.scheme, Scheme::Trojan);
        assert_eq!(trojan.credential, "pw");
        assert_eq!(trojan.param("type"), Some("grpc"));
        assert_eq!(trojan.param("serviceName"), Some("svc"));
        assert_output_round_trip(&trojan);

        let ss = parse_one(
            r#"{"outbounds":[{"tag":"s","protocol":"shadowsocks",
                "settings":{"servers":[{"address":"h.example.com","port":8388,
                    "method":"chacha20-ietf-poly1305","password":"pw"}]}}]}"#,
        );
        assert_eq!(ss.scheme, Scheme::Ss);
        assert_eq!(ss.credential, "chacha20-ietf-poly1305:pw");
        assert_output_round_trip(&ss);

        let socks = parse_one(
            r#"{"outbounds":[{"tag":"k","protocol":"socks",
                "settings":{"servers":[{"addr":"h.example.com","port":1080,
                    "users":[{"user":"u","pass":"p"}]}]}}]}"#,
        );
        assert_eq!(socks.scheme, Scheme::Socks5);
        assert_eq!(socks.credential, "u:p");
    }

    #[test]
    fn unsupported_protocols_are_counted_not_fatal() {
        let result = parse_payload(
            r#"{"outbounds":[
                {"type":"vless","tag":"ok","server":"h","server_port":1,"uuid":"u"},
                {"type":"tuic","tag":"t","server":"h","server_port":1,"uuid":"u"},
                {"protocol":"wireguard","tag":"w"},
                {"type":"selector","tag":"sel","outbounds":["ok"]}]}"#,
        )
        .unwrap();
        assert_eq!(result.entries.len(), 1);
        assert_eq!(result.unsupported, 2); // tuic + wireguard
        assert_eq!(result.invalid, 0); // selector is not a proxy at all
    }

    #[test]
    fn malformed_outbounds_are_counted_not_fatal() {
        let result = parse_payload(
            r#"{"outbounds":[
                {"type":"vless","server":"h.example.com","server_port":443,"uuid":"u"},
                {"type":"trojan","tag":"no-server","server_port":443,"password":"p"},
                {"type":"trojan","tag":"no-port","server":"h.example.com","password":"p"},
                "just a string",
                {"protocol":"vless","settings":{}}]}"#,
        )
        .unwrap();
        // The first outbound is valid: `tag` is optional like in Clash.
        assert_eq!(result.entries.len(), 1);
        assert_eq!(result.invalid, 4);
    }

    #[test]
    fn payload_without_outbounds_is_an_error() {
        assert!(parse_payload(r#"{"dns":{}}"#).is_err());
        assert!(parse_payload("[]").is_err());
        assert!(parse_payload("42").is_err());
        assert!(parse_payload("not json").is_err());
    }

    #[test]
    fn line_breaks_in_host_or_credential_are_rejected() {
        let result = parse_payload(
            r#"{"outbounds":[{"type":"trojan","tag":"evil","server":"h.example.com\nvless://X@9.9.9.9:443#inj","server_port":443,"password":"p"}]}"#,
        )
        .unwrap();
        assert_eq!(result.entries.len(), 0);
        assert_eq!(result.invalid, 1);
    }

    #[test]
    fn parameter_cap_is_enforced() {
        let mut outbound = String::from(
            r#"{"type":"trojan","tag":"t","server":"h","server_port":1,"password":"p""#,
        );
        for i in 0..300 {
            outbound.push_str(&format!(r#","f{i}":"v{i}""#));
        }
        outbound.push('}');
        let result = parse_payload(&format!(r#"{{"outbounds":[{outbound}]}}"#)).unwrap();
        assert_eq!(result.entries.len(), 0);
        assert_eq!(result.invalid, 1);
    }

    // ─────────────────────────────────────────────────────────────────────
    // Fixture tests against the real sing-box/Xray samples `test-sing.txt`
    // (single Xray config) and `test-sing2.txt` (v2rayN share array). The
    // fixtures are gitignored (real credentials) and never committed;
    // these tests skip themselves when the files are absent.
    // ─────────────────────────────────────────────────────────────────────

    fn fixture_payload(name: &str) -> Option<String> {
        std::fs::read_to_string(
            std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(format!("../../{name}")),
        )
        .ok()
    }

    #[test]
    fn fixture_single_config_parses_and_round_trips() {
        let Some(payload) = fixture_payload("test-sing.txt") else {
            eprintln!("skipped: test-sing.txt fixture is absent (gitignored debug file)");
            return;
        };
        let result = parse_payload(&payload).unwrap();
        // The whole-pipeline path must auto-detect the format too.
        let via_auto =
            crate::parsers::parse_subscription(&payload, crate::models::Encoding::Auto, None)
                .unwrap();
        assert_eq!(via_auto.format, crate::models::InputFormat::SingBoxJson);
        assert_eq!(via_auto.entries.len(), result.entries.len());
        assert_eq!(via_auto.clash_skipped, 0);
        assert_eq!(result.invalid, 0, "no outbound should be malformed");
        assert_eq!(result.unsupported, 0);
        assert!(
            result.entries.len() >= 30,
            "suspiciously few entries: {}",
            result.entries.len()
        );
        assert!(result.entries.iter().all(|e| e.scheme == Scheme::Vless));
        for entry in &result.entries {
            assert_output_round_trip(entry);
        }
    }

    #[test]
    fn fixture_share_array_parses_and_round_trips() {
        let Some(payload) = fixture_payload("test-sing2.txt") else {
            eprintln!("skipped: test-sing2.txt fixture is absent (gitignored debug file)");
            return;
        };
        let result = parse_payload(&payload).unwrap();
        let via_auto =
            crate::parsers::parse_subscription(&payload, crate::models::Encoding::Auto, None)
                .unwrap();
        assert_eq!(via_auto.format, crate::models::InputFormat::SingBoxJson);
        assert_eq!(via_auto.entries.len(), result.entries.len());
        assert_eq!(via_auto.clash_skipped, 0);
        assert_eq!(result.invalid, 0, "no outbound should be malformed");
        assert_eq!(result.unsupported, 0);
        assert!(
            result.entries.len() >= 70,
            "suspiciously few entries: {}",
            result.entries.len()
        );
        for entry in &result.entries {
            assert_output_round_trip(entry);
        }
    }
}
