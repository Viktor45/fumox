//! sing-box / Xray JSON subscription input.
//!
//! Two JSON dialects share the `outbounds` key and are both accepted:
//!
//! * **sing-box native**, outbounds carry `type`/`server`/`server_port`;
//!   the mapping is the exact inverse of the [`crate::formats::singbox`]
//!   output encoder, so `parse ∘ encode_singbox` round-trips;
//! * **Xray/v2ray-core ("vnext")**, outbounds carry
//!   `protocol`/`settings.vnext`/`streamSettings`. The payload may also be
//!   a bare array of such configs (the v2rayN share format), and the
//!   per-config keys sing-box ignores (`dns`, `routing`, `remarks`, …) are
//!   simply not read. Both the endpoint array (`vnext`, `servers`) and each
//!   endpoint's `users` array are iterated in full: every user is a
//!   separate credential and therefore a separate entry.
//!
//! Supported proxy types: vless, vmess, trojan, shadowsocks, hysteria2,
//! socks. Types that are not proxies at all (`selector`, `urltest`,
//! `direct`, `block`, `dns`, `freedom`, `blackhole`, `loopback`) are
//! skipped silently; proxy protocols without a [`ProxyEntry`]
//! representation (`tuic`, `http`, `wireguard`, …) are counted as
//! unsupported. Everything follows the log-and-skip principle: a bad
//! outbound never fails the payload.
//!
//! Logging contract: the element loops never log per element — they count
//! their skips and the caller emits one summary debug event per outbound,
//! and [`parse_payload`] one warn for the whole payload. Every skip event
//! names what the outbound declared: `kind` and `tag` when it identified
//! itself (the `tag` field is omitted when the outbound carries no usable
//! tag), and `error` when a concrete reason is known. Endpoint hosts and
//! other address identifiers are never logged raw: they are feed-controlled
//! strings, a control character in one must not reach the logs, and skips
//! are identified by `tag` alone. The one case where nothing is known about
//! the outbound (an element that is not a JSON object) carries only
//! `error`.
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

/// Upper bound on the users processed per Xray endpoint.
///
/// Every user is a separate credential and therefore a separate entry with
/// its own parameter set, so an endpoint carrying a million users turns a
/// small payload into a million rows. The cap bounds the work per endpoint;
/// the dropped users are counted as invalid.
const MAX_USERS_PER_ENDPOINT: usize = 16;

/// Result of parsing a sing-box / Xray JSON payload.
#[derive(Debug, Default)]
pub struct SingBoxParseResult {
    pub entries: Vec<ProxyEntry>,
    /// Proxy protocols recognized but without a `ProxyEntry` representation.
    pub unsupported: usize,
    /// Outbound objects missing required fields or over the parameter cap.
    pub invalid: usize,
    /// Outbounds left out because the payload reached the entry cap.
    pub skipped: usize,
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
    // One summary line for the whole payload: the element loops only count
    // their skips, so this is where the truncation becomes visible.
    if result.unsupported > 0 || result.invalid > 0 {
        tracing::warn!(
            entries = result.entries.len(),
            unsupported = result.unsupported,
            invalid = result.invalid,
            skipped = result.skipped,
            "sing-box: payload parsed with skips"
        );
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
        // Nothing is known about this outbound, so the event carries only
        // `error` (see the logging contract in the module docs).
        let message = "outbound is not a JSON object";
        tracing::debug!(error = message, "skipping malformed sing-box outbound");
        result.invalid += 1;
        return;
    };
    // Dialect: sing-box spells the kind `type`, Xray spells it `protocol`.
    let (kind_key, kind) = if let Some(kind) = map.get("type").and_then(Value::as_str) {
        ("type", kind)
    } else if let Some(kind) = map.get("protocol").and_then(Value::as_str) {
        ("protocol", kind)
    } else {
        let message = "outbound without a `type`/`protocol`";
        tracing::debug!(error = message, "skipping malformed sing-box outbound");
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
    // sing-box spells the SOCKS protocol version explicitly; only 5 has a
    // URI representation, so an explicit other version is counted as
    // unsupported like the protocols without a representation at all
    // (serializing it as socks5 would serve a socks4 node on a socks5 URI).
    if kind_key == "type"
        && matches!(kind, "socks" | "socks5")
        && str_field(map, "version").is_some_and(|version| version != "5")
    {
        tracing::debug!(
            kind,
            tag = skip_tag(&name),
            "sing-box: proxy protocol without a representation"
        );
        result.unsupported += 1;
        return;
    }
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
            tracing::debug!(
                kind,
                tag = skip_tag(&name),
                "sing-box: proxy protocol without a representation"
            );
            result.unsupported += 1;
            return;
        }
    };
    match built {
        Ok(built) => {
            // One summary event per outbound: the element loops count their
            // skips instead of logging per element (the logging contract is
            // in the module docs).
            if built.skips.any() {
                tracing::debug!(
                    kind,
                    tag = skip_tag(&name),
                    no_endpoint = built.skips.no_endpoint,
                    no_credential = built.skips.no_credential,
                    rejected = built.skips.rejected,
                    dropped = built.skips.dropped,
                    "sing-box: outbound skipped elements"
                );
            }
            for entry in built.entries {
                if result.entries.len() >= super::MAX_ENTRIES {
                    result.skipped += 1;
                    continue;
                }
                result.entries.push(entry);
            }
            // The users dropped by the per-endpoint cap, and the non-object
            // junk elements, are counted as invalid: they were recognized
            // but not stored.
            result.invalid += built.skips.dropped;
        }
        Err(message) => {
            tracing::debug!(
                kind,
                tag = skip_tag(&name),
                error = %message,
                "skipping malformed sing-box outbound"
            );
            result.invalid += 1;
        }
    }
}

/// The `tag` field of a skip event: `None` when the outbound carries no
/// usable tag, which omits the field from the event (the logging contract
/// is in the module docs).
fn skip_tag(name: &str) -> Option<&str> {
    (!name.is_empty()).then_some(name)
}

/// What one outbound produced: its entries plus its skip counters. The
/// users/junk counted in `skips.dropped` become invalid; the rest of the
/// counters is summarized in one event per outbound.
struct XrayOutbound {
    entries: Vec<ProxyEntry>,
    skips: XraySkips,
}

/// Skip counters of one outbound. The element loops count instead of
/// logging per element — an endpoint carrying a cap-sized user list would
/// otherwise flood the log with one line per user (see the logging contract
/// in the module docs).
#[derive(Default)]
struct XraySkips {
    /// Endpoint elements without a usable address/port.
    no_endpoint: usize,
    /// Elements without their credential field (`id`/`password`/`method`).
    no_credential: usize,
    /// Elements whose entry `finish` rejected (line breaks, size caps).
    rejected: usize,
    /// Non-object elements dropped from the endpoint/user arrays plus the
    /// users over the per-endpoint cap; counted as invalid.
    dropped: usize,
}

impl XraySkips {
    fn merge(&mut self, other: XraySkips) {
        self.no_endpoint += other.no_endpoint;
        self.no_credential += other.no_credential;
        self.rejected += other.rejected;
        self.dropped += other.dropped;
    }

    fn any(&self) -> bool {
        self.no_endpoint + self.no_credential + self.rejected + self.dropped > 0
    }
}

fn vec1(entry: ProxyEntry) -> XrayOutbound {
    XrayOutbound {
        entries: vec![entry],
        skips: XraySkips::default(),
    }
}

// sing-box native dialect

fn native_vless(map: &Map<String, Value>, name: &str) -> Result<ProxyEntry, String> {
    let (host, port) = native_endpoint(map)?;
    let credential = required_str(map, "uuid")?;
    let mut params = Vec::new();
    if let Some(flow) = str_field(map, "flow") {
        push_param(&mut params, true, "flow", flow);
    }
    if let Some(tls) = map.get("tls").and_then(Value::as_object) {
        native_tls_params(tls, Some("security"), &mut params);
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
    // `tls: "tls"`, same convention as the vmess URI parser.
    if let Some(scy) = str_field(map, "security") {
        push_param(&mut params, true, "scy", scy);
    }
    if let Some(aid) = map.get("alter_id") {
        push_param(&mut params, true, "aid", json_to_param_value(aid));
    }
    if let Some(tls) = map.get("tls").and_then(Value::as_object) {
        native_tls_params(tls, Some("tls"), &mut params);
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
        native_tls_params(tls, Some("security"), &mut params);
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
    // A record without a password is invalid, not a no-auth proxy.
    let password = required_str(map, "password")?;
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
        native_tls_params(tls, Some("security"), &mut params);
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
    if let Some(tls) = map.get("tls").and_then(Value::as_object) {
        // The socks5 serializer rebuilds TLS from the bare `tls` toggle; the
        // field mapping itself comes from the shared helper, so the TLS
        // parameters of every native scheme have a single source.
        native_tls_params(tls, None, &mut params);
        if tls.get("enabled").and_then(Value::as_bool) == Some(true) {
            push_param(&mut params, true, "tls", "true");
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
/// NAME of the key spelled for TLS-on: `security` for the URI-family
/// schemes, `tls` for vmess JSON, nothing for socks.
fn native_tls_params(tls: &Map<String, Value>, security: Option<&str>, params: &mut Vec<Param>) {
    // The value the security key carries when TLS is on (`security=tls`,
    // `tls=tls`).
    const TLS_ON: &str = "tls";
    let enabled = tls.get("enabled").and_then(Value::as_bool).unwrap_or(false);
    let reality = tls.get("reality").and_then(Value::as_object);
    // An explicit `enabled: false` switches REALITY off, public key or not.
    // Without the switch the legacy lenient mode applies: a public key means
    // REALITY.
    let reality_on = reality.is_some_and(|r| match r.get("enabled").and_then(Value::as_bool) {
        Some(enabled) => enabled,
        None => str_field(r, "public_key").is_some(),
    });
    if !enabled && !reality_on {
        return;
    }
    match security {
        Some("security") if reality_on => push_param(params, true, "security", "reality"),
        Some(key) => push_param(params, true, key, TLS_ON),
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
            if let Some(headers) = transport.get("headers").and_then(Value::as_object) {
                if let Some(host) = headers.get("Host").and_then(Value::as_str) {
                    push_param(params, true, "host", host);
                }
                // Headers other than `Host` are part of the handshake
                // identity a client has to replay; they pass through as
                // `headers.<name>` parameters, like the other unmapped
                // fields.
                for (key, value) in headers {
                    if key.eq_ignore_ascii_case("host") || value.is_null() {
                        continue;
                    }
                    push_param(
                        params,
                        false,
                        &format!("headers.{key}"),
                        json_to_param_value(value),
                    );
                }
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

// Xray/v2ray-core ("vnext") dialect

/// Shared skeleton of the Xray builders: iterate `settings.<field>`, hand
/// every element to `per_element`, and apply the log-and-skip contract — a
/// junk element costs only itself, and the outbound is rejected only when
/// *no* element produced an entry: bailing out of the loop would throw away
/// the entries already built and charge a single invalid for the whole
/// outbound.
fn xray_elements<F>(
    map: &Map<String, Value>,
    field: &str,
    empty: &str,
    mut per_element: F,
) -> Result<XrayOutbound, String>
where
    F: FnMut(&Map<String, Value>) -> (Vec<ProxyEntry>, XraySkips),
{
    let (list, junk) = xray_settings_list(map, field)?;
    let mut entries = Vec::new();
    let mut skips = XraySkips {
        dropped: junk,
        ..Default::default()
    };
    let mut elements = 0usize;
    for element in list {
        elements += 1;
        let (built, element_skips) = per_element(element);
        skips.merge(element_skips);
        entries.extend(built);
    }
    if elements > 0 && entries.is_empty() {
        return Err(empty.to_string());
    }
    Ok(XrayOutbound { entries, skips })
}

/// The `vnext` dialect of [`xray_elements`]: every element is an endpoint
/// carrying a `users` list, one entry per user. vless and vmess differ only
/// in their per-user fields and the stream/TLS spelling, so the endpoint
/// and user scaffolding is shared; `per_user` contributes the user's own
/// fields and `security` is the TLS-on spelling of the scheme (see
/// [`xray_stream_params`]).
fn xray_vnext_elements<F>(
    map: &Map<String, Value>,
    scheme: Scheme,
    name: &str,
    network_key: &str,
    security: Option<&str>,
    empty: &str,
    per_user: F,
) -> Result<XrayOutbound, String>
where
    F: Fn(&Map<String, Value>, &mut Vec<Param>),
{
    xray_elements(map, "vnext", empty, |vnext| {
        let Ok((host, port)) = xray_endpoint(vnext) else {
            return (
                Vec::new(),
                XraySkips {
                    no_endpoint: 1,
                    ..Default::default()
                },
            );
        };
        let (users, dropped) = xray_users(vnext);
        let mut entries = Vec::new();
        let mut skips = XraySkips {
            dropped,
            ..Default::default()
        };
        for user in users {
            let Some(id) = str_field(user, "id") else {
                skips.no_credential += 1;
                continue;
            };
            let mut params = Vec::new();
            per_user(user, &mut params);
            if let Some(stream) = map.get("streamSettings").and_then(Value::as_object) {
                xray_stream_params(stream, network_key, security, &mut params);
            }
            passthrough(map, XRAY_TOP_LEVEL_CONSUMED, &mut params);
            // `finish` rejects (among others) a credential carrying a line
            // break, which is this one user only; propagating it would
            // discard the entries of every other endpoint.
            match finish(scheme, name, host.clone(), port, id.to_string(), params) {
                Ok(entry) => entries.push(entry),
                Err(_) => skips.rejected += 1,
            }
        }
        (entries, skips)
    })
}

fn xray_vless(map: &Map<String, Value>, name: &str) -> Result<XrayOutbound, String> {
    xray_vnext_elements(
        map,
        Scheme::Vless,
        name,
        "type",
        Some("security"),
        "xray: vless vnext without a usable user",
        |user, params| {
            if let Some(flow) = str_field(user, "flow") {
                push_param(params, true, "flow", flow);
            }
            if let Some(encryption) = str_field(user, "encryption")
                && encryption != "none"
            {
                push_param(params, true, "encryption", encryption);
            }
        },
    )
}

fn xray_vmess(map: &Map<String, Value>, name: &str) -> Result<XrayOutbound, String> {
    // vmess JSON spells TLS as `tls: "tls"`.
    xray_vnext_elements(
        map,
        Scheme::Vmess,
        name,
        "net",
        Some("tls"),
        "xray: vmess vnext without a usable user",
        |user, params| {
            if let Some(scy) = str_field(user, "security") {
                push_param(params, true, "scy", scy);
            }
            if let Some(aid) = user.get("alterId") {
                push_param(params, true, "aid", json_to_param_value(aid));
            }
            if let Some(encryption) = str_field(user, "encryption")
                && encryption != "none"
            {
                push_param(params, true, "encryption", encryption);
            }
        },
    )
}

fn xray_trojan(map: &Map<String, Value>, name: &str) -> Result<XrayOutbound, String> {
    xray_elements(
        map,
        "servers",
        "xray: trojan server without a usable endpoint",
        |server| {
            let mut skips = XraySkips::default();
            // A malformed element costs only itself (log-and-skip); the
            // `?` used to end the whole loop and discard the entries
            // already built for the elements before it.
            let (host, port) = match xray_endpoint(server) {
                Ok(endpoint) => endpoint,
                Err(_) => {
                    skips.no_endpoint += 1;
                    return (Vec::new(), skips);
                }
            };
            let Some(credential) = str_field(server, "password") else {
                skips.no_credential += 1;
                return (Vec::new(), skips);
            };
            let mut params = Vec::new();
            if let Some(stream) = map.get("streamSettings").and_then(Value::as_object) {
                xray_stream_params(stream, "type", Some("security"), &mut params);
            }
            passthrough(map, XRAY_TOP_LEVEL_CONSUMED, &mut params);
            match finish(
                Scheme::Trojan,
                name,
                host,
                port,
                credential.to_string(),
                params,
            ) {
                Ok(entry) => (vec![entry], skips),
                Err(_) => {
                    skips.rejected += 1;
                    (Vec::new(), skips)
                }
            }
        },
    )
}

fn xray_ss(map: &Map<String, Value>, name: &str) -> Result<XrayOutbound, String> {
    let settings = map.get("settings").and_then(Value::as_object);
    let plugin = settings
        .and_then(|s| s.get("plugin"))
        .and_then(Value::as_str);
    let plugin_opts = settings
        .and_then(|s| s.get("pluginOpts"))
        .and_then(Value::as_str)
        .unwrap_or_default();
    xray_elements(
        map,
        "servers",
        "xray: shadowsocks server without a usable endpoint",
        |server| {
            let mut skips = XraySkips::default();
            let (host, port) = match xray_endpoint(server) {
                Ok(endpoint) => endpoint,
                Err(_) => {
                    skips.no_endpoint += 1;
                    return (Vec::new(), skips);
                }
            };
            let Ok(method) = required_str(server, "method") else {
                skips.no_credential += 1;
                return (Vec::new(), skips);
            };
            // A server without a password is unusable, not a no-auth proxy.
            let Ok(password) = required_str(server, "password") else {
                skips.no_credential += 1;
                return (Vec::new(), skips);
            };
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
            match finish(
                Scheme::Ss,
                name,
                host,
                port,
                format!("{method}:{password}"),
                params,
            ) {
                Ok(entry) => (vec![entry], skips),
                Err(_) => {
                    skips.rejected += 1;
                    (Vec::new(), skips)
                }
            }
        },
    )
}

fn xray_socks(map: &Map<String, Value>, name: &str) -> Result<XrayOutbound, String> {
    xray_elements(
        map,
        "servers",
        "xray: socks server without a usable endpoint",
        |server| {
            let mut skips = XraySkips::default();
            // Unlike the other dialects socks accepts an `addr` spelling too.
            let (Some(host), Ok(port)) = (
                str_field(server, "address").or_else(|| str_field(server, "addr")),
                numeric_field(server, "port", "xray"),
            ) else {
                skips.no_endpoint += 1;
                return (Vec::new(), skips);
            };
            // A socks server without a `users` list is a no-auth proxy and
            // still yields one entry; with a list, every user is a separate
            // proxy.
            let (users, dropped) = xray_users(server);
            skips.dropped += dropped;
            let users: Vec<(String, String)> = users
                .into_iter()
                .map(|user| {
                    (
                        str_field(user, "user").unwrap_or_default().to_string(),
                        str_field(user, "pass").unwrap_or_default().to_string(),
                    )
                })
                .collect();
            let credentials = if users.is_empty() {
                vec![(String::new(), String::new())]
            } else {
                users
            };
            let mut entries = Vec::new();
            for (username, password) in credentials {
                let mut params = Vec::new();
                passthrough(map, XRAY_TOP_LEVEL_CONSUMED, &mut params);
                match finish(
                    Scheme::Socks5,
                    name,
                    host.to_string(),
                    port,
                    format!("{username}:{password}"),
                    params,
                ) {
                    Ok(entry) => entries.push(entry),
                    Err(_) => skips.rejected += 1,
                }
            }
            (entries, skips)
        },
    )
}

/// The `users` array of one Xray endpoint (`vnext[i].users`,
/// `servers[i].users`) as objects, with the number of elements dropped as
/// non-object junk or over the per-endpoint cap; the caller counts every
/// dropped element as invalid (see [`xray_elements`]).
///
/// Every user is a distinct credential for the same endpoint, so each one
/// becomes its own [`ProxyEntry`], the same treatment the sibling
/// `vnext`/`servers` arrays already get, and the reason a multi-user
/// outbound must not be collapsed to its first element. A junk element
/// costs only itself (log-and-skip), not the credentials around it.
///
/// At most [`MAX_USERS_PER_ENDPOINT`] users are processed; the rest are
/// counted as invalid, so one endpoint cannot turn a small payload into an
/// unbounded number of rows.
fn xray_users(map: &Map<String, Value>) -> XrayObjects<'_> {
    let Some(list) = map.get("users").and_then(Value::as_array) else {
        return (Vec::new(), 0);
    };
    let mut users: Vec<&Map<String, Value>> = list.iter().filter_map(Value::as_object).collect();
    let mut dropped = list.len() - users.len();
    if users.len() > MAX_USERS_PER_ENDPOINT {
        let over = users.len() - MAX_USERS_PER_ENDPOINT;
        tracing::warn!(
            users = users.len(),
            cap = MAX_USERS_PER_ENDPOINT,
            dropped = over,
            "sing-box: endpoint carries more users than the cap, the rest are dropped"
        );
        users.truncate(MAX_USERS_PER_ENDPOINT);
        dropped += over;
    }
    (users, dropped)
}

/// Outbound keys consumed structurally by every Xray builder; `mux` is a
/// client-side multiplexing knob, not proxy identity.
const XRAY_TOP_LEVEL_CONSUMED: &[&str] = &["tag", "protocol", "settings", "streamSettings", "mux"];

/// The object elements of an endpoint/user array (`settings.vnext`,
/// `settings.servers`, `users`), plus the number of elements dropped as
/// junk or over the per-endpoint cap; the caller counts every dropped
/// element as invalid.
type XrayObjects<'a> = (Vec<&'a Map<String, Value>>, usize);

/// Iterate `settings.<field>` (an array of endpoint objects). Non-object
/// elements are junk: they cost their number in `result.invalid` and one
/// line in the per-outbound summary event.
fn xray_settings_list<'a>(
    map: &'a Map<String, Value>,
    field: &str,
) -> Result<XrayObjects<'a>, String> {
    let list = map
        .get("settings")
        .and_then(Value::as_object)
        .and_then(|settings| settings.get(field))
        .and_then(Value::as_array)
        .ok_or_else(|| format!("xray: settings.{field} missing"))?;
    let junk = list.iter().filter(|v| v.as_object().is_none()).count();
    Ok((list.iter().filter_map(Value::as_object).collect(), junk))
}

/// The endpoint of one Xray element: `address`/`port`.
fn xray_endpoint(map: &Map<String, Value>) -> Result<(String, u16), String> {
    endpoint_fields(map, "address", "port", "xray")
}

/// Map `streamSettings` onto parameters; `network_key` is `type` for the
/// URI-family schemes, `net` for vmess. `security` is the NAME of the key
/// spelling TLS-on for the scheme (see [`native_tls_params`]).
fn xray_stream_params(
    stream: &Map<String, Value>,
    network_key: &str,
    security: Option<&str>,
    params: &mut Vec<Param>,
) {
    // The value the security key carries when TLS is on (`security=tls`,
    // `tls=tls`).
    const TLS_ON: &str = "tls";
    let network = str_field(stream, "network").unwrap_or("tcp");
    // TCP is the implicit transport in every dialect; `type=tcp` is stored
    // only when it carries HTTP obfuscation (see the `tcp` arm below).
    // Xray renamed `tcp` to `raw` in 1.8.24; it is the same transport.
    if network != "tcp" && network != "raw" {
        push_param(params, true, network_key, network);
    }
    match str_field(stream, "security") {
        Some("tls") => {
            if let Some(key) = security {
                push_param(params, true, key, TLS_ON);
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
                Some("security") => push_param(params, true, "security", "reality"),
                Some(key) => push_param(params, true, key, TLS_ON),
                None => {}
            }
            // `spiderX` is an Xray client-side crawler impersonation knob
            // (like `sockopt`) with no proxy-identity meaning and is
            // deliberately not read; the identity fields below are.
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
                if let Some(headers) = ws.get("headers").and_then(Value::as_object) {
                    if let Some(host) = string_or_joined_array(headers.get("Host")) {
                        push_param(params, true, "host", host);
                    }
                    // Headers other than `Host` are part of the handshake
                    // identity a client has to replay; they pass through as
                    // `headers.<name>` parameters, like the other unmapped
                    // fields.
                    for (key, value) in headers {
                        if key.eq_ignore_ascii_case("host") || value.is_null() {
                            continue;
                        }
                        push_param(
                            params,
                            false,
                            &format!("headers.{key}"),
                            json_to_param_value(value),
                        );
                    }
                }
                passthrough_settings(params, ws, &["path", "headers"]);
            }
        }
        "grpc" => {
            if let Some(grpc) = stream.get("grpcSettings").and_then(Value::as_object) {
                if let Some(service) = str_field(grpc, "serviceName") {
                    push_param(params, true, "serviceName", service);
                }
                passthrough_settings(params, grpc, &["serviceName"]);
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
                passthrough_settings(params, http, &["host", "path"]);
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
                passthrough_settings(params, upgrade, &["path", "host"]);
            }
        }
        "xhttp" | "splithttp" => {
            // Xray renamed the transport `splithttp` to `xhttp`; either
            // settings key may spell the block.
            if let Some(xhttp) = stream
                .get("xhttpSettings")
                .or_else(|| stream.get("splithttpSettings"))
                .and_then(Value::as_object)
            {
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
                passthrough_settings(params, xhttp, &["host", "path", "mode", "extra"]);
            }
        }
        // The mKCP and QUIC transports have no URI spelling the clients
        // understand, so their whole settings block passes through as one
        // unknown parameter: nothing is lost, and a client that knows the
        // transport can still read it.
        "kcp" | "quic" => {
            let key = format!("{network}Settings");
            if let Some(settings) = stream.get(&key) {
                push_param(params, false, &key, json_to_param_value(settings));
            }
        }
        // TCP with HTTP obfuscation (`header.type: "http"`); plain TCP
        // (`type: "none"` or absent) maps to no parameters at all. Xray's
        // `raw` is the renamed TCP transport and carries the same block.
        "tcp" | "raw" => {
            let key = if network == "raw" {
                "rawSettings"
            } else {
                "tcpSettings"
            };
            if let Some(settings) = stream.get(key).and_then(Value::as_object) {
                if let Some(header) = settings.get("header").and_then(Value::as_object)
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
                passthrough_settings(params, settings, &["header"]);
            }
        }
        _ => {}
    }
}

// Shared helpers

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

/// Keep the keys of a transport settings object the mapping did not consume.
///
/// A settings block carries transport identity (`maxEarlyData`,
/// `earlyDataHeaderName`, `seed`, …); dropping the unused ones loses
/// information, so they pass through under their original names as unknown
/// parameters.
fn passthrough_settings(params: &mut Vec<Param>, settings: &Map<String, Value>, consumed: &[&str]) {
    for (key, value) in settings {
        if consumed.contains(&key.as_str()) || value.is_null() {
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
    let host = super::normalize_host(&host);
    if host.is_empty() {
        return Err("sing-box: empty server".to_string());
    }
    super::reject_line_breaks("sing-box: server", &host)?;
    super::reject_line_breaks("sing-box: credential", &credential)?;
    // The host, the credential and the name are stored verbatim on every
    // row, so an oversized one is a storage bomb (the vector formats are
    // not bounded as a whole the way a URI list is).
    super::check_field_size("sing-box: server", &host)?;
    super::check_field_size("sing-box: credential", &credential)?;
    // A missing or non-string `tag` falls back to a `host:port` name (an
    // IPv6 host bracketed, the shape a URI authority spells). The
    // placeholder derives from the already-capped host, so it cannot exceed
    // the caps itself.
    let name = if name.is_empty() {
        host_port_name(&host, port)
    } else {
        name.to_string()
    };
    super::check_field_size("sing-box: name", &name)?;
    // JSON strings may contain `\n`, and the URI serializers emit these
    // fields verbatim (see `parsers::reject_line_breaks`). The cheap check
    // first keeps the per-param message allocation off the common path.
    for param in &params {
        if param.value.contains(['\n', '\r']) {
            super::reject_line_breaks(&format!("sing-box: field {:?}", param.key), &param.value)?;
        }
    }
    // Field-size cap: sing-box
    // params bypass `parse_query`, so the caps are enforced here.
    super::validate_params("sing-box", &params)?;
    Ok(super::with_canonical_cache(ProxyEntry {
        scheme,
        name,
        host,
        port,
        credential,
        params,
        raw_path: String::new(),
        raw_line: String::new(),
        canonical: None,
    }))
}

/// `host:port` with an IPv6 host bracketed: the name an outbound without a
/// usable `tag` falls back to (see `finish`).
fn host_port_name(host: &str, port: u16) -> String {
    if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

/// The endpoint of one sing-box native outbound: `server`/`server_port`.
fn native_endpoint(map: &Map<String, Value>) -> Result<(String, u16), String> {
    endpoint_fields(map, "server", "server_port", "sing-box")
}

/// The endpoint pair of an outbound/endpoint element; `dialect` prefixes
/// the one message template shared by every endpoint error.
fn endpoint_fields(
    map: &Map<String, Value>,
    host_key: &str,
    port_key: &str,
    dialect: &str,
) -> Result<(String, u16), String> {
    let host = str_field(map, host_key)
        .ok_or_else(|| format!("{dialect}: missing field {host_key:?}"))?
        .to_string();
    let port = numeric_field(map, port_key, dialect)?;
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
        bare: false,
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

/// A JSON number or decimal-string port; `dialect` prefixes the message.
fn numeric_field(map: &Map<String, Value>, key: &str, dialect: &str) -> Result<u16, String> {
    match map.get(key) {
        Some(Value::Number(n)) => n
            .as_u64()
            .and_then(|v| u16::try_from(v).ok())
            // Port 0 is not a dialable endpoint (the schema CHECK, migration
            // 0018, refuses it too), so the outbound is as invalid as an
            // out-of-range one.
            .filter(|&p| p != 0)
            .ok_or_else(|| format!("{dialect}: port out of range: {n}")),
        Some(Value::String(s)) => match s.trim().parse::<u16>() {
            // The same zero rejection on the string spelling.
            Ok(0) | Err(_) => Err(format!("{dialect}: invalid port string: {s:?}")),
            Ok(port) => Ok(port),
        },
        _ => Err(format!("{dialect}: missing field {key:?}")),
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
    use crate::parsers::uri::percent_decode;
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
    /// identical document (the mapped TLS/transport fields survive, a lost
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

    /// Port 0 is not a dialable endpoint: the outbound is invalid in either
    /// spelling, not stored with a port no client could connect to.
    #[test]
    fn a_zero_singbox_port_is_invalid() {
        for port in [r#""server_port":0"#, r#""server_port":"0""#] {
            let payload = format!(
                r#"{{"outbounds":[{{"type":"trojan","tag":"t","server":"h",{port},"password":"p"}}]}}"#
            );
            let result = parse_payload(&payload).unwrap();
            assert_eq!(result.entries.len(), 0, "{payload}");
            assert_eq!(result.invalid, 1, "{payload}");
        }
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

    /// Native `httpupgrade`: the path and the host are flat fields of the
    /// transport block.
    #[test]
    fn the_native_httpupgrade_transport_maps_path_and_host() {
        let entry = parse_one(
            r#"{"outbounds":[{"type":"vless","tag":"u","server":"h.example.com","server_port":443,
                "uuid":"u1",
                "transport":{"type":"httpupgrade","path":"/up","host":"up.example.net"}}]}"#,
        );
        assert_eq!(entry.param("type"), Some("httpupgrade"));
        assert_eq!(entry.param("path"), Some("/up"));
        assert_eq!(entry.param("host"), Some("up.example.net"));
        assert_output_round_trip(&entry);
    }

    /// Native `http`/`h2`: the `host` list flattens onto one comma-joined
    /// parameter, the same shape a URI carries.
    #[test]
    fn the_native_http_transport_joins_the_host_array() {
        let entry = parse_one(
            r#"{"outbounds":[{"type":"vless","tag":"h","server":"h.example.com","server_port":443,
                "uuid":"u1",
                "transport":{"type":"http","host":["a.example.net","b.example.net"],
                             "path":"/h2"}}]}"#,
        );
        assert_eq!(entry.param("type"), Some("http"));
        assert_eq!(entry.param("host"), Some("a.example.net,b.example.net"));
        assert_eq!(entry.param("path"), Some("/h2"));
        assert_output_round_trip(&entry);
    }

    /// Xray plain TCP with HTTP obfuscation (`header.type: "http"`):
    /// `type=tcp` is stored together with the `headertype`/path/host
    /// spelling the URI vocabulary uses.
    #[test]
    fn the_tcp_transport_with_http_obfuscation_maps_the_header() {
        let entry = parse_one(
            r#"{"outbounds":[{"protocol":"vless","tag":"t",
                "settings":{"vnext":[{"address":"h.example.com","port":443,
                    "users":[{"id":"u1","encryption":"none"}]}]},
                "streamSettings":{"network":"tcp","security":"none",
                    "tcpSettings":{"header":{"type":"http",
                        "request":{"path":["/tcp"],"headers":{"Host":["tcp.example.net"]}}}}}}]}"#,
        );
        assert_eq!(entry.param("type"), Some("tcp"));
        assert_eq!(entry.param("headertype"), Some("http"));
        assert_eq!(entry.param("path"), Some("/tcp"));
        assert_eq!(entry.param("host"), Some("tcp.example.net"));
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
        let with_sockopt = parse_one(
            r#"{"outbounds":[{"type":"trojan","tag":"t","server":"h.example.com","server_port":443,
                "password":"p","sockopt":{"domainStrategy":"UseIP"}}]}"#,
        );
        assert_eq!(with_sockopt.param("sockopt"), None);
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

    /// Xray renamed the transport `splithttp` to `xhttp`; the settings
    /// block under the old `splithttpSettings` key parses the same way.
    #[test]
    fn the_old_splithttp_settings_key_parses() {
        let entry = parse_one(
            r#"{"outbounds":[{"protocol":"vless","tag":"s",
                "settings":{"vnext":[{"address":"h.example.com","port":443,
                    "users":[{"id":"u1","encryption":"none"}]}]},
                "streamSettings":{"network":"splithttp","security":"tls",
                    "splithttpSettings":{"path":"/ray","host":"h.example.com"}}}]}"#,
        );
        assert_eq!(entry.param("type"), Some("splithttp"));
        assert_eq!(entry.param("path"), Some("/ray"));
        assert_eq!(entry.param("host"), Some("h.example.com"));
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
        assert_output_round_trip(&socks);
    }

    /// A socks server without a `users` list is a no-auth proxy: one entry
    /// with the empty credential pair.
    #[test]
    fn a_socks_server_without_users_is_no_auth() {
        let socks = parse_one(
            r#"{"outbounds":[{"tag":"k","protocol":"socks",
                "settings":{"servers":[{"address":"h.example.com","port":1080}]}}]}"#,
        );
        assert_eq!(socks.scheme, Scheme::Socks5);
        assert_eq!(socks.credential, ":");
        assert_output_round_trip(&socks);
    }

    /// A Shadowsocks record without a `password` is invalid, not a no-auth
    /// proxy.
    #[test]
    fn a_shadowsocks_without_password_is_invalid() {
        let result = parse_payload(
            r#"{"outbounds":[{"type":"shadowsocks","tag":"s","server":"h.example.com",
                "server_port":8388,"method":"aes-256-gcm"}]}"#,
        )
        .unwrap();
        assert_eq!(result.entries.len(), 0);
        assert_eq!(result.invalid, 1);
    }

    /// sing-box spells the SOCKS protocol version explicitly; only 5 has a
    /// URI representation, an explicit 4 is counted as unsupported instead
    /// of being served as a socks5 URI.
    #[test]
    fn a_native_socks4_outbound_is_unsupported() {
        let result = parse_payload(
            r#"{"outbounds":[{"type":"socks","tag":"k4","server":"h.example.com",
                "server_port":1080,"version":"4","username":"u","password":"p"}]}"#,
        )
        .unwrap();
        assert_eq!(result.entries.len(), 0);
        assert_eq!(result.unsupported, 1);
        assert_eq!(result.invalid, 0);
    }

    /// An Xray `port` may be spelled as a JSON string; it parses like the
    /// number form.
    #[test]
    fn an_xray_port_spelled_as_a_string_parses() {
        let entry = parse_one(
            r#"{"outbounds":[{"tag":"t","protocol":"trojan",
                "settings":{"servers":[{"address":"h.example.com","port":"443","password":"pw"}]}}]}"#,
        );
        assert_eq!(entry.port, 443);
    }

    /// A missing or non-string `tag` falls back to a `host:port` name, an
    /// IPv6 host bracketed the way a URI authority spells it.
    #[test]
    fn a_missing_or_non_string_tag_falls_back_to_host_port() {
        let result = parse_payload(
            r#"{"outbounds":[
                {"type":"trojan","server":"h.example.com","server_port":443,"password":"p"},
                {"type":"trojan","tag":4,"server":"[2001:db8::1]","server_port":8443,
                 "password":"p"}]}"#,
        )
        .unwrap();
        assert_eq!(result.entries.len(), 2);
        assert_eq!(result.invalid, 0);
        assert_eq!(result.entries[0].name, "h.example.com:443");
        assert_eq!(result.entries[1].name, "[2001:db8::1]:8443");
    }

    /// WS headers other than `Host` are part of the handshake identity and
    /// pass through as `headers.<name>` parameters.
    #[test]
    fn ws_headers_other_than_host_pass_through() {
        let entry = parse_one(
            r#"{"outbounds":[{"protocol":"vless","tag":"w",
                "settings":{"vnext":[{"address":"h.example.com","port":443,
                    "users":[{"id":"u1","encryption":"none"}]}]},
                "streamSettings":{"network":"ws","security":"none",
                    "wsSettings":{"path":"/ws",
                        "headers":{"Host":"ws.example.net","Authorization":"Basic ZZ"}}}}]}"#,
        );
        assert_eq!(entry.param("host"), Some("ws.example.net"));
        assert_eq!(entry.param("headers.Authorization"), Some("Basic ZZ"));
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

    /// An empty server is not a proxy: it must be counted as invalid instead
    /// of stored as a row whose host is the empty string. An oversized host
    /// or credential is a storage bomb the same way (the vector formats are
    /// not bounded as a whole the way a URI list is).
    #[test]
    fn an_empty_or_oversized_server_is_invalid() {
        let long = "h".repeat(crate::parsers::uri::MAX_PARAM_BYTES + 1);
        let payload = format!(
            r#"{{"outbounds":[
                {{"type":"vless","tag":"empty","server":"","server_port":443,"uuid":"u"}},
                {{"type":"vless","tag":"huge","server":"{long}","server_port":443,"uuid":"u"}},
                {{"type":"trojan","tag":"ok","server":"h.example.com","server_port":443,
                 "password":"p"}}]}}"#
        );
        let result = parse_payload(&payload).unwrap();
        assert_eq!(result.entries.len(), 1);
        assert_eq!(result.invalid, 2);
    }

    /// The stored host must have one shape whatever the source spelled it:
    /// the URI parser stores the bare literal, so a server written the URI
    /// way (`[2001:db8::1]`) is stored bare too.
    #[test]
    fn a_bracketed_ipv6_server_is_stored_bare() {
        let result = parse_payload(
            r#"{"outbounds":[
                {"type":"trojan","tag":"v6","server":"[2001:db8::1]","server_port":443,
                 "password":"p"}]}"#,
        )
        .unwrap();
        assert_eq!(result.entries.len(), 1);
        assert_eq!(result.entries[0].host, "2001:db8::1");
    }

    /// An Xray endpoint may carry several credentials in `users`; each is a
    /// distinct proxy. Truncating to the first entry silently dropped the
    /// rest, with no log line and no invalid counter to show for it.
    #[test]
    fn every_user_of_an_xray_endpoint_becomes_an_entry() {
        let result = parse_payload(
            r#"{"outbounds":[
                {"tag":"p","protocol":"vless",
                 "settings":{"vnext":[{"address":"1.2.3.4","port":443,
                    "users":[{"id":"user-one","encryption":"none","flow":"xtls-rprx-vision"},
                             {"id":"user-two","encryption":"none"}]}]},
                 "streamSettings":{"network":"tcp","security":"none"}},
                {"tag":"m","protocol":"vmess",
                 "settings":{"vnext":[{"address":"5.6.7.8","port":443,
                    "users":[{"id":"vm-one","alterId":0,"security":"auto"},
                             {"id":"vm-two","alterId":0,"security":"auto"}]}]}},
                {"tag":"k","protocol":"socks",
                 "settings":{"servers":[{"address":"9.9.9.9","port":1080,
                    "users":[{"user":"u1","pass":"p1"},{"user":"u2","pass":"p2"}]}]}}]}"#,
        )
        .unwrap();
        assert_eq!(result.entries.len(), 6);
        assert_eq!(result.invalid, 0);
        assert_eq!(result.unsupported, 0);
        let credentials: Vec<&str> = result
            .entries
            .iter()
            .map(|e| e.credential.as_str())
            .collect();
        assert_eq!(
            credentials,
            ["user-one", "user-two", "vm-one", "vm-two", "u1:p1", "u2:p2"]
        );
        // Per-user fields stay on their own entry.
        assert_eq!(result.entries[0].param("flow"), Some("xtls-rprx-vision"));
        assert_eq!(result.entries[1].param("flow"), None);
        for entry in &result.entries {
            assert_output_round_trip(entry);
        }
    }

    /// One junk user element costs only itself: the credentials around it
    /// still parse, and an outbound in which *no* endpoint yields a
    /// credential is counted as invalid instead of vanishing quietly. The
    /// junk element is counted as invalid too, with one debug summary for
    /// the whole outbound.
    #[test]
    fn unusable_xray_users_are_skipped_not_fatal() {
        let result = parse_payload(
            r#"{"outbounds":[
                {"tag":"mixed","protocol":"vless",
                 "settings":{"vnext":[{"address":"1.2.3.4","port":443,
                    "users":["junk",{"flow":"xtls-rprx-vision"},{"id":"good","encryption":"none"}]}]}},
                {"tag":"none","protocol":"vless",
                 "settings":{"vnext":[{"address":"5.6.7.8","port":443,
                    "users":[{"flow":"xtls-rprx-vision"}]}]}}]}"#,
        )
        .unwrap();
        assert_eq!(result.entries.len(), 1);
        assert_eq!(result.entries[0].credential, "good");
        // The junk user and the outbound whose only endpoint yields nothing.
        assert_eq!(result.invalid, 2);
    }

    /// Non-object elements of the endpoint arrays (`vnext`, `servers`) and
    /// of `users` are junk: they cost their number in `invalid` and one
    /// line in the per-outbound summary, not a silent drop.
    #[test]
    fn non_object_elements_are_counted_invalid() {
        let result = parse_payload(
            r#"{"outbounds":[
                {"tag":"v","protocol":"vless",
                 "settings":{"vnext":["junk",{"address":"1.2.3.4","port":443,
                    "users":[{"id":"good","encryption":"none"}]}]}},
                {"tag":"t","protocol":"trojan",
                 "settings":{"servers":[{"address":"5.6.7.8","port":443,"password":"pw"},
                    "junk"]}}]}"#,
        )
        .unwrap();
        assert_eq!(result.entries.len(), 2);
        // One junk element per outbound.
        assert_eq!(result.invalid, 2);
    }

    /// An unusable `vnext` element costs only its own endpoint: the
    /// entries already built for the earlier ones are kept. The early
    /// return used to throw the accumulated entries away and count the
    /// whole outbound as one `invalid`.
    #[test]
    fn an_unusable_vnext_element_keeps_the_earlier_endpoints() {
        let result = parse_payload(
            r#"{"outbounds":[
                {"tag":"v","protocol":"vless",
                 "settings":{"vnext":[
                    {"address":"1.2.3.4","port":443,
                     "users":[{"id":"good","encryption":"none"}]},
                    {"address":"5.6.7.8","port":443,
                     "users":[{"flow":"xtls-rprx-vision"}]}]}},
                {"tag":"m","protocol":"vmess",
                 "settings":{"vnext":[
                    {"address":"9.9.9.9","port":443,
                     "users":[{"id":"vm-good","alterId":0,"security":"auto"}]},
                    {"address":"8.8.8.8","port":443,
                     "users":[{"alterId":0}]}]}}]}"#,
        )
        .unwrap();
        assert_eq!(result.entries.len(), 2);
        assert_eq!(result.invalid, 0);
        assert_eq!(result.entries[0].credential, "good");
        assert_eq!(result.entries[0].host, "1.2.3.4");
        assert_eq!(result.entries[1].credential, "vm-good");
        assert_eq!(result.entries[1].host, "9.9.9.9");
    }

    /// A `vnext` element that is not a usable endpoint costs only itself:
    /// the entries already built for the earlier ones are kept. The
    /// `?` on the endpoint used to propagate out of the loop and throw
    /// them away, the same data loss the unusable-user case had.
    #[test]
    fn a_malformed_vnext_element_keeps_the_earlier_endpoints() {
        let result = parse_payload(
            r#"{"outbounds":[
                {"tag":"v","protocol":"vless",
                 "settings":{"vnext":[
                    {"address":"1.2.3.4","port":443,
                     "users":[{"id":"good","encryption":"none"}]},
                    {"port":443,"users":[{"id":"no-address","encryption":"none"}]},
                    {"address":"7.7.7.7","users":[{"id":"no-port","encryption":"none"}]}]}},
                {"tag":"m","protocol":"vmess",
                 "settings":{"vnext":[
                    {"address":"9.9.9.9","port":443,
                     "users":[{"id":"vm-good","alterId":0,"security":"auto"}]},
                    {"users":[{"id":"vm-nothing","alterId":0}]}]}}]}"#,
        )
        .unwrap();
        assert_eq!(result.entries.len(), 2);
        assert_eq!(result.invalid, 0);
        assert_eq!(result.entries[0].credential, "good");
        assert_eq!(result.entries[1].credential, "vm-good");
    }

    /// An outbound where no endpoint yields a usable entry is still
    /// counted as invalid rather than vanishing quietly.
    #[test]
    fn a_fully_malformed_vnext_outbound_is_counted_invalid() {
        let result = parse_payload(
            r#"{"outbounds":[
                {"tag":"v","protocol":"vless",
                 "settings":{"vnext":[
                    {"port":443,"users":[{"id":"no-address","encryption":"none"}]}]}},
                {"tag":"m","protocol":"vmess",
                 "settings":{"vnext":[{"users":[{"id":"nothing"}]}]}}]}"#,
        )
        .unwrap();
        assert_eq!(result.entries.len(), 0);
        assert_eq!(result.invalid, 2);
    }

    /// The same rule for the `settings.servers` dialect, which the vnext
    /// fix had left untouched: a `servers[i]` element missing its
    /// endpoint or credential used to propagate its `Err` out of the loop
    /// and discard every entry built for the earlier elements.
    #[test]
    fn a_malformed_xray_server_element_keeps_the_earlier_endpoints() {
        let result = parse_payload(
            r#"{"outbounds":[
                {"tag":"t","protocol":"trojan",
                 "settings":{"servers":[
                    {"address":"1.2.3.4","port":443,"password":"good"},
                    {"address":"5.6.7.8","port":443}]}},
                {"tag":"s","protocol":"shadowsocks",
                 "settings":{"servers":[
                    {"address":"9.9.9.9","port":8388,"method":"aes-256-gcm","password":"pw"},
                    {"address":"8.8.8.8","port":8388,"password":"no-method"}]}},
                {"tag":"k","protocol":"socks",
                 "settings":{"servers":[
                    {"address":"7.7.7.7","port":1080,"users":[{"user":"u","pass":"p"}]},
                    {"port":1080}]}}]}"#,
        )
        .unwrap();
        assert_eq!(result.entries.len(), 3);
        assert_eq!(result.invalid, 0);
        assert_eq!(result.entries[0].credential, "good");
        assert_eq!(result.entries[1].credential, "aes-256-gcm:pw");
        assert_eq!(result.entries[2].credential, "u:p");
    }

    /// …and an outbound where no element is usable is still invalid.
    #[test]
    fn a_fully_malformed_xray_servers_outbound_is_counted_invalid() {
        let result = parse_payload(
            r#"{"outbounds":[
                {"tag":"t","protocol":"trojan",
                 "settings":{"servers":[
                    {"address":"1.2.3.4","port":443},
                    {"address":"5.6.7.8","port":443,"password":"good"},
                    {"port":443}]}},
                {"tag":"s","protocol":"shadowsocks",
                 "settings":{"servers":[{"password":"no-endpoint"}]}}]}"#,
        )
        .unwrap();
        assert_eq!(result.entries.len(), 1);
        assert_eq!(result.entries[0].credential, "good");
        assert_eq!(result.invalid, 1);
    }

    /// A sing-box path is decoded text; a raw `&` or `#` in it must not
    /// spawn a bogus parameter or swallow the name when the entry is
    /// serialized back to a URI.
    #[test]
    fn decoded_values_with_query_delimiters_survive_uri_serialization() {
        let entry = parse_one(
            r#"{"outbounds":[{"type":"vless","tag":"n","server":"h.example.com","server_port":443,
                "uuid":"u1",
                "transport":{"type":"ws","path":"/search?q=1&host=evil",
                             "headers":{"Host":"ws.example.com"}}}]}"#,
        );
        let line = serialize(&entry);
        assert!(line.contains("path=/search?q=1%26host=evil"), "{line}");
        let LineOutcome::Parsed(back) = parse_line(&line) else {
            panic!("serialized entry no longer parses: {line}");
        };
        assert_eq!(back.params.len(), 3, "{back:?}");
        assert_eq!(back.name, "n");
        assert_eq!(
            percent_decode(back.param("path").unwrap()),
            "/search?q=1&host=evil"
        );
    }

    #[test]
    fn payload_without_outbounds_is_an_error() {
        assert!(parse_payload(r#"{"dns":{}}"#).is_err());
        assert!(parse_payload("[]").is_err());
        assert!(parse_payload("42").is_err());
        assert!(parse_payload("not json").is_err());
        // The pinned contract for an empty outbound list: a valid payload
        // carrying no proxies, not an error.
        let empty = parse_payload(r#"{"outbounds":[]}"#).unwrap();
        assert_eq!(empty.entries.len(), 0);
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
    fn line_breaks_in_query_param_value_are_rejected() {
        // The host/credential reject already covers those two fields; this
        // asserts the per-param.value loop catches a `\n` smuggled into a
        // outbound's query-style param (sing-box params bypass parse_query
        // and are emitted verbatim by the serializer).
        let result = parse_payload(
            r#"{"outbounds":[{"type":"trojan","tag":"evil","server":"h.example.com","server_port":443,"password":"p","network":"ws\nvless://SMUGGLED@7.7.7.7:443#pwn"}]}"#,
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

    /// The per-field byte cap applies to a single parameter too: an
    /// overlong value — and separately an overlong key — is rejected like
    /// an oversized server, not stored.
    #[test]
    fn an_oversized_parameter_value_or_key_is_rejected() {
        let long_value = "v".repeat(crate::parsers::uri::MAX_PARAM_BYTES + 1);
        let result = parse_payload(&format!(
            r#"{{"outbounds":[{{"type":"trojan","tag":"t","server":"h","server_port":1,
                "password":"p","note":"{long_value}"}}]}}"#
        ))
        .unwrap();
        assert_eq!(result.entries.len(), 0);
        assert_eq!(result.invalid, 1);

        let long_key = "k".repeat(crate::parsers::uri::MAX_PARAM_BYTES + 1);
        let result = parse_payload(&format!(
            r#"{{"outbounds":[{{"type":"trojan","tag":"t","server":"h","server_port":1,
                "password":"p","{long_key}":"v"}}]}}"#
        ))
        .unwrap();
        assert_eq!(result.entries.len(), 0);
        assert_eq!(result.invalid, 1);
    }

    /// An explicit `reality.enabled: false` switches REALITY off, public key
    /// or not: the node is a plain TLS node then.
    #[test]
    fn an_explicitly_disabled_reality_is_off() {
        let entry = parse_one(
            r#"{"outbounds":[{"type":"vless","tag":"r","server":"h.example.com","server_port":443,
                "uuid":"u1",
                "tls":{"enabled":true,"server_name":"s.example.com",
                       "reality":{"enabled":false,"public_key":"PBK"}}}]}"#,
        );
        assert_eq!(entry.param("security"), Some("tls"));
        assert_eq!(entry.param("pbk"), None);
    }

    /// The mKCP and QUIC transports have no URI spelling the clients
    /// understand: their settings block must pass through as one unknown
    /// parameter instead of being dropped.
    #[test]
    fn the_kcp_and_quic_settings_pass_through() {
        let kcp = parse_one(
            r#"{"outbounds":[{"protocol":"vless","tag":"k",
                "settings":{"vnext":[{"address":"h.example.com","port":443,
                    "users":[{"id":"u1","encryption":"none"}]}]},
                "streamSettings":{"network":"kcp","security":"none",
                    "kcpSettings":{"seed":"s0ed","header":{"type":"srtp"}}}}]}"#,
        );
        assert_eq!(kcp.param("type"), Some("kcp"));
        let settings = kcp
            .param("kcpSettings")
            .expect("the kcp settings must survive");
        assert!(settings.contains("s0ed"), "{settings}");

        let quic = parse_one(
            r#"{"outbounds":[{"protocol":"vless","tag":"q",
                "settings":{"vnext":[{"address":"h.example.com","port":443,
                    "users":[{"id":"u1","encryption":"none"}]}]},
                "streamSettings":{"network":"quic","security":"none",
                    "quicSettings":{"security":"aes-128-gcm","key":"k"}}}]}"#,
        );
        assert_eq!(quic.param("type"), Some("quic"));
        let settings = quic
            .param("quicSettings")
            .expect("the quic settings must survive");
        assert!(settings.contains("aes-128-gcm"), "{settings}");
    }

    /// The keys of a transport settings block the mapping does not consume
    /// describe the transport and must not be dropped.
    #[test]
    fn unused_transport_settings_keys_survive() {
        let entry = parse_one(
            r#"{"outbounds":[{"protocol":"vless","tag":"w",
                "settings":{"vnext":[{"address":"h.example.com","port":443,
                    "users":[{"id":"u1","encryption":"none"}]}]},
                "streamSettings":{"network":"ws","security":"none",
                    "wsSettings":{"path":"/ws","maxEarlyData":2048,
                        "earlyDataHeaderName":"Sec-WebSocket-Protocol"}}}]}"#,
        );
        assert_eq!(entry.param("path"), Some("/ws"));
        assert_eq!(entry.param("maxEarlyData"), Some("2048"));
        assert_eq!(
            entry.param("earlyDataHeaderName"),
            Some("Sec-WebSocket-Protocol")
        );
    }

    /// Xray renamed the TCP transport to `raw`; it is the same transport and
    /// carries the same settings block.
    #[test]
    fn the_raw_transport_is_the_tcp_one() {
        let entry = parse_one(
            r#"{"outbounds":[{"protocol":"vless","tag":"r",
                "settings":{"vnext":[{"address":"h.example.com","port":443,
                    "users":[{"id":"u1","encryption":"none"}]}]},
                "streamSettings":{"network":"raw","security":"none",
                    "rawSettings":{"header":{"type":"http",
                        "request":{"path":["/raw"],"headers":{"Host":["raw.example.net"]}}}}}}]}"#,
        );
        assert_eq!(entry.param("type"), Some("tcp"));
        assert_eq!(entry.param("headertype"), Some("http"));
        assert_eq!(entry.param("path"), Some("/raw"));
        assert_eq!(entry.param("host"), Some("raw.example.net"));
    }

    /// An endpoint with more users than the cap yields only the first ones;
    /// the rest are counted as invalid.
    #[test]
    fn the_users_of_an_endpoint_are_capped() {
        let users: Vec<String> = (0..40)
            .map(|i| format!(r#"{{"id":"u{i}","encryption":"none"}}"#))
            .collect();
        let payload = format!(
            r#"{{"outbounds":[{{"protocol":"vless","tag":"m",
                "settings":{{"vnext":[{{"address":"h.example.com","port":443,
                    "users":[{}]}}]}}}}]}}"#,
            users.join(",")
        );
        let result = parse_payload(&payload).unwrap();
        assert_eq!(result.entries.len(), MAX_USERS_PER_ENDPOINT);
        assert_eq!(result.invalid, 40 - MAX_USERS_PER_ENDPOINT);
    }

    // Fixture tests against the real sing-box/Xray samples `test-sing.txt`
    // (single Xray config) and `test-sing2.txt` (v2rayN share array). The
    // fixtures are gitignored (real credentials) and never committed, so
    // these tests are ignored by default: the committed synthetic fixtures
    // below carry the mandatory coverage.

    fn fixture_payload(name: &str) -> Option<String> {
        std::fs::read_to_string(
            std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(format!("../../{name}")),
        )
        .ok()
    }

    /// The committed synthetic fixture: generated outbounds without real
    /// credentials, committed so the fixture tests always run.
    fn synthetic_fixture(name: &str) -> String {
        let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures")
            .join(name);
        std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("fixture {} unreadable: {e}", path.display()))
    }

    /// The transports and TLS modes the synthetic fixture must cover, so a
    /// shrunken fixture cannot silently reduce the coverage.
    fn assert_variety(entries: &[ProxyEntry]) {
        let mut transports: Vec<&str> = entries.iter().filter_map(|e| e.param("type")).collect();
        transports.sort_unstable();
        transports.dedup();
        assert!(transports.contains(&"ws"), "{transports:?}");
        assert!(transports.contains(&"grpc"), "{transports:?}");
        assert!(transports.contains(&"http"), "{transports:?}");
        let reality = entries
            .iter()
            .filter(|e| e.param("security") == Some("reality"))
            .count();
        assert!(reality > 0, "no REALITY node in the fixture");
        let tls = entries
            .iter()
            .filter(|e| e.param("security") == Some("tls"))
            .count();
        assert!(tls > 0, "no TLS node in the fixture");
    }

    #[test]
    fn synthetic_fixture_single_config_parses_and_round_trips() {
        let payload = synthetic_fixture("singbox-config.json");
        let result = parse_payload(&payload).unwrap();
        // The whole-pipeline path must auto-detect the format too.
        let via_auto =
            crate::parsers::parse_subscription(&payload, crate::models::Encoding::Auto, None)
                .unwrap();
        assert_eq!(via_auto.format, crate::models::InputFormat::SingBoxJson);
        assert_eq!(via_auto.entries.len(), result.entries.len());
        assert_eq!(via_auto.skipped, 0);
        assert_eq!(result.invalid, 0, "no outbound should be malformed");
        assert_eq!(result.unsupported, 0);
        assert_eq!(result.entries.len(), 32);
        assert!(result.entries.iter().all(|e| e.scheme == Scheme::Vless));
        assert_variety(&result.entries);
        for entry in &result.entries {
            assert_output_round_trip(entry);
        }
    }

    #[test]
    fn synthetic_fixture_share_array_parses_and_round_trips() {
        let payload = synthetic_fixture("singbox-share.json");
        let result = parse_payload(&payload).unwrap();
        let via_auto =
            crate::parsers::parse_subscription(&payload, crate::models::Encoding::Auto, None)
                .unwrap();
        assert_eq!(via_auto.format, crate::models::InputFormat::SingBoxJson);
        assert_eq!(via_auto.entries.len(), result.entries.len());
        assert_eq!(via_auto.skipped, 0);
        assert_eq!(result.invalid, 0, "no outbound should be malformed");
        assert_eq!(result.unsupported, 0);
        assert_eq!(result.entries.len(), 72);
        assert_variety(&result.entries);
        for entry in &result.entries {
            assert_output_round_trip(entry);
        }
    }

    #[test]
    #[ignore = "requires the local gitignored fixture test-sing.txt"]
    fn fixture_single_config_parses_and_round_trips() {
        let payload = fixture_payload("test-sing.txt")
            .expect("the local gitignored fixture test-sing.txt is required for this test");
        let result = parse_payload(&payload).unwrap();
        // The whole-pipeline path must auto-detect the format too.
        let via_auto =
            crate::parsers::parse_subscription(&payload, crate::models::Encoding::Auto, None)
                .unwrap();
        assert_eq!(via_auto.format, crate::models::InputFormat::SingBoxJson);
        assert_eq!(via_auto.entries.len(), result.entries.len());
        assert_eq!(via_auto.skipped, 0);
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
    #[ignore = "requires the local gitignored fixture test-sing2.txt"]
    fn fixture_share_array_parses_and_round_trips() {
        let payload = fixture_payload("test-sing2.txt")
            .expect("the local gitignored fixture test-sing2.txt is required for this test");
        let result = parse_payload(&payload).unwrap();
        let via_auto =
            crate::parsers::parse_subscription(&payload, crate::models::Encoding::Auto, None)
                .unwrap();
        assert_eq!(via_auto.format, crate::models::InputFormat::SingBoxJson);
        assert_eq!(via_auto.entries.len(), result.entries.len());
        assert_eq!(via_auto.skipped, 0);
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
