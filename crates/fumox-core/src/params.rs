//! Parameter semantics shared by the fingerprint, the output encoders and
//! the pipeline filters.
//!
//! One node is spelled in several ways: the URI families use `sni`, `fp`
//! and `pbk`, Clash YAML uses `servername`, `client-fingerprint` and a
//! `reality-opts` block, sing-box JSON its own names again. Every consumer
//! that reads a parameter has to agree on which spelling wins and what the
//! value means; where they did not, the deduplication key and the emitted
//! document described different nodes (review WP-21).
//!
//! [`canonical`] is the one reduction of an entry to a single form: the
//! structured blocks expanded into the scalars they carry, the spellings
//! folded onto one canonical key, the cosmetic names dropped and the
//! values decoded. The fingerprint hashes that form and the encoders read
//! the same spellings it folds, so the key describes the node the way the
//! document is built.

use std::collections::{BTreeMap, HashSet};
use std::sync::LazyLock;

use serde_norway::Mapping;

use crate::models::{ProxyEntry, Scheme, is_falsy_toggle, is_truthy_toggle};

/// Parameter value by case-insensitive key, empty values dropped.
///
/// URI feeds keep values percent-encoded, so the result is leniently
/// decoded (valid `%XX` escapes resolve, garbage passes through); entries
/// from vmess JSON / Clash YAML carry plain values that decode unchanged.
pub fn value(entry: &ProxyEntry, key: &str) -> Option<String> {
    let value = entry.param_ignore_case(key)?.trim();
    (!value.is_empty()).then(|| crate::parsers::uri::percent_decode(value))
}

/// Whether the parameter is present with a truthy value (`1`/`true`/`yes`/
/// `on`, case-insensitive), how Clash YAML booleans land in params. The
/// vocabulary is the shared [`crate::models::is_truthy_toggle`], so the
/// writers agree with the fingerprint and the forbid-insecure filter.
pub fn truthy(entry: &ProxyEntry, key: &str) -> bool {
    entry.param_ignore_case(key).is_some_and(is_truthy_toggle)
}

/// Parameter as a list: YAML sequences (Clash-input `alpn: [h2, http/1.1]`)
/// keep their items, plain values split on commas (URI `alpn=h2,http/1.1`).
pub fn list(entry: &ProxyEntry, key: &str) -> Option<Vec<String>> {
    let raw = entry.param_ignore_case(key)?.to_string();
    if raw.trim().is_empty() {
        return None;
    }
    // Stored parameter values are feed-controlled and are re-parsed as YAML
    // at serve time; refuse alias references first (quadratic memory
    // amplification, see `parsers::reject_yaml_aliases`). A refused value
    // falls through to the plain comma-split path, nothing else regresses.
    //
    // Only a value that starts with `[` can be a YAML sequence, so only
    // that one is handed to the YAML parser: a plain scalar is split on
    // commas instead of being parsed as YAML first.
    if raw.trim_start().starts_with('[')
        && crate::parsers::reject_yaml_aliases(&raw).is_ok()
        && let Ok(serde_norway::Value::Sequence(seq)) = serde_norway::from_str(&raw)
    {
        return strings_of_sequence(&seq);
    }
    strings_of_scalar(&raw)
}

/// The strings of a YAML sequence: string items only, trimmed, empties
/// dropped. A non-string item is not scalarized into text — a number or a
/// nested mapping in an `alpn` list is not a protocol name a client could
/// speak — so it is dropped rather than stringified.
fn strings_of_sequence(seq: &[serde_norway::Value]) -> Option<Vec<String>> {
    let list: Vec<String> = seq
        .iter()
        .filter_map(serde_norway::Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect();
    (!list.is_empty()).then_some(list)
}

/// A plain value as a list: percent-decoded, split on commas.
fn strings_of_scalar(raw: &str) -> Option<Vec<String>> {
    let list: Vec<String> = crate::parsers::uri::percent_decode(raw)
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect();
    (!list.is_empty()).then_some(list)
}

/// Parameter value parsed back into a YAML mapping. Clash-input entries keep
/// structured fields (`ws-opts`, `reality-opts`, `grpc-opts`, …) as YAML
/// text; this reconstructs them for the output encoders.
pub fn map(entry: &ProxyEntry, key: &str) -> Option<Mapping> {
    let raw = entry.param_ignore_case(key)?;
    // Same alias guard as `list`: the value is feed-controlled and
    // re-parsed as YAML; on refusal the parameter keeps no mapping.
    if crate::parsers::reject_yaml_aliases(raw.trim()).is_err() {
        return None;
    }
    match serde_norway::from_str(raw.trim()) {
        Ok(serde_norway::Value::Mapping(map)) if !map.is_empty() => Some(map),
        _ => None,
    }
}

/// String lookup inside an optional parsed YAML mapping, trying both the
/// given key and its capitalized spelling (`host` / `Host`).
pub fn map_str(map: &Option<Mapping>, key: &str) -> Option<String> {
    map.as_ref().and_then(|m| map_value(m, key))
}

/// String lookup inside a parsed YAML mapping, trying both the given key
/// and its capitalized spelling (`host` / `Host`).
pub fn map_value(map: &Mapping, key: &str) -> Option<String> {
    for candidate in [key, &capitalize(key)] {
        if let Some(value) = map.get(candidate).and_then(|v| v.as_str())
            && !value.trim().is_empty()
        {
            return Some(value.trim().to_string());
        }
    }
    None
}

/// List of strings inside a parsed YAML mapping, sharing the [`list`]
/// semantics: a sequence keeps its string items, a plain scalar splits on
/// commas (`host: [a, b]` and `host: a,b` read the same).
pub fn map_list(map: &Option<Mapping>, key: &str) -> Option<Vec<String>> {
    match map.as_ref()?.get(key)? {
        serde_norway::Value::String(raw) => strings_of_scalar(raw),
        serde_norway::Value::Sequence(seq) => strings_of_sequence(seq),
        _ => None,
    }
}

/// The first string of a mapping field that is either a scalar or a
/// sequence of strings.
///
/// The structured blocks spell a path as a scalar (`ws-opts.path`) or as a
/// list (`http-opts.path`), and the writers have to read both.
pub fn map_first(map: &Option<Mapping>, key: &str) -> Option<String> {
    let map = map.as_ref()?;
    map_value(map, key).or_else(|| {
        map.get(key)
            .and_then(serde_norway::Value::as_sequence)
            .and_then(|seq| seq.iter().find_map(serde_norway::Value::as_str))
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string)
    })
}

/// The `Host` header inside a parsed `headers` block, with its value as a
/// list (the mihomo spelling allows several hosts).
pub fn map_header(map: &Option<Mapping>) -> Option<Vec<String>> {
    headers_of(map.as_ref()?)
}

fn headers_of(map: &Mapping) -> Option<Vec<String>> {
    let headers = map
        .get("headers")
        .and_then(serde_norway::Value::as_mapping)?;
    for key in ["Host", "host"] {
        if let Some(value) = headers.get(key) {
            let list: Vec<String> = match value {
                serde_norway::Value::String(s) => vec![s.trim().to_string()],
                serde_norway::Value::Sequence(seq) => seq
                    .iter()
                    .filter_map(serde_norway::Value::as_str)
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .map(str::to_string)
                    .collect(),
                _ => Vec::new(),
            };
            if !list.is_empty() {
                return Some(list);
            }
        }
    }
    None
}

fn capitalize(key: &str) -> String {
    let mut out = key.to_string();
    if let Some(first) = out.get_mut(..1) {
        first.make_ascii_uppercase();
    }
    out
}

/// Whether the entry carries a truthy insecure toggle under any of the
/// spelling aliases ([`crate::models::INSECURE_ALIASES`]).
pub fn is_insecure(entry: &ProxyEntry) -> bool {
    entry.params.iter().any(crate::models::is_insecure_param)
}

/// Whether the URI `security` parameter equals `want` (case-insensitive).
pub fn security_is(entry: &ProxyEntry, want: &str) -> bool {
    value(entry, "security").is_some_and(|v| v.eq_ignore_ascii_case(want))
}

/// The SNI under either spelling: the URI family's `sni` and the mihomo
/// `servername` that Clash YAML carries. Reading only the first dropped
/// the SNI of every Clash-sourced proxy.
pub fn sni(entry: &ProxyEntry) -> Option<String> {
    value(entry, "sni").or_else(|| value(entry, "servername"))
}

/// The uTLS client hello fingerprint under either spelling: the URI
/// family's `fp` and the mihomo `client-fingerprint`.
pub fn fingerprint_hint(entry: &ProxyEntry) -> Option<String> {
    value(entry, "fp").or_else(|| value(entry, "client-fingerprint"))
}

/// Whether the entry's transport is wrapped in TLS.
///
/// One decision for every consumer: the Clash writer, the sing-box writer
/// and the URI serializer all ask this question, and they used to answer
/// it differently — a node carrying only an SNI got a TLS block from the
/// sing-box writer and none from the Clash writer, and the two documents
/// disagreed about the very same proxy.
///
/// The rules, in order:
///
/// 1. an explicit `tls` toggle is authoritative wherever it appears: the
///    mihomo boolean (`tls: false`), the vmess string (`tls=tls`) and the
///    URI spelling (`tls=1`) all mean "this proxy is/is not wrapped";
/// 2. `security=none` states that there is no TLS layer and outranks the
///    heuristics below — an SNI or an insecure toggle left in the link
///    must not turn a plaintext proxy into a TLS one;
/// 3. `security=tls`, `security=reality` and `security=xtls` state a TLS
///    layer;
/// 4. an unknown, non-empty `security` on a vless/vmess node is a broken
///    spelling of a value this build does not know: the node is treated as
///    TLS-wrapped, because probing it as plaintext passes a broken node
///    (review WP-09, M-097);
/// 5. otherwise the REALITY keys state one: a node that carries a public
///    key or a short id is a REALITY node, whether it says so or not;
/// 6. otherwise an SNI or a certificate-verification toggle implies one:
///    neither exists for a plaintext connection.
///
/// Trojan is the exception to the whole list: the protocol carries the
/// password inside the TLS session and has no plain-text form, so a trojan
/// node is TLS-wrapped whatever its parameters say.
pub fn wants_tls(entry: &ProxyEntry, blocks: &Blocks) -> bool {
    if entry.scheme == Scheme::Trojan {
        return true;
    }
    if let Some(tls) = value(entry, "tls") {
        let tls = tls.trim().to_ascii_lowercase();
        if tls == "tls" || is_truthy_toggle(&tls) {
            return true;
        }
        if is_falsy_toggle(&tls) {
            return false;
        }
    }
    if security_is(entry, "none") {
        return false;
    }
    if security_is(entry, "tls") || security_is(entry, "reality") || security_is(entry, "xtls") {
        return true;
    }
    if matches!(entry.scheme, Scheme::Vless | Scheme::Vmess)
        && value(entry, "security").is_some_and(|value| !value.is_empty())
    {
        return true;
    }
    if is_reality(entry, blocks) {
        return true;
    }
    sni(entry).is_some() || is_insecure(entry)
}

/// Whether the entry is a REALITY node: it says so, or it carries the
/// REALITY keys.
pub fn is_reality(entry: &ProxyEntry, blocks: &Blocks) -> bool {
    security_is(entry, "reality") || !reality(entry, blocks).is_empty()
}

/// The REALITY keys of an entry: the URI `pbk`/`sid` parameters or the
/// values of a Clash-input `reality-opts` block.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Reality {
    pub public_key: Option<String>,
    pub short_id: Option<String>,
}

impl Reality {
    /// Whether neither key is present.
    pub fn is_empty(&self) -> bool {
        self.public_key.is_none() && self.short_id.is_none()
    }
}

/// The REALITY keys of an entry, read from the URI parameters or from the
/// structured block. The block is parsed once for the whole entry.
pub fn reality(entry: &ProxyEntry, blocks: &Blocks) -> Reality {
    Reality {
        public_key: value(entry, "pbk")
            .or_else(|| map_value(blocks.reality.as_ref()?, "public-key")),
        short_id: value(entry, "sid").or_else(|| map_value(blocks.reality.as_ref()?, "short-id")),
    }
}

/// The structured blocks of one entry, parsed once.
///
/// The blocks are YAML text inside a parameter value, and every consumer
/// that read one re-parsed it: the same `ws-opts` was parsed once per
/// encoder and once per fingerprint, on feed-controlled text (review
/// WP-21, L-041).
#[derive(Debug, Default, Clone)]
pub struct Blocks {
    pub reality: Option<Mapping>,
    pub ws: Option<Mapping>,
    pub ws_headers: Option<Mapping>,
    pub grpc: Option<Mapping>,
    pub h2: Option<Mapping>,
    pub http: Option<Mapping>,
    pub obfs: Option<Mapping>,
}

impl Blocks {
    /// Parse the structured blocks of an entry.
    pub fn of(entry: &ProxyEntry) -> Self {
        Self {
            reality: map(entry, "reality-opts"),
            ws: map(entry, "ws-opts"),
            ws_headers: map(entry, "ws-headers"),
            grpc: map(entry, "grpc-opts"),
            h2: map(entry, "h2-opts"),
            http: map(entry, "http-opts"),
            obfs: map(entry, "obfs-opts"),
        }
    }

    /// The parsed mapping of a block, by its parameter name.
    fn get(&self, name: &str) -> Option<&Mapping> {
        match name {
            "reality-opts" => self.reality.as_ref(),
            "ws-opts" => self.ws.as_ref(),
            "ws-headers" => self.ws_headers.as_ref(),
            "grpc-opts" => self.grpc.as_ref(),
            "h2-opts" => self.h2.as_ref(),
            "http-opts" => self.http.as_ref(),
            "obfs-opts" => self.obfs.as_ref(),
            _ => None,
        }
    }
}

/// The structured blocks and the canonical key their fields map onto.
///
/// A field with a flat spelling is folded onto it, so the same node
/// published as Clash YAML and as a URI shares one key. A field without
/// one keeps its block-qualified name (`ws-opts.max-early-data`), so two
/// nodes that differ in it do not collapse onto one another.
const BLOCK_FIELDS: &[(&str, &[(&str, &str)])] = &[
    (
        "reality-opts",
        &[("public-key", "pbk"), ("short-id", "sid")],
    ),
    (
        "ws-opts",
        &[
            ("path", "path"),
            ("v2ray-http-upgrade", "v2ray-http-upgrade"),
        ],
    ),
    ("ws-headers", &[("host", "host")]),
    ("grpc-opts", &[("grpc-service-name", "servicename")]),
    ("h2-opts", &[("host", "host"), ("path", "path")]),
    ("http-opts", &[("path", "path")]),
    ("obfs-opts", &[("mode", "obfs"), ("host", "obfs-host")]),
];

/// Parameters that carry no connection semantics: display names,
/// advertising tags, bandwidth caps and timestamps.
///
/// The rule is a deny-list on purpose. An allow-list has to name every
/// transport parameter a feed may use, and every one it missed merged two
/// different nodes onto one deduplication key (review WP-21, M-052/M-053):
/// two nodes differing only in their `grpc-mode` shared one row and the
/// upsert silently overwrote one with the other.
static COSMETIC_PARAMS: LazyLock<HashSet<&'static str>> = LazyLock::new(|| {
    HashSet::from([
        // display name and description
        "name",
        "remark",
        "remarks",
        "remark2",
        "des",
        "desc",
        "descr",
        "description",
        "title",
        "ps",
        // grouping and advertising tags
        "group",
        "group-name",
        "provider",
        "proxy-provider",
        "tag",
        "tags",
        "label",
        "labels",
        "category",
        "channel",
        "telegram",
        "discord",
        // bandwidth and traffic accounting
        "up",
        "down",
        "upmbps",
        "downmbps",
        "uplink",
        "downlink",
        "bandwidth",
        "traffic",
        "total",
        "used",
        "upload",
        "download",
        "used-traffic",
        "total-traffic",
        // timestamps and expiry
        "t",
        "time",
        "timestamp",
        "expire",
        "expiry",
        "expires",
        "expire-time",
        "lastupdated",
        "update",
        "refresh",
        "ttl",
        "ttl-secs",
    ])
});

/// Whether a canonical key names a cosmetic parameter: one hash lookup on
/// the key, no allocation.
fn is_cosmetic(key: &str) -> bool {
    COSMETIC_PARAMS.contains(key)
}

/// Map a parameter key onto the spelling the canonical form is keyed by.
///
/// Clash carries its own field names for fields every URI format spells the
/// same way. Left alone, the same node advertised as Clash YAML and as a URI
/// would get two different fingerprints and land in two rows, so the Clash
/// spelling is rewritten to the URI one before the filter runs.
///
/// The transport is spelled per scheme: the vmess JSON and the sing-box native
/// form both call it `net`, while vless, trojan and the rest call it `type`.
/// Folding it onto one spelling for every scheme would split the vmess forms
/// from each other, so the target key depends on the scheme.
pub fn canonical_key(scheme: Scheme, key: &str) -> &str {
    match key {
        "servername" => "sni",
        "network" if scheme == Scheme::Vmess => "net",
        "network" => "type",
        "ws-path" => "path",
        "client-fingerprint" => "fp",
        "grpc-service-name" => "servicename",
        // Clash's `fingerprint` is the certificate pin (`pinSHA256` in the
        // URI), not the uTLS client hello: that one is `client-fingerprint`.
        "fingerprint" => "pinsha256",
        // vmess JSON spells the cipher `scy` and the alter id `aid`; Clash
        // YAML calls them `cipher` and `alterId`. Without the folding the
        // same node advertised as Clash YAML and as a vmess:// link lands
        // in two rows, while two nodes differing only in the cipher
        // collapse onto one. (Same aliasing as the URI translation in
        // `parsers::translate_uri_param`.)
        "cipher" if scheme == Scheme::Vmess => "scy",
        "alterid" if scheme == Scheme::Vmess => "aid",
        other => other,
    }
}

/// The canonical key of the transport parameter of a scheme: the vmess
/// JSON and the sing-box native form spell it `net`, the rest `type`.
fn transport_key(scheme: Scheme) -> &'static str {
    if scheme == Scheme::Vmess {
        "net"
    } else {
        "type"
    }
}

/// The spellings that fold onto one canonical key, in the order the output
/// encoders read them.
///
/// The first spelling present wins, so the canonical form describes the
/// node the way the emitted document is built: a `sni` beats a
/// `servername`, a `pbk` beats the `public-key` of a `reality-opts`
/// block.
fn source_rank(scheme: Scheme, key: &str, source: &str) -> u32 {
    let order: &[&str] = match key {
        "sni" => &["sni", "servername"],
        "fp" => &["fp", "client-fingerprint"],
        "path" => &["path", "ws-opts.path"],
        "servicename" => &["servicename", "grpc-opts.grpc-service-name"],
        "pinsha256" => &["pinsha256", "fingerprint"],
        "scy" => &["scy", "cipher"],
        "aid" => &["aid", "alterid"],
        "pbk" => &["pbk", "reality-opts.public-key"],
        "sid" => &["sid", "reality-opts.short-id"],
        "host" => &[
            "host",
            "ws-headers.host",
            "ws-opts.headers.host",
            "http-opts.headers.host",
            "h2-opts.host",
        ],
        "obfs" => &["obfs", "obfs-opts.mode"],
        "obfs-host" => &["obfs-host", "obfs-opts.host"],
        "net" => &["net", "network"],
        "type" => &["type", "network"],
        _ => &[],
    };
    let _ = scheme;
    match order.iter().position(|candidate| *candidate == source) {
        Some(index) => index as u32,
        // A key without a table of its own is spelled by itself.
        None if order.is_empty() => u32::from(source != key),
        None => u32::MAX,
    }
}

/// The canonical connection parameters of an entry: one value per
/// canonical key, decoded, with the structured blocks expanded into the
/// scalars they carry and the cosmetic names dropped.
///
/// The order of the result is the sorted key order, so it does not depend
/// on the order the parameters were parsed in.
pub fn canonical(entry: &ProxyEntry) -> Vec<(String, String)> {
    let blocks = Blocks::of(entry);
    let mut candidates: Vec<(String, String, String)> = Vec::new();

    let transport = transport_key(entry.scheme);
    for param in &entry.params {
        let source = param.key.to_ascii_lowercase();
        // A structured block that parsed is represented by its expansion;
        // the raw YAML text would only add the block's own spelling to the
        // key. A block that did not parse stays in the pre-image as it
        // is, so two nodes differing in it do not collapse.
        if BLOCK_FIELDS.iter().any(|(block, _)| *block == source) && blocks.get(&source).is_some() {
            continue;
        }
        let key = canonical_key(entry.scheme, &source);
        // The transport parameter is replaced by its canonical name below:
        // the network it names depends on the other transport parameters.
        if key == transport {
            continue;
        }
        if let Some((name, value)) = scalar_value(entry.scheme, key, &param.value) {
            candidates.push((name, source, value));
        }
    }

    // The structured blocks carry the same settings as the flat
    // parameters; expanding them lets a node published as Clash YAML and
    // the same node published as a URI share one key.
    expand_blocks(&blocks, &mut candidates);

    // The transport: the network name every format agrees on.
    if let Some(network) = raw_network(entry, entry.scheme)
        && let Some((canonical_network, extra)) = canonical_transport(entry, &network)
    {
        candidates.push((
            transport.to_string(),
            transport.to_string(),
            canonical_network,
        ));
        if let Some((key, value)) = extra {
            candidates.push((key.clone(), key, value));
        }
    }

    // One value per canonical key: the spelling the encoders read first
    // wins, and a spelling repeated with different values keeps the first
    // occurrence, the way the stored parameters keep it.
    let mut chosen: BTreeMap<String, (u32, String, usize, String)> = BTreeMap::new();
    for (order, (key, source, value)) in candidates.iter().enumerate() {
        let rank = source_rank(entry.scheme, key, source);
        let replace = match chosen.get(key) {
            Some((best_rank, best_source, best_order, _)) => {
                (rank, source.as_str(), order) < (*best_rank, best_source.as_str(), *best_order)
            }
            None => true,
        };
        if replace {
            chosen.insert(key.clone(), (rank, source.clone(), order, value.clone()));
        }
    }

    chosen
        .into_iter()
        .map(|(key, (_, _, _, value))| (key, value))
        .collect()
}

/// The canonical value of a scalar parameter, or `None` when the parameter
/// is cosmetic or carries no value.
///
/// The certificate-verification toggles collapse onto one flag: a falsy
/// toggle is the same as no toggle at all, and the truthy ones spell the
/// same thing. The same holds for the `tls` switch.
fn scalar_value(scheme: Scheme, key: &str, raw: &str) -> Option<(String, String)> {
    let lower = key.to_ascii_lowercase();
    if crate::models::INSECURE_ALIASES.contains(&lower.as_str()) {
        return is_truthy_toggle(raw).then(|| ("insecure".to_string(), "1".to_string()));
    }
    if lower == "tls" {
        let value = raw.trim().to_ascii_lowercase();
        if value == "tls" || is_truthy_toggle(&value) {
            return Some(("tls".to_string(), "1".to_string()));
        }
        if is_falsy_toggle(&value) {
            return None;
        }
    }
    // The vmess dialect marker: the format version, not a connection
    // setting. It is the same in every feed, and it would split the
    // vmess JSON form of a node from its Clash form.
    if scheme == Scheme::Vmess && lower == "v" {
        return None;
    }
    if is_cosmetic(&lower) {
        return None;
    }
    let value = crate::parsers::uri::percent_decode(raw.trim());
    let value = value.trim();
    if value.is_empty() {
        return None;
    }
    Some((lower, value.to_string()))
}

/// The transport network of an entry as it was written: the scheme's
/// native key first, then the mihomo spelling `network` used by Clash
/// input. Lower-cased.
fn raw_network(entry: &ProxyEntry, scheme: Scheme) -> Option<String> {
    let native = transport_key(scheme);
    value(entry, native)
        .or_else(|| value(entry, "network"))
        .map(|v| v.to_ascii_lowercase())
}

/// The canonical transport of an entry: the network name the Clash writer
/// emits, plus the httpupgrade flag it carries.
///
/// The mapping follows the Clash writer, because it is the one that tells
/// the two Xray transports apart: `type=http` is HTTP/2 while
/// `type=tcp&headerType=http` is the plain-HTTP header obfuscation, and
/// both are spelled `http` in the URI family.
fn canonical_transport(
    entry: &ProxyEntry,
    network: &str,
) -> Option<(String, Option<(String, String)>)> {
    let header_http = value(entry, "headertype").is_some_and(|v| v.eq_ignore_ascii_case("http"))
        || (entry.scheme == Scheme::Vmess
            && value(entry, "type").is_some_and(|v| v.eq_ignore_ascii_case("http")));
    let canonical = match network {
        // `httpupgrade` is a WebSocket with the HTTP upgrade header: the
        // Clash writer emits it as `network: ws` plus the flag, so the
        // canonical form is the same pair.
        "httpupgrade" => {
            return Some((
                "ws".to_string(),
                Some(("v2ray-http-upgrade".to_string(), "true".to_string())),
            ));
        }
        "tcp" if header_http => "http",
        "http" if entry.scheme == Scheme::Vmess || header_http => "http",
        "http" => "h2",
        other => other,
    };
    Some((canonical.to_string(), None))
}

/// Expand the structured blocks into the scalars they carry.
fn expand_blocks(blocks: &Blocks, candidates: &mut Vec<(String, String, String)>) {
    for (block, fields) in BLOCK_FIELDS {
        let Some(mapping) = blocks.get(block) else {
            continue;
        };
        for (key, value) in mapping {
            let Some(key) = key.as_str() else {
                continue;
            };
            let source = format!("{block}.{key}");
            let canonical = fields
                .iter()
                .find(|(field, _)| *field == key)
                .map(|(_, canonical)| (*canonical).to_string());
            expand_field(canonical.as_deref(), &source, value, candidates);
        }
    }
}

/// Expand one field of a structured block into canonical candidates.
///
/// `canonical` is the flat key the field maps onto, `source` names where
/// the value came from (`ws-opts.headers.host`) and `value` is the raw
/// YAML value.
fn expand_field(
    canonical: Option<&str>,
    source: &str,
    value: &serde_norway::Value,
    candidates: &mut Vec<(String, String, String)>,
) {
    match value {
        serde_norway::Value::Null => {}
        serde_norway::Value::Mapping(map) => {
            for (key, child) in map {
                let Some(key) = key.as_str() else {
                    continue;
                };
                let child_source = format!("{source}.{key}");
                // The `Host` header of a transport block is the canonical
                // `host`; every other header keeps its qualified name.
                let child_canonical =
                    if source.ends_with(".headers") && key.eq_ignore_ascii_case("host") {
                        Some("host")
                    } else {
                        None
                    };
                expand_field(child_canonical, &child_source, child, candidates);
            }
        }
        serde_norway::Value::Sequence(seq) => {
            let joined = seq
                .iter()
                .map(scalar_text)
                .filter(|text| !text.is_empty())
                .collect::<Vec<_>>()
                .join(",");
            if joined.is_empty() {
                return;
            }
            let key = canonical.unwrap_or(source);
            candidates.push((key.to_string(), source.to_string(), joined));
        }
        other => {
            let text = scalar_text(other);
            if text.is_empty() {
                return;
            }
            let key = canonical.unwrap_or(source);
            candidates.push((key.to_string(), source.to_string(), text));
        }
    }
}

/// The text of a YAML scalar.
fn scalar_text(value: &serde_norway::Value) -> String {
    match value {
        serde_norway::Value::String(s) => s.trim().to_string(),
        serde_norway::Value::Number(n) => n.to_string(),
        serde_norway::Value::Bool(b) => b.to_string(),
        _ => String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::Param;

    fn entry(scheme: Scheme, params: &[(&str, &str)]) -> ProxyEntry {
        ProxyEntry {
            scheme,
            name: "proxy".into(),
            host: "example.com".into(),
            port: 443,
            credential: "secret".into(),
            params: params
                .iter()
                .map(|(k, v)| Param {
                    key: (*k).into(),
                    value: (*v).into(),
                    known: true,
                    bare: false,
                })
                .collect(),
            raw_path: String::new(),
            raw_line: String::new(),
            canonical: None,
        }
    }

    fn canonical_map(entry: &ProxyEntry) -> BTreeMap<String, String> {
        canonical(entry).into_iter().collect()
    }

    #[test]
    fn a_value_is_read_case_insensitively_and_decoded() {
        let e = entry(
            Scheme::Vless,
            &[("SNI", "a.example.com"), ("path", "%2Fws")],
        );
        assert_eq!(value(&e, "sni").as_deref(), Some("a.example.com"));
        assert_eq!(value(&e, "path").as_deref(), Some("/ws"));
        assert_eq!(value(&e, "missing"), None);
    }

    #[test]
    fn an_explicit_tls_toggle_outranks_the_heuristics() {
        // The mihomo boolean.
        let off = entry(Scheme::Vless, &[("tls", "false"), ("sni", "s.example.com")]);
        assert!(!wants_tls(&off, &Blocks::of(&off)));
        // The vmess string spelling.
        let on = entry(Scheme::Vmess, &[("tls", "tls")]);
        assert!(wants_tls(&on, &Blocks::of(&on)));
        // `security=none` states that there is no TLS layer.
        let none = entry(
            Scheme::Vless,
            &[
                ("security", "none"),
                ("sni", "s.example.com"),
                ("allowInsecure", "1"),
            ],
        );
        assert!(!wants_tls(&none, &Blocks::of(&none)));
        // An SNI on its own implies TLS.
        let sni = entry(Scheme::Vless, &[("sni", "s.example.com")]);
        assert!(wants_tls(&sni, &Blocks::of(&sni)));
    }

    #[test]
    fn a_reality_node_is_tls_wrapped_even_without_a_security_parameter() {
        let flat = entry(Scheme::Vless, &[("pbk", "key"), ("sid", "short")]);
        assert!(wants_tls(&flat, &Blocks::of(&flat)));
        assert!(is_reality(&flat, &Blocks::of(&flat)));
        let blocked = entry(
            Scheme::Vless,
            &[("reality-opts", "public-key: key\nshort-id: short")],
        );
        assert!(wants_tls(&blocked, &Blocks::of(&blocked)));
        assert!(is_reality(&blocked, &Blocks::of(&blocked)));
        // A plain node is neither.
        let plain = entry(Scheme::Vless, &[]);
        assert!(!wants_tls(&plain, &Blocks::of(&plain)));
        assert!(!is_reality(&plain, &Blocks::of(&plain)));
    }

    #[test]
    fn a_clash_and_a_uri_entry_share_one_canonical_form() {
        let uri = entry(
            Scheme::Vless,
            &[
                ("sni", "s.example.com"),
                ("pbk", "key"),
                ("sid", "short"),
                ("path", "/ws"),
            ],
        );
        let clash = entry(
            Scheme::Vless,
            &[
                ("servername", "s.example.com"),
                ("reality-opts", "public-key: key\nshort-id: short"),
                ("ws-opts", "path: /ws"),
            ],
        );
        assert_eq!(canonical_map(&uri), canonical_map(&clash));
    }

    #[test]
    fn cosmetic_parameters_do_not_contribute() {
        let plain = entry(Scheme::Vless, &[]);
        let tagged = entry(
            Scheme::Vless,
            &[
                ("remark", "free"),
                ("telegram", "@channel"),
                ("upmbps", "100"),
            ],
        );
        assert_eq!(canonical_map(&plain), canonical_map(&tagged));
    }

    #[test]
    fn transport_parameters_contribute() {
        let plain = entry(Scheme::Vless, &[("type", "ws")]);
        let upgraded = entry(Scheme::Vless, &[("type", "httpupgrade")]);
        assert_ne!(canonical_map(&plain), canonical_map(&upgraded));
        let grpc = entry(Scheme::Vless, &[("type", "grpc"), ("servicename", "svc")]);
        assert_ne!(canonical_map(&plain), canonical_map(&grpc));
    }

    #[test]
    fn the_transport_is_spelled_the_way_the_writers_emit_it() {
        // Xray's HTTP/2 spelling.
        let h2 = entry(Scheme::Vless, &[("type", "http")]);
        assert_eq!(
            canonical_map(&h2).get("type").map(String::as_str),
            Some("h2")
        );
        // The plain-HTTP header obfuscation.
        let http = entry(Scheme::Vless, &[("type", "tcp"), ("headertype", "http")]);
        assert_eq!(
            canonical_map(&http).get("type").map(String::as_str),
            Some("http")
        );
        // The mihomo spelling of the same HTTP/2 transport.
        let clash = entry(Scheme::Vless, &[("network", "h2")]);
        assert_eq!(canonical_map(&h2), canonical_map(&clash));
    }

    #[test]
    fn the_insecure_toggles_collapse_onto_one_flag() {
        let one = entry(Scheme::Trojan, &[("allowInsecure", "1")]);
        let two = entry(Scheme::Trojan, &[("skip-cert-verify", "true")]);
        let none = entry(Scheme::Trojan, &[("allowInsecure", "0")]);
        assert_eq!(canonical_map(&one), canonical_map(&two));
        assert_eq!(
            canonical_map(&none),
            canonical_map(&entry(Scheme::Trojan, &[]))
        );
    }

    /// The Clash spelling `ws-path` folds onto the URI `path`
    /// ([`canonical_key`]), so the same node advertised once as Clash YAML
    /// and once as a URI deduplicates together.
    #[test]
    fn a_clash_ws_path_and_a_uri_path_share_one_fingerprint() {
        let yaml = concat!(
            "proxies:\n",
            "  - {name: a, type: vless, server: h.example.com, port: 443, uuid: u,",
            "     network: ws, ws-path: /ws}\n",
        );
        let mut clash = crate::parsers::clash::parse_payload(yaml).unwrap().entries[0].clone();
        let crate::parsers::LineOutcome::Parsed(mut uri) =
            crate::parsers::parse_line("vless://u@h.example.com:443?type=ws&path=/ws#a")
        else {
            panic!("expected a parsed vless entry");
        };
        clash.name = String::new();
        uri.name = String::new();
        assert_eq!(
            crate::fingerprint::fingerprint(&clash),
            crate::fingerprint::fingerprint(&uri)
        );
    }

    /// The Clash spelling `grpc-service-name` folds onto the URI
    /// `servicename` ([`canonical_key`]) the same way.
    #[test]
    fn a_clash_grpc_service_name_and_a_uri_servicename_share_one_fingerprint() {
        let yaml = concat!(
            "proxies:\n",
            "  - {name: a, type: vless, server: h.example.com, port: 443, uuid: u,",
            "     network: grpc, grpc-service-name: g}\n",
        );
        let mut clash = crate::parsers::clash::parse_payload(yaml).unwrap().entries[0].clone();
        let crate::parsers::LineOutcome::Parsed(mut uri) =
            crate::parsers::parse_line("vless://u@h.example.com:443?type=grpc&servicename=g#a")
        else {
            panic!("expected a parsed vless entry");
        };
        clash.name = String::new();
        uri.name = String::new();
        assert_eq!(
            crate::fingerprint::fingerprint(&clash),
            crate::fingerprint::fingerprint(&uri)
        );
    }

    /// The fold must not erase the value: two nodes differing only in a
    /// Clash-spelled field are different nodes, and the upsert would
    /// silently overwrite one with the other if they collapsed onto one
    /// key.
    #[test]
    fn two_clash_nodes_differing_only_in_a_folded_field_do_not_collapse() {
        let yaml = concat!(
            "proxies:\n",
            "  - {name: a, type: vless, server: h.example.com, port: 443, uuid: u,",
            "     network: ws, ws-path: /ws}\n",
            "  - {name: b, type: vless, server: h.example.com, port: 443, uuid: u,",
            "     network: ws, ws-path: /other}\n",
        );
        let parsed = crate::parsers::clash::parse_payload(yaml).unwrap();
        assert_eq!(parsed.entries.len(), 2);
        assert_ne!(
            crate::fingerprint::fingerprint(&parsed.entries[0]),
            crate::fingerprint::fingerprint(&parsed.entries[1])
        );

        let yaml = concat!(
            "proxies:\n",
            "  - {name: a, type: vless, server: h.example.com, port: 443, uuid: u,",
            "     network: grpc, grpc-service-name: g}\n",
            "  - {name: b, type: vless, server: h.example.com, port: 443, uuid: u,",
            "     network: grpc, grpc-service-name: g2}\n",
        );
        let parsed = crate::parsers::clash::parse_payload(yaml).unwrap();
        assert_eq!(parsed.entries.len(), 2);
        assert_ne!(
            crate::fingerprint::fingerprint(&parsed.entries[0]),
            crate::fingerprint::fingerprint(&parsed.entries[1])
        );
    }
}
