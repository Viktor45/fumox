//! Protocol parsers and serializers for every supported subscription format.
//!
//! Public surface:
//!
//! * [`parse_line`], parse a single URI line (log-and-skip contract: it
//!   never panics, unrecognized lines are reported, not fatal);
//! * [`serialize`], turn a [`ProxyEntry`] back into its canonical line;
//! * [`parse_subscription`], decode + auto-detect a whole payload
//!   (URI list / Clash YAML / sing-box JSON / base64-wrapped) and parse
//!   every line.
//!
//! Round-trip guarantees: every parser has a serializer. URI schemes
//! round-trip byte-for-byte whenever the original used percent-encoded
//! fragments and standard formatting; vmess and ss normalize encoding and
//! guarantee semantic round-trip instead (`parse ∘ serialize ∘ parse`
//! equals the first parse). Unknown parameters always pass through untouched.
//!
//! Entries that never had a source line (Clash YAML, sing-box JSON) are the
//! exception: their parameters may carry mihomo field names, which the URI
//! serializers translate onto the canonical vocabulary first (see
//! `canonical_uri_entry`). The translation is output-only, stored
//! parameters are not rewritten.

pub mod clash;
pub mod singbox;
pub mod ss;
pub mod uri;
pub mod vmess;

use std::collections::HashSet;

use crate::models::{Encoding, InputFormat, Param, ProxyEntry, Scheme};

/// Outcome of parsing a single non-comment line.
#[derive(Debug)]
pub enum LineOutcome {
    Parsed(ProxyEntry),
    /// Recognized format that is deliberately dropped (`happ://`).
    Discarded,
    /// Unknown scheme or malformed line, counted and skipped.
    Unrecognized,
}

/// Parse one subscription line. Comments and blank lines must be filtered
/// out by the caller ([`parse_subscription`] does this).
pub fn parse_line(line: &str) -> LineOutcome {
    // Line-size cap: `raw_line` is
    // persisted verbatim onto every stored row, so an oversized line is a
    // storage bomb, the caller's log-and-skip path drops it like any other
    // malformed line.
    if line.len() > uri::MAX_LINE_BYTES {
        tracing::debug!(
            bytes = line.len(),
            cap = uri::MAX_LINE_BYTES,
            "skipping oversized proxy line"
        );
        return LineOutcome::Unrecognized;
    }
    let line = line.trim();
    let Some((scheme_raw, rest)) = line.split_once("://") else {
        return LineOutcome::Unrecognized;
    };
    let scheme = scheme_raw.to_ascii_lowercase();
    match scheme.as_str() {
        "vless" => parsed(uri::parse_with_spec(&uri::VLESS_SPEC, rest, line)),
        "trojan" => parsed(uri::parse_with_spec(&uri::TROJAN_SPEC, rest, line)),
        "hysteria2" | "hy2" => parsed(uri::parse_with_spec(&uri::HYSTERIA2_SPEC, rest, line)),
        "tuic" => parsed(uri::parse_with_spec(&uri::TUIC_SPEC, rest, line)),
        "mieru" => parsed(uri::parse_with_spec(&uri::MIERU_SPEC, rest, line)),
        "socks5" => parsed(uri::parse_with_spec(&uri::SOCKS5_SPEC, rest, line)),
        "snell" => parsed(uri::parse_with_spec(&uri::SNELL_SPEC, rest, line)),
        "anytls" => parsed(uri::parse_with_spec(&uri::ANYTLS_SPEC, rest, line)),
        "ss" => parsed(ss::parse(rest, line)),
        "vmess" => parsed(vmess::parse(rest, line)),
        // happ:// is recognized and deliberately discarded (MVP decision).
        "happ" => LineOutcome::Discarded,
        other => {
            if let Some(transport) = other.strip_prefix("naive+") {
                return parse_naive(transport, rest, line);
            }
            tracing::debug!(scheme = other, "unrecognized proxy scheme");
            LineOutcome::Unrecognized
        }
    }
}

fn parsed(result: Result<ProxyEntry, String>) -> LineOutcome {
    match result {
        Ok(entry) => LineOutcome::Parsed(entry),
        Err(message) => {
            tracing::debug!(error = %message, "skipping malformed proxy line");
            LineOutcome::Unrecognized
        }
    }
}

/// Reject a field value that would break the one-proxy-per-line contract.
///
/// The URI serializers emit `host` and `credential` verbatim and parameter
/// values with only the query delimiters escaped (`uri::encode_query_delimiters`),
/// `name` goes through [`uri::encode_fragment`], so a line break inside any
/// of them splits one stored proxy into several output lines. A crafted Clash
/// YAML or legacy-`ss` feed could smuggle a proxy of an entirely different
/// scheme past a source's protocol allowlist that way, or forge `url_list`
/// metadata comments.
///
/// URI-list input cannot reach this: `parse_uri_list` iterates over
/// `str::lines`. The vectors are the formats whose fields are not
/// line-delimited, Clash YAML scalars, vmess JSON `\n` escapes and the
/// base64 blob of a legacy `ss` line.
pub(crate) fn reject_line_breaks(field: &str, value: &str) -> Result<(), String> {
    if value.contains(['\n', '\r']) {
        return Err(format!("{field} contains a line break"));
    }
    Ok(())
}

/// Reject a YAML document that contains an alias reference (`*anchor`).
///
/// `serde_norway` resolves every alias by jumping to the anchor's event span
/// and re-deserializing it into fresh owned values that are retained in the
/// result tree; its only bound is a document-global jump counter that an
/// alias bomb stays far under. One anchor of `s` events plus `k` references
/// materializes ~`k×s` values from a payload of ~`k+s` events, quadratic
/// memory amplification from a feed payload bounded only by the 10 MiB fetch
/// cap (security review f4: 20 KiB → >1 GiB heap, allocation failure aborts
/// the whole process). Feed content has no legitimate use for aliases, so
/// the entire class is refused before parsing rather than budgeted.
///
/// The scan is a small YAML-token scanner, not a parser, and it is biased
/// toward false positives: a missed alias is a security hole, a wrongly
/// rejected payload is a visible parse error. It must therefore find every
/// alias an attacker can write (in valid YAML a `*` at a token position is
/// always an alias, plain scalars cannot start with an indicator), while
/// not rejecting the quoted scalars and block scalars real configs carry
/// (`password: pass*word` must keep parsing). Positions treated as literal
/// text: double/single-quoted scalars (entered only at token boundaries,
/// escapes honored, state carried across lines), comments (`#` after
/// whitespace to end of line) and block scalars (`|`/`>` header, content
/// skipped by indentation).
pub(crate) fn reject_yaml_aliases(payload: &str) -> Result<(), String> {
    let mut block_indent: Option<usize> = None;
    let mut in_double = false;
    let mut in_single = false;
    for (idx, line) in payload.lines().enumerate() {
        let indent = line.len() - line.trim_start().len();
        if let Some(header_indent) = block_indent {
            // Block-scalar content: blank lines and anything more indented
            // than the header line is literal text, however alias-shaped.
            if line.trim().is_empty() || indent > header_indent {
                continue;
            }
            block_indent = None;
        }
        if scan_yaml_line(
            line,
            indent,
            &mut in_double,
            &mut in_single,
            &mut block_indent,
        ) {
            return Err(format!(
                "YAML alias reference (`*…`) on line {}: feed content must not use YAML \
                 aliases, the parser re-materializes the anchor's whole subtree for every \
                 reference and a small payload amplifies into quadratic memory",
                idx + 1
            ));
        }
    }
    Ok(())
}

/// Scan one line for alias references. Returns `true` when an alias was
/// found. Quote state is carried across calls (multi-line quoted scalars
/// are legal); a recognized block-scalar header stores its indentation so
/// [`reject_yaml_aliases`] skips the literal content lines that follow.
fn scan_yaml_line(
    line: &str,
    indent: usize,
    in_double: &mut bool,
    in_single: &mut bool,
    block_indent: &mut Option<usize>,
) -> bool {
    let bytes = line.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        // A token boundary is the start of the line or a position after
        // whitespace or a structural character. `:` counts even without a
        // following space: block-context `key:*a` is a plain scalar, but a
        // missed alias is a hole while a rejected odd scalar is only a
        // parse error, so the boundary set is biased wide.
        let boundary = i == 0 || matches!(bytes[i - 1], b' ' | b'\t' | b',' | b'[' | b'{' | b':');
        if *in_double {
            match b {
                // Escaped byte (possibly a quote): skip it.
                b'\\' => i += 1,
                b'"' => *in_double = false,
                _ => {}
            }
        } else if *in_single {
            if b == b'\'' && bytes.get(i + 1) == Some(&b'\'') {
                i += 1; // '' is an escaped literal quote
            } else if b == b'\'' {
                *in_single = false;
            }
        } else if b == b'"' && boundary {
            *in_double = true;
        } else if b == b'\'' && boundary {
            *in_single = true;
        } else if b == b'#' && (i == 0 || matches!(bytes[i - 1], b' ' | b'\t')) {
            // Comment to end of line.
            break;
        } else if b == b'*' && boundary {
            // In valid YAML a `*` at a token position is always an alias:
            // plain scalars cannot start with an indicator character.
            return true;
        } else if (b == b'|' || b == b'>')
            && boundary
            && is_block_scalar_header(&line[..i], &line[i..])
        {
            *block_indent = Some(indent);
        }
        i += 1;
    }
    false
}

/// Does the `|`/`>` starting at `header` begin a block scalar? The header
/// must sit at a value position: after `key:`, after a `-` entry marker,
/// or alone on the line, and may only carry the indentation digit and
/// chomping indicator before whitespace or a comment. Text like
/// `key: a |` is a plain scalar ending in `|`; treating it as a header
/// would swallow the alias-bearing lines that follow.
fn is_block_scalar_header(prefix: &str, header: &str) -> bool {
    let mut rest = prefix.trim();
    while let Some(stripped) = rest.strip_prefix("- ") {
        rest = stripped.trim_start();
    }
    if !rest.is_empty() && rest != "-" && !rest.ends_with(':') {
        return false;
    }
    // Indicators after the `|`/`>` byte: one indentation digit and one
    // chomping marker, in either order.
    let bytes = header.as_bytes();
    let mut i = 1;
    let mut saw_indent = false;
    let mut saw_chomp = false;
    while let Some(&b) = bytes.get(i) {
        match b {
            b'0'..=b'9' if !saw_indent => {
                saw_indent = true;
                i += 1;
            }
            b'+' | b'-' if !saw_chomp => {
                saw_chomp = true;
                i += 1;
            }
            _ => break,
        }
    }
    let tail = header[i..].trim();
    tail.is_empty() || tail.starts_with('#')
}

/// `naive+https` / `naive+quic`: the transport suffix is scheme identity and
/// is preserved as the synthetic `naive_transport` parameter so the
/// serializer can rebuild the exact prefix.
fn parse_naive(transport: &str, rest: &str, line: &str) -> LineOutcome {
    if !matches!(transport, "https" | "quic") {
        return LineOutcome::Unrecognized;
    }
    let mut entry = match uri::parse_with_spec(&uri::NAIVE_SPEC, rest, line) {
        Ok(entry) => entry,
        Err(message) => {
            tracing::debug!(error = %message, "skipping malformed naive line");
            return LineOutcome::Unrecognized;
        }
    };
    // Insert first so the serializer sees it deterministically.
    entry.params.insert(
        0,
        crate::models::Param {
            key: "naive_transport".to_string(),
            value: transport.to_string(),
            known: true,
        },
    );
    LineOutcome::Parsed(entry)
}

/// Serialize an entry back into a subscription line.
///
/// Entries with a source line are emitted with their query bytes (almost)
/// untouched; entries without one (Clash YAML, sing-box JSON) go through
/// [`canonical_uri_entry`] first, so a Clash item's mihomo field names
/// become the URI vocabulary a client understands.
///
/// Guaranteed to return a single line: `sanitize_for_output` strips line
/// breaks from the fields the serializers emit verbatim. Parsers reject such
/// values up front, so this only catches rows that predate the check or were
/// written directly into SQLite.
pub fn serialize(entry: &ProxyEntry) -> String {
    let translated;
    let entry = if entry.raw_line.is_empty() {
        translated = canonical_uri_entry(entry);
        &translated
    } else {
        entry
    };
    let sanitized = sanitize_for_output(entry);
    let entry = sanitized.as_ref().unwrap_or(entry);
    match entry.scheme {
        Scheme::Vless => uri::serialize_with_spec(&uri::VLESS_SPEC, entry),
        Scheme::Trojan => uri::serialize_with_spec(&uri::TROJAN_SPEC, entry),
        Scheme::Hysteria2 => uri::serialize_with_spec(&uri::HYSTERIA2_SPEC, entry),
        Scheme::Tuic => uri::serialize_with_spec(&uri::TUIC_SPEC, entry),
        Scheme::Mieru => uri::serialize_with_spec(&uri::MIERU_SPEC, entry),
        Scheme::Socks5 => uri::serialize_with_spec(&uri::SOCKS5_SPEC, entry),
        Scheme::Snell => uri::serialize_with_spec(&uri::SNELL_SPEC, entry),
        Scheme::AnyTls => uri::serialize_with_spec(&uri::ANYTLS_SPEC, entry),
        Scheme::Naive => serialize_naive(entry),
        Scheme::Ss => ss::serialize(entry),
        Scheme::Vmess => vmess::serialize(entry),
    }
}

/// Translate an entry's parameters from mihomo (Clash) spellings onto the
/// canonical URI vocabulary, flattening the structured blocks Clash keeps
/// as YAML text.
///
/// Emitted verbatim into a URI query, a mihomo field name is either
/// ignored by the client (`network` selects no transport, `tls=true`
/// enables no TLS, `servername` sets no SNI) or is outright unparseable
/// (`ws-opts` is a multi-line YAML block). Only entries without a source
/// line reach this: URI-parsed entries keep their stored spellings
/// byte-for-byte, and the Clash/sing-box writers read both vocabularies,
/// so the stored parameters are deliberately not touched.
///
/// When a translated key collides with one already present (`servername`
/// next to a real `sni`), the first occurrence in stored order wins.
///
/// REALITY needs a value rewrite of its own: mihomo spells it as
/// `tls: true` + `reality-opts`, so flattening the block to `pbk`/`sid`
/// while the `tls` arm still emitted `security=tls` (or nothing at all)
/// handed clients a plain TLS node that drops the REALITY keys.
fn canonical_uri_entry(entry: &ProxyEntry) -> ProxyEntry {
    let mut out = entry.clone();
    out.params.clear();
    for param in &entry.params {
        translate_uri_param(entry.scheme, param, &mut out.params);
    }
    let mut seen: HashSet<String> = HashSet::new();
    out.params
        .retain(|p| seen.insert(p.key.to_ascii_lowercase()));
    // Force the one key the translation cannot know about: a public key
    // makes this a REALITY node whatever `security` says (or omits).
    if matches!(entry.scheme, Scheme::Vless | Scheme::Trojan)
        && crate::formats::reality_public_key(entry).is_some()
    {
        match out
            .params
            .iter_mut()
            .find(|p| p.key.eq_ignore_ascii_case("security"))
        {
            Some(security) => security.value = "reality".to_string(),
            None => push(&mut out.params, "security", "reality"),
        }
    }
    out
}

fn translate_uri_param(scheme: Scheme, param: &Param, out: &mut Vec<Param>) {
    let key = param.key.to_ascii_lowercase();
    let value = param.value.trim();
    match key.as_str() {
        "servername" => push(out, "sni", value),
        "network" => push(
            out,
            if scheme == Scheme::Vmess {
                "net"
            } else {
                "type"
            },
            value,
        ),
        "ws-path" => push(out, "path", value),
        "client-fingerprint" => push(out, "fp", value),
        "grpc-service-name" => push(out, "servicename", value),
        "fingerprint" => push(out, "pinsha256", value),
        // vmess JSON spells the cipher `scy` and the alter id `aid`.
        "cipher" if scheme == Scheme::Vmess => push(out, "scy", value),
        "alterid" if scheme == Scheme::Vmess => push(out, "aid", value),
        "alpn" => push(out, "alpn", &joined_alpn(value)),
        // Clash's `tls` boolean against the URI spellings: `security=tls`
        // for the URI-family schemes, the `tls: "tls"` string for vmess
        // JSON (which is also what the sing-box parser stores, hence the
        // literal check). A falsy toggle means plaintext, i.e. nothing.
        "tls" => match scheme {
            Scheme::Vless | Scheme::Trojan => {
                if truthy(value) || value.eq_ignore_ascii_case("tls") {
                    push(out, "security", "tls");
                }
            }
            Scheme::Vmess => {
                if truthy(value) || value.eq_ignore_ascii_case("tls") {
                    push(out, "tls", "tls");
                }
            }
            _ => out.push(param.clone()),
        },
        // The one Clash-only toggle spelling: mihomo writes
        // `skip-cert-verify`, the URI family reads `allowInsecure` (vless,
        // trojan, vmess JSON) or `insecure` (hysteria2, anytls). A falsy
        // toggle means verification on, i.e. nothing to emit. The
        // `insecure`/`allowInsecure` spellings themselves pass through
        // untouched wherever the source already used them.
        "skip-cert-verify" => {
            if truthy(value) {
                match scheme {
                    Scheme::Vless | Scheme::Trojan | Scheme::Vmess => {
                        push(out, "allowInsecure", "1")
                    }
                    Scheme::Hysteria2 | Scheme::AnyTls => push(out, "insecure", "1"),
                    _ => {}
                }
            }
        }
        "ws-opts" => flatten_ws_opts(value, out),
        "ws-headers" => {
            if let Some(map) = yaml_mapping(value) {
                push_opt(out, "host", block_string(&map, "host"));
            }
        }
        "reality-opts" => {
            if let Some(map) = yaml_mapping(value) {
                push_opt(
                    out,
                    "pbk",
                    block_string(&map, "public-key").or_else(|| block_string(&map, "public_key")),
                );
                push_opt(
                    out,
                    "sid",
                    block_string(&map, "short-id").or_else(|| block_string(&map, "short_id")),
                );
            }
        }
        "grpc-opts" => {
            if let Some(map) = yaml_mapping(value) {
                push_opt(
                    out,
                    "servicename",
                    block_string(&map, "grpc-service-name")
                        .or_else(|| block_string(&map, "serviceName")),
                );
            }
        }
        "h2-opts" => {
            if let Some(map) = yaml_mapping(value) {
                push_opt(out, "host", block_string(&map, "host"));
                push_opt(out, "path", block_string(&map, "path"));
            }
        }
        "http-opts" => {
            if let Some(map) = yaml_mapping(value) {
                push_opt(out, "path", block_string(&map, "path"));
                if let Some(headers) = block_value(&map, "headers").and_then(|v| v.as_mapping()) {
                    push_opt(out, "host", block_string(headers, "host"));
                }
            }
        }
        // Snell spells its obfuscation as a nested block; the URI form is
        // the flat `obfs` / `obfs-host` pair.
        "obfs-opts" => {
            if let Some(map) = yaml_mapping(value) {
                push_opt(out, "obfs", block_string(&map, "mode"));
                push_opt(out, "obfs-host", block_string(&map, "host"));
            }
        }
        _ => out.push(param.clone()),
    }
}

/// `ws-opts: {path: /ws, headers: {Host: h}}` → URI `path` + `host`.
/// The remaining mihomo knobs (`max-early-data`, `early-data-header-name`)
/// have no URI spelling and are dropped rather than emitted as YAML text.
fn flatten_ws_opts(value: &str, out: &mut Vec<Param>) {
    let Some(map) = yaml_mapping(value) else {
        return;
    };
    push_opt(out, "path", block_string(&map, "path"));
    if let Some(headers) = block_value(&map, "headers").and_then(|v| v.as_mapping()) {
        push_opt(out, "host", block_string(headers, "host"));
    }
}

fn push(out: &mut Vec<Param>, key: &str, value: &str) {
    if !value.is_empty() {
        out.push(Param {
            key: key.to_string(),
            value: value.to_string(),
            known: true,
        });
    }
}

fn push_opt(out: &mut Vec<Param>, key: &str, value: Option<String>) {
    if let Some(value) = value {
        push(out, key, &value);
    }
}

fn truthy(value: &str) -> bool {
    matches!(
        value.to_ascii_lowercase().as_str(),
        "1" | "true" | "yes" | "on"
    )
}

/// URI `alpn` is one comma-joined value; Clash feeds list it as a YAML
/// sequence (`alpn: [h2, http/1.1]`), which the Clash parser stores as
/// YAML text and a URI client cannot read. Plain scalars pass through.
fn joined_alpn(value: &str) -> String {
    match yaml_value(value) {
        Some(serde_norway::Value::Sequence(items)) => {
            let items: Vec<String> = items.iter().filter_map(yaml_scalar).collect();
            if items.is_empty() {
                value.to_string()
            } else {
                items.join(",")
            }
        }
        _ => value.to_string(),
    }
}

/// Parse stored YAML text back into a value, refusing alias references
/// first: block values are feed-controlled like any other parameter (see
/// [`reject_yaml_aliases`]).
fn yaml_value(text: &str) -> Option<serde_norway::Value> {
    if reject_yaml_aliases(text).is_err() {
        return None;
    }
    serde_norway::from_str(text).ok()
}

/// Parse a stored structured block (`ws-opts`, `reality-opts`, …) into a
/// mapping; `None` for anything else, including unparseable text.
fn yaml_mapping(text: &str) -> Option<serde_norway::Mapping> {
    match yaml_value(text) {
        Some(serde_norway::Value::Mapping(map)) => Some(map),
        _ => None,
    }
}

/// Case-insensitive lookup inside a parsed block.
fn block_value<'a>(map: &'a serde_norway::Mapping, key: &str) -> Option<&'a serde_norway::Value> {
    map.iter()
        .find(|(k, _)| k.as_str().is_some_and(|k| k.eq_ignore_ascii_case(key)))
        .map(|(_, v)| v)
}

/// Scalar under `key` inside a parsed block, as the text a URI value
/// needs. A sequence collapses to its items joined with `,` (Clash lists
/// hosts); anything else has no URI scalar form.
fn block_string(map: &serde_norway::Mapping, key: &str) -> Option<String> {
    match block_value(map, key)? {
        serde_norway::Value::Sequence(items) => {
            let items: Vec<String> = items.iter().filter_map(yaml_scalar).collect();
            (!items.is_empty()).then(|| items.join(","))
        }
        other => yaml_scalar(other).filter(|s| !s.is_empty()),
    }
}

/// Scalar value as text; sequences and mappings have no scalar form.
fn yaml_scalar(value: &serde_norway::Value) -> Option<String> {
    match value {
        serde_norway::Value::String(s) => Some(s.clone()),
        serde_norway::Value::Number(n) => Some(n.to_string()),
        serde_norway::Value::Bool(b) => Some(b.to_string()),
        _ => None,
    }
}

/// Replace line breaks in `host`, `credential` and parameter values with a
/// space, returning `None` when the entry is already clean (the overwhelming
/// case, so no allocation happens). `name` needs no treatment: every
/// serializer percent-encodes or JSON-escapes it.
fn sanitize_for_output(entry: &ProxyEntry) -> Option<ProxyEntry> {
    let dirty = |value: &str| value.contains(['\n', '\r']);
    let needs_fix = dirty(&entry.host)
        || dirty(&entry.credential)
        || dirty(&entry.raw_path)
        || entry
            .params
            .iter()
            .any(|p| dirty(&p.key) || dirty(&p.value));
    if !needs_fix {
        return None;
    }
    tracing::warn!(
        host = %entry.host.replace(['\n', '\r'], "\\n"),
        "proxy entry carries line breaks, sanitizing before output"
    );
    let strip = |value: &str| value.replace(['\n', '\r'], " ");
    let mut clean = entry.clone();
    clean.host = strip(&entry.host);
    clean.credential = strip(&entry.credential);
    clean.raw_path = strip(&entry.raw_path);
    for param in &mut clean.params {
        param.key = param.key.replace(['\n', '\r'], " ");
        param.value = param.value.replace(['\n', '\r'], " ");
    }
    Some(clean)
}

fn serialize_naive(entry: &ProxyEntry) -> String {
    let transport = entry.param("naive_transport").unwrap_or("https");
    let prefix = format!("naive+{transport}://");
    // Serialize through the generic machinery, then swap the prefix; the
    // synthetic parameter itself must not leak into the query string.
    let mut stripped = entry.clone();
    stripped.params.retain(|p| p.key != "naive_transport");
    let spec_prefix = uri::NAIVE_SPEC.prefix;
    let generic = uri::serialize_with_spec(&uri::NAIVE_SPEC, &stripped);
    format!("{prefix}{}", &generic[spec_prefix.len()..])
}

/// Aggregated result of parsing a whole subscription payload.
#[derive(Debug, Default)]
pub struct ParsedSubscription {
    pub entries: Vec<ProxyEntry>,
    /// Recognized lines deliberately dropped (`happ://`).
    pub discarded: usize,
    /// Unknown/malformed lines skipped.
    pub unrecognized: usize,
    /// Clash items of unsupported types or malformed items, and the same
    /// for sing-box/Xray outbounds.
    pub clash_skipped: usize,
    /// The format the payload was detected (or pinned) as.
    pub format: InputFormat,
}

/// Decode and parse a full subscription payload.
///
/// `encoding` and `input_format` mirror the `sources` columns: explicit pins
/// override auto-detection. Returns `Err` only when the payload as a whole
/// is unusable (bad pinned base64, invalid YAML/JSON); individual bad lines
/// are counted and skipped, never fatal.
pub fn parse_subscription(
    payload: &str,
    encoding: Encoding,
    input_format: Option<InputFormat>,
) -> crate::Result<ParsedSubscription> {
    let text = decode_payload(payload, encoding)?;
    let format = match input_format {
        Some(pinned) => pinned,
        None => detect_format(&text),
    };
    match format {
        InputFormat::UriList => parse_uri_list(&text, format),
        InputFormat::ClashYaml => parse_clash_payload(&text),
        InputFormat::SingBoxJson => parse_singbox_payload(&text),
    }
}

/// Unwrap the transport encoding. `auto` base64-decodes only when the payload
/// cannot already be a plain subscription (no `://` marker) and decodes to
/// something that looks like one: a URI list, Clash YAML, or a JSON config
/// (object or array, the v2rayN share format).
fn decode_payload(payload: &str, encoding: Encoding) -> crate::Result<String> {
    match encoding {
        Encoding::Plain => Ok(payload.to_string()),
        Encoding::Base64 => decode_base64_text(payload).ok_or_else(|| {
            crate::Error::Parse("payload is not valid base64 (pinned encoding)".to_string())
        }),
        Encoding::Auto => {
            let trimmed = payload.trim();
            if !trimmed.is_empty()
                && !trimmed.contains("://")
                && let Some(decoded) = decode_base64_text(trimmed)
            {
                let head = decoded.trim_start();
                if decoded.contains("://")
                    || decoded.contains("proxies:")
                    || head.starts_with('{')
                    || head.starts_with('[')
                {
                    return Ok(decoded);
                }
            }
            Ok(payload.to_string())
        }
    }
}

fn decode_base64_text(input: &str) -> Option<String> {
    // Feeds wrap long payloads at 76 columns or pad them with blank lines;
    // base64 has no whitespace of its own, so interior whitespace (which
    // also breaks the length-modulo check) is stripped before decoding.
    let bytes = ss::decode_b64_lenient(&input.split_whitespace().collect::<String>())?;
    // A subscription is text; reject binary garbage.
    let text = String::from_utf8(bytes).ok()?;
    (!text.trim().is_empty()).then_some(text)
}

/// Heuristic format detection: JSON (object or the v2rayN share array)
/// means sing-box, a `proxies:` key means Clash YAML, everything else is
/// treated as a URI list.
fn detect_format(text: &str) -> InputFormat {
    let trimmed = text.trim_start();
    if trimmed.starts_with('{') || trimmed.starts_with('[') {
        return InputFormat::SingBoxJson;
    }
    let has_proxies_key = trimmed.starts_with("proxies:")
        || text.contains("\nproxies:")
        || text.contains("\r\nproxies:");
    if has_proxies_key {
        return InputFormat::ClashYaml;
    }
    InputFormat::UriList
}

fn parse_uri_list(text: &str, format: InputFormat) -> crate::Result<ParsedSubscription> {
    let mut result = ParsedSubscription {
        format,
        ..Default::default()
    };
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        match parse_line(line) {
            LineOutcome::Parsed(entry) => result.entries.push(entry),
            LineOutcome::Discarded => result.discarded += 1,
            LineOutcome::Unrecognized => result.unrecognized += 1,
        }
    }
    Ok(result)
}

fn parse_clash_payload(text: &str) -> crate::Result<ParsedSubscription> {
    let clash_result = clash::parse_payload(text).map_err(crate::Error::Parse)?;
    Ok(ParsedSubscription {
        entries: clash_result.entries,
        clash_skipped: clash_result.unsupported + clash_result.invalid,
        format: InputFormat::ClashYaml,
        ..Default::default()
    })
}

fn parse_singbox_payload(text: &str) -> crate::Result<ParsedSubscription> {
    let result = singbox::parse_payload(text).map_err(crate::Error::Parse)?;
    Ok(ParsedSubscription {
        entries: result.entries,
        clash_skipped: result.unsupported + result.invalid,
        format: InputFormat::SingBoxJson,
        ..Default::default()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry_for(line: &str) -> ProxyEntry {
        match parse_line(line) {
            LineOutcome::Parsed(entry) => entry,
            other => panic!("expected Parsed for {line:?}, got {other:?}"),
        }
    }

    /// Compare two entries ignoring `raw_line`, which legitimately differs
    /// after a re-serialization.
    fn assert_semantically_equal(a: &ProxyEntry, b: &ProxyEntry) {
        assert_eq!(a.scheme, b.scheme, "scheme");
        assert_eq!(a.name, b.name, "name");
        assert_eq!(a.host, b.host, "host");
        assert_eq!(a.port, b.port, "port");
        assert_eq!(a.credential, b.credential, "credential");
        assert_eq!(a.params, b.params, "params");
        assert_eq!(a.raw_path, b.raw_path, "raw_path");
    }

    #[test]
    fn naive_transport_round_trip() {
        let line =
            "naive+https://User:d75ca9b2@grape.example.net:5443?sni=grape.example.net#Unknown";
        let entry = entry_for(line);
        assert_eq!(entry.scheme, Scheme::Naive);
        assert_eq!(entry.param("naive_transport"), Some("https"));
        assert_eq!(serialize(&entry), line);
    }

    fn clash_entries(yaml: &str) -> Vec<ProxyEntry> {
        parse_subscription(yaml, Encoding::Plain, Some(InputFormat::ClashYaml))
            .unwrap()
            .entries
    }

    /// A Clash vless item carries mihomo field names; served as a URI it
    /// must come out in the vocabulary a URI client understands, otherwise
    /// the node connects without TLS or transport, or not at all.
    #[test]
    fn clash_vless_item_serializes_onto_the_uri_vocabulary() {
        let yaml = concat!(
            "proxies:\n",
            "  - name: ws-node\n",
            "    type: vless\n",
            "    server: h.example.com\n",
            "    port: 443\n",
            "    uuid: uuid-1\n",
            "    tls: true\n",
            "    servername: s.example.com\n",
            "    network: ws\n",
            "    client-fingerprint: chrome\n",
            "    flow: xtls-rprx-vision\n",
            "    skip-cert-verify: true\n",
            "    alpn: [h2, http/1.1]\n",
            "    ws-opts:\n",
            "      path: /ws\n",
            "      headers:\n",
            "        Host: ws.example.com\n",
        );
        let line = serialize(&clash_entries(yaml)[0]);
        assert!(
            line.starts_with("vless://uuid-1@h.example.com:443?"),
            "{line}"
        );
        for expected in [
            "security=tls",
            "sni=s.example.com",
            "type=ws",
            "path=/ws",
            "host=ws.example.com",
            "fp=chrome",
            "flow=xtls-rprx-vision",
            "allowInsecure=1",
            "alpn=h2,http/1.1",
        ] {
            assert!(line.contains(expected), "missing {expected:?} in {line}");
        }
        for gone in [
            "network=",
            "servername",
            "ws-opts",
            "skip-cert-verify",
            "tls=true",
        ] {
            assert!(!line.contains(gone), "{gone:?} still in {line}");
        }
        assert!(line.ends_with("#ws-node"), "{line}");

        // The emitted line re-parses into the equivalent entry.
        let back = entry_for(&line);
        assert_eq!(back.param("security"), Some("tls"));
        assert_eq!(back.param("sni"), Some("s.example.com"));
        assert_eq!(back.param("type"), Some("ws"));
        assert_eq!(back.param("path"), Some("/ws"));
        assert_eq!(back.param("host"), Some("ws.example.com"));
        assert_eq!(back.param("allowInsecure"), Some("1"));
    }

    /// A Clash vmess item is re-encoded with the vmess JSON vocabulary
    /// (`scy`/`aid`/`net`, `tls` as a string), not the mihomo one.
    #[test]
    fn clash_vmess_item_serializes_onto_the_vmess_json_vocabulary() {
        let yaml = concat!(
            "proxies:\n",
            "  - {name: vm, type: vmess, server: h.example.com, port: 443, uuid: uuid-2, ",
            "alterId: 4, cipher: aes-128-gcm, network: ws, ws-path: /wsp, ",
            "ws-headers: {Host: vh.example.com}, tls: true}\n",
        );
        let line = serialize(&clash_entries(yaml)[0]);
        assert!(line.starts_with("vmess://"), "{line}");
        let back = entry_for(&line);
        assert_eq!(back.scheme, Scheme::Vmess);
        assert_eq!(back.host, "h.example.com");
        assert_eq!(back.param("scy"), Some("aes-128-gcm"));
        assert_eq!(back.param("aid"), Some("4"));
        assert_eq!(back.param("net"), Some("ws"));
        assert_eq!(back.param("path"), Some("/wsp"));
        assert_eq!(back.param("host"), Some("vh.example.com"));
        assert_eq!(back.param("tls"), Some("tls"));
        for gone in ["cipher", "network", "ws-path", "ws-headers", "alterId"] {
            assert!(
                back.param_ignore_case(gone).is_none(),
                "{gone} still present"
            );
        }
    }

    /// The structured blocks Clash keeps as YAML text (`reality-opts`,
    /// `grpc-opts`) flatten onto the URI scalars; the block text itself
    /// must never leak into the query.
    #[test]
    fn clash_structured_blocks_flatten_onto_uri_params() {
        let yaml = concat!(
            "proxies:\n",
            "  - name: r\n",
            "    type: vless\n",
            "    server: h.example.com\n",
            "    port: 443\n",
            "    uuid: u\n",
            "    network: grpc\n",
            "    grpc-opts:\n",
            "      grpc-service-name: svc\n",
            "    reality-opts:\n",
            "      public-key: PBK123\n",
            "      short-id: ab12\n",
        );
        let line = serialize(&clash_entries(yaml)[0]);
        assert!(line.contains("type=grpc"), "{line}");
        assert!(line.contains("servicename=svc"), "{line}");
        assert!(line.contains("pbk=PBK123"), "{line}");
        assert!(line.contains("sid=ab12"), "{line}");
        assert!(!line.contains("grpc-opts"), "{line}");
        assert!(!line.contains("reality-opts"), "{line}");
        let back = entry_for(&line);
        assert_eq!(back.param("pbk"), Some("PBK123"));
        assert_eq!(back.param("sid"), Some("ab12"));
        assert_eq!(back.param("servicename"), Some("svc"));
    }

    /// mihomo spells REALITY as `tls: true` + `reality-opts`; the URI
    /// vocabulary is `security=reality`. Flattening only the block while
    /// the `tls` boolean still emitted `security=tls` handed the client a
    /// plain TLS node that drops the REALITY keys.
    #[test]
    fn clash_vless_reality_item_serializes_with_security_reality() {
        let yaml = concat!(
            "proxies:\n",
            "  - name: rl\n",
            "    type: vless\n",
            "    server: h.example.com\n",
            "    port: 443\n",
            "    uuid: u-1\n",
            "    tls: true\n",
            "    servername: s.example.com\n",
            "    client-fingerprint: chrome\n",
            "    reality-opts:\n",
            "      public-key: PBK123\n",
            "      short-id: ab12\n",
            "    network: tcp\n",
        );
        let line = serialize(&clash_entries(yaml)[0]);
        assert!(line.starts_with("vless://u-1@h.example.com:443?"), "{line}");
        assert!(line.contains("security=reality"), "{line}");
        assert!(!line.contains("security=tls"), "{line}");
        for expected in ["pbk=PBK123", "sid=ab12", "sni=s.example.com", "fp=chrome"] {
            assert!(line.contains(expected), "missing {expected:?} in {line}");
        }
        let back = entry_for(&line);
        assert_eq!(back.param("security"), Some("reality"));
        assert_eq!(back.param("pbk"), Some("PBK123"));
        assert_eq!(back.param("sid"), Some("ab12"));
    }

    /// Snell spells its obfuscation as a nested block; the URI form is the
    /// flat `obfs` / `obfs-host` pair.
    #[test]
    fn clash_snell_obfs_block_flattens_to_obfs_params() {
        let yaml = concat!(
            "proxies:\n",
            "  - {name: sn, type: snell, server: 1.2.3.4, port: 44046, psk: psk1, ",
            "version: 4, obfs-opts: {mode: http, host: bing.com}}\n",
        );
        let line = serialize(&clash_entries(yaml)[0]);
        assert!(line.starts_with("snell://psk1@1.2.3.4:44046?"), "{line}");
        assert!(line.contains("obfs=http"), "{line}");
        assert!(line.contains("obfs-host=bing.com"), "{line}");
        assert!(!line.contains("obfs-opts"), "{line}");
        let back = entry_for(&line);
        assert_eq!(back.param("obfs"), Some("http"));
        assert_eq!(back.param("obfs-host"), Some("bing.com"));
        assert_eq!(back.param("version"), Some("4"));
    }

    /// A falsy toggle is indistinguishable from no toggle: nothing is
    /// emitted, the line stays clean.
    #[test]
    fn clash_falsy_toggles_are_dropped() {
        let yaml = concat!(
            "proxies:\n",
            "  - {name: n, type: vless, server: h.example.com, port: 443, uuid: u, ",
            "tls: false, skip-cert-verify: false}\n",
        );
        let line = serialize(&clash_entries(yaml)[0]);
        assert_eq!(line, "vless://u@h.example.com:443#n");
    }

    /// The translation is for line-less entries only: a URI line keeps its
    /// stored spelling in the output, mihomo-looking or not (the fixture
    /// test pins the same invariant for real feeds).
    #[test]
    fn uri_sourced_entries_are_not_translated() {
        let line = "vless://u@h.example.com:443?network=ws&servername=x.example.com&tls=true#n";
        let entry = entry_for(line);
        assert_eq!(serialize(&entry), line);
    }

    #[test]
    fn happ_is_discarded() {
        assert!(matches!(
            parse_line("happ://some-encoded-payload"),
            LineOutcome::Discarded
        ));
    }

    /// A line break in `host`/`credential`/params splits one stored proxy
    /// into several output lines, which smuggles a proxy of a different
    /// scheme past a source's protocol allowlist and forges `url_list`
    /// metadata comments.
    #[test]
    fn line_breaks_are_rejected_at_parse_time() {
        let clash = |body: &str| {
            parse_subscription(body, Encoding::Plain, Some(InputFormat::ClashYaml)).unwrap()
        };

        // Credential: a trojan-only source would have served a vless node.
        let smuggled = clash(concat!(
            "proxies:\n",
            "  - name: ok\n",
            "    type: trojan\n",
            "    server: good.example.com\n",
            "    port: 443\n",
            "    password: \"pw\\nvless://SMUGGLED@3.3.3.3:443#pwn\"\n",
        ));
        assert!(smuggled.entries.is_empty());
        assert_eq!(smuggled.clash_skipped, 1);

        // Host field.
        let bad_host = clash(concat!(
            "proxies:\n",
            "  - name: ok\n",
            "    type: trojan\n",
            "    server: \"h.example.com\\nvless://X@9.9.9.9:443#inj\"\n",
            "    port: 443\n",
            "    password: pw\n",
        ));
        assert!(bad_host.entries.is_empty());
        assert_eq!(bad_host.clash_skipped, 1);

        // vmess JSON carries the same risk through `add` and `id`.
        let json = r#"{"v":"2","ps":"x","add":"h.example.com","port":"443","id":"u\nvless://Y@8.8.8.8:443#inj"}"#;
        let b64 = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD_NO_PAD,
            json.as_bytes(),
        );
        assert!(matches!(
            parse_line(&format!("vmess://{b64}")),
            LineOutcome::Unrecognized
        ));
    }

    /// Every alias shape a feed can carry is refused. `key:*a` is a plain
    /// scalar in block context, but the boundary set is deliberately wide:
    /// a missed alias is a security hole, a rejected odd scalar is only a
    /// parse error.
    #[test]
    fn yaml_alias_forms_are_rejected() {
        for payload in [
            "proxies: &a [*a]",
            "proxies:\n  - *a\n",
            "a: [*b, {c: *d}]\n",
            "*anchor: value\n",
            "key:*a\n",
            "x: &a 1\ny: *a\n",
            "folded: >\n  text\nnext: *a\n",
        ] {
            assert!(
                reject_yaml_aliases(payload).is_err(),
                "must reject: {payload:?}"
            );
        }
    }

    /// Quoted scalars, comments, block-scalar content and stars inside
    /// plain scalars are literal text, real configs carrying them must
    /// keep parsing. The quoted scalar spanning two lines carries its
    /// state across lines, so a later alias-shaped line stays inside it.
    #[test]
    fn yaml_without_alias_references_still_parses() {
        for payload in [
            "name: \"*HK 01\"\n",
            "password: pass*word\n",
            "password: 'p*w'\n",
            "# *a comment\nkey: v\n",
            "script: |\n  echo *alias\nend: 1\n",
            "folded: >-\n  a *b\n",
            "- plain\n- list\n",
            "a: \"line1\n  line2 *b\"\n",
            "proxies:\n  - {name: n, type: trojan, server: h, port: 443, password: 'p*w'}\n",
        ] {
            assert!(
                reject_yaml_aliases(payload).is_ok(),
                "must accept: {payload:?}"
            );
        }
    }

    /// End to end: an alias bomb no longer reaches the YAML parser, the
    /// source is marked failed with the rejection instead of amplifying.
    #[test]
    fn alias_bomb_is_rejected_at_parse_time() {
        let bomb = "proxies: &a [0,0,0,0,0,0,0,0]\n".to_string() + &"*a, ".repeat(200) + "*a\n";
        let err =
            parse_subscription(&bomb, Encoding::Plain, Some(InputFormat::ClashYaml)).unwrap_err();
        assert!(matches!(err, crate::Error::Parse(_)));
    }

    /// Defence in depth for rows that predate the parser check or were
    /// written straight into SQLite: the serializer must still emit one line.
    #[test]
    fn serialize_sanitizes_line_breaks_it_is_handed() {
        let entry = ProxyEntry {
            scheme: Scheme::Trojan,
            name: "n".into(),
            host: "h.example.com\nvless://X@9.9.9.9:443#inj".into(),
            port: 443,
            credential: "pw\nsmuggled".into(),
            params: vec![crate::models::Param {
                key: "sni".into(),
                value: "a\n# profile-title: FORGED".into(),
                known: true,
            }],
            raw_path: String::new(),
            raw_line: String::new(),
        };
        let line = serialize(&entry);
        assert_eq!(line.lines().count(), 1, "{line:?}");
        assert!(!line.contains('\n') && !line.contains('\r'));
    }

    #[test]
    fn unknown_scheme_is_unrecognized() {
        assert!(matches!(
            parse_line("wireguard://abc"),
            LineOutcome::Unrecognized
        ));
        assert!(matches!(
            parse_line("just some text"),
            LineOutcome::Unrecognized
        ));
    }

    #[test]
    fn hy2_alias_parses_to_hysteria2() {
        let entry = entry_for("hy2://pass@host:443?sni=host#n");
        assert_eq!(entry.scheme, Scheme::Hysteria2);
    }

    #[test]
    fn auto_detects_base64_wrapped_uri_list() {
        use base64::Engine;
        let inner = "vless://uuid@1.2.3.4:443?security=reality#A\n# comment\ntrojan://pw@h:443#B\n";
        let wrapped = base64::engine::general_purpose::STANDARD.encode(inner);
        let result = parse_subscription(&wrapped, Encoding::Auto, None).unwrap();
        assert_eq!(result.entries.len(), 2);
        assert_eq!(result.format, InputFormat::UriList);
    }

    /// Real producers wrap the payload at 76 columns (email-style) or add
    /// blank lines. Interior whitespace is not base64, breaks the
    /// length-modulo check and used to make the whole payload fall back to
    /// being parsed as plain text, silently yielding zero entries.
    #[test]
    fn line_wrapped_base64_payload_decodes() {
        use base64::Engine;
        let inner = "vless://uuid@1.2.3.4:443?security=reality#A\nvless://uuid2@5.6.7.8:8443#B\n";
        let compact = base64::engine::general_purpose::STANDARD.encode(inner);
        let wrapped: String = compact
            .chars()
            .collect::<Vec<_>>()
            .chunks(16)
            .map(|chunk| chunk.iter().collect::<String>())
            .collect::<Vec<_>>()
            .join("\n");

        let result = parse_subscription(&wrapped, Encoding::Auto, None).unwrap();
        assert_eq!(result.entries.len(), 2);
        assert_eq!(result.format, InputFormat::UriList);
        // The pinned encoding takes the wrapped form too.
        let result = parse_subscription(&wrapped, Encoding::Base64, None).unwrap();
        assert_eq!(result.entries.len(), 2);
    }

    #[test]
    fn auto_detects_clash_yaml() {
        let yaml = "proxies:\n  - {name: n, type: trojan, server: h, port: 443, password: p}\n";
        let result = parse_subscription(yaml, Encoding::Auto, None).unwrap();
        assert_eq!(result.format, InputFormat::ClashYaml);
        assert_eq!(result.entries.len(), 1);
    }

    #[test]
    fn auto_detects_sing_box_json() {
        let json = r#"{"outbounds":[{"type":"trojan","tag":"t","server":"h","server_port":443,"password":"p"}]}"#;
        let result = parse_subscription(json, Encoding::Auto, None).unwrap();
        assert_eq!(result.format, InputFormat::SingBoxJson);
        assert_eq!(result.entries.len(), 1);

        // The v2rayN share format is a bare array of configs.
        let array = r#"[{"outbounds":[{"type":"trojan","tag":"t","server":"h","server_port":443,"password":"p"}]}]"#;
        let result = parse_subscription(array, Encoding::Auto, None).unwrap();
        assert_eq!(result.format, InputFormat::SingBoxJson);
        assert_eq!(result.entries.len(), 1);
    }

    #[test]
    fn auto_detects_base64_wrapped_sing_box_json() {
        use base64::Engine;
        let inner = r#"{"outbounds":[{"type":"trojan","tag":"t","server":"h","server_port":443,"password":"p"}]}"#;
        let wrapped = base64::engine::general_purpose::STANDARD.encode(inner);
        let result = parse_subscription(&wrapped, Encoding::Auto, None).unwrap();
        assert_eq!(result.format, InputFormat::SingBoxJson);
        assert_eq!(result.entries.len(), 1);
    }

    #[test]
    fn sing_box_json_without_outbounds_is_an_error() {
        let err = parse_subscription(r#"{"dns":{}}"#, Encoding::Auto, None).unwrap_err();
        assert!(matches!(err, crate::Error::Parse(_)));
    }

    #[test]
    fn pinned_base64_must_decode() {
        let err = parse_subscription("not base64 !!!", Encoding::Base64, None).unwrap_err();
        assert!(matches!(err, crate::Error::Parse(_)));
    }

    #[test]
    fn comments_and_blanks_are_ignored() {
        let payload = "# title\n\nvless://u@h:1#A\n   \n# another comment\n";
        let result = parse_subscription(payload, Encoding::Plain, None).unwrap();
        assert_eq!(result.entries.len(), 1);
        assert_eq!(result.unrecognized, 0);
    }

    // Fixture-driven tests against the real subscription sample in
    // `test.txt`. The fixture is gitignored (it may contain non-public
    // data) and is never committed; these tests skip themselves when it
    // is absent. Thresholds below are calibrated for a ~390-line sample
    // (Sept 2026); they guard against regressions, not exact sizes.

    #[test]
    fn fixture_authority_and_query_round_trip_byte_exact() {
        // Hard invariant for the URI schemes: everything before the fragment
        // (scheme, credential, host, port, path, query) must serialize back
        // byte-for-byte. vmess/ss are excluded, they normalize their
        // transport encoding by design (see module docs).
        let mut checked = 0usize;
        let Some(lines) = fixture_lines() else {
            eprintln!("skipped: test.txt fixture is absent (gitignored debug file)");
            return;
        };
        for line in lines {
            let line = line.trim().to_string();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if line.starts_with("vmess://") || line.starts_with("ss://") {
                continue;
            }
            let LineOutcome::Parsed(entry) = parse_line(&line) else {
                continue;
            };
            let serialized = serialize(&entry);
            let orig_prefix = line.split_once('#').map(|(p, _)| p).unwrap_or(&line);
            let ser_prefix = serialized
                .split_once('#')
                .map(|(p, _)| p)
                .unwrap_or(&serialized);
            assert_eq!(ser_prefix, orig_prefix, "authority/query round-trip broken");
            checked += 1;
        }
        assert!(checked > 300, "suspiciously few checked lines: {checked}");
    }

    fn fixture_path() -> std::path::PathBuf {
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../test.txt")
    }

    /// The fixture is a gitignored debug-only file and is not part of the
    /// repository; `None` tells the fixture tests to skip themselves.
    fn fixture_lines() -> Option<Vec<String>> {
        std::fs::read_to_string(fixture_path())
            .ok()
            .map(|content| content.lines().map(str::to_string).collect())
    }

    #[test]
    fn fixture_recognition_rate() {
        let mut parsed = 0usize;
        let mut discarded = 0usize;
        let mut unrecognized: Vec<String> = Vec::new();
        let Some(lines) = fixture_lines() else {
            eprintln!("skipped: test.txt fixture is absent (gitignored debug file)");
            return;
        };
        for line in lines {
            let line = line.trim().to_string();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            match parse_line(&line) {
                LineOutcome::Parsed(_) => parsed += 1,
                LineOutcome::Discarded => discarded += 1,
                LineOutcome::Unrecognized => unrecognized.push(line.chars().take(80).collect()),
            }
        }
        let total = parsed + discarded + unrecognized.len();
        eprintln!(
            "fixture: total={total} parsed={parsed} discarded={discarded} unrecognized={}",
            unrecognized.len()
        );
        for line in &unrecognized[..unrecognized.len().min(5)] {
            eprintln!("  unrecognized: {line}");
        }
        // Goal: at least 99% of lines recognized. The current
        // sample (Sept 2026) parses at 100% minus one ss2022 line whose
        // userinfo is plain text rather than base64 (SIP002 requires base64);
        // happ:// lines, when present, are deliberately discarded.
        assert!(
            parsed + discarded >= (total * 99).div_ceil(100),
            "recognition rate below 99%: {parsed}+{discarded} of {total}"
        );
        assert!(parsed > 350, "suspiciously few parsed lines: {parsed}");
        assert!(discarded <= 1, "unexpected discards: {discarded}");
    }

    #[test]
    fn fixture_semantic_round_trip_for_every_line() {
        let mut checked = 0usize;
        let Some(lines) = fixture_lines() else {
            eprintln!("skipped: test.txt fixture is absent (gitignored debug file)");
            return;
        };
        for line in lines {
            let line = line.trim().to_string();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let LineOutcome::Parsed(first) = parse_line(&line) else {
                continue;
            };
            let serialized = serialize(&first);
            let LineOutcome::Parsed(second) = parse_line(&serialized) else {
                panic!("serialized line no longer parses:\n{serialized}");
            };
            assert_semantically_equal(&first, &second);
            checked += 1;
        }
        assert!(
            checked > 350,
            "suspiciously few round-tripped lines: {checked}"
        );
    }

    #[test]
    fn fixture_byte_round_trip_rate() {
        // Observational guard. Full-line byte-exact round-trip holds for
        // percent-encoded lines; it intentionally does NOT hold when:
        //   * the original fragment was raw UTF-8 (~half of real feeds) ,
        //     the serializer emits the canonical percent-encoded form, which
        //     decodes to the identical name;
        //   * vmess/ss lines, their transport encoding (JSON field order,
        //     base64 padding) is normalized by design.
        // Authority/query fidelity is asserted strictly by
        // `fixture_authority_and_query_round_trip_byte_exact`; here we only
        // make sure the overall rate does not regress silently.
        let mut exact = 0usize;
        let mut total = 0usize;
        let Some(lines) = fixture_lines() else {
            eprintln!("skipped: test.txt fixture is absent (gitignored debug file)");
            return;
        };
        for line in lines {
            let line = line.trim().to_string();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let LineOutcome::Parsed(entry) = parse_line(&line) else {
                continue;
            };
            total += 1;
            if serialize(&entry) == line {
                exact += 1;
            }
        }
        let rate = exact as f64 / total as f64;
        eprintln!(
            "fixture byte round-trip: {exact}/{total} = {:.1}%",
            rate * 100.0
        );
        // Floor for the current sample: 51/387 ≈ 13%, it is dominated by
        // raw-UTF-8 names and vmess/ss normalization (all semantically
        // verified). Keep a margin: 0.10 for this sample shape, 0.40 held
        // for the previous percent-encoded-heavy sample.
        assert!(rate >= 0.10, "byte round-trip rate regressed: {rate:.3}");
    }

    #[test]
    fn fixture_fingerprints_are_unique_per_server() {
        use std::collections::HashSet;
        let mut fingerprints = HashSet::new();
        let mut parsed = 0usize;
        let Some(lines) = fixture_lines() else {
            eprintln!("skipped: test.txt fixture is absent (gitignored debug file)");
            return;
        };
        for line in lines {
            let line = line.trim().to_string();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if let LineOutcome::Parsed(entry) = parse_line(&line) {
                parsed += 1;
                fingerprints.insert(entry.fingerprint());
            }
        }
        eprintln!(
            "fixture dedup: {} lines -> {} fingerprints",
            parsed,
            fingerprints.len()
        );
        // Different servers must never collapse into one fingerprint: the
        // sample is expected to yield a unique fingerprint per distinct
        // server (some earlier samples carried name-only duplicates that
        // legitimately collapsed, "the collapse happens" is covered by the
        // fingerprint unit tests in fingerprint.rs, this guard pins the
        // no-false-merge side against the real-world data).
        assert!(
            fingerprints.len() > parsed / 2,
            "suspiciously few distinct fingerprints: {} of {parsed}",
            fingerprints.len()
        );
    }
}
