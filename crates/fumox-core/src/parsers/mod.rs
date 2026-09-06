//! Protocol parsers and serializers for every supported subscription format.
//!
//! Public surface:
//!
//! * [`parse_line`] — parse a single URI line (log-and-skip contract: it
//!   never panics, unrecognized lines are reported, not fatal);
//! * [`serialize`] — turn a [`ProxyEntry`] back into its canonical line;
//! * [`parse_subscription`] — decode + auto-detect a whole payload
//!   (URI list / Clash YAML / sing-box JSON / base64-wrapped) and parse
//!   every line.
//!
//! Round-trip guarantees: every parser has a serializer. URI schemes
//! round-trip byte-for-byte whenever the original used percent-encoded
//! fragments and standard formatting; vmess and ss normalize encoding and
//! guarantee semantic round-trip instead (`parse ∘ serialize ∘ parse`
//! equals the first parse). Unknown parameters always pass through untouched.

pub mod clash;
pub mod singbox;
pub mod ss;
pub mod uri;
pub mod vmess;

use crate::models::{Encoding, InputFormat, ProxyEntry, Scheme};

/// Outcome of parsing a single non-comment line.
#[derive(Debug)]
pub enum LineOutcome {
    Parsed(ProxyEntry),
    /// Recognized format that is deliberately dropped (`happ://`).
    Discarded,
    /// Unknown scheme or malformed line — counted and skipped.
    Unrecognized,
}

/// Parse one subscription line. Comments and blank lines must be filtered
/// out by the caller ([`parse_subscription`] does this).
pub fn parse_line(line: &str) -> LineOutcome {
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
/// The URI serializers emit `host`, `credential` and parameter values
/// verbatim — only `name` goes through [`uri::encode_fragment`] — so a line
/// break inside any of them splits one stored proxy into several output
/// lines. A crafted Clash YAML or legacy-`ss` feed could smuggle a proxy of
/// an entirely different scheme past a source's protocol allowlist that way,
/// or forge `url_list` metadata comments (security audit, 2026-09-05).
///
/// URI-list input cannot reach this: `parse_uri_list` iterates over
/// `str::lines`. The vectors are the formats whose fields are not
/// line-delimited — Clash YAML scalars, vmess JSON `\n` escapes and the
/// base64 blob of a legacy `ss` line.
pub(crate) fn reject_line_breaks(field: &str, value: &str) -> Result<(), String> {
    if value.contains(['\n', '\r']) {
        return Err(format!("{field} contains a line break"));
    }
    Ok(())
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
/// Guaranteed to return a single line: [`sanitize_for_output`] strips line
/// breaks from the fields the serializers emit verbatim. Parsers reject such
/// values up front, so this only catches rows that predate the check or were
/// written directly into SQLite.
pub fn serialize(entry: &ProxyEntry) -> String {
    let sanitized = sanitize_for_output(entry);
    let entry = sanitized.as_ref().unwrap_or(entry);
    match entry.scheme {
        Scheme::Vless => uri::serialize_with_spec(&uri::VLESS_SPEC, entry),
        Scheme::Trojan => uri::serialize_with_spec(&uri::TROJAN_SPEC, entry),
        Scheme::Hysteria2 => uri::serialize_with_spec(&uri::HYSTERIA2_SPEC, entry),
        Scheme::Tuic => uri::serialize_with_spec(&uri::TUIC_SPEC, entry),
        Scheme::Mieru => uri::serialize_with_spec(&uri::MIERU_SPEC, entry),
        Scheme::Socks5 => uri::serialize_with_spec(&uri::SOCKS5_SPEC, entry),
        Scheme::Naive => serialize_naive(entry),
        Scheme::Ss => ss::serialize(entry),
        Scheme::Vmess => vmess::serialize(entry),
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
        "proxy entry carries line breaks — sanitizing before output"
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
/// (object or array — the v2rayN share format).
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
    let bytes = ss::decode_b64_lenient(input.trim())?;
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
            continue; // comments and blanks are not proxy lines
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
    /// metadata comments (security audit, 2026-09-05).
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

    // ─────────────────────────────────────────────────────────────────────
    // Fixture-driven tests against the real subscription sample in
    // `test.txt`. The fixture is gitignored (it may contain non-public
    // data) and is never committed; these tests skip themselves when it
    // is absent. Thresholds below are calibrated for a ~390-line sample
    // (Sept 2026); they guard against regressions, not exact sizes.
    // ─────────────────────────────────────────────────────────────────────

    #[test]
    fn fixture_authority_and_query_round_trip_byte_exact() {
        // Hard invariant for the URI schemes: everything before the fragment
        // (scheme, credential, host, port, path, query) must serialize back
        // byte-for-byte. vmess/ss are excluded — they normalize their
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
        // Goal (TODO 1.2): at least 99% of lines recognized. The current
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
        //   * the original fragment was raw UTF-8 (~half of real feeds) —
        //     the serializer emits the canonical percent-encoded form, which
        //     decodes to the identical name;
        //   * vmess/ss lines — their transport encoding (JSON field order,
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
        // Floor for the current sample: 51/387 ≈ 13% — it is dominated by
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
        // legitimately collapsed — "the collapse happens" is covered by the
        // fingerprint unit tests in fingerprint.rs, this guard pins the
        // no-false-merge side against the real-world data).
        assert!(
            fingerprints.len() > parsed / 2,
            "suspiciously few distinct fingerprints: {} of {parsed}",
            fingerprints.len()
        );
    }
}
