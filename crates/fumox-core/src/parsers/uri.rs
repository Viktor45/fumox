//! Shared URI mechanics for the line-oriented proxy schemes
//! (vless, trojan, hysteria2, tuic, mieru, socks5, naive).
//!
//! Subscription URIs in the wild routinely violate RFC 3986 — raw UTF-8
//! fragments, raw `?` inside parameter values, mixed-case keys, junk
//! parameters — so splitting is done by hand with tolerant rules instead of a
//! standards-strict URL parser:
//!
//! * the name is everything after the **first** `#` (it may contain `?`/`#`);
//! * the query is everything after the **first** `?` of the remainder
//!   (values may contain further raw `?`);
//! * the userinfo ends at the **last** `@` (base64 userinfo of `ss:` may
//!   contain `/`);
//! * parameter values are stored exactly as they appear (still
//!   percent-encoded), so serialization can reproduce the original bytes.

use crate::models::{Param, ProxyEntry, Scheme};

/// Scheme-specific behaviour for the generic URI parser/serializer.
pub struct UriSchemeSpec {
    pub scheme: Scheme,
    /// URI prefix emitted on serialization, e.g. `"vless://"`.
    pub prefix: &'static str,
    /// Lower-cased keys recognized as defined parameters of this scheme.
    /// Anything else is kept as an unknown pass-through parameter.
    pub known_keys: &'static [&'static str],
    /// Whether a missing credential makes the line invalid.
    pub credential_required: bool,
}

pub static VLESS_SPEC: UriSchemeSpec = UriSchemeSpec {
    scheme: Scheme::Vless,
    prefix: "vless://",
    known_keys: &[
        "security",
        "encryption",
        "type",
        "headertype",
        "path",
        "host",
        "mode",
        "sni",
        "fp",
        "pbk",
        "sid",
        "spx",
        "flow",
        "alpn",
        "servicename",
        "congestioncontrol",
        "packetencoding",
        "allowinsecure",
        "insecure",
        "authority",
    ],
    credential_required: true,
};

pub static TROJAN_SPEC: UriSchemeSpec = UriSchemeSpec {
    scheme: Scheme::Trojan,
    prefix: "trojan://",
    known_keys: &[
        "security",
        "type",
        "headertype",
        "path",
        "host",
        "sni",
        "fp",
        "pbk",
        "sid",
        "flow",
        "alpn",
        "encryption",
        "allowinsecure",
        "insecure",
    ],
    credential_required: true,
};

pub static HYSTERIA2_SPEC: UriSchemeSpec = UriSchemeSpec {
    scheme: Scheme::Hysteria2,
    prefix: "hysteria2://",
    known_keys: &[
        "sni",
        "insecure",
        "allowinsecure",
        "obfs",
        "obfs-password",
        "alpn",
        "upmbps",
        "downmbps",
        "pinsha256",
    ],
    credential_required: true,
};

pub static TUIC_SPEC: UriSchemeSpec = UriSchemeSpec {
    scheme: Scheme::Tuic,
    prefix: "tuic://",
    known_keys: &[
        "congestion_control",
        "sni",
        "alpn",
        "udp_relay_mode",
        "disable_sni",
    ],
    credential_required: true,
};

/// Render a host for a `host:port` context: an IPv6 literal must be
/// bracketed (`[2001:db8::1]:443`) or the concatenation is not a parseable
/// `host:port` at all — both directions of the round-trip and every
/// consumer of the subscription output rely on that. `parse_hostport`
/// strips the brackets on input, so round-tripping stays byte-stable for
/// bracketed feeds too. Everything else (hostnames, IPv4) passes through.
pub(crate) fn host_for_uri(host: &str) -> String {
    if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]")
    } else {
        host.to_string()
    }
}

pub static MIERU_SPEC: UriSchemeSpec = UriSchemeSpec {
    scheme: Scheme::Mieru,
    prefix: "mieru://",
    known_keys: &["sni"],
    credential_required: true,
};

pub static SOCKS5_SPEC: UriSchemeSpec = UriSchemeSpec {
    scheme: Scheme::Socks5,
    prefix: "socks5://",
    known_keys: &[],
    // socks5 lines without authentication do exist in the wild.
    credential_required: false,
};

pub static NAIVE_SPEC: UriSchemeSpec = UriSchemeSpec {
    scheme: Scheme::Naive,
    prefix: "naive+https://",
    known_keys: &["sni", "naive_transport"],
    credential_required: true,
};

/// Decomposed URI with every component kept verbatim.
#[derive(Debug)]
pub struct UriParts {
    /// Raw (still percent-encoded) userinfo, if present.
    pub userinfo: Option<String>,
    pub host: String,
    pub port: u16,
    /// Raw path segment between the authority and the query ("" or "/...").
    pub raw_path: String,
    /// Query parameters in original order, raw values, `known` unset.
    pub query_pairs: Vec<Param>,
    /// Raw fragment (name), not percent-decoded.
    pub fragment: Option<String>,
}

/// Split `scheme://rest` into components using the tolerant rules described
/// in the module docs.
pub fn split_uri(rest: &str) -> Result<UriParts, String> {
    let (before_frag, fragment) = split_fragment(rest);
    let (before_query, query) = split_query(before_frag);
    let (userinfo, hostport_path) = split_userinfo(before_query);
    let (hostport, raw_path) = split_path(hostport_path);
    let (host, port) = parse_hostport(hostport)?;
    Ok(UriParts {
        userinfo: userinfo.map(str::to_string),
        host,
        port,
        raw_path: raw_path.to_string(),
        query_pairs: query.map(parse_query).transpose()?.unwrap_or_default(),
        fragment: fragment.map(str::to_string),
    })
}

/// Everything after the first `#` is the fragment (name).
pub fn split_fragment(s: &str) -> (&str, Option<&str>) {
    match s.find('#') {
        Some(i) => (&s[..i], Some(&s[i + 1..])),
        None => (s, None),
    }
}

/// Everything after the first `?` is the query.
pub fn split_query(s: &str) -> (&str, Option<&str>) {
    match s.find('?') {
        Some(i) => (&s[..i], Some(&s[i + 1..])),
        None => (s, None),
    }
}

/// The userinfo ends at the last `@`; anything before it may legally contain
/// `/` (ss base64), so the path is split only after this step.
pub fn split_userinfo(s: &str) -> (Option<&str>, &str) {
    match s.rfind('@') {
        Some(i) => (Some(&s[..i]), &s[i + 1..]),
        None => (None, s),
    }
}

/// Split off the (raw) path at the first `/`.
pub fn split_path(s: &str) -> (&str, &str) {
    match s.find('/') {
        Some(i) => (&s[..i], &s[i..]),
        None => (s, ""),
    }
}

/// Parse `host:port`, accepting bracketed IPv6 literals. The host is kept
/// verbatim; case normalization happens at fingerprint time.
pub fn parse_hostport(s: &str) -> Result<(String, u16), String> {
    if s.is_empty() {
        return Err("empty host".to_string());
    }
    let (host, port_str) = if let Some(stripped) = s.strip_prefix('[') {
        let close = stripped
            .find(']')
            .ok_or_else(|| "unclosed IPv6 bracket".to_string())?;
        let host = stripped[..close].to_string();
        let after = &stripped[close + 1..];
        let port = after
            .strip_prefix(':')
            .ok_or_else(|| "expected `:port` after IPv6 literal".to_string())?;
        (host, port)
    } else {
        let (host, port) = s
            .rsplit_once(':')
            .ok_or_else(|| "missing port in host:port".to_string())?;
        (host.to_string(), port)
    };
    if host.is_empty() {
        return Err("empty host".to_string());
    }
    let port: u16 = port_str
        .parse()
        .map_err(|_| format!("invalid port: {port_str:?}"))?;
    Ok((host, port))
}

/// Upper bound on query parameters per line.
///
/// One `Param` costs ~56 bytes plus two heap allocations, and a query is
/// split on every `&`, so a single 10 MiB line of `?&&&&…` expanded into
/// ~1 GB of resident memory — a process-wide OOM, not a per-task failure
/// (security audit, 2026-09-05). Real feeds carry at most a dozen
/// parameters; a line past this cap is malformed, and the caller's
/// log-and-skip path drops it.
pub const MAX_QUERY_PARAMS: usize = 256;

/// Upper bound on one parameter key or value, in bytes.
///
/// The count cap alone still let a 10 MiB single value ride one line into
/// the DB twice (`raw_line` plus the params JSON, ~20 MiB per row,
/// security audit v2, 2026-09-09, F13). Real proxy parameters are tens of
/// bytes; anything past this cap is malformed.
pub const MAX_PARAM_BYTES: usize = 8 * 1024;

/// Upper bound on one subscription line, in bytes.
///
/// `raw_line` is persisted verbatim onto every stored row, so an oversized
/// line is a storage bomb, not just a parse cost — a full 10 MiB fetch of a
/// single line became ~20 MiB of SQLite data per row per refresh (security
/// audit v2, 2026-09-09, F13). Legitimate proxy lines are well under 4 KiB.
pub const MAX_LINE_BYTES: usize = 64 * 1024;

/// Parse a raw query string into ordered parameters.
///
/// Pairs are split on the first `=` only, so values may contain further `=`
/// and `?`. Empty segments (a leading, trailing or doubled `&`) are kept as
/// empty-key params so serialization can reproduce them byte-for-byte.
/// Values keep their percent-encoding untouched.
///
/// Fails when the query exceeds [`MAX_QUERY_PARAMS`] or any single key or
/// value exceeds [`MAX_PARAM_BYTES`]; truncating instead would silently
/// break the round-trip guarantee.
pub fn parse_query(query: &str) -> Result<Vec<Param>, String> {
    // Count before allocating: `split` is lazy, so this never materializes
    // the oversized parameter list.
    let count = query.split('&').count();
    if count > MAX_QUERY_PARAMS {
        return Err(format!(
            "query has {count} parameters, over the {MAX_QUERY_PARAMS} cap"
        ));
    }
    let mut params = Vec::with_capacity(count);
    for pair in query.split('&') {
        // Size caps run before any allocation for the pair (F13).
        match pair.split_once('=') {
            Some((key, value)) => {
                check_param_size(key, value)?;
                params.push(Param {
                    key: key.to_string(),
                    value: value.to_string(),
                    known: false,
                });
            }
            None => {
                check_param_size(pair, "")?;
                params.push(Param {
                    key: pair.to_string(),
                    value: String::new(),
                    known: false,
                });
            }
        }
    }
    Ok(params)
}

/// Enforce [`MAX_PARAM_BYTES`] on one key/value pair.
fn check_param_size(key: &str, value: &str) -> Result<(), String> {
    if key.len() > MAX_PARAM_BYTES || value.len() > MAX_PARAM_BYTES {
        return Err(format!(
            "parameter over the {MAX_PARAM_BYTES}-byte cap (key {} bytes, value {} bytes)",
            key.len(),
            value.len()
        ));
    }
    Ok(())
}

/// Serialize ordered parameters back into a query string (`k=v&k=v`).
/// Empty-key params serialize as empty segments, reproducing the occasional
/// `?&k=v` / `k=v&` quirks of real feeds.
pub fn serialize_query(params: &[Param]) -> String {
    params
        .iter()
        .map(|p| {
            if p.key.is_empty() && p.value.is_empty() {
                String::new()
            } else {
                format!("{}={}", p.key, p.value)
            }
        })
        .collect::<Vec<_>>()
        .join("&")
}

/// Lenient percent-decoding: valid `%XX` escapes are decoded, anything else
/// (including raw UTF-8 and stray `%`) passes through unchanged. Invalid
/// UTF-8 sequences are replaced lossily — a display name is never worth
/// failing the whole line.
pub fn percent_decode(s: &str) -> String {
    percent_encoding::percent_decode_str(s)
        .decode_utf8_lossy()
        .into_owned()
}

/// Percent-encode a display name for use as a URI fragment.
///
/// Everything except the RFC 3986 unreserved set (`A-Za-z0-9-._~`) is
/// encoded, UTF-8 bytes included, with upper-case hex — this matches the
/// dominant producer style in real feeds (`encodeURIComponent`-like), so
/// already-encoded names round-trip byte-for-byte.
pub fn encode_fragment(name: &str) -> String {
    let mut out = String::with_capacity(name.len() * 3);
    for &byte in name.as_bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            out.push(byte as char);
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

/// Mark parameters whose (lower-cased) key is defined for the scheme.
pub fn mark_known(params: &mut [Param], known_keys: &[&str]) {
    for param in params.iter_mut() {
        let lower = param.key.to_ascii_lowercase();
        param.known = known_keys.contains(&lower.as_str());
    }
}

/// Generic parser for the `userinfo@host:port[?query][#name]` family.
pub fn parse_with_spec(
    spec: &UriSchemeSpec,
    rest: &str,
    raw_line: &str,
) -> Result<ProxyEntry, String> {
    let parts = split_uri(rest)?;
    let credential = match parts.userinfo {
        Some(userinfo) => userinfo,
        None if spec.credential_required => {
            return Err("missing credential".to_string());
        }
        None => String::new(),
    };
    let mut params = parts.query_pairs;
    mark_known(&mut params, spec.known_keys);
    Ok(ProxyEntry {
        scheme: spec.scheme,
        name: parts
            .fragment
            .map(|f| percent_decode(&f))
            .unwrap_or_default(),
        host: parts.host,
        port: parts.port,
        credential,
        params,
        raw_path: parts.raw_path,
        raw_line: raw_line.to_string(),
    })
}

/// Generic serializer for the `userinfo@host:port[?query][#name]` family.
///
/// The credential and parameter values are emitted exactly as stored (still
/// percent-encoded); the name is re-encoded with [`encode_fragment`].
pub fn serialize_with_spec(spec: &UriSchemeSpec, entry: &ProxyEntry) -> String {
    let mut out = String::with_capacity(128);
    out.push_str(spec.prefix);
    if !entry.credential.is_empty() {
        out.push_str(&entry.credential);
        out.push('@');
    }
    out.push_str(&host_for_uri(&entry.host));
    out.push(':');
    out.push_str(&entry.port.to_string());
    out.push_str(&entry.raw_path);
    if !entry.params.is_empty() {
        out.push('?');
        out.push_str(&serialize_query(&entry.params));
    }
    if !entry.name.is_empty() {
        out.push('#');
        out.push_str(&encode_fragment(&entry.name));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splits_fragment_before_query() {
        // The name may contain `?`; the query may not contain `#`.
        let parts = split_uri("uuid@host:443?a=b#name?with?marks").unwrap();
        assert_eq!(parts.fragment.as_deref(), Some("name?with?marks"));
        assert_eq!(parts.query_pairs.len(), 1);
        assert_eq!(parts.query_pairs[0].key, "a");
    }

    #[test]
    fn raw_question_mark_survives_inside_param_value() {
        let parts = split_uri("u@h:1?path=/websocket?ed=2560&sni=x").unwrap();
        assert_eq!(parts.query_pairs[0].key, "path");
        assert_eq!(parts.query_pairs[0].value, "/websocket?ed=2560");
        assert_eq!(parts.query_pairs[1].key, "sni");
    }

    #[test]
    fn userinfo_split_at_last_at_sign() {
        // base64 userinfo may contain `/` — the path split must not trigger.
        let parts = split_uri("YWVz/x@host:8388/").unwrap();
        assert_eq!(parts.userinfo.as_deref(), Some("YWVz/x"));
        assert_eq!(parts.host, "host");
        assert_eq!(parts.port, 8388);
        assert_eq!(parts.raw_path, "/");
    }

    #[test]
    fn parses_ipv6_host() {
        let (host, port) = parse_hostport("[2001:db8::1]:8443").unwrap();
        assert_eq!(host, "2001:db8::1");
        assert_eq!(port, 8443);
    }

    /// The serializer must bracket an IPv6 literal in the `host:port`
    /// context: the unbracketed `2001:db8::1:8443` is not a parseable
    /// `host:port` at all, so the subscription output used to be broken for
    /// every IPv6 proxy (regression fixed 2026-09-11).
    #[test]
    fn serializes_ipv6_host_bracketed_and_round_trips() {
        let entry = ProxyEntry {
            scheme: Scheme::Vless,
            name: "v6".into(),
            host: "2001:db8::1".into(),
            port: 8443,
            credential: "uuid".into(),
            params: vec![Param {
                key: "security".into(),
                value: "tls".into(),
                known: true,
            }],
            raw_path: String::new(),
            raw_line: String::new(),
        };
        let out = serialize_with_spec(&VLESS_SPEC, &entry);
        assert!(out.contains("@[2001:db8::1]:8443"), "{out}");
        // Bracketed input parses back to the same bare-literal host.
        let parsed =
            parse_with_spec(&VLESS_SPEC, out.strip_prefix("vless://").unwrap(), &out).unwrap();
        assert_eq!(parsed.host, "2001:db8::1");
        assert_eq!(parsed.port, 8443);
        assert_eq!(parsed.credential, "uuid");
        assert_eq!(parsed.name, "v6");
    }

    #[test]
    fn rejects_bad_ports() {
        assert!(parse_hostport("host:0x1f").is_err());
        assert!(parse_hostport("host:").is_err());
        assert!(parse_hostport("host").is_err());
        assert!(parse_hostport("").is_err());
    }

    #[test]
    fn empty_query_values_are_kept() {
        let pairs = parse_query("security=&encryption=none&headerType=").unwrap();
        assert_eq!(pairs.len(), 3);
        assert_eq!(pairs[0].value, "");
        assert_eq!(pairs[1].value, "none");
    }

    /// A 10 MiB line of `&` separators expanded into ~1 GB of `Param`s — a
    /// process-wide OOM (security audit, 2026-09-05).
    #[test]
    fn oversized_query_is_rejected_not_truncated() {
        let ok = "a=1&".repeat(MAX_QUERY_PARAMS - 1);
        assert!(parse_query(ok.trim_end_matches('&')).is_ok());

        let too_many = "&".repeat(MAX_QUERY_PARAMS);
        let err = parse_query(&too_many).unwrap_err();
        assert!(err.contains("over the"), "{err}");

        // The whole line is skipped rather than silently shortened.
        let line = format!("vless://u@h.example.com:443?{too_many}");
        assert!(matches!(
            super::super::parse_line(&line),
            super::super::LineOutcome::Unrecognized
        ));
    }

    /// One multi-megabyte parameter value rode a single line into the DB
    /// twice (`raw_line` + params JSON, ~20 MiB per row, security audit v2,
    /// 2026-09-09, F13) — the count cap alone never saw it.
    #[test]
    fn oversized_param_value_is_rejected() {
        let huge = "x".repeat(MAX_PARAM_BYTES + 1);
        let err = parse_query(&format!("type={huge}")).unwrap_err();
        assert!(err.contains("over the"), "{err}");
        // And the whole line is skipped, not stored truncated.
        let line = format!("vless://u@h.example.com:443?type={huge}");
        assert!(matches!(
            super::super::parse_line(&line),
            super::super::LineOutcome::Unrecognized
        ));
        // Just under the cap passes.
        let ok = "x".repeat(MAX_PARAM_BYTES);
        assert!(parse_query(&format!("type={ok}")).is_ok());
    }

    /// `raw_line` is persisted verbatim onto every stored row, so an
    /// oversized line is a storage bomb (security audit v2, 2026-09-09,
    /// F13): a 10 MiB single-line fetch became ~20 MiB of SQLite data per
    /// row per refresh.
    #[test]
    fn oversized_line_is_skipped_entirely() {
        // One huge fragment keeps the line under the param-value cap but
        // over the line cap — `parse_line` must drop it before anything is
        // stored.
        let name = "x".repeat(MAX_LINE_BYTES + 1);
        let line = format!("vless://u@h.example.com:443?security=reality#{name}");
        assert!(line.len() > MAX_LINE_BYTES);
        assert!(matches!(
            super::super::parse_line(&line),
            super::super::LineOutcome::Unrecognized
        ));

        // A normal-length line still parses.
        let ok = "vless://u@h.example.com:443?security=reality#node";
        assert!(matches!(
            super::super::parse_line(ok),
            super::super::LineOutcome::Parsed(_)
        ));
    }

    #[test]
    fn percent_decode_is_lenient() {
        assert_eq!(percent_decode("%F0%9F%8C%90%20World"), "🌐 World");
        // Invalid escapes and raw UTF-8 pass through unchanged.
        assert_eq!(percent_decode("50%off"), "50%off");
        assert_eq!(percent_decode("привет"), "привет");
    }

    #[test]
    fn encode_fragment_keeps_unreserved_set() {
        assert_eq!(
            encode_fragment("🇩🇪 DE-1 | [BL]"),
            "%F0%9F%87%A9%F0%9F%87%AA%20DE-1%20%7C%20%5BBL%5D"
        );
        assert_eq!(encode_fragment("a-z._~09"), "a-z._~09");
    }

    #[test]
    fn vless_round_trip_is_byte_exact_for_encoded_names() {
        let line = "vless://3e4d70e5@45.144.31.56:40004?encryption=none&flow=xtls-rprx-vision&pbk=vT4j#%F0%9F%87%A9%F0%9F%87%AA%20DE";
        let rest = line.strip_prefix("vless://").unwrap();
        let entry = parse_with_spec(&VLESS_SPEC, rest, line).unwrap();
        assert_eq!(entry.name, "🇩🇪 DE");
        assert_eq!(entry.param("pbk"), Some("vT4j"));
        assert_eq!(serialize_with_spec(&VLESS_SPEC, &entry), line);
    }

    #[test]
    fn socks5_without_credential_is_accepted() {
        let entry = parse_with_spec(
            &SOCKS5_SPEC,
            "72.195.34.35:27360/#name",
            "socks5://72.195.34.35:27360/#name",
        )
        .unwrap();
        assert_eq!(entry.credential, "");
        assert_eq!(entry.raw_path, "/");
        assert_eq!(entry.name, "name");
    }

    #[test]
    fn unknown_params_are_flagged_but_preserved() {
        let entry = parse_with_spec(
            &VLESS_SPEC,
            "u@h:443?security=reality&telegram=%40spam&burmalda=x",
            "",
        )
        .unwrap();
        assert!(entry.params[0].known);
        assert!(!entry.params[1].known);
        assert_eq!(entry.params[1].value, "%40spam");
        let unknown = entry.unknown_params_json();
        assert_eq!(unknown.get("telegram").unwrap(), "%40spam");
    }
}
