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
        query_pairs: query.map(parse_query).unwrap_or_default(),
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

/// Parse a raw query string into ordered parameters.
///
/// Pairs are split on the first `=` only, so values may contain further `=`
/// and `?`. Empty segments (a leading, trailing or doubled `&`) are kept as
/// empty-key params so serialization can reproduce them byte-for-byte.
/// Values keep their percent-encoding untouched.
pub fn parse_query(query: &str) -> Vec<Param> {
    query
        .split('&')
        .map(|pair| match pair.split_once('=') {
            Some((key, value)) => Param {
                key: key.to_string(),
                value: value.to_string(),
                known: false,
            },
            None => Param {
                key: pair.to_string(),
                value: String::new(),
                known: false,
            },
        })
        .collect()
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
    out.push_str(&entry.host);
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

    #[test]
    fn rejects_bad_ports() {
        assert!(parse_hostport("host:0x1f").is_err());
        assert!(parse_hostport("host:").is_err());
        assert!(parse_hostport("host").is_err());
        assert!(parse_hostport("").is_err());
    }

    #[test]
    fn empty_query_values_are_kept() {
        let pairs = parse_query("security=&encryption=none&headerType=");
        assert_eq!(pairs.len(), 3);
        assert_eq!(pairs[0].value, "");
        assert_eq!(pairs[1].value, "none");
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
