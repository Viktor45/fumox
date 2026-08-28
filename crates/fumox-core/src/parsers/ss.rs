//! Shadowsocks parser/serializer.
//!
//! Two line formats exist in the wild:
//!
//! * **SIP002** — `ss://base64(method:password)@host:port[/?query][#name]`;
//! * **legacy** — `ss://base64(method:password@host:port)[#name]`, where the
//!   whole server definition is inside the base64 blob.
//!
//! The credential is stored decoded (`method:password`): it is the semantic
//! identity used by the fingerprint, while base64 is only transport encoding.
//! Consequently ss round-trip is semantic (padding of the re-encoded blob
//! may differ), unlike the byte-exact URI schemes.
//!
//! Query parameters on ss lines (`security=none&headerType=…`) are foreign
//! Xray-isms copied from vless templates; they are kept as unknown
//! pass-through parameters so nothing is lost on re-serialization.

use crate::models::{ProxyEntry, Scheme};
use base64::Engine;

use super::uri::{
    encode_fragment, parse_hostport, parse_query, percent_decode, serialize_query, split_fragment,
    split_path, split_query,
};

/// Parse the part of an ss line that follows `ss://`.
pub fn parse(rest: &str, raw_line: &str) -> Result<ProxyEntry, String> {
    let (before_frag, fragment) = split_fragment(rest);
    let (before_query, query) = split_query(before_frag);

    let (credential, host, port, raw_path) = if before_query.contains('@') {
        parse_sip002(before_query)?
    } else {
        parse_legacy(before_query)?
    };

    let mut params = query.map(parse_query).unwrap_or_default();
    super::uri::mark_known(&mut params, &[]);

    Ok(ProxyEntry {
        scheme: Scheme::Ss,
        name: fragment.map(percent_decode).unwrap_or_default(),
        host,
        port,
        credential,
        params,
        raw_path,
        raw_line: raw_line.to_string(),
    })
}

/// SIP002: `base64(method:password)@host:port[/path]`.
fn parse_sip002(before_query: &str) -> Result<(String, String, u16, String), String> {
    let (userinfo, hostport_path) = match before_query.rfind('@') {
        Some(i) => (&before_query[..i], &before_query[i + 1..]),
        None => return Err("ss: missing @".to_string()),
    };
    let decoded = decode_b64_lenient(userinfo).ok_or("ss: invalid base64 userinfo")?;
    let credential =
        String::from_utf8(decoded).map_err(|_| "ss: non-UTF-8 userinfo".to_string())?;
    if !credential.contains(':') {
        return Err("ss: userinfo is not method:password".to_string());
    }
    let (hostport, raw_path) = split_path(hostport_path);
    let (host, port) = parse_hostport(hostport)?;
    Ok((credential, host, port, raw_path.to_string()))
}

/// Legacy: the whole `method:password@host:port` is base64-encoded.
fn parse_legacy(before_query: &str) -> Result<(String, String, u16, String), String> {
    let decoded = decode_b64_lenient(before_query).ok_or("ss: invalid base64 in legacy URI")?;
    let decoded =
        String::from_utf8(decoded).map_err(|_| "ss: non-UTF-8 legacy payload".to_string())?;
    let (credential, hostport) = match decoded.rfind('@') {
        Some(i) => (&decoded[..i], &decoded[i + 1..]),
        None => return Err("ss: legacy payload has no @".to_string()),
    };
    if !credential.contains(':') {
        return Err("ss: legacy payload is not method:password@host:port".to_string());
    }
    let (host, port) = parse_hostport(hostport)?;
    Ok((credential.to_string(), host, port, String::new()))
}

/// Serialize back to the SIP002 form with unpadded standard base64 — the
/// dominant style in real feeds.
pub fn serialize(entry: &ProxyEntry) -> String {
    let blob = base64::engine::general_purpose::STANDARD_NO_PAD.encode(entry.credential.as_bytes());
    let mut out = String::with_capacity(96);
    out.push_str("ss://");
    out.push_str(&blob);
    out.push('@');
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

/// Lenient base64 decoder: accepts both standard and URL-safe alphabets,
/// with or without padding. Returns `None` on invalid input.
pub fn decode_b64_lenient(input: &str) -> Option<Vec<u8>> {
    if input.is_empty() {
        return None;
    }
    // Map the URL-safe alphabet onto the standard one.
    let normalized: String = input
        .chars()
        .map(|c| match c {
            '-' => '+',
            '_' => '/',
            c => c,
        })
        .collect();
    let padded = match normalized.len() % 4 {
        2 => format!("{normalized}=="),
        3 => format!("{normalized}="),
        0 => normalized,
        _ => return None, // length % 4 == 1 is never valid base64
    };
    base64::engine::general_purpose::STANDARD
        .decode(padded.as_bytes())
        .ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_sip002_without_padding() {
        let line = "ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTo1Zi1pOG9WcDhVTTZqWEpoZ1N2SVJ3@64.49.15.51:842/?security=none&headerType=none&type=tcp#Name";
        let entry = parse(line.strip_prefix("ss://").unwrap(), line).unwrap();
        assert_eq!(
            entry.credential,
            "chacha20-ietf-poly1305:5f-i8oVp8UM6jXJhgSvIRw"
        );
        assert_eq!(entry.host, "64.49.15.51");
        assert_eq!(entry.port, 842);
        assert_eq!(entry.raw_path, "/");
        // Foreign Xray parameters survive as unknown pass-through.
        assert_eq!(entry.params.len(), 3);
        assert!(entry.params.iter().all(|p| !p.known));
        assert_eq!(entry.name, "Name");
    }

    #[test]
    fn parses_padded_sip002() {
        // method:pass = aes-256-gcm:pass123, padded base64.
        let blob = base64::engine::general_purpose::STANDARD.encode(b"aes-256-gcm:pass123");
        let line = format!("ss://{blob}@1.2.3.4:8388#x");
        let entry = parse(&line[5..], &line).unwrap();
        assert_eq!(entry.credential, "aes-256-gcm:pass123");
    }

    #[test]
    fn parses_legacy_format() {
        let blob = base64::engine::general_purpose::STANDARD_NO_PAD
            .encode(b"aes-256-gcm:pass@9.9.9.9:8388");
        let line = format!("ss://{blob}#legacy");
        let entry = parse(&line[5..], &line).unwrap();
        assert_eq!(entry.credential, "aes-256-gcm:pass");
        assert_eq!(entry.host, "9.9.9.9");
        assert_eq!(entry.port, 8388);
        assert_eq!(entry.name, "legacy");
    }

    #[test]
    fn semantic_round_trip() {
        let line = "ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTo1Zi1pOG9WcDhVTTZqWEpoZ1N2SVJ3@64.49.15.51:842/?security=none#%F0%9F%87%AC%20UK";
        let first = parse(line.strip_prefix("ss://").unwrap(), line).unwrap();
        let serialized = serialize(&first);
        let second = parse(serialized.strip_prefix("ss://").unwrap(), &serialized).unwrap();
        assert_eq!(first.scheme, second.scheme);
        assert_eq!(first.name, second.name);
        assert_eq!(first.host, second.host);
        assert_eq!(first.port, second.port);
        assert_eq!(first.credential, second.credential);
        assert_eq!(first.params, second.params);
    }

    #[test]
    fn rejects_garbage() {
        assert!(parse("not-base64!!!@host:80", "").is_err());
        assert!(parse("aG9zdA@host:80", "").is_err()); // decoded "host" has no ':'
    }
}
