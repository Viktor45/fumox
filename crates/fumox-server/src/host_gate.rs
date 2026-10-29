//! Host header policy: a single place that canonicalizes Host, compares it
//! against a per-listener allowlist, and either gates the request or builds
//! the admin panel's serve-link. Two consumers (gate vs builder), one
//! canonicalization, one comparison.

use axum::http::{HeaderMap, header};
use fumox_core::config::TrustedHeader;
use std::fmt;
use std::net::SocketAddr;

/// A Host-header check rejected a request: either the host was missing
/// (when an allowlist is configured) or it was not on the allowlist.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostRejected {
    pub host: String,
    pub reason: RejectionReason,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RejectionReason {
    /// Allowlist is non-empty but the host is empty / missing.
    Missing,
    /// Allowlist is non-empty and the host is set but does not match.
    NotAllowed,
}

impl fmt::Display for HostRejected {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.reason {
            RejectionReason::Missing => write!(f, "Host header is missing"),
            RejectionReason::NotAllowed => {
                write!(f, "Host header value is not in the allowlist")
            }
        }
    }
}

impl std::error::Error for HostRejected {}

/// Lowercase, port-stripped, IPv6-bracket-stripped canonical host from a
/// request's `Host` header. Returns an empty string when the header is
/// absent or empty (the caller is expected to treat that as "no host" and
/// reject when an allowlist is configured).
pub fn canonical_request_host(headers: &HeaderMap) -> String {
    let raw = match headers.get(header::HOST).and_then(|v| v.to_str().ok()) {
        Some(h) if !h.is_empty() => h,
        _ => return String::new(),
    };
    canonicalize_host_str(raw)
}

/// Internal helper: lowercase, strip port, strip IPv6 brackets. Bare IPv6
/// (multiple colons, no brackets) is wrapped in brackets and lowercased so
/// every IPv6 input shape canonicalizes to `[x]`. A literal `@` anywhere in
/// the input is rejected outright, `vpn.example.com:8080@evil.com` would
/// otherwise return `vpn.example.com` after the single-colon port strip, and
/// the rejected host (after the gate's `canonicalize_host_str` call) hides
/// the attacker payload from the `err.host` logged on rejection. Both the
/// gate (`validate_request_host`) and the link-builder
/// (`build_serve_link_host`) inherit the rejection without per-callsite
/// edits.
fn canonicalize_host_str(raw: &str) -> String {
    if raw.contains('@') {
        return String::new();
    }
    if let Some(rest) = raw.strip_prefix('[') {
        // IPv6 literal: `[::1]` or `[::1]:port`, keep the inside stripped of brackets.
        let inside = rest.split(']').next().unwrap_or(rest);
        format!("[{}]", inside.to_ascii_lowercase())
    } else if raw.matches(':').count() == 1 {
        if let Some((host, _)) = raw.rsplit_once(':') {
            return host.to_ascii_lowercase();
        }
        raw.to_ascii_lowercase()
    } else if raw.matches(':').count() > 1 {
        // Bare IPv6, wrap in brackets so the canonical form matches
        // `[2001:db8::1]`.
        format!("[{}]", raw.to_ascii_lowercase())
    } else {
        raw.to_ascii_lowercase()
    }
}

/// Request-time gate. Returns `Err(HostRejected)` when `allowed_hosts` is
/// non-empty AND the canonical host is not in the list (case-insensitive
/// after [`canonical_request_host`], brackets stripped for IPv6 literals so
/// `[::1]` and `::1` match either way). Empty allowlist = accept any host
/// (today's behavior, opt-in).
///
/// An empty canonical host is never in a non-empty allowlist, so a missing
/// `Host` header is rejected whenever an allowlist is configured, this is
/// the desired deny-by-default semantic.
pub fn validate_request_host(
    headers: &HeaderMap,
    allowed_hosts: &[String],
) -> Result<(), HostRejected> {
    if allowed_hosts.is_empty() {
        return Ok(());
    }
    validate_canonical_host(&canonical_request_host(headers), allowed_hosts)
}

/// Compare one canonical host against the allowlist.
fn validate_canonical_host(host: &str, allowed_hosts: &[String]) -> Result<(), HostRejected> {
    if host.is_empty() {
        return Err(HostRejected {
            host: host.to_string(),
            reason: RejectionReason::Missing,
        });
    }
    let allowed_canonical: Vec<String> = allowed_hosts
        .iter()
        .map(|h| canonicalize_host_str(h))
        .collect();
    if allowed_canonical.iter().any(|h| h == host) {
        Ok(())
    } else {
        Err(HostRejected {
            host: host.to_string(),
            reason: RejectionReason::NotAllowed,
        })
    }
}

/// The canonical host a trusted proxy names in `X-Forwarded-Host` or in the
/// RFC 7239 `Forwarded: host=` element.
///
/// Only the header family the operator declared ([`TrustedHeader`]) is
/// read: a client that reaches the panel directly can write these headers
/// itself, and an undeclared family is text nobody vouched for. Empty when
/// the declared family carries nothing usable.
pub fn canonical_forwarded_host(headers: &HeaderMap, trusted_header: TrustedHeader) -> String {
    if trusted_header.honors_xff()
        && let Some(raw) = headers
            .get("x-forwarded-host")
            .and_then(|v| v.to_str().ok())
            .map(str::trim)
            .filter(|raw| !raw.is_empty())
    {
        let host = canonicalize_host_str(raw);
        if !host.is_empty() {
            return host;
        }
    }
    if trusted_header.honors_forwarded()
        && let Some(host) = forwarded_host_element(headers)
    {
        return host;
    }
    String::new()
}

/// The `host=` element of an RFC 7239 `Forwarded` header, canonicalized.
fn forwarded_host_element(headers: &HeaderMap) -> Option<String> {
    let raw = headers.get(header::FORWARDED)?.to_str().ok()?;
    for element in raw.split(',') {
        for pair in element.split(';') {
            let Some((key, value)) = pair.split_once('=') else {
                continue;
            };
            if !key.trim().eq_ignore_ascii_case("host") {
                continue;
            }
            let value = value.trim().trim_matches('"');
            if value.is_empty() {
                continue;
            }
            let host = canonicalize_host_str(value);
            if !host.is_empty() {
                return Some(host);
            }
        }
    }
    None
}

/// Gate the host a trusted proxy forwarded: the request is allowed when
/// the proxy's own forwarded host is on the allowlist, even when the
/// `Host` header it rewrote is not.
pub fn validate_forwarded_host(
    headers: &HeaderMap,
    allowed_hosts: &[String],
    trusted_header: TrustedHeader,
) -> Result<(), HostRejected> {
    if allowed_hosts.is_empty() {
        return Ok(());
    }
    validate_canonical_host(
        &canonical_forwarded_host(headers, trusted_header),
        allowed_hosts,
    )
}

/// True when the canonical host is a well-formed authority component: a
/// DNS name (letters, digits, `-`, `.`), an IPv4 literal, or a bracketed
/// IPv6 literal whose contents parse as an address.
///
/// Everything else is not a host: a path, a query, a fragment, a percent
/// escape, a space or a backslash. Such a value must never reach a URL,
/// and the serve link carries a capability token, so a host of
/// `evil.com/#` would put the token behind an attacker-controlled
/// authority.
fn host_grammar_ok(host: &str) -> bool {
    if host.is_empty() {
        return false;
    }
    if let Some(rest) = host.strip_prefix('[') {
        let Some(inside) = rest.strip_suffix(']') else {
            return false;
        };
        return inside.parse::<std::net::Ipv6Addr>().is_ok();
    }
    if host.bytes().all(|b| b.is_ascii_digit() || b == b'.') {
        return host.parse::<std::net::Ipv4Addr>().is_ok();
    }
    host.bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.')
}

/// The host a serve link points at: the canonical name plus the port the
/// request's `Host` header carried, if it spelled one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServeLinkHost {
    /// The canonical host, port-stripped, IPv6 brackets preserved.
    pub host: String,
    /// The port the `Host` header spelled, if any. The caller decides
    /// whether it applies: the serve link points at the *public*
    /// listener, whose port is the one in `[server].bind`.
    pub port: Option<u16>,
}

/// A `Host` header that cannot be read as text, is blank, does not
/// canonicalize (a literal `@`, the userinfo separator) or is not a
/// well-formed host never becomes a URL host component. The serve link
/// carries a capability token, so `name@evil.com` would send the operator
/// (and anyone who clicks the link) to `http://name@evil.com/export/alive/{token}`
/// with the token as the query of an attacker-controlled host. The
/// canonicalizer is the same one the gate uses, so the two consumers can
/// never disagree about what a Host means, and the check runs even with an
/// empty allowlist, that is exactly the configuration the gate skips.
fn serve_link_host(headers: &HeaderMap) -> Option<String> {
    let raw = headers.get(header::HOST).and_then(|v| v.to_str().ok())?;
    if raw.trim().is_empty() {
        return None;
    }
    let host = canonicalize_host_str(raw.trim());
    if host.is_empty() || !host_grammar_ok(&host) {
        return None;
    }
    Some(host)
}

/// The port a `host[:port]` authority spells, IPv6-bracket aware. `None`
/// when the authority carries no port or the port is not a number.
fn authority_port(raw: &str) -> Option<u16> {
    let raw = raw.trim();
    if let Some(rest) = raw.strip_prefix('[') {
        let end = rest.find(']')?;
        let after = &rest[end + 1..];
        return after.strip_prefix(':').and_then(|p| p.parse().ok());
    }
    let (host, port) = raw.rsplit_once(':')?;
    if host.is_empty() || host.contains(':') || port.is_empty() {
        return None;
    }
    if !port.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    port.parse().ok()
}

/// The port the `Host` header spelled, if any.
fn serve_link_port(headers: &HeaderMap) -> Option<u16> {
    let raw = headers.get(header::HOST).and_then(|v| v.to_str().ok())?;
    authority_port(raw)
}

/// Link-builder for the admin panel: lowercases the host and matches it
/// against the allowlist, returning the canonical host (port-stripped,
/// IPv6 brackets preserved when present) and the port the request carried
/// on success, or `HostRejected` on mismatch.
pub fn build_serve_link_host(
    bind: SocketAddr,
    headers: &HeaderMap,
    allowed_hosts: &[String],
) -> Result<ServeLinkHost, HostRejected> {
    validate_request_host(headers, allowed_hosts)?;
    if let Some(host) = serve_link_host(headers) {
        return Ok(ServeLinkHost {
            port: serve_link_port(headers),
            host,
        });
    }
    // No usable Host header: fall back to the bound IP (unspecified →
    // loopback).
    Ok(ServeLinkHost {
        host: fallback_host(bind),
        port: None,
    })
}

fn fallback_host(bind: SocketAddr) -> String {
    let ip = bind.ip();
    if ip.is_unspecified() {
        "127.0.0.1".to_string()
    } else if ip.is_ipv6() {
        format!("[{ip}]")
    } else {
        ip.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn host(value: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(header::HOST, value.parse().unwrap());
        h
    }

    #[test]
    fn canonical_request_host_handles_plain_host() {
        let h = host("Example.COM");
        assert_eq!(canonical_request_host(&h), "example.com");
    }

    #[test]
    fn canonical_request_host_strips_port() {
        let h = host("vpn.example.com:8081");
        assert_eq!(canonical_request_host(&h), "vpn.example.com");
    }

    #[test]
    fn canonical_request_host_keeps_ipv6_brackets() {
        let h = host("[::1]:8081");
        assert_eq!(canonical_request_host(&h), "[::1]");
        let h = host("[::1]");
        assert_eq!(canonical_request_host(&h), "[::1]");
    }

    /// Bare IPv6 (no brackets) is wrapped in brackets and lowercased so the
    /// canonical form matches the bracketed-input shape (`[x]`).
    #[test]
    fn canonicalize_host_str_handles_bare_ipv6() {
        assert_eq!(canonicalize_host_str("2001:db8::1"), "[2001:db8::1]");
        assert_eq!(canonicalize_host_str("2001:DB8::1"), "[2001:db8::1]");
        // The trailing-port form is no longer the broken `rsplit_once(':')`
        // result, the gate and the link-builder must agree.
        assert_eq!(
            canonicalize_host_str("2001:db8::1:8080"),
            "[2001:db8::1:8080]"
        );
    }

    /// The link-builder runs the same canonicalization as the gate even with
    /// an empty allowlist, where the gate itself is a no-op: a `Host` holding
    /// userinfo would otherwise land verbatim in a link that carries the
    /// export token.
    #[test]
    fn build_serve_link_host_never_emits_userinfo() {
        let bind: SocketAddr = "0.0.0.0:8080".parse().unwrap();
        // `@` without a colon, the shape the gate's single-colon port strip
        // used to leave untouched.
        let out = build_serve_link_host(bind, &host("vpn.example.com@evil.com"), &[]).unwrap();
        assert_eq!(out.host, "127.0.0.1", "{out:?}");
        assert!(!out.host.contains('@'));
        // Same with a port on the attacker side.
        let out = build_serve_link_host(bind, &host("vpn.example.com:8080@evil.com"), &[]).unwrap();
        assert!(!out.host.contains('@'), "{out:?}");
        // An ordinary host still canonicalizes as before, allowlist or not.
        assert_eq!(
            build_serve_link_host(bind, &host("VPN.EXAMPLE.COM:8081"), &[])
                .unwrap()
                .host,
            "vpn.example.com"
        );
    }

    /// The single-colon rsplit branch would otherwise turn
    /// `vpn.example.com:8080@evil.com` into `vpn.example.com` (and log
    /// `vpn.example.com` on rejection, hiding the attacker payload).
    /// Rejecting `@` at the canonicalization layer means both the gate and
    /// the link-builder inherit the rejection without per-callsite edits.
    #[test]
    fn canonical_request_host_rejects_userinfo_with_at_sign() {
        let h = host("vpn.example.com:8080@evil.com");
        assert_eq!(canonical_request_host(&h), "");
        // Empty canonical host is never in a non-empty allowlist, so the
        // gate maps the rejection to `HostRejected { reason: Missing }`.
        let allowed = vec!["vpn.example.com".to_string()];
        let err = validate_request_host(&h, &allowed).unwrap_err();
        assert_eq!(err.reason, RejectionReason::Missing);
    }

    #[test]
    fn canonical_request_host_returns_empty_when_missing() {
        assert_eq!(canonical_request_host(&HeaderMap::new()), "");
        let mut h = HeaderMap::new();
        h.insert(header::HOST, "".parse().unwrap());
        assert_eq!(canonical_request_host(&h), "");
    }

    #[test]
    fn validate_request_host_empty_allowlist_accepts_anything() {
        let h = host("evil.example");
        assert!(validate_request_host(&h, &[]).is_ok());
        assert!(validate_request_host(&HeaderMap::new(), &[]).is_ok());
    }

    #[test]
    fn validate_request_host_matches_case_insensitively() {
        let allowed = vec!["vpn.example.com".to_string()];
        assert!(validate_request_host(&host("VPN.EXAMPLE.COM"), &allowed).is_ok());
        assert!(validate_request_host(&host("vpn.example.com"), &allowed).is_ok());
    }

    #[test]
    fn validate_request_host_rejects_when_host_not_in_allowlist() {
        let allowed = vec!["vpn.example.com".to_string()];
        let err = validate_request_host(&host("evil.example"), &allowed).unwrap_err();
        assert_eq!(err.reason, RejectionReason::NotAllowed);
        assert_eq!(err.host, "evil.example");
    }

    #[test]
    fn validate_request_host_matches_ipv6_in_either_form() {
        let allowed_with_brackets = vec!["[::1]".to_string()];
        assert!(validate_request_host(&host("[::1]:8080"), &allowed_with_brackets).is_ok());
        let allowed_without = vec!["::1".to_string()];
        assert!(validate_request_host(&host("[::1]:8080"), &allowed_without).is_ok());
    }

    #[test]
    fn validate_request_host_rejects_missing_host_when_allowlist_configured() {
        let allowed = vec!["vpn.example.com".to_string()];
        let err = validate_request_host(&HeaderMap::new(), &allowed).unwrap_err();
        assert_eq!(err.reason, RejectionReason::Missing);
    }

    #[test]
    fn build_serve_link_host_returns_canonical_when_in_allowlist() {
        let bind: SocketAddr = "0.0.0.0:8080".parse().unwrap();
        let allowed = vec!["vpn.example.com".to_string()];
        // The port is stripped for the URL host component, the caller
        // appends the public port from `[server].bind`.
        let out = build_serve_link_host(bind, &host("vpn.example.com:8081"), &allowed).unwrap();
        assert_eq!(out.host, "vpn.example.com");
        // The port the authority spelled is reported separately: behind a
        // trusted proxy it is the public authority's port.
        assert_eq!(out.port, Some(8081));
    }

    /// M-157: only a well-formed host reaches the URL. A host holding
    /// a path, a query, a fragment, a percent escape, a space or a
    /// backslash is not a host; the serve link carries a capability
    /// token, so such a value must never end up in it.
    #[test]
    fn a_malformed_host_never_reaches_the_serve_link() {
        let bind: SocketAddr = "0.0.0.0:8080".parse().unwrap();
        for raw in [
            "evil.com/",
            "evil.com?x=1",
            "evil.com#fragment",
            "evil.com%2f",
            "evil.com name",
            "evil\\com",
            "evil.com:@x",
            "[not-an-ip]",
            "999.1.1.1",
        ] {
            let out = build_serve_link_host(bind, &host(raw), &[]).unwrap();
            assert_eq!(
                out.host, "127.0.0.1",
                "{raw:?} must not reach the serve link: {out:?}"
            );
        }

        // A well-formed host still builds the link.
        assert_eq!(
            build_serve_link_host(bind, &host("vpn.example.com"), &[])
                .unwrap()
                .host,
            "vpn.example.com"
        );
        assert_eq!(
            build_serve_link_host(bind, &host("[::1]:8080"), &[])
                .unwrap()
                .host,
            "[::1]"
        );
    }

    #[test]
    fn build_serve_link_host_rejects_when_not_in_allowlist() {
        let bind: SocketAddr = "0.0.0.0:8080".parse().unwrap();
        let allowed = vec!["vpn.example.com".to_string()];
        assert!(build_serve_link_host(bind, &host("evil.example"), &allowed).is_err());
    }
}
