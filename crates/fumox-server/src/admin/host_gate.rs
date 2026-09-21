//! Host header policy: a single place that canonicalizes Host, compares it
//! against a per-listener allowlist, and either gates the request or builds
//! the admin panel's serve-link. Two consumers (gate vs builder), one
//! canonicalization, one comparison.

use axum::http::{HeaderMap, header};
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
/// the input is rejected outright — `vpn.example.com:8080@evil.com` would
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
        // IPv6 literal: `[::1]` or `[::1]:port` — keep the inside stripped of brackets.
        let inside = rest.split(']').next().unwrap_or(rest);
        format!("[{}]", inside.to_ascii_lowercase())
    } else if raw.matches(':').count() == 1 {
        if let Some((host, _)) = raw.rsplit_once(':') {
            return host.to_ascii_lowercase();
        }
        raw.to_ascii_lowercase()
    } else if raw.matches(':').count() > 1 {
        // Bare IPv6 — wrap in brackets so the canonical form matches
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
/// `Host` header is rejected whenever an allowlist is configured — this is
/// the desired deny-by-default semantic.
pub fn validate_request_host(
    headers: &HeaderMap,
    allowed_hosts: &[String],
) -> Result<(), HostRejected> {
    if allowed_hosts.is_empty() {
        return Ok(());
    }
    let host = canonical_request_host(headers);
    if host.is_empty() {
        return Err(HostRejected {
            host,
            reason: RejectionReason::Missing,
        });
    }
    let allowed_canonical: Vec<String> = allowed_hosts
        .iter()
        .map(|h| canonicalize_host_str(h))
        .collect();
    if allowed_canonical.iter().any(|h| h == &host) {
        Ok(())
    } else {
        Err(HostRejected {
            host,
            reason: RejectionReason::NotAllowed,
        })
    }
}

/// Link-builder for the admin panel: lowercases the host and matches it
/// against the allowlist, returning the canonical host (port-stripped,
/// IPv6 brackets preserved when present) on success or `HostRejected` on
/// mismatch.
pub fn build_serve_link_host(
    bind: SocketAddr,
    headers: &HeaderMap,
    allowed_hosts: &[String],
) -> Result<String, HostRejected> {
    validate_request_host(headers, allowed_hosts)?;
    if let Some(host) = port_stripped_host(headers) {
        return Ok(host);
    }
    // No Host header: fall back to the bound IP (unspecified → loopback).
    Ok(fallback_host(bind))
}

/// Strip the port from the Host header for use as a URL host component.
/// IPv6 literals keep their brackets so the URL stays well-formed.
fn port_stripped_host(headers: &HeaderMap) -> Option<String> {
    let raw = headers.get(header::HOST).and_then(|v| v.to_str().ok())?;
    if raw.is_empty() {
        return None;
    }
    Some(strip_port(raw))
}

fn strip_port(raw: &str) -> String {
    if let Some(rest) = raw.strip_prefix('[') {
        // IPv6 literal: `[::1]` or `[::1]:port` — keep brackets intact.
        if let Some((inside, _rest)) = rest.split_once(']') {
            let mut out = String::with_capacity(raw.len());
            out.push('[');
            out.push_str(inside);
            out.push(']');
            return out;
        }
        raw.to_string()
    } else if raw.matches(':').count() > 1 {
        // Bare IPv6 — wrap in brackets so the URL host stays well-formed.
        format!("[{raw}]")
    } else if let Some((host, _port)) = raw.rsplit_once(':') {
        host.to_string()
    } else {
        raw.to_string()
    }
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
        // result — the gate and the link-builder must agree.
        assert_eq!(
            canonicalize_host_str("2001:db8::1:8080"),
            "[2001:db8::1:8080]"
        );
    }

    /// Same property on the link-builder side: bare IPv6 is wrapped in
    /// brackets, with and without a trailing port, so the returned host is
    /// a well-formed URL component.
    #[test]
    fn strip_port_handles_bare_ipv6() {
        assert_eq!(strip_port("2001:db8::1"), "[2001:db8::1]");
        assert_eq!(strip_port("2001:db8::1:8080"), "[2001:db8::1:8080]");
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
        // The port is stripped for the URL host component — the caller
        // appends the public port from `[server].bind`.
        let out =
            build_serve_link_host(bind, &host("vpn.example.com:8081"), &allowed).unwrap();
        assert_eq!(out, "vpn.example.com");
    }

    #[test]
    fn build_serve_link_host_rejects_when_not_in_allowlist() {
        let bind: SocketAddr = "0.0.0.0:8080".parse().unwrap();
        let allowed = vec!["vpn.example.com".to_string()];
        assert!(build_serve_link_host(bind, &host("evil.example"), &allowed).is_err());
    }
}
