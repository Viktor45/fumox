//! Host header policy: a single place that canonicalizes Host, compares it
//! against a per-listener allowlist, and either gates the request or builds
//! the admin panel's serve-link. Two consumers (gate vs builder), one
//! canonicalization, one comparison.

use axum::http::{HeaderMap, header};
use fumox_core::config::TrustedHeader;
use std::fmt;
use std::net::{Ipv6Addr, SocketAddr};

/// A Host-header check rejected a request: the host was missing (when an
/// allowlist is configured), the header was present but its value can never
/// be a host, or the host was not on the allowlist.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostRejected {
    /// The canonical host that was refused. Empty for
    /// [`RejectionReason::Missing`] and [`RejectionReason::Malformed`]: a
    /// malformed value is deliberately not echoed back, it may be
    /// attacker-controlled and must not reach a log or a response body
    /// through the rejection itself.
    pub host: String,
    pub reason: RejectionReason,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RejectionReason {
    /// The `Host` header is absent, blank or carries no host at all (a
    /// bare `:port`): the allowlist is non-empty and there is nothing to
    /// match.
    Missing,
    /// The `Host` header is present but its value can never be a host: a
    /// literal `@` (the userinfo separator), a non-ASCII byte, or a
    /// bracketed literal that is not a whole IPv6 address with an optional
    /// port. A different failure than [`RejectionReason::Missing`] — the
    /// header was sent, its value is just not a host — so the rejection
    /// log names it differently.
    Malformed,
    /// Allowlist is non-empty and the host is set but does not match.
    NotAllowed,
}

impl fmt::Display for HostRejected {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.reason {
            RejectionReason::Missing => write!(f, "Host header is missing"),
            RejectionReason::Malformed => write!(f, "Host header value is not a valid host"),
            RejectionReason::NotAllowed => {
                write!(
                    f,
                    "Host header value '{}' is not in the allowlist",
                    self.host
                )
            }
        }
    }
}

impl std::error::Error for HostRejected {}

/// One extraction path for the `Host` header: present → readable as text →
/// trimmed → non-empty. The gate ([`canonical_request_host`]) and the
/// serve-link builder ([`serve_link_host`]) share it, so the two consumers
/// can never disagree about whether a request carried a host.
fn host_header(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(header::HOST)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|raw| !raw.is_empty())
}

/// What canonicalization made of one request's `Host` header: the one shape
/// the gate and the serve-link builder must agree on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RequestHost {
    /// No host at all: the header is absent, blank, or a bare `:port`.
    Missing,
    /// A canonical host: lowercased, port-stripped, IPv6 brackets kept.
    Host(String),
    /// The header is present but its value can never be a host (see
    /// [`canonicalize_host_str`]): a literal `@`, a non-ASCII byte, or a
    /// malformed bracketed literal.
    Malformed,
}

/// The gate's view of the request authority. Extraction goes through the
/// same [`host_header`] helper the serve-link builder uses; a value that is
/// present but unreadable as text (a byte outside UTF-8) is
/// [`RequestHost::Malformed`], not missing — the two read differently in
/// the rejection log.
pub fn canonical_request_host(headers: &HeaderMap) -> RequestHost {
    match host_header(headers) {
        Some(raw) => match canonicalize_host_str(raw) {
            Ok(host) if host.is_empty() => RequestHost::Missing,
            Ok(host) => RequestHost::Host(host),
            Err(_) => RequestHost::Malformed,
        },
        None => match headers.get(header::HOST) {
            // Present but not readable as text: the value can never be a
            // host, which is a different rejection than a header that is
            // simply not there.
            Some(value) if value.to_str().is_err() => RequestHost::Malformed,
            _ => RequestHost::Missing,
        },
    }
}

/// Canonicalization failed: the value can never be a host. The raw value
/// is deliberately not carried on the error — it may be attacker-controlled
/// and must not be echoed into a rejection log.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct MalformedHost;

/// Internal helper: lowercase, strip port, strip IPv6 brackets. Bare IPv6
/// (multiple colons, no brackets) is wrapped in brackets and lowercased so
/// every IPv6 input shape canonicalizes to `[x]`.
///
/// The fail-closed contract lives here and nowhere else; the gate, the
/// link-builder and the allowlist loader ([`HostAllowlist`]) all inherit it:
///
/// - A literal `@` anywhere in the input is rejected: it is the userinfo
///   separator, `vpn.example.com:8080@evil.com` would otherwise return
///   `vpn.example.com` after the single-colon port strip, and the rejected
///   host would hide the attacker payload from the `err.host` logged on
///   rejection. The same goes for a non-ASCII byte: it cannot appear in a
///   DNS name or an IP literal.
/// - A bracketed literal must be a whole IPv6 address optionally followed
///   by `:digits` (`[::1]`, `[::1]:80`); anything riding on the closing
///   bracket (`[::1]junk`, `[::1]:80:junk`) or brackets around something
///   that is not an address (`[foo]`) is rejected instead of
///   canonicalizing to whatever precedes the junk.
///
/// `Err(MalformedHost)` is that rejection. An `Ok` empty string is a value
/// that carries no host at all (a bare `:port`); the callers treat it as
/// "missing", not as malformed.
fn canonicalize_host_str(raw: &str) -> Result<String, MalformedHost> {
    if !raw.is_ascii() || raw.contains('@') {
        return Err(MalformedHost);
    }
    if let Some(rest) = raw.strip_prefix('[') {
        return bracketed_ipv6(rest);
    }
    // One count, three branches: no colon (a name or an IPv4 literal),
    // exactly one colon (a `host:port` authority), more (a bare IPv6).
    match raw.matches(':').count() {
        // A FQDN may spell a trailing dot; stripping it gives the name one
        // canonical form, so the allowlist match does not depend on the
        // resolver style the client used.
        0 => Ok(strip_trailing_dot(&raw.to_ascii_lowercase()).to_owned()),
        // `rsplit_once` handles exactly this single-colon form (a bare
        // IPv6 with its many colons never reaches this branch).
        1 => {
            let (host, _) = raw.rsplit_once(':').expect("one colon always splits");
            Ok(strip_trailing_dot(&host.to_ascii_lowercase()).to_owned())
        }
        // Bare IPv6, wrap in brackets so the canonical form matches
        // `[2001:db8::1]`.
        _ => Ok(format!("[{}]", raw.to_ascii_lowercase())),
    }
}

/// The tail of a bracketed literal: the content up to the closing `]`, and
/// whatever rides on it. Only `]` and `]:digits` after a whole IPv6 address
/// are hosts — the port must be all digits and nothing may follow it
/// (`[::1]junk` is junk, not a host).
fn bracketed_ipv6(rest: &str) -> Result<String, MalformedHost> {
    let Some((inside, tail)) = rest.split_once(']') else {
        return Err(MalformedHost); // no closing bracket: never a host
    };
    let port_ok = match tail.strip_prefix(':') {
        Some(port) => !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit()),
        None => tail.is_empty(),
    };
    if !port_ok || inside.parse::<Ipv6Addr>().is_err() {
        return Err(MalformedHost);
    }
    Ok(format!("[{}]", inside.to_ascii_lowercase()))
}

/// FQDNs may spell a trailing dot (`vpn.example.com.`); stripping one
/// trailing dot gives the name a single canonical form. A lone `.` is not
/// a name and stays as it is.
fn strip_trailing_dot(host: &str) -> &str {
    match host.strip_suffix('.') {
        Some(stripped) if !stripped.is_empty() => stripped,
        _ => host,
    }
}

/// A Host allowlist canonicalized once at config load. Every entry runs
/// through the same [`canonicalize_host_str`] as the request hosts it is
/// compared against, so the hot path is a plain string compare — no
/// per-request canonicalization, no allocation. Built from
/// `[server].allowed_hosts` or `[admin].allowed_hosts`; a port an entry
/// spells is dropped, and an entry that can never be a host is dropped
/// with it — both are named in the log, and the type is constructed at
/// config load only, so the warnings land where the operator reads them.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HostAllowlist {
    entries: Vec<String>,
}

impl HostAllowlist {
    /// Canonicalize every entry once. Called at config load only: at
    /// startup and on a settings save that swaps the live config.
    pub fn new(raw: &[String]) -> Self {
        let mut entries = Vec::with_capacity(raw.len());
        for entry in raw {
            match canonicalize_host_str(entry) {
                Ok(host) if !host.is_empty() => entries.push(host),
                _ => tracing::warn!(
                    entry = %entry,
                    "allowed_hosts entry is not a usable host, dropped from the allowlist"
                ),
            }
        }
        for entry in raw {
            // The canonicalization above silently dropped the port, so
            // `example.com:443` matches `example.com` on *any* port: worth
            // saying out loud, the operator may have meant the gate to pin
            // the port too. A bracketed IPv6 literal spells its port in
            // the one form there is, so it is not called out.
            if !entry.starts_with('[') && authority_port(entry).is_some() {
                tracing::warn!(
                    entry = %entry,
                    "allowed_hosts entry names a port; the port is ignored, \
                     the entry matches the host on any port"
                );
            }
        }
        Self { entries }
    }

    /// True when nothing is allowlisted: the gate is disabled.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// True when `host` — already canonical, the callers canonicalize the
    /// request side — is on the list.
    fn contains(&self, host: &str) -> bool {
        self.entries.iter().any(|entry| entry == host)
    }
}

/// Request-time gate: the canonical host must be on the allowlist
/// (case-insensitive after [`canonical_request_host`], IPv6 brackets kept
/// on both sides, so `[::1]` and `::1` entries match either way). An empty
/// allowlist disables the check: any host is accepted.
///
/// The list comes from the config, canonicalized once at load
/// ([`HostAllowlist`]): `[server].allowed_hosts` for the public listener,
/// `[admin].allowed_hosts` for the admin panel. An entry is a DNS name
/// (`vpn.example.com`), an IPv4 literal (`127.0.0.1`) or an IPv6 literal in
/// brackets (`[::1]`); a port an entry may spell is ignored.
///
/// A missing, blank or malformed `Host` header is never on a non-empty
/// allowlist, so it is rejected whenever one is configured — the
/// deny-by-default semantic.
pub fn validate_request_host(
    headers: &HeaderMap,
    allowed_hosts: &HostAllowlist,
) -> Result<(), HostRejected> {
    if allowed_hosts.is_empty() {
        return Ok(());
    }
    match canonical_request_host(headers) {
        RequestHost::Host(host) => validate_canonical_host(&host, allowed_hosts),
        RequestHost::Missing => validate_canonical_host("", allowed_hosts),
        RequestHost::Malformed => Err(HostRejected {
            host: String::new(),
            reason: RejectionReason::Malformed,
        }),
    }
}

/// Compare one canonical host against the allowlist. An empty host is "no
/// host at all" ([`RejectionReason::Missing`]); a malformed value is mapped
/// to [`RejectionReason::Malformed`] by the callers before they come here.
fn validate_canonical_host(host: &str, allowed_hosts: &HostAllowlist) -> Result<(), HostRejected> {
    if host.is_empty() {
        return Err(HostRejected {
            host: String::new(),
            reason: RejectionReason::Missing,
        });
    }
    if allowed_hosts.contains(host) {
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
        && let Ok(host) = canonicalize_host_str(raw)
        && !host.is_empty()
    {
        // A malformed forwarded host is simply not usable: the caller
        // falls through to the RFC 7239 element, and the `Host` header
        // carries its own rejection reason.
        return host;
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
            if let Ok(host) = canonicalize_host_str(value)
                && !host.is_empty()
            {
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
    allowed_hosts: &HostAllowlist,
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
    /// The host came from the request's `Host` header, not from the
    /// bind-address fallback: only then does its (possibly absent) port
    /// describe the public authority the caller may build on.
    pub from_header: bool,
}

/// The serve link's host comes from the same [`host_header`] extraction and
/// the same canonicalization the gate uses — see [`canonicalize_host_str`]
/// for what is rejected — plus a grammar check: only a well-formed
/// authority (a DNS name, an IPv4 literal, a bracketed IPv6 literal)
/// becomes a URL host component, the link carries a capability token and
/// must not grow a path, a query or a userinfo from the header.
fn serve_link_host(headers: &HeaderMap) -> Option<String> {
    let host = canonicalize_host_str(host_header(headers)?).ok()?;
    if host_grammar_ok(&host) {
        Some(host)
    } else {
        None
    }
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
    allowed_hosts: &HostAllowlist,
) -> Result<ServeLinkHost, HostRejected> {
    validate_request_host(headers, allowed_hosts)?;
    if let Some(host) = serve_link_host(headers) {
        return Ok(ServeLinkHost {
            port: serve_link_port(headers),
            host,
            from_header: true,
        });
    }
    // No usable Host header: fall back to the bound IP. The fallback is
    // distinguishable for the caller (`ServeLinkHost::from_header`), so
    // the admin's serve-link builder can log it (see `serve_base`).
    Ok(ServeLinkHost {
        host: fallback_host(bind),
        port: None,
        from_header: false,
    })
}

/// The serve-link host when the request named no usable authority: the
/// bound IP itself, loopback for an unspecified bind. The family follows
/// the bind — an unspecified IPv6 bind (`[::]:8080`) never answers on
/// IPv4, so its link must name the IPv6 loopback `[::1]`; the IPv4
/// wildcard keeps `127.0.0.1` for the same reason, an IPv4 bind never
/// answers on `::1`.
fn fallback_host(bind: SocketAddr) -> String {
    let ip = bind.ip();
    if ip.is_unspecified() {
        if ip.is_ipv6() {
            "[::1]".to_string()
        } else {
            "127.0.0.1".to_string()
        }
    } else if ip.is_ipv6() {
        format!("[{ip}]")
    } else {
        ip.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    fn host(value: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(header::HOST, value.parse().unwrap());
        h
    }

    fn bind() -> SocketAddr {
        "0.0.0.0:8080".parse().unwrap()
    }

    fn allowlist(entries: &[&str]) -> HostAllowlist {
        let owned: Vec<String> = entries.iter().map(|entry| entry.to_string()).collect();
        HostAllowlist::new(&owned)
    }

    fn canon(raw: &str) -> String {
        canonicalize_host_str(raw).expect("must be a usable host")
    }

    #[test]
    fn canonical_request_host_handles_plain_host() {
        let h = host("Example.COM");
        assert_eq!(
            canonical_request_host(&h),
            RequestHost::Host("example.com".to_string())
        );
    }

    #[test]
    fn canonical_request_host_strips_port() {
        let h = host("vpn.example.com:8081");
        assert_eq!(
            canonical_request_host(&h),
            RequestHost::Host("vpn.example.com".to_string())
        );
    }

    #[test]
    fn canonical_request_host_keeps_ipv6_brackets() {
        let h = host("[::1]:8081");
        assert_eq!(
            canonical_request_host(&h),
            RequestHost::Host("[::1]".into())
        );
        let h = host("[::1]");
        assert_eq!(
            canonical_request_host(&h),
            RequestHost::Host("[::1]".into())
        );
    }

    /// Bare IPv6 (no brackets) is wrapped in brackets and lowercased so the
    /// canonical form matches the bracketed-input shape (`[x]`): a bare
    /// IPv6 address with a trailing port (`2001:db8::1:8080`) must stay
    /// whole inside brackets — it is not a `host:port` pair, only the
    /// single-colon form is (`rsplit_once` handles exactly that one).
    #[test]
    fn canonicalize_host_str_handles_bare_ipv6() {
        assert_eq!(canon("2001:db8::1"), "[2001:db8::1]");
        assert_eq!(canon("2001:DB8::1"), "[2001:db8::1]");
        assert_eq!(canon("2001:db8::1:8080"), "[2001:db8::1:8080]");
    }

    /// A bracketed literal must be a whole IPv6 address with at most a
    /// `:digits` riding on the closing bracket; anything else is rejected
    /// fail-closed instead of canonicalizing to whatever precedes the junk.
    #[test]
    fn malformed_bracket_literals_are_rejected_fail_closed() {
        for raw in [
            "[::1]junk",
            "[foo]",
            "[::1]:80:junk",
            "[::1]:",
            "[::1",
            "[]",
        ] {
            assert_eq!(canonicalize_host_str(raw), Err(MalformedHost), "{raw:?}");
        }
        // The well-formed shapes still canonicalize.
        assert_eq!(canon("[::1]"), "[::1]");
        assert_eq!(canon("[::1]:80"), "[::1]");
        // The gate rejects the same values as malformed, and the one
        // well-formed bracketed shape still matches its allowlist entry.
        let allowed = allowlist(&["[::1]"]);
        assert!(validate_request_host(&host("[::1]:80"), &allowed).is_ok());
        let err = validate_request_host(&host("[::1]junk"), &allowed).unwrap_err();
        assert_eq!(err.reason, RejectionReason::Malformed);
    }

    /// The link-builder inherits the `@` rejection from
    /// [`canonicalize_host_str`] even with an empty allowlist, where the
    /// gate itself is a no-op.
    #[test]
    fn build_serve_link_host_never_emits_userinfo() {
        // `@` without a colon, the shape the gate's single-colon port strip
        // used to leave untouched.
        let out = build_serve_link_host(
            bind(),
            &host("vpn.example.com@evil.com"),
            &HostAllowlist::default(),
        )
        .unwrap();
        assert_eq!(out.host, "127.0.0.1");
        // Same with a port on the attacker side.
        let out = build_serve_link_host(
            bind(),
            &host("vpn.example.com:8080@evil.com"),
            &HostAllowlist::default(),
        )
        .unwrap();
        assert_eq!(out.host, "127.0.0.1");
        // An ordinary host still canonicalizes as before, allowlist or not.
        assert_eq!(
            build_serve_link_host(
                bind(),
                &host("VPN.EXAMPLE.COM:8081"),
                &HostAllowlist::default()
            )
            .unwrap()
            .host,
            "vpn.example.com"
        );
    }

    /// A `@` in the Host is a malformed value, not a missing one — the two
    /// need different lines in the rejection log
    /// ([`RejectionReason::Malformed`]).
    #[test]
    fn canonical_request_host_rejects_userinfo_with_at_sign() {
        let h = host("vpn.example.com:8080@evil.com");
        assert_eq!(canonical_request_host(&h), RequestHost::Malformed);
        assert_eq!(
            canonicalize_host_str("vpn.example.com:8080@evil.com"),
            Err(MalformedHost)
        );
        let err = validate_request_host(&h, &allowlist(&["vpn.example.com"])).unwrap_err();
        assert_eq!(err.reason, RejectionReason::Malformed);
    }

    /// A non-ASCII byte cannot appear in a DNS name or an IP literal: the
    /// value is malformed, not missing, and the payload is not echoed into
    /// the rejection. The admin route logs the rejection's `Display`
    /// (`error = %err`), so the log for such a request cannot read
    /// "Host header is missing".
    #[test]
    fn non_ascii_host_is_malformed() {
        let h = host("évil.example.com");
        assert_eq!(canonical_request_host(&h), RequestHost::Malformed);
        let err = validate_request_host(&h, &allowlist(&["vpn.example.com"])).unwrap_err();
        assert_eq!(err.reason, RejectionReason::Malformed);
        assert!(!err.to_string().contains("Host header is missing"));
        assert_eq!(err.to_string(), "Host header value is not a valid host");
    }

    /// A value that is not even readable as text (a byte outside UTF-8) is
    /// malformed the same way: present, but never a host.
    #[test]
    fn unreadable_host_value_is_malformed() {
        let mut h = HeaderMap::new();
        h.insert(header::HOST, HeaderValue::from_bytes(&[0xFF]).unwrap());
        assert_eq!(canonical_request_host(&h), RequestHost::Malformed);
    }

    /// The rejection names the refused host: the admin route logs the
    /// rejection's `Display`, and an operator must see *which* Host was
    /// refused, not only that something was.
    #[test]
    fn rejection_display_names_the_refused_host() {
        let err = validate_request_host(&host("evil.example"), &allowlist(&["vpn.example.com"]))
            .unwrap_err();
        assert_eq!(err.reason, RejectionReason::NotAllowed);
        assert_eq!(err.host, "evil.example");
        assert_eq!(
            err.to_string(),
            "Host header value 'evil.example' is not in the allowlist"
        );
    }

    #[test]
    fn canonical_request_host_returns_missing_when_header_absent_or_blank() {
        assert_eq!(
            canonical_request_host(&HeaderMap::new()),
            RequestHost::Missing
        );
        assert_eq!(canonical_request_host(&host("")), RequestHost::Missing);
        assert_eq!(canonical_request_host(&host("   ")), RequestHost::Missing);
        // A bare `:port` carries no host either.
        assert_eq!(canonical_request_host(&host(":8080")), RequestHost::Missing);
    }

    /// A FQDN may spell a trailing dot; with and without it the host has
    /// one canonical form, on the request side and the allowlist side
    /// alike.
    #[test]
    fn a_trailing_dot_gives_the_same_canonical_form() {
        assert_eq!(canon("vpn.example.com."), "vpn.example.com");
        assert_eq!(canon("vpn.example.com.:8081"), "vpn.example.com");
        // A lone dot is not a name; it stays as it is and can never match
        // a real entry.
        assert_eq!(canon("."), ".");
        assert!(
            validate_request_host(&host("vpn.example.com."), &allowlist(&["vpn.example.com"]))
                .is_ok()
        );
    }

    /// The gate and the serve-link builder extract the Host through the
    /// same [`host_header`] helper: one set of headers must give the same
    /// canonical host on both paths.
    #[test]
    fn gate_and_serve_link_extract_host_the_same_way() {
        for raw in [
            "Example.COM",
            "vpn.example.com:8081",
            "vpn.example.com.",
            "[::1]:8080",
            " vpn.example.com ",
        ] {
            let h = host(raw);
            let canonical = match canonical_request_host(&h) {
                RequestHost::Host(canonical) => canonical,
                other => panic!("{raw:?}: expected a canonical host, got {other:?}"),
            };
            let link = build_serve_link_host(bind(), &h, &HostAllowlist::default()).unwrap();
            assert_eq!(link.host, canonical, "{raw:?}");
            assert!(link.from_header, "{raw:?}");
        }
        // The paths also agree on what is no host at all: the gate answers
        // Missing, the builder falls back to the bind address.
        let missing = host("   ");
        assert_eq!(canonical_request_host(&missing), RequestHost::Missing);
        let out = build_serve_link_host(bind(), &missing, &HostAllowlist::default()).unwrap();
        assert!(!out.from_header);
        assert_eq!(out.host, "127.0.0.1");
    }

    #[test]
    fn validate_request_host_empty_allowlist_accepts_anything() {
        let h = host("evil.example");
        assert!(validate_request_host(&h, &HostAllowlist::default()).is_ok());
        assert!(validate_request_host(&HeaderMap::new(), &HostAllowlist::default()).is_ok());
    }

    #[test]
    fn validate_request_host_matches_case_insensitively() {
        let allowed = allowlist(&["vpn.example.com"]);
        assert!(validate_request_host(&host("VPN.EXAMPLE.COM"), &allowed).is_ok());
        assert!(validate_request_host(&host("vpn.example.com"), &allowed).is_ok());
    }

    /// The allowlist is canonicalized once at load: an entry may spell an
    /// uppercase name and a port, the request host arrives lowercase and
    /// bare — they must still match.
    #[test]
    fn allowlist_entries_are_canonicalized_once_at_load() {
        let allowed = allowlist(&["VPN.EXAMPLE.COM:443"]);
        assert!(validate_request_host(&host("vpn.example.com"), &allowed).is_ok());
        // An IPv6 entry with a port matches the bare bracketed literal.
        let ipv6 = allowlist(&["[::1]:9999"]);
        assert!(validate_request_host(&host("[::1]"), &ipv6).is_ok());
    }

    #[test]
    fn validate_request_host_rejects_when_host_not_in_allowlist() {
        let allowed = allowlist(&["vpn.example.com"]);
        let err = validate_request_host(&host("evil.example"), &allowed).unwrap_err();
        assert_eq!(err.reason, RejectionReason::NotAllowed);
        assert_eq!(err.host, "evil.example");
    }

    #[test]
    fn validate_request_host_matches_ipv6_in_either_form() {
        let allowed_with_brackets = allowlist(&["[::1]"]);
        assert!(validate_request_host(&host("[::1]:8080"), &allowed_with_brackets).is_ok());
        let allowed_without = allowlist(&["::1"]);
        assert!(validate_request_host(&host("[::1]:8080"), &allowed_without).is_ok());
    }

    #[test]
    fn validate_request_host_rejects_missing_host_when_allowlist_configured() {
        let allowed = allowlist(&["vpn.example.com"]);
        let err = validate_request_host(&HeaderMap::new(), &allowed).unwrap_err();
        assert_eq!(err.reason, RejectionReason::Missing);
    }

    #[test]
    fn build_serve_link_host_returns_canonical_when_in_allowlist() {
        let allowed = allowlist(&["vpn.example.com"]);
        // The port is stripped for the URL host component, the caller
        // appends the public port from `[server].bind`.
        let out = build_serve_link_host(bind(), &host("vpn.example.com:8081"), &allowed).unwrap();
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
        for raw in [
            "evil.com/",
            "evil.com?x=1",
            "evil.com#fragment",
            "evil.com%2f",
            "evil.com name",
            "evil\\com",
            "evil.com:@x",
            "[not-an-ip]",
            "[::1]junk",
            "999.1.1.1",
        ] {
            let out = build_serve_link_host(bind(), &host(raw), &HostAllowlist::default()).unwrap();
            assert_eq!(
                out.host, "127.0.0.1",
                "{raw:?} must not reach the serve link: {out:?}"
            );
        }

        // A well-formed host still builds the link.
        assert_eq!(
            build_serve_link_host(bind(), &host("vpn.example.com"), &HostAllowlist::default())
                .unwrap()
                .host,
            "vpn.example.com"
        );
        assert_eq!(
            build_serve_link_host(bind(), &host("[::1]:8080"), &HostAllowlist::default())
                .unwrap()
                .host,
            "[::1]"
        );
    }

    /// Without a usable `Host` header the link falls back to the bind
    /// address, family-aware: an unspecified IPv6 bind names the IPv6
    /// loopback, the IPv4 wildcard the IPv4 one — and the fallback is
    /// distinguishable from a Host-derived link.
    #[test]
    fn build_serve_link_host_falls_back_to_a_family_matched_bind_address() {
        // A specific IPv6 bind keeps its brackets.
        let out = build_serve_link_host(
            "[2001:db8::1]:80".parse().unwrap(),
            &HeaderMap::new(),
            &HostAllowlist::default(),
        )
        .unwrap();
        assert_eq!(out.host, "[2001:db8::1]");
        assert!(!out.from_header);
        // An unspecified IPv6 bind falls back to the IPv6 loopback.
        let out = build_serve_link_host(
            "[::]:80".parse().unwrap(),
            &HeaderMap::new(),
            &HostAllowlist::default(),
        )
        .unwrap();
        assert_eq!(out.host, "[::1]");
        // The IPv4 wildcard keeps the IPv4 loopback.
        let out = build_serve_link_host(
            "0.0.0.0:80".parse().unwrap(),
            &HeaderMap::new(),
            &HostAllowlist::default(),
        )
        .unwrap();
        assert_eq!(out.host, "127.0.0.1");
    }

    #[test]
    fn build_serve_link_host_rejects_when_not_in_allowlist() {
        let allowed = allowlist(&["vpn.example.com"]);
        assert!(build_serve_link_host(bind(), &host("evil.example"), &allowed).is_err());
    }
}
