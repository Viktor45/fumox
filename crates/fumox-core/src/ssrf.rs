//! Shared SSRF address policy for both long-lived consumers of untrusted
//! network input: the server's source fetcher (`[admin].allow_private_urls`)
//! and the probe daemon's dial targets (`[probe].allow_private_targets`,
//! security review v2).
//!
//! Proxy hosts and ports arrive from remote subscription feeds and were
//! previously dialed by the probe with no vetting at all, a feed line like
//! `vless://uuid@169.254.169.254:80#x` turned the daemon into an internal
//! port scanner. Both call sites now run every candidate through
//! [`check_ip`] with the same blocklist.
//!
//! # Denial reasons and the allow flags
//!
//! A refusal is a [`DenialReason`], not a bare string: the enum is closed,
//! its `Display` text names the refused range, and
//! [`DenialReason::code`] returns the stable class code a caller branches
//! on (the probe journal tells a policy refusal from a DNS failure by the
//! code, never by substring-matching an error text). The reason texts
//! deliberately do not name an allow flag, because two different flags
//! open the two consumers of this module — `[admin].allow_private_urls`
//! for the server's source fetcher and `[probe].allow_private_targets` for
//! the probe's dial targets — and each caller's own error names the flag
//! that governs its path (see `AppConfig::validate_meow_test_urls` and
//! `fetcher::SsrfRejection`).
//!
//! # The DNS resolution step
//!
//! A hostname has to be resolved before it can be vetted, and that step is
//! bounded by `[network].dns_timeout_secs`: `0` means "follow
//! `[geo].dns_timeout_secs`", and the effective bound is never below one
//! second. The two consumers read it through
//! `AppConfig::ssrf_dns_timeout`, so one setting governs both.
//!
//! That bound is the *caller's* wait, not the resolver's:
//! `tokio::net::lookup_host` hands the name to the OS resolver, which keeps
//! running after the caller gave up, so the timeout does not interrupt the
//! system resolution. The pipeline therefore admits a bounded number of
//! resolutions at a time ([`MAX_CONCURRENT_RESOLUTIONS`]) instead of
//! trusting the timeout to stop them.

use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

use crate::models::IpFamily;

/// Pick the connect address from an already-vetted list: first IPv4 with an
/// IPv6 fallback for `Any` (the historical behavior), otherwise the first
/// address of the requested family. `None` = no usable address.
///
/// Centralized here so the probe (`probe::clash::generate`) and the fetcher
/// (`fetcher::vet_host`) pick the same address from the same vetted list.
pub fn pick_vetted(addrs: &[IpAddr], family: IpFamily) -> Option<IpAddr> {
    match family {
        IpFamily::Any => addrs
            .iter()
            .find(|ip| ip.is_ipv4())
            .or_else(|| addrs.first())
            .copied(),
        IpFamily::Ipv4 => addrs.iter().copied().find(|ip| ip.is_ipv4()),
        IpFamily::Ipv6 => addrs.iter().copied().find(|ip| ip.is_ipv6()),
    }
}

/// Upper bound on the resolutions running at the same time.
///
/// The timeout of [`lookup_with_timeout`] bounds how long the caller waits,
/// it does not cancel the lookup: the OS resolver keeps working on the name
/// after the caller gave up. A feed full of dead names would otherwise
/// start one unbounded resolution per host, each of them holding a runtime
/// worker and a resolver thread until the OS gives up on its own.
const MAX_CONCURRENT_RESOLUTIONS: usize = 16;

/// The resolution slots. A static semaphore, so the cap holds across every
/// consumer of the policy in the process.
static RESOLUTION_SLOTS: tokio::sync::Semaphore =
    tokio::sync::Semaphore::const_new(MAX_CONCURRENT_RESOLUTIONS);

/// Async DNS resolution with an operator-supplied timeout. Async DNS has no
/// built-in timeout, a hostile authoritative resolver can pin the runtime
/// worker for the OS resolver's default (~30 s+). The single
/// `tokio::net::lookup_host` wrapper is preferred over per-family A/AAAA
/// split because the latter would double wire DNS traffic on every
/// resolution.
///
/// Happy-eyeballs regression: on macOS, `getaddrinfo` is sequential, so a
/// timeout that fires after A returns but before AAAA returns will kill a
/// successful combined response. On glibc, both run in parallel and the
/// timeout fires only when both have stalled. This is the documented cost
/// of avoiding the doubled wire DNS count.
///
/// The resolution runs under one of the [`MAX_CONCURRENT_RESOLUTIONS`]
/// slots, and the timeout covers the wait for a slot as well: the caller
/// stops waiting after `dns_timeout` either way.
pub async fn lookup_with_timeout(host: &str, dns_timeout: Duration) -> Result<Vec<IpAddr>, String> {
    timeout_lookup(host, dns_timeout, async {
        match with_resolution_slot(async {
            tokio::net::lookup_host((host, 0))
                .await
                .map(|addrs| addrs.collect::<Vec<_>>())
        })
        .await
        {
            Ok(resolved) => resolved,
            Err(err) => Err(err),
        }
    })
    .await
}

/// Run `fut` while holding one of the [`MAX_CONCURRENT_RESOLUTIONS`]
/// slots.
async fn with_resolution_slot<F, T>(fut: F) -> Result<T, std::io::Error>
where
    F: std::future::Future<Output = T>,
{
    let _permit = RESOLUTION_SLOTS
        .acquire()
        .await
        .map_err(|_| std::io::Error::other("the DNS resolution semaphore is closed"))?;
    Ok(fut.await)
}

/// Upper bound of one resolver answer the policy is willing to look at. A
/// hostile (or merely broken) resolver can return thousands of records,
/// each of them costing a policy check and a slot in the vetted list, so
/// the tail beyond this bound is dropped — with the truncation logged —
/// and the per-host dial budget is set later by [`MAX_VETTED_ADDRESSES`].
const MAX_RESOLVED_ADDRESSES: usize = 64;

/// Upper bound of a feed-supplied host embedded into an error message, in
/// characters (a DNS presentation name cannot exceed 253 anyway). The
/// probe journals these messages verbatim, so one crafted feed line must
/// not flood either sink.
const MAX_HOST_IN_MESSAGE: usize = 253;

/// Strip control characters and truncate a host before it is embedded
/// into an error text. A feed line like `vless://x@<esc-sequence>:80#y`
/// used to reach the log and the journal verbatim, where a `\r` or an ESC
/// could forge log lines or park a terminal in a weird mode.
fn sanitize_host(host: &str) -> String {
    host.chars()
        .filter(|c| !c.is_control())
        .take(MAX_HOST_IN_MESSAGE)
        .collect()
}

/// Inner wrapper of [`lookup_with_timeout`] generic over the resolver future
/// so tests can substitute a controllable future that sleeps past the
/// timeout. The public surface is unchanged.
async fn timeout_lookup<F, I>(
    host: &str,
    dns_timeout: Duration,
    fut: F,
) -> Result<Vec<IpAddr>, String>
where
    F: std::future::Future<Output = std::io::Result<I>>,
    I: IntoIterator<Item = std::net::SocketAddr>,
{
    match tokio::time::timeout(dns_timeout, fut).await {
        Ok(Ok(iter)) => {
            let mut ips: Vec<IpAddr> = iter.into_iter().map(|sa| sa.ip()).collect();
            if ips.len() > MAX_RESOLVED_ADDRESSES {
                tracing::debug!(
                    host = %sanitize_host(host),
                    kept = MAX_RESOLVED_ADDRESSES,
                    dropped = ips.len() - MAX_RESOLVED_ADDRESSES,
                    "resolver answer truncated before vetting"
                );
                ips.truncate(MAX_RESOLVED_ADDRESSES);
            }
            Ok(ips)
        }
        Ok(Err(e)) => Err(format!(
            "DNS resolution failed for {}: {e}",
            sanitize_host(host)
        )),
        Err(_) => Err(format!(
            "DNS resolution timed out after {}s for {}",
            dns_timeout.as_secs(),
            sanitize_host(host)
        )),
    }
}

/// Strip the URI decorations from a host: the square brackets of an IPv6
/// literal and the `%zone` scope id.
///
/// A feed may spell an IPv6 address the URI way (`[2606:4700:4700::1111]`)
/// or with a zone (`fe80::1%eth0`); neither parses as an IP literal, so the
/// host would be taken for a name and sent to the resolver, which is exactly
/// the gap the literal check exists to close.
pub fn strip_host_decorations(host: &str) -> &str {
    let trimmed = host.trim();
    let unbracketed = trimmed
        .strip_prefix('[')
        .and_then(|rest| rest.strip_suffix(']'))
        .unwrap_or(trimmed);
    match unbracketed.split_once('%') {
        Some((literal, _zone)) => literal,
        None => unbracketed,
    }
}

/// Parse a host as an IP literal, tolerating the bracketed URI form and a
/// `%zone` scope id. `None` = not a literal, the host must be resolved.
pub fn parse_ip_literal(host: &str) -> Option<IpAddr> {
    strip_host_decorations(host).parse::<IpAddr>().ok()
}

/// Whether the address is a globally routable public address, i.e. one
/// that must not be handed a secret.
///
/// The inverse of the private-address policy: [`check_ip`] rejects the
/// non-public ranges, this reports the addresses it lets through. It
/// exists for the *other* direction of the same policy: a service the
/// probe authenticates against (the tunnel engine's controller) must not
/// live in public space, where the credential it carries would leak.
pub fn is_public(ip: IpAddr) -> bool {
    check_ip(ip, false).is_ok()
}

/// The closed set of reasons the address policy refuses an address.
///
/// The `Display` text names the refused range, [`DenialReason::code`]
/// returns the stable class code a caller branches on. The transition
/// prefixes (Teredo, 6to4) refuse on their embedded IPv4 payload, so they
/// surface the payload's own reason: the class of the address that must
/// not be dialed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DenialReason {
    /// `127.0.0.0/8`, `::1`.
    Loopback,
    /// `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`.
    Rfc1918,
    /// `169.254.0.0/16` (incl. the cloud metadata endpoint), `fe80::/10`.
    LinkLocal,
    /// `100.64.0.0/10`.
    Cgnat,
    /// TEST-NET documentation space: `192.0.2.0/24`, `198.51.100.0/24`,
    /// `203.0.113.0/24`, `2001:db8::/32`.
    TestNet,
    /// `198.18.0.0/15`, `2001:2::/48`.
    Benchmark,
    /// `192.0.0.0/24` IETF protocol assignments.
    IetfProtocols,
    /// `240.0.0.0/4`, `255.0.0.0/8`.
    Reserved,
    /// `0.0.0.0/8` this-network.
    ThisNetwork,
    /// `0.0.0.0`, `::`.
    Unspecified,
    /// `255.255.255.255`.
    Broadcast,
    /// `224.0.0.0/4`, `ff00::/8`.
    Multicast,
    /// `fc00::/7`.
    UniqueLocal,
    /// `fec0::/10` (deprecated).
    SiteLocal,
    /// `64:ff9b:1::/48` local-use NAT64 prefix.
    Nat64LocalUse,
}

impl std::fmt::Display for DenialReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let text = match self {
            Self::Loopback => "loopback address (127.0.0.0/8, ::1)",
            Self::Rfc1918 => "RFC1918 private address (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)",
            Self::LinkLocal => {
                "link-local address (169.254.0.0/16 incl. the cloud metadata endpoint, fe80::/10)"
            }
            Self::Cgnat => "CGNAT address (100.64.0.0/10)",
            Self::TestNet => {
                "TEST-NET documentation address (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24, 2001:db8::/32)"
            }
            Self::Benchmark => "benchmark address (198.18.0.0/15, 2001:2::/48)",
            Self::IetfProtocols => "IETF protocol assignment address (192.0.0.0/24)",
            Self::Reserved => "reserved address (240.0.0.0/4, 255.0.0.0/8)",
            Self::ThisNetwork => "this-network address (0.0.0.0/8)",
            Self::Unspecified => "unspecified address (0.0.0.0, ::)",
            Self::Broadcast => "broadcast address (255.255.255.255)",
            Self::Multicast => "multicast address (224.0.0.0/4, ff00::/8)",
            Self::UniqueLocal => "unique-local address (fc00::/7)",
            Self::SiteLocal => "site-local address (fec0::/10, deprecated)",
            Self::Nat64LocalUse => "local-use NAT64 prefix (64:ff9b:1::/48)",
        };
        f.write_str(text)
    }
}

impl DenialReason {
    /// The stable class code of the refusal: a caller that has to tell a
    /// policy refusal from a DNS failure (the probe journal, the probe
    /// tests) branches on this instead of parsing the `Display` text.
    pub fn code(self) -> &'static str {
        match self {
            Self::Loopback => "loopback",
            Self::Rfc1918 => "rfc1918",
            Self::LinkLocal => "link_local",
            Self::Cgnat => "cgnat",
            Self::TestNet => "test_net",
            Self::Benchmark => "benchmark",
            Self::IetfProtocols => "ietf_protocols",
            Self::Reserved => "reserved",
            Self::ThisNetwork => "this_network",
            Self::Unspecified => "unspecified",
            Self::Broadcast => "broadcast",
            Self::Multicast => "multicast",
            Self::UniqueLocal => "unique_local",
            Self::SiteLocal => "site_local",
            Self::Nat64LocalUse => "nat64_local_use",
        }
    }
}

/// Vet a single IP address against the shared SSRF policy. Module-private
/// on purpose: the outside callers go through [`vet_addr`] (a single
/// literal) or the `vet_probe_host_*` functions (a host the resolver
/// answers for), so no dial path can reach an address this policy has not
/// seen.
///
/// With `allow_private = false` the following are rejected: loopback
/// (`127.0.0.0/8`, `::1`), RFC 1918 private space, link-local (incl. the
/// `169.254.169.254` cloud metadata endpoint), CGNAT, unspecified,
/// broadcast, multicast, the benchmark ranges (`198.18.0.0/15`,
/// `2001:2::/48`), the TEST-NET documentation space (`192.0.2.0/24`,
/// `198.51.100.0/24`, `203.0.113.0/24`, `2001:db8::/32`), the reserved
/// `240.0.0.0/4` and `255.0.0.0/8` blocks, plus the IPv6 equivalents of
/// every IPv4 rule (incl. the deprecated `fec0::/10` site-local block), the
/// IPv4-mapped `::ffff:0:0/96`, IPv4-compatible `::/96` and IPv4-translated
/// `::ffff:0:0:0/96` forms, the NAT64 `64:ff9b::/96` and `64:ff9b:1::/48`
/// prefixes, the Teredo `2001:0000::/32` range and the 6to4 `2002::/16`
/// transition range.
///
/// Every IPv6 form of a blocked IPv4 address is vetted on its embedded
/// payload, so a feed line writing the metadata endpoint as
/// `::ffff:0:a9fe:a9fe` or as a Teredo address is refused like the plain
/// `169.254.169.254` is.
fn check_ip(ip: IpAddr, allow_private: bool) -> Result<(), DenialReason> {
    if allow_private {
        return Ok(());
    }
    match ip {
        IpAddr::V4(v4) => check_ipv4(v4),
        IpAddr::V6(v6) => {
            if let Some(mapped) = v6.to_ipv4_mapped() {
                return check_ipv4(mapped);
            }
            if v6.is_loopback() {
                return Err(DenialReason::Loopback);
            }
            if v6.is_unspecified() {
                return Err(DenialReason::Unspecified);
            }
            // IPv4-compatible ::/96 (deprecated, RFC 4291 §2.5.5.1 but still
            // what a crafted feed line reaches for): the low 32 bits are a
            // plain IPv4 address, so `::a9fe:a9fe` must be vetted as
            // 169.254.169.254. `to_ipv4()` also covers the mapped form
            // handled above; keeping the two apart preserves the distinct
            // reason strings. `::` and `::1` are already handled above.
            if let Some(compat) = v6.to_ipv4() {
                return check_ipv4(compat);
            }
            if v6.is_multicast() {
                // ff00::/8, includes the often-routable ff02::1.
                return Err(DenialReason::Multicast);
            }
            let segments = v6.segments();
            // fe80::/10 link-local
            if segments[0] & 0xffc0 == 0xfe80 {
                return Err(DenialReason::LinkLocal);
            }
            // fc00::/7 unique-local
            if segments[0] & 0xfe00 == 0xfc00 {
                return Err(DenialReason::UniqueLocal);
            }
            // fec0::/10 site-local (deprecated by RFC 3879, but still
            // unicast space an internal service can be addressed on).
            if segments[0] & 0xffc0 == 0xfec0 {
                return Err(DenialReason::SiteLocal);
            }
            // IPv4-translated ::ffff:0:0:0/96 (RFC 2765): neither
            // `to_ipv4_mapped()` (the `ffff` sits one segment earlier) nor
            // `to_ipv4()` matches it, so the embedded IPv4 was never vetted.
            // The low 32 bits are a plain IPv4 address.
            if segments[0] == 0
                && segments[1] == 0
                && segments[2] == 0
                && segments[3] == 0
                && segments[4] == 0xffff
                && segments[5] == 0
            {
                return check_ipv4(embedded_v4(segments[6], segments[7]));
            }
            // NAT64 well-known prefix 64:ff9b::/96: the low 32 bits are an
            // IPv4 address, vet the embedded address, not the wrapper
            // (2001:db8::/32-only U64 prefix 64:ff9b:1::/48 is public space
            // and falls through).
            if segments[0] == 0x0064
                && segments[1] == 0xff9b
                && segments[2] == 0
                && segments[3] == 0
                && segments[4] == 0
                && segments[5] == 0
            {
                return check_ipv4(embedded_v4(segments[6], segments[7]));
            }
            // NAT64 local-use prefix 64:ff9b:1::/48 (RFC 8215): the whole
            // prefix is refused. The embedded IPv4 sits in octets 10 and 11
            // (RFC 6052 §2.2), and the well-known /96 form of the same
            // prefix is already vetted on its payload, so a payload rule
            // here would need the byte order right to close the hole.
            if segments[0] == 0x0064 && segments[1] == 0xff9b && segments[2] == 0x0001 {
                return Err(DenialReason::Nat64LocalUse);
            }
            // 2001:db8::/32 documentation (RFC 3849) and 2001:2::/48
            // benchmarking (RFC 5180): the IPv6 equivalents of TEST-NET and
            // of 198.18.0.0/15, unicast space no real dial target lives on.
            if segments[0] == 0x2001 && (segments[1] == 0x0db8 || segments[1] == 0x0002) {
                return Err(if segments[1] == 0x0db8 {
                    DenialReason::TestNet
                } else {
                    DenialReason::Benchmark
                });
            }
            // Teredo 2001:0000::/32 (RFC 4380): the address carries two
            // IPv4 addresses, the Teredo server (segments 2-3) and the
            // client (segments 6-7, every bit inverted). Both are vetted:
            // either side of the tunnel is a dial target of its own, and
            // the payload's own refusal reason is what surfaces.
            if segments[0] == 0x2001 && segments[1] == 0 {
                check_ipv4(embedded_v4(segments[2], segments[3]))?;
                return check_ipv4(inverted_v4(segments[6], segments[7]));
            }
            // 6to4 2002::/16: the next 32 bits are the encapsulated IPv4.
            if segments[0] == 0x2002 {
                return check_ipv4(embedded_v4(segments[1], segments[2]));
            }
            Ok(())
        }
    }
}

/// An address the shared policy has accepted. The only way to obtain one
/// from outside this module is a vetting function ([`vet_addr`]), so a
/// dial path that takes a `VettedAddr` cannot be fed an address that
/// skipped [`check_ip`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VettedAddr(IpAddr);

impl VettedAddr {
    /// The vetted address, for the dial path that needs the socket value.
    pub fn ip(self) -> IpAddr {
        self.0
    }
}

/// Vet a single address under the shared policy and return it as a
/// [`VettedAddr`] — the public form of the module-internal [`check_ip`],
/// for callers that only hold a literal (`AppConfig` validating
/// `[meow].test_url`, the admin settings editor) and for dial paths that
/// hand the address on.
pub fn vet_addr(ip: IpAddr, allow_private: bool) -> Result<VettedAddr, DenialReason> {
    check_ip(ip, allow_private).map(|()| VettedAddr(ip))
}

fn embedded_v4(high: u16, low: u16) -> Ipv4Addr {
    Ipv4Addr::new(
        (high >> 8) as u8,
        (high & 0xff) as u8,
        (low >> 8) as u8,
        (low & 0xff) as u8,
    )
}

/// The IPv4 address embedded in the last 32 bits of an IPv6 address, with
/// every bit inverted. Teredo stores the client address that way (RFC 4380
/// §6.1), so the embedded value must be inverted before it is vetted.
fn inverted_v4(high: u16, low: u16) -> Ipv4Addr {
    let [a, b, c, d] = embedded_v4(high, low).octets();
    Ipv4Addr::new(!a, !b, !c, !d)
}

/// Whether a proxy host may be dialed by the probe: IP literals are vetted
/// directly; hostnames are rejected when they cannot be resolved to a
/// vetted address (fail closed, an unresolvable name must never become a
/// probe target). Returns the full list of vetted addresses so the caller
/// can dial them directly instead of re-resolving the hostname, a second
/// DNS lookup between vet and connect would reopen the rebinding window
/// the first lookup just closed.
///
/// This is the only vetting entry point for dial targets, and there is no
/// "vet only, discard the addresses" variant: a dial path that cannot pin
/// the IP (an engine resolving the host itself) has to re-vet the address
/// it actually connected to, the resolver is free to answer differently
/// between vet and dial.
///
/// The async DNS resolution (`tokio::net::lookup_host`) is intentional:
/// every caller is on a Tokio task, and the previous synchronous
/// `std::net::ToSocketAddrs` blocked the runtime worker for the full
/// resolver timeout. The timeout is the operator's `[geo].dns_timeout_secs`
/// knob, see [`lookup_with_timeout`] for the rationale.
pub async fn vet_probe_host_addrs(
    host: &str,
    allow_private: bool,
    dns_timeout: Duration,
) -> Result<Vec<IpAddr>, String> {
    if let Some(ip) = parse_ip_literal(host) {
        check_ip(ip, allow_private).map_err(|reason| reason.to_string())?;
        return Ok(vec![ip]);
    }
    let lookup = lookup_with_timeout(host, dns_timeout).await?;
    vet_resolved_addrs(host, allow_private, lookup)
}

/// The policy and the per-host cap applied to one resolver answer list,
/// split out of [`vet_probe_host_addrs`] so the cap can be tested against a
/// recorded `getaddrinfo` ordering without live DNS.
fn vet_resolved_addrs(
    host: &str,
    allow_private: bool,
    lookup: Vec<IpAddr>,
) -> Result<Vec<IpAddr>, String> {
    let mut seen = std::collections::HashSet::new();
    let mut addrs: Vec<IpAddr> = Vec::new();
    for ip in lookup {
        check_ip(ip, allow_private)
            .map_err(|reason| format!("{}: {reason}", sanitize_host(host)))?;
        // HashSet-backed dedup, resolver order preserved.
        if seen.insert(ip) {
            addrs.push(ip);
        }
    }
    if addrs.is_empty() {
        return Err(format!(
            "DNS resolution returned no addresses for {}",
            sanitize_host(host)
        ));
    }
    let vetted = cap_vetted(&addrs);
    if vetted.len() < addrs.len() {
        tracing::debug!(
            host = %sanitize_host(host),
            kept = vetted.len(),
            dropped = addrs.len() - vetted.len(),
            "vetted address list capped"
        );
    }
    Ok(vetted)
}

/// Cap a vetted address list at [`MAX_VETTED_ADDRESSES`] without letting the
/// cap delete a whole address family.
///
/// A plain `truncate` is wrong here: `getaddrinfo` orders dual-stack answers
/// IPv6-first and CDN-fronted names publish more AAAA records than A ones, so
/// the window can close before the only A record, and the callers
/// (`pick_vetted` with `IpFamily::Any`, which prefers IPv4 and falls back to
/// the first address) then dial or pin a wrong-family address. One slot per
/// family is therefore reserved first, and the remaining slots are filled in
/// resolver order; the returned list is still at most
/// [`MAX_VETTED_ADDRESSES`] long, so the per-candidate dial budget the cap
/// exists to bound is unchanged.
fn cap_vetted(addrs: &[IpAddr]) -> Vec<IpAddr> {
    if addrs.len() <= MAX_VETTED_ADDRESSES {
        return addrs.to_vec();
    }
    // Pass one: the first address of every family present — the slots the
    // cap must not delete.
    let mut reserved: Vec<usize> = [
        addrs.iter().position(IpAddr::is_ipv4),
        addrs.iter().position(IpAddr::is_ipv6),
    ]
    .into_iter()
    .flatten()
    .collect();
    reserved.sort_unstable();
    // Pass two: the rest of the cap goes to the earliest addresses that are
    // not reserved slots, then the whole set is walked in resolver order.
    let mut slots = addrs
        .iter()
        .enumerate()
        .filter(|(i, _)| !reserved.contains(i))
        .take(MAX_VETTED_ADDRESSES - reserved.len())
        .map(|(i, _)| i)
        .collect::<Vec<_>>();
    slots.extend_from_slice(&reserved);
    slots.sort_unstable();
    slots.into_iter().map(|i| addrs[i]).collect()
}

/// Upper bound on the vetted addresses returned per host. DNS can resolve
/// a feed-supplied name to dozens of A/AAAA records, and every returned
/// address becomes one dial attempt holding a probe concurrency permit
/// (T1) or one pinned entry in a meow batch config (T2), without the cap
/// one hostname stretches a whole probe cycle by
/// `count × connect_timeout` (security review f9). Real frontends resolve
/// to a handful of addresses, so the tail beyond the cap is dropped.
///
/// The bound is on the list, not on what a family may claim: the tail can
/// hold the only address of a family the caller needs, so the tail is
/// dropped in favour of the first address of each family, see
/// [`cap_vetted`]. Public so the probe can size its permits and logs
/// against the same bound.
pub const MAX_VETTED_ADDRESSES: usize = 4;

/// The IPv4 rules of [`check_ip`]: the std helpers first (loopback, RFC
/// 1918, link-local, unspecified, broadcast, multicast), then the
/// first-octet ranges the helpers do not cover.
fn check_ipv4(v4: Ipv4Addr) -> Result<(), DenialReason> {
    let [a, b, c, _] = v4.octets();
    if v4.is_loopback() {
        return Err(DenialReason::Loopback);
    }
    if v4.is_private() {
        return Err(DenialReason::Rfc1918);
    }
    if v4.is_link_local() {
        // Covers 169.254.0.0/16 including the 169.254.169.254 metadata IP.
        return Err(DenialReason::LinkLocal);
    }
    if v4.is_unspecified() {
        return Err(DenialReason::Unspecified);
    }
    if v4.is_broadcast() {
        return Err(DenialReason::Broadcast);
    }
    if v4.is_multicast() {
        // 224.0.0.0/4 (255.255.255.255 is caught by is_broadcast above).
        return Err(DenialReason::Multicast);
    }
    match a {
        0 => Err(DenialReason::ThisNetwork),
        100 if (b & 0xc0) == 64 => Err(DenialReason::Cgnat),
        198 if b == 18 || b == 19 => Err(DenialReason::Benchmark),
        // 192.0.0.0/24 (IETF protocol assignments) and 192.0.2.0/24
        // (TEST-NET-1). Only the two /24s are special space, the rest of
        // 192.0.0.0/16 is ordinary public address space.
        192 if b == 0 && c == 0 => Err(DenialReason::IetfProtocols),
        192 if b == 0 && c == 2 => Err(DenialReason::TestNet),
        198 if b == 51 && c == 100 => Err(DenialReason::TestNet),
        203 if b == 0 && c == 113 => Err(DenialReason::TestNet),
        // 240.0.0.0/4 reserved for future use — the whole block, so
        // 255.0.0.0/8 lands here too (the 255.255.255.255 broadcast is
        // caught by is_broadcast above).
        240..=255 => Err(DenialReason::Reserved),
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn public_ips_are_allowed() {
        for addr in [
            "8.8.8.8",
            "1.1.1.1",
            "93.184.216.34",
            "2606:4700:4700::1111",
        ] {
            assert!(check_ip(ip(addr), false).is_ok(), "{addr} must pass");
        }
    }

    #[test]
    fn private_ranges_are_blocked() {
        for addr in [
            "127.0.0.1",
            "10.0.0.1",
            "172.16.0.1",
            "172.31.255.255",
            "192.168.1.1",
            "169.254.169.254",
            "169.254.1.1",
            "0.0.0.0",
            "100.64.0.1",
            "100.127.255.255",
            "198.18.0.1",
            "192.0.0.1",
            "192.0.2.1",
            "198.51.100.1",
            "203.0.113.1",
            "224.0.0.1",
            "239.255.255.255",
            "255.255.255.255",
            // 240.0.0.0/4 reserved and 255.0.0.0/8 reserved (the broadcast
            // address above is part of the same /4 but has its own rule).
            "240.0.0.1",
            "240.255.255.255",
            "255.0.0.1",
            "::1",
            "::",
            "fe80::1",
            "fd00::1",
            "ff02::1",
            "::ffff:127.0.0.1",
            "::ffff:192.168.0.1",
            // IPv4-translated ::ffff:0:0:0/96 embedding 169.254.169.254.
            "::ffff:0:a9fe:a9fe",
            // NAT64 64:ff9b::/96 embedding 192.0.2.1.
            "64:ff9b::192.0.2.1",
            "64:ff9b::c000:201",
            // NAT64 local-use prefix 64:ff9b:1::/48.
            "64:ff9b:1:a9fe:a9fe::",
            "64:ff9b:1::1",
            // 2001:db8::/32 documentation and 2001:2::/48 benchmarking.
            "2001:db8::1",
            "2001:2::1",
            // Teredo 2001:0000::/32 with 169.254.169.254 as the client
            // address (the last 32 bits are the inverted client IPv4).
            "2001:0:808:808::5601:5601",
            // 6to4 2002::/16 embedding 127.0.0.1.
            "2002:7f00:1::",
        ] {
            assert!(check_ip(ip(addr), false).is_err(), "{addr} must be blocked");
        }
    }

    /// The IPv4-translated prefix `::ffff:0:0:0/96` is neither
    /// `to_ipv4_mapped()` nor `to_ipv4()`, so the embedded address was never
    /// vetted: the same metadata endpoint spelled that way walked past the
    /// policy.
    #[test]
    fn ipv4_translated_addresses_are_vetted_on_their_payload() {
        assert!(check_ip(ip("::ffff:0:a9fe:a9fe"), false).is_err());
        assert!(check_ip(ip("::ffff:0:7f00:1"), false).is_err());
        // A public payload stays reachable.
        assert!(check_ip(ip("::ffff:0:0808:0808"), false).is_ok());
    }

    /// Teredo `2001:0000::/32` carries the Teredo server (segments 2-3) and
    /// the client (segments 6-7, inverted) as plain IPv4 addresses. Both are
    /// vetted, either side of the tunnel is a dial target of its own.
    #[test]
    fn teredo_addresses_are_vetted_on_both_payloads() {
        // Client 169.254.169.254 (inverted: 86.1.86.1) behind a public
        // Teredo server.
        assert!(check_ip(ip("2001:0:808:808::5601:5601"), false).is_err());
        // Client 127.0.0.1 (inverted: 128.0.0.128).
        assert!(check_ip(ip("2001:0:808:808::8000:80"), false).is_err());
        // A private Teredo server is blocked on its own side.
        assert!(check_ip(ip("2001:0:a9fe:a9fe::f7f7:f7f7"), false).is_err());
        // A public server with a public client stays reachable.
        assert!(check_ip(ip("2001:0:808:808::f7f7:f7f7"), false).is_ok());
    }

    /// The NAT64 local-use prefix `64:ff9b:1::/48` (RFC 8215) is refused
    /// as a whole: the embedded IPv4 sits in octets 10 and 11 (RFC 6052
    /// §2.2), so a payload rule would depend on the byte order being right.
    #[test]
    fn the_local_use_nat64_prefix_is_refused() {
        assert!(check_ip(ip("64:ff9b:1:a9fe:a9fe::"), false).is_err());
        assert!(check_ip(ip("64:ff9b:1::1"), false).is_err());
        // The well-known /96 prefix of the same block stays payload-vetted.
        assert!(check_ip(ip("64:ff9b::c000:201"), false).is_err());
        assert!(check_ip(ip("64:ff9b::808:808"), false).is_ok());
    }

    /// Only `192.0.0.0/24` and `192.0.2.0/24` are special space; the rest
    /// of `192.0.0.0/16` is ordinary public address space and must stay
    /// reachable.
    #[test]
    fn the_special_192_blocks_are_narrow() {
        assert!(check_ip(ip("192.0.0.1"), false).is_err());
        assert!(check_ip(ip("192.0.2.1"), false).is_err());
        assert!(check_ip(ip("192.0.1.1"), false).is_ok());
        assert!(check_ip(ip("192.2.0.1"), false).is_ok());
        assert!(check_ip(ip("192.1.2.3"), false).is_ok());
    }

    /// Every IPv6 spelling of a blocked IPv4 address must be blocked, not
    /// just the mapped form: a feed line writing the metadata endpoint as
    /// `[::a9fe:a9fe]` must not walk past a policy that only vets
    /// `to_ipv4_mapped()`. The deprecated `fec0::/10` site-local block is
    /// in the same shape, routable unicast, never a public target.
    #[test]
    fn ipv4_compatible_and_site_local_v6_are_blocked() {
        for addr in [
            // ::/96 IPv4-compatible: 127.0.0.1, 169.254.169.254, 192.168.0.1
            "::7f00:1",
            "::a9fe:a9fe",
            "::c0a8:1",
            // fec0::/10 site-local, deprecated but unicast.
            "fec0::1",
            "feff:ffff::1",
        ] {
            assert!(check_ip(ip(addr), false).is_err(), "{addr} must be blocked");
        }
        // fec0::/10 ends at feff:ffff, whose upper neighbour ff00::/8 is
        // multicast, so there is no public address to check on that edge.
        // The lower neighbour febf:... is fe80::/10 link-local and stays
        // blocked under its own rule.
        assert!(check_ip(ip("febf:ffff::1"), false).is_err());
        // ::/96 with a public payload is public space too, the 6to4-style
        // payload rule, not a blanket prefix ban.
        assert!(check_ip(ip("::8.8.8.8"), false).is_ok());
    }

    #[test]
    fn transition_prefixes_with_public_payloads_pass() {
        // The 6to4 relay anycast payload is vetted on its own merits.
        assert!(check_ip(ip("2002:0808:0808::"), false).is_ok()); // 8.8.8.8
    }

    #[test]
    fn allow_private_flag_disables_checks() {
        assert!(check_ip(ip("127.0.0.1"), true).is_ok());
        assert!(check_ip(ip("169.254.169.254"), true).is_ok());
    }

    #[test]
    fn cgnat_boundary_values() {
        // 100.64.0.0/10 spans 100.64.0.0 – 100.127.255.255.
        assert!(check_ip(ip("100.63.255.255"), false).is_ok());
        assert!(check_ip(ip("100.128.0.0"), false).is_ok());
    }

    #[tokio::test]
    async fn probe_host_vetting_literals() {
        // Private literals and public literals vet without DNS, and the
        // refusal names its reason.
        let err = vet_probe_host_addrs("127.0.0.1", false, Duration::from_secs(5))
            .await
            .unwrap_err();
        assert!(err.contains("loopback"), "{err}");
        let err = vet_probe_host_addrs("::1", false, Duration::from_secs(5))
            .await
            .unwrap_err();
        assert!(err.contains("loopback"), "{err}");
        assert!(
            vet_probe_host_addrs("8.8.8.8", false, Duration::from_secs(5))
                .await
                .is_ok()
        );
        // The allow flag turns everything into a pass.
        assert!(
            vet_probe_host_addrs("10.0.0.5", true, Duration::from_secs(5))
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn probe_host_addrs_vetting_returns_dialable_addresses() {
        // A blocked literal never yields addresses.
        assert!(
            vet_probe_host_addrs("127.0.0.1", false, Duration::from_secs(5))
                .await
                .is_err()
        );
        // A public literal yields exactly itself, the caller dials this
        // address instead of re-resolving the hostname.
        let addrs = vet_probe_host_addrs("8.8.8.8", false, Duration::from_secs(5))
            .await
            .unwrap();
        assert_eq!(addrs, vec!["8.8.8.8".parse::<IpAddr>().unwrap()]);
        // An IPv6 literal is returned verbatim (no bracket gymnastics).
        let addrs = vet_probe_host_addrs("2606:4700:4700::1111", false, Duration::from_secs(5))
            .await
            .unwrap();
        assert_eq!(
            addrs,
            vec!["2606:4700:4700::1111".parse::<IpAddr>().unwrap()]
        );
    }

    /// A feed may spell an IPv6 address the URI way (`[2606:4700:4700::1111]`)
    /// or with a `%zone` scope id. Neither parses as an IP literal, so the
    /// host used to be taken for a name and sent to the resolver, and a
    /// bracketed loopback (`[::1]`) slipped past the literal gate.
    #[tokio::test]
    async fn probe_host_addrs_vetting_accepts_the_decorated_literal_forms() {
        let addrs = vet_probe_host_addrs("[2606:4700:4700::1111]", false, Duration::from_secs(5))
            .await
            .unwrap();
        assert_eq!(
            addrs,
            vec!["2606:4700:4700::1111".parse::<IpAddr>().unwrap()]
        );
        // The zone id is dropped, the address is still the literal.
        let addrs =
            vet_probe_host_addrs("[2606:4700:4700::1111%eth0]", false, Duration::from_secs(5))
                .await
                .unwrap();
        assert_eq!(
            addrs,
            vec!["2606:4700:4700::1111".parse::<IpAddr>().unwrap()]
        );
        // A decorated loopback is still blocked.
        assert!(
            vet_probe_host_addrs("[::1]", false, Duration::from_secs(5))
                .await
                .is_err()
        );
    }

    /// An unresolvable name must fail closed: the refusal is a DNS
    /// failure, not a policy pass. The guarantee needs the OS resolver, so
    /// it only runs on demand; the offline suite pins the same contract
    /// through `vet_resolved_addrs` (an empty answer is a refusal too).
    #[tokio::test]
    #[ignore = "needs live DNS: the name must reach the OS resolver"]
    async fn probe_host_vetting_unresolvable_name_fails_closed() {
        let err = vet_probe_host_addrs(
            "this-host-does-not-exist.invalid",
            false,
            Duration::from_secs(5),
        )
        .await
        .unwrap_err();
        assert!(err.contains("DNS resolution failed"), "{err}");
    }

    /// The localhost loopback must fail closed under the default policy,
    /// this is the exact primitive the F1 fix removes (a feed steering the
    /// probe at the host's own services). Checked without any network —
    /// the guarantee is the policy, not what a resolver happens to answer
    /// for "localhost" — and the assertion reads the reason itself.
    #[test]
    fn probe_host_vetting_localhost_hostname() {
        let err =
            vet_resolved_addrs("localhost", false, vec![ip("127.0.0.1"), ip("::1")]).unwrap_err();
        assert!(err.contains("localhost"), "{err}");
        assert!(err.contains("loopback"), "{err}");
    }

    /// The resolution timeout does not cancel the OS resolver, so the
    /// pipeline admits a bounded number of resolutions at a time instead of
    /// trusting the timeout to stop them.
    #[tokio::test]
    async fn concurrent_resolutions_are_capped() {
        let running = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let peak = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let mut tasks = Vec::new();
        for _ in 0..(MAX_CONCURRENT_RESOLUTIONS * 2) {
            let running = running.clone();
            let peak = peak.clone();
            tasks.push(tokio::spawn(async move {
                with_resolution_slot(async {
                    let now = running.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1;
                    peak.fetch_max(now, std::sync::atomic::Ordering::SeqCst);
                    tokio::time::sleep(Duration::from_millis(20)).await;
                    running.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
                })
                .await
                .unwrap();
            }));
        }
        for task in tasks {
            task.await.unwrap();
        }
        let seen = peak.load(std::sync::atomic::Ordering::SeqCst);
        assert!(
            seen <= MAX_CONCURRENT_RESOLUTIONS,
            "{seen} resolutions ran at once, the cap is {MAX_CONCURRENT_RESOLUTIONS}"
        );
        assert!(
            seen > 1,
            "the cap serialized every resolution ({seen} at once)"
        );
    }

    /// Drive the timer-fired branch directly by injecting a future that
    /// sleeps past `dns_timeout`. On macOS where `.invalid` short-circuits
    /// synchronously the original assertion (`|| "DNS resolution failed"`)
    /// would still pass even if the `tokio::time::timeout` wrapper were
    /// removed; this rewrite pins the timeout path itself.
    #[tokio::test]
    async fn lookup_with_timeout_returns_quickly_when_resolver_hangs() {
        use std::net::SocketAddr;
        let dns_timeout = Duration::from_millis(100);
        let start = std::time::Instant::now();
        let fut = async {
            tokio::time::sleep(dns_timeout + Duration::from_secs(5)).await;
            Ok(Vec::<SocketAddr>::new().into_iter())
        };
        let err = timeout_lookup("synthetic-host", dns_timeout, fut)
            .await
            .unwrap_err();
        let elapsed = start.elapsed();
        assert!(
            err.contains("timed out"),
            "expected timer-fired timeout error, got: {err}"
        );
        assert!(
            elapsed < std::time::Duration::from_millis(500),
            "lookup should not block past the OS resolver default, took {elapsed:?}"
        );
    }

    /// Empty-string hostname is universally invalid in `getaddrinfo` and
    /// `tokio::net::lookup_host`; the call deterministically returns an
    /// error so we can assert on the error wording without relying on the
    /// timer-fired branch.
    #[tokio::test]
    async fn lookup_with_empty_host_returns_dns_resolution_failed_err() {
        let err = lookup_with_timeout("", Duration::from_secs(5))
            .await
            .unwrap_err();
        assert!(
            err.contains("DNS resolution failed"),
            "expected DNS resolution failed error, got: {err}"
        );
    }

    /// The success branch of the inner wrapper: every `SocketAddr` of the
    /// answer loses its port and the resolver order is preserved.
    #[tokio::test]
    async fn timeout_lookup_drops_ports_and_keeps_the_answer_order() {
        use std::net::SocketAddr;
        let answer = vec![
            SocketAddr::new(ip("8.8.8.8"), 53),
            SocketAddr::new(ip("1.1.1.1"), 80),
            SocketAddr::new(ip("2606:4700:4700::1111"), 443),
        ];
        let ips = timeout_lookup(
            "resolver.example.com",
            Duration::from_secs(5),
            std::future::ready(Ok(answer.into_iter())),
        )
        .await
        .unwrap();
        assert_eq!(
            ips,
            vec![ip("8.8.8.8"), ip("1.1.1.1"), ip("2606:4700:4700::1111")]
        );
    }

    /// A hostile (or broken) resolver answer is cut at
    /// [`MAX_RESOLVED_ADDRESSES`] records, keeping the first ones.
    #[tokio::test]
    async fn timeout_lookup_truncates_a_hostile_answer() {
        use std::net::SocketAddr;
        let answer: Vec<SocketAddr> = (0..(MAX_RESOLVED_ADDRESSES + 8) as u8)
            .map(|i| SocketAddr::from((Ipv4Addr::new(93, 184, 216, i), 53)))
            .collect();
        let ips = timeout_lookup(
            "flood.example.com",
            Duration::from_secs(5),
            std::future::ready(Ok(answer.into_iter())),
        )
        .await
        .unwrap();
        assert_eq!(ips.len(), MAX_RESOLVED_ADDRESSES);
        assert_eq!(ips[0], ip("93.184.216.0"));
        assert_eq!(
            ips[MAX_RESOLVED_ADDRESSES - 1],
            ip(&format!("93.184.216.{}", MAX_RESOLVED_ADDRESSES - 1))
        );
    }

    /// The error texts embed the feed-supplied host: control characters
    /// (a `\r`, `\n` or ESC from a crafted feed line) are stripped and the
    /// host is truncated, so the journal cannot be forged or flooded.
    #[tokio::test]
    async fn timeout_lookup_sanitizes_the_host_in_errors() {
        let hostile = format!(
            "{}\r\n{}evil\x1b]0;pwned\x07",
            "a".repeat(300),
            "b".repeat(300)
        );
        let err = timeout_lookup(
            &hostile,
            Duration::from_millis(1),
            std::future::ready(Err::<Vec<std::net::SocketAddr>, std::io::Error>(
                std::io::Error::other("no resolver"),
            )),
        )
        .await
        .unwrap_err();
        assert!(!err.chars().any(char::is_control), "{err}");
        let overhead = "DNS resolution failed for ".len() + ": no resolver".len();
        assert!(
            err.chars().count() <= MAX_HOST_IN_MESSAGE + overhead,
            "the host must be truncated, got {err}"
        );
    }

    /// One refused address refuses the whole answer (fail closed: dialing
    /// the public half would leave the rebinding window open), and the
    /// error names the host and the reason.
    #[test]
    fn vet_resolved_addrs_refuses_a_mixed_answer() {
        let err = vet_resolved_addrs(
            "rebind.example.com",
            false,
            vec![ip("93.184.216.34"), ip("169.254.169.254")],
        )
        .unwrap_err();
        assert!(err.contains("rebind.example.com"), "{err}");
        assert!(err.contains("link-local"), "{err}");
    }

    /// An answer made of private space only is refused outright.
    #[test]
    fn vet_resolved_addrs_refuses_an_all_private_answer() {
        let err =
            vet_resolved_addrs("internal.example.com", false, vec![ip("10.0.0.1")]).unwrap_err();
        assert!(err.contains("internal.example.com"), "{err}");
        assert!(err.contains("RFC1918"), "{err}");
    }

    /// An empty answer is a refusal, not a pass.
    #[test]
    fn vet_resolved_addrs_refuses_an_empty_answer() {
        let err = vet_resolved_addrs("dead.example.com", false, Vec::new()).unwrap_err();
        assert!(err.contains("no addresses"), "{err}");
        assert!(err.contains("dead.example.com"), "{err}");
    }

    /// A public answer passes and is deduplicated in resolver order.
    #[test]
    fn vet_resolved_addrs_deduplicates_public_answers() {
        let vetted = vet_resolved_addrs(
            "cdn.example.com",
            false,
            vec![ip("8.8.8.8"), ip("8.8.8.8"), ip("1.1.1.1"), ip("8.8.8.8")],
        )
        .unwrap();
        assert_eq!(vetted, vec![ip("8.8.8.8"), ip("1.1.1.1")]);
    }

    /// The per-host cap must not delete an address family.
    ///
    /// `getaddrinfo` orders dual-stack answers IPv6-first (RFC 6724
    /// destination selection) and CDN-fronted names routinely publish more
    /// AAAA records than A ones, so a cap that simply truncates the
    /// combined list drops the only A record, and the probe callers then
    /// pick (`IpFamily::Any`, which prefers IPv4 and falls back to the
    /// first address) or pin a wrong-family address, or dial an IPv6
    /// address the host cannot reach from this network.
    #[test]
    fn vetted_address_cap_keeps_both_families() {
        let v4 = "142.251.153.119".parse::<IpAddr>().unwrap();
        let v6s: Vec<IpAddr> = (1..=6)
            .map(|i| format!("2606:4700:4700::{i:x}").parse().unwrap())
            .collect();

        // Six AAAA then one A, the ordering the resolver hands back.
        let mut lookup = v6s.clone();
        lookup.push(v4);
        let vetted = vet_resolved_addrs("cdn.example.com", false, lookup).unwrap();
        // The dial budget is bounded exactly, not just loosely, and the
        // composition is pinned: the first AAAA records in resolver order
        // plus the one A record at its reserved slot.
        assert_eq!(vetted.len(), MAX_VETTED_ADDRESSES);
        assert_eq!(vetted, vec![v6s[0], v6s[1], v6s[2], v4]);
        assert_eq!(
            vetted.iter().filter(|ip| ip.is_ipv4()).count(),
            1,
            "exactly one IPv4 must survive the cap, kept {vetted:?}"
        );
        assert_eq!(
            pick_vetted(&vetted, IpFamily::Any),
            Some(v4),
            "the caller must still be able to pick the A record out of {vetted:?}"
        );

        // The mirror image: five A records then one AAAA.
        let mut lookup: Vec<IpAddr> = (1..=5)
            .map(|i| format!("93.184.216.{i}").parse().unwrap())
            .collect();
        let only_v6 = "2606:4700:4700::1111".parse::<IpAddr>().unwrap();
        lookup.push(only_v6);
        let vetted = vet_resolved_addrs("cdn.example.com", false, lookup).unwrap();
        assert_eq!(vetted.len(), MAX_VETTED_ADDRESSES);
        assert_eq!(
            vetted,
            vec![
                ip("93.184.216.1"),
                ip("93.184.216.2"),
                ip("93.184.216.3"),
                only_v6
            ]
        );
        assert_eq!(pick_vetted(&vetted, IpFamily::Ipv6), Some(only_v6));

        // Resolver order survives the cap within a family, and a list that
        // already fits is returned untouched.
        let short = vec![v6s[0], v4, v6s[1]];
        let vetted = vet_resolved_addrs("small.example.com", false, short.clone()).unwrap();
        assert_eq!(vetted, short);
    }

    /// The module's own logic is the guarantee, not the std helpers it
    /// rests on: `check_ip` refuses representatives of every range the
    /// policy claims, the embedded-address helpers decode the payloads the
    /// transition rules vet, and `cap_vetted` returns the addresses it is
    /// given when the list already fits.
    #[test]
    fn policy_representatives_are_refused_and_helpers_decode_payloads() {
        for addr in [
            "127.0.0.1",       // is_loopback
            "169.254.169.254", // is_link_local, the metadata endpoint
            "224.0.0.1",       // is_multicast
            "0.0.0.0",         // is_unspecified
            "240.0.0.1",       // reserved, helper-free rule
            "255.0.0.1",       // reserved, helper-free rule
        ] {
            assert!(check_ip(ip(addr), false).is_err(), "{addr} must be blocked");
        }
        assert_eq!(embedded_v4(0x0808, 0x0808), Ipv4Addr::new(8, 8, 8, 8));
        assert_eq!(
            embedded_v4(0xa9fe, 0xa9fe),
            Ipv4Addr::new(169, 254, 169, 254)
        );
        // The Teredo client payload is bit-inverted before vetting.
        assert_eq!(
            inverted_v4(0x5601, 0x5601),
            Ipv4Addr::new(169, 254, 169, 254)
        );
        // A list that fits the cap comes back unchanged, in order.
        let fitting = vec![ip("2606:4700:4700::1111"), ip("8.8.8.8")];
        assert_eq!(cap_vetted(&fitting), fitting);
    }

    /// The docstring of [`check_ip`] claims a specific set of ranges; this
    /// pins the claim, so a rule added or removed without updating the
    /// docstring fails here.
    #[test]
    fn check_ip_rules_match_the_docstring_claims() {
        // The IPv4 half of the docstring: loopback, RFC 1918, link-local
        // (metadata), CGNAT, unspecified, broadcast, multicast,
        // benchmarking, TEST-NET space, reserved blocks.
        for addr in [
            "127.0.0.1",
            "10.9.9.9",
            "172.31.255.255",
            "192.168.0.1",
            "169.254.169.254",
            "100.100.100.100",
            "0.0.0.0",
            "0.1.2.3",
            "255.255.255.255",
            "224.0.0.1",
            "198.18.0.1",
            "192.0.2.1",
            "198.51.100.1",
            "203.0.113.1",
            "240.0.0.1",
            "255.0.0.1",
        ] {
            assert!(check_ip(ip(addr), false).is_err(), "{addr} must be blocked");
        }
        // The IPv6 half: loopback, link-local, unique-local, the
        // deprecated site-local block, multicast, the IPv6 TEST-NET and
        // benchmarking equivalents, the transition forms.
        for addr in [
            "::1",
            "::",
            "fe80::1",
            "fd00::1",
            "fec0::1",
            "ff02::1",
            "2001:db8::1",
            "2001:2::1",
            "::ffff:169.254.169.254",
            "64:ff9b:1::1",
            "2001:0:808:808::5601:5601",
            "2002:7f00:1::",
        ] {
            assert!(check_ip(ip(addr), false).is_err(), "{addr} must be blocked");
        }
    }

    /// The `DenialReason` texts are the journal voice of the policy: the
    /// reason names its range and carries a stable class code, and the
    /// texts keep the markers the probe tests and the journal lines match
    /// on.
    #[test]
    fn denial_reasons_carry_text_and_class_code() {
        assert!(DenialReason::Loopback.to_string().contains("loopback"));
        assert!(DenialReason::Rfc1918.to_string().contains("RFC1918"));
        assert!(DenialReason::LinkLocal.to_string().contains("link-local"));
        assert_eq!(DenialReason::Loopback.code(), "loopback");
        assert_eq!(DenialReason::Cgnat.code(), "cgnat");
        assert_eq!(DenialReason::TestNet.code(), "test_net");
        // Every reason has a distinct, non-empty class code.
        let codes: Vec<&'static str> = [
            DenialReason::Loopback,
            DenialReason::Rfc1918,
            DenialReason::LinkLocal,
            DenialReason::Cgnat,
            DenialReason::TestNet,
            DenialReason::Benchmark,
            DenialReason::IetfProtocols,
            DenialReason::Reserved,
            DenialReason::ThisNetwork,
            DenialReason::Unspecified,
            DenialReason::Broadcast,
            DenialReason::Multicast,
            DenialReason::UniqueLocal,
            DenialReason::SiteLocal,
            DenialReason::Nat64LocalUse,
        ]
        .iter()
        .map(|reason| reason.code())
        .collect();
        assert!(codes.iter().all(|code| !code.is_empty()));
        let mut sorted = codes.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(codes.len(), sorted.len(), "class codes must be distinct");
    }

    /// Mirrors `fetcher::pick_address_matrix` (crates/fumox-server/src/fetcher.rs)
    /// against the moved `pick_vetted` so both crates stay in sync.
    #[test]
    fn pick_vetted_matches_pick_address() {
        let v4 = "203.0.113.10".parse::<IpAddr>().unwrap();
        let v6 = "2001:db8::1".parse::<IpAddr>().unwrap();
        let both = vec![v6, v4];
        let v4_only = vec![v4];
        let v6_only = vec![v6];
        assert_eq!(pick_vetted(&both, IpFamily::Any), Some(v4));
        assert_eq!(
            pick_vetted(&v6_only, IpFamily::Any),
            Some(v6),
            "Any with only IPv6 falls back to the first address"
        );
        assert_eq!(pick_vetted(&both, IpFamily::Ipv4), Some(v4));
        assert_eq!(pick_vetted(&both, IpFamily::Ipv6), Some(v6));
        assert_eq!(pick_vetted(&v6_only, IpFamily::Ipv4), None);
        assert_eq!(pick_vetted(&v4_only, IpFamily::Ipv6), None);
        assert_eq!(pick_vetted(&[], IpFamily::Any), None);
    }
}
