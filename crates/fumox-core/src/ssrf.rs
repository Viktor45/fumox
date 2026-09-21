//! Shared SSRF address policy for both long-lived consumers of untrusted
//! network input: the server's source fetcher (`[admin].allow_private_urls`)
//! and the probe daemon's dial targets (`[probe].allow_private_targets`,
//! security review v2).
//!
//! Proxy hosts and ports arrive from remote subscription feeds and were
//! previously dialed by the probe with no vetting at all — a feed line like
//! `vless://uuid@169.254.169.254:80#x` turned the daemon into an internal
//! port scanner. Both call sites now run every candidate through
//! [`check_ip`] with the same blocklist.

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

/// Async DNS resolution with an operator-supplied timeout. Async DNS has no
/// built-in timeout — a hostile authoritative resolver can pin the runtime
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
pub async fn lookup_with_timeout(host: &str, dns_timeout: Duration) -> Result<Vec<IpAddr>, String> {
    timeout_lookup(host, dns_timeout, tokio::net::lookup_host((host, 0))).await
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
        Ok(Ok(iter)) => Ok(iter.into_iter().map(|sa| sa.ip()).collect()),
        Ok(Err(e)) => Err(format!("DNS resolution failed for {host}: {e}")),
        Err(_) => Err(format!(
            "DNS resolution timed out after {}s for {host}",
            dns_timeout.as_secs()
        )),
    }
}

/// Vet a single IP address against the shared SSRF policy.
///
/// With `allow_private = false` the following are rejected: loopback,
/// RFC 1918 private space, link-local (incl. the `169.254.169.254` cloud
/// metadata endpoint), CGNAT, unspecified, broadcast, multicast and
/// benchmark ranges, TEST-NET documentation space, plus their IPv6
/// equivalents, IPv4-mapped IPv6 addresses and the IPv6 transition
/// ranges that embed IPv4 (NAT64 `64:ff9b::/96`, 6to4 `2002::/16`).
pub fn check_ip(ip: IpAddr, allow_private: bool) -> Result<(), String> {
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
                return Err("loopback address".into());
            }
            if v6.is_unspecified() {
                return Err("unspecified address".into());
            }
            if v6.is_multicast() {
                // ff00::/8, includes the often-routable ff02::1.
                return Err("multicast address".into());
            }
            let segments = v6.segments();
            // fe80::/10 link-local
            if segments[0] & 0xffc0 == 0xfe80 {
                return Err("link-local address".into());
            }
            // fc00::/7 unique-local
            if segments[0] & 0xfe00 == 0xfc00 {
                return Err("unique-local address".into());
            }
            // NAT64 well-known prefix 64:ff9b::/96: the low 32 bits are an
            // IPv4 address — vet the embedded address, not the wrapper
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
            // 6to4 2002::/16: the next 32 bits are the encapsulated IPv4.
            if segments[0] == 0x2002 {
                return check_ipv4(embedded_v4(segments[1], segments[2]));
            }
            Ok(())
        }
    }
}

fn embedded_v4(high: u16, low: u16) -> Ipv4Addr {
    Ipv4Addr::new(
        (high >> 8) as u8,
        (high & 0xff) as u8,
        (low >> 8) as u8,
        (low & 0xff) as u8,
    )
}

/// Whether a proxy host may be dialed by the probe: IP literals are vetted
/// directly; hostnames are rejected when they cannot be resolved to a
/// vetted address (fail closed — an unresolvable name must never become a
/// probe target). Returns the full list of vetted addresses so the caller
/// can dial them directly instead of re-resolving the hostname — a second
/// DNS lookup between vet and connect would reopen the rebinding window
/// the first lookup just closed.
///
/// The async DNS resolution (`tokio::net::lookup_host`) is intentional:
/// every caller is on a Tokio task, and the previous synchronous
/// `std::net::ToSocketAddrs` blocked the runtime worker for the full
/// resolver timeout. The timeout is the operator's `[geo].dns_timeout_secs`
/// knob — see [`lookup_with_timeout`] for the rationale.
pub async fn vet_probe_host_addrs(
    host: &str,
    allow_private: bool,
    dns_timeout: Duration,
) -> Result<Vec<IpAddr>, String> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        check_ip(ip, allow_private)?;
        return Ok(vec![ip]);
    }
    let lookup = lookup_with_timeout(host, dns_timeout).await?;
    let mut addrs: Vec<IpAddr> = Vec::new();
    for ip in lookup {
        check_ip(ip, allow_private).map_err(|reason| format!("{host}: {reason}"))?;
        if !addrs.contains(&ip) {
            addrs.push(ip);
        }
    }
    if addrs.is_empty() {
        return Err(format!("DNS resolution returned no addresses for {host}"));
    }
    Ok(addrs)
}

/// Same policy as [`vet_probe_host_addrs`], discarding the resolved
/// addresses — for dial paths that cannot pin the IP (e.g. a tunnel engine
/// resolving the host itself).
pub async fn vet_probe_host(
    host: &str,
    allow_private: bool,
    dns_timeout: Duration,
) -> Result<(), String> {
    vet_probe_host_addrs(host, allow_private, dns_timeout)
        .await
        .map(|_| ())
}

fn check_ipv4(v4: Ipv4Addr) -> Result<(), String> {
    let [a, b, c, _] = v4.octets();
    if v4.is_loopback() {
        return Err("loopback address".into());
    }
    if v4.is_private() {
        return Err("RFC1918 private address".into());
    }
    if v4.is_link_local() {
        // Covers 169.254.0.0/16 including the 169.254.169.254 metadata IP.
        return Err("link-local address (cloud metadata range)".into());
    }
    if v4.is_unspecified() {
        return Err("unspecified address".into());
    }
    if v4.is_broadcast() {
        return Err("broadcast address".into());
    }
    if v4.is_multicast() {
        // 224.0.0.0/4 (255.255.255.255 is caught by is_broadcast above).
        return Err("multicast address".into());
    }
    match a {
        0 => Err("0.0.0.0/8".into()),
        100 if (b & 0xc0) == 64 => Err("100.64.0.0/10 CGNAT".into()),
        198 if b == 18 || b == 19 => Err("198.18.0.0/15 benchmarking".into()),
        192 if b == 0 => Err("192.0.0.0/24 IETF".into()),
        192 if b == 2 => Err("192.0.2.0/24 TEST-NET-1".into()),
        198 if b == 51 && c == 100 => Err("198.51.100.0/24 TEST-NET-2".into()),
        203 if b == 0 && c == 113 => Err("203.0.113.0/24 TEST-NET-3".into()),
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv6Addr;

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
            "::1",
            "::",
            "fe80::1",
            "fd00::1",
            "ff02::1",
            "::ffff:127.0.0.1",
            "::ffff:192.168.0.1",
            // NAT64 64:ff9b::/96 embedding 192.0.2.1.
            "64:ff9b::192.0.2.1",
            "64:ff9b::c000:201",
            // 6to4 2002::/16 embedding 127.0.0.1.
            "2002:7f00:1::",
        ] {
            assert!(check_ip(ip(addr), false).is_err(), "{addr} must be blocked");
        }
    }

    #[test]
    fn transition_prefixes_with_public_payloads_pass() {
        // The local-use U64 prefix 64:ff9b:1::/48 is public space (RFC 8215),
        // and the 6to4 relay anycast payload is vetted on its own merits.
        assert!(check_ip(ip("64:ff9b:1::c000:201"), false).is_ok());
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
        // Private literals and public literals vet without DNS.
        assert!(
            vet_probe_host("127.0.0.1", false, Duration::from_secs(5))
                .await
                .is_err()
        );
        assert!(
            vet_probe_host("::1", false, Duration::from_secs(5))
                .await
                .is_err()
        );
        assert!(
            vet_probe_host("8.8.8.8", false, Duration::from_secs(5))
                .await
                .is_ok()
        );
        // The allow flag turns everything into a pass.
        assert!(
            vet_probe_host("10.0.0.5", true, Duration::from_secs(5))
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
        // A public literal yields exactly itself — the caller dials this
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

    #[tokio::test]
    async fn probe_host_vetting_unresolvable_name_fails_closed() {
        let err = vet_probe_host(
            "this-host-does-not-exist.invalid",
            false,
            Duration::from_secs(5),
        )
        .await
        .unwrap_err();
        assert!(err.contains("DNS resolution failed"), "{err}");
    }

    /// The localhost loopback must fail closed under the default policy —
    /// this is the exact primitive the F1 fix removes (a feed steering the
    /// probe at the host's own services).
    #[tokio::test]
    async fn probe_host_vetting_localhost_hostname() {
        // "localhost" resolves to loopback on every test platform.
        assert!(
            vet_probe_host("localhost", false, Duration::from_secs(5))
                .await
                .is_err()
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

    #[test]
    fn ipv4_helpers_covered_ranges() {
        // Sanity on the std helpers we rely on.
        assert!(Ipv4Addr::new(127, 0, 0, 1).is_loopback());
        assert!(Ipv4Addr::new(169, 254, 169, 254).is_link_local());
        assert!(Ipv6Addr::LOCALHOST.is_loopback());
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
