//! Shared SSRF address policy for both long-lived consumers of untrusted
//! network input: the server's source fetcher (`[admin].allow_private_urls`)
//! and the probe daemon's dial targets (`[probe].allow_private_targets`,
//! security audit v2, 2026-09-09, finding F1).
//!
//! Proxy hosts and ports arrive from remote subscription feeds and were
//! previously dialed by the probe with no vetting at all — a feed line like
//! `vless://uuid@169.254.169.254:80#x` turned the daemon into an internal
//! port scanner. Both call sites now run every candidate through
//! [`check_ip`] with the same blocklist.

use std::net::{IpAddr, Ipv4Addr};

/// Vet a single IP address against the shared SSRF policy.
///
/// With `allow_private = false` the following are rejected: loopback,
/// RFC 1918 private space, link-local (incl. the `169.254.169.254` cloud
/// metadata endpoint), CGNAT, unspecified, broadcast and benchmark ranges,
/// plus their IPv6 equivalents and IPv4-mapped IPv6 addresses.
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
            let segments = v6.segments();
            // fe80::/10 link-local
            if segments[0] & 0xffc0 == 0xfe80 {
                return Err("link-local address".into());
            }
            // fc00::/7 unique-local
            if segments[0] & 0xfe00 == 0xfc00 {
                return Err("unique-local address".into());
            }
            Ok(())
        }
    }
}

/// Whether a proxy host may be dialed by the probe: IP literals are vetted
/// directly; hostnames are rejected when they cannot be resolved to a
/// vetted address (fail closed — an unresolvable name must never become a
/// probe target). Returns `Ok(())` or a human-readable reason.
///
/// The async DNS resolution (`tokio::net::lookup_host`) is intentional:
/// every caller is on a Tokio task, and the previous synchronous
/// `std::net::ToSocketAddrs` blocked the runtime worker for the full
/// resolver timeout (security audit, 2026-09-10, L1).
pub async fn vet_probe_host(host: &str, allow_private: bool) -> Result<(), String> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return check_ip(ip, allow_private);
    }
    let lookup = tokio::net::lookup_host((host, 0))
        .await
        .map_err(|e| format!("DNS resolution failed for {host}: {e}"))?;
    let mut vetted = false;
    for addr in lookup {
        vetted = true;
        check_ip(addr.ip(), allow_private).map_err(|reason| format!("{host}: {reason}"))?;
    }
    if !vetted {
        return Err(format!("DNS resolution returned no addresses for {host}"));
    }
    Ok(())
}

fn check_ipv4(v4: Ipv4Addr) -> Result<(), String> {
    let [a, b, _, _] = v4.octets();
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
    match a {
        0 => Err("0.0.0.0/8".into()),
        100 if (b & 0xc0) == 64 => Err("100.64.0.0/10 CGNAT".into()),
        198 if b == 18 || b == 19 => Err("198.18.0.0/15 benchmarking".into()),
        192 if b == 0 => Err("192.0.0.0/24 IETF".into()),
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
            "255.255.255.255",
            "::1",
            "::",
            "fe80::1",
            "fd00::1",
            "::ffff:127.0.0.1",
            "::ffff:192.168.0.1",
        ] {
            assert!(check_ip(ip(addr), false).is_err(), "{addr} must be blocked");
        }
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
        assert!(vet_probe_host("127.0.0.1", false).await.is_err());
        assert!(vet_probe_host("::1", false).await.is_err());
        assert!(vet_probe_host("8.8.8.8", false).await.is_ok());
        // The allow flag turns everything into a pass.
        assert!(vet_probe_host("10.0.0.5", true).await.is_ok());
    }

    #[tokio::test]
    async fn probe_host_vetting_unresolvable_name_fails_closed() {
        let err = vet_probe_host("this-host-does-not-exist.invalid", false)
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
        assert!(vet_probe_host("localhost", false).await.is_err());
    }

    #[test]
    fn ipv4_helpers_covered_ranges() {
        // Sanity on the std helpers we rely on.
        assert!(Ipv4Addr::new(127, 0, 0, 1).is_loopback());
        assert!(Ipv4Addr::new(169, 254, 169, 254).is_link_local());
        assert!(Ipv6Addr::LOCALHOST.is_loopback());
    }
}
