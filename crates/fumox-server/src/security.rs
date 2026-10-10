//! Security primitives shared by the public subscription listener and the
//! admin panel: the fixed-window rate limiter, the trusted-proxy client-IP
//! key, constant-time secret comparison, and the RFC 3339 timestamp helper
//! the subscription header block renders.
//!
//! They live at the crate root, outside the admin tree, because the public
//! listener's rate limiting and capability-token checks are security core,
//! not panel functionality: they must stay reachable no matter how the
//! admin surface is wired, and the public serving layer (`serve`,
//! `alive_export`) must not depend on the admin module for them.

use axum::http::HeaderMap;
use moka::future::Cache;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

/// Constant-time string equality (cookie/CSRF comparison). Also used for
/// the public capability-token checks (`/sub` access token, alive-export
/// link) so every secret comparison goes through one implementation.
pub fn ct_eq(a: &str, b: &str) -> bool {
    let (ab, bb) = (a.as_bytes(), b.as_bytes());
    if ab.len() != bb.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in ab.iter().zip(bb) {
        diff |= x ^ y;
    }
    diff == 0
}

/// What one forwarded header says about the request it arrived on.
///
/// The three cases are not interchangeable. "Found no address" and "found
/// an address" tell [`client_key`] nothing about who wrote the *other*
/// header, but "every entry was inside the trust list" does: a trusted
/// address can only sit in a chain there because a trusted hop put it
/// there, and a chain of nothing-but-trusted hops is a chain that ran
/// *past* the client address this header is responsible for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Forwarded {
    /// An originating-client address, with the trusted-CIDR entries
    /// skipped from the right.
    Client(IpAddr),
    /// The header parsed, and every entry it holds is inside the trust
    /// list. The client address is not in this header; something further
    /// left in the chain, or another header, carries it.
    TrustedChain,
    /// No usable entry at all: the header is absent, empty, unparsable, or
    /// deliberately opaque (`for=_hidden`, `for=unknown`). This is silence,
    /// not evidence. A proxy that hides the client writes exactly this,
    /// and so does a client that sends a header the proxy ignores.
    Nothing,
}

/// The one address a single header names, if it names one.
fn sole(found: Forwarded, peer: SocketAddr) -> IpAddr {
    match found {
        Forwarded::Client(ip) => ip,
        Forwarded::TrustedChain | Forwarded::Nothing => peer.ip(),
    }
}

/// Compute the per-IP rate-limit key for the incoming request.
///
/// The two early-return conditions stay as two distinct code paths (a single
/// combined `if` would let a "trusted proxy, peer is the trusted CIDR" case
/// fall through to header inspection when `trusted_cidrs` is empty by
/// accident, easy bug, hard to catch in review).
///
/// 1. No trusted proxies configured ⇒ never honor forwarded headers.
/// 2. Peer is not in any trusted CIDR ⇒ the header is untrusted.
/// 3. Trusted peer, exactly one forwarded header present ⇒ whatever that
///    one walk returns, else the peer.
/// 4. Both headers present and both name the same IP ⇒ that IP.
/// 5. Both present, one names a client and the other is an exhausted
///    trusted chain ⇒ that client.
/// 6. Anything else ⇒ the peer IP.
///
/// No precedence between `Forwarded` and `X-Forwarded-For`: the walk cannot
/// tell a proxy-appended entry from a client-authored one, so either fixed
/// order is client-chosen.
pub fn client_key(peer: SocketAddr, headers: &HeaderMap, trusted_cidrs: &[ipnet::IpNet]) -> IpAddr {
    // 1. No trusted proxies configured ⇒ never honor forwarded headers.
    if trusted_cidrs.is_empty() {
        return peer.ip();
    }
    // 2. Peer is not in any trusted CIDR ⇒ the header is untrusted.
    if !trusted_cidrs.iter().any(|net| net.contains(&peer.ip())) {
        return peer.ip();
    }
    // 3. Which headers the request carries, not which of them resolves.
    let xff = headers.contains_key("x-forwarded-for");
    let forwarded = headers.contains_key(axum::http::header::FORWARDED);
    match (xff, forwarded) {
        (true, false) => sole(walk_xff(headers, trusted_cidrs), peer),
        (false, true) => sole(walk_forwarded(headers, trusted_cidrs), peer),
        (false, false) => peer.ip(),
        // 4/5/6. Both present: agreement, an exhausted chain, or the peer.
        (true, true) => match (
            walk_xff(headers, trusted_cidrs),
            walk_forwarded(headers, trusted_cidrs),
        ) {
            (Forwarded::Client(a), Forwarded::Client(b)) if a == b => a,
            (Forwarded::Client(a), Forwarded::TrustedChain) => a,
            (Forwarded::TrustedChain, Forwarded::Client(b)) => b,
            _ => peer.ip(),
        },
    }
}

/// Walk `X-Forwarded-For` right-to-left, starting at the entry next to the
/// peer. A trusted proxy either appends the address it observed (nginx
/// `$proxy_add_x_forwarded_for`) or overwrites the header wholesale, so the
/// entry closest to the peer is the client IP as seen by the innermost
/// trusted hop; scanning toward the left then skips further trusted hops
/// and lands on the first non-trusted IP.
///
/// The previous left-to-right walk took the left-most non-trusted entry,
/// which is text the *client* chose whenever it sends its own XFF and the
/// trusted proxy merely appends: every forged IP then got a fresh
/// rate-limit window, voiding the login brute-force cap (security review
/// f2). The right-to-left walk is the mirror image, so a client-supplied
/// prefix no longer wins.
///
/// What the walk does *not* do is prove authorship: a single-element XFF
/// reads the same whether the trusted proxy appended it or the client
/// authored it, since the proxy either appends or overwrites. Callers must
/// therefore establish that the trusted hop writes this header at all,
/// see [`client_key`], which does it from which headers the request
/// carries. A trust list broad enough to contain the clients themselves
/// (`0.0.0.0/0`, a `/8` the subscribers live in) also erases the
/// distinction: their addresses are skipped like a hop's.
fn walk_xff(headers: &HeaderMap, trusted_cidrs: &[ipnet::IpNet]) -> Forwarded {
    let Some(value) = headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()) else {
        return Forwarded::Nothing;
    };
    let mut parsed_any = false;
    for raw in value.split(',').rev() {
        let candidate = raw.trim();
        let Ok(ip) = candidate.parse::<IpAddr>() else {
            continue;
        };
        parsed_any = true;
        if !trusted_cidrs.iter().any(|net| net.contains(&ip)) {
            return Forwarded::Client(ip);
        }
    }
    if parsed_any {
        Forwarded::TrustedChain
    } else {
        Forwarded::Nothing
    }
}

/// Walk RFC 7239 `Forwarded: for=…` right-to-left from the peer, the same
/// direction [`walk_xff`] scans and for the same reason, and to the same
/// three-way outcome. Bracket-strip IPv6 literals; skip `for=_hidden` and
/// `for=unknown`, both mean the proxy declined to name the client, which
/// is [`Forwarded::Nothing`], never a chain that ran past it.
fn walk_forwarded(headers: &HeaderMap, trusted_cidrs: &[ipnet::IpNet]) -> Forwarded {
    let Some(value) = headers
        .get(axum::http::header::FORWARDED)
        .and_then(|v| v.to_str().ok())
    else {
        return Forwarded::Nothing;
    };
    let mut parsed_any = false;
    for raw in value.split(',').rev() {
        let entry = raw.trim();
        // Each Forwarded element is a `;`-separated list of parameters.
        for param in entry.split(';') {
            let param = param.trim();
            let Some(value) = param.strip_prefix("for=") else {
                continue;
            };
            let value = strip_obfuscation(value.trim_matches('"'));
            if value == "_hidden" || value.eq_ignore_ascii_case("unknown") {
                break;
            }
            let value = value
                .strip_prefix('[')
                .and_then(|v| v.strip_suffix(']'))
                .unwrap_or(value);
            let Ok(ip) = value.parse::<IpAddr>() else {
                continue;
            };
            parsed_any = true;
            if !trusted_cidrs.iter().any(|net| net.contains(&ip)) {
                return Forwarded::Client(ip);
            }
        }
    }
    if parsed_any {
        Forwarded::TrustedChain
    } else {
        Forwarded::Nothing
    }
}

/// Strip RFC 7239 §6.3 obfuscation (`for=_hidden`, `for=unknown`) and
/// surrounding quotes; returns the inner value.
fn strip_obfuscation(value: &str) -> &str {
    value
        .strip_prefix('"')
        .and_then(|v| v.strip_suffix('"'))
        .unwrap_or(value)
}

/// Fixed-window per-key rate limiter: counters live in a moka cache with
/// TTL = window, so expiry resets the window.
pub struct RateLimiter {
    counters: Cache<String, Arc<AtomicU64>>,
    limit: u64,
}

impl RateLimiter {
    pub fn new(limit: u64, window: Duration) -> Self {
        Self {
            counters: Cache::builder()
                .max_capacity(100_000)
                .time_to_live(window)
                .build(),
            limit,
        }
    }

    /// Count one hit for `key`; `true` while under the limit.
    pub async fn allow(&self, key: &str) -> bool {
        // moka's future cache expects a future (not a closure) as the init.
        let init = async { Ok::<_, std::convert::Infallible>(Arc::new(AtomicU64::new(0))) };
        let Ok(counter) = self.counters.try_get_with(key.to_string(), init).await else {
            return true; // cache hiccup must not lock the admin out
        };
        counter.fetch_add(1, Ordering::Relaxed) < self.limit
    }

    /// Give one hit back to `key`'s window: the outer middleware counts
    /// every request up front, but a deeper rate-limiting layer may reject
    /// the very same request too, without the refund the outer window pays
    /// for hits the inner limiter already punished. Saturating: a refund for a key whose counter already
    /// expired with its window (or never existed) must never wrap below
    /// zero, the wrap would blacklist the key for the whole window.
    pub async fn refund(&self, key: &str) {
        let init = async { Ok::<_, std::convert::Infallible>(Arc::new(AtomicU64::new(0))) };
        if let Ok(counter) = self.counters.try_get_with(key.to_string(), init).await {
            let mut current = counter.load(Ordering::Relaxed);
            loop {
                match counter.compare_exchange_weak(
                    current,
                    current.saturating_sub(1),
                    Ordering::Relaxed,
                    Ordering::Relaxed,
                ) {
                    Ok(_) => break,
                    Err(observed) => current = observed,
                }
            }
        }
    }
}

/// RFC 3339 UTC form of a Unix timestamp (second precision). Shared by the
/// `datetime` attribute of the admin panel's `<time>` elements and the
/// timestamp line of the subscription header block in [`crate::serve`].
pub fn fmt_rfc3339_utc(ts: i64) -> String {
    const FMT: &[time::format_description::FormatItem<'static>] =
        time::macros::format_description!("[year]-[month]-[day]T[hour]:[minute]:[second]Z");
    match time::OffsetDateTime::from_unix_timestamp(ts) {
        Ok(dt) => dt.format(FMT).unwrap_or_else(|_| ts.to_string()),
        Err(_) => ts.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::header;

    fn trusted_v4() -> Vec<ipnet::IpNet> {
        vec!["2.2.2.2/32".parse().unwrap()]
    }

    fn peer() -> SocketAddr {
        "2.2.2.2:41000".parse().unwrap()
    }

    fn xff(value: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert("x-forwarded-for", value.parse().unwrap());
        h
    }

    fn fwd(value: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(header::FORWARDED, value.parse().unwrap());
        h
    }

    #[test]
    fn empty_trusted_list_never_honors_forwarded_headers() {
        // Even with XFF claiming 1.2.3.4, an unconfigured trust list must
        // not let the header influence the rate-limit key, peer wins.
        let h = xff("1.2.3.4");
        assert_eq!(client_key(peer(), &h, &[]), peer().ip());
        let h = fwd("for=1.2.3.4;proto=https");
        assert_eq!(client_key(peer(), &h, &[]), peer().ip());
    }

    #[test]
    fn trusted_peer_with_single_xff_hop_returns_that_ip() {
        let h = xff("1.2.3.4");
        assert_eq!(
            client_key(peer(), &h, &trusted_v4()),
            "1.2.3.4".parse::<IpAddr>().unwrap()
        );
    }

    #[test]
    fn trusted_peer_with_chain_walks_past_trusted_hops_right_to_left() {
        // Two trusted hops appended in order: the innermost observation is
        // at the right, so the walk starts there, skips the trusted entry
        // and lands on the client IP the first trusted proxy observed.
        let h = xff("1.1.1.1, 2.2.2.2");
        assert_eq!(
            client_key(peer(), &h, &trusted_v4()),
            "1.1.1.1".parse::<IpAddr>().unwrap()
        );
    }

    /// The attack from security review f2: the client sends its own XFF
    /// prefix and a trusted proxy *appends* the real client IP (nginx
    /// `$proxy_add_x_forwarded_for`). The left-most entry is attacker text;
    /// only the right-most non-trusted entry is what the trusted hop saw.
    /// The old left-to-right walk returned 6.6.6.6, giving every forged IP
    /// a fresh rate-limit window.
    #[test]
    fn client_supplied_xff_prefix_cannot_pick_the_rate_limit_key() {
        let h = xff("6.6.6.6, 9.9.9.9");
        assert_eq!(
            client_key(peer(), &h, &trusted_v4()),
            "9.9.9.9".parse::<IpAddr>().unwrap()
        );
    }

    /// Same property on the RFC 7239 header: a client-supplied `for=` in
    /// the left-most element is ignored when a trusted proxy appended its
    /// own observation at the right.
    #[test]
    fn client_supplied_forwarded_prefix_cannot_pick_the_rate_limit_key() {
        let h = fwd("for=6.6.6.6, for=9.9.9.9");
        assert_eq!(
            client_key(peer(), &h, &trusted_v4()),
            "9.9.9.9".parse::<IpAddr>().unwrap()
        );
    }

    /// A proxy configured for RFC 7239 (`Forwarded`) leaves
    /// `X-Forwarded-For` alone, so a client-supplied XFF is the only XFF
    /// text the request carries. The walk must not resolve on that header:
    /// five forged XFFs must not produce five rate-limit keys on the login
    /// brute-force cap. A second header beside the proxy's is evidence the
    /// client wrote it, so the two disagree and the key falls back to the
    /// trusted peer, the one bucket a client cannot pick its way out of.
    #[test]
    fn client_authored_xff_cannot_pick_the_key_when_the_proxy_writes_forwarded() {
        for forged in [
            "6.6.6.6",
            "1.1.1.1",
            "203.0.113.7",
            "198.51.100.9",
            "192.0.2.3",
        ] {
            let mut headers = HeaderMap::new();
            headers.insert(header::FORWARDED, "for=9.9.9.9".parse().unwrap());
            headers.insert("x-forwarded-for", forged.parse().unwrap());
            assert_eq!(
                client_key(peer(), &headers, &trusted_v4()),
                peer().ip(),
                "a client-authored XFF beside the proxy's Forwarded chose the key"
            );
        }
    }

    /// The mirror image: a proxy that writes only XFF (nginx, Caddy) and
    /// forwards the client's `Forwarded` verbatim, the default of
    /// `proxy_pass_request_headers on`. A single client-authored `for=` is
    /// non-trusted, so the walk over it hands the attacker the key.
    #[test]
    fn client_authored_forwarded_cannot_pick_the_key_when_the_proxy_writes_xff() {
        for forged in [
            "for=6.6.6.6",
            "for=1.1.1.1",
            "for=203.0.113.7;proto=https",
            "for=\"[2001:db8::9]\"",
        ] {
            let mut headers = HeaderMap::new();
            headers.insert("x-forwarded-for", "9.9.9.9".parse().unwrap());
            headers.insert(header::FORWARDED, forged.parse().unwrap());
            assert_eq!(
                client_key(peer(), &headers, &trusted_v4()),
                peer().ip(),
                "a client-authored Forwarded beside the proxy's XFF chose the key"
            );
        }
    }

    /// A `Forwarded` the trusted proxy wrote but that yields no address
    /// (`for=_hidden`) is still evidence about which header the proxy
    /// writes: falling through to the XFF the proxy never touches is the
    /// original bypass with the sign flipped.
    #[test]
    fn a_hidden_forwarded_entry_never_falls_back_to_the_xff() {
        let mut headers = HeaderMap::new();
        headers.insert(header::FORWARDED, "for=_hidden".parse().unwrap());
        headers.insert("x-forwarded-for", "6.6.6.6".parse().unwrap());
        assert_eq!(client_key(peer(), &headers, &trusted_v4()), peer().ip());
    }

    /// A proxy that writes both headers (and appends to both) names the
    /// same client in each, so the two corroborate each other and the key
    /// is that client. This is the only case where a request carrying both
    /// headers resolves to anything other than the peer.
    #[test]
    fn headers_that_agree_name_the_client() {
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", "9.9.9.9".parse().unwrap());
        headers.insert(
            header::FORWARDED,
            "for=9.9.9.9;proto=https".parse().unwrap(),
        );
        assert_eq!(
            client_key(peer(), &headers, &trusted_v4()),
            "9.9.9.9".parse::<IpAddr>().unwrap()
        );
    }

    /// A two-proxy chain where the outer hop writes `Forwarded` and the
    /// inner one (the peer) writes XFF: Traefik in front of nginx, both in
    /// `trust_proxy_ips`. The XFF nginx appends is Traefik's own address,
    /// inside the trust list, so the walk returns nothing at all and the
    /// client address only exists in the `Forwarded` the outer hop wrote.
    /// Treating "one header found nothing" as a forged pair collapsed this
    /// whole deployment onto the peer's bucket, which for `/admin/login` is
    /// one shared 5-per-minute window.
    #[test]
    fn a_two_proxy_chain_writing_one_header_each_keeps_the_client_key() {
        let trusted: Vec<ipnet::IpNet> = vec![
            "2.2.2.2/32".parse().unwrap(), // nginx, the peer
            "10.0.0.0/8".parse().unwrap(), // Traefik, the outer hop
        ];
        let mut headers = HeaderMap::new();
        // nginx appends the address it observed from Traefik.
        headers.insert("x-forwarded-for", "10.0.0.7".parse().unwrap());
        // Traefik writes the address it observed from the client.
        headers.insert(
            header::FORWARDED,
            "for=9.9.9.9;proto=https".parse().unwrap(),
        );
        assert_eq!(
            client_key(peer(), &headers, &trusted),
            "9.9.9.9".parse::<IpAddr>().unwrap(),
            "a trusted chain through two proxies must keep its per-client key"
        );
    }

    /// A chain the walk can exhaust, every XFF entry inside the trust list
    /// , beside a header that names a client is the one disagreement that
    /// is not a forgery: an all-trusted XFF is evidence that the peer wrote
    /// it (only a trusted hop's appending puts a trusted address there, and
    /// the client then sits further left, in the other header). The mirror
    /// shape is pinned too, so neither direction is accidental.
    #[test]
    fn an_exhausted_chain_defers_to_the_header_that_names_a_client() {
        let trusted: Vec<ipnet::IpNet> =
            vec!["2.2.2.2/32".parse().unwrap(), "10.0.0.0/8".parse().unwrap()];
        // XFF exhausted on trusted entries, `Forwarded` exhausted on one.
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", "10.0.0.7, 10.0.0.8".parse().unwrap());
        headers.insert(header::FORWARDED, "for=10.0.0.9".parse().unwrap());
        assert_eq!(client_key(peer(), &headers, &trusted), peer().ip());

        // Mirror: the `Forwarded` chain is the exhausted one.
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", "9.9.9.9".parse().unwrap());
        headers.insert(
            header::FORWARDED,
            "for=9.9.9.9, for=10.0.0.8".parse().unwrap(),
        );
        assert_eq!(
            client_key(peer(), &headers, &trusted),
            "9.9.9.9".parse::<IpAddr>().unwrap()
        );
    }

    /// The remaining disagreement, pinned deliberately: a client that sends
    /// its own `Forwarded` (or arrives behind a proxy that writes only
    /// `Forwarded`) beside an XFF-writing peer is indistinguishable from a
    /// forgery, so the key is the peer's. That bucket is *shared*, one
    /// window for everything that lands there, which is the documented cost
    /// of failing closed here, never a bypass: the key is still not the
    /// client's choice.
    #[test]
    fn a_disagreeing_client_forwarded_lands_in_the_shared_peer_bucket() {
        let mut headers = HeaderMap::new();
        // The peer (nginx) writes XFF with the address it observed.
        headers.insert("x-forwarded-for", "9.9.9.9".parse().unwrap());
        // The client, or a proxy in front of nginx, writes this one.
        headers.insert(header::FORWARDED, "for=6.6.6.6".parse().unwrap());
        assert_eq!(client_key(peer(), &headers, &trusted_v4()), peer().ip());
    }

    /// The same request with only the proxy's XFF and no `Forwarded` at all
    /// still resolves through the XFF walk: a legacy proxy that writes
    /// XFF only must keep its per-client rate-limit key.
    #[test]
    fn xff_is_still_honored_when_no_forwarded_is_present() {
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", "6.6.6.6, 9.9.9.9".parse().unwrap());
        assert_eq!(
            client_key(peer(), &headers, &trusted_v4()),
            "9.9.9.9".parse::<IpAddr>().unwrap()
        );
    }

    #[test]
    fn chain_with_all_trusted_entries_falls_back_to_peer() {
        // Both hops are inside the trusted CIDR, walking past them all
        // leaves nothing usable, so the peer wins.
        let h = xff("2.2.2.2, 2.2.2.2");
        assert_eq!(client_key(peer(), &h, &trusted_v4()), peer().ip());
    }

    #[test]
    fn untrusted_peer_ignores_xff_and_keeps_peer() {
        let untrusted_peer: SocketAddr = "9.9.9.9:41000".parse().unwrap();
        let h = xff("1.2.3.4");
        assert_eq!(
            client_key(untrusted_peer, &h, &trusted_v4()),
            untrusted_peer.ip()
        );
    }

    #[test]
    fn trusted_peer_with_rfc7239_forwarded_returns_first_untrusted_for() {
        let h = fwd("for=1.2.3.4;proto=https");
        assert_eq!(
            client_key(peer(), &h, &trusted_v4()),
            "1.2.3.4".parse::<IpAddr>().unwrap()
        );
    }

    #[test]
    fn forwarded_for_hidden_falls_back_to_peer() {
        let h = fwd("for=_hidden");
        assert_eq!(client_key(peer(), &h, &trusted_v4()), peer().ip());
    }

    #[test]
    fn forwarded_walks_right_to_left_past_trusted_for_entries() {
        // The innermost trusted proxy's observation is on the right
        // (for=2.2.2.2); the walk starts there, skips the trusted entry and
        // returns the client IP the first trusted hop observed (1.1.1.1).
        let h = fwd("for=1.1.1.1, for=2.2.2.2");
        assert_eq!(
            client_key(peer(), &h, &trusted_v4()),
            "1.1.1.1".parse::<IpAddr>().unwrap()
        );
    }

    #[test]
    fn forwarded_with_bracketed_ipv6_literal_is_bracket_stripped() {
        let h = fwd("for=[2001:db8::1];proto=https");
        assert_eq!(
            client_key(peer(), &h, &trusted_v4()),
            "2001:db8::1".parse::<IpAddr>().unwrap()
        );
    }

    /// RFC 7239 §4 does not pin parameter ordering. A non-`for=` parameter
    /// appearing before the `for=` must not abort the walk, only the `for=`
    /// parameter is load-bearing for the originating-client lookup. The
    /// audit's reported shape was `Forwarded: proto=https;for=1.2.3.4` and
    /// the pre-fix code bailed at `proto=https` (`?` on `strip_prefix`).
    #[test]
    fn walk_forwarded_takes_first_for_param_regardless_of_position() {
        let h = fwd("proto=https;for=1.2.3.4");
        assert_eq!(
            client_key(peer(), &h, &trusted_v4()),
            "1.2.3.4".parse::<IpAddr>().unwrap()
        );
        // Also pin a chain shape with a non-`for=` parameter in the same
        // entry to make sure the loop walks the whole `;`-separated list.
        let h = fwd("for=1.2.3.4;by=2.2.2.2;proto=https");
        assert_eq!(
            client_key(peer(), &h, &trusted_v4()),
            "1.2.3.4".parse::<IpAddr>().unwrap()
        );
    }

    #[tokio::test]
    async fn rate_limiter_enforces_the_limit_per_key() {
        let limiter = RateLimiter::new(3, Duration::from_secs(60));
        assert!(limiter.allow("ip1").await);
        assert!(limiter.allow("ip1").await);
        assert!(limiter.allow("ip1").await);
        assert!(!limiter.allow("ip1").await);
        // Other keys are independent.
        assert!(limiter.allow("ip2").await);
    }

    /// The window *is* the reset mechanism: there is no explicit
    /// bookkeeping, the moka TTL expiring the counter is what opens the
    /// quota again. A real (short) sleep: the TTL runs on moka's own
    /// clock, so a paused tokio clock would not move it.
    #[tokio::test]
    async fn rate_limiter_reopens_after_the_window() {
        let limiter = RateLimiter::new(1, Duration::from_millis(50));
        assert!(limiter.allow("ip1").await);
        assert!(!limiter.allow("ip1").await, "window is exhausted");
        tokio::time::sleep(Duration::from_millis(500)).await;
        assert!(
            limiter.allow("ip1").await,
            "the counter must expire with its TTL and reopen the quota"
        );
    }

    /// A refunded hit opens the window slot it consumed: a request that passed this limiter but was rejected by
    /// a deeper one must not cost this window anything.
    #[tokio::test]
    async fn rate_limiter_refund_returns_the_hit_to_the_window() {
        let limiter = RateLimiter::new(2, Duration::from_secs(60));
        // One request counted here, rejected deeper, the refund leaves
        // the window exactly as it was before the request arrived.
        assert!(limiter.allow("ip1").await);
        limiter.refund("ip1").await;

        // The full quota is still available.
        assert!(limiter.allow("ip1").await);
        assert!(limiter.allow("ip1").await);
        assert!(!limiter.allow("ip1").await);

        // Refunding a key that was never counted is a no-op, not a credit:
        // a below-zero wrap (fetch_sub on 0) would blacklist the key for
        // the whole window instead.
        limiter.refund("never-seen").await;
        assert!(limiter.allow("never-seen").await);
        assert!(limiter.allow("never-seen").await);
        assert!(!limiter.allow("never-seen").await);
    }
}
