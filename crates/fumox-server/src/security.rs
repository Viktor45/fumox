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
use fumox_core::config::TrustedHeader;
use moka::future::Cache;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::LazyLock;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

/// Constant-time string equality (cookie/CSRF comparison). Also used for
/// the public capability-token checks (`/sub` access token, alive-export
/// link) so every secret comparison goes through one implementation.
///
/// The implementation lives in `fumox-core`, next to the token hashing it
/// has to stay consistent with: the profile access token is verified
/// against its stored hash there.
pub fn ct_eq(a: &str, b: &str) -> bool {
    fumox_core::token::ct_eq(a, b)
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

/// Where a rate-limit key came from: a forwarding header the trusted peer
/// vouched for, or the peer address itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientKeySource {
    /// The key names the client a trusted chain forwarded.
    Forwarded,
    /// The key is the peer address by design: no forwarding header is
    /// declared, no trusted proxy is configured, or the peer is not
    /// trusted to speak for a client. This is the best-available key,
    /// not a degradation.
    Peer,
    /// The operator declared a forwarding header and the peer is trusted,
    /// but the walks still produced no client address: the key fell back
    /// to the peer, and every client behind that peer shares one
    /// rate-limit bucket. The rate-limit middlewares warn about this
    /// once per window, see [`warn_shared_peer_bucket`].
    PeerFallback,
}

/// The one address a single header names, if it names one, and where it
/// came from. Past [`client_key`]'s gates a peer fallback is a degraded
/// key ([`ClientKeySource::PeerFallback`]), not the designed outcome.
fn sole(found: Forwarded, peer: SocketAddr) -> (IpAddr, ClientKeySource) {
    match found {
        Forwarded::Client(ip) => (ip, ClientKeySource::Forwarded),
        Forwarded::TrustedChain | Forwarded::Nothing => (peer.ip(), ClientKeySource::PeerFallback),
    }
}

/// Compute the per-IP rate-limit key for the incoming request.
///
/// The operator's declaration ([`TrustedHeader`]) decides which header is
/// read at all; the trusted CIDR list decides whether the peer may speak
/// for a client. Both gates are closed by default:
///
/// 1. No forwarding header declared ⇒ the peer address is the client.
/// 2. No trusted proxies configured ⇒ never honor forwarded headers.
/// 3. Peer is not in any trusted CIDR ⇒ the header is untrusted.
/// 4. `xff` declared ⇒ whatever the `X-Forwarded-For` walk returns, else
///    the peer. A `Forwarded` header beside it is ignored: it is text
///    nobody vouched for.
/// 5. `forwarded` declared ⇒ the same walk over the RFC 7239 header,
///    `X-Forwarded-For` ignored.
/// 6. `both` declared ⇒ the two walks must name the same address, or the
///    peer wins.
///
/// No precedence between `Forwarded` and `X-Forwarded-For`: the walk cannot
/// tell a proxy-appended entry from a client-authored one, so either fixed
/// order is client-chosen.
///
/// The returned [`ClientKeySource`] says where the key came from: rules
/// 1–3 make the peer the key by design ([`ClientKeySource::Peer`]), past
/// them a peer key is what the walks degraded to
/// ([`ClientKeySource::PeerFallback`]).
pub fn client_key(
    peer: SocketAddr,
    headers: &HeaderMap,
    trusted_cidrs: &[ipnet::IpNet],
    trusted_header: TrustedHeader,
) -> (IpAddr, ClientKeySource) {
    // 1. The operator named no header: nothing a client sends can move the
    // key off the peer address.
    if trusted_header == TrustedHeader::None {
        return (peer.ip(), ClientKeySource::Peer);
    }
    // 2. No trusted proxies configured ⇒ never honor forwarded headers.
    if trusted_cidrs.is_empty() {
        return (peer.ip(), ClientKeySource::Peer);
    }
    // 3. Peer is not in any trusted CIDR ⇒ the header is untrusted.
    if !trusted_cidrs.iter().any(|net| net.contains(&peer.ip())) {
        return (peer.ip(), ClientKeySource::Peer);
    }
    match trusted_header {
        TrustedHeader::None => (peer.ip(), ClientKeySource::Peer),
        TrustedHeader::Xff => sole(walk_xff(headers, trusted_cidrs), peer),
        TrustedHeader::Forwarded => sole(walk_forwarded(headers, trusted_cidrs), peer),
        TrustedHeader::Both => match (
            walk_xff(headers, trusted_cidrs),
            walk_forwarded(headers, trusted_cidrs),
        ) {
            (Forwarded::Client(a), Forwarded::Client(b)) if a == b => {
                (a, ClientKeySource::Forwarded)
            }
            (Forwarded::Client(a), Forwarded::TrustedChain) => (a, ClientKeySource::Forwarded),
            (Forwarded::TrustedChain, Forwarded::Client(b)) => (b, ClientKeySource::Forwarded),
            _ => (peer.ip(), ClientKeySource::PeerFallback),
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
/// see [`client_key`], which does it from the operator's declaration
/// ([`TrustedHeader`]). A trust list broad enough to contain the clients
/// themselves (`0.0.0.0/0`, a `/8` the subscribers live in) also erases the
/// distinction: their addresses are skipped like a hop's.
fn walk_xff(headers: &HeaderMap, trusted_cidrs: &[ipnet::IpNet]) -> Forwarded {
    // RFC 7230 §3.2.2: a repeated header field is equivalent to one field
    // with the values joined by commas. Reading only the first value would
    // silently drop the entries a proxy appended after it.
    let value = headers
        .get_all("x-forwarded-for")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .collect::<Vec<_>>()
        .join(", ");
    if value.is_empty() {
        return Forwarded::Nothing;
    }
    let mut parsed_any = false;
    for raw in value.split(',').rev() {
        let candidate = strip_port(raw.trim());
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
/// three-way outcome. Port-suffixed literals (`ip:port`,
/// `[v6]:port`) are reduced to the bare address; skip `for=_hidden` and
/// `for=unknown`, both mean the proxy declined to name the client, which
/// is [`Forwarded::Nothing`], never a chain that ran past it.
fn walk_forwarded(headers: &HeaderMap, trusted_cidrs: &[ipnet::IpNet]) -> Forwarded {
    // Repeated `Forwarded` headers are one field with comma-joined values.
    let value = headers
        .get_all(axum::http::header::FORWARDED)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .collect::<Vec<_>>()
        .join(", ");
    if value.is_empty() {
        return Forwarded::Nothing;
    }
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
            let Ok(ip) = strip_port(value).parse::<IpAddr>() else {
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

/// Reduce one header entry to a bare IP literal: a proxy may append the
/// port it observed (`1.2.3.4:8080`, `[2001:db8::1]:443`), which
/// `IpAddr::parse` rejects and the walk would silently skip. IPv4 (or an
/// unbracketed entry) is cut at its single colon; a bracketed IPv6
/// literal loses its brackets and the port behind them; a bare IPv6
/// literal always carries at least two colons, so a port is never cut
/// from one. Whatever still does not parse is skipped by the caller,
/// fail-closed as before.
fn strip_port(entry: &str) -> &str {
    if entry.starts_with('[') {
        return entry
            .split_once(']')
            .and_then(|(ip, _)| ip.strip_prefix('['))
            .unwrap_or(entry);
    }
    match entry.matches(':').count() {
        0 => entry,
        1 => entry.split_once(':').map_or(entry, |(ip, _)| ip),
        _ => entry,
    }
}

/// Strip surrounding quotes from a `for=` value; `_hidden`/`unknown` are
/// recognised by the caller ([`walk_forwarded`]), this only unwraps
/// quoting.
fn strip_obfuscation(value: &str) -> &str {
    value
        .strip_prefix('"')
        .and_then(|v| v.strip_suffix('"'))
        .unwrap_or(value)
}

/// Distinct keys the shared-peer-bucket warning tracks between warns,
/// bounding the memory a flood of distinct peers could pin.
const PEER_BUCKET_MAX_TRACKED: usize = 1_024;

/// The rate-limit keys a shared-bucket warning was emitted for, with the
/// instant the current window for that key began.
static PEER_BUCKET_WARNS: LazyLock<Mutex<HashMap<String, Instant>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// Warn that the rate-limit `key` degraded to the shared peer bucket
/// ([`ClientKeySource::PeerFallback`]): a trusted peer's forwarding data
/// produced no client address, so every client behind that peer now
/// shares one rate-limit window. One warn per key per `window` — the
/// limiter's own window is the natural horizon, since the condition holds
/// for every request it covers — not one warn per request.
pub fn warn_shared_peer_bucket(key: &str, window: Duration) {
    let now = Instant::now();
    let mut seen = PEER_BUCKET_WARNS
        .lock()
        .unwrap_or_else(|poison| poison.into_inner());
    if seen.len() >= PEER_BUCKET_MAX_TRACKED {
        // Bound the map, not the warnings: entries whose window elapsed
        // go first, the keys they held warn again from scratch; past that
        // the oldest entry is dropped.
        seen.retain(|_, began| now.duration_since(*began) < window);
        if seen.len() >= PEER_BUCKET_MAX_TRACKED
            && let Some(oldest) = seen
                .iter()
                .min_by_key(|(_, began)| **began)
                .map(|(key, _)| key.clone())
        {
            seen.remove(&oldest);
        }
    }
    if seen
        .get(key)
        .is_some_and(|began| now.duration_since(*began) < window)
    {
        return;
    }
    seen.insert(key.to_string(), now);
    tracing::warn!(
        client = %key,
        "rate-limit key degraded to the shared peer bucket: every client \
         behind it shares one window"
    );
}

/// Default number of keys a limiter's counter cache holds.
const DEFAULT_MAX_KEYS: u64 = 100_000;

/// The data a warn window accumulated since its last rollover: the
/// rejections it dropped to debug and how many there were in total. The
/// caller renders the summary sentence — the two registries word theirs
/// differently (auth failures vs. host-gate rejections), but the facts
/// are the same.
#[derive(Debug, Default)]
pub struct WarnSummary {
    /// Rejections the window dropped to debug, named ones first.
    pub suppressed: Vec<String>,
    /// How many rejections the window dropped to debug, suppressed names
    /// included.
    pub suppressed_total: u64,
}

/// One bounded per-key warn registry, the shape both public-listener
/// coalescers share: a failed secret check (`serve`'s auth-failure log)
/// and a host-gate rejection (`alive_export`'s host log) warn once per key
/// per window, then drop to debug, under a per-window budget that stops a
/// flood from mirroring itself into the log, with a rollover summary that
/// names what the window swallowed.
///
/// The registry owns three caps: the window, the number of distinct keys
/// tracked (bounding memory; hitting it never silences new keys), and the
/// warn budget per window. Eviction is O(log n) (an insert-order map,
/// oldest slot first), and a key that returns after its own quiet window
/// re-enters tracking and spends the same budget as a new one — a
/// campaign that rotates through a small key set cannot out-warn the
/// budget by waiting.
#[derive(Debug)]
pub struct WarnRegistry {
    window: Duration,
    max_tracked: usize,
    max_warns: u32,
    /// Tracked keys: when they were last seen and the slot they hold in
    /// the eviction order.
    seen: HashMap<String, (Instant, u64)>,
    /// The tracked keys by slot number, so the oldest one is dropped
    /// without a scan over the whole map.
    order: std::collections::BTreeMap<u64, String>,
    /// Next slot number handed out.
    next_slot: u64,
    /// Start of the current warn window, and how much of `max_warns` it
    /// has spent.
    window_start: Option<Instant>,
    warns_emitted: u32,
    /// What the current window dropped to debug, for the rollover summary.
    suppressed: WarnSummary,
}

impl WarnRegistry {
    pub fn new(window: Duration, max_tracked: usize, max_warns: u32) -> Self {
        Self {
            window,
            max_tracked,
            max_warns,
            seen: HashMap::new(),
            order: std::collections::BTreeMap::new(),
            next_slot: 0,
            window_start: None,
            warns_emitted: 0,
            suppressed: WarnSummary::default(),
        }
    }

    /// Number of keys currently tracked (the memory bound, for tests).
    #[cfg(test)]
    pub fn len_tracked(&self) -> usize {
        self.seen.len()
    }

    /// Warns spent in the current window (for tests).
    #[cfg(test)]
    pub fn warns_emitted(&self) -> u32 {
        self.warns_emitted
    }

    /// Roll the window over if it has elapsed, handing back the summary of
    /// the window that just closed (when it suppressed anything).
    fn roll_window(&mut self, now: Instant) -> Option<WarnSummary> {
        let Some(start) = self.window_start else {
            // First failure ever: open the window, report nothing.
            self.window_start = Some(now);
            return None;
        };
        if now.duration_since(start) < self.window {
            return None;
        }
        let summary = std::mem::take(&mut self.suppressed);
        self.warns_emitted = 0;
        self.window_start = Some(now);
        (summary.suppressed_total > 0).then_some(summary)
    }

    /// Remember `key` as seen, dropping the oldest tracked key when the
    /// set is full. The order map makes that drop O(log n) instead of a
    /// scan over every tracked key.
    fn track(&mut self, key: &str, now: Instant) {
        if !self.seen.contains_key(key) {
            if self.seen.len() >= self.max_tracked {
                // Bound the map, not the warnings: drop the oldest entry.
                if let Some((_, oldest)) = self.order.pop_first() {
                    self.seen.remove(&oldest);
                }
            }
            self.next_slot += 1;
            let slot = self.next_slot;
            self.seen.insert(key.to_string(), (now, slot));
            self.order.insert(slot, key.to_string());
            return;
        }
        // A key that comes back after its own window keeps its slot: only
        // the quiet window restarts.
        let slot = self.seen.get(key).map(|(_, slot)| *slot).unwrap_or(0);
        self.seen.insert(key.to_string(), (now, slot));
    }

    /// `true` when this occurrence for `key` should warn, plus the summary
    /// of a window that just rolled over.
    ///
    /// Three rules, in order: a key already warned inside the window is
    /// quiet; a key past the window's budget is quiet but remembered for
    /// the summary; otherwise it warns. The per-window budget covers a key
    /// that returns after its own quiet window as well: a flood of
    /// *repeat* visitors must not be able to spend the window's warns
    /// either.
    pub fn should_warn(&mut self, key: &str, now: Instant) -> (bool, Option<WarnSummary>) {
        let summary = self.roll_window(now);
        if let Some((first, _)) = self.seen.get(key)
            && now.duration_since(*first) < self.window
        {
            return (false, summary);
        }
        self.track(key, now);
        if self.warns_emitted >= self.max_warns {
            if self.suppressed.suppressed.len() < self.max_warns as usize {
                self.suppressed.suppressed.push(key.to_string());
            }
            self.suppressed.suppressed_total += 1;
            return (false, summary);
        }
        self.warns_emitted += 1;
        (true, summary)
    }
}

/// One fixed-window counter: the hit count and the instant the window
/// closes. The deadline travels with the entry — the same moment moka's
/// TTL starts from — so a rejection can name the exact `Retry-After`
/// instead of the whole window.
struct Window {
    count: AtomicU64,
    deadline: std::time::Instant,
}

/// Fixed-window per-key rate limiter: counters live in a moka cache with
/// TTL = window, so expiry resets the window.
///
/// The counter cache holds at most `max_keys` keys (100 000 by default);
/// past that the least-recently-used counters are evicted, and an evicted
/// key starts a fresh window — its counter is gone, so the next request
/// from it counts as the first one again. The ceiling bounds the memory a
/// flood of distinct keys could pin; it never bounds the number of
/// requests a single key may make.
pub struct RateLimiter {
    counters: Cache<String, Arc<Window>>,
    limit: u64,
    window: Duration,
}

impl RateLimiter {
    pub fn new(limit: u64, window: Duration) -> Self {
        Self::with_capacity(limit, window, DEFAULT_MAX_KEYS)
    }

    /// A limiter with its own key ceiling. The admin panel counts compact
    /// address keys and serves far fewer clients than the public
    /// listener, so it can afford a larger ceiling than the default one:
    /// a flood of distinct addresses must not push the counters of the
    /// real operators out of the cache.
    pub fn with_capacity(limit: u64, window: Duration, max_keys: u64) -> Self {
        Self {
            counters: Cache::builder()
                .max_capacity(max_keys)
                .time_to_live(window)
                .build(),
            limit,
            window,
        }
    }

    /// The window the counters live in: the horizon the shared-peer-bucket
    /// warning deduplicates on (see [`warn_shared_peer_bucket`]), the same
    /// span a degraded key keeps its clients in one bucket for.
    pub fn window(&self) -> Duration {
        self.window
    }

    /// Count one hit for `key`; `true` while under the limit. The
    /// production paths read [`Self::check`] (a refusal carries the
    /// `Retry-After` seconds); this boolean form stays for the unit tests
    /// of the limiter itself.
    #[cfg(test)]
    pub async fn allow(&self, key: &str) -> bool {
        self.check(key).await.is_ok()
    }

    /// Count one hit for `key`; `Err(seconds)` when the window is
    /// exhausted, carrying the `Retry-After` value: the seconds until the
    /// window's deadline, never zero (a zero would let an aggressive
    /// client spin on the same instant). The deadline is fixed by the
    /// entry's creation — the first hit of the window, the same moment
    /// moka's TTL starts from — so the header and the actual reset agree.
    pub async fn check(&self, key: &str) -> Result<(), u64> {
        // moka's future cache expects a future (not a closure) as the init.
        let window = self.window;
        let init = async move {
            Ok::<_, std::convert::Infallible>(Arc::new(Window {
                count: AtomicU64::new(0),
                deadline: std::time::Instant::now() + window,
            }))
        };
        let Ok(entry) = self.counters.try_get_with(key.to_string(), init).await else {
            return Ok(()); // cache hiccup must not lock the admin out
        };
        if entry.count.fetch_add(1, Ordering::Relaxed) < self.limit {
            return Ok(());
        }
        Err(entry
            .deadline
            .saturating_duration_since(std::time::Instant::now())
            .as_secs()
            .max(1))
    }

    /// Give one hit back to `key`'s window: the outer middleware counts
    /// every request up front, but a deeper rate-limiting layer may reject
    /// the very same request too, without the refund the outer window pays
    /// for hits the inner limiter already punished. Saturating: a refund
    /// for a key whose counter already expired with its window (or never
    /// existed) must never wrap below zero, the wrap would blacklist the
    /// key for the whole window.
    pub async fn refund(&self, key: &str) {
        let init = async {
            Ok::<_, std::convert::Infallible>(Arc::new(Window {
                count: AtomicU64::new(0),
                deadline: std::time::Instant::now(),
            }))
        };
        if let Ok(entry) = self.counters.try_get_with(key.to_string(), init).await {
            let mut current = entry.count.load(Ordering::Relaxed);
            loop {
                match entry.count.compare_exchange_weak(
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

    /// The rate-limit key under each declaration, for the trusted peer of
    /// the tests above.
    fn key_xff(headers: &HeaderMap) -> IpAddr {
        client_key(peer(), headers, &trusted_v4(), TrustedHeader::Xff).0
    }

    fn key_forwarded(headers: &HeaderMap) -> IpAddr {
        client_key(peer(), headers, &trusted_v4(), TrustedHeader::Forwarded).0
    }

    fn key_both(headers: &HeaderMap) -> IpAddr {
        client_key(peer(), headers, &trusted_v4(), TrustedHeader::Both).0
    }

    #[test]
    fn empty_trusted_list_never_honors_forwarded_headers() {
        // Even with XFF claiming 1.2.3.4, an unconfigured trust list must
        // not let the header influence the rate-limit key, peer wins.
        let h = xff("1.2.3.4");
        assert_eq!(
            client_key(peer(), &h, &[], TrustedHeader::Both).0,
            peer().ip()
        );
        let h = fwd("for=1.2.3.4;proto=https");
        assert_eq!(
            client_key(peer(), &h, &[], TrustedHeader::Both).0,
            peer().ip()
        );
    }

    /// The declaration is the gate: until the operator names a header, no
    /// forwarded header moves the key off the peer address, not even one
    /// the trusted proxy wrote.
    #[test]
    fn an_undeclared_forwarding_header_never_moves_the_key() {
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", "1.2.3.4".parse().unwrap());
        headers.insert(
            header::FORWARDED,
            "for=1.2.3.4;proto=https".parse().unwrap(),
        );
        assert_eq!(
            client_key(peer(), &headers, &trusted_v4(), TrustedHeader::None).0,
            peer().ip(),
            "a consistent pair of headers must resolve to the peer without a declaration"
        );
        // The same pair under a declaration names the client: the operator
        // has taken responsibility for the header.
        assert_eq!(key_both(&headers), "1.2.3.4".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn trusted_peer_with_single_xff_hop_returns_that_ip() {
        let h = xff("1.2.3.4");
        assert_eq!(key_xff(&h), "1.2.3.4".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn trusted_peer_with_chain_walks_past_trusted_hops_right_to_left() {
        // Two trusted hops appended in order: the innermost observation is
        // at the right, so the walk starts there, skips the trusted entry
        // and lands on the client IP the first trusted proxy observed.
        let h = xff("1.1.1.1, 2.2.2.2");
        assert_eq!(key_xff(&h), "1.1.1.1".parse::<IpAddr>().unwrap());
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
        assert_eq!(key_xff(&h), "9.9.9.9".parse::<IpAddr>().unwrap());
    }

    /// Same property on the RFC 7239 header: a client-supplied `for=` in
    /// the left-most element is ignored when a trusted proxy appended its
    /// own observation at the right.
    #[test]
    fn client_supplied_forwarded_prefix_cannot_pick_the_rate_limit_key() {
        let h = fwd("for=6.6.6.6, for=9.9.9.9");
        assert_eq!(key_forwarded(&h), "9.9.9.9".parse::<IpAddr>().unwrap());
    }

    /// A proxy configured for RFC 7239 (`Forwarded`) leaves
    /// `X-Forwarded-For` alone, so a client-supplied XFF is the only XFF
    /// text the request carries. Under the `forwarded` declaration the XFF
    /// is not read at all, so the five forged XFFs cannot produce five
    /// rate-limit keys on the login brute-force cap: the key is the
    /// address the proxy itself observed.
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
                key_forwarded(&headers),
                "9.9.9.9".parse::<IpAddr>().unwrap(),
                "a client-authored XFF beside the proxy's Forwarded chose the key"
            );
        }
    }

    /// The mirror image: a proxy that writes only XFF (nginx, Caddy) and
    /// forwards the client's `Forwarded` verbatim, the default of
    /// `proxy_pass_request_headers on`. Under the `xff` declaration the
    /// client's `for=` is not read, so it cannot pick the key.
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
                key_xff(&headers),
                "9.9.9.9".parse::<IpAddr>().unwrap(),
                "a client-authored Forwarded beside the proxy's XFF chose the key"
            );
        }
    }

    /// A `Forwarded` the trusted proxy wrote but that yields no address
    /// (`for=_hidden`) is text from a header the operator did not
    /// declare: it must not change the key the declared header produced.
    #[test]
    fn a_hidden_forwarded_entry_never_changes_the_declared_headers_key() {
        let mut headers = HeaderMap::new();
        headers.insert(header::FORWARDED, "for=_hidden".parse().unwrap());
        headers.insert("x-forwarded-for", "9.9.9.9".parse().unwrap());
        assert_eq!(key_xff(&headers), "9.9.9.9".parse::<IpAddr>().unwrap());
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
        assert_eq!(key_both(&headers), "9.9.9.9".parse::<IpAddr>().unwrap());
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
            client_key(peer(), &headers, &trusted, TrustedHeader::Both).0,
            "9.9.9.9".parse::<IpAddr>().unwrap(),
            "a trusted chain through two proxies must keep its per-client key"
        );
    }

    /// A chain the walk can exhaust, every XFF entry inside the trust
    /// list, beside a header that names a client is the one disagreement
    /// that is not a forgery: an all-trusted XFF is evidence that the
    /// peer wrote it (only a trusted hop's appending puts a trusted
    /// address there, and the client then sits further left, in the
    /// other header). The mirror shape is pinned too, so neither
    /// direction is accidental.
    #[test]
    fn an_exhausted_chain_defers_to_the_header_that_names_a_client() {
        let trusted: Vec<ipnet::IpNet> =
            vec!["2.2.2.2/32".parse().unwrap(), "10.0.0.0/8".parse().unwrap()];
        // XFF exhausted on trusted entries, `Forwarded` exhausted on one.
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", "10.0.0.7, 10.0.0.8".parse().unwrap());
        headers.insert(header::FORWARDED, "for=10.0.0.9".parse().unwrap());
        assert_eq!(
            client_key(peer(), &headers, &trusted, TrustedHeader::Both).0,
            peer().ip()
        );

        // Mirror: the `Forwarded` chain is the exhausted one.
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", "9.9.9.9".parse().unwrap());
        headers.insert(
            header::FORWARDED,
            "for=9.9.9.9, for=10.0.0.8".parse().unwrap(),
        );
        assert_eq!(
            client_key(peer(), &headers, &trusted, TrustedHeader::Both).0,
            "9.9.9.9".parse::<IpAddr>().unwrap()
        );
    }

    /// The remaining disagreement, pinned deliberately: a client that sends
    /// its own `Forwarded` (or arrives behind a proxy that writes only
    /// `Forwarded`) beside an XFF-writing peer is indistinguishable from a
    /// forgery, so under the `both` declaration the key is the peer's.
    /// That bucket is *shared*, one window for everything that lands there,
    /// which is the documented cost of failing closed here, never a
    /// bypass: the key is still not the client's choice.
    #[test]
    fn a_disagreeing_client_forwarded_lands_in_the_shared_peer_bucket() {
        let mut headers = HeaderMap::new();
        // The peer (nginx) writes XFF with the address it observed.
        headers.insert("x-forwarded-for", "9.9.9.9".parse().unwrap());
        // The client, or a proxy in front of nginx, writes this one.
        headers.insert(header::FORWARDED, "for=6.6.6.6".parse().unwrap());
        assert_eq!(key_both(&headers), peer().ip());
    }

    /// The same request with only the proxy's XFF and no `Forwarded` at all
    /// still resolves through the XFF walk when the operator declared
    /// `xff`: a legacy proxy that writes XFF only must keep its
    /// per-client rate-limit key. Under the `both` declaration the missing
    /// half is a disagreement and the peer wins.
    #[test]
    fn xff_is_still_honored_when_no_forwarded_is_present() {
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", "6.6.6.6, 9.9.9.9".parse().unwrap());
        assert_eq!(key_xff(&headers), "9.9.9.9".parse::<IpAddr>().unwrap());
        assert_eq!(key_both(&headers), peer().ip());
    }

    /// RFC 7230 §3.2.2: a repeated header field is one field with the
    /// values joined by commas. Reading only the first value would drop
    /// the entries the proxy appended after it, and the client address
    /// with them.
    #[test]
    fn a_repeated_forwarded_header_is_read_as_one_joined_field() {
        let mut headers = HeaderMap::new();
        headers.append("x-forwarded-for", "6.6.6.6".parse().unwrap());
        headers.append("x-forwarded-for", "9.9.9.9".parse().unwrap());
        assert_eq!(key_xff(&headers), "9.9.9.9".parse::<IpAddr>().unwrap());

        let mut headers = HeaderMap::new();
        headers.append(header::FORWARDED, "for=6.6.6.6".parse().unwrap());
        headers.append(header::FORWARDED, "for=9.9.9.9".parse().unwrap());
        assert_eq!(
            key_forwarded(&headers),
            "9.9.9.9".parse::<IpAddr>().unwrap()
        );
    }

    #[test]
    fn chain_with_all_trusted_entries_falls_back_to_peer() {
        // Both hops are inside the trusted CIDR, walking past them all
        // leaves nothing usable, so the peer wins.
        let h = xff("2.2.2.2, 2.2.2.2");
        assert_eq!(key_xff(&h), peer().ip());
    }

    /// A proxy that appends the port it observed (`ip:port`, some do) must
    /// not turn the client entry into unparsable text: the port is
    /// stripped before the parse, for IPv4 and for a bracketed IPv6
    /// literal alike, in both headers.
    #[test]
    fn port_suffixed_entries_still_name_the_client() {
        // XFF: a bare IPv4 literal with port, and a bracketed IPv6 literal.
        let h = xff("9.9.9.9:5678");
        assert_eq!(key_xff(&h), "9.9.9.9".parse::<IpAddr>().unwrap());
        let h = xff("[2001:db8::1]:443");
        assert_eq!(key_xff(&h), "2001:db8::1".parse::<IpAddr>().unwrap());

        // Forwarded: the quoted and the unquoted shape.
        let h = fwd("for=\"9.9.9.9:5678\"");
        assert_eq!(key_forwarded(&h), "9.9.9.9".parse::<IpAddr>().unwrap());
        let h = fwd("for=[2001:db8::1]:443");
        assert_eq!(key_forwarded(&h), "2001:db8::1".parse::<IpAddr>().unwrap());

        // A bare IPv6 literal is never mistaken for `ip:port`.
        let h = xff("2001:db8::1");
        assert_eq!(key_xff(&h), "2001:db8::1".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn untrusted_peer_ignores_xff_and_keeps_peer() {
        let untrusted_peer: SocketAddr = "9.9.9.9:41000".parse().unwrap();
        let h = xff("1.2.3.4");
        assert_eq!(
            client_key(untrusted_peer, &h, &trusted_v4(), TrustedHeader::Both).0,
            untrusted_peer.ip()
        );
    }

    #[test]
    fn trusted_peer_with_rfc7239_forwarded_returns_first_untrusted_for() {
        let h = fwd("for=1.2.3.4;proto=https");
        assert_eq!(key_forwarded(&h), "1.2.3.4".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn forwarded_for_hidden_falls_back_to_peer() {
        let h = fwd("for=_hidden");
        assert_eq!(key_forwarded(&h), peer().ip());
    }

    #[test]
    fn forwarded_walks_right_to_left_past_trusted_for_entries() {
        // The innermost trusted proxy's observation is on the right
        // (for=2.2.2.2); the walk starts there, skips the trusted entry and
        // returns the client IP the first trusted hop observed (1.1.1.1).
        let h = fwd("for=1.1.1.1, for=2.2.2.2");
        assert_eq!(key_forwarded(&h), "1.1.1.1".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn forwarded_with_bracketed_ipv6_literal_is_bracket_stripped() {
        let h = fwd("for=[2001:db8::1];proto=https");
        assert_eq!(key_forwarded(&h), "2001:db8::1".parse::<IpAddr>().unwrap());
    }

    /// RFC 7239 §4 does not pin parameter ordering. A non-`for=` parameter
    /// appearing before the `for=` must not abort the walk, only the `for=`
    /// parameter is load-bearing for the originating-client lookup. The
    /// audit's reported shape was `Forwarded: proto=https;for=1.2.3.4` and
    /// the pre-fix code bailed at `proto=https` (`?` on `strip_prefix`).
    #[test]
    fn walk_forwarded_takes_first_for_param_regardless_of_position() {
        let h = fwd("proto=https;for=1.2.3.4");
        assert_eq!(key_forwarded(&h), "1.2.3.4".parse::<IpAddr>().unwrap());
        // Also pin a chain shape with a non-`for=` parameter in the same
        // entry to make sure the loop walks the whole `;`-separated list.
        let h = fwd("for=1.2.3.4;by=2.2.2.2;proto=https");
        assert_eq!(key_forwarded(&h), "1.2.3.4".parse::<IpAddr>().unwrap());
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

    /// A refunded hit opens the window slot it consumed: a request that
    /// passed this limiter but was rejected by a deeper one must not cost
    /// this window anything.
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
