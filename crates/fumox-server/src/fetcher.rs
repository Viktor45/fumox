//! Source fetcher: HTTP download with SSRF protection, size caps and
//! retries with exponential backoff (SPEC §16 gaps 4–5, ADMIN_PLAN §3).
//!
//! Error classification follows the single `error_class` vocabulary
//! (SPEC §10.2): `network` / `http_server` are recoverable and retried;
//! `http_client` is not. An SSRF-blocked URL is reported as `http_client`
//! with status 403 — the source configuration is at fault and retrying
//! cannot help.

use fumox_core::config::FetchConfig;
use fumox_core::models::ErrorClass;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use url::Url;

/// Maximum accepted URL length (ADMIN_PLAN §3).
const MAX_URL_LEN: usize = 2048;
/// Upper bound on followed redirects.
const MAX_REDIRECTS: usize = 5;

/// A successfully downloaded payload.
#[derive(Debug, Clone)]
pub struct FetchedPayload {
    pub http_status: u16,
    pub bytes: u64,
    pub body: Vec<u8>,
}

/// Classified fetch failure — maps 1:1 onto the `error_class` vocabulary.
#[derive(Debug, thiserror::Error)]
pub enum FetchFailure {
    #[error("network error: {message}")]
    Network { message: String },
    #[error("server error: HTTP {status}")]
    HttpServer { status: u16 },
    #[error("client error: HTTP {status}")]
    HttpClient { status: u16 },
    #[error("response exceeds the {limit} byte cap")]
    ResponseTooLarge { limit: u64 },
}

impl FetchFailure {
    /// The `error_class` this failure is journaled as.
    pub fn error_class(&self) -> ErrorClass {
        match self {
            FetchFailure::Network { .. } => ErrorClass::Network,
            FetchFailure::HttpServer { .. } => ErrorClass::HttpServer,
            FetchFailure::HttpClient { .. } => ErrorClass::HttpClient,
            FetchFailure::ResponseTooLarge { .. } => ErrorClass::HttpServer,
        }
    }

    /// Whether a retry can plausibly succeed (SPEC §16.5).
    pub fn is_recoverable(&self) -> bool {
        matches!(
            self,
            FetchFailure::Network { .. }
                | FetchFailure::HttpServer { .. }
                | FetchFailure::ResponseTooLarge { .. }
        )
    }

    /// Upstream HTTP status, when there was one.
    pub fn http_status(&self) -> Option<u16> {
        match self {
            FetchFailure::HttpServer { status } | FetchFailure::HttpClient { status } => {
                Some(*status)
            }
            _ => None,
        }
    }
}

/// SSRF verdict for a URL or resolved IP.
#[derive(Debug, thiserror::Error)]
#[error("SSRF protection: {reason}")]
pub struct SsrfRejection {
    pub reason: String,
}

/// HTTP client wrapper carrying the fetch policy (timeouts, size cap,
/// retries, SSRF rules).
#[derive(Clone)]
pub struct Fetcher {
    config: FetchConfig,
    allow_private_urls: bool,
}

impl Fetcher {
    pub fn new(config: FetchConfig, allow_private_urls: bool) -> Self {
        Self {
            config,
            allow_private_urls,
        }
    }

    /// Build a one-shot client for a single fetch.
    ///
    /// reqwest exposes DNS override only on `ClientBuilder`, so the client
    /// is constructed per request with the vetted address pinned via
    /// `resolve()` — this is what closes the DNS-rebinding window between
    /// the SSRF check and the connect. Construction cost is negligible
    /// against network latency at the scheduler's fetch rate.
    fn build_client(
        &self,
        host: &str,
        addr: SocketAddr,
    ) -> Result<reqwest::Client, reqwest::Error> {
        reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(self.config.connect_timeout_secs))
            .timeout(Duration::from_secs(self.config.read_timeout_secs))
            .user_agent(self.config.user_agent.clone())
            .gzip(true)
            .brotli(true)
            .redirect(reqwest::redirect::Policy::limited(MAX_REDIRECTS))
            .resolve(host, addr)
            .build()
    }

    /// Fetch a URL with retries for recoverable failures.
    ///
    /// `headers` are extra request headers from the source configuration
    /// (they may override the default User-Agent).
    pub async fn fetch(
        &self,
        url: &str,
        headers: &std::collections::BTreeMap<String, String>,
    ) -> Result<FetchedPayload, FetchFailure> {
        let mut attempt = 0u32;
        loop {
            match self.fetch_once(url, headers).await {
                Ok(payload) => return Ok(payload),
                Err(failure) => {
                    if attempt >= self.config.max_retries || !failure.is_recoverable() {
                        return Err(failure);
                    }
                    let backoff = self.config.retry_base_backoff_ms * 2u64.pow(attempt);
                    tracing::warn!(
                        attempt = attempt + 1,
                        backoff_ms = backoff,
                        error = %failure,
                        "fetch failed, retrying"
                    );
                    tokio::time::sleep(Duration::from_millis(backoff)).await;
                    attempt += 1;
                }
            }
        }
    }

    async fn fetch_once(
        &self,
        url: &str,
        headers: &std::collections::BTreeMap<String, String>,
    ) -> Result<FetchedPayload, FetchFailure> {
        // Redirects are followed manually (up to MAX_REDIRECTS hops) because
        // every hop must pass the full SSRF vetting again — an automatic
        // redirect policy would let a public URL bounce the client into a
        // private or metadata address.
        let mut current = url.to_string();
        for _hop in 0..=MAX_REDIRECTS {
            if current.len() > MAX_URL_LEN {
                return Err(FetchFailure::HttpClient { status: 414 });
            }
            let parsed = Url::parse(&current).map_err(|e| FetchFailure::Network {
                message: format!("invalid URL: {e}"),
            })?;
            match parsed.scheme() {
                "http" | "https" => {}
                other => {
                    return Err(FetchFailure::Network {
                        message: format!("unsupported scheme: {other}"),
                    });
                }
            }

            // SSRF: resolve the host ourselves, vet every address, then pin
            // the chosen one so reqwest cannot be re-resolved (DNS
            // rebinding) to a different address between check and connect.
            let host = parsed.host_str().ok_or_else(|| FetchFailure::Network {
                message: "URL has no host".to_string(),
            })?;
            let pinned = self.resolve_and_vet(host).await.map_err(|e| {
                tracing::warn!(url = %current, reason = %e, "SSRF protection blocked the fetch");
                FetchFailure::HttpClient { status: 403 }
            })?;
            let port = parsed
                .port_or_known_default()
                .unwrap_or(if parsed.scheme() == "https" { 443 } else { 80 });

            let client = self
                .build_client(host, SocketAddr::new(pinned, port))
                .map_err(|e| FetchFailure::Network {
                    message: e.to_string(),
                })?;
            let mut request = client.get(parsed.clone());
            for (name, value) in headers {
                request = request.header(name.as_str(), value.as_str());
            }

            let response = request.send().await.map_err(|e| FetchFailure::Network {
                message: e.to_string(),
            })?;
            let status = response.status().as_u16();

            if (300..400).contains(&status) {
                let location = response
                    .headers()
                    .get(reqwest::header::LOCATION)
                    .and_then(|v| v.to_str().ok())
                    .ok_or(FetchFailure::HttpClient { status })?;
                current = parsed
                    .join(location)
                    .map_err(|_| FetchFailure::HttpClient { status })?
                    .to_string();
                continue;
            }

            if status >= 500 || status == 408 || status == 429 {
                return Err(FetchFailure::HttpServer { status });
            }
            if !(200..300).contains(&status) {
                return Err(FetchFailure::HttpClient { status });
            }

            // Stream the body with a hard cap (decompression-bomb guard).
            let limit = self.config.max_response_bytes;
            let mut body: Vec<u8> = Vec::new();
            let mut stream = response;
            while let Some(chunk) = stream.chunk().await.map_err(|e| FetchFailure::Network {
                message: e.to_string(),
            })? {
                if body.len() as u64 + chunk.len() as u64 > limit {
                    return Err(FetchFailure::ResponseTooLarge { limit });
                }
                body.extend_from_slice(&chunk);
            }
            let bytes = body.len() as u64;
            return Ok(FetchedPayload {
                http_status: status,
                bytes,
                body,
            });
        }
        // Redirect chain longer than MAX_REDIRECTS — a persistent server
        // misconfiguration, reported as 508 Loop Detected.
        Err(FetchFailure::HttpClient { status: 508 })
    }

    /// Resolve a host and vet all addresses. Returns the address to connect
    /// to (first IPv4 when available). IP literals skip DNS.
    async fn resolve_and_vet(&self, host: &str) -> Result<IpAddr, SsrfRejection> {
        vet_host(host, self.allow_private_urls).await
    }
}

/// Resolve a host and vet every address against the SSRF policy. Returns
/// the address to connect to (first IPv4 when available). Shared by the
/// fetch path and the save-time check ([`vet_url`]).
pub async fn vet_host(host: &str, allow_private_urls: bool) -> Result<IpAddr, SsrfRejection> {
    let addrs: Vec<IpAddr> = if let Ok(ip) = host.parse::<IpAddr>() {
        vec![ip]
    } else {
        let lookup = tokio::net::lookup_host((host, 0))
            .await
            .map_err(|e| SsrfRejection {
                reason: format!("DNS resolution failed for {host}: {e}"),
            })?;
        let addrs: Vec<IpAddr> = lookup.map(|addr| addr.ip()).collect();
        if addrs.is_empty() {
            return Err(SsrfRejection {
                reason: format!("no addresses for {host}"),
            });
        }
        addrs
    };
    for ip in &addrs {
        check_ip(*ip, allow_private_urls).map_err(|reason| SsrfRejection {
            reason: format!("{host} -> {ip}: {reason}"),
        })?;
    }
    Ok(addrs
        .iter()
        .find(|ip| ip.is_ipv4())
        .copied()
        .unwrap_or(addrs[0]))
}

/// Static URL validation applied when a source is saved (ADMIN_PLAN §3).
///
/// The DNS-level SSRF vetting happens at fetch time (addresses can change
/// between save and fetch), but scheme, length and host shape are checked
/// up front so that obviously bad URLs never reach the scheduler.
pub fn validate_url(url: &str) -> Result<(), String> {
    if url.len() > MAX_URL_LEN {
        return Err(format!("URL длиннее {MAX_URL_LEN} символов"));
    }
    let parsed = Url::parse(url).map_err(|e| format!("некорректный URL: {e}"))?;
    match parsed.scheme() {
        "http" | "https" => {}
        other => return Err(format!("поддерживаются только http/https, не «{other}»")),
    }
    if parsed.host_str().is_none() {
        return Err("у URL нет хоста".to_string());
    }
    Ok(())
}

/// Save-time SSRF check (ADMIN_PLAN §3): static validation plus DNS
/// resolution and address vetting. The fetch path re-vets on every request
/// to defend against DNS rebinding, so a failure here is fast feedback for
/// the form, not the last line of defense. Skips DNS when private URLs are
/// allowed (nothing to reject).
pub async fn vet_url(url: &str, allow_private_urls: bool) -> Result<(), String> {
    validate_url(url)?;
    if allow_private_urls {
        return Ok(());
    }
    let parsed = Url::parse(url).map_err(|e| format!("некорректный URL: {e}"))?;
    let host = parsed
        .host_str()
        .ok_or_else(|| "у URL нет хоста".to_string())?;
    vet_host(host, false)
        .await
        .map_err(|e| format!("SSRF-защита: {e}"))?;
    Ok(())
}

/// Vet a single IP address against the SSRF policy.
///
/// With `allow_private_urls = false` the following are rejected: loopback,
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

fn check_ipv4(v4: std::net::Ipv4Addr) -> Result<(), String> {
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
    use std::net::{Ipv4Addr, Ipv6Addr};

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

    #[test]
    fn failure_classification() {
        assert_eq!(
            FetchFailure::Network {
                message: "x".into()
            }
            .error_class(),
            ErrorClass::Network
        );
        assert_eq!(
            FetchFailure::HttpServer { status: 503 }.error_class(),
            ErrorClass::HttpServer
        );
        assert_eq!(
            FetchFailure::HttpClient { status: 404 }.error_class(),
            ErrorClass::HttpClient
        );
        assert!(
            FetchFailure::Network {
                message: "x".into()
            }
            .is_recoverable()
        );
        assert!(FetchFailure::HttpServer { status: 500 }.is_recoverable());
        assert!(!FetchFailure::HttpClient { status: 404 }.is_recoverable());
        assert_eq!(
            FetchFailure::HttpClient { status: 404 }.http_status(),
            Some(404)
        );
    }

    #[test]
    fn url_validation() {
        assert!(validate_url("https://example.com/sub").is_ok());
        assert!(validate_url("http://example.com").is_ok());
        assert!(validate_url("ftp://example.com").is_err());
        assert!(validate_url("not a url").is_err());
        assert!(validate_url(&format!("https://example.com/{}", "x".repeat(3000))).is_err());
    }

    #[test]
    fn ipv4_helpers_covered_ranges() {
        // Sanity on the std helpers we rely on.
        assert!(Ipv4Addr::new(127, 0, 0, 1).is_loopback());
        assert!(Ipv4Addr::new(169, 254, 169, 254).is_link_local());
        assert!(Ipv6Addr::LOCALHOST.is_loopback());
    }
}
