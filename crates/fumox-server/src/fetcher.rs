//! Source fetcher: HTTP download with SSRF protection, size caps and
//! retries with exponential backoff (SPEC §16 gaps 4–5, ADMIN_PLAN §3).
//!
//! Error classification follows the single `error_class` vocabulary
//! (SPEC §10.2): `network` / `http_server` are recoverable and retried;
//! `http_client` is not. An SSRF-blocked URL is reported as `http_client`
//! with status 403 — the source configuration is at fault and retrying
//! cannot help.

use fumox_core::config::FetchConfig;
use fumox_core::models::{ErrorClass, IpFamily};
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use url::Url;

/// Maximum accepted URL length (ADMIN_PLAN §3).
const MAX_URL_LEN: usize = 2048;
/// Upper bound on followed redirects.
const MAX_REDIRECTS: usize = 5;
/// Hard ceiling for one retry backoff: a misconfigured `[fetch].max_retries`
/// must neither overflow the exponential multiply nor park a fetch task for
/// hours (security audit, 2026-08-30).
const MAX_RETRY_BACKOFF: Duration = Duration::from_secs(60);

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

    /// Deployment-wide default family a source without its own `ip_family`
    /// resolves to (`[fetch] ip_family`).
    pub fn default_family(&self) -> IpFamily {
        self.config.ip_family
    }

    /// Build a one-shot client for a single fetch.
    ///
    /// reqwest exposes DNS override only on `ClientBuilder`, so the client
    /// is constructed per request with the vetted address pinned via
    /// `resolve()` — this is what closes the DNS-rebinding window between
    /// the SSRF check and the connect. Construction cost is negligible
    /// against network latency at the scheduler's fetch rate.
    ///
    /// `Policy::none()` is load-bearing, not a default: reqwest's redirect
    /// layer would consume the 3xx internally and hand back only the final
    /// response, which silently skips the per-hop SSRF vetting in
    /// [`Self::fetch_once`] (security audit, 2026-09-05). `resolve()` does
    /// not contain an automatic follow — it is a per-hostname DNS override,
    /// ignored outright for IP literals and overridden by a port in the
    /// redirect target — so the loop must see every hop itself.
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
            .redirect(reqwest::redirect::Policy::none())
            .resolve(host, addr)
            .build()
    }

    /// Fetch a URL with retries for recoverable failures.
    ///
    /// `headers` are extra request headers from the source configuration
    /// (they may override the default User-Agent). `family` is the source's
    /// preferred IP family; `None` inherits the deployment default from
    /// `[fetch] ip_family`. The family is strict: when the host has no
    /// address of that family the fetch fails with a client error.
    pub async fn fetch(
        &self,
        url: &str,
        headers: &std::collections::BTreeMap<String, String>,
        family: Option<IpFamily>,
    ) -> Result<FetchedPayload, FetchFailure> {
        let family = family.unwrap_or(self.config.ip_family);
        let mut attempt = 0u32;
        loop {
            match self.fetch_once(url, headers, family).await {
                Ok(payload) => return Ok(payload),
                Err(failure) => {
                    if attempt >= self.config.max_retries || !failure.is_recoverable() {
                        return Err(failure);
                    }
                    let delay = self.backoff_delay(attempt);
                    tracing::warn!(
                        attempt = attempt + 1,
                        backoff_ms = %delay.as_millis(),
                        error = %failure,
                        "fetch failed, retrying"
                    );
                    tokio::time::sleep(delay).await;
                    attempt += 1;
                }
            }
        }
    }

    /// Exponential backoff before retry `attempt` (0-based), hard-capped at
    /// [`MAX_RETRY_BACKOFF`].
    fn backoff_delay(&self, attempt: u32) -> Duration {
        Duration::from_millis(
            self.config
                .retry_base_backoff_ms
                .saturating_mul(2u64.saturating_pow(attempt)),
        )
        .min(MAX_RETRY_BACKOFF)
    }

    async fn fetch_once(
        &self,
        url: &str,
        headers: &std::collections::BTreeMap<String, String>,
        family: IpFamily,
    ) -> Result<FetchedPayload, FetchFailure> {
        // Redirects are followed manually (up to MAX_REDIRECTS hops) because
        // every hop must pass the full SSRF vetting again — an automatic
        // redirect policy would let a public URL bounce the client into a
        // private or metadata address. `build_client` therefore pins
        // `Policy::none()`; see the note there.
        let mut current = url.to_string();
        // Source-configured headers may carry subscription secrets, and
        // reqwest only strips the standardized ones (`Authorization`,
        // `Cookie`, …) across a redirect. They stay scoped to the origin the
        // admin configured, so a redirect to a collector harvests nothing
        // (security audit, 2026-09-05).
        let configured_origin = Url::parse(url).ok().map(|parsed| origin_of(&parsed));
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
            let pinned = self.resolve_and_vet(host, family).await.map_err(|e| {
                // The URL may carry userinfo credentials — never log it raw.
                tracing::warn!(url = %redact_url(&current), reason = %e, "SSRF protection blocked the fetch");
                FetchFailure::HttpClient { status: 403 }
            })?;
            let port = parsed
                .port_or_known_default()
                .unwrap_or(if parsed.scheme() == "https" { 443 } else { 80 });

            let client = self
                .build_client(host, SocketAddr::new(pinned, port))
                .map_err(|e| FetchFailure::Network {
                    message: redacted_request_error(&e),
                })?;
            let mut request = client.get(parsed.clone());
            let same_origin = configured_origin
                .as_ref()
                .is_some_and(|origin| *origin == origin_of(&parsed));
            if same_origin {
                for (name, value) in headers {
                    request = request.header(name.as_str(), value.as_str());
                }
            } else if !headers.is_empty() {
                tracing::warn!(
                    url = %redact_url(&current),
                    "redirect left the configured origin — source headers withheld"
                );
            }

            let response = request.send().await.map_err(|e| FetchFailure::Network {
                message: redacted_request_error(&e),
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
                message: redacted_request_error(&e),
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
    /// to, constrained to `family` (first IPv4 when available for `Any`).
    /// IP literals skip DNS.
    async fn resolve_and_vet(&self, host: &str, family: IpFamily) -> Result<IpAddr, SsrfRejection> {
        vet_host(host, self.allow_private_urls, family).await
    }
}

/// Strip userinfo (`user:pass@`) from a URL string. Applied on every path
/// where a URL — or an error text embedding one — reaches the tracing log,
/// `fetch_log` or `sources.last_error` (security audit, 2026-08-30).
fn redact_url(url: &str) -> String {
    match Url::parse(url) {
        Ok(mut parsed) => {
            let _ = parsed.set_username("");
            let _ = parsed.set_password(None);
            parsed.to_string()
        }
        // Not a URL (the error text embedded something else) — nothing to leak.
        Err(_) => url.to_string(),
    }
}

/// Scheme + host + effective port, the scope source headers are confined to.
/// A redirect that changes any of the three is a different origin, even when
/// only the port moved — the pinned DNS override does not constrain the port.
fn origin_of(url: &Url) -> (String, String, u16) {
    let port = url
        .port_or_known_default()
        .unwrap_or(if url.scheme() == "https" { 443 } else { 80 });
    (
        url.scheme().to_ascii_lowercase(),
        url.host_str().unwrap_or_default().to_ascii_lowercase(),
        port,
    )
}

/// Display text of a reqwest error with the embedded URL redacted:
/// reqwest appends ` for url (<url>)`, userinfo included.
fn redacted_request_error(error: &reqwest::Error) -> String {
    match error.url() {
        Some(url) => error
            .to_string()
            .replace(url.as_str(), &redact_url(url.as_str())),
        None => error.to_string(),
    }
}

/// Whether `ip` belongs to the requested family (`Any` matches both).
fn family_matches(ip: IpAddr, family: IpFamily) -> bool {
    match family {
        IpFamily::Any => true,
        IpFamily::Ipv4 => ip.is_ipv4(),
        IpFamily::Ipv6 => ip.is_ipv6(),
    }
}

/// Human-readable family name for error messages.
fn family_label(family: IpFamily) -> &'static str {
    match family {
        IpFamily::Any => "IPv4/IPv6",
        IpFamily::Ipv4 => "IPv4",
        IpFamily::Ipv6 => "IPv6",
    }
}

/// Pick the connect address from an already-vetted list: first IPv4 with an
/// IPv6 fallback for `Any` (the historical behavior), otherwise the first
/// address of the requested family. `None` = no usable address.
fn pick_address(addrs: &[IpAddr], family: IpFamily) -> Option<IpAddr> {
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

/// Resolve a host and vet every address against the SSRF policy, then pick
/// the connect address constrained to `family`. Shared by the fetch path
/// and the save-time check ([`vet_url`]).
pub async fn vet_host(
    host: &str,
    allow_private_urls: bool,
    family: IpFamily,
) -> Result<IpAddr, SsrfRejection> {
    let addrs: Vec<IpAddr> = if let Ok(ip) = host.parse::<IpAddr>() {
        // The literal fixes the family; a source pinned to the other one
        // can never reach it.
        if !family_matches(ip, family) {
            return Err(SsrfRejection {
                reason: format!(
                    "{host} is a {} address but the source requires {}",
                    if ip.is_ipv4() { "IPv4" } else { "IPv6" },
                    family_label(family)
                ),
            });
        }
        vec![ip]
    } else {
        let lookup = tokio::net::lookup_host((host, 0))
            .await
            .map_err(|e| SsrfRejection {
                reason: format!("DNS resolution failed for {host}: {e}"),
            })?;
        let addrs: Vec<IpAddr> = lookup
            .map(|addr| addr.ip())
            .filter(|ip| family_matches(*ip, family))
            .collect();
        if addrs.is_empty() {
            return Err(SsrfRejection {
                reason: format!("no {} addresses for {host}", family_label(family)),
            });
        }
        addrs
    };
    for ip in &addrs {
        check_ip(*ip, allow_private_urls).map_err(|reason| SsrfRejection {
            reason: format!("{host} -> {ip}: {reason}"),
        })?;
    }
    pick_address(&addrs, family).ok_or_else(|| SsrfRejection {
        reason: format!("no {} addresses for {host}", family_label(family)),
    })
}

/// A static URL-validation problem: a catalog key plus positional `{0}`,
/// `{1}`… arguments. The admin layer renders it with `Lang::t_args` in the
/// panel language; embedded diagnostics (URL-parser and SSRF-rejection
/// details) stay technical English — only the sentence around them is
/// localized.
#[derive(Debug, Clone)]
pub struct UrlIssue {
    /// Catalog key (`val.url_*` section of `locales/*.toml`).
    pub key: &'static str,
    /// Positional arguments: limits, offending values, technical details.
    pub args: Vec<String>,
}

/// Static URL validation applied when a source is saved (ADMIN_PLAN §3).
///
/// The DNS-level SSRF vetting happens at fetch time (addresses can change
/// between save and fetch), but scheme, length and host shape are checked
/// up front so that obviously bad URLs never reach the scheduler.
pub fn validate_url(url: &str) -> Result<(), UrlIssue> {
    if url.len() > MAX_URL_LEN {
        return Err(UrlIssue {
            key: "val.url_too_long",
            args: vec![MAX_URL_LEN.to_string()],
        });
    }
    let parsed = Url::parse(url).map_err(|e| UrlIssue {
        key: "val.url_invalid",
        args: vec![e.to_string()],
    })?;
    match parsed.scheme() {
        "http" | "https" => {}
        other => {
            return Err(UrlIssue {
                key: "val.url_scheme",
                args: vec![other.to_string()],
            });
        }
    }
    if parsed.host_str().is_none() {
        return Err(UrlIssue {
            key: "val.url_no_host",
            args: Vec::new(),
        });
    }
    Ok(())
}

/// Save-time SSRF check (ADMIN_PLAN §3): static validation plus DNS
/// resolution and address vetting. The fetch path re-vets on every request
/// to defend against DNS rebinding, so a failure here is fast feedback for
/// the form, not the last line of defense. Skips DNS when private URLs are
/// allowed (nothing to reject). `family` is the source's effective IP
/// family (after resolving `None` against `[fetch] ip_family`), so the form
/// flags hosts that can never be reached under the strict constraint.
pub async fn vet_url(
    url: &str,
    allow_private_urls: bool,
    family: IpFamily,
) -> Result<(), UrlIssue> {
    validate_url(url)?;
    if allow_private_urls {
        return Ok(());
    }
    let parsed = Url::parse(url).map_err(|e| UrlIssue {
        key: "val.url_invalid",
        args: vec![e.to_string()],
    })?;
    let host = parsed.host_str().ok_or(UrlIssue {
        key: "val.url_no_host",
        args: Vec::new(),
    })?;
    vet_host(host, false, family)
        .await
        .map(|_| ())
        .map_err(|e| UrlIssue {
            key: "val.url_ssrf",
            args: vec![e.reason],
        })
}

/// Vet a single IP address against the SSRF policy.
///
/// With `allow_private_urls = false` the following are rejected: loopback,
/// RFC 1918 private space, link-local (incl. the `169.254.169.254` cloud
/// metadata endpoint), CGNAT, unspecified, broadcast and benchmark ranges,
/// plus their IPv6 equivalents and IPv4-mapped IPv6 addresses. The policy
/// itself lives in `fumox-core` so the probe daemon applies the identical
/// blocklist to its dial targets (security audit v2, 2026-09-09, F1).
pub fn check_ip(ip: IpAddr, allow_private: bool) -> Result<(), String> {
    fumox_core::ssrf::check_ip(ip, allow_private)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn redact_url_strips_userinfo() {
        assert_eq!(
            redact_url("https://user:pass@example.com/sub?a=1"),
            "https://example.com/sub?a=1"
        );
        assert_eq!(
            redact_url("http://user@example.com/"),
            "http://example.com/"
        );
        // Without userinfo the URL is untouched; non-URLs pass through.
        assert_eq!(redact_url("https://example.com/"), "https://example.com/");
        assert_eq!(redact_url("not a url"), "not a url");
    }

    #[test]
    fn backoff_delay_is_capped_and_never_overflows() {
        let fetcher = Fetcher::new(FetchConfig::default(), true);
        assert_eq!(fetcher.backoff_delay(0), Duration::from_millis(500));
        assert_eq!(fetcher.backoff_delay(1), Duration::from_millis(1000));
        // An absurd max_retries must saturate into the cap, not overflow
        // (debug builds would panic on the raw 2u64.pow).
        assert_eq!(fetcher.backoff_delay(100), Duration::from_secs(60));

        let huge = FetchConfig {
            retry_base_backoff_ms: u64::MAX,
            ..FetchConfig::default()
        };
        let fetcher = Fetcher::new(huge, true);
        assert_eq!(fetcher.backoff_delay(0), Duration::from_secs(60));
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

    #[test]
    fn pick_address_matrix() {
        let both = [ip("203.0.113.10"), ip("2001:db8::1")];
        let v4_only = [ip("203.0.113.10")];
        let v6_only = [ip("2001:db8::1")];

        // Any: first IPv4 wins, IPv6 fallback (historical behavior).
        assert_eq!(pick_address(&both, IpFamily::Any), Some(ip("203.0.113.10")));
        assert_eq!(
            pick_address(&v6_only, IpFamily::Any),
            Some(ip("2001:db8::1"))
        );
        // Strict families pick their own address and never the other one.
        assert_eq!(
            pick_address(&both, IpFamily::Ipv4),
            Some(ip("203.0.113.10"))
        );
        assert_eq!(pick_address(&both, IpFamily::Ipv6), Some(ip("2001:db8::1")));
        assert_eq!(pick_address(&v6_only, IpFamily::Ipv4), None);
        assert_eq!(pick_address(&v4_only, IpFamily::Ipv6), None);
        assert_eq!(pick_address(&[], IpFamily::Any), None);
    }

    #[tokio::test]
    async fn literal_ip_of_the_wrong_family_is_rejected() {
        // A private URL would normally be vetted with allow_private=false,
        // but the family check fires before the private-range check either
        // way; use public test-net addresses to exercise both orders.
        let v4 = vet_host("203.0.113.10", true, IpFamily::Ipv6)
            .await
            .unwrap_err();
        assert!(v4.reason.contains("IPv4"), "{}", v4.reason);
        let v6 = vet_host("2001:db8::1", true, IpFamily::Ipv4)
            .await
            .unwrap_err();
        assert!(v6.reason.contains("IPv6"), "{}", v6.reason);
        // The matching family passes.
        assert!(vet_host("2001:db8::1", true, IpFamily::Ipv6).await.is_ok());
    }

    /// Minimal HTTP/1.1 responder on 127.0.0.1; serves any number of
    /// requests while the test runtime lives.
    async fn spawn_v4_listener() -> std::net::SocketAddr {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((mut sock, _)) = listener.accept().await {
                use tokio::io::{AsyncReadExt, AsyncWriteExt};
                let mut buf = [0u8; 1024];
                let _ = sock.read(&mut buf).await;
                let _ = sock
                    .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nok")
                    .await;
            }
        });
        addr
    }

    /// Responder that answers every request with `302 Location: <target>`.
    async fn spawn_redirector(target: String) -> std::net::SocketAddr {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((mut sock, _)) = listener.accept().await {
                use tokio::io::{AsyncReadExt, AsyncWriteExt};
                let mut buf = [0u8; 1024];
                let _ = sock.read(&mut buf).await;
                let response = format!(
                    "HTTP/1.1 302 Found\r\nLocation: {target}\r\ncontent-length: 0\r\n\r\n"
                );
                let _ = sock.write_all(response.as_bytes()).await;
            }
        });
        addr
    }

    /// Responder that echoes back which of the request's headers it saw,
    /// so a test can assert what survived a redirect.
    async fn spawn_header_echo() -> std::net::SocketAddr {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((mut sock, _)) = listener.accept().await {
                use tokio::io::{AsyncReadExt, AsyncWriteExt};
                let mut buf = [0u8; 4096];
                let n = sock.read(&mut buf).await.unwrap_or(0);
                let request = String::from_utf8_lossy(&buf[..n]).to_ascii_lowercase();
                let body = if request.contains("x-subscription-token:") {
                    "LEAKED"
                } else {
                    "clean"
                };
                let response = format!(
                    "HTTP/1.1 200 OK\r\ncontent-length: {}\r\n\r\n{body}",
                    body.len()
                );
                let _ = sock.write_all(response.as_bytes()).await;
            }
        });
        addr
    }

    /// The manual redirect loop must actually observe each hop, so that
    /// `resolve_and_vet` runs against the *target* of every redirect. reqwest
    /// following redirects itself would hide the hop and let a vetted public
    /// source bounce the fetch into a private address (security audit,
    /// 2026-09-05).
    #[tokio::test]
    async fn a_redirect_into_a_private_address_is_blocked() {
        let internal = spawn_v4_listener().await;
        // The source itself is vetted with allow_private=true (it is a
        // loopback listener in the test), but the hop is re-vetted strictly.
        let redirector = spawn_redirector(format!("http://{internal}/meta-data")).await;

        let strict = Fetcher::new(FetchConfig::default(), false);
        let err = strict
            .fetch(
                &format!("http://{redirector}/sub"),
                &Default::default(),
                None,
            )
            .await
            .unwrap_err();
        // The very first hop is already private here, so vetting rejects it
        // before any redirect — assert the class, then prove the hop itself
        // is seen by a lenient fetcher below.
        assert_eq!(err.error_class(), ErrorClass::HttpClient);
        assert!(!err.is_recoverable());

        // With private URLs allowed the same chain succeeds, which proves the
        // loop followed the redirect manually rather than erroring out.
        let lenient = Fetcher::new(FetchConfig::default(), true);
        let payload = lenient
            .fetch(
                &format!("http://{redirector}/sub"),
                &Default::default(),
                None,
            )
            .await
            .unwrap();
        assert_eq!(payload.body, b"ok");
    }

    /// Source-configured headers may carry subscription secrets; they must
    /// not follow a redirect off the configured origin.
    #[tokio::test]
    async fn source_headers_do_not_survive_a_cross_origin_redirect() {
        let echo = spawn_header_echo().await;
        let redirector = spawn_redirector(format!("http://{echo}/collect")).await;
        let fetcher = Fetcher::new(FetchConfig::default(), true);
        let headers = std::collections::BTreeMap::from([(
            "X-Subscription-Token".to_string(),
            "SECRET".to_string(),
        )]);

        // Straight to the echo endpoint: same origin, header applied.
        let direct = fetcher
            .fetch(&format!("http://{echo}/sub"), &headers, None)
            .await
            .unwrap();
        assert_eq!(
            direct.body, b"LEAKED",
            "header must reach the configured origin"
        );

        // Via a redirect to a different port: header withheld.
        let redirected = fetcher
            .fetch(&format!("http://{redirector}/sub"), &headers, None)
            .await
            .unwrap();
        assert_eq!(
            redirected.body, b"clean",
            "source headers leaked across a redirect"
        );
    }

    #[test]
    fn origin_comparison_covers_scheme_host_and_port() {
        let base = Url::parse("https://example.com/sub").unwrap();
        assert_eq!(
            origin_of(&base),
            origin_of(&Url::parse("https://EXAMPLE.com/other?x=1").unwrap())
        );
        // Explicit default port is the same origin; a different port is not.
        assert_eq!(
            origin_of(&base),
            origin_of(&Url::parse("https://example.com:443/sub").unwrap())
        );
        assert_ne!(
            origin_of(&base),
            origin_of(&Url::parse("https://example.com:8443/sub").unwrap())
        );
        assert_ne!(
            origin_of(&base),
            origin_of(&Url::parse("http://example.com/sub").unwrap())
        );
        assert_ne!(
            origin_of(&base),
            origin_of(&Url::parse("https://other.example.com/sub").unwrap())
        );
    }

    #[tokio::test]
    async fn fetch_respects_the_ip_family_constraint() {
        let addr = spawn_v4_listener().await;
        let fetcher = Fetcher::new(FetchConfig::default(), true);
        let url = format!("http://{addr}/sub");

        // Default (Any) reaches the IPv4-only endpoint...
        let payload = fetcher
            .fetch(&url, &Default::default(), None)
            .await
            .unwrap();
        assert_eq!(payload.body, b"ok");
        // ...and an explicit source family that matches works too.
        assert!(
            fetcher
                .fetch(&url, &Default::default(), Some(IpFamily::Ipv4))
                .await
                .is_ok()
        );

        // Strict IPv6 against an IPv4-only endpoint: rejected before any
        // connection, classified as a client error (no retries).
        let err = fetcher
            .fetch(&url, &Default::default(), Some(IpFamily::Ipv6))
            .await
            .unwrap_err();
        assert_eq!(err.error_class(), ErrorClass::HttpClient);
        assert!(!err.is_recoverable());
    }
}
