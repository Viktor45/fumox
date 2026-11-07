//! Source fetcher: HTTP download with SSRF protection, size caps and
//! retries with exponential backoff.
//!
//! Every failure carries a class from the single `error_class` vocabulary
//! (`network` / `http_server` / `http_client`): the coarse bucket the
//! journal and the admin panel group failures by, not a retry verdict —
//! retryability is answered separately by [`FetchFailure::is_recoverable`],
//! which retries everything except the two terminal cases: a `permanent`
//! network failure (the URL itself is unusable, e.g. an unparseable or
//! unsupported-scheme address) and [`FetchFailure::ResponseTooLarge`] (a
//! body over the cap is over it on every attempt). An SSRF-blocked URL is
//! reported as `http_client` with status 403, the source configuration is
//! at fault and retrying cannot help.
//!
//! Two paths have to stay the same path: the address that was vetted and
//! the address that is connected to. The client ignores the environment
//! proxy configuration for that reason (`no_proxy()`), and the vetted
//! address is pinned into the request (`resolve()`), so nothing between
//! the check and the connect can move the connection elsewhere.
//!
//! One fetch has one wall-clock budget ([`MAX_FETCH_BUDGET`]): the first
//! attempt, every retry and every backoff sleep share it, so a source
//! that never recovers cannot hold a concurrency permit forever.

use fumox_core::config::FetchConfig;
use fumox_core::models::{ErrorClass, IpFamily};
use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;
use url::Url;

use crate::redact::redact_url;

/// Maximum accepted URL length.
const MAX_URL_LEN: usize = 2048;
/// Upper bound on followed redirects.
const MAX_REDIRECTS: usize = 5;
/// Hard ceiling for one retry backoff: a misconfigured `[fetch].max_retries`
/// must neither overflow the exponential multiply nor park a fetch task for
/// hours.
const MAX_RETRY_BACKOFF: Duration = Duration::from_secs(60);
/// Ceiling on `[fetch].max_retries`, matching the admin form's range. The
/// form bounds the field, but the config file and the `FUMOX_*` env layer
/// do not, and each retry costs up to [`MAX_RETRY_BACKOFF`] while holding
/// the source's in-flight mark and one concurrency permit.
pub(crate) const MAX_RETRIES: u32 = 16;
/// Wall-clock ceiling for one fetch: the initial attempt, every retry and
/// every backoff sleep together.
///
/// The retry count and the per-request timeout bound a *single* attempt.
/// Without a ceiling for the whole fetch, a source that keeps answering
/// `503` holds a concurrency permit and the source's in-flight mark for
/// the sum of every backoff (16 retries from the shipped 500 ms base
/// already reach ~33 s of pure sleep, and every attempt adds up to a
/// connect plus a read timeout on top).
pub(crate) const MAX_FETCH_BUDGET: Duration = Duration::from_secs(180);

/// The wall-clock ceiling of one fetch, in seconds. The admin panel
/// quotes it next to the running refresh, so the operator knows how long
/// a slow source may take before it is dropped.
pub(crate) fn budget_seconds() -> u64 {
    MAX_FETCH_BUDGET.as_secs()
}

/// The number of requests one fetch may make: the first attempt plus
/// every retry it is allowed.
pub(crate) fn max_requests() -> u32 {
    MAX_RETRIES + 1
}

/// A successfully downloaded payload.
#[derive(Debug, Clone)]
pub struct FetchedPayload {
    pub http_status: u16,
    pub bytes: u64,
    pub body: Vec<u8>,
    /// How many HTTP attempts produced the payload (first try plus every
    /// retry), stamped by [`Fetcher::fetch`] once the loop is done.
    pub attempts: u32,
}

/// Classified fetch failure, maps 1:1 onto the `error_class` vocabulary.
#[derive(Debug, thiserror::Error)]
pub enum FetchFailure {
    #[error("network error: {message}")]
    Network {
        message: String,
        /// The URL itself is unusable (unparseable, no host, a scheme the
        /// fetcher does not speak). No attempt can change the outcome, so it
        /// is not retried; a real network fault is.
        permanent: bool,
        /// How many HTTP attempts ended in this failure (first try plus
        /// every retry), stamped by [`Fetcher::fetch`] once the loop is
        /// done; the constructors default to 1 (one attempt, no retry).
        attempts: u32,
    },
    #[error("server error: HTTP {status}")]
    HttpServer { status: u16, attempts: u32 },
    #[error("client error: HTTP {status}{}", detail(.reason.as_deref()))]
    HttpClient {
        status: u16,
        /// Why the request was refused, when the status code alone does not
        /// explain it. The text reaches `fetch_log.error` and
        /// `sources.last_error`, so it is the only trace the operator has
        /// of a chain that lost its source headers on the way.
        reason: Option<String>,
        attempts: u32,
    },
    #[error("response exceeds the {limit} byte cap")]
    ResponseTooLarge { limit: u64, attempts: u32 },
}

/// Render the optional client-error cause as a display suffix.
fn detail(reason: Option<&str>) -> String {
    match reason {
        Some(reason) => format!(": {reason}"),
        None => String::new(),
    }
}

impl FetchFailure {
    /// A client error with an optional human-readable cause; the text is
    /// what the operator reads in `fetch_log` and in the source's
    /// `last_error`. Synthesized client errors (SSRF 403, oversized-URL
    /// 414, redirect-loop 508) always pass a reason — the status alone
    /// would leave the operator guessing at a failure no upstream ever
    /// answered.
    fn http_client_why(status: u16, reason: Option<&str>) -> Self {
        FetchFailure::HttpClient {
            status,
            reason: reason.map(str::to_string),
            attempts: 1,
        }
    }

    /// Stamp the attempt count of a finished fetch. The constructors
    /// default to 1 (one attempt, no retry); the retry loop of
    /// [`Fetcher::fetch`] knows the real count and writes it here before
    /// returning the failure, so the journal row carries the number the
    /// caller actually paid for.
    fn set_attempts(&mut self, attempts: u32) {
        match self {
            FetchFailure::Network { attempts: n, .. }
            | FetchFailure::HttpServer { attempts: n, .. }
            | FetchFailure::HttpClient { attempts: n, .. }
            | FetchFailure::ResponseTooLarge { attempts: n, .. } => *n = attempts,
        }
    }

    /// How many HTTP attempts ended in this failure (first try plus every
    /// retry).
    pub fn attempts(&self) -> u32 {
        match self {
            FetchFailure::Network { attempts, .. }
            | FetchFailure::HttpServer { attempts, .. }
            | FetchFailure::HttpClient { attempts, .. }
            | FetchFailure::ResponseTooLarge { attempts, .. } => *attempts,
        }
    }

    /// The `error_class` this failure is journaled as.
    pub fn error_class(&self) -> ErrorClass {
        match self {
            FetchFailure::Network { .. } => ErrorClass::Network,
            FetchFailure::HttpServer { .. } => ErrorClass::HttpServer,
            FetchFailure::HttpClient { .. } => ErrorClass::HttpClient,
            FetchFailure::ResponseTooLarge { .. } => ErrorClass::HttpServer,
        }
    }

    /// Whether a retry can plausibly succeed.
    ///
    /// Two classes are left out because the same attempt fails the same way
    /// every time. `ResponseTooLarge` is a property of the body: a feed over
    /// `[fetch].max_response_bytes` is still over it on the fourth try, and
    /// every try reads the whole cap. A `permanent` network failure is a
    /// malformed URL rather than a fault, so re-reading it cannot help.
    pub fn is_recoverable(&self) -> bool {
        matches!(
            self,
            FetchFailure::Network {
                permanent: false,
                ..
            } | FetchFailure::HttpServer { .. }
        )
    }

    /// Upstream HTTP status, when there was one.
    pub fn http_status(&self) -> Option<u16> {
        match self {
            FetchFailure::HttpServer { status, .. } | FetchFailure::HttpClient { status, .. } => {
                Some(*status)
            }
            _ => None,
        }
    }
}

/// What kind of SSRF rejection this is.
///
/// The distinction decides what a caller may do with it: a policy
/// rejection is a property of the target and holds on every retry, a
/// transient one says only that the name could not be resolved this time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SsrfRejectionKind {
    /// The target is refused by the address policy: a private, loopback
    /// or link-local address, or a host that cannot serve the requested
    /// address family. The fetcher will refuse to dial it as well.
    Policy,
    /// The name could not be resolved: the resolver failed or the lookup
    /// timed out. Nothing is known about the target.
    Transient,
}

/// SSRF verdict for a URL or resolved IP.
#[derive(Debug, thiserror::Error)]
#[error("SSRF protection: {reason}")]
pub struct SsrfRejection {
    pub reason: String,
    /// Whether the target is refused by the policy or merely unresolvable
    /// right now.
    pub kind: SsrfRejectionKind,
}

/// The DNS resolution + SSRF vetting layer of the fetch path.
///
/// A seam, not an abstraction for its own sake: the redirect loop must
/// re-vet every hop, and the only honest way to test that is to answer
/// the vetting question per host. The production implementation resolves
/// and vets in one step ([`vet_host`]); a test supplies its own answers
/// and counts the calls, which turns "every hop is vetted again" from a
/// claim in a doc comment into an assertion.
pub(crate) trait HostResolver: Send + Sync {
    fn resolve_and_vet<'a>(
        &'a self,
        host: &'a str,
        family: IpFamily,
    ) -> Pin<Box<dyn Future<Output = Result<IpAddr, SsrfRejection>> + Send + 'a>>;
}

/// The production resolver: resolve the host, vet every address it
/// resolves to, and pick the connect address.
struct SsrfResolver {
    allow_private_urls: bool,
    dns_timeout: Duration,
}

impl HostResolver for SsrfResolver {
    fn resolve_and_vet<'a>(
        &'a self,
        host: &'a str,
        family: IpFamily,
    ) -> Pin<Box<dyn Future<Output = Result<IpAddr, SsrfRejection>> + Send + 'a>> {
        Box::pin(vet_host(
            host,
            self.allow_private_urls,
            family,
            self.dns_timeout,
        ))
    }
}

/// HTTP client wrapper carrying the fetch policy (timeouts, size cap,
/// retries, SSRF rules).
#[derive(Clone)]
pub struct Fetcher {
    config: FetchConfig,
    pub(crate) dns_timeout: Duration,
    /// The resolution + vetting layer; a seam so the redirect handling can
    /// be tested against hosts a real resolver would refuse.
    resolver: Arc<dyn HostResolver>,
    /// The wall-clock ceiling of one fetch: the first attempt, every retry
    /// and every backoff sleep share it.
    budget: Duration,
}

impl Fetcher {
    pub fn new(config: FetchConfig, allow_private_urls: bool, dns_timeout: Duration) -> Self {
        Self {
            resolver: Arc::new(SsrfResolver {
                allow_private_urls,
                dns_timeout,
            }),
            config,
            dns_timeout,
            budget: MAX_FETCH_BUDGET,
        }
    }

    /// Replace the wall-clock budget of one fetch. Test-only: the
    /// shipped budget is three minutes, far too long for a test to wait
    /// out.
    #[cfg(test)]
    fn with_budget(mut self, budget: Duration) -> Self {
        self.budget = budget;
        self
    }

    /// Replace the resolution + vetting layer. Test-only: it exists so a
    /// test can hand out an address per host and count the calls.
    #[cfg(test)]
    fn with_resolver(mut self, resolver: Arc<dyn HostResolver>) -> Self {
        self.resolver = resolver;
        self
    }

    /// Deployment-wide default family a source without its own `ip_family`
    /// resolves to (`[fetch] ip_family`).
    pub fn default_family(&self) -> IpFamily {
        self.config.ip_family
    }

    /// The retry count actually applied: the configured value capped at
    /// [`MAX_RETRIES`].
    fn effective_max_retries(&self) -> u32 {
        self.config.max_retries.min(MAX_RETRIES)
    }

    /// Build a one-shot client for a single fetch.
    ///
    /// reqwest exposes DNS override only on `ClientBuilder`, so the client
    /// is constructed per request with the vetted address pinned via
    /// `resolve()`, this is what closes the DNS-rebinding window between
    /// the SSRF check and the connect. Construction cost is negligible
    /// against network latency at the scheduler's fetch rate.
    ///
    /// `Policy::none()` is load-bearing, not a default: reqwest's redirect
    /// layer would consume the 3xx internally and hand back only the final
    /// response, which silently skips the per-hop SSRF vetting in
    /// [`Self::fetch_once`]. `resolve()` does
    /// not contain an automatic follow, it is a per-hostname DNS override,
    /// ignored outright for IP literals and overridden by a port in the
    /// redirect target, so the loop must see every hop itself.
    ///
    /// `no_proxy()` is load-bearing for the same reason: without it reqwest
    /// picks the `HTTP_PROXY` / `ALL_PROXY` environment configuration up,
    /// and the connection would leave the vetted address entirely. The
    /// vetting and the connect would then look at two different paths, and
    /// the pinned address would only describe the hop *to* the proxy. This
    /// process has no egress-proxy setting, so the environment must not
    /// smuggle one in.
    fn build_client(
        &self,
        host: &str,
        addr: SocketAddr,
        deadline: tokio::time::Instant,
    ) -> Result<reqwest::Client, reqwest::Error> {
        // reqwest is compiled without a crypto provider and panics when a
        // client is built before one is installed.
        fumox_core::tls::install_crypto_provider();
        // The request may not outlive the fetch budget: the whole-request
        // timeout is the smaller of the configured read timeout and what is
        // left of the budget.
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        let timeout = remaining.min(Duration::from_secs(self.config.read_timeout_secs));
        reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(self.config.connect_timeout_secs))
            .timeout(timeout)
            .user_agent(self.config.user_agent.clone())
            .gzip(true)
            .brotli(true)
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
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
    ///
    /// The whole fetch — the first attempt, every retry and every backoff
    /// sleep — shares one wall-clock budget ([`MAX_FETCH_BUDGET`]). The
    /// retry count alone does not bound the time: the backoff grows
    /// exponentially and every attempt adds a connect plus a read timeout.
    pub async fn fetch(
        &self,
        url: &str,
        headers: &std::collections::BTreeMap<String, String>,
        family: Option<IpFamily>,
    ) -> Result<FetchedPayload, FetchFailure> {
        let family = family.unwrap_or(self.config.ip_family);
        let max_retries = self.effective_max_retries();
        if max_retries != self.config.max_retries {
            tracing::warn!(
                configured = self.config.max_retries,
                applied = max_retries,
                "[fetch].max_retries is above the supported ceiling; using the ceiling"
            );
        }
        let deadline = tokio::time::Instant::now() + self.budget;
        let mut attempt = 0u32;
        loop {
            match self.fetch_once(url, headers, family, deadline).await {
                Ok(mut payload) => {
                    payload.attempts = attempt + 1;
                    return Ok(payload);
                }
                Err(mut failure) => {
                    failure.set_attempts(attempt + 1);
                    if attempt >= max_retries || !failure.is_recoverable() {
                        return Err(failure);
                    }
                    let delay = self.backoff_delay(attempt);
                    // A backoff that would run past the budget is not slept
                    // through: the budget is the ceiling, and the fetch ends
                    // with the cause of the failure rather than with a
                    // timeout nobody asked for.
                    if tokio::time::Instant::now() + delay >= deadline {
                        return Err(budget_exhausted(self.budget, &failure));
                    }
                    // The URL may carry userinfo credentials, never log it raw.
                    tracing::warn!(
                        url = %redact_url(url),
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
        deadline: tokio::time::Instant,
    ) -> Result<FetchedPayload, FetchFailure> {
        // Redirects are followed manually (up to MAX_REDIRECTS hops) because
        // every hop must pass the full SSRF vetting again, an automatic
        // redirect policy would let a public URL bounce the client into a
        // private or metadata address. `build_client` therefore pins
        // `Policy::none()`; see the note there.
        let mut current = url.to_string();
        // Source-configured headers may carry subscription secrets, and
        // reqwest only strips the standardized ones (`Authorization`,
        // `Cookie`, …) across a redirect. They stay scoped to the origin the
        // admin configured, so a redirect to a collector harvests nothing.
        let configured_origin = Url::parse(url).ok().map(|parsed| origin_of(&parsed));
        // Set when a hop had to withhold the source headers because the
        // redirect left the configured origin. Carried into the failure so
        // the operator sees why the request looked anonymous to the target.
        let mut withheld: Option<&'static str> = None;
        for _hop in 0..=MAX_REDIRECTS {
            if tokio::time::Instant::now() >= deadline {
                return Err(budget_exhausted(
                    self.budget,
                    &FetchFailure::Network {
                        message: "no time left in the fetch budget".to_string(),
                        permanent: false,
                        attempts: 1,
                    },
                ));
            }
            if current.len() > MAX_URL_LEN {
                return Err(FetchFailure::http_client_why(
                    414,
                    Some(&format!(
                        "URL grew past {MAX_URL_LEN} bytes after redirects"
                    )),
                ));
            }
            let parsed = Url::parse(&current).map_err(|e| FetchFailure::Network {
                message: format!("invalid URL: {e}"),
                permanent: true,
                attempts: 1,
            })?;
            match parsed.scheme() {
                "http" | "https" => {}
                other => {
                    return Err(FetchFailure::Network {
                        message: format!("unsupported scheme: {other}"),
                        permanent: true,
                        attempts: 1,
                    });
                }
            }

            // SSRF: resolve the host ourselves, vet every address, then pin
            // the chosen one so reqwest cannot be re-resolved (DNS
            // rebinding) to a different address between check and connect.
            let host = parsed.host_str().ok_or_else(|| FetchFailure::Network {
                message: "URL has no host".to_string(),
                permanent: true,
                attempts: 1,
            })?;
            let pinned = self
                .resolver
                .resolve_and_vet(host, family)
                .await
                .map_err(|e| {
                    // The URL may carry userinfo credentials, never log it raw.
                    tracing::warn!(url = %redact_url(&current), reason = %e, "SSRF protection blocked the fetch");
                    FetchFailure::http_client_why(403, Some("SSRF policy blocked the resolved address"))
                })?;
            let port = parsed
                .port_or_known_default()
                .unwrap_or(if parsed.scheme() == "https" { 443 } else { 80 });

            let client = self
                .build_client(host, SocketAddr::new(pinned, port), deadline)
                .map_err(|e| FetchFailure::Network {
                    message: redacted_request_error(&e),
                    permanent: false,
                    attempts: 1,
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
                withheld = Some("headers withheld: redirect left the configured origin");
                tracing::warn!(
                    url = %redact_url(&current),
                    "redirect left the configured origin, source headers withheld"
                );
            }

            let response = request.send().await.map_err(|e| FetchFailure::Network {
                message: redacted_request_error(&e),
                permanent: false,
                attempts: 1,
            })?;
            let status = response.status().as_u16();

            if (300..400).contains(&status) {
                let location = response
                    .headers()
                    .get(reqwest::header::LOCATION)
                    .and_then(|v| v.to_str().ok())
                    .ok_or_else(|| FetchFailure::http_client_why(status, withheld))?;
                current = parsed
                    .join(location)
                    .map_err(|_| FetchFailure::http_client_why(status, withheld))?
                    .to_string();
                continue;
            }

            // 408 (request timeout) and 429 (throttling) are 4xx by class
            // but transient by nature: the server itself says "try again",
            // so they are retried like the 5xx and journaled as
            // `http_server` (the class is the journal's coarse grouping,
            // not a retry verdict — [`FetchFailure::is_recoverable`] is).
            if status >= 500 || status == 408 || status == 429 {
                return Err(FetchFailure::HttpServer {
                    status,
                    attempts: 1,
                });
            }
            if !(200..300).contains(&status) {
                return Err(FetchFailure::http_client_why(status, withheld));
            }

            // Stream the body with a hard cap (decompression-bomb guard).
            let limit = self.config.max_response_bytes;
            let mut body: Vec<u8> = Vec::new();
            let mut stream = response;
            while let Some(chunk) = stream.chunk().await.map_err(|e| FetchFailure::Network {
                message: redacted_request_error(&e),
                permanent: false,
                attempts: 1,
            })? {
                if body.len() as u64 + chunk.len() as u64 > limit {
                    return Err(FetchFailure::ResponseTooLarge { limit, attempts: 1 });
                }
                body.extend_from_slice(&chunk);
            }
            let bytes = body.len() as u64;
            return Ok(FetchedPayload {
                http_status: status,
                bytes,
                body,
                attempts: 1,
            });
        }
        // Redirect chain longer than MAX_REDIRECTS, a persistent server
        // misconfiguration, reported as 508 Loop Detected.
        Err(FetchFailure::http_client_why(
            508,
            Some(&format!("redirect chain longer than {MAX_REDIRECTS} hops")),
        ))
    }
}

/// The failure reported when a fetch ran out of its wall-clock budget. The
/// cause of the last failure is kept: the budget is what stopped the
/// retrying, not what went wrong.
fn budget_exhausted(budget: Duration, cause: &FetchFailure) -> FetchFailure {
    FetchFailure::Network {
        message: format!(
            "fetch budget of {} exhausted ({cause})",
            format_budget(budget)
        ),
        permanent: false,
        attempts: 1,
    }
}

/// The budget as it reads in a message: seconds when it is a whole
/// number of them, milliseconds otherwise.
fn format_budget(budget: Duration) -> String {
    if budget.as_secs() > 0 {
        format!("{}s", budget.as_secs())
    } else {
        format!("{}ms", budget.as_millis())
    }
}

/// Scheme + host + effective port, the scope source headers are confined to.
/// A redirect that changes any of the three is a different origin, even when
/// only the port moved, the pinned DNS override does not constrain the port.
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
///
/// The tail is replaced rather than the URL text inside it: reqwest does
/// not always print the URL exactly as this process built it (it may drop
/// the userinfo or the default port), and a substitution that misses
/// leaves the raw credentials in the message.
fn redacted_request_error(error: &reqwest::Error) -> String {
    let text = error.to_string();
    let Some(url) = error.url() else {
        return text;
    };
    let redacted = redact_url(url.as_str());
    if let Some(idx) = text.find(" for url (") {
        return format!("{} for url ({redacted})", &text[..idx]);
    }
    if text.contains(url.as_str()) {
        return text.replace(url.as_str(), &redacted);
    }
    text
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

/// Pick the connect address from an already-vetted list. Re-exported from
/// `fumox_core::ssrf::pick_vetted` so the fetcher tests stay local.
pub(crate) use fumox_core::ssrf::pick_vetted as pick_address;

/// Resolve a host and vet every address against the SSRF policy, then pick
/// the connect address constrained to `family`. Shared by the fetch path
/// and the save-time check ([`vet_url_with_policy`]).
///
/// `dns_timeout` is the operator-supplied upper bound for the async DNS
/// resolution step. A hostile resolver can otherwise pin the runtime
/// worker for the OS resolver's default timeout (~30 s+).
pub async fn vet_host(
    host: &str,
    allow_private_urls: bool,
    family: IpFamily,
    dns_timeout: Duration,
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
                kind: SsrfRejectionKind::Policy,
            });
        }
        vec![ip]
    } else {
        // The name did not resolve: the target is unknown, not refused.
        let lookup = fumox_core::ssrf::lookup_with_timeout(host, dns_timeout)
            .await
            .map_err(|e| SsrfRejection {
                reason: e,
                kind: SsrfRejectionKind::Transient,
            })?;
        let addrs: Vec<IpAddr> = lookup
            .into_iter()
            .filter(|ip| family_matches(*ip, family))
            .collect();
        if addrs.is_empty() {
            return Err(SsrfRejection {
                reason: format!("no {} addresses for {host}", family_label(family)),
                kind: SsrfRejectionKind::Transient,
            });
        }
        addrs
    };
    for ip in &addrs {
        check_ip(*ip, allow_private_urls).map_err(|reason| SsrfRejection {
            reason: format!("{host} -> {ip}: {reason}"),
            kind: SsrfRejectionKind::Policy,
        })?;
    }
    pick_address(&addrs, family).ok_or_else(|| SsrfRejection {
        reason: format!("no {} addresses for {host}", family_label(family)),
        kind: SsrfRejectionKind::Transient,
    })
}

/// A static URL-validation problem, typed so this layer stays free of
/// i18n concerns: the admin layer maps each variant onto its `val.url_*`
/// catalog key and renders it with `Lang::t_args` in the panel language;
/// embedded diagnostics (URL-parser and SSRF-rejection details) stay
/// technical English, only the sentence around them is localized.
#[derive(Debug, Clone)]
pub enum UrlProblem {
    /// The URL is longer than the limit (the argument, in characters).
    TooLong(usize),
    /// The URL is malformed; the argument is the parser's message.
    Invalid(String),
    /// The URL uses a scheme other than http/https (the argument).
    Scheme(String),
    /// The URL has no host.
    NoHost,
    /// SSRF protection refused the target: the reason plus whether the
    /// refusal is a property of the address (policy) or of this moment
    /// (the name did not resolve).
    Ssrf {
        reason: String,
        kind: SsrfRejectionKind,
    },
}

impl UrlProblem {
    /// Whether the problem is a property of the URL itself, so a caller
    /// that retries gets the same answer. A name that did not resolve (an
    /// SSRF rejection of the transient kind) says nothing about the
    /// target and the fetch path re-checks it on every request.
    pub fn is_permanent(&self) -> bool {
        !matches!(
            self,
            UrlProblem::Ssrf {
                kind: SsrfRejectionKind::Transient,
                ..
            }
        )
    }
}

/// Static URL validation applied when a source is saved.
///
/// The DNS-level SSRF vetting happens at fetch time (addresses can change
/// between save and fetch), but scheme, length and host shape are checked
/// up front so that obviously bad URLs never reach the scheduler. The
/// parsed [`Url`] comes back with the verdict, so a caller that vetts the
/// host next does not parse the same string a second time.
pub fn validate_url(url: &str) -> Result<Url, UrlProblem> {
    if url.len() > MAX_URL_LEN {
        return Err(UrlProblem::TooLong(MAX_URL_LEN));
    }
    let parsed = Url::parse(url).map_err(|e| UrlProblem::Invalid(e.to_string()))?;
    match parsed.scheme() {
        "http" | "https" => {}
        other => return Err(UrlProblem::Scheme(other.to_string())),
    }
    if parsed.host_str().is_none() {
        return Err(UrlProblem::NoHost);
    }
    Ok(parsed)
}

/// Save-time SSRF check: static validation plus DNS
/// resolution and address vetting. The fetch path re-vets on every request
/// to defend against DNS rebinding, so a failure here is fast feedback for
/// the form, not the last line of defense. Private URLs are allowed by the
/// flag, but the DNS vetting still runs: `check_ip` passes every address
/// under `allow_private = true`, yet the family check of an IP literal and
/// the family filtering of the resolved addresses stay in force, so the
/// form flags a host that can never be reached. `family` is the source's
/// effective IP family (after resolving `None` against
/// `[fetch] ip_family`), so the form flags hosts that can never be reached
/// under the strict constraint.
///
/// The failure carries its kind ([`UrlProblem::is_permanent`]): a caller
/// that may treat an unresolvable name as a warning (the import path,
/// where the file is vetted again at fetch time) reads that instead of
/// parsing the message.
pub async fn vet_url_with_policy(
    url: &str,
    allow_private_urls: bool,
    family: IpFamily,
    dns_timeout: Duration,
) -> Result<(), UrlProblem> {
    let parsed = validate_url(url)?;
    let host = parsed.host_str().ok_or(UrlProblem::NoHost)?;
    vet_host(host, allow_private_urls, family, dns_timeout)
        .await
        .map(|_| ())
        .map_err(|e| UrlProblem::Ssrf {
            reason: e.reason,
            kind: e.kind,
        })
}

/// Vet a single IP address against the SSRF policy. A decorated form of
/// `fumox_core::ssrf::vet_addr`: the blocklist lives in `fumox-core` so
/// the probe daemon applies the identical policy to its dial targets, the
/// server only flattens the typed reason into a message.
///
/// With `allow_private = false` the rejected set is the one the core
/// policy documents (loopback, RFC 1918, link-local incl. the cloud
/// metadata endpoint, CGNAT, the reserved, benchmark and TEST-NET ranges,
/// and every IPv6 transition form).
pub fn check_ip(ip: IpAddr, allow_private: bool) -> Result<(), String> {
    fumox_core::ssrf::vet_addr(ip, allow_private)
        .map(|_| ())
        .map_err(|reason| reason.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn backoff_delay_is_capped_and_never_overflows() {
        let fetcher = Fetcher::new(FetchConfig::default(), true, Duration::from_secs(5));
        assert_eq!(fetcher.backoff_delay(0), Duration::from_millis(500));
        assert_eq!(fetcher.backoff_delay(1), Duration::from_millis(1000));
        // An absurd max_retries must saturate into the cap, not overflow
        // (debug builds would panic on the raw 2u64.pow).
        assert_eq!(fetcher.backoff_delay(100), Duration::from_secs(60));

        let huge = FetchConfig {
            retry_base_backoff_ms: u64::MAX,
            ..FetchConfig::default()
        };
        let fetcher = Fetcher::new(huge, true, Duration::from_secs(5));
        assert_eq!(fetcher.backoff_delay(0), Duration::from_secs(60));
    }

    /// The server-side gate is a decorated form of the core policy: the
    /// blocklist is not forked here, every verdict (and its class code)
    /// comes from `fumox_core::ssrf`. The range coverage itself is pinned
    /// by the core suite (`ssrf::tests`), not duplicated.
    #[test]
    fn check_ip_is_the_decorated_core_policy() {
        for addr in [
            "127.0.0.1",
            "169.254.169.254",
            "8.8.8.8",
            "2606:4700:4700::1111",
        ] {
            assert_eq!(
                check_ip(ip(addr), false).is_ok(),
                fumox_core::ssrf::vet_addr(ip(addr), false).is_ok(),
                "{addr} verdict must match the core policy"
            );
        }
        // The allow flag is passed through unchanged.
        assert!(check_ip(ip("127.0.0.1"), true).is_ok());
        // The decorated message still names the refused range.
        let reason = check_ip(ip("169.254.169.254"), false).unwrap_err();
        assert!(reason.contains("link-local"), "{reason}");
    }

    #[test]
    fn failure_classification() {
        assert_eq!(
            FetchFailure::Network {
                message: "x".into(),
                permanent: false,
                attempts: 1,
            }
            .error_class(),
            ErrorClass::Network
        );
        assert_eq!(
            FetchFailure::HttpServer {
                status: 503,
                attempts: 1
            }
            .error_class(),
            ErrorClass::HttpServer
        );
        assert_eq!(
            FetchFailure::http_client_why(404, None).error_class(),
            ErrorClass::HttpClient
        );
        assert_eq!(
            FetchFailure::ResponseTooLarge {
                limit: 10,
                attempts: 1
            }
            .error_class(),
            ErrorClass::HttpServer
        );
        // A body over the cap and a malformed URL fail identically on every
        // attempt, so neither is retried; a real network fault still is.
        assert!(
            !FetchFailure::ResponseTooLarge {
                limit: 10,
                attempts: 1
            }
            .is_recoverable()
        );
        assert!(
            !FetchFailure::Network {
                message: "x".into(),
                permanent: true,
                attempts: 1,
            }
            .is_recoverable()
        );
        assert!(
            FetchFailure::Network {
                message: "x".into(),
                permanent: false,
                attempts: 1,
            }
            .is_recoverable()
        );
        assert!(
            FetchFailure::HttpServer {
                status: 500,
                attempts: 1
            }
            .is_recoverable()
        );
        assert!(!FetchFailure::http_client_why(404, None).is_recoverable());
        assert_eq!(
            FetchFailure::http_client_why(404, None).http_status(),
            Some(404)
        );
    }

    #[test]
    fn url_validation() {
        // The Ok value is the parsed URL, so a caller that vetts the host
        // next does not parse the same string twice.
        let parsed = validate_url("https://example.com/sub").unwrap();
        assert_eq!(parsed.host_str(), Some("example.com"));
        assert!(validate_url("http://example.com").is_ok());
        assert!(validate_url("ftp://example.com").is_err());
        assert!(validate_url("not a url").is_err());
        assert!(validate_url(&format!("https://example.com/{}", "x".repeat(3000))).is_err());
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
        let v4 = vet_host("203.0.113.10", true, IpFamily::Ipv6, Duration::from_secs(5))
            .await
            .unwrap_err();
        assert!(v4.reason.contains("IPv4"), "{}", v4.reason);
        let v6 = vet_host("2001:db8::1", true, IpFamily::Ipv4, Duration::from_secs(5))
            .await
            .unwrap_err();
        assert!(v6.reason.contains("IPv6"), "{}", v6.reason);
        // The matching family passes.
        assert!(
            vet_host("2001:db8::1", true, IpFamily::Ipv6, Duration::from_secs(5))
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn vet_host_returns_timeout_or_resolution_error() {
        // On macOS the OS resolver short-circuits `.invalid` synchronously
        // with a "DNS resolution failed" error; on glibc with a hostile
        // resolver the wrapper returns "timed out". Both prove the call
        // returns quickly under the operator's `dns_timeout` knob.
        let rejection = vet_host(
            "this-host-does-not-exist.invalid",
            false,
            IpFamily::Any,
            Duration::from_millis(100),
        )
        .await
        .unwrap_err();
        assert!(
            rejection.reason.contains("timed out")
                || rejection.reason.contains("DNS resolution failed"),
            "expected timeout or resolution-failure, got: {}",
            rejection.reason
        );
    }

    /// Minimal HTTP/1.1 responder on 127.0.0.1; serves any number of
    /// requests while the test runtime lives. One shape for every test
    /// endpoint: `make` builds each response from the request bytes it
    /// receives, a counter it needs lives in an `Arc` the test owns and
    /// the closure captures.
    async fn spawn_responder(
        make: impl Fn(&[u8]) -> Vec<u8> + Send + 'static,
    ) -> std::net::SocketAddr {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((mut sock, _)) = listener.accept().await {
                use tokio::io::{AsyncReadExt, AsyncWriteExt};
                let mut buf = [0u8; 4096];
                let n = sock.read(&mut buf).await.unwrap_or(0);
                let response = make(&buf[..n]);
                let _ = sock.write_all(&response).await;
            }
        });
        addr
    }

    /// Minimal HTTP/1.1 responder on 127.0.0.1; serves any number of
    /// requests while the test runtime lives.
    async fn spawn_v4_listener() -> std::net::SocketAddr {
        spawn_responder(|_| b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nok".to_vec()).await
    }

    /// Responder that answers every request with `302 Location: <target>`.
    async fn spawn_redirector(target: String) -> std::net::SocketAddr {
        spawn_responder(move |_| {
            format!("HTTP/1.1 302 Found\r\nLocation: {target}\r\ncontent-length: 0\r\n\r\n")
                .into_bytes()
        })
        .await
    }

    /// Responder that echoes back which of the request's headers it saw,
    /// so a test can assert what survived a redirect.
    async fn spawn_header_echo() -> std::net::SocketAddr {
        spawn_responder(|request| {
            let request = String::from_utf8_lossy(request).to_ascii_lowercase();
            let body = if request.contains("x-subscription-token:") {
                "LEAKED"
            } else {
                "clean"
            };
            format!(
                "HTTP/1.1 200 OK\r\ncontent-length: {}\r\n\r\n{body}",
                body.len()
            )
            .into_bytes()
        })
        .await
    }

    /// The manual redirect loop follows the redirect itself: a strict
    /// fetcher refuses the private first hop before any redirect is
    /// seen, and a lenient one walks the chain and comes back with the
    /// body of the target. The per-hop re-vetting of the *target* is
    /// covered by [`every_redirect_hop_is_vetted_again`], which can hand
    /// the resolver a public first host and a private target.
    #[tokio::test]
    async fn a_redirect_into_a_private_address_is_blocked() {
        let internal = spawn_v4_listener().await;
        // The source itself is vetted with allow_private=true (it is a
        // loopback listener in the test), but the hop is re-vetted strictly.
        let redirector = spawn_redirector(format!("http://{internal}/meta-data")).await;

        let strict = Fetcher::new(FetchConfig::default(), false, Duration::from_secs(5));
        let err = strict
            .fetch(
                &format!("http://{redirector}/sub"),
                &Default::default(),
                None,
            )
            .await
            .unwrap_err();
        // The very first hop is already private here, so vetting rejects it
        // before any redirect, assert the class, then prove the hop itself
        // is seen by a lenient fetcher below.
        assert_eq!(err.error_class(), ErrorClass::HttpClient);
        assert!(!err.is_recoverable());

        // With private URLs allowed the same chain succeeds, which proves the
        // loop followed the redirect manually rather than erroring out.
        let lenient = Fetcher::new(FetchConfig::default(), true, Duration::from_secs(5));
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
        let fetcher = Fetcher::new(FetchConfig::default(), true, Duration::from_secs(5));
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
        let fetcher = Fetcher::new(FetchConfig::default(), true, Duration::from_secs(5));
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

    /// Responder answering every request with `status`; the returned
    /// counter records how many requests arrived, which is how a test
    /// observes whether (and how often) the retry loop ran.
    async fn spawn_canned_listener(
        status: u16,
    ) -> (std::net::SocketAddr, Arc<std::sync::atomic::AtomicUsize>) {
        let hits = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counter = Arc::clone(&hits);
        let addr = spawn_responder(move |_| {
            use std::sync::atomic::Ordering;
            counter.fetch_add(1, Ordering::SeqCst);
            format!("HTTP/1.1 {status} canned\r\ncontent-length: 2\r\n\r\nno").into_bytes()
        })
        .await;
        (addr, hits)
    }

    /// 503 on the first request, 200 `ok` on every later one.
    async fn spawn_recovering_listener()
    -> (std::net::SocketAddr, Arc<std::sync::atomic::AtomicUsize>) {
        let hits = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counter = Arc::clone(&hits);
        let addr = spawn_responder(move |_| {
            use std::sync::atomic::Ordering;
            let nth = counter.fetch_add(1, Ordering::SeqCst);
            if nth == 0 {
                b"HTTP/1.1 503 later\r\ncontent-length: 0\r\n\r\n".to_vec()
            } else {
                b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nok".to_vec()
            }
        })
        .await;
        (addr, hits)
    }

    /// Responder serving a deterministic 64 KiB body.
    async fn spawn_body_listener() -> std::net::SocketAddr {
        spawn_responder(|_| {
            let body = vec![b'x'; 64 * 1024];
            let mut response =
                format!("HTTP/1.1 200 OK\r\ncontent-length: {}\r\n\r\n", body.len()).into_bytes();
            response.extend_from_slice(&body);
            response
        })
        .await
    }

    /// The retry loop exists for transient upstream failures: a 503
    /// followed by a 200 must come back as a success after exactly one
    /// retry, an always-503 must give up after `max_retries` (3 attempts
    /// for 2 retries), and a client error must return without any retry.
    #[tokio::test]
    async fn retryable_failures_are_retried_and_client_errors_are_not() {
        use std::sync::atomic::Ordering;

        let (addr, hits) = spawn_recovering_listener().await;
        let config = FetchConfig {
            retry_base_backoff_ms: 1,
            ..FetchConfig::default()
        };
        let fetcher = Fetcher::new(config.clone(), true, Duration::from_secs(5));
        let payload = fetcher
            .fetch(&format!("http://{addr}/sub"), &Default::default(), None)
            .await
            .unwrap();
        assert_eq!(payload.body, b"ok");
        assert_eq!(hits.load(Ordering::SeqCst), 2, "503 then 200 = one retry");

        let (addr, hits) = spawn_canned_listener(503).await;
        let config = FetchConfig {
            max_retries: 2,
            retry_base_backoff_ms: 1,
            ..FetchConfig::default()
        };
        let fetcher = Fetcher::new(config, true, Duration::from_secs(5));
        let err = fetcher
            .fetch(&format!("http://{addr}/sub"), &Default::default(), None)
            .await
            .unwrap_err();
        assert!(matches!(err, FetchFailure::HttpServer { status: 503, .. }));
        assert_eq!(
            hits.load(Ordering::SeqCst),
            3,
            "max_retries = 2 means the initial attempt plus two retries"
        );
        // The attempt count travels with the failure into the journal:
        // three requests, not one.
        assert_eq!(err.attempts(), 3);

        // 403 is not recoverable: exactly one attempt, no backoff sleep.
        let (addr, hits) = spawn_canned_listener(403).await;
        let fetcher = Fetcher::new(FetchConfig::default(), true, Duration::from_secs(5));
        let err = fetcher
            .fetch(&format!("http://{addr}/sub"), &Default::default(), None)
            .await
            .unwrap_err();
        assert!(matches!(err, FetchFailure::HttpClient { status: 403, .. }));
        assert_eq!(hits.load(Ordering::SeqCst), 1, "403 is terminal");

        // 408 and 429 are 4xx by class but transient by nature: the server
        // itself says "try again", so they are retried like the 5xx and
        // journaled as `http_server`.
        for status in [408u16, 429] {
            let (addr, hits) = spawn_canned_listener(status).await;
            let config = FetchConfig {
                retry_base_backoff_ms: 1,
                ..FetchConfig::default()
            };
            let fetcher = Fetcher::new(config, true, Duration::from_secs(5));
            let err = fetcher
                .fetch(&format!("http://{addr}/sub"), &Default::default(), None)
                .await
                .unwrap_err();
            assert!(
                matches!(err, FetchFailure::HttpServer { .. }),
                "HTTP {status} must be classified as a server error, got {err:?}"
            );
            assert!(
                err.attempts() > 1,
                "HTTP {status} must be retried, attempts: {}",
                err.attempts()
            );
            assert!(
                hits.load(Ordering::SeqCst) > 1,
                "HTTP {status} must reach the listener more than once"
            );
        }
    }

    /// The body cap is the decompression-bomb guard: a response larger
    /// than `max_response_bytes` fails as `ResponseTooLarge` instead of
    /// being buffered to completion. The class is `http_server` — the
    /// `error_class` vocabulary is the journal's coarse grouping, not a
    /// retry verdict — while [`FetchFailure::is_recoverable`] says false:
    /// the same body is over the cap on every attempt, so retrying reads
    /// the whole oversized body again. The same body under a bigger cap
    /// passes.
    #[tokio::test]
    async fn oversized_bodies_stop_at_the_configured_cap() {
        let addr = spawn_body_listener().await;

        let config = FetchConfig {
            max_response_bytes: 1024,
            ..FetchConfig::default()
        };
        let fetcher = Fetcher::new(config, true, Duration::from_secs(5));
        let err = fetcher
            .fetch(&format!("http://{addr}/sub"), &Default::default(), None)
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            FetchFailure::ResponseTooLarge { limit: 1024, .. }
        ));
        assert_eq!(err.error_class(), ErrorClass::HttpServer);
        // The body is over the cap on every attempt, so it is not retried.
        assert!(!err.is_recoverable());

        let config = FetchConfig {
            max_response_bytes: 128 * 1024,
            ..FetchConfig::default()
        };
        let fetcher = Fetcher::new(config, true, Duration::from_secs(5));
        let payload = fetcher
            .fetch(&format!("http://{addr}/sub"), &Default::default(), None)
            .await
            .unwrap();
        assert_eq!(payload.bytes, 64 * 1024);
    }

    /// A redirect sequence longer than MAX_REDIRECTS terminates as 508
    /// Loop Detected instead of chasing forever. The hop count proves the
    /// cap is enforced on the wire (the initial request plus MAX_REDIRECTS
    /// followed hops), and the failure is terminal: `HttpClient`, never
    /// retried.
    #[tokio::test]
    async fn redirect_chains_longer_than_the_cap_end_as_loop_detected() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let hops = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counter = hops.clone();
        tokio::spawn(async move {
            while let Ok((mut sock, _)) = listener.accept().await {
                use std::sync::atomic::Ordering;
                use tokio::io::{AsyncReadExt, AsyncWriteExt};
                let mut buf = [0u8; 1024];
                let _ = sock.read(&mut buf).await;
                counter.fetch_add(1, Ordering::SeqCst);
                let response = format!(
                    "HTTP/1.1 302 Found\r\nLocation: http://{addr}/again\r\ncontent-length: 0\r\n\r\n"
                );
                let _ = sock.write_all(response.as_bytes()).await;
            }
        });

        let fetcher = Fetcher::new(FetchConfig::default(), true, Duration::from_secs(5));
        let err = fetcher
            .fetch(&format!("http://{addr}/start"), &Default::default(), None)
            .await
            .unwrap_err();
        assert!(
            matches!(err, FetchFailure::HttpClient { status: 508, .. }),
            "expected 508 Loop Detected, got {err:?}"
        );
        assert!(!err.is_recoverable());
        assert_eq!(
            hops.load(std::sync::atomic::Ordering::SeqCst),
            MAX_REDIRECTS + 1,
            "initial request plus MAX_REDIRECTS followed hops"
        );
    }

    /// A gzip stream of 128 KiB of zeros: 161 bytes on the wire that expand
    /// to 131072 bytes of body. The compressed size is what the wire
    /// carries, the expanded size is what the cap has to count.
    const GZIP_128K_ZEROS: [u8; 161] = [
        31, 139, 8, 0, 0, 0, 0, 0, 2, 255, 237, 193, 49, 1, 0, 0, 0, 194, 160, 245, 79, 237, 97,
        13, 160, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 110, 205, 205, 232, 126, 0, 0, 2, 0,
    ];

    /// Responder serving a gzip-compressed body with the matching
    /// `content-encoding` header, so the client decompresses it.
    async fn spawn_gzip_listener(body: &'static [u8]) -> std::net::SocketAddr {
        spawn_responder(move |_| {
            let mut response = format!(
                "HTTP/1.1 200 OK\r\ncontent-encoding: gzip\r\ncontent-length: {}\r\n\r\n",
                body.len()
            )
            .into_bytes();
            response.extend_from_slice(body);
            response
        })
        .await
    }

    /// Responder that accepts the connection and closes it at once, so the
    /// request fails inside the client and the failure text is built from
    /// the request that carried the credentials.
    async fn spawn_closing_listener() -> std::net::SocketAddr {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((sock, _)) = listener.accept().await {
                drop(sock);
            }
        });
        addr
    }

    /// The size cap counts the *decompressed* bytes. A body that is tiny
    /// on the wire and huge after decompression must still be refused,
    /// otherwise the cap is a decompression-bomb hole.
    #[tokio::test]
    async fn a_gzip_body_is_capped_after_decompression() {
        let addr = spawn_gzip_listener(&GZIP_128K_ZEROS).await;
        let config = FetchConfig {
            max_response_bytes: 64 * 1024,
            ..FetchConfig::default()
        };
        let fetcher = Fetcher::new(config, true, Duration::from_secs(5));
        let err = fetcher
            .fetch(&format!("http://{addr}/sub"), &Default::default(), None)
            .await
            .unwrap_err();
        assert!(
            matches!(err, FetchFailure::ResponseTooLarge { limit: 65536, .. }),
            "expected the decompressed body to hit the cap, got {err:?}"
        );
    }

    /// The credentials a source URL carries must not survive into the
    /// failure text: the userinfo and the token query pair end up in
    /// `fetch_log.error` and in the source's `last_error`, which live in
    /// the database and in every log shipper downstream of it.
    #[tokio::test]
    async fn a_failing_fetch_does_not_leak_the_source_credentials() {
        let addr = spawn_closing_listener().await;
        let config = FetchConfig {
            max_retries: 0,
            ..FetchConfig::default()
        };
        let fetcher = Fetcher::new(config, true, Duration::from_secs(5));
        let err = fetcher
            .fetch(
                &format!("http://user:SECRET@{addr}/sub?token=TOPSECRET"),
                &Default::default(),
                None,
            )
            .await
            .unwrap_err();
        let FetchFailure::Network { message, .. } = &err else {
            panic!("expected a network failure, got {err:?}");
        };
        assert!(!message.contains("SECRET"), "credentials leaked: {message}");
        assert!(!message.contains("TOPSECRET"), "token leaked: {message}");
    }

    /// The credential-bearing query names the feeds use in the wild: a
    /// signature, a session id, a credential of its own. A harmless pair
    /// survives, because the query is where the diagnostics are.
    #[test]
    fn credential_bearing_query_names_are_masked() {
        for url in [
            "https://example.com/sub?X-Amz-Signature=abc",
            "https://example.com/sub?sig=abc",
            "https://example.com/sub?session=abc",
            "https://example.com/sub?jsessionid=abc",
            "https://example.com/sub?credential=abc",
        ] {
            let redacted = redact_url(url);
            assert!(!redacted.contains("abc"), "{url} -> {redacted}");
            assert!(redacted.contains("[redacted]"), "{url} -> {redacted}");
        }
        assert_eq!(
            redact_url("https://example.com/sub?page=2"),
            "https://example.com/sub?page=2"
        );
    }

    /// A chain that lost its source headers has to say so: the refusal the
    /// collector answers with is otherwise indistinguishable from a plain
    /// 403, and the operator cannot tell that the subscription token never
    /// reached the target.
    #[tokio::test]
    async fn a_refused_redirect_states_that_the_headers_were_withheld() {
        let (collector, _) = spawn_canned_listener(403).await;
        let redirector = spawn_redirector(format!("http://{collector}/collect")).await;
        let fetcher = Fetcher::new(FetchConfig::default(), true, Duration::from_secs(5));
        let headers = std::collections::BTreeMap::from([(
            "X-Subscription-Token".to_string(),
            "SECRET".to_string(),
        )]);

        let err = fetcher
            .fetch(&format!("http://{redirector}/sub"), &headers, None)
            .await
            .unwrap_err();
        let text = err.to_string();
        match &err {
            FetchFailure::HttpClient { status, reason, .. } => {
                assert_eq!(*status, 403);
                assert_eq!(
                    reason.as_deref(),
                    Some("headers withheld: redirect left the configured origin")
                );
            }
            other => panic!("expected a client error, got {other:?}"),
        }
        // The reason travels with the journal text the operator reads.
        assert!(text.contains("headers withheld"), "{text}");
    }

    /// The retry ceiling is applied, not merely documented: the config
    /// file and the `FUMOX_*` env layer can ask for more retries than the
    /// process supports, and the request must not be made more often.
    #[test]
    fn the_retry_count_is_capped_at_the_supported_ceiling() {
        let fetcher = Fetcher::new(
            FetchConfig {
                max_retries: 100,
                ..FetchConfig::default()
            },
            true,
            Duration::from_secs(5),
        );
        assert_eq!(fetcher.effective_max_retries(), MAX_RETRIES);
        assert_eq!(MAX_RETRIES, 16);
    }

    /// The same ceiling on the wire: a source that always answers `503`
    /// is asked exactly as often as the ceiling allows, no matter what the
    /// configuration asked for.
    #[tokio::test]
    async fn an_oversized_retry_count_stops_at_the_ceiling() {
        use std::sync::atomic::Ordering;

        let (addr, hits) = spawn_canned_listener(503).await;
        let config = FetchConfig {
            max_retries: 100,
            // No backoff: the point of the test is the number of attempts,
            // and the real backoff would stretch it into a minute of
            // sleeping.
            retry_base_backoff_ms: 0,
            ..FetchConfig::default()
        };
        let fetcher = Fetcher::new(config, true, Duration::from_secs(5));
        let err = fetcher
            .fetch(&format!("http://{addr}/sub"), &Default::default(), None)
            .await
            .unwrap_err();
        assert!(matches!(err, FetchFailure::HttpServer { status: 503, .. }));
        assert_eq!(
            hits.load(Ordering::SeqCst),
            (MAX_RETRIES + 1) as usize,
            "the initial attempt plus the capped retries"
        );
    }

    /// One fetch has one wall-clock budget: the attempts and the backoffs
    /// share it, so a source that never recovers cannot hold a
    /// concurrency permit and the source's in-flight mark for the sum of
    /// every backoff.
    #[tokio::test]
    async fn a_fetch_is_bounded_by_its_wall_clock_budget() {
        use std::sync::atomic::Ordering;

        let (addr, hits) = spawn_canned_listener(503).await;
        let config = FetchConfig {
            max_retries: 100,
            retry_base_backoff_ms: 50,
            ..FetchConfig::default()
        };
        let fetcher = Fetcher::new(config, true, Duration::from_secs(5))
            .with_budget(Duration::from_millis(300));
        let err = fetcher
            .fetch(&format!("http://{addr}/sub"), &Default::default(), None)
            .await
            .unwrap_err();
        let text = err.to_string();
        assert!(text.contains("fetch budget of 300ms"), "{text}");
        // It was the budget that ended the retrying, not the retry
        // ceiling: the ceiling would have allowed seventeen attempts.
        assert!(
            hits.load(Ordering::SeqCst) < (MAX_RETRIES + 1) as usize,
            "the budget must cut the retrying short"
        );
    }

    /// The client must not pick up the environment proxy configuration:
    /// the vetted address and the address that is connected to have to be
    /// the same one, and a proxy in between would make the vetting
    /// describe a path the request does not take.
    ///
    /// The proxy variables are process-global, so the fetch runs in a child
    /// process: setting them here would change the behaviour of every
    /// other test in this binary.
    #[test]
    fn the_client_ignores_the_environment_proxy_configuration() {
        let exe = std::env::current_exe().expect("test executable path");
        let output = std::process::Command::new(exe)
            .args([
                "--ignored",
                "--exact",
                "fetcher::tests::a_fetch_ignores_the_environment_proxy",
                "--nocapture",
            ])
            // A proxy that points nowhere: a request that went through it
            // could not succeed.
            .env("ALL_PROXY", "http://127.0.0.1:1")
            .env("all_proxy", "http://127.0.0.1:1")
            .env("HTTP_PROXY", "http://127.0.0.1:1")
            .env("http_proxy", "http://127.0.0.1:1")
            .output()
            .expect("the child test must run");
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            output.status.success(),
            "the fetch failed with a proxy environment set:\nstdout: {stdout}\nstderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        // The child really ran: a name that matches nothing exits zero
        // without a test, and the check above would pass on a green run
        // that tested nothing.
        assert!(
            stdout.contains("1 passed"),
            "the child test did not run:\n{stdout}"
        );
    }

    /// The child half of
    /// [`the_client_ignores_the_environment_proxy_configuration`]: it runs
    /// with a proxy environment that points nowhere and fetches a local
    /// listener, which only succeeds when the environment proxy is
    /// ignored.
    #[tokio::test]
    #[ignore = "run by the_client_ignores_the_environment_proxy_configuration parent"]
    async fn a_fetch_ignores_the_environment_proxy() {
        let addr = spawn_v4_listener().await;
        let fetcher = Fetcher::new(FetchConfig::default(), true, Duration::from_secs(5));
        let payload = fetcher
            .fetch(&format!("http://{addr}/sub"), &Default::default(), None)
            .await
            .expect("the environment proxy must be ignored");
        assert_eq!(payload.body, b"ok");
    }

    /// A resolver that answers per host and records the hosts it was
    /// asked about.
    struct ScriptedResolver {
        /// The answer per host: the address to hand out, or the reason to
        /// refuse the host.
        answers: std::collections::HashMap<String, Result<IpAddr, String>>,
        calls: std::sync::Mutex<Vec<String>>,
    }

    impl HostResolver for ScriptedResolver {
        fn resolve_and_vet<'a>(
            &'a self,
            host: &'a str,
            _family: IpFamily,
        ) -> Pin<Box<dyn Future<Output = Result<IpAddr, SsrfRejection>> + Send + 'a>> {
            let answer = self.answers.get(host).cloned();
            self.calls
                .lock()
                .unwrap_or_else(|poison| poison.into_inner())
                .push(host.to_string());
            Box::pin(std::future::ready(match answer {
                Some(Ok(addr)) => Ok(addr),
                Some(Err(reason)) => Err(SsrfRejection {
                    reason,
                    kind: SsrfRejectionKind::Policy,
                }),
                None => Err(SsrfRejection {
                    reason: format!("no scripted answer for {host}"),
                    kind: SsrfRejectionKind::Policy,
                }),
            }))
        }
    }

    /// The manual redirect loop must re-vet *every* hop: a vetted public
    /// source must not be able to bounce the fetch into a private
    /// address. The resolver seam answers per host and records what it
    /// was asked, so the test can show that the second hop went through
    /// the vetting layer and was refused there.
    #[tokio::test]
    async fn every_redirect_hop_is_vetted_again() {
        let redirector = spawn_redirector("http://internal.example/meta-data".to_string()).await;
        let resolver = Arc::new(ScriptedResolver {
            answers: std::collections::HashMap::from([
                ("public.example".to_string(), Ok(ip("127.0.0.1"))),
                (
                    "internal.example".to_string(),
                    Err("private address is not allowed".to_string()),
                ),
            ]),
            calls: std::sync::Mutex::new(Vec::new()),
        });
        let fetcher = Fetcher::new(FetchConfig::default(), false, Duration::from_secs(5))
            .with_resolver(resolver.clone());

        let err = fetcher
            .fetch(
                &format!("http://public.example:{}/sub", redirector.port()),
                &Default::default(),
                None,
            )
            .await
            .unwrap_err();
        // The refusal is a client error: the source configuration is at
        // fault and retrying cannot help.
        assert_eq!(err.error_class(), ErrorClass::HttpClient);
        assert!(!err.is_recoverable());

        // Both hops went through the vetting layer, and the second one is
        // the hop that was refused.
        let calls = resolver
            .calls
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .clone();
        assert_eq!(
            calls,
            vec!["public.example".to_string(), "internal.example".to_string()],
            "every hop must be vetted again"
        );
    }
}
