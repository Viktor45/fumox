//! meow-rs REST client for T2 checks.
//!
//! meow-rs runs as a separate system service; the probe talks to its REST
//! API at four endpoints: `GET /version` (liveness), `PUT /configs` (hot
//! reload of the generated Clash YAML), `GET /proxies/{name}/delay` (the
//! tunnel check itself) and `GET /memory` (the kernel's RSS feed for the
//! admin card). Unavailability is reported, never fatal: the daemon skips
//! T2 with backoff and keeps running T1.
//!
//! The client draws one line and keeps it: a *verdict about the proxy*
//! (`ProxyFailed`) may be charged to the proxy's fail budget, a *fault of
//! the engine* (`ServiceUnavailable`) may not. The controller can rewrite
//! the proxy kernel's configuration, so it is also vetted at startup: it
//! must not live in public address space, and every request it answers
//! carries its bearer token.

use std::net::IpAddr;
use std::time::Duration;

use fumox_core::config::MeowConfig;
use rand::seq::IndexedRandom;

pub struct MeowClient {
    http: reqwest::Client,
    base_url: String,
    test_urls: Vec<String>,
    timeout: Duration,
    /// Bearer token for the external-controller, empty when the
    /// controller is unauthenticated.
    api_token: String,
    /// The controller host as configured. A name is resolved (and vetted)
    /// at startup, see [`MeowClient::verify_address`].
    host: String,
    /// Whether the host is a name rather than an IP literal.
    host_is_name: bool,
}

/// One sample of the proxy kernel's memory use.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MeowMemory {
    /// Resident set size of the meow-rs process, in bytes.
    pub rss_bytes: u64,
    /// Host cgroup/system memory limit meow-rs resolved, in bytes.
    pub os_limit_bytes: u64,
}

/// Outcome of one delay measurement.
#[derive(Debug)]
pub enum DelayOutcome {
    /// Tunnel established; latency in milliseconds.
    Ok(u64),
    /// meow-rs answered, but the proxy failed the tunnel test. This is the
    /// outcome meow reports for a dead or unusably slow proxy (its 503 and
    /// 504), and it never contributes to the engine-down abort.
    ///
    /// The only outcome that may be charged to the proxy's fail budget.
    ProxyFailed(String),
    /// meow-rs itself did not judge the proxy: it was unreachable, it
    /// answered with a status that is not a probe verdict, or it sent a
    /// body the probe cannot read. The batch is aborted without touching
    /// any proxy status.
    ///
    /// A request the engine *refused* (an unknown proxy name, a wrong
    /// token) lands here too: the engine did not run a tunnel test, so
    /// there is no verdict to charge anybody with.
    ServiceUnavailable(String),
}

/// How far the controller can be reached from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ControllerScope {
    /// Loopback: nothing but this host reaches the controller.
    Loopback,
    /// A private network: the local network reaches the controller.
    Private,
}

/// Vet the configured controller address and split it into host and port.
///
/// The controller carries the bearer token on every request and can
/// rewrite the proxy kernel's configuration, so it must stay where
/// nobody else reaches it: a public address would hand the token to the
/// internet. A private-network controller is allowed, but it needs the
/// token (see [`MeowClient::new`]).
fn vet_api_addr(addr: &str) -> Result<(String, u16, ControllerScope), String> {
    let trimmed = addr.trim();
    // The client prepends its own scheme when it dials the controller, so
    // a value that carries one would produce a broken authority like
    // `http://http://127.0.0.1:9090`; the config field is `host:port`.
    if trimmed.contains("://") {
        return Err(format!(
            "meow.api_addr {addr:?} must be host:port without a scheme"
        ));
    }
    if trimmed.parse::<IpAddr>().is_ok() {
        return Err(format!(
            "meow.api_addr {addr:?} is an address without a port, expected host:port"
        ));
    }
    let (host, port) = trimmed.rsplit_once(':').ok_or_else(|| {
        format!("meow.api_addr {addr:?} is not a host:port pair, expected host:port")
    })?;
    let port: u16 = port
        .parse()
        .map_err(|_| format!("meow.api_addr {addr:?} has no valid port"))?;
    let host = host.trim();
    if host.is_empty() {
        return Err(format!("meow.api_addr {addr:?} has no host"));
    }
    if let Some(ip) = fumox_core::ssrf::parse_ip_literal(host) {
        if ip.is_loopback() {
            return Ok((host.to_string(), port, ControllerScope::Loopback));
        }
        if fumox_core::ssrf::is_public(ip) {
            return Err(format!(
                "meow.api_addr {addr:?} is a public address: the controller carries the \
                 bearer token and can rewrite the proxy kernel's configuration, so it must \
                 stay on loopback or a private network"
            ));
        }
        return Ok((host.to_string(), port, ControllerScope::Private));
    }
    if host.eq_ignore_ascii_case("localhost") {
        return Ok((host.to_string(), port, ControllerScope::Loopback));
    }
    // A name: it is resolved and vetted at startup (see
    // `verify_address`), and until then it counts as network-reachable.
    Ok((host.to_string(), port, ControllerScope::Private))
}

/// The host and port as a URL authority: an IPv6 literal needs its
/// brackets, everything else is written as it is.
fn format_host_port(host: &str, port: u16) -> String {
    if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

/// Whether a delay-endpoint status is a verdict about the proxy.
///
/// meow-rs answers a failed tunnel with 503 (transport failure) or 504
/// (missed deadline). A 400 is ambiguous: it may be a tunnel failure in
/// another spelling or a request the engine refused, so it counts as a
/// verdict only when the message names a fault of the *proxy*.
///
/// Every other status (404, 405, 408, 401, 403, 429, the rest) is a
/// request or configuration error: the engine did not judge the proxy,
/// and charging the proxy for it would retire healthy entries.
fn is_tunnel_verdict(status: u16, message: &str) -> bool {
    match status {
        503 | 504 => true,
        400 => {
            let message = message.to_ascii_lowercase();
            [
                "dial",
                "tunnel",
                "timeout",
                "timed out",
                "refused",
                "unreachable",
                "connection",
                "delay test",
                // The proxy's own credentials: the request was well
                // formed and the engine rejected *the node*. The
                // controller's own token is a different thing and
                // answers 401/403, which never reaches this arm.
                "credential",
            ]
            .iter()
            .any(|marker| message.contains(marker))
        }
        _ => false,
    }
}

/// Upper bound of a controller body the probe buffers: every endpoint
/// answers a small JSON document (or a short error detail), so a bigger
/// body is a malfunction — or an impersonator — and is rejected instead
/// of being read into memory.
const MAX_BODY_BYTES: usize = 64 * 1024;

/// Read a controller body under [`MAX_BODY_BYTES`]: the content length is
/// checked before the first byte, and a chunked body is rejected the
/// moment it passes the cap, so an oversized (or lying) answer is never
/// buffered whole.
async fn read_body_capped(response: reqwest::Response, what: &str) -> Result<String, String> {
    if let Some(len) = response.content_length()
        && len > MAX_BODY_BYTES as u64
    {
        return Err(format!(
            "{what} body of {len} bytes exceeds the {MAX_BODY_BYTES}-byte read cap"
        ));
    }
    let mut response = response;
    let mut body: Vec<u8> = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|e| format!("{what} read failed: {e}"))?
    {
        if body.len().saturating_add(chunk.len()) > MAX_BODY_BYTES {
            return Err(format!(
                "{what} body exceeds the {MAX_BODY_BYTES}-byte read cap"
            ));
        }
        body.extend_from_slice(&chunk);
    }
    String::from_utf8(body).map_err(|e| format!("{what} body is not UTF-8: {e}"))
}

impl MeowClient {
    /// Build the client for the configured controller.
    ///
    /// Fails when the address is not a `host:port` pair, when it points at
    /// public address space, or when it is not loopback and no bearer token
    /// is configured: a controller on a shared network answers to whoever
    /// asks, and it can rewrite the proxy kernel's configuration.
    pub fn new(config: &MeowConfig) -> Result<Self, String> {
        // reqwest is compiled without a crypto provider and panics when a
        // client is built before one is installed.
        fumox_core::tls::install_crypto_provider();
        let (host, port, scope) = vet_api_addr(&config.api_addr)?;
        let api_token = config.api_token.trim().to_string();
        if scope != ControllerScope::Loopback && api_token.is_empty() {
            return Err(format!(
                "meow.api_token must be set: the controller at {} is not loopback, and it \
                 can rewrite the proxy kernel's configuration",
                config.api_addr
            ));
        }
        let timeout = Duration::from_secs(config.timeout_secs.max(1));
        // One client, built exactly once: a builder failure is a startup
        // error to report, not something to paper over with a silently
        // rebuilt fallback.
        let http = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(5))
            .timeout(timeout)
            // The controller is a loopback or private-network service,
            // vetted at startup, so ambient `HTTP(S)_PROXY` variables must
            // not reroute this traffic: the proxy would intercept requests
            // meant for the kernel and receive its bearer token.
            .no_proxy()
            // A redirect would carry the bearer token to whoever the
            // controller points at: the controller answers, it does not
            // redirect.
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|e| format!("cannot build the meow-rs HTTP client: {e}"))?;
        Ok(Self {
            // Client-level timeout as a floor: every call below also sets a
            // per-request timeout (which takes precedence), but a future one
            // that forgets to would otherwise hang forever.
            http,
            base_url: format!("http://{}", format_host_port(&host, port)),
            test_urls: config.test_url.clone(),
            timeout,
            api_token,
            host_is_name: fumox_core::ssrf::parse_ip_literal(&host).is_none(),
            host,
        })
    }

    /// Vet a controller *name* at startup: it must not resolve into public
    /// address space, where the bearer token would leak.
    ///
    /// A name that does not resolve is not a startup failure: the engine
    /// may simply not be up yet, and the probe is built to run without it
    /// (T2 is skipped with a backoff, T1 keeps going). The name is then
    /// treated as network-reachable, so the token rule of
    /// [`MeowClient::new`] applies to it.
    pub async fn verify_address(&self, dns_timeout: Duration) -> Result<(), String> {
        if !self.host_is_name {
            return Ok(());
        }
        let addrs = match fumox_core::ssrf::lookup_with_timeout(&self.host, dns_timeout).await {
            Ok(addrs) => addrs,
            Err(error) => {
                tracing::warn!(
                    host = %self.host,
                    %error,
                    "meow-rs controller host does not resolve (yet): the address is treated \
                     as network-reachable"
                );
                return Ok(());
            }
        };
        for ip in &addrs {
            if fumox_core::ssrf::is_public(*ip) {
                return Err(format!(
                    "meow.api_addr host {} resolves to the public address {ip}: the \
                     controller carries the bearer token, so it must stay on loopback or a \
                     private network",
                    self.host
                ));
            }
        }
        Ok(())
    }

    /// The `Authorization` header of every controller request.
    ///
    /// The controller can rewrite the proxy kernel's configuration, so a
    /// deployment that publishes it needs it to answer only to the
    /// probe. An empty token means the controller is unauthenticated:
    /// the header is left off entirely rather than sent empty, which
    /// some controllers answer differently from a missing one.
    fn auth(&self, request: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        if self.api_token.is_empty() {
            return request;
        }
        request.bearer_auth(&self.api_token)
    }

    /// Random test URL for one delay check: with several configured, the
    /// checks rotate across the list instead of hammering one endpoint
    /// (one URL may be blocked or degraded in a given region).
    fn pick_test_url<'a>(&'a self, rng: &mut impl rand::Rng) -> &'a str {
        self.test_urls
            .choose(rng)
            .expect("meow.test_url is never empty (guaranteed by the config deserializer)")
    }

    /// The test URL of one cycle: one draw from the configured list,
    /// shared by every check of the cycle.
    ///
    /// A per-check draw gives the same proxy opposite verdicts in
    /// consecutive cycles, which reads as "the proxy dies on its own", and
    /// a cycle whose draws all land on an unreachable endpoint fails every
    /// proxy at once. One draw per cycle keeps a cycle internally
    /// consistent and makes the endpoint a property of the cycle, visible
    /// in its log line.
    pub fn cycle_test_url(&self) -> &str {
        self.pick_test_url(&mut rand::rng())
    }

    /// `GET /version`, the version string of the controller.
    ///
    /// Strict on purpose: a body that is not JSON is a malfunction the
    /// operator has to see, not a version. The liveness question ("does
    /// the engine answer at all?") has its own method, [`Self::alive`],
    /// which the runtime uses; this one only serves the strict check of
    /// the tests.
    #[cfg(test)]
    pub async fn ping(&self) -> Result<String, String> {
        let response = self
            .auth(self.http.get(format!("{}/version", self.base_url)))
            .timeout(Duration::from_secs(3))
            .send()
            .await
            .map_err(|e| format!("meow-rs unreachable: {e}"))?;
        if !response.status().is_success() {
            return Err(format!("meow-rs /version returned {}", response.status()));
        }
        let body: serde_json::Value = response
            .json()
            .await
            .map_err(|e| format!("bad /version payload: {e}"))?;
        // The version field is optional: a controller that answers with
        // another JSON shape is alive, it just does not name itself.
        Ok(body
            .get("version")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
            .to_string())
    }

    /// Whether the controller answers at all, judged by the status code
    /// alone.
    ///
    /// The answer to "is the engine down?" must not depend on the shape of
    /// its payload: a controller that changed the format of `/version`
    /// would otherwise look dead, and the batch would be aborted (and
    /// every proxy of it stamped unverified) over a response format.
    pub async fn alive(&self) -> Result<(), String> {
        let response = self
            .auth(self.http.get(format!("{}/version", self.base_url)))
            .timeout(Duration::from_secs(3))
            .send()
            .await
            .map_err(|e| format!("meow-rs unreachable: {e}"))?;
        if !response.status().is_success() {
            return Err(format!("meow-rs /version returned {}", response.status()));
        }
        Ok(())
    }

    /// `GET /memory`, the proxy kernel's own RSS reading.
    ///
    /// Not a JSON document but an endless newline-delimited feed, whose
    /// first frame is a hardcoded zero placeholder. Frames are read until
    /// one reports a non-zero `inuse` (within the same deadline), so the
    /// placeholder never shows as "0 bytes"; a frame without the field is
    /// an error, not a zero reading.
    pub async fn memory(&self) -> Result<MeowMemory, String> {
        // The feed never ends, so the request cannot finish on time: its
        // timeout is a backstop well above the per-frame deadline, and
        // the deadline has to win. Otherwise a stalled feed looks like a
        // transport error instead of a stall.
        let frame_deadline = self.timeout.min(Duration::from_secs(5));
        let mut response = self
            .auth(self.http.get(format!("{}/memory", self.base_url)))
            .timeout(frame_deadline + Duration::from_secs(10))
            .send()
            .await
            .map_err(|e| format!("meow-rs unreachable: {e}"))?;
        if !response.status().is_success() {
            return Err(format!("meow-rs /memory returned {}", response.status()));
        }

        // The feed never ends, so read frames until one is a real sample.
        let mut buf = Vec::new();
        let started = std::time::Instant::now();
        loop {
            // A wall-clock bound of the whole read: a feed that answers
            // on time but never leaves the zero placeholder would
            // otherwise hold the request frame after frame forever.
            if started.elapsed() >= frame_deadline {
                return Err("meow-rs /memory feed stalled before a sample".into());
            }
            let chunk = tokio::time::timeout(frame_deadline, response.chunk())
                .await
                .map_err(|_| "meow-rs /memory feed stalled before a sample".to_string())?
                .map_err(|e| format!("meow-rs /memory read failed: {e}"))?
                .ok_or_else(|| "meow-rs /memory feed closed early".to_string())?;
            buf.extend_from_slice(&chunk);
            // A frame is a small JSON document; a buffer that grows past
            // the cap is not the feed it claims to be.
            if buf.len() > MAX_BODY_BYTES {
                return Err("meow-rs /memory frame exceeds the read cap".into());
            }
            while let Some(pos) = buf.iter().position(|b| *b == b'\n') {
                let line: Vec<u8> = buf.drain(..=pos).collect();
                let text = String::from_utf8_lossy(&line);
                let frame: serde_json::Value = serde_json::from_str(text.trim())
                    .map_err(|e| format!("bad /memory frame: {e}"))?;
                let Some(inuse) = frame.get("inuse").and_then(|v| v.as_u64()) else {
                    return Err("meow-rs /memory frame has no inuse field".into());
                };
                if inuse == 0 {
                    // The zero placeholder, or a kernel that has not
                    // accounted anything yet: keep reading.
                    continue;
                }
                return Ok(MeowMemory {
                    rss_bytes: inuse,
                    os_limit_bytes: frame.get("oslimit").and_then(|v| v.as_u64()).unwrap_or(0),
                });
            }
        }
    }

    /// `PUT /configs`, hot-reload the generated Clash YAML without
    /// restarting the meow-rs process.
    pub async fn reload_config(&self, path: &std::path::Path) -> Result<(), String> {
        let response = self
            .auth(self.http.put(format!("{}/configs", self.base_url)))
            .json(&serde_json::json!({ "path": path.to_string_lossy() }))
            .timeout(Duration::from_secs(10))
            .send()
            .await
            .map_err(|e| format!("meow-rs unreachable: {e}"))?;
        if response.status().is_success() {
            return Ok(());
        }
        let status = response.status();
        // The body is an error detail, not a document to trust: it is
        // read under the same cap as every other controller answer.
        let body = read_body_capped(response, "PUT /configs")
            .await
            .unwrap_or_else(|error| error);
        Err(format!("PUT /configs returned {status}: {body}"))
    }

    /// `GET /proxies/{name}/delay`, run one real tunnel check.
    ///
    /// `test_url` is the endpoint of the current cycle (see
    /// [`cycle_test_url`]): the same one for every check of the cycle.
    ///
    /// The outcome says who the failure belongs to. `ProxyFailed` is a
    /// verdict about the proxy (meow ran the tunnel test and it died) and
    /// is the only outcome that may be charged to the proxy's fail
    /// budget. `ServiceUnavailable` is a fault of the engine or of the
    /// request itself: the batch is aborted without touching any proxy
    /// status.
    ///
    /// Success is strict: 2xx **with** a numeric `delay` field; a 2xx
    /// without one is an engine malfunction, not a pass.
    pub async fn check_delay(&self, name: &str, test_url: &str) -> DelayOutcome {
        let url = format!("{}/proxies/{name}/delay", self.base_url);
        let timeout_ms = self.timeout.as_millis().to_string();
        let response = match self
            .auth(self.http.get(&url))
            .query(&[("url", test_url), ("timeout", timeout_ms.as_str())])
            .timeout(self.timeout + Duration::from_secs(5))
            .send()
            .await
        {
            Ok(response) => response,
            Err(e) => return DelayOutcome::ServiceUnavailable(format!("transport error: {e}")),
        };

        // The body is read after the status and under the shared cap: the
        // endpoint answers a small JSON verdict, so a bigger body is an
        // engine malfunction, not something to buffer.
        let status = response.status();
        let text = match read_body_capped(response, "delay").await {
            Ok(text) => text,
            Err(error) => return DelayOutcome::ServiceUnavailable(error),
        };
        let body: serde_json::Value = match serde_json::from_str(text.trim()) {
            Ok(body) => body,
            // A body that is not JSON still carries a verdict when the
            // status is one (a 503/504 tunnel failure, or a 400 that
            // names a fault of the proxy): the raw text becomes the
            // message and the proxy is charged. Any other status stays
            // an engine fault.
            Err(_) => {
                let message = text.trim();
                if is_tunnel_verdict(status.as_u16(), message) {
                    return DelayOutcome::ProxyFailed(format!("{status}: {message}"));
                }
                return DelayOutcome::ServiceUnavailable(format!("bad delay payload: {text}"));
            }
        };

        if status.is_success() {
            if let Some(delay) = body.get("delay").and_then(|v| v.as_u64()) {
                return DelayOutcome::Ok(delay);
            }
            return DelayOutcome::ServiceUnavailable("delay response has no delay field".into());
        }

        // The delay endpoint reports the tunnel outcome and nothing else:
        // 503 a transport failure, 504 a missed deadline, both a verdict
        // about this proxy. Every other status is the engine refusing the
        // request (an unknown proxy, a wrong token, a rate limit), which
        // says nothing about the proxy.
        let message = body
            .get("message")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown error")
            .to_string();
        if is_tunnel_verdict(status.as_u16(), &message) {
            // The status stays in the text: 503, 504 and a tunnel 400
            // have to stay distinguishable in `probe_results.error`.
            DelayOutcome::ProxyFailed(format!("{status}: {message}"))
        } else {
            DelayOutcome::ServiceUnavailable(format!("{status}: {message}"))
        }
    }

    /// `check_delay`, retrying only `ServiceUnavailable`. A `ProxyFailed`
    /// tunnel fails the same way on a second ask, so it is returned on
    /// first sight and a batch of dead proxies costs one request each.
    pub async fn check_delay_with_retry(
        &self,
        name: &str,
        test_url: &str,
        attempts: u8,
        backoff: Duration,
    ) -> DelayOutcome {
        debug_assert!(attempts >= 1, "attempts must be at least 1");
        let mut last_error = String::new();
        for attempt in 0..attempts {
            match self.check_delay(name, test_url).await {
                ok @ DelayOutcome::Ok(_) => return ok,
                pf @ DelayOutcome::ProxyFailed(_) => return pf,
                DelayOutcome::ServiceUnavailable(err) => {
                    last_error = err;
                    if attempt + 1 < attempts {
                        tokio::time::sleep(backoff).await;
                    }
                }
            }
        }
        DelayOutcome::ServiceUnavailable(last_error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::extract::{Path, Query};
    use axum::routing::{get, put};
    use axum::{Json, Router};
    use std::collections::{HashMap, HashSet};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// Bind and serve a mock app on an ephemeral loopback port; the
    /// address string is the `meow.api_addr` of a client config.
    async fn spawn_mock(app: Router) -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        addr
    }

    /// Stand up a mock meow-rs REST API on an ephemeral port. Captures
    /// both query parameters (`url` and `timeout`) of every delay request
    /// for rotation and timeout asserts.
    async fn mock_api(
        reloads: Arc<AtomicUsize>,
    ) -> (
        String,
        fumox_core::config::MeowConfig,
        Arc<std::sync::Mutex<HashMap<String, String>>>,
    ) {
        let seen_params: Arc<std::sync::Mutex<HashMap<String, String>>> = Arc::default();
        let capture = seen_params.clone();
        let app = Router::new()
            .route(
                "/version",
                get(|| async { Json(serde_json::json!({"version":"mock-0.20"})) }),
            )
            .route(
                "/configs",
                put(move || {
                    let reloads = reloads.clone();
                    async move {
                        reloads.fetch_add(1, Ordering::SeqCst);
                        Json(serde_json::json!({}))
                    }
                }),
            )
            // Mirrors the real /memory feed, zero placeholder first.
            .route(
                "/memory",
                get(|| async {
                    let mut body = String::from("{\"inuse\":0,\"oslimit\":0}\n");
                    for _ in 0..3 {
                        body.push_str("{\"inuse\":25780224,\"oslimit\":2147483648}\n");
                    }
                    (
                        [(axum::http::header::CONTENT_TYPE, "application/json")],
                        body,
                    )
                }),
            )
            .route(
                "/proxies/{name}/delay",
                get(
                    move |Path(name): Path<String>,
                          Query(query): Query<HashMap<String, String>>| {
                        let capture = capture.clone();
                        async move {
                            // Both parameters are part of the contract
                            // with the engine, not only the test URL.
                            for (key, value) in query {
                                capture.lock().unwrap().insert(key, value);
                            }
                            match name.as_str() {
                                "fumox-1" => (
                                    axum::http::StatusCode::OK,
                                    Json(serde_json::json!({"delay": 42})),
                                ),
                                "fumox-2" => (
                                    axum::http::StatusCode::BAD_REQUEST,
                                    Json(serde_json::json!({"message":"dial tcp: i/o timeout"})),
                                ),
                                _ => (
                                    axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                                    Json(serde_json::json!({"message":"proxy not found"})),
                                ),
                            }
                        }
                    },
                ),
            );

        let addr = spawn_mock(app).await;
        let config = MeowConfig {
            api_addr: addr.clone(),
            // The delay request must carry this timeout in milliseconds
            // (see `ping_reload_and_delay_outcomes`).
            timeout_secs: 5,
            ..Default::default()
        };
        (addr, config, seen_params)
    }

    #[tokio::test]
    async fn ping_reload_and_delay_outcomes() {
        let reloads = Arc::new(AtomicUsize::new(0));
        let (_addr, config, seen) = mock_api(reloads.clone()).await;
        let client = MeowClient::new(&config).unwrap();

        assert_eq!(client.ping().await.unwrap(), "mock-0.20");

        client.reload_config(&config.config_path).await.unwrap();
        assert_eq!(reloads.load(Ordering::SeqCst), 1);

        match client
            .check_delay("fumox-1", "http://cp.cloudflare.com")
            .await
        {
            DelayOutcome::Ok(delay) => assert_eq!(delay, 42),
            other => panic!("expected Ok, got {other:?}"),
        }
        match client
            .check_delay("fumox-2", "http://cp.cloudflare.com")
            .await
        {
            DelayOutcome::ProxyFailed(msg) => assert!(msg.contains("timeout")),
            other => panic!("expected ProxyFailed, got {other:?}"),
        }
        match client
            .check_delay("fumox-99", "http://cp.cloudflare.com")
            .await
        {
            DelayOutcome::ServiceUnavailable(_) => {}
            other => panic!("expected ServiceUnavailable, got {other:?}"),
        }

        // The delay request carries the configured timeout in
        // milliseconds: the engine applies it to its own tunnel test.
        let params = seen.lock().unwrap().clone();
        let expected_ms = (config.timeout_secs * 1000).to_string();
        assert_eq!(
            params.get("timeout"),
            Some(&expected_ms),
            "the delay request must carry the configured timeout"
        );
        assert_eq!(
            params.get("url").map(String::as_str),
            Some("http://cp.cloudflare.com"),
        );
    }

    /// The `Authorization` header of a request, as the controller sees it.
    fn auth_header(headers: &axum::http::HeaderMap) -> Option<String> {
        headers
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .map(str::to_string)
    }

    /// The controller can reconfigure the proxy kernel, so a deployment
    /// that publishes it needs it to answer only to the probe. Every
    /// request therefore carries the configured bearer token, and a
    /// client without a token sends no header at all.
    #[tokio::test]
    async fn the_bearer_token_is_sent_on_every_request() {
        let seen: Arc<std::sync::Mutex<Vec<Option<String>>>> = Arc::default();

        let capture = seen.clone();
        let version_capture = capture.clone();
        let configs_capture = capture.clone();
        let app = Router::new()
            .route(
                "/version",
                get(move |headers: axum::http::HeaderMap| {
                    let capture = version_capture.clone();
                    async move {
                        capture.lock().unwrap().push(auth_header(&headers));
                        Json(serde_json::json!({"version": "mock"}))
                    }
                }),
            )
            .route(
                "/configs",
                put(move |headers: axum::http::HeaderMap| {
                    let capture = configs_capture.clone();
                    async move {
                        capture.lock().unwrap().push(auth_header(&headers));
                        Json(serde_json::json!({}))
                    }
                }),
            )
            .route(
                "/proxies/{name}/delay",
                get(move |_name: Path<String>, headers: axum::http::HeaderMap| {
                    let capture = capture.clone();
                    async move {
                        capture.lock().unwrap().push(auth_header(&headers));
                        (
                            axum::http::StatusCode::OK,
                            Json(serde_json::json!({"delay": 42})),
                        )
                    }
                }),
            );

        let addr = spawn_mock(app).await;
        let config = MeowConfig {
            api_addr: addr,
            api_token: "s3cr3t".to_string(),
            ..Default::default()
        };

        let client = MeowClient::new(&config).unwrap();
        client.ping().await.unwrap();
        client.reload_config(&config.config_path).await.unwrap();
        assert!(matches!(
            client
                .check_delay("fumox-1", "https://www.gstatic.com/generate_204")
                .await,
            DelayOutcome::Ok(42)
        ));

        let headers = seen.lock().unwrap().clone();
        assert_eq!(headers.len(), 3, "every call must reach the controller");
        for header in &headers {
            assert_eq!(
                header.as_deref(),
                Some("Bearer s3cr3t"),
                "the controller must see the bearer token"
            );
        }

        // Without a token the header is absent, not empty: a controller
        // that treats "no header" and "empty header" differently has to
        // see the former.
        let plain = MeowClient::new(&MeowConfig {
            api_token: String::new(),
            ..config.clone()
        })
        .unwrap();
        plain.ping().await.unwrap();
        let headers = seen.lock().unwrap().clone();
        assert_eq!(
            headers.last().and_then(|header| header.as_deref()),
            None,
            "an unauthenticated client must not send an Authorization header"
        );
    }

    #[tokio::test]
    async fn unreachable_api_reports_service_unavailable() {
        let config = MeowConfig {
            // Nothing listens here.
            api_addr: "127.0.0.1:1".into(),
            // Keep the timeouts short: the test only exercises the
            // transport-failure path.
            timeout_secs: 2,
            ..Default::default()
        };
        let client = MeowClient::new(&config).unwrap();
        assert!(client.ping().await.is_err());
        assert!(client.reload_config(&config.config_path).await.is_err());
        assert!(matches!(
            client
                .check_delay("fumox-1", "http://cp.cloudflare.com")
                .await,
            DelayOutcome::ServiceUnavailable(_)
        ));
    }

    /// The URL of the cycle is the URL every check of the cycle uses: the
    /// probe draws it once, the checks do not pick their own.
    #[tokio::test]
    async fn delay_requests_use_the_url_of_the_cycle() {
        let reloads = Arc::new(AtomicUsize::new(0));
        let (_addr, mut config, seen) = mock_api(reloads.clone()).await;
        config.test_url = vec!["http://a.example/204".into(), "http://b.example/204".into()];
        let client = MeowClient::new(&config).unwrap();

        let cycle_url = client.cycle_test_url().to_string();
        assert!(
            cycle_url == "http://a.example/204" || cycle_url == "http://b.example/204",
            "{cycle_url}"
        );
        assert!(matches!(
            client.check_delay("fumox-1", &cycle_url).await,
            DelayOutcome::Ok(_)
        ));
        let params = seen.lock().unwrap().clone();
        assert_eq!(params.get("url"), Some(&cycle_url));
    }

    #[test]
    fn pick_test_url_covers_the_whole_list() {
        let config = MeowConfig {
            test_url: vec!["a".into(), "b".into(), "c".into()],
            ..Default::default()
        };
        let client = MeowClient::new(&config).unwrap();
        // Seeded: the assertion is deterministic for this fixed sequence.
        let mut rng = {
            use rand::SeedableRng;
            rand::rngs::StdRng::seed_from_u64(7)
        };
        let picked: HashSet<&str> = (0..100).map(|_| client.pick_test_url(&mut rng)).collect();
        assert_eq!(picked, HashSet::from(["a", "b", "c"]));
    }

    /// A flaky proxy fails the first request and succeeds the second ,
    /// `check_delay_with_retry` absorbs the transient blip and returns
    /// `Ok`. Without the retry the caller would see `ServiceUnavailable`
    /// and abort the rest of the batch on the first failure.
    ///
    /// The clock is paused: the backoff between the attempts is virtual,
    /// auto-advanced the moment the runtime runs out of other work.
    #[tokio::test(start_paused = true)]
    async fn check_delay_with_retry_recovers_from_transient_5xx() {
        let attempts: Arc<AtomicUsize> = Arc::new(AtomicUsize::new(0));
        let attempts_inner = attempts.clone();
        let app = Router::new()
            .route(
                "/version",
                get(|| async { Json(serde_json::json!({"version":"mock"})) }),
            )
            .route("/configs", put(|| async { Json(serde_json::json!({})) }))
            .route(
                "/proxies/{name}/delay",
                get(move |Path(_name): Path<String>| {
                    let attempts = attempts_inner.clone();
                    async move {
                        let n = attempts.fetch_add(1, Ordering::SeqCst);
                        if n == 0 {
                            (
                                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                                Json(serde_json::json!({"message":"blip"})),
                            )
                        } else {
                            (
                                axum::http::StatusCode::OK,
                                Json(serde_json::json!({"delay": 17})),
                            )
                        }
                    }
                }),
            );
        let addr = spawn_mock(app).await;
        let config = MeowConfig {
            api_addr: addr,
            ..Default::default()
        };
        let client = MeowClient::new(&config).unwrap();
        // Two attempts, 50ms between, first fails, second succeeds.
        match client
            .check_delay_with_retry(
                "fumox-flaky",
                "http://cp.cloudflare.com",
                2,
                Duration::from_millis(50),
            )
            .await
        {
            DelayOutcome::Ok(delay) => assert_eq!(delay, 17),
            other => panic!("expected Ok after retry, got {other:?}"),
        }
        assert_eq!(attempts.load(Ordering::SeqCst), 2);
    }

    /// `ProxyFailed` (4xx, the engine tried and the tunnel died) is not
    /// retried: the engine's answer is final, asking again would just
    /// pile more load on a dying tunnel.
    #[tokio::test]
    async fn check_delay_with_retry_does_not_retry_proxy_failed() {
        let attempts: Arc<AtomicUsize> = Arc::new(AtomicUsize::new(0));
        let attempts_inner = attempts.clone();
        let app = Router::new()
            .route(
                "/version",
                get(|| async { Json(serde_json::json!({"version":"mock"})) }),
            )
            .route("/configs", put(|| async { Json(serde_json::json!({})) }))
            .route(
                "/proxies/{name}/delay",
                get(move |Path(_name): Path<String>| {
                    let attempts = attempts_inner.clone();
                    async move {
                        attempts.fetch_add(1, Ordering::SeqCst);
                        (
                            axum::http::StatusCode::BAD_REQUEST,
                            Json(serde_json::json!({"message":"dial tcp: timeout"})),
                        )
                    }
                }),
            );
        let addr = spawn_mock(app).await;
        let config = MeowConfig {
            api_addr: addr,
            ..Default::default()
        };
        let client = MeowClient::new(&config).unwrap();
        match client
            .check_delay_with_retry(
                "fumox-dead",
                "http://cp.cloudflare.com",
                3,
                Duration::from_millis(10),
            )
            .await
        {
            DelayOutcome::ProxyFailed(msg) => assert!(msg.contains("timeout"), "{msg}"),
            other => panic!("expected ProxyFailed, got {other:?}"),
        }
        assert_eq!(attempts.load(Ordering::SeqCst), 1);
    }

    /// meow-rs answers /memory with a live feed whose first frame is a
    /// hardcoded zero placeholder. Reporting that as "0 bytes" would show a
    /// dead-looking kernel on the admin card, so the first frame is dropped.
    #[tokio::test]
    async fn memory_skips_the_zero_placeholder_frame() {
        let (_addr, config, _) = mock_api(Arc::default()).await;
        let client = MeowClient::new(&config).unwrap();

        let mem = client.memory().await.expect("memory sample");
        assert_eq!(mem.rss_bytes, 25_780_224);
        assert_eq!(mem.os_limit_bytes, 2_147_483_648);

        // `os_limit_bytes` is passed through verbatim: meow-rs resolves it
        // from the cgroup, and a container without one reports 0, which the
        // panel renders as "no percentage" rather than dividing by it.
    }

    /// meow-rs reports a failed tunnel as 503 or 504. Both are the one
    /// proxy's verdict, so they charge it and must not be retried.
    #[tokio::test]
    async fn meow_probe_statuses_charge_the_proxy_without_retrying() {
        for (status, label) in [
            (axum::http::StatusCode::SERVICE_UNAVAILABLE, "503"),
            (axum::http::StatusCode::GATEWAY_TIMEOUT, "504"),
        ] {
            let requests: Arc<AtomicUsize> = Arc::new(AtomicUsize::new(0));
            let counter = requests.clone();
            let app = Router::new()
                .route(
                    "/version",
                    get(|| async { Json(serde_json::json!({"version":"mock"})) }),
                )
                .route("/configs", put(|| async { Json(serde_json::json!({})) }))
                .route(
                    "/proxies/{name}/delay",
                    get(move |Path(_name): Path<String>| {
                        let counter = counter.clone();
                        async move {
                            counter.fetch_add(1, Ordering::SeqCst);
                            (
                                status,
                                Json(serde_json::json!({
                                    "message": "An error occurred in the delay test"
                                })),
                            )
                        }
                    }),
                );
            let addr = spawn_mock(app).await;
            let config = MeowConfig {
                api_addr: addr,
                ..Default::default()
            };
            let client = MeowClient::new(&config).unwrap();

            match client
                .check_delay_with_retry(
                    "fumox-dead",
                    "http://cp.cloudflare.com",
                    3,
                    Duration::from_millis(10),
                )
                .await
            {
                DelayOutcome::ProxyFailed(msg) => {
                    // The status code stays in the text: 503 and 504
                    // have to remain distinguishable in
                    // `probe_results.error`.
                    assert!(
                        msg.starts_with(label),
                        "{label} must lead the message, got {msg}"
                    );
                    assert!(
                        msg.contains("An error occurred in the delay test"),
                        "{label}: {msg}"
                    );
                }
                other => panic!("{label} must be ProxyFailed, got {other:?}"),
            }
            assert_eq!(
                requests.load(Ordering::SeqCst),
                1,
                "{label} must not be retried"
            );
        }
    }

    /// A tunnel verdict spelled in plain text (a 503 whose body is not
    /// JSON) is still a verdict about the proxy: the raw text becomes the
    /// message and the proxy is charged. Reading the body before the
    /// status used to file it as an engine outage (`ServiceUnavailable`)
    /// and abort the whole batch over one dead tunnel.
    #[tokio::test]
    async fn a_non_json_tunnel_verdict_still_charges_the_proxy() {
        for (status, label) in [
            (axum::http::StatusCode::SERVICE_UNAVAILABLE, "503"),
            (axum::http::StatusCode::GATEWAY_TIMEOUT, "504"),
        ] {
            let app = Router::new().route(
                "/proxies/{name}/delay",
                get(move || async move { (status, "An error occurred in the delay test") }),
            );
            let addr = spawn_mock(app).await;
            let client = MeowClient::new(&meow_config(&addr, "")).unwrap();
            match client
                .check_delay("fumox-dead", "http://cp.cloudflare.com")
                .await
            {
                DelayOutcome::ProxyFailed(msg) => {
                    assert!(msg.starts_with(label), "{label}: {msg}");
                    assert!(msg.contains("delay test"), "{label}: {msg}");
                }
                other => panic!("{label} with a plain-text body must be a verdict, got {other:?}"),
            }
        }
    }

    /// A status meow never uses for a probe result is engine trouble, and
    /// must still reach the retry/abort path.
    #[tokio::test]
    async fn unexpected_server_error_stays_service_unavailable() {
        let app = Router::new()
            .route(
                "/version",
                get(|| async { Json(serde_json::json!({"version":"mock"})) }),
            )
            .route("/configs", put(|| async { Json(serde_json::json!({})) }))
            .route(
                "/proxies/{name}/delay",
                get(|| async {
                    (
                        axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                        Json(serde_json::json!({"message": "boom"})),
                    )
                }),
            );
        let addr = spawn_mock(app).await;
        let config = MeowConfig {
            api_addr: addr,
            ..Default::default()
        };
        let client = MeowClient::new(&config).unwrap();
        match client
            .check_delay("fumox-x", "http://cp.cloudflare.com")
            .await
        {
            DelayOutcome::ServiceUnavailable(err) => assert!(err.contains("boom"), "{err}"),
            other => panic!("500 must stay ServiceUnavailable, got {other:?}"),
        }
    }

    /// A config with the given controller address and token. The timeout
    /// stays pinned: the /memory tests derive their deadlines from it.
    fn meow_config(api_addr: &str, api_token: &str) -> MeowConfig {
        MeowConfig {
            api_addr: api_addr.to_string(),
            api_token: api_token.to_string(),
            timeout_secs: 5,
            ..Default::default()
        }
    }

    /// The error of a refused client, or a panic.
    fn client_error(config: &MeowConfig) -> String {
        match MeowClient::new(config) {
            Ok(_) => panic!("the client must refuse {:?}", config.api_addr),
            Err(error) => error,
        }
    }

    /// The controller carries the bearer token and can rewrite the proxy
    /// kernel's configuration, so a public address is refused outright.
    #[tokio::test]
    async fn a_public_controller_address_is_refused() {
        let error = client_error(&meow_config("8.8.8.8:9090", "s3cr3t"));
        assert!(error.contains("public address"), "{error}");
    }

    /// A controller on a network somebody else reaches needs the token:
    /// an unauthenticated one answers to whoever asks.
    #[tokio::test]
    async fn a_network_controller_without_a_token_is_refused() {
        let error = client_error(&meow_config("10.0.0.5:9090", ""));
        assert!(error.contains("meow.api_token"), "{error}");
        // The same address with a token is fine.
        assert!(MeowClient::new(&meow_config("10.0.0.5:9090", "s3cr3t")).is_ok());
    }

    /// A loopback controller is reachable by nobody else, so it may run
    /// without a token: this is the shipped configuration.
    #[tokio::test]
    async fn a_loopback_controller_may_run_without_a_token() {
        for addr in ["127.0.0.1:9090", "[::1]:9090", "localhost:9090"] {
            assert!(
                MeowClient::new(&meow_config(addr, "")).is_ok(),
                "{addr} must be accepted"
            );
        }
    }

    /// An address that is not a `host:port` pair cannot be dialled at
    /// all, and the probe says so instead of failing later.
    #[tokio::test]
    async fn a_malformed_controller_address_is_refused() {
        for addr in [
            "9090",
            "127.0.0.1",
            "127.0.0.1:not-a-port",
            ":9090",
            "127.0.0.1:99999",
        ] {
            let error = client_error(&meow_config(addr, "s3cr3t"));
            assert!(error.contains("meow.api_addr"), "{addr}: {error}");
        }
    }

    /// The client prepends its own scheme when it dials the controller,
    /// so a configured `http://…` value would produce a broken authority;
    /// the config field is `host:port` and nothing else.
    #[tokio::test]
    async fn an_api_addr_with_a_scheme_is_refused() {
        let error = client_error(&meow_config("http://127.0.0.1:9090", "s3cr3t"));
        assert!(error.contains("host:port without a scheme"), "{error}");
        // The same address without the scheme is accepted.
        assert!(MeowClient::new(&meow_config("127.0.0.1:9090", "s3cr3t")).is_ok());
    }

    /// A controller body is an error detail, not a document to buffer: an
    /// oversized `PUT /configs` answer is rejected at the cap instead of
    /// being read into memory whole.
    #[tokio::test]
    async fn an_oversized_configs_body_is_rejected() {
        let app = Router::new().route(
            "/configs",
            put(|| async {
                (
                    axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                    "x".repeat(200_000),
                )
            }),
        );
        let addr = spawn_mock(app).await;
        let client = MeowClient::new(&meow_config(&addr, "")).unwrap();
        let error = client
            .reload_config(std::path::Path::new("/tmp/fumox-meow.yaml"))
            .await
            .expect_err("an oversized body must be rejected");
        assert!(error.contains("exceeds the"), "{error}");
    }

    /// Only a verdict about the proxy may be charged to it: 503 and 504
    /// are the engine's tunnel verdicts, a 400 counts when it names a
    /// fault of the proxy, and every other status is a fault of the
    /// engine or of the request.
    #[tokio::test]
    async fn only_a_tunnel_verdict_is_charged_to_the_proxy() {
        for (status, message, verdict) in [
            (503u16, "tunnel failed", true),
            (504, "gateway timeout", true),
            (400, "dial tcp: i/o timeout", true),
            (400, "invalid credential", true),
            (400, "bad request", false),
            (404, "proxy not found", false),
            (405, "method not allowed", false),
            (408, "request timeout", false),
            (401, "unauthorized", false),
            (403, "forbidden", false),
            (429, "too many requests", false),
            (500, "internal error", false),
            (502, "bad gateway", false),
        ] {
            let client = delay_client(status, message).await;
            match client
                .check_delay("fumox-1", "http://cp.cloudflare.com")
                .await
            {
                DelayOutcome::ProxyFailed(text) => {
                    assert!(verdict, "{status} {message} must not be a verdict");
                    assert!(
                        text.starts_with(&status.to_string()),
                        "{status} {message}: the status must stay readable, got {text}"
                    );
                }
                DelayOutcome::ServiceUnavailable(text) => {
                    assert!(!verdict, "{status} {message} must be a verdict");
                    assert!(
                        text.starts_with(&status.to_string()),
                        "{status} {message}: the status must stay readable, got {text}"
                    );
                }
                other => panic!("{status} {message}: unexpected {other:?}"),
            }
        }
    }

    /// A 2xx answer without a numeric delay is an engine malfunction,
    /// not a pass: the tunnel was never measured.
    #[tokio::test]
    async fn a_delay_response_without_a_numeric_delay_is_not_a_pass() {
        for body in ["{}", r#"{"delay":"42"}"#, r#"{"delay":null}"#] {
            let client = body_client(body).await;
            match client
                .check_delay("fumox-1", "http://cp.cloudflare.com")
                .await
            {
                DelayOutcome::ServiceUnavailable(_) => {}
                other => panic!("{body} must not be a pass, got {other:?}"),
            }
        }
        let client = body_client(r#"{"delay":42}"#).await;
        match client
            .check_delay("fumox-1", "http://cp.cloudflare.com")
            .await
        {
            DelayOutcome::Ok(delay) => assert_eq!(delay, 42),
            other => panic!("a numeric delay must be a pass, got {other:?}"),
        }
    }

    /// A broken `/version` is reported as broken: a 500 and a body that
    /// is not JSON both make the strict version check fail.
    #[tokio::test]
    async fn a_broken_version_endpoint_is_reported_as_broken() {
        let client = version_client(axum::http::StatusCode::INTERNAL_SERVER_ERROR, "{}").await;
        assert!(client.ping().await.is_err(), "a 500 is not a version");

        let client = version_client(axum::http::StatusCode::OK, "not json").await;
        let error = client.ping().await.unwrap_err();
        assert!(
            error.contains("bad /version payload"),
            "a body that is not JSON must name itself: {error}"
        );
    }

    /// The liveness check judges the status code alone: a controller
    /// that changed the format of `/version` is alive, not dead.
    #[tokio::test]
    async fn a_non_json_version_answer_is_still_alive() {
        let client = version_client(axum::http::StatusCode::OK, "not json").await;
        assert!(
            client.alive().await.is_ok(),
            "a changed payload format must not look like an outage"
        );
        let client = version_client(axum::http::StatusCode::INTERNAL_SERVER_ERROR, "{}").await;
        assert!(client.alive().await.is_err(), "a 500 is not alive");
    }

    /// A client whose delay endpoint always answers with `status` and
    /// `message`.
    async fn delay_client(status: u16, message: &str) -> MeowClient {
        let message = message.to_string();
        let app = Router::new()
            .route(
                "/version",
                get(|| async { Json(serde_json::json!({"version":"mock"})) }),
            )
            .route("/configs", put(|| async { Json(serde_json::json!({})) }))
            .route(
                "/proxies/{name}/delay",
                get(move || {
                    let message = message.clone();
                    async move {
                        (
                            axum::http::StatusCode::from_u16(status).unwrap(),
                            Json(serde_json::json!({ "message": message })),
                        )
                    }
                }),
            );
        let addr = spawn_mock(app).await;
        MeowClient::new(&meow_config(&addr, "")).unwrap()
    }

    /// A client whose delay endpoint answers 200 with a fixed body.
    async fn body_client(body: &'static str) -> MeowClient {
        let app = Router::new()
            .route(
                "/version",
                get(|| async { Json(serde_json::json!({"version":"mock"})) }),
            )
            .route("/configs", put(|| async { Json(serde_json::json!({})) }))
            .route(
                "/proxies/{name}/delay",
                get(move || async move { (axum::http::StatusCode::OK, body) }),
            );
        let addr = spawn_mock(app).await;
        MeowClient::new(&meow_config(&addr, "")).unwrap()
    }

    /// A client whose `/version` answers with a fixed status and body.
    async fn version_client(status: axum::http::StatusCode, body: &'static str) -> MeowClient {
        let app = Router::new().route("/version", get(move || async move { (status, body) }));
        let addr = spawn_mock(app).await;
        MeowClient::new(&meow_config(&addr, "")).unwrap()
    }

    /// A raw `/memory` feed: the given chunks are written with chunked
    /// encoding (the real feed never ends). `terminate` ends the body
    /// the way a well-behaved server does; without it the feed simply
    /// stops, which is the stall the probe has to notice.
    async fn memory_feed_server(chunks: Vec<Vec<u8>>, terminate: bool) -> String {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut head = Vec::new();
            let mut buf = [0u8; 1024];
            loop {
                let n = socket.read(&mut buf).await.unwrap_or(0);
                if n == 0 {
                    break;
                }
                head.extend_from_slice(&buf[..n]);
                if head.windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
            }
            socket
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\
                      Transfer-Encoding: chunked\r\n\r\n",
                )
                .await
                .unwrap();
            for chunk in chunks {
                socket
                    .write_all(format!("{:x}\r\n", chunk.len()).as_bytes())
                    .await
                    .unwrap();
                socket.write_all(&chunk).await.unwrap();
                socket.write_all(b"\r\n").await.unwrap();
                socket.flush().await.unwrap();
            }
            if terminate {
                socket.write_all(b"0\r\n\r\n").await.unwrap();
                let _ = socket.shutdown().await;
                return;
            }
            // The feed never ends: hold the connection open.
            let _ = tokio::time::timeout(std::time::Duration::from_secs(30), socket.read(&mut buf))
                .await;
        });
        addr
    }

    /// A client on a raw `/memory` feed.
    fn memory_client(addr: &str) -> MeowClient {
        let mut config = meow_config(addr, "");
        config.config_path = std::env::temp_dir().join("fumox-meow-memory.yaml");
        MeowClient::new(&config).unwrap()
    }

    /// The feed that stops after the placeholder leaves the probe
    /// waiting for a sample that never comes; a feed that closes leaves
    /// it with nothing to read. Both are errors, neither is a hang.
    #[tokio::test]
    async fn a_broken_memory_feed_is_reported_as_broken() {
        let placeholder = b"{\"inuse\":0,\"oslimit\":0}\n".to_vec();

        let stalled = memory_feed_server(vec![placeholder.clone()], false).await;
        let client = memory_client(&stalled);
        let error = tokio::time::timeout(std::time::Duration::from_secs(8), client.memory())
            .await
            .expect("the feed must not hang forever")
            .expect_err("a stalled feed is an error");
        assert!(error.contains("stalled"), "{error}");

        let closed = memory_feed_server(vec![placeholder], true).await;
        let client = memory_client(&closed);
        let error = tokio::time::timeout(std::time::Duration::from_secs(8), client.memory())
            .await
            .expect("the feed must not hang forever")
            .expect_err("a closed feed is an error");
        assert!(error.contains("closed early"), "{error}");
    }

    /// The sample may arrive in pieces: a frame split across two writes
    /// is still one frame, and the probe waits for the rest of it.
    #[tokio::test]
    async fn a_memory_frame_split_across_two_writes_is_read_as_one() {
        let placeholder = b"{\"inuse\":0,\"oslimit\":0}\n".to_vec();
        let head = b"{\"inuse\":25780224,\"oslim".to_vec();
        let tail = b"it\":2147483648}\n".to_vec();
        let addr = memory_feed_server(vec![placeholder, head, tail], true).await;
        let client = memory_client(&addr);

        let mem = client.memory().await.expect("memory sample");
        assert_eq!(mem.rss_bytes, 25_780_224);
        assert_eq!(mem.os_limit_bytes, 2_147_483_648);
    }

    /// A frame without the `inuse` field is a feed the probe does not
    /// understand: an error, never a reading of "0 bytes".
    #[tokio::test]
    async fn a_memory_frame_without_inuse_is_an_error() {
        let addr = memory_feed_server(vec![b"{\"oslimit\":0}\n".to_vec()], true).await;
        let client = memory_client(&addr);
        let error = client.memory().await.expect_err("no inuse field");
        assert!(error.contains("no inuse field"), "{error}");
    }

    /// A frame bigger than the read cap is not the feed it claims to be:
    /// the reading stops at the cap instead of buffering the body whole.
    #[tokio::test]
    async fn an_oversized_memory_frame_is_rejected() {
        let oversized = vec![b'x'; 70_000];
        let addr = memory_feed_server(vec![oversized], true).await;
        let client = memory_client(&addr);
        let error = client.memory().await.expect_err("an oversized frame");
        assert!(error.contains("exceeds the read cap"), "{error}");
    }
}
