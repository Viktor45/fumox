//! Download-speed measurement and Cloudflare trace fetch through a pinned
//! meow-rs listener.
//!
//! Both fetches ride the same path a client subscription would: the probe
//! opens an HTTP session against the listener the batch config rendered
//! for the proxy under test (`listeners[].proxy` forces every flow of it
//! through that proxy's tunnel), so the numbers describe the tunnel, not
//! the host. Nothing is written to disk: the speed payload is counted
//! chunk by chunk and dropped.
//!
//! The listener address is derived from `[meow].api_addr` — the controller
//! host the client already vets every cycle (a public controller address
//! is refused outright) — with the lane port from
//! `[network].speed_listener_port_base`, so the fetch target inherits the
//! vetting the controller went through.

use std::time::{Duration, Instant};

use futures_util::StreamExt;

/// The wall-clock budget of one trace fetch. The answer is a few hundred
/// bytes; the budget is generous because a slow tunnel must still be able
/// to finish it — a trace that times out is journaled as a failed attempt
/// and the row keeps its previous facts.
const TRACE_BUDGET: Duration = Duration::from_secs(15);

/// Extra time the download gets on top of the streaming ceiling, for the
/// connect and the TLS handshake: the ceiling measures the payload
/// window, not the setup.
const CONNECT_GRACE: Duration = Duration::from_secs(10);

/// The egress facts parsed from a trace answer, in the shape the repo
/// stamps onto the proxy row (see `repo::proxies::TraceFacts`).
pub type TraceFacts = fumox_core::repo::proxies::TraceFacts;

/// The result of one speed measurement or trace fetch; the error text is
/// what the journal records (`sanitize`-friendly: no credentials, no raw
/// URLs with tokens).
pub struct Attempt {
    pub ok: bool,
    /// The measured throughput (Mbit/s) or the parsed trace facts.
    pub value: AttemptValue,
    /// The failure reason when `ok` is false.
    pub error: Option<String>,
}

pub enum AttemptValue {
    Speed(f64),
    Trace(TraceFacts),
}

/// The address of the pinned listener for one lane: the controller host
/// (already vetted) with the lane port. `None` when `api_addr` carries no
/// parsable host part — a config the client would have refused already.
pub fn listener_addr(api_addr: &str, port: u16) -> Option<String> {
    let host = api_addr.rsplit_once(':')?.0;
    if host.is_empty() {
        return None;
    }
    // A bare IPv6 controller address ("::1") needs brackets in a URL; a
    // bracketed one ("[::1]:9090") already has them
    let host = if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]")
    } else {
        host.to_string()
    };
    Some(format!("{host}:{port}"))
}

/// Expand the speed-URL template: `{bytes}` to the payload size, `{rand}`
/// to a fresh random number per call (the anti-cache `measId` the
/// endpoint expects; validated at config load).
fn expand_speed_url(template: &str, bytes: u64) -> String {
    template
        .replace("{bytes}", &bytes.to_string())
        .replace("{rand}", &rand::random::<u32>().to_string())
}

/// Fetch the trace endpoint through the pinned listener and keep the
/// configured fields. The answer is plain text, one `key=value` per line;
/// unknown lines are ignored, an absent field stays `None` (the row keeps
/// what it had — a partial answer must not wipe facts a previous fetch
/// established).
pub async fn fetch_trace(trace_url: &str, fields: &[String], proxy_addr: &str) -> Attempt {
    match fetch_trace_inner(trace_url, fields, proxy_addr).await {
        Ok(facts) => Attempt {
            ok: true,
            value: AttemptValue::Trace(facts),
            error: None,
        },
        Err(error) => Attempt {
            ok: false,
            value: AttemptValue::Trace(TraceFacts::default()),
            error: Some(error),
        },
    }
}

async fn fetch_trace_inner(
    trace_url: &str,
    fields: &[String],
    proxy_addr: &str,
) -> Result<TraceFacts, String> {
    let client = build_client(TRACE_BUDGET, proxy_addr)?;
    let response = client
        .get(trace_url)
        .send()
        .await
        .and_then(|response| response.error_for_status())
        .map_err(|error| format!("trace request failed: {error}"))?;
    let body = tokio::time::timeout(TRACE_BUDGET, response.text())
        .await
        .map_err(|_| "trace answer timed out".to_string())?
        .map_err(|error| format!("trace answer read failed: {error}"))?;

    let mut facts = TraceFacts::default();
    let mut extra = serde_json::Map::new();
    for line in body.lines() {
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let (key, value) = (key.trim(), value.trim());
        if value.is_empty() {
            continue;
        }
        match key {
            "ip" => facts.ip = Some(value.to_string()),
            "colo" => facts.colo = Some(value.to_string()),
            "loc" => facts.loc = Some(value.to_string()),
            "warp" => facts.warp = Some(value.to_string()),
            _ if fields.iter().any(|f| f == key) => {
                extra.insert(
                    key.to_string(),
                    serde_json::Value::String(value.to_string()),
                );
            }
            _ => {}
        }
    }
    // The egress address is what the server-side GeoIP backfill consumes:
    // a value that is not an address literal would burn a backfill
    // attempt on every cycle, so it is dropped here instead
    if let Some(ip) = &facts.ip
        && ip.parse::<std::net::IpAddr>().is_err()
    {
        facts.ip = None;
    }
    if !extra.is_empty() {
        facts.extra = Some(serde_json::to_string(&extra).unwrap_or_default());
    }
    Ok(facts)
}

/// Download the synthetic payload through the pinned listener and return
/// the throughput in Mbit/s. The measurement is hybrid (owner decision,
/// 2026-11-21): it runs to the full `{bytes}` payload with a hard time
/// ceiling — a tunnel that cannot deliver it all in the ceiling still
/// yields the honest partial number. Nothing is written to disk.
pub async fn measure_speed(
    speed_url: &str,
    bytes: u64,
    ceiling: Duration,
    proxy_addr: &str,
) -> Attempt {
    match measure_speed_inner(speed_url, bytes, ceiling, proxy_addr).await {
        Ok(mbps) => Attempt {
            ok: true,
            value: AttemptValue::Speed(mbps),
            error: None,
        },
        Err(error) => Attempt {
            ok: false,
            value: AttemptValue::Speed(0.0),
            error: Some(error),
        },
    }
}

async fn measure_speed_inner(
    speed_url: &str,
    bytes: u64,
    ceiling: Duration,
    proxy_addr: &str,
) -> Result<f64, String> {
    if bytes == 0 {
        return Err("speed payload size is 0".to_string());
    }
    let url = expand_speed_url(speed_url, bytes);
    // The outer timeout covers connect + TLS + response head; the
    // per-chunk deadline below covers the body
    let client = build_client(ceiling + CONNECT_GRACE, proxy_addr)?;
    let started = Instant::now();
    let response = client
        .get(&url)
        .send()
        .await
        .and_then(|response| response.error_for_status())
        .map_err(|error| format!("speed request failed: {error}"))?;

    let deadline = tokio::time::Instant::now() + ceiling;
    let mut total: u64 = 0;
    let mut stream = response.bytes_stream();
    loop {
        match tokio::time::timeout_at(deadline, stream.next()).await {
            // The ceiling: count what arrived
            Err(_) => break,
            Ok(None) => break,
            Ok(Some(Err(error))) => {
                let partial = if total > 0 {
                    format!(" after {total} bytes")
                } else {
                    String::new()
                };
                return Err(format!("speed download failed{partial}: {error}"));
            }
            Ok(Some(Ok(chunk))) => {
                total = total.saturating_add(chunk.len() as u64);
                if total >= bytes {
                    total = bytes;
                    break;
                }
            }
        }
    }
    let elapsed = started.elapsed();
    if total == 0 {
        return Err("speed download produced no data".to_string());
    }
    if elapsed.is_zero() {
        return Err("speed download finished too fast to measure".to_string());
    }
    Ok(total as f64 * 8.0 / elapsed.as_secs_f64() / 1_000_000.0)
}

/// One fresh client per attempt: reqwest attaches the proxy at build
/// time, and each attempt dials a different pinned listener anyway, so a
/// shared pool would be dead weight. `Proxy::all`, not `Proxy::http`:
/// the speed and trace endpoints are https, and an https request reaches
/// the mixed listener as HTTP CONNECT, which only `all` routes through
/// the proxy.
fn build_client(timeout: Duration, proxy_addr: &str) -> Result<reqwest::Client, String> {
    let proxy = reqwest::Proxy::all(format!("http://{proxy_addr}"))
        .map_err(|error| format!("speed listener address is invalid: {error}"))?;
    reqwest::Client::builder()
        .timeout(timeout)
        .proxy(proxy)
        .build()
        .map_err(|error| format!("speed client build failed: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::Router;
    use axum::routing::get;

    /// A mock mixed listener is just an HTTP server in these tests: the
    /// real listener adds SOCKS5 next to HTTP CONNECT, but the probe only
    /// ever speaks HTTP CONNECT to it, which reqwest's `Proxy::http`
    /// produces.
    async fn spawn_mock(app: Router) -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        addr.to_string()
    }

    /// The trace endpoint the real kernel would answer through the
    /// tunnel: plain text, one key=value per line.
    #[tokio::test]
    async fn trace_facts_are_parsed_and_field_gated() {
        let app = Router::new().route(
            "/cdn-cgi/trace",
            get(|| async {
                "fl=1.0\nh=www.cloudflare.com\nip=203.0.113.7\nts=1700000000\n\
                 colo=SXC\nhttp=https/2\nloc=DE\ntls=TLSv1.3\nwarp=off\ngateway=off\njunkline\n"
            }),
        );
        let addr = spawn_mock(app).await;
        let fields = vec![
            "ip".to_string(),
            "colo".to_string(),
            "loc".to_string(),
            "warp".to_string(),
            "http".to_string(),
            "gateway".to_string(),
        ];
        let attempt = fetch_trace(&format!("http://{addr}/cdn-cgi/trace"), &fields, &addr).await;
        assert!(attempt.ok, "{:?}", attempt.error);
        let AttemptValue::Trace(facts) = attempt.value else {
            panic!("expected trace facts");
        };
        assert_eq!(facts.ip.as_deref(), Some("203.0.113.7"));
        assert_eq!(facts.colo.as_deref(), Some("SXC"));
        assert_eq!(facts.loc.as_deref(), Some("DE"));
        assert_eq!(facts.warp.as_deref(), Some("off"));
        // Only the configured fields beyond the four columns are kept
        let extra: serde_json::Value =
            serde_json::from_str(facts.extra.as_deref().unwrap()).unwrap();
        assert_eq!(extra["http"], "https/2");
        assert_eq!(extra["gateway"], "off");
        assert!(extra.get("tls").is_none(), "unrequested fields stay out");
        assert!(extra.get("h").is_none() && extra.get("ts").is_none());
    }

    /// An `ip=` value that is not an address literal is dropped, so the
    /// server-side GeoIP backfill never burns an attempt on it.
    #[tokio::test]
    async fn a_non_literal_ip_is_dropped() {
        let app = Router::new().route(
            "/cdn-cgi/trace",
            get(|| async { "ip=not-an-address\ncolo=FRA\n" }),
        );
        let addr = spawn_mock(app).await;
        let attempt = fetch_trace(
            &format!("http://{addr}/cdn-cgi/trace"),
            &["ip".into()],
            &addr,
        )
        .await;
        let AttemptValue::Trace(facts) = attempt.value else {
            panic!("expected trace facts");
        };
        assert_eq!(facts.ip, None);
        assert_eq!(facts.colo.as_deref(), Some("FRA"));
    }

    /// A non-2xx trace answer is a failed attempt with the status in the
    /// error text.
    #[tokio::test]
    async fn a_trace_error_status_fails_the_attempt() {
        let app = Router::new().route(
            "/cdn-cgi/trace",
            get(|| async { axum::http::StatusCode::INTERNAL_SERVER_ERROR }),
        );
        let addr = spawn_mock(app).await;
        let attempt = fetch_trace(&format!("http://{addr}/cdn-cgi/trace"), &[], &addr).await;
        assert!(!attempt.ok);
        assert!(
            attempt.error.as_deref().unwrap().contains("500"),
            "{}",
            attempt.error.unwrap()
        );
    }

    /// The full payload arrives: the throughput is derived from the
    /// requested size over the elapsed time.
    #[tokio::test]
    async fn a_complete_download_measures_the_payload_size() {
        const PAYLOAD: usize = 64 * 1024;
        let app = Router::new().route(
            "/__down",
            get(|| async { axum::body::Body::from(vec![0u8; PAYLOAD]) }),
        );
        let addr = spawn_mock(app).await;
        let attempt = measure_speed(
            &format!("http://{addr}/__down?measId={{rand}}&bytes={{bytes}}"),
            PAYLOAD as u64,
            Duration::from_secs(10),
            &addr,
        )
        .await;
        assert!(attempt.ok, "{:?}", attempt.error);
        let AttemptValue::Speed(mbps) = attempt.value else {
            panic!("expected a speed value");
        };
        assert!(mbps > 0.0);
        // The mock is loopback: the measured rate must be far above one
        // Mbit/s, which proves the payload was fully consumed
        assert!(mbps > 1.0, "{mbps}");
    }

    /// The ceiling cuts a stalled download: the attempt succeeds with the
    /// partial number instead of hanging the lane. The mock sends one
    /// chunk and then never resolves the stream, so the response head is
    /// there and the per-chunk deadline is what fires.
    #[tokio::test]
    async fn a_stalled_download_yields_the_partial_number() {
        let app = Router::new().route(
            "/__down",
            get(|| async {
                let chunk = futures_util::stream::once(async {
                    Ok::<axum::body::Bytes, std::convert::Infallible>(axum::body::Bytes::from(
                        vec![0u8; 32 * 1024],
                    ))
                })
                .chain(futures_util::stream::pending());
                axum::body::Body::from_stream(chunk)
            }),
        );
        let addr = spawn_mock(app).await;
        let attempt = measure_speed(
            &format!("http://{addr}/__down?bytes={{bytes}}"),
            1024 * 1024,
            Duration::from_millis(500),
            &addr,
        )
        .await;
        assert!(
            attempt.ok,
            "a stalled download must yield the partial number: {:?}",
            attempt.error
        );
        let AttemptValue::Speed(mbps) = attempt.value else {
            panic!("expected a speed value");
        };
        assert!(mbps > 0.0, "32 KiB in 500 ms is a positive rate");
    }

    /// A URL the endpoint answers with garbage status fails honestly.
    #[tokio::test]
    async fn a_speed_error_status_fails_the_attempt() {
        let app = Router::new().route(
            "/__down",
            get(|| async { axum::http::StatusCode::NOT_FOUND }),
        );
        let addr = spawn_mock(app).await;
        let attempt = measure_speed(
            &format!("http://{addr}/__down?bytes={{bytes}}"),
            1024,
            Duration::from_secs(5),
            &addr,
        )
        .await;
        assert!(!attempt.ok);
        assert!(attempt.error.unwrap().contains("404"));
    }

    /// The template expansion: `{bytes}` to the size, `{rand}` fresh per
    /// call.
    #[test]
    fn the_speed_url_template_expands_both_placeholders() {
        let url = expand_speed_url(
            "https://speed.cloudflare.com/__down?measId={rand}&bytes={bytes}",
            1048576,
        );
        assert!(url.contains("bytes=1048576"), "{url}");
        assert!(!url.contains("{rand}"), "{url}");
        assert!(!url.contains("{bytes}"), "{url}");
        let a = expand_speed_url("x{rand}y", 1);
        let b = expand_speed_url("x{rand}y", 1);
        assert_ne!(a, b, "the random value must be fresh per call");
    }

    /// The listener address derives from the controller address: same
    /// host (vetted), lane port; a bare IPv6 host gains brackets.
    #[test]
    fn the_listener_address_derives_from_the_controller_address() {
        assert_eq!(
            listener_addr("meow:9090", 30001).as_deref(),
            Some("meow:30001")
        );
        assert_eq!(
            listener_addr("127.0.0.1:9090", 30000).as_deref(),
            Some("127.0.0.1:30000")
        );
        assert_eq!(
            listener_addr("[::1]:9090", 30002).as_deref(),
            Some("[::1]:30002")
        );
        assert_eq!(listener_addr("9090", 30000), None);
        assert_eq!(listener_addr("", 30000), None);
    }
}
