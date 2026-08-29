//! meow-rs REST client for T2 checks (SPEC §8.2).
//!
//! meow-rs runs as a separate system service; the probe only reloads its
//! config (`PUT /configs`) and asks for per-proxy delay measurements
//! (`GET /proxies/{name}/delay`). Unavailability is reported, never fatal:
//! the daemon skips T2 with backoff and keeps running T1.

use std::time::Duration;

use fumox_core::config::MeowConfig;
use rand::seq::IndexedRandom;

pub struct MeowClient {
    http: reqwest::Client,
    base_url: String,
    test_urls: Vec<String>,
    timeout: Duration,
}

/// Outcome of one delay measurement.
#[derive(Debug)]
pub enum DelayOutcome {
    /// Tunnel established; latency in milliseconds.
    Ok(u64),
    /// meow-rs answered, but the proxy failed the tunnel test.
    ProxyFailed(String),
    /// meow-rs itself is unreachable or misbehaving — the batch must be
    /// aborted without touching proxy statuses.
    ServiceUnavailable(String),
}

impl MeowClient {
    pub fn new(config: &MeowConfig) -> Self {
        Self {
            http: reqwest::Client::new(),
            base_url: format!("http://{}", config.api_addr),
            test_urls: config.test_url.clone(),
            timeout: Duration::from_secs(config.timeout_secs.max(1)),
        }
    }

    /// Random test URL for one delay check: with several configured, the
    /// checks rotate across the list instead of hammering one endpoint
    /// (one URL may be blocked or degraded in a given region).
    fn pick_test_url<'a>(&'a self, rng: &mut impl rand::Rng) -> &'a str {
        self.test_urls
            .choose(rng)
            .expect("meow.test_url is never empty (guaranteed by the config deserializer)")
    }

    /// `GET /version` — cheap liveness probe of the REST API.
    pub async fn ping(&self) -> Result<String, String> {
        let response = self
            .http
            .get(format!("{}/version", self.base_url))
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
        Ok(body
            .get("version")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
            .to_string())
    }

    /// `PUT /configs` — hot-reload the generated Clash YAML without
    /// restarting the meow-rs process.
    pub async fn reload_config(&self, path: &std::path::Path) -> Result<(), String> {
        let response = self
            .http
            .put(format!("{}/configs", self.base_url))
            .json(&serde_json::json!({ "path": path.to_string_lossy() }))
            .timeout(Duration::from_secs(10))
            .send()
            .await
            .map_err(|e| format!("meow-rs unreachable: {e}"))?;
        if response.status().is_success() {
            return Ok(());
        }
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        Err(format!("PUT /configs returned {status}: {body}"))
    }

    /// `GET /proxies/{name}/delay` — run one real tunnel check.
    ///
    /// Distinguishes "the proxy is dead" (meow answered with a failure)
    /// from "meow itself is down" (transport error / 5xx), so the caller
    /// can quarantine the former and back off on the latter.
    pub async fn check_delay(&self, name: &str) -> DelayOutcome {
        let url = format!("{}/proxies/{name}/delay", self.base_url);
        let timeout_ms = self.timeout.as_millis().to_string();
        let test_url = self.pick_test_url(&mut rand::rng());
        let response = match self
            .http
            .get(&url)
            .query(&[("url", test_url), ("timeout", timeout_ms.as_str())])
            .timeout(self.timeout + Duration::from_secs(5))
            .send()
            .await
        {
            Ok(response) => response,
            Err(e) => return DelayOutcome::ServiceUnavailable(format!("transport error: {e}")),
        };

        let status = response.status();
        let body: serde_json::Value = match response.json().await {
            Ok(body) => body,
            Err(e) => return DelayOutcome::ServiceUnavailable(format!("bad delay payload: {e}")),
        };

        if status.is_success() {
            if let Some(delay) = body.get("delay").and_then(|v| v.as_u64()) {
                return DelayOutcome::Ok(delay);
            }
            return DelayOutcome::ServiceUnavailable("delay response has no delay field".into());
        }

        // 4xx from the delay endpoint means meow tried the tunnel and it
        // failed; 5xx means meow itself had a problem.
        let message = body
            .get("message")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown error")
            .to_string();
        if status.is_client_error() {
            DelayOutcome::ProxyFailed(message)
        } else {
            DelayOutcome::ServiceUnavailable(format!("{status}: {message}"))
        }
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

    /// Stand up a mock meow-rs REST API on an ephemeral port. Captures the
    /// `url` query parameter of every delay request for rotation asserts.
    async fn mock_api(
        reloads: Arc<AtomicUsize>,
    ) -> (
        String,
        fumox_core::config::MeowConfig,
        Arc<std::sync::Mutex<HashSet<String>>>,
    ) {
        let seen_test_urls: Arc<std::sync::Mutex<HashSet<String>>> = Arc::default();
        let capture = seen_test_urls.clone();
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
            .route(
                "/proxies/{name}/delay",
                get(
                    move |Path(name): Path<String>,
                          Query(query): Query<HashMap<String, String>>| {
                        let capture = capture.clone();
                        async move {
                            if let Some(url) = query.get("url") {
                                capture.lock().unwrap().insert(url.clone());
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

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let config = MeowConfig {
            api_addr: addr.to_string(),
            config_path: std::env::temp_dir().join("fumox-meow-test.yaml"),
            test_url: vec!["http://cp.cloudflare.com".to_string()],
            timeout_secs: 5,
        };
        (addr.to_string(), config, seen_test_urls)
    }

    #[tokio::test]
    async fn ping_reload_and_delay_outcomes() {
        let reloads = Arc::new(AtomicUsize::new(0));
        let (_addr, config, _seen) = mock_api(reloads.clone()).await;
        let client = MeowClient::new(&config);

        assert_eq!(client.ping().await.unwrap(), "mock-0.20");

        client.reload_config(&config.config_path).await.unwrap();
        assert_eq!(reloads.load(Ordering::SeqCst), 1);

        match client.check_delay("fumox-1").await {
            DelayOutcome::Ok(delay) => assert_eq!(delay, 42),
            other => panic!("expected Ok, got {other:?}"),
        }
        match client.check_delay("fumox-2").await {
            DelayOutcome::ProxyFailed(msg) => assert!(msg.contains("timeout")),
            other => panic!("expected ProxyFailed, got {other:?}"),
        }
        match client.check_delay("fumox-99").await {
            DelayOutcome::ServiceUnavailable(_) => {}
            other => panic!("expected ServiceUnavailable, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn unreachable_api_reports_service_unavailable() {
        let config = MeowConfig {
            // Nothing listens here.
            api_addr: "127.0.0.1:1".into(),
            config_path: std::env::temp_dir().join("fumox-meow-test.yaml"),
            test_url: vec!["http://cp.cloudflare.com".to_string()],
            timeout_secs: 2,
        };
        let client = MeowClient::new(&config);
        assert!(client.ping().await.is_err());
        assert!(client.reload_config(&config.config_path).await.is_err());
        assert!(matches!(
            client.check_delay("fumox-1").await,
            DelayOutcome::ServiceUnavailable(_)
        ));
    }

    #[tokio::test]
    async fn delay_requests_rotate_the_configured_test_urls() {
        let reloads = Arc::new(AtomicUsize::new(0));
        let (_addr, mut config, seen) = mock_api(reloads.clone()).await;
        config.test_url = vec!["http://a.example/204".into(), "http://b.example/204".into()];
        let client = MeowClient::new(&config);

        // 40 draws over two URLs: the odds of never seeing one are ~10^-12.
        for _ in 0..40 {
            assert!(matches!(
                client.check_delay("fumox-1").await,
                DelayOutcome::Ok(_)
            ));
        }
        assert_eq!(
            *seen.lock().unwrap(),
            HashSet::from([
                "http://a.example/204".to_string(),
                "http://b.example/204".to_string(),
            ])
        );
    }

    #[test]
    fn pick_test_url_covers_the_whole_list() {
        let config = MeowConfig {
            test_url: vec!["a".into(), "b".into(), "c".into()],
            ..Default::default()
        };
        let client = MeowClient::new(&config);
        // Seeded: the assertion is deterministic for this fixed sequence.
        let mut rng = {
            use rand::SeedableRng;
            rand::rngs::StdRng::seed_from_u64(7)
        };
        let picked: HashSet<&str> = (0..100).map(|_| client.pick_test_url(&mut rng)).collect();
        assert_eq!(picked, HashSet::from(["a", "b", "c"]));
    }
}
