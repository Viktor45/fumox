//! T1 connectivity checks: TCP connect with an optional TLS handshake
//!. The measured wall time becomes the proxy's latency.

use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use fumox_core::models::Scheme;
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

/// Transport-level flavour of a T1 check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CheckKind {
    Tcp,
    Tls,
}

impl CheckKind {
    /// Value stored in `probe_results.probe_kind`.
    pub fn as_str(self) -> &'static str {
        match self {
            CheckKind::Tcp => "tcp",
            CheckKind::Tls => "tls",
        }
    }
}

/// Decide the T1 flavour from the scheme and its recognized parameters.
///
/// trojan/naive always negotiate TLS; vless/vmess do so when their own
/// parameters say they are a TLS endpoint, in either of the two vocabularies
/// that reach `proxies.params` (see [`params_enable_tls`]); ss/socks5 are
/// plain TCP. QUIC schemes (hysteria2) and the unprobeable ones (tuic, mieru)
/// never reach T1, they are filtered out by the candidate query, so the
/// fallback branch is defensive only.
pub fn check_kind(scheme: Scheme, params_json: Option<&str>) -> CheckKind {
    match scheme {
        Scheme::Trojan | Scheme::Naive => CheckKind::Tls,
        Scheme::Vless | Scheme::Vmess => {
            if params_enable_tls(params_json) {
                CheckKind::Tls
            } else {
                CheckKind::Tcp
            }
        }
        // Snell is a plain TCP protocol (its obfs is a wrapper the tunnel
        // itself speaks, not a handshake T1 could validate), so a connect
        // is the honest reachability signal.
        Scheme::Ss | Scheme::Socks5 | Scheme::Snell => CheckKind::Tcp,
        Scheme::Hysteria2 | Scheme::Tuic | Scheme::Mieru => CheckKind::Tcp,
        // AnyTLS speaks TLS to its server, so a handshake is a stronger
        // liveness signal than a bare connect and matches trojan's tier.
        Scheme::AnyTls => CheckKind::Tls,
    }
}

/// Whether a vless/vmess entry's stored parameters put it behind TLS.
///
/// Both producer vocabularies have to be understood, exactly as the T2
/// mapping in `fumox_core::formats::clash` does:
/// `security=tls|reality` for URI links, and the mihomo spelling Clash YAML
/// inputs use, `tls: true` (`tls: "tls"` in the vmess JSON base64 blob).
/// Deciding on `security` alone checked every Clash-sourced node as plain
/// TCP, so a vless/vmess with a broken TLS listener passed T1 and was
/// served while the identical `vless://` spelling failed it.
///
/// Read case-insensitively on both sides, like `ProxyEntry::param_ignore_case`,
/// and a non-string JSON scalar (the stored params are strings today) still
/// counts through its textual form.
fn params_enable_tls(params_json: Option<&str>) -> bool {
    let Some(params) = params_json.and_then(|text| {
        serde_json::from_str::<serde_json::Map<String, serde_json::Value>>(text).ok()
    }) else {
        return false;
    };
    let param = |key: &str| param_text(&params, key);
    if param("security")
        .is_some_and(|v| v.eq_ignore_ascii_case("tls") || v.eq_ignore_ascii_case("reality"))
    {
        return true;
    }
    // `tls: "tls"` (vmess JSON) and `tls: true` → `"true"` (Clash YAML).
    param("tls").is_some_and(|v| {
        let v = v.to_ascii_lowercase();
        v == "tls" || matches!(v.as_str(), "1" | "true" | "yes" | "on")
    })
}

/// Trimmed textual form of a JSON object member, looked up case-insensitively.
fn param_text(params: &serde_json::Map<String, serde_json::Value>, key: &str) -> Option<String> {
    let value = params
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(key))
        .map(|(_, v)| match v {
            serde_json::Value::String(text) => text.clone(),
            other => other.to_string(),
        })?;
    let value = value.trim().to_string();
    (!value.is_empty()).then_some(value)
}

/// TLS connector with certificate verification disabled.
///
/// Health checks only care that the endpoint completes a handshake; many
/// proxy servers use self-signed certificates, so verification would
/// produce false deaths. This is deliberately not a trust boundary.
fn tls_connector() -> &'static TlsConnector {
    static CONNECTOR: OnceLock<TlsConnector> = OnceLock::new();
    CONNECTOR.get_or_init(|| {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let config = rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .expect("static protocol versions are valid")
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(InsecureVerifier))
            .with_no_client_auth();
        TlsConnector::from(Arc::new(config))
    })
}

/// Accepts any server certificate and signature: see [`tls_connector`].
#[derive(Debug)]
struct InsecureVerifier;

impl rustls::client::danger::ServerCertVerifier for InsecureVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA384,
            rustls::SignatureScheme::RSA_PKCS1_SHA512,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::ECDSA_NISTP521_SHA512,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA512,
            rustls::SignatureScheme::ED25519,
            rustls::SignatureScheme::ED448,
        ]
    }
}

/// One vetted T1 dial target: `host` is the name as stored (used for the
/// TLS SNI), `vetted` holds the SSRF-approved addresses to dial.
pub struct Target<'a> {
    pub host: &'a str,
    pub port: u16,
    pub kind: CheckKind,
    pub vetted: &'a [std::net::IpAddr],
}

/// Run one T1 check, dialing only the addresses the SSRF gate already
/// vetted. Returns the elapsed time on success or a human-readable failure
/// reason (journaled verbatim into `probe_results.error`).
///
/// `target.vetted` must be non-empty: it is what `fumox_core::ssrf::
/// vet_probe_host_addrs` returned for `target.host` moments ago. Connecting
/// to those exact IPs (instead of re-resolving the hostname) closes the
/// DNS-rebinding window between vet and dial, and sidesteps the IPv6
/// `host:port` formatting trap entirely, a `SocketAddr` needs no brackets.
pub async fn run(
    target: &Target<'_>,
    connect_timeout: Duration,
    tls_timeout: Duration,
) -> Result<Duration, String> {
    let started = Instant::now();

    // Each vetted address gets its own connect_timeout, so the worst case
    // stays `4 × connect_timeout` + the TLS handshake; the list is capped
    // at ssrf::MAX_VETTED_ADDRESSES.
    let mut stream = None;
    let mut last_error = "no vetted address to connect to".to_string();
    for ip in target.vetted {
        let addr = std::net::SocketAddr::new(*ip, target.port);
        match tokio::time::timeout(connect_timeout, TcpStream::connect(addr)).await {
            Ok(Ok(s)) => {
                stream = Some(s);
                break;
            }
            Ok(Err(e)) => last_error = format!("tcp connect failed: {e}"),
            Err(_) => {
                last_error = format!("tcp connect timed out after {}s", connect_timeout.as_secs())
            }
        }
    }
    let Some(stream) = stream else {
        return Err(last_error);
    };

    if target.kind == CheckKind::Tcp {
        return Ok(started.elapsed());
    }

    let server_name = rustls::pki_types::ServerName::try_from(target.host.to_string())
        .map_err(|e| format!("invalid TLS server name {}: {e}", target.host))?;
    let handshake = tls_connector().connect(server_name, stream);
    tokio::time::timeout(tls_timeout, handshake)
        .await
        .map_err(|_| format!("tls handshake timed out after {}s", tls_timeout.as_secs()))?
        .map_err(|e| format!("tls handshake failed: {e}"))?;

    Ok(started.elapsed())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn params(json: &str) -> Option<&str> {
        Some(json)
    }

    #[test]
    fn kind_decision_table() {
        assert_eq!(check_kind(Scheme::Trojan, None), CheckKind::Tls);
        assert_eq!(check_kind(Scheme::Naive, None), CheckKind::Tls);
        assert_eq!(check_kind(Scheme::Ss, None), CheckKind::Tcp);
        assert_eq!(check_kind(Scheme::Socks5, None), CheckKind::Tcp);
        assert_eq!(
            check_kind(Scheme::Vless, params(r#"{"security":"reality"}"#)),
            CheckKind::Tls
        );
        assert_eq!(
            check_kind(Scheme::Vless, params(r#"{"security":"tls"}"#)),
            CheckKind::Tls
        );
        assert_eq!(
            check_kind(Scheme::Vless, params(r#"{"security":"none"}"#)),
            CheckKind::Tcp
        );
        assert_eq!(check_kind(Scheme::Vless, None), CheckKind::Tcp);
        // Clash-sourced spells, the same params the T2 mapping reads
        // (`formats::clash`): boolean `tls: true` plus `servername`.
        assert_eq!(
            check_kind(
                Scheme::Vless,
                params(r#"{"tls":"true","servername":"s.example.com"}"#)
            ),
            CheckKind::Tls
        );
        assert_eq!(
            check_kind(Scheme::Vmess, params(r#"{"tls":"true"}"#)),
            CheckKind::Tls
        );
        // vmess JSON spells it `tls: "tls"`.
        assert_eq!(
            check_kind(
                Scheme::Vmess,
                params(r#"{"tls":"tls","sni":"s.example.com"}"#)
            ),
            CheckKind::Tls
        );
        // The negative Clash spelling stays plain TCP.
        assert_eq!(
            check_kind(Scheme::Vless, params(r#"{"tls":"false","network":"ws"}"#)),
            CheckKind::Tcp
        );
        assert_eq!(
            check_kind(Scheme::Vless, params(r#"{"TLS":"on"}"#)),
            CheckKind::Tls
        );
        assert_eq!(
            check_kind(Scheme::Vmess, params(r#"{"security":"tls"}"#)),
            CheckKind::Tls
        );
        assert_eq!(
            check_kind(Scheme::Vmess, params(r#"{"security":""}"#)),
            CheckKind::Tcp
        );
        // Corrupt JSON degrades to TCP instead of failing the check.
        assert_eq!(check_kind(Scheme::Vless, params("{oops")), CheckKind::Tcp);
    }

    /// The verdict must not depend on which feed spelling a node arrived
    /// in: the same TLS proxy parsed from a Clash YAML source and from a
    /// `vless://` URI has to be checked the same way, and T2's mapping of
    /// the very same two entries has to negotiate TLS for both, otherwise
    /// the daemon would tunnel-test a node it considered plain TCP.
    #[test]
    fn clash_and_uri_spellings_agree_on_tls() {
        let yaml = "proxies:\n  - name: clash-tls\n    type: vless\n    server: h.example.com\n    port: 443\n    uuid: uuid-1\n    network: ws\n    tls: true\n    servername: s.example.com\n";
        let parsed = fumox_core::parsers::clash::parse_payload(yaml).unwrap();
        let clash_json = serde_json::to_string(&parsed.entries[0].known_params_json()).unwrap();
        assert!(
            clash_json.contains(r#""tls""#) && !clash_json.contains(r#""security""#),
            "the Clash producer must land in params as `tls`, got {clash_json}"
        );

        let uri = match fumox_core::parsers::parse_line(
            "vless://uuid-1@h.example.com:443?security=tls&sni=s.example.com&type=ws#Name",
        ) {
            fumox_core::parsers::LineOutcome::Parsed(entry) => entry,
            other => panic!("expected a parsed entry, got {other:?}"),
        };
        let uri_json = serde_json::to_string(&uri.known_params_json()).unwrap();

        assert_eq!(check_kind(Scheme::Vless, Some(&clash_json)), CheckKind::Tls);
        assert_eq!(check_kind(Scheme::Vless, Some(&uri_json)), CheckKind::Tls);

        // T2 builds its proxy from the same two entries, through the shared
        // core mapping the subscriptions are served with.
        for (spelling, entry) in [("clash", &parsed.entries[0]), ("uri", &uri)] {
            let value = fumox_core::formats::clash::entry_to_clash(entry)
                .expect("vless has a mihomo counterpart");
            assert_eq!(
                value["tls"].as_bool(),
                Some(true),
                "{spelling} row: T2 must agree that this is a TLS endpoint"
            );
        }
    }

    #[tokio::test]
    async fn tcp_check_against_local_listener() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        let result = run(
            &Target {
                host: "127.0.0.1",
                port,
                kind: CheckKind::Tcp,
                vetted: &["127.0.0.1".parse().unwrap()],
            },
            Duration::from_secs(2),
            Duration::from_secs(2),
        )
        .await;
        assert!(result.is_ok(), "expected a successful connect: {result:?}");
    }

    /// An IPv6-literal host connects fine when dialed as a `SocketAddr` ,
    /// the previous `format!("{host}:{port}")` produced an unparseable
    /// `2001:db8::1:443` string and every IPv6 proxy failed T1.
    #[tokio::test]
    async fn tcp_check_handles_ipv6_loopback() {
        let listener = tokio::net::TcpListener::bind("[::1]:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        let result = run(
            &Target {
                host: "::1",
                port,
                kind: CheckKind::Tcp,
                vetted: &["::1".parse().unwrap()],
            },
            Duration::from_secs(2),
            Duration::from_secs(2),
        )
        .await;
        assert!(result.is_ok(), "expected a successful connect: {result:?}");
    }

    #[tokio::test]
    async fn tcp_check_fails_on_closed_port() {
        // Bind and immediately drop to obtain a port that is (almost
        // certainly) closed.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);

        let result = run(
            &Target {
                host: "127.0.0.1",
                port,
                kind: CheckKind::Tcp,
                vetted: &["127.0.0.1".parse().unwrap()],
            },
            Duration::from_secs(2),
            Duration::from_secs(2),
        )
        .await;
        assert!(result.is_err());
    }
}
