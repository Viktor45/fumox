//! T1 connectivity checks: TCP connect with an optional TLS handshake
//! (SPEC §8.1). The measured wall time becomes the proxy's latency.

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
    /// Value stored in `probe_results.probe_kind` (DATABASE.md).
    pub fn as_str(self) -> &'static str {
        match self {
            CheckKind::Tcp => "tcp",
            CheckKind::Tls => "tls",
        }
    }
}

/// Decide the T1 flavour from the scheme and its recognized parameters.
///
/// trojan/naive always negotiate TLS; vless/vmess do so only when their
/// `security` parameter is `tls` or `reality`; ss/socks5 are plain TCP.
/// QUIC schemes (hysteria2) and the unprobeable ones (tuic, mieru) never
/// reach T1 — they are filtered out by the candidate query — so the
/// fallback branch is defensive only.
pub fn check_kind(scheme: Scheme, params_json: Option<&str>) -> CheckKind {
    match scheme {
        Scheme::Trojan | Scheme::Naive => CheckKind::Tls,
        Scheme::Ss | Scheme::Socks5 => CheckKind::Tcp,
        Scheme::Vless | Scheme::Vmess => {
            let security = params_json
                .and_then(|text| serde_json::from_str::<serde_json::Value>(text).ok())
                .and_then(|value| value.get("security")?.as_str().map(str::to_string));
            match security.as_deref() {
                Some("tls") | Some("reality") => CheckKind::Tls,
                _ => CheckKind::Tcp,
            }
        }
        Scheme::Hysteria2 | Scheme::Tuic | Scheme::Mieru => CheckKind::Tcp,
    }
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

/// Run one T1 check against `host:port`. Returns the elapsed time on
/// success or a human-readable failure reason (journaled verbatim into
/// `probe_results.error`).
pub async fn run(
    host: &str,
    port: u16,
    kind: CheckKind,
    connect_timeout: Duration,
    tls_timeout: Duration,
) -> Result<Duration, String> {
    let addr = format!("{host}:{port}");
    let started = Instant::now();

    let stream = tokio::time::timeout(connect_timeout, TcpStream::connect(&addr))
        .await
        .map_err(|_| format!("tcp connect timed out after {}s", connect_timeout.as_secs()))?
        .map_err(|e| format!("tcp connect failed: {e}"))?;

    if kind == CheckKind::Tcp {
        return Ok(started.elapsed());
    }

    let server_name = rustls::pki_types::ServerName::try_from(host.to_string())
        .map_err(|e| format!("invalid TLS server name {host:?}: {e}"))?;
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

    #[tokio::test]
    async fn tcp_check_against_local_listener() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        let result = run(
            "127.0.0.1",
            port,
            CheckKind::Tcp,
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
            "127.0.0.1",
            port,
            CheckKind::Tcp,
            Duration::from_secs(2),
            Duration::from_secs(2),
        )
        .await;
        assert!(result.is_err());
    }
}
