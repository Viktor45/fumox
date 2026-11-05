//! T1 connectivity checks: TCP connect with an optional TLS handshake
//!. The measured wall time becomes the proxy's latency.

use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use fumox_core::models::{ProxyEntry, Scheme};
use futures_util::stream::{FuturesUnordered, StreamExt};
use rustls::pki_types::ServerName;
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

/// Decide the T1 flavour from the scheme and the node's own parameters.
///
/// The decision must match what the T2 batch asks the engine for, or the
/// two grades disagree about the same node: a check that passes a node the
/// tunnel cannot open leaves it `alive`.
///
/// The protocols that carry their credential inside the TLS session and
/// have no plain-text form always negotiate TLS (trojan/naive/anytls); the
/// ones the mihomo mapping never wraps are plain TCP (ss/snell and the
/// QUIC schemes, which never reach T1 at all).
///
/// For vless/vmess the decision belongs to the shared core predicate
/// ([`fumox_core::params::wants_tls`]), the same one the Clash writer and
/// the sing-box writer ask: a node whose parameters say it is wrapped is
/// checked with a handshake, and one whose parameters say it is not is
/// checked with a plain connect. The two used to answer differently — the
/// writer took an SNI as a TLS signal and the check did not, so a
/// `vless://` link with an SNI was written as a TLS node and probed as
/// plaintext, and a broken one passed the probe and was served.
///
/// SOCKS5 is the one scheme the writers decide on their own: both of them
/// wrap a socks5 node only when it asks for it explicitly, so the check
/// asks the same toggle.
pub fn check_kind(scheme: Scheme, entry: &ProxyEntry) -> CheckKind {
    match scheme {
        Scheme::Trojan | Scheme::Naive | Scheme::AnyTls => CheckKind::Tls,
        // Snell's obfs is spoken inside the tunnel, not a handshake T1
        // could validate: connect-only, the T2 tunnel is the verification.
        Scheme::Ss | Scheme::Snell => CheckKind::Tcp,
        Scheme::Hysteria2 | Scheme::Tuic | Scheme::Mieru => CheckKind::Tcp,
        Scheme::Socks5 => {
            if fumox_core::params::truthy(entry, "tls") {
                CheckKind::Tls
            } else {
                CheckKind::Tcp
            }
        }
        Scheme::Vless | Scheme::Vmess => {
            let blocks = fumox_core::params::Blocks::of(entry);
            if fumox_core::params::wants_tls(entry, &blocks) {
                CheckKind::Tls
            } else {
                CheckKind::Tcp
            }
        }
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

/// One vetted T1 dial target: `host` is the name as stored, `server_name`
/// is the name the TLS handshake presents, `vetted` holds the SSRF-approved
/// addresses to dial.
pub struct Target<'a> {
    pub host: &'a str,
    /// The name the handshake presents: the node's own SNI when it carries
    /// one, else the stored host.
    ///
    /// The stored host is not always the right name: a node reached
    /// through a CDN carries the CDN's name in `sni`/`servername`, and a
    /// node whose host is an IP literal carries the name its certificate
    /// was issued for. Presenting the host instead made the handshake
    /// fail against a server that only accepts its own name.
    pub server_name: Option<&'a str>,
    pub port: u16,
    pub kind: CheckKind,
    pub vetted: &'a [std::net::IpAddr],
}

/// What a check does once the connection is open.
enum Plan {
    /// The connection itself is the verdict.
    Tcp,
    /// A handshake has to complete on top of it, under this name.
    Tls(ServerName<'static>),
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
///
/// Every vetted address is dialed at the same time and the first one that
/// completes wins; the rest are cancelled. A TLS failure on one address
/// does not stop the others: only when the whole list has failed does the
/// check fail, with the error of the last attempt.
pub async fn run(
    target: &Target<'_>,
    connect_timeout: Duration,
    tls_timeout: Duration,
) -> Result<Duration, String> {
    let started = Instant::now();

    // The plan is resolved before the first dial: an invalid server name is
    // a property of the node, not of the address, and every address would
    // fail the same way.
    let plan = match target.kind {
        CheckKind::Tcp => Plan::Tcp,
        CheckKind::Tls => Plan::Tls(server_name_of(target)?),
    };

    let mut attempts = FuturesUnordered::new();
    for ip in target.vetted {
        attempts.push(attempt(
            *ip,
            target.port,
            &plan,
            connect_timeout,
            tls_timeout,
        ));
    }

    let mut last_error = "no vetted address to connect to".to_string();
    while let Some(outcome) = attempts.next().await {
        match outcome {
            Ok(()) => return Ok(started.elapsed()),
            Err(error) => last_error = error,
        }
    }
    Err(last_error)
}

/// The name the handshake presents: the node's own SNI when it has one,
/// else the stored host.
///
/// An IP-literal host keeps the SNI from the parameters: the address is
/// not a certificate name, so the name the certificate was issued for has
/// to come from the node itself.
fn server_name_of(target: &Target<'_>) -> Result<ServerName<'static>, String> {
    let name = target.server_name.unwrap_or(target.host);
    ServerName::try_from(name.to_string())
        .map_err(|error| format!("invalid TLS server name {name}: {error}"))
}

/// One dial attempt against a single vetted address: the TCP connect and,
/// for a TLS check, the handshake that follows it.
async fn attempt(
    ip: std::net::IpAddr,
    port: u16,
    plan: &Plan,
    connect_timeout: Duration,
    tls_timeout: Duration,
) -> Result<(), String> {
    let addr = std::net::SocketAddr::new(ip, port);
    let stream = match tokio::time::timeout(connect_timeout, TcpStream::connect(addr)).await {
        Ok(Ok(stream)) => stream,
        Ok(Err(error)) => return Err(format!("tcp connect failed: {error}")),
        Err(_) => {
            return Err(format!(
                "tcp connect timed out after {}s",
                connect_timeout.as_secs()
            ));
        }
    };
    let Plan::Tls(server_name) = plan else {
        return Ok(());
    };
    let handshake = tls_connector().connect(server_name.clone(), stream);
    match tokio::time::timeout(tls_timeout, handshake).await {
        Ok(Ok(_)) => Ok(()),
        Ok(Err(error)) => Err(format!("tls handshake failed: {error}")),
        Err(_) => Err(format!(
            "tls handshake timed out after {}s",
            tls_timeout.as_secs()
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fumox_core::models::Param;
    use std::sync::Mutex;
    use tokio::io::AsyncReadExt;

    /// A node with the given parameters.
    fn entry(scheme: Scheme, params: &[(&str, &str)]) -> ProxyEntry {
        ProxyEntry {
            scheme,
            name: "n".to_string(),
            host: "h.example.com".to_string(),
            port: 443,
            credential: "uuid-1".to_string(),
            params: params
                .iter()
                .map(|(key, value)| Param {
                    key: (*key).to_string(),
                    value: (*value).to_string(),
                    known: true,
                })
                .collect(),
            raw_path: String::new(),
            raw_line: String::new(),
        }
    }

    #[test]
    fn kind_decision_table() {
        let plain = |scheme| entry(scheme, &[]);
        assert_eq!(
            check_kind(Scheme::Trojan, &plain(Scheme::Trojan)),
            CheckKind::Tls
        );
        assert_eq!(
            check_kind(Scheme::Naive, &plain(Scheme::Naive)),
            CheckKind::Tls
        );
        assert_eq!(check_kind(Scheme::Ss, &plain(Scheme::Ss)), CheckKind::Tcp);
        assert_eq!(
            check_kind(Scheme::Socks5, &plain(Scheme::Socks5)),
            CheckKind::Tcp
        );
        // Snell's obfs is spoken inside the tunnel, not a handshake T1
        // could validate: connect-only, the T2 tunnel is the verification.
        assert_eq!(
            check_kind(Scheme::Snell, &plain(Scheme::Snell)),
            CheckKind::Tcp
        );
        // AnyTLS speaks TLS; the verdict ignores params (there is no
        // plain-TCP spelling of the protocol to fall back to).
        assert_eq!(
            check_kind(Scheme::AnyTls, &plain(Scheme::AnyTls)),
            CheckKind::Tls
        );
        assert_eq!(
            check_kind(Scheme::AnyTls, &entry(Scheme::AnyTls, &[("tls", "false")])),
            CheckKind::Tls
        );
        assert_eq!(
            check_kind(
                Scheme::Vless,
                &entry(Scheme::Vless, &[("security", "reality")])
            ),
            CheckKind::Tls
        );
        assert_eq!(
            check_kind(Scheme::Vless, &entry(Scheme::Vless, &[("security", "tls")])),
            CheckKind::Tls
        );
        // `xtls` is the older spelling of the REALITY transport and states
        // a TLS layer like the others.
        assert_eq!(
            check_kind(
                Scheme::Vless,
                &entry(Scheme::Vless, &[("security", "xtls")])
            ),
            CheckKind::Tls
        );
        assert_eq!(
            check_kind(
                Scheme::Vless,
                &entry(Scheme::Vless, &[("security", "none")])
            ),
            CheckKind::Tcp
        );
        assert_eq!(
            check_kind(Scheme::Vless, &plain(Scheme::Vless)),
            CheckKind::Tcp
        );
        // Clash-sourced spells, the same params the T2 mapping reads
        // (`formats::clash`): boolean `tls: true` plus `servername`.
        assert_eq!(
            check_kind(
                Scheme::Vless,
                &entry(
                    Scheme::Vless,
                    &[("tls", "true"), ("servername", "s.example.com")]
                )
            ),
            CheckKind::Tls
        );
        assert_eq!(
            check_kind(Scheme::Vmess, &entry(Scheme::Vmess, &[("tls", "true")])),
            CheckKind::Tls
        );
        // vmess JSON spells it `tls: "tls"`.
        assert_eq!(
            check_kind(
                Scheme::Vmess,
                &entry(Scheme::Vmess, &[("tls", "tls"), ("sni", "s.example.com")])
            ),
            CheckKind::Tls
        );
        // The negative Clash spelling stays plain TCP.
        assert_eq!(
            check_kind(
                Scheme::Vless,
                &entry(Scheme::Vless, &[("tls", "false"), ("network", "ws")])
            ),
            CheckKind::Tcp
        );
        assert_eq!(
            check_kind(Scheme::Vless, &entry(Scheme::Vless, &[("TLS", "on")])),
            CheckKind::Tls
        );
        assert_eq!(
            check_kind(Scheme::Vmess, &entry(Scheme::Vmess, &[("security", "tls")])),
            CheckKind::Tls
        );
        assert_eq!(
            check_kind(Scheme::Vmess, &entry(Scheme::Vmess, &[("security", "")])),
            CheckKind::Tcp
        );
        // An unknown, non-empty `security` is a spelling this build does
        // not know: the node is treated as wrapped, because probing it as
        // plaintext passes a node whose TLS is broken.
        assert_eq!(
            check_kind(
                Scheme::Vless,
                &entry(Scheme::Vless, &[("security", "quic")])
            ),
            CheckKind::Tls
        );
        // SOCKS5 is wrapped only when the node asks for it, the way both
        // writers decide it.
        assert_eq!(
            check_kind(Scheme::Socks5, &entry(Scheme::Socks5, &[("tls", "true")])),
            CheckKind::Tls
        );
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
        let clash_entry = parsed.entries[0].clone();

        let uri = match fumox_core::parsers::parse_line(
            "vless://uuid-1@h.example.com:443?security=tls&sni=s.example.com&type=ws#Name",
        ) {
            fumox_core::parsers::LineOutcome::Parsed(entry) => entry,
            other => panic!("expected a parsed entry, got {other:?}"),
        };

        assert_eq!(check_kind(Scheme::Vless, &clash_entry), CheckKind::Tls);
        assert_eq!(check_kind(Scheme::Vless, &uri), CheckKind::Tls);

        // T2 builds its proxy from the same two entries, through the shared
        // core mapping the subscriptions are served with.
        for (spelling, entry) in [("clash", &clash_entry), ("uri", &uri)] {
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
                server_name: None,
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
                server_name: None,
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
                server_name: None,
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

    /// A TLS listener that answers one handshake and remembers the name
    /// the client presented.
    #[derive(Debug)]
    struct RecordingResolver {
        key: Arc<rustls::sign::CertifiedKey>,
        seen: Arc<Mutex<Option<String>>>,
    }

    impl rustls::server::ResolvesServerCert for RecordingResolver {
        fn resolve(
            &self,
            client_hello: rustls::server::ClientHello<'_>,
        ) -> Option<Arc<rustls::sign::CertifiedKey>> {
            *self.seen.lock().unwrap() = client_hello.server_name().map(str::to_string);
            Some(self.key.clone())
        }
    }

    /// A TLS listener with a self-signed certificate, and the slot that
    /// receives the SNI the client presented.
    async fn tls_listener() -> (u16, Arc<Mutex<Option<String>>>) {
        let seen = Arc::new(Mutex::new(None));
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let generated = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
            .expect("the test certificate is generated");
        let key = rustls::crypto::ring::sign::any_supported_type(
            &rustls::pki_types::PrivateKeyDer::Pkcs8(rustls::pki_types::PrivatePkcs8KeyDer::from(
                generated.signing_key.serialize_der(),
            )),
        )
        .expect("the generated key is supported");
        let certified = Arc::new(rustls::sign::CertifiedKey::new(
            vec![generated.cert.der().clone()],
            key,
        ));
        let config = rustls::ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .expect("the default protocol versions are valid")
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(RecordingResolver {
                key: certified,
                seen: seen.clone(),
            }));
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let acceptor = acceptor.clone();
                tokio::spawn(async move {
                    // The handshake is the verdict; the connection is
                    // closed right after it.
                    let _ = acceptor.accept(stream).await;
                });
            }
        });
        (port, seen)
    }

    /// A plain TCP listener that never speaks TLS.
    async fn plain_listener() -> u16 {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                tokio::spawn(async move {
                    // Hold the connection open without answering: the
                    // handshake has to run into its timeout or fail.
                    let mut buffer = [0u8; 64];
                    let _ = stream.read(&mut buffer).await;
                });
            }
        });
        port
    }

    /// A TCP listener that accepts and stays silent: no read, no write and
    /// no close, so a handshake cannot fail early and can only end at its
    /// deadline.
    async fn silent_listener() -> u16 {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                tokio::spawn(async move {
                    // Dropping the stream would close the connection and
                    // fail the handshake with an EOF instead of a timeout.
                    let _held = stream;
                    std::future::pending::<()>().await;
                });
            }
        });
        port
    }

    #[tokio::test]
    async fn tls_check_completes_the_handshake() {
        let (port, _seen) = tls_listener().await;
        let result = run(
            &Target {
                host: "localhost",
                server_name: None,
                port,
                kind: CheckKind::Tls,
                vetted: &["127.0.0.1".parse().unwrap()],
            },
            Duration::from_secs(2),
            Duration::from_secs(2),
        )
        .await;
        assert!(result.is_ok(), "expected a completed handshake: {result:?}");
    }

    /// The node's own SNI is the name the handshake presents: a server
    /// that only knows its own name would otherwise refuse the connection.
    #[tokio::test]
    async fn tls_check_presents_the_nodes_own_sni() {
        let (port, seen) = tls_listener().await;
        let result = run(
            &Target {
                host: "h.example.com",
                server_name: Some("sni.example.com"),
                port,
                kind: CheckKind::Tls,
                vetted: &["127.0.0.1".parse().unwrap()],
            },
            Duration::from_secs(2),
            Duration::from_secs(2),
        )
        .await;
        assert!(result.is_ok(), "expected a completed handshake: {result:?}");
        assert_eq!(
            seen.lock().unwrap().as_deref(),
            Some("sni.example.com"),
            "the handshake must present the SNI of the node"
        );
    }

    #[tokio::test]
    async fn tls_check_against_a_plain_listener_fails_with_a_tls_error() {
        let port = plain_listener().await;
        let result = run(
            &Target {
                host: "localhost",
                server_name: None,
                port,
                kind: CheckKind::Tls,
                vetted: &["127.0.0.1".parse().unwrap()],
            },
            Duration::from_secs(2),
            Duration::from_secs(2),
        )
        .await;
        let error = result.expect_err("a plain listener cannot complete a handshake");
        assert!(
            error.starts_with("tls handshake failed"),
            "the failure must name the handshake, got {error}"
        );
    }

    /// A handshake against a listener that never speaks runs into the
    /// deadline. The clock is paused, so the two-second timeout is
    /// virtual: the runtime advances it the moment nothing else is left
    /// to do, and the test waits no real time.
    #[tokio::test(start_paused = true)]
    async fn tls_check_times_out_against_a_silent_listener() {
        let port = silent_listener().await;
        let result = run(
            &Target {
                host: "localhost",
                server_name: None,
                port,
                kind: CheckKind::Tls,
                vetted: &["127.0.0.1".parse().unwrap()],
            },
            Duration::from_secs(2),
            Duration::from_secs(2),
        )
        .await;
        let error = result.expect_err("a silent listener cannot complete a handshake");
        assert!(
            error.starts_with("tls handshake timed out"),
            "the failure must be the deadline, got {error}"
        );
    }

    /// An IP literal is not a certificate name: the handshake presents no
    /// SNI, but it must not fail because of it.
    #[tokio::test]
    async fn tls_check_accepts_an_ip_literal_host() {
        let (port, seen) = tls_listener().await;
        let result = run(
            &Target {
                host: "203.0.113.10",
                server_name: None,
                port,
                kind: CheckKind::Tls,
                vetted: &["127.0.0.1".parse().unwrap()],
            },
            Duration::from_secs(2),
            Duration::from_secs(2),
        )
        .await;
        assert!(result.is_ok(), "expected a completed handshake: {result:?}");
        assert_eq!(seen.lock().unwrap().as_deref(), None);
    }

    /// An IP-literal host keeps the SNI the node carries: the address is
    /// not a certificate name, so the name comes from the node.
    #[tokio::test]
    async fn tls_check_keeps_the_sni_of_an_ip_literal_host() {
        let (port, seen) = tls_listener().await;
        let result = run(
            &Target {
                host: "203.0.113.10",
                server_name: Some("sni.example.com"),
                port,
                kind: CheckKind::Tls,
                vetted: &["127.0.0.1".parse().unwrap()],
            },
            Duration::from_secs(2),
            Duration::from_secs(2),
        )
        .await;
        assert!(result.is_ok(), "expected a completed handshake: {result:?}");
        assert_eq!(seen.lock().unwrap().as_deref(), Some("sni.example.com"));
    }

    #[tokio::test]
    async fn tls_check_reports_an_invalid_server_name() {
        let result = run(
            &Target {
                host: "not a name",
                server_name: None,
                port: 443,
                kind: CheckKind::Tls,
                vetted: &["127.0.0.1".parse().unwrap()],
            },
            Duration::from_secs(2),
            Duration::from_secs(2),
        )
        .await;
        let error = result.expect_err("an invalid name cannot be presented");
        assert!(
            error.starts_with("invalid TLS server name"),
            "the failure must name the server name, got {error}"
        );
    }

    /// Every vetted address is tried: a TLS failure on one of them does
    /// not stop the others, and the error is the one of the last attempt.
    #[tokio::test]
    async fn every_vetted_address_is_tried() {
        let (port, _) = tls_listener().await;
        let dead = std::net::SocketAddr::from(([127, 0, 0, 1], 1));
        let result = run(
            &Target {
                host: "localhost",
                server_name: None,
                port,
                kind: CheckKind::Tls,
                vetted: &[dead.ip(), "127.0.0.1".parse().unwrap()],
            },
            Duration::from_secs(2),
            Duration::from_secs(2),
        )
        .await;
        assert!(
            result.is_ok(),
            "the second address must be tried after the first failed: {result:?}"
        );
    }
}
