//! What is no fault is not logged at WARN: a certificate reload that
//! worked, and a TLS peer that closes its connection without `close_notify`
//! (a phone that quits).
use super::test_tls_reload::generate_test_cert;
use crate::transport::{TlsConfig, TlsListenerConnection, TransportLayer};
use crate::Result;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio_util::sync::CancellationToken;
use tracing::{field::Field, span, Event, Level, Metadata, Subscriber};

/// Records every event as (level, " field=value ...").
#[derive(Clone, Default)]
struct Capture(Arc<Mutex<Vec<(Level, String)>>>);

impl Subscriber for Capture {
    fn enabled(&self, _: &Metadata<'_>) -> bool {
        true
    }
    fn new_span(&self, _: &span::Attributes<'_>) -> span::Id {
        span::Id::from_u64(1)
    }
    fn record(&self, _: &span::Id, _: &span::Record<'_>) {}
    fn record_follows_from(&self, _: &span::Id, _: &span::Id) {}
    fn event(&self, event: &Event<'_>) {
        let mut line = String::new();
        event.record(&mut |f: &Field, v: &dyn std::fmt::Debug| {
            line.push_str(&format!(" {}={:?}", f.name(), v))
        });
        self.0
            .lock()
            .unwrap()
            .push((*event.metadata().level(), line));
    }
    fn enter(&self, _: &span::Id) {}
    fn exit(&self, _: &span::Id) {}
}

impl Capture {
    fn count(&self, needle: &str) -> usize {
        let records = self.0.lock().unwrap();
        records.iter().filter(|(_, s)| s.contains(needle)).count()
    }
    fn has(&self, level: Level, needle: &str) -> bool {
        let records = self.0.lock().unwrap();
        records
            .iter()
            .any(|(l, s)| *l == level && s.contains(needle))
    }
}

async fn tls_listener(
    cancel: &CancellationToken,
) -> Result<(TransportLayer, TlsListenerConnection, std::net::SocketAddr)> {
    let (cert, key) = generate_test_cert("localhost")?;
    // A free port; the listener binds with SO_REUSEADDR.
    let addr = {
        let probe = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        probe.local_addr()?
    };
    let transport_layer = TransportLayer::new(cancel.clone());
    let listener = TlsListenerConnection::new(
        addr,
        None,
        TlsConfig {
            cert: Some(cert.into_bytes()),
            key: Some(key.into_bytes()),
            ..Default::default()
        },
    )
    .await?;
    listener
        .serve_listener(transport_layer.inner.clone())
        .await?;
    Ok((transport_layer, listener, addr))
}

#[tokio::test]
async fn test_tls_reload_is_logged_at_info() -> Result<()> {
    let capture = Capture::default();
    let _guard = tracing::subscriber::set_default(capture.clone());
    let cancel = CancellationToken::new();
    let (_layer, listener, _) = tls_listener(&cancel).await?;

    let (cert, key) = generate_test_cert("localhost")?;
    listener
        .reload_tls_config(cert.into_bytes(), key.into_bytes())
        .await?;

    assert!(capture.has(Level::INFO, "TLS certificate reloaded"));
    assert!(
        !capture.has(Level::WARN, "TLS certificate reloaded"),
        "a reload that worked is no warning"
    );
    cancel.cancel();
    Ok(())
}

#[tokio::test]
async fn test_tls_peer_close_without_close_notify_is_not_a_warning() -> Result<()> {
    use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
    use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
    use rustls::{DigitallySignedStruct, SignatureScheme};

    /// Accepts the test's self-signed certificate.
    #[derive(Debug)]
    struct AcceptAny(Vec<SignatureScheme>);

    impl ServerCertVerifier for AcceptAny {
        fn verify_server_cert(
            &self,
            _: &CertificateDer<'_>,
            _: &[CertificateDer<'_>],
            _: &ServerName<'_>,
            _: &[u8],
            _: UnixTime,
        ) -> std::result::Result<ServerCertVerified, rustls::Error> {
            Ok(ServerCertVerified::assertion())
        }
        fn verify_tls12_signature(
            &self,
            _: &[u8],
            _: &CertificateDer<'_>,
            _: &DigitallySignedStruct,
        ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
            Ok(HandshakeSignatureValid::assertion())
        }
        fn verify_tls13_signature(
            &self,
            _: &[u8],
            _: &CertificateDer<'_>,
            _: &DigitallySignedStruct,
        ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
            Ok(HandshakeSignatureValid::assertion())
        }
        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            self.0.clone()
        }
    }

    let capture = Capture::default();
    let _guard = tracing::subscriber::set_default(capture.clone());
    let cancel = CancellationToken::new();
    let (_layer, _listener, addr) = tls_listener(&cancel).await?;

    // TLS 1.2: the handshake leaves nothing unread, the close is a FIN
    // (UnexpectedEof on the listener). TLS 1.3: the listener's session
    // tickets are still unread, the close is a reset (ConnectionReset).
    for version in [&rustls::version::TLS12, &rustls::version::TLS13] {
        let provider = rustls::ServerConfig::builder().crypto_provider().clone();
        let schemes = provider
            .signature_verification_algorithms
            .supported_schemes();
        let mut config = rustls::ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(&[version])
            .map_err(|e| crate::Error::Error(e.to_string()))?
            .with_root_certificates(rustls::RootCertStore::empty())
            .with_no_client_auth();
        config
            .dangerous()
            .set_certificate_verifier(Arc::new(AcceptAny(schemes)));
        let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
        let tcp = tokio::net::TcpStream::connect(addr).await?;
        let tls = connector
            .connect(ServerName::try_from("localhost").unwrap(), tcp)
            .await?;
        let before = capture.count("serve_loop exited");
        // Close the TCP connection under the session, without close_notify.
        let (tcp, _) = tls.into_inner();
        drop(tcp);

        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        while capture.count("serve_loop exited") == before {
            assert!(
                tokio::time::Instant::now() < deadline,
                "the listener never saw the close ({:?})",
                version.version
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert!(
            !capture.has(Level::WARN, "Error reading from stream"),
            "a peer that closes without close_notify is no warning ({:?}): {:?}",
            version.version,
            capture.0.lock().unwrap()
        );
    }
    assert!(capture.has(Level::DEBUG, "Error reading from stream"));
    cancel.cancel();
    Ok(())
}
