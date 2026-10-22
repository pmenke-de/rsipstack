//! A secure WebSocket listener that terminates TLS itself (`new_tls`):
//! a client's TLS handshake and WebSocket upgrade, SIP in both directions
//! over the connection, a certificate reload, and the upgrade timeout.
use super::test_tls_reload::generate_test_cert;
use crate::sip::{SipMessage, StatusCode, Transport};
use crate::transport::{TlsConfig, TransportLayer, WebSocketListenerConnection};
use crate::{EndpointBuilder, Result};
use futures_util::{SinkExt, StreamExt};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::AsyncReadExt;
use tokio_tungstenite::tungstenite::{self, Message};
use tokio_util::sync::CancellationToken;

/// Accepts any certificate and records the one the server presented.
#[derive(Debug)]
struct Recorder {
    seen: Mutex<Option<CertificateDer<'static>>>,
    schemes: Vec<SignatureScheme>,
}

impl ServerCertVerifier for Recorder {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        _: UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        *self.seen.lock().unwrap() = Some(end_entity.clone().into_owned());
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
        self.schemes.clone()
    }
}

type ClientWs =
    tokio_tungstenite::WebSocketStream<tokio_rustls::client::TlsStream<tokio::net::TcpStream>>;

/// TLS to `addr`, then the WebSocket upgrade asking for `sip`. Returns the
/// WebSocket, the certificate the server presented and the client's
/// address.
async fn wss_client(addr: SocketAddr) -> Result<(ClientWs, CertificateDer<'static>, SocketAddr)> {
    let provider = rustls::ServerConfig::builder().crypto_provider().clone();
    let recorder = Arc::new(Recorder {
        seen: Mutex::new(None),
        schemes: provider
            .signature_verification_algorithms
            .supported_schemes(),
    });
    let mut config = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| crate::Error::Error(e.to_string()))?
        .with_root_certificates(rustls::RootCertStore::empty())
        .with_no_client_auth();
    config
        .dangerous()
        .set_certificate_verifier(recorder.clone());
    let tcp = tokio::net::TcpStream::connect(addr).await?;
    let me = tcp.local_addr()?;
    let tls = tokio_rustls::TlsConnector::from(Arc::new(config))
        .connect(ServerName::try_from("localhost").unwrap(), tcp)
        .await?;
    let request = tungstenite::http::Request::builder()
        .uri(format!("wss://localhost:{}/", addr.port()))
        .header("Host", format!("localhost:{}", addr.port()))
        .header("Connection", "Upgrade")
        .header("Upgrade", "websocket")
        .header("Sec-WebSocket-Version", "13")
        .header(
            "Sec-WebSocket-Key",
            tungstenite::handshake::client::generate_key(),
        )
        .header("Sec-WebSocket-Protocol", "sip")
        .body(())
        .unwrap();
    let (ws, response) = tokio_tungstenite::client_async(request, tls).await?;
    assert_eq!(
        response.headers().get("sec-websocket-protocol").unwrap(),
        "sip"
    );
    let seen = recorder.seen.lock().unwrap().clone().unwrap();
    Ok((ws, seen, me))
}

fn free_port() -> SocketAddr {
    let probe = std::net::TcpListener::bind("127.0.0.1:0").expect("bind probe");
    probe.local_addr().expect("probe addr")
}

#[tokio::test]
async fn test_wss_listener_terminates_tls() -> Result<()> {
    let (cert1, key1) = generate_test_cert("before.example.com")?;
    let (cert2, key2) = generate_test_cert("after.example.com")?;
    let der1 = CertificateDer::from_pem_slice(cert1.as_bytes()).unwrap();
    let der2 = CertificateDer::from_pem_slice(cert2.as_bytes()).unwrap();

    let addr = free_port();
    let listener = WebSocketListenerConnection::new_tls(
        addr,
        Some("203.0.113.5:8443".parse()?),
        TlsConfig {
            cert: Some(cert1.into_bytes()),
            key: Some(key1.into_bytes()),
            ..Default::default()
        },
    )
    .await?;
    assert_eq!(listener.get_addr().to_string(), "WSS 203.0.113.5:8443");

    let cancel = CancellationToken::new();
    let transport_layer = TransportLayer::new(cancel.clone());
    transport_layer.add_transport(listener.clone().into());
    let endpoint = EndpointBuilder::new()
        .with_cancel_token(cancel.clone())
        .with_transport_layer(transport_layer)
        .build();
    let mut incoming = endpoint.incoming_transactions()?;
    let inner = endpoint.inner.clone();
    tokio::spawn(async move { endpoint.serve().await });

    // The listener starts with the endpoint; wait until it accepts.
    let mut client = None;
    for _ in 0..50 {
        if let Ok(c) = wss_client(addr).await {
            client = Some(c);
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let (mut ws, presented, me) = client.expect("no WSS connection");
    assert_eq!(presented, der1);

    let register = "REGISTER sip:example.com SIP/2.0\r\n\
         Via: SIP/2.0/WSS df7jal23ls0d.invalid;branch=z9hG4bKwss1\r\n\
         Max-Forwards: 70\r\nFrom: <sip:alice@example.com>;tag=a\r\n\
         To: <sip:alice@example.com>\r\nCall-ID: wss1\r\nCSeq: 1 REGISTER\r\n\
         Contact: <sip:alice@df7jal23ls0d.invalid;transport=ws>\r\n\
         Content-Length: 0\r\n\r\n";
    ws.send(Message::Text(register.into())).await?;
    let mut tx = tokio::time::timeout(Duration::from_secs(5), incoming.recv())
        .await
        .expect("no REGISTER within 5 s")
        .expect("incoming closed");
    let connection = tx.connection.clone().expect("connection");
    assert_eq!(connection.get_addr().to_string(), "WSS 203.0.113.5:8443");
    let from = connection.get_remote_addr().expect("remote").clone();
    assert_eq!(from.r#type, Some(Transport::Wss));
    assert_eq!(from.get_socketaddr()?, me);

    // The answer goes back over the TLS WebSocket.
    tx.reply(StatusCode::OK).await?;
    let answer = tokio::time::timeout(Duration::from_secs(5), ws.next())
        .await
        .expect("no answer within 5 s")
        .expect("closed")?;
    let answer = SipMessage::try_from(answer.to_text()?)?;
    assert!(
        matches!(&answer, SipMessage::Response(r) if r.status_code == StatusCode::OK),
        "{answer}"
    );
    // And the transport layer finds the connection to reach the client.
    let (found, _) = inner.transport_layer.lookup(&from, None).await?;
    assert_eq!(found.get_remote_addr(), Some(&from));

    // A reload reaches the next handshake; the open connection stays.
    listener
        .reload_tls_config(cert2.into_bytes(), key2.into_bytes())
        .await?;
    let (_second, presented, _) = wss_client(addr).await?;
    assert_eq!(presented, der2);
    ws.send(Message::Ping(Vec::new().into())).await?;

    cancel.cancel();
    Ok(())
}

#[tokio::test]
async fn test_wss_listener_closes_a_silent_client() -> Result<()> {
    let (cert, key) = generate_test_cert("localhost")?;
    let addr = free_port();
    let listener = WebSocketListenerConnection::new_tls(
        addr,
        None,
        TlsConfig {
            cert: Some(cert.into_bytes()),
            key: Some(key.into_bytes()),
            ..Default::default()
        },
    )
    .await?;
    listener.set_upgrade_timeout(Duration::from_millis(300));
    let cancel = CancellationToken::new();
    let transport_layer = TransportLayer::new(cancel.clone());
    listener
        .serve_listener(transport_layer.inner.clone())
        .await?;

    // Connects and sends nothing: no TLS ClientHello, no upgrade.
    let mut silent = tokio::net::TcpStream::connect(addr).await?;
    let started = tokio::time::Instant::now();
    let mut buf = [0u8; 16];
    let closed = tokio::time::timeout(Duration::from_secs(5), silent.read(&mut buf))
        .await
        .expect("the listener keeps a silent client open");
    assert!(matches!(closed, Ok(0) | Err(_)), "{closed:?}");
    assert!(started.elapsed() >= Duration::from_millis(250));
    cancel.cancel();
    Ok(())
}

/// A listener made with `new` keeps serving plain `ws://`, also when it is
/// flagged secure (TLS ended in front of it).
#[tokio::test]
async fn test_plain_listener_still_upgrades_without_tls() -> Result<()> {
    for secure in [false, true] {
        let addr = free_port();
        let listener = WebSocketListenerConnection::new(addr, None, secure).await?;
        let cancel = CancellationToken::new();
        let transport_layer = TransportLayer::new(cancel.clone());
        listener
            .serve_listener(transport_layer.inner.clone())
            .await?;
        let mut request = format!("ws://127.0.0.1:{}/", addr.port())
            .into_client_request()
            .unwrap();
        request
            .headers_mut()
            .insert("sec-websocket-protocol", "sip".parse().unwrap());
        let (_ws, response) = tokio_tungstenite::connect_async(request).await?;
        assert_eq!(
            response.headers().get("sec-websocket-protocol").unwrap(),
            "sip"
        );
        cancel.cancel();
    }
    Ok(())
}

use tungstenite::client::IntoClientRequest;
