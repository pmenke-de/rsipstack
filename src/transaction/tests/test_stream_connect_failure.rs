//! A request whose stream connection (TCP, TLS, WS) cannot be opened, for
//! example because the TLS handshake fails, is a transport error: the TU
//! gets a local 503 at once (RFC 3261 §8.1.3.1) and decides when to try
//! again. Timer A must not open a new connection for it on every tick.
use crate::sip::{headers::*, Method, SipMessage, StatusCode};
use crate::transaction::endpoint::EndpointOption;
use crate::transaction::key::{TransactionKey, TransactionRole};
use crate::transaction::transaction::Transaction;
use crate::transaction::EndpointBuilder;
use crate::transport::{udp::UdpConnection, TransportLayer};
use crate::Result;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;

fn register(peer: std::net::SocketAddr, transport: &str) -> Result<crate::sip::Request> {
    let uri = crate::sip::Uri::try_from(format!("sip:{};transport={}", peer, transport).as_str())?;
    Ok(crate::sip::Request {
        method: Method::Register,
        uri,
        headers: vec![
            Via::new(format!(
                "SIP/2.0/{} 127.0.0.1:5060;branch=z9hG4bK-connect-failure",
                transport.to_uppercase()
            ))
            .into(),
            CSeq::new("1 REGISTER").into(),
            From::new("<sip:alice@127.0.0.1>;tag=connect-failure").into(),
            To::new("<sip:alice@127.0.0.1>").into(),
            CallId::new("connect-failure@127.0.0.1").into(),
            MaxForwards::new("70").into(),
        ]
        .into(),
        version: crate::sip::Version::V2,
        body: vec![],
    })
}

/// A peer that accepts every TCP connection and closes it at once, so a
/// TLS handshake on it fails. Returns its address and the accept count.
async fn closing_peer() -> Result<(std::net::SocketAddr, Arc<AtomicUsize>)> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let accepted = Arc::new(AtomicUsize::new(0));
    let count = accepted.clone();
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            count.fetch_add(1, Ordering::SeqCst);
            drop(stream);
        }
    });
    Ok((addr, accepted))
}

async fn build_endpoint() -> Result<crate::transaction::endpoint::Endpoint> {
    let token = CancellationToken::new();
    let tl = TransportLayer::new(token.child_token());
    let udp = UdpConnection::create_connection("127.0.0.1:0".parse()?, None, None).await?;
    tl.add_transport(udp.into());
    Ok(EndpointBuilder::new()
        .with_user_agent("rsipstack-test")
        .with_transport_layer(tl)
        .with_option(EndpointOption::default())
        .build())
}

/// The final response the TU sees within `limit`, if any.
async fn final_status(tx: &mut Transaction, limit: Duration) -> Option<StatusCode> {
    tokio::time::timeout(limit, async {
        while let Some(msg) = tx.receive().await {
            if let SipMessage::Response(resp) = msg {
                if resp.status_code.kind() != crate::sip::StatusCodeKind::Provisional {
                    return Some(resp.status_code);
                }
            }
        }
        None
    })
    .await
    .unwrap_or(None)
}

/// REGISTER over TLS to a peer whose handshake fails: one connection
/// attempt and a 503 for the TU, not a new handshake on every Timer A
/// tick until Timer F.
#[cfg(feature = "rustls")]
#[tokio::test]
async fn test_failed_tls_handshake_is_reported_once() -> Result<()> {
    let endpoint = build_endpoint().await?;
    let (peer, accepted) = closing_peer().await?;
    let inner = endpoint.inner.clone();

    let client = async move {
        let req = register(peer, "tls")?;
        let key = TransactionKey::from_request(&req, TransactionRole::Client)?;
        let mut tx = Transaction::new_client(key, req, inner, None);
        tx.send().await?;
        let started = tokio::time::Instant::now();
        let status = final_status(&mut tx, Duration::from_secs(8)).await;
        let reported_after = started.elapsed();
        // Keep the transaction alive for the rest of the eight seconds:
        // whatever Timer A would do, it does now.
        tokio::time::sleep_until(started + Duration::from_secs(8)).await;
        Ok::<_, crate::Error>((status, reported_after))
    };

    let (status, reported_after) = tokio::select! {
        r = client => r?,
        _ = endpoint.serve() => panic!("endpoint stopped"),
    };
    let attempts = accepted.load(Ordering::SeqCst);
    assert_eq!(
        status,
        Some(StatusCode::ServiceUnavailable),
        "the failed handshake is reported to the TU as 503"
    );
    assert!(
        reported_after < Duration::from_secs(1),
        "the 503 comes at once, not after {:?}",
        reported_after
    );
    assert_eq!(
        attempts, 1,
        "one handshake in eight seconds, not one per Timer A tick ({} seen)",
        attempts
    );
    Ok(())
}

/// The same for TCP: a refused connection is reported at once.
#[tokio::test]
async fn test_refused_tcp_connection_is_reported_at_once() -> Result<()> {
    let endpoint = build_endpoint().await?;
    // A port nobody listens on.
    let peer = {
        let probe = TcpListener::bind("127.0.0.1:0").await?;
        probe.local_addr()?
    };
    let inner = endpoint.inner.clone();
    let client = async move {
        let req = register(peer, "tcp")?;
        let key = TransactionKey::from_request(&req, TransactionRole::Client)?;
        let mut tx = Transaction::new_client(key, req, inner, None);
        tx.send().await?;
        Ok::<_, crate::Error>(final_status(&mut tx, Duration::from_secs(2)).await)
    };
    let status = tokio::select! {
        r = client => r?,
        _ = endpoint.serve() => panic!("endpoint stopped"),
    };
    assert_eq!(status, Some(StatusCode::ServiceUnavailable));
    Ok(())
}
