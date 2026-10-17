use crate::{
    platform::CancellationToken,
    transport::{
        SipConnection, TcpListenerConnection, TransportLayer, WebSocketListenerConnection,
    },
    Result,
};
use std::{net::SocketAddr, time::Duration};

/// Test new TcpListenerConnection API
#[tokio::test]
async fn test_tcp_listener_connection_api() -> Result<()> {
    // Create TCP listener connection with a specific port to avoid conflicts
    let socket_addr: std::net::SocketAddr = "127.0.0.1:0".parse()?;
    let tcp_listener = TcpListenerConnection::new(socket_addr, None).await?;

    // Get the address (should be the same as input since we don't bind in new())
    let bound_addr = tcp_listener.get_addr().clone();

    println!(
        "Successfully created TCP listener using new API: {:?}",
        bound_addr
    );

    // Test that we can get the address
    assert_eq!(
        bound_addr.r#type,
        Some(crate::sip::transport::Transport::Tcp)
    );
    assert_eq!(bound_addr.addr.host.to_string(), "127.0.0.1");

    Ok(())
}

/// Test new WebSocketListenerConnection API
#[cfg(feature = "websocket")]
#[tokio::test]
async fn test_websocket_listener_connection_api() -> Result<()> {
    // Create WebSocket listener connection
    let socket_addr: std::net::SocketAddr = "127.0.0.1:0".parse()?;
    let ws_listener = WebSocketListenerConnection::new(socket_addr, None, false).await?;

    // Get the address (should be the same as input since we don't bind in new())
    let bound_addr = ws_listener.get_addr().clone();

    println!(
        "Successfully created WebSocket listener using new API: {:?}",
        bound_addr
    );

    // Test that we can get the address
    assert_eq!(
        bound_addr.r#type,
        Some(crate::sip::transport::Transport::Ws)
    );
    assert_eq!(bound_addr.addr.host.to_string(), "127.0.0.1");

    let wss_listener = WebSocketListenerConnection::new(socket_addr, None, true).await?;
    assert_eq!(
        wss_listener.get_addr().r#type,
        Some(crate::sip::transport::Transport::Wss)
    );

    Ok(())
}

/// Reserves a free loopback port (listeners bind lazily in `serve_listens`).
fn free_port() -> SocketAddr {
    let probe = std::net::TcpListener::bind("127.0.0.1:0").expect("bind probe");
    probe.local_addr().expect("probe addr")
}

/// The accept loop must stop when the transport layer is cancelled, closing the
/// listening socket even while the `TransportLayer` itself is still alive.
async fn assert_listener_closed_on_cancel(listener: SipConnection, addr: SocketAddr) {
    let cancel = CancellationToken::new();
    let transport_layer = TransportLayer::new(cancel.clone());
    transport_layer.add_transport(listener);
    transport_layer
        .serve_listens()
        .await
        .expect("serve listeners");
    tokio::net::TcpStream::connect(addr)
        .await
        .expect("listener accepts before cancel");

    cancel.cancel();
    for _ in 0..50 {
        if tokio::net::TcpStream::connect(addr).await.is_err() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("listener on {addr} still accepting after cancel");
}

#[tokio::test]
async fn test_tcp_listener_closed_on_cancel() -> Result<()> {
    let addr = free_port();
    let listener = TcpListenerConnection::new(addr, None).await?;
    assert_listener_closed_on_cancel(listener.into(), addr).await;
    Ok(())
}

#[cfg(feature = "websocket")]
#[tokio::test]
async fn test_websocket_listener_closed_on_cancel() -> Result<()> {
    let addr = free_port();
    let listener = WebSocketListenerConnection::new(addr, None, false).await?;
    assert_listener_closed_on_cancel(listener.into(), addr).await;
    Ok(())
}

#[cfg(feature = "rustls")]
#[tokio::test]
async fn test_tls_listener_closed_on_cancel() -> Result<()> {
    use crate::transport::{TlsConfig, TlsListenerConnection};

    let (cert, key) = super::test_tls_reload::generate_test_cert("localhost")?;
    let config = TlsConfig {
        cert: Some(cert.into_bytes()),
        key: Some(key.into_bytes()),
        ..Default::default()
    };
    let addr = free_port();
    let listener = TlsListenerConnection::new(addr, None, config).await?;
    assert_listener_closed_on_cancel(listener.into(), addr).await;
    Ok(())
}

/// Dropping a clone of a `TransportLayer` must leave the layer running: only
/// the last clone cancels it.
#[tokio::test]
async fn test_dropping_a_clone_keeps_the_layer_running() -> Result<()> {
    let addr = free_port();
    let cancel = CancellationToken::new();
    let transport_layer = TransportLayer::new(cancel.clone());
    transport_layer.add_transport(TcpListenerConnection::new(addr, None).await?.into());
    transport_layer.serve_listens().await?;

    let clone = transport_layer.clone();
    drop(clone);
    assert!(
        !cancel.is_cancelled(),
        "dropping a clone cancelled the layer"
    );
    tokio::net::TcpStream::connect(addr)
        .await
        .expect("listener accepts after a clone was dropped");

    // A clone that outlives the original keeps the layer running, too.
    let survivor = transport_layer.clone();
    drop(transport_layer);
    assert!(
        !cancel.is_cancelled(),
        "dropping the original cancelled the layer"
    );
    tokio::net::TcpStream::connect(addr)
        .await
        .expect("listener accepts while a clone is alive");

    // The last clone shuts the layer down.
    drop(survivor);
    assert!(
        cancel.is_cancelled(),
        "dropping the last clone left the layer running"
    );
    for _ in 0..50 {
        if tokio::net::TcpStream::connect(addr).await.is_err() {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("listener on {addr} still accepting after the last clone was dropped");
}
