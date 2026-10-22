use crate::platform::CancellationToken;
use crate::sip::SipMessage;
use crate::transport::tcp_listener::accept_or_cancelled;
#[cfg(feature = "rustls")]
use crate::transport::tls::{ReloadableCertResolver, TlsConfig, TlsListenerConnection};
use crate::{
    transport::{
        connection::{TransportSender, KEEPALIVE_REQUEST, KEEPALIVE_RESPONSE},
        sip_addr::SipAddr,
        stream::StreamConnection,
        transport_layer::TransportLayerInnerRef,
        SipConnection, TransportEvent,
    },
    Result,
};
use core::sync::atomic::{AtomicU64, Ordering};
use core::time::Duration;
use futures_util::stream::{SplitSink, SplitStream};
use futures_util::{SinkExt, StreamExt};
use socket2::{Domain, Protocol, Socket, Type};
use std::{fmt, net::SocketAddr, sync::Arc};
use tokio::{
    net::{TcpListener, TcpStream},
    sync::Mutex,
};
use tokio_tungstenite::{
    connect_async,
    tungstenite::{
        client::IntoClientRequest,
        handshake::server::{ErrorResponse, Request, Response},
        protocol::Message,
    },
    MaybeTlsStream, WebSocketStream,
};
use tracing::{debug, info, warn};

/// A WebSocket over plain TCP, or over TLS that this side started as the
/// client (`MaybeTlsStream`).
type PlainWs = WebSocketStream<MaybeTlsStream<TcpStream>>;
/// A WebSocket over TLS that a secure listener accepted as the server.
#[cfg(feature = "rustls")]
type ServerTlsWs = WebSocketStream<tokio_rustls::server::TlsStream<TcpStream>>;

/// The sending half of a WebSocket connection. `MaybeTlsStream` has no
/// server-side TLS variant, so a connection a secure listener accepted
/// has a stream type of its own.
pub enum WsSink {
    Plain(SplitSink<PlainWs, Message>),
    #[cfg(feature = "rustls")]
    ServerTls(SplitSink<ServerTlsWs, Message>),
}

impl WsSink {
    pub async fn send(
        &mut self,
        msg: Message,
    ) -> core::result::Result<(), tokio_tungstenite::tungstenite::Error> {
        match self {
            WsSink::Plain(sink) => sink.send(msg).await,
            #[cfg(feature = "rustls")]
            WsSink::ServerTls(sink) => sink.send(msg).await,
        }
    }
}

impl From<SplitSink<PlainWs, Message>> for WsSink {
    fn from(sink: SplitSink<PlainWs, Message>) -> Self {
        WsSink::Plain(sink)
    }
}

/// The receiving half of a WebSocket connection (see [`WsSink`]).
pub enum WsRead {
    Plain(SplitStream<PlainWs>),
    #[cfg(feature = "rustls")]
    ServerTls(SplitStream<ServerTlsWs>),
}

impl WsRead {
    pub async fn next(
        &mut self,
    ) -> Option<core::result::Result<Message, tokio_tungstenite::tungstenite::Error>> {
        match self {
            WsRead::Plain(read) => read.next().await,
            #[cfg(feature = "rustls")]
            WsRead::ServerTls(read) => read.next().await,
        }
    }
}

impl From<SplitStream<PlainWs>> for WsRead {
    fn from(read: SplitStream<PlainWs>) -> Self {
        WsRead::Plain(read)
    }
}

/// How long a new connection to a WebSocket listener has for its TLS
/// handshake (secure listener) and its WebSocket upgrade together.
pub const DEFAULT_UPGRADE_TIMEOUT: Duration = Duration::from_secs(10);

/// Answers a client that asks for the `sip` subprotocol (RFC 7118) with it.
#[allow(clippy::result_large_err)] // tungstenite's callback signature
fn sip_subprotocol(
    req: &Request,
    mut response: Response,
) -> core::result::Result<Response, ErrorResponse> {
    if let Some(protocols) = req.headers().get("sec-websocket-protocol") {
        if let Ok(protocols_str) = protocols.to_str() {
            if protocols_str.contains("sip") {
                response
                    .headers_mut()
                    .insert("sec-websocket-protocol", "sip".parse().unwrap());
            }
        }
    }
    Ok(response)
}

// WebSocket Listener Connection Structure
pub struct WebSocketListenerConnectionInner {
    pub local_addr: SipAddr,
    pub external: Option<SipAddr>,
    pub is_secure: bool,
    /// The TLS a secure listener terminates itself (`new_tls`). `None` for
    /// a plain listener, and for a secure one whose TLS ends in front of
    /// it (a proxy): `is_secure` then only names the transport.
    #[cfg(feature = "rustls")]
    pub tls_config: Option<TlsConfig>,
    /// The acceptor's certificate resolver, for `reload_tls_config`; set
    /// when the listener starts.
    #[cfg(feature = "rustls")]
    pub cert_resolver: crate::platform::sync::Mutex<Option<Arc<ReloadableCertResolver>>>,
    /// Bound for the TLS handshake and WebSocket upgrade of a new
    /// connection, in milliseconds (see `set_upgrade_timeout`).
    pub upgrade_timeout_ms: AtomicU64,
}

#[derive(Clone)]
pub struct WebSocketListenerConnection {
    pub inner: Arc<WebSocketListenerConnectionInner>,
}

impl WebSocketListenerConnection {
    pub async fn new(
        local_addr: SocketAddr,
        external: Option<SocketAddr>,
        is_secure: bool,
    ) -> Result<Self> {
        let transport_type = if is_secure {
            crate::sip::transport::Transport::Wss
        } else {
            crate::sip::transport::Transport::Ws
        };

        let inner = WebSocketListenerConnectionInner {
            local_addr: SipAddr {
                r#type: Some(transport_type),
                addr: local_addr.into(),
            },
            external: external.map(|addr| SipAddr {
                r#type: Some(transport_type),
                addr: addr.into(),
            }),
            is_secure,
            #[cfg(feature = "rustls")]
            tls_config: None,
            #[cfg(feature = "rustls")]
            cert_resolver: crate::platform::sync::Mutex::new(None),
            upgrade_timeout_ms: AtomicU64::new(DEFAULT_UPGRADE_TIMEOUT.as_millis() as u64),
        };
        Ok(WebSocketListenerConnection {
            inner: Arc::new(inner),
        })
    }

    /// A secure WebSocket listener (`wss://`, transport `WSS`) that runs the
    /// TLS handshake itself with the certificate and key of `config`, like
    /// `TlsListenerConnection`; `reload_tls_config` replaces them for later
    /// handshakes.
    #[cfg(feature = "rustls")]
    pub async fn new_tls(
        local_addr: SocketAddr,
        external: Option<SocketAddr>,
        config: TlsConfig,
    ) -> Result<Self> {
        let transport_type = crate::sip::transport::Transport::Wss;
        let inner = WebSocketListenerConnectionInner {
            local_addr: SipAddr {
                r#type: Some(transport_type),
                addr: local_addr.into(),
            },
            external: external.map(|addr| SipAddr {
                r#type: Some(transport_type),
                addr: addr.into(),
            }),
            is_secure: true,
            tls_config: Some(config),
            cert_resolver: crate::platform::sync::Mutex::new(None),
            upgrade_timeout_ms: AtomicU64::new(DEFAULT_UPGRADE_TIMEOUT.as_millis() as u64),
        };
        Ok(WebSocketListenerConnection {
            inner: Arc::new(inner),
        })
    }

    /// Bounds the TLS handshake and WebSocket upgrade of every connection
    /// accepted from now on (default [`DEFAULT_UPGRADE_TIMEOUT`]); a client
    /// that has not completed both by then is closed.
    pub fn set_upgrade_timeout(&self, timeout: Duration) {
        let ms = u64::try_from(timeout.as_millis()).unwrap_or(u64::MAX);
        self.inner.upgrade_timeout_ms.store(ms, Ordering::Relaxed);
    }

    /// Replaces the certificate and key of a listener made with `new_tls`;
    /// handshakes from then on present the new pair, open connections keep
    /// theirs.
    #[cfg(feature = "rustls")]
    pub async fn reload_tls_config(&self, cert: Vec<u8>, key: Vec<u8>) -> Result<()> {
        let resolver = {
            let guard = self.inner.cert_resolver.lock();
            guard
                .as_ref()
                .ok_or_else(|| crate::Error::Error("No cert resolver available".to_string()))?
                .clone()
        };
        resolver
            .reload(&cert, &key)
            .map_err(|e| crate::Error::Error(e.to_string()))
    }

    pub async fn serve_listener(
        &self,
        transport_layer_inner: TransportLayerInnerRef,
    ) -> Result<()> {
        let local = self.inner.local_addr.get_socketaddr()?;
        let domain = if local.is_ipv6() {
            Domain::IPV6
        } else {
            Domain::IPV4
        };
        let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;
        if let Err(e) = socket.set_reuse_address(true) {
            warn!(error = %e, "failed to set SO_REUSEADDR on WebSocket listener");
        }
        socket.set_nonblocking(true)?;
        socket.bind(&local.into())?;
        socket.listen(128)?;
        let listener = TcpListener::from_std(socket.into())?;
        let transport_type = if self.inner.is_secure {
            crate::sip::transport::Transport::Wss
        } else {
            crate::sip::transport::Transport::Ws
        };
        let listener_local_addr = self.get_addr().clone();
        #[cfg(feature = "rustls")]
        let acceptor = match &self.inner.tls_config {
            Some(config) => {
                let (acceptor, resolver) = TlsListenerConnection::create_acceptor(config).await?;
                *self.inner.cert_resolver.lock() = Some(resolver);
                Some(acceptor)
            }
            None => None,
        };
        let listener_inner = self.inner.clone();

        debug!(local = %self.inner.local_addr, "Starting WebSocket listener");
        crate::platform::spawn(async move {
            loop {
                let (stream, remote_addr) =
                    match accept_or_cancelled(&listener, &transport_layer_inner.cancel_token).await
                    {
                        Some(Ok((stream, remote_addr))) => (stream, remote_addr),
                        Some(Err(e)) => {
                            warn!(error = ?e, "Failed to accept WebSocket connection");
                            continue;
                        }
                        None => {
                            debug!(local = %listener_local_addr, "WebSocket listener cancelled");
                            break;
                        }
                    };
                if !transport_layer_inner.is_whitelisted(remote_addr.ip()).await {
                    debug!(remote = %remote_addr, "websocket connection rejected by whitelist");
                    continue;
                }

                debug!(remote = %remote_addr, "New WebSocket connection");

                let remote_addr = SipAddr {
                    r#type: Some(transport_type),
                    addr: remote_addr.into(),
                };
                let transport_layer_inner_ref = transport_layer_inner.clone();
                let local_addr = listener_local_addr.clone();
                #[cfg(feature = "rustls")]
                let acceptor = acceptor.clone();
                let upgrade_timeout = Duration::from_millis(
                    listener_inner.upgrade_timeout_ms.load(Ordering::Relaxed),
                );
                crate::platform::spawn(async move {
                    let upgrade = async {
                        #[cfg(feature = "rustls")]
                        if let Some(acceptor) = acceptor {
                            let tls_stream = acceptor
                                .accept(stream)
                                .await
                                .map_err(|e| format!("TLS handshake failed: {}", e))?;
                            let ws =
                                tokio_tungstenite::accept_hdr_async(tls_stream, sip_subprotocol)
                                    .await
                                    .map_err(|e| format!("Error upgrading to WebSocket: {}", e))?;
                            let (sink, read) = ws.split();
                            return Ok((WsSink::ServerTls(sink), WsRead::ServerTls(read)));
                        }
                        let ws = tokio_tungstenite::accept_hdr_async(
                            MaybeTlsStream::Plain(stream),
                            sip_subprotocol,
                        )
                        .await
                        .map_err(|e| format!("Error upgrading to WebSocket: {}", e))?;
                        let (sink, read) = ws.split();
                        Ok::<_, String>((WsSink::from(sink), WsRead::from(read)))
                    };
                    let (ws_sink, ws_read) = match tokio::time::timeout(upgrade_timeout, upgrade)
                        .await
                    {
                        Ok(Ok(halves)) => halves,
                        Ok(Err(e)) => {
                            warn!(error = %e, remote = %remote_addr, "WebSocket connection not accepted");
                            return;
                        }
                        Err(_) => {
                            debug!(remote = %remote_addr, "WebSocket upgrade timed out");
                            return;
                        }
                    };

                    let connection = WebSocketConnection {
                        inner: Arc::new(WebSocketInner {
                            local_addr,
                            remote_addr,
                            ws_sink: Mutex::new(ws_sink),
                            ws_read: Mutex::new(Some(ws_read)),
                        }),
                        cancel_token: Some(transport_layer_inner_ref.cancel_token.child_token()),
                    };
                    let sip_connection = SipConnection::WebSocket(connection.clone());
                    let connection_addr = connection.get_addr().clone();
                    transport_layer_inner_ref.add_connection(sip_connection.clone());
                    info!(?connection_addr, "new websocket connection");
                });
            }
        });
        Ok(())
    }

    pub fn get_addr(&self) -> &SipAddr {
        if let Some(external) = &self.inner.external {
            external
        } else {
            &self.inner.local_addr
        }
    }

    pub async fn close(&self) -> Result<()> {
        Ok(())
    }
}

impl fmt::Display for WebSocketListenerConnection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let transport = if self.inner.is_secure { "WSS" } else { "WS" };
        write!(f, "{} Listener {}", transport, self.get_addr())
    }
}

impl fmt::Debug for WebSocketListenerConnection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

pub struct WebSocketInner {
    pub local_addr: SipAddr,
    pub remote_addr: SipAddr,
    pub ws_sink: Mutex<WsSink>,
    pub ws_read: Mutex<Option<WsRead>>,
}

#[derive(Clone)]
pub struct WebSocketConnection {
    pub inner: Arc<WebSocketInner>,
    pub cancel_token: Option<CancellationToken>,
}

impl WebSocketConnection {
    pub async fn connect(
        remote: &SipAddr,
        cancel_token: Option<CancellationToken>,
    ) -> Result<Self> {
        Self::connect_with_path(remote, None, cancel_token).await
    }

    /// Connect to a WebSocket server with an optional URL path.
    ///
    /// `path` defaults to `/` when `None` is passed, allowing callers to
    /// specify a custom path such as `/ws` for rustpbx-style endpoints.
    pub async fn connect_with_path(
        remote: &SipAddr,
        path: Option<&str>,
        cancel_token: Option<CancellationToken>,
    ) -> Result<Self> {
        let scheme = match remote.r#type {
            Some(crate::sip::transport::Transport::Wss) => "wss",
            _ => "ws",
        };

        let host = match &remote.addr.host {
            crate::sip::Host::Domain(domain) => domain.to_string(),
            crate::sip::Host::IpAddr(ip) => ip.to_string(),
        };

        let port = remote.addr.port.as_ref().map_or(5060, |p| p.value());
        let ws_path = path.unwrap_or("/");
        let url = format!("{}://{}:{}{}", scheme, host, port, ws_path);
        let mut request = url.into_client_request()?;
        request
            .headers_mut()
            .insert("sec-websocket-protocol", "sip".parse().unwrap());

        let (ws_stream, _) = connect_async(request).await?;
        let local_addr = SipAddr {
            r#type: Some(
                remote
                    .r#type
                    .unwrap_or(crate::sip::transport::Transport::Ws),
            ),
            addr: ws_stream.get_ref().get_ref().local_addr()?.into(),
        };
        let (ws_sink, ws_stream) = ws_stream.split();

        let connection = WebSocketConnection {
            inner: Arc::new(WebSocketInner {
                local_addr,
                remote_addr: remote.clone(),
                ws_sink: Mutex::new(ws_sink.into()),
                ws_read: Mutex::new(Some(ws_stream.into())),
            }),
            cancel_token,
        };

        debug!(
            local = %connection.get_addr(),
            remote = %remote,
            "Created WebSocket client connection"
        );

        Ok(connection)
    }
    pub fn cancel_token(&self) -> Option<CancellationToken> {
        self.cancel_token.clone()
    }
}

#[async_trait::async_trait]
impl StreamConnection for WebSocketConnection {
    fn get_addr(&self) -> &SipAddr {
        &self.inner.local_addr
    }

    fn get_remote_addr(&self) -> &SipAddr {
        &self.inner.remote_addr
    }

    async fn send_message(&self, msg: SipMessage) -> Result<()> {
        let data = msg.to_string();
        let mut sink = self.inner.ws_sink.lock().await;
        info!(dest = %self.inner.remote_addr, raw_message = ?data, "websocket send");
        sink.send(Message::Text(data.into())).await?;
        Ok(())
    }

    async fn send_raw(&self, data: &[u8]) -> Result<()> {
        let mut sink = self.inner.ws_sink.lock().await;
        sink.send(Message::Binary(data.to_vec().into())).await?;
        Ok(())
    }

    async fn serve_loop(&self, sender: TransportSender, idle_timeout: Duration) -> Result<()> {
        let sip_connection = SipConnection::WebSocket(self.clone());

        let remote_addr = self.inner.remote_addr.clone();
        let mut ws_read = match self.inner.ws_read.lock().await.take() {
            Some(ws_read) => ws_read,
            None => {
                warn!(src = %remote_addr, "WebSocket connection already closed");
                return Ok(());
            }
        };
        loop {
            let msg_opt = if idle_timeout.is_zero() {
                ws_read.next().await
            } else {
                match tokio::time::timeout(idle_timeout, ws_read.next()).await {
                    Ok(msg_opt) => msg_opt,
                    Err(_) => {
                        warn!(
                            src = %remote_addr,
                            idle_secs = idle_timeout.as_secs(),
                            "websocket idle timeout, closing connection"
                        );
                        break;
                    }
                }
            };
            let Some(msg) = msg_opt else {
                break;
            };
            match msg {
                Ok(Message::Text(text)) => {
                    info!(src = %remote_addr, raw_message = ?text.as_str(), "websocket message received");
                    match SipMessage::try_from(text.as_str()) {
                        Ok(sip_msg) => {
                            let remote_socket_addr = remote_addr.get_socketaddr()?;
                            let sip_msg = SipConnection::update_msg_received(
                                sip_msg,
                                remote_socket_addr,
                                remote_addr.r#type.unwrap_or_default(),
                            )?;

                            if let Err(e) = sender.send(TransportEvent::Incoming(
                                sip_msg,
                                sip_connection.clone(),
                                remote_addr.clone(),
                            )) {
                                warn!(error = ?e, src = %remote_addr, "Error sending incoming message");
                                break;
                            }
                        }
                        Err(e) => {
                            warn!(error = %e, src = %remote_addr, len = text.len(), "Error parsing SIP message");
                        }
                    }
                }
                Ok(Message::Binary(bin)) => {
                    if bin == *KEEPALIVE_REQUEST {
                        if let Err(e) = self.send_raw(KEEPALIVE_RESPONSE).await {
                            warn!(error = ?e, src = %remote_addr, "Error sending keepalive response");
                        }
                        continue;
                    }
                    debug!(src = %remote_addr, "websocket binary message received");
                    match SipMessage::try_from(bin) {
                        Ok(sip_msg) => {
                            if let Err(e) = sender.send(TransportEvent::Incoming(
                                sip_msg,
                                sip_connection.clone(),
                                remote_addr.clone(),
                            )) {
                                warn!(error = ?e, src = %remote_addr, "Error sending incoming message");
                                break;
                            }
                        }
                        Err(e) => {
                            warn!(error = %e, src = %remote_addr, "Error parsing SIP message from binary");
                        }
                    }
                }
                Ok(Message::Ping(data)) => {
                    let mut sink = self.inner.ws_sink.lock().await;
                    if let Err(e) = sink.send(Message::Pong(data)).await {
                        warn!(error = %e, src = %remote_addr, "Error sending pong");
                        break;
                    }
                }
                Ok(Message::Close(_)) => {
                    info!(src = %remote_addr, "WebSocket connection closed by peer");
                    break;
                }
                Err(e) => {
                    warn!(error = %e, src = %remote_addr, "WebSocket error");
                    break;
                }
                _ => {}
            }
        }

        info!(src = %remote_addr, "WebSocket serve_loop exiting");
        Ok(())
    }

    async fn close(&self) -> Result<()> {
        let mut sink = self.inner.ws_sink.lock().await;
        sink.send(Message::Close(None)).await?;
        Ok(())
    }
}

impl fmt::Display for WebSocketConnection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let transport = match self.inner.remote_addr.r#type {
            Some(crate::sip::transport::Transport::Wss) => "WSS",
            _ => "WS",
        };
        write!(
            f,
            "{} {} -> {}",
            transport, self.inner.local_addr, self.inner.remote_addr
        )
    }
}

impl fmt::Debug for WebSocketConnection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}
