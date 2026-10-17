//! `InviteDialog::cancel_with_headers` adds headers (here a `Reason`, RFC
//! 3326) to the CANCEL, and the CANCEL goes where the INVITE went (RFC 3261
//! §9.1), also when that was `InviteOption::destination` rather than what
//! the Request-URI resolves to.
//!
//! The Request-URI names a `decoy` socket; the INVITE is sent to the `peer`
//! socket through `destination`. The CANCEL must reach the peer, never the
//! decoy.
use crate::dialog::{
    dialog::{DialogState, DialogStateReceiver},
    dialog_layer::DialogLayer,
    invitation::InviteOption,
};
use crate::sip::{prelude::HeadersExt, Header, Method, Request, SipMessage, Uri};
use crate::transport::{udp::UdpConnection, SipAddr, TransportLayer};
use crate::EndpointBuilder;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::mpsc::unbounded_channel;
use tokio_util::sync::CancellationToken;

const REASON: &str = "SIP;cause=200;text=\"Call completed elsewhere\"";
const WAIT: Duration = Duration::from_secs(2);

/// The next request on `socket` within `wait`, or `None`.
async fn next_request(socket: &UdpSocket, wait: Duration) -> Option<(Request, SocketAddr)> {
    let mut buf = vec![0u8; 4096];
    let deadline = tokio::time::Instant::now() + wait;
    loop {
        let (len, from) = tokio::time::timeout_at(deadline, socket.recv_from(&mut buf))
            .await
            .ok()?
            .expect("recv_from failed");
        let text = std::str::from_utf8(&buf[..len]).expect("non utf-8 SIP message");
        if let Ok(SipMessage::Request(req)) = SipMessage::try_from(text) {
            return Some((req, from));
        }
    }
}

async fn expect_request(socket: &UdpSocket, method: Method) -> (Request, SocketAddr) {
    loop {
        let (req, from) = next_request(socket, WAIT)
            .await
            .unwrap_or_else(|| panic!("timeout waiting for {method}"));
        if req.method == method {
            return (req, from);
        }
    }
}

async fn reply(socket: &UdpSocket, to: SocketAddr, req: &Request, code: u16) {
    let to_header = req.to_header().unwrap().value().to_string();
    let to_header = if to_header.contains(";tag=") {
        to_header
    } else {
        format!("{to_header};tag=peer-tag")
    };
    let resp = format!(
        "SIP/2.0 {code} Response\r\n\
         Via: {}\r\n\
         From: {}\r\n\
         To: {to_header}\r\n\
         Call-ID: {}\r\n\
         CSeq: {}\r\n\
         Contact: <sip:bob@{}>\r\n\
         Content-Length: 0\r\n\r\n",
        req.via_header().unwrap().value(),
        req.from_header().unwrap().value(),
        req.call_id_header().unwrap().value(),
        req.cseq_header().unwrap().value(),
        socket.local_addr().unwrap(),
    );
    socket.send_to(resp.as_bytes(), to).await.unwrap();
}

async fn wait_for_state(
    rx: &mut DialogStateReceiver,
    what: &str,
    pred: impl Fn(&DialogState) -> bool,
) {
    tokio::time::timeout(WAIT, async {
        loop {
            if pred(&rx.recv().await.expect("state channel closed")) {
                return;
            }
        }
    })
    .await
    .unwrap_or_else(|_| panic!("timeout waiting for {what}"))
}

struct Uac {
    dialog_layer: Arc<DialogLayer>,
    option: InviteOption,
    peer: UdpSocket,
    decoy: UdpSocket,
}

/// A UAC whose INVITE names the decoy in its Request-URI and is sent to the
/// peer by `destination`.
async fn setup(token: &CancellationToken) -> crate::Result<Uac> {
    let peer = UdpSocket::bind("127.0.0.1:0").await?;
    let decoy = UdpSocket::bind("127.0.0.1:0").await?;
    let transport_layer = TransportLayer::new(token.child_token());
    let udp = UdpConnection::create_connection(
        "127.0.0.1:0".parse().unwrap(),
        None,
        Some(token.child_token()),
    )
    .await?;
    let uac_addr = udp.get_addr().addr.clone();
    transport_layer.add_transport(udp.into());
    let endpoint = EndpointBuilder::new()
        .with_user_agent("rsipstack-test")
        .with_transport_layer(transport_layer)
        .with_cancel_token(token.child_token())
        .build();
    let endpoint_inner = endpoint.inner.clone();
    tokio::spawn(async move {
        let _ = endpoint_inner.serve().await;
    });
    let dialog_layer = Arc::new(DialogLayer::new(endpoint.inner.clone()));
    let option = InviteOption {
        caller: Uri::try_from("sip:alice@example.com")?,
        callee: Uri::try_from(format!("sip:bob@{}", decoy.local_addr()?).as_str())?,
        contact: Uri::try_from(format!("sip:alice@{uac_addr}").as_str())?,
        destination: Some(SipAddr::try_from(&Uri::try_from(
            format!("sip:{};transport=udp", peer.local_addr()?).as_str(),
        )?)?),
        ..Default::default()
    };
    Ok(Uac {
        dialog_layer,
        option,
        peer,
        decoy,
    })
}

fn reasons(req: &Request) -> Vec<String> {
    req.headers
        .iter()
        .filter_map(|h| match h {
            Header::Reason(r) => Some(r.value().to_string()),
            _ => None,
        })
        .collect()
}

/// `in_calling`: cancel before any response (the CANCEL waits for the 180),
/// else after the 180. `with_reason`: `cancel_with_headers` with a `Reason`,
/// else plain `cancel()`.
async fn run_cancel(in_calling: bool, with_reason: bool) -> crate::Result<()> {
    let token = CancellationToken::new();
    let Uac {
        dialog_layer,
        option,
        peer,
        decoy,
    } = setup(&token).await?;
    let (state_sender, mut states) = unbounded_channel();
    let (dialog, join) = dialog_layer.do_invite_async(option, state_sender)?;
    let (inv, uac) = expect_request(&peer, Method::Invite).await;
    assert!(
        inv.uri
            .to_string()
            .contains(&decoy.local_addr()?.to_string()),
        "the Request-URI names the decoy: {}",
        inv.uri
    );

    let headers = if with_reason {
        vec![Header::Reason(REASON.into())]
    } else {
        vec![]
    };
    let cancel = {
        let dialog = dialog.clone();
        move || async move {
            if with_reason {
                dialog.cancel_with_headers(headers).await
            } else {
                dialog.cancel().await
            }
        }
    };
    if in_calling {
        wait_for_state(&mut states, "Calling", |s| {
            matches!(s, DialogState::Calling(_))
        })
        .await;
        cancel().await?;
        reply(&peer, uac, &inv, 180).await;
    } else {
        reply(&peer, uac, &inv, 180).await;
        wait_for_state(&mut states, "Early", |s| {
            matches!(s, DialogState::Early(..))
        })
        .await;
        // In Early the call waits for the CANCEL's response.
        tokio::spawn(cancel());
    }

    let (cancel_req, _) = expect_request(&peer, Method::Cancel).await;
    assert_eq!(cancel_req.uri, inv.uri, "CANCEL Request-URI");
    assert_eq!(
        cancel_req.cseq_header()?.seq()?,
        inv.cseq_header()?.seq()?,
        "CANCEL CSeq number"
    );
    let expected: Vec<String> = if with_reason {
        vec![REASON.to_string()]
    } else {
        vec![]
    };
    assert_eq!(reasons(&cancel_req), expected, "Reason of the CANCEL");
    reply(&peer, uac, &cancel_req, 200).await;
    reply(&peer, uac, &inv, 487).await;
    expect_request(&peer, Method::Ack).await;

    let (_, resp) = tokio::time::timeout(WAIT, join)
        .await
        .expect("join")
        .expect("invite task")?;
    assert_eq!(resp.map(|r| u16::from(r.status_code)), Some(487));
    assert!(
        next_request(&decoy, Duration::from_millis(300))
            .await
            .is_none(),
        "nothing goes to the Request-URI's address"
    );
    token.cancel();
    Ok(())
}

#[tokio::test]
async fn test_cancel_with_reason_in_early_goes_to_the_invite_destination() -> crate::Result<()> {
    run_cancel(false, true).await
}

#[tokio::test]
async fn test_deferred_cancel_keeps_its_reason() -> crate::Result<()> {
    run_cancel(true, true).await
}

#[tokio::test]
async fn test_plain_cancel_goes_to_the_invite_destination() -> crate::Result<()> {
    run_cancel(false, false).await
}
