//! A request the callee sends in an early client dialog (an UPDATE after
//! its 180, RFC 3311) must be matched to that dialog. The dialog layer
//! keeps an early client dialog under its initial key, without the remote
//! tag, until the INVITE's final response; the request carries the tag the
//! dialog learned from the provisional response, so the lookup by the
//! request's full id missed and the application could only answer 481.
use crate::dialog::{
    dialog::DialogState, dialog_layer::DialogLayer, invitation::InviteOption, DialogId,
};
use crate::sip::{prelude::HeadersExt, Method, Request, Response, SipMessage, StatusCode, Uri};
use crate::transport::{udp::UdpConnection, TransportLayer};
use crate::EndpointBuilder;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::mpsc::unbounded_channel;
use tokio_util::sync::CancellationToken;

const PEER_TAG: &str = "peer-tag";

async fn recv_request(socket: &UdpSocket, method: Method) -> (Request, SocketAddr) {
    let mut buf = vec![0u8; 4096];
    loop {
        let (len, from) = tokio::time::timeout(Duration::from_secs(2), socket.recv_from(&mut buf))
            .await
            .unwrap_or_else(|_| panic!("timeout waiting for {method}"))
            .expect("recv_from failed");
        let text = std::str::from_utf8(&buf[..len]).expect("non utf-8 SIP message");
        if let Ok(SipMessage::Request(req)) = SipMessage::try_from(text) {
            if req.method == method {
                return (req, from);
            }
        }
    }
}

async fn recv_response(socket: &UdpSocket, cseq: &str) -> Response {
    let mut buf = vec![0u8; 4096];
    loop {
        let (len, _) = tokio::time::timeout(Duration::from_secs(2), socket.recv_from(&mut buf))
            .await
            .unwrap_or_else(|_| panic!("timeout waiting for the response to {cseq}"))
            .expect("recv_from failed");
        let text = std::str::from_utf8(&buf[..len]).expect("non utf-8 SIP message");
        if let Ok(SipMessage::Response(resp)) = SipMessage::try_from(text) {
            if resp.cseq_header().unwrap().value() == cseq {
                return resp;
            }
        }
    }
}

fn response(req: &Request, code: u16, reason: &str, contact: &str) -> String {
    let to = req.to_header().unwrap().value().to_string();
    let to = if to.contains(";tag=") {
        to
    } else {
        format!("{to};tag={PEER_TAG}")
    };
    format!(
        "SIP/2.0 {code} {reason}\r\n\
         Via: {}\r\n\
         From: {}\r\n\
         To: {to}\r\n\
         Call-ID: {}\r\n\
         CSeq: {}\r\n\
         Contact: <{contact}>\r\n\
         Content-Length: 0\r\n\r\n",
        req.via_header().unwrap().value(),
        req.from_header().unwrap().value(),
        req.call_id_header().unwrap().value(),
        req.cseq_header().unwrap().value(),
    )
}

async fn reply(socket: &UdpSocket, to: SocketAddr, req: &Request, code: u16, reason: &str) {
    let contact = format!("sip:bob@{}", socket.local_addr().unwrap());
    socket
        .send_to(response(req, code, reason, &contact).as_bytes(), to)
        .await
        .expect("send_to failed");
}

/// An in-dialog request from the peer, as the callee of `invite` would
/// send it: From carries `from_tag`, To the caller's tag.
fn in_dialog_request(
    invite: &Request,
    uac: SocketAddr,
    peer: SocketAddr,
    from_tag: &str,
    cseq: u32,
    method: &str,
) -> String {
    let from_tag_of_invite = invite.from_header().unwrap().tag().unwrap().unwrap();
    format!(
        "{method} sip:alice@{uac} SIP/2.0\r\n\
         Via: SIP/2.0/UDP {peer};branch=z9hG4bK-{method}-{cseq}\r\n\
         Max-Forwards: 70\r\n\
         From: <sip:bob@{peer}>;tag={from_tag}\r\n\
         To: <sip:alice@example.com>;tag={local}\r\n\
         Call-ID: {call_id}\r\n\
         CSeq: {cseq} {method}\r\n\
         Content-Length: 0\r\n\r\n",
        local = from_tag_of_invite.value(),
        call_id = invite.call_id_header().unwrap().value(),
    )
}

#[tokio::test]
async fn test_request_in_early_client_dialog_is_matched() -> crate::Result<()> {
    let token = CancellationToken::new();
    let peer = UdpSocket::bind("127.0.0.1:0").await?;
    let peer_port = peer.local_addr()?.port();
    let peer_addr = peer.local_addr()?;

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
    let dialog_layer = std::sync::Arc::new(DialogLayer::new(endpoint.inner.clone()));

    // The application: a matched in-dialog request is answered 200 with the
    // matched dialog's id in a header, an unmatched one 481.
    let mut incoming = endpoint.incoming_transactions()?;
    let pump_layer = DialogLayer {
        endpoint: dialog_layer.endpoint.clone(),
        inner: dialog_layer.inner.clone(),
    };
    tokio::spawn(async move {
        while let Some(mut tx) = incoming.recv().await {
            match pump_layer.match_dialog(&tx) {
                Some(dialog) => {
                    let matched = crate::sip::Header::Other(
                        "X-Matched-Dialog".to_string(),
                        dialog.id().to_string(),
                    );
                    let _ = tx.reply_with(StatusCode::OK, vec![matched], None).await;
                }
                None => {
                    let _ = tx.reply(StatusCode::CallTransactionDoesNotExist).await;
                }
            }
        }
    });

    let (state_sender, mut states) = unbounded_channel();
    let invite_option = InviteOption {
        caller: Uri::try_from("sip:alice@example.com")?,
        callee: Uri::try_from(format!("sip:bob@127.0.0.1:{peer_port};transport=udp").as_str())?,
        contact: Uri::try_from(format!("sip:alice@{uac_addr}").as_str())?,
        ..Default::default()
    };
    let (dialog, invite) = dialog_layer.do_invite_async(invite_option, state_sender)?;

    let (invite_req, uac) = recv_request(&peer, Method::Invite).await;
    reply(&peer, uac, &invite_req, 180, "Ringing").await;
    // Wait until the dialog is early and knows the peer's tag.
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if matches!(states.recv().await, Some(DialogState::Early(..))) {
                break;
            }
        }
    })
    .await
    .expect("timeout waiting for Early");
    let expected = DialogId {
        call_id: invite_req.call_id_header()?.value().to_string(),
        local_tag: invite_req
            .from_header()?
            .tag()?
            .unwrap()
            .value()
            .to_string(),
        remote_tag: PEER_TAG.to_string(),
    };
    assert_eq!(
        dialog.id(),
        expected,
        "the dialog learned the peer's tag from the 180"
    );

    // The callee's UPDATE in the early dialog is matched to it.
    let update = in_dialog_request(&invite_req, uac, peer_addr, PEER_TAG, 1, "UPDATE");
    peer.send_to(update.as_bytes(), uac).await?;
    let resp = recv_response(&peer, "1 UPDATE").await;
    assert_eq!(
        resp.status_code,
        StatusCode::OK,
        "the UPDATE reached the dialog"
    );
    let matched = resp
        .headers
        .iter()
        .find_map(|h| match h {
            crate::sip::Header::Other(name, value) if name == "X-Matched-Dialog" => {
                Some(value.clone())
            }
            _ => None,
        })
        .expect("the application names the matched dialog");
    assert_eq!(matched, expected.to_string());

    // A request with another remote tag is no part of this dialog.
    let other = in_dialog_request(&invite_req, uac, peer_addr, "other-tag", 2, "UPDATE");
    peer.send_to(other.as_bytes(), uac).await?;
    let resp = recv_response(&peer, "2 UPDATE").await;
    assert_eq!(resp.status_code, StatusCode::CallTransactionDoesNotExist);

    // Finish the call so the dialog ends cleanly.
    reply(&peer, uac, &invite_req, 200, "OK").await;
    recv_request(&peer, Method::Ack).await;
    let (confirmed, _) = invite.await.expect("do_invite_async task panicked")?;
    assert_eq!(confirmed, expected);
    assert!(dialog.state().is_confirmed());
    token.cancel();
    Ok(())
}
