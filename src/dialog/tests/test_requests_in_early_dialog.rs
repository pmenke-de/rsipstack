//! Requests other than the INVITE's own in an early dialog (RFC 3261 §12,
//! RFC 3311 §5.1): OPTIONS, INFO, MESSAGE and UPDATE reach the application
//! as in a confirmed dialog, on both roles, and get its response; the
//! dialog stays early.

use super::test_dialog_states::create_test_endpoint;
use crate::dialog::{
    dialog::{DialogInner, DialogState},
    invite_dialog::InviteDialog,
    DialogId,
};
use crate::sip::{headers::*, Method, Request, Response, SipMessage, StatusCode};
use crate::transaction::{
    key::{TransactionKey, TransactionRole},
    transaction::Transaction,
};
use crate::transport::{channel::ChannelConnection, SipAddr, SipConnection, TransportEvent};
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver};

const CALL_ID: &str = "early-dialog-requests";
const SDP: &[u8] = b"v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\nm=audio 4000 RTP/AVP 0\r\n";

struct Peer {
    endpoint: crate::transaction::endpoint::Endpoint,
    conn: SipConnection,
}

/// What the dialog sends to the peer.
type Wire = UnboundedReceiver<TransportEvent>;

impl Peer {
    async fn new() -> crate::Result<(Self, Wire)> {
        let endpoint = create_test_endpoint().await?;
        let (_in_tx, in_rx) = unbounded_channel();
        let (out_tx, wire) = unbounded_channel();
        let addr = SipAddr::from("127.0.0.1:5999".parse::<std::net::SocketAddr>().unwrap());
        let conn = ChannelConnection::create_connection(in_rx, out_tx, addr, None).await?;
        let peer = Self {
            endpoint,
            conn: SipConnection::Channel(conn),
        };
        Ok((peer, wire))
    }

    /// A request from the peer in the dialog; `from`/`to` are the tags as
    /// the peer writes them (its own first).
    fn request(&self, method: Method, cseq: u32, from: &str, to: &str, body: &[u8]) -> Transaction {
        let req = Request {
            method,
            uri: crate::sip::Uri::try_from("sip:us@127.0.0.1:5060").unwrap(),
            headers: vec![
                Via::new(format!(
                    "SIP/2.0/UDP 127.0.0.1:5999;branch=z9hG4bK-{}-{}",
                    method, cseq
                ))
                .into(),
                CSeq::new(format!("{} {}", cseq, method)).into(),
                From::new(format!("<sip:peer@127.0.0.1>;tag={}", from)).into(),
                To::new(format!("<sip:us@127.0.0.1>;tag={}", to)).into(),
                CallId::new(CALL_ID).into(),
                MaxForwards::new("70").into(),
            ]
            .into(),
            version: crate::sip::Version::V2,
            body: body.to_vec(),
        };
        let key = TransactionKey::from_request(&req, TransactionRole::Server).unwrap();
        Transaction::new_server(
            key,
            req,
            self.endpoint.inner.clone(),
            Some(self.conn.clone()),
        )
    }
}

fn invite(body: &[u8]) -> Request {
    Request {
        method: Method::Invite,
        uri: crate::sip::Uri::try_from("sip:callee@127.0.0.1:5060").unwrap(),
        headers: vec![
            Via::new("SIP/2.0/UDP 127.0.0.1:5998;branch=z9hG4bK-invite").into(),
            CSeq::new("1 INVITE").into(),
            From::new("<sip:caller@127.0.0.1>;tag=caller-tag").into(),
            To::new("<sip:callee@127.0.0.1>").into(),
            CallId::new(CALL_ID).into(),
            Contact::new("<sip:caller@127.0.0.1:5998>").into(),
            MaxForwards::new("70").into(),
        ]
        .into(),
        version: crate::sip::Version::V2,
        body: body.to_vec(),
    }
}

fn provisional(status: StatusCode, body: &[u8]) -> Response {
    Response {
        status_code: status,
        wire_reason: None,
        version: crate::sip::Version::V2,
        headers: vec![
            Via::new("SIP/2.0/UDP 127.0.0.1:5998;branch=z9hG4bK-invite").into(),
            CSeq::new("1 INVITE").into(),
            From::new("<sip:caller@127.0.0.1>;tag=caller-tag").into(),
            To::new("<sip:callee@127.0.0.1>;tag=callee-tag").into(),
            CallId::new(CALL_ID).into(),
            Contact::new("<sip:callee@127.0.0.1:5999>").into(),
        ]
        .into(),
        body: body.to_vec(),
    }
}

fn early_dialog(
    peer: &Peer,
    role: TransactionRole,
    invite_body: &[u8],
) -> crate::Result<(InviteDialog, UnboundedReceiver<DialogState>)> {
    let (state_sender, state_receiver) = unbounded_channel();
    let (tu_sender, _tu_receiver) = unbounded_channel();
    let (local_tag, remote_tag) = match role {
        TransactionRole::Server => ("callee-tag", "caller-tag"),
        TransactionRole::Client => ("caller-tag", "callee-tag"),
    };
    let id = DialogId {
        call_id: CALL_ID.to_string(),
        local_tag: local_tag.to_string(),
        remote_tag: remote_tag.to_string(),
    };
    let inner = DialogInner::new(
        role,
        id.clone(),
        invite(invite_body),
        peer.endpoint.inner.clone(),
        state_sender,
        None,
        None,
        tu_sender,
    )?;
    inner.transition(DialogState::Early(
        id,
        provisional(StatusCode::Ringing, b""),
    ));
    let dialog = InviteDialog::from_inner(Arc::new(inner));
    let mut receiver = state_receiver;
    // The Early notification itself.
    while receiver.try_recv().is_ok() {}
    Ok((dialog, receiver))
}

/// Runs `handle` for `tx`; when the dialog raises a request event, answers
/// it with `answer`. Returns the event's name (or `None`) and the status
/// sent to the peer (or `None`).
async fn exchange(
    dialog: &InviteDialog,
    states: &mut UnboundedReceiver<DialogState>,
    wire: &mut Wire,
    mut tx: Transaction,
    answer: StatusCode,
) -> (Option<&'static str>, Option<StatusCode>) {
    let mut d = dialog.clone();
    let task = tokio::spawn(async move { d.handle(&mut tx).await });
    let event = match tokio::time::timeout(Duration::from_millis(500), states.recv()).await {
        Ok(Some(DialogState::Options(_, _, h))) => Some(("Options", h)),
        Ok(Some(DialogState::Info(_, _, h))) => Some(("Info", h)),
        Ok(Some(DialogState::Message(_, _, h))) => Some(("Message", h)),
        Ok(Some(DialogState::Updated(_, _, h))) => Some(("Updated", h)),
        Ok(Some(other)) => panic!("unexpected dialog state {}", other),
        Ok(None) | Err(_) => None,
    };
    let name = event.as_ref().map(|(n, _)| *n);
    if let Some((_, handle)) = event {
        handle.reply(answer).await.expect("handle reply");
    }
    tokio::time::timeout(Duration::from_secs(5), task)
        .await
        .expect("handle() returned")
        .expect("handle task")
        .ok();
    let mut status = None;
    while let Ok(event) = wire.try_recv() {
        if let TransportEvent::Incoming(SipMessage::Response(resp), _, _) = event {
            status = Some(resp.status_code);
        }
    }
    (name, status)
}

#[tokio::test]
async fn uas_early_dialog_passes_requests_to_the_application() -> crate::Result<()> {
    let (peer, mut wire) = Peer::new().await?;
    let (dialog, mut states) = early_dialog(&peer, TransactionRole::Server, SDP)?;
    let req = |m, cseq, body: &[u8]| peer.request(m, cseq, "caller-tag", "callee-tag", body);

    for (method, cseq, body, event) in [
        (Method::Options, 2, &b""[..], "Options"),
        (Method::Info, 3, &b""[..], "Info"),
        (Method::Message, 4, &b"hello"[..], "Message"),
        (Method::Update, 5, SDP, "Updated"),
    ] {
        let (name, status) = exchange(
            &dialog,
            &mut states,
            &mut wire,
            req(method, cseq, body),
            StatusCode::OK,
        )
        .await;
        assert_eq!(name, Some(event), "{} raises {}", method, event);
        assert_eq!(status, Some(StatusCode::OK), "{} is answered", method);
        assert!(
            matches!(dialog.state(), DialogState::Early(..)),
            "{} leaves the dialog early, not {}",
            method,
            dialog.state()
        );
    }
    assert_eq!(dialog.inner.remote_seq.load(Ordering::Relaxed), 5);
    assert!(
        states.try_recv().is_err(),
        "no Confirmed after the requests"
    );

    // An older CSeq is discarded by the UAS, as in a confirmed dialog.
    let (name, status) = exchange(
        &dialog,
        &mut states,
        &mut wire,
        req(Method::Options, 4, b""),
        StatusCode::OK,
    )
    .await;
    assert_eq!((name, status), (None, None));
    Ok(())
}

#[tokio::test]
async fn uac_early_dialog_passes_requests_to_the_application() -> crate::Result<()> {
    let (peer, mut wire) = Peer::new().await?;
    let (dialog, mut states) = early_dialog(&peer, TransactionRole::Client, SDP)?;
    let req = |m, cseq, body: &[u8]| peer.request(m, cseq, "callee-tag", "caller-tag", body);

    for (method, cseq, body, event) in [
        (Method::Options, 1, &b""[..], "Options"),
        (Method::Info, 2, &b""[..], "Info"),
        (Method::Message, 3, &b"hello"[..], "Message"),
        // Without an offer: a session refresh needs no answer to ours.
        (Method::Update, 4, &b""[..], "Updated"),
    ] {
        let (name, status) = exchange(
            &dialog,
            &mut states,
            &mut wire,
            req(method, cseq, body),
            StatusCode::OK,
        )
        .await;
        assert_eq!(name, Some(event), "{} raises {}", method, event);
        assert_eq!(status, Some(StatusCode::OK), "{} is answered", method);
        assert!(matches!(dialog.state(), DialogState::Early(..)));
    }
    assert_eq!(dialog.inner.remote_seq.load(Ordering::Relaxed), 4);
    assert!(
        states.try_recv().is_err(),
        "no Confirmed after the requests"
    );
    Ok(())
}

#[tokio::test]
async fn uac_update_offer_before_the_answer_to_ours_is_491() -> crate::Result<()> {
    let (peer, mut wire) = Peer::new().await?;
    let (dialog, mut states) = early_dialog(&peer, TransactionRole::Client, SDP)?;
    let req = |m, cseq, body: &[u8]| peer.request(m, cseq, "callee-tag", "caller-tag", body);

    // A 180 without SDP: the offer in our INVITE has no answer yet.
    dialog
        .inner
        .handle_provisional_response(&provisional(StatusCode::Ringing, b""))
        .await?;
    let (name, status) = exchange(
        &dialog,
        &mut states,
        &mut wire,
        req(Method::Update, 1, SDP),
        StatusCode::OK,
    )
    .await;
    assert_eq!(name, None, "the application does not see the UPDATE");
    assert_eq!(status, Some(StatusCode::RequestPending));

    // The answer arrives in a 183; a new offer is taken now.
    dialog
        .inner
        .handle_provisional_response(&provisional(StatusCode::SessionProgress, SDP))
        .await?;
    let (name, status) = exchange(
        &dialog,
        &mut states,
        &mut wire,
        req(Method::Update, 2, SDP),
        StatusCode::OK,
    )
    .await;
    assert_eq!(name, Some("Updated"));
    assert_eq!(status, Some(StatusCode::OK));
    Ok(())
}

#[tokio::test]
async fn uac_without_an_offer_in_the_invite_takes_an_update_offer() -> crate::Result<()> {
    let (peer, mut wire) = Peer::new().await?;
    let (dialog, mut states) = early_dialog(&peer, TransactionRole::Client, b"")?;
    let req = |m, cseq, body: &[u8]| peer.request(m, cseq, "callee-tag", "caller-tag", body);
    let (name, status) = exchange(
        &dialog,
        &mut states,
        &mut wire,
        req(Method::Update, 1, SDP),
        StatusCode::OK,
    )
    .await;
    assert_eq!(name, Some("Updated"));
    assert_eq!(status, Some(StatusCode::OK));
    Ok(())
}

#[tokio::test]
async fn role_dialogs_pass_early_requests_too() -> crate::Result<()> {
    use crate::dialog::{client_dialog::ClientInviteDialog, server_dialog::ServerInviteDialog};
    let (peer, mut wire) = Peer::new().await?;

    let (dialog, mut states) = early_dialog(&peer, TransactionRole::Server, SDP)?;
    let mut server = ServerInviteDialog {
        inner: dialog.inner.clone(),
    };
    let mut tx = peer.request(Method::Info, 2, "caller-tag", "callee-tag", b"");
    let task = tokio::spawn(async move { server.handle(&mut tx).await });
    match tokio::time::timeout(Duration::from_millis(500), states.recv()).await {
        Ok(Some(DialogState::Info(_, _, h))) => h.reply(StatusCode::OK).await.unwrap(),
        _ => panic!("ServerInviteDialog raises no Info in an early dialog"),
    }
    task.await.unwrap()?;

    let (dialog, mut states) = early_dialog(&peer, TransactionRole::Client, SDP)?;
    let mut client = ClientInviteDialog::from_inner(dialog.inner.clone());
    let mut tx = peer.request(Method::Update, 1, "callee-tag", "caller-tag", SDP);
    client.handle(&mut tx).await?;
    assert!(
        states.try_recv().is_err(),
        "the UPDATE does not reach the application"
    );
    let mut status = None;
    while let Ok(event) = wire.try_recv() {
        if let TransportEvent::Incoming(SipMessage::Response(resp), _, _) = event {
            status = Some(resp.status_code);
        }
    }
    assert_eq!(status, Some(StatusCode::RequestPending));
    Ok(())
}
