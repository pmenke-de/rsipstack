//! RFC 3262 §3 on the UAS side: reliable provisional responses carry
//! `Require: 100rel` and `RSeq`, are retransmitted until the matching PRACK
//! arrives, hold back a 2xx while one with a body is unacknowledged, and end
//! the INVITE with a 500 when no PRACK comes within 64*T1.
use crate::dialog::{
    dialog::{Dialog, DialogState, DialogStateReceiver, TerminatedReason},
    dialog_layer::DialogLayer,
    invite_dialog::InviteDialog,
};
use crate::sip::{prelude::HeadersExt, Method, Response, SipMessage, StatusCode};
use crate::transaction::endpoint::EndpointOption;
use crate::transport::{udp::UdpConnection, TransportLayer};
use crate::EndpointBuilder;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver};
use tokio_util::sync::CancellationToken;

const CALL_ID: &str = "uas-prack-test";
const FROM_TAG: &str = "uac-tag";
const T1: Duration = Duration::from_millis(20);
const T1X64: Duration = Duration::from_millis(64 * 20);
const SDP: &str = "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\n";

/// A raw UAC peer.
struct Peer {
    socket: UdpSocket,
    uas: SocketAddr,
}

impl Peer {
    async fn send_request(
        &self,
        method: Method,
        cseq: u32,
        to_tag: Option<&str>,
        extra: &str,
        body: &str,
    ) {
        let addr = self.socket.local_addr().unwrap();
        let to = match to_tag {
            Some(tag) => format!("<sip:bob@{}>;tag={tag}", self.uas),
            None => format!("<sip:bob@{}>", self.uas),
        };
        // A CANCEL takes the branch of the INVITE it cancels.
        let branch = match method {
            Method::Cancel => format!("z9hG4bK-INVITE-{cseq}"),
            _ => format!("z9hG4bK-{method}-{cseq}"),
        };
        let msg = format!(
            "{method} sip:bob@{uas} SIP/2.0\r\n\
             Via: SIP/2.0/UDP {addr};branch={branch}\r\n\
             Max-Forwards: 70\r\n\
             From: <sip:alice@{addr}>;tag={FROM_TAG}\r\n\
             To: {to}\r\n\
             Call-ID: {CALL_ID}\r\n\
             CSeq: {cseq} {method}\r\n\
             Contact: <sip:alice@{addr}>\r\n\
             {extra}Content-Length: {}\r\n\r\n{body}",
            body.len(),
            uas = self.uas,
        );
        self.socket.send_to(msg.as_bytes(), self.uas).await.unwrap();
    }

    async fn invite(&self, extra: &str) {
        self.send_request(Method::Invite, 1, None, extra, "").await;
    }

    async fn prack(&self, cseq: u32, to_tag: &str, rack: &str, body: &str) {
        let mut extra = format!("RAck: {rack}\r\n");
        if !body.is_empty() {
            extra.push_str("Content-Type: application/sdp\r\n");
        }
        self.send_request(Method::PRack, cseq, Some(to_tag), &extra, body)
            .await;
    }

    /// Every response the UAS sends until `deadline`, with arrival times.
    async fn collect(&self, deadline: Instant) -> Vec<(Instant, Response)> {
        let mut out = Vec::new();
        let mut buf = vec![0u8; 4096];
        loop {
            let now = Instant::now();
            if now >= deadline {
                return out;
            }
            let Ok(Ok((len, _))) =
                tokio::time::timeout(deadline - now, self.socket.recv_from(&mut buf)).await
            else {
                return out;
            };
            let text = std::str::from_utf8(&buf[..len]).unwrap();
            if let Ok(SipMessage::Response(resp)) = SipMessage::try_from(text) {
                out.push((Instant::now(), resp));
            }
        }
    }

    /// The next response with `code` to `method`, within a second.
    async fn expect(&self, code: u16, method: Method) -> Response {
        let deadline = Instant::now() + Duration::from_secs(1);
        let mut buf = vec![0u8; 4096];
        loop {
            let now = Instant::now();
            assert!(now < deadline, "timeout waiting for {code} to {method}");
            let Ok(Ok((len, _))) =
                tokio::time::timeout(deadline - now, self.socket.recv_from(&mut buf)).await
            else {
                panic!("timeout waiting for {code} to {method}");
            };
            let text = std::str::from_utf8(&buf[..len]).unwrap();
            if let Ok(SipMessage::Response(resp)) = SipMessage::try_from(text) {
                if resp.status_code.code() == code && cseq_method(&resp) == method {
                    return resp;
                }
            }
        }
    }
}

fn cseq_method(resp: &Response) -> Method {
    resp.cseq_header().unwrap().method().unwrap()
}

fn to_tag(resp: &Response) -> String {
    resp.to_header()
        .unwrap()
        .tag()
        .unwrap()
        .unwrap()
        .value()
        .to_string()
}

fn short_timers() -> EndpointOption {
    EndpointOption {
        t1: T1,
        t4: T1 * 10,
        t1x64: T1X64,
        ..Default::default()
    }
}

/// A UAS endpoint with short timers, running the usual incoming-transaction
/// loop; the first INVITE's dialog is handed out through the receiver.
async fn setup(
    token: &CancellationToken,
) -> crate::Result<(DialogStateReceiver, UnboundedReceiver<InviteDialog>, Peer)> {
    let transport_layer = TransportLayer::new(token.child_token());
    let udp = UdpConnection::create_connection(
        "127.0.0.1:0".parse().unwrap(),
        None,
        Some(token.child_token()),
    )
    .await?;
    let uas: SocketAddr = udp.get_addr().get_socketaddr()?;
    transport_layer.add_transport(udp.into());
    let endpoint = EndpointBuilder::new()
        .with_user_agent("rsipstack-test")
        .with_transport_layer(transport_layer)
        .with_cancel_token(token.child_token())
        .with_option(short_timers())
        .build();
    let dialog_layer = Arc::new(DialogLayer::new(endpoint.inner.clone()));
    let mut incoming = endpoint.incoming_transactions()?;
    let endpoint_inner = endpoint.inner.clone();
    tokio::spawn(async move {
        let _ = endpoint_inner.serve().await;
    });

    let (state_sender, states) = unbounded_channel();
    let (dialog_sender, dialogs) = unbounded_channel();
    tokio::spawn(async move {
        while let Some(mut tx) = incoming.recv().await {
            let has_to_tag = tx.original.to_header().unwrap().tag().unwrap().is_some();
            let dialog = if has_to_tag {
                dialog_layer.match_dialog(&tx)
            } else if tx.original.method == Method::Invite {
                let dialog = dialog_layer
                    .get_or_create_server_invite(&tx, state_sender.clone(), None, None)
                    .expect("server dialog");
                dialog_sender.send(dialog.clone()).unwrap();
                Some(Dialog::Invite(dialog))
            } else {
                None
            };
            if let Some(mut dialog) = dialog {
                tokio::spawn(async move {
                    let _ = dialog.handle(&mut tx).await;
                });
            }
        }
    });

    let peer = Peer {
        socket: UdpSocket::bind("127.0.0.1:0").await?,
        uas,
    };
    Ok((states, dialogs, peer))
}

/// Drop every state, as an application that does not look at `Prack` does;
/// the dropped handle lets the library answer the PRACK itself.
fn drain(mut states: DialogStateReceiver) {
    tokio::spawn(async move { while states.recv().await.is_some() {} });
}

async fn next_dialog(dialogs: &mut UnboundedReceiver<InviteDialog>) -> InviteDialog {
    tokio::time::timeout(Duration::from_secs(2), dialogs.recv())
        .await
        .expect("timeout waiting for the server dialog")
        .unwrap()
}

fn rseq(resp: &Response) -> u32 {
    resp.rseq_value()
        .expect("a reliable provisional carries RSeq")
}

/// The next `DialogState::Prack`, skipping other states.
async fn next_prack(states: &mut DialogStateReceiver) -> DialogState {
    loop {
        let state = tokio::time::timeout(Duration::from_secs(1), states.recv())
            .await
            .expect("timeout waiting for the PRACK event")
            .expect("state channel open");
        if matches!(state, DialogState::Prack(..)) {
            return state;
        }
    }
}

#[tokio::test]
async fn reliable_180_carries_require_and_rseq_and_rseq_increments() -> crate::Result<()> {
    let token = CancellationToken::new();
    let (mut states, mut dialogs, peer) = setup(&token).await?;
    peer.invite("Supported: 100rel\r\n").await;
    let dialog = next_dialog(&mut dialogs).await;
    assert!(dialog.supports_100rel());
    assert!(!dialog.requires_100rel());

    dialog.ringing_reliable(None, None)?;
    let first = peer.expect(180, Method::Invite).await;
    assert!(first.header_contains_token("Require", "100rel"));
    let first_rseq = rseq(&first);
    assert!((1..=0x7fff_ffff).contains(&first_rseq));
    assert!(matches!(dialog.state(), DialogState::Early(..)));

    // RFC 3262 §3: no second reliable 1xx before the first is acknowledged.
    assert!(dialog.ringing_reliable(None, None).is_err());

    let tag = to_tag(&first);
    peer.prack(2, &tag, &format!("{first_rseq} 1 INVITE"), "")
        .await;
    match next_prack(&mut states).await {
        DialogState::Prack(id, req, _handle) => {
            assert_eq!(id, dialog.id());
            assert_eq!(req.rack_value(), Some((first_rseq, 1, Method::Invite)));
        }
        _ => unreachable!(),
    }
    // The handle was dropped without a reply: the library answers 200.
    peer.expect(200, Method::PRack).await;

    dialog.reliable_provisional(StatusCode::SessionProgress, None, None)?;
    let second = peer.expect(183, Method::Invite).await;
    assert_eq!(rseq(&second), first_rseq + 1, "RSeq grows by exactly one");
    peer.prack(3, &tag, &format!("{} 1 INVITE", first_rseq + 1), "")
        .await;
    next_prack(&mut states).await;
    peer.expect(200, Method::PRack).await;

    token.cancel();
    Ok(())
}

#[tokio::test]
async fn reliable_1xx_is_retransmitted_until_the_prack() -> crate::Result<()> {
    let token = CancellationToken::new();
    let (states, mut dialogs, peer) = setup(&token).await?;
    drain(states);
    peer.invite("Supported: 100rel\r\n").await;
    let dialog = next_dialog(&mut dialogs).await;

    let sent = Instant::now();
    dialog.ringing_reliable(None, None)?;
    // Original, then T1 and 2*T1 later: at 0, T1, 3*T1 (next at 7*T1).
    let ringing: Vec<(Instant, Response)> = peer
        .collect(sent + T1 * 5)
        .await
        .into_iter()
        .filter(|(_, r)| r.status_code.code() == 180)
        .collect();
    assert!(
        ringing.len() >= 3,
        "the reliable 180 must be retransmitted at T1 and 2*T1, got {} copies",
        ringing.len()
    );
    assert!(ringing.iter().all(|(_, r)| rseq(r) == rseq(&ringing[0].1)));
    let gaps: Vec<Duration> = ringing.windows(2).map(|w| w[1].0 - w[0].0).collect();
    assert!(
        gaps[1] + T1 / 2 >= gaps[0] * 2 - T1 / 2,
        "the retransmission interval doubles: {gaps:?}"
    );

    let first = &ringing[0].1;
    peer.prack(2, &to_tag(first), &format!("{} 1 INVITE", rseq(first)), "")
        .await;
    let acked = Instant::now();
    let after = peer.collect(acked + T1 * 16).await;
    assert!(after
        .iter()
        .any(|(_, r)| r.status_code.code() == 200 && cseq_method(r) == Method::PRack));
    assert!(
        !after
            .iter()
            .any(|(at, r)| r.status_code.code() == 180 && *at > acked + T1),
        "no retransmission after the matching PRACK"
    );

    token.cancel();
    Ok(())
}

#[tokio::test]
async fn prack_that_matches_nothing_gets_481() -> crate::Result<()> {
    let token = CancellationToken::new();
    let (mut states, mut dialogs, peer) = setup(&token).await?;
    peer.invite("Supported: 100rel\r\n").await;
    let dialog = next_dialog(&mut dialogs).await;

    dialog.ringing_reliable(None, None)?;
    let ringing = peer.expect(180, Method::Invite).await;
    let tag = to_tag(&ringing);
    let rseq = rseq(&ringing);

    // Wrong RSeq, wrong CSeq number, wrong method.
    for (cseq, rack) in [
        (2, format!("{} 1 INVITE", rseq + 1)),
        (3, format!("{rseq} 7 INVITE")),
        (4, format!("{rseq} 1 UPDATE")),
    ] {
        peer.prack(cseq, &tag, &rack, "").await;
        peer.expect(481, Method::PRack).await;
    }
    // The 180 is still unacknowledged: the matching PRACK is answered.
    peer.prack(5, &tag, &format!("{rseq} 1 INVITE"), "").await;
    next_prack(&mut states).await;
    peer.expect(200, Method::PRack).await;
    // Acknowledged once: a repeated PRACK matches nothing any more.
    peer.prack(6, &tag, &format!("{rseq} 1 INVITE"), "").await;
    peer.expect(481, Method::PRack).await;

    token.cancel();
    Ok(())
}

/// RFC 3262 §5: a PRACK with an offer is answered by the application in the
/// 2xx to the PRACK.
#[tokio::test]
async fn prack_with_body_is_answered_through_the_handle() -> crate::Result<()> {
    let token = CancellationToken::new();
    let (mut states, mut dialogs, peer) = setup(&token).await?;
    peer.invite("Supported: 100rel\r\n").await;
    let dialog = next_dialog(&mut dialogs).await;

    dialog.ringing_reliable(None, None)?;
    let ringing = peer.expect(180, Method::Invite).await;
    peer.prack(
        2,
        &to_tag(&ringing),
        &format!("{} 1 INVITE", rseq(&ringing)),
        SDP,
    )
    .await;
    let DialogState::Prack(_, req, handle) = next_prack(&mut states).await else {
        unreachable!()
    };
    assert_eq!(req.body, SDP.as_bytes());
    handle
        .respond(
            StatusCode::OK,
            Some(vec![crate::sip::Header::ContentType(
                "application/sdp".into(),
            )]),
            Some(b"answer".to_vec()),
        )
        .await
        .unwrap();
    let ok = peer.expect(200, Method::PRack).await;
    assert_eq!(ok.body, b"answer");

    token.cancel();
    Ok(())
}

/// RFC 3262 §3: a 2xx must wait while a reliable 1xx with a session
/// description is unacknowledged.
#[tokio::test]
async fn accept_after_reliable_183_with_sdp_waits_for_the_prack() -> crate::Result<()> {
    let token = CancellationToken::new();
    let (mut states, mut dialogs, peer) = setup(&token).await?;
    peer.invite("Supported: 100rel\r\n").await;
    let dialog = next_dialog(&mut dialogs).await;

    dialog.ringing_reliable(None, Some(SDP.as_bytes().to_vec()))?;
    let progress = peer.expect(183, Method::Invite).await;
    assert_eq!(progress.body, SDP.as_bytes());

    dialog.accept(None, None)?;
    let held = peer.collect(Instant::now() + T1 * 4).await;
    assert!(
        !held.iter().any(|(_, r)| r.status_code.code() == 200),
        "the 2xx must wait for the PRACK"
    );
    assert!(matches!(dialog.state(), DialogState::Early(..)));

    peer.prack(
        2,
        &to_tag(&progress),
        &format!("{} 1 INVITE", rseq(&progress)),
        "",
    )
    .await;
    next_prack(&mut states).await;
    peer.expect(200, Method::PRack).await;
    peer.expect(200, Method::Invite).await;
    assert!(dialog.state().waiting_ack());

    token.cancel();
    Ok(())
}

/// Without a body, the reliable 1xx does not hold the 2xx; the 2xx stops
/// its retransmission and a late PRACK is still answered (RFC 3262 §3).
#[tokio::test]
async fn accept_after_reliable_180_without_body_goes_at_once() -> crate::Result<()> {
    let token = CancellationToken::new();
    let (states, mut dialogs, peer) = setup(&token).await?;
    drain(states);
    peer.invite("Supported: 100rel\r\n").await;
    let dialog = next_dialog(&mut dialogs).await;

    dialog.ringing_reliable(None, None)?;
    let ringing = peer.expect(180, Method::Invite).await;
    dialog.accept(None, None)?;
    let accepted = Instant::now();
    let after = peer.collect(accepted + T1 * 8).await;
    assert!(after.iter().any(|(_, r)| r.status_code.code() == 200));
    assert!(
        !after
            .iter()
            .any(|(at, r)| r.status_code.code() == 180 && *at > accepted + T1),
        "the final response stops the retransmission"
    );
    peer.prack(
        2,
        &to_tag(&ringing),
        &format!("{} 1 INVITE", rseq(&ringing)),
        "",
    )
    .await;
    peer.expect(200, Method::PRack).await;

    token.cancel();
    Ok(())
}

#[tokio::test]
async fn no_prack_within_64_t1_rejects_the_invite_with_500() -> crate::Result<()> {
    let token = CancellationToken::new();
    let (mut states, mut dialogs, peer) = setup(&token).await?;
    peer.invite("Require: 100rel\r\n").await;
    let dialog = next_dialog(&mut dialogs).await;
    assert!(dialog.supports_100rel());
    assert!(dialog.requires_100rel());

    let sent = Instant::now();
    dialog.ringing_reliable(None, Some(SDP.as_bytes().to_vec()))?;
    dialog.accept(None, None)?;
    let messages = peer.collect(sent + T1X64 + T1 * 16).await;

    let (rejected_at, _) = messages
        .iter()
        .find(|(_, r)| r.status_code.code() == 500 && cseq_method(r) == Method::Invite)
        .expect("the INVITE must be rejected with 500 after 64*T1 without PRACK");
    assert!(
        *rejected_at - sent >= T1X64 - T1,
        "rejected too early, after {:?}",
        *rejected_at - sent
    );
    assert!(
        !messages.iter().any(|(_, r)| r.status_code.code() == 200),
        "the held 2xx must not be sent"
    );
    let copies = messages
        .iter()
        .filter(|(_, r)| r.status_code.code() == 183)
        .count();
    assert!(
        (5..=8).contains(&copies),
        "T1 doubling without cap up to 64*T1 sends 7 copies, got {copies}"
    );

    let mut terminated = None;
    while let Ok(state) = states.try_recv() {
        if let DialogState::Terminated(_, reason) = state {
            terminated = Some(reason);
        }
    }
    assert!(
        matches!(terminated, Some(TerminatedReason::Timeout)),
        "got {terminated:?}"
    );

    token.cancel();
    Ok(())
}

#[tokio::test]
async fn reliable_provisional_needs_100rel_in_the_invite() -> crate::Result<()> {
    let token = CancellationToken::new();
    let (_states, mut dialogs, peer) = setup(&token).await?;
    peer.invite("").await;
    let dialog = next_dialog(&mut dialogs).await;

    assert!(!dialog.supports_100rel());
    assert!(dialog.ringing_reliable(None, None).is_err());
    assert!(dialog
        .reliable_provisional(StatusCode::Trying, None, None)
        .is_err());

    // The plain variant is unchanged: no Require, no RSeq, no retransmission.
    let sent = Instant::now();
    dialog.ringing(None, None)?;
    let ringing: Vec<_> = peer
        .collect(sent + T1 * 6)
        .await
        .into_iter()
        .filter(|(_, r)| r.status_code.code() == 180)
        .collect();
    assert_eq!(ringing.len(), 1);
    let ringing = &ringing[0].1;
    assert!(!ringing.header_contains_token("Require", "100rel"));
    assert_eq!(ringing.rseq_value(), None);
    assert!(matches!(dialog.state(), DialogState::Early(..)));

    token.cancel();
    Ok(())
}

/// A CANCEL ends the INVITE with 487 and stops the retransmission.
#[tokio::test]
async fn cancel_stops_the_retransmission() -> crate::Result<()> {
    let token = CancellationToken::new();
    let (states, mut dialogs, peer) = setup(&token).await?;
    drain(states);
    peer.invite("Supported: 100rel\r\n").await;
    let dialog = next_dialog(&mut dialogs).await;

    dialog.ringing_reliable(None, None)?;
    peer.expect(180, Method::Invite).await;
    peer.send_request(Method::Cancel, 1, None, "", "").await;
    peer.expect(487, Method::Invite).await;
    let cancelled = Instant::now();
    let after = peer.collect(cancelled + T1 * 16).await;
    assert!(
        !after
            .iter()
            .any(|(at, r)| r.status_code.code() == 180 && *at > cancelled + T1),
        "no retransmission after the INVITE ended"
    );
    assert!(dialog.state().is_terminated());

    token.cancel();
    Ok(())
}

/// An rsipstack UAC with `support_prack` PRACKs the reliable 183 of an
/// rsipstack UAS and gets the held 2xx.
#[tokio::test]
async fn uac_pracks_the_reliable_183_of_the_uas() -> crate::Result<()> {
    use crate::dialog::invitation::InviteOption;

    let token = CancellationToken::new();
    let (states, mut dialogs, peer) = setup(&token).await?;
    drain(states);

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
        .with_transport_layer(transport_layer)
        .with_cancel_token(token.child_token())
        .with_option(short_timers())
        .build();
    let inner = endpoint.inner.clone();
    tokio::spawn(async move { inner.serve().await });
    let layer = DialogLayer::new(endpoint.inner.clone());
    let option = InviteOption {
        caller: crate::sip::Uri::try_from("sip:alice@example.com")?,
        callee: crate::sip::Uri::try_from(format!("sip:bob@{}", peer.uas).as_str())?,
        contact: crate::sip::Uri::try_from(format!("sip:alice@{uac_addr}").as_str())?,
        offer: Some(SDP.as_bytes().to_vec()),
        support_prack: true,
        ..Default::default()
    };
    let (uac_states, _uac_receiver) = unbounded_channel();
    let invite = tokio::spawn(async move { layer.do_invite(option, uac_states).await });

    let dialog = next_dialog(&mut dialogs).await;
    assert!(dialog.supports_100rel());
    dialog.ringing_reliable(None, Some(SDP.as_bytes().to_vec()))?;
    dialog.accept(None, Some(SDP.as_bytes().to_vec()))?;

    let (uac_dialog, resp) = tokio::time::timeout(Duration::from_secs(2), invite)
        .await
        .expect("the INVITE must complete once the 183 is PRACKed")
        .unwrap()?;
    assert_eq!(resp.map(|r| r.status_code.code()), Some(200));
    assert!(uac_dialog.state().is_confirmed());

    token.cancel();
    Ok(())
}
