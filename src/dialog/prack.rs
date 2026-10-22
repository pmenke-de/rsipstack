//! Reliable provisional responses sent by a UAS (RFC 3262 §3).
//!
//! The UAC side (sending PRACK for a reliable 1xx) lives in
//! [`DialogInner::prepare_prack_request`]. This module holds the UAS side:
//! the `Require: 100rel` / `RSeq` response, its retransmission, matching an
//! incoming PRACK against it, and holding back a 2xx to the INVITE while a
//! reliable 1xx with a body waits for its PRACK.

use super::dialog::{DialogInner, DialogState, TerminatedReason, TransactionHandle};
use crate::platform::CancellationToken;
use crate::prelude::*;
use crate::sip::prelude::HeadersExt;
use crate::sip::{Header, Method, Request, Response, StatusCode, StatusCodeKind};
use crate::transaction::key::TransactionRole;
use crate::transaction::transaction::{Transaction, TransactionEvent};
use crate::Result;
use tracing::{debug, warn};

/// UAS state of the reliable provisional responses to the initial INVITE.
#[derive(Default)]
pub(super) struct LocalReliableState {
    /// RSeq of the next reliable 1xx; `None` until the first one picks a
    /// random start (RFC 3262 §3).
    next_rseq: Option<u32>,
    /// The reliable 1xx that waits for its PRACK. RFC 3262 §3 forbids a
    /// second one before the first is acknowledged, so there is at most one.
    unacked: Option<UnackedProvisional>,
    /// A 2xx to the INVITE held back until `unacked` is acknowledged.
    held_2xx: Option<Response>,
    /// A final response to the INVITE was sent (or held): no new reliable
    /// 1xx may follow.
    final_sent: bool,
}

struct UnackedProvisional {
    rseq: u32,
    cseq: u32,
    method: Method,
    has_body: bool,
    /// Stops the retransmission task.
    retransmit: CancellationToken,
}

/// A random first RSeq in 1..=2^31-1 (RFC 3262 §3).
fn initial_rseq() -> u32 {
    let mut bytes = [0u8; 4];
    crate::transaction::fill_random_bytes(&mut bytes);
    (u32::from_le_bytes(bytes) & 0x7fff_ffff).max(1)
}

/// `RAck: <rseq> <cseq> <method>` of a PRACK (RFC 3262 §7.2).
fn rack_of(req: &Request) -> Option<(u32, u32, Method)> {
    req.rack_value().or_else(|| {
        let value = req.header_value("RAck")?;
        let mut items = value.split_whitespace();
        let rseq = items.next()?.parse::<u32>().ok()?;
        let cseq = items.next()?.parse::<u32>().ok()?;
        let method = items.next()?.parse::<Method>().ok()?;
        Some((rseq, cseq, method))
    })
}

impl DialogInner {
    /// Whether the initial INVITE listed `100rel` in `Require`.
    pub(super) fn requires_100rel(&self) -> bool {
        self.initial_request
            .lock()
            .header_contains_token("Require", "100rel")
    }

    /// Send `status` (101..=199) reliably to the initial INVITE and start
    /// retransmitting it (RFC 3262 §3). See
    /// [`InviteDialog::reliable_provisional`](super::invite_dialog::InviteDialog::reliable_provisional).
    pub(super) fn send_reliable_provisional(
        self: &Arc<Self>,
        status: StatusCode,
        headers: Option<Vec<Header>>,
        body: Option<Vec<u8>>,
    ) -> Result<()> {
        let id = self.id.lock().clone();
        let refuse = |why: &str| {
            Err(crate::Error::DialogError(
                format!("cannot send a reliable {status}: {why}"),
                id.clone(),
                StatusCode::ServerInternalError,
            ))
        };
        if self.role != TransactionRole::Server {
            return refuse("not a UAS dialog");
        }
        if status.kind() != StatusCodeKind::Provisional || status == StatusCode::Trying {
            return refuse("only 101..=199 can be sent reliably");
        }
        if !self.supports_100rel {
            return refuse("the INVITE did not list 100rel in Supported or Require");
        }
        if !self.can_cancel() {
            return refuse("the INVITE is no longer pending");
        }

        let initial = self.initial_request.lock().clone();
        let cseq_header = initial.cseq_header()?;
        let (cseq, method) = (cseq_header.seq()?, cseq_header.method()?);

        let mut reliable = self.local_reliable.lock();
        if reliable.final_sent {
            return refuse("a final response was already sent");
        }
        if let Some(unacked) = reliable.unacked.as_ref() {
            return refuse(&format!(
                "the reliable provisional with RSeq {} is not acknowledged yet",
                unacked.rseq
            ));
        }
        let rseq = match reliable.next_rseq {
            Some(rseq) => rseq,
            None => initial_rseq(),
        };
        // RSeq increases by exactly one and never wraps (RFC 3262 §3).
        let Some(next_rseq) = rseq.checked_add(1) else {
            return refuse("the RSeq space is exhausted");
        };

        let mut resp = self.make_response(&initial, status.clone(), headers, body);
        let require = resp.headers.iter().find_map(|h| match h {
            Header::Require(r) => Some(r.value().to_string()),
            _ => None,
        });
        let require = match require {
            Some(value)
                if value
                    .split(',')
                    .any(|t| t.trim().eq_ignore_ascii_case("100rel")) =>
            {
                value
            }
            Some(value) => format!("{value}, 100rel"),
            None => "100rel".to_string(),
        };
        resp.headers.unique_push(Header::Require(require.into()));
        resp.headers
            .unique_push(Header::RSeq(rseq.to_string().into()));

        self.tu_sender
            .send(TransactionEvent::Respond(resp.clone()))?;
        let retransmit = CancellationToken::new();
        reliable.next_rseq = Some(next_rseq);
        reliable.unacked = Some(UnackedProvisional {
            rseq,
            cseq,
            method,
            has_body: !resp.body.is_empty(),
            retransmit: retransmit.clone(),
        });
        drop(reliable);
        debug!(%id, %status, rseq, "sent reliable provisional response");

        let _handle = crate::platform::spawn(Self::retransmit_reliable_provisional(
            self.clone(),
            resp.clone(),
            retransmit,
        ));
        self.transition(DialogState::Early(id, resp));
        Ok(())
    }

    /// Retransmit a reliable 1xx at T1, 2*T1, 4*T1, ... (no T2 cap, RFC 3262
    /// §3) until `retransmit` is cancelled, and reject the INVITE with a 500
    /// when no PRACK arrived within 64*T1.
    async fn retransmit_reliable_provisional(
        inner: Arc<Self>,
        resp: Response,
        retransmit: CancellationToken,
    ) {
        let limit = inner.endpoint_inner.option.t1x64;
        let mut interval = inner.endpoint_inner.option.t1;
        let mut elapsed = Duration::ZERO;
        loop {
            let wait = interval.min(limit.saturating_sub(elapsed));
            let mut sleep = core::pin::pin!(crate::platform::sleep(wait));
            let mut cancelled = core::pin::pin!(retransmit.cancelled());
            if let crate::platform::Either::B(()) =
                crate::platform::select2(&mut sleep, &mut cancelled).await
            {
                return;
            }
            elapsed += wait;
            if elapsed >= limit {
                inner.reliable_provisional_timed_out(&retransmit);
                return;
            }
            if retransmit.is_cancelled() || !inner.can_cancel() {
                return;
            }
            if inner
                .tu_sender
                .send(TransactionEvent::Respond(resp.clone()))
                .is_err()
            {
                return;
            }
            interval = interval.saturating_mul(2);
        }
    }

    /// No PRACK within 64*T1: reject the INVITE with a 500 (RFC 3262 §3
    /// SHOULD) and terminate the dialog with [`TerminatedReason::Timeout`].
    fn reliable_provisional_timed_out(&self, retransmit: &CancellationToken) {
        {
            let mut reliable = self.local_reliable.lock();
            if retransmit.is_cancelled() {
                return;
            }
            reliable.unacked = None;
            reliable.held_2xx = None;
            reliable.final_sent = true;
        }
        if !self.can_cancel() {
            return;
        }
        let id = self.id.lock().clone();
        warn!(%id, "no PRACK for the reliable provisional response within 64*T1, rejecting the INVITE");
        let initial = self.initial_request.lock().clone();
        let resp = self.make_response(&initial, StatusCode::ServerInternalError, None, None);
        self.tu_sender.send(TransactionEvent::Respond(resp)).ok();
        self.transition(DialogState::Terminated(id, TerminatedReason::Timeout));
    }

    /// Called before a final response to the INVITE goes out. Returns
    /// `false` when it is a 2xx that must wait for the PRACK of a reliable
    /// 1xx with a body (RFC 3262 §3, §5); the 2xx is then kept and sent when
    /// that PRACK arrives. Otherwise the final response may go now: the
    /// retransmission of an unacknowledged reliable 1xx stops, while a late
    /// PRACK for it is still answered with 200 (RFC 3262 §3).
    pub(super) fn release_final_response(&self, resp: &Response) -> bool {
        let mut reliable = self.local_reliable.lock();
        if resp.status_code.kind() == StatusCodeKind::Successful
            && reliable.unacked.as_ref().is_some_and(|u| u.has_body)
        {
            debug!(id = %self.id.lock(), "holding the 2xx until the reliable provisional is acknowledged");
            reliable.held_2xx = Some(resp.clone());
            reliable.final_sent = true;
            return false;
        }
        reliable.held_2xx = None;
        reliable.final_sent = true;
        if let Some(unacked) = reliable.unacked.as_ref() {
            unacked.retransmit.cancel();
        }
        true
    }

    /// Match a PRACK's RAck against the unacknowledged reliable 1xx. On a
    /// match, its retransmission stops and the held 2xx (if any) is
    /// returned as `Some(Some(_))`.
    fn acknowledge_reliable_provisional(
        &self,
        rack: (u32, u32, Method),
    ) -> Option<Option<Response>> {
        let mut reliable = self.local_reliable.lock();
        let unacked = reliable.unacked.as_ref()?;
        if (unacked.rseq, unacked.cseq, &unacked.method) != (rack.0, rack.1, &rack.2) {
            return None;
        }
        unacked.retransmit.cancel();
        reliable.unacked = None;
        Some(reliable.held_2xx.take())
    }

    /// Handle a PRACK (RFC 3262 §3): 400 without a valid RAck, 481 when it
    /// matches no unacknowledged reliable 1xx, else
    /// [`DialogState::Prack`] with a handle for the answer (200 OK when the
    /// handle is dropped without one), then the held 2xx to the INVITE.
    pub(super) async fn handle_prack(&self, tx: &mut Transaction) -> Result<()> {
        let id = self.id.lock().clone();
        let Some(rack) = rack_of(&tx.original) else {
            warn!(%id, "received PRACK without a valid RAck header");
            tx.reply(StatusCode::BadRequest).await?;
            return Ok(());
        };
        let Some(held_2xx) = self.acknowledge_reliable_provisional(rack) else {
            debug!(%id, ?rack, "PRACK matches no unacknowledged reliable provisional response");
            tx.reply(StatusCode::CallTransactionDoesNotExist).await?;
            return Ok(());
        };
        debug!(%id, ?rack, "reliable provisional response acknowledged");

        let (handle, rx) = TransactionHandle::new();
        self.transition(DialogState::Prack(id.clone(), tx.original.clone(), handle));
        let result = self
            .process_transaction_handle_or(tx, rx, StatusCode::OK)
            .await;

        if let Some(resp) = held_2xx {
            if self.can_cancel() {
                debug!(%id, "sending the held 2xx after the PRACK");
                self.tu_sender
                    .send(TransactionEvent::Respond(resp.clone()))?;
                self.transition(DialogState::WaitAck(id, resp));
            }
        }
        result
    }
}
