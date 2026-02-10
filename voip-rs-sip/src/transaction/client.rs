use std::net::SocketAddr;

use tokio::sync::mpsc::{self};
use tokio::time::{Instant, timeout, timeout_at};
use utils::PeekableReceiver;

use crate::error::TransactionError;
use crate::message::Request;
use crate::message::headers::{Header, Via};
use crate::transaction::fsm::{State, StateMachine};
use crate::transaction::manager::TransactionKey;
use crate::transaction::{Role, T1, T4, TransactionMessage};
use crate::transport::Transport;
use crate::transport::incoming::IncomingResponse;
use crate::transport::outgoing::OutgoingRequest;
use crate::{Endpoint, Method, Result, find_map_mut_header};

// ACK para 2xx é responsabilidade do TU.

/// A Client Transaction.
///
/// Represents a SIP client transaction.
pub struct ClientTransaction {
    key: TransactionKey,
    endpoint: Endpoint,
    state_machine: StateMachine,
    request: OutgoingRequest,
    channel: PeekableReceiver<TransactionMessage>,
    timeout: Instant,
}

impl ClientTransaction {
    pub(crate) async fn send_request(request: Request, endpoint: Endpoint) -> Result<Self> {
        Self::send_request_inner(request, None, endpoint).await
    }

    pub(crate) async fn send_request_with_target(
        request: Request,
        target: (Transport, SocketAddr),
        endpoint: Endpoint,
    ) -> Result<Self> {
        Self::send_request_inner(request, Some(target), endpoint).await
    }

    async fn send_request_inner(
        request: Request,
        target: Option<(Transport, SocketAddr)>,
        endpoint: Endpoint,
    ) -> Result<Self> {
        let method = request.req_line.method;
        assert_ne!(
            method,
            Method::Ack,
            "ACK requests do not create transactions"
        );
        let mut outgoing = endpoint.create_outgoing_request(request, target).await?;
        let headers = &mut outgoing.request.headers;

        let via = match find_map_mut_header!(headers, Via) {
            Some(via) => via,
            None => {
                let sent_by = outgoing.target_info.transport.local_addr().into();
                let transport = outgoing.target_info.transport.transport_type();
                let branch = crate::generate_branch();
                let via = Via::new_with_transport(transport, sent_by, Some(branch));

                headers.prepend_header(Header::Via(via));

                match headers.first_mut().unwrap() {
                    Header::Via(v) => v,
                    _ => unreachable!(),
                }
            }
        };
        let branch = match via.branch.clone() {
            Some(branch) => branch,
            None => {
                let branch = crate::generate_branch();
                via.branch = Some(branch.clone());
                branch
            }
        };
        let key = TransactionKey::new_key_3261(Role::UAC, method, branch);

        endpoint.send_outgoing_request(&mut outgoing).await?;

        let state = if method == Method::Invite {
            State::Calling
        } else {
            State::Trying
        };
        let (sender, channel) = mpsc::channel(10);

        endpoint.register_transaction(key.clone(), sender);

        let uac = Self {
            key,
            endpoint,
            state_machine: StateMachine::new(state),
            channel: channel.into(),
            request: outgoing,
            timeout: Instant::now() + T1 * 64,
        };

        log::trace!("Transaction Created [{:#?}] ({:p})", Role::UAC, &uac);

        Ok(uac)
    }

    pub fn state(&self) -> State {
        self.state_machine.state()
    }

    pub fn state_machine_mut(&mut self) -> &mut StateMachine {
        &mut self.state_machine
    }

    async fn recv_provisional_msg(&mut self) -> Option<IncomingResponse> {
        match self
            .channel
            .recv_if(|msg| match msg {
                TransactionMessage::Response(response) if response.status().is_provisional() => {
                    true
                }
                _ => false,
            })
            .await
        {
            Some(TransactionMessage::Response(provisional_response)) => {
                return Some(provisional_response);
            }
            _ => return None,
        }
    }

    pub async fn receive_provisional_response(&mut self) -> Result<Option<IncomingResponse>> {
        match self.state_machine.state() {
            State::Initial | State::Calling | State::Trying
                if !self.request.target_info.transport.is_reliable() =>
            {
                let mut retrans_interval = T1;
                loop {
                    let timer = self.timeout.into();
                    let msg = timeout(retrans_interval, self.recv_provisional_msg());

                    match timeout_at(timer, msg).await {
                        Ok(Ok(Some(msg))) => {
                            self.state_machine.set_state(State::Proceeding);
                            return Ok(Some(msg));
                        }
                        Ok(Err(_)) => {
                            // retransmit
                            self.endpoint
                                .send_outgoing_request(&mut self.request)
                                .await?;
                            retrans_interval *= 2;
                            continue;
                        }
                        Err(_elapsed) => {
                            self.state_machine.set_state(State::Terminated);
                            return Err(TransactionError::Timeout.into());
                        }
                        _ => todo!(),
                    }
                }
            }
            State::Initial | State::Calling | State::Trying => {
                match timeout_at(self.timeout.into(), self.recv_provisional_msg()).await {
                    Ok(Some(msg)) => {
                        self.state_machine.set_state(State::Proceeding);
                        return Ok(Some(msg));
                    }
                    Ok(None) => return Ok(None),
                    Err(_elapsed) => {
                        self.state_machine.set_state(State::Terminated);
                        return Err(TransactionError::Timeout.into());
                    }
                }
            }
            State::Proceeding => {
                // TODO: Add Timeout
                return Ok(self.recv_provisional_msg().await);
            }
            State::Completed => todo!(),
            State::Confirmed => todo!(),
            State::Terminated => todo!(),
        }
    }

    pub async fn receive_final_response(mut self) -> Result<IncomingResponse> {
        // Change to only receive final.
        let response = self.channel.recv().await.unwrap();

        let TransactionMessage::Response(response) = response else {
            unimplemented!()
        };

        if self.request.request.req_line.method == Method::Invite
            && let 200..299 = response.status().as_u16()
            && matches!(
                self.state_machine.state(),
                State::Calling | State::Proceeding
            )
        {
            self.state_machine.set_state(State::Terminated);
            return Ok(response);
        }
        self.state_machine.set_state(State::Completed);

        if self.is_reliable() {
            self.state_machine.set_state(State::Terminated);
            return Ok(response);
        }

        if self.request.request.req_line.method == Method::Invite {
            // send ACK
            let mut ack_request = self.endpoint.create_ack_request(&self.request, &response);
            self.endpoint
                .send_outgoing_request(&mut ack_request)
                .await?;

            // timer d fires
            let timer_d = Instant::now() + 64 * T1;
            tokio::spawn(async move {
                while let Ok(Some(_)) = timeout_at(timer_d, self.channel.recv()).await {
                    if let Err(err) = self.endpoint.send_outgoing_request(&mut ack_request).await {
                        log::error!("Failed to retransmit: {}", err);
                    }
                }
                self.state_machine.set_state(State::Terminated);
            });
        } else {
            // timer k fires
            let timer_k = Instant::now() + T4;
            tokio::spawn(async move {
                while let Ok(Some(_)) = timeout_at(timer_k, self.channel.recv()).await {
                    // buffer any additional response retransmissions that may be received
                }
                self.state_machine.set_state(State::Terminated);
            });
        }

        Ok(response)
    }

    pub fn transaction_key(&self) -> &TransactionKey {
        &self.key
    }

    fn is_reliable(&self) -> bool {
        self.request.target_info.transport.is_reliable()
    }
}

impl Drop for ClientTransaction {
    fn drop(&mut self) {
        self.endpoint.transactions().remove(&self.key);
        log::trace!("Transaction Destroyed [{:#?}] ({:p})", Role::UAC, &self);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::{Error, TransactionError};
    use crate::test_utils::transaction::{
        CODE_100_TRYING, CODE_180_RINGING, CODE_202_ACCEPTED, CODE_301_MOVED_PERMANENTLY,
        CODE_404_NOT_FOUND, CODE_504_SERVER_TIMEOUT, CODE_603_DECLINE, ClientTestContext,
        SendRequestContext,
    };
    use crate::{Method, assert_eq_state};

    // INVITE Client tests

    #[tokio::test]
    async fn invite_transitions_to_calling_when_request_is_sent() {
        let ctx = SendRequestContext::setup(Method::Invite);

        let uac = ClientTransaction::send_request_with_target(
            ctx.request,
            (ctx.transport, ctx.destination),
            ctx.endpoint,
        )
        .await
        .expect("error sending request");

        assert_eq!(
            uac.state(),
            State::Calling,
            "client INVITE must transition to the Calling state when sending the request"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn invite_should_not_start_timer_a_when_transport_is_reliable() {
        let mut ctx = ClientTestContext::setup_reliable(Method::Invite).await;
        let expected_requests = 1;
        let expected_retrans = 0;

        let opt_err = ctx.client.receive_provisional_response().await.err();

        assert_matches!(
            opt_err,
            Some(Error::TransactionError(TransactionError::Timeout)),
            "Expected TransactionError::Timeout, got {opt_err:?}"
        );

        assert_eq!(
            ctx.transport.sent_count(),
            expected_requests + expected_retrans,
            "sent count should match {expected_requests} requests and {expected_retrans} retransmissions"
        );
    }

    #[tokio::test]
    async fn invite_transitions_from_calling_to_proceeding_when_receiving_1xx_response() {
        let mut ctx = ClientTestContext::setup(Method::Invite).await;

        ctx.server.respond(CODE_100_TRYING).await;

        ctx.client
            .receive_provisional_response()
            .await
            .expect("Error receiving provisional response")
            .expect("Expected provisional response, but received None");

        assert_eq_state!(
            ctx.state,
            State::Proceeding,
            "client INVITE must transition to the Proceeding state when receiving 1xx response"
        );
    }

    #[tokio::test]
    async fn invite_transitions_from_calling_to_completed_when_receiving_3xx_response() {
        let mut ctx = ClientTestContext::setup(Method::Invite).await;

        ctx.server.respond(CODE_301_MOVED_PERMANENTLY).await;

        ctx.client
            .receive_final_response()
            .await
            .expect("Error receiving final response");

        assert_eq_state!(
            ctx.state,
            State::Completed,
            "client INVITE must transition to the Completed state when receiving 3xx response"
        );
    }

    #[tokio::test]
    async fn invite_transitions_from_calling_to_completed_when_receiving_4xx_response() {
        let mut ctx = ClientTestContext::setup(Method::Invite).await;

        ctx.server.respond(CODE_404_NOT_FOUND).await;

        ctx.client
            .receive_final_response()
            .await
            .expect("Error receiving final response");

        assert_eq_state!(
            ctx.state,
            State::Completed,
            "client INVITE must transition to the Completed state when receiving 4xx response"
        );
    }

    #[tokio::test]
    async fn invite_transitions_from_calling_to_completed_when_receiving_5xx_response() {
        let mut ctx = ClientTestContext::setup(Method::Invite).await;

        ctx.server.respond(CODE_504_SERVER_TIMEOUT).await;

        ctx.client
            .receive_final_response()
            .await
            .expect("Error receiving final response");

        assert_eq_state!(
            ctx.state,
            State::Completed,
            "client INVITE must transition to the Completed state when receiving 5xx response"
        );
    }

    #[tokio::test]
    async fn invite_transitions_from_calling_to_completed_when_receiving_6xx_response() {
        let mut ctx = ClientTestContext::setup(Method::Invite).await;

        ctx.server.respond(CODE_603_DECLINE).await;

        ctx.client
            .receive_final_response()
            .await
            .expect("Error receiving final response");

        assert_eq_state!(
            ctx.state,
            State::Completed,
            "client INVITE must transition to the Completed state when receiving 6xx response"
        );
    }

    #[tokio::test]
    async fn invite_transitions_from_calling_to_terminated_when_receiving_2xx_response() {
        let mut ctx = ClientTestContext::setup(Method::Invite).await;

        ctx.server.respond(CODE_202_ACCEPTED).await;

        ctx.client
            .receive_final_response()
            .await
            .expect("Error receiving final response");

        assert_eq_state!(
            ctx.state,
            State::Terminated,
            "client INVITE must transition to the Terminated state when receiving 2xx response"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn invite_transitions_from_calling_to_terminated_when_timer_b_fires() {
        let mut ctx = ClientTestContext::setup(Method::Invite).await;

        let opt_err = ctx.client.receive_provisional_response().await.err();

        assert_matches!(
            opt_err,
            Some(Error::TransactionError(TransactionError::Timeout)),
            "Expected TransactionError::Timeout, got {opt_err:?}"
        );

        assert_eq_state!(
            ctx.state,
            State::Terminated,
            "client INVITE must transition to the Terminated state when timer B fires"
        );
    }

    #[tokio::test]
    async fn invite_should_send_ack_when_receiving_3xx_response_in_calling_state() {
        let ctx = ClientTestContext::setup(Method::Invite).await;

        ctx.server.respond(CODE_301_MOVED_PERMANENTLY).await;

        ctx.client
            .receive_final_response()
            .await
            .expect("Error receiving final response");

        let req = ctx.transport.get_last_sent_request().expect("A request");
        assert_eq!(
            req.method(),
            Method::Ack,
            "client INVITE must generate an ACK request when receiving 3xx response"
        );
    }

    #[tokio::test]
    async fn invite_should_send_ack_when_receiving_4xx_response_in_calling_state() {
        let ctx = ClientTestContext::setup(Method::Invite).await;

        ctx.server.respond(CODE_404_NOT_FOUND).await;

        ctx.client
            .receive_final_response()
            .await
            .expect("Error receiving final response");

        let req = ctx.transport.get_last_sent_request().expect("A request");
        assert_eq!(
            req.method(),
            Method::Ack,
            "client INVITE must generate an ACK request when receiving 4xx response"
        );
    }

    #[tokio::test]
    async fn invite_should_send_ack_when_receiving_5xx_response_in_calling_state() {
        let ctx = ClientTestContext::setup(Method::Invite).await;

        ctx.server.respond(CODE_504_SERVER_TIMEOUT).await;

        ctx.client
            .receive_final_response()
            .await
            .expect("Error receiving final response");

        let req = ctx.transport.get_last_sent_request().expect("A request");
        assert_eq!(
            req.method(),
            Method::Ack,
            "client INVITE must generate an ACK request when receiving 5xx response"
        );
    }

    #[tokio::test]
    async fn invite_should_send_ack_when_receiving_6xx_response_in_calling_state() {
        let ctx = ClientTestContext::setup(Method::Invite).await;

        ctx.server.respond(CODE_603_DECLINE).await;

        ctx.client
            .receive_final_response()
            .await
            .expect("Error receiving final response");

        let req = ctx.transport.get_last_sent_request().expect("A request");
        assert_eq!(
            req.method(),
            Method::Ack,
            "client INVITE must generate an ACK request when receiving 6xx response"
        );
    }

    #[tokio::test]
    async fn invite_transitions_from_proceeding_to_completed_when_receiving_3xx_response() {
        let mut ctx = ClientTestContext::setup(Method::Invite).await;

        ctx.server.respond(CODE_301_MOVED_PERMANENTLY).await;

        ctx.client
            .receive_final_response()
            .await
            .expect("Error receiving final response");

        assert_eq_state!(
            ctx.state,
            State::Completed,
            "client INVITE must transition to the Completed state when receiving 3xx response"
        );
    }

    #[tokio::test]
    async fn invite_transitions_from_proceeding_to_completed_when_receiving_4xx_response() {
        let mut ctx = ClientTestContext::setup(Method::Invite).await;

        ctx.server.respond(CODE_404_NOT_FOUND).await;

        ctx.client
            .receive_final_response()
            .await
            .expect("Error receiving final response");

        assert_eq_state!(
            ctx.state,
            State::Completed,
            "client INVITE must transition to the Completed state when receiving 4xx response"
        );
    }

    #[tokio::test]
    async fn invite_transitions_from_proceeding_to_completed_when_receiving_5xx_response() {
        let mut ctx = ClientTestContext::setup(Method::Invite).await;

        ctx.server.respond(CODE_504_SERVER_TIMEOUT).await;

        ctx.client
            .receive_final_response()
            .await
            .expect("Error receiving final response");

        assert_eq_state!(
            ctx.state,
            State::Completed,
            "client INVITE must transition to the Completed state when receiving 5xx response"
        );
    }

    #[tokio::test]
    async fn invite_transitions_from_proceeding_to_completed_when_receiving_6xx_response() {
        let mut ctx = ClientTestContext::setup(Method::Invite).await;

        ctx.server.respond(CODE_603_DECLINE).await;

        ctx.client
            .receive_final_response()
            .await
            .expect("Error receiving final response");

        assert_eq_state!(
            ctx.state,
            State::Completed,
            "client INVITE must transition to the Completed state when receiving 6xx response"
        );
    }

    #[tokio::test]
    async fn invite_transitions_from_proceeding_to_terminated_when_receiving_2xx_response() {
        let mut ctx = ClientTestContext::setup(Method::Invite).await;

        ctx.server.respond(CODE_202_ACCEPTED).await;

        ctx.client
            .receive_final_response()
            .await
            .expect("Error receiving final response");

        assert_eq_state!(
            ctx.state,
            State::Terminated,
            "client INVITE must transition to the Completed state when receiving receiving 2xx response"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn invite_should_not_retransmit_request_in_proceeding_state() {
        let mut ctx = ClientTestContext::setup(Method::Invite).await;
        let expected_requests = 1;
        let expected_retrans = 0;

        ctx.server.respond(CODE_100_TRYING).await;

        ctx.client
            .receive_provisional_response()
            .await
            .expect("Error receiving provisional response")
            .expect("Expected provisional response, but received None");

        assert_eq_state!(
            ctx.state,
            State::Proceeding,
            "client INVITE must transition to the Proceeding state when receiving receiving 1xx response"
        );

        ctx.timer.wait_for_retransmissions(5).await;

        assert_eq!(
            ctx.transport.sent_count(),
            expected_requests + expected_retrans
        );
    }

    #[tokio::test]
    async fn invite_should_send_ack_when_receiving_3xx_response_in_proceeding_state() {
        let mut ctx = ClientTestContext::setup(Method::Invite).await;

        ctx.server.respond(CODE_100_TRYING).await;

        ctx.client
            .receive_provisional_response()
            .await
            .expect("Error receiving provisional response")
            .expect("Expected provisional response, but received None");

        assert_eq_state!(
            ctx.state,
            State::Proceeding,
            "client INVITE must transition to the Proceeding state when receiving receiving 1xx response"
        );

        ctx.server.respond(CODE_301_MOVED_PERMANENTLY).await;

        ctx.client
            .receive_final_response()
            .await
            .expect("Error receiving final response");

        let req = ctx.transport.get_last_sent_request().expect("A request");
        assert_eq!(
            req.method(),
            Method::Ack,
            "client INVITE must generate an ACK request when receiving 3xx response"
        );
    }

    #[tokio::test]
    async fn invite_should_send_ack_after_4xx_response_in_proceeding_state() {
        let mut ctx = ClientTestContext::setup(Method::Invite).await;

        ctx.server.respond(CODE_100_TRYING).await;

        ctx.client
            .receive_provisional_response()
            .await
            .expect("Error receiving provisional response")
            .expect("Expected provisional response, but received None");

        assert_eq_state!(
            ctx.state,
            State::Proceeding,
            "client INVITE must transition to the Proceeding state when receiving receiving 1xx response"
        );

        ctx.server.respond(CODE_404_NOT_FOUND).await;

        ctx.client
            .receive_final_response()
            .await
            .expect("Error receiving final response");

        let req = ctx.transport.get_last_sent_request().expect("A request");
        assert_eq!(
            req.method(),
            Method::Ack,
            "client INVITE must generate an ACK request when receiving 4xx response"
        );
    }

    #[tokio::test]
    async fn invite_should_send_ack_when_receiving_5xx_response_in_proceeding_state() {
        let mut ctx = ClientTestContext::setup(Method::Invite).await;

        ctx.server.respond(CODE_100_TRYING).await;

        ctx.client
            .receive_provisional_response()
            .await
            .expect("Error receiving provisional response")
            .expect("Expected provisional response, but received None");

        assert_eq_state!(
            ctx.state,
            State::Proceeding,
            "client INVITE must transition to the Proceeding state when receiving receiving 1xx response"
        );

        ctx.server.respond(CODE_504_SERVER_TIMEOUT).await;

        ctx.client
            .receive_final_response()
            .await
            .expect("Error receiving final response");

        let req = ctx.transport.get_last_sent_request().expect("A request");
        assert_eq!(
            req.method(),
            Method::Ack,
            "client INVITE must generate an ACK request when receiving 5xx response"
        );
    }

    #[tokio::test]
    async fn invite_should_send_ack_after_6xx_response_in_proceeding_state() {
        let mut ctx = ClientTestContext::setup(Method::Invite).await;

        ctx.server.respond(CODE_100_TRYING).await;

        ctx.client
            .receive_provisional_response()
            .await
            .expect("Error receiving provisional response")
            .expect("Expected provisional response, but received None");

        assert_eq_state!(
            ctx.state,
            State::Proceeding,
            "client INVITE must transition to the Proceeding state when receiving receiving 1xx response"
        );

        ctx.server.respond(CODE_603_DECLINE).await;

        ctx.client
            .receive_final_response()
            .await
            .expect("Error receiving final response");

        let req = ctx.transport.get_last_sent_request().expect("A request");
        assert_eq!(
            req.method(),
            Method::Ack,
            "client INVITE must generate an ACK request when receiving 6xx response"
        );
    }

    #[tokio::test]
    async fn invite_should_pass_provisional_responses_to_tu_in_proceeding_state() {
        let mut ctx = ClientTestContext::setup(Method::Invite).await;

        ctx.server.respond(CODE_100_TRYING).await;
        ctx.server.respond(CODE_180_RINGING).await;

        let incoming = ctx
            .client
            .receive_provisional_response()
            .await
            .expect("Error receiving provisional response")
            .expect("Expected provisional response, but received None");

        assert_eq!(
            incoming.response.status(),
            CODE_100_TRYING,
            "should match 100 status code"
        );

        let incoming = ctx
            .client
            .receive_provisional_response()
            .await
            .expect("Error receiving provisional response")
            .expect("Expected provisional response, but received None");

        assert_eq!(
            incoming.response.status(),
            CODE_180_RINGING,
            "should match 180 status code"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn invite_transitions_from_completed_to_terminated_when_timer_d_fires() {
        let mut ctx = ClientTestContext::setup(Method::Invite).await;

        ctx.server.respond(CODE_301_MOVED_PERMANENTLY).await;

        ctx.client
            .receive_final_response()
            .await
            .expect("Error receiving final response");

        assert_eq_state!(
            ctx.state,
            State::Completed,
            "client INVITE must transition to the Completed state when receiving 3xx response"
        );

        ctx.timer.timer_d().await;

        assert_eq_state!(
            ctx.state,
            State::Terminated,
            "client INVITE must transition to the Terminated state when timer D fires"
        );
    }

    // Non-INVITE Client tests

    #[tokio::test]
    async fn non_invite_transitions_to_trying_when_request_is_sent() {
        let ctx = SendRequestContext::setup(Method::Register);

        let uac = ClientTransaction::send_request_with_target(
            ctx.request,
            (ctx.transport, ctx.destination),
            ctx.endpoint,
        )
        .await
        .expect("failure sending request");

        assert_eq!(
            uac.state(),
            State::Trying,
            "client non-INVITE must transition to the Trying state when sending the request"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn non_invite_should_not_start_timer_e_when_transport_is_reliable() {
        let mut ctx = ClientTestContext::setup_reliable(Method::Invite).await;
        let expected_requests = 1;
        let expected_retrans = 0;

        let opt_err = ctx.client.receive_provisional_response().await.err();

        assert_matches!(
            opt_err,
            Some(Error::TransactionError(TransactionError::Timeout)),
            "Expected TransactionError::Timeout, got {opt_err:?}"
        );

        assert_eq!(
            ctx.transport.sent_count(),
            expected_requests + expected_retrans,
            "sent count should match {expected_requests} requests and {expected_retrans} retransmissions"
        );
    }

    #[tokio::test]
    async fn non_invite_transitions_from_trying_to_proceeding_when_receiving_1xx_response() {
        let mut ctx = ClientTestContext::setup(Method::Register).await;

        ctx.server.respond(CODE_100_TRYING).await;

        ctx.client
            .receive_provisional_response()
            .await
            .expect("Error receiving provisional response")
            .expect("Expected provisional response, but received None");

        assert_eq_state!(
            ctx.state,
            State::Proceeding,
            "client non-INVITE must transition to the Proceeding state when receiving receiving 1xx response"
        );
    }

    #[tokio::test]
    async fn non_invite_transitions_from_trying_to_completed_when_receiving_2xx_response() {
        let mut ctx = ClientTestContext::setup(Method::Options).await;

        ctx.server.respond(CODE_301_MOVED_PERMANENTLY).await;

        ctx.client
            .receive_final_response()
            .await
            .expect("Error receiving final response");

        assert_eq_state!(
            ctx.state,
            State::Completed,
            "client non-INVITE must transition to the Completed state when receiving receiving 6xx response"
        );
    }

    #[tokio::test]
    async fn non_invite_transitions_from_trying_to_completed_when_receiving_3xx_response() {
        let mut ctx = ClientTestContext::setup(Method::Options).await;

        ctx.server.respond(CODE_301_MOVED_PERMANENTLY).await;

        ctx.client
            .receive_final_response()
            .await
            .expect("Error receiving final response");

        assert_eq_state!(
            ctx.state,
            State::Completed,
            "client non-INVITE must transition to the Completed state when receiving receiving 3xx response"
        );
    }

    #[tokio::test]
    async fn non_invite_transitions_from_trying_to_completed_when_receiving_4xx_response() {
        let mut ctx = ClientTestContext::setup(Method::Options).await;

        ctx.server.respond(CODE_404_NOT_FOUND).await;

        ctx.client
            .receive_final_response()
            .await
            .expect("Error receiving final response");

        assert_eq_state!(
            ctx.state,
            State::Completed,
            "client non-INVITE must transition to the Completed state when receiving receiving 4xx response"
        );
    }

    #[tokio::test]
    async fn non_invite_transitions_from_trying_to_completed_when_receiving_5xx_response() {
        let mut ctx = ClientTestContext::setup(Method::Options).await;

        ctx.server.respond(CODE_504_SERVER_TIMEOUT).await;

        ctx.client
            .receive_final_response()
            .await
            .expect("Error receiving final response");

        assert_eq_state!(
            ctx.state,
            State::Completed,
            "client non-INVITE must transition to the Completed state when receiving receiving 5xx response"
        );
    }

    #[tokio::test]
    async fn non_invite_transitions_from_trying_to_completed_when_receiving_6xx_response() {
        let mut ctx = ClientTestContext::setup(Method::Options).await;

        ctx.server.respond(CODE_603_DECLINE).await;

        ctx.client
            .receive_final_response()
            .await
            .expect("Error receiving final response");

        assert_eq_state!(
            ctx.state,
            State::Completed,
            "client non-INVITE must transition to the Completed state when receiving receiving 6xx response"
        );
    }
    #[tokio::test]
    async fn non_invite_transitions_from_proceeding_to_completed_when_receiving_3xx_response() {
        let mut ctx = ClientTestContext::setup(Method::Options).await;

        ctx.server.respond(CODE_301_MOVED_PERMANENTLY).await;

        ctx.client
            .receive_final_response()
            .await
            .expect("Error receiving final response");

        assert_eq_state!(
            ctx.state,
            State::Completed,
            "client non-INVITE must transition to the Completed state when receiving receiving 3xx response"
        );
    }

    #[tokio::test]
    async fn non_invite_transitions_from_proceeding_to_completed_when_receiving_4xx_response() {
        let mut ctx = ClientTestContext::setup(Method::Options).await;

        ctx.server.respond(CODE_404_NOT_FOUND).await;

        ctx.client
            .receive_final_response()
            .await
            .expect("Error receiving final response");

        assert_eq_state!(
            ctx.state,
            State::Completed,
            "client non-INVITE must transition to the Completed state when receiving receiving 4xx response"
        );
    }

    #[tokio::test]
    async fn non_invite_transitions_from_proceeding_to_completed_when_receiving_5xx_response() {
        let mut ctx = ClientTestContext::setup(Method::Options).await;

        ctx.server.respond(CODE_504_SERVER_TIMEOUT).await;

        ctx.client
            .receive_final_response()
            .await
            .expect("Error receiving final response");

        assert_eq_state!(
            ctx.state,
            State::Completed,
            "client non-INVITE must transition to the Completed state when receiving receiving 5xx response"
        );
    }

    #[tokio::test]
    async fn non_invite_transitions_from_proceeding_to_completed_when_receiving_6xx_response() {
        let mut ctx = ClientTestContext::setup(Method::Options).await;

        ctx.server.respond(CODE_603_DECLINE).await;

        ctx.client
            .receive_final_response()
            .await
            .expect("Error receiving final response");

        assert_eq_state!(
            ctx.state,
            State::Completed,
            "client non-INVITE must transition to the Completed state when receiving receiving 6xx response"
        );
    }

    #[tokio::test]
    async fn non_invite_transitions_from_proceeding_to_completed_when_receiving_2xx_response() {
        let mut ctx = ClientTestContext::setup(Method::Options).await;

        ctx.server.respond(CODE_202_ACCEPTED).await;

        ctx.client
            .receive_final_response()
            .await
            .expect("Error receiving final response");

        assert_eq_state!(
            ctx.state,
            State::Completed,
            "client non-INVITE must transition to the Completed state when receiving receiving 2xx response"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn non_invite_transitions_from_trying_to_terminated_when_timer_f_fires() {
        let mut ctx = ClientTestContext::setup(Method::Register).await;

        let opt_err = ctx.client.receive_provisional_response().await.err();

        assert_matches!(
            opt_err,
            Some(Error::TransactionError(TransactionError::Timeout)),
            "Expected TransactionError::Timeout, got {opt_err:?}"
        );

        assert_eq_state!(
            ctx.state,
            State::Terminated,
            "client non-INVITE must transition to the Terminated state when timer F fires"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn non_invite_should_not_retransmit_request_in_proceeding_state() {
        let mut ctx = ClientTestContext::setup(Method::Options).await;
        let expected_requests = 1;
        let expected_retrans = 0;

        ctx.server.respond(CODE_100_TRYING).await;

        ctx.client
            .receive_provisional_response()
            .await
            .expect("Error receiving provisional response")
            .expect("Expected provisional response, but received None");

        assert_eq_state!(
            ctx.state,
            State::Proceeding,
            "client non-INVITE must transition to the Proceeding state when receiving receiving 1xx response"
        );

        ctx.timer.wait_for_retransmissions(5).await;

        assert_eq!(
            ctx.transport.sent_count(),
            expected_requests + expected_retrans,
            "sent count should match {expected_requests} requests and {expected_retrans} retransmissions"
        );
    }

    #[tokio::test]
    async fn non_invite_should_pass_provisional_responses_to_tu_in_proceeding_state() {
        let mut ctx = ClientTestContext::setup(Method::Options).await;

        ctx.server.respond(CODE_100_TRYING).await;
        ctx.server.respond(CODE_180_RINGING).await;

        let response = ctx
            .client
            .receive_provisional_response()
            .await
            .expect("Error receiving provisional response")
            .expect("Expected provisional response, but received None");

        assert_eq!(
            response.response.status(),
            CODE_100_TRYING,
            "should match 100 status code"
        );

        let response = ctx
            .client
            .receive_provisional_response()
            .await
            .expect("Error receiving provisional response")
            .expect("Expected provisional response, but received None");

        assert_eq!(
            response.response.status(),
            CODE_180_RINGING,
            "should match 180 status code"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn non_invite_transitions_from_completed_to_terminated_when_timer_k_fires() {
        let mut ctx = ClientTestContext::setup(Method::Options).await;

        ctx.server.respond(CODE_301_MOVED_PERMANENTLY).await;

        ctx.client
            .receive_final_response()
            .await
            .expect("Error receiving final response");

        ctx.timer.timer_k().await;
        tokio::task::yield_now().await;

        assert_eq_state!(
            ctx.state,
            State::Terminated,
            "should transition to Terminated after timer d fires"
        );
    }
}
