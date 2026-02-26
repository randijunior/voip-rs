//! Test utilities for all unit tests in the library.

use std::str::FromStr;

use bytes::Bytes;

use crate::transaction::TsxModule;
use crate::ua::dialog::UaModule;
use crate::endpoint::{Endpoint, EndpointBuilder};
use crate::message::headers::{CSeq, CallId, From, Header, Headers, MaxForwards, To, Via};
use crate::message::{MandatoryHeaders, Method, Request, Uri};
use crate::transport::incoming::{IncomingInfo, IncomingRequest};
use crate::transport::{Packet, Transport, TransportMessage};

pub fn create_test_endpoint() -> Endpoint {
    EndpointBuilder::new()
        .build()
}

fn create_test_headers(method: Method) -> Headers {
    let branch = crate::generate_branch();

    let via = Via::from_str(&format!("SIP/2.0/UDP localhost:5060;branch={branch}")).unwrap();
    let from = From::from_str("Alice <sip:alice@localhost>;tag=1928301774").unwrap();
    let to = To::from_str("Bob <sip:bob@localhost>").unwrap();
    let cid = CallId::from("a84b4c76e66710@pc33.atlanta.com");
    let mfowards = MaxForwards::new(70);
    let cseq = CSeq::new(1, method);

    crate::headers! {
        Header::Via(via),
        Header::From(from),
        Header::To(to),
        Header::CallId(cid),
        Header::CSeq(cseq),
        Header::MaxForwards(mfowards)
    }
}

pub fn create_test_request(method: Method, transport: Transport) -> IncomingRequest {
    let headers = create_test_headers(method);
    let target = format!("sip:{}", transport.local_addr());
    let uri = Uri::from_str(&target).unwrap();

    let mandatory_headers = MandatoryHeaders::from_headers(&headers).unwrap();

    let request = Request::with_headers(method, uri, headers);
    let packet = Packet::new(Bytes::new(), transport.local_addr());

    let transport = TransportMessage { packet, transport };

    let incoming_info = IncomingInfo {
        transport,
        mandatory_headers,
    };

    IncomingRequest {
        request,
        incoming_info: Box::new(incoming_info),
    }
}

pub mod parser {
    /// Expands to a test function that validates if a given `input` string
    /// is a valid SIP URI and matches the `expected` structure.
    ///
    /// # Example
    ///
    /// ```rust
    /// uri_test_ok!(
    ///     name: test_simple_uri,
    ///     input: "sip:alice@atlanta.com",
    ///     expected: my_expected_uri_struct
    /// );
    /// ```
    #[macro_export]
    macro_rules! uri_test_ok {
        (name: $name:ident, input: $input:literal, expected: $expected:expr) => {
            #[test]
            fn $name() -> Result<()> {
                let uri = $crate::parser::Parser::new($input).parse_sip_uri(true)?;

                assert_eq!($expected.scheme, uri.scheme());
                assert_eq!($expected.host_port.host, uri.host_port().host);
                assert_eq!($expected.host_port.port, uri.host_port().port);
                assert_eq!($expected.user, uri.user().cloned());
                assert_eq!($expected.transport_param, uri.transport_param());
                assert_eq!($expected.ttl_param, uri.ttl_param());
                assert_eq!($expected.method_param, uri.method_param());
                assert_eq!($expected.user_param.as_deref(), uri.user_param());
                assert_eq!($expected.lr_param, uri.lr_param());
                assert_eq!(&$expected.maddr_param, uri.maddr_param());

                if let Some(params) = uri.other_params() {
                    assert!($expected.parameters.is_some(), "missing parameters!");
                    for param in $expected.parameters.unwrap().iter() {
                        assert_eq!(params.get_named(param.name()), param.value());
                    }
                }
                if let Some(headers) = uri.headers() {
                    assert!($expected.headers.is_some(), "missing headers!");
                    for param in $expected.headers.unwrap().iter() {
                        assert_eq!(headers.get_named(param.name()), param.value());
                    }
                }

                Ok(())
            }
        };
    }
}

pub mod transaction {
    use std::cmp;
    use std::net::SocketAddr;
    use std::time::Duration;

    use tokio::sync::{mpsc, watch};
    use tokio::task;
    use tokio::time::{self};

    use super::transport::MockTransport;
    use super::{create_test_endpoint, create_test_request};
    use crate::endpoint::Endpoint;
    use crate::message::{Method, Request, StatusCode};
    use crate::transaction::client::ClientTransaction;
    use crate::transaction::fsm::{self};
    use crate::transaction::{ServerTransaction, T1, T2, T4, TransactionMessage};
    use crate::transport::incoming::{IncomingInfo, IncomingRequest, IncomingResponse};
    use crate::transport::{Packet, Transport, TransportMessage};

    pub const CODE_100_TRYING: StatusCode = StatusCode::Trying;
    pub const CODE_180_RINGING: StatusCode = StatusCode::Ringing;
    pub const CODE_202_ACCEPTED: StatusCode = StatusCode::Accepted;
    pub const CODE_301_MOVED_PERMANENTLY: StatusCode = StatusCode::MovedPermanently;
    pub const CODE_404_NOT_FOUND: StatusCode = StatusCode::NotFound;
    pub const CODE_504_SERVER_TIMEOUT: StatusCode = StatusCode::ServerTimeout;
    pub const CODE_603_DECLINE: StatusCode = StatusCode::Decline;

    /// Asserts that the last state received in the [`watch::Receiver<State>`] are equal to the expected.
    #[macro_export]
    macro_rules! assert_eq_state {
        ($watcher:expr, $state:expr $(,)?) => {
            $crate::assert_eq_state!($watcher, $state,)
        };
        ($watcher:expr, $state:expr, $($arg:tt)+) => {{
            $crate::test_utils::transaction::wait_state_change(&mut $watcher).await;
            assert_eq!(*$watcher.borrow(), $state, $($arg)+);
        }};
    }

    pub async fn wait_state_change(state: &mut watch::Receiver<fsm::State>) {
        if let Ok(Err(_err)) = time::timeout(Duration::from_millis(50), state.changed()).await {
            panic!("The channel has been closed")
        }
    }

    pub struct FakeUAS {
        pub sender: mpsc::Sender<TransactionMessage>,
        pub request: IncomingRequest,
        pub endpoint: Endpoint,
    }

    impl FakeUAS {
        pub async fn respond(&self, code: StatusCode) {
            let mandatory_headers = self.request.incoming_info.mandatory_headers.clone();
            let outgoing = self.endpoint.create_response(&self.request, code, None);
            let packet = Packet::new(outgoing.encoded, outgoing.target_info.target);

            let transport = TransportMessage {
                packet,
                transport: outgoing.target_info.transport,
            };
            let info = IncomingInfo {
                transport,
                mandatory_headers,
            };

            let response = IncomingResponse {
                response: outgoing.response,
                incoming_info: Box::new(info),
            };

            let transaction_message = TransactionMessage::Response(response);

            self.sender.send(transaction_message).await.unwrap();
        }
    }

    pub struct FakeUAC {
        pub sender: mpsc::Sender<TransactionMessage>,
        pub request: IncomingRequest,
    }

    impl FakeUAC {
        pub async fn retransmit_n_times(&self, n: usize) {
            for _ in 0..n {
                self.retransmit().await;
            }
        }

        pub async fn retransmit(&self) {
            self.send(self.request.clone()).await;
        }

        pub async fn send_ack_request(&mut self) {
            let mut incoming = self.request.clone();
            incoming.request.req_line.method = Method::Ack;
            self.send(incoming).await;
        }

        async fn send(&self, request: IncomingRequest) {
            self.sender
                .send(TransactionMessage::Request(request))
                .await
                .unwrap();
            tokio::task::yield_now().await;
        }
    }

    pub struct TestTimer {
        retrans_interval: Duration,
    }

    impl TestTimer {
        pub fn new() -> Self {
            Self {
                retrans_interval: T1,
            }
        }

        pub async fn timer_h(&self) {
            tokio::time::sleep(T1 * 64).await
        }

        pub async fn timer_j(&self) {
            tokio::time::sleep(T1 * 64).await
        }

        pub async fn timer_k(&self) {
            tokio::time::sleep(T1 * 64).await
        }

        pub async fn timer_d(&self) {
            tokio::time::sleep(T1 * 64).await
        }

        pub async fn timer_i(&self) {
            tokio::time::sleep(T4).await
        }

        fn next_interval(&mut self) {
            self.retrans_interval = cmp::min(self.retrans_interval * 2, T2);
        }

        async fn wait_interval(&self) {
            time::sleep(self.retrans_interval).await;
        }

        pub async fn wait_for_retransmissions(&mut self, n: usize) {
            for _ in 0..n {
                self.wait_interval().await;
                self.next_interval();
                task::yield_now().await;
            }
        }
    }

    pub struct SendRequestContext {
        pub endpoint: Endpoint,
        pub request: Request,
        pub transport: Transport,
        pub destination: SocketAddr,
    }

    impl SendRequestContext {
        pub fn setup(method: Method) -> Self {
            let transport = Transport::new(MockTransport::new_udp());

            let endpoint = create_test_endpoint();
            let incoming = create_test_request(method, transport.clone());

            let destination = incoming.incoming_info.transport.packet.source;
            let request = incoming.request;

            Self {
                endpoint,
                request,
                transport,
                destination,
            }
        }
    }

    pub struct ClientTestContext {
        pub client: ClientTransaction,
        pub server: FakeUAS,
        pub transport: MockTransport,
        pub timer: TestTimer,
        pub state: watch::Receiver<fsm::State>,
    }

    impl ClientTestContext {
        pub async fn setup(method: Method) -> Self {
            Self::new(method, MockTransport::new_udp()).await
        }

        pub async fn setup_reliable(method: Method) -> Self {
            Self::new(method, MockTransport::new_tcp()).await
        }

        async fn new(method: Method, transport: MockTransport) -> Self {
            let transport_impl = Transport::new(transport.clone());
            let timer = TestTimer::new();

            let endpoint = create_test_endpoint();
            let request = create_test_request(method, transport_impl.clone());

            let destination = request.incoming_info.transport.packet.source;

            let target = (transport_impl, destination);

            let mut client = ClientTransaction::send_request_with_target(
                request.request.clone(),
                target,
                endpoint.clone(),
            )
            .await
            .expect("failure sending request");

            let expected_state = if method == Method::Invite {
                fsm::State::Calling
            } else {
                fsm::State::Trying
            };

            assert_eq!(
                client.state(),
                expected_state,
                "Transaction state should transition to {expected_state} after sending request"
            );

            let sender = endpoint
                .transactions()
                .get_entry(client.transaction_key())
                .unwrap();

            let server = FakeUAS {
                sender,
                request,
                endpoint,
            };

            let state = client.state_machine_mut().subscribe_state();

            Self {
                client,
                server,
                transport,
                timer,
                state,
            }
        }
    }

    pub struct ServerTestContext {
        pub server: ServerTransaction,
        pub client: FakeUAC,
        pub transport: MockTransport,
        pub timer: TestTimer,
        pub state: watch::Receiver<fsm::State>,
    }

    impl ServerTestContext {
        pub fn setup(method: Method) -> Self {
            Self::new(method, MockTransport::new_udp())
        }

        pub fn setup_reliable(method: Method) -> Self {
            Self::new(method, MockTransport::new_tcp())
        }

        fn new(method: Method, transport: MockTransport) -> Self {
            let transport_impl = Transport::new(transport.clone());

            let endpoint = create_test_endpoint();
            let request = create_test_request(method, transport_impl);

            let mut server = ServerTransaction::new(request.clone(), endpoint.clone());

            let sender = endpoint
                .transactions()
                .get_entry(server.transaction_key())
                .unwrap();

            let client = FakeUAC { sender, request };

            let timer = TestTimer::new();

            let state = server.state_machine_mut().subscribe_state();

            Self {
                server,
                client,
                transport,
                timer,
                state,
            }
        }
    }
}

pub mod transport {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::sync::{Arc, Mutex};

    use crate::message::{Request, SipMessage};
    use crate::parser::Parser;
    use crate::transport::{SipTransport, TransportType};

    /// A mock transport, for testing purposes
    #[derive(Clone)]
    pub struct MockTransport {
        sent: Arc<Mutex<Vec<(Vec<u8>, SocketAddr)>>>,
        addr: SocketAddr,
        tp_type: TransportType,
        fail_at: Option<usize>,
    }

    impl MockTransport {
        pub fn with_transport_type(tp_type: TransportType) -> Self {
            let ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
            let port = tp_type.default_port();
            let mock = Self {
                sent: Default::default(),
                addr: SocketAddr::new(ip, port),
                tp_type,
                fail_at: None,
            };

            mock
        }

        pub fn new_udp() -> Self {
            Self::with_transport_type(TransportType::Udp)
        }

        pub fn new_tcp() -> Self {
            Self::with_transport_type(TransportType::Tcp)
        }

        pub fn new_tls() -> Self {
            Self::with_transport_type(TransportType::Tls)
        }

        pub fn sent_count(&self) -> usize {
            self.sent.lock().unwrap().len()
        }

        pub fn get_last_sent_request(&self) -> Option<Request> {
            self.get_last_sent_message().map(|msg| {
                if let SipMessage::Request(req) = msg {
                    Some(req)
                } else {
                    None
                }
            })?
        }

        pub fn last_buffer(&self) -> Option<Vec<u8>> {
            let guard = self.sent.lock().unwrap();
            guard.last().map(|(buff, _)| buff).cloned()
        }

        pub fn get_last_sent_message(&self) -> Option<SipMessage> {
            self.last_buffer().map(|b| Parser::parse(&b).unwrap())
        }

        fn push_msg(&self, (buf_vec, address): (Vec<u8>, SocketAddr)) -> usize {
            let mut guard = self.sent.lock().unwrap();
            guard.push((buf_vec, address));
            guard.len()
        }
    }

    #[async_trait::async_trait]
    impl SipTransport for MockTransport {
        async fn send_msg(&self, buf: &[u8], address: &SocketAddr) -> crate::Result<usize> {
            let current_count = self.push_msg((buf.to_vec(), *address));

            if let Some(fail_at) = self.fail_at
                && fail_at == current_count
            {
                return Err(crate::Error::TransportError("Simulated failure".into()));
            }

            Ok(buf.len())
        }

        fn remote_addr(&self) -> Option<SocketAddr> {
            None
        }

        fn transport_type(&self) -> TransportType {
            self.tp_type
        }

        fn local_addr(&self) -> SocketAddr {
            self.addr
        }

        fn is_reliable(&self) -> bool {
            self.tp_type.is_reliable()
        }

        fn is_secure(&self) -> bool {
            self.tp_type.is_secure()
        }
    }
}
