#![warn(missing_docs)]
//! SIP Endpoint

use std::borrow::Cow;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

pub use builder::EndpointBuilder;
use bytes::Bytes;
use tokio::net::ToSocketAddrs;
use tokio::sync::mpsc;
use utils::DnsResolver;
use uuid::Uuid;

use crate::error::TransactionError;
use crate::message::headers::{
    CSeq, CallId, Contact, From, Header, Headers, MaxForwards, Route, To, Via,
};
use crate::message::{
    CodeClass, DomainName, Host, HostPort, MandatoryHeaders, NameAddr, ReasonPhrase, Request,
    RequestLine, Response, SipBody, SipMessage, SipUri, StatusCode, StatusLine, Uri, UriBuilder,
};
use crate::transaction::manager::{TransactionKey, TransactionManager};
use crate::transaction::{ClientTransaction, ServerTransaction, TransactionMessage};
use crate::transport::incoming::{IncomingInfo, IncomingRequest, IncomingResponse};
use crate::transport::outgoing::{Encode, OutgoingRequest, OutgoingResponse, TargetTransportInfo};
use crate::transport::tcp::TcpListener;
use crate::transport::udp::UdpTransport;
use crate::transport::ws::WebSocketListener;
use crate::transport::{SipTransport, Transport, TransportManager, TransportMessage};
use crate::ua::UA;
use crate::ua::dialog::Dialog;
use crate::{Method, Result};

mod builder;

/// A trait which provides a way to extend the SIP endpoint functionalities.
#[async_trait::async_trait]
#[allow(unused_variables)]
pub trait EndpointHandler: Sync + Send + 'static {
    /// Called when an inbound SIP request is received.
    async fn handle(&self, request: IncomingRequest, endpoint: &Endpoint);
}

struct EndpointInner {
    /// The transport layer for the endpoint.
    transport: TransportManager,
    /// The transaction layer for the endpoint.
    transaction: Option<TransactionManager>,
    /// The name of the endpoint.
    name: String,
    /// The capability header list.
    capabilities: Headers,
    /// The resolver for DNS lookups.
    resolver: DnsResolver,
    /// The list of services registered.
    handler: Option<Box<dyn EndpointHandler>>,
    user_agent: Option<UA>,
}

/// A SIP endpoint.
#[derive(Clone)]
pub struct Endpoint {
    inner: Arc<EndpointInner>,
}

impl Endpoint {
    /// Returns a EndpointBuilder to create an `Endpoint`.
    ///
    /// # Examples
    ///
    /// ```
    /// # use csip::*;
    /// let endpoint = endpoint::EndpointBuilder::new()
    ///     .with_name("My Endpoint")
    ///     .build();
    /// ```
    pub fn builder() -> EndpointBuilder {
        EndpointBuilder::default()
    }

    /// Get the endpoint name.
    pub fn get_name(&self) -> &String {
        &self.inner.name
    }

    /// Creates a new SIP response based on an incoming
    /// request.
    ///
    /// This method generates a response message with the specified status code
    /// and reason phrase. It also sets the necessary headers from request,
    /// including `Call-ID`, `From`, `To`, `CSeq`, `Via` and
    /// `Record-Route` headers.
    pub fn create_response(
        &self,
        request: &IncomingRequest,
        code: StatusCode,
        reason: Option<ReasonPhrase>,
    ) -> OutgoingResponse {
        let all_hdrs = &request.request.headers;
        let mandatory_headers = &request.incoming_info.mandatory_headers;

        // Copy the necessary headers from the request.
        let mut headers = Headers::with_capacity(7);

        // `Via` header.
        let topmost_via = mandatory_headers.via.clone();
        headers.push(Header::Via(topmost_via));
        let other_vias = all_hdrs
            .iter()
            .filter(|h| matches!(h, Header::Via(_)))
            .skip(1);
        headers.extend(other_vias.cloned());

        // `Record-Route` header.
        let rr = all_hdrs
            .iter()
            .filter(|h| matches!(h, Header::RecordRoute(_)));
        headers.extend(rr.cloned());

        // `Call-ID` header.
        headers.push(Header::CallId(mandatory_headers.call_id.clone()));

        // `From` header.
        headers.push(Header::From(mandatory_headers.from.clone()));

        // `To` header.
        let mut to = mandatory_headers.to.clone();
        // 8.2.6.2 Headers and Tags
        // The UAS MUST add a tag to the To header field in
        // the response (with the exception of the 100 (Trying)
        // response, in which a tag MAY be present).
        if to.tag().is_none() && code.as_u16() > 100 {
            to.set_tag(mandatory_headers.via.branch.clone());
        }
        headers.push(Header::To(to));

        // `CSeq` header.
        headers.push(Header::CSeq(mandatory_headers.cseq));

        let reason = match reason {
            None => code.reason(),
            Some(reason) => reason.into(),
        };
        let status_line = StatusLine::new(code, reason);
        let response = Response::with_headers(status_line, headers);

        // Done.
        OutgoingResponse {
            response,
            target_info: TargetTransportInfo {
                target: request.incoming_info.transport.packet.source,
                transport: request.incoming_info.transport.transport.clone(),
            },
            encoded: Bytes::new(),
        }
    }

    pub fn new_server_transaction(&self, request: IncomingRequest) -> ServerTransaction {
        ServerTransaction::new(request, self.clone())
    }

    pub(crate) fn create_ack_request(
        &self,
        outgoing: &OutgoingRequest,
        response: &IncomingResponse,
    ) -> OutgoingRequest {
        assert!(
            matches!(response.status().as_u16(), 300..699),
            "message must be a 300-699 final response"
        );
        let target = outgoing.request.req_line.uri.clone();
        // Clone: Via, To, From, Max-Forwards, Call-ID and CSeq from response.
        let headers = MandatoryHeaders {
            cseq: CSeq {
                method: Method::Ack,
                ..response.incoming_info.mandatory_headers.cseq
            },
            ..response.incoming_info.mandatory_headers.clone()
        }
        .into_headers();

        let request = Request::with_headers(Method::Ack, target, headers);
        let target_info = outgoing.target_info.clone();

        OutgoingRequest {
            request,
            target_info,
            encoded: Bytes::new(),
        }
    }

    /// Send the request.
    pub async fn send_outgoing_request(&self, request: &mut OutgoingRequest) -> Result<()> {
        if request.encoded.is_empty() {
            request.encoded = request.encode()?;
        }

        log::debug!(
            "Sending Request {} {} to /{}",
            request.request.req_line.method,
            request.request.req_line.uri,
            request.target_info.target
        );

        request
            .target_info
            .transport
            .send_msg(&request.encoded, &request.target_info.target)
            .await?;

        Ok(())
    }

    pub async fn send_outgoing_response(&self, response: &mut OutgoingResponse) -> Result<()> {
        if response.encoded.is_empty() {
            response.encoded = response.encode()?;
        }
        log::debug!(
            "Sending Response {} {} to /{}",
            response.status().as_u16(),
            response.reason().as_str(),
            response.target_info.target
        );

        response
            .target_info
            .transport
            .send_msg(&response.encoded, &response.target_info.target)
            .await?;

        Ok(())
    }

    // https://www.rfc-editor.org/rfc/rfc3261#section-8.1.1
    // A valid SIP request formulated by a UAC MUST, at a minimum, contain
    // the following header fields: To, From, CSeq, Call-ID, Max-Forwards,
    // and Via
    fn ensure_mandatory_headers(&self, request: &mut Request, target_info: &TargetTransportInfo) {
        let mut headers: [Option<Header>; 6] = [const { None }; 6];
        let TargetTransportInfo { target, transport } = target_info;
        let request_headers = &mut request.headers;

        let mut exists_via = false;
        let mut exists_cseq = false;
        let mut exists_from = false;
        let mut exists_call_id = false;
        let mut exists_to = false;
        let mut exists_max_fowards = false;

        for header in request_headers.iter() {
            match header {
                Header::Via(_) if !exists_via => exists_via = true,
                Header::From(_) => exists_from = true,
                Header::To(_) => exists_to = true,
                Header::CallId(_) => exists_call_id = true,
                Header::CSeq(_) => exists_cseq = true,
                Header::MaxForwards(_) => exists_max_fowards = true,
                _ => (),
            }
        }

        if !exists_via {
            let sent_by = transport.local_addr().into();
            let transport = transport.transport_type();
            let branch = crate::generate_branch();
            let via = Via::new_with_transport(transport, sent_by, Some(branch));

            headers[0] = Some(Header::Via(via));
        }

        if !exists_from {
            let host = transport.local_addr().into();
            let uri = UriBuilder::new()
                .with_host(host)
                .with_scheme(request.req_line.uri.scheme)
                .build();
            let name_adddr = NameAddr::new(uri);
            let from = From::new(SipUri::NameAddr(name_adddr));

            headers[1] = Some(Header::From(from));
        }

        if !exists_to {
            let to_uri = request.req_line.uri.clone();
            let name_addr = NameAddr::new(to_uri);
            let to = To::new(SipUri::NameAddr(name_addr));

            headers[2] = Some(Header::To(to));
        }

        if !exists_cseq {
            let cseq = CSeq::new(1, request.req_line.method);

            headers[3] = Some(Header::CSeq(cseq));
        }

        if !exists_call_id {
            let id = Uuid::new_v4();
            let call_id_str = format!("{}@{}", id, transport.local_addr());
            let call_id = CallId::new(call_id_str);

            headers[4] = Some(Header::CallId(call_id));
        }

        if !exists_max_fowards {
            let max_forwards = MaxForwards::new(70);

            headers[5] = Some(Header::MaxForwards(max_forwards));
        }

        let new_headers = headers.into_iter().flatten();

        request_headers.splice(0..0, new_headers);
    }

    fn process_route_set<'a>(&self, request: &'a mut Request) -> Cow<'a, Uri> {
        let topmost_route = request
            .headers
            .iter_mut()
            .position(
                |header| matches!(header, Header::Route(route) if !route.name_addr.uri.lr_param),
            )
            .map(|index| {
                request
                    .headers
                    .remove(index)
                    .into_route()
                    .expect("The header must be a Route")
            });

        if topmost_route.is_some() {
            let name_addr = NameAddr::new(request.req_line.uri.clone());
            let route = Header::Route(Route {
                name_addr,
                param: None,
            });
            let index = request
                .headers
                .iter()
                .rposition(|h| matches!(h, Header::Route(_)));

            if let Some(index) = index {
                request.headers.insert(index, route);
            } else {
                request.headers.push(route);
            }
        }

        topmost_route
            .map(|route| Cow::Owned(route.name_addr.uri))
            .unwrap_or(Cow::Borrowed(&request.req_line.uri))
    }

    // RFC 3263 - 4.1 Selecting a Transport Protocol (UDP/TCP/TLS)
    // RFC 3263 - 4.2 Determining Port and IP Address (SRV/A/AAAA)
    // RFC 3261 - 12.2.1.1 Generating the Request
    // RFC 3261 - 8.1.1 Generating the Request
    // RFC 3261 - 8.1.2 Sending the Request
    pub(crate) async fn create_outgoing_request(
        &self,
        mut request: Request,
        target: Option<(Transport, SocketAddr)>,
    ) -> Result<OutgoingRequest> {
        let (transport, target) = if let Some(target) = target {
            target
        } else {
            let new_request_uri = self.process_route_set(&mut request);
            self.transports()
                .select_transport(self, &new_request_uri)
                .await?
        };

        log::debug!(
            "Resolved target: transport={}, addr={}",
            transport.transport_type(),
            target
        );

        let target_info = TargetTransportInfo { target, transport };

        self.ensure_mandatory_headers(&mut request, &target_info);

        Ok(OutgoingRequest {
            request,
            target_info,
            encoded: bytes::Bytes::new(),
        })
    }

    pub async fn start_udp_transport<A: ToSocketAddrs>(&self, addr: A) -> Result<()> {
        let udp = UdpTransport::bind(addr).await?;
        log::info!("SIP UDP transport started, bound to: {}", udp.local_addr());
        self.transports()
            .register_transport(Transport::new(udp.clone()))?;
        tokio::spawn(udp.receive_datagram(self.clone()));
        Ok(())
    }

    pub async fn start_tcp_transport<A: ToSocketAddrs>(&self, addr: A) -> Result<()> {
        let tcp = TcpListener::bind(addr).await?;
        log::info!(
            "SIP TCP listener ready for incoming connections at: {}",
            tcp.local_addr()
        );
        tokio::spawn(tcp.accept_clients(self.clone()));
        Ok(())
    }

    pub async fn start_ws_transport(&self, addr: SocketAddr) -> Result<()> {
        let ws = WebSocketListener::bind(addr).await?;
        log::info!(
            "SIP WS listener ready for incoming connections at: {}",
            ws.local_addr()
        );
        tokio::spawn(ws.accept_clients(self.clone()));
        Ok(())
    }

    pub(crate) fn receive_transport_message(&self, message: TransportMessage) {
        tokio::spawn({
            let endpoint = self.clone();
            async move {
                if let Err(err) = endpoint.process_transport_message(message).await {
                    log::error!("Error on process transport message: {}", err);
                }
            }
        });
    }

    async fn process_transport_message(self, message: TransportMessage) -> Result<()> {
        match message.parse() {
            Ok(SipMessage::Request(request)) => {
                let mut headers: MandatoryHeaders = (&request.headers).try_into()?;
                // 4. Server Behavior
                // the server MUST insert a "received" parameter containing the source
                // IP address that the request came from.
                headers.via.received = message.packet.source.ip().into();
                let info = IncomingInfo {
                    mandatory_headers: headers,
                    transport: message,
                };
                self.process_request(IncomingRequest {
                    request,
                    incoming_info: Box::new(info),
                })
                .await?;
            }
            Ok(SipMessage::Response(res)) => {
                let mut headers: MandatoryHeaders = res.headers().try_into()?;
                // 4. Server Behavior
                // the server MUST insert a "received" parameter containing the source
                // IP address that the request came from.
                headers.via.received = message.packet.source.ip().into();
                let info = IncomingInfo {
                    mandatory_headers: headers,
                    transport: message,
                };
                self.process_response(IncomingResponse {
                    response: res,
                    incoming_info: Box::new(info),
                })
                .await?;
            }
            Err(err) => log::error!("ERR = {:#?}", err),
        }

        Ok(())
    }

    pub(crate) async fn dns_lookup(&self, domain: &DomainName) -> Result<IpAddr> {
        Ok(self.inner.resolver.resolve(domain.as_str()).await?)
    }

    pub(crate) fn dns_resolver(&self) -> &DnsResolver {
        &self.inner.resolver
    }

    pub(crate) async fn lookup_address(&self, host: &Host) -> Result<IpAddr> {
        match host {
            Host::DomainName(domain) => self.dns_lookup(domain).await,
            Host::IpAddr(ip) => Ok(*ip),
        }
    }

    // https://datatracker.ietf.org/doc/html/rfc3261#section-18.2.2
    // https://datatracker.ietf.org/doc/html/rfc3581s
    pub async fn get_outbound_addr(
        &self,
        via: &Via,
        transport: &Transport,
    ) -> Result<(SocketAddr, Transport)> {
        if transport.is_reliable() {
            // Tcp, TLS, etc..
            return Ok((transport.remote_addr().unwrap(), transport.clone()));
        }

        if let Some(maddr) = &via.maddr {
            let port = via.sent_by.port.unwrap_or(5060);
            let ip = self.lookup_address(maddr).await?;
            let addr = SocketAddr::new(ip, port);

            return Ok((addr, transport.clone()));
        } else if let Some(rport) = via.rport {
            let ip = via.received.unwrap();
            let addr = SocketAddr::new(ip, rport);
            return Ok((addr, transport.clone()));
        } else {
            let ip = via
                .received
                .expect("Missing received parameter on 'Via' header");
            let port = via.sent_by.port.unwrap_or(5060);
            let addr = SocketAddr::new(ip, port);
            return Ok((addr, transport.clone()));
        }
    }

    pub(crate) async fn process_response(&self, response: IncomingResponse) -> Result<()> {
        log::debug!(
            "<= Response ({} {})",
            response.status().as_u16(),
            response.reason().as_str()
        );

        let response = match self.inner.transaction {
            Some(ref tsx_layer) => tsx_layer.handle_response(response).await,
            None => Some(response),
        };

        if let Some(response) = response {
            log::info!(
                "Response ({} {}) from /{} was unhandled",
                response.status().as_u16(),
                response.reason().as_str(),
                response.incoming_info.transport.packet.source
            );
        }
        Ok(())
    }

    pub(crate) async fn dispatch_to_server_transaction(
        &self,
        request: IncomingRequest,
    ) -> Option<IncomingRequest> {
        match self.inner.transaction {
            Some(ref tsx_layer) => tsx_layer.receive(request).await,
            None => Some(request),
        }
    }

    pub(crate) async fn process_request(&self, request: IncomingRequest) -> Result<()> {
        log::debug!(
            "<= Request {} from /{}",
            request.request.method(),
            request.incoming_info.transport.packet.source
        );

        let msg = match self.inner.transaction {
            Some(ref tsx_layer) => tsx_layer.receive(request).await,
            None => Some(request),
        };

        let Some(msg) = msg else {
            return Ok(());
        };

        if let Some(handler) = &self.inner.handler {
            handler.handle(msg, self).await;
        } else {
            log::debug!(
                "Request ({}, cseq={}) from /{} was unhandled",
                msg.request.method(),
                msg.incoming_info.mandatory_headers.cseq.cseq,
                msg.incoming_info.transport.packet.source
            );
        }

        Ok(())
    }

    pub(crate) fn transactions(&self) -> &TransactionManager {
        self.inner
            .transaction
            .as_ref()
            .expect("Transaction Manager not set")
    }

    pub(crate) fn register_transaction(
        &self,
        key: TransactionKey,
        entry: mpsc::Sender<TransactionMessage>,
    ) {
        self.transactions().add_transaction(key, entry);
    }

    pub(crate) fn transports(&self) -> &TransportManager {
        &self.inner.transport
    }

    pub(crate) fn create_uas_dialog(
        &self,
        request: &IncomingRequest,
        contact: Contact,
    ) -> Result<Dialog> {
        self.ua().create_uas_dialog(request, contact, self.clone())
    }

    pub(crate) fn ua(&self) -> &UA {
        self.inner.user_agent.as_ref().expect("User Agent not set")
    }
}
