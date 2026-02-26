#![warn(missing_docs)]
//! SIP Endpoint

mod builder;
mod module;

pub use module::{ReceivedRequest, ReceivedResponse};
pub use module::Module;

pub use builder::EndpointBuilder;

use std::any::type_name;
use std::borrow::Cow;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use bytes::Bytes;
use tokio::net::ToSocketAddrs;

use utils::{DnsResolver, ToTake};


use crate::message::headers::{
    CSeq, Header, Headers, Route,
};
use crate::message::{
    DomainName, Host, MandatoryHeaders, NameAddr, ReasonPhrase, Request, Response, SipMessage,
    StatusCode, StatusLine, Uri,
};
use crate::transaction::manager::{TsxModule};
use crate::transaction::{ServerTransaction};
use crate::transport::incoming::{IncomingInfo, IncomingRequest, IncomingResponse};
use crate::transport::outgoing::{Encode, OutgoingRequest, OutgoingResponse, TargetTransportInfo};
use crate::transport::tcp::TcpListener;
use crate::transport::udp::UdpTransport;
use crate::transport::ws::WebSocketListener;
use crate::transport::{SipTransport, Transport, TransportModule, TransportMessage};
use crate::ua::dialog::UaModule;
use crate::endpoint::module::Modules;
use crate::{Result, Method};

struct EndpointInner {
    /// The transport module for the endpoint.
    transport: TransportModule,
    /// The name of the endpoint.
    name: String,
    /// The capability header list.
    capabilities: Headers,
    /// The resolver for DNS lookups.
    resolver: DnsResolver,
    /// The list of services registered.
    modules: Modules,
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
    /// # use voip::*;
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

    pub fn module<M: module::Module>(&self) -> &M {
        self.inner
            .modules
            .find_module()
            .ok_or_else(|| format!("endpoint missing module {}", type_name::<M>()))
            .unwrap()
    }

    pub async fn respond(
        &self,
        request: &IncomingRequest,
        code: StatusCode,
        reason: Option<ReasonPhrase>,
    ) -> Result<()> {
        let mut response = self.create_response(request, code, reason);

        self.send_response(&mut response).await?;

        Ok(())
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
    pub async fn send_request(&self, request: &mut OutgoingRequest) -> Result<()> {
        if request.encoded.is_empty() {
            request.encoded = request.encode()?;
        }

        log::debug!(
            "Sending Request {} {} to /{}",
            request.request.req_line.method,
            request.request.req_line.uri,
            request.target_info.target
        );

        for module in self.inner.modules.modules() {
            module.on_send_request(request).await;
        }

        request
            .target_info
            .transport
            .send_msg(&request.encoded, &request.target_info.target)
            .await?;

        Ok(())
    }

    pub async fn send_response(&self, response: &mut OutgoingResponse) -> Result<()> {
        if response.encoded.is_empty() {
            response.encoded = response.encode()?;
        }
        log::debug!(
            "Sending Response {} {} to /{}",
            response.status().as_u16(),
            response.reason().as_str(),
            response.target_info.target
        );

        for module in self.inner.modules.modules() {
            module.on_send_response(response).await;
        }

        response
            .target_info
            .transport
            .send_msg(&response.encoded, &response.target_info.target)
            .await?;

        Ok(())
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

    pub async fn start_ws_transport<A: ToSocketAddrs>(&self, addr: A) -> Result<()> {
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
                self.on_request(IncomingRequest {
                    request,
                    incoming_info: Box::new(info),
                })
                .await?;
            }
            Ok(SipMessage::Response(response)) => {
                let mut headers: MandatoryHeaders = response.headers().try_into()?;
                // 4. Server Behavior
                // the server MUST insert a "received" parameter containing the source
                // IP address that the request came from.
                headers.via.received = message.packet.source.ip().into();
                let info = IncomingInfo {
                    mandatory_headers: headers,
                    transport: message,
                };
                self.on_response(IncomingResponse {
                    response,
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

    pub(crate) async fn lookup_address(&self, host: &Host) -> Result<IpAddr> {
        match host {
            Host::DomainName(domain) => self.dns_lookup(domain).await,
            Host::IpAddr(ip) => Ok(*ip),
        }
    }

    async fn on_response(&self, response: IncomingResponse) -> Result<()> {
        log::debug!(
            "<= Response ({} {})",
            response.status().as_u16(),
            response.reason().as_str()
        );

        let mut response = Some(response);

        for module in self.inner.modules.modules() {
            module
                .on_receive_response(ReceivedResponse::new(ToTake::new(&mut response)), self)
                .await;

            if response.is_none() {
                break;
            }
        }

        if let Some(response) = response {
            log::info!(
                "Response ({} {}) from /{} was unhandled by any module",
                response.status().as_u16(),
                response.reason().as_str(),
                response.incoming_info.transport.packet.source
            );
        }
        Ok(())
    }

    async fn on_request(&self, request: IncomingRequest) -> Result<()> {
        log::debug!(
            "<= Request {} from /{}",
            request.request.method(),
            request.incoming_info.transport.packet.source
        );

        let mut request = Some(request);

        for module in self.inner.modules.modules() {
            module
                .on_receive_request(module::ReceivedRequest::new(ToTake::new(&mut request)), self)
                .await;

            if request.is_none() {
                break;
            }
        }

        if let Some(msg) = request {
            log::debug!(
                "Request ({}, cseq={}) from /{} was unhandled",
                msg.request.method(),
                msg.incoming_info.mandatory_headers.cseq.cseq,
                msg.incoming_info.transport.packet.source
            );
        }

        Ok(())
    }

    pub(crate) fn dns_resolver(&self) -> &DnsResolver {
        &self.inner.resolver
    }

    pub(crate) fn transports(&self) -> &TransportModule {
        &self.inner.transport
    }

    pub(crate) fn transactions(&self) -> &TsxModule {
        self.module::<TsxModule>()
    }

    pub(crate) fn dialogs(&self) -> &UaModule {
        self.module::<UaModule>()
    }
}
