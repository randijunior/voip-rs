use std::net::{SocketAddr, ToSocketAddrs};
use std::sync::Arc;
use std::{io, mem};

use utils::DnsResolver;

use crate::endpoint::EndpointInner;
use crate::endpoint::module::{Module, Modules};
use crate::message::headers::{Accept, Allow, Header, Supported};
use crate::message::method::Method;
use crate::transport::tcp::TcpListener;
use crate::transport::udp::UdpTransport;
use crate::transport::ws::WebSocketListener;
use crate::transport::{SipTransport, Transport, TransportModule};
use crate::{Endpoint, MediaType, Result};

/// Builder for creating a new SIP `Endpoint`.
pub struct EndpointBuilder {
    name: String,
    resolver: DnsResolver,
    modules: Modules,
    allow: Allow,
    accept: Accept,
    supported: Supported,
    tcp: Vec<Box<dyn AddressResolver>>,
    udp: Vec<Box<dyn AddressResolver>>,
    ws: Vec<Box<dyn AddressResolver>>,
}

pub trait AddressResolver: Send + Sync {
    fn resolve(&self) -> io::Result<Vec<SocketAddr>>;
}

impl<T> AddressResolver for T
where
    T: ToSocketAddrs + Clone + Send + Sync + 'static,
{
    fn resolve(&self) -> io::Result<Vec<SocketAddr>> {
        self.to_socket_addrs().map(|iter| iter.collect())
    }
}

impl EndpointBuilder {
    pub fn new() -> Self {
        EndpointBuilder {
            name: String::new(),
            resolver: DnsResolver::default(),
            modules: Modules::default(),
            accept: Accept::default(),
            allow: Allow::default(),
            supported: Supported::default(),
            tcp: Default::default(),
            udp: Default::default(),
            ws: Default::default(),
        }
    }

    pub fn with_tcp_addr<A>(mut self, addr: A) -> EndpointBuilder
    where
        A: AddressResolver + 'static,
    {
        self.tcp.push(Box::new(addr));

        self
    }

    pub fn with_udp_addr<A>(mut self, addr: A) -> EndpointBuilder
    where
        A: AddressResolver + 'static,
    {
        self.udp.push(Box::new(addr));
        self
    }

    pub fn with_ws_addr<A>(mut self, addr: A) -> EndpointBuilder
    where
        A: AddressResolver + 'static,
    {
        self.ws.push(Box::new(addr));
        self
    }

    pub fn with_name(mut self, name: String) -> EndpointBuilder {
        self.name = name;

        self
    }

    pub fn with_module<M: Module>(mut self, module: M) -> EndpointBuilder {
        self.modules.add_module(module);

        self
    }

    pub fn insert_allow(&mut self, sip_method: Method) {
        self.allow.push(sip_method);
    }

    pub fn insert_accept(&mut self, media_type: MediaType) {
        self.accept.push(media_type);
    }

    pub fn insert_supported(&mut self, tag: String) {
        self.supported.add_tag(tag);
    }

    /// Finalize the Builder into a `Endpoint`.
    pub async fn build(mut self) -> Result<Endpoint> {
        log::trace!("Creating endpoint...");

        let mut modules = std::mem::take(&mut self.modules);

        for module in modules.iter_mut() {
            module.on_load(&mut self);
            log::debug!("Module {} loaded", format_args!("({})", module.name()));
        }

        let capabilities = crate::headers![
            Header::Allow(self.allow),
            Header::Supported(self.supported),
            Header::Accept(self.accept)
        ];

        let endpoint = Endpoint {
            inner: Arc::new(EndpointInner {
                transport: TransportModule::new(),
                name: self.name,
                capabilities,
                resolver: self.resolver,
                modules,
            }),
        };

        let mut tcp_resolvers = mem::take(&mut self.tcp);
        let mut udp_resolvers = mem::take(&mut self.udp);
        let mut ws_resolvers = mem::take(&mut self.ws);

        while let Some(resolver) = tcp_resolvers.pop() {
            for addr in resolver.resolve()? {
                let tcp = TcpListener::bind(addr).await?;
                log::info!(
                    "SIP TCP listener ready for incoming connections at: {}",
                    tcp.local_addr()
                );
                tokio::spawn(tcp.accept_clients(endpoint.clone()));
            }
        }

        while let Some(resolver) = udp_resolvers.pop() {
            for addr in resolver.resolve()? {
                let udp = UdpTransport::bind(addr).await?;
                log::info!("SIP UDP transport started, bound to: {}", udp.local_addr());
                endpoint
                    .transports()
                    .register_transport(Transport::new(udp.clone()));

                tokio::spawn(udp.receive_datagram(endpoint.clone()));
            }
        }

        while let Some(resolver) = ws_resolvers.pop() {
            for addr in resolver.resolve()? {
                let ws = WebSocketListener::bind(addr).await?;
                log::info!(
                    "SIP WS listener ready for incoming connections at: {}",
                    ws.local_addr()
                );
                tokio::spawn(ws.accept_clients(endpoint.clone()));
            }
        }

        Ok(endpoint)
    }
}

impl Default for EndpointBuilder {
    fn default() -> Self {
        Self::new()
    }
}
