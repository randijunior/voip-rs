use std::net::{SocketAddr, ToSocketAddrs};
use std::sync::Arc;

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

#[derive(Default)]
pub struct EndpointTransports {
    udp_addrs: Vec<SocketAddr>,
    tcp_addrs: Vec<SocketAddr>,
    ws_addrs: Vec<SocketAddr>,
}

impl EndpointTransports {
    async fn bind_udp(&self, addr: SocketAddr, endpoint: Endpoint) -> Result<()> {
        let udp = UdpTransport::bind(addr).await?;
        log::info!("SIP UDP transport started, bound to: {}", udp.local_addr());
        endpoint
            .transports()
            .register_transport(Transport::new(udp.clone()));
        tokio::spawn(udp.receive_datagram(endpoint));
        Ok(())
    }

    async fn bind_tcp(&self, addr: SocketAddr, endpoint: Endpoint) -> Result<()> {
        let tcp = TcpListener::bind(addr).await?;
        log::info!(
            "SIP TCP listener ready for incoming connections at: {}",
            tcp.local_addr()
        );
        tokio::spawn(tcp.accept_clients(endpoint));
        Ok(())
    }

    async fn bind_ws(&self, addr: SocketAddr, endpoint: Endpoint) -> Result<()> {
        let ws = WebSocketListener::bind(addr).await?;
        log::info!(
            "SIP WS listener ready for incoming connections at: {}",
            ws.local_addr()
        );
        tokio::spawn(ws.accept_clients(endpoint));
        Ok(())
    }

    pub fn add_udp<A: ToSocketAddrs>(&mut self, addr: A) -> crate::Result<()> {
        let addrs = addr.to_socket_addrs()?;
        for addr in addrs {
            self.udp_addrs.push(addr);
        }

        Ok(())
    }
    pub fn add_tcp<A: ToSocketAddrs>(&mut self, addr: A) -> crate::Result<()> {
        let addrs = addr.to_socket_addrs()?;
        for addr in addrs {
            self.tcp_addrs.push(addr);
        }

        Ok(())
    }
    pub fn add_ws<A: ToSocketAddrs>(&mut self, addr: A) -> crate::Result<()> {
        let addrs = addr.to_socket_addrs()?;
        for addr in addrs {
            self.ws_addrs.push(addr);
        }

        Ok(())
    }

    pub async fn bind(mut self, endpoint: Endpoint) -> crate::Result<()> {
        while let Some(addr) = self.udp_addrs.pop() {
            self.bind_udp(addr, endpoint.clone()).await?;
        }
        while let Some(addr) = self.tcp_addrs.pop() {
            self.bind_tcp(addr, endpoint.clone()).await?;
        }
        while let Some(addr) = self.ws_addrs.pop() {
            self.bind_ws(addr, endpoint.clone()).await?;
        }
        Ok(())
    }
}

/// Builder for creating a new SIP `Endpoint`.
pub struct EndpointBuilder {
    name: String,
    resolver: DnsResolver,
    modules: Modules,
    allow: Allow,
    accept: Accept,
    supported: Supported,
    transports: EndpointTransports,
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
            transports: EndpointTransports::default(),
        }
    }

    pub fn name(&mut self, name: String) -> &mut EndpointBuilder {
        self.name = name;

        self
    }

    pub fn module<M: Module>(&mut self, module: M) -> &mut EndpointBuilder {
        self.modules.add_module(module);

        self
    }

    pub fn transports(&mut self, transports: EndpointTransports) -> &mut EndpointBuilder {
        self.transports = transports;

        self
    }

    pub fn allow(&mut self, sip_method: Method) -> &mut EndpointBuilder {
        self.allow.push(sip_method);
        self
    }

    pub fn accept(&mut self, media_type: MediaType) -> &mut EndpointBuilder {
        self.accept.push(media_type);
        self
    }

    pub fn supported(&mut self, tag: String) -> &mut EndpointBuilder {
        self.supported.add_tag(tag);
        self
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
                modules: modules,
            }),
        };

        self.transports.bind(endpoint.clone()).await?;

        Ok(endpoint)
    }
}

impl Default for EndpointBuilder {
    fn default() -> Self {
        Self::new()
    }
}
