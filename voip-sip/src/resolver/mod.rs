//! DNS resolve with the `SipDomainResolver` type.

use std::net::SocketAddr;
use std::{io, ops, sync};

pub use hickory_resolver::Name;
use tokio::net;
use utils::OneOrMore;

use crate::message::sip_uri::{Host, HostPort};
use crate::transport::TransportProtocol;

type IoResult<T> = io::Result<T>;

#[derive(Clone)]
pub struct DomainResolver(sync::Arc<dyn SipDomainResolver>);


impl<T: SipDomainResolver> From<T> for DomainResolver {
    fn from(value: T) -> Self {
        Self(std::sync::Arc::new(value))
    }
}

impl ops::Deref for DomainResolver {
    type Target = dyn SipDomainResolver;

    fn deref(&self) -> &Self::Target {
        &*self.0
    }
}

#[async_trait::async_trait]
pub trait SipDomainResolver: Send + Sync + 'static {
    async fn resolve(&self, target: &SipHost) -> IoResult<ServerAddresses>;
}

pub struct DefaultResolver;

#[async_trait::async_trait]
impl SipDomainResolver for DefaultResolver {
    async fn resolve(&self, target: &SipHost) -> IoResult<ServerAddresses> {
        let transport = match target.protocol {
            Some(protocol) => protocol,
            None => TransportProtocol::Udp,
        };
        let socket_addr = match target.host_port.host {
            Host::HostName(ref host_name) => {
                let mut iter_addr = net::lookup_host(host_name.as_str()).await?;

                iter_addr.next().unwrap_or(Err(io::Error::other(format!(
                    "No address found for '{host_name}'"
                )))?)
            }
            Host::IpAddr(ip_addr) => {
                let port = match target.host_port.port {
                    Some(port) => port,
                    None => transport.default_port(),
                };
                SocketAddr::new(ip_addr, port)
            }
        };

        let addresses = OneOrMore::one(LookupAddress {
            socket_addr,
            transport,
        });

        Ok(ServerAddresses { addresses })
    }
}

pub struct SipHost {
    pub host_port: HostPort,
    pub protocol: Option<TransportProtocol>,
}

pub struct LookupAddress {
    pub socket_addr: SocketAddr,
    pub transport: TransportProtocol,
}

pub struct ServerAddresses {
    addresses: OneOrMore<LookupAddress>,
}

impl IntoIterator for ServerAddresses {
    type Item = LookupAddress;

    type IntoIter = utils::one::IntoIter<LookupAddress>;

    fn into_iter(self) -> Self::IntoIter {
        self.addresses.into_iter()
    }
}
