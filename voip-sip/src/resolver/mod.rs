//! DNS resolve with the `SipDomainResolver` type.

use std::io;
use std::net::SocketAddr;

use tokio::net;
use utils::OneOrMore;

use crate::message::sip_uri::{Host, HostPort};
use crate::transport::TransportProtocol;

#[async_trait::async_trait]
pub trait SipDomainResolver: Send + Sync + 'static {
    async fn resolve(&self, target: &SipHost) -> io::Result<ServerAddresses>;
}

pub struct DefaultResolver;

#[async_trait::async_trait]
impl SipDomainResolver for DefaultResolver {
    async fn resolve(&self, target: &SipHost) -> io::Result<ServerAddresses> {
        let transport = match target.protocol {
            Some(protocol) => protocol,
            None => TransportProtocol::Udp,
        };
        let HostPort { ref host, port } = target.host_port;

        let lookup_address = match host {
            Host::HostName(host_name) => {
                let mut iter_addr = net::lookup_host(host_name.as_str()).await?;

                let Some(socket_addr) = iter_addr.next() else {
                    return Err(io::Error::other(format!(
                        "No address found for '{host_name}'"
                    )));
                };

                LookupAddress {
                    socket_addr,
                    transport,
                }
            }
            Host::IpAddr(ip_addr) => {
                let port = port.unwrap_or(transport.default_port());
                let socket_addr = SocketAddr::new(*ip_addr, port);

                LookupAddress {
                    socket_addr,
                    transport,
                }
            }
        };

        let addresses = OneOrMore::one(lookup_address);

        Ok(ServerAddresses { addresses })
    }
}

pub struct SipHost {
    host_port: HostPort,
    protocol: Option<TransportProtocol>,
}

pub struct LookupAddress {
    pub socket_addr: SocketAddr,
    pub transport: TransportProtocol,
}

pub struct ServerAddresses {
    addresses: OneOrMore<LookupAddress>,
}

impl SipHost {
    pub fn new(host_port: HostPort, protocol: Option<TransportProtocol>) -> Self {
        Self {
            host_port,
            protocol,
        }
    }
}

impl IntoIterator for ServerAddresses {
    type Item = LookupAddress;

    type IntoIter = utils::one::IntoIter<LookupAddress>;

    fn into_iter(self) -> Self::IntoIter {
        self.addresses.into_iter()
    }
}
