//! Transport layer.
//!
//! This module defines different transport protocols used to
//! exchange SIP messages between entities.
//!
//! All transports implement the [`SipTransport`] trait and expose a
//! common interface for sending and receiving SIP messages.
//!
//! The [`Transport`] struct is a wrapper around any transport implementation
//! that allows for easy management of different transport types.
//!
//! # Available Transports
//!
//! - [`udp`]: SIP over UDP transport implementation.
//! - [`tcp`]: SIP over TCP transport implementation.
//! - [`ws`]:  SIP over WebSocket transport implementation.

use std::collections::HashMap;
use std::fmt::{self, Formatter, Result as FmtResult};
use std::io::{self};
use std::net::{IpAddr, SocketAddr};
use std::ops;
use std::result::Result as StdResult;
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

use async_trait::async_trait;
use bytes::Bytes;
use utils::{NAPTR, Name, RData, SRV};

use crate::Endpoint;
use crate::error::{Error, Result};
use crate::message::SipMessage;
use crate::message::uri::{DomainName, Host, Scheme, Uri};
use crate::parser::Parser;
use crate::transport::tcp::TcpTransport;
use crate::transport::ws::WebSocketTransport;

// Core Transport modules
mod decode;

pub mod incoming;
pub mod outgoing;
pub mod tcp;
pub mod udp;
pub mod ws;

/// Keep-alive Request.
pub const KEEPALIVE_REQUEST: &[u8] = b"\r\n\r\n";

/// Keep-alive Response.
pub const KEEPALIVE_RESPONSE: &[u8] = b"\r\n";

/// Marks the end of headers in a SIP message.
pub const MSG_HEADERS_END: &[u8] = b"\r\n\r\n";

/// Type alias for a map of transports.
pub(crate) type TransportsMap = HashMap<TransportKey, Transport>;

/// This type is a wrapper around a SIP transport implementation.
#[derive(Clone)]
pub struct Transport {
    /// Shared transport instance.
    shared: Arc<dyn SipTransport>,
}

impl Transport {
    /// Creates a new `Transport` instance with the given implementation.
    pub fn new(transport: impl SipTransport) -> Self {
        Transport {
            shared: Arc::new(transport),
        }
    }
}

impl ops::Deref for Transport {
    type Target = dyn SipTransport;

    fn deref(&self) -> &Self::Target {
        &*self.shared
    }
}

/// Manager for SIP all transports.
pub struct TransportManager {
    /// All transports indexed by their unique keys.
    transports: Mutex<TransportsMap>,
}

impl From<TransportsMap> for TransportManager {
    fn from(value: TransportsMap) -> Self {
        Self {
            transports: Mutex::new(value),
        }
    }
}

impl TransportManager {
    /// Create a new `TransportManager` instance.
    pub fn new() -> Self {
        TransportManager {
            transports: Mutex::new(HashMap::new()),
        }
    }

    /// Add a new transport to the manager.
    pub fn register_transport(&self, transport: Transport) -> Result<()> {
        let key = transport.key();
        let mut map = self.transports.lock().map_err(|_| Error::PoisonedLock)?;

        map.insert(key, transport);

        Ok(())
    }

    /// Remove a transport by its key.
    pub fn remove_transport(&self, key: &TransportKey) -> Result<()> {
        let mut map = self.transports.lock().map_err(|_| Error::PoisonedLock)?;

        map.remove(key);

        Ok(())
    }

    /// Select a suitable transport for the given `Uri`.
    pub async fn select_transport(
        &self,
        endpoint: &Endpoint,
        uri: &Uri,
    ) -> Result<(Transport, SocketAddr)> {
        let target = uri.maddr_param.as_ref().unwrap_or(&uri.host_port.host);
        let port = uri.host_port.port;

        match uri.transport_param {
            Some(transport) => {
                // 1. If transport parameter is specified it takes precedence.
                let port = port.unwrap_or(transport.default_port());
                let ip = endpoint.lookup_address(target).await?;
                let addr = SocketAddr::new(ip, port);
                let transport = self
                    .get_or_create_transport(transport, addr, endpoint)
                    .await?;
                Ok((transport, addr))
            }
            None => match target {
                Host::IpAddr(ip_addr) => {
                    // 2. If no transport parameter and target is an IP address then sip should use
                    // udp and sips tcp.
                    let transport = TransportType::from_scheme(uri.scheme);
                    let port = port.unwrap_or(transport.default_port());
                    let addr = SocketAddr::new(*ip_addr, port);
                    let transport = self
                        .get_or_create_transport(transport, addr, endpoint)
                        .await?;
                    return Ok((transport, addr));
                }
                Host::DomainName(domain) => {
                    if let Some(port) = port {
                        // 3. If no transport parameter and target is a host name with an explicit port
                        // then sip should use udp and sips tcp and host should be resolved using an A
                        // or AAAA record DNS lookup (section 4.2)
                        let transport = TransportType::from_scheme(uri.scheme);
                        let ip = endpoint.dns_lookup(domain).await?;
                        let addr = SocketAddr::new(ip, port);
                        let transport = self
                            .get_or_create_transport(transport, addr, endpoint)
                            .await?;
                        Ok((transport, addr))
                    } else {
                        // 4. If no transport protocol and no explicit port and target is a host name then
                        // the client should do an NAPTR lookup.
                        if let Ok(Some((transport, addr))) =
                            self.perform_natptr_query(endpoint, domain).await
                        {
                            return Ok((transport, addr));
                        } else {
                            let name = domain.as_str();
                            let records = [
                                (
                                    Name::from_utf8(format!("_sips._tcp.{name}")).unwrap(),
                                    TransportType::Tls,
                                ),
                                (
                                    Name::from_utf8(format!("_sip._udp.{name}")).unwrap(),
                                    TransportType::Udp,
                                ),
                                (
                                    Name::from_utf8(format!("_sip._tcp.{name}")).unwrap(),
                                    TransportType::Tcp,
                                ),
                            ];

                            for (record, protocol) in records {
                                let srv_lookup = endpoint.dns_resolver().srv_lookup(record).await;
                                let Ok(srv_lookup) = srv_lookup else {
                                    continue;
                                };
                                if srv_lookup.records().len() == 0 {
                                    continue;
                                }

                                let srv_records: Vec<&SRV> = srv_lookup
                                    .record_iter()
                                    .filter_map(|record| match record.data() {
                                        RData::SRV(srv) => Some(srv),
                                        _ => None,
                                    })
                                    .collect();

                                for record in srv_records {
                                    let port = record.port();
                                    let target = record.target();
                                    let lookup =
                                        endpoint.dns_resolver().lookup_ip(target.clone()).await;
                                    let Ok(lookup) = lookup else {
                                        continue;
                                    };
                                    for ip in lookup {
                                        let addr = SocketAddr::new(ip, port);
                                        match self
                                            .get_or_create_transport(protocol, addr, endpoint)
                                            .await
                                        {
                                            Ok(transport) => return Ok((transport, addr)),
                                            Err(_) => continue,
                                        }
                                    }
                                }
                            }

                            let ip = endpoint.dns_lookup(domain).await?;
                            let transport = TransportType::from_scheme(uri.scheme);
                            let port = transport.default_port();
                            let addr = SocketAddr::new(ip, port);
                            let transport = self
                                .get_or_create_transport(transport, addr, endpoint)
                                .await?;
                            Ok((transport, addr))
                        }
                    }
                }
            },
        }
    }
    /// Implements RFC 3263 §4.1 and §4.2
    async fn perform_natptr_query(
        &self,
        endpoint: &Endpoint,
        target: &DomainName,
    ) -> Result<Option<(Transport, SocketAddr)>> {
        let lookup = endpoint
            .dns_resolver()
            .naptr_lookup(target.as_str())
            .await?;
        let naptr_records: Vec<&NAPTR> = lookup
            .record_iter()
            .filter_map(|record| match record.data() {
                RData::NAPTR(naptr) => Some(naptr),
                _record_data => None,
            })
            .collect();
        if naptr_records.is_empty() {
            return Ok(None);
        }
        for record in naptr_records {
            // If NAPTR record(s) are found select the desired transport and lookup the SRV record.
            let Some(transport) = TransportType::from_naptr_service(record.services()) else {
                continue;
            };
            match record.flags() {
                b"s" => {
                    let srv_records = endpoint
                        .dns_resolver()
                        .srv_lookup(record.replacement().clone())
                        .await?;
                    let srv_records: Vec<&SRV> = srv_records
                        .record_iter()
                        .filter_map(|record| match record.data() {
                            RData::SRV(srv) => Some(srv),
                            _ => None,
                        })
                        .collect();

                    for record in srv_records {
                        let port = record.port();
                        let target = record.target();
                        let lookup = endpoint
                            .dns_resolver()
                            .lookup_ip(target.clone())
                            .await
                            .map_err(|err| {
                                io::Error::other(format!("Failed to lookup DNS: {}", err))
                            })?;
                        for ip in lookup {
                            let addr = SocketAddr::new(ip, port);
                            match self
                                .get_or_create_transport(transport, addr, endpoint)
                                .await
                            {
                                Ok(transport) => return Ok(Some((transport, addr))),
                                Err(_) => continue,
                            }
                        }
                    }

                    return Ok(None);
                }
                b"a" => todo!("resolve_a_records"),
                _ => todo!(""),
            }
        }

        Ok(None)
    }

    fn get_by_key(&self, key: &TransportKey) -> Result<Option<Transport>> {
        let map = self.transports.lock().map_err(|_| Error::PoisonedLock)?;
        Ok(map.get(key).cloned())
    }

    fn get_by_transport_type_and_ip_family(
        &self,
        protocol: TransportType,
        ip: IpAddr,
    ) -> Result<Option<Transport>> {
        let map = self.transports.lock().map_err(|_| Error::PoisonedLock)?;
        let transport = map.iter().find(|(_key, transport)| {
            transport.transport_type() == protocol
                && is_same_ip_family(&transport.local_addr().ip(), &ip)
        });

        match transport {
            Some((_addr, transport)) => return Ok(Some(transport.clone())),
            None => Ok(None),
        }
    }

    async fn get_or_create_transport(
        &self,
        protocol: TransportType,
        addr: SocketAddr,
        endpoint: &Endpoint,
    ) -> Result<Transport> {
        let key = TransportKey::new(addr, protocol);
        if let Some(transport) = self.get_by_key(&key)? {
            return Ok(transport.clone());
        }
        let transport = match protocol {
            TransportType::Tcp => TcpTransport::connect(addr, endpoint).await?,
            TransportType::Ws | TransportType::Wss => {
                let scheme = if protocol == TransportType::Ws {
                    "ws"
                } else {
                    "wss"
                };
                let url = format!("{scheme}://{addr}");
                WebSocketTransport::connect(&url, 1.0, endpoint).await?
            }
            TransportType::Udp => self
                .get_by_transport_type_and_ip_family(TransportType::Udp, addr.ip())?
                .ok_or(Error::UnsupportedTransport)?,
            _ => return Err(Error::UnsupportedTransport),
        };

        self.register_transport(transport.clone())?;

        Ok(transport)
    }

    /// Return the number of transports registered.
    pub fn transport_count(&self) -> Result<usize> {
        let map = self.transports.lock().map_err(|_| Error::PoisonedLock)?;

        Ok(map.len())
    }
}

/// Represents the type of transport.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TransportType {
    /// Udp.
    Udp,
    /// Tcp.
    Tcp,
    /// WebSocket.
    Ws,
    /// Websocket with tls.
    Wss,
    /// Tcp with tls
    Tls,
    /// Sctp.
    Sctp,
}

impl TransportType {
    /// Returns true if the transport is reliable.
    pub fn is_reliable(self) -> bool {
        matches!(
            self,
            Self::Tcp | Self::Tls | Self::Sctp | Self::Wss | Self::Ws
        )
    }

    pub(crate) fn from_naptr_service(service: &[u8]) -> Option<Self> {
        match service {
            b"SIP+D2U" => Some(Self::Udp),
            b"SIP+D2T" => Some(Self::Tcp),
            b"SIPS+D2T" => Some(Self::Tls),
            _ => None,
        }
    }
    pub(crate) fn from_scheme(scheme: Scheme) -> Self {
        match scheme {
            Scheme::Sip => Self::Udp,
            Scheme::Sips => Self::Tcp,
        }
    }

    /// Returns true if the transport is secure.
    pub fn is_secure(self) -> bool {
        matches!(self, Self::Tls | Self::Wss)
    }

    /// Returns the default port number associated with the transport.
    #[inline]
    pub const fn default_port(&self) -> u16 {
        match self {
            Self::Udp | Self::Tcp | Self::Sctp => 5060,
            Self::Tls => 5061,
            Self::Ws | Self::Wss => 80,
        }
    }
}

impl FromStr for TransportType {
    type Err = ();

    fn from_str(s: &str) -> StdResult<Self, Self::Err> {
        match s {
            s if s.eq_ignore_ascii_case("udp") => Ok(Self::Udp),
            s if s.eq_ignore_ascii_case("tcp") => Ok(Self::Tcp),
            s if s.eq_ignore_ascii_case("ws") => Ok(Self::Ws),
            s if s.eq_ignore_ascii_case("wss") => Ok(Self::Wss),
            s if s.eq_ignore_ascii_case("tls") => Ok(Self::Tls),
            s if s.eq_ignore_ascii_case("sctp") => Ok(Self::Sctp),
            _ => Err(()),
        }
    }
}

impl TryFrom<&str> for TransportType {
    type Error = ();

    fn try_from(s: &str) -> StdResult<Self, Self::Error> {
        Self::from_str(s)
    }
}

impl TryFrom<String> for TransportType {
    type Error = ();

    fn try_from(s: String) -> StdResult<Self, Self::Error> {
        Self::from_str(&s)
    }
}

impl fmt::Display for TransportType {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        use self::TransportType::*;

        f.write_str(match self {
            Udp => "UDP",
            Tcp => "TCP",
            Tls => "TLS",
            Sctp => "SCTP",
            Ws => "WS",
            Wss => "WSS",
        })
    }
}

/// Trait for all transport implementations.
#[async_trait]
pub trait SipTransport: Send + Sync + 'static {
    /// Sends data on the socket to the given address. On success, returns the
    /// number of bytes written.
    async fn send_msg(&self, buf: &[u8], address: &SocketAddr) -> Result<usize>;

    /// Get transport type.
    fn transport_type(&self) -> TransportType;

    /// Get the local socket address addr to this transport.
    fn local_addr(&self) -> SocketAddr;

    /// Get the remote socket address addr to this transport (if any).
    fn remote_addr(&self) -> Option<SocketAddr>;

    /// Returns `true` if the transport is reliable.
    fn is_reliable(&self) -> bool;

    /// Returns `true` if the transport is secure.
    fn is_secure(&self) -> bool;

    // TODO: implement this
    /// Returns the transport target addr as a plain sip uri.
    fn target_uri(&self) -> Uri {
        unimplemented!()
    }

    /// Get the id that uniquely identifies this transport.
    fn key(&self) -> TransportKey {
        TransportKey::from(self)
    }
}

/// Unique key for a transport instance.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
pub struct TransportKey {
    /// The destination address of the transport.
    pub address: SocketAddr,
    /// The transport type (e.g., UDP, TCP, TLS).
    pub tp_type: TransportType,
}

impl TransportKey {
    /// Creates a new transport key.
    pub fn new(address: SocketAddr, tp_type: TransportType) -> Self {
        TransportKey { address, tp_type }
    }
}

impl<T> From<&T> for TransportKey
where
    T: SipTransport + ?Sized,
{
    fn from(transport: &T) -> Self {
        let address = transport.local_addr();
        let tp_type = transport.transport_type();

        Self { address, tp_type }
    }
}

/// A raw network packet.
#[derive(Clone)]
pub struct Packet {
    /// Raw packet payload.
    pub data: Bytes,
    /// Remote address of the sender.
    pub source: SocketAddr,
    /// Time when the packet was received.
    pub timestamp: SystemTime,
}

impl Packet {
    /// Creates a new `Packet` whith the given `data` and `source` addr.
    pub fn new(data: Bytes, source: SocketAddr) -> Self {
        Self {
            data,
            source,
            timestamp: SystemTime::now(),
        }
    }
}

/// A network packet received through a transport.
#[derive(Clone)]
pub struct TransportMessage {
    /// Transport that received the packet.
    pub transport: Transport,
    /// The raw packet data and metadata.
    pub packet: Packet,
}

impl TransportMessage {
    /// Parse the packet into an sip message.
    pub fn parse(&self) -> Result<SipMessage> {
        let Self { transport, packet } = self;
        let sip_message = match Parser::parse(&packet.data) {
            Ok(parsed) => parsed,
            Err(err) => {
                log::warn!(
                    "Ignoring {} bytes packet from {} {} : {}\n{}-- end of packet.",
                    packet.data.len(),
                    transport.transport_type(),
                    packet.source,
                    err,
                    String::from_utf8_lossy(&packet.data)
                );

                return Err(err);
            }
        };

        Ok(sip_message)
    }
}

fn is_same_ip_family(first: &IpAddr, second: &IpAddr) -> bool {
    match (first, second) {
        (IpAddr::V4(_), IpAddr::V4(_)) => true,
        (IpAddr::V6(_), IpAddr::V6(_)) => true,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::transport::MockTransport;

    #[test]
    fn test_sip_transport() {
        let transport = MockTransport::new_udp();
        assert_eq!(transport.transport_type(), TransportType::Udp);
        assert!(!transport.is_reliable());
        assert!(!transport.is_secure());

        let transport = MockTransport::new_tcp();
        assert_eq!(transport.transport_type(), TransportType::Tcp);
        assert!(transport.is_reliable());
        assert!(!transport.is_secure());

        let transport = MockTransport::new_tls();
        assert_eq!(transport.transport_type(), TransportType::Tls);
        assert!(transport.is_reliable());
        assert!(transport.is_secure());
    }

    #[test]
    fn test_transport_type() {
        let udp = TransportType::Udp;
        assert_eq!(udp.default_port(), 5060);
        assert!(!udp.is_reliable());
        assert!(!udp.is_secure());

        let tcp = TransportType::Tcp;
        assert_eq!(tcp.default_port(), 5060);
        assert!(tcp.is_reliable());
        assert!(!tcp.is_secure());

        let tls = TransportType::Tls;
        assert_eq!(tls.default_port(), 5061);
        assert!(tls.is_reliable());
        assert!(tls.is_secure());

        let ws = TransportType::Ws;
        assert_eq!(ws.default_port(), 80);
        assert!(ws.is_reliable());
        assert!(!ws.is_secure());
    }

    #[test]
    fn test_transport_type_from_string() {
        let tp_type: TransportType = "UDP".try_into().unwrap();
        assert_eq!(tp_type, TransportType::Udp);
        let tp_type: TransportType = "udp".try_into().unwrap();
        assert_eq!(tp_type, TransportType::Udp);

        let tp_type: TransportType = "TCP".try_into().unwrap();
        assert_eq!(tp_type, TransportType::Tcp);
        let tp_type: TransportType = "tcp".try_into().unwrap();
        assert_eq!(tp_type, TransportType::Tcp);

        let tp_type: TransportType = "TLS".try_into().unwrap();
        assert_eq!(tp_type, TransportType::Tls);
        let tp_type: TransportType = "tls".try_into().unwrap();
        assert_eq!(tp_type, TransportType::Tls);

        let tp_type: TransportType = "WS".try_into().unwrap();
        assert_eq!(tp_type, TransportType::Ws);
        let tp_type: TransportType = "ws".try_into().unwrap();
        assert_eq!(tp_type, TransportType::Ws);
    }

    #[test]
    fn test_transport_manager() {
        let manager = TransportManager::new();
        let transport = MockTransport::new_udp();
        let addr = transport.local_addr();
        let tp_type = transport.transport_type();
        let key = transport.key();

        // manager.register_transport(transport).unwrap();
        // assert_eq!(manager.transport_count().unwrap(), 1);

        // let selected = manager.select_transport(addr, TransportType::Udp);
        // let selected = selected.unwrap().unwrap();
        // assert_eq!(selected.transport_type(), tp_type);
        // assert_eq!(selected.local_addr(), addr);

        // manager.remove_transport(&key).unwrap();
        // assert_eq!(manager.transport_count().unwrap(), 0);
    }

    #[test]
    fn test_transport_key_from_tp() {
        let transport = MockTransport::new_udp();
        let key: TransportKey = transport.key();
        assert_eq!(key.address, transport.local_addr());
        assert_eq!(key.tp_type, transport.transport_type());
    }
}
