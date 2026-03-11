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

use crate::endpoint::Endpoint;
use crate::error::{Error, Result};
use crate::message::SipMessage;
use crate::message::sip_uri::{DomainName, Host, Scheme, Uri};
use crate::parser::SipParser;
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

pub struct TransportConfig {
    // Enable NAPTR lookups
    naptrlookup: bool,
    // Enable DNS SRV lookups
    srvlookup: bool,
}

/// Module for SIP all transports.
#[derive(Default)]
pub struct TransportModule {
    map: Mutex<rustc_hash::FxHashMap<TransportKey, Transport>>,
}

impl TransportModule {
    /// Create a new `TransportModule` instance.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a new transport to the manager.
    pub fn register_transport(&self, transport: Transport) {
        let key = transport.key();
        let mut map = self.map.lock().expect("Lock failed");

        map.insert(key, transport);
    }

    /// Remove a transport by its key.
    pub fn remove_transport(&self, key: &TransportKey) {
        let mut map = self.map.lock().expect("Lock failed");

        map.remove(key);
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
                    let transport = SipTransportType::from_scheme(uri.scheme);
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
                        let transport = SipTransportType::from_scheme(uri.scheme);
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
                                    SipTransportType::Tls,
                                ),
                                (
                                    Name::from_utf8(format!("_sip._udp.{name}")).unwrap(),
                                    SipTransportType::Udp,
                                ),
                                (
                                    Name::from_utf8(format!("_sip._tcp.{name}")).unwrap(),
                                    SipTransportType::Tcp,
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
                            let transport = SipTransportType::from_scheme(uri.scheme);
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
            let Some(transport) = SipTransportType::from_naptr_service(record.services()) else {
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
        let map = self.map.lock().expect("Lock failed");
        Ok(map.get(key).cloned())
    }

    fn get_by_transport_type_and_ip_family(
        &self,
        protocol: SipTransportType,
        ip: IpAddr,
    ) -> Result<Option<Transport>> {
        let map = self.map.lock().expect("Lock failed");
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
        protocol: SipTransportType,
        addr: SocketAddr,
        endpoint: &Endpoint,
    ) -> Result<Transport> {
        let key = TransportKey::new(addr, protocol);
        if let Some(transport) = self.get_by_key(&key)? {
            return Ok(transport.clone());
        }
        let transport = match protocol {
            SipTransportType::Tcp => TcpTransport::connect(addr, endpoint).await?,
            SipTransportType::Ws | SipTransportType::Wss => {
                let scheme = if protocol == SipTransportType::Ws {
                    "ws"
                } else {
                    "wss"
                };
                let url = format!("{scheme}://{addr}");
                WebSocketTransport::connect(&url, 1.0, endpoint).await?
            }
            SipTransportType::Udp => self
                .get_by_transport_type_and_ip_family(SipTransportType::Udp, addr.ip())?
                .ok_or(Error::UnsupportedTransport)?,
            _ => return Err(Error::UnsupportedTransport),
        };

        self.register_transport(transport.clone());

        Ok(transport)
    }

    /// Return the number of transports registered.
    pub fn transport_count(&self) -> usize {
        let map = self.map.lock().expect("Lock failed");

        map.len()
    }
}

/// Represents the type of transport.
#[derive(Default, Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SipTransportType {
    /// Udp.
    #[default]
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

impl SipTransportType {
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

impl FromStr for SipTransportType {
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

impl TryFrom<&str> for SipTransportType {
    type Error = ();

    fn try_from(s: &str) -> StdResult<Self, Self::Error> {
        Self::from_str(s)
    }
}

impl TryFrom<String> for SipTransportType {
    type Error = ();

    fn try_from(s: String) -> StdResult<Self, Self::Error> {
        Self::from_str(&s)
    }
}

impl fmt::Display for SipTransportType {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        f.write_str(match self {
            Self::Udp => "UDP",
            Self::Tcp => "TCP",
            Self::Tls => "TLS",
            Self::Sctp => "SCTP",
            Self::Ws => "WS",
            Self::Wss => "WSS",
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
    fn transport_type(&self) -> SipTransportType;

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
    pub tp_type: SipTransportType,
}

impl TransportKey {
    /// Creates a new transport key.
    pub fn new(address: SocketAddr, tp_type: SipTransportType) -> Self {
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
        let sip_message = match SipParser::parse(&packet.data) {
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
    matches!(
        (first, second),
        (IpAddr::V4(_), IpAddr::V4(_)) | (IpAddr::V6(_), IpAddr::V6(_))
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::transport::MockTransport;

    #[test]
    fn test_sip_transport() {
        let transport = MockTransport::new_udp();
        assert_eq!(transport.transport_type(), SipTransportType::Udp);
        assert!(!transport.is_reliable());
        assert!(!transport.is_secure());

        let transport = MockTransport::new_tcp();
        assert_eq!(transport.transport_type(), SipTransportType::Tcp);
        assert!(transport.is_reliable());
        assert!(!transport.is_secure());

        let transport = MockTransport::new_tls();
        assert_eq!(transport.transport_type(), SipTransportType::Tls);
        assert!(transport.is_reliable());
        assert!(transport.is_secure());
    }

    #[test]
    fn test_transport_type() {
        let udp = SipTransportType::Udp;
        assert_eq!(udp.default_port(), 5060);
        assert!(!udp.is_reliable());
        assert!(!udp.is_secure());

        let tcp = SipTransportType::Tcp;
        assert_eq!(tcp.default_port(), 5060);
        assert!(tcp.is_reliable());
        assert!(!tcp.is_secure());

        let tls = SipTransportType::Tls;
        assert_eq!(tls.default_port(), 5061);
        assert!(tls.is_reliable());
        assert!(tls.is_secure());

        let ws = SipTransportType::Ws;
        assert_eq!(ws.default_port(), 80);
        assert!(ws.is_reliable());
        assert!(!ws.is_secure());
    }

    #[test]
    fn test_transport_type_from_string() {
        let tp_type: SipTransportType = "UDP".try_into().unwrap();
        assert_eq!(tp_type, SipTransportType::Udp);
        let tp_type: SipTransportType = "udp".try_into().unwrap();
        assert_eq!(tp_type, SipTransportType::Udp);

        let tp_type: SipTransportType = "TCP".try_into().unwrap();
        assert_eq!(tp_type, SipTransportType::Tcp);
        let tp_type: SipTransportType = "tcp".try_into().unwrap();
        assert_eq!(tp_type, SipTransportType::Tcp);

        let tp_type: SipTransportType = "TLS".try_into().unwrap();
        assert_eq!(tp_type, SipTransportType::Tls);
        let tp_type: SipTransportType = "tls".try_into().unwrap();
        assert_eq!(tp_type, SipTransportType::Tls);

        let tp_type: SipTransportType = "WS".try_into().unwrap();
        assert_eq!(tp_type, SipTransportType::Ws);
        let tp_type: SipTransportType = "ws".try_into().unwrap();
        assert_eq!(tp_type, SipTransportType::Ws);
    }

    #[test]
    fn test_transport_manager() {
        let manager = TransportModule::new();
        let transport = MockTransport::new_udp();
        let addr = transport.local_addr();
        let tp_type = transport.transport_type();
        let key = transport.key();

        // manager.register_transport(transport).unwrap();
        // assert_eq!(manager.transport_count().unwrap(), 1);

        // let selected = manager.select_transport(addr, SipTransportType::Udp);
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
