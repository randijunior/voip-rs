use core::fmt;
use std::net::IpAddr;
use std::str::{self, FromStr};

use crate::error::{ParseErrorKind as ErrorKind, Result};
use crate::macros::parse_param;
use crate::message::{DomainName, Host, HostPort, Params};
use crate::parser::{
    HeaderParser, Parser, SIPV2, {self},
};
use crate::transport::TransportType;

const MADDR_PARAM: &str = "maddr";
const BRANCH_PARAM: &str = "branch";
const TTL_PARAM: &str = "ttl";
const RPORT_PARAM: &str = "rport";
const RECEIVED_PARAM: &str = "received";

/// The `Via` SIP header.
///
/// Indicates the path taken by the request so far and the
/// path that should be followed in routing responses.
///
/// # Examples
/// ```
/// # use voip_rs::header::Via;
/// # use std::str::FromStr;
///
/// let input = "Via: SIP/2.0/UDP server10.biloxi.com;branch=z9hG4bKnashds8";
///
/// let via = Via::new_udp(
///     "server10.biloxi.com".parse().unwrap(),
///     Some("z9hG4bKnashds8"),
/// );
///
/// assert_eq!(input, via.to_string());
/// ```
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Via {
    /// Transport type.
    pub transport: TransportType,
    /// Via sent_by.
    pub sent_by: HostPort,
    /// Via ttl.
    pub ttl: Option<u8>,
    /// Via host.
    pub maddr: Option<Host>,
    /// Via received.
    pub received: Option<IpAddr>,
    /// Via branch.
    pub branch: Option<String>,
    /// Via rport.
    pub rport: Option<u16>,
    /// Via comment.
    pub comment: Option<String>,
    /// Via params.
    pub params: Option<Params>,
}

impl Via {
    /// Creates a new `Via` header with UDP transport and
    /// optional branch.
    ///
    /// # Arguments
    /// * `sent_by` - The host and optional port to which responses should be sent.
    /// * `branch` - Optional branch parameter to identify the transaction.
    pub fn new_udp(sent_by: HostPort, branch: Option<String>) -> Self {
        Self {
            transport: TransportType::Udp,
            sent_by,
            ttl: None,
            maddr: None,
            received: None,
            branch: branch.map(|b| b.into()),
            rport: None,
            comment: None,
            params: None,
        }
    }

    /// Create an `Via` with the given `transport` and `sent_by`.
    pub fn new_with_transport(
        transport: TransportType,
        sent_by: HostPort,
        branch: Option<String>,
    ) -> Self {
        Self {
            transport,
            sent_by,
            ttl: None,
            maddr: None,
            received: None,
            branch,
            rport: None,
            comment: None,
            params: None,
        }
    }
}

impl fmt::Display for Via {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}: {}/{} {}",
            Via::NAME,
            SIPV2,
            self.transport,
            self.sent_by
        )?;

        if let Some(rport) = self.rport {
            write!(f, ";rport={}", rport)?;
        }
        if let Some(received) = &self.received {
            write!(f, ";received={received}")?;
        }
        if let Some(ttl) = &self.ttl {
            write!(f, ";ttl={ttl}")?;
        }
        if let Some(maddr) = &self.maddr {
            write!(f, ";maddr={maddr}")?;
        }
        if let Some(branch) = &self.branch {
            write!(f, ";branch={branch}")?;
        }
        if let Some(params) = &self.params {
            write!(f, "{params}")?;
        }
        if let Some(comment) = &self.comment {
            write!(f, " ({comment})")?;
        }

        Ok(())
    }
}

impl HeaderParser for Via {
    const NAME: &'static str = "Via";
    const SHORT_NAME: &'static str = "v";

    /*
     * Via               =  ( "Via" / "v" ) HCOLON via-parm
     * *(COMMA via-parm) via-parm          =
     * sent-protocol LWS sent-by *( SEMI via-params )
     * via-params        =  via-ttl / via-maddr
     *                      / via-received / via-branch
     *                      / via-extension
     * via-ttl           =  "ttl" EQUAL ttl
     * via-maddr         =  "maddr" EQUAL host
     * via-received      =  "received" EQUAL (IPv4address /
     * IPv6address) via-branch        =  "branch" EQUAL
     * token via-extension     =  generic-param
     * sent-protocol     =  protocol-name SLASH
     * protocol-version                      SLASH
     * transport protocol-name     =  "SIP" / token
     * protocol-version  =  token
     * transport         =  "UDP" / "TCP" / "TLS" / "SCTP"
     *                      / other-transport
     * sent-by           =  host [ COLON port ]
     * ttl               =  1*3DIGIT ; 0 to 255
     */
    fn parse(parser: &mut Parser) -> Result<Self> {
        //@TODO: handle LWS
        parser.parse_sip_version()?;
        parser.next_byte()?;

        let transport = parser.read_token_str();
        let transport = transport
            .parse()
            .or_else(|_| parser.parse_error(ErrorKind::Transport))?;

        parser.skip_ws();

        let sent_by = parser.parse_host_port()?;
        let mut branch = None;
        let mut ttl = None;
        let mut maddr = None;
        let mut received = None;
        let mut rport_p: Option<&str> = None;
        let params = parse_param!(
            parser,
            parser::parse_via_param,
            BRANCH_PARAM = branch,
            TTL_PARAM = ttl,
            MADDR_PARAM = maddr,
            RECEIVED_PARAM = received,
            RPORT_PARAM = rport_p
        );
        // TODO: Return err for invalid received and rport parameter.
        let received = received.and_then(|r: &str| r.parse().ok());
        let maddr = maddr.map(|a: &str| match a.parse() {
            Ok(addr) => Host::IpAddr(addr),
            Err(_) => Host::DomainName(DomainName::new(a.to_string())),
        });
        let ttl = ttl.map(|ttl: &str| ttl.parse().unwrap());
        let branch = branch.map(|b: &str| b.into());

        let rport = if let Some(rport) = rport_p
            .filter(|rport| !rport.is_empty())
            .and_then(|rpot| rpot.parse().ok())
        {
            if crate::is_valid_port(rport) {
                Some(rport)
            } else {
                return parser.parse_error(ErrorKind::Header);
            }
        } else {
            None
        };

        let comment = if parser.peek_byte() == Some(&b'(') {
            parser.next_byte()?;
            let comment = parser.read_until(b')');
            parser.next_byte()?;
            Some(str::from_utf8(comment)?.into())
        } else {
            None
        };

        Ok(Via {
            transport,
            sent_by,
            params,
            comment,
            ttl,
            maddr,
            received,
            branch,
            rport,
        })
    }
}

impl FromStr for Via {
    type Err = crate::error::Error;

    /// Parse a `To` header instance from a `&str`.
    fn from_str(s: &str) -> Result<Self> {
        Self::parse(&mut Parser::new(s))
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use super::*;
    use crate::message::Host;

    #[test]
    fn test_parse() {
        let src = b"SIP/2.0/UDP bobspc.biloxi.com:5060;received=192.0.2.4\r\n";
        let mut scanner = Parser::new(src);
        let via = Via::parse(&mut scanner);
        let via = via.unwrap();

        assert_eq!(via.transport, TransportType::Udp);
        assert_eq!(
            via.sent_by,
            HostPort {
                host: Host::DomainName(DomainName::new("bobspc.biloxi.com")),
                port: Some(5060)
            }
        );

        assert_eq!(via.received, Some("192.0.2.4".parse().unwrap()));

        let src = b"SIP/2.0/UDP 192.0.2.1:5060 ;received=192.0.2.207 \
        ;branch=z9hG4bK77asjd\r\n";
        let mut scanner = Parser::new(src);
        let via = Via::parse(&mut scanner);
        let via = via.unwrap();

        assert_eq!(via.transport, TransportType::Udp);
        assert_eq!(
            via.sent_by,
            HostPort {
                host: Host::IpAddr(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))),
                port: Some(5060)
            }
        );

        assert_eq!(via.received, Some("192.0.2.207".parse().unwrap()));
        assert_eq!(via.branch, Some("z9hG4bK77asjd".into()));
    }
}
