use core::fmt;
use std::net::IpAddr;
use std::str::{self, FromStr};

use crate::error::{ParseErrorKind as ErrorKind, Result};
use crate::macros::parse_param;
use crate::message::{DomainName, Host, HostPort, Params};
use crate::parser::{
    HeaderParser, SIPV2, SipParser, {self},
};
use crate::transport::SipTransportType;

const MADDR_PARAM: &str = "maddr";
const BRANCH_PARAM: &str = "branch";
const TTL_PARAM: &str = "ttl";
const RPORT_PARAM: &str = "rport";
const RECEIVED_PARAM: &str = "received";

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Via {
    transport: SipTransportType,
    sent_by: HostPort,
    ttl: Option<u8>,
    maddr: Option<Host>,
    received: Option<IpAddr>,
    branch: Option<String>,
    rport: Option<u16>,
    comment: Option<String>,
    params: Option<Params>,
}

impl Via {
    pub fn new_udp(sent_by: HostPort, branch: Option<String>) -> Self {
        Self::new_with_transport(SipTransportType::Udp, sent_by, branch)
    }

    pub fn new_with_transport(
        transport: SipTransportType,
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

    pub fn branch(&self) -> Option<&str> {
        self.branch.as_deref()
    }

    pub fn set_branch(&mut self, branch: String) {
        self.branch = Some(branch);
    }

    pub fn set_received(&mut self, received: IpAddr) {
        self.received = Some(received);
    }
}

impl HeaderParser for Via {
    const NAME: &'static str = "Via";
    const SHORT_NAME: &'static str = "v";

    fn parse(parser: &mut SipParser) -> Result<Self> {
        //@TODO: handle LWS
        parser.parse_sip_version()?;
        parser.read()?;

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

        let comment = if parser.peek() == Some(&b'(') {
            parser.read()?;
            let comment = parser.read_until(b')');
            parser.read()?;
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

    fn from_str(s: &str) -> Result<Self> {
        Self::parse(&mut SipParser::new(s))
    }
}

impl fmt::Display for Via {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}: {}/{} {}",
            Self::NAME,
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