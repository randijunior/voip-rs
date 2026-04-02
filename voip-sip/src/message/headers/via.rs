use core::fmt;
use std::net::IpAddr;
use std::str::{self, FromStr};

use crate::error::{ParseErrorKind as ErrorKind, Result};
use crate::macros;
use crate::message::param::{self, Params};
use crate::message::sip_uri::{Host, HostPort};
use crate::parser::{HeaderParse, SIPV2, SipParser};
use crate::transport::TransportProtocol;

#[derive(Default, Debug, PartialEq, Eq, Clone)]
pub struct Via {
    transport: TransportProtocol,
    sent_by: HostPort,
    ttl: Option<u8>,
    maddr: Option<Host>,
    received: Option<IpAddr>,
    branch: Option<String>,
    rport: Option<u16>,
    comment: Option<String>,
    params: Params,
}

impl Via {
    pub fn new_udp(sent_by: HostPort, branch: Option<String>) -> Self {
        Self::new_with_transport(TransportProtocol::Udp, sent_by, branch)
    }

    pub fn new_with_transport(
        transport: TransportProtocol,
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
            params: Default::default(),
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

    pub fn maddr(&self) -> Option<&Host> {
        self.maddr.as_ref()
    }

    pub fn sent_by(&self) -> &HostPort {
        &self.sent_by
    }

    pub fn received(&self) -> Option<IpAddr> {
        self.received
    }

    pub fn rport(&self) -> Option<u16> {
        self.rport
    }

    pub fn sent_protocol(&self) -> TransportProtocol {
        self.transport
    }
}

impl HeaderParse for Via {
    const NAME: &'static str = "Via";
    const SHORT_NAME: &'static str = "v";

    fn parse(parser: &mut SipParser) -> Result<Self> {
        let mut via = Self::default();

        //@TODO: handle LWS
        parser.parse_sip_version()?;
        parser.advance()?;

        via.transport = parser
            .read_token()
            .parse()
            .or_else(|_| parser.error(ErrorKind::Transport))?;

        parser.skip_ws();

        via.sent_by = parser.parse_host_port()?;

        via.params = macros::parse_params!(parser, {
            let (pname, pvalue) = parser.via_param()?;
            match pname {
                param::BRANCH_PARAM => {
                    via.branch = pvalue.map(ToOwned::to_owned);
                    None
                }
                param::TTL_PARAM => {
                    via.ttl = pvalue
                        .map(|p| p.parse())
                        .transpose()
                        .or_else(|_| parser.error(ErrorKind::Param))?;
                    None
                }
                param::MADDR_PARAM => {
                    via.maddr = pvalue
                        .map(|maddr| maddr.parse())
                        .transpose()
                        .or_else(|_| parser.error(ErrorKind::Host))?;
                    None
                }
                param::RECEIVED_PARAM => {
                    via.received = pvalue
                        .map(|p| p.parse())
                        .transpose()
                        .or_else(|_| parser.error(ErrorKind::Param))?;
                    None
                }
                param::RPORT_PARAM => {
                    via.rport = if let Some(rport) = pvalue
                        .filter(|rport| !rport.is_empty())
                        .map(|rport| rport.parse())
                        .transpose()
                        .or_else(|_| parser.error(ErrorKind::Port))?
                    {
                        if crate::is_valid_port(rport) {
                            Some(rport)
                        } else {
                            return parser.error(ErrorKind::Port);
                        }
                    } else {
                        None
                    };
                    None
                }
                _ => Some((pname, pvalue).into()),
            }
        });

        via.comment = if parser.take_if_eq(b'(').is_some() {
            let comment = parser.take_until(b')');
            parser.advance()?;
            Some(str::from_utf8(comment)?.to_owned())
        } else {
            None
        };

        Ok(via)
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
        write!(f, "{}", self.params)?;

        if let Some(comment) = &self.comment {
            write!(f, " ({comment})")?;
        }

        Ok(())
    }
}
