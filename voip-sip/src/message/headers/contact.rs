use core::fmt;

use crate::Q;
use crate::error::Result;
use crate::macros::parse_header_param;
use crate::message::param::{EXPIRES_PARAM, Params, Q_PARAM};
use crate::message::sip_uri::SipUri;
use crate::parser::{HeaderParser, SipParser};

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Contact {
    uri: SipUri,
    q: Option<Q>,
    expires: Option<u32>,
    param: Option<Params>,
}

impl HeaderParser for Contact {
    const NAME: &'static str = "Contact";
    const SHORT_NAME: &'static str = "m";

    fn parse(parser: &mut SipParser) -> Result<Self> {
        let uri = parser.parse_sip_uri(false)?;
        let mut q = None;
        let mut expires = None;
        let param = parse_header_param!(parser, Q_PARAM = q, EXPIRES_PARAM = expires);

        let q = q.map(|q: &str| q.parse()).transpose()?;
        let expires = expires.and_then(|expires: &str| expires.parse().ok());

        Ok(Contact {
            uri,
            q,
            expires,
            param,
        })
    }
}

impl std::str::FromStr for Contact {
    type Err = crate::error::Error;

    fn from_str(s: &str) -> Result<Self> {
        Self::parse(&mut SipParser::new(s.as_bytes()))
    }
}

impl fmt::Display for Contact {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: ", Self::NAME)?;

        write!(f, "{}", self.uri)?;

        if let Some(q) = self.q {
            write!(f, "{}", q)?;
        }
        if let Some(expires) = self.expires {
            write!(f, "{}", expires)?;
        }
        if let Some(param) = &self.param {
            write!(f, "{}", param)?;
        }
        Ok(())
    }
}
