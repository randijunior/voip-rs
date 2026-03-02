use core::fmt;
use std::str::{self, FromStr};

use crate::error::Result;
use crate::macros::parse_header_param;
use crate::message::headers::TAG_PARAM;
use crate::message::{Params, SipUri};
use crate::parser::{HeaderParser, SipParser};

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct From {
    uri: SipUri,
    tag: Option<String>,
    params: Option<Params>,
}

impl FromStr for From {
    type Err = crate::error::Error;

    fn from_str(s: &str) -> Result<Self> {
        Self::parse(&mut SipParser::new(s.as_bytes()))
    }
}

impl From {
    /// Returns the tag parameter.
    pub fn tag(&self) -> Option<&str> {
        self.tag.as_deref()
    }
}

impl HeaderParser for From {
    const NAME: &'static str = "From";
    const SHORT_NAME: &'static str = "f";

    fn parse(parser: &mut SipParser) -> Result<Self> {
        let uri = parser.parse_sip_uri(false)?;
        let mut tag = None;
        let params = parse_header_param!(parser, TAG_PARAM = tag);

        Ok(Self { tag, uri, params })
    }
}

impl fmt::Display for From {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: ", Self::NAME)?;
        
        match &self.uri {
            SipUri::Uri(uri) => write!(f, "{}", uri)?,
            SipUri::NameAddr(name_addr) => write!(f, "{}", name_addr)?,
        }
        if let Some(tag) = &self.tag {
            write!(f, ";tag={}", tag)?;
        }
        if let Some(params) = &self.params {
            write!(f, "{}", params)?;
        }

        Ok(())
    }
}