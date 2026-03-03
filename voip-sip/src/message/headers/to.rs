use std::fmt;
use std::str::{
    FromStr, {self},
};

use crate::error::Result;
use crate::macros::parse_header_param;
use crate::message::param::{Params, TAG_PARAM};
use crate::message::sip_uri::SipUri;
use crate::parser::{HeaderParser, SipParser};

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct To {
    uri: SipUri,
    tag: Option<String>,
    params: Option<Params>,
}

impl To {
    /// Returns the tag parameter.
    pub fn tag(&self) -> Option<&str> {
        self.tag.as_deref()
    }

    /// Set the tag parameter.
    pub fn set_tag(&mut self, tag: Option<String>) {
        self.tag = tag;
    }
}

impl HeaderParser for To {
    const NAME: &'static str = "To";
    const SHORT_NAME: &'static str = "t";

    fn parse(parser: &mut SipParser) -> Result<Self> {
        let uri = parser.parse_sip_uri(false)?;
        let mut tag: Option<String> = None;
        let params = parse_header_param!(parser, TAG_PARAM = tag);

        Ok(Self { tag, uri, params })
    }
}

impl FromStr for To {
    type Err = crate::error::Error;

    fn from_str(s: &str) -> Result<Self> {
        Self::parse(&mut SipParser::new(s.as_bytes()))
    }
}

impl fmt::Display for To {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", Self::NAME, self.uri)?;
        if let Some(tag) = &self.tag {
            write!(f, ";tag={}", tag)?;
        }
        if let Some(params) = &self.params {
            write!(f, "{}", params)?;
        }

        Ok(())
    }
}
