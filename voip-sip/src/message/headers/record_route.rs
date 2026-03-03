use std::fmt;

use crate::error::Result;
use crate::macros::parse_header_param;
use crate::message::param::Params;
use crate::message::sip_uri::NameAddr;
use crate::parser::{HeaderParser, SipParser};

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct RecordRoute {
    addr: NameAddr,
    params: Option<Params>,
}

impl RecordRoute {
    pub fn name_addr(&self) -> &NameAddr {
        &self.addr
    }
    pub fn params(&self) -> Option<&Params> {
        self.params.as_ref()
    }
}

impl HeaderParser for RecordRoute {
    const NAME: &'static str = "Record-Route";

    fn parse(parser: &mut SipParser) -> Result<Self> {
        let addr = parser.parse_name_addr()?;
        let params = parse_header_param!(parser);

        Ok(Self { addr, params })
    }
}

impl fmt::Display for RecordRoute {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", Self::NAME, self.addr)?;
        if let Some(param) = &self.params {
            write!(f, ";{}", param)?;
        }

        Ok(())
    }
}
