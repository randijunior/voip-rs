use std::fmt;

use crate::error::Result;
use crate::macros::parse_header_param;
use crate::message::{NameAddr, Params};
use crate::parser::{HeaderParser, SipParser};

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Route {
    pub(crate) name_addr: NameAddr,
    pub(crate) params: Option<Params>,
}

impl HeaderParser for Route {
    const NAME: &'static str = "Route";

    fn parse(parser: &mut SipParser) -> Result<Self> {
        let name_addr = parser.parse_name_addr()?;
        let params = parse_header_param!(parser);
        Ok(Self { name_addr, params })
    }
}

impl fmt::Display for Route {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: ", Self::NAME)?;
        
        write!(f, "{}", self.name_addr)?;

        if let Some(param) = &self.params {
            write!(f, ";{}", param)?;
        }

        Ok(())
    }
}


