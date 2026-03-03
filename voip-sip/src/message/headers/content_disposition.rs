use core::fmt;

use crate::error::Result;
use crate::macros::parse_header_param;
use crate::message::param::Params;
use crate::parser::{HeaderParser, SipParser};

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct ContentDisposition {
    r#type: String,
    params: Option<Params>,
}

impl HeaderParser for ContentDisposition {
    const NAME: &'static str = "Content-Disposition";

    fn parse(parser: &mut SipParser) -> Result<Self> {
        let r#type = parser.parse_token()?.to_owned();
        let params = parse_header_param!(parser);

        Ok(Self { r#type, params })
    }
}

impl fmt::Display for ContentDisposition {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", Self::NAME, self.r#type)?;

        if let Some(param) = &self.params {
            write!(f, ";{}", param)?;
        }

        Ok(())
    }
}
