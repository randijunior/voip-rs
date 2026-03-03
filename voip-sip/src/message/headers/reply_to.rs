use std::fmt;

use crate::error::Result;
use crate::macros::parse_header_param;
use crate::message::param::Params;
use crate::message::sip_uri::SipUri;
use crate::parser::{HeaderParser, SipParser};

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct ReplyTo {
    uri: SipUri,
    param: Option<Params>,
}

impl HeaderParser for ReplyTo {
    const NAME: &'static str = "Reply-To";

    fn parse(parser: &mut SipParser) -> Result<Self> {
        let uri = parser.parse_sip_uri(false)?;
        let param = parse_header_param!(parser);

        Ok(Self { uri, param })
    }
}

impl fmt::Display for ReplyTo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", Self::NAME, self.uri)?;
        if let Some(param) = &self.param {
            write!(f, ";{}", param)?;
        }

        Ok(())
    }
}
