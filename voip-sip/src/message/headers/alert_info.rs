use std::{fmt, str};

use crate::error::Result;
use crate::macros::parse_header_param;
use crate::message::Params;
use crate::parser::{HeaderParser, SipParser};

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct AlertInfo {
    url: String,
    params: Option<Params>,
}

impl HeaderParser for AlertInfo {
    const NAME: &'static str = "Alert-Info";

    fn parse(parser: &mut SipParser) -> Result<Self> {
        parser.skip_ws();

        parser.read()?;
        let url = parser.read_until(b'>');
        parser.read()?;

        let url = str::from_utf8(url)?.to_owned();
        let params = parse_header_param!(parser);

        Ok(AlertInfo { url, params })
    }
}

impl fmt::Display for AlertInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: <{}>", Self::NAME, self.url)?;
        if let Some(params) = &self.params {
            write!(f, "{}", params)?;
        }
        Ok(())
    }
}
