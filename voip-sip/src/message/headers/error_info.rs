use std::{fmt, str};

use itertools::Itertools;

use crate::error::Result;
use crate::macros::{parse_comma_separated_header_value, parse_header_param};
use crate::message::param::Params;
use crate::parser::{HeaderParser, SipParser};

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct ErrorInfoUri {
    url: String,
    params: Option<Params>,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct ErrorInfo(Vec<ErrorInfoUri>);

impl HeaderParser for ErrorInfo {
    const NAME: &'static str = "Error-Info";

    fn parse(parser: &mut SipParser) -> Result<Self> {
        let infos = parse_comma_separated_header_value!(parser => {
            ErrorInfoUri::parse(parser)?
        });

        Ok(Self(infos))
    }
}

impl ErrorInfoUri {
    pub fn parse(parser: &mut SipParser) -> Result<Self> {
        parser.must_read(b'<')?;
        let url = parser.read_until(b'>');
        parser.read()?;

        let url = str::from_utf8(url)?.to_owned();
        let params = parse_header_param!(parser);

        Ok(Self { url, params })
    }
}

impl fmt::Display for ErrorInfoUri {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.url)?;

        if let Some(param) = &self.params {
            write!(f, ";{}", param)?;
        }

        Ok(())
    }
}

impl fmt::Display for ErrorInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0.iter().format(", "))
    }
}
