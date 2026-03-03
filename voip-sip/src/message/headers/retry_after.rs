use std::{fmt, str, u32};

use crate::error::Result;
use crate::macros::parse_header_param;
use crate::message::param::Params;
use crate::parser::{HeaderParser, SipParser};

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct RetryAfter {
    seconds: u32,
    param: Option<Params>,
    comment: Option<String>,
}

impl HeaderParser for RetryAfter {
    const NAME: &'static str = "Retry-After";

    fn parse(parser: &mut SipParser) -> Result<Self> {
        let seconds = parser.read_u32()?;
        let mut comment = None;

        parser.skip_ws();
        if let Some(b'(') = parser.peek() {
            parser.read()?;
            let b = parser.read_until(b')');
            parser.read()?;
            comment = Some(str::from_utf8(b)?);
        }
        let param = parse_header_param!(parser);

        Ok(Self {
            seconds,
            param,
            comment: comment.map(|c| c.into()),
        })
    }
}

impl fmt::Display for RetryAfter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: ", Self::NAME)?;

        write!(f, "{}", self.seconds)?;

        if let Some(param) = &self.param {
            write!(f, ";{}", param)?;
        }
        if let Some(comment) = &self.comment {
            write!(f, "{}", comment)?;
        }

        Ok(())
    }
}
