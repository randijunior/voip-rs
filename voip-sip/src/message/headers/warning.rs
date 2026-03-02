use std::{fmt, str};

use crate::error::{ParseErrorKind as ErrorKind, Result};
use crate::parser::{HeaderParser, SipParser};

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Warning {
    code: u32,
    host: String,
    text: String,
}

impl HeaderParser for Warning {
    const NAME: &'static str = "Warning";

    fn parse(parser: &mut SipParser) -> Result<Self> {
        let code = parser.read_u32()?;
        parser.skip_ws();
        let host = parser.read_host_str().to_owned();
        parser.skip_ws();
        let Some(b'"') = parser.peek() else {
            return parser.parse_error(ErrorKind::Header);
        };
        parser.read()?;
        let text = parser.read_until(b'"');
        parser.read()?;
        let text = str::from_utf8(text)?.to_owned();

        Ok(Warning {
            code,
            host,
            text,
        })
    }
}

impl fmt::Display for Warning {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}: {} {} {}",
            Self::NAME,
            self.code,
            self.host,
            self.text
        )
    }
}
