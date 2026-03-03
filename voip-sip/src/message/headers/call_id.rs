use core::fmt;
use std::str::{self, FromStr};

use crate::error::Result;
use crate::parser::{HeaderParser, SipParser};

#[derive(Debug, PartialEq, Eq, Clone, Hash)]
#[repr(transparent)]
pub struct CallId(String);

impl From<&str> for CallId {
    fn from(id: &str) -> Self {
        Self::new(id.to_owned())
    }
}

impl FromStr for CallId {
    type Err = crate::error::Error;

    fn from_str(s: &str) -> Result<Self> {
        Self::parse(&mut SipParser::new(s))
    }
}

impl CallId {
    pub fn new(id: String) -> Self {
        Self(id)
    }

    pub fn id(&self) -> &str {
        &self.0
    }
}

impl HeaderParser for CallId {
    const NAME: &'static str = "Call-ID";
    const SHORT_NAME: &'static str = "i";

    fn parse(parser: &mut SipParser) -> Result<Self> {
        let id = parser.read_line()?;

        Ok(CallId(id.to_owned()))
    }
}

impl fmt::Display for CallId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", Self::NAME, self.0)
    }
}
