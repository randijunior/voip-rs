use std::{fmt, str};

use crate::error::Result;
use crate::parser::{HeaderParser, SipParser};

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[repr(transparent)]
pub struct Expires(u32);

impl HeaderParser for Expires {
    const NAME: &'static str = "Expires";

    fn parse(parser: &mut SipParser) -> Result<Expires> {
        let expires = parser.read_u32()?;

        Ok(Self(expires))
    }
}

impl fmt::Display for Expires {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", Expires::NAME, self.0)
    }
}
