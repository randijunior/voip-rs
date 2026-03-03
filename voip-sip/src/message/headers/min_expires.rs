use std::{fmt, str};

use crate::error::Result;
use crate::parser::{HeaderParser, SipParser};

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[repr(transparent)]
pub struct MinExpires(u32);

impl MinExpires {
    #[inline]
    pub const fn new(value: u32) -> Self {
        Self(value)
    }

    #[inline]
    pub const fn as_u32(&self) -> u32 {
        self.0
    }
}

impl HeaderParser for MinExpires {
    const NAME: &'static str = "Min-Expires";

    fn parse(parser: &mut SipParser) -> Result<Self> {
        let expires = parser.read_u32()?;

        Ok(Self(expires))
    }
}

impl fmt::Display for MinExpires {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", Self::NAME, self.0)
    }
}
