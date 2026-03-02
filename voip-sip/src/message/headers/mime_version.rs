use std::{fmt, str};

use crate::error::Result;
use crate::parser::{HeaderParser, SipParser};

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct MimeVersion {
    major: u8,
    minor: u8,
}

impl HeaderParser for MimeVersion {
    const NAME: &'static str = "MIME-Version";

    fn parse(parser: &mut SipParser) -> Result<Self> {
        let (major, _, minor) = (
            parser.read()? - b'0',
            parser.must_read(b'.')?,
            parser.read()? - b'0',
        );

        Ok(MimeVersion { major, minor })
    }
}

impl fmt::Display for MimeVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}.{}", Self::NAME, self.major, self.minor)
    }
}
