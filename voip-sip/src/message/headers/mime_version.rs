use std::{fmt, str};

use crate::error::Result;
use crate::parser::{HeaderParser, Parser};

/// The `MIME-Version` SIP header.
///
/// Indicate what version of the `MIME` protocol was used to
/// construct the message.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct MimeVersion {
    major: u8,
    minor: u8,
}

impl HeaderParser for MimeVersion {
    const NAME: &'static str = "MIME-Version";

    fn parse(parser: &mut Parser) -> Result<Self> {
        let (major, _, minor) = (
            parser.next_byte()? - b'0',
            parser.must_read(b'.')?,
            parser.next_byte()? - b'0',
        );

        Ok(MimeVersion { major, minor })
    }
}

impl fmt::Display for MimeVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}.{}", MimeVersion::NAME, self.major, self.minor)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse() {
        let src = b"1.0";
        let mut scanner = Parser::new(src);
        let mime_version = MimeVersion::parse(&mut scanner).unwrap();

        assert_eq!(mime_version.major, 1);
        assert_eq!(mime_version.minor, 0);
    }
}
