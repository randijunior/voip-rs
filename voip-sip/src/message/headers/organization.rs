use std::{fmt, str};

use crate::error::Result;
use crate::parser::{HeaderParser, Parser};

/// The `Organization` SIP header.
///
/// The name of the organization to which the SIP
/// element issuing the request or response belongs.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Organization(String);

impl HeaderParser for Organization {
    const NAME: &'static str = "Organization";

    fn parse(parser: &mut Parser) -> Result<Self> {
        let organization = parser.read_until_new_line_as_str()?;

        Ok(Organization(organization.into()))
    }
}

impl fmt::Display for Organization {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", Organization::NAME, self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse() {
        let src = b"Boxes by Bob\r\n";
        let mut scanner = Parser::new(src);
        let org = Organization::parse(&mut scanner).unwrap();

        assert_eq!(org.0, "Boxes by Bob");
    }
}
