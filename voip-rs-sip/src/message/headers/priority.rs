use std::{fmt, str};

use crate::error::Result;
use crate::parser::{HeaderParser, Parser};

/// The `Priority` SIP header.
///
/// Indicates the urgency of the request as received by the
/// client.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Priority(String);

impl HeaderParser for Priority {
    const NAME: &'static str = "Priority";

    fn parse(parser: &mut Parser) -> Result<Self> {
        let priority = parser.parse_token()?;

        Ok(Priority(priority.into()))
    }
}

impl fmt::Display for Priority {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", Priority::NAME, self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse() {
        let src = b"emergency\r\n";
        let mut scanner = Parser::new(src);
        let priority = Priority::parse(&mut scanner).unwrap();

        assert_eq!(priority.0, "emergency");
    }
}
