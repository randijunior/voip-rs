use core::fmt;
use std::str::{self, FromStr};

use crate::error::Result;
use crate::parser::{HeaderParser, Parser};

/// The `Call-ID` SIP header.
///
/// Uniquely identifies a particular invitation or all
/// registrations of a particular client.
///
/// # Examples
///
/// ```
/// # use voip::header::CallId;
/// let cid = CallId::new("bs9ki9iqbee8k5kal8mpqb");
///
/// assert_eq!("Call-ID: bs9ki9iqbee8k5kal8mpqb", cid.to_string());
/// ```
#[derive(Debug, PartialEq, Eq, Clone, Hash)]
#[repr(transparent)]
pub struct CallId(String);

impl From<&str> for CallId {
    fn from(value: &str) -> Self {
        Self::new(value.into())
    }
}

impl FromStr for CallId {
    type Err = crate::error::Error;

    /// Parse a `To` header instance from a `&str`.
    fn from_str(s: &str) -> Result<Self> {
        Self::parse(&mut Parser::new(s))
    }
}

impl CallId {
    /// Creates a new `CallId` instance with the given
    /// identifier.
    pub fn new(id: String) -> Self {
        Self(id)
    }

    /// Returns the internal `CallId` identifier.
    pub fn id(&self) -> &str {
        &self.0
    }
}

impl HeaderParser for CallId {
    const NAME: &'static str = "Call-ID";
    const SHORT_NAME: &'static str = "i";

    fn parse(parser: &mut Parser) -> Result<Self> {
        let id = parser.read_until_new_line_as_str()?;

        Ok(CallId(id.to_owned()))
    }
}

impl fmt::Display for CallId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", CallId::NAME, self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse() {
        let src = b"bs9ki9iqbee8k5kal8mpqb\r\n";
        let mut scanner = Parser::new(src);
        let cid = CallId::parse(&mut scanner).unwrap();

        assert_eq!(cid.id(), "bs9ki9iqbee8k5kal8mpqb");
    }
}
