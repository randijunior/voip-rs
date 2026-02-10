use std::{fmt, str};

use crate::error::Result;
use crate::parser::{HeaderParser, Parser};

/// The `Date` SIP header.
///
/// Reflects the time when the request or response is first
/// sent.
///
/// # Examples
///
/// ```
/// # use voip_rs::{header::Date};
/// let date = Date::new("Sat, 13 Nov 2010 23:29:00 GMT");
///
/// assert_eq!("Date: Sat, 13 Nov 2010 23:29:00 GMT", date.to_string());
/// ```
#[derive(Debug, PartialEq, Eq, Clone)]
#[repr(transparent)]
pub struct Date(String);

impl Date {
    /// Create a new `Date` instance.
    pub fn new(d: &str) -> Self {
        Self(d.into())
    }
}

impl HeaderParser for Date {
    const NAME: &'static str = "Date";

    fn parse(parser: &mut Parser) -> Result<Self> {
        let date = parser.read_until_new_line_as_str()?;

        Ok(Date(date.into()))
    }
}

impl fmt::Display for Date {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", Date::NAME, self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse() {
        let src = b"Sat, 13 Nov 2010 23:29:00 GMT\r\n";
        let mut scanner = Parser::new(src);
        let date = Date::parse(&mut scanner).unwrap();

        assert_eq!(scanner.remaining(), b"\r\n");
        assert_eq!(date.0, "Sat, 13 Nov 2010 23:29:00 GMT");
    }
}
