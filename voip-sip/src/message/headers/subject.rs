use std::{fmt, str};

use crate::error::Result;
use crate::parser::{HeaderParser, Parser};

/// The `Subject` SIP header.
///
/// Provides a summary or indicates the nature of the call.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Subject(String);

impl HeaderParser for Subject {
    const NAME: &'static str = "Subject";
    const SHORT_NAME: &'static str = "s";

    fn parse(parser: &mut Parser) -> Result<Self> {
        let subject = parser.read_until_new_line_as_str()?;

        Ok(Subject(subject.into()))
    }
}

impl fmt::Display for Subject {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", Subject::NAME, self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse() {
        let src = b"Need more boxes\r\n";
        let mut scanner = Parser::new(src);
        let subject = Subject::parse(&mut scanner);
        let subject = subject.unwrap();

        assert_eq!(scanner.remaining(), b"\r\n");
        assert_eq!(subject.0, "Need more boxes");

        let src = b"Tech Support\r\n";
        let mut scanner = Parser::new(src);
        let subject = Subject::parse(&mut scanner);
        let subject = subject.unwrap();

        assert_eq!(scanner.remaining(), b"\r\n");
        assert_eq!(subject.0, "Tech Support");
    }
}
