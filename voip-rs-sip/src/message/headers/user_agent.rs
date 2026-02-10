use std::{fmt, str};

use crate::error::Result;
use crate::parser::{HeaderParser, Parser};

/// The `User-Agent` SIP header.
///
/// Contains information about the `UAC` originating the
/// request.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct UserAgent(String);

impl HeaderParser for UserAgent {
    const NAME: &'static str = "User-Agent";

    /*
     * User-Agent  =  "User-Agent" HCOLON server-val *(LWS
     * server-val)
     */
    fn parse(parser: &mut Parser) -> Result<Self> {
        let agent = parser.read_until_new_line_as_str()?;

        Ok(UserAgent(agent.into()))
    }
}

impl fmt::Display for UserAgent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", UserAgent::NAME, self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse() {
        let src = b"Softphone Beta1.5\r\n";
        let mut scanner = Parser::new(src);
        let ua = UserAgent::parse(&mut scanner);
        let ua = ua.unwrap();

        assert_eq!(scanner.remaining(), b"\r\n");
        assert_eq!(ua.0, "Softphone Beta1.5");
    }
}
