use std::{fmt, str};

use crate::error::Result;
use crate::parser::{HeaderParser, Parser};

/// The `Server` SIP header.
///
/// Is used by UACs to tell UASs about options
/// that the UAC expects the UAS to support in order to
/// process the request.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Server(String);

impl Server {
    /// Creates a new `Server` header with the given value.
    pub fn new(s: &str) -> Self {
        Self(s.into())
    }
}

impl HeaderParser for Server {
    const NAME: &'static str = "Server";

    fn parse(parser: &mut Parser) -> Result<Self> {
        let server = parser.read_until_new_line_as_str()?;

        Ok(Server(server.into()))
    }
}

impl fmt::Display for Server {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", Server::NAME, self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse() {
        let src = b"HomeServer v2\r\n";
        let mut scanner = Parser::new(src);
        let server = Server::parse(&mut scanner);
        let server = server.unwrap();

        assert_eq!(scanner.remaining(), b"\r\n");
        assert_eq!(server.0, "HomeServer v2");
    }
}
