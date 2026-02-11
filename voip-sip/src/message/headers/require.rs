use std::{fmt, str};

use itertools::Itertools;

use crate::error::Result;
use crate::macros::comma_separated_header_value;
use crate::parser::{HeaderParser, Parser};

/// The `Require` SIP header.
///
/// Is used by `UACs` to tell `UASs` about options that the
/// `UAC` expects the `UAS` to support in order to process
/// the request.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Require(Vec<String>);

impl HeaderParser for Require {
    const NAME: &'static str = "Require";

    fn parse(parser: &mut Parser) -> Result<Self> {
        let tags = comma_separated_header_value!(parser => parser.parse_token()?.into());

        Ok(Require(tags))
    }
}

impl fmt::Display for Require {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", Require::NAME, self.0.iter().format(", "))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse() {
        let src = b"100rel\r\n";
        let mut scanner = Parser::new(src);
        let require = Require::parse(&mut scanner);
        let require = require.unwrap();

        assert_eq!(require.0.get(0), Some(&"100rel".into()));
    }
}
