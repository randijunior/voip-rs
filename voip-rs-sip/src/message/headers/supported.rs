use std::{fmt, str};

use itertools::Itertools;

use crate::error::Result;
use crate::macros::comma_separated_header_value;
use crate::parser::{HeaderParser, Parser};

/// The `Supported` SIP header.
///
/// Enumerates all the extensions supported by the `UAC` or
/// `UAS`.
#[derive(Debug, PartialEq, Eq, Clone, Default)]
pub struct Supported(Vec<String>);

impl Supported {
    /// Add a new tag to the list of supported tags.
    pub fn add_tag(&mut self, tag: &str) {
        self.0.push(tag.into());
    }
}

impl HeaderParser for Supported {
    const NAME: &'static str = "Supported";
    const SHORT_NAME: &'static str = "k";

    fn parse(parser: &mut Parser) -> Result<Self> {
        let tags = comma_separated_header_value!(parser => parser.parse_token()?.into());

        Ok(Supported(tags))
    }
}

impl fmt::Display for Supported {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", Supported::NAME, self.0.iter().format(", "))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse() {
        let src = b"100rel, other\r\n";
        let mut scanner = Parser::new(src);
        let supported = Supported::parse(&mut scanner);
        let supported = supported.unwrap();

        assert_eq!(scanner.remaining(), b"\r\n");
        assert_eq!(supported.0.get(0), Some(&"100rel".into()));
        assert_eq!(supported.0.get(1), Some(&"other".into()));
    }
}
