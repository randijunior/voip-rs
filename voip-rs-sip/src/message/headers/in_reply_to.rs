use std::{fmt, str};

use itertools::Itertools;

use crate::error::Result;
use crate::macros::comma_separated_header_value;
use crate::message::headers::CallId;
use crate::parser::{HeaderParser, Parser};

/// The `In-Reply-To` SIP header.
///
/// Enumerates the `Call-IDs` that this call references or
/// returns.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct InReplyTo(Vec<CallId>);

impl HeaderParser for InReplyTo {
    const NAME: &'static str = "In-Reply-To";

    fn parse(parser: &mut Parser) -> Result<Self> {
        let ids = comma_separated_header_value!(parser => {
            let id = parser.not_comma_or_newline();
            let id = str::from_utf8(id)?;

            CallId::from(id)
        });

        Ok(InReplyTo(ids))
    }
}

impl fmt::Display for InReplyTo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", InReplyTo::NAME, self.0.iter().format(", "))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse() {
        let src = b"70710@saturn.bell-tel.com, 17320@saturn.bell-tel.com\r\n";
        let mut scanner = Parser::new(src);
        let in_reply_to = InReplyTo::parse(&mut scanner).unwrap();
        assert_eq!(scanner.remaining(), b"\r\n");

        assert_eq!(
            in_reply_to.0.get(0).unwrap().id(),
            "70710@saturn.bell-tel.com"
        );
        assert_eq!(
            in_reply_to.0.get(1).unwrap().id(),
            "17320@saturn.bell-tel.com"
        );
    }
}
