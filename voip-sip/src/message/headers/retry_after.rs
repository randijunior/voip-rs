use std::{fmt, str, u32};

use crate::error::Result;
use crate::macros::parse_header_param;
use crate::message::Params;
use crate::parser::{HeaderParser, Parser};

/// The `Retry-After` SIP header.
///
/// Indicate how long the service is expected to be
/// unavailable to the requesting client.
/// Or when the called party anticipates being available
/// again.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct RetryAfter {
    seconds: u32,
    param: Option<Params>,
    comment: Option<String>,
}

impl HeaderParser for RetryAfter {
    const NAME: &'static str = "Retry-After";

    fn parse(parser: &mut Parser) -> Result<Self> {
        let digits = parser.read_u32()?;
        let mut comment = None;

        parser.skip_ws();
        if let Some(b'(') = parser.peek_byte() {
            parser.next_byte()?;
            let b = parser.read_until(b')');
            parser.next_byte()?;
            comment = Some(str::from_utf8(b)?);
        }
        let param = parse_header_param!(parser);

        Ok(RetryAfter {
            seconds: digits,
            param,
            comment: comment.map(|c| c.into()),
        })
    }
}

impl fmt::Display for RetryAfter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.seconds)?;

        if let Some(param) = &self.param {
            write!(f, ";{}", param)?;
        }
        if let Some(comment) = &self.comment {
            write!(f, "{}", comment)?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_parse() {
        let src = b"18000;duration=3600\r\n";
        let mut scanner = Parser::new(src);
        let retry_after = RetryAfter::parse(&mut scanner);
        let retry_after = retry_after.unwrap();

        assert_eq!(scanner.remaining(), b"\r\n");
        assert_eq!(retry_after.seconds, 18000);
        assert_eq!(
            retry_after.param.unwrap().get_named("duration"),
            Some("3600")
        );

        let src = b"120 (I'm in a meeting)\r\n";
        let mut scanner = Parser::new(src);
        let retry_after = RetryAfter::parse(&mut scanner);
        let retry_after = retry_after.unwrap();

        assert_eq!(scanner.remaining(), b"\r\n");
        assert_eq!(retry_after.seconds, 120);
        assert_eq!(retry_after.comment, Some("I'm in a meeting".into()));
    }
}
