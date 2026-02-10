use std::{fmt, str};

use crate::error::Result;
use crate::parser::{HeaderParser, Parser};

/// The `Max-Forwards` SIP header.
///
/// Limits the number of proxies or gateways that can
/// forward the request.
///
/// # Examples
/// ```
/// # use voip_rs::header::MaxForwards;
///
/// let max = MaxForwards::new(70);
///
/// assert_eq!("Max-Forwards: 70", max.to_string());
/// ```
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[repr(transparent)]
pub struct MaxForwards(u32);

impl MaxForwards {
    /// Creates a new `MaxForwards` header with the given
    /// number of forwards.
    pub const fn new(fowards: u32) -> Self {
        Self(fowards)
    }

    /// Returns the internal `MaxForwards` value.
    pub fn max_fowards(&self) -> u32 {
        self.0
    }
}

impl HeaderParser for MaxForwards {
    const NAME: &'static str = "Max-Forwards";

    fn parse(parser: &mut Parser) -> Result<MaxForwards> {
        let fowards = parser.read_u32()?;

        Ok(MaxForwards(fowards))
    }
}

impl fmt::Display for MaxForwards {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", MaxForwards::NAME, self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_parse() {
        let src = b"6\r\n";
        let mut scanner = Parser::new(src);
        let c_length = MaxForwards::parse(&mut scanner).unwrap();

        assert_eq!(scanner.remaining(), b"\r\n");
        assert_eq!(c_length.0, 6)
    }
}
