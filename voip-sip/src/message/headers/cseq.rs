use core::fmt;
use std::str::{self, FromStr};

use crate::error::Result;
use crate::message::Method;
use crate::parser::{HeaderParser, Parser};

/// The `CSeq` SIP header.
///
/// Ensures order and tracking of SIP Transaction within a
/// session.
///
/// # Examples
///
/// ```
/// # use voip::{header::CSeq, message::Method};
/// let cseq = CSeq::new(1, Method::Options);
///
/// assert_eq!("CSeq: 1 OPTIONS", cseq.to_string());
/// ```
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct CSeq {
    /// The CSeq number.
    pub cseq: u32,
    /// The CSeq method.
    pub method: Method,
}

impl fmt::Display for CSeq {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {} {}", CSeq::NAME, self.cseq, self.method)
    }
}

impl FromStr for CSeq {
    type Err = crate::error::Error;

    /// Parse a `To` header instance from a `&str`.
    fn from_str(s: &str) -> Result<Self> {
        Self::parse(&mut Parser::new(s))
    }
}

impl CSeq {
    /// Creates a new `CSeq` instance.
    pub fn new(cseq: u32, method: Method) -> Self {
        Self { cseq, method }
    }

    /// Returns the cseq number.
    pub fn cseq(&self) -> u32 {
        self.cseq
    }

    /// Returns the SIP method associated with the cseq.
    pub fn method(&self) -> &Method {
        &self.method
    }
}

impl HeaderParser for CSeq {
    const NAME: &'static str = "CSeq";

    fn parse(parser: &mut Parser) -> Result<CSeq> {
        let cseq = parser.read_u32()?;

        parser.skip_ws();
        let b_method = parser.alphabetic();
        let method = Method::from(b_method);

        Ok(CSeq { cseq, method })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_parse() {
        let src = b"4711 INVITE\r\n";
        let mut scanner = Parser::new(src);
        let c_length = CSeq::parse(&mut scanner).unwrap();

        assert_eq!(scanner.remaining(), b"\r\n");
        assert_eq!(c_length.method, Method::Invite);
        assert_eq!(c_length.cseq, 4711);
    }
}
