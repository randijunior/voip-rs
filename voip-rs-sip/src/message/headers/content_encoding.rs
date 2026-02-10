use core::fmt;
use std::str;

use itertools::Itertools;

use crate::error::Result;
use crate::macros::comma_separated_header_value;
use crate::parser::{HeaderParser, Parser};

/// The `Content-Encoding` SIP header.
///
/// Indicates what decoding mechanisms must be applied to
/// obtain the media-type referenced by the Content-Type
/// header field.
///
/// # Examples
///
/// ```
/// # use voip_rs::header::ContentEncoding;
/// let encoding = ContentEncoding::from(["gzip", "deflate"]);
///
/// assert_eq!("Content-Encoding: gzip, deflate", encoding.to_string());
/// ```
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct ContentEncoding(Vec<String>);

impl ContentEncoding {
    ///
    pub fn new() -> Self {
        todo!()
    }

    /// Get the content encoding at the specified index.
    pub fn get(&self, index: usize) -> Option<&str> {
        self.0.get(index).map(|s| s.as_ref())
    }

    /// Return the number of content encodings.
    pub fn len(&self) -> usize {
        self.0.len()
    }
}

impl HeaderParser for ContentEncoding {
    const NAME: &'static str = "Content-Encoding";
    const SHORT_NAME: &'static str = "e";

    fn parse(parser: &mut Parser) -> Result<Self> {
        let codings = comma_separated_header_value!(parser => parser.parse_token()?.into());

        Ok(ContentEncoding(codings))
    }
}

impl fmt::Display for ContentEncoding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}: {}",
            ContentEncoding::NAME,
            self.0.iter().format(", ")
        )
    }
}

impl<'a, const N: usize> From<[&str; N]> for ContentEncoding {
    fn from(value: [&str; N]) -> Self {
        Self(value.into_iter().map(String::from).collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse() {
        let src = b"gzip\r\n";
        let mut scanner = Parser::new(src);
        let encoding = ContentEncoding::parse(&mut scanner);
        let encoding = encoding.unwrap();

        assert!(encoding.len() == 1);
        assert_eq!(scanner.remaining(), b"\r\n");
        assert_eq!(encoding.get(0), Some("gzip"));

        let src = b"gzip, deflate\r\n";
        let mut scanner = Parser::new(src);
        let encoding = ContentEncoding::parse(&mut scanner);
        let encoding = encoding.unwrap();

        assert!(encoding.len() == 2);
        assert_eq!(scanner.remaining(), b"\r\n");
        assert_eq!(encoding.get(0), Some("gzip"));
        assert_eq!(encoding.get(1), Some("deflate"));
    }
}
