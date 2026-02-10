use core::fmt;
use std::str;

use crate::MediaType;
use crate::error::Result;
use crate::parser::{HeaderParser, Parser};

/// The `Content-Type` SIP header.
///
/// Indicates the media type of the `message-body` sent to
/// the recipient.
///
/// Both the long (`Content-Type`) and short (`c`) header
/// names are supported.
///
/// # Examples
/// ```
/// # use voip_rs::header::ContentType;
/// # use voip_rs::MediaType;
///
/// let ctype = ContentType::new(MediaType::from_static("application/sdp").unwrap());
///
/// assert_eq!("Content-Type: application/sdp", ctype.to_string());
/// ```
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct ContentType(MediaType);

impl ContentType {
    /// Creates a new `Content-Type` with sdp as `MediaType`
    pub fn new_sdp() -> Self {
        Self(MediaType {
            mimetype: crate::MimeType {
                mtype: "application".into(),
                subtype: "sdp".into(),
            },
            param: None,
        })
    }

    /// Creates a new `ContentType`.
    pub fn new(m: MediaType) -> Self {
        Self(m)
    }

    /// Returns the internal `MediaType`.
    pub fn media_type(&self) -> &MediaType {
        &self.0
    }
}

impl HeaderParser for ContentType {
    const NAME: &'static str = "Content-Type";
    const SHORT_NAME: &'static str = "c";

    fn parse(parser: &mut Parser) -> Result<Self> {
        let media_type = MediaType::parse(parser)?;

        Ok(ContentType(media_type))
    }
}

impl fmt::Display for ContentType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", ContentType::NAME, self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse() {
        let src = b"application/sdp\r\n";
        let mut scanner = Parser::new(src);
        let c_type = ContentType::parse(&mut scanner);
        let c_type = c_type.unwrap();

        assert_eq!(scanner.remaining(), b"\r\n");
        assert_eq!(c_type.0.mimetype.mtype, "application");
        assert_eq!(c_type.0.mimetype.subtype, "sdp");

        let src = b"text/html; charset=ISO-8859-4\r\n";
        let mut scanner = Parser::new(src);
        let c_type = ContentType::parse(&mut scanner);
        let c_type = c_type.unwrap();

        assert_eq!(scanner.remaining(), b"\r\n");
        assert_eq!(c_type.0.mimetype.mtype, "text");
        assert_eq!(c_type.0.mimetype.subtype, "html");
        assert_eq!(
            c_type.0.param.unwrap().get_named("charset"),
            Some("ISO-8859-4")
        );
    }
}
