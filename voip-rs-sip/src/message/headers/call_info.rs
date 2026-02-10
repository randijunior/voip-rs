use std::{fmt, str};

use crate::error::Result;
use crate::macros::parse_header_param;
use crate::message::Params;
use crate::parser::{HeaderParser, Parser};

const PURPOSE: &str = "purpose";

/// The `Call-Info` SIP header.
///
/// Provides aditional information aboute the caller or
/// calle.
///
/// # Examples
///
/// ```
/// # use voip_rs::header::CallInfo;
/// let mut info = CallInfo::new("http://www.example.com/alice/");
///
/// assert_eq!(
///     "Call-Info: <http://www.example.com/alice/>",
///     info.to_string()
/// );
/// ```
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct CallInfo {
    url: String,
    purpose: Option<String>,
    params: Option<Params>,
}

impl CallInfo {
    /// Creates a new `CallInfo` header.
    pub fn new(url: &str) -> Self {
        Self {
            url: url.into(),
            purpose: None,
            params: None,
        }
    }

    /// Creates a new `CallInfo` header with the given url,
    /// params and purpose.
    pub fn from_parts(url: String, purpose: Option<&str>, params: Option<Params>) -> Self {
        Self {
            url,
            purpose: purpose.map(|p| p.into()),
            params,
        }
    }

    /// Set the url for this header.
    pub fn set_url(&mut self, url: &str) {
        self.url = url.into();
    }
}

impl HeaderParser for CallInfo {
    const NAME: &'static str = "Call-Info";

    fn parse(parser: &mut Parser) -> Result<Self> {
        let mut purpose: Option<String> = None;
        // must be an '<'
        parser.next_byte()?;
        let url = parser.read_until(b'>');
        // must be an '>'
        parser.next_byte()?;
        let url = str::from_utf8(url)?;
        let params = parse_header_param!(parser, PURPOSE = purpose);

        Ok(CallInfo {
            url: url.into(),
            params,
            purpose,
        })
    }
}

impl fmt::Display for CallInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: <{}>", CallInfo::NAME, self.url)?;
        if let Some(purpose) = &self.purpose {
            write!(f, ";{}", purpose)?;
        }
        if let Some(params) = &self.params {
            write!(f, "{}", params)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse() {
        let src = b"<http://wwww.example.com/alice/photo.jpg> \
        ;purpose=icon\r\n";
        let mut scanner = Parser::new(src);
        let info = CallInfo::parse(&mut scanner).unwrap();

        assert_eq!(scanner.remaining(), b"\r\n");
        assert_eq!(info.url, "http://wwww.example.com/alice/photo.jpg");
        assert_eq!(info.purpose, Some("icon".into()));

        let src = b"<http://www.example.com/alice/> ;purpose=info\r\n";
        let mut scanner = Parser::new(src);
        let info = CallInfo::parse(&mut scanner).unwrap();

        assert_eq!(info.url, "http://www.example.com/alice/");
        assert_eq!(info.purpose, Some("info".into()));
    }
}
