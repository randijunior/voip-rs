use std::{fmt, str};

use crate::error::Result;
use crate::macros::parse_header_param;
use crate::message::Params;
use crate::parser::{HeaderParser, Parser};

/// The `Alert-Info` SIP header.
///
/// Specifies an alternative ring tone.
///
/// # Examples
///
/// ```
/// # use voip::header::AlertInfo;
/// let info = AlertInfo::new("http://www.alert.com/sounds/moo.wav");
///
/// assert_eq!(
///     info.to_string(),
///     "Alert-Info: <http://www.alert.com/sounds/moo.wav>"
/// );
/// ```
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct AlertInfo {
    url: String,
    params: Option<Params>,
}

impl AlertInfo {
    /// Creates a new `AlertInfo` header.
    pub fn new(url: &str) -> Self {
        Self {
            url: url.into(),
            params: None,
        }
    }

    /// Creates a new `AlertInfo` header with the specified
    /// url and params.
    pub fn from_parts(url: String, params: Option<Params>) -> Self {
        Self { url, params }
    }

    /// Set the url for this header.
    pub fn set_url(&mut self, url: &str) {
        self.url = url.into();
    }
}

impl HeaderParser for AlertInfo {
    const NAME: &'static str = "Alert-Info";

    fn parse(parser: &mut Parser) -> Result<Self> {
        parser.skip_ws();

        parser.read()?;
        let url = parser.read_until(b'>');
        parser.read()?;

        let url = str::from_utf8(url)?.into();
        let params = parse_header_param!(parser);

        Ok(AlertInfo { url, params })
    }
}

impl fmt::Display for AlertInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: <{}>", AlertInfo::NAME, self.url)?;
        if let Some(params) = &self.params {
            write!(f, "{}", params)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::parser::Parser;

    #[test]
    fn test_parse() {
        let src = b"<http://www.example.com/sounds/moo.wav>\r\n";
        let mut scanner = Parser::new(src);
        let alert_info = AlertInfo::parse(&mut scanner);
        let alert_info = alert_info.unwrap();

        assert_eq!(scanner.remaining(), b"\r\n");
        assert_eq!(alert_info.url, "http://www.example.com/sounds/moo.wav");

        let src = b"<http://example.com/ringtones/premium.wav>;purpose=ringtone\r\n";
        let mut scanner = Parser::new(src);
        let alert_info = AlertInfo::parse(&mut scanner);
        let alert_info = alert_info.unwrap();

        assert_eq!(scanner.remaining(), b"\r\n");
        assert_eq!(alert_info.url, "http://example.com/ringtones/premium.wav");
        assert_eq!(
            alert_info.params.unwrap().get_named("purpose"),
            Some("ringtone")
        );
    }
}
