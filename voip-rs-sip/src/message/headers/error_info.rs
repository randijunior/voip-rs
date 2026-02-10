use std::{fmt, str};

use itertools::Itertools;

use crate::error::Result;
use crate::macros::{comma_separated_header_value, parse_header_param};
use crate::message::Params;
use crate::parser::{HeaderParser, Parser};

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct ErrorInfoUri {
    url: String,
    params: Option<Params>,
}

impl fmt::Display for ErrorInfoUri {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.url)?;

        if let Some(param) = &self.params {
            write!(f, ";{}", param)?;
        }

        Ok(())
    }
}

/// The `Error-Info` SIP header.
///
/// Provides a pointer to additional information about the
/// error status response.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct ErrorInfo(Vec<ErrorInfoUri>);

impl HeaderParser for ErrorInfo {
    const NAME: &'static str = "Error-Info";

    fn parse(parser: &mut Parser) -> Result<Self> {
        let infos = comma_separated_header_value!(parser => {
            parser.next_byte()?;
            let url = parser.read_until(b'>');
            parser.next_byte()?;

            let url = str::from_utf8(url)?;
            let params = parse_header_param!(parser);
            ErrorInfoUri {
                url: url.into(),
                params
            }
        });

        Ok(ErrorInfo(infos))
    }
}

impl fmt::Display for ErrorInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0.iter().format(", "))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse() {
        let src = b"<sip:not-in-service-recording@atlanta.com>\r\n";
        let mut scanner = Parser::new(src);
        let err_info = ErrorInfo::parse(&mut scanner).unwrap();
        assert_eq!(scanner.remaining(), b"\r\n");

        let err = err_info.0.get(0).unwrap();
        assert_eq!(err.url, "sip:not-in-service-recording@atlanta.com");
    }
}
