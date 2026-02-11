use std::{fmt, str};

use itertools::Itertools;

use crate::error::Result;
use crate::macros::comma_separated_header_value;
use crate::parser::{HeaderParser, Parser};

/// The `Proxy-Require` SIP header.
///
/// Indicate `proxy-sensitive` features that must be
/// supported by the proxy.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct ProxyRequire(Vec<String>);

impl HeaderParser for ProxyRequire {
    const NAME: &'static str = "Proxy-Require";

    fn parse(parser: &mut Parser) -> Result<Self> {
        let tags = comma_separated_header_value!(parser => parser.parse_token()?.into());

        Ok(ProxyRequire(tags))
    }
}

impl fmt::Display for ProxyRequire {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", ProxyRequire::NAME, self.0.iter().format(", "))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse() {
        let src = b"foo, bar\r\n";
        let mut scanner = Parser::new(src);
        let proxy_require = ProxyRequire::parse(&mut scanner).unwrap();

        assert_eq!(scanner.remaining(), b"\r\n");

        assert_eq!(proxy_require.0.get(0), Some(&"foo".into()));
        assert_eq!(proxy_require.0.get(1), Some(&"bar".into()));
    }
}
