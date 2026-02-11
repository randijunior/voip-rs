use std::fmt;

use crate::error::Result;
use crate::macros::parse_header_param;
use crate::message::{NameAddr, Params};
use crate::parser::{HeaderParser, Parser};

/// The `Route` SIP header.
///
/// Specify the sequence of proxy servers and other
/// intermediaries that a SIP message should pass through on
/// its way to the final destination.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Route {
    pub(crate) name_addr: NameAddr,
    pub(crate) param: Option<Params>,
}

impl HeaderParser for Route {
    const NAME: &'static str = "Route";

    fn parse(parser: &mut Parser) -> Result<Self> {
        let name_addr = parser.parse_name_addr()?;
        let param = parse_header_param!(parser);
        Ok(Route { name_addr, param })
    }
}

impl fmt::Display for Route {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name_addr)?;

        if let Some(param) = &self.param {
            write!(f, ";{}", param)?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::message::{DomainName, Host, HostPort, Scheme};

    #[test]
    fn test_parse() {
        let src = b"<sip:bigbox3.site3.atlanta.com;lr>\r\n";
        let mut scanner = Parser::new(src);
        let r = Route::parse(&mut scanner);
        let r = r.unwrap();

        assert_eq!(r.name_addr.display, None);
        assert_eq!(r.name_addr.uri.scheme, Scheme::Sip);
        assert_eq!(
            r.name_addr.uri.host_port,
            HostPort {
                host: Host::DomainName(DomainName::new("bigbox3.site3.atlanta.com")),
                port: None
            }
        );
        assert!(r.name_addr.uri.lr_param);

        let src = b"<sip:server10.biloxi.com;lr>;foo=bar\r\n";
        let mut scanner = Parser::new(src);
        let r = Route::parse(&mut scanner);
        let r = r.unwrap();

        assert_eq!(r.name_addr.display, None);
        assert_eq!(r.name_addr.uri.scheme, Scheme::Sip);
        assert_eq!(
            r.name_addr.uri.host_port,
            HostPort {
                host: Host::DomainName(DomainName::new("server10.biloxi.com")),
                port: None
            }
        );
        assert_eq!(r.param.unwrap().get_named("foo"), Some("bar"));
    }
}
