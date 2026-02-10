use std::fmt;

use crate::error::Result;
use crate::macros::parse_header_param;
use crate::message::{NameAddr, Params};
use crate::parser::{HeaderParser, Parser};

/// The `Record-Route` SIP header.
///
/// Keeps proxies in the signaling path for consistent
/// routing and session control.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct RecordRoute {
    /// The address of the record route.
    pub addr: NameAddr,
    /// Optional parameters associated with the record
    /// route.
    pub params: Option<Params>,
}

impl HeaderParser for RecordRoute {
    const NAME: &'static str = "Record-Route";

    fn parse(parser: &mut Parser) -> Result<Self> {
        let addr = parser.parse_name_addr()?;
        let params = parse_header_param!(parser);
        Ok(RecordRoute { addr, params })
    }
}

impl fmt::Display for RecordRoute {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", RecordRoute::NAME, self.addr)?;
        if let Some(param) = &self.params {
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
        let src = b"<sip:server10.biloxi.com;lr>\r\n";
        let mut scanner = Parser::new(src);
        let rr = RecordRoute::parse(&mut scanner);
        let rr = rr.unwrap();

        assert_eq!(rr.addr.display, None);
        assert_eq!(rr.addr.uri.scheme, Scheme::Sip);
        assert_eq!(
            rr.addr.uri.host_port,
            HostPort {
                host: Host::DomainName(DomainName::new("server10.biloxi.com")),
                port: None
            }
        );
        assert!(rr.addr.uri.lr_param);

        let src = b"<sip:bigbox3.site3.atlanta.com;lr>;foo=bar\r\n";
        let mut scanner = Parser::new(src);
        let rr = RecordRoute::parse(&mut scanner);
        let rr = rr.unwrap();

        assert_eq!(rr.addr.display, None);
        assert_eq!(rr.addr.uri.scheme, Scheme::Sip);
        assert_eq!(
            rr.addr.uri.host_port,
            HostPort {
                host: Host::DomainName(DomainName::new("bigbox3.site3.atlanta.com")),
                port: None
            }
        );
        assert_eq!(rr.params.unwrap().get_named("foo"), Some("bar"));
    }
}
