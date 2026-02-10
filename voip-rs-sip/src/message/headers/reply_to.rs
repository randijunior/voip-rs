use std::fmt;

use crate::error::Result;
use crate::macros::parse_header_param;
use crate::message::{Params, SipUri};
use crate::parser::{HeaderParser, Parser};

/// The `Reply-To` SIP header.
///
/// Contains a logical return URI that may be different from
/// the From header field
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct ReplyTo {
    uri: SipUri,
    param: Option<Params>,
}

impl HeaderParser for ReplyTo {
    const NAME: &'static str = "Reply-To";

    fn parse(parser: &mut Parser) -> Result<Self> {
        let uri = parser.parse_sip_uri(false)?;
        let param = parse_header_param!(parser);

        Ok(ReplyTo { uri, param })
    }
}

impl fmt::Display for ReplyTo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", ReplyTo::NAME, self.uri)?;
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
        let src = b"Bob <sip:bob@biloxi.com>\r\n";
        let mut scanner = Parser::new(src);
        let reply_to = ReplyTo::parse(&mut scanner);
        let reply_to = reply_to.unwrap();

        assert_matches!(reply_to, ReplyTo {
            uri: SipUri::NameAddr(addr),
            ..
        } => {
            assert_eq!(addr.uri.scheme, Scheme::Sip);
            assert_eq!(addr.uri.user.unwrap().user, "bob");
            assert_eq!(
                addr.uri.host_port,
                HostPort {
                    host: Host::DomainName(DomainName::new("biloxi.com")),
                    port: None
                }
            );
        });
    }
}
