use std::fmt;

use crate::error::Result;
use crate::message::Challenge;
use crate::parser::{HeaderParser, Parser};

/// The `Proxy-Authenticate` SIP header.
///
/// The authentication requirements from a proxy server to a
/// client.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct ProxyAuthenticate(Challenge);

impl HeaderParser for ProxyAuthenticate {
    const NAME: &'static str = "Proxy-Authenticate";

    fn parse(parser: &mut Parser) -> Result<Self> {
        let challenge = parser.parse_auth_challenge()?;

        Ok(ProxyAuthenticate(challenge))
    }
}

impl fmt::Display for ProxyAuthenticate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", ProxyAuthenticate::NAME, self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::message::DigestChallenge;

    #[test]
    fn test_parse() {
        let src = b"Digest realm=\"atlanta.com\", \
        domain=\"sip:ss1.carrier.com\", qop=\"auth\", \
        nonce=\"f84f1cec41e6cbe5aea9c8e88d359\", \
        opaque=\"\", stale=FALSE, algorithm=MD5\r\n";
        let mut scanner = Parser::new(src);
        let proxy_auth = ProxyAuthenticate::parse(&mut scanner).unwrap();

        assert_matches!(proxy_auth.0, Challenge::Digest( DigestChallenge { realm, domain, nonce, opaque, stale, algorithm, qop, .. }) => {
            assert_eq!(realm, Some("\"atlanta.com\"".into()));
            assert_eq!(algorithm, Some("MD5".into()));
            assert_eq!(domain, Some("\"sip:ss1.carrier.com\"".into()));
            assert_eq!(qop, Some("\"auth\"".into()));
            assert_eq!(nonce, Some("\"f84f1cec41e6cbe5aea9c8e88d359\"".into()));
            assert_eq!(opaque, Some("\"\"".into()));
            assert_eq!(stale, Some("FALSE".into()));
        });
    }
}
