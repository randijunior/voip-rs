use std::fmt;

use crate::error::Result;
use crate::message::Credential;
use crate::parser::{HeaderParser, Parser};

/// The `Authorization` SIP header.
///
/// Contains authentication credentials of a `UserAgent`.
///
/// # Examples
///
/// ```
/// # use voip_rs::header::Authorization;
/// # use voip_rs::message::auth::{Credential, DigestCredential};
/// let auth = Authorization(Credential::Digest(DigestCredential {
///     username: Some("Alice".into()),
///     realm: Some("atlanta.com".into()),
///     nonce: Some("84a4cc6f3082121f32b42a2187831a9e".into()),
///     response: Some("7587245234b3434cc3412213e5f113a5432".into()),
///     ..Default::default()
/// }));
///
/// assert_eq!(
///     "Authorization: Digest username=Alice, realm=atlanta.com, \
///             nonce=84a4cc6f3082121f32b42a2187831a9e, \
///             response=7587245234b3434cc3412213e5f113a5432",
///     auth.to_string()
/// );
/// ```
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Authorization(pub Credential);

impl<'a> Authorization {
    /// Get the `Credential` from the `Authorization`
    /// header.
    pub fn credential(&self) -> &Credential {
        &self.0
    }
}

impl HeaderParser for Authorization {
    const NAME: &'static str = "Authorization";

    fn parse(parser: &mut Parser) -> Result<Self> {
        let credential = parser.parse_auth_credential()?;

        Ok(Authorization(credential))
    }
}

impl fmt::Display for Authorization {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", Authorization::NAME, self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::message::DigestCredential;

    #[test]
    fn test_parse() {
        let src = b"Digest username=\"Alice\", realm=\"atlanta.com\", \
        nonce=\"84a4cc6f3082121f32b42a2187831a9e\",\
        response=\"7587245234b3434cc3412213e5f113a5432\"\r\n";
        let mut scanner = Parser::new(src);
        let auth = Authorization::parse(&mut scanner).unwrap();

        assert_eq!(scanner.remaining(), b"\r\n");

        assert_matches!(auth.credential(), &Credential::Digest( DigestCredential { ref username, ref realm, ref nonce, ref response, ..}) => {
            assert_eq!(username, &Some("\"Alice\"".into()));
            assert_eq!(realm, &Some("\"atlanta.com\"".into()));
            assert_eq!(
                nonce,
                &Some("\"84a4cc6f3082121f32b42a2187831a9e\"".into())
            );
            assert_eq!(
                response,
                &Some("\"7587245234b3434cc3412213e5f113a5432\"".into())
            );
        });
    }
}
