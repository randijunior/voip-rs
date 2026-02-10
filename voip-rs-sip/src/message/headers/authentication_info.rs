use std::{fmt, str};

use crate::error::{ParseErrorKind as ErrorKind, Result};
use crate::macros::comma_separated;
use crate::message::{CNONCE, NC, NEXTNONCE, Param, QOP, RSPAUTH};
use crate::parser::{HeaderParser, Parser};

/// The `Authentication-Info` SIP header.
///
/// Provides additional authentication information.
///
/// # Examples
///
/// ```
/// # use voip_rs::header::AuthenticationInfo;
/// let mut auth = AuthenticationInfo::default();
/// auth.set_nextnonce(Some("5ccc069c403ebaf9f0171e9517f40e41"));
///
/// assert_eq!(
///     "Authentication-Info: nextnonce=5ccc069c403ebaf9f0171e9517f40e41",
///     auth.to_string()
/// );
/// ```
#[derive(Debug, Default, PartialEq, Eq, Clone)]
pub struct AuthenticationInfo {
    nextnonce: Option<String>,
    qop: Option<String>,
    rspauth: Option<String>,
    cnonce: Option<String>,
    nc: Option<String>,
}

impl<'a> AuthenticationInfo {
    /// Sets the `nextnonce` field.
    pub fn set_nextnonce(&mut self, nextnonce: Option<&'a str>) {
        self.nextnonce = nextnonce.map(|n| n.into());
    }
}

impl HeaderParser for AuthenticationInfo {
    const NAME: &'static str = "Authentication-Info";

    fn parse(parser: &mut Parser) -> Result<Self> {
        let mut auth_info = AuthenticationInfo::default();

        comma_separated!(parser => {
            let Param {name, value} = parser.parse_ref_param()?.into();
            match name.as_ref() {
                NEXTNONCE => auth_info.nextnonce = value,
                QOP => auth_info.qop = value,
                RSPAUTH => auth_info.rspauth = value,
                CNONCE => auth_info.cnonce = value,
                NC => auth_info.nc = value,
                _ => parser.parse_error(ErrorKind::Header)?,
            };
        });

        Ok(auth_info)
    }
}

impl fmt::Display for AuthenticationInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: ", AuthenticationInfo::NAME)?;

        if let Some(nextnonce) = &self.nextnonce {
            write!(f, "nextnonce={}", nextnonce)?;
        }
        if let Some(qop) = &self.qop {
            write!(f, ", qop={}", qop)?;
        }
        if let Some(rspauth) = &self.rspauth {
            write!(f, ", rspauth={}", rspauth)?;
        }
        if let Some(cnonce) = &self.cnonce {
            write!(f, ", cnonce={}", cnonce)?;
        }
        if let Some(nc) = &self.nc {
            write!(f, ", nc={}", nc)?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse() {
        let src = b"nextnonce=\"47364c23432d2e131a5fb210812c\"\r\n";
        let mut scanner = Parser::new(src);
        let auth_info = AuthenticationInfo::parse(&mut scanner).unwrap();

        assert_eq!(scanner.remaining(), b"\r\n");
        assert_eq!(
            auth_info.nextnonce,
            Some("\"47364c23432d2e131a5fb210812c\"".into())
        );

        let src = b"nextnonce=\"5ccc069c403ebaf9f0171e9517f40e41\", \
        cnonce=\"0a4f113b\", nc=00000001, \
        qop=\"auth\", \
        rspauth=\"6629fae49393a05397450978507c4ef1\"\r\n";
        let mut scanner = Parser::new(src);
        let auth_info = AuthenticationInfo::parse(&mut scanner).unwrap();

        assert_eq!(scanner.remaining(), b"\r\n");
        assert_eq!(
            auth_info.nextnonce,
            Some("\"5ccc069c403ebaf9f0171e9517f40e41\"".into())
        );
        assert_eq!(auth_info.cnonce, Some("\"0a4f113b\"".into()));
        assert_eq!(auth_info.nc, Some("00000001".into()));
        assert_eq!(auth_info.qop, Some("\"auth\"".into()));
        assert_eq!(
            auth_info.rspauth,
            Some("\"6629fae49393a05397450978507c4ef1\"".into())
        );
    }
}
