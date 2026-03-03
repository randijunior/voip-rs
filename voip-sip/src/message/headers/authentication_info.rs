use std::{fmt, str};

use crate::error::{ParseErrorKind as ErrorKind, Result};
use crate::macros::comma_separated;
use crate::message::auth::{CNONCE, NC, NEXTNONCE, QOP, RSPAUTH};
use crate::message::param::Param;
use crate::parser::{HeaderParser, SipParser};

#[derive(Debug, Default, PartialEq, Eq, Clone)]
pub struct AuthenticationInfo {
    nextnonce: Option<String>,
    qop: Option<String>,
    rspauth: Option<String>,
    cnonce: Option<String>,
    nc: Option<String>,
}

impl HeaderParser for AuthenticationInfo {
    const NAME: &'static str = "Authentication-Info";

    fn parse(parser: &mut SipParser) -> Result<Self> {
        let mut auth_info = Self::default();

        comma_separated!(parser => {
            let Param {name, value} = parser.parse_param_ref()?.into();
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
        write!(f, "{}: ", Self::NAME)?;

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
