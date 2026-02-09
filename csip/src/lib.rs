#![warn(missing_docs)]
//! # csip
//!
//! A rust library that implements the SIP protocol.
//!

pub mod endpoint;
pub mod message;
pub mod parser;
pub mod transaction;
pub mod transport;
pub mod ua;

pub(crate) mod error;

pub mod macros;

pub use endpoint::{Endpoint, EndpointHandler};
use error::Error;
pub use error::Result;
pub use message::Method;
use parser::Parser;

#[cfg(test)]
#[macro_use]
extern crate assert_matches;

#[cfg(test)]
pub(crate) mod test_utils;

use std::fmt::{self, Debug, Display};
use std::net::SocketAddr;
use std::str::{
    FromStr, {self},
};

/// Branch parameter prefix defined in RFC3261.
pub(crate) const RFC3261_BRANCH_ID: &str = "z9hG4bK";

use rand::distr::{Alphanumeric, SampleString};

use crate::message::Params;

pub(crate) fn generate_branch() -> String {
    generate_branch_n(8)
}

pub(crate) fn generate_branch_n(n: usize) -> String {
    let mut branch = String::with_capacity(RFC3261_BRANCH_ID.len() + n);
    branch.push_str(RFC3261_BRANCH_ID);
    Alphanumeric.append_string(&mut rand::rng(), &mut branch, n);
    branch
}

pub(crate) fn generate_tag_n(n: usize) -> String {
    generate_random_str(n)
}

pub(crate) fn generate_random_str(n: usize) -> String {
    Alphanumeric.sample_string(&mut rand::rng(), n)
}

#[inline(always)]
pub(crate) fn is_valid_port(v: u16) -> bool {
    matches!(v, 0..=65535)
}

/// Represents a quality value (q-value) used in SIP
/// headers.
///
/// The `Q` struct provides a method to parse a string
/// representation of a q-value into a `Q` instance. The
/// q-value is typically used to indicate the preference
/// of certain SIP headers.
///
/// # Examples
///
/// ```
/// use csip::Q;
///
/// let q_value = "0.5".parse();
/// assert_eq!(q_value, Ok(Q(0, 5)));
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Copy)]
pub struct Q(pub u8, pub u8);

impl Q {
    pub fn new(a: u8, b: u8) -> Self {
        Self(a, b)
    }
}
impl From<u8> for Q {
    fn from(value: u8) -> Self {
        Self(value, 0)
    }
}
#[derive(Debug, PartialEq, Eq)]
pub struct ParseQError;

impl From<ParseQError> for Error {
    fn from(value: ParseQError) -> Self {
        todo!()
        // Self::ParseError(SipParserError {
        //     message: format!("{:?}", value),
        // })
    }
}

impl FromStr for Q {
    type Err = ParseQError;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s.rsplit_once('.') {
            Some((a, b)) => {
                let a = a.parse().map_err(|_| ParseQError)?;
                let b = b.parse().map_err(|_| ParseQError)?;
                Ok(Q(a, b))
            }
            None => match s.parse() {
                Ok(n) => Ok(Q(n, 0)),
                Err(_) => Err(ParseQError),
            },
        }
    }
}

impl fmt::Display for Q {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, ";q={}.{}", self.0, self.1)
    }
}

/// This type reprents an MIME type that indicates an
/// content format.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MimeType {
    pub mtype: String,
    pub subtype: String,
}

/// The `media-type` that appears in `Accept` and
/// `Content-Type` SIP headers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MediaType {
    pub mimetype: MimeType,
    pub param: Option<Params>,
}

impl fmt::Display for MediaType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let MediaType { mimetype, param } = self;
        write!(f, "{}/{}", mimetype.mtype, mimetype.subtype)?;
        if let Some(param) = &param {
            write!(f, ";{}", param)?;
        }
        Ok(())
    }
}

impl MediaType {
    /// Constructs a `MediaType` from a type and a subtype.
    pub fn new(mtype: &str, subtype: &str) -> Self {
        Self {
            mimetype: MimeType {
                mtype: mtype.into(),
                subtype: subtype.into(),
            },
            param: None,
        }
    }

    pub fn parse(parser: &mut Parser) -> Result<Self> {
        let mtype = parser.parse_token()?;
        parser.next_byte();
        let subtype = parser.parse_token()?;
        let param = crate::macros::parse_header_param!(parser);

        Ok(Self::from_parts(mtype, subtype, param))
    }

    pub fn from_static(s: &'static str) -> Result<Self> {
        Self::parse(&mut Parser::new(s.as_bytes()))
    }

    /// Constructs a `MediaType` with an optional
    /// parameters.
    pub fn from_parts(mtype: &str, subtype: &str, param: Option<Params>) -> Self {
        Self {
            mimetype: MimeType {
                mtype: mtype.into(),
                subtype: subtype.into(),
            },
            param,
        }
    }
}

pub(crate) fn get_local_name(addr: &SocketAddr) -> String {
    let ip = local_ip_address::local_ip().unwrap_or(addr.ip());
    let local_name = format!("{}:{}", ip, addr.port());

    local_name
}
