use std::{fmt, str};

use itertools::Itertools;

use crate::error::Result;
use crate::macros::parse_comma_separated_header_value;
use crate::parser::{HeaderParser, SipParser};

/// The `Supported` SIP header.
///
/// Enumerates all the extensions supported by the `UAC` or
/// `UAS`.
#[derive(Debug, PartialEq, Eq, Clone, Default)]
pub struct Supported(Vec<String>);

impl Supported {
    /// Add a new tag to the list of supported tags.
    pub fn add_tag(&mut self, tag: String) {
        self.0.push(tag);
    }
}

impl HeaderParser for Supported {
    const NAME: &'static str = "Supported";
    const SHORT_NAME: &'static str = "k";

    fn parse(parser: &mut SipParser) -> Result<Self> {
        let tags = parse_comma_separated_header_value!(parser => parser.parse_token()?.to_owned());

        Ok(Self(tags))
    }
}

impl fmt::Display for Supported {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", Self::NAME, self.0.iter().format(", "))
    }
}
