use std::{fmt, str};

use itertools::Itertools;

use crate::error::Result;
use crate::macros::parse_comma_separated_header_value;
use crate::parser::{HeaderParser, SipParser};

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Require(Vec<String>);

impl HeaderParser for Require {
    const NAME: &'static str = "Require";

    fn parse(parser: &mut SipParser) -> Result<Self> {
        let tags = parse_comma_separated_header_value!(parser => parser.parse_token()?.to_owned());

        Ok(Self(tags))
    }
}

impl fmt::Display for Require {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", Self::NAME, self.0.iter().format(", "))
    }
}
