use core::fmt;
use std::str;

use itertools::Itertools;

use crate::error::Result;
use crate::macros::parse_comma_separated_header_value;
use crate::parser::{HeaderParser, SipParser};

#[derive(Default, Debug, PartialEq, Eq, Clone)]
pub struct ContentEncoding(Vec<String>);

impl HeaderParser for ContentEncoding {
    const NAME: &'static str = "Content-Encoding";
    const SHORT_NAME: &'static str = "e";

    fn parse(parser: &mut SipParser) -> Result<Self> {
        let codings = parse_comma_separated_header_value!(parser => parser.parse_token()?.into());

        Ok(Self(codings))
    }
}

impl fmt::Display for ContentEncoding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", Self::NAME, self.0.iter().format(", "))
    }
}
