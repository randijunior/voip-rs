use std::fmt;

use itertools::Itertools;

use crate::error::Result;
use crate::macros::parse_comma_separated_header_value;
use crate::message::Method;
use crate::parser::{HeaderParser, SipParser};

#[derive(Debug, PartialEq, Eq, Default, Clone)]
pub struct Allow(Vec<Method>);

impl Allow {
    pub fn push(&mut self, method: Method) {
        self.0.push(method);
    }
}

impl HeaderParser for Allow {
    const NAME: &'static str = "Allow";

    fn parse(parser: &mut SipParser) -> Result<Self> {
        let allow = parse_comma_separated_header_value!(parser => {
            let method = parser.read_alphabetic();

            Method::from(method)
        });

        Ok(Self(allow))
    }
}

impl fmt::Display for Allow {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", Self::NAME, self.0.iter().format(", "))
    }
}
