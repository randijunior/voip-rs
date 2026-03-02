use std::fmt;

use itertools::Itertools;

use crate::MediaType;
use crate::error::Result;
use crate::macros::{parse_comma_separated_header_value, parse_header_param};
use crate::parser::{HeaderParser, SipParser};
#[derive(Default, Debug, Clone, PartialEq, Eq)]
pub struct Accept(Vec<MediaType>);

impl Accept {
    #[inline]
    pub fn push(&mut self, mtype: MediaType) {
        self.0.push(mtype);
    }
}

impl HeaderParser for Accept {
    const NAME: &'static str = "Accept";

    fn parse(parser: &mut SipParser) -> Result<Accept> {
        let mtypes = parse_comma_separated_header_value!(parser => {
            let mtype = parser.parse_token()?;
            parser.read()?;
            let subtype = parser.parse_token()?;
            let param = parse_header_param!(parser);

            MediaType::from_parts(mtype, subtype, param)
        });

        Ok(Self(mtypes))
    }
}

impl fmt::Display for Accept {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", Self::NAME, self.0.iter().format(", "))
    }
}
