use std::{fmt, str};

use itertools::Itertools;

use crate::error::Result;
use crate::macros::parse_comma_separated_header_value;
use crate::message::headers::CallId;
use crate::parser::{HeaderParser, SipParser};

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct InReplyTo(Vec<CallId>);

impl HeaderParser for InReplyTo {
    const NAME: &'static str = "In-Reply-To";

    fn parse(parser: &mut SipParser) -> Result<Self> {
        let ids = parse_comma_separated_header_value!(parser => {
            let id = parser.not_comma_or_newline();
            let id = str::from_utf8(id)?;

            CallId::from(id)
        });

        Ok(Self(ids))
    }
}

impl fmt::Display for InReplyTo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", Self::NAME, self.0.iter().format(", "))
    }
}
