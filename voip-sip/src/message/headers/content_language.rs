use std::{fmt, str};

use itertools::Itertools;

use crate::error::Result;
use crate::macros::parse_comma_separated_header_value;
use crate::message::headers::LanguageTag;
use crate::parser::{HeaderParser, SipParser};

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct ContentLanguage(Vec<LanguageTag>);

impl HeaderParser for ContentLanguage {
    const NAME: &'static str = "Content-Language";

    fn parse(parser: &mut SipParser) -> Result<Self> {
        let languages = parse_comma_separated_header_value!(parser => LanguageTag::parse(parser));

        Ok(ContentLanguage(languages))
    }
}

impl fmt::Display for ContentLanguage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", Self::NAME, self.0.iter().format(", "))
    }
}
