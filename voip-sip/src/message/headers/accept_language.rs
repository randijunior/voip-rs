use std::{fmt, str};

use itertools::Itertools;
use utils::is_alphabetic;

use crate::Q;
use crate::error::Result;
use crate::macros::{parse_comma_separated_header_value, parse_header_param};
use crate::message::param::{Params, Q_PARAM};
use crate::parser::{HeaderParser, SipParser};

#[derive(Default, Debug, Clone, PartialEq, Eq)]
pub struct AcceptLanguage(Vec<Language>);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Language {
    language: LanguageTag,
    q: Option<Q>,
    param: Option<Params>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LanguageTag(String);

impl LanguageTag {
    pub fn parse(parser: &mut SipParser) -> Self {
        let is_lang = |byte: u8| is_alphabetic(byte) || matches!(byte, b'*' | b'-');
        let s = unsafe { parser.read_while_as_str_unchecked(is_lang) };

        Self(s.to_owned())
    }
}

impl fmt::Display for LanguageTag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)?;

        Ok(())
    }
}

impl HeaderParser for AcceptLanguage {
    const NAME: &'static str = "Accept-Language";

    fn parse(parser: &mut SipParser) -> Result<Self> {
        let languages = parse_comma_separated_header_value!(parser => {
            let language = LanguageTag::parse(parser);
            let mut q_param = None;
            let param = parse_header_param!(parser, Q_PARAM = q_param);
            let q = q_param.map(|q: &str| q.parse()).transpose()?;

            Language { language: language.into(), q, param }
        });

        Ok(Self(languages))
    }
}

impl fmt::Display for AcceptLanguage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", Self::NAME, self.0.iter().format(", "))
    }
}

impl Language {
    pub fn new(language: LanguageTag) -> Self {
        Self {
            language,
            q: None,
            param: None,
        }
    }

    pub fn from_parts(language: LanguageTag, q: Option<Q>, param: Option<Params>) -> Self {
        Self { language, q, param }
    }
}

impl fmt::Display for Language {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Language { language, q, param } = self;
        write!(f, "{}", language)?;
        if let Some(q) = q {
            write!(f, "{}", q)?;
        }
        if let Some(param) = param {
            write!(f, ";{}", param)?;
        }
        Ok(())
    }
}
