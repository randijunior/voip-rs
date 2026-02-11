use std::{fmt, str};

use itertools::Itertools;

use crate::error::Result;
use crate::macros::comma_separated_header_value;
use crate::message::headers::accept_language::is_lang;
use crate::parser::{HeaderParser, Parser};

/// The `Content-Language` SIP header.
///
/// Specifies the language of the `message-body` content.
///
/// # Examples
///
/// ```
/// # use voip::header::ContentLanguage;
/// let c_language = ContentLanguage::from(["fr", "en"]);
///
/// assert_eq!("Content-Language: fr, en", c_language.to_string());
/// ```
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct ContentLanguage(Vec<String>);

impl HeaderParser for ContentLanguage {
    const NAME: &'static str = "Content-Language";

    fn parse(parser: &mut Parser) -> Result<Self> {
        let languages = comma_separated_header_value!(parser => unsafe {
            parser.read_while_as_str_unchecked(is_lang).into()
        });

        Ok(ContentLanguage(languages))
    }
}

impl fmt::Display for ContentLanguage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}: {}",
            ContentLanguage::NAME,
            self.0.iter().format(", ")
        )
    }
}

impl<'a, const N: usize> From<[&'a str; N]> for ContentLanguage {
    fn from(value: [&'a str; N]) -> Self {
        Self(value.into_iter().map(String::from).collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse() {
        let src = b"fr\r\n";
        let mut scanner = Parser::new(src);
        let lang = ContentLanguage::parse(&mut scanner);
        let lang = lang.unwrap();

        assert_eq!(scanner.remaining(), b"\r\n");
        assert_eq!(lang.0.get(0), Some(&"fr".into()));

        let src = b"fr, en\r\n";
        let mut scanner = Parser::new(src);
        let lang = ContentLanguage::parse(&mut scanner);
        let lang = lang.unwrap();

        assert_eq!(scanner.remaining(), b"\r\n");

        assert_eq!(lang.0.get(0), Some(&"fr".into()));
        assert_eq!(lang.0.get(1), Some(&"en".into()));
    }
}
