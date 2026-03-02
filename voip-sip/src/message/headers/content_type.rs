use core::fmt;
use std::str;

use crate::MediaType;
use crate::error::Result;
use crate::parser::{HeaderParser, SipParser};

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct ContentType(MediaType);

impl ContentType {
    pub fn new_sdp() -> Self {
        Self(MediaType {
            mimetype: crate::MimeType {
                mtype: "application".into(),
                subtype: "sdp".into(),
            },
            param: None,
        })
    }
}

impl HeaderParser for ContentType {
    const NAME: &'static str = "Content-Type";
    const SHORT_NAME: &'static str = "c";

    fn parse(parser: &mut SipParser) -> Result<Self> {
        let media_type = MediaType::parse(parser)?;

        Ok(Self(media_type))
    }
}

impl fmt::Display for ContentType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", Self::NAME, self.0)
    }
}
