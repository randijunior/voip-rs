use std::{fmt, str};

use itertools::Itertools;

use crate::Q;
use crate::error::Result;
use crate::macros::{parse_comma_separated_header_value, parse_header_param};
use crate::message::Params;
use crate::message::headers::Q_PARAM;
use crate::parser::{HeaderParser, SipParser};

#[derive(Default, Debug, Clone, PartialEq, Eq)]
pub struct AcceptEncoding(Vec<Coding>);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Coding {
    coding: String,
    q: Option<Q>,
    param: Option<Params>,
}


impl HeaderParser for AcceptEncoding {
    const NAME: &'static str = "Accept-Encoding";

    fn parse(parser: &mut SipParser) -> Result<Self> {
        let codings = parse_comma_separated_header_value!(parser => {
            let coding = parser.parse_token()?;
            let mut q_param = None;
            let param = parse_header_param!(parser, Q_PARAM = q_param);
            let q = q_param.map(|q: &str| q.parse()).transpose()?;

            Coding { coding: coding.into(), q, param }
        });

        Ok(Self(codings))
    }
}

impl fmt::Display for AcceptEncoding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", Self::NAME, self.0.iter().format(", "))
    }
}


impl fmt::Display for Coding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Coding { coding, q, param } = self;

        write!(f, "{}", coding)?;
        if let Some(q) = q {
            write!(f, ";q={}.{}", q.0, q.1)?;
        }
        if let Some(param) = param {
            write!(f, ";{}", param)?;
        }
        Ok(())
    }
}
