use std::fmt;

use itertools::Itertools;

use crate::error::Result;
use crate::macros::comma_separated_header_value;
use crate::message::Method;
use crate::parser::{HeaderParser, Parser};

/// The `Allow` SIP header.
///
/// Indicates what methods is supported by the `UserAgent`.
///
/// # Examples
///
/// ```
/// # use voip::header::Allow;
/// # use voip::message::Method;
/// let mut allow = Allow::new();
///
/// allow.push(Method::Invite);
/// allow.push(Method::Register);
///
/// assert_eq!("Allow: INVITE, REGISTER", allow.to_string());
/// ```
#[derive(Debug, PartialEq, Eq, Default, Clone)]
pub struct Allow(Vec<Method>);

impl Allow {
    /// Creates a empty `Allow` header.
    pub fn new() -> Self {
        Self(Vec::new())
    }

    /// Appends an new `Method`.
    pub fn push(&mut self, method: Method) {
        self.0.push(method);
    }

    /// Gets the `Method` at the specified index.
    pub fn get(&self, index: usize) -> Option<&Method> {
        self.0.get(index)
    }

    /// Returns the number of `SipMethods` in the header.
    pub fn len(&self) -> usize {
        self.0.len()
    }
}

impl HeaderParser for Allow {
    const NAME: &'static str = "Allow";

    fn parse(parser: &mut Parser) -> Result<Self> {
        let allow = comma_separated_header_value!(parser => {
            let b_method = parser.alphabetic();

            Method::from(b_method)
        });

        Ok(Allow(allow))
    }
}

impl fmt::Display for Allow {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", Allow::NAME, self.0.iter().format(", "))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse() {
        let src = b"INVITE, ACK, OPTIONS, CANCEL, BYE\r\n";
        let mut scanner = Parser::new(src);
        let allow = Allow::parse(&mut scanner).unwrap();

        assert_eq!(scanner.remaining(), b"\r\n");

        assert_eq!(allow.get(0), Some(&Method::Invite));
        assert_eq!(allow.get(1), Some(&Method::Ack));
        assert_eq!(allow.get(2), Some(&Method::Options));
        assert_eq!(allow.get(3), Some(&Method::Cancel));
        assert_eq!(allow.get(4), Some(&Method::Bye));
        assert_eq!(allow.get(5), None);
    }
}
