use std::fmt;
use std::str::FromStr;

use crate::parser::Parser;
use crate::{Error, Result};

pub(crate) type ParameterRef<'a> = (&'a str, Option<&'a str>);

/// A collection of SIP parameters.
///
/// A parameter takes the form `name=value` and can appear in a SIP message as
/// either a URI parameter or a header parameter.
#[derive(Debug, PartialEq, Eq, Default, Clone)]
pub struct Params {
    inner: Vec<Param>,
}

impl Params {
    /// Creates an empty `Params`.
    pub fn new() -> Self {
        Self { inner: Vec::new() }
    }

    /// Returns the number of elements in the parameters.
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// Gets the value of a parameter by name.
    ///
    /// Returns the value associated with the given `name`, if it exists.
    pub fn get_named(&self, name: &str) -> Option<&str> {
        self.inner
            .iter()
            .find(|Param { name: p_name, .. }| p_name == name)
            .map(|Param { value, .. }| value.as_deref())?
    }

    /// Returns an iterator over the parameters.
    pub fn iter(&self) -> impl Iterator<Item = &Param> {
        self.inner.iter()
    }

    /// Pushes a new parameter into collection.
    pub fn push(&mut self, param: Param) {
        self.inner.push(param)
    }

    /// Checks if the parameter list is empty.
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }
}

impl fmt::Display for Params {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for Param { name, value } in &self.inner {
            write!(f, ";{}", name)?;
            if let Some(v) = value {
                write!(f, "={}", v)?;
            }
        }
        Ok(())
    }
}

impl<'a, const N: usize> From<[(&'a str, &'a str); N]> for Params {
    fn from(params: [(&'a str, &'a str); N]) -> Self {
        let params = params
            .map(|(name, value)| Param::new(name, Some(value)))
            .to_vec();

        Self { inner: params }
    }
}

/// A parameter.
///
/// This struct represents a parameter in a SIP message, consisting of a name
/// and an optional value.
///
/// # Examples
///
/// ```
/// use voip::message::Param;
///
/// let param: Param = "param=value".parse().unwrap();
///
/// assert_eq!(param.name(), "param");
/// assert_eq!(param.value(), Some("value"));
/// ```
#[derive(Debug, PartialEq, Eq, Default, Clone)]
pub struct Param {
    /// The parameter name.
    pub(crate) name: String,
    /// The parameter optional value
    pub(crate) value: Option<String>,
}

impl Param {
    /// Creates a new `Param` with the given `name` and optional `value`.
    pub fn new(name: &str, value: Option<&str>) -> Self {
        Self {
            name: name.into(),
            value: value.map(|v| v.into()),
        }
    }

    /// Returns the param `name`.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the param `value` if any.
    pub fn value(&self) -> Option<&str> {
        self.value.as_deref()
    }
}

impl From<ParameterRef<'_>> for Param {
    #[inline]
    fn from((name, value): ParameterRef) -> Self {
        Self {
            name: name.into(),
            value: value.map(|v| v.into()),
        }
    }
}

impl FromStr for Param {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        Ok(Parser::new(s).parse_ref_param()?.into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parameter_from_str() {
        let param: Param = "param=value".parse().unwrap();
        assert_eq!(param.name(), "param");
        assert_eq!(param.value(), Some("value"));
    }

    #[test]
    fn test_parameters_display() {
        let params = Params::from([("param1", "value1"), ("param2", "value2")]);
        assert_eq!(params.to_string(), ";param1=value1;param2=value2");
    }

    #[test]
    fn test_parameters_get_named() {
        let params = Params::from([("param1", "value1"), ("param2", "value2")]);
        assert_eq!(params.get_named("param1"), Some("value1"));
        assert_eq!(params.get_named("param3"), None);
    }
}
