#![deny(missing_docs)]
//! SIP Headers types
//!
//! The module provide the [`Headers`] struct that contains
//! an list of [`Header`] and a can be used to manipulating
//! SIP headers.

mod accept;
mod accept_encoding;
mod accept_language;
mod alert_info;
mod allow;
mod authentication_info;
mod authorization;
mod call_id;
mod call_info;
mod contact;
mod content_disposition;
mod content_encoding;
mod content_language;
mod content_length;
mod content_type;
mod cseq;
mod date;
mod error_info;
mod expires;
mod from;
mod header;
mod in_reply_to;
mod max_fowards;
mod mime_version;
mod min_expires;
mod organization;
mod priority;
mod proxy_authenticate;
mod proxy_authorization;
mod proxy_require;
mod record_route;
mod reply_to;
mod require;
mod retry_after;
mod route;
mod server;
mod subject;
mod supported;
mod timestamp;
mod to;
mod unsupported;
mod user_agent;
mod via;
mod warning;
mod www_authenticate;

use core::fmt;
use std::ops::{Index, IndexMut, Range, RangeBounds, RangeFrom};
use std::str::{self};
use std::vec::Splice;

pub use accept::Accept;
pub use accept_encoding::*;
pub use accept_language::*;
pub use alert_info::AlertInfo;
pub use allow::Allow;
pub use authentication_info::AuthenticationInfo;
pub use authorization::Authorization;
pub use call_id::CallId;
pub use call_info::CallInfo;
pub use contact::Contact;
pub use content_disposition::ContentDisposition;
pub use content_encoding::ContentEncoding;
pub use content_language::ContentLanguage;
pub use content_length::ContentLength;
pub use content_type::ContentType;
pub use cseq::CSeq;
pub use date::Date;
pub use error_info::ErrorInfo;
pub use expires::Expires;
pub use from::From;
pub use header::*;
pub use in_reply_to::InReplyTo;
pub use max_fowards::MaxForwards;
pub use mime_version::MimeVersion;
pub use min_expires::MinExpires;
pub use organization::Organization;
pub use priority::Priority;
pub use proxy_authenticate::ProxyAuthenticate;
pub use proxy_authorization::ProxyAuthorization;
pub use proxy_require::ProxyRequire;
pub use record_route::RecordRoute;
pub use reply_to::ReplyTo;
pub use require::Require;
pub use retry_after::RetryAfter;
pub use route::Route;
pub use server::Server;
pub use subject::Subject;
pub use supported::Supported;
pub use timestamp::Timestamp;
pub use to::To;
pub use unsupported::Unsupported;
pub use user_agent::UserAgent;
pub use via::Via;
pub use warning::Warning;
pub use www_authenticate::WWWAuthenticate;

/// The tag parameter that is used normaly in [`From`] and
/// [`To`] headers.
const TAG_PARAM: &str = "tag";

/// The q parameter that is used normaly in [`Contact`],
/// [`AcceptEncoding`] and [`AcceptLanguage`] headers.
const Q_PARAM: &str = "q";

/// The expires parameter that is used normaly in
/// [`Contact`] headers.
const EXPIRES_PARAM: &str = "expires";

/// A coolection of SIP Headers.
///
/// A wrapper over Vec<[`Header`]> that contains the header
/// list.
///
/// # Examples
///
/// ```
/// # use voip_rs::header::Headers;
/// # use voip_rs::header::Header;
/// # use voip_rs::header::ContentLength;
/// let mut headers = Headers::new();
/// headers.push(Header::ContentLength(ContentLength::new(10)));
///
/// assert_eq!(headers.len(), 1);
/// ```
#[derive(Debug, PartialEq, Clone)]
pub struct Headers(Vec<Header>);

impl Headers {
    /// Create a new empty collection of headers.
    ///
    /// # Examples
    ///
    /// ```
    /// # use voip_rs::header::Headers;
    /// let mut headers = Headers::new();
    /// ```
    #[inline]
    pub const fn new() -> Self {
        Self(Vec::new())
    }

    /// last
    pub fn last(&self) -> Option<&Header> {
        self.0.last()
    }

    /// last mut
    pub fn last_mut(&mut self) -> Option<&mut Header> {
        self.0.last_mut()
    }

    /// first mut
    pub fn first_mut(&mut self) -> Option<&mut Header> {
        self.0.first_mut()
    }

    /// Removes and returns the element at position `index`.
    pub fn remove(&mut self, index: usize) -> Header {
        self.0.remove(index)
    }

    /// Inserts an header at position index.
    pub fn insert(&mut self, index: usize, header: Header) {
        self.0.insert(index, header);
    }

    /// Constructs a new, empty  collection of `Headers`
    /// with at least the specified capacity.
    #[inline]
    pub fn with_capacity(capacity: usize) -> Self {
        Self(Vec::with_capacity(capacity))
    }

    /// Extends the headers collection with the contents of
    /// an another.
    ///
    /// # Examples
    ///
    /// ```
    /// # use voip_rs::header::Headers;
    /// # use voip_rs::header::Header;
    /// # use voip_rs::header::{Expires, ContentLength};
    /// let mut headers = Headers::new();
    /// headers.push(Header::Expires(Expires::new(10)));
    ///
    /// let additional_headers = [Header::ContentLength(ContentLength::new(0))];
    /// headers.extend(additional_headers);
    ///
    /// assert_eq!(headers.len(), 2);
    /// ```
    #[inline]
    pub fn extend<I>(&mut self, iter: I)
    where
        I: IntoIterator<Item = Header>,
    {
        self.0.extend(iter);
    }

    /// Splices in an header at the given range.
    pub fn splice<R, I>(&mut self, range: R, replace_with: I) -> Splice<'_, I::IntoIter>
    where
        R: RangeBounds<usize>,
        I: IntoIterator<Item = Header>,
    {
        self.0.splice(range, replace_with)
    }

    /// Returns an iterator over headers.
    #[inline]
    pub fn iter(&self) -> core::slice::Iter<'_, Header> {
        self.0.iter()
    }

    /// Returns an iterator over headers.
    #[inline]
    pub fn iter_mut(&mut self) -> core::slice::IterMut<'_, Header> {
        self.0.iter_mut()
    }

    /// Moves all the elements of `other` into `self`,
    /// leaving `other` empty.
    ///
    /// # Panics
    ///
    /// Panics if the new capacity exceeds `isize::MAX`
    /// bytes.
    #[inline]
    pub fn append(&mut self, other: &mut Self) {
        self.0.append(&mut other.0);
    }

    /// Push an new header.
    ///
    /// # Examples
    ///
    /// ```
    /// # use voip_rs::header::Headers;
    /// # use voip_rs::header::Header;
    /// # use voip_rs::header::Expires;
    /// let mut headers = Headers::new();
    /// headers.push(Header::Expires(Expires::new(10)));
    ///
    /// assert_eq!(headers.len(), 1);
    /// assert!(headers.get(0).is_some());
    #[inline]
    pub fn push(&mut self, hdr: Header) {
        self.0.push(hdr);
    }

    /// Insert a header on the front
    pub fn prepend_header(&mut self, hdr: Header) {
        self.0.insert(0, hdr);
    }

    /// Returns the number of headers in the collection.
    #[inline]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Get an reference to an header at the index
    /// specified.
    pub fn get(&self, index: usize) -> Option<&Header> {
        self.0.get(index)
    }

    /// Removes the last element and returns it, or None if
    /// it is empty. # Examples
    ///
    /// ```
    /// # use voip_rs::header::Headers;
    /// # use voip_rs::header::Header;
    /// # use voip_rs::header::Expires;
    /// let expires = Expires::new(10);
    /// let mut headers = Headers::from([Header::Expires(expires)]);
    ///
    /// assert_eq!(headers.pop(), Some(Header::Expires(expires)));
    /// assert_eq!(headers.pop(), None);
    #[inline]
    pub fn pop(&mut self) -> Option<Header> {
        self.0.pop()
    }

    /// Returns `true` if the header collection contains no
    /// elements.
    ///
    /// # Examples
    ///
    /// ```
    /// # use voip_rs::header::Headers;
    /// # use voip_rs::header::Header;
    /// # use voip_rs::header::Expires;
    /// let mut h = Headers::new();
    /// assert!(h.is_empty());
    /// h.push(Header::Expires(Expires::new(10)));
    /// assert!(!h.is_empty());
    /// ```
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    #[inline]
    /// Returns the total number of elements the header list
    /// can hold without reallocating.
    pub fn capacity(&self) -> usize {
        self.0.capacity()
    }
}

impl IntoIterator for Headers {
    type Item = Header;

    type IntoIter = std::vec::IntoIter<Self::Item>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl<'a> Index<usize> for Headers {
    type Output = Header;

    fn index(&self, index: usize) -> &Self::Output {
        &self.0[index]
    }
}

impl IndexMut<usize> for Headers {
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        &mut self.0[index]
    }
}

impl<'a, Header, const N: usize> std::convert::From<[Header; N]> for Headers
where
    Headers: FromIterator<Header>,
{
    fn from(array: [Header; N]) -> Self {
        array.into_iter().collect()
    }
}

impl<'a> FromIterator<Header> for Headers {
    fn from_iter<I: IntoIterator<Item = Header>>(iter: I) -> Self {
        let headers: Vec<Header> = iter.into_iter().collect();
        Headers(headers)
    }
}

impl<'a> Index<Range<usize>> for Headers {
    type Output = [Header];

    fn index(&self, range: Range<usize>) -> &Self::Output {
        &self.0[range]
    }
}

impl<'a> Index<RangeFrom<usize>> for Headers {
    type Output = [Header];

    fn index(&self, range: RangeFrom<usize>) -> &Self::Output {
        &self.0[range]
    }
}

impl fmt::Display for Headers {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for hdr in self.iter() {
            write!(f, "{hdr}\r\n")?;
        }
        Ok(())
    }
}

impl Default for Headers {
    fn default() -> Self {
        Self::new()
    }
}

impl<'a> std::convert::From<Vec<Header>> for Headers {
    fn from(headers: Vec<Header>) -> Self {
        Self(headers)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_retrieves_header_by_index_correctly() {
        let mut headers = Headers::new();

        let clen = ContentLength::new(10);
        let cid = CallId::new("bs9ki9iqbee8k5kal8mpqb".into());

        headers.push(Header::CallId(cid.clone()));
        headers.push(Header::ContentLength(clen));

        assert_eq!(headers.get(0), Some(&Header::CallId(cid.into())));
        assert_eq!(headers.get(1), Some(&Header::ContentLength(clen)));

        assert!(headers.get(2).is_none());
    }

    #[test]
    fn test_finds_header_matching_predicate() {
        let clen = ContentLength::new(10);
        let headers = Headers::from([Header::ContentLength(clen)]);
        let header = headers
            .iter()
            .find(|h| matches!(h, Header::ContentLength(_)));

        assert_eq!(header.unwrap().to_string(), "Content-Length: 10");
    }

    #[test]
    fn test_creates_empty_headers_collection_with_new() {
        let headers = Headers::new();
        assert_eq!(headers.len(), 0);
        assert!(headers.is_empty());
    }

    #[test]
    fn test_pushes_and_pops_header_correctly() {
        let expires = Expires::new(3600);
        let mut headers = Headers::new();

        headers.push(Header::Expires(expires));
        assert_eq!(headers.len(), 1);

        let popped = headers.pop();
        assert_eq!(popped, Some(Header::Expires(expires)));
        assert!(headers.is_empty());
    }

    #[test]
    fn test_appends_headers_from_another_collection() {
        let mut headers1 = Headers::new();
        let mut headers2 = Headers::new();

        headers1.push(Header::Expires(Expires::new(10)));
        headers2.push(Header::ContentLength(ContentLength::new(20)));

        headers1.append(&mut headers2);

        assert_eq!(headers1.len(), 2);
        assert!(headers2.is_empty());
    }

    #[test]
    fn test_checks_if_headers_is_empty_correctly() {
        let mut headers = Headers::new();
        assert!(headers.is_empty());

        headers.push(Header::Expires(Expires::new(10)));
        assert!(!headers.is_empty());
    }

    #[test]
    fn test_creates_headers_with_capacity_and_pushes_elements() {
        let mut headers = Headers::with_capacity(5);
        assert_eq!(headers.len(), 0);
        assert!(headers.capacity() >= 5);

        headers.push(Header::Expires(Expires::new(42)));
        assert_eq!(headers.len(), 1);
        assert!(headers.capacity() >= 5);
    }
}
