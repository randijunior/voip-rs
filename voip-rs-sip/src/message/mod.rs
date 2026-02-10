//! SIP Message types
//!
//! This module provides the [`SipMessage`] enum, which can be either a
//! [`SipMessage::Request`] or a [`SipMessage::Response`], representing
//! a complete SIP message.
//!
//! Within this crate, the module corresponds to the lowest layer of SIP: syntax
//! and encoding.

use std::borrow::Cow;
use std::fmt::{Display, Formatter, Result as FmtResult};
use std::ops::Deref;
use std::result::Result as StdResult;

use bytes::Bytes;

pub mod headers;

use headers::{CSeq, CallId, From as FromHeader, Header, Headers, To, Via};

use crate::error::{Error, Result};
use crate::parser::HeaderParser;

mod auth;
mod code;
mod method;
mod param;
pub(crate) mod uri;

pub use auth::*;
pub use code::*;
pub use method::*;
pub use param::*;
pub use uri::*;

/// An SIP message, either Request or Response.
///
/// This enum can contain either an [`Request`] or an [`Response`], see their
/// respective documentation for more details.
pub enum SipMessage {
    /// An SIP Request.
    Request(Request),
    /// An SIP Response.
    Response(Response),
}

impl SipMessage {
    /// Returns a reference to the inner [`Request`] if this message is an request.
    pub fn request(&self) -> Option<&Request> {
        if let SipMessage::Request(req) = self {
            Some(req)
        } else {
            None
        }
    }

    /// Returns a reference to the inner [`Response`] if this message is an response.
    pub fn response(&self) -> Option<&Response> {
        if let SipMessage::Response(res) = self {
            Some(res)
        } else {
            None
        }
    }

    /// Returns a reference to the headers of the message.
    pub fn headers(&self) -> &Headers {
        match self {
            SipMessage::Request(req) => &req.headers,
            SipMessage::Response(res) => &res.headers,
        }
    }

    /// Returns a reference to the message body.
    pub fn body(&self) -> Option<&SipBody> {
        match self {
            SipMessage::Request(req) => req.body.as_ref(),
            SipMessage::Response(res) => res.body.as_ref(),
        }
    }

    /// Sets the body of the message. It can be `None` to remove the body.
    pub fn set_body(&mut self, body: Option<impl Into<SipBody>>) {
        let body = body.map(|b| b.into());

        match self {
            SipMessage::Request(req) => req.body = body,
            SipMessage::Response(res) => res.body = body,
        }
    }

    /// Returns a mutable reference to the headers of this [`SipMessage`].
    pub fn headers_mut(&mut self) -> &mut Headers {
        match self {
            SipMessage::Request(req) => &mut req.headers,
            SipMessage::Response(res) => &mut res.headers,
        }
    }

    /// Sets the headers of the message, replacing any existing headers.
    pub fn set_headers(&mut self, headers: Headers) {
        match self {
            SipMessage::Request(req) => req.headers = headers,
            SipMessage::Response(res) => res.headers = headers,
        }
    }

    /// If this message is an request, returns `true` otherwise returns `false`.
    pub fn is_request(&self) -> bool {
        matches!(self, SipMessage::Request(_))
    }

    /// If this message is an response, returns `true` otherwise returns `false`.
    pub fn is_response(&self) -> bool {
        matches!(self, SipMessage::Response(_))
    }
}

impl From<Request> for SipMessage {
    fn from(request: Request) -> Self {
        SipMessage::Request(request)
    }
}

impl From<Response> for SipMessage {
    fn from(response: Response) -> Self {
        SipMessage::Response(response)
    }
}

/// Represents the mandatory headers that every SIP message must contain.
#[derive(Clone)]
pub struct MandatoryHeaders {
    /// The topmost `Via` header.
    pub via: Via,
    /// The `From` header.
    pub from: FromHeader,
    /// The `To` header.
    pub to: To,
    /// The `Call-ID` header.
    pub call_id: CallId,
    /// The `CSeq` header.
    pub cseq: CSeq,
}

impl MandatoryHeaders {
    pub fn from_headers(headers: &Headers) -> Result<Self> {
        Self::try_from(headers)
    }
    pub fn into_headers(self) -> Headers {
        let mut headers = Headers::with_capacity(5);
        headers.push(Header::Via(self.via));
        headers.push(Header::From(self.from));
        headers.push(Header::To(self.to));
        headers.push(Header::CallId(self.call_id));
        headers.push(Header::CSeq(self.cseq));
        headers
    }
    /// Extracts a mandatory header.
    pub fn required<T>(header: Option<T>, name: &'static str) -> Result<T> {
        header.ok_or(Error::MissingHeader(name))
    }
}

impl TryFrom<&Headers> for MandatoryHeaders {
    type Error = Error;

    fn try_from(headers: &Headers) -> StdResult<Self, Self::Error> {
        let mut via: Option<Via> = None;
        let mut cseq: Option<CSeq> = None;
        let mut from: Option<FromHeader> = None;
        let mut call_id: Option<CallId> = None;
        let mut to: Option<To> = None;

        for header in headers.iter() {
            match header {
                Header::Via(v) if via.is_none() => via = Some(v.clone()),
                Header::From(f) => from = Some(f.clone()),
                Header::To(t) => to = Some(t.clone()),
                Header::CallId(c) => call_id = Some(c.clone()),
                Header::CSeq(c) => cseq = Some(*c),
                _ => (),
            }
        }
        let via = Self::required(via, Via::NAME)?;
        let from = Self::required(from, FromHeader::NAME)?;
        let to = Self::required(to, To::NAME)?;
        let call_id = Self::required(call_id, CallId::NAME)?;
        let cseq = Self::required(cseq, CSeq::NAME)?;

        Ok(MandatoryHeaders {
            via,
            from,
            to,
            call_id,
            cseq,
        })
    }
}

/// A parsed SIP Request.
///
/// SIP request represents a request from a client to a server.
#[derive(Clone)]
pub struct Request {
    /// The Request-Line of the SIP message.
    pub req_line: RequestLine,
    /// All headers present in the SIP message.
    pub headers: Headers,
    /// The body of the SIP message, if present.
    pub body: Option<SipBody>,
}

impl Request {
    /// Creates a new SIP `Request`.
    pub fn new(method: Method, uri: Uri) -> Self {
        Request {
            req_line: RequestLine { method, uri },
            headers: Headers::new(),
            body: None,
        }
    }

    pub fn with_headers(method: Method, uri: Uri, headers: Headers) -> Self {
        Request {
            req_line: RequestLine { method, uri },
            headers,
            body: None,
        }
    }

    /// Returns the SIP method of the request.
    pub fn method(&self) -> Method {
        self.req_line.method
    }
}

impl Display for RequestLine {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        write!(f, "{} {} SIP/2.0\r\n", self.method, self.uri)
    }
}

/// Represents a SIP Request-Line.
///
/// The Request-Line contains the method and the Request-URI, which indicate the
/// target of the SIP request.
#[derive(Clone)]
pub struct RequestLine {
    /// The SIP method associated with the request.
    pub method: Method,
    /// The Request-URI indicating the target of the request.
    pub uri: Uri,
}

impl RequestLine {
    /// Creates a new `RequestLine` instance from the given [`Method`] and
    /// [`Uri`].
    pub const fn new(method: Method, uri: Uri) -> Self {
        Self { method, uri }
    }
}

/// A parsed SIP Response.
#[derive(Clone)]
pub struct Response {
    /// The Status-Line of the SIP message.
    status_line: StatusLine,
    /// All headers present in the SIP message.
    headers: Headers,
    /// The body of the SIP message, if present.
    body: Option<SipBody>,
}

impl Response {
    /// Creates a new SIP `Response` from a `Status-Line`, with empty headers
    /// and no body.
    pub const fn new(status_line: StatusLine) -> Self {
        Self {
            status_line,
            headers: Headers::new(),
            body: None,
        }
    }

    /// Returns the `StatusCode`.
    pub fn status(&self) -> StatusCode {
        self.status_line.code
    }

    /// Returns the `ReasonPhrase`.
    pub fn reason(&self) -> &ReasonPhrase {
        &self.status_line.reason
    }

    /// Returns a reference to the response headers.
    pub fn headers(&self) -> &Headers {
        &self.headers
    }

    /// Returns a shared reference to the response headers.
    pub fn headers_mut(&mut self) -> &mut Headers {
        &mut self.headers
    }

    /// Returns the `SipBody`.
    pub fn body(&self) -> Option<&SipBody> {
        self.body.as_ref()
    }

    /// Creates a new `Response` with the given `Status-Line` and headers,
    pub const fn with_headers(status_line: StatusLine, headers: Headers) -> Self {
        Self {
            status_line,
            headers,
            body: None,
        }
    }

    /// Creates a new `Response` with the given `Status-Line`, reason, and body.
    pub fn with_body(status_line: StatusLine, body: &[u8]) -> Self {
        Self {
            status_line,
            headers: Default::default(),
            body: Some(body.into()),
        }
    }

    /// Set the headers of the response, replacing any existing headers.
    pub fn set_headers(&mut self, headers: Headers) {
        self.headers = headers;
    }
}

/// Represents a `reason-phrase` in Status-Line.
#[derive(Clone)]
pub struct ReasonPhrase(Cow<'static, str>);

impl ReasonPhrase {
    /// Creates a new `ReasonPhrase` whith the given `reason`.
    #[inline]
    pub const fn new(reason: Cow<'static, str>) -> Self {
        Self(reason)
    }

    /// Returns the inner phrase as str.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub const fn from_static(s: &'static str) -> Self {
        Self(Cow::Borrowed(s))
    }
}

impl<S> From<S> for ReasonPhrase
where
    S: Into<Cow<'static, str>>,
{
    fn from(value: S) -> Self {
        Self::new(value.into())
    }
}

/// This type represents a body in a SIP message.
#[derive(Clone, Default)]
pub struct SipBody {
    data: Bytes,
}

impl SipBody {
    /// Creates a new `SipBody` whith the given `data`.
    #[inline]
    pub fn new(data: Bytes) -> Self {
        Self { data }
    }
}

impl From<&str> for SipBody {
    fn from(value: &str) -> Self {
        value.as_bytes().into()
    }
}

impl From<&[u8]> for SipBody {
    fn from(data: &[u8]) -> Self {
        Self::new(Bytes::copy_from_slice(data))
    }
}

impl Deref for SipBody {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.data
    }
}

/// Represents a SIP Status-Line.
///
/// The Status-Line appears in SIP responses and includes a status code and a
/// `reason-phrase` explaining the result of the request.
#[derive(Clone)]
pub struct StatusLine {
    /// The SIP status code associated with the response.
    pub code: StatusCode,
    /// The reason phrase explaining the status code.
    pub reason: ReasonPhrase,
}

impl Display for StatusLine {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        write!(f, "SIP/2.0 {} {}\r\n", self.code as i32, self.reason.0)
    }
}

impl StatusLine {
    /// Creates a new `StatusLine` instance from the given
    /// [`StatusCode`] and `reason-phrase`.
    pub const fn new(code: StatusCode, reason: ReasonPhrase) -> Self {
        StatusLine { code, reason }
    }
}
