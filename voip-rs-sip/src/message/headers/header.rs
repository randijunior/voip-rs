use std::fmt;

use enum_as_inner::EnumAsInner;

use crate::message::headers::*;

/// A SIP Header.
///
/// This enum contain the SIP headers, as defined in
/// `RFC3261`, see their respective documentation for more
/// details.
#[derive(Debug, PartialEq, EnumAsInner, Clone)]
pub enum Header {
    /// `Accept` Header
    Accept(Accept),
    /// `Accept-Enconding` Header
    AcceptEncoding(AcceptEncoding),
    /// `Accept-Language` Header
    AcceptLanguage(AcceptLanguage),
    /// `Alert-Info` Header.
    AlertInfo(AlertInfo),
    /// `Allow` Header
    Allow(Allow),
    /// `Authentication-Info` Header
    AuthenticationInfo(AuthenticationInfo),
    /// `Authorization` Header
    Authorization(Authorization),
    /// `Call-ID` Header
    CallId(CallId),
    /// `Call-Info` Header
    CallInfo(CallInfo),
    /// `Contact` Header
    Contact(Contact),
    /// `Content-Disposition` Header
    ContentDisposition(ContentDisposition),
    /// `Content-Encoding` Header
    ContentEncoding(ContentEncoding),
    /// `Content-Language` Header
    ContentLanguage(ContentLanguage),
    /// `Content-Length` Header
    ContentLength(ContentLength),
    /// `Content-Type` Header
    ContentType(ContentType),
    /// `CSeq` Header
    CSeq(CSeq),
    /// `Date` Header
    Date(Date),
    /// `Error-Info` Header
    ErrorInfo(ErrorInfo),
    /// `Expires` Header
    Expires(Expires),
    /// `From` Header
    From(From),
    /// `In-Reply-To` Header
    InReplyTo(InReplyTo),
    /// `Max-Fowards` Header
    MaxForwards(MaxForwards),
    /// `Min-Expires` Header
    MinExpires(MinExpires),
    /// `MIME-Version` Header
    MimeVersion(MimeVersion),
    /// `Organization` Header
    Organization(Organization),
    /// `Priority` Header
    Priority(Priority),
    /// `Proxy-Authenticate` Header
    ProxyAuthenticate(ProxyAuthenticate),
    /// `Proxy-Authorization` Header
    ProxyAuthorization(ProxyAuthorization),
    /// `Proxy-Require` Header
    ProxyRequire(ProxyRequire),
    /// `Retry-After` Header
    RetryAfter(RetryAfter),
    /// `Route` Header
    Route(Route),
    /// `Record-Route` Header
    RecordRoute(RecordRoute),
    /// `Reply-To` Header
    ReplyTo(ReplyTo),
    /// `Require` Header
    Require(Require),
    /// `Server` Header
    Server(Server),
    /// `Subject` Header
    Subject(Subject),
    /// `Supported` Header
    Supported(Supported),
    /// `Timestamp` Header
    Timestamp(Timestamp),
    /// `To` Header
    To(To),
    /// `Unsupported` Header
    Unsupported(Unsupported),
    /// `User-Agent` Header
    UserAgent(UserAgent),
    /// `Via` Header
    Via(Via),
    /// `Warning` Header
    Warning(Warning),
    /// `WWW-Authenticate` Header
    WWWAuthenticate(WWWAuthenticate),
    /// Other Generic Header
    RawHeader(RawHeader),
}

/// Raw SIP header.
#[derive(Clone, Debug, PartialEq)]
pub struct RawHeader {
    /// Header name.
    pub name: String,
    /// Header value.
    pub data: String,
}

impl RawHeader {
    /// Constructs a raw Header header using the specified name and value.
    pub fn new<N, V>(name: N, data: V) -> Self
    where
        N: Into<String>,
        V: Into<String>,
    {
        Self {
            name: name.into(),
            data: data.into(),
        }
    }
}

impl fmt::Display for RawHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.name, self.data)
    }
}

macro_rules! impl_header_display {
    ( $($variant:ident),* $(,)? ) => {
        impl fmt::Display for Header {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                match self {
                    $( Header::$variant(inner) => inner.fmt(f), )*
                }
            }
        }
    };
}

impl_header_display!(
    Accept,
    AcceptEncoding,
    AcceptLanguage,
    AlertInfo,
    Allow,
    AuthenticationInfo,
    Authorization,
    CallId,
    CallInfo,
    Contact,
    ContentDisposition,
    ContentEncoding,
    ContentLanguage,
    ContentLength,
    ContentType,
    CSeq,
    Date,
    ErrorInfo,
    Expires,
    From,
    InReplyTo,
    MaxForwards,
    MinExpires,
    MimeVersion,
    Organization,
    Priority,
    ProxyAuthenticate,
    ProxyAuthorization,
    ProxyRequire,
    RetryAfter,
    Route,
    RecordRoute,
    ReplyTo,
    Require,
    Server,
    Subject,
    Supported,
    Timestamp,
    To,
    Unsupported,
    UserAgent,
    Via,
    Warning,
    WWWAuthenticate,
    RawHeader
);
