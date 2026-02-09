//! SIP Parser
//!
//! The module provides [`Parser`] struct for parsing SIP messages, including
//! requests and responses, as well as various components such as URIs and
//! headers.

use std::str::{self, FromStr};

use utils::{
    Position, Scanner, ScannerError, is_alphabetic, is_digit, is_newline, is_not_newline, is_space,
    not_comma_or_newline,
};

use crate::Result;
use crate::error::{Error, ParseError, ParseErrorKind as Kind};
use crate::macros::{comma_separated, lookup_table, parse_param, try_parse_hdr};
use crate::message::headers::*;
use crate::message::*;
use crate::transport::TransportType;

// ---------------------------------------------------------------------
// Parser constants
// ---------------------------------------------------------------------

/// The user param used in SIP URIs.
const USER_PARAM: &str = "user";

/// The method param used in SIP URIs.
const METHOD_PARAM: &str = "method";

/// The transport param used in SIP URIs.
const TRANSPORT_PARAM: &str = "transport";

/// The ttl param used in SIP URIs.
const TTL_PARAM: &str = "ttl";

/// The lr param used in SIP URIs.
const LR_PARAM: &str = "lr";

/// The maddr param used in SIP URIs.
const MADDR_PARAM: &str = "maddr";

/// Alphanumeric is valid in all sip message components.
const ALPHANUMERIC: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

/// Unreserved characters in user, password, uri and header
/// parameters in SIP uris.
const UNRESERVED: &[u8] = b"-_.!~*'()%";

/// Escaped character in SIP URIs.
const ESCAPED: &[u8] = b"%";

/// Unreserverd charaters in user part of SIP URIs.
const USER_UNRESERVED: &[u8] = b"&=+$,;?/";

/// Token in SIP Messages
const TOKEN: &[u8] = b"-.!%*_`'~+";

/// Password valid characters in SIP URIs.
const PASS: &[u8] = b"&=+$,";

/// Valid characters in SIP URIs host part.
const HOST: &[u8] = b"_-.";

/// The "sip" schema used in SIP URIs.
const SIP: &[u8] = b"sip";

/// The "sips" schema used in SIP URIs.
const SIPS: &[u8] = b"sips";

/// The SIP version used in the parser.
pub(crate) const SIPV2: &str = "SIP/2.0";

const B_SIPV2: &[u8] = SIPV2.as_bytes();

// ---------------------------------------------------------------------
// Lookup Tables
// ---------------------------------------------------------------------

// For reading user in uri.
lookup_table!(USER_TAB => ALPHANUMERIC, UNRESERVED, USER_UNRESERVED, ESCAPED);

// For reading password in uri.
lookup_table!(PASS_TAB => ALPHANUMERIC, UNRESERVED, ESCAPED, PASS);

// For reading host in uri.
lookup_table!(HOST_TAB => ALPHANUMERIC, HOST);

// For reading parameter in uri.
lookup_table!(PARAM_TAB => b"[]/:&+$", ALPHANUMERIC, UNRESERVED, ESCAPED);

// For reading header parameter in uri.
lookup_table!(HDR_TAB => b"[]/?:+$", ALPHANUMERIC, UNRESERVED, ESCAPED);

// For reading token.
lookup_table!(TOKEN_TAB => ALPHANUMERIC, TOKEN);

// For reading via parameter.
lookup_table!(VIA_PARAM_TAB => b"[:]", ALPHANUMERIC, TOKEN);

type ParamRef<'a> = (&'a str, Option<&'a str>);

/// Trait to parse SIP headers.
///
/// This trait defines how a specific SIP header type can be
/// parsed from a byte slice, as typically received in SIP
/// messages.
pub trait HeaderParser: Sized {
    /// The full name of the SIP header (e.g., `"Contact"`).
    const NAME: &'static str;
    /// The abbreviated name of the SIP header, if any
    /// (e.g., `"f"` for `"From"`).
    ///
    /// Defaults to a panic if the header does not have a
    /// short name.
    const SHORT_NAME: &'static str = panic!("This header not have a short name!");

    /// Checks if the given name matches this header's name.
    fn matches_name(name: &[u8]) -> bool {
        name.eq_ignore_ascii_case(Self::NAME.as_bytes())
            || name.eq_ignore_ascii_case(Self::SHORT_NAME.as_bytes())
    }

    /// Parse the SIP header from the buffer return a parsed
    /// structure.
    fn parse(parser: &mut Parser) -> Result<Self>;

    /// Parses this header from a raw byte slice.
    ///
    /// This is a convenience method that creates a
    /// [`Parser`] and delegates to
    /// [`parse`](HeaderParser::parse).
    fn from_bytes(src: &[u8]) -> Result<Self> {
        Self::parse(&mut Parser::new(src))
    }
}

/// A SIP message parser.
///
/// This struct provides methods for parsing various components of SIP messages,
/// such as header fields, URIs, and start lines.
pub struct Parser<'buf> {
    /// The scanner used to read the input buffer.
    scanner: Scanner<'buf>,
}

impl<'buf> Parser<'buf> {
    /// Creates a new `Parser` from the given byte slice.
    ///
    /// This method is useful if you want to parse only specific parts of a SIP
    /// message, such as a URI.
    ///
    /// To parse the buffer direct into a [`SipMessage`], use the [`Parser::parse`]
    /// method.
    ///
    /// # Examples
    /// ```
    /// let line = Parser::new(b"SIP/2.0 200 OK\r\n")
    ///     .parse_status_line()
    ///     .unwrap();
    /// ```
    #[inline]
    pub fn new<B>(buf: &'buf B) -> Self
    where
        B: AsRef<[u8]> + ?Sized,
    {
        Self {
            scanner: Scanner::new(buf.as_ref()),
        }
    }

    /// Parses the `buf` into a [`SipMessage`].
    ///
    /// This is equivalent to `Parser::new(buf).parse()`.
    ///
    /// # Examples
    ///
    /// ```
    /// let buf = b"SIP/2.0 200 OK\r\nContent-Length: 0\r\n\r\n";
    /// let msg = Parser::parse(buf).unwrap();
    /// let res = msg.response().unwrap();
    ///
    /// assert_eq!(res.code().as_u16(), 200);
    /// assert_eq!(res.reason(), "OK");
    /// ```
    #[inline]
    pub fn parse<B>(buf: &'buf B) -> Result<SipMessage>
    where
        B: AsRef<[u8]> + ?Sized,
    {
        Self::new(buf.as_ref()).parse_sip_msg()
    }

    /// Parses the internal buffer into a [`SipMessage`].
    ///
    /// # Examples
    ///
    /// ```
    /// let buf = b"SIP/2.0 200 OK\r\nContent-Length: 0\r\n\r\n";
    /// let msg = Parser::new().parse(buf).unwrap();
    /// let res = result.response().unwrap();
    ///
    /// assert_eq!(res.code().as_u16(), 200);
    /// assert_eq!(res.reason(), "OK");
    /// assert_eq!(res.headers.len(), 1);
    /// ```
    pub fn parse_sip_msg(&mut self) -> Result<SipMessage> {
        // Might be enough for most messages.
        let minimal_header_size = 7;
        let mut sip_message = if matches!(self.scanner.peek_bytes(B_SIPV2.len()), Some(B_SIPV2)) {
            // Is an status line, e.g, "SIP/2.0 200 OK".
            // TODO: Add "match" here.
            let status_line = self.parse_status_line()?;
            let headers = Headers::with_capacity(minimal_header_size);

            SipMessage::Response(Response::with_headers(status_line, headers))
        } else {
            // Is an request line, e.g, "OPTIONS sip:localhost SIP/2.0".
            // TODO: Add "match" here.
            let req_line = self.parse_request_line()?;

            SipMessage::Request(Request {
                req_line,
                headers: Headers::with_capacity(minimal_header_size),
                body: None,
            })
        };

        let mut found_content_type = false;

        // Parse headers loop.
        let headers = sip_message.headers_mut();
        'headers: loop {
            // Get name.
            let header_name = self.parse_token()?;

            self.skip_ws();
            self.must_read(b':')?;
            self.skip_ws();

            match header_name {
                ErrorInfo::NAME => {
                    let header = try_parse_hdr!(ErrorInfo, self);
                    headers.push(Header::ErrorInfo(header));
                }
                Route::NAME => comma_separated!(self => {
                    let header = try_parse_hdr!(Route, self);
                    headers.push(Header::Route(header));
                }),
                Via::NAME | Via::SHORT_NAME => comma_separated!(self => {
                    let header = try_parse_hdr!(Via, self);
                    headers.push(Header::Via(header));
                }),
                MaxForwards::NAME => {
                    let header = try_parse_hdr!(MaxForwards, self);
                    headers.push(Header::MaxForwards(header));
                }
                From::NAME | From::SHORT_NAME => {
                    let header = try_parse_hdr!(From, self);
                    headers.push(Header::From(header));
                }
                To::NAME | To::SHORT_NAME => {
                    let header = try_parse_hdr!(To, self);
                    headers.push(Header::To(header));
                }
                CallId::NAME | CallId::SHORT_NAME => {
                    let header = try_parse_hdr!(CallId, self);
                    headers.push(Header::CallId(header));
                }
                CSeq::NAME => {
                    let header = try_parse_hdr!(CSeq, self);
                    headers.push(Header::CSeq(header));
                }
                Authorization::NAME => {
                    let header = try_parse_hdr!(Authorization, self);
                    headers.push(Header::Authorization(header));
                }
                Contact::NAME | Contact::SHORT_NAME => comma_separated!(self => {
                    let header = try_parse_hdr!(Contact, self);
                    headers.push(Header::Contact(header));
                }),
                Expires::NAME => {
                    let header = try_parse_hdr!(Expires, self);
                    headers.push(Header::Expires(header));
                }
                InReplyTo::NAME => {
                    let header = try_parse_hdr!(InReplyTo, self);
                    headers.push(Header::InReplyTo(header));
                }
                MimeVersion::NAME => {
                    let header = try_parse_hdr!(MimeVersion, self);
                    headers.push(Header::MimeVersion(header));
                }
                MinExpires::NAME => {
                    let header = try_parse_hdr!(MinExpires, self);
                    headers.push(Header::MinExpires(header));
                }
                UserAgent::NAME => {
                    let header = try_parse_hdr!(UserAgent, self);
                    headers.push(Header::UserAgent(header));
                }
                Date::NAME => {
                    let header = try_parse_hdr!(Date, self);
                    headers.push(Header::Date(header));
                }
                Server::NAME => {
                    let header = try_parse_hdr!(Server, self);
                    headers.push(Header::Server(header));
                }
                Subject::NAME | Subject::SHORT_NAME => {
                    let header = try_parse_hdr!(Subject, self);
                    headers.push(Header::Subject(header));
                }
                Priority::NAME => {
                    let header = try_parse_hdr!(Priority, self);
                    headers.push(Header::Priority(header));
                }
                ProxyAuthenticate::NAME => {
                    let header = try_parse_hdr!(ProxyAuthenticate, self);
                    headers.push(Header::ProxyAuthenticate(header));
                }
                ProxyAuthorization::NAME => {
                    let header = try_parse_hdr!(ProxyAuthorization, self);
                    headers.push(Header::ProxyAuthorization(header));
                }
                ProxyRequire::NAME => {
                    let header = try_parse_hdr!(ProxyRequire, self);
                    headers.push(Header::ProxyRequire(header));
                }
                ReplyTo::NAME => {
                    let header = try_parse_hdr!(ReplyTo, self);
                    headers.push(Header::ReplyTo(header));
                }
                ContentLength::NAME | ContentLength::SHORT_NAME => {
                    let header = try_parse_hdr!(ContentLength, self);
                    headers.push(Header::ContentLength(header));
                }
                ContentEncoding::NAME | ContentEncoding::SHORT_NAME => {
                    let header = try_parse_hdr!(ContentEncoding, self);
                    headers.push(Header::ContentEncoding(header));
                }
                ContentType::NAME | ContentType::SHORT_NAME => {
                    let header = try_parse_hdr!(ContentType, self);
                    headers.push(Header::ContentType(header));
                    found_content_type = true;
                }
                ContentDisposition::NAME => {
                    let header = try_parse_hdr!(ContentDisposition, self);
                    headers.push(Header::ContentDisposition(header));
                }
                RecordRoute::NAME => comma_separated!(self => {
                    let header = try_parse_hdr!(RecordRoute, self);
                    headers.push(Header::RecordRoute(header));
                }),
                Require::NAME => {
                    let header = try_parse_hdr!(Require, self);
                    headers.push(Header::Require(header));
                }
                RetryAfter::NAME => {
                    let header = try_parse_hdr!(RetryAfter, self);
                    headers.push(Header::RetryAfter(header));
                }
                Organization::NAME => {
                    let header = try_parse_hdr!(Organization, self);
                    headers.push(Header::Organization(header));
                }
                AcceptEncoding::NAME => {
                    let header = try_parse_hdr!(AcceptEncoding, self);
                    headers.push(Header::AcceptEncoding(header));
                }
                Accept::NAME => {
                    let header = try_parse_hdr!(Accept, self);
                    headers.push(Header::Accept(header));
                }
                AcceptLanguage::NAME => {
                    let header = try_parse_hdr!(AcceptLanguage, self);
                    headers.push(Header::AcceptLanguage(header));
                }
                AlertInfo::NAME => {
                    let header = try_parse_hdr!(AlertInfo, self);
                    headers.push(Header::AlertInfo(header));
                }
                Allow::NAME => {
                    let header = try_parse_hdr!(Allow, self);
                    headers.push(Header::Allow(header));
                }
                AuthenticationInfo::NAME => {
                    let header = try_parse_hdr!(AuthenticationInfo, self);
                    headers.push(Header::AuthenticationInfo(header));
                }
                Supported::NAME | Supported::SHORT_NAME => {
                    let header = try_parse_hdr!(Supported, self);
                    headers.push(Header::Supported(header));
                }
                Timestamp::NAME => {
                    let header = try_parse_hdr!(Timestamp, self);
                    headers.push(Header::Timestamp(header));
                }
                Unsupported::NAME => {
                    let header = try_parse_hdr!(Unsupported, self);
                    headers.push(Header::Unsupported(header));
                }
                WWWAuthenticate::NAME => {
                    let header = try_parse_hdr!(WWWAuthenticate, self);
                    headers.push(Header::WWWAuthenticate(header));
                }
                Warning::NAME => {
                    let header = try_parse_hdr!(Warning, self);
                    headers.push(Header::Warning(header));
                }
                name => {
                    // Found a header that is not defined in RFC 3261.
                    let data = self.read_until_new_line_as_str()?;
                    let header = RawHeader::new(name, data);
                    headers.push(Header::RawHeader(header));
                }
            };

            if !self.parse_header_end() {
                return self.parse_error(Kind::Header);
            }

            if matches!(self.scanner.peek_byte(), Some(b'\r') | Some(b'\n') | None) {
                break 'headers;
            }
        }

        if found_content_type {
            self.skip_new_line();
            let body = self.remaining();
            sip_message.set_body(body.into());
        }

        Ok(sip_message)
    }

    pub fn parse_status_line(&mut self) -> Result<StatusLine> {
        self.parse_sip_version()?;

        let code = self.parse_code()?;
        let reason = self.parse_reason()?;

        self.skip_new_line();

        Ok(StatusLine { code, reason })
    }

    pub fn parse_request_line(&mut self) -> Result<RequestLine> {
        let token = self.scanner.read_while(is_token);
        let method = token.into();
        let uri = self.parse_uri(true)?;

        self.parse_sip_version()?;
        self.skip_new_line();

        Ok(RequestLine { method, uri })
    }

    #[inline]
    pub(crate) fn parse_sip_version(&mut self) -> Result<()> {
        Ok(self
            .scanner
            .must_read_bytes(B_SIPV2)
            .or_else(|_| self.parse_error(Kind::Version))?)
    }

    pub fn parse_sip_uri(&mut self, parse_params: bool) -> Result<SipUri> {
        self.skip_ws();

        match self.scanner.peek_bytes(3) {
            Some(SIP) | Some(SIPS) => {
                let uri = self.parse_uri(parse_params)?;
                Ok(SipUri::Uri(uri))
            }
            _ => {
                let addr = self.parse_name_addr()?;
                Ok(SipUri::NameAddr(addr))
            }
        }
    }

    pub fn parse_uri(&mut self, parse_params: bool) -> Result<Uri> {
        self.skip_ws();

        let scheme = self.parse_scheme()?;
        let user = self.parse_user_info()?;
        let host_port = self.parse_host_port()?;

        if !parse_params {
            return Ok(Uri::new(scheme, user, host_port));
        }

        // Parse SIP uri parameters.
        let mut user_param = None;
        let mut method_param = None;
        let mut transport_param: Option<&str> = None;
        let mut ttl_param = None;
        let mut lr_param: Option<&str> = None;
        let mut maddr_param = None;

        let parameters = parse_param!(
            self,
            parse_uri_param,
            USER_PARAM = user_param,
            METHOD_PARAM = method_param,
            TRANSPORT_PARAM = transport_param,
            TTL_PARAM = ttl_param,
            LR_PARAM = lr_param,
            MADDR_PARAM = maddr_param
        );

        let transport_param = transport_param
            .map(TransportType::from_str)
            .transpose()
            .or_else(|_| self.parse_error(Kind::Transport))?;
        let ttl_param = ttl_param.map(|ttl: &str| ttl.parse().unwrap());
        let lr_param = lr_param.is_some();
        let method_param = method_param.map(|p: &str| p.as_bytes().into());
        let user_param = user_param.map(|u: &str| u.into());
        let maddr_param = maddr_param.and_then(|m: &str| m.parse::<Host>().ok());

        let headers = if let Some(b'?') = self.scanner.advance_if_eq(b'?') {
            // The uri has header parameters.
            Some(self.parse_headers_in_sip_uri()?)
        } else {
            None
        };
        self.skip_ws();

        Ok(Uri {
            scheme,
            user,
            host_port,
            transport_param,
            ttl_param,
            method_param,
            user_param,
            lr_param,
            maddr_param,
            parameters,
            headers,
        })
    }

    pub fn parse_name_addr(&mut self) -> Result<NameAddr> {
        self.skip_ws();
        let display = self.parse_display_name()?;
        self.skip_ws();

        self.must_read(b'<')?;
        let uri = self.parse_uri(true)?;
        self.must_read(b'>')?;

        Ok(NameAddr { display, uri })
    }

    pub fn parse_host_port(&mut self) -> Result<HostPort> {
        let host = match self.peek_byte() {
            Some(b'[') => {
                // Is a Ipv6 host
                self.next_byte()?;
                // the '[' and ']' characters are removed from the host
                let host = self
                    .scanner
                    .read_while_as_str(|b| b != b']')
                    .or_else(|_| self.parse_error(Kind::Host))?;
                self.next_byte()?;

                if let Ok(ipv6_addr) = host.parse() {
                    Host::IpAddr(ipv6_addr)
                } else {
                    return self.parse_error(Kind::Host);
                }
            }
            _ => {
                // Is a domain name or Ipv4 host.
                let host = self.read_host_str();
                if host.is_empty() {
                    return self.parse_error(Kind::Host);
                }
                if let Ok(ip_addr) = host.parse() {
                    Host::IpAddr(ip_addr)
                } else {
                    Host::DomainName(DomainName::new(host.to_string()))
                }
            }
        };

        let port = self.parse_port()?;

        Ok(HostPort { host, port })
    }

    fn parse_code(&mut self) -> Result<StatusCode> {
        self.skip_ws();
        let digits = self.scanner.read_while(is_digit);
        self.skip_ws();

        let code = digits
            .try_into()
            .or_else(|_| self.parse_error(Kind::StatusCode))?;

        Ok(code)
    }

    fn parse_reason(&mut self) -> Result<ReasonPhrase> {
        let reason = self.read_until_new_line_as_str()?.to_string().into();

        Ok(ReasonPhrase::new(reason))
    }

    fn parse_scheme(&mut self) -> Result<Scheme> {
        let token = self.scanner.peek_while(is_token);
        let scheme = match token {
            SIP => Scheme::Sip,
            SIPS => Scheme::Sips,
            _ => return self.parse_error(Kind::Uri),
        };
        // Eat the scheme.
        self.scanner.advance_by(token.len());
        // Eat the ":" character.
        self.must_read(b':')?;

        Ok(scheme)
    }

    fn parse_user_info(&mut self) -> Result<Option<UserInfo>> {
        if !self.exists_user_part_in_uri() {
            return Ok(None);
        }
        // We have user part in uri.
        let user = self.read_user_str().into();
        let pass = if let Some(b':') = self.scanner.advance_if_eq(b':') {
            Some(self.read_pass_as_str().into())
        } else {
            None
        };
        // Take '@'.
        self.scanner
            .must_read(b'@')
            .or_else(|_| self.parse_error(Kind::Uri))?;

        Ok(Some(UserInfo { user, pass }))
    }

    fn parse_port(&mut self) -> Result<Option<u16>> {
        let Some(b':') = self.scanner.advance_if_eq(b':') else {
            return Ok(None);
        };
        let port = self
            .scanner
            .read_u16()
            .or_else(|_| self.parse_error(Kind::Host))?;

        if crate::is_valid_port(port) {
            Ok(Some(port))
        } else {
            self.parse_error(Kind::Host)
        }
    }

    fn parse_headers_in_sip_uri(&mut self) -> Result<UriHeaders> {
        let mut params = Params::new();
        loop {
            let param = self.parse_hdr_in_uri()?;
            params.push(param);

            if self.scanner.advance_if_eq(b'&').is_none() {
                break;
            }
        }
        Ok(UriHeaders { inner: params })
    }

    fn parse_display_name(&mut self) -> Result<Option<DisplayName>> {
        match self.scanner.peek_byte() {
            Some(b'"') => {
                self.next_byte()?; // consume '"'
                let name = self.scanner.read_while(|b| b != b'"');
                self.next_byte()?; // consume closing '"'
                Ok(Some(DisplayName::new(str::from_utf8(name)?.into())))
            }
            Some(b'<') => Ok(None), // no display name
            None => {
                return Err(crate::Error::Other("EOF!".to_string()));
            }
            _ => {
                let name = self.parse_token()?;
                self.skip_ws();
                Ok(Some(DisplayName::new(name.into())))
            }
        }
    }

    fn exists_user_part_in_uri(&self) -> bool {
        self.remaining()
            .iter()
            .take_while(|&&b| !is_space(b) && !is_newline(b) && b != b'>')
            .any(|&b| b == b'@')
    }

    #[inline]
    fn parse_header_end(&mut self) -> bool {
        !(self.scanner.advance_if_eq(b'\r').is_none()
            || self.scanner.advance_if_eq(b'\n').is_none())
    }

    #[inline]
    pub(crate) fn parse_token(&mut self) -> Result<&'buf str> {
        if let Some(b'"') = self.scanner.advance_if_eq(b'"') {
            let value = self.scanner.read_while(|b| b != b'"');
            self.next_byte()?;

            Ok(str::from_utf8(value)?)
        } else {
            // is_token ensures that is valid UTF-8
            Ok(self.read_token_str())
        }
    }

    #[inline]
    pub(crate) fn next_byte(&mut self) -> Result<u8> {
        self.scanner.next_byte().ok_or_else(|| {
            self.parse_error::<u8>(Kind::Scanner(ScannerError::Eof))
                .unwrap_err()
        })
    }

    /// Shortcut for yielding a parse error wrapped in a result type.
    pub(crate) fn parse_error<T>(&self, kind: Kind) -> Result<T> {
        Err(Error::ParseError(ParseError::new(kind, *self.position())))
    }

    /// Read until a new line (`\r` or `\n`) is found.
    pub(crate) fn read_until_new_line_as_str(&mut self) -> Result<&'buf str> {
        let bytes = self.scanner.read_while(is_not_newline);

        Ok(str::from_utf8(bytes)?)
    }

    pub(crate) fn parse_auth_challenge(&mut self) -> Result<Challenge> {
        let scheme = self.parse_token()?;
        if scheme == DIGEST {
            return self.parse_digest_challenge();
        }
        let mut params = Params::new();
        comma_separated!(self => {
            let param = self.parse_ref_param()?.into();

            params.push(param);

        });

        Ok(Challenge::Other {
            scheme: scheme.into(),
            param: params,
        })
    }

    fn parse_digest_challenge(&mut self) -> Result<Challenge> {
        let mut digest = DigestChallenge::default();

        comma_separated!(self => {
            let (name, value) = self.parse_ref_param()?;

            match name {
                REALM => digest.realm = value.map(String::from),
                NONCE => digest.nonce = value.map(String::from),
                DOMAIN => digest.domain = value.map(String::from),
                ALGORITHM => digest.algorithm = value.map(String::from),
                OPAQUE => digest.opaque = value.map(String::from),
                QOP => digest.qop = value.map(String::from),
                STALE => digest.stale = value.map(String::from),
                _other => {
                    // return err?
                }
            }
        });

        Ok(Challenge::Digest(digest))
    }

    fn parse_digest_credential(&mut self) -> Result<Credential> {
        let mut digest = DigestCredential::default();

        comma_separated!(self => {
            let (name, value) = self.parse_ref_param()?;

            match name {
                REALM => digest.realm = value.map(String::from),
                USERNAME => digest.username = value.map(String::from),
                NONCE => digest.nonce = value.map(String::from),
                URI => digest.uri = value.map(String::from),
                RESPONSE => digest.response = value.map(String::from),
                ALGORITHM => digest.algorithm = value.map(String::from),
                CNONCE => digest.cnonce = value.map(String::from),
                OPAQUE => digest.opaque = value.map(String::from),
                QOP => digest.qop = value.map(String::from),
                NC => digest.nc = value.map(String::from),
                _ => {}, // Ignore unknown parameters
            }
        });

        Ok(Credential::Digest(digest))
    }

    fn parse_other_credential(&mut self, scheme: &'buf str) -> Result<Credential> {
        let mut param = Params::new();
        comma_separated!(self => {
            let p: Param = self.parse_ref_param()?.into();

            param.push(p);
        });

        Ok(Credential::Other {
            scheme: scheme.into(),
            param,
        })
    }

    #[inline]
    pub(crate) fn skip_ws(&mut self) {
        self.scanner.read_while(is_space);
    }

    #[inline]
    pub(crate) fn skip_new_line(&mut self) {
        self.scanner.read_while(is_newline);
    }

    #[inline]
    pub(crate) fn alphabetic(&mut self) -> &'buf [u8] {
        self.scanner.read_while(is_alphabetic)
    }

    #[inline]
    pub(crate) fn read_until(&mut self, byte: u8) -> &'buf [u8] {
        self.scanner.read_until(byte)
    }

    #[inline]
    pub(crate) fn peek_byte(&self) -> Option<&u8> {
        self.scanner.peek_byte()
    }

    #[inline]
    pub(crate) fn position(&self) -> &Position {
        self.scanner.position()
    }

    #[inline]
    pub(crate) fn remaining(&self) -> &[u8] {
        self.scanner.remaining()
    }

    #[inline]
    pub(crate) fn not_comma_or_newline(&mut self) -> &'buf [u8] {
        self.scanner.read_while(not_comma_or_newline)
    }

    #[inline]
    pub(crate) fn is_next_newline(&self) -> bool {
        self.scanner.peek_if(is_newline).is_some()
    }

    #[inline]
    pub(crate) fn read_u32(&mut self) -> Result<u32> {
        Ok(self
            .scanner
            .read_u32()
            .or_else(|err| self.parse_error(Kind::Scanner(err)))?)
    }

    #[inline]
    pub(crate) fn must_read(&mut self, byte: u8) -> Result<()> {
        Ok(self
            .scanner
            .must_read(byte)
            .or_else(|err| self.parse_error(Kind::Scanner(err)))?)
    }

    #[inline]
    pub(crate) fn read_f32(&mut self) -> Result<f32> {
        Ok(self
            .scanner
            .read_f32()
            .or_else(|err| self.parse_error(Kind::Scanner(err)))?)
    }

    #[inline]
    fn read_user_str(&mut self) -> &'buf str {
        unsafe { self.scanner.read_while_as_str_unchecked(is_user) }
    }

    #[inline]
    fn read_pass_as_str(&mut self) -> &'buf str {
        unsafe { self.scanner.read_while_as_str_unchecked(is_pass) }
    }

    #[inline]
    fn read_host_str(&mut self) -> &'buf str {
        unsafe { self.scanner.read_while_as_str_unchecked(is_host) }
    }

    #[inline]
    pub(crate) fn read_token_str(&mut self) -> &'buf str {
        unsafe { self.scanner.read_while_as_str_unchecked(is_token) }
    }

    #[inline]
    pub(crate) unsafe fn read_while_as_str_unchecked(
        &mut self,
        func: impl Fn(u8) -> bool,
    ) -> &'buf str {
        unsafe { self.scanner.read_while_as_str_unchecked(func) }
    }

    pub(crate) unsafe fn parse_param_unchecked(
        &mut self,
        func: impl Fn(u8) -> bool,
    ) -> Result<(&'buf str, Option<&'buf str>)> {
        self.skip_ws();
        let name = unsafe { self.scanner.read_while_as_str_unchecked(&func) };
        let Some(b'=') = self.scanner.peek_byte() else {
            return Ok((name, None));
        };
        self.next_byte()?;
        let value = if let Some(b'"') = self.scanner.peek_byte() {
            // TODO: skip ignore \"\"
            let Some(value) = self.scanner.read_between(b'"') else {
                return self.parse_error(Kind::Param);
            };
            str::from_utf8(value)?
        } else {
            unsafe { self.scanner.read_while_as_str_unchecked(func) }
        };

        Ok((name, Some(value)))
    }

    pub(crate) fn parse_ref_param(&mut self) -> Result<ParamRef<'buf>> {
        unsafe { self.parse_param_unchecked(is_token) }
    }

    pub(crate) fn parse_auth_credential(&mut self) -> Result<Credential> {
        let scheme = self.parse_token()?;
        if scheme == DIGEST {
            return self.parse_digest_credential();
        }
        self.parse_other_credential(scheme)
    }

    #[inline]
    fn parse_hdr_in_uri(&mut self) -> Result<Param> {
        // SAFETY: `is_hdr_uri` only accepts ASCII bytes, which are
        // always valid UTF-8.
        Ok(unsafe { self.parse_param_unchecked(is_hdr_uri)?.into() })
    }
}

fn parse_uri_param<'a>(parser: &mut Parser<'a>) -> Result<ParamRef<'a>> {
    // SAFETY: `is_param` only accepts ASCII bytes, which are
    // always valid UTF-8.
    let mut param = unsafe { parser.parse_param_unchecked(is_param)? };

    if param.0 == LR_PARAM && param.1.is_none() {
        param.1 = Some("");
    }

    Ok(param)
}

#[inline]
pub(crate) fn parse_via_param<'a>(parser: &mut Parser<'a>) -> Result<ParamRef<'a>> {
    // SAFETY: `is_via_param` only accepts ASCII bytes, which
    // are always valid UTF-8.
    unsafe { parser.parse_param_unchecked(is_via_param) }
}

#[inline(always)]
pub(crate) fn is_via_param(b: u8) -> bool {
    VIA_PARAM_TAB[b as usize]
}

#[inline(always)]
pub(crate) fn is_host(b: u8) -> bool {
    HOST_TAB[b as usize]
}

#[inline(always)]
pub(crate) fn is_token(b: u8) -> bool {
    TOKEN_TAB[b as usize]
}

#[inline(always)]
fn is_user(b: u8) -> bool {
    USER_TAB[b as usize]
}

#[inline(always)]
fn is_pass(b: u8) -> bool {
    PASS_TAB[b as usize]
}

#[inline(always)]
fn is_param(b: u8) -> bool {
    PARAM_TAB[b as usize]
}

#[inline(always)]
fn is_hdr_uri(b: u8) -> bool {
    HDR_TAB[b as usize]
}

#[cfg(test)]
mod tests {
    use crate::message::{Scheme, Uri, UserInfo};
    use crate::{Result, uri_test_ok};

    uri_test_ok! {
        name: uri_test_1,
        input: "sip:biloxi.com",
        expected: Uri::builder()
            .with_scheme(Scheme::Sip)
            .with_host("biloxi.com".parse().unwrap())
            .build()
    }

    uri_test_ok! {
        name: uri_test_2,
        input: "sip:biloxi.com:5060",
        expected: Uri::builder()
            .with_scheme(Scheme::Sip)
            .with_host("biloxi.com:5060".parse().unwrap())
            .build()
    }

    uri_test_ok! {
        name: uri_test_3,
        input: "sip:a@b:5060",
        expected: Uri::builder()
            .with_scheme(Scheme::Sip)
            .with_user(UserInfo::new("a", None))
            .with_host("b:5060".parse().unwrap())
            .build()
    }

    uri_test_ok! {
        name: uri_test_4,
        input: "sip:bob@biloxi.com:5060",
        expected: Uri::builder()
            .with_scheme(Scheme::Sip)
            .with_user(UserInfo::new("bob", None))
            .with_host("biloxi.com:5060".parse().unwrap())
            .build()
    }

    uri_test_ok! {
        name: uri_test_5,
        input: "sip:bob@192.0.2.201:5060",
        expected: Uri::builder()
            .with_scheme(Scheme::Sip)
            .with_user(UserInfo::new("bob", None))
            .with_host("192.0.2.201:5060".parse().unwrap())
            .build()
    }

    uri_test_ok! {
        name: uri_test_6,
        input: "sip:bob@[::1]:5060",
        expected: Uri::builder()
            .with_scheme(Scheme::Sip)
            .with_user(UserInfo::new("bob", None))
            .with_host("[::1]:5060".parse().unwrap())
            .build()
    }

    uri_test_ok! {
        name: uri_test_7,
        input: "sip:bob:secret@biloxi.com",
        expected: Uri::builder()
            .with_scheme(Scheme::Sip)
            .with_user(UserInfo::new("bob", Some("secret")))
            .with_host("biloxi.com".parse().unwrap())
            .build()
    }

    uri_test_ok! {
        name: uri_test_8,
        input: "sip:bob:pass@192.0.2.201",
        expected: Uri::builder()
            .with_scheme(Scheme::Sip)
            .with_user(UserInfo::new("bob", Some("pass")))
            .with_host("192.0.2.201".parse().unwrap())
            .build()
    }

    uri_test_ok! {
        name: uri_test_9,
        input: "sip:bob@biloxi.com;foo=bar",
        expected: Uri::builder()
            .with_scheme(Scheme::Sip)
            .with_user(UserInfo::new("bob", None))
            .with_host("biloxi.com".parse().unwrap())
            .with_param("foo", Some("bar"))
            .build()
    }

    uri_test_ok! {
        name: uri_test_10,
        input: "sip:bob@biloxi.com:5060;foo=bar",
        expected: Uri::builder()
            .with_scheme(Scheme::Sip)
            .with_user(UserInfo::new("bob", None))
            .with_host("biloxi.com:5060".parse().unwrap())
            .with_param("foo", Some("bar"))
            .build()
    }

    uri_test_ok! {
        name: uri_test_11,
        input: "sips:bob@biloxi.com:5060",
        expected: Uri::builder()
            .with_scheme(Scheme::Sips)
            .with_user(UserInfo::new("bob", None))
            .with_host("biloxi.com:5060".parse().unwrap())
            .build()
    }

    uri_test_ok! {
        name: uri_test_12,
        input: "sips:bob:pass@biloxi.com:5060",
        expected: Uri::builder()
            .with_scheme(Scheme::Sips)
            .with_user(UserInfo::new("bob", Some("pass")))
            .with_host("biloxi.com:5060".parse().unwrap())
            .build()
    }

    uri_test_ok! {
        name: test_uri_11,
        input: "sip:bob@biloxi.com:5060;foo",
        expected: Uri::builder()
            .with_scheme(Scheme::Sip)
            .with_user(UserInfo::new("bob", None))
            .with_param("foo", None)
            .with_host("biloxi.com:5060".parse().unwrap())
            .build()
    }

    uri_test_ok! {
        name: test_uri_12,
        input: "sip:bob@biloxi.com:5060;foo;baz=bar",
        expected: Uri::builder()
            .with_scheme(Scheme::Sip)
            .with_user(UserInfo::new("bob", None))
            .with_host("biloxi.com:5060".parse().unwrap())
            .with_param("baz", Some("bar"))
            .build()
    }

    uri_test_ok! {
        name: test_uri_13,
        input: "sip:bob@biloxi.com:5060;baz=bar;foo",
        expected: Uri::builder()
            .with_scheme(Scheme::Sip)
            .with_user(UserInfo::new("bob", None))
            .with_host("biloxi.com:5060".parse().unwrap())
            .with_param("baz", Some("bar"))
            .build()
    }

    uri_test_ok! {
        name: test_uri_14,
        input: "sip:bob@biloxi.com:5060;baz=bar;foo;a=b",
        expected: Uri::builder()
            .with_scheme(Scheme::Sip)
            .with_user(UserInfo::new("bob", None))
            .with_host("biloxi.com:5060".parse().unwrap())
            .with_param("baz", Some("bar"))
            .with_param("foo", None)
            .with_param("a", Some("b"))
            .build()
    }

    uri_test_ok! {
        name: test_uri_15,
        input: "sip:bob@biloxi.com?foo=bar",
        expected: Uri::builder()
            .with_scheme(Scheme::Sip)
            .with_user(UserInfo::new("bob", None))
            .with_host("biloxi.com".parse().unwrap())
            .with_header("foo", Some("bar"))
            .build()
    }

    uri_test_ok! {
        name: test_uri_16,
        input: "sip:bob@biloxi.com?foo",
        expected: Uri::builder()
            .with_scheme(Scheme::Sip)
            .with_user(UserInfo::new("bob", None))
            .with_host("biloxi.com".parse().unwrap())
            .with_header("foo", None)
            .build()
    }

    uri_test_ok! {
        name: test_uri_17,
        input: "sip:bob@biloxi.com:5060?foo=bar",
        expected: Uri::builder()
            .with_scheme(Scheme::Sip)
            .with_user(UserInfo::new("bob", None))
            .with_host("biloxi.com:5060".parse().unwrap())
            .with_header("foo", Some("bar"))
            .build()
    }

    uri_test_ok! {
        name: test_uri_18,
        input: "sip:bob@biloxi.com:5060?baz=bar&foo=&a=b",
        expected: Uri::builder()
            .with_scheme(Scheme::Sip)
            .with_user(UserInfo::new("bob", None))
            .with_host("biloxi.com:5060".parse().unwrap())
            .with_header("baz", Some("bar"))
            .with_header("foo", Some(""))
            .with_header("a", Some("b"))
            .build()
    }

    uri_test_ok! {
        name: test_uri_19,
        input: "sip:bob@biloxi.com:5060?foo=bar&baz",
        expected: Uri::builder()
            .with_scheme(Scheme::Sip)
            .with_user(UserInfo::new("bob", None))
            .with_host("biloxi.com:5060".parse().unwrap())
            .with_header("foo", Some("bar"))
            .with_header("baz", None)
            .build()
    }

    uri_test_ok! {
        name: test_uri_20,
        input: "sip:bob@biloxi.com;foo?foo=bar",
        expected: Uri::builder()
            .with_scheme(Scheme::Sip)
            .with_user(UserInfo::new("bob", None))
            .with_host("biloxi.com".parse().unwrap())
            .with_param("foo", None)
            .with_header("foo", Some("bar"))
            .build()
    }
}
