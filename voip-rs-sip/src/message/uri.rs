use std::borrow::Cow;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::str::FromStr;
use std::{fmt, ops};

use itertools::Itertools;

use super::{Method, Params};
use crate::error::{Error, Result};
use crate::parser::Parser;
use crate::transport::TransportType;

/// A SIP uri.
///
/// Represents an uri used in SIP messages, which can be either:
/// - a plain [`Uri`] (e.g. `sip:user@example.com`), or
/// - a [`NameAddr`] (e.g. `"Alice" <sip:user@example.com>`, a URI with an optional
///   display name).
///
/// # Examples
///
/// ```rust
/// use voip_rs::message::{NameAddr, SipUri};
///
/// let uri: SipUri = "sip:alice@example.com".parse().unwrap();
/// assert!(uri.is_uri());
///
/// let name_addr: SipUri = "\"Alice\" <sip:alice@example.com>".parse().unwrap();
/// assert!(name_addr.is_name_addr());
/// ```
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum SipUri {
    /// A plain SIP URI.
    Uri(Uri),
    /// A named address.
    NameAddr(NameAddr),
}

impl SipUri {
    /// Returns `true` if this is a [`SipUri::NameAddr`] variant, otherwise
    /// returns `false`.
    pub fn is_name_addr(&self) -> bool {
        matches!(self, SipUri::NameAddr(_))
    }

    /// Returns `true` if this is a [`SipUri::Uri`] variant, otherwise returns
    /// `false`.
    pub fn is_uri(&self) -> bool {
        matches!(self, SipUri::Uri(_))
    }

    /// Returns a reference to the [`Uri`].
    pub fn uri(&self) -> &Uri {
        match self {
            SipUri::Uri(uri) => &uri,
            SipUri::NameAddr(name_addr) => &name_addr.uri,
        }
    }

    /// Returns a reference to the [`NameAddr`] if this is a
    /// [`SipUri::NameAddr`] variant.
    pub fn name_addr(&self) -> Option<&NameAddr> {
        if let SipUri::NameAddr(addr) = self {
            Some(addr)
        } else {
            None
        }
    }

    /// Returns the display part if present.
    pub fn display(&self) -> Option<&str> {
        if let SipUri::NameAddr(addr) = self {
            addr.display()
        } else {
            None
        }
    }

    /// Returns the scheme of the uri.
    pub fn scheme(&self) -> Scheme {
        match self {
            SipUri::Uri(uri) => uri.scheme,
            SipUri::NameAddr(addr) => addr.uri.scheme,
        }
    }

    /// Returns the user part of the uri.
    pub fn user(&self) -> Option<&UserInfo> {
        match self {
            SipUri::Uri(uri) => uri.user.as_ref(),
            SipUri::NameAddr(addr) => addr.uri.user.as_ref(),
        }
    }

    /// Returns a reference to the [`HostPort`] of the uri.
    pub fn host_port(&self) -> &HostPort {
        match self {
            SipUri::Uri(uri) => &uri.host_port,
            SipUri::NameAddr(addr) => &addr.uri.host_port,
        }
    }

    /// Returns the `transport` parameter.
    pub fn transport_param(&self) -> Option<TransportType> {
        match self {
            SipUri::Uri(uri) => uri.transport_param,
            SipUri::NameAddr(addr) => addr.uri.transport_param,
        }
    }

    /// Returns the user parameter of the uri.
    pub fn user_param(&self) -> Option<&str> {
        match self {
            SipUri::Uri(uri) => uri.user_param.as_deref(),
            SipUri::NameAddr(addr) => addr.uri.user_param.as_deref(),
        }
    }

    /// Returns the method parameter of the uri.
    pub fn method_param(&self) -> Option<Method> {
        match self {
            SipUri::Uri(uri) => uri.method_param,
            SipUri::NameAddr(addr) => addr.uri.method_param,
        }
    }

    /// Returns the ttl parameter of the uri.
    pub fn ttl_param(&self) -> Option<u8> {
        match self {
            SipUri::Uri(uri) => uri.ttl_param,
            SipUri::NameAddr(addr) => addr.uri.ttl_param,
        }
    }

    /// Returns the lr parameter of the uri.
    pub fn lr_param(&self) -> bool {
        match self {
            SipUri::Uri(uri) => uri.lr_param,
            SipUri::NameAddr(addr) => addr.uri.lr_param,
        }
    }

    /// Returns the maddr parameter of the uri.
    pub fn maddr_param(&self) -> &Option<Host> {
        match self {
            SipUri::Uri(uri) => &uri.maddr_param,
            SipUri::NameAddr(addr) => &addr.uri.maddr_param,
        }
    }

    /// Returns the other parameters of the uri.
    pub fn other_params(&self) -> Option<&Params> {
        match self {
            SipUri::Uri(uri) => uri.parameters.as_ref(),
            SipUri::NameAddr(addr) => addr.uri.parameters.as_ref(),
        }
    }

    /// Returns the header parameters of the uri.
    pub fn headers(&self) -> Option<&UriHeaders> {
        match self {
            SipUri::Uri(uri) => uri.headers.as_ref(),
            SipUri::NameAddr(addr) => addr.uri.headers.as_ref(),
        }
    }
}

impl FromStr for SipUri {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        Parser::new(s.as_bytes()).parse_sip_uri(true)
    }
}

impl fmt::Display for SipUri {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SipUri::Uri(uri) => write!(f, "{}", uri),
            SipUri::NameAddr(addr) => write!(f, "{}", addr),
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Default, Copy)]
/// A SIP URI scheme, either `sip` or `sips`.
///
/// Represents the scheme that appears in a SIP URI.
pub enum Scheme {
    #[default]
    /// An Sip uri scheme.
    Sip,
    /// An Sips uri scheme.
    Sips,
}

/// Represents the header parameters of a SIP URI.
#[derive(Debug, PartialEq, Eq, Default, Clone)]
pub struct UriHeaders {
    pub(crate) inner: Params,
}

impl ops::Deref for UriHeaders {
    type Target = Params;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

#[derive(Debug, PartialEq, Eq, Default, Clone)]
/// An SIP uri.
pub struct Uri {
    /// The uri scheme.
    pub scheme: Scheme,
    /// Optional user part of uri.
    pub user: Option<UserInfo>,
    /// The uri host.
    pub host_port: HostPort,
    /// The user parameter.
    pub user_param: Option<String>,
    /// The method parameter.
    pub method_param: Option<Method>,
    /// The transport parameter.
    pub transport_param: Option<TransportType>,
    /// The ttl parameter.
    pub ttl_param: Option<u8>,
    /// The lr parameter.
    pub lr_param: bool,
    /// The maddr parameter.
    pub maddr_param: Option<Host>,
    /// Other parameters.
    pub parameters: Option<Params>,
    /// Optional header parameters
    pub headers: Option<UriHeaders>,
}

impl Uri {
    /// Returns a builder to create an `SipUri`.
    pub fn builder() -> UriBuilder {
        UriBuilder::new()
    }

    /// Creates an `Uri` instance.
    pub const fn new(scheme: Scheme, user: Option<UserInfo>, host_port: HostPort) -> Self {
        Uri {
            scheme,
            user,
            host_port,
            user_param: None,
            method_param: None,
            transport_param: None,
            ttl_param: None,
            lr_param: false,
            maddr_param: None,
            parameters: None,
            headers: None,
        }
    }
}

impl FromStr for Uri {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        let mut p = Parser::new(s.as_bytes());

        p.parse_uri(true)
    }
}

impl fmt::Display for Uri {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.scheme {
            Scheme::Sip => write!(f, "sip")?,
            Scheme::Sips => write!(f, "sips")?,
        }
        write!(f, ":")?;

        if let Some(user) = &self.user {
            write!(f, "{}", user.user)?;
            if let Some(pass) = &user.pass {
                write!(f, ":{}", pass)?;
            }
            write!(f, "@")?;
        }
        write!(f, "{}", self.host_port)?;

        if let Some(user) = &self.user_param {
            write!(f, ";user={}", user)?;
        }
        if let Some(method) = &self.method_param {
            write!(f, ";method={}", method)?;
        }
        if let Some(maddr) = &self.maddr_param {
            write!(f, ";maddr={}", maddr)?;
        }
        if let Some(transport) = &self.transport_param {
            write!(f, ";transport={}", transport)?;
        }
        if let Some(ttl) = self.ttl_param {
            write!(f, ";ttl={}", ttl)?;
        }
        if self.lr_param {
            write!(f, ";lr")?;
        }
        if let Some(params) = &self.parameters {
            write!(f, "{}", params)?;
        }
        if let Some(hdr_params) = &self.headers {
            let formater = Itertools::format_with(hdr_params.inner.iter(), "&", |it, f| {
                f(&format_args!(
                    "{}={}",
                    it.name,
                    it.value.as_ref().map_or("", |v| &v)
                ))
            });
            write!(f, "?{}", formater)?;
        }

        Ok(())
    }
}

#[derive(Default)]
/// Builder for creating a new SIP URI.
pub struct UriBuilder {
    uri: Uri,
}

impl UriBuilder {
    /// Returns a builder to create an `UriBuilder`.
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the uri scheme.
    pub fn with_scheme(mut self, scheme: Scheme) -> Self {
        self.uri.scheme = scheme;
        self
    }

    /// Sets the user part of the uri.
    pub fn with_user(mut self, user: UserInfo) -> Self {
        self.uri.user = Some(user);
        self
    }

    /// Sets the host of the uri.
    pub fn with_host(mut self, host_port: HostPort) -> Self {
        self.uri.host_port = host_port;
        self
    }

    /// Sets the user parameter of the uri.
    pub fn with_user_param(mut self, param: &str) -> Self {
        self.uri.user_param = Some(param.into());
        self
    }

    /// Sets the method parameter of the uri.
    pub fn with_method_param(mut self, param: Method) -> Self {
        self.uri.method_param = Some(param);
        self
    }

    /// Sets the transport parameter of the uri.
    pub fn with_transport_param(mut self, param: TransportType) -> Self {
        self.uri.transport_param = Some(param);
        self
    }

    /// Sets the ttl parameter of the uri.
    pub fn with_ttl_param(mut self, param: &str) -> Self {
        self.uri.ttl_param = Some(param.parse().unwrap());
        self
    }

    /// Sets the lr parameter of the uri.
    pub fn with_lr_param(mut self, param: bool) -> Self {
        self.uri.lr_param = param;
        self
    }

    /// Sets the maddr parameter of the uri.
    pub fn with_maddr_param(mut self, param: &str) -> Self {
        self.uri.maddr_param = Some(param.parse().unwrap());
        self
    }

    /// Sets other parameters of the uri.
    pub fn with_params(mut self, params: Params) -> Self {
        self.uri.parameters = Some(params);
        self
    }

    /// Set generic parameter of the uri.
    pub fn with_param(mut self, name: &str, value: Option<&str>) -> Self {
        if let Some(params) = &mut self.uri.parameters {
            params.push(super::Param {
                name: name.into(),
                value: value.map(|v| v.into()),
            });
        } else {
            let mut params = Params::new();
            params.push(super::Param {
                name: name.into(),
                value: value.map(|v| v.into()),
            });
            self.uri.parameters = Some(params);
        }
        self
    }

    /// Set header parameter of the uri.
    pub fn with_header(mut self, name: &str, value: Option<&str>) -> Self {
        if let Some(hdr_params) = &mut self.uri.headers {
            hdr_params.inner.push(super::Param {
                name: name.into(),
                value: value.map(|v| v.into()),
            });
        } else {
            let mut hdr_params = Params::new();
            hdr_params.push(super::Param {
                name: name.into(),
                value: value.map(|v| v.into()),
            });
            self.uri.headers = Some(UriHeaders { inner: hdr_params });
        }
        self
    }

    /// Finalize the builder into a `Uri`.
    pub fn build(self) -> Uri {
        self.uri
    }
}

/// Represents an display name in `NameAddr`
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct DisplayName(String);

impl DisplayName {
    /// Creates a new `DisplayName` whith the given `display`.
    #[inline]
    pub fn new(display: &str) -> Self {
        Self(display.into())
    }

    /// Returns the inner phrase as str.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Represents an SIP `name-addr`.
///  
/// Typically appear in `From`, `To`, and `Contact` header. Contains an sip uri
/// and a optional display part.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct NameAddr {
    /// The optional display part.
    pub display: Option<DisplayName>,
    /// The uri of the `name-addr`.
    pub uri: Uri,
}

impl NameAddr {
    pub fn new(uri: Uri) -> Self {
        Self { display: None, uri }
    }
    /// Returns the display part if present.
    pub fn display(&self) -> Option<&str> {
        self.display.as_ref().map(|d| d.as_str())
    }
}

impl FromStr for NameAddr {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        let mut p = Parser::new(s.as_bytes());

        p.parse_name_addr()
    }
}

impl fmt::Display for NameAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(display) = &self.display {
            write!(f, "{} ", display.0)?;
        }
        write!(f, "<{}>", self.uri)?;

        Ok(())
    }
}

/// Represents the user information component of a URI.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct UserInfo {
    /// The username part of the URI.
    pub user: String,
    /// The optional password associated with the user.
    pub pass: Option<String>,
}

impl UserInfo {
    /// Creates a new `UserInfo` with the given `user` and optional `pass`.
    pub fn new(user: &str, pass: Option<&str>) -> Self {
        Self {
            user: user.into(),
            pass: pass.map(|pass| pass.into()),
        }
    }

    /// Returns the user.
    pub fn user(&self) -> &str {
        &self.user
    }

    /// Returns the pass.
    pub fn pass(&self) -> Option<&str> {
        self.pass.as_deref()
    }
}

/// Represents a domain name in a SIP URI.
#[derive(Debug, PartialEq, Eq, Clone, Hash)]
pub struct DomainName(pub(crate) Cow<'static, str>);

impl From<&str> for DomainName {
    fn from(name: &str) -> Self {
        Self::new(name.to_string())
    }
}

impl DomainName {
    /// Creates a new `DomainName` from a string slice.
    pub fn new(name: impl Into<Cow<'static, str>>) -> Self {
        DomainName(name.into())
    }

    /// Returns the string representation of the domain name.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for DomainName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Represents the host part of a URI, which can be either a
/// domain name or an IP address.
#[derive(Debug, PartialEq, Eq, Clone, Hash)]
pub enum Host {
    /// A domain name, such as `example.com`.
    DomainName(DomainName),
    /// An IP address, either IPv4 or IPv6.
    IpAddr(IpAddr),
}

impl From<SocketAddr> for HostPort {
    fn from(value: SocketAddr) -> Self {
        Self {
            host: Host::IpAddr(value.ip()),
            port: value.port().into(),
        }
    }
}

impl fmt::Display for Host {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Host::DomainName(domain) => write!(f, "{domain}"),
            Host::IpAddr(ip_addr) => write!(f, "{ip_addr}"),
        }
    }
}

impl Host {
    /// Returns `true` if the host is an IP address (IPv4 or IPv6).
    pub fn is_ip_addr(&self) -> bool {
        match self {
            Host::DomainName(_) => false,
            Host::IpAddr(_) => true,
        }
    }

    /// Returns the string representation of the host as a `Cow<str>`.
    ///
    /// If the host is a domain name, this returns a borrowed string. If the
    /// host is an IP address, this returns an owned string created via
    /// formatting.
    pub fn as_str(&self) -> Cow<'_, str> {
        match self {
            Host::DomainName(host) => Cow::Borrowed(&host.0),
            Host::IpAddr(host) => Cow::Owned(host.to_string()),
        }
    }
}

impl FromStr for Host {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        if let Ok(ip_addr) = s.parse::<IpAddr>() {
            Ok(Host::IpAddr(ip_addr))
        } else {
            Ok(Host::DomainName(DomainName::new(s.to_string())))
        }
    }
}

/// Represents a combination of a host (domain or IP address) and an optional
/// port.
#[derive(Debug, PartialEq, Eq, Clone, Hash)]
pub struct HostPort {
    /// The host part, which may be a domain name or an IP address.
    pub host: Host,
    /// The optional port number.
    pub port: Option<u16>,
}

impl HostPort {
    /// Returns the IP address if the host is an IP address, otherwise `None`.
    pub fn ip_addr(&self) -> Option<IpAddr> {
        match self.host {
            Host::DomainName(_) => None,
            Host::IpAddr(ip_addr) => Some(ip_addr),
        }
    }

    /// Returns `true` if the host is an IP address.
    pub fn is_ip_addr(&self) -> bool {
        self.ip_addr().is_some()
    }
}

impl FromStr for HostPort {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        let mut p = Parser::new(s.as_bytes());

        p.parse_host_port()
    }
}

impl fmt::Display for HostPort {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.host {
            Host::DomainName(domain) => f.write_str(&domain.0)?,
            Host::IpAddr(ip_addr) => write!(f, "{}", ip_addr)?,
        }
        if let Some(port) = self.port {
            write!(f, ":{}", port)?;
        }
        Ok(())
    }
}

impl From<Host> for HostPort {
    fn from(host: Host) -> Self {
        Self { host, port: None }
    }
}

impl HostPort {
    /// Creates a new `HostPort` from a host and optional port.
    pub const fn new(host: Host, port: Option<u16>) -> Self {
        Self { host, port }
    }

    /// Returns `true` if the host is a domain name.
    pub fn is_domain(&self) -> bool {
        matches!(self.host, Host::DomainName(_))
    }

    /// Returns the string representation of the host.
    pub fn host_as_str(&self) -> Cow<'_, str> {
        self.host.as_str()
    }
}

impl Default for HostPort {
    fn default() -> Self {
        Self {
            host: Host::IpAddr(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))),
            port: Some(5060),
        }
    }
}
