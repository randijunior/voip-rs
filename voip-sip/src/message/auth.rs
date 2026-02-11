//! SIP Auth types
use std::fmt;

use super::Params;

/// The cnonce parameter used in Digest authentication.
pub const CNONCE: &str = "cnonce";

/// The qop parameter used in Digest authentication.
pub const QOP: &str = "qop";

/// The nc parameter used in Digest authentication.
pub const NC: &str = "nc";

/// The nextnonce parameter used in Digest authentication.
pub const NEXTNONCE: &str = "nextnonce";

/// The rspauth parameter used in Digest authentication.
pub const RSPAUTH: &str = "rspauth";

/// The SIP authentication scheme used in Digest authentication.
pub const DIGEST: &str = "Digest";

/// The realm parameter used in Digest authentication.
pub const REALM: &str = "realm";

/// The username parameter used in Digest authentication.
pub const USERNAME: &str = "username";

/// The nonce parameter used in Digest authentication.
pub const NONCE: &str = "nonce";

/// The uri parameter used in Digest authentication.
pub const URI: &str = "uri";

/// The response parameter used in Digest authentication.
pub const RESPONSE: &str = "response";

/// The algorithm parameter used in Digest authentication.
pub const ALGORITHM: &str = "algorithm";

/// The opaque parameter used in Digest authentication.
pub const OPAQUE: &str = "opaque";

/// The authentication scheme used in Digest authentication.
pub const DOMAIN: &str = "domain";

/// The authentication scheme used in Digest authentication.
pub const STALE: &str = "stale";

/// A Digest Challenge.
#[derive(Debug, PartialEq, Eq, Clone, Default)]
pub struct DigestChallenge {
    /// The realm of the digest authentication.
    pub realm: Option<String>,
    /// The domain of the digest authentication.
    pub domain: Option<String>,
    /// The nonce of the digest authentication.
    pub nonce: Option<String>,
    /// The opaque value of the digest authentication.
    pub opaque: Option<String>,
    /// Indicates whether the previous request was stale.
    pub stale: Option<String>,
    /// The algorithm used in the digest authentication.
    pub algorithm: Option<String>,
    /// The quality of protection (qop) value.
    pub qop: Option<String>,
}

/// This enum represents an authentication challenge mechanism used in
/// `Proxy-Authenticate` and `WWW-Authenticate` headers.
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum Challenge {
    /// A `Digest` authentication scheme.
    Digest(DigestChallenge),
    /// Any other authentication scheme not specifically handled.
    Other {
        /// The name of the authentication scheme.
        scheme: String,
        /// The parameters associated with the scheme.
        param: Params,
    },
}

impl fmt::Display for Challenge {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Challenge::Digest(DigestChallenge {
                realm,
                domain,
                nonce,
                opaque,
                stale,
                algorithm,
                qop,
            }) => {
                write!(f, "Digest ")?;
                if let Some(realm) = realm {
                    write!(f, "realm={realm}, ")?;
                }
                if let Some(domain) = domain {
                    write!(f, "domain={domain}, ")?;
                }
                if let Some(nonce) = nonce {
                    write!(f, "nonce={nonce}, ")?;
                }
                if let Some(opaque) = opaque {
                    write!(f, "opaque={opaque}, ")?;
                }
                if let Some(stale) = stale {
                    write!(f, "stale={stale}, ")?;
                }
                if let Some(algorithm) = algorithm {
                    write!(f, "algorithm={algorithm}, ")?;
                }
                if let Some(qop) = qop {
                    write!(f, "qop={qop}")?;
                }

                Ok(())
            }
            Challenge::Other {
                scheme: _,
                param: _,
            } => todo!(),
        }
    }
}

/// Represents credentials for a `Digest` authentication scheme, typically found
/// in the `Authorization` and `Proxy-Authorization` headers.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DigestCredential {
    /// The realm value that defines the protection split_ws.
    pub realm: Option<String>,
    /// The username associated with the credential.
    pub username: Option<String>,
    /// The nonce value provided by the server.
    pub nonce: Option<String>,
    /// The URI of the requested resource.
    pub uri: Option<String>,
    /// The response hash calculated from the credential data.
    pub response: Option<String>,
    /// The algorithm used to hash the credentials (e.g., "MD5").
    pub algorithm: Option<String>,
    /// The client nonce value (cnonce) used to prevent replay attacks.
    pub cnonce: Option<String>,
    /// The opaque value provided by the server, to be returned unchanged.
    pub opaque: Option<String>,
    /// The quality of protection (qop) applied to the message.
    pub qop: Option<String>,
    /// The nonce count (nc), indicating the number of requests made with the
    /// same nonce.
    pub nc: Option<String>,
}

/// This type represent a credential containing the authentication information
/// in `Authorization` and `Proxy-Authorization` headers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Credential {
    /// A `digest` authentication scheme.
    Digest(DigestCredential),
    /// Other scheme not specified.
    Other {
        /// The name of the authentication scheme.
        scheme: String,
        /// The parameters associated with the scheme.
        param: Params,
    },
}

impl fmt::Display for Credential {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Credential::Digest(DigestCredential {
                realm,
                username,
                nonce,
                uri,
                response,
                algorithm,
                cnonce,
                opaque,
                qop,
                nc,
            }) => {
                write!(f, "Digest ")?;
                if let Some(username) = username {
                    write!(f, "username={username}")?;
                }
                if let Some(realm) = realm {
                    write!(f, "realm={realm}, ")?;
                }
                if let Some(nonce) = nonce {
                    write!(f, "nonce={nonce}, ")?;
                }
                if let Some(uri) = uri {
                    write!(f, "uri={uri}, ")?;
                }
                if let Some(response) = response {
                    write!(f, "response={response}, ")?;
                }
                if let Some(algorithm) = algorithm {
                    write!(f, "algorithm={algorithm}, ")?;
                }
                if let Some(cnonce) = cnonce {
                    write!(f, "cnonce={cnonce}, ")?;
                }
                if let Some(qop) = qop {
                    write!(f, "qop={qop}, ")?;
                }
                if let Some(nc) = nc {
                    write!(f, "nc={nc}, ")?;
                }
                if let Some(opaque) = opaque {
                    write!(f, "opaque={opaque}, ")?;
                }

                Ok(())
            }
            Credential::Other {
                scheme: _,
                param: _,
            } => todo!(),
        }
    }
}
