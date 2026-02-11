use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
/// An SIP Method.
///
/// This enum declares SIP methods as described by RFC3261 and Others.
pub enum Method {
    /// SIP INVITE Method.
    Invite,
    /// SIP ACK Method.
    Ack,
    /// SIP BYE Method.
    Bye,
    /// SIP CANCEL Method.
    Cancel,
    /// SIP REGISTER Method.
    Register,
    /// SIP OPTIONS Method.
    Options,
    /// SIP INFO Method.
    Info,
    /// SIP NOTIFY Method.
    Notify,
    /// SIP SUBSCRIBE Method.
    Subscribe,
    /// SIP UPDATE Method.
    Update,
    /// SIP REFER Method.
    Refer,
    /// SIP PRACK Method.
    Prack,
    /// SIP MESSAGE Method.
    Message,
    /// SIP PUBLISH Method.
    Publish,
    /// An unknown SIP method.
    Unknown,
}

impl Method {
    /// Returns the byte representation of a method.
    pub fn as_bytes(&self) -> &'static [u8] {
        self.as_str().as_bytes()
    }

    pub fn is_invite(&self) -> bool {
        matches!(self, Self::Invite)
    }

    pub fn is_ack(&self) -> bool {
        matches!(self, Self::Ack)
    }

    /// Returns the string representation of a method.
    #[inline(always)]
    pub fn as_str(&self) -> &'static str {
        match self {
            Method::Invite => "INVITE",
            Method::Ack => "ACK",
            Method::Bye => "BYE",
            Method::Cancel => "CANCEL",
            Method::Register => "REGISTER",
            Method::Options => "OPTIONS",
            Method::Info => "INFO",
            Method::Notify => "NOTIFY",
            Method::Subscribe => "SUBSCRIBE",
            Method::Update => "UPDATE",
            Method::Refer => "REFER",
            Method::Prack => "PRACK",
            Method::Message => "MESSAGE",
            Method::Publish => "PUBLISH",
            Method::Unknown => "UNKNOWN-Method",
        }
    }
}

impl From<&[u8]> for Method {
    fn from(value: &[u8]) -> Self {
        match value {
            b"INVITE" => Method::Invite,
            b"CANCEL" => Method::Cancel,
            b"ACK" => Method::Ack,
            b"BYE" => Method::Bye,
            b"REGISTER" => Method::Register,
            b"OPTIONS" => Method::Options,
            b"INFO" => Method::Info,
            b"NOTIFY" => Method::Notify,
            b"SUBSCRIBE" => Method::Subscribe,
            b"UPDATE" => Method::Update,
            b"REFER" => Method::Refer,
            b"PRACK" => Method::Prack,
            b"MESSAGE" => Method::Message,
            b"PUBLISH" => Method::Publish,
            _ => Method::Unknown,
        }
    }
}

impl fmt::Display for Method {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}
