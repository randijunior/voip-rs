use std::ops;

use crate::message::{MandatoryHeaders, Request, Response};

/// This type represents an received SIP request.
#[derive(Clone)]
pub struct IncomingRequest {
    /// The SIP message.
    pub request: Request,
    /// Incoming message info.
    pub incoming_info: Box<IncomingInfo>,
}

impl ops::Deref for IncomingRequest {
    type Target = Request;
    fn deref(&self) -> &Self::Target {
        &self.request
    }
}

/// This type represents an received SIP response.
#[derive(Clone)]
pub struct IncomingResponse {
    /// The SIP message.
    pub response: Response,
    /// Incoming message info.
    pub incoming_info: Box<IncomingInfo>,
}

impl ops::Deref for IncomingResponse {
    type Target = Response;
    fn deref(&self) -> &Self::Target {
        &self.response
    }
}

/// Incoming message info.
#[derive(Clone)]
pub struct IncomingInfo {
    /// The mandatory headers extracted from the message.
    pub mandatory_headers: MandatoryHeaders,
    /// The received transport packet.
    pub transport: super::TransportMessage,
}
