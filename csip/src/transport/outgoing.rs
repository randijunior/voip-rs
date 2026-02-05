use std::io::Write;
use std::net::SocketAddr;
use std::ops;

use bytes::{BufMut, Bytes, BytesMut};

use crate::error::Result;
use crate::message::headers::{ContentLength};
use crate::message::{Request, Response, SipBody};
use crate::parser::HeaderParser;

/// This type represents an outbound SIP request.
pub struct OutgoingRequest {
    /// The SIP request.
    pub request: Request,
    /// Metadata about how the message will be sent.
    pub target_info: TargetTransportInfo,
    /// Message encoded representation.
    pub encoded: Bytes,
}

impl ops::Deref for OutgoingRequest {
    type Target = Request;
    fn deref(&self) -> &Self::Target {
        &self.request
    }
}

impl ops::DerefMut for OutgoingRequest {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.request
    }
}

/// This type represents an outgoing SIP response.
pub struct OutgoingResponse {
    /// The SIP response.
    pub response: Response,
    /// Metadata about how the message will be sent.
    pub target_info: TargetTransportInfo,
    /// Message encoded representation.
    pub encoded: Bytes,
}

impl ops::Deref for OutgoingResponse {
    type Target = Response;
    fn deref(&self) -> &Self::Target {
        &self.response
    }
}

impl ops::DerefMut for OutgoingResponse {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.response
    }
}

/// Outgoing message info.
#[derive(Clone)]
pub struct TargetTransportInfo {
    /// The socket this message should be sent to.
    pub target: SocketAddr,
    /// The transport to use for sending the message.
    pub transport: super::Transport,
}

/// Trait for converting a type into into a buffer.
pub trait Encode {
    /// The buffer type that holds the encoded data.
    type Buffer: AsRef<[u8]>;
    /// Converts the type into a byte buffer.
    fn encode(&self) -> Result<Self::Buffer>;
}

impl Encode for OutgoingResponse {
    type Buffer = Bytes;

    fn encode(&self) -> Result<Self::Buffer> {
        let response = &self.response;
        let buf = BytesMut::new();
        let mut writer = buf.writer();

        write!(
            writer,
            "SIP/2.0 {} {}\r\n",
            response.status().as_u16(),
            response.reason().as_str()
        )?;
        write!(writer, "{}", response.headers())?;
        write_body(&mut writer, response.body())?;

        Ok(writer.into_inner().freeze())
    }
}

impl Encode for OutgoingRequest {
    type Buffer = Bytes;

    fn encode(&self) -> Result<Self::Buffer> {
        let request = &self.request;
        let buf = BytesMut::new();
        let mut writer = buf.writer();

        write!(writer, "{}", request.req_line)?;
        write!(writer, "{}", request.headers)?;
        write_body(&mut writer, request.body.as_ref())?;

        Ok(writer.into_inner().freeze())
    }
}

fn write_body<W: Write>(writer: &mut W, body: Option<&SipBody>) -> Result<()> {
    const CONTENT_LENGTH: &str = ContentLength::NAME;
    if let Some(body) = body {
        write!(writer, "{CONTENT_LENGTH}: {}\r\n", body.len())?;
        write!(writer, "\r\n")?;
        writer.write_all(body)?;
    } else {
        write!(writer, "{CONTENT_LENGTH}: 0\r\n")?;
        write!(writer, "\r\n")?;
    }
    Ok(())
}
