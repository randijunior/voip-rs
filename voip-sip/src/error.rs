use std::ops::Range;
use std::str::{self, Utf8Error};

use thiserror::Error;
use utils::{Position, ScannerError};

use crate::message::{CodeClass, Method, StatusCode};

pub type Result<T> = std::result::Result<T, Error>;

// impl std::convert::From<tokio::sync::mpsc::error::SendError<crate::transport::TransportMessage>>
//     for Error
// {
//     fn from(
//         value:
// tokio::sync::mpsc::error::SendError<crate::transport::TransportMessage>,
//     ) -> Self {
//         Self::ChannelClosed
//     }
// }

impl std::convert::From<Utf8Error> for Error {
    fn from(value: Utf8Error) -> Self {
        todo!()
    }
}

impl From<std::fmt::Error> for Error {
    fn from(value: std::fmt::Error) -> Self {
        Self::FmtError(value)
    }
}

#[derive(Debug, Error)]
pub enum Error {
    #[error(transparent)]
    ParseError(#[from] ParseError),

    #[error("Transport: {0}")]
    TransportError(String),

    #[error("Transaction Error: {0}")]
    TransactionError(#[from] TransactionError),

    #[error(transparent)]
    DialogError(#[from] DialogError),

    #[error("Missing required '{0}' header")]
    MissingHeader(&'static str),

    #[error(transparent)]
    Io(#[from] std::io::Error),

    #[error("Channel closed")]
    ChannelClosed,

    #[error("Unsupported transport")]
    UnsupportedTransport,

    #[error("Poisoned lock")]
    PoisonedLock,

    #[error("Invalid Status Code")]
    InvalidStatusCode,

    #[error("Fmt Error")]
    FmtError(std::fmt::Error),

    #[error("Internal error: {0}")]
    Other(String),
}

impl Error {
    pub fn is_transport_error(&self) -> bool {
        matches!(self, Self::TransportError(_))
    }
}

#[derive(Debug, Error)]
pub struct ParseError {
    pub kind: ParseErrorKind,
    pub position: Position,
}

impl ParseError {
    pub fn new(kind: ParseErrorKind, position: Position) -> Self {
        Self { kind, position }
    }
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        todo!()
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum ParseErrorKind {
    StatusCode,
    Header,
    Host,
    Method,
    Version,
    Uri,
    Param,
    Transport,
    Scanner(ScannerError),
}

#[derive(Debug, Error, PartialEq)]
pub enum DialogError {
    #[error("Method cannot establish a dialog")]
    InvalidMethod,

    #[error("Missing To tag in 'To' header")]
    MissingTagInToHeader,
}

#[derive(Debug, Error, PartialEq)]
pub enum TransactionError {
    #[error(
        "Received invalid 'ACK' method, The ACK request must be passed directly to the transport layer for transmission."
    )]
    AckCannotCreateTransaction,
    #[error("Failed to send request: {0}")]
    FailedToSendMessage(String),
    #[error("Timeout reached after send message")]
    Timeout, //     #[error("The transaction is no longer valid")]
             // Invalid,
}
