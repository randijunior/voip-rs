pub type Result<T> = std::result::Result<T, Error>;

use thiserror::Error;
use utils::{Position, ScannerError};

#[derive(Debug, Error, PartialEq)]
pub enum Error {
    #[error("ParseSdpError : {0}")]
    ParseSdpError(#[from] ParseSdpError),
}

#[derive(Debug, Error, PartialEq)]
pub enum ParseSdpError {
    #[error("invalid protocol")]
    SdpInvalidProtocolVersion,

    #[error("scanner error : {:#?}", 0)]
    ScannerError(ScannerError),

    #[error("{} : {:#?}", s, pos)]
    SyntaxError { s: String, pos: Position },
}

impl From<ScannerError> for Error {
    fn from(err: ScannerError) -> Self {
        Self::ParseSdpError(ParseSdpError::ScannerError(err))
    }
}
