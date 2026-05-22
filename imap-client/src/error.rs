use imap_core::error::ParseError;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ClientError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Parse error: {0}")]
    Parse(#[from] ParseError),
    #[error("Connection closed")]
    ConnectionClosed,
    #[error("response frame exceeded the maximum size of {max} bytes")]
    FrameTooLarge { max: usize },
    #[error("Command failed: {0}")]
    CommandFailed(String),
    #[error("Capability not supported: {0}")]
    UnsupportedCapability(&'static str),
    #[error("Command timed out")]
    Timeout,
}
