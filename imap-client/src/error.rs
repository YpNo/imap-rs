//! Error type for the IMAP client.

use imap_core::error::ParseError;
use thiserror::Error;

/// Errors returned by [`RawClient`](crate::client::RawClient) and
/// [`Session`](crate::session::Session) operations.
#[derive(Error, Debug)]
pub enum ClientError {
    /// An underlying socket I/O error.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    /// A server response could not be parsed.
    #[error("Parse error: {0}")]
    Parse(#[from] ParseError),
    /// The connection was closed before the operation completed.
    #[error("Connection closed")]
    ConnectionClosed,
    /// A single response frame exceeded the client's in-flight size cap — a
    /// denial-of-service guard against a server that never terminates a frame.
    #[error("response frame exceeded the maximum size of {max} bytes")]
    FrameTooLarge {
        /// The maximum frame size, in bytes, that the client will buffer.
        max: usize,
    },
    /// The server returned a tagged `NO` / `BAD`; the string is its resp-text.
    #[error("Command failed: {0}")]
    CommandFailed(String),
    /// A command required a capability the server did not advertise.
    #[error("Capability not supported: {0}")]
    UnsupportedCapability(&'static str),
    /// The command did not receive its tagged response within the timeout.
    #[error("Command timed out")]
    Timeout,
}
