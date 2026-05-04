use thiserror::Error;

/// Errors produced by the IMAP response parser.
#[derive(Error, Debug, PartialEq, Eq)]
pub enum ParseError {
    /// Input ended before a complete response could be parsed.
    /// The caller should accumulate more bytes and retry.
    #[error("Incomplete input")]
    Incomplete,
    #[error("Invalid character at offset {0}")]
    InvalidChar(usize),
    #[error("Expected literal {expected:?} at offset {offset}")]
    ExpectedLiteral { expected: String, offset: usize },
    #[error("Unexpected end of input")]
    UnexpectedEof,
    #[error("Number parsing error")]
    InvalidNumber,
    /// A literal whose declared length exceeds the parser's hard cap.
    /// Used as an explicit DoS guard against hostile servers.
    #[error("Literal length {got} exceeds maximum {max}")]
    LiteralTooLarge { got: usize, max: usize },
    #[error("Malformed response: {0}")]
    Malformed(&'static str),
    #[error("Other parsing error: {0}")]
    Other(&'static str),
}
