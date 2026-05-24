use thiserror::Error;

/// Errors produced by the IMAP response parser.
#[derive(Error, Debug, PartialEq, Eq)]
pub enum ParseError {
    /// Input ended before a complete response could be parsed.
    /// The caller should accumulate more bytes and retry.
    #[error("Incomplete input")]
    Incomplete,
    /// A byte that is invalid at the current grammar position was found.
    /// The value is the byte offset into the input where it occurred.
    #[error("Invalid character at offset {0}")]
    InvalidChar(usize),
    /// An expected literal token was not present at the given offset.
    #[error("Expected literal {expected:?} at offset {offset}")]
    ExpectedLiteral {
        /// The literal token the parser expected to find.
        expected: String,
        /// Byte offset into the input where the literal was expected.
        offset: usize,
    },
    /// Input ended unexpectedly in the middle of a token.
    #[error("Unexpected end of input")]
    UnexpectedEof,
    /// A numeric field could not be parsed as a valid integer.
    #[error("Number parsing error")]
    InvalidNumber,
    /// A literal whose declared length exceeds the parser's hard cap.
    /// Used as an explicit DoS guard against hostile servers.
    #[error("Literal length {got} exceeds maximum {max}")]
    LiteralTooLarge {
        /// Literal length declared by the server, in octets.
        got: usize,
        /// Maximum literal length the parser accepts, in octets.
        max: usize,
    },
    /// Well-formed bytes that nonetheless violate the response grammar.
    /// The value is a human-readable description of the violation.
    #[error("Malformed response: {0}")]
    Malformed(&'static str),
    /// A parsing error that does not fit any of the more specific variants.
    #[error("Other parsing error: {0}")]
    Other(&'static str),
}
