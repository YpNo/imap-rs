use thiserror::Error;

#[derive(Error, Debug, PartialEq, Eq)]
pub enum ParseError {
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
    #[error("Other parsing error: {0}")]
    Other(&'static str),
}
