//! Protocol core for the [`imap-rs`](https://crates.io/crates/imap-rs) library.
//!
//! `imap-rs-core` owns the IMAP4rev2 (RFC 9051) response model and a zero-copy,
//! hand-rolled recursive-descent parser. It performs **no I/O** and has no
//! network dependencies, which keeps it small and trivially testable.
//!
//! # Layout
//!
//! - [`ast`] — the typed response grammar ([`Response`], [`Status`], data
//!   responses, and `FETCH` attributes).
//! - [`parser`] — [`parse_response`], which turns a byte slice into a
//!   [`Response`], borrowing from the input where possible.
//! - [`error`] — [`ParseError`], the failure type returned by the parser.
//!
//! # Example
//!
//! ```
//! use imap_core::parser::parse_response;
//!
//! let input = b"* OK IMAP4rev2 Service Ready\r\n";
//! let (_rest, response) = parse_response(input).expect("valid greeting");
//! ```
#![forbid(unsafe_code)]

/// Typed IMAP4rev2 response grammar: [`Response`] and its constituents.
pub mod ast;
/// Parser failure type: [`ParseError`].
pub mod error;
/// Zero-copy response parser: [`parse_response`].
pub mod parser;

pub use ast::*;
pub use error::ParseError;
pub use parser::parse_response;
