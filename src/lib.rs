//! `imap-rs`: a modern, high-performance, security-first IMAP client for Rust.
//!
//! This is the umbrella crate. It re-exports the three workspace crates and a
//! handful of convenience entry points, so most users need only one dependency:
//!
//! ```toml
//! [dependencies]
//! imap-rs = "0.2"
//! ```
//!
//! # Quick start
//!
//! ```no_run
//! use imap_rs::connect_tls;
//! use imap_rs::credentials::Password;
//!
//! # async fn run() -> Result<(), Box<dyn std::error::Error>> {
//! // TCP + TLS handshake (both with timeouts), then CAPABILITY inside TLS.
//! let session = connect_tls("imap.example.com", 993).await?;
//! // `login` only exists on a TLS session — enforced at compile time.
//! let auth = session.login("user", Password::new("pass")).await?;
//! let mut inbox = auth.select("INBOX").await?;
//! for msg in inbox.fetch("1:*", "BODY[]").await? {
//!     println!("seq={} uid={:?}", msg.seq, msg.uid);
//! }
//! # Ok(()) }
//! ```
//!
//! # Highlights
//!
//! - **Security-first**: `rustls`-only TLS, [`zeroize`]d credentials,
//!   `#![forbid(unsafe_code)]`, and a fuzzed, bounds-checked parser.
//! - **Compile-time-correct sessions**: illegal protocol transitions do not
//!   compile (see [`Session`]).
//! - **Zero-copy parser** with a small dependency tree.
//!
//! # Crate layout
//!
//! The implementation is split across three crates, re-exported here:
//!
//! - [`core`] — protocol types and the zero-copy parser (no I/O).
//! - [`client`] — the async, type-state session and command dispatcher.
//! - [`tls`] — `rustls`-based transport ([`connect_tls`], [`connect_starttls`]).
//!
//! [`zeroize`]: https://crates.io/crates/zeroize

#![forbid(unsafe_code)]

/// Protocol types, AST, and zero-copy parser.
pub use imap_core as core;

/// Async session management and IMAP state machine.
pub use imap_client as client;

/// High-level secure connection wrappers using `rustls`.
pub use imap_tls as tls;

// Ergonomic top-level re-exports for common usage
pub use imap_client::Session;
pub use imap_tls::{connect_starttls, connect_tls};

/// Secret credential wrappers (`Password` and `OAuthToken`) re-exported from
/// `imap_client::credentials`.
pub mod credentials {
    pub use imap_client::credentials::{OAuthToken, Password};
}
