//! imap-rs: A modern, high-performance, and security-first IMAP library for Rust.
//!
//! This crate serves as the primary facade for the `imap-rs` project,
//! aggregating the protocol core, client state machine, and TLS transport.

/// Protocol types, AST, and zero-copy parser.
pub use imap_core as core;

/// Async session management and IMAP state machine.
pub use imap_client as client;

/// High-level secure connection wrappers using `rustls`.
pub use imap_tls as tls;

// Ergonomic top-level re-exports for common usage
pub use imap_client::Session;
pub use imap_tls::{connect_starttls, connect_tls};

pub mod credentials {
    pub use imap_client::credentials::{OAuthToken, Password};
}
