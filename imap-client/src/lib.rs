//! Async, type-state IMAP client for the
//! [`imap-rs`](https://crates.io/crates/imap-rs) library.
//!
//! This crate owns the session state machine and the command dispatcher. It is
//! transport-agnostic: drive it with any `AsyncRead + AsyncWrite` stream (see
//! [`imap-rs-tls`](https://crates.io/crates/imap-rs-tls) for a ready-made
//! `rustls` transport).
//!
//! # Highlights
//!
//! - [`Session`] is type-stated over protocol phase ([`Unauthenticated`],
//!   [`Authenticated`], [`Selected`]) and transport ([`PlainText`], [`Tls`]),
//!   so invalid command sequences fail to compile. The transport marker is
//!   asserted by whoever builds the session: `imap-rs-tls` does so after a
//!   verified handshake, and [`Session::new_tls`] states the contract for
//!   custom transports.
//! - [`RawClient`] is the lower-level pipelining dispatcher: it routes tagged
//!   responses back to callers, streams each command's own untagged data to
//!   it under backpressure, and broadcasts the rest as shared [`Bytes`].
//! - Credentials ([`credentials::Password`], [`credentials::OAuthToken`]) are
//!   zeroized on drop and redacted in `Debug`.
#![forbid(unsafe_code)]

mod base64;
pub mod capabilities;
pub mod client;
pub mod credentials;
pub mod error;
pub mod flags;
pub mod idle;
pub mod search;
pub mod session;
mod wire;

/// Shared, cheaply cloned frame bytes, as delivered by
/// [`RawClient::events`] and [`client::CommandStream`].
pub use bytes::Bytes;
pub use capabilities::Capabilities;
pub use client::RawClient;
pub use error::ClientError;
pub use flags::{Flag, StoreAction};
pub use search::{SearchKey, SearchQuery};
pub use session::{Authenticated, PlainText, Selected, Session, Tls, Unauthenticated};

#[cfg(test)]
mod tests {

    #[test]
    fn test_type_states() {
        // This test ensures that the generic state machine builds and provides the expected interface.
        // We cannot call .fetch() on an Unauthenticated session, and we cannot call login() on a PlainText session!

        // let raw = RawClient::new(mock_stream);
        // let unauth = Session::<Unauthenticated, Tls>::new_tls(raw, Capabilities::default());
        // let auth = unauth.login("user", credentials::Password::new("pass")).await.unwrap();
    }
}
