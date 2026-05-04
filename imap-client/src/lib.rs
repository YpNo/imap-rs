pub mod capabilities;
pub mod client;
pub mod credentials;
pub mod error;
pub mod flags;
pub mod idle;
pub mod search;
pub mod session;

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
        // let unauth = Session::<Unauthenticated, Tls>::new(raw, Capabilities::default());
        // let auth = unauth.login("user", credentials::Password::new("pass")).await.unwrap();
    }
}
