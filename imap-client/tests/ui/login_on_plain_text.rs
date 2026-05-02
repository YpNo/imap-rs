use imap_client::{Session, Unauthenticated, PlainText, RawClient, Capabilities};
use imap_client::credentials::Password;

#[tokio::main]
async fn main() {
    // This is just a mock for compilation testing
    let raw: RawClient = unsafe { std::mem::zeroed() }; 
    let session = Session::<Unauthenticated, PlainText>::new(raw, Capabilities::default());
    
    // This should fail to compile because login() is only for Tls transport
    let _ = session.login("user", Password::new("pass")).await;
}
