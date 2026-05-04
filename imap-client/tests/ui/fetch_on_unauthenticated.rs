use imap_client::{Session, Unauthenticated, Tls, RawClient, Capabilities};

#[tokio::main]
async fn main() {
    let raw: RawClient = unsafe { std::mem::zeroed() };
    let mut session = Session::<Unauthenticated, Tls>::new(raw, Capabilities::default());
    
    // This should fail to compile because fetch() is only for Selected state
    let _ = session.fetch("1", "ALL").await;
}
