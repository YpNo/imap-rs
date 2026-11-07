use imap_client::{Capabilities, RawClient, Session, Tls, Unauthenticated};

// `Session::new` builds a `PlainText` session. Only `Session::new_tls`, whose
// caller vouches for a verified TLS stream, may produce the `Tls` marker.
fn claim_tls(raw: RawClient) -> Session<Unauthenticated, Tls> {
    Session::new(raw, Capabilities::default())
}

fn main() {
    let _ = claim_tls;
}
