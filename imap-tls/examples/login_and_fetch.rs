//! End-to-end smoke example: TLS connect → LOGIN → SELECT → FETCH → IDLE.
//!
//! Run with:
//!     IMAP_HOST=imap.example.com IMAP_USER=me@example.com IMAP_PASS=... \
//!         cargo run --example login_and_fetch -p imap-tls
//!
//! The example uses environment variables so secrets never end up in the
//! repository or shell history. It is *not* run in CI; treat it as a
//! manual smoke test.

use std::env;
use std::time::Duration;

use imap_client::credentials::Password;
use imap_tls::connect_tls;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let host = env::var("IMAP_HOST").map_err(|_| "set IMAP_HOST")?;
    let port: u16 = env::var("IMAP_PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(993);
    let user = env::var("IMAP_USER").map_err(|_| "set IMAP_USER")?;
    let pass = Password::new(env::var("IMAP_PASS").map_err(|_| "set IMAP_PASS")?);

    // 1. TLS connect — TCP + handshake both have timeouts; CAPABILITY is
    //    fetched automatically.
    let session = connect_tls(&host, port).await?;
    println!(
        "Connected. IMAP4rev1={} IMAP4rev2={} IDLE={} MOVE={}",
        session.capabilities.imap4rev1,
        session.capabilities.imap4rev2,
        session.capabilities.idle,
        session.capabilities.move_ext,
    );

    // 2. LOGIN — credentials are quoted/escaped and the response is
    //    parsed; NO/BAD become CommandFailed errors.
    let auth = session.login(&user, pass).await?;
    println!("Authenticated.");

    // 3. SELECT INBOX → Selected state.
    let mut inbox = auth.select("INBOX").await?;

    // 4. FETCH the most recent message body.
    let results = inbox.fetch("*", "BODY[]").await?;
    if let Some(first) = results.first() {
        let bytes = first.body.as_deref().unwrap_or(&[]);
        println!(
            "seq={} uid={:?} body={}B",
            first.seq,
            first.uid,
            bytes.len()
        );
    }

    // 5. IDLE for 10 s, then DONE. Production code should re-issue IDLE
    //    every <29 minutes per RFC 2177.
    if inbox.capabilities.idle {
        let idle = inbox.idle().await?;
        tokio::time::sleep(Duration::from_secs(10)).await;
        idle.stop().await?;
        println!("IDLE finished cleanly.");
    }

    Ok(())
}
