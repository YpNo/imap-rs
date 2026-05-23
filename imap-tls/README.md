# imap-rs-tls

`rustls`-based secure transport for the [`imap-rs`](https://github.com/YpNo/imap-rs)
library.

This is the **infrastructure** layer of the hexagonal `imap-rs` workspace. It
establishes encrypted IMAP connections and returns a ready-to-use
[`imap-rs-client`](https://crates.io/crates/imap-rs-client) session.

## Features

- **Pure-Rust TLS**: uses `rustls` (via `tokio-rustls`) exclusively — no OpenSSL,
  no native-tls, no C FFI.
- **Implicit TLS** (`connect_tls`, port 993) and **STARTTLS upgrade**
  (`connect_starttls`, port 143).
- **Security-first STARTTLS**: capabilities are re-fetched *inside* the encrypted
  channel; pre-TLS server-asserted capabilities are never trusted.
- **Timeout guards** on TCP connect, TLS handshake, and pre-TLS exchanges to
  resist slowloris-style hangs.

## Usage

```toml
[dependencies]
imap-rs-tls = "0.2"
```

```rust
use imap_tls::connect_tls;

# async fn run() -> Result<(), Box<dyn std::error::Error>> {
let session = connect_tls("imap.example.com", 993).await?;
# Ok(()) }
```

> Most users should depend on the umbrella [`imap-rs`](https://crates.io/crates/imap-rs)
> crate, which re-exports this crate as `imap_rs::tls`.

## License

MIT
