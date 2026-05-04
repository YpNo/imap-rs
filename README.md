# imap-rs

A modern, high-performance, and security-first IMAP library for Rust.

## Features

- **Security First**: 100% Safe Rust. Built-in protection against credential leaks using `zeroize`.
- **Memory Safe TLS**: Exclusively uses `rustls` (no OpenSSL or Native-TLS).
- **Zero-Copy Parser**: Hand-rolled recursive descent parser for maximum performance without allocations.
- **Typed State Machine**: Leverages Rust's type system to enforce valid IMAP command sequences at compile-time.
- **IMAP4rev2 Ready**: Designed for RFC 9051 with backward compatibility via automatic capability negotiation.
- **Async Native**: Built on `tokio` for high-concurrency workloads.

## Project Structure

The project is split into three core crates to ensure a clean separation of concerns:

- `imap-core`: Protocol types, AST, and the zero-copy parser (no I/O).
- `imap-client`: Async session management, command pipelining, and state machine.
- `imap-tls`: High-level secure connection wrapper using `rustls`.

## Usage

Add this to your `Cargo.toml`:

```toml
[dependencies]
imap-rs = { git = "https://github.com/YpNo/imap-rs" }
```

### Basic Example

```rust
use imap_tls::connect_tls;
use imap_client::credentials::Password;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // connect_tls performs TCP + TLS handshake (both with timeouts) and
    // fetches CAPABILITY in the encrypted channel.
    let session = connect_tls("imap.example.com", 993).await?;

    // LOGIN is only available on TLS sessions (compile-time enforced).
    // Username and password are quote-escaped per RFC 9051; passwords
    // containing 8-bit or control bytes should use AUTHENTICATE PLAIN
    // (`session.authenticate_plain(...)`).
    let auth = session.login("user", Password::new("pass")).await?;

    // SELECT a mailbox (transitions to Selected state).
    let mut inbox = auth.select("INBOX").await?;

    // FETCH returns structured results.
    for msg in inbox.fetch("1:*", "BODY[]").await? {
        println!("seq={} uid={:?} body={}B",
                 msg.seq, msg.uid, msg.body.as_deref().map(|b| b.len()).unwrap_or(0));
    }

    Ok(())
}
```

### STARTTLS

```rust
let session = imap_tls::connect_starttls("imap.example.com", 143).await?;
// Capabilities are *only* trusted from inside the TLS channel.
```

## Development & Testing

### Toolchain
This project is pinned to Rust **1.95.0** to ensure consistent diagnostic output for UI tests (`trybuild`). A `rust-toolchain.toml` file is included in the repository.

### Running Tests
To run all tests (including state-machine validation):
```bash
cargo test --workspace
```

### Coverage
We use `cargo-tarpaulin` for coverage. You can run it on the stable toolchain:
```bash
cargo tarpaulin --all-features --workspace --timeout 120 --out xml
```

### Troubleshooting UI Tests
If you see a `mismatch` error in `tests/ui/` after updating the compiler or changing error messages, you can "bless" the new output:
```bash
TRYBUILD=overwrite cargo test -p imap-client --test type_state_tests
```
Verify the changes with `git diff` before committing.

Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines on how to contribute to this project.

## Security

Please see [SECURITY.md](SECURITY.md) for our vulnerability disclosure policy.

## License

Licensed under the MIT license.
