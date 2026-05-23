<p align="center">
  <img src="./assets/banner.svg" alt="imap-rs — secure, async, pure-Rust IMAP" width="100%">
</p>

# imap-rs

[![CI](https://github.com/YpNo/imap-rs/actions/workflows/ci.yml/badge.svg)](https://github.com/YpNo/imap-rs/actions/workflows/ci.yml)
[![crates.io](https://img.shields.io/crates/v/imap-rs.svg)](https://crates.io/crates/imap-rs)
[![GitHub release](https://img.shields.io/github/v/release/YpNo/imap-rs?sort=semver)](https://github.com/YpNo/imap-rs/releases/latest)
[![docs.rs](https://docs.rs/imap-rs/badge.svg)](https://docs.rs/imap-rs)
[![codecov](https://codecov.io/gh/YpNo/imap-rs/branch/main/graph/badge.svg)](https://codecov.io/gh/YpNo/imap-rs)
[![MSRV](https://img.shields.io/badge/MSRV-1.95.0-blue.svg)](https://github.com/YpNo/imap-rs)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

A modern, high-performance, and security-first IMAP library for Rust.

## Project Status & Call for Maintainers

> **Heads-up:** `imap-rs` has so far been **mainly "vibe coded"** — built rapidly with heavy AI assistance rather than by a seasoned IMAP/Rust team. It compiles cleanly, is panic-free in its production paths, and ships with unit + integration tests, a parser fuzz target, CI, and security hardening (`rustls`-only TLS, `zeroize`d credentials, `#![forbid(unsafe_code)]` across all crates). However, it has **not** yet been battle-tested in production or independently audited.

I'm now looking for **Senior Rust developers** to help **maintain and steward** this project long-term — reviewing the architecture and protocol correctness, hardening edge cases, expanding IMAP4rev2 / extension coverage, and guiding releases.

If you have deep Rust and/or IMAP experience and want to get involved:

- Open or comment on a [GitHub issue](https://github.com/YpNo/imap-rs/issues), or start a [discussion](https://github.com/YpNo/imap-rs/discussions)
- Let me know you're interested in a **maintainer** role
- See [CONTRIBUTING.md](CONTRIBUTING.md) for the development workflow, quality bar, and coding standards

Contributions of every size are welcome — but experienced maintainer reviews are what the project needs most right now.

## Features

- **Security First**: 100% Safe Rust. Built-in protection against credential leaks using `zeroize`.
- **Memory Safe TLS**: Exclusively uses `rustls` (no OpenSSL or Native-TLS).
- **Zero-Copy Parser**: Hand-rolled recursive descent parser for maximum performance without allocations.
- **Typed State Machine**: Leverages Rust's type system to enforce valid IMAP command sequences at compile-time.
- **IMAP4rev2 Ready**: Designed for RFC 9051 with backward compatibility via automatic capability negotiation.
- **Async Native**: Built on `tokio` for high-concurrency workloads.

## Why another IMAP library?

`imap-rs` exists to explore a deliberately different set of trade-offs, with a
few opinionated defaults:

- **Security as the default, not a configuration choice.** TLS is `rustls`-only
  (no OpenSSL / native-tls backend to misconfigure); credentials are `zeroize`d
  and redacted in `Debug`; `#![forbid(unsafe_code)]` is enforced across every
  crate; the parser is bounds-checked, literal-size-capped, and fuzzed; and
  STARTTLS re-validates capabilities *inside* the encrypted channel.
- **Illegal states that don't compile.** The session is type-stated over both
  protocol phase and transport (`Session<Unauthenticated|Authenticated|Selected,
  PlainText|Tls>`), so mistakes like `LOGIN` over plaintext or `FETCH` before
  authentication are caught by the compiler rather than at runtime.
- **A zero-copy parser with no parser dependency.** The RFC 9051 parser is
  hand-rolled and reads directly from the network buffer (`&[u8]`), keeping
  allocations and the dependency tree small.
- **Hexagonal, layered crates.** Protocol (`imap-rs-core`, zero I/O), session
  logic (`imap-rs-client`), and transport (`imap-rs-tls`) are separate crates —
  depend on just the parser, or swap the transport, without pulling in the rest.
- **A modern baseline.** Rust 2024 edition, `tokio`-native, and IMAP4rev2
  (RFC 9051)-first with automatic capability negotiation.

This isn't a claim that the alternatives are doing anything wrong — it's a
from-scratch take that optimizes for security defaults, compile-time
correctness, and a minimal dependency surface. (See the
[status note](#project-status--call-for-maintainers) above: the library is
young and not yet battle-tested.)

## Project Structure

The project is split into three core crates to ensure a clean separation of concerns. The `imap-rs` umbrella crate re-exports all three:

- `imap-rs-core` (re-exported as `imap_rs::core`): Protocol types, AST, and the zero-copy parser (no I/O).
- `imap-rs-client` (re-exported as `imap_rs::client`): Async session management, command pipelining, and state machine.
- `imap-rs-tls` (re-exported as `imap_rs::tls`): High-level secure connection wrapper using `rustls`.

## Usage

Add this to your `Cargo.toml`:

```toml
[dependencies]
imap-rs = "0.2"
```

### Basic Example

```rust
use imap_rs::connect_tls;
use imap_rs::credentials::Password;

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
let session = imap_rs::connect_starttls("imap.example.com", 143).await?;
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
TRYBUILD=overwrite cargo test -p imap-rs-client --test type_state_tests
```
Verify the changes with `git diff` before committing.

Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines on how to contribute to this project.

## Security

Please see [SECURITY.md](SECURITY.md) for our vulnerability disclosure policy.

## License

Licensed under the MIT license.
