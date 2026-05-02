# imap-rs: High-Security Rust IMAP Library

## Project Mission
`imap-rs` is a production-grade, memory-safe, and security-first IMAP library for the Rust ecosystem. It is designed to replace aging libraries with a modern, async-native architecture that enforces strict security boundaries at compile-time.

## Core Architectural Principles

### 1. Hexagonal & Tiered Structure
The workspace is split into three specialized crates:
- **`imap-core`**: The "Domain" layer. Contains the AST, error types, and a zero-copy recursive descent parser. It is strictly I/O-free and designed to be `no-std` compatible.
- **`imap-client`**: The "Service" layer. Manages the asynchronous state machine, command pipelining, and background I/O dispatcher. It handles the mapping of tagged responses back to callers.
- **`imap-tls`**: The "Infrastructure" layer. A high-level wrapper that utilizes `rustls` and `tokio-rustls` to establish secure connections without relying on C-based FFI (OpenSSL/Native-TLS).

### 2. Type-Safe State Machine
Session states are managed via generic markers: `Session<State, Transport>`.
- **States**: `Unauthenticated`, `Authenticated`, `Selected`.
- **Transports**: `PlainText`, `Tls`.
- **Enforcement**: Security-critical methods like `.login()` are only implemented for `Session<Unauthenticated, Tls>`, preventing accidental credential leakage over unencrypted channels at compile-time.

### 3. Zero-Copy Performance
The parser operates on `&[u8]` slices and maintains references into the original network buffer. This minimizes allocations and maximizes throughput, even for large IMAP literals (e.g., email attachments).

### 4. Robust Streaming Dispatcher
The `RawClient` uses a `BytesMut` buffer strategy to handle:
- **Partial Reads**: Correctly reassembles protocol frames split across multiple TCP packets.
- **Binary Literals**: Identifies `{n}\r\n` lengths to wait for complete data blocks.
- **Event Broadcasting**: Background untagged responses (e.g., `EXISTS`, `FETCH`) are broadcast via a `tokio::sync::broadcast` channel.

## Security & Quality Gates

- **Memory Safety**: 100% `safe` Rust. `unsafe` code is strictly prohibited.
- **No-FFI TLS**: Only `rustls` is allowed for transport encryption to avoid the vulnerability surface of C-based TLS libraries.
- **Credential Hygiene**: Sensitive data is wrapped in `Password` and `OAuthToken` types which use the `zeroize` crate to wipe memory on drop and obfuscate `Debug` output.
- **Dependency Audit**: `deny.toml` is active to block legacy, risky, or deprecated crates (e.g., `lazy_static`, `openssl`).
- **Fuzzing**: `cargo-fuzz` is integrated into `imap-core` to ensure the parser is resilient against malformed or malicious server input.

## Key Features & Extensions

- **RFC 9051 Compliance**: Primary support for IMAP4rev2 with automatic capability negotiation for RFC 3501 (IMAP4rev1) servers.
- **Feature Flags**: Extensions like `MOVE` (RFC 6851), `CONDSTORE`, and `UIDPLUS` are feature-gated to keep the core library lightweight.
- **Async Native**: Built entirely on the `tokio` ecosystem for high-concurrency performance.

## Maintainability & Community
- **Automated Releases**: CI/CD handles releases on every merge to `main`.
- **Performance Gated**: PRs are benchmarked via `criterion` to prevent performance regressions in the parser.
- **Governance**: Multi-maintainer model defined in `CONTRIBUTING.md`.

---
*This document serves as a high-level anchor for AI agents and human contributors to understand the design intent and constraints of the imap-rs project.*
