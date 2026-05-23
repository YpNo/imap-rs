# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

This is the changelog for the umbrella `imap-rs` crate. Each member crate keeps
its own changelog: [`imap-rs-core`](imap-core/CHANGELOG.md),
[`imap-rs-client`](imap-client/CHANGELOG.md), and
[`imap-rs-tls`](imap-tls/CHANGELOG.md).

## [Unreleased]

## [0.2.0] - 2026-05-23

Initial release published to crates.io.

### Added

- Umbrella crate that re-exports the three workspace crates and provides
  ergonomic top-level access:
  - `imap_rs::core` → [`imap-rs-core`](https://crates.io/crates/imap-rs-core):
    protocol types and zero-copy parser (no I/O).
  - `imap_rs::client` → [`imap-rs-client`](https://crates.io/crates/imap-rs-client):
    async, type-state session and command dispatcher.
  - `imap_rs::tls` → [`imap-rs-tls`](https://crates.io/crates/imap-rs-tls):
    `rustls`-based secure transport (TLS and STARTTLS).
- Convenience re-exports: `Session`, `connect_tls`, `connect_starttls`, and
  `credentials::{Password, OAuthToken}`.

### Security

- 100% safe Rust across every crate (`#![forbid(unsafe_code)]`).
- `rustls`-only TLS (no OpenSSL / native-tls); STARTTLS capabilities are
  re-validated inside the encrypted channel.
- Credentials are zeroized on drop and redacted in `Debug`.
- Parser is bounds-checked, literal-size-capped, and fuzzed; the client bounds
  its read buffer against unbounded-memory denial-of-service.

[Unreleased]: https://github.com/YpNo/imap-rs/compare/imap-rs-v0.2.0...HEAD
[0.2.0]: https://github.com/YpNo/imap-rs/releases/tag/imap-rs-v0.2.0
