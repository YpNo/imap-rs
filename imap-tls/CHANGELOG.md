# Changelog

All notable changes to this crate are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.2](https://github.com/YpNo/imap-rs/compare/imap-rs-tls-v0.2.1...imap-rs-tls-v0.2.2) - 2026-05-24

### Other

- release v0.2.2 ([#14](https://github.com/YpNo/imap-rs/pull/14))

## [0.2.1](https://github.com/YpNo/imap-rs/compare/imap-rs-tls-v0.2.0...imap-rs-tls-v0.2.1) - 2026-05-23

### Fixed

- clean up changelogs ([#12](https://github.com/YpNo/imap-rs/pull/12))

### Other

- release v0.2.0 ([#10](https://github.com/YpNo/imap-rs/pull/10))

## [0.2.0] - 2026-05-23

Initial release published to crates.io. `imap-rs-tls` is the secure transport
adapter that establishes encrypted connections and returns a ready-to-use
`imap-rs-client` session.

### Added

- `rustls`-based TLS adapter using `webpki-roots` for certificate validation —
  no OpenSSL, no native-tls, no C FFI.
- Two entry points:
  - `connect_tls` — direct TLS on port 993.
  - `connect_starttls` — port 143 cleartext greeting, then `STARTTLS` upgrade.
- TCP-connect and TLS-handshake timeouts (default 30 s), overridable via the
  `*_with_timeouts` variants.
- `handshake_with_connector` and `starttls_with_connector` for supplying a
  custom `TlsConnector` (e.g. integration tests with self-signed certs).
- In-process TLS integration tests using `rcgen` and `tokio_rustls::TlsAcceptor`
  (full handshake, greeting-with-`[CAPABILITY]`, full STARTTLS upgrade).

### Security

- STARTTLS hardening: capabilities are re-fetched **inside** the encrypted
  channel after the upgrade; pre-TLS, server-asserted capabilities are never
  trusted (defends against STARTTLS stripping/injection).
- Handshake and connect timeouts guard against slowloris-style hangs.
- `#![forbid(unsafe_code)]`; pure-Rust TLS stack.

[Unreleased]: https://github.com/YpNo/imap-rs/compare/imap-rs-tls-v0.2.0...HEAD
[0.2.0]: https://github.com/YpNo/imap-rs/releases/tag/imap-rs-tls-v0.2.0
