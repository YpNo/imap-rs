# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- _(nothing yet)_

### Changed

- _(nothing yet)_

### Fixed

- _(nothing yet)_

## [0.1.0] - 2026-05-04

Initial public release of the workspace.

### Added

- **`imap-core`** — RFC 9051 zero-copy recursive-descent parser. Handles
  all status responses (`OK`, `NO`, `BAD`, `PREAUTH`, `BYE`) with full
  resp-text-code coverage (`ALERT`, `BADCHARSET`, `CAPABILITY`, `PARSE`,
  `PERMANENTFLAGS`, `READ-ONLY`, `READ-WRITE`, `TRYCREATE`, `UIDNEXT`,
  `UIDVALIDITY`, `UNSEEN`, plus generic `Other`); data responses
  (`CAPABILITY`, `LIST`, `LSUB`, `STATUS`, `SEARCH`, `FLAGS`, `EXISTS`,
  `RECENT`, `EXPUNGE`, `FETCH`); and `FETCH` attributes (`FLAGS`,
  `INTERNALDATE`, `RFC822[.SIZE|.HEADER|.TEXT]`, `ENVELOPE`, `BODY`,
  `BODYSTRUCTURE`, `BODY[<section>]<<origin>>`, `UID`).
- **DoS guard**: `MAX_LITERAL_SIZE = 64 MiB` cap on a single literal,
  surfaced as `ParseError::LiteralTooLarge` before any allocation.
- **`imap-client`** — async type-state IMAP session: `Session<State,
  Transport>` with `Unauthenticated → Authenticated → Selected`
  transitions and `PlainText`/`Tls` transport markers. `LOGIN` is
  compile-time gated to `Session<Unauthenticated, Tls>`.
- Commands: `LOGIN`, `AUTHENTICATE PLAIN` (SASL via `base64`),
  `LOGOUT`, `NOOP`, `CHECK`, `CAPABILITY`, `SELECT`, `EXAMINE`, `LIST`,
  `FETCH` (raw + structured `FetchResult`), `STORE`/`UID STORE`,
  `SEARCH`/`UID SEARCH`, `EXPUNGE`, `CLOSE`, `UNSELECT`, `IDLE`,
  `MOVE` (feature-gated).
- **Credential hygiene**: `Password` and `OAuthToken` use `zeroize` and
  obfuscate `Debug`. `Password::as_imap_quoted` performs RFC 9051
  quoted-string escaping (`\`, `"`); 8-bit / control-byte secrets are
  rejected with a pointer to `AUTHENTICATE PLAIN`.
- **Dispatcher** (`RawClient`): pipelined commands routed by tag,
  untagged frames broadcast on a 1024-slot `tokio::sync::broadcast`
  channel. Tagged `NO`/`BAD` responses become
  `ClientError::CommandFailed` carrying the server's resp-text.
- **`IDLE`** (RFC 2177): proper `+ idling` continuation handshake;
  `IdleHandle::stop` writes `DONE` and awaits the tagged `OK` with its
  own timeout. Capability-gated.
- **`imap-tls`** — TLS adapter using `rustls` + `webpki-roots`. Two
  entry points: `connect_tls` (port 993, direct TLS) and
  `connect_starttls` (port 143, cleartext greeting → STARTTLS upgrade
  → re-fetch CAPABILITY in the encrypted channel — pre-TLS server
  capabilities are never trusted).
- TCP-connect and TLS-handshake timeouts (default 30 s, overridable
  via `_with_timeouts` variants).
- Public `handshake_with_connector` and `starttls_with_connector` for
  custom `TlsConnector` use (e.g. tests with self-signed certs).
- **CI gates**: `cargo fmt`, `cargo clippy -D warnings`, `cargo test
  --all-features`, `cargo build --examples`, `cargo check` on the fuzz
  manifest, `cargo doc -D warnings`, `cargo deny`, SonarQube,
  Codecov, weekly security audits. All GitHub Actions pinned to
  commit SHAs.
- **In-process TLS integration tests** (4) using `rcgen` self-signed
  certs and `tokio_rustls::TlsAcceptor`: full handshake, greeting-with-
  `[CAPABILITY]` round-trip avoidance, full STARTTLS upgrade.

### Fixed

- _(initial release — no prior versions to fix)_

### Security

- 100% safe Rust; no `unsafe` blocks, no FFI dependencies, only
  `rustls` for TLS.

[Unreleased]: https://github.com/YpNo/imap-rs/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/YpNo/imap-rs/releases/tag/v0.1.0
