# Changelog

All notable changes to this crate are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.3](https://github.com/YpNo/imap-rs/compare/imap-rs-client-v0.2.2...imap-rs-client-v0.2.3) - 2026-06-03

### Other

- release v0.2.3 ([#16](https://github.com/YpNo/imap-rs/pull/16))

## [0.2.2](https://github.com/YpNo/imap-rs/compare/imap-rs-client-v0.2.1...imap-rs-client-v0.2.2) - 2026-05-24

### Fixed

- update documentation ([#13](https://github.com/YpNo/imap-rs/pull/13))

## [0.2.1](https://github.com/YpNo/imap-rs/compare/imap-rs-client-v0.2.0...imap-rs-client-v0.2.1) - 2026-05-23

### Fixed

- clean up changelogs ([#12](https://github.com/YpNo/imap-rs/pull/12))

### Other

- release v0.2.0 ([#10](https://github.com/YpNo/imap-rs/pull/10))

## [0.2.0] - 2026-05-23

Initial release published to crates.io. `imap-rs-client` provides the async,
type-state IMAP session and command dispatcher, built on `imap-rs-core`.

### Added

- Type-state session: `Session<State, Transport>` enforcing
  `Unauthenticated → Authenticated → Selected` transitions, with `PlainText` /
  `Tls` transport markers. Invalid sequences fail to compile — e.g. `LOGIN` is
  gated to `Session<Unauthenticated, Tls>`.
- Commands: `LOGIN`, `AUTHENTICATE PLAIN` (SASL via `base64`), `LOGOUT`,
  `NOOP`, `CHECK`, `CAPABILITY`, `SELECT`, `EXAMINE`, `LIST`, `FETCH`
  (raw and structured `FetchResult`), `STORE` / `UID STORE`, `SEARCH` /
  `UID SEARCH`, `EXPUNGE`, `CLOSE`, `UNSELECT`, `IDLE`, and `MOVE`
  (feature-gated behind `move_ext`).
- `IDLE` (RFC 2177): proper `+ idling` continuation handshake; `IdleHandle::stop`
  writes `DONE` and awaits the tagged `OK` under its own timeout. Capability-gated.
- Pipelining dispatcher (`RawClient`): commands routed by tag; untagged frames
  broadcast on a 1024-slot `tokio::sync::broadcast` channel. Tagged `NO` / `BAD`
  responses become `ClientError::CommandFailed` carrying the server's resp-text.

### Security

- Credential hygiene: `Password` and `OAuthToken` are zeroized on drop
  (`zeroize`) and redacted in `Debug`. Quoted-string escaping follows RFC 9051;
  8-bit / control-byte secrets are rejected with a pointer to `AUTHENTICATE PLAIN`.
- Denial-of-service guard: the read loop bounds the in-flight frame buffer
  (`MAX_FRAME_SIZE`), surfaced as `ClientError::FrameTooLarge`, so a server
  streaming a never-terminating frame cannot exhaust memory.
- `#![forbid(unsafe_code)]`; 100% safe Rust.

[Unreleased]: https://github.com/YpNo/imap-rs/compare/imap-rs-client-v0.2.0...HEAD
[0.2.0]: https://github.com/YpNo/imap-rs/releases/tag/imap-rs-client-v0.2.0
