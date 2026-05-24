# Changelog

All notable changes to this crate are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.2](https://github.com/YpNo/imap-rs/compare/imap-rs-core-v0.2.1...imap-rs-core-v0.2.2) - 2026-05-24

### Fixed

- update documentation ([#13](https://github.com/YpNo/imap-rs/pull/13))

## [0.2.1](https://github.com/YpNo/imap-rs/compare/imap-rs-core-v0.2.0...imap-rs-core-v0.2.1) - 2026-05-23

### Fixed

- clean up changelogs ([#12](https://github.com/YpNo/imap-rs/pull/12))

### Other

- release v0.2.0 ([#10](https://github.com/YpNo/imap-rs/pull/10))

## [0.2.0] - 2026-05-23

Initial release published to crates.io. `imap-rs-core` provides the protocol
types and parser shared by the workspace; it performs no I/O.

### Added

- Zero-copy, hand-rolled recursive-descent parser for IMAP4rev2 (RFC 9051),
  operating directly on `&[u8]` with no external parser dependency.
  - Status responses (`OK`, `NO`, `BAD`, `PREAUTH`, `BYE`) with full
    resp-text-code coverage (`ALERT`, `BADCHARSET`, `CAPABILITY`, `PARSE`,
    `PERMANENTFLAGS`, `READ-ONLY`, `READ-WRITE`, `TRYCREATE`, `UIDNEXT`,
    `UIDVALIDITY`, `UNSEEN`, and generic `Other`).
  - Data responses (`CAPABILITY`, `LIST`, `LSUB`, `STATUS`, `SEARCH`,
    `FLAGS`, `EXISTS`, `RECENT`, `EXPUNGE`, `FETCH`).
  - `FETCH` attributes (`FLAGS`, `INTERNALDATE`, `RFC822[.SIZE|.HEADER|.TEXT]`,
    `ENVELOPE`, `BODY`, `BODYSTRUCTURE`, `BODY[<section>]<<origin>>`, `UID`).
- Protocol AST types covering the response grammar above.
- Fuzz target for `parse_response` with a seeded corpus of diverse inputs.

### Security

- Denial-of-service guard: `MAX_LITERAL_SIZE` (64 MiB) caps any single literal,
  surfaced as `ParseError::LiteralTooLarge` **before** allocation.
- Bounds-checked slicing throughout the parser; malformed input is reported as
  `ParseError`, never a panic.
- `#![forbid(unsafe_code)]`; 100% safe Rust with no FFI dependencies.

[Unreleased]: https://github.com/YpNo/imap-rs/compare/imap-rs-core-v0.2.0...HEAD
[0.2.0]: https://github.com/YpNo/imap-rs/releases/tag/imap-rs-core-v0.2.0
