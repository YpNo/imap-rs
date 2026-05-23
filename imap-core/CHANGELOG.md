# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.0](https://github.com/YpNo/imap-rs/releases/tag/imap-rs-core-v0.2.0) - 2026-05-23

### Added

- *(imap-core)* RFC 9051 recursive-descent parser
- feat/init

### Fixed

- *(imap-core/fuzz)* split tracked seeds from runtime corpus output
- fixing CI

### Other

- Prepare the crate release ([#5](https://github.com/YpNo/imap-rs/pull/5))
- *(imap-core/fuzz)* seed parse_response corpus with 44 diverse inputs
- *(imap-client,imap-core)* drop unimplemented feature flags; refresh benches
- Enhancement
- Code coverage enhancement
