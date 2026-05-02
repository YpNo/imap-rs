# Contributing to imap-rs

Thank you for your interest in contributing! To maintain the high quality and security standards of this library, we follow a strict set of rules.

## The Three Non-Negotiable Rules

1. **A new dependency requires a written RFC in the PR** explaining why no existing dependency or standard library alternative works.
2. **Any parse panic = blocked merge**, no exceptions. Fuzzing in CI must pass.
3. **One approval (for now) is required on any public API change.**

## Development Workflow

- **Edition 2024**: All code must use Edition 2024 semantics.
- **Zero-Warning Policy**: All code must pass `cargo clippy` and `cargo fmt` without warnings.
- **Hexagonal Integrity**: Keep the protocol logic (`imap-core`) separate from IO and transport.
- **Instrumentation**: Prefer `tracing` over `log`.

## Security

- Never commit sensitive data (API keys, credentials).
- Use the `zeroize` crate for any credential handling.
- Refer to `SECURITY.md` for vulnerability disclosures.

## Governance

This project is maintained by at least two codeowners per module to ensure sustainability.
