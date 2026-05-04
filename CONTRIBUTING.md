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

## Commits and Changelog

- **Conventional Commits**: every commit subject MUST follow
  [Conventional Commits 1.0](https://www.conventionalcommits.org/en/v1.0.0/).
  The `type(scope): summary` form makes Renovate's semantic grouping
  and any future `release-please` automation possible.
  - Common types in this repo: `feat`, `fix`, `chore`, `ci`, `docs`,
    `refactor`, `test`, `perf`, `security`.
  - Common scopes: `imap-core`, `imap-client`, `imap-tls`, omitted for
    repo-wide changes.
  - Example: `feat(imap-client): add AUTHENTICATE PLAIN`.
- **Changelog**: every user-visible change appends an entry under
  `[Unreleased]` in `CHANGELOG.md` with the appropriate
  Added/Changed/Fixed/Security heading. The release workflow promotes
  `[Unreleased]` to a versioned section on tag.

## Security

- Never commit sensitive data (API keys, credentials).
- Use the `zeroize` crate for any credential handling.
- Refer to `SECURITY.md` for vulnerability disclosures.

## Governance

This project is maintained by at least two codeowners per module to ensure sustainability.
