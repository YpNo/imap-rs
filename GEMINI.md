# Project: imap-rs

## Context

- **Purpose**: A high-security, async-native IMAP library for the Rust ecosystem.
- **Type**: Workspace (Crates: `imap-core`, `imap-client`, `imap-tls`)
- **Domain**: Email Protocol (IMAP4rev1/rev2)
- **Primary adapters (inbound)**: Library API (`Session<State, Transport>`)
- **Driven adapters (outbound)**: TCP Sockets, `rustls` (via `tokio-rustls`)
- **MSRV**: 1.95.0 (pinned for consistent `trybuild` diagnostics)
- **Async runtime**: tokio

---

## Hexagonal Architecture Map

```
┌─────────────────────────────────────────────────────────────┐
│                    DRIVING ADAPTERS                         │
│  [User Application]  [Arlo Streamer]  [Mail Proxy]          │
└───────────────────────────┬─────────────────────────────────┘
                            │ calls Session API
┌───────────────────────────▼─────────────────────────────────┐
│                 CLIENT LAYER (imap-client)                  │
│  session.rs: Managed state machine and command execution    │
│  client.rs: Raw I/O dispatcher and event broadcasting       │
└───────────────────────────┬─────────────────────────────────┘
                            │ calls parser / transport
┌───────────────────────────▼─────────────────────────────────┐
│                   CORE (imap-core)                          │
│  ast.rs: Protocol types | parser.rs: Zero-copy parser       │
│  ⚠ ZERO I/O or network dependencies                        │
└───────────────────────────┬─────────────────────────────────┘
                            │ uses
┌───────────────────────────▼─────────────────────────────────┐
│                  INFRASTRUCTURE (imap-tls)                  │
│  lib.rs: rustls-based secure transport establishment        │
└─────────────────────────────────────────────────────────────┘
```

### Bounded Contexts / Crates in this project
- `imap-core`: Owns the protocol AST and the recursive-descent parser.
- `imap-client`: Owns the session state machine, credential management, and async I/O loops.
- `imap-tls`: Owns the secure handshake logic and certificate validation.

---

## Architecture Decision Records

- **ADR-001**: **No-FFI TLS** — Using `rustls` exclusively to avoid vulnerabilities associated with C-based TLS libraries (OpenSSL).
- **ADR-002**: **Type-State Sessions** — Using the Rust type system to enforce valid protocol transitions (e.g., no LOGIN over PlainText).
- **ADR-003**: **Zero-Copy Parsing** — The parser uses `&[u8]` references into the network buffer to minimize allocations.

---

## Project-Specific Rules

### Forbidden in this project
- [ ] `unwrap()` / `expect()` anywhere except tests (use `Result` and `thiserror`)
- [ ] C-based FFI dependencies (prefer pure-Rust crates)
- [ ] Manual memory management or `unsafe` blocks
- [ ] Committing sensitive test data (use mocks or dynamically generated creds)

### Naming Conventions
- Session states: `PascalCase` adjectives (`Unauthenticated`, `Authenticated`, `Selected`)
- Error types: `<Crate>Error` at crate root
- IMAP Flags: `Flag::PascalCase`

### Module Visibility Rules
- AST types: `pub` (central to all logic)
- Internal parsers: `pub(crate)`
- Session internals: Private, exposed only via the `Session` public API

---

## Local Development

```bash

# Run all tests (stable 1.95.0)
cargo test --workspace --all-features

# Run coverage (requires cargo-tarpaulin)
cargo tarpaulin --all-features --workspace --timeout 120 --out xml

# Update UI test expectations (after toolchain changes)
TRYBUILD=overwrite cargo test -p imap-client --test type_state_tests

# Run Lint checks
cargo clippy --workspace -- -D warnings

# Check style
cargo fmt --check 
# Check for vulnerabilities
cargo audit
# Check licenses + duplicates
cargo deny check
```

---

## Environment Variables

| Variable | Type | Default | Description |
|---|---|---|---|
| `IMAP_DEBUG_LOG` | `bool` | `false` | Enables low-level packet tracing |
| `TRYBUILD` | `string` | — | Set to `overwrite` to bless UI test diagnostics |

---

## Common Tasks

### Adding a new IMAP Extension
1. Define the extension feature in `imap-client/Cargo.toml`.
2. Add necessary types to `imap-core/src/ast.rs`.
3. Update `imap-core/src/parser.rs` to recognize the extension's untagged responses.
4. Implement the logic in `imap-client/src/session.rs` guarded by the feature flag.
5. Add unit tests in a `mod tests` block using `tokio::io::duplex`.

### Improving Parser Coverage
1. Identify missing branches in `parser.rs` via the Tarpaulin report.
2. Add targeted byte-stream tests to `test_parse_response` variants.
3. Ensure both success and all possible failure paths (Incomplete, Malformed, Invalid UTF-8) are covered.
