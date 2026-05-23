# imap-rs-core

Zero-copy IMAP4rev2 protocol types and parser for the [`imap-rs`](https://github.com/YpNo/imap-rs) library.

This is the **core** layer of the hexagonal `imap-rs` workspace: it owns the
protocol AST and a hand-rolled recursive-descent parser. It performs **no I/O**
and has no network dependencies, which keeps it trivially testable and reusable.

## Features

- Zero-copy parsing — borrows `&[u8]` slices from the network buffer to avoid allocations.
- Typed protocol AST covering IMAP4rev2 (RFC 9051) responses.
- Explicit error handling via `thiserror` (`Incomplete`, `Malformed`, invalid UTF-8).

## Usage

```toml
[dependencies]
imap-rs-core = "0.2"
```

```rust
use imap_core::parser::parse_response;

let input = b"* OK IMAP4rev2 Service Ready\r\n";
let (_rest, response) = parse_response(input).expect("valid greeting");
```

> Most users should depend on the umbrella [`imap-rs`](https://crates.io/crates/imap-rs)
> crate, which re-exports this crate as `imap_rs::core`.

## License

MIT
