# imap-rs-client

Async IMAP session state machine and client logic for the
[`imap-rs`](https://github.com/YpNo/imap-rs) library.

This is the **client** layer of the hexagonal `imap-rs` workspace. It owns the
type-state session machine, command pipelining, capability negotiation, and
credential handling. It builds on [`imap-rs-core`](https://crates.io/crates/imap-rs-core)
and is transport-agnostic — bring your own `AsyncRead + AsyncWrite` stream.

## Features

- **Type-state sessions**: invalid protocol transitions (e.g. `LOGIN` over
  plaintext, `FETCH` before authentication) fail to compile.
- **Credential hygiene**: secrets are wrapped and zeroized on drop via `zeroize`.
- **Async-native**: built on `tokio`.

### Cargo features

| Feature | Default | Description |
|---|---|---|
| `move_ext` | off | RFC 6851 `MOVE` extension (`Session::move_messages`). |

## Usage

```toml
[dependencies]
imap-rs-client = "0.2"
```

> Most users should depend on the umbrella [`imap-rs`](https://crates.io/crates/imap-rs)
> crate, which re-exports this crate as `imap_rs::client`. For a ready-made secure
> transport, see [`imap-rs-tls`](https://crates.io/crates/imap-rs-tls).

## License

MIT
