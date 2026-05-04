# imap-core fuzz harness

`cargo-fuzz` target for [`imap_core::parser::parse_response`].

## Layout

```
fuzz/
├── Cargo.toml
├── fuzz_targets/
│   └── parse_response.rs
├── seeds/                # tracked: hand-curated seed inputs
│   └── parse_response/
└── corpus/               # gitignored: runtime fuzzer output
    └── parse_response/
```

`seeds/parse_response/` holds 44 hand-curated inputs covering every
parser branch (status responses, response codes, all `DataResponse`
variants, every `FETCH` attribute including literals and sections,
continuation requests, plus incomplete and malformed buffers). The
top-level `.gitattributes` marks the directory `binary` so git does
not normalise the embedded `CR/LF` bytes.

`corpus/parse_response/` is what `cargo fuzz run` reads from and
writes minimised mutations into. It is `.gitignored` to keep the repo
small.

## Running

```bash
# 1. Seed the corpus from the tracked inputs (one-time per checkout).
mkdir -p imap-core/fuzz/corpus/parse_response
cp imap-core/fuzz/seeds/parse_response/* imap-core/fuzz/corpus/parse_response/

# 2. Run the fuzzer (requires a nightly toolchain + cargo-fuzz).
cargo install cargo-fuzz
cargo +nightly fuzz run parse_response --manifest-path imap-core/fuzz/Cargo.toml
```

The CI `fuzz-build` job runs `cargo check` against this manifest on
stable Rust to catch parser API drift; full fuzzing still needs
nightly + sanitizers locally.

## Adding a new seed

1. Drop a file under `seeds/parse_response/` with a short descriptive
   name (no extension; the file IS the input). Use `printf '%b'` or
   write raw bytes — escape sequences inside the seed are NOT
   processed by the fuzzer.
2. Run the steps above to copy it into the active corpus.
3. Commit the new seed; corpus output stays untracked.

## Reporting a crash

If the fuzzer finds a panic, the input is saved under
`fuzz/artifacts/parse_response/<sha256>`. Do **not** commit the
artifact directly — minimise it (`cargo +nightly fuzz tmin`), then
add the minimised input as a new seed plus a regression test in
`imap-core/src/parser.rs::tests` so it's locked in even without a
fuzzer run.
