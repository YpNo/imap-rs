# Dependency & Architecture Review — 2026-11-06

**Scope.** Every direct dependency of the three published crates
(`imap-rs-core`, `imap-rs-client`, `imap-rs-tls`) plus the umbrella crate,
reviewed after consolidating Renovate PRs #20, #21, #22, #25 and #26 on
branch `chore/deps-consolidate-renovate`.

**Question asked.** Is each crate still relevant, and could it be replaced by
dedicated or simplified in-tree code with the same safety guarantees?

**Method.** `cargo tree` (features, inverted, build edges), `grep` of actual
API use per crate, `cargo info` for upstream versions and feature tables,
release notes for the one semver-breaking bump (base64 0.22 → 0.23), and a
scratch build of the recommended manifest changes to measure the effect.

---

## 1. Verdict per dependency

| Crate | Used by | Kind | Verdict | Why |
|---|---|---|---|---|
| `tokio` | client, tls | runtime | **Narrow** | `features = ["full"]` in a library forces every feature (fs, process, signal, …) on every consumer. Code uses only `rt`, `net`, `io-util`, `sync`, `time`, `macros`. |
| `rustls` | tls | runtime | **Fix features** | `features = ["ring"]` was added without `default-features = false`, so the default `aws_lc_rs` + `prefer-post-quantum` stay on. Result: `aws-lc-sys` (69 MB of C, built via `cmake`) is compiled into every build even though `connect_tls` explicitly installs `ring::default_provider()` and never uses it. This is the root cause of the "cmake / nasm / go" apt installs in CI. |
| `tokio-rustls` | tls | runtime | **Fix features** | Same issue: default `aws_lc_rs`. Needs `default-features = false, features = ["ring", "tls12", "logging"]`. |
| `tracing` | client, tls | runtime | **Remove** | Declared in both crates, used **zero** times (`grep -rn tracing` over `src/` → 0 hits). It only contributes `tracing-attributes` → `syn 2` to the build. |
| `bytes` | core | runtime | **Remove from core** | `imap-core` never uses it (the single match is the word "Bytes" in a comment). The parser is `&[u8]`-only by design (ADR-003). |
| `bytes` | client, tls | runtime | Keep | `BytesMut` + `AsyncReadExt::read_buf` (which is bounded on `bytes::BufMut`) drive both frame loops. It is already a hard dependency of `tokio/io-util`, so it is free. A `Vec<u8>` rewrite would add manual `drain(..n)` bookkeeping for no graph reduction. |
| `base64` | client | runtime | **Replace with in-tree encoder** | Production use is one call: encoding `\0user\0pass` for `AUTHENTICATE PLAIN` (≤ a few hundred bytes, once per login). `decode` is only used inside a unit test. The crate ships breaking 0.x bumps regularly (0.21 → 0.22 → 0.23), and 0.23 enables a new default feature literally named `simd-unsafe` — a poor default for a crate that advertises `#![forbid(unsafe_code)]`. A standard-alphabet, padded encoder is ~25 lines of pure safe Rust with an exhaustive RFC 4648 test vector table. For this PR the crate is pinned to `default-features = false, features = ["std"]` so the scalar engine is used. |
| `zeroize` | client | runtime | Keep crate, **drop `zeroize_derive`** | Only two newtypes derive `Zeroize, ZeroizeOnDrop`. A manual `impl Drop { self.0.zeroize() }` + `impl ZeroizeOnDrop` is 6 lines each and removes the proc-macro, which (together with `tracing`) is the last reason a second `syn` (2.x) is compiled next to `syn 3` pulled by `thiserror`/`tokio-macros`. `zeroize` itself stays: it is also required by `rustls` and `rustls-pki-types`, and `String::zeroize` must defeat the optimiser, which is exactly what you do not want to hand-roll. |
| `thiserror` | all | runtime | Keep | Project rule (CLAUDE.md), 17 `#[error]` variants across three crates. Hand-written `Display`/`Error` impls would be ~120 lines of boilerplate for no safety gain. Pulls `syn 3`, which `tokio-macros` needs anyway. |
| `rustls-pki-types` | tls | runtime | Keep | Needed for `ServerName`. Already a transitive dep of rustls; direct declaration is correct to avoid re-exporting through `rustls::pki_types` paths. |
| `webpki-roots` | tls | runtime | Keep | Mozilla root store, pure data. The alternative (`rustls-platform-verifier`) adds OS-specific FFI on macOS/Windows, contradicting ADR-001. |
| `criterion` | core | dev | Keep (note) | Bench-only. It is the heaviest dev dependency (brings `regex`, `serde_json`, `plotters`, `rayon` … 58 crates with dev edges vs 16 without). Acceptable because it never ships; `divan` is a lighter drop-in if bench build time ever matters. |
| `trybuild` | client | dev | Keep | It *is* the compile-time type-state test (ADR-002). No substitute. |
| `rcgen` | tls | dev | Keep | Generates throwaway certs for STARTTLS tests. Its 0.14 default features are `crypto, pem, ring` — already aws-lc-free. |
| `libfuzzer-sys` | core/fuzz | fuzz | Keep | Separate workspace, nightly-only; standard `cargo-fuzz` harness. |

Inter-crate edges: `imap-tls → imap-core` is legitimate (it parses the
greeting and the `STARTTLS` tagged reply before handing the stream to the
client); `imap-tls → imap-client` for `Session`/`ClientError`. No cycles, no
layering violation.

## 2. Measured impact of the recommended manifest changes

Scratch build of the branch with: `tracing` removed, `bytes` removed from
core, `tokio` narrowed, `rustls` and `tokio-rustls` with
`default-features = false` and `ring` (`tokio` with `rt-multi-thread` + `macros` added as a dev-dependency of
`imap-client` and `imap-tls`, because the trybuild fixtures and the example
use `#[tokio::main]`). No source change required.

| Metric | Before (this branch) | After | Δ |
|---|---|---|---|
| Crates, normal edges | 59 | 44 | −15 |
| Crates, normal + build edges | 68 | 47 | −21 |
| `aws-lc-rs` / `aws-lc-sys` / `cmake` in graph | yes | no | removed |
| `cargo check --all-targets --all-features` | ok | ok | — |
| Test suite (158 tests) | ok | ok (158 passed, `--no-fail-fast`) | — |

Replacing `base64` and `zeroize_derive` on top of that (source changes) is
estimated to remove a further 3 crates (`base64`, `zeroize_derive`, `syn 2`)
and leave a single `syn` version in the build.

The remaining C in the graph is `ring`'s vendored BoringSSL primitives
(built with `cc`, no system library, no `cmake`). That is the accepted
trade-off behind ADR-001; `aws-lc-rs` is not.

## 3. CI / toolchain findings

1. **`apt-get install … cmake nasm golang-go chromium-browser` in three jobs**
   (`test`, `coverage`, `doc`). The comment says "for boring-sys"; nothing in
   this workspace depends on BoringSSL or a browser. This is copied from the
   `rs-cloudscraper` project. Once `aws-lc-sys` is gone it is pure cost
   (package index refresh + ~300 MB of packages per job). Remove.
2. **`cargo-tarpaulin` is installed from the GitHub `releases/latest` URL.**
   A moving tag in a pipeline, and the download is `curl | tar` with no
   checksum. Pin a version (and ideally use `taiki-e/install-action`, which
   is digest-pinned like the other actions).
3. **MSRV is declared (`rust-version = 1.95.0`) but never exercised.** CI
   and `rust-toolchain.toml` now both run 1.99.1. Either add an
   `msrv` job (`cargo +1.95.0 check --workspace --all-features`) or admit
   the real MSRV and bump `rust-version`. CLAUDE.md still says
   "MSRV 1.95.0 (pinned for consistent trybuild diagnostics)" — the
   diagnostics are now pinned to 1.99.1, update the sentence.
4. **The toolchain version is hard-coded in eight places** across two
   workflows, separate from `rust-toolchain.toml`; Renovate has to touch all
   of them and they drifted before (1.95.0 file vs 1.96.0 CI). Drop the
   `toolchain:` input and let the action read `rust-toolchain.toml`
   (`actions-rust-lang/setup-rust-toolchain` does; `dtolnay/rust-toolchain`
   can be pointed at the file via a `uses: …@` ref that matches the channel).
5. **`ci.yml` triggers only on `pull_request` and a weekly cron**, not on
   `push` to `main`. A direct push or a squash-merge rebase conflict lands
   untested; `release-plz` then releases from it. Add `push: branches: [main]`.
6. **`deny.toml` bans `openssl` and `native-tls` but not `aws-lc-rs`/`aws-lc-sys`.**
   Add them to `[bans].deny` once removed so ADR-001 is enforced, not just
   documented.
7. **`renovate.json` groups base64 0.22 → 0.23 under "cargo non-major".**
   For 0.x crates Cargo treats the minor as the major; a `matchCurrentVersion:
   "/^0\\./"` rule that opts 0.x minors out of the non-major group would have
   surfaced this bump (and its new unsafe default) as its own PR.
8. Nits: `sonar.projectVersion=0.2.0` is stale (crate is 0.2.4);
   `tokio-rustls` and `rustls` are listed separately in the Renovate
   "tokio + rustls stack" group but `rustls-webpki` is not.

## 4. Recommended sequencing

| PR | Content | Risk |
|---|---|---|
| this one | Renovate consolidation (done) | none beyond upstream patch releases |
| `chore/deps-slim` | §2 manifest-only changes + deny.toml ban + CI apt cleanup | low: verified by scratch build; no public API change |
| `refactor/no-base64-no-derive` | in-tree base64 encoder, manual `Zeroize` impls | low: 2 files, covered by existing SASL and credential tests + new vector table |
| `ci/msrv-and-pins` | MSRV job, tarpaulin pin, `push` trigger, single toolchain source | low |

Nothing here changes the public API; all of it can ship in 0.2.x patch
releases.
