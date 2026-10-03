# Contributing to stamp-suite

This guide is for people who change stamp-suite: how to build it, run the
tests and linters that CI runs, and what a change should include.

Open an issue before starting a large change, so the approach can be agreed
first. Report security problems privately as described in
[SECURITY.md](SECURITY.md).

## Build

Rust 1.85 or newer is required (`rust-version` in `Cargo.toml`).

```sh
cargo build                     # debug build, default features
cargo build --release --all-features
cargo check --all-targets       # type-check tests, benches and examples too
```

The receiver backend is chosen at compile time. Linux and macOS use the nix
UDP socket backend by default; Windows uses pnet capture. `ttl-pnet` selects
pnet on Linux, unless `ttl-nix` is also enabled, so `--all-features` builds the
nix backend. The [architecture guide](doc/architecture.md#module-structure)
describes the modules.

With Nix, `nix develop` opens a shell with the toolchain and `nix build`
builds the package with all features.

## Tests

Run the full unprivileged suite with all features:

```sh
cargo test --all-features
```

Run one test or one integration target:

```sh
cargo test --all-features <test_name>
cargo test --all-features --test loopback_test
cargo test --locked --lib tlv::list     # TLV unit and property tests
```

CI also runs the suite without features and with the pnet backend. Run these
when a change touches backend code, feature gates or `cfg` attributes:

```sh
cargo test --locked
cargo test --locked --no-default-features --features ttl-pnet
```

Other test entry points:

- `cargo test --locked --example live_udp_bench` checks the live benchmark's
  reply accounting. [doc/benchmarks.md](doc/benchmarks.md) explains the
  benchmarks themselves.
- `python3 -m unittest discover -s scripts/tests -v` runs the tests of the
  Python evidence scripts.
- `python3 scripts/interop_stamp.py --binary target/debug/stamp-suite` runs the
  independent wire fixtures against a built binary. See
  [doc/testing-interop.md](doc/testing-interop.md).
- The fuzz targets live in `fuzz/` and need a nightly compiler. See
  [fuzz/README.md](fuzz/README.md).

### Privileged and namespace tests

Some tests need root, `CAP_NET_RAW` or network namespaces. They are marked
`#[ignore]` or gated by an environment variable, so `cargo test` skips them.
[tests/README.md](tests/README.md#tests-that-need-privileges-or-namespaces)
lists them with the command for each one, and
[doc/testing-netns.md](doc/testing-netns.md) covers the namespace conformance
tier. Build as your normal user and give privileges only to the test binary
you run; `scripts/run_privileged_test.py` does this.

## Lint and format

CI runs clippy in three configurations and treats warnings as errors:

```sh
cargo clippy --locked --all-targets -- -D warnings
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo clippy --locked --no-default-features --features ttl-pnet --all-targets -- -D warnings
```

The third command is the only one that compiles the pnet receiver on Linux.

Format with `cargo fmt --all` and check with `cargo fmt --all -- --check`.
`.rustfmt.toml` sets `imports_granularity = "Crate"` and
`group_imports = "StdExternalCrate"`. Both options require nightly rustfmt.
Stable rustfmt, which CI uses, prints a warning and ignores them. Group imports
by hand in that style (standard library, external crates, then `crate::`).

CI also runs `cargo doc --no-deps --all-features` with `RUSTDOCFLAGS=-D warnings`,
`cargo check --all-features --all-targets` on the 1.85 toolchain, and
`cargo deny check` for advisories, licenses and sources.

## Conformance tooling

The [conformance matrices](doc/conformance/README.md) record evidence for each
RFC and draft clause. Two scripts check them, and CI runs both:

```sh
python3 scripts/check_conformance_counts.py --json
python3 scripts/check_conformance_citations.py --json --details
```

`check_conformance_counts.py` checks that each matrix's summary and the
README totals match its clause rows. `check_conformance_citations.py` checks
that every cited file, item and line range still exists in the source. Run
both after renaming or moving code that a matrix cites, and after changing a
clause row.

`scripts/check_standards.py` compares the frozen RFC and draft revisions with
the published ones. [doc/release-evidence.md](doc/release-evidence.md)
describes it and the other release checks.

## Man page

`dist/man/stamp-suite.1` is generated from the clap definitions and committed.
`tests/man_page.rs` fails on Linux when the two differ. After changing
an option, its help text or its default, regenerate the page and commit it:

```sh
STAMP_UPDATE_MAN=1 cargo test --all-features --test man_page
```

## What a change should include

- **Tests.** A bug fix includes a test that fails without the fix. A new
  option or behavior includes tests for it, including its error cases.
- **A CHANGELOG entry** under `## [Unreleased]` in [CHANGELOG.md](CHANGELOG.md)
  for any change a user, packager or peer implementation could notice.
- **Formatting and lint.** Run `cargo fmt --all` and the clippy commands above.
- **Documentation.** Update the document that owns the topic (see the index
  in [README.md](README.md#documentation)) and the man page when the CLI
  changes.
- **Conformance rows.** When a change affects a cited clause, update the
  matrix row and rerun both conformance scripts.

Changes to experimental codepoints follow the policy in
[doc/conformance/README.md](doc/conformance/README.md#experimental-codepoints).
