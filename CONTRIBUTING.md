# Contributing to stamp-suite

Discuss large changes in an issue first. Report security problems privately;
see [SECURITY.md](SECURITY.md).

## Build

Rust 1.87 or newer is required (`rust-version` in `Cargo.toml`).

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

After changing documentation or linked evidence, run:

```sh
python3 scripts/check_doc_links.py
python3 scripts/check_conformance_counts.py
python3 scripts/check_conformance_citations.py --require-test-evidence
```

`check_doc_links.py` works offline. It reads every Markdown file Git can see,
including untracked files that are not ignored, and checks local paths, heading
fragments and HTML anchors in inline links, reference links and images. It
skips code blocks and comments, reports fragments into non-Markdown files as
unverified, and does not fetch external URLs. An untracked file passes locally
but is missing from a clean CI checkout, so commit linked evidence with the
change that links to it.

A missing relative target is an error, with no exemption for generated or
historical files. Link release-only assets by their release URL, and write
generated local paths as code. The check proves that a link resolves, not that
the linked claim is true.

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

Format with stable `cargo fmt --all` and check with
`cargo fmt --all -- --check`, as CI does. `.rustfmt.toml` sets
`imports_granularity = "Crate"` and `group_imports = "StdExternalCrate"`, but
both options need nightly rustfmt and stable rustfmt ignores them. The tree is
not formatted with them, so do not run `cargo +nightly fmt`: it would rewrite
imports across much of the tree.

CI also runs `cargo doc --no-deps --all-features` with `RUSTDOCFLAGS=-D warnings`,
`cargo check --all-features --all-targets` on the 1.87 toolchain,
`cargo deny check` for advisories, bans, licenses and sources, the RustSec
audit, and CodeQL for the Rust, Python and workflow code (`codeql.yml`).

## Conformance tooling

The [conformance matrices](doc/conformance/README.md) record evidence for each
RFC and draft clause. Two scripts check them. CI (`conformance.yml`) runs:

```sh
python3 scripts/check_conformance_counts.py --json
python3 scripts/check_conformance_citations.py --require-test-evidence --json --details
```

`check_conformance_counts.py` checks that each matrix's summary line and the
totals in `doc/conformance/README.md` match its clause rows.
`check_conformance_citations.py` checks that every cited file, item and line
range still exists. With `--require-test-evidence` it also fails on a
normative Compliant row without a test reference; without the flag it only
reports such rows. Run both after renaming or moving code that a matrix cites,
and after changing a clause row.

Cite a named test or a dedicated test suite, and cite a Python wire driver as
`Wire test:` followed by its qualified function name. A helper or data file
alone is not test evidence. The script only checks that the reference exists:
review separately that the test runs, asserts the right thing and exercises the
production path. See [test-evidence policy](doc/conformance/test-evidence.md).

`scripts/check_standards.py` compares the frozen RFC and draft revisions with
the published ones; see
[standards revision monitor](doc/releasing.md#standards-revision-monitor).
[doc/releasing.md](doc/releasing.md) describes the other release checks.

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

## Code provenance

stamp-suite is MIT-licensed. Contribute only code you wrote or code under a
license compatible with MIT, and say where any third-party code comes from.

Other STAMP and TWAMP implementations, such as Teaparty (GPL-3.0), are used
only as black-box interoperability peers. Do not copy or translate their
source, tests or comments into this repository, whether by hand or with a
code-generation tool. Work from the RFCs and drafts, and use packet captures
or recorded exchanges with those implementations only as test data.

When changing dependencies or release feature profiles, validate the locked
runtime graphs and their legal inputs (Python 3.9+ and Cargo are required):

```sh
python3 scripts/third_party_notices.py --validate-release-profiles
```

The notice bundle is generated during packaging and is not in Git or the
crates.io source package. For an `OR` license the generator picks one of the
offered licenses; it keeps every license an `AND` requires, keeps extra
attribution, and lists shared license texts once. Missing license text and
changes to `scripts/licenses/notice-policy.json` need review; do not replace
missing attribution with a license identifier. Keep `RELEASE_PROFILES` in the
generator aligned with the release workflow's targets and features. See [release procedures](doc/releasing.md#third-party-notices)
for distribution checks.
