# Release verification

Release checks, reproduction commands and recorded results.

Record the tested revision, features, platform and wire profile with each
result. The [conformance matrices](conformance/README.md) cover the frozen
specifications. Compiling a test, or listing it as ignored, does not establish
runtime behavior.

## Release gate boundary

The tag workflow calls `rust.yml` and `conformance.yml` as reusable workflows.
Publication waits for both and for the source, Linux, macOS and Windows package jobs.
This runs backend, native-platform, MSRV, evidence and privileged checks on the
tagged commit. Platform exclusions still apply; required driver-free Windows
tests do not establish driver-backed capture behavior.

Cargo builds in the release jobs and container enforce the lockfile. Debian
builds are offline: extract the release vendor archive into `vendor/` beside
`Cargo.toml` before invoking `debian/rules`. The build fails if that input is
missing, and cleaning preserves it. For a development source tree, prepare
that input separately with `cargo vendor --locked vendor`.

The OpenWrt recipe in `dist/openwrt/Makefile` is a template that refuses to
build with an unset hash. The source job hashes its exact deterministic
`stamp-suite-VERSION.tar.gz` and publishes a completed
`stamp-suite-VERSION-openwrt.mk`, included in checksums and attestations. Use
that asset as the feed's `Makefile`. To render it locally from the same archive:

```sh
python3 scripts/render_openwrt.py --archive stamp-suite-1.0.0.tar.gz --output Makefile
```

An unpublished or unavailable archive cannot supply a verified digest. The
recipe generation step avoids bypassing that check with `PKG_HASH:=skip`.

## Third-party notices

`THIRD_PARTY_NOTICES.txt` is generated during packaging for that build's target
and feature set. It is excluded from Git and source-only archives. The generator
follows normal dependency edges and excludes development/build dependencies,
procedural macros and their host-only dependencies. It selects one offered
license for `OR` expressions and preserves mandatory `AND` requirements. Complete
license terms are shared across crates; copyright and additional attribution
remain associated with each crate. This is a runtime dependency inventory, not
an analysis of which functions survive linker optimization. System libraries
and separately installed drivers are outside its scope.

CI and release preflight validate all release profiles. After changing a
dependency or release profile, run:

```sh
python3 scripts/third_party_notices.py --validate-release-profiles
```

Add `--offline` when all locked dependencies are already fetched. Generate the
bundle before calling a packager, then verify the resulting archives:

```sh
python3 scripts/third_party_notices.py --target x86_64-unknown-linux-gnu
python3 scripts/check_packaged_notices.py 'target/x86_64-unknown-linux-gnu/debian/*.deb' 'target/x86_64-unknown-linux-gnu/generate-rpm/*.rpm' 'stamp-suite-*.tar.gz'
```

The archive check compares the embedded text byte for byte with the generated
bundle, allowing gzip compression by packagers. It fails on missing archives,
missing notices or altered text. RPM inspection requires `rpm2cpio`; DEB
inspection requires `dpkg-deb`. Tar and ZIP inspection use Python's standard
library. These checks run before release artifacts are uploaded.

Debian, RPM, Gentoo, OpenWrt, Nix and container recipes install the bundle under
`/usr/share/doc/stamp-suite/` (or the platform's documentation prefix). Source
archives retain the generator and reviewed policy; vendor archives preserve
upstream files.
There is no combined bundle to commit. Pass `--features` with the exact build
features for a custom build (`all` selects all features); without it, the generator
uses that target's release profile. `--check` compares an existing generated
bundle against the same target and features.
For custom builds that disable defaults, also pass `--no-default-features`.
Offline generation requires the locked metadata dependencies to be fetched or
vendored, including those needed by Cargo to resolve development targets.

The supplemental Apache-2.0 text in `scripts/licenses/Apache-2.0.txt` comes from
the [Apache Software Foundation](https://www.apache.org/licenses/LICENSE-2.0.txt).
It supplies complete terms for included components whose source header refers to
them. Package-specific rules in `scripts/licenses/notice-policy.json` pin reviewed
versions and input hashes. They cover nested Unicode/third-party notices and
`ring`'s architecture-selected native sources, exclude BoringSSL's explicitly
unlinked test/CI licenses, and include the Prometheus schema only if `protobuf`
is enabled. Updates to those inputs fail validation until the policy is reviewed.

## Procedures

### Authenticated control and a reference SNMP master

On Linux with Python 3.10+, OpenSSL and the Net-SNMP tools (`snmpd`,
`snmpget`, `snmpgetnext`, `snmpwalk`, `snmpbulkget`):

```sh
cargo build --locked --all-features
python3 scripts/release_checks.py --binary target/debug/stamp-suite --report /tmp/release-integration.json
```

The script runs four control cases (IPv4 and IPv6, each over HTTP and HTTPS)
and one reference SNMP case. `--only control` or `--only snmp` selects a subset,
which is recorded in `expected_cases`. Every selected case must pass, and a
missing tool is an error. The report keeps commands, logs, HTTP responses, UDP
payloads, Net-SNMP queries, binary and runner hashes, counts and completion
state. Keys, tokens and communities are temporary fixture values, never
production credentials.

The control cases use the real binary and HTTP server, a mode-0600 token file,
and independently encoded and authenticated UDP traffic. They check that:

- A missing or wrong bearer token cannot read status or change keys.
- Replacing a key over HTTP during a burst affects new requests, while queued
  copies that were already accepted keep the old key and valid signatures
  after an SRv6 U-flag fallback. Their software T3 must be later than the
  rotation acknowledgment, so copies sent before it cannot satisfy the check.
- The old key is rejected, the new key works without resetting session
  sequencing, deletion revokes access, and adding or removing the default key
  affects both an existing SSID and a new one.
- The key inventory omits secret bytes, and an authenticated shutdown exits
  cleanly.

The HTTPS cases generate a temporary self-signed certificate with an IP SAN.
The client trusts that certificate explicitly and performs normal certificate
and endpoint validation. This tests the TLS server and bearer authentication,
not mTLS or an external CA.

The SNMP case starts its own `snmpd` in the foreground on an ephemeral IPv4
loopback port, with a private AgentX socket and persistence directory. Its
read-only community is limited to the STAMP enterprise subtree. It does not
read the system daemon configuration or touch an existing service. The real
stamp-suite sub-agent registers with that master. Independent Net-SNMP clients
check initial and live counters, two session rows across seven columns,
GetBulk non-repeater and repeater order, and the end-of-MIB boundary. The case
then stops its own master, confirms that authenticated STAMP still reflects,
restarts the master, and checks that the sub-agent registers again with
counters and session state intact.

Master configuration follows the Net-SNMP
[AgentX guide](https://www.net-snmp.org/docs/README.agentx.html) and
[snmpd options](https://www.net-snmp.org/docs/man/snmpd.html). This complements
the independent AgentX framing tests described under
[SNMP AgentX sub-agent](architecture.md#snmp-agentx-sub-agent). It does not
certify every SNMP version, context, byte order or writable MIB. Record both
the Net-SNMP package version and the version string the daemon reports.

The `release-integration` job in `conformance.yml` runs all five cases on
Ubuntu. It downloads and extracts the Net-SNMP packages into `/tmp` without
installing them or starting a system service. Locally installed tools also
work.

### macOS runtime gate

`rust.yml` runs native macOS jobs for the default and all-features profiles.
Each calls `scripts/run_native_tests.py --expected-platform darwin` and uploads
its JSON report and raw Cargo log, even after a failure. The report keeps
platform and toolchain identity, commit and patch hash, command, exit status,
logs, and executed and ignored counts. A platform mismatch, missing or empty
test summaries, filtered tests, or a Cargo failure fail the gate.

On a local Mac, run each profile explicitly:

```sh
python3 scripts/run_native_tests.py --expected-platform darwin --profile default --report native-macos-default.json
python3 scripts/run_native_tests.py --expected-platform darwin --profile all-features --report native-macos-all-features.json
```

This covers native socket builds. Pnet capture, Intel Mac runtime and physical
NIC timestamps need separate evidence. Tests excluded by platform are not
counted as executed.

### Windows runtime gate

`rust.yml` requires the library unit tests and eight integration test targets
on Windows: configuration files, malformed input, TLV properties, mixed clocks,
required Micro-session validation, SSID validation, sender measurement
summaries and startup error reporting. These exercise codecs, the transmit
scheduler and UDP sender peers without starting the pnet capture receiver.
Scheduler tests inject a known MTU; a separate test checks that an unavailable
route MTU drops a size-controlled burst while an ordinary reply still
succeeds.

The job builds with `ttl-pnet,metrics,control`. Windows executables reserve
4 MiB for the main stack, checked from the PE header during release builds.
The job downloads pinned Npcap SDK and runtime files and checks that the staged
DLLs are x64. Missing DLLs or a failed required test fail the job. The job then
runs the mixed-clock suite 20 times; any failed run stops the step. A final
full-suite step is informational (`continue-on-error`) because no capture
driver is installed. All logs are uploaded.

To run the required targets yourself:

```sh
cargo test --locked --no-fail-fast --no-default-features --features ttl-pnet,metrics,control \
  --lib --test config_file_test --test malformed_input_test --test proptest_tlv \
  --test mixed_clock_test --test required_micro_session_test \
  --test session_ssid_validation_test --test sender_measurement_test \
  --test startup_failure_test
```

Automatic sender source-port selection retries Windows `WSAEACCES` (10013)
within its limit of 128 candidates. Explicit ports and other errors fail at
once. Tests cover both address families, exhaustion and avoiding the peer's
port.

A release that claims Windows runtime coverage should keep the successful
required-gate artifact, the native job log and the job metadata for its exact
commit; the raw logs alone do not identify the checkout. Driver-backed pnet
capture, physical NIC traffic and hardware timestamps are not covered.
Repository branch protection is configured separately from these workflows.

### Hardware timestamps

Physical NIC timestamps need two capable hosts. Follow the
[two-host procedure](testing-hardware-timestamps.md) and keep the actual RX and
TX method counts. A virtual `ptp0` device does not establish NIC delivery.

### Successful SRv6 transit gate

`scenario_3_srv6_return_path` requires successful forwarding through an
intermediate Linux router. Captures check SRH traversal, open and authenticated
replies, CoS, and that ordinary replies carry no SRH. A U-flag fallback fails
this gate. See [namespace tests](testing-netns.md). The result covers virtual
Linux routing with nix, not a physical SRv6 fabric or hardware.

### Standards revision monitor

[`standards.json`](conformance/standards.json) pins three implemented draft
revisions and seven RFC metadata records. The checker queries the public IETF
Datatracker document API and the RFC Editor JSON, validates document identity
and required fields, and saves the source JSON with its SHA-256. Each draft pin
must also match the "Revision frozen" text in its matrix. A new revision, RFC
publication, expiry, or a change to an RFC's status, updates or obsolescence
relationships requests review. Expiry within 14 days is an advisory warning.
Network failures and malformed or missing evidence never count as unchanged.

```sh
python3 scripts/check_standards.py --report /tmp/standards.json --cache /tmp/standards-source
python3 scripts/check_standards.py --offline /tmp/standards-source \
  --as-of 2026-09-11 --report /tmp/standards-replay.json
```

Exit codes: **0** current, **1** specification review needed, **2** incomplete
check. Offline mode replays saved observations and does not show the latest
revision. `standards.yml` runs weekly (Mondays) and on demand and uploads
results even on failure. It does not edit pins, open issues or send messages.
Only a reviewed change to the implementation and matrix should update a frozen
draft revision. The monitor does not audit normative text, IANA code points or
errata; release review should check each RFC's errata page and keep the
result. STAMP YANG and TWAMP-Control are outside the product scope.

## Recorded results

Each entry names the date, commit and platform it applies to. Later commits are
not covered until the procedure is repeated.

### 1.0.0 preparation, 2026-10-05

Local checks cover the working-tree changes based on `614a61f1`, on x86_64
Linux (WSL2), with Rust 1.99 and a separate Rust 1.86 check. No release was
tagged or published. The [dependency inventory](release/1.0.0-dependencies.json)
records all 31 direct dependencies from the main and fuzz manifests; each
matches its latest non-yanked stable release. Upstream Axum still pins the
transitive `matchit` dependency to 0.8.4.

| Check | Result |
|---|---|
| Linux all-features tests | 1,363 passed; 12 privileged tests ignored |
| Linux default tests | 1,262 passed; 12 privileged tests ignored |
| Rust 1.86 | Locked all-features, all-targets compilation passed |
| Clippy | Default, all-features and pnet profiles passed with warnings denied |
| Formatting and Rustdoc | Passed; Rustdoc warnings denied |
| Dependency audits | Main and fuzz manifests passed advisories, bans, licenses and sources |
| Independent UDP fixtures | All 16 IPv4/IPv6, auth/open, clock and state combinations passed |
| Control and Net-SNMP | All five HTTP/TLS and reference-master cases passed, including reconnection |
| Sanitizer fuzzing | All nine targets passed a three-second smoke run each |
| Nix | x86_64-linux package/tests, Clippy and formatting passed |
| Windows x64 | `ttl-pnet,metrics,control` cross-link and all-targets Clippy passed; PE stack reserve verified at 4 MiB |
| macOS Intel | All-targets compilation passed with `ttl-nix,ttl-pnet,metrics,snmp,hwtstamp` |
| Packaging | crates.io package verification and x86_64 DEB/RPM generation passed |
| Metadata and workflows | Release versions, Gentoo crate list, Python tests and actionlint passed |
| Standards | All ten frozen draft/RFC metadata records are current |

The DEB was extracted and its executable reported `stamp-suite 1.0.0`.
Its control data includes `libc6 (>= 2.34)`, `adduser` and
`init-system-helpers`; generated scripts maintain the systemd unit. Both Linux
packages include the manual, MIB, release notes and security guidance.

The preceding [CI run](https://github.com/asmie/stamp-suite/actions/runs/37240020027)
failed on an obsolete Nix hash, the Rustls advisory, inherited nonblocking
macOS SNMP test sockets and a Windows CLI stack overflow. These causes are
addressed. The [integration run](https://github.com/asmie/stamp-suite/actions/runs/37240019965)
also exposed Net-SNMP's administrative AgentX binding echoes; the sub-agent now
accepts matching echoes and rejects malformed or unrelated data. Fuzz CI
explicitly selects GNU/Linux so AddressSanitizer can run.

Before tagging, require a fresh native macOS and Windows CI run on the final
commit, plus the privileged wire gate. Cross-compilation does not establish
runtime behavior. This host's Windows application-control policy blocked Cargo
build-script executables (OS error 4551), and no native Mac was available.
macOS TLS cross-compilation also needs Apple's SDK. Container, Gentoo, OpenWrt
and ARM distro builds were not run locally. Generate Gentoo's `Manifest` after
the source archive is published; the release workflow fills the OpenWrt hash
from that same archive. Physical NIC timestamp coverage remains outstanding.

### Net-SNMP reference master, 2026-09-11

All five `release_checks.py` cases passed locally on Linux (WSL2). The tools
were Ubuntu packages `5.9.4+dfsg-2ubuntu3`; the daemon reported `5.9.4.pre2`.

### Native macOS, commit of 2026-09-12

Commit `7ae15c3136b475fe184d0c6f73bde33999a0bf8b`,
[run 34702868546](https://github.com/asmie/stamp-suite/actions/runs/34702868546):
**1150 default and 1234 all-features tests passed**, with no failed, ignored or
filtered tests in either profile. Both profiles ran on macOS 26.6.2 arm64 with
Rust 1.98.1 from clean checkouts, with 35 suite summaries each and Cargo exit
status zero. The report identities, runner and log hashes and counts were
checked against the raw logs.

### Native Windows, commit of 2026-09-12

Commit `2548231aa31644fadd4bb1c634f80c9c7d95dd10` on Windows Server 2025 x64,
[run 34717692891](https://github.com/asmie/stamp-suite/actions/runs/34717692891):
**1041 required tests, 120 mixed-clock checks across all 20 repetitions, and
1140 informational full-suite tests passed**, with no failed, ignored or
filtered tests in any log (9, 20 and 35 suite summaries). The informational
step itself succeeded, so these counts do not depend on `continue-on-error`.
This run also verified the `WSAEACCES` source-port retry.

### Hardware timestamp availability, 2026-09-11

Physical NIC timestamp tests have not been run. On WSL2, `eth0` advertised only
software transmit, software receive and the software system clock; there was
no PHC and no hardware filter or transmit mode. Kernel timestamp and Follow-Up
regression tests provide software evidence only.
