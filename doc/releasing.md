# Releasing

This page lists what the release workflow checks and how to run the same
checks locally. The [conformance matrices](conformance/README.md) cover the
frozen specifications, and the
[supported profiles and limits](conformance/README.md#known-limits) apply to
release claims too. A passing job says nothing about a capability it does not
exercise, such as physical LAG, NIC timestamps, a capture driver or PMTU
discovery.

## Release gate boundary

A `v*` tag starts `release.yml`. Its `release-preflight` job runs first and
every other job depends on it: it checks that the tag matches every version
source (`scripts/check_release_metadata.py --version`), validates the notice
profiles and dry-runs `cargo publish`. The workflow then calls `rust.yml` and
`conformance.yml` as reusable workflows. Nothing is published until both have
passed, along with the source, Linux, macOS and Windows package jobs, so the
backend, native-platform, MSRV, evidence and privileged checks all run on the
tagged commit. Platform exclusions still apply: the Windows tests that run
without a capture driver say nothing about capture with a driver.

CodeQL is not part of the release gate. `codeql.yml` is an advanced-setup
workflow that analyzes Actions, Python and Rust without a build
(`build-mode: none`) on pushes and pull requests to `master` and every Monday.
Its configuration, `.github/codeql/codeql-config.yml`, leaves out test code
(`tests/`, `benches/`, `fuzz/` and the test files under `src/`), which uses
fixed keys on purpose and does not ship. GitHub's default CodeQL setup must be
turned off in the repository's code security settings, because both cannot
upload results.

The `independent-wire` jobs in `conformance.yml` run the protocol-combination
fixtures (`scripts/interop_stamp.py`) and the
[successor BER profile](testing-interop.md#independent-successor-ber-profile)
(`scripts/interop_ber.py`) with stamp-suite in both roles: 60 required BER
cases for the default build and 60 for the all-features build. Both reports
are uploaded even when cases fail.

Cargo builds in the release jobs and in the container must match the
lockfile. Debian builds run offline: before running `debian/rules`,
extract the release vendor archive into `vendor/` next to `Cargo.toml`. The
build fails if `vendor/` is missing, and cleaning does not delete it. In a
development checkout, create it yourself with `cargo vendor --locked vendor`.

The OpenWrt recipe in `dist/openwrt/Makefile` is a template, and it refuses to
build while the hash is unset. The source job hashes the exact
`stamp-suite-VERSION.tar.gz` it produced (the archive is built
deterministically) and publishes a filled-in `stamp-suite-VERSION-openwrt.mk`,
which is covered by the checksums and attestations. Use that file as the
feed's `Makefile`. To render it yourself from the same archive:

```sh
python3 scripts/render_openwrt.py --archive stamp-suite-VERSION.tar.gz --output Makefile
```

If the archive has not been published or cannot be fetched, there is no
digest to check against. The recipe generator does not work around that with
`PKG_HASH:=skip`.

## Third-party notices

`THIRD_PARTY_NOTICES.txt` is generated at packaging time for the target and
feature set of that build. It is not in Git or in the source-only archives.
The generator follows normal dependency edges and leaves out development and
build dependencies, procedural macros and the dependencies those macros only
need on the host. For an `OR` license expression it picks one of the offered
licenses; for `AND` it keeps every license that is required. Full license
texts are listed once and shared between crates, while copyright lines and
other attributions stay with their crate. The file lists runtime dependencies.
It does not try to work out which functions are left after linker
optimization. System libraries and drivers installed separately are out of
scope.

CI and the release preflight check every release profile. After you change a
dependency or a release profile, run:

```sh
python3 scripts/third_party_notices.py --validate-release-profiles
```

Add `--offline` if all locked dependencies are already downloaded. Generate
the bundle before running a packager, then check the archives it produced:

```sh
python3 scripts/third_party_notices.py --target x86_64-unknown-linux-gnu
python3 scripts/check_packaged_notices.py 'target/x86_64-unknown-linux-gnu/debian/*.deb' 'target/x86_64-unknown-linux-gnu/generate-rpm/*.rpm' 'stamp-suite-*.tar.gz'
```

The archive check compares the text inside each package byte for byte with the
generated bundle, and accepts a copy the packager compressed with gzip. It
fails if an archive or its notices are missing, or if the text was changed.
RPMs need `rpm2archive` (from the `rpm` package), which, unlike `rpm2cpio` in
RPM 4.18, reads packages that lack the archive-size tag. DEBs need
`dpkg-deb`. Tar and ZIP files are read with Python's standard library. These
checks run before any release artifact is uploaded.

Building RPMs needs the RPM tools, including `/usr/lib/rpm/find-requires`.
Build the binary and generate its notices first, then run
`cargo generate-rpm --auto-req find-requires`. CI and the release jobs name
that scanner so that packaging fails when the tools are missing. Without it the
packager falls back to its automatic mode, which on some hosts adds invalid
weak-symbol dependencies and produces an RPM that cannot be installed.

The Debian, RPM, Gentoo, OpenWrt, Nix and container recipes install the bundle
under `/usr/share/doc/stamp-suite/` (or the platform's documentation prefix).
Source archives ship the generator and the reviewed policy, and vendor
archives keep the upstream files as they are. There is no combined bundle to
commit.

For a custom build, pass `--features` with the exact features you built with
(`all` means all features), and `--no-default-features` if you disabled the
defaults. Without `--features`, the generator uses the target's release
profile. `--check` compares an existing generated bundle with what the same
target and features would produce. To generate offline, the locked metadata
dependencies must already be downloaded or vendored, including the ones Cargo
needs to resolve development targets.

The extra Apache-2.0 text in `scripts/licenses/Apache-2.0.txt` comes from the
[Apache Software Foundation](https://www.apache.org/licenses/LICENSE-2.0.txt).
It provides the full license terms for included components whose source
headers point to them. `scripts/licenses/notice-policy.json` holds
per-package rules, pinned to reviewed versions and input hashes. They pick up
nested Unicode and third-party notices and the native sources that `ring`
selects per architecture, leave out the licenses of BoringSSL test and CI
files that are never linked, and add the Prometheus schema only when
`protobuf` is enabled. If any of those inputs changes, validation fails until
someone reviews the policy.

## Procedures

### Linux package installation

The CI `package` job and both Linux release package jobs (x86_64 and aarch64)
run `scripts/check_package_install.py` on the DEB and RPM files they built.
Linux packages are built on Ubuntu 24.04 runners to keep that glibc baseline.
The checks need Docker running native Linux containers, and Python 3.10 or
later:

```sh
python3 scripts/check_package_install.py --package target/debian/stamp-suite_VERSION-1_amd64.deb --report /tmp/package-install-deb.json
python3 scripts/check_package_install.py --package target/generate-rpm/stamp-suite-VERSION-1.x86_64.rpm --report /tmp/package-install-rpm.json
```

Replace the paths and versions with the ones your build produced. The script
builds its test images from `dist/package-check/`: Ubuntu 24.04 for DEB and
Fedora 45 for RPM. Both are pinned so that a new upstream release cannot change
the gate; update them on purpose. Building the images needs network access.
The installation and service checks run with networking off, apart from the
container's own loopback. `--image NAME` reuses a test image you have
already built. The report records the image ID, architecture, OS release,
package hash, the native package manager's output and the wire exchanges. CI
uploads whatever reports exist, even when a check fails.

Each check runs in a throwaway container. It installs the package and then
reinstalls it, with dependency checks on, and verifies that the service
account is still non-root and still has the same UID and GID. It validates the
packaged unit with `systemd-analyze verify`. It then reads the account,
capabilities and `NoNewPrivileges` setting from that installed unit, runs the
reflector under exactly that sandbox, and checks in `/proc` that the process
got it. It checks open and authenticated reflection on port 862 over IPv4 and
IPv6, that replies carry the right identity and valid HMACs, and that the
reflector shuts down cleanly. As a negative control, the bind must fail
without that capability. Removing the package must remove the binary. On DEB,
removal keeps the account and purging must delete it. Nothing on the host
(accounts or services) is changed.

The locally built RPM is unsigned, so the check skips signature verification
but keeps dependency and payload digest checks. It says nothing about whether
a distribution's signing keys are trusted. The service
checks cover the unit's syntax and the process privileges listed above. They
do not boot systemd or test every sandbox directive. Booting a full service
manager is a separate deployment check.

### Authenticated control and a reference SNMP master

On Linux, with Python 3.10 or later, OpenSSL and the Net-SNMP tools (`snmpd`,
`snmpget`, `snmpgetnext`, `snmpwalk`, `snmpbulkget`):

```sh
cargo build --locked --all-features
python3 scripts/release_checks.py --binary target/debug/stamp-suite --report /tmp/release-integration.json
```

The script runs four control cases (IPv4 and IPv6, each over HTTP and HTTPS)
and one SNMP case against a reference master. `--only control` or
`--only snmp` runs just one group, and the report lists the chosen cases under
`expected_cases`. Every chosen case must pass, and a missing tool counts as an
error. The report keeps the commands, logs, HTTP responses, UDP payloads,
Net-SNMP queries, the hashes of the binary and the runner, the counts and
whether the run completed. Keys, tokens and communities are throwaway test
values, never production credentials.

The control cases run the real binary and its HTTP server with a token file of
mode 0600. The UDP traffic is encoded and signed by the script's own code. The
cases check that:

- Without the right bearer token, a client can neither read the status nor
  change keys.
- When a key is replaced over HTTP in the middle of a burst, new requests use
  the new key. Copies that were already queued keep the old key and still
  carry valid signatures after an SRv6 U-flag fallback. Their software T3 must
  be later than the time the rotation was acknowledged, so copies sent before
  the rotation cannot make the check pass.
- The old key is rejected, and the new key works without resetting the
  session's sequence numbers. Deleting a key revokes access. Adding or
  removing the default key affects both an existing SSID and a new one.
- The key list does not contain secret bytes, and a shutdown request with a
  valid token makes the process exit cleanly.

The HTTPS cases create a temporary self-signed certificate with an IP address
in its SAN. The client is told to trust that certificate and then validates
the certificate and endpoint as usual. This tests the TLS server and bearer
authentication. It does not test mTLS or certificates from an external CA.

The SNMP case starts its own `snmpd` in the foreground on a random IPv4
loopback port, with its own AgentX socket and persistence directory. Its
read-only community can only see the STAMP enterprise subtree. It does not
read the system's daemon configuration or touch a running service. The real
stamp-suite sub-agent registers with this master. Net-SNMP clients, which
share no code with stamp-suite, then check the counters at startup and while
traffic flows, two session rows in the six readable columns (the
not-accessible `stampReflSessIndex` appears only in each cell's OID), the
order of non-repeaters and repeaters in GetBulk, and the end-of-MIB boundary.
The case then stops its master, checks that authenticated STAMP is still
reflected, starts the master again, and checks that the sub-agent registers
again with its counters and session state intact.

The master is configured as described in the Net-SNMP
[AgentX guide](https://www.net-snmp.org/docs/README.agentx.html) and the
[snmpd options](https://www.net-snmp.org/docs/man/snmpd.html). This adds to
the separate AgentX framing tests described under
[SNMP AgentX sub-agent](architecture.md#snmp-agentx-sub-agent). It does not
cover every SNMP version, context or byte order, or a writable MIB. Record
both the Net-SNMP package version and the version string the daemon reports.

The `release-integration` job in `conformance.yml` runs all five cases on
Ubuntu with an all-features debug build. It downloads the Net-SNMP packages
and unpacks them into `/tmp` without installing them or starting a system
service. Locally installed tools work too.

### macOS runtime gate

The `test-macos` job in `rust.yml` runs the default and all-features profiles
natively. Each one runs Clippy with `-D warnings` (the Linux Clippy jobs do not
compile macOS-only code), then calls
`scripts/run_native_tests.py --expected-platform darwin` and uploads its JSON
report and the raw Cargo log, also when the job fails. The
report records the platform and toolchain, the commit and patch hash, the
command, its exit status, the logs, and how many tests ran and how many were
ignored. The gate fails on a platform mismatch, on test summaries that are
missing or empty, on filtered tests, or if Cargo fails.

On a local Mac, run each profile by name:

```sh
python3 scripts/run_native_tests.py --expected-platform darwin --profile default --report native-macos-default.json
python3 scripts/run_native_tests.py --expected-platform darwin --profile all-features --report native-macos-all-features.json
```

This covers builds that use native sockets. Pnet capture, runtime on Intel
Macs and physical NIC timestamps need their own evidence. Tests that are
excluded on the platform do not count as executed.

### Windows runtime gate

The `test-windows` job in `rust.yml` requires the library unit tests and
thirteen integration test targets to pass: configuration files, malformed input, TLV
properties, mixed clocks, required Micro-session validation, SSID validation,
sender measurement summaries, startup error reporting, base-protocol sender
bytes, Return Path sender bytes, header-request controls, TLV flag semantics
and sender scheduling. The scheduling tests cover duration and count limits,
sub-millisecond intervals and Poisson rates against a UDP peer that never
answers. Together these exercise the codecs, the transmit scheduler and UDP
sender peers without starting the pnet capture receiver. The scheduler tests
use a fixed MTU. A separate test checks that when the route MTU is unknown, a
size-controlled burst is dropped and an ordinary reply still goes out.

The job builds with `ttl-pnet,metrics,control` and runs Clippy on that
profile first, since the Linux Clippy jobs do not compile Windows-only code.
Windows executables reserve 4 MiB for the main thread's stack (`build.rs`),
and release builds read that value back from the PE header to check it. The
job downloads pinned Npcap SDK and runtime files and checks that the staged
DLLs are x64. It fails if a DLL is missing or a required test fails. It then
runs the mixed-clock suite 20 times and stops at the first failed run. A last step runs the full suite for information only
(`continue-on-error`), because no capture driver is installed. All logs are
uploaded.

To run the required targets yourself:

```sh
cargo test --locked --no-fail-fast --no-default-features --features ttl-pnet,metrics,control \
  --lib --test config_file_test --test malformed_input_test --test proptest_tlv \
  --test mixed_clock_test --test required_micro_session_test \
  --test session_ssid_validation_test --test sender_measurement_test \
  --test startup_failure_test --test base_protocol_wire_test --test return_path_wire_test \
  --test header_request_wire_test --test tlv_flag_semantics --test sender_schedule_test
```

When the sender picks its own source port, it retries on Windows `WSAEACCES`
(10013), trying up to 128 candidate ports. An explicitly configured port, or
any other error, fails straight away. Tests cover both address families,
running out of candidates, and skipping the peer's port.

If a release claims Windows runtime coverage, keep the artifact from the
successful required gate, the native job log and the job metadata for that
exact commit. The raw logs alone do not say which checkout they came from.
Pnet capture through a driver, traffic on a physical NIC and hardware
timestamps are not covered. Branch protection for the repository is set up
outside these workflows.

### Hardware timestamps

Testing physical NIC timestamps takes two hosts with capable NICs. Follow the
[two-host procedure](testing-hardware-timestamps.md) and keep the actual counts
of each RX and TX timestamp method. A virtual `ptp0` device does not show that
the NIC delivers timestamps.

### Successful SRv6 transit gate

`scenario_3_srv6_return_path` passes only if the reply is actually forwarded
through an intermediate Linux router. Packet captures check that the SRH is
traversed, that open and authenticated replies and CoS work, and that ordinary
replies carry no SRH. A U-flag fallback fails this gate. See
[namespace tests](testing-netns.md). The result covers virtual Linux routing
with the nix backend, not a physical SRv6 fabric or hardware.

### Standards revision monitor

[`standards.json`](conformance/standards.json) pins three implemented draft
revisions and seven RFC metadata records, and tracks the expired STAMP YANG
draft separately as watch-only. For drafts, the checker queries Datatracker's
`/doc/<name>/doc.json` endpoint for the resolved draft state; for RFCs, it
reads the RFC Editor JSON. It checks each document's identity and required
fields and saves every JSON response along with its SHA-256. The pin for each
implemented draft must also match the "Revision frozen" text in its matrix.
Any of the following asks for a review: a new revision, publication as an RFC,
an inactive draft state, expiry, or a change to an RFC's status or to its
updates or obsoletes relationships. A draft that expires within 14 days only
produces a warning.

For a draft in the Replaced state, the checker reads the `replaces`
relationships from `/api/v1/doc/relateddocument/` and follows every successor
branch. The report lists the complete replacement paths and the successors'
metadata, and the cache keeps every document and relationship response. Each
tracked draft gets at most eight hops, 16 documents and 64 visits. Cycles,
incomplete relationship pages, missing successors and invalid metadata mark
the check as incomplete. The checker does not guess a successor or claim that
the pinned document is current in that case.

An entry with `"watch_only": true` reports changes without failing the run. A
watch-only draft must set `expected_state` and can leave out a matrix, since
stamp-suite claims no implementation of it. The YANG entry expects revision 12
in the Expired state. You still see a renewal, a new revision or a replacement
path, but the known expiry does not block a release. Network failures and
malformed or missing evidence still make the check incomplete, watch-only
entries included.

```sh
python3 scripts/check_standards.py --report /tmp/standards.json --cache /tmp/standards-source
python3 scripts/check_standards.py --offline /tmp/standards-source \
  --as-of 2026-09-11 --report /tmp/standards-replay.json
```

Exit codes: `0` current, `1` specification review needed, `2` incomplete
check. Offline mode replays saved responses, so it cannot show the latest
revision. When you compare replay results, use the `as_of` date from the live
report. Reports use schema version 2 and include a `sources` list with the
URL, cache file name and digest of each response. Caches saved from the old
document API have no resolved draft state and must be refreshed; this checker
cannot report a current result from them.

`standards.yml` runs every Monday and on demand, and uploads its results even
when it fails. When the check fails or is incomplete, it opens one GitHub issue
titled "Standards revision monitor needs review", or updates it if it is
already open, with a link to the run and the review or error details. The
workflow has `issues: write` permission and runs one at a time so that it does
not post duplicate notifications. `scripts/notify_standards.py` finds its
issue by a marker in the body, leaves other issues alone, and passes the body
to `gh` through a file. The notification tests mock `gh` and never write to
GitHub. The workflow stays red while a review is needed. Close the issue by
hand once you have reconciled the change; a later successful check does not
close it or change any pins.
Only a reviewed change to both the implementation and the matrix should move a
frozen draft revision. The monitor does not check normative text, IANA code
points or errata. During release review, check the errata page of each RFC and
keep the result. Watching STAMP YANG does not mean stamp-suite implements YANG,
and TWAMP-Control stays out of the product's scope.
