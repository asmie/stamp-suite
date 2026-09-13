# Release verification

Record the tested revision, features, platform, and wire profile with each result.
The [matrices](conformance/README.md) cover frozen specifications. Compilation
and ignored tests do not establish runtime behavior.

## Authenticated control and a reference SNMP master

On Linux with Python 3.10+, OpenSSL and Net-SNMP tools available:

```sh
cargo build --locked --all-features
python3 scripts/release_checks.py --binary target/debug/stamp-suite --report /tmp/release-integration.json
```

The script runs four control cases (IPv4/IPv6 × HTTP/HTTPS) and one reference
SNMP case. `--only control` or `--only snmp` selects an explicit subset, which
is recorded in `expected_cases`. All selected cases must pass; missing tools
are errors. Reports retain commands, logs, HTTP responses, UDP payloads,
Net-SNMP queries, binary/runner hashes, counts and completion state. These are
temporary fixture keys, tokens and communities, never production credentials.

Control checks use the real binary and HTTP server, a mode-0600 token file,
and independently encoded/authenticated UDP traffic. They verify:

- Missing or incorrect bearer tokens cannot read status or mutate keys.
- HTTP key replacement during a burst affects new requests; accepted queued
  copies retain the old key and valid signatures after SRv6 U-flag fallback.
  Their software T3 must be after the successful HTTP rotation acknowledgement;
  already-transmitted copies cannot satisfy this check.
- The old key is rejected, the replacement works without resetting session
  sequencing, deletion revokes access, and default-key insertion/removal affects
  both an existing SSID and a new one.
- Key inventory omits secret bytes, and authenticated shutdown exits cleanly.

HTTPS cases generate a temporary self-signed certificate with an IP SAN. The
client trusts that certificate explicitly and performs normal certificate and
endpoint validation; verification is never disabled. This tests the TLS server
and bearer authentication, not mTLS or an external CA deployment.

The Net-SNMP fixture launches its own `snmpd` in the foreground on an ephemeral
IPv4 loopback port, with a private AgentX socket and persistence directory.
The configuration limits its read-only community to the STAMP enterprise
subtree. It neither reads system daemon configuration nor starts/stops an
existing service. The real stamp-suite subagent registers with that master.
Independent `snmpget`, `snmpwalk`, `snmpbulkget` and `snmpgetnext` clients check
initial/live counters, two session rows across seven columns, repeater ordering
and the end-of-MIB boundary. The fixture restarts only its own master, confirms
that authenticated STAMP still reflects while it is down, then verifies
re-registration with counters/session state preserved.

Net-SNMP master configuration and process isolation follow its
[AgentX guide](https://www.net-snmp.org/docs/README.agentx.html) and
[snmpd options](https://www.net-snmp.org/docs/man/snmpd.html).
This complements the [independent AgentX framing fixtures](conformance/agentx-review.md);
it does not certify every SNMP version, context, byte order or writable MIB.

`conformance.yml` gates all five cases. Its Ubuntu job downloads and extracts
Net-SNMP packages/dependencies into `/tmp`, with no package installation or
system-service startup. Locally installed tools also work. The September 11
local run used Ubuntu packages `5.9.4+dfsg-2ubuntu3`; the daemon itself reports
`5.9.4.pre2`. Record both version strings. All five cases passed on Linux/WSL2.

## macOS runtime gate

`rust.yml` runs separate native macOS jobs for the default and all-features
profiles. Each calls `scripts/run_native_tests.py --expected-platform darwin`
and uploads its JSON report plus raw Cargo log even after a test failure.
Reports retain platform/toolchain identity, commit and patch hash, command,
exit status, logs, and executed/ignored counts. Platform mismatch, missing or
empty summaries, filtered tests, and Cargo failure reject the result.

For a native local Mac, use either profile explicitly:

```sh
python3 scripts/run_native_tests.py --expected-platform darwin --profile default --report native-macos-default.json
python3 scripts/run_native_tests.py --expected-platform darwin --profile all-features --report native-macos-all-features.json
```

Native macOS verification passed at commit
`7ae15c3136b475fe184d0c6f73bde33999a0bf8b` in
[run 34702868546](https://github.com/asmie/stamp-suite/actions/runs/34702868546):
**1150 default / 1234 all-features tests passed**, with zero failed, ignored or
filtered tests in either profile. Both ran on macOS 26.6.2 arm64 with Rust 1.98.1,
clean checkouts, 35 suite summaries and Cargo exit zero. The retained reports'
identities, runner/log hashes and counts were checked against their raw logs.

This result covers native arm64 default/all-feature socket builds. Pnet capture,
Intel Mac runtime, and physical NIC timestamps require separate evidence.
Platform-excluded tests are not counted as executed.

## Windows runtime gate

`rust.yml` requires the library unit suite and eight explicit integration test
targets on Windows:
configuration files, malformed input, TLV properties, mixed clocks, required
micro-session validation, SSID validation, sender measurement summaries and
startup error reporting.
These exercise codecs, the transmit scheduler and UDP sender peers without
starting the pnet capture receiver. Scheduler fixtures inject a known MTU; a
separate regression checks that unavailable route MTU drops a controlled burst
while an ordinary reply still succeeds.
The job retains pinned Npcap SDK/runtime downloads and validates the staged
DLLs' x64 PE machine type. Missing DLLs or a failed core test fail the job.
Its full-suite step remains informational because a capture-driver fixture is
not installed. Both logs are uploaded.

The same eight targets can be selected explicitly:

```sh
cargo test --locked --no-fail-fast --no-default-features --features ttl-pnet \
  --lib --test config_file_test --test malformed_input_test --test proptest_tlv \
  --test mixed_clock_test --test required_micro_session_test \
  --test session_ssid_validation_test --test sender_measurement_test \
  --test startup_failure_test
```

Automatic source-port selection retries Windows WSAEACCES (10013) within its
128-candidate limit. Explicit ports and unrelated errors fail immediately.
Tests cover both address families, exhaustion, and peer-port avoidance.
Native Windows Server 2025 x64 verified this behavior at `2548231` in
[run 34717692891](https://github.com/asmie/stamp-suite/actions/runs/34717692891):
**1041 core tests, 120 checks across all 20 repetitions, and 1140 informational
full-suite tests passed**, with zero failures, ignored or filtered tests in each
log (9, 20 and 35 suite summaries respectively). The informational step itself
succeeded; these counts do not rely on its `continue-on-error` setting.
The five-second packet deadline and child-process failure diagnostics remain enabled.

A release claiming Windows runtime coverage should retain the successful
required-gate artifact and native job log for its exact commit. The raw logs
alone do not identify their checkout; retain the matching job metadata too.
Driver-backed pnet capture, physical NIC traffic and hardware timestamps remain
unverified. Repository branch protection is administered separately from these
workflow definitions.

## Hardware timestamps

Physical NIC timestamp tests have not run. The September WSL2 availability checks
found software timestamp support and no NIC PHC; a virtual `ptp0` device does not
establish NIC delivery. Use the [two-host procedure](testing-hardware-timestamps.md)
on capable hardware and retain actual RX/TX method counts.

## Standards revision monitor

[`standards.json`](conformance/standards.json) pins four implemented draft
revisions and six RFC metadata records. The checker queries the public IETF
Datatracker document API and RFC Editor JSON, validates document identity and
required fields, and saves source JSON plus SHA-256. Draft pins must also match
their matrix text. New revisions, RFC publication, expiry, or changes to an RFC's
status/update/obsolescence relationships request review. Expiry within 14 days
is an advisory warning. Network failures and malformed/missing evidence never
count as unchanged.

```sh
python3 scripts/check_standards.py --report /tmp/standards.json --cache /tmp/standards-source
python3 scripts/check_standards.py --offline /tmp/standards-source \
  --as-of 2026-09-11 --report /tmp/standards-replay.json
```

Exit codes: **0** current, **1** specification review needed, **2** incomplete
check. Offline mode replays saved observations; it does not establish the latest
revision. `standards.yml` runs weekly and on demand, uploading results even on
failure. It does not edit pins, open issues or send messages. Only reviewed
implementation/matrix changes should update the frozen draft revision. The
monitor does not automatically audit normative text, IANA code points or errata;
release review should check each RFC's linked errata page and retain the result.

The September 11 check found ext-hdr -13 while the implementation used -11.
The [revision-13 review](conformance/ext-hdr-13-review.md) updated implementation,
matrix, and pin. Offline replay checks that baseline, not current live metadata.
STAMP YANG and TWAMP-Control remain outside the product scope.

## Successful SRv6 transit gate

`scenario_3_srv6_return_path` requires successful forwarding through an
intermediate Linux router. Captures check SRH traversal, open/authenticated
replies, CoS, and ordinary-reply isolation. U fallback fails this gate. See
[namespace procedures](testing-netns.md). The result covers virtual Linux/nix
routing; it does not establish physical-fabric or hardware behavior.
