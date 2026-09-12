# Integration test layout

Default `cargo test --all-features` runs every test in this directory that
doesn't require special privileges. A small set of tests is gated either
by Cargo features or by `#[ignore]` so unprivileged CI passes cleanly;
this file documents the opt-in invocations. The standalone Python wire tier
runs separately from Cargo; CI requires both default and all-feature binaries.
See [independent interoperability fixtures](../doc/testing-interop.md) for its
frozen payloads, 16 combined configurations, negative oracle checks and limits.

[`release_checks.py`](../scripts/release_checks.py) separately gates four
authenticated control cases (HTTP/HTTPS over IPv4/IPv6) and a real Net-SNMP master
case in conformance CI. The latter uses temporary processes and tests live MIB
counters/table walks, bulk ordering and reconnect. See the
[release guide](../doc/release-evidence.md) for tools, reports, Windows runtime
scope and the [hardware procedure](../doc/testing-hardware-timestamps.md).
Python discovery (`python3 -m unittest discover -s scripts/tests -v`) also checks
standards-monitor drift, matrix pins and unavailable/malformed source handling.

## Files

`keyset_fallback_test`, `burst_transmission_test`, `session_auth_admission_test`,
`required_micro_session_test` and `mixed_clock_test` build wire bytes manually
and use `common/wire_hmac.rs` for digests without production HMAC/coverage helpers.
In-process key/session state mutation remains part of their test setup.

Performance measurements are documented in [benchmarks.md](../doc/benchmarks.md).
The live UDP example measures release-build throughput and process CPU;
`cargo test --locked --example live_udp_bench` checks its reply validation and
duplicate/reordering accounting. The `idle_cpu_test` regression below separately
enforces an idle CPU ceiling and verifies resumed reception.

Shared processing unit tests count one base-HMAC verification (authenticated
mode), one provisioning check and one session acquisition per accepted live
packet, including all its burst copies, for IPv4/IPv6 and both sequencing modes.
They also cover standalone stateless allocation behavior, authentication failures
before acquisition, and cap/drain/expiry changes after a provisioning decision.
The counters exist only in test builds; the tests run in both backend builds.

TLV unit/property tests in `src/tlv/list/` cover canonical ownership, mutation
and removal, opaque truncated tails, arbitrary interleaved duplicate HMACs,
legal padding on both sides of HMAC, and failure-echo flags/digests. Signing
properties compare serialized coverage with contiguous HMAC input, including
BER padding and structural edits; `src/crypto.rs` varies streaming chunk sizes.
Run the focused subset with `cargo test --locked --lib tlv::list`. Full suites
also exercise live signing, BER, fallback and burst replies in both backend builds.

Measurement collector tests cover late replies, per-probe burst targets, serial
wrap/reset, counter gaps/reordering, Follow-Up repeats/ambiguity/clock formats,
and bounded histories. Typed DM/Follow-Up tests cover U/M/I, malformed/duplicate
values and absent/corrupt/unverifiable HMACs for both base sizes.

Sender validation tests assert typed Access Report, CE, Micro-session and HMAC
outcomes. `telemetry_flag_and_hmac_gates_match_decision_oracle` combines U/M/I
boundaries, signed/unsigned and corrupt/unverifiable input for 44/112-byte bases.
Other regressions cover missing HMAC key/bytes, invalid Access Report length,
unusable HMAC flags, duplicate-HMAC counts and identical control decisions with
printing on/off in text/JSON/CSV modes. Existing live output, session admission,
Access Report, congestion and BER tests exercise integration.

| File | Purpose | Default-run? |
| --- | --- | --- |
| `reply_queue_test.rs` | Real IPv4/open and IPv6/auth queue saturation, capacity recovery without sequence consumption, SIGINT/SIGTERM shutdown, immediate/deadline cancellation and graceful burst completion with counters. | yes, Linux nix |
| `scoped_ipv6_test.rs` | Isolated veth/netns link-local IPv6 replies, delayed bursts, alternate-address HMACs and CLI sender zones; open/auth and both backend builds. | ignored; command below |
| `sender_measurement_test.rs` | Independent IPv4/open and IPv6/authenticated peer verifies delayed burst collection, duplicates, directional counter gaps and mixed-clock Follow-Up summaries. | yes |
| `output_stream_test.rs` | CLI stdout parsing with default/JSON logs, packet details, periodic reports, BER/measurement CSV quoting, reflector shutdown, quiet logging, schema and validation errors. | yes, Linux nix |
| `config_file_test.rs` | TOML config parsing and validation. | yes |
| `loopback_test.rs` | UDP-loopback round-trips on `127.0.0.1` (and one `[::1]`). | yes |
| `replay_control_test.rs` | Independent Type-12 peer: single U-flagged replies for duplicate/reordered/old requests, sequence wraparound, SSID isolation, HMACs, both sequencing modes and drop policies, IPv4/IPv6. | yes, Linux nix |
| `burst_transmission_test.rs` | Live interleaved burst replies: IPv4/IPv6, open/auth, NTP/PTP, stateless/stateful, CoS, DM, Follow-Up, HMAC, and kernel TX correlation. | yes, Linux nix |
| `idle_cpu_test.rs` | Real reflector process: bounded idle CPU after traffic, then receipt of another packet; IPv4/IPv6 and optional kernel timestamps. Linux nix backend; reads child CPU accounting from `/proc`. | yes, Linux nix |
| `loopback_ipv6_test.rs` | TLV-by-TLV IPv6 parity via `process_stamp_packet`. | yes |
| `tlv_flag_semantics.rs` | RFC 8972 U/M/I + draft-asymmetrical C flag conformance. | yes |
| `agentx_protocol_test.rs` | Independent Unix-socket master fixtures: GETBULK row order/end-of-MIB slots, inclusive bounds, fragmented/coalesced frames, cancellation, Close acknowledgment and range-limit errors. | yes, Unix + `snmp` |
| `ber_regression_test.rs` | BER-07 counts and bit-error bursts through packet processing. | yes |
| `ber_measurement_test.rs` | BER-07 IPv4/IPv6 open/auth directional errors, repaired padding, HMAC, duplicate exclusion, unsupported peers and C-flag combinations. Real reflector signing checks require the Linux UDP backend. | yes |
| `session_capacity_test.rs` | Live cap rejection and continued sequence state, IPv4/IPv6, open/authenticated, both sequencing modes; with `control`, drain/resume, runtime caps, expiry/restart, and drop counters. | yes, Linux nix |
| `session_ssid_validation_test.rs` | Independent UDP peer: wrong/matching SSIDs and zero-SSID policies, open/authenticated replies over IPv4/IPv6. | yes |
| `required_micro_session_test.rs` | Independent UDP peer: missing/flagged Micro-session IDs produce no measurement; authenticated valid-ID control, IPv4/IPv6. No physical LAG test. | yes |
| `keyset_fallback_test.rs` | Directory/default keys through normal/SRv6 fallback replies and queued-burst rotation; authenticated revocation, open/auth, IPv4/IPv6. | yes, Unix nix |
| `mixed_clock_test.rs` | Live sender against independent NTP/PTP peer encoding in both mixed directions; IPv4 open, IPv6 authenticated, explicit UTC offset. | yes |
| `ptp_e2e_test.rs` | PTP timestamp encoding + Type 3 sync-source reporting. | yes |
| `malformed_input_test.rs` | Hand-crafted hostile byte sequences at every parser boundary. | yes |
| `pnet_loopback_test.rs` | Real pnet capture on the `lo` interface. | **no — see below** |

The shared transmission unit tests cover SRH/source/alternate-address/CoS
fallback combinations, final signatures, malformed-tail preservation, failed-send
accounting, and real Linux source pinning. They also verify interleaved IPv4/IPv6
CoS/source/PMTU settings on one sender, cached option changes and failed retries,
shared SRH storage across fallbacks/copies, and rejection of incomplete sends. The pnet-only library test
`transmit_worker_interleaves_requests_and_burst_deadlines` exercises the send
worker with ordinary UDP sockets and needs no raw capture capability:

```bash
cargo test --locked --no-default-features --features ttl-pnet --lib
```

`--all-features` selects the nix backend; use the explicit pnet-only build above
to compile and exercise the pnet worker.

Queue unit tests reserve one shared budget across concurrent producers, handoff,
active sends and burst rescheduling, and verify released slots/cancelled-copy
counts. Pnet worker tests exercise grace/deadline shutdown over ordinary UDP;
the privileged capture fixtures disable session expiry (`--session-timeout 0`)
and still require the receiver to join promptly after control shutdown.

## Running the pnet integration tests (C10)

`tests/pnet_loopback_test.rs` is cfg-gated to Linux + the `ttl-pnet`
feature, and every test is marked `#[ignore]`. It needs `CAP_NET_RAW`
(or root) to attach to the `lo` interface via `pnet::datalink::channel`.

**Easiest (run-as-root):**

```bash
sudo -E cargo test --features ttl-pnet --test pnet_loopback_test -- --ignored
```

**With `setcap` on the test binary (no sudo at run time):**

```bash
# 1. Build the binary first so we know its path.
cargo test --features ttl-pnet --test pnet_loopback_test --no-run

# 2. Find the most recent test binary cargo produced.
BIN=$(ls -t target/debug/deps/pnet_loopback_test-* | head -1)

# 3. Grant raw-socket capability.
sudo setcap cap_net_raw+eip "$BIN"

# 4. Run.
"$BIN" --ignored
```

Set `STAMP_REQUIRE_PRIVILEGED=1` for evidence runs. Missing effective
`CAP_NET_RAW` then fails; root alone is not assumed to carry the capability.
Without required mode these ignored tests may report a local prerequisite skip;
that return is not a successful wire test. Authenticated replies must arrive
and verify their HMAC. The fixture requests shutdown and joins its capture worker.

`.github/workflows/conformance.yml` runs required raw pnet, namespace and MTU
checks. It builds each backend separately without root, selects exact Cargo
artifacts and rejects empty/wrong-backend test lists before running with privilege.

## Running everything else

```bash
cargo test --all-features          # default — skips pnet tests
cargo fmt --all -- --check         # formatting gate
cargo clippy --all --all-features --tests -- -D warnings   # lint gate
```

`session_identity_test.rs` exercises the real nix reflector with IPv4/IPv6,
open/authenticated traffic, permissive/provisioned admission, and
stateless/stateful replies. It checks independent SSIDs and micro-sessions,
source-port admission, and Linux wildcard-bind destination separation. Session
unit tests cover counters, replay windows, Follow-Up isolation, expiry and
persistent provisioning; control tests cover ambiguous expiry (409).

`session_auth_admission_test.rs` exercises real nix receive loops and inspects
shared state: bad HMAC slot exhaustion, invalid refreshes on an existing session,
unknown SSIDs, key revocation/rotation, strict short-packet rejection, IPv4/IPv6,
and stateful/stateless accounting. It also verifies a valid base HMAC plus an
invalid TLV HMAC still receives an I-flag response. The shared
`tracked_processing_validates_before_any_session_mutation` unit test runs in
pnet-only builds without requiring raw capture capability.


Statistics unit tests cover exact-to-histogram promotion at 4096 observations,
all magnitude bucket boundaries, sorted independent signed/unsigned quantile
oracles, full-range variance and cancellation errors, fixed storage through one
million samples, and cumulative long-run RTT/OWD summaries. BER history tests
verify bounded retention, omission counters, lifetime totals and continued alarm
transitions. `output_stream_test.rs` checks precision metadata and BER omission
fields in CLI output, including periodic JSON/CSV.


Run the scoped IPv6 fixture only inside isolated namespaces (Linux, `ip`,
`unshare`, `nsenter` and user-namespace support required):

```sh
STAMP_SCOPE_NETNS_TESTS=1 unshare -Urn cargo test --locked --test scoped_ipv6_test -- --ignored --nocapture
STAMP_SCOPE_NETNS_TESTS=1 unshare -Urn cargo test --locked --no-default-features --features ttl-pnet --test scoped_ipv6_test -- --ignored --nocapture
```

The fixture creates a temporary veth pair and a nested network namespace. It uses
independent base/Type-12 bytes and HMAC coverage; only the Return Address TLV uses
the production encoder. Nix checks wildcard and concrete binds; pnet checks
concrete binds. The host network remains unchanged. `mixed_clock_test` checks
local/remote S combinations, error decoding and untrusted echoed local metadata.
Clock-quality unit tests distinguish invalid, absent and unsynchronized estimates;
Follow-Up tests attach quality to the referenced earlier reply.


Revision-13 coverage lives in `ext_hdr_revision13_test.rs` (independent IPv4/IPv6
TTL/port/state peers on Linux and macOS, including mapped IPv4 TTL 255), `tlv_flag_semantics.rs` (raw eight-byte selector/tail oracles)
and pnet checksum unit/privileged tests. Loopback raw tests inject complete UDP
checksums and first verify that corrupted checksums produce no replies. Private
veth fixtures require `ethtool` to disable TX offload on their own interfaces;
partial offloaded capture frames are rejected by design. No host NIC change is
required. These checks supplement the existing MTU and protocol-combination tiers.

Native macOS verification uses the default and all-features jobs in `rust.yml`.
The [native evidence runner](../scripts/run_native_tests.py) retains JSON identity,
exit status, executed/ignored totals and the complete Cargo log, with platform
and completion guards. See [release verification](../doc/release-evidence.md#macos-runtime-gate).
The MTU-race unit regression remains active on macOS and checks preservation of
its supported source-selection policy; it does not require Linux-only pinning.

The keyset fallback tests retain ordinary key rotation, default/SSID selection
and revocation checks on both platforms. Linux additionally verifies queued
Type-12 burst copies retain their accepted key; macOS verifies the documented
drop when the route MTU required for a size-controlled reply is unavailable.

The required Windows runtime gate also runs `--lib` with the seven portable
integration targets listed in [release verification](../doc/release-evidence.md#windows-runtime-gate).
Pnet worker unit tests send ordinary loopback UDP without starting capture.
Burst scheduling and shutdown fixtures inject a known route payload cap; an
additional test exercises unsupported route lookup (injected on Linux, real on
Windows) and verifies drop accounting, reservation release and subsequent replies.
These are scheduler tests, not evidence of Windows capture-driver operation.
