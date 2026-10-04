# Integration tests

Integration test inventory, feature/platform requirements and commands for
ignored tests. General build and lint commands are in
[CONTRIBUTING.md](../CONTRIBUTING.md#tests).

The [3 October review](../doc/review/2026-10-03/README.md#test-value-and-missing-cases)
records the original test assessment. Regression tests now cover rendered
statistics, process metrics, AgentX lifetime, sender size limits, source churn
and blocked output. Keep helper-based scenarios and no-panic properties;
consolidation must preserve their boundary inputs and independent checks.

## Running the default suite

```bash
cargo test --all-features
```

This runs every test that needs no special privileges. Tests are excluded in
two ways:

- **Build gates (`cfg`).** Some files compile only on certain platforms, with
  certain features, or with one receiver backend. "nix" in the table below
  means a build that selects the nix backend: the default on Linux and macOS,
  and any build with `ttl-nix`. `--all-features` selects nix, so the pnet
  backend is tested only in a build with
  `--no-default-features --features ttl-pnet`.
- **`#[ignore]`.** Tests that need raw sockets, root or namespaces are ignored.
  Each also checks its own environment variable before doing anything. See
  [Tests that need privileges or namespaces](#tests-that-need-privileges-or-namespaces).

To exercise the pnet backend's library tests (the send worker uses ordinary UDP
sockets and needs no capture capability). This also checks Ethernet source MAC
propagation through ingest and transmission for IPv4 and IPv6:

```bash
cargo test --locked --no-default-features --features ttl-pnet --lib
```

The library and test targets that CI requires on Windows and macOS are listed
in [release verification](../doc/release-evidence.md#procedures).

## Test files

| File | What it tests | Runs when |
| --- | --- | --- |
| `agentx_protocol_test.rs` | Independent AgentX master over a Unix socket: GetBulk order and end-of-MIB positions, search range bounds, fragmented and coalesced frames, cancellation, Close acknowledgment, range-limit error, invalid handshakes and both byte orders. | Unix, `snmp` |
| `ber_measurement_test.rs` | End-to-end BER (draft-gandhi-ippm-stamp-ber-07): directional errors, padding repair, HMAC, duplicate exclusion, peers without BER, C-flag cases; IPv4/IPv6, open/authenticated. | always; the real-reflector signing test needs Linux nix |
| `ber_regression_test.rs` | BER counts and bit error bursts through packet processing. | always |
| `burst_transmission_test.rs` | Live interleaved burst replies: IPv4/IPv6, open/authenticated, NTP/PTP, stateless/stateful, CoS, Direct Measurement, Follow-Up, HMAC and kernel TX correlation. | Linux, nix |
| `clock_metadata_test.rs` | Clock discipline, timestamp encoding and TX provenance on the wire, for IPv4/IPv6, open/authenticated and stateless/stateful. | Linux, nix |
| `config_file_test.rs` | TOML configuration file: CLI precedence, parse errors that name the path, unknown keys. | always |
| `control_api_test.rs` | Control API end to end over raw HTTP/1.1. | `control` |
| `ext_hdr_nix_test.rs` | Type 246 reflection from ancillary data on the nix backend. | Linux, nix; ignored, see [User-namespace tests](#user-namespace-tests) |
| `ext_hdr_revision13_test.rs` | draft-ietf-ippm-stamp-ext-hdr-15 sender rules: random source ports, TTL/Hop Limit 255 (including IPv4-mapped), session state notifications and their deadlines. | Linux, macOS |
| `idle_cpu_test.rs` | A real reflector process returns to idle after traffic and still receives the next packet; IPv4, IPv6 and kernel timestamps. Reads child CPU time from `/proc`. | Linux, nix |
| `key_reload_test.rs` | `receiver::reload_keys` (the SIGHUP path) picks up new key files and keeps the current keys on error. | Unix |
| `keyset_fallback_test.rs` | Per-SSID and default keys through source and SRv6 fallback replies, queued burst rotation and revocation; IPv4/IPv6, open/authenticated. | Unix, nix |
| `loopback_ipv6_test.rs` | IPv6 through `process_stamp_packet`: authentication, CoS, Location, Destination Node Address, Micro-session ID, BER and unknown TLVs. | always |
| `loopback_test.rs` | Sender and reflector over loopback: single and multiple packets, authentication, timestamp order, stateful multi-client, IPv6, Location TLV. | always |
| `malformed_input_test.rs` | Malformed base packets and TLV chains through the reflector: base sizes, TLV layouts, HMAC order, Return Path sub-TLVs. | always |
| `man_page.rs` | `dist/man/stamp-suite.1` matches the clap definition. Regenerate with `STAMP_UPDATE_MAN=1 cargo test --all-features --test man_page`. | Linux |
| `metrics_accounting_test.rs` | Real Prometheus scrapes match burst copies, suppression, queue rejection and rate limits. | Linux, nix, `metrics` |
| `mixed_clock_test.rs` | Live sender against an independently encoded NTP/PTP peer in both directions, with a UTC offset and clock quality metadata; IPv4 open, IPv6 authenticated. | always |
| `multi_key_hmac_test.rs` | Per-SSID HMAC verification and signing: single-key fallback, key selection, rejection without a key. | always |
| `multi_target_test.rs` | One sender measuring several reflectors, each in its own session. | Linux, nix |
| `netns_conformance.rs` | Wire behavior across network namespaces (CoS, SRv6, header reflection, Address Groups, BER, Type 12, TTL). | Linux; ignored, see [Namespace conformance tier](#namespace-conformance-tier) |
| `output_stream_test.rs` | CLI stdout stays parseable with logs, packet details, periodic reports, BER and measurement CSV, reflector shutdown, schema output, validation errors, blocked stdout and broken pipes. | Linux, nix |
| `pnet_loopback_test.rs` | Real pnet capture on `lo`: open, authenticated and TLV round trips, and that bad UDP checksums get no reply. | Linux, `ttl-pnet` without `ttl-nix`; ignored, see [Raw capture (pnet)](#raw-capture-pnet) |
| `proptest_tlv.rs` | Property tests: typed TLV and wire round trips, and no panics in TLV, packet and AgentX decoders on arbitrary bytes. | always; AgentX properties need `snmp` |
| `ptp_e2e_test.rs` | PTP/NTP encoding and the reflector's declared clock metadata in Type 3. | always |
| `replay_control_test.rs` | Type 12 replay handling (RFC 10052 §5): one U-flagged reply for duplicate, reordered or old requests; wraparound, SSID isolation, HMACs, both sequencing modes and drop policies; IPv4/IPv6. | Linux, nix |
| `reply_queue_test.rs` | Reply queue overload and recovery without consuming sequence numbers; SIGINT/SIGTERM shutdown with immediate or graceful drain of queued bursts. | Linux, nix |
| `required_micro_session_test.rs` | A sender rejects replies without a usable requested Micro-session ID; IPv4/IPv6, open and authenticated. | always |
| `route_mtu_test.rs` | Reply route MTU in a second namespace: MTU changes, route metrics, alternate destinations, C-flagged clamps and final HMACs. | Linux, nix; ignored, see [User-namespace tests](#user-namespace-tests) |
| `same_link_reply_test.rs` | Return Path control code 0x1 (RFC 9503 §4.1.1): the reply leaves on the arrival link, or U is set where that cannot be done. | Unix, nix |
| `scoped_ipv6_test.rs` | Link-local IPv6 over a veth pair: replies, delayed bursts, alternate return address and CLI zones, on both backends. | Linux; ignored, see [User-namespace tests](#user-namespace-tests) |
| `sender_measurement_test.rs` | Independent peer checks sender summaries, burst collection, duplicates, counter gaps and Follow-Up summaries. | always |
| `sender_pacing_test.rs` | A sender keeps its schedule when the reflector port is closed (ICMP errors), and interim reports continue during the final wait. | always |
| `sender_schedule_test.rs` | `--count 0` with `--duration`, duration before count, sub-millisecond and Poisson intervals, `--interface`. | always; interface test on Linux and macOS |
| `session_auth_admission_test.rs` | Rejected base packets do not create or refresh sessions: bad HMACs, unknown SSIDs, key rotation, strict short packets; an invalid TLV HMAC still gets an I-flagged reply. | Unix, nix |
| `session_capacity_test.rs` | Session cap rejection keeps sequence state; with `control`, drain and resume, runtime caps, expiry and drop counters. | Linux, nix |
| `session_identity_test.rs` | Session identity and static admission on real sockets: SSIDs, Micro-session IDs, source ports and wildcard-bind destinations. | Unix, nix |
| `session_ssid_validation_test.rs` | Sender SSID checks and zero-SSID policies against an independent peer; IPv4/IPv6, open/authenticated. | always |
| `snmp_lifecycle_test.rs` | CLI exits after finite sends, startup failures, signals and silent initial/reconnect handshakes. | Unix, `snmp`; reflector needs nix |
| `startup_failure_test.rs` | Startup failures (bind, key file, missing key, bad BER pattern, missing interface) return errors; total loss and shutdown do not. | always; some cases Linux only |
| `tlv_flag_semantics.rs` | U, M, I and C flag rules (RFC 8972, RFC 10052, draft-ietf-ippm-stamp-ext-hdr-15) through `process_stamp_packet`. | always |

Shared helpers and data:

| Path | Purpose |
| --- | --- |
| `common/wire_hmac.rs` | HMAC-SHA-256 computed directly with `hmac` and `sha2`, so wire tests do not use the production HMAC or coverage code. |
| `netns/mod.rs` | Namespace fixture for `netns_conformance.rs`: namespaces, veth links, tcpdump capture and pcap parsing. |
| `privileged/mod.rs` | Shared skip policy: with `STAMP_REQUIRE_PRIVILEGED=1` an unavailable prerequisite fails instead of skipping. |
| `fixtures/interop/` | Request and reply bytes for the Python wire fixtures; see [testing-interop.md](../doc/testing-interop.md). |
| `proptest_tlv.proptest-regressions` | Saved proptest failure seeds, replayed on every run. |

## Tests that need privileges or namespaces

These tests are ignored by default, so they run only with `--ignored`. Most
also need an environment variable; the last column says what happens when it is
missing.

| Test | Gate | Needs | Without the gate or a prerequisite |
| --- | --- | --- | --- |
| `pnet_loopback_test` | `ttl-pnet` build | `CAP_NET_RAW` | Skips, or fails in required mode |
| `netns_conformance` | `STAMP_NETNS_TESTS=1` | Root or mapped root, `ip`, `tcpdump`, `ethtool` | Skips, or fails in required mode |
| `route_mtu_test` | `STAMP_MTU_NETNS_TESTS=1` | User namespaces, `ip`, `unshare`, `nsenter` | Fails |
| `scoped_ipv6_test` | `STAMP_SCOPE_NETNS_TESTS=1` | User namespaces, `ip`, `unshare`, `nsenter` | Fails |
| `ext_hdr_nix_test` | `STAMP_EXTHDR_NETNS_TESTS=1` | User namespaces, `ip` | Skips without the variable |

Required mode is `STAMP_REQUIRE_PRIVILEGED=1`. It applies to
`pnet_loopback_test` and `netns_conformance` and turns every skip into a
failure: a missing capability, tool or kernel feature then fails the test. Use
it for any result that counts as evidence. Without it those tests are optional
local probes, and a printed `SKIP` followed by Cargo's `ok` does not mean the
test ran.

### Raw capture (pnet)

`pnet_loopback_test.rs` attaches to `lo` with `pnet::datalink::channel`, so it
needs effective `CAP_NET_RAW`. In required mode a missing capability fails the
test; root without the capability is not enough. Authenticated replies must
arrive and verify, and the test checks that the capture worker stops after
shutdown.

As root:

```bash
sudo -E env STAMP_REQUIRE_PRIVILEGED=1 cargo test --locked --no-default-features --features ttl-pnet \
  --test pnet_loopback_test -- --ignored --test-threads=1
```

Or grant the capability to the test binary and run it without sudo:

```bash
cargo test --locked --no-default-features --features ttl-pnet --test pnet_loopback_test --no-run
BIN=$(ls -t target/debug/deps/pnet_loopback_test-* | grep -v '\.d$' | head -1)
sudo setcap cap_net_raw+eip "$BIN"
STAMP_REQUIRE_PRIVILEGED=1 "$BIN" --ignored --test-threads=1
```

Loopback delivers frames before the checksum is filled in, so the test injects
packets with complete UDP checksums through a raw socket, and first checks that
a corrupted checksum gets no reply.

### Namespace conformance tier

`netns_conformance.rs` needs `STAMP_NETNS_TESTS=1`, effective root (host root
or mapped root in a user namespace), `ip`, `tcpdump` and `ethtool`. Scenario 4b
also needs `STAMP_NETNS_PNET_BIN`. Commands, prerequisites and what each
scenario proves are in [testing-netns.md](../doc/testing-netns.md).

### User-namespace tests

These run as mapped root in a new user and network namespace, so they need no
host root and change no host network settings. Linux must allow unprivileged
user namespaces.

```bash
STAMP_MTU_NETNS_TESTS=1 unshare -Urn \
  cargo test --locked --test route_mtu_test -- --ignored --nocapture

STAMP_SCOPE_NETNS_TESTS=1 unshare -Urn \
  cargo test --locked --test scoped_ipv6_test -- --ignored --nocapture
STAMP_SCOPE_NETNS_TESTS=1 unshare -Urn \
  cargo test --locked --no-default-features --features ttl-pnet --test scoped_ipv6_test -- --ignored --nocapture

STAMP_EXTHDR_NETNS_TESTS=1 unshare -Urn \
  cargo test --locked --test ext_hdr_nix_test -- --ignored --nocapture
```

- `route_mtu_test` starts a reflector in a second namespace joined by a veth
  pair and changes interface and route MTUs there. See
  [Reply-route MTU regression](../doc/testing-netns.md#reply-route-mtu-regression).
- `scoped_ipv6_test` creates a veth pair and a nested namespace and uses
  independently built base, Type 12 and HMAC bytes; only the Return Address TLV
  uses the production encoder. The nix build checks wildcard and concrete
  binds; the pnet build checks concrete binds.
- `ext_hdr_nix_test` needs the namespace because the sender's sticky
  Destination Options header requires `CAP_NET_RAW`.

The private veth fixtures turn off TX checksum offload with `ethtool` on their
own interfaces, because the pnet backend rejects frames with incomplete
checksums.

### In CI

The `privileged` job in `.github/workflows/conformance.yml` builds each backend
without root, then uses `scripts/run_privileged_test.py` to run the three pnet
tests, the nine namespace scenarios and the route MTU test in required mode.
The script rejects an executable whose ignored-test count is wrong or zero, so
a build with the wrong backend cannot pass with an empty suite.
`scoped_ipv6_test` and `ext_hdr_nix_test` are not run in CI.

## Unit test coverage notes

Many protocol details are covered by unit tests inside `src/` rather than by
files in this directory.

- **TLV lists** (`src/tlv/list/`): ownership, mutation and removal, truncated
  tails, interleaved duplicate HMACs, padding on both sides of HMAC, and
  failure-echo flags and digests. Signing properties compare serialized
  coverage with contiguous HMAC input, including BER padding and structural
  edits; `src/crypto.rs` varies streaming chunk sizes. Run with
  `cargo test --locked --lib tlv::list`.
- **Reflector processing** (`src/receiver/tests.rs`): one base HMAC check, one
  provisioning check and one session acquisition per accepted packet, including
  all its burst copies, for IPv4/IPv6 and both sequencing modes. Also
  authentication failures before acquisition and cap, drain and expiry changes
  after a provisioning decision.
  `tracked_processing_validates_before_any_session_mutation` runs in pnet-only
  builds too.
- **Transmission** (`src/receiver/transmit/`): SRH, source, alternate address
  and CoS fallback combinations, final signatures, malformed tails, failed
  sends, Linux source pinning, interleaved IPv4/IPv6 socket options on one
  sender, and rejection of incomplete sends. Queue tests share one budget
  across concurrent producers, handoff, active sends and burst rescheduling.
- **pnet send worker** (`src/receiver/pnet.rs`):
  `transmit_worker_interleaves_requests_and_burst_deadlines` and the grace and
  deadline shutdown tests use ordinary UDP sockets and need no capture
  capability.
- **Sender validation** (`src/sender/tests.rs`): typed Access Report, CE,
  Micro-session and HMAC outcomes.
  `telemetry_flag_and_hmac_gates_match_decision_oracle` combines U/M/I
  boundaries with signed, unsigned, corrupt and unverifiable input for 44- and
  112-byte bases. Other tests cover missing keys or HMAC bytes, invalid Access
  Report lengths, duplicate HMACs, and identical decisions with output on or
  off in text, JSON and CSV.
- **Measurements** (`src/sender/measurements.rs`): late replies, per-probe
  burst targets, serial wrap and reset, counter gaps and reordering, Follow-Up
  repeats and ambiguity, and bounded histories.
- **Sessions** (`src/session/tests.rs`): counters, replay windows, Follow-Up
  isolation, expiry and persistent provisioning.
- **Statistics** (`src/stats/`): exact-to-histogram promotion at 4096 samples,
  bucket boundaries, quantile oracles, variance, fixed storage through one
  million samples, long-run RTT and one-way delay summaries, BER history
  retention and alarms, and clock quality (invalid, absent, unsynchronized).

## Platform notes

- **macOS.** CI runs the default and all-features suites natively through
  `scripts/run_native_tests.py`, which keeps the report and the full Cargo log.
  The route MTU unit tests run on macOS and check its source selection, without
  Linux source pinning. `keyset_fallback_test` checks key rotation and
  revocation on both platforms; on Linux it also checks that queued Type 12
  burst copies keep their accepted key, and on macOS that a size-controlled
  reply is dropped when the route MTU is unknown.
- **Windows.** CI requires `--lib` and eight integration targets (see
  [Windows runtime gate](../doc/release-evidence.md#windows-runtime-gate)).
  Burst scheduling and shutdown tests inject a known route MTU; another test
  covers an unavailable route MTU (injected on Linux, real on Windows). Startup
  error tests use wildcard binds and must report port and key failures before
  the pnet backend looks for a capture interface. The mixed-clock suite runs 20
  times; its subprocess helpers keep stdout, stderr and exit status when a peer
  receives nothing or a sender does not exit. None of this exercises the
  capture driver.

## Other test suites

- **Python wire fixtures.** `scripts/interop_stamp.py` checks the reflector
  against an independent Python implementation. See
  [testing-interop.md](../doc/testing-interop.md).
- **Release fixtures.** `scripts/release_checks.py` runs authenticated control
  API cases and a real Net-SNMP master. See
  [release verification](../doc/release-evidence.md).
- **Script unit tests.** `python3 -m unittest discover -s scripts/tests -v`
  tests the Python fixtures, the native test runner and the standards monitor.
- **Benchmark accounting.** `cargo test --locked --example live_udp_bench`
  checks the live benchmark's reply validation and loss, duplicate and
  reordering accounting. See [benchmarks.md](../doc/benchmarks.md).
- **Fuzzing.** See [fuzz/README.md](../fuzz/README.md).
