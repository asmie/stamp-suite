# Integration test layout

Default `cargo test --all-features` runs every test in this directory that
doesn't require special privileges. A small set of tests is gated either
by Cargo features or by `#[ignore]` so unprivileged CI passes cleanly;
this file documents the opt-in invocations.

## Files

| File | Purpose | Default-run? |
| --- | --- | --- |
| `config_file_test.rs` | TOML config parsing and validation. | yes |
| `loopback_test.rs` | UDP-loopback round-trips on `127.0.0.1` (and one `[::1]`). | yes |
| `burst_transmission_test.rs` | Live interleaved burst replies: IPv4/IPv6, open/auth, NTP/PTP, stateless/stateful, CoS, DM, Follow-Up, HMAC, and kernel TX correlation. | yes, Linux nix |
| `idle_cpu_test.rs` | Real reflector process: bounded idle CPU after traffic, then receipt of another packet; IPv4/IPv6 and optional kernel timestamps. Linux nix backend; reads child CPU accounting from `/proc`. | yes, Linux nix |
| `loopback_ipv6_test.rs` | TLV-by-TLV IPv6 parity via `process_stamp_packet`. | yes |
| `tlv_flag_semantics.rs` | RFC 8972 U/M/I + draft-asymmetrical C flag conformance. | yes |
| `ber_regression_test.rs` | BER (Types 240/241/242) on-wire counts. | yes |
| `mixed_clock_test.rs` | Live sender against independent NTP/PTP peer encoding in both mixed directions; IPv4 open, IPv6 authenticated, explicit UTC offset. | yes |
| `ptp_e2e_test.rs` | PTP timestamp encoding + Type 3 sync-source reporting. | yes |
| `malformed_input_test.rs` | Hand-crafted hostile byte sequences at every parser boundary. | yes |
| `pnet_loopback_test.rs` | Real pnet capture on the `lo` interface. | **no — see below** |

The shared transmission unit tests cover SRH/source/alternate-address/CoS
fallback combinations, final signatures, malformed-tail preservation, failed-send
accounting, and real Linux source pinning. The pnet-only library test
`transmit_worker_interleaves_requests_and_burst_deadlines` exercises the send
worker with ordinary UDP sockets and needs no raw capture capability:

```bash
cargo test --locked --no-default-features --features ttl-pnet --lib
```

`--all-features` selects the nix backend; use the explicit pnet-only build above
to compile and exercise the pnet worker.

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

The tests will **skip themselves** (print a notice and return success)
if the running process has neither uid 0 nor `CAP_NET_RAW` in its
effective set, so the wrong invocation can't produce a false failure.

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
