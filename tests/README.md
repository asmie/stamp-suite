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
| `loopback_ipv6_test.rs` | TLV-by-TLV IPv6 parity via `process_stamp_packet`. | yes |
| `tlv_flag_semantics.rs` | RFC 8972 U/M/I + draft-asymmetrical C flag conformance. | yes |
| `ber_regression_test.rs` | BER (Types 240/241/242) on-wire counts. | yes |
| `ptp_e2e_test.rs` | PTP timestamp encoding + Type 3 sync-source reporting. | yes |
| `malformed_input_test.rs` | Hand-crafted hostile byte sequences at every parser boundary. | yes |
| `pnet_loopback_test.rs` | Real pnet capture on the `lo` interface. | **no — see below** |

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
