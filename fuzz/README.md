# Fuzz targets

This directory holds libFuzzer harnesses for the byte-level parsers and packet
paths most exposed to hostile input. It is for contributors who change parsing
or packet processing.

The `fuzz` package is excluded from the main workspace (`[workspace] exclude`
in the top-level `Cargo.toml`), so ordinary `cargo build` and `cargo test` runs
do not build `libfuzzer-sys` or need a nightly compiler. It depends on
stamp-suite with default features off and the `snmp` feature on, which exposes
the AgentX decoders.

## Setup

```bash
cargo install cargo-fuzz
rustup toolchain install nightly
```

## Running a target

Run from the repository root or from `fuzz/`:

```bash
cargo +nightly fuzz run tlv_list_parse_lenient
```

Limit the run time (the scheduled CI job uses 60 seconds per target):

```bash
cargo +nightly fuzz run tlv_list_parse_lenient -- -max_total_time=60
```

Crashes are written to `fuzz/artifacts/<target>/` and the growing corpus to
`fuzz/corpus/<target>/`.

## Targets

These are the `[[bin]]` entries in `fuzz/Cargo.toml`.

| Target | Code under test |
| --- | --- |
| `tlv_list_parse` | `TlvList::parse`, the strict TLV parser. Accepted input must serialize back to itself, with reserved flag bits cleared. |
| `tlv_list_parse_lenient` | `TlvList::parse_lenient`, the parser the receive path uses. |
| `raw_tlv_parse` | `RawTlv::parse`, with the same round-trip check for one TLV. |
| `packet_unauth_parse` | `PacketUnauthenticated::from_bytes` (round trip) and `from_bytes_lenient`. |
| `packet_auth_parse` | `PacketAuthenticated::from_bytes` (round trip) and `from_bytes_lenient_with_canonical`. |
| `agentx_decode_header` | AgentX PDU header decoding (RFC 2741 §6). |
| `agentx_decode_oid` | AgentX OID and SearchRange decoding. |
| `process_stamp_packet` | Reflector processing from parsing to the reply. The first input byte selects an HMAC key, required and verified HMACs, strict parsing, ignore mode and captured headers. It calls the processing entry point without the live path's panic guard, so a panic reaches libFuzzer. |
| `sender_reply` | The sender's reply processing (`sender::fuzz_reply`) with measurements, BER, an Access Report exchange and congestion state active. The first byte selects authenticated mode, TLV parsing, a key and a required Micro-session ID. |

## Seed corpus

`cargo fuzz` creates an empty corpus under `fuzz/corpus/<target>/` on the first
run. For better coverage, add known-interesting inputs there. The integration
tests contain hand-built boundary inputs that make good seeds:

- `tests/malformed_input_test.rs`: short and oversized base packets, broken TLV
  layouts, HMAC ordering and Return Path sub-TLVs.
- `tests/tlv_flag_semantics.rs`: TLV chains with each U, M, I and C flag set.
- `tests/proptest_tlv.rs`: property tests that run the same parsers and the
  AgentX decoders on arbitrary bytes in every `cargo test` run.

## CI

- `.github/workflows/fuzz.yml` runs every target listed above for 60 seconds
  each Sunday at 03:30 UTC, and on manual dispatch, which can set another
  duration. Each target's corpus is cached between runs. When a target fails,
  its crash artifacts and corpus are uploaded.
- The `fuzz-build` job in `.github/workflows/conformance.yml` runs
  `cargo check --locked --manifest-path fuzz/Cargo.toml` on stable, so the
  harnesses keep compiling between scheduled runs.
