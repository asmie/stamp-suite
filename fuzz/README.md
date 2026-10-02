# Fuzz targets

libfuzzer-based fuzz harnesses for the byte-level parsers most exposed to
hostile input. Excluded from the workspace (see `[workspace] exclude` in
the top-level `Cargo.toml`) so default `cargo build` / `cargo test` runs
don't pull in `libfuzzer-sys` and don't require a nightly compiler.

## Setup

```bash
cargo install cargo-fuzz       # one-time
rustup toolchain install nightly
```

## Running a target

```bash
cargo +nightly fuzz run tlv_list_parse_lenient
```

Or pin a wall-clock budget (e.g. one minute, used by the CI fuzz job
below):

```bash
cargo +nightly fuzz run tlv_list_parse_lenient -- -max_total_time=60
```

## Targets

| Target | Code under test |
| --- | --- |
| `tlv_list_parse` | `TlvList::parse`, the strict TLV parser. Accepted input must serialize back to itself, with reserved flag bits cleared. |
| `tlv_list_parse_lenient` | `TlvList::parse_lenient`, the parser the receive path uses. |
| `raw_tlv_parse` | `RawTlv::parse`, with the same round-trip check for one TLV. |
| `packet_unauth_parse` | `PacketUnauthenticated::from_bytes` (round trip) and `from_bytes_lenient`. |
| `packet_auth_parse` | `PacketAuthenticated::from_bytes` (round trip) and `from_bytes_lenient_with_canonical`. |
| `agentx_decode_header` | AgentX PDU header decoding (RFC 2741 §6). |
| `agentx_decode_oid` | AgentX OID and SearchRange decoding. |
| `process_stamp_packet` | Reflector processing from parsing to the reply. The first input byte turns on an HMAC key, required and verified HMACs, strict parsing, ignore mode and captured headers. |
| `sender_reply` | The sender's reply processing (`sender::fuzz_reply`) with measurements, BER, Access Report and congestion state active. The first byte selects authenticated mode, TLVs, a key and a required Micro-session ID. |

## Seed corpus

`cargo fuzz` will create an initial corpus under
`fuzz/corpus/<target>/` automatically. For seeded coverage, drop
known-interesting samples there. The integration tests already exercise
hand-crafted boundary inputs that make good seeds:

- `tests/malformed_input_test.rs` — every parser boundary the audit
  identified.
- `tests/tlv_flag_semantics.rs` — TLVs with each U/M/I/C flag bit set.
- `tests/loopback_test.rs` — real wire packets dumped via `tcpdump -x`.

## CI

`.github/workflows/fuzz.yml` runs every target for 60 seconds each Sunday
and on manual dispatch, which can set another duration. Each target's corpus
is cached between runs. Crashes and the corpus are uploaded as artifacts.
