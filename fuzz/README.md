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
| `tlv_list_parse` | `TlvList::parse(&[u8])` — strict TLV chain parser. |
| `tlv_list_parse_lenient` | `TlvList::parse_lenient(&[u8])` — the variant the receive path actually uses. |
| `raw_tlv_parse` | `RawTlv::parse(&[u8])` — single-TLV header parse. |
| `packet_unauth_parse` | `PacketUnauthenticated::from_bytes{,_lenient}`. |
| `packet_auth_parse` | `PacketAuthenticated::from_bytes{,_lenient_with_canonical}`. |
| `agentx_decode_header` | AgentX PDU header decode (RFC 2741 §6). |
| `agentx_decode_oid` | AgentX OID + SearchRange decode. |

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

A nightly GitHub Actions job runs each target for 60 seconds against
`origin/master`. Crashes are uploaded as artifacts. The job is gated
behind a manual trigger to avoid spending minutes on every PR; see
`.github/workflows/fuzz.yml` (added separately).
