# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **draft-ietf-ippm-asymmetrical-pkts Reflected Test Packet Control TLV (Type 12)**:
  asymmetrical reply measurement
  - `ReflectedControlTlv` struct (Length / Count / Interval + opaque sub-TLV bytes)
  - Reflector emits up to `REFLECTED_CONTROL_MAX_COUNT` (16) reply packets per
    request, spaced by the requested interval (clamped to
    `REFLECTED_CONTROL_MIN_INTERVAL_NS` of 1 µs). Excess count, clamped interval,
    or any non-zero requested length sets the new Conformant (C) flag on the
    echoed TLV.
  - nix backend emits extra copies on a spawned tokio task so the recv loop is
    not blocked; pnet backend sleeps inline (fallback platforms only).
  - New C-flag bit (0x10) added to `TlvFlags` and `RawTlv::set_conformant_reflected()`.
    The draft leaves the C bit position TBA; we place it at bit 3, the first bit
    unused by RFC 8972's U/M/I triple.
  - Sender CLI: `--reflected-control-count`, `--reflected-control-length`,
    `--reflected-control-interval-ns`.
- **draft-gandhi-ippm-stamp-ber BER TLVs**:
  - Bit Pattern in Padding (Type 240), Bit Error Count in Padding (Type 241),
    Max Bit Error Burst Size (Type 242). Type numbers are TBD in the draft;
    240/241/242 from RFC 8972's experimental range.
  - Reflector XORs the received Extra Padding against the Bit Pattern TLV (or
    the draft's 0xFF00 default), counts error bits and longest consecutive run
    across byte boundaries, and writes the results into the Count and Max Burst
    TLVs.
  - Missing Extra Padding or duplicate BER TLVs mark all BER TLVs with the
    U-flag per draft §3.
  - Sender CLI: `--ber`, `--ber-pattern <HEX>`, `--ber-padding-size`.

- **RFC 9534 Micro-session ID TLV**: Per-member-link performance measurement on LAGs
  - Micro-session ID TLV (Type 11) with sender and reflector member link identifiers
  - `--micro-session-id <ID>` sender CLI option to identify the local LAG member link
  - `--reflector-member-link-id <ID>` reflector CLI option to fill in reflector-side member link ID
  - Reflector validates non-zero reflector ID in received TLV (discards on mismatch per RFC 9534 §3.2)
  - Full `MicroSessionIdTlv` struct with `new`/`from_raw`/`to_raw` and `TlvList::update_micro_session_id_tlvs()`
- `SenderSnmpStats::inc_lost_by(count)` for batched loss counter updates
- `record_packets_lost(count)` batch metrics API for sender loss events

### Fixed

- AgentX OID decode (`decode_oid`) now requires 8 bytes minimum instead of 4, preventing panic when reading `prefix`/`include` fields from short buffers
- AgentX OID decode uses `checked_mul`/`checked_add` for expected buffer length to prevent overflow on 32-bit targets with crafted wire data
- Sender interim report (`--report-interval`) now uses confirmed `packets_lost` counter instead of `pending.len()`, which incorrectly counted in-flight packets as lost
- SNMP `loss_pct_x100` is now computed on read instead of cached, preventing stale values when `packets_sent` increases without corresponding loss events

- Sender timeout eviction replaced O(n) full HashMap scan with O(k) `VecDeque`-based lazy eviction queue; deadlines are naturally time-ordered since packets are sent sequentially
- Final sender loss accounting uses batched `inc_lost_by()` and `record_packets_lost()` instead of per-packet loops
- Reflector TLV semantic processing (CoS, Timestamp Info, Direct Measurement, Location, Follow-Up Telemetry, Destination Node Address, Micro-session ID, Return Path, HMAC recomputation) extracted into shared `apply_semantic_tlv_processing()` helper, eliminating duplication between `assemble_unauth_answer_with_tlvs` and `assemble_auth_answer_with_tlvs`
- `TlvList::validate_known_tlv_lengths()` refactored to use shared `validate_known_tlv_lengths_slice()` helper operating on both `tlvs` and `wire_order_tlvs`
- `TlvList::update_micro_session_id_tlvs()` uses shared `apply_micro_session_id()` helper for both TLV vectors

### Removed

- `SenderStatsSnapshot` struct and `SenderSnmpStats::update_from_snapshot()` — all sender SNMP counters are now updated live; the final-snapshot path was dead code

## [0.5.0] - 2026-02-13

### Added

- **SNMP AgentX Sub-Agent**: MIB-based monitoring via net-snmpd (requires `snmp` feature, Unix only)
  - Minimal AgentX protocol implementation (RFC 2741) with no external SNMP crate dependency
  - STAMP-SUITE-MIB under enterprise OID `.1.3.6.1.4.1.65134` with SMIv2 definition (`mibs/STAMP-SUITE-MIB.mib`)
  - Reflector subtree: configuration scalars, packet counters (received/reflected/dropped), active session count, uptime
  - Session table: per-client address, port, packet counts, last sequence number, last active time
  - Sender subtree: configuration scalars, packets sent/received/lost, RTT min/max/avg, jitter, loss percentage
  - Live sender statistics updated in the hot path (received, RTT min/max/avg, jitter) — SNMP polling during long runs reflects current progress
  - `--snmp` and `--snmp-socket <PATH>` CLI options
- `SessionManager::session_summaries_extended()` for retrieving per-session state
- `ReceiverSharedState` struct for sharing counters and session manager between receiver backends and SNMP

### Fixed

- pnet backend no longer drops valid fallback responses for Return-Path alternate IPv6 targets; the early-return gate that bypassed the try_send + U-flag fallback path has been removed
- `snmp` feature is now platform-gated with `cfg(unix)` — on non-Unix platforms, `--snmp` prints a clear error and exits instead of failing to compile

### Changed

- Receiver backends (`nix.rs`, `pnet.rs`) now accept `&ReceiverSharedState` instead of creating their own `Arc<ReflectorCounters>` and `Arc<SessionManager>` internally
- `run_sender` accepts an optional `Arc<SenderSnmpStats>` (behind `snmp` feature gate) for live statistics export

## [0.4.0] - 2026-02-11

### Added

- **RFC 9503 Segment Routing Extensions**: STAMP extensions for SR-MPLS and SRv6 networks
  - Destination Node Address TLV (Type 9): sender specifies intended reflector address; reflector sets U-flag on mismatch
  - Return Path TLV (Type 10) with sub-TLV support:
    - Control Code sub-TLV: suppress reply (code 0) or request same-link reply (code 1); reserved bits ignored per RFC 9503
    - Return Address sub-TLV: reflector sends reply to an alternate IP address
    - SR-MPLS Label Stack sub-TLV: proper MPLS LSE encoding (Label/TC/S/TTL); echoed with U-flag (userspace SR forwarding unsupported)
    - SRv6 Segment List sub-TLV: echoed with U-flag (userspace SR forwarding unsupported)
  - `--dest-node-addr <IP>` sender CLI option (requires `--ssid`)
  - `--return-path-cc <CODE>` sender CLI option (0=suppress, 1=same-link)
  - `--return-address <IP>` sender CLI option for alternate reply address
  - `--return-sr-mpls-labels <LABELS>` sender CLI option (comma-separated 20-bit labels)
  - `--return-srv6-sids <SIDS>` sender CLI option (comma-separated IPv6 SIDs)
- Alternate-address send failure fallback: on failure, reflector sets U-flag on Return Path TLV, recomputes HMAC, and retries to original source address
- Local address enumeration for Destination Node Address matching (nix: `getifaddrs`, pnet: `datalink::interfaces`)

### Fixed

- SR-MPLS labels are now encoded as proper MPLS Label Stack Entries (Label<<12 | TC | S-bit | TTL) instead of raw u32 values
- Return Path Control Code decoding uses `cc & 1` bit masking instead of rejecting reserved bits, per RFC 9503
- `--return-sr-mpls-labels` and `--return-srv6-sids` now correctly conflict with each other at the CLI level

### Changed

- `ProcessingContext.local_addresses` changed from `Vec<IpAddr>` to `&[IpAddr]` to avoid per-packet cloning in hot path

## [0.3.1] - 2026-02-08

### Changed

- Multiple optimizations and refactorings.

## [0.3.0] - 2026-02-08

### Added

- **RFC 8972 TLV Extension Support**: Full implementation of Type-Length-Value extensions
  - New `tlv` module with `TlvFlags`, `TlvType`, `RawTlv`, `TlvList`, `ExtraPaddingTlv`, `HmacTlv`, and `SessionSenderId` types
  - TLV handling modes: `ignore` (strip TLVs) and `echo` (reflect TLVs with appropriate flags)
  - `--tlv-mode` CLI option to control TLV handling behavior (default: `echo`)
  - `--verify-tlv-hmac` CLI option to verify incoming TLV HMAC
  - `--ssid` CLI option for sender to include Session-Sender Identifier in Extra Padding TLV
  - HMAC TLV (Type 8) support for TLV integrity verification
  - Proper flag handling: U-flag for unrecognized types, M-flag for malformed TLVs, I-flag for integrity failures
- Extended packet types: `ExtendedPacketAuthenticated`, `ExtendedPacketUnauthenticated`, and their reflected variants
- Lenient packet parsing with `from_bytes_lenient()` methods for short-packet interoperability (RFC 8762 Section 4.6)
- Canonical buffer support for HMAC verification of zero-padded short packets
- Wire-order preservation for TLV failure echo paths per RFC 8972 Section 4.8
- Truncated TLV byte-exact echo: preserves original wire length in header for malformed TLVs
- Sender-side TLV validation with `validate_reflected_tlvs()` helper
- Configuration validation: `--verify-tlv-hmac` now requires `--hmac-key` or `--hmac-key-file`

### Changed

- **Breaking**: `auth_mode` now only accepts exactly `A` (authenticated) or `O` (open/unauthenticated)
  - Composite strings like `AO` are no longer valid (modes are mutually exclusive per RFC 8762)
  - `is_auth()` and `is_open()` now use exact string matching instead of substring search
- Receiver assembly functions updated to handle TLV extensions
- Both `nix` and `pnet` receiver backends updated for TLV-aware packet processing
- HMAC verification in authenticated mode now uses canonical zero-padded buffers

### Fixed

- Sender TLV-HMAC validation now uses fixed base offset (44/112 bytes) instead of fragile inference from packet length
- Short authenticated packets are now properly zero-filled before HMAC verification
- Malformed TLVs are echoed byte-exactly with original declared length preserved

### Removed

- Removed unsupported `process` TLV handling mode from documentation
- Removed `E` (encrypted) auth mode option (not defined in RFC 8762)

## [0.2.0] - 2024-12-01

### Added

- Multi-session support in reflector with `SessionManager`
- Stateful reflector mode (`--stateful-reflector`) per RFC 8972
- Session timeout configuration (`--session-timeout`)
- HMAC authentication support with `--hmac-key` and `--hmac-key-file` options
- `--require-hmac` option to mandate HMAC verification
- Error estimate configuration (`--error-scale`, `--error-multiplier`, `--clock-synchronized`)
- Integration tests using loopback interface
- RFC 8762 compatibility improvements

### Changed

- Improved packet serialization using big-endian encoding
- Enhanced error handling throughout the codebase

## [0.1.0] - 2024-01-01

### Added

- Initial implementation of STAMP protocol (RFC 8762)
- Session-Sender and Session-Reflector modes
- Unauthenticated and authenticated packet formats
- NTP and PTP timestamp support
- IPv4 and IPv6 support
- Basic RTT and packet loss statistics
- CLI interface with clap
