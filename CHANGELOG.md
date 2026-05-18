# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.8.0] - 2026-05-18

### Added

- **Per-SSID HMAC key set (B6)** — `--hmac-key-dir <DIR>` flag and new
  `crypto::HmacKeySet` type let a single reflector serve multiple
  senders without sharing a key. Each file's name (minus extension) is
  the SSID in hex; an optional `default.key` is the fallback for
  unknown SSIDs. Mutually exclusive with `--hmac-key` /
  `--hmac-key-file`; the legacy single-key path is preserved. The
  reflector peeks the incoming packet's SSID, resolves the per-SSID
  key, and uses it for both verification and response HMAC.
- **Per-client token-bucket rate limiting (B4)** — rewrote `RateLimiter`
  from a fixed-window counter to a true token bucket keyed by
  `(source_ip, ssid)`. New `--reflector-rate-burst` flag tunes bucket
  capacity independently of `--max-pps` (which retains its old
  semantic of "tokens / second"; `burst = 0` falls back to `rate` for
  backward compat). New `packets_rate_limited` counter distinguishes
  rate-limit drops from generic drops in metrics and SNMP. Reflected
  Test Packet Control (Type 12) extra-copy emission consumes one
  token per extra send and breaks the loop early on bucket
  exhaustion, so an asymmetric burst cannot exceed the per-client
  budget.
- **Reflected Test Packet Control Type 12 — draft-14 alignment (A1)** —
  the reflector now honours the requested reply length by inserting an
  `ExtraPaddingTlv` ahead of the HMAC TLV up to a configurable cap;
  parses Layer-3 Address Group sub-TLV (Type 11) and drops the packet
  (via `ReturnPathAction::SuppressReply`) when no local address
  matches the requested prefix per draft §3; parses Layer-2 Address
  Group sub-TLV (Type 10) and sets the U flag on the echoed Type 12
  when MAC visibility isn't available (UDP-socket backends). New
  CLI flags `--reflected-control-max-count`,
  `--reflected-control-max-size`,
  `--reflected-control-min-interval-ns` expose the previously
  compile-time amplification caps as runtime config. Minimum
  value-field size raised from 8 to 12 octets per draft §3; the
  encoder zero-pads short emissions to 12 bytes (placeholder sub-TLV
  header) so existing single-TLV senders stay on the wire.
- **`draft-ietf-ippm-stamp-ext-hdr-08` Type 247 length-mismatch
  conformance (A3)** — the Reflected Fixed Header Data TLV's Length
  MUST equal 20 (IPv4) or 40 (IPv6) per §5.2. If the sender's
  requested Length doesn't match the captured header size (e.g. a
  20-byte request reaches an IPv6 reflector), the reflector now
  zero-fills the Value and sets the U-flag rather than silently
  truncating or padding. New `log_reflected_hdr_length_mismatch_once`
  helper emits a one-time warning citing draft §5.2.
- **Structured logging via `tracing-subscriber` (D5)** — new
  `--log-format text|json` flag selects between the historic
  human-readable single-line output (default) and one-line-per-event
  JSON suitable for Fluent Bit, Vector, or journald JSON forwarding.
  `tracing-log` bridges existing `log::*` call sites so the
  conversion is transparent. `RUST_LOG` continues to control
  verbosity in both modes.
- **`--print-config-schema` for TOML config validation (D4)** — dumps
  a hand-maintained JSON Schema (draft 2020-12) for the
  `FileConfiguration` accepted by `--config`. Pair with the
  `jsonschema` CLI or an IDE plugin for autocomplete /
  pre-deployment validation. Hand-maintained alongside the struct;
  a coverage test fails loudly when a new TOML field has no
  corresponding schema property.
- **Defensive hardware-timestamping scaffold (F1)** — new `hwtstamp`
  Cargo feature (default-off), `--hwtstamp auto|on|off` flag,
  `crypto::HwTsMode` enum, capability probe stub, and
  `effective_method` resolver that picks `HwAssist` vs `SwLocal` per
  direction. `auto` (default) silently falls back to software when
  the kernel/NIC doesn't advertise support; `on` fails-fast at
  startup; `off` always uses software. The kernel-side
  `SO_TIMESTAMPING` / `MSG_ERRQUEUE` wiring is a tracked follow-up;
  the public API is in place so call sites won't change when it
  lands.
- **Capture-thread liveness signal (B2)** — new `capture_alive: Arc<AtomicBool>`
  on `ReceiverSharedState`. Both backends clear the flag when their
  receive loop exits unexpectedly (interface-not-found, channel-init
  failure, send-socket bind failure, `spawn_blocking` panic) so a
  future readiness probe and `systemd`'s `MonitorPolicy` can tell
  "process alive but not reflecting" from "process alive and
  healthy." Every `eprintln!` in the pnet capture path replaced with
  structured `log::error!` / `log::warn!`.
- **AgentX sub-agent panic-resistance (B1)** — audited every
  `unwrap()` / `panic!` / `unreachable!()` reachable from the AgentX
  event loop (`agentx::decode_header`, `decode_oid`,
  `decode_search_range`, `handle_get_bulk`, `MibHandler::get` /
  `get_next`); confirmed every buffer-indexing site is preceded by
  an explicit length check returning `AgentXError::Protocol`. Added
  a supervisor task that observes the `spawn_blocking` JoinHandle so
  an unforeseen panic logs `JoinError::is_panic()` instead of being
  silently dropped. Module-level doc comment in `src/snmp/mod.rs`
  records the audit conclusion so a future reader doesn't redo it.
- **Asymmetric observability failure semantics (B3)** — `--metrics`
  fails fast on bind error with the specific `io::ErrorKind`
  (AddrInUse / AddrNotAvailable / PermissionDenied) in the exit
  message; `--snmp` degrades gracefully on missing AgentX master,
  logs a warning, and continues. Reasoning: silent metrics disable
  leaves dashboards blind; silent SNMP disable doesn't affect the
  reflector's primary duty. Documented in `doc/usage.md`.

### Changed

- **`apply_semantic_tlv_processing` thread the resolved HMAC key** —
  `process_auth_packet` now takes an explicit `resolved_hmac_key`
  parameter set by `process_stamp_packet` after a per-SSID lookup,
  replacing the previous direct read of `ctx.hmac_key`. Required by
  the new `HmacKeySet` path; the single-key path is unchanged because
  the legacy field still feeds `resolve_hmac_key()` when no set is
  configured.
- **`REFLECTED_CONTROL_TLV_FIXED_FIELDS_SIZE` constant** — added
  alongside the raised-to-12 minimum so the parser can address the
  fixed header (length + count + interval) and the sub-TLV chain
  separately without re-deriving the offset.
- **TLV reference table in `doc/architecture.md`** — adopt
  `supported / partial / experimental / interop-only` labels.
  Type 10 → partial (SR-MPLS / SRv6 echoed with U-flag). Type 12 →
  supported (post-A1). Types 246 / 247 → partial (pnet backend only).
  Type 242 documented as having a wire-format collision with
  teaparty's Heartbeat use of the same byte; both implementations
  are in the experimental range so neither is wrong per IANA, but
  mixed deployments need to pick one.
- **Operational characteristics section** (new in `doc/architecture.md`):
  `--strict-packets` contract, `capture_alive` semantics, metrics
  fail-fast vs SNMP graceful, AgentX panic-audit results, and the
  new `--hwtstamp` modes.

### Fixed

- **RFC 8972 §3 `set_reflected_control_u_flag`** — when a Layer-2
  Address Group sub-TLV arrives on a backend without MAC visibility,
  the reflector now sets the U flag on the echoed Type 12 TLV and
  continues processing. Previously the sub-TLV was silently ignored,
  giving the sender no signal that the filter wasn't honoured.

### Tests

- **Malformed-input suite (C6)** — 12 hand-crafted hostile byte
  sequences across base-packet length boundaries (RFC 8762 §4.1.x),
  TLV-header length-field abuses (overflow, u16::MAX, truncated
  header), HMAC ordering violations (TLV after HMAC, wrong-length
  HMAC value, corrupted digest → I-flag on every TLV per §4.8),
  Return Path sub-TLV nesting overflow, and high-entropy spot
  checks. Implementation handles every case correctly — no
  production change.
- **TLV flag-semantics audit (A7)** — 15 tests pinning the
  RFC 8972 §3 / §4.8 + draft-asymmetrical §3 U/M/I/C wire bit
  positions (0x80 / 0x40 / 0x20 / 0x10), unknown-type echo with U,
  length-mismatch with M, HMAC failure with I on every TLV
  (packet still echoed), Reflected Control clamping with C, plus
  flag-independence negative controls.
- **BER on-wire regression (A4)** — 6 tests covering clean
  channel, single-bit flip, intra-byte 3-bit burst, cross-byte
  4-bit burst (exercises the MSB-first bit walker), sender
  hex-dump verification, and a custom non-default pattern.
- **PTP timestamp end-to-end (A8)** — 6 tests covering wire-encoding
  distinction (NTP-vs-PTP epoch offset), Type 3 TLV
  `sync_src_out` reporting under PTP and NTP reflector modes,
  mixed-mode preservation of sender-declared sync source, and
  big-endian timestamp placement at byte offset 4..12.
- **Stats edge cases (C11)** — 10 tests covering RFC 3550 jitter
  on single-sample / zero-jitter / negative-skew / alternating
  patterns, two-sample std-dev boundary, large-RTT u128 overflow
  safety, percentile of empty set and out-of-range p, single-sample
  percentile off-by-one, and zero-sent loss_percent NaN guard.
- **IPv6 TLV-by-TLV parity (C4)** — 10 tests driving every major
  reflector code path with an IPv6 source: unauth + auth round
  trips, CoS DSCP/ECN echo, RFC 9503 Destination Node Address
  match / mismatch, Micro-session ID, BER trio, Location sub-TLVs,
  combined auth+CoS, unknown-TLV U-flag.
- **Multi-key HMAC integration (B6)** — 6 tests: legacy single-key
  SSID=0 / non-zero compat, per-SSID happy path, wrong-key-for-SSID
  rejection, unknown-SSID + `require_hmac` drop, default-key
  fallback for missing per-SSID entries.
- **pnet backend integration (C10)** — 3 `#[ignore]`'d tests that
  spin up a real pnet receiver on the `lo` interface and round-trip
  open mode, authenticated mode, and a TLV chain. Self-skip when
  the process lacks `CAP_NET_RAW`. Gated by
  `target_os = "linux" + feature = "ttl-pnet" + not ttl-nix`.
  `tests/README.md` documents the privileged-run invocation.
- **AgentX malformed-PDU coverage (C9)** — 8 tests on the public
  decoders + 4 OID-boundary tests on the handler dispatch, locking
  in the B1 audit invariant that every buffer index is bounds-checked.
- **Rate-limit isolation (B4)** — 7 tests: burst exhaustion,
  multi-client isolation (greedy client doesn't drain a polite
  one), per-SSID isolation (same IP, different SSIDs → independent
  buckets), atomic `allow_n`, sustained-rate refill, backward-compat
  burst=0, expired-bucket reaping.
- **`--strict-packets` contract (B7)** — 7 tests pinning the
  lenient-vs-strict asymmetry across short / full / empty buffers
  in both modes, MBZ-always-ignored per RFC 8762 §4.1.1, and
  require_hmac interactions.
- **Property-based + libfuzzer harnesses (C5)** — 16 proptest cases
  (default `cargo test` run) covering typed-TLV round-trips and
  arbitrary-bytes no-panic invariants for every parser. Seven
  cargo-fuzz targets under `fuzz/` (workspace-excluded, nightly-only)
  exercise the same code paths via libfuzzer. New manual /
  weekly GitHub Actions workflow runs each fuzz target for 60s
  and uploads crashes as artifacts.
- **Criterion benchmark suite (E2)** — `benches/reflector_hotpath.rs`
  measures `process_stamp_packet` end-to-end without UDP: open mode
  no-TLV (~100 ns/op), one TLV, full chain, authenticated mode HMAC
  success path, authenticated full chain. Reference numbers in
  `doc/architecture.md` for regression triage.

### CI / build

- **`mib-lint` job** — runs `smilint -l 4` against
  `mibs/STAMP-SUITE-MIB.mib` on every push/PR. Package install
  tries `smitools` (Ubuntu 24.04+) then falls back to
  `libsmi2-bin` for older base images.
- **`fuzz.yml` workflow** — manual / weekly cron; matrix-builds and
  runs each of the seven cargo-fuzz targets for 60s. Failures
  upload `fuzz/artifacts/` + `fuzz/corpus/`.
- **`windows-2022` pin** — Windows test and build-release jobs pin
  to `windows-2022` instead of `windows-latest`. The
  `windows-2025` rollover dropped the bundled tooling that was
  satisfying pnet's load-time `wpcap.dll` / `Packet.dll` imports,
  and the Npcap silent installer hangs on Server 2025 (UAC +
  driver-signing prompts). Long-term answer is to gate pnet behind
  a Cargo feature on Windows.
- **Documentation refresh** — `doc/architecture.md` reorganised
  with a new "Operational Characteristics" section, a Hardware-
  Assisted Timestamping section, a Benchmarks section, and an
  updated TLV table.

## [0.7.0] - 2026-05-04

### Added

- **draft-ietf-ippm-stamp-ext-hdr Reflected Fixed / IPv6 Extension Header Data
  TLVs (Types 247 / 246)**: let the sender ask the reflector to echo the raw
  bytes of the received IP fixed header (Type 247 — 20 B IPv4 or 40 B IPv6)
  and IPv6 Hop-by-Hop / Destination Options extension headers (Type 246),
  which allows end-to-end diagnostics of DSCP remarking, TTL decrement,
  Flow Label rewriting, and in-path tampering with IPv6 options.
  - New typed TLVs `ReflectedFixedHdrTlv` and `ReflectedIpv6ExtHdrTlv`
    implementing `TypedTlv`, plus `TlvType::ReflectedFixedHdr` /
    `ReflectedIpv6ExtHdr` enum variants and length validation that treats
    the Value as variable-length (sender pre-allocates a zero-filled
    Value sized to the expected header length per draft-ietf-ippm-stamp-ext-hdr;
    populated bytes on response).
  - New `CapturedHeaders` struct threaded through `ProcessingContext` so the
    reflector's TLV processing can see the raw IP-layer bytes captured at
    receive time.
  - New `TlvList::process_reflected_headers()` invoked from
    `apply_semantic_tlv_processing` — copies captured bytes into the TLV or
    sets the U-flag when the backend cannot observe the IP layer.
  - `pnet` backend populates `CapturedHeaders` from `Ipv4Packet` / `Ipv6Packet`
    and walks Hop-by-Hop (NextHeader=0) / Destination Options (NextHeader=60)
    in wire format (NextHeader byte + HdrExtLen byte + body, per RFC 8200);
    non-options headers (Routing, Fragment, ESP, AH) stop the walk, matching
    the draft's scope. For IPv4 only the fixed 20-byte header is copied —
    IPv4 options are intentionally dropped.
  - `nix` backend passes `captured_headers: None` unconditionally; the
    reflector echoes the TLV empty with the U-flag set per RFC 8972 §4.2
    and emits a one-time log warning suggesting a rebuild with
    `--features ttl-pnet` if header reflection is genuinely required. An
    empty Value on an IPv4 packet or an IPv6 packet without extension
    headers is legitimate and does **not** set the U-flag.
  - Sender CLI: `--reflected-fixed-hdr`, `--reflected-ipv6-ext-hdr` (plus
    matching `FileConfiguration` TOML fields). Sender attaches a zero-filled
    request TLV sized to the destination's IP family for Type 247 and an
    8-byte default (one option's worth) for Type 246; reflector fills them
    on the pnet backend or U-flags them on nix.

### Fixed

- **RFC 8972 §4.4.1 sender flag default**: `TlvFlags::for_sender()` now
  returns `U=1, M=0, I=0` instead of all-zero. The RFC requires the
  Session-Sender to send every TLV with the U flag set; the reflector then
  overwrites it. Sender-built TLVs (`RawTlv::new`) inherit the corrected
  default. Visible on the wire as the leading flag byte of every outgoing
  TLV flipping from `0x00` to `0x80`.
- **RFC 8972 §4.4.1 reflector flag overwrite**: the reflector now clears
  U, M, and I on every parsed TLV before the type-recognition / length-
  validation / HMAC-verification pass re-derives them. Previously each
  flag was only ever set to 1; the RFC's three "Otherwise … MUST set …
  to 0" clauses require them to be cleared as well. Practically: an
  echoed CoS TLV (or any other recognized type) now reports `U=0` to the
  sender even when the sender obeyed the §4.4.1 mandate to send `U=1`.
  The C-flag (`conformant_reflected`, draft-ietf-ippm-asymmetrical-pkts)
  and parser-detected truncation M-flag are preserved across the clear.
- **draft-ietf-ippm-stamp-ext-hdr Type 246 / 247 sender request encoding**:
  Session-Sender now pre-allocates the Value field with zeros sized to the
  expected header length (20 for IPv4 fixed header, 40 for IPv6 fixed
  header, 8-byte capacity for IPv6 ext-header chain) per the draft.
  Previously sent length=0; conforming reflectors that validate the
  request's Length field rejected it as malformed.

### Changed

- **Shared `build_local_addresses` between backends**: the interface-address
  enumeration used for Destination Node Address TLV matching (RFC 9503 §4)
  was duplicated in `receiver/nix.rs` and `receiver/pnet.rs` with platform-
  specific implementations. Consolidated into a single
  `receiver::build_local_addresses()` with `cfg(unix)` / `cfg(not(unix))`
  internals — `nix::ifaddrs::getifaddrs` on Unix, `pnet::datalink::interfaces`
  on Windows. Removes ~60 lines of near-duplicate code and a class of
  drift bugs.
- `--micro-session-id` and `--reflector-member-link-id` (RFC 9534 LAG
  identifiers) now accept `0x`-prefixed hex (`0xff`, `0XFF`, `0x00ab`)
  in addition to decimal. Aligns with the conventional way these wire
  fields are written.

### Breaking

- `ReflectedFixedHdrTlv::request()` removed; replaced by
  `ReflectedFixedHdrTlv::request_for(IpAddr)` (chooses 20 / 40 bytes from
  the destination address family) or
  `ReflectedFixedHdrTlv::request_with_capacity(usize)` (explicit zero-fill
  size). The old API produced an empty-Value TLV that did not match the
  draft's request format.
- `ReflectedIpv6ExtHdrTlv::request()` removed; replaced by
  `ReflectedIpv6ExtHdrTlv::request_with_capacity(usize)` so the caller
  picks the zero-filled Value size to match the path's expected
  extension-header chain. The default size for the sender flag
  (`--reflected-ipv6-ext-hdr`) is exposed as
  `tlv::DEFAULT_IPV6_EXT_HDR_REQUEST_CAPACITY` (8 bytes — one option).
- Reflector behavior change: when populating Type 246 / 247 responses,
  the reflector now preserves the sender-advertised Length, zero-padding
  short captures and truncating long ones. Callers that depended on the
  response length matching the captured-bytes length should size the
  request appropriately.

### Documentation

- README gained a **Receiver Backends** section explaining the two capture
  paths (nix UDP socket + cmsg vs pnet datalink capture), why `nix` stays
  the default on Linux/macOS (unprivileged execution, no libpcap runtime
  dependency, kernel-side UDP demultiplex, firewall integration, kernel-
  handled checksums / fragmentation / ARP, socket observability), and what
  the tradeoff is (TLV 246/247 only on the pnet backend; two capture loops
  to maintain).
- **README split** into a slim landing page (~200 lines) and three deep
  references under `doc/`:
  - `doc/usage.md` — TOML configuration file format, supported keys,
    validation behavior, and the full grouped CLI flag reference.
  - `doc/architecture.md` — module layout, receiver backends, packet
    processing pipeline, session management, full TLV reference,
    Prometheus and SNMP subsystems.
  - `doc/security.md` — threat model, HMAC and TLV integrity, key
    sourcing precedence (with the `STAMP_HMAC_KEY` + `hmac_key_file`
    mutual-exclusion caveat), config and key file permissions, the
    `stamp` system user, an annotated walkthrough of the systemd unit's
    hardening directives, the capability model, and a step-by-step
    procedure for switching the packaged systemd unit from open to
    authenticated mode before exposing UDP/862. Top-level `SECURITY.md`
    pointer added for GitHub auto-discovery.
- Cargo packaging (`cargo deb` / `cargo generate-rpm`) ships the three
  new docs at `/usr/share/doc/stamp-suite/` alongside `README.md`.

## [0.6.0] - 2026-04-22

### Added

- **TOML configuration file support** (`--config <PATH>`): every CLI option can
  be supplied through a TOML file so long-lived deployments (systemd units,
  reflectors, reproducible test rigs) no longer need sprawling command lines.
  - New `FileConfiguration` struct mirrors `Configuration` with all fields
    optional; unknown keys are rejected at parse time (`deny_unknown_fields`)
    so typos surface with the full list of valid keys.
  - Precedence: command-line flag / `STAMP_HMAC_KEY` env var > TOML file
    value > hardcoded default. Detected via `clap::ArgMatches::value_source`
    so the same `Configuration` struct serves both sources.
  - New `Configuration::load()` entry point parses CLI, merges the optional
    TOML file, then runs `validate()`. `main.rs` uses it in place of
    `Configuration::parse()`.
  - Plaintext `hmac_key` is deliberately absent from the file schema; only
    `hmac_key_file` is accepted, so secrets cannot leak into a shared config.
  - On Unix, a warning is logged if the config file is writable by group or
    other (mask `0o022`) — mirrors the existing check on `--hmac-key-file`.
  - Range checks for `dscp` (0-63), `ecn` (0-3), `access_report` (0-15),
    `micro_session_id` (>=1), `reflector_member_link_id` (>=1) were added to
    `Configuration::validate()` since clap's CLI-side `value_parser!().range()`
    does not run on values deserialized from TOML.
  - New dependency: `toml = "0.9"`; dev-dependency: `tempfile = "3"`.
  - `AuthMode`, `ClockFormat`, `TlvHandlingMode`, and `OutputFormat` gained
    `serde::Deserialize` derives with renames matching the existing
    `ValueEnum` string forms.

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
