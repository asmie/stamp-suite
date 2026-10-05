# Changelog

Based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versions follow [Semantic Versioning](https://semver.org/spec/v2.0.0/).

## [Unreleased]

### Changed

- Short help (`-h`) shows everyday options and two examples; `--help` and the
  manual keep every option. Sender and reflector TOML examples are included
  in packages and binary archives. CLI overrides and existing flags are unchanged.

## [1.0.0] - 2026-10-05

First stable release. See [conformance matrices](doc/conformance/README.md)
for supported profiles and remaining gaps. Experimental extensions can change
when their drafts or IANA assignments change.

### Added

- Concurrent measurement of several reflectors with per-target reports.
  Repeat `--remote-addr` or pass a comma-separated list.
- Continuous and time-limited runs (`--count 0`, `--duration`), sub-millisecond
  intervals, Poisson scheduling and summaries on Ctrl-C or SIGTERM.
- Device/VRF binding and scoped IPv6 link-local addresses for both roles.
- Provisioned session admission, bounded reply queues, configurable shutdown
  grace, and session failure/recovery monitoring.
- Sender accounting for requested reply copies, duplicates, late replies,
  reordering, Direct Measurement windows and Follow-Up delays. Reports include
  clock quality and structured TLV flag/HMAC validation results.
- Bearer-authenticated reflector control API with optional HTTPS: session/key
  management, live limits, drain and graceful shutdown. Keys remain write-only.
- SIGHUP reload of reflector HMAC key files and directories.
- Linux kernel RX/TX timestamping, NIC hardware timestamp configuration and
  capability probing. macOS supports kernel RX timestamps. Hardware results
  require a disciplined PHC and separate physical-NIC verification.
- Location disclosure and destination-scoped DSCP/ECN admission policies,
  replay detection/drop policy, and sender ECN congestion response.
- Access Report retries, required Micro-session ID validation, zero-SSID
  handling, extra padding and separate TLV HMAC configuration.
- Linux socket-backend IPv6 extension-header reflection without raw capture;
  pnet fixed-header reflection, selectors and tunnel/header-chain inspection.
- Directional BER intervals, burst counters, alarms and bounded history.
- Grouped CLI help and generated manual; Gentoo overlay with systemd/OpenRC
  services; Linux DEB/RPM and macOS/Windows release archives. Source/vendor
  archives, pinned OpenWrt recipes and provenance accompany releases.
- Independent wire fixtures, real Net-SNMP/control integration checks,
  privileged namespace/SRv6 tests, fuzz targets and a standards monitor.

### Changed

- **Type 246 wire format:** reflected IPv6 headers follow
  draft-ietf-ippm-stamp-ext-hdr-15, with eight-octet selectors introduced in
  revision -13. Upgrade both peers together. Type 247 retains four-octet
  selectors. Pending IANA codepoints remain experimental.
- Reflected Test Packet Control follows RFC 10052; BER follows
  draft-gandhi-ippm-stamp-ber-07. Clock-source declarations are independent of
  timestamp format and synchronization flags.
- Sender ports default to randomized dynamic ports and must differ from the
  reflector port. Both roles transmit with TTL/Hop Limit 255.
- Stateful identities include both UDP endpoints, SSID and sender
  micro-session ID. New identities are rejected at capacity or during drain;
  expiry retires pending replies before a session restarts.
- Linux replies respect the actual reply-route MTU, including SRH overhead.
  Resized replies are signed again; replies without a usable mandatory-field
  budget are dropped. Both roles validate configured payload sizes.
- Sender RTT/OWD quantiles are exact through 4096 samples, then use bounded
  full-run histograms with less than 0.78125% magnitude error. BER history and
  output queues are bounded. JSON/CSV expose precision and omission counts.
- Packet construction, HMAC state, ancillary buffers, session lookup and
  metrics handles are reused to reduce per-probe work. Interim formatting runs
  outside the sender loop; reflector receive processing batches ready packets.
- The minimum Rust version is 1.86; Criterion moves to 0.8.2. Debian trixie
  source builds need a newer toolchain than the stock compiler. Both lockfiles,
  CI actions and DEB/RPM packagers are updated, along with Nix inputs and
  the vendor hash.
- Tagged releases require CI and conformance gates. Release metadata and the
  Gentoo crate list are checked before packaging. Debian builds use supplied
  offline vendor inputs.

### Fixed

- CoS, Location, Timestamp Information, Access Report and Follow-Up wire
  layouts and reflected field handling; malformed padding/TLV parsing,
  integrity coverage, flag ordering and final reply signing.
- Reply source-address pinning, IPv4 packet-info byte order, IPv6 hop metadata,
  scope preservation, SRv6 transit and routing-header cleanup.
- Required session IDs and SSIDs are checked before measurement admission.
  Mixed NTP/PTP timescales, timestamp error estimates, counter wrap and burst
  loss/reordering accounting are handled consistently.
- Send scheduling survives ICMP errors; terminal sends and failed startup
  return errors. Broken measurement output also exits unsuccessfully.
- Pnet macOS loopback parsing accounts for its 12-byte placeholder, and capture
  thread panics cause a non-zero exit so supervisors can restart the process.
- Windows debug startup no longer overflows its 1 MiB default stack: builds
  reserve 4 MiB for the executable. Npcap library paths preserve existing SDK
  paths. Native CI checks the executable reserve and required runtime tests.
- macOS SNMP test peers explicitly restore blocking mode on accepted sockets.
  AgentX accepts Net-SNMP's echoed administrative bindings while still rejecting
  unrelated trailing data, incorrect correlation and error responses.
- SNMP workers stop with their owner, including during incomplete handshakes,
  and reconnect after master restarts. AgentX supports both byte orders and
  bounds request framing, search ranges and GetBulk work.
- Fuzz CI explicitly uses GNU/Linux for AddressSanitizer instead of selecting
  a musl target with statically linked libc.
- DEB systemd maintenance hooks are generated, and the unit installs under
  `/usr/lib/systemd/system` for merged-/usr systems. Packages include release
  notes and security guidance.
- Feature-dependent services fail startup when unavailable; macOS packages
  include metrics, and Windows packages include metrics and the control API.
- Documentation, conformance citations, MIB descriptions and manual snapshots
  match current behavior. Older test reports remain tied to their recorded
  commits and platforms.

### Security

- Rustls 0.23.45 fixes RUSTSEC-2026-0285, a TLS 1.3 handshake encryption-level
  validation flaw. The dependency audit passes without advisory exceptions.
- Reflection/amplification controls, bounded per-source rate-limit state,
  bounded sessions and packet panic isolation limit hostile-input costs.
- Key/token files enforce private permissions; secrets are redacted and
  zeroized. Key rotation preserves signatures on already accepted bursts.

## [0.9.0] - 2026-06-10

### Added

- **One-way delay statistics.** The sender reports forward (T2 − T1) and
  reverse (T4 − T3) one-way delay as min, average, median and max next to RTT.
  The figures are meaningful only when both ends have synchronized clocks.
- **Egress IP header marking.** `--ttl` sets the IPv4 TTL or IPv6 Hop Limit of
  test packets, and `--cos` also sets the DSCP and ECN of outgoing test packets
  to the values the Class of Service TLV requests (Linux and macOS).
- **Malformed TLV injection.** `--malformed bad-flags|bad-length` appends a
  deliberately malformed TLV to every test packet, to test how a reflector
  handles RFC 8972 §4.2 flags and lengths. It is not for normal measurements.
- **SRv6 return path.** With `--srv6-return-forwarding`, a Linux reflector
  answering over IPv6 inserts a Segment Routing Header built from the Return
  Path TLV's SRv6 Segment List (RFC 9503 §5, RFC 8754). Without the option, or
  where the kernel or path does not support it, the reflector replies normally
  and sets the U flag. SR-MPLS segment lists are echoed with the U flag.

### Changed

- Reflected Test Packet Control (Type 12) multi-reply is off by default:
  `--reflected-control-max-count` defaults to 0, so the reflector sends one
  reply and sets the C flag. Set a positive value to allow more replies.
- `--hwtstamp on` warns and uses software timestamps when hardware
  timestamping is unavailable instead of refusing to start. Hardware
  timestamping was not implemented in this release.
- Dependencies updated to their current versions, including criterion 0.8 for
  the benchmarks.

## [0.8.0] - 2026-05-18

### Added

- **Per-SSID HMAC key set.** `--hmac-key-dir <DIR>` and the
  `crypto::HmacKeySet` type let one reflector serve several senders without
  sharing a key. Each file's name (without extension) is the SSID in hex; an
  optional `default.key` is the fallback for unknown SSIDs. The option is
  mutually exclusive with `--hmac-key` and `--hmac-key-file`, and the
  single-key path still works. The reflector reads the incoming packet's SSID,
  resolves the per-SSID key and uses it for both verification and the
  response HMAC.
- **Per-client token-bucket rate limiting.** `RateLimiter` is a token bucket
  keyed by `(source_ip, ssid)` instead of a fixed-window counter.
  `--reflector-rate-burst` sets the bucket capacity independently of
  `--max-pps`, which still means tokens per second; `burst = 0` falls back to
  `rate` for backward compatibility. A `packets_rate_limited` counter
  separates rate-limit drops from other drops in metrics and SNMP. Each extra
  Reflected Test Packet Control (Type 12) copy consumes one token, and the
  burst stops early when the bucket is empty, so an asymmetric burst cannot
  exceed the per-client budget.
- **Reflected Test Packet Control (Type 12) aligned with draft-14.** The
  reflector honors the requested reply length by inserting an
  `ExtraPaddingTlv` ahead of the HMAC TLV, up to a configurable cap. It parses
  the Layer-3 Address Group sub-TLV (Type 11) and drops the packet (through
  `ReturnPathAction::SuppressReply`) when no local address matches the
  requested prefix (draft §3). It parses the Layer-2 Address Group sub-TLV
  (Type 10) and sets the U flag on the echoed Type 12 when MAC visibility is
  not available (UDP socket backends). `--reflected-control-max-count`,
  `--reflected-control-max-size` and `--reflected-control-min-interval-ns`
  expose the amplification caps, which were compile-time constants, as
  runtime configuration. The minimum value-field size is 12 octets instead of
  8 (draft §3); the encoder zero-pads short emissions to 12 bytes (a
  placeholder sub-TLV header) so existing single-TLV senders stay on the wire.
- **draft-ietf-ippm-stamp-ext-hdr-08 Type 247 length-mismatch handling.** The
  Reflected Fixed Header Data TLV's Length must equal 20 (IPv4) or 40 (IPv6)
  (§5.2). If the sender's requested Length does not match the captured header
  size (for example a 20-byte request reaching an IPv6 reflector), the
  reflector zero-fills the Value and sets the U flag rather than truncating or
  padding. `log_reflected_hdr_length_mismatch_once` emits a one-time warning
  citing draft §5.2.
- **Structured logging with `tracing-subscriber`.** `--log-format text|json`
  selects human-readable single-line output (the default) or one JSON object
  per event, for Fluent Bit, Vector or journald JSON forwarding. `tracing-log`
  bridges existing `log::*` call sites. `RUST_LOG` controls verbosity in both
  modes.
- **`--print-config-schema`** prints a hand-maintained JSON Schema (draft
  2020-12) for the `FileConfiguration` accepted by `--config`. Use it with the
  `jsonschema` CLI or an IDE plugin for autocompletion and validation before
  deployment. A coverage test fails when a TOML field has no schema property.
- **Hardware timestamping scaffold.** A `hwtstamp` Cargo feature (off by
  default), `--hwtstamp auto|on|off`, a `crypto::HwTsMode` enum, a capability
  probe stub and an `effective_method` resolver that picks `HwAssist` or
  `SwLocal` per direction. `auto` (the default) falls back to software
  silently when the kernel or NIC does not advertise support, `on` fails at
  startup, and `off` always uses software. The kernel-side `SO_TIMESTAMPING`
  and `MSG_ERRQUEUE` wiring was left for a later release; the public API is in
  place so call sites do not change when it lands.
- **Capture-thread liveness signal.** `ReceiverSharedState` has a
  `capture_alive: Arc<AtomicBool>`. Both backends clear it when their receive
  loop exits unexpectedly (interface not found, channel initialization
  failure, send-socket bind failure, `spawn_blocking` panic), so a readiness
  probe or systemd's `MonitorPolicy` can tell "process alive but not
  reflecting" from "process alive and healthy". The pnet capture path logs
  with `log::error!` and `log::warn!` instead of `eprintln!`.
- **AgentX sub-agent panic resistance.** Every `unwrap()`, `panic!` and
  `unreachable!()` reachable from the AgentX event loop
  (`agentx::decode_header`, `decode_oid`, `decode_search_range`,
  `handle_get_bulk`, `MibHandler::get` and `get_next`) was checked: each
  buffer index is preceded by an explicit length check that returns
  `AgentXError::Protocol`. A supervisor task observes the `spawn_blocking`
  JoinHandle, so an unexpected panic logs `JoinError::is_panic()` instead of
  being dropped. The module documentation in `src/snmp/mod.rs` records the
  result.
- **Observability failure semantics.** `--metrics` fails at startup on a bind
  error and names the `io::ErrorKind` (AddrInUse, AddrNotAvailable,
  PermissionDenied) in the exit message. `--snmp` logs a warning and continues
  when the AgentX master is missing. A silently disabled metrics endpoint
  leaves dashboards blind, while a disabled SNMP sub-agent does not affect the
  reflector's main job. Documented in `doc/usage.md`.
- **Malformed-input tests:** 12 hand-crafted hostile byte sequences across
  base packet length boundaries (RFC 8762 §4.1.x), TLV header length abuses
  (overflow, u16::MAX, truncated header), HMAC ordering violations (TLV after
  HMAC, wrong-length HMAC value, corrupted digest giving the I flag on every
  TLV per §4.8), Return Path sub-TLV nesting overflow, and high-entropy spot
  checks. The implementation handled every case correctly; no production code
  changed.
- **TLV flag semantics tests:** 15 tests pin the RFC 8972 §3/§4.8 and
  draft-asymmetrical §3 U/M/I/C bit positions (0x80/0x40/0x20/0x10),
  unknown-type echo with U, length mismatch with M, HMAC failure with I on
  every TLV (the packet is still echoed), Reflected Control clamping with C,
  and flag-independence negative controls.
- **BER on-wire tests:** 6 tests cover a clean channel, a single-bit flip, an
  intra-byte 3-bit burst, a cross-byte 4-bit burst (exercising the MSB-first
  bit walker), sender hex-dump verification and a custom non-default pattern.
- **PTP timestamp end-to-end tests:** 6 tests cover the wire encoding
  difference (NTP versus PTP epoch offset), Type 3 TLV `sync_src_out`
  reporting with PTP and NTP reflector modes, preservation of the
  sender-declared sync source in mixed mode, and big-endian timestamp
  placement at byte offset 4..12.
- **Statistics edge-case tests:** 10 tests cover RFC 3550 jitter on
  single-sample, zero-jitter, negative-skew and alternating patterns, the
  two-sample standard deviation boundary, large-RTT u128 overflow safety,
  percentile of an empty set and out-of-range p, a single-sample percentile
  off-by-one, and the zero-sent `loss_percent` NaN guard.
- **IPv6 TLV parity tests:** 10 tests drive every major reflector code path
  with an IPv6 source: unauthenticated and authenticated round trips, CoS
  DSCP/ECN echo, RFC 9503 Destination Node Address match and mismatch,
  Micro-session ID, the BER TLVs, Location sub-TLVs, combined authentication
  and CoS, and unknown-TLV U flag.
- **Multi-key HMAC integration tests:** 6 tests cover single-key mode with
  SSID 0 and non-zero SSIDs, the per-SSID happy path, rejection of the wrong
  key for an SSID, unknown SSID with `require_hmac` (dropped), and default-key
  fallback for missing per-SSID entries.
- **pnet backend integration tests:** 3 `#[ignore]`d tests start a real pnet
  receiver on the `lo` interface and round-trip open mode, authenticated mode
  and a TLV chain. They skip themselves when the process lacks `CAP_NET_RAW`
  and require `target_os = "linux"`, `feature = "ttl-pnet"` and not
  `ttl-nix`. `tests/README.md` documents the privileged invocation.
- **AgentX malformed-PDU tests:** 8 tests on the public decoders and 4
  OID-boundary tests on the handler dispatch confirm that every buffer index
  is bounds-checked.
- **Rate-limit isolation tests:** 7 tests cover burst exhaustion, multi-client
  isolation (a greedy client does not drain a polite one), per-SSID isolation
  (same IP with different SSIDs gets independent buckets), atomic `allow_n`,
  sustained-rate refill, backward-compatible `burst = 0` and expired-bucket
  reaping.
- **`--strict-packets` contract tests:** 7 tests pin the lenient versus strict
  behavior for short, full and empty buffers in both modes, MBZ always ignored
  (RFC 8762 §4.1.1), and `require_hmac` interactions.
- **Property-based and libFuzzer harnesses.** 16 proptest cases (run by the
  default `cargo test`) cover typed TLV round trips and no-panic invariants on
  arbitrary bytes for every parser. Seven cargo-fuzz targets under `fuzz/`
  (excluded from the workspace, nightly only) exercise the same code paths.
  The `fuzz.yml` workflow (manual or weekly cron) builds and runs each target
  for 60 s and uploads `fuzz/artifacts/` and `fuzz/corpus/` on failure.
- **Criterion benchmark suite.** `benches/reflector_hotpath.rs` measures
  `process_stamp_packet` end to end without UDP: open mode with no TLVs
  (about 100 ns/op), one TLV, a full chain, the authenticated HMAC success
  path, and an authenticated full chain. Reference numbers are in
  `doc/architecture.md` for regression triage.
- **`mib-lint` CI job.** It runs `smilint -l 4` against
  `mibs/STAMP-SUITE-MIB.mib` on every push and pull request. The package
  install tries `smitools` (Ubuntu 24.04 and later) and falls back to
  `libsmi2-bin` on older images.

### Changed

- `process_auth_packet` takes an explicit `resolved_hmac_key` parameter that
  `process_stamp_packet` sets after a per-SSID lookup, instead of reading
  `ctx.hmac_key` directly. The `HmacKeySet` path needs this; the single-key
  path is unchanged because the legacy field still feeds `resolve_hmac_key()`
  when no key set is configured.
- A `REFLECTED_CONTROL_TLV_FIXED_FIELDS_SIZE` constant, added with the
  12-octet minimum, lets the parser address the fixed header (length, count,
  interval) and the sub-TLV chain separately without re-deriving the offset.
- The TLV reference table in `doc/architecture.md` uses the labels supported,
  partial, experimental and interop-only. Type 10 is partial (SR-MPLS and
  SRv6 are echoed with the U flag), Type 12 is supported after the draft-14
  alignment above, and Types 246 and 247 are partial (pnet backend only).
  Type 242 is documented as colliding on the wire with teaparty's Heartbeat
  use of the same byte; both implementations are in the experimental range,
  so neither is wrong per IANA, but mixed deployments need to pick one.
- `doc/architecture.md` is reorganized, with an Operational Characteristics
  section (the `--strict-packets` contract, `capture_alive` semantics, metrics
  failing at startup versus SNMP continuing, the AgentX panic-resistance
  results and the `--hwtstamp` modes), a Hardware-Assisted Timestamping
  section, a Benchmarks section and an updated TLV table.
- Windows test and release-build jobs are pinned to `windows-2022` instead of
  `windows-latest`. The `windows-2025` image dropped the bundled tooling that
  satisfied pnet's load-time `wpcap.dll` and `Packet.dll` imports, and the
  Npcap silent installer hangs on Server 2025 (UAC and driver-signing
  prompts). The long-term fix is to gate pnet behind a Cargo feature on
  Windows.

### Fixed

- **Layer-2 Address Group without MAC visibility** (RFC 8972 §3,
  `set_reflected_control_u_flag`). When a Layer-2 Address Group sub-TLV
  arrives on a backend without MAC visibility, the reflector sets the U flag
  on the echoed Type 12 TLV and continues processing. The sub-TLV used to be
  ignored silently, which gave the sender no signal that the filter was not
  honored.

## [0.7.0] - 2026-05-04

### Added

- **Reflected Fixed and IPv6 Extension Header Data TLVs (Types 247 and 246,
  draft-ietf-ippm-stamp-ext-hdr).** The sender can ask the reflector to echo
  the raw bytes of the received IP fixed header (Type 247: 20 bytes for IPv4,
  40 bytes for IPv6) and the IPv6 Hop-by-Hop and Destination Options extension
  headers (Type 246). This allows end-to-end diagnosis of DSCP remarking, TTL
  decrement, Flow Label rewriting and in-path tampering with IPv6 options.
  - Typed TLVs `ReflectedFixedHdrTlv` and `ReflectedIpv6ExtHdrTlv` implement
    `TypedTlv`, with `TlvType::ReflectedFixedHdr` and `ReflectedIpv6ExtHdr`
    variants. Length validation treats the Value as variable-length: the
    sender pre-allocates a zero-filled Value sized to the expected header
    length (per draft-ietf-ippm-stamp-ext-hdr), and the response carries the
    populated bytes.
  - A `CapturedHeaders` struct is passed through `ProcessingContext`, so the
    reflector's TLV processing can see the raw IP-layer bytes captured at
    receive time.
  - `TlvList::process_reflected_headers()`, called from
    `apply_semantic_tlv_processing`, copies the captured bytes into the TLV or
    sets the U flag when the backend cannot observe the IP layer.
  - The `pnet` backend fills `CapturedHeaders` from `Ipv4Packet` and
    `Ipv6Packet` and walks Hop-by-Hop (NextHeader 0) and Destination Options
    (NextHeader 60) headers in wire format (NextHeader byte, HdrExtLen byte,
    body, per RFC 8200). Other headers (Routing, Fragment, ESP, AH) stop the
    walk, matching the draft's scope. For IPv4, only the fixed 20-byte header
    is copied; IPv4 options are dropped on purpose.
  - The `nix` backend passes `captured_headers: None`. The reflector echoes the
    TLV empty with the U flag set (RFC 8972 §4.2) and logs a one-time warning
    suggesting a rebuild with `--features ttl-pnet` if header reflection is
    needed. An empty Value on an IPv4 packet, or on an IPv6 packet without
    extension headers, is legitimate and does not set the U flag.
  - Sender options `--reflected-fixed-hdr` and `--reflected-ipv6-ext-hdr`,
    with matching `FileConfiguration` TOML fields. The sender attaches a
    zero-filled request TLV sized to the destination's IP family for Type 247,
    and an 8-byte default (one option) for Type 246. The reflector fills them
    on the pnet backend or sets U on nix.
- `doc/usage.md`, `doc/architecture.md` and `doc/security.md` hold the
  detailed documentation, and the README is a short landing page of about 200
  lines:
  - `doc/usage.md`: the TOML configuration file format, supported keys,
    validation behavior and the full grouped CLI option reference.
  - `doc/architecture.md`: module layout, receiver backends, the packet
    processing pipeline, session management, the full TLV reference, and the
    Prometheus and SNMP subsystems.
  - `doc/security.md`: the threat model, HMAC and TLV integrity, key sourcing
    precedence (including the `STAMP_HMAC_KEY` and `hmac_key_file` mutual
    exclusion caveat), configuration and key file permissions, the `stamp`
    system user, an annotated walkthrough of the systemd unit's hardening
    directives, the capability model, and a step-by-step procedure for
    switching the packaged systemd unit from open to authenticated mode before
    exposing UDP port 862. A top-level `SECURITY.md` points to it for GitHub
    discovery.
- The README has a Receiver Backends section. It explains the two capture
  paths (nix UDP socket with cmsg, pnet datalink capture), why `nix` is the
  default on Linux and macOS (unprivileged execution, no libpcap runtime
  dependency, kernel-side UDP demultiplexing, firewall integration,
  kernel-handled checksums, fragmentation and ARP, socket observability), and
  the tradeoff (TLVs 246 and 247 only on the pnet backend, and two capture
  loops to maintain).

### Changed

- **Breaking:** when filling Type 246 and 247 responses, the reflector keeps
  the Length the sender advertised, zero-padding short captures and truncating
  long ones. Callers that relied on the response length matching the
  captured length should size the request accordingly.
- `build_local_addresses` is shared between backends. The interface address
  enumeration used for Destination Node Address TLV matching (RFC 9503 §4)
  was duplicated in `receiver/nix.rs` and `receiver/pnet.rs`. It is one
  `receiver::build_local_addresses()` with `cfg(unix)` and `cfg(not(unix))`
  internals (`nix::ifaddrs::getifaddrs` on Unix,
  `pnet::datalink::interfaces` on Windows), which removes about 60 lines of
  near-duplicate code and a class of drift bugs.
- `--micro-session-id` and `--reflector-member-link-id` (RFC 9534 LAG
  identifiers) accept `0x`-prefixed hex (`0xff`, `0XFF`, `0x00ab`) as well as
  decimal, the usual way these wire fields are written.
- Cargo packaging (`cargo deb` and `cargo generate-rpm`) installs the three
  documents in `/usr/share/doc/stamp-suite/` next to `README.md`.

### Removed

- **Breaking:** `ReflectedFixedHdrTlv::request()` is removed. Use
  `ReflectedFixedHdrTlv::request_for(IpAddr)`, which picks 20 or 40 bytes from
  the destination address family, or
  `ReflectedFixedHdrTlv::request_with_capacity(usize)` for an explicit
  zero-fill size. The old API produced an empty-Value TLV that did not match
  the draft's request format.
- **Breaking:** `ReflectedIpv6ExtHdrTlv::request()` is removed. Use
  `ReflectedIpv6ExtHdrTlv::request_with_capacity(usize)`, so the caller picks
  the zero-filled Value size to match the path's expected extension header
  chain. The default size for `--reflected-ipv6-ext-hdr` is
  `tlv::DEFAULT_IPV6_EXT_HDR_REQUEST_CAPACITY` (8 bytes, one option).

### Fixed

- **Sender flag default** (RFC 8972 §4). `TlvFlags::for_sender()` returns
  `U=1, M=0, I=0` instead of all zeroes. The RFC requires the Session-Sender
  to send every TLV with the U flag set; the reflector then overwrites it.
  Sender-built TLVs (`RawTlv::new`) inherit the corrected default. On the
  wire, the leading flag byte of every outgoing TLV changes from `0x00` to
  `0x80`.
- **Reflector flag overwrite** (RFC 8972 §4). The reflector clears U, M and I
  on every parsed TLV before the type recognition, length validation and HMAC
  verification pass re-derives them. Each flag used to be only ever set to 1,
  but the RFC's three "Otherwise … MUST set … to 0" clauses require clearing
  them as well. As a result, an echoed CoS TLV (or any other recognized type)
  reports `U=0` to the sender even when the sender followed the requirement to
  send `U=1`. The C flag (`conformant_reflected`,
  draft-ietf-ippm-asymmetrical-pkts) and the M flag for parser-detected
  truncation are preserved across the clear.
- **Type 246 and 247 sender request encoding**
  (draft-ietf-ippm-stamp-ext-hdr). The Session-Sender pre-allocates the Value
  with zeros sized to the expected header length (20 for the IPv4 fixed
  header, 40 for the IPv6 fixed header, 8 bytes for the IPv6 extension header
  chain), as the draft requires. It used to send Length 0, which conforming
  reflectors that validate the request's Length rejected as malformed.

## [0.6.1] - 2026-04-22

### Changed

- The `toml` dependency is updated from 0.9 to 1.1.

## [0.6.0] - 2026-04-22

### Added

- **TOML configuration file** (`--config <PATH>`). Every CLI option can be set
  in a TOML file, so long-lived deployments (systemd units, reflectors,
  reproducible test rigs) do not need long command lines.
  - The `FileConfiguration` struct mirrors `Configuration` with all fields
    optional. Unknown keys are rejected at parse time (`deny_unknown_fields`),
    so typos are reported with the full list of valid keys.
  - Precedence: command-line option or `STAMP_HMAC_KEY` environment variable,
    then the TOML file value, then the built-in default. The source is
    detected with `clap::ArgMatches::value_source`, so one `Configuration`
    struct serves both sources.
  - `Configuration::load()` parses the CLI, merges the optional TOML file and
    runs `validate()`. `main.rs` uses it instead of `Configuration::parse()`.
  - A plaintext `hmac_key` is not part of the file schema; only
    `hmac_key_file` is accepted, so secrets cannot leak into a shared
    configuration.
  - On Unix, a warning is logged if the configuration file is writable by
    group or other (mask `0o022`), like the existing check on
    `--hmac-key-file`.
  - `Configuration::validate()` checks the ranges of `dscp` (0-63), `ecn`
    (0-3), `access_report` (0-15), `micro_session_id` (>=1) and
    `reflector_member_link_id` (>=1), because clap's CLI-side
    `value_parser!().range()` does not run on values read from TOML.
  - New dependency `toml = "0.9"`; new dev-dependency `tempfile = "3"`.
  - `AuthMode`, `ClockFormat`, `TlvHandlingMode` and `OutputFormat` derive
    `serde::Deserialize`, with renames matching their `ValueEnum` string forms.
- **Reflected Test Packet Control TLV (Type 12,
  draft-ietf-ippm-asymmetrical-pkts)** for asymmetrical reply measurement.
  - `ReflectedControlTlv` struct (Length, Count, Interval and opaque sub-TLV
    bytes).
  - The reflector sends up to `REFLECTED_CONTROL_MAX_COUNT` (16) reply packets
    per request, spaced by the requested interval (clamped to
    `REFLECTED_CONTROL_MIN_INTERVAL_NS`, 1 µs). An excess count, a clamped
    interval or any non-zero requested length sets the Conformant (C) flag on
    the echoed TLV.
  - The nix backend sends extra copies from a spawned tokio task so the
    receive loop is not blocked; the pnet backend sleeps inline (fallback
    platforms only).
  - A C flag bit (0x10) in `TlvFlags` and `RawTlv::set_conformant_reflected()`.
    The draft leaves the C bit position TBA; this implementation uses bit 3,
    the first bit not used by RFC 8972's U/M/I flags.
  - Sender options `--reflected-control-count`, `--reflected-control-length`
    and `--reflected-control-interval-ns`.
- **BER TLVs (draft-gandhi-ippm-stamp-ber).**
  - Bit Pattern in Padding (Type 240), Bit Error Count in Padding (Type 241)
    and Max Bit Error Burst Size (Type 242). The draft leaves the type numbers
    TBD; 240/241/242 come from RFC 8972's experimental range.
  - The reflector XORs the received Extra Padding against the Bit Pattern TLV
    (or the draft's 0xFF00 default), counts error bits and the longest run of
    consecutive errors across byte boundaries, and writes the results into the
    Count and Max Burst TLVs.
  - Missing Extra Padding or duplicate BER TLVs mark all BER TLVs with the U
    flag (draft §3).
  - Sender options `--ber`, `--ber-pattern <HEX>` and `--ber-padding-size`.
- **Micro-session ID TLV (RFC 9534)** for per-member-link performance
  measurement on LAGs.
  - Micro-session ID TLV (Type 11) with sender and reflector member link
    identifiers.
  - Sender option `--micro-session-id <ID>` identifies the local LAG member
    link.
  - Reflector option `--reflector-member-link-id <ID>` fills in the reflector
    member link ID.
  - The reflector validates a non-zero reflector ID in the received TLV and
    discards the packet on mismatch (RFC 9534 §3.2).
  - `MicroSessionIdTlv` struct with `new`, `from_raw` and `to_raw`, and
    `TlvList::update_micro_session_id_tlvs()`.
- `SenderSnmpStats::inc_lost_by(count)` for batched loss counter updates.
- `record_packets_lost(count)` batch metrics API for sender loss events.

### Changed

- Sender timeout eviction uses an O(k) `VecDeque`-based lazy eviction queue
  instead of an O(n) scan of the whole HashMap. Deadlines are naturally in
  time order because packets are sent sequentially.
- Final sender loss accounting uses the batched `inc_lost_by()` and
  `record_packets_lost()` instead of per-packet loops.
- Reflector TLV semantic processing (CoS, Timestamp Info, Direct Measurement,
  Location, Follow-Up Telemetry, Destination Node Address, Micro-session ID,
  Return Path, HMAC recomputation) is in a shared
  `apply_semantic_tlv_processing()` helper, which removes the duplication
  between `assemble_unauth_answer_with_tlvs` and
  `assemble_auth_answer_with_tlvs`.
- `TlvList::validate_known_tlv_lengths()` uses a shared
  `validate_known_tlv_lengths_slice()` helper that operates on both `tlvs` and
  `wire_order_tlvs`.
- `TlvList::update_micro_session_id_tlvs()` uses a shared
  `apply_micro_session_id()` helper for both TLV vectors.

### Removed

- `SenderStatsSnapshot` and `SenderSnmpStats::update_from_snapshot()`. All
  sender SNMP counters are updated live, so the final-snapshot path was dead
  code.

### Fixed

- AgentX OID decoding (`decode_oid`) requires at least 8 bytes instead of 4,
  which prevents a panic when reading the `prefix` and `include` fields from
  short buffers.
- AgentX OID decoding uses `checked_mul` and `checked_add` for the expected
  buffer length, which prevents overflow on 32-bit targets with crafted wire
  data.
- The sender's interim report (`--report-interval`) uses the confirmed
  `packets_lost` counter instead of `pending.len()`, which counted in-flight
  packets as lost.
- SNMP `loss_pct_x100` is computed on read instead of cached, so it does not go
  stale when `packets_sent` increases without new loss events.

## [0.5.0] - 2026-02-13

### Added

- **SNMP AgentX sub-agent** for MIB-based monitoring through net-snmpd
  (requires the `snmp` feature, Unix only).
  - A minimal AgentX implementation (RFC 2741) with no external SNMP crate.
  - STAMP-SUITE-MIB under enterprise OID `.1.3.6.1.4.1.65134`, with an SMIv2
    definition in `mibs/STAMP-SUITE-MIB.mib`.
  - Reflector subtree: configuration scalars, packet counters (received,
    reflected, dropped), active session count and uptime.
  - Session table: per-client address, port, packet counts, last sequence
    number and last active time.
  - Sender subtree: configuration scalars, packets sent, received and lost,
    RTT min/max/avg, jitter and loss percentage.
  - Sender statistics (received, RTT min/max/avg, jitter) are updated in the
    hot path, so SNMP polling during long runs shows current progress.
  - `--snmp` and `--snmp-socket <PATH>` options.
- `SessionManager::session_summaries_extended()` returns per-session state.
- `ReceiverSharedState` shares counters and the session manager between the
  receiver backends and SNMP.

### Changed

- The receiver backends (`nix.rs`, `pnet.rs`) take `&ReceiverSharedState`
  instead of creating their own `Arc<ReflectorCounters>` and
  `Arc<SessionManager>`.
- `run_sender` accepts an optional `Arc<SenderSnmpStats>` (behind the `snmp`
  feature) for live statistics export.

### Fixed

- The pnet backend no longer drops valid fallback responses for Return Path
  alternate IPv6 targets. An early return that bypassed the `try_send` and
  U-flag fallback path is removed.
- The `snmp` feature is gated with `cfg(unix)`. On other platforms, `--snmp`
  prints a clear error and exits instead of failing to compile.

## [0.4.0] - 2026-02-11

### Added

- **RFC 9503 Segment Routing extensions** for SR-MPLS and SRv6 networks.
  - Destination Node Address TLV (Type 9): the sender names the intended
    reflector address, and the reflector sets the U flag on a mismatch.
  - Return Path TLV (Type 10) with sub-TLVs:
    - Control Code sub-TLV: suppress the reply (code 0) or request a
      same-link reply (code 1). Reserved bits are ignored, per RFC 9503.
    - Return Address sub-TLV: the reflector sends the reply to an alternate IP
      address.
    - SR-MPLS Label Stack sub-TLV: MPLS LSE encoding (Label, TC, S, TTL),
      echoed with the U flag (userspace SR forwarding is not supported).
    - SRv6 Segment List sub-TLV: echoed with the U flag (userspace SR
      forwarding is not supported).
  - Sender option `--dest-node-addr <IP>` (requires `--ssid`).
  - Sender option `--return-path-cc <CODE>` (0 = suppress, 1 = same link).
  - Sender option `--return-address <IP>` for an alternate reply address.
  - Sender option `--return-sr-mpls-labels <LABELS>` (comma-separated 20-bit
    labels).
  - Sender option `--return-srv6-sids <SIDS>` (comma-separated IPv6 SIDs).
- If sending to the alternate address fails, the reflector sets the U flag on
  the Return Path TLV, recomputes the HMAC and retries to the original source
  address.
- Local address enumeration for Destination Node Address matching (nix:
  `getifaddrs`, pnet: `datalink::interfaces`).

### Changed

- `ProcessingContext.local_addresses` is `&[IpAddr]` instead of
  `Vec<IpAddr>`, which avoids cloning per packet in the hot path.

### Fixed

- SR-MPLS labels are encoded as MPLS Label Stack Entries
  (`Label<<12 | TC | S | TTL`) instead of raw u32 values.
- Return Path Control Code decoding masks with `cc & 1` instead of rejecting
  reserved bits, per RFC 9503.
- `--return-sr-mpls-labels` and `--return-srv6-sids` conflict with each other
  at the CLI level.

## [0.3.1] - 2026-02-08

### Changed

- Multiple optimizations and refactorings.

## [0.3.0] - 2026-02-08

### Added

- **RFC 8972 TLV extensions.**
  - A `tlv` module with `TlvFlags`, `TlvType`, `RawTlv`, `TlvList`,
    `ExtraPaddingTlv`, `HmacTlv` and `SessionSenderId` types.
  - TLV handling modes: `ignore` (strip TLVs) and `echo` (reflect TLVs with
    the appropriate flags).
  - `--tlv-mode` selects the TLV handling mode (default: `echo`).
  - `--verify-tlv-hmac` verifies the incoming TLV HMAC.
  - `--ssid` makes the sender include a Session-Sender Identifier in the Extra
    Padding TLV.
  - HMAC TLV (Type 8) for TLV integrity verification.
  - Flag handling: U flag for unrecognized types, M flag for malformed TLVs,
    I flag for integrity failures.
- Extended packet types: `ExtendedPacketAuthenticated`,
  `ExtendedPacketUnauthenticated` and their reflected variants.
- Lenient packet parsing with `from_bytes_lenient()` for short-packet
  interoperability (RFC 8762 §4.6).
- Canonical buffers for HMAC verification of zero-padded short packets.
- Wire-order preservation for TLV failure echo paths (RFC 8972 §4.8).
- Byte-exact echo of truncated TLVs: the original wire length is kept in the
  header of a malformed TLV.
- Sender-side TLV validation with the `validate_reflected_tlvs()` helper.
- Configuration validation: `--verify-tlv-hmac` requires `--hmac-key` or
  `--hmac-key-file`.

### Changed

- **Breaking:** `auth_mode` accepts exactly `A` (authenticated) or `O` (open).
  Composite strings like `AO` are invalid, because the modes are mutually
  exclusive (RFC 8762). `is_auth()` and `is_open()` use exact string matching
  instead of substring search.
- The receiver assembly functions handle TLV extensions.
- Both `nix` and `pnet` receiver backends process TLV-aware packets.
- HMAC verification in authenticated mode uses canonical zero-padded buffers.

### Removed

- The unsupported `process` TLV handling mode is removed from the
  documentation.
- The `E` (encrypted) auth mode option is removed; RFC 8762 does not define
  it.

### Fixed

- Sender TLV-HMAC validation uses a fixed base offset (44 or 112 bytes)
  instead of inferring it from the packet length.
- Short authenticated packets are zero-filled before HMAC verification.
- Malformed TLVs are echoed byte-exactly, with the original declared length
  preserved.

## [0.2.0] - 2026-02-03

### Added

- Multi-session support in the reflector with `SessionManager`.
- Stateful reflector mode (`--stateful-reflector`) per RFC 8972.
- Session timeout configuration (`--session-timeout`).
- HMAC authentication with `--hmac-key` and `--hmac-key-file`.
- `--require-hmac` to require HMAC verification.
- Error estimate configuration (`--error-scale`, `--error-multiplier`,
  `--clock-synchronized`).
- Integration tests on the loopback interface.
- RFC 8762 compatibility improvements.

### Changed

- Packet serialization uses big-endian encoding.
- Error handling is improved throughout the codebase.

## [0.1.0] - 2022-03-10

This entry covers versions 0.1.0 to 0.1.3 (2022-03-10 to 2024-06-03).

### Added

- Initial implementation of the STAMP protocol (RFC 8762).
- Session-Sender and Session-Reflector modes.
- Unauthenticated and authenticated packet formats.
- NTP and PTP timestamp support.
- IPv4 and IPv6 support.
- Basic RTT and packet loss statistics.
- CLI built with clap.
