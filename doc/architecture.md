# Architecture

This document describes the internal structure of `stamp-suite`: the module layout, the receiver backends, the packet-processing pipeline, the TLV reference, and the optional observability subsystems (Prometheus, SNMP). The top-level [README](../README.md) covers user-facing material — install, run, configure. Anything that explains *how* the implementation works lives here.

## Overview

```
┌─────────────────┐         UDP/862         ┌─────────────────┐
│ Session-Sender  │ ──────────────────────► │Session-Reflector│
│   (stamp-suite) │ ◄────────────────────── │  (stamp-suite -i)│
└─────────────────┘    Reflected Packets    └─────────────────┘
```

A single binary plays both roles. The Session-Sender transmits STAMP test packets and timestamps the reply; the Session-Reflector receives, timestamps, and reflects. STAMP wire formats follow RFC 8762; optional TLV extensions follow RFC 8972, with additions from RFC 9503 (Segment Routing), RFC 9534 (Link Aggregation Group micro-sessions), and two active IETF drafts.

## Module Structure

- `main.rs` — Entry point and CLI handling. Branches into sender or reflector mode based on `--is-reflector`.
- `configuration.rs` — Command-line argument parsing (clap derive), TOML config-file merging, validation. Auth-mode helpers (`is_auth`, `is_enc`, `is_open`).
- `packets.rs` — STAMP packet structures for authenticated and unauthenticated modes, with explicit big-endian fixed-width serialization.
- `sender.rs` — Session-Sender implementation: packet assembly, send loop, RTT statistics.
- `stats.rs` / `stats/quantiles.rs` — cumulative moments and bounded full-run quantiles; [precision and retention](statistics.md).
- `receiver/` — Session-Reflector implementations:
  - `receiver/mod.rs` — Shared STAMP-level pipeline. All TLV parsing, HMAC verification, Return Path handling, session tracking, and counter updates live here. Both backends call into the same `process_stamp_packet` after capturing a packet.
  - `receiver/nix.rs` — Default backend on Linux and macOS. Uses a `tokio::net::UdpSocket` with `IP_RECVTTL`, `IP_RECVTOS`, and `IP_PKTINFO` (plus IPv6 equivalents) to extract per-packet metadata via `recvmsg` control messages.
  - `receiver/pnet.rs` — Default backend on Windows; opt-in elsewhere via `--features ttl-pnet`. Captures at the datalink layer via libpcap / Npcap.
- `session.rs` — `SessionManager` and per-session state. Atomic sequence-number generation, idle-timeout reaping.
- `time.rs` — UTC timestamp generation in NTP and truncated PTP encodings; era-aware decoding onto the Unix epoch.
- `clock_format.rs` — `ClockFormat` enum (NTP / PTP) with parsing.
- `stamp_modes.rs` — STAMP mode enum (Authenticated / Unauthenticated).
- `tlv/` — TLV extension support (RFC 8972 + 9503 + 9534 + drafts). Subdivided by TLV type with shared parsing scaffolding.
- `crypto.rs` — HMAC computation and verification (`compute_packet_hmac`, `verify_packet_hmac`, `HmacKey`).
- `metrics/` — Prometheus metrics (optional, requires `metrics` feature):
  - `sender_metrics.rs` — Sender-side metrics
  - `reflector_metrics.rs` — Reflector-side metrics
- `snmp/` — SNMP AgentX sub-agent (optional, requires `snmp` feature, Unix only):
  - `agentx.rs` — AgentX protocol implementation (RFC 2741)
  - `handler.rs` — STAMP-SUITE-MIB handler
  - `oids.rs` — OID constants
  - `state.rs` — Shared state types

## Receiver Backends

The reflector has two receive-path backends. They differ in how they extract
per-packet metadata (TTL, DSCP/ECN, destination address, raw IP headers), not in
STAMP protocol behaviour — both go through the same `process_stamp_packet`
pipeline.

**`nix` backend (default on Linux and macOS)**

Binds a normal `tokio::net::UdpSocket` and attaches `IP_RECVTTL`,
`IP_RECVTOS`, and `IP_PKTINFO` (with IPv6 equivalents) so the kernel hands
per-packet metadata through `recvmsg` control messages. The kernel performs UDP
demultiplexing and checksum validation; userspace only sees traffic destined
for the bound port.

Raw receives run inside `UdpSocket::try_io(Interest::READABLE, ...)` after
waiting for readability. Converting `recvmsg` errors to `std::io::Error`
lets Tokio clear cached readiness on `WouldBlock`; a raw syscall outside
this wrapper leaves the socket appearing readable after its queue empties.
The sender uses the same pattern for ECN and kernel RX timestamps. It still
returns `WouldBlock` to its outer loop so TX error-queue draining, timers,
and shutdown handling remain available. `tests/idle_cpu_test.rs` exercises
the real Linux reflector process before and after idle, while sender unit
tests verify readiness clearing and preservation of ancillary metadata.

**`pnet` backend (default on Windows, opt-in elsewhere)**

Captures frames at the datalink layer via libpcap / Npcap, parses Ethernet /
IPv4 / IPv6 / UDP manually, and sends replies through a separate `UdpSocket`.
Sees full IP headers, including IPv6 extension headers.

### Why nix is the default where it works

Picking `pnet` everywhere would simplify the codebase slightly (one capture
loop instead of two), but it would regress every Linux/macOS deployment on
several independent axes:

1. **Privileges.** The `nix` backend runs as an unprivileged user — it binds a
   UDP port and that is it. The `pnet` backend needs `CAP_NET_RAW` (or
   `setcap cap_net_raw=eip` on the binary, or plain root). That matters for
   container images, systemd hardening, CI runners, SaaS deployments, and
   anywhere security policy limits capabilities.

2. **Runtime dependencies.** `nix` only needs libc. `pnet` links against
   libpcap on Unix and Npcap on Windows; these must be installed out-of-band
   before the binary will start. A statically-linked `nix` build drops into
   minimal containers and immutable OS images without extra packaging work.

3. **Kernel packet filtering.** With `nix`, the kernel demultiplexes UDP by
   destination port before userspace wakes up — stamp-suite only ever sees
   its own traffic. With `pnet`, every frame on the interface reaches
   userspace; we then discard everything that is not UDP to our port. On a
   10 Gb/s link carrying unrelated traffic this wastes CPU and causes
   scheduling jitter that pollutes delay measurements.

4. **Interaction with the host firewall.** `nix` goes through the normal
   socket path, so `iptables` / `nftables` INPUT rules and per-socket
   accounting behave exactly as the operator expects. `pnet` bypasses INPUT
   on receive and can bypass OUTPUT on raw send, so host-level policy is
   silently skipped.

5. **Kernel does the heavy lifting.** `nix` lets the kernel handle UDP
   checksum, fragmentation, path MTU discovery, ICMP unreachable, ARP /
   NDP for the next hop, and routing-table changes. A pnet-everywhere
   design would have to re-implement or work around each of these.

6. **Observability.** The `nix` backend has a real socket visible to
   `ss -u`, `netstat`, `lsof`, tracing tools, and systemd socket accounting.
   The pnet backend has none of these handles.

### Tradeoff

Keeping two backends has a real cost: packet-processing changes that touch
the capture path have to be mirrored in both files. We mitigate this by
keeping all STAMP-level logic (TLV parsing, HMAC, Return Path handling,
session tracking, counter updates) in `receiver/mod.rs` — the two backends
differ only in how they capture packets and whether they send over an async
tokio socket or a blocking std socket.

The other consequence is that a handful of features that genuinely require
raw IP-header visibility — currently just the Reflected Fixed Header Data
(Type 247) and Reflected IPv6 Extension Header Data (Type 246) TLVs from
draft-ietf-ippm-stamp-ext-hdr — are only populated on the pnet backend.
On the nix backend the reflector echoes the TLV with the C flag set per
draft revision 13 §§5.1/5.2, and logs a one-time warning suggesting a rebuild with
`--features ttl-pnet` if header reflection is actually needed. This
follows the draft's own "may be unsupported by the reflector" semantics,
so the sender sees a spec-compliant response either way.

If you specifically need TLV 246/247 reflection, or you want to craft
outgoing packets with non-default IPv6 extension headers, build with
`--no-default-features --features ttl-pnet` and accept the tradeoffs
above.

## Sender timestamp arithmetic

`process_response` retains the reflector's Error Estimate in all four parser
branches (open/authenticated, base/extended). T1/T4 use the local configuration;
T2/T3 use `ErrorEstimate::clock_format()`, independently of the local format or
S bit. `timestamp_to_unix_nanos` unfolds each seconds word to the nearest era
relative to the local wall-clock reference and removes the NTP epoch offset.
Its signed integer arithmetic preserves sub-millisecond differences around the
2036 NTP wrap and the 2106 truncated PTP wrap without subtracting large floats.
An era reference must be within half the 136-year wrap period.

The sender subtracts `reflector_utc_offset` from remote timestamps after decoding,
using the offset-adjusted wall clock as the remote era reference. This explicit
setting handles a known remote UTC/TAI difference; Z alone cannot identify it.
The suite's software timestamp generation remains UTC-based for both encodings.
Hardware PHC alignment and leap-second policy are separate clock-quality work.
Invalid PTP fractional words skip OWD collection; valid receive/RTT accounting
uses the existing monotonic `Instant` path. Signed OWD retains real clock skew.

## Packet Processing Pipeline

Both backends use `process_session_packet_isolated` for the following stages.
A single keyset read guard spans validation and reply assembly. The shared
processing result also owns a snapshot of the selected key for live sends;
neither backend performs a second key lookup. The finalizer uses this same key
for base/TLV signatures after fallback mutations and for every queued copy.
Standalone packet processing avoids the snapshot allocation.

After rate limiting, live backends first reserve a slot from one `ReplyBudget`.
This bounds processing, pnet handoff, queued bursts and the active send together.
A full budget rejects the packet before the stages below. Rejected parsing/auth
returns the reservation; successful processing attaches it to `QueuedTransmission`
and retains it through all copies. The wrapper counts unsent copies on cancellation
and releases its slot only after dropping the retained transmission.

1. **Identify and admit** — Extract the complete session key and check immutable provisioning once, returning an internal permit bound to that manager and identity. The permit neither reserves capacity nor creates runtime state.
2. **Parse and authenticate** — Decode the base header; enforce strict length or canonical zero-fill policy, the open-mode shape guard, and configured base HMAC verification. Unknown/revoked keys and invalid base packets stop here. Both backends count rejected processing in aggregate `packets_dropped`; no session is created or refreshed.
3. **Session lookup / update** — Consume the permit only after validation. One table write lock and one `HashMap::entry` lookup refresh an existing session or create an allowed entry. Cap/drain checks use the current settings under that lock; rejection precedes receive-state mutation and returns no temporary session. Provisioning is not checked a second time. Update the acquired session's receive counter, classify replay, and snapshot Direct Measurement / Follow-Up state. `--drop-replayed` can suppress ordinary duplicates; a handled Type-12 request uses the mandatory single U-flagged ordering-failure reply. The replay verdict travels in `ProcessingContext` to semantic TLV processing before response signing. Stateful sequence numbers are assigned from this same session handle at transmission; stateless replies echo the sender sequence.
4. **TLV pipeline** — Parse/verify extensions and preserve the RFC 8972 flag rules. A valid base packet with an invalid TLV HMAC still receives the required I-flag response; it is not treated as a failed base HMAC.
5. **RFC 9503 processing** — Destination Node Address matching against `local_addresses`; Return Path action selection (Normal, SuppressReply, AlternateAddress, Srv6Forward, UnsupportedSr). Encoded into a `ReturnPathAction` carried in `StampResponse`; the send path attempts best-effort SRv6 SRH forwarding for `Srv6Forward` (see Return Path TLV below). A *matched* Destination Node Address is also carried as `StampResponse::reply_source`, and both send paths pin it as the reply's IP source address via an `IP_PKTINFO`/`IPV6_PKTINFO` ancillary message (`src/receiver/transmit.rs`, RFC 9503 §3). That is Linux-only and best-effort: elsewhere, or on any failure, the reply goes out with the OS's choice of source, which is still a correct reply — the SHOULD is about which correct source is preferred. This matters on a wildcard or multi-homed bind, where the kernel picks by route rather than by what the sender asked for; on a single-address bind the two coincide anyway.
6. **Assemble reply** — `assemble_unauth_answer_with_tlvs` / `assemble_auth_answer_with_tlvs` build the response, populate reflector-side TLV fields (DM counters, Follow-Up Telemetry, Timestamp Info, Location, Class of Service, etc.), and recompute HMACs (base + TLV) if applicable.
7. **Send** — Commit the validated replay sequence after response assembly, then reply to the original source, an alternate address (Return Path), or suppress entirely. `Transmission::send_next_with_mtu` (`src/receiver/transmit.rs`) assigns the stateful sequence in send order, refreshes T3 and eligible DM/Follow-Up fields, and signs the final bytes before each attempt. Each successful send, including every burst copy, updates the same session handle's transmit/Follow-Up state without another lookup. T2 and the echoed sender fields retain the original request's values. The queued response owns the key selected under the validation/assembly guard; key rotation affects newly accepted requests. Fallback retries retain their sequence and refresh T3 and signatures after any flag changes.

The `ProcessingContext` struct carries per-packet shared state (counters, optional `SessionManager` reference, local addresses, sender port). `ReceiverSharedState` (counters, session manager, start time) lives at the receiver level and is created once via `create_shared_state()` before `run_receiver()`. Standalone library callers now supply `replay_verdict`: use `ReplayVerdict::New` without ordering history, or pass a verdict from caller-managed session state. Live backends compute and replace this field after base validation.

### TLV ownership and signing

`TlvList` owns each `RawTlv` once in `entries`: non-HMAC entries form a borrowed
prefix and HMAC entries form a suffix. An optional vector of indices preserves
received order for malformed echoes and legal padding following HMAC. Semantic
updates modify only the owner; serialization follows indices without a second
payload copy. Duplicate-HMAC partitioning uses a temporary index permutation
and linear swaps, avoiding quadratic work on hostile input. Normal lists need
no partition scratch. BER presence is cached and maintained by structural edits.

Reflector flag clearing, recognition and length validation share a traversal.
BER processing borrows disjoint pattern/padding slices rather than cloning the
pattern. Verification hashes the sequence and original covered byte slice;
signing hashes headers and values incrementally. The live finalizer updates
HMAC in its existing reply buffer. Assembly reserves room for the incoming
packet and a possible HMAC before appending TLVs. Queued requests still own
separate buffers, and parsing still allocates owned values.

Only Extra Padding may follow HMAC, and its position determines which bytes
are covered. Verification retains the parsed HMAC offset; structural edits
invalidate it. New signatures select outgoing order, putting BER padding after
HMAC. Failure echoes retain received order and digest bytes, with required
flags; regeneration on malformed lists leaves them unchanged. See
[RFC 8972 section 4.8](https://www.rfc-editor.org/rfc/rfc8972.html#section-4.8).

The public `non_hmac_tlvs()` slice and logical `iter()` order remain available.
For duplicate HMACs, `hmac_tlv()` and `iter()` select the last HMAC as before;
`len()`, `wire_size()`, serialization and error-flag counts include every owner.
`is_wire_order_mode()` retains its failure-only meaning: a valid parsed list
can preserve trailing padding while returning false. Structural additions to
valid lists select outgoing order; malformed additions update the indexed view.
Typed Return Path/sub-TLV decoders and captured-header wrappers may still allocate.
Local measurement results and limits are recorded with
[O06 evidence](reviews/2026-09-08/logs/optimization-o06/results.json).

### Validated sender telemetry

`validate_reflected_tlvs` returns `Result<TlvTelemetry, TlvRejection>`.
The internal result in `src/sender/telemetry.rs` carries TLV/flag counts,
`HmacStatus`, the first usable Access Report, any forward CE observation, and
validated Micro-session IDs. Control decisions read those fields directly.
`Display` formats packet diagnostics only when `-R` requests them; parsing does
not build or search status strings. This is an internal Rust type, not a new
JSON/CSV schema or CLI output stream.

The validator counts flags across all canonical TLVs, including duplicate HMACs,
and determines integrity before consuming values. U skips a TLV; M stops the
remainder; any I flag or failed/unavailable present HMAC blocks all values.
An HMAC with no key, unusable flags or missing covered bytes cannot acknowledge
an Access Report or report forward CE. A locally invalid Access Report length
adds a malformed diagnostic count and stops further value consumption. Required
Micro-session IDs retain rejection and tentative-latch behavior; the caller
commits learned identity only after SSID and pending-probe admission.

`HmacStatus::Missing` explicitly retains the existing optional legacy-peer policy:
when a configured key receives no HMAC TLV, ordinary optional Access Report/CoS
values may still be used. Required Micro-session IDs, BER, Direct Measurement
and Follow-Up reject that case.
A typed result does not imply cryptographic authentication of an unsigned reply.
Base-packet validation remains in `process_response`, before these decisions.

Diagnostic tokens retain their names but render once per decision in fixed order:
HMAC, Access Report, CE, Micro-session ID, then U/M/I counts. Existing BER extraction
still produces its separate typed `Observation` and performs its own integrity
check. `sender::measurements` keeps bounded probe/reply/counter histories for
burst and duplicate accounting, Direct Measurement window estimates and Follow-Up
reverse-delay summaries. See [measurement semantics](measurements.md).
Allocation measurements for the O07 validator and their limits are in
[O07 evidence](reviews/2026-09-08/logs/optimization-o07/results.json).

`OwdCollector::record_with_quality` retains endpoint synchronization declarations
and advertised error estimates alongside the delay distribution. Follow-Up quality
uses the referenced reply's metadata. The local estimate comes from configuration,
not the echoed sender field; neither endpoint's S bit certifies clock discipline.
See [clock quality](measurements.md#clock-quality-accompanying-delay).

The nix receive path retains IPv6 link-local zones from the source socket address
and destination packet info. `ProcessingContext::packet_local_addr` preserves the
complete scoped destination for session identity without adding interface data to
Location TLV wire fields. Pnet obtains zones from its selected capture interface.
Scoped endpoints survive deferred transmission and original-target fallback.
See [scoped IPv6 usage](usage.md#link-local-ipv6-interface-zones).

## Operational Characteristics

A few cross-cutting operational invariants are worth pinning down separately, since they affect every code path that touches the network or the optional subsystems.

### Packet-receive contract: `--strict-packets`

The reflector's packet-parse path has two modes:

- **Lenient (default)** — short packets are zero-filled to the canonical size per RFC 8762 §4.6, then parsed. HMAC, when present, is verified against the canonical (zero-padded) buffer. This is the interop-friendly mode and matches the behaviour TWAMP-Light senders expect.
- **Strict (`--strict-packets`)** — short packets are rejected at the parser. The HMAC, MBZ, and `require_hmac` checks are independent of strictness — strict mode only changes how short packets are treated.

The contract is exhaustively pinned by `strict_packets_*` tests in `src/receiver/mod.rs`, including the explicit RFC 8762 §4.1.1 case that **non-zero MBZ on receipt is always ignored in both modes** (the RFC mandates "MUST be ignored on receipt"). Both modes also tolerate a zero-byte buffer without panicking.

### Capture-thread liveness signal

`ReceiverSharedState` carries `capture_alive: Arc<AtomicBool>` (initialised `true`). Both backends clear this flag when their receive loop exits unexpectedly (`nix`: socket creation or bind failure; `pnet`: missing interface, channel-init failure, send-socket bind failure, or a `spawn_blocking` panic propagated up through the JoinHandle). The flag exists so a future `/healthz` endpoint (and external monitors today, via SNMP or signal) can distinguish "process alive but not reflecting" from "process alive and healthy" without scraping stdout. Operationally this means a single dead capture loop never goes silent — it surfaces as `false` on this flag and as `log::error!` lines in the journal.

### Observability subsystem failure semantics (`--metrics` vs `--snmp`)

The two optional subsystems handle initialisation failure asymmetrically by design:

- **`--metrics` fails fast.** If the operator explicitly requested a Prometheus endpoint and the bind fails (`AddrInUse`, `AddrNotAvailable`, `PermissionDenied`, …), `main.rs` exits with a specific error message naming the `io::ErrorKind`. The reasoning: silently disabling the endpoint would leave dashboards and alerts running blind without any signal that they are.
- **`--snmp` degrades gracefully.** If the AgentX master socket is absent or unreachable (e.g. `net-snmpd` hasn't started yet during boot), `main.rs` logs a warning and continues with `None`. The reflector's primary duty — forwarding STAMP packets — is unaffected by the SNMP sub-agent being down. Operators who want SNMP-required-to-start semantics can wrap `stamp-suite.service` with a systemd ordering directive (`After=snmpd.service`, `Requires=snmpd.service`).

The same asymmetry is documented for end-users in [usage.md](usage.md#failure-semantics).

### AgentX sub-agent panic-resistance

The AgentX event loop runs inside `tokio::task::spawn_blocking`. A separate supervisor `tokio::spawn` task awaits the JoinHandle and logs panics (`JoinError::is_panic()`) and abnormal terminations rather than dropping them silently. The decoder itself was audited for production-path panics; every buffer-indexing site (`agentx::decode_header`, `decode_oid`, `decode_search_range`, `AgentXSession::handle_get_bulk`) is preceded by an explicit length check returning `AgentXError::Protocol`. The `MibHandler` dispatch (`StampMibHandler::get`/`get_next`) bounds-checks OIDs via `Oid::starts_with` before any indexing. Coverage is locked in by the malformed-input tests in `src/snmp/agentx.rs` and `src/snmp/handler.rs`.

## Session Management

`SessionManager` is **always** instantiated. Both backends extract a
`SessionKey` from the actual source/destination UDP endpoints, SSID, and optional
sender micro-session ID before admission. `--session-admission provisioned`
requires exact membership in immutable startup rules; permissive mode learns
runtime sessions from traffic. The core also enforces admission when a manager
is supplied. Live processing validates the base before allocating runtime state
or refreshing activity; rejected traffic does not enter session counters. `--stateful-reflector` controls only sequence generation; stateless
replies echo the sender sequence. Counters and Follow-Up/replay state are keyed
by the same full identity in both modes. Kernel TX timestamp correlation retains
the full key. Runtime expiry leaves provisioning intact. The legacy source-only
library API maps callers to SSID 0 with an unknown destination; live backends
always use the full key.

Sessions are reaped after `--session-timeout` seconds of inactivity (default 300 s). When the SNMP feature is enabled, `SessionSummary` / `session_summaries_extended()` exposes per-session data for the SNMP session table.

## TLV Extensions Reference

The implementation supports RFC 8972 TLV (Type-Length-Value) extensions, which allow STAMP packets to carry optional data beyond the base packet format.

### Supported TLV Types

Status labels used in this table — kept aligned with the (forthcoming) standards matrix:

- **supported** — structured parsing, validation, and reflector-side field population are complete and conform to the spec.
- **partial** — implemented to the spec on most paths but with a named gap (sub-TLV, sub-field, or backend-restricted feature). The gap is explicit in the table row.
- **experimental** — implements an active IETF draft. Wire format or type number may change before standardisation; treat as best-effort interop only.
- **interop-only** — present solely to interoperate with another implementation's non-standard extension. Off in default builds.

| Type | Name | Description | Status |
|------|------|-------------|--------|
| 1 | Extra Padding | Can carry Session-Sender ID (SSID) in first 2 bytes | supported |
| 2 | Location | Source/destination addresses and ports (RFC 8972 §4.2) | supported |
| 3 | Timestamp Info | Sync source and timestamping method (RFC 8972 §4.3) | supported |
| 4 | Class of Service | DSCP/ECN measurement (RFC 8972 §5.2) | supported |
| 5 | Direct Measurement | Sender/reflector packet counters (RFC 8972 §4.5) | supported |
| 6 | Access Report | Access identifier and return code (RFC 8972 §4.6) | supported |
| 7 | Follow-Up Telemetry | Previous reflection seq/timestamp (RFC 8972 §4.7) | supported |
| 8 | HMAC | TLV integrity verification (only Extra Padding may follow) | supported |
| 9 | Destination Node Address | Verify intended reflector identity (RFC 9503 §3) | supported |
| 10 | Return Path | Control reply routing: suppress, alternate address, SR-MPLS, SRv6 (RFC 9503 §4) | supported — suppress / alternate address (opt-in `--return-path-allow-alternate`, U-flag fallback when off) / SRv6 best-effort SRH forwarding (opt-in `--srv6-return-forwarding`, Linux+IPv6, graceful U-flag fallback); SR-MPLS echoed with U-flag (out of scope for userspace UDP) |
| 11 | Micro-session ID | Configured numeric identifiers (RFC 9534 §3.1) | encoding/validation supported; physical LAG association unsupported |
| 12 | Reflected Test Packet Control | Asymmetrical reply request — count, length, interval (draft-ietf-ippm-asymmetrical-pkts-14, IANA-assigned) | supported — emission, length padding (up to `--reflected-control-max-size`), L2 (§3.1.1) and L3 (§3.1.2) Address Group sub-TLV match against the reflector's own MAC/IP addresses; either mismatching drops the packet |
| 240 | BER Bit Pattern in Padding | Repeated bit pattern carried alongside Extra Padding (draft-gandhi-ippm-stamp-ber-07) | experimental |
| 241 | BER Bit Error Count | u32 error-bit count, computed by reflector | experimental |
| 242 | BER Max Bit Error Burst Size | u32 longest consecutive error run, computed by reflector | experimental — **wire-format collision with teaparty Heartbeat (same Type 242)**; see note below |
| 246 | Reflected IPv6 Extension Header Data | Reflects received IPv6 Hop-by-Hop / Destination Options headers (draft-ietf-ippm-stamp-ext-hdr) | pnet captures headers; nix returns the specified C flag |
| 247 | Reflected Fixed Header Data | Reflects the raw 20-byte IPv4 or 40-byte IPv6 fixed header (draft-ietf-ippm-stamp-ext-hdr) | pnet captures headers; nix returns the specified C flag |

**IANA registry**: Type 12 and the C flag (bit 3 of TLV flags) are IANA-assigned per draft-ietf-ippm-asymmetrical-pkts-14. Types 240–251 are *Experimental Use* per RFC 8972 §6 — picks by individual implementations.

**Type 242 collision**: stamp-suite uses Type 242 for *BER Max Bit Error Burst Size* (draft-gandhi-ippm-stamp-ber-07); teaparty uses the same Type 242 for an experimental *Heartbeat* TLV. Both are within the Experimental Use range so neither is wrong per IANA, but the wire formats are mutually incompatible. Use `--ber-omit-burst` when the peer assigns Type 242 to Heartbeat; forward error counts remain available, with forward burst statistics reported as unavailable.

**Backend restriction on Types 246/247**: Both require the reflector to copy raw IP-header bytes into the response, which is only possible when the capture path sees full IP headers. The default `nix` UDP-socket backend cannot provide this — see [Receiver Backends](#receiver-backends) for why the default remains `nix`. On the `nix` backend these TLVs are echoed with the C flag set per draft revision 13 §§5.1/5.2 and a one-time warning is logged.

### TLV Handling Modes

The reflector supports two TLV handling modes via `--tlv-mode`:

| Mode | Behavior |
|------|----------|
| `echo` (default) | Echo TLVs back to sender, marking unknown types with U-flag |
| `ignore` | Strip all TLVs from response (backward compatibility) |

### Backward Compatibility

The implementation is fully backward compatible:

- **No TLVs in packet**: Standard RFC 8762 handling is used
- **TLVs present**: Handled according to `--tlv-mode` setting
- **Old clients**: Work seamlessly with TLV-enabled reflectors
- **Senders with a nonzero SSID**: Replies must echo that SSID. Other nonzero
  IDs are discarded before measurement and control state updates. A legacy
  reflector returns zero in the single SSID field; `--on-zero-ssid` controls
  whether the sender continues or stops. The echoed sender Error Estimate is
  followed by MBZ bytes, not a second SSID field.

### TLV Wire Format (RFC 8972 Section 4.2)

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|STAMP TLV Flags|     Type      |            Length             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                         Value...                              |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

- **Flags (1 octet)**: U=Unrecognized (bit 0), M=Malformed (bit 1), I=Integrity failed (bit 2), C=Conformant Reflected Packet (bit 3, draft-ietf-ippm-asymmetrical-pkts, set only on Type 12 TLVs), Reserved (bits 4-7)
- **Type (1 octet)**: TLV type identifier (0-255)
- **Length (2 octets)**: Length of Value field in bytes

### Class of Service TLV (RFC 8972 §5.2)

The CoS TLV enables measurement of DSCP and ECN handling across the network path:

```bash
# Sender requests DSCP 46 (EF) and ECN 2
stamp-suite --remote-addr 192.168.1.100 --cos --dscp 46 --ecn 2
```

The reflector automatically fills in:
- **DSCP2/ECN2**: Values received at the reflector's ingress
- **RP (Reverse Path)**: Set to 1 if local policy rejected the requested DSCP

This allows detection of DSCP remarking or ECN modification in the network.

### Location TLV (RFC 8972 §4.2)

The Location TLV reports the observed source and destination addresses and ports at the reflector:

```bash
stamp-suite --remote-addr 192.168.1.100 --location
```

The TLV value begins with a fixed 4-octet prefix — Destination Port then Source Port (RFC 8972 §4.2) — that the reflector fills from the received UDP header, followed by sub-TLVs. The sender emits *generic request* sub-TLVs (Source IP = Type 7, Destination IP = Type 4) with the standard 4-octet STAMP TLV header and zeroed values; the reflector answers each with the corresponding *specific* sub-TLV for the observed address family (Source IPv4 = 8 / Source IPv6 = 9, Destination IPv4 = 5 / Destination IPv6 = 6) per §4.2.2, keeping the TLV Length unchanged. A generic Source MAC request (Type 1) is answered with a zeroed Source EUI-64 (Type 3) since neither backend observes the received frame's L2 source MAC; a sub-TLV the reflector cannot answer is echoed with the U flag, and one whose Length is invalid for its type is marked with the M flag. The reflector fills in the actual destination IP from the received packet (using `IP_PKTINFO`/`IPV6_RECVPKTINFO` on nix, or parsed IP headers on pnet), so it reports the correct address even when bound to a wildcard (`0.0.0.0`/`::`).

### Direct Measurement TLV (RFC 8972 §4.5)

The Direct Measurement TLV carries per-session packet counters for loss measurement:

```bash
stamp-suite --remote-addr 192.168.1.100 --direct-measurement
```

- **Sender** fills its transmit count (incremented per packet)
- **Reflector** fills its receive and transmit counts for the client's session

Counters are tracked per full session identity regardless of whether `--stateful-reflector` is enabled.
The sender reports provisional forward/reverse missing counts over a bounded
[observed counter window](measurements.md#direct-measurement-counter-window).

### Follow-Up Telemetry TLV (RFC 8972 §4.7)

The Follow-Up Telemetry TLV carries information about the previously reflected packet:

```bash
stamp-suite --remote-addr 192.168.1.100 --follow-up-telemetry
```

In stateful mode, the reflector reads a coherent sequence/timestamp/method record from the session. The method describes the actual stored timestamp, including asynchronous software or hardware TX corrections. Burst copies refresh all three before signing. Stateless replies zero the Follow-Up sequence and timestamp. The sender correlates
usable references against recent independent reflector sequences and reports
[corrected reverse delays and unresolved references](measurements.md#follow-up-corrected-reverse-delay).

### Timestamp Information TLV (RFC 8972 §4.3)

The Timestamp Info TLV describes the reflector's ingress T2 and egress T3:

```bash
stamp-suite --remote-addr 192.168.1.100 --timestamp-info
```

The sender zeroes all information fields. The reflector uses explicit system/PHC source settings, independently of NTP/PTP encoding and the Error Estimate S bit. An actual hardware T2 uses the PHC source; software T2 and current T3 use the system source. Current T3 is generated in software. See [clock metadata](usage.md#clock-synchronization-metadata) for configuration and registry values.

### Access Report TLV (RFC 8972 §4.6)

The Access Report TLV carries an access identifier and return code. The reflector echoes it unchanged:

```bash
stamp-suite --remote-addr 192.168.1.100 --access-report 5 --access-return-code 1
```

### Destination Node Address TLV (RFC 9503 §3)

The Destination Node Address TLV lets the sender specify the intended reflector address. The reflector checks whether the address matches any of its local interfaces:

```bash
# Verify that 192.168.1.100 is handling the reflection (requires --ssid)
stamp-suite --remote-addr 192.168.1.100 --ssid 1 --dest-node-addr 192.168.1.100
```

If the address does not match, the reflector sets the U-flag on the TLV and still reflects the packet, allowing the sender to detect misrouting (e.g., anycast failover).

### Return Path TLV (RFC 9503 §4)

The Return Path TLV controls how the reflector routes its reply. Several sub-TLV types are supported:

```bash
# Suppress reply entirely (control code 0)
stamp-suite --remote-addr 192.168.1.100 --return-path-cc 0

# Request reply to an alternate address
stamp-suite --remote-addr 192.168.1.100 --return-address 10.0.0.5

# Request SR-MPLS return path (echoed with U-flag in userspace)
stamp-suite --remote-addr 192.168.1.100 --return-sr-mpls-labels 100,200,300

# Request SRv6 return path
stamp-suite --remote-addr 2001:db8::100 --return-srv6-sids 2001:db8::1,2001:db8::2

# Reflector: opt in to best-effort SRv6 SRH forwarding (Linux, IPv6)
stamp-suite --is-reflector --srv6-return-forwarding
```

The reflector handles each sub-TLV type:
- **Control Code**: Bit 0 controls reply behavior (0=suppress, 1=reply); reserved bits are ignored per RFC 9503
- **Return Address**: Opt-in via `--return-path-allow-alternate` (off by default). When enabled, the reflector sends the reply to the specified IP; on send failure it sets the U-flag and falls back to the original source address. **When disabled (the default), the sub-TLV is echoed with the U-flag set and the reply goes to the packet source** — honouring arbitrary return addresses on an open reflector would make it a traffic-redirection / reflection gadget aimed at third parties (see [security.md](security.md#reflection-and-amplification-open-mode)).
- **SRv6 Segment List**: Best-effort forwarding (RFC 9503 §4 + RFC 8754), opt-in via `--srv6-return-forwarding`. When enabled and the kernel supports it, the reflector builds an SRv6 Segment Routing Header (`src/srv6.rs`) and attaches it to the IPv6 reply via an `IPV6_RTHDR` ancillary message (`sendmsg`). A one-shot capability probe gates the attempt; on a non-Linux/IPv4 path, an unsupported kernel, or any send error it falls back to a normal reply with the Return Path **U-flag** set. Disabled by default. The SRH construction is unit-tested against RFC 8754; the live kernel send path requires an SRv6-capable testbed to exercise fully.
- **SR-MPLS**: Echoed with U-flag set — forwarding an arbitrary MPLS label stack from a userspace UDP socket is out of scope (it requires raw `AF_PACKET` framing and next-hop resolution).

### Micro-session ID TLV (RFC 9534 §3.1)

The implementation encodes and validates configured 16-bit Micro-session IDs.
It does not map them to physical interfaces, force a LAG egress member, or verify
which physical ingress member delivered a packet. Numeric checks and ID learning
alone do not establish RFC 9534 physical-link conformance. No real-LAG test is
claimed; the RFC 9534 matrix records the unsupported association/steering clauses.

```bash
# Sender: advertise numeric ID 1 (does not select a physical member)
stamp-suite --remote-addr 192.168.1.100 --micro-session-id 1

# Reflector: supply numeric ID 2 when handling a Micro-session ID TLV
stamp-suite -i --reflector-member-link-id 2
```

The sender emits its configured ID in every request. It requires exactly one
usable Micro-session ID in every measured reply, even a base-only response or one
received through the base-parser option. The sender ID must match; the reflector
ID must be nonzero and match its configured or previously learned value. U/M flags
that make the ID unavailable, an I flag anywhere, duplicate IDs, or failed required
TLV integrity cause rejection without consuming the probe or changing its learned
ID. With a configured key, missing or unusable HMAC also prevents ID validation.
An M flag after an already validated ID stops later TLV processing under RFC 8972.

Learning is staged until the whole reply passes validation and corresponds to a
pending probe. Rejected or unsolicited micro-session replies cannot acknowledge
Access Reports or change congestion state. Non-micro sessions retain their existing
base-reply compatibility. The reflector compares a present, nonzero reflector ID
with its configured numeric ID, echoes the sender ID, and fills its configured ID;
that comparison is not a check of the actual ingress member.

### Reflected Test Packet Control TLV (draft-ietf-ippm-asymmetrical-pkts)

The Reflected Test Packet Control TLV (Type 12, IANA-assigned) lets the sender request asymmetrical reply traffic — multiple reply copies spaced at a specified interval:

```bash
# Ask for 4 replies, 1 ms apart
stamp-suite --remote-addr 192.168.1.100 \
    --reflected-control-count 4 \
    --reflected-control-interval-ns 1000000
```

Reflector behaviour (aligned with draft-14 §3 as of this release):

- **Disabled by default** (`--reflected-control-max-count` defaults to 0), per draft-ietf-ippm-asymmetrical-pkts, which requires the feature be administratively controllable and off by default: the reflector then sends only the single normal reply and sets the **C flag** (Conformant Reflected Packet, bit 3 of the TLV flags byte, mask 0x10) to signal the request was not honoured. Set a positive `--reflected-control-max-count` (e.g. 16) to opt in; the reflector then emits up to that many reply packets per request and clamps/​C-flags anything above it. Pair with `--max-pps` to bound amplification.
- Clamps the inter-packet interval up to at least `--reflected-control-min-interval-ns` (default 1 µs).
- Honours requested Type-12 length up to the administrative cap, then checks the actual reply route in `receiver/mtu.rs` before each datagram in `receiver/transmit.rs`. Linux RTM_GETROUTE includes the UDP flow, DSCP and IPv6 scope; route metrics and interface MTU bound the payload after IP/UDP/SRH overhead. A bounded cache uses route/interface notifications, 250 ms expiry and forced refresh after EMSGSIZE. The send path prevents fragmentation, removes padding/optional header TLVs as needed, sets C and stops a clamped burst, and signs the final bytes. Unavailable budgets or mandatory fields that cannot fit cause a drop. See [usage](usage.md) for supported encapsulation and platform limits. Runtime size updates change the administrative limit, not a startup interface ceiling.
- Parses **Layer-2 Address Group sub-TLV** (sub-TLV Type 10, draft §3.1.1): the reflector bitwise-ANDs the requested mask against each of its own local MAC addresses (enumerated via `build_local_macs`, both backends) and checks equality against the group field; if none matches, the packet is dropped per §3.1.1 ("MUST stop processing the received packet"). All enumerated MACs are 6-octet EUI-48s, so only the 12-octet Sub-TLV Length (6-byte mask + 6-byte group) can ever match — the 4- and 16-octet forms always fail to match. No frame-level visibility is required, so this is evaluated the same way on both the `nix` and `pnet` backends.
- Parses **Layer-3 Address Group sub-TLV** (sub-TLV Type 11, draft §3.1.2): the reflector applies the requested prefix mask to each of its local IP addresses; if none matches, the packet is dropped per §3.1.2 ("MUST stop processing the received packet"). The drop surfaces to the backend as `ReturnPathAction::SuppressReply`.
- L2 and L3 Address Group sub-TLVs may appear together on the same TLV; each gates independently, so a mismatch on either one drops the packet (both must match for the packet to be reflected). A malformed sub-TLV (Sub-TLV Length outside the valid set) is skipped rather than gating anything — it simply does not participate in matching, per how out-of-range L3 prefix lengths were already handled.
- Enforces the draft-14 §3 minimum value-field size of 12 octets at parse time. The sender path (`ReflectedControlTlv::encode_value`) emits 4-byte zero placeholders to satisfy this when no real sub-TLV is attached.
- Both backends use a deadline queue with one entry per active burst. The `nix` receive loop owns all sends, including kernel TX timestamp correlation; `pnet` has a dedicated send worker so inter-copy waits do not block capture. After a successful copy, the next deadline is the current time plus the requested interval. OS scheduling and send work can lengthen the observed interval; nanosecond precision is not guaranteed.
- Every copy uses the same transport policy. On Linux one `sendmsg` carries CoS, matched source address, and supported SRH together. Other supported platforms update cached CoS before the sole send owner's syscall when the setting changes. SRH/source/alternate-address failures take the shared best-effort fallback path; flag changes are signed with the request's selected key. Socket queue pressure stops the remaining burst and records a drop without downgrading metadata.
- On the first eligible send, each queued request prepares an immutable `TransportPlan` containing its destination, source/CoS choices, fragmentation requirement and optional shared SRH bytes. Later copies clone the options, keeping fallbacks local to one copy and retaining the originally selected signing key. Expired/suppressed work never needs that preparation. Session sequences, timestamps, telemetry and route-MTU checks remain dynamic at each attempt.
- Both backends use `DatagramSender`, a mutable owner borrowed from each socket. Linux CoS/source/SRH remain per-datagram ancillary data. PMTU policy is necessarily a socket setting here; the owner serializes changes and caches successful settings separately for IPv4/IPv6. Ordinary traffic after controlled traffic restores the original policy. Non-Linux CoS uses the same owner/cache, and failed option changes are retried. Receive operations may share the socket; another send/option writer would invalidate this ownership contract. Bound local endpoints are captured once for route lookups. An incomplete datagram send does not update transmit/Follow-Up counters or attempt routing fallbacks.
- One shared reservation budget bounds pending requests (`--reflector-queue-capacity`, default 1024), including the active send and the bounded pnet handoff channel. Capture uses nonblocking `try_send`; the worker services at most one handoff before each due copy so short-interval bursts do not starve reserved new work. The nix loop retains its unbiased socket/timer scheduling.
- Session drain rejects new identities and lets existing sessions/bursts continue within the work limit. Expiry retires that session and cancels its remaining copies when serviced. Shutdown stops all new packet intake, drains accepted work for `--reflector-shutdown-grace-ms` (default 0, maximum 60000), then discards the remainder. `ShutdownDrain` sets one deadline that subsequent signals cannot extend; empty work exits early. Ctrl-C, Unix SIGTERM and control shutdown use this policy. Deadline checks precede each send-loop iteration; polling, scheduling and in-flight syscalls can delay observation.
- Pnet capture uses a 100 ms timeout even with session expiry disabled; send sockets are nonblocking. The async shutdown observer is cancelled when capture ends; cancelling the receiver future signals capture too. RAII guards stop capture if the send worker exits and join the worker on capture unwind. Normal shutdown joins workers before printing stats. The queue wrapper also accounts for copies discarded from a closed channel or during unwinding.
- `reply_queue_rejected` counts requests refused at the work cap; `queued_replies_cancelled` counts discarded unsent copies. Reflector text/JSON/CSV summaries and control status expose them. Aggregate dropped packets gain one per rejected request or cancelled request remainder. Ordinary send failures/suppression retain their existing drop accounting. No new SNMP OIDs are introduced; existing aggregate drop counters continue to include queue drops.

### Bit Error Rate TLVs (draft-gandhi-ippm-stamp-ber)

Three experimental TLVs cooperate to measure residual bit errors in the Extra Padding TLV (RFC 8972 Type 1). Type numbers in the draft are TBD; this implementation uses 240/241/242 from RFC 8972's experimental range.

| Type | Name | Direction |
|------|------|-----------|
| 240 | Bit Pattern in Padding | sender → reflector (carries the pattern used to fill padding) |
| 241 | Bit Error Count in Padding | reflector fills (u32 popcount of XOR diff) |
| 242 | Max Bit Error Burst Size | reflector fills (u32 longest consecutive error run) |

```bash
# Default pattern 0xFF00, 128-byte padding
stamp-suite --remote-addr 192.168.1.100 --ber --ber-padding-size 128

# Custom pattern (hex; `0x` prefix optional)
stamp-suite --remote-addr 192.168.1.100 --ber --ber-pattern aa55 --ber-padding-size 256
```

The reflector measures errors against the expected pattern, records the count and longest
bit-error burst, and repairs the padding before replying. Missing/duplicate padding,
duplicate BER TLVs, and non-divisible pattern lengths get C flags. Empty explicit
patterns are rejected; omitting Type 240 selects `ff00`. BER padding follows the HMAC
TLV so errors in padding remain measurable while metadata stays protected.

`--ber-interval N` computes windows of `N × --send-delay` milliseconds (default N=10).
The configured interval stays fixed if ECN changes the actual send delay. Each accepted
pending probe contributes at most one BER sample. Duplicate replies and replies with
missing, invalid, C/I/M-flagged or unverifiable metadata do not inflate the totals.
A BER U flag disables subsequent BER requests while preserving the other measurements.
The sender computes forward errors from the reflected count and reverse errors from
the repaired padding. Text, JSON and CSV summaries include packet/bit totals, error
ratios, errored packets, maximum/average error bursts, and interval records. CSV appends
a quoted JSON `ber` cell. Omitted burst requests report null forward burst statistics.

`--ber-bit-threshold` and `--ber-packet-threshold` set thresholds per million in both
directions. A completed interval crossing above a threshold produces a structured log
event and an alarm in the summary; remaining above it does not repeat the alarm. Empty
windows are omitted; the last nonempty partial window is labeled `complete: false` and
does not trigger threshold alarms. BER follows monotonic receipt time, not the peer's clock.
History uses bounded deques: the latest 1024 completed nonempty intervals and 1024
alarms, plus the current partial interval in snapshots. `intervals_omitted` and
`alarms_omitted` count evictions. Lifetime directional aggregates and live alarm
logging are independent of retention. Snapshot cloning is therefore bounded too.

On Linux, the sender trims padding in whole pattern repetitions using the connected
route MTU and prevents fragmentation. The reflector checks the actual reply route MTU
at each send. If reply sizing changes the padding length, BER metadata gets C flags
because the original forward denominator cannot be preserved. A metadata-only packet
that cannot fit is dropped. Type-12 resizing can therefore yield no BER sample; use
symmetric replies for measurement. Non-Linux active PMTU enforcement remains unverified.
Normal UDP checksums and link CRC/FEC may discard corrupted packets before delivery;
these statistics describe delivered padding and are not a measurement of raw link BER.
See the [BER-07 matrix](conformance/draft-stamp-ber.md) for scoped conformance evidence.


### Reflected Fixed / IPv6 Extension Header Data TLVs (draft revision 13)

The feature implements draft-ietf-ippm-stamp-ext-hdr-13, an Internet-Draft.
Type 246 carries Requested(8) plus Reflected(Length−8); Type 247 carries
Requested(4) plus Reflected(Length−4). Length is the target header's complete
size. A zero selector matches the first unconsumed matching-length header;
nonzero selectors match all eight or four on-wire octets. The Requested field
is preserved, and only the corresponding header tail is copied.

```bash
# One originated fixed IP header, reflected when the backend can capture it.
stamp-suite --remote-addr 192.168.1.100 --reflected-fixed-hdr

# Linux: a real 16-byte Destination Options header plus its matching request.
stamp-suite --local-addr :: --remote-addr 2001:db8::1 \
  --attach-ext-hdr dest:0001010c000000000b0c0d0e0f101112
```

Pnet validates IP/UDP framing and checksums before admitting captured packets,
including the innermost endpoint addresses for IP-in-IP. Raw capture must expose
complete wire checksums; checksum-offload partial frames are rejected. Nix cannot
access the raw headers and echoes recognized requests with **C**, preserving their
values and lengths. Missing headers, selectors or length matches also produce C.
Both backends set C in the control sub-TLV when reverse-header insertion is requested
but cannot be performed. These are specified fallback behaviors, not U-flag responses.

Sender attachment supports one HBH then one Destination Options header on Linux.
Explicit Type 246 requests replace automatic requests and must match the attached
headers in order; ambiguous same-length subsets require selectors. One Type 247
request is supported for the sender's single IP header. Attachment/MTU setup failure
aborts header-request origination. MTU is rechecked before normal sends, optional
header TLVs are removed when needed, and PMTU/DF prevents oversized fragmentation.

Experimental Type 246/247 and sub-TLV 240 values require peer agreement. Type 246
is wire-incompatible with revision 11. See the [revision-13 matrix](conformance/draft-stamp-ext-hdr.md)
for the supported profile and [measurement semantics](measurements.md) for the
new session-state notifications.

## Prometheus Metrics

When built with `--features metrics`, the reflector can expose Prometheus metrics:

```bash
cargo build --release --features metrics
stamp-suite -i --metrics --metrics-addr 127.0.0.1:9090
```

Available metrics include:
- `stamp_reflector_packets_received_total` — Total packets received
- `stamp_reflector_packets_reflected_total` — Total packets reflected
- `stamp_reflector_packets_dropped_total` — Dropped packets by reason
- `stamp_reflector_active_sessions` — Current active sessions (stateful mode)
- `stamp_reflector_hmac_failures_total` — HMAC verification failures
- `stamp_reflector_processing_seconds` — Packet processing time histogram

## SNMP AgentX Sub-Agent

When built with `--features snmp` (Unix only), stamp-suite can connect to an existing net-snmpd master agent via the AgentX protocol (RFC 2741) and expose reflector/sender state through a custom STAMP-SUITE-MIB.

```bash
cargo build --release --features snmp

# Reflector with SNMP
stamp-suite -i --snmp

# Custom AgentX socket path
stamp-suite -i --snmp --snmp-socket /var/agentx/master

# Query via net-snmp tools
snmpwalk -v2c -c public localhost .1.3.6.1.4.1.65134
```

The MIB (provided in `mibs/STAMP-SUITE-MIB.mib`) exposes:

| Subtree | Contents |
|---------|----------|
| Reflector Config | Admin status, listen address/port, auth mode, TLV mode, stateful flag, session timeout |
| Reflector Stats | Packets received/reflected/dropped, active sessions, uptime |
| Session Table | Per-client address, port, packet counts, last sequence number, last active time |
| Sender Config | Remote address/port, local port, packet count, send delay, auth mode |
| Sender Stats | Packets sent/received/lost, RTT min/max/avg, jitter, loss percentage |

Sender statistics are updated live during the measurement run (not just at completion), so SNMP polling reflects current progress.

GETBULK emits repeating ranges in iteration order (A1, B1, A2, B2), retains
end-of-MIB placeholders for exhausted ranges, and stops after an entirely exhausted
iteration. GETNEXT and the first GETBULK lookup honor inclusive starts; subsequent
lookups are strictly advancing, and end bounds remain exclusive. One OID snapshot
is shared across the request. Requests above 256 ranges receive `genErr` at index
257; repetition work remains capped at 100 complete iterations.

The request reader retains partial headers and payloads across one-second socket
read timeouts. These timeouts are cancellation checks, not frame boundaries. Incoming
payloads remain capped at 1 MiB before allocation. EOF or malformed framing ends the
connection and lets the existing supervisor reconnect. Cancellation during a partial
frame closes the transport; it cannot treat those bytes as a Close acknowledgment.
A master-initiated Close receives a correlated success response before teardown.

See the [targeted AgentX review](conformance/agentx-review.md) for RFC references
and verification scope. The master wire fixtures are independent of the production
codec; they are not a Net-SNMP interoperability certification.


**Note**: The `snmp` feature requires a Unix platform (Linux/macOS) because AgentX uses Unix domain sockets. On non-Unix platforms, `--snmp` prints an error and exits.

## Hardware-Assisted Timestamping

Support for Linux NIC timestamping capabilities, selected at runtime via
`--hwtstamp auto|on|off` (default `auto`).

**Current status** (kernel read paths gated behind the `hwtstamp` cargo
feature; no extra dependencies).

- Capability probe ✅ — `ETHTOOL_GET_TS_INFO` via the `SIOCETHTOOL`
  ioctl, run at startup against the interface owning `--local-addr`
  (resolved with `getifaddrs`; wildcard binds skip the probe). The
  result is logged: `hwtstamp probe: interface=… rx_hw=… tx_hw=… ptp=…`.
- Kernel RX timestamps ✅ (Linux + macOS) — the reflector's T2 and the
  sender's T4 come from `SCM_TIMESTAMPING` cmsgs (Linux) or
  `SCM_TIMESTAMP` (macOS, software tier, µs resolution) instead of a
  post-wakeup userspace clock read. Over loopback this cuts the
  measured forward OWD from ~50–150 µs of scheduler noise to single-digit
  microseconds.
- Kernel TX timestamps ✅ (Linux) — `MSG_ERRQUEUE` with
  `SOF_TIMESTAMPING_OPT_ID` correlation. On the sender, the stored T1
  used for forward OWD is corrected retroactively before the response is
  processed. On the reflector, the Follow-Up Telemetry record (RFC 8972
  §4.7) is corrected, so the FUT TLV reports the previous reply's kernel
  TX time. Every nix burst copy participates in the same serialized OPT_ID mapping, which holds a weak reference to the validated session. Note: T3 *inside* a reflected packet is physically
  uncorrectable (the timestamp is serialized before the send) — that is
  exactly the gap FUT exists to close.
- NIC hardware tier ✅ (Linux, `--hwtstamp on`) — sets NIC filters via
  `SIOCSHWTSTAMP` (needs CAP_NET_ADMIN) and requests the raw-hardware
  timestamp slots; every failure falls back to the kernel software tier
  with a warning. Type 3 reports `HwAssist` only for an actual hardware T2;
  current T3 is software. The FUT mode byte comes from the stored TX report,
  not the enabled socket tier. Software and hardware reports may arrive
  separately; correlation is retained while hardware is pending, and a
  software report cannot overwrite an already corrected hardware record.
- Windows ❌ — the pnet receiver captures at the datalink layer (no
  socket to timestamp) and a sender-side `SIO_TIMESTAMPING` port is
  future work; the feature compiles to a graceful no-op there.

> **PHC clock-domain caveat (hardware tier).** NIC hardware timestamps
> are taken on the PTP hardware clock, not CLOCK_REALTIME. One-way
> delays mix the local timestamp domain with the peer's, so hardware
> timestamps are only meaningful for OWD when the PHC is disciplined to
> the same timescale as the peer (ptp4l + phc2sys). Round-trip
> quantities require a consistent clock domain within each endpoint too:
> hardware T2 and software T3 are different clocks unless explicitly aligned.
> Declaring their synchronization sources does not perform that alignment.
> `--hwtstamp on` leaves this responsibility with the operator; `auto` never
> uses the hardware tier.

**Defensive contract.** Hardware timestamping is a per-NIC capability —
some adapters support RX, some both, most consumer NICs neither. The
implementation:

- Never panics and never fails the probe fatally: unknown interfaces,
  rejected ioctls, and non-Linux platforms all degrade to "no
  capabilities".
- Never refuses to start the binary, even with `--hwtstamp on`: that
  mode warns rather than aborts.
- Is structured for per-direction reporting in the Type 3 Timestamp
  Information TLV (`effective_method(mode, cap, direction)`): `HwAssist`
  only when the NIC really provides the timestamp — which awaits the
  kernel read path.

**Modes.**

- `auto` *(default)* — probe silently; use HW when the read path lands
  and the NIC supports it, software otherwise. Safe on every host.
- `on` — probe and warn at startup when hardware timestamps cannot be
  used, so an operator who explicitly asked for HW is told what they
  actually got and why.
- `off` — software timestamps only; the probe result is informational.

**Clock-domain limitation.** The kernel RX/TX paths above are implemented.
Live NIC hardware verification still requires suitable hardware and privileges.
Use the [two-host hardware procedure](testing-hardware-timestamps.md) to record
actual RX/Follow-Up TX methods and clock-domain evidence. A capability probe or
software fallback does not count as a hardware pass.
The PHC clock-domain hazard remains: NIC hardware timestamps live on the
PTP hardware clock, which is only meaningful against CLOCK_REALTIME
T1/T4 when the PHC is synchronized (ptp4l/phc2sys) — the read path must
gate on that or surface it via the Error Estimate S-bit.

## Benchmarks

`benches/reflector_hotpath.rs` is a Criterion harness that drives
`process_stamp_packet` end-to-end through the in-process pipeline (no
real UDP). It measures parse + HMAC + TLV processing + response
assembly without the kernel scheduler in the loop — useful for catching
performance regressions in the parser, HMAC code, or TLV walkers
without socket-level noise.

Run:

```bash
cargo bench --bench reflector_hotpath
# or a single bench:
cargo bench --bench reflector_hotpath -- unauth_full_chain
```

HTML reports land under `target/criterion/<bench>/report/`.

Bench cases:

- `unauth_no_tlvs` — 44-byte open-mode baseline.
- `unauth_one_tlv` — open mode + a CoS TLV.
- `unauth_full_chain` — open mode + CoS + Location + Direct Measurement
  + Follow-Up Telemetry + Timestamp Info + Access Report.
- `auth_no_tlvs` — 112-byte authenticated baseline with HMAC
  verification on the success path.
- `auth_full_chain` — authenticated mode + the same TLV chain.

`examples/live_udp_bench.rs` measures the complete reflector over real loopback
UDP, including achieved send/receive rates, loss, generator/reflector CPU, and
idle CPU before and after load. It supports IPv4/IPv6, authentication and stateful
sequencing, records repeated trials and binary/environment metadata, and checks
that reception resumes after idle. See [benchmarks.md](benchmarks.md) for release
build commands, accounting definitions and measurement limits. In-process
operations/sec and generator-limited loopback results are not NIC capacity
measurements. Performance claims require recorded measurements for the actual
build and environment.

## See Also

- [README](../README.md) — install and quick-start.
- [usage.md](usage.md) — configuration file format, full CLI flag reference.
- [security.md](security.md) — HMAC, key management, systemd hardening, capability model.


### Session admission API and lifetime

`SessionManager::get_or_create_session`, `get_session_and_seq`, and
`generate_sequence_number` return `Option`: `None` means acquisition was denied
(or the acquired session expired before sequence allocation). Callers must handle
rejection instead of substituting a new Session or sequence zero. The shared live
pipeline propagates rejection in both backends; standalone stateful processing
also propagates a manager's denial.

The internal `SessionAdmissionPermit` carries only the immutable provisioning
decision. It is consumed once, belongs to one manager/key, and holds no lock
across authentication. Cap/drain changes or expiry between checking provisioning
and acquisition still apply. Public session acquisition uses the same path.
Standalone stateful processing takes its sequence directly from the acquired
handle under its lifetime guard; standalone stateless processing only checks
provisioning and does not allocate/refresh runtime state. Neither standalone mode
updates the live receive/replay counters.

Tests count base-HMAC verifications, provisioning checks and acquisitions across
both sequencing modes, IP families, new/existing sessions and burst sends. These
counters compile only in test builds. Earlier correctness fixes already removed
repeated live authentication and session acquisition; the remaining new-session
provisioning check and hash-table insertion lookup are now shared. This is an
operation-count reduction, not a measured throughput gain. The table remains
unsharded; no multi-session contention measurements justify changing its locking.

The table write lock serializes creation with cap/drain updates. Cap pressure
never evicts an existing entry. Explicit/idle expiry removes an entry and takes
its session lifetime write lock before admitting another instance of that
identity. Each send holds a lifetime read guard through its syscall, retries,
and counter/Follow-Up updates; retirement excludes later sends using the old Arc.
The send path never takes the session-table lock while holding this guard.
