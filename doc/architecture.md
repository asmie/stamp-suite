# Architecture

This document describes how stamp-suite is built inside: its modules, the two
reflector backends, the packet paths through sender and reflector, and how each
TLV is handled. It is for contributors and reviewers. Operator behavior and
options are in [usage](usage.md); protocol scope is in
[conformance](conformance/README.md).

One binary runs as a Session-Sender or a Session-Reflector over UDP (default
port 862). The sender sends probes and records replies. The reflector
timestamps accepted packets and returns them.

## Module structure

Paths are relative to `src/`. The library modules are public only so that
integration tests, benchmarks and fuzz targets can reach them. They are
internal and are not covered by the CLI, configuration and wire compatibility
contract.

### Entry points and configuration

| Module | Purpose |
| --- | --- |
| `main.rs` | Binary entry: logging, timestamp capability probe, metrics server, then the sender or reflector role. Installs signal handlers and the SIGHUP key reload. |
| `lib.rs` | Module list and `StartupError`, the error type that makes `main` exit nonzero. |
| `configuration.rs` | CLI definition (clap), TOML configuration file merge, JSON schema output and validation. Unit tests are in `configuration/tests.rs`. |
| `shutdown.rs` | The process shutdown token and `cancel_on_signal` for SIGINT and SIGTERM (Ctrl-C on Windows). |

### Wire format and TLVs

| Module | Purpose |
| --- | --- |
| `packets.rs` | Base packet layouts (44-byte open, 112-byte authenticated) with hand-written big-endian `to_bytes`/`from_bytes`. |
| `tlv/core.rs` | `TlvError`, `TlvFlags`, `TlvType`, `RawTlv` and size constants. |
| `tlv/experimental.rs` | Experimental TLV and sub-TLV codepoints (240 to 251), kept in one place for renumbering. |
| `tlv/list/` | `TlvList`: parsing, ownership, HMAC placement and serialization; `processing.rs` holds the in-place reflector updates. |
| `tlv/traits.rs` | `TypedTlv` trait for conversion between `RawTlv` and typed values. |
| `tlv/typed/` | One file per TLV type with its value layout. |
| `crypto.rs` | HMAC-SHA-256 keys, key files and directories, base and TLV HMAC computation and verification. |
| `error_estimate.rs` | The 16-bit Error Estimate field (RFC 8762 §4.2.1). |
| `clock_format.rs` | `ClockFormat` (NTP or PTP). |
| `time.rs` | Timestamp generation and conversion of NTP/PTP wire timestamps to Unix time. |
| `tos.rs` | The IPv4 TOS / IPv6 Traffic Class octet: DSCP and ECN. |

### Sender

| Module | Purpose |
| --- | --- |
| `sender.rs` | Public entry points (`run_sender`, `run_sender_with_output`, `run_senders`), reply processing, and `fuzz_reply` for the fuzz target. |
| `sender/run.rs` | One sender run: socket setup, probe schedule, final reply drain and Access Report retries. |
| `sender/schedule.rs` | Probe spacing: periodic or Poisson. |
| `sender/packet.rs` | Test packet and request TLV construction. |
| `sender/socket.rs` | Sender socket options: egress TOS, attached IPv6 extension headers, route MTU and reply TOS reception. |
| `sender/validate.rs` | Validation of reflected TLVs before any value is used. |
| `sender/telemetry.rs` | Typed results of validation (HMAC status, Access Report, CE, Micro-session ID). |
| `sender/measurements.rs` | Reply-copy accounting and the optional counter and Follow-Up measurements. |
| `sender/access_report.rs` | Access Report retransmission state (RFC 8972 §4.6). |
| `sender/congestion.rs`, `rate_control.rs` | Response to CE-marked replies (AIMD, draft-ietf-ippm-stamp-cos-ecn-01 §3.4). |
| `sender/session_state.rs` | Session state notifications (draft-ietf-ippm-stamp-ext-hdr-15 §9.2). |
| `sender/observer.rs` | `SenderObserver`: live sender events for metrics, SNMP and library callers. |

### Reflector

| Module | Purpose |
| --- | --- |
| `receiver/mod.rs` | Backend selection, shared admission, authentication and processing (`process_stamp_packet`). |
| `receiver/ingest.rs` | Startup settings and the per-packet ingest path shared by both backends. |
| `receiver/nix.rs` | UDP socket backend (`recvmsg` with ancillary data). |
| `receiver/pnet.rs` | Raw capture backend (pnet datalink) with a separate send worker. |
| `receiver/assemble.rs` | Reply packet assembly with TLV handling. |
| `receiver/transmit.rs` | Reply queue and budget, shutdown drain, `DatagramSender`, final per-send timestamps and signing. |
| `receiver/mtu.rs` | Linux route MTU lookup with a notification-invalidated cache. |
| `receiver/shared.rs` | `ReceiverSharedState` (counters, sessions, keys, caps, shutdown token) and `reload_keys`. |
| `receiver/limits.rs` | Reflector counters, the per-source rate limiter and runtime Type 12 caps. |
| `receiver/keys.rs` | Per-packet HMAC key selection. |
| `receiver/replay.rs` | Sequence replay classification (RFC 10052 §5). |
| `receiver/reflected_control.rs` | Type 12 request parsing and Address Group matching. |
| `receiver/local_addrs.rs` | Local addresses and MACs for Destination Node Address and Address Group matching. |
| `receiver/reply_bytes.rs` | In-place edits to an assembled reply when the send path falls back. |
| `cos_policy.rs` | Which DSCP and ECN values a reply may use. |
| `reply_source.rs` | Reply source address pinning (RFC 9503 §3). |
| `srv6.rs` | SRv6 return-path forwarding (RFC 9503 §4, RFC 8754). |

### Sessions, networking and measurement

| Module | Purpose |
| --- | --- |
| `session.rs` | Session table, counters, replay windows, Follow-Up state and lifetime. |
| `session_identity.rs` | Session identity and static reflector admission (RFC 8972 §3). |
| `net_policy.rs` | Outgoing TTL/Hop Limit 255, interface binding (`--interface`) and sender port selection (draft-ietf-ippm-stamp-ext-hdr-15 §3.1). |
| `net_scope.rs` | Interface zones for IPv6 link-local endpoints. |
| `hwtstamp.rs` | Kernel and NIC timestamping with per-packet provenance. |
| `stats.rs`, `stats/` | Statistics collection and text/JSON/CSV output; `stats/quantiles.rs` holds bounded quantiles and `stats/clock_quality.rs` the declared clock quality. |
| `ber.rs` | Residual bit error measurement (draft-gandhi-ippm-stamp-ber-07). |
| `log_throttle.rs` | Throttled logging for events a remote peer can trigger on every packet. |

### Monitoring and control (optional features)

| Module | Feature | Purpose |
| --- | --- | --- |
| `metrics/` | `metrics` | Prometheus `/metrics` endpoint; `reflector_metrics.rs` and `sender_metrics.rs` define the series. |
| `snmp/` | `snmp` (Unix) | AgentX sub-agent for STAMP-SUITE-MIB: `agentx.rs` (protocol), `handler.rs` (MIB reads), `oids.rs`, `state.rs`. |
| `control/` | `control` | Reflector REST API for sessions, keys, limits, status and shutdown. See [control plane](control-plane.md). |

## Receiver backends

Both backends hand each datagram to the same ingest, processing and
transmission code (see [Reflector packet path](#reflector-packet-path)).

| | nix | pnet |
| --- | --- | --- |
| Default platform | Linux, macOS | Windows |
| Input | UDP socket and `recvmsg` ancillary data | Datalink frames parsed as Ethernet/IP/UDP |
| Filtering and checksums | Kernel UDP stack | The capture parser validates framing and checksums |
| Metadata | TTL/Hop Limit, DSCP/ECN, destination address and interface | Raw IP headers, source MAC and the same metadata |
| Header reflection | Linux: Type 246 from ancillary data, C on Type 247. macOS: C on both. | Types 246 and 247 |
| Requirements | Ordinary UDP socket permissions | Linux `CAP_NET_RAW`; Windows Npcap |
| Scheduling | One async loop receives and sends | Blocking capture thread plus a send worker thread |

Backend selection happens at build time. Linux and macOS use nix and Windows
uses pnet. The `ttl-pnet` feature selects pnet on any platform; `ttl-nix`
selects nix and only matters when `ttl-pnet` is also enabled, so
`--all-features` builds nix. See [Networking](usage.md#networking) for the
operator view.

The nix backend receives only traffic delivered to its bound UDP socket and
passes through the normal host firewall path. Raw capture sees interface
traffic before UDP delivery, so UDP INPUT filtering alone does not restrict it.
Pnet replies use UDP sockets bound to the STAMP port, so connected senders
accept the source port. Pnet captures one interface: it needs a concrete local
address, or a wildcard address together with `--interface`.

Nix `recvmsg` calls run inside `UdpSocket::try_io`. `WouldBlock` clears the
cached readiness; bypassing this wrapper can make an idle loop spin. The sender
uses the same pattern for ECN and kernel timestamps.

### Capture liveness flag

`ReceiverSharedState::capture_alive` starts as `true`. The pnet backend sets it
to `false` when capture cannot start or the capture thread ends abnormally; the
nix backend never changes it. No production code reads the flag: metrics, SNMP
and the control API do not report it. Only tests read it (a unit test in
`receiver/pnet.rs` and `tests/pnet_loopback_test.rs`). Capture failures are
logged, and a startup failure returns an error so the process exits nonzero.

## Reflector packet path

### Ingest

`receiver/ingest.rs` is the shared path between a backend and the reply queue.

At startup, `ReflectorSettings::from_config` resolves the configuration once.
A missing key in authenticated mode, or a CoS policy, location disclosure
setting or error estimate that does not parse, stops startup. `ReflectorCore`
then holds those settings together with the shared counters, rate limiter,
session manager, keyset, runtime caps and the reply budget
(`--reflector-queue-capacity` slots).

For each datagram, the backend builds a `ReceivedPacket`: the bytes, source,
destination address and local endpoint (including an IPv6 zone), TTL, DSCP,
ECN, ingress interface, source MAC (pnet only), captured IP headers, and the
kernel or NIC receive timestamp with its method. `ReflectorCore::ingest` then:

1. Applies the per-source rate limiter (`--max-pps`, `--reflector-rate-burst`).
   A limited packet is counted and dropped.
2. Counts the packet and reserves one `ReplyBudget` slot. A full budget rejects
   the packet before any session state changes (`reply_queue_rejected`).
3. Takes a read guard on the keyset and builds the `ProcessingContext`. Runtime
   caps are read once here, so a control-plane change applies to whole packets.
4. Runs processing inside `catch_unwind`. A panic drops that packet and is
   logged; it does not stop the reflector.
5. Attaches the reply to the reserved slot and returns it for queuing, or
   counts a drop.

The slot covers validation, handoff, queued deadlines and active sending until
every copy is sent or discarded.

### Processing and transmission

1. Extract the full session identity and check static provisioning.
2. Parse the base packet and verify configured authentication. A rejected base
   cannot create or refresh a session.
3. Acquire the session under the current cap and drain rules. Update receive
   state and classify replay without advancing the replay window yet.
4. Parse and verify TLVs, apply flag rules, resolve routing and CoS requests,
   and assemble the reply. A bad TLV HMAC produces I-flagged echoes; this is
   separate from base HMAC rejection.
5. Commit the validated replay sequence after assembly and queue the reply.
6. At each send attempt, check session lifetime and route MTU, assign the
   stateful sequence, refresh T3 and eligible telemetry, and sign the final
   bytes.
7. A successful send updates the session's transmit and Follow-Up state.

The keyset read guard spans authentication and assembly. The queued reply owns
the key it selected, so key rotation cannot change the key between acceptance
and signing. Fallbacks keep the sequence and refresh timestamps and signatures
after the change. T2 and the echoed sender fields stay those of the original
request.

### TLV ownership and signing

`TlvList` owns each value once. Non-HMAC entries form a prefix and HMAC entries
form a suffix. Optional indices record the received wire order, including
malformed chains and Extra Padding after HMAC. Mutation updates the owner;
serialization uses the indices. Duplicate HMAC partitioning uses linear swaps.

Verification hashes the sequence number and the original covered prefix. Only
Extra Padding may follow HMAC, and it is outside that coverage. New signatures
use the outgoing order, with BER padding after HMAC. Failure echoes keep the
received order and digest bytes and set the required flags. Malformed lists are
not re-signed by normal TLV regeneration. Final signing at send time operates
on the reply buffer.

### Short packets and `--strict-packets`

By default a short base packet is zero-filled before parsing and HMAC
verification (RFC 8762 §4.6). `--strict-packets` rejects it instead.
Authentication checks are independent of this setting, and received MBZ fields
are ignored in both modes.

## Sender run loop

`sender/run.rs` runs one session. `run_senders` (in `sender.rs`) opens one
`SenderRun` per `--remote-addr` before sending any probe, so a startup error in
one target stops them all. It then runs them concurrently and labels each
report with its target when there is more than one. See
[Several reflectors](usage.md#several-reflectors) for the operator view.

`SenderRun::open` loads the key before touching the network, binds the socket
(`net_policy::bind_sender`, which picks a random port from 49152 to 65535 when
the local port is 0), applies `--interface`, socket options and timestamping,
and builds the static request TLVs. An open-mode run also signs the TLV HMAC
when a key is given.

`SenderRun::run` then works in three phases:

1. **Probe schedule.** Each probe is due one gap after the previous due time,
   so build and send time does not stretch the gap. The gap comes from
   `schedule.rs` (periodic, or exponentially distributed for Poisson) applied
   to `--send-delay`, or to the AIMD interval when congestion response is
   active. A probe up to 2 ms late is sent at once; later than that, the
   schedule restarts from now instead of bursting. Between probes the loop
   receives replies. Tokio timers fire on whole milliseconds, so gaps under
   1 ms are busy-waited, which keeps one CPU core busy above 1000 probes per
   second. The loop ends at `--count` probes (`0` means no limit), at the end
   of `--duration`, on a zero-SSID stop, or on shutdown.

   Each probe is built in two steps. `build_probe` writes the TLVs straight
   into the packet buffer behind a zeroed base packet (`write_probe_tlvs`, no
   copy of the static TLVs). Only then are T1 and the RTT start read, and
   `stamp_probe` writes the base packet with that timestamp (and its HMAC,
   which covers the timestamp) before the send. TLV construction therefore
   does not count as network delay.
2. **Drain.** The run waits up to `--timeout` for outstanding replies and burst
   copies. Shutdown ends the wait at once.
3. **Access Report retries.** An Access Report exchange that started during
   the probe loop continues until acknowledged or out of retries (RFC 8972
   §4.6), with identical report bytes.

Probes still unanswered at the end count as lost. The run returns a
`StatsSnapshot`.

### Sender timestamp arithmetic

T1 and T4 use the sender's configured format; T2 and T3 use the format given by
the reflector's Error Estimate Z bit. `timestamp_to_unix_nanos` converts both to
the Unix epoch and unfolds the 32-bit seconds field near a local reference,
which must be within about 68 years. Integer subtraction keeps small
differences exact across wraps.

`--reflector-utc-offset` removes a known remote offset after decoding. Software
timestamps use UTC in both formats. A malformed PTP fractional field omits the
one-way delay while monotonic RTT accounting continues. Signed one-way delay
keeps clock skew visible. See [Timestamps and clocks](usage.md#timestamps-and-clocks).

### Validated sender telemetry

`validate_reflected_tlvs` returns typed telemetry or a rejection. Control logic
reads HMAC status, Access Report acknowledgment, CE and Micro-session IDs
directly; text formatting is only for diagnostics.

U skips a TLV; M stops processing of the rest; any I flag or an unusable HMAC
that is present blocks all values. With a key, a required Micro-session ID,
BER, Direct Measurement and Follow-Up require verified TLV integrity. Optional
Access Report and CoS handling also accept replies that omit the HMAC. Passing
structural validation does not make an unsigned reply authenticated.

SSID and pending-probe validation happen before a learned Micro-session ID is
committed. See [integrity and BER](measurements.md#integrity-and-ber).

### Sender observers

`SenderObserver` receives events as they happen: probe sent, reply received
with its RTT, probes lost, base HMAC failure, reply rejected by TLV validation,
and U/M/I flag counts. Every method has an empty default. `main.rs` registers
`PrometheusSenderObserver` when `--metrics` is set and `SenderSnmpStats` when
`--snmp` is set. Library callers can pass their own observers to
`run_sender_with_output` or `run_senders`.

## Shutdown

`shutdown.rs` provides one `CancellationToken` per role. `cancel_on_signal`
registers the SIGINT and SIGTERM handlers (Ctrl-C on non-Unix platforms) before
it returns, so a signal during the rest of startup is not lost.

- **Reflector.** The token lives in `ReceiverSharedState`. A signal or
  `POST /v1/shutdown` on the control API cancels it. Both backends then stop
  accepting packets, finish queued replies for at most
  `--reflector-shutdown-grace-ms` (default 0), cancel the rest, print the
  summary and return `Ok`.
- **Sender.** A signal cancels the token. The probe loop and the drain stop at
  once, unanswered probes count as lost, and the statistics so far are printed.

SIGHUP on Unix is separate: it reloads the reflector's HMAC keys
(`receiver::reload_keys`) and keeps the current keys on error. The SNMP
sub-agent has its own internal token and ends with the process. See
[Capacity, drain and shutdown](usage.md#capacity-drain-and-shutdown).

## Session management

A session is identified by the source and actual destination UDP endpoints,
the SSID, and the optional sender Micro-session ID, in both sequencing modes.
Permissive admission learns identities from traffic; provisioned admission
requires an exact startup rule. `--stateful-reflector` changes only sequence
generation: independent reflector sequences instead of echoed sender sequences.
See [Session provisioning](usage.md#session-provisioning).

Runtime entries hold counters, replay state and Follow-Up state. Accepted
packets refresh the idle clock; outgoing copies do not. The default idle
timeout is 300 seconds, and 0 disables cleanup. A cap or drain rejection
creates no temporary session and consumes no ID or sequence number. Expiry
keeps static provisioning.

### Session admission and lifetime

The internal admission permit records a provisioning decision for one manager
and identity. It holds no lock during authentication and reserves no capacity.
Acquisition rechecks the current cap and drain state under the table write
lock.

Each send holds a session lifetime read guard through the syscall and the state
updates. Expiry removes the entry and takes the lifetime write lock, so it
waits for an active send and excludes later queued copies. The send path never
takes the table lock while holding this guard. Re-admission creates fresh state
and a new internal ID. Acquisition APIs return `None` on rejection or
retirement.

## TLV extensions reference

### Supported TLV types

| Type | Name | Behavior and limits |
| --- | --- | --- |
| 1 | Extra Padding | Opaque padding; the SSID is in the base header |
| 2 | Location | Observed addresses and ports, subject to the disclosure policy |
| 3 | Timestamp Information | Reflector ingress and egress clock metadata |
| 4 | Class of Service | DSCP/ECN request, observed values and results |
| 5 | Direct Measurement | Sender and reflector counters |
| 6 | Access Report | Access identifier, return code and sender retries |
| 7 | Follow-Up Telemetry | Previous stateful reflection timestamp |
| 8 | HMAC | TLV integrity; only Extra Padding may follow |
| 9 | Destination Node Address | Local address matching and Linux source pinning |
| 10 | Return Path | Suppression, opt-in alternate address or SRv6; SR-MPLS unsupported |
| 11 | Micro-session ID | Numeric validation; no physical LAG member association |
| 12 | Reflected Test Packet Control | Opt-in asymmetric replies and address group filters |
| 240 to 242 | BER pattern, count and burst | Experimental; Type 242 conflicts with some Heartbeat implementations |
| 246, 247 | Reflected IPv6 extension and fixed header data | Experimental; pnet reflects both, nix on Linux reflects Type 246 and sets C on Type 247 |

See [experimental codepoints](conformance/README.md#experimental-codepoints)
for allocation and renumbering policy.

### TLV handling modes

`--tlv-mode echo` (default) processes and reflects TLVs and sets U on unknown
types. A malformed TLV gets M; TLVs before it are still processed, and TLVs
after it are copied with U set (RFC 8972 §4). `ignore` copies everything after
the base packet without processing, as a reflector without TLV support does.

### Backward compatibility

Base-only peers get RFC 8762 handling. A sender that requests a nonzero SSID
rejects replies with another nonzero SSID. Replies with a zero SSID follow
`--on-zero-ssid continue|stop`; continuing does not disable validation of later
nonzero SSIDs.

### TLV wire format (RFC 8972 §4)

A TLV has one flags octet, one type octet, a two-octet big-endian value length,
and the value. U, M, I and C use the masks `0x80`, `0x40`, `0x20` and `0x10`;
the lower bits are reserved. C is defined by the extensions that use it,
including Type 12, BER and header reflection. Type-specific layouts are in
`src/tlv/typed/`.

### Class of Service TLV (RFC 8972 §4.4)

The reflector records the received DSCP and ECN in DSCP2 and EC2. Local policy
decides whether the requested DSCP1 and EC1 are permitted, and socket support
decides whether they can be applied. A refused DSCP keeps the received DSCP and
reports RPD=0b01. An ECN that is not applied becomes Not-ECT and reports
RPE=0b10. Destination rules match the actual reply destination. The sender's
AIMD response is described under
[TLV-driven sender features](usage.md#tlv-driven-sender-features).

### Location TLV (RFC 8972 §4.2)

The value starts with the destination and source ports, followed by sub-TLVs.
Generic address requests become IPv4 or IPv6 responses without changing the
length. Withheld fields are zeroed; a withheld IP request keeps its generic
type so the family is not revealed. A source MAC request gets a zeroed EUI-64
response. On a wildcard bind the received destination metadata is used, not
the bind address.

### Direct Measurement TLV (RFC 8972 §4.5)

The sender supplies its transmit count; the reflector supplies the session's
receive and transmit counts. See
[counter windows](measurements.md#direct-measurement-counter-window) for the
sender's directional loss estimates.

### Follow-Up Telemetry TLV (RFC 8972 §4.7)

Stateful replies carry the previous reflection's sequence number, timestamp and
method, including accepted kernel or NIC TX corrections. Stateless replies zero
the sequence number and timestamp. The sender correlates the independent
sequence to report
[corrected reverse delay](measurements.md#follow-up-corrected-reverse-delay).

### Timestamp Information TLV (RFC 8972 §4.3)

Senders zero all information fields. Reflectors report the clock sources and
methods actually used for T2 and T3. A hardware T2 uses the PHC source; a
software T2 and the current T3 use the system source. See
[Clock synchronization metadata](usage.md#clock-synchronization-metadata).

### Access Report TLV (RFC 8972 §4.6)

Valid IDs 1 (3GPP) and 2 (Non-3GPP) are echoed; other IDs get U set. The
sender retransmits until a usable echo arrives or the retry budget runs out,
including after its main send loop ends.

### Destination Node Address TLV (RFC 9503 §3)

A local address match is carried to the send path for Linux source pinning. A
mismatch gets U set. When pinning is unsupported or fails, the kernel selects
the source. This is separate from session admission.

### Return Path TLV (RFC 9503 §4)

- Control code bit 0 selects suppression or a reply; reserved bits are ignored.
- A Return Address is honored only with `--return-path-allow-alternate`. When
  redirection is unsupported or fails, U is set and the reply goes to the
  original source.
- `--srv6-return-forwarding` enables SRH forwarding on Linux with nix. The
  single send owner applies the sticky `IPV6_RTHDR` option, keeps the requested
  SIDs, reserves the final UDP destination slot, and clears the SRH before
  ordinary replies. Unsupported paths, including pnet, fall back with U set.
- SR-MPLS label stack forwarding is unsupported and gets U set.

Source, alternate-address and SRH fallbacks are re-signed with the request's
key. See [SRv6 verification](testing-netns.md#retaining-successful-srv6-evidence).

### Micro-session ID TLV (RFC 9534 §3.1)

The sender requires exactly one usable ID TLV, a matching sender ID, and a
nonzero reflector ID that matches its configured or first accepted value. The
learned ID is committed only for a validated reply to a pending probe. With a
key, valid TLV integrity is also required. A rejected reply leaves the probe and
the learned ID unchanged.

The reflector validates and fills configured numeric IDs. Neither endpoint maps
these IDs to physical LAG members, selects egress members, or verifies ingress
members. See [RFC 9534 gaps](conformance/rfc9534.md).

### Reflected Test Packet Control TLV (RFC 10052)

Type 12 requests a reply count, length and interval. It is disabled by default:
with `--reflected-control-max-count 0` the reflector treats the TLV as
unsupported and sends one reply with U set. When enabled, a request that
exceeds the count, interval, byte rate (`--reflected-control-max-rate`) or byte
volume (`--reflected-control-max-volume`) limit gets one C-flagged reply rather
than a reduced burst. L2 and L3 Address Groups each require a local match;
either mismatch drops the packet. Malformed groups are skipped.

Enabled bursts use deadline queues. One request owns one budget slot and a
fixed transport plan; a fallback on one copy cannot change the policy of later
copies. Timestamps, stateful sequences, telemetry and route MTU are evaluated
per copy. `DatagramSender` serializes socket options and sends, and caches
successful sticky settings separately per address family. Rate limiting or a
send failure can stop the rest of a burst.

Linux checks each reply route and subtracts IP, UDP and SRH overhead. Netlink
notifications, a 250 ms expiry and an `EMSGSIZE` refresh keep the bounded cache
current. Padding and optional reflected-header TLVs may shrink; mandatory
fields may not. An MTU clamp sets C and stops the burst. An unknown MTU budget
drops the reply. See [Reply size and route MTU](usage.md#reply-size-and-route-mtu).

Drain rejects new session identities. Expiry retires a session's queued sends.
Shutdown stops intake, allows the configured grace period, then cancels the
rest. `reply_queue_rejected` counts refused requests and
`queued_replies_cancelled` counts unsent copies. Aggregate drops count one per
rejected request or per cancelled request remainder.

### Bit Error Rate TLVs (draft-gandhi-ippm-stamp-ber)

Types 240, 241 and 242 carry the pattern, the error count and the maximum error
burst (draft-gandhi-ippm-stamp-ber-07). The reflector compares the delivered
Extra Padding with the repeated pattern, records errors, and repairs the
padding for reverse-path measurement. A missing Type 240 means pattern `ff00`;
an explicit empty pattern is invalid. Duplicate or missing padding, duplicate
BER TLVs and lengths not divisible by the pattern get C set.

BER padding follows HMAC so that corruption stays measurable outside the
metadata coverage. Each accepted pending probe contributes once. Missing,
flagged or unverifiable metadata contributes no sample. A U flag on a BER TLV
disables later BER requests. `--ber-omit-burst` avoids the Type 242 Heartbeat
collision and reports forward burst statistics as unavailable.

A BER interval lasts `--ber-interval` × `--send-delay`, fixed at startup even
under ECN backoff. Thresholds are per million; only completed intervals that
cross above a threshold raise alarms. Empty windows are omitted, and the
current partial window does not raise alarms. See
[retention](statistics.md#memory-and-ber-history).

On Linux, sender padding shrinks by whole pattern repetitions to fit the route
MTU. A resized reply marks the BER metadata with C because the denominator
changed. Use symmetric replies for BER. UDP checksums and link CRC or FEC may
discard corrupt packets before delivery, so this measures residual delivered
errors, not raw link BER.

### Reflected IPv6 Extension and Fixed Header Data TLVs (draft-ietf-ippm-stamp-ext-hdr-15)

Type 246 (IPv6 extension header, §4.1 and §4.2) has an 8-octet Requested field;
Type 247 (IP fixed header, §6.1 and §6.2) has a 4-octet Requested field. The TLV
length is the complete size of the target header, and a Type 246 length must be
a multiple of 8. A nonzero Requested field selects the first unconsumed
captured header of that length whose first octets match it. A zero Requested
field selects the first unconsumed header of that length and is filled with
that header's first octets. The whole matched header is copied into the value.
Each captured header is reflected by at most one TLV, so successive TLVs pair
with successive headers. No captured headers or no match sets C and leaves the
value unchanged. A Type 247 after a Type 246 sets C on every header TLV and
copies nothing (§6.3).

Where headers come from:

- **pnet** captures the full IP packet and fills both types. It requires
  complete, valid wire checksums, so partial checksum-offloaded frames are
  rejected.
- **nix on Linux** enables `IPV6_RECVHOPOPTS`, `IPV6_RECVDSTOPTS` and
  `IPV6_RECVRTHDR` on IPv6 sockets and reflects Type 246 from that ancillary
  data, in wire order. It cannot see fixed headers, so Type 247 gets C.
- **nix on macOS** supplies no headers, so both types get C.

Both backends set C on Type 12 IPv6 Extension Header Control sub-TLVs (§5.1),
because inserting headers into replies is unsupported.

On the sender, Linux can attach one Hop-by-Hop and then one Destination Options
header (`--attach-ext-hdr`). Explicit `--reflected-ipv6-ext-hdr` requests
replace the automatic requests and must match the attached headers in order;
an ambiguous subset needs a selector. Type 247 covers the sender's one fixed
header. A failure to attach a header or set up the route MTU aborts startup.
See [IPv6 extension headers](usage.md#ipv6-extension-headers) and the
[conformance matrix](conformance/draft-stamp-ext-hdr.md).

## Prometheus metrics

The `metrics` feature exposes sender and reflector counters, session counts,
and processing and RTT measurements. `--metrics` starts the endpoint (default
bind `127.0.0.1:9090`). The Prometheus exporter is built without its own HTTP
listener: `metrics/mod.rs` installs the recorder and serves `/metrics` from an
axum server. A bind failure stops startup. A non-loopback bind logs a warning
because the endpoint has no authentication. Series are defined in
`src/metrics/`. See [Observability](usage.md#observability).

## SNMP AgentX sub-agent

The `snmp` feature (Unix only) connects to an AgentX master over a Unix socket
(default `/var/agentx/master`) and exposes
[STAMP-SUITE-MIB](../mibs/STAMP-SUITE-MIB.mib) in both roles. Sender counters
are updated during the run through the sender observer.

### Protocol subset

The sub-agent is read-only and implements the sub-agent side of
[RFC 2741](https://www.rfc-editor.org/rfc/rfc2741.html).

| PDU | Handling |
| --- | --- |
| Open, Register | Sent at connect and after each reconnect. |
| Get, GetNext, GetBulk | Answered from the MIB handler. |
| TestSet | Response with `notWritable` (17). |
| CommitSet, UndoSet | Response with `commitFailed` (14) or `undoFailed` (15). |
| CleanupSet | No response (RFC 2741 §7.2.4.4). |
| Close from the master | Acknowledged with a correlated Response before teardown (§7.1.8). |
| Other types | Logged and ignored. |

- GetBulk returns results iteration by iteration (§7.2.3.3). An exhausted range
  keeps its position with `endOfMibView` until every range is exhausted.
- Search ranges honor an inclusive start once and an exclusive end
  (§5.2, §7.2.3.2, §7.2.3.3).
- A request with more than 256 search ranges gets `genErr` with index 257 and
  no varbinds (§7.2.3); the next request on the same connection works.
- Limits: 1 MiB incoming payload, 256 search ranges per PDU, at most 100
  GetBulk repetitions.
- Only network byte order and the default context are supported. Byte order is
  a per-PDU flag, not negotiated by Open; a little-endian PDU is a protocol
  error.

### Framing and failure handling

`PduReader` keeps partially read headers and payloads across the one-second
read timeout, checks the payload length before allocating, and treats EOF as a
lost connection. Decoders check lengths before indexing. If the initial
connection fails, a warning is logged and STAMP keeps running without SNMP.
After a successful start, a lost connection is retried with exponential backoff
from 1 s to 30 s, and registration is repeated. A supervisor task logs a panic
of the blocking event loop.

### Tests

- `tests/agentx_protocol_test.rs` runs an independent master over a real Unix
  socket against the production session and event loop. Its encoder and
  decoder do not use production codec helpers. It covers GetBulk ordering and
  end-of-MIB positions, inclusive and exclusive bounds, zero repetitions, header
  and payload fragments that each cross a 1.25 s gap (longer than the read
  timeout), coalesced PDUs, cancellation during a partial frame, the Close
  acknowledgment and the range-limit error.
- Unit tests in `src/snmp/agentx.rs` cover every split offset with
  `WouldBlock`, `TimedOut` and `Interrupted`, truncated frames and oversized
  headers.
- `tests/proptest_tlv.rs` and the `agentx_decode_header` and
  `agentx_decode_oid` fuzz targets feed arbitrary bytes to the decoders.
- `scripts/release_checks.py` runs a real Net-SNMP master and clients against
  the binary. See
  [release verification](release-evidence.md#authenticated-control-and-a-reference-snmp-master).

This is evidence for the subset above, not a full SNMP certification.

## Hardware-assisted timestamping

The `--hwtstamp` modes need the `hwtstamp` build feature for the kernel read
paths:

| Mode | Behavior |
| --- | --- |
| `auto` (default) | Kernel software timestamps where available; no NIC changes and no privileges |
| `on` | Also attempt Linux NIC timestamps (`SIOCSHWTSTAMP`, needs `CAP_NET_ADMIN`); warn and fall back on failure |
| `off` | Userspace timestamps only |

On Linux, RX timestamps come from `SCM_TIMESTAMPING` and TX timestamps from
`MSG_ERRQUEUE`, matched by `SOF_TIMESTAMPING_OPT_ID`. On the sender, a TX
report replaces the stored T1 of its probe. On the reflector, a TX report
corrects the Follow-Up record. T3 in the current reply stays a software
timestamp because it is written before transmission. A hardware report may
upgrade a software record; a later software report cannot downgrade hardware
provenance.

macOS supports software RX timestamps through `SO_TIMESTAMP`. Windows has no
kernel or NIC timestamp path. A capability probe does not prove that a hardware
timestamp was used. NIC PHCs must be synchronized with the clocks used at both
endpoints (for example with ptp4l and phc2sys); the synchronization
declarations and the S bit do not synchronize anything. See the
[two-host verification procedure](testing-hardware-timestamps.md).

## Benchmarks

[benchmarks.md](benchmarks.md) covers the Criterion and live UDP benchmarks,
how to record results, and their limits. In-process timing and loopback
throughput do not establish physical NIC capacity.

## See also

- [Usage](usage.md)
- [Protocol overview](protocol.md)
- [Measurement semantics](measurements.md)
- [Security](security.md)
- [Integration tests](../tests/README.md)
