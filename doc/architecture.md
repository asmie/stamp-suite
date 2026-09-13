# Architecture

One binary runs as a sender or reflector over UDP (default port 862).
The sender records probes and replies; the reflector timestamps and returns
accepted packets. See [usage](usage.md) for configuration and
[conformance](conformance/README.md) for protocol scope.

## Module structure

| Module | Responsibility |
| --- | --- |
| `main.rs`, `configuration.rs` | Startup, CLI/TOML loading, validation |
| `packets.rs`, `tlv/` | Wire layouts, parsing, TLV mutation and serialization |
| `crypto.rs` | Key loading and base/TLV HMAC |
| `sender.rs`, `sender/` | Probe scheduling, reply validation, telemetry and session-state notifications |
| `receiver/mod.rs` | Shared admission, authentication and reply assembly |
| `receiver/nix.rs`, `receiver/pnet.rs` | Socket receive or raw capture |
| `receiver/transmit.rs`, `receiver/mtu.rs` | Queued sends, transport policy, route MTU and final signing |
| `session.rs`, `session_identity.rs` | Session identity, counters, replay windows and lifetime |
| `time.rs`, `hwtstamp.rs` | Wire timestamp conversion and kernel/NIC timestamps |
| `stats.rs`, `stats/`, `ber.rs` | Measurement accumulation and reporting |
| `cos_policy.rs`, `rate_control.rs` | Reflector CoS admission and sender congestion response |
| `control/`, `metrics/`, `snmp/` | Runtime API and monitoring |

Paths are relative to `src/`. Rust library interfaces are internal and are not
covered by the CLI/wire compatibility contract.

## Receiver backends

Both backends use the same STAMP processing and transmission code.

| | nix | pnet |
| --- | --- | --- |
| Default platform | Linux/macOS | Windows |
| Input | UDP socket plus `recvmsg` metadata | Datalink frames parsed as Ethernet/IP/UDP |
| Filtering/checksums | Kernel UDP stack | Capture parser validates framing and checksums |
| Metadata | TTL/Hop Limit, CoS, destination and interface | Raw IP headers plus the same packet metadata |
| Raw-header reflection | Returns C on Types 246/247 | Can populate Types 246/247 |
| Requirements | Normal UDP socket permissions | Linux `CAP_NET_RAW`; Windows Npcap |
| Scheduling | Async receive loop owns sends | Blocking capture plus a separate send worker |

The nix backend receives only traffic delivered to its bound UDP socket and
uses the normal host firewall path. Raw capture sees interface traffic before
normal UDP delivery; do not rely on UDP INPUT filtering alone to restrict it.
Pnet replies use UDP sockets bound to the STAMP port, so connected senders accept
the source port. Pnet requires a concrete local address and captures one interface.

Nix `recvmsg` calls run inside `UdpSocket::try_io`. `WouldBlock` clears cached
readiness; bypassing this wrapper can make an idle loop spin. The sender uses
the same pattern for ECN and kernel timestamps.

## Sender timestamp arithmetic

T1/T4 use the sender's configured encoding; T2/T3 use the reflector Error
Estimate Z bit. `timestamp_to_unix_nanos` converts both to the Unix epoch and
unfolds the 32-bit seconds word near a local reference, which must be within
about 68 years. Integer subtraction preserves small differences across wraps.

`--reflector-utc-offset` removes a known remote offset after decoding.
Software timestamps use UTC in both encodings. A malformed PTP fractional word
omits OWD while valid monotonic RTT accounting continues. Signed OWD preserves
clock skew. See [clock settings](usage.md#timestamp--clock).

## Packet processing pipeline

Live receivers reserve a `ReplyBudget` slot before processing. The slot covers
validation, handoff, queued deadlines and active sending until all copies finish
or are discarded. Overflow rejects the new request before session mutation.

1. Extract the full session identity and check static provisioning.
2. Parse the base packet and verify configured authentication. Rejected bases
   cannot create or refresh sessions.
3. Acquire the session under current cap/drain rules. Update receive state and
   classify replay without yet advancing its window.
4. Parse and verify TLVs, apply flag rules, resolve routing/CoS requests, and
   assemble the reply. Bad TLV integrity produces I-flagged echoes; it is distinct
   from base-HMAC rejection.
5. Commit the validated replay sequence after assembly and queue the reply.
6. At each send attempt, check session lifetime and route MTU, assign the stateful
   sequence, refresh T3 and eligible telemetry, and sign the final bytes.
7. Successful sends update that session's transmit and Follow-Up state.

A keyset read guard spans authentication and assembly. The queued reply owns the
selected key, so rotation cannot change the key between acceptance and signing.
Fallbacks retain the sequence and refresh timestamps/signatures after mutation.
T2 and echoed sender fields remain those of the original request.

### TLV ownership and signing

`TlvList` owns each value once. Non-HMAC entries form a prefix; HMAC entries form
a suffix. Optional indices preserve received wire order, including malformed
chains and Extra Padding after HMAC. Mutation updates the owner; serialization
uses the indices. Duplicate-HMAC partitioning uses linear swaps.

Verification hashes the sequence and the original covered prefix. Only Extra
Padding may follow HMAC, outside that coverage. New signatures use outgoing
order with BER padding after HMAC. Failure echoes retain received order and
digest bytes with the required flags. Malformed lists are not re-signed by normal
TLV regeneration. Final send-time signing operates on the reply buffer.

### Validated sender telemetry

`validate_reflected_tlvs` returns typed telemetry or a rejection. Control logic
reads HMAC status, Access Report acknowledgment, CE and Micro-session IDs directly;
text formatting is only for diagnostics.

U skips a TLV; M stops the remainder; any I flag or unusable present HMAC blocks
all values. With a key, required Micro-session IDs, BER, Direct Measurement and
Follow-Up require verified TLV integrity. Optional Access Report/CoS handling
retains compatibility with replies that omit HMAC. An unsigned reply is not
made authenticated by passing structural validation.

SSID and pending-probe validation precede committing learned Micro-session IDs.
See [measurement admission](measurements.md#integrity-and-ber).

## Operational characteristics

### Packet-receive contract: `--strict-packets`

Lenient mode zero-fills short base packets before parsing and HMAC verification
(RFC 8762 §4.6). `--strict-packets` rejects them. Authentication checks remain
independent; received MBZ fields are ignored in either mode.

### Capture-thread liveness signal

`capture_alive` records receive-loop liveness. Startup and capture-task failures
are logged; pnet task panics are observed through the join handle.

### Observability subsystem failure semantics (`--metrics` vs `--snmp`)

A requested metrics or control endpoint that cannot bind causes startup failure.
An initial AgentX connection failure logs a warning and leaves STAMP running.
After a successful initial AgentX connection, disconnects trigger bounded-backoff
reconnection. See [failure behavior](usage.md#failure-semantics).

### AgentX sub-agent panic-resistance

Decoders check lengths before indexing and bound request work. A supervisor
observes the blocking event loop's join handle. See the
[AgentX review](conformance/agentx-review.md) for framing and ordering tests.

## Session management

Sessions use source and actual destination UDP endpoints, SSID, and optional
sender Micro-session ID in both sequencing modes. Permissive admission learns
identities from traffic; provisioned admission requires an exact startup rule.
`--stateful-reflector` changes only sequence generation: independent reflector
sequences versus echoed sender sequences.

Runtime entries hold counters, replay and Follow-Up state. Accepted receives
refresh the idle clock; outgoing copies do not. The default idle timeout is
300 seconds, and zero disables cleanup. Cap/drain rejection creates no temporary
session and consumes no ID or sequence. Expiry preserves static provisioning.

### Session admission API and lifetime

The internal admission permit records a provisioning decision for one manager
and identity. It holds no lock during authentication and reserves no capacity.
Acquisition rechecks current cap/drain state under the table write lock.

Each send holds a session lifetime read guard through the syscall and state
updates. Expiry removes the entry and takes the lifetime write lock, waiting for
an active send and excluding later queued copies. The send path never takes
the table lock while holding this guard. Re-admission creates fresh state and
a new internal ID. Acquisition APIs return `None` on rejection or retirement.

## TLV extensions reference

### Supported TLV types

| Type | Name | Behavior / limit |
| --- | --- | --- |
| 1 | Extra Padding | Opaque padding; SSID lives in the base header |
| 2 | Location | Observed addresses/ports subject to disclosure policy |
| 3 | Timestamp Information | Reflector ingress/egress clock metadata |
| 4 | Class of Service | DSCP/ECN request, observations and application results |
| 5 | Direct Measurement | Sender/reflector counters |
| 6 | Access Report | Access identifier, return code and sender retries |
| 7 | Follow-Up Telemetry | Previous stateful reflection timestamp |
| 8 | HMAC | TLV integrity; only Extra Padding may follow |
| 9 | Destination Node Address | Local-address matching and Linux source pinning |
| 10 | Return Path | Suppression, opt-in alternate address/SRv6; SR-MPLS unsupported |
| 11 | Micro-session ID | Numeric validation; physical LAG association unsupported |
| 12 | Reflected Test Packet Control | Opt-in asymmetric replies and address-group filters |
| 240–242 | BER pattern/count/burst | Experimental; Type 242 conflicts with some Heartbeat implementations |
| 246/247 | Reflected extension/fixed headers | Experimental; requires pnet capture, nix returns C |

See [codepoint disclosure](conformance/README.md#experimental-codepoints)
for allocation and renumbering policy.

### TLV handling modes

`--tlv-mode echo` (default) processes and reflects TLVs, setting U for unknown
types. `ignore` strips extensions from the response.

### Backward compatibility

Base-only peers use RFC 8762 handling. A sender requesting a nonzero SSID rejects
other nonzero IDs. Zero replies follow `--on-zero-ssid continue|stop`; continuing
does not disable validation of later nonzero IDs.

### TLV wire format (RFC 8972 Section 4.2)

A TLV has one flags byte, one type byte, a two-byte big-endian value length,
and the value. U/M/I/C use masks `0x80/0x40/0x20/0x10`; lower bits are reserved.
C is used by the applicable draft extensions, including Type 12, BER and header
reflection. Type-specific layouts are documented in `src/tlv/typed/`.

### Class of Service TLV (RFC 8972 §4.4)

The reflector records received DSCP/ECN in DSCP2/EC2. Local policy determines
permission; socket support determines whether it can apply requested DSCP1/EC1.
Rejected DSCP retains received DSCP and reports RPD=0b01. Unapplied ECN becomes
Not-ECT and reports RPE=0b10. Destination rules use the actual reply destination.
The sender's AIMD response is described in [usage](usage.md#tlv-driven-sender-features).

### Location TLV (RFC 8972 §4.2)

The value starts with destination/source ports, followed by sub-TLVs. Generic
address requests become IPv4/IPv6 responses without changing length. Withheld
fields are zeroed; withheld IP requests keep their generic type to avoid
revealing the family. Source MAC requests receive a zeroed EUI-64 response.
Wildcard binds use received destination metadata, not the bind address.

### Direct Measurement TLV (RFC 8972 §4.5)

The sender supplies its transmit count; the reflector supplies session receive
and transmit counts. See [counter windows](measurements.md#direct-measurement-counter-window)
for the sender's provisional directional-loss estimates.

### Follow-Up Telemetry TLV (RFC 8972 §4.7)

Stateful replies carry the previous reflection's sequence, timestamp and method,
including accepted kernel/NIC TX corrections. Stateless replies zero sequence
and timestamp. The sender correlates the independent sequence to report
[corrected reverse delay](measurements.md#follow-up-corrected-reverse-delay).

### Timestamp Information TLV (RFC 8972 §4.3)

Senders zero all information fields. Reflectors report the clock sources and
methods actually used for T2/T3. Hardware T2 uses the PHC source; software T2
and current T3 use the system source. See [clock metadata](usage.md#clock-synchronization-metadata).

### Access Report TLV (RFC 8972 §4.6)

Valid IDs 1 (3GPP) and 2 (Non-3GPP) are echoed. Other IDs get U set.
The sender retransmits until a usable echo arrives or the retry budget expires,
including after its main send loop ends.

### Destination Node Address TLV (RFC 9503 §3)

A local-address match is carried to the send path for Linux source pinning.
A mismatch gets U set. Unsupported or failed pinning falls back to kernel source
selection. This is separate from session admission.

### Return Path TLV (RFC 9503 §4)

- Control code bit 0 selects suppression or a reply; reserved bits are ignored.
- Return Address is enabled by `--return-path-allow-alternate`. Unsupported or
  failed redirection sets U and uses the original source.
- `--srv6-return-forwarding` enables Linux/nix SRH forwarding. The sole send owner
  applies sticky `IPV6_RTHDR`, preserves requested SIDs, reserves the final UDP
  destination slot, and clears SRH before ordinary replies. Unsupported paths,
  including pnet, use U-flagged fallback.
- SR-MPLS label-stack forwarding is unsupported and gets U set.

Source, alternate-address and SRH fallbacks are re-signed with the request's key.
See [SRv6 verification](testing-netns.md#retaining-successful-srv6-evidence).

### Micro-session ID TLV (RFC 9534 §3.1)

The sender requires exactly one usable ID TLV, a matching sender ID, and a
nonzero reflector ID matching its configured or first accepted value. Learning
is committed only for a validated reply to a pending probe. A key requires valid
TLV integrity too. Rejected replies leave the probe and learned ID unchanged.

The reflector validates and fills configured numeric IDs. Neither endpoint maps
these IDs to physical LAG members, selects egress members, or verifies ingress
members. See [RFC 9534 gaps](conformance/rfc9534.md).

### Reflected Test Packet Control TLV (draft-ietf-ippm-asymmetrical-pkts)

Type 12 requests reply count, length and interval. It is disabled by default:
`--reflected-control-max-count 0` returns one C-flagged reply without requested
padding. Requests exceeding count/rate limits also get one C-flagged reply,
rather than a reduced burst. L2/L3 Address Groups each require a local match;
either mismatch drops the packet. Malformed groups are skipped.

Enabled bursts use deadline queues. One request owns one budget slot and an
immutable transport plan; per-copy fallbacks cannot alter later copies' policy.
Timestamps, stateful sequences, telemetry and route MTU remain dynamic.
`DatagramSender` serializes socket options and sends, caching successful sticky
settings separately by address family. Rate limiting or a send failure can stop the remaining burst.

Linux checks each reply route and subtracts IP/UDP/SRH overhead. Notifications,
a 250 ms expiry and an `EMSGSIZE` refresh keep the bounded cache current.
Padding and optional reflected-header TLVs may shrink; mandatory fields may not.
An MTU clamp sets C and stops the burst. Unknown budgets cause a drop.
See [size and queue policies](usage.md#reflector-mode).

Drain rejects new session identities. Expiry retires a session's queued sends.
Shutdown stops intake, allows the configured grace period, then cancels the
remainder. `reply_queue_rejected` counts refused requests;
`queued_replies_cancelled` counts unsent copies. Aggregate drops count one per
rejected request or cancelled request remainder.

### Bit Error Rate TLVs (draft-gandhi-ippm-stamp-ber)

Types 240/241/242 carry pattern, error count and maximum error burst. The
reflector compares delivered Extra Padding with the repeated pattern, records
errors, and repairs padding for reverse-path measurement. Missing Type 240 uses
`ff00`; an explicit empty pattern is invalid. Duplicate/missing padding,
duplicate BER TLVs, and non-divisible lengths get C set.

BER padding follows HMAC so corruption remains measurable outside metadata
coverage. Each accepted pending probe contributes once. Missing, flagged or
unverifiable metadata contributes no sample. A BER U flag disables later BER
requests. `--ber-omit-burst` avoids the Type-242 Heartbeat collision and reports
forward burst statistics as unavailable.

BER intervals last `ber_interval × send_delay` milliseconds, fixed at startup
even under ECN backoff. Thresholds are per million; only completed intervals crossing
above a threshold create alarms. Empty windows are omitted; a current partial
window does not trigger alarms. See [retention](statistics.md#memory-and-ber-history).

Linux sender padding shrinks by whole pattern repetitions to fit route MTU.
Reply resizing marks BER metadata with C because it changes the denominator.
Use symmetric replies for BER. UDP checksums and link CRC/FEC may discard corrupt
packets before delivery: this measures residual delivered errors, not raw link BER.

### Reflected Fixed / IPv6 Extension Header Data TLVs (draft revision 13)

Type 246 has Requested(8) + Reflected(Length−8); Type 247 uses Requested(4).
Length is the complete target header size. Nonzero Requested matches the wire
prefix; zero selects the first unconsumed length match. Only the header tail is
copied. Missing capture or no match sets C and preserves the value.

Pnet requires complete valid wire checksums; partial offloaded frames are
rejected. Nix returns C because raw headers are unavailable. Both backends return
C for unsupported reply-header insertion requests.

The Linux sender can attach one HBH then one Destination Options header.
Explicit Type-246 requests replace automatic requests and must match attachments
in order; ambiguous subsets need selectors. Type 247 supports the sender's one
fixed header. Attachment or MTU-setup failure aborts startup. See
[migration](usage.md#draft-revision-13-migration) and the
[revision-13 matrix](conformance/draft-stamp-ext-hdr.md).

## Prometheus metrics

The `metrics` feature exposes sender/reflector counters, session counts and
processing/RTT measurements over HTTP. Enable `--metrics`; the default bind is
`127.0.0.1:9090`. Definitions are in `src/metrics/`.

## SNMP AgentX sub-agent

The Unix-only `snmp` feature connects to a master socket (default
`/var/agentx/master`) and exposes [STAMP-SUITE-MIB](../mibs/STAMP-SUITE-MIB.mib).
It supports GET/GETNEXT/GETBULK; SET operations are rejected. Sender counters are
updated during the run. See [AgentX behavior](conformance/agentx-review.md) and
[Net-SNMP verification](release-evidence.md#authenticated-control-and-a-reference-snmp-master).

## Hardware-assisted timestamping

With the `hwtstamp` feature:

| Mode | Behavior |
| --- | --- |
| `auto` (default) | Kernel software timestamps where available |
| `on` | Attempt Linux NIC timestamps; warn and fall back on failure |
| `off` | Userspace timestamps only |

Linux reads RX via `SCM_TIMESTAMPING` and TX via `MSG_ERRQUEUE` with OPT_ID
correlation. Sender TX reports correct stored T1; reflector TX reports correct
the Follow-Up record. T3 in the current reply remains software because it is
serialized before transmission. Hardware reports may upgrade software records;
a later software report cannot downgrade hardware provenance.

macOS supports software RX through `SO_TIMESTAMP`; Windows has no kernel/NIC
path here. Probing capabilities does not prove a hardware timestamp was used.
NIC PHCs must be aligned with the clocks used at both endpoints. Declarations
and the S bit do not synchronize clocks. See the
[two-host verification procedure](testing-hardware-timestamps.md).

## Benchmarks

[benchmarks.md](benchmarks.md) covers Criterion and live UDP runs, recording
methods, and limits. In-process timing and loopback throughput do not establish
physical NIC capacity.

## See also

- [Usage](usage.md)
- [Measurement semantics](measurements.md)
- [Security](security.md)
