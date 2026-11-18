# Architecture

Modules, sender and reflector packet paths, and TLV processing.
For options, see [usage](usage.md); for protocol coverage, see
[conformance](conformance/README.md).

## Module structure

Both receiver backends feed the same packet pipeline. On the sender, state
machines track the session and synchronous observers report events as they
happen. RAII guards hand back reply capacity and other resources. Each packet
layout and each set of session admission rules is defined in one place. What
the code supports is subject to the
[profile limits](conformance/README.md#known-limits).

Paths below are relative to `src/`. The library modules are public so that
tests, benchmarks and fuzz targets can use them. They are not covered by the
compatibility promise for the CLI, the configuration or the wire format.

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
| `packets.rs` | Base packet layouts (44-byte open, 112-byte authenticated), each declared once with `wire_packet!`, which generates the big-endian `to_bytes`/`from_bytes` and checks field offsets at compile time. `Extended<B>` is a base packet followed by TLVs. |
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
| `sender/run.rs` | One sender run: probe schedule, reply handling, final reply drain and Access Report retries. |
| `sender/run/setup.rs` | Opening a run: key loading, socket options and connect, kernel timestamps, static TLVs and the startup route-MTU fit. |
| `sender/schedule.rs` | Probe spacing: periodic or Poisson. |
| `sender/pending.rs` | `PendingTable`: probes awaiting a reply, retired by age under `--max-pending-probes` or expired after `--timeout`, with indexes kept in step on every removal. |
| `sender/packet.rs` | Test packet and request TLV construction. |
| `sender/socket.rs` | Sender socket options: egress TOS, attached IPv6 extension headers, route MTU and reply TOS reception. |
| `sender/validate.rs` | Validation of reflected TLVs before any value is used. |
| `sender/telemetry.rs` | Typed results of validation (HMAC status, Access Report, CE, Micro-session ID). |
| `sender/measurements.rs` | Reply-copy accounting and the optional counter and Follow-Up measurements. |
| `sender/access_report.rs` | Access Report retransmission state (RFC 8972 §4.6). |
| `sender/congestion.rs`, `rate_control.rs` | Response to CE-marked replies (AIMD, draft-ietf-bpm-stamp-cos-ecn-00 §3.4). |
| `sender/session_state.rs` | Session state notifications (draft-ietf-ippm-stamp-ext-hdr-26 §9.2). |
| `sender/observer.rs` | `SenderObserver`: live sender events for metrics, SNMP and library callers. |

### Reflector

| Module | Purpose |
| --- | --- |
| `receiver/mod.rs` | Backend selection, shared admission, authentication and processing (`process_stamp_packet`). |
| `receiver/ingest.rs` | Startup settings and the per-packet ingest path shared by both backends. |
| `receiver/nix.rs` | UDP socket backend (`recvmsg` with ancillary data). |
| `receiver/pnet.rs` | Raw capture backend (pnet datalink) with a separate send worker. |
| `receiver/assemble.rs` | Reply packet assembly with TLV handling. |
| `receiver/transmit.rs` | `Transmission`: the per-copy send loop with its routing, CoS and MTU fallbacks. |
| `receiver/transmit/shape.rs` | Fitting a reply to its payload budget, send-time telemetry refresh and TLV signing. |
| `receiver/transmit/queue.rs` | Reply budget, burst scheduling queue and shutdown drain. |
| `receiver/transmit/datagram.rs` | `DatagramSender`: the one socket owner that applies per-reply options and sends, with the per-OS code. |
| `receiver/transmit/errors.rs` | Marker errors (`ReplyTooLarge`, `LocalSendError`, `CosApplyError`) and EMSGSIZE detection that steer the send loop. |
| `receiver/mtu.rs` | Route MTU lookup. Linux keeps a cache that route notifications invalidate; Windows queries IP Helper for the path and interface on every attempt; macOS estimates IPv6 MTU from a connected native socket. |
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
| `session/inventory.rs` | Optional ordered index and size-limited session pages for the control plane. |
| `session_identity.rs` | Session identity and static reflector admission (RFC 8972 §3). |
| `net_policy.rs` | Outgoing TTL/Hop Limit 255, interface binding (`--interface`) and sender port selection (draft-ietf-ippm-stamp-ext-hdr-26 §3.1). |
| `net_scope.rs` | Interface zones for IPv6 link-local endpoints. |
| `hwtstamp.rs` | Kernel and NIC timestamping with per-packet provenance. |
| `stats.rs`, `stats/` | Statistics collection and text/JSON/CSV output; `stats/quantiles.rs` holds the fixed-memory quantiles and `stats/clock_quality.rs` the declared clock quality. |
| `ber.rs` | Residual bit error measurement (draft-ietf-bpm-stamp-ber-01). |
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

The nix backend only sees traffic that the kernel delivers to its bound UDP
socket, so the host firewall applies as usual. Raw capture sees traffic on the
interface before UDP delivery, so UDP filtering in the INPUT chain does not
stop it. Pnet captures without promiscuous mode and answers only datagrams
addressed to this host, as a UDP socket would: the bound address in its own
family, or any local address otherwise. That keeps it from answering probes
routed through the host to someone else. The address list is read at startup
and again, at most once a second, when an unknown destination arrives. Pnet sends replies from UDP sockets bound to the STAMP port, so
senders using connected sockets accept the replies' source port. Pnet captures
on one interface. It needs a concrete local address, or a wildcard address
together with `--interface`.
A capture API can list an unspecified address for an adapter, but that address
does not identify the interface. A wildcard without an interface name is
therefore a startup error, and pnet does not open capture on that adapter. A
concrete address must belong to the selected interface. If you also give an
interface name or an IPv6 scope, they must match as well.

Pnet binds the configured address family first. With port zero the kernel
picks a port, and pnet uses it for readiness, the capture filter, received
endpoint metadata and both reply sockets. The other family binds the same port
if it is free. If it is not, the configured family keeps running. A bind
failure in the configured family stops startup before capture begins. IPv6
reply sockets are IPv6-only, so IPv4 and IPv6 wildcard sockets can coexist
without handing a port from one to the other.

Nix `recvmsg` calls run inside `UdpSocket::try_io`, which clears the cached
readiness on `WouldBlock`. Calling `recvmsg` outside that wrapper can leave an
idle loop spinning. The sender uses the same pattern for ECN and kernel
timestamps.

The nix embedding API `receiver::run_receiver_with_socket` takes ownership of
a UDP socket that is already bound and not connected. Its endpoint must match
the configured bind endpoint, and a configured port of zero accepts whatever
port the kernel assigned. It applies the same socket options and receive loop
as `run_receiver` without releasing the port in between. The shared-state and
provisioned-session fixtures use it so there is no race while the port is
handed over. See [startup fixtures](testing-startup.md).

## Reflector packet path

### Ingest

`receiver/ingest.rs` is the shared path between a backend and the reply queue.

At startup, `ReflectorSettings::from_config` resolves the configuration once.
Startup stops if authenticated mode has no key, or if a CoS policy, location
disclosure setting or error estimate does not parse. `ReflectorCore` then
holds those settings along with the shared counters, rate limiter, session
manager, keyset, runtime caps and the reply budget
(`--reflector-queue-capacity` slots).

For each datagram, the backend builds a `ReceivedPacket`: the bytes, source,
destination address and local endpoint (including an IPv6 zone), TTL, DSCP,
ECN, ingress interface, source MAC (pnet only), captured IP headers, and the
kernel or NIC receive timestamp with its method. `ReflectorCore::ingest` then:

1. Applies the per-source rate limiter (`--max-pps`, `--reflector-rate-burst`).
   A limited packet is counted and dropped.
2. Counts the packet and reserves one `ReplyBudget` slot. A full budget rejects
   the packet before any session state changes (`reply_queue_rejected`).
3. Takes a read guard on the keyset and builds the `ProcessingContext`. Each
   runtime cap is loaded once. The loads are separate atomic reads, so they
   can see different control updates. Changing several caps at once is not
   transactional.
4. Runs processing inside `catch_unwind`. A panic drops that packet and is
   logged; it does not stop the reflector.
5. Attaches the reply to the reserved slot and returns it for queuing, or
   counts a drop.

The packet keeps its slot through validation, handoff, waiting in the queue
and sending, until every copy has been sent or discarded.

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

The keyset read guard is held through authentication and assembly. The queued
reply owns the key it selected, so a key rotation cannot swap the key between
acceptance and signing. When a send falls back to another path, the reply keeps
its sequence number, and the timestamps and signatures are refreshed after the
change. T2 and the echoed sender fields stay those of the original request.

### TLV ownership and signing

`TlvList` stores each value once. Non-HMAC entries come first and HMAC
entries last. Optional indices record the order in which the TLVs arrived,
including malformed chains and Extra Padding after HMAC. Changes go to the
stored entry, and serialization follows the indices. Duplicate HMAC entries
are moved to the end with linear swaps.

Verification hashes the sequence number and the covered prefix as received.
Only Extra Padding may follow HMAC, and the HMAC does not cover it. New
signatures use the outgoing order, with BER padding after HMAC. Failure echoes
keep the received order and digest bytes and set the required flags. Normal
TLV regeneration does not re-sign malformed lists. The final signing step at
send time works on the reply buffer. It walks complete frames, even past a
semantic M, to find a generated HMAC that sits before nonzero BER padding. An
ownership flag stops this step from changing digests copied into I-marked
failure echoes.

### Short packets and `--strict-packets`

By default a short base packet is zero-filled before parsing and HMAC
verification (RFC 8762 §4.6). `--strict-packets` rejects it instead.
Authentication checks work the same either way, and received MBZ fields are
ignored in both modes.

That policy covers requests at the reflector. Reply admission on the sender is
separate. The sender needs the complete echoed sequence number and the
eight-byte wire T1, even when unused fields at the end of the reply are
zero-filled. It checks this identity against pending and retained history
before deduplication, SSID policy and any state changes. Pending probes keep
the wire T1 as sent, apart from the corrected T1 used for OWD. TX error-queue
mappings carry the monotonic send time and wire T1 along with the sequence
number, so a report for an older send cannot correct a newer probe that reused
the sequence. Reply-copy identities include wire T1.

## Sender run loop

The sender decides whether a reply carries extensions from the received
payload length, not from its own TLV configuration. In authenticated mode it
first verifies base integrity. It then derives malformed markers for every
known outer-TLV length before evaluating flags and optional values, including
types it does not use. The list carries these diagnostic markers, while HMAC
verification uses the original wire bytes.

Location validation walks the whole nested structure before any semantic
handling. An incomplete child or an invalid known length sets M on the outer
Location TLV. The whole value is then unusable, and the reflector sets U on the
outer TLVs that follow. When integrity passes and the list can be processed,
an identifiable malformed child header also gets M. Signed echoes that failed
integrity or are structurally malformed keep every original value byte. The
sender also promotes a received child M to its local outer diagnostic and
ignores nested I, as the Location format requires.

Timestamp Information validation checks the four-field prefix and the framing
of every optional child. Child values stay opaque. The typed decoder and the
sender and reflector length checks share this code. Semantic handling clears
reserved Access Report and Follow-Up fields only on valid values that can be
processed. When Follow-Up zeroes a malformed sequence or timestamp field, it
also honors the parser's M instead of treating the bytes that happen to be
present as a valid declared size.
At send time, a copied outer HMAC stops telemetry from being refreshed unless
the reflector generated that HMAC. This keeps the decision made during
assembly to copy the values of a signed error, while normally processed
replies are still refreshed and signed on every send.

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
   second. The loop ends at `--count` successful sends (`0` means no limit), at the end
   of `--duration`, on a zero-SSID stop, or on shutdown.

   On Windows, each sender run requests 1 ms timer resolution through
   [WinMM](https://learn.microsoft.com/en-us/windows/win32/api/timeapi/nf-timeapi-timebeginperiod).
   A scoped guard releases each successful request when the run returns or is
   dropped, including on cancellation and errors. Without the 1 ms request,
   coarser Windows waits would stretch short probe intervals past the 2 ms catch-up budget.
   The request can increase CPU wakeups and power use while it is active, and
   it does not guarantee real-time scheduling. If the request fails, the
   sender logs a warning and carries on with the timer resolution it has.

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

`StatsOutput` formats and writes reports on a shared thread. The sender
builds a snapshot only after it has reserved queue space. The queue holds
eight reports or detail lines, and interim output beyond that is skipped.
Final output and flushes have a five-second deadline, and a run waits for its
queued reports before it returns. The writer keeps reports in queue order and
prints a single CSV header. Text `-R` lines go through this queue, and JSON/CSV
diagnostics go to stderr. See
[report retention](statistics.md#report-output-and-pending-probes).

### Sender timestamp arithmetic

T1 and T4 use the sender's configured format. T2 and T3 use the format that
the Z bit in the reflector's Error Estimate selects. `timestamp_to_unix_nanos`
converts both to the Unix epoch and unfolds the 32-bit seconds field around a
local reference, which must be within about 68 years. Integer subtraction keeps
small differences exact across a wrap.

`--reflector-utc-offset` removes a known remote offset after decoding.
Software timestamps use UTC in both formats. If a PTP fractional field is
malformed, the one-way delay is left out, while RTT accounting on the
monotonic clock continues. One-way delay is signed, so clock skew stays
visible. See [Timestamps and clocks](usage.md#timestamps-and-clocks).

### Validated sender telemetry

`validate_reflected_tlvs` returns either typed telemetry or a rejection.
Control logic reads the HMAC status, Access Report acknowledgment, CE and
Micro-session IDs from the typed result. Text formatting is only for
diagnostics.

U skips a TLV and M stops processing of the rest. Any I flag, or an HMAC that
is present but unusable, blocks all values. With a key, a required
Micro-session ID, BER, Direct Measurement and Follow-Up need verified TLV
integrity. Optional Access Report and CoS handling also accept replies without
an HMAC. A reply that passes structural validation without a signature is
still not authenticated.

The sender validates the SSID and the pending probe before it commits a
learned Micro-session ID. See
[integrity and BER](measurements.md#integrity-and-ber).

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

SIGHUP on Unix is handled separately. It reloads the reflector's HMAC keys
(`receiver::reload_keys`), and if the reload fails the current keys stay in
use. The SNMP sub-agent uses a child of the role token, and dropping its
handle cancels the worker, including on early returns. Blocking I/O checks for
cancellation every 200 ms. Close acknowledgments have their own 200 ms
deadline. See
[Capacity, drain and shutdown](usage.md#capacity-drain-and-shutdown).

## Session management

In both sequencing modes, a session is identified by the source UDP endpoint,
the actual destination UDP endpoint, the SSID and, if present, the sender's
Micro-session ID. Permissive admission learns identities from traffic.
Provisioned admission needs an exactly matching rule configured at startup.
`--stateful-reflector` only changes how sequence numbers are generated: the
reflector counts its own sequence instead of echoing the sender's. See
[Session provisioning](usage.md#session-provisioning).

Each session entry holds counters, replay state and Follow-Up state. Accepted
packets reset the idle timer, but outgoing copies do not. The default idle
timeout is 300 seconds, and 0 turns cleanup off. When the session cap or a
drain rejects a packet, no temporary session is created and no ID or sequence
number is used up. When a session expires, its static provisioning stays in
place.

Each reflector with a nonzero session timeout runs one cleanup worker. It scans
every half timeout, with a minimum of one second. The nix backend runs its
first scan at once, and pnet waits one interval. Each later scan starts one
interval after the previous one finishes, so scans never overlap and missed
scans do not pile up. A timeout of zero starts no worker. Cleanup does not run
inside the async receive loop or the pnet capture loop, so it makes progress
even when no traffic arrives.

The worker first looks for expired sessions under a shared lock on the table,
so existing sessions can still record activity during scans that remove
nothing. Before it commits to retiring a session, it checks again under the
exclusive lock. A session committed for retirement rejects new acquisitions
and queued sends. If no send holds its lifetime guard, cleanup removes it at
once. Otherwise its identity and capacity stay reserved while cleanup waits for
that send outside the table lock. During the wait, other sessions can be
looked up, admitted or controlled, subject to the current cap and drain state.
New identities still need exclusive access to the table, and the initial scan
can still delay them.

Inventory and capacity counts include reserved entries until they are
removed. Direct lookup and admission return `None` for an identity that is
being retired, and a later request can create fresh state once it is gone.
Activity after the commit cannot undo the retirement. Removal through the
control API reserves and waits in the same way. Removal compares the exact
session reference it holds, so a late finisher cannot remove a replacement,
even if numeric session IDs wrap.

Cleanup keeps a temporary reference to each removed session until it releases
the table lock. Committing to retirement and the final removal happen under
the lock, and waiting for busy sends happens outside it. Cleanup drops its
extra references afterward. Sessions that nothing else references are
therefore destroyed, along with the allocator work that involves, outside the
lock. Queued replies and other owners can keep state alive for longer. The
reference buffer grows with the number of removals, and busy sessions need
extra key and reference storage, so cleanup uses some temporary memory and
bookkeeping. Scanning and removal still take the table lock. This does not
put a limit on packet latency or remove every source of contention.

When the control inventory index is enabled, cleanup removes a small first
batch of index entries directly and then buffers the ordinals of further
removals. Sparse expiry can finish without that buffer. If at least three
quarters of the table has gone and buffered removals remain, cleanup builds a
new index of the surviving sessions and destroys the old tree after it
releases the table lock. The survivors include busy sessions that are reserved
for retirement. They keep their original inventory ordinals, so existing page
cursors keep their creation boundary and order. The ordinal buffer and the
replacement index use temporary memory during cleanup. Managers with the index
disabled allocate neither.

On exit, or when the reflector's future is cancelled, the cleanup worker is
stopped and joined before its owner is released. Joining can wait for a scan
that is already running, including its waits for sends to retire. If the
worker fails to start, that is reported as a startup error. A panic in cleanup
cancels only the affected reflector's child shutdown token and is returned as
a receiver error after draining. It does not cancel a shared parent token, and
it does not leave the reflector running without periodic expiry.

### Session admission and lifetime

The internal admission permit records the provisioning decision for one
manager and identity. It holds no lock during authentication and reserves no
capacity. Acquisition checks the current cap and drain state again under the
table write lock.

Each send holds a read guard on the session's lifetime through the syscall and
the state updates. Retirement starts by setting a flag, which cannot be
cleared, under exclusive table access. New sends check that flag before and
after taking the lifetime guard. Removal waits for existing guards outside the
table lock and then removes only that same session instance. The send path
never takes the table lock while it holds its guard. Re-admission creates
fresh state with a new internal ID. Acquisition APIs return `None` when they
reject a session or it is being retired.

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
| 243 | Residual BER count, burst and optional nested pattern (sub-TLV 241) | Experimental; legacy outer Types 240–242 are retired |
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
rejects replies that carry a different nonzero SSID. Replies with a zero SSID
are handled according to `--on-zero-ssid continue|stop`. With `continue`,
later nonzero SSIDs are still checked.

### TLV wire format (RFC 8972 §4)

A TLV has one flags octet, one type octet, a two-octet big-endian value length,
and the value. U, M, I and C use the masks `0x80`, `0x40`, `0x20` and `0x10`;
the lower bits are reserved. C is defined by the extensions that use it,
including Type 12, BER and header reflection. Type-specific layouts are in
`src/tlv/typed/`.

### Class of Service TLV (RFC 8972 §4.4)

The reflector records the DSCP and ECN it received in DSCP2 and EC2. Local
policy decides whether the requested DSCP1 and EC1 are allowed, and socket
support decides whether they can be applied. If the requested DSCP is refused,
the reply reports RPD=01 and uses the received DSCP if policy permits it.
Otherwise it uses the lowest admitted value and also sets C; an empty policy
uses the default DSCP 0. DSCP2 always reports what arrived. A restricted policy
that cannot be enforced suppresses processed CoS replies. An ECN fallback uses Not-ECT and reports RPE=10. If
neither marking can be applied, unrestricted policies report RPE=01.
Destination rules are checked again for the address the reply actually goes
to, including return-path retries. The sender's AIMD response is described
under [TLV-driven sender features](usage.md#tlv-driven-sender-features).

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
the sequence number and timestamp. The sender matches the reflector's own
sequence number against its reply history to report
[corrected reverse delay](measurements.md#follow-up-corrected-reverse-delay).

### Timestamp Information TLV (RFC 8972 §4.3)

Senders zero all information fields. Reflectors report the clock sources and
methods actually used for T2 and T3. A hardware T2 uses the PHC source; a
software T2 and the current T3 use the system source. See
[Clock synchronization metadata](usage.md#clock-synchronization-metadata).

### Access Report TLV (RFC 8972 §4.6)

Valid IDs 1 (3GPP) and 2 (Non-3GPP) are echoed; other IDs get U set. The
sender retransmits until a usable echo arrives or the retry budget runs out,
including after its main send loop ends. A U-flagged echo is skipped
(RFC 8972 §4) and does not count as an acknowledgement.

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
  one component that owns sending sets the sticky `IPV6_RTHDR` option, keeps
  the requested SIDs, reserves the last segment slot for the UDP destination,
  and clears the SRH again before ordinary replies. Paths that cannot do this,
  including pnet, fall back with U set.
- SR-MPLS label stack forwarding is unsupported and gets U set.

The first Return Path TLV decides routing. The reflector validates the framing
of every child before it changes any of them. A Control Code takes precedence,
and other well-framed parameter values are then ignored. Without one, only the
first address and the first segment list are used. Selected child headers have
U, M, I and the reserved bits cleared, and unknown or ignored children get U.
A processed Control Code transmits only bit 0. Broken framing, or an invalid
length in a selected child, sets M/U on the parent and M on the identifiable
child, and stops processing of later extensions. When the sender receives a
child M or I, it promotes it to local validation before it uses any extension
value. An unrecognized parent is skipped. Copies that failed integrity or were
already skipped keep their child bytes as received. The inherited requirement
to set these flags unconditionally is still rated Partial. See
[nested flag limits](conformance/rfc9503.md#nested-flags).

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
either mismatch drops the packet, also when Type 12 is disabled, because the
group checks run before the disabled check. Malformed groups are skipped. An L2
group with two- or eight-byte halves is well formed but never matches an
EUI-48 address.

Enabled bursts use deadline queues. Each request takes one budget slot and
gets a fixed transport plan, so a fallback on one copy cannot change the
policy for later copies. Timestamps, stateful sequence numbers, telemetry and
route MTU are evaluated for each copy. `DatagramSender` serializes socket
option changes and sends, and caches sticky settings that succeeded separately
for each address family. Rate limiting or a send failure can stop the rest of
a burst.

An attempt that needs no trimming reuses the current copy's buffer. Shaping
uses a separate buffer, so a retry over another route can send the full reply
without inheriting a clamp's C flag or padding. Every attempt refreshes T3 and
generated HMACs, and failed sends do not use up sequence or counter state.
Earlier burst copies keep the original template, and the last copy takes over
its buffer.

On Linux the reflector looks up the route of each reply and subtracts the IP,
UDP and SRH overhead. Netlink notifications, a 250 ms expiry and a refresh on
`EMSGSIZE` keep the cache current. The cache holds at most 256 entries. When
it is full, a second-chance queue replaces one route instead of clearing the
whole working set. A hit marks an entry for another chance but does not extend
its expiry. Expired entries are rejected on lookup or replaced. A notification,
or a failure to receive notifications, clears both the entries and the queue
state. Padding and optional reflected-header TLVs may shrink to fit, but
mandatory fields may not. An MTU clamp sets C and stops the burst. If the MTU
budget is unknown, the reply is dropped. See
[Reply size and route MTU](usage.md#reply-size-and-route-mtu).

Drain rejects new session identities. Expiry retires a session's queued sends.
Shutdown stops intake, allows the configured grace period, then cancels the
rest. `reply_queue_rejected` counts refused requests, and
`queued_replies_cancelled` counts copies that were never sent. The aggregate
drop count goes up by one for each rejected request, and by one for each
request whose remaining copies were cancelled.

### Residual BER TLV (draft-ietf-bpm-stamp-ber-01)

Experimental outer Type 243 carries the error count and maximum burst in
eight fixed bytes, followed by an optional pattern sub-TLV (experimental
Type 241). Without the sub-TLV the pattern is `ff00ff00`. A pattern carried in
the sub-TLV must be at least four bytes. The reflector checks the padding it received,
reports the forward errors, and repairs the padding for the reverse
measurement. Missing or duplicate padding or BER TLVs, duplicate patterns and
misalignment get C on the outer TLV. A short outer value gets M+C. A short
value in a known pattern sub-TLV gets M on the sub-TLV. Unknown nested values
are echoed with U.

BER padding goes after the HMAC, outside the bytes it covers, so corruption in
the padding can be measured without touching the signed metadata. Parent and
nested flags and integrity decide whether the sender records an observation.
After a U, the sender stops requesting BER, and delay and loss measurement
carries on. A count with a zero burst can mean the burst is unavailable, and
it is not recorded as a clean burst sample. Legacy Types 240–242 get U, and
`--ber-omit-burst` is a migration error. See
[migration and peer compatibility](ber-migration.md).

A BER interval lasts `--ber-interval` × `--send-delay`. The length is fixed at
startup and stays the same under ECN backoff. Thresholds are per million. Only
a completed interval that goes above a threshold raises an alarm. Empty
windows are left out, and the current partial window never raises alarms. See
[retention](statistics.md#memory-and-ber-history).

On Linux the sender shrinks its padding by whole pattern repetitions to fit the
route MTU. When the reflector fits a reply to the route budget for Type 12 or
the MTU, it fills the exact budget with the validated BER pattern, even if
semantic resizing has already set C on the parent. A controlled reply can then
end with a partial repetition, and C on the BER TLV marks the resized sample
as unusable.
Reflected headers are removed before BER padding is shrunk. Resizing the
padding sets C on the BER metadata because the denominator changed. Removing
only headers leaves the denominator as it was. The Type 12 MTU clamp sets its
own C and stops the burst. Standalone BER trimming keeps whole repetitions.
Controlled fitting needs the mandatory fields and the padding header to fit.
If they do not, the reply is dropped instead of being sent with a malformed
TLV tail.
Use symmetric replies for BER. UDP checksums and link CRC or FEC can discard
corrupt packets before delivery, so this measures residual errors in
delivered packets, not raw link BER.

C flags set for BER, Type 12, header reflection, CoS and nested control
reasons have fixed counters, and each reason is logged with its own throttle
after the reply has been sent. Header reasons carry fixed provenance metadata
so the reflector can tell whether the offending header survived size
trimming. Failed MTU attempts do not affect later retries.
Administrative trimming counts an existing request HMAC once and reserves room
for a new HMAC only when one is needed. The shorter reply keeps complete TLV
framing and does not fill the space of removed headers with raw zero bytes
after the HMAC.
The [matrix](conformance/draft-stamp-ber.md) records the diagnostics for the
TLV-enabled profile. Every known place where the reflector sets C itself has a
specific reason. `peer_c_preserved` separately counts C copied from the peer
in complete child headers of Location, Timestamp Information, Return Path,
Type 12 and BER containers. This count reads headers only and stops at
incomplete child framing. It never decodes values or unknown container
formats, does not validate opaque values, and does not affect packet
processing. Legacy tails in TLV-ignore mode are not interpreted.
The structural C for a short BER TLV is set before HMAC verification, so it
can still be counted when an I is added later. Failed digests and payload
bytes stay opaque. Zero-checksum validation, platform MTU and physical LAG
remain listed as limitations.

### Reflected IPv6 Extension and Fixed Header Data TLVs (draft-ietf-ippm-stamp-ext-hdr-26)

Type 246 (IPv6 extension header, §4.1 and §4.2) has an 8-octet Requested
field. Type 247 (IP fixed header, §6.1 and §6.2) has a 4-octet Requested
field. The TLV length is the full size of the target header, and a Type 246
length must be a multiple of 8. Each zero octet in Requested is a wildcard. A
Requested field with nonzero octets must identify exactly one unconsumed header
of matching length. If it matches more than one, the reply gets C and nothing
is copied or consumed. An all-zero Requested field selects the first
unconsumed header of that length and is filled with that header's first
octets. A nonzero Requested field is left as it is, and the rest of the header
is copied into Received. Separate allowlists of source IPs control whether
fixed headers and extension headers are disclosed, and both deny by default.
Each captured header is reflected by at most one TLV, so successive TLVs pair
with successive headers. If no headers were captured, or none match, C is set
and the value is left unchanged. A Type 247 after a Type 246 sets C on every
header TLV, and nothing is copied (§7.1).

Revision 26's example with identical prefixes contradicts its own ambiguity
rules. The shared processor follows the rules: repeated ambiguous nonzero
selectors get C without consuming a header, and all-zero requests select each
capture once, in order. See the [conformance interpretation](conformance/draft-stamp-ext-hdr.md#revision-26-interpretation).

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
header (`--attach-ext-hdr`). Requests given with `--reflected-ipv6-ext-hdr`
replace the automatic ones and must match the attached headers in order. If
they cover an ambiguous subset, they need a selector. Type 247 covers the sender's one fixed
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
`src/metrics/` and are not registered in advance, so each one appears only
after its first event. See [Observability](usage.md#observability).

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
- Both byte orders are decoded according to each PDU header. Responses use
  network byte order. Only the default context is supported.

### Framing and failure handling

`PduReader` keeps partial frames across 200 ms read timeouts and checks
lengths before it allocates or indexes. EOF ends the connection. If the first
connection attempt fails, the sub-agent logs a warning and STAMP keeps
running without SNMP; it never retries that first connection. Later failures
trigger reconnection and re-registration with exponential backoff from 1 to
30 s. A supervisor logs panics in the event
loop.

The Open and Register handshakes check the eight-byte Response prefix, the
error status, the packet ID and, after Open, the session ID. Net-SNMP may
append the original administrative binding, and only the matching OID and
value are accepted. RFC 2741 defines no value for administrative transaction
IDs, so they are not compared. Each handshake read and frame write has an
absolute 30-second deadline and checks for role cancellation. Tests against a
separately written master cover invalid responses, both byte orders and
cancellation.

### Tests

- `tests/agentx_protocol_test.rs` runs a separately written master over a real
  Unix socket against the production session and event loop. Its encoder and
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

These tests cover the subset above. They are not a full SNMP certification.

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
timestamp because it is written before transmission. A hardware report can
replace a software record, but a later software report cannot replace a
hardware one.

macOS supports software RX timestamps through `SO_TIMESTAMP`. Windows has no
kernel or NIC timestamp path. A capability probe does not prove that a
hardware timestamp was used. NIC PHCs must be synchronized with the clocks
used at both endpoints, for example with ptp4l and phc2sys. The
synchronization declarations and the S bit do not synchronize anything. See
the [two-host verification procedure](testing-hardware-timestamps.md).

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
