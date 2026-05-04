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
- `packets.rs` — STAMP packet structures for authenticated and unauthenticated modes. Big-endian fixed-width serialization via `bincode`.
- `sender.rs` — Session-Sender implementation: packet assembly, send loop, RTT statistics.
- `receiver/` — Session-Reflector implementations:
  - `receiver/mod.rs` — Shared STAMP-level pipeline. All TLV parsing, HMAC verification, Return Path handling, session tracking, and counter updates live here. Both backends call into the same `process_stamp_packet` after capturing a packet.
  - `receiver/nix.rs` — Default backend on Linux and macOS. Uses a `tokio::net::UdpSocket` with `IP_RECVTTL`, `IP_RECVTOS`, and `IP_PKTINFO` (plus IPv6 equivalents) to extract per-packet metadata via `recvmsg` control messages.
  - `receiver/pnet.rs` — Default backend on Windows; opt-in elsewhere via `--features ttl-pnet`. Captures at the datalink layer via libpcap / Npcap.
- `session.rs` — `SessionManager` and per-session state. Atomic sequence-number generation, idle-timeout reaping.
- `time.rs` — Timestamp generation in NTP and PTP formats.
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
On the nix backend the reflector echoes the TLV with the U-flag set per
RFC 8972 §4.2, and logs a one-time warning suggesting a rebuild with
`--features ttl-pnet` if header reflection is actually needed. This
follows the draft's own "may be unsupported by the reflector" semantics,
so the sender sees a spec-compliant response either way.

If you specifically need TLV 246/247 reflection, or you want to craft
outgoing packets with non-default IPv6 extension headers, build with
`--no-default-features --features ttl-pnet` and accept the tradeoffs
above.

## Packet Processing Pipeline

Both backends, after capturing a packet, hand it to the same shared pipeline in `receiver/mod.rs`:

1. **Parse** — Decode the STAMP base header into `PacketUnauthenticated` or `PacketAuthenticated`.
2. **HMAC verify** — In authenticated mode, `crypto::verify_packet_hmac` checks the keyed digest over the base packet. Failures increment `hmac_failures_total` and drop the packet.
3. **TLV pipeline** — Walk the TLV chain. For each known type, run its typed parser; unknown types are preserved and echoed with the U-flag set (per RFC 8972 §4.2).
4. **Session lookup / update** — Per-client counters (`reflector_rx_count`, `reflector_tx_count`, `last_reflection`) are always tracked. If `--stateful-reflector` is set, a per-client sequence number is also assigned via `SessionManager`.
5. **RFC 9503 processing** — Destination Node Address matching against `local_addresses`; Return Path action selection (Normal, SuppressReply, AlternateAddress, UnsupportedSr). Encoded into a `ReturnPathAction` carried in `StampResponse`.
6. **Assemble reply** — `assemble_unauth_answer_with_tlvs` / `assemble_auth_answer_with_tlvs` build the response, populate reflector-side TLV fields (DM counters, Follow-Up Telemetry, Timestamp Info, Location, Class of Service, etc.), and recompute HMACs (base + TLV) if applicable.
7. **Send** — Reply to the original source, an alternate address (Return Path), or suppress entirely.

The `ProcessingContext` struct carries per-packet shared state (counters, optional `SessionManager` reference, local addresses, sender port). `ReceiverSharedState` (counters, session manager, start time) lives at the receiver level and is created once via `create_shared_state()` before `run_receiver()`.

## Session Management

`SessionManager` is **always** instantiated, regardless of the `--stateful-reflector` flag. The flag only controls one thing: whether the assembler uses per-client sequence numbering (`ProcessingContext.session_manager: Option<&Arc<SessionManager>>`) instead of a global counter. Per-client packet counters and last-reflection tracking — needed by the Direct Measurement (Type 5) and Follow-Up Telemetry (Type 7) TLVs — run unconditionally because the TLV semantics require them.

Sessions are reaped after `--session-timeout` seconds of inactivity (default 300 s). When the SNMP feature is enabled, `SessionSummary` / `session_summaries_extended()` exposes per-session data for the SNMP session table.

## TLV Extensions Reference

The implementation supports RFC 8972 TLV (Type-Length-Value) extensions, which allow STAMP packets to carry optional data beyond the base packet format.

### Supported TLV Types

| Type | Name | Description | Status |
|------|------|-------------|--------|
| 1 | Extra Padding | Can carry Session-Sender ID (SSID) in first 2 bytes | Full |
| 2 | Location | Source/destination addresses and ports (RFC 8972 §4.2) | Full |
| 3 | Timestamp Info | Sync source and timestamping method (RFC 8972 §4.3) | Full |
| 4 | Class of Service | DSCP/ECN measurement (RFC 8972 §5.2) | Full |
| 5 | Direct Measurement | Sender/reflector packet counters (RFC 8972 §4.5) | Full |
| 6 | Access Report | Access identifier and return code (RFC 8972 §4.6) | Full |
| 7 | Follow-Up Telemetry | Previous reflection seq/timestamp (RFC 8972 §4.7) | Full |
| 8 | HMAC | TLV integrity verification (must be last) | Full |
| 9 | Destination Node Address | Verify intended reflector identity (RFC 9503 §4) | Full |
| 10 | Return Path | Control reply routing: suppress, alternate address, SR-MPLS, SRv6 (RFC 9503 §5) | Full |
| 11 | Micro-session ID | LAG member link identifiers for per-link measurement (RFC 9534 §3.1) | Full |
| 12 | Reflected Test Packet Control | Asymmetrical reply request — count, length, interval (draft-ietf-ippm-asymmetrical-pkts-14) | Experimental |
| 240 | BER Bit Pattern in Padding | Repeated bit pattern carried alongside Extra Padding (draft-gandhi-ippm-stamp-ber-05) | Experimental |
| 241 | BER Bit Error Count | u32 error-bit count, computed by reflector | Experimental |
| 242 | BER Max Bit Error Burst Size | u32 longest consecutive error run, computed by reflector | Experimental |
| 246 | Reflected IPv6 Extension Header Data | Reflects received IPv6 Hop-by-Hop / Destination Options headers (draft-ietf-ippm-stamp-ext-hdr) | Experimental (pnet backend only) |
| 247 | Reflected Fixed Header Data | Reflects the raw 20-byte IPv4 or 40-byte IPv6 fixed header (draft-ietf-ippm-stamp-ext-hdr) | Experimental (pnet backend only) |

**Status**: Full = structured parsing, validation, and reflector field population. Experimental = implements an active IETF draft; wire format and type numbers for BER (240/241/242) and ext-hdr reflection (246/247) are TBD in the draft (experimental-range picks) while Reflected Control (Type 12) is IANA-assigned. SR-MPLS/SRv6 forwarding is echoed with U-flag (actual segment routing is out of scope for userspace UDP). Types 246/247 require raw IP-header visibility which the default `nix` UDP-socket backend cannot provide; on that backend they are echoed with the U-flag set and a one-time warning is logged — see [Receiver Backends](#receiver-backends) for why the default remains `nix`.

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
- **New clients with SSID**: Reflectors without TLV support will zero-pad the response

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

The reflector fills in the actual destination IP from the received packet (using `IP_PKTINFO`/`IPV6_RECVPKTINFO` on nix, or parsed IP headers on pnet), so it reports the correct address even when bound to a wildcard (`0.0.0.0`/`::`). Address information is carried as sub-TLVs (IPv4 or IPv6 source/destination).

### Direct Measurement TLV (RFC 8972 §4.5)

The Direct Measurement TLV carries per-session packet counters for loss measurement:

```bash
stamp-suite --remote-addr 192.168.1.100 --direct-measurement
```

- **Sender** fills its transmit count (incremented per packet)
- **Reflector** fills its receive and transmit counts for the client's session

Counters are tracked per-client regardless of whether `--stateful-reflector` is enabled.

### Follow-Up Telemetry TLV (RFC 8972 §4.7)

The Follow-Up Telemetry TLV carries information about the previously reflected packet:

```bash
stamp-suite --remote-addr 192.168.1.100 --follow-up-telemetry
```

The reflector fills in the sequence number and timestamp from the last reflection for the client's session, along with its timestamping method. Like Direct Measurement, this works independently of `--stateful-reflector`.

### Timestamp Information TLV (RFC 8972 §4.3)

The Timestamp Info TLV reports the synchronization source and timestamping method at each endpoint:

```bash
stamp-suite --remote-addr 192.168.1.100 --timestamp-info
```

The sender fills its own sync source and method; the reflector fills in its values (e.g., NTP + software-local timestamping).

### Access Report TLV (RFC 8972 §4.6)

The Access Report TLV carries an access identifier and return code. The reflector echoes it unchanged:

```bash
stamp-suite --remote-addr 192.168.1.100 --access-report 5 --access-return-code 1
```

### Destination Node Address TLV (RFC 9503 §4)

The Destination Node Address TLV lets the sender specify the intended reflector address. The reflector checks whether the address matches any of its local interfaces:

```bash
# Verify that 192.168.1.100 is handling the reflection (requires --ssid)
stamp-suite --remote-addr 192.168.1.100 --ssid 1 --dest-node-addr 192.168.1.100
```

If the address does not match, the reflector sets the U-flag on the TLV and still reflects the packet, allowing the sender to detect misrouting (e.g., anycast failover).

### Return Path TLV (RFC 9503 §5)

The Return Path TLV controls how the reflector routes its reply. Several sub-TLV types are supported:

```bash
# Suppress reply entirely (control code 0)
stamp-suite --remote-addr 192.168.1.100 --return-path-cc 0

# Request reply to an alternate address
stamp-suite --remote-addr 192.168.1.100 --return-address 10.0.0.5

# Request SR-MPLS return path (echoed with U-flag in userspace)
stamp-suite --remote-addr 192.168.1.100 --return-sr-mpls-labels 100,200,300

# Request SRv6 return path (echoed with U-flag in userspace)
stamp-suite --remote-addr 192.168.1.100 --return-srv6-sids 2001:db8::1,2001:db8::2
```

The reflector handles each sub-TLV type:
- **Control Code**: Bit 0 controls reply behavior (0=suppress, 1=reply); reserved bits are ignored per RFC 9503
- **Return Address**: Reflector sends the reply to the specified IP. On send failure, it sets the U-flag and falls back to the original source address
- **SR-MPLS / SRv6**: Echoed with U-flag set (actual segment routing forwarding is out of scope for userspace UDP)

### Micro-session ID TLV (RFC 9534 §3.1)

The Micro-session ID TLV enables per-member-link performance measurement within Link Aggregation Groups (LAGs). Each member link is identified by a 16-bit ID on both sender and reflector sides:

```bash
# Sender: identify this member link as ID 1
stamp-suite --remote-addr 192.168.1.100 --micro-session-id 1

# Reflector: identify this member link as ID 2
stamp-suite -i --reflector-member-link-id 2
```

The sender sets its member link ID in outgoing packets. The reflector validates any non-zero reflector ID in the received TLV (discards on mismatch), echoes the sender ID unchanged, and fills in its own member link ID.

### Reflected Test Packet Control TLV (draft-ietf-ippm-asymmetrical-pkts)

The Reflected Test Packet Control TLV (Type 12, IANA-assigned) lets the sender request asymmetrical reply traffic — multiple reply copies spaced at a specified interval:

```bash
# Ask for 4 replies, 1 ms apart
stamp-suite --remote-addr 192.168.1.100 \
    --reflected-control-count 4 \
    --reflected-control-interval-ns 1000000
```

Reflector behaviour:
- Emits up to 16 reply packets per request (hard cap in `REFLECTED_CONTROL_MAX_COUNT`); excess requests are clamped and the **C flag** (Conformant Reflected Packet, bit 3 of the TLV flags byte) is set on the echoed TLV to indicate non-conformance.
- Clamps the inter-packet interval to at least 1 µs.
- A non-zero requested packet length is not honoured in this implementation (the reply is not re-padded); the C flag is set to signal this.
- On the `nix` backend extra copies are sent on a spawned tokio task so the recv loop is never blocked; the `pnet` backend sleeps inline on its capture thread.

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

The reflector XORs the received padding against the expected pattern (from the Bit Pattern TLV, or 0xFF00 if absent), counts error bits and the longest consecutive error run across byte boundaries, and writes the results into Types 241 and 242. Per draft §3, duplicate BER TLVs or a missing companion Extra Padding TLV cause the reflector to set the U-flag on all BER TLVs and skip the computation.

### Reflected Fixed / IPv6 Extension Header Data TLVs (draft-ietf-ippm-stamp-ext-hdr)

Two experimental TLVs let the sender ask the reflector to echo the bytes of the
received IP headers — useful for diagnosing DSCP remarking, TTL decrement,
Flow Label rewriting, or tampering with IPv6 Hop-by-Hop / Destination Options
by intermediate routers.

| Type | Name | Content |
|------|------|---------|
| 246 | Reflected IPv6 Extension Header Data | Concatenated Hop-by-Hop (NextHeader 0) and Destination Options (NextHeader 60) extension headers, each prefixed with its NextHeader byte and HdrExtLen byte as they appeared on the wire |
| 247 | Reflected Fixed Header Data | Raw 20-byte IPv4 or 40-byte IPv6 fixed header as received |

Type numbers are TBD in the draft; this implementation uses 246/247 from RFC
8972's experimental range.

```bash
# Ask the reflector to reflect the IPv4/IPv6 fixed header
stamp-suite --remote-addr 192.168.1.100 --reflected-fixed-hdr

# IPv6 test with reflected extension headers
stamp-suite --remote-addr 2001:db8::1 --reflected-ipv6-ext-hdr
```

**Backend requirement:** these TLVs require the reflector to copy raw IP-header
bytes into the response, which is only possible when the reflector captures at
the datalink layer. Only the `pnet` backend can do this (see
[Receiver Backends](#receiver-backends)).

- On the **pnet** backend (Windows default, or `--features ttl-pnet` on Unix):
  the reflector populates the TLV Value with the captured bytes. For IPv4
  packets the TLV is truncated to the fixed 20-byte header, so IPv4 options
  are not reflected.
- On the **nix** backend (Linux/macOS default): the kernel hides raw IP
  headers from the application, so the reflector has nothing to copy. The
  TLVs are echoed with an empty Value and the U-flag set per RFC 8972 §4.2,
  and a one-time warning is logged telling the operator to rebuild with
  `--features ttl-pnet` if header reflection is required. The sender sees a
  protocol-compliant response either way.
- A sender-requested Type 246 TLV on an IPv4 packet, or on an IPv6 packet
  without any extension headers, legitimately produces an empty Value — this
  is **not** the same as the U-flag case and is treated as a valid "no data"
  response.

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

**Note**: The `snmp` feature requires a Unix platform (Linux/macOS) because AgentX uses Unix domain sockets. On non-Unix platforms, `--snmp` prints an error and exits.

## See Also

- [README](../README.md) — install and quick-start.
- [usage.md](usage.md) — configuration file format, full CLI flag reference.
- [security.md](security.md) — HMAC, key management, systemd hardening, capability model.
