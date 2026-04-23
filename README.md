# stamp-suite

Simple Two-Way Active Measurement Protocol (STAMP) implementation in Rust (RFC 8762, RFC 8972, RFC 9503, and RFC 9534; plus experimental support for draft-ietf-ippm-asymmetrical-pkts and draft-gandhi-ippm-stamp-ber)

[![CI](https://github.com/asmie/stamp-suite/actions/workflows/rust.yml/badge.svg)](https://github.com/asmie/stamp-suite/actions/workflows/rust.yml)
[![Dependency status](https://deps.rs/repo/github/asmie/stamp-suite/status.svg)](https://deps.rs/repo/github/asmie/stamp-suite)
[![License](https://img.shields.io/crates/l/stamp-suite.svg)](https://opensource.org/licenses/MIT)
[![Latest version](https://img.shields.io/crates/v/stamp-suite.svg)](https://crates.io/crates/stamp-suite)

## About

stamp-suite is a Rust implementation of the Simple Two-Way Active Measurement Protocol (STAMP) as defined in RFC 8762, RFC 8972, RFC 9503, and RFC 9534. It also includes experimental support for two IETF drafts: Reflected Test Packet Control (draft-ietf-ippm-asymmetrical-pkts, Type 12) for asymmetrical reply traffic, and Bit Error Rate measurement (draft-gandhi-ippm-stamp-ber, Types 240/241/242). It provides a single binary that can operate as either a Session-Sender (client) or Session-Reflector (server) for measuring packet loss and network delays.

### Key Features

- Full RFC 8762 compliance (unauthenticated and authenticated modes)
- RFC 8972 TLV extension support with full processing for all defined types
- RFC 9503 Segment Routing extensions (Destination Node Address, Return Path with SR-MPLS/SRv6)
- RFC 9534 Micro-session ID TLV for LAG per-member-link measurement
- Reflected Test Packet Control TLV (draft-ietf-ippm-asymmetrical-pkts-14, Type 12) for asymmetrical reply measurement
- Bit Error Rate TLVs (draft-gandhi-ippm-stamp-ber-05, Types 240/241/242) for residual BER measurement against a known padding pattern
- Reflected Fixed/IPv6 Extension Header Data TLVs (draft-ietf-ippm-stamp-ext-hdr, Types 247/246) for header-transparency diagnostics — feature-gated to the pnet backend, gracefully U-flagged on the default nix backend
- Class of Service (CoS) TLV support with DSCP/ECN measurement (RFC 8972 §5.2)
- Location, Timestamp Info, Direct Measurement, Access Report, and Follow-Up Telemetry TLVs
- HMAC authentication support
- Stateful reflector mode with per-client session tracking (RFC 8972 Section 4)
- Support for both NTP and PTP timestamp formats
- Real TTL/Hop Limit capture on all platforms
- Optional Prometheus metrics endpoint for observability
- Optional SNMP AgentX sub-agent for MIB-based monitoring (Unix only)
- Backward compatible - works with clients/reflectors without TLV support
- Async I/O using Tokio
- Cross-platform support (Linux, macOS, Windows)

### How STAMP Works

STAMP measures packet loss and one-way/two-way delays between two endpoints. The Session-Sender transmits test packets to the Session-Reflector, which timestamps and reflects them back. By comparing timestamps, you can calculate:

- Round-trip time (RTT)
- One-way delay (requires synchronized clocks via NTP/PTP)
- Packet loss rate

## Installation

### From Source (Cargo)

```bash
# Default build (real TTL capture on Linux/macOS/Windows)
cargo build --release
```

### Using Nix

```bash
# Build the package
nix build

# Run directly without installing
nix run . -- --is-reflector

# Enter a development shell with cargo, rustc, rustfmt, and clippy
nix develop
```

### Platform Support

| Platform | Default Backend | TTL Capture |
|----------|-----------------|-------------|
| Linux    | nix (IP_RECVTTL) | Real TTL, no special privileges |
| macOS    | nix (IP_RECVTTL) | Real TTL, no special privileges |
| Windows  | pnet (raw packets) | Real TTL, requires Npcap |

### Feature Flags

| Feature | Description |
|---------|-------------|
| `ttl-nix` | Force nix backend (Linux/macOS/BSD) |
| `ttl-pnet` | Force pnet raw socket backend (requires root/admin) |
| `metrics` | Enable Prometheus metrics endpoint |
| `snmp` | Enable SNMP AgentX sub-agent (Unix only) |

### Receiver Backends

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

#### Why nix is the default where it works

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

#### Tradeoff

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

## Usage

### Session-Reflector (Server)

Start the reflector to listen for incoming STAMP packets:

```bash
# Listen on all interfaces, default port 862
stamp-suite -i

# Listen on specific address and port
stamp-suite -i --local-addr 192.168.1.100 --local-port 8620

# With verbose per-packet statistics
stamp-suite -i -R

# Stateful reflector mode (RFC 8972) - maintains independent sequence
# counters per client, allowing detection of reflector-side packet loss
stamp-suite -i --stateful-reflector

# Stateful mode with custom session timeout (default: 300 seconds)
stamp-suite -i --stateful-reflector --session-timeout 600

# TLV handling modes (RFC 8972 extensions)
stamp-suite -i --tlv-mode echo      # Echo TLVs back (default, RFC compliant)
stamp-suite -i --tlv-mode ignore    # Strip TLVs for backward compatibility

# Reflector member link ID for LAG micro-sessions (RFC 9534)
stamp-suite -i --reflector-member-link-id 2

# Verify TLV HMAC integrity (requires --hmac-key)
stamp-suite -i --verify-tlv-hmac --hmac-key <hex-key>

# With Prometheus metrics endpoint (requires --features metrics)
stamp-suite -i --metrics --metrics-addr 127.0.0.1:9090

# With SNMP AgentX sub-agent (requires --features snmp, Unix only)
stamp-suite -i --snmp

# Custom AgentX socket path
stamp-suite -i --snmp --snmp-socket /var/agentx/master
```

### Session-Sender (Client)

Send test packets to a reflector:

```bash
# Basic usage - send 1000 packets to remote reflector
stamp-suite --remote-addr 192.168.1.100

# Custom settings
stamp-suite --remote-addr 192.168.1.100 \
    --remote-port 8620 \
    --local-port 8621 \
    --count 100 \
    --send-delay 100 \
    -R

# With Session-Sender Identifier (RFC 8972 TLV extension)
stamp-suite --remote-addr 192.168.1.100 --ssid 12345

# With Class of Service TLV (measure DSCP/ECN handling)
stamp-suite --remote-addr 192.168.1.100 --cos --dscp 46 --ecn 2

# With Location TLV (reflector reports observed src/dst addresses)
stamp-suite --remote-addr 192.168.1.100 --location

# With Direct Measurement TLV (packet loss counters)
stamp-suite --remote-addr 192.168.1.100 --direct-measurement

# With Timestamp Info TLV (clock sync and timestamping method)
stamp-suite --remote-addr 192.168.1.100 --timestamp-info

# With Follow-Up Telemetry TLV (previous reflection data)
stamp-suite --remote-addr 192.168.1.100 --follow-up-telemetry

# With Access Report TLV (access ID 5, return code 1)
stamp-suite --remote-addr 192.168.1.100 --access-report 5

# With Destination Node Address TLV (RFC 9503 - verify reflector identity)
stamp-suite --remote-addr 192.168.1.100 --ssid 1 --dest-node-addr 192.168.1.100

# With Return Path TLV - suppress reply (RFC 9503)
stamp-suite --remote-addr 192.168.1.100 --return-path-cc 0

# With Return Path TLV - alternate reply address (RFC 9503)
stamp-suite --remote-addr 192.168.1.100 --return-address 10.0.0.5

# With Return Path TLV - SR-MPLS label stack (RFC 9503)
stamp-suite --remote-addr 192.168.1.100 --return-sr-mpls-labels 100,200,300

# With Return Path TLV - SRv6 segment list (RFC 9503)
stamp-suite --remote-addr 192.168.1.100 --return-srv6-sids 2001:db8::1,2001:db8::2

# With Micro-session ID TLV for LAG member link measurement (RFC 9534)
stamp-suite --remote-addr 192.168.1.100 --micro-session-id 1

# Request asymmetrical reply traffic: 4 replies at 1ms intervals
# (draft-ietf-ippm-asymmetrical-pkts, Type 12)
stamp-suite --remote-addr 192.168.1.100 \
    --reflected-control-count 4 \
    --reflected-control-interval-ns 1000000

# Enable Bit Error Rate TLVs against a 0xFF00 pattern (draft-gandhi-ippm-stamp-ber)
stamp-suite --remote-addr 192.168.1.100 --ber --ber-padding-size 128

# BER with a custom pattern (hex, with or without 0x prefix)
stamp-suite --remote-addr 192.168.1.100 --ber --ber-pattern aa55 --ber-padding-size 256

# Combine multiple TLV types
stamp-suite --remote-addr 192.168.1.100 \
    --cos --dscp 46 \
    --direct-measurement \
    --location \
    --timestamp-info
```

### Command-Line Options

```
Options:
  -r, --remote-addr <REMOTE_ADDR>  Remote address for Session Reflector [default: 0.0.0.0]
  -S, --local-addr <LOCAL_ADDR>    Local address to bind for [default: 0.0.0.0]
  -p, --remote-port <REMOTE_PORT>  UDP port number for outgoing packets [default: 862]
  -o, --local-port <LOCAL_PORT>    UDP port number for incoming packets [default: 862]
  -K, --clock-source <CLOCK_SOURCE> Clock source to be used [default: NTP]
  -d, --send-delay <SEND_DELAY>    Delay between packets in milliseconds [default: 1000]
  -c, --count <COUNT>              Number of packets to send [default: 1000]
  -L, --timeout <TIMEOUT>          Timeout for lost packets in seconds [default: 5]
  -A, --auth-mode <AUTH_MODE>      Work mode: A=authenticated, O=open [default: O]
  -R                               Print individual statistics for each packet
  -i, --is-reflector               Run as Session Reflector instead of Sender
      --stateful-reflector         Enable stateful reflector mode (RFC 8972 Section 4)
      --session-timeout <SECONDS>  Session timeout for stateful mode [default: 300]
      --tlv-mode <MODE>            TLV handling: ignore, echo [default: echo]
      --verify-tlv-hmac            Verify HMAC TLV in incoming packets
      --ssid <ID>                  Session-Sender Identifier for TLV extension
      --cos                        Enable Class of Service TLV
      --dscp <VALUE>               DSCP value for CoS TLV (0-63) [default: 0]
      --ecn <VALUE>                ECN value for CoS TLV (0-3) [default: 0]
      --location                   Enable Location TLV
      --timestamp-info             Enable Timestamp Information TLV
      --direct-measurement         Enable Direct Measurement TLV
      --follow-up-telemetry        Enable Follow-Up Telemetry TLV
      --access-report <ID>         Enable Access Report TLV with Access ID (0-15)
      --access-return-code <CODE>  Return code for Access Report TLV [default: 1]
      --hmac-key <HEX>             HMAC key in hex format
      --hmac-key-file <PATH>       Path to file containing HMAC key
      --dest-node-addr <IP>        Destination Node Address TLV (RFC 9503, requires --ssid)
      --return-path-cc <CODE>      Return Path control code: 0=suppress, 1=same-link (RFC 9503)
      --return-address <IP>        Return Path alternate reply address (RFC 9503)
      --return-sr-mpls-labels <L>  Return Path SR-MPLS label stack, comma-separated (RFC 9503)
      --return-srv6-sids <SIDS>    Return Path SRv6 segment list, comma-separated (RFC 9503)
      --micro-session-id <ID>      Sender micro-session member link ID for LAG measurement (RFC 9534)
      --reflector-member-link-id <ID> Reflector member link ID for LAG micro-sessions (RFC 9534)
      --reflected-control-count <N> Number of reply packets to request (Type 12, >1 activates)
      --reflected-control-length <LEN> Requested reply packet length in octets (0 = don't pad)
      --reflected-control-interval-ns <NS> Inter-packet gap in nanoseconds [default: 1000000]
      --ber                        Enable BER TLVs (Types 240/241/242, sender side)
      --ber-pattern <HEX>          Bit pattern to repeat in the Extra Padding (default: ff00)
      --ber-padding-size <BYTES>   Extra Padding length used with --ber [default: 64]
      --metrics                    Enable Prometheus metrics endpoint (requires metrics feature)
      --metrics-addr <ADDR>        Metrics server bind address [default: 127.0.0.1:9090]
      --snmp                       Enable SNMP AgentX sub-agent (requires snmp feature, Unix only)
      --snmp-socket <PATH>         AgentX master agent socket path [default: /var/agentx/master]
  -h, --help                       Print help
  -V, --version                    Print version
```

### Example Output

**Sender with per-packet statistics (-R):**
```
seq=0 rtt=0.523ms ttl=64 reflector_recv_ts=16890123456789 reflector_send_ts=16890123456790
seq=1 rtt=0.498ms ttl=64 reflector_recv_ts=16890123556789 reflector_send_ts=16890123556790
...

--- STAMP Statistics ---
Packets sent: 100
Packets received: 100
Packets lost: 0 (0.0%)
Min RTT: 0.412 ms
Max RTT: 1.203 ms
Avg RTT: 0.521 ms
```

## Configuration File

Any option accepted on the command line can also be supplied through a TOML
configuration file via `--config <PATH>`. Values in the file are used as
defaults; any key not present in the file keeps its built-in default.

```bash
stamp-suite --config /etc/stamp/reflector.toml
```

### Precedence

From highest to lowest priority:

1. Command-line flag (e.g. `--remote-port 1234`)
2. `STAMP_HMAC_KEY` environment variable (for the HMAC key only)
3. Value from the `--config` TOML file
4. Hardcoded default

In other words: the file provides new defaults; CLI flags and env vars still
override them field-by-field.

### Example `reflector.toml`

```toml
# Reflector bound on a specific address/port
is_reflector = true
local_addr = "192.0.2.10"
local_port = 862

# Protocol behaviour
auth_mode = "O"              # "A" for authenticated, "O" for open
clock_source = "NTP"         # "NTP" or "PTP"
tlv_mode = "echo"            # "echo" or "ignore"
stateful_reflector = true
session_timeout = 300

# Optional features
metrics = true
metrics_addr = "127.0.0.1:9090"

# HMAC key – only a PATH can be set from the config file.
# The plaintext `hmac_key` field is deliberately rejected; pass the raw
# key via --hmac-key or the STAMP_HMAC_KEY environment variable instead.
hmac_key_file = "/etc/stamp/hmac.key"
```

### Supported keys

Every long-form CLI flag is available in the file using its snake_case
name (e.g. `--remote-addr` becomes `remote_addr`, `--ber-padding-size`
becomes `ber_padding_size`). Examples of non-trivial types:

| Field | TOML type | Example |
|-------|-----------|---------|
| `remote_addr`, `local_addr`, `dest_node_addr`, `return_address` | string (IPv4 or IPv6) | `"192.0.2.10"`, `"2001:db8::1"` |
| `metrics_addr` | string (`addr:port`) | `"127.0.0.1:9090"` |
| `auth_mode` | enum | `"A"` or `"O"` |
| `clock_source` | enum | `"NTP"` or `"PTP"` |
| `tlv_mode` | enum | `"echo"` or `"ignore"` |
| `output_format` | enum | `"text"`, `"json"`, or `"csv"` |
| `return_sr_mpls_labels` | integer array | `[100, 200, 300]` |
| `return_srv6_sids` | string array (IPv6) | `["2001:db8::1", "2001:db8::2"]` |
| `hmac_key_file` | string (path) | `"/etc/stamp/hmac.key"` |

The `hmac_key` and `config` fields are intentionally **not** accepted
from the file — the former to keep plaintext secrets out of config files,
the latter because it would be recursive.

### File permissions

Because the config file can set `hmac_key_file` and every other setting,
treat it as trusted: an attacker who can overwrite it can change any
STAMP parameter. On Unix, `stamp-suite` logs a warning if the file is
writable by group or other (any bit in `0o022`). Recommended:

```bash
chmod 600 /etc/stamp/reflector.toml
```

### Validation and error messages

Failures are reported with actionable messages:

- **Unknown key** (typo): the parse error lists every valid field name.
  ```text
  Configuration file error: parse error in /etc/stamp.toml:
  TOML parse error at line 1, column 1
    |
  1 | remote_portt = 1234
    | ^^^^^^^^^^^^
  unknown field `remote_portt`, expected one of `remote_addr`, `local_addr`, ...
  ```
- **Wrong type / bad enum variant / malformed TOML**: reported with the
  exact line/column and caret marker from the `toml` crate.
- **Out-of-range values** (e.g. `dscp = 200`, `error_scale = 100`, or
  `auth_mode = "A"` without an HMAC key): caught by
  `Configuration::validate()` after the merge, with a message naming the
  offending field.

## Architecture

```
┌─────────────────┐         UDP/862         ┌─────────────────┐
│ Session-Sender  │ ──────────────────────► │Session-Reflector│
│   (stamp-suite) │ ◄────────────────────── │  (stamp-suite -i)│
└─────────────────┘    Reflected Packets    └─────────────────┘
```

### Module Structure

- `main.rs` - Entry point and CLI handling
- `configuration.rs` - Command-line argument parsing
- `packets.rs` - STAMP packet structures (RFC 8762 format)
- `sender.rs` - Session-Sender implementation
- `receiver/` - Session-Reflector implementations
  - `nix.rs` - nix crate with IP_RECVTTL (Linux/macOS)
  - `pnet.rs` - Raw packet capture (Windows)
- `session.rs` - Session state management
- `time.rs` - NTP/PTP timestamp generation
- `tlv.rs` - TLV extension support (RFC 8972)
- `metrics/` - Prometheus metrics (optional, requires `metrics` feature)
  - `sender_metrics.rs` - Sender-side metrics
  - `reflector_metrics.rs` - Reflector-side metrics
- `snmp/` - SNMP AgentX sub-agent (optional, requires `snmp` feature, Unix only)
  - `agentx.rs` - AgentX protocol implementation (RFC 2741)
  - `handler.rs` - STAMP-SUITE-MIB handler
  - `oids.rs` - OID constants
  - `state.rs` - Shared state types

## TLV Extensions (RFC 8972)

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
- `stamp_reflector_packets_received_total` - Total packets received
- `stamp_reflector_packets_reflected_total` - Total packets reflected
- `stamp_reflector_packets_dropped_total` - Dropped packets by reason
- `stamp_reflector_active_sessions` - Current active sessions (stateful mode)
- `stamp_reflector_hmac_failures_total` - HMAC verification failures
- `stamp_reflector_processing_seconds` - Packet processing time histogram

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

## Current Status

The project is functional for STAMP measurements with the following features:

- Full RFC 8762 compliance (unauthenticated and authenticated modes)
- Full RFC 8972 TLV extension support (all 8 defined TLV types)
- RFC 9503 Segment Routing extensions (Destination Node Address and Return Path TLVs)
- RFC 9534 Micro-session ID TLV for LAG per-member-link measurement
- Experimental Reflected Test Packet Control TLV for asymmetrical reply measurement (draft-ietf-ippm-asymmetrical-pkts-14, Type 12)
- Experimental Bit Error Rate TLVs for residual BER measurement (draft-gandhi-ippm-stamp-ber-05, Types 240/241/242)
- HMAC authentication support (base packet and TLV integrity)
- Class of Service TLV with DSCP/ECN measurement (RFC 8972 §5.2)
- Location TLV with real destination address capture (even on wildcard binds)
- Direct Measurement TLV with per-client packet counters
- Timestamp Information TLV with sync source and method reporting
- Follow-Up Telemetry TLV with previous reflection tracking
- Access Report TLV with structured validation
- Destination Node Address TLV with local address matching (RFC 9503 §4)
- Return Path TLV with suppress, alternate address, and SR echo support (RFC 9503 §5)
- Stateful reflector mode with per-client session tracking (RFC 8972 Section 4)
- Session-Sender Identifier (SSID) support via Extra Padding TLV
- Real TTL capture on all major platforms
- Optional Prometheus metrics for observability (requires `metrics` feature)
- Optional SNMP AgentX sub-agent with STAMP-SUITE-MIB (requires `snmp` feature, Unix only)
- Backward compatible with non-TLV implementations

### Roadmap

- [ ] Enhanced statistics and reporting

## Contributing

Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

Please ensure:
- Code passes `cargo clippy --all --all-features --tests -- -D warnings`
- Code is formatted with `cargo fmt`
- Tests are updated as appropriate

## Versioning

This project uses [SemVer](http://semver.org/) for versioning. See the [tags](https://github.com/asmie/stamp-suite/tags) for available versions.

## Authors

* **Piotr Olszewski** - *Original work* - [asmie](https://github.com/asmie)

See the list of [contributors](https://github.com/asmie/stamp-suite/contributors) who participated in this project.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## References

- [RFC 8762 - Simple Two-Way Active Measurement Protocol](https://datatracker.ietf.org/doc/html/rfc8762)
- [RFC 8972 - Simple Two-Way Active Measurement Protocol Optional Extensions](https://datatracker.ietf.org/doc/html/rfc8972)
- [RFC 9503 - Simple Two-Way Active Measurement Protocol Extensions for Segment Routing Networks](https://datatracker.ietf.org/doc/html/rfc9503)
- [RFC 9534 - Simple Two-Way Active Measurement Protocol Extensions for Performance Measurement on a Link Aggregation Group](https://datatracker.ietf.org/doc/html/rfc9534)
- [draft-ietf-ippm-asymmetrical-pkts - Performance Measurement with Asymmetrical Traffic Using STAMP](https://datatracker.ietf.org/doc/draft-ietf-ippm-asymmetrical-pkts/) (IETF IPPM working group draft; in RFC Editor queue)
- [draft-gandhi-ippm-stamp-ber - STAMP Extensions for Residual Bit Error Rate Measurement](https://datatracker.ietf.org/doc/draft-gandhi-ippm-stamp-ber/) (individual IETF draft)
