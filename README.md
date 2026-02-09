# stamp-suite

Simple Two-Way Active Measurement Protocol (STAMP) implementation in Rust (RFC 8762 and RFC 8972)

[![CI](https://github.com/asmie/stamp-suite/actions/workflows/rust.yml/badge.svg)](https://github.com/asmie/stamp-suite/actions/workflows/rust.yml)
[![Dependency status](https://deps.rs/repo/github/asmie/stamp-suite/status.svg)](https://deps.rs/repo/github/asmie/stamp-suite)
[![License](https://img.shields.io/crates/l/stamp-suite.svg)](https://opensource.org/licenses/MIT)
[![Latest version](https://img.shields.io/crates/v/stamp-suite.svg)](https://crates.io/crates/stamp-suite)

## About

stamp-suite is a Rust implementation of the Simple Two-Way Active Measurement Protocol (STAMP) as defined in RFC 8762 and RFC 8972. It provides a single binary that can operate as either a Session-Sender (client) or Session-Reflector (server) for measuring packet loss and network delays.

### Key Features

- Full RFC 8762 compliance (unauthenticated and authenticated modes)
- RFC 8972 TLV extension support (Session-Sender ID, HMAC for TLV integrity)
- Class of Service (CoS) TLV support with DSCP/ECN measurement (RFC 8972 §5.2)
- HMAC authentication support
- Stateful reflector mode with per-client session tracking (RFC 8972 Section 4)
- Support for both NTP and PTP timestamp formats
- Real TTL/Hop Limit capture on all platforms
- Optional Prometheus metrics endpoint for observability
- Backward compatible - works with clients/reflectors without TLV support
- Async I/O using Tokio
- Cross-platform support (Linux, macOS, Windows)

### How STAMP Works

STAMP measures packet loss and one-way/two-way delays between two endpoints. The Session-Sender transmits test packets to the Session-Reflector, which timestamps and reflects them back. By comparing timestamps, you can calculate:

- Round-trip time (RTT)
- One-way delay (requires synchronized clocks via NTP/PTP)
- Packet loss rate

## Installation

### From Source

```bash
# Default build (real TTL capture on Linux/macOS/Windows)
cargo build --release
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

# Verify TLV HMAC integrity (requires --hmac-key)
stamp-suite -i --verify-tlv-hmac --hmac-key <hex-key>

# With Prometheus metrics endpoint (requires --features metrics)
stamp-suite -i --metrics --metrics-addr 127.0.0.1:9090
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
      --hmac-key <HEX>             HMAC key in hex format
      --hmac-key-file <PATH>       Path to file containing HMAC key
      --metrics                    Enable Prometheus metrics endpoint (requires metrics feature)
      --metrics-addr <ADDR>        Metrics server bind address [default: 127.0.0.1:9090]
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

## TLV Extensions (RFC 8972)

The implementation supports RFC 8972 TLV (Type-Length-Value) extensions, which allow STAMP packets to carry optional data beyond the base packet format.

### Supported TLV Types

| Type | Name | Description | Status |
|------|------|-------------|--------|
| 1 | Extra Padding | Can carry Session-Sender ID (SSID) in first 2 bytes | Full |
| 2 | Location | Location information | Echo |
| 3 | Timestamp Info | Additional timestamp data | Echo |
| 4 | Class of Service | DSCP/ECN measurement (RFC 8972 §5.2) | Full |
| 5 | Direct Measurement | Direct measurement data | Echo |
| 6 | Access Report | Access report data | Echo |
| 7 | Follow-Up Telemetry | Telemetry information | Echo |
| 8 | HMAC | TLV integrity verification (must be last) | Full |

**Status**: Full = fully processed, Echo = echoed back with appropriate flags

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

- **Flags (1 octet)**: U=Unrecognized (bit 0), M=Malformed (bit 1), I=Integrity failed (bit 2), Reserved (bits 3-7)
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

## Current Status

The project is functional for STAMP measurements with the following features:

- Full RFC 8762 compliance (unauthenticated and authenticated modes)
- RFC 8972 TLV extension support with automatic detection
- HMAC authentication support (base packet and TLV integrity)
- Class of Service TLV with DSCP/ECN measurement (RFC 8972 §5.2)
- Stateful reflector mode with per-client session tracking (RFC 8972 Section 4)
- Session-Sender Identifier (SSID) support via Extra Padding TLV
- Real TTL capture on all major platforms
- Optional Prometheus metrics for observability (requires `metrics` feature)
- Backward compatible with non-TLV implementations

### Roadmap

- [ ] Enhanced statistics and reporting
- [ ] Additional TLV type processing (Location, Telemetry, etc.)
- [ ] SNMP/STAMP-MIB support

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
