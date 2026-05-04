# stamp-suite

Simple Two-Way Active Measurement Protocol (STAMP) implementation in Rust — RFC 8762, RFC 8972, RFC 9503, RFC 9534, plus experimental support for draft-ietf-ippm-asymmetrical-pkts and draft-gandhi-ippm-stamp-ber.

[![CI](https://github.com/asmie/stamp-suite/actions/workflows/rust.yml/badge.svg)](https://github.com/asmie/stamp-suite/actions/workflows/rust.yml)
[![Dependency status](https://deps.rs/repo/github/asmie/stamp-suite/status.svg)](https://deps.rs/repo/github/asmie/stamp-suite)
[![License](https://img.shields.io/crates/l/stamp-suite.svg)](https://opensource.org/licenses/MIT)
[![Latest version](https://img.shields.io/crates/v/stamp-suite.svg)](https://crates.io/crates/stamp-suite)

## About

A single binary that runs as either a Session-Sender (client) or a Session-Reflector (server) for measuring round-trip time and packet loss. Reflector send/receive timestamps are exposed in the per-packet output, so external tooling with synchronized clocks can derive one-way delay; the tool itself does not currently aggregate OWD statistics.

### Key features

- Full RFC 8762 compliance — open and authenticated modes
- RFC 8972 TLV extensions, RFC 9503 (Segment Routing), RFC 9534 (LAG micro-sessions)
- HMAC packet authentication and TLV integrity
- Stateful reflector mode with per-client session tracking
- NTP and PTP timestamp formats; real TTL/Hop Limit capture on all platforms
- Optional Prometheus metrics endpoint and SNMP AgentX sub-agent (Unix)
- Backward compatible with non-TLV implementations
- Cross-platform (Linux, macOS, Windows), async I/O via Tokio

### How STAMP works

The Session-Sender transmits test packets to the Session-Reflector, which timestamps and reflects them back. Comparing timestamps yields:

- Round-trip time (RTT) — aggregated min/max/avg/median/p95/p99 over the run
- Packet loss rate
- Per-packet reflector receive/send timestamps in `-R` mode — usable for external one-way-delay analysis when both endpoints share an NTP/PTP-synced clock

## Installation

### From a release (DEB / RPM)

Pre-built `.deb` and `.rpm` packages for x86_64 and aarch64 are attached to each tagged release on [GitHub Releases](https://github.com/asmie/stamp-suite/releases). The packages install to `/usr/bin/stamp-suite`, ship a hardened systemd unit, and create a dedicated `stamp` system user.

```bash
# Debian / Ubuntu (filename embeds the version, e.g. stamp-suite_0.7.0-1_amd64.deb)
sudo apt install ./stamp-suite_*_amd64.deb

# Fedora / RHEL
sudo dnf install ./stamp-suite-*.x86_64.rpm

# Start the reflector
sudo systemctl enable --now stamp-suite
```

The packaged unit starts an **open-mode** reflector by default (`ExecStart=/usr/bin/stamp-suite --is-reflector`). Before exposing UDP/862 to the internet or any untrusted network, switch to authenticated mode — see [doc/security.md#enabling-authenticated-mode-on-the-packaged-unit](doc/security.md#enabling-authenticated-mode-on-the-packaged-unit).

### From source (Cargo)

```bash
cargo build --release
# or
cargo install --path .
```

### Using Nix

```bash
nix build
nix run . -- --is-reflector
nix develop      # dev shell with cargo, rustc, rustfmt, clippy
```

### Platform support

| Platform | Default backend | TTL capture |
|----------|-----------------|-------------|
| Linux    | nix (`IP_RECVTTL`) | Real TTL, no special privileges |
| macOS    | nix (`IP_RECVTTL`) | Real TTL, no special privileges |
| Windows  | pnet (raw packets) | Real TTL, requires Npcap |

### Feature flags

| Feature | Description |
|---------|-------------|
| `ttl-nix` | Force the nix backend (Linux/macOS/BSD) |
| `ttl-pnet` | Force the pnet raw-socket backend (requires `CAP_NET_RAW`) |
| `metrics` | Enable Prometheus metrics endpoint |
| `snmp` | Enable SNMP AgentX sub-agent (Unix only) |

The receiver backend choice is consequential — privileges, runtime deps, kernel filtering, observability all differ. See [doc/architecture.md#receiver-backends](doc/architecture.md#receiver-backends) for the full comparison.

## Usage

### Reflector

```bash
# Listen on all interfaces, default port 862
stamp-suite -i

# Bind a specific address/port; print per-packet stats
stamp-suite -i --local-addr 192.168.1.100 --local-port 8620 -R

# Stateful reflector with per-client sequence tracking (RFC 8972 §4)
stamp-suite -i --stateful-reflector --session-timeout 600
```

### Sender

```bash
# Send 1000 packets to a remote reflector (defaults: 1 packet/sec)
stamp-suite --remote-addr 192.168.1.100

# Custom count and rate
stamp-suite --remote-addr 192.168.1.100 --count 100 --send-delay 100 -R

# With multiple TLV extensions
stamp-suite --remote-addr 192.168.1.100 \
    --cos --dscp 46 \
    --direct-measurement \
    --location \
    --timestamp-info
```

For the full TLV menu and CLI flag reference, see [doc/usage.md](doc/usage.md).

### Configuration file

Any CLI option can be supplied via a TOML file passed with `--config <PATH>`. Values in the file are defaults; CLI flags and the `STAMP_HMAC_KEY` environment variable still override them. Note: `STAMP_HMAC_KEY` (which fills `--hmac-key`) and a `hmac_key_file` line in the TOML file are mutually exclusive — supplying both is rejected by validation. Pick one source for the key.

```toml
# /etc/stamp/reflector.toml
is_reflector       = true
local_addr         = "192.0.2.10"
auth_mode          = "O"           # "A" for authenticated
clock_source       = "NTP"
stateful_reflector = true
hmac_key_file      = "/etc/stamp/hmac.key"
```

```bash
stamp-suite --config /etc/stamp/reflector.toml
```

The plaintext `hmac_key` field is **deliberately rejected** in the config file — pass the raw key via `--hmac-key`, the `STAMP_HMAC_KEY` environment variable, or `--hmac-key-file <PATH>`. Set `chmod 600` on both the config file and the key file. See [doc/security.md](doc/security.md) for the full key-management story.

For the complete list of supported keys, validation behavior, and error message examples, see [doc/usage.md#configuration-file](doc/usage.md#configuration-file).

### Example output

Sender with per-packet statistics (`-R`):

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

## Documentation

- **[doc/usage.md](doc/usage.md)** — configuration file format, supported TOML keys, validation messages, full CLI flag reference.
- **[doc/architecture.md](doc/architecture.md)** — module layout, receiver backends, packet processing pipeline, full TLV reference, Prometheus and SNMP subsystems.
- **[doc/security.md](doc/security.md)** — threat model, HMAC and TLV integrity, key sourcing, file permissions, the `stamp` system user, systemd hardening, capability model, vulnerability reporting.

## Status

The project is functional for STAMP measurements. Full RFC 8762 / 8972 / 9503 / 9534 support, HMAC authentication on both base packets and TLVs, stateful reflector mode, real TTL capture, optional Prometheus + SNMP. Backward compatible with non-TLV peers. See [doc/architecture.md](doc/architecture.md) for the per-TLV implementation status table.

### Roadmap

- [ ] Enhanced statistics and reporting

## Contributing

Pull requests are welcome. For major changes, please open an issue first.

Before submitting:

- `cargo fmt --all` — formatting
- `cargo clippy --all --all-features --tests -- -D warnings` — linting (CI is strict)
- `cargo test --all-features` — tests

## Versioning

Semantic versioning ([SemVer](http://semver.org/)). See [tags](https://github.com/asmie/stamp-suite/tags) for releases.

## Authors

* **Piotr Olszewski** — [asmie](https://github.com/asmie)

See the list of [contributors](https://github.com/asmie/stamp-suite/contributors).

## License

MIT — see [LICENSE](LICENSE).

## References

- [RFC 8762 — Simple Two-Way Active Measurement Protocol](https://datatracker.ietf.org/doc/html/rfc8762)
- [RFC 8972 — Optional Extensions](https://datatracker.ietf.org/doc/html/rfc8972)
- [RFC 9503 — Extensions for Segment Routing Networks](https://datatracker.ietf.org/doc/html/rfc9503)
- [RFC 9534 — Extensions for Performance Measurement on a Link Aggregation Group](https://datatracker.ietf.org/doc/html/rfc9534)
- [draft-ietf-ippm-asymmetrical-pkts-14](https://datatracker.ietf.org/doc/draft-ietf-ippm-asymmetrical-pkts/) — Asymmetrical Traffic (IETF IPPM WG, RFC Editor queue)
- [draft-ietf-ippm-stamp-ext-hdr-07](https://datatracker.ietf.org/doc/draft-ietf-ippm-stamp-ext-hdr/) — Reflected IP header / IPv6 extension headers, basis for TLV Types 246/247 (IETF IPPM WG, active)
- [draft-gandhi-ippm-stamp-ber-05](https://datatracker.ietf.org/doc/draft-gandhi-ippm-stamp-ber/) — Residual Bit Error Rate Measurement (individual draft)
