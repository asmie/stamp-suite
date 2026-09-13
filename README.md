# stamp-suite

A Rust sender and reflector for the Simple Two-Way Active Measurement Protocol
(STAMP). Measures round-trip time, packet loss, one-way delay, and residual bit
errors in delivered test packets.

[![CI](https://github.com/asmie/stamp-suite/actions/workflows/rust.yml/badge.svg)](https://github.com/asmie/stamp-suite/actions/workflows/rust.yml)
[![Latest version](https://img.shields.io/crates/v/stamp-suite.svg)](https://crates.io/crates/stamp-suite)
[![License](https://img.shields.io/crates/l/stamp-suite.svg)](LICENSE)

## Quick start

Run a reflector on a trusted network:

```sh
stamp-suite --is-reflector
```

Send 100 probes, 100 ms apart:

```sh
stamp-suite --remote-addr 192.0.2.20 --count 100 --send-delay 100 -R
```

The reflector listens on UDP/862 by default. Senders use randomized dynamic
source ports. Both endpoints send with TTL/Hop Limit 255.

Open mode accepts unsigned traffic. For untrusted networks, restrict access
and configure [authenticated mode](doc/security.md#enabling-authenticated-mode-on-the-packaged-unit).

## Measurements and protocol support

- RTT and probe loss, with cumulative statistics and bounded-memory quantiles.
- Signed forward/reverse one-way delay. This requires synchronized clocks on
  compatible timescales; NTP and truncated PTP wire encodings can differ between
  endpoints. See [clock settings](doc/usage.md#timestamp--clock).
- RFC 8762 base packets and HMAC authentication; RFC 8972 optional TLVs.
- RFC 9503 return-path controls, including optional Linux SRv6 forwarding.
- RFC 9534 numeric Micro-session IDs. Physical LAG member selection is unsupported.
- Draft extensions for asymmetric replies, header reflection, CoS/ECN response,
  and residual BER. Experimental codepoints require peer agreement.
- Text, JSON lines, and CSV output; optional Prometheus, AgentX, and control API.

See the [conformance matrices](doc/conformance/README.md) for supported profiles
and gaps, and [measurement semantics](doc/measurements.md) for burst-copy,
directional-loss, and clock-quality limits.

## Installation

### Release packages

DEB and RPM packages for x86_64 and aarch64 are published with
[GitHub releases](https://github.com/asmie/stamp-suite/releases).
They install `/usr/bin/stamp-suite`, the man page, a systemd service, and the
`stamp` service account.

```sh
sudo apt install ./stamp-suite_*_amd64.deb  # Debian/Ubuntu
sudo dnf install ./stamp-suite-*.x86_64.rpm # Fedora/RHEL
sudo systemctl enable --now stamp-suite
```

The packaged service starts in open mode. Configure authentication before
exposing it to an untrusted network.

### Source

```sh
cargo build --release
# Or install into Cargo's binary directory:
cargo install --path .
```

Rust 1.85 or newer is required. Build optional features with, for example,
`cargo build --release --features metrics,control,hwtstamp`.

### Nix and Gentoo

```sh
nix build
nix run . -- --is-reflector
nix develop
```

The [Gentoo overlay](dist/gentoo/README.md) includes service-account packages,
systemd/OpenRC integration, and Cargo feature mappings.

### Platforms and features

| Platform | Default receiver | Requirements |
| --- | --- | --- |
| Linux | nix UDP socket | No raw-socket privilege; low ports may need bind permission |
| macOS | nix UDP socket | No raw-socket privilege |
| Windows | pnet capture | Npcap; capture tests require a driver-backed environment |

Both backends capture received TTL/Hop Limit. See
[backend limits](doc/architecture.md#receiver-backends).

| Cargo feature | Purpose |
| --- | --- |
| `ttl-nix` | Select the nix receiver |
| `ttl-pnet` | Select raw packet capture; Linux requires `CAP_NET_RAW` |
| `metrics` | Prometheus HTTP endpoint |
| `control` | Reflector session/key/limit API with optional HTTPS |
| `snmp` | Read-only AgentX sub-agent, Unix only |
| `hwtstamp` | Kernel timestamps and optional Linux NIC hardware timestamps |

## Configuration

Use `--config PATH` for TOML settings. Explicit CLI values override file values.
`STAMP_HMAC_KEY` supplies the CLI key field; it conflicts with a configured key
file or directory. Plaintext `hmac_key` is not a TOML field.

```toml
is_reflector = true
local_addr = "192.0.2.20"
auth_mode = "A"
hmac_key_file = "/etc/stamp/hmac.key"
verify_tlv_hmac = true
stateful_reflector = true
session_timeout = 300
```

Protect key files with owner-only permissions. See [key setup](doc/security.md)
and the [configuration reference](doc/usage.md#configuration-file).

Sessions are separated by both UDP endpoints, SSID, and optional sender
Micro-session ID. The default `permissive` policy learns sessions from traffic.
For RFC 8972 provisioned admission:

```sh
stamp-suite -i --local-addr 192.0.2.20 --session-admission provisioned \
  --reflector-session '42,192.0.2.10:4862,192.0.2.20:862'
```

See [session provisioning](doc/usage.md#session-provisioning) and
[IPv6 interface zones](doc/usage.md#link-local-ipv6-interface-zones).

## Examples

Request CoS and reflector metadata:

```sh
stamp-suite --remote-addr 192.0.2.20 --cos --dscp 46 \
  --direct-measurement --location --timestamp-info
```

Record measurements separately from diagnostics:

```sh
stamp-suite --remote-addr 192.0.2.20 --output-format json \
  > measurements.jsonl 2> diagnostics.log
```

Measure residual BER with one-second windows:

```sh
stamp-suite --remote-addr 192.0.2.20 --ber --ber-pattern ff00 \
  --ber-padding-size 128 --send-delay 100 --ber-interval 10
```

BER measures delivered padding, not raw link errors. Use `--ber-omit-burst` if
Type 242 means Heartbeat to the peer. See [BER limits](doc/architecture.md#bit-error-rate-tlvs-draft-gandhi-ippm-stamp-ber).

With the `control` feature, `--control` enables a reflector API at
`127.0.0.1:9091`. It manages keys, sessions, limits, drain, and shutdown. Set a
bearer token on shared hosts; use HTTPS or a secure tunnel for remote access.
See the [API reference](doc/control-plane.md).

## Documentation

- [Usage](doc/usage.md): configuration, options, and migration notes.
- [Architecture](doc/architecture.md): packet processing, backends, and TLVs.
- [Measurements](doc/measurements.md) and [statistics](doc/statistics.md): definitions and retention.
- [Security](doc/security.md) and [vulnerability reporting](SECURITY.md).
- [Benchmarks](doc/benchmarks.md): reproducible throughput and CPU measurements.
- [Release verification](doc/release-evidence.md): platform and integration gates.
- [Conformance](doc/conformance/README.md): protocol sources, evidence, and exclusions.

## Versioning

The 1.x compatibility contract covers CLI behavior, TOML schema, and default wire
behavior. The internal Rust library API is unsupported and may change in any
release. Experimental codepoint renumbering and MSRV increases may occur in minor
releases and are recorded in [CHANGELOG.md](CHANGELOG.md).

## Contributing

Open an issue before a major change. Before submitting, run:

```sh
cargo fmt --all
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-features
```

[Independent wire fixtures](doc/testing-interop.md) run separately from Cargo
and are required by conformance CI.

## Authors and license

Maintained by [Piotr Olszewski](https://github.com/asmie), with
[contributors](https://github.com/asmie/stamp-suite/contributors).
Licensed under [MIT](LICENSE).
