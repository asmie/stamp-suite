# stamp-suite

stamp-suite measures round-trip time, packet loss, one-way delay and residual
bit errors with the Simple Two-Way Active Measurement Protocol (STAMP, RFC 8762
and RFC 8972). It is one binary that runs either as a Session-Sender, which
sends test packets and reports results, or as a Session-Reflector, which
answers them.

[![CI](https://github.com/asmie/stamp-suite/actions/workflows/rust.yml/badge.svg)](https://github.com/asmie/stamp-suite/actions/workflows/rust.yml)
[![Latest version](https://img.shields.io/crates/v/stamp-suite.svg)](https://crates.io/crates/stamp-suite)
[![License](https://img.shields.io/crates/l/stamp-suite.svg)](LICENSE)

New to STAMP? Read the [protocol overview](doc/protocol.md) first.

## Quick start

Start a reflector. It listens on UDP port 862, which on Linux needs root or
`CAP_NET_BIND_SERVICE`:

```sh
sudo stamp-suite --is-reflector
```

From another host, send 100 test packets 100 ms apart and print each result:

```sh
stamp-suite --remote-addr 192.0.2.20 --count 100 --send-delay 100ms -R
```

Without root, run the reflector on a high port and point the sender at it:

```sh
stamp-suite --is-reflector --local-port 8620
stamp-suite --remote-addr 192.0.2.20 --remote-port 8620
```

The sender prints a summary when it finishes or when you press Ctrl-C. A few
more examples:

```sh
# Measure two reflectors at once; each report carries a target label
stamp-suite --remote-addr 192.0.2.20,198.51.100.7 --count 0 --duration 60

# 4000 packets per second, Poisson-spaced, JSON lines on stdout
stamp-suite --remote-addr 192.0.2.20 --send-delay 250us --send-schedule poisson \
  --count 0 --duration 600 --output-format json > results.jsonl
```

The reflector starts in open mode and answers anyone who can reach it. On an
untrusted network, restrict access and turn on
[authenticated mode](doc/security.md#enabling-authenticated-mode-on-the-packaged-unit).

## What it supports

- Round-trip time, loss, and forward and reverse one-way delay. One-way delay
  needs synchronized clocks; see [Timestamps and clocks](doc/usage.md#timestamps-and-clocks).
- Open and authenticated (HMAC) modes, stateless and stateful reflection, and
  RFC 8972 TLVs.
- RFC 9503 return-path control, RFC 9534 Micro-session IDs, and RFC 10052
  reflected test packet control.
- Draft extensions for reflected IP headers, CoS/ECN response and residual bit
  error rate. Their experimental codepoints need agreement with the peer.
- Text, JSON lines and CSV output. Optional Prometheus metrics, SNMP AgentX
  sub-agent and reflector control API.

The [conformance matrices](doc/conformance/README.md) list what is supported
for each RFC and draft, and what is not.

## Installation

### Release packages

Each [GitHub release](https://github.com/asmie/stamp-suite/releases) has DEB
and RPM packages for Linux x86_64 and aarch64, built with all Cargo features.
They install `/usr/bin/stamp-suite`, the man page, the SNMP MIB, a systemd unit
and the `stamp` service account.

```sh
sudo apt install ./stamp-suite_*_amd64.deb    # Debian, Ubuntu
sudo dnf install ./stamp-suite-*.x86_64.rpm   # Fedora, RHEL
sudo systemctl enable --now stamp-suite
```

The packaged service runs a reflector in open mode. Configure authentication
before exposing it to an untrusted network; see [security](doc/security.md).

Releases also include plain binary tarballs for these Linux targets and for
macOS on Apple silicon, a source tarball and a `cargo vendor` tarball.

### From source

Rust 1.85 or newer is required.

```sh
cargo install stamp-suite                       # from crates.io
cargo build --release --features metrics,control,hwtstamp   # from a checkout
```

Building on Windows needs the Npcap SDK; running needs Npcap.

### Nix, Gentoo and OpenWrt

```sh
nix build
nix run . -- --is-reflector
```

The [Gentoo overlay](dist/gentoo/README.md) maps Cargo features to USE flags
and installs systemd and OpenRC services. `dist/openwrt/` holds an OpenWrt
package with a procd init script.

## Platforms and Cargo features

| Platform | Receiver backend | Requirements |
| --- | --- | --- |
| Linux | nix UDP socket | No raw-socket privilege; ports below 1024 need `CAP_NET_BIND_SERVICE` |
| macOS | nix UDP socket | No raw-socket privilege |
| Windows | pnet capture | Npcap |

The backend is chosen at build time. Both backends read the received TTL or Hop
Limit. On Linux the nix backend reflects IPv6 extension headers; reflecting
fixed IP headers needs the pnet backend. See
[Networking](doc/usage.md#networking).

No Cargo feature is on by default.

| Cargo feature | Effect |
| --- | --- |
| `ttl-pnet` | Uses the pnet capture backend on Linux and macOS. On Linux it needs `CAP_NET_RAW` or root. |
| `ttl-nix` | Matters only together with `ttl-pnet`: it keeps the nix backend, as `--all-features` does. Linux and macOS use nix without it. |
| `metrics` | Adds `--metrics`, a Prometheus endpoint at `http://127.0.0.1:9090/metrics` by default. |
| `control` | Adds `--control`, the reflector's HTTP API for keys, sessions, limits, drain and shutdown, with optional HTTPS. |
| `snmp` | Adds `--snmp`, a read-only AgentX sub-agent (Unix only) for `mibs/STAMP-SUITE-MIB.mib`. |
| `hwtstamp` | Uses kernel timestamps (Linux receive and transmit, macOS receive) and, with `--hwtstamp on`, Linux NIC hardware timestamps. |

`--metrics`, `--control` and `--snmp` fail at startup when the binary was built
without the feature.

## Documentation

| Document | Contents |
| --- | --- |
| [Protocol overview](doc/protocol.md) | STAMP concepts, the extensions implemented here, glossary |
| [Usage](doc/usage.md) | Configuration file, sender, reflector, timestamps, networking, observability |
| [Security](doc/security.md) | Threat model, HMAC keys and rotation, service hardening |
| [Control API](doc/control-plane.md) | Reflector HTTP API endpoints |
| [Measurements](doc/measurements.md) | What each reported value means and its limits |
| [Statistics](doc/statistics.md) | Quantile precision and retention |
| [Architecture](doc/architecture.md) | Modules, receiver backends, packet processing, TLV reference |
| [Conformance](doc/conformance/README.md) | Per-clause evidence for each RFC and draft |
| [Benchmarks](doc/benchmarks.md) | Throughput and CPU measurements |
| [Release verification](doc/release-evidence.md) | Platform and integration checks run before a release |
| [Contributing](CONTRIBUTING.md) | Building, testing, linting and submitting changes |
| [Vulnerability reporting](SECURITY.md) | How to report a security problem |
| [Changelog](CHANGELOG.md) | Changes in each release |

The man page (`man stamp-suite`) lists every option. `stamp-suite --help`
prints the same list.

## Versioning

The 1.x compatibility promise covers CLI behavior, the TOML configuration
schema and default wire behavior. The Rust library API is internal and may
change in any release. Minor releases may renumber experimental codepoints or
raise the minimum Rust version; [CHANGELOG.md](CHANGELOG.md) records each such
change.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Open an issue before starting a large
change.

## Authors and license

Maintained by [Piotr Olszewski](https://github.com/asmie), with
[contributors](https://github.com/asmie/stamp-suite/contributors).
Licensed under the [MIT license](LICENSE).
