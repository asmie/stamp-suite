# Privileged network-namespace conformance tests

Run Linux namespace tests and inspect their wire evidence.

`tests/netns_conformance.rs` starts real reflectors and senders in Linux
network namespaces joined by veth links and records the traffic with tcpdump.
It covers CoS marking, TTL/Hop Limit, SRv6, header reflection, Address Groups,
BER and Type 12 bursts. Most scenarios use two namespaces; the SRv6 scenario
adds a third as a transit router. Every scenario is `#[ignore]`d, so ordinary
Cargo runs skip them. Other tests that need namespaces or capabilities are
listed in [tests/README.md](../tests/README.md#tests-that-need-privileges-or-namespaces).

## Running

Set `STAMP_REQUIRE_PRIVILEGED=1` whenever the results count as conformance or
CI evidence. Every call to the harness's skip path then fails, including a
missing tool, SRv6 not available, a capture timeout and a missing pnet binary.
Without it the scenarios are optional local probes: a printed `SKIP` followed by
Cargo's `ok` does not mean the scenario ran.

Build without root, then run the selected test executable with namespace
privileges. Build the pnet reflector first (see
[Building the pnet reflector for scenario 4b](#building-the-pnet-reflector-for-scenario-4b)).

```sh
cargo test --locked --test netns_conformance --no-run --message-format=json > /tmp/netns-artifacts.json
python3 scripts/run_privileged_test.py /tmp/netns-artifacts.json netns_conformance 9 \
  sudo env STAMP_NETNS_TESTS=1 STAMP_NETNS_PNET_BIN="$PWD/target/pnet/debug/stamp-suite"
```

`scripts/run_privileged_test.py` selects exactly one test executable from the
Cargo JSON, checks that it lists the expected number of ignored tests (9 here),
sets `STAMP_REQUIRE_PRIVILEGED=1` after the prefix command, and runs serially
with output shown. The count check stops a build with the wrong features from
passing with an empty suite. Effective root can be host root or mapped root
with the capabilities the namespace operations need.

The `privileged` job in `.github/workflows/conformance.yml` runs this tier, the
three raw pnet tests and the route MTU test this way, inside private mount and
network namespaces.

### Running without sudo (user namespaces)

When `sudo` is unavailable but unprivileged user namespaces work
(`unshare -Urn true` succeeds), run the tier as mapped root. `ip netns` needs a
writable `/run/netns`, so mount a tmpfs over `/run` inside the namespace first:

```bash
unshare -Urnm bash -ec '
  mount --make-rprivate /
  mount -t tmpfs none /run
  mkdir -p /run/netns
  ip link set lo up
  sysctl -w net.ipv6.conf.all.seg6_enabled=1
  export STAMP_REQUIRE_PRIVILEGED=1 STAMP_NETNS_TESTS=1
  cargo test --locked --offline --test netns_conformance -- --ignored --test-threads=1 --nocapture
'
```

Inside this namespace the effective UID is 0, so the root check passes, and
the process holds `CAP_NET_ADMIN` and `CAP_NET_RAW` for the namespace's own
resources. Missing kernel features still fail in required mode or skip in
optional mode. Set `STAMP_NETNS_PNET_BIN` as well to run scenario 4b.

## Prerequisites

Every scenario needs the following. A missing item fails in required mode and
skips otherwise.

| Requirement | Why |
| --- | --- |
| `STAMP_NETNS_TESTS=1` | Explicit opt-in |
| Effective root with namespace and network capabilities | Create namespaces and veth links, bind, capture |
| `ip` (iproute2) | Namespace, veth and address setup |
| `tcpdump` | Wire capture |
| `ethtool` | Turn off TX checksum offload on the private veth devices |
| `ss` (iproute2), recommended | Reflector readiness check; without it the fixture waits a fixed time |

Extra prerequisites per scenario:

| Scenario | Extra prerequisite |
| --- | --- |
| 3, SRv6 return path | `net.ipv6.conf.all.seg6_enabled` not 0 (kernel SRv6 support) |
| 4b, pnet header capture | `STAMP_NETNS_PNET_BIN` set to a reflector built with `ttl-pnet` |

Set `STAMP_NETNS_CAPTURE_DIR` to a directory to keep each completed pcap (see
[Retaining successful SRv6 evidence](#retaining-successful-srv6-evidence)).

## What each scenario evidences

| # | Test | Evidence |
| --- | --- | --- |
| 1 | `scenario_1_roundtrip_unauth_and_auth` | RFC 8762 §4.2 to §4.5 sender and reflector round trip on a real link, unauthenticated and HMAC-authenticated. |
| 2 | `scenario_2_cos_dscp_ecn_onwire` | RFC 8972 §4.4 CoS with erratum 8199 and draft-ietf-ippm-stamp-cos-ecn-01 §3.2: the reply carries DSCP=DSCP1, ECN=EC1 and RPE=0b11 on the wire. |
| 3 | `scenario_3_srv6_return_path` | RFC 9503 §4 and RFC 8754 through a transit router: requires real SRH forwarding (a fallback fails). Covers SID-only and explicit final-SID requests, open and authenticated modes, independent HMACs, CoS, Segments Left 1 to 0 and Hop Limit 255 to 254. Ordinary replies interleaved on the same reflector must carry no SRH. |
| 4a | `scenario_4a_ext_hdr_nix_ancillary` | draft-ietf-ippm-stamp-ext-hdr-15 §4.2: the nix backend reads the sender's Destination Options header from ancillary data and returns it in the Type 246 value with C clear (checked from offset 8). |
| 4b | `scenario_4b_ext_hdr_pnet_capture` | draft-ietf-ippm-stamp-ext-hdr-15 §4.1 and §4.2: the pnet backend captures an injected 16-byte Destination Options header and returns it in the Type 246 value with C clear (checked from offset 8). |
| 5 | `scenario_5_address_group_filters` | RFC 10052 §3.1.1 and §3.1.2: a matching L2 (own MAC) or L3 (own prefix) Address Group gets a reply; a non-matching one drops the packet. |
| 6 | `scenario_6_type12_multi_reply` | RFC 10052 §3: several reply copies on the wire, within the requested and capped count, spaced about the requested interval, padded beyond the base length. |
| 7 | `scenario_7_ber_onwire` | draft-gandhi-ippm-stamp-ber-07 §4: the bit pattern (0xFF00) fills the Extra Padding TLV on the wire, and the reflector's Bit Error Count is 0 on a clean link. |
| 8 | `scenario_8_ttl_egress_marking` | draft-ietf-ippm-stamp-ext-hdr-15 §3.1: outgoing test packets carry IP TTL 255. |

## Building the pnet reflector for scenario 4b

Scenario 4a covers the nix backend, which reads IPv6 extension headers from
ancillary data. Scenario 4b covers the pnet backend, which captures the whole
IP packet, so it needs a reflector built with `ttl-pnet`:

```bash
cargo build --locked --no-default-features --features ttl-pnet --target-dir target/pnet
export STAMP_NETNS_PNET_BIN="$PWD/target/pnet/debug/stamp-suite"
```

Keep this binary in its own target directory (or copy it) so a later nix build
does not overwrite it. Without `STAMP_NETNS_PNET_BIN`, 4b fails in required mode
and skips otherwise. The scenario injects the Destination Options header
through a sticky `IPV6_DSTOPTS` socket option; if the kernel or namespace
refuses the option, it fails in required mode and skips otherwise.

The private veth devices have TX checksum offload turned off with `ethtool`, so
raw capture sees complete UDP checksums. No host NIC settings change.

## Troubleshooting

- **`tcpdump: Couldn't change ownership of savefile`**: the harness passes
  `-Z root` so tcpdump does not drop privileges and chown the file, which fails
  under mapped root. Add `-Z root` when you run tcpdump yourself.
- **Scenario 3 always skips**: the kernel has SRv6 disabled
  (`sysctl net.ipv6.conf.all.seg6_enabled`), which is common on WSL2. Enable it
  with `sysctl -w net.ipv6.conf.all.seg6_enabled=1` on a kernel with `seg6`, or
  run on a host with SRv6.
- **A scenario fails rather than skips**: read the assertion and the captured
  traffic. Rule out a failed prerequisite, timeout or byte mismatch in the setup
  before attributing it to the implementation.
- **Namespaces left over after a hard kill** (`SIGKILL` skips cleanup): list
  them with `ip netns list` and remove `stnsr*` and `stnss*` with
  `ip netns del <name>`.
- **`no packets captured`**: fails in required mode. The fixture waits for
  tcpdump's readiness notice, checks its exit status and keeps its startup
  output. It captures immediately with an IP/IPv6 filter, so a plain UDP filter
  cannot hide extension-header traffic. Check interface state and traffic.
- **SRv6 fallback**: a U-flag fallback fails scenario 3, which requires SRH
  traffic captured through the transit router.

## Reply-route MTU regression

`tests/route_mtu_test.rs` is a separate ignored test. It needs `ip`, `unshare`
and `nsenter`, but not tcpdump or host root. Run it in a user and network
namespace (Linux with unprivileged user namespaces):

```sh
STAMP_MTU_NETNS_TESTS=1 unshare -Urn \
  cargo test --locked --test route_mtu_test -- --ignored --nocapture
```

Without `STAMP_MTU_NETNS_TESTS=1` the test fails rather than skips. It starts
a reflector in a second network namespace, connects it with a
temporary veth pair, and sends independently built UDP requests. It covers
IPv4 and IPv6, open and authenticated replies, wildcard and bound reflectors,
interface MTU decreases and increases, route MTU metrics, and alternate
destinations. It checks payload lengths, a single C-flagged reply, and the final
base and TLV HMACs. Cleanup removes the veth and child processes even after an
assertion failure. These are real UDP and kernel route tests, not packet
captures or SRv6 transit tests. Report the result of this separate run; an
ignored test in an ordinary run is not a pass.

### Retaining successful SRv6 evidence

Set `STAMP_NETNS_CAPTURE_DIR` to a directory to keep each completed pcap. CI
uploads these pcaps and `netns.log` with the Cargo executable manifests.
Scenario 3 captures both sides of a real transit router: 12 SRH replies and 12
interleaved ordinary replies across open and authenticated modes. Keep the test
log, executable manifest, commit, build features and capture hashes with the
pcaps. These tests verify virtual Linux routing, not a physical SRv6 fabric.
