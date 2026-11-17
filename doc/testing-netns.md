# Privileged network-namespace conformance tests

How to run the Linux network-namespace tests and check what they captured on
the wire.

`tests/netns_conformance.rs` starts real reflectors and senders in Linux
network namespaces joined by veth links, and records the traffic with tcpdump.
It covers CoS marking, TTL/Hop Limit, SRv6, header reflection, Address Groups,
BER and Type 12 bursts. Most scenarios use two namespaces. The SRv6 scenario
adds a third one as a transit router. Every scenario is `#[ignore]`d, so
ordinary Cargo runs skip them. Other tests that need namespaces or capabilities
are listed in [tests/README.md](../tests/README.md#tests-that-need-privileges-or-namespaces).

## Running

Set `STAMP_REQUIRE_PRIVILEGED=1` whenever the results count as conformance or
CI evidence. With it set, every place where the harness would skip fails
instead: a missing tool, SRv6 not available, a capture timeout, a missing pnet
binary. Without it the scenarios are optional local probes, and a printed
`SKIP` followed by Cargo's `ok` does not mean the scenario ran.

Build as a normal user, then run the selected test executable with namespace
privileges. Build the pnet reflector first (see
[Building the pnet reflector for scenario 4b](#building-the-pnet-reflector-for-scenario-4b)).

```sh
cargo test --locked --test netns_conformance --no-run --message-format=json > /tmp/netns-artifacts.json
python3 scripts/run_privileged_test.py /tmp/netns-artifacts.json netns_conformance 9 \
  sudo env STAMP_NETNS_TESTS=1 STAMP_NETNS_PNET_BIN="$PWD/target/pnet/debug/stamp-suite"
```

`scripts/run_privileged_test.py` picks exactly one test executable from the
Cargo JSON and checks that it lists the expected number of ignored tests (9
here). It sets `STAMP_REQUIRE_PRIVILEGED=1` after the prefix command and runs
the tests serially with their output shown. The count check stops a build with
the wrong features from passing with an empty suite. Effective root can be
real host root, or a mapped root that has the capabilities the namespace
operations need.

The `privileged` job in `.github/workflows/conformance.yml` runs this tier, the
three raw pnet tests and the two route MTU tests this way, inside private mount
and network namespaces.

### Running without sudo (user namespaces)

If `sudo` is not available but unprivileged user namespaces work
(`unshare -Urn true` succeeds), run the tier as mapped root. `ip netns` needs a
writable `/run/netns`, so first mount a tmpfs over `/run` inside the namespace:

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
the process has `CAP_NET_ADMIN` and `CAP_NET_RAW` over the namespace's own
resources. Missing kernel features still fail in required mode and skip in
optional mode. Also set `STAMP_NETNS_PNET_BIN` to run scenario 4b.

## Prerequisites

Every scenario needs the following. A missing item fails in required mode and
skips otherwise.

| Requirement | Why |
| --- | --- |
| `STAMP_NETNS_TESTS=1` | Opt-in switch |
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
| 2 | `scenario_2_cos_dscp_ecn_onwire` | RFC 8972 §4.4 CoS with erratum 8199 and draft-ietf-bpm-stamp-cos-ecn-00 §3.2: the reply carries DSCP=DSCP1, ECN=EC1 and RPE=0b11 on the wire. |
| 3 | `scenario_3_srv6_return_path` | RFC 9503 §4 and RFC 8754 through a transit router. Real SRH forwarding is required; a fallback fails the test. Covers SID-only and explicit final-SID requests, open and authenticated modes, HMACs computed by the test itself, CoS, Segments Left 1 to 0 and Hop Limit 255 to 254. Ordinary replies interleaved on the same reflector must carry no SRH. |
| 4a | `scenario_4a_ext_hdr_nix_ancillary` | draft-ietf-ippm-stamp-ext-hdr-26 §4.2: the nix backend reads the sender's Destination Options header from ancillary data and returns it in the Type 246 value with C clear (checked from offset 8). |
| 4b | `scenario_4b_ext_hdr_pnet_capture` | draft-ietf-ippm-stamp-ext-hdr-26 §4.1 and §4.2: the pnet backend captures an injected 16-byte Destination Options header and returns it in the Type 246 value with C clear (checked from offset 8). |
| 5 | `scenario_5_address_group_filters` | RFC 10052 §3.1.1 and §3.1.2: a matching L2 (own MAC) or L3 (own prefix) Address Group gets a reply; a non-matching one drops the packet. |
| 6 | `scenario_6_type12_multi_reply` | RFC 10052 §3: several reply copies on the wire, within the requested and capped count, spaced about the requested interval, padded beyond the base length. |
| 7 | `scenario_7_ber_onwire` | draft-ietf-bpm-stamp-ber-01 §5: the bit pattern (0xFF00FF00) fills the Extra Padding TLV on the wire, and the reflector's Bit Error Count is 0 on a clean link. |
| 8 | `scenario_8_ttl_egress_marking` | draft-ietf-ippm-stamp-ext-hdr-26 §3.1: outgoing test packets carry IP TTL 255. |

## Building the pnet reflector for scenario 4b

Scenario 4a covers the nix backend, which reads IPv6 extension headers from
ancillary data. Scenario 4b covers the pnet backend, which captures the whole
IP packet, so it needs a reflector built with `ttl-pnet`:

```bash
cargo build --locked --no-default-features --features ttl-pnet --target-dir target/pnet
export STAMP_NETNS_PNET_BIN="$PWD/target/pnet/debug/stamp-suite"
```

Keep this binary in its own target directory (or copy it somewhere) so that a
later nix build does not overwrite it. Without `STAMP_NETNS_PNET_BIN`, 4b fails
in required mode and skips otherwise. The scenario injects the Destination
Options header through a sticky `IPV6_DSTOPTS` socket option. If the kernel or
the namespace refuses the option, the scenario fails in required mode and skips
otherwise.

The test turns off TX checksum offload on the private veth devices with
`ethtool`, so raw capture sees complete UDP checksums. Host NIC settings are
not touched.

## Troubleshooting

- **`tcpdump: Couldn't change ownership of savefile`**: the harness passes
  `-Z root` so that tcpdump does not drop privileges and chown the file, which
  fails under mapped root. Add `-Z root` when you run tcpdump yourself.
- **Scenario 3 always skips**: the kernel has SRv6 disabled
  (`sysctl net.ipv6.conf.all.seg6_enabled`). This is common on WSL2. Enable it
  with `sysctl -w net.ipv6.conf.all.seg6_enabled=1` on a kernel with `seg6`, or
  run on a host with SRv6.
- **A scenario fails instead of skipping**: read the assertion and the captured
  traffic. Rule out a failed prerequisite, a timeout or a byte mismatch in the
  setup before you blame the implementation.
- **Namespaces left over after a hard kill** (`SIGKILL` skips cleanup): list
  them with `ip netns list` and remove the `stnsr*` and `stnss*` ones with
  `ip netns del <name>`.
- **`no packets captured`**: this fails in required mode. The fixture waits for
  tcpdump to say it is ready, checks its exit status and keeps its startup
  output. It starts capturing right away with an IP/IPv6 filter, so a plain UDP
  filter cannot hide traffic with extension headers. Check the interface state
  and whether any traffic flowed.
- **SRv6 fallback**: a U-flag fallback fails scenario 3, which requires SRH
  traffic captured through the transit router.

## Reply-route MTU regression

`tests/route_mtu_test.rs` contains two separate ignored tests. They need `ip`,
`unshare` and `nsenter`, but not tcpdump or host root. Run them in a user and
network namespace (Linux with unprivileged user namespaces):

```sh
STAMP_MTU_NETNS_TESTS=1 unshare -Urn \
  cargo test --locked --test route_mtu_test -- --ignored --nocapture --test-threads=1
```

Without `STAMP_MTU_NETNS_TESTS=1` the tests fail instead of skipping.

The reflector test starts a reflector in a second network namespace, connects
it with a temporary veth pair, and sends UDP requests that the test builds
itself. It covers IPv4 and IPv6, open and authenticated replies, wildcard and
bound reflectors, interface MTU decreases and increases, route MTU metrics,
and alternate destinations. It checks payload lengths, that exactly one reply
has the C flag, and the final base and TLV HMACs. Requests without Type 12 also
exercise two kinds of single reply. BER replies get their padding trimmed in
whole patterns and their metadata marked with C. Header replies get the
optional Types 246/247 removed while the mandatory padding stays intact. The
single header requests have no captured headers, so they are answered with C
before MTU fitting. The transmit unit tests cover successful header data and
the paths where the send is refused or returns EMSGSIZE. Cleanup removes the
veth and the child processes even after an assertion fails. These tests use
real UDP and real kernel routes. They are not packet captures or SRv6 transit
tests. Report the result of this separate run. An ignored test in an ordinary
run is not a pass.

The sender test runs the public sender loop against a UDP peer written in the
test. After each successful send and before the next probe, an observer
changes the MTU of the isolated loopback synchronously, so there are no timer
races. It covers IPv4 and IPv6 in the open, keyed open (HMAC origination on and
off) and authenticated modes. It checks exact size budgets, that Types 246/247
are removed and restored in order, that mandatory padding is kept, the dynamic
Direct Measurement and Type 12 fields, and the final base and TLV signatures.
The IPv6 cases attach a real default Hop-by-Hop header and count it in the full
packet budget. Extra IPv4 cases remove every request at startup and check that
requests come back when the MTU increases. Mandatory fields that are one byte
over budget are refused at startup and after a route decrease, and no oversized
datagram arrives. Run the target serially, because both tests change their
namespace's network state. CI requires exactly two ignored tests. This is
evidence about kernel routes and software loopback. It is not a packet capture
and not a guarantee for a physical link.

### Retaining successful SRv6 evidence

Set `STAMP_NETNS_CAPTURE_DIR` to a directory to keep each completed pcap. CI
uploads these pcaps and `netns.log` along with the Cargo executable manifests.
Scenario 3 captures both sides of a real transit router: 12 SRH replies and 12
ordinary replies interleaved with them, across open and authenticated modes.
Keep the test log, the executable manifest, the commit, the build features and
the capture hashes with the pcaps. These tests check virtual Linux routing, not
a physical SRv6 fabric.

## Directional ECN rewrites

`tests/ecn_path_test.rs` checks the sender's per-direction diagnostics against
real kernel ECN rewrites and real reflector processing. It runs in one private
network namespace over loopback. Separate nftables output rules match the
reflector's assigned UDP port, and each rule changes only the two ECN bits.
That DSCP stays unchanged is checked separately. The fixture does not fabricate
or alter either endpoint's packet payload.

Build as a normal user, then enter a fresh user and network namespace. Install
`iproute2`, `nftables` and `util-linux`. The kernel must support nftables ECN
rewriting and packet sockets, and this form of the command needs user
namespaces to be allowed:

```sh
cargo test --locked --test ecn_path_test --no-run --message-format=json > /tmp/ecn-artifacts.json
python3 scripts/run_privileged_test.py /tmp/ecn-artifacts.json ecn_path_test 1 \
  unshare -Urn env STAMP_PARENT_NETNS="$(readlink /proc/self/ns/net)" \
  STAMP_ECN_NETNS_TESTS=1 STAMP_ECN_CAPTURE_DIR="$PWD/ecn-captures" TOKIO_WORKER_THREADS=2
```

You can also use `sudo -n unshare --net --fork env ...` with the same
variables. The parent namespace is recorded before entering the new one, and
the fixture refuses to run in that parent namespace. All rules and sockets
belong to the fresh namespace. Builds with `--all-features` select nix and use
the same command. Builds with only pnet do not contain this fixture. The runner
requires exactly one ignored test.

The 72-case matrix covers 12 scenarios in both IP families and three key modes
(open, keyed open and authenticated). Each case sends only three probes, to
keep the traffic small. A separate AF_PACKET socket captures both directions.
The test validates the IP and CoS fields and the base and TLV signatures, and
compares the sender's actual JSON output with the rewrites seen in the capture.
When a reflector refuses with an RPE=2 policy, the result must stay unknown even
if the reply is later marked CE. AIMD feedback stays enabled, and its CE
observations are checked too.

When `STAMP_ECN_CAPTURE_DIR` is set, each case writes a raw-IP `.pcap` and a
`.json` with the sender report and the nftables counters. CI keeps both
profiles' captures in its privileged-test artifacts. Capture timestamps are the
times userspace dequeued the packets, so they say nothing about latency. A
failed case can leave partial pcaps. Only a successful test run establishes all
assertions. Inspect a capture with `tcpdump -nn -vv -r FILE.pcap` and match it
against its JSON report. This shows controlled Linux kernel rewriting on
loopback. It does not locate a physical hop, and it does not cover multi-host
routing or native Windows/macOS behavior.
