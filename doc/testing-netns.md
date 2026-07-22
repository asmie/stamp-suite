# Privileged network-namespace conformance tests

`tests/netns_conformance.rs` is a privileged integration-test tier that
exercises the on-wire STAMP behaviours that unit and loopback tests cannot
reach: real IP TOS/ECN bytes, TTL / Hop-Limit marking, IPv6 extension headers,
SRv6 SRH routing, Layer-2 / Layer-3 Address Group filtering, and Type-12
multi-reply pacing/count/length.

Each test spins up a pair of Linux network namespaces joined by a `veth` link,
runs the real `stamp-suite` reflector in one namespace, drives a sender from the
other, and observes the wire with `tcpdump`. It therefore needs privileges and
extra tooling, so **every test is `#[ignore]`d and additionally gated** — a
normal `cargo test` run never touches the network.

## Running

The tier is opted in with the `STAMP_NETNS_TESTS=1` environment variable and
must run as root (or with `CAP_NET_ADMIN`). The canonical invocation:

```bash
sudo -E STAMP_NETNS_TESTS=1 \
    cargo test --test netns_conformance -- --ignored --test-threads=1 --nocapture
```

* `-E` preserves your environment so `STAMP_NETNS_TESTS` and `CARGO_*` survive
  the `sudo`.
* `--ignored` runs the otherwise-skipped tests.
* `--test-threads=1` serialises them. The fixture already uses unique namespace,
  interface, address and port names per test, so parallel runs are safe, but
  serial output is easier to read and lighter on the box.
* `--nocapture` surfaces the `[netns] PASS …` / `[netns] SKIP …` lines.

### Running without a usable `sudo` (rootless via user namespaces)

On a box where `sudo` needs an interactive password (or is unavailable) but
unprivileged user namespaces are enabled (`unshare -Urn` succeeds), you can run
the whole tier as *mapped* root. `ip netns` needs a writable `/run/netns`, so
shadow `/run` with a tmpfs inside the namespace first:

```bash
unshare -Urnm --map-root-user bash -c '
  mount -t tmpfs none /run
  mkdir -p /run/netns
  export STAMP_NETNS_TESTS=1
  cargo test --offline --test netns_conformance -- --ignored --test-threads=1 --nocapture
'
```

Inside this namespace the effective UID is 0 (so the root gate passes) and you
hold `CAP_NET_ADMIN`/`CAP_NET_RAW` for the namespace's own resources. Kernel
features that are globally disabled (e.g. SRv6, see below) still skip.

## Prerequisites

Common (all scenarios), enforced by the gate — missing any of these **skips**
cleanly, it never fails:

| Requirement | Why |
|---|---|
| `STAMP_NETNS_TESTS=1` | explicit opt-in |
| root / `CAP_NET_ADMIN` | create namespaces + veth, bind, capture |
| `ip` (iproute2) | namespace/veth/address setup |
| `tcpdump` | on-wire capture |
| `ss` (iproute2) *(recommended)* | reflector readiness probe (falls back to a timed wait if absent) |

Per-scenario prerequisites:

| Scenario | Extra prerequisite |
|---|---|
| 3 — SRv6 return path | `net.ipv6.conf.all.seg6_enabled != 0` (SRv6 support in the kernel) |
| 4b — ext-hdr pnet capture | `STAMP_NETNS_PNET_BIN` pointing at a `ttl-pnet` reflector binary |

## What each scenario evidences

| # | Test | Evidence |
|---|---|---|
| 1 | `scenario_1_roundtrip_unauth_and_auth` | Base RFC 8762 §4.2–4.5 sender/reflector round-trip on a real link, unauthenticated and HMAC-authenticated. |
| 2 | `scenario_2_cos_dscp_ecn_onwire` | RFC 8972 §4.4 CoS reply-TOS + erratum 8199 DSCP/ECN reflection + draft-ietf-ippm-stamp-cos-ecn-01 §3.2 (reply DSCP=DSCP1, ECN=EC1, RPE=0b11) observed on the wire. |
| 3 | `scenario_3_srv6_return_path` | RFC 9503 §5 / RFC 8754 SRv6 return path — first live exercise of `send_with_srh()`; reports SRH-forwarded vs U-flag fallback. |
| 4a | `scenario_4a_ext_hdr_nix_c_flag` | draft-ietf-ippm-stamp-ext-hdr-11 §5.1: the nix (UDP-socket) backend has no data-plane access, so a Type-246 request comes back with the **C** (Conformance) flag set — not the pre-11 U-flag. |
| 4b | `scenario_4b_ext_hdr_pnet_capture` | draft-ietf-ippm-stamp-ext-hdr-11 §§3.1/5.1: the `ttl-pnet` backend captures an injected IPv6 Destination Options header and echoes its bytes-from-offset-4 into the Type-246 Reflected field with the C flag **clear**. |
| 5 | `scenario_5_address_group_filters` | draft-ietf-ippm-asymmetrical-pkts-14 §3.1.1/§3.1.2: a matching L2 (own-MAC) or L3 (own-prefix) Address Group sub-TLV yields a reply; a non-matching one drops the packet (no reply). |
| 6 | `scenario_6_type12_multi_reply` | draft-ietf-ippm-asymmetrical-pkts-14 §3: multiple reply copies on the wire (count within the requested/cap bound), inter-packet pacing ≈ the requested interval, replies padded beyond the base length. |
| 7 | `scenario_7_ber_onwire` | draft-gandhi-ippm-stamp-ber §3: the Bit Pattern (0xFF00) fills the Extra Padding TLV on the wire; the reflector's Bit Error Count reads 0 on a clean channel. |
| 8 | `scenario_8_ttl_egress_marking` | Sender `--ttl` egress marking: the requested IP TTL / Hop Limit appears on the outgoing test packets. |

## Building the pnet reflector for scenario 4b

The nix backend cannot see the IP data plane; only the `ttl-pnet` backend
captures IPv6 extension headers. Scenario 4b therefore uses a separately-built
reflector binary:

```bash
cargo build --features ttl-pnet
export STAMP_NETNS_PNET_BIN="$PWD/target/debug/stamp-suite"
```

Then run the tier as above. Without `STAMP_NETNS_PNET_BIN`, 4b skips. The
scenario injects a Destination Options extension header via a sticky
`IPV6_DSTOPTS` socket option; if the kernel/namespace declines the option it
also skips cleanly.

## Troubleshooting

* **`tcpdump: Couldn't change ownership of savefile`** — the harness already
  passes `-Z root` to stop tcpdump dropping privileges (which chowns the
  savefile and fails under mapped-root). If you invoke tcpdump manually, add
  `-Z root`.
* **Scenario 3 always skips** — the kernel has SRv6 disabled
  (`sysctl net.ipv6.conf.all.seg6_enabled`), common on WSL2. Enable it
  (`sysctl -w net.ipv6.conf.all.seg6_enabled=1`, needs a kernel with `seg6`)
  or run on a host with SRv6 to exercise the live SRH path.
* **A scenario FAILs (not skips)** — that is a genuine conformance failure:
  packets flowed but the on-wire bytes or reflector behaviour did not match the
  cited clause. Capture with the same fixture parameters and inspect.
* **Leftover namespaces** after a hard kill (`SIGKILL` skips `Drop`): list with
  `ip netns list` and remove `stnsr*` / `stnss*` with `ip netns del <name>`.
* **`no packets captured`** skips — tcpdump produced only the pcap header. Give
  it more lead time or confirm the interface is up; the fixture allows a fixed
  window before generating traffic.
