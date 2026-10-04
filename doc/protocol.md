# STAMP protocol overview

STAMP concepts and their use in stamp-suite. See the RFCs and
[conformance matrices](conformance/README.md) for requirements and coverage.

## What STAMP measures

STAMP (RFC 8762) measures delay and packet loss between two hosts by sending
test packets over UDP and timing their return. One host, the
**Session-Sender**, sends test packets. The other, the **Session-Reflector**,
answers each one with a reflected packet that carries its own timestamps.
UDP port 862 is the default reflector port (RFC 8762 §4.1).

stamp-suite is one binary that runs in either role:

```sh
# Session-Reflector
stamp-suite --is-reflector

# Session-Sender: 10 test packets, 100 ms apart
stamp-suite --remote-addr 192.0.2.20 --count 10 --send-delay 100
```

A **STAMP session** is the stream of test packets between one sender and one
reflector. STAMP does not define a protocol to set up or tear down sessions;
both ends are configured by other means, such as command-line options or a
configuration file.

## Test packets and timestamps

Each test packet carries a sequence number, a timestamp and an Error Estimate
that describes the sender clock (RFC 8762 §4.2). The reflected packet copies
the sender's sequence number, timestamp and Error Estimate, and adds its own
sequence number, timestamps and Error Estimate (RFC 8762 §4.3).

Four timestamps describe one exchange:

| Timestamp | Taken by | Event |
| --- | --- | --- |
| T1 | Sender | Test packet sent |
| T2 | Reflector | Test packet received |
| T3 | Reflector | Reflected packet sent |
| T4 | Sender | Reflected packet received |

From these the sender computes:

- **Round-trip time.** stamp-suite reports T4 − T1 measured on the sender's
  monotonic clock, so it includes the reflector's processing time (T3 − T2).
- **Forward one-way delay**, T2 − T1, and **reverse one-way delay**, T4 − T3.
  These use timestamps from two different clocks. They are meaningful only
  when both clocks are synchronized to the same timescale; otherwise the clock
  offset shifts delay from one direction to the other. Their sum excludes the
  reflector's processing time.
- **Loss.** A test packet without a reply within `--timeout` seconds counts
  as lost.

Timestamps use the 64-bit NTP format or the truncated PTP format. The Z bit of
the Error Estimate says which one a packet uses. See
[Timestamps and clocks](usage.md#timestamps-and-clocks) for the options and
[measurements](measurements.md) for how stamp-suite reports clock quality.

## Open and authenticated modes

STAMP defines two packet layouts (RFC 8762 §4.2 and §4.3):

- **Open (unauthenticated) mode** uses a 44-octet base packet with no
  integrity protection. This is the stamp-suite default (`--auth-mode O`).
- **Authenticated mode** (`--auth-mode A`) uses a 112-octet base packet with
  an HMAC field. The HMAC is HMAC-SHA-256 truncated to 16 octets, computed
  with a key both ends share (RFC 8762 §4.4).

Authentication provides integrity, not confidentiality. STAMP has no
encrypted mode. Both ends must use the same mode. See
[security](security.md) for key setup.

## Stateless and stateful reflectors

RFC 8762 §4 defines two reflector behaviors:

- A **stateless reflector** copies the sender's sequence number into its own
  Sequence Number field. The sender can detect round-trip loss only.
- A **stateful reflector** keeps an independent sequence counter per session
  and increments it for each packet it reflects. A test packet lost on the
  forward path never advances the counter; a reply lost on the reverse path
  leaves a gap in it. Comparing both sequence numbers therefore separates
  forward from reverse loss.

stamp-suite reflects statelessly by default. `--stateful-reflector` selects
the stateful behavior. In both modes the reflector tracks each session it
answers, and `--max-sessions` bounds how many it tracks. The stamp-suite
sender does not infer directional loss from sequence gaps; it reports
directional counts from the Direct Measurement TLV (see
[measurements](measurements.md#direct-measurement-counter-window)).

## Sessions and the SSID

RFC 8972 §3 adds the **Session-Sender Identifier (SSID)**, a 16-bit value in
the base packet that lets one sender run several sessions to the same
reflector. The sender sets it with `--ssid`.

A stamp-suite reflector identifies a session by both UDP endpoints (source
and destination address and port), the SSID, and the sender's Micro-session
ID when one is present (RFC 9534). By default it learns sessions from
incoming traffic. With `--session-admission provisioned` it answers only the
sessions listed with `--reflector-session`. See
[Session provisioning](usage.md#session-provisioning).

## TLV extensions

RFC 8972 §4 lets a test packet carry optional **TLVs** (Type, Length, Value
fields) after the base packet. The sender uses TLVs to request extra
information or behavior; the reflector echoes each TLV, fills in its part and
sets flags to report problems:

| Flag | Meaning |
| --- | --- |
| U (Unrecognized) | The reflector does not support this TLV type. |
| M (Malformed) | The TLV is malformed, for example its length overruns the packet. |
| I (Integrity) | The HMAC TLV failed verification. |

A reflector that does not support TLVs copies them back unchanged. The
stamp-suite reflector behaves that way with `--tlv-mode ignore`.

## Extensions implemented here

| Document | What it adds | Matrix |
| --- | --- | --- |
| RFC 8762 | Base protocol: test packets, open and authenticated modes, stateless and stateful reflectors | [rfc8762](conformance/rfc8762.md) |
| RFC 8972 | SSID and TLVs: Extra Padding, Location, Timestamp Information, Class of Service, Direct Measurement, Access Report, Follow-Up Telemetry, HMAC | [rfc8972](conformance/rfc8972.md) |
| RFC 9503 | Destination Node Address and Return Path TLVs, including optional Linux SRv6 return paths | [rfc9503](conformance/rfc9503.md) |
| RFC 9534 | Micro-session ID TLV (numeric IDs; physical LAG member selection is unsupported) | [rfc9534](conformance/rfc9534.md) |
| RFC 10052 | Reflected Test Packet Control TLV (Type 12): several or larger replies per test packet | [draft-asymmetrical-pkts](conformance/draft-asymmetrical-pkts.md) |
| draft-ietf-ippm-stamp-ext-hdr-15 | Reflected IPv6 extension headers (Type 246) and fixed headers (Type 247) | [draft-stamp-ext-hdr](conformance/draft-stamp-ext-hdr.md) |
| draft-ietf-ippm-stamp-cos-ecn-01 | ECN reporting in the Class of Service TLV and a sender congestion response | [draft-stamp-cos-ecn](conformance/draft-stamp-cos-ecn.md) |
| draft-gandhi-ippm-stamp-ber-07 | Residual bit error rate in the padding of delivered packets (Types 240 to 242) | [draft-stamp-ber](conformance/draft-stamp-ber.md) |

Types 240 to 251 are experimental codepoints. Both ends must agree on their
meaning. See [experimental codepoints](conformance/README.md#experimental-codepoints).
The [TLV extensions reference](architecture.md#tlv-extensions-reference)
describes how stamp-suite handles each TLV.

## Glossary

| Term | Meaning |
| --- | --- |
| Session-Sender | The host that sends test packets and computes the results. `stamp-suite` without `--is-reflector`. |
| Session-Reflector | The host that answers test packets. `stamp-suite --is-reflector`. |
| Test packet | A STAMP packet sent by the Session-Sender. |
| Reflected packet | The reply a Session-Reflector sends for one test packet. |
| STAMP session | The test packets between one sender and one reflector, identified by both UDP endpoints and the SSID. |
| SSID | Session-Sender Identifier, a 16-bit session number in the base packet (RFC 8972 §3). |
| Micro-session ID | Identifier of one member link of a link aggregation group (RFC 9534). stamp-suite validates the numbers but does not select physical links. |
| T1, T2, T3, T4 | Sender transmit, reflector receive, reflector transmit and sender receive timestamps. |
| RTT | Round-trip time. stamp-suite reports T4 − T1. |
| One-way delay (OWD) | Forward T2 − T1 or reverse T4 − T3. Needs synchronized clocks. |
| Error Estimate | Two-octet field that describes a clock's synchronization state, error bound and timestamp format (RFC 8762 §4.2.1). |
| S bit | Error Estimate bit that asserts the clock is synchronized to an external source. |
| Z bit | Error Estimate bit that selects the timestamp format: 0 for NTP, 1 for PTP. |
| NTP format | 64-bit timestamp: 32-bit seconds since 1900 and a 32-bit fraction. |
| PTP format | Truncated 64-bit IEEE 1588 timestamp: 32-bit seconds and 32-bit nanoseconds. |
| Open mode | Unauthenticated packet layout with no HMAC. |
| Authenticated mode | Packet layout with an HMAC field covering the base packet. |
| HMAC | Keyed hash (HMAC-SHA-256 truncated to 16 octets) that detects modified packets. |
| Stateless reflector | Reflector that reuses the sender's sequence number. |
| Stateful reflector | Reflector that keeps its own sequence counter per session. |
| TLV | Type-Length-Value field appended to a test packet (RFC 8972 §4). |
| U, M, I flags | TLV flags for Unrecognized, Malformed and Integrity failure. |
| MBZ | Must Be Zero: reserved fields that senders set to zero. |
| DSCP, ECN | IP header fields for traffic class and congestion marking, requested and reported through the Class of Service TLV. |
| BER | Bit error rate, measured here on the padding of delivered packets, not on the raw link. |
| Experimental codepoint | TLV type in the 240 to 251 range; meaning set by agreement, not by IANA. |
