# BER migration

Since 1.1.0, both roles measure residual bit errors with
[draft-ietf-bpm-stamp-ber-01](https://www.ietf.org/archive/id/draft-ietf-bpm-stamp-ber-01.txt)
(2 November 2026). Releases up to 1.0.x used `draft-gandhi-ippm-stamp-ber-07`.
The two wire formats are incompatible, so a 1.0.x peer and a 1.1.0 peer
cannot measure BER against each other.

## Upgrading

1. Upgrade the sender and the reflector together. Delay and loss keep working
   with a mixed pair; only BER stops (see [Old peers](#old-peers)).
2. Make explicit patterns at least four bytes long by repeating them:
   `--ber-pattern aa55` becomes `--ber-pattern aa55aa55`. The old default,
   `ff00`, is rejected too. Without `--ber-pattern` the default is `FF00FF00`,
   and no pattern sub-TLV is sent.
3. Choose a padding size that holds whole repetitions of the pattern: a
   multiple of four for four-byte patterns, of five for five-byte patterns.
4. Remove `--ber-omit-burst` and `ber_omit_burst`. The new format always
   carries the burst field. Setting either one stops startup with an error,
   even when BER is disabled.

## Wire format

| Revision | BER fields and pattern |
|---|---|
| gandhi -07 and ippm -00 | Separate top-level pattern, count and optional maximum-burst TLVs; two-byte default pattern. |
| ippm -01 | One TLV with a four-byte count; optional pattern and maximum-burst sub-TLVs. Explicit patterns have a length divisible by four. |
| bpm -01 (current) | One TLV with two fixed four-byte fields: count, then maximum burst. Optional pattern sub-TLV; its value needs at least four bytes. Default pattern is `FF00FF00`. |

The BER TLV uses experimental Type 243, and its pattern sub-TLV uses
experimental Type 241, until IANA assigns TBA1 and TBA2. Both peers must agree
on these codepoints. They avoid the old Type 242 (which collided with
Heartbeat) and Types 9 and 10, which RFC 9503 assigns. The allocations are
listed in `src/tlv/experimental.rs` and the conformance inventory.

The value is at least eight bytes and may contain any number of sub-TLVs, with
at most one known pattern sub-TLV. A burst of zero with a nonzero count means
the reflector could not calculate the burst. The sender then keeps the count
sample but records no burst sample; JSON and CSV show a null burst and a zero
burst sample count.

## Old peers

Nothing guesses the format from a TLV's length. A 1.1.0 endpoint answers the
retired Types 240–242 with U. A peer that does not support Type 243 should
answer with U too, and the sender then disables BER while delay and loss
measurements continue. A reflector without TLV support, such as
`--tlv-mode ignore`, returns the request's U flags unchanged and has the same
effect. `tests/ber_measurement_test.rs` covers both cases
(`unsupported_peer_disables_ber_only`,
`tlv_unaware_reflector_disables_ber_with_one_warning`).

## Reflector behavior

The reflector checks BER before the other TLV updates, after base and TLV
HMAC verification and session admission:

- A BER value shorter than eight bytes gets M and C.
- A short known pattern sub-TLV gets M on that sub-TLV. Processing stops at a
  malformed boundary and the rest is echoed unchanged; it is never replaced
  by the default pattern.
- Unknown sub-TLVs get U and keep their values.
- Missing or duplicate padding, duplicate BER or pattern TLVs, and padding
  that is not a whole number of patterns get C on the BER TLV.
- Values that failed HMAC verification, and their padding, are echoed
  unchanged.

Padding is repaired and the reply is signed after all other changes.

When a reply must shrink to fit the route MTU, the reflector first removes
optional reflected-header TLVs and then shortens BER padding. A Type 12 reply
clamped to the MTU fills the exact budget with the pattern, possibly ending in
a partial repetition, and sets C on the BER TLV because the denominator
changed. A standalone BER reply keeps whole repetitions. If the mandatory
fields cannot fit, or the pattern is unusable, the reply is dropped. Route-MTU
sizing works on Linux, on Windows, and on macOS for native unicast IPv6; see
[Reply size and route MTU](usage.md#reply-size-and-route-mtu). There is no
end-to-end path-MTU probing.

## Sender behavior

The sender checks the reflected BER TLV and its sub-TLVs for U, M and I after
integrity and session checks. It rejects duplicate or mismatched patterns and
a changed padding size. U on the BER TLV or one of its sub-TLVs, wherever it
sits in the reply, disables BER for the rest of the run: the sender logs one
warning and reports `disabled_by_peer`. U or C on the Extra Padding TLV alone
only drops that reply's sample, because the draft ties the fallback to the BER
TLV (§5.1). Padding is sized in whole pattern repetitions after the BER TLV
itself is counted, and follows the route MTU when it changes.

## Zero-checksum ingress boundary

`--zero-udp-checksum` lets a Linux sender send authenticated IPv4 BER requests
with a zero UDP checksum; see
[zero-checksum transmission](usage.md#zero-checksum-ber-transmission). It is
off by default, rejected in open mode, and keeps base and TLV HMACs and receive
checksum validation. There is no bidirectional zero-checksum mode and no IPv6
support: the
[BER draft §3](https://www.ietf.org/archive/id/draft-ietf-bpm-stamp-ber-01.txt#section-3)
excludes IPv6 under RFC 8200. The pnet capture backend rejects zero UDP
checksums in both families.

On the receive side, the tested profile is a Linux IPv4 nix reflector run with
`--strict-packets --session-admission provisioned --drop-replayed --tlv-mode echo`,
an exact `--reflector-session SSID,SOURCE,DESTINATION` and `--hwtstamp off`.
The raw-wire [fixture](../tests/zero_checksum_test.rs) sends checksum-zero
requests in open, keyed-open and authenticated modes, with valid and invalid
nonzero-checksum controls.

Two opt-in reflector options drop damaged requests before they touch session
state (allocation, activity, receive counts or replay):

- `--validate-base-fields` rejects incomplete bases, zero Error Estimate
  multipliers and out-of-range PTP nanoseconds; see
  [base-field validation](usage.md#base-field-validation).
- `--validate-tlv-framing` rejects incomplete outer TLVs and incomplete
  children of the known containers (Location, Timestamp Information, Return
  Path, Type 12 and BER); see
  [TLV framing admission](usage.md#tlv-framing-admission).

Raw-wire tests send validly signed zero-checksum requests that each option
must reject, both before a session exists and after. Requests that are complete
but semantically invalid, and TLVs that fail their HMAC, still get the normal
M and I replies of RFC 8972 §4 and §4.8.

This conformance row (`ber-3-zero-udp`) stays Partial. The BER draft wants
failed open-mode checks discarded, but nothing here validates freshness or
session-specific timestamp rules, and a normal UDP socket cannot see the
incoming UDP checksum. Changes that still look valid, such as sequence gaps,
reordering or an old timestamp, cannot be told apart from corruption, and
received MBZ fields are ignored as
[RFC 8762](https://www.rfc-editor.org/rfc/rfc8762.html#section-4.2) requires.
Only Extra Padding produces BER samples; corrupting an authenticated base
field is tested as an authentication drop. These loopback tests say nothing
about physical links, FEC or NIC error capture.

## Conformance diagnostics

The reflector counts the local reasons it sets C on a BER TLV. A counter
advances once per reason per datagram, after a complete successful UDP send.
Burst copies count separately; failed or partial sends, cancelled work and
suppressed replies count nothing. An MTU retry starts again from the template's
reasons, so a failed trimmed attempt does not label a later untrimmed reply.

| Reason | Meaning |
| --- | --- |
| `missing_padding` | Processed BER has no Extra Padding TLV. |
| `duplicate_padding` | More than one Extra Padding TLV is present. |
| `duplicate_ber` | More than one BER TLV is present. |
| `short_ber_value` | Recognized BER value is shorter than eight bytes (M+C), including when a later HMAC failure adds I. |
| `duplicate_pattern` | More than one known pattern sub-TLV is encountered. |
| `padding_misaligned` | Padding length is not a whole number of patterns. |
| `padding_resized` | Local Type 12 or MTU shaping changes the BER denominator. |

One datagram can raise several reasons, but the same reason counts once.
Validation still stops where it did before, so these counts are not a complete
diagnosis of an invalid packet. Errors that carry only M on a sub-TLV add no
reason. A C flag copied from the peer in a known container is counted
separately as `peer_c_preserved`; it never admits a BER sample or implies a
local fault.

Counts are lifetime totals for the reflector, kept across session expiry, under
`counters.ber_conformance` in [control status](control-plane.md#status).
With runtime metrics, Prometheus exposes
`stamp_reflector_ber_conformance_total` with only the fixed `reason` label.
Each reason is logged on its first, tenth, hundredth and every later
power-of-ten occurrence. Messages contain the reason and its total, never
packet values, keys, addresses or session identifiers. Type 12, reflected-header
and CoS reasons have their own counters, described in
[control status](control-plane.md#status).

## Interoperability

No other maintained application has completed a BER exchange with
stamp-suite in this format. Teaparty was built and run only as a black-box
peer; none of its code, tests or comments were used.

- The commit the draft lists,
  [`592558a`](https://github.com/cerfcast/teaparty/commit/592558a38dbcf9b273acb2a2fe8ab0d8f16d0709),
  sends Extra Padding followed by separate four-byte Types 9 (count) and 10
  (pattern), which RFC 9503 assigns to other TLVs
  ([captures](../tests/fixtures/residual-ber/teaparty-592558a.json)).
- Its main branch on 9 November 2026,
  [`7fb2bde`](https://github.com/cerfcast/teaparty/commit/7fb2bdea48d42875e3237b97718f3c2149995b40),
  sends separate Type 241 (four-byte count) and Type 240 (pattern) TLVs
  ([captures](../tests/fixtures/residual-ber/teaparty-7fb2bde.json)).

Neither uses the combined value of the current draft. Cisco IOS XR 26.1.1, the
other implementation the draft names, was not available for testing.

## Evidence

- [Hand-encoded values](../tests/fixtures/residual-ber/values.json) taken from
  the draft's field diagrams, with tests for byte order, omitted and explicit
  patterns, zero burst, unknown sub-TLVs, truncation, duplicates and length
  limits. The `residual_ber_value` fuzz target is seeded from them.
- An independent Python peer, `scripts/interop_ber.py`, which CI runs against
  both build profiles in both roles: 60 cases each. Its first run found a
  signing defect in stateful BER error replies, since fixed.
- The [BER conformance matrix](conformance/draft-stamp-ber.md), which lists the
  four Partial rows: zero-checksum validation, MTU fitting on platforms without
  route-MTU lookup, physical LAG members, and automatic padding to the link
  MTU.
