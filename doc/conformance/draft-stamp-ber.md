# draft-gandhi-ippm-stamp-ber conformance

This matrix maps each normative clause of draft-gandhi-ippm-stamp-ber (residual
bit error rate measurement with STAMP) to the stamp-suite code and tests that
implement it. It is for contributors and reviewers checking BER support.

Revision frozen: draft-gandhi-ippm-stamp-ber-07, 30 June 2026.
Source: [draft-gandhi-ippm-stamp-ber](https://datatracker.ietf.org/doc/draft-gandhi-ippm-stamp-ber/).

Summary: 30 clauses: 27 Compliant, 2 Partial, 0 Gap, 1 N-A, 0 Excluded.

The Clause column paraphrases the draft. Rows cover wire behavior and
directional reporting; the [README](README.md) explains how statuses are
assigned.

## Scope

This individual draft has no IANA assignments. stamp-suite uses the local
experimental Types 240 (Bit Pattern), 241 (Bit Error Count) and 242 (Maximum
Bit Error Burst Size). Type 242 collides with another implementation's
experimental Heartbeat TLV; `--ber-omit-burst` leaves it out. See the
[experimental codepoints](README.md#experimental-codepoints) table.

The sender enables BER with `--ber` and adds one Extra Padding TLV filled with
the pattern, one Bit Pattern TLV, one Bit Error Count TLV and, unless omitted,
one Maximum Bit Error Burst Size TLV (`src/sender/run.rs::SenderRun::open`).

## Clauses

| ID | Clause | Level | Role | Status | Evidence |
|---|---|---|---|---|---|
| ber-3-1 | Sender and reflector adjust the extra padding so test packets do not exceed the path MTU. | MUST | Both | Partial | `src/ber.rs::fit_padding`, `src/sender.rs::run_sender`, `src/receiver/transmit.rs::fit_reply`. See [MTU budget](#mtu-budget). Route MTU enforcement exists only on Linux. |
| ber-4.1-1 | A test packet carries one Bit Error Count TLV and one Extra Padding TLV, and at most one Bit Pattern and one burst TLV. | Descriptive | Sender | Compliant | `src/sender/run.rs::SenderRun::open` builds each TLV once; `tests/ber_measurement_test.rs` inspects production packets. |
| ber-4.1-2 | Add an Extra Padding TLV whenever a Bit Pattern TLV is added. | MUST | Sender | Compliant | `src/sender.rs::run_sender` sends the pair together. |
| ber-4.1-3 | The Bit Pattern TLV contains the pattern used in the Extra Padding TLV. | MUST | Sender | Compliant | `src/sender.rs::run_sender` fills the padding by repeating the pattern. CLI and TOML validation reject empty or invalid hex. |
| ber-4.1-4 | The padding length is an integer multiple of the pattern length. | MUST | Sender | Compliant | `src/configuration.rs::validate` rejects partial repetitions and zero padding; MTU trimming rounds down to whole repetitions. |
| ber-4.1-5 | Add an Extra Padding TLV whenever a Bit Error Count TLV is added. | MUST | Sender | Compliant | `src/sender/run.rs::SenderRun::open` adds the count only together with padding. |
| ber-4.1-6 | The sender sets the bit error count to zero. | MUST | Sender | Compliant | `src/tlv/typed/ber_count.rs`. Live tests check that the reflector counts corrupted forward padding. |
| ber-4.1-7 | On a reply with U set on the BER TLVs, the sender disables BER and continues other measurements. | Descriptive | Sender | Compliant | `src/ber.rs::observation`, `src/ber.rs::BerCollector`, `src/sender.rs::process_response`. Only an admitted reply can disable BER; later probes and Access Report retransmissions omit the BER TLVs. |
| ber-4.1.1-1 | Without a Bit Pattern TLV, both ends use the default pattern 0xFF00. | Descriptive | Both | Compliant | `src/tlv/list/processing.rs::process_ber` uses `BER_DEFAULT_PATTERN` (`src/tlv/typed/ber_pattern.rs`) when Type 240 is absent. An explicit empty pattern gets C. |
| ber-4.2-1 | Check the padding against the pattern and count mismatched bits. | MUST | Reflector | Compliant | `src/tlv/list/processing.rs::process_ber`. The byte XOR and bit scan are shared with reverse-direction measurement. |
| ber-4.2-2 | Write the bit error count into the reflected Bit Error Count TLV (zero when there are none). | MUST | Reflector | Compliant | `tests/ber_regression_test.rs`, `tests/ber_measurement_test.rs` cover zero, isolated and cross-byte errors. |
| ber-4.2-3 | Write the longest run of mismatched bits into the reflected burst TLV. | MUST | Reflector | Compliant | The same fixtures check runs of bit errors across byte boundaries. |
| ber-4.2-4 | Correct the padding to the pattern and reflect it for reverse-direction BER. | Descriptive | Reflector | Compliant | `src/tlv/list/processing.rs::process_ber`, `src/tlv/list/processing.rs::finish_ber_padding`. Correction happens before signing; if the reply is resized, the BER metadata gets C. |
| ber-4.2-5 | A reflector that does not recognize a BER TLV returns it with U set. | MUST | Reflector | Compliant | stamp-suite recognizes all three types. Unknown-type reflection follows RFC 8972; a sender test simulates a peer without BER support. |
| ber-4.2.1-1 | Set C on the BER TLVs when the Extra Padding TLV is missing or duplicated. | MUST | Reflector | Compliant | `src/tlv/list/processing.rs::process_ber`; a processing fixture covers zero and two padding TLVs. |
| ber-4.2.1-2 | Set C on the BER TLVs when any BER type is duplicated. | MUST | Reflector | Compliant | `src/tlv/list/processing.rs::process_ber`; a fixture covers a duplicate of each type. All BER metadata gets C and no count is computed. |
| ber-4.2.1-3 | Set C on the Bit Pattern TLV when the padding is not a multiple of the pattern length. | MUST | Reflector | Compliant | `src/tlv/list/processing.rs::process_ber`; three-octet padding with a two-octet pattern gets C on Type 240. A mismatch with the default pattern invalidates the count and burst. |
| ber-4.3-1 | The procedure applies to each member link of a LAG, using RFC 9534 micro-sessions. | Descriptive | Both | Partial | Micro-session IDs are validated, but member-link steering and verification are not implemented; see [RFC 9534](rfc9534.md). |
| ber-4.3-2 | Use padding that matches the link MTU. | RECOMMENDED | Sender | Compliant | The operator sets `--ber-padding-size` (default 64); the sender clamps it to the packet budget. The tool does not choose a size from the link. |
| ber-5.1-1 | Bit Pattern TLV: variable-length pattern. | MUST (implied, structural) | Both | Compliant | `src/tlv/typed/ber_pattern.rs`, with round-trip tests. |
| ber-5.2-1 | Bit Error Count TLV: Length 4. | MUST (implied, structural) | Both | Compliant | `src/tlv/typed/ber_count.rs`; invalid lengths are rejected. |
| ber-5.3-1 | Maximum Bit Error Burst Size TLV: Length 4. | MUST (implied, structural) | Both | Compliant | `src/tlv/typed/ber_burst.rs`, with zero-initialization and invalid-length tests. |
| ber-6.1-1 | Configuration allows padding size, pattern and transmit interval. | MUST | Sender | Compliant | `--ber-padding-size`, `--ber-pattern` and `--send-delay` (`ber_padding_size`, `ber_pattern`, `send_delay` in TOML). Startup validation also covers file and library callers. |
| ber-6.1-2 | Configuration allows the computation interval as a multiple of the transmit interval. | MUST | Sender | Compliant | `--ber-interval` (default 10) multiplies `--send-delay`. Windows are fixed intervals of monotonic receive time. |
| ber-6.2-1 | Report received packets and packets with errors, per direction. | MUST | Sender | Compliant | `src/ber.rs::DirectionSummary`. One accepted reply counts per probe; missing or invalid metadata and duplicates never count as clean samples. |
| ber-6.2-2 | Report padding bits and bit error totals, per direction. | MUST | Sender | Compliant | `src/ber.rs::DirectionSummary`. Forward counts come from validated metadata, reverse counts from XOR of the corrected padding. Lost or unusable replies add no bits. |
| ber-6.2-3 | Report maximum and average burst sizes, per direction. | MUST | Sender | Compliant | `src/ber.rs::DirectionSummary`. Zero-error samples count toward the average. Without Type 242 the forward burst values are null with a zero sample count. |
| ber-6.2-4 | Thresholds on bit errors and errored packets per million raise alarms. | Descriptive | Sender | Compliant | `--ber-bit-threshold` and `--ber-packet-threshold` apply to each direction. An upward crossing in a completed window logs a structured event and adds a summary alarm. |
| ber-7-1 | RFC 8762 and RFC 8972 security considerations apply, including HMAC protection. | Descriptive | Both | Compliant | `src/tlv/list/mod.rs::set_hmac`, `src/tlv/list/mod.rs::write_to`, `src/receiver/transmit.rs::sign_tlvs`. The HMAC TLV covers the BER TLVs and padding. IPv4/IPv6 open, keyed and authenticated exchange and tamper tests pass. |
| ber-9-1 | IANA allocates the three TLV types. | Descriptive (IANA) | N-A | N-A | Registry action is external. See [scope](#scope) for the local experimental types. |

## Notes

### MTU budget

On Linux the sender sizes the padding against the connected route MTU, sets
Don't Fragment, and trims the padding in whole pattern repetitions
(`src/ber.rs::fit_padding`). The Linux reflector sizes each reply against the
route MTU of its destination (`src/receiver/mtu.rs`). On other platforms the
sender cannot read the route MTU and uses a fixed budget (1280 octets for
IPv6, 1500 for IPv4). This is a route MTU lookup, not path-MTU probing, and no
physical path-MTU test backs the row.

### Reporting

Text and JSON summaries and the CSV `ber` object report per-direction totals,
nonempty windows and alarms. The final partial window is marked incomplete and
does not raise alarms. ECN pacing does not change the computation interval.

### Limits

Packets dropped by UDP checksum, CRC or FEC never reach the padding sample.
Type 12 resizing or MTU trimming can make forward BER unusable for a probe.
Duplicate replies do not add a second forward sample. No physical
error-injection test is claimed.

See [measurement semantics](../measurements.md), [bounded
history](../statistics.md), `tests/ber_measurement_test.rs` and
`tests/ber_regression_test.rs`.
