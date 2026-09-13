# Residual BER — draft-gandhi-ippm-stamp-ber-07

Summary: 30 clauses — 27 Compliant / 2 Partial / 0 Gap / 1 N-A / 0 Excluded

Revision frozen: **-07, 30 June 2026**, checked 9 September 2026 against the
[IETF draft](https://datatracker.ietf.org/doc/draft-gandhi-ippm-stamp-ber/).
This individual draft has no final IANA assignments. The implementation uses
experimental Types 240–242; Type 242 can collide with a peer's Heartbeat extension.

Rows cover wire behavior and directional reporting. See the [rollup](README.md)
for scoring and verification limits.

| ID / section | Requirement | Status | Implementation / evidence |
|---|---|---|---|
| ber-3-1 | Packet MTU | Partial | `src/ber.rs::fit_padding`, `src/sender.rs::run_sender`, `src/receiver/transmit.rs::fit_reply`: Linux connected-route sender budget and actual per-send reflector route budget, DF, whole repetitions. Non-Linux active route enforcement is not implemented. No new physical-path PMTU experiment in this checkpoint. |
| ber-4.1-1 | Unique BER/padding fields | Compliant | Sender builds one count and padding, one pattern and optionally one burst TLV; `tests/ber_measurement_test.rs` inspects production packets. |
| ber-4.1-2 | Pattern accompanied by padding | Compliant | `src/sender.rs::run_sender` originates the pair. |
| ber-4.1-3 | Pattern matches padding | Compliant | Deterministic repetition in `src/sender.rs::run_sender`; CLI/TOML validation rejects empty/invalid hex. |
| ber-4.1-4 | Divisible padding length | Compliant | `src/configuration.rs::validate` rejects partial repetitions and zero padding; MTU trimming rounds down by repeat length. |
| ber-4.1-5 | Count accompanied by padding | Compliant | Sender's BER request construction. |
| ber-4.1-6 | Count initialized to zero | Compliant | `src/tlv/typed/ber_count.rs`; live tests verify corrupted forward padding is counted by the reflector. |
| ber-4.1-7 | Disable BER after U | Compliant | `src/ber.rs::observation`, `src/ber.rs::BerCollector`, `src/sender.rs::process_response`: only an admitted reply can disable BER; subsequent normal and Access Report retransmission requests omit BER types. RTT/other measurements continue. |
| ber-4.1.1-1 | Default pattern without Type 240 | Compliant | Reflector selects `ff00` when absent. Explicit empty values get C; the typed local convenience fallback is not on-wire acceptance. |
| ber-4.2-1 | Pattern comparison | Compliant | `src/tlv/list/processing.rs::process_ber`; byte XOR and bit scan shared with reverse measurement. |
| ber-4.2-2 | Reflected error count | Compliant | `tests/ber_regression_test.rs`, `tests/ber_measurement_test.rs`: zero, isolated and cross-byte errors. |
| ber-4.2-3 | Reflected maximum error burst | Compliant | Same fixtures check consecutive error runs across byte boundaries, not packet bursts. |
| ber-4.2-4 | Padding repair | Compliant | `src/tlv/list/processing.rs::process_ber`, `src/tlv/list/processing.rs::finish_ber_padding`: repair precedes signing; resizing marks unusable metadata C. |
| ber-4.2-5 | Unsupported type U | Compliant | All three local experimental types are recognized. Sender has a simulated unsupported-peer test; generic unknown-type reflection uses RFC 8972 handling. |
| ber-4.2.1-1 | Missing/duplicate padding C | Compliant | Real processing fixture covers zero and two padding TLVs. |
| ber-4.2.1-2 | Duplicate BER type C | Compliant | Real processing fixture covers each of the three duplicate types. All BER metadata is marked C; no computation is consumed. |
| ber-4.2.1-3 | Non-divisible pattern C | Compliant | Three-byte padding with two-byte pattern returns C on Type 240; omitted-default mismatch invalidates count/burst. |
| ber-4.3-1 | Per-member LAG measurement | Partial | Numeric micro-session validation exists; physical member steering/verification remains unsupported, as recorded in `rfc9534.md`. |
| ber-4.3-2 | MTU-sized padding recommendation | Compliant | Operator chooses padding size; sender clamps the combined packet budget. Conservative 64-byte default remains deliberate; no automatic link sampling-rate selection. |
| ber-5.1-1 | Variable pattern encoding | Compliant | `src/tlv/typed/ber_pattern.rs`; round-trip tests. |
| ber-5.2-1 | Four-octet count encoding | Compliant | `src/tlv/typed/ber_count.rs`; invalid lengths rejected. |
| ber-5.3-1 | Four-octet burst encoding | Compliant | `src/tlv/typed/ber_burst.rs`; zero initialization and invalid-length tests. |
| ber-6.1-1 | Configurable size, pattern, transmit interval | Compliant | `ber_padding_size`, `ber_pattern`, and `send_delay` are configurable. Startup validation also covers file and library callers. |
| ber-6.1-2 | Computation interval multiple | Compliant | `ber_interval` in CLI/TOML/schema, default 10, multiplied by configured positive `send_delay`; fixed monotonic receive-time windows. |
| ber-6.2-1 | Directional received/errored packets | Compliant | `src/ber.rs::DirectionSummary`; one accepted reply per pending probe. Missing/invalid metadata and duplicates never become clean samples. |
| ber-6.2-2 | Directional padding bits/error totals | Compliant | Forward count from validated metadata; reverse XOR of repaired padding. Lost/unusable replies supply no estimated bits. |
| ber-6.2-3 | Directional maximum/average bursts | Compliant | Zero-error samples participate in the average; omitted Type 242 yields null forward burst values and zero burst sample count. |
| ber-6.2-4 | Ratios and threshold events | Compliant | Optional bit/packet per-million thresholds apply independently to each direction; completed-window upward crossings create structured log events and summary alarms. |
| ber-7-1 | Existing authentication procedures | Compliant | `src/tlv/list/mod.rs::set_hmac`, `src/tlv/list/mod.rs::write_to`, `src/receiver/transmit.rs::sign_tlvs`: BER padding follows HMAC; metadata remains covered. IPv4/IPv6 open/keyed/authenticated exchange and tamper tests pass. |
| ber-9-1 | IANA allocation | N/A | Registry action is external. 240/241 follow existing experimental use; 242 is a local experimental choice, not an assigned draft value. |

## Reporting and limits

Text/JSON summaries and the quoted CSV `ber` object report directional totals,
nonempty windows, and alarms. Final partial windows are incomplete and do not
trigger alarms. ECN pacing does not change the configured computation interval.

UDP checksum, CRC, and FEC drops lie outside the delivered-padding sample.
Type-12 resizing or MTU trimming can make forward BER unusable. Duplicate replies
do not repeat a forward sample. No physical error-injection test is claimed.

See [measurement semantics](../measurements.md), [bounded history](../statistics.md),
`tests/ber_measurement_test.rs`, and `tests/ber_regression_test.rs`.
