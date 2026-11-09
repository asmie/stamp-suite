# Residual BER in Padding

Revision frozen: draft-ietf-bpm-stamp-ber-01, 2 November 2026.
Source: [successor draft](https://www.ietf.org/archive/id/draft-ietf-bpm-stamp-ber-01.txt).

Summary: 54 clauses: 48 Compliant, 4 Partial, 1 Gap, 1 N-A, 0 Excluded.

## Scope

This matrix replaces the retired Gandhi -07 profile. Clauses below paraphrase
the successor. Experimental outer Type 243 and pattern sub-TLV Type 241 stand
in for TBA1/TBA2 in separate registries. These are local allocations requiring
peer agreement, not IANA assignments. Legacy outer Types 240–242 receive U;
length does not negotiate a format. The change belongs in the planned 1.1.0
minor release, not a 1.0.x patch.

The [independent BER wire peer](../../scripts/interop_ber.py) imports no crate
code and implements both roles with Python's standard library. Its 60 cases
cover IPv4/IPv6, unkeyed open, keyed open and authenticated base modes,
stateful/stateless reflection, default/explicit patterns and malformed nested
values. [Recorded evidence](../interop/2026-11-09-ber/REPORT.md) includes frozen
observations, oracle mutation tests, both build profiles and route-MTU tests.
Loopback payload transformations retain valid UDP checksums; they establish
neither raw-link error capture nor zero-checksum operation, FEC, NIC timestamps
or physical LAG steering. All-features selects nix, not pnet.

The draft-listed Teaparty revision and current main emit older layouts.
Successor interoperability with a separately maintained application or Cisco
device remains unverified. See the [migration guide](../ber-migration.md).

## Clauses

Named vectors are in [`requests.json`](../../tests/fixtures/residual-ber/requests.json)
and run in every reflector configuration. Sender scenarios independently check
requests and measurement summaries. Structural length bounds are also covered
by the value codec's property tests and fuzz target.

| ID | Clause | Level | Role | Status | Evidence |
|---|---|---|---|---|---|
| ber-3-zero-udp | Validate packet/session fields and reject invalid open packets when UDP checksums are zero. | MUST | Both | Partial | `src/receiver/mod.rs`; strict parsing, provisioned admission and replay policy are available but are not the permissive defaults. No zero-checksum sender mode or independently validated zero-checksum admission profile is provided. IPv4 sockets can still receive zero-checksum traffic; ordinary-checksum loopback evidence cannot certify this clause. |
| ber-4-flags | Reuse RFC 8972 flags for outer and nested TLVs. | Structural | Both | Compliant | `src/tlv/residual_ber.rs`; independent unknown-child, processed-prefix and opaque-after-m checks. |
| ber-4-type | Use the Residual BER type. | MUST | Both | Compliant (experimental profile) | `src/tlv/experimental.rs`; outer Type 243 pending TBA1, by agreement. Wire test: `scripts/interop_ber.py::reflector_case`. Wire test: `scripts/interop_ber.py::sender_case`. |
| ber-4-fields | Encode four-byte network-order count and burst fields, then framed sub-TLVs. | Structural | Both | Compliant | `src/tlv/residual_ber/tests.rs::independent_successor_vectors_preserve_counters_patterns_and_opaque_sub_tlvs`; clean-default and explicit-5. |
| ber-4-length | Require at least eight value octets. | MUST | Both | Compliant | `src/tlv/residual_ber.rs`; short-outer. Wire test: `scripts/interop_ber.py::reflector_case`. Wire test: `scripts/interop_ber.py::sender_case`. |
| ber-4-short | Return M for shorter outer values. | MUST | Reflector | Compliant | `src/tlv/list/processing.rs::process_ber`; short-outer returns M+C, leaving later padding U. Wire test: `scripts/interop_ber.py::reflector_case`. |
| ber-4.1-type | Use the Bit Pattern sub-TLV type. | MUST | Both | Compliant (experimental profile) | `src/tlv/experimental.rs`; nested Type 241 pending TBA2, in a separate registry. Wire test: `scripts/interop_ber.py::reflector_case`. Wire test: `scripts/interop_ber.py::sender_case`. |
| ber-4.1-length | Require at least four pattern octets; return nested M otherwise. | MUST | Both | Compliant | `src/configuration.rs`; short-pattern and opaque-after-m; explicit-5 verifies no multiple-of-four restriction. Wire test: `scripts/interop_ber.py::reflector_case`. Wire test: `scripts/interop_ber.py::sender_case`. |
| ber-4.1-pattern | Repeat the supplied pattern in padding. | MUST | Both | Compliant | explicit-4/5 independently verify counters and repaired padding across pattern boundaries. Wire test: `scripts/interop_ber.py::reflector_case`. Wire test: `scripts/interop_ber.py::sender_case`. |
| ber-5.1-pad-count | Send at most one Extra Padding TLV. | MUST NOT | Sender | Compliant | `src/sender.rs`; `scripts/interop_ber.py` checks every sender request. Wire test: `scripts/interop_ber.py::sender_case`. |
| ber-5.1-ber-count | Send at most one Residual BER TLV. | MUST NOT | Sender | Compliant | Independent sender request checks require one BER value, or none after peer U. Wire test: `scripts/interop_ber.py::sender_case`. |
| ber-5.1-padding | Include padding whenever BER metadata is sent. | MUST | Sender | Compliant | Independent requests cover all modes, both families and both pattern profiles. Wire test: `scripts/interop_ber.py::sender_case`. |
| ber-5.1-pattern | An explicit pattern matches padding and contains at least four octets. | MUST | Sender | Compliant | `src/configuration.rs`; independent five-byte sender wire checks and configuration regressions. Wire test: `scripts/interop_ber.py::sender_case`. |
| ber-5.1-alignment | Padding contains whole pattern repetitions. | MUST | Sender | Compliant | `src/ber.rs::padding_budget_preserves_whole_pattern_and_mandatory_fields`; request oracle compares every padding byte. Wire test: `scripts/interop_ber.py::sender_case`. |
| ber-5.1-count-zero | Initialize the count to zero. | MUST | Sender | Compliant | `src/tlv/residual_ber/tests.rs::requests_zero_counters_and_separate_pattern_absence_from_empty`; all independently decoded requests. Wire test: `scripts/interop_ber.py::sender_case`. |
| ber-5.1-burst-zero | Initialize maximum burst to zero. | MUST | Sender | Compliant | The request oracle checks both fixed fields with and without an explicit pattern. Wire test: `scripts/interop_ber.py::sender_case`. |
| ber-5.1-integrity | Protect metadata and sub-TLVs with RFC 8972 HMAC. | Descriptive | Both | Compliant (keyed modes) | Independent base/TLV digest checks, signed semantic mutations, failed-TLV I echoes and invalid-base silence. Padding follows HMAC. |
| ber-5.1-parent-u | Stop BER after parent U; retain delay/loss measurements. | Descriptive | Sender | Compliant | parent-u checks subsequent requests omit BER and the summary retains three delay/loss replies. |
| ber-5.1-child-u | Apply that fallback for any sub-TLV U. | Descriptive | Sender | Compliant | child-u in both pattern profiles; `src/ber.rs::nested_flags_and_duplicate_patterns_gate_sender_observations`. |
| ber-5.1.1-mtu | Fit added TLVs and padding to the MTU at both ends. | MUST | Both | Partial | `tests/route_mtu_test.rs::live_route_mtu_changes_and_alternate_destinations`; Linux route lookup and whole-pattern trimming work. Non-Linux uses fixed budgets; end-to-end PMTU learning is not implemented and its mechanism is outside the draft's scope. |
| ber-5.1.2-default | Without a pattern sub-TLV, use a configured pattern or FF00FF00. | Descriptive | Both | Compliant (default pattern) | clean-default/default-errors; default sender requests omit the child. A separately configured reflector pattern is not offered. |
| ber-5.2-compare | Count every mismatching padding bit. | MUST | Reflector | Compliant | default-errors and explicit-4/5; `src/ber.rs::popcount_and_burst_match_bit_by_bit_reference`. Wire test: `scripts/interop_ber.py::reflector_case`. |
| ber-5.2-count | Reflect the computed count, including zero for clean padding. | MUST | Reflector | Compliant | Exact expected values in clean-default/default-errors and explicit-4/5. Wire test: `scripts/interop_ber.py::reflector_case`. |
| ber-5.2-burst | Return the longest consecutive mismatch run. | MUST | Reflector | Compliant | Independent four-bit runs cross byte/pattern boundaries; bit-by-bit reference regression. Wire test: `scripts/interop_ber.py::reflector_case`. |
| ber-5.2-zero | Return burst zero for clean padding or unavailable computation. | MUST | Reflector | Compliant (software computation available) | clean-default returns zero; valid software samples always compute burst. The sender's unavailable scenario separately verifies count-only admission. Wire test: `scripts/interop_ber.py::reflector_case`. |
| ber-5.2-repair | Correct and reflect padding for reverse measurement. | Descriptive | Reflector | Compliant | `src/tlv/list/processing.rs::finish_ber_padding`; exact repaired bytes; a separate reverse error is introduced in sender scenarios. |
| ber-5.2-unknown-parent | Return U for unrecognized outer TLVs. | MUST | Reflector | Compliant | retired-legacy checks unchanged values and U on Types 240–242; Type 243 is recognized. Wire test: `scripts/interop_ber.py::reflector_case`. |
| ber-5.2-unknown-child | Return nested U for unknown sub-TLVs. | MUST | Reflector | Compliant | unknown-child checks value preservation; processed-prefix checks U+M on a truncated unknown child. Wire test: `scripts/interop_ber.py::reflector_case`. |
| ber-5.2.1-missing-pad | Set parent C for missing padding. | MUST | Reflector | Compliant | missing-padding; `src/tlv/list/processing.rs::process_ber`. Wire test: `scripts/interop_ber.py::reflector_case`. |
| ber-5.2.1-duplicate-pad | Set parent C for duplicate padding. | MUST | Reflector | Compliant | duplicate-padding preserves both padding values. Wire test: `scripts/interop_ber.py::reflector_case`. |
| ber-5.2.1-duplicate-ber | Set C for duplicate BER TLVs. | MUST | Reflector | Compliant | duplicate-ber checks both parents. Wire test: `scripts/interop_ber.py::reflector_case`. |
| ber-5.2.1-short | Set C for outer values shorter than eight octets. | MUST | Reflector | Compliant | short-outer checks M+C and final stateful signatures; `src/receiver/transmit/ber_tests.rs::generated_hmac_after_malformed_ber_uses_actual_stateful_sequence`. Wire test: `scripts/interop_ber.py::reflector_case`. |
| ber-5.2.1-patterns | Set parent C for duplicate pattern children. | MUST | Reflector | Compliant | duplicate-pattern checks both acknowledged children and parent C. Wire test: `scripts/interop_ber.py::reflector_case`. |
| ber-5.2.1-alignment | Set parent C for partial pattern repetitions. | MUST | Reflector | Compliant | unaligned-default preserves invalid padding. Wire test: `scripts/interop_ber.py::reflector_case`. |
| ber-5.3-lag | Measure each physical LAG member using micro-sessions. | Descriptive | Both | Partial | `src/tlv/typed/micro_session.rs`; numeric IDs work; physical association, steering and ingress validation are absent. See [RFC 9534](rfc9534.md). |
| ber-5.3-link-mtu | Prefer padding that fills the link MTU. | RECOMMENDED | Sender | Partial | Operators can configure padding within the budget; automatic filling to the selected link MTU is absent. |
| ber-6.1-size | Configure aligned padding size. | MUST | Sender | Compliant | `src/configuration.rs`; live tests use 60 bytes for four- and five-byte patterns. Wire test: `scripts/interop_ber.py::sender_case`. |
| ber-6.1-pattern | Configure a variable pattern of at least four bytes. | MUST | Sender | Compliant | `src/configuration.rs`; explicit-5 and short-pattern validation. Wire test: `scripts/interop_ber.py::sender_case`. |
| ber-6.1-transmit | Configure transmit interval. | MUST | Sender | Compliant | `src/configuration.rs`; live sender uses --send-delay 100. Wire test: `scripts/interop_ber.py::sender_case`. |
| ber-6.1-computation | Configure computation interval as a transmit-interval multiple. | MUST | Sender | Compliant | `src/ber.rs::directional_intervals_ratios_and_threshold_crossings`; independent interval totals with --ber-interval 1. Wire test: `scripts/interop_ber.py::sender_case`. |
| ber-6.2-forward-packets | Report received packets per forward interval. | MUST | Sender | Compliant | Independent summary oracle checks admitted samples and interval sums. Wire test: `scripts/interop_ber.py::sender_case`. |
| ber-6.2-forward-errored | Report forward packets with nonzero count. | MUST | Sender | Compliant | Baseline: 3; gates: 2; U fallback: 0. Invalid observations add no samples. Wire test: `scripts/interop_ber.py::sender_case`. |
| ber-6.2-forward-bits | Report total forward padding bits. | MUST | Sender | Compliant | Expected denominator: samples × 60 × 8; changed denominators and duplicate metadata are rejected. Wire test: `scripts/interop_ber.py::sender_case`. |
| ber-6.2-forward-errors | Report forward bit error total. | MUST | Sender | Compliant | Baseline: 12; gates: 6, including count-only admission when burst is unavailable. Wire test: `scripts/interop_ber.py::sender_case`. |
| ber-6.2-forward-burst | Report maximum and average forward burst. | MUST | Sender | Compliant | Independent maximum/average 4 and burst sample counts; `src/ber.rs::unavailable_burst_keeps_count_without_inventing_a_clean_burst`. Wire test: `scripts/interop_ber.py::sender_case`. Test: `src/ber.rs::directional_intervals_ratios_and_threshold_crossings` checks unequal burst samples and their average. |
| ber-6.2-reverse-packets | Report received packets per reverse interval. | MUST | Sender | Compliant | Independent sample admission and interval sums. Wire test: `scripts/interop_ber.py::sender_case`. |
| ber-6.2-reverse-errored | Report reverse packets with padding errors. | MUST | Sender | Compliant | Baseline: 3; gates: 1; U fallback: 0. Wire test: `scripts/interop_ber.py::sender_case`. |
| ber-6.2-reverse-bits | Report total reverse padding bits. | MUST | Sender | Compliant | Independent denominator and per-interval sums for both patterns. Wire test: `scripts/interop_ber.py::sender_case`. |
| ber-6.2-reverse-errors | Report reverse bit error total. | MUST | Sender | Compliant | One reverse bit per accepted ordinary sample; the unavailable-burst response has clean reverse padding. Wire test: `scripts/interop_ber.py::sender_case`. |
| ber-6.2-reverse-burst | Report maximum and average reverse burst. | MUST | Sender | Compliant | Maximum 1; average 1 (baseline) or 0.5 (gates); every accepted reverse burst is counted. Wire test: `scripts/interop_ber.py::sender_case`. |
| ber-6.2-alarms | Configure per-million bit/packet thresholds and signal crossings. | Descriptive | Sender | Compliant | `src/ber.rs::directional_intervals_ratios_and_threshold_crossings`; `src/ber.rs::long_run_bounds_history_and_preserves_totals_and_alarm_transitions`; independent rate checks. |
| ber-6.2-diagnostics | Log and count specific reflected C conditions locally. | SHOULD | Reflector | Gap | `src/receiver/limits.rs` has generic packet/drop counters; BER-specific reason logging and counters are absent. Follow-up: bounded per-reason diagnostics without packet payload logging. |
| ber-7-security | Apply RFC 8762/8972 security considerations. | Descriptive | Both | Compliant (tested keyed profile) | Independent failures cover base/extension digests, opaque I echoes and invalid measurement admission. Provisioning remains operator policy; open mode supplies no general integrity protection. |
| ber-9-iana | Allocate TBA1 and TBA2 in the respective registries. | IANA action | N-A | N-A | Allocation is external; local experimental values require explicit agreement. |

## Evidence boundaries

The signer regression failed before the fix: a well-framed semantic M response
retained assembly's sequence-zero HMAC because its nonzero BER padding tail
prevented the final signer from finding the HMAC. Final signing now walks
complete TLV frames even past semantic M. Callers still sign only generated
HMACs; failed incoming digests are copied with I under RFC 8972 §4.8.

Sender gates include validly signed unusable observations: duplicate metadata,
changed patterns/denominators, impossible counts, M/C/I and duplicate patterns.
They add no BER sample. Duplicate replies add none either. An unavailable
burst retains a valid count without inventing a clean burst sample. Frozen
observations are application regression inputs, not independent certification.
