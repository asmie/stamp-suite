# Residual BER in Padding

Revision frozen: draft-ietf-bpm-stamp-ber-01, 2 November 2026.
Source: [successor draft](https://www.ietf.org/archive/id/draft-ietf-bpm-stamp-ber-01.txt).

Summary: 54 clauses: 49 Compliant, 4 Partial, 0 Gap, 1 N-A, 0 Excluded.

## Scope

This matrix replaces the retired Gandhi -07 profile, and its clauses
paraphrase the successor draft. Outer Type 243 and pattern sub-TLV Type 241
stand in for TBA1 and TBA2, which live in separate registries. They are local
experimental allocations that both peers must agree on, not IANA assignments.
The retired outer Types 240–242 get U, and the TLV length never selects a
format. The change shipped in 1.1.0; see the
[migration guide](../ber-migration.md).

The [independent BER wire peer](../../scripts/interop_ber.py) imports no crate
code and implements both roles with the Python standard library. Its 60 cases
(12 reflector, 48 sender) cover IPv4 and IPv6, unkeyed open, keyed open and
authenticated base modes, stateful and stateless reflection, default and
explicit patterns, and malformed nested values. CI runs it against the default
and all-features builds; all-features selects nix, not pnet. Its loopback
payload changes keep valid UDP checksums, so they show nothing about raw-link
error capture, zero-checksum operation, FEC, NIC timestamps or physical LAG
steering.

The Teaparty revision the draft lists, and Teaparty main, emit older layouts.
No separately maintained application or Cisco device has been tested with
the successor format. See [interoperability](../ber-migration.md#interoperability).

## Clauses

Lowercase names such as `short-outer` or `parent-u` refer to the named
vectors in [`requests.json`](../../tests/fixtures/residual-ber/requests.json),
which run in every reflector configuration, or to the peer's sender scenarios,
which check each request and the final measurement summary. The value codec's
property tests and the `residual_ber_value` fuzz target also cover the
structural length bounds.

| ID | Clause | Level | Role | Status | Evidence |
|---|---|---|---|---|---|
| ber-3-zero-udp | Validate packet/session fields and reject invalid open packets when UDP checksums are zero. | MUST | Both | Partial | Test: `tests/zero_checksum_test.rs::zero_checksum_padding_errors_survive_kernel_checks_and_preserve_hmac` sends captured IPv4 zero-checksum requests, with kernel checksum-drop controls, and checks BER padding repair and signatures in open, keyed-open and authenticated modes. Test: `tests/zero_checksum_test.rs::zero_checksum_strict_and_provisioned_rejections_precede_session_mutation`: short bases and wrong provisioned identities are rejected before state updates. Test: `tests/zero_checksum_test.rs::zero_checksum_authenticated_base_corruption_does_not_advance_session`: changes to protected fields other than padding cannot advance state. Test: `tests/zero_checksum_test.rs::zero_checksum_base_field_policy_rejects_validly_signed_invalid_fields`: opt-in `--validate-base-fields` rejects validly signed bases with zero multipliers or invalid PTP nanoseconds before session updates. Test: `src/receiver/base_validation/tests.rs::policy_rejections_precede_allocation_activity_counters_and_replay` covers IPv4/IPv6, open/authenticated and state modes, mixed clocks, and sequence wrap and reordering. Test: `tests/sender_zero_checksum_test.rs::authenticated_sender_uses_zero_checksum_only_when_requested`: a Linux IPv4 authenticated BER sender sends a zero checksum only with `--zero-udp-checksum`, keeps base and TLV HMACs and still validates received checksums. Test: `tests/zero_checksum_test.rs::zero_checksum_framing_admission_preserves_session_state`: opt-in `--validate-tlv-framing` drops incomplete outer and known-child frames before session updates. Tests: `src/receiver/framing_admission_tests.rs::framing_admission_precedes_allocation_activity_counters_and_replay`, `src/receiver/framing_admission_tests.rs::framing_admission_keeps_complete_semantic_errors_and_opaque_values`, `src/receiver/framing_admission_tests.rs::framing_admission_keeps_type12_ordering_error_reply`. Partial because there is no complete open-mode admission profile: semantic TLV validation still runs after session updates, and freshness is not checked. Loopback with ordinary checksums cannot show this clause. See [zero-checksum ingress boundary](../ber-migration.md#zero-checksum-ingress-boundary). |
| ber-4-flags | Reuse RFC 8972 flags for outer and nested TLVs. | Structural | Both | Compliant | `src/tlv/residual_ber.rs`; vectors unknown-child, processed-prefix and opaque-after-m. |
| ber-4-type | Use the Residual BER type. | MUST | Both | Compliant (experimental profile) | `src/tlv/experimental.rs`; outer Type 243 pending TBA1, by agreement. Wire test: `scripts/interop_ber.py::reflector_case`. Wire test: `scripts/interop_ber.py::sender_case`. |
| ber-4-fields | Encode four-byte network-order count and burst fields, then framed sub-TLVs. | Structural | Both | Compliant | `src/tlv/residual_ber/tests.rs::independent_successor_vectors_preserve_counters_patterns_and_opaque_sub_tlvs`; clean-default and explicit-5. |
| ber-4-length | Require at least eight value octets. | MUST | Both | Compliant | `src/tlv/residual_ber.rs`; short-outer. Wire test: `scripts/interop_ber.py::reflector_case`. Wire test: `scripts/interop_ber.py::sender_case`. |
| ber-4-short | Return M for shorter outer values. | MUST | Reflector | Compliant | `src/tlv/list/processing.rs::process_ber`; short-outer returns M+C, leaving later padding U. Wire test: `scripts/interop_ber.py::reflector_case`. |
| ber-4.1-type | Use the Bit Pattern sub-TLV type. | MUST | Both | Compliant (experimental profile) | `src/tlv/experimental.rs`; nested Type 241 pending TBA2, in a separate registry. Wire test: `scripts/interop_ber.py::reflector_case`. Wire test: `scripts/interop_ber.py::sender_case`. |
| ber-4.1-length | Require at least four pattern octets; return nested M otherwise. | MUST | Both | Compliant | `src/configuration.rs`; vectors short-pattern and opaque-after-m; explicit-5 shows that the length need not be a multiple of four. Wire test: `scripts/interop_ber.py::reflector_case`. Wire test: `scripts/interop_ber.py::sender_case`. |
| ber-4.1-pattern | Repeat the supplied pattern in padding. | MUST | Both | Compliant | Vectors explicit-4 and explicit-5 check counters and repaired padding across pattern boundaries. Wire test: `scripts/interop_ber.py::reflector_case`. Wire test: `scripts/interop_ber.py::sender_case`. |
| ber-5.1-pad-count | Send at most one Extra Padding TLV. | MUST NOT | Sender | Compliant | `src/sender.rs`; `scripts/interop_ber.py` checks every sender request. Wire test: `scripts/interop_ber.py::sender_case`. |
| ber-5.1-ber-count | Send at most one Residual BER TLV. | MUST NOT | Sender | Compliant | The peer requires one BER value in each request, or none after it returned U. Wire test: `scripts/interop_ber.py::sender_case`. |
| ber-5.1-padding | Include padding whenever BER metadata is sent. | MUST | Sender | Compliant | The peer checks requests in all modes, both families and both pattern profiles. Wire test: `scripts/interop_ber.py::sender_case`. |
| ber-5.1-pattern | An explicit pattern matches padding and contains at least four octets. | MUST | Sender | Compliant | `src/configuration.rs`; the peer checks five-byte sender patterns on the wire, and configuration tests reject short patterns. Wire test: `scripts/interop_ber.py::sender_case`. |
| ber-5.1-alignment | Padding contains whole pattern repetitions. | MUST | Sender | Compliant | `src/ber.rs::padding_budget_preserves_whole_pattern_and_mandatory_fields`; the peer compares every padding byte. Wire test: `scripts/interop_ber.py::sender_case`. |
| ber-5.1-count-zero | Initialize the count to zero. | MUST | Sender | Compliant | `src/tlv/residual_ber/tests.rs::requests_zero_counters_and_separate_pattern_absence_from_empty`; the peer decodes every request. Wire test: `scripts/interop_ber.py::sender_case`. |
| ber-5.1-burst-zero | Initialize maximum burst to zero. | MUST | Sender | Compliant | The peer checks both fixed fields with and without an explicit pattern. Wire test: `scripts/interop_ber.py::sender_case`. |
| ber-5.1-integrity | Protect metadata and sub-TLVs with RFC 8972 HMAC. | Descriptive | Both | Compliant (keyed modes) | The peer checks base and TLV digests, signed semantic changes, I echoes of failed TLVs and silence after an invalid base. Padding follows the HMAC TLV, so the HMAC covers the BER TLV but not the padding. |
| ber-5.1-parent-u | Stop BER after parent U; retain delay/loss measurements. | Descriptive | Sender | Compliant | `src/ber.rs::observation`. Scenario parent-u checks that later requests omit BER and that the summary keeps three delay/loss replies. Test: `src/ber.rs::ber_u_disables_in_either_order_but_padding_u_alone_does_not`: U on the BER TLV disables BER whether it comes before or after Extra Padding. U or C on Extra Padding alone drops only that sample, and U on an unrelated TLV is ignored. A failed HMAC or an earlier M hides the U. Test: `tests/ber_measurement_test.rs::tlv_unaware_reflector_disables_ber_with_one_warning`: a `--tlv-mode ignore` reflector echoes U on every TLV, and the sender warns once and reports `disabled_by_peer`. |
| ber-5.1-child-u | Apply that fallback for any sub-TLV U. | Descriptive | Sender | Compliant | Scenario child-u in both pattern profiles; `src/ber.rs::nested_flags_and_duplicate_patterns_gate_sender_observations`. U on a sub-TLV disables BER in either TLV order, even when the padding is unusable. |
| ber-5.1.1-mtu | Fit added TLVs and padding to the MTU at both ends. | MUST | Both | Partial | Linux: `tests/route_mtu_test.rs::live_route_mtu_changes_and_alternate_destinations` checks whole-pattern trimming of standalone replies and exact-budget Type 12 clamping with default and five-byte pattern prefixes. Test: `src/receiver/transmit/ber_tests.rs::controlled_ber_mtu_clamp_preserves_pattern_bytes_and_signatures`. Windows sender: test `src/sender/run/windows_mtu_tests.rs::windows_mtu_ber_initial_fit_uses_the_connected_budget` fits padding to the connected kernel estimate. Windows reflector: test `src/receiver/transmit/windows_tests.rs::windows_reflector_mtu_shapes_native_datagrams_and_restores_policy` uses fresh path and interface estimates. macOS sender, native unicast IPv6 without interface pinning: test `src/sender/run/macos_mtu_tests.rs::macos_ipv6_mtu_ber_initial_fit_uses_the_connected_budget`. macOS reflector: test `src/receiver/transmit/macos_tests.rs::macos_ipv6_reflector_shapes_datagrams_and_restores_independent_policies`. The macOS tests run only in native macOS CI. Partial because other sender sockets size padding for a fixed 1500-byte (IPv4) or 1280-byte (IPv6) MTU, and the reflector sends BER replies without route sizing where it has no lookup. There is no end-to-end PMTU discovery; the draft does not define one. |
| ber-5.1.2-default | Without a pattern sub-TLV, use a configured pattern or FF00FF00. | Descriptive | Both | Compliant (default pattern) | Vectors clean-default and default-errors; default sender requests omit the sub-TLV. The reflector has no option to configure its own pattern. |
| ber-5.2-compare | Count every mismatching padding bit. | MUST | Reflector | Compliant | Vectors default-errors, explicit-4 and explicit-5; `src/ber.rs::popcount_and_burst_match_bit_by_bit_reference`. Wire test: `scripts/interop_ber.py::reflector_case`. |
| ber-5.2-count | Reflect the computed count, including zero for clean padding. | MUST | Reflector | Compliant | Exact expected values in clean-default, default-errors, explicit-4 and explicit-5. Wire test: `scripts/interop_ber.py::reflector_case`. |
| ber-5.2-burst | Return the longest consecutive mismatch run. | MUST | Reflector | Compliant | Four-bit error runs cross byte and pattern boundaries; `src/ber.rs::popcount_and_burst_match_bit_by_bit_reference` compares with a bit-by-bit reference. Wire test: `scripts/interop_ber.py::reflector_case`. |
| ber-5.2-zero | Return burst zero for clean padding or unavailable computation. | MUST | Reflector | Compliant (software computation available) | clean-default returns zero. The software reflector always computes the burst, so it never reports it as unavailable. The sender's unavailable scenario checks that such a reply still counts errors. Wire test: `scripts/interop_ber.py::reflector_case`. |
| ber-5.2-repair | Correct and reflect padding for reverse measurement. | Descriptive | Reflector | Compliant | `src/tlv/list/processing.rs::finish_ber_padding`; vectors check the exact repaired bytes, and sender scenarios add a separate reverse-path error. Type 12 and MTU fitting keep the repaired pattern prefix, the exact size and the signatures: `src/receiver/transmit/ber_tests.rs::controlled_ber_mtu_clamp_preserves_pattern_bytes_and_signatures`, `src/receiver/transmit/ber_tests.rs::controlled_header_trimming_marks_only_changed_ber_denominators`. |
| ber-5.2-unknown-parent | Return U for unrecognized outer TLVs. | MUST | Reflector | Compliant | Vector retired-legacy checks U and unchanged values on Types 240–242; Type 243 is recognized. Wire test: `scripts/interop_ber.py::reflector_case`. |
| ber-5.2-unknown-child | Return nested U for unknown sub-TLVs. | MUST | Reflector | Compliant | Vector unknown-child checks that the value is kept; processed-prefix checks U+M on a truncated unknown sub-TLV. Wire test: `scripts/interop_ber.py::reflector_case`. |
| ber-5.2.1-missing-pad | Set parent C for missing padding. | MUST | Reflector | Compliant | Vector missing-padding; `src/tlv/list/processing.rs::process_ber`. Wire test: `scripts/interop_ber.py::reflector_case`. |
| ber-5.2.1-duplicate-pad | Set parent C for duplicate padding. | MUST | Reflector | Compliant | Vector duplicate-padding; both padding values are kept. Wire test: `scripts/interop_ber.py::reflector_case`. |
| ber-5.2.1-duplicate-ber | Set C for duplicate BER TLVs. | MUST | Reflector | Compliant | Vector duplicate-ber checks C on both BER TLVs. Wire test: `scripts/interop_ber.py::reflector_case`. |
| ber-5.2.1-short | Set C for outer values shorter than eight octets. | MUST | Reflector | Compliant | Vector short-outer checks M+C and the stateful signature over the final sequence number; `src/receiver/transmit/ber_tests.rs::generated_hmac_after_malformed_ber_uses_actual_stateful_sequence`. Wire test: `scripts/interop_ber.py::reflector_case`. |
| ber-5.2.1-patterns | Set parent C for duplicate pattern children. | MUST | Reflector | Compliant | Vector duplicate-pattern checks both pattern sub-TLVs and C on the BER TLV. Wire test: `scripts/interop_ber.py::reflector_case`. |
| ber-5.2.1-alignment | Set parent C for partial pattern repetitions. | MUST | Reflector | Compliant | Vector unaligned-default; the misaligned padding is returned unchanged. Wire test: `scripts/interop_ber.py::reflector_case`. |
| ber-5.3-lag | Measure each physical LAG member using micro-sessions. | Descriptive | Both | Partial | `src/tlv/typed/micro_session.rs`; numeric IDs work. IDs are not tied to physical members, traffic is not steered to a member, and the ingress member is not checked. See [RFC 9534](rfc9534.md). |
| ber-5.3-link-mtu | Prefer padding that fills the link MTU. | RECOMMENDED | Sender | Partial | Operators set the padding size, and the sender shrinks it to fit the route MTU. It does not grow padding to fill the link MTU. |
| ber-6.1-size | Configure aligned padding size. | MUST | Sender | Compliant | `src/configuration.rs` (`--ber-padding-size`); the peer uses 60 bytes for four- and five-byte patterns. Wire test: `scripts/interop_ber.py::sender_case`. |
| ber-6.1-pattern | Configure a variable pattern of at least four bytes. | MUST | Sender | Compliant | `src/configuration.rs` (`--ber-pattern`); explicit-5, and short-pattern rejection. Wire test: `scripts/interop_ber.py::sender_case`. |
| ber-6.1-transmit | Configure transmit interval. | MUST | Sender | Compliant | `src/configuration.rs` (`--send-delay`); the peer runs the sender with `--send-delay 100`. Wire test: `scripts/interop_ber.py::sender_case`. |
| ber-6.1-computation | Configure computation interval as a transmit-interval multiple. | MUST | Sender | Compliant | `src/ber.rs::directional_intervals_ratios_and_threshold_crossings`; the peer checks interval totals with `--ber-interval 1`. Wire test: `scripts/interop_ber.py::sender_case`. |
| ber-6.2-forward-packets | Report received packets per forward interval. | MUST | Sender | Compliant | The peer checks admitted samples and interval sums in the summary. Wire test: `scripts/interop_ber.py::sender_case`. |
| ber-6.2-forward-errored | Report forward packets with nonzero count. | MUST | Sender | Compliant | Expected: 3 (baseline), 2 (gates), 0 (U fallback). Unusable replies add no sample. Wire test: `scripts/interop_ber.py::sender_case`. |
| ber-6.2-forward-bits | Report total forward padding bits. | MUST | Sender | Compliant | Expected: samples × 60 × 8. Replies with a changed padding size or duplicate metadata add no sample. Wire test: `scripts/interop_ber.py::sender_case`. |
| ber-6.2-forward-errors | Report forward bit error total. | MUST | Sender | Compliant | Expected: 12 (baseline), 6 (gates, including a count-only sample with an unavailable burst). Wire test: `scripts/interop_ber.py::sender_case`. |
| ber-6.2-forward-burst | Report maximum and average forward burst. | MUST | Sender | Compliant | The peer expects maximum and average 4 and checks burst sample counts; `src/ber.rs::unavailable_burst_keeps_count_without_inventing_a_clean_burst`. Wire test: `scripts/interop_ber.py::sender_case`. Test: `src/ber.rs::directional_intervals_ratios_and_threshold_crossings` checks unequal burst samples and their average. |
| ber-6.2-reverse-packets | Report received packets per reverse interval. | MUST | Sender | Compliant | The peer checks admitted samples and interval sums. Wire test: `scripts/interop_ber.py::sender_case`. |
| ber-6.2-reverse-errored | Report reverse packets with padding errors. | MUST | Sender | Compliant | Expected: 3 (baseline), 1 (gates), 0 (U fallback). Wire test: `scripts/interop_ber.py::sender_case`. |
| ber-6.2-reverse-bits | Report total reverse padding bits. | MUST | Sender | Compliant | The peer checks the total and per-interval sums for both patterns. Wire test: `scripts/interop_ber.py::sender_case`. |
| ber-6.2-reverse-errors | Report reverse bit error total. | MUST | Sender | Compliant | The peer flips one reverse bit per accepted ordinary sample; its unavailable-burst reply has clean reverse padding. Wire test: `scripts/interop_ber.py::sender_case`. |
| ber-6.2-reverse-burst | Report maximum and average reverse burst. | MUST | Sender | Compliant | Expected maximum 1; average 1 (baseline) or 0.5 (gates); every accepted reverse burst is counted. Wire test: `scripts/interop_ber.py::sender_case`. |
| ber-6.2-alarms | Configure per-million bit/packet thresholds and signal crossings. | Descriptive | Sender | Compliant | `src/ber.rs::directional_intervals_ratios_and_threshold_crossings`; `src/ber.rs::long_run_bounds_history_and_preserves_totals_and_alarm_transitions`; the peer checks the per-million rates. |
| ber-6.2-diagnostics | Log and count specific reflected C conditions locally. | SHOULD | Reflector | Compliant (TLV-enabled profile) | Each BER reason for C, including padding resizing, has a fixed counter and its own throttled log, updated after a successful send. Test: `src/receiver/transmit/diagnostics_tests.rs::ber_reasons_match_reflected_c_flags_in_open_auth_ipv4_ipv6`, `src/receiver/transmit/diagnostics_tests.rs::diagnostics_log_each_reason_independently_without_per_packet_log_floods`, `src/receiver/transmit/diagnostics_tests.rs::mtu_retry_does_not_leak_failed_attempt_diagnostics`. Type 12 semantic and send-time C conditions have their own counters and logs. Test: `src/receiver/transmit/type12_diagnostics_tests.rs::type12_semantic_reasons_match_signed_c_flags_and_successful_sends`, `src/receiver/transmit/type12_diagnostics_tests.rs::type12_send_time_clamps_distinguish_route_admin_and_tied_limits`, `src/receiver/transmit/type12_diagnostics_tests.rs::type12_mtu_retry_discards_only_failed_attempt_reasons`. Header-reflection C reasons are counted only for headers that survive trimming. Test: `src/receiver/transmit/header_diagnostics_tests.rs::header_reasons_match_processed_c_flags_and_signed_successful_sends`, `src/receiver/transmit/header_diagnostics_tests.rs::header_diagnostics_follow_only_surviving_headers_after_size_trimming`, `src/receiver/transmit/header_diagnostics_tests.rs::header_mtu_retries_restore_reason_provenance_from_the_original_reply`. CoS RPE=01, third-DSCP C, nested control C and short-value C set before HMAC verification have their own reasons. Tests: `src/receiver/transmit/dscp_tests.rs::dscp_admission_marks_signed_bursts_and_counts_only_successful_third_values`, `src/receiver/transmit/cos_control_diagnostics_tests.rs::cos_reason_requires_rpe01_and_a_complete_successful_send`, `src/receiver/transmit/cos_control_diagnostics_tests.rs::nested_control_reports_follow_actual_mutations_across_parents_and_later_u`, `src/receiver/transmit/cos_control_diagnostics_tests.rs::structural_short_ber_c_is_counted_even_when_hmac_later_fails`. Every place that sets C locally has a reason. A C flag kept from the peer in a complete child header of a known container counts under a separate reason, including in integrity-failure echoes; values and unknown container formats are not interpreted. Tests: `src/receiver/transmit/peer_c_diagnostics_tests.rs::preserved_peer_c_uses_known_layouts_and_preserves_failed_integrity_values`, `src/receiver/transmit/peer_c_diagnostics_tests.rs::peer_and_local_child_c_provenance_remain_distinct_across_later_u`, `src/receiver/transmit/peer_c_diagnostics_tests.rs::peer_c_observation_stops_at_incomplete_children_and_never_scans_values`, `src/receiver/transmit/peer_c_diagnostics_tests.rs::legacy_ignore_tail_has_no_tlv_provenance_claim`. This does not cover `--tlv-mode ignore`. |
| ber-7-security | Apply RFC 8762/8972 security considerations. | Descriptive | Both | Compliant (tested keyed profile) | The peer checks failed base and extension digests, opaque I echoes, and that unusable replies add no measurement. Provisioning is operator policy, and open mode has no general integrity protection. |
| ber-9-iana | Allocate TBA1 and TBA2 in the respective registries. | IANA action | N-A | N-A | IANA allocates these; until then both peers must agree on the experimental values. |

## Evidence boundaries

`src/tlv/framing.rs::check_tlv_framing` backs the opt-in
`--validate-tlv-framing` gate, which drops packets with incomplete outer or
known-child frames before any session state changes. It checks framing only,
not typed lengths, flags or integrity. It stops at the first failure, keeps
child reads inside the owning parent and never guesses a value's container
layout. Complete frames still get the normal M and I responses, so
ber-3-zero-udp stays Partial. Tests:
`src/tlv/framing/tests.rs::known_children_report_absolute_offsets_and_parent_ownership`,
`src/tlv/framing/tests.rs::child_values_cannot_consume_a_later_parent`,
`src/tlv/framing/tests.rs::framing_success_does_not_validate_semantic_lengths_or_integrity`
and `src/tlv/framing/tests.rs::opaque_values_and_child_type_numbers_never_trigger_recursion`.

The final signer walks complete TLV frames past a semantic M. Before this, it
could not find the HMAC in a well-framed M reply with nonzero BER padding
after the HMAC, so the reply kept the HMAC that assembly had computed with
sequence number zero. The signer replaces only HMACs that the reflector
generated; failed incoming digests are copied with I (RFC 8972 §4.8).

The sender's gates scenario sends validly signed replies that are still
unusable: duplicate metadata, changed patterns or padding sizes, impossible
counts, M, C or I flags, and duplicate patterns. None of them adds a BER
sample, and neither do duplicate replies. A reply with an unavailable burst
keeps its count but adds no burst sample. The frozen vectors are regression
inputs, not independent certification.
