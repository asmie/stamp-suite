# RFC 10052 conformance

RFC 10052 Type-12 requirements, implementation and tests.

Revision frozen: RFC 10052, September 2026.
Source: [RFC 10052](https://www.rfc-editor.org/rfc/rfc10052).

Summary: 47 clauses: 38 Compliant, 1 Partial, 0 Gap, 7 N-A, 1 Excluded.

## Scope

RFC 10052 was published from draft-ietf-ippm-asymmetrical-pkts-14. Its section
numbers and codepoints (Type 12, the C flag, the Address Group sub-TLVs) are the
same, so row IDs use those section numbers.

Type 12 is disabled on the reflector by default (`--reflected-control-max-count 0`).
Reply sizing depends on a known route MTU, which only Linux provides; see
[Reply size and route MTU](#reply-size-and-route-mtu). Burst timing is
best-effort; see [Burst timing](#burst-timing). The IPv6 Extension Header Control
sub-TLV (240) carried inside Type 12 is covered in the
[ext-hdr matrix](draft-stamp-ext-hdr.md).

The matrix leaves out keyword boilerplate, editorial and registry instructions,
and requirements on external IP/MPLS networks. The Clause column quotes the RFC,
trimmed with `...`.

## Clauses

| ID | Clause | Level | Role | Status | Evidence |
|---|---|---|---|---|---|
| asym-3-01 | "Length ... MUST NOT be smaller than 12 octets." | MUST NOT | Both | Compliant | `src/tlv/core.rs::REFLECTED_CONTROL_TLV_MIN_VALUE_SIZE` (12); `src/tlv/typed/reflected_control.rs` rejects shorter values and pads to 12. Tests: `test_reflected_control_wire_format_pads_to_min_12_bytes`, `test_reflected_control_invalid_length_rejected`, `a1_reflected_control_min_length_12_pre_14_rejected`. |
| asym-3-02 | "A Session-Sender MUST zero this flag [C] on transmission" | MUST | Sender | Compliant | `src/tlv/core.rs::TlvFlags::for_sender` leaves C clear, and `src/sender/packet.rs::build_reflected_control_tlv` never sets it. No sender code path sets C. |
| asym-3-03 | "the Session-Reflector MUST ignore its value on the receipt of a STAMP test packet" [C flag] | MUST | Reflector | Compliant | `src/receiver/mod.rs::apply_semantic_tlv_processing` uses `src/tlv/list/processing.rs::get_reflected_control_request` and never reads the received C flag. Test: `tests/tlv_flag_semantics.rs::incoming_c_flag_on_request_is_ignored`. |
| asym-3-04 | "A Session-Sender MAY include the Reflected Test Packet Control TLV in a STAMP test packet." | MAY | Sender | Compliant | `src/configuration.rs::Configuration::reflected_control_count`; `src/sender/packet.rs::build_reflected_control_tlv` adds the TLV when count > 1 or `--reflected-control-no-ext-hdr` is set. Test: `build_reflected_control_tlv_only_when_requested`. |
| asym-3-05 | "the Session-Reflector MUST transmit a sequence of reflected test packets according to the following rules" | MUST | Reflector | Compliant | `src/receiver/mod.rs::apply_semantic_tlv_processing` yields a `ReflectedControlBehavior`; both backends send it through `src/receiver/transmit.rs::ReplyQueue`. Test: `tests/burst_transmission_test.rs`. See [decision order](#type-12-decision-order). |
| asym-3-06 | "The length of the reflected test packet MUST be the largest of" [base packet without Extra Padding, or the request aligned to four octets] | MUST | Reflector | Compliant | `src/receiver/mod.rs::apply_semantic_tlv_processing` drops echoed Extra Padding, rounds the request up to four octets and pads if larger. Tests: `reflected_control_strips_echoed_extra_padding`, `reflected_control_pads_to_four_octet_aligned_length`. |
| asym-3-07 | "the Session-Reflector MUST use the Extra Padding TLV ... to increase the length of the reflected test packet" | MUST | Reflector | Compliant | `src/receiver/mod.rs::apply_semantic_tlv_processing` adds `src/tlv/typed/extra_padding.rs::new_zeros`. Tests: `a1_reflected_control_length_padding_within_cap`, `tests/netns_conformance.rs::scenario_6_type12_multi_reply`. |
| asym-3-08 | "If the calculated length ... exceeds the MTU ..., the Session-Reflector MUST set the C flag ... and MUST transmit a single reflected packet of the length equal to MTU" | MUST | Reflector | Partial | `src/receiver/mtu.rs`, `src/receiver/transmit.rs::fit_reply`; Linux only, see [route MTU](#reply-size-and-route-mtu). Tests: `tests/route_mtu_test.rs`, `a1_reflected_control_length_request_exceeds_cap_sets_c_flag`, [namespace test](../testing-netns.md#reply-route-mtu-regression). |
| asym-3-09 | "Otherwise, the Session-Reflector MUST set the C flag to 0 in each reflected test packet" [MTU context] | MUST | Reflector | Compliant | `src/receiver/mod.rs::apply_semantic_tlv_processing` sets C only on the non-conformant branch. Tests in `tests/tlv_flag_semantics.rs`: `a1_reflected_control_length_padding_within_cap`, `c_flag_clear_when_reflected_control_request_within_caps`. |
| asym-3-10 | "The number of reflected test packets in the sequence MUST equal the value of the Number of the Reflected Packets field." | MUST | Reflector | Compliant | `Transmission::send_next` and `ReplyQueue::schedule_next` (`src/receiver/transmit.rs`) send the first reply plus the admitted copies. Test: `tests/burst_transmission_test.rs`. A send failure ends a burst early. |
| asym-3-11 | "the interval between the transmission of two consecutive reflected packets ... MUST be equal to the value in the Interval Between the Reflected Packets field" | MUST | Reflector | Compliant | `ReplyQueue::schedule_next` (`src/receiver/transmit.rs`) schedules each copy one interval after the previous send; intervals below `--reflected-control-min-interval-ns` get C. See [Burst timing](#burst-timing). |
| asym-3-12 | "a Session-Reflector that supports the Reflected Test Control TLV MUST enforce limits on both the data rate (bytes per second) and the total data volume (bytes) of the STAMP payload it generates ..." | MUST | Reflector | Compliant | `src/receiver/mod.rs::apply_semantic_tlv_processing`; see [Type 12 limits](#type-12-limits). Test: `reflected_control_rate_and_volume_limits_set_c`. |
| asym-3-13 | "If a test packet ... would generate traffic that exceeds either of these limits, the Session-Reflector MUST set the C flag to 1, and MUST transmit a single reflected packet" | MUST | Reflector | Compliant | `src/receiver/mod.rs::apply_semantic_tlv_processing` sends one padded reply with C. Tests: `reflected_control_rate_and_volume_limits_set_c`, `reflected_control_count_above_cap_collapses_to_single_reply`, `reflected_control_interval_below_floor_collapses_to_single_reply`. |
| asym-3-14 | "Otherwise, the Session-Reflector MUST set the C flag to 0 in each reflected test packet." [rate/volume context] | MUST | Reflector | Compliant | Same branch as asym-3-09: one non-conformant flag covers the MTU and rate/volume triggers. Test: `tests/tlv_flag_semantics.rs::c_flag_clear_when_reflected_control_request_within_caps`. |
| asym-3-15 | "If the Number of Reflected Packets field is set to zero, the Session-Reflector MUST NOT send any reflected packets." | MUST NOT | Reflector | Compliant | `src/receiver/mod.rs::apply_semantic_tlv_processing` sends no reply to a new count-zero request. See [Type 12 decision order](#type-12-decision-order). Test: `reflected_control_count_zero_suppresses_reply`. |
| asym-3-16 | "Furthermore, in this case, the Session-Reflector SHOULD discard the received STAMP test packet." | SHOULD | Reflector | Compliant | The enabled count-zero branch of `src/receiver/mod.rs::apply_semantic_tlv_processing` discards the request (see asym-3-15). |
| asym-3-17 | "a local policy MAY override this default behavior and specify an alternative handling" | MAY | Reflector | Compliant | With `--reflected-control-max-count 0` the reflector treats Type 12 as unsupported and replies once with U. Non-new requests get the single U-flagged reply of asym-5-08. |
| asym-3.1-01 | "A multicast network that uses an active performance measurement method for In-Service rate estimation MUST include a rate control mechanism that bounds and regulates the generation of measurement packets." | MUST | N-A | N-A | Requirement on the multicast network design, not on a STAMP endpoint. |
| asym-3.1-02 | "The rate control mechanism MUST ensure that probe traffic remains non-intrusive, predictable, and consistent with the operational characteristics of the multicast topology." | MUST | N-A | N-A | Network design requirement, as asym-3.1-01. |
| asym-3.1-03 | "implementations SHOULD provide operators with the ability to configure rate limits and pacing parameters ..." | SHOULD | Reflector | Compliant | `src/configuration.rs::Configuration::reflected_control_max_size` and the other [Type 12 limits](#type-12-limits); `RuntimeCaps` (`src/receiver/limits.rs`) lets the control API change them at run time. |
| asym-3.1.1-01 | "lengths of MAC Address Group Mask and MAC Address Group fields MUST be equal, valid values for the Sub-TLV Length are 4, 12, and 16" | MUST | Both | Compliant | `src/receiver/reflected_control.rs::parse_reflected_control_sub_tlvs` accepts 4, 12 and 16 and splits the value in halves. The sender does not originate this sub-TLV. Test: `l2_group_matches_any_local_length_mismatch_never_matches`. |
| asym-3.1.1-02 | "Any other value MUST be considered by the Session-Reflector as a malformed sub-TLV." | MUST | Reflector | Compliant | `src/receiver/reflected_control.rs::parse_reflected_control_sub_tlvs` skips other lengths, so they take no part in matching. The RFC prescribes no specific response. Test: `tests/tlv_flag_semantics.rs::a1_reflected_control_l2_malformed_length_does_not_drop`. |
| asym-3.1.1-03 | "If the Session-Reflector applies the ... Mask ... and the result is equal to ... the Layer 2 Address Group field, then the Session-Reflector MUST stop processing the ... sub-TLV" | MUST | Reflector | Compliant | `src/receiver/reflected_control.rs::l2_group_matches_any_local` masks each local MAC. Tests: `l2_group_matches_any_local_masked_match`, `a1_reflected_control_l2_match_replies_normally`, netns `scenario_5_address_group_filters`. |
| asym-3.1.1-04 | "If no matches are found, the Session-Reflector MUST stop processing the received packet." [L2] | MUST | Reflector | Compliant | `src/receiver/mod.rs::apply_semantic_tlv_processing` drops the packet without a reply. Tests: `a1_reflected_control_l2_mismatch_suppresses_reply`, `tests/netns_conformance.rs::scenario_5_address_group_filters`. |
| asym-3.1.2-01 | "Sub-TLV Length ... equals either 8 ... or 20 ... Any other value MUST be considered by the Session-Reflector as a malformed sub-TLV." | MUST | Reflector | Compliant | `src/receiver/reflected_control.rs::parse_reflected_control_sub_tlvs` accepts 8 and 20 and skips other lengths. The invalid-length branch is checked by code inspection only; no bad-L3 wire test exists. |
| asym-3.1.2-02 | "Reserved: A three-octet field. The field MUST be set to zeros on transmission" | MUST | Sender | N-A | The sender does not originate the L3 Address Group sub-TLV. The reflector ignores the reserved octets (`src/receiver/reflected_control.rs::parse_reflected_control_sub_tlvs`). |
| asym-3.1.2-03 | "if the Session-Reflector applies it ... and the result is equal to the value in the IP Prefix field, then the Session-Reflector MUST stop processing the ... sub-TLV" | MUST | Reflector | Compliant | `src/receiver/reflected_control.rs::l3_group_matches_any_local` masks each local address of the same family. Tests: `a1_reflected_control_l2_and_l3_both_match_replies_normally`, netns `scenario_5_address_group_filters`. |
| asym-3.1.2-04 | "If no matches are found, the Session-Reflector MUST stop processing the received packet." [L3] | MUST | Reflector | Compliant | `src/receiver/mod.rs::apply_semantic_tlv_processing` drops the packet without a reply. Tests: `a1_reflected_control_l3_mismatch_suppresses_reply`, `tests/netns_conformance.rs::scenario_5_address_group_filters`. |
| asym-4.1.1-01 | "A service subscriber performing extensive rate measurements on the operational network, SHOULD consider the Consideration 6 ... and be mindful of limits placed on their service by the Service Provider." | SHOULD | N-A | N-A | Guidance for the operator's judgment, with no protocol action to implement. |
| asym-4.2-01 | "The Session-Reflector MUST use the source IP address of the received STAMP test packet as the destination IP address of the reflected test packet" | MUST | Reflector | Compliant | `Transmission::send_next` (`src/receiver/transmit.rs`) sends to the request source unless an authorized Return Path alternate applies. Tests: `tests/burst_transmission_test.rs`, loopback round trips. |
| asym-4.2-02 | "and MUST use one of the IP addresses associated with the node as the source IP address for that packet" | MUST | Reflector | Compliant | Both backends reply from UDP sockets bound to a local or wildcard address (`src/receiver/nix.rs`, `src/receiver/pnet.rs`), so the OS chooses a local source. Linux source pinning uses only a matched local Destination Node Address. |
| asym-4.3-01 | "a Session-Sender MUST NOT include a Return Path Control Code Sub-TLV with the Control Code flag set to No Reply Requested in the same test packet as the Reflected Test Packet Control TLV ..." | MUST NOT | Sender | Compliant | `src/configuration.rs::Configuration::validate` rejects the combination. Test: `test_return_path_no_reply_conflicts_with_reflected_control`. |
| asym-4.3-02 | "A Session-Reflector that supports both TLVs MUST set the U flag to 1 in Return Path and Reflected Test Packet Control TLVs in the reflected STAMP packet." | MUST | Reflector | Compliant | `src/receiver/mod.rs::apply_semantic_tlv_processing` sets U on both TLVs and sends one normal reply. Test: `tests/tlv_flag_semantics.rs::return_path_no_reply_conflict_sets_u_on_both_tlvs`. |
| asym-4.3-03 | "the Session-Reflector SHOULD log a notification to inform an operator about the misconstructed STAMP packet." | SHOULD | Reflector | Compliant | `src/receiver/mod.rs::apply_semantic_tlv_processing` logs a rate-limited warning (`warn_throttled!`) on the asym-4.3-02 path. |
| asym-5-01 | "spoofed STAMP test packets with the Reflected Test Packet Control TLV can be exploited to conduct a Denial-of-Service (DoS) attack. Hence, implementations MUST use an identity protection mechanism." | MUST | Both | Compliant | Authenticated mode (`src/configuration.rs::AuthMode`) and the HMAC TLV (`src/crypto.rs::HmacKeySet`); `--max-pps` limits replies per source. Use is the operator's choice (asym-5-03). |
| asym-5-02 | "an implementation ... MUST provide administrative control of support of the Reflected Test Packet Control TLV ... with it being disabled by default." | MUST | Reflector | Compliant | `src/configuration.rs::Configuration::reflected_control_max_count` defaults to 0 (disabled, U reply); the control API can change it. Tests: `test_reflected_control_max_count_defaults_to_zero`, `reflected_control_disabled_by_default_emits_no_extra_copies`. |
| asym-5-03 | "either STAMP authentication mode [RFC8762] or HMAC TLV [RFC8972] SHOULD be used for a STAMP test session containing the Reflected Test Packet Control TLV." | SHOULD | Both | Compliant | Type 12 processing and HMAC signing share one path in `src/receiver/assemble.rs::assemble_unauth_answer_with_tlvs` and `assemble_auth_answer_with_tlvs`. Any combination is allowed. |
| asym-5-04 | "a Session-Reflector implementation that supports the new TLV MUST provide a mechanism to limit the reflection rate and volume of STAMP test packets" | MUST | Reflector | Compliant | Same mechanisms as asym-3-12; see [Type 12 limits](#type-12-limits). |
| asym-5-05 | "parameters in the first STAMP test packet with the Reflected Test Packet Control TLV MUST be selected conservatively." | MUST | Sender | Compliant | `src/configuration.rs::Configuration::reflected_control_count` defaults to 1, so `src/sender/packet.rs::build_reflected_control_tlv` sends no TLV; length defaults to 0 and interval to 1 ms. |
| asym-5-06 | "a Session-Sender SHOULD sign packets using the HMAC TLV when sending such messages in unauthenticated mode [RFC8762]." | SHOULD | Sender | Compliant | `src/configuration.rs::Configuration::hmac_key` and `--hmac-key-file` work in unauthenticated mode together with `--reflected-control-*`; `src/configuration.rs::Configuration::validate` places no restriction on the combination. |
| asym-5-07 | "a STAMP Session-Reflector SHOULD use the value of the Sequence Number field [RFC8762] of the received STAMP test packet" [to detect replays] | SHOULD | Reflector | Compliant | `src/receiver/replay.rs::evaluate_replay`, `Session::classify_replay` and `Session::commit_replay` (`src/session.rs`); see [Replay handling](#replay-handling). Tests: `non_monotonic_control_gets_one_u_flagged_reply`, `tests/replay_control_test.rs`. |
| asym-5-08 | "If that value ... is not monotonically increasing, then the Session-Reflector MUST respond with a single reflected packet, setting the U flag to 1" | MUST | Reflector | Compliant | `src/receiver/mod.rs::apply_semantic_tlv_processing` sets U and ignores count, padding and interval. Tests: `non_monotonic_control_preserves_tlv_validation_and_group_filters`, `non_monotonic_control_does_not_execute_zero_count_or_disabled_requests`, `tests/replay_control_test.rs`. |
| asym-5-09 | "A Session-Sender SHOULD NOT send the next STAMP test packet with the Reflected Test Packet Control TLV before the Session-Reflector is expected to complete transmitting all reflected packets ..." | SHOULD NOT | Sender | Compliant | `src/configuration.rs::Configuration::reflected_burst_pacing_warning` warns when `--send-delay` is below (count - 1) x interval. Pacing is unchanged. |
| asym-5-10 | "When planning In-Service capacity measurement operators SHOULD follow recommendations formulated in Sections 3 and 7 of [RFC7497]." | SHOULD | N-A | N-A | Operator planning guidance that refers to another document. |
| asym-5-11 | "Implementations and operational procedures SHOULD ensure that the use of STAMP for In-Service measurement does not unintentionally degrade data traffic or lead to misinterpretation of ECN-related congestion signals." | SHOULD | N-A | N-A | Deployment goal with no concrete action. CoS/ECN behavior is covered in the [CoS/ECN matrix](draft-stamp-cos-ecn.md). |
| asym-5-12 | "Appropriate thresholds and mitigation actions remain deployment-specific and SHOULD be guided by operator policy and network performance objectives." | SHOULD | N-A | N-A | Operator policy guidance with no protocol action. |
| asym-5-13 | "Section 3.1.5 of [RFC8085] determines that a UDP congestion control SHOULD respond quickly to experienced congestion and account for loss rate and response time when choosing a new rate." | SHOULD | Both | Excluded | The RFC cites RFC 8085 informatively in its security discussion. General RFC 8085 congestion-control conformance is outside this Type 12 matrix. |

## Notes

### Type 12 decision order

`src/receiver/mod.rs::apply_semantic_tlv_processing` handles a Type 12 request
in this order, after identity, TLV integrity and Address Group checks:

1. Return Path "no reply requested" with a nonzero Type 12 request: U on both
   TLVs, one normal reply, and a warning in the log (asym-4.3-02, asym-4.3-03).
2. Replayed, reordered or out-of-window sequence number: U on Type 12, one
   reply, request fields ignored (asym-5-08).
3. Type 12 disabled (`--reflected-control-max-count 0`): U on Type 12, one
   normal reply, as a reflector without Type 12 support (RFC 8972 §4).
4. Count zero: no reply; the request is discarded (asym-3-15, asym-3-16).
5. A count, interval, rate or volume limit exceeded: one padded reply with C
   set (asym-3-13).
6. Otherwise: the first reply plus the requested copies, with C clear.

### Type 12 limits

Each request is checked against `--reflected-control-max-count` (default 0,
disabled), `--reflected-control-max-size` (default 1500 bytes),
`--reflected-control-min-interval-ns` (default 1000 ns),
`--reflected-control-max-rate` (bytes per second, reply size x 10^9 / interval)
and `--reflected-control-max-volume` (bytes, reply size x count). The control
API can change these at run time through `RuntimeCaps`
(`src/receiver/limits.rs`). `--max-pps` limits replies per source address and
counts every copy.

### Reply size and route MTU

On Linux the reflector looks up the route MTU for the actual reply destination
before each copy (`src/receiver/mtu.rs`), subtracts IP, UDP and SRH overhead,
and trims padding in `fit_reply` (`src/receiver/transmit.rs`) without cutting
mandatory fields. Route and link notifications plus a 250 ms cache expiry track
changes; Don't Fragment prevents fragmentation if the route changes between
lookup and send. A trimmed reply is sent once with C set.

Limits behind the Partial score of asym-3-08:

- When the budget leaves a remainder of 1 to 3 bytes, no TLV header fits, so the
  reply stays slightly short of the MTU.
- If the route MTU cannot be determined, the reply is dropped. Other platforms
  have no route MTU lookup, so they drop replies to admitted Type 12 requests.
- This is route MTU lookup, not active path MTU probing.

### Burst timing

`ReplyQueue::schedule_next` (`src/receiver/transmit.rs`) schedules each copy
one interval after the previous successful send, on both backends; the pnet
capture loop does not sleep between copies. OS scheduling and reply
finalization can lengthen the gap on the wire. Neither the implementation nor
the loopback tests establish exact nanosecond equality, so asym-3-11 is
Compliant only with this timing qualification.

### Replay handling

Replay state is kept per session, scoped by both UDP endpoints, the SSID and
the optional sender Micro-session ID. `ProcessingContext::replay_verdict`
carries the verdict into Type 12 processing. Both backends send the single
U-flagged reply through the normal finalization and signing path.
`--drop-replayed` does not suppress these Type 12 replies.
`tests/replay_control_test.rs` checks reply count, size and U flag, both HMACs,
stateless and stateful sequences, wraparound, SSID isolation and both drop
policies over IPv4 and IPv6.
