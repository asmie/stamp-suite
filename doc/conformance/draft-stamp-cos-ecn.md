# draft-ietf-bpm-stamp-cos-ecn conformance

CoS and ECN requirements, implementation and tests.

Revision frozen: draft-ietf-bpm-stamp-cos-ecn-00, 16 November 2026.
Source: [draft-ietf-bpm-stamp-cos-ecn-00](https://www.ietf.org/archive/id/draft-ietf-bpm-stamp-cos-ecn-00.txt).

Summary: 31 clauses: 19 Compliant, 3 Partial, 0 Gap, 9 N-A, 0 Excluded.

## Scope

This is an Internet-Draft; the matrix covers BPM revision -00, which replaces
IPPM revision -02. The wire layout and congestion-response requirements are
unchanged, but section 3.2 changes DSCP fallback selection and ECN capability
reporting. DSCP fallback and ECN capability reporting follow BPM -00.
Empty DSCP policies suppress processed CoS replies, as no permitted value
exists; a restricted policy also requires an enforceable backend marking.
The changed clauses are paraphrased below, with stable IDs retained for existing
requirements. Operator SHOULDs are recorded separately from endpoint behavior.

See [successor changes](#bpm-00-successor-changes).

The supported profile includes the reflector's DSCP and ECN admission policy
(`--allowed-dscp`, `--allowed-dscp-for`, `--allowed-ecn`) and the sender's
AIMD rate response to CE marks. The sender reads reverse-path ECN from IP
metadata on Linux and macOS; on other platforms it uses only the forward-path
EC2 feedback in the reflected CoS TLV. Windows marking is
reported unavailable with RPE=01, preserving any independent C flag. The
deprecated Winsock IP_TOS API cannot prove wire marking. macOS sticky marking is checked by socket-option readback;
Linux uses per-message ancillary marking. Microsoft documents the
[IP_TOS option](https://learn.microsoft.com/en-us/windows/win32/winsock/ipproto-ip-socket-options)
as unsuitable for setting ToS. Readback does not prove delivery
or detect downstream remarking; deployment captures remain necessary.

## Clauses

| ID | Clause | Level | Role | Status | Evidence |
|---|---|---|---|---|---|
| cos-ecn-3.1-1 | "The STAMP Session-Sender MAY include a CoS TLV in the STAMP test packet" | MAY | Sender | Compliant | `src/configuration.rs::Configuration::cos`, `src/configuration.rs::Configuration::dscp`. `src/sender.rs::run_sender_with_output` adds the CoS TLV only with `--cos`. |
| cos-ecn-3.1-2 | "CoS (Class of Service) Type: one-octet field; the value MUST be set to 4" | MUST | Both | Compliant | The type is 4 and value length is 4. Tests: `tests/sender_measurement_test.rs::sender_cos_fields_and_automatic_ect_response_reach_the_wire`, `tests/cos_ecn_wire_test.rs::reflector_cos_bytes_and_wire_markings_follow_ingress_and_admission_policy` check actual request/reply bytes in both families and all key modes. |
| cos-ecn-3.1-3 | "a Session-Sender MUST set the value of the RPD field to 0b00 on transmission" | MUST | Sender | Compliant | `ClassOfServiceTlv::new` (`src/tlv/typed/cos.rs`) sets RPD to 0; `test_cos_tlv_new` (`src/tlv/typed/cos.rs`). Wire tests: `tests/sender_measurement_test.rs::sender_cos_fields_and_automatic_ect_response_reach_the_wire`, `tests/cos_ecn_wire_test.rs::reflector_cos_bytes_and_wire_markings_follow_ingress_and_admission_policy` check originated RPD/RPE/reserved bits and normalization of dirty received fields on processed replies. |
| cos-ecn-3.1-4 | "a Session-Sender MUST set the value of the RPE field to 0b00 on transmission" | MUST | Sender | Compliant | `ClassOfServiceTlv::new` (`src/tlv/typed/cos.rs`) sets RPE to 0; `test_cos_tlv_new` (`src/tlv/typed/cos.rs`). Wire tests: `tests/sender_measurement_test.rs::sender_cos_fields_and_automatic_ect_response_reach_the_wire`, `tests/cos_ecn_wire_test.rs::reflector_cos_bytes_and_wire_markings_follow_ingress_and_admission_policy` check originated RPD/RPE/reserved bits and normalization of dirty received fields on processed replies. |
| cos-ecn-3.1-5 | "Reserved: twelve-bit field; MUST be zeroed on transmission and ignored on receipt" | MUST | Both | Compliant | `encode_value` and `decode_value` (`src/tlv/typed/cos.rs`); the reflector zeroes the bits in `update_cos_value_in_place` (`src/tlv/list/processing.rs`). Tests: `test_cos_tlv_wire_format_boundary_values` (`src/tlv/typed/cos.rs`), `test_cos_reserved_bits_are_zeroed` (`src/receiver/tests.rs`). Wire tests: `tests/sender_measurement_test.rs::sender_cos_fields_and_automatic_ect_response_reach_the_wire`, `tests/cos_ecn_wire_test.rs::reflector_cos_bytes_and_wire_markings_follow_ingress_and_admission_policy` check originated RPD/RPE/reserved bits and normalization of dirty received fields on processed replies. |
| cos-ecn-3.2-1 | "A STAMP Session-Reflector that receives a test packet with the CoS TLV MUST include the CoS TLV in the reflected test packet" | MUST | Reflector | Compliant | Received processable CoS TLVs remain present with the original length. Test: `tests/cos_ecn_wire_test.rs::reflector_cos_bytes_and_wire_markings_follow_ingress_and_admission_policy` checks every copy, including global/destination admission rejection and interleaved ordinary traffic. |
| cos-ecn-3.2-2 | "The Session-Reflector MUST copy the value of the DSCP and ECN fields of the IP header of the received STAMP test packet into the DSCP2 and EC2 fields" | MUST | Reflector | Compliant | `src/receiver/mod.rs::apply_semantic_tlv_processing` passes the received DSCP and ECN to `src/tlv/list/processing.rs::update_cos_value_in_place`. `test_cos_tlv_draft_figure_cross_vector` (`src/tlv/typed/cos.rs`) checks bytes computed by hand from the draft's Figure 1. Wire test: `tests/cos_ecn_wire_test.rs::reflector_cos_bytes_and_wire_markings_follow_ingress_and_admission_policy` checks actual ingress fields, admitted/policy-refused reply markings and RPD/RPE on every copy; capability-failure coverage remains injected. |
| cos-ecn-3.2-3 | "The Session-Reflector MUST verify whether the use of the value of the DSCP1 field is permitted in the reflected test packet" | MUST | Reflector | Compliant | `CosAdmissionPolicy` (`src/cos_policy.rs`), applied in `src/receiver/mod.rs::apply_semantic_tlv_processing` against the reply destination. `cos_tlv_destination_scoped_policy_decides_per_peer` (`tests/tlv_flag_semantics.rs`). See [admission policy](#admission-policy). Wire test: `tests/cos_ecn_wire_test.rs::reflector_cos_bytes_and_wire_markings_follow_ingress_and_admission_policy` checks actual ingress fields, admitted/policy-refused reply markings and RPD/RPE on every copy; capability-failure coverage remains injected. |
| cos-ecn-3.2-4 | When DSCP1 is permitted, use it in the reply IP header and set RPD=00. | MUST | Reflector | Compliant | `Transmission::send_next` and `send_datagram` (`src/receiver/transmit.rs`), `tests/burst_transmission_test.rs`. See [per-copy CoS](#per-copy-cos). Wire test: `tests/cos_ecn_wire_test.rs::reflector_cos_bytes_and_wire_markings_follow_ingress_and_admission_policy` checks actual ingress fields, admitted/policy-refused reply markings and RPD/RPE on every copy; capability-failure coverage remains injected. |
| cos-ecn-3.2-5 | If DSCP1 is refused, use received DSCP2 as the fallback only when local policy permits it, with RPD=01. | MUST | Reflector | Compliant | `src/cos_policy.rs::DscpSet::select` checks both candidates against the effective destination set. `src/receiver/cos.rs::CosReplyPolicy` retains both primary and original-source policies for retries. Tests: `src/cos_policy.rs::selection_tests::dscp_selection_exhausts_candidate_pairs_and_policy_boundaries`, `src/receiver/transmit/dscp_tests.rs::dscp_route_retry_reselects_policy_and_sets_c_only_for_a_third_value`, `tests/cos_ecn_wire_test.rs::reflector_cos_bytes_and_wire_markings_follow_ingress_and_admission_policy`. |
| cos-ecn-3.2-6 | "The Session-Reflector MUST set the ECN value in the IP header of the reflected STAMP test packet to the value of the EC1 field, if it is permitted and capable to do so" | MUST | Reflector | Compliant | `CosAdmissionPolicy` (`src/cos_policy.rs`) applies `--allowed-ecn`; a refused value forces Not-ECT and RPE 0b10. `cos_tlv_refused_ecn_forces_not_ect` (`tests/tlv_flag_semantics.rs`), `tests/burst_transmission_test.rs`. Wire test: `tests/cos_ecn_wire_test.rs::reflector_cos_bytes_and_wire_markings_follow_ingress_and_admission_policy` checks actual ingress fields, admitted/policy-refused reply markings and RPD/RPE on every copy; capability-failure coverage remains injected. |
| cos-ecn-3.2-7 | "If the Session-Reflector is able to set the ECN value ... to the EC1 value, it MUST then set the RPE field ... to the value 0b11" | MUST | Reflector | Compliant | `Transmission::send_next` and `send_datagram` (`src/receiver/transmit.rs`), `tests/burst_transmission_test.rs`. See [per-copy CoS](#per-copy-cos). Wire test: `tests/cos_ecn_wire_test.rs::reflector_cos_bytes_and_wire_markings_follow_ingress_and_admission_policy` checks actual ingress fields, admitted/policy-refused reply markings and RPD/RPE on every copy; capability-failure coverage remains injected. |
| cos-ecn-3.2-8 | If EC1 cannot be applied but Not-ECT can, use Not-ECT in the reply IP header and report RPE=10. | MUST | Reflector | Compliant | `cos_unable_fallback_tos` and `set_cos_policy_rejected` (`src/receiver/reply_bytes.rs`), `cos_failure_uses_zero_ecn_fallback_and_resigns` (`src/receiver/transmit/tests.rs`). See [marking fallback](#marking-fallback). |
| cos-ecn-3.2-9 | Report RPE=01 when neither EC1 nor Not-ECT can be applied. | MUST | Reflector | Compliant | `src/receiver/reply_bytes.rs::set_cos_marking_unavailable` sets RPE=01 and preserves independent C. Tests in `src/receiver/transmit/tests.rs`: `unavailable_ecn_sets_rpe01_on_every_copy_and_preserves_routing_and_signatures`, `unavailable_ecn_preserves_independent_c_in_signed_bursts`, `failed_not_ect_request_needs_no_identical_marking_retry`, `cos_unavailable_preserves_opaque_echoes_and_received_fields`. These inject capability failure across burst copies and key/family combinations; `windows_sender_sends_cos_unavailable_and_ordinary_replies` exercises the native Windows send path. See [marking fallback](#marking-fallback). |
| cos-ecn-3.2-10 | If policy permits neither requested nor received DSCP, choose a locally permitted DSCP and report RPD=01 with C set. | MUST | Reflector | Compliant | Select the lowest admitted value, preserving observed DSCP2/EC2. Empty sets suppress the CoS reply; restricted sets cannot fall through to unmarked sends. Tests: `src/receiver/transmit/dscp_tests.rs::dscp_admission_marks_signed_bursts_and_counts_only_successful_third_values`, `src/receiver/transmit/dscp_tests.rs::dscp_marking_retry_never_uses_forbidden_received_value_or_unmarked_restricted_send`, `src/receiver/transmit/dscp_tests.rs::windows_restricted_dscp_sends_nothing_and_permissive_reply_reports_rpe01`, `tests/cos_ecn_wire_test.rs::empty_dscp_policy_drops_cos_but_keeps_base_sessions_usable`, `tests/cos_ecn_wire_test.rs::reflector_cos_bytes_and_wire_markings_follow_ingress_and_admission_policy`. See [admission policy](#admission-policy). |
| cos-ecn-3.4-1 | Observe EC2 and be capable of reducing the sending rate on CE [multiple CoS packets within an RTT with ECT0 or ECT1] | MUST | Sender | Compliant | `src/sender/validate.rs::validate_reflected_tlvs`, `src/sender.rs::process_response`, `on_ce_observed` (`src/rate_control.rs`). `test_process_response_forward_path_ce_backs_off_congestion_controller` (`src/sender/tests.rs`). See [sender rate response](#sender-rate-response). Binary test: `tests/sender_measurement_test.rs::sender_cos_fields_and_automatic_ect_response_reach_the_wire` verifies automatic ECT0/ECT1 controller activation and a CE backoff with independent peer signatures. |
| cos-ecn-3.4-2 | Observe reflected IP ECN and be capable of reducing the sending rate on CE [ECT0 or ECT1 in EC1] | MUST | Sender | Partial | `AimdController` (`src/rate_control.rs`). Tests: `test_process_response_forward_path_ce_backs_off_congestion_controller`, `test_process_response_reverse_path_ce_backs_off_congestion_controller` (`src/sender/tests.rs`). Reverse ECN is read on Linux and macOS only. |
| cos-ecn-3.4-3 | Observe reflected IP ECN and be capable of adjusting future Reflected Test Packet Control parameters on CE [CoS TLV with Type 12] | MUST | Sender | Partial | Normal sends and Access Report retries scale the Type 12 interval by the current AIMD factor; the reply count is unchanged. `test_wait_phase_retransmit_still_carries_scaled_control_tlv` and `ce_backoff_paces_zero_interval_bursts_but_preserves_control_only_zero` (`src/sender/tests.rs`). Reverse IP ECN is unavailable outside Linux/macOS. |
| cos-ecn-3.4-4 | Congestion response must be consistent with RFC 3168 and RFC 9330. | MUST | Sender | Partial | `src/rate_control.rs::AimdController` reduces the requested rate on CE, including Type 12 pacing, but per-reply interval recovery is not an RTT/window-based Classic controller or a demonstrated scalable L4S controller. See [response limits](#response-limits); full consistency evidence remains open. |
| cos-ecn-3.4-5 | Enable congestion response except for controlled measurements agreed with network operators. | MUST | Sender | Compliant | `src/sender/run.rs::SenderRun::open` enables AIMD for CoS ECT0/ECT1 without a disable override. Test: `tests/sender_measurement_test.rs::sender_cos_fields_and_automatic_ect_response_reach_the_wire` invokes the binary in both families and all key modes, captures the originated CoS and verifies controller presence plus an actual backoff on signed forward CE. Default/no-CoS and CoS Not-ECT/CE inputs are negative controls. This establishes enablement/capability; controller consistency remains Partial below. |
| cos-ecn-3.4-6 | For controlled measurements, limit rate and duration, including reflected traffic, and prevent impact outside the test. | SHOULD | Operator | N-A | Operator responsibility; [operator guidance](../usage.md#ecn-deployment-and-interpretation) maps duration/count, send delay and reflector caps. No controlled-measurement override is implemented. |
| cos-ecn-4.1-1 | Both peers should support the extended CoS TLV. | SHOULD | Both | Compliant | `src/tlv/typed/cos.rs::ClassOfServiceTlv`; [deployment guidance](../usage.md#ecn-deployment-and-interpretation) requires checking peer support and on-wire behavior. |
| cos-ecn-4.1-2 | Detect legacy reverse-path support from RPE and limit analysis accordingly. | SHOULD | Sender | Compliant | `src/sender/ecn.rs::EcnSummary` retains RPE and reports legacy/unconfirmed reverse comparisons as unknown, including peers that zero EC1. C, request mismatch, refusal and missing IP metadata also gate reverse analysis. Tests: `src/sender/ecn/tests.rs::ecn_unknown_reasons_are_exclusive_and_do_not_fabricate_transitions`, `src/sender/ecn/tests.rs::ecn_forward_baseline_is_local_marking_and_reverse_pairs_stay_per_reply`, `src/sender/run/admission_tests.rs::ecn_reporting_counts_only_admitted_distinct_copies`. See [directional diagnostics](../measurements.md#directional-ecn-diagnostics). Controlled Linux rewrite evidence: `tests/ecn_path_test.rs::kernel_rewrites_match_captured_packets_and_directional_reports` checks real endpoints, captures, policy refusal and subsequent CE changes (ignored locally; required in namespace CI). This limits analysis without claiming physical path localization or changing AIMD. |
| cos-ecn-4.1-3 | Verify reflector platform ECN setting/reporting capability. | SHOULD | Operator | N-A | [Deployment guidance](../usage.md#ecn-deployment-and-interpretation); Linux wire coverage: `tests/burst_transmission_test.rs`. Windows QoS support and native macOS capture evidence remain outside these tests. |
| cos-ecn-4.2-1 | Understand and document local DSCP/ECN policies. | SHOULD | Operator | N-A | [CoS policy](../usage.md#cos-and-location-policy) documents global, destination-scoped and ECN admission. |
| cos-ecn-4.2-2 | Coordinate ECN handling across administrative domains. | SHOULD | Operator | N-A | [Deployment guidance](../usage.md#ecn-deployment-and-interpretation). |
| cos-ecn-4.3-1 | Collect and analyze EC2, reflected IP ECN and RPE. | SHOULD | Operator | N-A | [Deployment guidance](../usage.md#ecn-deployment-and-interpretation) requires capture alongside current aggregate CE statistics; dedicated field output remains follow-up work. |
| cos-ecn-4.4-1 | Examine EC2/RPE and reflected IP ECN together when troubleshooting. | SHOULD | Operator | N-A | [Deployment guidance](../usage.md#ecn-deployment-and-interpretation) distinguishes policy rejection, platform inability and network remarking. |
| cos-ecn-4.5-1 | Bound automated measurement traffic and obey congestion response requirements. | SHOULD | Operator | N-A | [Deployment guidance](../usage.md#ecn-deployment-and-interpretation), including Type 12 rate/volume caps. |
| cos-ecn-4.6-1 | Verify interoperability and reverse ECN support before relying on bidirectional results. | SHOULD | Operator | N-A | [Deployment guidance](../usage.md#ecn-deployment-and-interpretation); absence of reverse metadata is explicitly a platform limit. |
| cos-ecn-6-1 | Consider HMAC TLVs and dynamic destination ports to mitigate CoS tampering or identification. | Descriptive | Operator | N-A | [ECN security](../security.md#ecn-measurement-integrity) maps existing key/TLV verification and port options; port choice does not authenticate traffic. |

## Notes

### BPM 00 successor changes

The [IPPM -02 predecessor](https://www.ietf.org/archive/id/draft-ietf-ippm-stamp-cos-ecn-02.txt)
was replaced on 16 November 2026. Comparing sections 1 through 6 shows changes
to DSCP fallback, ECN inability signaling and its legacy-interoperability
explanation, plus replacement of the Type 12 draft reference with RFC 10052.
The Type 4 layout and section 3.4 congestion requirements are unchanged.

DSCP fallback admits received DSCP2 before using it. If neither requested nor
received DSCP is allowed, it selects the lowest permitted value and sets RPD=01
and C. DSCP2 remains the ingress observation. An empty allowed set suppresses
processed CoS replies. A backend that cannot enforce a restricted set also
suppresses the reply instead of sending with an unknown DSCP.

ECN capability reporting now emits RPE=01 when neither EC1 nor Not-ECT can be
applied, preserving independent reasons for C. Sender diagnostics classify it
as `reflector_marking_unavailable`, without inferring reverse bleaching or CE.
`src/sender/run/admission_tests.rs::ecn_reporting_counts_only_admitted_distinct_copies`
checks independently signed replies, duplicate admission and serialized fields.

The DSCP wire tests now cover admitted DSCP2 and third-value fallback, including
both address families and open, keyed-open and authenticated modes.
Congestion-controller and platform Partial rows remain open. A successful metadata-monitor run only establishes that this
reviewed revision is current.

### Reviewed wire and enablement evidence (10 November 2026)

`tests/cos_ecn_wire_test.rs::reflector_cos_bytes_and_wire_markings_follow_ingress_and_admission_policy`
uses independent packet bytes and Linux receive metadata in IPv4/IPv6 and
open/keyed-open/authenticated modes. It checks observed DSCP2/EC2 against IP
headers set separately from the TLV, global/scoped DSCP admission, ECN refusal,
all ECN codepoints, twelve-bit Reserved normalization, and final markings and
signatures on every burst copy. An interleaved ordinary reply retains its own
marking. A genuine RFC-only zero-reserved request also verifies the extended
reflector's RPE response. The original RFC sixteen-bit rule is Partial in the
[RFC matrix](rfc8972.md#cos-format-profiles).

`tests/sender_measurement_test.rs::sender_cos_fields_and_automatic_ect_response_reach_the_wire`
captures originated Type/Length/RPD/RPE/Reserved values and verifies automatic
controller activation for CoS ECT0/ECT1, plus a backoff on an independently
signed forward CE report. Default/no-CoS and non-ECT inputs are negative controls.
This is enablement/response-capability evidence; the existing controller
consistency and unsupported reverse-metadata Partial rows remain open.
The Linux wire checks do not establish hardware, native-platform, downstream
remarking or real platform-failure behavior; capability-failure tests remain
explicitly injected.

### Admission policy

`--allowed-dscp` sets the DSCP values permitted on processed CoS replies, and
`--allowed-dscp-for PREFIX/LEN=SPEC` overrides it for reply destinations in a
prefix (the longest matching prefix wins). `--allowed-ecn` does the same for
EC1. Semantic processing admits DSCP1, then DSCP2, then the lowest permitted
value. An empty set suppresses the reply. The two effective DSCP sets are
retained for the primary destination and original sender; return-path retries
reselect marking and C before signing. Independent C flags remain intact.
No-CoS traffic and opaque integrity-failure echoes do not request this policy.
The `cos_dscp_fallback` counter records successful replies using a third value;
failed attempts and discarded replies do not count.

### Per-copy CoS

`Transmission::send_next` (`src/receiver/transmit.rs`) applies the admitted
CoS value to every reply copy. On Linux, `send_datagram` sets IP_TOS or
IPV6_TCLASS per message. Other Unix platforms set and read back the socket
option immediately before their single sending task transmits. Windows
reports marking unavailable with RPE=01. `tests/burst_transmission_test.rs`
checks that on-wire CoS stays correct when a request with a different CoS
arrives between copies.

### Marking fallback

Only a typed option-application error triggers the CoS fallback. A routing,
queue, MTU or datagram failure does not establish that marking failed and
must not change RPD/RPE/C. On non-Linux Unix, the sole send owner sets and
reads back the sticky ToS byte; failures or ignored values invalidate its
cache. Linux carries ToS in ancillary data for each datagram; a failed
`sendmsg` cannot identify which ancillary option failed, so it is handled as
a datagram failure, without inventing CoS evidence.

After a marking error, retry with Not-ECT. Use received DSCP only if admitted;
otherwise retain an admitted DSCP1 or the locally selected third value. If the
initial byte already equals the fallback, do not repeat the same operation.
If marking still cannot be applied, unrestricted DSCP policies can send without
the marking operation and report RPE=01. Restricted policies suppress the reply,
since an unknown DSCP cannot be assumed permitted. Each attempt is timestamped
and signed again; only a full datagram send advances counters. Routing, source
pinning and MTU policy remain intact. A fallback to the original sender
re-evaluates its policy, including removing only locally generated CoS C from
a failed third-value attempt.

Windows therefore reports RPE=01 for unrestricted CoS requests and suppresses
restricted CoS replies; ordinary replies bypass the unsupported marking operation.

Tests in `src/receiver/transmit/tests.rs` cover setter and readback failures,
silently ignored values, cache invalidation, datagram versus option failures,
opaque echoes, every burst copy, IPv4/IPv6 and both authentication modes.
`cos_failure_uses_zero_ecn_fallback_and_resigns` checks successful fallback;
`unavailable_ecn_sets_rpe01_on_every_copy_and_preserves_routing_and_signatures`
checks final RPE=01 and both HMACs. These are injected capability failures;
`windows_sender_sends_cos_unavailable_and_ordinary_replies` exercises native
Windows UDP sends with RPE=01. `tests/burst_transmission_test.rs` supplies actual
Linux wire marking evidence. Neither test establishes third-party support
for the successor's RPE=01 meaning.

### Sender rate response

`validate_reflected_tlvs` reports forward-path CE only from a usable reflected
CoS TLV that passes the U, M, I and HMAC checks. `process_response` applies
`on_ce_observed` after Micro-session ID and SSID admission, so a rejected reply
changes no rate state (`mismatched_ssid_preserves_measurement_and_control_state`
in `src/sender/tests.rs`). The sender enables
AIMD pacing when `--cos` is set with ECT0 or ECT1 (`--ecn 2` or `--ecn 1`);
`--ecn-backoff-factor`, `--ecn-max-delay` and `--ecn-recovery-step` tune it.
`AimdController` backs off once per accepted CE reply. Reverse-path ECN comes
from IP metadata and is not covered by STAMP HMAC.

### Response limits

The default backoff factor of 2 doubles the interval and halves the requested
probe rate, up to the configured maximum delay. It also scales future Type 12
intervals; a zero burst interval uses a 1 ms floor before scaling while backed off.
Control-only requests keep their required zero interval. Reply counts remain
unchanged. Response remains enabled for CoS ECT0/ECT1 and has no
controlled-measurement disable option.

Duration rounding cannot stall backoff below the cap: factors just above one
advance the stored interval by at least 1 ns. This is arithmetic progress,
not nanosecond wire-timing evidence. Tests:
`src/rate_control.rs::near_unity_backoff_makes_progress_until_the_cap`,
`src/rate_control.rs::every_ce_increases_the_interval_unless_capped` and
`tests/sender_measurement_test.rs::near_unity_ce_factors_do_not_stall_sender_backoff`.

The zero-gap burst floor uses the controller's backoff state, independently
of its scale factor. With a zero probe interval, a 1 ms cap or partial recovery
below 1 ms can leave the factor at one while still backed off. Tests:
`src/sender/tests.rs::zero_base_bursts_stay_paced_at_the_cap_and_during_partial_recovery`
and `src/sender/run/congestion_tests.rs::backed_off_zero_base_bursts_keep_the_floor_on_wire`
cover these transitions, full recovery, unchanged nonzero burst gaps and
independently verified probe bytes/signatures across both IP families and
all three key modes.

Scaling always uses the original draw and interval, avoiding accumulated
rounding error across small increases; each new probe resets that reference.
This is deadline arithmetic evidence, not sub-timer wire-accuracy evidence.
CE also extends the pending probe deadline, scaling the existing Poisson draw
where applicable. Recovery does not shorten that wait, and the duration limit
still caps it. Deadline tests:
`src/sender/schedule/timeline_tests.rs::ce_extends_pending_deadline_and_recovery_cannot_shorten_it`,
`src/sender/schedule/timeline_tests.rs::ce_scales_the_existing_poisson_draw_without_resampling`,
`src/sender/schedule/timeline_tests.rs::small_backoff_steps_accumulate_against_the_original_poisson_draw`,
`src/sender/schedule/timeline_tests.rs::near_unity_controller_backoff_scales_each_new_draw_from_its_own_base`,
`src/sender/schedule/timeline_tests.rs::backoff_deadline_depends_on_peak_not_feedback_partition`,
`src/sender/schedule/timeline_tests.rs::duration_limit_still_clamps_a_backed_off_deadline`
and `tests/sender_measurement_test.rs::sender_applies_ce_backoff_to_the_already_scheduled_probe`.

Recovery requires one usable non-CE CoS observation and no observed reverse
CE. Missing, duplicate, skipped, malformed or integrity-unusable CoS leaves
the interval unchanged; a configured key requires a verified TLV HMAC for
recovery. Valid base-packet measurements remain available. CE still takes
precedence, including reverse IP CE when CoS is unusable. Tests:
`src/sender/tests.rs::congestion_recovery_requires_unambiguous_usable_cos` and
`tests/sender_measurement_test.rs::sender_holds_ecn_backoff_until_usable_non_ce_feedback_returns`.
This is feedback admission, not an assertion that an unobserved reverse path
is congestion-free or that non-CE proves the absence of bleaching.

This demonstrates CE response capability. It does not establish all the
consistency required by section 3.4. Recovery subtracts a fixed interval on
each clean reply; it does not implement a congestion window, RTT epochs,
Classic fairness evidence or an L4S scalable controller. In particular,
using ECT(1) does not establish compliance with the L4S architecture in
[RFC 9330 §4.3](https://www.rfc-editor.org/rfc/rfc9330.html#section-4.3).
[RFC 3168 §6.1.2](https://www.rfc-editor.org/rfc/rfc3168.html#section-6.1.2)
describes TCP congestion-window response, which this interval controller
cannot simply claim to implement. The new consistency row remains Partial
pending a controller design and coexistence tests. The unsupported reverse
metadata platforms likewise remain Partial for reverse response requirements.
