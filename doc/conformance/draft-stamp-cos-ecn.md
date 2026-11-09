# draft-ietf-ippm-stamp-cos-ecn conformance

CoS and ECN requirements, implementation and tests.

Revision frozen: draft-ietf-ippm-stamp-cos-ecn-02, 2 November 2026.
Source: [draft-ietf-ippm-stamp-cos-ecn-02](https://www.ietf.org/archive/id/draft-ietf-ippm-stamp-cos-ecn-02.txt).

Summary: 30 clauses: 17 Compliant, 4 Partial, 0 Gap, 9 N-A, 0 Excluded.

## Scope

This is an Internet-Draft; the matrix covers revision -02 only. The
introductory, example and registry sections add no endpoint requirements.
New rows paraphrase revision 02; operator SHOULDs are recorded separately
from endpoint behavior.

The supported profile includes the reflector's DSCP and ECN admission policy
(`--allowed-dscp`, `--allowed-dscp-for`, `--allowed-ecn`) and the sender's
AIMD rate response to CE marks. The sender reads reverse-path ECN from IP
metadata on Linux and macOS; on other platforms it uses only the forward-path
EC2 feedback in the reflected CoS TLV. Windows marking is conservatively
reported unavailable with C; the deprecated Winsock IP_TOS API cannot prove
wire marking. macOS sticky marking is checked by socket-option readback;
Linux uses per-message ancillary marking. Microsoft documents the
[IP_TOS option](https://learn.microsoft.com/en-us/windows/win32/winsock/ipproto-ip-socket-options)
as unsuitable for setting ToS. Readback does not prove delivery
or detect downstream remarking; deployment captures remain necessary.

## Clauses

| ID | Clause | Level | Role | Status | Evidence |
|---|---|---|---|---|---|
| cos-ecn-3.1-1 | "The STAMP Session-Sender MAY include a CoS TLV in the STAMP test packet" | MAY | Sender | Compliant | `src/configuration.rs::Configuration::cos`, `src/configuration.rs::Configuration::dscp`. `src/sender.rs::run_sender_with_output` adds the CoS TLV only with `--cos`. |
| cos-ecn-3.1-2 | "CoS (Class of Service) Type: one-octet field; the value MUST be set to 4" | MUST | Both | Compliant | `src/tlv/core.rs::TlvType::ClassOfService` is 4; `src/tlv/core.rs::COS_TLV_VALUE_SIZE` gives Length 4. |
| cos-ecn-3.1-3 | "a Session-Sender MUST set the value of the RPD field to 0b00 on transmission" | MUST | Sender | Compliant | `ClassOfServiceTlv::new` (`src/tlv/typed/cos.rs`) sets RPD to 0; `test_cos_tlv_new` (`src/tlv/typed/cos.rs`). |
| cos-ecn-3.1-4 | "a Session-Sender MUST set the value of the RPE field to 0b00 on transmission" | MUST | Sender | Compliant | `ClassOfServiceTlv::new` (`src/tlv/typed/cos.rs`) sets RPE to 0; `test_cos_tlv_new` (`src/tlv/typed/cos.rs`). |
| cos-ecn-3.1-5 | "Reserved: twelve-bit field; MUST be zeroed on transmission and ignored on receipt" | MUST | Both | Compliant | `encode_value` and `decode_value` (`src/tlv/typed/cos.rs`); the reflector zeroes the bits in `update_cos_value_in_place` (`src/tlv/list/processing.rs`). Tests: `test_cos_tlv_wire_format_boundary_values` (`src/tlv/typed/cos.rs`), `test_cos_reserved_bits_are_zeroed` (`src/receiver/tests.rs`). |
| cos-ecn-3.2-1 | "A STAMP Session-Reflector that receives a test packet with the CoS TLV MUST include the CoS TLV in the reflected test packet" | MUST | Reflector | Compliant | Received TLVs are echoed under RFC 8972; `src/tlv/list/processing.rs::update_cos_tlvs` updates the echoed CoS TLV in place and never drops it. |
| cos-ecn-3.2-2 | "The Session-Reflector MUST copy the value of the DSCP and ECN fields of the IP header of the received STAMP test packet into the DSCP2 and EC2 fields" | MUST | Reflector | Compliant | `src/receiver/mod.rs::apply_semantic_tlv_processing` passes the received DSCP and ECN to `src/tlv/list/processing.rs::update_cos_value_in_place`. `test_cos_tlv_draft_figure_cross_vector` (`src/tlv/typed/cos.rs`) checks bytes computed by hand from the draft's Figure 1. |
| cos-ecn-3.2-3 | "The Session-Reflector MUST verify whether the use of the value of the DSCP1 field is permitted in the reflected test packet" | MUST | Reflector | Compliant | `CosAdmissionPolicy` (`src/cos_policy.rs`), applied in `src/receiver/mod.rs::apply_semantic_tlv_processing` against the reply destination. `cos_tlv_destination_scoped_policy_decides_per_peer` (`tests/tlv_flag_semantics.rs`). See [admission policy](#admission-policy). |
| cos-ecn-3.2-4 | "If it is [permitted], the Session-Reflector MUST set the DSCP field's value in the IP header of the reflected test packet equal to the value of the DSCP1 field" | MUST | Reflector | Compliant | `Transmission::send_next` and `send_datagram` (`src/receiver/transmit.rs`), `tests/burst_transmission_test.rs`. See [per-copy CoS](#per-copy-cos). |
| cos-ecn-3.2-5 | "Otherwise, the Session-Reflector MUST use the DSCP value of the received STAMP packet and set the value of the RPD field to 0b01" | MUST | Reflector | Compliant | `cos_unable_fallback_tos` and `set_cos_policy_rejected` (`src/receiver/reply_bytes.rs`), `cos_failure_uses_zero_ecn_fallback_and_resigns` (`src/receiver/transmit/tests.rs`). See [marking fallback](#marking-fallback). |
| cos-ecn-3.2-6 | "The Session-Reflector MUST set the ECN value in the IP header of the reflected STAMP test packet to the value of the EC1 field, if it is permitted and capable to do so" | MUST | Reflector | Compliant | `CosAdmissionPolicy` (`src/cos_policy.rs`) applies `--allowed-ecn`; a refused value forces Not-ECT and RPE 0b10. `cos_tlv_refused_ecn_forces_not_ect` (`tests/tlv_flag_semantics.rs`), `tests/burst_transmission_test.rs`. |
| cos-ecn-3.2-7 | "If the Session-Reflector is able to set the ECN value ... to the EC1 value, it MUST then set the RPE field ... to the value 0b11" | MUST | Reflector | Compliant | `Transmission::send_next` and `send_datagram` (`src/receiver/transmit.rs`), `tests/burst_transmission_test.rs`. See [per-copy CoS](#per-copy-cos). |
| cos-ecn-3.2-8 | "If the Session-Reflector is unable to set the ECN value ... it MUST instead set the ECN value in the IP header to 0b00 and set the RPE field ... to the value 0b10" | MUST | Reflector | Compliant | `cos_unable_fallback_tos` and `set_cos_policy_rejected` (`src/receiver/reply_bytes.rs`), `cos_failure_uses_zero_ecn_fallback_and_resigns` (`src/receiver/transmit/tests.rs`). See [marking fallback](#marking-fallback). |
| cos-ecn-3.2-9 | Set C when neither EC1 nor Not-ECT can be applied. | MUST | Reflector | Compliant | `src/receiver/reply_bytes.rs::set_cos_marking_unavailable`, `src/receiver/transmit.rs::Transmission::send_next_with_mtu`. Tests: `unavailable_ecn_sets_c_on_every_copy_and_preserves_routing_and_signatures`, `failed_not_ect_request_needs_no_identical_marking_retry`, `cos_unavailable_preserves_opaque_echoes_and_received_fields` (`src/receiver/transmit/tests.rs`). See [marking fallback](#marking-fallback). |
| cos-ecn-3.4-1 | Observe EC2 and be capable of reducing the sending rate on CE [multiple CoS packets within an RTT with ECT0 or ECT1] | MUST | Sender | Compliant | `src/sender/validate.rs::validate_reflected_tlvs`, `src/sender.rs::process_response`, `on_ce_observed` (`src/rate_control.rs`). `test_process_response_forward_path_ce_backs_off_congestion_controller` (`src/sender/tests.rs`). See [sender rate response](#sender-rate-response). |
| cos-ecn-3.4-2 | Observe reflected IP ECN and be capable of reducing the sending rate on CE [ECT0 or ECT1 in EC1] | MUST | Sender | Partial | `AimdController` (`src/rate_control.rs`). Tests: `test_process_response_forward_path_ce_backs_off_congestion_controller`, `test_process_response_reverse_path_ce_backs_off_congestion_controller` (`src/sender/tests.rs`). Reverse ECN is read on Linux and macOS only. |
| cos-ecn-3.4-3 | Observe reflected IP ECN and be capable of adjusting future Reflected Test Packet Control parameters on CE [CoS TLV with Type 12] | MUST | Sender | Partial | Normal sends and Access Report retries scale the Type 12 interval by the current AIMD factor; the reply count is unchanged. `test_wait_phase_retransmit_still_carries_scaled_control_tlv` and `ce_backoff_paces_zero_interval_bursts_but_preserves_control_only_zero` (`src/sender/tests.rs`). Reverse IP ECN is unavailable outside Linux/macOS. |
| cos-ecn-3.4-4 | Congestion response must be consistent with RFC 3168 and RFC 9330. | MUST | Sender | Partial | `src/rate_control.rs::AimdController` reduces the requested rate on CE, including Type 12 pacing, but per-reply interval recovery is not an RTT/window-based Classic controller or a demonstrated scalable L4S controller. See [response limits](#response-limits); full consistency evidence remains open. |
| cos-ecn-3.4-5 | Enable congestion response except for controlled measurements agreed with network operators. | MUST | Sender | Compliant | `src/sender/run.rs::SenderRun::open` enables the controller for CoS ECT0/ECT1, and scales reflected intervals. No disable override is exposed. [Operator guidance](../usage.md#ecn-deployment-and-interpretation). |
| cos-ecn-3.4-6 | For controlled measurements, limit rate and duration, including reflected traffic, and prevent impact outside the test. | SHOULD | Operator | N-A | Operator responsibility; [operator guidance](../usage.md#ecn-deployment-and-interpretation) maps duration/count, send delay and reflector caps. No controlled-measurement override is implemented. |
| cos-ecn-4.1-1 | Both peers should support the extended CoS TLV. | SHOULD | Both | Compliant | `src/tlv/typed/cos.rs::ClassOfServiceTlv`; [deployment guidance](../usage.md#ecn-deployment-and-interpretation) requires checking peer support and on-wire behavior. |
| cos-ecn-4.1-2 | Detect legacy reverse-path support from RPE and limit analysis accordingly. | SHOULD | Sender | Partial | The sender reports TLV flags and CE counters, but does not expose a dedicated RPE-based capability or bleaching diagnosis. [Operator guidance](../usage.md#ecn-deployment-and-interpretation) requires packet capture; structured diagnostics are follow-up work. |
| cos-ecn-4.1-3 | Verify reflector platform ECN setting/reporting capability. | SHOULD | Operator | N-A | [Deployment guidance](../usage.md#ecn-deployment-and-interpretation); Linux wire coverage: `tests/burst_transmission_test.rs`. Windows QoS support and native macOS capture evidence remain outside these tests. |
| cos-ecn-4.2-1 | Understand and document local DSCP/ECN policies. | SHOULD | Operator | N-A | [CoS policy](../usage.md#cos-and-location-policy) documents global, destination-scoped and ECN admission. |
| cos-ecn-4.2-2 | Coordinate ECN handling across administrative domains. | SHOULD | Operator | N-A | [Deployment guidance](../usage.md#ecn-deployment-and-interpretation). |
| cos-ecn-4.3-1 | Collect and analyze EC2, reflected IP ECN and RPE. | SHOULD | Operator | N-A | [Deployment guidance](../usage.md#ecn-deployment-and-interpretation) requires capture alongside current aggregate CE statistics; dedicated field output remains follow-up work. |
| cos-ecn-4.4-1 | Examine EC2/RPE and reflected IP ECN together when troubleshooting. | SHOULD | Operator | N-A | [Deployment guidance](../usage.md#ecn-deployment-and-interpretation) distinguishes policy rejection, platform inability and network remarking. |
| cos-ecn-4.5-1 | Bound automated measurement traffic and obey congestion response requirements. | SHOULD | Operator | N-A | [Deployment guidance](../usage.md#ecn-deployment-and-interpretation), including Type 12 rate/volume caps. |
| cos-ecn-4.6-1 | Verify interoperability and reverse ECN support before relying on bidirectional results. | SHOULD | Operator | N-A | [Deployment guidance](../usage.md#ecn-deployment-and-interpretation); absence of reverse metadata is explicitly a platform limit. |
| cos-ecn-6-1 | Consider HMAC TLVs and dynamic destination ports to mitigate CoS tampering or identification. | Descriptive | Operator | N-A | [ECN security](../security.md#ecn-measurement-integrity) maps existing key/TLV verification and port options; port choice does not authenticate traffic. |

## Notes

### Admission policy

`--allowed-dscp` sets the DSCP values the reflector may copy from DSCP1, and
`--allowed-dscp-for PREFIX/LEN=SPEC` overrides it for reply destinations in a
prefix (the longest matching prefix wins). `--allowed-ecn` does the same for
EC1. The reflector decides permission during semantic TLV processing, before
the reply is assembled and independently of whether the transport can set the
value.

### Per-copy CoS

`Transmission::send_next` (`src/receiver/transmit.rs`) applies the admitted
CoS value to every reply copy. On Linux, `send_datagram` sets IP_TOS or
IPV6_TCLASS per message. Other Unix platforms set and read back the socket
option immediately before their single sending task transmits. Windows
reports marking unavailable with C. `tests/burst_transmission_test.rs`
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

After a marking error, retry with received DSCP and Not-ECT, setting RPD=01
and RPE=10. If that attempt also cannot apply marking, send without the
marking operation and set C. If the initial requested byte already equals
the fallback, its failure establishes both cases without a duplicate retry.
Each attempt is timestamped and signed again; only a full datagram send
advances counters. C means the reply's wire ECN cannot be guaranteed.
Routing, source pinning and MTU policy remain intact during these fallbacks.
Windows always takes this conservative path for a processed CoS request;
ordinary replies bypass the unsupported marking operation.

Tests in `src/receiver/transmit/tests.rs` cover setter and readback failures,
silently ignored values, cache invalidation, datagram versus option failures,
opaque echoes, every burst copy, IPv4/IPv6 and both authentication modes.
`cos_failure_uses_zero_ecn_fallback_and_resigns` checks successful fallback;
`unavailable_ecn_sets_c_on_every_copy_and_preserves_routing_and_signatures`
checks final C and both HMACs. These are injected capability failures;
`tests/burst_transmission_test.rs` supplies actual Linux wire marking evidence.

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

This demonstrates CE response capability. It does not establish all the
consistency required by revision 02. Recovery subtracts a fixed interval on
each clean reply; it does not implement a congestion window, RTT epochs,
Classic fairness evidence or an L4S scalable controller. In particular,
using ECT(1) does not establish compliance with the L4S architecture in
[RFC 9330 §4.3](https://www.rfc-editor.org/rfc/rfc9330.html#section-4.3).
[RFC 3168 §6.1.2](https://www.rfc-editor.org/rfc/rfc3168.html#section-6.1.2)
describes TCP congestion-window response, which this interval controller
cannot simply claim to implement. The new consistency row remains Partial
pending a controller design and coexistence tests. The unsupported reverse
metadata platforms likewise remain Partial for reverse response requirements.
