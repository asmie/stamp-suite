# draft-ietf-ippm-stamp-cos-ecn conformance

CoS and ECN requirements, implementation and tests.

Revision frozen: draft-ietf-ippm-stamp-cos-ecn-01, 20 July 2026.
Source: [draft-ietf-ippm-stamp-cos-ecn-01](https://www.ietf.org/archive/id/draft-ietf-ippm-stamp-cos-ecn-01.txt).

Summary: 16 clauses: 16 Compliant, 0 Partial, 0 Gap, 0 N-A, 0 Excluded.

## Scope

This is an Internet-Draft; the matrix covers revision -01 only. The
introductory, example and registry sections add no endpoint requirements.

The supported profile includes the reflector's DSCP and ECN admission policy
(`--allowed-dscp`, `--allowed-dscp-for`, `--allowed-ecn`) and the sender's
AIMD rate response to CE marks. The sender reads reverse-path ECN from IP
metadata on Linux and macOS; on other platforms it uses only the forward-path
EC2 feedback in the reflected CoS TLV.

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
| cos-ecn-3.2-5 | "Otherwise, the Session-Reflector MUST use the DSCP value of the received STAMP packet and set the value of the RPD field to 0b01" | MUST | Reflector | Compliant | `cos_unable_fallback_tos` and `set_cos_policy_rejected` (`src/receiver/reply_bytes.rs`), `cos_failure_uses_zero_ecn_fallback_and_resigns` (`src/receiver/transmit/tests.rs`). See [send-failure fallback](#send-failure-fallback). |
| cos-ecn-3.2-6 | "The Session-Reflector MUST set the ECN value in the IP header of the reflected STAMP test packet to the value of the EC1 field, if it is permitted and capable to do so" | MUST | Reflector | Compliant | `CosAdmissionPolicy` (`src/cos_policy.rs`) applies `--allowed-ecn`; a refused value forces Not-ECT and RPE 0b10. `cos_tlv_refused_ecn_forces_not_ect` (`tests/tlv_flag_semantics.rs`), `tests/burst_transmission_test.rs`. |
| cos-ecn-3.2-7 | "If the Session-Reflector is able to set the ECN value ... to the EC1 value, it MUST then set the RPE field ... to the value 0b11" | MUST | Reflector | Compliant | `Transmission::send_next` and `send_datagram` (`src/receiver/transmit.rs`), `tests/burst_transmission_test.rs`. See [per-copy CoS](#per-copy-cos). |
| cos-ecn-3.2-8 | "If the Session-Reflector is unable to set the ECN value ... it MUST instead set the ECN value in the IP header to 0b00 and set the RPE field ... to the value 0b10" | MUST | Reflector | Compliant | `cos_unable_fallback_tos` and `set_cos_policy_rejected` (`src/receiver/reply_bytes.rs`), `cos_failure_uses_zero_ecn_fallback_and_resigns` (`src/receiver/transmit/tests.rs`). See [send-failure fallback](#send-failure-fallback). |
| cos-ecn-3.4-1 | "...it MUST observe the reflected EC2 field and reduce its sending rate upon observation of a CE value" [multiple CoS packets within an RTT with ECT0 or ECT1] | MUST | Sender | Compliant | `src/sender/validate.rs::validate_reflected_tlvs`, `src/sender.rs::process_response`, `on_ce_observed` (`src/rate_control.rs`). `test_process_response_forward_path_ce_backs_off_congestion_controller` (`src/sender/tests.rs`). See [sender rate response](#sender-rate-response). |
| cos-ecn-3.4-2 | "...it MUST observe the ECN value in the IP header of the reflected packets and reduce its sending rate upon observation of a CE value" [ECT0 or ECT1 in EC1] | MUST | Sender | Compliant | `AimdController` (`src/rate_control.rs`). Tests: `test_process_response_forward_path_ce_backs_off_congestion_controller`, `test_process_response_reverse_path_ce_backs_off_congestion_controller` (`src/sender/tests.rs`). Reverse ECN is read on Linux and macOS only. |
| cos-ecn-3.4-3 | "...it MUST observe the ECN value ... and adjust the Reflected Test Packet Control parameters in any future STAMP packet ... based on the observation of CE values" [CoS TLV with Type 12] | MUST | Sender | Compliant | Normal sends and Access Report retries scale the Type 12 interval by the current AIMD factor; the reply count is unchanged. `test_wait_phase_retransmit_still_carries_scaled_control_tlv` (`src/sender/tests.rs`). |

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
IPV6_TCLASS per message; other platforms set the socket option immediately
before their single sending task transmits. `tests/burst_transmission_test.rs`
checks that on-wire CoS stays correct when a request with a different CoS
arrives between copies.

### Send-failure fallback

When the kernel refuses the requested CoS, `Transmission::send_next` retries
with the received DSCP and ECN 0 (`cos_unable_fallback_tos`), and
`set_cos_policy_rejected` sets RPD 0b01 and RPE 0b10 before the reply is
signed. `cos_failure_uses_zero_ecn_fallback_and_resigns` checks the fields,
flags and both HMACs with an injected send failure; no test drives a real
kernel failure.

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
