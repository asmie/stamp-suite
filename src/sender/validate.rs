//! Validation of reflected TLVs before their values are used
//! (RFC 8972 §4, §4.8).

use super::*;

/// TLV rejection: discard without recording RTT, consuming pending state
/// or incrementing received counts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum TlvRejection {
    /// Echoed sender Micro-session ID differs from the sent ID (RFC 9534 §3.2).
    MsidMismatch { got: u16, expected: u16 },
    /// Reflector ID differs from the configured or first accepted value
    /// (RFC 9534 §3.2). Discard the reply.
    ReflectorMsidMismatch { got: u16, expected: u16 },
    /// Malformed Micro-session ID; session binding cannot be checked.
    MsidMalformed,
    /// Required binding is absent, unusable, or cannot be integrity-validated.
    MsidUnavailable,
    /// The reflector flagged the Micro-session ID TLV U (RFC 8972 §4): it
    /// does not support RFC 9534.
    MsidUnrecognized,
    /// The reflector returned Reflector Micro-session ID 0, so it has no
    /// member link identifier to validate (RFC 9534 §3.2).
    ReflectorMsidUnset,
    /// More than one Micro-session ID makes the binding ambiguous.
    MsidAmbiguous,
}

impl std::fmt::Display for TlvRejection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MsidMismatch { got, expected } => write!(
                f,
                "Micro-session ID mismatch (got sender_id={}, expected={})",
                got, expected
            ),
            Self::ReflectorMsidMismatch { got, expected } => write!(
                f,
                "Reflector Micro-session ID mismatch (got reflector_id={}, expected={})",
                got, expected
            ),
            Self::MsidUnavailable => write!(f, "required Micro-session ID is missing or unusable"),
            Self::MsidUnrecognized => write!(
                f,
                "reflector flagged the Micro-session ID TLV unrecognized (U flag); \
                 it does not support RFC 9534 micro-sessions"
            ),
            Self::ReflectorMsidUnset => write!(
                f,
                "reflector returned Reflector Micro-session ID 0: it has no member link ID \
                 configured (start a stamp-suite reflector with --reflector-member-link-id)"
            ),
            Self::MsidAmbiguous => write!(f, "multiple Micro-session ID TLVs in reflected packet"),
            Self::MsidMalformed => {
                write!(f, "malformed Micro-session ID TLV in reflected packet")
            }
        }
    }
}

/// Initial flag and HMAC diagnostics, also retained when required binding fails.
/// `reply_hmac_expected` is false when an open-mode sender holds a key but
/// sent no HMAC TLV (`--tlv-hmac off`): a reflector then signs only if it
/// chooses to (RFC 8972 §4.8), so a missing HMAC TLV is not a gap.
pub(super) fn reflected_tlv_telemetry(
    tlvs: &TlvList,
    data: &[u8],
    base_size: usize,
    hmac_key: Option<&HmacKey>,
    reply_hmac_expected: bool,
) -> TlvTelemetry {
    let (unrecognized, malformed, integrity_failed) = tlvs.count_error_flags();
    let hmac = match (hmac_key, tlvs.hmac_tlv()) {
        (_, Some(_)) if tlvs.hmac_misplaced() => HmacStatus::Failed,
        (_, Some(raw))
            if raw.is_unrecognized() || raw.is_malformed() || raw.is_integrity_failed() =>
        {
            HmacStatus::Unverified
        }
        (Some(key), Some(_)) => {
            if base_size < 4 || data.len() <= base_size {
                HmacStatus::Unverified
            } else if tlvs
                .verify_hmac(key, &data[..4], &data[base_size..])
                .is_ok()
            {
                HmacStatus::Verified
            } else {
                HmacStatus::Failed
            }
        }
        (None, Some(_)) => HmacStatus::Unverified,
        // Authenticated mode requires the HMAC TLV unless the only TLV is
        // Extra Padding (RFC 8972 §4.8). The base size identifies the mode.
        (Some(_), None) if base_size == AUTH_BASE_SIZE && !tlvs.contains_only_extra_padding() => {
            HmacStatus::Failed
        }
        (Some(_), None) if reply_hmac_expected => HmacStatus::Missing,
        (_, None) => HmacStatus::NotRequested,
    };
    TlvTelemetry {
        tlv_count: tlvs.len(),
        flags: FlagCounts {
            unrecognized,
            malformed,
            integrity_failed,
        },
        hmac,
        ..TlvTelemetry::default()
    }
}

/// Validate flags, HMAC and required IDs before returning usable values.
/// TLVs start at base_size (44 open, 112 authenticated). Display is diagnostic.
#[allow(clippy::too_many_arguments)]
pub(super) fn validate_reflected_tlvs(
    tlvs: &TlvList,
    data: &[u8],
    base_size: usize,
    hmac_key: Option<&HmacKey>,
    reply_hmac_expected: bool,
    expected_sender_msid: Option<u16>,
    expected_reflector_msid: Option<u16>,
    latched_reflector_msid: &mut Option<u16>,
    // Decode these values only when their respective state machines are active.
    track_access_report: bool,
    track_congestion: bool,
) -> Result<TlvTelemetry, TlvRejection> {
    let mut telemetry =
        reflected_tlv_telemetry(tlvs, data, base_size, hmac_key, reply_hmac_expected);
    let hmac = telemetry.hmac;
    let integrity_failed = telemetry.flags.integrity_failed;
    // Check integrity before U/M processing. Missing optional HMAC follows
    // legacy policy; required MSID still rejects it. Unverifiable HMAC blocks values.
    let integrity_ok = hmac.permits_optional_values() && integrity_failed == 0;
    let want_msid = expected_sender_msid.is_some()
        || expected_reflector_msid.is_some()
        || latched_reflector_msid.is_some();
    let mut validated_msid = false;
    let mut dm_seen = false;
    let mut follow_seen = false;
    let mut next_reflector_msid = *latched_reflector_msid;
    // Multiple CoS instances are ambiguous for diagnostic pairing, including
    // instances that will be skipped by U/M processing below.
    let single_cos = tlvs
        .non_hmac_tlvs()
        .iter()
        .filter(|raw| raw.tlv_type == TlvType::ClassOfService)
        .count()
        == 1;
    // The sender originates one Access Report. Multiple instances cannot
    // unambiguously acknowledge it, even when a later one is flagged U/M.
    let single_access_report = track_access_report
        && tlvs
            .non_hmac_tlvs()
            .iter()
            .filter(|raw| raw.tlv_type == TlvType::AccessReport)
            .count()
            == 1;
    if want_msid {
        let count = tlvs
            .non_hmac_tlvs()
            .iter()
            .filter(|raw| raw.tlv_type == TlvType::MicroSessionId)
            .count();
        if count > 1 {
            return Err(TlvRejection::MsidAmbiguous);
        }
        let usable_hmac = match tlvs.hmac_tlv() {
            None => hmac_key.is_none() || !reply_hmac_expected,
            Some(raw) => {
                hmac_key.is_none()
                    || (!raw.is_unrecognized() && !raw.is_malformed() && !raw.is_integrity_failed())
            }
        };
        if count == 0 || !integrity_ok || !usable_hmac {
            return Err(TlvRejection::MsidUnavailable);
        }
    }
    if integrity_ok {
        for raw in tlvs.non_hmac_tlvs() {
            if raw.is_malformed() {
                break; // RFC 8972 §4: M flag halts the remainder.
            }
            if raw.is_unrecognized() {
                // A required Micro-session ID flagged U cannot bind the reply;
                // name the cause instead of reporting it missing.
                if want_msid && raw.tlv_type == TlvType::MicroSessionId {
                    return Err(TlvRejection::MsidUnrecognized);
                }
                continue; // RFC 8972 §4: U flag skips this TLV.
            }
            if track_access_report && raw.tlv_type == crate::tlv::TlvType::AccessReport {
                // Retain one usable candidate; the retransmission state also
                // checks its ID and Return Code against the original report.
                // U/M checks above and the surrounding integrity check reject unusable TLVs.
                match AccessReportTlv::from_raw(raw) {
                    Ok(report) => {
                        if single_access_report {
                            telemetry.access_report = Some(report);
                        }
                    }
                    Err(_) => {
                        telemetry.flags.malformed += 1;
                        break;
                    }
                }
            }
            if track_congestion && raw.tlv_type == TlvType::ClassOfService {
                // draft-ietf-bpm-stamp-cos-ecn-00 §3.4: EC2 = 0b11 signals
                // forward-path (sender→reflector) congestion. Same
                // U/M-flag-gated, integrity-checked path as every other
                // reflected value consumed above.
                if let Ok(cos) = ClassOfServiceTlv::from_raw(raw) {
                    if cos.ecn2 == 0b11 {
                        telemetry.forward_ce = true;
                    }
                }
            }
            // Measurement counters/timestamps require a verified HMAC when a
            // key is configured; legacy control acknowledgements remain separate.
            if hmac.permits_measurements() {
                if single_cos && raw.tlv_type == TlvType::ClassOfService {
                    if let Ok(value) = ClassOfServiceTlv::from_raw(raw) {
                        telemetry.cos = Some(super::telemetry::CosObservation {
                            value,
                            conformant_reflected: raw.flags.conformant_reflected,
                        });
                    }
                }
                if raw.tlv_type == TlvType::DirectMeasurement {
                    match DirectMeasurementTlv::from_raw(raw) {
                        Ok(value) => {
                            telemetry.direct_measurement = if dm_seen { None } else { Some(value) };
                            dm_seen = true;
                        }
                        Err(_) => {
                            telemetry.flags.malformed += 1;
                            break;
                        }
                    }
                }
                if raw.tlv_type == TlvType::FollowUpTelemetry {
                    match FollowUpTelemetryTlv::from_raw(raw) {
                        Ok(value) => {
                            telemetry.follow_up = if follow_seen { None } else { Some(value) };
                            follow_seen = true;
                        }
                        Err(_) => {
                            telemetry.flags.malformed += 1;
                            break;
                        }
                    }
                }
            }
            if want_msid && raw.tlv_type == crate::tlv::TlvType::MicroSessionId {
                let parsed =
                    MicroSessionIdTlv::from_raw(raw).map_err(|_| TlvRejection::MsidMalformed)?;
                // RFC 9534 §3.2: our sender_micro_session_id must be echoed
                // unchanged. A mismatch means the reply belongs to a different
                // session (or is spoofed); discard.
                if let Some(expected) = expected_sender_msid {
                    if parsed.sender_micro_session_id != expected {
                        return Err(TlvRejection::MsidMismatch {
                            got: parsed.sender_micro_session_id,
                            expected,
                        });
                    }
                }
                // RFC 9534 §3.2: a sender that does not know the reflector's
                // member link identifier sends zero, and the reflector "MUST
                // put the ... Reflector member link identifiers that are
                // associated with the micro STAMP session" in the reply. Zero
                // therefore identifies no member link: the sender "MUST use the
                // Reflector Micro-session ID to validate the Reflector's
                // behavior" and cannot validate or learn zero, so it discards.
                if parsed.reflector_micro_session_id == 0 {
                    return Err(TlvRejection::ReflectorMsidUnset);
                }
                // Validate the reflector ID on every usable reply (RFC 9534 §3.2).
                // A configured ID takes precedence; otherwise use the first accepted ID.
                // Reject mismatches without replacing the expected value.
                if let Some(expected_refl) = expected_reflector_msid {
                    if parsed.reflector_micro_session_id != expected_refl {
                        return Err(TlvRejection::ReflectorMsidMismatch {
                            got: parsed.reflector_micro_session_id,
                            expected: expected_refl,
                        });
                    }
                } else if let Some(expected_refl) = *latched_reflector_msid {
                    if parsed.reflector_micro_session_id != expected_refl {
                        return Err(TlvRejection::ReflectorMsidMismatch {
                            got: parsed.reflector_micro_session_id,
                            expected: expected_refl,
                        });
                    }
                } else {
                    next_reflector_msid = Some(parsed.reflector_micro_session_id);
                }
                validated_msid = true;
                telemetry.micro_session = Some(parsed);
            }
        }
    }

    if want_msid && !validated_msid {
        return Err(TlvRejection::MsidUnavailable);
    }
    *latched_reflector_msid = next_reflector_msid;
    Ok(telemetry)
}
