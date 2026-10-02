//! Validation of reflected TLVs before their values are used
//! (RFC 8972 §4, §4.8).

use super::*;

/// Reason a reflected packet is rejected without updating sender state.
///
/// Returned as the error variant of [`validate_reflected_tlvs`]. The caller
/// must log and discard the packet: no RTT sample recorded, no `pending`
/// entry consumed, no received counter incremented.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum TlvRejection {
    /// Reflected Micro-session ID echoed a `sender_micro_session_id` that
    /// does not match what this sender emitted (RFC 9534 §3.2 binding check).
    /// A legitimate reflector always echoes the sender ID unchanged, so a
    /// mismatch means the response belongs to a different session, a stale
    /// packet, or a spoofed reply.
    MsidMismatch { got: u16, expected: u16 },
    /// Reflector ID differs from the configured or first accepted value
    /// (RFC 9534 §3.2-11/-12). Discard the reply.
    ReflectorMsidMismatch { got: u16, expected: u16 },
    /// Reflected Micro-session ID TLV could not be parsed. Since the TLV
    /// carries the session binding, we cannot attribute the response to this
    /// sender and must drop it.
    MsidMalformed,
    /// Required binding is absent, unusable, or cannot be integrity-validated.
    MsidUnavailable,
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
            Self::MsidAmbiguous => write!(f, "multiple Micro-session ID TLVs in reflected packet"),
            Self::MsidMalformed => {
                write!(f, "malformed Micro-session ID TLV in reflected packet")
            }
        }
    }
}

/// Return typed decision fields after U/M/I/HMAC and required identifier checks.
/// Wire bytes start at `base_size` (44 open, 112 authenticated). Diagnostic
/// formatting is deferred to Display and never drives sender state changes.
#[allow(clippy::too_many_arguments)]
pub(super) fn validate_reflected_tlvs(
    tlvs: &TlvList,
    data: &[u8],
    base_size: usize,
    hmac_key: Option<&HmacKey>,
    expected_sender_msid: Option<u16>,
    expected_reflector_msid: Option<u16>,
    latched_reflector_msid: &mut Option<u16>,
    // Decode these values only when their respective state machines are active.
    track_access_report: bool,
    track_congestion: bool,
    #[cfg(feature = "metrics")] metrics_enabled: bool,
) -> Result<TlvTelemetry, TlvRejection> {
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
        (Some(_), None) => HmacStatus::Missing,
        (None, None) => HmacStatus::NotRequested,
    };
    let mut telemetry = TlvTelemetry {
        tlv_count: tlvs.len(),
        flags: FlagCounts {
            unrecognized,
            malformed,
            integrity_failed,
        },
        hmac,
        ..TlvTelemetry::default()
    };
    // Integrity gates all values before U skips a TLV or M stops the remainder.
    // Missing optional HMAC retains the legacy-peer policy; required MSID below
    // still rejects it. A present but unverifiable HMAC never permits values.
    let integrity_ok = hmac.permits_optional_values() && integrity_failed == 0;
    let want_msid = expected_sender_msid.is_some()
        || expected_reflector_msid.is_some()
        || latched_reflector_msid.is_some();
    let mut validated_msid = false;
    let mut dm_seen = false;
    let mut follow_seen = false;
    let mut next_reflector_msid = *latched_reflector_msid;
    if want_msid {
        let count = tlvs
            .non_hmac_tlvs()
            .iter()
            .filter(|raw| raw.tlv_type == TlvType::MicroSessionId)
            .count();
        if count > 1 {
            return Err(TlvRejection::MsidAmbiguous);
        }
        let usable_hmac = hmac_key.is_none()
            || tlvs.hmac_tlv().is_some_and(|raw| {
                !raw.is_unrecognized() && !raw.is_malformed() && !raw.is_integrity_failed()
            });
        if count == 0 || !integrity_ok || !usable_hmac {
            return Err(TlvRejection::MsidUnavailable);
        }
    }
    if integrity_ok {
        for raw in tlvs.non_hmac_tlvs() {
            if raw.is_malformed() {
                break; // §4-18: M flag halts remainder.
            }
            if raw.is_unrecognized() {
                continue; // §4-17: U flag skips this TLV.
            }
            if track_access_report && raw.tlv_type == crate::tlv::TlvType::AccessReport {
                // A recognized, well-formed echo acknowledges the report (RFC 8972 §4.6).
                // U/M checks above and the surrounding integrity check reject unusable TLVs.
                match AccessReportTlv::from_raw(raw) {
                    Ok(report) => {
                        telemetry.access_report.get_or_insert(report);
                    }
                    Err(_) => {
                        telemetry.flags.malformed += 1;
                        break;
                    }
                }
            }
            if track_congestion && raw.tlv_type == TlvType::ClassOfService {
                // draft-ietf-ippm-stamp-cos-ecn-01 §3.4: EC2 = 0b11 signals
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
                if parsed.reflector_micro_session_id == 0 {
                    return Err(TlvRejection::MsidUnavailable);
                }
                // RFC 9534 §3.2 / §3.2-9: our sender_micro_session_id must be
                // echoed unchanged — a mismatch means the reply belongs to a
                // different session (or is spoofed); discard.
                if let Some(expected) = expected_sender_msid {
                    if parsed.sender_micro_session_id != expected {
                        return Err(TlvRejection::MsidMismatch {
                            got: parsed.sender_micro_session_id,
                            expected,
                        });
                    }
                }
                // Validate the reflector ID on every usable reply (RFC 9534 §3.2-11).
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

    #[cfg(feature = "metrics")]
    if metrics_enabled {
        crate::metrics::sender_metrics::record_tlv_errors(
            telemetry.flags.unrecognized,
            telemetry.flags.malformed,
            telemetry.flags.integrity_failed,
        );
    }
    Ok(telemetry)
}
