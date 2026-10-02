//! In-place edits to an assembled reply, applied when the send path falls back.

use super::*;
use crate::tlv::{TlvFlags, TlvSpan, COS_TLV_VALUE_SIZE};

/// Marks CoS application failure: RPD=0b01 (RFC 8972 §4.4) and RPE=0b10
/// (draft-ietf-ippm-stamp-cos-ecn-01 §3.2). Returns whether a CoS TLV was updated.
///
/// The caller must recompute the TLV HMAC and attempt the Not-ECT IP-header
/// fallback from [`cos_unable_fallback_tos`]. This only updates TLV fields.
pub fn set_cos_policy_rejected(response: &mut [u8], base_packet_size: usize) -> bool {
    let mut pos = base_packet_size;
    let mut updated = false;
    while let Some(tlv) = TlvSpan::at(response, pos) {
        if tlv.flags.malformed {
            break; // Processing stopped at a malformed TLV.
        }
        // Only CoS TLVs the reflector processed carry RPD/RPE.
        if tlv.tlv_type == TlvType::ClassOfService
            && tlv.len == COS_TLV_VALUE_SIZE
            && tlv.flags.processed()
        {
            // The backend could not apply DSCP1 and EC1 to the reply:
            // RPD = 0b01 (DSCP1 not used, RFC 8972 §4.4) and RPE = 0b10
            // (EC1 not applied, cos-ecn-01 §3.2), replacing the 0b11 set
            // during TLV processing.
            let value = tlv.value_start();
            response[value + 1] = (response[value + 1] & 0xFC) | 0b01;
            response[value + 2] = (response[value + 2] & 0xCF) | (0b10 << 4);
            updated = true;
        }
        pos = tlv.end();
    }
    updated
}

/// Returns received DSCP with Not-ECT for a failed CoS application
/// (draft-ietf-ippm-stamp-cos-ecn-01 §3.2).
///
/// Matches RPD=0b01/RPE=0b10 from [`set_cos_policy_rejected`]. Backends must
/// attempt this fallback; socket failure can still prevent clearing ECN.
/// See [`crate::tlv::ClassOfServiceTlv::reply_wire_tos`].
#[must_use]
pub fn cos_unable_fallback_tos(received_dscp: u8) -> u8 {
    crate::tos::Tos::new(received_dscp, 0).0
}

/// Sets the U-flag on the Return Path TLV in a serialized STAMP response.
///
/// Walks the TLV area to find a Return Path TLV (type 10) and sets its
/// unrecognized flag. Used when the reflector cannot honor the requested
/// return path (e.g., alternate-address send failure) per RFC 9503 §4.
///
/// Returns `true` if the Return Path TLV was found and updated.
pub fn set_return_path_u_flag_in_response(response: &mut [u8], base_packet_size: usize) -> bool {
    let mut pos = base_packet_size;
    while let Some(tlv) = TlvSpan::at(response, pos) {
        if tlv.flags.malformed {
            break; // Processing stopped at a malformed TLV.
        }
        if tlv.tlv_type == TlvType::ReturnPath {
            response[tlv.start] |= TlvFlags::U;
            return true;
        }
        pos = tlv.end();
    }
    false
}
