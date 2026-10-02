//! In-place edits to an assembled reply, applied when the send path falls back.

use super::*;

/// Marks CoS application failure: RPD=0b01 (RFC 8972 §4.4) and RPE=0b10
/// (draft-ietf-ippm-stamp-cos-ecn-01 §3.2). Returns whether a CoS TLV was updated.
///
/// The caller must recompute the TLV HMAC and attempt the Not-ECT IP-header
/// fallback from [`cos_unable_fallback_tos`]. This only updates TLV fields.
pub fn set_cos_policy_rejected(response: &mut [u8], base_packet_size: usize) -> bool {
    let Some(tlv_area) = response.get_mut(base_packet_size..) else {
        return false;
    };
    // An all-zero remainder is padding; find where it starts once.
    let data_end = tlv_area.iter().rposition(|&b| b != 0).map_or(0, |i| i + 1);
    let mut offset = 0;
    let mut updated = false;
    while offset < data_end && offset + TLV_HEADER_SIZE <= tlv_area.len() {
        let flags = tlv_area[offset];
        let tlv_type = TlvType::from_byte(tlv_area[offset + 1]);
        let length = u16::from_be_bytes([tlv_area[offset + 2], tlv_area[offset + 3]]) as usize;
        let value = offset + TLV_HEADER_SIZE;
        if flags & 0x40 != 0 || value + length > tlv_area.len() {
            break; // Processing stopped at a malformed TLV.
        }
        // Only CoS TLVs the reflector processed (U, M, I clear) carry RPD/RPE.
        if tlv_type == TlvType::ClassOfService && length == 4 && flags & 0xE0 == 0 {
            // The backend could not apply DSCP1 and EC1 to the reply:
            // RPD = 0b01 (DSCP1 not used, RFC 8972 §4.4) and RPE = 0b10
            // (EC1 not applied, cos-ecn-01 §3.2), replacing the 0b11 set
            // during TLV processing.
            tlv_area[value + 1] = (tlv_area[value + 1] & 0xFC) | 0b01;
            tlv_area[value + 2] = (tlv_area[value + 2] & 0xCF) | (0b10 << 4);
            updated = true;
        }
        offset = value + length;
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
    (received_dscp & 0x3F) << 2
}

/// Sets the U-flag on the Return Path TLV in a serialized STAMP response.
///
/// Walks the TLV area to find a Return Path TLV (type 10) and sets its
/// unrecognized flag. Used when the reflector cannot honor the requested
/// return path (e.g., alternate-address send failure) per RFC 9503 §4.
///
/// Returns `true` if the Return Path TLV was found and updated.
pub fn set_return_path_u_flag_in_response(response: &mut [u8], base_packet_size: usize) -> bool {
    if response.len() <= base_packet_size {
        return false;
    }

    let tlv_area = &mut response[base_packet_size..];
    let mut offset = 0;

    while offset + TLV_HEADER_SIZE <= tlv_area.len() {
        if tlv_area[offset..offset + TLV_HEADER_SIZE] == [0, 0, 0, 0]
            && tlv_area[offset..].iter().all(|&b| b == 0)
        {
            break;
        }

        let tlv_type = TlvType::from_byte(tlv_area[offset + 1]);
        let length = u16::from_be_bytes([tlv_area[offset + 2], tlv_area[offset + 3]]) as usize;

        if tlv_type == TlvType::ReturnPath {
            // Set U-flag (bit 7) on the flags byte
            tlv_area[offset] |= 0x80;
            return true;
        }

        offset += TLV_HEADER_SIZE + length;
    }

    false
}
