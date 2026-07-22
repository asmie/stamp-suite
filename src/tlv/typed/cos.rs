//! Class of Service TLV (Type 4) per RFC 8972 §4.4 (with verified erratum
//! 8199), extended with the reverse-path ECN fields (EC1/RPE) of
//! draft-ietf-ippm-stamp-cos-ecn-01 (wire format byte-identical to -00; -01
//! §3.2 additionally requires the reply's on-wire ECN bits be zeroed when
//! EC1 cannot be applied — see [`ClassOfServiceTlv::reply_wire_tos`]).

use crate::tlv::core::{TlvError, TlvType, COS_TLV_VALUE_SIZE};
use crate::tlv::traits::TypedTlv;

/// Class of Service TLV (Type 4) for DSCP/ECN measurement per RFC 8972 §4.4
/// as updated by draft-ietf-ippm-stamp-cos-ecn-01. EC1 and RPE occupy bits
/// that RFC 8972 reserved, so the extension is backward compatible in both
/// directions (§3.3 of the draft).
///
/// # Wire Format
///
/// ```text
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |   DSCP1   |   DSCP2   |EC2|RPD|EC1|RPE|        Reserved       |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ClassOfServiceTlv {
    /// DSCP value intended for the reflected packet (6 bits, 0-63).
    pub dscp1: u8,
    /// EC1: ECN value intended for the reflected packet (2 bits, 0-3;
    /// draft-ietf-ippm-stamp-cos-ecn-01 §3.1).
    pub ecn1: u8,
    /// DSCP value received at the Session-Reflector's ingress (6 bits).
    pub dscp2: u8,
    /// EC2: ECN value received at the Session-Reflector's ingress (2 bits).
    pub ecn2: u8,
    /// RPD (reverse path DSCP, 2 bits): 0b01 when the reflector's policy
    /// rejected DSCP1 and the received DSCP was used for the reply instead.
    pub rpd: u8,
    /// RPE (reverse path ECN, 2 bits; draft-ietf-ippm-stamp-cos-ecn-01
    /// §3.2): 0b11 when the reflector set the reply's ECN to EC1, 0b10 when
    /// it was unable to — in which case -01 additionally requires the
    /// reply's on-wire ECN bits be forced to 0b00 (see
    /// [`ClassOfServiceTlv::reply_wire_tos`]); 0b00 from senders and RFC
    /// 8972-only reflectors.
    pub rpe: u8,
}

impl ClassOfServiceTlv {
    /// Creates a new CoS TLV for the sender. DSCP2/EC2 are zero and the
    /// RPD/RPE fields MUST be transmitted as 0b00 (RFC 8972 §4.4 +
    /// draft-ietf-ippm-stamp-cos-ecn-01 §3.1).
    #[must_use]
    pub fn new(dscp: u8, ecn: u8) -> Self {
        Self {
            dscp1: dscp & 0x3F,
            ecn1: ecn & 0x03,
            dscp2: 0,
            ecn2: 0,
            rpd: 0,
            rpe: 0,
        }
    }

    /// Creates a CoS TLV for the reflector response.
    ///
    /// `ecn_applied` reports whether the reflector set the reply packet's
    /// ECN field to EC1 (RPE = 0b11) or was unable to (RPE = 0b10), per
    /// draft-ietf-ippm-stamp-cos-ecn-01 §3.2. When unable, callers MUST
    /// also zero the reply's on-wire ECN bits — see
    /// [`ClassOfServiceTlv::reply_wire_tos`].
    #[must_use]
    pub fn for_response(
        dscp1: u8,
        ecn1: u8,
        received_dscp: u8,
        received_ecn: u8,
        policy_rejected: bool,
        ecn_applied: bool,
    ) -> Self {
        Self {
            dscp1: dscp1 & 0x3F,
            ecn1: ecn1 & 0x03,
            dscp2: received_dscp & 0x3F,
            ecn2: received_ecn & 0x03,
            rpd: if policy_rejected { 0b01 } else { 0b00 },
            rpe: if ecn_applied { 0b11 } else { 0b10 },
        }
    }

    /// Packs the requested DSCP1/EC1 pair into the single octet used by the
    /// IPv4 TOS / IPv6 Traffic Class field, so a sender can mark its egress
    /// IP header to match what this TLV requests for the reflected packet.
    /// Note: this is *not* encoded byte 0, which carries DSCP2's upper bits.
    #[must_use]
    pub const fn wire_tos(&self) -> u8 {
        ((self.dscp1 & 0x3F) << 2) | (self.ecn1 & 0x03)
    }

    /// Returns true if the reflector's policy rejected the requested DSCP.
    #[must_use]
    pub fn policy_rejected(&self) -> bool {
        self.rpd != 0
    }

    /// Returns true if the reflector reported (RPE = 0b11) that it set the
    /// reply packet's ECN field to the requested EC1 value.
    #[must_use]
    pub fn reply_ecn_was_set(&self) -> bool {
        self.rpe == 0b11
    }

    /// Returns the DSCP value that should be used for the reflected packet.
    #[must_use]
    pub fn effective_dscp(&self, policy_rejected: bool) -> u8 {
        if policy_rejected {
            self.dscp2
        } else {
            self.dscp1
        }
    }

    /// Computes the TOS (IPv4) / Traffic Class (IPv6) byte the reflector
    /// should apply to the reply packet's IP header, derived from this
    /// TLV's own RPD/RPE fields.
    ///
    /// Per draft-ietf-ippm-stamp-cos-ecn-01 §3.2, when RPE = 0b10 (the
    /// reflector was unable to set the reply's ECN to EC1) the reply's
    /// on-wire ECN bits MUST be forced to 0b00 (Not-ECT) rather than left
    /// at whatever value the packet previously carried — this is the one
    /// normative delta over -00, which only required the RPE signal
    /// itself. The DSCP half of the byte is unaffected by this rule and
    /// still follows RPD / [`ClassOfServiceTlv::effective_dscp`].
    #[must_use]
    pub fn reply_wire_tos(&self) -> u8 {
        let dscp = self.effective_dscp(self.policy_rejected());
        let ecn = if self.reply_ecn_was_set() {
            self.ecn1
        } else {
            0
        };
        ((dscp & 0x3F) << 2) | (ecn & 0x03)
    }
}

impl TypedTlv for ClassOfServiceTlv {
    const TYPE: TlvType = TlvType::ClassOfService;

    fn decode_value(value: &[u8]) -> Result<Self, TlvError> {
        if value.len() != COS_TLV_VALUE_SIZE {
            return Err(TlvError::InvalidCosLength(value.len()));
        }
        let dscp1 = (value[0] >> 2) & 0x3F;
        let dscp2 = ((value[0] & 0x03) << 4) | ((value[1] >> 4) & 0x0F);
        let ecn2 = (value[1] >> 2) & 0x03;
        let rpd = value[1] & 0x03;
        let ecn1 = (value[2] >> 6) & 0x03;
        let rpe = (value[2] >> 4) & 0x03;
        Ok(Self {
            dscp1,
            ecn1,
            dscp2,
            ecn2,
            rpd,
            rpe,
        })
    }

    fn encode_value(&self, out: &mut Vec<u8>) {
        out.push(((self.dscp1 & 0x3F) << 2) | ((self.dscp2 >> 4) & 0x03));
        out.push(((self.dscp2 & 0x0F) << 4) | ((self.ecn2 & 0x03) << 2) | (self.rpd & 0x03));
        out.push(((self.ecn1 & 0x03) << 6) | ((self.rpe & 0x03) << 4));
        out.push(0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tlv::core::RawTlv;

    #[test]
    fn test_cos_tlv_new() {
        let cos = ClassOfServiceTlv::new(46, 2);
        assert_eq!(cos.dscp1, 46);
        assert_eq!(cos.ecn1, 2);
        assert_eq!(cos.dscp2, 0);
        assert_eq!(cos.ecn2, 0);
        assert_eq!(cos.rpd, 0);
        assert_eq!(cos.rpe, 0, "sender MUST transmit RPE as 0b00");
    }

    #[test]
    fn test_cos_tlv_new_clamps_values() {
        let cos = ClassOfServiceTlv::new(0xFF, 0xFF);
        assert_eq!(cos.dscp1, 0x3F);
        assert_eq!(cos.ecn1, 0x03);
    }

    #[test]
    fn test_cos_tlv_for_response() {
        let cos = ClassOfServiceTlv::for_response(46, 2, 0, 1, false, true);
        assert_eq!(cos.dscp1, 46);
        assert_eq!(cos.ecn1, 2);
        assert_eq!(cos.dscp2, 0);
        assert_eq!(cos.ecn2, 1);
        assert_eq!(cos.rpd, 0);
        assert_eq!(cos.rpe, 0b11, "ECN applied to the reply → RPE=0b11");
        assert!(!cos.policy_rejected());
        assert!(cos.reply_ecn_was_set());
    }

    #[test]
    fn test_cos_tlv_for_response_policy_rejected() {
        let cos = ClassOfServiceTlv::for_response(46, 2, 0, 1, true, false);
        assert_eq!(cos.rpd, 0b01);
        assert_eq!(cos.rpe, 0b10, "ECN not applied → RPE=0b10");
        assert!(cos.policy_rejected());
        assert!(!cos.reply_ecn_was_set());
    }

    #[test]
    fn test_cos_tlv_to_raw() {
        // RFC 8972 §4.4 layout: byte0 = DSCP1(6) | DSCP2[5:4]. With
        // DSCP2 = 0, byte0 is 46 << 2 = 0xB8 and EC1 lands in byte2[7:6].
        let cos = ClassOfServiceTlv::new(46, 2);
        let raw = cos.to_raw();
        assert_eq!(raw.tlv_type, TlvType::ClassOfService);
        assert_eq!(raw.value.len(), COS_TLV_VALUE_SIZE);
        assert_eq!(raw.value[0], 0xB8);
        assert_eq!(raw.value[1], 0x00);
        assert_eq!(raw.value[2], 0x80, "EC1=2 sits in byte2 bits 7:6");
        assert_eq!(raw.value[3], 0x00);
    }

    #[test]
    fn test_cos_tlv_draft_figure_cross_vector() {
        // Hand-computed from draft-ietf-ippm-stamp-cos-ecn-01 Figure 1, §3.1
        // (| DSCP1 | DSCP2 |EC2|RPD|EC1|RPE| Reserved |; byte-identical to
        // -00's Figure 1). The same bytes round-trip through teaparty's CoS
        // decoder, pinning interop.
        // DSCP1=46 (0b101110), DSCP2=20 (0b010100), EC2=1, RPD=0,
        // EC1=2, RPE=3:
        //   byte0 = 101110_01          = 0xB9
        //   byte1 = 0100_01_00         = 0x44
        //   byte2 = 10_11_0000         = 0xB0
        let wire = [0xB9u8, 0x44, 0xB0, 0x00];

        let parsed =
            ClassOfServiceTlv::from_raw(&RawTlv::new(TlvType::ClassOfService, wire.to_vec()))
                .unwrap();
        assert_eq!(parsed.dscp1, 46);
        assert_eq!(parsed.dscp2, 20);
        assert_eq!(parsed.ecn2, 1);
        assert_eq!(parsed.rpd, 0);
        assert_eq!(parsed.ecn1, 2);
        assert_eq!(parsed.rpe, 3);

        assert_eq!(parsed.to_raw().value, wire, "encode must mirror decode");
    }

    #[test]
    fn test_cos_tlv_roundtrip() {
        let original = ClassOfServiceTlv::for_response(46, 2, 10, 1, true, true);
        let raw = original.to_raw();
        let parsed = ClassOfServiceTlv::from_raw(&raw).unwrap();
        assert_eq!(parsed, original);
    }

    #[test]
    fn test_cos_tlv_from_raw_invalid_length() {
        let raw = RawTlv::new(TlvType::ClassOfService, vec![0, 0]);
        let result = ClassOfServiceTlv::from_raw(&raw);
        assert!(matches!(result, Err(TlvError::InvalidCosLength(2))));
    }

    #[test]
    fn test_cos_tlv_effective_dscp() {
        let cos = ClassOfServiceTlv::for_response(46, 2, 10, 1, false, true);
        assert_eq!(cos.effective_dscp(false), 46);
        assert_eq!(cos.effective_dscp(true), 10);
    }

    #[test]
    fn test_reply_wire_tos_success_uses_ec1() {
        // draft-ietf-ippm-stamp-cos-ecn-01 §3.2 success path (unchanged from
        // -00): RPE=0b11, reply ECN = EC1.
        let cos = ClassOfServiceTlv::for_response(46, 2, 10, 1, false, true);
        assert_eq!(cos.rpe, 0b11);
        assert_eq!(cos.reply_wire_tos(), 0xBA); // (46 << 2) | 2
    }

    #[test]
    fn test_reply_wire_tos_unable_zeroes_ecn_bits() {
        // draft-ietf-ippm-stamp-cos-ecn-01 §3.2 MUST rule (the -01 delta):
        // when the reflector is unable to set EC1, RPE=0b10 AND the
        // reply's on-wire ECN bits must be forced to 0b00 — asserted here
        // on the actual computed TOS byte, not just the TLV's RPE field.
        let cos = ClassOfServiceTlv::for_response(46, 2, 10, 1, false, false);
        assert_eq!(cos.rpe, 0b10, "unable to set EC1 => RPE=0b10");
        let tos = cos.reply_wire_tos();
        assert_eq!(
            tos & 0x03,
            0,
            "reply's wire ECN bits MUST be 0b00 (-01 §3.2)"
        );
        assert_eq!(
            tos >> 2,
            46,
            "DSCP bits are unaffected by the ECN-only MUST rule"
        );
    }

    #[test]
    fn test_reply_wire_tos_policy_rejected_uses_dscp2() {
        // RPD cross-check (-01 §3.2, unchanged from -00): local policy
        // rejecting DSCP1 must make the reply use the received DSCP
        // (DSCP2), independently of whether EC1 was applied.
        let cos = ClassOfServiceTlv::for_response(46, 2, 10, 1, true, true);
        assert_eq!(cos.rpd, 0b01);
        assert_eq!(
            cos.reply_wire_tos(),
            (10 << 2) | 2,
            "DSCP2 used, EC1 still applied"
        );
    }

    #[test]
    fn test_wire_tos_packs_dscp_and_ecn() {
        // EF (DSCP 46) with ECN(0) => (46 << 2) | 0 = 0xB8
        assert_eq!(ClassOfServiceTlv::new(46, 0).wire_tos(), 0xB8);
        // EF (DSCP 46) with CE (ECN 3) => (46 << 2) | 3 = 0xBB
        assert_eq!(ClassOfServiceTlv::new(46, 3).wire_tos(), 0xBB);
        // ECN-only
        assert_eq!(ClassOfServiceTlv::new(0, 3).wire_tos(), 0x03);
        // Maximum values saturate the whole byte
        assert_eq!(ClassOfServiceTlv::new(63, 3).wire_tos(), 0xFF);
        // Out-of-range inputs are masked by new()
        assert_eq!(ClassOfServiceTlv::new(0xFF, 0xFF).wire_tos(), 0xFF);
    }

    #[test]
    fn test_wire_tos_is_independent_of_received_fields() {
        // wire_tos() packs the *requested* DSCP1/EC1 pair for the IP TOS /
        // Traffic Class field. Unlike the pre-cos-ecn layout it no longer
        // equals encoded byte 0, which carries DSCP2's upper bits.
        let cos = ClassOfServiceTlv::for_response(46, 2, 20, 1, false, true);
        assert_eq!(cos.wire_tos(), 0xBA); // (46 << 2) | 2
        assert_ne!(cos.wire_tos(), cos.to_raw().value[0]);
    }

    #[test]
    fn test_cos_tlv_wire_format_boundary_values() {
        let cos = ClassOfServiceTlv {
            dscp1: 63,
            ecn1: 3,
            dscp2: 63,
            ecn2: 3,
            rpd: 3,
            rpe: 3,
        };
        let raw = cos.to_raw();
        assert_eq!(raw.value[0], 0xFF);
        assert_eq!(raw.value[1], 0xFF);
        assert_eq!(raw.value[2], 0xF0);
        assert_eq!(raw.value[3], 0x00);

        let parsed = ClassOfServiceTlv::from_raw(&raw).unwrap();
        assert_eq!(parsed, cos);
    }
}
