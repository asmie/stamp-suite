//! Class of Service TLV (Type 4) per RFC 8972 §4.4.

use crate::tlv::core::{TlvError, TlvType, COS_TLV_VALUE_SIZE};
use crate::tlv::traits::TypedTlv;

/// Class of Service TLV (Type 4) for DSCP/ECN measurement per RFC 8972 §4.4.
///
/// Enables measurement of DSCP and ECN field manipulation by middleboxes.
///
/// # Wire Format
///
/// ```text
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |   DSCP1   |ECN|   DSCP2   |EC2| RP|        Reserved           |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ClassOfServiceTlv {
    /// DSCP value intended for reflected packet (6 bits, 0-63).
    pub dscp1: u8,
    /// ECN value intended for reflected packet (2 bits, 0-3).
    pub ecn1: u8,
    /// DSCP value received at Session-Reflector's ingress (6 bits, 0-63).
    pub dscp2: u8,
    /// ECN value received at Session-Reflector's ingress (2 bits, 0-3).
    pub ecn2: u8,
    /// Reverse Path flag (2 bits).
    pub rp: u8,
}

impl ClassOfServiceTlv {
    /// Creates a new CoS TLV for the sender (DSCP2/ECN2/RP are zero).
    #[must_use]
    pub fn new(dscp: u8, ecn: u8) -> Self {
        Self {
            dscp1: dscp & 0x3F,
            ecn1: ecn & 0x03,
            dscp2: 0,
            ecn2: 0,
            rp: 0,
        }
    }

    /// Creates a CoS TLV for the reflector response.
    #[must_use]
    pub fn for_response(
        dscp1: u8,
        ecn1: u8,
        received_dscp: u8,
        received_ecn: u8,
        policy_rejected: bool,
    ) -> Self {
        Self {
            dscp1: dscp1 & 0x3F,
            ecn1: ecn1 & 0x03,
            dscp2: received_dscp & 0x3F,
            ecn2: received_ecn & 0x03,
            rp: if policy_rejected { 1 } else { 0 },
        }
    }

    /// Returns true if the reflector's policy rejected the requested DSCP.
    #[must_use]
    pub fn policy_rejected(&self) -> bool {
        self.rp != 0
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
}

impl TypedTlv for ClassOfServiceTlv {
    const TYPE: TlvType = TlvType::ClassOfService;

    fn decode_value(value: &[u8]) -> Result<Self, TlvError> {
        if value.len() != COS_TLV_VALUE_SIZE {
            return Err(TlvError::InvalidCosLength(value.len()));
        }
        let dscp1 = (value[0] >> 2) & 0x3F;
        let ecn1 = value[0] & 0x03;
        let dscp2 = (value[1] >> 2) & 0x3F;
        let ecn2 = value[1] & 0x03;
        let rp = (value[2] >> 6) & 0x03;
        Ok(Self {
            dscp1,
            ecn1,
            dscp2,
            ecn2,
            rp,
        })
    }

    fn encode_value(&self, out: &mut Vec<u8>) {
        out.push(((self.dscp1 & 0x3F) << 2) | (self.ecn1 & 0x03));
        out.push(((self.dscp2 & 0x3F) << 2) | (self.ecn2 & 0x03));
        out.push((self.rp & 0x03) << 6);
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
        assert_eq!(cos.rp, 0);
    }

    #[test]
    fn test_cos_tlv_new_clamps_values() {
        let cos = ClassOfServiceTlv::new(0xFF, 0xFF);
        assert_eq!(cos.dscp1, 0x3F);
        assert_eq!(cos.ecn1, 0x03);
    }

    #[test]
    fn test_cos_tlv_for_response() {
        let cos = ClassOfServiceTlv::for_response(46, 2, 0, 1, false);
        assert_eq!(cos.dscp1, 46);
        assert_eq!(cos.ecn1, 2);
        assert_eq!(cos.dscp2, 0);
        assert_eq!(cos.ecn2, 1);
        assert_eq!(cos.rp, 0);
        assert!(!cos.policy_rejected());
    }

    #[test]
    fn test_cos_tlv_for_response_policy_rejected() {
        let cos = ClassOfServiceTlv::for_response(46, 2, 0, 1, true);
        assert_eq!(cos.rp, 1);
        assert!(cos.policy_rejected());
    }

    #[test]
    fn test_cos_tlv_to_raw() {
        let cos = ClassOfServiceTlv::new(46, 2);
        let raw = cos.to_raw();
        assert_eq!(raw.tlv_type, TlvType::ClassOfService);
        assert_eq!(raw.value.len(), COS_TLV_VALUE_SIZE);
        assert_eq!(raw.value[0], 0xBA);
        assert_eq!(raw.value[1], 0x00);
        assert_eq!(raw.value[2], 0x00);
        assert_eq!(raw.value[3], 0x00);
    }

    #[test]
    fn test_cos_tlv_roundtrip() {
        let original = ClassOfServiceTlv::for_response(46, 2, 10, 1, true);
        let raw = original.to_raw();
        let parsed = ClassOfServiceTlv::from_raw(&raw).unwrap();
        assert_eq!(parsed.dscp1, original.dscp1);
        assert_eq!(parsed.ecn1, original.ecn1);
        assert_eq!(parsed.dscp2, original.dscp2);
        assert_eq!(parsed.ecn2, original.ecn2);
        assert_eq!(parsed.rp, original.rp);
    }

    #[test]
    fn test_cos_tlv_from_raw_invalid_length() {
        let raw = RawTlv::new(TlvType::ClassOfService, vec![0, 0]);
        let result = ClassOfServiceTlv::from_raw(&raw);
        assert!(matches!(result, Err(TlvError::InvalidCosLength(2))));
    }

    #[test]
    fn test_cos_tlv_effective_dscp() {
        let cos = ClassOfServiceTlv::for_response(46, 2, 10, 1, false);
        assert_eq!(cos.effective_dscp(false), 46);
        assert_eq!(cos.effective_dscp(true), 10);
    }

    #[test]
    fn test_cos_tlv_wire_format_boundary_values() {
        let cos = ClassOfServiceTlv {
            dscp1: 63,
            ecn1: 3,
            dscp2: 63,
            ecn2: 3,
            rp: 3,
        };
        let raw = cos.to_raw();
        assert_eq!(raw.value[0], 0xFF);
        assert_eq!(raw.value[1], 0xFF);
        assert_eq!(raw.value[2], 0xC0);

        let parsed = ClassOfServiceTlv::from_raw(&raw).unwrap();
        assert_eq!(parsed.dscp1, 63);
        assert_eq!(parsed.ecn1, 3);
        assert_eq!(parsed.dscp2, 63);
        assert_eq!(parsed.ecn2, 3);
        assert_eq!(parsed.rp, 3);
    }
}
