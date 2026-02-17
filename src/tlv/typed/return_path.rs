//! Return Path TLV (Type 10) per RFC 9503 §5.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use crate::tlv::core::{RawTlv, TlvError, TlvType, RETURN_PATH_CONTROL_CODE_SIZE, TLV_HEADER_SIZE};
use crate::tlv::list::TlvList;

/// Return Path sub-TLV type identifiers per RFC 9503 §5.
///
/// Sub-TLVs use the standard 4-byte STAMP TLV header format.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReturnPathSubType {
    /// Control Code sub-TLV (1).
    ControlCode,
    /// Return Address sub-TLV (2).
    ReturnAddress,
    /// SR-MPLS Label Stack sub-TLV (3).
    SrMplsLabelStack,
    /// SRv6 Segment List sub-TLV (4).
    Srv6SegmentList,
    /// Unknown sub-type.
    Unknown(u8),
}

impl ReturnPathSubType {
    /// Creates a ReturnPathSubType from a byte value.
    #[must_use]
    pub fn from_byte(byte: u8) -> Self {
        match byte {
            1 => Self::ControlCode,
            2 => Self::ReturnAddress,
            3 => Self::SrMplsLabelStack,
            4 => Self::Srv6SegmentList,
            n => Self::Unknown(n),
        }
    }

    /// Converts the sub-type to a byte value.
    #[must_use]
    pub fn to_byte(self) -> u8 {
        match self {
            Self::ControlCode => 1,
            Self::ReturnAddress => 2,
            Self::SrMplsLabelStack => 3,
            Self::Srv6SegmentList => 4,
            Self::Unknown(n) => n,
        }
    }
}

/// Return Path TLV (Type 10) per RFC 9503 §5.
///
/// Contains sub-TLVs that specify how the reflector should route its reply.
/// Sub-TLVs use the standard 4-byte STAMP TLV header (Flags | Type | Length x 2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReturnPathTlv {
    /// Sub-TLVs within this Return Path TLV.
    pub sub_tlvs: Vec<RawTlv>,
}

impl ReturnPathTlv {
    /// Creates an empty Return Path TLV.
    #[must_use]
    pub fn new() -> Self {
        Self {
            sub_tlvs: Vec::new(),
        }
    }

    /// Creates a Return Path TLV with a Control Code sub-TLV.
    #[must_use]
    pub fn with_control_code(code: u32) -> Self {
        let value = code.to_be_bytes().to_vec();
        let sub = RawTlv::new(
            TlvType::Unknown(ReturnPathSubType::ControlCode.to_byte()),
            value,
        );
        Self {
            sub_tlvs: vec![sub],
        }
    }

    /// Creates a Return Path TLV with a Return Address sub-TLV.
    #[must_use]
    pub fn with_return_address(addr: IpAddr) -> Self {
        let value = match addr {
            IpAddr::V4(a) => a.octets().to_vec(),
            IpAddr::V6(a) => a.octets().to_vec(),
        };
        let sub = RawTlv::new(
            TlvType::Unknown(ReturnPathSubType::ReturnAddress.to_byte()),
            value,
        );
        Self {
            sub_tlvs: vec![sub],
        }
    }

    /// Creates a Return Path TLV with an SR-MPLS Label Stack sub-TLV.
    ///
    /// Each label is a 20-bit MPLS label value, encoded as a proper 4-byte
    /// MPLS Label Stack Entry (LSE): Label(20) | TC(3) | S(1) | TTL(8).
    /// TC is set to 0, TTL to 255, and the S-bit (bottom-of-stack) is set
    /// on the last entry only.
    #[must_use]
    pub fn with_sr_mpls_labels(labels: &[u32]) -> Self {
        let mut value = Vec::with_capacity(labels.len() * 4);
        let last = labels.len().saturating_sub(1);
        for (i, label) in labels.iter().enumerate() {
            let s_bit: u32 = if i == last { 1 } else { 0 };
            let lse = (label << 12) | (s_bit << 8) | 255; // TC=0, TTL=255
            value.extend_from_slice(&lse.to_be_bytes());
        }
        let sub = RawTlv::new(
            TlvType::Unknown(ReturnPathSubType::SrMplsLabelStack.to_byte()),
            value,
        );
        Self {
            sub_tlvs: vec![sub],
        }
    }

    /// Creates a Return Path TLV with an SRv6 Segment List sub-TLV.
    ///
    /// Each SID is encoded as a 16-byte IPv6 address.
    #[must_use]
    pub fn with_srv6_sids(sids: &[Ipv6Addr]) -> Self {
        let mut value = Vec::with_capacity(sids.len() * 16);
        for sid in sids {
            value.extend_from_slice(&sid.octets());
        }
        let sub = RawTlv::new(
            TlvType::Unknown(ReturnPathSubType::Srv6SegmentList.to_byte()),
            value,
        );
        Self {
            sub_tlvs: vec![sub],
        }
    }

    /// Adds a Return Address sub-TLV to this Return Path TLV.
    pub fn add_return_address(&mut self, addr: IpAddr) {
        let value = match addr {
            IpAddr::V4(a) => a.octets().to_vec(),
            IpAddr::V6(a) => a.octets().to_vec(),
        };
        self.sub_tlvs.push(RawTlv::new(
            TlvType::Unknown(ReturnPathSubType::ReturnAddress.to_byte()),
            value,
        ));
    }

    /// Parses a Return Path TLV from a RawTlv.
    ///
    /// The value is parsed as a sequence of sub-TLVs using the standard 4-byte header.
    ///
    /// # Errors
    /// Returns an error if the value is too short to contain any sub-TLV.
    pub fn from_raw(raw: &RawTlv) -> Result<Self, TlvError> {
        if raw.value.len() < TLV_HEADER_SIZE {
            return Err(TlvError::InvalidReturnPathLength(raw.value.len()));
        }
        let (sub_tlvs_list, _) = TlvList::parse_lenient(&raw.value);
        let mut sub_tlvs = Vec::new();
        for tlv in sub_tlvs_list.non_hmac_tlvs() {
            sub_tlvs.push(tlv.clone());
        }
        if let Some(hmac) = sub_tlvs_list.hmac_tlv() {
            sub_tlvs.push(hmac.clone());
        }
        Ok(Self { sub_tlvs })
    }

    /// Converts to a RawTlv.
    #[must_use]
    pub fn to_raw(&self) -> RawTlv {
        let mut value = Vec::new();
        for sub in &self.sub_tlvs {
            sub.write_to(&mut value);
        }
        RawTlv::new(TlvType::ReturnPath, value)
    }

    /// Returns the Control Code value if a Control Code sub-TLV is present.
    #[must_use]
    pub fn get_control_code(&self) -> Option<u32> {
        for sub in &self.sub_tlvs {
            if sub.tlv_type.to_byte() == ReturnPathSubType::ControlCode.to_byte()
                && sub.value.len() == RETURN_PATH_CONTROL_CODE_SIZE
            {
                return Some(u32::from_be_bytes([
                    sub.value[0],
                    sub.value[1],
                    sub.value[2],
                    sub.value[3],
                ]));
            }
        }
        None
    }

    /// Returns the Return Address if a Return Address sub-TLV is present.
    #[must_use]
    pub fn get_return_address(&self) -> Option<IpAddr> {
        for sub in &self.sub_tlvs {
            if sub.tlv_type.to_byte() == ReturnPathSubType::ReturnAddress.to_byte() {
                match sub.value.len() {
                    4 => {
                        return Some(IpAddr::V4(Ipv4Addr::new(
                            sub.value[0],
                            sub.value[1],
                            sub.value[2],
                            sub.value[3],
                        )));
                    }
                    16 => {
                        let mut octets = [0u8; 16];
                        octets.copy_from_slice(&sub.value);
                        return Some(IpAddr::V6(Ipv6Addr::from(octets)));
                    }
                    _ => {}
                }
            }
        }
        None
    }

    /// Returns true if an SR-MPLS Label Stack sub-TLV is present.
    #[must_use]
    pub fn has_sr_mpls(&self) -> bool {
        self.sub_tlvs
            .iter()
            .any(|sub| sub.tlv_type.to_byte() == ReturnPathSubType::SrMplsLabelStack.to_byte())
    }

    /// Returns true if an SRv6 Segment List sub-TLV is present.
    #[must_use]
    pub fn has_srv6(&self) -> bool {
        self.sub_tlvs
            .iter()
            .any(|sub| sub.tlv_type.to_byte() == ReturnPathSubType::Srv6SegmentList.to_byte())
    }
}

impl Default for ReturnPathTlv {
    fn default() -> Self {
        Self::new()
    }
}

/// Action determined by processing a Return Path TLV (RFC 9503 §5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReturnPathAction {
    /// Normal reply (no Return Path TLV, or Control Code 0x1 same-link).
    Normal,
    /// Suppress reply entirely (Control Code 0x0).
    SuppressReply,
    /// Reply to an alternate address (Return Address sub-TLV).
    AlternateAddress(SocketAddr),
    /// SR forwarding requested but unsupported -- echo with U-flag, reply normally.
    UnsupportedSr,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sub_type_roundtrip() {
        let types = [
            ReturnPathSubType::ControlCode,
            ReturnPathSubType::ReturnAddress,
            ReturnPathSubType::SrMplsLabelStack,
            ReturnPathSubType::Srv6SegmentList,
            ReturnPathSubType::Unknown(42),
        ];
        for t in &types {
            let byte = t.to_byte();
            let parsed = ReturnPathSubType::from_byte(byte);
            assert_eq!(*t, parsed);
        }
    }

    #[test]
    fn test_control_code_roundtrip() {
        let rp = ReturnPathTlv::with_control_code(0x0000_0001);
        let raw = rp.to_raw();
        let parsed = ReturnPathTlv::from_raw(&raw).unwrap();
        assert_eq!(parsed.get_control_code(), Some(0x0000_0001));
    }

    #[test]
    fn test_return_address_ipv4_roundtrip() {
        let addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let rp = ReturnPathTlv::with_return_address(addr);
        let raw = rp.to_raw();
        let parsed = ReturnPathTlv::from_raw(&raw).unwrap();
        assert_eq!(parsed.get_return_address(), Some(addr));
    }

    #[test]
    fn test_return_address_ipv6_roundtrip() {
        let addr = IpAddr::V6(Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1));
        let rp = ReturnPathTlv::with_return_address(addr);
        let raw = rp.to_raw();
        let parsed = ReturnPathTlv::from_raw(&raw).unwrap();
        assert_eq!(parsed.get_return_address(), Some(addr));
    }

    #[test]
    fn test_sr_mpls_roundtrip() {
        let labels = [100, 200, 300];
        let rp = ReturnPathTlv::with_sr_mpls_labels(&labels);
        let raw = rp.to_raw();
        let parsed = ReturnPathTlv::from_raw(&raw).unwrap();
        assert!(parsed.has_sr_mpls());
        assert!(!parsed.has_srv6());

        // Verify LSE encoding: label(20) | TC(3)=0 | S(1) | TTL(8)=255
        let sub = &parsed.sub_tlvs[0];
        assert_eq!(
            sub.tlv_type.to_byte(),
            ReturnPathSubType::SrMplsLabelStack.to_byte()
        );
        // 3 labels * 4 bytes each
        assert_eq!(sub.value.len(), 12);

        // First label: 100, S=0, TTL=255
        let lse0 = u32::from_be_bytes([sub.value[0], sub.value[1], sub.value[2], sub.value[3]]);
        assert_eq!(lse0 >> 12, 100); // label
        assert_eq!((lse0 >> 8) & 0x1, 0); // S-bit = 0
        assert_eq!(lse0 & 0xFF, 255); // TTL

        // Second label: 200, S=0, TTL=255
        let lse1 = u32::from_be_bytes([sub.value[4], sub.value[5], sub.value[6], sub.value[7]]);
        assert_eq!(lse1 >> 12, 200);
        assert_eq!((lse1 >> 8) & 0x1, 0);
        assert_eq!(lse1 & 0xFF, 255);

        // Third label (last): 300, S=1, TTL=255
        let lse2 = u32::from_be_bytes([sub.value[8], sub.value[9], sub.value[10], sub.value[11]]);
        assert_eq!(lse2 >> 12, 300);
        assert_eq!((lse2 >> 8) & 0x1, 1); // S-bit = 1 (bottom of stack)
        assert_eq!(lse2 & 0xFF, 255);
    }

    #[test]
    fn test_srv6_roundtrip() {
        let sids = [
            Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1),
            Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2),
        ];
        let rp = ReturnPathTlv::with_srv6_sids(&sids);
        let raw = rp.to_raw();
        let parsed = ReturnPathTlv::from_raw(&raw).unwrap();
        assert!(parsed.has_srv6());
        assert!(!parsed.has_sr_mpls());

        let sub = &parsed.sub_tlvs[0];
        assert_eq!(
            sub.tlv_type.to_byte(),
            ReturnPathSubType::Srv6SegmentList.to_byte()
        );
        // 2 SIDs * 16 bytes each
        assert_eq!(sub.value.len(), 32);
    }

    #[test]
    fn test_return_path_empty_value_error() {
        let raw = RawTlv::new(TlvType::ReturnPath, vec![]);
        let result = ReturnPathTlv::from_raw(&raw);
        assert!(matches!(result, Err(TlvError::InvalidReturnPathLength(0))));
    }

    #[test]
    fn test_add_return_address() {
        let mut rp = ReturnPathTlv::with_control_code(1);
        let addr = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        rp.add_return_address(addr);
        assert_eq!(rp.sub_tlvs.len(), 2);

        let raw = rp.to_raw();
        let parsed = ReturnPathTlv::from_raw(&raw).unwrap();
        assert_eq!(parsed.get_control_code(), Some(1));
        assert_eq!(parsed.get_return_address(), Some(addr));
    }
}
