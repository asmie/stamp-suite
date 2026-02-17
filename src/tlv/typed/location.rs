//! Location TLV (Type 2) per RFC 8972 §4.2.

use crate::tlv::core::{TlvError, TlvType, LOCATION_TLV_MIN_VALUE_SIZE};
use crate::tlv::traits::TypedTlv;

/// Location sub-TLV types per RFC 8972 §4.2.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum LocationSubType {
    /// IPv4 source address (4 bytes).
    Ipv4Src = 1,
    /// IPv4 destination address (4 bytes).
    Ipv4Dst = 2,
    /// IPv6 source address (16 bytes).
    Ipv6Src = 3,
    /// IPv6 destination address (16 bytes).
    Ipv6Dst = 4,
    /// Autonomous System Number (4 bytes).
    Asn = 5,
    /// Interface name (variable).
    IfName = 6,
    /// Interface index (4 bytes).
    IfIndex = 7,
    /// MPLS label stack (variable).
    MplsLabel = 8,
    /// Segment Routing SID (variable).
    SrSid = 9,
    /// Unknown sub-type.
    Unknown(u8),
}

impl LocationSubType {
    /// Creates a LocationSubType from a byte value.
    #[must_use]
    pub fn from_byte(byte: u8) -> Self {
        match byte {
            1 => Self::Ipv4Src,
            2 => Self::Ipv4Dst,
            3 => Self::Ipv6Src,
            4 => Self::Ipv6Dst,
            5 => Self::Asn,
            6 => Self::IfName,
            7 => Self::IfIndex,
            8 => Self::MplsLabel,
            9 => Self::SrSid,
            n => Self::Unknown(n),
        }
    }

    /// Converts to a byte value.
    #[must_use]
    pub fn to_byte(self) -> u8 {
        match self {
            Self::Ipv4Src => 1,
            Self::Ipv4Dst => 2,
            Self::Ipv6Src => 3,
            Self::Ipv6Dst => 4,
            Self::Asn => 5,
            Self::IfName => 6,
            Self::IfIndex => 7,
            Self::MplsLabel => 8,
            Self::SrSid => 9,
            Self::Unknown(n) => n,
        }
    }
}

/// A single location sub-TLV within the Location TLV.
///
/// # Wire Format
///
/// ```text
///  0         1         2         3
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |   Sub-Type    |    Length      |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |            Value ...           |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocationSubTlv {
    /// Sub-TLV type.
    pub sub_type: LocationSubType,
    /// Sub-TLV value.
    pub value: Vec<u8>,
}

impl LocationSubTlv {
    /// Creates a new location sub-TLV.
    #[must_use]
    pub fn new(sub_type: LocationSubType, value: Vec<u8>) -> Self {
        Self { sub_type, value }
    }

    /// Appends the serialized sub-TLV directly to an existing buffer.
    pub fn write_to(&self, buf: &mut Vec<u8>) {
        buf.push(self.sub_type.to_byte());
        buf.push(self.value.len() as u8);
        buf.extend_from_slice(&self.value);
    }

    /// Serializes the sub-TLV to bytes.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(2 + self.value.len());
        self.write_to(&mut buf);
        buf
    }

    /// Parses a sub-TLV from a byte slice.
    ///
    /// Returns the parsed sub-TLV and bytes consumed, or None if buffer is too small.
    #[must_use]
    pub fn parse(buf: &[u8]) -> Option<(Self, usize)> {
        if buf.len() < 2 {
            return None;
        }
        let sub_type = LocationSubType::from_byte(buf[0]);
        let length = buf[1] as usize;
        if buf.len() < 2 + length {
            return None;
        }
        let value = buf[2..2 + length].to_vec();
        Some((Self { sub_type, value }, 2 + length))
    }
}

/// Location TLV (Type 2) per RFC 8972 §4.2.
///
/// Carries source/destination ports and sub-TLVs for addresses.
/// The reflector fills in its observed ports and addresses.
///
/// # Wire Format
///
/// ```text
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |         Dest Port             |         Source Port            |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |         Sub-TLVs ...                                          |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocationTlv {
    /// Destination port.
    pub dest_port: u16,
    /// Source port.
    pub src_port: u16,
    /// Sub-TLVs containing address information.
    pub sub_tlvs: Vec<LocationSubTlv>,
}

impl LocationTlv {
    /// Creates a new empty Location TLV (sender requests reflector to fill).
    #[must_use]
    pub fn new() -> Self {
        Self {
            dest_port: 0,
            src_port: 0,
            sub_tlvs: Vec::new(),
        }
    }
}

impl Default for LocationTlv {
    fn default() -> Self {
        Self::new()
    }
}

impl TypedTlv for LocationTlv {
    const TYPE: TlvType = TlvType::Location;

    fn decode_value(value: &[u8]) -> Result<Self, TlvError> {
        if value.len() < LOCATION_TLV_MIN_VALUE_SIZE {
            return Err(TlvError::InvalidLocationLength(value.len()));
        }
        let dest_port = u16::from_be_bytes([value[0], value[1]]);
        let src_port = u16::from_be_bytes([value[2], value[3]]);

        let mut sub_tlvs = Vec::new();
        let mut offset = 4;
        while offset < value.len() {
            if let Some((sub, consumed)) = LocationSubTlv::parse(&value[offset..]) {
                sub_tlvs.push(sub);
                offset += consumed;
            } else {
                break;
            }
        }

        Ok(Self {
            dest_port,
            src_port,
            sub_tlvs,
        })
    }

    fn encode_value(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.dest_port.to_be_bytes());
        out.extend_from_slice(&self.src_port.to_be_bytes());
        for sub in &self.sub_tlvs {
            sub.write_to(out);
        }
    }
}

/// Packet address information for Location TLV processing.
///
/// Used by the reflector to fill in the Location TLV with observed addresses/ports.
#[derive(Debug, Clone)]
pub struct PacketAddressInfo {
    /// Source IP address of the received packet.
    pub src_addr: std::net::IpAddr,
    /// Source port of the received packet.
    pub src_port: u16,
    /// Destination IP address of the received packet.
    pub dst_addr: std::net::IpAddr,
    /// Destination port of the received packet.
    pub dst_port: u16,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tlv::core::RawTlv;

    #[test]
    fn test_sub_type_roundtrip() {
        let types = [
            LocationSubType::Ipv4Src,
            LocationSubType::Ipv4Dst,
            LocationSubType::Ipv6Src,
            LocationSubType::Ipv6Dst,
            LocationSubType::Asn,
            LocationSubType::IfName,
            LocationSubType::IfIndex,
            LocationSubType::MplsLabel,
            LocationSubType::SrSid,
            LocationSubType::Unknown(42),
        ];
        for t in &types {
            let byte = t.to_byte();
            let parsed = LocationSubType::from_byte(byte);
            assert_eq!(*t, parsed);
        }
    }

    #[test]
    fn test_sub_tlv_to_bytes_and_parse() {
        let sub = LocationSubTlv::new(LocationSubType::Ipv4Src, vec![192, 168, 1, 1]);
        let bytes = sub.to_bytes();
        assert_eq!(bytes[0], 1); // Ipv4Src
        assert_eq!(bytes[1], 4); // length
        assert_eq!(&bytes[2..], &[192, 168, 1, 1]);

        let (parsed, consumed) = LocationSubTlv::parse(&bytes).unwrap();
        assert_eq!(consumed, 6);
        assert_eq!(parsed, sub);
    }

    #[test]
    fn test_sub_tlv_ipv6() {
        let addr_bytes = [
            0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x01,
        ];
        let sub = LocationSubTlv::new(LocationSubType::Ipv6Src, addr_bytes.to_vec());
        let bytes = sub.to_bytes();
        let (parsed, consumed) = LocationSubTlv::parse(&bytes).unwrap();
        assert_eq!(consumed, 18);
        assert_eq!(parsed.sub_type, LocationSubType::Ipv6Src);
        assert_eq!(parsed.value, addr_bytes);
    }

    #[test]
    fn test_sub_tlv_parse_too_short() {
        let result = LocationSubTlv::parse(&[0x01]);
        assert!(result.is_none());
    }

    #[test]
    fn test_sub_tlv_parse_truncated_value() {
        // Header says 4 bytes but only 2 available
        let buf = [0x01, 0x04, 0xAA, 0xBB];
        let result = LocationSubTlv::parse(&buf);
        assert!(result.is_none());
    }

    #[test]
    fn test_location_tlv_new() {
        let tlv = LocationTlv::new();
        assert_eq!(tlv.dest_port, 0);
        assert_eq!(tlv.src_port, 0);
        assert!(tlv.sub_tlvs.is_empty());
    }

    #[test]
    fn test_location_tlv_default() {
        let tlv = LocationTlv::default();
        assert_eq!(tlv.dest_port, 0);
        assert_eq!(tlv.src_port, 0);
        assert!(tlv.sub_tlvs.is_empty());
    }

    #[test]
    fn test_location_tlv_roundtrip_empty() {
        let original = LocationTlv {
            dest_port: 862,
            src_port: 12345,
            sub_tlvs: Vec::new(),
        };
        let raw = original.to_raw();
        let parsed = LocationTlv::from_raw(&raw).unwrap();
        assert_eq!(parsed, original);
    }

    #[test]
    fn test_location_tlv_roundtrip_with_sub_tlvs() {
        let original = LocationTlv {
            dest_port: 862,
            src_port: 54321,
            sub_tlvs: vec![
                LocationSubTlv::new(LocationSubType::Ipv4Src, vec![10, 0, 0, 1]),
                LocationSubTlv::new(LocationSubType::Ipv4Dst, vec![10, 0, 0, 2]),
            ],
        };
        let raw = original.to_raw();
        let parsed = LocationTlv::from_raw(&raw).unwrap();
        assert_eq!(parsed, original);
    }

    #[test]
    fn test_location_tlv_wire_format() {
        let tlv = LocationTlv {
            dest_port: 0x0362,
            src_port: 0x3039,
            sub_tlvs: Vec::new(),
        };
        let raw = tlv.to_raw();
        assert_eq!(raw.tlv_type, TlvType::Location);
        assert_eq!(raw.value.len(), LOCATION_TLV_MIN_VALUE_SIZE);
        assert_eq!(raw.value[0], 0x03);
        assert_eq!(raw.value[1], 0x62);
        assert_eq!(raw.value[2], 0x30);
        assert_eq!(raw.value[3], 0x39);
    }

    #[test]
    fn test_location_tlv_from_raw_too_short() {
        let raw = RawTlv::new(TlvType::Location, vec![0x00, 0x01]);
        let result = LocationTlv::from_raw(&raw);
        assert!(matches!(result, Err(TlvError::InvalidLocationLength(2))));
    }

    #[test]
    fn test_location_tlv_from_raw_empty() {
        let raw = RawTlv::new(TlvType::Location, vec![]);
        let result = LocationTlv::from_raw(&raw);
        assert!(matches!(result, Err(TlvError::InvalidLocationLength(0))));
    }

    #[test]
    fn test_location_tlv_from_raw_ports_only() {
        let raw = RawTlv::new(TlvType::Location, vec![0x00, 0x50, 0x00, 0x51]);
        let tlv = LocationTlv::from_raw(&raw).unwrap();
        assert_eq!(tlv.dest_port, 80);
        assert_eq!(tlv.src_port, 81);
        assert!(tlv.sub_tlvs.is_empty());
    }
}
