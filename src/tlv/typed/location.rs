//! Location TLV (Type 2) per RFC 8972 §4.2 and its sub-TLVs (§4.2.1).

use crate::tlv::core::{TlvError, TlvFlags, TlvType, LOCATION_TLV_MIN_VALUE_SIZE, TLV_HEADER_SIZE};
use crate::tlv::traits::TypedTlv;

/// Location value length of the address-family sub-TLVs (Types 4-9): the
/// RFC-mandated Length field value for every Destination/Source IP variant.
const LOCATION_IP_SUBTLV_LEN: usize = 16;

/// Location value length of the MAC-family sub-TLVs (Types 1-3): the
/// RFC-mandated Length field value for Source MAC / EUI-48 / EUI-64.
const LOCATION_MAC_SUBTLV_LEN: usize = 8;

/// Which Location TLV fields the Session-Reflector is permitted to report.
///
/// RFC 8972 §4.2.2 pairs a permission with an obligation: "Based on the local
/// policy, the Session-Reflector MAY leave some fields unreported by filling
/// them with zeroes. An implementation of the stateful Session-Reflector MUST
/// provide control for managing such policies." This type is that control; a
/// suppressed field is answered as zeroes, exactly as the MAY describes, rather
/// than being dropped or flagged (dropping it would change the reply's size and
/// flagging it would misreport a well-formed request as unrecognized).
///
/// The default discloses everything, which is what a measurement tool is for —
/// the policy exists so an operator on an untrusted path can narrow it.
///
/// The Source MAC answer is not represented here: both backends already answer
/// it with a zeroed EUI-64 (they have no L2 visibility), so there is nothing to
/// suppress.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LocationDisclosure {
    /// Report the observed source port (value octets 2-3).
    pub src_port: bool,
    /// Report the observed destination port (value octets 0-1).
    pub dst_port: bool,
    /// Answer a Source IP Address generic request (sub-TLV Type 7).
    pub src_ip: bool,
    /// Answer a Destination IP Address generic request (sub-TLV Type 4).
    pub dst_ip: bool,
}

impl Default for LocationDisclosure {
    fn default() -> Self {
        Self::all()
    }
}

impl LocationDisclosure {
    /// Every field reported — the default.
    #[must_use]
    pub const fn all() -> Self {
        Self {
            src_port: true,
            dst_port: true,
            src_ip: true,
            dst_ip: true,
        }
    }

    /// No field reported; every answer is zeroes.
    #[must_use]
    pub const fn none() -> Self {
        Self {
            src_port: false,
            dst_port: false,
            src_ip: false,
            dst_ip: false,
        }
    }

    /// True when no field may be reported.
    #[must_use]
    pub const fn discloses_nothing(&self) -> bool {
        !self.src_port && !self.dst_port && !self.src_ip && !self.dst_ip
    }

    /// Parses a comma-separated field list: `all`, `none`, or any combination
    /// of `src-port`, `dst-port`, `ports`, `src-ip`, `dst-ip`, `ips`.
    ///
    /// # Errors
    /// Returns the offending token when it is not a recognized field name, and
    /// rejects mixing `all`/`none` with individual field names — a list like
    /// `none,src-ip` has no unambiguous reading.
    pub fn parse(spec: &str) -> Result<Self, String> {
        let mut policy = Self::none();
        let mut saw_wildcard = false;
        let mut saw_field = false;

        for token in spec.split(',') {
            let token = token.trim();
            if token.is_empty() {
                continue;
            }
            match token.to_ascii_lowercase().as_str() {
                "all" => {
                    policy = Self::all();
                    saw_wildcard = true;
                }
                "none" => {
                    policy = Self::none();
                    saw_wildcard = true;
                }
                "src-port" => {
                    policy.src_port = true;
                    saw_field = true;
                }
                "dst-port" => {
                    policy.dst_port = true;
                    saw_field = true;
                }
                "ports" => {
                    policy.src_port = true;
                    policy.dst_port = true;
                    saw_field = true;
                }
                "src-ip" => {
                    policy.src_ip = true;
                    saw_field = true;
                }
                "dst-ip" => {
                    policy.dst_ip = true;
                    saw_field = true;
                }
                "ips" => {
                    policy.src_ip = true;
                    policy.dst_ip = true;
                    saw_field = true;
                }
                other => {
                    return Err(format!(
                        "unknown Location field '{other}' (expected all, none, \
                         src-port, dst-port, ports, src-ip, dst-ip, or ips)"
                    ))
                }
            }
        }

        if saw_wildcard && saw_field {
            return Err("'all'/'none' cannot be combined with individual field names".to_string());
        }
        if !saw_wildcard && !saw_field {
            return Err("empty Location disclosure list".to_string());
        }
        Ok(policy)
    }
}

/// Location sub-TLV types per RFC 8972 §4.2.1 (Table 5).
///
/// Types 1, 4, and 7 are the *generic request* types a Session-Sender emits;
/// the Session-Reflector answers each with the corresponding *specific* type
/// (EUI-48/EUI-64 for MAC, IPv4/IPv6 for the addresses) per §4.2.2.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocationSubType {
    /// Source MAC Address (Type 1) — generic request. Value is an 8-octet MBZ.
    SourceMac,
    /// Source EUI-48 Address (Type 2). Value is 6-octet EUI-48 + 2-octet MBZ.
    SourceEui48,
    /// Source EUI-64 Address (Type 3). Value is an 8-octet EUI-64.
    SourceEui64,
    /// Destination IP Address (Type 4) — generic request. Value is 16-octet MBZ.
    DestinationIp,
    /// Destination IPv4 Address (Type 5). Value is 4-octet IPv4 + 12-octet MBZ.
    DestinationIpv4,
    /// Destination IPv6 Address (Type 6). Value is a 16-octet IPv6 address.
    DestinationIpv6,
    /// Source IP Address (Type 7) — generic request. Value is 16-octet MBZ.
    SourceIp,
    /// Source IPv4 Address (Type 8). Value is 4-octet IPv4 + 12-octet MBZ.
    SourceIpv4,
    /// Source IPv6 Address (Type 9). Value is a 16-octet IPv6 address.
    SourceIpv6,
    /// Unknown / unassigned sub-type.
    Unknown(u8),
}

impl LocationSubType {
    /// Creates a `LocationSubType` from its Type byte.
    #[must_use]
    pub fn from_byte(byte: u8) -> Self {
        match byte {
            1 => Self::SourceMac,
            2 => Self::SourceEui48,
            3 => Self::SourceEui64,
            4 => Self::DestinationIp,
            5 => Self::DestinationIpv4,
            6 => Self::DestinationIpv6,
            7 => Self::SourceIp,
            8 => Self::SourceIpv4,
            9 => Self::SourceIpv6,
            n => Self::Unknown(n),
        }
    }

    /// Converts to its Type byte.
    #[must_use]
    pub fn to_byte(self) -> u8 {
        match self {
            Self::SourceMac => 1,
            Self::SourceEui48 => 2,
            Self::SourceEui64 => 3,
            Self::DestinationIp => 4,
            Self::DestinationIpv4 => 5,
            Self::DestinationIpv6 => 6,
            Self::SourceIp => 7,
            Self::SourceIpv4 => 8,
            Self::SourceIpv6 => 9,
            Self::Unknown(n) => n,
        }
    }

    /// The RFC 8972 §4.2.1-mandated Length field value (Value size in octets)
    /// for this sub-TLV type, or `None` for unknown types.
    ///
    /// Types 1-3 (MAC family) carry 8 octets; Types 4-9 (address family) carry
    /// 16 octets. The reflector uses this to detect a sub-TLV whose Length is
    /// not valid for its type (RFC 8972 §4 M-flag rule).
    #[must_use]
    pub fn mandated_value_len(self) -> Option<usize> {
        match self {
            Self::SourceMac | Self::SourceEui48 | Self::SourceEui64 => {
                Some(LOCATION_MAC_SUBTLV_LEN)
            }
            Self::DestinationIp
            | Self::DestinationIpv4
            | Self::DestinationIpv6
            | Self::SourceIp
            | Self::SourceIpv4
            | Self::SourceIpv6 => Some(LOCATION_IP_SUBTLV_LEN),
            Self::Unknown(_) => None,
        }
    }
}

/// A single sub-TLV within the Location TLV, per RFC 8972 §4.2.1.
///
/// # Wire Format (Figure 5 — the standard 4-octet STAMP TLV header)
///
/// ```text
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// | Sub-TLV Flags |     Type      |            Length             |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ~                            Value                              ~
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocationSubTlv {
    /// Sub-TLV flags (U/M/I as per RFC 8972 §4; I MUST be 0 on transmit).
    pub flags: TlvFlags,
    /// Sub-TLV type.
    pub sub_type: LocationSubType,
    /// Sub-TLV value.
    pub value: Vec<u8>,
}

impl LocationSubTlv {
    /// Creates a new location sub-TLV with cleared flags.
    #[must_use]
    pub fn new(sub_type: LocationSubType, value: Vec<u8>) -> Self {
        Self {
            flags: TlvFlags::default(),
            sub_type,
            value,
        }
    }

    /// Creates a new location sub-TLV with explicit flags.
    #[must_use]
    pub fn with_flags(flags: TlvFlags, sub_type: LocationSubType, value: Vec<u8>) -> Self {
        Self {
            flags,
            sub_type,
            value,
        }
    }

    /// Builds a Session-Sender *generic request* sub-TLV: the correct
    /// RFC-mandated Length, a fully zeroed (MBZ) value, and U=1 flags per
    /// RFC 8972 §4 / §4.2.1. Only the three generic request types
    /// (Source MAC, Destination IP, Source IP) have a well-defined request
    /// form; for any other type the value is zeroed to a length of 0.
    #[must_use]
    pub fn generic_request(sub_type: LocationSubType) -> Self {
        let len = sub_type.mandated_value_len().unwrap_or(0);
        Self {
            flags: TlvFlags::for_sender(),
            sub_type,
            value: vec![0u8; len],
        }
    }

    /// Appends the serialized sub-TLV (4-octet STAMP TLV header + value) to an
    /// existing buffer.
    pub fn write_to(&self, buf: &mut Vec<u8>) {
        buf.push(self.flags.to_byte());
        buf.push(self.sub_type.to_byte());
        buf.extend_from_slice(&(self.value.len() as u16).to_be_bytes());
        buf.extend_from_slice(&self.value);
    }

    /// Serializes the sub-TLV to bytes.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(TLV_HEADER_SIZE + self.value.len());
        self.write_to(&mut buf);
        buf
    }

    /// Parses a sub-TLV from a byte slice.
    ///
    /// Returns the parsed sub-TLV and bytes consumed, or `None` if the buffer
    /// is too small to hold the 4-octet header plus the declared value length.
    #[must_use]
    pub fn parse(buf: &[u8]) -> Option<(Self, usize)> {
        if buf.len() < TLV_HEADER_SIZE {
            return None;
        }
        let flags = TlvFlags::from_byte(buf[0]);
        let sub_type = LocationSubType::from_byte(buf[1]);
        let length = u16::from_be_bytes([buf[2], buf[3]]) as usize;
        let end = TLV_HEADER_SIZE.checked_add(length)?;
        if buf.len() < end {
            return None;
        }
        let value = buf[TLV_HEADER_SIZE..end].to_vec();
        Some((
            Self {
                flags,
                sub_type,
                value,
            },
            end,
        ))
    }
}

/// Location TLV (Type 2) per RFC 8972 §4.2.
///
/// The Value field is a fixed 4-octet port prefix (Destination Port, then
/// Source Port) followed by a sequence of sub-TLVs. A Session-Sender emits
/// generic request sub-TLVs with zeroed values; the Session-Reflector fills in
/// the observed ports and answers each generic request with the corresponding
/// specific sub-TLV (RFC 8972 §4.2.2).
///
/// # Wire Format (Figure 8)
///
/// ```text
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |        Destination Port       |          Source Port          |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ~                            Sub-TLVs                            ~
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocationTlv {
    /// Destination Port — the received STAMP packet's UDP destination port.
    pub dest_port: u16,
    /// Source Port — the received STAMP packet's UDP source port.
    pub src_port: u16,
    /// Sub-TLVs (generic requests on the wire from a sender; specific answers
    /// from a reflector).
    pub sub_tlvs: Vec<LocationSubTlv>,
}

impl LocationTlv {
    /// Creates an empty Location TLV (ports only, no sub-TLV requests).
    #[must_use]
    pub fn new() -> Self {
        Self {
            dest_port: 0,
            src_port: 0,
            sub_tlvs: Vec::new(),
        }
    }

    /// Builds a Session-Sender Location *request* per RFC 8972 §4.2: zeroed
    /// ports plus generic Source IP (Type 7) and Destination IP (Type 4)
    /// request sub-TLVs. The reflector answers these with the specific
    /// IPv4/IPv6 variants and fills in the observed ports, which lets the
    /// sender detect a NAT on the path (§4.2.2).
    #[must_use]
    pub fn request() -> Self {
        Self {
            dest_port: 0,
            src_port: 0,
            sub_tlvs: vec![
                LocationSubTlv::generic_request(LocationSubType::SourceIp),
                LocationSubTlv::generic_request(LocationSubType::DestinationIp),
            ],
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
        let mut offset = LOCATION_TLV_MIN_VALUE_SIZE;
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
/// Used by the reflector to fill in the Location TLV with the observed
/// addresses/ports of the received packet.
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
    use super::LocationDisclosure;

    #[test]
    fn test_location_disclosure_default_is_permissive() {
        // A measurement tool answers by default; the policy exists to narrow.
        assert_eq!(LocationDisclosure::default(), LocationDisclosure::all());
        assert!(!LocationDisclosure::all().discloses_nothing());
        assert!(LocationDisclosure::none().discloses_nothing());
    }

    #[test]
    fn test_location_disclosure_parse_wildcards() {
        assert_eq!(
            LocationDisclosure::parse("all").unwrap(),
            LocationDisclosure::all()
        );
        assert_eq!(
            LocationDisclosure::parse("none").unwrap(),
            LocationDisclosure::none()
        );
        // Case and surrounding space are tolerated.
        assert_eq!(
            LocationDisclosure::parse("  ALL ").unwrap(),
            LocationDisclosure::all()
        );
    }

    #[test]
    fn test_location_disclosure_parse_individual_and_groups() {
        let p = LocationDisclosure::parse("ports").unwrap();
        assert!(p.src_port && p.dst_port && !p.src_ip && !p.dst_ip);

        let p = LocationDisclosure::parse("src-ip,dst-port").unwrap();
        assert!(p.src_ip && p.dst_port && !p.dst_ip && !p.src_port);

        let p = LocationDisclosure::parse("ips").unwrap();
        assert!(p.src_ip && p.dst_ip && !p.src_port && !p.dst_port);
    }

    #[test]
    fn test_location_disclosure_parse_rejects_bad_input() {
        // Unknown field name.
        assert!(LocationDisclosure::parse("src-mac").is_err());
        // Mixing a wildcard with named fields has no unambiguous reading.
        assert!(LocationDisclosure::parse("none,src-ip").is_err());
        assert!(LocationDisclosure::parse("all,ports").is_err());
        // An empty list is a typo, not "disclose nothing" — `none` says that.
        assert!(LocationDisclosure::parse("").is_err());
        assert!(LocationDisclosure::parse(" , ").is_err());
    }

    use super::*;
    use crate::tlv::core::RawTlv;

    #[test]
    fn test_sub_type_roundtrip() {
        let types = [
            LocationSubType::SourceMac,
            LocationSubType::SourceEui48,
            LocationSubType::SourceEui64,
            LocationSubType::DestinationIp,
            LocationSubType::DestinationIpv4,
            LocationSubType::DestinationIpv6,
            LocationSubType::SourceIp,
            LocationSubType::SourceIpv4,
            LocationSubType::SourceIpv6,
            LocationSubType::Unknown(42),
        ];
        for t in &types {
            assert_eq!(*t, LocationSubType::from_byte(t.to_byte()));
        }
    }

    #[test]
    fn test_sub_type_registry_byte_values() {
        // Pin the RFC 8972 §4.2.1 Table 5 assignments.
        assert_eq!(LocationSubType::SourceMac.to_byte(), 1);
        assert_eq!(LocationSubType::SourceEui48.to_byte(), 2);
        assert_eq!(LocationSubType::SourceEui64.to_byte(), 3);
        assert_eq!(LocationSubType::DestinationIp.to_byte(), 4);
        assert_eq!(LocationSubType::DestinationIpv4.to_byte(), 5);
        assert_eq!(LocationSubType::DestinationIpv6.to_byte(), 6);
        assert_eq!(LocationSubType::SourceIp.to_byte(), 7);
        assert_eq!(LocationSubType::SourceIpv4.to_byte(), 8);
        assert_eq!(LocationSubType::SourceIpv6.to_byte(), 9);
    }

    #[test]
    fn test_mandated_value_len() {
        assert_eq!(LocationSubType::SourceMac.mandated_value_len(), Some(8));
        assert_eq!(LocationSubType::SourceEui48.mandated_value_len(), Some(8));
        assert_eq!(LocationSubType::SourceEui64.mandated_value_len(), Some(8));
        assert_eq!(
            LocationSubType::DestinationIp.mandated_value_len(),
            Some(16)
        );
        assert_eq!(LocationSubType::SourceIpv6.mandated_value_len(), Some(16));
        assert_eq!(LocationSubType::Unknown(200).mandated_value_len(), None);
    }

    #[test]
    fn test_sub_tlv_uses_four_octet_header() {
        // RFC 8972 §4.2.1: sub-TLVs use the standard 4-octet STAMP TLV header
        // (Flags, Type, 2-octet Length).
        let sub = LocationSubTlv::new(LocationSubType::SourceIpv4, vec![192, 168, 1, 1]);
        let bytes = sub.to_bytes();
        assert_eq!(bytes.len(), TLV_HEADER_SIZE + 4);
        assert_eq!(bytes[0], 0x00); // flags cleared
        assert_eq!(bytes[1], 8); // Source IPv4 Address type
        assert_eq!(&bytes[2..4], &4u16.to_be_bytes()); // 2-octet Length
        assert_eq!(&bytes[4..], &[192, 168, 1, 1]);

        let (parsed, consumed) = LocationSubTlv::parse(&bytes).unwrap();
        assert_eq!(consumed, TLV_HEADER_SIZE + 4);
        assert_eq!(parsed, sub);
    }

    #[test]
    fn test_sub_tlv_flags_roundtrip() {
        let sub = LocationSubTlv::with_flags(
            TlvFlags::unrecognized(),
            LocationSubType::Unknown(200),
            vec![1, 2],
        );
        let bytes = sub.to_bytes();
        assert_eq!(bytes[0], 0x80); // U flag set
        assert_eq!(bytes[1], 200);
        let (parsed, _) = LocationSubTlv::parse(&bytes).unwrap();
        assert_eq!(parsed, sub);
        assert!(parsed.flags.unrecognized);
    }

    #[test]
    fn test_generic_request_zero_filled_correct_length() {
        let src = LocationSubTlv::generic_request(LocationSubType::SourceIp);
        assert_eq!(src.sub_type, LocationSubType::SourceIp);
        assert_eq!(src.value, vec![0u8; 16]);
        assert!(src.flags.unrecognized, "sender sets U=1 (RFC 8972 §4)");

        let mac = LocationSubTlv::generic_request(LocationSubType::SourceMac);
        assert_eq!(mac.value, vec![0u8; 8]);
    }

    #[test]
    fn test_sub_tlv_ipv6() {
        let addr = std::net::Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        let sub = LocationSubTlv::new(LocationSubType::SourceIpv6, addr.octets().to_vec());
        let bytes = sub.to_bytes();
        let (parsed, consumed) = LocationSubTlv::parse(&bytes).unwrap();
        assert_eq!(consumed, TLV_HEADER_SIZE + 16);
        assert_eq!(parsed.sub_type, LocationSubType::SourceIpv6);
        assert_eq!(parsed.value, addr.octets());
    }

    #[test]
    fn test_sub_tlv_parse_too_short() {
        assert!(LocationSubTlv::parse(&[0x00, 0x07, 0x00]).is_none());
    }

    #[test]
    fn test_sub_tlv_parse_truncated_value() {
        // Header says 16 bytes but only 2 available.
        let buf = [0x00, 0x07, 0x00, 0x10, 0xAA, 0xBB];
        assert!(LocationSubTlv::parse(&buf).is_none());
    }

    #[test]
    fn test_location_tlv_new() {
        let tlv = LocationTlv::new();
        assert_eq!(tlv.dest_port, 0);
        assert_eq!(tlv.src_port, 0);
        assert!(tlv.sub_tlvs.is_empty());
    }

    #[test]
    fn test_location_tlv_request_builds_generic_sub_tlvs() {
        let tlv = LocationTlv::request();
        assert_eq!(tlv.dest_port, 0);
        assert_eq!(tlv.src_port, 0);
        assert_eq!(tlv.sub_tlvs.len(), 2);
        assert_eq!(tlv.sub_tlvs[0].sub_type, LocationSubType::SourceIp);
        assert_eq!(tlv.sub_tlvs[1].sub_type, LocationSubType::DestinationIp);
        // Value on the wire: ports(4) + 2 * (4 header + 16 value) = 44.
        let raw = tlv.to_raw();
        assert_eq!(raw.value.len(), 4 + 2 * (TLV_HEADER_SIZE + 16));
    }

    #[test]
    fn test_location_tlv_default() {
        let tlv = LocationTlv::default();
        assert_eq!(tlv.dest_port, 0);
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
        assert_eq!(LocationTlv::from_raw(&raw).unwrap(), original);
    }

    #[test]
    fn test_location_tlv_roundtrip_with_sub_tlvs() {
        let original = LocationTlv {
            dest_port: 862,
            src_port: 54321,
            sub_tlvs: vec![
                LocationSubTlv::new(
                    LocationSubType::SourceIpv4,
                    vec![10, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                ),
                LocationSubTlv::new(
                    LocationSubType::DestinationIpv4,
                    vec![10, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                ),
            ],
        };
        let raw = original.to_raw();
        assert_eq!(LocationTlv::from_raw(&raw).unwrap(), original);
    }

    #[test]
    fn test_location_tlv_wire_format_ports() {
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
        assert!(matches!(
            LocationTlv::from_raw(&raw),
            Err(TlvError::InvalidLocationLength(2))
        ));
    }

    #[test]
    fn test_location_tlv_from_raw_empty() {
        let raw = RawTlv::new(TlvType::Location, vec![]);
        assert!(matches!(
            LocationTlv::from_raw(&raw),
            Err(TlvError::InvalidLocationLength(0))
        ));
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
