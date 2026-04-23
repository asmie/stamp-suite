//! Reflected Fixed Header Data TLV (Type 247) per
//! draft-ietf-ippm-stamp-ext-hdr §4.
//!
//! Sender transmits this TLV with an empty Value field to request that the
//! reflector copy the bytes of the received IP fixed header (20 bytes for
//! IPv4, 40 bytes for IPv6) into the response. When the reflector backend
//! cannot capture raw IP headers (nix UDP-socket backend), the reflector
//! sets the U-flag and echoes the TLV with an empty Value.
//!
//! The reflected bytes are the fixed header exactly as received, in wire
//! order and network byte order. Receivers identify IPv4 vs IPv6 by the
//! Version nibble in the first byte.

use crate::tlv::core::{TlvError, TlvType};
use crate::tlv::traits::TypedTlv;

/// IPv4 fixed header size in bytes.
pub const IPV4_FIXED_HEADER_SIZE: usize = 20;
/// IPv6 fixed header size in bytes.
pub const IPV6_FIXED_HEADER_SIZE: usize = 40;

/// Reflected Fixed Header Data TLV (Type 247).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ReflectedFixedHdrTlv {
    /// Raw fixed-header bytes (IPv4: 20 octets; IPv6: 40 octets).
    /// Empty when sent by the sender as a request.
    pub header: Vec<u8>,
}

impl ReflectedFixedHdrTlv {
    /// Creates an empty request TLV for the sender to attach.
    #[must_use]
    pub fn request() -> Self {
        Self::default()
    }

    /// Creates a response TLV carrying a raw fixed IP header.
    #[must_use]
    pub fn with_header(header: Vec<u8>) -> Self {
        Self { header }
    }

    /// Returns true when this TLV carries an IPv4 fixed header.
    #[must_use]
    pub fn is_ipv4(&self) -> bool {
        self.header.len() == IPV4_FIXED_HEADER_SIZE
            && self.header.first().map(|b| b >> 4) == Some(4)
    }

    /// Returns true when this TLV carries an IPv6 fixed header.
    #[must_use]
    pub fn is_ipv6(&self) -> bool {
        self.header.len() == IPV6_FIXED_HEADER_SIZE
            && self.header.first().map(|b| b >> 4) == Some(6)
    }
}

impl TypedTlv for ReflectedFixedHdrTlv {
    const TYPE: TlvType = TlvType::ReflectedFixedHdr;

    fn decode_value(value: &[u8]) -> Result<Self, TlvError> {
        Ok(Self {
            header: value.to_vec(),
        })
    }

    fn encode_value(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.header);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tlv::core::RawTlv;

    #[test]
    fn test_from_raw_wrong_type_rejected() {
        let raw = RawTlv::new(TlvType::Location, vec![]);
        let result = ReflectedFixedHdrTlv::from_raw(&raw);
        assert!(matches!(result, Err(TlvError::TypeMismatch { .. })));
    }

    #[test]
    fn test_request_is_empty() {
        let tlv = ReflectedFixedHdrTlv::request();
        assert!(tlv.header.is_empty());
        let raw = tlv.to_raw();
        assert_eq!(raw.tlv_type, TlvType::ReflectedFixedHdr);
        assert_eq!(raw.value.len(), 0);
    }

    #[test]
    fn test_roundtrip_ipv4_header() {
        let mut hdr = vec![0u8; IPV4_FIXED_HEADER_SIZE];
        hdr[0] = 0x45;
        let original = ReflectedFixedHdrTlv::with_header(hdr);
        let raw = original.to_raw();
        let parsed = ReflectedFixedHdrTlv::from_raw(&raw).unwrap();
        assert_eq!(parsed, original);
        assert!(parsed.is_ipv4());
        assert!(!parsed.is_ipv6());
    }

    #[test]
    fn test_roundtrip_ipv6_header() {
        let mut hdr = vec![0u8; IPV6_FIXED_HEADER_SIZE];
        hdr[0] = 0x60;
        let original = ReflectedFixedHdrTlv::with_header(hdr);
        let raw = original.to_raw();
        let parsed = ReflectedFixedHdrTlv::from_raw(&raw).unwrap();
        assert_eq!(parsed, original);
        assert!(parsed.is_ipv6());
        assert!(!parsed.is_ipv4());
    }

    #[test]
    fn test_empty_request_is_neither_v4_nor_v6() {
        let tlv = ReflectedFixedHdrTlv::request();
        assert!(!tlv.is_ipv4());
        assert!(!tlv.is_ipv6());
    }
}
