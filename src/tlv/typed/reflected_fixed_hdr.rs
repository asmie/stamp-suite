//! Reflected Fixed Header Data TLV (Type 247) per
//! draft-ietf-ippm-stamp-ext-hdr §4.
//!
//! The Session-Sender transmits this TLV with the Length set to the IP
//! header length (20 for IPv4, 40 for IPv6) and the Value initialised to
//! zeros, per the draft. The reflector overwrites those zero bytes with
//! the bytes of the received IP fixed header. When the reflector backend
//! cannot capture raw IP headers (nix UDP-socket backend) it sets the
//! U-flag and clears the Value.
//!
//! Receivers identify IPv4 vs IPv6 by the Version nibble in the first byte.

use std::net::IpAddr;

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
    /// Filled with zeros when sent by the sender as a request.
    pub header: Vec<u8>,
}

impl ReflectedFixedHdrTlv {
    /// Creates a sender request TLV with `bytes` zero-filled Value bytes.
    #[must_use]
    pub fn request_with_capacity(bytes: usize) -> Self {
        Self {
            header: vec![0u8; bytes],
        }
    }

    /// Creates a sender request TLV sized for the destination's IP family.
    ///
    /// Per draft-ietf-ippm-stamp-ext-hdr §4 the sender pre-allocates 20
    /// (IPv4) or 40 (IPv6) zero bytes for the reflector to overwrite.
    /// Only the address family is consulted; the address bytes are unused.
    #[must_use]
    pub fn request_for(dest: IpAddr) -> Self {
        let bytes = match dest {
            IpAddr::V4(_) => IPV4_FIXED_HEADER_SIZE,
            IpAddr::V6(_) => IPV6_FIXED_HEADER_SIZE,
        };
        Self::request_with_capacity(bytes)
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
    fn test_request_with_capacity_is_zero_filled() {
        let tlv = ReflectedFixedHdrTlv::request_with_capacity(IPV4_FIXED_HEADER_SIZE);
        assert_eq!(tlv.header, vec![0u8; IPV4_FIXED_HEADER_SIZE]);
        let raw = tlv.to_raw();
        assert_eq!(raw.tlv_type, TlvType::ReflectedFixedHdr);
        assert_eq!(raw.value.len(), IPV4_FIXED_HEADER_SIZE);
    }

    #[test]
    fn test_request_for_picks_size_by_family() {
        let v4 = ReflectedFixedHdrTlv::request_for("127.0.0.1".parse().unwrap());
        let v6 = ReflectedFixedHdrTlv::request_for("::1".parse().unwrap());
        assert_eq!(v4.header.len(), IPV4_FIXED_HEADER_SIZE);
        assert_eq!(v6.header.len(), IPV6_FIXED_HEADER_SIZE);
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
    fn test_zero_filled_request_is_neither_v4_nor_v6_until_reflector_fills_it() {
        // Zero-filled request has the right length but Version=0, so neither
        // is_ipv4 nor is_ipv6 returns true until the reflector overwrites.
        let tlv = ReflectedFixedHdrTlv::request_for("127.0.0.1".parse().unwrap());
        assert!(!tlv.is_ipv4());
        assert!(!tlv.is_ipv6());
    }
}
