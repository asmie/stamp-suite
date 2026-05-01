//! Reflected IPv6 Extension Header Data TLV (Type 246) per
//! draft-ietf-ippm-stamp-ext-hdr §3.
//!
//! The sender pre-allocates a zero-filled Value of the size it expects the
//! reflector to fill (one octet pair per extension-header option, plus body
//! bytes). The reflector replaces those zeros with the bytes of received
//! IPv6 Hop-by-Hop Options (NextHeader 0) and/or Destination Options
//! (NextHeader 60) extension headers. When the reflector backend cannot
//! capture raw IP headers (nix UDP-socket backend) it sets the U-flag and
//! clears the Value.
//!
//! Capacity choice is the sender's: too small drops trailing options, too
//! large just pads with zeros. IPv4 paths have no IPv6 extension headers,
//! so the reflector returns the Value unchanged in that case.
//!
//! # Wire Format
//!
//! ```text
//!  0                   1                   2                   3
//!  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! | NextHeader=0  | HdrLen        |  ... Hop-by-Hop body ...      |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! | NextHeader=60 | HdrLen        |  ... Destination body ...     |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! ```
//!
//! Reflector concatenates every captured extension header starting with its
//! NextHeader byte (protocol number from the preceding header) and its HdrLen
//! byte followed by the remaining octets of that option header.

use crate::tlv::core::{TlvError, TlvType};
use crate::tlv::traits::TypedTlv;

/// Default zero-fill capacity when the sender requests Type 246 without
/// knowing the path's extension-header chain. Holds one standard 8-byte
/// option (NextHeader + HdrLen + 6 body bytes); the reflector overwrites
/// fewer / more bytes as the actual chain dictates.
pub const DEFAULT_IPV6_EXT_HDR_REQUEST_CAPACITY: usize = 8;

/// Reflected IPv6 Extension Header Data TLV (Type 246).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ReflectedIpv6ExtHdrTlv {
    /// Concatenated extension-header bytes as received on the wire.
    /// Zero-filled when sent by the sender as a request.
    pub data: Vec<u8>,
}

impl ReflectedIpv6ExtHdrTlv {
    /// Creates a sender request TLV with `bytes` zero octets of Value.
    ///
    /// Per draft-ietf-ippm-stamp-ext-hdr §3 the sender sets the Length to
    /// the IPv6 extension-header length the reflector will populate; the
    /// caller picks `bytes` from the largest extension-header chain it
    /// expects on the path.
    #[must_use]
    pub fn request_with_capacity(bytes: usize) -> Self {
        Self {
            data: vec![0u8; bytes],
        }
    }

    /// Creates a response TLV populated with captured extension-header bytes.
    #[must_use]
    pub fn with_data(data: Vec<u8>) -> Self {
        Self { data }
    }
}

impl TypedTlv for ReflectedIpv6ExtHdrTlv {
    const TYPE: TlvType = TlvType::ReflectedIpv6ExtHdr;

    fn decode_value(value: &[u8]) -> Result<Self, TlvError> {
        Ok(Self {
            data: value.to_vec(),
        })
    }

    fn encode_value(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.data);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_request_with_capacity_is_zero_filled() {
        let tlv = ReflectedIpv6ExtHdrTlv::request_with_capacity(8);
        assert_eq!(tlv.data, vec![0u8; 8]);
        let raw = tlv.to_raw();
        assert_eq!(raw.tlv_type, TlvType::ReflectedIpv6ExtHdr);
        assert_eq!(raw.value.len(), 8);
    }

    #[test]
    fn test_request_with_capacity_zero_for_ipv4_path() {
        let tlv = ReflectedIpv6ExtHdrTlv::request_with_capacity(0);
        assert!(tlv.data.is_empty());
        assert_eq!(tlv.to_raw().value.len(), 0);
    }

    #[test]
    fn test_roundtrip_with_data() {
        let original = ReflectedIpv6ExtHdrTlv::with_data(vec![0x00, 0x01, 0x06, 0x04, 0xAA, 0xBB]);
        let raw = original.to_raw();
        let parsed = ReflectedIpv6ExtHdrTlv::from_raw(&raw).unwrap();
        assert_eq!(parsed, original);
    }

    #[test]
    fn test_from_raw_wrong_type() {
        let raw = crate::tlv::core::RawTlv::new(TlvType::Location, vec![]);
        let result = ReflectedIpv6ExtHdrTlv::from_raw(&raw);
        assert!(matches!(result, Err(TlvError::TypeMismatch { .. })));
    }
}
