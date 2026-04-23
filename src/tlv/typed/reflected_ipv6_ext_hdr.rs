//! Reflected IPv6 Extension Header Data TLV (Type 246) per
//! draft-ietf-ippm-stamp-ext-hdr §3.
//!
//! Sender transmits this TLV with an empty Value field to request that the
//! reflector copy the bytes of received IPv6 Hop-by-Hop Options (NextHeader 0)
//! and/or Destination Options (NextHeader 60) extension headers into the
//! response. When the reflector backend cannot capture raw IP headers (nix
//! UDP-socket backend), the reflector sets the U-flag and echoes the TLV with
//! an empty Value.
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

/// Reflected IPv6 Extension Header Data TLV (Type 246).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ReflectedIpv6ExtHdrTlv {
    /// Concatenated extension-header bytes as received on the wire.
    /// Empty when sent by the sender as a request.
    pub data: Vec<u8>,
}

impl ReflectedIpv6ExtHdrTlv {
    /// Creates an empty request TLV for the sender to attach.
    #[must_use]
    pub fn request() -> Self {
        Self::default()
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
    fn test_request_is_empty() {
        let tlv = ReflectedIpv6ExtHdrTlv::request();
        assert!(tlv.data.is_empty());
        let raw = tlv.to_raw();
        assert_eq!(raw.tlv_type, TlvType::ReflectedIpv6ExtHdr);
        assert_eq!(raw.value.len(), 0);
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
