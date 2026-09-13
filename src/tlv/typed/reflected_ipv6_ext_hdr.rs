//! Reflected IPv6 Extension Header Data TLV (Type 246) per
//! draft-ietf-ippm-stamp-ext-hdr-13 §§3.2, 5.1.
//!
//! # Wire Format (-13 Figure 6)
//!
//! ```text
//!  0                   1                   2                   3
//!  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |STAMP TLV Flags|  Type = 246   |         Length                |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |               Requested IPv6 Extension Header Data            |
//! |                       (8 octets)                              |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |               Reflected IPv6 Extension Header Data            |
//! ~                     (Length - 8 octets)                       ~
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! ```
//!
//! Length equals the target extension header size. Requested occupies eight
//! bytes; Reflected receives `header[8..]`. The sender zeroes Reflected and
//! sets Requested to zero or the target header's first eight wire bytes.
//! The reflector preserves Requested. On missing capture or no match, it
//! sets C and preserves the value.
//!
//! Nonzero Requested matches the header's prefix, including its own Next
//! Header byte (the following protocol, not this header's type). Zero selects
//! the first length match. Each captured header is consumed once, so repeated
//! requests select successive matches. See
//! [`TlvList::process_reflected_headers`](crate::tlv::TlvList::process_reflected_headers).

use crate::tlv::core::{TlvError, TlvType};
use crate::tlv::traits::TypedTlv;

/// Default request length for one eight-byte IPv6 extension header.
pub const DEFAULT_IPV6_EXT_HDR_REQUEST_CAPACITY: usize = 8;

/// Reflected IPv6 Extension Header Data TLV (Type 246).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ReflectedIpv6ExtHdrTlv {
    /// Eight-byte Requested selector followed by the reflected header tail.
    pub data: Vec<u8>,
}

impl ReflectedIpv6ExtHdrTlv {
    /// Creates a sender request TLV with `bytes` zero octets of Value.
    ///
    /// Per draft-ietf-ippm-stamp-ext-hdr-13 §5.1 the sender sets the Length to
    /// the target IPv6 extension-header size (from its Next Header field
    /// onward). The first 8 octets are the all-zeros Requested field and the
    /// remaining `bytes - 8` octets are the zero-initialised Reflected field.
    #[must_use]
    pub fn request_with_capacity(bytes: usize) -> Self {
        Self {
            data: vec![0u8; bytes],
        }
    }

    /// Creates a request with up to eight selector bytes and a zeroed tail
    /// (draft-ietf-ippm-stamp-ext-hdr-13 §5.1). Allocates at least eight bytes.
    /// The selector matches the target header's wire prefix, including its
    /// Next Header byte. Longer prefixes are truncated; the CLI rejects them.
    #[must_use]
    pub fn request_with_selector(prefix: &[u8], capacity: usize) -> Self {
        let prefix = &prefix[..prefix.len().min(8)];
        let mut data = vec![0u8; capacity.max(8)];
        data[..prefix.len()].copy_from_slice(prefix);
        Self { data }
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

    #[test]
    fn test_request_with_selector_prefixes_then_zero_pads() {
        // draft §3.2 selector: first 8 bytes carry the match pattern, the
        // rest of the requested capacity is zero for the reflector to fill.
        let tlv = ReflectedIpv6ExtHdrTlv::request_with_selector(&[0x3C, 0x00, 0x01, 0x02], 8);
        assert_eq!(tlv.data, vec![0x3C, 0x00, 0x01, 0x02, 0, 0, 0, 0]);
        assert_eq!(tlv.to_raw().value.len(), 8);
    }

    #[test]
    fn test_request_with_selector_grows_capacity_to_fit_prefix() {
        // A capacity smaller than the prefix must not truncate the selector.
        let tlv = ReflectedIpv6ExtHdrTlv::request_with_selector(&[1, 2, 3, 4, 5, 6], 4);
        assert_eq!(tlv.data, vec![1, 2, 3, 4, 5, 6, 0, 0]);
    }
}
