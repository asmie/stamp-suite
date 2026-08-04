//! Reflected IPv6 Extension Header Data TLV (Type 246) per
//! draft-ietf-ippm-stamp-ext-hdr-11 §§3.1, 5.1.
//!
//! # Wire Format (-11 Figure 6)
//!
//! ```text
//!  0                   1                   2                   3
//!  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |STAMP TLV Flags|  Type = 246   |         Length                |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |               Requested IPv6 Extension Header Data            |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |               Reflected IPv6 Extension Header Data            |
//! ~                     (Length - 4 octets)                       ~
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! ```
//!
//! -11 splits the value into two fields: a fixed 4-octet **Requested** field
//! and a **Reflected** field of `Length - 4` octets, where `Length` equals the
//! full target extension header's size (from its Next Header field onward).
//!
//! The sender sends the Requested field as either all zeros or a disambiguation
//! selector (the target header's first 4 on-wire octets), with the Reflected
//! field zero-initialised. The reflector leaves the Requested field exactly as
//! received and copies the matched header's bytes **from offset 4 onward** into
//! the Reflected field (`header[4..]`); the header's own first 4 octets are
//! never written into the reply value. When the reflector cannot use the TLV
//! (length mismatch, no data-plane access, or no header matches the Requested
//! field) it sets the **C flag** (Conformance) and leaves the value as
//! received — the pre-11 U-flag failure signalling is gone.
//!
//! # Selector / Requested field (-11 §5.1)
//!
//! A non-zero Requested field (see
//! [`ReflectedIpv6ExtHdrTlv::request_with_selector`]) disambiguates multiple
//! extension headers of the same length: the reflector matches it against the
//! header's **on-wire first 4 octets** — byte 0 is the header's own Next Header
//! field (naming what *follows* it), byte 1 is HdrExtLen, then the first 2
//! option octets. An all-zeros Requested field matches the first
//! length-matching header.
//!
//! With several Type 246 TLVs present, selection is
//! **first-fit-with-consumption**: each matched captured header is consumed so
//! no later TLV re-uses it. That reconciles §5.1's first-fit-by-length MUST
//! with §3.1 rule 2's positional pairing (successive same-length TLVs end up
//! pairing 1st↔1st, 2nd↔2nd) — see
//! [`TlvList::process_reflected_headers`](crate::tlv::TlvList::process_reflected_headers)
//! for the reconciliation this implements.

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
    /// Per draft-ietf-ippm-stamp-ext-hdr-11 §5.1 the sender sets the Length to
    /// the target IPv6 extension-header size (from its Next Header field
    /// onward). The first 4 octets are the all-zeros Requested field and the
    /// remaining `bytes - 4` octets are the zero-initialised Reflected field.
    #[must_use]
    pub fn request_with_capacity(bytes: usize) -> Self {
        Self {
            data: vec![0u8; bytes],
        }
    }

    /// Creates a sender request TLV whose first 4 octets carry the Requested
    /// selector (draft-ietf-ippm-stamp-ext-hdr-11 §5.1), followed by the
    /// zero-initialised Reflected field the reflector fills. `capacity` is
    /// grown to fit `prefix` so the selector is never truncated.
    ///
    /// The selector is the target header's **on-wire first 4 octets**: byte 0
    /// is the header's own Next Header field (naming what follows it), byte 1
    /// is HdrExtLen, then the first 2 option octets — NOT the header's own type
    /// (which lives in the *preceding* Next Header pointer).
    #[must_use]
    pub fn request_with_selector(prefix: &[u8], capacity: usize) -> Self {
        let mut data = vec![0u8; capacity.max(prefix.len())];
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
        // draft §3.1 selector: first 4 bytes carry the match pattern, the
        // rest of the requested capacity is zero for the reflector to fill.
        let tlv = ReflectedIpv6ExtHdrTlv::request_with_selector(&[0x3C, 0x00, 0x01, 0x02], 8);
        assert_eq!(tlv.data, vec![0x3C, 0x00, 0x01, 0x02, 0, 0, 0, 0]);
        assert_eq!(tlv.to_raw().value.len(), 8);
    }

    #[test]
    fn test_request_with_selector_grows_capacity_to_fit_prefix() {
        // A capacity smaller than the prefix must not truncate the selector.
        let tlv = ReflectedIpv6ExtHdrTlv::request_with_selector(&[1, 2, 3, 4, 5, 6], 4);
        assert_eq!(tlv.data, vec![1, 2, 3, 4, 5, 6]);
    }
}
