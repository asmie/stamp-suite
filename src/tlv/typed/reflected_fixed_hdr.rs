//! Reflected Fixed Header Data TLV (Type 247) per
//! draft-ietf-ippm-stamp-ext-hdr-11 §§3.2, 5.2.
//!
//! # Wire Format (-11 Figure 7)
//!
//! ```text
//!  0                   1                   2                   3
//!  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |STAMP TLV Flags|  Type = 247   |         Length                |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                  Requested Fixed Header Data                  |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                  Reflected Fixed Header Data                  |
//! ~                     (Length - 4 octets)                       ~
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! ```
//!
//! -11 splits the value into a fixed 4-octet **Requested** field and a
//! **Reflected** field. Critically, `Length` stays 20 (IPv4) / 40 (IPv6) — it
//! did NOT grow by 4 — so the Reflected field is only 16 / 36 octets and holds
//! the IP header's bytes **from offset 4 onward**, never a full copy.
//!
//! The Session-Sender transmits the TLV with the Requested field set to either
//! all zeros or a disambiguation selector (the target IP header's first 4
//! octets) and the Reflected field zero-initialised. The reflector leaves the
//! Requested field exactly as received and copies `header[4..]` into the
//! Reflected field. When it cannot use the TLV (length mismatch, no data-plane
//! access, or no header matches the Requested field) it sets the **C flag**
//! (Conformance) and leaves the value as received — the pre-11 U-flag failure
//! signalling is gone.
//!
//! Receivers identify IPv4 vs IPv6 by the Version nibble in the first byte
//! (present only when the sender's Requested selector carried it).
//!
//! Per -11 §5.2 a non-zero Requested field (see
//! [`ReflectedFixedHdrTlv::request_with_selector`]) disambiguates multiple IP
//! headers of the same length by matching the header's first 4 octets; an
//! all-zeros Requested field matches the first length-matching IP header.

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
    /// Per draft-ietf-ippm-stamp-ext-hdr-11 §5.2 the sender sets Length to 20
    /// (IPv4) or 40 (IPv6): the first 4 octets are the all-zeros Requested
    /// field and the remaining 16 / 36 are the zero-initialised Reflected
    /// field. Only the address family is consulted; the address bytes are
    /// unused.
    #[must_use]
    pub fn request_for(dest: IpAddr) -> Self {
        let bytes = match dest {
            IpAddr::V4(_) => IPV4_FIXED_HEADER_SIZE,
            IpAddr::V6(_) => IPV6_FIXED_HEADER_SIZE,
        };
        Self::request_with_capacity(bytes)
    }

    /// Creates a sender request TLV whose first 4 octets carry the Requested
    /// selector (draft-ietf-ippm-stamp-ext-hdr-11 §5.2) — the target IP
    /// header's first 4 octets — padded with the zero-initialised Reflected
    /// field to `total_len` (the IP fixed-header length: 20 or 40).
    /// `total_len` is grown to fit `prefix`.
    #[must_use]
    pub fn request_with_selector(prefix: &[u8], total_len: usize) -> Self {
        let mut header = vec![0u8; total_len.max(prefix.len())];
        header[..prefix.len()].copy_from_slice(prefix);
        Self { header }
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

    #[test]
    fn test_request_with_selector_fills_prefix_and_pads_to_len() {
        // draft §3.2 selector: first 4 bytes carry the match pattern, the rest
        // of the fixed-header length stays zero for the reflector to fill.
        let tlv = ReflectedFixedHdrTlv::request_with_selector(
            &[0x45, 0x00, 0x00, 0x54],
            IPV4_FIXED_HEADER_SIZE,
        );
        assert_eq!(tlv.header.len(), IPV4_FIXED_HEADER_SIZE);
        assert_eq!(&tlv.header[..4], &[0x45, 0x00, 0x00, 0x54]);
        assert!(tlv.header[4..].iter().all(|&b| b == 0));
    }

    #[test]
    fn test_request_with_selector_grows_to_fit_prefix() {
        let tlv = ReflectedFixedHdrTlv::request_with_selector(&[1, 2, 3, 4, 5], 4);
        assert_eq!(tlv.header, vec![1, 2, 3, 4, 5]);
    }
}
