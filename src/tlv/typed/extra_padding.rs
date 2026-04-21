//! Extra Padding TLV (Type 1) with optional Session-Sender Identifier.

use std::cell::Cell;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::tlv::core::{RawTlv, TlvError, TlvType};
use crate::tlv::traits::TypedTlv;

// Per RFC 8972 §4.2, the Extra Padding TLV Value SHOULD carry a pseudorandom
// sequence of numbers. A xorshift64 stream is sufficient here: the bytes are
// not keying material and do not need cryptographic quality — they only need
// to be non-compressible and distinct across packets.
thread_local! {
    static PRNG_STATE: Cell<u64> = Cell::new(seed_prng());
}

fn seed_prng() -> u64 {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0x9E37_79B9_7F4A_7C15);
    let mixed = nanos.wrapping_mul(0x2545_F491_4F6C_DD1D) ^ nanos.rotate_left(32);
    if mixed == 0 {
        0x9E37_79B9_7F4A_7C15
    } else {
        mixed
    }
}

fn fill_pseudorandom(buf: &mut [u8]) {
    PRNG_STATE.with(|cell| {
        let mut state = cell.get();
        let mut i = 0;
        while i < buf.len() {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            let bytes = state.to_le_bytes();
            let n = (buf.len() - i).min(8);
            buf[i..i + n].copy_from_slice(&bytes[..n]);
            i += n;
        }
        cell.set(state);
    });
}

fn pseudorandom_bytes(n: usize) -> Vec<u8> {
    let mut v = vec![0u8; n];
    fill_pseudorandom(&mut v);
    v
}

/// Extra Padding TLV (Type 1) with optional Session-Sender Identifier.
///
/// The first 2 bytes of the value can carry the SSID.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtraPaddingTlv {
    /// Optional Session-Sender Identifier (first 2 bytes).
    pub ssid: Option<u16>,
    /// Additional padding bytes after SSID.
    pub padding: Vec<u8>,
}

impl ExtraPaddingTlv {
    /// Creates an Extra Padding TLV with pseudorandom padding per RFC 8972 §4.2.
    #[must_use]
    pub fn new(padding_size: usize) -> Self {
        Self {
            ssid: None,
            padding: pseudorandom_bytes(padding_size),
        }
    }

    /// Creates an Extra Padding TLV with an SSID and pseudorandom padding.
    #[must_use]
    pub fn with_ssid(ssid: u16, additional_padding: usize) -> Self {
        Self {
            ssid: Some(ssid),
            padding: pseudorandom_bytes(additional_padding),
        }
    }

    /// Creates an Extra Padding TLV with zero-filled padding.
    ///
    /// Intended for deterministic construction (tests, fixtures). For normal
    /// sender use, prefer `new()` which fills with pseudorandom bytes as
    /// recommended by RFC 8972 §4.2.
    #[must_use]
    pub fn new_zeros(padding_size: usize) -> Self {
        Self {
            ssid: None,
            padding: vec![0u8; padding_size],
        }
    }

    /// Creates an Extra Padding TLV with an SSID and zero-filled padding.
    ///
    /// See `new_zeros` for when to use this over `with_ssid`.
    #[must_use]
    pub fn with_ssid_zeros(ssid: u16, additional_padding: usize) -> Self {
        Self {
            ssid: Some(ssid),
            padding: vec![0u8; additional_padding],
        }
    }

    /// Parses an Extra Padding TLV from a RawTlv.
    #[must_use]
    pub fn from_raw(raw: &RawTlv) -> Self {
        // decode_value is infallible for ExtraPadding
        Self::decode_value(&raw.value).unwrap()
    }

    /// Converts to a RawTlv.
    #[must_use]
    pub fn to_raw(&self) -> RawTlv {
        <Self as TypedTlv>::to_raw(self)
    }
}

impl TypedTlv for ExtraPaddingTlv {
    const TYPE: TlvType = TlvType::ExtraPadding;

    fn decode_value(value: &[u8]) -> Result<Self, TlvError> {
        if value.len() >= 2 {
            let ssid = u16::from_be_bytes([value[0], value[1]]);
            if ssid != 0 {
                return Ok(Self {
                    ssid: Some(ssid),
                    padding: value[2..].to_vec(),
                });
            }
        }
        Ok(Self {
            ssid: None,
            padding: value.to_vec(),
        })
    }

    fn encode_value(&self, out: &mut Vec<u8>) {
        if let Some(ssid) = self.ssid {
            out.extend_from_slice(&ssid.to_be_bytes());
        }
        out.extend_from_slice(&self.padding);
    }
}

/// Session-Sender Identifier encoded in Extra Padding TLV.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionSenderId(pub u16);

impl SessionSenderId {
    /// Creates a new Session-Sender ID.
    #[must_use]
    pub fn new(id: u16) -> Self {
        Self(id)
    }

    /// Returns the ID value.
    #[must_use]
    pub fn value(self) -> u16 {
        self.0
    }

    /// Creates an Extra Padding TLV containing this SSID.
    #[must_use]
    pub fn to_extra_padding_tlv(self, additional_padding: usize) -> ExtraPaddingTlv {
        ExtraPaddingTlv::with_ssid(self.0, additional_padding)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extra_padding_tlv_new() {
        let tlv = ExtraPaddingTlv::new(10);
        assert!(tlv.ssid.is_none());
        assert_eq!(tlv.padding.len(), 10);
    }

    #[test]
    fn test_extra_padding_tlv_with_ssid() {
        let tlv = ExtraPaddingTlv::with_ssid(0x1234, 5);
        assert_eq!(tlv.ssid, Some(0x1234));
        assert_eq!(tlv.padding.len(), 5);
    }

    #[test]
    fn test_extra_padding_tlv_from_raw() {
        let raw = RawTlv::new(TlvType::ExtraPadding, vec![0x12, 0x34, 0x00, 0x00]);
        let tlv = ExtraPaddingTlv::from_raw(&raw);
        assert_eq!(tlv.ssid, Some(0x1234));
        assert_eq!(tlv.padding, vec![0x00, 0x00]);
    }

    #[test]
    fn test_extra_padding_tlv_from_raw_zero_ssid() {
        let raw = RawTlv::new(TlvType::ExtraPadding, vec![0x00, 0x00, 0x11, 0x22]);
        let tlv = ExtraPaddingTlv::from_raw(&raw);
        assert!(tlv.ssid.is_none());
        assert_eq!(tlv.padding, vec![0x00, 0x00, 0x11, 0x22]);
    }

    #[test]
    fn test_extra_padding_tlv_to_raw() {
        let tlv = ExtraPaddingTlv::with_ssid_zeros(0xABCD, 2);
        let raw = tlv.to_raw();
        assert_eq!(raw.tlv_type, TlvType::ExtraPadding);
        assert_eq!(raw.value, vec![0xAB, 0xCD, 0x00, 0x00]);
    }

    #[test]
    fn test_extra_padding_tlv_new_is_pseudorandom() {
        // Two consecutive calls must not produce identical padding, and the
        // padding must not be all-zero (RFC 8972 §4.2).
        let a = ExtraPaddingTlv::new(32);
        let b = ExtraPaddingTlv::new(32);
        assert_ne!(a.padding, b.padding);
        assert!(a.padding.iter().any(|&x| x != 0));
        assert!(b.padding.iter().any(|&x| x != 0));
    }

    #[test]
    fn test_extra_padding_tlv_with_ssid_is_pseudorandom() {
        let a = ExtraPaddingTlv::with_ssid(0x1234, 32);
        let b = ExtraPaddingTlv::with_ssid(0x1234, 32);
        assert_eq!(a.ssid, Some(0x1234));
        assert_eq!(b.ssid, Some(0x1234));
        assert_ne!(a.padding, b.padding);
        assert!(a.padding.iter().any(|&x| x != 0));
    }

    #[test]
    fn test_extra_padding_tlv_new_zeros() {
        let tlv = ExtraPaddingTlv::new_zeros(8);
        assert!(tlv.ssid.is_none());
        assert_eq!(tlv.padding, vec![0u8; 8]);
    }

    #[test]
    fn test_session_sender_id() {
        let ssid = SessionSenderId::new(12345);
        assert_eq!(ssid.value(), 12345);

        let tlv = ssid.to_extra_padding_tlv(4);
        assert_eq!(tlv.ssid, Some(12345));
        assert_eq!(tlv.padding.len(), 4);
    }
}
