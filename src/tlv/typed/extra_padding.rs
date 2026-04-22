//! Extra Padding TLV (Type 1) per RFC 8972 §4.2.
//!
//! The Value field carries opaque padding — typically pseudorandom bytes to
//! ensure the TLV is non-compressible. SSID is **not** carried here: per
//! RFC 8972 §3 it lives in the base STAMP packet header (bytes 14-15 unauth /
//! 26-27 auth), not in any TLV payload.

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

fn pseudorandom_bytes(n: usize) -> Vec<u8> {
    let mut v = Vec::with_capacity(n);
    PRNG_STATE.with(|cell| {
        let mut state = cell.get();
        while v.len() < n {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            let bytes = state.to_le_bytes();
            let take = (n - v.len()).min(8);
            v.extend_from_slice(&bytes[..take]);
        }
        cell.set(state);
    });
    v
}

/// Extra Padding TLV (Type 1) per RFC 8972 §4.2.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtraPaddingTlv {
    /// Opaque padding bytes (pseudorandom for normal sender use).
    pub padding: Vec<u8>,
}

impl ExtraPaddingTlv {
    /// Creates an Extra Padding TLV with pseudorandom padding per RFC 8972 §4.2.
    #[must_use]
    pub fn new(padding_size: usize) -> Self {
        Self {
            padding: pseudorandom_bytes(padding_size),
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
            padding: vec![0u8; padding_size],
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
        Ok(Self {
            padding: value.to_vec(),
        })
    }

    fn encode_value(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.padding);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extra_padding_tlv_new() {
        let tlv = ExtraPaddingTlv::new(10);
        assert_eq!(tlv.padding.len(), 10);
    }

    #[test]
    fn test_extra_padding_tlv_from_raw_round_trip() {
        let raw = RawTlv::new(TlvType::ExtraPadding, vec![0x00, 0x00, 0x11, 0x22]);
        let tlv = ExtraPaddingTlv::from_raw(&raw);
        assert_eq!(tlv.padding, vec![0x00, 0x00, 0x11, 0x22]);
        assert_eq!(tlv.to_raw().value, raw.value);
    }

    #[test]
    fn test_extra_padding_tlv_to_raw() {
        let tlv = ExtraPaddingTlv::new_zeros(4);
        let raw = tlv.to_raw();
        assert_eq!(raw.tlv_type, TlvType::ExtraPadding);
        assert_eq!(raw.value, vec![0; 4]);
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
    fn test_extra_padding_tlv_new_zeros() {
        let tlv = ExtraPaddingTlv::new_zeros(8);
        assert_eq!(tlv.padding, vec![0u8; 8]);
    }
}
