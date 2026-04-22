//! BER Bit Error Count in Padding TLV (Type 241)
//! per draft-gandhi-ippm-stamp-ber-05 §3.3.
//!
//! Carries the number of error bits observed by the Session-Reflector when
//! XORing the received Extra Padding TLV against the expected pattern from
//! the companion Bit Pattern TLV. The Session-Sender MUST initialize to 0.

use crate::tlv::core::{TlvError, TlvType, BER_COUNT_TLV_VALUE_SIZE};
use crate::tlv::traits::TypedTlv;

/// BER Bit Error Count in Padding TLV (Type 241).
///
/// # Wire Format
///
/// ```text
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                  Bit Error Count in Padding                   |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct BerCountTlv {
    /// Number of error bits observed. Sender sets 0; reflector fills in.
    pub count: u32,
}

impl BerCountTlv {
    /// Creates a new Bit Error Count TLV with the given count.
    ///
    /// Senders should use `BerCountTlv::default()` (count = 0) and let the
    /// reflector compute the value.
    #[must_use]
    pub fn new(count: u32) -> Self {
        Self { count }
    }
}

impl TypedTlv for BerCountTlv {
    const TYPE: TlvType = TlvType::BerCount;

    fn decode_value(value: &[u8]) -> Result<Self, TlvError> {
        if value.len() != BER_COUNT_TLV_VALUE_SIZE {
            return Err(TlvError::InvalidBerCountLength(value.len()));
        }
        let count = u32::from_be_bytes([value[0], value[1], value[2], value[3]]);
        Ok(Self { count })
    }

    fn encode_value(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.count.to_be_bytes());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tlv::core::RawTlv;

    #[test]
    fn test_ber_count_new() {
        let tlv = BerCountTlv::new(42);
        assert_eq!(tlv.count, 42);
    }

    #[test]
    fn test_ber_count_default_is_zero() {
        assert_eq!(BerCountTlv::default().count, 0);
    }

    #[test]
    fn test_ber_count_roundtrip() {
        let original = BerCountTlv::new(0xDEAD_BEEF);
        let raw = original.to_raw();
        assert_eq!(raw.tlv_type, TlvType::BerCount);
        assert_eq!(raw.value.len(), BER_COUNT_TLV_VALUE_SIZE);
        assert_eq!(raw.value, 0xDEAD_BEEFu32.to_be_bytes());

        let parsed = BerCountTlv::from_raw(&raw).unwrap();
        assert_eq!(parsed, original);
    }

    #[test]
    fn test_ber_count_invalid_length() {
        let raw = RawTlv::new(TlvType::BerCount, vec![0, 0, 0]);
        let result = BerCountTlv::from_raw(&raw);
        assert!(matches!(result, Err(TlvError::InvalidBerCountLength(3))));
    }
}
