//! BER Max Bit Error Burst Size TLV (Type 242)
//! per draft-gandhi-ippm-stamp-ber-05 §3.4.
//!
//! Carries the longest run of consecutive `1` bits observed by the
//! Session-Reflector when XORing the received Extra Padding against the
//! expected Bit Pattern. The Session-Sender MUST initialize to 0.

use crate::tlv::core::{TlvError, TlvType, BER_BURST_TLV_VALUE_SIZE};
use crate::tlv::traits::TypedTlv;

/// BER Max Bit Error Burst Size TLV (Type 242).
///
/// # Wire Format
///
/// ```text
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |          Maximum Bit Error Burst Size in Padding              |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct BerBurstTlv {
    /// Longest consecutive run of error bits. Sender sets 0; reflector fills in.
    pub max_burst: u32,
}

impl BerBurstTlv {
    /// Creates a new Max Burst TLV with the given value.
    #[must_use]
    pub fn new(max_burst: u32) -> Self {
        Self { max_burst }
    }
}

impl TypedTlv for BerBurstTlv {
    const TYPE: TlvType = TlvType::BerBurst;

    fn decode_value(value: &[u8]) -> Result<Self, TlvError> {
        if value.len() != BER_BURST_TLV_VALUE_SIZE {
            return Err(TlvError::InvalidBerBurstLength(value.len()));
        }
        let max_burst = u32::from_be_bytes([value[0], value[1], value[2], value[3]]);
        Ok(Self { max_burst })
    }

    fn encode_value(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.max_burst.to_be_bytes());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tlv::core::RawTlv;

    #[test]
    fn test_ber_burst_new() {
        let tlv = BerBurstTlv::new(42);
        assert_eq!(tlv.max_burst, 42);
    }

    #[test]
    fn test_ber_burst_default_is_zero() {
        assert_eq!(BerBurstTlv::default().max_burst, 0);
    }

    #[test]
    fn test_ber_burst_roundtrip() {
        let original = BerBurstTlv::new(0xCAFEBABE);
        let raw = original.to_raw();
        assert_eq!(raw.tlv_type, TlvType::BerBurst);
        assert_eq!(raw.value.len(), BER_BURST_TLV_VALUE_SIZE);
        assert_eq!(raw.value, 0xCAFE_BABEu32.to_be_bytes());

        let parsed = BerBurstTlv::from_raw(&raw).unwrap();
        assert_eq!(parsed, original);
    }

    #[test]
    fn test_ber_burst_invalid_length() {
        let raw = RawTlv::new(TlvType::BerBurst, vec![0; 2]);
        let result = BerBurstTlv::from_raw(&raw);
        assert!(matches!(result, Err(TlvError::InvalidBerBurstLength(2))));
    }
}
