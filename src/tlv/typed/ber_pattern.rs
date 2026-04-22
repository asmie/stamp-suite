//! BER Bit Pattern in Padding TLV (Type 240)
//! per draft-gandhi-ippm-stamp-ber-05 §3.2.
//!
//! Carries the bit pattern the Session-Sender used to fill the companion
//! RFC 8972 Extra Padding TLV. The Session-Reflector uses it as the expected
//! pattern when computing the Bit Error Count and Max Burst Size TLVs.
//!
//! Per the draft, the default pattern when the value is empty is `0xFF00`
//! (alternating 0xFF and 0x00 bytes).

use crate::tlv::core::{TlvError, TlvType};
use crate::tlv::traits::TypedTlv;

/// Default bit pattern `{0xFF, 0x00}` used when the sender omits the pattern
/// value (draft §3.2).
pub const BER_DEFAULT_PATTERN: [u8; 2] = [0xFF, 0x00];

/// BER Bit Pattern in Padding TLV (Type 240).
///
/// Variable-length value containing the bit pattern the sender repeated to
/// fill the Extra Padding TLV. An empty value means "use the default pattern".
///
/// # Wire Format
///
/// ```text
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                                                               |
/// ~                  Bit Pattern in Padding                       ~
/// |                                                               |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct BerPatternTlv {
    /// The bit pattern bytes. Empty means "use `BER_DEFAULT_PATTERN`".
    pub pattern: Vec<u8>,
}

impl BerPatternTlv {
    /// Creates a new Bit Pattern TLV with an explicit pattern.
    #[must_use]
    pub fn new(pattern: Vec<u8>) -> Self {
        Self { pattern }
    }

    /// Creates a new Bit Pattern TLV carrying the default pattern (0xFF00).
    #[must_use]
    pub fn with_default_pattern() -> Self {
        Self {
            pattern: BER_DEFAULT_PATTERN.to_vec(),
        }
    }

    /// Returns the effective pattern: the explicit one, or `BER_DEFAULT_PATTERN`
    /// if the TLV carries no pattern bytes.
    #[must_use]
    pub fn effective_pattern(&self) -> &[u8] {
        if self.pattern.is_empty() {
            &BER_DEFAULT_PATTERN
        } else {
            &self.pattern
        }
    }
}

impl TypedTlv for BerPatternTlv {
    const TYPE: TlvType = TlvType::BerPattern;

    fn decode_value(value: &[u8]) -> Result<Self, TlvError> {
        Ok(Self {
            pattern: value.to_vec(),
        })
    }

    fn encode_value(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.pattern);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ber_pattern_new() {
        let tlv = BerPatternTlv::new(vec![0xAA, 0x55]);
        assert_eq!(tlv.pattern, vec![0xAA, 0x55]);
    }

    #[test]
    fn test_ber_pattern_default() {
        let tlv = BerPatternTlv::with_default_pattern();
        assert_eq!(tlv.pattern, vec![0xFF, 0x00]);
    }

    #[test]
    fn test_ber_pattern_effective_when_empty() {
        let tlv = BerPatternTlv::default();
        assert_eq!(tlv.effective_pattern(), &BER_DEFAULT_PATTERN);
    }

    #[test]
    fn test_ber_pattern_effective_when_explicit() {
        let tlv = BerPatternTlv::new(vec![0x5A]);
        assert_eq!(tlv.effective_pattern(), &[0x5A]);
    }

    #[test]
    fn test_ber_pattern_roundtrip() {
        let original = BerPatternTlv::new(vec![0xDE, 0xAD, 0xBE, 0xEF]);
        let raw = original.to_raw();
        let parsed = BerPatternTlv::from_raw(&raw).unwrap();
        assert_eq!(parsed, original);
        assert_eq!(raw.tlv_type, TlvType::BerPattern);
    }

    #[test]
    fn test_ber_pattern_empty_roundtrip() {
        let original = BerPatternTlv::default();
        let raw = original.to_raw();
        assert_eq!(raw.value.len(), 0);
        let parsed = BerPatternTlv::from_raw(&raw).unwrap();
        assert_eq!(parsed, original);
    }
}
