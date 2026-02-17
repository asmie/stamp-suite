//! HMAC TLV (Type 8) for TLV integrity verification.

use crate::tlv::core::{RawTlv, TlvError, TlvType, HMAC_TLV_VALUE_SIZE};
use crate::tlv::traits::TypedTlv;

/// HMAC TLV (Type 8) for TLV integrity verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HmacTlv {
    /// The 16-byte HMAC value.
    pub hmac: [u8; 16],
}

impl HmacTlv {
    /// Creates an HMAC TLV from a computed HMAC.
    #[must_use]
    pub fn new(hmac: [u8; 16]) -> Self {
        Self { hmac }
    }

    /// Parses an HMAC TLV from a RawTlv.
    ///
    /// # Errors
    /// Returns an error if the value is not 16 bytes.
    pub fn from_raw(raw: &RawTlv) -> Result<Self, TlvError> {
        Self::decode_value(&raw.value)
    }

    /// Converts to a RawTlv.
    #[must_use]
    pub fn to_raw(&self) -> RawTlv {
        <Self as TypedTlv>::to_raw(self)
    }
}

impl TypedTlv for HmacTlv {
    const TYPE: TlvType = TlvType::Hmac;

    fn decode_value(value: &[u8]) -> Result<Self, TlvError> {
        if value.len() != HMAC_TLV_VALUE_SIZE {
            return Err(TlvError::InvalidHmacLength(value.len()));
        }
        let mut hmac = [0u8; 16];
        hmac.copy_from_slice(value);
        Ok(Self { hmac })
    }

    fn encode_value(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.hmac);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hmac_tlv_new() {
        let hmac = [0xAB; 16];
        let tlv = HmacTlv::new(hmac);
        assert_eq!(tlv.hmac, hmac);
    }

    #[test]
    fn test_hmac_tlv_from_raw() {
        let raw = RawTlv::new(TlvType::Hmac, vec![0xCD; 16]);
        let tlv = HmacTlv::from_raw(&raw).unwrap();
        assert_eq!(tlv.hmac, [0xCD; 16]);
    }

    #[test]
    fn test_hmac_tlv_from_raw_invalid_length() {
        let raw = RawTlv::new(TlvType::Hmac, vec![0xCD; 10]);
        let result = HmacTlv::from_raw(&raw);
        assert!(matches!(result, Err(TlvError::InvalidHmacLength(10))));
    }
}
