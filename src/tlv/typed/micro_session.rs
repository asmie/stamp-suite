//! Micro-session ID TLV (Type 11) per RFC 9534 §3.1.

use crate::tlv::core::{TlvError, TlvType, MICRO_SESSION_ID_TLV_VALUE_SIZE};
use crate::tlv::traits::TypedTlv;

/// Micro-session ID TLV (Type 11) per RFC 9534 §3.1.
///
/// Carries two 16-bit member link identifiers for LAG performance measurement.
/// The sender sets its own member link ID; the reflector fills in its own.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MicroSessionIdTlv {
    /// Sender's LAG member link identifier.
    pub sender_micro_session_id: u16,
    /// Reflector's LAG member link identifier (0 = unknown).
    pub reflector_micro_session_id: u16,
}

impl MicroSessionIdTlv {
    /// Creates a new Micro-session ID TLV.
    #[must_use]
    pub fn new(sender_id: u16, reflector_id: u16) -> Self {
        Self {
            sender_micro_session_id: sender_id,
            reflector_micro_session_id: reflector_id,
        }
    }
}

impl TypedTlv for MicroSessionIdTlv {
    const TYPE: TlvType = TlvType::MicroSessionId;

    fn decode_value(value: &[u8]) -> Result<Self, TlvError> {
        if value.len() != MICRO_SESSION_ID_TLV_VALUE_SIZE {
            return Err(TlvError::InvalidMicroSessionIdLength(value.len()));
        }
        let sender_id = u16::from_be_bytes([value[0], value[1]]);
        let reflector_id = u16::from_be_bytes([value[2], value[3]]);
        Ok(Self {
            sender_micro_session_id: sender_id,
            reflector_micro_session_id: reflector_id,
        })
    }

    fn encode_value(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.sender_micro_session_id.to_be_bytes());
        out.extend_from_slice(&self.reflector_micro_session_id.to_be_bytes());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tlv::core::RawTlv;

    #[test]
    fn test_micro_session_id_roundtrip() {
        let original = MicroSessionIdTlv::new(0x1234, 0x5678);
        let raw = original.to_raw();
        assert_eq!(raw.tlv_type, TlvType::MicroSessionId);
        assert_eq!(raw.value.len(), MICRO_SESSION_ID_TLV_VALUE_SIZE);
        let parsed = MicroSessionIdTlv::from_raw(&raw).unwrap();
        assert_eq!(parsed, original);
    }

    #[test]
    fn test_micro_session_id_invalid_length() {
        let raw = RawTlv::new(TlvType::MicroSessionId, vec![0u8; 6]);
        let result = MicroSessionIdTlv::from_raw(&raw);
        assert!(matches!(
            result,
            Err(TlvError::InvalidMicroSessionIdLength(6))
        ));
    }

    #[test]
    fn test_micro_session_id_type_recognized() {
        assert!(TlvType::MicroSessionId.is_recognized());
        assert_eq!(TlvType::MicroSessionId.to_byte(), 11);
    }
}
