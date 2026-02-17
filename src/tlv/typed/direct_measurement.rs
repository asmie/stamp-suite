//! Direct Measurement TLV (Type 5) per RFC 8972 §4.5.

use crate::tlv::core::{TlvError, TlvType, DIRECT_MEASUREMENT_TLV_VALUE_SIZE};
use crate::tlv::traits::TypedTlv;

/// Direct Measurement TLV (Type 5) per RFC 8972 §4.5.
///
/// Three 4-byte counters: sender transmit count, reflector receive count,
/// and reflector transmit count.
///
/// # Wire Format
///
/// ```text
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                    Sender Tx Count (S_TxC)                    |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                   Reflector Rx Count (R_RxC)                  |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                   Reflector Tx Count (R_TxC)                  |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DirectMeasurementTlv {
    /// Sender transmit count.
    pub sender_tx_count: u32,
    /// Reflector receive count.
    pub reflector_rx_count: u32,
    /// Reflector transmit count.
    pub reflector_tx_count: u32,
}

impl DirectMeasurementTlv {
    /// Creates a new Direct Measurement TLV for the sender.
    ///
    /// The sender fills `sender_tx_count`; reflector fields are zeroed.
    #[must_use]
    pub fn new(sender_tx_count: u32) -> Self {
        Self {
            sender_tx_count,
            reflector_rx_count: 0,
            reflector_tx_count: 0,
        }
    }
}

impl TypedTlv for DirectMeasurementTlv {
    const TYPE: TlvType = TlvType::DirectMeasurement;

    fn decode_value(value: &[u8]) -> Result<Self, TlvError> {
        if value.len() != DIRECT_MEASUREMENT_TLV_VALUE_SIZE {
            return Err(TlvError::InvalidDirectMeasurementLength(value.len()));
        }
        let sender_tx_count = u32::from_be_bytes([value[0], value[1], value[2], value[3]]);
        let reflector_rx_count = u32::from_be_bytes([value[4], value[5], value[6], value[7]]);
        let reflector_tx_count = u32::from_be_bytes([value[8], value[9], value[10], value[11]]);
        Ok(Self {
            sender_tx_count,
            reflector_rx_count,
            reflector_tx_count,
        })
    }

    fn encode_value(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.sender_tx_count.to_be_bytes());
        out.extend_from_slice(&self.reflector_rx_count.to_be_bytes());
        out.extend_from_slice(&self.reflector_tx_count.to_be_bytes());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tlv::core::RawTlv;

    #[test]
    fn test_direct_measurement_tlv_new() {
        let tlv = DirectMeasurementTlv::new(42);
        assert_eq!(tlv.sender_tx_count, 42);
        assert_eq!(tlv.reflector_rx_count, 0);
        assert_eq!(tlv.reflector_tx_count, 0);
    }

    #[test]
    fn test_direct_measurement_tlv_roundtrip() {
        let original = DirectMeasurementTlv {
            sender_tx_count: 100,
            reflector_rx_count: 200,
            reflector_tx_count: 300,
        };
        let raw = original.to_raw();
        let parsed = DirectMeasurementTlv::from_raw(&raw).unwrap();
        assert_eq!(parsed, original);
    }

    #[test]
    fn test_direct_measurement_tlv_wire_format() {
        let tlv = DirectMeasurementTlv {
            sender_tx_count: 1,
            reflector_rx_count: 2,
            reflector_tx_count: 3,
        };
        let raw = tlv.to_raw();
        assert_eq!(raw.tlv_type, TlvType::DirectMeasurement);
        assert_eq!(raw.value.len(), DIRECT_MEASUREMENT_TLV_VALUE_SIZE);
        assert_eq!(&raw.value[0..4], &1u32.to_be_bytes());
        assert_eq!(&raw.value[4..8], &2u32.to_be_bytes());
        assert_eq!(&raw.value[8..12], &3u32.to_be_bytes());
    }

    #[test]
    fn test_direct_measurement_tlv_max_values() {
        let tlv = DirectMeasurementTlv {
            sender_tx_count: u32::MAX,
            reflector_rx_count: u32::MAX,
            reflector_tx_count: u32::MAX,
        };
        let raw = tlv.to_raw();
        let parsed = DirectMeasurementTlv::from_raw(&raw).unwrap();
        assert_eq!(parsed.sender_tx_count, u32::MAX);
        assert_eq!(parsed.reflector_rx_count, u32::MAX);
        assert_eq!(parsed.reflector_tx_count, u32::MAX);
    }

    #[test]
    fn test_direct_measurement_tlv_from_raw_invalid_length() {
        let raw = RawTlv::new(TlvType::DirectMeasurement, vec![0u8; 8]);
        let result = DirectMeasurementTlv::from_raw(&raw);
        assert!(matches!(
            result,
            Err(TlvError::InvalidDirectMeasurementLength(8))
        ));
    }

    #[test]
    fn test_direct_measurement_tlv_from_raw_too_long() {
        let raw = RawTlv::new(TlvType::DirectMeasurement, vec![0u8; 16]);
        let result = DirectMeasurementTlv::from_raw(&raw);
        assert!(matches!(
            result,
            Err(TlvError::InvalidDirectMeasurementLength(16))
        ));
    }
}
