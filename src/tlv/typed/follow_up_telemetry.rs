//! Follow-Up Telemetry TLV (Type 7) per RFC 8972 §4.7.

use crate::tlv::core::{TlvError, TlvType, FOLLOW_UP_TELEMETRY_TLV_VALUE_SIZE};
use crate::tlv::traits::TypedTlv;
use crate::tlv::typed::timestamp_info::TimestampMethod;

/// Follow-Up Telemetry TLV (Type 7) per RFC 8972 §4.7.
///
/// References a previously reflected packet with a follow-up timestamp.
///
/// # Wire Format
///
/// ```text
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                    Sequence Number                            |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                                                               |
/// |                    Follow-Up Timestamp (8 bytes)              |
/// |                                                               |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// | TS Mode       |           Reserved (3 bytes)                  |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FollowUpTelemetryTlv {
    /// Sequence number of the previously reflected packet.
    pub sequence_number: u32,
    /// Follow-up timestamp from the reflector.
    pub follow_up_timestamp: u64,
    /// Timestamp mode used by the reflector.
    pub timestamp_mode: TimestampMethod,
}

impl FollowUpTelemetryTlv {
    /// Creates a new Follow-Up Telemetry TLV for the sender (all fields zeroed).
    #[must_use]
    pub fn new() -> Self {
        Self {
            sequence_number: 0,
            follow_up_timestamp: 0,
            timestamp_mode: TimestampMethod::Unknown(0),
        }
    }
}

impl Default for FollowUpTelemetryTlv {
    fn default() -> Self {
        Self::new()
    }
}

impl TypedTlv for FollowUpTelemetryTlv {
    const TYPE: TlvType = TlvType::FollowUpTelemetry;

    fn decode_value(value: &[u8]) -> Result<Self, TlvError> {
        if value.len() != FOLLOW_UP_TELEMETRY_TLV_VALUE_SIZE {
            return Err(TlvError::InvalidFollowUpTelemetryLength(value.len()));
        }
        let sequence_number = u32::from_be_bytes([value[0], value[1], value[2], value[3]]);
        let follow_up_timestamp = u64::from_be_bytes([
            value[4], value[5], value[6], value[7], value[8], value[9], value[10], value[11],
        ]);
        let timestamp_mode = TimestampMethod::from_byte(value[12]);
        Ok(Self {
            sequence_number,
            follow_up_timestamp,
            timestamp_mode,
        })
    }

    fn encode_value(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.sequence_number.to_be_bytes());
        out.extend_from_slice(&self.follow_up_timestamp.to_be_bytes());
        out.push(self.timestamp_mode.to_byte());
        out.extend_from_slice(&[0u8; 3]); // Reserved
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tlv::core::RawTlv;

    #[test]
    fn test_follow_up_telemetry_tlv_new() {
        let tlv = FollowUpTelemetryTlv::new();
        assert_eq!(tlv.sequence_number, 0);
        assert_eq!(tlv.follow_up_timestamp, 0);
        assert_eq!(tlv.timestamp_mode, TimestampMethod::Unknown(0));
    }

    #[test]
    fn test_follow_up_telemetry_tlv_default() {
        let tlv = FollowUpTelemetryTlv::default();
        assert_eq!(tlv.sequence_number, 0);
        assert_eq!(tlv.follow_up_timestamp, 0);
        assert_eq!(tlv.timestamp_mode, TimestampMethod::Unknown(0));
    }

    #[test]
    fn test_follow_up_telemetry_tlv_roundtrip() {
        let original = FollowUpTelemetryTlv {
            sequence_number: 12345,
            follow_up_timestamp: 0xDEAD_BEEF_CAFE_BABE,
            timestamp_mode: TimestampMethod::HwAssist,
        };
        let raw = original.to_raw();
        let parsed = FollowUpTelemetryTlv::from_raw(&raw).unwrap();
        assert_eq!(parsed, original);
    }

    #[test]
    fn test_follow_up_telemetry_tlv_wire_format() {
        let tlv = FollowUpTelemetryTlv {
            sequence_number: 1,
            follow_up_timestamp: 2,
            timestamp_mode: TimestampMethod::SwLocal,
        };
        let raw = tlv.to_raw();
        assert_eq!(raw.tlv_type, TlvType::FollowUpTelemetry);
        assert_eq!(raw.value.len(), FOLLOW_UP_TELEMETRY_TLV_VALUE_SIZE);
        // Sequence number (4 bytes)
        assert_eq!(&raw.value[0..4], &1u32.to_be_bytes());
        // Timestamp (8 bytes)
        assert_eq!(&raw.value[4..12], &2u64.to_be_bytes());
        // TS Mode (1 byte)
        assert_eq!(raw.value[12], TimestampMethod::SwLocal.to_byte());
        // Reserved (3 bytes)
        assert_eq!(&raw.value[13..16], &[0, 0, 0]);
    }

    #[test]
    fn test_follow_up_telemetry_tlv_from_raw_invalid_length() {
        let raw = RawTlv::new(TlvType::FollowUpTelemetry, vec![0u8; 12]);
        let result = FollowUpTelemetryTlv::from_raw(&raw);
        assert!(matches!(
            result,
            Err(TlvError::InvalidFollowUpTelemetryLength(12))
        ));
    }

    #[test]
    fn test_follow_up_telemetry_tlv_from_raw_too_long() {
        let raw = RawTlv::new(TlvType::FollowUpTelemetry, vec![0u8; 20]);
        let result = FollowUpTelemetryTlv::from_raw(&raw);
        assert!(matches!(
            result,
            Err(TlvError::InvalidFollowUpTelemetryLength(20))
        ));
    }

    #[test]
    fn test_follow_up_telemetry_tlv_max_values() {
        let tlv = FollowUpTelemetryTlv {
            sequence_number: u32::MAX,
            follow_up_timestamp: u64::MAX,
            timestamp_mode: TimestampMethod::Unknown(255),
        };
        let raw = tlv.to_raw();
        let parsed = FollowUpTelemetryTlv::from_raw(&raw).unwrap();
        assert_eq!(parsed.sequence_number, u32::MAX);
        assert_eq!(parsed.follow_up_timestamp, u64::MAX);
        assert_eq!(parsed.timestamp_mode, TimestampMethod::Unknown(255));
    }
}
