//! TypedTlv trait for zero-cost static dispatch on TLV extensions.

use super::core::{RawTlv, TlvError, TlvType};

/// Static, zero-cost trait for typed STAMP TLV extensions.
///
/// Implementors provide `decode_value` and `encode_value` for the raw byte
/// payload. The trait supplies default `from_raw` and `to_raw` that handle
/// type validation and TLV header wrapping automatically.
pub trait TypedTlv: Sized {
    /// The TLV type code for this extension.
    const TYPE: TlvType;

    /// Decode the TLV value bytes into this typed representation.
    ///
    /// # Errors
    /// Returns `TlvError` if the value bytes are malformed for this type.
    fn decode_value(value: &[u8]) -> Result<Self, TlvError>;

    /// Encode this TLV's payload into the output buffer.
    fn encode_value(&self, out: &mut Vec<u8>);

    /// Parse a typed TLV from its raw wire representation.
    ///
    /// Default implementation validates the type code matches `Self::TYPE`,
    /// then delegates to `decode_value`.
    fn from_raw(raw: &RawTlv) -> Result<Self, TlvError> {
        if raw.tlv_type != Self::TYPE {
            return Err(TlvError::TypeMismatch {
                expected: Self::TYPE,
                actual: raw.tlv_type,
            });
        }
        Self::decode_value(&raw.value)
    }

    /// Serialize this TLV to its raw wire representation.
    ///
    /// Default implementation builds a `RawTlv` with sender flags and the correct type.
    fn to_raw(&self) -> RawTlv {
        let mut value = Vec::new();
        self.encode_value(&mut value);
        RawTlv::new(Self::TYPE, value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tlv::{ClassOfServiceTlv, SyncSource, TimestampInfoTlv, TimestampMethod};

    #[test]
    fn test_from_raw_success_with_matching_type() {
        let cos = ClassOfServiceTlv::new(46, 2);
        let raw = cos.to_raw();
        let parsed = ClassOfServiceTlv::from_raw(&raw).unwrap();
        assert_eq!(parsed.dscp1, 46);
        assert_eq!(parsed.ecn1, 2);
    }

    #[test]
    fn test_from_raw_returns_type_mismatch_on_wrong_type() {
        let raw = RawTlv::new(TlvType::Location, vec![0xBA, 0x00, 0x00, 0x00]);
        let result = ClassOfServiceTlv::from_raw(&raw);
        assert!(matches!(
            result,
            Err(TlvError::TypeMismatch {
                expected: TlvType::ClassOfService,
                actual: TlvType::Location,
            })
        ));
    }

    #[test]
    fn test_to_raw_roundtrip_cos() {
        let original = ClassOfServiceTlv::new(63, 3);
        let raw = original.to_raw();
        assert_eq!(raw.tlv_type, TlvType::ClassOfService);
        let parsed = ClassOfServiceTlv::from_raw(&raw).unwrap();
        assert_eq!(parsed.dscp1, original.dscp1);
        assert_eq!(parsed.ecn1, original.ecn1);
    }

    #[test]
    fn test_to_raw_roundtrip_timestamp_info() {
        let original = TimestampInfoTlv {
            sync_src_in: SyncSource::Ptp,
            timestamp_in: TimestampMethod::HwAssist,
            sync_src_out: SyncSource::Gps,
            timestamp_out: TimestampMethod::ControlPlane,
        };
        let raw = original.to_raw();
        assert_eq!(raw.tlv_type, TlvType::TimestampInfo);
        let parsed = TimestampInfoTlv::from_raw(&raw).unwrap();
        assert_eq!(parsed, original);
    }

    #[test]
    fn test_from_raw_type_mismatch_timestamp_info() {
        let raw = RawTlv::new(TlvType::ClassOfService, vec![1, 2, 3, 4]);
        let result = TimestampInfoTlv::from_raw(&raw);
        assert!(matches!(
            result,
            Err(TlvError::TypeMismatch {
                expected: TlvType::TimestampInfo,
                actual: TlvType::ClassOfService,
            })
        ));
    }
}
