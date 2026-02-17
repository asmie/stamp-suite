//! Access Report TLV (Type 6) per RFC 8972 §4.6.

use crate::tlv::core::{TlvError, TlvType, ACCESS_REPORT_TLV_VALUE_SIZE};
use crate::tlv::traits::TypedTlv;

/// Access Report TLV (Type 6) per RFC 8972 §4.6.
///
/// Carries an Access Identifier and Return Code.
///
/// # Wire Format
///
/// ```text
///  0                   1
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// | Access ID |Rsv|  Return Code  |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct AccessReportTlv {
    /// Access Identifier (4 bits, 0-15).
    pub access_id: u8,
    /// Return Code (8 bits).
    pub return_code: u8,
}

impl AccessReportTlv {
    /// Creates a new Access Report TLV.
    #[must_use]
    pub fn new(access_id: u8, return_code: u8) -> Self {
        Self {
            access_id: access_id & 0x0F,
            return_code,
        }
    }
}

impl TypedTlv for AccessReportTlv {
    const TYPE: TlvType = TlvType::AccessReport;

    fn decode_value(value: &[u8]) -> Result<Self, TlvError> {
        if value.len() != ACCESS_REPORT_TLV_VALUE_SIZE {
            return Err(TlvError::InvalidAccessReportLength(value.len()));
        }
        let access_id = (value[0] >> 4) & 0x0F;
        let return_code = value[1];
        Ok(Self {
            access_id,
            return_code,
        })
    }

    fn encode_value(&self, out: &mut Vec<u8>) {
        out.push((self.access_id & 0x0F) << 4);
        out.push(self.return_code);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tlv::core::RawTlv;

    #[test]
    fn test_access_report_tlv_new() {
        let tlv = AccessReportTlv::new(5, 1);
        assert_eq!(tlv.access_id, 5);
        assert_eq!(tlv.return_code, 1);
    }

    #[test]
    fn test_access_report_tlv_new_clamps_access_id() {
        let tlv = AccessReportTlv::new(0xFF, 1);
        assert_eq!(tlv.access_id, 0x0F);
    }

    #[test]
    fn test_access_report_tlv_roundtrip() {
        let original = AccessReportTlv::new(10, 42);
        let raw = original.to_raw();
        let parsed = AccessReportTlv::from_raw(&raw).unwrap();
        assert_eq!(parsed.access_id, original.access_id);
        assert_eq!(parsed.return_code, original.return_code);
    }

    #[test]
    fn test_access_report_tlv_wire_format() {
        let tlv = AccessReportTlv::new(0x0A, 0x03);
        let raw = tlv.to_raw();
        assert_eq!(raw.tlv_type, TlvType::AccessReport);
        assert_eq!(raw.value.len(), ACCESS_REPORT_TLV_VALUE_SIZE);
        assert_eq!(raw.value[0], 0xA0);
        assert_eq!(raw.value[1], 0x03);
    }

    #[test]
    fn test_access_report_tlv_from_raw_invalid_length() {
        let raw = RawTlv::new(TlvType::AccessReport, vec![0x00]);
        let result = AccessReportTlv::from_raw(&raw);
        assert!(matches!(
            result,
            Err(TlvError::InvalidAccessReportLength(1))
        ));
    }

    #[test]
    fn test_access_report_tlv_from_raw_too_long() {
        let raw = RawTlv::new(TlvType::AccessReport, vec![0x00, 0x01, 0x02]);
        let result = AccessReportTlv::from_raw(&raw);
        assert!(matches!(
            result,
            Err(TlvError::InvalidAccessReportLength(3))
        ));
    }

    #[test]
    fn test_access_report_tlv_boundary_values() {
        let tlv = AccessReportTlv::new(15, 255);
        let raw = tlv.to_raw();
        let parsed = AccessReportTlv::from_raw(&raw).unwrap();
        assert_eq!(parsed.access_id, 15);
        assert_eq!(parsed.return_code, 255);

        let tlv = AccessReportTlv::new(0, 0);
        let raw = tlv.to_raw();
        let parsed = AccessReportTlv::from_raw(&raw).unwrap();
        assert_eq!(parsed.access_id, 0);
        assert_eq!(parsed.return_code, 0);
    }
}
