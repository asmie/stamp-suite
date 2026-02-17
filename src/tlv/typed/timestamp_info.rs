//! Timestamp Information TLV (Type 3) per RFC 8972 §4.3 and supporting enums.

use crate::tlv::core::{TlvError, TlvType, TIMESTAMP_INFO_TLV_VALUE_SIZE};
use crate::tlv::traits::TypedTlv;

/// Synchronization source for Timestamp Information TLV per RFC 8972 §4.3.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SyncSource {
    /// NTP synchronization.
    Ntp = 1,
    /// PTP (IEEE 1588) synchronization.
    Ptp = 2,
    /// GPS synchronization.
    Gps = 3,
    /// GLONASS synchronization.
    Glonass = 4,
    /// LORAN-C synchronization.
    LoranC = 5,
    /// BDS (BeiDou) synchronization.
    Bds = 6,
    /// Galileo synchronization.
    Galileo = 7,
    /// Local clock (unsynchronized).
    Local = 8,
    /// SSU/BITS synchronization.
    SsuBits = 9,
    /// Unknown synchronization source.
    Unknown(u8),
}

impl SyncSource {
    /// Creates a SyncSource from a byte value.
    #[must_use]
    pub fn from_byte(byte: u8) -> Self {
        match byte {
            1 => Self::Ntp,
            2 => Self::Ptp,
            3 => Self::Gps,
            4 => Self::Glonass,
            5 => Self::LoranC,
            6 => Self::Bds,
            7 => Self::Galileo,
            8 => Self::Local,
            9 => Self::SsuBits,
            n => Self::Unknown(n),
        }
    }

    /// Converts to a byte value.
    #[must_use]
    pub fn to_byte(self) -> u8 {
        match self {
            Self::Ntp => 1,
            Self::Ptp => 2,
            Self::Gps => 3,
            Self::Glonass => 4,
            Self::LoranC => 5,
            Self::Bds => 6,
            Self::Galileo => 7,
            Self::Local => 8,
            Self::SsuBits => 9,
            Self::Unknown(n) => n,
        }
    }
}

/// Timestamp method for Timestamp Information TLV per RFC 8972 §4.3.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum TimestampMethod {
    /// Hardware-assisted timestamping.
    HwAssist = 1,
    /// Software local timestamping.
    SwLocal = 2,
    /// Control plane timestamping.
    ControlPlane = 3,
    /// Unknown method.
    Unknown(u8),
}

impl TimestampMethod {
    /// Creates a TimestampMethod from a byte value.
    #[must_use]
    pub fn from_byte(byte: u8) -> Self {
        match byte {
            1 => Self::HwAssist,
            2 => Self::SwLocal,
            3 => Self::ControlPlane,
            n => Self::Unknown(n),
        }
    }

    /// Converts to a byte value.
    #[must_use]
    pub fn to_byte(self) -> u8 {
        match self {
            Self::HwAssist => 1,
            Self::SwLocal => 2,
            Self::ControlPlane => 3,
            Self::Unknown(n) => n,
        }
    }
}

/// Timestamp Information TLV (Type 3) per RFC 8972 §4.3.
///
/// # Wire Format
///
/// ```text
///  0         1         2         3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// | Sync Src In   | TS Method In  | Sync Src Out  | TS Method Out |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TimestampInfoTlv {
    /// Synchronization source of the sender.
    pub sync_src_in: SyncSource,
    /// Timestamp method of the sender.
    pub timestamp_in: TimestampMethod,
    /// Synchronization source of the reflector.
    pub sync_src_out: SyncSource,
    /// Timestamp method of the reflector.
    pub timestamp_out: TimestampMethod,
}

impl TimestampInfoTlv {
    /// Creates a new Timestamp Info TLV for the sender.
    #[must_use]
    pub fn new(sync_src: SyncSource, ts_method: TimestampMethod) -> Self {
        Self {
            sync_src_in: sync_src,
            timestamp_in: ts_method,
            sync_src_out: SyncSource::Unknown(0),
            timestamp_out: TimestampMethod::Unknown(0),
        }
    }
}

impl TypedTlv for TimestampInfoTlv {
    const TYPE: TlvType = TlvType::TimestampInfo;

    fn decode_value(value: &[u8]) -> Result<Self, TlvError> {
        if value.len() != TIMESTAMP_INFO_TLV_VALUE_SIZE {
            return Err(TlvError::InvalidTimestampInfoLength(value.len()));
        }
        Ok(Self {
            sync_src_in: SyncSource::from_byte(value[0]),
            timestamp_in: TimestampMethod::from_byte(value[1]),
            sync_src_out: SyncSource::from_byte(value[2]),
            timestamp_out: TimestampMethod::from_byte(value[3]),
        })
    }

    fn encode_value(&self, out: &mut Vec<u8>) {
        out.push(self.sync_src_in.to_byte());
        out.push(self.timestamp_in.to_byte());
        out.push(self.sync_src_out.to_byte());
        out.push(self.timestamp_out.to_byte());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tlv::core::RawTlv;

    #[test]
    fn test_sync_source_roundtrip() {
        let sources = [
            SyncSource::Ntp,
            SyncSource::Ptp,
            SyncSource::Gps,
            SyncSource::Glonass,
            SyncSource::LoranC,
            SyncSource::Bds,
            SyncSource::Galileo,
            SyncSource::Local,
            SyncSource::SsuBits,
            SyncSource::Unknown(42),
        ];
        for src in &sources {
            let byte = src.to_byte();
            let parsed = SyncSource::from_byte(byte);
            assert_eq!(*src, parsed);
        }
    }

    #[test]
    fn test_sync_source_byte_values() {
        assert_eq!(SyncSource::Ntp.to_byte(), 1);
        assert_eq!(SyncSource::Ptp.to_byte(), 2);
        assert_eq!(SyncSource::Gps.to_byte(), 3);
        assert_eq!(SyncSource::Local.to_byte(), 8);
        assert_eq!(SyncSource::SsuBits.to_byte(), 9);
        assert_eq!(SyncSource::Unknown(0).to_byte(), 0);
        assert_eq!(SyncSource::Unknown(255).to_byte(), 255);
    }

    #[test]
    fn test_timestamp_method_roundtrip() {
        let methods = [
            TimestampMethod::HwAssist,
            TimestampMethod::SwLocal,
            TimestampMethod::ControlPlane,
            TimestampMethod::Unknown(99),
        ];
        for method in &methods {
            let byte = method.to_byte();
            let parsed = TimestampMethod::from_byte(byte);
            assert_eq!(*method, parsed);
        }
    }

    #[test]
    fn test_timestamp_method_byte_values() {
        assert_eq!(TimestampMethod::HwAssist.to_byte(), 1);
        assert_eq!(TimestampMethod::SwLocal.to_byte(), 2);
        assert_eq!(TimestampMethod::ControlPlane.to_byte(), 3);
        assert_eq!(TimestampMethod::Unknown(0).to_byte(), 0);
    }

    #[test]
    fn test_timestamp_info_tlv_new() {
        let tlv = TimestampInfoTlv::new(SyncSource::Ntp, TimestampMethod::SwLocal);
        assert_eq!(tlv.sync_src_in, SyncSource::Ntp);
        assert_eq!(tlv.timestamp_in, TimestampMethod::SwLocal);
        assert_eq!(tlv.sync_src_out, SyncSource::Unknown(0));
        assert_eq!(tlv.timestamp_out, TimestampMethod::Unknown(0));
    }

    #[test]
    fn test_timestamp_info_tlv_roundtrip() {
        let original = TimestampInfoTlv {
            sync_src_in: SyncSource::Ptp,
            timestamp_in: TimestampMethod::HwAssist,
            sync_src_out: SyncSource::Gps,
            timestamp_out: TimestampMethod::ControlPlane,
        };
        let raw = original.to_raw();
        let parsed = TimestampInfoTlv::from_raw(&raw).unwrap();
        assert_eq!(parsed, original);
    }

    #[test]
    fn test_timestamp_info_tlv_wire_format() {
        let tlv = TimestampInfoTlv {
            sync_src_in: SyncSource::Ntp,
            timestamp_in: TimestampMethod::SwLocal,
            sync_src_out: SyncSource::Ptp,
            timestamp_out: TimestampMethod::HwAssist,
        };
        let raw = tlv.to_raw();
        assert_eq!(raw.tlv_type, TlvType::TimestampInfo);
        assert_eq!(raw.value.len(), TIMESTAMP_INFO_TLV_VALUE_SIZE);
        assert_eq!(raw.value, vec![1, 2, 2, 1]);
    }

    #[test]
    fn test_timestamp_info_tlv_from_raw_invalid_length() {
        let raw = RawTlv::new(TlvType::TimestampInfo, vec![1, 2, 3]);
        let result = TimestampInfoTlv::from_raw(&raw);
        assert!(matches!(
            result,
            Err(TlvError::InvalidTimestampInfoLength(3))
        ));
    }

    #[test]
    fn test_timestamp_info_tlv_from_raw_too_long() {
        let raw = RawTlv::new(TlvType::TimestampInfo, vec![1, 2, 3, 4, 5]);
        let result = TimestampInfoTlv::from_raw(&raw);
        assert!(matches!(
            result,
            Err(TlvError::InvalidTimestampInfoLength(5))
        ));
    }
}
