//! Core TLV types: TlvError, TlvFlags, TlvType, RawTlv, and size constants.

use thiserror::Error;

/// TLV header size in bytes (1 byte flags+type, 2 bytes length).
pub const TLV_HEADER_SIZE: usize = 4;

/// HMAC TLV value length (16 bytes).
pub const HMAC_TLV_VALUE_SIZE: usize = 16;

/// Class of Service TLV value size (4 bytes).
pub const COS_TLV_VALUE_SIZE: usize = 4;

/// Access Report TLV value size (2 bytes).
pub const ACCESS_REPORT_TLV_VALUE_SIZE: usize = 2;

/// Timestamp Information TLV value size (4 bytes).
pub const TIMESTAMP_INFO_TLV_VALUE_SIZE: usize = 4;

/// Direct Measurement TLV value size (12 bytes: three u32 counters).
pub const DIRECT_MEASUREMENT_TLV_VALUE_SIZE: usize = 12;

/// Location TLV minimum value size (4 bytes: dest_port + src_port).
pub const LOCATION_TLV_MIN_VALUE_SIZE: usize = 4;

/// Follow-Up Telemetry TLV value size (16 bytes).
pub const FOLLOW_UP_TELEMETRY_TLV_VALUE_SIZE: usize = 16;

/// Destination Node Address TLV IPv4 value size (4 bytes).
pub const DEST_NODE_ADDR_IPV4_SIZE: usize = 4;

/// Destination Node Address TLV IPv6 value size (16 bytes).
pub const DEST_NODE_ADDR_IPV6_SIZE: usize = 16;

/// Return Path Control Code sub-TLV value size (4 bytes).
pub const RETURN_PATH_CONTROL_CODE_SIZE: usize = 4;

/// Micro-session ID TLV value size (4 bytes: two u16 IDs).
pub const MICRO_SESSION_ID_TLV_VALUE_SIZE: usize = 4;

/// Errors that can occur during TLV parsing or processing.
#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum TlvError {
    /// Buffer is too small to contain a valid TLV header.
    #[error("Buffer too small for TLV header: need {TLV_HEADER_SIZE} bytes, got {0}")]
    BufferTooSmall(usize),

    /// TLV length exceeds available buffer space.
    #[error("TLV length {length} exceeds remaining buffer size {available}")]
    LengthExceedsBuffer { length: usize, available: usize },

    /// HMAC TLV is not at the end of the TLV list.
    #[error("HMAC TLV must be last in the TLV list per RFC 8972")]
    HmacNotLast,

    /// HMAC TLV has invalid length.
    #[error("HMAC TLV has invalid length {0}, expected {HMAC_TLV_VALUE_SIZE}")]
    InvalidHmacLength(usize),

    /// HMAC verification failed.
    #[error("HMAC verification failed")]
    HmacVerificationFailed,

    /// Multiple HMAC TLVs found.
    #[error("Multiple HMAC TLVs found, only one allowed")]
    MultipleHmacTlvs,

    /// Class of Service TLV has invalid length.
    #[error("CoS TLV has invalid length {0}, expected {COS_TLV_VALUE_SIZE}")]
    InvalidCosLength(usize),

    /// Access Report TLV has invalid length.
    #[error("Access Report TLV has invalid length {0}, expected {ACCESS_REPORT_TLV_VALUE_SIZE}")]
    InvalidAccessReportLength(usize),

    /// Timestamp Information TLV has invalid length.
    #[error("Timestamp Info TLV has invalid length {0}, expected {TIMESTAMP_INFO_TLV_VALUE_SIZE}")]
    InvalidTimestampInfoLength(usize),

    /// Direct Measurement TLV has invalid length.
    #[error("Direct Measurement TLV has invalid length {0}, expected {DIRECT_MEASUREMENT_TLV_VALUE_SIZE}")]
    InvalidDirectMeasurementLength(usize),

    /// Location TLV has invalid length (too short for ports).
    #[error("Location TLV has invalid length {0}, minimum {LOCATION_TLV_MIN_VALUE_SIZE}")]
    InvalidLocationLength(usize),

    /// Follow-Up Telemetry TLV has invalid length.
    #[error("Follow-Up Telemetry TLV has invalid length {0}, expected {FOLLOW_UP_TELEMETRY_TLV_VALUE_SIZE}")]
    InvalidFollowUpTelemetryLength(usize),

    /// Destination Node Address TLV has invalid length.
    #[error("Destination Node Address TLV has invalid length {0}, expected 4 (IPv4) or 16 (IPv6)")]
    InvalidDestinationNodeAddressLength(usize),

    /// Return Path TLV has invalid length.
    #[error("Return Path TLV has invalid length {0}, minimum 4 (one sub-TLV header)")]
    InvalidReturnPathLength(usize),

    /// Micro-session ID TLV has invalid length.
    #[error(
        "Micro-session ID TLV has invalid length {0}, expected {MICRO_SESSION_ID_TLV_VALUE_SIZE}"
    )]
    InvalidMicroSessionIdLength(usize),

    /// TLV type mismatch when parsing a typed TLV.
    #[error("TLV type mismatch: expected {expected:?}, got {actual:?}")]
    TypeMismatch {
        /// The expected TLV type.
        expected: TlvType,
        /// The actual TLV type found.
        actual: TlvType,
    },
}

/// TLV flag bits as defined in RFC 8972 Section 4.2.
///
/// Flags occupy a full octet with the following layout:
/// ```text
///  0 1 2 3 4 5 6 7
/// +-+-+-+-+-+-+-+-+
/// |U|M|I|R|R|R|R|R|
/// +-+-+-+-+-+-+-+-+
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct TlvFlags {
    /// Unrecognized TLV type (bit 0, set by receiver when type is unknown).
    pub unrecognized: bool,
    /// Malformed TLV (bit 1, set when TLV structure is invalid).
    pub malformed: bool,
    /// Integrity check failed (bit 2, set when HMAC verification fails).
    pub integrity_failed: bool,
}

impl TlvFlags {
    /// Creates flags from a full octet value.
    #[must_use]
    pub fn from_byte(byte: u8) -> Self {
        Self {
            unrecognized: (byte & 0x80) != 0,     // Bit 0 (MSB)
            malformed: (byte & 0x40) != 0,        // Bit 1
            integrity_failed: (byte & 0x20) != 0, // Bit 2
        }
    }

    /// Converts flags to a full octet value.
    #[must_use]
    pub fn to_byte(self) -> u8 {
        let mut byte = 0u8;
        if self.unrecognized {
            byte |= 0x80; // Bit 0 (MSB)
        }
        if self.malformed {
            byte |= 0x40; // Bit 1
        }
        if self.integrity_failed {
            byte |= 0x20; // Bit 2
        }
        byte
    }

    /// Creates flags with the unrecognized bit set.
    #[must_use]
    pub fn unrecognized() -> Self {
        Self {
            unrecognized: true,
            ..Default::default()
        }
    }

    /// Creates flags with the malformed bit set.
    #[must_use]
    pub fn malformed() -> Self {
        Self {
            malformed: true,
            ..Default::default()
        }
    }

    /// Creates flags with the integrity_failed bit set.
    #[must_use]
    pub fn integrity_failed() -> Self {
        Self {
            integrity_failed: true,
            ..Default::default()
        }
    }

    /// Creates flags for sender-originated TLVs per RFC 8972.
    ///
    /// Per RFC 8972, the Session-Sender initializes all flags to 0.
    /// The Session-Reflector may modify these flags based on processing results.
    #[must_use]
    pub fn for_sender() -> Self {
        Self::default() // U=0, M=0, I=0
    }
}

/// TLV type identifiers as defined in RFC 8972 Section 4.3.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum TlvType {
    /// Reserved type (0).
    Reserved = 0,
    /// Extra Padding TLV (1) - Can carry SSID in first 2 bytes.
    ExtraPadding = 1,
    /// Location TLV (2).
    Location = 2,
    /// Timestamp Information TLV (3).
    TimestampInfo = 3,
    /// Class of Service TLV (4).
    ClassOfService = 4,
    /// Direct Measurement TLV (5).
    DirectMeasurement = 5,
    /// Access Report TLV (6).
    AccessReport = 6,
    /// Follow-Up Telemetry TLV (7).
    FollowUpTelemetry = 7,
    /// HMAC TLV (8) - Must be last in the TLV list.
    Hmac = 8,
    /// Destination Node Address TLV (9) - RFC 9503 §4.
    DestinationNodeAddress = 9,
    /// Return Path TLV (10) - RFC 9503 §5.
    ReturnPath = 10,
    /// Micro-session ID TLV (11) - RFC 9534 §3.1.
    MicroSessionId = 11,
    /// Unknown type (12-255).
    Unknown(u8),
}

impl TlvType {
    /// Creates a TlvType from a byte value.
    #[must_use]
    pub fn from_byte(byte: u8) -> Self {
        match byte {
            0 => Self::Reserved,
            1 => Self::ExtraPadding,
            2 => Self::Location,
            3 => Self::TimestampInfo,
            4 => Self::ClassOfService,
            5 => Self::DirectMeasurement,
            6 => Self::AccessReport,
            7 => Self::FollowUpTelemetry,
            8 => Self::Hmac,
            9 => Self::DestinationNodeAddress,
            10 => Self::ReturnPath,
            11 => Self::MicroSessionId,
            n => Self::Unknown(n),
        }
    }

    /// Converts the type to a byte value.
    #[must_use]
    pub fn to_byte(self) -> u8 {
        match self {
            Self::Reserved => 0,
            Self::ExtraPadding => 1,
            Self::Location => 2,
            Self::TimestampInfo => 3,
            Self::ClassOfService => 4,
            Self::DirectMeasurement => 5,
            Self::AccessReport => 6,
            Self::FollowUpTelemetry => 7,
            Self::Hmac => 8,
            Self::DestinationNodeAddress => 9,
            Self::ReturnPath => 10,
            Self::MicroSessionId => 11,
            Self::Unknown(n) => n,
        }
    }

    /// Returns true if this is the HMAC TLV type.
    #[must_use]
    pub fn is_hmac(self) -> bool {
        matches!(self, Self::Hmac)
    }

    /// Returns true if this is a known/recognized type.
    #[must_use]
    pub fn is_recognized(self) -> bool {
        !matches!(self, Self::Unknown(_) | Self::Reserved)
    }
}

/// A raw TLV with unparsed value bytes.
///
/// This is the basic building block for TLV parsing and serialization.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawTlv {
    /// TLV flags.
    pub flags: TlvFlags,
    /// TLV type.
    pub tlv_type: TlvType,
    /// Raw value bytes.
    pub value: Vec<u8>,
    /// Original wire length for truncated TLVs (when different from value.len()).
    /// Used to echo malformed TLVs byte-exactly per RFC 8972 §4.8.
    wire_length: Option<u16>,
}

impl RawTlv {
    /// Creates a new RawTlv with the given type and value.
    ///
    /// Flags are initialized to 0 (U=0, M=0, I=0) per RFC 8972 for sender use.
    #[must_use]
    pub fn new(tlv_type: TlvType, value: Vec<u8>) -> Self {
        Self {
            flags: TlvFlags::for_sender(),
            tlv_type,
            value,
            wire_length: None,
        }
    }

    /// Creates a new RawTlv with explicit flags.
    #[must_use]
    pub fn with_flags(flags: TlvFlags, tlv_type: TlvType, value: Vec<u8>) -> Self {
        Self {
            flags,
            tlv_type,
            value,
            wire_length: None,
        }
    }

    /// Parses a single TLV from the beginning of the buffer.
    ///
    /// Returns the parsed TLV and the number of bytes consumed.
    ///
    /// Wire format per RFC 8972 Section 4.2:
    /// - Byte 0: Flags (1 octet)
    /// - Byte 1: Type (1 octet)
    /// - Bytes 2-3: Length (2 octets, big-endian)
    /// - Bytes 4+: Value
    ///
    /// # Errors
    /// Returns an error if the buffer is too small or the TLV is malformed.
    pub fn parse(buf: &[u8]) -> Result<(Self, usize), TlvError> {
        if buf.len() < TLV_HEADER_SIZE {
            return Err(TlvError::BufferTooSmall(buf.len()));
        }

        let flags = TlvFlags::from_byte(buf[0]);
        let tlv_type = TlvType::from_byte(buf[1]);
        let length = u16::from_be_bytes([buf[2], buf[3]]) as usize;

        let total_size = TLV_HEADER_SIZE + length;
        if buf.len() < total_size {
            return Err(TlvError::LengthExceedsBuffer {
                length,
                available: buf.len() - TLV_HEADER_SIZE,
            });
        }

        let value = buf[TLV_HEADER_SIZE..total_size].to_vec();

        Ok((
            Self {
                flags,
                tlv_type,
                value,
                wire_length: None,
            },
            total_size,
        ))
    }

    /// Parses a single TLV leniently, marking truncated TLVs as malformed.
    ///
    /// Unlike `parse()`, this method handles truncated TLVs by:
    /// - Taking whatever value bytes are available (up to declared length)
    /// - Setting the M-flag (malformed) on the TLV
    /// - Consuming all remaining bytes
    ///
    /// Returns the parsed TLV, bytes consumed, and whether the TLV was malformed.
    ///
    /// # Errors
    /// Returns an error only if the buffer is too small for even a TLV header.
    pub fn parse_lenient(buf: &[u8]) -> Result<(Self, usize, bool), TlvError> {
        if buf.len() < TLV_HEADER_SIZE {
            return Err(TlvError::BufferTooSmall(buf.len()));
        }

        let mut flags = TlvFlags::from_byte(buf[0]);
        let tlv_type = TlvType::from_byte(buf[1]);
        let declared_length = u16::from_be_bytes([buf[2], buf[3]]) as usize;
        let available = buf.len() - TLV_HEADER_SIZE;

        let (value, wire_length, consumed, malformed) = if declared_length <= available {
            let value = buf[TLV_HEADER_SIZE..TLV_HEADER_SIZE + declared_length].to_vec();
            (value, None, TLV_HEADER_SIZE + declared_length, false)
        } else {
            flags.malformed = true;
            let value = buf[TLV_HEADER_SIZE..].to_vec();
            let original_length = Some(declared_length as u16);
            (value, original_length, buf.len(), true)
        };

        Ok((
            Self {
                flags,
                tlv_type,
                value,
                wire_length,
            },
            consumed,
            malformed,
        ))
    }

    /// Serializes the TLV to bytes.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(self.wire_size());
        self.write_to(&mut buf);
        buf
    }

    /// Writes the TLV to the provided buffer without allocating.
    #[inline]
    pub fn write_to(&self, buf: &mut Vec<u8>) {
        let length = self.wire_length.unwrap_or(self.value.len() as u16);
        buf.push(self.flags.to_byte());
        buf.push(self.tlv_type.to_byte());
        buf.extend_from_slice(&length.to_be_bytes());
        buf.extend_from_slice(&self.value);
    }

    /// Returns the total size of this TLV when serialized (header + value).
    #[must_use]
    pub fn wire_size(&self) -> usize {
        TLV_HEADER_SIZE + self.value.len()
    }

    /// Returns true if this TLV has the unrecognized flag set.
    #[must_use]
    pub fn is_unrecognized(&self) -> bool {
        self.flags.unrecognized
    }

    /// Returns true if this TLV has the malformed flag set.
    #[must_use]
    pub fn is_malformed(&self) -> bool {
        self.flags.malformed
    }

    /// Returns true if this TLV has the integrity_failed flag set.
    #[must_use]
    pub fn is_integrity_failed(&self) -> bool {
        self.flags.integrity_failed
    }

    /// Sets the unrecognized flag (U-flag).
    pub fn set_unrecognized(&mut self) {
        self.flags.unrecognized = true;
    }

    /// Sets the malformed flag (M-flag).
    pub fn set_malformed(&mut self) {
        self.flags.malformed = true;
    }

    /// Sets the integrity_failed flag (I-flag).
    pub fn set_integrity_failed(&mut self) {
        self.flags.integrity_failed = true;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tlv_flags_from_byte() {
        let flags = TlvFlags::from_byte(0xE0);
        assert!(flags.unrecognized);
        assert!(flags.malformed);
        assert!(flags.integrity_failed);

        let flags = TlvFlags::from_byte(0x80);
        assert!(flags.unrecognized);
        assert!(!flags.malformed);
        assert!(!flags.integrity_failed);

        let flags = TlvFlags::from_byte(0x40);
        assert!(!flags.unrecognized);
        assert!(flags.malformed);
        assert!(!flags.integrity_failed);

        let flags = TlvFlags::from_byte(0x20);
        assert!(!flags.unrecognized);
        assert!(!flags.malformed);
        assert!(flags.integrity_failed);

        let flags = TlvFlags::from_byte(0x00);
        assert!(!flags.unrecognized);
        assert!(!flags.malformed);
        assert!(!flags.integrity_failed);
    }

    #[test]
    fn test_tlv_flags_to_byte() {
        let flags = TlvFlags {
            unrecognized: true,
            malformed: false,
            integrity_failed: true,
        };
        assert_eq!(flags.to_byte(), 0xA0);

        let flags = TlvFlags::default();
        assert_eq!(flags.to_byte(), 0x00);

        let flags = TlvFlags {
            unrecognized: true,
            malformed: true,
            integrity_failed: true,
        };
        assert_eq!(flags.to_byte(), 0xE0);
    }

    #[test]
    fn test_tlv_flags_roundtrip() {
        for u in [false, true] {
            for m in [false, true] {
                for i in [false, true] {
                    let original = TlvFlags {
                        unrecognized: u,
                        malformed: m,
                        integrity_failed: i,
                    };
                    let byte = original.to_byte();
                    let parsed = TlvFlags::from_byte(byte);
                    assert_eq!(original, parsed);
                }
            }
        }
    }

    #[test]
    fn test_tlv_type_from_byte() {
        assert_eq!(TlvType::from_byte(0), TlvType::Reserved);
        assert_eq!(TlvType::from_byte(1), TlvType::ExtraPadding);
        assert_eq!(TlvType::from_byte(8), TlvType::Hmac);
        assert_eq!(TlvType::from_byte(9), TlvType::DestinationNodeAddress);
        assert_eq!(TlvType::from_byte(10), TlvType::ReturnPath);
        assert_eq!(TlvType::from_byte(15), TlvType::Unknown(15));
        assert_eq!(TlvType::from_byte(200), TlvType::Unknown(200));
    }

    #[test]
    fn test_tlv_type_to_byte() {
        assert_eq!(TlvType::Reserved.to_byte(), 0);
        assert_eq!(TlvType::ExtraPadding.to_byte(), 1);
        assert_eq!(TlvType::Hmac.to_byte(), 8);
        assert_eq!(TlvType::DestinationNodeAddress.to_byte(), 9);
        assert_eq!(TlvType::ReturnPath.to_byte(), 10);
        assert_eq!(TlvType::Unknown(200).to_byte(), 200);
    }

    #[test]
    fn test_tlv_type_is_recognized() {
        assert!(TlvType::ExtraPadding.is_recognized());
        assert!(TlvType::Hmac.is_recognized());
        assert!(!TlvType::Reserved.is_recognized());
        assert!(!TlvType::Unknown(99).is_recognized());
    }

    #[test]
    fn test_raw_tlv_new() {
        let tlv = RawTlv::new(TlvType::ExtraPadding, vec![0x01, 0x02]);
        assert_eq!(tlv.tlv_type, TlvType::ExtraPadding);
        assert_eq!(tlv.value, vec![0x01, 0x02]);
        assert_eq!(tlv.flags.to_byte(), 0);
    }

    #[test]
    fn test_raw_tlv_to_bytes() {
        let tlv = RawTlv::new(TlvType::ExtraPadding, vec![0xAB, 0xCD]);
        let bytes = tlv.to_bytes();
        assert_eq!(bytes[0], 0x00);
        assert_eq!(bytes[1], 0x01);
        assert_eq!(bytes[2], 0x00);
        assert_eq!(bytes[3], 0x02);
        assert_eq!(&bytes[4..], &[0xAB, 0xCD]);
    }

    #[test]
    fn test_raw_tlv_to_bytes_with_flags() {
        let tlv = RawTlv::with_flags(
            TlvFlags::unrecognized(),
            TlvType::Location,
            vec![0x11, 0x22],
        );
        let bytes = tlv.to_bytes();
        assert_eq!(bytes[0], 0x80);
        assert_eq!(bytes[1], 0x02);
        assert_eq!(bytes[2], 0x00);
        assert_eq!(bytes[3], 0x02);
        assert_eq!(&bytes[4..], &[0x11, 0x22]);
    }

    #[test]
    fn test_raw_tlv_parse() {
        let data = [0x00, 0x01, 0x00, 0x02, 0xAB, 0xCD];
        let (tlv, consumed) = RawTlv::parse(&data).unwrap();
        assert_eq!(consumed, 6);
        assert_eq!(tlv.tlv_type, TlvType::ExtraPadding);
        assert_eq!(tlv.value, vec![0xAB, 0xCD]);
        assert!(!tlv.flags.unrecognized);
    }

    #[test]
    fn test_raw_tlv_parse_with_flags() {
        let data = [0x80, 0x01, 0x00, 0x01, 0xFF];
        let (tlv, consumed) = RawTlv::parse(&data).unwrap();
        assert_eq!(consumed, 5);
        assert!(tlv.flags.unrecognized);
        assert_eq!(tlv.tlv_type, TlvType::ExtraPadding);
        assert_eq!(tlv.value, vec![0xFF]);
    }

    #[test]
    fn test_raw_tlv_roundtrip() {
        let original = RawTlv::with_flags(
            TlvFlags::unrecognized(),
            TlvType::Location,
            vec![1, 2, 3, 4, 5],
        );
        let bytes = original.to_bytes();
        let (parsed, _) = RawTlv::parse(&bytes).unwrap();
        assert_eq!(original, parsed);
    }

    #[test]
    fn test_raw_tlv_parse_buffer_too_small() {
        let data = [0x00, 0x01];
        let result = RawTlv::parse(&data);
        assert!(matches!(result, Err(TlvError::BufferTooSmall(2))));
    }

    #[test]
    fn test_raw_tlv_parse_length_exceeds_buffer() {
        let data = [0x00, 0x01, 0x00, 0x10];
        let result = RawTlv::parse(&data);
        assert!(matches!(
            result,
            Err(TlvError::LengthExceedsBuffer {
                length: 16,
                available: 0
            })
        ));
    }

    #[test]
    fn test_raw_tlv_wire_size() {
        let tlv = RawTlv::new(TlvType::ExtraPadding, vec![0; 10]);
        assert_eq!(tlv.wire_size(), TLV_HEADER_SIZE + 10);
    }

    #[test]
    fn test_tlv_flags_for_sender() {
        let flags = TlvFlags::for_sender();
        assert!(!flags.unrecognized);
        assert!(!flags.malformed);
        assert!(!flags.integrity_failed);
        assert_eq!(flags.to_byte(), 0x00);
    }

    #[test]
    fn test_raw_tlv_flag_setters() {
        let mut tlv = RawTlv::new(TlvType::ExtraPadding, vec![]);
        assert!(!tlv.is_unrecognized());
        assert!(!tlv.is_malformed());
        assert!(!tlv.is_integrity_failed());

        tlv.set_unrecognized();
        assert!(tlv.is_unrecognized());
        tlv.set_malformed();
        assert!(tlv.is_malformed());
        tlv.set_integrity_failed();
        assert!(tlv.is_integrity_failed());
        assert_eq!(tlv.flags.to_byte(), 0xE0);
    }

    #[test]
    fn test_truncated_tlv_preserves_wire_length() {
        let mut buf = Vec::new();
        buf.push(0x00);
        buf.push(0x02);
        buf.extend_from_slice(&100u16.to_be_bytes());
        buf.extend_from_slice(&[0xAA; 10]);

        let (tlv, consumed, malformed) = RawTlv::parse_lenient(&buf).unwrap();
        assert!(malformed);
        assert!(tlv.is_malformed());
        assert_eq!(consumed, 14);
        assert_eq!(tlv.value.len(), 10);

        let output = tlv.to_bytes();
        assert_eq!(output[0], 0x40);
        assert_eq!(output[1], 0x02);
        assert_eq!(u16::from_be_bytes([output[2], output[3]]), 100);
        assert_eq!(&output[4..], &[0xAA; 10]);
    }

    #[test]
    fn test_normal_tlv_uses_value_length() {
        let mut buf = Vec::new();
        buf.push(0x00);
        buf.push(0x02);
        buf.extend_from_slice(&10u16.to_be_bytes());
        buf.extend_from_slice(&[0xBB; 10]);

        let (tlv, consumed, malformed) = RawTlv::parse_lenient(&buf).unwrap();
        assert!(!malformed);
        assert!(!tlv.is_malformed());
        assert_eq!(consumed, 14);
        assert_eq!(tlv.value.len(), 10);

        let output = tlv.to_bytes();
        assert_eq!(output[0], 0x00);
        assert_eq!(output[1], 0x02);
        assert_eq!(u16::from_be_bytes([output[2], output[3]]), 10);
        assert_eq!(&output[4..], &[0xBB; 10]);
    }
}
