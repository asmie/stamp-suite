//! TLV (Type-Length-Value) extension support per RFC 8972 Section 4.
//!
//! This module provides structures and functions for parsing and serializing
//! STAMP TLV extensions, enabling optional features like Session-Sender Identifier,
//! timestamps, telemetry, and HMAC for TLV integrity.
//!
//! # TLV Wire Format (RFC 8972 Section 4.2)
//!
//! ```text
//!  0                   1                   2                   3
//!  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |STAMP TLV Flags|     Type      |            Length             |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                         Value...                              |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! ```
//!
//! - **Flags (1 octet)**: U=Unrecognized, M=Malformed, I=Integrity failed, Reserved
//! - **Type (1 octet)**: TLV type identifier (0-255)
//! - **Length (2 octets)**: Length of Value field in bytes
//! - **Value**: Variable-length data (may be 0 bytes)
//!
//! # Flags Format
//!
//! ```text
//!  0 1 2 3 4 5 6 7
//! +-+-+-+-+-+-+-+-+
//! |U|M|I|R|R|R|R|R|
//! +-+-+-+-+-+-+-+-+
//! ```

use thiserror::Error;

use crate::crypto::HmacKey;

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
    /// Unknown type (11-255).
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

        // Byte 0: Flags (1 octet)
        let flags = TlvFlags::from_byte(buf[0]);

        // Byte 1: Type (1 octet)
        let tlv_type = TlvType::from_byte(buf[1]);

        // Bytes 2-3: Length (2 octets, big-endian)
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

        // Byte 0: Flags (1 octet)
        let mut flags = TlvFlags::from_byte(buf[0]);

        // Byte 1: Type (1 octet)
        let tlv_type = TlvType::from_byte(buf[1]);

        // Bytes 2-3: Length (2 octets, big-endian)
        let declared_length = u16::from_be_bytes([buf[2], buf[3]]) as usize;
        let available = buf.len() - TLV_HEADER_SIZE;

        let (value, wire_length, consumed, malformed) = if declared_length <= available {
            // Normal case: full value available
            let value = buf[TLV_HEADER_SIZE..TLV_HEADER_SIZE + declared_length].to_vec();
            (value, None, TLV_HEADER_SIZE + declared_length, false)
        } else {
            // Truncated: take what's available, mark as malformed, and preserve original wire length
            // for byte-exact echo per RFC 8972 §4.8
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
    ///
    /// Wire format per RFC 8972 Section 4.2:
    /// - Byte 0: Flags (1 octet)
    /// - Byte 1: Type (1 octet)
    /// - Bytes 2-3: Length (2 octets, big-endian)
    /// - Bytes 4+: Value
    ///
    /// For truncated TLVs (where `wire_length` is set), the original declared length
    /// is used in the Length field to produce a byte-exact echo per RFC 8972 §4.8.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(self.wire_size());
        self.write_to(&mut buf);
        buf
    }

    /// Writes the TLV to the provided buffer without allocating.
    ///
    /// This is more efficient than `to_bytes()` when building larger messages.
    #[inline]
    pub fn write_to(&self, buf: &mut Vec<u8>) {
        // Use preserved wire length for truncated TLVs, otherwise actual value length
        let length = self.wire_length.unwrap_or(self.value.len() as u16);

        // Byte 0: Flags (1 octet)
        buf.push(self.flags.to_byte());

        // Byte 1: Type (1 octet)
        buf.push(self.tlv_type.to_byte());

        // Bytes 2-3: Length (2 octets, big-endian)
        buf.extend_from_slice(&length.to_be_bytes());

        // Value (only the bytes we actually have)
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
    ///
    /// Per RFC 8972, set by the reflector when the TLV type is not recognized.
    pub fn set_unrecognized(&mut self) {
        self.flags.unrecognized = true;
    }

    /// Sets the malformed flag (M-flag).
    ///
    /// Per RFC 8972, set by the reflector when the TLV structure is invalid.
    pub fn set_malformed(&mut self) {
        self.flags.malformed = true;
    }

    /// Sets the integrity_failed flag (I-flag).
    ///
    /// Per RFC 8972, set by the reflector when HMAC verification fails for this TLV.
    pub fn set_integrity_failed(&mut self) {
        self.flags.integrity_failed = true;
    }
}

/// A list of TLVs with special handling for HMAC TLV.
///
/// Per RFC 8972, the HMAC TLV must always be the last TLV in the list.
/// For failure echo paths, wire order is preserved to comply with RFC 8972 §4.8.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TlvList {
    /// The TLVs in the list (excluding HMAC).
    tlvs: Vec<RawTlv>,
    /// Optional HMAC TLV (always serialized last in normal mode).
    hmac_tlv: Option<RawTlv>,
    /// All TLVs in original wire order (used for failure echo per RFC 8972 §4.8).
    /// When set, `to_bytes()` will use this order instead of the separated fields.
    wire_order_tlvs: Option<Vec<RawTlv>>,
}

impl TlvList {
    /// Creates a new empty TlvList.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns true if the list is empty (no TLVs including HMAC).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        if let Some(ref wire_order) = self.wire_order_tlvs {
            wire_order.is_empty()
        } else {
            self.tlvs.is_empty() && self.hmac_tlv.is_none()
        }
    }

    /// Returns the number of TLVs (including HMAC if present).
    #[must_use]
    pub fn len(&self) -> usize {
        if let Some(ref wire_order) = self.wire_order_tlvs {
            wire_order.len()
        } else {
            self.tlvs.len() + usize::from(self.hmac_tlv.is_some())
        }
    }

    /// Returns true if using wire-order preservation mode (for failure echo).
    #[must_use]
    pub fn is_wire_order_mode(&self) -> bool {
        self.wire_order_tlvs.is_some()
    }

    /// Adds a TLV to the list.
    ///
    /// HMAC TLVs are stored separately to ensure they're serialized last.
    ///
    /// # Errors
    /// Returns an error if trying to add multiple HMAC TLVs.
    pub fn push(&mut self, tlv: RawTlv) -> Result<(), TlvError> {
        if tlv.tlv_type.is_hmac() {
            if self.hmac_tlv.is_some() {
                return Err(TlvError::MultipleHmacTlvs);
            }
            self.hmac_tlv = Some(tlv);
        } else {
            self.tlvs.push(tlv);
        }
        Ok(())
    }

    /// Returns an iterator over all TLVs (non-HMAC first, then HMAC).
    pub fn iter(&self) -> impl Iterator<Item = &RawTlv> {
        self.tlvs.iter().chain(self.hmac_tlv.iter())
    }

    /// Returns a reference to the HMAC TLV if present.
    #[must_use]
    pub fn hmac_tlv(&self) -> Option<&RawTlv> {
        self.hmac_tlv.as_ref()
    }

    /// Returns the non-HMAC TLVs.
    #[must_use]
    pub fn non_hmac_tlvs(&self) -> &[RawTlv] {
        &self.tlvs
    }

    /// Parses a TLV list from a buffer.
    ///
    /// # Errors
    /// Returns an error if parsing fails or HMAC TLV is not last.
    pub fn parse(buf: &[u8]) -> Result<Self, TlvError> {
        let mut list = Self::new();
        let mut offset = 0;
        let mut found_hmac = false;

        while offset < buf.len() {
            // Check if remaining buffer is too small for a TLV header
            if buf.len() - offset < TLV_HEADER_SIZE {
                // Remaining bytes might be padding, stop parsing
                break;
            }

            let (tlv, consumed) = RawTlv::parse(&buf[offset..])?;

            // Check HMAC positioning
            if found_hmac {
                // Found a TLV after HMAC - this is an error
                return Err(TlvError::HmacNotLast);
            }

            if tlv.tlv_type.is_hmac() {
                found_hmac = true;
                if tlv.value.len() != HMAC_TLV_VALUE_SIZE {
                    return Err(TlvError::InvalidHmacLength(tlv.value.len()));
                }
            }

            list.push(tlv)?;
            offset += consumed;
        }

        Ok(list)
    }

    /// Parses a TLV list leniently, marking malformed TLVs with M-flag.
    ///
    /// Unlike `parse()`, this method:
    /// - Handles truncated TLVs by marking them as malformed (M-flag)
    /// - Continues parsing after recoverable errors
    /// - Does not fail on HMAC length mismatch (marks as malformed instead)
    /// - Preserves wire order for RFC 8972 §4.8 "copy all TLVs" compliance
    ///
    /// Use this for reflector mode where we want to echo TLVs with appropriate
    /// flags rather than failing completely.
    ///
    /// # Returns
    /// A tuple of (TlvList, bool) where the bool indicates if any TLV was malformed.
    pub fn parse_lenient(buf: &[u8]) -> (Self, bool) {
        // Parse TLVs into a temporary Vec first to avoid cloning in the common case.
        // Only if there are issues requiring wire-order preservation do we need
        // to keep both the wire-order Vec and the separated fields.
        let mut parsed_tlvs: Vec<RawTlv> = Vec::new();
        let mut offset = 0;
        let mut found_hmac = false;
        let mut any_malformed = false;
        let mut has_multiple_hmac = false;

        while offset < buf.len() {
            // Check if remaining buffer is too small for a TLV header
            if buf.len() - offset < TLV_HEADER_SIZE {
                // Remaining bytes are padding, stop parsing
                break;
            }

            // Check for trailing zero-padding: if the TLV header is all zeros AND all remaining
            // bytes are zeros, treat as padding and stop parsing. This handles the case where
            // reflector in "ignore" mode pads the response with zeros to maintain symmetric
            // packet size.
            //
            // We cannot treat *any* all-zero header as padding because a Reserved TLV (type=0)
            // with zero-length value is valid on the wire and has an all-zero header.
            // Only if the entire remaining buffer is zeros do we know it's padding.
            let header = &buf[offset..offset + TLV_HEADER_SIZE];
            if header == [0, 0, 0, 0] && buf[offset..].iter().all(|&b| b == 0) {
                // Trailing zeros indicate padding, not a real TLV
                break;
            }

            match RawTlv::parse_lenient(&buf[offset..]) {
                Ok((mut tlv, consumed, malformed)) => {
                    if malformed {
                        any_malformed = true;
                    }

                    // Check HMAC positioning - if we found HMAC already, mark subsequent as malformed
                    if found_hmac {
                        tlv.set_malformed();
                        any_malformed = true;
                    }

                    // Handle HMAC TLV
                    if tlv.tlv_type.is_hmac() {
                        if found_hmac {
                            // Multiple HMAC TLVs - mark for wire-order preservation
                            has_multiple_hmac = true;
                        }
                        found_hmac = true;
                        // Mark HMAC as malformed if wrong length
                        if tlv.value.len() != HMAC_TLV_VALUE_SIZE {
                            tlv.set_malformed();
                            any_malformed = true;
                        }
                    }

                    parsed_tlvs.push(tlv);
                    offset += consumed;

                    // If this TLV was truncated, we can't continue (don't know where next starts)
                    if malformed {
                        break;
                    }
                }
                Err(_) => {
                    // Can't even parse header - stop
                    break;
                }
            }
        }

        let need_wire_order = any_malformed || has_multiple_hmac;

        // Build the TlvList from parsed TLVs
        let mut list = Self::new();

        if need_wire_order {
            // Clone TLVs into separated fields while keeping wire order
            for tlv in &parsed_tlvs {
                if tlv.tlv_type.is_hmac() {
                    list.hmac_tlv = Some(tlv.clone());
                } else {
                    list.tlvs.push(tlv.clone());
                }
            }
            list.wire_order_tlvs = Some(parsed_tlvs);
        } else {
            // No issues: move TLVs directly into separated fields (no cloning)
            for tlv in parsed_tlvs {
                if tlv.tlv_type.is_hmac() {
                    list.hmac_tlv = Some(tlv);
                } else {
                    list.tlvs.push(tlv);
                }
            }
        }

        (list, any_malformed)
    }

    /// Serializes the TLV list to bytes.
    ///
    /// If wire-order mode is active (from lenient parsing with issues),
    /// TLVs are serialized in their original wire order per RFC 8972 §4.8.
    /// Otherwise, HMAC TLV is always serialized last per RFC 8972.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(self.wire_size());
        self.write_to(&mut buf);
        buf
    }

    /// Writes the TLV list to the provided buffer without allocating.
    ///
    /// This is more efficient than `to_bytes()` when building larger messages.
    #[inline]
    pub fn write_to(&self, buf: &mut Vec<u8>) {
        // Use wire-order if available (for failure echo)
        if let Some(ref wire_order) = self.wire_order_tlvs {
            for tlv in wire_order {
                tlv.write_to(buf);
            }
            return;
        }

        // Normal mode: non-HMAC TLVs first, HMAC last
        for tlv in &self.tlvs {
            tlv.write_to(buf);
        }

        if let Some(ref hmac) = self.hmac_tlv {
            hmac.write_to(buf);
        }
    }

    /// Returns the total wire size of all TLVs.
    #[must_use]
    pub fn wire_size(&self) -> usize {
        self.iter().map(|t| t.wire_size()).sum()
    }

    /// Builds the HMAC input data per RFC 8972 §4.8.
    ///
    /// The HMAC covers: Sequence Number (first 4 bytes) + preceding TLVs (non-HMAC).
    fn build_hmac_input(&self, sequence_number_bytes: &[u8], tlv_bytes: &[u8]) -> Vec<u8> {
        let non_hmac_size: usize = self.tlvs.iter().map(|t| t.wire_size()).sum();

        let mut data = Vec::with_capacity(4 + non_hmac_size);

        // Append sequence number (up to 4 bytes)
        if sequence_number_bytes.len() >= 4 {
            data.extend_from_slice(&sequence_number_bytes[..4]);
        } else {
            data.extend_from_slice(sequence_number_bytes);
        }

        // Append preceding TLVs (non-HMAC portion of TLV bytes)
        if non_hmac_size <= tlv_bytes.len() {
            data.extend_from_slice(&tlv_bytes[..non_hmac_size]);
        }

        data
    }

    /// Extracts the expected HMAC bytes from the HMAC TLV value.
    ///
    /// # Errors
    /// Returns `TlvError::InvalidHmacLength` if the value is not exactly 16 bytes.
    fn extract_hmac_bytes(hmac_tlv: &RawTlv) -> Result<[u8; 16], TlvError> {
        hmac_tlv
            .value
            .as_slice()
            .try_into()
            .map_err(|_| TlvError::InvalidHmacLength(hmac_tlv.value.len()))
    }

    /// Verifies the HMAC TLV if present per RFC 8972 §4.8.
    ///
    /// The HMAC covers the Sequence Number field (first 4 bytes) plus all preceding TLVs.
    ///
    /// # Arguments
    /// * `key` - The HMAC key
    /// * `sequence_number_bytes` - The 4-byte sequence number field from base packet
    /// * `tlv_bytes` - The raw TLV bytes (for recomputing HMAC)
    ///
    /// # Errors
    /// Returns an error if HMAC verification fails.
    pub fn verify_hmac(
        &self,
        key: &HmacKey,
        sequence_number_bytes: &[u8],
        tlv_bytes: &[u8],
    ) -> Result<(), TlvError> {
        let Some(hmac_tlv) = &self.hmac_tlv else {
            return Ok(()); // No HMAC to verify
        };

        let data = self.build_hmac_input(sequence_number_bytes, tlv_bytes);
        let expected = Self::extract_hmac_bytes(hmac_tlv)?;

        if key.verify(&data, &expected) {
            Ok(())
        } else {
            Err(TlvError::HmacVerificationFailed)
        }
    }

    /// Verifies HMAC and marks ALL TLVs with I-flag on failure per RFC 8972 §4.8.
    ///
    /// Per RFC 8972 §4.8, when HMAC verification fails, the Session-Reflector must:
    /// 1. Stop processing the received packet
    /// 2. Copy all TLVs into the reflected packet
    /// 3. Set I-flag to 1 in EACH TLV before transmission
    ///
    /// # Arguments
    /// * `key` - The HMAC key
    /// * `sequence_number_bytes` - The 4-byte sequence number field from base packet
    /// * `tlv_bytes` - The raw TLV bytes
    ///
    /// # Returns
    /// `true` if HMAC verification passed (or no HMAC present), `false` if failed.
    pub fn verify_hmac_and_mark(
        &mut self,
        key: &HmacKey,
        sequence_number_bytes: &[u8],
        tlv_bytes: &[u8],
    ) -> bool {
        let Some(hmac_tlv) = &self.hmac_tlv else {
            return true; // No HMAC to verify
        };

        let data = self.build_hmac_input(sequence_number_bytes, tlv_bytes);

        let Ok(expected) = Self::extract_hmac_bytes(hmac_tlv) else {
            // Invalid HMAC length - mark ALL TLVs with I-flag per RFC 8972 §4.8
            self.mark_all_integrity_failed();
            return false;
        };

        if key.verify(&data, &expected) {
            true
        } else {
            // HMAC verification failed - set I-flag on ALL TLVs per RFC 8972 §4.8
            self.mark_all_integrity_failed();
            false
        }
    }

    /// Marks ALL TLVs (including HMAC) with I-flag per RFC 8972 §4.8.
    ///
    /// Called when HMAC verification fails. The reflector must set I-flag
    /// on each TLV before transmission.
    pub fn mark_all_integrity_failed(&mut self) {
        // Mark separated fields
        for tlv in &mut self.tlvs {
            tlv.set_integrity_failed();
        }
        if let Some(ref mut hmac) = self.hmac_tlv {
            hmac.set_integrity_failed();
        }

        // Also mark wire-order TLVs if present (for failure echo path)
        if let Some(ref mut wire_order) = self.wire_order_tlvs {
            for tlv in wire_order {
                tlv.set_integrity_failed();
            }
        }
    }

    /// Returns true if the TLV list contains only Extra Padding TLVs.
    ///
    /// Per RFC 8972, packets containing only Extra Padding TLVs may be
    /// exempt from HMAC TLV requirements in some implementations.
    #[must_use]
    pub fn contains_only_extra_padding(&self) -> bool {
        // If there's an HMAC TLV, this is not "only extra padding"
        if self.hmac_tlv.is_some() {
            return false;
        }
        // All non-HMAC TLVs must be Extra Padding
        !self.tlvs.is_empty()
            && self
                .tlvs
                .iter()
                .all(|t| t.tlv_type == TlvType::ExtraPadding)
    }

    /// Counts TLVs with each error flag type (U, M, I).
    ///
    /// Returns a tuple of (unrecognized_count, malformed_count, integrity_failed_count).
    /// Useful for metrics recording after applying reflector flags.
    #[must_use]
    pub fn count_error_flags(&self) -> (usize, usize, usize) {
        let mut unrecognized = 0;
        let mut malformed = 0;
        let mut integrity_failed = 0;

        for tlv in &self.tlvs {
            if tlv.is_unrecognized() {
                unrecognized += 1;
            }
            if tlv.is_malformed() {
                malformed += 1;
            }
            if tlv.is_integrity_failed() {
                integrity_failed += 1;
            }
        }

        // Also check HMAC TLV if present
        if let Some(ref hmac) = self.hmac_tlv {
            if hmac.is_unrecognized() {
                unrecognized += 1;
            }
            if hmac.is_malformed() {
                malformed += 1;
            }
            if hmac.is_integrity_failed() {
                integrity_failed += 1;
            }
        }

        (unrecognized, malformed, integrity_failed)
    }

    /// Computes and sets the HMAC TLV per RFC 8972 §4.8.
    ///
    /// The HMAC covers the Sequence Number field (first 4 bytes of base packet)
    /// plus all preceding TLVs, NOT the entire base packet.
    ///
    /// Replaces any existing HMAC TLV.
    ///
    /// # Arguments
    /// * `key` - The HMAC key
    /// * `sequence_number_bytes` - The 4-byte sequence number field from base packet
    pub fn set_hmac(&mut self, key: &HmacKey, sequence_number_bytes: &[u8]) {
        // Per RFC 8972 §4.8: HMAC covers Sequence Number field + preceding TLVs
        // Pre-calculate size to avoid reallocations
        let tlvs_size: usize = self.tlvs.iter().map(|t| t.wire_size()).sum();
        let mut data = Vec::with_capacity(4 + tlvs_size);

        // Sequence Number field (first 4 bytes)
        if sequence_number_bytes.len() >= 4 {
            data.extend_from_slice(&sequence_number_bytes[..4]);
        } else {
            data.extend_from_slice(sequence_number_bytes);
        }

        // All preceding TLVs (non-HMAC) - write directly without intermediate allocations
        for tlv in &self.tlvs {
            tlv.write_to(&mut data);
        }

        let hmac = key.compute(&data);
        self.hmac_tlv = Some(RawTlv::new(TlvType::Hmac, hmac.to_vec()));
    }

    /// Marks unrecognized TLV types with the U flag.
    ///
    /// Per RFC 8972 Section 4.2, the Session-Reflector sets the U-flag
    /// when it receives a TLV type that it does not recognize.
    /// This allows the Session-Sender to know which TLVs were not processed.
    pub fn mark_unrecognized_types(&mut self) {
        // Mark separated fields
        for tlv in &mut self.tlvs {
            if !tlv.tlv_type.is_recognized() {
                tlv.set_unrecognized();
            }
        }

        // Also mark wire-order TLVs if present (for failure echo path)
        if let Some(ref mut wire_order) = self.wire_order_tlvs {
            for tlv in wire_order {
                if !tlv.tlv_type.is_recognized() {
                    tlv.set_unrecognized();
                }
            }
        }
    }

    /// Applies all reflector-side flag updates per RFC 8972.
    ///
    /// This method:
    /// 1. Marks unrecognized TLV types with U-flag
    /// 2. Optionally verifies HMAC and marks ALL TLVs with I-flag on failure
    /// 3. Optionally requires HMAC TLV for strict RFC 8972 authenticated mode
    ///
    /// Per RFC 8972 §4.8, on HMAC verification failure, the reflector must
    /// set I-flag on ALL TLVs, not just the HMAC TLV.
    ///
    /// # Arguments
    /// * `hmac_key` - Optional HMAC key for verification
    /// * `sequence_number_bytes` - The 4-byte sequence number from base packet
    /// * `tlv_bytes` - The raw TLV bytes
    ///
    /// # Returns
    /// `true` if HMAC verification passed (or no key/HMAC), `false` if failed.
    pub fn apply_reflector_flags(
        &mut self,
        hmac_key: Option<&HmacKey>,
        sequence_number_bytes: &[u8],
        tlv_bytes: &[u8],
    ) -> bool {
        self.apply_reflector_flags_strict(hmac_key, sequence_number_bytes, tlv_bytes, false)
    }

    /// Applies reflector-side flag updates with optional strict HMAC TLV requirement.
    ///
    /// This is the extended version of `apply_reflector_flags` that supports
    /// strict RFC 8972 authenticated mode where HMAC TLV is required.
    ///
    /// # Arguments
    /// * `hmac_key` - Optional HMAC key for verification
    /// * `sequence_number_bytes` - The 4-byte sequence number from base packet
    /// * `tlv_bytes` - The raw TLV bytes
    /// * `require_hmac_tlv` - If true, packets without HMAC TLV are marked with I-flag
    ///   (unless they contain only Extra Padding TLVs, per RFC 8972 special case)
    ///
    /// # Returns
    /// `true` if verification passed, `false` if failed or HMAC TLV missing when required.
    pub fn apply_reflector_flags_strict(
        &mut self,
        hmac_key: Option<&HmacKey>,
        sequence_number_bytes: &[u8],
        tlv_bytes: &[u8],
        require_hmac_tlv: bool,
    ) -> bool {
        // Mark unrecognized types with U-flag
        self.mark_unrecognized_types();

        // Validate known TLV types for correct value sizes (sets M-flag on mismatches)
        self.validate_known_tlv_lengths();

        // If we have an HMAC key, verify the HMAC TLV
        if let Some(key) = hmac_key {
            // Check for missing HMAC TLV in strict mode
            if require_hmac_tlv && self.hmac_tlv.is_none() {
                // Exception: packets containing only Extra Padding TLVs
                // may be exempt per RFC 8972 implementation flexibility
                if !self.contains_only_extra_padding() {
                    // Missing HMAC TLV in authenticated TLV packet - mark all with I-flag
                    self.mark_all_integrity_failed();
                    return false;
                }
                // Extra-padding-only case: allow without HMAC
                return true;
            }

            // Verify HMAC if present - marks ALL TLVs with I-flag on failure
            self.verify_hmac_and_mark(key, sequence_number_bytes, tlv_bytes)
        } else {
            // No key available — if HMAC TLV is present, we cannot verify integrity.
            // Per RFC 8972 §4.8: set I-flag on ALL TLVs (not just the HMAC TLV)
            // and treat as verification failure.
            if self.hmac_tlv.is_some() {
                self.mark_all_integrity_failed();
                false
            } else {
                true // No HMAC TLV present, nothing to verify
            }
        }
    }

    /// Extracts the requested DSCP1/ECN1 from the first CoS TLV if present.
    ///
    /// Returns `Some((dscp1, ecn1))` if a CoS TLV is found and valid.
    #[must_use]
    pub fn get_cos_request(&self) -> Option<(u8, u8)> {
        for tlv in &self.tlvs {
            if tlv.tlv_type == TlvType::ClassOfService {
                if let Ok(cos) = ClassOfServiceTlv::from_raw(tlv) {
                    return Some((cos.dscp1, cos.ecn1));
                }
            }
        }
        None
    }

    /// Updates any Class of Service TLVs with the received DSCP/ECN values.
    ///
    /// Per RFC 8972 §5.2, the Session-Reflector fills in DSCP2 and ECN2 fields
    /// with the values received at its ingress before reflecting the packet.
    ///
    /// Updates bytes in-place to avoid allocation overhead. The CoS TLV layout:
    /// - Byte 0: DSCP1 (6 bits) | ECN1 (2 bits) - preserved
    /// - Byte 1: DSCP2 (6 bits) | ECN2 (2 bits) - updated
    /// - Byte 2: RP (2 bits) | Reserved (6 bits) - RP updated if policy_rejected
    /// - Byte 3: Reserved - preserved
    ///
    /// # Arguments
    /// * `received_dscp` - DSCP value received at reflector's ingress (6 bits, 0-63)
    /// * `received_ecn` - ECN value received at reflector's ingress (2 bits, 0-3)
    /// * `policy_rejected` - True if local policy rejected the requested DSCP1
    pub fn update_cos_tlvs(&mut self, received_dscp: u8, received_ecn: u8, policy_rejected: bool) {
        // Update in separated tlvs list
        for tlv in &mut self.tlvs {
            if tlv.tlv_type == TlvType::ClassOfService && tlv.value.len() == COS_TLV_VALUE_SIZE {
                Self::update_cos_value_in_place(
                    &mut tlv.value,
                    received_dscp,
                    received_ecn,
                    policy_rejected,
                );
            }
        }

        // Also update wire-order TLVs if present (for failure echo path)
        if let Some(ref mut wire_order) = self.wire_order_tlvs {
            for tlv in wire_order {
                if tlv.tlv_type == TlvType::ClassOfService && tlv.value.len() == COS_TLV_VALUE_SIZE
                {
                    Self::update_cos_value_in_place(
                        &mut tlv.value,
                        received_dscp,
                        received_ecn,
                        policy_rejected,
                    );
                }
            }
        }
    }

    /// Updates CoS TLV value bytes in-place.
    ///
    /// Modifies DSCP2/ECN2/RP fields without allocating a new value buffer.
    /// Assumes value is exactly `COS_TLV_VALUE_SIZE` (4) bytes.
    #[inline]
    fn update_cos_value_in_place(
        value: &mut [u8],
        received_dscp: u8,
        received_ecn: u8,
        policy_rejected: bool,
    ) {
        // Byte 1: DSCP2 (6 bits) | ECN2 (2 bits)
        value[1] = ((received_dscp & 0x3F) << 2) | (received_ecn & 0x03);

        // Byte 2: RP (2 bits) | Reserved (6 bits) - preserve reserved bits
        let rp_bits = if policy_rejected { 0x40 } else { 0x00 }; // RP=1 in bits 7-6
        value[2] = rp_bits | (value[2] & 0x3F);
    }

    /// Updates Timestamp Information TLVs with the reflector's sync source and method.
    ///
    /// Per RFC 8972 §4.3, the Session-Reflector fills `sync_src_out` and `timestamp_out`
    /// (bytes 2-3 of the value) with its own clock information.
    pub fn update_timestamp_info_tlvs(&mut self, sync_src: SyncSource, ts_method: TimestampMethod) {
        for tlv in &mut self.tlvs {
            if tlv.tlv_type == TlvType::TimestampInfo
                && tlv.value.len() == TIMESTAMP_INFO_TLV_VALUE_SIZE
            {
                tlv.value[2] = sync_src.to_byte();
                tlv.value[3] = ts_method.to_byte();
            }
        }

        if let Some(ref mut wire_order) = self.wire_order_tlvs {
            for tlv in wire_order {
                if tlv.tlv_type == TlvType::TimestampInfo
                    && tlv.value.len() == TIMESTAMP_INFO_TLV_VALUE_SIZE
                {
                    tlv.value[2] = sync_src.to_byte();
                    tlv.value[3] = ts_method.to_byte();
                }
            }
        }
    }

    /// Updates Direct Measurement TLVs with the reflector's packet counters.
    ///
    /// Per RFC 8972 §4.5, the Session-Reflector fills `R_RxC` and `R_TxC`
    /// (bytes 4-11 of the value) while preserving `S_TxC` (bytes 0-3).
    pub fn update_direct_measurement_tlvs(&mut self, rx_count: u32, tx_count: u32) {
        let rx_bytes = rx_count.to_be_bytes();
        let tx_bytes = tx_count.to_be_bytes();

        for tlv in &mut self.tlvs {
            if tlv.tlv_type == TlvType::DirectMeasurement
                && tlv.value.len() == DIRECT_MEASUREMENT_TLV_VALUE_SIZE
            {
                tlv.value[4..8].copy_from_slice(&rx_bytes);
                tlv.value[8..12].copy_from_slice(&tx_bytes);
            }
        }

        if let Some(ref mut wire_order) = self.wire_order_tlvs {
            for tlv in wire_order {
                if tlv.tlv_type == TlvType::DirectMeasurement
                    && tlv.value.len() == DIRECT_MEASUREMENT_TLV_VALUE_SIZE
                {
                    tlv.value[4..8].copy_from_slice(&rx_bytes);
                    tlv.value[8..12].copy_from_slice(&tx_bytes);
                }
            }
        }
    }

    /// Updates Location TLVs with the observed packet address information.
    ///
    /// Per RFC 8972 §4.2, the Session-Reflector fills in the ports and adds
    /// sub-TLVs for the source and destination IP addresses it observed.
    pub fn update_location_tlvs(&mut self, info: &PacketAddressInfo) {
        for tlv in &mut self.tlvs {
            if tlv.tlv_type == TlvType::Location && tlv.value.len() >= LOCATION_TLV_MIN_VALUE_SIZE {
                Self::update_location_value_in_place(&mut tlv.value, info);
            }
        }

        if let Some(ref mut wire_order) = self.wire_order_tlvs {
            for tlv in wire_order {
                if tlv.tlv_type == TlvType::Location
                    && tlv.value.len() >= LOCATION_TLV_MIN_VALUE_SIZE
                {
                    Self::update_location_value_in_place(&mut tlv.value, info);
                }
            }
        }
    }

    /// Updates Location TLV value with address information.
    ///
    /// Replaces the entire value with ports and address sub-TLVs.
    fn update_location_value_in_place(value: &mut Vec<u8>, info: &PacketAddressInfo) {
        value.clear();
        // Dest port and src port
        value.extend_from_slice(&info.dst_port.to_be_bytes());
        value.extend_from_slice(&info.src_port.to_be_bytes());
        // Add source address sub-TLV
        match info.src_addr {
            std::net::IpAddr::V4(addr) => {
                let sub = LocationSubTlv::new(LocationSubType::Ipv4Src, addr.octets().to_vec());
                value.extend_from_slice(&sub.to_bytes());
            }
            std::net::IpAddr::V6(addr) => {
                let sub = LocationSubTlv::new(LocationSubType::Ipv6Src, addr.octets().to_vec());
                value.extend_from_slice(&sub.to_bytes());
            }
        }
        // Add destination address sub-TLV
        match info.dst_addr {
            std::net::IpAddr::V4(addr) => {
                let sub = LocationSubTlv::new(LocationSubType::Ipv4Dst, addr.octets().to_vec());
                value.extend_from_slice(&sub.to_bytes());
            }
            std::net::IpAddr::V6(addr) => {
                let sub = LocationSubTlv::new(LocationSubType::Ipv6Dst, addr.octets().to_vec());
                value.extend_from_slice(&sub.to_bytes());
            }
        }
    }

    /// Updates Follow-Up Telemetry TLVs with the last reflection data.
    ///
    /// Per RFC 8972 §4.7, the Session-Reflector fills in the sequence number
    /// and timestamp from its previous reflection.
    pub fn update_follow_up_telemetry_tlvs(
        &mut self,
        last_seq: u32,
        last_ts: u64,
        mode: TimestampMethod,
    ) {
        let seq_bytes = last_seq.to_be_bytes();
        let ts_bytes = last_ts.to_be_bytes();
        let mode_byte = mode.to_byte();

        for tlv in &mut self.tlvs {
            if tlv.tlv_type == TlvType::FollowUpTelemetry
                && tlv.value.len() == FOLLOW_UP_TELEMETRY_TLV_VALUE_SIZE
            {
                tlv.value[0..4].copy_from_slice(&seq_bytes);
                tlv.value[4..12].copy_from_slice(&ts_bytes);
                tlv.value[12] = mode_byte;
                tlv.value[13..16].fill(0); // Reserved
            }
        }

        if let Some(ref mut wire_order) = self.wire_order_tlvs {
            for tlv in wire_order {
                if tlv.tlv_type == TlvType::FollowUpTelemetry
                    && tlv.value.len() == FOLLOW_UP_TELEMETRY_TLV_VALUE_SIZE
                {
                    tlv.value[0..4].copy_from_slice(&seq_bytes);
                    tlv.value[4..12].copy_from_slice(&ts_bytes);
                    tlv.value[12] = mode_byte;
                    tlv.value[13..16].fill(0); // Reserved
                }
            }
        }
    }

    /// Validates known TLV types for correct value sizes and sets M-flag on mismatches.
    ///
    /// Per RFC 8972, the Session-Reflector sets the M (malformed) flag when a
    /// recognized TLV type has an incorrect value length.
    pub fn validate_known_tlv_lengths(&mut self) {
        for tlv in &mut self.tlvs {
            let malformed = match tlv.tlv_type {
                TlvType::ClassOfService => tlv.value.len() != COS_TLV_VALUE_SIZE,
                TlvType::AccessReport => tlv.value.len() != ACCESS_REPORT_TLV_VALUE_SIZE,
                TlvType::TimestampInfo => tlv.value.len() != TIMESTAMP_INFO_TLV_VALUE_SIZE,
                TlvType::DirectMeasurement => tlv.value.len() != DIRECT_MEASUREMENT_TLV_VALUE_SIZE,
                TlvType::Location => tlv.value.len() < LOCATION_TLV_MIN_VALUE_SIZE,
                TlvType::FollowUpTelemetry => tlv.value.len() != FOLLOW_UP_TELEMETRY_TLV_VALUE_SIZE,
                TlvType::DestinationNodeAddress => {
                    tlv.value.len() != DEST_NODE_ADDR_IPV4_SIZE
                        && tlv.value.len() != DEST_NODE_ADDR_IPV6_SIZE
                }
                TlvType::ReturnPath => tlv.value.len() < TLV_HEADER_SIZE,
                _ => false,
            };
            if malformed {
                tlv.set_malformed();
            }
        }

        if let Some(ref mut wire_order) = self.wire_order_tlvs {
            for tlv in wire_order {
                let malformed = match tlv.tlv_type {
                    TlvType::ClassOfService => tlv.value.len() != COS_TLV_VALUE_SIZE,
                    TlvType::AccessReport => tlv.value.len() != ACCESS_REPORT_TLV_VALUE_SIZE,
                    TlvType::TimestampInfo => tlv.value.len() != TIMESTAMP_INFO_TLV_VALUE_SIZE,
                    TlvType::DirectMeasurement => {
                        tlv.value.len() != DIRECT_MEASUREMENT_TLV_VALUE_SIZE
                    }
                    TlvType::Location => tlv.value.len() < LOCATION_TLV_MIN_VALUE_SIZE,
                    TlvType::FollowUpTelemetry => {
                        tlv.value.len() != FOLLOW_UP_TELEMETRY_TLV_VALUE_SIZE
                    }
                    TlvType::DestinationNodeAddress => {
                        tlv.value.len() != DEST_NODE_ADDR_IPV4_SIZE
                            && tlv.value.len() != DEST_NODE_ADDR_IPV6_SIZE
                    }
                    TlvType::ReturnPath => tlv.value.len() < TLV_HEADER_SIZE,
                    _ => false,
                };
                if malformed {
                    tlv.set_malformed();
                }
            }
        }
    }
}

/// Extra Padding TLV (Type 1) with optional Session-Sender Identifier.
///
/// The first 2 bytes of the value can carry the SSID.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtraPaddingTlv {
    /// Optional Session-Sender Identifier (first 2 bytes).
    pub ssid: Option<u16>,
    /// Additional padding bytes after SSID.
    pub padding: Vec<u8>,
}

impl ExtraPaddingTlv {
    /// Creates an Extra Padding TLV with just padding.
    #[must_use]
    pub fn new(padding_size: usize) -> Self {
        Self {
            ssid: None,
            padding: vec![0u8; padding_size],
        }
    }

    /// Creates an Extra Padding TLV with an SSID.
    #[must_use]
    pub fn with_ssid(ssid: u16, additional_padding: usize) -> Self {
        Self {
            ssid: Some(ssid),
            padding: vec![0u8; additional_padding],
        }
    }

    /// Parses an Extra Padding TLV from a RawTlv.
    #[must_use]
    pub fn from_raw(raw: &RawTlv) -> Self {
        if raw.value.len() >= 2 {
            let ssid = u16::from_be_bytes([raw.value[0], raw.value[1]]);
            // Only treat as SSID if non-zero
            if ssid != 0 {
                Self {
                    ssid: Some(ssid),
                    padding: raw.value[2..].to_vec(),
                }
            } else {
                Self {
                    ssid: None,
                    padding: raw.value.clone(),
                }
            }
        } else {
            Self {
                ssid: None,
                padding: raw.value.clone(),
            }
        }
    }

    /// Converts to a RawTlv.
    #[must_use]
    pub fn to_raw(&self) -> RawTlv {
        let mut value = Vec::new();
        if let Some(ssid) = self.ssid {
            value.extend_from_slice(&ssid.to_be_bytes());
        }
        value.extend_from_slice(&self.padding);
        RawTlv::new(TlvType::ExtraPadding, value)
    }
}

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
        if raw.value.len() != HMAC_TLV_VALUE_SIZE {
            return Err(TlvError::InvalidHmacLength(raw.value.len()));
        }
        let mut hmac = [0u8; 16];
        hmac.copy_from_slice(&raw.value);
        Ok(Self { hmac })
    }

    /// Converts to a RawTlv.
    #[must_use]
    pub fn to_raw(&self) -> RawTlv {
        RawTlv::new(TlvType::Hmac, self.hmac.to_vec())
    }
}

/// Session-Sender Identifier encoded in Extra Padding TLV.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionSenderId(pub u16);

impl SessionSenderId {
    /// Creates a new Session-Sender ID.
    #[must_use]
    pub fn new(id: u16) -> Self {
        Self(id)
    }

    /// Returns the ID value.
    #[must_use]
    pub fn value(self) -> u16 {
        self.0
    }

    /// Creates an Extra Padding TLV containing this SSID.
    #[must_use]
    pub fn to_extra_padding_tlv(self, additional_padding: usize) -> ExtraPaddingTlv {
        ExtraPaddingTlv::with_ssid(self.0, additional_padding)
    }
}

/// Class of Service TLV (Type 4) for DSCP/ECN measurement per RFC 8972 §4.4.
///
/// Enables measurement of DSCP and ECN field manipulation by middleboxes.
///
/// # Wire Format
///
/// ```text
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |   DSCP1   |ECN|   DSCP2   |EC2| RP|        Reserved           |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ClassOfServiceTlv {
    /// DSCP value intended for reflected packet (6 bits, 0-63).
    /// Set by Session-Sender to indicate desired DSCP for the return path.
    pub dscp1: u8,
    /// ECN value intended for reflected packet (2 bits, 0-3).
    /// Set by Session-Sender to indicate desired ECN for the return path.
    pub ecn1: u8,
    /// DSCP value received at Session-Reflector's ingress (6 bits, 0-63).
    /// Filled in by Session-Reflector to report received DSCP.
    pub dscp2: u8,
    /// ECN value received at Session-Reflector's ingress (2 bits, 0-3).
    /// Filled in by Session-Reflector to report received ECN.
    pub ecn2: u8,
    /// Reverse Path flag (2 bits).
    /// - 0: Session-Reflector applied DSCP1 to reflected packet
    /// - 1: Session-Reflector's policy rejected DSCP1, used received DSCP instead
    pub rp: u8,
}

impl ClassOfServiceTlv {
    /// Creates a new CoS TLV for the sender (DSCP2/ECN2/RP are zero).
    #[must_use]
    pub fn new(dscp: u8, ecn: u8) -> Self {
        Self {
            dscp1: dscp & 0x3F, // 6 bits max
            ecn1: ecn & 0x03,   // 2 bits max
            dscp2: 0,
            ecn2: 0,
            rp: 0,
        }
    }

    /// Creates a CoS TLV for the reflector response.
    ///
    /// # Arguments
    /// * `dscp1` - Original DSCP1 from sender's request
    /// * `ecn1` - Original ECN1 from sender's request
    /// * `received_dscp` - DSCP value received at reflector's ingress
    /// * `received_ecn` - ECN value received at reflector's ingress
    /// * `policy_rejected` - True if local policy rejected DSCP1
    #[must_use]
    pub fn for_response(
        dscp1: u8,
        ecn1: u8,
        received_dscp: u8,
        received_ecn: u8,
        policy_rejected: bool,
    ) -> Self {
        Self {
            dscp1: dscp1 & 0x3F,
            ecn1: ecn1 & 0x03,
            dscp2: received_dscp & 0x3F,
            ecn2: received_ecn & 0x03,
            rp: if policy_rejected { 1 } else { 0 },
        }
    }

    /// Parses a CoS TLV from a RawTlv.
    ///
    /// # Errors
    /// Returns an error if the value is not 4 bytes.
    pub fn from_raw(raw: &RawTlv) -> Result<Self, TlvError> {
        if raw.value.len() != COS_TLV_VALUE_SIZE {
            return Err(TlvError::InvalidCosLength(raw.value.len()));
        }

        // Byte 0: DSCP1 (6 bits) | ECN1 (2 bits)
        let dscp1 = (raw.value[0] >> 2) & 0x3F;
        let ecn1 = raw.value[0] & 0x03;

        // Byte 1: DSCP2 (6 bits) | ECN2 (2 bits)
        let dscp2 = (raw.value[1] >> 2) & 0x3F;
        let ecn2 = raw.value[1] & 0x03;

        // Byte 2: RP (2 bits) | Reserved (6 bits)
        let rp = (raw.value[2] >> 6) & 0x03;

        Ok(Self {
            dscp1,
            ecn1,
            dscp2,
            ecn2,
            rp,
        })
    }

    /// Converts to a RawTlv.
    #[must_use]
    pub fn to_raw(&self) -> RawTlv {
        let mut value = [0u8; COS_TLV_VALUE_SIZE];

        // Byte 0: DSCP1 (6 bits) | ECN1 (2 bits)
        value[0] = ((self.dscp1 & 0x3F) << 2) | (self.ecn1 & 0x03);

        // Byte 1: DSCP2 (6 bits) | ECN2 (2 bits)
        value[1] = ((self.dscp2 & 0x3F) << 2) | (self.ecn2 & 0x03);

        // Byte 2: RP (2 bits) | Reserved (6 bits)
        value[2] = (self.rp & 0x03) << 6;

        // Byte 3: Reserved
        value[3] = 0;

        RawTlv::new(TlvType::ClassOfService, value.to_vec())
    }

    /// Returns true if the reflector's policy rejected the requested DSCP.
    #[must_use]
    pub fn policy_rejected(&self) -> bool {
        self.rp != 0
    }

    /// Returns the DSCP value that should be used for the reflected packet.
    ///
    /// Returns DSCP1 if policy allows, or DSCP2 (received) if policy rejected.
    #[must_use]
    pub fn effective_dscp(&self, policy_rejected: bool) -> u8 {
        if policy_rejected {
            self.dscp2
        } else {
            self.dscp1
        }
    }
}

/// Access Report TLV (Type 6) per RFC 8972 §4.6.
///
/// Carries an Access Identifier and Return Code. The reflector echoes this TLV
/// unchanged; structured parsing provides validation.
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

    /// Parses an Access Report TLV from a RawTlv.
    ///
    /// # Errors
    /// Returns an error if the value is not 2 bytes.
    pub fn from_raw(raw: &RawTlv) -> Result<Self, TlvError> {
        if raw.value.len() != ACCESS_REPORT_TLV_VALUE_SIZE {
            return Err(TlvError::InvalidAccessReportLength(raw.value.len()));
        }
        let access_id = (raw.value[0] >> 4) & 0x0F;
        let return_code = raw.value[1];
        Ok(Self {
            access_id,
            return_code,
        })
    }

    /// Converts to a RawTlv.
    #[must_use]
    pub fn to_raw(&self) -> RawTlv {
        let mut value = [0u8; ACCESS_REPORT_TLV_VALUE_SIZE];
        value[0] = (self.access_id & 0x0F) << 4;
        value[1] = self.return_code;
        RawTlv::new(TlvType::AccessReport, value.to_vec())
    }
}

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
/// Carries synchronization source and timestamp method for both
/// the sender (in) and reflector (out) directions.
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
    ///
    /// The sender fills the in-fields with its own values and zeros out-fields.
    #[must_use]
    pub fn new(sync_src: SyncSource, ts_method: TimestampMethod) -> Self {
        Self {
            sync_src_in: sync_src,
            timestamp_in: ts_method,
            sync_src_out: SyncSource::Unknown(0),
            timestamp_out: TimestampMethod::Unknown(0),
        }
    }

    /// Parses a Timestamp Info TLV from a RawTlv.
    ///
    /// # Errors
    /// Returns an error if the value is not 4 bytes.
    pub fn from_raw(raw: &RawTlv) -> Result<Self, TlvError> {
        if raw.value.len() != TIMESTAMP_INFO_TLV_VALUE_SIZE {
            return Err(TlvError::InvalidTimestampInfoLength(raw.value.len()));
        }
        Ok(Self {
            sync_src_in: SyncSource::from_byte(raw.value[0]),
            timestamp_in: TimestampMethod::from_byte(raw.value[1]),
            sync_src_out: SyncSource::from_byte(raw.value[2]),
            timestamp_out: TimestampMethod::from_byte(raw.value[3]),
        })
    }

    /// Converts to a RawTlv.
    #[must_use]
    pub fn to_raw(&self) -> RawTlv {
        let value = vec![
            self.sync_src_in.to_byte(),
            self.timestamp_in.to_byte(),
            self.sync_src_out.to_byte(),
            self.timestamp_out.to_byte(),
        ];
        RawTlv::new(TlvType::TimestampInfo, value)
    }
}

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

    /// Parses a Direct Measurement TLV from a RawTlv.
    ///
    /// # Errors
    /// Returns an error if the value is not 12 bytes.
    pub fn from_raw(raw: &RawTlv) -> Result<Self, TlvError> {
        if raw.value.len() != DIRECT_MEASUREMENT_TLV_VALUE_SIZE {
            return Err(TlvError::InvalidDirectMeasurementLength(raw.value.len()));
        }
        let sender_tx_count =
            u32::from_be_bytes([raw.value[0], raw.value[1], raw.value[2], raw.value[3]]);
        let reflector_rx_count =
            u32::from_be_bytes([raw.value[4], raw.value[5], raw.value[6], raw.value[7]]);
        let reflector_tx_count =
            u32::from_be_bytes([raw.value[8], raw.value[9], raw.value[10], raw.value[11]]);
        Ok(Self {
            sender_tx_count,
            reflector_rx_count,
            reflector_tx_count,
        })
    }

    /// Converts to a RawTlv.
    #[must_use]
    pub fn to_raw(&self) -> RawTlv {
        let mut value = Vec::with_capacity(DIRECT_MEASUREMENT_TLV_VALUE_SIZE);
        value.extend_from_slice(&self.sender_tx_count.to_be_bytes());
        value.extend_from_slice(&self.reflector_rx_count.to_be_bytes());
        value.extend_from_slice(&self.reflector_tx_count.to_be_bytes());
        RawTlv::new(TlvType::DirectMeasurement, value)
    }
}

/// Location sub-TLV types per RFC 8972 §4.2.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum LocationSubType {
    /// IPv4 source address (4 bytes).
    Ipv4Src = 1,
    /// IPv4 destination address (4 bytes).
    Ipv4Dst = 2,
    /// IPv6 source address (16 bytes).
    Ipv6Src = 3,
    /// IPv6 destination address (16 bytes).
    Ipv6Dst = 4,
    /// Autonomous System Number (4 bytes).
    Asn = 5,
    /// Interface name (variable).
    IfName = 6,
    /// Interface index (4 bytes).
    IfIndex = 7,
    /// MPLS label stack (variable).
    MplsLabel = 8,
    /// Segment Routing SID (variable).
    SrSid = 9,
    /// Unknown sub-type.
    Unknown(u8),
}

impl LocationSubType {
    /// Creates a LocationSubType from a byte value.
    #[must_use]
    pub fn from_byte(byte: u8) -> Self {
        match byte {
            1 => Self::Ipv4Src,
            2 => Self::Ipv4Dst,
            3 => Self::Ipv6Src,
            4 => Self::Ipv6Dst,
            5 => Self::Asn,
            6 => Self::IfName,
            7 => Self::IfIndex,
            8 => Self::MplsLabel,
            9 => Self::SrSid,
            n => Self::Unknown(n),
        }
    }

    /// Converts to a byte value.
    #[must_use]
    pub fn to_byte(self) -> u8 {
        match self {
            Self::Ipv4Src => 1,
            Self::Ipv4Dst => 2,
            Self::Ipv6Src => 3,
            Self::Ipv6Dst => 4,
            Self::Asn => 5,
            Self::IfName => 6,
            Self::IfIndex => 7,
            Self::MplsLabel => 8,
            Self::SrSid => 9,
            Self::Unknown(n) => n,
        }
    }
}

/// A single location sub-TLV within the Location TLV.
///
/// # Wire Format
///
/// ```text
///  0         1         2         3
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |   Sub-Type    |    Length      |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |            Value ...           |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocationSubTlv {
    /// Sub-TLV type.
    pub sub_type: LocationSubType,
    /// Sub-TLV value.
    pub value: Vec<u8>,
}

impl LocationSubTlv {
    /// Creates a new location sub-TLV.
    #[must_use]
    pub fn new(sub_type: LocationSubType, value: Vec<u8>) -> Self {
        Self { sub_type, value }
    }

    /// Serializes the sub-TLV to bytes.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(2 + self.value.len());
        buf.push(self.sub_type.to_byte());
        buf.push(self.value.len() as u8);
        buf.extend_from_slice(&self.value);
        buf
    }

    /// Parses a sub-TLV from a byte slice.
    ///
    /// Returns the parsed sub-TLV and bytes consumed, or None if buffer is too small.
    #[must_use]
    pub fn parse(buf: &[u8]) -> Option<(Self, usize)> {
        if buf.len() < 2 {
            return None;
        }
        let sub_type = LocationSubType::from_byte(buf[0]);
        let length = buf[1] as usize;
        if buf.len() < 2 + length {
            return None;
        }
        let value = buf[2..2 + length].to_vec();
        Some((Self { sub_type, value }, 2 + length))
    }
}

/// Location TLV (Type 2) per RFC 8972 §4.2.
///
/// Carries source/destination ports and sub-TLVs for addresses.
/// The reflector fills in its observed ports and addresses.
///
/// # Wire Format
///
/// ```text
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |         Dest Port             |         Source Port            |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |         Sub-TLVs ...                                          |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocationTlv {
    /// Destination port.
    pub dest_port: u16,
    /// Source port.
    pub src_port: u16,
    /// Sub-TLVs containing address information.
    pub sub_tlvs: Vec<LocationSubTlv>,
}

impl LocationTlv {
    /// Creates a new empty Location TLV (sender requests reflector to fill).
    #[must_use]
    pub fn new() -> Self {
        Self {
            dest_port: 0,
            src_port: 0,
            sub_tlvs: Vec::new(),
        }
    }

    /// Parses a Location TLV from a RawTlv.
    ///
    /// # Errors
    /// Returns an error if the value is shorter than 4 bytes (ports).
    pub fn from_raw(raw: &RawTlv) -> Result<Self, TlvError> {
        if raw.value.len() < LOCATION_TLV_MIN_VALUE_SIZE {
            return Err(TlvError::InvalidLocationLength(raw.value.len()));
        }
        let dest_port = u16::from_be_bytes([raw.value[0], raw.value[1]]);
        let src_port = u16::from_be_bytes([raw.value[2], raw.value[3]]);

        let mut sub_tlvs = Vec::new();
        let mut offset = 4;
        while offset < raw.value.len() {
            if let Some((sub, consumed)) = LocationSubTlv::parse(&raw.value[offset..]) {
                sub_tlvs.push(sub);
                offset += consumed;
            } else {
                break;
            }
        }

        Ok(Self {
            dest_port,
            src_port,
            sub_tlvs,
        })
    }

    /// Converts to a RawTlv.
    #[must_use]
    pub fn to_raw(&self) -> RawTlv {
        let mut value = Vec::new();
        value.extend_from_slice(&self.dest_port.to_be_bytes());
        value.extend_from_slice(&self.src_port.to_be_bytes());
        for sub in &self.sub_tlvs {
            value.extend_from_slice(&sub.to_bytes());
        }
        RawTlv::new(TlvType::Location, value)
    }
}

impl Default for LocationTlv {
    fn default() -> Self {
        Self::new()
    }
}

/// Packet address information for Location TLV processing.
///
/// Used by the reflector to fill in the Location TLV with observed addresses/ports.
#[derive(Debug, Clone)]
pub struct PacketAddressInfo {
    /// Source IP address of the received packet.
    pub src_addr: std::net::IpAddr,
    /// Source port of the received packet.
    pub src_port: u16,
    /// Destination IP address of the received packet.
    pub dst_addr: std::net::IpAddr,
    /// Destination port of the received packet.
    pub dst_port: u16,
}

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

    /// Parses a Follow-Up Telemetry TLV from a RawTlv.
    ///
    /// # Errors
    /// Returns an error if the value is not 16 bytes.
    pub fn from_raw(raw: &RawTlv) -> Result<Self, TlvError> {
        if raw.value.len() != FOLLOW_UP_TELEMETRY_TLV_VALUE_SIZE {
            return Err(TlvError::InvalidFollowUpTelemetryLength(raw.value.len()));
        }
        let sequence_number =
            u32::from_be_bytes([raw.value[0], raw.value[1], raw.value[2], raw.value[3]]);
        let follow_up_timestamp = u64::from_be_bytes([
            raw.value[4],
            raw.value[5],
            raw.value[6],
            raw.value[7],
            raw.value[8],
            raw.value[9],
            raw.value[10],
            raw.value[11],
        ]);
        let timestamp_mode = TimestampMethod::from_byte(raw.value[12]);
        Ok(Self {
            sequence_number,
            follow_up_timestamp,
            timestamp_mode,
        })
    }

    /// Converts to a RawTlv.
    #[must_use]
    pub fn to_raw(&self) -> RawTlv {
        let mut value = Vec::with_capacity(FOLLOW_UP_TELEMETRY_TLV_VALUE_SIZE);
        value.extend_from_slice(&self.sequence_number.to_be_bytes());
        value.extend_from_slice(&self.follow_up_timestamp.to_be_bytes());
        value.push(self.timestamp_mode.to_byte());
        value.extend_from_slice(&[0u8; 3]); // Reserved
        RawTlv::new(TlvType::FollowUpTelemetry, value)
    }
}

impl Default for FollowUpTelemetryTlv {
    fn default() -> Self {
        Self::new()
    }
}

/// Destination Node Address TLV (Type 9) per RFC 9503 §4.
///
/// The Session-Sender includes this TLV to specify the intended reflector address.
/// The Session-Reflector checks if the address matches one of its local addresses
/// and sets the U-flag if it does not.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DestinationNodeAddressTlv {
    /// The intended destination address.
    pub address: std::net::IpAddr,
}

impl DestinationNodeAddressTlv {
    /// Creates a new Destination Node Address TLV.
    #[must_use]
    pub fn new(address: std::net::IpAddr) -> Self {
        Self { address }
    }

    /// Parses a Destination Node Address TLV from a RawTlv.
    ///
    /// # Errors
    /// Returns an error if the value length is not 4 (IPv4) or 16 (IPv6).
    pub fn from_raw(raw: &RawTlv) -> Result<Self, TlvError> {
        match raw.value.len() {
            DEST_NODE_ADDR_IPV4_SIZE => {
                let addr =
                    std::net::Ipv4Addr::new(raw.value[0], raw.value[1], raw.value[2], raw.value[3]);
                Ok(Self {
                    address: std::net::IpAddr::V4(addr),
                })
            }
            DEST_NODE_ADDR_IPV6_SIZE => {
                let mut octets = [0u8; 16];
                octets.copy_from_slice(&raw.value);
                let addr = std::net::Ipv6Addr::from(octets);
                Ok(Self {
                    address: std::net::IpAddr::V6(addr),
                })
            }
            other => Err(TlvError::InvalidDestinationNodeAddressLength(other)),
        }
    }

    /// Converts to a RawTlv.
    #[must_use]
    pub fn to_raw(&self) -> RawTlv {
        let value = match self.address {
            std::net::IpAddr::V4(addr) => addr.octets().to_vec(),
            std::net::IpAddr::V6(addr) => addr.octets().to_vec(),
        };
        RawTlv::new(TlvType::DestinationNodeAddress, value)
    }
}

/// Return Path sub-TLV type identifiers per RFC 9503 §5.
///
/// Sub-TLVs use the standard 4-byte STAMP TLV header format.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReturnPathSubType {
    /// Control Code sub-TLV (1).
    ControlCode,
    /// Return Address sub-TLV (2).
    ReturnAddress,
    /// SR-MPLS Label Stack sub-TLV (3).
    SrMplsLabelStack,
    /// SRv6 Segment List sub-TLV (4).
    Srv6SegmentList,
    /// Unknown sub-type.
    Unknown(u8),
}

impl ReturnPathSubType {
    /// Creates a ReturnPathSubType from a byte value.
    #[must_use]
    pub fn from_byte(byte: u8) -> Self {
        match byte {
            1 => Self::ControlCode,
            2 => Self::ReturnAddress,
            3 => Self::SrMplsLabelStack,
            4 => Self::Srv6SegmentList,
            n => Self::Unknown(n),
        }
    }

    /// Converts the sub-type to a byte value.
    #[must_use]
    pub fn to_byte(self) -> u8 {
        match self {
            Self::ControlCode => 1,
            Self::ReturnAddress => 2,
            Self::SrMplsLabelStack => 3,
            Self::Srv6SegmentList => 4,
            Self::Unknown(n) => n,
        }
    }
}

/// Return Path TLV (Type 10) per RFC 9503 §5.
///
/// Contains sub-TLVs that specify how the reflector should route its reply.
/// Sub-TLVs use the standard 4-byte STAMP TLV header (Flags | Type | Length×2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReturnPathTlv {
    /// Sub-TLVs within this Return Path TLV.
    pub sub_tlvs: Vec<RawTlv>,
}

impl ReturnPathTlv {
    /// Creates an empty Return Path TLV.
    #[must_use]
    pub fn new() -> Self {
        Self {
            sub_tlvs: Vec::new(),
        }
    }

    /// Creates a Return Path TLV with a Control Code sub-TLV.
    #[must_use]
    pub fn with_control_code(code: u32) -> Self {
        let value = code.to_be_bytes().to_vec();
        let sub = RawTlv::new(
            TlvType::Unknown(ReturnPathSubType::ControlCode.to_byte()),
            value,
        );
        Self {
            sub_tlvs: vec![sub],
        }
    }

    /// Creates a Return Path TLV with a Return Address sub-TLV.
    #[must_use]
    pub fn with_return_address(addr: std::net::IpAddr) -> Self {
        let value = match addr {
            std::net::IpAddr::V4(a) => a.octets().to_vec(),
            std::net::IpAddr::V6(a) => a.octets().to_vec(),
        };
        let sub = RawTlv::new(
            TlvType::Unknown(ReturnPathSubType::ReturnAddress.to_byte()),
            value,
        );
        Self {
            sub_tlvs: vec![sub],
        }
    }

    /// Creates a Return Path TLV with an SR-MPLS Label Stack sub-TLV.
    ///
    /// Each label is a 20-bit MPLS label value, encoded as a proper 4-byte
    /// MPLS Label Stack Entry (LSE): Label(20) | TC(3) | S(1) | TTL(8).
    /// TC is set to 0, TTL to 255, and the S-bit (bottom-of-stack) is set
    /// on the last entry only.
    #[must_use]
    pub fn with_sr_mpls_labels(labels: &[u32]) -> Self {
        let mut value = Vec::with_capacity(labels.len() * 4);
        let last = labels.len().saturating_sub(1);
        for (i, label) in labels.iter().enumerate() {
            let s_bit: u32 = if i == last { 1 } else { 0 };
            let lse = (label << 12) | (s_bit << 8) | 255; // TC=0, TTL=255
            value.extend_from_slice(&lse.to_be_bytes());
        }
        let sub = RawTlv::new(
            TlvType::Unknown(ReturnPathSubType::SrMplsLabelStack.to_byte()),
            value,
        );
        Self {
            sub_tlvs: vec![sub],
        }
    }

    /// Creates a Return Path TLV with an SRv6 Segment List sub-TLV.
    ///
    /// Each SID is encoded as a 16-byte IPv6 address.
    #[must_use]
    pub fn with_srv6_sids(sids: &[std::net::Ipv6Addr]) -> Self {
        let mut value = Vec::with_capacity(sids.len() * 16);
        for sid in sids {
            value.extend_from_slice(&sid.octets());
        }
        let sub = RawTlv::new(
            TlvType::Unknown(ReturnPathSubType::Srv6SegmentList.to_byte()),
            value,
        );
        Self {
            sub_tlvs: vec![sub],
        }
    }

    /// Adds a Return Address sub-TLV to this Return Path TLV.
    pub fn add_return_address(&mut self, addr: std::net::IpAddr) {
        let value = match addr {
            std::net::IpAddr::V4(a) => a.octets().to_vec(),
            std::net::IpAddr::V6(a) => a.octets().to_vec(),
        };
        self.sub_tlvs.push(RawTlv::new(
            TlvType::Unknown(ReturnPathSubType::ReturnAddress.to_byte()),
            value,
        ));
    }

    /// Parses a Return Path TLV from a RawTlv.
    ///
    /// The value is parsed as a sequence of sub-TLVs using the standard 4-byte header.
    ///
    /// # Errors
    /// Returns an error if the value is too short to contain any sub-TLV.
    pub fn from_raw(raw: &RawTlv) -> Result<Self, TlvError> {
        if raw.value.len() < TLV_HEADER_SIZE {
            return Err(TlvError::InvalidReturnPathLength(raw.value.len()));
        }
        let (sub_tlvs_list, _) = TlvList::parse_lenient(&raw.value);
        let mut sub_tlvs = Vec::new();
        for tlv in sub_tlvs_list.non_hmac_tlvs() {
            sub_tlvs.push(tlv.clone());
        }
        if let Some(hmac) = sub_tlvs_list.hmac_tlv() {
            sub_tlvs.push(hmac.clone());
        }
        Ok(Self { sub_tlvs })
    }

    /// Converts to a RawTlv.
    #[must_use]
    pub fn to_raw(&self) -> RawTlv {
        let mut value = Vec::new();
        for sub in &self.sub_tlvs {
            sub.write_to(&mut value);
        }
        RawTlv::new(TlvType::ReturnPath, value)
    }

    /// Returns the Control Code value if a Control Code sub-TLV is present.
    #[must_use]
    pub fn get_control_code(&self) -> Option<u32> {
        for sub in &self.sub_tlvs {
            if sub.tlv_type.to_byte() == ReturnPathSubType::ControlCode.to_byte()
                && sub.value.len() == RETURN_PATH_CONTROL_CODE_SIZE
            {
                return Some(u32::from_be_bytes([
                    sub.value[0],
                    sub.value[1],
                    sub.value[2],
                    sub.value[3],
                ]));
            }
        }
        None
    }

    /// Returns the Return Address if a Return Address sub-TLV is present.
    #[must_use]
    pub fn get_return_address(&self) -> Option<std::net::IpAddr> {
        for sub in &self.sub_tlvs {
            if sub.tlv_type.to_byte() == ReturnPathSubType::ReturnAddress.to_byte() {
                match sub.value.len() {
                    4 => {
                        return Some(std::net::IpAddr::V4(std::net::Ipv4Addr::new(
                            sub.value[0],
                            sub.value[1],
                            sub.value[2],
                            sub.value[3],
                        )));
                    }
                    16 => {
                        let mut octets = [0u8; 16];
                        octets.copy_from_slice(&sub.value);
                        return Some(std::net::IpAddr::V6(std::net::Ipv6Addr::from(octets)));
                    }
                    _ => {}
                }
            }
        }
        None
    }

    /// Returns true if an SR-MPLS Label Stack sub-TLV is present.
    #[must_use]
    pub fn has_sr_mpls(&self) -> bool {
        self.sub_tlvs
            .iter()
            .any(|sub| sub.tlv_type.to_byte() == ReturnPathSubType::SrMplsLabelStack.to_byte())
    }

    /// Returns true if an SRv6 Segment List sub-TLV is present.
    #[must_use]
    pub fn has_srv6(&self) -> bool {
        self.sub_tlvs
            .iter()
            .any(|sub| sub.tlv_type.to_byte() == ReturnPathSubType::Srv6SegmentList.to_byte())
    }
}

impl Default for ReturnPathTlv {
    fn default() -> Self {
        Self::new()
    }
}

/// Action determined by processing a Return Path TLV (RFC 9503 §5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReturnPathAction {
    /// Normal reply (no Return Path TLV, or Control Code 0x1 same-link).
    Normal,
    /// Suppress reply entirely (Control Code 0x0).
    SuppressReply,
    /// Reply to an alternate address (Return Address sub-TLV).
    AlternateAddress(std::net::SocketAddr),
    /// SR forwarding requested but unsupported — echo with U-flag, reply normally.
    UnsupportedSr,
}

impl TlvList {
    /// Processes Destination Node Address TLVs per RFC 9503 §4.
    ///
    /// Finds the first Destination Node Address TLV and checks if the address
    /// matches one of the reflector's local addresses. If not, sets the U-flag.
    ///
    /// Returns `true` if the address matched (or no such TLV was present).
    pub fn process_destination_node_address(&mut self, local_addrs: &[std::net::IpAddr]) -> bool {
        let mut matched = true;

        // Check in separated tlvs
        for tlv in &mut self.tlvs {
            if tlv.tlv_type == TlvType::DestinationNodeAddress {
                if let Ok(dna) = DestinationNodeAddressTlv::from_raw(tlv) {
                    if !local_addrs.contains(&dna.address) {
                        tlv.set_unrecognized();
                        matched = false;
                    }
                }
                break;
            }
        }

        // Also update wire-order TLVs if present
        if !matched {
            if let Some(ref mut wire_order) = self.wire_order_tlvs {
                for tlv in wire_order {
                    if tlv.tlv_type == TlvType::DestinationNodeAddress {
                        tlv.set_unrecognized();
                        break;
                    }
                }
            }
        }

        matched
    }

    /// Processes Return Path TLVs per RFC 9503 §5.
    ///
    /// Finds the first Return Path TLV, parses its sub-TLVs, and determines
    /// the appropriate action for the reflector.
    ///
    /// # Arguments
    /// * `sender_port` - The sender's UDP port (used for alternate address replies)
    pub fn process_return_path(&mut self, sender_port: u16) -> ReturnPathAction {
        // Find the first Return Path TLV
        let rp_idx = self
            .tlvs
            .iter()
            .position(|tlv| tlv.tlv_type == TlvType::ReturnPath);

        let Some(idx) = rp_idx else {
            return ReturnPathAction::Normal;
        };

        let Ok(rp) = ReturnPathTlv::from_raw(&self.tlvs[idx]) else {
            // Parse failed — set U-flag and return Normal
            self.tlvs[idx].set_unrecognized();
            if let Some(ref mut wire_order) = self.wire_order_tlvs {
                for tlv in wire_order.iter_mut() {
                    if tlv.tlv_type == TlvType::ReturnPath {
                        tlv.set_unrecognized();
                        break;
                    }
                }
            }
            return ReturnPathAction::Normal;
        };

        // Check for Control Code sub-TLV
        // RFC 9503: only bit 0 (reply-request) is meaningful; remaining bits are reserved and ignored.
        if let Some(cc) = rp.get_control_code() {
            return if cc & 1 == 0 {
                ReturnPathAction::SuppressReply
            } else {
                ReturnPathAction::Normal // Same-link = normal for userspace UDP
            };
        }

        // Check for Return Address sub-TLV
        if let Some(addr) = rp.get_return_address() {
            return ReturnPathAction::AlternateAddress(std::net::SocketAddr::new(
                addr,
                sender_port,
            ));
        }

        // Check for SR-MPLS or SRv6 — unsupported in userspace
        if rp.has_sr_mpls() || rp.has_srv6() {
            self.set_return_path_u_flag();
            return ReturnPathAction::UnsupportedSr;
        }

        // Empty or unrecognized sub-TLVs — set U-flag, return Normal
        self.set_return_path_u_flag();
        ReturnPathAction::Normal
    }

    /// Sets the U-flag on the Return Path TLV in both separated and wire-order lists.
    fn set_return_path_u_flag(&mut self) {
        for tlv in &mut self.tlvs {
            if tlv.tlv_type == TlvType::ReturnPath {
                tlv.set_unrecognized();
                break;
            }
        }
        if let Some(ref mut wire_order) = self.wire_order_tlvs {
            for tlv in wire_order.iter_mut() {
                if tlv.tlv_type == TlvType::ReturnPath {
                    tlv.set_unrecognized();
                    break;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tlv_flags_from_byte() {
        // All flags set (U=0x80, M=0x40, I=0x20)
        let flags = TlvFlags::from_byte(0xE0);
        assert!(flags.unrecognized);
        assert!(flags.malformed);
        assert!(flags.integrity_failed);

        // Only U flag (0x80)
        let flags = TlvFlags::from_byte(0x80);
        assert!(flags.unrecognized);
        assert!(!flags.malformed);
        assert!(!flags.integrity_failed);

        // Only M flag (0x40)
        let flags = TlvFlags::from_byte(0x40);
        assert!(!flags.unrecognized);
        assert!(flags.malformed);
        assert!(!flags.integrity_failed);

        // Only I flag (0x20)
        let flags = TlvFlags::from_byte(0x20);
        assert!(!flags.unrecognized);
        assert!(!flags.malformed);
        assert!(flags.integrity_failed);

        // No flags
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
        assert_eq!(flags.to_byte(), 0xA0); // U=0x80, I=0x20

        let flags = TlvFlags::default();
        assert_eq!(flags.to_byte(), 0x00);

        let flags = TlvFlags {
            unrecognized: true,
            malformed: true,
            integrity_failed: true,
        };
        assert_eq!(flags.to_byte(), 0xE0); // U=0x80, M=0x40, I=0x20
    }

    #[test]
    fn test_tlv_flags_roundtrip() {
        // Test roundtrip for all flag combinations
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

        // Byte 0: Flags (0x00)
        assert_eq!(bytes[0], 0x00);
        // Byte 1: Type (1 = ExtraPadding)
        assert_eq!(bytes[1], 0x01);
        // Bytes 2-3: Length (2)
        assert_eq!(bytes[2], 0x00);
        assert_eq!(bytes[3], 0x02);
        // Value
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

        // Byte 0: Flags (U=0x80)
        assert_eq!(bytes[0], 0x80);
        // Byte 1: Type (2 = Location)
        assert_eq!(bytes[1], 0x02);
        // Bytes 2-3: Length (2)
        assert_eq!(bytes[2], 0x00);
        assert_eq!(bytes[3], 0x02);
        // Value
        assert_eq!(&bytes[4..], &[0x11, 0x22]);
    }

    #[test]
    fn test_raw_tlv_parse() {
        // ExtraPadding TLV with 2 bytes value
        // Byte 0: Flags=0, Byte 1: Type=1, Bytes 2-3: Length=2, Bytes 4-5: Value
        let data = [0x00, 0x01, 0x00, 0x02, 0xAB, 0xCD];
        let (tlv, consumed) = RawTlv::parse(&data).unwrap();

        assert_eq!(consumed, 6);
        assert_eq!(tlv.tlv_type, TlvType::ExtraPadding);
        assert_eq!(tlv.value, vec![0xAB, 0xCD]);
        assert!(!tlv.flags.unrecognized);
    }

    #[test]
    fn test_raw_tlv_parse_with_flags() {
        // U flag set (0x80), type 1
        // Byte 0: Flags=0x80, Byte 1: Type=1, Bytes 2-3: Length=1, Byte 4: Value
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
        let data = [0x00, 0x01]; // Only 2 bytes, need 4
        let result = RawTlv::parse(&data);
        assert!(matches!(result, Err(TlvError::BufferTooSmall(2))));
    }

    #[test]
    fn test_raw_tlv_parse_length_exceeds_buffer() {
        // Byte 0: Flags=0, Byte 1: Type=1, Bytes 2-3: Length=16 but only 0 value bytes
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
    fn test_tlv_list_empty() {
        let list = TlvList::new();
        assert!(list.is_empty());
        assert_eq!(list.len(), 0);
    }

    #[test]
    fn test_tlv_list_push() {
        let mut list = TlvList::new();
        list.push(RawTlv::new(TlvType::ExtraPadding, vec![0, 0]))
            .unwrap();
        list.push(RawTlv::new(TlvType::Location, vec![1, 2, 3, 4]))
            .unwrap();

        assert_eq!(list.len(), 2);
        assert!(!list.is_empty());
    }

    #[test]
    fn test_tlv_list_hmac_separate() {
        let mut list = TlvList::new();
        list.push(RawTlv::new(TlvType::ExtraPadding, vec![0, 0]))
            .unwrap();
        list.push(RawTlv::new(TlvType::Hmac, vec![0; 16])).unwrap();

        assert_eq!(list.len(), 2);
        assert!(list.hmac_tlv().is_some());
        assert_eq!(list.non_hmac_tlvs().len(), 1);
    }

    #[test]
    fn test_tlv_list_multiple_hmac_error() {
        let mut list = TlvList::new();
        list.push(RawTlv::new(TlvType::Hmac, vec![0; 16])).unwrap();
        let result = list.push(RawTlv::new(TlvType::Hmac, vec![0; 16]));
        assert!(matches!(result, Err(TlvError::MultipleHmacTlvs)));
    }

    #[test]
    fn test_tlv_list_to_bytes_hmac_last() {
        let mut list = TlvList::new();
        // Add HMAC first
        list.push(RawTlv::new(TlvType::Hmac, vec![0xFF; 16]))
            .unwrap();
        // Add other TLV
        list.push(RawTlv::new(TlvType::ExtraPadding, vec![0xAA, 0xBB]))
            .unwrap();

        let bytes = list.to_bytes();

        // ExtraPadding should come first (4 header + 2 value = 6 bytes)
        // Byte 0: Flags, Byte 1: Type
        assert_eq!(bytes[1], 1); // Type 1 = ExtraPadding

        // HMAC should come last
        let hmac_start = 6; // After ExtraPadding TLV
        assert_eq!(bytes[hmac_start + 1], 8); // Type 8 = HMAC
    }

    #[test]
    fn test_tlv_list_parse() {
        // Create bytes for two TLVs using RFC 8972 format:
        // Byte 0: Flags, Byte 1: Type, Bytes 2-3: Length
        let mut bytes = Vec::new();
        // ExtraPadding TLV: Flags=0, Type=1, Length=2, Value=0xAA 0xBB
        bytes.extend_from_slice(&[0x00, 0x01, 0x00, 0x02, 0xAA, 0xBB]);
        // HMAC TLV: Flags=0, Type=8, Length=16, Value=16 bytes of 0xFF
        bytes.extend_from_slice(&[0x00, 0x08, 0x00, 0x10]);
        bytes.extend_from_slice(&[0xFF; 16]);

        let list = TlvList::parse(&bytes).unwrap();

        assert_eq!(list.len(), 2);
        assert!(list.hmac_tlv().is_some());
        assert_eq!(list.non_hmac_tlvs().len(), 1);
    }

    #[test]
    fn test_tlv_list_parse_hmac_not_last_error() {
        // Create bytes with HMAC followed by another TLV
        let mut bytes = Vec::new();
        // HMAC TLV first: Flags=0, Type=8, Length=16
        bytes.extend_from_slice(&[0x00, 0x08, 0x00, 0x10]);
        bytes.extend_from_slice(&[0xFF; 16]);
        // ExtraPadding TLV after: Flags=0, Type=1, Length=2
        bytes.extend_from_slice(&[0x00, 0x01, 0x00, 0x02, 0xAA, 0xBB]);

        let result = TlvList::parse(&bytes);
        assert!(matches!(result, Err(TlvError::HmacNotLast)));
    }

    #[test]
    fn test_tlv_list_roundtrip() {
        let mut original = TlvList::new();
        original
            .push(RawTlv::new(TlvType::ExtraPadding, vec![0, 0, 0, 0]))
            .unwrap();
        original
            .push(RawTlv::new(TlvType::Location, vec![1, 2, 3, 4]))
            .unwrap();
        original
            .push(RawTlv::new(TlvType::Hmac, vec![0xAB; 16]))
            .unwrap();

        let bytes = original.to_bytes();
        let parsed = TlvList::parse(&bytes).unwrap();

        assert_eq!(original, parsed);
    }

    #[test]
    fn test_tlv_list_mark_unrecognized() {
        let mut list = TlvList::new();
        list.push(RawTlv::new(TlvType::ExtraPadding, vec![]))
            .unwrap();
        list.push(RawTlv::new(TlvType::Unknown(10), vec![]))
            .unwrap();
        list.push(RawTlv::new(TlvType::Reserved, vec![])).unwrap();

        list.mark_unrecognized_types();

        assert!(!list.non_hmac_tlvs()[0].is_unrecognized()); // ExtraPadding is recognized
        assert!(list.non_hmac_tlvs()[1].is_unrecognized()); // Unknown is unrecognized
        assert!(list.non_hmac_tlvs()[2].is_unrecognized()); // Reserved is unrecognized
    }

    #[test]
    fn test_count_error_flags() {
        let mut list = TlvList::new();

        // Add TLVs with various error states
        let mut unrecognized_tlv = RawTlv::new(TlvType::Unknown(99), vec![1, 2]);
        unrecognized_tlv.set_unrecognized();

        let mut malformed_tlv = RawTlv::new(TlvType::ExtraPadding, vec![]);
        malformed_tlv.set_malformed();

        let mut integrity_failed_tlv = RawTlv::new(TlvType::Location, vec![1, 2, 3, 4]);
        integrity_failed_tlv.set_integrity_failed();

        // Normal TLV without errors
        let normal_tlv = RawTlv::new(TlvType::ClassOfService, vec![0; 4]);

        list.push(unrecognized_tlv).unwrap();
        list.push(malformed_tlv).unwrap();
        list.push(integrity_failed_tlv).unwrap();
        list.push(normal_tlv).unwrap();

        let (u, m, i) = list.count_error_flags();
        assert_eq!(u, 1, "Expected 1 unrecognized TLV");
        assert_eq!(m, 1, "Expected 1 malformed TLV");
        assert_eq!(i, 1, "Expected 1 integrity-failed TLV");
    }

    #[test]
    fn test_count_error_flags_includes_hmac() {
        let mut list = TlvList::new();

        // Add HMAC TLV with integrity-failed flag
        let mut hmac_tlv = RawTlv::new(TlvType::Hmac, vec![0xAB; 16]);
        hmac_tlv.set_integrity_failed();
        list.push(hmac_tlv).unwrap();

        let (u, m, i) = list.count_error_flags();
        assert_eq!(u, 0);
        assert_eq!(m, 0);
        assert_eq!(i, 1, "HMAC TLV integrity flag should be counted");
    }

    #[test]
    fn test_extra_padding_tlv_new() {
        let tlv = ExtraPaddingTlv::new(10);
        assert!(tlv.ssid.is_none());
        assert_eq!(tlv.padding.len(), 10);
    }

    #[test]
    fn test_extra_padding_tlv_with_ssid() {
        let tlv = ExtraPaddingTlv::with_ssid(0x1234, 5);
        assert_eq!(tlv.ssid, Some(0x1234));
        assert_eq!(tlv.padding.len(), 5);
    }

    #[test]
    fn test_extra_padding_tlv_from_raw() {
        let raw = RawTlv::new(TlvType::ExtraPadding, vec![0x12, 0x34, 0x00, 0x00]);
        let tlv = ExtraPaddingTlv::from_raw(&raw);
        assert_eq!(tlv.ssid, Some(0x1234));
        assert_eq!(tlv.padding, vec![0x00, 0x00]);
    }

    #[test]
    fn test_extra_padding_tlv_from_raw_zero_ssid() {
        let raw = RawTlv::new(TlvType::ExtraPadding, vec![0x00, 0x00, 0x11, 0x22]);
        let tlv = ExtraPaddingTlv::from_raw(&raw);
        // Zero SSID is treated as no SSID
        assert!(tlv.ssid.is_none());
        assert_eq!(tlv.padding, vec![0x00, 0x00, 0x11, 0x22]);
    }

    #[test]
    fn test_extra_padding_tlv_to_raw() {
        let tlv = ExtraPaddingTlv::with_ssid(0xABCD, 2);
        let raw = tlv.to_raw();

        assert_eq!(raw.tlv_type, TlvType::ExtraPadding);
        assert_eq!(raw.value, vec![0xAB, 0xCD, 0x00, 0x00]);
    }

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

    #[test]
    fn test_session_sender_id() {
        let ssid = SessionSenderId::new(12345);
        assert_eq!(ssid.value(), 12345);

        let tlv = ssid.to_extra_padding_tlv(4);
        assert_eq!(tlv.ssid, Some(12345));
        assert_eq!(tlv.padding.len(), 4);
    }

    #[test]
    fn test_raw_tlv_wire_size() {
        let tlv = RawTlv::new(TlvType::ExtraPadding, vec![0; 10]);
        assert_eq!(tlv.wire_size(), TLV_HEADER_SIZE + 10);
    }

    #[test]
    fn test_tlv_list_wire_size() {
        let mut list = TlvList::new();
        list.push(RawTlv::new(TlvType::ExtraPadding, vec![0; 4]))
            .unwrap();
        list.push(RawTlv::new(TlvType::Location, vec![0; 8]))
            .unwrap();

        // 2 TLVs: (4 header + 4 value) + (4 header + 8 value) = 20
        assert_eq!(list.wire_size(), 20);
    }

    #[test]
    fn test_tlv_list_set_hmac() {
        let key = HmacKey::new(vec![0xAB; 32]).unwrap();
        let base_packet = vec![0x01, 0x02, 0x03, 0x04];

        let mut list = TlvList::new();
        list.push(RawTlv::new(TlvType::ExtraPadding, vec![0; 4]))
            .unwrap();
        list.set_hmac(&key, &base_packet);

        assert!(list.hmac_tlv().is_some());
        let hmac_tlv = list.hmac_tlv().unwrap();
        assert_eq!(hmac_tlv.tlv_type, TlvType::Hmac);
        assert_eq!(hmac_tlv.value.len(), 16);
    }

    #[test]
    fn test_tlv_list_verify_hmac() {
        let key = HmacKey::new(vec![0xAB; 32]).unwrap();
        let base_packet = vec![0x01, 0x02, 0x03, 0x04];

        let mut list = TlvList::new();
        list.push(RawTlv::new(TlvType::ExtraPadding, vec![0; 4]))
            .unwrap();
        list.set_hmac(&key, &base_packet);

        let tlv_bytes = list.to_bytes();
        let result = list.verify_hmac(&key, &base_packet, &tlv_bytes);
        assert!(result.is_ok());
    }

    #[test]
    fn test_tlv_list_verify_hmac_wrong_key() {
        let key1 = HmacKey::new(vec![0xAB; 32]).unwrap();
        let key2 = HmacKey::new(vec![0xCD; 32]).unwrap();
        let base_packet = vec![0x01, 0x02, 0x03, 0x04];

        let mut list = TlvList::new();
        list.push(RawTlv::new(TlvType::ExtraPadding, vec![0; 4]))
            .unwrap();
        list.set_hmac(&key1, &base_packet);

        let tlv_bytes = list.to_bytes();
        let result = list.verify_hmac(&key2, &base_packet, &tlv_bytes);
        assert!(matches!(result, Err(TlvError::HmacVerificationFailed)));
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

        // Initial state: all flags 0
        assert!(!tlv.is_unrecognized());
        assert!(!tlv.is_malformed());
        assert!(!tlv.is_integrity_failed());

        // Set each flag
        tlv.set_unrecognized();
        assert!(tlv.is_unrecognized());

        tlv.set_malformed();
        assert!(tlv.is_malformed());

        tlv.set_integrity_failed();
        assert!(tlv.is_integrity_failed());

        // All flags should now be set
        assert_eq!(tlv.flags.to_byte(), 0xE0);
    }

    #[test]
    fn test_verify_hmac_and_mark_success() {
        let key = HmacKey::new(vec![0xAB; 32]).unwrap();
        let base_packet = vec![0x01, 0x02, 0x03, 0x04];

        let mut list = TlvList::new();
        list.push(RawTlv::new(TlvType::ExtraPadding, vec![0; 4]))
            .unwrap();
        list.set_hmac(&key, &base_packet);

        let tlv_bytes = list.to_bytes();
        let result = list.verify_hmac_and_mark(&key, &base_packet, &tlv_bytes);

        assert!(result);
        // HMAC TLV should not have I-flag set
        assert!(!list.hmac_tlv().unwrap().is_integrity_failed());
    }

    #[test]
    fn test_verify_hmac_and_mark_failure() {
        let key1 = HmacKey::new(vec![0xAB; 32]).unwrap();
        let key2 = HmacKey::new(vec![0xCD; 32]).unwrap();
        let base_packet = vec![0x01, 0x02, 0x03, 0x04];

        let mut list = TlvList::new();
        list.push(RawTlv::new(TlvType::ExtraPadding, vec![0; 4]))
            .unwrap();
        list.set_hmac(&key1, &base_packet);

        let tlv_bytes = list.to_bytes();
        let result = list.verify_hmac_and_mark(&key2, &base_packet, &tlv_bytes);

        assert!(!result);
        // HMAC TLV should have I-flag set
        assert!(list.hmac_tlv().unwrap().is_integrity_failed());
    }

    #[test]
    fn test_apply_reflector_flags() {
        let key = HmacKey::new(vec![0xAB; 32]).unwrap();
        let base_packet = vec![0x01, 0x02, 0x03, 0x04];

        let mut list = TlvList::new();
        list.push(RawTlv::new(TlvType::ExtraPadding, vec![0; 4]))
            .unwrap();
        list.push(RawTlv::new(TlvType::Unknown(15), vec![1, 2]))
            .unwrap();
        list.set_hmac(&key, &base_packet);

        let tlv_bytes = list.to_bytes();

        // Apply reflector flags with correct key
        let result = list.apply_reflector_flags(Some(&key), &base_packet, &tlv_bytes);

        assert!(result); // HMAC should verify
        assert!(!list.non_hmac_tlvs()[0].is_unrecognized()); // ExtraPadding recognized
        assert!(list.non_hmac_tlvs()[1].is_unrecognized()); // Unknown(15) unrecognized
    }

    #[test]
    fn test_apply_reflector_flags_hmac_failure() {
        let key1 = HmacKey::new(vec![0xAB; 32]).unwrap();
        let key2 = HmacKey::new(vec![0xCD; 32]).unwrap();
        let base_packet = vec![0x01, 0x02, 0x03, 0x04];

        let mut list = TlvList::new();
        list.push(RawTlv::new(TlvType::ExtraPadding, vec![0; 4]))
            .unwrap();
        list.set_hmac(&key1, &base_packet);

        let tlv_bytes = list.to_bytes();

        // Apply reflector flags with wrong key
        let result = list.apply_reflector_flags(Some(&key2), &base_packet, &tlv_bytes);

        assert!(!result); // HMAC should fail
        assert!(list.hmac_tlv().unwrap().is_integrity_failed()); // I-flag set
    }

    #[test]
    fn test_contains_only_extra_padding_true() {
        let mut list = TlvList::new();
        list.push(RawTlv::new(TlvType::ExtraPadding, vec![0; 4]))
            .unwrap();
        list.push(RawTlv::new(TlvType::ExtraPadding, vec![0; 8]))
            .unwrap();

        assert!(list.contains_only_extra_padding());
    }

    #[test]
    fn test_contains_only_extra_padding_false_with_other_tlv() {
        let mut list = TlvList::new();
        list.push(RawTlv::new(TlvType::ExtraPadding, vec![0; 4]))
            .unwrap();
        list.push(RawTlv::new(TlvType::Location, vec![1, 2, 3, 4]))
            .unwrap();

        assert!(!list.contains_only_extra_padding());
    }

    #[test]
    fn test_contains_only_extra_padding_false_with_hmac() {
        let key = HmacKey::new(vec![0xAB; 32]).unwrap();
        let base_packet = vec![0x01, 0x02, 0x03, 0x04];

        let mut list = TlvList::new();
        list.push(RawTlv::new(TlvType::ExtraPadding, vec![0; 4]))
            .unwrap();
        list.set_hmac(&key, &base_packet);

        // Has HMAC TLV, so not "only extra padding"
        assert!(!list.contains_only_extra_padding());
    }

    #[test]
    fn test_contains_only_extra_padding_empty() {
        let list = TlvList::new();
        // Empty list is not "only extra padding"
        assert!(!list.contains_only_extra_padding());
    }

    #[test]
    fn test_apply_reflector_flags_strict_missing_hmac() {
        let key = HmacKey::new(vec![0xAB; 32]).unwrap();
        let base_packet = vec![0x01, 0x02, 0x03, 0x04];

        let mut list = TlvList::new();
        list.push(RawTlv::new(TlvType::Location, vec![1, 2, 3, 4]))
            .unwrap();

        let tlv_bytes = list.to_bytes();

        // Strict mode: require HMAC TLV (not extra-padding-only)
        let result = list.apply_reflector_flags_strict(Some(&key), &base_packet, &tlv_bytes, true);

        assert!(!result); // Should fail - missing HMAC TLV
        assert!(list.non_hmac_tlvs()[0].is_integrity_failed()); // I-flag set
    }

    #[test]
    fn test_apply_reflector_flags_strict_extra_padding_only_exception() {
        let key = HmacKey::new(vec![0xAB; 32]).unwrap();
        let base_packet = vec![0x01, 0x02, 0x03, 0x04];

        let mut list = TlvList::new();
        list.push(RawTlv::new(TlvType::ExtraPadding, vec![0; 4]))
            .unwrap();

        let tlv_bytes = list.to_bytes();

        // Strict mode, but only Extra Padding TLVs - should be allowed
        let result = list.apply_reflector_flags_strict(Some(&key), &base_packet, &tlv_bytes, true);

        assert!(result); // Should pass - extra-padding-only exception
        assert!(!list.non_hmac_tlvs()[0].is_integrity_failed()); // No I-flag
    }

    #[test]
    fn test_apply_reflector_flags_strict_with_valid_hmac() {
        let key = HmacKey::new(vec![0xAB; 32]).unwrap();
        let base_packet = vec![0x01, 0x02, 0x03, 0x04];

        let mut list = TlvList::new();
        list.push(RawTlv::new(TlvType::Location, vec![1, 2, 3, 4]))
            .unwrap();
        list.set_hmac(&key, &base_packet);

        let tlv_bytes = list.to_bytes();

        // Strict mode with valid HMAC TLV
        let result = list.apply_reflector_flags_strict(Some(&key), &base_packet, &tlv_bytes, true);

        assert!(result); // Should pass - valid HMAC present
    }

    #[test]
    fn test_apply_reflector_flags_strict_non_strict_mode() {
        let key = HmacKey::new(vec![0xAB; 32]).unwrap();
        let base_packet = vec![0x01, 0x02, 0x03, 0x04];

        let mut list = TlvList::new();
        list.push(RawTlv::new(TlvType::Location, vec![1, 2, 3, 4]))
            .unwrap();

        let tlv_bytes = list.to_bytes();

        // Non-strict mode: missing HMAC TLV is OK
        let result = list.apply_reflector_flags_strict(Some(&key), &base_packet, &tlv_bytes, false);

        assert!(result); // Should pass - non-strict allows missing HMAC
        assert!(!list.non_hmac_tlvs()[0].is_integrity_failed()); // No I-flag
    }

    #[test]
    fn test_apply_reflector_flags_no_key_with_hmac_tlv() {
        // When HMAC TLV exists but no key is available, ALL TLVs must get I-flag
        let key = HmacKey::new(vec![0xAB; 32]).unwrap();
        let seq = vec![0x01, 0x02, 0x03, 0x04];

        let mut list = TlvList::new();
        list.push(RawTlv::new(TlvType::ExtraPadding, vec![0xCC; 4]))
            .unwrap();
        list.push(RawTlv::new(TlvType::Location, vec![1, 2, 3, 4]))
            .unwrap();
        list.set_hmac(&key, &seq);

        let tlv_bytes = list.to_bytes();

        // Call with no key (None) — HMAC TLV is present but unverifiable
        let result = list.apply_reflector_flags(None, &seq, &tlv_bytes);

        assert!(!result, "Should return false when HMAC present but no key");
        // ALL non-HMAC TLVs must have I-flag set
        for tlv in list.non_hmac_tlvs() {
            assert!(
                tlv.is_integrity_failed(),
                "Non-HMAC TLV type {:?} should have I-flag set",
                tlv.tlv_type
            );
        }
        // HMAC TLV itself must also have I-flag
        assert!(
            list.hmac_tlv().unwrap().is_integrity_failed(),
            "HMAC TLV should have I-flag set"
        );
    }

    #[test]
    fn test_apply_reflector_flags_no_key_no_hmac_tlv() {
        // When no HMAC TLV exists and no key, should pass (nothing to verify)
        let seq = vec![0x01, 0x02, 0x03, 0x04];

        let mut list = TlvList::new();
        list.push(RawTlv::new(TlvType::ExtraPadding, vec![0xCC; 4]))
            .unwrap();

        let tlv_bytes = list.to_bytes();

        let result = list.apply_reflector_flags(None, &seq, &tlv_bytes);

        assert!(result, "Should pass when no HMAC TLV and no key");
        assert!(
            !list.non_hmac_tlvs()[0].is_integrity_failed(),
            "No I-flag should be set"
        );
    }

    #[test]
    fn test_wire_order_preserved_for_malformed_tlvs() {
        // Build bytes with TLVs in specific order: Location, ExtraPadding, HMAC (truncated)
        let mut buf = Vec::new();

        // Location TLV (type 2)
        buf.push(0x00); // flags
        buf.push(0x02); // type = Location
        buf.extend_from_slice(&4u16.to_be_bytes()); // length = 4
        buf.extend_from_slice(&[1, 2, 3, 4]); // value

        // ExtraPadding TLV (type 1)
        buf.push(0x00); // flags
        buf.push(0x01); // type = ExtraPadding
        buf.extend_from_slice(&2u16.to_be_bytes()); // length = 2
        buf.extend_from_slice(&[0xAA, 0xBB]); // value

        // Truncated HMAC TLV (should be malformed)
        buf.push(0x00); // flags
        buf.push(0x08); // type = HMAC
        buf.extend_from_slice(&16u16.to_be_bytes()); // length = 16
        buf.extend_from_slice(&[0xCC; 8]); // only 8 bytes of value (truncated)

        let (list, had_malformed) = TlvList::parse_lenient(&buf);

        assert!(had_malformed);
        assert!(list.is_wire_order_mode()); // Wire-order mode should be active

        // Serialize back - should preserve wire order
        let output = list.to_bytes();

        // First TLV should be Location
        assert_eq!(output[1], 0x02); // type = Location

        // Second TLV should be ExtraPadding (at offset 8)
        assert_eq!(output[9], 0x01); // type = ExtraPadding

        // Third TLV should be HMAC (at offset 14)
        assert_eq!(output[15], 0x08); // type = HMAC
    }

    #[test]
    fn test_wire_order_preserved_for_multiple_hmac_tlvs() {
        // Build bytes with multiple HMAC TLVs (malformed case)
        let mut buf = Vec::new();

        // First HMAC TLV
        buf.push(0x00); // flags
        buf.push(0x08); // type = HMAC
        buf.extend_from_slice(&16u16.to_be_bytes()); // length = 16
        buf.extend_from_slice(&[0xAA; 16]); // value

        // Second HMAC TLV (should be marked malformed)
        buf.push(0x00); // flags
        buf.push(0x08); // type = HMAC
        buf.extend_from_slice(&16u16.to_be_bytes()); // length = 16
        buf.extend_from_slice(&[0xBB; 16]); // value

        let (list, had_malformed) = TlvList::parse_lenient(&buf);

        assert!(had_malformed); // Second HMAC should be marked malformed
        assert!(list.is_wire_order_mode()); // Wire-order mode should be active
        assert_eq!(list.len(), 2); // Both HMACs should be present

        // Serialize back - should have both HMAC TLVs in order
        let output = list.to_bytes();

        // First HMAC at offset 0
        assert_eq!(output[1], 0x08);
        assert_eq!(&output[4..20], &[0xAA; 16]);

        // Second HMAC at offset 20
        assert_eq!(output[21], 0x08);
        assert_eq!(&output[24..40], &[0xBB; 16]);
    }

    #[test]
    fn test_wire_order_not_used_for_valid_tlvs() {
        // Build valid TLVs
        let mut buf = Vec::new();

        // ExtraPadding TLV
        buf.push(0x00); // flags
        buf.push(0x01); // type = ExtraPadding
        buf.extend_from_slice(&4u16.to_be_bytes());
        buf.extend_from_slice(&[0; 4]);

        // Valid HMAC TLV
        buf.push(0x00); // flags
        buf.push(0x08); // type = HMAC
        buf.extend_from_slice(&16u16.to_be_bytes());
        buf.extend_from_slice(&[0xAA; 16]);

        let (list, had_malformed) = TlvList::parse_lenient(&buf);

        assert!(!had_malformed);
        assert!(!list.is_wire_order_mode()); // Should NOT be in wire-order mode
    }

    #[test]
    fn test_mark_all_integrity_failed_updates_wire_order() {
        // Build malformed TLVs to trigger wire-order mode
        let mut buf = Vec::new();

        // Location TLV
        buf.push(0x00);
        buf.push(0x02);
        buf.extend_from_slice(&4u16.to_be_bytes());
        buf.extend_from_slice(&[1, 2, 3, 4]);

        // Truncated HMAC
        buf.push(0x00);
        buf.push(0x08);
        buf.extend_from_slice(&16u16.to_be_bytes());
        buf.extend_from_slice(&[0xCC; 8]); // truncated

        let (mut list, _) = TlvList::parse_lenient(&buf);
        assert!(list.is_wire_order_mode());

        list.mark_all_integrity_failed();

        // Serialize and check I-flag is set on all TLVs
        let output = list.to_bytes();

        // Location TLV should have I-flag (0x20)
        assert_eq!(output[0] & 0x20, 0x20);

        // HMAC TLV should have I-flag
        assert_eq!(output[8] & 0x20, 0x20);
    }

    #[test]
    fn test_truncated_tlv_preserves_wire_length() {
        // Build a truncated TLV: declares length=100 but only has 10 bytes
        let mut buf = Vec::new();
        buf.push(0x00); // flags
        buf.push(0x02); // type = Location
        buf.extend_from_slice(&100u16.to_be_bytes()); // declared length = 100
        buf.extend_from_slice(&[0xAA; 10]); // only 10 bytes available

        // Parse leniently
        let (tlv, consumed, malformed) = RawTlv::parse_lenient(&buf).unwrap();

        assert!(malformed);
        assert!(tlv.is_malformed());
        assert_eq!(consumed, 14); // header (4) + available (10)
        assert_eq!(tlv.value.len(), 10); // only available bytes stored

        // Serialize back - should preserve original wire length (100) in header
        let output = tlv.to_bytes();

        assert_eq!(output[0], 0x40); // M-flag set
        assert_eq!(output[1], 0x02); // type = Location
                                     // Length field should be 100 (original wire length), not 10
        assert_eq!(u16::from_be_bytes([output[2], output[3]]), 100);
        // Value should only have the 10 bytes we actually have
        assert_eq!(&output[4..], &[0xAA; 10]);
    }

    #[test]
    fn test_normal_tlv_uses_value_length() {
        // Build a normal (non-truncated) TLV
        let mut buf = Vec::new();
        buf.push(0x00); // flags
        buf.push(0x02); // type = Location
        buf.extend_from_slice(&10u16.to_be_bytes()); // length = 10
        buf.extend_from_slice(&[0xBB; 10]); // full 10 bytes

        // Parse leniently
        let (tlv, consumed, malformed) = RawTlv::parse_lenient(&buf).unwrap();

        assert!(!malformed);
        assert!(!tlv.is_malformed());
        assert_eq!(consumed, 14);
        assert_eq!(tlv.value.len(), 10);

        // Serialize back - should use actual value length
        let output = tlv.to_bytes();

        assert_eq!(output[0], 0x00); // no flags
        assert_eq!(output[1], 0x02); // type = Location
        assert_eq!(u16::from_be_bytes([output[2], output[3]]), 10);
        assert_eq!(&output[4..], &[0xBB; 10]);
    }

    // Class of Service TLV tests

    #[test]
    fn test_cos_tlv_new() {
        let cos = ClassOfServiceTlv::new(46, 2); // DSCP=46 (EF), ECN=2

        assert_eq!(cos.dscp1, 46);
        assert_eq!(cos.ecn1, 2);
        assert_eq!(cos.dscp2, 0);
        assert_eq!(cos.ecn2, 0);
        assert_eq!(cos.rp, 0);
    }

    #[test]
    fn test_cos_tlv_new_clamps_values() {
        // Values exceeding max should be clamped
        let cos = ClassOfServiceTlv::new(0xFF, 0xFF);

        assert_eq!(cos.dscp1, 0x3F); // 6 bits max
        assert_eq!(cos.ecn1, 0x03); // 2 bits max
    }

    #[test]
    fn test_cos_tlv_for_response() {
        let cos = ClassOfServiceTlv::for_response(46, 2, 0, 1, false);

        assert_eq!(cos.dscp1, 46);
        assert_eq!(cos.ecn1, 2);
        assert_eq!(cos.dscp2, 0);
        assert_eq!(cos.ecn2, 1);
        assert_eq!(cos.rp, 0);
        assert!(!cos.policy_rejected());
    }

    #[test]
    fn test_cos_tlv_for_response_policy_rejected() {
        let cos = ClassOfServiceTlv::for_response(46, 2, 0, 1, true);

        assert_eq!(cos.rp, 1);
        assert!(cos.policy_rejected());
    }

    #[test]
    fn test_cos_tlv_to_raw() {
        let cos = ClassOfServiceTlv::new(46, 2);
        let raw = cos.to_raw();

        assert_eq!(raw.tlv_type, TlvType::ClassOfService);
        assert_eq!(raw.value.len(), COS_TLV_VALUE_SIZE);

        // Byte 0: DSCP1 (46 = 0x2E) << 2 | ECN1 (2) = 0xBA
        assert_eq!(raw.value[0], 0xBA);
        // Byte 1: DSCP2 (0) << 2 | ECN2 (0) = 0x00
        assert_eq!(raw.value[1], 0x00);
        // Byte 2: RP (0) << 6 = 0x00
        assert_eq!(raw.value[2], 0x00);
        // Byte 3: Reserved
        assert_eq!(raw.value[3], 0x00);
    }

    #[test]
    fn test_cos_tlv_roundtrip() {
        let original = ClassOfServiceTlv::for_response(46, 2, 10, 1, true);
        let raw = original.to_raw();
        let parsed = ClassOfServiceTlv::from_raw(&raw).unwrap();

        assert_eq!(parsed.dscp1, original.dscp1);
        assert_eq!(parsed.ecn1, original.ecn1);
        assert_eq!(parsed.dscp2, original.dscp2);
        assert_eq!(parsed.ecn2, original.ecn2);
        assert_eq!(parsed.rp, original.rp);
    }

    #[test]
    fn test_cos_tlv_from_raw_invalid_length() {
        let raw = RawTlv::new(TlvType::ClassOfService, vec![0, 0]); // Only 2 bytes
        let result = ClassOfServiceTlv::from_raw(&raw);

        assert!(matches!(result, Err(TlvError::InvalidCosLength(2))));
    }

    #[test]
    fn test_cos_tlv_effective_dscp() {
        let cos = ClassOfServiceTlv::for_response(46, 2, 10, 1, false);

        // When policy allows, use DSCP1
        assert_eq!(cos.effective_dscp(false), 46);

        // When policy rejects, use DSCP2
        assert_eq!(cos.effective_dscp(true), 10);
    }

    #[test]
    fn test_cos_tlv_wire_format_boundary_values() {
        // Test with max values
        let cos = ClassOfServiceTlv {
            dscp1: 63, // Max 6-bit value
            ecn1: 3,   // Max 2-bit value
            dscp2: 63,
            ecn2: 3,
            rp: 3, // Max 2-bit value
        };
        let raw = cos.to_raw();

        // Byte 0: (63 << 2) | 3 = 0xFF
        assert_eq!(raw.value[0], 0xFF);
        // Byte 1: (63 << 2) | 3 = 0xFF
        assert_eq!(raw.value[1], 0xFF);
        // Byte 2: 3 << 6 = 0xC0
        assert_eq!(raw.value[2], 0xC0);

        // Roundtrip
        let parsed = ClassOfServiceTlv::from_raw(&raw).unwrap();
        assert_eq!(parsed.dscp1, 63);
        assert_eq!(parsed.ecn1, 3);
        assert_eq!(parsed.dscp2, 63);
        assert_eq!(parsed.ecn2, 3);
        assert_eq!(parsed.rp, 3);
    }

    #[test]
    fn test_parse_lenient_skips_zero_padding() {
        // Test that zero-padding (all-zero TLV headers) is treated as padding, not TLVs.
        // This handles the case where reflector in "ignore" mode pads responses with zeros.

        // Build buffer with one real TLV followed by zero-padding
        let mut buf = Vec::new();

        // Location TLV (type 2)
        buf.push(0x00); // flags
        buf.push(0x02); // type = Location
        buf.extend_from_slice(&4u16.to_be_bytes()); // length = 4
        buf.extend_from_slice(&[1, 2, 3, 4]); // value

        // Zero-padding (simulating reflector ignore mode)
        buf.extend_from_slice(&[0u8; 16]); // 16 bytes of zeros = 4 all-zero TLV headers

        let (list, had_malformed) = TlvList::parse_lenient(&buf);

        // Should only have one TLV, zero-padding should be ignored
        assert!(!had_malformed);
        assert_eq!(list.len(), 1);
        assert_eq!(list.non_hmac_tlvs().len(), 1);
        assert_eq!(list.non_hmac_tlvs()[0].tlv_type, TlvType::Location);
    }

    #[test]
    fn test_parse_lenient_all_zero_buffer() {
        // Test that a buffer of all zeros is treated as empty (no TLVs)
        let buf = [0u8; 32]; // 32 bytes of zeros

        let (list, had_malformed) = TlvList::parse_lenient(&buf);

        assert!(!had_malformed);
        assert!(list.is_empty());
        assert_eq!(list.len(), 0);
    }

    #[test]
    fn test_parse_lenient_zero_padding_after_hmac() {
        // Test that zero-padding after HMAC TLV is properly ignored
        let mut buf = Vec::new();

        // Valid HMAC TLV
        buf.push(0x00); // flags
        buf.push(0x08); // type = HMAC
        buf.extend_from_slice(&16u16.to_be_bytes()); // length = 16
        buf.extend_from_slice(&[0xAA; 16]); // 16-byte value

        // Zero-padding after HMAC
        buf.extend_from_slice(&[0u8; 8]); // 8 bytes of zeros

        let (list, had_malformed) = TlvList::parse_lenient(&buf);

        assert!(!had_malformed);
        assert_eq!(list.len(), 1);
        assert!(list.hmac_tlv().is_some());
        assert!(list.non_hmac_tlvs().is_empty());
    }

    #[test]
    fn test_parse_lenient_reserved_tlv_zero_length_not_padding() {
        // A Reserved TLV (type=0) with zero-length value has header 00 00 00 00.
        // This must NOT be treated as padding if followed by non-zero data.
        let mut buf = Vec::new();

        // Reserved TLV with zero length (header: 00 00 00 00)
        buf.push(0x00); // flags = 0
        buf.push(0x00); // type = Reserved (0)
        buf.extend_from_slice(&0u16.to_be_bytes()); // length = 0 (no value)

        // Another TLV after the Reserved TLV
        buf.push(0x00); // flags
        buf.push(0x02); // type = Location
        buf.extend_from_slice(&4u16.to_be_bytes()); // length = 4
        buf.extend_from_slice(&[1, 2, 3, 4]); // value

        let (list, had_malformed) = TlvList::parse_lenient(&buf);

        // Should have TWO TLVs: Reserved and Location
        assert!(!had_malformed);
        assert_eq!(list.len(), 2);
        assert_eq!(list.non_hmac_tlvs().len(), 2);
        assert_eq!(list.non_hmac_tlvs()[0].tlv_type, TlvType::Reserved);
        assert_eq!(list.non_hmac_tlvs()[0].value.len(), 0);
        assert_eq!(list.non_hmac_tlvs()[1].tlv_type, TlvType::Location);
    }

    #[test]
    fn test_parse_lenient_reserved_tlv_followed_by_trailing_zeros() {
        // Edge case: A Reserved TLV (type=0) with zero-length followed by only trailing zeros.
        // Since the remaining bytes are all zeros, the lenient parser treats this as trailing
        // padding (indistinguishable from a zero-length Reserved TLV + padding).
        // This is acceptable for lenient parsing - if precise distinction is needed,
        // use the non-lenient parser.
        let mut buf = Vec::new();

        // Location TLV first
        buf.push(0x00); // flags
        buf.push(0x02); // type = Location
        buf.extend_from_slice(&4u16.to_be_bytes()); // length = 4
        buf.extend_from_slice(&[1, 2, 3, 4]); // value

        // Reserved TLV with zero length (header: 00 00 00 00)
        buf.push(0x00); // flags = 0
        buf.push(0x00); // type = Reserved (0)
        buf.extend_from_slice(&0u16.to_be_bytes()); // length = 0

        // Trailing zeros after Reserved TLV
        buf.extend_from_slice(&[0u8; 8]);

        let (list, had_malformed) = TlvList::parse_lenient(&buf);

        // Lenient parser treats all-zero trailing bytes as padding.
        // Only the Location TLV is parsed; the Reserved+zeros are treated as padding.
        assert!(!had_malformed);
        assert_eq!(list.len(), 1);
        assert_eq!(list.non_hmac_tlvs()[0].tlv_type, TlvType::Location);
    }

    #[test]
    fn test_parse_lenient_reserved_tlv_with_value_not_padding() {
        // A Reserved TLV with non-zero length is distinguishable from padding.
        let mut buf = Vec::new();

        // Reserved TLV with length=2 (not all-zeros)
        buf.push(0x00); // flags = 0
        buf.push(0x00); // type = Reserved (0)
        buf.extend_from_slice(&2u16.to_be_bytes()); // length = 2
        buf.extend_from_slice(&[0x00, 0x00]); // value (zeros, but length > 0)

        // Location TLV after
        buf.push(0x00); // flags
        buf.push(0x02); // type = Location
        buf.extend_from_slice(&4u16.to_be_bytes()); // length = 4
        buf.extend_from_slice(&[1, 2, 3, 4]); // value

        let (list, had_malformed) = TlvList::parse_lenient(&buf);

        // Should have TWO TLVs: Reserved (with value) and Location
        assert!(!had_malformed);
        assert_eq!(list.len(), 2);
        assert_eq!(list.non_hmac_tlvs()[0].tlv_type, TlvType::Reserved);
        assert_eq!(list.non_hmac_tlvs()[0].value.len(), 2);
        assert_eq!(list.non_hmac_tlvs()[1].tlv_type, TlvType::Location);
    }

    // ========================================================================
    // Access Report TLV tests (Type 6)
    // ========================================================================

    #[test]
    fn test_access_report_tlv_new() {
        let tlv = AccessReportTlv::new(5, 1);
        assert_eq!(tlv.access_id, 5);
        assert_eq!(tlv.return_code, 1);
    }

    #[test]
    fn test_access_report_tlv_new_clamps_access_id() {
        let tlv = AccessReportTlv::new(0xFF, 1);
        assert_eq!(tlv.access_id, 0x0F); // Only lower 4 bits kept
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
        // Byte 0: access_id (0x0A) << 4 = 0xA0
        assert_eq!(raw.value[0], 0xA0);
        // Byte 1: return_code = 0x03
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
        // Max access_id (15), max return_code (255)
        let tlv = AccessReportTlv::new(15, 255);
        let raw = tlv.to_raw();
        let parsed = AccessReportTlv::from_raw(&raw).unwrap();
        assert_eq!(parsed.access_id, 15);
        assert_eq!(parsed.return_code, 255);

        // Min values
        let tlv = AccessReportTlv::new(0, 0);
        let raw = tlv.to_raw();
        let parsed = AccessReportTlv::from_raw(&raw).unwrap();
        assert_eq!(parsed.access_id, 0);
        assert_eq!(parsed.return_code, 0);
    }

    // ========================================================================
    // SyncSource and TimestampMethod enum tests
    // ========================================================================

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

    // ========================================================================
    // Timestamp Info TLV tests (Type 3)
    // ========================================================================

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
            sync_src_in: SyncSource::Ntp,             // 1
            timestamp_in: TimestampMethod::SwLocal,   // 2
            sync_src_out: SyncSource::Ptp,            // 2
            timestamp_out: TimestampMethod::HwAssist, // 1
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

    // ========================================================================
    // Direct Measurement TLV tests (Type 5)
    // ========================================================================

    #[test]
    fn test_direct_measurement_tlv_new() {
        let tlv = DirectMeasurementTlv::new(100);
        assert_eq!(tlv.sender_tx_count, 100);
        assert_eq!(tlv.reflector_rx_count, 0);
        assert_eq!(tlv.reflector_tx_count, 0);
    }

    #[test]
    fn test_direct_measurement_tlv_roundtrip() {
        let original = DirectMeasurementTlv {
            sender_tx_count: 1000,
            reflector_rx_count: 999,
            reflector_tx_count: 998,
        };
        let raw = original.to_raw();
        let parsed = DirectMeasurementTlv::from_raw(&raw).unwrap();
        assert_eq!(parsed, original);
    }

    #[test]
    fn test_direct_measurement_tlv_wire_format() {
        let tlv = DirectMeasurementTlv {
            sender_tx_count: 0x00000001,
            reflector_rx_count: 0x00000002,
            reflector_tx_count: 0x00000003,
        };
        let raw = tlv.to_raw();
        assert_eq!(raw.tlv_type, TlvType::DirectMeasurement);
        assert_eq!(raw.value.len(), DIRECT_MEASUREMENT_TLV_VALUE_SIZE);
        // Big-endian u32 values
        assert_eq!(&raw.value[0..4], &[0, 0, 0, 1]);
        assert_eq!(&raw.value[4..8], &[0, 0, 0, 2]);
        assert_eq!(&raw.value[8..12], &[0, 0, 0, 3]);
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
        let raw = RawTlv::new(TlvType::DirectMeasurement, vec![0; 8]);
        let result = DirectMeasurementTlv::from_raw(&raw);
        assert!(matches!(
            result,
            Err(TlvError::InvalidDirectMeasurementLength(8))
        ));
    }

    #[test]
    fn test_direct_measurement_tlv_from_raw_too_long() {
        let raw = RawTlv::new(TlvType::DirectMeasurement, vec![0; 16]);
        let result = DirectMeasurementTlv::from_raw(&raw);
        assert!(matches!(
            result,
            Err(TlvError::InvalidDirectMeasurementLength(16))
        ));
    }

    // ========================================================================
    // Location sub-TLV tests
    // ========================================================================

    #[test]
    fn test_location_sub_type_roundtrip() {
        let types = [
            LocationSubType::Ipv4Src,
            LocationSubType::Ipv4Dst,
            LocationSubType::Ipv6Src,
            LocationSubType::Ipv6Dst,
            LocationSubType::Asn,
            LocationSubType::IfName,
            LocationSubType::IfIndex,
            LocationSubType::MplsLabel,
            LocationSubType::SrSid,
            LocationSubType::Unknown(42),
        ];
        for t in &types {
            assert_eq!(*t, LocationSubType::from_byte(t.to_byte()));
        }
    }

    #[test]
    fn test_location_sub_tlv_to_bytes_and_parse() {
        let sub = LocationSubTlv::new(LocationSubType::Ipv4Src, vec![192, 168, 1, 1]);
        let bytes = sub.to_bytes();
        assert_eq!(bytes.len(), 6); // 1 type + 1 length + 4 value
        assert_eq!(bytes[0], 1); // Ipv4Src
        assert_eq!(bytes[1], 4); // length
        assert_eq!(&bytes[2..], &[192, 168, 1, 1]);

        let (parsed, consumed) = LocationSubTlv::parse(&bytes).unwrap();
        assert_eq!(consumed, 6);
        assert_eq!(parsed, sub);
    }

    #[test]
    fn test_location_sub_tlv_ipv6() {
        let addr = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let sub = LocationSubTlv::new(LocationSubType::Ipv6Dst, addr.to_vec());
        let bytes = sub.to_bytes();
        assert_eq!(bytes.len(), 18); // 1 + 1 + 16

        let (parsed, consumed) = LocationSubTlv::parse(&bytes).unwrap();
        assert_eq!(consumed, 18);
        assert_eq!(parsed.sub_type, LocationSubType::Ipv6Dst);
        assert_eq!(parsed.value, addr.to_vec());
    }

    #[test]
    fn test_location_sub_tlv_parse_too_short() {
        assert!(LocationSubTlv::parse(&[]).is_none());
        assert!(LocationSubTlv::parse(&[1]).is_none());
    }

    #[test]
    fn test_location_sub_tlv_parse_truncated_value() {
        // Header says length=4 but only 2 bytes available
        let buf = [1, 4, 192, 168];
        assert!(LocationSubTlv::parse(&buf).is_none());
    }

    // ========================================================================
    // Location TLV tests (Type 2)
    // ========================================================================

    #[test]
    fn test_location_tlv_new() {
        let tlv = LocationTlv::new();
        assert_eq!(tlv.dest_port, 0);
        assert_eq!(tlv.src_port, 0);
        assert!(tlv.sub_tlvs.is_empty());
    }

    #[test]
    fn test_location_tlv_default() {
        let tlv = LocationTlv::default();
        assert_eq!(tlv.dest_port, 0);
        assert_eq!(tlv.src_port, 0);
        assert!(tlv.sub_tlvs.is_empty());
    }

    #[test]
    fn test_location_tlv_roundtrip_empty() {
        let original = LocationTlv {
            dest_port: 862,
            src_port: 50000,
            sub_tlvs: vec![],
        };
        let raw = original.to_raw();
        let parsed = LocationTlv::from_raw(&raw).unwrap();
        assert_eq!(parsed.dest_port, 862);
        assert_eq!(parsed.src_port, 50000);
        assert!(parsed.sub_tlvs.is_empty());
    }

    #[test]
    fn test_location_tlv_roundtrip_with_sub_tlvs() {
        let original = LocationTlv {
            dest_port: 862,
            src_port: 12345,
            sub_tlvs: vec![
                LocationSubTlv::new(LocationSubType::Ipv4Src, vec![10, 0, 0, 1]),
                LocationSubTlv::new(LocationSubType::Ipv4Dst, vec![10, 0, 0, 2]),
            ],
        };
        let raw = original.to_raw();
        let parsed = LocationTlv::from_raw(&raw).unwrap();
        assert_eq!(parsed, original);
    }

    #[test]
    fn test_location_tlv_wire_format() {
        let tlv = LocationTlv {
            dest_port: 0x035E, // 862
            src_port: 0xC350,  // 50000
            sub_tlvs: vec![LocationSubTlv::new(
                LocationSubType::Ipv4Src,
                vec![192, 168, 1, 1],
            )],
        };
        let raw = tlv.to_raw();
        assert_eq!(raw.tlv_type, TlvType::Location);
        // 4 bytes ports + 6 bytes sub-TLV = 10
        assert_eq!(raw.value.len(), 10);
        assert_eq!(&raw.value[0..2], &[0x03, 0x5E]); // dest_port
        assert_eq!(&raw.value[2..4], &[0xC3, 0x50]); // src_port
        assert_eq!(raw.value[4], 1); // sub-TLV type: Ipv4Src
        assert_eq!(raw.value[5], 4); // sub-TLV length
        assert_eq!(&raw.value[6..10], &[192, 168, 1, 1]); // sub-TLV value
    }

    #[test]
    fn test_location_tlv_from_raw_too_short() {
        let raw = RawTlv::new(TlvType::Location, vec![0, 0, 0]); // Only 3 bytes
        let result = LocationTlv::from_raw(&raw);
        assert!(matches!(result, Err(TlvError::InvalidLocationLength(3))));
    }

    #[test]
    fn test_location_tlv_from_raw_empty() {
        let raw = RawTlv::new(TlvType::Location, vec![]);
        let result = LocationTlv::from_raw(&raw);
        assert!(matches!(result, Err(TlvError::InvalidLocationLength(0))));
    }

    #[test]
    fn test_location_tlv_from_raw_ports_only() {
        // Exactly 4 bytes: just ports, no sub-TLVs
        let raw = RawTlv::new(TlvType::Location, vec![0x03, 0x5E, 0xC3, 0x50]);
        let parsed = LocationTlv::from_raw(&raw).unwrap();
        assert_eq!(parsed.dest_port, 862);
        assert_eq!(parsed.src_port, 50000);
        assert!(parsed.sub_tlvs.is_empty());
    }

    // ========================================================================
    // Follow-Up Telemetry TLV tests (Type 7)
    // ========================================================================

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
    }

    #[test]
    fn test_follow_up_telemetry_tlv_roundtrip() {
        let original = FollowUpTelemetryTlv {
            sequence_number: 42,
            follow_up_timestamp: 0x0123456789ABCDEF,
            timestamp_mode: TimestampMethod::SwLocal,
        };
        let raw = original.to_raw();
        let parsed = FollowUpTelemetryTlv::from_raw(&raw).unwrap();
        assert_eq!(parsed, original);
    }

    #[test]
    fn test_follow_up_telemetry_tlv_wire_format() {
        let tlv = FollowUpTelemetryTlv {
            sequence_number: 1,
            follow_up_timestamp: 0xFF00FF00FF00FF00,
            timestamp_mode: TimestampMethod::HwAssist,
        };
        let raw = tlv.to_raw();
        assert_eq!(raw.tlv_type, TlvType::FollowUpTelemetry);
        assert_eq!(raw.value.len(), FOLLOW_UP_TELEMETRY_TLV_VALUE_SIZE);
        // Bytes 0-3: sequence_number = 1
        assert_eq!(&raw.value[0..4], &[0, 0, 0, 1]);
        // Bytes 4-11: follow_up_timestamp
        assert_eq!(
            &raw.value[4..12],
            &[0xFF, 0x00, 0xFF, 0x00, 0xFF, 0x00, 0xFF, 0x00]
        );
        // Byte 12: timestamp_mode = HwAssist (1)
        assert_eq!(raw.value[12], 1);
        // Bytes 13-15: reserved (zeros)
        assert_eq!(&raw.value[13..16], &[0, 0, 0]);
    }

    #[test]
    fn test_follow_up_telemetry_tlv_from_raw_invalid_length() {
        let raw = RawTlv::new(TlvType::FollowUpTelemetry, vec![0; 12]);
        let result = FollowUpTelemetryTlv::from_raw(&raw);
        assert!(matches!(
            result,
            Err(TlvError::InvalidFollowUpTelemetryLength(12))
        ));
    }

    #[test]
    fn test_follow_up_telemetry_tlv_from_raw_too_long() {
        let raw = RawTlv::new(TlvType::FollowUpTelemetry, vec![0; 20]);
        let result = FollowUpTelemetryTlv::from_raw(&raw);
        assert!(matches!(
            result,
            Err(TlvError::InvalidFollowUpTelemetryLength(20))
        ));
    }

    #[test]
    fn test_follow_up_telemetry_tlv_max_values() {
        let original = FollowUpTelemetryTlv {
            sequence_number: u32::MAX,
            follow_up_timestamp: u64::MAX,
            timestamp_mode: TimestampMethod::Unknown(255),
        };
        let raw = original.to_raw();
        let parsed = FollowUpTelemetryTlv::from_raw(&raw).unwrap();
        assert_eq!(parsed, original);
    }

    // ========================================================================
    // TlvList update method tests
    // ========================================================================

    #[test]
    fn test_update_timestamp_info_tlvs() {
        let mut list = TlvList::new();
        let sender_tlv = TimestampInfoTlv::new(SyncSource::Ntp, TimestampMethod::SwLocal);
        list.push(sender_tlv.to_raw()).unwrap();

        list.update_timestamp_info_tlvs(SyncSource::Ptp, TimestampMethod::HwAssist);

        let raw = &list.non_hmac_tlvs()[0];
        let parsed = TimestampInfoTlv::from_raw(raw).unwrap();
        // In-fields should be preserved
        assert_eq!(parsed.sync_src_in, SyncSource::Ntp);
        assert_eq!(parsed.timestamp_in, TimestampMethod::SwLocal);
        // Out-fields should be updated
        assert_eq!(parsed.sync_src_out, SyncSource::Ptp);
        assert_eq!(parsed.timestamp_out, TimestampMethod::HwAssist);
    }

    #[test]
    fn test_update_timestamp_info_skips_wrong_size() {
        let mut list = TlvList::new();
        // Push a TimestampInfo with wrong size (3 bytes instead of 4)
        list.push(RawTlv::new(TlvType::TimestampInfo, vec![1, 2, 3]))
            .unwrap();

        list.update_timestamp_info_tlvs(SyncSource::Ptp, TimestampMethod::HwAssist);

        // Value should be unchanged since size didn't match
        assert_eq!(list.non_hmac_tlvs()[0].value, vec![1, 2, 3]);
    }

    #[test]
    fn test_update_direct_measurement_tlvs() {
        let mut list = TlvList::new();
        let sender_tlv = DirectMeasurementTlv::new(100);
        list.push(sender_tlv.to_raw()).unwrap();

        list.update_direct_measurement_tlvs(50, 49);

        let raw = &list.non_hmac_tlvs()[0];
        let parsed = DirectMeasurementTlv::from_raw(raw).unwrap();
        // Sender tx count preserved
        assert_eq!(parsed.sender_tx_count, 100);
        // Reflector counts filled
        assert_eq!(parsed.reflector_rx_count, 50);
        assert_eq!(parsed.reflector_tx_count, 49);
    }

    #[test]
    fn test_update_direct_measurement_skips_wrong_size() {
        let mut list = TlvList::new();
        list.push(RawTlv::new(TlvType::DirectMeasurement, vec![0; 8]))
            .unwrap();

        list.update_direct_measurement_tlvs(50, 49);

        // Value should be unchanged
        assert_eq!(list.non_hmac_tlvs()[0].value, vec![0; 8]);
    }

    #[test]
    fn test_update_location_tlvs_ipv4() {
        use std::net::{IpAddr, Ipv4Addr};

        let mut list = TlvList::new();
        let sender_tlv = LocationTlv::new();
        list.push(sender_tlv.to_raw()).unwrap();

        let info = PacketAddressInfo {
            src_addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            src_port: 50000,
            dst_addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            dst_port: 862,
        };
        list.update_location_tlvs(&info);

        let raw = &list.non_hmac_tlvs()[0];
        let parsed = LocationTlv::from_raw(raw).unwrap();
        assert_eq!(parsed.dest_port, 862);
        assert_eq!(parsed.src_port, 50000);
        assert_eq!(parsed.sub_tlvs.len(), 2);
        assert_eq!(parsed.sub_tlvs[0].sub_type, LocationSubType::Ipv4Src);
        assert_eq!(parsed.sub_tlvs[0].value, vec![10, 0, 0, 1]);
        assert_eq!(parsed.sub_tlvs[1].sub_type, LocationSubType::Ipv4Dst);
        assert_eq!(parsed.sub_tlvs[1].value, vec![10, 0, 0, 2]);
    }

    #[test]
    fn test_update_location_tlvs_ipv6() {
        use std::net::{IpAddr, Ipv6Addr};

        let mut list = TlvList::new();
        let sender_tlv = LocationTlv::new();
        list.push(sender_tlv.to_raw()).unwrap();

        let src = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        let dst = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2);
        let info = PacketAddressInfo {
            src_addr: IpAddr::V6(src),
            src_port: 50000,
            dst_addr: IpAddr::V6(dst),
            dst_port: 862,
        };
        list.update_location_tlvs(&info);

        let raw = &list.non_hmac_tlvs()[0];
        let parsed = LocationTlv::from_raw(raw).unwrap();
        assert_eq!(parsed.dest_port, 862);
        assert_eq!(parsed.src_port, 50000);
        assert_eq!(parsed.sub_tlvs.len(), 2);
        assert_eq!(parsed.sub_tlvs[0].sub_type, LocationSubType::Ipv6Src);
        assert_eq!(parsed.sub_tlvs[0].value, src.octets().to_vec());
        assert_eq!(parsed.sub_tlvs[1].sub_type, LocationSubType::Ipv6Dst);
        assert_eq!(parsed.sub_tlvs[1].value, dst.octets().to_vec());
    }

    #[test]
    fn test_update_follow_up_telemetry_tlvs() {
        let mut list = TlvList::new();
        let sender_tlv = FollowUpTelemetryTlv::new();
        list.push(sender_tlv.to_raw()).unwrap();

        list.update_follow_up_telemetry_tlvs(42, 0xDEADBEEFCAFEBABE, TimestampMethod::SwLocal);

        let raw = &list.non_hmac_tlvs()[0];
        let parsed = FollowUpTelemetryTlv::from_raw(raw).unwrap();
        assert_eq!(parsed.sequence_number, 42);
        assert_eq!(parsed.follow_up_timestamp, 0xDEADBEEFCAFEBABE);
        assert_eq!(parsed.timestamp_mode, TimestampMethod::SwLocal);
    }

    #[test]
    fn test_update_follow_up_telemetry_skips_wrong_size() {
        let mut list = TlvList::new();
        list.push(RawTlv::new(TlvType::FollowUpTelemetry, vec![0; 8]))
            .unwrap();

        list.update_follow_up_telemetry_tlvs(42, 100, TimestampMethod::SwLocal);

        // Value should be unchanged
        assert_eq!(list.non_hmac_tlvs()[0].value, vec![0; 8]);
    }

    // ========================================================================
    // validate_known_tlv_lengths tests
    // ========================================================================

    #[test]
    fn test_validate_known_tlv_lengths_correct_sizes() {
        let mut list = TlvList::new();
        list.push(RawTlv::new(
            TlvType::ClassOfService,
            vec![0; COS_TLV_VALUE_SIZE],
        ))
        .unwrap();
        list.push(RawTlv::new(
            TlvType::AccessReport,
            vec![0; ACCESS_REPORT_TLV_VALUE_SIZE],
        ))
        .unwrap();
        list.push(RawTlv::new(
            TlvType::TimestampInfo,
            vec![0; TIMESTAMP_INFO_TLV_VALUE_SIZE],
        ))
        .unwrap();
        list.push(RawTlv::new(
            TlvType::DirectMeasurement,
            vec![0; DIRECT_MEASUREMENT_TLV_VALUE_SIZE],
        ))
        .unwrap();
        list.push(RawTlv::new(
            TlvType::Location,
            vec![0; LOCATION_TLV_MIN_VALUE_SIZE],
        ))
        .unwrap();
        list.push(RawTlv::new(
            TlvType::FollowUpTelemetry,
            vec![0; FOLLOW_UP_TELEMETRY_TLV_VALUE_SIZE],
        ))
        .unwrap();

        list.validate_known_tlv_lengths();

        // None should be marked malformed
        for tlv in list.non_hmac_tlvs() {
            assert!(
                !tlv.is_malformed(),
                "TLV {:?} should not be malformed",
                tlv.tlv_type
            );
        }
    }

    #[test]
    fn test_validate_known_tlv_lengths_wrong_sizes() {
        let mut list = TlvList::new();
        list.push(RawTlv::new(TlvType::ClassOfService, vec![0; 2]))
            .unwrap(); // Wrong: needs 4
        list.push(RawTlv::new(TlvType::AccessReport, vec![0; 5]))
            .unwrap(); // Wrong: needs 2
        list.push(RawTlv::new(TlvType::TimestampInfo, vec![0; 1]))
            .unwrap(); // Wrong: needs 4
        list.push(RawTlv::new(TlvType::DirectMeasurement, vec![0; 8]))
            .unwrap(); // Wrong: needs 12
        list.push(RawTlv::new(TlvType::Location, vec![0; 2]))
            .unwrap(); // Wrong: min 4
        list.push(RawTlv::new(TlvType::FollowUpTelemetry, vec![0; 10]))
            .unwrap(); // Wrong: needs 16

        list.validate_known_tlv_lengths();

        // All should be marked malformed
        for tlv in list.non_hmac_tlvs() {
            assert!(
                tlv.is_malformed(),
                "TLV {:?} should be malformed",
                tlv.tlv_type
            );
        }
    }

    #[test]
    fn test_validate_known_tlv_lengths_location_longer_ok() {
        let mut list = TlvList::new();
        // Location with sub-TLVs (longer than minimum) should be fine
        list.push(RawTlv::new(TlvType::Location, vec![0; 20]))
            .unwrap();

        list.validate_known_tlv_lengths();

        assert!(!list.non_hmac_tlvs()[0].is_malformed());
    }

    #[test]
    fn test_validate_known_tlv_lengths_unknown_types_ignored() {
        let mut list = TlvList::new();
        // Unknown type with any length should not be marked malformed
        list.push(RawTlv::new(TlvType::Unknown(99), vec![0; 3]))
            .unwrap();

        list.validate_known_tlv_lengths();

        assert!(!list.non_hmac_tlvs()[0].is_malformed());
    }

    // ===== RFC 9503 Tests =====

    #[test]
    fn test_destination_node_address_ipv4_roundtrip() {
        let addr = "192.168.1.1".parse::<std::net::IpAddr>().unwrap();
        let tlv = DestinationNodeAddressTlv::new(addr);
        let raw = tlv.to_raw();
        assert_eq!(raw.tlv_type, TlvType::DestinationNodeAddress);
        assert_eq!(raw.value.len(), 4);

        let parsed = DestinationNodeAddressTlv::from_raw(&raw).unwrap();
        assert_eq!(parsed.address, addr);
    }

    #[test]
    fn test_destination_node_address_ipv6_roundtrip() {
        let addr = "2001:db8::1".parse::<std::net::IpAddr>().unwrap();
        let tlv = DestinationNodeAddressTlv::new(addr);
        let raw = tlv.to_raw();
        assert_eq!(raw.tlv_type, TlvType::DestinationNodeAddress);
        assert_eq!(raw.value.len(), 16);

        let parsed = DestinationNodeAddressTlv::from_raw(&raw).unwrap();
        assert_eq!(parsed.address, addr);
    }

    #[test]
    fn test_destination_node_address_invalid_length() {
        let raw = RawTlv::new(TlvType::DestinationNodeAddress, vec![0; 8]);
        let result = DestinationNodeAddressTlv::from_raw(&raw);
        assert!(matches!(
            result,
            Err(TlvError::InvalidDestinationNodeAddressLength(8))
        ));
    }

    #[test]
    fn test_return_path_sub_type_roundtrip() {
        for (byte, expected) in [
            (1, ReturnPathSubType::ControlCode),
            (2, ReturnPathSubType::ReturnAddress),
            (3, ReturnPathSubType::SrMplsLabelStack),
            (4, ReturnPathSubType::Srv6SegmentList),
            (99, ReturnPathSubType::Unknown(99)),
        ] {
            let sub_type = ReturnPathSubType::from_byte(byte);
            assert_eq!(sub_type, expected);
            assert_eq!(sub_type.to_byte(), byte);
        }
    }

    #[test]
    fn test_return_path_control_code_roundtrip() {
        let rp = ReturnPathTlv::with_control_code(0x1);
        let raw = rp.to_raw();
        assert_eq!(raw.tlv_type, TlvType::ReturnPath);

        let parsed = ReturnPathTlv::from_raw(&raw).unwrap();
        assert_eq!(parsed.get_control_code(), Some(0x1));
        assert!(parsed.get_return_address().is_none());
        assert!(!parsed.has_sr_mpls());
        assert!(!parsed.has_srv6());
    }

    #[test]
    fn test_return_path_return_address_ipv4_roundtrip() {
        let addr: std::net::IpAddr = "10.0.0.1".parse().unwrap();
        let rp = ReturnPathTlv::with_return_address(addr);
        let raw = rp.to_raw();

        let parsed = ReturnPathTlv::from_raw(&raw).unwrap();
        assert_eq!(parsed.get_return_address(), Some(addr));
        assert!(parsed.get_control_code().is_none());
    }

    #[test]
    fn test_return_path_return_address_ipv6_roundtrip() {
        let addr: std::net::IpAddr = "2001:db8::1".parse().unwrap();
        let rp = ReturnPathTlv::with_return_address(addr);
        let raw = rp.to_raw();

        let parsed = ReturnPathTlv::from_raw(&raw).unwrap();
        assert_eq!(parsed.get_return_address(), Some(addr));
    }

    #[test]
    fn test_return_path_sr_mpls_roundtrip() {
        let labels = vec![100, 200, 300];
        let rp = ReturnPathTlv::with_sr_mpls_labels(&labels);
        let raw = rp.to_raw();

        let parsed = ReturnPathTlv::from_raw(&raw).unwrap();
        assert!(parsed.has_sr_mpls());
        assert!(!parsed.has_srv6());

        // Verify proper MPLS LSE encoding: Label(20)|TC(3)|S(1)|TTL(8)
        let sr_sub = parsed
            .sub_tlvs
            .iter()
            .find(|s| s.tlv_type.to_byte() == ReturnPathSubType::SrMplsLabelStack.to_byte())
            .unwrap();
        assert_eq!(sr_sub.value.len(), 12); // 3 labels × 4 bytes
        let lse0 = u32::from_be_bytes(sr_sub.value[0..4].try_into().unwrap());
        let lse1 = u32::from_be_bytes(sr_sub.value[4..8].try_into().unwrap());
        let lse2 = u32::from_be_bytes(sr_sub.value[8..12].try_into().unwrap());
        // Label field (top 20 bits)
        assert_eq!(lse0 >> 12, 100);
        assert_eq!(lse1 >> 12, 200);
        assert_eq!(lse2 >> 12, 300);
        // S-bit (bit 8) — only set on last entry
        assert_eq!(lse0 & 0x100, 0);
        assert_eq!(lse1 & 0x100, 0);
        assert_eq!(lse2 & 0x100, 0x100);
        // TTL (bottom 8 bits) = 255
        assert_eq!(lse0 & 0xFF, 255);
        assert_eq!(lse1 & 0xFF, 255);
        assert_eq!(lse2 & 0xFF, 255);
        // TC (bits 11-9) = 0
        assert_eq!(lse0 & 0xE00, 0);
    }

    #[test]
    fn test_return_path_srv6_roundtrip() {
        let sids = vec![
            "2001:db8::1".parse::<std::net::Ipv6Addr>().unwrap(),
            "2001:db8::2".parse::<std::net::Ipv6Addr>().unwrap(),
        ];
        let rp = ReturnPathTlv::with_srv6_sids(&sids);
        let raw = rp.to_raw();

        let parsed = ReturnPathTlv::from_raw(&raw).unwrap();
        assert!(!parsed.has_sr_mpls());
        assert!(parsed.has_srv6());
    }

    #[test]
    fn test_return_path_empty_value_error() {
        let raw = RawTlv::new(TlvType::ReturnPath, vec![0; 2]);
        let result = ReturnPathTlv::from_raw(&raw);
        assert!(matches!(result, Err(TlvError::InvalidReturnPathLength(2))));
    }

    #[test]
    fn test_validate_destination_node_address_correct_sizes() {
        // IPv4 (4 bytes) — should NOT be malformed
        let mut list = TlvList::new();
        list.push(RawTlv::new(TlvType::DestinationNodeAddress, vec![0; 4]))
            .unwrap();
        list.validate_known_tlv_lengths();
        assert!(!list.non_hmac_tlvs()[0].is_malformed());

        // IPv6 (16 bytes) — should NOT be malformed
        let mut list = TlvList::new();
        list.push(RawTlv::new(TlvType::DestinationNodeAddress, vec![0; 16]))
            .unwrap();
        list.validate_known_tlv_lengths();
        assert!(!list.non_hmac_tlvs()[0].is_malformed());
    }

    #[test]
    fn test_validate_destination_node_address_wrong_size() {
        let mut list = TlvList::new();
        list.push(RawTlv::new(TlvType::DestinationNodeAddress, vec![0; 8]))
            .unwrap();
        list.validate_known_tlv_lengths();
        assert!(list.non_hmac_tlvs()[0].is_malformed());
    }

    #[test]
    fn test_validate_return_path_correct_size() {
        // Minimum valid: 4 bytes (one sub-TLV header)
        let mut list = TlvList::new();
        list.push(RawTlv::new(TlvType::ReturnPath, vec![0; 4]))
            .unwrap();
        list.validate_known_tlv_lengths();
        assert!(!list.non_hmac_tlvs()[0].is_malformed());
    }

    #[test]
    fn test_validate_return_path_wrong_size() {
        let mut list = TlvList::new();
        list.push(RawTlv::new(TlvType::ReturnPath, vec![0; 2]))
            .unwrap();
        list.validate_known_tlv_lengths();
        assert!(list.non_hmac_tlvs()[0].is_malformed());
    }

    #[test]
    fn test_process_destination_node_address_match() {
        let addr: std::net::IpAddr = "192.168.1.1".parse().unwrap();
        let tlv = DestinationNodeAddressTlv::new(addr);
        let mut list = TlvList::new();
        list.push(tlv.to_raw()).unwrap();

        let local_addrs = vec![addr];
        let matched = list.process_destination_node_address(&local_addrs);
        assert!(matched);
        assert!(!list.non_hmac_tlvs()[0].is_unrecognized());
    }

    #[test]
    fn test_process_destination_node_address_mismatch() {
        let addr: std::net::IpAddr = "192.168.1.1".parse().unwrap();
        let tlv = DestinationNodeAddressTlv::new(addr);
        let mut list = TlvList::new();
        list.push(tlv.to_raw()).unwrap();

        let local_addrs = vec!["10.0.0.1".parse().unwrap()];
        let matched = list.process_destination_node_address(&local_addrs);
        assert!(!matched);
        assert!(list.non_hmac_tlvs()[0].is_unrecognized());
    }

    #[test]
    fn test_process_return_path_suppress() {
        let rp = ReturnPathTlv::with_control_code(0x0);
        let mut list = TlvList::new();
        list.push(rp.to_raw()).unwrap();

        let action = list.process_return_path(1234);
        assert_eq!(action, ReturnPathAction::SuppressReply);
    }

    #[test]
    fn test_process_return_path_normal() {
        let rp = ReturnPathTlv::with_control_code(0x1);
        let mut list = TlvList::new();
        list.push(rp.to_raw()).unwrap();

        let action = list.process_return_path(1234);
        assert_eq!(action, ReturnPathAction::Normal);
    }

    #[test]
    fn test_process_return_path_cc_reserved_bits_suppress() {
        // RFC 9503: only bit 0 matters; reserved bits are ignored.
        // 0xFE has bit 0 clear → suppress.
        let rp = ReturnPathTlv::with_control_code(0xFE);
        let mut list = TlvList::new();
        list.push(rp.to_raw()).unwrap();

        let action = list.process_return_path(1234);
        assert_eq!(action, ReturnPathAction::SuppressReply);
    }

    #[test]
    fn test_process_return_path_cc_reserved_bits_normal() {
        // RFC 9503: only bit 0 matters; reserved bits are ignored.
        // 0xFF has bit 0 set → normal reply.
        let rp = ReturnPathTlv::with_control_code(0xFF);
        let mut list = TlvList::new();
        list.push(rp.to_raw()).unwrap();

        let action = list.process_return_path(1234);
        assert_eq!(action, ReturnPathAction::Normal);
    }

    #[test]
    fn test_process_return_path_alternate_addr() {
        let addr: std::net::IpAddr = "10.0.0.5".parse().unwrap();
        let rp = ReturnPathTlv::with_return_address(addr);
        let mut list = TlvList::new();
        list.push(rp.to_raw()).unwrap();

        let action = list.process_return_path(862);
        assert_eq!(
            action,
            ReturnPathAction::AlternateAddress(std::net::SocketAddr::new(addr, 862))
        );
    }

    #[test]
    fn test_process_return_path_sr_unsupported() {
        let rp = ReturnPathTlv::with_sr_mpls_labels(&[100, 200]);
        let mut list = TlvList::new();
        list.push(rp.to_raw()).unwrap();

        let action = list.process_return_path(862);
        assert_eq!(action, ReturnPathAction::UnsupportedSr);
        assert!(list.non_hmac_tlvs()[0].is_unrecognized());
    }

    #[test]
    fn test_tlv_type_is_recognized_for_rfc9503_types() {
        assert!(TlvType::DestinationNodeAddress.is_recognized());
        assert!(TlvType::ReturnPath.is_recognized());
    }

    #[test]
    fn test_return_path_add_return_address() {
        let labels = vec![100, 200];
        let mut rp = ReturnPathTlv::with_sr_mpls_labels(&labels);
        let addr: std::net::IpAddr = "10.0.0.1".parse().unwrap();
        rp.add_return_address(addr);

        let raw = rp.to_raw();
        let parsed = ReturnPathTlv::from_raw(&raw).unwrap();
        assert!(parsed.has_sr_mpls());
        assert_eq!(parsed.get_return_address(), Some(addr));
    }
}
