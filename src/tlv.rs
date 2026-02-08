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
    /// Unknown type (9-15).
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
        // Use preserved wire length for truncated TLVs, otherwise actual value length
        let length = self.wire_length.unwrap_or(self.value.len() as u16);
        let mut buf = Vec::with_capacity(TLV_HEADER_SIZE + self.value.len());

        // Byte 0: Flags (1 octet)
        buf.push(self.flags.to_byte());

        // Byte 1: Type (1 octet)
        buf.push(self.tlv_type.to_byte());

        // Bytes 2-3: Length (2 octets, big-endian)
        buf.extend_from_slice(&length.to_be_bytes());

        // Value (only the bytes we actually have)
        buf.extend_from_slice(&self.value);

        buf
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
        let mut list = Self::new();
        let mut wire_order: Vec<RawTlv> = Vec::new();
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

                    // Always add to wire_order for potential failure echo
                    wire_order.push(tlv.clone());

                    // Also populate separated fields for normal operations
                    if tlv.tlv_type.is_hmac() {
                        list.hmac_tlv = Some(tlv);
                    } else {
                        list.tlvs.push(tlv);
                    }

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

        // Preserve wire order if there are issues that require exact echo
        // (malformed TLVs, multiple HMACs, or TLVs after HMAC)
        if any_malformed || has_multiple_hmac {
            list.wire_order_tlvs = Some(wire_order);
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
        // Use wire-order if available (for failure echo)
        if let Some(ref wire_order) = self.wire_order_tlvs {
            let total_size: usize = wire_order.iter().map(|t| t.wire_size()).sum();
            let mut buf = Vec::with_capacity(total_size);
            for tlv in wire_order {
                buf.extend_from_slice(&tlv.to_bytes());
            }
            return buf;
        }

        // Normal mode: non-HMAC TLVs first, HMAC last
        let total_size: usize = self.iter().map(|t| t.wire_size()).sum();
        let mut buf = Vec::with_capacity(total_size);

        for tlv in &self.tlvs {
            buf.extend_from_slice(&tlv.to_bytes());
        }

        if let Some(ref hmac) = self.hmac_tlv {
            buf.extend_from_slice(&hmac.to_bytes());
        }

        buf
    }

    /// Returns the total wire size of all TLVs.
    #[must_use]
    pub fn wire_size(&self) -> usize {
        self.iter().map(|t| t.wire_size()).sum()
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

        // Per RFC 8972 §4.8: HMAC covers Sequence Number + preceding TLVs
        let non_hmac_size: usize = self.tlvs.iter().map(|t| t.wire_size()).sum();

        // Build data to verify: Sequence Number (4 bytes) + preceding TLVs
        let mut data = Vec::with_capacity(4 + non_hmac_size);
        if sequence_number_bytes.len() >= 4 {
            data.extend_from_slice(&sequence_number_bytes[..4]);
        } else {
            data.extend_from_slice(sequence_number_bytes);
        }
        if non_hmac_size <= tlv_bytes.len() {
            data.extend_from_slice(&tlv_bytes[..non_hmac_size]);
        }

        let expected: [u8; 16] = hmac_tlv
            .value
            .as_slice()
            .try_into()
            .map_err(|_| TlvError::InvalidHmacLength(hmac_tlv.value.len()))?;

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

        // Per RFC 8972 §4.8: HMAC covers Sequence Number + preceding TLVs
        let non_hmac_size: usize = self.tlvs.iter().map(|t| t.wire_size()).sum();

        let mut data = Vec::with_capacity(4 + non_hmac_size);
        if sequence_number_bytes.len() >= 4 {
            data.extend_from_slice(&sequence_number_bytes[..4]);
        } else {
            data.extend_from_slice(sequence_number_bytes);
        }
        if non_hmac_size <= tlv_bytes.len() {
            data.extend_from_slice(&tlv_bytes[..non_hmac_size]);
        }

        let Ok(expected): Result<[u8; 16], _> = hmac_tlv.value.as_slice().try_into() else {
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
        let mut data = Vec::with_capacity(4 + self.wire_size());

        // Sequence Number field (first 4 bytes)
        if sequence_number_bytes.len() >= 4 {
            data.extend_from_slice(&sequence_number_bytes[..4]);
        } else {
            data.extend_from_slice(sequence_number_bytes);
        }

        // All preceding TLVs (non-HMAC)
        for tlv in &self.tlvs {
            data.extend_from_slice(&tlv.to_bytes());
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
            true
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
        assert_eq!(TlvType::from_byte(9), TlvType::Unknown(9));
        assert_eq!(TlvType::from_byte(15), TlvType::Unknown(15));
        assert_eq!(TlvType::from_byte(200), TlvType::Unknown(200));
    }

    #[test]
    fn test_tlv_type_to_byte() {
        assert_eq!(TlvType::Reserved.to_byte(), 0);
        assert_eq!(TlvType::ExtraPadding.to_byte(), 1);
        assert_eq!(TlvType::Hmac.to_byte(), 8);
        assert_eq!(TlvType::Unknown(10).to_byte(), 10);
        assert_eq!(TlvType::Unknown(200).to_byte(), 200);
    }

    #[test]
    fn test_tlv_type_is_recognized() {
        assert!(TlvType::ExtraPadding.is_recognized());
        assert!(TlvType::Hmac.is_recognized());
        assert!(!TlvType::Reserved.is_recognized());
        assert!(!TlvType::Unknown(9).is_recognized());
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
}
