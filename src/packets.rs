//! STAMP packet structures as defined in RFC 8762 and RFC 8972.
//!
//! This module contains the packet formats for both authenticated and unauthenticated
//! STAMP test packets, as well as their reflected counterparts.
//!
//! These are in-memory representations. Wire format serialization is handled
//! explicitly by `to_bytes()` and `from_bytes()` methods with big-endian encoding.

use thiserror::Error;

use crate::tlv::{TlvError, TlvList};

/// Errors that can occur during packet parsing or processing.
#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum PacketError {
    /// Buffer is too small for the packet type.
    #[error("Buffer too small: expected at least {expected} bytes, got {actual}")]
    BufferTooSmall { expected: usize, actual: usize },

    /// TLV parsing or validation error.
    #[error("TLV error: {0}")]
    TlvError(#[from] TlvError),
}

// ============================================================================
// Wire format parsing helpers
// ============================================================================

/// Checks that buffer has at least `expected` bytes.
#[inline]
fn check_size(buf: &[u8], expected: usize) -> Result<(), PacketError> {
    if buf.len() < expected {
        Err(PacketError::BufferTooSmall {
            expected,
            actual: buf.len(),
        })
    } else {
        Ok(())
    }
}

/// Reads a big-endian u16 from buffer at given offset.
///
/// # Safety invariant
/// Caller must ensure `offset + 2 <= buf.len()`. This is checked via debug_assert.
#[inline]
fn read_u16(buf: &[u8], offset: usize) -> u16 {
    debug_assert!(
        offset + 2 <= buf.len(),
        "read_u16: offset {} + 2 exceeds buffer length {}",
        offset,
        buf.len()
    );
    // SAFETY: debug_assert ensures bounds; slice length is exactly 2
    u16::from_be_bytes([buf[offset], buf[offset + 1]])
}

/// Reads a big-endian u32 from buffer at given offset.
///
/// # Safety invariant
/// Caller must ensure `offset + 4 <= buf.len()`. This is checked via debug_assert.
#[inline]
fn read_u32(buf: &[u8], offset: usize) -> u32 {
    debug_assert!(
        offset + 4 <= buf.len(),
        "read_u32: offset {} + 4 exceeds buffer length {}",
        offset,
        buf.len()
    );
    // SAFETY: debug_assert ensures bounds; slice length is exactly 4
    u32::from_be_bytes([
        buf[offset],
        buf[offset + 1],
        buf[offset + 2],
        buf[offset + 3],
    ])
}

/// Reads a big-endian u64 from buffer at given offset.
///
/// # Safety invariant
/// Caller must ensure `offset + 8 <= buf.len()`. This is checked via debug_assert.
#[inline]
fn read_u64(buf: &[u8], offset: usize) -> u64 {
    debug_assert!(
        offset + 8 <= buf.len(),
        "read_u64: offset {} + 8 exceeds buffer length {}",
        offset,
        buf.len()
    );
    // SAFETY: debug_assert ensures bounds; slice length is exactly 8
    u64::from_be_bytes([
        buf[offset],
        buf[offset + 1],
        buf[offset + 2],
        buf[offset + 3],
        buf[offset + 4],
        buf[offset + 5],
        buf[offset + 6],
        buf[offset + 7],
    ])
}

/// Copies a fixed-size array from buffer at given offset.
///
/// # Safety invariant
/// Caller must ensure `offset + N <= buf.len()`. This is checked via debug_assert.
#[inline]
fn read_array<const N: usize>(buf: &[u8], offset: usize) -> [u8; N] {
    debug_assert!(
        offset + N <= buf.len(),
        "read_array<{}>: offset {} + {} exceeds buffer length {}",
        N,
        offset,
        N,
        buf.len()
    );
    // SAFETY: debug_assert ensures bounds; try_into succeeds because slice length equals N
    buf[offset..offset + N].try_into().unwrap()
}

/// Unauthenticated STAMP test packet sent by the Session-Sender.
///
/// This is the basic packet format without HMAC authentication (44 bytes).
/// See RFC 8762 Section 4.2.
///
/// Wire format:
/// ```text
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                        Sequence Number                       |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                          Timestamp                           |
/// |                                                               |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |         Error Estimate        |                               |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               +
/// |                                                               |
/// |                         MBZ (30 octets)                       |
/// |                                                               |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct PacketUnauthenticated {
    /// Packet sequence number for ordering and loss detection.
    pub sequence_number: u32,
    /// Timestamp when the packet was sent (NTP or PTP format).
    pub timestamp: u64,
    /// Error estimate for the timestamp.
    pub error_estimate: u16,
    /// Must Be Zero - reserved padding bytes.
    pub mbz: [u8; 30],
}

impl PacketUnauthenticated {
    /// Serializes the packet to a 44-byte array in big-endian wire format.
    pub fn to_bytes(&self) -> [u8; 44] {
        let mut buf = [0u8; 44];
        buf[0..4].copy_from_slice(&self.sequence_number.to_be_bytes());
        buf[4..12].copy_from_slice(&self.timestamp.to_be_bytes());
        buf[12..14].copy_from_slice(&self.error_estimate.to_be_bytes());
        buf[14..44].copy_from_slice(&self.mbz);
        buf
    }

    /// Deserializes a packet from big-endian wire format.
    ///
    /// # Errors
    /// Returns an error if the buffer is smaller than 44 bytes.
    pub fn from_bytes(buf: &[u8]) -> Result<Self, PacketError> {
        check_size(buf, 44)?;
        Ok(Self {
            sequence_number: read_u32(buf, 0),
            timestamp: read_u64(buf, 4),
            error_estimate: read_u16(buf, 12),
            mbz: read_array(buf, 14),
        })
    }

    /// Deserializes a packet with zero-fill for missing bytes (RFC 8762 Section 4.6).
    ///
    /// This method enables interoperability with TWAMP-Light implementations that
    /// may send packets smaller than the base 44 bytes. Missing bytes are zero-filled.
    pub fn from_bytes_lenient(buf: &[u8]) -> Self {
        let mut padded = [0u8; 44];
        let copy_len = buf.len().min(44);
        padded[..copy_len].copy_from_slice(&buf[..copy_len]);

        Self {
            sequence_number: read_u32(&padded, 0),
            timestamp: read_u64(&padded, 4),
            error_estimate: read_u16(&padded, 12),
            mbz: read_array(&padded, 14),
        }
    }
}

/// Unauthenticated STAMP reflected packet sent by the Session-Reflector.
///
/// Contains the original sender information plus reflector timestamps (44 bytes).
/// See RFC 8762 Section 4.3.
///
/// Wire format:
/// ```text
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                        Sequence Number                       |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                          Timestamp                           |
/// |                                                               |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |         Error Estimate        |           MBZ                 |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                       Receive Timestamp                       |
/// |                                                               |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                  Session-Sender Seq Number                    |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                  Session-Sender Timestamp                     |
/// |                                                               |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// | Session-Sender Error Estimate |           MBZ                 |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |Ses-Sender TTL |                      MBZ                      |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct ReflectedPacketUnauthenticated {
    /// Reflector's sequence number.
    pub sequence_number: u32,
    /// Timestamp when the reflector sent the response.
    pub timestamp: u64,
    /// Reflector's error estimate.
    pub error_estimate: u16,
    /// Must Be Zero - reserved.
    pub mbz1: u16,
    /// Timestamp when the reflector received the test packet.
    pub receive_timestamp: u64,
    /// Original sender's sequence number (echoed back).
    pub sess_sender_seq_number: u32,
    /// Original sender's timestamp (echoed back).
    pub sess_sender_timestamp: u64,
    /// Original sender's error estimate (echoed back).
    pub sess_sender_err_estimate: u16,
    /// Must Be Zero - reserved.
    pub mbz2: u16,
    /// TTL/Hop Limit of the received test packet.
    pub sess_sender_ttl: u8,
    /// Must Be Zero - reserved (3 bytes).
    pub mbz3: [u8; 3],
}

impl ReflectedPacketUnauthenticated {
    /// Serializes the packet to a 44-byte array in big-endian wire format.
    pub fn to_bytes(&self) -> [u8; 44] {
        let mut buf = [0u8; 44];
        buf[0..4].copy_from_slice(&self.sequence_number.to_be_bytes());
        buf[4..12].copy_from_slice(&self.timestamp.to_be_bytes());
        buf[12..14].copy_from_slice(&self.error_estimate.to_be_bytes());
        buf[14..16].copy_from_slice(&self.mbz1.to_be_bytes());
        buf[16..24].copy_from_slice(&self.receive_timestamp.to_be_bytes());
        buf[24..28].copy_from_slice(&self.sess_sender_seq_number.to_be_bytes());
        buf[28..36].copy_from_slice(&self.sess_sender_timestamp.to_be_bytes());
        buf[36..38].copy_from_slice(&self.sess_sender_err_estimate.to_be_bytes());
        buf[38..40].copy_from_slice(&self.mbz2.to_be_bytes());
        buf[40] = self.sess_sender_ttl;
        buf[41..44].copy_from_slice(&self.mbz3);
        buf
    }

    /// Deserializes a packet from big-endian wire format.
    ///
    /// # Errors
    /// Returns an error if the buffer is smaller than 44 bytes.
    pub fn from_bytes(buf: &[u8]) -> Result<Self, PacketError> {
        check_size(buf, 44)?;
        Ok(Self {
            sequence_number: read_u32(buf, 0),
            timestamp: read_u64(buf, 4),
            error_estimate: read_u16(buf, 12),
            mbz1: read_u16(buf, 14),
            receive_timestamp: read_u64(buf, 16),
            sess_sender_seq_number: read_u32(buf, 24),
            sess_sender_timestamp: read_u64(buf, 28),
            sess_sender_err_estimate: read_u16(buf, 36),
            mbz2: read_u16(buf, 38),
            sess_sender_ttl: buf[40],
            mbz3: read_array(buf, 41),
        })
    }

    /// Deserializes a packet leniently, zero-filling missing bytes per RFC 8762 §4.6.
    ///
    /// Short packets are accepted and missing bytes are treated as zero.
    #[must_use]
    pub fn from_bytes_lenient(buf: &[u8]) -> Self {
        let mut padded = [0u8; 44];
        let copy_len = buf.len().min(44);
        padded[..copy_len].copy_from_slice(&buf[..copy_len]);

        Self {
            sequence_number: read_u32(&padded, 0),
            timestamp: read_u64(&padded, 4),
            error_estimate: read_u16(&padded, 12),
            mbz1: read_u16(&padded, 14),
            receive_timestamp: read_u64(&padded, 16),
            sess_sender_seq_number: read_u32(&padded, 24),
            sess_sender_timestamp: read_u64(&padded, 28),
            sess_sender_err_estimate: read_u16(&padded, 36),
            mbz2: read_u16(&padded, 38),
            sess_sender_ttl: padded[40],
            mbz3: read_array(&padded, 41),
        }
    }
}

/// Authenticated STAMP test packet sent by the Session-Sender.
///
/// Includes HMAC for integrity verification (112 bytes).
/// See RFC 8762 Section 4.4.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct PacketAuthenticated {
    /// Packet sequence number for ordering and loss detection.
    pub sequence_number: u32,
    /// Must Be Zero - reserved padding (12 bytes).
    pub mbz0: [u8; 12],
    /// Timestamp when the packet was sent (NTP or PTP format).
    pub timestamp: u64,
    /// Error estimate for the timestamp.
    pub error_estimate: u16,
    /// Must Be Zero - reserved padding (70 bytes total = 32+32+6).
    pub mbz1a: [u8; 32],
    pub mbz1b: [u8; 32],
    pub mbz1c: [u8; 6],
    /// HMAC for packet authentication.
    pub hmac: [u8; 16],
}

impl PacketAuthenticated {
    /// Serializes the packet to a 112-byte array in big-endian wire format.
    pub fn to_bytes(&self) -> [u8; 112] {
        let mut buf = [0u8; 112];
        buf[0..4].copy_from_slice(&self.sequence_number.to_be_bytes());
        buf[4..16].copy_from_slice(&self.mbz0);
        buf[16..24].copy_from_slice(&self.timestamp.to_be_bytes());
        buf[24..26].copy_from_slice(&self.error_estimate.to_be_bytes());
        buf[26..58].copy_from_slice(&self.mbz1a);
        buf[58..90].copy_from_slice(&self.mbz1b);
        buf[90..96].copy_from_slice(&self.mbz1c);
        buf[96..112].copy_from_slice(&self.hmac);
        buf
    }

    /// Deserializes a packet from big-endian wire format.
    ///
    /// # Errors
    /// Returns an error if the buffer is smaller than 112 bytes.
    pub fn from_bytes(buf: &[u8]) -> Result<Self, PacketError> {
        check_size(buf, 112)?;
        Ok(Self {
            sequence_number: read_u32(buf, 0),
            mbz0: read_array(buf, 4),
            timestamp: read_u64(buf, 16),
            error_estimate: read_u16(buf, 24),
            mbz1a: read_array(buf, 26),
            mbz1b: read_array(buf, 58),
            mbz1c: read_array(buf, 90),
            hmac: read_array(buf, 96),
        })
    }

    /// Deserializes a packet with zero-fill for missing bytes (RFC 8762 Section 4.6).
    ///
    /// This method enables interoperability with TWAMP-Light implementations that
    /// may send packets smaller than the base 112 bytes. Missing bytes are zero-filled.
    pub fn from_bytes_lenient(buf: &[u8]) -> Self {
        let (packet, _) = Self::from_bytes_lenient_with_canonical(buf);
        packet
    }

    /// Deserializes a packet leniently and returns the canonical zero-padded buffer.
    ///
    /// Returns the parsed packet and the canonical 112-byte buffer for HMAC verification.
    /// This is needed because HMAC must be verified against the canonical (zero-padded)
    /// representation per RFC 8762 §4.6.
    #[must_use]
    pub fn from_bytes_lenient_with_canonical(buf: &[u8]) -> (Self, [u8; 112]) {
        let mut padded = [0u8; 112];
        let copy_len = buf.len().min(112);
        padded[..copy_len].copy_from_slice(&buf[..copy_len]);

        let packet = Self {
            sequence_number: read_u32(&padded, 0),
            mbz0: read_array(&padded, 4),
            timestamp: read_u64(&padded, 16),
            error_estimate: read_u16(&padded, 24),
            mbz1a: read_array(&padded, 26),
            mbz1b: read_array(&padded, 58),
            mbz1c: read_array(&padded, 90),
            hmac: read_array(&padded, 96),
        };

        (packet, padded)
    }
}

/// Authenticated STAMP reflected packet sent by the Session-Reflector.
///
/// Contains the original sender information plus reflector timestamps with HMAC (112 bytes).
/// See RFC 8762 Section 4.5.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct ReflectedPacketAuthenticated {
    /// Reflector's sequence number.
    pub sequence_number: u32,
    /// Must Be Zero - reserved padding (12 bytes).
    pub mbz0: [u8; 12],
    /// Timestamp when the reflector sent the response.
    pub timestamp: u64,
    /// Reflector's error estimate.
    pub error_estimate: u16,
    /// Must Be Zero - reserved padding (6 bytes).
    pub mbz1: [u8; 6],
    /// Timestamp when the reflector received the test packet.
    pub receive_timestamp: u64,
    /// Must Be Zero - reserved padding (8 bytes).
    pub mbz2: [u8; 8],
    /// Original sender's sequence number (echoed back).
    pub sess_sender_seq_number: u32,
    /// Must Be Zero - reserved padding (12 bytes).
    pub mbz3: [u8; 12],
    /// Original sender's timestamp (echoed back).
    pub sess_sender_timestamp: u64,
    /// Original sender's error estimate (echoed back).
    pub sess_sender_err_estimate: u16,
    /// Must Be Zero - reserved padding (6 bytes).
    pub mbz4: [u8; 6],
    /// TTL/Hop Limit of the received test packet.
    pub sess_sender_ttl: u8,
    /// Must Be Zero - reserved padding (15 bytes).
    pub mbz5: [u8; 15],
    /// HMAC for packet authentication.
    pub hmac: [u8; 16],
}

impl ReflectedPacketAuthenticated {
    /// Serializes the packet to a 112-byte array in big-endian wire format.
    pub fn to_bytes(&self) -> [u8; 112] {
        let mut buf = [0u8; 112];
        buf[0..4].copy_from_slice(&self.sequence_number.to_be_bytes());
        buf[4..16].copy_from_slice(&self.mbz0);
        buf[16..24].copy_from_slice(&self.timestamp.to_be_bytes());
        buf[24..26].copy_from_slice(&self.error_estimate.to_be_bytes());
        buf[26..32].copy_from_slice(&self.mbz1);
        buf[32..40].copy_from_slice(&self.receive_timestamp.to_be_bytes());
        buf[40..48].copy_from_slice(&self.mbz2);
        buf[48..52].copy_from_slice(&self.sess_sender_seq_number.to_be_bytes());
        buf[52..64].copy_from_slice(&self.mbz3);
        buf[64..72].copy_from_slice(&self.sess_sender_timestamp.to_be_bytes());
        buf[72..74].copy_from_slice(&self.sess_sender_err_estimate.to_be_bytes());
        buf[74..80].copy_from_slice(&self.mbz4);
        buf[80] = self.sess_sender_ttl;
        buf[81..96].copy_from_slice(&self.mbz5);
        buf[96..112].copy_from_slice(&self.hmac);
        buf
    }

    /// Deserializes a packet from big-endian wire format.
    ///
    /// # Errors
    /// Returns an error if the buffer is smaller than 112 bytes.
    pub fn from_bytes(buf: &[u8]) -> Result<Self, PacketError> {
        check_size(buf, 112)?;
        Ok(Self {
            sequence_number: read_u32(buf, 0),
            mbz0: read_array(buf, 4),
            timestamp: read_u64(buf, 16),
            error_estimate: read_u16(buf, 24),
            mbz1: read_array(buf, 26),
            receive_timestamp: read_u64(buf, 32),
            mbz2: read_array(buf, 40),
            sess_sender_seq_number: read_u32(buf, 48),
            mbz3: read_array(buf, 52),
            sess_sender_timestamp: read_u64(buf, 64),
            sess_sender_err_estimate: read_u16(buf, 72),
            mbz4: read_array(buf, 74),
            sess_sender_ttl: buf[80],
            mbz5: read_array(buf, 81),
            hmac: read_array(buf, 96),
        })
    }

    /// Deserializes a packet leniently, zero-filling missing bytes per RFC 8762 §4.6.
    ///
    /// Short packets are accepted and missing bytes are treated as zero.
    /// Returns the parsed packet and the canonical zero-padded buffer for HMAC verification.
    #[must_use]
    pub fn from_bytes_lenient(buf: &[u8]) -> (Self, [u8; 112]) {
        let mut padded = [0u8; 112];
        let copy_len = buf.len().min(112);
        padded[..copy_len].copy_from_slice(&buf[..copy_len]);

        let packet = Self {
            sequence_number: read_u32(&padded, 0),
            mbz0: read_array(&padded, 4),
            timestamp: read_u64(&padded, 16),
            error_estimate: read_u16(&padded, 24),
            mbz1: read_array(&padded, 26),
            receive_timestamp: read_u64(&padded, 32),
            mbz2: read_array(&padded, 40),
            sess_sender_seq_number: read_u32(&padded, 48),
            mbz3: read_array(&padded, 52),
            sess_sender_timestamp: read_u64(&padded, 64),
            sess_sender_err_estimate: read_u16(&padded, 72),
            mbz4: read_array(&padded, 74),
            sess_sender_ttl: padded[80],
            mbz5: read_array(&padded, 81),
            hmac: read_array(&padded, 96),
        };

        (packet, padded)
    }
}

/// Unauthenticated STAMP packet with TLV extensions (RFC 8972).
///
/// Contains the base packet data plus optional TLV extensions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtendedPacketUnauthenticated {
    /// The base unauthenticated packet.
    pub base: PacketUnauthenticated,
    /// TLV extensions following the base packet.
    pub tlvs: TlvList,
}

impl ExtendedPacketUnauthenticated {
    /// Base packet size (44 bytes).
    pub const BASE_SIZE: usize = 44;

    /// Creates a new extended packet with just the base packet.
    #[must_use]
    pub fn new(base: PacketUnauthenticated) -> Self {
        Self {
            base,
            tlvs: TlvList::new(),
        }
    }

    /// Creates a new extended packet with TLVs.
    #[must_use]
    pub fn with_tlvs(base: PacketUnauthenticated, tlvs: TlvList) -> Self {
        Self { base, tlvs }
    }

    /// Parses an extended packet from bytes.
    ///
    /// # Errors
    /// Returns an error if the buffer is too small or TLV parsing fails.
    pub fn from_bytes(buf: &[u8]) -> Result<Self, PacketError> {
        let base = PacketUnauthenticated::from_bytes(buf)?;

        let tlvs = if buf.len() > Self::BASE_SIZE {
            TlvList::parse(&buf[Self::BASE_SIZE..])?
        } else {
            TlvList::new()
        };

        Ok(Self { base, tlvs })
    }

    /// Parses with lenient base packet handling (zero-fills missing bytes).
    pub fn from_bytes_lenient(buf: &[u8]) -> Result<Self, PacketError> {
        let base = PacketUnauthenticated::from_bytes_lenient(buf);

        let tlvs = if buf.len() > Self::BASE_SIZE {
            TlvList::parse(&buf[Self::BASE_SIZE..])?
        } else {
            TlvList::new()
        };

        Ok(Self { base, tlvs })
    }

    /// Serializes the extended packet to bytes.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        // Pre-allocate exact capacity to avoid reallocations
        let mut buf = Vec::with_capacity(Self::BASE_SIZE + self.tlvs.wire_size());
        buf.extend_from_slice(&self.base.to_bytes());
        self.tlvs.write_to(&mut buf);
        buf
    }

    /// Returns the total wire size of the packet.
    #[must_use]
    pub fn wire_size(&self) -> usize {
        Self::BASE_SIZE + self.tlvs.wire_size()
    }

    /// Returns true if the packet has TLV extensions.
    #[must_use]
    pub fn has_tlvs(&self) -> bool {
        !self.tlvs.is_empty()
    }
}

/// Unauthenticated reflected STAMP packet with TLV extensions (RFC 8972).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtendedReflectedPacketUnauthenticated {
    /// The base reflected packet.
    pub base: ReflectedPacketUnauthenticated,
    /// TLV extensions following the base packet.
    pub tlvs: TlvList,
}

impl ExtendedReflectedPacketUnauthenticated {
    /// Base packet size (44 bytes).
    pub const BASE_SIZE: usize = 44;

    /// Creates a new extended packet with just the base packet.
    #[must_use]
    pub fn new(base: ReflectedPacketUnauthenticated) -> Self {
        Self {
            base,
            tlvs: TlvList::new(),
        }
    }

    /// Creates a new extended packet with TLVs.
    #[must_use]
    pub fn with_tlvs(base: ReflectedPacketUnauthenticated, tlvs: TlvList) -> Self {
        Self { base, tlvs }
    }

    /// Serializes the extended packet to bytes.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        // Pre-allocate exact capacity to avoid reallocations
        let mut buf = Vec::with_capacity(Self::BASE_SIZE + self.tlvs.wire_size());
        buf.extend_from_slice(&self.base.to_bytes());
        self.tlvs.write_to(&mut buf);
        buf
    }

    /// Returns the total wire size of the packet.
    #[must_use]
    pub fn wire_size(&self) -> usize {
        Self::BASE_SIZE + self.tlvs.wire_size()
    }

    /// Parses an extended reflected packet from bytes.
    ///
    /// # Errors
    /// Returns an error if the buffer is too small or TLV parsing fails.
    pub fn from_bytes(buf: &[u8]) -> Result<Self, PacketError> {
        let base = ReflectedPacketUnauthenticated::from_bytes(buf)?;

        let tlvs = if buf.len() > Self::BASE_SIZE {
            TlvList::parse(&buf[Self::BASE_SIZE..])?
        } else {
            TlvList::new()
        };

        Ok(Self { base, tlvs })
    }

    /// Parses an extended reflected packet leniently (RFC 8762 §4.6 short-packet support).
    ///
    /// Unlike `from_bytes`, this method:
    /// - Handles short base packets by zero-filling missing bytes
    /// - Handles malformed TLVs by marking them with M-flag rather than failing
    pub fn from_bytes_lenient(buf: &[u8]) -> Self {
        // Use lenient parsing for base packet (zero-fills short packets)
        let base = ReflectedPacketUnauthenticated::from_bytes_lenient(buf);

        let tlvs = if buf.len() > Self::BASE_SIZE {
            let (tlvs, _malformed) = TlvList::parse_lenient(&buf[Self::BASE_SIZE..]);
            tlvs
        } else {
            TlvList::new()
        };

        Self { base, tlvs }
    }

    /// Returns true if the packet has TLV extensions.
    #[must_use]
    pub fn has_tlvs(&self) -> bool {
        !self.tlvs.is_empty()
    }
}

/// Authenticated STAMP packet with TLV extensions (RFC 8972).
///
/// Note: The base packet HMAC covers only the base packet fields.
/// TLV integrity uses a separate HMAC TLV per RFC 8972.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtendedPacketAuthenticated {
    /// The base authenticated packet.
    pub base: PacketAuthenticated,
    /// TLV extensions following the base packet.
    pub tlvs: TlvList,
}

impl ExtendedPacketAuthenticated {
    /// Base packet size (112 bytes).
    pub const BASE_SIZE: usize = 112;

    /// Creates a new extended packet with just the base packet.
    #[must_use]
    pub fn new(base: PacketAuthenticated) -> Self {
        Self {
            base,
            tlvs: TlvList::new(),
        }
    }

    /// Creates a new extended packet with TLVs.
    #[must_use]
    pub fn with_tlvs(base: PacketAuthenticated, tlvs: TlvList) -> Self {
        Self { base, tlvs }
    }

    /// Parses an extended packet from bytes.
    ///
    /// # Errors
    /// Returns an error if the buffer is too small or TLV parsing fails.
    pub fn from_bytes(buf: &[u8]) -> Result<Self, PacketError> {
        let base = PacketAuthenticated::from_bytes(buf)?;

        let tlvs = if buf.len() > Self::BASE_SIZE {
            TlvList::parse(&buf[Self::BASE_SIZE..])?
        } else {
            TlvList::new()
        };

        Ok(Self { base, tlvs })
    }

    /// Parses with lenient base packet handling (zero-fills missing bytes).
    pub fn from_bytes_lenient(buf: &[u8]) -> Result<Self, PacketError> {
        let base = PacketAuthenticated::from_bytes_lenient(buf);

        let tlvs = if buf.len() > Self::BASE_SIZE {
            TlvList::parse(&buf[Self::BASE_SIZE..])?
        } else {
            TlvList::new()
        };

        Ok(Self { base, tlvs })
    }

    /// Serializes the extended packet to bytes.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        // Pre-allocate exact capacity to avoid reallocations
        let mut buf = Vec::with_capacity(Self::BASE_SIZE + self.tlvs.wire_size());
        buf.extend_from_slice(&self.base.to_bytes());
        self.tlvs.write_to(&mut buf);
        buf
    }

    /// Returns the total wire size of the packet.
    #[must_use]
    pub fn wire_size(&self) -> usize {
        Self::BASE_SIZE + self.tlvs.wire_size()
    }

    /// Returns true if the packet has TLV extensions.
    #[must_use]
    pub fn has_tlvs(&self) -> bool {
        !self.tlvs.is_empty()
    }
}

/// Authenticated reflected STAMP packet with TLV extensions (RFC 8972).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtendedReflectedPacketAuthenticated {
    /// The base reflected packet.
    pub base: ReflectedPacketAuthenticated,
    /// TLV extensions following the base packet.
    pub tlvs: TlvList,
}

impl ExtendedReflectedPacketAuthenticated {
    /// Base packet size (112 bytes).
    pub const BASE_SIZE: usize = 112;

    /// Creates a new extended packet with just the base packet.
    #[must_use]
    pub fn new(base: ReflectedPacketAuthenticated) -> Self {
        Self {
            base,
            tlvs: TlvList::new(),
        }
    }

    /// Creates a new extended packet with TLVs.
    #[must_use]
    pub fn with_tlvs(base: ReflectedPacketAuthenticated, tlvs: TlvList) -> Self {
        Self { base, tlvs }
    }

    /// Serializes the extended packet to bytes.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        // Pre-allocate exact capacity to avoid reallocations
        let mut buf = Vec::with_capacity(Self::BASE_SIZE + self.tlvs.wire_size());
        buf.extend_from_slice(&self.base.to_bytes());
        self.tlvs.write_to(&mut buf);
        buf
    }

    /// Returns the total wire size of the packet.
    #[must_use]
    pub fn wire_size(&self) -> usize {
        Self::BASE_SIZE + self.tlvs.wire_size()
    }

    /// Parses an extended reflected packet from bytes.
    ///
    /// # Errors
    /// Returns an error if the buffer is too small or TLV parsing fails.
    pub fn from_bytes(buf: &[u8]) -> Result<Self, PacketError> {
        let base = ReflectedPacketAuthenticated::from_bytes(buf)?;

        let tlvs = if buf.len() > Self::BASE_SIZE {
            TlvList::parse(&buf[Self::BASE_SIZE..])?
        } else {
            TlvList::new()
        };

        Ok(Self { base, tlvs })
    }

    /// Parses an extended reflected packet leniently (RFC 8762 §4.6 short-packet support).
    ///
    /// Unlike `from_bytes`, this method:
    /// - Handles short base packets by zero-filling missing bytes
    /// - Handles malformed TLVs by marking them with M-flag rather than failing
    ///
    /// Returns the packet and the canonical 112-byte buffer for HMAC verification.
    pub fn from_bytes_lenient(buf: &[u8]) -> (Self, [u8; 112]) {
        // Use lenient parsing for base packet (zero-fills short packets)
        let (base, canonical) = ReflectedPacketAuthenticated::from_bytes_lenient(buf);

        let tlvs = if buf.len() > Self::BASE_SIZE {
            let (tlvs, _malformed) = TlvList::parse_lenient(&buf[Self::BASE_SIZE..]);
            tlvs
        } else {
            TlvList::new()
        };

        (Self { base, tlvs }, canonical)
    }

    /// Returns true if the packet has TLV extensions.
    #[must_use]
    pub fn has_tlvs(&self) -> bool {
        !self.tlvs.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wire_format_sizes_match_rfc() {
        // Verify wire format sizes match RFC 8762 requirements
        let unauth = PacketUnauthenticated {
            sequence_number: 0,
            timestamp: 0,
            error_estimate: 0,
            mbz: [0; 30],
        };
        assert_eq!(unauth.to_bytes().len(), 44);

        let reflected_unauth = ReflectedPacketUnauthenticated {
            sequence_number: 0,
            timestamp: 0,
            error_estimate: 0,
            mbz1: 0,
            receive_timestamp: 0,
            sess_sender_seq_number: 0,
            sess_sender_timestamp: 0,
            sess_sender_err_estimate: 0,
            mbz2: 0,
            sess_sender_ttl: 0,
            mbz3: [0; 3],
        };
        assert_eq!(reflected_unauth.to_bytes().len(), 44);

        let auth = PacketAuthenticated {
            sequence_number: 0,
            mbz0: [0; 12],
            timestamp: 0,
            error_estimate: 0,
            mbz1a: [0; 32],
            mbz1b: [0; 32],
            mbz1c: [0; 6],
            hmac: [0; 16],
        };
        assert_eq!(auth.to_bytes().len(), 112);

        let reflected_auth = ReflectedPacketAuthenticated {
            sequence_number: 0,
            mbz0: [0; 12],
            timestamp: 0,
            error_estimate: 0,
            mbz1: [0; 6],
            receive_timestamp: 0,
            mbz2: [0; 8],
            sess_sender_seq_number: 0,
            mbz3: [0; 12],
            sess_sender_timestamp: 0,
            sess_sender_err_estimate: 0,
            mbz4: [0; 6],
            sess_sender_ttl: 0,
            mbz5: [0; 15],
            hmac: [0; 16],
        };
        assert_eq!(reflected_auth.to_bytes().len(), 112);
    }

    #[test]
    fn test_packet_unauthenticated_serialization() {
        let packet = PacketUnauthenticated {
            sequence_number: 1,
            timestamp: 123456789,
            error_estimate: 100,
            mbz: [0; 30],
        };
        let serialized = packet.to_bytes();
        let deserialized = PacketUnauthenticated::from_bytes(&serialized).unwrap();
        assert_eq!(packet, deserialized);
    }

    #[test]
    fn test_reflected_packet_unauthenticated_serialization() {
        let packet = ReflectedPacketUnauthenticated {
            sequence_number: 1,
            timestamp: 123456789,
            error_estimate: 100,
            mbz1: 0,
            receive_timestamp: 987654321,
            sess_sender_seq_number: 2,
            sess_sender_timestamp: 123456789,
            sess_sender_err_estimate: 100,
            mbz2: 0,
            sess_sender_ttl: 64,
            mbz3: [0; 3],
        };
        let serialized = packet.to_bytes();
        let deserialized = ReflectedPacketUnauthenticated::from_bytes(&serialized).unwrap();
        assert_eq!(packet, deserialized);
    }

    #[test]
    fn test_packet_authenticated_serialization() {
        let packet = PacketAuthenticated {
            sequence_number: 1,
            mbz0: [0; 12],
            timestamp: 123456789,
            error_estimate: 100,
            mbz1a: [0; 32],
            mbz1b: [0; 32],
            mbz1c: [0; 6],
            hmac: [0; 16],
        };
        let serialized = packet.to_bytes();
        let deserialized = PacketAuthenticated::from_bytes(&serialized).unwrap();
        assert_eq!(packet, deserialized);
    }

    #[test]
    fn test_reflected_packet_authenticated_serialization() {
        let packet = ReflectedPacketAuthenticated {
            sequence_number: 1,
            mbz0: [0; 12],
            timestamp: 123456789,
            error_estimate: 100,
            mbz1: [0; 6],
            receive_timestamp: 987654321,
            mbz2: [0; 8],
            sess_sender_seq_number: 2,
            mbz3: [0; 12],
            sess_sender_timestamp: 123456789,
            sess_sender_err_estimate: 100,
            mbz4: [0; 6],
            sess_sender_ttl: 64,
            mbz5: [0; 15],
            hmac: [0; 16],
        };
        let serialized = packet.to_bytes();
        let deserialized = ReflectedPacketAuthenticated::from_bytes(&serialized).unwrap();
        assert_eq!(packet, deserialized);
    }

    #[test]
    fn test_packet_unauthenticated_buffer_too_small() {
        let small_buffer = [0u8; 43];
        let result = PacketUnauthenticated::from_bytes(&small_buffer);
        assert!(result.is_err());
    }

    #[test]
    fn test_packet_authenticated_buffer_too_small() {
        let small_buffer = [0u8; 111];
        let result = PacketAuthenticated::from_bytes(&small_buffer);
        assert!(result.is_err());
    }

    #[test]
    fn test_reflected_unauth_buffer_too_small() {
        let small_buffer = [0u8; 43];
        let result = ReflectedPacketUnauthenticated::from_bytes(&small_buffer);
        assert!(result.is_err());
    }

    #[test]
    fn test_reflected_auth_buffer_too_small() {
        let small_buffer = [0u8; 111];
        let result = ReflectedPacketAuthenticated::from_bytes(&small_buffer);
        assert!(result.is_err());
    }

    #[test]
    fn test_packet_field_values_preserved() {
        // Test specific field values are correctly preserved
        let packet = PacketUnauthenticated {
            sequence_number: 0x12345678,
            timestamp: 0xDEADBEEFCAFEBABE,
            error_estimate: 0xABCD,
            mbz: [0x42; 30],
        };
        let serialized = packet.to_bytes();
        let deserialized = PacketUnauthenticated::from_bytes(&serialized).unwrap();

        assert_eq!(deserialized.sequence_number, 0x12345678);
        assert_eq!(deserialized.timestamp, 0xDEADBEEFCAFEBABE);
        assert_eq!(deserialized.error_estimate, 0xABCD);
        assert_eq!(deserialized.mbz, [0x42; 30]);
    }

    #[test]
    fn test_reflected_packet_echoed_fields() {
        // Verify reflected packet can store echoed sender fields
        let packet = ReflectedPacketUnauthenticated {
            sequence_number: 100,
            timestamp: 200,
            error_estimate: 300,
            mbz1: 0,
            receive_timestamp: 400,
            sess_sender_seq_number: 500,
            sess_sender_timestamp: 600,
            sess_sender_err_estimate: 700,
            mbz2: 0,
            sess_sender_ttl: 64,
            mbz3: [0; 3],
        };
        let serialized = packet.to_bytes();
        let deserialized = ReflectedPacketUnauthenticated::from_bytes(&serialized).unwrap();

        // Verify echoed fields
        assert_eq!(deserialized.sess_sender_seq_number, 500);
        assert_eq!(deserialized.sess_sender_timestamp, 600);
        assert_eq!(deserialized.sess_sender_err_estimate, 700);
        assert_eq!(deserialized.sess_sender_ttl, 64);
    }

    #[test]
    fn test_buffer_larger_than_needed() {
        // Create a packet and serialize it
        let packet = PacketUnauthenticated {
            sequence_number: 1,
            timestamp: 2,
            error_estimate: 3,
            mbz: [0; 30],
        };
        let mut bytes = packet.to_bytes().to_vec();

        // Add extra bytes at the end
        bytes.extend_from_slice(&[0xff; 100]);

        // Should still deserialize correctly (reads only what it needs)
        let restored = PacketUnauthenticated::from_bytes(&bytes).unwrap();
        assert_eq!(packet, restored);
    }

    #[test]
    fn test_big_endian_wire_format() {
        // Test that sequence number is serialized in big-endian
        let packet = PacketUnauthenticated {
            sequence_number: 0x12345678,
            timestamp: 0,
            error_estimate: 0,
            mbz: [0; 30],
        };
        let bytes = packet.to_bytes();

        // Big-endian: most significant byte first
        assert_eq!(bytes[0], 0x12);
        assert_eq!(bytes[1], 0x34);
        assert_eq!(bytes[2], 0x56);
        assert_eq!(bytes[3], 0x78);
    }

    #[test]
    fn test_timestamp_big_endian() {
        let packet = PacketUnauthenticated {
            sequence_number: 0,
            timestamp: 0x0102030405060708,
            error_estimate: 0,
            mbz: [0; 30],
        };
        let bytes = packet.to_bytes();

        // Timestamp starts at offset 4
        assert_eq!(bytes[4], 0x01);
        assert_eq!(bytes[5], 0x02);
        assert_eq!(bytes[6], 0x03);
        assert_eq!(bytes[7], 0x04);
        assert_eq!(bytes[8], 0x05);
        assert_eq!(bytes[9], 0x06);
        assert_eq!(bytes[10], 0x07);
        assert_eq!(bytes[11], 0x08);
    }

    #[test]
    fn test_error_estimate_big_endian() {
        let packet = PacketUnauthenticated {
            sequence_number: 0,
            timestamp: 0,
            error_estimate: 0xABCD,
            mbz: [0; 30],
        };
        let bytes = packet.to_bytes();

        // Error estimate starts at offset 12
        assert_eq!(bytes[12], 0xAB);
        assert_eq!(bytes[13], 0xCD);
    }

    #[test]
    fn test_mbz_bytes_at_correct_offset() {
        let mbz_pattern = [0x42u8; 30];
        let packet = PacketUnauthenticated {
            sequence_number: 0,
            timestamp: 0,
            error_estimate: 0,
            mbz: mbz_pattern,
        };
        let bytes = packet.to_bytes();

        // MBZ starts at offset 14
        for i in 0..30 {
            assert_eq!(bytes[14 + i], 0x42);
        }
    }

    #[test]
    fn test_hmac_at_correct_offset_auth() {
        let hmac_pattern = [0xAB; 16];
        let packet = PacketAuthenticated {
            sequence_number: 0,
            mbz0: [0; 12],
            timestamp: 0,
            error_estimate: 0,
            mbz1a: [0; 32],
            mbz1b: [0; 32],
            mbz1c: [0; 6],
            hmac: hmac_pattern,
        };
        let bytes = packet.to_bytes();

        // HMAC starts at offset 96 (4+12+8+2+32+32+6)
        for i in 0..16 {
            assert_eq!(bytes[96 + i], 0xAB);
        }
    }

    #[test]
    fn test_sequence_number_boundary_values() {
        for seq in [0u32, 1, u32::MAX / 2, u32::MAX - 1, u32::MAX] {
            let packet = PacketUnauthenticated {
                sequence_number: seq,
                timestamp: 0,
                error_estimate: 0,
                mbz: [0; 30],
            };

            let bytes = packet.to_bytes();
            let restored = PacketUnauthenticated::from_bytes(&bytes).unwrap();

            assert_eq!(
                restored.sequence_number, seq,
                "Sequence number {} should roundtrip correctly",
                seq
            );
        }
    }

    #[test]
    fn test_timestamp_boundary_values() {
        for ts in [0u64, 1, u64::MAX / 2, u64::MAX - 1, u64::MAX] {
            let packet = PacketUnauthenticated {
                sequence_number: 0,
                timestamp: ts,
                error_estimate: 0,
                mbz: [0; 30],
            };

            let bytes = packet.to_bytes();
            let restored = PacketUnauthenticated::from_bytes(&bytes).unwrap();

            assert_eq!(
                restored.timestamp, ts,
                "Timestamp {} should roundtrip correctly",
                ts
            );
        }
    }

    #[test]
    fn test_error_estimate_boundary_values() {
        for ee in [0u16, 1, u16::MAX / 2, u16::MAX - 1, u16::MAX] {
            let packet = PacketUnauthenticated {
                sequence_number: 0,
                timestamp: 0,
                error_estimate: ee,
                mbz: [0; 30],
            };

            let bytes = packet.to_bytes();
            let restored = PacketUnauthenticated::from_bytes(&bytes).unwrap();

            assert_eq!(
                restored.error_estimate, ee,
                "Error estimate {} should roundtrip correctly",
                ee
            );
        }
    }

    #[test]
    fn test_ttl_boundary_values() {
        for ttl in [0u8, 1, 64, 128, 255] {
            let packet = ReflectedPacketUnauthenticated {
                sequence_number: 0,
                timestamp: 0,
                error_estimate: 0,
                mbz1: 0,
                receive_timestamp: 0,
                sess_sender_seq_number: 0,
                sess_sender_timestamp: 0,
                sess_sender_err_estimate: 0,
                mbz2: 0,
                sess_sender_ttl: ttl,
                mbz3: [0; 3],
            };

            let bytes = packet.to_bytes();
            let restored = ReflectedPacketUnauthenticated::from_bytes(&bytes).unwrap();

            assert_eq!(
                restored.sess_sender_ttl, ttl,
                "TTL {} should roundtrip correctly",
                ttl
            );
        }
    }

    #[test]
    fn test_from_bytes_lenient_unauth_full_packet() {
        let packet = PacketUnauthenticated {
            sequence_number: 0x12345678,
            timestamp: 0xDEADBEEFCAFEBABE,
            error_estimate: 0xABCD,
            mbz: [0x42; 30],
        };
        let bytes = packet.to_bytes();

        let restored = PacketUnauthenticated::from_bytes_lenient(&bytes);
        assert_eq!(packet, restored);
    }

    #[test]
    fn test_from_bytes_lenient_unauth_short_packet() {
        // Only first 20 bytes provided (seq + timestamp + error_estimate + 6 bytes mbz)
        let mut short_buf = [0u8; 20];
        short_buf[0..4].copy_from_slice(&0x12345678u32.to_be_bytes()); // seq
        short_buf[4..12].copy_from_slice(&0xDEADBEEFCAFEBABEu64.to_be_bytes()); // timestamp
        short_buf[12..14].copy_from_slice(&0xABCDu16.to_be_bytes()); // error_estimate
        short_buf[14..20].copy_from_slice(&[0x42; 6]); // partial mbz

        let restored = PacketUnauthenticated::from_bytes_lenient(&short_buf);

        assert_eq!(restored.sequence_number, 0x12345678);
        assert_eq!(restored.timestamp, 0xDEADBEEFCAFEBABE);
        assert_eq!(restored.error_estimate, 0xABCD);
        // First 6 bytes should be 0x42, rest zero-filled
        assert_eq!(restored.mbz[0..6], [0x42; 6]);
        assert_eq!(restored.mbz[6..30], [0; 24]);
    }

    #[test]
    fn test_from_bytes_lenient_unauth_empty_packet() {
        let empty: [u8; 0] = [];
        let restored = PacketUnauthenticated::from_bytes_lenient(&empty);

        assert_eq!(restored.sequence_number, 0);
        assert_eq!(restored.timestamp, 0);
        assert_eq!(restored.error_estimate, 0);
        assert_eq!(restored.mbz, [0; 30]);
    }

    #[test]
    fn test_from_bytes_lenient_auth_full_packet() {
        let packet = PacketAuthenticated {
            sequence_number: 0x12345678,
            mbz0: [0x11; 12],
            timestamp: 0xDEADBEEFCAFEBABE,
            error_estimate: 0xABCD,
            mbz1a: [0x22; 32],
            mbz1b: [0x33; 32],
            mbz1c: [0x44; 6],
            hmac: [0x55; 16],
        };
        let bytes = packet.to_bytes();

        let restored = PacketAuthenticated::from_bytes_lenient(&bytes);
        assert_eq!(packet, restored);
    }

    #[test]
    fn test_from_bytes_lenient_auth_short_packet() {
        // Only 30 bytes provided
        let mut short_buf = [0u8; 30];
        short_buf[0..4].copy_from_slice(&0x12345678u32.to_be_bytes()); // seq
        short_buf[4..16].copy_from_slice(&[0x11; 12]); // mbz0
        short_buf[16..24].copy_from_slice(&0xDEADBEEFCAFEBABEu64.to_be_bytes()); // timestamp
        short_buf[24..26].copy_from_slice(&0xABCDu16.to_be_bytes()); // error_estimate
        short_buf[26..30].copy_from_slice(&[0x22; 4]); // partial mbz1a

        let restored = PacketAuthenticated::from_bytes_lenient(&short_buf);

        assert_eq!(restored.sequence_number, 0x12345678);
        assert_eq!(restored.mbz0, [0x11; 12]);
        assert_eq!(restored.timestamp, 0xDEADBEEFCAFEBABE);
        assert_eq!(restored.error_estimate, 0xABCD);
        // First 4 bytes of mbz1a should be 0x22, rest zero-filled
        assert_eq!(restored.mbz1a[0..4], [0x22; 4]);
        assert_eq!(restored.mbz1a[4..32], [0; 28]);
        assert_eq!(restored.mbz1b, [0; 32]);
        assert_eq!(restored.mbz1c, [0; 6]);
        assert_eq!(restored.hmac, [0; 16]);
    }

    // Extended packet tests

    #[test]
    fn test_extended_packet_unauth_new() {
        let base = PacketUnauthenticated {
            sequence_number: 1,
            timestamp: 100,
            error_estimate: 10,
            mbz: [0; 30],
        };
        let ext = ExtendedPacketUnauthenticated::new(base);

        assert_eq!(ext.base.sequence_number, 1);
        assert!(!ext.has_tlvs());
    }

    #[test]
    fn test_extended_packet_unauth_with_tlvs() {
        use crate::tlv::{RawTlv, TlvType};

        let base = PacketUnauthenticated {
            sequence_number: 1,
            timestamp: 100,
            error_estimate: 10,
            mbz: [0; 30],
        };

        let mut tlvs = TlvList::new();
        tlvs.push(RawTlv::new(TlvType::ExtraPadding, vec![0, 0, 0, 0]))
            .unwrap();

        let ext = ExtendedPacketUnauthenticated::with_tlvs(base, tlvs);

        assert!(ext.has_tlvs());
        assert_eq!(ext.tlvs.len(), 1);
    }

    #[test]
    fn test_extended_packet_unauth_to_bytes() {
        use crate::tlv::{RawTlv, TlvType, TLV_HEADER_SIZE};

        let base = PacketUnauthenticated {
            sequence_number: 1,
            timestamp: 100,
            error_estimate: 10,
            mbz: [0; 30],
        };

        let mut tlvs = TlvList::new();
        tlvs.push(RawTlv::new(TlvType::ExtraPadding, vec![0xAA; 4]))
            .unwrap();

        let ext = ExtendedPacketUnauthenticated::with_tlvs(base, tlvs);
        let bytes = ext.to_bytes();

        // 44 base + 4 header + 4 value = 52
        assert_eq!(bytes.len(), 44 + TLV_HEADER_SIZE + 4);
        assert_eq!(ext.wire_size(), bytes.len());
    }

    #[test]
    fn test_extended_packet_unauth_from_bytes() {
        use crate::tlv::{RawTlv, TlvType};

        let base = PacketUnauthenticated {
            sequence_number: 42,
            timestamp: 12345,
            error_estimate: 100,
            mbz: [0; 30],
        };

        let mut tlvs = TlvList::new();
        tlvs.push(RawTlv::new(TlvType::ExtraPadding, vec![1, 2, 3, 4]))
            .unwrap();

        let original = ExtendedPacketUnauthenticated::with_tlvs(base, tlvs);
        let bytes = original.to_bytes();

        let parsed = ExtendedPacketUnauthenticated::from_bytes(&bytes).unwrap();

        assert_eq!(parsed.base.sequence_number, 42);
        assert_eq!(parsed.tlvs.len(), 1);
    }

    #[test]
    fn test_extended_packet_unauth_from_bytes_no_tlvs() {
        let base = PacketUnauthenticated {
            sequence_number: 42,
            timestamp: 12345,
            error_estimate: 100,
            mbz: [0; 30],
        };
        let bytes = base.to_bytes();

        let parsed = ExtendedPacketUnauthenticated::from_bytes(&bytes).unwrap();

        assert_eq!(parsed.base.sequence_number, 42);
        assert!(!parsed.has_tlvs());
    }

    #[test]
    fn test_extended_packet_auth_new() {
        let base = PacketAuthenticated {
            sequence_number: 1,
            mbz0: [0; 12],
            timestamp: 100,
            error_estimate: 10,
            mbz1a: [0; 32],
            mbz1b: [0; 32],
            mbz1c: [0; 6],
            hmac: [0; 16],
        };
        let ext = ExtendedPacketAuthenticated::new(base);

        assert_eq!(ext.base.sequence_number, 1);
        assert!(!ext.has_tlvs());
    }

    #[test]
    fn test_extended_packet_auth_to_bytes() {
        use crate::tlv::{RawTlv, TlvType, TLV_HEADER_SIZE};

        let base = PacketAuthenticated {
            sequence_number: 1,
            mbz0: [0; 12],
            timestamp: 100,
            error_estimate: 10,
            mbz1a: [0; 32],
            mbz1b: [0; 32],
            mbz1c: [0; 6],
            hmac: [0xAB; 16],
        };

        let mut tlvs = TlvList::new();
        tlvs.push(RawTlv::new(TlvType::ExtraPadding, vec![0; 8]))
            .unwrap();

        let ext = ExtendedPacketAuthenticated::with_tlvs(base, tlvs);
        let bytes = ext.to_bytes();

        // 112 base + 4 header + 8 value = 124
        assert_eq!(bytes.len(), 112 + TLV_HEADER_SIZE + 8);
    }

    #[test]
    fn test_extended_reflected_packet_unauth() {
        use crate::tlv::{RawTlv, TlvType};

        let base = ReflectedPacketUnauthenticated {
            sequence_number: 1,
            timestamp: 100,
            error_estimate: 10,
            mbz1: 0,
            receive_timestamp: 50,
            sess_sender_seq_number: 1,
            sess_sender_timestamp: 30,
            sess_sender_err_estimate: 5,
            mbz2: 0,
            sess_sender_ttl: 64,
            mbz3: [0; 3],
        };

        let mut tlvs = TlvList::new();
        tlvs.push(RawTlv::new(TlvType::ExtraPadding, vec![0; 4]))
            .unwrap();

        let ext = ExtendedReflectedPacketUnauthenticated::with_tlvs(base, tlvs);
        let bytes = ext.to_bytes();

        assert_eq!(bytes.len(), ext.wire_size());
    }

    #[test]
    fn test_extended_reflected_packet_auth() {
        use crate::tlv::{RawTlv, TlvType};

        let base = ReflectedPacketAuthenticated {
            sequence_number: 1,
            mbz0: [0; 12],
            timestamp: 100,
            error_estimate: 10,
            mbz1: [0; 6],
            receive_timestamp: 50,
            mbz2: [0; 8],
            sess_sender_seq_number: 1,
            mbz3: [0; 12],
            sess_sender_timestamp: 30,
            sess_sender_err_estimate: 5,
            mbz4: [0; 6],
            sess_sender_ttl: 64,
            mbz5: [0; 15],
            hmac: [0; 16],
        };

        let mut tlvs = TlvList::new();
        tlvs.push(RawTlv::new(TlvType::ExtraPadding, vec![0; 4]))
            .unwrap();
        tlvs.push(RawTlv::new(TlvType::Hmac, vec![0xFF; 16]))
            .unwrap();

        let ext = ExtendedReflectedPacketAuthenticated::with_tlvs(base, tlvs);
        let bytes = ext.to_bytes();

        assert_eq!(bytes.len(), ext.wire_size());
    }
}
