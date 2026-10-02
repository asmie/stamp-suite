//! Sender and reflector packet layouts (RFC 8762 and RFC 8972).
//! `to_bytes()` and `from_bytes()` explicitly encode/decode big-endian wire fields;
//! the Rust structs are in-memory representations.

use thiserror::Error;

use crate::tlv::{TlvError, TlvList};

/// Receive-buffer capacity for the 16-bit UDP length limit (IPv4 allows 65507
/// payload bytes). Accommodates padded probes without datagram truncation.
pub(crate) const MAX_UDP_PAYLOAD: usize = 65535;

/// Size of an unauthenticated base packet in both directions
/// (RFC 8762 §4.2.1, §4.3.1).
pub const UNAUTH_BASE_SIZE: usize = 44;

/// Size of an authenticated base packet in both directions
/// (RFC 8762 §4.2.2, §4.3.2).
pub const AUTH_BASE_SIZE: usize = 112;

/// Offset of the HMAC field in authenticated packets of either direction.
/// The HMAC covers the octets before it (RFC 8762 §4.4).
pub const AUTH_HMAC_OFFSET: usize = 96;

/// Offset of the SSID field in unauthenticated packets (RFC 8972 §3).
pub(crate) const UNAUTH_SSID_OFFSET: usize = 14;

/// Offset of the SSID field in authenticated packets (RFC 8972 §3).
pub(crate) const AUTH_SSID_OFFSET: usize = 26;

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
/// Caller must ensure `offset + 2 <= buf.len()`. This is checked via assert.
#[inline]
fn read_u16(buf: &[u8], offset: usize) -> u16 {
    assert!(
        offset + 2 <= buf.len(),
        "read_u16: offset {} + 2 exceeds buffer length {}",
        offset,
        buf.len()
    );
    // SAFETY: assert ensures bounds; slice length is exactly 2
    u16::from_be_bytes([buf[offset], buf[offset + 1]])
}

/// Reads a big-endian u32 from buffer at given offset.
///
/// # Safety invariant
/// Caller must ensure `offset + 4 <= buf.len()`. This is checked via assert.
#[inline]
fn read_u32(buf: &[u8], offset: usize) -> u32 {
    assert!(
        offset + 4 <= buf.len(),
        "read_u32: offset {} + 4 exceeds buffer length {}",
        offset,
        buf.len()
    );
    // SAFETY: assert ensures bounds; slice length is exactly 4
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
/// Caller must ensure `offset + 8 <= buf.len()`. This is checked via assert.
#[inline]
fn read_u64(buf: &[u8], offset: usize) -> u64 {
    assert!(
        offset + 8 <= buf.len(),
        "read_u64: offset {} + 8 exceeds buffer length {}",
        offset,
        buf.len()
    );
    // SAFETY: assert ensures bounds; slice length is exactly 8
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
/// Caller must ensure `offset + N <= buf.len()`. This is checked via assert.
#[inline]
fn read_array<const N: usize>(buf: &[u8], offset: usize) -> [u8; N] {
    assert!(
        offset + N <= buf.len(),
        "read_array<{}>: offset {} + {} exceeds buffer length {}",
        N,
        offset,
        N,
        buf.len()
    );
    // SAFETY: assert ensures bounds; try_into succeeds because slice length equals N
    buf[offset..offset + N].try_into().unwrap()
}

/// Unauthenticated STAMP test packet sent by the Session-Sender.
///
/// This is the basic packet format without HMAC authentication (44 bytes).
/// See RFC 8762 Section 4.2, with the RFC 8972 §3 SSID extension occupying
/// the two octets immediately following Error Estimate.
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
/// |         Error Estimate        |             SSID              |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                                                               |
/// |                         MBZ (28 octets)                       |
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
    /// Session-Sender Identifier per RFC 8972 §3 (0 if unused).
    pub ssid: u16,
    /// Must Be Zero - reserved padding bytes.
    pub mbz: [u8; 28],
}

impl PacketUnauthenticated {
    /// Serializes the packet to a 44-byte array in big-endian wire format.
    pub fn to_bytes(&self) -> [u8; 44] {
        let mut buf = [0u8; 44];
        buf[0..4].copy_from_slice(&self.sequence_number.to_be_bytes());
        buf[4..12].copy_from_slice(&self.timestamp.to_be_bytes());
        buf[12..14].copy_from_slice(&self.error_estimate.to_be_bytes());
        buf[14..16].copy_from_slice(&self.ssid.to_be_bytes());
        buf[16..44].copy_from_slice(&self.mbz);
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
            ssid: read_u16(buf, 14),
            mbz: read_array(buf, 16),
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
            ssid: read_u16(&padded, 14),
            mbz: read_array(&padded, 16),
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
    /// Session-Sender Identifier echoed/asserted by reflector (RFC 8972 §4.1.1).
    pub ssid: u16,
    /// Timestamp when the reflector received the test packet.
    pub receive_timestamp: u64,
    /// Original sender's sequence number (echoed back).
    pub sess_sender_seq_number: u32,
    /// Original sender's timestamp (echoed back).
    pub sess_sender_timestamp: u64,
    /// Original sender's error estimate (echoed back).
    pub sess_sender_err_estimate: u16,
    /// Reserved bytes 38-39; must remain zero (RFC 8762 §4.6).
    /// The reply SSID appears only at bytes 14-15 (RFC 8972 §3 Figure 2).
    pub mbz2: [u8; 2],
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
        buf[14..16].copy_from_slice(&self.ssid.to_be_bytes());
        buf[16..24].copy_from_slice(&self.receive_timestamp.to_be_bytes());
        buf[24..28].copy_from_slice(&self.sess_sender_seq_number.to_be_bytes());
        buf[28..36].copy_from_slice(&self.sess_sender_timestamp.to_be_bytes());
        buf[36..38].copy_from_slice(&self.sess_sender_err_estimate.to_be_bytes());
        buf[38..40].copy_from_slice(&self.mbz2);
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
            ssid: read_u16(buf, 14),
            receive_timestamp: read_u64(buf, 16),
            sess_sender_seq_number: read_u32(buf, 24),
            sess_sender_timestamp: read_u64(buf, 28),
            sess_sender_err_estimate: read_u16(buf, 36),
            mbz2: read_array(buf, 38),
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
            ssid: read_u16(&padded, 14),
            receive_timestamp: read_u64(&padded, 16),
            sess_sender_seq_number: read_u32(&padded, 24),
            sess_sender_timestamp: read_u64(&padded, 28),
            sess_sender_err_estimate: read_u16(&padded, 36),
            mbz2: read_array(&padded, 38),
            sess_sender_ttl: padded[40],
            mbz3: read_array(&padded, 41),
        }
    }
}

/// Authenticated STAMP test packet sent by the Session-Sender.
///
/// Includes HMAC for integrity verification (112 bytes).
/// See RFC 8762 Section 4.4, with the RFC 8972 §3 SSID extension occupying
/// the two octets immediately following Error Estimate.
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
    /// Session-Sender Identifier per RFC 8972 §3 (0 if unused).
    pub ssid: u16,
    /// Must Be Zero - reserved padding (68 bytes total = 30+32+6).
    pub mbz1a: [u8; 30],
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
        buf[26..28].copy_from_slice(&self.ssid.to_be_bytes());
        buf[28..58].copy_from_slice(&self.mbz1a);
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
            ssid: read_u16(buf, 26),
            mbz1a: read_array(buf, 28),
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
            ssid: read_u16(&padded, 26),
            mbz1a: read_array(&padded, 28),
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
    /// Session-Sender Identifier echoed/asserted by reflector (RFC 8972 §4.1.2).
    pub ssid: u16,
    /// Must Be Zero - reserved padding (4 bytes).
    pub mbz1: [u8; 4],
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
    ///
    /// Covers octets 74-79. RFC 8972 §3 places the SSID once per reflected
    /// packet (`ssid`, octets 26-27); the run after the Session-Sender Error
    /// Estimate is MBZ. See `ReflectedPacketUnauthenticated::mbz2`.
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
        buf[26..28].copy_from_slice(&self.ssid.to_be_bytes());
        buf[28..32].copy_from_slice(&self.mbz1);
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
            ssid: read_u16(buf, 26),
            mbz1: read_array(buf, 28),
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
            ssid: read_u16(&padded, 26),
            mbz1: read_array(&padded, 28),
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
    pub const BASE_SIZE: usize = UNAUTH_BASE_SIZE;

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
    pub const BASE_SIZE: usize = UNAUTH_BASE_SIZE;

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
    pub const BASE_SIZE: usize = AUTH_BASE_SIZE;

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
    pub const BASE_SIZE: usize = AUTH_BASE_SIZE;

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
mod tests;
