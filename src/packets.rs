//! STAMP packet structures as defined in RFC 8762.
//!
//! This module contains the packet formats for both authenticated and unauthenticated
//! STAMP test packets, as well as their reflected counterparts.
//!
//! All packet structures use `#[repr(C, packed)]` to ensure exact byte layout
//! matching RFC 8762 requirements, with explicit big-endian serialization.

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
#[repr(C, packed)]
#[derive(Debug, Copy, Clone, PartialEq)]
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

// Compile-time size assertion for PacketUnauthenticated
const _: () = assert!(std::mem::size_of::<PacketUnauthenticated>() == 44);

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
    pub fn from_bytes(buf: &[u8]) -> Result<Self, &'static str> {
        if buf.len() < 44 {
            return Err("Buffer too small for PacketUnauthenticated");
        }
        Ok(Self {
            sequence_number: u32::from_be_bytes(buf[0..4].try_into().unwrap()),
            timestamp: u64::from_be_bytes(buf[4..12].try_into().unwrap()),
            error_estimate: u16::from_be_bytes(buf[12..14].try_into().unwrap()),
            mbz: buf[14..44].try_into().unwrap(),
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
            sequence_number: u32::from_be_bytes(padded[0..4].try_into().unwrap()),
            timestamp: u64::from_be_bytes(padded[4..12].try_into().unwrap()),
            error_estimate: u16::from_be_bytes(padded[12..14].try_into().unwrap()),
            mbz: padded[14..44].try_into().unwrap(),
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
#[repr(C, packed)]
#[derive(Debug, Copy, Clone, PartialEq)]
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

// Compile-time size assertion for ReflectedPacketUnauthenticated
const _: () = assert!(std::mem::size_of::<ReflectedPacketUnauthenticated>() == 44);

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
    pub fn from_bytes(buf: &[u8]) -> Result<Self, &'static str> {
        if buf.len() < 44 {
            return Err("Buffer too small for ReflectedPacketUnauthenticated");
        }
        Ok(Self {
            sequence_number: u32::from_be_bytes(buf[0..4].try_into().unwrap()),
            timestamp: u64::from_be_bytes(buf[4..12].try_into().unwrap()),
            error_estimate: u16::from_be_bytes(buf[12..14].try_into().unwrap()),
            mbz1: u16::from_be_bytes(buf[14..16].try_into().unwrap()),
            receive_timestamp: u64::from_be_bytes(buf[16..24].try_into().unwrap()),
            sess_sender_seq_number: u32::from_be_bytes(buf[24..28].try_into().unwrap()),
            sess_sender_timestamp: u64::from_be_bytes(buf[28..36].try_into().unwrap()),
            sess_sender_err_estimate: u16::from_be_bytes(buf[36..38].try_into().unwrap()),
            mbz2: u16::from_be_bytes(buf[38..40].try_into().unwrap()),
            sess_sender_ttl: buf[40],
            mbz3: buf[41..44].try_into().unwrap(),
        })
    }
}

/// Authenticated STAMP test packet sent by the Session-Sender.
///
/// Includes HMAC for integrity verification (112 bytes).
/// See RFC 8762 Section 4.4.
#[repr(C, packed)]
#[derive(Debug, Copy, Clone, PartialEq)]
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

// Compile-time size assertion for PacketAuthenticated
const _: () = assert!(std::mem::size_of::<PacketAuthenticated>() == 112);

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
    pub fn from_bytes(buf: &[u8]) -> Result<Self, &'static str> {
        if buf.len() < 112 {
            return Err("Buffer too small for PacketAuthenticated");
        }
        Ok(Self {
            sequence_number: u32::from_be_bytes(buf[0..4].try_into().unwrap()),
            mbz0: buf[4..16].try_into().unwrap(),
            timestamp: u64::from_be_bytes(buf[16..24].try_into().unwrap()),
            error_estimate: u16::from_be_bytes(buf[24..26].try_into().unwrap()),
            mbz1a: buf[26..58].try_into().unwrap(),
            mbz1b: buf[58..90].try_into().unwrap(),
            mbz1c: buf[90..96].try_into().unwrap(),
            hmac: buf[96..112].try_into().unwrap(),
        })
    }

    /// Deserializes a packet with zero-fill for missing bytes (RFC 8762 Section 4.6).
    ///
    /// This method enables interoperability with TWAMP-Light implementations that
    /// may send packets smaller than the base 112 bytes. Missing bytes are zero-filled.
    pub fn from_bytes_lenient(buf: &[u8]) -> Self {
        let mut padded = [0u8; 112];
        let copy_len = buf.len().min(112);
        padded[..copy_len].copy_from_slice(&buf[..copy_len]);

        Self {
            sequence_number: u32::from_be_bytes(padded[0..4].try_into().unwrap()),
            mbz0: padded[4..16].try_into().unwrap(),
            timestamp: u64::from_be_bytes(padded[16..24].try_into().unwrap()),
            error_estimate: u16::from_be_bytes(padded[24..26].try_into().unwrap()),
            mbz1a: padded[26..58].try_into().unwrap(),
            mbz1b: padded[58..90].try_into().unwrap(),
            mbz1c: padded[90..96].try_into().unwrap(),
            hmac: padded[96..112].try_into().unwrap(),
        }
    }
}

/// Authenticated STAMP reflected packet sent by the Session-Reflector.
///
/// Contains the original sender information plus reflector timestamps with HMAC (112 bytes).
/// See RFC 8762 Section 4.5.
#[repr(C, packed)]
#[derive(Debug, Copy, Clone, PartialEq)]
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

// Compile-time size assertion for ReflectedPacketAuthenticated
const _: () = assert!(std::mem::size_of::<ReflectedPacketAuthenticated>() == 112);

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
    pub fn from_bytes(buf: &[u8]) -> Result<Self, &'static str> {
        if buf.len() < 112 {
            return Err("Buffer too small for ReflectedPacketAuthenticated");
        }
        Ok(Self {
            sequence_number: u32::from_be_bytes(buf[0..4].try_into().unwrap()),
            mbz0: buf[4..16].try_into().unwrap(),
            timestamp: u64::from_be_bytes(buf[16..24].try_into().unwrap()),
            error_estimate: u16::from_be_bytes(buf[24..26].try_into().unwrap()),
            mbz1: buf[26..32].try_into().unwrap(),
            receive_timestamp: u64::from_be_bytes(buf[32..40].try_into().unwrap()),
            mbz2: buf[40..48].try_into().unwrap(),
            sess_sender_seq_number: u32::from_be_bytes(buf[48..52].try_into().unwrap()),
            mbz3: buf[52..64].try_into().unwrap(),
            sess_sender_timestamp: u64::from_be_bytes(buf[64..72].try_into().unwrap()),
            sess_sender_err_estimate: u16::from_be_bytes(buf[72..74].try_into().unwrap()),
            mbz4: buf[74..80].try_into().unwrap(),
            sess_sender_ttl: buf[80],
            mbz5: buf[81..96].try_into().unwrap(),
            hmac: buf[96..112].try_into().unwrap(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_packet_sizes_match_rfc() {
        assert_eq!(std::mem::size_of::<PacketUnauthenticated>(), 44);
        assert_eq!(std::mem::size_of::<ReflectedPacketUnauthenticated>(), 44);
        assert_eq!(std::mem::size_of::<PacketAuthenticated>(), 112);
        assert_eq!(std::mem::size_of::<ReflectedPacketAuthenticated>(), 112);
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

        assert_eq!({ deserialized.sequence_number }, 0x12345678);
        assert_eq!({ deserialized.timestamp }, 0xDEADBEEFCAFEBABE);
        assert_eq!({ deserialized.error_estimate }, 0xABCD);
        assert_eq!({ deserialized.mbz }, [0x42; 30]);
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
        assert_eq!({ deserialized.sess_sender_seq_number }, 500);
        assert_eq!({ deserialized.sess_sender_timestamp }, 600);
        assert_eq!({ deserialized.sess_sender_err_estimate }, 700);
        assert_eq!({ deserialized.sess_sender_ttl }, 64);
    }

    #[test]
    fn test_to_bytes_size() {
        let packet = PacketUnauthenticated {
            sequence_number: 1,
            timestamp: 2,
            error_estimate: 3,
            mbz: [0; 30],
        };
        let bytes = packet.to_bytes();
        assert_eq!(bytes.len(), 44);
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
    fn test_different_packets_different_bytes() {
        let packet1 = PacketUnauthenticated {
            sequence_number: 1,
            timestamp: 100,
            error_estimate: 10,
            mbz: [0; 30],
        };

        let packet2 = PacketUnauthenticated {
            sequence_number: 2,
            timestamp: 200,
            error_estimate: 20,
            mbz: [0; 30],
        };

        let bytes1 = packet1.to_bytes();
        let bytes2 = packet2.to_bytes();

        assert_ne!(
            bytes1, bytes2,
            "Different packets should serialize differently"
        );
    }

    #[test]
    fn test_identical_packets_identical_bytes() {
        let packet1 = PacketUnauthenticated {
            sequence_number: 42,
            timestamp: 12345,
            error_estimate: 99,
            mbz: [0xAA; 30],
        };

        let packet2 = PacketUnauthenticated {
            sequence_number: 42,
            timestamp: 12345,
            error_estimate: 99,
            mbz: [0xAA; 30],
        };

        let bytes1 = packet1.to_bytes();
        let bytes2 = packet2.to_bytes();

        assert_eq!(
            bytes1, bytes2,
            "Identical packets should serialize identically"
        );
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
                { restored.sequence_number },
                seq,
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
                { restored.timestamp },
                ts,
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
                { restored.error_estimate },
                ee,
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
                { restored.sess_sender_ttl },
                ttl,
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

        assert_eq!({ restored.sequence_number }, 0x12345678);
        assert_eq!({ restored.timestamp }, 0xDEADBEEFCAFEBABE);
        assert_eq!({ restored.error_estimate }, 0xABCD);
        // First 6 bytes should be 0x42, rest zero-filled
        assert_eq!(restored.mbz[0..6], [0x42; 6]);
        assert_eq!(restored.mbz[6..30], [0; 24]);
    }

    #[test]
    fn test_from_bytes_lenient_unauth_empty_packet() {
        let empty: [u8; 0] = [];
        let restored = PacketUnauthenticated::from_bytes_lenient(&empty);

        assert_eq!({ restored.sequence_number }, 0);
        assert_eq!({ restored.timestamp }, 0);
        assert_eq!({ restored.error_estimate }, 0);
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

        assert_eq!({ restored.sequence_number }, 0x12345678);
        assert_eq!(restored.mbz0, [0x11; 12]);
        assert_eq!({ restored.timestamp }, 0xDEADBEEFCAFEBABE);
        assert_eq!({ restored.error_estimate }, 0xABCD);
        // First 4 bytes of mbz1a should be 0x22, rest zero-filled
        assert_eq!(restored.mbz1a[0..4], [0x22; 4]);
        assert_eq!(restored.mbz1a[4..32], [0; 28]);
        assert_eq!(restored.mbz1b, [0; 32]);
        assert_eq!(restored.mbz1c, [0; 6]);
        assert_eq!(restored.hmac, [0; 16]);
    }
}
