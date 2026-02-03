//! STAMP packet structures as defined in RFC 8762.
//!
//! This module contains the packet formats for both authenticated and unauthenticated
//! STAMP test packets, as well as their reflected counterparts.

use rkyv::{rancor, Archive, Deserialize, Serialize};

/// Unauthenticated STAMP test packet sent by the Session-Sender.
///
/// This is the basic packet format without HMAC authentication (44 bytes).
/// See RFC 8762 Section 4.2.
#[derive(Archive, Serialize, Deserialize, Debug, Copy, Clone, PartialEq)]
#[rkyv(derive(Debug))]
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

/// Unauthenticated STAMP reflected packet sent by the Session-Reflector.
///
/// Contains the original sender information plus reflector timestamps.
/// See RFC 8762 Section 4.3.
#[derive(Archive, Serialize, Deserialize, Debug, Copy, Clone, PartialEq)]
#[rkyv(derive(Debug))]
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
    /// Must Be Zero - reserved.
    pub mbz3a: u8,
    /// Must Be Zero - reserved.
    pub mbz3b: u16,
}

/// Authenticated STAMP test packet sent by the Session-Sender.
///
/// Includes HMAC for integrity verification (112 bytes).
/// See RFC 8762 Section 4.4.
#[derive(Archive, Serialize, Deserialize, Debug, Copy, Clone, PartialEq)]
#[rkyv(derive(Debug))]
pub struct PacketAuthenticated {
    /// Packet sequence number for ordering and loss detection.
    pub sequence_number: u32,
    /// Must Be Zero - reserved padding.
    pub mbz0: [u8; 12],
    /// Timestamp when the packet was sent (NTP or PTP format).
    pub timestamp: u64,
    /// Error estimate for the timestamp.
    pub error_estimate: u16,
    /// Must Be Zero - reserved padding.
    pub mbz1a: [u8; 32],
    /// Must Be Zero - reserved padding.
    pub mbz1b: [u8; 32],
    /// Must Be Zero - reserved padding.
    pub mbz1c: [u8; 6],
    /// HMAC for packet authentication.
    pub hmac: [u8; 16],
}

/// Authenticated STAMP reflected packet sent by the Session-Reflector.
///
/// Contains the original sender information plus reflector timestamps with HMAC.
/// See RFC 8762 Section 4.5.
#[derive(Archive, Serialize, Deserialize, Debug, Copy, Clone, PartialEq)]
#[rkyv(derive(Debug))]
pub struct ReflectedPacketAuthenticated {
    /// Reflector's sequence number.
    pub sequence_number: u32,
    /// Must Be Zero - reserved padding.
    pub mbz0: [u8; 12],
    /// Timestamp when the reflector sent the response.
    pub timestamp: u64,
    /// Reflector's error estimate.
    pub error_estimate: u16,
    /// Must Be Zero - reserved padding.
    pub mbz1: [u8; 6],
    /// Timestamp when the reflector received the test packet.
    pub receive_timestamp: u64,
    /// Must Be Zero - reserved padding.
    pub mbz2: [u8; 8],
    /// Original sender's sequence number (echoed back).
    pub sess_sender_seq_number: u32,
    /// Must Be Zero - reserved padding.
    pub mbz3: [u8; 12],
    /// Original sender's timestamp (echoed back).
    pub sess_sender_timestamp: u64,
    /// Original sender's error estimate (echoed back).
    pub sess_sender_err_estimate: u16,
    /// Must Be Zero - reserved padding.
    pub mbz4: [u8; 6],
    /// TTL/Hop Limit of the received test packet.
    pub sess_sender_ttl: u8,
    /// Must Be Zero - reserved padding.
    pub mbz5: [u8; 15],
    /// HMAC for packet authentication.
    pub hmac: [u8; 16],
}

// Macro to generate read/write functions for each packet type
macro_rules! impl_packet_io {
    ($packet_type:ty, $read_fn:ident, $write_fn:ident) => {
        pub fn $read_fn(bytes: &[u8]) -> Option<$packet_type> {
            // Use unsafe access since we trust the incoming data format
            // In production, validation should be added
            if bytes.len() < core::mem::size_of::<$packet_type>() {
                return None;
            }
            let archived = unsafe { rkyv::access_unchecked::<rkyv::Archived<$packet_type>>(bytes) };
            rkyv::deserialize::<$packet_type, rancor::Error>(archived).ok()
        }

        pub fn $write_fn(packet: &$packet_type) -> Option<Vec<u8>> {
            rkyv::to_bytes::<rancor::Error>(packet)
                .ok()
                .map(|v| v.to_vec())
        }
    };
}

impl_packet_io!(
    PacketUnauthenticated,
    read_packet_unauth,
    write_packet_unauth
);
impl_packet_io!(
    ReflectedPacketUnauthenticated,
    read_reflected_packet_unauth,
    write_reflected_packet_unauth
);
impl_packet_io!(PacketAuthenticated, read_packet_auth, write_packet_auth);
impl_packet_io!(
    ReflectedPacketAuthenticated,
    read_reflected_packet_auth,
    write_reflected_packet_auth
);

/// Legacy generic read function - reads bytes and deserializes to a structure.
/// Callers should prefer the type-specific functions above.
pub fn read_struct<T: Copy>(bytes: &[u8]) -> Result<T, &'static str> {
    if bytes.len() < core::mem::size_of::<T>() {
        return Err("Buffer too small");
    }
    // Direct memory copy for simple Copy types
    let mut value = unsafe { core::mem::zeroed::<T>() };
    unsafe {
        core::ptr::copy_nonoverlapping(
            bytes.as_ptr(),
            &mut value as *mut T as *mut u8,
            core::mem::size_of::<T>(),
        );
    }
    Ok(value)
}

/// Legacy generic write function - serializes a structure to bytes.
/// Callers should prefer the type-specific functions above.
pub fn any_as_u8_slice<T>(t: &T) -> Result<Vec<u8>, &'static str> {
    let size = core::mem::size_of::<T>();
    let ptr = t as *const T as *const u8;
    let slice = unsafe { core::slice::from_raw_parts(ptr, size) };
    Ok(slice.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_packet_unauthenticated_serialization() {
        let packet = PacketUnauthenticated {
            sequence_number: 1,
            timestamp: 123456789,
            error_estimate: 100,
            mbz: [0; 30],
        };
        let serialized = write_packet_unauth(&packet).unwrap();
        let deserialized = read_packet_unauth(&serialized).unwrap();
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
            mbz3a: 0,
            mbz3b: 0,
        };
        let serialized = write_reflected_packet_unauth(&packet).unwrap();
        let deserialized = read_reflected_packet_unauth(&serialized).unwrap();
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
        let serialized = write_packet_auth(&packet).unwrap();
        let deserialized = read_packet_auth(&serialized).unwrap();
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
        let serialized = write_reflected_packet_auth(&packet).unwrap();
        let deserialized = read_reflected_packet_auth(&serialized).unwrap();
        assert_eq!(packet, deserialized);
    }

    // Test legacy functions still work
    #[test]
    fn test_legacy_read_write() {
        let packet = PacketUnauthenticated {
            sequence_number: 42,
            timestamp: 999999,
            error_estimate: 50,
            mbz: [0; 30],
        };
        let bytes = any_as_u8_slice(&packet).unwrap();
        let restored: PacketUnauthenticated = read_struct(&bytes).unwrap();
        assert_eq!(packet, restored);
    }

    #[test]
    fn test_read_struct_buffer_too_small() {
        let small_buffer = [0u8; 4];
        let result = read_struct::<PacketUnauthenticated>(&small_buffer);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "Buffer too small");
    }

    #[test]
    fn test_read_struct_empty_buffer() {
        let empty_buffer: [u8; 0] = [];
        let result = read_struct::<PacketUnauthenticated>(&empty_buffer);
        assert!(result.is_err());
    }

    #[test]
    fn test_read_packet_unauth_buffer_too_small() {
        let small_buffer = [0u8; 10];
        let result = read_packet_unauth(&small_buffer);
        assert!(result.is_none());
    }

    #[test]
    fn test_read_packet_auth_buffer_too_small() {
        let small_buffer = [0u8; 50];
        let result = read_packet_auth(&small_buffer);
        assert!(result.is_none());
    }

    #[test]
    fn test_read_reflected_unauth_buffer_too_small() {
        let small_buffer = [0u8; 20];
        let result = read_reflected_packet_unauth(&small_buffer);
        assert!(result.is_none());
    }

    #[test]
    fn test_read_reflected_auth_buffer_too_small() {
        let small_buffer = [0u8; 100];
        let result = read_reflected_packet_auth(&small_buffer);
        assert!(result.is_none());
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
        let serialized = write_packet_unauth(&packet).unwrap();
        let deserialized = read_packet_unauth(&serialized).unwrap();

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
            mbz3a: 0,
            mbz3b: 0,
        };
        let serialized = write_reflected_packet_unauth(&packet).unwrap();
        let deserialized = read_reflected_packet_unauth(&serialized).unwrap();

        // Verify echoed fields
        assert_eq!(deserialized.sess_sender_seq_number, 500);
        assert_eq!(deserialized.sess_sender_timestamp, 600);
        assert_eq!(deserialized.sess_sender_err_estimate, 700);
        assert_eq!(deserialized.sess_sender_ttl, 64);
    }

    #[test]
    fn test_any_as_u8_slice_size() {
        let packet = PacketUnauthenticated {
            sequence_number: 1,
            timestamp: 2,
            error_estimate: 3,
            mbz: [0; 30],
        };
        let bytes = any_as_u8_slice(&packet).unwrap();
        assert_eq!(bytes.len(), core::mem::size_of::<PacketUnauthenticated>());
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
        let mut bytes = any_as_u8_slice(&packet).unwrap();

        // Add extra bytes at the end
        bytes.extend_from_slice(&[0xff; 100]);

        // Should still deserialize correctly (reads only what it needs)
        let restored: PacketUnauthenticated = read_struct(&bytes).unwrap();
        assert_eq!(packet, restored);
    }
}
