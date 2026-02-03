use rkyv::{rancor, Archive, Deserialize, Serialize};

#[derive(Archive, Serialize, Deserialize, Debug, Copy, Clone, PartialEq)]
#[rkyv(derive(Debug))]
pub struct PacketUnauthenticated {
    pub sequence_number: u32,
    pub timestamp: u64,
    pub error_estimate: u16,
    pub mbz: [u8; 30],
}

#[derive(Archive, Serialize, Deserialize, Debug, Copy, Clone, PartialEq)]
#[rkyv(derive(Debug))]
pub struct ReflectedPacketUnauthenticated {
    pub sequence_number: u32,
    pub timestamp: u64,
    pub error_estimate: u16,
    pub mbz1: u16,
    pub receive_timestamp: u64,
    pub sess_sender_seq_number: u32,
    pub sess_sender_timestamp: u64,
    pub sess_sender_err_estimate: u16,
    pub mbz2: u16,
    pub sess_sender_ttl: u8,
    pub mbz3a: u8,
    pub mbz3b: u16,
}

#[derive(Archive, Serialize, Deserialize, Debug, Copy, Clone, PartialEq)]
#[rkyv(derive(Debug))]
pub struct PacketAuthenticated {
    pub sequence_number: u32,
    pub mbz0: [u8; 12],
    pub timestamp: u64,
    pub error_estimate: u16,
    pub mbz1a: [u8; 32],
    pub mbz1b: [u8; 32],
    pub mbz1c: [u8; 6],
    pub hmac: [u8; 16],
}

#[derive(Archive, Serialize, Deserialize, Debug, Copy, Clone, PartialEq)]
#[rkyv(derive(Debug))]
pub struct ReflectedPacketAuthenticated {
    pub sequence_number: u32,
    pub mbz0: [u8; 12],
    pub timestamp: u64,
    pub error_estimate: u16,
    pub mbz1: [u8; 6],
    pub receive_timestamp: u64,
    pub mbz2: [u8; 8],
    pub sess_sender_seq_number: u32,
    pub mbz3: [u8; 12],
    pub sess_sender_timestamp: u64,
    pub sess_sender_err_estimate: u16,
    pub mbz4: [u8; 6],
    pub sess_sender_ttl: u8,
    pub mbz5: [u8; 15],
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
}
