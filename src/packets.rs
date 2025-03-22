use bincode::Options;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Copy, Clone, PartialEq)]
pub struct PacketUnauthenticated {
    pub sequence_number: u32,
    pub timestamp: u64,
    pub error_estimate: u16,
    pub mbz: [u8; 30],
}

#[derive(Serialize, Deserialize, Debug, Copy, Clone, PartialEq)]
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

#[derive(Serialize, Deserialize, Debug, Copy, Clone, PartialEq)]
pub struct PacketAuthenticated {
    pub sequence_number: u32,
    pub mbz0: [u8; 12],
    pub timestamp: u64,
    pub error_estimate: u16,
    // split the fields since Serialize/Deserialize trait does not implement [u8; 70]
    pub mbz1a: [u8; 32],
    pub mbz1b: [u8; 32],
    pub mbz1c: [u8; 6],
    pub hmac: [u8; 16],
}

#[derive(Serialize, Deserialize, Debug, Copy, Clone, PartialEq)]
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

/// Read bytes and fill the structure.
///
/// Read bytes from something implementing Deserialize trait and then fill the structure T. Structure
/// T must be built only from PDO types.
///
pub fn read_struct<'a, T: serde::Deserialize<'a>>(bytes: &'a [u8]) -> bincode::Result<T> {
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .allow_trailing_bytes()
        .with_big_endian()
        .deserialize(bytes)
}

pub fn any_as_u8_slice<S: ?Sized + Serialize>(t: &S) -> bincode::Result<Vec<u8>> {
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .allow_trailing_bytes()
        .with_big_endian()
        .serialize(t)
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
        let serialized = any_as_u8_slice(&packet).unwrap();
        let deserialized: PacketUnauthenticated = read_struct(&serialized).unwrap();
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
        let serialized = any_as_u8_slice(&packet).unwrap();
        let deserialized: ReflectedPacketUnauthenticated = read_struct(&serialized).unwrap();
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
        let serialized = any_as_u8_slice(&packet).unwrap();
        let deserialized: PacketAuthenticated = read_struct(&serialized).unwrap();
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
        let serialized = any_as_u8_slice(&packet).unwrap();
        let deserialized: ReflectedPacketAuthenticated = read_struct(&serialized).unwrap();
        assert_eq!(packet, deserialized);
    }
}
