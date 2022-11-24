use bincode::Options;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Copy, Clone)]
pub struct PacketUnauthenticated {
    pub sequence_number: u32,
    pub timestamp: u64,
    pub error_estimate: u16,
    pub mbz: [u8; 30],
}

#[derive(Serialize, Deserialize, Debug, Copy, Clone)]
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

#[derive(Serialize, Deserialize, Debug, Copy, Clone)]
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

#[derive(Serialize, Deserialize, Debug, Copy, Clone)]
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
