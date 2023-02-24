use crate::packets::*;

pub fn assemble_unauth_packet() -> PacketUnauthenticated {
    PacketUnauthenticated {
        timestamp: 0,
        mbz: [0u8; 30],
        error_estimate: 0,
        sequence_number: 0,
    }
}

pub fn assemble_auth_packet() -> PacketAuthenticated {
    PacketAuthenticated {
        timestamp: 0,
        mbz0: [0u8; 12],
        error_estimate: 0,
        sequence_number: 0,
        hmac: [0u8; 16],
        mbz1a: [0u8; 32],
        mbz1b: [0u8; 32],
        mbz1c: [0u8; 6],
    }
}
