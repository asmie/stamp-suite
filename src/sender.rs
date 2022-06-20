use crate::packets::*;

pub fn assemble_unauth_packet() -> PacketUnauthenticated {
    let packet = PacketUnauthenticated {
        timestamp: 0,
        mbz: [0u8; 30],
        error_estimate: 0,
        sequence_number: 0,
    };

    packet
}

pub fn assemble_auth_packet() -> PacketAuthenticated {
    let packet = PacketAuthenticated {
        timestamp: 0,
        mbz0: [0u8; 12],
        error_estimate: 0,
        sequence_number: 0,
        hmac : [0u8; 16],
        mbz1 : [0u8; 70],
    };

    packet
}

