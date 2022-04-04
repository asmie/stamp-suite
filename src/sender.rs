use crate::configuration::*;
use crate::packets::*;
use std::sync::Arc;
use std::net::UdpSocket;
use std::{io, thread};
use std::time::Duration;

pub fn assemble_unauth_packet() -> PacketUnauthenticated {
    let mut packet = PacketUnauthenticated {
        timestamp: 0,
        mbz: [0u8; 30],
        error_estimate: 0,
        sequence_number: 0,
    };

    packet
}

