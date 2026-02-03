//! STAMP Session Reflector implementations.
//!
//! This module provides different implementations for the STAMP reflector based on
//! compile-time feature flags:
//!
//! - **Default** (no features): Uses tokio UDP sockets with placeholder TTL (255)
//! - **`ttl-nix`**: Uses nix crate for real TTL capture via IP_RECVTTL (Linux preferred)
//! - **`ttl-pnet`**: Uses pnet for raw packet capture with real TTL (requires root)

#[cfg(not(any(feature = "ttl-nix", feature = "ttl-pnet")))]
mod default;
#[cfg(feature = "ttl-nix")]
mod nix;
#[cfg(all(feature = "ttl-pnet", not(feature = "ttl-nix")))]
mod pnet;

#[cfg(not(any(feature = "ttl-nix", feature = "ttl-pnet")))]
pub use default::run_receiver;
#[cfg(feature = "ttl-nix")]
pub use nix::run_receiver;
#[cfg(all(feature = "ttl-pnet", not(feature = "ttl-nix")))]
pub use pnet::run_receiver;

use crate::{
    configuration::ClockFormat,
    packets::{
        PacketAuthenticated, PacketUnauthenticated, ReflectedPacketAuthenticated,
        ReflectedPacketUnauthenticated,
    },
    time::generate_timestamp,
};

/// Assembles an unauthenticated reflected packet from a received test packet.
///
/// # Arguments
/// * `packet` - The received unauthenticated test packet
/// * `cs` - Clock format to use for timestamps
/// * `rcvt` - Receive timestamp when the packet was received
/// * `ttl` - TTL/Hop Limit value from the received packet's IP header
pub fn assemble_unauth_answer(
    packet: &PacketUnauthenticated,
    cs: ClockFormat,
    rcvt: u64,
    ttl: u8,
) -> ReflectedPacketUnauthenticated {
    ReflectedPacketUnauthenticated {
        sess_sender_timestamp: packet.timestamp,
        sess_sender_err_estimate: packet.error_estimate,
        sess_sender_seq_number: packet.sequence_number,
        sess_sender_ttl: ttl,
        sequence_number: packet.sequence_number,
        error_estimate: packet.error_estimate,
        timestamp: generate_timestamp(cs),
        receive_timestamp: rcvt,
        mbz1: 0,
        mbz2: 0,
        mbz3a: 0,
        mbz3b: 0,
    }
}

/// Assembles an authenticated reflected packet from a received test packet.
///
/// # Arguments
/// * `packet` - The received authenticated test packet
/// * `cs` - Clock format to use for timestamps
/// * `rcvt` - Receive timestamp when the packet was received
/// * `ttl` - TTL/Hop Limit value from the received packet's IP header
pub fn assemble_auth_answer(
    packet: &PacketAuthenticated,
    cs: ClockFormat,
    rcvt: u64,
    ttl: u8,
) -> ReflectedPacketAuthenticated {
    ReflectedPacketAuthenticated {
        sess_sender_timestamp: packet.timestamp,
        sess_sender_err_estimate: packet.error_estimate,
        sess_sender_seq_number: packet.sequence_number,
        sess_sender_ttl: ttl,
        sequence_number: packet.sequence_number,
        error_estimate: packet.error_estimate,
        timestamp: generate_timestamp(cs),
        receive_timestamp: rcvt,
        mbz0: [0u8; 12],
        mbz1: [0u8; 6],
        mbz2: [0u8; 8],
        mbz3: [0u8; 12],
        mbz4: [0u8; 6],
        mbz5: [0u8; 15],
        hmac: [0u8; 16],
    }
}
