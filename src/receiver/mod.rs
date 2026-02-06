//! STAMP Session Reflector implementations.
//!
//! Platform defaults with real TTL capture:
//! - **Linux**: Uses nix via IP_RECVTTL
//! - **Windows/macOS**: Uses pnet for raw packet capture
//!
//! Explicit overrides:
//! - **`ttl-nix`**: Force nix backend on any platform
//! - **`ttl-pnet`**: Force pnet backend on any platform

// Explicit feature flags take priority
#[cfg(feature = "ttl-nix")]
mod nix;
#[cfg(feature = "ttl-nix")]
pub use nix::run_receiver;

#[cfg(all(feature = "ttl-pnet", not(feature = "ttl-nix")))]
mod pnet;
#[cfg(all(feature = "ttl-pnet", not(feature = "ttl-nix")))]
pub use pnet::run_receiver;

// Platform defaults (when no explicit feature)
#[cfg(all(
    target_os = "linux",
    not(feature = "ttl-nix"),
    not(feature = "ttl-pnet")
))]
mod nix;
#[cfg(all(
    target_os = "linux",
    not(feature = "ttl-nix"),
    not(feature = "ttl-pnet")
))]
pub use nix::run_receiver;

#[cfg(all(
    any(target_os = "windows", target_os = "macos"),
    not(feature = "ttl-nix"),
    not(feature = "ttl-pnet")
))]
mod pnet;
#[cfg(all(
    any(target_os = "windows", target_os = "macos"),
    not(feature = "ttl-nix"),
    not(feature = "ttl-pnet")
))]
pub use pnet::run_receiver;

// Fallback to placeholder TTL on other platforms
#[cfg(not(any(
    feature = "ttl-nix",
    feature = "ttl-pnet",
    target_os = "linux",
    target_os = "windows",
    target_os = "macos"
)))]
mod default;
#[cfg(not(any(
    feature = "ttl-nix",
    feature = "ttl-pnet",
    target_os = "linux",
    target_os = "windows",
    target_os = "macos"
)))]
pub use default::run_receiver;

use crate::{
    configuration::ClockFormat,
    crypto::{compute_packet_hmac, HmacKey},
    packets::{
        PacketAuthenticated, PacketUnauthenticated, ReflectedPacketAuthenticated,
        ReflectedPacketUnauthenticated,
    },
    time::generate_timestamp,
};

/// HMAC field offset in ReflectedPacketAuthenticated (bytes before HMAC field).
pub const REFLECTED_AUTH_PACKET_HMAC_OFFSET: usize = 96;

/// Assembles an unauthenticated reflected packet from a received test packet.
///
/// # Arguments
/// * `packet` - The received unauthenticated test packet
/// * `cs` - Clock format to use for timestamps
/// * `rcvt` - Receive timestamp when the packet was received
/// * `ttl` - TTL/Hop Limit value from the received packet's IP header
/// * `reflector_error_estimate` - The reflector's own error estimate in wire format
/// * `reflector_seq` - Optional independent reflector sequence number (RFC 8972 stateful mode)
pub fn assemble_unauth_answer(
    packet: &PacketUnauthenticated,
    cs: ClockFormat,
    rcvt: u64,
    ttl: u8,
    reflector_error_estimate: u16,
    reflector_seq: Option<u32>,
) -> ReflectedPacketUnauthenticated {
    ReflectedPacketUnauthenticated {
        sess_sender_timestamp: packet.timestamp,
        sess_sender_err_estimate: packet.error_estimate,
        sess_sender_seq_number: packet.sequence_number,
        sess_sender_ttl: ttl,
        sequence_number: reflector_seq.unwrap_or(packet.sequence_number),
        error_estimate: reflector_error_estimate,
        timestamp: generate_timestamp(cs),
        receive_timestamp: rcvt,
        mbz1: 0,
        mbz2: 0,
        mbz3: [0; 3],
    }
}

/// Base size of unauthenticated STAMP packets.
pub const UNAUTH_BASE_SIZE: usize = 44;

/// Base size of authenticated STAMP packets.
pub const AUTH_BASE_SIZE: usize = 112;

/// Assembles an unauthenticated reflected packet with symmetric size (RFC 8762 Section 4.3).
///
/// Preserves the original packet length by copying extra bytes beyond the base 44 bytes.
///
/// # Arguments
/// * `packet` - The received unauthenticated test packet
/// * `original_data` - The original received packet data
/// * `cs` - Clock format to use for timestamps
/// * `rcvt` - Receive timestamp when the packet was received
/// * `ttl` - TTL/Hop Limit value from the received packet's IP header
/// * `reflector_error_estimate` - The reflector's own error estimate in wire format
/// * `reflector_seq` - Optional independent reflector sequence number (RFC 8972 stateful mode)
pub fn assemble_unauth_answer_symmetric(
    packet: &PacketUnauthenticated,
    original_data: &[u8],
    cs: ClockFormat,
    rcvt: u64,
    ttl: u8,
    reflector_error_estimate: u16,
    reflector_seq: Option<u32>,
) -> Vec<u8> {
    let base = assemble_unauth_answer(
        packet,
        cs,
        rcvt,
        ttl,
        reflector_error_estimate,
        reflector_seq,
    );
    let mut response = base.to_bytes().to_vec();

    // Copy extra bytes beyond base packet (RFC 8762 Section 4.3)
    if original_data.len() > UNAUTH_BASE_SIZE {
        response.extend_from_slice(&original_data[UNAUTH_BASE_SIZE..]);
    }

    response
}

/// Assembles an authenticated reflected packet from a received test packet.
///
/// # Arguments
/// * `packet` - The received authenticated test packet
/// * `cs` - Clock format to use for timestamps
/// * `rcvt` - Receive timestamp when the packet was received
/// * `ttl` - TTL/Hop Limit value from the received packet's IP header
/// * `reflector_error_estimate` - The reflector's own error estimate in wire format
/// * `hmac_key` - Optional HMAC key for computing the response HMAC
/// * `reflector_seq` - Optional independent reflector sequence number (RFC 8972 stateful mode)
pub fn assemble_auth_answer(
    packet: &PacketAuthenticated,
    cs: ClockFormat,
    rcvt: u64,
    ttl: u8,
    reflector_error_estimate: u16,
    hmac_key: Option<&HmacKey>,
    reflector_seq: Option<u32>,
) -> ReflectedPacketAuthenticated {
    let mut response = ReflectedPacketAuthenticated {
        sess_sender_timestamp: packet.timestamp,
        sess_sender_err_estimate: packet.error_estimate,
        sess_sender_seq_number: packet.sequence_number,
        sess_sender_ttl: ttl,
        sequence_number: reflector_seq.unwrap_or(packet.sequence_number),
        error_estimate: reflector_error_estimate,
        timestamp: generate_timestamp(cs),
        receive_timestamp: rcvt,
        mbz0: [0u8; 12],
        mbz1: [0u8; 6],
        mbz2: [0u8; 8],
        mbz3: [0u8; 12],
        mbz4: [0u8; 6],
        mbz5: [0u8; 15],
        hmac: [0u8; 16],
    };

    // Compute HMAC if key is provided
    if let Some(key) = hmac_key {
        let bytes = response.to_bytes();
        response.hmac = compute_packet_hmac(key, &bytes, REFLECTED_AUTH_PACKET_HMAC_OFFSET);
    }

    response
}

/// Assembles an authenticated reflected packet with symmetric size (RFC 8762 Section 4.3).
///
/// Preserves the original packet length by copying extra bytes beyond the base 112 bytes.
///
/// # Arguments
/// * `packet` - The received authenticated test packet
/// * `original_data` - The original received packet data
/// * `cs` - Clock format to use for timestamps
/// * `rcvt` - Receive timestamp when the packet was received
/// * `ttl` - TTL/Hop Limit value from the received packet's IP header
/// * `reflector_error_estimate` - The reflector's own error estimate in wire format
/// * `hmac_key` - Optional HMAC key for computing the response HMAC
/// * `reflector_seq` - Optional independent reflector sequence number (RFC 8972 stateful mode)
#[allow(clippy::too_many_arguments)]
pub fn assemble_auth_answer_symmetric(
    packet: &PacketAuthenticated,
    original_data: &[u8],
    cs: ClockFormat,
    rcvt: u64,
    ttl: u8,
    reflector_error_estimate: u16,
    hmac_key: Option<&HmacKey>,
    reflector_seq: Option<u32>,
) -> Vec<u8> {
    let base = assemble_auth_answer(
        packet,
        cs,
        rcvt,
        ttl,
        reflector_error_estimate,
        hmac_key,
        reflector_seq,
    );
    let mut response = base.to_bytes().to_vec();

    // Copy extra bytes beyond base packet (RFC 8762 Section 4.3)
    if original_data.len() > AUTH_BASE_SIZE {
        response.extend_from_slice(&original_data[AUTH_BASE_SIZE..]);
    }

    response
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_assemble_unauth_answer_echoes_sender_fields() {
        let sender_packet = PacketUnauthenticated {
            sequence_number: 42,
            timestamp: 123456789,
            error_estimate: 100,
            mbz: [0; 30],
        };

        let rcvt = 987654321u64;
        let ttl = 64u8;
        let reflector_error_estimate = 200u16;

        let reflected = assemble_unauth_answer(
            &sender_packet,
            ClockFormat::NTP,
            rcvt,
            ttl,
            reflector_error_estimate,
            None,
        );

        // Verify sender fields are echoed
        assert_eq!({ reflected.sess_sender_seq_number }, {
            sender_packet.sequence_number
        });
        assert_eq!({ reflected.sess_sender_timestamp }, {
            sender_packet.timestamp
        });
        assert_eq!({ reflected.sess_sender_err_estimate }, {
            sender_packet.error_estimate
        });
        assert_eq!({ reflected.sess_sender_ttl }, ttl);
        // Verify reflector's own error estimate is used
        assert_eq!({ reflected.error_estimate }, reflector_error_estimate);
    }

    #[test]
    fn test_assemble_unauth_answer_receive_timestamp() {
        let sender_packet = PacketUnauthenticated {
            sequence_number: 1,
            timestamp: 100,
            error_estimate: 10,
            mbz: [0; 30],
        };

        let rcvt = 500u64;
        let reflected = assemble_unauth_answer(&sender_packet, ClockFormat::NTP, rcvt, 64, 0, None);

        assert_eq!({ reflected.receive_timestamp }, rcvt);
    }

    #[test]
    fn test_assemble_unauth_answer_timestamp_generated() {
        let sender_packet = PacketUnauthenticated {
            sequence_number: 1,
            timestamp: 0,
            error_estimate: 0,
            mbz: [0; 30],
        };

        let reflected = assemble_unauth_answer(&sender_packet, ClockFormat::NTP, 0, 64, 0, None);

        // Reflector's timestamp should be non-zero (generated)
        assert!({ reflected.timestamp } > 0);
    }

    #[test]
    fn test_assemble_auth_answer_echoes_sender_fields() {
        let sender_packet = PacketAuthenticated {
            sequence_number: 42,
            mbz0: [0; 12],
            timestamp: 123456789,
            error_estimate: 100,
            mbz1a: [0; 32],
            mbz1b: [0; 32],
            mbz1c: [0; 6],
            hmac: [0xab; 16],
        };

        let rcvt = 987654321u64;
        let ttl = 128u8;
        let reflector_error_estimate = 300u16;

        let reflected = assemble_auth_answer(
            &sender_packet,
            ClockFormat::NTP,
            rcvt,
            ttl,
            reflector_error_estimate,
            None,
            None,
        );

        // Verify sender fields are echoed
        assert_eq!({ reflected.sess_sender_seq_number }, {
            sender_packet.sequence_number
        });
        assert_eq!({ reflected.sess_sender_timestamp }, {
            sender_packet.timestamp
        });
        assert_eq!({ reflected.sess_sender_err_estimate }, {
            sender_packet.error_estimate
        });
        assert_eq!({ reflected.sess_sender_ttl }, ttl);
        // Verify reflector's own error estimate is used
        assert_eq!({ reflected.error_estimate }, reflector_error_estimate);
    }

    #[test]
    fn test_assemble_unauth_answer_ttl_preserved() {
        let sender_packet = PacketUnauthenticated {
            sequence_number: 1,
            timestamp: 2,
            error_estimate: 3,
            mbz: [0; 30],
        };

        // Test various TTL values
        for ttl in [0u8, 1, 64, 128, 255] {
            let reflected =
                assemble_unauth_answer(&sender_packet, ClockFormat::NTP, 0, ttl, 0, None);
            assert_eq!({ reflected.sess_sender_ttl }, ttl);
        }
    }

    #[test]
    fn test_assemble_auth_answer_ttl_preserved() {
        let sender_packet = PacketAuthenticated {
            sequence_number: 1,
            mbz0: [0; 12],
            timestamp: 2,
            error_estimate: 3,
            mbz1a: [0; 32],
            mbz1b: [0; 32],
            mbz1c: [0; 6],
            hmac: [0; 16],
        };

        // Test various TTL values
        for ttl in [0u8, 1, 64, 128, 255] {
            let reflected =
                assemble_auth_answer(&sender_packet, ClockFormat::NTP, 0, ttl, 0, None, None);
            assert_eq!({ reflected.sess_sender_ttl }, ttl);
        }
    }

    #[test]
    fn test_assemble_auth_answer_with_hmac() {
        let sender_packet = PacketAuthenticated {
            sequence_number: 1,
            mbz0: [0; 12],
            timestamp: 123456789,
            error_estimate: 100,
            mbz1a: [0; 32],
            mbz1b: [0; 32],
            mbz1c: [0; 6],
            hmac: [0; 16],
        };

        let key = HmacKey::new(vec![0xab; 32]).unwrap();
        let reflected = assemble_auth_answer(
            &sender_packet,
            ClockFormat::NTP,
            987654321,
            64,
            200,
            Some(&key),
            None,
        );

        // HMAC should be non-zero when key is provided
        assert_ne!({ reflected.hmac }, [0u8; 16]);
    }

    #[test]
    fn test_assemble_auth_answer_without_hmac() {
        let sender_packet = PacketAuthenticated {
            sequence_number: 1,
            mbz0: [0; 12],
            timestamp: 123456789,
            error_estimate: 100,
            mbz1a: [0; 32],
            mbz1b: [0; 32],
            mbz1c: [0; 6],
            hmac: [0; 16],
        };

        let reflected = assemble_auth_answer(
            &sender_packet,
            ClockFormat::NTP,
            987654321,
            64,
            200,
            None,
            None,
        );

        // HMAC should be zero when no key is provided
        assert_eq!({ reflected.hmac }, [0u8; 16]);
    }

    #[test]
    fn test_assemble_unauth_answer_with_reflector_seq() {
        let sender_packet = PacketUnauthenticated {
            sequence_number: 42,
            timestamp: 123456789,
            error_estimate: 100,
            mbz: [0; 30],
        };

        // Test with independent reflector sequence number
        let reflected = assemble_unauth_answer(
            &sender_packet,
            ClockFormat::NTP,
            987654321,
            64,
            200,
            Some(999),
        );

        // Reflector's sequence should be independent
        assert_eq!({ reflected.sequence_number }, 999);
        // Sender's sequence still echoed in sess_sender_seq_number
        assert_eq!({ reflected.sess_sender_seq_number }, 42);
    }

    #[test]
    fn test_assemble_auth_answer_with_reflector_seq() {
        let sender_packet = PacketAuthenticated {
            sequence_number: 42,
            mbz0: [0; 12],
            timestamp: 123456789,
            error_estimate: 100,
            mbz1a: [0; 32],
            mbz1b: [0; 32],
            mbz1c: [0; 6],
            hmac: [0; 16],
        };

        // Test with independent reflector sequence number
        let reflected = assemble_auth_answer(
            &sender_packet,
            ClockFormat::NTP,
            987654321,
            64,
            200,
            None,
            Some(999),
        );

        // Reflector's sequence should be independent
        assert_eq!({ reflected.sequence_number }, 999);
        // Sender's sequence still echoed in sess_sender_seq_number
        assert_eq!({ reflected.sess_sender_seq_number }, 42);
    }

    #[test]
    fn test_assemble_unauth_answer_symmetric_preserves_length() {
        let sender_packet = PacketUnauthenticated {
            sequence_number: 1,
            timestamp: 100,
            error_estimate: 10,
            mbz: [0; 30],
        };

        // Create original data with extra bytes beyond base 44
        let mut original_data = sender_packet.to_bytes().to_vec();
        original_data.extend_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD]); // 4 extra bytes

        let response = assemble_unauth_answer_symmetric(
            &sender_packet,
            &original_data,
            ClockFormat::NTP,
            200,
            64,
            300,
            None,
        );

        // Response should be 48 bytes (44 base + 4 extra)
        assert_eq!(response.len(), 48);
        // Extra bytes should be preserved at the end
        assert_eq!(&response[44..], &[0xAA, 0xBB, 0xCC, 0xDD]);
    }

    #[test]
    fn test_assemble_auth_answer_symmetric_preserves_length() {
        let sender_packet = PacketAuthenticated {
            sequence_number: 1,
            mbz0: [0; 12],
            timestamp: 100,
            error_estimate: 10,
            mbz1a: [0; 32],
            mbz1b: [0; 32],
            mbz1c: [0; 6],
            hmac: [0; 16],
        };

        // Create original data with extra bytes beyond base 112
        let mut original_data = sender_packet.to_bytes().to_vec();
        original_data.extend_from_slice(&[0x11, 0x22, 0x33, 0x44, 0x55]); // 5 extra bytes

        let response = assemble_auth_answer_symmetric(
            &sender_packet,
            &original_data,
            ClockFormat::NTP,
            200,
            64,
            300,
            None,
            None,
        );

        // Response should be 117 bytes (112 base + 5 extra)
        assert_eq!(response.len(), 117);
        // Extra bytes should be preserved at the end
        assert_eq!(&response[112..], &[0x11, 0x22, 0x33, 0x44, 0x55]);
    }

    #[test]
    fn test_assemble_unauth_answer_symmetric_base_size() {
        let sender_packet = PacketUnauthenticated {
            sequence_number: 1,
            timestamp: 100,
            error_estimate: 10,
            mbz: [0; 30],
        };

        // Original data is exactly base size
        let original_data = sender_packet.to_bytes();

        let response = assemble_unauth_answer_symmetric(
            &sender_packet,
            &original_data,
            ClockFormat::NTP,
            200,
            64,
            300,
            None,
        );

        // Response should be exactly 44 bytes
        assert_eq!(response.len(), 44);
    }
}
