//! STAMP Session Reflector implementations.
//!
//! Platform defaults with real TTL capture:
//! - **Linux/macOS**: Uses nix via IP_RECVTTL
//! - **Windows**: Uses pnet for raw packet capture
//!
//! Explicit overrides (for other platforms or to override defaults):
//! - **`ttl-nix`**: Force nix backend
//! - **`ttl-pnet`**: Force pnet backend

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
    any(target_os = "linux", target_os = "macos"),
    not(feature = "ttl-nix"),
    not(feature = "ttl-pnet")
))]
mod nix;
#[cfg(all(
    any(target_os = "linux", target_os = "macos"),
    not(feature = "ttl-nix"),
    not(feature = "ttl-pnet")
))]
pub use nix::run_receiver;

#[cfg(all(
    target_os = "windows",
    not(feature = "ttl-nix"),
    not(feature = "ttl-pnet")
))]
mod pnet;
#[cfg(all(
    target_os = "windows",
    not(feature = "ttl-nix"),
    not(feature = "ttl-pnet")
))]
pub use pnet::run_receiver;

use crate::{
    configuration::{ClockFormat, TlvHandlingMode},
    crypto::{compute_packet_hmac, HmacKey},
    packets::{
        PacketAuthenticated, PacketUnauthenticated, ReflectedPacketAuthenticated,
        ReflectedPacketUnauthenticated,
    },
    time::generate_timestamp,
    tlv::TlvList,
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
/// Preserves the original packet length by padding with zeros beyond the base 44 bytes.
/// Per RFC 8762 Section 4.2.1, extra octets SHOULD be filled with zeros.
///
/// # Arguments
/// * `packet` - The received unauthenticated test packet
/// * `original_data` - The original received packet data (used only for length)
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

    // Pad with zeros to match original length (RFC 8762 Section 4.2.1)
    if original_data.len() > UNAUTH_BASE_SIZE {
        response.resize(original_data.len(), 0);
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
/// Preserves the original packet length by padding with zeros beyond the base 112 bytes.
/// Per RFC 8762 Section 4.2.1, extra octets SHOULD be filled with zeros.
///
/// # Arguments
/// * `packet` - The received authenticated test packet
/// * `original_data` - The original received packet data (used only for length)
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

    // Pad with zeros to match original length (RFC 8762 Section 4.2.1)
    if original_data.len() > AUTH_BASE_SIZE {
        response.resize(original_data.len(), 0);
    }

    response
}

/// Assembles an unauthenticated reflected packet with TLV handling (RFC 8972).
///
/// Per RFC 8972 §4.8, on HMAC verification failure, TLVs are echoed with I-flag
/// set on ALL TLVs rather than dropping the packet.
///
/// # Arguments
/// * `packet` - The received unauthenticated test packet
/// * `original_data` - The original received packet data
/// * `cs` - Clock format to use for timestamps
/// * `rcvt` - Receive timestamp when the packet was received
/// * `ttl` - TTL/Hop Limit value from the received packet's IP header
/// * `reflector_error_estimate` - The reflector's own error estimate in wire format
/// * `reflector_seq` - Optional independent reflector sequence number
/// * `tlv_mode` - How to handle TLV extensions
/// * `tlv_hmac_key` - Optional HMAC key for TLV HMAC computation in response
/// * `verify_incoming_hmac` - Whether to verify incoming TLV HMAC (sets I-flag on failure)
#[allow(clippy::too_many_arguments)]
pub fn assemble_unauth_answer_with_tlvs(
    packet: &PacketUnauthenticated,
    original_data: &[u8],
    cs: ClockFormat,
    rcvt: u64,
    ttl: u8,
    reflector_error_estimate: u16,
    reflector_seq: Option<u32>,
    tlv_mode: TlvHandlingMode,
    tlv_hmac_key: Option<&HmacKey>,
    verify_incoming_hmac: bool,
) -> Vec<u8> {
    let base = assemble_unauth_answer(
        packet,
        cs,
        rcvt,
        ttl,
        reflector_error_estimate,
        reflector_seq,
    );
    let base_bytes = base.to_bytes();
    let mut response = base_bytes.to_vec();

    // Handle TLVs based on mode
    match tlv_mode {
        TlvHandlingMode::Ignore => {
            // Strip TLVs - just return base packet, optionally padded
            if original_data.len() > UNAUTH_BASE_SIZE {
                // Preserve symmetric size with zero padding (no TLVs)
                response.resize(original_data.len(), 0);
            }
        }
        TlvHandlingMode::Echo => {
            // Parse and echo TLVs from incoming packet
            if original_data.len() > UNAUTH_BASE_SIZE {
                let tlv_data = &original_data[UNAUTH_BASE_SIZE..];

                // Try strict parsing first, fall back to lenient parsing for malformed TLVs
                let (mut tlvs, had_malformed) = match TlvList::parse(tlv_data) {
                    Ok(tlvs) => (tlvs, false),
                    Err(_) => {
                        // Strict parsing failed - use lenient parsing to mark malformed TLVs
                        TlvList::parse_lenient(tlv_data)
                    }
                };

                // Per RFC 8972 §4.8: HMAC covers Sequence Number (first 4 bytes) + TLVs
                let incoming_seq_bytes = &original_data[..4];

                // Apply reflector-side flag updates per RFC 8972:
                // - U-flag for unrecognized types
                // - I-flag on ALL TLVs if HMAC verification fails (only if verify_incoming_hmac)
                // Per RFC 8972 §4.8: on failure, TLVs are echoed with I-flag set (not dropped)
                // Note: Unauthenticated mode does not require HMAC TLV presence
                let verify_key = if verify_incoming_hmac {
                    tlv_hmac_key
                } else {
                    None
                };
                let hmac_ok = tlvs.apply_reflector_flags(verify_key, incoming_seq_bytes, tlv_data);

                // Only compute fresh HMAC for response if verification passed AND no malformed TLVs
                // Per RFC 8972 §4.8: on failure, echo TLVs with flags set, don't regenerate HMAC
                if hmac_ok && !had_malformed {
                    if let Some(key) = tlv_hmac_key {
                        let response_seq_bytes = &base_bytes[..4];
                        tlvs.set_hmac(key, response_seq_bytes);
                    }
                }

                response.extend_from_slice(&tlvs.to_bytes());
            }
        }
    }

    response
}

/// Assembles an authenticated reflected packet with TLV handling (RFC 8972).
///
/// Per RFC 8972 §4.8, on HMAC verification failure, TLVs are echoed with I-flag
/// set on ALL TLVs rather than dropping the packet.
///
/// # Arguments
/// * `packet` - The received authenticated test packet
/// * `original_data` - The original received packet data
/// * `cs` - Clock format to use for timestamps
/// * `rcvt` - Receive timestamp when the packet was received
/// * `ttl` - TTL/Hop Limit value from the received packet's IP header
/// * `reflector_error_estimate` - The reflector's own error estimate in wire format
/// * `hmac_key` - Optional HMAC key for computing the base response HMAC
/// * `reflector_seq` - Optional independent reflector sequence number
/// * `tlv_mode` - How to handle TLV extensions
/// * `tlv_hmac_key` - Optional HMAC key for TLV HMAC computation in response
/// * `verify_incoming_hmac` - Whether to verify incoming TLV HMAC (sets I-flag on failure)
#[allow(clippy::too_many_arguments)]
pub fn assemble_auth_answer_with_tlvs(
    packet: &PacketAuthenticated,
    original_data: &[u8],
    cs: ClockFormat,
    rcvt: u64,
    ttl: u8,
    reflector_error_estimate: u16,
    hmac_key: Option<&HmacKey>,
    reflector_seq: Option<u32>,
    tlv_mode: TlvHandlingMode,
    tlv_hmac_key: Option<&HmacKey>,
    verify_incoming_hmac: bool,
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
    let base_bytes = base.to_bytes();
    let mut response = base_bytes.to_vec();

    // Handle TLVs based on mode
    match tlv_mode {
        TlvHandlingMode::Ignore => {
            // Strip TLVs - just return base packet, optionally padded
            if original_data.len() > AUTH_BASE_SIZE {
                response.resize(original_data.len(), 0);
            }
        }
        TlvHandlingMode::Echo => {
            // Parse and echo TLVs from incoming packet
            if original_data.len() > AUTH_BASE_SIZE {
                let tlv_data = &original_data[AUTH_BASE_SIZE..];

                // Try strict parsing first, fall back to lenient parsing for malformed TLVs
                let (mut tlvs, had_malformed) = match TlvList::parse(tlv_data) {
                    Ok(tlvs) => (tlvs, false),
                    Err(_) => {
                        // Strict parsing failed - use lenient parsing to mark malformed TLVs
                        TlvList::parse_lenient(tlv_data)
                    }
                };

                // Per RFC 8972 §4.8: HMAC covers Sequence Number (first 4 bytes) + TLVs
                let incoming_seq_bytes = &original_data[..4];

                // Apply reflector-side flag updates per RFC 8972:
                // - U-flag for unrecognized types
                // - I-flag on ALL TLVs if HMAC verification fails (only if verify_incoming_hmac)
                // Per RFC 8972 §4.8: on failure, TLVs are echoed with I-flag set (not dropped)
                // For strict RFC 8972 authenticated mode: require HMAC TLV (unless only Extra Padding)
                let verify_key = if verify_incoming_hmac {
                    tlv_hmac_key
                } else {
                    None
                };
                let require_hmac_tlv = verify_incoming_hmac;
                let hmac_ok = tlvs.apply_reflector_flags_strict(
                    verify_key,
                    incoming_seq_bytes,
                    tlv_data,
                    require_hmac_tlv,
                );

                // Only compute fresh HMAC for response if verification passed AND no malformed TLVs
                // Per RFC 8972 §4.8: on failure, echo TLVs with flags set, don't regenerate HMAC
                if hmac_ok && !had_malformed {
                    if let Some(key) = tlv_hmac_key {
                        let response_seq_bytes = &base_bytes[..4];
                        tlvs.set_hmac(key, response_seq_bytes);
                    }
                }

                response.extend_from_slice(&tlvs.to_bytes());
            }
        }
    }

    response
}

/// Verifies TLV HMAC if present in the incoming packet per RFC 8972 §4.8.
///
/// The HMAC covers the Sequence Number field (first 4 bytes) + preceding TLVs.
///
/// Returns true if no HMAC TLV is present or if verification succeeds.
/// Returns false if HMAC verification fails.
pub fn verify_incoming_tlv_hmac(original_data: &[u8], base_size: usize, key: &HmacKey) -> bool {
    if original_data.len() <= base_size {
        return true; // No TLVs to verify
    }

    let tlv_data = &original_data[base_size..];
    let Ok(tlvs) = TlvList::parse(tlv_data) else {
        return false; // Malformed TLVs
    };

    if tlvs.hmac_tlv().is_none() {
        return true; // No HMAC TLV to verify
    }

    // Per RFC 8972 §4.8: HMAC covers Sequence Number (first 4 bytes) + preceding TLVs
    let sequence_number_bytes = &original_data[..4];
    tlvs.verify_hmac(key, sequence_number_bytes, tlv_data)
        .is_ok()
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
        assert_eq!(
            reflected.sess_sender_seq_number,
            sender_packet.sequence_number
        );
        assert_eq!(reflected.sess_sender_timestamp, sender_packet.timestamp);
        assert_eq!(
            reflected.sess_sender_err_estimate,
            sender_packet.error_estimate
        );
        assert_eq!(reflected.sess_sender_ttl, ttl);
        // Verify reflector's own error estimate is used
        assert_eq!(reflected.error_estimate, reflector_error_estimate);
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

        assert_eq!(reflected.receive_timestamp, rcvt);
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
        assert!(reflected.timestamp > 0);
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
        assert_eq!(
            reflected.sess_sender_seq_number,
            sender_packet.sequence_number
        );
        assert_eq!(reflected.sess_sender_timestamp, sender_packet.timestamp);
        assert_eq!(
            reflected.sess_sender_err_estimate,
            sender_packet.error_estimate
        );
        assert_eq!(reflected.sess_sender_ttl, ttl);
        // Verify reflector's own error estimate is used
        assert_eq!(reflected.error_estimate, reflector_error_estimate);
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
            assert_eq!(reflected.sess_sender_ttl, ttl);
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
            assert_eq!(reflected.sess_sender_ttl, ttl);
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
        assert_ne!(reflected.hmac, [0u8; 16]);
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
        assert_eq!(reflected.hmac, [0u8; 16]);
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
        assert_eq!(reflected.sequence_number, 999);
        // Sender's sequence still echoed in sess_sender_seq_number
        assert_eq!(reflected.sess_sender_seq_number, 42);
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
        assert_eq!(reflected.sequence_number, 999);
        // Sender's sequence still echoed in sess_sender_seq_number
        assert_eq!(reflected.sess_sender_seq_number, 42);
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
        // Extra bytes should be zeros per RFC 8762 Section 4.2.1
        assert_eq!(&response[44..], &[0x00, 0x00, 0x00, 0x00]);
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
        // Extra bytes should be zeros per RFC 8762 Section 4.2.1
        assert_eq!(&response[112..], &[0x00, 0x00, 0x00, 0x00, 0x00]);
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

    // TLV-aware assembly tests

    #[test]
    fn test_assemble_unauth_with_tlvs_ignore_mode() {
        use crate::tlv::{RawTlv, TlvType, TLV_HEADER_SIZE};

        let sender_packet = PacketUnauthenticated {
            sequence_number: 1,
            timestamp: 100,
            error_estimate: 10,
            mbz: [0; 30],
        };

        // Create packet with TLV extension
        let mut original_data = sender_packet.to_bytes().to_vec();
        let tlv = RawTlv::new(TlvType::ExtraPadding, vec![0xAA; 8]);
        original_data.extend_from_slice(&tlv.to_bytes());

        let response = assemble_unauth_answer_with_tlvs(
            &sender_packet,
            &original_data,
            ClockFormat::NTP,
            200,
            64,
            300,
            None,
            TlvHandlingMode::Ignore,
            None,
            false,
        );

        // Response should match original length but TLVs stripped (zero-padded)
        assert_eq!(response.len(), 44 + TLV_HEADER_SIZE + 8);
        // Extra bytes should be zero (TLVs stripped)
        assert!(response[44..].iter().all(|&b| b == 0));
    }

    #[test]
    fn test_assemble_unauth_with_tlvs_echo_mode() {
        use crate::tlv::{RawTlv, TlvType, TLV_HEADER_SIZE};

        let sender_packet = PacketUnauthenticated {
            sequence_number: 1,
            timestamp: 100,
            error_estimate: 10,
            mbz: [0; 30],
        };

        // Create packet with TLV extension
        let mut original_data = sender_packet.to_bytes().to_vec();
        let tlv = RawTlv::new(TlvType::ExtraPadding, vec![0xAA; 4]);
        original_data.extend_from_slice(&tlv.to_bytes());

        let response = assemble_unauth_answer_with_tlvs(
            &sender_packet,
            &original_data,
            ClockFormat::NTP,
            200,
            64,
            300,
            None,
            TlvHandlingMode::Echo,
            None,
            false,
        );

        // Response should include echoed TLV
        assert_eq!(response.len(), 44 + TLV_HEADER_SIZE + 4);
        // TLV should be echoed (check type in byte 1 per RFC 8972)
        assert_eq!(response[45], 1); // ExtraPadding type
    }

    #[test]
    fn test_assemble_unauth_with_tlvs_marks_unknown() {
        use crate::tlv::{RawTlv, TlvType, TLV_HEADER_SIZE};

        let sender_packet = PacketUnauthenticated {
            sequence_number: 1,
            timestamp: 100,
            error_estimate: 10,
            mbz: [0; 30],
        };

        // Create packet with unknown TLV type
        let mut original_data = sender_packet.to_bytes().to_vec();
        let tlv = RawTlv::new(TlvType::Unknown(15), vec![0xBB; 4]);
        original_data.extend_from_slice(&tlv.to_bytes());

        let response = assemble_unauth_answer_with_tlvs(
            &sender_packet,
            &original_data,
            ClockFormat::NTP,
            200,
            64,
            300,
            None,
            TlvHandlingMode::Echo,
            None,
            false,
        );

        // Check U-flag is set (bit 0 of flags byte per RFC 8972)
        // Byte 0: Flags (U=0x80), Byte 1: Type
        assert_eq!(response[44], 0x80); // U-flag set in flags byte
        assert_eq!(response[45], 15); // Type 15 in type byte
        assert_eq!(response.len(), 44 + TLV_HEADER_SIZE + 4);
    }

    #[test]
    fn test_assemble_auth_with_tlvs_ignore_mode() {
        use crate::tlv::{RawTlv, TlvType, TLV_HEADER_SIZE};

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

        // Create packet with TLV extension
        let mut original_data = sender_packet.to_bytes().to_vec();
        let tlv = RawTlv::new(TlvType::ExtraPadding, vec![0xCC; 8]);
        original_data.extend_from_slice(&tlv.to_bytes());

        let response = assemble_auth_answer_with_tlvs(
            &sender_packet,
            &original_data,
            ClockFormat::NTP,
            200,
            64,
            300,
            None,
            None,
            TlvHandlingMode::Ignore,
            None,
            false,
        );

        // Response should match original length but TLVs stripped
        assert_eq!(response.len(), 112 + TLV_HEADER_SIZE + 8);
        // Extra bytes should be zero
        assert!(response[112..].iter().all(|&b| b == 0));
    }

    #[test]
    fn test_assemble_auth_with_tlvs_echo_mode() {
        use crate::tlv::{RawTlv, TlvType, TLV_HEADER_SIZE};

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

        // Create packet with TLV extension
        let mut original_data = sender_packet.to_bytes().to_vec();
        let tlv = RawTlv::new(TlvType::Location, vec![1, 2, 3, 4]);
        original_data.extend_from_slice(&tlv.to_bytes());

        let response = assemble_auth_answer_with_tlvs(
            &sender_packet,
            &original_data,
            ClockFormat::NTP,
            200,
            64,
            300,
            None,
            None,
            TlvHandlingMode::Echo,
            None,
            false,
        );

        // Response should include echoed TLV
        assert_eq!(response.len(), 112 + TLV_HEADER_SIZE + 4);
        // TLV should be echoed (check type in byte 1 per RFC 8972)
        assert_eq!(response[113], 2); // Location type
    }

    #[test]
    fn test_assemble_unauth_with_tlvs_adds_hmac() {
        use crate::tlv::{RawTlv, TlvType, HMAC_TLV_VALUE_SIZE, TLV_HEADER_SIZE};

        let sender_packet = PacketUnauthenticated {
            sequence_number: 1,
            timestamp: 100,
            error_estimate: 10,
            mbz: [0; 30],
        };

        // Create packet with TLV extension (no HMAC)
        let mut original_data = sender_packet.to_bytes().to_vec();
        let tlv = RawTlv::new(TlvType::ExtraPadding, vec![0xDD; 4]);
        original_data.extend_from_slice(&tlv.to_bytes());

        let key = HmacKey::new(vec![0xAB; 32]).unwrap();
        let response = assemble_unauth_answer_with_tlvs(
            &sender_packet,
            &original_data,
            ClockFormat::NTP,
            200,
            64,
            300,
            None,
            TlvHandlingMode::Echo,
            Some(&key),
            false,
        );

        // Response should include ExtraPadding + HMAC TLV
        // 44 base + (4 header + 4 value) + (4 header + 16 value)
        assert_eq!(
            response.len(),
            44 + TLV_HEADER_SIZE + 4 + TLV_HEADER_SIZE + HMAC_TLV_VALUE_SIZE
        );

        // HMAC TLV should be last (type 8 in byte 1 per RFC 8972)
        let hmac_tlv_start = 44 + TLV_HEADER_SIZE + 4;
        assert_eq!(response[hmac_tlv_start + 1], 8);
    }

    #[test]
    fn test_verify_incoming_tlv_hmac_no_tlvs() {
        let key = HmacKey::new(vec![0xAB; 32]).unwrap();
        let packet_data = [0u8; 44]; // Just base packet

        assert!(verify_incoming_tlv_hmac(
            &packet_data,
            UNAUTH_BASE_SIZE,
            &key
        ));
    }

    #[test]
    fn test_verify_incoming_tlv_hmac_no_hmac_tlv() {
        use crate::tlv::{RawTlv, TlvType};

        let key = HmacKey::new(vec![0xAB; 32]).unwrap();

        // Create packet with TLV but no HMAC
        let mut packet_data = vec![0u8; 44];
        let tlv = RawTlv::new(TlvType::ExtraPadding, vec![0; 4]);
        packet_data.extend_from_slice(&tlv.to_bytes());

        assert!(verify_incoming_tlv_hmac(
            &packet_data,
            UNAUTH_BASE_SIZE,
            &key
        ));
    }

    #[test]
    fn test_verify_incoming_tlv_hmac_valid() {
        use crate::tlv::{RawTlv, TlvList, TlvType};

        let key = HmacKey::new(vec![0xAB; 32]).unwrap();

        // Create base packet
        let base_packet = vec![0x01u8; 44];

        // Create TLV list with HMAC
        let mut tlvs = TlvList::new();
        tlvs.push(RawTlv::new(TlvType::ExtraPadding, vec![0xCC; 4]))
            .unwrap();
        tlvs.set_hmac(&key, &base_packet);

        // Combine base + TLVs
        let mut packet_data = base_packet.clone();
        packet_data.extend_from_slice(&tlvs.to_bytes());

        assert!(verify_incoming_tlv_hmac(
            &packet_data,
            UNAUTH_BASE_SIZE,
            &key
        ));
    }

    #[test]
    fn test_verify_incoming_tlv_hmac_invalid() {
        use crate::tlv::{RawTlv, TlvList, TlvType};

        let key1 = HmacKey::new(vec![0xAB; 32]).unwrap();
        let key2 = HmacKey::new(vec![0xCD; 32]).unwrap();

        // Create base packet
        let base_packet = vec![0x01u8; 44];

        // Create TLV list with HMAC using key1
        let mut tlvs = TlvList::new();
        tlvs.push(RawTlv::new(TlvType::ExtraPadding, vec![0xCC; 4]))
            .unwrap();
        tlvs.set_hmac(&key1, &base_packet);

        // Combine base + TLVs
        let mut packet_data = base_packet.clone();
        packet_data.extend_from_slice(&tlvs.to_bytes());

        // Verify with wrong key
        assert!(!verify_incoming_tlv_hmac(
            &packet_data,
            UNAUTH_BASE_SIZE,
            &key2
        ));
    }

    #[test]
    fn test_assemble_unauth_with_tlvs_hmac_failure_preserves_original() {
        use crate::tlv::{RawTlv, TlvList, TlvType, TLV_HEADER_SIZE};

        let key1 = HmacKey::new(vec![0xAB; 32]).unwrap();
        let key2 = HmacKey::new(vec![0xCD; 32]).unwrap();

        let sender_packet = PacketUnauthenticated {
            sequence_number: 0x12345678,
            timestamp: 100,
            error_estimate: 10,
            mbz: [0; 30],
        };
        let base_bytes = sender_packet.to_bytes();

        // Create TLV list with HMAC using key1
        let mut tlvs = TlvList::new();
        tlvs.push(RawTlv::new(TlvType::ExtraPadding, vec![0xCC; 4]))
            .unwrap();
        tlvs.set_hmac(&key1, &base_bytes);

        // Save original HMAC value
        let original_hmac = tlvs.hmac_tlv().unwrap().value.clone();

        // Combine base + TLVs
        let mut original_data = base_bytes.to_vec();
        original_data.extend_from_slice(&tlvs.to_bytes());

        // Reflect with verification using wrong key (key2)
        // This should fail HMAC verification and set I-flag on all TLVs
        let response = assemble_unauth_answer_with_tlvs(
            &sender_packet,
            &original_data,
            ClockFormat::NTP,
            200,
            64,
            300,
            None,
            TlvHandlingMode::Echo,
            Some(&key2), // Wrong key for verification
            true,        // Verify HMAC (will fail)
        );

        // Response should include TLVs
        // Base (44) + ExtraPadding TLV (4+4) + HMAC TLV (4+16) = 72 bytes
        assert_eq!(
            response.len(),
            44 + TLV_HEADER_SIZE + 4 + TLV_HEADER_SIZE + 16
        );

        // Find HMAC TLV in response (last TLV)
        let hmac_tlv_start = 44 + TLV_HEADER_SIZE + 4;

        // Check I-flag is set on HMAC TLV (bit 5 of flags byte)
        let hmac_flags = response[hmac_tlv_start];
        assert!(
            hmac_flags & 0x20 != 0,
            "I-flag should be set on HMAC TLV, flags={:02x}",
            hmac_flags
        );

        // Check HMAC value is preserved (NOT regenerated)
        let response_hmac = &response[hmac_tlv_start + TLV_HEADER_SIZE..];
        assert_eq!(
            response_hmac,
            &original_hmac[..],
            "HMAC should be preserved on verification failure, not regenerated"
        );
    }

    #[test]
    fn test_assemble_unauth_with_tlvs_hmac_success_regenerates() {
        use crate::tlv::{RawTlv, TlvList, TlvType, TLV_HEADER_SIZE};

        let key = HmacKey::new(vec![0xAB; 32]).unwrap();

        let sender_packet = PacketUnauthenticated {
            sequence_number: 0x12345678,
            timestamp: 100,
            error_estimate: 10,
            mbz: [0; 30],
        };
        let base_bytes = sender_packet.to_bytes();

        // Create TLV list with HMAC
        let mut tlvs = TlvList::new();
        tlvs.push(RawTlv::new(TlvType::ExtraPadding, vec![0xCC; 4]))
            .unwrap();
        tlvs.set_hmac(&key, &base_bytes);

        // Save original HMAC value
        let original_hmac = tlvs.hmac_tlv().unwrap().value.clone();

        // Combine base + TLVs
        let mut original_data = base_bytes.to_vec();
        original_data.extend_from_slice(&tlvs.to_bytes());

        // Reflect with verification using correct key and a DIFFERENT reflector seq
        // This should pass HMAC verification and regenerate HMAC for response
        // (HMAC covers sequence number, so different seq = different HMAC)
        let response = assemble_unauth_answer_with_tlvs(
            &sender_packet,
            &original_data,
            ClockFormat::NTP,
            200,
            64,
            300,
            Some(0x87654321), // Different reflector sequence number
            TlvHandlingMode::Echo,
            Some(&key), // Correct key for verification
            true,       // Verify HMAC (will succeed)
        );

        // Response should include TLVs
        assert_eq!(
            response.len(),
            44 + TLV_HEADER_SIZE + 4 + TLV_HEADER_SIZE + 16
        );

        // Find HMAC TLV in response (last TLV)
        let hmac_tlv_start = 44 + TLV_HEADER_SIZE + 4;

        // Check I-flag is NOT set on HMAC TLV
        let hmac_flags = response[hmac_tlv_start];
        assert!(
            hmac_flags & 0x20 == 0,
            "I-flag should NOT be set on successful verification, flags={:02x}",
            hmac_flags
        );

        // Check HMAC value is DIFFERENT (regenerated for new sequence number)
        let response_hmac = &response[hmac_tlv_start + TLV_HEADER_SIZE..];
        assert_ne!(
            response_hmac,
            &original_hmac[..],
            "HMAC should be regenerated on successful verification"
        );
    }

    #[test]
    fn test_assemble_unauth_with_malformed_tlv_sets_mflag() {
        let sender_packet = PacketUnauthenticated {
            sequence_number: 0x12345678,
            timestamp: 100,
            error_estimate: 10,
            mbz: [0; 30],
        };
        let base_bytes = sender_packet.to_bytes();

        // Create a truncated/malformed TLV manually:
        // Header says length is 100 bytes, but only 4 bytes of value are present
        let mut original_data = base_bytes.to_vec();
        original_data.push(0x00); // Flags (no flags set by sender)
        original_data.push(0x01); // Type = ExtraPadding
        original_data.extend_from_slice(&100u16.to_be_bytes()); // Length = 100 (but only 4 available)
        original_data.extend_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD]); // Only 4 bytes of value

        // Reflect the packet
        let response = assemble_unauth_answer_with_tlvs(
            &sender_packet,
            &original_data,
            ClockFormat::NTP,
            200,
            64,
            300,
            None,
            TlvHandlingMode::Echo,
            None,
            false,
        );

        // Response should include base + malformed TLV (header + truncated value)
        // The TLV should have whatever data was available
        assert!(response.len() > 44, "Response should include TLV data");

        // Check M-flag is set on the TLV (bit 6 of flags byte = 0x40)
        let tlv_flags = response[44];
        assert!(
            tlv_flags & 0x40 != 0,
            "M-flag should be set on malformed TLV, flags={:02x}",
            tlv_flags
        );

        // Type should be preserved
        assert_eq!(response[45], 0x01, "TLV type should be preserved");
    }

    #[test]
    fn test_assemble_unauth_with_malformed_tlv_no_hmac_regen() {
        use crate::tlv::TLV_HEADER_SIZE;

        let key = HmacKey::new(vec![0xAB; 32]).unwrap();

        let sender_packet = PacketUnauthenticated {
            sequence_number: 0x12345678,
            timestamp: 100,
            error_estimate: 10,
            mbz: [0; 30],
        };
        let base_bytes = sender_packet.to_bytes();

        // Create a truncated/malformed TLV
        let mut original_data = base_bytes.to_vec();
        original_data.push(0x00); // Flags
        original_data.push(0x01); // Type = ExtraPadding
        original_data.extend_from_slice(&50u16.to_be_bytes()); // Length = 50 (but only 4 available)
        original_data.extend_from_slice(&[0x11, 0x22, 0x33, 0x44]); // Only 4 bytes

        // Reflect with HMAC key - should NOT regenerate HMAC due to malformed TLV
        let response = assemble_unauth_answer_with_tlvs(
            &sender_packet,
            &original_data,
            ClockFormat::NTP,
            200,
            64,
            300,
            None,
            TlvHandlingMode::Echo,
            Some(&key),
            false,
        );

        // Response should only have the malformed TLV, no HMAC TLV added
        // (because we don't regenerate HMAC when there are malformed TLVs)
        assert!(response.len() > 44);

        // Check M-flag is set
        let tlv_flags = response[44];
        assert!(
            tlv_flags & 0x40 != 0,
            "M-flag should be set on malformed TLV"
        );

        // Should NOT have an HMAC TLV appended (response should be relatively short)
        // Base (44) + header (4) + truncated value (4) = 52 bytes
        assert_eq!(
            response.len(),
            44 + TLV_HEADER_SIZE + 4,
            "Should not have HMAC TLV when TLVs are malformed"
        );
    }
}
