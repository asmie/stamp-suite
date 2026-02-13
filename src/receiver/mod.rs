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

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::{
    configuration::{ClockFormat, Configuration, TlvHandlingMode},
    crypto::{compute_packet_hmac, verify_packet_hmac, HmacKey},
    packets::{
        PacketAuthenticated, PacketUnauthenticated, ReflectedPacketAuthenticated,
        ReflectedPacketUnauthenticated,
    },
    session::SessionManager,
    stats::{self, OutputFormat},
    time::generate_timestamp,
    tlv::{
        PacketAddressInfo, ReturnPathAction, SyncSource, TimestampMethod, TlvList, TlvType,
        TLV_HEADER_SIZE,
    },
};

/// Loads the HMAC key from configuration (hex string or file).
pub fn load_hmac_key(conf: &Configuration) -> Option<HmacKey> {
    if let Some(ref hex_key) = conf.hmac_key {
        match HmacKey::from_hex(hex_key) {
            Ok(key) => return Some(key),
            Err(e) => {
                eprintln!("Failed to parse HMAC key: {}", e);
                return None;
            }
        }
    }

    if let Some(ref path) = conf.hmac_key_file {
        match HmacKey::from_file(path) {
            Ok(key) => return Some(key),
            Err(e) => {
                eprintln!("Failed to load HMAC key from file: {}", e);
                return None;
            }
        }
    }

    None
}

/// Aggregate packet counters for the reflector.
pub struct ReflectorCounters {
    pub packets_received: AtomicU64,
    pub packets_reflected: AtomicU64,
    pub packets_dropped: AtomicU64,
}

impl ReflectorCounters {
    pub fn new() -> Self {
        ReflectorCounters {
            packets_received: AtomicU64::new(0),
            packets_reflected: AtomicU64::new(0),
            packets_dropped: AtomicU64::new(0),
        }
    }
}

impl Default for ReflectorCounters {
    fn default() -> Self {
        Self::new()
    }
}

/// Shared state created externally and passed into receiver backends.
///
/// This allows the SNMP sub-agent (and other subsystems) to access
/// reflector counters and session state concurrently.
pub struct ReceiverSharedState {
    pub counters: Arc<ReflectorCounters>,
    pub session_manager: Arc<SessionManager>,
    pub start_time: Instant,
}

/// Creates the shared state for the receiver, using configuration values.
pub fn create_shared_state(conf: &Configuration) -> ReceiverSharedState {
    let session_timeout = if conf.session_timeout > 0 {
        Some(Duration::from_secs(conf.session_timeout))
    } else {
        None
    };

    ReceiverSharedState {
        counters: Arc::new(ReflectorCounters::new()),
        session_manager: Arc::new(SessionManager::new(session_timeout)),
        start_time: Instant::now(),
    }
}

/// Builds and prints the reflector shutdown statistics.
pub fn print_reflector_stats(
    counters: &ReflectorCounters,
    session_manager: &SessionManager,
    start_time: Instant,
    output_format: OutputFormat,
) {
    let stats = stats::build_reflector_stats(
        counters.packets_received.load(Ordering::Relaxed),
        counters.packets_reflected.load(Ordering::Relaxed),
        counters.packets_dropped.load(Ordering::Relaxed),
        session_manager.session_summaries(),
        session_manager.session_count(),
        start_time.elapsed().as_secs_f64(),
    );
    stats.print(output_format);
}

/// HMAC field offset in ReflectedPacketAuthenticated (bytes before HMAC field).
pub const REFLECTED_AUTH_PACKET_HMAC_OFFSET: usize = 96;

/// Updates the RP (policy rejected) flag in a CoS TLV within the response buffer.
///
/// This should be called when setsockopt fails to apply the requested DSCP/ECN,
/// per RFC 8972 §5.2 which requires setting RP=1 to indicate policy rejection.
///
/// # Arguments
/// * `response` - The response buffer containing TLVs after the base packet
/// * `base_packet_size` - Size of the base packet (44 for unauth, 112 for auth)
///
/// # Returns
/// `true` if a CoS TLV was found and updated, `false` otherwise.
pub fn set_cos_policy_rejected(response: &mut [u8], base_packet_size: usize) -> bool {
    if response.len() <= base_packet_size {
        return false; // No TLV area
    }

    let tlv_area = &mut response[base_packet_size..];
    let mut offset = 0;

    while offset + TLV_HEADER_SIZE <= tlv_area.len() {
        // Check for trailing zero-padding: only treat all-zero header as padding
        // if ALL remaining bytes are zeros. A Reserved TLV (type=0) with zero-length
        // is valid and should not stop iteration if followed by real TLVs.
        if tlv_area[offset..offset + TLV_HEADER_SIZE] == [0, 0, 0, 0]
            && tlv_area[offset..].iter().all(|&b| b == 0)
        {
            break;
        }

        let tlv_type = TlvType::from_byte(tlv_area[offset + 1]);
        let length = u16::from_be_bytes([tlv_area[offset + 2], tlv_area[offset + 3]]) as usize;
        let value_start = offset + TLV_HEADER_SIZE;
        let value_end = value_start + length.min(tlv_area.len() - value_start);

        if tlv_type == TlvType::ClassOfService && value_end >= value_start + 3 {
            // CoS TLV found - set RP flag (bits 6-7 of byte 2 in value)
            // RP=1 means policy rejected the DSCP request
            let rp_byte_offset = value_start + 2;
            // Set RP bits (upper 2 bits) to 01 (rejected), preserving reserved bits
            tlv_area[rp_byte_offset] = (tlv_area[rp_byte_offset] & 0x3F) | 0x40;
            return true;
        }

        offset += TLV_HEADER_SIZE + length;
    }

    false
}

/// Sets the U-flag on the Return Path TLV in a serialized STAMP response.
///
/// Walks the TLV area to find a Return Path TLV (type 10) and sets its
/// unrecognized flag. Used when the reflector cannot honor the requested
/// return path (e.g., alternate-address send failure) per RFC 9503 §5.
///
/// Returns `true` if the Return Path TLV was found and updated.
pub fn set_return_path_u_flag_in_response(response: &mut [u8], base_packet_size: usize) -> bool {
    if response.len() <= base_packet_size {
        return false;
    }

    let tlv_area = &mut response[base_packet_size..];
    let mut offset = 0;

    while offset + TLV_HEADER_SIZE <= tlv_area.len() {
        if tlv_area[offset..offset + TLV_HEADER_SIZE] == [0, 0, 0, 0]
            && tlv_area[offset..].iter().all(|&b| b == 0)
        {
            break;
        }

        let tlv_type = TlvType::from_byte(tlv_area[offset + 1]);
        let length = u16::from_be_bytes([tlv_area[offset + 2], tlv_area[offset + 3]]) as usize;

        if tlv_type == TlvType::ReturnPath {
            // Set U-flag (bit 7) on the flags byte
            tlv_area[offset] |= 0x80;
            return true;
        }

        offset += TLV_HEADER_SIZE + length;
    }

    false
}

/// Recomputes the TLV HMAC in a serialized STAMP response after in-place mutation.
///
/// This must be called after any modification to the TLV area of an already-assembled
/// response (e.g., after `set_cos_policy_rejected` sets the RP flag) to keep the
/// HMAC consistent with the packet contents.
///
/// The function locates the HMAC TLV at the end of the response (per RFC 8972 §4.8,
/// HMAC TLV is always last), recomputes the HMAC over `seq_bytes + preceding TLVs`,
/// and overwrites the HMAC value in place.
///
/// Returns `true` if the HMAC was recomputed, `false` if no HMAC TLV was found.
pub fn recompute_response_tlv_hmac(
    data: &mut [u8],
    base_packet_size: usize,
    hmac_key: &HmacKey,
) -> bool {
    // HMAC TLV: header (4 bytes) + value (16 bytes) = 20 bytes total
    const HMAC_TLV_SIZE: usize = TLV_HEADER_SIZE + 16;

    if data.len() < base_packet_size + HMAC_TLV_SIZE || data.len() < 4 {
        return false;
    }

    // HMAC TLV is always serialized last (TlvList::write_to guarantees this)
    let hmac_tlv_offset = data.len() - HMAC_TLV_SIZE;

    // Verify the last TLV is actually an HMAC TLV (type byte at offset 1 in header)
    if TlvType::from_byte(data[hmac_tlv_offset + 1]) != TlvType::Hmac {
        return false;
    }

    // HMAC input: seq_bytes (first 4 bytes of packet) + all TLV bytes before the HMAC TLV
    let preceding_len = hmac_tlv_offset - base_packet_size;
    let mut hmac_input = Vec::with_capacity(4 + preceding_len);
    hmac_input.extend_from_slice(&data[..4]);
    hmac_input.extend_from_slice(&data[base_packet_size..hmac_tlv_offset]);

    let hmac = hmac_key.compute(&hmac_input);

    // Overwrite HMAC value in place (value starts after the 4-byte header)
    let value_start = hmac_tlv_offset + TLV_HEADER_SIZE;
    data[value_start..value_start + 16].copy_from_slice(&hmac);
    true
}

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

/// HMAC offset in authenticated sender packets (for verifying incoming packets).
const AUTH_PACKET_HMAC_OFFSET: usize = 96;

/// Response from STAMP packet processing, including optional CoS request.
#[derive(Debug)]
pub struct StampResponse {
    /// The response packet data to send.
    pub data: Vec<u8>,
    /// Requested DSCP/ECN from CoS TLV (if present).
    /// Tuple of (dscp1, ecn1) that should be applied to the outgoing packet.
    pub cos_request: Option<(u8, u8)>,
    /// Action determined by Return Path TLV processing (RFC 9503 §5).
    pub return_path_action: ReturnPathAction,
}

/// Context for processing STAMP packets, shared between backends.
pub struct ProcessingContext<'a> {
    /// Clock format for timestamps.
    pub clock_source: ClockFormat,
    /// Error estimate in wire format.
    pub error_estimate_wire: u16,
    /// HMAC key for authentication.
    pub hmac_key: Option<&'a HmacKey>,
    /// Whether HMAC is required.
    pub require_hmac: bool,
    /// Session manager for stateful mode.
    pub session_manager: Option<&'a Arc<SessionManager>>,
    /// TLV handling mode.
    pub tlv_mode: TlvHandlingMode,
    /// Whether to verify incoming TLV HMAC.
    pub verify_tlv_hmac: bool,
    /// Whether to use strict packet parsing.
    pub strict_packets: bool,
    /// Whether metrics recording is enabled.
    #[cfg(feature = "metrics")]
    pub metrics_enabled: bool,
    /// DSCP value received from IP header (6 bits, 0-63).
    pub received_dscp: u8,
    /// ECN value received from IP header (2 bits, 0-3).
    pub received_ecn: u8,
    /// Reflector packet receive count (for Direct Measurement TLV).
    pub reflector_rx_count: Option<u32>,
    /// Reflector packet transmit count (for Direct Measurement TLV).
    pub reflector_tx_count: Option<u32>,
    /// Packet address information (for Location TLV).
    pub packet_addr_info: Option<PacketAddressInfo>,
    /// Last reflection data: (seq, timestamp) for Follow-Up Telemetry TLV.
    pub last_reflection: Option<(u32, u64)>,
    /// Local addresses for Destination Node Address TLV matching (RFC 9503 §4).
    pub local_addresses: &'a [std::net::IpAddr],
    /// Sender's UDP port for Return Path alternate address replies (RFC 9503 §5).
    pub sender_port: u16,
}

/// Processes a STAMP packet and returns the response.
///
/// This is the shared packet processing logic used by both nix and pnet backends.
/// Handles parsing, HMAC verification, and response assembly for both authenticated
/// and unauthenticated modes.
///
/// # Arguments
/// * `data` - The raw packet data
/// * `src` - Source address for session tracking
/// * `ttl` - TTL/Hop Limit from IP header
/// * `use_auth` - Whether authenticated mode is enabled
/// * `ctx` - Processing context with configuration
///
/// # Returns
/// `Some(StampResponse)` on success, `None` if packet should be dropped.
/// The response includes the packet data and optional CoS request (DSCP1/ECN1).
pub fn process_stamp_packet(
    data: &[u8],
    src: SocketAddr,
    ttl: u8,
    use_auth: bool,
    ctx: &ProcessingContext,
) -> Option<StampResponse> {
    #[cfg(feature = "metrics")]
    let start_time = if ctx.metrics_enabled {
        Some(std::time::Instant::now())
    } else {
        None
    };

    #[cfg(feature = "metrics")]
    if ctx.metrics_enabled {
        crate::metrics::reflector_metrics::record_packet_received();
    }

    let rcvt = generate_timestamp(ctx.clock_source);

    // Determine if packet has TLVs
    let base_size = if use_auth {
        AUTH_BASE_SIZE
    } else {
        UNAUTH_BASE_SIZE
    };
    let has_tlvs = data.len() > base_size;

    // TLV HMAC key for responses (only if we're not ignoring TLVs)
    // Per RFC 8972 §4.8: on HMAC verification failure, TLVs are echoed
    // with I-flag set rather than dropping the packet
    let tlv_hmac_key = if ctx.tlv_mode != TlvHandlingMode::Ignore {
        ctx.hmac_key
    } else {
        None
    };

    // Determine whether to verify incoming TLV HMAC:
    // - Always verify if --verify-tlv-hmac is set
    // - Auto-verify when HMAC key is configured (regardless of auth mode)
    let verify_tlv_hmac = ctx.verify_tlv_hmac || ctx.hmac_key.is_some();

    let result = if use_auth {
        process_auth_packet(
            data,
            src,
            ttl,
            rcvt,
            has_tlvs,
            tlv_hmac_key,
            verify_tlv_hmac,
            ctx,
        )
    } else {
        process_unauth_packet(
            data,
            src,
            ttl,
            rcvt,
            has_tlvs,
            tlv_hmac_key,
            verify_tlv_hmac,
            ctx,
        )
    };

    #[cfg(feature = "metrics")]
    if ctx.metrics_enabled {
        if result.is_some() {
            crate::metrics::reflector_metrics::record_packet_reflected();
        }
        if let Some(start) = start_time {
            let elapsed = start.elapsed().as_secs_f64();
            crate::metrics::reflector_metrics::record_processing_time(elapsed);
        }
    }

    result
}

/// Processes an authenticated STAMP packet.
#[allow(clippy::too_many_arguments)]
fn process_auth_packet(
    data: &[u8],
    src: SocketAddr,
    ttl: u8,
    rcvt: u64,
    has_tlvs: bool,
    tlv_hmac_key: Option<&HmacKey>,
    verify_tlv_hmac: bool,
    ctx: &ProcessingContext,
) -> Option<StampResponse> {
    // Parse packet leniently with canonical buffer for HMAC verification
    // Per RFC 8762 §4.6, short packets are zero-filled and HMAC must be
    // verified against the canonical (zero-padded) representation
    let (packet, canonical_buf) = if ctx.strict_packets {
        match PacketAuthenticated::from_bytes(data) {
            Ok(p) => {
                let mut buf = [0u8; 112];
                buf.copy_from_slice(&data[..112]);
                (p, buf)
            }
            Err(e) => {
                eprintln!(
                    "Failed to deserialize authenticated packet from {}: {}",
                    src, e
                );
                #[cfg(feature = "metrics")]
                if ctx.metrics_enabled {
                    crate::metrics::reflector_metrics::record_packet_dropped("parse_error");
                }
                return None;
            }
        }
    } else {
        PacketAuthenticated::from_bytes_lenient_with_canonical(data)
    };

    // Extract HMAC for verification
    let hmac = packet.hmac;

    // Verify HMAC against canonical buffer - mandatory when key is present (RFC 8762 §4.4)
    if let Some(key) = ctx.hmac_key {
        if !verify_packet_hmac(key, &canonical_buf, AUTH_PACKET_HMAC_OFFSET, &hmac) {
            eprintln!("HMAC verification failed for packet from {}", src);
            #[cfg(feature = "metrics")]
            if ctx.metrics_enabled {
                crate::metrics::reflector_metrics::record_hmac_failure();
                crate::metrics::reflector_metrics::record_packet_dropped("hmac_failure");
            }
            return None;
        }
    } else if ctx.require_hmac {
        eprintln!("HMAC key required but not configured");
        #[cfg(feature = "metrics")]
        if ctx.metrics_enabled {
            crate::metrics::reflector_metrics::record_packet_dropped("hmac_required");
        }
        return None;
    }

    // Generate reflector sequence number only after successful validation
    let reflector_seq = ctx
        .session_manager
        .map(|mgr| mgr.generate_sequence_number(src));

    // Use TLV-aware assembly if packet has TLVs
    if has_tlvs {
        Some(assemble_auth_answer_with_tlvs(
            &packet,
            data,
            ctx.clock_source,
            rcvt,
            ttl,
            ctx.error_estimate_wire,
            ctx.hmac_key,
            reflector_seq,
            ctx.tlv_mode,
            tlv_hmac_key,
            verify_tlv_hmac,
            ctx,
        ))
    } else {
        Some(StampResponse {
            data: assemble_auth_answer_symmetric(
                &packet,
                data,
                ctx.clock_source,
                rcvt,
                ttl,
                ctx.error_estimate_wire,
                ctx.hmac_key,
                reflector_seq,
            ),
            cos_request: None,
            return_path_action: ReturnPathAction::Normal,
        })
    }
}

/// Processes an unauthenticated STAMP packet.
#[allow(clippy::too_many_arguments)]
fn process_unauth_packet(
    data: &[u8],
    src: SocketAddr,
    ttl: u8,
    rcvt: u64,
    has_tlvs: bool,
    tlv_hmac_key: Option<&HmacKey>,
    verify_tlv_hmac: bool,
    ctx: &ProcessingContext,
) -> Option<StampResponse> {
    let packet_result = if ctx.strict_packets {
        PacketUnauthenticated::from_bytes(data)
    } else {
        Ok(PacketUnauthenticated::from_bytes_lenient(data))
    };

    match packet_result {
        Ok(packet) => {
            // Generate reflector sequence number only after successful validation
            let reflector_seq = ctx
                .session_manager
                .map(|mgr| mgr.generate_sequence_number(src));

            // Use TLV-aware assembly if packet has TLVs
            if has_tlvs {
                Some(assemble_unauth_answer_with_tlvs(
                    &packet,
                    data,
                    ctx.clock_source,
                    rcvt,
                    ttl,
                    ctx.error_estimate_wire,
                    reflector_seq,
                    ctx.tlv_mode,
                    tlv_hmac_key,
                    verify_tlv_hmac,
                    ctx,
                ))
            } else {
                Some(StampResponse {
                    data: assemble_unauth_answer_symmetric(
                        &packet,
                        data,
                        ctx.clock_source,
                        rcvt,
                        ttl,
                        ctx.error_estimate_wire,
                        reflector_seq,
                    ),
                    cos_request: None,
                    return_path_action: ReturnPathAction::Normal,
                })
            }
        }
        Err(e) => {
            eprintln!(
                "Failed to deserialize unauthenticated packet from {}: {}",
                src, e
            );
            #[cfg(feature = "metrics")]
            if ctx.metrics_enabled {
                crate::metrics::reflector_metrics::record_packet_dropped("parse_error");
            }
            None
        }
    }
}

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
/// * `received_dscp` - DSCP value received from IP header (for CoS TLV)
/// * `received_ecn` - ECN value received from IP header (for CoS TLV)
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
    ctx: &ProcessingContext,
) -> StampResponse {
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
    let mut cos_request: Option<(u8, u8)> = None;
    let mut return_path_action = ReturnPathAction::Normal;

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

                // Parse TLVs leniently - this handles both valid and malformed TLVs in a single pass.
                // had_malformed indicates whether any TLV was malformed (which also means strict
                // parsing would have failed). This avoids double-parsing malformed/adversarial traffic.
                let (mut tlvs, had_malformed) = TlvList::parse_lenient(tlv_data);

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

                // Record TLV error metrics
                #[cfg(feature = "metrics")]
                {
                    let (u_count, m_count, i_count) = tlvs.count_error_flags();
                    for _ in 0..u_count {
                        crate::metrics::reflector_metrics::record_tlv_error("U");
                    }
                    for _ in 0..m_count {
                        crate::metrics::reflector_metrics::record_tlv_error("M");
                    }
                    for _ in 0..i_count {
                        crate::metrics::reflector_metrics::record_tlv_error("I");
                    }
                }

                // Per RFC 8972 §4.8: on HMAC failure or malformed TLVs, only echo
                // TLVs with flags set — do NOT perform semantic TLV processing.
                if hmac_ok && !had_malformed {
                    // Extract CoS request (DSCP1/ECN1) for outgoing IP_TOS
                    cos_request = tlvs.get_cos_request();

                    // Update CoS TLVs with received DSCP/ECN values (RFC 8972 §5.2)
                    tlvs.update_cos_tlvs(ctx.received_dscp, ctx.received_ecn, false);

                    // Update Timestamp Information TLVs (RFC 8972 §4.3)
                    let sync_src = match ctx.clock_source {
                        ClockFormat::NTP => SyncSource::Ntp,
                        ClockFormat::PTP => SyncSource::Ptp,
                    };
                    tlvs.update_timestamp_info_tlvs(sync_src, TimestampMethod::SwLocal);

                    // Update Direct Measurement TLVs (RFC 8972 §4.5)
                    if let (Some(rx), Some(tx)) = (ctx.reflector_rx_count, ctx.reflector_tx_count) {
                        tlvs.update_direct_measurement_tlvs(rx, tx);
                    }

                    // Update Location TLVs (RFC 8972 §4.2)
                    if let Some(ref addr_info) = ctx.packet_addr_info {
                        tlvs.update_location_tlvs(addr_info);
                    }

                    // Update Follow-Up Telemetry TLVs (RFC 8972 §4.7)
                    if let Some((last_seq, last_ts)) = ctx.last_reflection {
                        tlvs.update_follow_up_telemetry_tlvs(
                            last_seq,
                            last_ts,
                            TimestampMethod::SwLocal,
                        );
                    }

                    // Process Destination Node Address TLV (RFC 9503 §4)
                    tlvs.process_destination_node_address(ctx.local_addresses);

                    // Process Return Path TLV (RFC 9503 §5)
                    return_path_action = tlvs.process_return_path(ctx.sender_port);

                    // Compute fresh HMAC for response
                    if let Some(key) = tlv_hmac_key {
                        let response_seq_bytes = &base_bytes[..4];
                        tlvs.set_hmac(key, response_seq_bytes);
                    }
                }

                tlvs.write_to(&mut response);
            }
        }
    }

    StampResponse {
        data: response,
        cos_request,
        return_path_action,
    }
}

/// Assembles an authenticated reflected packet with TLV handling (RFC 8972).
///
/// Per RFC 8972 §4.8, on HMAC verification failure, TLVs are echoed with I-flag
/// set on ALL TLVs rather than dropping the packet.
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
    ctx: &ProcessingContext,
) -> StampResponse {
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
    let mut cos_request: Option<(u8, u8)> = None;
    let mut return_path_action = ReturnPathAction::Normal;

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

                // Parse TLVs leniently - this handles both valid and malformed TLVs in a single pass.
                // had_malformed indicates whether any TLV was malformed (which also means strict
                // parsing would have failed). This avoids double-parsing malformed/adversarial traffic.
                let (mut tlvs, had_malformed) = TlvList::parse_lenient(tlv_data);

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

                // Record TLV error metrics
                #[cfg(feature = "metrics")]
                {
                    let (u_count, m_count, i_count) = tlvs.count_error_flags();
                    for _ in 0..u_count {
                        crate::metrics::reflector_metrics::record_tlv_error("U");
                    }
                    for _ in 0..m_count {
                        crate::metrics::reflector_metrics::record_tlv_error("M");
                    }
                    for _ in 0..i_count {
                        crate::metrics::reflector_metrics::record_tlv_error("I");
                    }
                }

                // Per RFC 8972 §4.8: on HMAC failure or malformed TLVs, only echo
                // TLVs with flags set — do NOT perform semantic TLV processing.
                if hmac_ok && !had_malformed {
                    // Extract CoS request (DSCP1/ECN1) for outgoing IP_TOS
                    cos_request = tlvs.get_cos_request();

                    // Update CoS TLVs with received DSCP/ECN values (RFC 8972 §5.2)
                    tlvs.update_cos_tlvs(ctx.received_dscp, ctx.received_ecn, false);

                    // Update Timestamp Information TLVs (RFC 8972 §4.3)
                    let sync_src = match ctx.clock_source {
                        ClockFormat::NTP => SyncSource::Ntp,
                        ClockFormat::PTP => SyncSource::Ptp,
                    };
                    tlvs.update_timestamp_info_tlvs(sync_src, TimestampMethod::SwLocal);

                    // Update Direct Measurement TLVs (RFC 8972 §4.5)
                    if let (Some(rx), Some(tx)) = (ctx.reflector_rx_count, ctx.reflector_tx_count) {
                        tlvs.update_direct_measurement_tlvs(rx, tx);
                    }

                    // Update Location TLVs (RFC 8972 §4.2)
                    if let Some(ref addr_info) = ctx.packet_addr_info {
                        tlvs.update_location_tlvs(addr_info);
                    }

                    // Update Follow-Up Telemetry TLVs (RFC 8972 §4.7)
                    if let Some((last_seq, last_ts)) = ctx.last_reflection {
                        tlvs.update_follow_up_telemetry_tlvs(
                            last_seq,
                            last_ts,
                            TimestampMethod::SwLocal,
                        );
                    }

                    // Process Destination Node Address TLV (RFC 9503 §4)
                    tlvs.process_destination_node_address(ctx.local_addresses);

                    // Process Return Path TLV (RFC 9503 §5)
                    return_path_action = tlvs.process_return_path(ctx.sender_port);

                    // Compute fresh HMAC for response
                    if let Some(key) = tlv_hmac_key {
                        let response_seq_bytes = &base_bytes[..4];
                        tlvs.set_hmac(key, response_seq_bytes);
                    }
                }

                tlvs.write_to(&mut response);
            }
        }
    }

    StampResponse {
        data: response,
        cos_request,
        return_path_action,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Creates a default ProcessingContext for tests with given DSCP/ECN values.
    fn test_ctx(received_dscp: u8, received_ecn: u8) -> ProcessingContext<'static> {
        ProcessingContext {
            clock_source: ClockFormat::NTP,
            error_estimate_wire: 0,
            hmac_key: None,
            require_hmac: false,
            session_manager: None,
            tlv_mode: TlvHandlingMode::Echo,
            verify_tlv_hmac: false,
            strict_packets: false,
            #[cfg(feature = "metrics")]
            metrics_enabled: false,
            received_dscp,
            received_ecn,
            reflector_rx_count: None,
            reflector_tx_count: None,
            packet_addr_info: None,
            last_reflection: None,
            local_addresses: &[],
            sender_port: 0,
        }
    }

    /// Test helper: Verifies TLV HMAC if present in the incoming packet per RFC 8972 §4.8.
    ///
    /// The HMAC covers the Sequence Number field (first 4 bytes) + preceding TLVs.
    ///
    /// Returns true if no HMAC TLV is present or if verification succeeds.
    /// Returns false if HMAC verification fails.
    fn verify_incoming_tlv_hmac(original_data: &[u8], base_size: usize, key: &HmacKey) -> bool {
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
            &test_ctx(0, 0),
        );

        // Response should match original length but TLVs stripped (zero-padded)
        assert_eq!(response.data.len(), 44 + TLV_HEADER_SIZE + 8);
        // Extra bytes should be zero (TLVs stripped)
        assert!(response.data[44..].iter().all(|&b| b == 0));
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
            &test_ctx(0, 0),
        );

        // Response should include echoed TLV
        assert_eq!(response.data.len(), 44 + TLV_HEADER_SIZE + 4);
        // TLV should be echoed (check type in byte 1 per RFC 8972)
        assert_eq!(response.data[45], 1); // ExtraPadding type
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
            &test_ctx(0, 0),
        );

        // Check U-flag is set (bit 0 of flags byte per RFC 8972)
        // Byte 0: Flags (U=0x80), Byte 1: Type
        assert_eq!(response.data[44], 0x80); // U-flag set in flags byte
        assert_eq!(response.data[45], 15); // Type 15 in type byte
        assert_eq!(response.data.len(), 44 + TLV_HEADER_SIZE + 4);
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
            &test_ctx(0, 0),
        );

        // Response should match original length but TLVs stripped
        assert_eq!(response.data.len(), 112 + TLV_HEADER_SIZE + 8);
        // Extra bytes should be zero
        assert!(response.data[112..].iter().all(|&b| b == 0));
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
            &test_ctx(0, 0),
        );

        // Response should include echoed TLV
        assert_eq!(response.data.len(), 112 + TLV_HEADER_SIZE + 4);
        // TLV should be echoed (check type in byte 1 per RFC 8972)
        assert_eq!(response.data[113], 2); // Location type
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
            &test_ctx(0, 0),
        );

        // Response should include ExtraPadding + HMAC TLV
        // 44 base + (4 header + 4 value) + (4 header + 16 value)
        assert_eq!(
            response.data.len(),
            44 + TLV_HEADER_SIZE + 4 + TLV_HEADER_SIZE + HMAC_TLV_VALUE_SIZE
        );

        // HMAC TLV should be last (type 8 in byte 1 per RFC 8972)
        let hmac_tlv_start = 44 + TLV_HEADER_SIZE + 4;
        assert_eq!(response.data[hmac_tlv_start + 1], 8);
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
            &test_ctx(0, 0),
        );

        // Response should include TLVs
        // Base (44) + ExtraPadding TLV (4+4) + HMAC TLV (4+16) = 72 bytes
        assert_eq!(
            response.data.len(),
            44 + TLV_HEADER_SIZE + 4 + TLV_HEADER_SIZE + 16
        );

        // Find HMAC TLV in response (last TLV)
        let hmac_tlv_start = 44 + TLV_HEADER_SIZE + 4;

        // Check I-flag is set on HMAC TLV (bit 5 of flags byte)
        let hmac_flags = response.data[hmac_tlv_start];
        assert!(
            hmac_flags & 0x20 != 0,
            "I-flag should be set on HMAC TLV, flags={:02x}",
            hmac_flags
        );

        // Check HMAC value is preserved (NOT regenerated)
        let response_hmac = &response.data[hmac_tlv_start + TLV_HEADER_SIZE..];
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
            &test_ctx(0, 0),
        );

        // Response should include TLVs
        assert_eq!(
            response.data.len(),
            44 + TLV_HEADER_SIZE + 4 + TLV_HEADER_SIZE + 16
        );

        // Find HMAC TLV in response (last TLV)
        let hmac_tlv_start = 44 + TLV_HEADER_SIZE + 4;

        // Check I-flag is NOT set on HMAC TLV
        let hmac_flags = response.data[hmac_tlv_start];
        assert!(
            hmac_flags & 0x20 == 0,
            "I-flag should NOT be set on successful verification, flags={:02x}",
            hmac_flags
        );

        // Check HMAC value is DIFFERENT (regenerated for new sequence number)
        let response_hmac = &response.data[hmac_tlv_start + TLV_HEADER_SIZE..];
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
            &test_ctx(0, 0),
        );

        // Response should include base + malformed TLV (header + truncated value)
        // The TLV should have whatever data was available
        assert!(response.data.len() > 44, "Response should include TLV data");

        // Check M-flag is set on the TLV (bit 6 of flags byte = 0x40)
        let tlv_flags = response.data[44];
        assert!(
            tlv_flags & 0x40 != 0,
            "M-flag should be set on malformed TLV, flags={:02x}",
            tlv_flags
        );

        // Type should be preserved
        assert_eq!(response.data[45], 0x01, "TLV type should be preserved");
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
            &test_ctx(0, 0),
        );

        // Response should only have the malformed TLV, no HMAC TLV added
        // (because we don't regenerate HMAC when there are malformed TLVs)
        assert!(response.data.len() > 44);

        // Check M-flag is set
        let tlv_flags = response.data[44];
        assert!(
            tlv_flags & 0x40 != 0,
            "M-flag should be set on malformed TLV"
        );

        // Should NOT have an HMAC TLV appended (response should be relatively short)
        // Base (44) + header (4) + truncated value (4) = 52 bytes
        assert_eq!(
            response.data.len(),
            44 + TLV_HEADER_SIZE + 4,
            "Should not have HMAC TLV when TLVs are malformed"
        );
    }

    #[test]
    fn test_assemble_unauth_with_cos_tlv_updates_dscp_ecn() {
        use crate::tlv::{ClassOfServiceTlv, TlvType, COS_TLV_VALUE_SIZE, TLV_HEADER_SIZE};

        let sender_packet = PacketUnauthenticated {
            sequence_number: 1,
            timestamp: 100,
            error_estimate: 10,
            mbz: [0; 30],
        };

        // Create packet with CoS TLV (sender requests DSCP=46 EF, ECN=0)
        let mut original_data = sender_packet.to_bytes().to_vec();
        let cos_tlv = ClassOfServiceTlv::new(46, 0);
        original_data.extend_from_slice(&cos_tlv.to_raw().to_bytes());

        // Reflect with received DSCP=10, ECN=2 (simulating network modified values)
        let received_dscp = 10u8;
        let received_ecn = 2u8;
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
            &test_ctx(received_dscp, received_ecn),
        );

        // Response should include base + CoS TLV
        assert_eq!(
            response.data.len(),
            44 + TLV_HEADER_SIZE + COS_TLV_VALUE_SIZE
        );

        // Parse the CoS TLV from response to verify DSCP2/ECN2 were filled in
        let tlv_start = 44;
        assert_eq!(
            response.data[tlv_start + 1],
            TlvType::ClassOfService.to_byte()
        ); // Type

        // Parse the value bytes
        let value_start = tlv_start + TLV_HEADER_SIZE;
        // Byte 0: DSCP1 (6 bits) | ECN1 (2 bits) - should be preserved from sender
        let dscp1 = (response.data[value_start] >> 2) & 0x3F;
        let ecn1 = response.data[value_start] & 0x03;
        assert_eq!(dscp1, 46, "DSCP1 should be preserved");
        assert_eq!(ecn1, 0, "ECN1 should be preserved");

        // Byte 1: DSCP2 (6 bits) | ECN2 (2 bits) - should be filled by reflector
        let dscp2 = (response.data[value_start + 1] >> 2) & 0x3F;
        let ecn2 = response.data[value_start + 1] & 0x03;
        assert_eq!(dscp2, received_dscp, "DSCP2 should be received DSCP");
        assert_eq!(ecn2, received_ecn, "ECN2 should be received ECN");

        // Byte 2: RP (2 bits) - should be 0 (policy not rejected)
        let rp = (response.data[value_start + 2] >> 6) & 0x03;
        assert_eq!(rp, 0, "RP should be 0 (policy accepted)");
    }

    #[test]
    fn test_assemble_auth_with_cos_tlv_updates_dscp_ecn() {
        use crate::tlv::{ClassOfServiceTlv, TlvType, COS_TLV_VALUE_SIZE, TLV_HEADER_SIZE};

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

        // Create packet with CoS TLV (sender requests DSCP=0 BE, ECN=1)
        let mut original_data = sender_packet.to_bytes().to_vec();
        let cos_tlv = ClassOfServiceTlv::new(0, 1);
        original_data.extend_from_slice(&cos_tlv.to_raw().to_bytes());

        // Reflect with received DSCP=32, ECN=3
        let received_dscp = 32u8;
        let received_ecn = 3u8;
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
            &test_ctx(received_dscp, received_ecn),
        );

        // Response should include base + CoS TLV
        assert_eq!(
            response.data.len(),
            112 + TLV_HEADER_SIZE + COS_TLV_VALUE_SIZE
        );

        // Parse the CoS TLV from response
        let tlv_start = 112;
        assert_eq!(
            response.data[tlv_start + 1],
            TlvType::ClassOfService.to_byte()
        );

        let value_start = tlv_start + TLV_HEADER_SIZE;
        // DSCP1/ECN1 preserved
        let dscp1 = (response.data[value_start] >> 2) & 0x3F;
        let ecn1 = response.data[value_start] & 0x03;
        assert_eq!(dscp1, 0);
        assert_eq!(ecn1, 1);

        // DSCP2/ECN2 filled by reflector
        let dscp2 = (response.data[value_start + 1] >> 2) & 0x3F;
        let ecn2 = response.data[value_start + 1] & 0x03;
        assert_eq!(dscp2, received_dscp);
        assert_eq!(ecn2, received_ecn);
    }

    #[test]
    fn test_set_cos_policy_rejected_unauth() {
        use crate::tlv::ClassOfServiceTlv;

        // Build an unauthenticated response with a CoS TLV
        let sender_packet = PacketUnauthenticated {
            sequence_number: 42,
            timestamp: 100,
            error_estimate: 10,
            mbz: [0; 30],
        };
        let mut original_data = sender_packet.to_bytes().to_vec();
        let cos_tlv = ClassOfServiceTlv::new(46, 2); // DSCP=46, ECN=2
        original_data.extend_from_slice(&cos_tlv.to_raw().to_bytes());

        let mut response = assemble_unauth_answer_with_tlvs(
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
            &test_ctx(0, 0),
        );

        // Verify RP is initially 0
        let value_start = UNAUTH_BASE_SIZE + TLV_HEADER_SIZE;
        let rp_before = (response.data[value_start + 2] >> 6) & 0x03;
        assert_eq!(rp_before, 0);

        // Simulate DSCP application failure by calling set_cos_policy_rejected
        let updated = set_cos_policy_rejected(&mut response.data, UNAUTH_BASE_SIZE);
        assert!(updated);

        // Verify RP is now 1
        let rp_after = (response.data[value_start + 2] >> 6) & 0x03;
        assert_eq!(rp_after, 1);
    }

    #[test]
    fn test_set_cos_policy_rejected_auth() {
        use crate::tlv::ClassOfServiceTlv;

        // Build an authenticated response with a CoS TLV
        let sender_packet = PacketAuthenticated {
            sequence_number: 42,
            mbz0: [0; 12],
            timestamp: 100,
            error_estimate: 10,
            mbz1a: [0; 32],
            mbz1b: [0; 32],
            mbz1c: [0; 6],
            hmac: [0; 16],
        };
        let mut original_data = sender_packet.to_bytes().to_vec();
        let cos_tlv = ClassOfServiceTlv::new(46, 2);
        original_data.extend_from_slice(&cos_tlv.to_raw().to_bytes());

        let mut response = assemble_auth_answer_with_tlvs(
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
            &test_ctx(0, 0),
        );

        // Verify RP is initially 0
        let value_start = AUTH_BASE_SIZE + TLV_HEADER_SIZE;
        let rp_before = (response.data[value_start + 2] >> 6) & 0x03;
        assert_eq!(rp_before, 0);

        // Simulate DSCP application failure
        let updated = set_cos_policy_rejected(&mut response.data, AUTH_BASE_SIZE);
        assert!(updated);

        // Verify RP is now 1
        let rp_after = (response.data[value_start + 2] >> 6) & 0x03;
        assert_eq!(rp_after, 1);
    }

    #[test]
    fn test_set_cos_policy_rejected_no_cos_tlv() {
        // Build a response without a CoS TLV
        let sender_packet = PacketUnauthenticated {
            sequence_number: 42,
            timestamp: 100,
            error_estimate: 10,
            mbz: [0; 30],
        };
        let mut response = sender_packet.to_bytes().to_vec();

        // Should return false when no CoS TLV is present
        let updated = set_cos_policy_rejected(&mut response, UNAUTH_BASE_SIZE);
        assert!(!updated);
    }

    #[test]
    fn test_set_cos_policy_rejected_reserved_tlv_before_cos() {
        use crate::tlv::ClassOfServiceTlv;

        // Build a response with a zero-length Reserved TLV (header 00 00 00 00)
        // followed by a CoS TLV. The Reserved TLV must not be mistaken for padding.
        let sender_packet = PacketUnauthenticated {
            sequence_number: 42,
            timestamp: 100,
            error_estimate: 10,
            mbz: [0; 30],
        };
        let mut response = sender_packet.to_bytes().to_vec();

        // Add Reserved TLV with zero length: flags=0, type=0, length=0
        response.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);

        // Add CoS TLV after the Reserved TLV
        let cos_tlv = ClassOfServiceTlv::new(46, 2); // DSCP=46, ECN=2
        response.extend_from_slice(&cos_tlv.to_raw().to_bytes());

        // Verify RP is initially 0
        let cos_value_start = UNAUTH_BASE_SIZE + TLV_HEADER_SIZE + TLV_HEADER_SIZE; // Skip Reserved + CoS header
        let rp_before = (response[cos_value_start + 2] >> 6) & 0x03;
        assert_eq!(rp_before, 0);

        // The Reserved TLV (00 00 00 00) should NOT stop iteration because
        // it's followed by non-zero data (the CoS TLV).
        let updated = set_cos_policy_rejected(&mut response, UNAUTH_BASE_SIZE);
        assert!(updated, "Should find CoS TLV after Reserved TLV");

        // Verify RP is now 1
        let rp_after = (response[cos_value_start + 2] >> 6) & 0x03;
        assert_eq!(rp_after, 1);
    }

    #[test]
    fn test_recompute_hmac_after_rp_mutation() {
        use crate::tlv::{ClassOfServiceTlv, TlvList, TLV_HEADER_SIZE};

        let key = HmacKey::new(vec![0xAB; 32]).unwrap();

        // Build an unauthenticated packet with CoS TLV + HMAC
        let sender_packet = PacketUnauthenticated {
            sequence_number: 0x12345678,
            timestamp: 100,
            error_estimate: 10,
            mbz: [0; 30],
        };
        let base_bytes = sender_packet.to_bytes();

        let cos_tlv = ClassOfServiceTlv::new(46, 2);
        let mut tlvs = TlvList::new();
        tlvs.push(cos_tlv.to_raw()).unwrap();
        tlvs.set_hmac(&key, &base_bytes);

        let mut original_data = base_bytes.to_vec();
        original_data.extend_from_slice(&tlvs.to_bytes());

        // Assemble reflector response (HMAC will be recomputed for the response)
        let mut response = assemble_unauth_answer_with_tlvs(
            &sender_packet,
            &original_data,
            ClockFormat::NTP,
            200,
            64,
            300,
            None,
            TlvHandlingMode::Echo,
            Some(&key),
            true,
            &test_ctx(0, 0),
        );

        // Save the valid HMAC before mutation
        let hmac_start = response.data.len() - TLV_HEADER_SIZE - 16;
        let hmac_before = response.data[hmac_start + TLV_HEADER_SIZE..].to_vec();

        // Verify the response HMAC is valid before mutation
        let resp_tlv_data = &response.data[UNAUTH_BASE_SIZE..];
        let (resp_tlvs, _) = TlvList::parse_lenient(resp_tlv_data);
        assert!(
            resp_tlvs
                .verify_hmac(&key, &response.data[..4], resp_tlv_data)
                .is_ok(),
            "HMAC should be valid before RP mutation"
        );

        // Simulate RP mutation (DSCP application failure)
        assert!(set_cos_policy_rejected(
            &mut response.data,
            UNAUTH_BASE_SIZE
        ));

        // HMAC is now invalid because packet data changed
        let resp_tlv_data_after_rp = &response.data[UNAUTH_BASE_SIZE..];
        let (resp_tlvs_bad, _) = TlvList::parse_lenient(resp_tlv_data_after_rp);
        assert!(
            resp_tlvs_bad
                .verify_hmac(&key, &response.data[..4], resp_tlv_data_after_rp)
                .is_err(),
            "HMAC should be INVALID after RP mutation without recompute"
        );

        // Recompute HMAC
        assert!(recompute_response_tlv_hmac(
            &mut response.data,
            UNAUTH_BASE_SIZE,
            &key,
        ));

        // HMAC value should have changed
        let hmac_after = response.data[hmac_start + TLV_HEADER_SIZE..].to_vec();
        assert_ne!(
            hmac_before, hmac_after,
            "HMAC should change after recompute"
        );

        // Verify the recomputed HMAC is valid
        let resp_tlv_data_fixed = &response.data[UNAUTH_BASE_SIZE..];
        let (resp_tlvs_fixed, _) = TlvList::parse_lenient(resp_tlv_data_fixed);
        assert!(
            resp_tlvs_fixed
                .verify_hmac(&key, &response.data[..4], resp_tlv_data_fixed)
                .is_ok(),
            "HMAC should be valid after recompute"
        );
    }

    #[test]
    fn test_recompute_hmac_no_hmac_tlv() {
        // Response without HMAC TLV — recompute should return false
        let sender_packet = PacketUnauthenticated {
            sequence_number: 42,
            timestamp: 100,
            error_estimate: 10,
            mbz: [0; 30],
        };
        let key = HmacKey::new(vec![0xAB; 32]).unwrap();
        let mut data = sender_packet.to_bytes().to_vec();
        // Add some non-HMAC TLV bytes
        data.extend_from_slice(&[0, 1, 0, 4, 0xCC, 0xCC, 0xCC, 0xCC]);
        assert!(!recompute_response_tlv_hmac(
            &mut data,
            UNAUTH_BASE_SIZE,
            &key
        ));
    }

    // ===== RFC 9503 Integration Tests =====

    #[test]
    fn test_unauth_dest_node_addr_match() {
        use crate::tlv::DestinationNodeAddressTlv;

        let sender_packet = PacketUnauthenticated {
            sequence_number: 1,
            timestamp: 100,
            error_estimate: 10,
            mbz: [0; 30],
        };

        let addr: std::net::IpAddr = "192.168.1.1".parse().unwrap();
        let dna_tlv = DestinationNodeAddressTlv::new(addr);

        let mut original_data = sender_packet.to_bytes().to_vec();
        original_data.extend_from_slice(&dna_tlv.to_raw().to_bytes());

        let local_addrs = vec![addr];
        let mut ctx = test_ctx(0, 0);
        ctx.local_addresses = &local_addrs;

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
            &ctx,
        );

        // Check TLV is echoed without U-flag (flags byte at offset 44 = 0x00)
        assert_eq!(response.data[UNAUTH_BASE_SIZE] & 0x80, 0x00);
        assert_eq!(response.return_path_action, ReturnPathAction::Normal);
    }

    #[test]
    fn test_unauth_dest_node_addr_mismatch() {
        use crate::tlv::DestinationNodeAddressTlv;

        let sender_packet = PacketUnauthenticated {
            sequence_number: 1,
            timestamp: 100,
            error_estimate: 10,
            mbz: [0; 30],
        };

        let addr: std::net::IpAddr = "192.168.1.1".parse().unwrap();
        let dna_tlv = DestinationNodeAddressTlv::new(addr);

        let mut original_data = sender_packet.to_bytes().to_vec();
        original_data.extend_from_slice(&dna_tlv.to_raw().to_bytes());

        let local_addrs: Vec<std::net::IpAddr> = vec!["10.0.0.1".parse().unwrap()];
        let mut ctx = test_ctx(0, 0);
        ctx.local_addresses = &local_addrs;

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
            &ctx,
        );

        // Check TLV is echoed WITH U-flag set (flags byte bit 7)
        assert_eq!(response.data[UNAUTH_BASE_SIZE] & 0x80, 0x80);
    }

    #[test]
    fn test_unauth_return_path_suppress() {
        use crate::tlv::ReturnPathTlv;

        let sender_packet = PacketUnauthenticated {
            sequence_number: 1,
            timestamp: 100,
            error_estimate: 10,
            mbz: [0; 30],
        };

        let rp_tlv = ReturnPathTlv::with_control_code(0x0);

        let mut original_data = sender_packet.to_bytes().to_vec();
        original_data.extend_from_slice(&rp_tlv.to_raw().to_bytes());

        let ctx = test_ctx(0, 0);

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
            &ctx,
        );

        assert_eq!(response.return_path_action, ReturnPathAction::SuppressReply);
    }

    #[test]
    fn test_unauth_return_path_alternate_addr() {
        use crate::tlv::ReturnPathTlv;

        let sender_packet = PacketUnauthenticated {
            sequence_number: 1,
            timestamp: 100,
            error_estimate: 10,
            mbz: [0; 30],
        };

        let alt_addr: std::net::IpAddr = "10.0.0.5".parse().unwrap();
        let rp_tlv = ReturnPathTlv::with_return_address(alt_addr);

        let mut original_data = sender_packet.to_bytes().to_vec();
        original_data.extend_from_slice(&rp_tlv.to_raw().to_bytes());

        let mut ctx = test_ctx(0, 0);
        ctx.sender_port = 12345;

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
            &ctx,
        );

        assert_eq!(
            response.return_path_action,
            ReturnPathAction::AlternateAddress(std::net::SocketAddr::new(alt_addr, 12345))
        );
    }

    #[test]
    fn test_unauth_return_path_sr_unsupported() {
        use crate::tlv::ReturnPathTlv;

        let sender_packet = PacketUnauthenticated {
            sequence_number: 1,
            timestamp: 100,
            error_estimate: 10,
            mbz: [0; 30],
        };

        let rp_tlv = ReturnPathTlv::with_sr_mpls_labels(&[100, 200]);

        let mut original_data = sender_packet.to_bytes().to_vec();
        original_data.extend_from_slice(&rp_tlv.to_raw().to_bytes());

        let ctx = test_ctx(0, 0);

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
            &ctx,
        );

        assert_eq!(response.return_path_action, ReturnPathAction::UnsupportedSr);
        // Return Path TLV should have U-flag set
        assert_eq!(response.data[UNAUTH_BASE_SIZE] & 0x80, 0x80);
    }

    #[test]
    fn test_set_return_path_u_flag_in_response() {
        use crate::tlv::ReturnPathTlv;

        let sender_packet = PacketUnauthenticated {
            sequence_number: 1,
            timestamp: 100,
            error_estimate: 10,
            mbz: [0; 30],
        };

        let rp_tlv = ReturnPathTlv::with_return_address("10.0.0.5".parse().unwrap());

        let mut data = sender_packet.to_bytes().to_vec();
        data.extend_from_slice(&rp_tlv.to_raw().to_bytes());

        // U-flag should not be set initially
        assert_eq!(data[UNAUTH_BASE_SIZE] & 0x80, 0);

        let updated = set_return_path_u_flag_in_response(&mut data, UNAUTH_BASE_SIZE);
        assert!(updated);
        assert_eq!(data[UNAUTH_BASE_SIZE] & 0x80, 0x80);
    }

    #[test]
    fn test_set_return_path_u_flag_no_return_path_tlv() {
        let sender_packet = PacketUnauthenticated {
            sequence_number: 1,
            timestamp: 100,
            error_estimate: 10,
            mbz: [0; 30],
        };

        let mut data = sender_packet.to_bytes().to_vec();

        let updated = set_return_path_u_flag_in_response(&mut data, UNAUTH_BASE_SIZE);
        assert!(!updated);
    }
}
