use std::{
    collections::HashMap,
    net::SocketAddr,
    time::{Duration, Instant},
};

use tokio::net::UdpSocket;

use crate::{
    clock_format::ClockFormat,
    configuration::{is_auth, Configuration},
    crypto::{compute_packet_hmac, verify_packet_hmac, HmacKey},
    error_estimate::ErrorEstimate,
    packets::{
        ExtendedPacketAuthenticated, ExtendedPacketUnauthenticated,
        ExtendedReflectedPacketAuthenticated, ExtendedReflectedPacketUnauthenticated,
        PacketAuthenticated, PacketUnauthenticated, ReflectedPacketAuthenticated,
        ReflectedPacketUnauthenticated,
    },
    receiver::{AUTH_BASE_SIZE, REFLECTED_AUTH_PACKET_HMAC_OFFSET, UNAUTH_BASE_SIZE},
    session::Session,
    time::generate_timestamp,
    tlv::{RawTlv, SessionSenderId, TlvList},
};

/// Statistics collected during a STAMP sender session.
///
/// Contains counters for sent/received/lost packets and RTT measurements.
#[derive(Debug, Default)]
pub struct SessionStats {
    /// Total number of packets sent during the session.
    pub packets_sent: u32,
    /// Total number of response packets received.
    pub packets_received: u32,
    /// Number of packets that were not acknowledged (lost or timed out).
    pub packets_lost: u32,
    /// Minimum round-trip time observed in nanoseconds.
    pub min_rtt_ns: Option<u64>,
    /// Maximum round-trip time observed in nanoseconds.
    pub max_rtt_ns: Option<u64>,
    /// Average round-trip time in nanoseconds.
    pub avg_rtt_ns: Option<u64>,
}

/// Internal structure to track packets awaiting responses.
struct PendingPacket {
    /// Wall-clock time when the packet was sent.
    send_time: Instant,
    /// STAMP timestamp embedded in the sent packet.
    #[allow(dead_code)]
    send_timestamp: u64,
}

/// Runs the STAMP sender, transmitting test packets and collecting statistics.
///
/// Sends packets to the configured remote address and waits for reflected responses.
/// Returns statistics about the measurement session including RTT and packet loss.
pub async fn run_sender(conf: &Configuration) -> SessionStats {
    let local_addr: SocketAddr = (conf.local_addr, conf.local_port).into();
    let remote_addr: SocketAddr = (conf.remote_addr, conf.remote_port).into();

    let socket = match UdpSocket::bind(local_addr).await {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Cannot bind to address {}: {}", local_addr, e);
            return SessionStats::default();
        }
    };

    if let Err(e) = socket.connect(remote_addr).await {
        eprintln!("Cannot connect to address {}: {}", remote_addr, e);
        return SessionStats::default();
    }

    // Build error estimate from configuration with Z flag set based on clock source
    let error_estimate = ErrorEstimate::with_clock_format(
        conf.clock_synchronized,
        conf.clock_source,
        conf.error_scale,
        conf.error_multiplier,
    )
    .unwrap_or_else(|_| ErrorEstimate::unsynchronized_with_format(conf.clock_source));
    let error_estimate_wire = error_estimate.to_wire();

    // Check if authenticated mode is used
    let use_auth = is_auth(&conf.auth_mode);

    // Load HMAC key if configured
    let hmac_key = load_hmac_key(conf);

    // Validate: authenticated mode requires HMAC key
    if use_auth && hmac_key.is_none() {
        eprintln!(
            "Error: Authenticated mode (-A A) requires HMAC key (--hmac-key or --hmac-key-file)"
        );
        return SessionStats::default();
    }

    if hmac_key.is_some() {
        log::info!("HMAC authentication enabled");
    }

    let sess = Session::new(0);
    let mut pending: HashMap<u32, PendingPacket> = HashMap::new();
    let mut stats = SessionStats::default();
    let mut rtt_sum: u64 = 0;
    let mut recv_buf = [0u8; 1024];
    let timeout = Duration::from_secs(conf.timeout as u64);

    // Check if we need to include TLV extensions (SSID)
    let use_tlvs = conf.ssid.is_some();
    if use_tlvs {
        log::info!("TLV extensions enabled with SSID: {}", conf.ssid.unwrap());
    }

    for _ in 0..conf.count {
        let seq_num = sess.generate_sequence_number();
        let send_time = Instant::now();
        let send_timestamp = generate_timestamp(conf.clock_source);

        let send_result = if use_auth {
            if use_tlvs {
                // Use TLV-aware packet builder with SSID
                // TLV HMAC uses same key as base packet HMAC
                let buf = build_auth_packet_with_tlvs(
                    seq_num,
                    send_timestamp,
                    error_estimate_wire,
                    hmac_key.as_ref().expect("auth mode requires key"),
                    conf.ssid,
                    vec![],
                    hmac_key.as_ref(), // TLV HMAC key
                );
                socket.send(&buf).await
            } else {
                // Base packet without TLVs
                let mut packet = assemble_auth_packet(error_estimate_wire);
                packet.sequence_number = seq_num;
                packet.timestamp = send_timestamp;

                // Compute and set HMAC (key is guaranteed to be present in auth mode)
                if let Some(ref key) = hmac_key {
                    finalize_auth_packet(&mut packet, key);
                }

                let buf = packet.to_bytes();
                socket.send(&buf).await
            }
        } else if use_tlvs {
            // Use TLV-aware packet builder with SSID
            let buf = build_unauth_packet_with_tlvs(
                seq_num,
                send_timestamp,
                error_estimate_wire,
                conf.ssid,
                vec![],
                hmac_key.as_ref(), // TLV HMAC key (optional in unauth mode)
            );
            socket.send(&buf).await
        } else {
            // Base packet without TLVs
            let mut packet = assemble_unauth_packet(error_estimate_wire);
            packet.sequence_number = seq_num;
            packet.timestamp = send_timestamp;
            let buf = packet.to_bytes();
            socket.send(&buf).await
        };

        if let Err(e) = send_result {
            eprintln!("Failed to send packet {}: {}", seq_num, e);
            continue;
        }

        stats.packets_sent += 1;
        pending.insert(
            seq_num,
            PendingPacket {
                send_time,
                send_timestamp,
            },
        );

        // Non-blocking receive attempts
        loop {
            match tokio::time::timeout(Duration::from_millis(1), socket.recv(&mut recv_buf)).await {
                Ok(Ok(len)) => {
                    process_response(
                        &recv_buf[..len],
                        use_auth,
                        use_tlvs,
                        conf.clock_source,
                        &mut pending,
                        &mut stats,
                        &mut rtt_sum,
                        conf.print_stats,
                        hmac_key.as_ref(),
                    );
                }
                Ok(Err(e)) => {
                    eprintln!("Receive error: {}", e);
                    break;
                }
                Err(_) => break, // Timeout - no more packets available
            }
        }

        // Wait for send delay
        tokio::time::sleep(Duration::from_millis(conf.send_delay as u64)).await;
    }

    // Final wait phase for remaining responses
    let wait_start = Instant::now();
    while !pending.is_empty() && wait_start.elapsed() < timeout {
        let remaining = timeout.saturating_sub(wait_start.elapsed());
        match tokio::time::timeout(remaining, socket.recv(&mut recv_buf)).await {
            Ok(Ok(len)) => {
                process_response(
                    &recv_buf[..len],
                    use_auth,
                    use_tlvs,
                    conf.clock_source,
                    &mut pending,
                    &mut stats,
                    &mut rtt_sum,
                    conf.print_stats,
                    hmac_key.as_ref(),
                );
            }
            Ok(Err(e)) => {
                eprintln!("Receive error during final wait: {}", e);
                break;
            }
            Err(_) => break, // Timeout expired
        }
    }

    // Mark remaining pending packets as lost
    stats.packets_lost = pending.len() as u32;

    // Calculate average RTT
    if stats.packets_received > 0 {
        stats.avg_rtt_ns = Some(rtt_sum / stats.packets_received as u64);
    }

    stats
}

#[allow(clippy::too_many_arguments)]
fn process_response(
    data: &[u8],
    use_auth: bool,
    use_tlvs: bool,
    clock_source: ClockFormat,
    pending: &mut HashMap<u32, PendingPacket>,
    stats: &mut SessionStats,
    rtt_sum: &mut u64,
    print_stats: bool,
    hmac_key: Option<&HmacKey>,
) {
    let recv_time = Instant::now();

    // Parse response and validate TLVs if extension mode is enabled
    // Use lenient parsing per RFC 8762 §4.6 to handle short packets
    let (seq_num, reflector_recv_ts, reflector_send_ts, sender_ttl, tlv_info) = if use_auth {
        if use_tlvs {
            // Parse as extended packet with TLVs (lenient, returns canonical buffer)
            let (ext_packet, canonical_buf) =
                ExtendedReflectedPacketAuthenticated::from_bytes_lenient(data);
            let base = &ext_packet.base;
            let seq_num = base.sess_sender_seq_number;
            let recv_ts = base.receive_timestamp;
            let send_ts = base.timestamp;
            let ttl = base.sess_sender_ttl;
            let hmac = base.hmac;

            // Verify base packet HMAC against canonical buffer (RFC 8762 §4.4, §4.6)
            if let Some(key) = hmac_key {
                if !verify_packet_hmac(
                    key,
                    &canonical_buf,
                    REFLECTED_AUTH_PACKET_HMAC_OFFSET,
                    &hmac,
                ) {
                    eprintln!(
                        "HMAC verification failed for reflected packet seq={}",
                        seq_num
                    );
                    return;
                }
            }

            // Validate TLVs if present
            let tlv_info = if ext_packet.has_tlvs() {
                validate_reflected_tlvs(&ext_packet.tlvs, data, AUTH_BASE_SIZE, hmac_key)
            } else {
                None
            };

            (seq_num, recv_ts, send_ts, ttl, tlv_info)
        } else {
            // Parse base packet only (lenient, returns canonical buffer)
            let (packet, canonical_buf) = ReflectedPacketAuthenticated::from_bytes_lenient(data);
            let seq_num = packet.sess_sender_seq_number;
            let recv_ts = packet.receive_timestamp;
            let send_ts = packet.timestamp;
            let ttl = packet.sess_sender_ttl;
            let hmac = packet.hmac;

            // Verify HMAC against canonical buffer when key is present (RFC 8762 §4.4, §4.6)
            if let Some(key) = hmac_key {
                if !verify_packet_hmac(
                    key,
                    &canonical_buf,
                    REFLECTED_AUTH_PACKET_HMAC_OFFSET,
                    &hmac,
                ) {
                    eprintln!(
                        "HMAC verification failed for reflected packet seq={}",
                        seq_num
                    );
                    return;
                }
            }
            (seq_num, recv_ts, send_ts, ttl, None)
        }
    } else if use_tlvs {
        // Parse as extended packet with TLVs (unauthenticated, lenient)
        let ext_packet = ExtendedReflectedPacketUnauthenticated::from_bytes_lenient(data);
        let base = &ext_packet.base;

        // Validate TLVs if present
        let tlv_info = if ext_packet.has_tlvs() {
            validate_reflected_tlvs(&ext_packet.tlvs, data, UNAUTH_BASE_SIZE, hmac_key)
        } else {
            None
        };

        (
            base.sess_sender_seq_number,
            base.receive_timestamp,
            base.timestamp,
            base.sess_sender_ttl,
            tlv_info,
        )
    } else {
        // Parse base packet only (lenient)
        let packet = ReflectedPacketUnauthenticated::from_bytes_lenient(data);
        (
            packet.sess_sender_seq_number,
            packet.receive_timestamp,
            packet.timestamp,
            packet.sess_sender_ttl,
            None,
        )
    };

    if let Some(pending_packet) = pending.remove(&seq_num) {
        let rtt_ns = recv_time
            .duration_since(pending_packet.send_time)
            .as_nanos() as u64;

        stats.packets_received += 1;
        *rtt_sum += rtt_ns;

        stats.min_rtt_ns = Some(stats.min_rtt_ns.map_or(rtt_ns, |min| min.min(rtt_ns)));
        stats.max_rtt_ns = Some(stats.max_rtt_ns.map_or(rtt_ns, |max| max.max(rtt_ns)));

        if print_stats {
            let _now_ts = generate_timestamp(clock_source);
            let tlv_status = tlv_info
                .as_ref()
                .map_or(String::new(), |info| format!(" tlv=[{}]", info));
            println!(
                "seq={} rtt={:.3}ms ttl={} reflector_recv_ts={} reflector_send_ts={}{}",
                seq_num,
                rtt_ns as f64 / 1_000_000.0,
                sender_ttl,
                reflector_recv_ts,
                reflector_send_ts,
                tlv_status
            );
        }
    } else {
        eprintln!("Received response for unknown sequence number: {}", seq_num);
    }
}

/// Validates TLVs in a reflected packet and returns a status string.
///
/// Checks for:
/// - Unrecognized TLV types (U-flag)
/// - Malformed TLVs (M-flag)
/// - Integrity failures (I-flag)
/// - TLV HMAC verification (if key is provided)
///
/// The `base_size` parameter specifies the fixed base packet size (44 for unauthenticated,
/// 112 for authenticated) to correctly locate TLV bytes in the packet data.
fn validate_reflected_tlvs(
    tlvs: &TlvList,
    data: &[u8],
    base_size: usize,
    hmac_key: Option<&HmacKey>,
) -> Option<String> {
    let mut status_parts = Vec::new();
    let tlv_count = tlvs.len();

    // Check for flagged TLVs
    let mut unrecognized_count = 0;
    let mut malformed_count = 0;
    let mut integrity_failed_count = 0;

    for tlv in tlvs.non_hmac_tlvs() {
        if tlv.is_unrecognized() {
            unrecognized_count += 1;
        }
        if tlv.is_malformed() {
            malformed_count += 1;
        }
        if tlv.is_integrity_failed() {
            integrity_failed_count += 1;
        }
    }

    // Check HMAC TLV flags too
    if let Some(hmac_tlv) = tlvs.hmac_tlv() {
        if hmac_tlv.is_integrity_failed() {
            integrity_failed_count += 1;
        }
        if hmac_tlv.is_malformed() {
            malformed_count += 1;
        }
    }

    // Report flagged TLVs
    if unrecognized_count > 0 {
        status_parts.push(format!("{}U", unrecognized_count));
    }
    if malformed_count > 0 {
        status_parts.push(format!("{}M", malformed_count));
    }
    if integrity_failed_count > 0 {
        status_parts.push(format!("{}I", integrity_failed_count));
    }

    // Verify TLV HMAC if key is available
    if let Some(key) = hmac_key {
        if tlvs.hmac_tlv().is_some() {
            // Use the fixed base_size to locate TLV bytes correctly
            // (avoids fragility with trailing padding or non-TLV bytes)
            if base_size >= 4 && data.len() > base_size {
                let seq_bytes = &data[..4];
                let tlv_bytes = &data[base_size..];

                if tlvs.verify_hmac(key, seq_bytes, tlv_bytes).is_ok() {
                    status_parts.push("HMAC:ok".to_string());
                } else {
                    status_parts.push("HMAC:fail".to_string());
                }
            }
        } else {
            // No HMAC TLV in response (reflector may not support it)
            status_parts.push("no-hmac".to_string());
        }
    }

    if status_parts.is_empty() {
        Some(format!("{} TLVs", tlv_count))
    } else {
        Some(format!("{} TLVs, {}", tlv_count, status_parts.join(", ")))
    }
}

/// Loads the HMAC key from configuration (hex string or file).
fn load_hmac_key(conf: &Configuration) -> Option<HmacKey> {
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

/// Creates a new unauthenticated STAMP test packet with the specified error estimate.
///
/// The caller should set the sequence number and timestamp before sending.
///
/// # Arguments
/// * `error_estimate` - The 16-bit error estimate value in wire format
pub fn assemble_unauth_packet(error_estimate: u16) -> PacketUnauthenticated {
    PacketUnauthenticated {
        timestamp: 0,
        mbz: [0u8; 30],
        error_estimate,
        sequence_number: 0,
    }
}

/// Creates a new authenticated STAMP test packet with the specified error estimate.
///
/// The caller should set the sequence number and timestamp before sending.
/// Use `finalize_auth_packet` to compute and set the HMAC after all fields are set.
///
/// # Arguments
/// * `error_estimate` - The 16-bit error estimate value in wire format
pub fn assemble_auth_packet(error_estimate: u16) -> PacketAuthenticated {
    PacketAuthenticated {
        timestamp: 0,
        mbz0: [0u8; 12],
        error_estimate,
        sequence_number: 0,
        hmac: [0u8; 16],
        mbz1a: [0u8; 32],
        mbz1b: [0u8; 32],
        mbz1c: [0u8; 6],
    }
}

/// HMAC field offset in PacketAuthenticated (bytes before HMAC field).
pub const AUTH_PACKET_HMAC_OFFSET: usize = 96;

/// Computes and sets the HMAC for an authenticated packet.
///
/// This should be called after all other fields in the packet have been set.
///
/// # Arguments
/// * `packet` - The packet to finalize
/// * `key` - The HMAC key to use
pub fn finalize_auth_packet(packet: &mut PacketAuthenticated, key: &HmacKey) {
    let bytes = packet.to_bytes();
    packet.hmac = compute_packet_hmac(key, &bytes, AUTH_PACKET_HMAC_OFFSET);
}

/// Builds an unauthenticated STAMP packet with TLV extensions.
///
/// # Arguments
/// * `sequence_number` - Packet sequence number
/// * `timestamp` - Send timestamp
/// * `error_estimate` - Error estimate in wire format
/// * `ssid` - Optional Session-Sender Identifier
/// * `extra_tlvs` - Additional TLVs to include
/// * `tlv_hmac_key` - Optional HMAC key for TLV integrity
pub fn build_unauth_packet_with_tlvs(
    sequence_number: u32,
    timestamp: u64,
    error_estimate: u16,
    ssid: Option<u16>,
    extra_tlvs: Vec<RawTlv>,
    tlv_hmac_key: Option<&HmacKey>,
) -> Vec<u8> {
    let base = PacketUnauthenticated {
        sequence_number,
        timestamp,
        error_estimate,
        mbz: [0u8; 30],
    };
    let base_bytes = base.to_bytes();

    let mut tlvs = TlvList::new();

    // Add SSID as Extra Padding TLV if provided
    if let Some(id) = ssid {
        let ssid_tlv = SessionSenderId::new(id).to_extra_padding_tlv(0);
        tlvs.push(ssid_tlv.to_raw()).ok();
    }

    // Add any extra TLVs
    for tlv in extra_tlvs {
        tlvs.push(tlv).ok();
    }

    // Add TLV HMAC if key is provided
    // Per RFC 8972 §4.8: HMAC covers Sequence Number (first 4 bytes) + preceding TLVs
    if let Some(key) = tlv_hmac_key {
        let seq_bytes = &base_bytes[..4];
        tlvs.set_hmac(key, seq_bytes);
    }

    let mut result = base_bytes.to_vec();
    if !tlvs.is_empty() {
        result.extend_from_slice(&tlvs.to_bytes());
    }

    result
}

/// Builds an authenticated STAMP packet with TLV extensions.
///
/// # Arguments
/// * `sequence_number` - Packet sequence number
/// * `timestamp` - Send timestamp
/// * `error_estimate` - Error estimate in wire format
/// * `base_hmac_key` - HMAC key for base packet authentication
/// * `ssid` - Optional Session-Sender Identifier
/// * `extra_tlvs` - Additional TLVs to include
/// * `tlv_hmac_key` - Optional HMAC key for TLV integrity (can be same as base)
pub fn build_auth_packet_with_tlvs(
    sequence_number: u32,
    timestamp: u64,
    error_estimate: u16,
    base_hmac_key: &HmacKey,
    ssid: Option<u16>,
    extra_tlvs: Vec<RawTlv>,
    tlv_hmac_key: Option<&HmacKey>,
) -> Vec<u8> {
    let mut base = PacketAuthenticated {
        sequence_number,
        timestamp,
        error_estimate,
        mbz0: [0u8; 12],
        mbz1a: [0u8; 32],
        mbz1b: [0u8; 32],
        mbz1c: [0u8; 6],
        hmac: [0u8; 16],
    };

    // Compute base packet HMAC
    finalize_auth_packet(&mut base, base_hmac_key);
    let base_bytes = base.to_bytes();

    let mut tlvs = TlvList::new();

    // Add SSID as Extra Padding TLV if provided
    if let Some(id) = ssid {
        let ssid_tlv = SessionSenderId::new(id).to_extra_padding_tlv(0);
        tlvs.push(ssid_tlv.to_raw()).ok();
    }

    // Add any extra TLVs
    for tlv in extra_tlvs {
        tlvs.push(tlv).ok();
    }

    // Add TLV HMAC if key is provided
    // Per RFC 8972 §4.8: HMAC covers Sequence Number (first 4 bytes) + preceding TLVs
    if let Some(key) = tlv_hmac_key {
        let seq_bytes = &base_bytes[..4];
        tlvs.set_hmac(key, seq_bytes);
    }

    let mut result = base_bytes.to_vec();
    if !tlvs.is_empty() {
        result.extend_from_slice(&tlvs.to_bytes());
    }

    result
}

/// Creates an Extended unauthenticated packet from configuration.
///
/// This is a convenience wrapper for building packets with TLV support.
pub fn create_extended_unauth_packet(
    sequence_number: u32,
    timestamp: u64,
    error_estimate: u16,
    ssid: Option<u16>,
) -> ExtendedPacketUnauthenticated {
    let base = PacketUnauthenticated {
        sequence_number,
        timestamp,
        error_estimate,
        mbz: [0u8; 30],
    };

    let mut tlvs = TlvList::new();
    if let Some(id) = ssid {
        let ssid_tlv = SessionSenderId::new(id).to_extra_padding_tlv(0);
        tlvs.push(ssid_tlv.to_raw()).ok();
    }

    ExtendedPacketUnauthenticated::with_tlvs(base, tlvs)
}

/// Creates an Extended authenticated packet from configuration.
///
/// This is a convenience wrapper for building packets with TLV support.
pub fn create_extended_auth_packet(
    sequence_number: u32,
    timestamp: u64,
    error_estimate: u16,
    hmac_key: &HmacKey,
    ssid: Option<u16>,
) -> ExtendedPacketAuthenticated {
    let mut base = PacketAuthenticated {
        sequence_number,
        timestamp,
        error_estimate,
        mbz0: [0u8; 12],
        mbz1a: [0u8; 32],
        mbz1b: [0u8; 32],
        mbz1c: [0u8; 6],
        hmac: [0u8; 16],
    };

    finalize_auth_packet(&mut base, hmac_key);

    let mut tlvs = TlvList::new();
    if let Some(id) = ssid {
        let ssid_tlv = SessionSenderId::new(id).to_extra_padding_tlv(0);
        tlvs.push(ssid_tlv.to_raw()).ok();
    }

    ExtendedPacketAuthenticated::with_tlvs(base, tlvs)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_assemble_unauth_packet_defaults() {
        let packet = assemble_unauth_packet(0);
        assert_eq!(packet.sequence_number, 0);
        assert_eq!(packet.timestamp, 0);
        assert_eq!(packet.error_estimate, 0);
        assert_eq!(packet.mbz, [0u8; 30]);
    }

    #[test]
    fn test_assemble_unauth_packet_with_error_estimate() {
        let error_estimate = 0x8A64; // S=1, Scale=10, Multiplier=100
        let packet = assemble_unauth_packet(error_estimate);
        assert_eq!(packet.error_estimate, error_estimate);
    }

    #[test]
    fn test_assemble_auth_packet_defaults() {
        let packet = assemble_auth_packet(0);
        assert_eq!(packet.sequence_number, 0);
        assert_eq!(packet.timestamp, 0);
        assert_eq!(packet.error_estimate, 0);
        assert_eq!(packet.mbz0, [0u8; 12]);
        assert_eq!(packet.mbz1a, [0u8; 32]);
        assert_eq!(packet.mbz1b, [0u8; 32]);
        assert_eq!(packet.mbz1c, [0u8; 6]);
        assert_eq!(packet.hmac, [0u8; 16]);
    }

    #[test]
    fn test_assemble_auth_packet_with_error_estimate() {
        let error_estimate = 0x8A64;
        let packet = assemble_auth_packet(error_estimate);
        assert_eq!(packet.error_estimate, error_estimate);
    }

    #[test]
    fn test_finalize_auth_packet_sets_hmac() {
        use crate::crypto::HmacKey;

        let mut packet = assemble_auth_packet(0);
        packet.sequence_number = 42;
        packet.timestamp = 123456789;

        let key = HmacKey::new(vec![0xab; 32]).unwrap();
        finalize_auth_packet(&mut packet, &key);

        // HMAC should no longer be all zeros
        assert_ne!(packet.hmac, [0u8; 16]);
    }

    #[test]
    fn test_finalize_auth_packet_deterministic() {
        use crate::crypto::HmacKey;

        let key = HmacKey::new(vec![0xab; 32]).unwrap();

        let mut packet1 = assemble_auth_packet(100);
        packet1.sequence_number = 1;
        packet1.timestamp = 999;
        finalize_auth_packet(&mut packet1, &key);

        let mut packet2 = assemble_auth_packet(100);
        packet2.sequence_number = 1;
        packet2.timestamp = 999;
        finalize_auth_packet(&mut packet2, &key);

        assert_eq!(packet1.hmac, packet2.hmac);
    }

    // TLV building tests

    #[test]
    fn test_build_unauth_packet_with_tlvs_no_tlvs() {
        let packet = build_unauth_packet_with_tlvs(1, 1000, 100, None, vec![], None);

        // Should be just base packet (44 bytes)
        assert_eq!(packet.len(), 44);
    }

    #[test]
    fn test_build_unauth_packet_with_ssid() {
        use crate::tlv::TLV_HEADER_SIZE;

        let ssid: u16 = 12345;
        let packet = build_unauth_packet_with_tlvs(1, 1000, 100, Some(ssid), vec![], None);

        // Base (44) + ExtraPadding TLV (4 header + 2 SSID value)
        assert_eq!(packet.len(), 44 + TLV_HEADER_SIZE + 2);

        // Check TLV structure at offset 44:
        // Byte 0: Flags (should be 0)
        assert_eq!(packet[44], 0x00);
        // Byte 1: Type (ExtraPadding = 1)
        assert_eq!(packet[45], 1);
        // Bytes 2-3: Length (2 bytes for SSID)
        assert_eq!(u16::from_be_bytes([packet[46], packet[47]]), 2);
        // Bytes 4-5: SSID value in big-endian
        assert_eq!(u16::from_be_bytes([packet[48], packet[49]]), ssid);
    }

    #[test]
    fn test_build_unauth_packet_with_extra_tlvs() {
        use crate::tlv::{TlvType, TLV_HEADER_SIZE};

        let extra_tlv = RawTlv::new(TlvType::Location, vec![1, 2, 3, 4]);
        let packet = build_unauth_packet_with_tlvs(1, 1000, 100, None, vec![extra_tlv], None);

        // Base (44) + Location TLV (4 header + 4 value)
        assert_eq!(packet.len(), 44 + TLV_HEADER_SIZE + 4);

        // Check TLV type (byte 1 per RFC 8972)
        assert_eq!(packet[45], 2); // Location type
    }

    #[test]
    fn test_build_unauth_packet_with_tlv_hmac() {
        use crate::tlv::{HMAC_TLV_VALUE_SIZE, TLV_HEADER_SIZE};

        let key = HmacKey::new(vec![0xAB; 32]).unwrap();
        let packet = build_unauth_packet_with_tlvs(1, 1000, 100, Some(100), vec![], Some(&key));

        // Base (44) + SSID TLV (4+2) + HMAC TLV (4+16)
        assert_eq!(
            packet.len(),
            44 + TLV_HEADER_SIZE + 2 + TLV_HEADER_SIZE + HMAC_TLV_VALUE_SIZE
        );

        // HMAC TLV should be last (type in byte 1 per RFC 8972)
        let hmac_start = 44 + TLV_HEADER_SIZE + 2;
        assert_eq!(packet[hmac_start + 1], 8); // HMAC type
    }

    #[test]
    fn test_build_auth_packet_with_tlvs_no_tlvs() {
        let key = HmacKey::new(vec![0xAB; 32]).unwrap();
        let packet = build_auth_packet_with_tlvs(1, 1000, 100, &key, None, vec![], None);

        // Should be just base packet (112 bytes)
        assert_eq!(packet.len(), 112);

        // Base HMAC should be set
        assert_ne!(&packet[96..112], &[0u8; 16]);
    }

    #[test]
    fn test_build_auth_packet_with_ssid() {
        use crate::tlv::TLV_HEADER_SIZE;

        let key = HmacKey::new(vec![0xAB; 32]).unwrap();
        let packet = build_auth_packet_with_tlvs(1, 1000, 100, &key, Some(54321), vec![], None);

        // Base (112) + ExtraPadding TLV (4 header + 2 SSID value)
        assert_eq!(packet.len(), 112 + TLV_HEADER_SIZE + 2);

        // Check TLV type (byte 1 per RFC 8972)
        assert_eq!(packet[113], 1); // ExtraPadding type
    }

    #[test]
    fn test_build_auth_packet_with_tlv_hmac() {
        use crate::tlv::{HMAC_TLV_VALUE_SIZE, TLV_HEADER_SIZE};

        let key = HmacKey::new(vec![0xAB; 32]).unwrap();
        let packet = build_auth_packet_with_tlvs(1, 1000, 100, &key, Some(100), vec![], Some(&key));

        // Base (112) + SSID TLV (4+2) + HMAC TLV (4+16)
        assert_eq!(
            packet.len(),
            112 + TLV_HEADER_SIZE + 2 + TLV_HEADER_SIZE + HMAC_TLV_VALUE_SIZE
        );
    }

    #[test]
    fn test_create_extended_unauth_packet() {
        let ext = create_extended_unauth_packet(1, 1000, 100, None);

        assert_eq!(ext.base.sequence_number, 1);
        assert!(!ext.has_tlvs());
    }

    #[test]
    fn test_create_extended_unauth_packet_with_ssid() {
        let ext = create_extended_unauth_packet(1, 1000, 100, Some(9999));

        assert_eq!(ext.base.sequence_number, 1);
        assert!(ext.has_tlvs());
        assert_eq!(ext.tlvs.len(), 1);
    }

    #[test]
    fn test_create_extended_auth_packet() {
        let key = HmacKey::new(vec![0xCD; 32]).unwrap();
        let ext = create_extended_auth_packet(1, 1000, 100, &key, None);

        assert_eq!(ext.base.sequence_number, 1);
        assert!(!ext.has_tlvs());
        // Base HMAC should be computed
        assert_ne!(ext.base.hmac, [0u8; 16]);
    }

    #[test]
    fn test_create_extended_auth_packet_with_ssid() {
        let key = HmacKey::new(vec![0xCD; 32]).unwrap();
        let ext = create_extended_auth_packet(1, 1000, 100, &key, Some(8888));

        assert!(ext.has_tlvs());
        assert_eq!(ext.tlvs.len(), 1);
    }
}
