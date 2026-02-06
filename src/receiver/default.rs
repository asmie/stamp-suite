//! Default receiver implementation using tokio UDP sockets.
//!
//! Uses a placeholder TTL value (255) since tokio doesn't provide access to IP header fields.
//! For real TTL capture, build with `--features ttl-nix` (Linux) or `--features ttl-pnet`.

use std::{
    net::SocketAddr,
    sync::atomic::{AtomicBool, Ordering},
};

use tokio::net::UdpSocket;

/// Flag to ensure TTL warning is only shown once.
static TTL_WARNING_SHOWN: AtomicBool = AtomicBool::new(false);

use crate::{
    configuration::{is_auth, Configuration},
    crypto::HmacKey,
    error_estimate::ErrorEstimate,
    packets::{PacketAuthenticated, PacketUnauthenticated},
    session::Session,
    time::generate_timestamp,
};

use super::{assemble_auth_answer_symmetric, assemble_unauth_answer_symmetric};

/// Runs the STAMP Session Reflector using tokio UDP sockets.
///
/// This is the default implementation that uses a placeholder TTL value (255)
/// since tokio doesn't provide direct access to IP header fields.
/// For real TTL capture, use the `ttl-nix` or `ttl-pnet` features.
pub async fn run_receiver(conf: &Configuration) {
    let local_addr: SocketAddr = (conf.local_addr, conf.local_port).into();

    let socket = match UdpSocket::bind(local_addr).await {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Cannot bind to address {}: {}", local_addr, e);
            return;
        }
    };

    // Check if authenticated mode is used
    let use_auth = is_auth(&conf.auth_mode);

    // Load HMAC key if configured
    let hmac_key = load_hmac_key(conf);

    // Validate: authenticated mode requires HMAC key
    if use_auth && hmac_key.is_none() {
        eprintln!(
            "Error: Authenticated mode (-A A) requires HMAC key (--hmac-key or --hmac-key-file)"
        );
        return;
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

    if hmac_key.is_some() {
        log::info!("HMAC authentication enabled");
    }

    // Create session for stateful reflector mode (RFC 8972)
    let reflector_session = if conf.stateful_reflector {
        log::info!("Stateful reflector mode enabled (RFC 8972)");
        Some(Session::new(0))
    } else {
        None
    };

    // Warn user about TTL placeholder (only once)
    if !TTL_WARNING_SHOWN.swap(true, Ordering::Relaxed) {
        log::warn!(
            "Default mode: TTL reported as 255 (placeholder). \
             For real TTL capture, use --features ttl-nix (Linux) or --features ttl-pnet."
        );
    }

    println!(
        "STAMP Reflector listening on {} (default mode, TTL=255 placeholder)",
        local_addr
    );

    let mut buf = [0u8; 1024];

    loop {
        match socket.recv_from(&mut buf).await {
            Ok((len, src)) => {
                let rcvt = generate_timestamp(conf.clock_source);
                let ttl = 255u8; // Placeholder TTL

                let response = if use_auth {
                    let packet_result = if conf.strict_packets {
                        PacketAuthenticated::from_bytes(&buf[..len])
                    } else {
                        Ok(PacketAuthenticated::from_bytes_lenient(&buf[..len]))
                    };
                    match packet_result {
                        Ok(packet) => {
                            // Copy HMAC to avoid unaligned access
                            let hmac = packet.hmac;

                            // Verify HMAC - mandatory when key is present (RFC 8762 §4.4)
                            if let Some(ref key) = hmac_key {
                                if !verify_incoming_hmac(key, &buf[..len], &hmac) {
                                    eprintln!("HMAC verification failed for packet from {}", src);
                                    continue; // Always reject invalid HMAC in auth mode
                                }
                            } else if conf.require_hmac {
                                // require_hmac means "require key to be configured"
                                eprintln!("HMAC key required but not configured");
                                continue;
                            }

                            // Generate reflector sequence number only after successful validation
                            let reflector_seq = reflector_session
                                .as_ref()
                                .map(|s| s.generate_sequence_number());

                            // Use symmetric assembly to preserve original packet length (RFC 8762 Section 4.3)
                            Some(assemble_auth_answer_symmetric(
                                &packet,
                                &buf[..len],
                                conf.clock_source,
                                rcvt,
                                ttl,
                                error_estimate_wire,
                                hmac_key.as_ref(),
                                reflector_seq,
                            ))
                        }
                        Err(e) => {
                            eprintln!(
                                "Failed to deserialize authenticated packet from {}: {}",
                                src, e
                            );
                            continue;
                        }
                    }
                } else {
                    let packet_result = if conf.strict_packets {
                        PacketUnauthenticated::from_bytes(&buf[..len])
                    } else {
                        Ok(PacketUnauthenticated::from_bytes_lenient(&buf[..len]))
                    };
                    match packet_result {
                        Ok(packet) => {
                            // Generate reflector sequence number only after successful validation
                            let reflector_seq = reflector_session
                                .as_ref()
                                .map(|s| s.generate_sequence_number());

                            // Use symmetric assembly to preserve original packet length (RFC 8762 Section 4.3)
                            Some(assemble_unauth_answer_symmetric(
                                &packet,
                                &buf[..len],
                                conf.clock_source,
                                rcvt,
                                ttl,
                                error_estimate_wire,
                                reflector_seq,
                            ))
                        }
                        Err(e) => {
                            eprintln!(
                                "Failed to deserialize unauthenticated packet from {}: {}",
                                src, e
                            );
                            continue;
                        }
                    }
                };

                if let Some(response_buf) = response {
                    if let Err(e) = socket.send_to(&response_buf, src).await {
                        eprintln!("Failed to send response to {}: {}", src, e);
                    }
                }
            }
            Err(e) => {
                eprintln!("Receive error: {}", e);
            }
        }
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

/// Verifies the HMAC of an incoming authenticated packet.
fn verify_incoming_hmac(key: &HmacKey, packet_bytes: &[u8], expected_hmac: &[u8; 16]) -> bool {
    use crate::crypto::verify_packet_hmac;
    use crate::sender::AUTH_PACKET_HMAC_OFFSET;

    verify_packet_hmac(key, packet_bytes, AUTH_PACKET_HMAC_OFFSET, expected_hmac)
}
