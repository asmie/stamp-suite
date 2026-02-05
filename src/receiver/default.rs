//! Default receiver implementation using tokio UDP sockets.
//!
//! Uses a placeholder TTL value (255) since tokio doesn't provide access to IP header fields.
//! For real TTL capture, build with `--features ttl-nix` (Linux) or `--features ttl-pnet`.

use std::net::SocketAddr;

use tokio::net::UdpSocket;

use crate::{
    configuration::{is_auth, Configuration},
    crypto::HmacKey,
    error_estimate::ErrorEstimate,
    packets::{any_as_u8_slice, read_struct, PacketAuthenticated, PacketUnauthenticated},
    time::generate_timestamp,
};

use super::{assemble_auth_answer, assemble_unauth_answer};

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

    // Build error estimate from configuration
    let error_estimate = ErrorEstimate::new(
        conf.clock_synchronized,
        conf.error_scale,
        conf.error_multiplier,
    )
    .unwrap_or_else(|_| ErrorEstimate::unsynchronized());
    let error_estimate_wire = error_estimate.to_wire();

    // Load HMAC key if configured
    let hmac_key = load_hmac_key(conf);
    if hmac_key.is_some() {
        log::info!("HMAC authentication enabled");
    }

    println!(
        "STAMP Reflector listening on {} (default mode, TTL=255 placeholder)",
        local_addr
    );

    let mut buf = [0u8; 1024];
    let use_auth = is_auth(&conf.auth_mode);

    loop {
        match socket.recv_from(&mut buf).await {
            Ok((len, src)) => {
                let rcvt = generate_timestamp(conf.clock_source);
                let ttl = 255u8; // Placeholder TTL

                let response = if use_auth {
                    match read_struct::<PacketAuthenticated>(&buf[..len]) {
                        Ok(packet) => {
                            // Verify HMAC if required
                            if conf.require_hmac {
                                if let Some(ref key) = hmac_key {
                                    if !verify_incoming_hmac(key, &buf[..len], &packet.hmac) {
                                        eprintln!(
                                            "HMAC verification failed for packet from {}",
                                            src
                                        );
                                        continue;
                                    }
                                } else {
                                    eprintln!("HMAC required but no key configured");
                                    continue;
                                }
                            }

                            let answer = assemble_auth_answer(
                                &packet,
                                conf.clock_source,
                                rcvt,
                                ttl,
                                error_estimate_wire,
                                hmac_key.as_ref(),
                            );
                            any_as_u8_slice(&answer).ok()
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
                    match read_struct::<PacketUnauthenticated>(&buf[..len]) {
                        Ok(packet) => {
                            let answer = assemble_unauth_answer(
                                &packet,
                                conf.clock_source,
                                rcvt,
                                ttl,
                                error_estimate_wire,
                            );
                            any_as_u8_slice(&answer).ok()
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
