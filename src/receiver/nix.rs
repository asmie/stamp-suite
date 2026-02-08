//! Receiver implementation using nix crate for real TTL capture via IP_RECVTTL.
//!
//! Preferred on Linux systems. No special privileges required for regular UDP sockets.

use std::{io::IoSliceMut, net::SocketAddr, os::fd::AsRawFd, sync::Arc};

use nix::{
    libc,
    sys::socket::{recvmsg, ControlMessageOwned, MsgFlags, SockaddrStorage},
};
use tokio::net::UdpSocket;

use crate::{
    configuration::{is_auth, Configuration, TlvHandlingMode},
    crypto::HmacKey,
    error_estimate::ErrorEstimate,
    packets::{PacketAuthenticated, PacketUnauthenticated},
    session::SessionManager,
    time::generate_timestamp,
};

use super::{
    assemble_auth_answer_symmetric, assemble_auth_answer_with_tlvs,
    assemble_unauth_answer_symmetric, assemble_unauth_answer_with_tlvs, AUTH_BASE_SIZE,
    UNAUTH_BASE_SIZE,
};

/// Runs the STAMP Session Reflector using nix for real TTL capture.
///
/// Uses IP_RECVTTL/IPV6_RECVHOPLIMIT socket options to capture the actual
/// TTL/Hop Limit from incoming packets. Preferred on Linux systems.
pub async fn run_receiver(conf: &Configuration) {
    let local_addr: SocketAddr = (conf.local_addr, conf.local_port).into();
    let is_ipv6 = conf.local_addr.is_ipv6();

    // Create a standard UDP socket
    let std_socket = match std::net::UdpSocket::bind(local_addr) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Cannot bind to address {}: {}", local_addr, e);
            return;
        }
    };

    // Enable TTL/hop limit reception via setsockopt using libc directly
    // nix doesn't expose IP_RECVTTL, so we use libc
    let fd = std_socket.as_raw_fd();
    let enable: libc::c_int = 1;

    let result = if is_ipv6 {
        unsafe {
            libc::setsockopt(
                fd,
                libc::IPPROTO_IPV6,
                libc::IPV6_RECVHOPLIMIT,
                &enable as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            )
        }
    } else {
        unsafe {
            libc::setsockopt(
                fd,
                libc::IPPROTO_IP,
                libc::IP_RECVTTL,
                &enable as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            )
        }
    };

    if result < 0 {
        eprintln!(
            "Failed to set IP_RECVTTL/IPV6_RECVHOPLIMIT: {}",
            std::io::Error::last_os_error()
        );
        return;
    }

    // Set non-blocking for tokio
    std_socket
        .set_nonblocking(true)
        .expect("Failed to set non-blocking");

    // Wrap in tokio for async readiness notifications
    let tokio_socket = UdpSocket::from_std(std_socket).expect("Failed to create tokio socket");

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

    if conf.tlv_mode != TlvHandlingMode::Ignore {
        log::info!("TLV handling mode: {:?}", conf.tlv_mode);
    }

    // Create session manager for stateful reflector mode (RFC 8972)
    let session_manager: Option<Arc<SessionManager>> = if conf.stateful_reflector {
        let timeout = if conf.session_timeout > 0 {
            Some(std::time::Duration::from_secs(conf.session_timeout))
        } else {
            None
        };
        log::info!("Stateful reflector mode enabled (RFC 8972)");
        Some(Arc::new(SessionManager::new(timeout)))
    } else {
        None
    };

    println!(
        "STAMP Reflector listening on {} (nix mode, real TTL)",
        local_addr
    );

    let mut buf = [0u8; 1024];
    let mut cmsg_buf = vec![0u8; 256];

    loop {
        // Wait for socket to be readable
        if let Err(e) = tokio_socket.readable().await {
            eprintln!("Failed to wait for readable: {}", e);
            continue;
        }

        // Use nix recvmsg to get TTL from control messages
        let mut iov = [IoSliceMut::new(&mut buf)];

        match recvmsg::<SockaddrStorage>(
            tokio_socket.as_raw_fd(),
            &mut iov,
            Some(&mut cmsg_buf),
            MsgFlags::MSG_DONTWAIT,
        ) {
            Ok(msg) => {
                let len = msg.bytes;
                let src_storage = msg.address;

                // Extract TTL from control messages
                let ttl = match extract_ttl_from_cmsgs(&msg) {
                    Some(t) => t,
                    None => {
                        log::warn!("Failed to extract TTL from packet, skipping");
                        continue;
                    }
                };

                // Convert source address for session lookup and response
                let src_addr: SocketAddr = match src_storage {
                    Some(ref src) => {
                        if let Some(v4) = src.as_sockaddr_in() {
                            std::net::SocketAddrV4::new(v4.ip(), v4.port()).into()
                        } else if let Some(v6) = src.as_sockaddr_in6() {
                            std::net::SocketAddrV6::new(v6.ip(), v6.port(), 0, 0).into()
                        } else {
                            eprintln!("Unknown source address type");
                            continue;
                        }
                    }
                    None => {
                        eprintln!("No source address available");
                        continue;
                    }
                };

                let rcvt = generate_timestamp(conf.clock_source);
                let data = &buf[..len];

                // Determine if packet has TLVs
                let base_size = if use_auth {
                    AUTH_BASE_SIZE
                } else {
                    UNAUTH_BASE_SIZE
                };
                let has_tlvs = len > base_size;

                // TLV HMAC key for responses (only if we're not ignoring TLVs)
                // Per RFC 8972 §4.8: on HMAC verification failure, TLVs are echoed
                // with I-flag set rather than dropping the packet
                let tlv_hmac_key = if conf.tlv_mode != TlvHandlingMode::Ignore {
                    hmac_key.as_ref()
                } else {
                    None
                };

                // Determine whether to verify incoming TLV HMAC:
                // - Always verify if --verify-tlv-hmac is set
                // - Auto-verify in authenticated mode when HMAC key is configured
                //   (consistent with base packet HMAC verification behavior)
                let verify_tlv_hmac = conf.verify_tlv_hmac || (use_auth && hmac_key.is_some());

                let response = if use_auth {
                    // Parse packet leniently with canonical buffer for HMAC verification
                    // Per RFC 8762 §4.6, short packets are zero-filled and HMAC must be
                    // verified against the canonical (zero-padded) representation
                    let (packet, canonical_buf) = if conf.strict_packets {
                        match PacketAuthenticated::from_bytes(data) {
                            Ok(p) => {
                                // For strict mode, the buffer is already full-size
                                let mut buf = [0u8; 112];
                                buf.copy_from_slice(&data[..112]);
                                (p, buf)
                            }
                            Err(e) => {
                                eprintln!("Failed to deserialize authenticated packet: {}", e);
                                continue;
                            }
                        }
                    } else {
                        PacketAuthenticated::from_bytes_lenient_with_canonical(data)
                    };

                    // Extract HMAC for verification
                    let hmac = packet.hmac;

                    // Verify HMAC against canonical buffer - mandatory when key is present (RFC 8762 §4.4)
                    if let Some(ref key) = hmac_key {
                        if !verify_incoming_hmac(key, &canonical_buf, &hmac) {
                            eprintln!("HMAC verification failed");
                            continue; // Always reject invalid HMAC in auth mode
                        }
                    } else if conf.require_hmac {
                        // require_hmac means "require key to be configured"
                        eprintln!("HMAC key required but not configured");
                        continue;
                    }

                    // Generate reflector sequence number only after successful validation
                    let reflector_seq = session_manager
                        .as_ref()
                        .map(|mgr| mgr.generate_sequence_number(src_addr));

                    // Use TLV-aware assembly if packet has TLVs
                    // Per RFC 8972 §4.8: on HMAC failure, echo TLVs with I-flag set
                    if has_tlvs {
                        Some(assemble_auth_answer_with_tlvs(
                            &packet,
                            data,
                            conf.clock_source,
                            rcvt,
                            ttl,
                            error_estimate_wire,
                            hmac_key.as_ref(),
                            reflector_seq,
                            conf.tlv_mode,
                            tlv_hmac_key,
                            verify_tlv_hmac,
                        ))
                    } else {
                        Some(assemble_auth_answer_symmetric(
                            &packet,
                            data,
                            conf.clock_source,
                            rcvt,
                            ttl,
                            error_estimate_wire,
                            hmac_key.as_ref(),
                            reflector_seq,
                        ))
                    }
                } else {
                    let packet_result = if conf.strict_packets {
                        PacketUnauthenticated::from_bytes(data)
                    } else {
                        Ok(PacketUnauthenticated::from_bytes_lenient(data))
                    };
                    match packet_result {
                        Ok(packet) => {
                            // Generate reflector sequence number only after successful validation
                            let reflector_seq = session_manager
                                .as_ref()
                                .map(|mgr| mgr.generate_sequence_number(src_addr));

                            // Use TLV-aware assembly if packet has TLVs
                            // Per RFC 8972 §4.8: on HMAC failure, echo TLVs with I-flag set
                            if has_tlvs {
                                Some(assemble_unauth_answer_with_tlvs(
                                    &packet,
                                    data,
                                    conf.clock_source,
                                    rcvt,
                                    ttl,
                                    error_estimate_wire,
                                    reflector_seq,
                                    conf.tlv_mode,
                                    tlv_hmac_key,
                                    verify_tlv_hmac,
                                ))
                            } else {
                                Some(assemble_unauth_answer_symmetric(
                                    &packet,
                                    data,
                                    conf.clock_source,
                                    rcvt,
                                    ttl,
                                    error_estimate_wire,
                                    reflector_seq,
                                ))
                            }
                        }
                        Err(e) => {
                            eprintln!("Failed to deserialize unauthenticated packet: {}", e);
                            continue;
                        }
                    }
                };

                if let Some(response_buf) = response {
                    if let Err(e) = tokio_socket.send_to(&response_buf, src_addr).await {
                        eprintln!("Failed to send response: {}", e);
                    }
                }
            }
            Err(nix::errno::Errno::EAGAIN) => {
                // No data available, will retry after next readable notification
                continue;
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

/// Extract TTL from control messages received via recvmsg.
///
/// Returns `None` if TTL/HopLimit could not be extracted from the control messages.
#[cfg(target_os = "linux")]
fn extract_ttl_from_cmsgs(msg: &nix::sys::socket::RecvMsg<SockaddrStorage>) -> Option<u8> {
    let cmsgs = msg.cmsgs().ok()?;

    for cmsg in cmsgs {
        match cmsg {
            // IPv4 TTL (from IP_RECVTTL socket option)
            ControlMessageOwned::Ipv4Ttl(ttl) => {
                // TTL is i32 but valid range is 0-255
                return Some(ttl.clamp(0, 255) as u8);
            }
            // IPv6 Hop Limit (from IPV6_RECVHOPLIMIT socket option)
            ControlMessageOwned::Ipv6HopLimit(hoplimit) => {
                // Hop limit is i32 but valid range is 0-255
                return Some(hoplimit.clamp(0, 255) as u8);
            }
            _ => continue,
        }
    }

    None
}

/// Extract TTL from control messages received via recvmsg (macOS version).
///
/// On macOS, nix doesn't have typed Ipv4Ttl/Ipv6HopLimit variants, so we parse Unknown cmsgs.
/// Returns `None` if TTL/HopLimit could not be extracted from the control messages.
#[cfg(target_os = "macos")]
fn extract_ttl_from_cmsgs(msg: &nix::sys::socket::RecvMsg<SockaddrStorage>) -> Option<u8> {
    let cmsgs = msg.cmsgs().ok()?;

    for cmsg in cmsgs {
        if let ControlMessageOwned::Unknown(ref ucmsg) = cmsg {
            let level = ucmsg.cmsg_header.cmsg_level;
            let data = &ucmsg.data_bytes;

            // IPv4 TTL (level=IPPROTO_IP)
            if level == libc::IPPROTO_IP {
                if data.len() >= 4 {
                    let ttl = i32::from_ne_bytes([data[0], data[1], data[2], data[3]]);
                    return Some(ttl.clamp(0, 255) as u8);
                } else if !data.is_empty() {
                    return Some(data[0]);
                }
            }
            // IPv6 Hop Limit (level=IPPROTO_IPV6)
            else if level == libc::IPPROTO_IPV6 {
                if data.len() >= 4 {
                    let hoplimit = i32::from_ne_bytes([data[0], data[1], data[2], data[3]]);
                    return Some(hoplimit.clamp(0, 255) as u8);
                } else if !data.is_empty() {
                    return Some(data[0]);
                }
            }
        }
    }

    None
}
