//! Receiver implementation using nix crate for real TTL capture via IP_RECVTTL.
//!
//! Preferred on Linux systems. No special privileges required for regular UDP sockets.

use std::{io::IoSliceMut, net::SocketAddr, os::fd::AsRawFd, sync::Arc, time::Duration};

use nix::{
    libc,
    sys::socket::{recvmsg, ControlMessageOwned, MsgFlags, SockaddrStorage},
};
use tokio::{net::UdpSocket, time::interval};

use crate::{
    configuration::{is_auth, Configuration, TlvHandlingMode},
    error_estimate::ErrorEstimate,
    session::SessionManager,
};

use super::{
    load_hmac_key, process_stamp_packet, set_cos_policy_rejected, ProcessingContext,
    AUTH_BASE_SIZE, UNAUTH_BASE_SIZE,
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

    // Enable TTL/hop limit and TOS/Traffic Class reception via setsockopt using libc directly
    // nix doesn't expose IP_RECVTTL/IP_RECVTOS, so we use libc
    let fd = std_socket.as_raw_fd();
    let enable: libc::c_int = 1;

    // Enable TTL/Hop Limit reception
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

    // Enable TOS/Traffic Class reception (for DSCP/ECN measurement)
    let tos_result = if is_ipv6 {
        unsafe {
            libc::setsockopt(
                fd,
                libc::IPPROTO_IPV6,
                libc::IPV6_RECVTCLASS,
                &enable as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            )
        }
    } else {
        unsafe {
            libc::setsockopt(
                fd,
                libc::IPPROTO_IP,
                libc::IP_RECVTOS,
                &enable as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            )
        }
    };

    if tos_result < 0 {
        // TOS reception is optional (for DSCP/ECN measurement), just log warning
        log::warn!(
            "Failed to set IP_RECVTOS/IPV6_RECVTCLASS: {} (DSCP/ECN measurement disabled)",
            std::io::Error::last_os_error()
        );
    }

    // Set non-blocking for tokio
    if let Err(e) = std_socket.set_nonblocking(true) {
        eprintln!("Error: Failed to set socket non-blocking: {}", e);
        return;
    }

    // Wrap in tokio for async readiness notifications
    let tokio_socket = match UdpSocket::from_std(std_socket) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Error: Failed to create tokio socket: {}", e);
            return;
        }
    };

    // Check if authenticated mode is used
    let use_auth = is_auth(conf.auth_mode);

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

    // Session cleanup interval: run at half the timeout period, minimum 1 second
    // When session_timeout is 0, checked_div returns None, disabling cleanup
    let cleanup_interval = session_manager.as_ref().and_then(|_| {
        conf.session_timeout
            .checked_div(2)
            .map(|t| Duration::from_secs(t.max(1)))
    });
    let mut cleanup_timer = cleanup_interval.map(interval);

    // Cache last applied TOS value to avoid redundant setsockopt calls under load.
    // Sockets default to TOS=0, so we start with that assumption.
    let mut last_tos: u8 = 0;

    loop {
        // Wait for socket to be readable or cleanup timer to fire.
        // Use unbiased select to ensure fair scheduling - biased select
        // would starve the cleanup timer under heavy packet load.
        tokio::select! {
            result = tokio_socket.readable() => {
                if let Err(e) = result {
                    eprintln!("Failed to wait for readable: {}", e);
                    continue;
                }
            }

            _ = async {
                if let Some(ref mut timer) = cleanup_timer {
                    timer.tick().await
                } else {
                    std::future::pending::<tokio::time::Instant>().await
                }
            } => {
                // Run periodic session cleanup
                if let Some(ref mgr) = session_manager {
                    let removed = mgr.cleanup_stale_sessions();
                    if removed > 0 {
                        log::debug!("Session cleanup: removed {} stale sessions", removed);
                    }
                }
                continue;
            }
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

                // Extract TOS (DSCP/ECN) from control messages
                let (received_dscp, received_ecn) = extract_tos_from_cmsgs(&msg)
                    .map(|tos| ((tos >> 2) & 0x3F, tos & 0x03))
                    .unwrap_or((0, 0));

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

                let data = &buf[..len];

                let ctx = ProcessingContext {
                    clock_source: conf.clock_source,
                    error_estimate_wire,
                    hmac_key: hmac_key.as_ref(),
                    require_hmac: conf.require_hmac,
                    session_manager: session_manager.as_ref(),
                    tlv_mode: conf.tlv_mode,
                    verify_tlv_hmac: conf.verify_tlv_hmac,
                    strict_packets: conf.strict_packets,
                    #[cfg(feature = "metrics")]
                    metrics_enabled: conf.metrics,
                    received_dscp,
                    received_ecn,
                };

                if let Some(mut response) =
                    process_stamp_packet(data, src_addr, ttl, use_auth, &ctx)
                {
                    // Determine TOS value: use CoS TLV request if present, otherwise default (0).
                    let (tos, has_cos_request) = match response.cos_request {
                        Some((dscp, ecn)) => (((dscp & 0x3F) << 2) | (ecn & 0x03), true),
                        None => (0u8, false),
                    };

                    // Only call setsockopt if TOS value changed (reduces syscall overhead under load)
                    if tos != last_tos {
                        let fd = tokio_socket.as_raw_fd();
                        let tos_val: libc::c_int = tos as libc::c_int;
                        let result = if is_ipv6 {
                            unsafe {
                                libc::setsockopt(
                                    fd,
                                    libc::IPPROTO_IPV6,
                                    libc::IPV6_TCLASS,
                                    &tos_val as *const _ as *const libc::c_void,
                                    std::mem::size_of::<libc::c_int>() as libc::socklen_t,
                                )
                            }
                        } else {
                            unsafe {
                                libc::setsockopt(
                                    fd,
                                    libc::IPPROTO_IP,
                                    libc::IP_TOS,
                                    &tos_val as *const _ as *const libc::c_void,
                                    std::mem::size_of::<libc::c_int>() as libc::socklen_t,
                                )
                            }
                        };
                        if result < 0 {
                            if has_cos_request {
                                log::debug!(
                                    "Failed to set IP_TOS/IPV6_TCLASS to {}: {}",
                                    tos,
                                    std::io::Error::last_os_error()
                                );
                                // Set RP flag in CoS TLV to indicate policy rejection (RFC 8972 §5.2)
                                let base_size = if use_auth {
                                    AUTH_BASE_SIZE
                                } else {
                                    UNAUTH_BASE_SIZE
                                };
                                set_cos_policy_rejected(&mut response.data, base_size);
                            }
                            // Don't update last_tos on failure - retry next time
                        } else {
                            last_tos = tos;
                        }
                    }

                    if let Err(e) = tokio_socket.send_to(&response.data, src_addr).await {
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

/// Extract TOS (Type of Service) from control messages received via recvmsg.
///
/// Returns the raw TOS byte which contains DSCP (upper 6 bits) and ECN (lower 2 bits).
/// Returns `None` if TOS/Traffic Class could not be extracted from the control messages.
#[cfg(target_os = "linux")]
fn extract_tos_from_cmsgs(msg: &nix::sys::socket::RecvMsg<SockaddrStorage>) -> Option<u8> {
    let cmsgs = msg.cmsgs().ok()?;

    for cmsg in cmsgs {
        match cmsg {
            // IPv4 TOS (from IP_RECVTOS socket option)
            ControlMessageOwned::Ipv4Tos(tos) => {
                return Some(tos);
            }
            // IPv6 Traffic Class (from IPV6_RECVTCLASS socket option)
            ControlMessageOwned::Ipv6TClass(tclass) => {
                return Some(tclass.clamp(0, 255) as u8);
            }
            _ => continue,
        }
    }

    None
}

/// Extract TOS (Type of Service) from control messages received via recvmsg (macOS version).
///
/// Returns the raw TOS byte which contains DSCP (upper 6 bits) and ECN (lower 2 bits).
/// Returns `None` if TOS/Traffic Class could not be extracted from the control messages.
#[cfg(target_os = "macos")]
fn extract_tos_from_cmsgs(msg: &nix::sys::socket::RecvMsg<SockaddrStorage>) -> Option<u8> {
    let cmsgs = msg.cmsgs().ok()?;

    for cmsg in cmsgs {
        if let ControlMessageOwned::Unknown(ref ucmsg) = cmsg {
            let level = ucmsg.cmsg_header.cmsg_level;
            let cmsg_type = ucmsg.cmsg_header.cmsg_type;
            let data = &ucmsg.data_bytes;

            // IPv4 TOS (level=IPPROTO_IP, type=IP_RECVTOS)
            if level == libc::IPPROTO_IP && cmsg_type == libc::IP_RECVTOS {
                if data.len() >= 4 {
                    let tos = i32::from_ne_bytes([data[0], data[1], data[2], data[3]]);
                    return Some(tos.clamp(0, 255) as u8);
                } else if !data.is_empty() {
                    return Some(data[0]);
                }
            }
            // IPv6 Traffic Class (level=IPPROTO_IPV6, type=IPV6_RECVTCLASS)
            else if level == libc::IPPROTO_IPV6 && cmsg_type == libc::IPV6_TCLASS {
                if data.len() >= 4 {
                    let tclass = i32::from_ne_bytes([data[0], data[1], data[2], data[3]]);
                    return Some(tclass.clamp(0, 255) as u8);
                } else if !data.is_empty() {
                    return Some(data[0]);
                }
            }
        }
    }

    None
}
