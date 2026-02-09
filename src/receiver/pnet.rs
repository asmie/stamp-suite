//! Receiver implementation using pnet for raw packet capture with real TTL.
//!
//! Requires raw socket capabilities (root/CAP_NET_RAW on Linux).
//!
//! Uses `spawn_blocking` to run the blocking packet capture loop on a dedicated
//! thread, preventing starvation of the async runtime.

use nix::libc;
use std::{
    net::{IpAddr, SocketAddr},
    time::{Duration, Instant},
};

use pnet::{
    datalink::{self, Channel::Ethernet, Config, DataLinkReceiver, NetworkInterface},
    packet::{
        ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket},
        ip::IpNextHeaderProtocols,
        ipv4::Ipv4Packet,
        ipv6::Ipv6Packet,
        udp::UdpPacket,
        Packet,
    },
    util::MacAddr,
};

use std::sync::Arc;

use crate::{
    clock_format::ClockFormat,
    configuration::{is_auth, Configuration, TlvHandlingMode},
    crypto::HmacKey,
    error_estimate::ErrorEstimate,
    session::SessionManager,
};

use super::{
    load_hmac_key, process_stamp_packet, set_cos_policy_rejected, ProcessingContext,
    AUTH_BASE_SIZE, UNAUTH_BASE_SIZE,
};

/// Context for sending STAMP responses in pnet mode.
struct PnetSendContext {
    send_socket_v4: std::net::UdpSocket,
    send_socket_v6: Option<std::net::UdpSocket>,
    /// Cached TOS value for IPv4 socket to avoid redundant setsockopt calls.
    last_tos_v4: std::cell::Cell<u8>,
    /// Cached TOS value for IPv6 socket to avoid redundant setsockopt calls.
    last_tos_v6: std::cell::Cell<u8>,
}

/// Configuration extracted for the blocking capture loop.
/// This allows us to move owned data into the spawn_blocking closure.
struct CaptureConfig {
    local_port: u16,
    clock_source: ClockFormat,
    use_auth: bool,
    error_estimate_wire: u16,
    hmac_key: Option<HmacKey>,
    session_manager: Option<Arc<SessionManager>>,
    tlv_mode: TlvHandlingMode,
    require_hmac: bool,
    verify_tlv_hmac: bool,
    strict_packets: bool,
    cleanup_interval: Option<Duration>,
    #[cfg(feature = "metrics")]
    metrics_enabled: bool,
}

/// Interface properties needed for macOS special handling.
/// Extracted from NetworkInterface since it's not Send.
struct InterfaceProps {
    is_up: bool,
    is_broadcast: bool,
    is_loopback: bool,
    is_point_to_point: bool,
}

/// Runs the STAMP Session Reflector using pnet for raw packet capture.
///
/// Captures packets at the datalink layer to extract the real TTL value.
/// Requires elevated privileges (root or CAP_NET_RAW on Linux).
///
/// The blocking packet capture loop runs in a dedicated thread via `spawn_blocking`
/// to prevent starvation of the async runtime (e.g., metrics server).
pub async fn run_receiver(conf: &Configuration) {
    let interface_ip_match =
        |iface: &NetworkInterface| iface.ips.iter().any(|ip| ip.ip() == conf.local_addr);

    // Find the network interface with the provided local IP address
    let interfaces = datalink::interfaces();
    let interface = interfaces.into_iter().find(interface_ip_match);

    let interface = match interface {
        Some(iface) => iface,
        None => {
            eprintln!(
                "Error: No interface found with IP address {}",
                conf.local_addr
            );
            return;
        }
    };

    // Extract interface properties for macOS special handling (NetworkInterface is not Send)
    let iface_props = InterfaceProps {
        is_up: interface.is_up(),
        is_broadcast: interface.is_broadcast(),
        is_loopback: interface.is_loopback(),
        is_point_to_point: interface.is_point_to_point(),
    };

    // Configure read timeout for periodic cleanup during idle periods
    // Use half the session timeout (min 1s) if stateful mode, otherwise no timeout
    let read_timeout = if conf.stateful_reflector && conf.session_timeout > 0 {
        Some(Duration::from_secs((conf.session_timeout / 2).max(1)))
    } else {
        None
    };
    let config = Config {
        read_timeout,
        ..Default::default()
    };

    // Create a channel to receive on
    let (_, rx) = match datalink::channel(&interface, config) {
        Ok(Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => {
            eprintln!(
                "Error: Unhandled channel type for interface {}",
                interface.name
            );
            return;
        }
        Err(e) => {
            eprintln!("Error: Unable to create capture channel: {}", e);
            return;
        }
    };

    // We need UDP sockets to send responses - one for each address family
    // since pnet captures at the datalink layer and may see both IPv4 and IPv6 packets
    let local_addr: SocketAddr = (conf.local_addr, conf.local_port).into();
    let send_socket_v4 = match std::net::UdpSocket::bind("0.0.0.0:0") {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Error: Cannot bind IPv4 send socket: {}", e);
            return;
        }
    };
    let send_socket_v6 = std::net::UdpSocket::bind("[::]:0").ok(); // Optional, may fail if IPv6 unavailable

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

    let send_ctx = PnetSendContext {
        send_socket_v4,
        send_socket_v6,
        last_tos_v4: std::cell::Cell::new(0),
        last_tos_v6: std::cell::Cell::new(0),
    };

    if conf.tlv_mode != TlvHandlingMode::Ignore {
        log::info!("TLV handling mode: {:?}", conf.tlv_mode);
    }

    println!(
        "STAMP Reflector listening on {} (pnet mode, real TTL)",
        local_addr
    );

    // Session cleanup interval: run at half the timeout period, minimum 1 second
    // When session_timeout is 0, checked_div returns None, disabling cleanup
    let cleanup_interval = session_manager.as_ref().and_then(|_| {
        conf.session_timeout
            .checked_div(2)
            .map(|t| Duration::from_secs(t.max(1)))
    });

    // Build capture config with all values needed by the blocking loop
    let capture_config = CaptureConfig {
        local_port: conf.local_port,
        clock_source: conf.clock_source,
        use_auth,
        error_estimate_wire,
        hmac_key,
        session_manager,
        tlv_mode: conf.tlv_mode,
        require_hmac: conf.require_hmac,
        verify_tlv_hmac: conf.verify_tlv_hmac,
        strict_packets: conf.strict_packets,
        cleanup_interval,
        #[cfg(feature = "metrics")]
        metrics_enabled: conf.metrics,
    };

    // Spawn the blocking packet capture loop on a dedicated thread.
    // This prevents starvation of the async runtime which may be running
    // other tasks like the metrics HTTP server.
    let result = tokio::task::spawn_blocking(move || {
        run_capture_loop(rx, capture_config, send_ctx, iface_props);
    })
    .await;

    if let Err(e) = result {
        eprintln!("Capture thread panicked: {}", e);
    }
}

/// The blocking packet capture loop, run on a dedicated thread.
fn run_capture_loop(
    mut rx: Box<dyn DataLinkReceiver>,
    config: CaptureConfig,
    send_ctx: PnetSendContext,
    iface_props: InterfaceProps,
) {
    let mut last_cleanup = Instant::now();
    let mut buf = [0u8; 1600];

    loop {
        // Periodic session cleanup check
        if let (Some(ref mgr), Some(interval)) = (&config.session_manager, config.cleanup_interval)
        {
            if last_cleanup.elapsed() >= interval {
                let removed = mgr.cleanup_stale_sessions();
                if removed > 0 {
                    log::debug!("Session cleanup: removed {} stale sessions", removed);
                }
                last_cleanup = Instant::now();
            }
        }

        let mut fake_ethernet_frame = MutableEthernetPacket::new(&mut buf[..]).unwrap();
        match rx.next() {
            Ok(packet) => {
                let payload_offset;
                if cfg!(any(
                    target_os = "macos",
                    target_os = "ios",
                    target_os = "tvos"
                )) && iface_props.is_up
                    && !iface_props.is_broadcast
                    && ((!iface_props.is_loopback && iface_props.is_point_to_point)
                        || iface_props.is_loopback)
                {
                    if iface_props.is_loopback {
                        payload_offset = 14;
                    } else {
                        payload_offset = 0;
                    }
                    if packet.len() > payload_offset {
                        let Some(ip_header) = Ipv4Packet::new(&packet[payload_offset..]) else {
                            continue; // Malformed packet, skip
                        };
                        let version = ip_header.get_version();
                        if version == 4 {
                            fake_ethernet_frame.set_destination(MacAddr(0, 0, 0, 0, 0, 0));
                            fake_ethernet_frame.set_source(MacAddr(0, 0, 0, 0, 0, 0));
                            fake_ethernet_frame.set_ethertype(EtherTypes::Ipv4);
                            fake_ethernet_frame.set_payload(&packet[payload_offset..]);
                            handle_packet(&fake_ethernet_frame.to_immutable(), &config, &send_ctx);
                            continue;
                        } else if version == 6 {
                            fake_ethernet_frame.set_destination(MacAddr(0, 0, 0, 0, 0, 0));
                            fake_ethernet_frame.set_source(MacAddr(0, 0, 0, 0, 0, 0));
                            fake_ethernet_frame.set_ethertype(EtherTypes::Ipv6);
                            fake_ethernet_frame.set_payload(&packet[payload_offset..]);
                            handle_packet(&fake_ethernet_frame.to_immutable(), &config, &send_ctx);
                            continue;
                        }
                    }
                }
                let Some(ethernet) = EthernetPacket::new(packet) else {
                    continue; // Malformed frame, skip
                };
                handle_packet(&ethernet, &config, &send_ctx);
            }
            Err(e) => {
                // Timeout errors are expected when read_timeout is set - just continue to run cleanup
                if e.kind() != std::io::ErrorKind::TimedOut
                    && e.kind() != std::io::ErrorKind::WouldBlock
                {
                    eprintln!("packetdump: unable to receive packet: {}", e);
                }
            }
        }
    }
}

fn handle_packet(ethernet: &EthernetPacket, config: &CaptureConfig, send_ctx: &PnetSendContext) {
    match ethernet.get_ethertype() {
        EtherTypes::Ipv4 => {
            if let Some(header) = Ipv4Packet::new(ethernet.payload()) {
                if header.get_next_level_protocol() == IpNextHeaderProtocols::Udp {
                    if let Some(udp) = UdpPacket::new(header.payload()) {
                        if udp.get_destination() == config.local_port {
                            let ttl = header.get_ttl();
                            let dscp = header.get_dscp();
                            let ecn = header.get_ecn();
                            let src =
                                SocketAddr::new(IpAddr::V4(header.get_source()), udp.get_source());
                            handle_stamp_packet(
                                udp.payload(),
                                src,
                                ttl,
                                dscp,
                                ecn,
                                config,
                                send_ctx,
                            );
                        }
                    }
                }
            }
        }
        EtherTypes::Ipv6 => {
            if let Some(header) = Ipv6Packet::new(ethernet.payload()) {
                if header.get_next_header() == IpNextHeaderProtocols::Udp {
                    if let Some(udp) = UdpPacket::new(header.payload()) {
                        if udp.get_destination() == config.local_port {
                            let ttl = header.get_hop_limit();
                            // IPv6 Traffic Class contains DSCP (upper 6 bits) and ECN (lower 2 bits)
                            let traffic_class = header.get_traffic_class();
                            let dscp = (traffic_class >> 2) & 0x3F;
                            let ecn = traffic_class & 0x03;
                            let src =
                                SocketAddr::new(IpAddr::V6(header.get_source()), udp.get_source());
                            handle_stamp_packet(
                                udp.payload(),
                                src,
                                ttl,
                                dscp,
                                ecn,
                                config,
                                send_ctx,
                            );
                        }
                    }
                }
            }
        }
        _ => {}
    }
}

fn handle_stamp_packet(
    data: &[u8],
    src: SocketAddr,
    ttl: u8,
    dscp: u8,
    ecn: u8,
    config: &CaptureConfig,
    send_ctx: &PnetSendContext,
) {
    let ctx = ProcessingContext {
        clock_source: config.clock_source,
        error_estimate_wire: config.error_estimate_wire,
        hmac_key: config.hmac_key.as_ref(),
        require_hmac: config.require_hmac,
        session_manager: config.session_manager.as_ref(),
        tlv_mode: config.tlv_mode,
        verify_tlv_hmac: config.verify_tlv_hmac,
        strict_packets: config.strict_packets,
        #[cfg(feature = "metrics")]
        metrics_enabled: config.metrics_enabled,
        received_dscp: dscp,
        received_ecn: ecn,
    };

    if let Some(mut response) = process_stamp_packet(data, src, ttl, config.use_auth, &ctx) {
        use std::os::fd::AsRawFd;

        // Determine TOS value: use CoS TLV request if present, otherwise default (0).
        let (tos, has_cos_request) = match response.cos_request {
            Some((dscp, ecn)) => (((dscp & 0x3F) << 2) | (ecn & 0x03), true),
            None => (0u8, false),
        };

        // Get socket info and TOS cache based on address family
        let (fd, level, opt, last_tos_cache) = match src {
            SocketAddr::V4(_) => (
                send_ctx.send_socket_v4.as_raw_fd(),
                libc::IPPROTO_IP,
                libc::IP_TOS,
                &send_ctx.last_tos_v4,
            ),
            SocketAddr::V6(_) => {
                if let Some(ref socket) = send_ctx.send_socket_v6 {
                    (
                        socket.as_raw_fd(),
                        libc::IPPROTO_IPV6,
                        libc::IPV6_TCLASS,
                        &send_ctx.last_tos_v6,
                    )
                } else {
                    eprintln!("Cannot send IPv6 response: IPv6 socket unavailable");
                    return;
                }
            }
        };

        // Only call setsockopt if TOS value changed (reduces syscall overhead under load)
        if tos != last_tos_cache.get() {
            let tos_val: libc::c_int = tos as libc::c_int;
            let result = unsafe {
                libc::setsockopt(
                    fd,
                    level,
                    opt,
                    &tos_val as *const _ as *const libc::c_void,
                    std::mem::size_of::<libc::c_int>() as libc::socklen_t,
                )
            };
            if result < 0 {
                if has_cos_request {
                    log::debug!(
                        "Failed to set IP_TOS/IPV6_TCLASS to {}: {}",
                        tos,
                        std::io::Error::last_os_error()
                    );
                    // Set RP flag in CoS TLV to indicate policy rejection (RFC 8972 §5.2)
                    let base_size = if config.use_auth {
                        AUTH_BASE_SIZE
                    } else {
                        UNAUTH_BASE_SIZE
                    };
                    set_cos_policy_rejected(&mut response.data, base_size);
                }
                // Don't update cache on failure - retry next time
            } else {
                last_tos_cache.set(tos);
            }
        }

        // Use the appropriate socket based on address family
        let send_result = match src {
            SocketAddr::V4(_) => send_ctx.send_socket_v4.send_to(&response.data, src),
            SocketAddr::V6(_) => match &send_ctx.send_socket_v6 {
                Some(socket) => socket.send_to(&response.data, src),
                None => {
                    eprintln!("Cannot send IPv6 response: IPv6 socket unavailable");
                    return;
                }
            },
        };
        if let Err(e) = send_result {
            eprintln!("Failed to send response to {}: {}", src, e);
        }
    }
}
