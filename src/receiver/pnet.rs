//! Receiver implementation using pnet for raw packet capture with real TTL.
//!
//! Requires raw socket capabilities (root/CAP_NET_RAW on Linux).

use std::{
    net::{IpAddr, SocketAddr},
    time::{Duration, Instant},
};

use pnet::{
    datalink::{self, Channel::Ethernet, Config, NetworkInterface},
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
    configuration::{is_auth, Configuration},
    error_estimate::ErrorEstimate,
    session::SessionManager,
};

use super::{load_hmac_key, process_stamp_packet, ProcessingContext};

/// Context for sending STAMP responses in pnet mode.
struct PnetSendContext {
    send_socket_v4: std::net::UdpSocket,
    send_socket_v6: Option<std::net::UdpSocket>,
}

/// Runs the STAMP Session Reflector using pnet for raw packet capture.
///
/// Captures packets at the datalink layer to extract the real TTL value.
/// Requires elevated privileges (root or CAP_NET_RAW on Linux).
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
    let (_, mut rx) = match datalink::channel(&interface, config) {
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
    };

    if conf.tlv_mode != crate::configuration::TlvHandlingMode::Ignore {
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
    let mut last_cleanup = Instant::now();

    // Reusable buffer for constructing fake ethernet frames (hoisted outside loop)
    let mut buf = [0u8; 1600];

    loop {
        // Periodic session cleanup check
        if let (Some(ref mgr), Some(interval)) = (&session_manager, cleanup_interval) {
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
                )) && interface.is_up()
                    && !interface.is_broadcast()
                    && ((!interface.is_loopback() && interface.is_point_to_point())
                        || interface.is_loopback())
                {
                    if interface.is_loopback() {
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
                            handle_packet(
                                &fake_ethernet_frame.to_immutable(),
                                conf,
                                use_auth,
                                error_estimate_wire,
                                hmac_key.as_ref(),
                                session_manager.as_ref(),
                                &send_ctx,
                            );
                            continue;
                        } else if version == 6 {
                            fake_ethernet_frame.set_destination(MacAddr(0, 0, 0, 0, 0, 0));
                            fake_ethernet_frame.set_source(MacAddr(0, 0, 0, 0, 0, 0));
                            fake_ethernet_frame.set_ethertype(EtherTypes::Ipv6);
                            fake_ethernet_frame.set_payload(&packet[payload_offset..]);
                            handle_packet(
                                &fake_ethernet_frame.to_immutable(),
                                conf,
                                use_auth,
                                error_estimate_wire,
                                hmac_key.as_ref(),
                                session_manager.as_ref(),
                                &send_ctx,
                            );
                            continue;
                        }
                    }
                }
                let Some(ethernet) = EthernetPacket::new(packet) else {
                    continue; // Malformed frame, skip
                };
                handle_packet(
                    &ethernet,
                    conf,
                    use_auth,
                    error_estimate_wire,
                    hmac_key.as_ref(),
                    session_manager.as_ref(),
                    &send_ctx,
                );
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

use crate::crypto::HmacKey;

fn handle_packet(
    ethernet: &EthernetPacket,
    conf: &Configuration,
    use_auth: bool,
    error_estimate_wire: u16,
    hmac_key: Option<&HmacKey>,
    session_manager: Option<&Arc<SessionManager>>,
    send_ctx: &PnetSendContext,
) {
    match ethernet.get_ethertype() {
        EtherTypes::Ipv4 => {
            if let Some(header) = Ipv4Packet::new(ethernet.payload()) {
                if header.get_next_level_protocol() == IpNextHeaderProtocols::Udp {
                    if let Some(udp) = UdpPacket::new(header.payload()) {
                        if udp.get_destination() == conf.local_port {
                            let ttl = header.get_ttl();
                            let src =
                                SocketAddr::new(IpAddr::V4(header.get_source()), udp.get_source());
                            handle_stamp_packet(
                                udp.payload(),
                                src,
                                ttl,
                                conf,
                                use_auth,
                                error_estimate_wire,
                                hmac_key,
                                session_manager,
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
                        if udp.get_destination() == conf.local_port {
                            let ttl = header.get_hop_limit();
                            let src =
                                SocketAddr::new(IpAddr::V6(header.get_source()), udp.get_source());
                            handle_stamp_packet(
                                udp.payload(),
                                src,
                                ttl,
                                conf,
                                use_auth,
                                error_estimate_wire,
                                hmac_key,
                                session_manager,
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

#[allow(clippy::too_many_arguments)]
fn handle_stamp_packet(
    data: &[u8],
    src: SocketAddr,
    ttl: u8,
    conf: &Configuration,
    use_auth: bool,
    error_estimate_wire: u16,
    hmac_key: Option<&HmacKey>,
    session_manager: Option<&Arc<SessionManager>>,
    send_ctx: &PnetSendContext,
) {
    let ctx = ProcessingContext {
        clock_source: conf.clock_source,
        error_estimate_wire,
        hmac_key,
        require_hmac: conf.require_hmac,
        session_manager,
        tlv_mode: conf.tlv_mode,
        verify_tlv_hmac: conf.verify_tlv_hmac,
        strict_packets: conf.strict_packets,
    };

    if let Some(response_buf) = process_stamp_packet(data, src, ttl, use_auth, &ctx) {
        // Use the appropriate socket based on address family
        let send_result = match src {
            SocketAddr::V4(_) => send_ctx.send_socket_v4.send_to(&response_buf, src),
            SocketAddr::V6(_) => match &send_ctx.send_socket_v6 {
                Some(socket) => socket.send_to(&response_buf, src),
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
