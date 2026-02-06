//! Receiver implementation using pnet for raw packet capture with real TTL.
//!
//! Requires raw socket capabilities (root/CAP_NET_RAW on Linux).

use std::net::{IpAddr, SocketAddr};

use pnet::{
    datalink::{self, Channel::Ethernet, NetworkInterface},
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

use crate::{
    configuration::{is_auth, Configuration},
    crypto::HmacKey,
    error_estimate::ErrorEstimate,
    packets::{PacketAuthenticated, PacketUnauthenticated},
    session::Session,
    time::generate_timestamp,
};

use super::{assemble_auth_answer_symmetric, assemble_unauth_answer_symmetric};

/// Context for handling STAMP packets in pnet mode.
struct PnetContext {
    error_estimate_wire: u16,
    hmac_key: Option<HmacKey>,
    require_hmac: bool,
    reflector_session: Option<Session>,
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
    let interface = interfaces
        .into_iter()
        .find(interface_ip_match)
        .unwrap_or_else(|| panic!("No interface found with IP address {}", conf.local_addr));

    // Create a channel to receive on
    let (_, mut rx) = match datalink::channel(&interface, Default::default()) {
        Ok(Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("packetdump: unhandled channel type"),
        Err(e) => panic!("packetdump: unable to create channel: {}", e),
    };

    // We also need a UDP socket to send responses
    // Bind to appropriate address family based on configured local address
    let local_addr: SocketAddr = (conf.local_addr, conf.local_port).into();
    let send_bind_addr = if conf.local_addr.is_ipv6() {
        "[::]:0"
    } else {
        "0.0.0.0:0"
    };
    let send_socket =
        std::net::UdpSocket::bind(send_bind_addr).expect("Cannot bind send socket");

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

    let ctx = PnetContext {
        error_estimate_wire,
        hmac_key,
        require_hmac: conf.require_hmac,
        reflector_session,
    };

    println!(
        "STAMP Reflector listening on {} (pnet mode, real TTL)",
        local_addr
    );

    loop {
        let mut buf: [u8; 1600] = [0u8; 1600];
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
                        let version = Ipv4Packet::new(&packet[payload_offset..])
                            .unwrap()
                            .get_version();
                        if version == 4 {
                            fake_ethernet_frame.set_destination(MacAddr(0, 0, 0, 0, 0, 0));
                            fake_ethernet_frame.set_source(MacAddr(0, 0, 0, 0, 0, 0));
                            fake_ethernet_frame.set_ethertype(EtherTypes::Ipv4);
                            fake_ethernet_frame.set_payload(&packet[payload_offset..]);
                            handle_packet(
                                &fake_ethernet_frame.to_immutable(),
                                conf,
                                use_auth,
                                &send_socket,
                                &ctx,
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
                                &send_socket,
                                &ctx,
                            );
                            continue;
                        }
                    }
                }
                handle_packet(
                    &EthernetPacket::new(packet).unwrap(),
                    conf,
                    use_auth,
                    &send_socket,
                    &ctx,
                );
            }
            Err(e) => eprintln!("packetdump: unable to receive packet: {}", e),
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

fn handle_packet(
    ethernet: &EthernetPacket,
    conf: &Configuration,
    use_auth: bool,
    send_socket: &std::net::UdpSocket,
    ctx: &PnetContext,
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
                            process_stamp_packet(
                                udp.payload(),
                                src,
                                ttl,
                                conf,
                                use_auth,
                                send_socket,
                                ctx,
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
                            process_stamp_packet(
                                udp.payload(),
                                src,
                                ttl,
                                conf,
                                use_auth,
                                send_socket,
                                ctx,
                            );
                        }
                    }
                }
            }
        }
        _ => {}
    }
}

fn process_stamp_packet(
    data: &[u8],
    src: SocketAddr,
    ttl: u8,
    conf: &Configuration,
    use_auth: bool,
    send_socket: &std::net::UdpSocket,
    ctx: &PnetContext,
) {
    let rcvt = generate_timestamp(conf.clock_source);

    let response = if use_auth {
        let packet_result = if conf.strict_packets {
            PacketAuthenticated::from_bytes(data)
        } else {
            Ok(PacketAuthenticated::from_bytes_lenient(data))
        };
        match packet_result {
            Ok(packet) => {
                // Copy HMAC to avoid unaligned access
                let hmac = packet.hmac;

                // Verify HMAC - mandatory when key is present (RFC 8762 §4.4)
                if let Some(ref key) = ctx.hmac_key {
                    if !verify_incoming_hmac(key, data, &hmac) {
                        eprintln!("HMAC verification failed for packet from {}", src);
                        return; // Always reject invalid HMAC in auth mode
                    }
                } else if ctx.require_hmac {
                    // require_hmac means "require key to be configured"
                    eprintln!("HMAC key required but not configured");
                    return;
                }

                // Generate reflector sequence number only after successful validation
                let reflector_seq = ctx
                    .reflector_session
                    .as_ref()
                    .map(|s| s.generate_sequence_number());

                // Use symmetric assembly to preserve original packet length (RFC 8762 Section 4.3)
                Some(assemble_auth_answer_symmetric(
                    &packet,
                    data,
                    conf.clock_source,
                    rcvt,
                    ttl,
                    ctx.error_estimate_wire,
                    ctx.hmac_key.as_ref(),
                    reflector_seq,
                ))
            }
            Err(e) => {
                eprintln!(
                    "Failed to deserialize authenticated packet from {}: {}",
                    src, e
                );
                return;
            }
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
                let reflector_seq = ctx
                    .reflector_session
                    .as_ref()
                    .map(|s| s.generate_sequence_number());

                // Use symmetric assembly to preserve original packet length (RFC 8762 Section 4.3)
                Some(assemble_unauth_answer_symmetric(
                    &packet,
                    data,
                    conf.clock_source,
                    rcvt,
                    ttl,
                    ctx.error_estimate_wire,
                    reflector_seq,
                ))
            }
            Err(e) => {
                eprintln!(
                    "Failed to deserialize unauthenticated packet from {}: {}",
                    src, e
                );
                return;
            }
        }
    };

    if let Some(response_buf) = response {
        if let Err(e) = send_socket.send_to(&response_buf, src) {
            eprintln!("Failed to send response to {}: {}", src, e);
        }
    }
}
