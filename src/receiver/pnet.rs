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
    packets::{any_as_u8_slice, read_struct, PacketAuthenticated, PacketUnauthenticated},
    time::generate_timestamp,
};

use super::{assemble_auth_answer, assemble_unauth_answer};

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
    let local_addr: SocketAddr = (conf.local_addr, conf.local_port).into();
    let send_socket = std::net::UdpSocket::bind("0.0.0.0:0").expect("Cannot bind send socket");

    println!(
        "STAMP Reflector listening on {} (pnet mode, real TTL)",
        local_addr
    );

    let use_auth = is_auth(&conf.auth_mode);

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
                );
            }
            Err(e) => eprintln!("packetdump: unable to receive packet: {}", e),
        }
    }
}

fn handle_packet(
    ethernet: &EthernetPacket,
    conf: &Configuration,
    use_auth: bool,
    send_socket: &std::net::UdpSocket,
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
) {
    let rcvt = generate_timestamp(conf.clock_source);

    let response = if use_auth {
        match read_struct::<PacketAuthenticated>(data) {
            Ok(packet) => {
                let answer = assemble_auth_answer(&packet, conf.clock_source, rcvt, ttl);
                any_as_u8_slice(&answer).ok()
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
        match read_struct::<PacketUnauthenticated>(data) {
            Ok(packet) => {
                let answer = assemble_unauth_answer(&packet, conf.clock_source, rcvt, ttl);
                any_as_u8_slice(&answer).ok()
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
