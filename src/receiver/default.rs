//! Default receiver implementation using tokio UDP sockets.
//!
//! Uses a placeholder TTL value (255) since tokio doesn't provide access to IP header fields.
//! For real TTL capture, build with `--features ttl-nix` (Linux) or `--features ttl-pnet`.

use std::net::SocketAddr;

use tokio::net::UdpSocket;

use crate::{
    configuration::{is_auth, Configuration},
    packets::{any_as_u8_slice, read_struct, PacketAuthenticated, PacketUnauthenticated},
    time::generate_timestamp,
};

use super::{assemble_auth_answer, assemble_unauth_answer};

pub async fn run_receiver(conf: &Configuration) {
    let local_addr: SocketAddr = (conf.local_addr, conf.local_port).into();

    let socket = match UdpSocket::bind(local_addr).await {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Cannot bind to address {}: {}", local_addr, e);
            return;
        }
    };

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
                            let answer =
                                assemble_auth_answer(&packet, conf.clock_source, rcvt, ttl);
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
                            let answer =
                                assemble_unauth_answer(&packet, conf.clock_source, rcvt, ttl);
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
