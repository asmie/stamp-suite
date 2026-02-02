//! Receiver implementation using nix crate for real TTL capture via IP_RECVTTL.
//!
//! Preferred on Linux systems. No special privileges required for regular UDP sockets.

use std::{io::IoSliceMut, net::SocketAddr, os::fd::AsRawFd};

use nix::{
    libc,
    sys::socket::{recvmsg, ControlMessageOwned, MsgFlags, SockaddrStorage},
};
use tokio::net::UdpSocket;

use crate::{
    configuration::{is_auth, Configuration},
    packets::{any_as_u8_slice, read_struct, PacketAuthenticated, PacketUnauthenticated},
    time::generate_timestamp,
};

use super::{assemble_auth_answer, assemble_unauth_answer};

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

    println!(
        "STAMP Reflector listening on {} (nix mode, real TTL)",
        local_addr
    );

    let use_auth = is_auth(&conf.auth_mode);
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
                let src_addr = msg.address;

                // Extract TTL from control messages
                let ttl = extract_ttl_from_cmsgs(&msg);
                let rcvt = generate_timestamp(conf.clock_source);

                let response = if use_auth {
                    match read_struct::<PacketAuthenticated>(&buf[..len]) {
                        Ok(packet) => {
                            let answer =
                                assemble_auth_answer(&packet, conf.clock_source, rcvt, ttl);
                            any_as_u8_slice(&answer).ok()
                        }
                        Err(e) => {
                            eprintln!("Failed to deserialize authenticated packet: {}", e);
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
                            eprintln!("Failed to deserialize unauthenticated packet: {}", e);
                            continue;
                        }
                    }
                };

                if let Some(response_buf) = response {
                    if let Some(src) = src_addr {
                        // Convert SockaddrStorage back to SocketAddr
                        let dest: SocketAddr = if let Some(v4) = src.as_sockaddr_in() {
                            std::net::SocketAddrV4::new(v4.ip(), v4.port()).into()
                        } else if let Some(v6) = src.as_sockaddr_in6() {
                            std::net::SocketAddrV6::new(v6.ip(), v6.port(), 0, 0).into()
                        } else {
                            eprintln!("Unknown source address type");
                            continue;
                        };

                        if let Err(e) = tokio_socket.send_to(&response_buf, dest).await {
                            eprintln!("Failed to send response: {}", e);
                        }
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
fn extract_ttl_from_cmsgs(msg: &nix::sys::socket::RecvMsg<SockaddrStorage>) -> u8 {
    let mut ttl = 255u8;

    if let Ok(cmsgs) = msg.cmsgs() {
        for cmsg in cmsgs {
            if let ControlMessageOwned::Unknown(ucmsg) = cmsg {
                // The UnknownCmsg contains (cmsghdr, Vec<u8>)
                // For IPv4: level=IPPROTO_IP, type=IP_TTL
                // For IPv6: level=IPPROTO_IPV6, type=IPV6_HOPLIMIT
                //
                // Unfortunately, UnknownCmsg fields are not directly accessible.
                // We parse the debug output as a workaround.
                let cmsg_data = format!("{:?}", ucmsg);
                if cmsg_data.contains('[') {
                    if let Some(start) = cmsg_data.rfind('[') {
                        if let Some(end) = cmsg_data.rfind(']') {
                            let bytes_str = &cmsg_data[start + 1..end];
                            let bytes: Vec<u8> = bytes_str
                                .split(", ")
                                .filter_map(|s| s.trim().parse().ok())
                                .collect();
                            if !bytes.is_empty() {
                                // TTL is typically sent as int, take first byte
                                ttl = bytes[0];
                            }
                        }
                    }
                }
            }
        }
    }

    ttl
}
