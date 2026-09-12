//! Draft ext-hdr-13 §3.1 endpoint and outgoing-hop policy.
use std::{
    io,
    net::{SocketAddr, UdpSocket},
};

pub(crate) fn set_hops(socket: &UdpSocket) -> io::Result<()> {
    let sock = socket2::SockRef::from(socket);
    if socket.local_addr()?.is_ipv6() {
        sock.set_unicast_hops_v6(255)?;
        // Darwin's IPV6_UNICAST_HOPS also sets the TTL for IPv4-mapped
        // traffic. Its IPv6 socket option handler rejects IPPROTO_IP options.
        #[cfg(not(target_os = "macos"))]
        if !sock.only_v6()? {
            // IPv4-mapped traffic uses the IPv4 TTL even on this socket.
            sock.set_ttl_v4(255)?;
        }
        Ok(())
    } else {
        sock.set_ttl_v4(255)
    }
}

/// Randomized dynamic-port binding. Avoid the peer's listening port so
/// reverse-direction requests cannot be confused with reflected packets.
pub(crate) fn bind_sender(mut local: SocketAddr, remote: SocketAddr) -> io::Result<UdpSocket> {
    if local.port() != 0 {
        if local.port() == remote.port() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "sender local and remote ports must differ",
            ));
        }
        return UdpSocket::bind(local);
    }
    for _ in 0..128 {
        let mut random = [0u8; 2];
        getrandom::fill(&mut random).map_err(io::Error::other)?;
        let port = 49152 + (u16::from_ne_bytes(random) & 0x3fff);
        if port == remote.port() {
            continue;
        }
        local.set_port(port);
        match UdpSocket::bind(local) {
            Ok(socket) => return Ok(socket),
            Err(e) if e.kind() == io::ErrorKind::AddrInUse => continue,
            Err(e) => return Err(e),
        }
    }
    Err(io::Error::new(
        io::ErrorKind::AddrInUse,
        "could not allocate a randomized dynamic STAMP port",
    ))
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    #[test]
    fn dual_stack_hop_policy_covers_ipv4_mapped_traffic() {
        let socket = UdpSocket::bind("[::]:0").unwrap();
        set_hops(&socket).unwrap();
        let sock = socket2::SockRef::from(&socket);
        assert_eq!(sock.unicast_hops_v6().unwrap(), 255);
        if !sock.only_v6().unwrap() {
            assert_eq!(sock.ttl_v4().unwrap(), 255);
        }
    }
}
