//! Connected native IPv6 MTU estimates from Darwin. No active path probing.

use std::{io, net::IpAddr, os::fd::AsRawFd};

use nix::libc;
use tokio::net::UdpSocket;

// Darwin RFC 3542 ABI, missing from libc's Apple bindings:
// https://github.com/apple-oss-distributions/xnu/blob/main/bsd/netinet6/in6.h
pub(in crate::sender) const IPV6_USE_MIN_MTU: libc::c_int = 42;
const IPV6_PATHMTU: libc::c_int = 44;

#[repr(C)]
struct MtuInfo {
    address: libc::sockaddr_in6,
    mtu: u32,
}

fn native_unicast(ip: IpAddr) -> bool {
    matches!(ip, IpAddr::V6(ip) if ip.to_ipv4_mapped().is_none() && !ip.is_multicast())
}

fn read_int(socket: &UdpSocket, option: libc::c_int) -> Option<libc::c_int> {
    let mut value: libc::c_int = 0;
    let size = std::mem::size_of_val(&value) as libc::socklen_t;
    let mut len = size;
    // SAFETY: The socket owns the live descriptor, and value/len are aligned
    // writable locals with the exact buffer size passed to the kernel.
    let result = unsafe {
        libc::getsockopt(
            socket.as_raw_fd(),
            libc::IPPROTO_IPV6,
            option,
            std::ptr::addr_of_mut!(value).cast(),
            &mut len,
        )
    };
    (result == 0 && len == size).then_some(value)
}

/// Read the connected peer's kernel estimate on every call. Darwin's PATHMTU
/// query does not cover all egress overrides, so explicitly pinned interfaces
/// are unavailable here. Its returned address is zero, not a peer identity.
pub(in crate::sender) fn egress_mtu(socket: &UdpSocket) -> Option<u32> {
    if !native_unicast(socket.peer_addr().ok()?.ip()) || read_int(socket, libc::IPV6_BOUND_IF)? != 0
    {
        return None;
    }
    let minimum = read_int(socket, IPV6_USE_MIN_MTU)?;
    if !matches!(minimum, -1..=1) {
        return None;
    }
    // SAFETY: Both fields are plain integer-based C structures, valid at zero.
    let mut info: MtuInfo = unsafe { std::mem::zeroed() };
    let size = std::mem::size_of_val(&info) as libc::socklen_t;
    let mut len = size;
    // SAFETY: MtuInfo matches Darwin's ip6_mtuinfo ABI; the buffer and length
    // are live, aligned, and exactly sized for the synchronous kernel write.
    let result = unsafe {
        libc::getsockopt(
            socket.as_raw_fd(),
            libc::IPPROTO_IPV6,
            IPV6_PATHMTU,
            std::ptr::addr_of_mut!(info).cast(),
            &mut len,
        )
    };
    if result != 0 || len != size || info.mtu == 0 {
        return None;
    }
    Some(if minimum == 1 {
        info.mtu.min(1280)
    } else {
        info.mtu
    })
}

/// Prevent fragmentation for the IPv6 profile supported by this adapter.
/// Other address families retain their existing unsupported-MTU behavior.
pub(in crate::sender) fn enable_mtu_discovery(socket: &UdpSocket, peer: IpAddr) -> io::Result<()> {
    if !native_unicast(peer) {
        return Ok(());
    }
    let enabled: libc::c_int = 1;
    // SAFETY: The socket and correctly sized integer remain live for this
    // synchronous call, which changes only this socket's fragmentation policy.
    let result = unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            libc::IPPROTO_IPV6,
            libc::IPV6_DONTFRAG,
            std::ptr::addr_of!(enabled).cast(),
            std::mem::size_of_val(&enabled) as libc::socklen_t,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}
