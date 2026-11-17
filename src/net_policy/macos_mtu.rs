//! Connected native IPv6 MTU estimates from Darwin. No active path probing.

use std::{
    io,
    net::IpAddr,
    os::fd::{AsFd, AsRawFd, RawFd},
};

use nix::libc;

// Darwin RFC 3542 ABI, missing from libc's Apple bindings:
// https://github.com/apple-oss-distributions/xnu/blob/main/bsd/netinet6/in6.h
pub(crate) const IPV6_USE_MIN_MTU: libc::c_int = 42;
const IPV6_PATHMTU: libc::c_int = 44;

#[repr(C)]
struct MtuInfo {
    address: libc::sockaddr_in6,
    mtu: u32,
}

pub(crate) fn native_unicast(ip: IpAddr) -> bool {
    matches!(ip, IpAddr::V6(ip) if ip.to_ipv4_mapped().is_none() && !ip.is_multicast())
}

fn read_int(socket: &socket2::Socket, option: libc::c_int) -> Option<libc::c_int> {
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
pub(crate) fn egress_mtu(socket: &impl AsFd) -> Option<u32> {
    let socket = socket2::SockRef::from(socket);
    let peer = socket.peer_addr().ok()?.as_socket()?;
    if !native_unicast(peer.ip()) || read_int(&socket, libc::IPV6_BOUND_IF)? != 0 {
        return None;
    }
    let minimum = read_int(&socket, IPV6_USE_MIN_MTU)?;
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
pub(crate) fn enable_mtu_discovery(socket: &impl AsFd, peer: IpAddr) -> io::Result<()> {
    if !native_unicast(peer) {
        return Ok(());
    }
    set_ipv6_dont_fragment(socket.as_fd().as_raw_fd(), true)
}

/// Sets `IPV6_DONTFRAG` on the socket `fd`. Only this socket changes.
pub(crate) fn set_ipv6_dont_fragment(fd: RawFd, enabled: bool) -> io::Result<()> {
    let enabled = libc::c_int::from(enabled);
    // SAFETY: the caller keeps `fd` open for this synchronous call, and the
    // correctly sized integer stays live while the kernel reads it.
    let result = unsafe {
        libc::setsockopt(
            fd,
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
