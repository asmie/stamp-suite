//! Winsock path-MTU discovery options shared by the sender and reflector.

use std::{io, net::IpAddr, os::windows::io::RawSocket};

use windows_sys::Win32::Networking::WinSock::{
    setsockopt, WSAGetLastError, IPPROTO_IP, IPPROTO_IPV6, IPV6_MTU_DISCOVER, IP_MTU_DISCOVER,
};

/// Native IPv6 traffic. An IPv4-mapped peer on a dual-stack socket uses the
/// IPv4 socket options.
pub(crate) fn native_ipv6(ip: IpAddr) -> bool {
    matches!(ip, IpAddr::V6(ip) if ip.to_ipv4_mapped().is_none())
}

/// Sets `IP_MTU_DISCOVER` or `IPV6_MTU_DISCOVER`, whichever applies to traffic
/// to `peer`, to `state` (an `IP_PMTUDISC_*` value). Only this socket changes.
pub(crate) fn set_mtu_discover(socket: RawSocket, peer: IpAddr, state: i32) -> io::Result<()> {
    let (level, option) = if native_ipv6(peer) {
        (IPPROTO_IPV6, IPV6_MTU_DISCOVER)
    } else {
        (IPPROTO_IP, IP_MTU_DISCOVER)
    };
    // SAFETY: the caller's socket owns the live handle; `state` outlives the
    // call, and its exact four-byte DWORD size is passed to Winsock.
    let result = unsafe {
        setsockopt(
            socket as _,
            level,
            option,
            std::ptr::addr_of!(state).cast(),
            std::mem::size_of_val(&state) as i32,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        // SAFETY: WSAGetLastError has no preconditions; read it immediately
        // after the failed Winsock call rather than Win32 GetLastError.
        Err(io::Error::from_raw_os_error(unsafe { WSAGetLastError() }))
    }
}
