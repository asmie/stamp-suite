//! Connected-socket MTU estimates from Winsock. No active path probing.

use std::{io, net::IpAddr, os::windows::io::AsRawSocket};

use tokio::net::UdpSocket;
use windows_sys::Win32::Networking::WinSock::{
    getsockopt, setsockopt, WSAGetLastError, IPPROTO_IP, IPPROTO_IPV6, IPV6_MTU, IPV6_MTU_DISCOVER,
    IPV6_USER_MTU, IP_MTU, IP_MTU_DISCOVER, IP_PMTUDISC_DO, IP_USER_MTU,
};

fn is_ipv6(ip: IpAddr) -> bool {
    matches!(ip, IpAddr::V6(ip) if ip.to_ipv4_mapped().is_none())
}

fn read_dword(socket: &UdpSocket, level: i32, option: i32) -> Option<u32> {
    let mut value = 0u32;
    let size = std::mem::size_of_val(&value) as i32;
    let mut len = size;
    // SAFETY: socket owns the live handle, and value/len are aligned locals
    // with exactly the DWORD buffer size required by these Winsock options.
    let result = unsafe {
        getsockopt(
            socket.as_raw_socket() as _,
            level,
            option,
            std::ptr::addr_of_mut!(value).cast(),
            &mut len,
        )
    };
    (result == 0 && len == size).then_some(value)
}

/// Return the connected peer's kernel MTU estimate, bounded by any socket-local
/// user MTU. Missing options or an unknown/zero budget fail closed. This is not
/// proof of the end-to-end path MTU; the kernel may not have discovered it yet.
pub(in crate::sender) fn egress_mtu(socket: &UdpSocket) -> Option<u32> {
    let (level, option, cap) = if is_ipv6(socket.peer_addr().ok()?.ip()) {
        (IPPROTO_IPV6, IPV6_MTU, IPV6_USER_MTU)
    } else {
        (IPPROTO_IP, IP_MTU, IP_USER_MTU)
    };
    let mtu = read_dword(socket, level, option)?.min(read_dword(socket, level, cap)?);
    (mtu > 0).then_some(mtu)
}

/// Reject oversize datagrams instead of fragmenting when the route changes
/// between the budget query and send. Only the caller's socket is affected.
pub(in crate::sender) fn enable_mtu_discovery(socket: &UdpSocket, peer: IpAddr) -> io::Result<()> {
    let (level, option) = if is_ipv6(peer) {
        (IPPROTO_IPV6, IPV6_MTU_DISCOVER)
    } else {
        (IPPROTO_IP, IP_MTU_DISCOVER)
    };
    let value = IP_PMTUDISC_DO as u32;
    // SAFETY: socket owns the live handle; value remains live for the call,
    // and its exact DWORD size is passed to Winsock.
    let result = unsafe {
        setsockopt(
            socket.as_raw_socket() as _,
            level,
            option,
            std::ptr::addr_of!(value).cast(),
            std::mem::size_of_val(&value) as i32,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        // SAFETY: WSAGetLastError has no preconditions; read immediately after
        // the failed Winsock call rather than consulting Win32 GetLastError.
        Err(io::Error::from_raw_os_error(unsafe { WSAGetLastError() }))
    }
}
