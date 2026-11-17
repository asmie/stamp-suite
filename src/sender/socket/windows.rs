//! Connected-socket MTU estimates from Winsock. No active path probing.

use std::{io, net::IpAddr, os::windows::io::AsRawSocket};

use tokio::net::UdpSocket;
use windows_sys::Win32::Networking::WinSock::{
    getsockopt, IPPROTO_IP, IPPROTO_IPV6, IPV6_MTU, IPV6_USER_MTU, IP_MTU, IP_PMTUDISC_DO,
    IP_USER_MTU,
};

use crate::net_policy::windows_mtu::{native_ipv6, set_mtu_discover};

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
    let (level, option, cap) = if native_ipv6(socket.peer_addr().ok()?.ip()) {
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
    set_mtu_discover(socket.as_raw_socket(), peer, IP_PMTUDISC_DO)
}
