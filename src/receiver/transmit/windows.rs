use std::{
    io,
    net::{SocketAddr, UdpSocket},
    os::windows::io::AsRawSocket,
};
use windows_sys::Win32::Networking::WinSock::{
    setsockopt, WSAGetLastError, IPPROTO_IP, IPPROTO_IPV6, IPV6_MTU_DISCOVER, IP_MTU_DISCOVER,
    IP_PMTUDISC_DO, IP_PMTUDISC_NOT_SET,
};

pub(super) fn apply_fragmentation_policy(
    socket: &UdpSocket,
    target: SocketAddr,
    dont_fragment: bool,
    settings: &mut [Option<i32>; 2],
) -> io::Result<()> {
    // Mapped destinations use IPv4 options on a dual-stack socket.
    let ipv6 = matches!(target.ip(), std::net::IpAddr::V6(ip) if ip.to_ipv4_mapped().is_none());
    let (level, option) = if ipv6 {
        (IPPROTO_IPV6, IPV6_MTU_DISCOVER)
    } else {
        (IPPROTO_IP, IP_MTU_DISCOVER)
    };
    let value = if dont_fragment {
        IP_PMTUDISC_DO
    } else {
        IP_PMTUDISC_NOT_SET
    };
    // The exclusive DatagramSender owns all option changes and sends. Restore
    // the default policy for ordinary replies after a size-controlled one.
    super::update_socket_option(&mut settings[usize::from(ipv6)], value, || {
        // SAFETY: socket owns the live handle and value outlives the syscall;
        // Winsock receives the exact four-byte option buffer size.
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
            // SAFETY: no preconditions; query immediately after failed Winsock call.
            Err(io::Error::from_raw_os_error(unsafe { WSAGetLastError() }))
        }
    })
}
