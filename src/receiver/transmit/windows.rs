use std::{
    io,
    net::{SocketAddr, UdpSocket},
    os::windows::io::AsRawSocket,
};

use windows_sys::Win32::Networking::WinSock::{IP_PMTUDISC_DO, IP_PMTUDISC_NOT_SET};

use crate::net_policy::windows_mtu::{native_ipv6, set_mtu_discover};

pub(super) fn apply_fragmentation_policy(
    socket: &UdpSocket,
    target: SocketAddr,
    dont_fragment: bool,
    settings: &mut [Option<i32>; 2],
) -> io::Result<()> {
    let value = if dont_fragment {
        IP_PMTUDISC_DO
    } else {
        IP_PMTUDISC_NOT_SET
    };
    // The exclusive DatagramSender owns all option changes and sends. Restore
    // the default policy for ordinary replies after a size-controlled one.
    let family = usize::from(native_ipv6(target.ip()));
    super::datagram::update_socket_option(&mut settings[family], value, || {
        set_mtu_discover(socket.as_raw_socket(), target.ip(), value)
    })
}
