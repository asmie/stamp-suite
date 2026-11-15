use super::enable_zero_udp_checksum;
use nix::libc;
use std::{net::UdpSocket, os::fd::AsRawFd};

fn no_check(socket: &UdpSocket) -> i32 {
    let mut value: libc::c_int = -1;
    let mut size = std::mem::size_of_val(&value) as libc::socklen_t;
    // SAFETY: the socket descriptor is owned and both output pointers are
    // aligned, live locals with the exact buffer length supplied.
    let result = unsafe {
        libc::getsockopt(
            socket.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_NO_CHECK,
            std::ptr::addr_of_mut!(value).cast(),
            &mut size,
        )
    };
    assert_eq!(result, 0, "{}", std::io::Error::last_os_error());
    assert_eq!(size as usize, std::mem::size_of_val(&value));
    value
}

#[test]
fn zero_udp_checksum_is_disabled_by_default_and_explicitly_enabled() {
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    assert_eq!(no_check(&socket), 0);
    enable_zero_udp_checksum(&socket).unwrap();
    assert_eq!(no_check(&socket), 1);
}

#[test]
fn zero_udp_checksum_rejects_ipv6_before_changing_socket_options() {
    let socket = UdpSocket::bind("[::1]:0").unwrap();
    let error = enable_zero_udp_checksum(&socket).unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
    assert_eq!(no_check(&socket), 0);
}
