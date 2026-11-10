//! Independent IPv4 TTL / IPv6 Hop Limit receive metadata on Linux and macOS.
use nix::libc;
use std::{net::UdpSocket, os::fd::AsRawFd, time::Duration};

pub fn socket(ip: &str) -> UdpSocket {
    let socket = UdpSocket::bind((ip, 0)).unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    let (level, option) = if ip.contains(':') {
        (libc::IPPROTO_IPV6, libc::IPV6_RECVHOPLIMIT)
    } else {
        (libc::IPPROTO_IP, libc::IP_RECVTTL)
    };
    let on: libc::c_int = 1;
    assert_eq!(
        // SAFETY: the fd belongs to `socket`, which outlives the call, and the
        // option value points to a live, aligned c_int whose size is passed.
        unsafe {
            libc::setsockopt(
                socket.as_raw_fd(),
                level,
                option,
                std::ptr::addr_of!(on).cast(),
                std::mem::size_of_val(&on) as _,
            )
        },
        0
    );
    socket
}
pub fn receive(socket: &UdpSocket) -> (Vec<u8>, std::net::SocketAddr, i32) {
    // This socket has one receiver; peek obtains the peer without consuming
    // the datagram whose ancillary hop metadata is inspected below.
    let (_, peer) = socket.peek_from(&mut [0u8; 1]).unwrap();
    let mut bytes = [0u8; 4096];
    let mut iov = libc::iovec {
        iov_base: bytes.as_mut_ptr().cast(),
        iov_len: bytes.len(),
    };
    // usize provides cmsghdr alignment on both Darwin and Linux.
    let mut control = [0usize; 16];
    // SAFETY: msghdr is a plain C struct; all-zero (null pointers, zero
    // lengths) is a valid value, and every pointer used is set below.
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control.as_mut_ptr().cast();
    msg.msg_controllen = std::mem::size_of_val(&control) as _;
    // SAFETY: `msg` points to `iov` and `control`, which stay live and writable
    // for the call, with lengths that match their buffers; the fd is owned by
    // `socket`.
    let len = unsafe { libc::recvmsg(socket.as_raw_fd(), &mut msg, 0) };
    assert!(len >= 0, "recvmsg: {}", std::io::Error::last_os_error());
    assert_eq!(msg.msg_flags & (libc::MSG_TRUNC | libc::MSG_CTRUNC), 0);
    let mut hops = None;
    // SAFETY: recvmsg filled `control` (usize-aligned) and set msg_controllen,
    // so CMSG_FIRSTHDR/CMSG_NXTHDR only yield headers inside it or null. Each
    // payload length is checked before it is read, and multi-byte reads are
    // unaligned.
    unsafe {
        let mut header = libc::CMSG_FIRSTHDR(&msg);
        while !header.is_null() {
            let data_len = (*header).cmsg_len as usize - libc::CMSG_LEN(0) as usize;
            match ((*header).cmsg_level, (*header).cmsg_type) {
                #[cfg(target_os = "linux")]
                (libc::IPPROTO_IP, libc::IP_TTL) => {
                    assert_eq!(data_len, std::mem::size_of::<libc::c_int>());
                    hops = Some(std::ptr::read_unaligned(
                        libc::CMSG_DATA(header).cast::<libc::c_int>(),
                    ));
                }
                #[cfg(target_os = "macos")]
                (libc::IPPROTO_IP, libc::IP_RECVTTL) => {
                    assert_eq!(data_len, 1);
                    hops = Some(i32::from(*libc::CMSG_DATA(header)));
                }
                (libc::IPPROTO_IPV6, libc::IPV6_HOPLIMIT) => {
                    assert_eq!(data_len, std::mem::size_of::<libc::c_int>());
                    hops = Some(std::ptr::read_unaligned(
                        libc::CMSG_DATA(header).cast::<libc::c_int>(),
                    ));
                }
                _ => {}
            }
            header = libc::CMSG_NXTHDR(&msg, header);
        }
    }
    (
        bytes[..len as usize].to_vec(),
        peer,
        hops.expect("received hop metadata"),
    )
}
