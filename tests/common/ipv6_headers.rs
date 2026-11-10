//! Linux ancillary header capture for independent UDP peers.
use std::os::fd::AsRawFd;
pub type Values = Vec<(u8, Vec<u8>)>;

pub fn enable_capture(peer: &tokio::net::UdpSocket) {
    for option in [libc::IPV6_RECVHOPOPTS, libc::IPV6_RECVDSTOPTS] {
        let on: libc::c_int = 1;
        // SAFETY: the live socket and aligned option value outlive this call.
        assert_eq!(
            unsafe {
                libc::setsockopt(
                    peer.as_raw_fd(),
                    libc::IPPROTO_IPV6,
                    option,
                    std::ptr::addr_of!(on).cast(),
                    std::mem::size_of_val(&on) as _,
                )
            },
            0,
            "header capture: {}",
            std::io::Error::last_os_error()
        );
    }
}

pub fn receive(peer: &tokio::net::UdpSocket) -> std::io::Result<(Vec<u8>, Values)> {
    let mut bytes = [0; 2048];
    let mut control = [0usize; 128]; // Aligned for cmsghdr.
    let mut iov = libc::iovec {
        iov_base: bytes.as_mut_ptr().cast(),
        iov_len: bytes.len(),
    };
    // SAFETY: zeroed msghdr has valid null pointers and zero lengths.
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control.as_mut_ptr().cast();
    msg.msg_controllen = std::mem::size_of_val(&control);
    // SAFETY: all writable buffers stay live, and their exact sizes are passed.
    let len = unsafe { libc::recvmsg(peer.as_raw_fd(), &mut msg, 0) };
    if len < 0 {
        return Err(std::io::Error::last_os_error());
    }
    assert_eq!(msg.msg_flags & (libc::MSG_TRUNC | libc::MSG_CTRUNC), 0);
    let mut headers = Vec::new();
    // SAFETY: recvmsg filled the aligned buffer and its returned length bounds
    // CMSG iteration. Every slice is bounded by the returned cmsg length.
    unsafe {
        let mut header = libc::CMSG_FIRSTHDR(&msg);
        while !header.is_null() {
            let kind = match ((*header).cmsg_level, (*header).cmsg_type) {
                (libc::IPPROTO_IPV6, libc::IPV6_HOPOPTS) => Some(0),
                (libc::IPPROTO_IPV6, libc::IPV6_DSTOPTS) => Some(60),
                _ => None,
            };
            if let Some(kind) = kind {
                let len = (*header).cmsg_len - libc::CMSG_LEN(0) as usize;
                headers.push((
                    kind,
                    std::slice::from_raw_parts(libc::CMSG_DATA(header), len).to_vec(),
                ));
            }
            header = libc::CMSG_NXTHDR(&msg, header);
        }
    }
    Ok((bytes[..len as usize].to_vec(), headers))
}
