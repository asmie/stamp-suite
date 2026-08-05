//! Pinning a reflected packet's IP source address (RFC 9503 §3).
//!
//! When a Destination Node Address TLV matches one of the reflector's own
//! addresses, RFC 9503 §3 says that address "SHOULD be used as the Source
//! Address in the IP header of the reply test packet".
//!
//! Leaving source selection to the OS satisfies this only by coincidence. On a
//! single-address bind the kernel picks the same address anyway; on the
//! wildcard or multi-homed bind that §2 actually motivates — a tunnel-decap
//! address that is not suitable as a routable source — the kernel picks by
//! route, not by what the sender asked for. Forcing it takes a per-packet
//! ancillary message.
//!
//! Linux-only, and best-effort by this project's convention for anything
//! platform-dependent: [`supported`] is `false` elsewhere, and a caller that
//! tries anyway gets an error to fall back on rather than a dropped reply. A
//! reply sent from the kernel's choice of source is still a correct STAMP
//! reply; the SHOULD is about which of several correct answers is preferred.

// Only the `send_from` signatures need these, and that function exists on Unix
// only — see its Windows note below.
#[cfg(unix)]
use std::net::{IpAddr, SocketAddr};

/// Whether this build can pin a reply's source address.
///
/// `IP_PKTINFO`/`IPV6_PKTINFO` as *outgoing* ancillary data is a Linux
/// interface. Darwin has no equivalent that sets the source of an individual
/// datagram on an unconnected socket, so callers there keep the kernel's choice.
#[must_use]
pub const fn supported() -> bool {
    cfg!(target_os = "linux")
}

/// Sends `payload` to `dst` with the IP source address forced to `src`.
///
/// The address families of `src` and `dst` must agree — a socket cannot emit an
/// IPv4 datagram from an IPv6 source — and a mismatch is reported rather than
/// silently ignored, because silently sending from the wrong source is exactly
/// the outcome this function exists to prevent.
///
/// # Errors
/// Returns the OS error from `sendmsg`, or `InvalidInput` on a family mismatch.
/// Callers fall back to an ordinary send.
#[cfg(target_os = "linux")]
pub fn send_from(
    fd: std::os::fd::RawFd,
    payload: &[u8],
    dst: SocketAddr,
    src: IpAddr,
) -> std::io::Result<usize> {
    use nix::libc;

    if dst.is_ipv4() != src.is_ipv4() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "reply source address family does not match the destination",
        ));
    }

    let mut iov = libc::iovec {
        iov_base: payload.as_ptr() as *mut libc::c_void,
        iov_len: payload.len(),
    };
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = std::ptr::addr_of_mut!(iov);
    msg.msg_iovlen = 1;

    // Destination sockaddr, kept alive for the whole call by these bindings.
    let mut addr4: libc::sockaddr_in = unsafe { std::mem::zeroed() };
    let mut addr6: libc::sockaddr_in6 = unsafe { std::mem::zeroed() };
    match dst {
        SocketAddr::V4(v4) => {
            addr4.sin_family = libc::AF_INET as libc::sa_family_t;
            addr4.sin_port = v4.port().to_be();
            addr4.sin_addr.s_addr = u32::from_ne_bytes(v4.ip().octets());
            msg.msg_name = std::ptr::addr_of_mut!(addr4).cast();
            msg.msg_namelen = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
        }
        SocketAddr::V6(v6) => {
            addr6.sin6_family = libc::AF_INET6 as libc::sa_family_t;
            addr6.sin6_port = v6.port().to_be();
            addr6.sin6_addr.s6_addr = v6.ip().octets();
            addr6.sin6_scope_id = v6.scope_id();
            msg.msg_name = std::ptr::addr_of_mut!(addr6).cast();
            msg.msg_namelen = std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t;
        }
    }

    // One ancillary message carrying the pktinfo for the relevant family.
    let data_len = match src {
        IpAddr::V4(_) => std::mem::size_of::<libc::in_pktinfo>(),
        IpAddr::V6(_) => std::mem::size_of::<libc::in6_pktinfo>(),
    };
    let cmsg_space = unsafe { libc::CMSG_SPACE(data_len as libc::c_uint) } as usize;
    let mut cmsg_buf = vec![0u8; cmsg_space];
    msg.msg_control = cmsg_buf.as_mut_ptr().cast();
    msg.msg_controllen = cmsg_buf.len() as _;

    // SAFETY: `msg` is fully initialised and `msg_control`/`msg_controllen`
    // describe a buffer sized with CMSG_SPACE for exactly one message of
    // `data_len` bytes, so CMSG_FIRSTHDR and the copy below stay in bounds.
    unsafe {
        let cmsg = libc::CMSG_FIRSTHDR(&msg);
        if cmsg.is_null() {
            return Err(std::io::Error::other("CMSG_FIRSTHDR returned null"));
        }
        match src {
            IpAddr::V4(v4) => {
                (*cmsg).cmsg_level = libc::IPPROTO_IP;
                (*cmsg).cmsg_type = libc::IP_PKTINFO;
                (*cmsg).cmsg_len = libc::CMSG_LEN(data_len as libc::c_uint) as _;
                let mut info: libc::in_pktinfo = std::mem::zeroed();
                // `ipi_spec_dst` is the *source* address of an outgoing packet
                // (it names the local end); `ipi_addr` is left zero so the
                // kernel keeps choosing the route. Interface 0 means "decide
                // from the route", which is what we want: only the source
                // address is being overridden.
                info.ipi_spec_dst.s_addr = u32::from_ne_bytes(v4.octets());
                std::ptr::copy_nonoverlapping(
                    std::ptr::addr_of!(info).cast::<u8>(),
                    libc::CMSG_DATA(cmsg),
                    data_len,
                );
            }
            IpAddr::V6(v6) => {
                (*cmsg).cmsg_level = libc::IPPROTO_IPV6;
                (*cmsg).cmsg_type = libc::IPV6_PKTINFO;
                (*cmsg).cmsg_len = libc::CMSG_LEN(data_len as libc::c_uint) as _;
                let mut info: libc::in6_pktinfo = std::mem::zeroed();
                info.ipi6_addr.s6_addr = v6.octets();
                std::ptr::copy_nonoverlapping(
                    std::ptr::addr_of!(info).cast::<u8>(),
                    libc::CMSG_DATA(cmsg),
                    data_len,
                );
            }
        }
        msg.msg_controllen = cmsg_space as _;

        let sent = libc::sendmsg(fd, &msg, 0);
        if sent < 0 {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(sent as usize)
        }
    }
}

/// Source pinning is Linux-only; callers gate on [`supported`] and fall back to
/// an ordinary send. This stub exists so the other Unix platforms still compile.
///
/// Gated to Unix, not merely to "not Linux": `std::os::fd::RawFd` does not exist
/// on Windows, so a `not(target_os = "linux")` stub fails to compile there. On
/// Windows this function is absent entirely and callers reach it only from
/// inside their own `cfg(unix)` blocks — the same arrangement
/// [`crate::srv6::send_with_srh`] uses.
#[cfg(all(unix, not(target_os = "linux")))]
pub fn send_from(
    _fd: std::os::fd::RawFd,
    _payload: &[u8],
    _dst: SocketAddr,
    _src: IpAddr,
) -> std::io::Result<usize> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "reply source-address pinning is Linux-only",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn supported_matches_the_platform() {
        assert_eq!(supported(), cfg!(target_os = "linux"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn send_from_rejects_a_family_mismatch() {
        use std::os::fd::AsRawFd;

        let sock = std::net::UdpSocket::bind(("127.0.0.1", 0)).unwrap();
        let dst: SocketAddr = "127.0.0.1:9".parse().unwrap();
        let v6_src: IpAddr = "::1".parse().unwrap();
        let err = send_from(sock.as_raw_fd(), b"x", dst, v6_src)
            .expect_err("an IPv6 source with an IPv4 destination must be refused");
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn send_from_delivers_with_the_pinned_source() {
        use std::os::fd::AsRawFd;

        // Both ends on loopback, so 127.0.0.1 is a legitimate source to pin
        // and the datagram can actually be observed arriving.
        let receiver = std::net::UdpSocket::bind(("127.0.0.1", 0)).unwrap();
        let dst = receiver.local_addr().unwrap();
        let sender = std::net::UdpSocket::bind(("0.0.0.0", 0)).unwrap();

        let pinned: IpAddr = "127.0.0.1".parse().unwrap();
        let sent = send_from(sender.as_raw_fd(), b"stamp", dst, pinned)
            .expect("pinned send must succeed on loopback");
        assert_eq!(sent, 5);

        receiver
            .set_read_timeout(Some(std::time::Duration::from_secs(2)))
            .unwrap();
        let mut buf = [0u8; 16];
        let (len, from) = receiver.recv_from(&mut buf).expect("datagram must arrive");
        assert_eq!(&buf[..len], b"stamp");
        assert_eq!(
            from.ip(),
            pinned,
            "the receiver must see the pinned source address"
        );
    }
}
