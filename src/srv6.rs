//! Best-effort SRv6 return-path forwarding (RFC 9503 §5 + RFC 8754).
//!
//! A userspace UDP Session-Reflector cannot forward over an arbitrary
//! SR-MPLS label stack, but on Linux it *can* ask the kernel to insert an
//! SRv6 Segment Routing Header (IPv6 routing header type 4) on its reply by
//! attaching an `IPV6_RTHDR` ancillary message to a `sendmsg` call.
//!
//! **Defensive contract.** This is opt-in (`--srv6-return-forwarding`) and
//! capability-gated: [`srh_supported`] probes the running kernel once, and the
//! reflector silently falls back to the safe "reply normally + set the Return
//! Path U-flag" behaviour when SRv6 is unavailable (non-Linux, IPv4 reply, no
//! seg6 support, or any send error). It never requires SRv6 and never panics.
//!
//! **Verification boundary.** The SRH byte construction ([`build_srh`]) is
//! pinned by unit tests against RFC 8754. The live kernel send path can only
//! be exercised on an SRv6-capable multi-hop testbed, so it is intentionally
//! gated behind the probe and the opt-in flag.

use std::net::Ipv6Addr;

/// IPv6 Routing Type for the Segment Routing Header (RFC 8754 §2).
pub const SRH_ROUTING_TYPE: u8 = 4;

/// Maximum number of segments we will encode. The SRH `Hdr Ext Len` field is
/// `2 * n` and must fit in a u8, bounding `n` to 127.
pub const MAX_SEGMENTS: usize = 127;

/// Builds an RFC 8754 Segment Routing Header from a return-path segment list.
///
/// `segments` is in path order (the first segment to traverse first), matching
/// the on-wire order of the RFC 9503 SRv6 Segment List sub-TLV. The SRH stores
/// the list in reverse, so `Segment List[0]` is the last segment (final
/// destination) per RFC 8754 §2.
///
/// The `Next Header` octet is left zero: when the buffer is handed to the
/// kernel via an `IPV6_RTHDR` ancillary message the kernel fills it in (the
/// same convention as the RFC 3542 `inet6_rth_*` helpers).
///
/// Returns `None` if the list is empty or longer than [`MAX_SEGMENTS`].
#[must_use]
pub fn build_srh(segments: &[Ipv6Addr]) -> Option<Vec<u8>> {
    let n = segments.len();
    if n == 0 || n > MAX_SEGMENTS {
        return None;
    }
    let last_index = (n - 1) as u8;
    let mut srh = Vec::with_capacity(8 + 16 * n);
    srh.push(0); // Next Header — populated by the kernel on insertion.
    srh.push(2 * last_index + 2); // Hdr Ext Len = (8 + 16n)/8 - 1 = 2n.
    srh.push(SRH_ROUTING_TYPE); // Routing Type = 4 (SRH).
    srh.push(last_index); // Segments Left — index of the first segment to visit.
    srh.push(last_index); // Last Entry — index of the last list element.
    srh.push(0); // Flags.
    srh.extend_from_slice(&0u16.to_be_bytes()); // Tag.
                                                // Segment List in reverse (on-wire) order: index 0 is the final destination.
    for sid in segments.iter().rev() {
        srh.extend_from_slice(&sid.octets());
    }
    Some(srh)
}

/// Returns whether the running kernel accepts an SRv6 SRH via `IPV6_RTHDR`.
///
/// Probed once and cached. On non-Linux platforms this is always `false`.
#[cfg(target_os = "linux")]
#[must_use]
pub fn srh_supported() -> bool {
    use std::sync::OnceLock;
    static SUPPORTED: OnceLock<bool> = OnceLock::new();
    *SUPPORTED.get_or_init(probe_srh_support)
}

/// On non-Linux platforms SRv6 SRH insertion via `IPV6_RTHDR` is unavailable.
#[cfg(not(target_os = "linux"))]
#[must_use]
pub fn srh_supported() -> bool {
    false
}

/// One-shot probe: open a throwaway IPv6 UDP socket and try to set a minimal
/// type-4 SRH via `IPV6_RTHDR`. A kernel without seg6 support rejects the
/// option, in which case we report "unsupported" and never attempt the real
/// send path.
#[cfg(target_os = "linux")]
fn probe_srh_support() -> bool {
    use nix::libc;
    use std::os::fd::{FromRawFd, OwnedFd};

    // SAFETY: socket() returns -1 on error (checked) or a fresh fd we wrap in
    // an OwnedFd so it is closed on drop regardless of the outcome.
    let fd = unsafe { libc::socket(libc::AF_INET6, libc::SOCK_DGRAM, libc::IPPROTO_UDP) };
    if fd < 0 {
        return false;
    }
    let _guard = unsafe { OwnedFd::from_raw_fd(fd) };

    let Some(sample) = build_srh(&[Ipv6Addr::LOCALHOST]) else {
        return false;
    };
    // SAFETY: `sample` lives for the call and its length is passed explicitly.
    let rc = unsafe {
        libc::setsockopt(
            fd,
            libc::IPPROTO_IPV6,
            libc::IPV6_RTHDR,
            sample.as_ptr().cast(),
            sample.len() as libc::socklen_t,
        )
    };
    rc == 0
}

/// Sends `payload` to `dst` with an SRv6 SRH attached as an `IPV6_RTHDR`
/// ancillary message, so the kernel routes the reply through the segment list.
///
/// Best-effort: callers must gate this behind [`srh_supported`] and fall back
/// to a normal reply (with the Return Path U-flag set) on `Err`.
#[cfg(target_os = "linux")]
pub fn send_with_srh(
    fd: std::os::fd::RawFd,
    payload: &[u8],
    dst: std::net::SocketAddrV6,
    srh: &[u8],
) -> std::io::Result<usize> {
    use nix::libc;

    let mut addr: libc::sockaddr_in6 = unsafe { std::mem::zeroed() };
    addr.sin6_family = libc::AF_INET6 as libc::sa_family_t;
    addr.sin6_port = dst.port().to_be();
    addr.sin6_addr.s6_addr = dst.ip().octets();
    addr.sin6_scope_id = dst.scope_id();

    let mut iov = libc::iovec {
        iov_base: payload.as_ptr() as *mut libc::c_void,
        iov_len: payload.len(),
    };

    // Control buffer large enough for one IPV6_RTHDR cmsg carrying the SRH.
    let cmsg_space = unsafe { libc::CMSG_SPACE(srh.len() as libc::c_uint) } as usize;
    let mut cmsg_buf = vec![0u8; cmsg_space];

    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_name = std::ptr::addr_of_mut!(addr).cast();
    msg.msg_namelen = std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t;
    msg.msg_iov = std::ptr::addr_of_mut!(iov);
    msg.msg_iovlen = 1;
    msg.msg_control = cmsg_buf.as_mut_ptr().cast();
    msg.msg_controllen = cmsg_buf.len() as _;

    // SAFETY: msg is fully initialised; CMSG_FIRSTHDR is valid because
    // msg_control/msg_controllen describe a buffer sized via CMSG_SPACE.
    unsafe {
        let cmsg = libc::CMSG_FIRSTHDR(&msg);
        if cmsg.is_null() {
            return Err(std::io::Error::other("CMSG_FIRSTHDR returned null"));
        }
        (*cmsg).cmsg_level = libc::IPPROTO_IPV6;
        (*cmsg).cmsg_type = libc::IPV6_RTHDR;
        (*cmsg).cmsg_len = libc::CMSG_LEN(srh.len() as libc::c_uint) as _;
        std::ptr::copy_nonoverlapping(srh.as_ptr(), libc::CMSG_DATA(cmsg), srh.len());
        msg.msg_controllen = libc::CMSG_SPACE(srh.len() as libc::c_uint) as _;

        let sent = libc::sendmsg(fd, &msg, 0);
        if sent < 0 {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(sent as usize)
        }
    }
}

/// On other Unix platforms (e.g. macOS) SRv6 SRH insertion is unavailable;
/// callers gate on [`srh_supported`] (always `false` here) so this is never
/// reached, but it must exist for the Unix-only `nix` backend to compile.
#[cfg(all(unix, not(target_os = "linux")))]
pub fn send_with_srh(
    _fd: std::os::fd::RawFd,
    _payload: &[u8],
    _dst: std::net::SocketAddrV6,
    _srh: &[u8],
) -> std::io::Result<usize> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "SRv6 SRH insertion is Linux-only",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_srh_single_segment() {
        let sid = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0xaa);
        let srh = build_srh(&[sid]).expect("one segment");
        assert_eq!(srh.len(), 8 + 16, "8-byte header + one 16-byte SID");
        assert_eq!(srh[0], 0, "Next Header left for the kernel");
        assert_eq!(srh[1], 2, "Hdr Ext Len = 2n = 2 for n=1");
        assert_eq!(srh[2], SRH_ROUTING_TYPE, "Routing Type = 4");
        assert_eq!(srh[3], 0, "Segments Left = n-1 = 0");
        assert_eq!(srh[4], 0, "Last Entry = n-1 = 0");
        assert_eq!(srh[5], 0, "Flags = 0");
        assert_eq!(&srh[6..8], &[0, 0], "Tag = 0");
        assert_eq!(&srh[8..24], &sid.octets(), "segment list[0] = the SID");
    }

    #[test]
    fn build_srh_reverses_into_on_wire_order() {
        // Path order: first hop A, then B. On the wire, list[0] is the final
        // destination (B), list[1] is the first hop (A).
        let a = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        let b = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2);
        let srh = build_srh(&[a, b]).expect("two segments");
        assert_eq!(srh.len(), 8 + 32);
        assert_eq!(srh[1], 4, "Hdr Ext Len = 2n = 4 for n=2");
        assert_eq!(srh[3], 1, "Segments Left = n-1 = 1");
        assert_eq!(srh[4], 1, "Last Entry = n-1 = 1");
        assert_eq!(&srh[8..24], &b.octets(), "list[0] = final destination (B)");
        assert_eq!(&srh[24..40], &a.octets(), "list[1] = first hop (A)");
    }

    #[test]
    fn build_srh_rejects_empty_and_oversized() {
        assert_eq!(build_srh(&[]), None);
        let too_many = vec![Ipv6Addr::LOCALHOST; MAX_SEGMENTS + 1];
        assert_eq!(build_srh(&too_many), None);
    }

    #[test]
    fn build_srh_length_is_eight_plus_sixteen_n() {
        for n in 1..=8usize {
            let segs = vec![Ipv6Addr::LOCALHOST; n];
            let srh = build_srh(&segs).unwrap();
            assert_eq!(srh.len(), 8 + 16 * n);
            assert_eq!(srh[1] as usize, 2 * n, "Hdr Ext Len must equal 2n");
        }
    }
}
