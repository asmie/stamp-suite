//! SRv6 return paths (RFC 9503 §4, RFC 8754), enabled by
//! `--srv6-return-forwarding` when `srh_supported` permits them.
//! Linux uses sticky IPV6_RTHDR because ancillary parsing rejects type 4.
//! DatagramSender owns and clears the option. Unsupported routes or failed
//! sends can fall back to ordinary replies with Return Path U set.
//! Unit tests check encoding; namespace tests check forwarding, signed
//! replies and cleanup before later ordinary replies.

use std::net::Ipv6Addr;

/// IPv6 Routing Type for the Segment Routing Header (RFC 8754 §2).
pub const SRH_ROUTING_TYPE: u8 = 4;

/// Maximum number of segments we will encode. The SRH `Hdr Ext Len` field is
/// `2 * n` and must fit in a u8, bounding `n` to 127.
pub const MAX_SEGMENTS: usize = 127;

/// Builds an RFC 8754 SRH from segments in traversal order.
///
/// Reverses the RFC 9503 segment list so `Segment List[0]` is the final
/// destination (RFC 8754 §2). Leaves Next Header zero for the kernel to fill.
/// Returns `None` for an empty list or more than [`MAX_SEGMENTS`] entries.
#[must_use]
pub fn build_srh(segments: &[Ipv6Addr]) -> Option<Vec<u8>> {
    let n = segments.len();
    if n == 0 || n > MAX_SEGMENTS {
        return None;
    }
    let last_index = (n - 1) as u8;
    let mut srh = Vec::with_capacity(8 + 16 * n);
    srh.push(0); // Next Header: populated by the kernel on insertion.
    srh.push(2 * last_index + 2); // Hdr Ext Len = (8 + 16n)/8 - 1 = 2n.
    srh.push(SRH_ROUTING_TYPE); // Routing Type = 4 (SRH).
    srh.push(last_index); // Segments Left: index of the first segment to visit.
    srh.push(last_index); // Last Entry: index of the last list element.
    srh.push(0); // Flags.
    srh.extend_from_slice(&0u16.to_be_bytes()); // Tag.
    for sid in segments.iter().rev() {
        // Segment List in reverse (on-wire) order: index 0 is the final destination.
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

/// Opens a throwaway IPv6 UDP socket and tries to set a minimal type-4 SRH
/// via `IPV6_RTHDR`.
///
/// A kernel without seg6 support rejects the option, so the probe reports
/// "unsupported" and the real send path is never attempted.
#[cfg(target_os = "linux")]
fn probe_srh_support() -> bool {
    use nix::libc;
    use std::os::fd::{FromRawFd, OwnedFd};

    // SAFETY: socket() takes only integer arguments and returns -1 on error,
    // which is checked before the result is used.
    let fd = unsafe { libc::socket(libc::AF_INET6, libc::SOCK_DGRAM, libc::IPPROTO_UDP) };
    if fd < 0 {
        return false;
    }
    // SAFETY: `fd` is non-negative, freshly returned by socket() and owned by
    // nothing else, so the OwnedFd is its sole owner and closes it on drop.
    let _guard = unsafe { OwnedFd::from_raw_fd(fd) };

    let Some(sample) = build_srh(&[Ipv6Addr::LOCALHOST]) else {
        return false;
    };
    // SAFETY: `fd` stays open while `_guard` lives. `sample` is an initialized
    // buffer that outlives the call, and its exact length is passed, so the
    // kernel reads only those bytes.
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
