//! Sender socket options: egress IP options, attached IPv6 extension headers,
//! route MTU, and reply TOS reception.

#[cfg(not(target_os = "windows"))]
use super::*;

#[cfg(all(test, target_os = "linux"))]
mod tests;

#[cfg(target_os = "windows")]
mod windows;
#[cfg(target_os = "windows")]
pub(super) use windows::{egress_mtu, enable_mtu_discovery};

/// Disable IPv4 UDP TX checksums only. Kernel receive validation is unchanged.
#[cfg(target_os = "linux")]
pub(super) fn enable_zero_udp_checksum(socket: &std::net::UdpSocket) -> std::io::Result<()> {
    use nix::libc;
    use std::os::fd::AsRawFd;

    if !socket.local_addr()?.is_ipv4() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "zero UDP checksum requires an IPv4 socket",
        ));
    }
    let enabled: libc::c_int = 1;
    // SAFETY: socket owns this open descriptor; enabled is aligned and live
    // throughout the call, and its exact size is supplied to the kernel.
    let result = unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_NO_CHECK,
            std::ptr::addr_of!(enabled).cast(),
            std::mem::size_of_val(&enabled) as libc::socklen_t,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

#[cfg(not(target_os = "linux"))]
pub(super) fn enable_zero_udp_checksum(_socket: &std::net::UdpSocket) -> std::io::Result<()> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "zero UDP checksum transmission is supported only on Linux",
    ))
}

/// Applies the egress IP header options to the socket `fd`.
///
/// DSCP/ECN is packed into the TOS / IPv6 Traffic Class octet so the *wire*
/// IP header matches what the Class of Service TLV advertises (RFC 8972
/// §4.4); `ttl` sets the TTL / Hop Limit. Each option is independently
/// optional; `None` leaves the kernel default untouched.
///
/// Only available on Linux/macOS, where `nix` (and thus `libc`) is guaranteed.
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(super) fn apply_egress_ip_options(
    fd: std::os::fd::RawFd,
    is_ipv6: bool,
    tos: Option<u8>,
    ttl: Option<u8>,
) -> std::io::Result<()> {
    use nix::libc;

    let set_int =
        |level: libc::c_int, name: libc::c_int, value: libc::c_int| -> std::io::Result<()> {
            // SAFETY: `fd` is an open socket owned by the caller for the
            // duration of the call; `value` is a live, aligned c_int and its
            // exact size is passed, so `setsockopt` reads only those bytes.
            let rc = unsafe {
                libc::setsockopt(
                    fd,
                    level,
                    name,
                    std::ptr::addr_of!(value).cast(),
                    std::mem::size_of::<libc::c_int>() as libc::socklen_t,
                )
            };
            if rc < 0 {
                Err(std::io::Error::last_os_error())
            } else {
                Ok(())
            }
        };

    if let Some(tos) = tos {
        let (level, name) = if is_ipv6 {
            (libc::IPPROTO_IPV6, libc::IPV6_TCLASS)
        } else {
            (libc::IPPROTO_IP, libc::IP_TOS)
        };
        set_int(level, name, libc::c_int::from(tos))?;
    }
    if let Some(ttl) = ttl {
        let (level, name) = if is_ipv6 {
            (libc::IPPROTO_IPV6, libc::IPV6_UNICAST_HOPS)
        } else {
            (libc::IPPROTO_IP, libc::IP_TTL)
        };
        set_int(level, name, libc::c_int::from(ttl))?;
    }
    Ok(())
}

/// Attach `--attach-ext-hdr` buffers through IPV6_HOPOPTS/IPV6_DSTOPTS
/// (ext-hdr-26 §4.2). The kernel sets Next Header; other bytes pass unchanged.
/// Options apply to every probe. Attachment failure aborts startup.
/// Allow one HBH followed by one Destination Options header.
#[cfg(target_os = "linux")]
pub(super) fn apply_attach_ext_hdrs(
    fd: std::os::fd::RawFd,
    specs: &[crate::configuration::AttachExtHdrSpec],
) -> std::io::Result<()> {
    use nix::libc;

    use crate::configuration::AttachExtHdrKind;

    for spec in specs {
        let (opt, label) = match spec.kind {
            AttachExtHdrKind::HopByHop => (libc::IPV6_HOPOPTS, "Hop-by-Hop"),
            AttachExtHdrKind::DestOpts => (libc::IPV6_DSTOPTS, "Destination Options"),
        };
        // SAFETY: `fd` is an open IPv6 socket owned by the caller; the buffer
        // outlives the syscall and its length is passed explicitly. The kernel
        // validates the extension-header contents and rejects a malformed one.
        let rc = unsafe {
            libc::setsockopt(
                fd,
                libc::IPPROTO_IPV6,
                opt,
                spec.bytes.as_ptr().cast(),
                spec.bytes.len() as libc::socklen_t,
            )
        };
        if rc < 0 {
            return Err(std::io::Error::last_os_error());
        } else {
            log::info!(
                "Attached {label} IPv6 extension header ({} bytes) to egress packets \
                 (draft-ietf-ippm-stamp-ext-hdr-26 §4.2)",
                spec.bytes.len()
            );
        }
    }
    Ok(())
}

/// Returns the egress route/interface MTU for the (connected) sender socket via
/// `getsockopt(IP_MTU / IPV6_MTU)` on Linux, or `None` when the option is
/// unavailable. This reads the kernel's
/// cached route MTU for the connected peer; it does not probe the path.
#[cfg(target_os = "linux")]
pub(super) fn egress_mtu(socket: &UdpSocket) -> Option<u32> {
    use std::os::fd::AsRawFd;

    use nix::libc;

    let is_v6 = socket.local_addr().is_ok_and(|a| a.is_ipv6());
    let (level, name) = if is_v6 {
        (libc::IPPROTO_IPV6, libc::IPV6_MTU)
    } else {
        (libc::IPPROTO_IP, libc::IP_MTU)
    };
    let mut mtu: libc::c_int = 0;
    let mut len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
    // SAFETY: `mtu` and `len` are live, aligned locals and `len` holds the
    // size of `mtu`, so the kernel's writes stay in bounds; `socket` owns the
    // open fd for the call's duration.
    let rc = unsafe {
        libc::getsockopt(
            socket.as_raw_fd(),
            level,
            name,
            std::ptr::addr_of_mut!(mtu).cast(),
            &mut len,
        )
    };
    (rc == 0 && mtu > 0).then_some(mtu as u32)
}

#[cfg(not(any(target_os = "linux", target_os = "windows")))]
pub(super) fn egress_mtu(_socket: &UdpSocket) -> Option<u32> {
    None
}

/// Enables `IP_RECVTOS` / `IPV6_RECVTCLASS` for reverse-path CE detection
/// (draft-ietf-ippm-stamp-cos-ecn-02 §3.4).
///
/// Failure disables reverse-path feedback; validated CoS EC2 feedback still works.
/// See [`extract_reply_ecn_from_cmsgs`].
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(super) fn enable_reply_tos_reception(
    fd: std::os::fd::RawFd,
    is_ipv6: bool,
) -> std::io::Result<()> {
    use nix::libc;

    let enable: libc::c_int = 1;
    let (level, name) = if is_ipv6 {
        (libc::IPPROTO_IPV6, libc::IPV6_RECVTCLASS)
    } else {
        (libc::IPPROTO_IP, libc::IP_RECVTOS)
    };
    // SAFETY: `fd` is an open socket owned by the caller for the duration
    // of the call; `enable` outlives the syscall and its length is passed
    // explicitly.
    let rc = unsafe {
        libc::setsockopt(
            fd,
            level,
            name,
            std::ptr::addr_of!(enable).cast(),
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if rc < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

/// Extracts reply ECN from `recvmsg` metadata. CE (0b11) indicates reverse-path
/// congestion (draft-ietf-ippm-stamp-cos-ecn-02 §3.4).
/// Requires [`enable_reply_tos_reception`] on the socket.
#[cfg(target_os = "linux")]
pub(super) fn extract_reply_ecn_from_cmsgs(
    msg: &nix::sys::socket::RecvMsg<nix::sys::socket::SockaddrStorage>,
) -> Option<u8> {
    use nix::sys::socket::ControlMessageOwned;

    let cmsgs = msg.cmsgs().ok()?;
    for cmsg in cmsgs {
        match cmsg {
            ControlMessageOwned::Ipv4Tos(tos) => return Some(tos & 0x03),
            ControlMessageOwned::Ipv6TClass(tclass) => {
                return Some((tclass.clamp(0, 255) as u8) & 0x03)
            }
            _ => continue,
        }
    }
    None
}

/// macOS variant of [`extract_reply_ecn_from_cmsgs`]: `nix` has no typed
/// cmsg variant for `IP_RECVTOS`/`IPV6_RECVTCLASS` on this platform, so the
/// raw `ControlMessageOwned::Unknown` payload is decoded by level/type,
/// mirroring `receiver::nix::extract_tos_from_cmsgs`'s macOS variant.
#[cfg(target_os = "macos")]
pub(super) fn extract_reply_ecn_from_cmsgs(
    msg: &nix::sys::socket::RecvMsg<nix::sys::socket::SockaddrStorage>,
) -> Option<u8> {
    use nix::{libc, sys::socket::ControlMessageOwned};

    let cmsgs = msg.cmsgs().ok()?;
    for cmsg in cmsgs {
        if let ControlMessageOwned::Unknown(ref ucmsg) = cmsg {
            let level = ucmsg.cmsg_header.cmsg_level;
            let cmsg_type = ucmsg.cmsg_header.cmsg_type;
            let data = &ucmsg.data_bytes;

            let tos = ((level == libc::IPPROTO_IP && cmsg_type == libc::IP_RECVTOS)
                || (level == libc::IPPROTO_IPV6 && cmsg_type == libc::IPV6_TCLASS))
                .then_some(data);
            if let Some(data) = tos {
                if data.len() >= 4 {
                    let v = i32::from_ne_bytes([data[0], data[1], data[2], data[3]]);
                    return Some((v.clamp(0, 255) as u8) & 0x03);
                } else if !data.is_empty() {
                    return Some(data[0] & 0x03);
                }
            }
        }
    }
    None
}
