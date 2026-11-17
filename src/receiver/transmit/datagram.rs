//! The socket owner that applies per-reply options and sends datagrams.

use super::*;

/// The sole option-setting sender for a borrowed socket. Receive operations may
/// share the socket, but all sends/options go through this mutable owner.
/// Successful sticky settings are cached separately for IPv4 and IPv6.
pub(in crate::receiver) struct DatagramSender<'a> {
    #[cfg(unix)]
    pub(super) fd: std::os::fd::BorrowedFd<'a>,
    #[cfg(windows)]
    pub(super) socket: &'a std::net::UdpSocket,
    pub(super) settings: [Option<i32>; 2],
    #[cfg(target_os = "macos")]
    pub(super) send_buffer: send_buffer::SendBuffer,
    #[cfg(target_os = "macos")]
    pub(super) fragmentation: Option<i32>,
    #[cfg(target_os = "linux")]
    pub(super) srh: Option<Arc<[u8]>>,
}

impl<'a> DatagramSender<'a> {
    #[cfg(unix)]
    pub fn new(socket: &'a impl std::os::fd::AsFd) -> Self {
        Self {
            fd: socket.as_fd(),
            settings: [None; 2],
            #[cfg(target_os = "macos")]
            send_buffer: send_buffer::SendBuffer::default(),
            #[cfg(target_os = "macos")]
            fragmentation: None,
            #[cfg(target_os = "linux")]
            srh: None,
        }
    }

    #[cfg(windows)]
    pub fn new(socket: &'a std::net::UdpSocket) -> Self {
        Self {
            socket,
            settings: [None; 2],
        }
    }

    pub fn send(
        &mut self,
        payload: &[u8],
        dst: SocketAddr,
        options: &SendOptions,
    ) -> io::Result<usize> {
        #[cfg(target_os = "macos")]
        {
            // Darwin's default UDP send buffer can be smaller than a valid
            // route-MTU-sized reply. Grow only this socket, without changing
            // the already computed payload budget or fragmentation policy.
            let socket = socket2::SockRef::from(&self.fd);
            self.send_buffer
                .ensure(
                    payload.len(),
                    || socket.send_buffer_size(),
                    |size| socket.set_send_buffer_size(size),
                )
                .map_err(local_send_error)?;
        }
        #[cfg(unix)]
        {
            use std::os::fd::AsRawFd;
            send_datagram(
                self.fd.as_raw_fd(),
                payload,
                dst,
                options,
                &mut self.settings,
                #[cfg(target_os = "macos")]
                &mut self.fragmentation,
                #[cfg(target_os = "linux")]
                &mut self.srh,
            )
        }
        #[cfg(windows)]
        {
            if options.apply_tos {
                // Winsock IP_TOS is documented as unsupported for setting
                // ToS. A successful legacy call cannot prove wire marking;
                // a QoS-capable backend is needed before reporting RPE=11.
                return Err(cos_apply_error(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "Windows CoS marking requires a QoS-capable backend",
                )));
            }
            windows::apply_fragmentation_policy(
                self.socket,
                dst,
                options.dont_fragment,
                &mut self.settings,
            )
            .map_err(local_send_error)?;
            self.socket.send_to(payload, dst)
        }
    }
}

/// Readback catches ignored sticky options. Invalidate on any failure: a
/// setter can change the socket even if the requested value did not stick.
#[cfg(any(all(unix, not(target_os = "linux")), test))]
pub(super) fn apply_verified_tos(
    cached: &mut Option<i32>,
    requested: i32,
    set: impl FnOnce() -> io::Result<()>,
    get: impl FnOnce() -> io::Result<i32>,
) -> io::Result<()> {
    if *cached == Some(requested) {
        return Ok(());
    }
    *cached = None;
    set().map_err(cos_apply_error)?;
    let actual = get().map_err(cos_apply_error)?;
    if actual != requested {
        return Err(cos_apply_error(io::Error::new(
            io::ErrorKind::Unsupported,
            "socket ignored the requested DSCP/ECN value",
        )));
    }
    *cached = Some(requested);
    Ok(())
}

#[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos", test))]
pub(super) fn update_socket_option(
    cached: &mut Option<i32>,
    requested: i32,
    set: impl FnOnce() -> io::Result<()>,
) -> io::Result<()> {
    if *cached != Some(requested) {
        set()?;
        *cached = Some(requested);
    }
    Ok(())
}

/// Ancillary data for one `sendmsg`, built in place on the stack.
#[cfg(target_os = "linux")]
#[derive(Default)]
pub(super) struct ControlBuffer {
    /// `usize` elements keep every header `cmsghdr`-aligned.
    pub(super) words: [usize; 16],
    /// Bytes in use.
    pub(super) used: usize,
}

#[cfg(target_os = "linux")]
impl ControlBuffer {
    pub(super) fn append(&mut self, level: i32, kind: i32, bytes: &[u8]) {
        use nix::libc;
        // SAFETY: CMSG_SPACE only computes a size.
        let space = unsafe { libc::CMSG_SPACE(bytes.len() as _) } as usize;
        assert!(
            self.used + space <= std::mem::size_of_val(&self.words),
            "control buffer overflow"
        );
        // SAFETY: the assertion keeps the header and data inside `words`,
        // which starts zeroed, so padding stays zero. `used` is a multiple of
        // CMSG_ALIGN, so the header is aligned.
        unsafe {
            let header = self
                .words
                .as_mut_ptr()
                .cast::<u8>()
                .add(self.used)
                .cast::<libc::cmsghdr>();
            (*header).cmsg_level = level;
            (*header).cmsg_type = kind;
            (*header).cmsg_len = libc::CMSG_LEN(bytes.len() as _) as _;
            std::ptr::copy_nonoverlapping(bytes.as_ptr(), libc::CMSG_DATA(header), bytes.len());
        }
        self.used += space;
    }
}

/// CoS and source pinning accompany sendmsg; Linux SRH uses the sticky socket
/// option because the ancillary IPV6_RTHDR parser rejects routing type 4.
/// The exclusive send owner restores/clears SRH before a different reply.
/// Other Unix systems update cached TOS before sendmsg; the mutable send owner
/// never awaits between setting the socket option and issuing the syscall.
#[cfg(unix)]
pub(super) fn send_datagram(
    fd: std::os::fd::RawFd,
    payload: &[u8],
    dst: SocketAddr,
    options: &SendOptions,
    settings: &mut [Option<i32>; 2],
    #[cfg(target_os = "macos")] fragmentation: &mut Option<i32>,
    #[cfg(target_os = "linux")] srh_setting: &mut Option<Arc<[u8]>>,
) -> io::Result<usize> {
    use nix::libc;
    #[cfg(target_os = "macos")]
    if dst.is_ipv6() {
        // Separate from the CoS cache: each sticky setting has one send owner.
        // Ordinary replies clear the policy left by a controlled reply.
        let enabled = i32::from(options.dont_fragment);
        update_socket_option(fragmentation, enabled, || {
            crate::net_policy::macos_mtu::set_ipv6_dont_fragment(fd, options.dont_fragment)
        })
        .map_err(local_send_error)?;
    }
    // SAFETY: `sockaddr_in` and `sockaddr_in6` are plain C structs of integers
    // and byte arrays; all-zero is a valid value for both.
    let mut addr4: libc::sockaddr_in = unsafe { std::mem::zeroed() };
    // SAFETY: as above.
    let mut addr6: libc::sockaddr_in6 = unsafe { std::mem::zeroed() };
    #[cfg(any(
        target_os = "macos",
        target_os = "ios",
        target_os = "freebsd",
        target_os = "netbsd",
        target_os = "openbsd",
        target_os = "dragonfly"
    ))]
    {
        addr4.sin_len = std::mem::size_of_val(&addr4) as _;
        addr6.sin6_len = std::mem::size_of_val(&addr6) as _;
    }
    // SAFETY: `msghdr` is a plain C struct; all-zero means null name, iov and
    // control pointers with zero lengths, which is valid until filled in below.
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    match dst {
        SocketAddr::V4(v) => {
            addr4.sin_family = libc::AF_INET as _;
            addr4.sin_port = v.port().to_be();
            addr4.sin_addr.s_addr = u32::from_ne_bytes(v.ip().octets());
            msg.msg_name = std::ptr::addr_of_mut!(addr4).cast();
            msg.msg_namelen = std::mem::size_of_val(&addr4) as _;
        }
        SocketAddr::V6(v) => {
            addr6.sin6_family = libc::AF_INET6 as _;
            addr6.sin6_port = v.port().to_be();
            addr6.sin6_addr.s6_addr = v.ip().octets();
            addr6.sin6_scope_id = v.scope_id();
            msg.msg_name = std::ptr::addr_of_mut!(addr6).cast();
            msg.msg_namelen = std::mem::size_of_val(&addr6) as _;
        }
    }
    let mut iov = libc::iovec {
        iov_base: payload.as_ptr() as *mut libc::c_void,
        iov_len: payload.len(),
    };
    msg.msg_iov = std::ptr::addr_of_mut!(iov);
    msg.msg_iovlen = 1;
    #[cfg(target_os = "linux")]
    // TOS plus one PKTINFO fit well within the 16-word buffer; usize elements
    // give cmsghdr alignment without a heap allocation per send.
    let mut control = ControlBuffer::default();
    #[cfg(target_os = "linux")]
    {
        // This socket has one send owner. Restore normal PMTU policy for
        // ordinary STAMP replies after a size-controlled send on the same fd.
        let discover: libc::c_int = if options.dont_fragment {
            libc::IP_PMTUDISC_DO
        } else {
            libc::IP_PMTUDISC_WANT
        };
        // IP_PMTUDISC_DO sets DF and fails oversized sends with EMSGSIZE;
        // IP_PMTUDISC_WANT lets the kernel fragment locally when needed.
        update_socket_option(&mut settings[usize::from(dst.is_ipv6())], discover, || {
            // SAFETY: `fd` is the open socket borrowed by the caller; the value
            // pointer and length describe the live `discover` c_int.
            if unsafe {
                libc::setsockopt(
                    fd,
                    if dst.is_ipv4() {
                        libc::IPPROTO_IP
                    } else {
                        libc::IPPROTO_IPV6
                    },
                    if dst.is_ipv4() {
                        libc::IP_MTU_DISCOVER
                    } else {
                        libc::IPV6_MTU_DISCOVER
                    },
                    std::ptr::addr_of!(discover).cast(),
                    std::mem::size_of_val(&discover) as _,
                )
            } < 0
            {
                Err(io::Error::last_os_error())
            } else {
                Ok(())
            }
        })
        .map_err(local_send_error)?;
        // IP_TOS / IPV6_TCLASS ancillary data is a host-order c_int holding
        // the whole TOS / Traffic Class byte (DSCP and ECN).
        if options.apply_tos {
            let tos = options.tos as libc::c_int;
            control.append(
                if dst.is_ipv4() {
                    libc::IPPROTO_IP
                } else {
                    libc::IPPROTO_IPV6
                },
                if dst.is_ipv4() {
                    libc::IP_TOS
                } else {
                    libc::IPV6_TCLASS
                },
                &tos.to_ne_bytes(),
            );
        }
        if options
            .source
            .is_some_and(|source| source.is_ipv4() != dst.is_ipv4())
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "source/destination family mismatch",
            ));
        }
        // One PKTINFO carries the pinned source address and the egress
        // interface; either may be unset (zero).
        if options.source.is_some() || options.egress_ifindex.is_some() {
            let ifindex = options.egress_ifindex.unwrap_or(0);
            if dst.is_ipv4() {
                // SAFETY: in_pktinfo is plain old data; all-zero is valid.
                let mut info: libc::in_pktinfo = unsafe { std::mem::zeroed() };
                if let Some(IpAddr::V4(ip)) = options.source {
                    info.ipi_spec_dst.s_addr = u32::from_ne_bytes(ip.octets());
                }
                info.ipi_ifindex = ifindex as _;
                // SAFETY: the slice covers exactly `info`, which outlives it.
                control.append(libc::IPPROTO_IP, libc::IP_PKTINFO, unsafe {
                    std::slice::from_raw_parts(
                        std::ptr::addr_of!(info).cast(),
                        std::mem::size_of_val(&info),
                    )
                });
            } else {
                // SAFETY: in6_pktinfo is plain old data; all-zero is valid.
                let mut info: libc::in6_pktinfo = unsafe { std::mem::zeroed() };
                if let Some(IpAddr::V6(ip)) = options.source {
                    info.ipi6_addr.s6_addr = ip.octets();
                }
                info.ipi6_ifindex = ifindex as _;
                // SAFETY: the slice covers exactly `info`, which outlives it.
                control.append(libc::IPPROTO_IPV6, libc::IPV6_PKTINFO, unsafe {
                    std::slice::from_raw_parts(
                        std::ptr::addr_of!(info).cast(),
                        std::mem::size_of_val(&info),
                    )
                });
            }
        }
        if *srh_setting != options.srh {
            let bytes = options.srh.as_deref().unwrap_or(&[]);
            // No await or other sender can interleave this option and sendmsg.
            // On failure retain the previous cache: a fallback must clear it
            // successfully before transmitting an ordinary reply. An empty value
            // removes the sticky routing header.
            // SAFETY: `fd` is the open socket borrowed by the caller; the pointer
            // and length describe `bytes`, which lives across the call (an empty
            // slice has a dangling but non-null pointer and length 0).
            if unsafe {
                libc::setsockopt(
                    fd,
                    libc::IPPROTO_IPV6,
                    libc::IPV6_RTHDR,
                    bytes.as_ptr().cast(),
                    bytes.len() as _,
                )
            } < 0
            {
                return Err(io::Error::last_os_error());
            }
            *srh_setting = options.srh.clone();
        }
        msg.msg_control = control.words.as_mut_ptr().cast();
        msg.msg_controllen = control.used as _;
    }
    #[cfg(not(target_os = "linux"))]
    if options.apply_tos {
        let tos = i32::from(options.tos);
        let (level, name) = if dst.is_ipv4() {
            (libc::IPPROTO_IP, libc::IP_TOS)
        } else {
            (libc::IPPROTO_IPV6, libc::IPV6_TCLASS)
        };
        apply_verified_tos(
            &mut settings[usize::from(dst.is_ipv6())],
            tos,
            || {
                // SAFETY: fd is borrowed and the pointer/size describe tos.
                let result = unsafe {
                    libc::setsockopt(
                        fd,
                        level,
                        name,
                        std::ptr::addr_of!(tos).cast(),
                        std::mem::size_of_val(&tos) as _,
                    )
                };
                if result < 0 {
                    Err(io::Error::last_os_error())
                } else {
                    Ok(())
                }
            },
            || {
                let mut actual: libc::c_int = 0;
                let mut len = std::mem::size_of_val(&actual) as libc::socklen_t;
                // SAFETY: the writable pointer/size describe actual; len is
                // initialized to its capacity and lives across getsockopt.
                let result = unsafe {
                    libc::getsockopt(
                        fd,
                        level,
                        name,
                        std::ptr::addr_of_mut!(actual).cast(),
                        &mut len,
                    )
                };
                if result < 0 {
                    Err(io::Error::last_os_error())
                } else if len as usize != std::mem::size_of_val(&actual) {
                    Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "invalid ToS readback size",
                    ))
                } else {
                    Ok(actual)
                }
            },
        )?;
    }

    // SAFETY: `fd` is the open socket borrowed by the caller. Every pointer in
    // `msg` refers to a local that outlives the call: the address (`addr4` or
    // `addr6`), `iov` (whose base is `payload`, only read by sendmsg) and, on
    // Linux, `control.words` with `control.used` initialized bytes.
    let sent = unsafe { libc::sendmsg(fd, &msg, 0) };
    if sent < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(sent as usize)
    }
}
