//! Destination-specific kernel MTU estimates for reflected datagrams.
//!
//! Linux route/link/address/rule notifications invalidate the bounded cache; a
//! 250 ms expiry and EMSGSIZE-triggered refresh provide additional backstops.
//! Kernel fragmentation prevention closes the race between lookup and send.
//! Windows and supported macOS IPv6 sockets query on every attempt, without
//! reusing cached estimates.
use super::transmit::SendOptions;
use std::{
    collections::{HashMap, VecDeque},
    io,
    net::SocketAddr,
    time::{Duration, Instant},
};

const CACHE_LIMIT: usize = 256;
const CACHE_TTL: Duration = Duration::from_millis(250);

#[cfg(target_os = "windows")]
mod windows;
#[cfg(target_os = "windows")]
use windows::route_mtu;

#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "macos")]
use macos::route_mtu;

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct RouteKey {
    local: SocketAddr,
    target: SocketAddr,
    tos: u8,
    /// Pinned egress interface, 0 when the route chooses.
    oif: u32,
}

struct CachedMtu {
    until: Instant,
    mtu: u32,
    referenced: bool,
}

#[derive(Default)]
pub(super) struct MtuCache {
    entries: HashMap<RouteKey, CachedMtu>,
    // One key per entry; hits only set a bit. Capacity pressure advances this
    // bounded second-chance queue rather than discarding the whole working set.
    order: VecDeque<RouteKey>,
    #[cfg(target_os = "linux")]
    notifications: Option<std::os::fd::OwnedFd>,
    /// Interface the reply sockets are bound to with `--interface`, 0 when
    /// unbound. Every reply leaves through it, so route lookups use it as the
    /// egress interface unless RFC 9503 §4.1.1 pins the arrival link.
    bound_oif: u32,
}

impl MtuCache {
    /// A cache for reply sockets bound to interface `oif` (0 for unbound).
    /// Linux looks the route up through that interface or VRF; macOS has no
    /// estimate for pinned sockets and refuses size-controlled replies.
    pub fn bound_to(oif: u32) -> Self {
        Self {
            bound_oif: oif,
            ..Self::default()
        }
    }

    pub fn payload_cap(
        &mut self,
        local: SocketAddr,
        target: SocketAddr,
        options: &SendOptions,
        refresh: bool,
    ) -> io::Result<usize> {
        #[cfg(target_os = "macos")]
        if options.srh.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "macOS SRH MTU lookup is unavailable",
            ));
        }
        let (key, overhead) = route_key(local, target, options, self.bound_oif)?;
        // Until native route-change notifications are supported, never reuse
        // a cached estimate, including for later copies of a burst.
        let refresh = refresh || cfg!(any(target_os = "windows", target_os = "macos"));
        #[cfg(target_os = "linux")]
        let refresh = refresh || !self.invalidate_routes();
        let mtu = self.lookup(key, Instant::now(), refresh, route_mtu)?;
        Ok(usize::from(mtu_payload_cap(mtu, target.is_ipv6())).saturating_sub(overhead))
    }

    #[cfg(target_os = "linux")]
    fn invalidate_routes(&mut self) -> bool {
        use nix::libc;
        use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
        if self.notifications.is_none() {
            // Subscribe before querying so a change during lookup is observed
            // before the next use. A missing subscription disables caching.
            // SAFETY: socket(2) takes no pointers; a negative result is
            // handled below before the value is used as a descriptor.
            let raw = unsafe {
                libc::socket(
                    libc::AF_NETLINK,
                    libc::SOCK_RAW | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
                    libc::NETLINK_ROUTE,
                )
            };
            if raw < 0 {
                self.clear();
                return false;
            }
            // SAFETY: `raw` is a fresh, non-negative descriptor from socket(2)
            // that nothing else owns, so `OwnedFd` may take ownership and close it.
            let socket = unsafe { OwnedFd::from_raw_fd(raw) };
            // SAFETY: `sockaddr_nl` is a plain C struct of integers; all-zero is
            // a valid value (pid 0 lets the kernel assign the port id).
            let mut address: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
            address.nl_family = libc::AF_NETLINK as _;
            // Link, address, route and rule changes for both families can
            // change a cached route MTU. Group n is bit n-1 of nl_groups.
            address.nl_groups = [
                libc::RTNLGRP_LINK,
                libc::RTNLGRP_IPV4_IFADDR,
                libc::RTNLGRP_IPV4_ROUTE,
                libc::RTNLGRP_IPV4_RULE,
                libc::RTNLGRP_IPV6_IFADDR,
                libc::RTNLGRP_IPV6_ROUTE,
                libc::RTNLGRP_IPV6_RULE,
            ]
            .into_iter()
            .fold(0, |groups, group| groups | 1 << (group - 1));
            // SAFETY: the fd is open and owned by `socket`; the address pointer
            // and length describe the initialized `address` local, which outlives
            // the call.
            if unsafe {
                libc::bind(
                    socket.as_raw_fd(),
                    std::ptr::addr_of!(address).cast(),
                    std::mem::size_of_val(&address) as _,
                )
            } < 0
            {
                self.clear();
                return false;
            }
            self.notifications = Some(socket);
        }
        // Clearing cache/replacement state below leaves this owned fd open.
        let socket = self.notifications.as_ref().unwrap().as_raw_fd();
        let mut bytes = [0u8; 8192];
        for _ in 0..64 {
            // SAFETY: the fd is open and owned by `self.notifications`; the
            // pointer and length describe the writable `bytes` buffer. With
            // MSG_TRUNC the return value may exceed `bytes.len()`, but the kernel
            // still writes at most `bytes.len()` bytes and the contents are unused.
            let received = unsafe {
                libc::recv(
                    socket,
                    bytes.as_mut_ptr().cast(),
                    bytes.len(),
                    libc::MSG_DONTWAIT | libc::MSG_TRUNC,
                )
            };
            if received < 0 {
                let error = io::Error::last_os_error();
                if error.kind() == io::ErrorKind::WouldBlock {
                    return true;
                }
                self.clear(); // includes ENOBUFS: notifications lost
                return false;
            }
            self.clear();
            if received == 0 {
                return false;
            }
        }
        // Bound notification work under churn. Query this reply afresh.
        false
    }

    fn lookup(
        &mut self,
        key: RouteKey,
        now: Instant,
        refresh: bool,
        query: impl FnOnce(&RouteKey) -> io::Result<u32>,
    ) -> io::Result<u32> {
        if !refresh {
            if let Some(entry) = self.entries.get_mut(&key) {
                if entry.until > now {
                    entry.referenced = true;
                    return Ok(entry.mtu);
                }
            }
        }
        if self.entries.remove(&key).is_some() {
            self.order.retain(|queued| queued != &key);
        }
        let mtu = query(&key)?;
        if self.entries.len() >= CACHE_LIMIT {
            self.evict_one(now);
        }
        self.order.push_back(key.clone());
        self.entries.insert(
            key,
            CachedMtu {
                until: now + CACHE_TTL,
                mtu,
                referenced: true,
            },
        );
        Ok(mtu)
    }

    fn clear(&mut self) {
        self.entries.clear();
        self.order.clear();
    }

    fn evict_one(&mut self, now: Instant) {
        while let Some(key) = self.order.pop_front() {
            let Some(entry) = self.entries.get_mut(&key) else {
                continue;
            };
            if entry.until > now && entry.referenced {
                entry.referenced = false;
                self.order.push_back(key);
            } else {
                self.entries.remove(&key);
                return;
            }
        }
        // Fail safe if replacement metadata ever becomes inconsistent. The
        // normal path visits at most CACHE_LIMIT + 1 keys with exclusive access.
        self.clear();
    }
}

fn route_key(
    mut local: SocketAddr,
    mut target: SocketAddr,
    options: &SendOptions,
    bound_oif: u32,
) -> io::Result<(RouteKey, usize)> {
    if let Some(source) = options.source {
        local.set_ip(source);
    }
    let overhead = options.srh.as_ref().map_or(0, |srh| srh.len());
    if let Some(srh) = &options.srh {
        let invalid = || io::Error::new(io::ErrorKind::InvalidInput, "invalid SRH");
        let start = 8 + 16 * usize::from(*srh.get(3).ok_or_else(invalid)?);
        let octets: [u8; 16] = srh
            .get(start..start + 16)
            .ok_or_else(invalid)?
            .try_into()
            .unwrap();
        target.set_ip(std::net::Ipv6Addr::from(octets).into());
    }
    Ok((
        RouteKey {
            local,
            target,
            tos: options.tos,
            oif: options.egress_ifindex.unwrap_or(bound_oif),
        },
        overhead,
    ))
}

#[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos")))]
fn route_mtu(_: &RouteKey) -> io::Result<u32> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "reply route MTU lookup requires Linux, Windows or macOS",
    ))
}

#[cfg(target_os = "linux")]
fn route_mtu(key: &RouteKey) -> io::Result<u32> {
    #[cfg(test)]
    benchmarks::note_route_query();
    use nix::libc;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    // No destination traffic is generated. RTM_GETROUTE asks the kernel for
    // the UDP flow's actual output route, including source, ports and DSCP.
    // The kernel answers inside sendto(), so the reply is already queued when
    // the nonblocking receive runs; it does not wait for notifications.
    // SAFETY: plain socket(2) call; the result is checked before use.
    let raw = unsafe {
        libc::socket(
            libc::AF_NETLINK,
            libc::SOCK_RAW | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
            libc::NETLINK_ROUTE,
        )
    };
    if raw < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: successful socket() returned a fresh owned descriptor.
    let socket = unsafe { OwnedFd::from_raw_fd(raw) };
    let request = route_request(key);
    // SAFETY: `sockaddr_nl` is a plain C struct of integers; all-zero is valid
    // and pid 0 addresses the kernel.
    let mut kernel: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
    kernel.nl_family = libc::AF_NETLINK as _;
    // SAFETY: the fd is open and owned by `socket`; `request` and `kernel` are
    // live, initialized locals and each pointer is passed with its exact length.
    if unsafe {
        libc::sendto(
            socket.as_raw_fd(),
            request.as_ptr().cast(),
            request.len(),
            0,
            std::ptr::addr_of!(kernel).cast(),
            std::mem::size_of_val(&kernel) as _,
        )
    } < 0
    {
        return Err(io::Error::last_os_error());
    }
    let mut reply = [0u8; 8192];
    // SAFETY: `sockaddr_nl` is a plain C struct of integers; all-zero is valid.
    let mut sender: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
    let mut sender_len = std::mem::size_of_val(&sender) as libc::socklen_t;
    // SAFETY: the fd is open and owned by `socket`; `reply` is writable for
    // `reply.len()` bytes and `sender`/`sender_len` describe a writable
    // `sockaddr_nl` of the stated size. The kernel writes no more than those
    // lengths even though MSG_TRUNC may report a larger `len`, which is checked
    // below before slicing.
    let len = unsafe {
        libc::recvfrom(
            socket.as_raw_fd(),
            reply.as_mut_ptr().cast(),
            reply.len(),
            libc::MSG_TRUNC | libc::MSG_DONTWAIT,
            std::ptr::addr_of_mut!(sender).cast(),
            &mut sender_len,
        )
    };
    if len < 0 {
        return Err(io::Error::last_os_error());
    }
    if len as usize > reply.len() || sender.nl_pid != 0 {
        return Err(invalid_route());
    }
    let (index, metric, overhead) = parse_route(&reply[..len as usize])?;
    let mut name = [0 as libc::c_char; libc::IFNAMSIZ];
    // SAFETY: if_indextoname(3) requires a writable buffer of at least IFNAMSIZ
    // bytes, which `name` is; it writes a NUL-terminated name on success.
    if unsafe { libc::if_indextoname(index, name.as_mut_ptr()) }.is_null() {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: the call above succeeded, so `name` holds a NUL-terminated
    // string within its IFNAMSIZ bytes, and the buffer outlives the borrow.
    let name = unsafe { std::ffi::CStr::from_ptr(name.as_ptr()) }
        .to_str()
        .map_err(|_| invalid_route())?;
    let mtu = interface_mtu(name).ok_or_else(|| {
        io::Error::new(io::ErrorKind::NotFound, "egress interface MTU unavailable")
    })?;
    // A tunnel device advertises its inner IP MTU. Lightweight route
    // encapsulation instead reserves overhead on the underlying device.
    Ok(metric.unwrap_or(u32::MAX).min(mtu.saturating_sub(overhead)))
}

#[cfg(target_os = "linux")]
fn attr(bytes: &mut Vec<u8>, kind: u16, value: &[u8]) {
    bytes.extend_from_slice(&((value.len() + 4) as u16).to_ne_bytes());
    bytes.extend_from_slice(&kind.to_ne_bytes());
    bytes.extend_from_slice(value);
    bytes.resize(bytes.len().div_ceil(4) * 4, 0);
}

#[cfg(target_os = "linux")]
fn route_request(key: &RouteKey) -> Vec<u8> {
    use nix::libc;
    let v6 = key.target.is_ipv6();
    // 16-byte nlmsghdr (len 0..4, type 4..6, flags 6..8, seq 8..12, pid
    // 12..16) followed by a 12-byte rtmsg (family 16, dst_len 17, src_len 18,
    // tos 19, then table/protocol/scope/type/flags, left zero). Fields are in
    // host byte order; the length is filled in once the attributes are added.
    let mut request = vec![0u8; 28]; // nlmsghdr + rtmsg
    request[4..6].copy_from_slice(&26u16.to_ne_bytes()); // RTM_GETROUTE
    request[6..8].copy_from_slice(&1u16.to_ne_bytes()); // NLM_F_REQUEST
    request[8..12].copy_from_slice(&1u32.to_ne_bytes()); // seq 1, checked in parse_route()
    request[16] = if v6 { libc::AF_INET6 } else { libc::AF_INET } as u8;
    // rtm_dst_len: a host route (full-length prefix) for the exact target.
    request[17] = if v6 { 128 } else { 32 };
    request[19] = crate::tos::Tos(key.tos).without_ecn().0;
    fn ip_bytes(ip: std::net::IpAddr) -> Vec<u8> {
        match ip {
            std::net::IpAddr::V4(v) => v.octets().to_vec(),
            std::net::IpAddr::V6(v) => v.octets().to_vec(),
        }
    }
    attr(&mut request, 1, &ip_bytes(key.target.ip())); // RTA_DST
    if !key.local.ip().is_unspecified() {
        // rtm_src_len: full-length prefix for the bound source address.
        request[18] = request[17];
        attr(&mut request, 2, &ip_bytes(key.local.ip())); // RTA_SRC
    }
    let oif = match key.target {
        _ if key.oif != 0 => key.oif,
        SocketAddr::V6(v) => v.scope_id(),
        SocketAddr::V4(_) => 0,
    };
    if oif != 0 {
        attr(&mut request, 4, &oif.to_ne_bytes()); // RTA_OIF
    }
    // SAFETY: geteuid(2) cannot fail and has no preconditions.
    attr(&mut request, 25, &unsafe { libc::geteuid() }.to_ne_bytes()); // RTA_UID
    attr(&mut request, 27, &[libc::IPPROTO_UDP as u8]); // RTA_IP_PROTO
    attr(&mut request, 28, &key.local.port().to_be_bytes()); // RTA_SPORT
    attr(&mut request, 29, &key.target.port().to_be_bytes()); // RTA_DPORT
    let len = request.len() as u32;
    request[..4].copy_from_slice(&len.to_ne_bytes());
    request
}

#[cfg(target_os = "linux")]
fn invalid_route() -> io::Error {
    super::transmit::local_send_error(io::Error::new(
        io::ErrorKind::InvalidData,
        "invalid route MTU response",
    ))
}

#[cfg(target_os = "linux")]
/// Splits a run of netlink attributes into `(type, payload)` pairs.
///
/// Each attribute is a 4-byte header (u16 length including the header, u16
/// type) followed by the payload, padded to a 4-byte boundary. The type is
/// masked with 0x3fff to drop the NLA_F_NESTED and NLA_F_NET_BYTEORDER flags.
fn attributes(mut bytes: &[u8]) -> io::Result<Vec<(u16, &[u8])>> {
    let mut result = Vec::new();
    while !bytes.is_empty() {
        if bytes.len() < 4 {
            return Err(invalid_route());
        }
        let len = u16::from_ne_bytes(bytes[..2].try_into().unwrap()) as usize;
        if len < 4 || len > bytes.len() {
            return Err(invalid_route());
        }
        result.push((
            u16::from_ne_bytes(bytes[2..4].try_into().unwrap()) & 0x3fff,
            &bytes[4..len],
        ));
        let aligned = len.div_ceil(4) * 4;
        if aligned > bytes.len() {
            return Err(invalid_route());
        }
        bytes = &bytes[aligned..];
    }
    Ok(result)
}

#[cfg(target_os = "linux")]
/// Parses an RTM_GETROUTE reply into (egress ifindex, RTAX_MTU metric,
/// encapsulation overhead in bytes).
fn parse_route(bytes: &[u8]) -> io::Result<(u32, Option<u32>, u32)> {
    // 16-byte nlmsghdr plus at least the 4-byte error code of an NLMSG_ERROR.
    if bytes.len() < 20 {
        return Err(invalid_route());
    }
    let len = u32::from_ne_bytes(bytes[..4].try_into().unwrap()) as usize;
    if len > bytes.len() || len < 20 || bytes[8..12] != 1u32.to_ne_bytes() {
        return Err(invalid_route());
    }
    let kind = u16::from_ne_bytes(bytes[4..6].try_into().unwrap());
    if kind == 2 {
        // NLMSG_ERROR: a negative errno follows the 16-byte header.
        let error = i32::from_ne_bytes(bytes[16..20].try_into().unwrap());
        return Err(if error < 0 {
            io::Error::from_raw_os_error(error.saturating_neg())
        } else {
            invalid_route()
        });
    }
    // RTM_NEWROUTE (24) with a full nlmsghdr + rtmsg; attributes start at 28.
    if kind != 24 || len < 28 {
        return Err(invalid_route());
    }
    let mut index = None;
    let mut mtu = None;
    let mut encap_type = None;
    let mut encap = None;
    // RTA_OIF (4), RTA_METRICS (8) holding nested RTAX_MTU (2),
    // RTA_ENCAP_TYPE (21) and RTA_ENCAP (22).
    for (kind, value) in attributes(&bytes[28..len])? {
        match kind {
            4 if value.len() == 4 => index = Some(u32::from_ne_bytes(value.try_into().unwrap())),
            8 => {
                for (metric, value) in attributes(value)? {
                    if metric == 2 && value.len() == 4 {
                        mtu = Some(u32::from_ne_bytes(value.try_into().unwrap()));
                    }
                }
            }
            21 if value.len() == 2 => {
                encap_type = Some(u16::from_ne_bytes(value.try_into().unwrap()))
            }
            22 => encap = Some(value),
            _ => {}
        }
    }
    if encap_type.is_some() && encap.is_none() {
        return Err(invalid_route());
    }
    // Only LWTUNNEL_ENCAP_SEG6 (5) has a known overhead. Its payload holds
    // SEG6_IPTUNNEL_SRH (1): a host-order i32 mode, then the SRH, whose Hdr Ext
    // Len byte (offset 5 here) counts 8-byte units beyond the first 8 bytes.
    let overhead = if let Some(encap) = encap {
        if encap_type != Some(5) {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "unknown route encapsulation overhead",
            ));
        }
        let attrs = attributes(encap)?;
        let srh = attrs
            .iter()
            .find(|(kind, _)| *kind == 1)
            .ok_or_else(invalid_route)?
            .1;
        if srh.len() < 12 {
            return Err(invalid_route());
        }
        let mode = u32::from_ne_bytes(srh[..4].try_into().unwrap());
        let srh_len = (u32::from(srh[5]) + 1) * 8;
        if srh.len() < 4 + srh_len as usize {
            return Err(invalid_route());
        }
        // SEG6_IPTUN_MODE_INLINE (0) inserts only the SRH; ENCAP (1) and
        // ENCAP_RED (3) add a 40-byte outer IPv6 header too.
        match mode {
            0 => srh_len,
            1 | 3 => 40 + srh_len, // reduced mode conservatively reserves full SRH
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "unsupported route encapsulation mode",
                ))
            }
        }
    } else {
        0
    };
    Ok((
        index.filter(|i| *i != 0).ok_or_else(invalid_route)?,
        mtu.filter(|m| *m > 0),
        overhead,
    ))
}

/// Reads an interface's MTU with `ioctl(SIOCGIFMTU)`.
///
/// A throwaway UDP socket supplies the descriptor: `SIOCGIFMTU` only needs
/// *some* socket of the right family, not the reflector's own.
///
/// Returns `None` on any failure (unknown interface, permission, non-Linux), so
/// callers can reject a reply whose egress budget cannot be established.
#[cfg(target_os = "linux")]
#[must_use]
pub(crate) fn interface_mtu(iface: &str) -> Option<u32> {
    use std::os::fd::AsRawFd;

    // `::nix`: inside this module, a bare `nix` would resolve to the sibling
    // `receiver::nix` backend module.
    use ::nix::libc;

    if iface.is_empty() || iface.len() >= libc::IFNAMSIZ {
        return None;
    }
    let probe = std::net::UdpSocket::bind(("0.0.0.0", 0)).ok()?;

    // SAFETY: `ifreq` is a plain C struct with no invalid bit patterns; an
    // all-zero value is a valid "empty request" before the name is filled in.
    let mut req: libc::ifreq = unsafe { std::mem::zeroed() };
    for (dst, byte) in req.ifr_name.iter_mut().zip(iface.as_bytes()) {
        *dst = *byte as libc::c_char;
    }

    // SAFETY: `probe` owns an open socket for the call's duration and `req` is
    // a valid, correctly-sized `ifreq` the kernel writes the MTU into.
    let rc = unsafe { libc::ioctl(probe.as_raw_fd(), libc::SIOCGIFMTU, &mut req) };
    if rc != 0 {
        return None;
    }
    // SAFETY: SIOCGIFMTU populates the `ifru_mtu` arm of the union.
    let mtu = unsafe { req.ifr_ifru.ifru_mtu };
    (mtu > 0).then_some(mtu as u32)
}

// Off Linux only the unit tests call this.
#[cfg(not(target_os = "linux"))]
#[cfg_attr(not(test), allow(dead_code))]
#[must_use]
pub(crate) fn interface_mtu(_iface: &str) -> Option<u32> {
    None
}

/// Largest STAMP payload (UDP payload) that fits in `mtu` without fragmenting.
///
/// `--reflected-control-max-size` bounds the *STAMP packet*, while an MTU bounds
/// the whole IP datagram, so the IP and UDP headers have to come off before the
/// two are comparable.
///
/// No base-size floor: a reply whose mandatory fields cannot fit is dropped.
#[must_use]
pub(crate) fn mtu_payload_cap(mtu: u32, is_ipv6: bool) -> u16 {
    use crate::tlv::{IPV4_FIXED_HEADER_SIZE, IPV6_FIXED_HEADER_SIZE};
    const UDP_HEADER: u32 = 8;

    let ip_hdr = if is_ipv6 {
        IPV6_FIXED_HEADER_SIZE as u32
    } else {
        IPV4_FIXED_HEADER_SIZE as u32
    };
    let payload = mtu.saturating_sub(ip_hdr).saturating_sub(UDP_HEADER);
    // Ordinary UDP/IP lengths exclude jumbograms.
    let protocol_cap = if is_ipv6 { 65_527 } else { 65_507 };
    payload.min(protocol_cap) as u16
}

#[cfg(test)]
mod benchmarks;

#[cfg(test)]
mod tests {
    use super::*;

    fn key(port: u16) -> RouteKey {
        RouteKey {
            local: "0.0.0.0:862".parse().unwrap(),
            target: SocketAddr::from(([127, 0, 0, 1], port)),
            tos: 184,
            oif: 0,
        }
    }

    fn family_key(port: u16, ipv6: bool) -> RouteKey {
        let mut key = key(port);
        if ipv6 {
            key.local = "[::1]:862".parse().unwrap();
            key.target = SocketAddr::new(std::net::Ipv6Addr::LOCALHOST.into(), port);
        }
        key
    }

    fn verify_order(cache: &MtuCache) {
        let queued: std::collections::HashSet<_> = cache.order.iter().collect();
        assert_eq!(queued.len(), cache.order.len());
        assert_eq!(queued, cache.entries.keys().collect());
        assert!(cache.order.len() <= CACHE_LIMIT);
    }

    #[test]
    fn capacity_replaces_one_entry_and_gives_hits_a_second_chance() {
        for ipv6 in [false, true] {
            let now = Instant::now();
            let mut cache = MtuCache::default();
            for port in 0..CACHE_LIMIT as u16 {
                cache
                    .lookup(family_key(port, ipv6), now, false, |_| Ok(1500))
                    .unwrap();
            }
            cache
                .lookup(family_key(256, ipv6), now, false, |_| Ok(1400))
                .unwrap();
            assert_eq!(cache.entries.len(), CACHE_LIMIT);
            assert!(!cache.entries.contains_key(&family_key(0, ipv6)));
            assert_eq!(
                cache
                    .lookup(family_key(1, ipv6), now, false, |_| panic!(
                        "recent entry lost"
                    ))
                    .unwrap(),
                1500
            );
            cache
                .lookup(family_key(257, ipv6), now, false, |_| Ok(1300))
                .unwrap();
            assert!(cache.entries.contains_key(&family_key(1, ipv6)));
            assert!(!cache.entries.contains_key(&family_key(2, ipv6)));
            verify_order(&cache);
        }
    }

    #[test]
    fn expiry_refresh_failure_and_clear_keep_replacement_metadata_bounded() {
        for ipv6 in [false, true] {
            let now = Instant::now();
            let mut cache = MtuCache::default();
            for port in 0..CACHE_LIMIT as u16 {
                cache
                    .lookup(family_key(port, ipv6), now, false, |_| Ok(1500))
                    .unwrap();
            }
            // A hit does not extend the original TTL.
            cache
                .lookup(family_key(0, ipv6), now + CACHE_TTL / 2, false, |_| {
                    panic!("early expiry")
                })
                .unwrap();
            assert_eq!(
                cache
                    .lookup(family_key(0, ipv6), now + CACHE_TTL, false, |_| Ok(1280))
                    .unwrap(),
                1280
            );
            for _ in 0..1000 {
                cache
                    .lookup(family_key(0, ipv6), now + CACHE_TTL, true, |_| Ok(9000))
                    .unwrap();
                verify_order(&cache);
            }
            assert!(cache
                .lookup(family_key(0, ipv6), now + CACHE_TTL, true, |_| Err(
                    io::Error::other("route removed")
                ))
                .is_err());
            assert!(!cache.entries.contains_key(&family_key(0, ipv6)));
            verify_order(&cache);
            // Expired entries can remain stored, but are never returned.
            assert_eq!(
                cache
                    .lookup(family_key(1, ipv6), now + CACHE_TTL, false, |_| Ok(1200))
                    .unwrap(),
                1200
            );
            cache
                .lookup(family_key(300, ipv6), now + CACHE_TTL, false, |_| Ok(1600))
                .unwrap();
            verify_order(&cache);
            cache.clear();
            assert!(cache.entries.is_empty() && cache.order.is_empty());
        }
    }

    #[test]
    fn eviction_preserves_complete_flow_key_isolation() {
        for ipv6 in [false, true] {
            let now = Instant::now();
            let base = family_key(5000, ipv6);
            let mut keys = vec![base.clone()];
            let mut other = base.clone();
            other.local.set_port(863);
            keys.push(other);
            let mut other = base.clone();
            other
                .local
                .set_ip(if ipv6 { "::2" } else { "127.0.0.2" }.parse().unwrap());
            keys.push(other);
            let mut other = base.clone();
            other.target.set_port(5001);
            keys.push(other);
            let mut other = base.clone();
            other
                .target
                .set_ip(if ipv6 { "::2" } else { "127.0.0.2" }.parse().unwrap());
            keys.push(other);
            let mut other = base.clone();
            other.tos = 0;
            keys.push(other);
            let mut other = base.clone();
            other.oif = 7;
            keys.push(other);
            if let SocketAddr::V6(target) = base.target {
                let mut other = base.clone();
                let mut scoped = target;
                scoped.set_scope_id(7);
                other.target = SocketAddr::V6(scoped);
                keys.push(other);
            }
            let mut cache = MtuCache::default();
            for (i, key) in keys.iter().enumerate() {
                cache
                    .lookup(key.clone(), now, false, |_| Ok(1280 + i as u32))
                    .unwrap();
            }
            for (i, key) in keys.iter().enumerate() {
                assert_eq!(
                    cache
                        .lookup(key.clone(), now, false, |_| panic!("flow aliased or lost"))
                        .unwrap(),
                    1280 + i as u32
                );
            }
            verify_order(&cache);
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn notification_and_receive_error_clear_all_replacement_state() {
        use std::os::unix::net::UnixDatagram;
        for empty in [false, true] {
            let mut cache = MtuCache::default();
            cache
                .lookup(key(1), Instant::now(), false, |_| Ok(1500))
                .unwrap();
            let (sender, receiver) = UnixDatagram::pair().unwrap();
            receiver.set_nonblocking(true).unwrap();
            sender.send(if empty { &[] } else { &[1] }).unwrap();
            cache.notifications = Some(receiver.into());
            assert_eq!(cache.invalidate_routes(), !empty);
            assert!(cache.entries.is_empty() && cache.order.is_empty());
        }
        let mut cache = MtuCache {
            notifications: Some(std::fs::File::open("/dev/null").unwrap().into()),
            ..MtuCache::default()
        };
        let options = SendOptions {
            apply_tos: true,
            egress_ifindex: None,
            tos: 184,
            source: None,
            srh: None,
            dont_fragment: true,
        };
        let local = "127.0.0.1:862".parse().unwrap();
        let target = "127.0.0.1:5000".parse().unwrap();
        let (route, _) = route_key(local, target, &options, 0).unwrap();
        for _ in 0..2 {
            cache
                .lookup(route.clone(), Instant::now(), true, |_| Ok(1))
                .unwrap();
            assert!(cache.payload_cap(local, target, &options, false).unwrap() >= 1000);
            verify_order(&cache);
        }
    }

    #[test]
    fn cache_is_bounded_and_refreshes_expired_or_failed_entries() {
        let mut cache = MtuCache::default();
        let now = Instant::now();
        assert_eq!(
            cache.lookup(key(1), now, false, |_| Ok(1500)).unwrap(),
            1500
        );
        assert_eq!(
            cache
                .lookup(key(1), now, false, |_| panic!("cache miss"))
                .unwrap(),
            1500
        );
        assert_eq!(
            cache
                .lookup(key(1), now + CACHE_TTL, false, |_| Ok(1280))
                .unwrap(),
            1280
        );
        assert!(cache
            .lookup(key(1), now + CACHE_TTL, true, |_| Err(io::Error::other(
                "route removed"
            )))
            .is_err());
        assert_eq!(
            cache
                .lookup(key(1), now + CACHE_TTL, false, |_| Ok(9000))
                .unwrap(),
            9000
        );
        for port in 2..=300 {
            cache
                .lookup(key(port), now + CACHE_TTL, false, |_| Ok(1500))
                .unwrap();
        }
        assert!(cache.entries.len() <= CACHE_LIMIT);
        let mut other = key(300);
        other.local = "127.0.0.2:862".parse().unwrap();
        assert_eq!(
            cache
                .lookup(other.clone(), now + CACHE_TTL, false, |_| Ok(1400))
                .unwrap(),
            1400
        );
        other.tos = 0;
        assert_eq!(
            cache
                .lookup(other, now + CACHE_TTL, false, |_| Ok(1300))
                .unwrap(),
            1300
        );
    }

    /// A socket bound with `--interface` sends every reply through that
    /// device, so the kernel route query must be restricted to it as well.
    #[cfg(target_os = "linux")]
    #[test]
    fn route_lookup_follows_the_bound_interface() {
        let loopback = ::nix::net::if_::if_nametoindex("lo").unwrap();
        let local: SocketAddr = "127.0.0.1:862".parse().unwrap();
        let target: SocketAddr = "127.0.0.1:5000".parse().unwrap();
        let key = |oif| RouteKey {
            local,
            target,
            tos: 0,
            oif,
        };
        let request = route_request(&key(loopback));
        let attrs = attributes(&request[28..]).unwrap();
        assert!(attrs.contains(&(4, &loopback.to_ne_bytes()[..])));
        let unbound = route_mtu(&key(0)).unwrap();
        assert_eq!(route_mtu(&key(loopback)).unwrap(), unbound);
        // No device has this index; the kernel rejects the pinned lookup
        // instead of falling back to the default table.
        assert!(route_mtu(&key(u32::MAX >> 1)).is_err());

        let options = SendOptions {
            apply_tos: false,
            egress_ifindex: None,
            tos: 0,
            source: None,
            srh: None,
            dont_fragment: true,
        };
        let mut cache = MtuCache::bound_to(u32::MAX >> 1);
        assert!(cache.payload_cap(local, target, &options, true).is_err());
        let mut cache = MtuCache::bound_to(loopback);
        assert!(cache.payload_cap(local, target, &options, true).unwrap() >= 1000);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn route_request_carries_udp_flow_and_ipv6_scope() {
        let key = RouteKey {
            local: "[fe80::2]:862".parse().unwrap(),
            target: "[fe80::3%7]:5000".parse().unwrap(),
            tos: 187,
            oif: 0,
        };
        let request = route_request(&key);
        assert_eq!(request[16..20], [10, 128, 128, 184]);
        let attrs = attributes(&request[28..]).unwrap();
        assert!(attrs.contains(&(4, &7u32.to_ne_bytes()[..])));
        assert!(attrs.contains(&(27, &[17][..])));
        assert!(attrs.contains(&(28, &862u16.to_be_bytes()[..])));
        assert!(attrs.contains(&(29, &5000u16.to_be_bytes()[..])));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn route_response_validates_metrics_encapsulation_and_framing() {
        let mut response = route_request(&key(1));
        response.truncate(28);
        response[4..6].copy_from_slice(&24u16.to_ne_bytes());
        attr(&mut response, 4, &2u32.to_ne_bytes());
        let mut metrics = Vec::new();
        attr(&mut metrics, 2, &1280u32.to_ne_bytes());
        attr(&mut response, 8, &metrics);
        fn finish(response: &mut [u8]) {
            let len = response.len() as u32;
            response[..4].copy_from_slice(&len.to_ne_bytes());
        }
        finish(&mut response);
        assert_eq!(parse_route(&response).unwrap(), (2, Some(1280), 0));
        let mut srh = 1u32.to_ne_bytes().to_vec();
        srh.extend(crate::srv6::build_srh(&["2001:db8::1".parse().unwrap()]).unwrap());
        let mut encap = Vec::new();
        attr(&mut encap, 1, &srh);
        attr(&mut response, 21, &5u16.to_ne_bytes());
        attr(&mut response, 22, &encap);
        finish(&mut response);
        assert_eq!(parse_route(&response).unwrap(), (2, Some(1280), 64));
        for len in 0..response.len() {
            assert!(parse_route(&response[..len]).is_err());
        }
        let offset = response.len() - encap.len() - 8;
        response[offset] = 255;
        assert!(parse_route(&response).is_err());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn live_route_mtu_for_wildcard_and_bound_ipv4_ipv6() {
        for (local, target) in [
            ("0.0.0.0:862", "127.0.0.1:5000"),
            ("127.0.0.1:862", "127.0.0.1:5000"),
            ("[::]:862", "[::1]:5000"),
            ("[::1]:862", "[::1]:5000"),
        ] {
            let key = RouteKey {
                local: local.parse().unwrap(),
                target: target.parse().unwrap(),
                tos: 184,
                oif: 0,
            };
            assert!(route_mtu(&key).unwrap() >= 1280, "{key:?}");
        }
    }

    #[test]
    fn srh_budget_uses_first_hop_and_subtracts_all_header_bytes() {
        let local = "[::]:862".parse().unwrap();
        let target = "[2001:db8::9]:5000".parse().unwrap();
        let options = SendOptions {
            apply_tos: true,
            egress_ifindex: None,
            tos: 0,
            source: Some("2001:db8::2".parse().unwrap()),
            srh: crate::srv6::build_srh(&[
                "2001:db8::1".parse().unwrap(),
                "2001:db8::9".parse().unwrap(),
            ])
            .map(std::sync::Arc::from),
            dont_fragment: true,
        };
        let (key, overhead) = route_key(local, target, &options, 0).unwrap();
        assert_eq!(key.local, "[2001:db8::2]:862".parse().unwrap());
        assert_eq!(key.target, "[2001:db8::1]:5000".parse().unwrap());
        assert_eq!(
            usize::from(super::mtu_payload_cap(1500, true)) - overhead,
            1500 - 40 - 8 - 40
        );
        let mut invalid = options;
        invalid.srh = Some(std::sync::Arc::from([]));
        assert!(route_key(local, target, &invalid, 0).is_err());
    }

    #[test]
    fn bound_interface_is_the_egress_unless_the_arrival_link_is_pinned() {
        let local = "127.0.0.1:862".parse().unwrap();
        let target = "127.0.0.1:5000".parse().unwrap();
        let mut options = SendOptions {
            apply_tos: true,
            egress_ifindex: None,
            tos: 0,
            source: None,
            srh: None,
            dont_fragment: true,
        };
        for (bound, pinned, expected) in
            [(0, None, 0), (7, None, 7), (7, Some(3), 3), (0, Some(3), 3)]
        {
            options.egress_ifindex = pinned;
            let (key, _) = route_key(local, target, &options, bound).unwrap();
            assert_eq!(key.oif, expected, "bound={bound} pinned={pinned:?}");
        }
    }
}
