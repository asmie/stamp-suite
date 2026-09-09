//! Destination-specific Linux route MTU lookup for reflected datagrams.
//!
//! Route/link/address/rule notifications invalidate the bounded cache; a
//! 250 ms expiry and EMSGSIZE-triggered refresh provide additional backstops.
//! Kernel fragmentation prevention closes the race between lookup and send.
use super::transmit::SendOptions;
use std::{
    collections::HashMap,
    io,
    net::SocketAddr,
    time::{Duration, Instant},
};

const CACHE_LIMIT: usize = 256;
const CACHE_TTL: Duration = Duration::from_millis(250);

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct RouteKey {
    local: SocketAddr,
    target: SocketAddr,
    tos: u8,
}

#[derive(Default)]
pub(super) struct MtuCache {
    entries: HashMap<RouteKey, (Instant, u32)>,
    #[cfg(target_os = "linux")]
    notifications: Option<std::os::fd::OwnedFd>,
}

impl MtuCache {
    pub fn payload_cap(
        &mut self,
        local: SocketAddr,
        target: SocketAddr,
        options: &SendOptions,
        refresh: bool,
    ) -> io::Result<usize> {
        let (key, overhead) = route_key(local, target, options)?;
        #[cfg(target_os = "linux")]
        let refresh = refresh || !self.invalidate_routes();
        let mtu = self.lookup(key, Instant::now(), refresh, route_mtu)?;
        Ok(usize::from(super::mtu_payload_cap(mtu, target.is_ipv6())).saturating_sub(overhead))
    }

    #[cfg(target_os = "linux")]
    fn invalidate_routes(&mut self) -> bool {
        use nix::libc;
        use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
        if self.notifications.is_none() {
            // Subscribe before querying so a change during lookup is observed
            // before the next use. A missing subscription disables caching.
            let raw = unsafe {
                libc::socket(
                    libc::AF_NETLINK,
                    libc::SOCK_RAW | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
                    libc::NETLINK_ROUTE,
                )
            };
            if raw < 0 {
                self.entries.clear();
                return false;
            }
            let socket = unsafe { OwnedFd::from_raw_fd(raw) };
            let mut address: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
            address.nl_family = libc::AF_NETLINK as _;
            // RTMGRP_LINK, IPv4/IPv6 IFADDR, ROUTE and RULE.
            address.nl_groups = 1 | 0x10 | 0x40 | 0x80 | 0x100 | 0x400 | 0x80000;
            if unsafe {
                libc::bind(
                    socket.as_raw_fd(),
                    std::ptr::addr_of!(address).cast(),
                    std::mem::size_of_val(&address) as _,
                )
            } < 0
            {
                self.entries.clear();
                return false;
            }
            self.notifications = Some(socket);
        }
        let socket = self.notifications.as_ref().unwrap();
        let mut bytes = [0u8; 8192];
        for _ in 0..64 {
            let received = unsafe {
                libc::recv(
                    socket.as_raw_fd(),
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
                self.entries.clear(); // includes ENOBUFS: notifications lost
                return false;
            }
            self.entries.clear();
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
            if let Some((until, mtu)) = self.entries.get(&key) {
                if *until > now {
                    return Ok(*mtu);
                }
            }
        }
        self.entries.remove(&key);
        let mtu = query(&key)?;
        self.entries.retain(|_, (until, _)| *until > now);
        if self.entries.len() >= CACHE_LIMIT {
            self.entries.clear();
        }
        self.entries.insert(key, (now + CACHE_TTL, mtu));
        Ok(mtu)
    }
}

fn route_key(
    mut local: SocketAddr,
    mut target: SocketAddr,
    options: &SendOptions,
) -> io::Result<(RouteKey, usize)> {
    if let Some(source) = options.source {
        local.set_ip(source);
    }
    let overhead = options.srh.as_ref().map_or(0, Vec::len);
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
        },
        overhead,
    ))
}

#[cfg(not(target_os = "linux"))]
fn route_mtu(_: &RouteKey) -> io::Result<u32> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "reply route MTU lookup requires Linux",
    ))
}

#[cfg(target_os = "linux")]
fn route_mtu(key: &RouteKey) -> io::Result<u32> {
    use nix::libc;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    // No destination traffic is generated. RTM_GETROUTE asks the kernel for
    // the UDP flow's actual output route, including source, ports and DSCP.
    let raw = unsafe {
        libc::socket(
            libc::AF_NETLINK,
            libc::SOCK_RAW | libc::SOCK_CLOEXEC,
            libc::NETLINK_ROUTE,
        )
    };
    if raw < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: successful socket() returned a fresh owned descriptor.
    let socket = unsafe { OwnedFd::from_raw_fd(raw) };
    let timeout = libc::timeval {
        tv_sec: 0,
        tv_usec: 100_000,
    };
    if unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_RCVTIMEO,
            std::ptr::addr_of!(timeout).cast(),
            std::mem::size_of_val(&timeout) as _,
        )
    } < 0
    {
        return Err(io::Error::last_os_error());
    }
    let request = route_request(key);
    let mut kernel: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
    kernel.nl_family = libc::AF_NETLINK as _;
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
    let mut sender: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
    let mut sender_len = std::mem::size_of_val(&sender) as libc::socklen_t;
    let len = unsafe {
        libc::recvfrom(
            socket.as_raw_fd(),
            reply.as_mut_ptr().cast(),
            reply.len(),
            libc::MSG_TRUNC,
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
    if unsafe { libc::if_indextoname(index, name.as_mut_ptr()) }.is_null() {
        return Err(io::Error::last_os_error());
    }
    let name = unsafe { std::ffi::CStr::from_ptr(name.as_ptr()) }
        .to_str()
        .map_err(|_| invalid_route())?;
    let mtu = super::interface_mtu(name).ok_or_else(|| {
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
    let mut request = vec![0u8; 28]; // nlmsghdr + rtmsg
    request[4..6].copy_from_slice(&26u16.to_ne_bytes()); // RTM_GETROUTE
    request[6..8].copy_from_slice(&1u16.to_ne_bytes()); // NLM_F_REQUEST
    request[8..12].copy_from_slice(&1u32.to_ne_bytes());
    request[16] = if v6 { libc::AF_INET6 } else { libc::AF_INET } as u8;
    request[17] = if v6 { 128 } else { 32 };
    request[19] = key.tos & 0xfc;
    fn ip_bytes(ip: std::net::IpAddr) -> Vec<u8> {
        match ip {
            std::net::IpAddr::V4(v) => v.octets().to_vec(),
            std::net::IpAddr::V6(v) => v.octets().to_vec(),
        }
    }
    attr(&mut request, 1, &ip_bytes(key.target.ip())); // RTA_DST
    if !key.local.ip().is_unspecified() {
        request[18] = request[17];
        attr(&mut request, 2, &ip_bytes(key.local.ip())); // RTA_SRC
    }
    if let SocketAddr::V6(v) = key.target {
        if v.scope_id() != 0 {
            attr(&mut request, 4, &v.scope_id().to_ne_bytes());
        }
    }
    attr(&mut request, 25, &unsafe { libc::geteuid() }.to_ne_bytes()); // RTA_UID
    attr(&mut request, 27, &[libc::IPPROTO_UDP as u8]);
    attr(&mut request, 28, &key.local.port().to_be_bytes());
    attr(&mut request, 29, &key.target.port().to_be_bytes());
    let len = request.len() as u32;
    request[..4].copy_from_slice(&len.to_ne_bytes());
    request
}

#[cfg(target_os = "linux")]
fn invalid_route() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "invalid route MTU response")
}

#[cfg(target_os = "linux")]
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
fn parse_route(bytes: &[u8]) -> io::Result<(u32, Option<u32>, u32)> {
    if bytes.len() < 20 {
        return Err(invalid_route());
    }
    let len = u32::from_ne_bytes(bytes[..4].try_into().unwrap()) as usize;
    if len > bytes.len() || len < 20 || bytes[8..12] != 1u32.to_ne_bytes() {
        return Err(invalid_route());
    }
    let kind = u16::from_ne_bytes(bytes[4..6].try_into().unwrap());
    if kind == 2 {
        // NLMSG_ERROR
        let error = i32::from_ne_bytes(bytes[16..20].try_into().unwrap());
        return Err(if error < 0 {
            io::Error::from_raw_os_error(error.saturating_neg())
        } else {
            invalid_route()
        });
    }
    if kind != 24 || len < 28 {
        return Err(invalid_route());
    } // RTM_NEWROUTE
    let mut index = None;
    let mut mtu = None;
    let mut encap_type = None;
    let mut encap = None;
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

#[cfg(test)]
mod tests {
    use super::*;

    fn key(port: u16) -> RouteKey {
        RouteKey {
            local: "0.0.0.0:862".parse().unwrap(),
            target: SocketAddr::from(([127, 0, 0, 1], port)),
            tos: 184,
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

    #[cfg(target_os = "linux")]
    #[test]
    fn route_request_carries_udp_flow_and_ipv6_scope() {
        let key = RouteKey {
            local: "[fe80::2]:862".parse().unwrap(),
            target: "[fe80::3%7]:5000".parse().unwrap(),
            tos: 187,
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
            };
            assert!(route_mtu(&key).unwrap() >= 1280, "{key:?}");
        }
    }

    #[test]
    fn srh_budget_uses_first_hop_and_subtracts_all_header_bytes() {
        let local = "[::]:862".parse().unwrap();
        let target = "[2001:db8::9]:5000".parse().unwrap();
        let options = SendOptions {
            tos: 0,
            source: Some("2001:db8::2".parse().unwrap()),
            srh: crate::srv6::build_srh(&[
                "2001:db8::1".parse().unwrap(),
                "2001:db8::9".parse().unwrap(),
            ]),
            dont_fragment: true,
        };
        let (key, overhead) = route_key(local, target, &options).unwrap();
        assert_eq!(key.local, "[2001:db8::2]:862".parse().unwrap());
        assert_eq!(key.target, "[2001:db8::1]:5000".parse().unwrap());
        assert_eq!(
            usize::from(super::super::mtu_payload_cap(1500, true)) - overhead,
            1500 - 40 - 8 - 40
        );
        let mut invalid = options;
        invalid.srh = Some(vec![]);
        assert!(route_key(local, target, &invalid).is_err());
    }
}
