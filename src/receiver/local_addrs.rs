//! Local interface addresses and MACs, used to match Destination Node Address
//! TLVs (RFC 9503 §3) and RFC 10052 Address Group sub-TLVs.

/// Returns the list of local IP addresses used for Destination Node Address
/// TLV matching (RFC 9503 §3).
///
/// When `bind_addr` is a wildcard (`0.0.0.0` or `::`), enumerates every
/// interface address on the system. Otherwise returns just `bind_addr`.
///
/// Interface enumeration uses the `nix` crate on Unix and `pnet::datalink` on
/// Windows — both produce the same logical output.
pub fn build_local_addresses(bind_addr: std::net::IpAddr) -> Vec<std::net::IpAddr> {
    let is_wildcard = match bind_addr {
        std::net::IpAddr::V4(v4) => v4.is_unspecified(),
        std::net::IpAddr::V6(v6) => v6.is_unspecified(),
    };
    if !is_wildcard {
        return vec![bind_addr];
    }

    let addrs = enumerate_interface_addresses();
    if addrs.is_empty() {
        log::warn!(
            "Could not enumerate local addresses; Destination Node Address matching may fail"
        );
        vec![bind_addr]
    } else {
        addrs
    }
}

#[cfg(unix)]
pub(super) fn enumerate_interface_addresses() -> Vec<std::net::IpAddr> {
    let mut addrs = Vec::new();
    if let Ok(ifaddrs) = ::nix::ifaddrs::getifaddrs() {
        for ifaddr in ifaddrs {
            if let Some(addr) = ifaddr.address {
                if let Some(v4) = addr.as_sockaddr_in() {
                    addrs.push(std::net::IpAddr::V4(v4.ip()));
                } else if let Some(v6) = addr.as_sockaddr_in6() {
                    addrs.push(std::net::IpAddr::V6(v6.ip()));
                }
            }
        }
    }
    addrs
}

#[cfg(not(unix))]
pub(super) fn enumerate_interface_addresses() -> Vec<std::net::IpAddr> {
    // Windows has no `getifaddrs`; fall back to pnet's datalink enumeration.
    // pnet is always a build dependency on Windows (default ttl-pnet backend).
    // Use absolute `::pnet` so we resolve the external crate, not the
    // sibling `crate::receiver::pnet` submodule.
    ::pnet::datalink::interfaces()
        .into_iter()
        .flat_map(|iface| iface.ips.into_iter().map(|n| n.ip()))
        .collect()
}

/// Enumerates local MAC addresses for L2 Address Group matching
/// (RFC 10052 §3.1.1), regardless of bind address.
/// Returns an empty list on enumeration failure; L2 requests then cannot match.
pub fn build_local_macs() -> Vec<[u8; 6]> {
    let macs = enumerate_interface_macs();
    if macs.is_empty() {
        log::warn!(
            "Could not enumerate local MAC addresses; L2 Address Group sub-TLV \
             requests will never match (packets requesting one will be dropped)"
        );
    }
    macs
}

#[cfg(unix)]
pub(super) fn enumerate_interface_macs() -> Vec<[u8; 6]> {
    // `as_link_addr()` handles Linux AF_PACKET and macOS/BSD AF_LINK.
    let mut macs = Vec::new();
    if let Ok(ifaddrs) = ::nix::ifaddrs::getifaddrs() {
        for ifaddr in ifaddrs {
            if let Some(addr) = ifaddr.address {
                if let Some(link) = addr.as_link_addr() {
                    if let Some(mac) = link.addr() {
                        if mac != [0u8; 6] && !macs.contains(&mac) {
                            macs.push(mac);
                        }
                    }
                }
            }
        }
    }
    macs
}

#[cfg(not(unix))]
pub(super) fn enumerate_interface_macs() -> Vec<[u8; 6]> {
    // Use absolute `::pnet` so we resolve the external crate, not the
    // sibling `crate::receiver::pnet` submodule (see
    // `enumerate_interface_addresses` above for the same convention).
    let mut macs = Vec::new();
    for iface in ::pnet::datalink::interfaces() {
        if let Some(::pnet::util::MacAddr(a, b, c, d, e, f)) = iface.mac {
            let mac = [a, b, c, d, e, f];
            if mac != [0u8; 6] && !macs.contains(&mac) {
                macs.push(mac);
            }
        }
    }
    macs
}
