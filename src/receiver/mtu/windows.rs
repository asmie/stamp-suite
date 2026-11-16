//! Read-only IP Helper queries. No traffic or host route changes are generated.

use super::RouteKey;
use std::{io, net::SocketAddr};
use windows_sys::Win32::{
    NetworkManagement::IpHelper::{
        GetBestRoute2, GetIpInterfaceEntry, GetIpPathEntry, MIB_IPFORWARD_ROW2,
        MIB_IPINTERFACE_ROW, MIB_IPPATH_ROW,
    },
    Networking::WinSock::{
        AF_INET, AF_INET6, IN6_ADDR, IN6_ADDR_0, IN_ADDR, IN_ADDR_0, SOCKADDR_IN, SOCKADDR_IN6,
        SOCKADDR_IN6_0, SOCKADDR_INET,
    },
};

fn address(address: SocketAddr) -> SOCKADDR_INET {
    // IP Helper selects by IP/interface; ports and flowinfo stay zero. Preserve
    // the IPv6 zone so a link-local destination cannot select another link.
    match address {
        SocketAddr::V4(address) => SOCKADDR_INET {
            Ipv4: SOCKADDR_IN {
                sin_family: AF_INET,
                sin_addr: IN_ADDR {
                    S_un: IN_ADDR_0 {
                        S_addr: u32::from_ne_bytes(address.ip().octets()),
                    },
                },
                ..Default::default()
            },
        },
        SocketAddr::V6(address) => SOCKADDR_INET {
            Ipv6: SOCKADDR_IN6 {
                sin6_family: AF_INET6,
                sin6_addr: IN6_ADDR {
                    u: IN6_ADDR_0 {
                        Byte: address.ip().octets(),
                    },
                },
                Anonymous: SOCKADDR_IN6_0 {
                    sin6_scope_id: address.scope_id(),
                },
                ..Default::default()
            },
        },
    }
}

fn check(result: u32) -> io::Result<()> {
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::from_raw_os_error(result as i32))
    }
}

pub(super) fn route_mtu(key: &RouteKey) -> io::Result<u32> {
    if key.local.is_ipv4() != key.target.is_ipv4() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "MTU address families differ",
        ));
    }
    if key.oif != 0 {
        // The Windows transport cannot pin the outgoing interface. Refuse the
        // constrained estimate so the existing Return Path fallback marks U.
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "Windows reply interface pinning is unavailable",
        ));
    }
    let destination = address(key.target);
    let source = address(key.local);
    let source_ptr = if key.local.ip().is_unspecified() {
        std::ptr::null()
    } else {
        std::ptr::from_ref(&source)
    };
    let mut route = MIB_IPFORWARD_ROW2::default();
    let mut best_source = SOCKADDR_INET::default();
    // SAFETY: all pointers refer to correctly initialized live structures of
    // the documented type; null requests automatic interface/source selection.
    check(unsafe {
        GetBestRoute2(
            std::ptr::null(),
            0,
            source_ptr,
            &destination,
            0,
            &mut route,
            &mut best_source,
        )
    })?;
    let mut path = MIB_IPPATH_ROW {
        Source: if source_ptr.is_null() {
            best_source
        } else {
            source
        },
        Destination: destination,
        InterfaceLuid: route.InterfaceLuid,
        ..Default::default()
    };
    // SAFETY: path has the selected interface and same-family source/target;
    // it remains live and writable for the call.
    check(unsafe { GetIpPathEntry(&mut path) })?;
    let mut interface = MIB_IPINTERFACE_ROW {
        Family: if key.target.is_ipv6() {
            AF_INET6
        } else {
            AF_INET
        },
        InterfaceLuid: route.InterfaceLuid,
        ..Default::default()
    };
    // SAFETY: interface identifies the selected LUID/family and is writable
    // for its complete C structure size throughout the call.
    check(unsafe { GetIpInterfaceEntry(&mut interface) })?;
    let mtu = path.PathMtu.min(interface.NlMtu);
    if mtu == 0 {
        return Err(super::super::transmit::local_send_error(io::Error::new(
            io::ErrorKind::InvalidData,
            "Windows returned a zero MTU",
        )));
    }
    Ok(mtu)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::receiver::{mtu::MtuCache, transmit::SendOptions};
    use std::{
        net::UdpSocket,
        time::{Duration, Instant},
    };

    #[test]
    fn windows_route_mtu_is_fresh_for_bound_and_wildcard_sources() {
        for (local, target) in [
            ("0.0.0.0:0", "127.0.0.1:0"),
            ("127.0.0.1:0", "127.0.0.1:0"),
            ("[::]:0", "[::1]:0"),
            ("[::1]:0", "[::1]:0"),
        ] {
            let peer = UdpSocket::bind(target).unwrap();
            peer.set_read_timeout(Some(Duration::from_millis(20)))
                .unwrap();
            let socket = UdpSocket::bind(local).unwrap();
            let key = RouteKey {
                local: socket.local_addr().unwrap(),
                target: peer.local_addr().unwrap(),
                tos: 0,
                oif: 0,
            };
            let mtu = route_mtu(&key).unwrap();
            assert!(mtu >= 1280);
            let options = SendOptions {
                tos: 0,
                apply_tos: false,
                source: None,
                egress_ifindex: None,
                srh: None,
                dont_fragment: true,
            };
            let mut cache = MtuCache::default();
            // Plant an unexpired stale value: Windows must query again even
            // when the caller did not request an EMSGSIZE refresh.
            cache
                .lookup(key.clone(), Instant::now(), false, |_| Ok(128))
                .unwrap();
            for refresh in [false, true] {
                assert_eq!(
                    cache
                        .payload_cap(key.local, key.target, &options, refresh)
                        .unwrap(),
                    usize::from(crate::receiver::mtu_payload_cap(mtu, key.target.is_ipv6()))
                );
            }
            assert!(
                peer.recv_from(&mut [0; 1]).is_err(),
                "route lookup must not send traffic"
            );
            let mut bad = key.clone();
            bad.oif = 1;
            assert_eq!(
                route_mtu(&bad).unwrap_err().kind(),
                io::ErrorKind::Unsupported
            );
            bad = key.clone();
            bad.local.set_ip(
                if key.target.is_ipv4() {
                    "::1"
                } else {
                    "127.0.0.1"
                }
                .parse()
                .unwrap(),
            );
            assert_eq!(
                route_mtu(&bad).unwrap_err().kind(),
                io::ErrorKind::InvalidInput
            );
        }
        let key = RouteKey {
            local: "192.0.2.99:0".parse().unwrap(),
            target: "127.0.0.1:0".parse().unwrap(),
            tos: 0,
            oif: 0,
        };
        assert!(
            route_mtu(&key).is_err(),
            "unassigned source must not get a guessed budget"
        );
    }

    #[test]
    fn windows_route_address_encoding_preserves_family_bytes_and_zone() {
        let v4 = address("192.0.2.7:54321".parse().unwrap());
        let v6 = address("[fe80::1234%17]:54321".parse().unwrap());
        // SAFETY: each union is read using the family explicitly constructed above.
        unsafe {
            assert_eq!(v4.Ipv4.sin_family, AF_INET);
            assert_eq!(v4.Ipv4.sin_addr.S_un.S_addr.to_ne_bytes(), [192, 0, 2, 7]);
            assert_eq!(v4.Ipv4.sin_port, 0);
            assert_eq!(v6.Ipv6.sin6_family, AF_INET6);
            assert_eq!(
                v6.Ipv6.sin6_addr.u.Byte,
                "fe80::1234".parse::<std::net::Ipv6Addr>().unwrap().octets()
            );
            assert_eq!(v6.Ipv6.Anonymous.sin6_scope_id, 17);
            assert_eq!(v6.Ipv6.sin6_port, 0);
        }
    }
}
