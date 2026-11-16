//! Destination-specific IPv6 estimates without sending UDP probes.

use super::RouteKey;
use crate::net_policy::macos_mtu::{egress_mtu, native_unicast};
use std::{io, net::UdpSocket};

pub(super) fn route_mtu(key: &RouteKey) -> io::Result<u32> {
    if key.local.is_ipv4() != key.target.is_ipv4() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "MTU address families differ",
        ));
    }
    if !native_unicast(key.target.ip())
        || key.target.ip().is_unspecified()
        || !native_unicast(key.local.ip())
        || key.oif != 0
    {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "macOS reply MTU lookup requires unpinned native unicast IPv6",
        ));
    }
    // Preserve source/destination addresses and IPv6 zones, but use a temporary
    // local port so the live reflector socket is never connected or rebound.
    // This is a kernel destination-route estimate, not a port-policy lookup.
    let mut local = key.local;
    local.set_port(0);
    let socket = UdpSocket::bind(local)?;
    socket2::SockRef::from(&socket).set_tclass_v6(u32::from(key.tos))?;
    socket.connect(key.target)?;
    egress_mtu(&socket).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::Unsupported,
            "macOS IPv6 reply MTU estimate is unavailable",
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::receiver::{
        mtu::{MtuCache, RouteKey},
        transmit::SendOptions,
    };
    use std::time::{Duration, Instant};

    #[test]
    fn macos_reply_mtu_queries_refresh_and_reject_unsupported_routes() {
        for local in ["[::1]:0", "[::]:0"] {
            let peer = UdpSocket::bind("[::1]:0").unwrap();
            peer.set_read_timeout(Some(Duration::from_millis(20)))
                .unwrap();
            let socket = UdpSocket::bind(local).unwrap();
            let key = RouteKey {
                local: socket.local_addr().unwrap(),
                target: peer.local_addr().unwrap(),
                tos: 0x2e,
                oif: 0,
            };
            let mtu = route_mtu(&key).unwrap();
            assert!(mtu >= 1280);
            let options = SendOptions {
                tos: key.tos,
                apply_tos: true,
                source: None,
                egress_ifindex: None,
                srh: None,
                dont_fragment: true,
            };
            let mut cache = MtuCache::default();
            cache
                .lookup(key.clone(), Instant::now(), false, |_| Ok(128))
                .unwrap();
            for refresh in [false, true] {
                assert_eq!(
                    cache
                        .payload_cap(key.local, key.target, &options, refresh)
                        .unwrap(),
                    usize::from(crate::receiver::mtu_payload_cap(mtu, true))
                );
            }
            assert!(
                peer.recv_from(&mut [0; 1]).is_err(),
                "lookup must not send UDP traffic"
            );
            assert!(
                socket.peer_addr().is_err(),
                "live reflector must remain unconnected"
            );
            let mut pinned = options.clone();
            pinned.egress_ifindex = Some(1);
            assert_eq!(
                cache
                    .payload_cap(key.local, key.target, &pinned, false)
                    .unwrap_err()
                    .kind(),
                io::ErrorKind::Unsupported
            );
            // A reflector bound with --interface is pinned the same way;
            // Darwin has no estimate for it, so the lookup fails closed.
            let lo0 = ::nix::net::if_::if_nametoindex("lo0").unwrap();
            assert_eq!(
                MtuCache::bound_to(lo0)
                    .payload_cap(key.local, key.target, &options, false)
                    .unwrap_err()
                    .kind(),
                io::ErrorKind::Unsupported
            );
            let mut srh = options.clone();
            srh.srh = Some(std::sync::Arc::from([0u8; 8]));
            assert_eq!(
                cache
                    .payload_cap(key.local, key.target, &srh, false)
                    .unwrap_err()
                    .kind(),
                io::ErrorKind::Unsupported
            );
            let mut bad = key.clone();
            bad.local = "127.0.0.1:0".parse().unwrap();
            assert_eq!(
                route_mtu(&bad).unwrap_err().kind(),
                io::ErrorKind::InvalidInput
            );
            bad.target = "127.0.0.1:9".parse().unwrap();
            assert_eq!(
                route_mtu(&bad).unwrap_err().kind(),
                io::ErrorKind::Unsupported
            );
            bad.local = "[::ffff:127.0.0.1]:0".parse().unwrap();
            bad.target = "[::ffff:127.0.0.1]:9".parse().unwrap();
            assert_eq!(
                route_mtu(&bad).unwrap_err().kind(),
                io::ErrorKind::Unsupported
            );
            bad = key;
            bad.local = "[2001:db8::99]:0".parse().unwrap();
            assert!(
                route_mtu(&bad).is_err(),
                "unassigned sources cannot get a guessed budget"
            );
        }
    }
}
