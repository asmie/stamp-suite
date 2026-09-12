//! Draft ext-hdr-13 §3.1 endpoint and outgoing-hop policy.
use std::{
    io,
    net::{SocketAddr, UdpSocket},
};

pub(crate) fn set_hops(socket: &UdpSocket) -> io::Result<()> {
    let sock = socket2::SockRef::from(socket);
    if socket.local_addr()?.is_ipv6() {
        sock.set_unicast_hops_v6(255)?;
        // Darwin's IPV6_UNICAST_HOPS also sets the TTL for IPv4-mapped
        // traffic. Its IPv6 socket option handler rejects IPPROTO_IP options.
        #[cfg(not(target_os = "macos"))]
        if !sock.only_v6()? {
            // IPv4-mapped traffic uses the IPv4 TTL even on this socket.
            sock.set_ttl_v4(255)?;
        }
        Ok(())
    } else {
        sock.set_ttl_v4(255)
    }
}

/// Randomized dynamic-port binding. Avoid the peer's listening port so
/// reverse-direction requests cannot be confused with reflected packets.
pub(crate) fn bind_sender(local: SocketAddr, remote: SocketAddr) -> io::Result<UdpSocket> {
    bind_sender_with(
        local,
        remote,
        || {
            let mut random = [0u8; 2];
            getrandom::fill(&mut random).map_err(io::Error::other)?;
            Ok(49152 + (u16::from_ne_bytes(random) & 0x3fff))
        },
        UdpSocket::bind,
        cfg!(windows),
    )
}

// Inject port selection and binding so platform error handling is deterministic
// in tests, without reserving host ports or changing kernel socket policy.
fn bind_sender_with<T>(
    mut local: SocketAddr,
    remote: SocketAddr,
    mut next_port: impl FnMut() -> io::Result<u16>,
    mut bind: impl FnMut(SocketAddr) -> io::Result<T>,
    windows: bool,
) -> io::Result<T> {
    if local.port() != 0 {
        if local.port() == remote.port() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "sender local and remote ports must differ",
            ));
        }
        return bind(local);
    }
    let mut last_error = None;
    for _ in 0..128 {
        let port = next_port()?;
        if port == remote.port() {
            continue;
        }
        local.set_port(port);
        match bind(local) {
            Ok(socket) => return Ok(socket),
            // Winsock can report a conflicting/exclusively held port as
            // WSAEACCES (10013), not just WSAEADDRINUSE. Only automatic port
            // selection may try a different candidate after that error.
            Err(e)
                if e.kind() == io::ErrorKind::AddrInUse
                    || (windows && e.raw_os_error() == Some(10013)) =>
            {
                last_error = Some(e);
            }
            Err(e) => return Err(e),
        }
    }
    Err(last_error.unwrap_or_else(|| {
        io::Error::new(
            io::ErrorKind::AddrInUse,
            "could not allocate a randomized dynamic STAMP port",
        )
    }))
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    #[test]
    fn dual_stack_hop_policy_covers_ipv4_mapped_traffic() {
        let socket = UdpSocket::bind("[::]:0").unwrap();
        set_hops(&socket).unwrap();
        let sock = socket2::SockRef::from(&socket);
        assert_eq!(sock.unicast_hops_v6().unwrap(), 255);
        if !sock.only_v6().unwrap() {
            assert_eq!(sock.ttl_v4().unwrap(), 255);
        }
    }
}

#[cfg(test)]
mod bind_tests {
    use super::*;

    #[test]
    fn automatic_binding_skips_peer_denied_and_busy_ports_for_both_families() {
        for address in ["127.0.0.1:0", "[::1]:0"] {
            let local: SocketAddr = address.parse().unwrap();
            let mut remote = local;
            remote.set_port(55000);
            let mut ports = [55000, 55001, 55002, 55003].into_iter();
            let mut attempted = Vec::new();
            let bound = bind_sender_with(
                local,
                remote,
                || Ok(ports.next().unwrap()),
                |candidate| {
                    attempted.push(candidate.port());
                    assert_eq!(candidate.ip(), local.ip());
                    match candidate.port() {
                        55001 => Err(io::Error::from_raw_os_error(10013)),
                        55002 => Err(io::Error::from(io::ErrorKind::AddrInUse)),
                        55003 => Ok(candidate),
                        _ => panic!("must not bind peer's port"),
                    }
                },
                true,
            )
            .unwrap();
            assert_eq!(bound.port(), 55003);
            assert_eq!(attempted, [55001, 55002, 55003]);
        }
    }

    #[test]
    fn explicit_port_error_is_returned_without_random_selection_or_retry() {
        for address in ["127.0.0.1:55001", "[::1]:55001"] {
            let local: SocketAddr = address.parse().unwrap();
            let mut remote = local;
            remote.set_port(55000);
            let mut attempts = 0;
            let error = bind_sender_with::<()>(
                local,
                remote,
                || panic!("explicit port must not be randomized"),
                |candidate| {
                    assert_eq!(candidate, local);
                    attempts += 1;
                    Err(io::Error::from_raw_os_error(10013))
                },
                true,
            )
            .unwrap_err();
            assert_eq!(error.raw_os_error(), Some(10013));
            assert_eq!(attempts, 1);
        }
    }

    #[test]
    fn other_errors_and_non_windows_access_denials_are_not_retried() {
        for (windows, code) in [(false, 10013), (true, 10049), (true, 10022)] {
            let mut attempts = 0;
            let error = bind_sender_with::<()>(
                "127.0.0.1:0".parse().unwrap(),
                "127.0.0.1:55000".parse().unwrap(),
                || Ok(55001),
                |_| {
                    attempts += 1;
                    Err(io::Error::from_raw_os_error(code))
                },
                windows,
            )
            .unwrap_err();
            assert_eq!(error.raw_os_error(), Some(code));
            assert_eq!(attempts, 1);
        }
    }

    #[test]
    fn retries_are_bounded_and_preserve_last_bind_error() {
        let mut attempts = 0;
        let error = bind_sender_with::<()>(
            "[::1]:0".parse().unwrap(),
            "[::1]:55000".parse().unwrap(),
            || Ok(55001),
            |_| {
                attempts += 1;
                Err(io::Error::from_raw_os_error(10013))
            },
            true,
        )
        .unwrap_err();
        assert_eq!(attempts, 128);
        assert_eq!(error.raw_os_error(), Some(10013));
    }

    #[test]
    fn invalid_explicit_peer_port_and_randomness_failure_never_bind() {
        let peer: SocketAddr = "127.0.0.1:55000".parse().unwrap();
        let error = bind_sender_with::<()>(
            peer,
            peer,
            || panic!("must reject matching explicit ports"),
            |_| panic!("must not bind"),
            true,
        )
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        let error = bind_sender_with::<()>(
            "127.0.0.1:0".parse().unwrap(),
            peer,
            || Err(io::Error::other("random source unavailable")),
            |_| panic!("must not bind"),
            true,
        )
        .unwrap_err();
        assert_eq!(error.to_string(), "random source unavailable");
    }
}
