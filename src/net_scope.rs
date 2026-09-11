//! Interface zones for IPv6 link-local endpoints. Global addresses keep zone zero.
use std::net::{IpAddr, SocketAddr, SocketAddrV6};

pub(crate) fn received_endpoint(ip: IpAddr, port: u16, interface: u32) -> SocketAddr {
    match ip {
        IpAddr::V6(ip) if ip.is_unicast_link_local() => {
            SocketAddrV6::new(ip, port, 0, interface).into()
        }
        _ => SocketAddr::new(ip, port),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn only_link_local_addresses_inherit_ingress_zone() {
        assert_eq!(
            received_endpoint("fe80::1".parse().unwrap(), 862, 7).to_string(),
            "[fe80::1%7]:862"
        );
        assert_eq!(
            received_endpoint("::1".parse().unwrap(), 862, 7).to_string(),
            "[::1]:862"
        );
        assert_eq!(
            received_endpoint("2001:db8::1".parse().unwrap(), 862, 7).to_string(),
            "[2001:db8::1]:862"
        );
        assert_eq!(
            received_endpoint("127.0.0.1".parse().unwrap(), 862, 7).to_string(),
            "127.0.0.1:862"
        );
    }
}
