//! A nix reflector bound to `::` on Linux answers IPv4 clients through the
//! dual-stack socket, with their real TTL and DSCP (RFC 8762 §4.3.1,
//! RFC 8972 §4.4).
#![cfg(all(
    target_os = "linux",
    any(feature = "ttl-nix", not(feature = "ttl-pnet"))
))]
#[path = "common/hops.rs"]
mod hops;
#[path = "common/reflector.rs"]
mod reflector;

use reflector::Reflector;

/// Sender TTL echoed in an open-mode reply.
const SENDER_TTL: usize = 40;

#[test]
fn wildcard_ipv6_reflector_answers_ipv4_with_its_ttl_and_dscp() {
    // With bindv6only set, `::` is IPv6-only and IPv4 never reaches it.
    let v6only = std::fs::read_to_string("/proc/sys/net/ipv6/bindv6only").unwrap();
    if v6only.trim() != "0" {
        eprintln!("net.ipv6.bindv6only={} makes `::` IPv6-only", v6only.trim());
        return;
    }
    let reflector = Reflector::spawn(Reflector::command("::")).unwrap();
    let peer = hops::socket("127.0.0.1");
    let sock = socket2::SockRef::from(&peer);
    sock.set_ttl_v4(37).unwrap();
    sock.set_tos_v4(46 << 2).unwrap();

    // Open-mode base packet with a CoS TLV that requests DSCP 0, so the
    // reply's DSCP2 reports what actually arrived.
    let mut request = vec![0; 44];
    request[..4].copy_from_slice(&7u32.to_be_bytes());
    request[13] = 1;
    request.extend_from_slice(&[0x80, 4, 0, 4, 0, 0, 0, 0]);
    peer.send_to(&request, ("127.0.0.1", reflector.address.port()))
        .unwrap();

    let (reply, source, hops) = hops::receive(&peer);
    assert_eq!(source.ip().to_string(), "127.0.0.1");
    assert_eq!(hops, 255, "reply TTL");
    assert_eq!(&reply[24..28], &7u32.to_be_bytes(), "echoed sequence");
    assert_eq!(reply[SENDER_TTL], 37, "IPv4 TTL from the dual-stack socket");
    let cos = &reply[44 + 4..44 + 8];
    let dscp2 = ((cos[0] & 0x3) << 4) | (cos[1] >> 4);
    assert_eq!(dscp2, 46, "IPv4 DSCP from the dual-stack socket");
}
