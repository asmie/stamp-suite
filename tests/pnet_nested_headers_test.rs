//! Nested IP capture through the actual pnet receiver and independent bytes.
#![cfg(all(target_os = "linux", feature = "ttl-pnet", not(feature = "ttl-nix")))]
#[path = "common/hops.rs"]
mod hops;
#[path = "common/reflector.rs"]
mod reflector;
#[path = "common/wire_hmac.rs"]
mod wire_hmac;

use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket},
    time::Duration,
};
const KEY: [u8; 16] = [0xab; 16];

fn checksum(bytes: &[u8]) -> u16 {
    let mut sum = bytes
        .chunks(2)
        .map(|p| (u32::from(p[0]) << 8) + u32::from(*p.get(1).unwrap_or(&0)))
        .sum::<u32>();
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}
fn frame(value: &[u8]) -> Vec<u8> {
    let mut bytes = vec![0x80, 247];
    bytes.extend_from_slice(&(value.len() as u16).to_be_bytes());
    bytes.extend_from_slice(value);
    bytes
}
fn request(mode: u8, seq: u32, lengths: &[usize]) -> Vec<u8> {
    let base = if mode == 2 { 112 } else { 44 };
    let mut bytes = vec![0; base];
    bytes[..4].copy_from_slice(&seq.to_be_bytes());
    bytes[if mode == 2 { 25 } else { 13 }] = 1;
    for len in lengths {
        bytes.extend(frame(&vec![0; *len]));
    }
    if mode != 0 {
        let covered = [&bytes[..4], &bytes[base..]].concat();
        bytes.extend_from_slice(&[0x80, 8, 0, 16]);
        bytes.extend_from_slice(&wire_hmac::digest(&KEY, &covered));
    }
    if mode == 2 {
        let digest = wire_hmac::digest(&KEY, &bytes[..96]);
        bytes[96..112].copy_from_slice(&digest);
    }
    bytes
}

fn envelope(
    chain: &[u8],
    source: SocketAddr,
    port: u16,
    payload: &[u8],
    bad_checksum: bool,
) -> (Vec<u8>, Vec<Vec<u8>>) {
    let len = (payload.len() + 8) as u16;
    let mut udp = [
        source.port().to_be_bytes(),
        port.to_be_bytes(),
        len.to_be_bytes(),
        [0; 2],
    ]
    .concat();
    udp.extend_from_slice(payload);
    let mut pseudo = match source.ip() {
        IpAddr::V4(src) => [
            src.octets().as_slice(),
            Ipv4Addr::LOCALHOST.octets().as_slice(),
            &[0, 17],
            &len.to_be_bytes(),
        ]
        .concat(),
        IpAddr::V6(src) => [
            src.octets().as_slice(),
            Ipv6Addr::LOCALHOST.octets().as_slice(),
            &u32::from(len).to_be_bytes(),
            &[0, 0, 0, 17],
        ]
        .concat(),
    };
    pseudo.extend_from_slice(&udp);
    let sum = checksum(&pseudo);
    udp[6..8].copy_from_slice(&if sum == 0 { u16::MAX } else { sum }.to_be_bytes());
    if bad_checksum {
        udp[6] ^= 0x80;
    }
    let mut wire = udp;
    let mut headers = Vec::new();
    for (index, version) in chain.iter().enumerate().rev() {
        let inner = index + 1 == chain.len();
        let protocol = if inner {
            17
        } else if chain[index + 1] == 4 {
            4
        } else {
            41
        };
        let hop = if inner { 37 } else { 47 + index as u8 };
        let header = if *version == 4 {
            let mut h = vec![0; 20];
            h[0] = 0x45;
            h[2..4].copy_from_slice(&((20 + wire.len()) as u16).to_be_bytes());
            h[4..6].copy_from_slice(&(0x1200 + index as u16).to_be_bytes());
            h[8] = hop;
            h[9] = protocol;
            h[12..16].copy_from_slice(&[127, 0, 0, if inner { 1 } else { 2 }]);
            h[16..20].copy_from_slice(&[127, 0, 0, 1]);
            let sum = checksum(&h);
            h[10..12].copy_from_slice(&sum.to_be_bytes());
            h
        } else {
            let mut h = vec![0; 40];
            h[0] = 0x60;
            h[2] = 0x10;
            h[3] = 0x20 + index as u8;
            h[4..6].copy_from_slice(&(wire.len() as u16).to_be_bytes());
            h[6] = protocol;
            h[7] = hop;
            h[23] = if inner { 1 } else { 2 };
            h[39] = 1;
            h
        };
        wire = [header.as_slice(), &wire].concat();
        headers.insert(0, header);
    }
    (wire, headers)
}

fn inject(version: u8, wire: &[u8]) {
    let target = SocketAddr::new(
        if version == 4 {
            Ipv4Addr::LOCALHOST.into()
        } else {
            Ipv6Addr::LOCALHOST.into()
        },
        0,
    );
    let socket = socket2::Socket::new(
        socket2::Domain::for_address(target),
        socket2::Type::from(libc::SOCK_RAW),
        Some(socket2::Protocol::from(libc::IPPROTO_RAW)),
    )
    .unwrap();
    assert_eq!(socket.send_to(wire, &target.into()).unwrap(), wire.len());
}

fn verify(peer: &UdpSocket, port: u16, mode: u8, seq: u32, headers: &[Vec<u8>]) {
    peer.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    let (reply, source, hops) = hops::receive(peer);
    assert_eq!(
        source,
        SocketAddr::new(peer.local_addr().unwrap().ip(), port)
    );
    assert_eq!(hops, 255);
    let base = if mode == 2 { 112 } else { 44 };
    let offset = if mode == 2 { 48 } else { 24 };
    assert_eq!(&reply[offset..offset + 4], &seq.to_be_bytes());
    assert_eq!(
        reply[if mode == 2 { 80 } else { 40 }],
        37,
        "innermost hop count"
    );
    let mut expected = Vec::new();
    for header in headers {
        let mut tlv = frame(header);
        tlv[0] = 0;
        expected.extend(tlv);
    }
    if mode != 0 {
        let covered = [&reply[..4], &expected].concat();
        expected.extend_from_slice(&[0, 8, 0, 16]);
        expected.extend_from_slice(&wire_hmac::digest(&KEY, &covered));
    }
    assert_eq!(
        &reply[base..],
        expected,
        "outer-to-inner fixed header bytes must survive capture and dispatch"
    );
    if mode == 2 {
        assert_eq!(&reply[96..112], &wire_hmac::digest(&KEY, &reply[..96]));
    }
}

fn quiet(peer: &UdpSocket) {
    peer.set_read_timeout(Some(Duration::from_millis(60)))
        .unwrap();
    assert!(matches!(
        peer.recv_from(&mut [0; 2048]).unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
    ));
}

#[test]
#[ignore = "requires STAMP_PNET_HEADER_TESTS=1 inside unshare -Urn"]
fn actual_nested_capture_reflects_outer_to_inner_and_rejects_bad_checksums_and_depth() {
    assert_eq!(std::env::var("STAMP_PNET_HEADER_TESTS").as_deref(), Ok("1"));
    assert_ne!(
        std::fs::read_link("/proc/self/ns/net")
            .unwrap()
            .to_str()
            .unwrap(),
        std::env::var("STAMP_PARENT_NETNS").unwrap()
    );
    for args in [
        vec!["link", "set", "lo", "up"],
        vec!["-6", "addr", "add", "::2/128", "dev", "lo", "nodad"],
    ] {
        assert!(std::process::Command::new("ip")
            .args(args)
            .status()
            .unwrap()
            .success());
    }
    for mode in 0..3 {
        for strict in [false, true] {
            let mut command = reflector::Reflector::command("::1");
            command.args([
                "--interface",
                "lo",
                "--hwtstamp",
                "off",
                "--reflect-fixed-header-from",
                "127.0.0.1",
                "--reflect-fixed-header-from",
                "::1",
            ]);
            if mode != 0 {
                command.args([
                    "--hmac-key",
                    "abababababababababababababababab",
                    "--verify-tlv-hmac",
                ]);
            }
            if mode == 2 {
                command.args(["--auth-mode", "A"]);
            }
            if strict {
                command.arg("--strict-packets");
            }
            let child = reflector::Reflector::spawn(command).unwrap();
            for (seq, chain) in [
                vec![4, 4],
                vec![4, 6],
                vec![6, 4],
                vec![6, 6],
                vec![4, 6, 4],
                vec![6, 4, 6],
            ]
            .into_iter()
            .enumerate()
            {
                let peer = hops::socket(if chain.last() == Some(&4) {
                    "127.0.0.1"
                } else {
                    "::1"
                });
                let lengths = chain
                    .iter()
                    .map(|v| if *v == 4 { 20 } else { 40 })
                    .collect::<Vec<_>>();
                let packet = request(mode, seq as u32, &lengths);
                let (bad, _) = envelope(
                    &chain,
                    peer.local_addr().unwrap(),
                    child.address.port(),
                    &packet,
                    true,
                );
                inject(chain[0], &bad);
                quiet(&peer);
                let (wire, headers) = envelope(
                    &chain,
                    peer.local_addr().unwrap(),
                    child.address.port(),
                    &packet,
                    false,
                );
                inject(chain[0], &wire);
                verify(&peer, child.address.port(), mode, seq as u32, &headers);
            }
            let peer = hops::socket("::1");
            let packet = request(mode, 99, &[40]);
            let (deep, _) = envelope(
                &[6; 32],
                peer.local_addr().unwrap(),
                child.address.port(),
                &packet,
                false,
            );
            inject(6, &deep);
            quiet(&peer);
            let packet = request(mode, 100, &[40, 40]);
            let (wire, headers) = envelope(
                &[6, 6],
                peer.local_addr().unwrap(),
                child.address.port(),
                &packet,
                false,
            );
            inject(6, &wire);
            verify(&peer, child.address.port(), mode, 100, &headers);
        }
    }
}
