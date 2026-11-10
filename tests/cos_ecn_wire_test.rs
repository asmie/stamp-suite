//! Independent CoS bytes, ingress/reply markings, policies and burst isolation.
#![cfg(all(
    target_os = "linux",
    any(feature = "ttl-nix", not(feature = "ttl-pnet"))
))]

#[path = "common/reflector.rs"]
mod reflector;
#[path = "common/wire_hmac.rs"]
mod wire_hmac;
use nix::sys::socket::{recvmsg, ControlMessageOwned, MsgFlags, SockaddrStorage};
use reflector::Reflector;
use std::{net::UdpSocket, os::fd::AsRawFd, time::Duration};

const KEY: [u8; 16] = [0xab; 16];

fn request(mode: u8, sequence: u32, cos: Option<[u8; 4]>) -> Vec<u8> {
    let base = if mode == 2 { 112 } else { 44 };
    let error = if mode == 2 { 24 } else { 12 };
    let mut bytes = vec![0; base];
    bytes[..4].copy_from_slice(&sequence.to_be_bytes());
    bytes[error + 1] = 1;
    bytes[error + 2..error + 4].copy_from_slice(&42u16.to_be_bytes());
    if let Some(value) = cos {
        bytes.extend_from_slice(&[0x80, 4, 0, 4]);
        bytes.extend_from_slice(&value);
        bytes.extend_from_slice(&[0x80, 12, 0, 12, 0, 0, 0, 3]);
        bytes.extend_from_slice(&20_000_000u32.to_be_bytes());
        bytes.extend_from_slice(&[0; 4]);
        if mode != 0 {
            let mut covered = bytes[..4].to_vec();
            covered.extend_from_slice(&bytes[base..]);
            let digest = wire_hmac::digest(&KEY, &covered);
            bytes.extend_from_slice(&[0x80, 8, 0, 16]);
            bytes.extend_from_slice(&digest);
        }
    }
    if mode == 2 {
        let digest = wire_hmac::digest(&KEY, &bytes[..96]);
        bytes[96..112].copy_from_slice(&digest);
    }
    bytes
}

fn socket_option(socket: &UdpSocket, ipv6: bool, receive: bool, value: i32) {
    let (level, option) = match (ipv6, receive) {
        (false, false) => (libc::IPPROTO_IP, libc::IP_TOS),
        (false, true) => (libc::IPPROTO_IP, libc::IP_RECVTOS),
        (true, false) => (libc::IPPROTO_IPV6, libc::IPV6_TCLASS),
        (true, true) => (libc::IPPROTO_IPV6, libc::IPV6_RECVTCLASS),
    };
    // SAFETY: the socket owns the live fd, and value is an aligned live i32
    // matching these Linux options, with its actual size passed to the kernel.
    let result = unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            level,
            option,
            (&value as *const i32).cast(),
            std::mem::size_of_val(&value) as _,
        )
    };
    assert_eq!(result, 0, "{}", std::io::Error::last_os_error());
}

fn receive(socket: &UdpSocket) -> (Vec<u8>, u8) {
    let mut data = [0; 1024];
    let mut iov = [std::io::IoSliceMut::new(&mut data)];
    let mut control = nix::cmsg_space!(u8, i32);
    let message = recvmsg::<SockaddrStorage>(
        socket.as_raw_fd(),
        &mut iov,
        Some(&mut control),
        MsgFlags::empty(),
    )
    .unwrap();
    assert!(!message
        .flags
        .intersects(MsgFlags::MSG_TRUNC | MsgFlags::MSG_CTRUNC));
    let tos = message
        .cmsgs()
        .unwrap()
        .find_map(|c| match c {
            ControlMessageOwned::Ipv4Tos(n) => Some(n),
            ControlMessageOwned::Ipv6TClass(n) => Some(n as u8),
            _ => None,
        })
        .expect("actual received IP TOS/Traffic Class metadata");
    let length = message.bytes;
    (data[..length].to_vec(), tos)
}

fn verify_cos_reply(bytes: &[u8], mode: u8, expected: [u8; 4]) {
    let base = if mode == 2 { 112 } else { 44 };
    assert_eq!(
        &bytes[base..base + 8],
        &[
            0,
            4,
            0,
            4,
            expected[0],
            expected[1],
            expected[2],
            expected[3]
        ]
    );
    assert_eq!(&bytes[base + 8..base + 12], &[0, 12, 0, 12]);
    let expected_length = base + 24 + if mode == 0 { 0 } else { 20 };
    assert_eq!(bytes.len(), expected_length);
    if mode != 0 {
        let pos = bytes.len() - 20;
        assert_eq!(&bytes[pos..pos + 4], &[0, 8, 0, 16]);
        let mut covered = bytes[..4].to_vec();
        covered.extend_from_slice(&bytes[base..pos]);
        assert_eq!(&bytes[pos + 4..], &wire_hmac::digest(&KEY, &covered));
    }
    if mode == 2 {
        assert_eq!(&bytes[96..112], &wire_hmac::digest(&KEY, &bytes[..96]));
    }
}

#[test]
fn reflector_cos_bytes_and_wire_markings_follow_ingress_and_admission_policy() {
    for (ip, peer_ip, prefix) in [
        ("127.0.0.1", "127.0.0.2", "127.0.0.2/32"),
        ("::1", "::1", "::1/128"),
    ] {
        let ipv6 = ip == "::1";
        for mode in 0..3 {
            // Global allow/deny, scoped overrides, all ECN codepoints and
            // both DSCP2 high bits are exercised independently of DSCP1.
            for (policy, received_dscp, received_ecn, requested_ecn, rejected_dscp, rejected_ecn) in [
                (0, 51u8, 1u8, 2u8, false, false),
                (1, 10, 3, 1, true, false),
                (2, 51, 2, 1, false, true),
                (3, 10, 1, 2, true, true),
                (4, 51, 0, 0, false, false),
                (5, 10, 2, 3, true, false),
                (0, 51, 3, 3, false, false),
            ] {
                let mut command = Reflector::command(ip);
                command.args([
                    "--hwtstamp",
                    "off",
                    "--stateful-reflector",
                    "--reflected-control-max-count",
                    "3",
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
                if matches!(policy, 1 | 3 | 4) {
                    command.args(["--allowed-dscp", "0"]);
                }
                if matches!(policy, 2 | 3) {
                    command.args(["--allowed-ecn", "0"]);
                }
                if policy == 4 {
                    command.args(["--allowed-dscp-for", &format!("{prefix}=46")]);
                }
                if policy == 5 {
                    command.args(["--allowed-dscp-for", &format!("{prefix}=0")]);
                }
                let reflector = Reflector::spawn(command).unwrap();
                let peer = UdpSocket::bind((peer_ip, 0)).unwrap();
                peer.connect(reflector.address).unwrap();
                peer.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
                socket_option(&peer, ipv6, true, 1);
                socket_option(
                    &peer,
                    ipv6,
                    false,
                    i32::from((received_dscp << 2) | received_ecn),
                );
                // Dirty received DSCP2/EC2/RPD/RPE/Reserved must not influence
                // reports; only DSCP1=46 and EC1 are requests.
                let value = if requested_ecn == 0 {
                    // A genuine RFC-only request: its whole original
                    // sixteen-bit Reserved field is zero.
                    [184, 0, 0, 0]
                } else {
                    [187, 0xff, (requested_ecn << 6) | 0x3f, 0xff]
                };
                peer.send(&request(mode, 100, Some(value))).unwrap();
                let expected_value = [
                    (46 << 2) | (received_dscp >> 4),
                    ((received_dscp & 15) << 4) | (received_ecn << 2) | u8::from(rejected_dscp),
                    (requested_ecn << 6) | (if rejected_ecn { 2 } else { 3 } << 4),
                    0,
                ];
                let reply_dscp = if rejected_dscp { received_dscp } else { 46 };
                let reply_ecn = if rejected_ecn { 0 } else { requested_ecn };
                let expected_tos = (reply_dscp << 2) | reply_ecn;
                let echoed = if mode == 2 { 48 } else { 24 };
                let first = receive(&peer);
                assert_eq!(&first.0[echoed..echoed + 4], &100u32.to_be_bytes());
                verify_cos_reply(&first.0, mode, expected_value);
                assert_eq!(first.1, expected_tos, "{ip} mode={mode} policy={policy}");
                socket_option(&peer, ipv6, false, 0);
                peer.send(&request(mode, 200, None)).unwrap();
                let mut burst = 1;
                let mut ordinary = 0;
                let mut sequences = vec![u32::from_be_bytes(first.0[..4].try_into().unwrap())];
                while burst < 3 || ordinary < 1 {
                    let (bytes, tos) = receive(&peer);
                    let sequence =
                        u32::from_be_bytes(bytes[echoed..echoed + 4].try_into().unwrap());
                    if sequence == 100 {
                        assert!(burst < 3);
                        verify_cos_reply(&bytes, mode, expected_value);
                        assert_eq!(tos, expected_tos, "each copy retains admitted marking");
                        sequences.push(u32::from_be_bytes(bytes[..4].try_into().unwrap()));
                        burst += 1;
                    } else {
                        assert_eq!(sequence, 200);
                        ordinary += 1;
                        assert_eq!(ordinary, 1);
                        assert_eq!(tos, 0, "CoS must not leak into ordinary traffic");
                        assert_eq!(bytes.len(), if mode == 2 { 112 } else { 44 });
                        if mode == 2 {
                            assert_eq!(&bytes[96..112], &wire_hmac::digest(&KEY, &bytes[..96]));
                        }
                    }
                }
                assert!(sequences.windows(2).all(|p| p[0] < p[1]));
            }
        }
    }
}
