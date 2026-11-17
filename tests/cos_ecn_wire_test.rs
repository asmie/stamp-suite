//! Independent CoS bytes, ingress/reply markings, policies and burst isolation.
#![cfg(all(
    target_os = "linux",
    any(feature = "ttl-nix", not(feature = "ttl-pnet"))
))]

#[path = "common/case.rs"]
mod case;
#[path = "common/reflector.rs"]
mod reflector;
#[path = "common/wire_hmac.rs"]
mod wire_hmac;
#[path = "common/wire_mode.rs"]
mod wire_mode;
use case::Case;
use nix::sys::socket::{recvmsg, ControlMessageOwned, MsgFlags, SockaddrStorage};
use reflector::Reflector;
use std::{net::UdpSocket, os::fd::AsRawFd, time::Duration};
use wire_mode::Mode;

fn request(mode: Mode, sequence: u32, cos: Option<[u8; 4]>) -> Vec<u8> {
    let mut bytes = mode.request(sequence);
    let ssid = mode.ssid();
    bytes[ssid..ssid + 2].copy_from_slice(&42u16.to_be_bytes());
    if let Some(value) = cos {
        bytes.extend_from_slice(&[0x80, 4, 0, 4]);
        bytes.extend_from_slice(&value);
        bytes.extend_from_slice(&[0x80, 12, 0, 12, 0, 0, 0, 3]);
        bytes.extend_from_slice(&20_000_000u32.to_be_bytes());
        bytes.extend_from_slice(&[0; 4]);
        mode.append_hmac_tlv(&mut bytes);
    }
    mode.seal(&mut bytes);
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

fn verify_cos_reply(bytes: &[u8], mode: Mode, expected: [u8; 4], third: bool) {
    let base = mode.base();
    assert_eq!(
        &bytes[base..base + 8],
        &[
            if third { 0x10 } else { 0 },
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
    let expected_length = base + 24 + if mode.keyed() { 20 } else { 0 };
    assert_eq!(bytes.len(), expected_length);
    mode.assert_hmac_tlv(bytes);
    mode.assert_sealed(bytes);
}

#[test]
fn reflector_cos_bytes_and_wire_markings_follow_ingress_and_admission_policy() {
    for (ip, peer_ip, prefix) in [
        ("127.0.0.1", "127.0.0.2", "127.0.0.2/32"),
        ("::1", "::1", "::1/128"),
    ] {
        let ipv6 = ip == "::1";
        for mode in Mode::ALL {
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
                (6, 10, 1, 2, true, false),
                (7, 10, 1, 2, true, false),
            ] {
                let _case = Case::new(format!("{ip} {mode:?} policy={policy} dscp={received_dscp} ecn={received_ecn} requested_ecn={requested_ecn}"));
                let mut command = Reflector::command(ip);
                command.args([
                    "--hwtstamp",
                    "off",
                    "--stateful-reflector",
                    "--reflected-control-max-count",
                    "3",
                ]);
                command.args(mode.key_args());
                if mode.keyed() {
                    command.arg("--verify-tlv-hmac");
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
                if policy == 6 {
                    command.args(["--allowed-dscp", "10,34"]);
                }
                if policy == 7 {
                    command.args(["--allowed-dscp", "34"]);
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
                let third = matches!(policy, 1 | 3 | 5 | 7);
                let reply_dscp = if policy == 7 {
                    34
                } else if third {
                    0
                } else if rejected_dscp {
                    received_dscp
                } else {
                    46
                };
                let reply_ecn = if rejected_ecn { 0 } else { requested_ecn };
                let expected_tos = (reply_dscp << 2) | reply_ecn;
                let echoed = mode.sender_sequence();
                let first = receive(&peer);
                assert_eq!(&first.0[echoed..echoed + 4], &100u32.to_be_bytes());
                verify_cos_reply(&first.0, mode, expected_value, third);
                assert_eq!(first.1, expected_tos, "{ip} {mode:?} policy={policy}");
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
                        verify_cos_reply(&bytes, mode, expected_value, third);
                        assert_eq!(tos, expected_tos, "each copy retains admitted marking");
                        sequences.push(u32::from_be_bytes(bytes[..4].try_into().unwrap()));
                        burst += 1;
                    } else {
                        assert_eq!(sequence, 200);
                        ordinary += 1;
                        assert_eq!(ordinary, 1);
                        assert_eq!(tos, 0, "CoS must not leak into ordinary traffic");
                        assert_eq!(bytes.len(), mode.base());
                        mode.assert_sealed(&bytes);
                    }
                }
                assert!(sequences.windows(2).all(|p| p[0] < p[1]));
            }
        }
    }
}

#[test]
fn empty_dscp_policy_drops_cos_but_keeps_base_sessions_usable() {
    for ip in ["127.0.0.1", "::1"] {
        for mode in Mode::ALL {
            let _case = Case::new(format!("{ip} {mode:?}"));
            let mut command = Reflector::command(ip);
            command.args(["--hwtstamp", "off", "--allowed-dscp", "none"]);
            command.args(mode.key_args());
            if mode.keyed() {
                command.arg("--verify-tlv-hmac");
            }
            let reflector = Reflector::spawn(command).unwrap();
            let peer = UdpSocket::bind((ip, 0)).unwrap();
            peer.connect(reflector.address).unwrap();
            peer.set_read_timeout(Some(Duration::from_millis(150)))
                .unwrap();
            peer.send(&request(mode, 100, Some([184, 0, 128, 0])))
                .unwrap();
            let mut data = [0; 512];
            let error = peer.recv(&mut data).unwrap_err();
            assert!(matches!(
                error.kind(),
                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
            ));
            peer.send(&request(mode, 101, None)).unwrap();
            let size = peer.recv(&mut data).expect("ordinary session still usable");
            assert_eq!(size, mode.base(), "{ip} {mode:?}");
            let echoed = mode.sender_sequence();
            assert_eq!(&data[echoed..echoed + 4], &101u32.to_be_bytes());
            mode.assert_sealed(&data[..size]);
        }
    }
}
