//! Linux ingest/policy/control evidence on UDP ancillary and raw capture backends.
#![cfg(target_os = "linux")]
#[path = "common/ipv6_headers.rs"]
mod ipv6_headers;
#[path = "common/reflector.rs"]
mod reflector;
#[path = "common/wire_hmac.rs"]
mod wire_hmac;

use std::{os::fd::AsRawFd, time::Duration};
use tokio::net::UdpSocket;

const KEY: [u8; 16] = [0xab; 16];
const PNET: bool = cfg!(all(feature = "ttl-pnet", not(feature = "ttl-nix")));

async fn send(
    peer: &UdpSocket,
    destination: std::net::SocketAddr,
    payload: &[u8],
    header: &[u8],
) -> Vec<u8> {
    if !PNET {
        peer.send(payload).await.unwrap();
        return vec![];
    }
    // Loopback exposes incomplete TX checksums to raw capture. Inject a full
    // independent IPv6/UDP wire packet rather than relaxing checksum validation.
    let udp_len = (8 + payload.len()) as u16;
    let mut udp = Vec::new();
    udp.extend_from_slice(&peer.local_addr().unwrap().port().to_be_bytes());
    udp.extend_from_slice(&destination.port().to_be_bytes());
    udp.extend_from_slice(&udp_len.to_be_bytes());
    udp.extend_from_slice(&[0; 2]);
    udp.extend_from_slice(payload);
    let address = std::net::Ipv6Addr::LOCALHOST.octets();
    let mut pseudo = [
        address.as_slice(),
        address.as_slice(),
        &u32::from(udp_len).to_be_bytes(),
        &[0, 0, 0, 17],
        &udp,
    ]
    .concat();
    if pseudo.len() % 2 != 0 {
        pseudo.push(0);
    }
    let mut sum: u32 = pseudo
        .chunks_exact(2)
        .map(|word| u32::from(u16::from_be_bytes([word[0], word[1]])))
        .sum();
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    let checksum = !(sum as u16);
    udp[6..8].copy_from_slice(&if checksum == 0 { u16::MAX } else { checksum }.to_be_bytes());
    let mut fixed = vec![0; 40];
    fixed[0] = 0x60;
    fixed[4..6].copy_from_slice(&((header.len() + udp.len()) as u16).to_be_bytes());
    fixed[6] = 60;
    fixed[7] = 255;
    fixed[8..24].copy_from_slice(&address);
    fixed[24..40].copy_from_slice(&address);
    let wire = [fixed.as_slice(), header, &udp].concat();
    // SAFETY: socket returns a fresh fd, transferred once to OwnedFd on success.
    let fd = unsafe { libc::socket(libc::AF_INET6, libc::SOCK_RAW, libc::IPPROTO_RAW) };
    assert!(fd >= 0, "raw socket: {}", std::io::Error::last_os_error());
    use std::os::fd::{FromRawFd, OwnedFd};
    // SAFETY: fd is newly created, nonnegative and uniquely owned.
    let socket = unsafe { OwnedFd::from_raw_fd(fd) };
    // SAFETY: an all-zero sockaddr_in6 is valid before its family/address are set.
    let mut target: libc::sockaddr_in6 = unsafe { std::mem::zeroed() };
    target.sin6_family = libc::AF_INET6 as _;
    target.sin6_addr.s6_addr = address;
    // SAFETY: the socket, wire buffer and sockaddr remain live for this call;
    // the supplied lengths match their allocations.
    let sent = unsafe {
        libc::sendto(
            socket.as_raw_fd(),
            wire.as_ptr().cast(),
            wire.len(),
            0,
            std::ptr::addr_of!(target).cast(),
            std::mem::size_of_val(&target) as _,
        )
    };
    assert_eq!(
        sent,
        wire.len() as isize,
        "raw send: {}",
        std::io::Error::last_os_error()
    );
    fixed
}

fn frame(flags: u8, kind: u8, value: &[u8]) -> Vec<u8> {
    let mut bytes = vec![flags, kind];
    bytes.extend_from_slice(&(value.len() as u16).to_be_bytes());
    bytes.extend_from_slice(value);
    bytes
}

fn packet(mode: u8, seq: u32, chain: &[u8]) -> Vec<u8> {
    let mut bytes = vec![0; if mode == 2 { 112 } else { 44 }];
    bytes[..4].copy_from_slice(&seq.to_be_bytes());
    bytes[if mode == 2 { 25 } else { 13 }] = 1;
    if mode == 2 {
        let digest = wire_hmac::digest(&KEY, &bytes[..96]);
        bytes[96..112].copy_from_slice(&digest);
    }
    bytes.extend_from_slice(chain);
    if mode != 0 {
        let covered = [&bytes[..4], chain].concat();
        bytes.extend(frame(0x80, 8, &wire_hmac::digest(&KEY, &covered)));
    }
    bytes
}

fn check_reply(bytes: &[u8], mode: u8, seq: u32, expected: &[u8]) {
    let base = if mode == 2 { 112 } else { 44 };
    let sender_seq = if mode == 2 { 48 } else { 24 };
    assert_eq!(&bytes[sender_seq..sender_seq + 4], &seq.to_be_bytes());
    let mut expected = expected.to_vec();
    if mode != 0 {
        let covered = [&bytes[..4], &expected].concat();
        expected.extend(frame(0, 8, &wire_hmac::digest(&KEY, &covered)));
    }
    assert_eq!(&bytes[base..], expected);
    if mode == 2 {
        assert_eq!(&bytes[96..112], &wire_hmac::digest(&KEY, &bytes[..96]));
    }
}

#[tokio::test]
#[ignore = "requires STAMP_HEADER_NETNS_TESTS=1 inside unshare -Urn"]
async fn reflector_disclosure_order_and_control_use_actual_headers_without_reverse_attachment() {
    assert_eq!(
        std::env::var("STAMP_HEADER_NETNS_TESTS").as_deref(),
        Ok("1")
    );
    // SAFETY: geteuid takes no arguments and writes no caller memory.
    assert_eq!(unsafe { libc::geteuid() }, 0, "run inside unshare -Urn");
    assert!(std::process::Command::new("ip")
        .args(["link", "set", "lo", "up"])
        .status()
        .unwrap()
        .success());
    for policy in 0..5 {
        for mode in 0..3 {
            for strict in [false, true] {
                let mut command = if PNET {
                    // Port zero is not supported by the current pnet capture
                    // filter. This sole reflector owns a fixed port inside the
                    // fresh private network namespace, before the peer binds.
                    let mut command = std::process::Command::new(env!("CARGO_BIN_EXE_stamp-suite"));
                    command.args([
                        "--is-reflector",
                        "--local-addr",
                        "::1",
                        "--local-port",
                        "19862",
                        "--log-format",
                        "json",
                    ]);
                    command
                } else {
                    reflector::Reflector::command("::1")
                };
                command.args(["--hwtstamp", "off", "--reflected-control-max-count", "1"]);
                match policy {
                    0 => {} // Default deny.
                    1 => {
                        command.args(["--reflect-ipv6-ext-header-from", "2001:db8::1"]);
                    }
                    2 => {
                        command.args(["--reflect-fixed-header-from", "::1"]);
                    }
                    3 => {
                        command.args(["--reflect-ipv6-ext-header-from", "::1"]);
                    }
                    _ => {
                        command.args([
                            "--reflect-fixed-header-from",
                            "::1",
                            "--reflect-ipv6-ext-header-from",
                            "::1",
                        ]);
                        if PNET {
                            command.args(["--interface", "lo"]);
                        }
                    }
                }
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
                let peer = UdpSocket::bind(("::1", 0)).await.unwrap();
                peer.connect(child.address).await.unwrap();
                ipv6_headers::enable_capture(&peer);
                // A skip-on-unknown experimental option with distinctive data.
                let header = [
                    17u8, 1, 0x1e, 12, 1, 2, 3, 4, 11, 12, 13, 14, 15, 16, 17, 18,
                ];
                // SAFETY: the live socket/header outlive the call, with exact buffer size.
                assert_eq!(
                    unsafe {
                        libc::setsockopt(
                            peer.as_raw_fd(),
                            libc::IPPROTO_IPV6,
                            libc::IPV6_DSTOPTS,
                            header.as_ptr().cast(),
                            header.len() as _,
                        )
                    },
                    0,
                    "attach: {}",
                    std::io::Error::last_os_error()
                );
                for controls in 0..3 {
                    for reversed in [false, true] {
                        let mut ext = vec![0; 16];
                        ext[8..].fill(0xa5);
                        let mut fixed = vec![0; 40];
                        fixed[4..].fill(0x5a);
                        let chain = if reversed {
                            [frame(0x80, 246, &ext), frame(0x80, 247, &fixed)].concat()
                        } else {
                            [frame(0x80, 247, &fixed), frame(0x80, 246, &ext)].concat()
                        };
                        let mut control = vec![0, 0, 0, 1, 0, 0, 0, 0];
                        for _ in 0..controls {
                            control.extend([0, 240, 0, 0]);
                        }
                        let request_chain = if controls != 0 {
                            [chain, frame(0x80, 12, &control)].concat()
                        } else {
                            chain
                        };
                        let seq = (controls * 2 + usize::from(reversed)) as u32;
                        let captured_fixed = send(
                            &peer,
                            child.address,
                            &packet(mode, seq, &request_chain),
                            &header,
                        )
                        .await;
                        let (bytes, reply_headers) = tokio::time::timeout(
                            Duration::from_secs(3),
                            peer.async_io(tokio::io::Interest::READABLE, || {
                                ipv6_headers::receive(&peer)
                            }),
                        )
                        .await
                        .unwrap()
                        .unwrap();
                        assert!(
                            reply_headers.is_empty(),
                            "matching reverse headers must not be attached"
                        );
                        let ext_reply = if !reversed && policy >= 3 {
                            frame(0, 246, &header)
                        } else {
                            frame(0x10, 246, &ext)
                        };
                        let fixed_reply = if PNET && !reversed && matches!(policy, 2 | 4) {
                            frame(0, 247, &captured_fixed)
                        } else {
                            frame(0x10, 247, &fixed)
                        }; // UDP ancillary capture cannot supply fixed headers.
                        let mut expected = if reversed {
                            [ext_reply, fixed_reply].concat()
                        } else {
                            [fixed_reply, ext_reply].concat()
                        };
                        if controls != 0 {
                            for offset in (8..control.len()).step_by(4) {
                                control[offset] = 0x10;
                            }
                            expected.extend(frame(0, 12, &control));
                        }
                        check_reply(&bytes, mode, seq, &expected);
                    }
                }
                if mode != 0 {
                    let value = vec![0; 16];
                    let chain = frame(0x80, 246, &value);
                    let mut request = packet(mode, 99, &chain);
                    *request.last_mut().unwrap() ^= 1;
                    send(&peer, child.address, &request, &header).await;
                    let (bytes, headers) = tokio::time::timeout(
                        Duration::from_secs(3),
                        peer.async_io(tokio::io::Interest::READABLE, || {
                            ipv6_headers::receive(&peer)
                        }),
                    )
                    .await
                    .unwrap()
                    .unwrap();
                    assert!(headers.is_empty());
                    let base = if mode == 2 { 112 } else { 44 };
                    let expected = [
                        frame(0x20, 246, &value),
                        frame(0x20, 8, &request[request.len() - 16..]),
                    ]
                    .concat();
                    assert_eq!(
                        &bytes[base..],
                        expected,
                        "failed integrity must not expose captured headers"
                    );
                    if mode == 2 {
                        assert_eq!(&bytes[96..112], &wire_hmac::digest(&KEY, &bytes[..96]));
                    }
                }
            }
        }
    }
}
