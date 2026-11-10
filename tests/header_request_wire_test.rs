//! Independent sender bytes for the frozen ext-hdr-26 originated profile.
#[path = "common/wire_hmac.rs"]
mod wire_hmac;

use clap::Parser;
use stamp_suite::{
    configuration::Configuration, sender, shutdown::CancellationToken, stats::StatsOutput,
};
use std::time::Duration;

const KEY: [u8; 16] = [0xab; 16];

fn fields(bytes: &[u8]) -> Vec<(u8, &[u8])> {
    let mut result = Vec::new();
    let mut offset = 0;
    while offset < bytes.len() {
        assert!(bytes.len() - offset >= 4, "partial TLV header");
        assert_eq!(bytes[offset], 0x80, "sender U set, other flags clear");
        let end =
            offset + 4 + usize::from(u16::from_be_bytes([bytes[offset + 2], bytes[offset + 3]]));
        assert!(end <= bytes.len(), "truncated TLV");
        result.push((bytes[offset + 1], &bytes[offset + 4..end]));
        offset = end;
    }
    result
}

fn check(bytes: &[u8], mode: u8, expected: &[(u8, Vec<u8>)]) {
    let base = if mode == 2 { 112 } else { 44 };
    assert_eq!(&bytes[..4], &[0; 4]);
    if mode == 2 {
        assert_eq!(&bytes[96..112], &wire_hmac::digest(&KEY, &bytes[..96]));
    }
    let actual = fields(&bytes[base..]);
    let mut expected: Vec<_> = expected
        .iter()
        .map(|(kind, value)| (*kind, value.as_slice()))
        .collect();
    let digest;
    if mode != 0 && !expected.is_empty() {
        assert_eq!(actual.last().unwrap().0, 8);
        let last = bytes.len() - 20;
        let covered = [&bytes[..4], &bytes[base..last]].concat();
        digest = wire_hmac::digest(&KEY, &covered);
        expected.push((8, &digest));
    }
    assert_eq!(actual, expected);
}

fn configuration(peer: &tokio::net::UdpSocket, mode: u8, extra: &[&str]) -> Configuration {
    let address = peer.local_addr().unwrap();
    let ip = address.ip().to_string();
    let port = address.port().to_string();
    let mut args = vec![
        "test",
        "--remote-addr",
        &ip,
        "--local-addr",
        &ip,
        "--local-port",
        "0",
        "--remote-port",
        &port,
        "--count",
        "1",
        "--hwtstamp",
        "off",
    ];
    args.extend_from_slice(extra);
    if mode != 0 {
        args.extend(["--hmac-key", "abababababababababababababababab"]);
    }
    if mode == 2 {
        args.extend(["--auth-mode", "A"]);
    }
    let conf = Configuration::try_parse_from(args).expect("sender arguments");
    conf.validate().unwrap();
    conf
}

async fn run(
    conf: &Configuration,
    observed: impl std::future::Future<Output = ()>,
    stop: CancellationToken,
) {
    let output = StatsOutput::new(conf.output_format).unwrap();
    let (stats, ()) = tokio::time::timeout(Duration::from_secs(5), async {
        tokio::join!(
            sender::run_sender_with_output(conf, &output, sender::SenderObservers::default(), stop),
            observed,
        )
    })
    .await
    .expect("sender did not originate the requested profile");
    let stats = stats.expect("validated sender startup/run");
    assert_eq!(stats.packets_sent, 1);
    assert_eq!(stats.packets_received, 0);
}

#[tokio::test]
async fn sender_control_request_is_unique_zero_length_and_opt_in() {
    for ip in ["127.0.0.1", "::1"] {
        for mode in 0..3 {
            for profile in 0..3 {
                let peer = tokio::net::UdpSocket::bind((ip, 0)).await.unwrap();
                let extra: &[&str] = match profile {
                    0 => &[],
                    1 => &["--reflected-control-no-ext-hdr"],
                    _ => &[
                        "--reflected-control-no-ext-hdr",
                        "--reflected-control-count",
                        "3",
                        "--reflected-control-length",
                        "256",
                        "--reflected-control-interval-ns",
                        "1000000",
                    ],
                };
                let conf = configuration(&peer, mode, extra);
                let expected = match profile {
                    0 => vec![],
                    1 => vec![(12, vec![0, 0, 0, 1, 0, 0, 0, 0, 0, 240, 0, 0])],
                    _ => vec![(12, vec![1, 0, 0, 3, 0, 15, 66, 64, 0, 240, 0, 0])],
                };
                let stop = CancellationToken::new();
                let observed = async {
                    let mut bytes = [0; 512];
                    let (len, source) = peer.recv_from(&mut bytes).await.unwrap();
                    assert_ne!(source.port(), peer.local_addr().unwrap().port());
                    check(&bytes[..len], mode, &expected);
                    stop.cancel();
                };
                run(&conf, observed, stop.clone()).await;
            }
        }
    }
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn sender_fixed_header_requests_have_family_length_selector_and_zero_received() {
    for ip in ["127.0.0.1", "::1"] {
        for mode in 0..3 {
            for selector in [false, true] {
                let peer = tokio::net::UdpSocket::bind((ip, 0)).await.unwrap();
                let extra = if selector {
                    vec![
                        "--reflected-fixed-hdr",
                        if ip == "::1" { "00000123" } else { "45000054" },
                    ]
                } else {
                    vec!["--reflected-fixed-hdr"]
                };
                let conf = configuration(&peer, mode, &extra);
                let mut value = vec![0; if ip == "::1" { 40 } else { 20 }];
                if selector {
                    value[..4].copy_from_slice(if ip == "::1" {
                        &[0, 0, 1, 0x23]
                    } else {
                        &[0x45, 0, 0, 0x54]
                    });
                }
                let stop = CancellationToken::new();
                let observed = async {
                    let mut bytes = [0; 512];
                    let len = peer.recv(&mut bytes).await.unwrap();
                    check(&bytes[..len], mode, &[(247, value)]);
                    stop.cancel();
                };
                run(&conf, observed, stop.clone()).await;
            }
        }
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use std::os::fd::AsRawFd;
    type Values = Vec<(u8, Vec<u8>)>;

    fn enable_capture(peer: &tokio::net::UdpSocket) {
        for option in [libc::IPV6_RECVHOPOPTS, libc::IPV6_RECVDSTOPTS] {
            let on: libc::c_int = 1;
            // SAFETY: the live socket and aligned option value outlive this call.
            assert_eq!(
                unsafe {
                    libc::setsockopt(
                        peer.as_raw_fd(),
                        libc::IPPROTO_IPV6,
                        option,
                        std::ptr::addr_of!(on).cast(),
                        std::mem::size_of_val(&on) as _,
                    )
                },
                0,
                "header capture: {}",
                std::io::Error::last_os_error()
            );
        }
    }

    fn receive(peer: &tokio::net::UdpSocket) -> std::io::Result<(Vec<u8>, Values)> {
        let mut bytes = [0; 2048];
        let mut control = [0usize; 128]; // Aligned for cmsghdr.
        let mut iov = libc::iovec {
            iov_base: bytes.as_mut_ptr().cast(),
            iov_len: bytes.len(),
        };
        // SAFETY: zeroed msghdr has valid null pointers and zero lengths.
        let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = control.as_mut_ptr().cast();
        msg.msg_controllen = std::mem::size_of_val(&control);
        // SAFETY: all writable buffers stay live, and their exact sizes are passed.
        let len = unsafe { libc::recvmsg(peer.as_raw_fd(), &mut msg, 0) };
        if len < 0 {
            return Err(std::io::Error::last_os_error());
        }
        assert_eq!(msg.msg_flags & (libc::MSG_TRUNC | libc::MSG_CTRUNC), 0);
        let mut headers = Vec::new();
        // SAFETY: recvmsg filled the aligned buffer and its returned length bounds
        // CMSG iteration. Every slice is bounded by the returned cmsg length.
        unsafe {
            let mut header = libc::CMSG_FIRSTHDR(&msg);
            while !header.is_null() {
                let kind = match ((*header).cmsg_level, (*header).cmsg_type) {
                    (libc::IPPROTO_IPV6, libc::IPV6_HOPOPTS) => Some(0),
                    (libc::IPPROTO_IPV6, libc::IPV6_DSTOPTS) => Some(60),
                    _ => None,
                };
                if let Some(kind) = kind {
                    let len = (*header).cmsg_len - libc::CMSG_LEN(0) as usize;
                    headers.push((
                        kind,
                        std::slice::from_raw_parts(libc::CMSG_DATA(header), len).to_vec(),
                    ));
                }
                header = libc::CMSG_NXTHDR(&msg, header);
            }
        }
        Ok((bytes[..len as usize].to_vec(), headers))
    }

    #[tokio::test]
    #[ignore = "requires STAMP_HEADER_NETNS_TESTS=1 inside unshare -Urn"]
    async fn sender_header_requests_follow_actual_attached_order_and_select_subsets() {
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
        for mode in 0..3 {
            for profile in 0..7 {
                let peer = tokio::net::UdpSocket::bind(("::1", 0)).await.unwrap();
                enable_capture(&peer);
                let (extra, expected, attached): (Vec<&str>, Values, Values) = match profile {
                    0..=2 => {
                        let mut hbh = vec![60, 1, 0x1e, 12];
                        hbh.extend(0x10..0x1c);
                        let mut dest = vec![17, 2, 0x1e, 20];
                        dest.extend(0x20..0x34);
                        let mut args = vec![
                            "--attach-ext-hdr",
                            "hbh:00011e0c101112131415161718191a1b",
                            "--attach-ext-hdr",
                            "dest:00021e14202122232425262728292a2b2c2d2e2f30313233",
                        ];
                        let expected = if profile == 0 {
                            args.push("--reflected-fixed-hdr");
                            vec![(247, vec![0; 40]), (246, vec![0; 16]), (246, vec![0; 24])]
                        } else if profile == 1 {
                            args.extend([
                                "--reflected-ipv6-ext-hdr",
                                "16:3c011e0c10111213",
                                "--reflected-ipv6-ext-hdr",
                                "24:11021e1420212223",
                                "--reflected-fixed-hdr",
                                "00000123",
                            ]);
                            let mut fixed = vec![0; 40];
                            fixed[..4].copy_from_slice(&[0, 0, 1, 0x23]);
                            let mut first = vec![0; 16];
                            first[..8].copy_from_slice(&hbh[..8]);
                            let mut second = vec![0; 24];
                            second[..8].copy_from_slice(&dest[..8]);
                            vec![(247, fixed), (246, first), (246, second)]
                        } else {
                            args.extend(["--reflected-ipv6-ext-hdr", "24"]);
                            vec![(246, vec![0; 24])]
                        };
                        (args, expected, vec![(0, hbh), (60, dest)])
                    }
                    3 | 4 | 6 => {
                        let mut args = vec!["--attach-ext-hdr", "hbh", "--attach-ext-hdr", "dest"];
                        let expected = if profile == 3 {
                            vec![(246, vec![0; 8]), (246, vec![0; 8])]
                        } else {
                            let (selector, next_header) = if profile == 4 {
                                ("8:11000104", 17)
                            } else {
                                ("8:3c000104", 60)
                            };
                            args.extend(["--reflected-ipv6-ext-hdr", selector]);
                            vec![(246, vec![next_header, 0, 1, 4, 0, 0, 0, 0])]
                        };
                        (
                            args,
                            expected,
                            vec![
                                (0, vec![60, 0, 1, 4, 0, 0, 0, 0]),
                                (60, vec![17, 0, 1, 4, 0, 0, 0, 0]),
                            ],
                        )
                    }
                    _ => (
                        vec![
                            "--attach-ext-hdr",
                            "dest:00013e0caabbccddeeff102030405060",
                            "--reflected-ipv6-ext-hdr",
                            "16:11013e0c00000000",
                        ],
                        vec![(
                            246,
                            vec![17, 1, 0x3e, 12, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                        )],
                        vec![(
                            60,
                            vec![
                                17, 1, 0x3e, 12, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x10, 0x20,
                                0x30, 0x40, 0x50, 0x60,
                            ],
                        )],
                    ),
                };
                let conf = configuration(&peer, mode, &extra);
                let stop = CancellationToken::new();
                let observed = async {
                    let (bytes, headers) = peer
                        .async_io(tokio::io::Interest::READABLE, || receive(&peer))
                        .await
                        .unwrap();
                    assert_eq!(headers, attached, "mode={mode}, profile={profile}");
                    check(&bytes, mode, &expected);
                    stop.cancel();
                };
                run(&conf, observed, stop.clone()).await;
            }
        }
    }
}
