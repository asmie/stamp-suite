//! Independent RFC 9503 sender bytes and reflector first-owner routing.
#[cfg(all(unix, any(feature = "ttl-nix", not(feature = "ttl-pnet"))))]
#[path = "common/reflector.rs"]
mod reflector;
#[path = "common/wire_hmac.rs"]
mod wire_hmac;

use clap::Parser;
use stamp_suite::{
    configuration::Configuration, sender, shutdown::CancellationToken, stats::StatsOutput,
};
use std::time::Duration;

const KEY: [u8; 16] = [0xab; 16];

fn frame(kind: u8, value: &[u8]) -> Vec<u8> {
    let mut bytes = vec![0x80, kind];
    bytes.extend_from_slice(&(value.len() as u16).to_be_bytes());
    bytes.extend_from_slice(value);
    bytes
}

fn fields(bytes: &[u8]) -> Vec<(usize, u8, &[u8])> {
    let mut result = Vec::new();
    let mut pos = 0;
    while pos < bytes.len() {
        assert!(bytes.len() - pos >= 4, "partial TLV header");
        let end = pos + 4 + usize::from(u16::from_be_bytes([bytes[pos + 2], bytes[pos + 3]]));
        assert!(end <= bytes.len(), "truncated TLV value");
        result.push((pos, bytes[pos + 1], &bytes[pos + 4..end]));
        pos = end;
    }
    result
}

fn verify_signatures(bytes: &[u8], mode: u8) {
    let base = if mode == 2 { 112 } else { 44 };
    if mode == 2 {
        assert_eq!(&bytes[96..112], &wire_hmac::digest(&KEY, &bytes[..96]));
    }
    if mode != 0 {
        let (pos, kind, digest) = *fields(&bytes[base..]).last().unwrap();
        assert_eq!(kind, 8);
        let mut covered = bytes[..4].to_vec();
        covered.extend_from_slice(&bytes[base..base + pos]);
        assert_eq!(digest, &wire_hmac::digest(&KEY, &covered));
    }
}

#[tokio::test]
async fn sender_emits_one_return_path_with_unique_network_order_children() {
    let srv6 = frame(
        4,
        &[
            0x20, 1, 0x0d, 0xb8, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb,
            0xcc, 0x20, 1, 0x0d, 0xb8, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10, 0xab, 0xcd,
            0xef, 1,
        ],
    );
    let mpls = frame(3, &[0x12, 0x34, 0x50, 0xff, 0xab, 0xcd, 0xe1, 0xff]);
    let sid_text = "2001:db8:1122:3344:5566:7788:99aa:bbcc,2001:db8:fedc:ba98:7654:3210:abcd:ef01";
    for ip in ["127.0.0.1", "::1"] {
        let address = if ip == "::1" {
            frame(2, &[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1])
        } else {
            frame(2, &[127, 0, 0, 1])
        };
        let profiles = [
            (vec!["--return-path-cc", "0"], frame(1, &[0, 0, 0, 0])),
            (vec!["--return-path-cc", "1"], frame(1, &[0, 0, 0, 1])),
            (vec!["--return-address", ip], address.clone()),
            (vec!["--return-srv6-sids", sid_text], srv6.clone()),
            (
                vec!["--return-sr-mpls-labels", "74565,703710"],
                mpls.clone(),
            ),
            (
                vec!["--return-srv6-sids", sid_text, "--return-address", ip],
                [srv6.clone(), address.clone()].concat(),
            ),
            (
                vec![
                    "--return-sr-mpls-labels",
                    "74565,703710",
                    "--return-address",
                    ip,
                ],
                [mpls.clone(), address.clone()].concat(),
            ),
        ];
        for mode in 0..3 {
            for (options, expected) in &profiles {
                let peer = tokio::net::UdpSocket::bind((ip, 0)).await.unwrap();
                let port = peer.local_addr().unwrap().port().to_string();
                let mut args = vec![
                    "stamp-suite",
                    "--local-addr",
                    ip,
                    "--remote-addr",
                    ip,
                    "--local-port",
                    "0",
                    "--remote-port",
                    &port,
                    "--count",
                    "1",
                    "--hwtstamp",
                    "off",
                ];
                args.extend(options.iter().copied());
                if mode != 0 {
                    args.extend(["--hmac-key", "abababababababababababababababab"]);
                }
                if mode == 2 {
                    args.extend(["--auth-mode", "A"]);
                }
                let conf = Configuration::parse_from(args);
                conf.validate().unwrap();
                let shutdown = CancellationToken::new();
                let output = StatsOutput::new(conf.output_format).unwrap();
                let check = async {
                    let mut request = [0; 512];
                    let (len, source) = peer.recv_from(&mut request).await.unwrap();
                    let bytes = &request[..len];
                    let base = if mode == 2 { 112 } else { 44 };
                    let top = fields(&bytes[base..]);
                    let paths: Vec<_> = top.iter().filter(|(_, kind, _)| *kind == 10).collect();
                    assert_eq!(paths.len(), 1, "{ip}, mode={mode}, {options:?}");
                    assert_eq!(paths[0].2, expected);
                    let mut counts = [0; 5];
                    for (_, kind, value) in fields(paths[0].2) {
                        counts[usize::from(kind)] += 1;
                        assert!(!value.is_empty());
                    }
                    assert!(counts[1] <= 1 && counts[2] <= 1 && counts[3] + counts[4] <= 1);
                    assert!(counts[1] == 0 || counts[2] + counts[3] + counts[4] == 0);
                    verify_signatures(bytes, mode);
                    assert_ne!(source.port(), peer.local_addr().unwrap().port());
                    shutdown.cancel();
                };
                let (stats, ()) = tokio::time::timeout(Duration::from_secs(5), async {
                    tokio::join!(
                        async {
                            sender::run_sender_with_output(
                                &conf,
                                &output,
                                sender::SenderObservers::default(),
                                shutdown.clone(),
                            )
                            .await
                            .expect("sender startup/run")
                        },
                        check
                    )
                })
                .await
                .expect("sender did not originate the return path");
                assert_eq!(stats.packets_sent, 1);
                assert_eq!(stats.packets_received, 0);
            }
        }
    }
}

#[cfg(all(unix, any(feature = "ttl-nix", not(feature = "ttl-pnet"))))]
fn packet(mode: u8, seq: u32, tlvs: &[u8]) -> Vec<u8> {
    let base = if mode == 2 { 112 } else { 44 };
    let mut bytes = vec![0; base];
    bytes[..4].copy_from_slice(&seq.to_be_bytes());
    bytes[if mode == 2 { 25 } else { 13 }] = 1;
    bytes.extend_from_slice(tlvs);
    if mode != 0 {
        let mut covered = bytes[..4].to_vec();
        covered.extend_from_slice(tlvs);
        bytes.extend_from_slice(&frame(8, &wire_hmac::digest(&KEY, &covered)));
    }
    if mode == 2 {
        let digest = wire_hmac::digest(&KEY, &bytes[..96]);
        bytes[96..112].copy_from_slice(&digest);
    }
    bytes
}

#[cfg(all(unix, any(feature = "ttl-nix", not(feature = "ttl-pnet"))))]
#[test]
fn reflector_first_return_path_owns_routing_even_when_unusable() {
    use reflector::Reflector;
    use std::net::UdpSocket;
    let same_link = frame(10, &frame(1, &[0, 0, 0, 1]));
    let suppress = frame(10, &frame(1, &[0, 0, 0, 0]));
    for ip in ["127.0.0.1", "::1"] {
        for mode in 0..3 {
            let mut command = Reflector::command(ip);
            command.args(["--hwtstamp", "off"]);
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
            let child = Reflector::spawn(command).unwrap();
            let peer = UdpSocket::bind((ip, 0)).unwrap();
            peer.connect(child.address).unwrap();
            peer.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
            let base = if mode == 2 { 112 } else { 44 };
            for (index, (first, expected_flags)) in [
                (
                    same_link.clone(),
                    if cfg!(target_os = "linux") { 0 } else { 0x80 },
                ),
                (frame(10, &frame(4, &[])), 0xc0),
                (frame(10, &frame(3, &[])), 0xc0),
                (frame(10, &[0xde, 0xad]), 0xc0),
            ]
            .into_iter()
            .enumerate()
            {
                let extra = [first.clone(), suppress.clone()].concat();
                let request = packet(mode, index as u32, &extra);
                peer.send(&request).unwrap();
                let mut data = [0; 512];
                let len = peer.recv(&mut data).unwrap();
                let reply = &data[..len];
                assert_eq!(len, request.len());
                assert_eq!(&reply[..4], &(index as u32).to_be_bytes());
                assert_eq!(reply[base] & 0xc0, expected_flags);
                assert_eq!(&reply[base + 1..base + 4], &first[1..4]);
                if first.len() >= 8 {
                    // Compare values separately from newly derived flags.
                    let actual = fields(&reply[base + 4..base + first.len()]);
                    let expected = fields(&first[4..]);
                    assert_eq!(actual, expected);
                } else {
                    assert_eq!(&reply[base + 4..base + first.len()], &first[4..]);
                }
                assert_eq!(
                    &reply[base + first.len() + 1..base + extra.len()],
                    &suppress[1..]
                );
                verify_signatures(reply, mode);
            }
            // A later same-link command must not override the first no-reply.
            let request = packet(mode, 40, &[suppress.clone(), same_link.clone()].concat());
            peer.set_read_timeout(Some(Duration::from_millis(50)))
                .unwrap();
            peer.send(&request).unwrap();
            let error = peer.recv(&mut [0; 512]).unwrap_err();
            assert!(matches!(
                error.kind(),
                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
            ));
            // Prove the receiver is live after suppression, with no retry.
            peer.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
            let request = packet(mode, 41, &same_link);
            peer.send(&request).unwrap();
            let mut data = [0; 512];
            let len = peer.recv(&mut data).unwrap();
            assert_eq!(&data[..4], &41u32.to_be_bytes());
            verify_signatures(&data[..len], mode);
        }
    }
}

#[cfg(all(unix, any(feature = "ttl-nix", not(feature = "ttl-pnet"))))]
#[test]
fn reflector_normalizes_return_path_children_and_preserves_failure_values() {
    use reflector::Reflector;
    use std::net::UdpSocket;
    let mut control = frame(1, &u32::MAX.to_be_bytes());
    control[0] = 0xff;
    let mut ignored_address = frame(2, &[0xaa]);
    ignored_address[0] = 0xff;
    let mut unknown = frame(8, &[0x12, 0x34]); // Child registry, not top-level HMAC.
    unknown[0] = 0xff;
    let valid = [control.clone(), ignored_address, unknown].concat();
    let expected = vec![
        0, 1, 0, 4, 0, 0, 0, 1, 0x80, 2, 0, 1, 0xaa, 0x80, 8, 0, 2, 0x12, 0x34,
    ];
    let mut malformed_tail = control.clone();
    malformed_tail.extend_from_slice(&[0xff, 2, 0, 16, 0xaa]);
    let mut short_tail = control.clone();
    short_tail.push(0xff);
    let cases = [
        (valid.clone(), expected, None),
        (malformed_tail.clone(), malformed_tail, Some(8)),
        (short_tail.clone(), short_tail, Some(8)),
        (frame(2, &[0xaa]), frame(2, &[0xaa]), Some(0)),
        (frame(4, &[]), frame(4, &[]), Some(0)),
        (frame(3, &[]), frame(3, &[]), Some(0)),
        (
            [control.clone(), frame(4, &[])].concat(),
            [vec![0, 1, 0, 4, 0, 0, 0, 1], frame(4, &[])].concat(),
            None,
        ),
    ];
    for ip in ["127.0.0.1", "::1"] {
        for mode in 0..3 {
            for strict in [false, true] {
                let mut command = Reflector::command(ip);
                command.args(["--hwtstamp", "off"]);
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
                let child = Reflector::spawn(command).unwrap();
                let peer = UdpSocket::bind((ip, 0)).unwrap();
                peer.connect(child.address).unwrap();
                peer.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
                let base = if mode == 2 { 112 } else { 44 };
                for (index, (value, expected, malformed)) in cases.iter().enumerate() {
                    let access = frame(6, &[0x1f, 1, 0xa5, 0x5a]);
                    let path = frame(10, value);
                    let request =
                        packet(mode, index as u32, &[path.clone(), access.clone()].concat());
                    peer.send(&request).unwrap();
                    let mut data = [0; 512];
                    let len = peer.recv(&mut data).unwrap();
                    let reply = &data[..len];
                    assert_eq!(len, request.len());
                    let mut expected = expected.clone();
                    if let Some(offset) = malformed {
                        if expected.len() - offset >= 4 {
                            expected[*offset] = 0x40;
                        }
                        assert_eq!(reply[base] & 0xe0, 0xc0);
                        assert_eq!(
                            &reply[base + path.len()..base + path.len() + access.len()],
                            &access
                        );
                    } else {
                        assert_eq!(
                            reply[base] & 0xe0,
                            if cfg!(target_os = "linux") { 0 } else { 0x80 }
                        );
                        assert_eq!(
                            &reply[base + path.len()..base + path.len() + access.len()],
                            &[0, 6, 0, 4, 0x10, 1, 0, 0]
                        );
                    }
                    assert_eq!(
                        &reply[base + 4..base + path.len()],
                        &expected,
                        "{ip}, mode={mode}, strict={strict}, case={index}"
                    );
                    verify_signatures(reply, mode);
                }
                if mode != 0 {
                    for value in [&valid, &frame(1, &[0xff, 0xff, 0xff, 0xfe])] {
                        let path = frame(10, value);
                        let mut request = packet(mode, 99, &path);
                        let last = request.len() - 1;
                        request[last] ^= 1; // Extension digest, outside base coverage.
                        peer.send(&request).unwrap();
                        let mut data = [0; 512];
                        let len = peer.recv(&mut data).unwrap();
                        let reply = &data[..len];
                        assert_ne!(reply[base] & 0x20, 0);
                        assert_eq!(&reply[base + 4..base + path.len()], value);
                        assert_eq!(&reply[len - 16..], &request[request.len() - 16..]);
                        if mode == 2 {
                            assert_eq!(&reply[96..112], &wire_hmac::digest(&KEY, &reply[..96]));
                        }
                    }
                }
                // Ignore the unusable but well-framed list under Control Code 0.
                let suppressed = [frame(1, &[0xff, 0xff, 0xff, 0xfe]), frame(4, &[])].concat();
                peer.set_read_timeout(Some(Duration::from_millis(50)))
                    .unwrap();
                peer.send(&packet(mode, 100, &frame(10, &suppressed)))
                    .unwrap();
                let error = peer.recv(&mut [0; 512]).unwrap_err();
                assert!(matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ));
                peer.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
                peer.send(&packet(mode, 101, &frame(10, &control))).unwrap();
                let mut data = [0; 512];
                let len = peer.recv(&mut data).unwrap();
                assert_eq!(&data[..4], &101u32.to_be_bytes());
                assert_eq!(&data[base + 4..base + 12], &[0, 1, 0, 4, 0, 0, 0, 1]);
                verify_signatures(&data[..len], mode);
            }
        }
    }
}
