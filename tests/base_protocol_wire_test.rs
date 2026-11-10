//! RFC 8762 base packets checked as raw bytes across the public endpoints.
//! Field offsets and HMAC coverage below are independent of production codecs.
#[cfg(all(unix, any(feature = "ttl-nix", not(feature = "ttl-pnet"))))]
#[path = "common/reflector.rs"]
mod reflector;
#[path = "common/wire_hmac.rs"]
mod wire_hmac;

use clap::Parser;
use stamp_suite::{configuration::Configuration, sender};
use std::{
    ops::Range,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

const KEY: [u8; 16] = [0xab; 16];
const OPEN_REQUEST_RESERVED: Range<usize> = 16..44;

#[derive(Clone, Copy)]
struct Layout {
    base: usize,
    timestamp: usize,
    error: usize,
    received: usize,
    echo_sequence: usize,
    echo_timestamp: usize,
    echo_error: usize,
    ttl: usize,
}

fn layout(auth: bool) -> Layout {
    if auth {
        Layout {
            base: 112,
            timestamp: 16,
            error: 24,
            received: 32,
            echo_sequence: 48,
            echo_timestamp: 64,
            echo_error: 72,
            ttl: 80,
        }
    } else {
        Layout {
            base: 44,
            timestamp: 4,
            error: 12,
            received: 16,
            echo_sequence: 24,
            echo_timestamp: 28,
            echo_error: 36,
            ttl: 40,
        }
    }
}

// The RFC 8972 SSID occupies two original MBZ octets after Error Estimate.
// These base-only cases use SSID zero and check it separately.
fn request_reserved(auth: bool) -> &'static [Range<usize>] {
    if auth {
        &[4..16, 28..96]
    } else {
        &[OPEN_REQUEST_RESERVED]
    }
}

fn reply_reserved(auth: bool) -> &'static [Range<usize>] {
    if auth {
        &[4..16, 28..32, 40..48, 52..64, 74..80, 81..96]
    } else {
        &[38..40, 41..44]
    }
}

fn now_nanos() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos()
}

fn check_timestamp(bytes: &[u8], ptp: bool, before: u128, after: u128) -> u128 {
    let raw = u64::from_be_bytes(bytes.try_into().unwrap());
    let offset = if ptp { 0 } else { 2_208_988_800 };
    let reference = (before / 1_000_000_000) as u64 + offset;
    let seconds = (reference & !0xffff_ffff) | (raw >> 32);
    let seconds = [
        seconds.saturating_sub(1 << 32),
        seconds,
        seconds + (1 << 32),
    ]
    .into_iter()
    .min_by_key(|s| s.abs_diff(reference))
    .unwrap();
    let fraction = u128::from(raw as u32);
    let nanos = if ptp {
        assert!(fraction < 1_000_000_000, "invalid PTP nanoseconds");
        fraction
    } else {
        (fraction * 1_000_000_000) >> 32
    };
    let decoded = u128::from(seconds.checked_sub(offset).unwrap()) * 1_000_000_000 + nanos;
    // NTP fixed-point conversion can discard one nanosecond.
    assert!(
        decoded + 2 >= before && decoded <= after + 2,
        "timestamp {decoded} outside {before}..={after}, PTP={ptp}"
    );
    decoded
}

fn sign(bytes: &mut [u8], auth: bool) {
    if auth {
        let digest = wire_hmac::digest(&KEY, &bytes[..96]);
        bytes[96..112].copy_from_slice(&digest);
    }
}

fn check_signature(bytes: &[u8], auth: bool) {
    if auth {
        assert_eq!(&bytes[96..112], &wire_hmac::digest(&KEY, &bytes[..96]));
    }
}

fn check_zero(bytes: &[u8], ranges: &[Range<usize>]) {
    for range in ranges {
        assert!(
            bytes[range.clone()].iter().all(|&b| b == 0),
            "nonzero MBZ at {range:?}"
        );
    }
}

#[tokio::test]
async fn sender_base_sequence_clock_layout_and_reserved_receipt() {
    for ip in ["127.0.0.1", "::1"] {
        for auth in [false, true] {
            for ptp in [false, true] {
                for strict in [false, true] {
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
                        "3",
                        "--send-delay",
                        "10ms",
                        "--timeout",
                        "1",
                        "--hwtstamp",
                        "off",
                    ];
                    if auth {
                        args.extend([
                            "--auth-mode",
                            "A",
                            "--hmac-key",
                            "abababababababababababababababab",
                        ]);
                    }
                    if ptp {
                        args.extend(["--clock-source", "PTP"]);
                    }
                    if strict {
                        args.push("--strict-packets");
                    }
                    let conf = Configuration::parse_from(args);
                    conf.validate().unwrap();
                    let fields = layout(auth);
                    let before = now_nanos();
                    let exchange = async {
                        for seq in 0..3u32 {
                            let mut data = [0; 256];
                            let (len, source) = peer.recv_from(&mut data).await.unwrap();
                            let packet = &data[..len];
                            assert_eq!(len, fields.base);
                            assert_eq!(&packet[..4], &seq.to_be_bytes());
                            assert_eq!(&packet[fields.error + 2..fields.error + 4], &[0, 0]);
                            assert_eq!(packet[fields.error] & 0x40 != 0, ptp);
                            check_timestamp(
                                &packet[fields.timestamp..fields.timestamp + 8],
                                ptp,
                                before,
                                now_nanos(),
                            );
                            check_zero(packet, request_reserved(auth));
                            check_signature(packet, auth);
                            assert_ne!(source.port(), peer.local_addr().unwrap().port());

                            let mut reply = vec![0; fields.base];
                            reply[..4].copy_from_slice(&seq.to_be_bytes());
                            reply[fields.timestamp..fields.timestamp + 8]
                                .copy_from_slice(&packet[fields.timestamp..fields.timestamp + 8]);
                            reply[fields.received..fields.received + 8]
                                .copy_from_slice(&packet[fields.timestamp..fields.timestamp + 8]);
                            reply[fields.error..fields.error + 2]
                                .copy_from_slice(&packet[fields.error..fields.error + 2]);
                            reply[fields.echo_sequence..fields.echo_sequence + 4]
                                .copy_from_slice(&seq.to_be_bytes());
                            reply[fields.echo_timestamp..fields.echo_timestamp + 8]
                                .copy_from_slice(&packet[fields.timestamp..fields.timestamp + 8]);
                            reply[fields.echo_error..fields.echo_error + 2]
                                .copy_from_slice(&packet[fields.error..fields.error + 2]);
                            reply[fields.ttl] = 64;
                            for range in reply_reserved(auth) {
                                reply[range.clone()].fill(0xa5);
                            }
                            sign(&mut reply, auth);
                            peer.send_to(&reply, source).await.unwrap();
                        }
                    };
                    let (stats, ()) = tokio::time::timeout(Duration::from_secs(5), async {
                        tokio::join!(
                            async { sender::run_sender(&conf).await.expect("sender startup/run") },
                            exchange
                        )
                    })
                    .await
                    .expect("base sender exchange timed out");
                    assert_eq!(stats.packets_sent, 3);
                    assert_eq!(stats.packets_received, 3);
                }
            }
        }
    }
}

#[cfg(all(unix, any(feature = "ttl-nix", not(feature = "ttl-pnet"))))]
#[test]
fn reflector_base_mbz_symmetry_clocks_and_stateless_sequences() {
    use reflector::Reflector;
    use std::net::UdpSocket;

    for ip in ["127.0.0.1", "::1"] {
        for auth in [false, true] {
            for ptp in [false, true] {
                for strict in [false, true] {
                    for stateful in [false, true] {
                        let mut command = Reflector::command(ip);
                        command.args(["--hwtstamp", "off"]);
                        if auth {
                            command.args([
                                "--auth-mode",
                                "A",
                                "--hmac-key",
                                "abababababababababababababababab",
                            ]);
                        }
                        if ptp {
                            command.args(["--clock-source", "PTP"]);
                        }
                        if strict {
                            command.arg("--strict-packets");
                        }
                        if stateful {
                            command.arg("--stateful-reflector");
                        }
                        let child = Reflector::spawn(command).unwrap();
                        let peer = UdpSocket::bind((ip, 0)).unwrap();
                        peer.connect(child.address).unwrap();
                        peer.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
                        let socket = socket2::SockRef::from(&peer);
                        if ip == "::1" {
                            socket.set_unicast_hops_v6(37).unwrap();
                        } else {
                            socket.set_ttl_v4(37).unwrap();
                        }
                        let fields = layout(auth);
                        for (index, (seq, tail_len)) in [(0x10203040u32, 0), (7, 3), (u32::MAX, 32)]
                            .into_iter()
                            .enumerate()
                        {
                            let mut request = vec![0; fields.base + tail_len];
                            if tail_len == 3 {
                                request[fields.base..].copy_from_slice(&[0xde, 0xad, 0xbe]);
                            }
                            request[..4].copy_from_slice(&seq.to_be_bytes());
                            request[fields.timestamp..fields.timestamp + 8]
                                .copy_from_slice(&0x112233448899aabbu64.to_be_bytes());
                            request[fields.error..fields.error + 2]
                                .copy_from_slice(&0xc712u16.to_be_bytes());
                            for range in request_reserved(auth) {
                                request[range.clone()].fill(0xa5);
                            }
                            sign(&mut request, auth);
                            if auth && index == 0 {
                                let mut forged = request.clone();
                                forged[4] ^= 1; // MBZ is still covered by the base HMAC.
                                peer.set_read_timeout(Some(Duration::from_millis(50)))
                                    .unwrap();
                                peer.send(&forged).unwrap();
                                let error = peer.recv(&mut [0; 256]).unwrap_err();
                                assert!(matches!(
                                    error.kind(),
                                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                                ));
                                peer.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
                            }
                            let before = now_nanos();
                            peer.send(&request).unwrap();
                            let mut data = [0; 256];
                            let len = peer.recv(&mut data).unwrap();
                            let after = now_nanos();
                            let response = &data[..len];
                            assert_eq!(len, request.len());
                            assert_eq!(&response[fields.base..], &request[fields.base..]);
                            assert_eq!(
                                &response[..4],
                                &(if stateful { index as u32 } else { seq }).to_be_bytes()
                            );
                            assert_eq!(
                                &response[fields.echo_sequence..fields.echo_sequence + 4],
                                &seq.to_be_bytes()
                            );
                            assert_eq!(
                                &response[fields.echo_timestamp..fields.echo_timestamp + 8],
                                &request[fields.timestamp..fields.timestamp + 8]
                            );
                            assert_eq!(
                                &response[fields.echo_error..fields.echo_error + 2],
                                &request[fields.error..fields.error + 2]
                            );
                            assert_eq!(&response[fields.error + 2..fields.error + 4], &[0, 0]);
                            assert_eq!(response[fields.error] & 0x40 != 0, ptp);
                            let t2 = check_timestamp(
                                &response[fields.received..fields.received + 8],
                                ptp,
                                before,
                                after,
                            );
                            let t3 = check_timestamp(
                                &response[fields.timestamp..fields.timestamp + 8],
                                ptp,
                                before,
                                after,
                            );
                            assert!(t2 <= t3);
                            assert_eq!(response[fields.ttl], 37);
                            check_zero(response, reply_reserved(auth));
                            check_signature(response, auth);
                        }
                    }
                }
            }
        }
    }
}
