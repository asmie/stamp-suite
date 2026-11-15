//! Capture actual sender output, independently of the crate's packet codecs.
#![cfg(target_os = "linux")]

#[path = "common/wire_hmac.rs"]
mod wire_hmac;

use std::{
    net::{SocketAddr, UdpSocket},
    process::{Child, Command, Output, Stdio},
    time::{Duration, Instant},
};

const KEY: [u8; 16] = [0xab; 16];

struct Sender(Option<Child>);
impl Sender {
    fn finish(&mut self) -> Output {
        let deadline = Instant::now() + Duration::from_secs(5);
        while self.0.as_mut().unwrap().try_wait().unwrap().is_none() {
            if Instant::now() >= deadline {
                self.0.as_mut().unwrap().kill().unwrap();
                break;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        self.0.take().unwrap().wait_with_output().unwrap()
    }
}
impl Drop for Sender {
    fn drop(&mut self) {
        if let Some(child) = self.0.as_mut() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

fn namespace() {
    assert_eq!(std::env::var("STAMP_ZERO_UDP_TESTS").as_deref(), Ok("1"));
    assert_ne!(
        std::fs::read_link("/proc/self/ns/net").unwrap(),
        std::path::PathBuf::from(std::env::var("STAMP_PARENT_NETNS").unwrap()),
        "requires a private network namespace"
    );
    assert!(Command::new("ip")
        .args(["link", "set", "lo", "up"])
        .status()
        .unwrap()
        .success());
}

fn checksum(bytes: &[u8]) -> u16 {
    let mut sum: u32 = bytes
        .chunks(2)
        .map(|part| (u32::from(part[0]) << 8) | u32::from(*part.get(1).unwrap_or(&0)))
        .sum();
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn capture() -> UdpSocket {
    let socket = socket2::Socket::new(
        socket2::Domain::IPV4,
        socket2::Type::from(libc::SOCK_RAW),
        Some(socket2::Protocol::UDP),
    )
    .unwrap();
    socket
        .bind(&"127.0.0.1:0".parse::<SocketAddr>().unwrap().into())
        .unwrap();
    let socket: UdpSocket = socket.into();
    socket
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    socket
}

fn captured_request(
    capture: &UdpSocket,
    source: SocketAddr,
    target: SocketAddr,
    request: &[u8],
    zero: bool,
) {
    let deadline = Instant::now() + Duration::from_secs(3);
    let mut bytes = [0; 4096];
    loop {
        assert!(Instant::now() < deadline, "request not captured");
        let (size, _) = capture.recv_from(&mut bytes).unwrap();
        if size < 28 {
            continue;
        }
        let ihl = usize::from(bytes[0] & 15) * 4;
        if ihl < 20 || ihl + 8 > size {
            continue;
        }
        let udp = &bytes[ihl..size];
        if udp[..2] != source.port().to_be_bytes()
            || udp[2..4] != target.port().to_be_bytes()
            || &udp[8..] != request
        {
            continue;
        }
        assert_eq!(&bytes[12..20], &[127, 0, 0, 1, 127, 0, 0, 1]);
        assert_eq!(
            usize::from(u16::from_be_bytes(bytes[2..4].try_into().unwrap())),
            size
        );
        assert_eq!(
            usize::from(u16::from_be_bytes(udp[4..6].try_into().unwrap())),
            udp.len()
        );
        assert_eq!(bytes[8], 255);
        assert_eq!(checksum(&bytes[..ihl]), 0);
        // Loopback may expose checksum-offload partial values in the default
        // case. Assert the field is nonzero, not that this capture is a final
        // software-completed UDP checksum. Zero must be exactly zero.
        assert_eq!(udp[6..8] == [0, 0], zero);
        eprintln!(
            "captured sender checksum={:04x}, payload={} octets",
            u16::from_be_bytes(udp[6..8].try_into().unwrap()),
            request.len()
        );
        return;
    }
}

fn fields(bytes: &[u8]) -> Vec<(u8, usize, &[u8])> {
    let mut fields = Vec::new();
    let mut at = 112;
    while at < bytes.len() {
        assert!(bytes.len() - at >= 4);
        assert_eq!(bytes[at], 0x80);
        let end = at
            + 4
            + usize::from(u16::from_be_bytes(
                bytes[at + 2..at + 4].try_into().unwrap(),
            ));
        assert!(end <= bytes.len());
        fields.push((bytes[at + 1], at, &bytes[at + 4..end]));
        at = end;
    }
    fields
}

fn check_request(request: &[u8], sequence: u32, ptp: bool, explicit: bool) -> Vec<u8> {
    assert!(request.len() >= 112);
    assert_eq!(&request[..4], &sequence.to_be_bytes());
    assert_eq!(request[24] & 0x40 != 0, ptp);
    assert_ne!(request[25], 0);
    assert_eq!(&request[26..28], &42u16.to_be_bytes());
    assert_eq!(&request[96..112], &wire_hmac::digest(&KEY, &request[..96]));
    if ptp {
        assert!(u32::from_be_bytes(request[20..24].try_into().unwrap()) < 1_000_000_000);
    }
    let actual = fields(request);
    assert_eq!(
        actual.iter().map(|field| field.0).collect::<Vec<_>>(),
        [243, 8, 1]
    );
    let mut metadata = vec![0; 8];
    if explicit {
        metadata.extend_from_slice(&[0x80, 241, 0, 5, 0xa5, 0x12, 0xf0, 0x0d, 0x33]);
    }
    assert_eq!(actual[0].2, metadata);
    let covered = [&request[..4], &request[112..actual[1].1]].concat();
    assert_eq!(actual[1].2, wire_hmac::digest(&KEY, &covered));
    let pattern: &[u8] = if explicit {
        &[0xa5, 0x12, 0xf0, 0x0d, 0x33]
    } else {
        &[0xff, 0, 0xff, 0]
    };
    assert_eq!(actual[2].2, pattern.repeat(20 / pattern.len()));
    metadata
}

fn reply(request: &[u8], mut metadata: Vec<u8>, errors: u32) -> Vec<u8> {
    let mut bytes = vec![0; 112];
    let sequence = u32::from_be_bytes(request[..4].try_into().unwrap());
    bytes[..4].copy_from_slice(&(100 + sequence).to_be_bytes());
    bytes[16..28].copy_from_slice(&request[16..28]);
    bytes[32..40].copy_from_slice(&request[16..24]);
    bytes[48..52].copy_from_slice(&request[..4]);
    bytes[64..74].copy_from_slice(&request[16..26]);
    bytes[80] = 255;
    let digest = wire_hmac::digest(&KEY, &bytes[..96]);
    bytes[96..112].copy_from_slice(&digest);
    metadata[..4].copy_from_slice(&errors.to_be_bytes());
    metadata[4..8].copy_from_slice(&errors.to_be_bytes());
    if metadata.len() > 8 {
        metadata[8] = 0;
    }
    bytes.extend_from_slice(&[0, 243]);
    bytes.extend_from_slice(&(metadata.len() as u16).to_be_bytes());
    bytes.extend_from_slice(&metadata);
    let digest = wire_hmac::digest(&KEY, &[&bytes[..4], &bytes[112..]].concat());
    bytes.extend_from_slice(&[0, 8, 0, 16]);
    bytes.extend_from_slice(&digest);
    let padding = fields(request).last().unwrap().2;
    bytes.extend_from_slice(&[0, 1, 0, 20]);
    bytes.extend_from_slice(padding);
    bytes
}

fn checksum_errors() -> u64 {
    let text = std::fs::read_to_string("/proc/net/snmp").unwrap();
    let mut rows = text.lines().filter_map(|line| line.strip_prefix("Udp: "));
    let index = rows
        .next()
        .unwrap()
        .split_whitespace()
        .position(|name| name == "InCsumErrors")
        .unwrap();
    rows.next()
        .unwrap()
        .split_whitespace()
        .nth(index)
        .unwrap()
        .parse()
        .unwrap()
}

fn bad_checksum_reply(source: SocketAddr, destination: SocketAddr, payload: &[u8]) {
    let raw = socket2::Socket::new(
        socket2::Domain::IPV4,
        socket2::Type::from(libc::SOCK_RAW),
        Some(socket2::Protocol::from(libc::IPPROTO_RAW)),
    )
    .unwrap();
    let length = (payload.len() + 8) as u16;
    let mut udp = [
        source.port().to_be_bytes(),
        destination.port().to_be_bytes(),
        length.to_be_bytes(),
        [0; 2],
    ]
    .concat();
    udp.extend_from_slice(payload);
    let mut pseudo = vec![127, 0, 0, 1, 127, 0, 0, 1, 0, 17];
    pseudo.extend_from_slice(&length.to_be_bytes());
    pseudo.extend_from_slice(&udp);
    let correct = checksum(&pseudo);
    let wrong = if correct == 1 { 2u16 } else { 1u16 };
    udp[6..8].copy_from_slice(&wrong.to_be_bytes());
    let mut ip = vec![
        0x45, 0, 0, 0, 0, 0, 0, 0, 255, 17, 0, 0, 127, 0, 0, 1, 127, 0, 0, 1,
    ];
    ip[2..4].copy_from_slice(&(length + 20).to_be_bytes());
    ip.extend_from_slice(&udp);
    raw.send_to(&ip, &destination.into()).unwrap();
}

#[test]
#[ignore = "requires a private network namespace and CAP_NET_RAW"]
fn authenticated_sender_uses_zero_checksum_only_when_requested() {
    namespace();
    for zero in [false, true] {
        for ptp in [false, true] {
            for explicit in [false, true] {
                let peer = UdpSocket::bind("127.0.0.1:0").unwrap();
                peer.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
                let target = peer.local_addr().unwrap();
                let capture = capture();
                let mut command = Command::new(env!("CARGO_BIN_EXE_stamp-suite"));
                command
                    .args([
                        "--local-addr",
                        "127.0.0.1",
                        "--local-port",
                        "0",
                        "--remote-addr",
                        "127.0.0.1",
                        "--remote-port",
                        &target.port().to_string(),
                        "--count",
                        "3",
                        "--send-delay",
                        "10",
                        "--timeout",
                        "1",
                        "--hwtstamp",
                        "off",
                        "--output-format",
                        "json",
                        "--ssid",
                        "42",
                        "--ber",
                        "--ber-padding-size",
                        "20",
                        "--ber-interval",
                        "1",
                        "--auth-mode",
                        "A",
                        "--hmac-key",
                        "abababababababababababababababab",
                    ])
                    .env("TOKIO_WORKER_THREADS", "2")
                    .env("RUST_LOG", "info")
                    .env_remove("STAMP_HMAC_KEY")
                    .stdout(Stdio::piped())
                    .stderr(Stdio::piped());
                if zero {
                    command.arg("--zero-udp-checksum");
                }
                if ptp {
                    command.args(["--clock-source", "PTP"]);
                }
                if explicit {
                    command.args(["--ber-pattern", "a512f00d33"]);
                }
                let mut sender = Sender(Some(command.spawn().unwrap()));
                for sequence in 0..3 {
                    let mut request = [0; 4096];
                    let (length, source) = peer.recv_from(&mut request).unwrap_or_else(|error| {
                        let output = sender.finish();
                        panic!(
                            "request receive {error}: {}",
                            String::from_utf8_lossy(&output.stderr)
                        );
                    });
                    let request = &request[..length];
                    captured_request(&capture, source, target, request, zero);
                    let metadata = check_request(request, sequence, ptp, explicit);
                    if sequence == 0 {
                        // Valid base/TLV digests, plausible BER errors, invalid UDP
                        // checksum: TX checksum suppression must not disable RX checks.
                        let before = checksum_errors();
                        bad_checksum_reply(target, source, &reply(request, metadata.clone(), 4));
                        let deadline = Instant::now() + Duration::from_secs(2);
                        while checksum_errors() != before + 1 {
                            assert!(
                                Instant::now() < deadline,
                                "kernel did not reject bad reply checksum"
                            );
                            std::thread::sleep(Duration::from_millis(1));
                        }
                    }
                    peer.send_to(&reply(request, metadata, 0), source).unwrap();
                }
                let output = sender.finish();
                assert!(
                    output.status.success(),
                    "{}",
                    String::from_utf8_lossy(&output.stderr)
                );
                let stats: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
                assert_eq!(stats["packets_sent"], 3);
                assert_eq!(stats["packets_received"], 3);
                assert_eq!(stats["packets_lost"], 0);
                for direction in ["forward", "reverse"] {
                    assert_eq!(stats["ber"][direction]["packets_received"], 3);
                    assert_eq!(stats["ber"][direction]["padding_bits"], 480);
                    assert_eq!(stats["ber"][direction]["bit_errors"], 0);
                }
                eprintln!("PASS zero={zero} ptp={ptp} explicit-pattern={explicit}: signatures, samples and RX checksum rejection");
            }
        }
    }
}
