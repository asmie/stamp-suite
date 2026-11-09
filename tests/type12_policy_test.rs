//! Type 12 policy decisions through real UDP dispatch and independent bytes.
#![cfg(all(
    target_os = "linux",
    any(feature = "ttl-nix", not(feature = "ttl-pnet"))
))]

#[path = "common/reflector.rs"]
mod reflector;
#[path = "common/wire_hmac.rs"]
mod wire_hmac;
use reflector::Reflector;
use std::{
    net::{SocketAddr, UdpSocket},
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};

const KEY: [u8; 16] = [0xab; 16];

fn request(mode: u8, sequence: u32, count: u16, interval: u32, sign_tlvs: bool) -> Vec<u8> {
    let auth = mode == 2;
    let base = if auth { 112 } else { 44 };
    let mut bytes = vec![0; base];
    bytes[..4].copy_from_slice(&sequence.to_be_bytes());
    let error = if auth { 24 } else { 12 };
    bytes[error + 1] = 1;
    bytes[error + 2..error + 4].copy_from_slice(&42u16.to_be_bytes());
    // Received C is deliberately set: the reflector must ignore it and decide
    // from the actual request and configured policy.
    bytes.extend_from_slice(&[0x90, 12, 0, 12]);
    bytes.extend_from_slice(&500u16.to_be_bytes());
    bytes.extend_from_slice(&count.to_be_bytes());
    bytes.extend_from_slice(&interval.to_be_bytes());
    bytes.extend_from_slice(&[0; 4]);
    if sign_tlvs {
        let mut covered = bytes[..4].to_vec();
        covered.extend_from_slice(&bytes[base..]);
        bytes.extend_from_slice(&[0x80, 8, 0, 16]);
        bytes.extend_from_slice(&wire_hmac::digest(&KEY, &covered));
    }
    if auth {
        let mac = wire_hmac::digest(&KEY, &bytes[..96]);
        bytes[96..112].copy_from_slice(&mac);
    }
    bytes
}

fn server(ip: &str, mode: u8) -> Reflector {
    let mut command = Reflector::command(ip);
    command.args([
        "--hwtstamp",
        "off",
        "--reflected-control-max-count",
        "16",
        "--reflected-control-max-rate",
        "5000",
        "--reflected-control-max-volume",
        "1000",
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
    Reflector::spawn(command).unwrap()
}

fn receive(socket: &UdpSocket, source: SocketAddr) -> Vec<u8> {
    socket
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let mut bytes = [0; 2048];
    let (size, from) = socket.recv_from(&mut bytes).unwrap();
    assert_eq!(from, source, "reply must use a node-local source");
    bytes[..size].to_vec()
}

fn quiet(socket: &UdpSocket) {
    socket
        .set_read_timeout(Some(Duration::from_millis(180)))
        .unwrap();
    let error = socket
        .recv_from(&mut [0; 2048])
        .expect_err("unexpected extra reply");
    assert!(
        matches!(
            error.kind(),
            std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
        ),
        "{error}"
    );
}

fn verify_signatures(bytes: &[u8], mode: u8, originated: bool) {
    let base = if mode == 2 { 112 } else { 44 };
    if mode == 2 {
        assert_eq!(&bytes[96..112], &wire_hmac::digest(&KEY, &bytes[..96]));
    }
    let mut pos = base;
    let mut seen = 0;
    while pos < bytes.len() {
        assert!(pos + 4 <= bytes.len());
        let length = u16::from_be_bytes([bytes[pos + 2], bytes[pos + 3]]) as usize;
        assert!(pos + 4 + length <= bytes.len());
        if bytes[pos + 1] == 8 {
            assert_eq!(length, 16);
            assert_eq!(bytes[pos], if originated { 0x80 } else { 0 }, "HMAC flags");
            assert_eq!(pos + 4 + length, bytes.len());
            let mut covered = bytes[..4].to_vec();
            covered.extend_from_slice(&bytes[base..pos]);
            assert_eq!(&bytes[pos + 4..], &wire_hmac::digest(&KEY, &covered));
            seen += 1;
        }
        pos += 4 + length;
    }
    assert_eq!(seen, usize::from(mode != 0));
}

#[test]
fn exact_rate_volume_and_zero_count_decisions_reach_the_wire() {
    for ip in ["127.0.0.1", "::1"] {
        for mode in 0..3 {
            let reflector = server(ip, mode);
            let socket = UdpSocket::bind((ip, 0)).unwrap();
            for (index, (count, interval, replies, flags)) in [
                (2, 100_000_001, 2, 0),    // just below the rate ceiling
                (2, 100_000_000, 2, 0),    // exact rate and volume ceilings
                (2, 99_999_999, 1, 0x10),  // fractionally above: one C response
                (3, 100_000_000, 1, 0x10), // volume only: one C response
                (0, 100_000_000, 0, 0),    // enabled new count-zero request: no reply
            ]
            .into_iter()
            .enumerate()
            {
                socket
                    .send_to(
                        &request(mode, index as u32 + 1, count, interval, mode != 0),
                        reflector.address,
                    )
                    .unwrap();
                for _ in 0..replies {
                    let bytes = receive(&socket, reflector.address);
                    let base = if mode == 2 { 112 } else { 44 };
                    assert_eq!(bytes.len(), 500);
                    assert_eq!(bytes[base + 1], 12);
                    assert_eq!(
                        bytes[base], flags,
                        "ip={ip} mode={mode} interval={interval} count={count}"
                    );
                    verify_signatures(&bytes, mode, false);
                }
                quiet(&socket);
            }
        }
    }
}

#[test]
fn protected_type12_profile_rejects_unverified_amplification() {
    for ip in ["127.0.0.1", "::1"] {
        let reflector = server(ip, 2);
        let socket = UdpSocket::bind((ip, 0)).unwrap();
        for (seq, missing) in [(1, true), (2, false)] {
            let mut bytes = request(2, seq, 2, 100_000_000, !missing);
            if !missing {
                let last = bytes.len() - 1;
                bytes[last] ^= 1;
            }
            socket.send_to(&bytes, reflector.address).unwrap();
            let reply = receive(&socket, reflector.address);
            assert_eq!(
                reply.len(),
                bytes.len(),
                "failed extensions must not execute requested padding"
            );
            assert_eq!(
                reply[112] & 0xf0,
                0x20,
                "only I is set; Type 12 is not executed"
            );
            assert_eq!(&reply[96..112], &wire_hmac::digest(&KEY, &reply[..96]));
            if !missing {
                assert_eq!(&reply[reply.len() - 16..], &bytes[bytes.len() - 16..]);
            }
            quiet(&socket);
        }
        let mut bad_base = request(2, 3, 2, 100_000_000, true);
        bad_base[96] ^= 1;
        socket.send_to(&bad_base, reflector.address).unwrap();
        quiet(&socket);
        socket
            .send_to(&request(2, 4, 2, 100_000_000, true), reflector.address)
            .unwrap();
        for _ in 0..2 {
            let reply = receive(&socket, reflector.address);
            assert_eq!(reply.len(), 500);
            assert_eq!(reply[112], 0);
            verify_signatures(&reply, 2, false);
        }
        quiet(&socket);
        // An optional-HMAC open profile is intentionally outside this claim:
        // verify-tlv-hmac does not require a missing optional HMAC to appear.
        let optional = server(ip, 1);
        socket
            .send_to(&request(1, 1, 2, 100_000_000, false), optional.address)
            .unwrap();
        for _ in 0..2 {
            let reply = receive(&socket, optional.address);
            assert_eq!(reply[44], 0);
            verify_signatures(&reply, 1, false);
        }
        quiet(&socket);
    }
}

#[test]
fn every_l3_group_must_match_before_wire_reflection() {
    for ip in ["127.0.0.1", "::1"] {
        let address: std::net::IpAddr = ip.parse().unwrap();
        let prefix = match address {
            std::net::IpAddr::V4(v) => v.octets().to_vec(),
            std::net::IpAddr::V6(v) => v.octets().to_vec(),
        };
        let mut good = vec![0, 11];
        good.extend_from_slice(&(prefix.len() as u16 + 4).to_be_bytes());
        good.extend_from_slice(&[(prefix.len() * 8) as u8, 0, 0, 0]);
        good.extend_from_slice(&prefix);
        let mut bad = good.clone();
        bad[8..].fill(0); // unspecified addresses are not local interface addresses
        for mode in 0..3 {
            let reflector = server(ip, mode);
            let socket = UdpSocket::bind((ip, 0)).unwrap();
            for (index, (groups, accepted)) in [
                ([bad.clone(), good.clone()].concat(), false),
                ([good.clone(), bad.clone()].concat(), false),
                ([good.clone(), good.clone()].concat(), true),
            ]
            .into_iter()
            .enumerate()
            {
                let base = if mode == 2 { 112 } else { 44 };
                let mut bytes = request(mode, index as u32 + 1, 1, 100_000_000, false);
                bytes.truncate(base + 12); // base, TLV header and eight control octets
                bytes.extend_from_slice(&groups);
                bytes[base + 2..base + 4].copy_from_slice(&(8 + groups.len() as u16).to_be_bytes());
                if mode != 0 {
                    let mut covered = bytes[..4].to_vec();
                    covered.extend_from_slice(&bytes[base..]);
                    bytes.extend_from_slice(&[0x80, 8, 0, 16]);
                    bytes.extend_from_slice(&wire_hmac::digest(&KEY, &covered));
                }
                socket.send_to(&bytes, reflector.address).unwrap();
                if accepted {
                    let reply = receive(&socket, reflector.address);
                    assert_eq!(reply.len(), 500);
                    assert_eq!(reply[base], 0);
                    verify_signatures(&reply, mode, false);
                }
                quiet(&socket);
            }
        }
    }
}

struct Sender(Child);
impl Drop for Sender {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
fn sender_control_defaults_and_static_or_scaled_requests_clear_c() {
    for ip in ["127.0.0.1", "::1"] {
        for auth in [false, true] {
            for profile in 0..3 {
                let peer = UdpSocket::bind((ip, 0)).unwrap();
                peer.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
                let mut command = Command::new(env!("CARGO_BIN_EXE_stamp-suite"));
                command
                    .args([
                        "--remote-addr",
                        ip,
                        "--remote-port",
                        &peer.local_addr().unwrap().port().to_string(),
                        "--local-addr",
                        ip,
                        "--local-port",
                        "0",
                        "--count",
                        "1",
                        "--timeout",
                        "0",
                        "--hwtstamp",
                        "off",
                    ])
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .env_remove("STAMP_HMAC_KEY")
                    .env("TOKIO_WORKER_THREADS", "2");
                if auth {
                    command.args([
                        "--auth-mode",
                        "A",
                        "--hmac-key",
                        "abababababababababababababababab",
                    ]);
                }
                if profile != 0 {
                    command.args(["--reflected-control-count", "2"]);
                }
                if profile == 2 {
                    command.args(["--cos", "--ecn", "2"]);
                }
                let mut sender = Sender(command.spawn().unwrap());
                let mut bytes = [0; 2048];
                let (length, _) = peer.recv_from(&mut bytes).unwrap();
                let bytes = &bytes[..length];
                if auth {
                    assert_eq!(&bytes[96..112], &wire_hmac::digest(&KEY, &bytes[..96]));
                }
                let mut pos = if auth { 112 } else { 44 };
                let mut controls = 0;
                while pos < bytes.len() {
                    let size = u16::from_be_bytes([bytes[pos + 2], bytes[pos + 3]]) as usize;
                    assert!(pos + 4 + size <= bytes.len());
                    if bytes[pos + 1] == 12 {
                        controls += 1;
                        assert_eq!(bytes[pos], 0x80, "sender emits U only, with C clear");
                        assert_eq!(&bytes[pos + 4..pos + 6], &[0, 0]);
                        assert_eq!(&bytes[pos + 6..pos + 8], &2u16.to_be_bytes());
                        assert_eq!(&bytes[pos + 8..pos + 12], &1_000_000u32.to_be_bytes());
                    }
                    pos += 4 + size;
                }
                assert_eq!(controls, usize::from(profile != 0));
                if profile != 0 {
                    verify_signatures(bytes, if auth { 2 } else { 0 }, true);
                }
                let start = Instant::now();
                loop {
                    if let Some(status) = sender.0.try_wait().unwrap() {
                        assert!(status.success());
                        break;
                    }
                    assert!(
                        start.elapsed() < Duration::from_secs(3),
                        "sender did not stop"
                    );
                    std::thread::sleep(Duration::from_millis(5));
                }
            }
        }
    }
}
