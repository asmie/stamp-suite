//! Independent wire checks for the Type-12 non-monotonic response (§5).
#![cfg(all(
    target_os = "linux",
    any(feature = "ttl-nix", not(feature = "ttl-pnet"))
))]

use stamp_suite::crypto::{compute_packet_hmac, HmacKey};
use std::{
    net::UdpSocket,
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};

struct Reflector(Child);
impl Drop for Reflector {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn packet(seq: u32, ssid: u16, auth: bool, control: bool) -> Vec<u8> {
    let base = if auth { 112 } else { 44 };
    let mut data = vec![0; base];
    data[..4].copy_from_slice(&seq.to_be_bytes());
    let offset = if auth { 26 } else { 14 };
    data[offset - 1] = 1;
    data[offset..offset + 2].copy_from_slice(&ssid.to_be_bytes());
    if control {
        // Request 3 replies, 512 octets each, 1 ms apart.
        data.extend_from_slice(&[0x80, 12, 0, 12, 2, 0, 0, 3]);
        data.extend_from_slice(&1_000_000u32.to_be_bytes());
        data.extend_from_slice(&[0; 4]);
    }
    if auth {
        let key = HmacKey::new(vec![0xAB; 16]).unwrap();
        let mac = compute_packet_hmac(&key, &data, 96);
        data[96..112].copy_from_slice(&mac);
        if control {
            let mut covered = data[..4].to_vec();
            covered.extend_from_slice(&data[base..]);
            data.extend_from_slice(&[0x80, 8, 0, 16]);
            data.extend_from_slice(&key.compute(&covered));
        }
    }
    data
}

fn check(ip: &str, auth: bool, stateful: bool, drop_replayed: bool) {
    let reserve = UdpSocket::bind((ip, 0)).unwrap();
    let destination = reserve.local_addr().unwrap();
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_stamp-suite"));
    cmd.args([
        "--is-reflector",
        "--local-addr",
        ip,
        "--local-port",
        &destination.port().to_string(),
        "--hwtstamp",
        "off",
        "--reflected-control-max-count",
        "3",
    ]);
    if auth {
        cmd.args([
            "--auth-mode",
            "A",
            "--hmac-key",
            "ABABABABABABABABABABABABABABABAB",
        ]);
    }
    if stateful {
        cmd.arg("--stateful-reflector");
    }
    if drop_replayed {
        cmd.arg("--drop-replayed");
    }
    drop(reserve);
    let mut reflector = Reflector(
        cmd.stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    let warmup = UdpSocket::bind((ip, 0)).unwrap();
    warmup
        .set_read_timeout(Some(Duration::from_millis(40)))
        .unwrap();
    let start = Instant::now();
    for seq in 0.. {
        assert!(
            reflector.0.try_wait().unwrap().is_none(),
            "reflector exited"
        );
        warmup
            .send_to(&packet(seq, 0, auth, false), destination)
            .unwrap();
        if warmup.recv_from(&mut [0; 256]).is_ok() {
            break;
        }
        assert!(
            start.elapsed() < Duration::from_secs(5),
            "reflector readiness"
        );
    }
    let socket = UdpSocket::bind((ip, 0)).unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let key = HmacKey::new(vec![0xAB; 16]).unwrap();
    let base = if auth { 112 } else { 44 };
    let echoed_seq = if auth { 48 } else { 24 };
    let mut buffer = [0; 2048];
    let cases = [
        (42, 1000, false),
        (42, 1002, false),
        (42, 1000, true), // replay within the window
        (42, 1001, true), // unseen reordering
        (42, 900, true),  // older than the window
        (42, 1003, false),
        (43, u32::MAX - 1, false), // independent SSID, same UDP endpoints
        (43, u32::MAX, false),
        (43, 0, false),
        (43, u32::MAX, true),
        (43, 1, false),
    ];
    let mut next_seq = [0u32; 2];
    for (ssid, seq, non_monotonic) in cases {
        let request = packet(seq, ssid, auth, true);
        socket.send_to(&request, destination).unwrap();
        for _ in 0..if non_monotonic { 1 } else { 3 } {
            let (len, source) = socket.recv_from(&mut buffer).unwrap();
            assert_eq!(source, destination);
            let data = &buffer[..len];
            assert_eq!(
                u32::from_be_bytes(data[echoed_seq..echoed_seq + 4].try_into().unwrap()),
                seq
            );
            assert_eq!(data[base + 1], 12);
            assert_eq!(data[base] & 0xE8, if non_monotonic { 0x80 } else { 0 });
            assert_eq!(len, if non_monotonic { request.len() } else { 512 });
            let slot = (ssid - 42) as usize;
            assert_eq!(
                u32::from_be_bytes(data[..4].try_into().unwrap()),
                if stateful { next_seq[slot] } else { seq }
            );
            next_seq[slot] += 1;
            if auth {
                assert_eq!(&data[96..112], &compute_packet_hmac(&key, data, 96));
                let mut pos = base;
                loop {
                    assert!(pos + 4 <= len, "missing TLV HMAC");
                    let size = u16::from_be_bytes([data[pos + 2], data[pos + 3]]) as usize;
                    if data[pos + 1] == 8 {
                        assert_eq!(size, 16);
                        let mut covered = data[..4].to_vec();
                        covered.extend_from_slice(&data[base..pos]);
                        assert_eq!(&data[pos + 4..pos + 20], &key.compute(&covered));
                        break;
                    }
                    pos += 4 + size;
                }
            }
        }
        // Detect extra queued copies, then prove a subsequent new request works.
        socket
            .set_read_timeout(Some(Duration::from_millis(100)))
            .unwrap();
        let error = socket
            .recv_from(&mut buffer)
            .expect_err("unexpected extra reply");
        assert!(matches!(
            error.kind(),
            std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
        ));
        socket
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
    }
}

#[test]
fn open_ipv4_stateless() {
    check("127.0.0.1", false, false, false);
}
#[test]
fn open_ipv6_stateful() {
    check("::1", false, true, false);
}
#[test]
fn auth_ipv4_stateful() {
    check("127.0.0.1", true, true, false);
}
#[test]
fn auth_ipv6_stateless() {
    check("::1", true, false, false);
}
#[test]
fn drop_policy_open_ipv4() {
    check("127.0.0.1", false, true, true);
}
#[test]
fn drop_policy_open_ipv6() {
    check("::1", false, false, true);
}
#[test]
fn drop_policy_auth_ipv4() {
    check("127.0.0.1", true, false, true);
}
#[test]
fn drop_policy_auth_ipv6() {
    check("::1", true, true, true);
}
