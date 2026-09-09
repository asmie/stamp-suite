//! Independent wire checks for clock discipline, encoding and TX provenance.
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
fn request(auth: bool, seq: u32, extensions: bool) -> Vec<u8> {
    let base = if auth { 112 } else { 44 };
    let mut data = vec![0; base];
    data[..4].copy_from_slice(&seq.to_be_bytes());
    let error = if auth { 24 } else { 12 };
    data[error + 1] = 1;
    data[error + 2..error + 4].copy_from_slice(&42u16.to_be_bytes());
    let key = HmacKey::new(vec![0xAB; 16]).unwrap();
    if extensions {
        // Deliberately bogus sender metadata must be replaced with local facts.
        data.extend_from_slice(&[0x80, 3, 0, 4, 255, 255, 255, 255]);
        data.extend_from_slice(&[0x80, 7, 0, 16]);
        data.extend_from_slice(&[0; 16]);
        data.extend_from_slice(&[0x80, 12, 0, 12, 0, 0, 0, 3]);
        data.extend_from_slice(&5_000_000u32.to_be_bytes());
        data.extend_from_slice(&[0; 4]);
        if auth {
            let mut covered = data[..4].to_vec();
            covered.extend_from_slice(&data[base..]);
            data.extend_from_slice(&[0x80, 8, 0, 16]);
            data.extend_from_slice(&key.compute(&covered));
        }
    }
    if auth {
        let mac = compute_packet_hmac(&key, &data, 96);
        data[96..112].copy_from_slice(&mac);
    }
    data
}
fn exercise(ipv6: bool, auth: bool, stateful: bool) {
    let ip = if ipv6 { "::1" } else { "127.0.0.1" };
    for (format, source, code, synchronized) in [
        ("PTP", None, 5, false),
        ("NTP", Some("gps"), 4, true),
        ("PTP", Some("ntp"), 1, true),
        ("NTP", Some("ptp"), 2, false),
    ] {
        let reserved = UdpSocket::bind((ip, 0)).unwrap();
        let target = reserved.local_addr().unwrap();
        drop(reserved);
        let mut command = Command::new(env!("CARGO_BIN_EXE_stamp-suite"));
        command.args([
            "--is-reflector",
            "--local-addr",
            ip,
            "--local-port",
            &target.port().to_string(),
            "--clock-source",
            format,
            "--hardware-clock-sync-source",
            "ssu-bits",
            "--hwtstamp",
            if cfg!(feature = "hwtstamp") {
                "on"
            } else {
                "off"
            },
            "--reflected-control-max-count",
            "3",
        ]);
        if let Some(source) = source {
            command.args(["--clock-sync-source", source]);
        }
        if synchronized {
            command.arg("--clock-synchronized");
        }
        if stateful {
            command.arg("--stateful-reflector");
        }
        if auth {
            command.args([
                "--auth-mode",
                "A",
                "--hmac-key",
                "abababababababababababababababab",
            ]);
        }
        let mut reflector = Reflector(
            command
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .unwrap(),
        );
        let socket = UdpSocket::bind((ip, 0)).unwrap();
        socket
            .set_read_timeout(Some(Duration::from_millis(40)))
            .unwrap();
        let started = Instant::now();
        loop {
            assert!(reflector.0.try_wait().unwrap().is_none());
            socket.send_to(&request(auth, 0, false), target).unwrap();
            if socket.recv_from(&mut [0; 256]).is_ok() {
                break;
            }
            assert!(started.elapsed() < Duration::from_secs(5));
        }
        socket
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        socket.send_to(&request(auth, 1, true), target).unwrap();
        let mut previous = None;
        for copy in 0..3 {
            let mut data = [0; 2048];
            let (len, _) = socket.recv_from(&mut data).unwrap();
            let data = &data[..len];
            let base = if auth { 112 } else { 44 };
            let error = if auth { 24 } else { 12 };
            let estimate = u16::from_be_bytes(data[error..error + 2].try_into().unwrap());
            assert_eq!(estimate & 0x8000 != 0, synchronized);
            assert_eq!(estimate & 0x4000 != 0, format == "PTP");
            // Loopback has no NIC timestamps: even --hwtstamp on falls back
            // to software. The separate PHC source must not leak into Type 3.
            assert_eq!(&data[base..base + 8], &[0, 3, 0, 4, code, 2, code, 2]);
            let follow = &data[base + 12..base + 28];
            if stateful {
                assert_eq!(follow[12], 2, "actual software Follow-Up method");
                let seq = u32::from_be_bytes(follow[..4].try_into().unwrap());
                if let Some(previous) = previous {
                    assert_eq!(seq, previous);
                }
                assert_ne!(&follow[4..12], &[0; 8]);
            } else {
                assert_eq!(&follow[..12], &[0; 12]);
            }
            let seq = u32::from_be_bytes(data[..4].try_into().unwrap());
            if stateful {
                if let Some(previous) = previous {
                    assert_eq!(seq, previous + 1);
                }
            } else {
                assert_eq!(seq, 1);
            }
            previous = Some(seq);
            if auth {
                let key = HmacKey::new(vec![0xAB; 16]).unwrap();
                assert_eq!(&data[96..112], &compute_packet_hmac(&key, data, 96));
                let pos = len - 20;
                assert_eq!(&data[pos..pos + 4], &[0, 8, 0, 16]);
                let mut covered = data[..4].to_vec();
                covered.extend_from_slice(&data[base..pos]);
                assert_eq!(&data[pos + 4..], &key.compute(&covered));
            }
            assert_eq!(data[base + 28] & 0xf0, 0, "normal burst copy {copy}");
        }
    }
}
#[test]
fn ipv4_open_stateful() {
    exercise(false, false, true);
}
#[test]
fn ipv4_open_stateless() {
    exercise(false, false, false);
}
#[test]
fn ipv4_auth_stateful() {
    exercise(false, true, true);
}
#[test]
fn ipv4_auth_stateless() {
    exercise(false, true, false);
}
#[test]
fn ipv6_open_stateful() {
    exercise(true, false, true);
}
#[test]
fn ipv6_open_stateless() {
    exercise(true, false, false);
}
#[test]
fn ipv6_auth_stateful() {
    exercise(true, true, true);
}
#[test]
fn ipv6_auth_stateless() {
    exercise(true, true, false);
}
