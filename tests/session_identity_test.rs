//! Real socket coverage of session identity and static admission.
#![cfg(all(unix, any(feature = "ttl-nix", not(feature = "ttl-pnet"))))]

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

fn packet(auth: bool, ssid: u16, micro: Option<u16>, seq: u32) -> Vec<u8> {
    let mut data = vec![0; if auth { 112 } else { 44 }];
    data[..4].copy_from_slice(&seq.to_be_bytes());
    let offset = if auth { 26 } else { 14 };
    data[offset - 1] = 1;
    data[offset..offset + 2].copy_from_slice(&ssid.to_be_bytes());
    if auth {
        let key = HmacKey::new(vec![0xAB; 16]).unwrap();
        let mac = compute_packet_hmac(&key, &data, 96);
        data[96..112].copy_from_slice(&mac);
    }
    if let Some(id) = micro {
        data.extend_from_slice(&[0, 11, 0, 4]);
        data.extend_from_slice(&id.to_be_bytes());
        data.extend_from_slice(&[0, 0]);
    }
    data
}

fn exercise(ip: &str, auth: bool, provisioned: bool, stateful: bool) {
    let socket = UdpSocket::bind((ip, 0)).unwrap();
    let other = UdpSocket::bind((ip, 0)).unwrap();
    socket
        .set_read_timeout(Some(Duration::from_millis(100)))
        .unwrap();
    other
        .set_read_timeout(Some(Duration::from_millis(100)))
        .unwrap();
    let reserve = UdpSocket::bind((ip, 0)).unwrap();
    let dest = reserve.local_addr().unwrap();
    drop(reserve);
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_stamp-suite"));
    cmd.args([
        "--is-reflector",
        "--local-addr",
        if ip == "::1" { "::" } else { "0.0.0.0" },
        "--local-port",
        &dest.port().to_string(),
    ]);
    if stateful {
        cmd.arg("--stateful-reflector");
    }
    if auth {
        cmd.args([
            "--auth-mode",
            "A",
            "--hmac-key",
            "abababababababababababababababab",
        ]);
    }
    if provisioned {
        cmd.args(["--session-admission", "provisioned"]);
        for suffix in ["", ",1", ",2"] {
            cmd.args([
                "--reflector-session",
                &format!("42,{},{dest}{suffix}", socket.local_addr().unwrap()),
            ]);
        }
    }
    let mut child = Reflector(
        cmd.stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    let mut response = [0; 512];
    // Use the base session to establish readiness; micro-session sequences
    // must still start at zero after any number of these startup attempts.
    let startup = Instant::now();
    loop {
        assert!(child.0.try_wait().unwrap().is_none(), "reflector exited");
        socket.send_to(&packet(auth, 42, None, 900), dest).unwrap();
        if socket.recv_from(&mut response).is_ok() {
            break;
        }
        assert!(startup.elapsed() < Duration::from_secs(5));
    }
    // A malformed TLV cannot supply a micro ID, but an admitted base session
    // must retain RFC 8972's malformed-TLV echo behavior.
    let mut malformed = packet(auth, 42, None, 901);
    malformed.extend_from_slice(&[0, 11, 0, 3, 0, 7, 0]);
    socket.send_to(&malformed, dest).unwrap();
    socket.recv_from(&mut response).unwrap();
    assert_ne!(response[if auth { 112 } else { 44 }] & 0x40, 0);

    for (micro, expected) in [(1, 0u32), (2, 0), (1, 1), (2, 1)] {
        socket
            .send_to(&packet(auth, 42, Some(micro), 100 + expected), dest)
            .unwrap();
        socket.recv_from(&mut response).unwrap();
        assert_eq!(
            u32::from_be_bytes(response[..4].try_into().unwrap()),
            if stateful { expected } else { 100 + expected }
        );
    }
    // Same tuple, different SSID; same SSID, different source port; and
    // an unprovisioned micro-session must be admitted only in legacy mode.
    for (sender, ssid, micro) in [
        (&socket, 43, None),
        (&other, 42, None),
        (&socket, 42, Some(3)),
    ] {
        sender
            .send_to(&packet(auth, ssid, micro, 100), dest)
            .unwrap();
        let result = sender.recv_from(&mut response);
        assert_eq!(result.is_ok(), !provisioned);
        if result.is_ok() {
            assert_eq!(
                u32::from_be_bytes(response[..4].try_into().unwrap()),
                if stateful { 0 } else { 100 }
            );
        }
    }
    // A wildcard bind must use packet destination metadata, not 0.0.0.0.
    // Linux routes the whole 127/8 prefix to loopback.
    #[cfg(target_os = "linux")]
    if ip != "::1" {
        let other_dest = ("127.0.0.2", dest.port());
        socket
            .send_to(&packet(auth, 42, None, 100), other_dest)
            .unwrap();
        let result = socket.recv_from(&mut response);
        assert_eq!(result.is_ok(), !provisioned);
        if result.is_ok() {
            assert_eq!(
                u32::from_be_bytes(response[..4].try_into().unwrap()),
                if stateful { 0 } else { 100 }
            );
        }
    }
}

#[test]
fn full_identity_and_provisioning_ipv4_open() {
    for provisioned in [false, true] {
        for stateful in [false, true] {
            exercise("127.0.0.1", false, provisioned, stateful);
        }
    }
}

#[test]
fn full_identity_and_provisioning_ipv4_authenticated() {
    for provisioned in [false, true] {
        for stateful in [false, true] {
            exercise("127.0.0.1", true, provisioned, stateful);
        }
    }
}

#[test]
fn full_identity_and_provisioning_ipv6() {
    for auth in [false, true] {
        for provisioned in [false, true] {
            exercise("::1", auth, provisioned, true);
        }
    }
}
