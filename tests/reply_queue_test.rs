//! Real UDP overload, capacity recovery and bounded shutdown with queued bursts.
#![cfg(all(
    target_os = "linux",
    any(feature = "ttl-nix", not(feature = "ttl-pnet"))
))]

use stamp_suite::crypto::HmacKey;
use std::{
    io::Read,
    net::UdpSocket,
    process::Stdio,
    time::{Duration, Instant},
};

#[path = "common/reflector.rs"]
mod reflector;
use reflector::Reflector;

fn request(auth: bool, seq: u32, interval: Option<u32>) -> Vec<u8> {
    let base = if auth { 112 } else { 44 };
    let mut data = vec![0; base];
    data[..4].copy_from_slice(&seq.to_be_bytes());
    let offset = if auth { 26 } else { 14 };
    data[offset - 1] = 1;
    data[offset..offset + 2].copy_from_slice(&42u16.to_be_bytes());
    if let Some(interval) = interval {
        data.extend_from_slice(&[0x80, 12, 0, 12, 0, 0, 0, 3]);
        data.extend_from_slice(&interval.to_be_bytes());
        data.extend_from_slice(&[0; 4]);
    }
    if auth {
        let key = HmacKey::new(vec![0xAB; 16]).unwrap();
        let mac = key.compute(&data[..96]);
        data[96..112].copy_from_slice(&mac);
        if interval.is_some() {
            let mut covered = data[..4].to_vec();
            covered.extend_from_slice(&data[base..]);
            data.extend_from_slice(&[0x80, 8, 0, 16]);
            data.extend_from_slice(&key.compute(&covered));
        }
    }
    data
}

fn receive(socket: &UdpSocket, auth: bool) -> Option<(u32, u32)> {
    let mut data = [0; 2048];
    match socket.recv(&mut data) {
        Ok(n) => {
            assert!(n >= if auth { 112 } else { 44 });
            if auth {
                assert_eq!(
                    &data[96..112],
                    &HmacKey::new(vec![0xAB; 16]).unwrap().compute(&data[..96])
                );
            }
            let offset = if auth { 48 } else { 24 };
            Some((
                u32::from_be_bytes(data[..4].try_into().unwrap()),
                u32::from_be_bytes(data[offset..offset + 4].try_into().unwrap()),
            ))
        }
        Err(e)
            if matches!(
                e.kind(),
                std::io::ErrorKind::WouldBlock
                    | std::io::ErrorKind::TimedOut
                    | std::io::ErrorKind::ConnectionRefused
            ) =>
        {
            None
        }
        Err(e) => panic!("receive failed: {e}"),
    }
}

fn start(ip: &str, auth: bool, grace: u32) -> (Reflector, UdpSocket) {
    let mut cmd = Reflector::command(ip);
    cmd.args([
        "--stateful-reflector",
        "--hwtstamp",
        "off",
        "--output-format",
        "json",
        "--reflected-control-max-count",
        "16",
        "--reflector-queue-capacity",
        "1",
        "--reflector-shutdown-grace-ms",
        &grace.to_string(),
        "--session-timeout",
        "0",
    ])
    .env_remove("STAMP_HMAC_KEY")
    .stdout(Stdio::piped());
    if auth {
        cmd.args(["-A", "A", "--hmac-key", "abababababababababababababababab"]);
    }
    let child = Reflector::spawn(cmd).unwrap();
    let address = child.address;
    let socket = UdpSocket::bind((ip, 0)).unwrap();
    socket.connect(address).unwrap();
    socket
        .set_read_timeout(Some(Duration::from_millis(30)))
        .unwrap();
    (child, socket)
}

fn next(socket: &UdpSocket, auth: bool) -> (u32, u32) {
    let start = Instant::now();
    loop {
        if let Some(response) = receive(socket, auth) {
            return response;
        }
        assert!(start.elapsed() < Duration::from_secs(3), "response missing");
    }
}
fn signal(child: &Reflector, signal: i32) {
    // SAFETY: kill(2) accesses no memory. The PID is our child, which is not
    // reaped until `finish`, so it cannot name another process.
    assert_eq!(unsafe { libc::kill(child.child.id() as i32, signal) }, 0);
}
fn finish(child: &mut Reflector) -> serde_json::Value {
    let start = Instant::now();
    loop {
        if let Some(status) = child.child.try_wait().unwrap() {
            assert!(status.success());
            break;
        }
        assert!(
            start.elapsed() < Duration::from_secs(3),
            "shutdown exceeded its bound"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    let mut output = String::new();
    child
        .child
        .stdout
        .take()
        .unwrap()
        .read_to_string(&mut output)
        .unwrap();
    serde_json::from_str(&output).unwrap()
}

#[test]
fn full_burst_queue_rejects_requests_and_recovers_without_consuming_sequences() {
    for (ip, auth) in [("127.0.0.1", false), ("::1", true)] {
        let (mut child, socket) = start(ip, auth, 0);
        socket.send(&request(auth, 10, Some(200_000_000))).unwrap();
        assert_eq!(next(&socket, auth), (0, 10));
        socket.send(&request(auth, 11, None)).unwrap();
        assert_eq!(next(&socket, auth), (1, 10));
        assert_eq!(next(&socket, auth), (2, 10));
        std::thread::sleep(Duration::from_millis(20));
        socket.send(&request(auth, 12, None)).unwrap();
        assert_eq!(next(&socket, auth), (3, 12));
        signal(&child, libc::SIGINT);
        let stats = finish(&mut child);
        assert!(stats["reply_queue_rejected"].as_u64().unwrap() >= 1);
        assert_eq!(stats["queued_replies_cancelled"], 0);
    }
}

#[test]
fn shutdown_cancels_long_bursts_or_finishes_short_ones_within_grace() {
    for (ip, auth) in [("127.0.0.1", false), ("::1", true)] {
        for (grace, interval, complete) in [
            (0, 1_000_000_000, false),
            (150, 1_000_000_000, false),
            (500, 80_000_000, true),
        ] {
            let (mut child, socket) = start(ip, auth, grace);
            socket.send(&request(auth, 10, Some(interval))).unwrap();
            assert_eq!(next(&socket, auth), (0, 10));
            let began = Instant::now();
            signal(&child, libc::SIGTERM);
            if complete {
                assert_eq!(next(&socket, auth), (1, 10));
                assert_eq!(next(&socket, auth), (2, 10));
            }
            let stats = finish(&mut child);
            assert!(began.elapsed() < Duration::from_secs(2));
            if grace == 150 {
                assert!(began.elapsed() >= Duration::from_millis(140));
            }
            assert_eq!(
                stats["queued_replies_cancelled"],
                if complete { 0 } else { 2 }
            );
            assert!(
                receive(&socket, auth).is_none(),
                "no late replies after shutdown"
            );
        }
    }
}
