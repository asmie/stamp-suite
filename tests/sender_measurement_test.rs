//! Independent wire peer verifies sender summaries and final burst draining.
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use std::{
    net::UdpSocket,
    process::{Child, Command, Stdio},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

struct Sender(Option<Child>);
impl Drop for Sender {
    fn drop(&mut self) {
        if let Some(child) = &mut self.0 {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}
impl Sender {
    fn start(peer: &UdpSocket, auth: bool, count: u32, copies: u16) -> Self {
        let ip = peer.local_addr().unwrap().ip().to_string();
        let mut command = Command::new(env!("CARGO_BIN_EXE_stamp-suite"));
        command
            .args([
                "--remote-addr",
                &ip,
                "--remote-port",
                &peer.local_addr().unwrap().port().to_string(),
                "--local-addr",
                &ip,
                "--local-port",
                "0",
                "--count",
                &count.to_string(),
                "--send-delay",
                "20",
                "--timeout",
                "1",
                "--hwtstamp",
                "off",
                "--output-format",
                "json",
                "--direct-measurement",
                "--follow-up-telemetry",
                "--reflected-control-count",
                &copies.to_string(),
            ])
            .env_remove("STAMP_HMAC_KEY")
            .env("RUST_LOG", "off")
            .env("TOKIO_WORKER_THREADS", "2");
        if auth {
            command.args([
                "--auth-mode",
                "A",
                "--hmac-key",
                "ABABABABABABABABABABABABABABABAB",
            ]);
        }
        Self(Some(
            command
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap(),
        ))
    }
    fn finish(mut self) -> serde_json::Value {
        let deadline = Instant::now() + Duration::from_secs(5);
        while self.0.as_mut().unwrap().try_wait().unwrap().is_none() {
            assert!(Instant::now() < deadline, "sender failed to exit");
            std::thread::sleep(Duration::from_millis(10));
        }
        let output = self.0.take().unwrap().wait_with_output().unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        serde_json::from_slice(&output.stdout).unwrap()
    }
}
fn ptp_now() -> u64 {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
    (now.as_secs() << 32) | u64::from(now.subsec_nanos())
}
fn sign(parts: &[&[u8]]) -> [u8; 16] {
    let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(&[0xAB; 16]).unwrap();
    for part in parts {
        mac.update(part);
    }
    mac.finalize().into_bytes()[..16].try_into().unwrap()
}
fn reply(
    request: &[u8],
    auth: bool,
    reflected: u32,
    dm: [u32; 3],
    previous: Option<(u32, u64)>,
) -> (Vec<u8>, u64) {
    let base = if auth { 112 } else { 44 };
    let (ts, err, rx, seq, echo, echo_err, ttl) = if auth {
        (16, 24, 32, 48, 64, 72, 80)
    } else {
        (4, 12, 16, 24, 28, 36, 40)
    };
    let t3 = ptp_now();
    let mut bytes = vec![0; base];
    bytes[..4].copy_from_slice(&reflected.to_be_bytes());
    bytes[ts..ts + 8].copy_from_slice(&t3.to_be_bytes());
    bytes[err..err + 2].copy_from_slice(&0x4001u16.to_be_bytes());
    bytes[rx..rx + 8].copy_from_slice(&t3.to_be_bytes());
    bytes[seq..seq + 4].copy_from_slice(&request[..4]);
    bytes[echo..echo + 8].copy_from_slice(&request[ts..ts + 8]);
    bytes[echo_err..echo_err + 2].copy_from_slice(&request[err..err + 2]);
    bytes[ttl] = 64;
    bytes.extend_from_slice(&[0, 5, 0, 12]);
    for n in dm {
        bytes.extend_from_slice(&n.to_be_bytes());
    }
    bytes.extend_from_slice(&[0, 7, 0, 16]);
    let (previous_seq, previous_ts) = previous.unwrap_or((0, 0));
    bytes.extend_from_slice(&previous_seq.to_be_bytes());
    bytes.extend_from_slice(&previous_ts.to_be_bytes());
    bytes.extend_from_slice(&[2, 0, 0, 0]);
    if auth {
        let digest = sign(&[&bytes[..4], &bytes[base..]]);
        bytes.extend_from_slice(&[0, 8, 0, 16]);
        bytes.extend_from_slice(&digest);
        let digest = sign(&[&bytes[..96]]);
        bytes[96..112].copy_from_slice(&digest);
    }
    (bytes, t3)
}
fn peer(auth: bool) -> UdpSocket {
    let socket = UdpSocket::bind((if auth { "::1" } else { "127.0.0.1" }, 0)).unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    socket
}
fn burst(auth: bool) {
    let peer = peer(auth);
    let sender = Sender::start(&peer, auth, 1, 3);
    let mut request = [0; 2048];
    let (len, source) = peer.recv_from(&mut request).unwrap();
    let mut previous = None;
    for n in 0..3 {
        let (bytes, timestamp) = reply(&request[..len], auth, 10 + n, [1, 1, n], previous);
        peer.send_to(&bytes, source).unwrap();
        if n == 0 {
            peer.send_to(&bytes, source).unwrap();
        }
        previous = Some((10 + n, timestamp));
        // Copies arrive after the main send loop and the first response.
        std::thread::sleep(Duration::from_millis(60));
    }
    let stats = sender.finish();
    assert_eq!(stats["packets_received"], 1, "{stats}");
    let m = &stats["measurements"];
    for (name, value) in [
        ("unique_replies", 3),
        ("additional_replies", 2),
        ("duplicate_replies", 1),
        ("unobserved_requested_replies", 0),
    ] {
        assert_eq!(m[name], value, "{stats}");
    }
    assert_eq!(m["reply_rtt"]["samples"], 3);
    assert_eq!(m["direct_measurement"]["forward_missing"], 0);
    assert_eq!(m["direct_measurement"]["reverse_missing"], 0);
    assert_eq!(m["follow_up"]["matched"], 2, "{stats}");
    assert!(
        m["follow_up"]["reverse_delay"]["avg_ms"]
            .as_f64()
            .unwrap()
            .abs()
            < 1000.0
    );
}
fn loss(auth: bool) {
    let peer = peer(auth);
    let sender = Sender::start(&peer, auth, 4, 1);
    let mut request = [0; 2048];
    let mut previous = None;
    for n in 0..4 {
        let (len, source) = peer.recv_from(&mut request).unwrap();
        assert_eq!(u32::from_be_bytes(request[..4].try_into().unwrap()), n);
        if n == 1 {
            continue;
        } // Model one request absent from reflector's in-profile count.
        let tx = if n == 0 { 0 } else { n - 1 + u32::from(n == 3) };
        let rx = if n == 0 { 1 } else { n };
        let (bytes, timestamp) = reply(&request[..len], auth, 10 + tx, [n + 1, rx, tx], previous);
        peer.send_to(&bytes, source).unwrap();
        previous = Some((10 + tx, timestamp));
    }
    let stats = sender.finish();
    assert_eq!(stats["packets_received"], 3, "{stats}");
    assert_eq!(stats["packets_lost"], 1);
    let m = &stats["measurements"]["direct_measurement"];
    assert_eq!(m["sender_packets"], 3, "{stats}");
    assert_eq!(m["reflector_received"], 2);
    assert_eq!(m["forward_missing"], 1);
    assert_eq!(m["reflector_transmitted"], 3);
    assert_eq!(m["replies_received"], 2);
    assert_eq!(m["reverse_missing"], 1);
}
#[test]
fn ipv4_open_burst_and_duplicate() {
    burst(false);
}
#[test]
fn ipv6_authenticated_burst_and_duplicate() {
    burst(true);
}
#[test]
fn ipv4_open_directional_counter_window() {
    loss(false);
}
#[test]
fn ipv6_authenticated_directional_counter_window() {
    loss(true);
}
