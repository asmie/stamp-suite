//! Live admission checks: reaching the cap or draining cannot reset sequences.
#![cfg(all(
    target_os = "linux",
    any(feature = "ttl-nix", not(feature = "ttl-pnet"))
))]
use stamp_suite::crypto::{compute_packet_hmac, HmacKey};
use std::{
    net::{SocketAddr, UdpSocket},
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
fn packet(seq: u32, auth: bool) -> Vec<u8> {
    let mut data = vec![0; if auth { 112 } else { 44 }];
    data[..4].copy_from_slice(&seq.to_be_bytes());
    let ssid = if auth { 26 } else { 14 };
    data[ssid - 1] = 1;
    data[ssid..ssid + 2].copy_from_slice(&42u16.to_be_bytes());
    if auth {
        let key = HmacKey::new(vec![0xAB; 16]).unwrap();
        let mac = compute_packet_hmac(&key, &data, 96);
        data[96..112].copy_from_slice(&mac);
    }
    data
}
fn exchange(socket: &UdpSocket, target: SocketAddr, seq: u32, auth: bool, expected: Option<u32>) {
    socket
        .set_read_timeout(Some(Duration::from_millis(if expected.is_some() {
            2000
        } else {
            100
        })))
        .unwrap();
    socket.send_to(&packet(seq, auth), target).unwrap();
    let mut data = [0; 256];
    if let Some(expected) = expected {
        let (len, source) = socket.recv_from(&mut data).unwrap();
        assert_eq!(source, target);
        assert_eq!(u32::from_be_bytes(data[..4].try_into().unwrap()), expected);
        let echoed = if auth { 48 } else { 24 };
        assert_eq!(
            u32::from_be_bytes(data[echoed..echoed + 4].try_into().unwrap()),
            seq
        );
        if auth {
            let key = HmacKey::new(vec![0xAB; 16]).unwrap();
            assert_eq!(&data[96..112], &compute_packet_hmac(&key, &data[..len], 96));
        }
    } else {
        let error = socket
            .recv_from(&mut data)
            .expect_err("unadmitted session received a reply");
        assert!(matches!(
            error.kind(),
            std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
        ));
    }
}
#[cfg(feature = "control")]
fn http(addr: SocketAddr, method: &str, path: &str, body: &str) -> serde_json::Value {
    use std::io::{Read, Write};
    let mut stream = std::net::TcpStream::connect_timeout(&addr, Duration::from_secs(2)).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    write!(stream, "{method} {path} HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}", body.len()).unwrap();
    let mut response = String::new();
    stream.read_to_string(&mut response).unwrap();
    assert!(response.starts_with("HTTP/1.1 200"), "{response}");
    let body = response.split_once("\r\n\r\n").unwrap().1;
    if body.is_empty() {
        serde_json::Value::Null
    } else {
        serde_json::from_str(body).unwrap()
    }
}
fn check(ip: &str, auth: bool, stateful: bool) {
    let reserve = UdpSocket::bind((ip, 0)).unwrap();
    let target = reserve.local_addr().unwrap();
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_stamp-suite"));
    cmd.args([
        "--is-reflector",
        "--local-addr",
        ip,
        "--local-port",
        &target.port().to_string(),
        "--max-sessions",
        "1",
        "--hwtstamp",
        "off",
    ]);
    if stateful {
        cmd.arg("--stateful-reflector");
    }
    if auth {
        cmd.args([
            "--auth-mode",
            "A",
            "--hmac-key",
            "ABABABABABABABABABABABABABABABAB",
        ]);
    }
    #[cfg(feature = "control")]
    let control = {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        cmd.args(["--control", "--control-addr", &addr.to_string()]);
        addr
    };
    drop(reserve);
    let mut reflector = Reflector(
        cmd.stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    let known = UdpSocket::bind((ip, 0)).unwrap();
    known
        .set_read_timeout(Some(Duration::from_millis(40)))
        .unwrap();
    let start = Instant::now();
    let mut seq = 0;
    let initial = loop {
        assert!(
            reflector.0.try_wait().unwrap().is_none(),
            "reflector exited"
        );
        known.send_to(&packet(seq, auth), target).unwrap();
        seq += 1;
        let mut bytes = [0; 256];
        if known.recv_from(&mut bytes).is_ok() {
            break u32::from_be_bytes(bytes[..4].try_into().unwrap());
        }
        assert!(start.elapsed() < Duration::from_secs(5));
    };
    let other = UdpSocket::bind((ip, 0)).unwrap();
    for seq in 0..3 {
        exchange(&other, target, seq, auth, None);
    }
    exchange(
        &known,
        target,
        100,
        auth,
        Some(if stateful { initial + 1 } else { 100 }),
    );
    #[cfg(feature = "control")]
    {
        http(control, "POST", "/v1/drain", r#"{"draining":true}"#);
        http(control, "PATCH", "/v1/caps", r#"{"max_sessions":0}"#);
        exchange(&other, target, 4, auth, None);
        exchange(
            &known,
            target,
            101,
            auth,
            Some(if stateful { initial + 2 } else { 101 }),
        );
        http(control, "POST", "/v1/drain", r#"{"draining":false}"#);
        exchange(
            &other,
            target,
            100,
            auth,
            Some(if stateful { 0 } else { 100 }),
        );
        http(control, "PATCH", "/v1/caps", r#"{"max_sessions":1}"#);
        exchange(
            &other,
            target,
            101,
            auth,
            Some(if stateful { 1 } else { 101 }),
        );
        let third = UdpSocket::bind((ip, 0)).unwrap();
        exchange(&third, target, 0, auth, None);
        for socket in [&known, &other] {
            http(
                control,
                "POST",
                "/v1/sessions/expire",
                &serde_json::json!({"client":socket.local_addr().unwrap().to_string()}).to_string(),
            );
        }
        exchange(
            &other,
            target,
            200,
            auth,
            Some(if stateful { 0 } else { 200 }),
        );
        let sessions = http(control, "GET", "/v1/sessions", "");
        assert_eq!(sessions.as_array().unwrap().len(), 1);
        let status = http(control, "GET", "/v1/status", "");
        assert!(status["counters"]["packets_dropped"].as_u64().unwrap() >= 5);
    }
}
#[test]
fn open_ipv4_stateful() {
    check("127.0.0.1", false, true);
}
#[test]
fn open_ipv6_stateful() {
    check("::1", false, true);
}
#[test]
fn auth_ipv4_stateful() {
    check("127.0.0.1", true, true);
}
#[test]
fn auth_ipv6_stateful() {
    check("::1", true, true);
}
#[test]
fn open_ipv4_stateless() {
    check("127.0.0.1", false, false);
}
#[test]
fn open_ipv6_stateless() {
    check("::1", false, false);
}
#[test]
fn auth_ipv4_stateless() {
    check("127.0.0.1", true, false);
}
#[test]
fn auth_ipv6_stateless() {
    check("::1", true, false);
}
