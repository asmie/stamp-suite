//! Scrape real CLI processes so recorder state cannot leak between tests.
#![cfg(all(
    target_os = "linux",
    feature = "metrics",
    any(feature = "ttl-nix", not(feature = "ttl-pnet"))
))]
use std::{
    io::{Read, Write},
    net::{TcpListener, TcpStream, UdpSocket},
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};
struct Reflector {
    child: Child,
    udp: u16,
    metrics: u16,
}
impl Drop for Reflector {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}
impl Reflector {
    fn start(extra: &[&str]) -> (Self, f64) {
        let udp = UdpSocket::bind("127.0.0.1:0").unwrap();
        let port = udp.local_addr().unwrap().port();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let metrics = listener.local_addr().unwrap().port();
        drop((udp, listener));
        let child = Command::new(env!("CARGO_BIN_EXE_stamp-suite"))
            .args([
                "-i",
                "--local-addr",
                "127.0.0.1",
                "--local-port",
                &port.to_string(),
                "--hwtstamp",
                "off",
                "--metrics",
                "--metrics-addr",
                &format!("127.0.0.1:{metrics}"),
                "--reflected-control-max-count",
                "3",
            ])
            .args(extra)
            .env("RUST_LOG", "off")
            .env("TOKIO_WORKER_THREADS", "2")
            .env_remove("STAMP_HMAC_KEY")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let mut server = Self {
            child,
            udp: port,
            metrics,
        };
        let probe = client("127.0.0.9");
        let until = Instant::now() + Duration::from_secs(5);
        loop {
            assert!(server.child.try_wait().unwrap().is_none());
            probe.send_to(&[0; 44], ("127.0.0.1", port)).unwrap();
            if probe.recv(&mut [0; 256]).is_ok() {
                break;
            }
            assert!(Instant::now() < until);
        }
        let baseline = value(&server.scrape(), "stamp_reflector_packets_reflected_total");
        assert!(baseline >= 1.0);
        (server, baseline)
    }
    fn scrape(&self) -> String {
        let mut stream = TcpStream::connect(("127.0.0.1", self.metrics)).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        stream
            .write_all(b"GET /metrics HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            .unwrap();
        let mut text = String::new();
        stream.read_to_string(&mut text).unwrap();
        assert!(text.starts_with("HTTP/1.1 200"), "{text}");
        text
    }
    fn wait_metric(&self, series: &str, expected: f64) -> String {
        let until = Instant::now() + Duration::from_secs(3);
        loop {
            let text = self.scrape();
            if value(&text, series) == expected {
                return text;
            }
            assert!(Instant::now() < until, "{series} != {expected}: {text}");
            std::thread::sleep(Duration::from_millis(5));
        }
    }
}
fn client(ip: &str) -> UdpSocket {
    let s = UdpSocket::bind((ip, 0)).unwrap();
    s.set_read_timeout(Some(Duration::from_millis(100)))
        .unwrap();
    s
}
fn value(text: &str, series: &str) -> f64 {
    text.lines()
        .find_map(|line| {
            line.strip_prefix(&format!("{series} "))
                .and_then(|n| n.parse().ok())
        })
        .unwrap_or(0.0)
}
fn burst(interval: u32) -> Vec<u8> {
    let mut bytes = vec![0; 44];
    bytes.extend([0x80, 12, 0, 12, 0, 60, 0, 3]);
    bytes.extend(interval.to_be_bytes());
    bytes.extend([0; 4]);
    bytes
}

#[test]
fn burst_copies_and_rate_rejections_match_scraped_counts() {
    let (server, baseline) = Reflector::start(&["--max-pps", "1", "--reflector-rate-burst", "3"]);
    let client = client("127.0.0.1");
    client
        .send_to(&burst(1_000_000), ("127.0.0.1", server.udp))
        .unwrap();
    for _ in 0..3 {
        assert_eq!(client.recv(&mut [0; 256]).unwrap(), 60);
    }
    server.wait_metric("stamp_reflector_packets_reflected_total", baseline + 3.0);
    client.send_to(&[0; 44], ("127.0.0.1", server.udp)).unwrap();
    let text = server.wait_metric(
        "stamp_reflector_packets_dropped_total{reason=\"rate_limited\"}",
        1.0,
    );
    assert_eq!(
        value(&text, "stamp_reflector_packets_reflected_total"),
        baseline + 3.0
    );
}

#[test]
fn suppressed_responses_do_not_count_as_reflections() {
    let (server, baseline) = Reflector::start(&[]);
    let client = client("127.0.0.1");
    let mut request = vec![0; 44];
    request.extend([0x80, 10, 0, 8, 0x80, 1, 0, 4, 0, 0, 0, 0]);
    client.send_to(&request, ("127.0.0.1", server.udp)).unwrap();
    let text = server.wait_metric(
        "stamp_reflector_packets_dropped_total{reason=\"suppressed\"}",
        1.0,
    );
    assert_eq!(
        value(&text, "stamp_reflector_packets_reflected_total"),
        baseline
    );
    assert!(client.recv(&mut [0; 256]).is_err());
}

#[test]
fn malformed_request_counts_once_without_a_reflection() {
    let (server, baseline) = Reflector::start(&["--strict-packets"]);
    let client = client("127.0.0.1");
    client.send_to(&[0; 43], ("127.0.0.1", server.udp)).unwrap();
    let text = server.wait_metric(
        "stamp_reflector_packets_dropped_total{reason=\"processing_rejected\"}",
        1.0,
    );
    assert_eq!(
        value(&text, "stamp_reflector_packets_reflected_total"),
        baseline
    );
    assert!(client.recv(&mut [0; 256]).is_err());
}

#[test]
fn queue_rejection_is_visible_in_scrape() {
    let (server, baseline) = Reflector::start(&["--reflector-queue-capacity", "1"]);
    let client = client("127.0.0.1");
    client
        .send_to(&burst(2_000_000_000), ("127.0.0.1", server.udp))
        .unwrap();
    assert_eq!(client.recv(&mut [0; 256]).unwrap(), 60);
    client.send_to(&[0; 44], ("127.0.0.1", server.udp)).unwrap();
    let text = server.wait_metric(
        "stamp_reflector_packets_dropped_total{reason=\"queue_full\"}",
        1.0,
    );
    assert_eq!(
        value(&text, "stamp_reflector_packets_reflected_total"),
        baseline + 1.0
    );
}
