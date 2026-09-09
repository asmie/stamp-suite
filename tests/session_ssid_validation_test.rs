//! An independent UDP peer checks sender SSID admission and legacy compatibility.
use stamp_suite::crypto::{compute_packet_hmac, HmacKey};
use std::{
    net::UdpSocket,
    process::{Child, Command, Stdio},
    time::Duration,
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
fn check(ip: &str, auth: bool, ssid: u16, policy: &str, accepted: bool) {
    let peer = UdpSocket::bind((ip, 0)).unwrap();
    peer.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_stamp-suite"));
    cmd.args([
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
        "--on-zero-ssid",
        policy,
    ]);
    if auth {
        cmd.args([
            "--auth-mode",
            "A",
            "--hmac-key",
            "ABABABABABABABABABABABABABABABAB",
        ]);
    }
    let mut sender = Sender(Some(
        cmd.stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap(),
    ));
    let mut request = [0; 2048];
    let (len, source) = peer.recv_from(&mut request).unwrap();
    let base = if auth { 112 } else { 44 };
    assert!(len >= base);
    let ssid_offset = if auth { 26 } else { 14 };
    assert_eq!(&request[ssid_offset..ssid_offset + 2], &42u16.to_be_bytes());
    let mut reply = vec![0; base];
    let (seq, timestamp, estimate) = if auth { (48, 64, 72) } else { (24, 28, 36) };
    reply[..4].copy_from_slice(&request[..4]);
    reply[seq..seq + 4].copy_from_slice(&request[..4]);
    let request_ts = if auth { 16 } else { 4 };
    reply[timestamp..timestamp + 8].copy_from_slice(&request[request_ts..request_ts + 8]);
    reply[estimate..estimate + 2].copy_from_slice(&[0, 1]);
    reply[ssid_offset..ssid_offset + 2].copy_from_slice(&ssid.to_be_bytes());
    if auth {
        let key = HmacKey::new(vec![0xAB; 16]).unwrap();
        let mac = compute_packet_hmac(&key, &reply, 96);
        reply[96..112].copy_from_slice(&mac);
    }
    peer.send_to(&reply, source).unwrap();
    let output = sender.0.take().unwrap().wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    // stdout isolation remains finding 15.
    let start = stdout.find('{').expect("statistics JSON");
    let stats: serde_json::Value = serde_json::from_str(&stdout[start..]).unwrap();
    assert_eq!(stats["packets_received"], u32::from(accepted), "{stdout}");
    assert_eq!(stats["packets_lost"], u32::from(!accepted), "{stdout}");
    assert_eq!(stats["owd"].is_null(), !accepted, "{stdout}");
}
#[test]
fn wrong_ssid_open_ipv4() {
    check("127.0.0.1", false, 43, "continue", false);
}
#[test]
fn wrong_ssid_open_ipv6() {
    check("::1", false, 43, "stop", false);
}
#[test]
fn wrong_ssid_auth_ipv4() {
    check("127.0.0.1", true, 43, "stop", false);
}
#[test]
fn wrong_ssid_auth_ipv6() {
    check("::1", true, 43, "continue", false);
}
#[test]
fn matching_ssid_open_ipv6() {
    check("::1", false, 42, "stop", true);
}
#[test]
fn matching_ssid_auth_ipv4() {
    check("127.0.0.1", true, 42, "continue", true);
}
#[test]
fn zero_ssid_continue_auth_ipv6() {
    check("::1", true, 0, "continue", true);
}
#[test]
fn zero_ssid_stop_open_ipv4() {
    check("127.0.0.1", false, 0, "stop", false);
}
