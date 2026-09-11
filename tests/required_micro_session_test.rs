//! A live sender must reject replies without a usable requested Micro-session ID.
#[path = "common/wire_hmac.rs"]
mod wire_hmac;
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
fn check(ip: &str, auth: bool, flags: Option<u8>, accepted: bool) {
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
        "--micro-session-id",
        "7",
        "--reflector-member-link-id",
        "9",
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
    assert!(len >= base + 8);
    let mut reply = vec![0; base];
    let (seq, timestamp, estimate) = if auth { (48, 64, 72) } else { (24, 28, 36) };
    reply[..4].copy_from_slice(&request[..4]);
    reply[seq..seq + 4].copy_from_slice(&request[..4]);
    let request_ts = if auth { 16 } else { 4 };
    reply[timestamp..timestamp + 8].copy_from_slice(&request[request_ts..request_ts + 8]);
    reply[estimate..estimate + 2].copy_from_slice(&[0, 1]);
    if let Some(flags) = flags {
        reply.extend_from_slice(&[flags, 11, 0, 4, 0, 7, 0, 9]);
    }
    if auth {
        let key = [0xAB; 16];
        if flags.is_some() {
            let mut covered = reply[..4].to_vec();
            covered.extend_from_slice(&reply[base..]);
            reply.extend_from_slice(&[0, 8, 0, 16]);
            reply.extend_from_slice(&wire_hmac::digest(&key, &covered));
        }
        let mac = wire_hmac::digest(&key, &reply[..96]);
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
    let stats: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(stats["packets_received"], u32::from(accepted), "{stdout}");
    assert_eq!(stats["packets_lost"], u32::from(!accepted), "{stdout}");
    assert_eq!(stats["owd"].is_null(), !accepted, "{stdout}");
}
#[test]
fn absent_id_open_ipv4() {
    check("127.0.0.1", false, None, false);
}
#[test]
fn absent_id_auth_ipv6() {
    check("::1", true, None, false);
}
#[test]
fn flagged_id_open_ipv6() {
    check("::1", false, Some(0x80), false);
}
#[test]
fn flagged_id_auth_ipv4() {
    check("127.0.0.1", true, Some(0x20), false);
}
#[test]
fn valid_id_auth_ipv4() {
    check("127.0.0.1", true, Some(0), true);
}
