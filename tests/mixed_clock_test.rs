//! Live sender against an independently encoded peer with a different clock format.
use stamp_suite::crypto::{compute_packet_hmac, HmacKey};
use std::{
    net::UdpSocket,
    process::{Child, Command, Stdio},
    time::{Duration, SystemTime, UNIX_EPOCH},
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

fn remote_time(ptp: bool, utc_offset: u64) -> u64 {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
    let sec = now.as_secs() + utc_offset + if ptp { 0 } else { 2_208_988_800 };
    let fraction = if ptp {
        u64::from(now.subsec_nanos())
    } else {
        (u64::from(now.subsec_nanos()) << 32) / 1_000_000_000
    };
    ((sec as u32 as u64) << 32) | fraction
}

fn check(local_ptp: bool, ipv6_auth: bool) {
    let ip = if ipv6_auth { "::1" } else { "127.0.0.1" };
    let peer = UdpSocket::bind((ip, 0)).unwrap();
    peer.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let remote_ptp = !local_ptp;
    // An explicit TAI-like peer offset is exercised without relying on the
    // host's leap-second database or PHC. This is a fixed fixture, not a claim
    // that a UTC offset can be inferred from the Z bit.
    let offset = if ipv6_auth { 37 } else { 0 };
    let mut command = Command::new(env!("CARGO_BIN_EXE_stamp-suite"));
    command.args([
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
        "--clock-source",
        if local_ptp { "PTP" } else { "NTP" },
        "--reflector-utc-offset",
        &offset.to_string(),
    ]);
    if ipv6_auth {
        command.args([
            "--auth-mode",
            "A",
            "--hmac-key",
            "ABABABABABABABABABABABABABABABAB",
        ]);
    }
    let mut sender = Sender(Some(
        command
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap(),
    ));
    let mut request = [0; 2048];
    let (length, source) = peer.recv_from(&mut request).unwrap();
    let t2 = remote_time(remote_ptp, offset);
    let base = if ipv6_auth { 112 } else { 44 };
    assert!(length >= base);
    let mut reply = vec![0; base];
    let (ts, err, rx, seq, echo, echo_err, ttl) = if ipv6_auth {
        (16, 24, 32, 48, 64, 72, 80)
    } else {
        (4, 12, 16, 24, 28, 36, 40)
    };
    reply[..4].copy_from_slice(&request[..4]);
    reply[rx..rx + 8].copy_from_slice(&t2.to_be_bytes());
    reply[seq..seq + 4].copy_from_slice(&request[..4]);
    reply[echo..echo + 8].copy_from_slice(&request[ts..ts + 8]);
    reply[echo_err..echo_err + 2].copy_from_slice(&request[err..err + 2]);
    let estimate: u16 = if remote_ptp { 0x4001 } else { 1 };
    reply[err..err + 2].copy_from_slice(&estimate.to_be_bytes());
    reply[ttl] = 64;
    reply[ts..ts + 8].copy_from_slice(&remote_time(remote_ptp, offset).to_be_bytes());
    if ipv6_auth {
        let key = HmacKey::new(vec![0xAB; 16]).unwrap();
        let hmac = compute_packet_hmac(&key, &reply, 96);
        reply[96..112].copy_from_slice(&hmac);
    }
    peer.send_to(&reply, source).unwrap();
    let output = sender.0.take().unwrap().wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    // Machine-readable stdout isolation is tracked separately as finding 15.
    let start = stdout.find('{').expect("JSON statistics");
    let stats: serde_json::Value = serde_json::from_str(&stdout[start..]).unwrap();
    let owd = &stats["owd"];
    assert_eq!(owd["samples"], 1, "{stdout}");
    for direction in ["forward_avg_ms", "reverse_avg_ms"] {
        let delay = owd[direction].as_f64().unwrap();
        assert!(delay.abs() < 1000.0, "{direction}: {delay} ms; {stdout}");
    }
}

#[test]
fn ntp_sender_ptp_peer_ipv4() {
    check(false, false);
}
#[test]
fn ptp_sender_ntp_peer_ipv4() {
    check(true, false);
}
#[test]
fn ntp_sender_ptp_peer_ipv6_auth_offset() {
    check(false, true);
}
#[test]
fn ptp_sender_ntp_peer_ipv6_auth_offset() {
    check(true, true);
}
