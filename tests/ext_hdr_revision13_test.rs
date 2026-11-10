//! Independent loopback peer for draft-ietf-ippm-stamp-ext-hdr-26 rules: source
//! ports, TTL/Hop Limit 255 and session state notifications.
#![cfg(any(target_os = "linux", target_os = "macos"))]
#[path = "common/hops.rs"]
mod hops;
#[cfg(any(feature = "ttl-nix", not(feature = "ttl-pnet")))]
#[path = "common/reflector.rs"]
mod reflector;
#[path = "common/wire_hmac.rs"]
mod wire_hmac;
use hops::{receive, socket};
use std::{
    process::{Child, Command, Stdio},
    time::Duration,
};

struct Process(Option<Child>);
impl Drop for Process {
    fn drop(&mut self) {
        if let Some(child) = &mut self.0 {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}
fn reflected(request: &[u8]) -> Vec<u8> {
    let mut reply = vec![0; 44];
    reply[..16].copy_from_slice(&request[..16]);
    reply[16..24].copy_from_slice(&request[4..12]);
    reply[24..38].copy_from_slice(&request[..14]);
    reply[40] = 254;
    reply
}

fn finish(mut process: Process) -> std::process::Output {
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while process.0.as_mut().unwrap().try_wait().unwrap().is_none() {
        assert!(
            std::time::Instant::now() < deadline,
            "sender failed to exit"
        );
        std::thread::sleep(Duration::from_millis(5));
    }
    process.0.take().unwrap().wait_with_output().unwrap()
}

#[test]
fn sender_hops_and_held_local_endpoint_separation_cover_both_families_and_keys() {
    for ip in ["127.0.0.1", "::1"] {
        for mode in 0..3 {
            let peer = socket(ip);
            let local_reflector = socket(ip); // Held throughout both attempts.
            let command = |port: u16| {
                let mut command = Command::new(env!("CARGO_BIN_EXE_stamp-suite"));
                command
                    .args([
                        "--remote-addr",
                        ip,
                        "--local-addr",
                        ip,
                        "--remote-port",
                        &peer.local_addr().unwrap().port().to_string(),
                        "--local-port",
                        &port.to_string(),
                        "--count",
                        "1",
                        "--timeout",
                        "1",
                        "--hwtstamp",
                        "off",
                        "--output-format",
                        "json",
                    ])
                    .env_remove("STAMP_HMAC_KEY")
                    .env("TOKIO_WORKER_THREADS", "2")
                    .stdout(Stdio::piped())
                    .stderr(Stdio::piped());
                if mode != 0 {
                    command.args(["--hmac-key", "abababababababababababababababab"]);
                }
                if mode == 2 {
                    command.args(["--auth-mode", "A"]);
                }
                command
            };
            let output = finish(Process(Some(
                command(local_reflector.local_addr().unwrap().port())
                    .spawn()
                    .unwrap(),
            )));
            assert!(!output.status.success());
            assert!(
                String::from_utf8_lossy(&output.stderr).contains("bind"),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
            peer.set_read_timeout(Some(Duration::from_millis(30)))
                .unwrap();
            assert!(matches!(
                peer.peek_from(&mut [0; 1]).unwrap_err().kind(),
                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
            ));
            peer.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
            let process = Process(Some(command(0).spawn().unwrap()));
            let (request, source, hops) = receive(&peer);
            assert_eq!(hops, 255);
            assert_ne!(source.port(), local_reflector.local_addr().unwrap().port());
            assert_ne!(source.port(), peer.local_addr().unwrap().port());
            if mode == 2 {
                assert_eq!(
                    &request[96..112],
                    &wire_hmac::digest(&[0xab; 16], &request[..96])
                );
            }
            let output = finish(process);
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
            let stats: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
            assert_eq!(stats["packets_sent"], 1);
        }
    }
}
#[test]
fn sender_random_ports_hops_and_state_notifications_over_both_families() {
    for ip in ["127.0.0.1", "::1"] {
        let peer = socket(ip);
        let mut child = Process(Some(
            Command::new(env!("CARGO_BIN_EXE_stamp-suite"))
                .args([
                    "--remote-addr",
                    ip,
                    "--local-addr",
                    ip,
                    "--remote-port",
                    &peer.local_addr().unwrap().port().to_string(),
                    "--count",
                    "12",
                    "--send-delay",
                    "250",
                    "--timeout",
                    "1",
                    "--session-loss-threshold",
                    "2",
                    "--ssid",
                    "77",
                    "--output-format",
                    "json",
                ])
                .env("RUST_LOG", "info")
                .env("TOKIO_WORKER_THREADS", "2")
                .env_remove("STAMP_HMAC_KEY")
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap(),
        ));
        for ordinal in 0..12 {
            let (request, source, hops) = receive(&peer);
            assert_eq!(hops, 255);
            assert!((49152..=65535).contains(&source.port()));
            assert_ne!(source.port(), peer.local_addr().unwrap().port());
            if ordinal == 0 || ordinal >= 8 {
                peer.send_to(&reflected(&request), source).unwrap();
            } else {
                // A well-framed reply from the right endpoint with the wrong
                // session must not reset the consecutive-loss notification.
                let mut wrong = reflected(&request);
                wrong[15] = 78;
                peer.send_to(&wrong, source).unwrap();
            }
        }
        let output = child.0.take().unwrap().wait_with_output().unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let summary: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        let state = &summary["measurements"]["session_state"];
        assert_eq!(state["state"], "idle");
        assert_eq!(state["active_notifications"], 2);
        assert_eq!(state["failed_notifications"], 1);
        assert_eq!(state["idle_notifications"], 1);
        let logs = String::from_utf8_lossy(&output.stderr);
        assert!(logs.contains("STAMP session state changed"));
    }
}
#[test]
#[cfg(any(feature = "ttl-nix", not(feature = "ttl-pnet")))]
fn reflector_transmits_255_and_accepts_lower_received_hops() {
    for ip in ["127.0.0.1", "::1"] {
        for mode in 0..3 {
            let peer = socket(ip);
            let mut command = reflector::Reflector::command(ip);
            command.args(["--hwtstamp", "off"]);
            if mode != 0 {
                command.args(["--hmac-key", "abababababababababababababababab"]);
            }
            if mode == 2 {
                command.args(["--auth-mode", "A"]);
            }
            let child = reflector::Reflector::spawn(command).unwrap();
            let sock = socket2::SockRef::from(&peer);
            if ip.contains(':') {
                sock.set_unicast_hops_v6(37).unwrap();
            } else {
                sock.set_ttl_v4(37).unwrap();
            }
            let mut request = vec![0; if mode == 2 { 112 } else { 44 }];
            request[..4].copy_from_slice(&42u32.to_be_bytes());
            request[if mode == 2 { 25 } else { 13 }] = 1;
            if mode == 2 {
                let digest = wire_hmac::digest(&[0xab; 16], &request[..96]);
                request[96..112].copy_from_slice(&digest);
            }
            peer.send_to(&request, child.address).unwrap();
            let (reply, source, hops) = receive(&peer);
            assert_eq!(source, child.address);
            assert_eq!(hops, 255);
            assert_eq!(reply[if mode == 2 { 80 } else { 40 }], 37);
            if mode == 2 {
                assert_eq!(
                    &reply[96..112],
                    &wire_hmac::digest(&[0xab; 16], &reply[..96])
                );
            }
        }
    }
}

#[test]
fn access_report_retry_phase_drives_state_deadlines() {
    let peer = socket("127.0.0.1");
    let mut child = Process(Some(
        Command::new(env!("CARGO_BIN_EXE_stamp-suite"))
            .args([
                "--remote-addr",
                "127.0.0.1",
                "--local-addr",
                "127.0.0.1",
                "--remote-port",
                &peer.local_addr().unwrap().port().to_string(),
                "--count",
                "1",
                "--send-delay",
                "100",
                "--timeout",
                "1",
                "--session-loss-threshold",
                "1",
                "--access-report",
                "1",
                "--access-report-timeout",
                "1",
                "--access-report-retries",
                "3",
                "--output-format",
                "json",
            ])
            .env("TOKIO_WORKER_THREADS", "2")
            .env_remove("STAMP_HMAC_KEY")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap(),
    ));
    for n in 0..4 {
        let (request, source, _) = receive(&peer);
        // Reply without acknowledging the Access Report, then lose two retries.
        if n < 2 {
            peer.send_to(&reflected(&request), source).unwrap();
        }
    }
    let output = child.0.take().unwrap().wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let summary: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(
        summary["measurements"]["session_state"]["failed_notifications"],
        1
    );
    assert_eq!(summary["measurements"]["session_state"]["state"], "idle");
}

#[test]
fn mapped_ipv4_sender_transmits_ttl_255() {
    let peer = socket("127.0.0.1");
    let mut child = Process(Some(
        Command::new(env!("CARGO_BIN_EXE_stamp-suite"))
            .args([
                "--local-addr",
                "::",
                "--remote-addr",
                "::ffff:127.0.0.1",
                "--remote-port",
                &peer.local_addr().unwrap().port().to_string(),
                "--count",
                "1",
                "--send-delay",
                "50",
                "--timeout",
                "1",
                "--output-format",
                "json",
            ])
            .env_remove("STAMP_HMAC_KEY")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap(),
    ));
    let (request, source, ttl) = receive(&peer);
    assert_eq!(ttl, 255, "mapped IPv4 traffic must use the draft's TTL");
    peer.send_to(&reflected(&request), source).unwrap();
    let output = child.0.take().unwrap().wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let summary: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(summary["packets_received"], 1);
}
