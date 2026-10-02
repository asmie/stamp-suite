//! A sender whose reflector is down keeps its send schedule.
//!
//! On a connected UDP socket, ICMP port-unreachable comes back as
//! ECONNREFUSED (WSAECONNRESET on Windows) from the next receive. The sender
//! must treat that as feedback, not as a reason to send the next probe early.
use std::{
    net::UdpSocket,
    process::Command,
    time::{Duration, Instant},
};

#[test]
fn closed_reflector_port_does_not_speed_up_sending() {
    let port = {
        let probe = UdpSocket::bind("127.0.0.1:0").unwrap();
        probe.local_addr().unwrap().port()
    };
    let count = 5u32;
    let delay_ms = 100u64;

    let started = Instant::now();
    let output = Command::new(env!("CARGO_BIN_EXE_stamp-suite"))
        .args([
            "--remote-addr",
            "127.0.0.1",
            "--remote-port",
            &port.to_string(),
            "--local-addr",
            "127.0.0.1",
            "--local-port",
            "0",
            "--count",
            &count.to_string(),
            "--send-delay",
            &delay_ms.to_string(),
            // No final wait, so elapsed time is the send schedule alone.
            "--timeout",
            "0",
            "--hwtstamp",
            "off",
            "--output-format",
            "json",
        ])
        .env_remove("STAMP_HMAC_KEY")
        .env("RUST_LOG", "off")
        .output()
        .unwrap();
    let elapsed = started.elapsed();

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let min = Duration::from_millis(delay_ms * u64::from(count - 1));
    assert!(
        elapsed >= min,
        "{count} probes at {delay_ms} ms finished in {elapsed:?}"
    );

    // One line for the first error; repeats are summarised at 10, 100, ...
    let stderr = String::from_utf8_lossy(&output.stderr);
    let error_lines = stderr.lines().filter(|l| l.contains("error")).count();
    assert!(error_lines <= 1, "unthrottled errors:\n{stderr}");
}
