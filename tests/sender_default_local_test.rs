//! A sender without `--local-addr` binds the unspecified address of each
//! target's family, so IPv6 and mixed-family targets get replies.
#![cfg(all(
    target_os = "linux",
    any(feature = "ttl-nix", not(feature = "ttl-pnet"))
))]
#[path = "common/child.rs"]
mod child;
#[path = "common/reflector.rs"]
mod reflector;

use std::{process::Command, time::Duration};

use child::ChildProcess;
use reflector::Reflector;

/// Runs a sender with no local address and returns its JSON summaries.
fn summaries(remote: &str, port: u16) -> Vec<serde_json::Value> {
    let mut command = Command::new(env!("CARGO_BIN_EXE_stamp-suite"));
    command
        .args(["--remote-addr", remote, "--remote-port", &port.to_string()])
        .args(["--count", "3", "--send-delay", "20", "--timeout", "1"])
        .args(["--hwtstamp", "off", "--output-format", "json"])
        .env_remove("STAMP_HMAC_KEY")
        .env("RUST_LOG", "off")
        .env("TOKIO_WORKER_THREADS", "2");
    let output = ChildProcess::spawn(&mut command).finish(Duration::from_secs(10));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    stdout
        .lines()
        .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
        .filter(|report| report["type"] == "summary")
        .collect()
}

#[test]
fn ipv6_target_without_local_addr_gets_replies() {
    let reflector = Reflector::spawn(Reflector::command("::1")).unwrap();
    let summaries = summaries("::1", reflector.address.port());
    assert_eq!(summaries.len(), 1, "{summaries:?}");
    assert_eq!(summaries[0]["packets_sent"], 3, "{summaries:?}");
    assert_eq!(summaries[0]["packets_received"], 3, "{summaries:?}");
}

#[test]
fn mixed_family_targets_without_local_addr_get_replies() {
    // The targets share --remote-port, so both reflectors use the port the
    // kernel assigned to the first.
    let v4 = Reflector::spawn(Reflector::command("127.0.0.1")).unwrap();
    let port = v4.address.port();
    let mut command = Command::new(env!("CARGO_BIN_EXE_stamp-suite"));
    command
        .args(["--is-reflector", "--local-addr", "::1"])
        .args(["--local-port", &port.to_string(), "--log-format", "json"])
        .stdout(std::process::Stdio::null());
    let v6 = Reflector::spawn(command).unwrap();
    assert_eq!(v6.address.port(), port);

    let summaries = summaries("127.0.0.1,::1", port);
    let results: Vec<_> = summaries
        .iter()
        .map(|s| {
            (
                s["target"].as_str().unwrap().to_string(),
                s["packets_sent"].as_u64().unwrap(),
                s["packets_received"].as_u64().unwrap(),
            )
        })
        .collect();
    assert_eq!(
        results,
        [("127.0.0.1".into(), 3, 3), ("::1".into(), 3, 3)],
        "{summaries:?}"
    );
}
