//! A live micro-session sender against a live reflector (RFC 9534 §3.2).
//! A reflector without a member link ID reports Reflector Micro-session ID 0;
//! the sender discards those replies and names the missing reflector option.
#![cfg(all(
    target_os = "linux",
    any(feature = "ttl-nix", not(feature = "ttl-pnet"))
))]
#[path = "common/child.rs"]
mod child;
#[path = "common/reflector.rs"]
mod reflector;

use child::ChildProcess;
use reflector::Reflector;
use std::{process::Command, time::Duration};

const COUNT: u32 = 3;

/// Runs a sender with `--micro-session-id 5` and the extra sender options;
/// returns the JSON summary and the sender's stderr.
fn run(reflector_args: &[&str], sender_args: &[&str]) -> (serde_json::Value, String, String) {
    let mut command = Reflector::command("127.0.0.1");
    command.args(["--hwtstamp", "off"]).args(reflector_args);
    let reflector = Reflector::spawn(command).unwrap();
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_stamp-suite"));
    cmd.args([
        "--remote-addr",
        "127.0.0.1",
        "--remote-port",
        &reflector.address.port().to_string(),
        "--local-addr",
        "127.0.0.1",
        "--local-port",
        "0",
        "--count",
        &COUNT.to_string(),
        "--send-delay",
        "10",
        "--timeout",
        "1",
        "--hwtstamp",
        "off",
        "--output-format",
        "json",
        "--micro-session-id",
        "5",
    ])
    .args(sender_args)
    .env("RUST_LOG", "warn");
    let output = ChildProcess::spawn(&mut cmd).finish(Duration::from_secs(15));
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    assert!(output.status.success(), "{stderr}");
    let stdout = String::from_utf8(output.stdout).unwrap();
    let summary = stdout
        .lines()
        .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
        .find(|value| value["type"] == "summary")
        .unwrap_or_else(|| panic!("no JSON summary in {stdout}"));
    (summary, stderr, reflector.diagnostics())
}

#[test]
fn plain_reflector_replies_are_rejected_with_a_named_cause() {
    // With and without an expected reflector ID on the sender: the reflector
    // must not echo a requested ID it does not have.
    for sender_args in [&[][..], &["--reflector-member-link-id", "9"][..]] {
        let (summary, stderr, reflector_log) = run(&[], sender_args);
        assert_eq!(summary["packets_received"], 0, "{summary}");
        assert_eq!(summary["packets_lost"], COUNT, "{summary}");
        assert!(
            stderr.contains("Reflector Micro-session ID 0")
                && stderr.contains("--reflector-member-link-id"),
            "sender must name the cause: {stderr}"
        );
        assert!(
            reflector_log.contains("--reflector-member-link-id is not set"),
            "reflector must name the missing option: {reflector_log}"
        );
    }
}

#[test]
fn reflector_with_member_link_id_is_accepted() {
    for sender_args in [&[][..], &["--reflector-member-link-id", "9"][..]] {
        let (summary, stderr, _) = run(&["--reflector-member-link-id", "9"], sender_args);
        assert_eq!(summary["packets_received"], COUNT, "{summary} {stderr}");
        assert_eq!(summary["packets_lost"], 0, "{summary}");
    }
}
