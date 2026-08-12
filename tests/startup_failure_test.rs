//! A role that cannot start must *report* it, so `main` can exit non-zero.
//!
//! `dist/systemd/stamp-suite.service` is `Type=simple` with
//! `Restart=on-failure`: an exit status of 0 tells systemd the process stopped
//! deliberately and must not be restarted. A reflector that failed to bind, or
//! failed to load the key its authenticated mode requires, used to return
//! normally and exit 0 — the unit then silently stayed down, and
//! `stamp-suite … && echo ok` printed `ok` after a total failure.
//!
//! These tests pin the library-level contract that makes the exit status
//! correct. The graceful-shutdown paths must keep returning `Ok`.

use clap::Parser;
use stamp_suite::configuration::Configuration;
use stamp_suite::{receiver, sender};
use tokio::net::UdpSocket;

/// Grabs a port, then releases it so a caller can rebind it.
async fn free_port() -> u16 {
    let s = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    s.local_addr().unwrap().port()
}

#[tokio::test]
async fn reflector_reports_bind_failure() {
    let port = free_port().await;
    // Hold the port so the reflector cannot have it.
    let _squatter = UdpSocket::bind(("127.0.0.1", port)).await.unwrap();

    let conf = Configuration::parse_from([
        "stamp-suite",
        "--is-reflector",
        "--local-addr",
        "127.0.0.1",
        "--local-port",
        &port.to_string(),
    ]);
    let shared = receiver::create_shared_state(&conf);
    let err = receiver::run_receiver(&conf, &shared)
        .await
        .expect_err("binding an occupied port is a startup failure");
    assert!(
        err.to_string().contains("Cannot bind to address"),
        "unexpected error: {err}"
    );
}

#[tokio::test]
async fn reflector_reports_missing_key_in_authenticated_mode() {
    let port = free_port().await;
    let conf = Configuration::parse_from([
        "stamp-suite",
        "--is-reflector",
        "--local-addr",
        "127.0.0.1",
        "--local-port",
        &port.to_string(),
        "--auth-mode",
        "A",
        "--hmac-key-file",
        "/nonexistent/stamp-suite-test-key",
    ]);
    let shared = receiver::create_shared_state(&conf);
    let err = receiver::run_receiver(&conf, &shared)
        .await
        .expect_err("authenticated mode without a usable key cannot start");
    assert!(
        err.to_string().contains("Authenticated mode"),
        "unexpected error: {err}"
    );
}

#[tokio::test]
async fn sender_reports_missing_key_in_authenticated_mode() {
    let conf = Configuration::parse_from([
        "stamp-suite",
        "--remote-addr",
        "127.0.0.1",
        "--local-addr",
        "127.0.0.1",
        "--local-port",
        &free_port().await.to_string(),
        "--remote-port",
        &free_port().await.to_string(),
        "--count",
        "1",
        "--auth-mode",
        "A",
        "--hmac-key-file",
        "/nonexistent/stamp-suite-test-key",
    ]);
    let err = expect_startup_err(
        run_sender_compat(&conf).await,
        "authenticated mode without a usable key cannot start",
    );
    assert!(
        err.to_string().contains("Authenticated mode"),
        "unexpected error: {err}"
    );
}

#[tokio::test]
async fn sender_reports_bind_failure() {
    let port = free_port().await;
    let _squatter = UdpSocket::bind(("127.0.0.1", port)).await.unwrap();

    let conf = Configuration::parse_from([
        "stamp-suite",
        "--remote-addr",
        "127.0.0.1",
        "--local-addr",
        "127.0.0.1",
        "--local-port",
        &port.to_string(),
        "--remote-port",
        &free_port().await.to_string(),
        "--count",
        "1",
    ]);
    let err = expect_startup_err(
        run_sender_compat(&conf).await,
        "binding an occupied port is a startup failure",
    );
    assert!(
        err.to_string().contains("Cannot bind to address"),
        "unexpected error: {err}"
    );
}

#[tokio::test]
async fn sender_reports_invalid_ber_pattern() {
    let conf = Configuration::parse_from([
        "stamp-suite",
        "--remote-addr",
        "127.0.0.1",
        "--local-addr",
        "127.0.0.1",
        "--local-port",
        &free_port().await.to_string(),
        "--remote-port",
        &free_port().await.to_string(),
        "--count",
        "1",
        "--ber",
        "--ber-pattern",
        "gg",
    ]);
    let err = expect_startup_err(
        run_sender_compat(&conf).await,
        "a non-hex BER pattern cannot start",
    );
    assert!(
        err.to_string().contains("Invalid --ber-pattern"),
        "unexpected error: {err}"
    );
}

/// A successful run reports success, so the exit status stays 0 — including
/// when every packet is lost, which is a measurement result and not a failure
/// to start.
#[tokio::test]
async fn sender_total_loss_is_not_a_startup_failure() {
    let conf = Configuration::parse_from([
        "stamp-suite",
        "--remote-addr",
        "127.0.0.1",
        "--local-addr",
        "127.0.0.1",
        "--local-port",
        &free_port().await.to_string(),
        // Nothing is listening here, so the reply never comes.
        "--remote-port",
        &free_port().await.to_string(),
        "--count",
        "1",
        "--send-delay",
        "1",
        "--timeout",
        "1",
    ]);
    let stats = run_sender_compat(&conf)
        .await
        .expect("losing packets is a result, not a startup failure");
    assert_eq!(stats.packets_received, 0);
}

/// `StatsSnapshot` deliberately has no `Debug`, so `expect_err` is unavailable.
fn expect_startup_err(
    outcome: Result<stamp_suite::stats::StatsSnapshot, stamp_suite::StartupError>,
    why: &str,
) -> stamp_suite::StartupError {
    match outcome {
        Err(e) => e,
        Ok(_) => panic!("{why}"),
    }
}

/// `run_sender`'s second parameter is cfg-gated on the `snmp` feature, but
/// `None` infers under either signature, so one wrapper covers both.
async fn run_sender_compat(
    conf: &Configuration,
) -> Result<stamp_suite::stats::StatsSnapshot, stamp_suite::StartupError> {
    sender::run_sender(conf, None).await
}
