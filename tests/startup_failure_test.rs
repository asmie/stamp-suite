//! Startup failures must return errors so `main` exits non-zero and supervisors
//! can restart the process. Graceful shutdown must still return `Ok`.

use clap::Parser;
use stamp_suite::configuration::Configuration;
use stamp_suite::{crypto::KeyLoadError, receiver, sender, StartupError};
use tokio::net::UdpSocket;

/// Grabs a port, then releases it so a caller can rebind it.
async fn free_port() -> u16 {
    let s = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    s.local_addr().unwrap().port()
}

#[tokio::test]
async fn reflector_reports_bind_failure() {
    // Occupy the exact wildcard address the reflector will bind. A socket
    // bound only to loopback does not establish this conflict on Windows.
    let _squatter = UdpSocket::bind("0.0.0.0:0").await.unwrap();
    let port = _squatter.local_addr().unwrap().port();

    // Wildcard binds work without an interface carrying the unspecified IP.
    // Socket/key errors must be reported before capture interface discovery.
    let conf = Configuration::parse_from([
        "stamp-suite",
        "--is-reflector",
        "--local-addr",
        "0.0.0.0",
        "--local-port",
        &port.to_string(),
    ]);
    let shared = receiver::create_shared_state(&conf).unwrap();
    let err = receiver::run_receiver(&conf, &shared)
        .await
        .expect_err("binding an occupied port is a startup failure");
    assert!(
        err.to_string().contains("Cannot bind to address"),
        "unexpected error: {err}"
    );
}

#[tokio::test]
async fn reflector_reports_unreadable_key_file() {
    let port = free_port().await;
    let conf = Configuration::parse_from([
        "stamp-suite",
        "--is-reflector",
        "--local-addr",
        "0.0.0.0",
        "--local-port",
        &port.to_string(),
        "--auth-mode",
        "A",
        "--hmac-key-file",
        "/nonexistent/stamp-suite-test-key",
    ]);
    let err = receiver::create_shared_state(&conf)
        .err()
        .expect("an unreadable key file cannot start");
    assert!(
        matches!(err, StartupError::Key(KeyLoadError::File { .. })),
        "unexpected error: {err}"
    );
    assert!(
        err.to_string()
            .contains("/nonexistent/stamp-suite-test-key"),
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
        "0.0.0.0",
        "--local-port",
        &port.to_string(),
        "--auth-mode",
        "A",
    ]);
    let shared = receiver::create_shared_state(&conf).unwrap();
    let err = receiver::run_receiver(&conf, &shared)
        .await
        .expect_err("authenticated mode without a key cannot start");
    assert!(
        err.to_string().contains("Authenticated mode"),
        "unexpected error: {err}"
    );
}

fn sender_conf(port: u16, remote_port: u16, extra: &[&str]) -> Configuration {
    let local_port = port.to_string();
    let remote_port = remote_port.to_string();
    let mut args = vec![
        "stamp-suite",
        "--remote-addr",
        "127.0.0.1",
        "--local-addr",
        "127.0.0.1",
        "--local-port",
        &local_port,
        "--remote-port",
        &remote_port,
        "--count",
        "1",
        "--auth-mode",
        "A",
    ];
    args.extend_from_slice(extra);
    Configuration::parse_from(args)
}

#[tokio::test]
async fn sender_reports_unreadable_key_file() {
    let conf = sender_conf(
        free_port().await,
        free_port().await,
        &["--hmac-key-file", "/nonexistent/stamp-suite-test-key"],
    );
    let err = expect_startup_err(
        sender::run_sender(&conf).await,
        "an unreadable key file cannot start",
    );
    assert!(
        matches!(err, StartupError::Key(KeyLoadError::File { .. })),
        "unexpected error: {err}"
    );
}

#[tokio::test]
async fn sender_reports_missing_key_in_authenticated_mode() {
    let conf = sender_conf(free_port().await, free_port().await, &[]);
    let err = expect_startup_err(
        sender::run_sender(&conf).await,
        "authenticated mode without a key cannot start",
    );
    assert!(
        err.to_string().contains("Authenticated mode"),
        "unexpected error: {err}"
    );
}

#[tokio::test]
async fn sender_reports_bind_failure() {
    let _squatter = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let port = _squatter.local_addr().unwrap().port();

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
        sender::run_sender(&conf).await,
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
        sender::run_sender(&conf).await,
        "a non-hex BER pattern cannot start",
    );
    assert!(
        err.to_string().contains("Invalid --ber-pattern"),
        "unexpected error: {err}"
    );
}

/// A successful run reports success, so the exit status stays 0. That holds
/// when every packet is lost too: loss is a measurement result, not a failure
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
    let stats = sender::run_sender(&conf)
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

#[tokio::test]
async fn sender_stops_on_shutdown_and_reports_what_it_sent() {
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
        "1000",
        "--send-delay",
        "10",
    ]);
    let shutdown = stamp_suite::shutdown::CancellationToken::new();
    let trigger = shutdown.clone();
    tokio::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        trigger.cancel();
    });
    let mut output = stamp_suite::stats::StatsOutput::new(conf.output_format);
    let started = std::time::Instant::now();
    let stats = sender::run_sender_with_output(
        &conf,
        &mut output,
        sender::SenderObservers::default(),
        shutdown,
    )
    .await
    .expect("an interrupted run still reports statistics");
    assert!(started.elapsed() < std::time::Duration::from_secs(2));
    assert!(
        (1..1000).contains(&stats.packets_sent),
        "sent {}",
        stats.packets_sent
    );
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn reflector_reports_missing_interface() {
    let conf = Configuration::parse_from([
        "stamp-suite",
        "--is-reflector",
        "--local-addr",
        "127.0.0.1",
        "--local-port",
        &free_port().await.to_string(),
        "--interface",
        "nosuchif0",
    ]);
    let shared = receiver::create_shared_state(&conf).unwrap();
    let err = receiver::run_receiver(&conf, &shared)
        .await
        .expect_err("a missing interface cannot be bound");
    assert!(
        err.to_string()
            .contains("Cannot bind to interface nosuchif0"),
        "unexpected error: {err}"
    );
}
