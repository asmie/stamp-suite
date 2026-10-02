//! Probe scheduling: continuous runs, `--duration`, sub-millisecond and
//! Poisson intervals, and interface binding.

use std::{
    net::UdpSocket,
    time::{Duration, Instant},
};

use clap::Parser;
use stamp_suite::{configuration::Configuration, sender};

/// A bound socket that never answers, so probes draw neither replies nor
/// ICMP errors.
fn silent_sink() -> UdpSocket {
    UdpSocket::bind("127.0.0.1:0").unwrap()
}

fn sender_conf(sink: &UdpSocket, extra: &[&str]) -> Configuration {
    let port = sink.local_addr().unwrap().port().to_string();
    let mut args = vec![
        "stamp-suite",
        "--remote-addr",
        "127.0.0.1",
        "--remote-port",
        &port,
        "--local-addr",
        "127.0.0.1",
        "--timeout",
        "0",
    ];
    args.extend_from_slice(extra);
    let conf = Configuration::parse_from(args);
    conf.validate().unwrap();
    conf
}

async fn sent_in(conf: &Configuration) -> (u64, Duration) {
    let started = Instant::now();
    let stats = sender::run_sender(conf).await.unwrap();
    (stats.packets_sent, started.elapsed())
}

#[tokio::test(flavor = "multi_thread")]
async fn count_zero_sends_until_duration_ends() {
    let sink = silent_sink();
    let conf = sender_conf(
        &sink,
        &["--count", "0", "--duration", "1", "--send-delay", "10"],
    );
    let (sent, elapsed) = sent_in(&conf).await;
    assert!((90..=101).contains(&sent), "sent {sent}");
    assert!(elapsed < Duration::from_millis(1500), "took {elapsed:?}");
}

#[tokio::test(flavor = "multi_thread")]
async fn duration_stops_before_count() {
    let sink = silent_sink();
    let conf = sender_conf(
        &sink,
        &["--count", "100000", "--duration", "1", "--send-delay", "20"],
    );
    let (sent, _) = sent_in(&conf).await;
    assert!((45..=51).contains(&sent), "sent {sent}");
}

#[tokio::test(flavor = "multi_thread")]
async fn sub_millisecond_interval_keeps_its_rate() {
    let sink = silent_sink();
    let conf = sender_conf(
        &sink,
        &["--count", "0", "--duration", "1", "--send-delay", "500us"],
    );
    let (sent, _) = sent_in(&conf).await;
    // 2000 at the exact rate; the 1 ms timer alone would allow at most 1000.
    assert!((1600..=2001).contains(&sent), "sent {sent}");
}

#[tokio::test(flavor = "multi_thread")]
async fn poisson_schedule_keeps_the_mean_rate() {
    let sink = silent_sink();
    let conf = sender_conf(
        &sink,
        &[
            "--count",
            "0",
            "--duration",
            "2",
            "--send-delay",
            "5ms",
            "--send-schedule",
            "poisson",
        ],
    );
    let (sent, _) = sent_in(&conf).await;
    // Mean 400 with a standard deviation of 20.
    assert!((300..=500).contains(&sent), "sent {sent}");
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[tokio::test(flavor = "multi_thread")]
async fn sender_binds_to_the_requested_interface() {
    let sink = silent_sink();
    let loopback = if cfg!(target_os = "macos") {
        "lo0"
    } else {
        "lo"
    };
    let conf = sender_conf(
        &sink,
        &["--count", "3", "--send-delay", "1", "--interface", loopback],
    );
    assert_eq!(sender::run_sender(&conf).await.unwrap().packets_sent, 3);

    let conf = sender_conf(&sink, &["--count", "1", "--interface", "nosuchif0"]);
    let Err(err) = sender::run_sender(&conf).await else {
        panic!("binding to a missing interface must fail");
    };
    assert!(
        err.to_string()
            .contains("Cannot bind to interface nosuchif0"),
        "{err}"
    );
}
