//! One sender measuring several reflectors at once.
#![cfg(all(
    target_os = "linux",
    any(feature = "ttl-nix", not(feature = "ttl-pnet"))
))]

use clap::Parser;
use stamp_suite::{configuration::Configuration, receiver, sender, stats::StatsOutput};

fn free_port() -> u16 {
    std::net::UdpSocket::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

#[tokio::test(flavor = "multi_thread")]
async fn sender_measures_each_target_in_its_own_session() {
    let port = free_port().to_string();
    // Linux routes all of 127.0.0.0/8 to the loopback interface.
    let mut reflectors = Vec::new();
    for addr in ["127.0.0.1", "127.0.0.2"] {
        let conf = Configuration::parse_from([
            "stamp-suite",
            "--is-reflector",
            "--local-addr",
            addr,
            "--local-port",
            &port,
        ]);
        let shared = receiver::create_shared_state(&conf).unwrap();
        let shutdown = shared.shutdown.clone();
        let task = tokio::spawn(async move { receiver::run_receiver(&conf, &shared).await });
        reflectors.push((shutdown, task));
    }
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    let conf = Configuration::parse_from([
        "stamp-suite",
        "--remote-addr",
        "127.0.0.1,127.0.0.2",
        "--remote-port",
        &port,
        "--count",
        "5",
        "--send-delay",
        "10",
        "--timeout",
        "1",
    ]);
    conf.validate().unwrap();
    let output = StatsOutput::new(conf.output_format).unwrap();
    let results = sender::run_senders(
        &conf,
        &output,
        sender::SenderObservers::default(),
        stamp_suite::shutdown::CancellationToken::new(),
    )
    .await
    .unwrap();

    let summary: Vec<_> = results
        .iter()
        .map(|s| (s.target.clone(), s.packets_sent, s.packets_received))
        .collect();
    assert_eq!(
        summary,
        [
            (Some("127.0.0.1".to_string()), 5, 5),
            (Some("127.0.0.2".to_string()), 5, 5),
        ]
    );
    for (shutdown, task) in reflectors {
        shutdown.cancel();
        task.await.unwrap().unwrap();
    }
}
