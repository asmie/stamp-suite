//! Independent UDP peers exercise bounded pending retention through real sends.
use clap::Parser;
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use stamp_suite::{
    configuration::Configuration,
    sender,
    shutdown::CancellationToken,
    stats::{OutputFormat, StatsOutput, StatsSnapshot},
};
use std::{
    net::SocketAddr,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{net::UdpSocket, time::timeout};

fn conf(address: SocketAddr, count: u32, limit: u32, auth: bool, extra: &[&str]) -> Configuration {
    let mut args = vec![
        "test".to_string(),
        "--remote-addr".into(),
        address.ip().to_string(),
        "--remote-port".into(),
        address.port().to_string(),
        "--local-addr".into(),
        address.ip().to_string(),
        "--local-port".into(),
        "0".into(),
        "--count".into(),
        count.to_string(),
        "--max-pending-probes".into(),
        limit.to_string(),
        "--timeout".into(),
        "0".into(),
        "--send-delay".into(),
        "5ms".into(),
        "--hwtstamp".into(),
        "off".into(),
        "--ssid".into(),
        "42".into(),
    ];
    if auth {
        args.extend(
            ["-A", "A", "--hmac-key", "abababababababababababababababab"].map(String::from),
        );
    }
    for pair in extra.chunks_exact(2) {
        if let Some(index) = args.iter().position(|arg| arg == pair[0]) {
            args[index + 1] = pair[1].into();
        } else {
            args.extend(pair.iter().map(|s| s.to_string()));
        }
    }
    let conf = Configuration::parse_from(args);
    conf.validate().unwrap();
    conf
}

fn start(
    conf: Configuration,
    shutdown: CancellationToken,
) -> tokio::task::JoinHandle<StatsSnapshot> {
    tokio::spawn(async move {
        let output = StatsOutput::new(OutputFormat::Json).unwrap();
        sender::run_sender_with_output(&conf, &output, sender::SenderObservers::default(), shutdown)
            .await
            .unwrap()
    })
}

async fn receive(peer: &UdpSocket) -> (Vec<u8>, SocketAddr) {
    let mut bytes = [0; 2048];
    let (size, source) = timeout(Duration::from_secs(3), peer.recv_from(&mut bytes))
        .await
        .unwrap()
        .unwrap();
    (bytes[..size].to_vec(), source)
}

fn reply(request: &[u8], auth: bool) -> Vec<u8> {
    let mut data = vec![0; if auth { 112 } else { 44 }];
    let (t3, error, t2, echo, t1, ttl) = if auth {
        (16, 24, 32, 48, 64, 80)
    } else {
        (4, 12, 16, 24, 28, 40)
    };
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
    let timestamp = ((now.as_secs().wrapping_add(2_208_988_800) as u32 as u64) << 32)
        | ((u64::from(now.subsec_nanos()) << 32) / 1_000_000_000);
    data[..4].copy_from_slice(&request[..4]);
    data[t3..t3 + 8].copy_from_slice(&timestamp.to_be_bytes());
    data[error..error + 4].copy_from_slice(&request[error..error + 4]);
    data[t2..t2 + 8].copy_from_slice(&timestamp.to_be_bytes());
    data[echo..echo + 4].copy_from_slice(&request[..4]);
    data[t1..t1 + 10].copy_from_slice(&request[t3..t3 + 10]);
    data[ttl] = 255;
    if auth {
        let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(&[0xab; 16]).unwrap();
        mac.update(&data[..96]);
        data[96..112].copy_from_slice(&mac.finalize().into_bytes()[..16]);
    }
    data
}

#[tokio::test]
async fn silent_peers_keep_count_pacing_and_exact_final_loss_in_both_families_and_modes() {
    for ip in ["127.0.0.1", "::1"] {
        for auth in [false, true] {
            let peer = UdpSocket::bind((ip, 0)).await.unwrap();
            let task = start(
                conf(peer.local_addr().unwrap(), 12, 3, auth, &[]),
                CancellationToken::new(),
            );
            for seq in 0..12u32 {
                let (packet, _) = receive(&peer).await;
                assert_eq!(&packet[..4], &seq.to_be_bytes());
            }
            let stats = timeout(Duration::from_secs(3), task)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(
                (
                    stats.packets_sent,
                    stats.packets_received,
                    stats.packets_lost
                ),
                (12, 0, 12)
            );
            let m = stats.measurements.unwrap();
            assert_eq!(
                (
                    m.pending_limit,
                    m.pending_probes,
                    m.pending_high_watermark,
                    m.pending_evictions
                ),
                (3, 3, 3, 9)
            );
            assert_eq!(m.session_state.failed_notifications, 0);
        }
    }
}

#[tokio::test]
async fn late_and_duplicate_replies_preserve_cap_and_loss_identity() {
    for auth in [false, true] {
        let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let task = start(
            conf(
                peer.local_addr().unwrap(),
                5,
                2,
                auth,
                &["--send-delay", "100ms"],
            ),
            CancellationToken::new(),
        );
        let (first, source) = receive(&peer).await;
        let (second, _) = receive(&peer).await;
        receive(&peer).await; // sending probe 2 retires probe 0
        let late = reply(&first, auth);
        peer.send_to(&late, source).await.unwrap();
        peer.send_to(&late, source).await.unwrap();
        let valid = reply(&second, auth);
        peer.send_to(&valid, source).await.unwrap();
        peer.send_to(&valid, source).await.unwrap();
        for _ in 0..2 {
            let (request, source) = receive(&peer).await;
            peer.send_to(&reply(&request, auth), source).await.unwrap();
        }
        let stats = timeout(Duration::from_secs(3), task)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(stats.packets_sent, 5);
        assert!(stats.packets_received > 0);
        assert_eq!(stats.packets_received + stats.packets_lost, 5);
        let m = stats.measurements.unwrap();
        assert_eq!(m.pending_high_watermark, 2);
        assert!(m.pending_probes <= 2 && m.pending_evictions >= 1);
        assert_eq!(
            m.pending_evictions + m.pending_probes as u64,
            stats.packets_lost
        );
        assert!(m.late_replies >= 1 && m.duplicate_replies >= 1);
    }
}

#[tokio::test]
async fn cancellation_finishes_with_retired_and_retained_probes_counted_once() {
    let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let shutdown = CancellationToken::new();
    let task = start(
        conf(peer.local_addr().unwrap(), 0, 2, false, &[]),
        shutdown.clone(),
    );
    for _ in 0..8 {
        receive(&peer).await;
    }
    shutdown.cancel();
    let stats = timeout(Duration::from_secs(3), task)
        .await
        .unwrap()
        .unwrap();
    assert!(stats.packets_sent >= 8);
    assert_eq!(stats.packets_lost, stats.packets_sent);
    let m = stats.measurements.unwrap();
    assert_eq!(m.pending_probes, 2);
    assert_eq!(m.pending_evictions + 2, stats.packets_sent);
}

#[tokio::test]
async fn access_report_retries_obey_the_same_cap_and_keep_their_retry_budget() {
    let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let task = start(
        conf(
            peer.local_addr().unwrap(),
            1,
            1,
            false,
            &[
                "--access-report",
                "1",
                "--access-report-timeout",
                "1",
                "--access-report-retries",
                "1",
            ],
        ),
        CancellationToken::new(),
    );
    receive(&peer).await;
    receive(&peer).await;
    let stats = timeout(Duration::from_secs(4), task)
        .await
        .unwrap()
        .unwrap();
    assert_eq!((stats.packets_sent, stats.packets_lost), (2, 2));
    let report = stats.access_report.unwrap();
    assert_eq!(
        report.outcome,
        stamp_suite::stats::AccessReportOutcome::Aborted
    );
    assert_eq!(report.retransmissions, 1);
    let m = stats.measurements.unwrap();
    assert_eq!(
        (
            m.pending_probes,
            m.pending_evictions,
            m.pending_high_watermark
        ),
        (1, 1, 1)
    );
}

#[tokio::test]
#[cfg(target_os = "linux")]
async fn multiple_targets_have_independent_retention_budgets() {
    let first = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let _second = UdpSocket::bind(("127.0.0.2", first.local_addr().unwrap().port()))
        .await
        .unwrap();
    let config = conf(
        first.local_addr().unwrap(),
        8,
        2,
        false,
        &["--remote-addr", "127.0.0.1,127.0.0.2"],
    );
    let out = StatsOutput::new(OutputFormat::Json).unwrap();
    let stats = timeout(
        Duration::from_secs(3),
        sender::run_senders(
            &config,
            &out,
            sender::SenderObservers::default(),
            CancellationToken::new(),
        ),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(stats.len(), 2);
    assert_ne!(stats[0].target, stats[1].target);
    for s in stats {
        assert_eq!((s.packets_sent, s.packets_lost), (8, 8));
        let m = s.measurements.unwrap();
        assert_eq!(
            (
                m.pending_probes,
                m.pending_evictions,
                m.pending_high_watermark
            ),
            (2, 6, 2)
        );
    }
}
