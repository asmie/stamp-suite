use super::*;
use clap::Parser;

async fn run(limit: u32, timeout: u8) -> (SenderRun, UdpSocket) {
    let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let conf = Configuration::parse_from([
        "test",
        "--local-addr",
        "127.0.0.1",
        "--local-port",
        "0",
        "--remote-addr",
        "127.0.0.1",
        "--remote-port",
        &peer.local_addr().unwrap().port().to_string(),
        "--max-pending-probes",
        &limit.to_string(),
        "--timeout",
        &timeout.to_string(),
        "--hwtstamp",
        "off",
        "--count",
        "1",
    ]);
    (
        SenderRun::open(
            Arc::new(conf),
            SenderObservers::default(),
            CancellationToken::new(),
        )
        .await
        .unwrap(),
        peer,
    )
}

fn record(run: &mut SenderRun, seq: u32, time: Instant) {
    run.record_sent(seq, time, generate_timestamp(ClockFormat::NTP));
}

fn reply(run: &mut SenderRun, seq: u32, valid_ssid: bool) {
    let now = generate_timestamp(ClockFormat::NTP);
    let mut bytes = [0; 44];
    bytes[..4].copy_from_slice(&seq.to_be_bytes());
    bytes[4..12].copy_from_slice(&now.to_be_bytes());
    bytes[13] = 1;
    bytes[14..16].copy_from_slice(&(if valid_ssid { 42u16 } else { 43 }).to_be_bytes());
    bytes[16..24].copy_from_slice(&now.to_be_bytes());
    bytes[24..28].copy_from_slice(&seq.to_be_bytes());
    bytes[37] = 1;
    if let Some(packet) = run.pending.get(&seq) {
        bytes[28..36].copy_from_slice(&packet.send_timestamp.to_be_bytes());
    }
    run.recv_buf[..44].copy_from_slice(&bytes);
    let out = crate::stats::StatsOutput::new(crate::stats::OutputFormat::Json).unwrap();
    run.on_reply(&out, 44, None, None);
}

#[tokio::test]
async fn sustained_loss_bounds_both_pending_structures_without_timed_expiry() {
    let (mut sender, _peer) = run(7, 0).await;
    #[derive(Default)]
    struct Losses(std::sync::atomic::AtomicU64);
    impl SenderObserver for Losses {
        fn probes_lost(&self, count: u32) {
            self.0
                .fetch_add(u64::from(count), std::sync::atomic::Ordering::Relaxed);
        }
    }
    let losses = Arc::new(Losses::default());
    sender.observers.push(losses.clone());
    let start = Instant::now();
    for seq in 0..100_000 {
        record(
            &mut sender,
            seq,
            start + Duration::from_nanos(u64::from(seq)),
        );
        assert!(sender.pending.len() <= 7);
        assert_eq!(sender.pending_order.len(), sender.pending.len());
        assert_eq!(sender.pending_generation.len(), sender.pending.len());
    }
    sender.expire_at(start + Duration::from_secs(1_000_000));
    assert_eq!(sender.pending.len(), 7);
    assert!(sender.expiry_queue.is_empty());
    assert_eq!(sender.pending_evictions, 99_993);
    assert_eq!(sender.packets_lost, 99_993);
    let stats = sender
        .run(&crate::stats::StatsOutput::new(crate::stats::OutputFormat::Json).unwrap())
        .await
        .unwrap();
    assert_eq!(stats.packets_sent, 100_000);
    assert_eq!(stats.packets_lost, 100_000);
    assert_eq!(losses.0.load(std::sync::atomic::Ordering::Relaxed), 100_000);
    assert_eq!(
        stats.measurements.as_ref().unwrap().pending_high_watermark,
        7
    );
    assert_eq!(stats.measurements.as_ref().unwrap().pending_probes, 7);
}

#[tokio::test]
async fn replies_release_slots_but_invalid_and_late_or_duplicate_replies_do_not() {
    let (mut sender, _peer) = run(2, 0).await;
    sender.expected_ssid = Some(42);
    let start = Instant::now();
    for seq in 1..=3 {
        record(&mut sender, seq, start);
    }
    reply(&mut sender, 3, false);
    assert_eq!(sender.pending.len(), 2);
    assert_eq!(sender.pending_order.len(), 2);
    reply(&mut sender, 1, true); // retained measurement history, retired pending context
    let out = crate::stats::StatsOutput::new(crate::stats::OutputFormat::Json).unwrap();
    sender.on_reply(&out, 44, None, None); // exact duplicate bytes
    assert_eq!(sender.packets_received, 0);
    assert_eq!(sender.pending_order.len(), 2);
    reply(&mut sender, 2, true);
    assert_eq!(sender.packets_received, 1);
    assert_eq!(sender.pending_order.len(), 1);
    record(&mut sender, 4, Instant::now());
    assert_eq!(sender.pending_evictions, 1);
    assert!(sender.pending.contains_key(&3) && sender.pending.contains_key(&4));
    let stats = sender.snapshot();
    let measurements = stats.measurements.unwrap();
    assert_eq!(measurements.late_replies, 1);
    assert_eq!(measurements.duplicate_replies, 1);
    assert_eq!(measurements.pending_probes, 2);
    assert_eq!(measurements.pending_evictions, 1);
    assert_eq!(stats.packets_lost, 1);
}

#[tokio::test]
async fn short_reply_index_uses_canonical_zero_fill_not_previous_buffer_bytes() {
    let (mut sender, _peer) = run(2, 0).await;
    record(&mut sender, 0, Instant::now());
    record(&mut sender, 99, Instant::now());
    sender.recv_buf[24..28].copy_from_slice(&99u32.to_be_bytes());
    let out = crate::stats::StatsOutput::new(crate::stats::OutputFormat::Json).unwrap();
    sender.on_reply(&out, 0, None, None);
    assert!(!sender.pending.contains_key(&0));
    assert_eq!(sender.pending_order.len(), 1);
    assert_eq!(sender.pending_order.first_key_value().unwrap().1 .1, 99);
}

#[tokio::test]
async fn wrap_and_reused_sequences_keep_the_order_and_loss_accounting_consistent() {
    let (mut sender, _peer) = run(2, 0).await;
    let start = Instant::now();
    record(&mut sender, u32::MAX - 1, start);
    record(&mut sender, u32::MAX, start);
    record(&mut sender, 0, start);
    assert!(!sender.pending.contains_key(&(u32::MAX - 1)));
    assert!(sender.pending.contains_key(&u32::MAX) && sender.pending.contains_key(&0));
    record(&mut sender, 1, start);
    assert!(sender.pending.contains_key(&0) && sender.pending.contains_key(&1));
    assert!(!sender.pending.contains_key(&u32::MAX));
    record(&mut sender, 1, start);
    assert_eq!(sender.pending_order.len(), 2);
    assert_eq!(sender.pending_evictions, 3);
    assert_eq!(sender.packets_lost, 3);
    assert_eq!(*sender.pending_order.last_key_value().unwrap().0, 5);
    assert_eq!(sender.pending_generation.len(), 2);
}

#[tokio::test]
async fn bounded_expiry_only_expires_retained_generations_at_their_actual_deadline() {
    let (mut sender, _peer) = run(2, 1).await;
    let start = Instant::now();
    record(&mut sender, 5, start);
    record(&mut sender, 6, start + Duration::from_millis(1));
    record(&mut sender, 7, start + Duration::from_millis(2));
    sender.expire_at(start + Duration::from_secs(1));
    assert_eq!(sender.pending.len(), 2);
    sender.expire_at(start + Duration::from_millis(1001));
    assert_eq!(sender.pending.len(), 1);
    assert!(sender.pending.contains_key(&7));
    sender.expire_at(start + Duration::from_millis(1002));
    assert!(sender.pending.is_empty() && sender.pending_order.is_empty());
    assert!(sender.pending_generation.is_empty());
    assert!(sender.expiry_queue.is_empty());
    assert_eq!(sender.packets_lost, 3);
    assert_eq!(sender.pending_evictions, 1);
}

#[tokio::test]
async fn default_retention_stays_unlimited_and_stale_expiry_cannot_remove_a_reused_sequence() {
    let (mut sender, _peer) = run(0, 0).await;
    for seq in 0..5000 {
        record(&mut sender, seq, Instant::now());
    }
    assert_eq!(sender.pending.len(), 5000);
    assert!(sender.pending_order.is_empty() && sender.expiry_queue.is_empty());
    assert_eq!(sender.pending_evictions, 0);
    let (mut sender, _peer) = run(0, 1).await;
    let start = Instant::now();
    record(&mut sender, 5, start);
    record(&mut sender, 5, start + Duration::from_millis(500));
    sender.expire_at(start + Duration::from_secs(1));
    assert!(sender.pending.contains_key(&5));
    sender.expire_at(start + Duration::from_millis(1500));
    assert!(sender.pending.is_empty());
    assert_eq!(sender.packets_lost, 2);
    assert_eq!(sender.pending_evictions, 1);
}

#[tokio::test]
async fn retention_pressure_is_visible_in_text_json_and_existing_csv_measurements_column() {
    let (mut sender, _peer) = run(1, 0).await;
    record(&mut sender, 1, Instant::now());
    record(&mut sender, 2, Instant::now());
    let stats = sender.snapshot();
    for format in [
        crate::stats::OutputFormat::Text,
        crate::stats::OutputFormat::Json,
        crate::stats::OutputFormat::Csv,
    ] {
        let mut bytes = Vec::new();
        stats.write_report(&mut bytes, format, false, true).unwrap();
        let text = String::from_utf8(bytes).unwrap();
        match format {
            crate::stats::OutputFormat::Text => {
                assert!(text.contains("1 retired as lost (not timed expiry)"))
            }
            crate::stats::OutputFormat::Json => {
                let json: serde_json::Value = serde_json::from_str(&text).unwrap();
                assert_eq!(json["measurements"]["pending_limit"], 1);
                assert_eq!(json["measurements"]["pending_evictions"], 1);
            }
            crate::stats::OutputFormat::Csv => {
                assert!(text.contains("\"\"pending_evictions\"\":1"))
            }
        }
    }
}
