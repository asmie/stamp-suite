use super::*;
use clap::Parser;

#[tokio::test]
async fn drain_preserves_deadline_and_pending_probes_across_report_retry_states() {
    for (timeout, outcome) in [
        (Duration::from_secs(1), AccessReportOutcome::Pending),
        (Duration::from_millis(10), AccessReportOutcome::Aborted),
    ] {
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
            "--hwtstamp",
            "off",
            "--access-report",
            "1",
            "--access-report-retries",
            "1",
        ]);
        let mut run = SenderRun::open(
            Arc::new(conf),
            SenderObservers::default(),
            CancellationToken::new(),
        )
        .await
        .unwrap();
        let state = run.access_report_state.as_mut().unwrap();
        state.timeout = timeout;
        // Enter the drain with the original report already due. A retry must
        // happen now, without resetting the final-wait deadline.
        run.send_probe(true).await.unwrap();
        run.access_report_state.as_mut().unwrap().phase = AccessReportPhase::Armed {
            attempt: 0,
            deadline: Instant::now() - timeout,
        };
        let deadline = tokio::time::Instant::now() + Duration::from_millis(50);
        let output = crate::stats::StatsOutput::new(crate::stats::OutputFormat::Json).unwrap();
        assert!(tokio::time::timeout(
            Duration::from_millis(500),
            run.receive_until(deadline, Wait::Drain, &output),
        )
        .await
        .expect("retries must not extend the drain")
        .unwrap());
        assert!(
            tokio::time::Instant::now() >= deadline,
            "a terminal report must not abandon pending base replies"
        );
        let state = run.access_report_state.as_ref().unwrap();
        assert_eq!(state.retransmissions(), 1);
        assert_eq!(state.outcome(), outcome);
        assert_eq!(run.packets_sent, 2);
        assert_eq!(run.pending.len(), 2);
        let mut buffer = [0; 2048];
        for _ in 0..2 {
            tokio::time::timeout(Duration::from_secs(1), peer.recv_from(&mut buffer))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(&buffer[44..52], &[0x80, 6, 0, 4, 0x10, 1, 0, 0]);
        }
        assert!(
            peer.try_recv_from(&mut buffer).is_err(),
            "retry budget exceeded"
        );
    }
}

async fn pacing_run(retries: u32) -> (SenderRun, UdpSocket) {
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
        "--hwtstamp",
        "off",
        "--send-delay",
        "500",
        "--cos",
        "--ecn",
        "2",
        "--ecn-backoff-factor",
        "2",
        "--ecn-max-delay",
        "2000",
        "--access-report",
        "1",
        "--access-report-retries",
        &retries.to_string(),
        "--reflected-control-count",
        "3",
        "--reflected-control-interval-ns",
        "100000",
    ]);
    let mut run = SenderRun::open(
        Arc::new(conf),
        SenderObservers::default(),
        CancellationToken::new(),
    )
    .await
    .unwrap();
    run.access_report_state.as_mut().unwrap().timeout = Duration::from_millis(20);
    (run, peer)
}

#[tokio::test]
async fn pacing_retries_preserve_poisson_draw_and_ce_backoff() {
    use crate::configuration::SendSchedule;
    for retries in [0, 2] {
        let (mut run, peer) = pacing_run(retries).await;
        run.schedule = Schedule::with_seed(SendSchedule::Poisson, 42);
        let mut expected_schedule = Schedule::with_seed(SendSchedule::Poisson, 42);
        let interval = run.send_interval();
        let gap = run.schedule.next_gap(interval);
        assert_eq!(gap, expected_schedule.next_gap(interval));
        assert!(gap > Duration::from_millis(100));
        run.send_probe(true).await.unwrap();
        let start = tokio::time::Instant::now();
        let mut timeline = SendTimeline::new(start, 0, None);
        let wait = timeline.after_probe(gap, || start);
        run.congestion.as_mut().unwrap().controller.on_ce_observed();
        let expected_deadline = start + gap * 2;
        let output = crate::stats::StatsOutput::new(crate::stats::OutputFormat::Json).unwrap();
        tokio::time::timeout(
            Duration::from_secs(3),
            run.receive_until(
                wait.deadline,
                Wait::NextSend {
                    timeline: &mut timeline,
                    gap,
                    interval,
                },
                &output,
            ),
        )
        .await
        .unwrap()
        .unwrap();
        assert!(tokio::time::Instant::now() >= expected_deadline);
        assert_eq!(
            timeline
                .after_probe(Duration::ZERO, || expected_deadline)
                .deadline,
            expected_deadline
        );
        assert_eq!(
            run.schedule.next_gap(interval),
            expected_schedule.next_gap(interval)
        );
        let state = run.access_report_state.as_ref().unwrap();
        assert_eq!(state.retransmissions(), retries);
        assert_eq!(state.outcome(), AccessReportOutcome::Aborted);
        assert_eq!(run.packets_sent, 1 + u64::from(retries));
        let mut buffer = [0; 2048];
        for attempt in 0..=retries {
            let length = tokio::time::timeout(Duration::from_secs(1), peer.recv(&mut buffer))
                .await
                .unwrap()
                .unwrap();
            let mut offset = 44;
            let mut reports = 0;
            let mut intervals = Vec::new();
            while offset < length {
                let size =
                    usize::from(u16::from_be_bytes([buffer[offset + 2], buffer[offset + 3]]));
                let end = offset + 4 + size;
                assert!(end <= length);
                match buffer[offset + 1] {
                    6 => {
                        reports += 1;
                        assert_eq!(&buffer[offset + 4..end], &[0x10, 1, 0, 0]);
                    }
                    12 => intervals.push(u32::from_be_bytes(
                        buffer[offset + 8..offset + 12].try_into().unwrap(),
                    )),
                    _ => (),
                }
                offset = end;
            }
            assert_eq!(reports, 1);
            assert_eq!(intervals, [if attempt == 0 { 100_000 } else { 200_000 }]);
        }
        assert!(peer.try_recv(&mut buffer).is_err());
    }
}

#[tokio::test]
async fn expired_pacing_wait_leaves_due_report_for_the_scheduled_probe() {
    let (mut run, _peer) = pacing_run(2).await;
    run.send_probe(true).await.unwrap();
    run.access_report_state.as_mut().unwrap().phase = AccessReportPhase::Armed {
        attempt: 0,
        deadline: Instant::now() - Duration::from_secs(2),
    };
    let start = tokio::time::Instant::now() - Duration::from_secs(2);
    let interval = run.send_interval();
    let mut timeline = SendTimeline::new(start, 2, None);
    let wait = timeline.after_probe(interval, || start);
    let output = crate::stats::StatsOutput::new(crate::stats::OutputFormat::Json).unwrap();
    run.receive_until(
        wait.deadline,
        Wait::NextSend {
            timeline: &mut timeline,
            gap: interval,
            interval,
        },
        &output,
    )
    .await
    .unwrap();
    assert_eq!(run.packets_sent, 1);
    let state = run.access_report_state.as_mut().unwrap();
    assert_eq!(state.retransmissions(), 0);
    assert!(state.due(Instant::now()));
    run.send_probe(true).await.unwrap();
    assert_eq!(run.packets_sent, 2);
    assert_eq!(
        run.access_report_state.as_ref().unwrap().retransmissions(),
        1
    );
}
async fn report_failure_run(ip: &str, mode: u8) -> (SenderRun, UdpSocket) {
    let peer = UdpSocket::bind((ip, 0)).await.unwrap();
    let mut conf = Configuration::parse_from([
        "test",
        "--hwtstamp",
        "off",
        "--access-report",
        "1",
        "--access-report-retries",
        "1",
    ]);
    conf.local_addr = peer.local_addr().unwrap().ip();
    conf.local_port = 0;
    conf.remote_addr = vec![conf.local_addr];
    conf.remote_port = peer.local_addr().unwrap().port();
    if mode != 0 {
        conf.hmac_key = Some("abababababababababababababababab".parse().unwrap());
    }
    if mode == 2 {
        conf.auth_mode = crate::configuration::AuthMode::Authenticated;
    }
    let run = SenderRun::open(
        Arc::new(conf),
        SenderObservers::new(),
        CancellationToken::new(),
    )
    .await
    .unwrap();
    (run, peer)
}

fn failed_report_send(
    run: &mut SenderRun,
    result: std::io::Result<usize>,
) -> Result<(), crate::StartupError> {
    assert!(run
        .access_report_state
        .as_mut()
        .unwrap()
        .due(Instant::now()));
    let seq = run.sess.generate_sequence_number();
    let packet = run.build_probe(seq, true);
    run.finish_probe_send(seq, packet.len(), Instant::now(), 0, true, result)
}

#[tokio::test]
async fn report_send_failures_preserve_initial_and_retry_budget() {
    for ip in ["127.0.0.1", "::1"] {
        for mode in 0..3 {
            let (mut run, peer) = report_failure_run(ip, mode).await;
            let initial = run.access_report_state.as_ref().unwrap().clone();
            failed_report_send(&mut run, Err(std::io::ErrorKind::WouldBlock.into())).unwrap();
            assert_eq!(
                run.access_report_state.as_ref().unwrap(),
                &initial,
                "an unsent initial report must not arm its timer"
            );
            assert_eq!(run.packets_sent, 0);
            assert!(run.pending.is_empty());
            assert!(run.access_report_reply_deadline.is_none());
            assert!(!run.access_report_state.as_ref().unwrap().has_started());
            let mut bytes = [0; 2048];
            assert!(peer.try_recv_from(&mut bytes).is_err());

            let before = Instant::now();
            run.send_probe(true).await.unwrap();
            let after = Instant::now();
            let state = run.access_report_state.as_ref().unwrap();
            let deadline = state.armed_deadline().unwrap();
            assert!(deadline >= before + state.timeout && deadline <= after + state.timeout);
            assert_eq!(state.retransmissions(), 0);
            assert_eq!(run.consecutive_send_errors, 0);
            let base = if mode == 2 { 112 } else { 44 };
            let (len, _) = tokio::time::timeout(Duration::from_secs(2), peer.recv_from(&mut bytes))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(&bytes[..4], &1u32.to_be_bytes());
            assert!(len >= base + 8);
            assert_eq!(&bytes[base..base + 8], &[0x80, 6, 0, 4, 0x10, 1, 0, 0]);

            // Expire the actual original send without a wall-clock sleep.
            run.access_report_state.as_mut().unwrap().phase = AccessReportPhase::Armed {
                attempt: 0,
                deadline: Instant::now() - Duration::from_secs(1),
            };
            let retry = run.access_report_state.as_ref().unwrap().clone();
            failed_report_send(&mut run, Err(std::io::ErrorKind::ConnectionRefused.into()))
                .unwrap();
            assert_eq!(
                run.access_report_state.as_ref().unwrap(),
                &retry,
                "failed retry must keep its budget and deadline"
            );
            assert_eq!(run.packets_sent, 1);
            assert_eq!(run.pending.len(), 1);
            assert!(run.access_report_reply_deadline.is_none());
            assert!(peer.try_recv_from(&mut bytes).is_err());
            run.send_probe(true).await.unwrap();
            let (len, _) = tokio::time::timeout(Duration::from_secs(2), peer.recv_from(&mut bytes))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(&bytes[..4], &3u32.to_be_bytes());
            assert!(len >= base + 8);
            assert_eq!(&bytes[base..base + 8], &[0x80, 6, 0, 4, 0x10, 1, 0, 0]);
            assert_eq!(
                run.access_report_state.as_ref().unwrap().retransmissions(),
                1
            );
            assert_eq!(run.packets_sent, 2);
            assert_eq!(run.pending.len(), 2);
            assert_eq!(run.consecutive_send_errors, 0);
            assert_eq!(
                run.access_report_reply_deadline,
                Some(run.pending[&3].send_time + run.timeout)
            );
        }
    }
}

#[tokio::test]
async fn report_failed_sends_remain_bounded_and_short_sends_do_not_arm() {
    let (mut run, _) = report_failure_run("127.0.0.1", 0).await;
    for attempt in 1..=8 {
        let result = failed_report_send(&mut run, Err(std::io::ErrorKind::WouldBlock.into()));
        assert_eq!(result.is_err(), attempt == 8);
        assert_eq!(run.consecutive_send_errors, attempt);
        assert!(!run.access_report_state.as_ref().unwrap().has_started());
        assert_eq!(
            run.access_report_state.as_ref().unwrap().retransmissions(),
            0
        );
        assert!(run.pending.is_empty());
    }
    let (mut run, _) = report_failure_run("::1", 2).await;
    assert!(failed_report_send(&mut run, Ok(0)).is_err());
    assert!(!run.access_report_state.as_ref().unwrap().has_started());
    assert!(
        failed_report_send(&mut run, Err(std::io::ErrorKind::PermissionDenied.into())).is_err()
    );
    assert!(!run.access_report_state.as_ref().unwrap().has_started());
    assert_eq!(run.packets_sent, 0);
    assert!(run.pending.is_empty());
}
