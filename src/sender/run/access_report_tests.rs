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
        state.tick(Instant::now() - timeout);
        run.send_probe(true).await.unwrap();
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
