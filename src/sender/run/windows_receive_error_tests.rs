use super::*;
use clap::Parser;
use std::{future::Future, task::Poll};
use windows_sys::Win32::Networking::WinSock::WSAEMSGSIZE;

async fn fixture(ip: &str, mode: u8) -> (SenderRun, UdpSocket) {
    let peer = UdpSocket::bind((ip, 0)).await.unwrap();
    let port = peer.local_addr().unwrap().port().to_string();
    let mut args = vec![
        "test",
        "--local-addr",
        ip,
        "--local-port",
        "0",
        "--remote-addr",
        ip,
        "--remote-port",
        &port,
        "--hwtstamp",
        "off",
        "--access-report",
        "1",
        "--access-report-retries",
        "1",
    ];
    if mode != 0 {
        args.extend(["--hmac-key", "abababababababababababababababab"]);
    }
    if mode == 2 {
        args.extend(["--auth-mode", "A"]);
    }
    let conf = Configuration::parse_from(args);
    conf.validate().unwrap();
    let run = SenderRun::open(
        Arc::new(conf),
        SenderObservers::new(),
        CancellationToken::new(),
    )
    .await
    .unwrap();
    (run, peer)
}

async fn queue_receive_error(run: &mut SenderRun, peer: &UdpSocket) {
    // A small fixture buffer makes Winsock return a real non-ICMP error for
    // an oversized datagram, without corrupting/closing a live socket handle.
    run.recv_buf.resize(1, 0);
    let target = run.socket.local_addr().unwrap();
    peer.send_to(&[1, 2], target).await.unwrap();
    let error = recv_packet(
        &run.socket,
        &mut run.recv_buf,
        &mut run.cmsg_buf,
        false,
        false,
        ClockFormat::NTP,
    )
    .await
    .unwrap_err();
    assert_eq!(error.raw_os_error(), Some(WSAEMSGSIZE));
    assert!(!is_icmp_feedback(&error));
    // Queue the same error for receive_until, then establish readiness before
    // polling it. This keeps cancellation from winning before the error path.
    peer.send_to(&[1, 2], target).await.unwrap();
    run.socket.readable().await.unwrap();
}

#[tokio::test]
async fn windows_receive_error_keeps_pacing_cancellable() {
    for ip in ["127.0.0.1", "::1"] {
        for mode in 0..3 {
            let (mut run, peer) = fixture(ip, mode).await;
            queue_receive_error(&mut run, &peer).await;
            let cancel = run.shutdown.clone();
            let start = tokio::time::Instant::now();
            let gap = Duration::from_secs(5);
            let mut timeline = SendTimeline::new(start, 0, None);
            let wait = timeline.after_probe(gap, || start);
            let output = crate::stats::StatsOutput::new(crate::stats::OutputFormat::Json).unwrap();
            let receive = run.receive_until(
                wait.deadline,
                Wait::NextSend {
                    timeline: &mut timeline,
                    gap,
                    interval: gap,
                },
                &output,
            );
            tokio::pin!(receive);
            std::future::poll_fn(|cx| {
                assert!(receive.as_mut().poll(cx).is_pending());
                Poll::Ready(())
            })
            .await;
            cancel.cancel();
            tokio::time::timeout(Duration::from_millis(500), receive)
                .await
                .expect("receive failure must not hide cancellation until the next probe")
                .unwrap();
        }
    }
}

#[tokio::test]
async fn windows_receive_error_preserves_report_timers_and_retries_receiving_next_wait() {
    for ip in ["127.0.0.1", "::1"] {
        for mode in 0..3 {
            let (mut run, peer) = fixture(ip, mode).await;
            let state = run.access_report_state.as_mut().unwrap();
            state.timeout = Duration::from_millis(20);
            run.send_probe(true).await.unwrap();
            queue_receive_error(&mut run, &peer).await;
            let start = tokio::time::Instant::now();
            let gap = Duration::from_millis(150);
            let mut timeline = SendTimeline::new(start, 0, None);
            let wait = timeline.after_probe(gap, || start);
            let output = crate::stats::StatsOutput::new(crate::stats::OutputFormat::Json).unwrap();
            assert!(tokio::time::timeout(
                Duration::from_secs(1),
                run.receive_until(
                    wait.deadline,
                    Wait::NextSend {
                        timeline: &mut timeline,
                        gap,
                        interval: gap
                    },
                    &output
                )
            )
            .await
            .unwrap()
            .unwrap());
            assert!(tokio::time::Instant::now() >= wait.deadline);
            assert_eq!(
                run.access_report_state.as_ref().unwrap().retransmissions(),
                1
            );
            assert_eq!(run.packets_sent, 2);
            assert_eq!(run.pending.len(), 2);
            let mut bytes = [0; 512];
            for _ in 0..2 {
                let len = tokio::time::timeout(Duration::from_secs(1), peer.recv(&mut bytes))
                    .await
                    .unwrap()
                    .unwrap();
                let base = if mode == 2 { 112 } else { 44 };
                assert!(len >= base + 8);
                assert_eq!(&bytes[base..base + 8], &[0x80, 6, 0, 4, 0x10, 1, 0, 0]);
            }
            assert!(peer.try_recv(&mut bytes).is_err(), "retry budget exceeded");
            // Receiving is disabled only for the failed wait. A fitting (but
            // intentionally invalid STAMP) datagram is consumed in the next one.
            peer.send_to(&[42], run.socket.local_addr().unwrap())
                .await
                .unwrap();
            run.socket.readable().await.unwrap();
            let gap = Duration::from_millis(20);
            let wait = timeline.after_probe(gap, tokio::time::Instant::now);
            run.receive_until(
                wait.deadline,
                Wait::NextSend {
                    timeline: &mut timeline,
                    gap,
                    interval: gap,
                },
                &output,
            )
            .await
            .unwrap();
            assert_eq!(
                run.socket.try_recv(&mut bytes).unwrap_err().kind(),
                std::io::ErrorKind::WouldBlock
            );
        }
    }
}

#[tokio::test]
async fn windows_receive_error_still_ends_drain_and_report_waits() {
    for ip in ["127.0.0.1", "::1"] {
        for mode in 0..3 {
            for wait in [Wait::Drain, Wait::AccessReport] {
                let (mut run, peer) = fixture(ip, mode).await;
                run.send_probe(true).await.unwrap();
                queue_receive_error(&mut run, &peer).await;
                let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
                let output =
                    crate::stats::StatsOutput::new(crate::stats::OutputFormat::Json).unwrap();
                assert!(!tokio::time::timeout(
                    Duration::from_millis(500),
                    run.receive_until(deadline, wait, &output)
                )
                .await
                .unwrap()
                .unwrap());
                assert_eq!(run.packets_sent, 1);
                assert_eq!(run.pending.len(), 1);
            }
        }
    }
}
