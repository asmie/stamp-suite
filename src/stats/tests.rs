#[test]
fn long_run_keeps_cumulative_moments_and_signed_owd() {
    let mut rtt = RttCollector::new();
    let mut owd = OwdCollector::new();
    for seq in 0..100_000 {
        rtt.record(RttSample {
            seq,
            rtt_ns: 1_000_000_000_000 + 2 * u64::from(seq % 2),
            ttl: 64,
        });
        owd.record(OwdSample {
            seq,
            forward_ns: if seq % 2 == 0 { i64::MIN } else { i64::MAX },
            reverse_ns: -7_777_777,
        });
    }
    let snapshot = rtt.snapshot(100_000, 0).with_owd(&owd);
    assert_eq!(snapshot.packets_received, 100_000);
    assert!((snapshot.avg_rtt_ms.unwrap() - 1_000_000.000_001).abs() < 1e-9);
    assert_eq!(rtt.jitter_ns(), Some(2));
    assert!((rtt.std_dev_ns().unwrap() - 1.0).abs() < 1e-12);
    let summary = snapshot.owd.as_ref().unwrap();
    assert_eq!(summary.samples, 100_000);
    assert_eq!(summary.forward_avg_ms, -0.000_000_5);
    assert_eq!(summary.reverse_avg_ms, -7.777_777);
    assert_eq!(summary.reverse_median_ms, -7.777_777);
    assert_eq!(
        serde_json::to_value(&snapshot).unwrap()["quantile_precision"]["exact_sample_limit"],
        4096
    );
}

#[test]
fn variance_preserves_small_spread_on_a_large_baseline() {
    let mut collector = RttCollector::new();
    for rtt_ns in [1_000_000_000_000, 1_000_000_000_002] {
        collector.record(RttSample {
            seq: 0,
            rtt_ns,
            ttl: 64,
        });
    }
    assert_eq!(collector.std_dev_ns(), Some(1.0));
}

#[test]
fn full_range_rtt_does_not_overflow_variance() {
    let mut collector = RttCollector::new();
    for rtt_ns in [u64::MAX, u64::MAX - 2] {
        collector.record(RttSample {
            seq: 0,
            rtt_ns,
            ttl: 64,
        });
    }
    assert_eq!(collector.std_dev_ns(), Some(1.0));
    assert_eq!(collector.jitter_ns(), Some(2));
}

use super::*;

#[test]
fn test_empty_collector() {
    let c = RttCollector::new();
    assert!(c.percentile_ns(50.0).is_none());
    assert!(c.jitter_ns().is_none());
    assert!(c.std_dev_ns().is_none());

    let snap = c.snapshot(0, 0);
    assert_eq!(snap.packets_sent, 0);
    assert_eq!(snap.packets_received, 0);
    assert!(snap.min_rtt_ms.is_none());
}

#[test]
fn test_single_sample() {
    let mut c = RttCollector::new();
    c.record(RttSample {
        seq: 0,
        rtt_ns: 1_000_000,
        ttl: 64,
    });

    assert_eq!(c.min_ns, Some(1_000_000));
    assert_eq!(c.max_ns, Some(1_000_000));
    assert!(c.jitter_ns().is_none()); // need at least 2 samples
    assert!(c.std_dev_ns().is_none()); // need at least 2 samples
    assert_eq!(c.percentile_ns(50.0), Some(1_000_000));

    let snap = c.snapshot(1, 0);
    assert_eq!(snap.packets_received, 1);
    assert!((snap.min_rtt_ms.unwrap() - 1.0).abs() < 0.001);
}

#[test]
fn test_multi_samples() {
    let mut c = RttCollector::new();
    // 1ms, 2ms, 3ms, 4ms, 5ms
    for i in 1..=5 {
        c.record(RttSample {
            seq: i,
            rtt_ns: i as u64 * 1_000_000,
            ttl: 64,
        });
    }

    assert_eq!(c.min_ns, Some(1_000_000));
    assert_eq!(c.max_ns, Some(5_000_000));

    // Jitter: mean of |2-1|, |3-2|, |4-3|, |5-4| = mean of 1,1,1,1 = 1ms
    assert_eq!(c.jitter_ns(), Some(1_000_000));

    // Median of [1,2,3,4,5] = 3
    assert_eq!(c.percentile_ns(50.0), Some(3_000_000));

    // Std dev
    let sd = c.std_dev_ns().unwrap();
    assert!(sd > 0.0);

    let snap = c.snapshot(5, 0);
    assert_eq!(snap.packets_sent, 5);
    assert_eq!(snap.packets_received, 5);
    assert_eq!(snap.packets_lost, 0);
    assert!((snap.loss_percent - 0.0).abs() < 0.01);
    assert!((snap.avg_rtt_ms.unwrap() - 3.0).abs() < 0.001);
}

#[test]
fn test_percentiles() {
    let mut c = RttCollector::new();
    for i in 1..=100 {
        c.record(RttSample {
            seq: i,
            rtt_ns: i as u64 * 1000,
            ttl: 64,
        });
    }
    // P0 = 1000, P50 ~= 50500, P95 ~= 95000, P99 ~= 99000, P100 = 100000
    assert_eq!(c.percentile_ns(0.0), Some(1000));
    assert_eq!(c.percentile_ns(100.0), Some(100_000));
}

#[test]
fn test_snapshot_loss_percent() {
    let c = RttCollector::new();
    let snap = c.snapshot(10, 3);
    assert!((snap.loss_percent - 30.0).abs() < 0.01);
}

#[test]
fn test_stats_text_format() {
    let snap = StatsSnapshot {
        target: None,
        quantile_precision: QuantilePrecision::default(),
        measurements: None,
        packets_sent: 10,
        packets_received: 8,
        packets_lost: 2,
        loss_percent: 20.0,
        min_rtt_ms: Some(1.0),
        max_rtt_ms: Some(5.0),
        avg_rtt_ms: Some(3.0),
        median_rtt_ms: Some(3.0),
        p95_rtt_ms: Some(4.5),
        p99_rtt_ms: Some(4.9),
        jitter_ms: Some(0.5),
        std_dev_ms: Some(1.2),
        owd: None,
        access_report: None,
        congestion: None,
        ber: None,
    };
    // Should not panic
    snap.print(OutputFormat::Text);
}

#[test]
fn test_stats_json_format() {
    let snap = StatsSnapshot {
        target: None,
        quantile_precision: QuantilePrecision::default(),
        measurements: None,
        packets_sent: 10,
        packets_received: 8,
        packets_lost: 2,
        loss_percent: 20.0,
        min_rtt_ms: Some(1.0),
        max_rtt_ms: Some(5.0),
        avg_rtt_ms: Some(3.0),
        median_rtt_ms: Some(3.0),
        p95_rtt_ms: Some(4.5),
        p99_rtt_ms: Some(4.9),
        jitter_ms: Some(0.5),
        std_dev_ms: Some(1.2),
        owd: None,
        access_report: None,
        congestion: None,
        ber: None,
    };
    // Should not panic
    snap.print(OutputFormat::Json);
}

#[test]
fn test_stats_csv_format() {
    let snap = StatsSnapshot {
        target: None,
        quantile_precision: QuantilePrecision::default(),
        measurements: None,
        packets_sent: 10,
        packets_received: 8,
        packets_lost: 2,
        loss_percent: 20.0,
        min_rtt_ms: Some(1.0),
        max_rtt_ms: Some(5.0),
        avg_rtt_ms: Some(3.0),
        median_rtt_ms: Some(3.0),
        p95_rtt_ms: Some(4.5),
        p99_rtt_ms: Some(4.9),
        jitter_ms: Some(0.5),
        std_dev_ms: Some(1.2),
        owd: None,
        access_report: None,
        congestion: None,
        ber: None,
    };
    // Should not panic
    snap.print(OutputFormat::Csv);
}

fn base_snapshot() -> StatsSnapshot {
    StatsSnapshot {
        target: None,
        quantile_precision: QuantilePrecision::default(),
        measurements: None,
        packets_sent: 10,
        packets_received: 8,
        packets_lost: 2,
        loss_percent: 20.0,
        min_rtt_ms: Some(1.0),
        max_rtt_ms: Some(5.0),
        avg_rtt_ms: Some(3.0),
        median_rtt_ms: Some(3.0),
        p95_rtt_ms: Some(4.5),
        p99_rtt_ms: Some(4.9),
        jitter_ms: Some(0.5),
        std_dev_ms: Some(1.2),
        owd: None,
        access_report: None,
        congestion: None,
        ber: None,
    }
}

#[test]
fn test_access_report_outcome_display() {
    assert_eq!(
        AccessReportOutcome::Acknowledged.to_string(),
        "acknowledged"
    );
    assert_eq!(AccessReportOutcome::Pending.to_string(), "pending");
    assert_eq!(
        AccessReportOutcome::Aborted.to_string(),
        "aborted (retries exhausted)"
    );
}

#[test]
fn test_with_access_report_attaches_summary() {
    let snap = base_snapshot().with_access_report(Some(AccessReportSummary {
        outcome: AccessReportOutcome::Acknowledged,
        retransmissions: 0,
    }));
    let ar = snap.access_report.expect("summary attached");
    assert_eq!(ar.outcome, AccessReportOutcome::Acknowledged);
    assert_eq!(ar.retransmissions, 0);
}

#[test]
fn test_with_access_report_none_is_noop() {
    let snap = base_snapshot().with_access_report(None);
    assert!(snap.access_report.is_none());
}

#[test]
fn test_stats_text_format_includes_access_report() {
    // Capture behaviour indirectly: printing must not panic when the
    // Access Report summary is present, for every outcome variant.
    for (outcome, retransmissions) in [
        (AccessReportOutcome::Acknowledged, 0),
        (AccessReportOutcome::Acknowledged, 2),
        (AccessReportOutcome::Pending, 1),
        (AccessReportOutcome::Aborted, 4),
    ] {
        let snap = base_snapshot().with_access_report(Some(AccessReportSummary {
            outcome,
            retransmissions,
        }));
        snap.print(OutputFormat::Text);
        snap.print(OutputFormat::Json);
        snap.print(OutputFormat::Csv);
    }
}

#[test]
fn test_stats_json_serializes_access_report_fields() {
    let snap = base_snapshot().with_access_report(Some(AccessReportSummary {
        outcome: AccessReportOutcome::Aborted,
        retransmissions: 4,
    }));
    let json = serde_json::to_string(&snap).unwrap();
    assert!(json.contains("\"access_report\""));
    assert!(json.contains("\"aborted\""));
    assert!(json.contains("\"retransmissions\":4"));
}

#[test]
fn test_stats_json_omits_access_report_when_none() {
    let snap = base_snapshot();
    let json = serde_json::to_string(&snap).unwrap();
    assert!(!json.contains("access_report"));
}

#[test]
fn test_stats_csv_includes_access_report_columns() {
    // Smoke check: CSV printing with an access-report summary attached
    // must not panic (columns validated via manual inspection since
    // print_csv writes to stdout, not a capturable buffer here).
    let snap = base_snapshot().with_access_report(Some(AccessReportSummary {
        outcome: AccessReportOutcome::Pending,
        retransmissions: 1,
    }));
    snap.print(OutputFormat::Csv);
}

// ===== Congestion response (draft-ietf-ippm-stamp-cos-ecn-01 §3.4) =====

fn sample_congestion() -> CongestionSummary {
    CongestionSummary {
        ce_replies: 3,
        backoffs_applied: 2,
        current_interval_ms: 200.0,
        max_interval_reached_ms: 400.0,
        base_interval_ms: 100.0,
    }
}

#[test]
fn test_with_congestion_attaches_summary() {
    let snap = base_snapshot().with_congestion(Some(sample_congestion()));
    let c = snap.congestion.expect("summary attached");
    assert_eq!(c.ce_replies, 3);
    assert_eq!(c.backoffs_applied, 2);
    assert!((c.current_interval_ms - 200.0).abs() < f64::EPSILON);
}

#[test]
fn test_with_congestion_none_is_noop() {
    let snap = base_snapshot().with_congestion(None);
    assert!(snap.congestion.is_none());
}

#[test]
fn test_stats_text_format_includes_congestion() {
    let snap = base_snapshot().with_congestion(Some(sample_congestion()));
    // Must not panic in any output format.
    snap.print(OutputFormat::Text);
    snap.print(OutputFormat::Json);
    snap.print(OutputFormat::Csv);
}

#[test]
fn test_stats_json_serializes_congestion_fields() {
    let snap = base_snapshot().with_congestion(Some(sample_congestion()));
    let json = serde_json::to_string(&snap).unwrap();
    assert!(json.contains("\"congestion\""));
    assert!(json.contains("\"ce_replies\":3"));
    assert!(json.contains("\"backoffs_applied\":2"));
}

#[test]
fn test_stats_json_omits_congestion_when_none() {
    let snap = base_snapshot();
    let json = serde_json::to_string(&snap).unwrap();
    assert!(!json.contains("congestion"));
}

#[test]
fn test_stats_csv_includes_congestion_columns() {
    let snap = base_snapshot().with_congestion(Some(sample_congestion()));
    snap.print(OutputFormat::Csv);
}

#[test]
fn test_stats_json_none_fields() {
    let snap = StatsSnapshot {
        target: None,
        quantile_precision: QuantilePrecision::default(),
        measurements: None,
        packets_sent: 5,
        packets_received: 0,
        packets_lost: 5,
        loss_percent: 100.0,
        min_rtt_ms: None,
        max_rtt_ms: None,
        avg_rtt_ms: None,
        median_rtt_ms: None,
        p95_rtt_ms: None,
        p99_rtt_ms: None,
        jitter_ms: None,
        std_dev_ms: None,
        owd: None,
        access_report: None,
        congestion: None,
        ber: None,
    };
    snap.print(OutputFormat::Json);
}

#[test]
fn test_reflector_stats_text() {
    let stats = ReflectorStats {
        total_packets_received: 100,
        total_packets_reflected: 98,
        total_packets_dropped: 2,
        reply_queue_rejected: 0,
        queued_replies_cancelled: 0,
        active_sessions: 1,
        uptime_seconds: 60.0,
        sessions: vec![ClientSessionStats {
            client: "127.0.0.1:12345".to_string(),
            local: "127.0.0.1:862".to_string(),
            ssid: 42,
            sender_micro_session_id: None,
            packets_received: 100,
            packets_transmitted: 98,
        }],
    };
    stats.print(OutputFormat::Text);
}

#[test]
fn test_reflector_stats_json() {
    let stats = ReflectorStats {
        total_packets_received: 100,
        total_packets_reflected: 98,
        total_packets_dropped: 2,
        reply_queue_rejected: 0,
        queued_replies_cancelled: 0,
        active_sessions: 1,
        uptime_seconds: 60.0,
        sessions: vec![],
    };
    stats.print(OutputFormat::Json);
}

#[test]
fn test_reflector_stats_csv() {
    let stats = ReflectorStats {
        total_packets_received: 100,
        total_packets_reflected: 98,
        total_packets_dropped: 2,
        reply_queue_rejected: 0,
        queued_replies_cancelled: 0,
        active_sessions: 1,
        uptime_seconds: 60.0,
        sessions: vec![],
    };
    stats.print(OutputFormat::Csv);
}

#[test]
fn test_build_reflector_stats() {
    let summaries = vec![
        (
            "127.0.0.1:1001".parse::<SocketAddr>().unwrap().into(),
            50u32,
            48u32,
        ),
        (
            "127.0.0.1:1002".parse::<SocketAddr>().unwrap().into(),
            30u32,
            30u32,
        ),
    ];
    let stats = build_reflector_stats(80, 78, 2, summaries, 2, 120.5);
    assert_eq!(stats.total_packets_received, 80);
    assert_eq!(stats.total_packets_reflected, 78);
    assert_eq!(stats.total_packets_dropped, 2);
    assert_eq!(stats.active_sessions, 2);
    assert_eq!(stats.sessions.len(), 2);
}

// -----------------------------------------------------------------------
// Successive RTT variation and percentile edge cases.

/// Empty collector: percentile_ns over any p must return None, never
/// panic with a sort-empty / index-out-of-bounds.
#[test]
fn test_percentile_empty_set_returns_none_for_any_p() {
    let c = RttCollector::new();
    for p in [0.0, 50.0, 99.0, 100.0, -10.0, 200.0, f64::NAN] {
        assert!(
            c.percentile_ns(p).is_none(),
            "percentile_ns({p}) on empty collector must be None"
        );
    }
}

/// Single sample: successive variation and std_dev need two samples. Our
/// implementation returns None for both rather than 0 or NaN.
#[test]
fn test_single_sample_jitter_and_stddev_undefined() {
    let mut c = RttCollector::new();
    c.record(RttSample {
        seq: 0,
        rtt_ns: 5_000_000,
        ttl: 64,
    });
    assert_eq!(
        c.jitter_ns(),
        None,
        "successive RTT variation requires ≥ 2 samples"
    );
    assert_eq!(
        c.std_dev_ns(),
        None,
        "std dev requires ≥ 2 samples for the n-1 (or n) denominator"
    );
}

/// Zero-jitter sequence: 10 identical RTTs produce jitter = 0 and
/// std_dev = 0 exactly (no floating-point drift).
#[test]
fn test_zero_jitter_constant_rtts() {
    let mut c = RttCollector::new();
    for i in 0..10 {
        c.record(RttSample {
            seq: i,
            rtt_ns: 5_000_000,
            ttl: 64,
        });
    }
    assert_eq!(c.jitter_ns(), Some(0));
    let sd = c.std_dev_ns().expect("std dev defined for ≥ 2 samples");
    assert!(
        sd.abs() < 1e-3,
        "constant RTTs must produce std_dev = 0 (got {sd})"
    );
}

/// Negative-skew sequence: RTTs that decrease across the window. Mean
/// successive RTT variation uses |Δ| so the result must be positive and equal to
/// the abs-difference mean.
#[test]
fn test_negative_skew_jitter_uses_abs_diff() {
    let mut c = RttCollector::new();
    // RTTs: 5, 4, 3, 2, 1 ms. |Δ| sequence: 1,1,1,1 → jitter = 1 ms.
    for i in (1..=5).rev() {
        c.record(RttSample {
            seq: 6 - i,
            rtt_ns: i as u64 * 1_000_000,
            ttl: 64,
        });
    }
    assert_eq!(c.jitter_ns(), Some(1_000_000));
    assert_eq!(c.min_ns, Some(1_000_000));
    assert_eq!(c.max_ns, Some(5_000_000));
}

/// Percentile at p=0 and p=100 must be min and max respectively.
/// Percentile at fractional p (e.g. 37.5) must not panic.
#[test]
fn test_percentile_boundary_values() {
    let mut c = RttCollector::new();
    for i in 1..=10 {
        c.record(RttSample {
            seq: i,
            rtt_ns: i as u64 * 1000,
            ttl: 64,
        });
    }
    assert_eq!(c.percentile_ns(0.0), Some(1000));
    assert_eq!(c.percentile_ns(100.0), Some(10_000));
    // Out-of-range p: implementation clamps to last index, must not
    // panic.
    let _ = c.percentile_ns(150.0);
    let _ = c.percentile_ns(-25.0);
    // Fractional p: rounds to nearest index.
    let p375 = c
        .percentile_ns(37.5)
        .expect("must be defined for 10 samples");
    assert!((1000..=10_000).contains(&p375));
}

/// Alternating high/low RTTs produce mean |Δ| = (h - l). The classic
/// "telecoms jitter" testcase.
#[test]
fn test_alternating_jitter() {
    let mut c = RttCollector::new();
    let pattern = [10_000_000u64, 1_000_000, 10_000_000, 1_000_000];
    for (i, &rtt) in pattern.iter().enumerate() {
        c.record(RttSample {
            seq: i as u32,
            rtt_ns: rtt,
            ttl: 64,
        });
    }
    // |Δ| sequence: 9_000_000, 9_000_000, 9_000_000 → mean 9 ms.
    assert_eq!(c.jitter_ns(), Some(9_000_000));
}

/// Two-sample std dev must be defined (boundary case for the n ≥ 2
/// check) and equal half the absolute difference (population formula).
#[test]
fn test_two_sample_std_dev_defined() {
    let mut c = RttCollector::new();
    c.record(RttSample {
        seq: 0,
        rtt_ns: 1_000_000,
        ttl: 64,
    });
    c.record(RttSample {
        seq: 1,
        rtt_ns: 3_000_000,
        ttl: 64,
    });
    // Population variance of {1e6, 3e6} = ((1e6-2e6)^2 + (3e6-2e6)^2)/2 = 1e12
    // → std_dev = 1e6.
    let sd = c.std_dev_ns().expect("defined for 2 samples");
    assert!(
        (sd - 1_000_000.0).abs() < 1.0,
        "expected ~1e6 ns std dev, got {sd}"
    );
}

/// Large RTT samples (seconds, so billions of ns) must not overflow the
/// u128 accumulators. Pins numerical stability.
#[test]
fn test_large_rtt_no_overflow() {
    let mut c = RttCollector::new();
    // 1000 samples of 3 seconds each, accumulated as u128 ns.
    for i in 0..1000 {
        c.record(RttSample {
            seq: i,
            rtt_ns: 3_000_000_000,
            ttl: 64,
        });
    }
    assert_eq!(c.jitter_ns(), Some(0));
    assert_eq!(c.std_dev_ns(), Some(0.0));
    let snap = c.snapshot(1000, 0);
    assert!(
        (snap.avg_rtt_ms.unwrap() - 3000.0).abs() < 0.001,
        "expected ~3000ms avg, got {:?}",
        snap.avg_rtt_ms
    );
}

/// Percentile on a single-sample collector must return that sample for
/// every valid p (no off-by-one in the index calculation).
#[test]
fn test_single_sample_percentile_returns_that_sample() {
    let mut c = RttCollector::new();
    c.record(RttSample {
        seq: 0,
        rtt_ns: 7_777_777,
        ttl: 64,
    });
    for p in [0.0, 25.0, 50.0, 95.0, 99.0, 100.0] {
        assert_eq!(c.percentile_ns(p), Some(7_777_777));
    }
}

/// Loss percent edge case: zero packets sent → no division-by-zero,
/// no NaN in the loss_percent field. The snapshot uses `packets_sent.max(1)`
/// internally; verify it produces 0.0.
#[test]
fn test_snapshot_zero_sent_zero_loss() {
    let c = RttCollector::new();
    let snap = c.snapshot(0, 0);
    assert!(snap.loss_percent.is_finite());
    assert!((snap.loss_percent - 0.0).abs() < 0.01);
}

// -----------------------------------------------------------------------
// One-way delay aggregation.

#[test]
fn owd_empty_summary_is_none() {
    assert!(OwdCollector::new().summary().is_none());
}

#[test]
fn owd_records_forward_and_reverse() {
    let mut c = OwdCollector::new();
    // forward: 1,2,3 ms; reverse: 4,5,6 ms
    for i in 0..3 {
        c.record(OwdSample {
            seq: i,
            forward_ns: (i as i64 + 1) * 1_000_000,
            reverse_ns: (i as i64 + 4) * 1_000_000,
        });
    }
    let s = c.summary().expect("summary present");
    assert_eq!(s.samples, 3);
    assert!((s.forward_min_ms - 1.0).abs() < 1e-9);
    assert!((s.forward_avg_ms - 2.0).abs() < 1e-9);
    assert!((s.forward_max_ms - 3.0).abs() < 1e-9);
    assert!((s.forward_median_ms - 2.0).abs() < 1e-9);
    assert!((s.reverse_min_ms - 4.0).abs() < 1e-9);
    assert!((s.reverse_avg_ms - 5.0).abs() < 1e-9);
    assert!((s.reverse_max_ms - 6.0).abs() < 1e-9);
    assert!((s.reverse_median_ms - 5.0).abs() < 1e-9);
}

#[test]
fn owd_preserves_negative_offset() {
    // Unsynchronised clocks can yield a negative one-way delay; it must be
    // preserved (not clamped to zero) so the directional asymmetry shows.
    let mut c = OwdCollector::new();
    c.record(OwdSample {
        seq: 0,
        forward_ns: -2_000_000,
        reverse_ns: 8_000_000,
    });
    let s = c.summary().unwrap();
    assert!((s.forward_min_ms - (-2.0)).abs() < 1e-9);
    assert!((s.forward_avg_ms - (-2.0)).abs() < 1e-9);
}

#[test]
fn owd_summary_attaches_to_snapshot() {
    let mut owd = OwdCollector::new();
    owd.record(OwdSample {
        seq: 0,
        forward_ns: 1_000_000,
        reverse_ns: 2_000_000,
    });
    let snap = RttCollector::new().snapshot(1, 0).with_owd(&owd);
    assert!(snap.owd.is_some());
    // Without samples, with_owd leaves it None (does not attach).
    let empty = RttCollector::new()
        .snapshot(0, 0)
        .with_owd(&OwdCollector::new());
    assert!(empty.owd.is_none());
}
