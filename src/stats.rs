//! Statistics collection, computation, and formatted output.
//!
//! Provides rich sender statistics (RTT percentiles, jitter, standard deviation),
//! reflector shutdown summaries, and multiple output formats (text, JSON, CSV).

use std::net::SocketAddr;

/// Output format for statistics reporting.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Default,
    clap::ValueEnum,
    serde::Serialize,
    serde::Deserialize,
)]
#[serde(rename_all = "lowercase")]
pub enum OutputFormat {
    /// Human-readable text output.
    #[default]
    Text,
    /// JSON output for machine consumption.
    Json,
    /// CSV output for spreadsheet import.
    Csv,
}

/// A single RTT measurement sample.
pub struct RttSample {
    /// Packet sequence number.
    pub seq: u32,
    /// Round-trip time in nanoseconds.
    pub rtt_ns: u64,
    /// TTL from reflected packet.
    pub ttl: u8,
}

/// Collects RTT samples and computes derived statistics.
pub struct RttCollector {
    samples: Vec<RttSample>,
    min_ns: Option<u64>,
    max_ns: Option<u64>,
    sum_ns: u128,
    sum_sq_ns: u128,
    jitter_sum_ns: u128,
    jitter_count: u64,
    last_rtt_ns: Option<u64>,
}

impl RttCollector {
    /// Creates a new empty collector.
    pub fn new() -> Self {
        RttCollector {
            samples: Vec::new(),
            min_ns: None,
            max_ns: None,
            sum_ns: 0,
            sum_sq_ns: 0,
            jitter_sum_ns: 0,
            jitter_count: 0,
            last_rtt_ns: None,
        }
    }

    /// Records a new RTT sample.
    pub fn record(&mut self, sample: RttSample) {
        let rtt = sample.rtt_ns;

        self.min_ns = Some(self.min_ns.map_or(rtt, |m| m.min(rtt)));
        self.max_ns = Some(self.max_ns.map_or(rtt, |m| m.max(rtt)));
        self.sum_ns += rtt as u128;
        self.sum_sq_ns += (rtt as u128) * (rtt as u128);

        // RFC 3550 jitter: mean |RTT_i - RTT_{i-1}|
        if let Some(prev) = self.last_rtt_ns {
            let delta = rtt.abs_diff(prev);
            self.jitter_sum_ns += delta as u128;
            self.jitter_count += 1;
        }
        self.last_rtt_ns = Some(rtt);

        self.samples.push(sample);
    }

    /// Returns the p-th percentile RTT in nanoseconds (0.0..=100.0).
    pub fn percentile_ns(&self, p: f64) -> Option<u64> {
        if self.samples.is_empty() {
            return None;
        }
        let mut sorted: Vec<u64> = self.samples.iter().map(|s| s.rtt_ns).collect();
        sorted.sort_unstable();
        let idx = ((p / 100.0) * (sorted.len() - 1) as f64).round() as usize;
        Some(sorted[idx.min(sorted.len() - 1)])
    }

    /// Returns mean jitter in nanoseconds (RFC 3550 definition).
    pub fn jitter_ns(&self) -> Option<u64> {
        if self.jitter_count == 0 {
            return None;
        }
        Some((self.jitter_sum_ns / self.jitter_count as u128) as u64)
    }

    /// Returns standard deviation of RTT in nanoseconds.
    pub fn std_dev_ns(&self) -> Option<f64> {
        let n = self.samples.len();
        if n < 2 {
            return None;
        }
        let mean = self.sum_ns as f64 / n as f64;
        let mean_sq = self.sum_sq_ns as f64 / n as f64;
        let variance = mean_sq - mean * mean;
        if variance < 0.0 {
            // Floating-point rounding — treat as zero
            return Some(0.0);
        }
        Some(variance.sqrt())
    }

    /// Builds a snapshot of current statistics.
    pub fn snapshot(&self, packets_sent: u32, packets_lost: u32) -> StatsSnapshot {
        let packets_received = self.samples.len() as u32;
        let total = packets_sent.max(1) as f64;

        StatsSnapshot {
            packets_sent,
            packets_received,
            packets_lost,
            loss_percent: (packets_lost as f64 / total) * 100.0,
            min_rtt_ms: self.min_ns.map(ns_to_ms),
            max_rtt_ms: self.max_ns.map(ns_to_ms),
            avg_rtt_ms: if packets_received > 0 {
                Some(self.sum_ns as f64 / packets_received as f64 / 1_000_000.0)
            } else {
                None
            },
            median_rtt_ms: self.percentile_ns(50.0).map(ns_to_ms),
            p95_rtt_ms: self.percentile_ns(95.0).map(ns_to_ms),
            p99_rtt_ms: self.percentile_ns(99.0).map(ns_to_ms),
            jitter_ms: self.jitter_ns().map(ns_to_ms),
            std_dev_ms: self.std_dev_ns().map(|ns| ns / 1_000_000.0),
        }
    }
}

impl Default for RttCollector {
    fn default() -> Self {
        Self::new()
    }
}

fn ns_to_ms(ns: u64) -> f64 {
    ns as f64 / 1_000_000.0
}

/// Serializable sender statistics snapshot.
#[derive(serde::Serialize)]
pub struct StatsSnapshot {
    pub packets_sent: u32,
    pub packets_received: u32,
    pub packets_lost: u32,
    pub loss_percent: f64,
    pub min_rtt_ms: Option<f64>,
    pub max_rtt_ms: Option<f64>,
    pub avg_rtt_ms: Option<f64>,
    pub median_rtt_ms: Option<f64>,
    pub p95_rtt_ms: Option<f64>,
    pub p99_rtt_ms: Option<f64>,
    pub jitter_ms: Option<f64>,
    pub std_dev_ms: Option<f64>,
}

impl StatsSnapshot {
    /// Prints the final summary in the given format.
    pub fn print(&self, format: OutputFormat) {
        match format {
            OutputFormat::Text => self.print_text(""),
            OutputFormat::Json => self.print_json(false),
            OutputFormat::Csv => self.print_csv(),
        }
    }

    /// Prints an interim (periodic) summary in the given format.
    pub fn print_interim(&self, format: OutputFormat) {
        match format {
            OutputFormat::Text => self.print_text("[INTERIM] "),
            OutputFormat::Json => self.print_json(true),
            OutputFormat::Csv => self.print_csv(),
        }
    }

    fn print_text(&self, prefix: &str) {
        println!("\n{}--- STAMP Statistics ---", prefix);
        println!("{}Packets sent: {}", prefix, self.packets_sent);
        println!("{}Packets received: {}", prefix, self.packets_received);
        println!(
            "{}Packets lost: {} ({:.1}%)",
            prefix, self.packets_lost, self.loss_percent
        );
        if let Some(v) = self.min_rtt_ms {
            println!("{}Min RTT: {:.3} ms", prefix, v);
        }
        if let Some(v) = self.max_rtt_ms {
            println!("{}Max RTT: {:.3} ms", prefix, v);
        }
        if let Some(v) = self.avg_rtt_ms {
            println!("{}Avg RTT: {:.3} ms", prefix, v);
        }
        if let Some(v) = self.median_rtt_ms {
            println!("{}Median RTT: {:.3} ms", prefix, v);
        }
        if let Some(v) = self.p95_rtt_ms {
            println!("{}P95 RTT: {:.3} ms", prefix, v);
        }
        if let Some(v) = self.p99_rtt_ms {
            println!("{}P99 RTT: {:.3} ms", prefix, v);
        }
        if let Some(v) = self.jitter_ms {
            println!("{}Jitter: {:.3} ms", prefix, v);
        }
        if let Some(v) = self.std_dev_ms {
            println!("{}Std Dev: {:.3} ms", prefix, v);
        }
    }

    fn print_json(&self, interim: bool) {
        #[derive(serde::Serialize)]
        struct JsonOutput<'a> {
            #[serde(rename = "type")]
            report_type: &'a str,
            #[serde(flatten)]
            stats: &'a StatsSnapshot,
        }
        let output = JsonOutput {
            report_type: if interim { "interim" } else { "summary" },
            stats: self,
        };
        if let Ok(json) = serde_json::to_string(&output) {
            println!("{}", json);
        }
    }

    fn print_csv(&self) {
        // Header + data row
        println!(
            "packets_sent,packets_received,packets_lost,loss_percent,\
             min_rtt_ms,max_rtt_ms,avg_rtt_ms,median_rtt_ms,\
             p95_rtt_ms,p99_rtt_ms,jitter_ms,std_dev_ms"
        );
        println!(
            "{},{},{},{:.2},{},{},{},{},{},{},{},{}",
            self.packets_sent,
            self.packets_received,
            self.packets_lost,
            self.loss_percent,
            fmt_opt(self.min_rtt_ms),
            fmt_opt(self.max_rtt_ms),
            fmt_opt(self.avg_rtt_ms),
            fmt_opt(self.median_rtt_ms),
            fmt_opt(self.p95_rtt_ms),
            fmt_opt(self.p99_rtt_ms),
            fmt_opt(self.jitter_ms),
            fmt_opt(self.std_dev_ms),
        );
    }
}

fn fmt_opt(v: Option<f64>) -> String {
    v.map_or_else(String::new, |x| format!("{:.3}", x))
}

/// Per-client session statistics for reflector reporting.
#[derive(serde::Serialize)]
pub struct ClientSessionStats {
    pub client: String,
    pub packets_received: u32,
    pub packets_transmitted: u32,
}

/// Serializable reflector statistics summary.
#[derive(serde::Serialize)]
pub struct ReflectorStats {
    pub total_packets_received: u64,
    pub total_packets_reflected: u64,
    pub total_packets_dropped: u64,
    pub active_sessions: usize,
    pub uptime_seconds: f64,
    pub sessions: Vec<ClientSessionStats>,
}

impl ReflectorStats {
    /// Prints the reflector summary in the given format.
    pub fn print(&self, format: OutputFormat) {
        match format {
            OutputFormat::Text => self.print_text(),
            OutputFormat::Json => self.print_json(),
            OutputFormat::Csv => self.print_csv(),
        }
    }

    fn print_text(&self) {
        println!("\n--- STAMP Reflector Statistics ---");
        println!("Uptime: {:.1} seconds", self.uptime_seconds);
        println!("Total packets received: {}", self.total_packets_received);
        println!("Total packets reflected: {}", self.total_packets_reflected);
        println!("Total packets dropped: {}", self.total_packets_dropped);
        println!("Active sessions: {}", self.active_sessions);
        if !self.sessions.is_empty() {
            println!("Sessions:");
            for s in &self.sessions {
                println!(
                    "  {} - rx: {}, tx: {}",
                    s.client, s.packets_received, s.packets_transmitted
                );
            }
        }
    }

    fn print_json(&self) {
        if let Ok(json) = serde_json::to_string(self) {
            println!("{}", json);
        }
    }

    fn print_csv(&self) {
        println!("total_received,total_reflected,total_dropped,active_sessions,uptime_seconds");
        println!(
            "{},{},{},{},{:.1}",
            self.total_packets_received,
            self.total_packets_reflected,
            self.total_packets_dropped,
            self.active_sessions,
            self.uptime_seconds,
        );
    }
}

/// Builds a ReflectorStats from counters and session manager state.
pub fn build_reflector_stats(
    packets_received: u64,
    packets_reflected: u64,
    packets_dropped: u64,
    session_summaries: Vec<(SocketAddr, u32, u32)>,
    active_sessions: usize,
    uptime_seconds: f64,
) -> ReflectorStats {
    let sessions = session_summaries
        .into_iter()
        .map(|(addr, rx, tx)| ClientSessionStats {
            client: addr.to_string(),
            packets_received: rx,
            packets_transmitted: tx,
        })
        .collect();
    ReflectorStats {
        total_packets_received: packets_received,
        total_packets_reflected: packets_reflected,
        total_packets_dropped: packets_dropped,
        active_sessions,
        uptime_seconds,
        sessions,
    }
}

#[cfg(test)]
mod tests {
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
        };
        // Should not panic
        snap.print(OutputFormat::Text);
    }

    #[test]
    fn test_stats_json_format() {
        let snap = StatsSnapshot {
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
        };
        // Should not panic
        snap.print(OutputFormat::Json);
    }

    #[test]
    fn test_stats_csv_format() {
        let snap = StatsSnapshot {
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
        };
        // Should not panic
        snap.print(OutputFormat::Csv);
    }

    #[test]
    fn test_stats_json_none_fields() {
        let snap = StatsSnapshot {
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
        };
        snap.print(OutputFormat::Json);
    }

    #[test]
    fn test_reflector_stats_text() {
        let stats = ReflectorStats {
            total_packets_received: 100,
            total_packets_reflected: 98,
            total_packets_dropped: 2,
            active_sessions: 1,
            uptime_seconds: 60.0,
            sessions: vec![ClientSessionStats {
                client: "127.0.0.1:12345".to_string(),
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
                "127.0.0.1:1001".parse::<SocketAddr>().unwrap(),
                50u32,
                48u32,
            ),
            (
                "127.0.0.1:1002".parse::<SocketAddr>().unwrap(),
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
    // C11: RFC 3550 jitter and percentile edge cases.

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

    /// Single sample: jitter and std_dev are undefined per RFC 3550. Our
    /// implementation returns None for both rather than 0 or NaN.
    #[test]
    fn test_single_sample_jitter_and_stddev_undefined() {
        let mut c = RttCollector::new();
        c.record(RttSample {
            seq: 0,
            rtt_ns: 5_000_000,
            ttl: 64,
        });
        assert_eq!(c.jitter_ns(), None, "RFC 3550 jitter requires ≥ 2 samples");
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

    /// Negative-skew sequence: RTTs that decrease across the window. RFC
    /// 3550 jitter uses |Δ| so the result must be positive and equal to
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

    /// Large RTT samples (sub-second but at the multi-billion-ns scale)
    /// must not overflow the u128 accumulators. Pin numerical stability.
    #[test]
    fn test_large_rtt_no_overflow() {
        let mut c = RttCollector::new();
        // 1000 samples at ~3 seconds each — within u32::MAX seconds but
        // accumulated as u128 ns to avoid overflow.
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
    /// every valid p — no off-by-one in the index calculation.
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
}
