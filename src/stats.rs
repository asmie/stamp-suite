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
            owd: None,
            access_report: None,
            congestion: None,
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

fn ns_i64_to_ms(ns: i64) -> f64 {
    ns as f64 / 1_000_000.0
}

/// A single one-way-delay measurement derived from the four STAMP timestamps.
///
/// Both directions are **signed**: when the sender and reflector clocks are
/// not synchronised the constant clock offset adds to one direction and
/// subtracts from the other, which can make a value negative. We preserve the
/// sign so the asymmetry remains visible rather than masking a clock problem.
pub struct OwdSample {
    /// Sequence number of the measured packet.
    pub seq: u32,
    /// Forward one-way delay `T2 − T1` (sender → reflector), nanoseconds.
    pub forward_ns: i64,
    /// Reverse one-way delay `T4 − T3` (reflector → sender), nanoseconds.
    pub reverse_ns: i64,
}

/// Accumulates the samples for one OWD direction and derives min/max/mean/median.
#[derive(Default)]
struct OwdDirection {
    samples: Vec<i64>,
    min_ns: Option<i64>,
    max_ns: Option<i64>,
    sum_ns: i128,
}

impl OwdDirection {
    fn record(&mut self, v: i64) {
        self.min_ns = Some(self.min_ns.map_or(v, |m| m.min(v)));
        self.max_ns = Some(self.max_ns.map_or(v, |m| m.max(v)));
        self.sum_ns += i128::from(v);
        self.samples.push(v);
    }

    fn mean_ns(&self) -> Option<f64> {
        let n = self.samples.len();
        (n > 0).then(|| self.sum_ns as f64 / n as f64)
    }

    /// Median using the same nearest-rank rounding as [`RttCollector::percentile_ns`].
    fn median_ns(&self) -> Option<i64> {
        if self.samples.is_empty() {
            return None;
        }
        let mut sorted = self.samples.clone();
        sorted.sort_unstable();
        let idx = (0.5 * (sorted.len() - 1) as f64).round() as usize;
        Some(sorted[idx])
    }
}

/// Collects per-packet one-way-delay samples (both directions) and produces an
/// [`OwdSummary`]. Fed from the sender's response path, where all four STAMP
/// timestamps (T1..T4) are available.
#[derive(Default)]
pub struct OwdCollector {
    forward: OwdDirection,
    reverse: OwdDirection,
    count: u32,
}

impl OwdCollector {
    /// Creates a new empty collector.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Records one packet's forward and reverse one-way delays.
    pub fn record(&mut self, sample: OwdSample) {
        self.forward.record(sample.forward_ns);
        self.reverse.record(sample.reverse_ns);
        self.count += 1;
    }

    /// Summarises the collected samples, or `None` if none were recorded.
    #[must_use]
    pub fn summary(&self) -> Option<OwdSummary> {
        Some(OwdSummary {
            samples: self.count,
            forward_min_ms: ns_i64_to_ms(self.forward.min_ns?),
            forward_avg_ms: self.forward.mean_ns()? / 1_000_000.0,
            forward_max_ms: ns_i64_to_ms(self.forward.max_ns?),
            forward_median_ms: ns_i64_to_ms(self.forward.median_ns()?),
            reverse_min_ms: ns_i64_to_ms(self.reverse.min_ns?),
            reverse_avg_ms: self.reverse.mean_ns()? / 1_000_000.0,
            reverse_max_ms: ns_i64_to_ms(self.reverse.max_ns?),
            reverse_median_ms: ns_i64_to_ms(self.reverse.median_ns()?),
        })
    }
}

/// Aggregated one-way-delay statistics (milliseconds), both directions.
///
/// Values assume the sender and reflector clocks are synchronised (e.g. via
/// NTP/PTP); without synchronisation the forward/reverse split reflects the
/// clock offset rather than true path delay, though their sum stays consistent
/// with the round-trip time.
#[derive(serde::Serialize)]
pub struct OwdSummary {
    pub samples: u32,
    pub forward_min_ms: f64,
    pub forward_avg_ms: f64,
    pub forward_max_ms: f64,
    pub forward_median_ms: f64,
    pub reverse_min_ms: f64,
    pub reverse_avg_ms: f64,
    pub reverse_max_ms: f64,
    pub reverse_median_ms: f64,
}

/// Delivery outcome of the Access Report TLV retransmission procedure
/// (RFC 8972 §4.6). Reported once per sender run, since the CLI carries a
/// single Access ID / Return Code for the run's duration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AccessReportOutcome {
    /// The reflector echoed the Access Report TLV (disarming the
    /// retransmission timer) before the retry budget was exhausted.
    Acknowledged,
    /// Still awaiting acknowledgment when the run ended — e.g. the fixed
    /// `--count`/`--interval` schedule finished before the timer expired or
    /// the retry budget was exhausted.
    Pending,
    /// Retransmission retries were exhausted without acknowledgment; the
    /// procedure was aborted per RFC 8972 §4.6 ("...SHOULD be repeated up to
    /// four times before the procedure is aborted"). The measurement itself
    /// is unaffected — this reflects only the Access Report sub-feature.
    Aborted,
}

impl AccessReportOutcome {
    /// Short machine-friendly label (matches the JSON `snake_case` value),
    /// used for CSV output where a parenthetical note would be noise.
    fn as_str(&self) -> &'static str {
        match self {
            Self::Acknowledged => "acknowledged",
            Self::Pending => "pending",
            Self::Aborted => "aborted",
        }
    }
}

impl std::fmt::Display for AccessReportOutcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Acknowledged | Self::Pending => write!(f, "{}", self.as_str()),
            Self::Aborted => write!(f, "aborted (retries exhausted)"),
        }
    }
}

/// Access Report TLV delivery summary (RFC 8972 §4.6), present in
/// [`StatsSnapshot`] only when `--access-report` was set.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub struct AccessReportSummary {
    pub outcome: AccessReportOutcome,
    /// Number of retransmissions actually performed (0 means the original
    /// send was acknowledged, or the run ended/aborted before any
    /// retransmission was needed).
    pub retransmissions: u32,
}

/// AIMD congestion-response observability summary
/// (draft-ietf-ippm-stamp-cos-ecn-01 §3.4), present in [`StatsSnapshot`]
/// only when the controller is active (`--cos` with `--ecn` requesting
/// ECT0/ECT1). Built from `rate_control::AimdStats` by the sender.
#[derive(Debug, Clone, Copy, PartialEq, serde::Serialize)]
pub struct CongestionSummary {
    /// CE-marked replies observed (forward-path EC2 in the reflected CoS
    /// TLV, or reverse-path wire ECN on the reply itself — a reply flagged
    /// by both counts once).
    pub ce_replies: u64,
    /// Number of times a CE observation actually grew the send interval
    /// (excludes CE observations that arrived already saturated at
    /// `max_interval_reached_ms`'s cap).
    pub backoffs_applied: u64,
    /// The send interval in effect when the run ended, milliseconds.
    pub current_interval_ms: f64,
    /// Highest send interval reached at any point during the run,
    /// milliseconds.
    pub max_interval_reached_ms: f64,
    /// The configured base interval (`--send-delay`), milliseconds, for
    /// reference.
    pub base_interval_ms: f64,
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
    /// One-way-delay summary, present once at least one response with usable
    /// timestamps has been measured.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub owd: Option<OwdSummary>,
    /// Access Report TLV delivery outcome (RFC 8972 §4.6), present only when
    /// `--access-report` was set.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub access_report: Option<AccessReportSummary>,
    /// AIMD congestion-response summary (draft-ietf-ippm-stamp-cos-ecn-01
    /// §3.4), present only when the controller was active.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub congestion: Option<CongestionSummary>,
}

impl StatsSnapshot {
    /// Attaches one-way-delay statistics from `owd` to this snapshot. A no-op
    /// (leaves `owd` as `None`) when the collector has no samples.
    #[must_use]
    pub fn with_owd(mut self, owd: &OwdCollector) -> Self {
        self.owd = owd.summary();
        self
    }

    /// Attaches the Access Report TLV delivery outcome (RFC 8972 §4.6) to
    /// this snapshot. Pass `None` when `--access-report` was not set.
    #[must_use]
    pub fn with_access_report(mut self, summary: Option<AccessReportSummary>) -> Self {
        self.access_report = summary;
        self
    }

    /// Attaches the AIMD congestion-response summary
    /// (draft-ietf-ippm-stamp-cos-ecn-01 §3.4) to this snapshot. Pass
    /// `None` when the controller was never active this run.
    #[must_use]
    pub fn with_congestion(mut self, summary: Option<CongestionSummary>) -> Self {
        self.congestion = summary;
        self
    }

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
        if let Some(owd) = &self.owd {
            println!(
                "{}One-way delay (assumes synchronized clocks, n={}):",
                prefix, owd.samples
            );
            println!(
                "{}  Forward (sender→reflector): min {:.3} / avg {:.3} / med {:.3} / max {:.3} ms",
                prefix,
                owd.forward_min_ms,
                owd.forward_avg_ms,
                owd.forward_median_ms,
                owd.forward_max_ms
            );
            println!(
                "{}  Reverse (reflector→sender): min {:.3} / avg {:.3} / med {:.3} / max {:.3} ms",
                prefix,
                owd.reverse_min_ms,
                owd.reverse_avg_ms,
                owd.reverse_median_ms,
                owd.reverse_max_ms
            );
        }
        if let Some(ar) = &self.access_report {
            println!(
                "{}Access Report (RFC 8972 §4.6): {} (retransmissions={})",
                prefix, ar.outcome, ar.retransmissions
            );
        }
        if let Some(c) = &self.congestion {
            println!(
                "{}Congestion response (draft-ietf-ippm-stamp-cos-ecn-01 §3.4): \
                 ce_replies={} backoffs_applied={} interval={:.1}ms \
                 (base={:.1}ms, peak={:.1}ms)",
                prefix,
                c.ce_replies,
                c.backoffs_applied,
                c.current_interval_ms,
                c.base_interval_ms,
                c.max_interval_reached_ms
            );
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
        // Header + data row. OWD, Access Report, and Congestion columns
        // are always present but left empty when no samples were
        // collected / the feature was not enabled.
        println!(
            "packets_sent,packets_received,packets_lost,loss_percent,\
             min_rtt_ms,max_rtt_ms,avg_rtt_ms,median_rtt_ms,\
             p95_rtt_ms,p99_rtt_ms,jitter_ms,std_dev_ms,\
             owd_fwd_min_ms,owd_fwd_avg_ms,owd_fwd_max_ms,\
             owd_rev_min_ms,owd_rev_avg_ms,owd_rev_max_ms,\
             access_report_outcome,access_report_retransmissions,\
             congestion_ce_replies,congestion_backoffs_applied,\
             congestion_current_interval_ms,congestion_max_interval_reached_ms"
        );
        println!(
            "{},{},{},{:.2},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{}",
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
            fmt_opt(self.owd.as_ref().map(|o| o.forward_min_ms)),
            fmt_opt(self.owd.as_ref().map(|o| o.forward_avg_ms)),
            fmt_opt(self.owd.as_ref().map(|o| o.forward_max_ms)),
            fmt_opt(self.owd.as_ref().map(|o| o.reverse_min_ms)),
            fmt_opt(self.owd.as_ref().map(|o| o.reverse_avg_ms)),
            fmt_opt(self.owd.as_ref().map(|o| o.reverse_max_ms)),
            self.access_report.map_or("", |ar| ar.outcome.as_str()),
            self.access_report
                .map_or_else(String::new, |ar| ar.retransmissions.to_string()),
            self.congestion
                .map_or_else(String::new, |c| c.ce_replies.to_string()),
            self.congestion
                .map_or_else(String::new, |c| c.backoffs_applied.to_string()),
            fmt_opt(self.congestion.map(|c| c.current_interval_ms)),
            fmt_opt(self.congestion.map(|c| c.max_interval_reached_ms)),
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
            owd: None,
            access_report: None,
            congestion: None,
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
            owd: None,
            access_report: None,
            congestion: None,
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
            owd: None,
            access_report: None,
            congestion: None,
        };
        // Should not panic
        snap.print(OutputFormat::Csv);
    }

    fn base_snapshot() -> StatsSnapshot {
        StatsSnapshot {
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

    // ===== Congestion response (F2, draft-ietf-ippm-stamp-cos-ecn-01 §3.4) =====

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
}
