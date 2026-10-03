//! Statistics collection, computation, and formatted output.
//!
//! Provides rich sender statistics (RTT percentiles, jitter, standard deviation),
//! reflector shutdown summaries, and multiple output formats (text, JSON, CSV).

pub use crate::sender::measurements::{
    CounterPoint, DelaySummary, DirectSummary, FollowUpSummary, MeasurementSummary,
};

mod clock_quality;
pub use clock_quality::{ClockEstimate, ClockQuality};

mod quantiles;
use quantiles::Quantiles;

#[cfg(test)]
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

/// Output state for one sender reporting stream. Reuse it for interim and final
/// snapshots so CSV has one header, even when a run produces no interim report.
///
/// Clones share the CSV header state and print one report at a time, so
/// concurrent sender runs can report into one stream.
#[derive(Clone)]
pub struct StatsOutput {
    format: OutputFormat,
    /// Whether the CSV header was printed; the lock also serializes reports.
    csv_header_printed: std::sync::Arc<std::sync::Mutex<bool>>,
}

impl StatsOutput {
    pub fn new(format: OutputFormat) -> Self {
        Self {
            format,
            csv_header_printed: Default::default(),
        }
    }

    /// Prints one snapshot; `interim` selects the JSON type and text prefix.
    pub fn print(&mut self, stats: &StatsSnapshot, interim: bool) {
        let mut header_printed = self
            .csv_header_printed
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        match self.format {
            OutputFormat::Text => stats.print_text(if interim { "[INTERIM] " } else { "" }),
            OutputFormat::Json => stats.print_json(interim),
            OutputFormat::Csv => {
                stats.print_csv(!*header_printed);
                *header_printed = true;
            }
        }
    }
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
    quantiles: Quantiles<u64>,
    min_ns: Option<u64>,
    max_ns: Option<u64>,
    sum_ns: u128,
    variance_origin: Option<u64>,
    centered_mean_ns: f64,
    m2_ns: f64,
    jitter_sum_ns: u128,
    jitter_count: u64,
    last_rtt_ns: Option<u64>,
}

impl RttCollector {
    /// Creates a new empty collector.
    pub fn new() -> Self {
        RttCollector {
            quantiles: Quantiles::default(),
            min_ns: None,
            max_ns: None,
            sum_ns: 0,
            variance_origin: None,
            centered_mean_ns: 0.0,
            m2_ns: 0.0,
            jitter_sum_ns: 0,
            jitter_count: 0,
            last_rtt_ns: None,
        }
    }

    /// Records a new RTT sample. Collection stops at u64::MAX observations.
    pub fn record(&mut self, sample: RttSample) {
        let rtt = sample.rtt_ns;
        if !self.quantiles.record(rtt) {
            return;
        }

        self.min_ns = Some(self.min_ns.map_or(rtt, |m| m.min(rtt)));
        self.max_ns = Some(self.max_ns.map_or(rtt, |m| m.max(rtt)));
        self.sum_ns += rtt as u128;
        // Welford population variance, centered on the first integer sample before
        // conversion to f64. This preserves small spreads on a large baseline.
        let origin = *self.variance_origin.get_or_insert(rtt);
        let centered = (i128::from(rtt) - i128::from(origin)) as f64;
        let delta = centered - self.centered_mean_ns;
        self.centered_mean_ns += delta / self.quantiles.count() as f64;
        self.m2_ns += delta * (centered - self.centered_mean_ns);

        // Mean absolute successive RTT difference, in receive order.
        if let Some(prev) = self.last_rtt_ns {
            let delta = rtt.abs_diff(prev);
            self.jitter_sum_ns += delta as u128;
            self.jitter_count += 1;
        }
        self.last_rtt_ns = Some(rtt);
    }

    /// Returns the p-th percentile RTT in nanoseconds. Exact through 4096
    /// samples, then <0.78125% magnitude error; all observations contribute.
    pub fn percentile_ns(&self, p: f64) -> Option<u64> {
        self.quantiles.percentiles([p])[0]
    }

    /// Returns mean absolute successive RTT difference in nanoseconds.
    pub fn jitter_ns(&self) -> Option<u64> {
        if self.jitter_count == 0 {
            return None;
        }
        Some((self.jitter_sum_ns / self.jitter_count as u128) as u64)
    }

    /// Returns population standard deviation of RTT in nanoseconds.
    pub fn std_dev_ns(&self) -> Option<f64> {
        let n = self.quantiles.count();
        (n >= 2).then(|| (self.m2_ns / n as f64).max(0.0).sqrt())
    }

    /// Builds a snapshot of current statistics.
    pub fn snapshot(&self, packets_sent: u64, packets_lost: u64) -> StatsSnapshot {
        let packets_received = self.quantiles.count();
        let [median, p95, p99] = self.quantiles.percentiles([50.0, 95.0, 99.0]);
        let total = packets_sent.max(1) as f64;

        StatsSnapshot {
            target: None,
            quantile_precision: QuantilePrecision::default(),
            measurements: None,
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
            median_rtt_ms: median.map(ns_to_ms),
            p95_rtt_ms: p95.map(ns_to_ms),
            p99_rtt_ms: p99.map(ns_to_ms),
            jitter_ms: self.jitter_ns().map(ns_to_ms),
            std_dev_ms: self.std_dev_ns().map(|ns| ns / 1_000_000.0),
            owd: None,
            access_report: None,
            congestion: None,
            ber: None,
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

/// Signed one-way delays derived from the four STAMP timestamps.
/// Clock offset adds to one direction and subtracts from the other;
/// negative values are preserved to expose unsynchronized clocks.
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
    quantiles: Quantiles<i64>,
    min_ns: Option<i64>,
    max_ns: Option<i64>,
    sum_ns: i128,
}

impl OwdDirection {
    fn record(&mut self, v: i64) {
        if !self.quantiles.record(v) {
            return;
        }
        self.min_ns = Some(self.min_ns.map_or(v, |m| m.min(v)));
        self.max_ns = Some(self.max_ns.map_or(v, |m| m.max(v)));
        self.sum_ns += i128::from(v);
    }

    fn mean_ns(&self) -> Option<f64> {
        let n = self.quantiles.count();
        (n > 0).then(|| self.sum_ns as f64 / n as f64)
    }

    /// Median uses the same rounded zero-based rank as [`RttCollector::percentile_ns`].
    fn median_ns(&self) -> Option<i64> {
        self.quantiles.percentiles([50.0])[0]
    }
}

/// Collects per-packet one-way-delay samples (both directions) and produces an
/// [`OwdSummary`]. Fed from the sender's response path, where all four STAMP
/// timestamps (T1..T4) are available.
#[derive(Default)]
pub struct OwdCollector {
    quality: ClockQuality,
    forward: OwdDirection,
    reverse: OwdDirection,
}

impl OwdCollector {
    /// Creates a new empty collector.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Records one packet's forward and reverse one-way delays.
    /// Collection stops at u64::MAX observations.
    pub fn record(&mut self, sample: OwdSample) {
        self.record_with_quality(sample, None);
    }

    /// Record delay with locally configured and reflected base Error Estimates.
    pub fn record_with_quality(
        &mut self,
        sample: OwdSample,
        estimates: Option<(
            crate::error_estimate::ErrorEstimate,
            crate::error_estimate::ErrorEstimate,
        )>,
    ) {
        if self.forward.quantiles.count() == u64::MAX {
            return;
        }
        self.quality.record(estimates);
        self.forward.record(sample.forward_ns);
        self.reverse.record(sample.reverse_ns);
    }

    /// Summarises the collected samples, or `None` if none were recorded.
    #[must_use]
    pub fn summary(&self) -> Option<OwdSummary> {
        Some(OwdSummary {
            clock_quality: self.quality.clone(),
            quantile_precision: QuantilePrecision::default(),
            samples: self.forward.quantiles.count(),
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
/// clock offset rather than true path delay. Their sum excludes reflector
/// residence time.
/// `clock_quality` discloses declarations and unknown/invalid estimates.
#[derive(serde::Serialize)]
pub struct OwdSummary {
    pub clock_quality: ClockQuality,
    pub quantile_precision: QuantilePrecision,
    pub samples: u64,
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
    /// Still awaiting acknowledgment when the run ended, for example because
    /// the run reached `--count` or `--duration`, or was interrupted, before
    /// the timer expired or the retry budget was exhausted.
    Pending,
    /// Retransmission retries were exhausted without acknowledgment; the
    /// procedure was aborted per RFC 8972 §4.6 ("...SHOULD be repeated up to
    /// four times before the procedure is aborted"). The measurement itself
    /// is unaffected; this reflects only the Access Report sub-feature.
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
    /// TLV, or reverse-path wire ECN on the reply itself). A reply flagged
    /// by both counts once.
    pub ce_replies: u64,
    /// Number of times a CE observation actually grew the send interval
    /// (excludes CE observations that arrived with the interval already at
    /// the `--ecn-max-delay` cap).
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

/// Full-run quantile policy. Error is relative to the magnitude of the exact
/// order statistic; zero and extrema remain exact. This is value error, not a
/// statistical confidence interval or a bound on timestamp measurement error.
#[derive(Debug, Clone, Copy, serde::Serialize)]
pub struct QuantilePrecision {
    pub exact_sample_limit: usize,
    pub relative_error_bound: f64,
}
impl Default for QuantilePrecision {
    fn default() -> Self {
        Self {
            exact_sample_limit: quantiles::EXACT_LIMIT,
            relative_error_bound: quantiles::RELATIVE_ERROR,
        }
    }
}

/// Serializable sender statistics snapshot.
#[derive(serde::Serialize)]
pub struct StatsSnapshot {
    /// The reflector this report is for, when one sender runs several.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub measurements: Option<MeasurementSummary>,
    /// Quantile accuracy policy for RTT and both OWD directions.
    pub quantile_precision: QuantilePrecision,
    /// Residual BER totals and computation intervals, when requested.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ber: Option<crate::ber::BerSummary>,
    pub packets_sent: u64,
    pub packets_received: u64,
    pub packets_lost: u64,
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
    pub fn with_measurements(mut self, summary: MeasurementSummary) -> Self {
        self.measurements = Some(summary);
        self
    }
    #[must_use]
    pub fn with_ber(mut self, summary: Option<crate::ber::BerSummary>) -> Self {
        self.ber = summary;
        self
    }

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

    pub fn with_target(mut self, target: Option<String>) -> Self {
        self.target = target;
        self
    }

    /// Prints a standalone final summary in the given format, including a CSV header.
    /// Use [`StatsOutput`] to combine interim and final reports in one stream.
    pub fn print(&self, format: OutputFormat) {
        match format {
            OutputFormat::Text => self.print_text(""),
            OutputFormat::Json => self.print_json(false),
            OutputFormat::Csv => self.print_csv(true),
        }
    }

    fn print_text(&self, prefix: &str) {
        println!("\n{}--- STAMP Statistics ---", prefix);
        if let Some(target) = &self.target {
            println!("{prefix}Target: {target}");
        }
        println!("{}Packets sent: {}", prefix, self.packets_sent);
        println!("{}Packets received: {}", prefix, self.packets_received);
        println!(
            "{}Packets lost: {} ({:.1}%)",
            prefix, self.packets_lost, self.loss_percent
        );
        println!(
            "{}Quantiles: exact through {} samples per series; otherwise <{:.5}% magnitude error",
            prefix,
            self.quantile_precision.exact_sample_limit,
            self.quantile_precision.relative_error_bound * 100.0,
        );
        if let Some(m) = &self.measurements {
            println!("{prefix}Replies: {} unique, {} additional, {} late, {} duplicates, {} reordered, {} unknown",
                m.unique_replies, m.additional_replies, m.late_replies, m.duplicate_replies, m.reordered_replies, m.unknown_replies);
            println!("{prefix}Requested replies unobserved: {} (includes policy caps); history evictions: {} probes, {} replies",
                m.unobserved_requested_replies, m.probes_evicted, m.replies_evicted);
            println!(
                "{prefix}Reply RTT: {} samples, avg {}",
                m.reply_rtt.samples,
                fmt_ms_text(m.reply_rtt.avg_ms)
            );
            println!("{prefix}Direct Measurement window: forward missing {}, reverse missing {}; unavailable {}, discontinuities {}",
                m.direct_measurement.forward_missing.map_or_else(|| "unavailable".into(), |n| n.to_string()), m.direct_measurement.reverse_missing.map_or_else(|| "unavailable".into(), |n| n.to_string()), m.direct_measurement.unavailable, m.direct_measurement.discontinuities);
            println!("{prefix}Follow-Up: {} matched, {} repeated, {} unmatched, {} ambiguous, {} unavailable; reverse delay avg {}",
                m.follow_up.matched, m.follow_up.repeated, m.follow_up.unmatched, m.follow_up.ambiguous, m.follow_up.unavailable, fmt_ms_text(m.follow_up.reverse_delay.avg_ms));
        }
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
            println!("{prefix}OWD clock declarations: {} both synchronized, {} unsynchronized, {} invalid, {} unknown; max advertised combined error {} ms (not verified accuracy)",
                owd.clock_quality.both_synchronized, owd.clock_quality.unsynchronized,
                owd.clock_quality.invalid_estimate, owd.clock_quality.unknown,
                fmt_opt(owd.clock_quality.max_combined_error_ms));
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
        if let Some(ber) = &self.ber {
            println!(
                "{prefix}BER: interval={}ms padding={} bytes disabled_by_peer={}",
                ber.interval_ms, ber.padding_bytes, ber.disabled_by_peer
            );
            if ber.intervals_omitted != 0 || ber.alarms_omitted != 0 {
                println!(
                    "{prefix}  Older BER history omitted: intervals={} alarms={}",
                    ber.intervals_omitted, ber.alarms_omitted
                );
            }
            for (name, stats) in [("Forward", &ber.forward), ("Reverse", &ber.reverse)] {
                println!("{prefix}  {name}: packets={} errored={} bits={} errors={} BER={} burst max={} avg={}",
                    stats.packets_received, stats.packets_with_errors, stats.padding_bits, stats.bit_errors,
                    stats.bit_error_ratio.map_or_else(|| "n/a".into(), |v| format!("{v:.6e}")),
                    stats.max_burst_bits.map_or_else(|| "n/a".into(), |v| v.to_string()),
                    fmt_opt(stats.average_max_burst_bits));
            }
            for interval in &ber.intervals {
                println!(
                    "{prefix}  BER interval: {}",
                    serde_json::to_string(interval).unwrap_or_default()
                );
            }
            for alarm in &ber.alarms {
                println!(
                    "{prefix}  BER alarm: {}",
                    serde_json::to_string(alarm).unwrap_or_default()
                );
            }
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

    fn print_csv(&self, header: bool) {
        // Optional header + data row. OWD, Access Report, and Congestion columns
        // are always present but left empty when no samples were
        // collected / the feature was not enabled.
        // The target column appears only when one sender runs several.
        let target = self.target.as_deref().map(|t| format!("{t},"));
        if header {
            println!(
                "{}packets_sent,packets_received,packets_lost,loss_percent,\
             min_rtt_ms,max_rtt_ms,avg_rtt_ms,median_rtt_ms,\
             p95_rtt_ms,p99_rtt_ms,jitter_ms,std_dev_ms,\
             owd_fwd_min_ms,owd_fwd_avg_ms,owd_fwd_max_ms,\
             owd_rev_min_ms,owd_rev_avg_ms,owd_rev_max_ms,\
             access_report_outcome,access_report_retransmissions,\
             congestion_ce_replies,congestion_backoffs_applied,\
             congestion_current_interval_ms,congestion_max_interval_reached_ms,quantile_exact_sample_limit,quantile_relative_error_bound,ber,measurements,owd_clock_quality",
                if target.is_some() { "target," } else { "" }
            );
        }
        println!(
            "{}{},{},{},{:.2},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{}",
            target.unwrap_or_default(),
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
            self.quantile_precision.exact_sample_limit,
            self.quantile_precision.relative_error_bound,
            self.ber.as_ref().map_or_else(String::new, |ber| format!(
                "\"{}\"",
                serde_json::to_string(ber)
                    .unwrap_or_default()
                    .replace('"', "\"\"")
            )),
            self.measurements.as_ref().map_or_else(String::new, |m| format!("\"{}\"", serde_json::to_string(m).unwrap_or_default().replace('"', "\"\""))),
            self.owd.as_ref().map_or_else(String::new, |o| format!("\"{}\"", serde_json::to_string(&o.clock_quality).unwrap_or_default().replace('"', "\"\""))),
        );
    }
}

fn fmt_opt(v: Option<f64>) -> String {
    v.map_or_else(String::new, |x| format!("{:.3}", x))
}

/// Text-report form of an optional millisecond value.
fn fmt_ms_text(v: Option<f64>) -> String {
    v.map_or_else(|| "n/a".to_string(), |x| format!("{x:.3} ms"))
}

/// Per-client session statistics for reflector reporting.
#[derive(serde::Serialize)]
pub struct ClientSessionStats {
    pub client: String,
    pub local: String,
    pub ssid: u16,
    pub sender_micro_session_id: Option<u16>,
    pub packets_received: u32,
    pub packets_transmitted: u32,
}

/// Serializable reflector statistics summary.
#[derive(serde::Serialize)]
pub struct ReflectorStats {
    pub total_packets_received: u64,
    pub total_packets_reflected: u64,
    pub total_packets_dropped: u64,
    pub reply_queue_rejected: u64,
    pub queued_replies_cancelled: u64,
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
        println!("Reply queue rejections: {}", self.reply_queue_rejected);
        println!(
            "Queued replies cancelled: {}",
            self.queued_replies_cancelled
        );
        println!("Active sessions: {}", self.active_sessions);
        if !self.sessions.is_empty() {
            println!("Sessions:");
            for s in &self.sessions {
                println!(
                    "  {} -> {} SSID={} micro={:?} - rx: {}, tx: {}",
                    s.client,
                    s.local,
                    s.ssid,
                    s.sender_micro_session_id,
                    s.packets_received,
                    s.packets_transmitted
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
        println!("total_received,total_reflected,total_dropped,active_sessions,uptime_seconds,reply_queue_rejected,queued_replies_cancelled");
        println!(
            "{},{},{},{},{:.1},{},{}",
            self.total_packets_received,
            self.total_packets_reflected,
            self.total_packets_dropped,
            self.active_sessions,
            self.uptime_seconds,
            self.reply_queue_rejected,
            self.queued_replies_cancelled,
        );
    }
}

/// Builds a ReflectorStats from counters and session manager state.
pub(crate) fn build_reflector_stats(
    packets_received: u64,
    packets_reflected: u64,
    packets_dropped: u64,
    session_summaries: Vec<(crate::session::SessionKey, u32, u32)>,
    active_sessions: usize,
    uptime_seconds: f64,
) -> ReflectorStats {
    let sessions = session_summaries
        .into_iter()
        .map(|(addr, rx, tx)| ClientSessionStats {
            client: addr.client.to_string(),
            local: addr.local.to_string(),
            ssid: addr.ssid,
            sender_micro_session_id: addr.sender_micro_session_id,
            packets_received: rx,
            packets_transmitted: tx,
        })
        .collect();
    ReflectorStats {
        total_packets_received: packets_received,
        total_packets_reflected: packets_reflected,
        total_packets_dropped: packets_dropped,
        reply_queue_rejected: 0,
        queued_replies_cancelled: 0,
        active_sessions,
        uptime_seconds,
        sessions,
    }
}

#[cfg(test)]
mod tests;
