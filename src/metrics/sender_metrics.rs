//! Metrics for STAMP sender (Session-Sender) mode.
//!
//! Provides Prometheus metrics for monitoring sender operations including
//! packet transmission, reception, loss, and RTT measurements.

use std::sync::OnceLock;

use metrics::{counter, histogram, Counter, Histogram};

// Per-probe handles are looked up once; see `reflector_metrics`.
static SENT: OnceLock<Counter> = OnceLock::new();
static RECEIVED: OnceLock<Counter> = OnceLock::new();
static RTT: OnceLock<Histogram> = OnceLock::new();

/// Records that a packet was sent.
pub(crate) fn record_packet_sent() {
    SENT.get_or_init(|| counter!("stamp_sender_packets_sent_total"))
        .increment(1);
}

/// Records that a response packet was received.
pub(crate) fn record_packet_received() {
    RECEIVED
        .get_or_init(|| counter!("stamp_sender_packets_received_total"))
        .increment(1);
}

/// Records that multiple packets were lost (batch variant).
pub(crate) fn record_packets_lost(count: u64) {
    counter!("stamp_sender_packets_lost_total").increment(count);
}

/// Records an RTT observation in seconds.
pub(crate) fn record_rtt(rtt_seconds: f64) {
    RTT.get_or_init(|| histogram!("stamp_sender_rtt_seconds"))
        .record(rtt_seconds);
}

/// Records an HMAC verification failure.
pub(crate) fn record_hmac_failure() {
    counter!("stamp_sender_hmac_failures_total").increment(1);
}

/// Records TLV error flags by type: "U" (unrecognized), "M" (malformed) or
/// "I" (integrity).
pub(crate) fn record_tlv_error(flag: &'static str) {
    counter!("stamp_sender_tlv_errors_total", "flag" => flag).increment(1);
}

/// Records the U, M and I flag counts of one packet's TLVs.
pub(crate) fn record_tlv_errors(unrecognized: usize, malformed: usize, integrity: usize) {
    for (flag, count) in [("U", unrecognized), ("M", malformed), ("I", integrity)] {
        if count > 0 {
            counter!("stamp_sender_tlv_errors_total", "flag" => flag).increment(count as u64);
        }
    }
}

/// Records sender events as Prometheus metrics.
pub struct PrometheusSenderObserver;

impl crate::sender::SenderObserver for PrometheusSenderObserver {
    fn probe_sent(&self) {
        record_packet_sent();
    }
    fn reply_received(&self, rtt_ns: u64) {
        record_packet_received();
        record_rtt(rtt_ns as f64 / 1e9);
    }
    fn probes_lost(&self, count: u32) {
        record_packets_lost(u64::from(count));
    }
    fn hmac_failed(&self) {
        record_hmac_failure();
    }
    fn reply_rejected(&self) {
        record_tlv_error("M");
    }
    fn tlv_flags(&self, unrecognized: usize, malformed: usize, integrity_failed: usize) {
        record_tlv_errors(unrecognized, malformed, integrity_failed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_metrics_functions_callable() {
        // These tests just verify the functions are callable without panicking.
        // Actual metric recording requires a recorder to be installed.
        record_packet_sent();
        record_packet_received();
        record_packets_lost(5);
        record_rtt(0.001);
        record_hmac_failure();
        record_tlv_error("U");
        record_tlv_error("M");
        record_tlv_error("I");
    }
}
