//! Metrics for STAMP sender (Session-Sender) mode.
//!
//! Provides Prometheus metrics for monitoring sender operations including
//! packet transmission, reception, loss, and RTT measurements.

use metrics::{counter, gauge, histogram};

/// Records that a packet was sent.
pub fn record_packet_sent() {
    counter!("stamp_sender_packets_sent_total").increment(1);
}

/// Records that a response packet was received.
pub fn record_packet_received() {
    counter!("stamp_sender_packets_received_total").increment(1);
}

/// Records that multiple packets were lost (batch variant).
pub fn record_packets_lost(count: u64) {
    counter!("stamp_sender_packets_lost_total").increment(count);
}

/// Records an RTT observation in seconds.
pub fn record_rtt(rtt_seconds: f64) {
    histogram!("stamp_sender_rtt_seconds").record(rtt_seconds);
}

/// Updates the minimum RTT gauge in seconds.
pub fn set_rtt_min(rtt_seconds: f64) {
    gauge!("stamp_sender_rtt_min_seconds").set(rtt_seconds);
}

/// Updates the maximum RTT gauge in seconds.
pub fn set_rtt_max(rtt_seconds: f64) {
    gauge!("stamp_sender_rtt_max_seconds").set(rtt_seconds);
}

/// Records an HMAC verification failure.
pub fn record_hmac_failure() {
    counter!("stamp_sender_hmac_failures_total").increment(1);
}

/// Records TLV error flags by type: "U" (unrecognized), "M" (malformed) or
/// "I" (integrity).
pub fn record_tlv_error(flag: &'static str) {
    counter!("stamp_sender_tlv_errors_total", "flag" => flag).increment(1);
}

/// Records the U, M and I flag counts of one packet's TLVs.
pub fn record_tlv_errors(unrecognized: usize, malformed: usize, integrity: usize) {
    for (flag, count) in [("U", unrecognized), ("M", malformed), ("I", integrity)] {
        if count > 0 {
            counter!("stamp_sender_tlv_errors_total", "flag" => flag).increment(count as u64);
        }
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
        set_rtt_min(0.0005);
        set_rtt_max(0.002);
        record_hmac_failure();
        record_tlv_error("U");
        record_tlv_error("M");
        record_tlv_error("I");
    }
}
