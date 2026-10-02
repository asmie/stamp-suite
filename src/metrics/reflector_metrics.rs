//! Metrics for STAMP reflector (Session-Reflector) mode.
//!
//! Provides Prometheus metrics for monitoring reflector operations including
//! packet reception, reflection, drops, session management, and processing time.

use metrics::{counter, gauge, histogram};

/// Records that a packet was received by the reflector.
pub fn record_packet_received() {
    counter!("stamp_reflector_packets_received_total").increment(1);
}

/// Records that a packet was successfully reflected.
pub fn record_packet_reflected() {
    counter!("stamp_reflector_packets_reflected_total").increment(1);
}

/// Records that a packet was dropped with the specified reason.
///
/// # Arguments
/// * `reason` - The reason for dropping: "parse_error", "hmac_failure", "short_packet", etc.
pub fn record_packet_dropped(reason: &'static str) {
    counter!("stamp_reflector_packets_dropped_total", "reason" => reason).increment(1);
}

/// Sets the current number of active sessions.
pub fn set_active_sessions(count: usize) {
    gauge!("stamp_reflector_active_sessions").set(count as f64);
}

/// Records that a new session was created.
pub fn record_session_created() {
    counter!("stamp_reflector_sessions_total").increment(1);
}

/// Records an HMAC verification failure.
pub fn record_hmac_failure() {
    counter!("stamp_reflector_hmac_failures_total").increment(1);
}

/// Records the time spent processing a packet in seconds.
pub fn record_processing_time(seconds: f64) {
    histogram!("stamp_reflector_processing_seconds").record(seconds);
}

/// Records TLV error flags by type: "U" (unrecognized), "M" (malformed) or
/// "I" (integrity).
pub fn record_tlv_error(flag: &'static str) {
    counter!("stamp_reflector_tlv_errors_total", "flag" => flag).increment(1);
}

/// Records the U, M and I flag counts of one packet's TLVs.
pub fn record_tlv_errors(unrecognized: usize, malformed: usize, integrity: usize) {
    for (flag, count) in [("U", unrecognized), ("M", malformed), ("I", integrity)] {
        if count > 0 {
            counter!("stamp_reflector_tlv_errors_total", "flag" => flag).increment(count as u64);
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
        record_packet_received();
        record_packet_reflected();
        record_packet_dropped("parse_error");
        record_packet_dropped("hmac_failure");
        set_active_sessions(5);
        record_session_created();
        record_hmac_failure();
        record_processing_time(0.001);
        record_tlv_error("U");
        record_tlv_error("M");
        record_tlv_error("I");
    }
}
