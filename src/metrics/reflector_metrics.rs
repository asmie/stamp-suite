//! Metrics for STAMP reflector (Session-Reflector) mode.
//!
//! Packet processing, session and timing counters exported through Prometheus.

use std::sync::OnceLock;

use metrics::{counter, gauge, histogram, Counter, Histogram};

// Per-packet handles are looked up once. `metrics::init` installs the
// recorder before the reflector starts, so the first call already sees it.
static RECEIVED: OnceLock<Counter> = OnceLock::new();
static REFLECTED: OnceLock<Counter> = OnceLock::new();
static PROCESSING: OnceLock<Histogram> = OnceLock::new();

/// Records that a packet was received by the reflector.
pub(crate) fn record_packet_received() {
    RECEIVED
        .get_or_init(|| counter!("stamp_reflector_packets_received_total"))
        .increment(1);
}

/// Records one successfully transmitted response, including each burst copy.
pub(crate) fn record_packet_reflected() {
    REFLECTED
        .get_or_init(|| counter!("stamp_reflector_packets_reflected_total"))
        .increment(1);
}

/// Records that a packet was dropped with the specified reason.
///
/// `reason` labels the rejection boundary: rate_limited, queue_full,
/// processing_rejected, session_expired, suppressed, send_failed or cancelled.
pub(crate) fn record_packet_dropped(reason: &'static str) {
    counter!("stamp_reflector_packets_dropped_total", "reason" => reason).increment(1);
}

/// Sets the current number of active sessions.
pub(crate) fn set_active_sessions(count: usize) {
    gauge!("stamp_reflector_active_sessions").set(count as f64);
}

/// Records that a new session was created.
pub(crate) fn record_session_created() {
    counter!("stamp_reflector_sessions_total").increment(1);
}

/// Records an HMAC verification failure.
pub(crate) fn record_hmac_failure() {
    counter!("stamp_reflector_hmac_failures_total").increment(1);
}

/// Records the time spent processing a packet in seconds.
pub(crate) fn record_processing_time(seconds: f64) {
    PROCESSING
        .get_or_init(|| histogram!("stamp_reflector_processing_seconds"))
        .record(seconds);
}

/// Records the U, M and I flag counts of one packet's TLVs.
pub(crate) fn record_tlv_errors(unrecognized: usize, malformed: usize, integrity: usize) {
    for (flag, count) in [("U", unrecognized), ("M", malformed), ("I", integrity)] {
        if count > 0 {
            counter!("stamp_reflector_tlv_errors_total", "flag" => flag).increment(count as u64);
        }
    }
}
