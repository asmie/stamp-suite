//! Sender congestion state driven by CE-marked replies
//! (draft-ietf-ippm-stamp-cos-ecn-01 §3.4).

use super::*;

/// CE-driven congestion state (draft-ietf-ippm-stamp-cos-ecn-01 §3.4).
/// Active with `--cos` and ECT0/ECT1. The send loop separately tracks
/// `scale_reflected_control` because TLV construction needs it before this state.
pub(super) struct CongestionState {
    pub(super) controller: AimdController,
}

impl CongestionState {
    pub(super) fn new(params: AimdParams) -> Self {
        Self {
            controller: AimdController::new(params),
        }
    }

    /// Builds the [`CongestionSummary`] for [`StatsSnapshot::with_congestion`].
    pub(super) fn summary(&self) -> CongestionSummary {
        let AimdStats {
            ce_observations,
            backoffs_applied,
            current_interval,
            peak_interval,
            base_interval,
        } = self.controller.stats();
        CongestionSummary {
            ce_replies: ce_observations,
            backoffs_applied,
            current_interval_ms: current_interval.as_secs_f64() * 1000.0,
            max_interval_reached_ms: peak_interval.as_secs_f64() * 1000.0,
            base_interval_ms: base_interval.as_secs_f64() * 1000.0,
        }
    }
}
