//! Declared timestamp quality; no clock service or PHC synchronization is verified.
use crate::{clock_format::ClockFormat, error_estimate::ErrorEstimate};

#[derive(Clone, Copy, Debug, serde::Serialize)]
pub struct ClockEstimate {
    pub synchronized: bool,
    pub format: ClockFormat,
    pub scale: u8,
    pub multiplier: u8,
    /// RFC 4656 §4.1.2: zero Multiplier is invalid, not zero error.
    pub error_ms: Option<f64>,
}
impl From<ErrorEstimate> for ClockEstimate {
    fn from(e: ErrorEstimate) -> Self {
        Self {
            synchronized: e.synchronized,
            format: e.clock_format(),
            scale: e.scale,
            multiplier: e.multiplier,
            error_ms: (e.multiplier != 0 && e.scale <= 63)
                .then(|| f64::from(e.multiplier) * 2f64.powi(i32::from(e.scale) - 32) * 1000.0),
        }
    }
}

/// Metadata for exactly the delay samples in the associated summary.
/// S bits are endpoint assertions, not proof of synchronized clocks.
#[derive(Clone, Debug, Default, serde::Serialize)]
pub struct ClockQuality {
    pub samples: u64,
    pub both_synchronized: u64,
    pub unsynchronized: u64,
    pub invalid_estimate: u64,
    pub unknown: u64,
    pub last_sender: Option<ClockEstimate>,
    pub last_reflector: Option<ClockEstimate>,
    /// Maximum sum of two usable advertised estimates. Not measured accuracy.
    pub max_combined_error_ms: Option<f64>,
}
impl ClockQuality {
    pub(crate) fn record(&mut self, estimates: Option<(ErrorEstimate, ErrorEstimate)>) {
        self.samples += 1;
        let Some((sender, reflector)) = estimates else {
            self.unknown += 1;
            self.last_sender = None;
            self.last_reflector = None;
            return;
        };
        let sender = ClockEstimate::from(sender);
        let reflector = ClockEstimate::from(reflector);
        self.last_sender = Some(sender);
        self.last_reflector = Some(reflector);
        if let (Some(s), Some(r)) = (sender.error_ms, reflector.error_ms) {
            self.max_combined_error_ms =
                Some(self.max_combined_error_ms.map_or(s + r, |m| m.max(s + r)));
            if sender.synchronized && reflector.synchronized {
                self.both_synchronized += 1;
            } else {
                self.unsynchronized += 1;
            }
        } else {
            self.invalid_estimate += 1;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn estimate(s: bool, ptp: bool, scale: u8, multiplier: u8) -> ErrorEstimate {
        ErrorEstimate::new(s, ptp, scale, multiplier).unwrap()
    }
    #[test]
    fn quality_distinguishes_asserted_unsynchronized_invalid_and_unknown() {
        let mut q = ClockQuality::default();
        q.record(Some((
            estimate(true, false, 32, 1),
            estimate(true, true, 31, 2),
        )));
        assert_eq!(q.max_combined_error_ms, Some(2000.0));
        assert_eq!(q.last_reflector.unwrap().format, ClockFormat::PTP);
        q.record(Some((
            estimate(false, false, 0, 1),
            estimate(true, false, 0, 1),
        )));
        q.record(Some((
            estimate(true, false, 0, 0),
            estimate(true, false, 0, 1),
        )));
        assert_eq!(q.last_sender.unwrap().error_ms, None);
        q.record(None);
        assert_eq!(
            (
                q.samples,
                q.both_synchronized,
                q.unsynchronized,
                q.invalid_estimate,
                q.unknown
            ),
            (4, 1, 1, 1, 1)
        );
        assert!(q.last_sender.is_none());
        assert_eq!(q.max_combined_error_ms, Some(2000.0));
    }
    #[test]
    fn estimate_extremes_are_finite_and_independent_of_format() {
        for scale in [0, 63] {
            let a = ClockEstimate::from(estimate(true, false, scale, 255));
            let b = ClockEstimate::from(estimate(false, true, scale, 255));
            assert_eq!(a.error_ms, b.error_ms);
            assert!(a.error_ms.unwrap().is_finite());
        }
    }
}
