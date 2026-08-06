//! AIMD congestion-response controller for the Session-Sender, per
//! draft-ietf-ippm-stamp-cos-ecn-01 §3.4 ("Congestion Response").
//!
//! §3.4 requires the Session-Sender to reduce its sending rate when it
//! observes a CE (Congestion Experienced) codepoint reflected back to it —
//! either in the CoS TLV's EC2 field (forward-path congestion, sender to
//! reflector) or in the IP header of the reply packet itself (reverse-path
//! congestion, reflector to sender). This module implements the *response*
//! half of that requirement: a pure, deterministic AIMD (Additive Increase
//! / Multiplicative Decrease, expressed here in delay-space rather than
//! window-space — see `AimdController`) state machine that turns a stream
//! of "CE observed" / "clean reply" events into an inter-packet send
//! interval.
//!
//! Deliberately free of sockets, timers, and wall-clock sleeps: the
//! Session-Sender's existing send loop (`sender::run_sender`) drives it by
//! calling `AimdController::on_ce_observed` or
//! `AimdController::on_clean_reply` once per processed reply, and reads
//! back `AimdController::current_interval` to decide how long to wait
//! before the next send. This is what makes the controller's AIMD sequence
//! properties unit-testable without any real waiting.

use std::time::Duration;

/// Floor used when backing off from a zero (or otherwise degenerate)
/// current interval — e.g. `--send-delay 0` ("send as fast as possible").
/// Multiplying zero by any finite factor stays zero, which would make a CE
/// observation a permanent no-op; bumping to this floor first guarantees a
/// CE always has a real, growing effect once it is observed.
const MIN_BACKOFF_FLOOR: Duration = Duration::from_millis(1);

/// Configuration for an `AimdController`, derived 1:1 from the
/// `--send-delay`, `--ecn-backoff-factor`, `--ecn-max-delay`, and
/// `--ecn-recovery-step` CLI flags.
///
/// Range validation (`backoff_factor > 1.0`, `recovery_step > 0`,
/// `max_interval >= base_interval`) is the caller's responsibility
/// (`configuration::Configuration::validate`) — this struct is plain data
/// so the controller itself stays trivially constructible in tests.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct AimdParams {
    /// The operator-configured steady-state send interval (`--send-delay`).
    /// The controller never recovers past this — it is the floor for
    /// `AimdController::on_clean_reply` and the starting point on
    /// construction.
    pub base_interval: Duration,
    /// Multiplicative factor applied to the current interval on each CE
    /// observation (`--ecn-backoff-factor`). Must be `> 1.0` for a CE to
    /// have any effect; the controller does not enforce this itself.
    pub backoff_factor: f64,
    /// Upper bound on the interval a backoff can reach (`--ecn-max-delay`).
    pub max_interval: Duration,
    /// Additive amount subtracted from the current interval after each
    /// clean (non-CE) reply, on the way back down to `base_interval`
    /// (`--ecn-recovery-step`).
    pub recovery_step: Duration,
}

/// Point-in-time observability snapshot of an `AimdController`, surfaced
/// in the sender's stats output (`stats::CongestionSummary`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AimdStats {
    /// Number of times `AimdController::on_ce_observed` was called
    /// (i.e. CE-marked replies seen, counting both forward- and
    /// reverse-path detections — a reply flagged in both directions at
    /// once still counts once, since only one backoff step is applied per
    /// reply).
    pub ce_observations: u64,
    /// Number of times a CE observation actually grew the interval (i.e.
    /// excludes CE observations that arrived while already saturated at
    /// `max_interval`).
    pub backoffs_applied: u64,
    /// Current controlled interval.
    pub current_interval: Duration,
    /// Highest interval reached at any point during the run.
    pub peak_interval: Duration,
    /// The configured base interval, for reference (`--send-delay`).
    pub base_interval: Duration,
}

/// AIMD (in delay-space) congestion-response controller.
///
/// "Multiplicative decrease" here means the *rate* decreases
/// multiplicatively on congestion — expressed as the *interval* growing
/// multiplicatively (`current *= backoff_factor`, capped at
/// `max_interval`). "Additive increase" mirrors it: the rate recovers
/// gently, expressed as the interval shrinking by a fixed step per clean
/// reply, floored at `base_interval` — the sender never goes faster than
/// what the operator configured, even during recovery.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct AimdController {
    params: AimdParams,
    current: Duration,
    ce_observations: u64,
    backoffs_applied: u64,
    peak_interval: Duration,
}

impl AimdController {
    /// Creates a new controller starting at `params.base_interval`.
    #[must_use]
    pub fn new(params: AimdParams) -> Self {
        Self {
            current: params.base_interval,
            peak_interval: params.base_interval,
            params,
            ce_observations: 0,
            backoffs_applied: 0,
        }
    }

    /// The interval the sender should currently wait between packets.
    #[must_use]
    pub fn current_interval(&self) -> Duration {
        self.current
    }

    /// Ratio of the current interval to the configured base interval — 1.0
    /// at rest, growing under backoff. Used to scale other interval-like
    /// parameters that should track the same congestion signal (e.g. the
    /// Reflected Test Packet Control TLV's inter-packet gap, §3.4-3).
    ///
    /// When `base_interval` is zero (`--send-delay 0`), the ratio is taken
    /// against [`MIN_BACKOFF_FLOOR`] instead, so the scale factor stays a
    /// finite, meaningful multiplier rather than dividing by zero. In that
    /// configuration the current interval also rests at zero, so the ratio
    /// is floored at 1.0 — the documented at-rest value — rather than
    /// reporting 0 and zeroing every scaled parameter (e.g. the Type 12
    /// inter-packet interval, which reflectors check against their minimum).
    #[must_use]
    pub fn scale_factor(&self) -> f64 {
        let base = self.params.base_interval;
        let base_secs = if base.is_zero() {
            MIN_BACKOFF_FLOOR.as_secs_f64()
        } else {
            base.as_secs_f64()
        };
        (self.current.as_secs_f64() / base_secs).max(1.0)
    }

    /// Records a CE-marked reply: multiplicatively grows the interval
    /// (capped at `params.max_interval`), per draft-ietf-ippm-stamp-cos-ecn-01
    /// §3.4 ("...it MUST observe the reflected EC2 field and reduce its
    /// sending rate upon observation of a CE value").
    pub fn on_ce_observed(&mut self) {
        self.ce_observations += 1;
        // A zero (or otherwise tiny) current interval can't be grown by a
        // finite multiplicative factor in any observable way; bump to a
        // floor first so backoff from "as fast as possible" is real.
        let floor = if self.current.is_zero() {
            MIN_BACKOFF_FLOOR
        } else {
            self.current
        };
        // Multiply in f64 and saturate at max_interval BEFORE constructing a
        // Duration: `Duration::mul_f64` panics on overflow, so an extreme
        // (but validated-finite) --ecn-backoff-factor must cap here rather
        // than let the first CE-marked reply terminate the sender.
        let max = self.params.max_interval;
        let scaled = floor.as_secs_f64() * self.params.backoff_factor;
        let next = if scaled.is_finite() && scaled < max.as_secs_f64() {
            Duration::from_secs_f64(scaled)
        } else {
            max
        };
        if next > self.current {
            self.current = next;
            self.backoffs_applied += 1;
            if self.current > self.peak_interval {
                self.peak_interval = self.current;
            }
        }
    }

    /// Records a reply that was NOT CE-marked: additively shrinks the
    /// interval by `params.recovery_step`, floored at `params.base_interval`
    /// — recovery never overshoots past the operator-configured rate.
    pub fn on_clean_reply(&mut self) {
        if self.current <= self.params.base_interval {
            self.current = self.params.base_interval;
            return;
        }
        let next = self.current.saturating_sub(self.params.recovery_step);
        self.current = next.max(self.params.base_interval);
    }

    /// Observability snapshot for [`crate::stats::CongestionSummary`].
    #[must_use]
    pub fn stats(&self) -> AimdStats {
        AimdStats {
            ce_observations: self.ce_observations,
            backoffs_applied: self.backoffs_applied,
            current_interval: self.current,
            peak_interval: self.peak_interval,
            base_interval: self.params.base_interval,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn params() -> AimdParams {
        AimdParams {
            base_interval: Duration::from_millis(100),
            backoff_factor: 2.0,
            max_interval: Duration::from_millis(1600),
            recovery_step: Duration::from_millis(20),
        }
    }

    #[test]
    fn new_controller_starts_at_base_interval() {
        let c = AimdController::new(params());
        assert_eq!(c.current_interval(), Duration::from_millis(100));
        assert_eq!(c.stats().current_interval, Duration::from_millis(100));
        assert_eq!(c.stats().peak_interval, Duration::from_millis(100));
        assert_eq!(c.stats().ce_observations, 0);
        assert_eq!(c.stats().backoffs_applied, 0);
    }

    #[test]
    fn single_ce_doubles_interval() {
        let mut c = AimdController::new(params());
        c.on_ce_observed();
        assert_eq!(c.current_interval(), Duration::from_millis(200));
        assert_eq!(c.stats().ce_observations, 1);
        assert_eq!(c.stats().backoffs_applied, 1);
    }

    #[test]
    fn repeated_ce_doubles_each_time_until_cap() {
        let mut c = AimdController::new(params());
        let expected_ms = [200u64, 400, 800, 1600, 1600, 1600];
        for expected in expected_ms {
            c.on_ce_observed();
            assert_eq!(c.current_interval(), Duration::from_millis(expected));
        }
        // Backoff only counted while it actually grew the interval: the
        // first four calls (200,400,800,1600) grew it, the last two
        // (already at the 1600ms cap) did not.
        assert_eq!(c.stats().backoffs_applied, 4);
        assert_eq!(c.stats().ce_observations, 6);
    }

    #[test]
    fn backoff_never_exceeds_configured_max_interval() {
        let mut c = AimdController::new(params());
        for _ in 0..50 {
            c.on_ce_observed();
        }
        assert_eq!(c.current_interval(), Duration::from_millis(1600));
        assert_eq!(c.stats().current_interval, Duration::from_millis(1600));
    }

    #[test]
    fn peak_interval_tracks_the_highest_value_even_after_recovery() {
        let mut c = AimdController::new(params());
        c.on_ce_observed(); // 200ms
        c.on_ce_observed(); // 400ms
        for _ in 0..20 {
            c.on_clean_reply();
        }
        assert_eq!(c.current_interval(), Duration::from_millis(100));
        assert_eq!(c.stats().peak_interval, Duration::from_millis(400));
    }

    #[test]
    fn clean_reply_recovers_additively_toward_base() {
        let mut c = AimdController::new(params());
        c.on_ce_observed(); // -> 200ms
        c.on_clean_reply(); // -> 180ms
        assert_eq!(c.current_interval(), Duration::from_millis(180));
        c.on_clean_reply(); // -> 160ms
        assert_eq!(c.current_interval(), Duration::from_millis(160));
    }

    #[test]
    fn clean_reply_recovery_does_not_overshoot_below_base() {
        let mut c = AimdController::new(params());
        c.on_ce_observed(); // -> 200ms
                            // Recovery step is 20ms; five clean replies would reach exactly
                            // 100ms, a sixth must clamp rather than go to 80ms.
        for _ in 0..6 {
            c.on_clean_reply();
        }
        assert_eq!(c.current_interval(), Duration::from_millis(100));
    }

    #[test]
    fn clean_reply_at_base_is_a_no_op() {
        let mut c = AimdController::new(params());
        c.on_clean_reply();
        c.on_clean_reply();
        assert_eq!(c.current_interval(), Duration::from_millis(100));
    }

    #[test]
    fn full_backoff_then_full_recovery_returns_exactly_to_base() {
        let mut c = AimdController::new(params());
        for _ in 0..10 {
            c.on_ce_observed();
        }
        assert_eq!(c.current_interval(), Duration::from_millis(1600));
        // (1600 - 100) / 20 = 75 clean replies to fully recover.
        for _ in 0..75 {
            c.on_clean_reply();
        }
        assert_eq!(c.current_interval(), Duration::from_millis(100));
    }

    #[test]
    fn zero_base_interval_backoff_starts_from_floor() {
        let zero_base = AimdParams {
            base_interval: Duration::ZERO,
            backoff_factor: 2.0,
            max_interval: Duration::from_millis(100),
            recovery_step: Duration::from_millis(1),
        };
        let mut c = AimdController::new(zero_base);
        assert_eq!(c.current_interval(), Duration::ZERO);
        c.on_ce_observed();
        // Bumped to the 1ms floor, then doubled: 1ms * 2.0 = 2ms.
        assert_eq!(c.current_interval(), Duration::from_millis(2));
        assert_eq!(c.stats().backoffs_applied, 1);
    }

    #[test]
    fn zero_base_interval_recovers_back_to_zero() {
        let zero_base = AimdParams {
            base_interval: Duration::ZERO,
            backoff_factor: 2.0,
            max_interval: Duration::from_millis(100),
            recovery_step: Duration::from_millis(1),
        };
        let mut c = AimdController::new(zero_base);
        c.on_ce_observed();
        for _ in 0..10 {
            c.on_clean_reply();
        }
        assert_eq!(c.current_interval(), Duration::ZERO);
    }

    #[test]
    fn scale_factor_is_one_at_rest() {
        let c = AimdController::new(params());
        assert!((c.scale_factor() - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn scale_factor_doubles_with_one_backoff() {
        let mut c = AimdController::new(params());
        c.on_ce_observed();
        assert!((c.scale_factor() - 2.0).abs() < 1e-9);
    }

    #[test]
    fn scale_factor_with_zero_base_uses_floor_reference() {
        let zero_base = AimdParams {
            base_interval: Duration::ZERO,
            backoff_factor: 3.0,
            max_interval: Duration::from_millis(100),
            recovery_step: Duration::from_millis(1),
        };
        let mut c = AimdController::new(zero_base);
        // At rest (current == 0) the documented value is 1.0 — a zero scale
        // would zero every scaled parameter (e.g. the Type 12 inter-packet
        // interval, which reflectors reject against their minimum).
        assert!((c.scale_factor() - 1.0).abs() < f64::EPSILON);
        c.on_ce_observed(); // current -> 1ms floor * 3.0 = 3ms
        assert!((c.scale_factor() - 3.0).abs() < 1e-9);
    }

    /// An extreme (but finite, hence validation-accepted) backoff factor
    /// must saturate at max_interval instead of panicking inside
    /// `Duration::mul_f64` on the first CE observation.
    #[test]
    fn extreme_backoff_factor_saturates_at_max_instead_of_panicking() {
        let extreme = AimdParams {
            base_interval: Duration::from_millis(100),
            backoff_factor: 1e308,
            max_interval: Duration::from_millis(1600),
            recovery_step: Duration::from_millis(20),
        };
        let mut c = AimdController::new(extreme);
        c.on_ce_observed();
        assert_eq!(c.current_interval(), Duration::from_millis(1600));
        assert_eq!(c.stats().backoffs_applied, 1);
    }

    #[test]
    fn interleaved_ce_and_clean_events_never_exceed_max_or_go_below_base() {
        let mut c = AimdController::new(params());
        let script = [
            true, true, false, true, false, false, true, true, true, false, false, false, false,
            false, true, false,
        ];
        for ce in script {
            if ce {
                c.on_ce_observed();
            } else {
                c.on_clean_reply();
            }
            assert!(c.current_interval() >= params().base_interval);
            assert!(c.current_interval() <= params().max_interval);
        }
    }

    #[test]
    fn stats_base_interval_matches_params() {
        let c = AimdController::new(params());
        assert_eq!(c.stats().base_interval, Duration::from_millis(100));
    }
}

#[cfg(test)]
mod proptests {
    use proptest::prelude::*;

    use super::*;

    proptest! {
        /// For any sequence of CE / clean events, the controller's interval
        /// stays within [base_interval, max_interval] at every step — the
        /// core AIMD safety property this controller exists to guarantee.
        #[test]
        fn interval_always_stays_within_bounds(events in proptest::collection::vec(any::<bool>(), 0..200)) {
            let base = Duration::from_millis(50);
            let max = Duration::from_millis(4000);
            let mut c = AimdController::new(AimdParams {
                base_interval: base,
                backoff_factor: 2.0,
                max_interval: max,
                recovery_step: Duration::from_millis(7),
            });
            for ce in events {
                if ce {
                    c.on_ce_observed();
                } else {
                    c.on_clean_reply();
                }
                prop_assert!(c.current_interval() >= base);
                prop_assert!(c.current_interval() <= max);
            }
        }

        /// A CE observation never *decreases* the interval, and a clean
        /// reply never *increases* it — monotonic direction per event type,
        /// regardless of history.
        #[test]
        fn ce_never_decreases_clean_never_increases(events in proptest::collection::vec(any::<bool>(), 1..200)) {
            let mut c = AimdController::new(AimdParams {
                base_interval: Duration::from_millis(50),
                backoff_factor: 1.5,
                max_interval: Duration::from_millis(2000),
                recovery_step: Duration::from_millis(5),
            });
            for ce in events {
                let before = c.current_interval();
                if ce {
                    c.on_ce_observed();
                    prop_assert!(c.current_interval() >= before);
                } else {
                    c.on_clean_reply();
                    prop_assert!(c.current_interval() <= before);
                }
            }
        }
    }
}
