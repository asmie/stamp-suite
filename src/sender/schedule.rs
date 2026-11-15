//! Probe spacing: periodic (RFC 3432) or Poisson (RFC 2330 §11.1.1).

use std::time::Duration;

use crate::configuration::SendSchedule;

/// Tokio timers fire on whole milliseconds. Shorter gaps are spun through,
/// polling for replies between yields. Windows also requests precise timers.
const TIMER_RESOLUTION: Duration = Duration::from_millis(1);
/// Keep a small lateness on the original timeline, but discard a larger backlog.
const CATCH_UP: Duration = Duration::from_millis(2);

/// Decisions for the initial probe loop. Access Report retries and the final
/// reply drain retain their separate rules in SenderRun.
pub(super) struct SendTimeline {
    due: tokio::time::Instant,
    stop_at: Option<tokio::time::Instant>,
    count: u64,
}

pub(super) struct SendWait {
    pub(super) deadline: tokio::time::Instant,
    pub(super) spin: bool,
}

impl SendTimeline {
    pub(super) fn new(start: tokio::time::Instant, count: u32, duration: Option<u32>) -> Self {
        Self {
            due: start,
            stop_at: duration.map(|seconds| start + Duration::from_secs(u64::from(seconds))),
            count: u64::from(count),
        }
    }

    /// Check count before reading the duration clock. No initial gap is drawn:
    /// the first probe is eligible at the run's start. The duration bound is
    /// exclusive and does not cancel a send already in progress.
    pub(super) fn can_send(&self, sent: u64, now: impl FnOnce() -> tokio::time::Instant) -> bool {
        (self.count == 0 || sent < self.count) && self.stop_at.is_none_or(|at| now() < at)
    }

    /// Advance from the previous due time before consulting the clock, matching
    /// the live loop's order. Each completed probe, including the last counted
    /// probe, gets this wait. Only the duration limit clamps its deadline.
    pub(super) fn after_probe(
        &mut self,
        gap: Duration,
        now: impl FnOnce() -> tokio::time::Instant,
    ) -> SendWait {
        self.due += gap;
        let now = now();
        if now.saturating_duration_since(self.due) > CATCH_UP {
            self.due = now;
        }
        SendWait {
            deadline: self.stop_at.map_or(self.due, |at| self.due.min(at)),
            spin: gap < TIMER_RESOLUTION,
        }
    }

    /// Apply backoff to the gap already drawn for the next probe. Retain the
    /// Poisson draw rather than sampling again for each reply. Recovery affects
    /// the next draw only: it must not undo a CE delay during the current wait.
    /// A zero base interval has no draw to scale, so use the controller's floor.
    pub(super) fn back_off(
        &mut self,
        gap: &mut Duration,
        interval: &mut Duration,
        current_interval: Duration,
    ) -> SendWait {
        if current_interval > *interval {
            let scaled = if interval.is_zero() {
                current_interval
            } else {
                gap.mul_f64(current_interval.as_secs_f64() / interval.as_secs_f64())
            };
            self.due += scaled.saturating_sub(*gap);
            *gap = scaled;
            *interval = current_interval;
        }
        SendWait {
            deadline: self.stop_at.map_or(self.due, |at| self.due.min(at)),
            spin: *gap < TIMER_RESOLUTION,
        }
    }
}

pub(super) struct Schedule {
    kind: SendSchedule,
    rng: u64,
}

impl Schedule {
    pub(super) fn new(kind: SendSchedule) -> Self {
        let mut seed = [0u8; 8];
        // A weak seed only makes the gap sequence predictable, which does
        // not matter for a measurement schedule.
        let rng = match getrandom::fill(&mut seed) {
            Ok(()) => u64::from_ne_bytes(seed),
            Err(_) => std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_nanos() as u64),
        };
        Self::with_seed(kind, rng)
    }

    pub(super) fn with_seed(kind: SendSchedule, seed: u64) -> Self {
        Self {
            kind,
            // xorshift never leaves zero.
            rng: seed | 1,
        }
    }

    /// The gap before the next probe. `interval` is the fixed gap, or the
    /// mean gap for a Poisson schedule.
    pub(super) fn next_gap(&mut self, interval: Duration) -> Duration {
        match self.kind {
            SendSchedule::Periodic => interval,
            // Exponential gaps: -ln(U) * mean with U uniform in (0, 1].
            SendSchedule::Poisson => interval.mul_f64(-self.uniform().ln()),
        }
    }

    /// Uniform in (0, 1] from xorshift64*. The multiplier is the standard
    /// xorshift64* constant; the top 53 bits fill an f64 mantissa exactly.
    /// Algorithm: Vigna, "An experimental exploration of Marsaglia's xorshift
    /// generators, scrambled", Figure 10: https://vigna.di.unimi.it/ftp/papers/xorshift.pdf.
    fn uniform(&mut self) -> f64 {
        self.rng ^= self.rng >> 12;
        self.rng ^= self.rng << 25;
        self.rng ^= self.rng >> 27;
        let bits = self.rng.wrapping_mul(0x2545_F491_4F6C_DD1D) >> 11;
        (bits as f64 + 1.0) / (1u64 << 53) as f64
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn periodic_gaps_are_the_interval() {
        let mut schedule = Schedule::with_seed(SendSchedule::Periodic, 7);
        assert_eq!(
            schedule.next_gap(Duration::from_millis(5)),
            Duration::from_millis(5)
        );
    }

    #[test]
    fn poisson_gaps_are_exponential_with_the_interval_as_mean() {
        let mut schedule = Schedule::with_seed(SendSchedule::Poisson, 42);
        let mean = Duration::from_millis(10);
        let gaps: Vec<f64> = (0..100_000)
            .map(|_| schedule.next_gap(mean).as_secs_f64() / mean.as_secs_f64())
            .collect();
        let average = gaps.iter().sum::<f64>() / gaps.len() as f64;
        assert!((average - 1.0).abs() < 0.02, "mean {average}");
        // P(gap > mean) = e^-1 for an exponential distribution.
        let above = gaps.iter().filter(|g| **g > 1.0).count() as f64 / gaps.len() as f64;
        assert!((above - (-1f64).exp()).abs() < 0.01, "tail {above}");
    }
}

#[cfg(test)]
#[path = "schedule/timeline_tests.rs"]
mod timeline_tests;
