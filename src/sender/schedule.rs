//! Probe spacing: periodic (RFC 3432) or Poisson (RFC 2330 §11.1.1).

use std::time::Duration;

use crate::configuration::SendSchedule;

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
