//! Bounded, full-run quantiles. Small series remain exact; larger series use
//! logarithmic magnitude buckets with eight significant bits. Bucket values
//! round toward zero, with error < |sample| / 128 (zero remains exact).

pub(super) const EXACT_LIMIT: usize = 4096;
pub(super) const RELATIVE_ERROR: f64 = 1.0 / 128.0;
const UNSIGNED_BUCKETS: usize = 7424;
const SIGNED_ZERO: usize = 7296; // magnitude_index(2^63)

fn magnitude_index(value: u64) -> usize {
    let shift = (64 - value.leading_zeros()).saturating_sub(8);
    shift as usize * 128 + (value >> shift) as usize
}

fn magnitude_value(index: usize) -> u64 {
    if index < 256 {
        index as u64
    } else {
        ((128 + index % 128) as u64) << (index / 128 - 1)
    }
}

pub(super) trait QuantileValue: Copy + Ord {
    const BUCKETS: usize;
    fn index(self) -> usize;
    fn value(index: usize) -> Self;
}
impl QuantileValue for u64 {
    const BUCKETS: usize = UNSIGNED_BUCKETS;
    fn index(self) -> usize {
        magnitude_index(self)
    }
    fn value(index: usize) -> Self {
        magnitude_value(index)
    }
}
impl QuantileValue for i64 {
    const BUCKETS: usize = SIGNED_ZERO * 2 + 1;
    fn index(self) -> usize {
        let index = magnitude_index(self.unsigned_abs());
        if self < 0 {
            SIGNED_ZERO - index
        } else {
            SIGNED_ZERO + index
        }
    }
    fn value(index: usize) -> Self {
        let magnitude = i128::from(magnitude_value(index.abs_diff(SIGNED_ZERO)));
        // Only populated buckets are decoded; the negative endpoint includes MIN.
        if index < SIGNED_ZERO {
            (-magnitude) as i64
        } else {
            magnitude as i64
        }
    }
}

enum Storage<T> {
    Exact(Vec<T>),
    Histogram(Box<[u64]>),
}

pub(super) struct Quantiles<T> {
    storage: Storage<T>,
    count: u64,
    min: Option<T>,
    max: Option<T>,
}

impl<T: QuantileValue> Default for Quantiles<T> {
    fn default() -> Self {
        Self {
            storage: Storage::Exact(Vec::new()),
            count: 0,
            min: None,
            max: None,
        }
    }
}

impl<T: QuantileValue> Quantiles<T> {
    /// Returns false once the full u64 observation count has been exhausted.
    pub fn record(&mut self, value: T) -> bool {
        if self.count == u64::MAX {
            return false;
        }
        if let Storage::Exact(samples) = &self.storage {
            if samples.len() == EXACT_LIMIT {
                let mut buckets = vec![0; T::BUCKETS].into_boxed_slice();
                for &sample in samples {
                    buckets[sample.index()] += 1;
                }
                self.storage = Storage::Histogram(buckets);
            }
        }
        match &mut self.storage {
            Storage::Exact(samples) => samples.push(value),
            Storage::Histogram(buckets) => buckets[value.index()] += 1,
        }
        self.count += 1;
        self.min = Some(self.min.map_or(value, |old| old.min(value)));
        self.max = Some(self.max.map_or(value, |old| old.max(value)));
        true
    }

    pub fn count(&self) -> u64 {
        self.count
    }

    /// All requested percentiles share one bounded sort or histogram traversal.
    /// Rank is round(p / 100 * (n - 1)), as before. NaN/negative p selects min;
    /// p >= 100 selects max. Endpoints and constant series remain exact.
    pub fn percentiles<const N: usize>(&self, ps: [f64; N]) -> [Option<T>; N] {
        let (Some(min), Some(max)) = (self.min, self.max) else {
            return [None; N];
        };
        let ranks = ps
            .map(|p| (((p / 100.0) * (self.count - 1) as f64).round() as u64).min(self.count - 1));
        match &self.storage {
            Storage::Exact(samples) => {
                let mut sorted = samples.clone();
                sorted.sort_unstable();
                ranks.map(|rank| Some(sorted[rank as usize]))
            }
            Storage::Histogram(buckets) => {
                let mut result = [None; N];
                let mut cumulative = 0;
                for (index, count) in buckets.iter().enumerate() {
                    cumulative += count;
                    for (slot, rank) in result.iter_mut().zip(ranks) {
                        if slot.is_none() && rank < cumulative {
                            *slot = Some(if rank == 0 {
                                min
                            } else if rank == self.count - 1 {
                                max
                            } else {
                                T::value(index).clamp(min, max)
                            });
                        }
                    }
                    if result.iter().all(Option::is_some) {
                        break;
                    }
                }
                result
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_magnitude_bucket_obeys_the_error_bound() {
        for index in 0..UNSIGNED_BUCKETS {
            let low = magnitude_value(index);
            let high = if index + 1 == UNSIGNED_BUCKETS {
                u64::MAX
            } else {
                magnitude_value(index + 1) - 1
            };
            for value in [low, high] {
                assert_eq!(magnitude_index(value), index);
                if value == 0 {
                    assert_eq!(low, 0);
                } else {
                    assert!(u128::from(value - low) * 128 < u128::from(value));
                }
            }
        }
        for value in 0..256 {
            assert_eq!(magnitude_value(magnitude_index(value)), value);
        }
    }

    fn check_oracle<T: QuantileValue + std::fmt::Debug + Into<i128>>(values: &[T]) {
        let mut collector = Quantiles::default();
        for &value in values {
            assert!(collector.record(value));
        }
        let mut sorted = values.to_vec();
        sorted.sort_unstable();
        let ps = [
            99.0,
            0.0,
            50.0,
            95.0,
            100.0,
            37.5,
            -1.0,
            f64::NAN,
            f64::INFINITY,
        ];
        let actual = collector.percentiles(ps);
        for (p, actual) in ps.into_iter().zip(actual) {
            let rank =
                (((p / 100.0) * (sorted.len() - 1) as f64).round() as usize).min(sorted.len() - 1);
            let expected: i128 = sorted[rank].into();
            let actual: i128 = actual.unwrap().into();
            if values.len() <= EXACT_LIMIT || rank == 0 || rank == sorted.len() - 1 || expected == 0
            {
                assert_eq!(actual, expected, "p={p}");
            } else {
                assert!(
                    actual.abs_diff(expected) * 128 < expected.unsigned_abs(),
                    "p={p}: actual={actual}, expected={expected}"
                );
                assert_eq!(actual.signum(), expected.signum());
            }
        }
    }

    #[test]
    fn exact_and_histogram_quantiles_match_independent_sorted_oracles() {
        let mut seed = 0x1234_5678_9ABC_DEF0u64;
        let mut unsigned = Vec::new();
        let mut signed = Vec::new();
        for i in 0..20_000 {
            seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
            unsigned.push(match i % 4 {
                0 => 0,
                1 => u64::MAX,
                _ => seed >> (i % 64),
            });
            signed.push(match i % 7 {
                0 => i64::MIN,
                1 => i64::MAX,
                2 => 0,
                _ => seed as i64 >> (i % 64),
            });
        }
        for len in [1, 2, EXACT_LIMIT, EXACT_LIMIT + 1, 20_000] {
            check_oracle(&unsigned[..len]);
            check_oracle(&signed[..len]);
        }
        check_oracle(&vec![-7_777_777i64; EXACT_LIMIT + 1]);
        check_oracle(&vec![7_777_777u64; EXACT_LIMIT + 1]);
    }

    #[test]
    fn retained_storage_stays_fixed_and_earlier_samples_still_count() {
        let mut collector = Quantiles::<u64>::default();
        for _ in 0..EXACT_LIMIT {
            collector.record(1);
        }
        let Storage::Exact(samples) = &collector.storage else {
            panic!("promoted too early")
        };
        assert_eq!(samples.len(), EXACT_LIMIT);
        assert!(samples.capacity() <= EXACT_LIMIT);
        for _ in EXACT_LIMIT..1_000_000 {
            collector.record(1_000_000);
        }
        let Storage::Histogram(buckets) = &collector.storage else {
            panic!("did not promote")
        };
        assert_eq!(buckets.len(), UNSIGNED_BUCKETS);
        assert_eq!(buckets.iter().sum::<u64>(), 1_000_000);
        assert_eq!(collector.percentiles([0.1])[0], Some(1));
        assert_eq!(collector.count(), 1_000_000);
    }

    #[test]
    fn full_count_stops_without_wrapping_or_losing_existing_quantiles() {
        let mut collector = Quantiles::<u64>::default();
        for _ in 0..=EXACT_LIMIT {
            collector.record(0);
        }
        collector.count = u64::MAX;
        let Storage::Histogram(buckets) = &mut collector.storage else {
            unreachable!()
        };
        buckets[0] = u64::MAX;
        assert!(!collector.record(u64::MAX));
        assert_eq!(collector.count(), u64::MAX);
        assert_eq!(collector.percentiles([0.0, 50.0, 100.0]), [Some(0); 3]);
    }
}
