//! Optional local send-call-to-receive observations, bounded by probe slots.

use serde::Serialize;
use stamp_suite::stats::{QuantilePrecision, RttCollector, RttSample};
use std::sync::atomic::{AtomicU64, Ordering};

pub(super) const MAX_PROBES: usize = 1_000_000;

pub(super) fn validate_capacity(capacity: usize) -> Result<(), &'static str> {
    if !(2..=MAX_PROBES + 1).contains(&capacity) {
        return Err("latency tracking requires 1–1,000,000 scheduled probes (rate × seconds)");
    }
    Ok(())
}

pub(super) struct SendTimes(Vec<AtomicU64>);

impl SendTimes {
    pub(super) fn new(capacity: usize) -> Result<Self, &'static str> {
        validate_capacity(capacity)?;
        Ok(Self((0..capacity).map(|_| AtomicU64::new(0)).collect()))
    }

    fn slot(&self, sequence: u32) -> Result<&AtomicU64, &'static str> {
        if sequence == 0 {
            return Err("warm-up sequence has no latency slot");
        }
        self.0
            .get(sequence as usize)
            .ok_or("latency sequence outside scheduled range")
    }

    pub(super) fn mark(&self, sequence: u32, elapsed_ns: u64) -> Result<(), &'static str> {
        let encoded = elapsed_ns.checked_add(1).ok_or("send timestamp overflow")?;
        self.slot(sequence)?
            .compare_exchange(0, encoded, Ordering::Release, Ordering::Relaxed)
            .map(|_| ())
            .map_err(|_| "send timestamp already published")
    }

    pub(super) fn elapsed(&self, sequence: u32, received_ns: u64) -> Result<u64, &'static str> {
        let encoded = self.slot(sequence)?.load(Ordering::Acquire);
        let sent = encoded
            .checked_sub(1)
            .ok_or("validated reply has no send timestamp")?;
        received_ns
            .checked_sub(sent)
            .ok_or("reply observation precedes send timestamp")
    }
}

#[derive(Default)]
pub(super) struct Samples {
    collector: RttCollector,
    count: u64,
    sum: u128,
    min: Option<u64>,
    max: Option<u64>,
}

#[derive(Serialize)]
pub(super) struct Summary {
    pub(super) samples: u64,
    min_ns: Option<u64>,
    max_ns: Option<u64>,
    mean_ns: Option<f64>,
    p50_ns: Option<u64>,
    p95_ns: Option<u64>,
    p99_ns: Option<u64>,
    quantile_precision: QuantilePrecision,
}

impl Samples {
    pub(super) fn record(&mut self, ns: u64) {
        self.collector.record(RttSample {
            seq: 0,
            rtt_ns: ns,
            ttl: 0,
        });
        self.count += 1;
        self.sum += u128::from(ns);
        self.min = Some(self.min.map_or(ns, |min| min.min(ns)));
        self.max = Some(self.max.map_or(ns, |max| max.max(ns)));
    }

    pub(super) fn summary(&self) -> Summary {
        Summary {
            samples: self.count,
            min_ns: self.min,
            max_ns: self.max,
            mean_ns: (self.count > 0).then(|| self.sum as f64 / self.count as f64),
            p50_ns: self.collector.percentile_ns(50.0),
            p95_ns: self.collector.percentile_ns(95.0),
            p99_ns: self.collector.percentile_ns(99.0),
            quantile_precision: self.collector.snapshot(self.count, 0).quantile_precision,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timestamps_preserve_zero_and_reject_reuse_missing_and_reversed_observations() {
        let times = SendTimes::new(3).unwrap();
        assert!(times.elapsed(1, 10).is_err());
        times.mark(1, 0).unwrap();
        assert_eq!(times.elapsed(1, 0), Ok(0));
        assert_eq!(times.elapsed(1, 100), Ok(100));
        assert!(times.mark(1, 2).is_err());
        times.mark(2, 100).unwrap();
        assert!(times.elapsed(2, 99).is_err());
        assert_eq!(times.elapsed(2, 110), Ok(10));
        for seq in [0, 3, u32::MAX] {
            assert!(times.mark(seq, 0).is_err());
            assert!(times.elapsed(seq, 10).is_err());
        }
        assert!(SendTimes::new(2).unwrap().mark(1, u64::MAX).is_err());
    }

    #[test]
    fn slots_are_bounded_and_publication_is_visible_to_the_receiver() {
        for capacity in [0, 1, MAX_PROBES + 2, usize::MAX] {
            assert!(validate_capacity(capacity).is_err());
            assert!(SendTimes::new(capacity).is_err());
        }
        assert!(validate_capacity(MAX_PROBES + 1).is_ok());
        let times = SendTimes::new(2).unwrap();
        std::thread::scope(|scope| {
            let (tx, rx) = std::sync::mpsc::sync_channel(0);
            let times_ref = &times;
            let receiver = scope.spawn(move || {
                rx.recv().unwrap();
                assert_eq!(times_ref.elapsed(1, 150), Ok(50));
            });
            times.mark(1, 100).unwrap();
            tx.send(()).unwrap();
            receiver.join().unwrap();
        });
    }

    #[test]
    fn summaries_have_exact_extrema_and_mean_and_label_quantile_precision() {
        let mut samples = Samples::default();
        let empty = samples.summary();
        assert_eq!(empty.samples, 0);
        assert!(empty.min_ns.is_none() && empty.max_ns.is_none() && empty.mean_ns.is_none());
        assert!(empty.p50_ns.is_none() && empty.p99_ns.is_none());
        for ns in [0, 100, 200, 300, 400] {
            samples.record(ns);
        }
        let exact = samples.summary();
        assert_eq!(
            (exact.samples, exact.min_ns, exact.max_ns),
            (5, Some(0), Some(400))
        );
        assert_eq!(exact.mean_ns, Some(200.0));
        assert_eq!(exact.p50_ns, Some(200));
        for _ in 0..5000 {
            samples.record(1000);
        }
        let bounded = samples.summary();
        assert_eq!(bounded.samples, 5005);
        assert_eq!((bounded.min_ns, bounded.max_ns), (Some(0), Some(1000)));
        assert_eq!(exact.quantile_precision.exact_sample_limit, 4096);
        assert!(bounded.samples > bounded.quantile_precision.exact_sample_limit as u64);
        assert!(bounded.quantile_precision.relative_error_bound < 0.008);
        assert!(bounded.p99_ns.unwrap().abs_diff(1000) <= 8);
    }
}
