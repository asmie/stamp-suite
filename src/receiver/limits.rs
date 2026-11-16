//! Reflector counters, the per-source rate limiter, and the runtime-adjustable
//! Type 12 caps.

use super::*;

/// Aggregate packet counters for the reflector.
pub struct ReflectorCounters {
    #[cfg(feature = "metrics")]
    pub(crate) metrics_enabled: bool,
    /// Requests refused before processing because all work slots are occupied.
    pub reply_queue_rejected: AtomicU64,
    /// Unsent copies discarded when queued work is cancelled (e.g. shutdown).
    pub queued_replies_cancelled: AtomicU64,
    pub packets_received: AtomicU64,
    pub packets_reflected: AtomicU64,
    pub packets_dropped: AtomicU64,
    /// Subset of `packets_dropped`: packets refused because the per-client
    /// token bucket was empty. Distinguishing this from generic drops lets
    /// operators tell rate-limit pressure from parse / HMAC failures.
    pub packets_rate_limited: AtomicU64,
    /// Received packets whose Sequence Number had already been seen on that
    /// session: duplicates or replays
    /// (RFC 10052 §5). Counted whether or not
    /// `--drop-replayed` acts on them; when it does, they are also included in
    /// `packets_dropped`.
    pub packets_replayed: AtomicU64,
    /// Received packets behind the session's high-water mark but not seen
    /// before: late or reordered delivery. Ordinary on a real path, tracked
    /// alongside the replay count so an operator can tell benign reordering
    /// from an actual duplicate.
    pub packets_reordered: AtomicU64,
    /// Successful reflected datagrams per TLV C condition or preserved peer flag.
    tlv_conformance: [AtomicU64; crate::tlv::TlvConformanceReason::ALL.len()],
    /// Successful reflected datagrams per locally generated BER C condition.
    ber_conformance: [AtomicU64; crate::ber::BerConformanceReason::ALL.len()],
}

impl ReflectorCounters {
    pub fn new() -> Self {
        ReflectorCounters {
            #[cfg(feature = "metrics")]
            metrics_enabled: false,
            reply_queue_rejected: AtomicU64::new(0),
            queued_replies_cancelled: AtomicU64::new(0),
            packets_received: AtomicU64::new(0),
            packets_reflected: AtomicU64::new(0),
            packets_dropped: AtomicU64::new(0),
            packets_rate_limited: AtomicU64::new(0),
            packets_replayed: AtomicU64::new(0),
            packets_reordered: AtomicU64::new(0),
            tlv_conformance: std::array::from_fn(|_| AtomicU64::new(0)),
            ber_conformance: std::array::from_fn(|_| AtomicU64::new(0)),
        }
    }

    pub(super) fn record_received(&self) {
        self.packets_received.fetch_add(1, Ordering::Relaxed);
        #[cfg(feature = "metrics")]
        if self.metrics_enabled {
            crate::metrics::reflector_metrics::record_packet_received();
        }
    }

    pub(super) fn record_reflected(&self) {
        self.packets_reflected.fetch_add(1, Ordering::Relaxed);
        #[cfg(feature = "metrics")]
        if self.metrics_enabled {
            crate::metrics::reflector_metrics::record_packet_reflected();
        }
    }

    pub(super) fn record_drop(&self, _reason: &'static str) {
        self.packets_dropped.fetch_add(1, Ordering::Relaxed);
        #[cfg(feature = "metrics")]
        if self.metrics_enabled {
            crate::metrics::reflector_metrics::record_packet_dropped(_reason);
        }
    }

    pub fn ber_conformance_count(&self, reason: crate::ber::BerConformanceReason) -> u64 {
        self.ber_conformance[reason as usize].load(Ordering::Relaxed)
    }

    pub fn ber_conformance_counts(&self) -> std::collections::BTreeMap<&'static str, u64> {
        crate::ber::BerConformanceReason::ALL
            .into_iter()
            .map(|reason| (reason.label(), self.ber_conformance_count(reason)))
            .collect()
    }

    pub(super) fn record_ber_conformance(&self, reasons: crate::ber::BerConformanceErrors) {
        if reasons.is_empty() {
            return;
        }
        for reason in reasons.iter() {
            let n = self.ber_conformance[reason as usize]
                .fetch_add(1, Ordering::Relaxed)
                .wrapping_add(1);
            if crate::log_throttle::is_power_of_ten(n) {
                log::warn!(target: "stamp_suite::ber::conformance",
                    "reflected BER C condition: {} ({n} reflected datagrams)", reason.label());
            }
            #[cfg(feature = "metrics")]
            if self.metrics_enabled {
                crate::metrics::reflector_metrics::record_ber_conformance(reason.label());
            }
        }
    }

    pub fn tlv_conformance_count(&self, reason: crate::tlv::TlvConformanceReason) -> u64 {
        self.tlv_conformance[reason as usize].load(Ordering::Relaxed)
    }

    pub fn tlv_conformance_counts(&self) -> std::collections::BTreeMap<&'static str, u64> {
        crate::tlv::TlvConformanceReason::ALL
            .into_iter()
            .map(|reason| (reason.label(), self.tlv_conformance_count(reason)))
            .collect()
    }

    pub(super) fn record_tlv_conformance(&self, reasons: crate::tlv::TlvConformanceErrors) {
        if reasons.is_empty() {
            return;
        }
        for reason in reasons.iter() {
            let n = self.tlv_conformance[reason as usize]
                .fetch_add(1, Ordering::Relaxed)
                .wrapping_add(1);
            if crate::log_throttle::is_power_of_ten(n) {
                log::warn!(target: "stamp_suite::tlv::conformance",
                    "reflected TLV C condition: {} ({n} reflected datagrams)", reason.label());
            }
            #[cfg(feature = "metrics")]
            if self.metrics_enabled {
                crate::metrics::reflector_metrics::record_tlv_conformance(reason.label());
            }
        }
    }
}

impl Default for ReflectorCounters {
    fn default() -> Self {
        Self::new()
    }
}

/// Token buckets keyed by source IP. Each refills at `rate` tokens/second up
/// to `burst`. Ingest takes one token before validation and admission; each
/// additional Type 12 reply copy takes another.
///
/// The SSID is not part of the key: a sender chooses it freely, so keying on
/// it would let one source multiply its budget.
pub struct RateLimiter {
    /// Atomic pair: tokens/second in the high half, effective burst in the low
    /// half. Readers must not combine fields from separate runtime updates.
    limits: AtomicU64,
    state: std::sync::Mutex<RateLimiterState>,
    capacity: usize,
}

pub(super) struct RateLimiterState {
    last_cleanup: Instant,
    sources: StdHashMap<std::net::IpAddr, Bucket>,
    sweep: std::collections::VecDeque<std::net::IpAddr>,
    cleanup_remaining: usize,
    overflow: Bucket,
}

pub(super) struct Bucket {
    tokens: f64,
    last_refill: Instant,
    last_seen: Instant,
}

impl RateLimiter {
    const BUCKET_TTL: Duration = Duration::from_secs(60);
    const CLEANUP_INTERVAL: Duration = Duration::from_secs(10);
    /// New sources share an overflow budget once this table is full.
    const MAX_SOURCES: usize = 16_384;
    const CLEANUP_BATCH: usize = 4;

    /// Creates a limiter with `rate` tokens/second and one second of burst capacity.
    pub fn new(rate: u32) -> Self {
        Self::with_burst(rate, rate)
    }

    /// Creates a limiter with an explicit token-bucket burst capacity.
    /// `burst` of 0 falls back to `rate`.
    pub fn with_burst(rate: u32, burst: u32) -> Self {
        Self::with_capacity(rate, burst, Self::MAX_SOURCES)
    }

    fn with_capacity(rate: u32, burst: u32, capacity: usize) -> Self {
        let burst = if burst == 0 { rate } else { burst };
        let now = Instant::now();
        RateLimiter {
            limits: AtomicU64::new(Self::encode_limits(rate, burst)),
            state: std::sync::Mutex::new(RateLimiterState {
                last_cleanup: now,
                sources: StdHashMap::new(),
                sweep: std::collections::VecDeque::new(),
                cleanup_remaining: 0,
                overflow: Bucket {
                    tokens: f64::from(burst),
                    last_refill: now,
                    last_seen: now,
                },
            }),
            capacity,
        }
    }

    fn encode_limits(rate: u32, burst: u32) -> u64 {
        let burst = if burst == 0 { rate } else { burst };
        (u64::from(rate) << 32) | u64::from(burst)
    }

    /// Adjusts the rate and burst together at runtime (control plane).
    /// `burst` of 0 falls back to `rate`; `rate` of 0 disables limiting entirely.
    pub fn set_rate(&self, rate: u32, burst: u32) {
        self.limits
            .store(Self::encode_limits(rate, burst), Ordering::Relaxed);
    }

    /// Updates only supplied fields without overwriting concurrent changes to
    /// omitted fields. A supplied zero burst uses the rate of the same update.
    /// An omitted burst retains its nonzero effective capacity; a zero capacity
    /// falls back to the updated rate, as at initial configuration.
    pub fn update_rate(&self, rate: Option<u32>, burst: Option<u32>) {
        if rate.is_none() && burst.is_none() {
            return;
        }
        // Retry from the latest pair if another writer changed either field.
        let mut current = self.limits.load(Ordering::Relaxed);
        loop {
            let updated = Self::encode_limits(
                rate.unwrap_or((current >> 32) as u32),
                burst.unwrap_or(current as u32),
            );
            match self.limits.compare_exchange_weak(
                current,
                updated,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(latest) => current = latest,
            }
        }
    }

    /// Coherent snapshot of the current rate and effective burst capacity.
    #[must_use]
    pub fn rate_and_burst(&self) -> (u32, u32) {
        let limits = self.limits.load(Ordering::Relaxed);
        ((limits >> 32) as u32, limits as u32)
    }

    /// Current rate (tokens/second); 0 = unlimited.
    #[must_use]
    pub fn rate(&self) -> u32 {
        self.rate_and_burst().0
    }

    /// Current burst capacity.
    #[must_use]
    pub fn burst(&self) -> u32 {
        self.rate_and_burst().1
    }

    /// Refills `src`'s bucket and takes one token if available. Denied requests
    /// still refresh the bucket's activity and refill timestamps.
    pub fn allow(&self, src: std::net::IpAddr) -> bool {
        self.allow_at(src, Instant::now())
    }

    fn allow_at(&self, src: std::net::IpAddr, now: Instant) -> bool {
        let (rate_now, burst_now) = self.rate_and_burst();
        if rate_now == 0 {
            // Unlimited: skip the lock and allocate no buckets.
            return true;
        }
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        Self::cleanup_expired_buckets(&mut state, now);

        let burst = f64::from(burst_now);
        let rate = rate_now as f64;
        if !state.sources.contains_key(&src) && state.sources.len() < self.capacity {
            state.sources.insert(
                src,
                Bucket {
                    tokens: burst,
                    last_refill: now,
                    last_seen: now,
                },
            );
            state.sweep.push_back(src);
        }
        let RateLimiterState {
            sources, overflow, ..
        } = &mut *state;
        let bucket = sources.get_mut(&src).unwrap_or(overflow);
        // Workers sample time before locking. An older sample can acquire the
        // lock later; never rewind refill/activity and credit an interval twice.
        let now = now.max(bucket.last_refill);
        let elapsed = now.duration_since(bucket.last_refill).as_secs_f64();
        bucket.tokens = (bucket.tokens + elapsed * rate).min(burst);
        bucket.last_refill = now;
        bucket.last_seen = now;

        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    fn cleanup_expired_buckets(state: &mut RateLimiterState, now: Instant) {
        if state.cleanup_remaining == 0
            && now.duration_since(state.last_cleanup) >= Self::CLEANUP_INTERVAL
        {
            state.cleanup_remaining = state.sweep.len();
            state.last_cleanup = now;
        }
        for _ in 0..Self::CLEANUP_BATCH.min(state.cleanup_remaining) {
            let Some(src) = state.sweep.pop_front() else {
                break;
            };
            state.cleanup_remaining -= 1;
            if state
                .sources
                .get(&src)
                .is_some_and(|b| now.duration_since(b.last_seen) >= Self::BUCKET_TTL)
            {
                state.sources.remove(&src);
            } else {
                state.sweep.push_back(src);
            }
        }
    }
}

/// Reflector caps adjustable at runtime via the control plane.
/// Loaded per packet with Relaxed ordering: these are tuning knobs,
/// not synchronization points.
#[derive(Debug)]
pub struct RuntimeCaps {
    /// Type 12 volume limit (max reply packets per request); 0 disables
    /// asymmetric reflection.
    pub reflected_control_max_count: std::sync::atomic::AtomicU16,
    /// Administrative Type 12 reply-size cap in octets; send-time route MTU
    /// enforcement can further reduce the actual payload.
    pub reflected_control_max_size: std::sync::atomic::AtomicU16,
    /// Type 12 rate limit: minimum inter-packet interval in nanoseconds.
    pub reflected_control_min_interval_ns: AtomicU32,
    /// Type 12 data-rate limit per request, bytes per second.
    pub reflected_control_max_rate: std::sync::atomic::AtomicU64,
    /// Type 12 data-volume limit per request, bytes.
    pub reflected_control_max_volume: AtomicU32,
}

impl RuntimeCaps {
    /// Builds the caps from startup configuration.
    #[must_use]
    pub fn from_conf(conf: &Configuration) -> Self {
        Self {
            reflected_control_max_count: std::sync::atomic::AtomicU16::new(
                conf.reflected_control_max_count,
            ),
            reflected_control_max_size: std::sync::atomic::AtomicU16::new(
                conf.reflected_control_max_size,
            ),
            reflected_control_min_interval_ns: AtomicU32::new(
                conf.reflected_control_min_interval_ns,
            ),
            reflected_control_max_rate: std::sync::atomic::AtomicU64::new(
                conf.reflected_control_max_rate,
            ),
            reflected_control_max_volume: AtomicU32::new(conf.reflected_control_max_volume),
        }
    }

    /// CLI-default values (count 0 = disabled, size 1500, interval 1 µs);
    /// used by tests and as a neutral baseline.
    #[must_use]
    pub fn from_defaults() -> Self {
        Self {
            reflected_control_max_count: std::sync::atomic::AtomicU16::new(0),
            reflected_control_max_size: std::sync::atomic::AtomicU16::new(
                REFLECTED_CONTROL_MAX_SIZE,
            ),
            reflected_control_min_interval_ns: AtomicU32::new(REFLECTED_CONTROL_MIN_INTERVAL_NS),
            reflected_control_max_rate: std::sync::atomic::AtomicU64::new(
                REFLECTED_CONTROL_MAX_RATE,
            ),
            reflected_control_max_volume: AtomicU32::new(REFLECTED_CONTROL_MAX_VOLUME),
        }
    }
}

/// Enabled-path reply-count cap used by tests and as a suggested opt-in value.
/// Requests above it get C set. The CLI default is 0 (asymmetric reflection
/// disabled, per RFC 10052 §5).
pub const REFLECTED_CONTROL_MAX_COUNT: u16 = 16;

/// Default padded reply payload cap for Type 12 (RFC 10052 §3).
/// The send path also applies the route MTU minus header overhead.
/// Requests above the cap get one C-flagged reply if mandatory fields fit.
/// Override with `--reflected-control-max-size` or the control API.
pub(crate) const REFLECTED_CONTROL_MAX_SIZE: u16 = 1500;

/// Default minimum inter-packet gap (nanoseconds): the per-request *rate*
/// limit of RFC 10052 §3, and a floor that avoids
/// tight busy-loops in the backends. A multi-packet request with a shorter
/// interval collapses to a single reply with the C flag set. Operators can
/// override it via `--reflected-control-min-interval-ns`.
pub(crate) const REFLECTED_CONTROL_MIN_INTERVAL_NS: u32 = 1_000;

/// Default Type 12 data-rate limit in bytes per second (100 Mbit/s).
/// RFC 10052 §3 requires a rate and a volume limit per request.
pub const REFLECTED_CONTROL_MAX_RATE: u64 = 12_500_000;

/// Default Type 12 data-volume limit in bytes per request (1000 replies of
/// 1500 bytes). See [`REFLECTED_CONTROL_MAX_RATE`].
pub const REFLECTED_CONTROL_MAX_VOLUME: u32 = 1_500_000;

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn source_churn_uses_bounded_overflow_and_incremental_expiry() {
        let limiter = RateLimiter::with_capacity(1, 2, 8);
        let now = Instant::now();
        let ip = |n| IpAddr::V4(Ipv4Addr::from(n));
        for n in 1..=8 {
            assert!(limiter.allow_at(ip(n), now));
        }
        assert!(limiter.allow_at(ip(9), now));
        assert!(limiter.allow_at(ip(10), now));
        for n in 11..10_000 {
            assert!(!limiter.allow_at(ip(n), now));
        }
        assert!(
            limiter.allow_at(ip(1), now),
            "existing source keeps its own budget"
        );
        assert!(!limiter.allow_at(ip(1), now));
        {
            let state = limiter.state.lock().unwrap();
            assert_eq!(state.sources.len(), 8);
            assert_eq!(state.sweep.len(), 8);
        }
        let expired = now + Duration::from_secs(61);
        assert!(limiter.allow_at(ip(10_000), expired));
        assert_eq!(
            limiter.state.lock().unwrap().sources.len(),
            5,
            "one call expires only four entries"
        );
        assert!(limiter.allow_at(ip(10_001), expired));
        assert_eq!(limiter.state.lock().unwrap().sources.len(), 2);
        assert!(!limiter.state.lock().unwrap().sources.contains_key(&ip(1)));
    }

    #[test]
    fn delayed_admission_does_not_refill_an_interval_twice() {
        for src in ["192.0.2.1", "2001:db8::1"] {
            for (overflow, burst) in [(false, 1), (false, 2), (true, 1), (true, 2)] {
                let limiter = RateLimiter::with_capacity(1, burst, 1);
                let start = Instant::now();
                if overflow {
                    assert!(limiter.allow_at("198.51.100.1".parse().unwrap(), start));
                }
                let src = src.parse().unwrap();
                assert!(limiter.allow_at(src, start));
                let later = start + Duration::from_secs(1);
                assert!(limiter.allow_at(src, later));
                // A worker sampled `start`, then lost the mutex race to the
                // worker with `later`. It must not rewind either timestamp,
                // but can still consume any existing token in a larger burst.
                assert_eq!(limiter.allow_at(src, start), burst == 2);
                for delayed in [start, start + Duration::from_millis(500), start] {
                    assert!(!limiter.allow_at(src, delayed));
                }
                assert!(
                    !limiter.allow_at(src, later),
                    "a delayed worker duplicated refill credit: src={src}, overflow={overflow}"
                );
                // Fractional credit survives both a denial and another stale
                // worker, but no full token appears until a new second elapses.
                assert!(!limiter.allow_at(src, later + Duration::from_millis(500)));
                assert!(!limiter.allow_at(src, start));
                assert!(limiter.allow_at(src, later + Duration::from_secs(1)));
                assert!(!limiter.allow_at(src, later + Duration::from_secs(1)));
                if overflow {
                    // Overflow sources share one clock and budget, even when
                    // they use different IP families.
                    let other = if src.is_ipv4() {
                        "2001:db8::2"
                    } else {
                        "192.0.2.2"
                    };
                    assert!(!limiter.allow_at(other.parse().unwrap(), start));
                    assert!(
                        !limiter.allow_at(other.parse().unwrap(), later + Duration::from_secs(1))
                    );
                }
            }
        }
    }

    #[test]
    fn delayed_admission_does_not_expire_an_active_source() {
        for src in ["192.0.2.1", "2001:db8::1"] {
            let limiter = RateLimiter::with_burst(1, 1);
            let start = Instant::now();
            let src = src.parse().unwrap();
            assert!(limiter.allow_at(src, start));
            let active = start + Duration::from_secs(50);
            assert!(limiter.allow_at(src, active));
            assert!(!limiter.allow_at(src, start));
            let trigger = "198.51.100.1".parse().unwrap();
            assert!(limiter.allow_at(trigger, start + Duration::from_secs(61)));
            assert!(
                limiter.state.lock().unwrap().sources.contains_key(&src),
                "a delayed worker backdated the source's last activity"
            );
            // The correction must not disable normal idle expiry.
            assert!(limiter.allow_at(trigger, active + RateLimiter::BUCKET_TTL));
            assert!(!limiter.state.lock().unwrap().sources.contains_key(&src));
        }
    }

    #[test]
    fn test_rate_limiter_expires_inactive_buckets() {
        let limiter = RateLimiter::new(10);
        let stale = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
        let fresh = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2));
        let trigger = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 3));

        assert!(limiter.allow(stale));
        assert!(limiter.allow(fresh));

        {
            let mut state = limiter.state.lock().unwrap_or_else(|e| e.into_inner());
            state.last_cleanup = Instant::now() - RateLimiter::CLEANUP_INTERVAL;
            let stale_bucket = state.sources.get_mut(&stale).unwrap();
            stale_bucket.last_seen =
                Instant::now() - RateLimiter::BUCKET_TTL - Duration::from_secs(1);
        }

        assert!(limiter.allow(trigger));

        let state = limiter.state.lock().unwrap_or_else(|e| e.into_inner());
        assert!(!state.sources.contains_key(&stale));
        assert!(state.sources.contains_key(&fresh));
        assert!(state.sources.contains_key(&trigger));
    }

    #[test]
    fn concurrent_rate_updates_preserve_new_source_admission() {
        // Both complete configurations allow a fresh source immediately.
        // A mixed pair (positive rate, zero burst) would spuriously reject it.
        let limiter = RateLimiter::with_burst(u32::MAX, 1);
        let barrier = std::sync::Barrier::new(2);
        let stop = std::sync::atomic::AtomicBool::new(false);
        let rejected = std::thread::scope(|scope| {
            scope.spawn(|| {
                barrier.wait();
                for _ in 0..1_000_000 {
                    if stop.load(Ordering::Relaxed) {
                        break;
                    }
                    limiter.set_rate(0, 0);
                    limiter.set_rate(u32::MAX, 1);
                }
            });
            barrier.wait();
            let rejected = (1..=2048u32)
                .flat_map(|n| {
                    [
                        IpAddr::V4(Ipv4Addr::from(0x0a000000 + n)),
                        IpAddr::V6(std::net::Ipv6Addr::from(u128::from(n))),
                    ]
                })
                .find(|&src| !limiter.allow(src));
            stop.store(true, Ordering::Relaxed);
            rejected
        });
        assert_eq!(rejected, None, "admission used mismatched rate and burst");
    }

    #[test]
    fn partial_rate_updates_keep_existing_bucket_tokens() {
        let limiter = RateLimiter::with_burst(10, 2);
        let now = Instant::now();
        for src in ["192.0.2.1", "2001:db8::1"] {
            let src = src.parse().unwrap();
            assert!(limiter.allow_at(src, now));
            assert!(limiter.allow_at(src, now));
            assert!(!limiter.allow_at(src, now));
            limiter.update_rate(Some(20), None);
            assert!(
                !limiter.allow_at(src, now),
                "changing rate must not refill the bucket"
            );
            limiter.update_rate(None, Some(3));
            assert!(
                !limiter.allow_at(src, now),
                "changing burst must not refill the bucket"
            );
            assert!(limiter.allow_at(src, now + Duration::from_millis(50)));
            assert!(!limiter.allow_at(src, now + Duration::from_millis(50)));
            limiter.set_rate(10, 2);
        }
    }

    /// Rate and burst changes made at runtime take effect immediately:
    /// unlimited, then limited, then unlimited again.
    #[test]
    fn test_rate_limiter_runtime_adjust() {
        // Starts unlimited (rate 0): always allows and allocates no buckets.
        let limiter = RateLimiter::with_burst(0, 0);
        let src = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        for _ in 0..1000 {
            assert!(limiter.allow(src), "rate 0 = unlimited");
        }

        // Control plane turns limiting on at runtime.
        limiter.set_rate(2, 2);
        assert_eq!(limiter.rate(), 2);
        assert_eq!(limiter.burst(), 2);
        let src2 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
        assert!(limiter.allow(src2));
        assert!(limiter.allow(src2));
        assert!(
            !limiter.allow(src2),
            "fresh bucket holds `burst` tokens; third immediate packet drops"
        );

        // And back to unlimited.
        limiter.set_rate(0, 0);
        assert!(limiter.allow(src2), "back to unlimited");
    }

    #[test]
    fn test_rate_limiter_burst_exhausts_then_denies() {
        let limiter = RateLimiter::with_burst(/* rate */ 1, /* burst */ 5);
        let src = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        // First 5 calls consume one token each and are accepted.
        for i in 0..5 {
            assert!(limiter.allow(src), "call {i} must be accepted within burst");
        }
        // 6th call: bucket empty (no time has passed → no refill yet),
        // must be denied.
        assert!(
            !limiter.allow(src),
            "burst+1 call must be denied when bucket is empty"
        );
    }

    /// Multi-client isolation: one greedy source MUST NOT drain another's
    /// budget. Both clients see the same independent burst capacity.
    #[test]
    fn test_rate_limiter_multi_client_isolation() {
        let limiter = RateLimiter::with_burst(1, 3);
        let greedy = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let polite = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));

        // Greedy client drains its bucket.
        for _ in 0..3 {
            assert!(limiter.allow(greedy));
        }
        assert!(!limiter.allow(greedy), "greedy client is now rate-limited");

        // Polite client must still have its full bucket available.
        for _ in 0..3 {
            assert!(
                limiter.allow(polite),
                "polite client's bucket must be unaffected by greedy client"
            );
        }
    }

    /// Sustained rate at the configured `rate` value must be sustainable
    /// (no false denies once the bucket is empty and the refill kicks in).
    /// Uses a real sleep so the test is timing-sensitive; keep the rate
    /// and sleep small.
    #[test]
    fn test_rate_limiter_sustained_rate_refills() {
        let limiter = RateLimiter::with_burst(100, 1);
        let src = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));

        // Drain the bucket.
        assert!(limiter.allow(src));
        assert!(!limiter.allow(src));

        // After ~15 ms the bucket should have refilled ≥ 1 token at
        // 100/sec.
        std::thread::sleep(Duration::from_millis(15));
        assert!(
            limiter.allow(src),
            "bucket must refill after at least one token's worth of time"
        );
    }

    /// Burst=0 in the explicit constructor falls back to `rate`, matching
    /// `--max-pps` without `--reflector-rate-burst` (one second of traffic).
    #[test]
    fn test_rate_limiter_burst_zero_falls_back_to_rate() {
        let limiter = RateLimiter::with_burst(7, 0);
        let src = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        // The bucket has 7 tokens initially.
        for _ in 0..7 {
            assert!(limiter.allow(src));
        }
        assert!(!limiter.allow(src));
    }
}
