//! Reflector counters, the per-source rate limiter, and the runtime-adjustable
//! Type 12 caps.

use super::*;

/// Aggregate packet counters for the reflector.
pub struct ReflectorCounters {
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
    /// session — duplicates or replays
    /// (RFC 10052 §5). Counted whether or not
    /// `--drop-replayed` acts on them; when it does, they are also included in
    /// `packets_dropped`.
    pub packets_replayed: AtomicU64,
    /// Received packets behind the session's high-water mark but not seen
    /// before: late or reordered delivery. Ordinary on a real path, tracked
    /// alongside the replay count so an operator can tell benign reordering
    /// from an actual duplicate.
    pub packets_reordered: AtomicU64,
}

impl ReflectorCounters {
    pub fn new() -> Self {
        ReflectorCounters {
            reply_queue_rejected: AtomicU64::new(0),
            queued_replies_cancelled: AtomicU64::new(0),
            packets_received: AtomicU64::new(0),
            packets_reflected: AtomicU64::new(0),
            packets_dropped: AtomicU64::new(0),
            packets_rate_limited: AtomicU64::new(0),
            packets_replayed: AtomicU64::new(0),
            packets_reordered: AtomicU64::new(0),
        }
    }
}

impl Default for ReflectorCounters {
    fn default() -> Self {
        Self::new()
    }
}

/// Token buckets keyed by source IP. Each refills at `rate` tokens/second up
/// to `burst`; every reply, including each Type-12 copy, costs one token.
///
/// The SSID is not part of the key: a sender chooses it freely, so keying on
/// it would let one source multiply its budget.
pub struct RateLimiter {
    /// Tokens/second; 0 = unlimited (always allow, no bucket allocation).
    /// Runtime-adjustable via the control plane.
    rate: AtomicU32,
    /// Bucket capacity. Kept equal to `rate` when configured as 0.
    burst: AtomicU32,
    state: std::sync::Mutex<RateLimiterState>,
}

pub(super) struct RateLimiterState {
    last_cleanup: Instant,
    sources: StdHashMap<std::net::IpAddr, Bucket>,
}

pub(super) struct Bucket {
    tokens: f64,
    last_refill: Instant,
    last_seen: Instant,
}

impl RateLimiter {
    const BUCKET_TTL: Duration = Duration::from_secs(60);
    const CLEANUP_INTERVAL: Duration = Duration::from_secs(10);

    /// Creates a limiter with `rate` tokens/second and one second of burst capacity.
    pub fn new(rate: u32) -> Self {
        Self::with_burst(rate, rate)
    }

    /// Creates a limiter with an explicit token-bucket burst capacity.
    /// `burst` of 0 falls back to `rate`.
    pub fn with_burst(rate: u32, burst: u32) -> Self {
        let burst = if burst == 0 { rate } else { burst };
        let now = Instant::now();
        RateLimiter {
            rate: AtomicU32::new(rate),
            burst: AtomicU32::new(burst),
            state: std::sync::Mutex::new(RateLimiterState {
                last_cleanup: now,
                sources: StdHashMap::new(),
            }),
        }
    }

    /// Adjusts the rate and burst at runtime (control plane). `burst` of 0
    /// falls back to `rate`; `rate` of 0 disables limiting entirely.
    pub fn set_rate(&self, rate: u32, burst: u32) {
        let burst = if burst == 0 { rate } else { burst };
        self.rate.store(rate, std::sync::atomic::Ordering::Relaxed);
        self.burst
            .store(burst, std::sync::atomic::Ordering::Relaxed);
    }

    /// Current rate (tokens/second); 0 = unlimited.
    #[must_use]
    pub fn rate(&self) -> u32 {
        self.rate.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Current burst capacity.
    #[must_use]
    pub fn burst(&self) -> u32 {
        self.burst.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Takes one token from `src`'s bucket. Returns false, leaving the
    /// bucket unchanged, when it is empty.
    pub fn allow(&self, src: std::net::IpAddr) -> bool {
        let rate_now = self.rate();
        if rate_now == 0 {
            // Unlimited: skip the lock and allocate no buckets.
            return true;
        }
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let now = Instant::now();
        Self::cleanup_expired_buckets(&mut state, now);

        let burst = self.burst() as f64;
        let rate = rate_now as f64;
        let bucket = state.sources.entry(src).or_insert(Bucket {
            tokens: burst,
            last_refill: now,
            last_seen: now,
        });
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
        if now.duration_since(state.last_cleanup) < Self::CLEANUP_INTERVAL {
            return;
        }

        state
            .sources
            .retain(|_, bucket| now.duration_since(bucket.last_seen) < Self::BUCKET_TTL);
        state.last_cleanup = now;
    }
}

/// Reflector caps adjustable at runtime via the control plane.
/// Loaded per packet with Relaxed ordering — these are tuning knobs,
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

/// Default reflector cap on the reply packet size (in octets) the reflector
/// will pad up to when honouring a Reflected Control TLV `length` request.
/// This is an administrative payload limit, not an IP MTU. The shared send
/// path applies the actual route budget, including header overhead, for
/// RFC 10052 §3. A longer request gets a single
/// C-flagged reply if its mandatory fields fit. Operators can override the
/// administrative value via `--reflected-control-max-size` or the control API.
pub const REFLECTED_CONTROL_MAX_SIZE: u16 = 1500;

/// Default minimum inter-packet gap (nanoseconds) — the per-request *rate*
/// limit of RFC 10052 §3, and a floor that avoids
/// tight busy-loops in the backends. A multi-packet request with a shorter
/// interval collapses to a single reply with the C flag set. Operators can
/// override at runtime via `--reflected-control-min-interval-ns`.
pub const REFLECTED_CONTROL_MIN_INTERVAL_NS: u32 = 1_000;

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

    /// Synthetic burst exceeding the bucket size must produce exactly
    /// `burst` accepts then deny — no off-by-one in the consume logic.
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
        // First 5 calls consume one token each — accepted.
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
    /// Uses a real sleep so the test is timing-sensitive — keep the rate
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

    /// Burst=0 in the explicit constructor falls back to `rate`,
    /// preserving backward compatibility with the old `--max-pps` flag.
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
