//! STAMP Session Reflector implementations.
//!
//! Platform defaults with real TTL capture:
//! - **Linux/macOS**: Uses nix via IP_RECVTTL
//! - **Windows**: Uses pnet for raw packet capture
//!
//! Explicit overrides (for other platforms or to override defaults):
//! - **`ttl-nix`**: Force nix backend
//! - **`ttl-pnet`**: Force pnet backend

// Explicit feature flags take priority
#[cfg(feature = "ttl-nix")]
mod nix;
#[cfg(feature = "ttl-nix")]
pub use nix::run_receiver;

#[cfg(all(feature = "ttl-pnet", not(feature = "ttl-nix")))]
mod pnet;
#[cfg(all(feature = "ttl-pnet", not(feature = "ttl-nix")))]
pub use pnet::run_receiver;

// Platform defaults (when no explicit feature)
#[cfg(all(
    any(target_os = "linux", target_os = "macos"),
    not(feature = "ttl-nix"),
    not(feature = "ttl-pnet")
))]
mod nix;
#[cfg(all(
    any(target_os = "linux", target_os = "macos"),
    not(feature = "ttl-nix"),
    not(feature = "ttl-pnet")
))]
pub use nix::run_receiver;

#[cfg(all(
    target_os = "windows",
    not(feature = "ttl-nix"),
    not(feature = "ttl-pnet")
))]
mod pnet;
#[cfg(all(
    target_os = "windows",
    not(feature = "ttl-nix"),
    not(feature = "ttl-pnet")
))]
pub use pnet::run_receiver;

use std::collections::HashMap as StdHashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::{
    configuration::{ClockFormat, Configuration, TlvHandlingMode},
    cos_policy::CosAdmissionPolicy,
    crypto::{compute_packet_hmac, verify_packet_hmac, HmacKey},
    packets::{
        PacketAuthenticated, PacketUnauthenticated, ReflectedPacketAuthenticated,
        ReflectedPacketUnauthenticated,
    },
    session::SessionManager,
    stats::{self, OutputFormat},
    time::generate_timestamp,
    tlv::{
        LocationDisclosure, PacketAddressInfo, ReturnPathAction, SyncSource, TimestampMethod,
        TlvList, TlvType, HMAC_TLV_VALUE_SIZE, REFLECTED_CONTROL_SUBTLV_IPV6_EXT_HDR_CONTROL,
        TLV_HEADER_SIZE,
    },
};

/// Returns the list of local IP addresses used for Destination Node Address
/// TLV matching (RFC 9503 §4).
///
/// When `bind_addr` is a wildcard (`0.0.0.0` or `::`), enumerates every
/// interface address on the system. Otherwise returns just `bind_addr`.
///
/// Interface enumeration uses the `nix` crate on Unix and `pnet::datalink` on
/// Windows — both produce the same logical output.
pub fn build_local_addresses(bind_addr: std::net::IpAddr) -> Vec<std::net::IpAddr> {
    let is_wildcard = match bind_addr {
        std::net::IpAddr::V4(v4) => v4.is_unspecified(),
        std::net::IpAddr::V6(v6) => v6.is_unspecified(),
    };
    if !is_wildcard {
        return vec![bind_addr];
    }

    let addrs = enumerate_interface_addresses();
    if addrs.is_empty() {
        log::warn!(
            "Could not enumerate local addresses; Destination Node Address matching may fail"
        );
        vec![bind_addr]
    } else {
        addrs
    }
}

#[cfg(unix)]
fn enumerate_interface_addresses() -> Vec<std::net::IpAddr> {
    let mut addrs = Vec::new();
    if let Ok(ifaddrs) = ::nix::ifaddrs::getifaddrs() {
        for ifaddr in ifaddrs {
            if let Some(addr) = ifaddr.address {
                if let Some(v4) = addr.as_sockaddr_in() {
                    addrs.push(std::net::IpAddr::V4(v4.ip()));
                } else if let Some(v6) = addr.as_sockaddr_in6() {
                    addrs.push(std::net::IpAddr::V6(v6.ip()));
                }
            }
        }
    }
    addrs
}

#[cfg(not(unix))]
fn enumerate_interface_addresses() -> Vec<std::net::IpAddr> {
    // Windows has no `getifaddrs`; fall back to pnet's datalink enumeration.
    // pnet is always a build dependency on Windows (default ttl-pnet backend).
    // Use absolute `::pnet` so we resolve the external crate, not the
    // sibling `crate::receiver::pnet` submodule.
    ::pnet::datalink::interfaces()
        .into_iter()
        .flat_map(|iface| iface.ips.into_iter().map(|n| n.ip()))
        .collect()
}

/// Returns the list of local MAC addresses used for the Reflected Test
/// Packet Control TLV's L2 Address Group sub-TLV matching
/// (draft-ietf-ippm-asymmetrical-pkts-14 §3.1.1).
///
/// Unlike [`build_local_addresses`], MAC addresses aren't scoped to a bind
/// address — every interface's hardware address is a candidate regardless
/// of which IP the reflector is bound to — so this always enumerates every
/// interface. Enumeration failures (missing permissions, an unsupported
/// platform, no interfaces with a hardware address) degrade to an empty
/// list rather than panicking; per §3.1.1 an empty list simply means any
/// incoming L2 Address Group sub-TLV will fail to match (packet dropped),
/// which is spec-correct, not a bug.
pub fn build_local_macs() -> Vec<[u8; 6]> {
    let macs = enumerate_interface_macs();
    if macs.is_empty() {
        log::warn!(
            "Could not enumerate local MAC addresses; L2 Address Group sub-TLV \
             requests will never match (packets requesting one will be dropped)"
        );
    }
    macs
}

#[cfg(unix)]
fn enumerate_interface_macs() -> Vec<[u8; 6]> {
    // `SockaddrStorage::as_link_addr()` transparently covers AF_PACKET on
    // Linux (`sockaddr_ll`) and AF_LINK on macOS/BSD (`sockaddr_dl`) — both
    // are exposed through the same `nix::sys::socket::LinkAddr::addr()`
    // accessor, so no per-OS branching is needed here (mirrors how
    // `enumerate_interface_addresses` uses `as_sockaddr_in`/`_in6` above).
    let mut macs = Vec::new();
    if let Ok(ifaddrs) = ::nix::ifaddrs::getifaddrs() {
        for ifaddr in ifaddrs {
            if let Some(addr) = ifaddr.address {
                if let Some(link) = addr.as_link_addr() {
                    if let Some(mac) = link.addr() {
                        if mac != [0u8; 6] && !macs.contains(&mac) {
                            macs.push(mac);
                        }
                    }
                }
            }
        }
    }
    macs
}

#[cfg(not(unix))]
fn enumerate_interface_macs() -> Vec<[u8; 6]> {
    // Use absolute `::pnet` so we resolve the external crate, not the
    // sibling `crate::receiver::pnet` submodule (see
    // `enumerate_interface_addresses` above for the same convention).
    let mut macs = Vec::new();
    for iface in ::pnet::datalink::interfaces() {
        if let Some(::pnet::util::MacAddr(a, b, c, d, e, f)) = iface.mac {
            let mac = [a, b, c, d, e, f];
            if mac != [0u8; 6] && !macs.contains(&mac) {
                macs.push(mac);
            }
        }
    }
    macs
}

/// Loads the HMAC key from configuration (hex string or file).
///
/// Single-key path retained for backward compatibility. Operators using
/// per-SSID keys should call `load_hmac_key_set` instead — see B6.
pub fn load_hmac_key(conf: &Configuration) -> Option<HmacKey> {
    if let Some(ref hex_key) = conf.hmac_key {
        match HmacKey::from_hex(hex_key.as_str()) {
            Ok(key) => return Some(key),
            Err(e) => {
                log::error!("Failed to parse HMAC key: {}", e);
                return None;
            }
        }
    }

    if let Some(ref path) = conf.hmac_key_file {
        match HmacKey::from_file(path) {
            Ok(key) => return Some(key),
            Err(e) => {
                log::error!("Failed to load HMAC key from file: {}", e);
                return None;
            }
        }
    }

    None
}

/// Loads the HMAC key *set* from configuration, supporting the three
/// mutually-exclusive sources (`--hmac-key`, `--hmac-key-file`,
/// `--hmac-key-dir`).
///
/// - Single key (`--hmac-key` / `--hmac-key-file`) → set with that key
///   as the `default`, no per-SSID overrides. The reflector then uses
///   this key for every SSID, preserving the existing behaviour.
/// - Key directory (`--hmac-key-dir`) → per-SSID map plus optional
///   `default.key` fallback (see `crypto::HmacKeySet::from_dir`).
/// - None of the three → returns `None`. Auth-mode validation in
///   `Configuration::validate` already rejects this case at startup.
pub fn load_hmac_key_set(conf: &Configuration) -> Option<crate::crypto::HmacKeySet> {
    use crate::crypto::HmacKeySet;

    if let Some(ref dir) = conf.hmac_key_dir {
        match HmacKeySet::from_dir(dir) {
            Ok(set) => {
                if set.is_empty() {
                    log::error!(
                        "HMAC key directory {:?} contained no usable keys",
                        dir.display()
                    );
                    return None;
                }
                return Some(set);
            }
            Err(e) => {
                log::error!(
                    "Failed to load HMAC key directory {:?}: {}",
                    dir.display(),
                    e
                );
                return None;
            }
        }
    }

    load_hmac_key(conf).map(HmacKeySet::with_default)
}

/// Peeks the SSID (RFC 8972 §3) field out of an incoming packet without
/// fully parsing the rest. Returns 0 if the buffer is too short — which
/// matches the RFC 8972 §4.1 "SSID 0 = unused" convention and is the
/// correct fallback for the per-SSID HMAC key lookup.
///
/// Offsets:
/// - Unauthenticated: bytes 14..16 (after seq, timestamp, error_estimate).
/// - Authenticated: bytes 26..28 (after seq, 12-byte MBZ, timestamp,
///   error_estimate).
fn peek_ssid(data: &[u8], use_auth: bool) -> u16 {
    let offset = if use_auth { 26 } else { 14 };
    if data.len() >= offset + 2 {
        u16::from_be_bytes([data[offset], data[offset + 1]])
    } else {
        0
    }
}

/// Resolves the HMAC key to use for an incoming packet.
///
/// Precedence (B6): if `ctx.hmac_key_set` is `Some`, that set is
/// authoritative — its `for_ssid(ssid)` lookup (with built-in default
/// fallback) determines the key. If `None`, the legacy single
/// `ctx.hmac_key` is used.
fn resolve_hmac_key<'a>(ctx: &'a ProcessingContext, ssid: u16) -> Option<&'a HmacKey> {
    if let Some(set) = ctx.hmac_key_set {
        return set.for_ssid(ssid);
    }
    ctx.hmac_key
}

/// Aggregate packet counters for the reflector.
pub struct ReflectorCounters {
    pub packets_received: AtomicU64,
    pub packets_reflected: AtomicU64,
    pub packets_dropped: AtomicU64,
    /// Subset of `packets_dropped`: packets refused because the per-client
    /// token bucket was empty. Distinguishing this from generic drops lets
    /// operators tell rate-limit pressure from parse / HMAC failures.
    pub packets_rate_limited: AtomicU64,
    /// Received packets whose Sequence Number had already been seen on that
    /// session — duplicates or replays
    /// (draft-ietf-ippm-asymmetrical-pkts-14 §5). Counted whether or not
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

/// Per-client token-bucket rate limiter.
///
/// Keys buckets by `(source_ip, ssid)` so multiple sessions from the same
/// host can share an IP without starving each other (and so a single
/// runaway SSID doesn't burn another client's budget). Each bucket
/// refills at `rate` tokens/second up to a maximum of `burst` tokens.
///
/// The default `allow()` consumes 1 token per call (one inbound packet).
/// `allow_n()` lets callers consume more — used by the Reflected Test
/// Packet Control (Type 12, draft-ietf-ippm-asymmetrical-pkts) extra-copy
/// emission so a request asking for N replies costs N tokens.
pub struct RateLimiter {
    /// Tokens/second; 0 = unlimited (always allow, no bucket allocation).
    /// Runtime-adjustable via the control plane.
    rate: AtomicU32,
    /// Bucket capacity. Kept equal to `rate` when configured as 0.
    burst: AtomicU32,
    state: std::sync::Mutex<RateLimiterState>,
}

struct RateLimiterState {
    last_cleanup: Instant,
    sources: StdHashMap<RateLimiterKey, Bucket>,
}

/// Bucket key — `(source_ip, ssid)` tuple. SSID 0 is the common case
/// when the sender doesn't set it explicitly (RFC 8972 §4.1: SSID 0
/// means "no session identifier").
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RateLimiterKey {
    pub src: std::net::IpAddr,
    pub ssid: u16,
}

impl RateLimiterKey {
    /// Convenience: build a key from just the source IP (SSID = 0).
    #[must_use]
    pub fn from_src(src: std::net::IpAddr) -> Self {
        Self { src, ssid: 0 }
    }
}

struct Bucket {
    tokens: f64,
    last_refill: Instant,
    last_seen: Instant,
}

impl RateLimiter {
    const BUCKET_TTL: Duration = Duration::from_secs(60);
    const CLEANUP_INTERVAL: Duration = Duration::from_secs(10);

    /// Creates a limiter with `rate` tokens/second and a burst capacity
    /// equal to `rate` (one-second worth). Equivalent to the historic
    /// fixed-window limiter when traffic is steady, but more lenient on
    /// bursty traffic — matches the user-visible behaviour of the older
    /// `--max-pps` flag.
    pub fn new(rate: u32) -> Self {
        Self::with_burst(rate, rate)
    }

    /// Creates a limiter with an explicit token-bucket burst capacity.
    /// `burst` of 0 falls back to `rate` to match the simple-flag semantic.
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

    /// Returns true if a single packet should be allowed for the given
    /// source IP. SSID defaults to 0 — callers that have SSID context
    /// should use `allow_keyed()` instead.
    pub fn allow(&self, src: std::net::IpAddr) -> bool {
        self.allow_n(RateLimiterKey::from_src(src), 1)
    }

    /// Returns true if a packet should be allowed for the given
    /// (source IP, SSID) bucket.
    pub fn allow_keyed(&self, key: RateLimiterKey) -> bool {
        self.allow_n(key, 1)
    }

    /// Returns true if `cost` tokens can be consumed from the bucket. On
    /// false the bucket is left unchanged (no partial consumption).
    pub fn allow_n(&self, key: RateLimiterKey, cost: u32) -> bool {
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
        let bucket = state.sources.entry(key).or_insert(Bucket {
            tokens: burst,
            last_refill: now,
            last_seen: now,
        });
        // Refill since last touch.
        let elapsed = now.duration_since(bucket.last_refill).as_secs_f64();
        bucket.tokens = (bucket.tokens + elapsed * rate).min(burst);
        bucket.last_refill = now;
        bucket.last_seen = now;

        if bucket.tokens >= cost as f64 {
            bucket.tokens -= cost as f64;
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
    /// Type 12 reply-size cap in octets (egress-MTU stand-in).
    pub reflected_control_max_size: std::sync::atomic::AtomicU16,
    /// Startup-immutable payload ceiling discovered from the live egress MTU
    /// (`u16::MAX` when undiscoverable). Control-plane updates to
    /// `reflected_control_max_size` are clamped to this, so a runtime PATCH
    /// cannot reintroduce replies that fragment on the link.
    pub reflected_control_size_ceiling: u16,
    /// Type 12 rate limit: minimum inter-packet interval in nanoseconds.
    pub reflected_control_min_interval_ns: AtomicU32,
}

impl RuntimeCaps {
    /// Builds the caps from startup configuration.
    #[must_use]
    pub fn from_conf(conf: &Configuration) -> Self {
        Self {
            reflected_control_max_count: std::sync::atomic::AtomicU16::new(
                conf.reflected_control_max_count,
            ),
            // Live egress MTU, when it can be read, bounds this alongside the
            // configured value (draft-ietf-ippm-asymmetrical-pkts-14 §3).
            reflected_control_max_size: std::sync::atomic::AtomicU16::new(
                effective_reflected_control_max_size(conf),
            ),
            reflected_control_size_ceiling: reflected_control_size_ceiling(conf),
            reflected_control_min_interval_ns: AtomicU32::new(
                conf.reflected_control_min_interval_ns,
            ),
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
            reflected_control_size_ceiling: u16::MAX,
            reflected_control_min_interval_ns: AtomicU32::new(REFLECTED_CONTROL_MIN_INTERVAL_NS),
        }
    }
}

/// Shared state created externally and passed into receiver backends.
///
/// This allows the SNMP sub-agent, the control plane, and other
/// subsystems to access reflector counters and session state concurrently.
pub struct ReceiverSharedState {
    pub counters: Arc<ReflectorCounters>,
    pub session_manager: Arc<SessionManager>,
    pub start_time: Instant,
    /// Always constructed; `rate() == 0` means unlimited, so limiting can
    /// be enabled at runtime via the control plane.
    pub rate_limiter: Arc<RateLimiter>,
    /// Flag observable by a future readiness probe (and the pnet
    /// `spawn_blocking` join path). Set to `false` when the capture / receive
    /// loop exits unexpectedly so external monitors can distinguish
    /// "process alive but not reflecting" from "process alive and healthy".
    pub capture_alive: Arc<std::sync::atomic::AtomicBool>,
    /// Per-SSID HMAC keyset; runtime-mutable via the control plane. The
    /// legacy single `--hmac-key` stays startup-immutable and backend-local.
    /// Packet loops take short read guards that never cross an `.await`.
    pub hmac_keys: Arc<std::sync::RwLock<Option<crate::crypto::HmacKeySet>>>,
    /// Runtime-adjustable reflector caps (see [`RuntimeCaps`]).
    pub caps: Arc<RuntimeCaps>,
    /// Set by the control plane's shutdown endpoint; both backends poll it
    /// and exit gracefully.
    pub shutdown_requested: Arc<std::sync::atomic::AtomicBool>,
}

/// Creates the shared state for the receiver, using configuration values.
pub fn create_shared_state(conf: &Configuration) -> ReceiverSharedState {
    let session_timeout = if conf.session_timeout > 0 {
        Some(Duration::from_secs(conf.session_timeout))
    } else {
        None
    };

    // Always constructed: rate 0 short-circuits to "allow", and the
    // control plane can raise the rate at runtime.
    let rate_limiter = Arc::new(RateLimiter::with_burst(
        conf.max_pps,
        conf.reflector_rate_burst,
    ));

    // Bound the session table so an unauthenticated peer cannot grow it until
    // the process is OOM-killed (0 = operator-disabled, unlimited).
    let max_sessions = if conf.max_sessions > 0 {
        Some(conf.max_sessions as usize)
    } else {
        None
    };

    ReceiverSharedState {
        counters: Arc::new(ReflectorCounters::new()),
        session_manager: Arc::new(SessionManager::new(session_timeout, max_sessions)),
        start_time: Instant::now(),
        rate_limiter,
        capture_alive: Arc::new(std::sync::atomic::AtomicBool::new(true)),
        hmac_keys: Arc::new(std::sync::RwLock::new(load_hmac_key_set(conf))),
        caps: Arc::new(RuntimeCaps::from_conf(conf)),
        shutdown_requested: Arc::new(std::sync::atomic::AtomicBool::new(false)),
    }
}

/// Builds and prints the reflector shutdown statistics.
pub fn print_reflector_stats(
    counters: &ReflectorCounters,
    session_manager: &SessionManager,
    start_time: Instant,
    output_format: OutputFormat,
) {
    let stats = stats::build_reflector_stats(
        counters.packets_received.load(Ordering::Relaxed),
        counters.packets_reflected.load(Ordering::Relaxed),
        counters.packets_dropped.load(Ordering::Relaxed),
        session_manager.session_summaries(),
        session_manager.session_count(),
        start_time.elapsed().as_secs_f64(),
    );
    stats.print(output_format);
}

/// HMAC field offset in ReflectedPacketAuthenticated (bytes before HMAC field).
pub const REFLECTED_AUTH_PACKET_HMAC_OFFSET: usize = 96;

/// Marks the CoS TLV in a serialized response as "requested CoS not applied":
/// RPD=0b01 (DSCP1 not used, RFC 8972 §4.4) and RPE=0b10 (unable to set the
/// reply's ECN to EC1, draft-ietf-ippm-stamp-cos-ecn-01 §3.2).
///
/// Called by the backends when setsockopt fails to apply the requested
/// DSCP/ECN to the reply packet. The caller must recompute the TLV HMAC
/// afterwards (see `recompute_response_tlv_hmac`), and — per the -01 MUST
/// rule — must also attempt to re-apply the reply's on-wire TOS/TCLASS with
/// the ECN bits forced to 0b00 (see [`cos_unable_fallback_tos`]); this
/// function only maintains the TLV bits, not the IP header.
///
/// # Arguments
/// * `response` - The response buffer containing TLVs after the base packet
/// * `base_packet_size` - Size of the base packet (44 for unauth, 112 for auth)
///
/// # Returns
/// `true` if a CoS TLV was found and updated, `false` otherwise.
pub fn set_cos_policy_rejected(response: &mut [u8], base_packet_size: usize) -> bool {
    if response.len() <= base_packet_size {
        return false; // No TLV area
    }

    let tlv_area = &mut response[base_packet_size..];
    let mut offset = 0;

    while offset + TLV_HEADER_SIZE <= tlv_area.len() {
        // Check for trailing zero-padding: only treat all-zero header as padding
        // if ALL remaining bytes are zeros. A Reserved TLV (type=0) with zero-length
        // is valid and should not stop iteration if followed by real TLVs.
        if tlv_area[offset..offset + TLV_HEADER_SIZE] == [0, 0, 0, 0]
            && tlv_area[offset..].iter().all(|&b| b == 0)
        {
            break;
        }

        let tlv_type = TlvType::from_byte(tlv_area[offset + 1]);
        let length = u16::from_be_bytes([tlv_area[offset + 2], tlv_area[offset + 3]]) as usize;
        let value_start = offset + TLV_HEADER_SIZE;
        let value_end = value_start + length.min(tlv_area.len() - value_start);

        if tlv_type == TlvType::ClassOfService && value_end >= value_start + 3 {
            // CoS TLV found. The backend failed to apply the requested TOS
            // (DSCP1 + EC1) to the reply, so report both halves:
            // - RPD (value byte 1, bits 1:0) = 0b01 — DSCP1 not used
            //   (RFC 8972 §4.4 / draft-ietf-ippm-stamp-cos-ecn-01 §3.2);
            // - RPE (value byte 2, bits 5:4) = 0b10 — unable to set the
            //   reply's ECN to EC1 (cos-ecn-01 §3.2), overwriting the
            //   optimistic 0b11 written during TLV processing.
            tlv_area[value_start + 1] = (tlv_area[value_start + 1] & 0xFC) | 0b01;
            tlv_area[value_start + 2] = (tlv_area[value_start + 2] & 0xCF) | (0b10 << 4);
            return true;
        }

        offset += TLV_HEADER_SIZE + length;
    }

    false
}

/// Computes the fallback reply TOS (IPv4) / Traffic Class (IPv6) byte the
/// backends must try to apply to the reply packet's IP header after the
/// primary `IP_TOS`/`IPV6_TCLASS` setsockopt call for the requested
/// DSCP1/EC1 fails and [`set_cos_policy_rejected`] marks the CoS TLV
/// RPD=0b01/RPE=0b10.
///
/// Per draft-ietf-ippm-stamp-cos-ecn-01 §3.2, when the reflector is unable
/// to set the reply's ECN to EC1 it MUST additionally zero the reply's
/// on-wire ECN bits (0b00, Not-ECT) instead of leaving whatever value the
/// packet previously carried, as -00 permitted. The DSCP half falls back to
/// the received DSCP (DSCP2), consistent with the RPD=0b01 already
/// reported. This is a best-effort retry: if the underlying transport
/// truly cannot set any TOS/TCLASS value on the socket, the second attempt
/// will also fail and the on-wire ECN bits may remain non-conformant — see
/// callers for the graceful-fallback handling of that case.
///
/// Mirrors [`crate::tlv::ClassOfServiceTlv::reply_wire_tos`] for the
/// "unable" state (`policy_rejected = true`, `ecn_applied = false`); see
/// that method's tests for the underlying bit arithmetic.
#[must_use]
pub fn cos_unable_fallback_tos(received_dscp: u8) -> u8 {
    (received_dscp & 0x3F) << 2
}

/// Decides whether the cos-ecn-01 §3.2 zero-ECN fallback is worth a
/// `setsockopt` call.
///
/// The fallback exists to force the reply's ECN bits to Not-ECT after the
/// requested DSCP1/EC1 byte was refused. Two cases make the retry pointless:
///
/// - `fallback == attempted`: the byte the fallback would set is the very byte
///   the kernel just rejected (happens when EC1 is already 0b00 and DSCP1
///   equals the received DSCP, so zeroing the ECN half changes nothing).
///   Re-issuing it can only fail again.
/// - `fallback == last`: that byte is already applied to the socket, so the
///   on-wire ECN bits are already conformant.
///
/// Keeping this out of the backend loops means both `nix` and `pnet` share one
/// tested rule.
#[must_use]
pub fn should_apply_fallback_tos(attempted: u8, fallback: u8, last: u8) -> bool {
    fallback != attempted && fallback != last
}

/// Reads an interface's MTU with `ioctl(SIOCGIFMTU)`.
///
/// The reflector cannot use the sender's `getsockopt(IP_MTU)` route lookup:
/// that only answers on a *connected* socket, and a reflector's socket is bound
/// to a local address and replies to arbitrary peers. Querying the egress
/// interface by name is the equivalent that works for a bound socket.
///
/// A throwaway UDP socket supplies the descriptor — `SIOCGIFMTU` only needs
/// *some* socket of the right family, not the reflector's own.
///
/// Returns `None` on any failure (unknown interface, permission, non-Linux), so
/// callers fall back to their configured value rather than losing the cap.
#[cfg(target_os = "linux")]
#[must_use]
pub fn interface_mtu(iface: &str) -> Option<u32> {
    use std::os::fd::AsRawFd;

    // `::nix` — inside this module, a bare `nix` would resolve to the sibling
    // `receiver::nix` backend module.
    use ::nix::libc;

    if iface.is_empty() || iface.len() >= libc::IFNAMSIZ {
        return None;
    }
    let probe = std::net::UdpSocket::bind(("0.0.0.0", 0)).ok()?;

    // SAFETY: `ifreq` is a plain C struct with no invalid bit patterns; an
    // all-zero value is a valid "empty request" before the name is filled in.
    let mut req: libc::ifreq = unsafe { std::mem::zeroed() };
    for (dst, byte) in req.ifr_name.iter_mut().zip(iface.as_bytes()) {
        *dst = *byte as libc::c_char;
    }

    // SAFETY: `fd` is an open socket owned for the call's duration and `req` is
    // a valid, correctly-sized `ifreq` the kernel writes the MTU into.
    let rc = unsafe { libc::ioctl(probe.as_raw_fd(), libc::SIOCGIFMTU, &mut req) };
    if rc != 0 {
        return None;
    }
    // SAFETY: SIOCGIFMTU populates the `ifru_mtu` arm of the union.
    let mtu = unsafe { req.ifr_ifru.ifru_mtu };
    (mtu > 0).then_some(mtu as u32)
}

#[cfg(not(target_os = "linux"))]
#[must_use]
pub fn interface_mtu(_iface: &str) -> Option<u32> {
    None
}

/// Largest STAMP payload (UDP payload) that fits in `mtu` without fragmenting.
///
/// `--reflected-control-max-size` bounds the *STAMP packet*, while an MTU bounds
/// the whole IP datagram, so the IP and UDP headers have to come off before the
/// two are comparable.
///
/// Floored at [`AUTH_BASE_SIZE`]: a cap below a reply's own mandatory base would
/// be unsatisfiable, and reporting the floor keeps the reply-shaping arithmetic
/// meaningful instead of collapsing to zero on an unusably small MTU.
#[must_use]
pub fn mtu_payload_cap(mtu: u32, is_ipv6: bool) -> u16 {
    use crate::tlv::{IPV4_FIXED_HEADER_SIZE, IPV6_FIXED_HEADER_SIZE};
    const UDP_HEADER: u32 = 8;

    let ip_hdr = if is_ipv6 {
        IPV6_FIXED_HEADER_SIZE as u32
    } else {
        IPV4_FIXED_HEADER_SIZE as u32
    };
    let payload = mtu.saturating_sub(ip_hdr).saturating_sub(UDP_HEADER);
    let clamped = payload.min(u16::MAX as u32) as u16;
    clamped.max(AUTH_BASE_SIZE as u16)
}

/// Resolves the reply-size cap the reflector should actually enforce
/// (draft-ietf-ippm-asymmetrical-pkts-14 §3).
///
/// `--reflected-control-max-size` stands in for the egress MTU, and the draft's
/// MTU-exceeded behaviour is only correct insofar as it matches reality. This
/// takes the **smaller** of the configured value and the live interface MTU's
/// payload capacity, so:
///
/// - an operator who left the default (1500) on a 1500-byte link no longer
///   invites a 1528-byte datagram — the STAMP payload cap becomes 1472 and the
///   draft's C-flag/MTU path fires where it genuinely should;
/// - an operator who deliberately configured something smaller keeps it;
/// - a jumbo link is not silently capped at a stale 1500 if the operator raised
///   the flag to match.
///
/// Best-effort by design (per this project's convention for anything that
/// depends on the platform): a wildcard bind has no single egress interface, and
/// a failed or unavailable query leaves the configured value untouched.
#[must_use]
pub fn effective_reflected_control_max_size(conf: &Configuration) -> u16 {
    let configured = conf.reflected_control_max_size;
    let live = reflected_control_size_ceiling(conf);
    let effective = configured.min(live);
    if effective != configured {
        log::info!(
            "reply-size cap reduced from {configured} to {effective} bytes: the egress              MTU leaves {live} bytes of STAMP payload              (draft-ietf-ippm-asymmetrical-pkts-14 §3)"
        );
    }
    effective
}

/// The payload ceiling discovered from the live egress MTU, independent of
/// the configured `--reflected-control-max-size`: what the link can carry,
/// as opposed to what the operator asked for. `u16::MAX` when no single
/// interface / MTU can be determined (wildcard bind, failed query).
///
/// Stored in [`RuntimeCaps`] at startup so control-plane cap updates stay
/// bounded by it — a runtime PATCH must not reintroduce Type 12 replies
/// that fragment or fail on the live link.
#[must_use]
pub fn reflected_control_size_ceiling(conf: &Configuration) -> u16 {
    let Some(iface) = crate::hwtstamp::interface_for_addr(conf.local_addr) else {
        log::debug!(
            "egress MTU not queried (no single interface for {}); reply-size cap              unbounded by MTU",
            conf.local_addr
        );
        return u16::MAX;
    };
    let Some(mtu) = interface_mtu(&iface) else {
        log::debug!("egress MTU unavailable on {iface}; reply-size cap unbounded by MTU");
        return u16::MAX;
    };
    let live = mtu_payload_cap(mtu, conf.local_addr.is_ipv6());
    log::debug!("egress MTU on {iface} is {mtu}: {live} bytes of STAMP payload");
    live
}

/// Classifies a received packet against its session's replay window and counts
/// the result (draft-ietf-ippm-asymmetrical-pkts-14 §5).
///
/// The Sequence Number is the first four octets of the base packet in both the
/// authenticated and unauthenticated layouts (RFC 8762 §4.2/§4.3), so no full
/// parse is needed — this runs before processing, on the bytes as received.
///
/// Shared by both backends so detection cannot drift between them. Returns the
/// verdict; acting on it (`--drop-replayed`) is the caller's decision, because
/// a duplicate is not proof of an attack: a sender restarted mid-run produces
/// the same pattern, and dropping its traffic would break an honest
/// measurement.
///
/// Classification only — the window is NOT advanced here. This runs before
/// parse/HMAC verification, and an unverified packet must never be able to
/// plant a sequence number in the anti-replay state (a spoofed packet with a
/// predicted sequence number would otherwise get the genuine one dropped
/// under `--drop-replayed`). Backends call [`commit_replay`] after the packet
/// has been verified and answered.
///
/// Logging stays at debug level deliberately. A replay is attacker-controlled
/// input, so warning per event would hand a remote peer a log-amplification
/// lever; the counters (visible over the control plane) are the operator's
/// signal, and they cannot be flooded.
pub fn evaluate_replay(
    session: &crate::session::Session,
    data: &[u8],
    counters: &ReflectorCounters,
) -> crate::session::ReplayVerdict {
    use crate::session::ReplayVerdict;

    if data.len() < 4 {
        // Too short to carry a Sequence Number; the base-packet length rules
        // (RFC 8762 §4.6, `--strict-packets`) deal with it downstream.
        return ReplayVerdict::New;
    }
    let seq = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
    let verdict = session.classify_replay(seq);
    match verdict {
        ReplayVerdict::Replay => {
            counters
                .packets_replayed
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            log::debug!(
                "replayed sequence number {seq} on session {}",
                session.get_id()
            );
        }
        ReplayVerdict::Reordered | ReplayVerdict::OutOfWindow => {
            counters
                .packets_reordered
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            log::debug!(
                "out-of-order sequence number {seq} ({verdict:?}) on session {}",
                session.get_id()
            );
        }
        ReplayVerdict::New => {}
    }
    verdict
}

/// Records a *verified* packet's Sequence Number in its session's replay
/// window — the mutating counterpart of [`evaluate_replay`]. Both backends
/// call this once processing has produced a response, i.e. after the packet
/// survived parsing and (when a key is configured) HMAC verification, so only
/// authenticated traffic can advance the anti-replay state.
pub fn commit_replay(session: &crate::session::Session, data: &[u8]) {
    if data.len() < 4 {
        return;
    }
    let seq = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
    session.commit_replay(seq);
}

/// Sets the U-flag on the Return Path TLV in a serialized STAMP response.
///
/// Walks the TLV area to find a Return Path TLV (type 10) and sets its
/// unrecognized flag. Used when the reflector cannot honor the requested
/// return path (e.g., alternate-address send failure) per RFC 9503 §5.
///
/// Returns `true` if the Return Path TLV was found and updated.
pub fn set_return_path_u_flag_in_response(response: &mut [u8], base_packet_size: usize) -> bool {
    if response.len() <= base_packet_size {
        return false;
    }

    let tlv_area = &mut response[base_packet_size..];
    let mut offset = 0;

    while offset + TLV_HEADER_SIZE <= tlv_area.len() {
        if tlv_area[offset..offset + TLV_HEADER_SIZE] == [0, 0, 0, 0]
            && tlv_area[offset..].iter().all(|&b| b == 0)
        {
            break;
        }

        let tlv_type = TlvType::from_byte(tlv_area[offset + 1]);
        let length = u16::from_be_bytes([tlv_area[offset + 2], tlv_area[offset + 3]]) as usize;

        if tlv_type == TlvType::ReturnPath {
            // Set U-flag (bit 7) on the flags byte
            tlv_area[offset] |= 0x80;
            return true;
        }

        offset += TLV_HEADER_SIZE + length;
    }

    false
}

/// Recomputes the TLV HMAC in a serialized STAMP response after in-place mutation.
///
/// This must be called after any modification to the TLV area of an already-assembled
/// response (e.g., after `set_cos_policy_rejected` sets the RP flag) to keep the
/// HMAC consistent with the packet contents.
///
/// The function locates the HMAC TLV at the end of the response (per RFC 8972 §4.8,
/// HMAC TLV is always last), recomputes the HMAC over `seq_bytes + preceding TLVs`,
/// and overwrites the HMAC value in place.
///
/// Returns `true` if the HMAC was recomputed, `false` if no HMAC TLV was found.
pub fn recompute_response_tlv_hmac(
    data: &mut [u8],
    base_packet_size: usize,
    hmac_key: &HmacKey,
) -> bool {
    // HMAC TLV: header (4 bytes) + value (16 bytes) = 20 bytes total
    const HMAC_TLV_SIZE: usize = TLV_HEADER_SIZE + 16;

    if data.len() < base_packet_size + HMAC_TLV_SIZE || data.len() < 4 {
        return false;
    }

    // HMAC TLV is always serialized last (TlvList::write_to guarantees this)
    let hmac_tlv_offset = data.len() - HMAC_TLV_SIZE;

    // Verify the last TLV is actually an HMAC TLV (type byte at offset 1 in header)
    if TlvType::from_byte(data[hmac_tlv_offset + 1]) != TlvType::Hmac {
        return false;
    }

    // HMAC input: seq_bytes (first 4 bytes of packet) + all TLV bytes before the HMAC TLV
    let preceding_len = hmac_tlv_offset - base_packet_size;
    let mut hmac_input = Vec::with_capacity(4 + preceding_len);
    hmac_input.extend_from_slice(&data[..4]);
    hmac_input.extend_from_slice(&data[base_packet_size..hmac_tlv_offset]);

    let hmac = hmac_key.compute(&hmac_input);

    // Overwrite HMAC value in place (value starts after the 4-byte header)
    let value_start = hmac_tlv_offset + TLV_HEADER_SIZE;
    data[value_start..value_start + 16].copy_from_slice(&hmac);
    true
}

/// Assembles an unauthenticated reflected packet from a received test packet.
///
/// # Arguments
/// * `packet` - The received unauthenticated test packet
/// * `cs` - Clock format to use for timestamps
/// * `rcvt` - Receive timestamp when the packet was received
/// * `ttl` - TTL/Hop Limit value from the received packet's IP header
/// * `reflector_error_estimate` - The reflector's own error estimate in wire format
/// * `reflector_seq` - Optional independent reflector sequence number (RFC 8972 stateful mode)
pub fn assemble_unauth_answer(
    packet: &PacketUnauthenticated,
    cs: ClockFormat,
    rcvt: u64,
    ttl: u8,
    reflector_error_estimate: u16,
    reflector_seq: Option<u32>,
) -> ReflectedPacketUnauthenticated {
    // RFC 8972 §4.1.1: both SSID fields carry the Session-Sender Identifier
    // from the received test packet (the reflector tracks sessions by SSID).
    ReflectedPacketUnauthenticated {
        sess_sender_timestamp: packet.timestamp,
        sess_sender_err_estimate: packet.error_estimate,
        sess_sender_seq_number: packet.sequence_number,
        sess_sender_ssid: packet.ssid,
        sess_sender_ttl: ttl,
        sequence_number: reflector_seq.unwrap_or(packet.sequence_number),
        error_estimate: reflector_error_estimate,
        timestamp: generate_timestamp(cs),
        receive_timestamp: rcvt,
        ssid: packet.ssid,
        mbz3: [0; 3],
    }
}

/// Base size of unauthenticated STAMP packets.
pub const UNAUTH_BASE_SIZE: usize = 44;

/// Base size of authenticated STAMP packets.
pub const AUTH_BASE_SIZE: usize = 112;

/// HMAC offset in authenticated sender packets (for verifying incoming packets).
const AUTH_PACKET_HMAC_OFFSET: usize = 96;

/// Behaviour requested by a Reflected Test Packet Control TLV
/// (draft-ietf-ippm-asymmetrical-pkts §3).
///
/// Tells the backend how many *additional* copies of the reply to emit (on
/// top of the primary reply), and the inter-packet gap in nanoseconds. If
/// `extra_copies` is 0, no additional sends are needed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReflectedControlBehavior {
    /// Additional reply packets to emit after the primary reply
    /// (i.e. total replies = 1 + `extra_copies`).
    pub extra_copies: u16,
    /// Nanoseconds between consecutive sends.
    pub interval_ns: u32,
    /// Set when exactly one IPv6 Extension Header Control sub-TLV
    /// (draft-ietf-ippm-stamp-ext-hdr-11 §5.3) was present. Under -11 the
    /// sub-TLV asks the reflector to add matching IPv6 extension headers to
    /// its OWN reply packet. Neither backend can do that, so rule 4 sets the C
    /// flag in the reflected sub-TLV's Sub-TLV Flags (see
    /// `set_ipv6_ext_hdr_control_c_flag`); this bit only records that a single
    /// such sub-TLV was seen, for the send path once a reply-attachment
    /// capability exists. Left `false` on a cardinality violation
    /// (more than one sub-TLV), which is not actionable.
    pub suppress_reply_ext_headers: bool,
}

/// Example hard cap on total reply packets emitted for a single Reflected
/// Control request when the feature is enabled. Protects against request
/// amplification / DoS; the C flag is set when the requested count exceeds it.
///
/// Note: this is **not** the production default. The CLI default for
/// `--reflected-control-max-count` is 0 (asymmetric reflection disabled, per
/// draft-ietf-ippm-asymmetrical-pkts); this constant is the enabled-path cap
/// used by tests and as a suggested opt-in value.
pub const REFLECTED_CONTROL_MAX_COUNT: u16 = 16;

/// Default reflector cap on the reply packet size (in octets) the reflector
/// will pad up to when honouring a Reflected Control TLV `length` request —
/// the operator's stand-in for the egress-interface MTU in
/// draft-ietf-ippm-asymmetrical-pkts-14 §3. A longer request gets a single
/// reply padded to this cap with the C flag set. Defaults to a typical
/// Ethernet MTU. Operators can override at runtime via
/// `--reflected-control-max-size`.
pub const REFLECTED_CONTROL_MAX_SIZE: u16 = 1500;

/// Default minimum inter-packet gap (nanoseconds) — the per-request *rate*
/// limit of draft-ietf-ippm-asymmetrical-pkts-14 §3, and a floor that avoids
/// tight busy-loops in the backends. A multi-packet request with a shorter
/// interval collapses to a single reply with the C flag set. Operators can
/// override at runtime via `--reflected-control-min-interval-ns`.
pub const REFLECTED_CONTROL_MIN_INTERVAL_NS: u32 = 1_000;

/// Reflected Control sub-TLV types per draft-ietf-ippm-asymmetrical-pkts §3.
const REFLECTED_CONTROL_SUBTLV_L2_GROUP: u8 = 10;
const REFLECTED_CONTROL_SUBTLV_L3_GROUP: u8 = 11;

/// Parsed Reflected Control sub-TLV per draft-ietf-ippm-asymmetrical-pkts §3.
#[derive(Debug, Clone, PartialEq, Eq)]
enum ReflectedControlSubTlv {
    /// Layer 2 Address Group (sub-TLV type 10, draft-ietf-ippm-
    /// asymmetrical-pkts-14 §3.1.1) — bitwise mask/group filter matched
    /// against the reflector's own local MAC addresses. `mask` and `group`
    /// are always equal length (half of the validated Sub-TLV Length: 2, 6,
    /// or 8 octets).
    L2Group { mask: Vec<u8>, group: Vec<u8> },
    /// Layer 3 Address Group (sub-TLV type 11) — IP prefix match.
    L3Group { prefix_len: u8, prefix: Vec<u8> },
    /// IPv6 Extension Header Control (draft-ietf-ippm-stamp-ext-hdr-11
    /// §5.3) — presence-only (Sub-TLV Length 0) request to add matching IPv6
    /// extension headers to the reply. This reflector cannot add reply
    /// extension headers, so its presence yields the C flag on the reflected
    /// sub-TLV (rule 4); more than one is a cardinality violation.
    Ipv6ExtHdrControl,
    /// Anything else (including the 4-byte zero placeholder that pads the
    /// TLV to the draft-14 §3 12-octet minimum). Ignored by the reflector.
    Unknown {
        #[allow(dead_code)]
        type_byte: u8,
    },
}

/// Parses a chain of Reflected Control sub-TLVs from a raw byte slice. Uses
/// the standard 4-byte STAMP sub-TLV header (flags + type + length).
/// Returns an empty vec if the body is empty, malformed, or contains only
/// the all-zeros placeholder.
fn parse_reflected_control_sub_tlvs(body: &[u8]) -> Vec<ReflectedControlSubTlv> {
    let mut out = Vec::new();
    let mut offset = 0;
    while offset + TLV_HEADER_SIZE <= body.len() {
        let _flags = body[offset];
        let type_byte = body[offset + 1];
        let length = u16::from_be_bytes([body[offset + 2], body[offset + 3]]) as usize;
        let value_start = offset + TLV_HEADER_SIZE;
        let value_end = value_start.saturating_add(length);
        if value_end > body.len() {
            // Truncated; stop parsing here.
            break;
        }
        let value = &body[value_start..value_end];
        match type_byte {
            REFLECTED_CONTROL_SUBTLV_L2_GROUP => {
                // draft-ietf-ippm-asymmetrical-pkts-14 §3.1.1: Mask and Group
                // fields MUST be equal length, so valid Sub-TLV Length values
                // are exactly 4, 12, or 16 octets (2/6/8-byte halves). "Any
                // other value MUST be considered by the Session-Reflector as
                // a malformed sub-TLV" — mirroring the L3 Address Group
                // handling just below, we skip it rather than guess: no
                // `L2Group` entry is pushed, so a malformed sub-TLV simply
                // does not participate in matching (same treatment as an
                // out-of-range L3 prefix length).
                let len = value.len();
                if len == 4 || len == 12 || len == 16 {
                    let half = len / 2;
                    let mask = value[..half].to_vec();
                    let group = value[half..].to_vec();
                    out.push(ReflectedControlSubTlv::L2Group { mask, group });
                }
            }
            REFLECTED_CONTROL_SUBTLV_L3_GROUP => {
                // Draft §3.1.2: prefix_len(1) + reserved(3) + prefix(4 or 16).
                // Exactly 8 octets (IPv4) or 20 octets (IPv6); anything
                // else is malformed and we skip it rather than guess
                // (an earlier `>= 4 + 4 || >= 4 + 16` check was a
                // tautology that accepted any length ≥ 8).
                let len = value.len();
                if len == 4 + 4 || len == 4 + 16 {
                    let prefix_len = value[0];
                    let prefix = value[4..].to_vec();
                    out.push(ReflectedControlSubTlv::L3Group { prefix_len, prefix });
                }
            }
            // Presence-only; the draft defines no value fields, so any
            // length is accepted and the value ignored.
            REFLECTED_CONTROL_SUBTLV_IPV6_EXT_HDR_CONTROL => {
                out.push(ReflectedControlSubTlv::Ipv6ExtHdrControl);
            }
            // The all-zeros 4-byte header is a draft-14 §3 placeholder.
            0 if length == 0 => {}
            other => out.push(ReflectedControlSubTlv::Unknown { type_byte: other }),
        }
        offset = value_end;
    }
    out
}

/// Returns true if the L3 Address Group prefix matches any of the
/// reflector's local addresses. Per draft §3, the comparison is "bitwise
/// AND the prefix mask with each local address and check equality with
/// the prefix field." Empty `locals` is treated as "no match" (drop).
fn l3_group_matches_any_local(prefix_len: u8, prefix: &[u8], locals: &[std::net::IpAddr]) -> bool {
    use std::net::IpAddr;
    for local in locals {
        let local_bytes: Vec<u8> = match local {
            IpAddr::V4(v4) => v4.octets().to_vec(),
            IpAddr::V6(v6) => v6.octets().to_vec(),
        };
        if local_bytes.len() != prefix.len() {
            continue; // family mismatch
        }
        let prefix_bits = prefix_len as usize;
        if prefix_bits > local_bytes.len() * 8 {
            continue;
        }
        let full_bytes = prefix_bits / 8;
        let extra_bits = prefix_bits % 8;
        let mut matched = true;
        for i in 0..full_bytes {
            if local_bytes[i] != prefix[i] {
                matched = false;
                break;
            }
        }
        if matched && extra_bits > 0 {
            let mask = 0xFFu8 << (8 - extra_bits);
            if (local_bytes[full_bytes] & mask) != (prefix[full_bytes] & mask) {
                matched = false;
            }
        }
        if matched {
            return true;
        }
    }
    false
}

/// Returns true if the L2 Address Group mask/group matches any of the
/// reflector's local MAC addresses. Per draft-ietf-ippm-asymmetrical-pkts-14
/// §3.1.1: "If the Session-Reflector applies the value of the [Mask] field
/// (using a bitwise AND) to any of its MAC addresses with the same length
/// and the result is equal to the value of the [Group] field... continue
/// processing... If no matches are found, the Session-Reflector MUST stop
/// processing the received packet" (drop).
///
/// `mask` and `group` are always equal length (validated at parse time: 2,
/// 6, or 8 octets); both lengths are re-checked here so a short slice can
/// never index out of bounds. Every MAC enumerated by [`build_local_macs`] is a
/// 6-octet EUI-48, so only the 12-octet Sub-TLV Length (6+6) can ever
/// match — the 4- and 16-octet forms compare against nothing and always
/// fail to match (this reflector does not enumerate EUI-64 addresses).
/// Empty `locals` is treated as "no match" (drop), consistent with the L3
/// path above.
fn l2_group_matches_any_local(mask: &[u8], group: &[u8], locals: &[[u8; 6]]) -> bool {
    if mask.len() != 6 || group.len() != 6 {
        return false;
    }
    for local in locals {
        let matched = (0..6).all(|i| (local[i] & mask[i]) == group[i]);
        if matched {
            return true;
        }
    }
    false
}

/// Response from STAMP packet processing, including optional CoS request.
#[derive(Debug)]
pub struct StampResponse {
    /// The response packet data to send.
    pub data: Vec<u8>,
    /// Requested DSCP/ECN from CoS TLV (if present).
    /// Tuple of (dscp1, ecn1) that should be applied to the outgoing packet.
    pub cos_request: Option<(u8, u8)>,
    /// Action determined by Return Path TLV processing (RFC 9503 §5).
    pub return_path_action: ReturnPathAction,
    /// Extra-replies descriptor from a Reflected Test Packet Control TLV
    /// (draft-ietf-ippm-asymmetrical-pkts §3). `None` when the incoming
    /// packet had no such TLV.
    pub reflected_control: Option<ReflectedControlBehavior>,
    /// IP source address the reply SHOULD be sent from, when a Destination
    /// Node Address TLV matched one of ours (RFC 9503 §3). `None` leaves source
    /// selection to the OS, which is also the fallback when pinning is
    /// unsupported or fails.
    pub reply_source: Option<std::net::IpAddr>,
}

/// Context for processing STAMP packets, shared between backends.
pub struct ProcessingContext<'a> {
    /// Clock format for timestamps.
    pub clock_source: ClockFormat,
    /// Error estimate in wire format.
    pub error_estimate_wire: u16,
    /// Single HMAC key (legacy single-tenant path). Used when no
    /// `hmac_key_set` is configured. Operators using `--hmac-key-dir`
    /// should populate `hmac_key_set` instead and leave this `None`.
    pub hmac_key: Option<&'a HmacKey>,
    /// Per-SSID HMAC key set (B6). When `Some`, the reflector resolves
    /// the verification + response-HMAC key against the incoming
    /// packet's SSID via [`crate::crypto::HmacKeySet::for_ssid`]; on no match
    /// the packet is rejected as if the wrong key was supplied. When
    /// `None`, the receiver falls back to `hmac_key`.
    pub hmac_key_set: Option<&'a crate::crypto::HmacKeySet>,
    /// Whether HMAC is required.
    pub require_hmac: bool,
    /// Session manager for stateful mode.
    pub session_manager: Option<&'a Arc<SessionManager>>,
    /// Whether the reflector runs in stateful mode (`--stateful-reflector`).
    /// Gates Follow-Up Telemetry reporting: in stateless mode (RFC 8762 §4.2)
    /// the Sequence Number and Follow-Up Timestamp fields MUST be zeroed
    /// (RFC 8972 §4.7-7) rather than carry the previous reflection.
    pub stateful_reflector: bool,
    /// TLV handling mode.
    pub tlv_mode: TlvHandlingMode,
    /// Whether to verify incoming TLV HMAC.
    pub verify_tlv_hmac: bool,
    /// Whether to use strict packet parsing.
    pub strict_packets: bool,
    /// Whether metrics recording is enabled.
    #[cfg(feature = "metrics")]
    pub metrics_enabled: bool,
    /// DSCP value received from IP header (6 bits, 0-63).
    pub received_dscp: u8,
    /// ECN value received from IP header (2 bits, 0-3).
    pub received_ecn: u8,
    /// Reflector packet receive count (for Direct Measurement TLV).
    pub reflector_rx_count: Option<u32>,
    /// Reflector packet transmit count (for Direct Measurement TLV).
    pub reflector_tx_count: Option<u32>,
    /// Packet address information (for Location TLV).
    pub packet_addr_info: Option<PacketAddressInfo>,
    /// Last reflection data: (seq, timestamp) for Follow-Up Telemetry TLV.
    pub last_reflection: Option<(u32, u64)>,
    /// Which Location TLV fields this reflector may report (RFC 8972 §4.2.2
    /// field-disclosure policy, `--location-disclose`).
    pub location_disclosure: LocationDisclosure,
    /// DSCP/ECN admission policy (RFC 8972 §4.4/§6, cos-ecn-01 §3.2): answers
    /// *permitted*, where the backends' setsockopt answers *capable*.
    pub cos_policy: &'a CosAdmissionPolicy,
    /// Local addresses for Destination Node Address TLV matching (RFC 9503 §4).
    pub local_addresses: &'a [std::net::IpAddr],
    /// Local MAC addresses for the Reflected Test Packet Control TLV's L2
    /// Address Group sub-TLV matching (draft-ietf-ippm-asymmetrical-pkts-14
    /// §3.1.1). Populated by [`build_local_macs`]; an empty slice means no
    /// L2 Address Group sub-TLV can ever match (the packet is dropped per
    /// spec, not treated as "unsupported").
    pub local_macs: &'a [[u8; 6]],
    /// Sender's UDP port for Return Path alternate address replies (RFC 9503 §5).
    pub sender_port: u16,
    /// Whether to honour a Return Path "Return Address" sub-TLV by replying to
    /// the peer-chosen address (RFC 9503 §5). Off by default; when off the
    /// reflector echoes the TLV with the U-flag and replies to the packet
    /// source, preventing third-party traffic redirection / reflection.
    pub return_path_allow_alternate: bool,
    /// Reflector member link ID for Micro-session ID TLV (RFC 9534 §3.2).
    pub reflector_member_link_id: Option<u16>,
    /// Raw bytes of the received IP fixed header and IPv6 extension headers,
    /// for draft-ietf-ippm-stamp-ext-hdr Reflected Fixed/Ext Header TLVs
    /// (Types 247/246). `None` on backends that cannot observe the IP layer
    /// (UDP-socket `nix` backend): the reflector then echoes the TLV with the
    /// U-flag set.
    pub captured_headers: Option<&'a CapturedHeaders>,
    /// Reflector-side amplification cap on the Reflected Test Packet Control
    /// (Type 12) request: maximum number of reply packets the reflector
    /// will emit. Exceeding clamps the count and sets the C flag.
    pub reflected_control_max_count: u16,
    /// Reflector-side amplification cap: maximum reply packet size in
    /// octets the reflector will pad up to when honouring the TLV
    /// `length` request. Exceeding sets the C flag.
    pub reflected_control_max_size: u16,
    /// Reflector-side amplification cap: minimum inter-packet interval
    /// in nanoseconds. Requested intervals shorter than this are clamped
    /// up and the C flag is set.
    pub reflected_control_min_interval_ns: u32,
    /// Kernel-provided receive timestamp for this packet (STAMP wire
    /// format), filled by backends with `SO_TIMESTAMPING` enabled
    /// (feature "hwtstamp"). `None` → T2 is generated in userspace.
    pub rx_timestamp: Option<u64>,
    /// How T2 was produced (`HwAssist` only for NIC hardware timestamps;
    /// kernel-software and userspace timestamps are both `SwLocal`).
    pub rx_method: TimestampMethod,
    /// How T3 (and the Follow-Up Telemetry record) is produced on the
    /// reply path, per the socket's timestamping configuration.
    pub tx_method: TimestampMethod,
}

/// Raw IP-layer bytes captured at receive time for reflecting back to the
/// sender via TLV Types 246 and 247 (draft-ietf-ippm-stamp-ext-hdr-11).
///
/// Populated only by backends that capture at the datalink layer (pnet).
/// UDP-socket backends (nix) cannot observe these bytes and leave the
/// struct unset; the reflector sets the C flag on any 246/247 request.
#[derive(Debug, Clone, Default)]
pub struct CapturedHeaders {
    /// Raw IP fixed headers (20 bytes for IPv4, 40 bytes for IPv6), ordered
    /// outer→inner. In the common (non-tunneled) case this holds exactly one
    /// header; an IP-in-IP tunnel (IP protocol 4 / next-header 41) contributes
    /// one record per stacked IP header for draft-ietf-ippm-stamp-ext-hdr-11
    /// §3.2 rule 2 positional pairing of multiple Type-247 TLVs.
    pub fixed_headers: Vec<Vec<u8>>,
    /// IPv6 Hop-by-Hop, Destination Options, Routing (incl. SRH) and Fragment
    /// extension headers concatenated verbatim as on the wire: each record
    /// starts with its own Next Header octet (naming what follows it), then
    /// HdrExtLen, then the header body.
    pub ipv6_ext_headers: Vec<u8>,
}

/// Runs [`process_stamp_packet`] with panic isolation.
///
/// A panic while parsing/processing a single attacker-controlled packet must
/// never unwind out of the receive loop — on the `nix` backend that would
/// terminate the whole process (a remote, single-packet DoS), and on the
/// `pnet` backend it would stop the capture task permanently. We have not found
/// any reachable panic in the processing path, but this is defence-in-depth: if
/// a future regression introduces one, the packet is dropped and the reflector
/// keeps serving.
///
/// On panic the packet is dropped (returns `None`); the caller is responsible
/// for bumping its drop counter. Shared mutable state behind the borrows in
/// `ctx` (the session manager's `RwLock`) already tolerates poisoning via
/// `unwrap_or_else(|e| e.into_inner())`, so continuing after a caught unwind is
/// safe, which is why [`std::panic::AssertUnwindSafe`] is justified here.
pub fn process_stamp_packet_isolated(
    data: &[u8],
    src: SocketAddr,
    ttl: u8,
    use_auth: bool,
    ctx: &ProcessingContext,
) -> Option<StampResponse> {
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        process_stamp_packet(data, src, ttl, use_auth, ctx)
    }));
    match result {
        Ok(response) => response,
        Err(_) => {
            note_processing_panic(src);
            None
        }
    }
}

/// Logs a caught packet-processing panic at most once at `error` level, then at
/// `debug` for subsequent occurrences. A reachable panic under a flood would
/// otherwise become its own log-amplification DoS.
fn note_processing_panic(src: SocketAddr) {
    use std::sync::atomic::{AtomicBool, Ordering};
    static LOGGED: AtomicBool = AtomicBool::new(false);
    if !LOGGED.swap(true, Ordering::Relaxed) {
        log::error!(
            "panic while processing a packet from {src}; packet dropped. This is \
             a bug — please report it. Further occurrences are logged at debug."
        );
    } else {
        log::debug!("panic while processing packet from {src} (dropped)");
    }
}

/// Processes a STAMP packet and returns the response.
///
/// This is the shared packet processing logic used by both nix and pnet backends.
/// Handles parsing, HMAC verification, and response assembly for both authenticated
/// and unauthenticated modes.
///
/// # Arguments
/// * `data` - The raw packet data
/// * `src` - Source address for session tracking
/// * `ttl` - TTL/Hop Limit from IP header
/// * `use_auth` - Whether authenticated mode is enabled
/// * `ctx` - Processing context with configuration
///
/// # Returns
/// `Some(StampResponse)` on success, `None` if packet should be dropped.
/// The response includes the packet data and optional CoS request (DSCP1/ECN1).
pub fn process_stamp_packet(
    data: &[u8],
    src: SocketAddr,
    ttl: u8,
    use_auth: bool,
    ctx: &ProcessingContext,
) -> Option<StampResponse> {
    #[cfg(feature = "metrics")]
    let start_time = if ctx.metrics_enabled {
        Some(std::time::Instant::now())
    } else {
        None
    };

    #[cfg(feature = "metrics")]
    if ctx.metrics_enabled {
        crate::metrics::reflector_metrics::record_packet_received();
    }

    // T2: prefer the backend's kernel receive timestamp (taken when the
    // packet entered the host) over a fresh userspace read, which would
    // include scheduler-wakeup and bookkeeping latency.
    let rcvt = ctx
        .rx_timestamp
        .unwrap_or_else(|| generate_timestamp(ctx.clock_source));

    // Determine if packet has TLVs
    let base_size = if use_auth {
        AUTH_BASE_SIZE
    } else {
        UNAUTH_BASE_SIZE
    };
    let has_tlvs = data.len() > base_size;

    // Resolve the HMAC key for this packet (B6: per-SSID lookup). Falls
    // back to `ctx.hmac_key` when no `hmac_key_set` is configured,
    // preserving the single-key path.
    let ssid = peek_ssid(data, use_auth);
    let resolved_hmac_key = resolve_hmac_key(ctx, ssid);

    // TLV HMAC key for responses (only if we're not ignoring TLVs)
    // Per RFC 8972 §4.8: on HMAC verification failure, TLVs are echoed
    // with I-flag set rather than dropping the packet
    let tlv_hmac_key = if ctx.tlv_mode != TlvHandlingMode::Ignore {
        resolved_hmac_key
    } else {
        None
    };

    // Determine whether to verify incoming TLV HMAC:
    // - Always verify if --verify-tlv-hmac is set
    // - Auto-verify when HMAC key is configured (regardless of auth mode)
    let verify_tlv_hmac = ctx.verify_tlv_hmac || resolved_hmac_key.is_some();

    let result = if use_auth {
        process_auth_packet(
            data,
            src,
            ttl,
            rcvt,
            has_tlvs,
            resolved_hmac_key,
            tlv_hmac_key,
            verify_tlv_hmac,
            ctx,
        )
    } else {
        process_unauth_packet(
            data,
            src,
            ttl,
            rcvt,
            has_tlvs,
            tlv_hmac_key,
            verify_tlv_hmac,
            ctx,
        )
    };

    #[cfg(feature = "metrics")]
    if ctx.metrics_enabled {
        if result.is_some() {
            crate::metrics::reflector_metrics::record_packet_reflected();
        }
        if let Some(start) = start_time {
            let elapsed = start.elapsed().as_secs_f64();
            crate::metrics::reflector_metrics::record_processing_time(elapsed);
        }
    }

    result
}

/// Processes an authenticated STAMP packet.
///
/// `resolved_hmac_key` is the per-SSID key already resolved by
/// `process_stamp_packet`; it shadows `ctx.hmac_key` so the auth path
/// behaves correctly under B6's `--hmac-key-dir` configuration.
#[allow(clippy::too_many_arguments)]
fn process_auth_packet(
    data: &[u8],
    src: SocketAddr,
    ttl: u8,
    rcvt: u64,
    has_tlvs: bool,
    resolved_hmac_key: Option<&HmacKey>,
    tlv_hmac_key: Option<&HmacKey>,
    verify_tlv_hmac: bool,
    ctx: &ProcessingContext,
) -> Option<StampResponse> {
    // Parse packet leniently with canonical buffer for HMAC verification
    // Per RFC 8762 §4.6, short packets are zero-filled and HMAC must be
    // verified against the canonical (zero-padded) representation
    let (packet, canonical_buf) = if ctx.strict_packets {
        match PacketAuthenticated::from_bytes(data) {
            Ok(p) => {
                let mut buf = [0u8; 112];
                buf.copy_from_slice(&data[..112]);
                (p, buf)
            }
            Err(e) => {
                log::warn!(
                    "Failed to deserialize authenticated packet from {}: {} (strict mode)",
                    src,
                    e
                );
                #[cfg(feature = "metrics")]
                if ctx.metrics_enabled {
                    crate::metrics::reflector_metrics::record_packet_dropped("parse_error");
                }
                return None;
            }
        }
    } else {
        PacketAuthenticated::from_bytes_lenient_with_canonical(data)
    };

    // Extract HMAC for verification
    let hmac = packet.hmac;

    // Verify HMAC against canonical buffer - mandatory when key is present (RFC 8762 §4.4)
    if let Some(key) = resolved_hmac_key {
        if !verify_packet_hmac(key, &canonical_buf, AUTH_PACKET_HMAC_OFFSET, &hmac) {
            log::warn!("HMAC verification failed for packet from {}", src);
            #[cfg(feature = "metrics")]
            if ctx.metrics_enabled {
                crate::metrics::reflector_metrics::record_hmac_failure();
                crate::metrics::reflector_metrics::record_packet_dropped("hmac_failure");
            }
            return None;
        }
    } else if ctx.hmac_key_set.is_some() {
        // A keyset exists (key dir / control plane) but resolved no key for
        // this packet's SSID — an unknown SSID with no default, or the last
        // key was deleted at runtime. Refuse the packet: removing a key must
        // revoke access, never downgrade the reflector to answering
        // authenticated-layout packets without verification.
        log::warn!(
            "no HMAC key for SSID {} (keyset configured); dropping packet from {}",
            packet.ssid,
            src
        );
        #[cfg(feature = "metrics")]
        if ctx.metrics_enabled {
            crate::metrics::reflector_metrics::record_packet_dropped("no_key_for_ssid");
        }
        return None;
    } else if ctx.require_hmac {
        log::warn!(
            "HMAC key required but not configured; dropping packet from {}",
            src
        );
        #[cfg(feature = "metrics")]
        if ctx.metrics_enabled {
            crate::metrics::reflector_metrics::record_packet_dropped("hmac_required");
        }
        return None;
    }

    // Generate reflector sequence number only after successful validation
    let reflector_seq = ctx
        .session_manager
        .map(|mgr| mgr.generate_sequence_number(src));

    // Use TLV-aware assembly if packet has TLVs
    if has_tlvs {
        Some(assemble_auth_answer_with_tlvs(
            &packet,
            data,
            ctx.clock_source,
            rcvt,
            ttl,
            ctx.error_estimate_wire,
            resolved_hmac_key,
            reflector_seq,
            ctx.tlv_mode,
            tlv_hmac_key,
            verify_tlv_hmac,
            ctx,
        ))
    } else {
        Some(StampResponse {
            data: assemble_auth_answer_symmetric(
                &packet,
                data,
                ctx.clock_source,
                rcvt,
                ttl,
                ctx.error_estimate_wire,
                // B6: use the per-SSID-resolved key (falls back to
                // ctx.hmac_key when no HmacKeySet is configured). Using
                // ctx.hmac_key directly here would emit unsigned
                // responses when --hmac-key-dir is the key source.
                resolved_hmac_key,
                reflector_seq,
            ),
            cos_request: None,
            return_path_action: ReturnPathAction::Normal,
            reflected_control: None,
            // The symmetric no-TLV path never parses a Destination Node
            // Address TLV, so there is nothing to pin.
            reply_source: None,
        })
    }
}

/// Processes an unauthenticated STAMP packet.
#[allow(clippy::too_many_arguments)]
fn process_unauth_packet(
    data: &[u8],
    src: SocketAddr,
    ttl: u8,
    rcvt: u64,
    has_tlvs: bool,
    tlv_hmac_key: Option<&HmacKey>,
    verify_tlv_hmac: bool,
    ctx: &ProcessingContext,
) -> Option<StampResponse> {
    let packet_result = if ctx.strict_packets {
        PacketUnauthenticated::from_bytes(data)
    } else {
        Ok(PacketUnauthenticated::from_bytes_lenient(data))
    };

    match packet_result {
        Ok(packet) => {
            // Generate reflector sequence number only after successful validation
            let reflector_seq = ctx
                .session_manager
                .map(|mgr| mgr.generate_sequence_number(src));

            // Use TLV-aware assembly if packet has TLVs
            if has_tlvs {
                Some(assemble_unauth_answer_with_tlvs(
                    &packet,
                    data,
                    ctx.clock_source,
                    rcvt,
                    ttl,
                    ctx.error_estimate_wire,
                    reflector_seq,
                    ctx.tlv_mode,
                    tlv_hmac_key,
                    verify_tlv_hmac,
                    ctx,
                ))
            } else {
                Some(StampResponse {
                    data: assemble_unauth_answer_symmetric(
                        &packet,
                        data,
                        ctx.clock_source,
                        rcvt,
                        ttl,
                        ctx.error_estimate_wire,
                        reflector_seq,
                    ),
                    cos_request: None,
                    reply_source: None,
                    return_path_action: ReturnPathAction::Normal,
                    reflected_control: None,
                })
            }
        }
        Err(e) => {
            log::warn!(
                "Failed to deserialize unauthenticated packet from {}: {} (strict mode)",
                src,
                e
            );
            #[cfg(feature = "metrics")]
            if ctx.metrics_enabled {
                crate::metrics::reflector_metrics::record_packet_dropped("parse_error");
            }
            None
        }
    }
}

/// Assembles an unauthenticated reflected packet with symmetric size (RFC 8762 Section 4.3).
///
/// Preserves the original packet length by padding with zeros beyond the base 44 bytes.
/// Per RFC 8762 Section 4.2.1, extra octets SHOULD be filled with zeros.
///
/// # Arguments
/// * `packet` - The received unauthenticated test packet
/// * `original_data` - The original received packet data (used only for length)
/// * `cs` - Clock format to use for timestamps
/// * `rcvt` - Receive timestamp when the packet was received
/// * `ttl` - TTL/Hop Limit value from the received packet's IP header
/// * `reflector_error_estimate` - The reflector's own error estimate in wire format
/// * `reflector_seq` - Optional independent reflector sequence number (RFC 8972 stateful mode)
pub fn assemble_unauth_answer_symmetric(
    packet: &PacketUnauthenticated,
    original_data: &[u8],
    cs: ClockFormat,
    rcvt: u64,
    ttl: u8,
    reflector_error_estimate: u16,
    reflector_seq: Option<u32>,
) -> Vec<u8> {
    let base = assemble_unauth_answer(
        packet,
        cs,
        rcvt,
        ttl,
        reflector_error_estimate,
        reflector_seq,
    );
    let mut response = base.to_bytes().to_vec();

    // Pad with zeros to match original length (RFC 8762 Section 4.2.1)
    if original_data.len() > UNAUTH_BASE_SIZE {
        response.resize(original_data.len(), 0);
    }

    response
}

/// Assembles an authenticated reflected packet from a received test packet.
///
/// # Arguments
/// * `packet` - The received authenticated test packet
/// * `cs` - Clock format to use for timestamps
/// * `rcvt` - Receive timestamp when the packet was received
/// * `ttl` - TTL/Hop Limit value from the received packet's IP header
/// * `reflector_error_estimate` - The reflector's own error estimate in wire format
/// * `hmac_key` - Optional HMAC key for computing the response HMAC
/// * `reflector_seq` - Optional independent reflector sequence number (RFC 8972 stateful mode)
pub fn assemble_auth_answer(
    packet: &PacketAuthenticated,
    cs: ClockFormat,
    rcvt: u64,
    ttl: u8,
    reflector_error_estimate: u16,
    hmac_key: Option<&HmacKey>,
    reflector_seq: Option<u32>,
) -> ReflectedPacketAuthenticated {
    let mut response = ReflectedPacketAuthenticated {
        sess_sender_timestamp: packet.timestamp,
        sess_sender_err_estimate: packet.error_estimate,
        sess_sender_seq_number: packet.sequence_number,
        sess_sender_ssid: packet.ssid,
        sess_sender_ttl: ttl,
        sequence_number: reflector_seq.unwrap_or(packet.sequence_number),
        error_estimate: reflector_error_estimate,
        timestamp: generate_timestamp(cs),
        receive_timestamp: rcvt,
        ssid: packet.ssid,
        mbz0: [0u8; 12],
        mbz1: [0u8; 4],
        mbz2: [0u8; 8],
        mbz3: [0u8; 12],
        mbz4: [0u8; 4],
        mbz5: [0u8; 15],
        hmac: [0u8; 16],
    };

    // Compute HMAC if key is provided
    if let Some(key) = hmac_key {
        let bytes = response.to_bytes();
        response.hmac = compute_packet_hmac(key, &bytes, REFLECTED_AUTH_PACKET_HMAC_OFFSET);
    }

    response
}

/// Assembles an authenticated reflected packet with symmetric size (RFC 8762 Section 4.3).
///
/// Preserves the original packet length by padding with zeros beyond the base 112 bytes.
/// Per RFC 8762 Section 4.2.1, extra octets SHOULD be filled with zeros.
///
/// # Arguments
/// * `packet` - The received authenticated test packet
/// * `original_data` - The original received packet data (used only for length)
/// * `cs` - Clock format to use for timestamps
/// * `rcvt` - Receive timestamp when the packet was received
/// * `ttl` - TTL/Hop Limit value from the received packet's IP header
/// * `reflector_error_estimate` - The reflector's own error estimate in wire format
/// * `hmac_key` - Optional HMAC key for computing the response HMAC
/// * `reflector_seq` - Optional independent reflector sequence number (RFC 8972 stateful mode)
#[allow(clippy::too_many_arguments)]
pub fn assemble_auth_answer_symmetric(
    packet: &PacketAuthenticated,
    original_data: &[u8],
    cs: ClockFormat,
    rcvt: u64,
    ttl: u8,
    reflector_error_estimate: u16,
    hmac_key: Option<&HmacKey>,
    reflector_seq: Option<u32>,
) -> Vec<u8> {
    let base = assemble_auth_answer(
        packet,
        cs,
        rcvt,
        ttl,
        reflector_error_estimate,
        hmac_key,
        reflector_seq,
    );
    let mut response = base.to_bytes().to_vec();

    // Pad with zeros to match original length (RFC 8762 Section 4.2.1)
    if original_data.len() > AUTH_BASE_SIZE {
        response.resize(original_data.len(), 0);
    }

    response
}

/// Tuple returned from `apply_semantic_tlv_processing`.
struct SemanticResult {
    cos_request: Option<(u8, u8)>,
    return_path_action: ReturnPathAction,
    reflected_control: Option<ReflectedControlBehavior>,
    /// RFC 9503 §3: the matched Destination Node Address, to be pinned as the
    /// reply's IP source address.
    reply_source: Option<std::net::IpAddr>,
}

/// Applies semantic TLV processing on the reflector side (RFC 8972 §4.8).
///
/// Called when HMAC verification passed and no malformed TLVs were found.
/// Returns `None` if the packet should be discarded (e.g. Micro-session ID mismatch).
fn apply_semantic_tlv_processing(
    tlvs: &mut TlvList,
    ctx: &ProcessingContext,
    tlv_hmac_key: Option<&HmacKey>,
    base_bytes: &[u8],
) -> Option<SemanticResult> {
    // Update Timestamp Information TLVs (RFC 8972 §4.3). All four value
    // octets describe this reflector: the In pair characterizes the ingress
    // that obtained T2, the Out pair the egress that obtained T3. Report each
    // direction's real acquisition method — a mixed configuration (kernel
    // software receive, NIC hardware transmit) is exactly what the separate
    // In/Out fields exist to express.
    let sync_src = match ctx.clock_source {
        ClockFormat::NTP => SyncSource::Ntp,
        ClockFormat::PTP => SyncSource::Ptp,
    };
    tlvs.update_timestamp_info_tlvs(sync_src, ctx.rx_method, ctx.tx_method);

    // Update Direct Measurement TLVs (RFC 8972 §4.5)
    if let (Some(rx), Some(tx)) = (ctx.reflector_rx_count, ctx.reflector_tx_count) {
        tlvs.update_direct_measurement_tlvs(rx, tx);
    }

    // Update Location TLVs (RFC 8972 §4.2), honouring the §4.2.2
    // field-disclosure policy.
    if let Some(ref addr_info) = ctx.packet_addr_info {
        tlvs.update_location_tlvs(addr_info, ctx.location_disclosure);
    }

    // Update Follow-Up Telemetry TLVs (RFC 8972 §4.7). In stateful mode the
    // TLV reports the previous reflection's seq/timestamp (the mode byte
    // reports how that recorded TX timestamp was produced); in stateless mode
    // (RFC 8762 §4.2, `--stateful-reflector` off) §4.7-7 requires the Sequence
    // Number and Follow-Up Timestamp fields be zeroed instead. Passing `None`
    // selects the stateless zeroing path; invalid-length TLVs are zeroed
    // regardless (§4.7-6). The call is unconditional so an invalid-length TLV
    // is always zeroed even when there is no reflection to report.
    let reflection = if ctx.stateful_reflector {
        ctx.last_reflection
    } else {
        None
    };
    tlvs.update_follow_up_telemetry_tlvs(reflection, ctx.tx_method);

    // Discard Access Report TLVs with an invalid Access ID (RFC 8972 §4.6:
    // values other than 1/2 MUST be discarded — marked U, size preserved).
    tlvs.discard_invalid_access_report_tlvs();

    // Process Destination Node Address TLV (RFC 9503 §4)
    let reply_source = tlvs
        .process_destination_node_address(ctx.local_addresses)
        .pinned_source();

    // Process Micro-session ID TLV (RFC 9534 §3.2)
    if let Some(refl_id) = ctx.reflector_member_link_id {
        if !tlvs.update_micro_session_id_tlvs(refl_id) {
            log::warn!("Micro-session ID validation failed, discarding packet");
            return None;
        }
    }

    // Process Return Path TLV (RFC 9503 §5). Mutable: the
    // draft-ietf-ippm-asymmetrical-pkts-14 §4.3 conflict rule below may
    // override a no-reply request.
    let mut return_path_action =
        tlvs.process_return_path(ctx.sender_port, ctx.return_path_allow_alternate);

    // Extract CoS request (DSCP1/ECN1) for outgoing IP_TOS.
    let requested_cos = tlvs.get_cos_request();

    // RFC 8972 §4.4: "The Session-Reflector MUST use the local policy to verify
    // whether the CoS corresponding to the value of the DSCP1 field is
    // permitted in the domain"; §6 adds the same as a SHOULD; cos-ecn-01 §3.2
    // extends it to EC1 ("if it is permitted and capable to do so").
    //
    // *Permitted* is decided here, against the operator's admission policy.
    // *Capable* stays with the backends' setsockopt attempt. A request must
    // clear both, and the two answers are genuinely different: the kernel will
    // happily apply a codepoint the domain is not supposed to carry, so
    // treating syscall success as permission answers only the second question.
    //
    // The policy is scoped to where the reply is actually going — which is why
    // this runs after the Return Path TLV: an honoured Return Address
    // (RFC 9503 §5, `--return-path-allow-alternate`) redirects the reply, and
    // a destination-scoped rule for that address must win over the original
    // source's.
    let reply_destination = match &return_path_action {
        ReturnPathAction::AlternateAddress(addr) => Some(addr.ip()),
        _ => ctx.packet_addr_info.as_ref().map(|info| info.src_addr),
    };
    let (dscp_permitted, ecn_permitted) = match requested_cos {
        Some((dscp1, ec1)) => (
            ctx.cos_policy.permits_dscp(reply_destination, dscp1),
            ctx.cos_policy.permits_ecn(ec1),
        ),
        // Nothing requested: nothing to admit or refuse.
        None => (true, true),
    };

    // What the backend should actually put on the wire. A refused DSCP1 falls
    // back to the received DSCP (DSCP2), matching the RPD=0b01 the TLV now
    // reports; a refused EC1 forces the reply's ECN bits to 0b00 (Not-ECT)
    // rather than leaving a value the policy rejected, which is the same
    // treatment cos-ecn-01 §3.2 mandates for the "unable" case.
    let cos_request = requested_cos.map(|(dscp1, ec1)| {
        (
            if dscp_permitted {
                dscp1
            } else {
                ctx.received_dscp
            },
            if ecn_permitted { ec1 } else { 0 },
        )
    });

    if let Some((dscp1, ec1)) = requested_cos {
        if !dscp_permitted {
            log::debug!(
                "CoS admission policy refused DSCP1 {dscp1} for a reply to {:?};                  using the received DSCP {} with RPD=0b01",
                reply_destination,
                ctx.received_dscp
            );
        }
        if !ecn_permitted {
            log::debug!("CoS admission policy refused EC1 {ec1}; reply ECN forced to Not-ECT");
        }
    }

    // Update CoS TLVs with received DSCP/ECN values (RFC 8972 §4.4 +
    // draft-ietf-ippm-stamp-cos-ecn-01 §3.2). RPD reports whether DSCP1 was
    // honoured and RPE whether the reply's ECN was set to EC1 — both now
    // reflect the admission decision above. If the backend's setsockopt call
    // later fails, `set_cos_policy_rejected` / `cos_unable_fallback_tos`
    // override these to RPD=0b01/RPE=0b10, so a request that was permitted but
    // turned out not to be applicable still reports honestly.
    tlvs.update_cos_tlvs(
        ctx.received_dscp,
        ctx.received_ecn,
        !dscp_permitted,
        ecn_permitted,
    );

    // Process BER TLVs (draft-gandhi-ippm-stamp-ber §3):
    // compute Bit Error Count and Max Burst against the companion Extra Padding.
    tlvs.process_ber();

    // Process Reflected Fixed / IPv6 Extension Header TLVs
    // (draft-ietf-ippm-stamp-ext-hdr-11 §§3.1, 3.2). If the backend captured
    // raw IP bytes, copy the matched header's [4..] into the TLV's Reflected
    // field; otherwise set the C flag (Conformance) per -11 §5.1/§5.2. A nix
    // UDP-socket backend hands us `captured_headers = None`, so this correctly
    // signals "could not reflect" to senders that requested header reflection.
    let (captured_fixed, captured_ext): (Option<&[Vec<u8>]>, Option<&[u8]>) =
        match ctx.captured_headers {
            Some(h) => (
                Some(h.fixed_headers.as_slice()),
                Some(h.ipv6_ext_headers.as_slice()),
            ),
            None => (None, None),
        };
    tlvs.process_reflected_headers_multi(captured_fixed, captured_ext);

    // draft-ietf-ippm-stamp-ext-hdr-11 §3.1/§3.2 MTU rule (reflector half): the
    // reflected test packet MUST NOT exceed the IP/IPv6 MTU after the Reflected
    // Fixed/IPv6 Ext Header TLVs; if necessary, one or more of those TLVs MUST
    // be removed. The reflector fills the sender-sized TLVs in place and never
    // grows them, so this is a defensive cap keyed to the operator's
    // `--reflected-control-max-size` (the same egress-MTU stand-in used for
    // Type-12 padding); it fires only when a request already sits at/over that
    // size. The base + a reserve for the response HMAC TLV (if keyed) is the
    // fixed part; TLVs are trimmed to fit the remainder.
    {
        // HMAC TLV wire size = 4-byte header + 16-byte value.
        let hmac_reserve = if tlv_hmac_key.is_some() {
            TLV_HEADER_SIZE + 16
        } else {
            0
        };
        let removed = tlvs.trim_reflected_headers_to_size(
            base_bytes.len() + hmac_reserve,
            ctx.reflected_control_max_size as usize,
        );
        if removed > 0 {
            log::warn!(
                "Removed {removed} Reflected Fixed/IPv6 Ext Header TLV(s) (Type 246/247) from \
                 the reply to stay within the {}-byte reply-size limit \
                 (draft-ietf-ippm-stamp-ext-hdr-11 §3.1/§3.2)",
                ctx.reflected_control_max_size
            );
        }
    }

    // Process Reflected Test Packet Control TLV
    // (draft-ietf-ippm-asymmetrical-pkts-14 §3).
    //
    // Per §3.1.1 (L2) / §3.1.2 (L3), each Address Group sub-TLV gates the
    // packet independently: the reflector bitwise-ANDs the requested mask
    // against its own local addresses (MAC for L2, IP for L3) and, on no
    // match, "MUST stop processing the received packet" (drop, no reply).
    // Both sub-TLVs may be present on the same TLV — each is evaluated on
    // its own terms, and either one failing to match drops the packet, so a
    // sender combining both is effectively asking for an AND of the two
    // filters. Neither sub-TLV's flags participate in this decision (the C/U
    // flags are reserved for the unrelated MTU/rate-limit signalling
    // elsewhere in this match arm).
    let reflected_control = match tlvs.get_reflected_control_request() {
        Some(req) => {
            // Pre-check sub-TLVs: an L2 or L3 mismatch drops the packet
            // entirely, before any reply-shaping (count/length/interval) is
            // considered.
            let sub_chain = parse_reflected_control_sub_tlvs(&req.sub_tlvs);
            let mut l2_matches: Option<bool> = None;
            let mut l3_matches: Option<bool> = None;
            let mut ipv6_ext_hdr_control_count = 0usize;
            for sub in &sub_chain {
                match sub {
                    ReflectedControlSubTlv::L2Group { mask, group } => {
                        l2_matches = Some(l2_group_matches_any_local(mask, group, ctx.local_macs));
                    }
                    ReflectedControlSubTlv::L3Group { prefix_len, prefix } => {
                        l3_matches = Some(l3_group_matches_any_local(
                            *prefix_len,
                            prefix,
                            ctx.local_addresses,
                        ));
                    }
                    ReflectedControlSubTlv::Ipv6ExtHdrControl => ipv6_ext_hdr_control_count += 1,
                    ReflectedControlSubTlv::Unknown { .. } => {}
                }
            }
            if l2_matches == Some(false) {
                // §3.1.1: "If no matches are found, the Session-Reflector
                // MUST stop processing the received packet."
                log::debug!(
                    "Reflected Control L2 Address Group did not match any local \
                     MAC address; dropping packet per draft-ietf-ippm-asymmetrical-pkts-14 §3.1.1"
                );
                return None;
            }
            if l3_matches == Some(false) {
                // §3.1.2: "If no matches are found, the Session-Reflector
                // MUST stop processing the received packet."
                log::debug!(
                    "Reflected Control L3 Address Group did not match any local \
                     address; dropping packet per draft-ietf-ippm-asymmetrical-pkts-14 §3.1.2"
                );
                return None;
            }

            // draft-ietf-ippm-stamp-ext-hdr-11 §5.3: the 'IPv6 Extension Header
            // Control' Sub-TLV asks the reflector to add matching IPv6 extension
            // headers to its OWN reply packet. Neither backend can add reply
            // extension headers, so rule 4 requires the C flag in that sub-TLV's
            // Sub-TLV Flags. More than one such sub-TLV is a cardinality
            // violation and gets the C flag on EVERY offending copy (and is not
            // treated as actionable). Both cases mark C on all matching sub-TLVs
            // in the reflected Type 12 value; 246 reflection is unaffected
            // (handled independently, rule 3).
            let one_way_ext_headers = ipv6_ext_hdr_control_count == 1;
            if ipv6_ext_hdr_control_count >= 1 {
                tlvs.set_ipv6_ext_hdr_control_c_flag();
            }

            if return_path_action == ReturnPathAction::SuppressReply
                && req.number_of_reflected_packets != 0
            {
                // §4.3: combining a Return Path "no reply requested" control
                // code with a non-zero Reflected Test Packet Control TLV is a
                // sender error. The reflector MUST set U on both TLVs in the
                // (single, normal) reflected packet and SHOULD log it.
                log::warn!(
                    "STAMP packet combines Return Path 'no reply requested' with a \
                     non-zero Reflected Test Packet Control TLV; setting U on both \
                     per draft-ietf-ippm-asymmetrical-pkts-14 §4.3"
                );
                tlvs.set_reflected_control_u_flag();
                tlvs.set_return_path_u_flag();
                return_path_action = ReturnPathAction::Normal;
                None
            } else if ctx.reflected_control_max_count == 0 {
                // Administrative disable (the production default; §5 mandates
                // support be off by default). Treated as a volume limit of
                // zero: echo the TLV with the C flag and send the single
                // normal reply, but never pad — otherwise an unauthenticated
                // peer could turn a tiny request into a 1500-byte reply and,
                // combined with a Return Address sub-TLV, aim it at a victim.
                tlvs.set_reflected_control_c_flag();
                None
            } else if req.number_of_reflected_packets == 0 {
                // §3: count 0 → "MUST NOT send any reflected packets", and
                // SHOULD discard the received test packet. (RFC 9503's
                // no-reply control code is the preferred way to request this.)
                log::debug!(
                    "Reflected Control count=0; suppressing reply per \
                     draft-ietf-ippm-asymmetrical-pkts-14 §3"
                );
                return None;
            } else {
                let requested_count = req.number_of_reflected_packets;
                let mut non_conformant = false;
                // §3 + §5: the reflector MUST limit the rate and volume of
                // the traffic it generates per incoming packet; a request
                // exceeding either limit gets C=1 and a SINGLE reflected
                // packet, not a clamped burst. `max_count` is the volume
                // limit and the interval floor is the rate limit.
                if requested_count > ctx.reflected_control_max_count {
                    non_conformant = true;
                }
                if requested_count > 1
                    && req.interval_nanoseconds < ctx.reflected_control_min_interval_ns
                {
                    non_conformant = true;
                }

                // §3 length rules: the reflected length is the larger of
                //  (a) the base reply plus echoed TLVs *excluding* Extra
                //      Padding TLVs (so replies can shrink below the
                //      received packet's size), and
                //  (b) the requested length aligned up to a 4-octet boundary,
                // capped at max_size — the operator's stand-in for the
                // egress-interface MTU; exceeding the cap is the C=1 "MTU"
                // case and the reply is padded to the cap instead.
                tlvs.remove_extra_padding_tlvs();
                // A keyed reflector appends its own HMAC TLV *after* this
                // padding decision, whether or not the request carried one
                // (see the §4.8 per-role adjudication at `set_hmac_response`
                // below). That TLV is part of the reflected packet, so its
                // 20 octets have to be reserved here; without the reserve a
                // request from a peer that sends no HMAC TLV of its own gets
                // a reply exactly 20 octets past the length it asked for.
                // When the request did carry an HMAC TLV, `wire_size()`
                // already counts it (`TlvList::iter` chains `hmac_tlv`).
                let hmac_reserve = if tlv_hmac_key.is_some() && tlvs.hmac_tlv().is_none() {
                    TLV_HEADER_SIZE + HMAC_TLV_VALUE_SIZE
                } else {
                    0
                };
                let current = base_bytes.len() + tlvs.wire_size() + hmac_reserve;
                let aligned_req = (req.length_of_reflected_packet as usize).div_ceil(4) * 4;
                let cap = ctx.reflected_control_max_size as usize;
                if aligned_req > cap {
                    non_conformant = true;
                }
                let target = aligned_req.min(cap);
                if target > current {
                    let delta = target - current;
                    if delta >= TLV_HEADER_SIZE {
                        // The padding value carries (delta - 4) octets of
                        // zeros; push() places it before the HMAC TLV in
                        // wire order so the chain remains spec-compliant.
                        let pad_tlv =
                            crate::tlv::ExtraPaddingTlv::new_zeros(delta - TLV_HEADER_SIZE)
                                .to_raw();
                        let _ = tlvs.push(pad_tlv);
                    } else {
                        // Can't grow by less than one TLV header.
                        non_conformant = true;
                    }
                }

                if non_conformant {
                    tlvs.set_reflected_control_c_flag();
                }
                let extra_copies = if non_conformant {
                    0
                } else {
                    requested_count - 1
                };
                Some(ReflectedControlBehavior {
                    extra_copies,
                    interval_ns: req
                        .interval_nanoseconds
                        .max(ctx.reflected_control_min_interval_ns),
                    suppress_reply_ext_headers: one_way_ext_headers,
                })
            }
        }
        None => None,
    };

    // Compute fresh HMAC for response (must be last, after all TLV mutations).
    // Use the reflector variant so the regenerated HMAC TLV carries U=0 per
    // RFC 8972 §4 — the reflector recognizes the HMAC type by construction.
    //
    // Deliberately unconditional on whether the *request* carried an HMAC
    // TLV — see the RFC 8972 §4.8 adjudication on
    // `TlvList::set_hmac_response` for why this is spec-compliant rather
    // than an unsolicited addition.
    if let Some(key) = tlv_hmac_key {
        let response_seq_bytes = &base_bytes[..4];
        tlvs.set_hmac_response(key, response_seq_bytes);
    }

    Some(SemanticResult {
        cos_request,
        return_path_action,
        reflected_control,
        reply_source,
    })
}

/// Assembles an unauthenticated reflected packet with TLV handling (RFC 8972).
///
/// Per RFC 8972 §4.8, on HMAC verification failure, TLVs are echoed with I-flag
/// set on ALL TLVs rather than dropping the packet.
///
/// # Arguments
/// * `packet` - The received unauthenticated test packet
/// * `original_data` - The original received packet data
/// * `cs` - Clock format to use for timestamps
/// * `rcvt` - Receive timestamp when the packet was received
/// * `ttl` - TTL/Hop Limit value from the received packet's IP header
/// * `reflector_error_estimate` - The reflector's own error estimate in wire format
/// * `reflector_seq` - Optional independent reflector sequence number
/// * `tlv_mode` - How to handle TLV extensions
/// * `tlv_hmac_key` - Optional HMAC key for TLV HMAC computation in response
/// * `verify_incoming_hmac` - Whether to verify incoming TLV HMAC (sets I-flag on failure)
/// * `received_dscp` - DSCP value received from IP header (for CoS TLV)
/// * `received_ecn` - ECN value received from IP header (for CoS TLV)
#[allow(clippy::too_many_arguments)]
pub fn assemble_unauth_answer_with_tlvs(
    packet: &PacketUnauthenticated,
    original_data: &[u8],
    cs: ClockFormat,
    rcvt: u64,
    ttl: u8,
    reflector_error_estimate: u16,
    reflector_seq: Option<u32>,
    tlv_mode: TlvHandlingMode,
    tlv_hmac_key: Option<&HmacKey>,
    verify_incoming_hmac: bool,
    ctx: &ProcessingContext,
) -> StampResponse {
    let base = assemble_unauth_answer(
        packet,
        cs,
        rcvt,
        ttl,
        reflector_error_estimate,
        reflector_seq,
    );
    let base_bytes = base.to_bytes();
    let mut response = base_bytes.to_vec();
    let mut cos_request: Option<(u8, u8)> = None;
    let mut return_path_action = ReturnPathAction::Normal;
    let mut reflected_control: Option<ReflectedControlBehavior> = None;
    let mut reply_source: Option<std::net::IpAddr> = None;

    // Handle TLVs based on mode
    match tlv_mode {
        TlvHandlingMode::Ignore => {
            // Strip TLVs - just return base packet, optionally padded
            if original_data.len() > UNAUTH_BASE_SIZE {
                // Preserve symmetric size with zero padding (no TLVs)
                response.resize(original_data.len(), 0);
            }
        }
        TlvHandlingMode::Echo => {
            // Parse and echo TLVs from incoming packet
            if original_data.len() > UNAUTH_BASE_SIZE {
                let tlv_data = &original_data[UNAUTH_BASE_SIZE..];

                // Parse TLVs leniently - this handles both valid and malformed TLVs in a single pass.
                // had_malformed indicates whether any TLV was malformed (which also means strict
                // parsing would have failed). This avoids double-parsing malformed/adversarial traffic.
                let (mut tlvs, had_malformed) = TlvList::parse_lenient(tlv_data);

                // Per RFC 8972 §4.8: HMAC covers Sequence Number (first 4 bytes) + TLVs
                let incoming_seq_bytes = &original_data[..4];

                // Apply reflector-side flag updates per RFC 8972:
                // - U-flag for unrecognized types
                // - I-flag on ALL TLVs if HMAC verification fails (only if verify_incoming_hmac)
                // Per RFC 8972 §4.8: on failure, TLVs are echoed with I-flag set (not dropped)
                // Note: Unauthenticated mode does not require HMAC TLV presence
                let verify_key = if verify_incoming_hmac {
                    tlv_hmac_key
                } else {
                    None
                };
                let hmac_ok = tlvs.apply_reflector_flags(verify_key, incoming_seq_bytes, tlv_data);

                // Record TLV error metrics
                #[cfg(feature = "metrics")]
                {
                    let (u_count, m_count, i_count) = tlvs.count_error_flags();
                    for _ in 0..u_count {
                        crate::metrics::reflector_metrics::record_tlv_error("U");
                    }
                    for _ in 0..m_count {
                        crate::metrics::reflector_metrics::record_tlv_error("M");
                    }
                    for _ in 0..i_count {
                        crate::metrics::reflector_metrics::record_tlv_error("I");
                    }
                }

                // Per RFC 8972 §4.8: on HMAC failure or malformed TLVs, only echo
                // TLVs with flags set — do NOT perform semantic TLV processing.
                if hmac_ok && !had_malformed {
                    match apply_semantic_tlv_processing(&mut tlvs, ctx, tlv_hmac_key, &base_bytes) {
                        Some(result) => {
                            cos_request = result.cos_request;
                            return_path_action = result.return_path_action;
                            reflected_control = result.reflected_control;
                            reply_source = result.reply_source;
                        }
                        None => {
                            return StampResponse {
                                data: response,
                                cos_request: None,
                                return_path_action: ReturnPathAction::SuppressReply,
                                reflected_control: None,
                                reply_source: None,
                            };
                        }
                    }
                }

                tlvs.write_to(&mut response);

                // RFC 8762 §4.3/§4.6: the reflected packet MUST be symmetric
                // in size to the received packet ("copy the content beyond the
                // size of the base STAMP packet"). The lenient TLV parser
                // stops at a trailing all-zero run (classic legacy/TWAMP-Light
                // padding with no TLVs) or a sub-4-byte tail without capturing
                // those octets, so re-pad the reply up to the received length.
                // The padding is appended after all echoed TLVs, so the TLV
                // HMAC coverage (sequence number + TLVs) is unchanged. Never
                // truncate a legitimately longer reply.
                //
                // Skip this default symmetric-size padding when a Reflected
                // Test Packet Control TLV (Type 12) governs the reply size
                // (draft-ietf-ippm-asymmetrical-pkts §3): that mechanism
                // deliberately controls the reply length (e.g. stripping Extra
                // Padding to produce a shorter reply) and overrides the legacy
                // symmetric-size default.
                if reflected_control.is_none() && response.len() < original_data.len() {
                    response.resize(original_data.len(), 0);
                }
            }
        }
    }

    StampResponse {
        data: response,
        cos_request,
        return_path_action,
        reflected_control,
        reply_source,
    }
}

/// Assembles an authenticated reflected packet with TLV handling (RFC 8972).
///
/// Per RFC 8972 §4.8, on HMAC verification failure, TLVs are echoed with I-flag
/// set on ALL TLVs rather than dropping the packet.
#[allow(clippy::too_many_arguments)]
pub fn assemble_auth_answer_with_tlvs(
    packet: &PacketAuthenticated,
    original_data: &[u8],
    cs: ClockFormat,
    rcvt: u64,
    ttl: u8,
    reflector_error_estimate: u16,
    hmac_key: Option<&HmacKey>,
    reflector_seq: Option<u32>,
    tlv_mode: TlvHandlingMode,
    tlv_hmac_key: Option<&HmacKey>,
    verify_incoming_hmac: bool,
    ctx: &ProcessingContext,
) -> StampResponse {
    let base = assemble_auth_answer(
        packet,
        cs,
        rcvt,
        ttl,
        reflector_error_estimate,
        hmac_key,
        reflector_seq,
    );
    let base_bytes = base.to_bytes();
    let mut response = base_bytes.to_vec();
    let mut cos_request: Option<(u8, u8)> = None;
    let mut return_path_action = ReturnPathAction::Normal;
    let mut reflected_control: Option<ReflectedControlBehavior> = None;
    let mut reply_source: Option<std::net::IpAddr> = None;

    // Handle TLVs based on mode
    match tlv_mode {
        TlvHandlingMode::Ignore => {
            // Strip TLVs - just return base packet, optionally padded
            if original_data.len() > AUTH_BASE_SIZE {
                response.resize(original_data.len(), 0);
            }
        }
        TlvHandlingMode::Echo => {
            // Parse and echo TLVs from incoming packet
            if original_data.len() > AUTH_BASE_SIZE {
                let tlv_data = &original_data[AUTH_BASE_SIZE..];

                // Parse TLVs leniently - this handles both valid and malformed TLVs in a single pass.
                // had_malformed indicates whether any TLV was malformed (which also means strict
                // parsing would have failed). This avoids double-parsing malformed/adversarial traffic.
                let (mut tlvs, had_malformed) = TlvList::parse_lenient(tlv_data);

                // Per RFC 8972 §4.8: HMAC covers Sequence Number (first 4 bytes) + TLVs
                let incoming_seq_bytes = &original_data[..4];

                // Apply reflector-side flag updates per RFC 8972:
                // - U-flag for unrecognized types
                // - I-flag on ALL TLVs if HMAC verification fails (only if verify_incoming_hmac)
                // Per RFC 8972 §4.8: on failure, TLVs are echoed with I-flag set (not dropped)
                // For strict RFC 8972 authenticated mode: require HMAC TLV (unless only Extra Padding)
                let verify_key = if verify_incoming_hmac {
                    tlv_hmac_key
                } else {
                    None
                };
                let require_hmac_tlv = verify_incoming_hmac;
                let hmac_ok = tlvs.apply_reflector_flags_strict(
                    verify_key,
                    incoming_seq_bytes,
                    tlv_data,
                    require_hmac_tlv,
                );

                // Record TLV error metrics
                #[cfg(feature = "metrics")]
                {
                    let (u_count, m_count, i_count) = tlvs.count_error_flags();
                    for _ in 0..u_count {
                        crate::metrics::reflector_metrics::record_tlv_error("U");
                    }
                    for _ in 0..m_count {
                        crate::metrics::reflector_metrics::record_tlv_error("M");
                    }
                    for _ in 0..i_count {
                        crate::metrics::reflector_metrics::record_tlv_error("I");
                    }
                }

                // Per RFC 8972 §4.8: on HMAC failure or malformed TLVs, only echo
                // TLVs with flags set — do NOT perform semantic TLV processing.
                if hmac_ok && !had_malformed {
                    match apply_semantic_tlv_processing(&mut tlvs, ctx, tlv_hmac_key, &base_bytes) {
                        Some(result) => {
                            cos_request = result.cos_request;
                            return_path_action = result.return_path_action;
                            reflected_control = result.reflected_control;
                            reply_source = result.reply_source;
                        }
                        None => {
                            return StampResponse {
                                data: response,
                                cos_request: None,
                                return_path_action: ReturnPathAction::SuppressReply,
                                reflected_control: None,
                                reply_source: None,
                            };
                        }
                    }
                }

                tlvs.write_to(&mut response);

                // RFC 8762 §4.3/§4.6: preserve symmetric size. In the
                // authenticated layout the padding is appended AFTER the base
                // packet (including its own HMAC field) and after all echoed
                // TLVs and the TLV HMAC, so neither the base packet HMAC nor
                // the TLV HMAC coverage is affected. Never truncate a
                // legitimately longer reply. Skipped when a Reflected Test
                // Packet Control TLV (Type 12) governs the reply size. See the
                // unauthenticated path for the full rationale.
                if reflected_control.is_none() && response.len() < original_data.len() {
                    response.resize(original_data.len(), 0);
                }
            }
        }
    }

    StampResponse {
        data: response,
        cos_request,
        return_path_action,
        reflected_control,
        reply_source,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    /// Creates a default ProcessingContext for tests with given DSCP/ECN values.
    fn test_ctx(received_dscp: u8, received_ecn: u8) -> ProcessingContext<'static> {
        ProcessingContext {
            clock_source: ClockFormat::NTP,
            error_estimate_wire: 0,
            hmac_key: None,
            hmac_key_set: None,
            require_hmac: false,
            session_manager: None,
            stateful_reflector: true,
            tlv_mode: TlvHandlingMode::Echo,
            verify_tlv_hmac: false,
            strict_packets: false,
            #[cfg(feature = "metrics")]
            metrics_enabled: false,
            received_dscp,
            received_ecn,
            reflector_rx_count: None,
            reflector_tx_count: None,
            packet_addr_info: None,
            last_reflection: None,
            location_disclosure: Default::default(),
            cos_policy: crate::cos_policy::permissive(),
            local_addresses: &[],
            local_macs: &[],
            sender_port: 0,
            return_path_allow_alternate: false,
            reflector_member_link_id: None,
            captured_headers: None,
            reflected_control_max_count: REFLECTED_CONTROL_MAX_COUNT,
            reflected_control_max_size: REFLECTED_CONTROL_MAX_SIZE,
            reflected_control_min_interval_ns: REFLECTED_CONTROL_MIN_INTERVAL_NS,
            rx_timestamp: None,
            rx_method: TimestampMethod::SwLocal,
            tx_method: TimestampMethod::SwLocal,
        }
    }

    /// Test helper: Verifies TLV HMAC if present in the incoming packet per RFC 8972 §4.8.
    ///
    /// The HMAC covers the Sequence Number field (first 4 bytes) + preceding TLVs.
    ///
    /// Returns true if no HMAC TLV is present or if verification succeeds.
    /// Returns false if HMAC verification fails.
    fn verify_incoming_tlv_hmac(original_data: &[u8], base_size: usize, key: &HmacKey) -> bool {
        if original_data.len() <= base_size {
            return true; // No TLVs to verify
        }

        let tlv_data = &original_data[base_size..];
        let Ok(tlvs) = TlvList::parse(tlv_data) else {
            return false; // Malformed TLVs
        };

        if tlvs.hmac_tlv().is_none() {
            return true; // No HMAC TLV to verify
        }

        // Per RFC 8972 §4.8: HMAC covers Sequence Number (first 4 bytes) + preceding TLVs
        let sequence_number_bytes = &original_data[..4];
        tlvs.verify_hmac(key, sequence_number_bytes, tlv_data)
            .is_ok()
    }

    #[test]
    fn test_assemble_unauth_answer_echoes_sender_fields() {
        let sender_packet = PacketUnauthenticated {
            sequence_number: 42,
            timestamp: 123456789,
            error_estimate: 100,
            ssid: 0,
            mbz: [0; 28],
        };

        let rcvt = 987654321u64;
        let ttl = 64u8;
        let reflector_error_estimate = 200u16;

        let reflected = assemble_unauth_answer(
            &sender_packet,
            ClockFormat::NTP,
            rcvt,
            ttl,
            reflector_error_estimate,
            None,
        );

        // Verify sender fields are echoed
        assert_eq!(
            reflected.sess_sender_seq_number,
            sender_packet.sequence_number
        );
        assert_eq!(reflected.sess_sender_timestamp, sender_packet.timestamp);
        assert_eq!(
            reflected.sess_sender_err_estimate,
            sender_packet.error_estimate
        );
        assert_eq!(reflected.sess_sender_ttl, ttl);
        // Verify reflector's own error estimate is used
        assert_eq!(reflected.error_estimate, reflector_error_estimate);
    }

    #[test]
    fn test_assemble_unauth_answer_receive_timestamp() {
        let sender_packet = PacketUnauthenticated {
            sequence_number: 1,
            timestamp: 100,
            error_estimate: 10,
            ssid: 0,
            mbz: [0; 28],
        };

        let rcvt = 500u64;
        let reflected = assemble_unauth_answer(&sender_packet, ClockFormat::NTP, rcvt, 64, 0, None);

        assert_eq!(reflected.receive_timestamp, rcvt);
    }

    #[test]
    fn test_assemble_unauth_answer_timestamp_generated() {
        let sender_packet = PacketUnauthenticated {
            sequence_number: 1,
            timestamp: 0,
            error_estimate: 0,
            ssid: 0,
            mbz: [0; 28],
        };

        let reflected = assemble_unauth_answer(&sender_packet, ClockFormat::NTP, 0, 64, 0, None);

        // Reflector's timestamp should be non-zero (generated)
        assert!(reflected.timestamp > 0);
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
            let key = RateLimiterKey::from_src(stale);
            let stale_bucket = state.sources.get_mut(&key).unwrap();
            stale_bucket.last_seen =
                Instant::now() - RateLimiter::BUCKET_TTL - Duration::from_secs(1);
        }

        assert!(limiter.allow(trigger));

        let state = limiter.state.lock().unwrap_or_else(|e| e.into_inner());
        assert!(!state.sources.contains_key(&RateLimiterKey::from_src(stale)));
        assert!(state.sources.contains_key(&RateLimiterKey::from_src(fresh)));
        assert!(state
            .sources
            .contains_key(&RateLimiterKey::from_src(trigger)));
    }

    // -----------------------------------------------------------------------
    // B4: token-bucket per-client rate limiting.

    /// Synthetic burst exceeding the bucket size must produce exactly
    /// `burst` accepts then deny — no off-by-one in the consume logic.
    #[test]
    fn test_rate_limiter_runtime_adjust() {
        // Starts unlimited (rate 0): always allows and allocates no buckets.
        let limiter = RateLimiter::with_burst(0, 0);
        let key = RateLimiterKey::from_src(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
        for _ in 0..1000 {
            assert!(limiter.allow_n(key, 1), "rate 0 = unlimited");
        }

        // Control plane turns limiting on at runtime.
        limiter.set_rate(2, 2);
        assert_eq!(limiter.rate(), 2);
        assert_eq!(limiter.burst(), 2);
        let key2 = RateLimiterKey::from_src(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)));
        assert!(limiter.allow_n(key2, 1));
        assert!(limiter.allow_n(key2, 1));
        assert!(
            !limiter.allow_n(key2, 1),
            "fresh bucket holds `burst` tokens; third immediate packet drops"
        );

        // And back to unlimited.
        limiter.set_rate(0, 0);
        assert!(limiter.allow_n(key2, 1), "back to unlimited");
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

    /// Per-(IP, SSID) isolation: same IP with two different SSIDs gets
    /// two independent buckets.
    #[test]
    fn test_rate_limiter_per_ssid_isolation() {
        let limiter = RateLimiter::with_burst(1, 2);
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let session_a = RateLimiterKey { src: ip, ssid: 1 };
        let session_b = RateLimiterKey { src: ip, ssid: 2 };

        for _ in 0..2 {
            assert!(limiter.allow_keyed(session_a));
        }
        assert!(!limiter.allow_keyed(session_a), "session A exhausted");

        // Same IP but different SSID → independent bucket.
        for _ in 0..2 {
            assert!(
                limiter.allow_keyed(session_b),
                "session B must have its own bucket"
            );
        }
    }

    /// `allow_n` consumes N tokens atomically: insufficient → leave bucket
    /// alone and return false.
    #[test]
    fn test_rate_limiter_allow_n_atomic() {
        let limiter = RateLimiter::with_burst(1, 5);
        let src = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let key = RateLimiterKey::from_src(src);

        // Bucket has 5 tokens — asking for 6 must fail without consuming.
        assert!(!limiter.allow_n(key, 6));
        // Bucket still full — we can consume all 5.
        assert!(limiter.allow_n(key, 5));
        // Now empty.
        assert!(!limiter.allow_n(key, 1));
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

    #[test]
    fn test_assemble_auth_answer_echoes_sender_fields() {
        let sender_packet = PacketAuthenticated {
            sequence_number: 42,
            mbz0: [0; 12],
            timestamp: 123456789,
            error_estimate: 100,
            ssid: 0,
            mbz1a: [0; 30],
            mbz1b: [0; 32],
            mbz1c: [0; 6],
            hmac: [0xab; 16],
        };

        let rcvt = 987654321u64;
        let ttl = 128u8;
        let reflector_error_estimate = 300u16;

        let reflected = assemble_auth_answer(
            &sender_packet,
            ClockFormat::NTP,
            rcvt,
            ttl,
            reflector_error_estimate,
            None,
            None,
        );

        // Verify sender fields are echoed
        assert_eq!(
            reflected.sess_sender_seq_number,
            sender_packet.sequence_number
        );
        assert_eq!(reflected.sess_sender_timestamp, sender_packet.timestamp);
        assert_eq!(
            reflected.sess_sender_err_estimate,
            sender_packet.error_estimate
        );
        assert_eq!(reflected.sess_sender_ttl, ttl);
        // Verify reflector's own error estimate is used
        assert_eq!(reflected.error_estimate, reflector_error_estimate);
    }

    #[test]
    fn test_assemble_unauth_answer_ttl_preserved() {
        let sender_packet = PacketUnauthenticated {
            sequence_number: 1,
            timestamp: 2,
            error_estimate: 3,
            ssid: 0,
            mbz: [0; 28],
        };

        // Test various TTL values
        for ttl in [0u8, 1, 64, 128, 255] {
            let reflected =
                assemble_unauth_answer(&sender_packet, ClockFormat::NTP, 0, ttl, 0, None);
            assert_eq!(reflected.sess_sender_ttl, ttl);
        }
    }

    #[test]
    fn test_assemble_auth_answer_ttl_preserved() {
        let sender_packet = PacketAuthenticated {
            sequence_number: 1,
            mbz0: [0; 12],
            timestamp: 2,
            error_estimate: 3,
            ssid: 0,
            mbz1a: [0; 30],
            mbz1b: [0; 32],
            mbz1c: [0; 6],
            hmac: [0; 16],
        };

        // Test various TTL values
        for ttl in [0u8, 1, 64, 128, 255] {
            let reflected =
                assemble_auth_answer(&sender_packet, ClockFormat::NTP, 0, ttl, 0, None, None);
            assert_eq!(reflected.sess_sender_ttl, ttl);
        }
    }

    #[test]
    fn test_assemble_auth_answer_with_hmac() {
        let sender_packet = PacketAuthenticated {
            sequence_number: 1,
            mbz0: [0; 12],
            timestamp: 123456789,
            error_estimate: 100,
            ssid: 0,
            mbz1a: [0; 30],
            mbz1b: [0; 32],
            mbz1c: [0; 6],
            hmac: [0; 16],
        };

        let key = HmacKey::new(vec![0xab; 32]).unwrap();
        let reflected = assemble_auth_answer(
            &sender_packet,
            ClockFormat::NTP,
            987654321,
            64,
            200,
            Some(&key),
            None,
        );

        // HMAC should be non-zero when key is provided
        assert_ne!(reflected.hmac, [0u8; 16]);
    }

    #[test]
    fn test_assemble_auth_answer_without_hmac() {
        let sender_packet = PacketAuthenticated {
            sequence_number: 1,
            mbz0: [0; 12],
            timestamp: 123456789,
            error_estimate: 100,
            ssid: 0,
            mbz1a: [0; 30],
            mbz1b: [0; 32],
            mbz1c: [0; 6],
            hmac: [0; 16],
        };

        let reflected = assemble_auth_answer(
            &sender_packet,
            ClockFormat::NTP,
            987654321,
            64,
            200,
            None,
            None,
        );

        // HMAC should be zero when no key is provided
        assert_eq!(reflected.hmac, [0u8; 16]);
    }

    #[test]
    fn test_assemble_unauth_answer_with_reflector_seq() {
        let sender_packet = PacketUnauthenticated {
            sequence_number: 42,
            timestamp: 123456789,
            error_estimate: 100,
            ssid: 0,
            mbz: [0; 28],
        };

        // Test with independent reflector sequence number
        let reflected = assemble_unauth_answer(
            &sender_packet,
            ClockFormat::NTP,
            987654321,
            64,
            200,
            Some(999),
        );

        // Reflector's sequence should be independent
        assert_eq!(reflected.sequence_number, 999);
        // Sender's sequence still echoed in sess_sender_seq_number
        assert_eq!(reflected.sess_sender_seq_number, 42);
    }

    #[test]
    fn test_assemble_auth_answer_with_reflector_seq() {
        let sender_packet = PacketAuthenticated {
            sequence_number: 42,
            mbz0: [0; 12],
            timestamp: 123456789,
            error_estimate: 100,
            ssid: 0,
            mbz1a: [0; 30],
            mbz1b: [0; 32],
            mbz1c: [0; 6],
            hmac: [0; 16],
        };

        // Test with independent reflector sequence number
        let reflected = assemble_auth_answer(
            &sender_packet,
            ClockFormat::NTP,
            987654321,
            64,
            200,
            None,
            Some(999),
        );

        // Reflector's sequence should be independent
        assert_eq!(reflected.sequence_number, 999);
        // Sender's sequence still echoed in sess_sender_seq_number
        assert_eq!(reflected.sess_sender_seq_number, 42);
    }

    #[test]
    fn test_assemble_unauth_answer_symmetric_preserves_length() {
        let sender_packet = PacketUnauthenticated {
            sequence_number: 1,
            timestamp: 100,
            error_estimate: 10,
            ssid: 0,
            mbz: [0; 28],
        };

        // Create original data with extra bytes beyond base 44
        let mut original_data = sender_packet.to_bytes().to_vec();
        original_data.extend_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD]); // 4 extra bytes

        let response = assemble_unauth_answer_symmetric(
            &sender_packet,
            &original_data,
            ClockFormat::NTP,
            200,
            64,
            300,
            None,
        );

        // Response should be 48 bytes (44 base + 4 extra)
        assert_eq!(response.len(), 48);
        // Extra bytes should be zeros per RFC 8762 Section 4.2.1
        assert_eq!(&response[44..], &[0x00, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn test_assemble_auth_answer_symmetric_preserves_length() {
        let sender_packet = PacketAuthenticated {
            sequence_number: 1,
            mbz0: [0; 12],
            timestamp: 100,
            error_estimate: 10,
            ssid: 0,
            mbz1a: [0; 30],
            mbz1b: [0; 32],
            mbz1c: [0; 6],
            hmac: [0; 16],
        };

        // Create original data with extra bytes beyond base 112
        let mut original_data = sender_packet.to_bytes().to_vec();
        original_data.extend_from_slice(&[0x11, 0x22, 0x33, 0x44, 0x55]); // 5 extra bytes

        let response = assemble_auth_answer_symmetric(
            &sender_packet,
            &original_data,
            ClockFormat::NTP,
            200,
            64,
            300,
            None,
            None,
        );

        // Response should be 117 bytes (112 base + 5 extra)
        assert_eq!(response.len(), 117);
        // Extra bytes should be zeros per RFC 8762 Section 4.2.1
        assert_eq!(&response[112..], &[0x00, 0x00, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn test_assemble_unauth_answer_symmetric_base_size() {
        let sender_packet = PacketUnauthenticated {
            sequence_number: 1,
            timestamp: 100,
            error_estimate: 10,
            ssid: 0,
            mbz: [0; 28],
        };

        // Original data is exactly base size
        let original_data = sender_packet.to_bytes();

        let response = assemble_unauth_answer_symmetric(
            &sender_packet,
            &original_data,
            ClockFormat::NTP,
            200,
            64,
            300,
            None,
        );

        // Response should be exactly 44 bytes
        assert_eq!(response.len(), 44);
    }

    // TLV-aware assembly tests

    #[test]
    fn test_assemble_unauth_with_tlvs_ignore_mode() {
        use crate::tlv::{RawTlv, TlvType, TLV_HEADER_SIZE};

        let sender_packet = PacketUnauthenticated {
            sequence_number: 1,
            timestamp: 100,
            error_estimate: 10,
            ssid: 0,
            mbz: [0; 28],
        };

        // Create packet with TLV extension
        let mut original_data = sender_packet.to_bytes().to_vec();
        let tlv = RawTlv::new(TlvType::ExtraPadding, vec![0xAA; 8]);
        original_data.extend_from_slice(&tlv.to_bytes());

        let response = assemble_unauth_answer_with_tlvs(
            &sender_packet,
            &original_data,
            ClockFormat::NTP,
            200,
            64,
            300,
            None,
            TlvHandlingMode::Ignore,
            None,
            false,
            &test_ctx(0, 0),
        );

        // Response should match original length but TLVs stripped (zero-padded)
        assert_eq!(response.data.len(), 44 + TLV_HEADER_SIZE + 8);
        // Extra bytes should be zero (TLVs stripped)
        assert!(response.data[44..].iter().all(|&b| b == 0));
    }

    #[test]
    fn test_assemble_unauth_with_tlvs_echo_mode() {
        use crate::tlv::{RawTlv, TlvType, TLV_HEADER_SIZE};

        let sender_packet = PacketUnauthenticated {
            sequence_number: 1,
            timestamp: 100,
            error_estimate: 10,
            ssid: 0,
            mbz: [0; 28],
        };

        // Create packet with TLV extension
        let mut original_data = sender_packet.to_bytes().to_vec();
        let tlv = RawTlv::new(TlvType::ExtraPadding, vec![0xAA; 4]);
        original_data.extend_from_slice(&tlv.to_bytes());

        let response = assemble_unauth_answer_with_tlvs(
            &sender_packet,
            &original_data,
            ClockFormat::NTP,
            200,
            64,
            300,
            None,
            TlvHandlingMode::Echo,
            None,
            false,
            &test_ctx(0, 0),
        );

        // Response should include echoed TLV
        assert_eq!(response.data.len(), 44 + TLV_HEADER_SIZE + 4);
        // TLV should be echoed (check type in byte 1 per RFC 8972)
        assert_eq!(response.data[45], 1); // ExtraPadding type
    }

    #[test]
    fn test_assemble_unauth_with_tlvs_does_not_truncate_oversized_response() {
        use crate::tlv::{ExtraPaddingTlv, TlvList};

        let sender_packet = PacketUnauthenticated {
            sequence_number: 1,
            timestamp: 100,
            error_estimate: 10,
            ssid: 0,
            mbz: [0; 28],
        };

        let mut original_data = sender_packet.to_bytes().to_vec();
        original_data.extend_from_slice(&ExtraPaddingTlv::new(1_600).to_raw().to_bytes());

        let response = assemble_unauth_answer_with_tlvs(
            &sender_packet,
            &original_data,
            ClockFormat::NTP,
            200,
            64,
            300,
            None,
            TlvHandlingMode::Echo,
            None,
            false,
            &test_ctx(0, 0),
        );

        assert!(response.data.len() > 1_500);
        let tlv_data = &response.data[UNAUTH_BASE_SIZE..];
        assert!(TlvList::parse(tlv_data).is_ok());
    }

    #[test]
    fn test_assemble_unauth_with_tlvs_marks_unknown() {
        use crate::tlv::{RawTlv, TlvType, TLV_HEADER_SIZE};

        let sender_packet = PacketUnauthenticated {
            sequence_number: 1,
            timestamp: 100,
            error_estimate: 10,
            ssid: 0,
            mbz: [0; 28],
        };

        // Create packet with unknown TLV type
        let mut original_data = sender_packet.to_bytes().to_vec();
        let tlv = RawTlv::new(TlvType::Unknown(15), vec![0xBB; 4]);
        original_data.extend_from_slice(&tlv.to_bytes());

        let response = assemble_unauth_answer_with_tlvs(
            &sender_packet,
            &original_data,
            ClockFormat::NTP,
            200,
            64,
            300,
            None,
            TlvHandlingMode::Echo,
            None,
            false,
            &test_ctx(0, 0),
        );

        // Check U-flag is set (bit 0 of flags byte per RFC 8972)
        // Byte 0: Flags (U=0x80), Byte 1: Type
        assert_eq!(response.data[44], 0x80); // U-flag set in flags byte
        assert_eq!(response.data[45], 15); // Type 15 in type byte
        assert_eq!(response.data.len(), 44 + TLV_HEADER_SIZE + 4);
    }

    #[test]
    fn test_assemble_auth_with_tlvs_ignore_mode() {
        use crate::tlv::{RawTlv, TlvType, TLV_HEADER_SIZE};

        let sender_packet = PacketAuthenticated {
            sequence_number: 1,
            mbz0: [0; 12],
            timestamp: 100,
            error_estimate: 10,
            ssid: 0,
            mbz1a: [0; 30],
            mbz1b: [0; 32],
            mbz1c: [0; 6],
            hmac: [0; 16],
        };

        // Create packet with TLV extension
        let mut original_data = sender_packet.to_bytes().to_vec();
        let tlv = RawTlv::new(TlvType::ExtraPadding, vec![0xCC; 8]);
        original_data.extend_from_slice(&tlv.to_bytes());

        let response = assemble_auth_answer_with_tlvs(
            &sender_packet,
            &original_data,
            ClockFormat::NTP,
            200,
            64,
            300,
            None,
            None,
            TlvHandlingMode::Ignore,
            None,
            false,
            &test_ctx(0, 0),
        );

        // Response should match original length but TLVs stripped
        assert_eq!(response.data.len(), 112 + TLV_HEADER_SIZE + 8);
        // Extra bytes should be zero
        assert!(response.data[112..].iter().all(|&b| b == 0));
    }

    #[test]
    fn test_assemble_auth_with_tlvs_echo_mode() {
        use crate::tlv::{RawTlv, TlvType, TLV_HEADER_SIZE};

        let sender_packet = PacketAuthenticated {
            sequence_number: 1,
            mbz0: [0; 12],
            timestamp: 100,
            error_estimate: 10,
            ssid: 0,
            mbz1a: [0; 30],
            mbz1b: [0; 32],
            mbz1c: [0; 6],
            hmac: [0; 16],
        };

        // Create packet with TLV extension
        let mut original_data = sender_packet.to_bytes().to_vec();
        let tlv = RawTlv::new(TlvType::Location, vec![1, 2, 3, 4]);
        original_data.extend_from_slice(&tlv.to_bytes());

        let response = assemble_auth_answer_with_tlvs(
            &sender_packet,
            &original_data,
            ClockFormat::NTP,
            200,
            64,
            300,
            None,
            None,
            TlvHandlingMode::Echo,
            None,
            false,
            &test_ctx(0, 0),
        );

        // Response should include echoed TLV
        assert_eq!(response.data.len(), 112 + TLV_HEADER_SIZE + 4);
        // TLV should be echoed (check type in byte 1 per RFC 8972)
        assert_eq!(response.data[113], 2); // Location type
    }

    #[test]
    fn test_assemble_auth_with_tlvs_does_not_truncate_oversized_response() {
        use crate::tlv::{ExtraPaddingTlv, TlvList};

        let sender_packet = PacketAuthenticated {
            sequence_number: 1,
            mbz0: [0; 12],
            timestamp: 100,
            error_estimate: 10,
            ssid: 0,
            mbz1a: [0; 30],
            mbz1b: [0; 32],
            mbz1c: [0; 6],
            hmac: [0; 16],
        };

        let mut original_data = sender_packet.to_bytes().to_vec();
        original_data.extend_from_slice(&ExtraPaddingTlv::new(1_500).to_raw().to_bytes());

        let key = HmacKey::new(vec![0xCD; 32]).unwrap();
        let response = assemble_auth_answer_with_tlvs(
            &sender_packet,
            &original_data,
            ClockFormat::NTP,
            200,
            64,
            300,
            None,
            None,
            TlvHandlingMode::Echo,
            Some(&key),
            false,
            &test_ctx(0, 0),
        );

        assert!(response.data.len() > 1_500);
        let tlv_data = &response.data[AUTH_BASE_SIZE..];
        let tlvs = TlvList::parse(tlv_data).unwrap();
        assert!(tlvs
            .verify_hmac(&key, &response.data[..4], tlv_data)
            .is_ok());
    }

    // RFC 8762 §4.3/§4.6: the reflected packet MUST be symmetric in size to
    // the received packet (copy the content beyond the base packet). A
    // trailing all-zero run (classic legacy/TWAMP-Light padding, no TLVs) or a
    // non-4-byte-aligned garbage trailer must not shrink the reply.

    #[test]
    fn test_zero_trailer_reply_preserves_symmetric_size_unauth() {
        let sender_packet = PacketUnauthenticated {
            sequence_number: 1,
            timestamp: 100,
            error_estimate: 10,
            ssid: 0,
            mbz: [0; 28],
        };

        // 44-octet base + 50-octet all-zero trailer (no TLVs at all).
        let mut original_data = sender_packet.to_bytes().to_vec();
        original_data.extend_from_slice(&[0u8; 50]);
        assert_eq!(original_data.len(), UNAUTH_BASE_SIZE + 50);

        let response = assemble_unauth_answer_with_tlvs(
            &sender_packet,
            &original_data,
            ClockFormat::NTP,
            200,
            64,
            300,
            None,
            TlvHandlingMode::Echo,
            None,
            false,
            &test_ctx(0, 0),
        );

        assert_eq!(
            response.data.len(),
            original_data.len(),
            "reply must be symmetric in size to the received packet"
        );
        // The trailing padding must remain zero.
        assert!(response.data[UNAUTH_BASE_SIZE..].iter().all(|&b| b == 0));
    }

    #[test]
    fn test_zero_trailer_reply_preserves_symmetric_size_auth() {
        let sender_packet = PacketAuthenticated {
            sequence_number: 1,
            mbz0: [0; 12],
            timestamp: 100,
            error_estimate: 10,
            ssid: 0,
            mbz1a: [0; 30],
            mbz1b: [0; 32],
            mbz1c: [0; 6],
            hmac: [0; 16],
        };

        // 112-octet base + 50-octet all-zero trailer (no TLVs at all).
        let mut original_data = sender_packet.to_bytes().to_vec();
        original_data.extend_from_slice(&[0u8; 50]);
        assert_eq!(original_data.len(), AUTH_BASE_SIZE + 50);

        let key = HmacKey::new(vec![0xCD; 32]).unwrap();
        let response = assemble_auth_answer_with_tlvs(
            &sender_packet,
            &original_data,
            ClockFormat::NTP,
            200,
            64,
            300,
            Some(&key),
            None,
            TlvHandlingMode::Echo,
            // No TLV-HMAC key: no HMAC TLV is appended, so the whole trailing
            // area is pure zero padding — the cleanest symmetric-size probe.
            None,
            false,
            &test_ctx(0, 0),
        );

        assert_eq!(
            response.data.len(),
            original_data.len(),
            "auth reply must be symmetric in size to the received packet"
        );
        // Padding is appended AFTER the base packet's HMAC; the trailing area
        // must be all zero.
        assert!(response.data[AUTH_BASE_SIZE..].iter().all(|&b| b == 0));

        // Packet-HMAC coverage must not change: the base packet HMAC (field at
        // [96..112]) still verifies against the reply's own first 112 octets.
        // The appended zero padding lies outside the HMAC's coverage, so it
        // cannot invalidate it.
        let hmac_field: [u8; 16] = response.data[REFLECTED_AUTH_PACKET_HMAC_OFFSET..AUTH_BASE_SIZE]
            .try_into()
            .unwrap();
        assert!(crate::crypto::verify_packet_hmac(
            &key,
            &response.data[..AUTH_BASE_SIZE],
            REFLECTED_AUTH_PACKET_HMAC_OFFSET,
            &hmac_field,
        ));
    }

    #[test]
    fn test_nonaligned_garbage_trailer_preserves_size_unauth() {
        use crate::tlv::{RawTlv, TlvType};

        let sender_packet = PacketUnauthenticated {
            sequence_number: 1,
            timestamp: 100,
            error_estimate: 10,
            ssid: 0,
            mbz: [0; 28],
        };

        // A real TLV followed by 3 stray non-zero bytes (not 4-byte aligned).
        let mut original_data = sender_packet.to_bytes().to_vec();
        let tlv = RawTlv::new(TlvType::ExtraPadding, vec![0xAA; 4]);
        original_data.extend_from_slice(&tlv.to_bytes());
        original_data.extend_from_slice(&[0xBB, 0xCC, 0xDD]);

        let response = assemble_unauth_answer_with_tlvs(
            &sender_packet,
            &original_data,
            ClockFormat::NTP,
            200,
            64,
            300,
            None,
            TlvHandlingMode::Echo,
            None,
            false,
            &test_ctx(0, 0),
        );

        assert_eq!(
            response.data.len(),
            original_data.len(),
            "reply must not drop the non-aligned trailer bytes"
        );
        // The echoed TLV is still intact at the head of the TLV area.
        assert_eq!(response.data[UNAUTH_BASE_SIZE + 1], 1); // ExtraPadding type
    }

    #[test]
    fn test_stateless_vs_stateful_follow_up_telemetry_reply() {
        use crate::tlv::{FollowUpTelemetryTlv, TlvList, TypedTlv};

        let sender_packet = PacketUnauthenticated {
            sequence_number: 1,
            timestamp: 100,
            error_estimate: 10,
            ssid: 0,
            mbz: [0; 28],
        };
        let mut original_data = sender_packet.to_bytes().to_vec();
        original_data.extend_from_slice(&FollowUpTelemetryTlv::new().to_raw().to_bytes());

        let assemble = |ctx: &ProcessingContext| {
            assemble_unauth_answer_with_tlvs(
                &sender_packet,
                &original_data,
                ClockFormat::NTP,
                200,
                64,
                300,
                None,
                TlvHandlingMode::Echo,
                None,
                false,
                ctx,
            )
        };

        // Stateless mode (RFC 8972 §4.7-7): the previous reflection is present
        // but MUST NOT be reported — seq/timestamp zeroed.
        let mut ctx = test_ctx(0, 0);
        ctx.stateful_reflector = false;
        ctx.last_reflection = Some((42, 0xDEAD_BEEF));
        let resp = assemble(&ctx);
        let tlvs = TlvList::parse(&resp.data[UNAUTH_BASE_SIZE..]).unwrap();
        let fut = FollowUpTelemetryTlv::from_raw(&tlvs.non_hmac_tlvs()[0]).unwrap();
        assert_eq!(fut.sequence_number, 0, "stateless: seq must be zero");
        assert_eq!(
            fut.follow_up_timestamp, 0,
            "stateless: timestamp must be zero"
        );

        // Stateful mode (§4.7-10): the same reflection IS reported.
        ctx.stateful_reflector = true;
        let resp = assemble(&ctx);
        let tlvs = TlvList::parse(&resp.data[UNAUTH_BASE_SIZE..]).unwrap();
        let fut = FollowUpTelemetryTlv::from_raw(&tlvs.non_hmac_tlvs()[0]).unwrap();
        assert_eq!(fut.sequence_number, 42);
        assert_eq!(fut.follow_up_timestamp, 0xDEAD_BEEF);
    }

    #[test]
    // RFC 8972 §4.8 adjudication (see also the module docs on
    // `TlvList::set_hmac_response`): "All authenticated STAMP base
    // packets ... MUST additionally authenticate the optional TLVs by
    // including the keyed HMAC TLV" and "The HMAC TLV MAY be used to
    // protect the integrity of STAMP extensions in the STAMP
    // unauthenticated mode. An implementation ... MUST provide controls
    // to enable [it]." Neither clause conditions the reflector's own
    // HMAC TLV on the *sender's* packet having carried one -- each party
    // protects the TLVs in the packet it is transmitting. Configuring a
    // TLV HMAC key on the reflector *is* the "control to enable" the
    // unauthenticated-mode case, so appending Type 8 to the reply here
    // even though the request had none is deliberate, RFC-compliant
    // behavior, not a mirror/echo of the request -- this test pins it.
    fn test_assemble_unauth_with_tlvs_adds_hmac() {
        use crate::tlv::{RawTlv, TlvType, HMAC_TLV_VALUE_SIZE, TLV_HEADER_SIZE};

        let sender_packet = PacketUnauthenticated {
            sequence_number: 1,
            timestamp: 100,
            error_estimate: 10,
            ssid: 0,
            mbz: [0; 28],
        };

        // Create packet with TLV extension (no HMAC)
        let mut original_data = sender_packet.to_bytes().to_vec();
        let tlv = RawTlv::new(TlvType::ExtraPadding, vec![0xDD; 4]);
        original_data.extend_from_slice(&tlv.to_bytes());

        let key = HmacKey::new(vec![0xAB; 32]).unwrap();
        let response = assemble_unauth_answer_with_tlvs(
            &sender_packet,
            &original_data,
            ClockFormat::NTP,
            200,
            64,
            300,
            None,
            TlvHandlingMode::Echo,
            Some(&key),
            false,
            &test_ctx(0, 0),
        );

        // Response should include ExtraPadding + HMAC TLV
        // 44 base + (4 header + 4 value) + (4 header + 16 value)
        assert_eq!(
            response.data.len(),
            44 + TLV_HEADER_SIZE + 4 + TLV_HEADER_SIZE + HMAC_TLV_VALUE_SIZE
        );

        // HMAC TLV should be last (type 8 in byte 1 per RFC 8972)
        let hmac_tlv_start = 44 + TLV_HEADER_SIZE + 4;
        assert_eq!(response.data[hmac_tlv_start + 1], 8);
    }

    #[test]
    /// Same adjudication as `test_assemble_unauth_with_tlvs_adds_hmac`,
    /// covering the authenticated-base-packet path: RFC 8972 §4.8's MUST
    /// applies "per Sections 4.2.2 and 4.3.2 of [RFC8762]" -- i.e. to both
    /// the Session-Sender's and the Session-Reflector's own authenticated
    /// packets independently. A Session-Sender that omitted the TLV HMAC
    /// (non-conformant, or simply not using TLV-level integrity itself)
    /// does not exempt this reflector from protecting its *own* reply's
    /// TLVs when it has a TLV HMAC key configured.
    fn test_assemble_auth_with_tlvs_adds_hmac_even_when_request_has_none() {
        use crate::tlv::{
            ClassOfServiceTlv, RawTlv, TlvType, TypedTlv, HMAC_TLV_VALUE_SIZE, TLV_HEADER_SIZE,
        };

        let sender_packet = PacketAuthenticated {
            sequence_number: 1,
            mbz0: [0; 12],
            timestamp: 100,
            error_estimate: 10,
            ssid: 0,
            mbz1a: [0; 30],
            mbz1b: [0; 32],
            mbz1c: [0; 6],
            hmac: [0; 16],
        };

        // Request carries a non-HMAC extension TLV but no Type 8.
        let mut original_data = sender_packet.to_bytes().to_vec();
        let cos = ClassOfServiceTlv::new(10, 1).to_raw();
        original_data.extend_from_slice(&cos.to_bytes());
        assert!(
            RawTlv::parse(&original_data[112..])
                .map(|(t, _)| t.tlv_type != TlvType::Hmac)
                .unwrap_or(true),
            "request must not itself carry an HMAC TLV"
        );

        let tlv_key = HmacKey::new(vec![0xCD; 32]).unwrap();
        let response = assemble_auth_answer_with_tlvs(
            &sender_packet,
            &original_data,
            ClockFormat::NTP,
            200,
            64,
            300,
            None,
            None,
            TlvHandlingMode::Echo,
            Some(&tlv_key),
            false,
            &test_ctx(0, 0),
        );

        // 112 base + (4 header + 4 CoS value) + (4 header + 16 HMAC value)
        assert_eq!(
            response.data.len(),
            112 + TLV_HEADER_SIZE + 4 + TLV_HEADER_SIZE + HMAC_TLV_VALUE_SIZE
        );
        let hmac_tlv_start = 112 + TLV_HEADER_SIZE + 4;
        assert_eq!(response.data[hmac_tlv_start + 1], 8); // Type 8 = HMAC
    }

    #[test]
    fn test_verify_incoming_tlv_hmac_no_tlvs() {
        let key = HmacKey::new(vec![0xAB; 32]).unwrap();
        let packet_data = [0u8; 44]; // Just base packet

        assert!(verify_incoming_tlv_hmac(
            &packet_data,
            UNAUTH_BASE_SIZE,
            &key
        ));
    }

    #[test]
    fn test_verify_incoming_tlv_hmac_no_hmac_tlv() {
        use crate::tlv::{RawTlv, TlvType};

        let key = HmacKey::new(vec![0xAB; 32]).unwrap();

        // Create packet with TLV but no HMAC
        let mut packet_data = vec![0u8; 44];
        let tlv = RawTlv::new(TlvType::ExtraPadding, vec![0; 4]);
        packet_data.extend_from_slice(&tlv.to_bytes());

        assert!(verify_incoming_tlv_hmac(
            &packet_data,
            UNAUTH_BASE_SIZE,
            &key
        ));
    }

    #[test]
    fn test_verify_incoming_tlv_hmac_valid() {
        use crate::tlv::{RawTlv, TlvList, TlvType};

        let key = HmacKey::new(vec![0xAB; 32]).unwrap();

        // Create base packet
        let base_packet = vec![0x01u8; 44];

        // Create TLV list with HMAC
        let mut tlvs = TlvList::new();
        tlvs.push(RawTlv::new(TlvType::ExtraPadding, vec![0xCC; 4]))
            .unwrap();
        tlvs.set_hmac(&key, &base_packet);

        // Combine base + TLVs
        let mut packet_data = base_packet.clone();
        packet_data.extend_from_slice(&tlvs.to_bytes());

        assert!(verify_incoming_tlv_hmac(
            &packet_data,
            UNAUTH_BASE_SIZE,
            &key
        ));
    }

    #[test]
    fn test_verify_incoming_tlv_hmac_invalid() {
        use crate::tlv::{RawTlv, TlvList, TlvType};

        let key1 = HmacKey::new(vec![0xAB; 32]).unwrap();
        let key2 = HmacKey::new(vec![0xCD; 32]).unwrap();

        // Create base packet
        let base_packet = vec![0x01u8; 44];

        // Create TLV list with HMAC using key1
        let mut tlvs = TlvList::new();
        tlvs.push(RawTlv::new(TlvType::ExtraPadding, vec![0xCC; 4]))
            .unwrap();
        tlvs.set_hmac(&key1, &base_packet);

        // Combine base + TLVs
        let mut packet_data = base_packet.clone();
        packet_data.extend_from_slice(&tlvs.to_bytes());

        // Verify with wrong key
        assert!(!verify_incoming_tlv_hmac(
            &packet_data,
            UNAUTH_BASE_SIZE,
            &key2
        ));
    }

    #[test]
    fn test_assemble_unauth_with_tlvs_hmac_failure_preserves_original() {
        use crate::tlv::{RawTlv, TlvList, TlvType, TLV_HEADER_SIZE};

        let key1 = HmacKey::new(vec![0xAB; 32]).unwrap();
        let key2 = HmacKey::new(vec![0xCD; 32]).unwrap();

        let sender_packet = PacketUnauthenticated {
            sequence_number: 0x12345678,
            timestamp: 100,
            error_estimate: 10,
            ssid: 0,
            mbz: [0; 28],
        };
        let base_bytes = sender_packet.to_bytes();

        // Create TLV list with HMAC using key1
        let mut tlvs = TlvList::new();
        tlvs.push(RawTlv::new(TlvType::ExtraPadding, vec![0xCC; 4]))
            .unwrap();
        tlvs.set_hmac(&key1, &base_bytes);

        // Save original HMAC value
        let original_hmac = tlvs.hmac_tlv().unwrap().value.clone();

        // Combine base + TLVs
        let mut original_data = base_bytes.to_vec();
        original_data.extend_from_slice(&tlvs.to_bytes());

        // Reflect with verification using wrong key (key2)
        // This should fail HMAC verification and set I-flag on all TLVs
        let response = assemble_unauth_answer_with_tlvs(
            &sender_packet,
            &original_data,
            ClockFormat::NTP,
            200,
            64,
            300,
            None,
            TlvHandlingMode::Echo,
            Some(&key2), // Wrong key for verification
            true,        // Verify HMAC (will fail)
            &test_ctx(0, 0),
        );

        // Response should include TLVs
        // Base (44) + ExtraPadding TLV (4+4) + HMAC TLV (4+16) = 72 bytes
        assert_eq!(
            response.data.len(),
            44 + TLV_HEADER_SIZE + 4 + TLV_HEADER_SIZE + 16
        );

        // Find HMAC TLV in response (last TLV)
        let hmac_tlv_start = 44 + TLV_HEADER_SIZE + 4;

        // Check I-flag is set on HMAC TLV (bit 5 of flags byte)
        let hmac_flags = response.data[hmac_tlv_start];
        assert!(
            hmac_flags & 0x20 != 0,
            "I-flag should be set on HMAC TLV, flags={:02x}",
            hmac_flags
        );

        // Check HMAC value is preserved (NOT regenerated)
        let response_hmac = &response.data[hmac_tlv_start + TLV_HEADER_SIZE..];
        assert_eq!(
            response_hmac,
            &original_hmac[..],
            "HMAC should be preserved on verification failure, not regenerated"
        );
    }

    #[test]
    fn test_assemble_unauth_with_tlvs_hmac_success_regenerates() {
        use crate::tlv::{RawTlv, TlvList, TlvType, TLV_HEADER_SIZE};

        let key = HmacKey::new(vec![0xAB; 32]).unwrap();

        let sender_packet = PacketUnauthenticated {
            sequence_number: 0x12345678,
            timestamp: 100,
            error_estimate: 10,
            ssid: 0,
            mbz: [0; 28],
        };
        let base_bytes = sender_packet.to_bytes();

        // Create TLV list with HMAC
        let mut tlvs = TlvList::new();
        tlvs.push(RawTlv::new(TlvType::ExtraPadding, vec![0xCC; 4]))
            .unwrap();
        tlvs.set_hmac(&key, &base_bytes);

        // Save original HMAC value
        let original_hmac = tlvs.hmac_tlv().unwrap().value.clone();

        // Combine base + TLVs
        let mut original_data = base_bytes.to_vec();
        original_data.extend_from_slice(&tlvs.to_bytes());

        // Reflect with verification using correct key and a DIFFERENT reflector seq
        // This should pass HMAC verification and regenerate HMAC for response
        // (HMAC covers sequence number, so different seq = different HMAC)
        let response = assemble_unauth_answer_with_tlvs(
            &sender_packet,
            &original_data,
            ClockFormat::NTP,
            200,
            64,
            300,
            Some(0x87654321), // Different reflector sequence number
            TlvHandlingMode::Echo,
            Some(&key), // Correct key for verification
            true,       // Verify HMAC (will succeed)
            &test_ctx(0, 0),
        );

        // Response should include TLVs
        assert_eq!(
            response.data.len(),
            44 + TLV_HEADER_SIZE + 4 + TLV_HEADER_SIZE + 16
        );

        // Find HMAC TLV in response (last TLV)
        let hmac_tlv_start = 44 + TLV_HEADER_SIZE + 4;

        // Check I-flag is NOT set on HMAC TLV
        let hmac_flags = response.data[hmac_tlv_start];
        assert!(
            hmac_flags & 0x20 == 0,
            "I-flag should NOT be set on successful verification, flags={:02x}",
            hmac_flags
        );

        // Check HMAC value is DIFFERENT (regenerated for new sequence number)
        let response_hmac = &response.data[hmac_tlv_start + TLV_HEADER_SIZE..];
        assert_ne!(
            response_hmac,
            &original_hmac[..],
            "HMAC should be regenerated on successful verification"
        );
    }

    #[test]
    fn test_assemble_unauth_with_malformed_tlv_sets_mflag() {
        let sender_packet = PacketUnauthenticated {
            sequence_number: 0x12345678,
            timestamp: 100,
            error_estimate: 10,
            ssid: 0,
            mbz: [0; 28],
        };
        let base_bytes = sender_packet.to_bytes();

        // Create a truncated/malformed TLV manually:
        // Header says length is 100 bytes, but only 4 bytes of value are present
        let mut original_data = base_bytes.to_vec();
        original_data.push(0x00); // Flags (no flags set by sender)
        original_data.push(0x01); // Type = ExtraPadding
        original_data.extend_from_slice(&100u16.to_be_bytes()); // Length = 100 (but only 4 available)
        original_data.extend_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD]); // Only 4 bytes of value

        // Reflect the packet
        let response = assemble_unauth_answer_with_tlvs(
            &sender_packet,
            &original_data,
            ClockFormat::NTP,
            200,
            64,
            300,
            None,
            TlvHandlingMode::Echo,
            None,
            false,
            &test_ctx(0, 0),
        );

        // Response should include base + malformed TLV (header + truncated value)
        // The TLV should have whatever data was available
        assert!(response.data.len() > 44, "Response should include TLV data");

        // Check M-flag is set on the TLV (bit 6 of flags byte = 0x40)
        let tlv_flags = response.data[44];
        assert!(
            tlv_flags & 0x40 != 0,
            "M-flag should be set on malformed TLV, flags={:02x}",
            tlv_flags
        );

        // Type should be preserved
        assert_eq!(response.data[45], 0x01, "TLV type should be preserved");
    }

    #[test]
    fn test_assemble_unauth_with_malformed_tlv_no_hmac_regen() {
        use crate::tlv::TLV_HEADER_SIZE;

        let key = HmacKey::new(vec![0xAB; 32]).unwrap();

        let sender_packet = PacketUnauthenticated {
            sequence_number: 0x12345678,
            timestamp: 100,
            error_estimate: 10,
            ssid: 0,
            mbz: [0; 28],
        };
        let base_bytes = sender_packet.to_bytes();

        // Create a truncated/malformed TLV
        let mut original_data = base_bytes.to_vec();
        original_data.push(0x00); // Flags
        original_data.push(0x01); // Type = ExtraPadding
        original_data.extend_from_slice(&50u16.to_be_bytes()); // Length = 50 (but only 4 available)
        original_data.extend_from_slice(&[0x11, 0x22, 0x33, 0x44]); // Only 4 bytes

        // Reflect with HMAC key - should NOT regenerate HMAC due to malformed TLV
        let response = assemble_unauth_answer_with_tlvs(
            &sender_packet,
            &original_data,
            ClockFormat::NTP,
            200,
            64,
            300,
            None,
            TlvHandlingMode::Echo,
            Some(&key),
            false,
            &test_ctx(0, 0),
        );

        // Response should only have the malformed TLV, no HMAC TLV added
        // (because we don't regenerate HMAC when there are malformed TLVs)
        assert!(response.data.len() > 44);

        // Check M-flag is set
        let tlv_flags = response.data[44];
        assert!(
            tlv_flags & 0x40 != 0,
            "M-flag should be set on malformed TLV"
        );

        // Should NOT have an HMAC TLV appended (response should be relatively short)
        // Base (44) + header (4) + truncated value (4) = 52 bytes
        assert_eq!(
            response.data.len(),
            44 + TLV_HEADER_SIZE + 4,
            "Should not have HMAC TLV when TLVs are malformed"
        );
    }

    #[test]
    fn test_assemble_unauth_with_cos_tlv_updates_dscp_ecn() {
        use crate::tlv::{
            ClassOfServiceTlv, TlvType, TypedTlv, COS_TLV_VALUE_SIZE, TLV_HEADER_SIZE,
        };

        let sender_packet = PacketUnauthenticated {
            sequence_number: 1,
            timestamp: 100,
            error_estimate: 10,
            ssid: 0,
            mbz: [0; 28],
        };

        // Create packet with CoS TLV (sender requests DSCP=46 EF, ECN=0)
        let mut original_data = sender_packet.to_bytes().to_vec();
        let cos_tlv = ClassOfServiceTlv::new(46, 0);
        original_data.extend_from_slice(&cos_tlv.to_raw().to_bytes());

        // Reflect with received DSCP=10, ECN=2 (simulating network modified values)
        let received_dscp = 10u8;
        let received_ecn = 2u8;
        let response = assemble_unauth_answer_with_tlvs(
            &sender_packet,
            &original_data,
            ClockFormat::NTP,
            200,
            64,
            300,
            None,
            TlvHandlingMode::Echo,
            None,
            false,
            &test_ctx(received_dscp, received_ecn),
        );

        // Response should include base + CoS TLV
        assert_eq!(
            response.data.len(),
            44 + TLV_HEADER_SIZE + COS_TLV_VALUE_SIZE
        );

        // Parse the CoS TLV from response to verify DSCP2/ECN2 were filled in
        let tlv_start = 44;
        assert_eq!(
            response.data[tlv_start + 1],
            TlvType::ClassOfService.to_byte()
        ); // Type

        // Parse the value via the typed decoder (single source of truth for
        // the RFC 8972 + cos-ecn-01 bit layout, unchanged from -00).
        let value_start = tlv_start + TLV_HEADER_SIZE;
        let raw = crate::tlv::RawTlv::new(
            TlvType::ClassOfService,
            response.data[value_start..value_start + COS_TLV_VALUE_SIZE].to_vec(),
        );
        let parsed = crate::tlv::ClassOfServiceTlv::from_raw(&raw).unwrap();
        assert_eq!(parsed.dscp1, 46, "DSCP1 should be preserved");
        assert_eq!(parsed.ecn1, 0, "EC1 should be preserved");
        assert_eq!(parsed.dscp2, received_dscp, "DSCP2 should be received DSCP");
        assert_eq!(parsed.ecn2, received_ecn, "EC2 should be received ECN");
        assert_eq!(parsed.rpd, 0, "RPD should be 0 (policy accepted)");
        assert_eq!(parsed.rpe, 0b11, "RPE should report reply ECN set to EC1");
    }

    #[test]
    fn test_assemble_auth_with_cos_tlv_updates_dscp_ecn() {
        use crate::tlv::{
            ClassOfServiceTlv, TlvType, TypedTlv, COS_TLV_VALUE_SIZE, TLV_HEADER_SIZE,
        };

        let sender_packet = PacketAuthenticated {
            sequence_number: 1,
            mbz0: [0; 12],
            timestamp: 100,
            error_estimate: 10,
            ssid: 0,
            mbz1a: [0; 30],
            mbz1b: [0; 32],
            mbz1c: [0; 6],
            hmac: [0; 16],
        };

        // Create packet with CoS TLV (sender requests DSCP=0 BE, ECN=1)
        let mut original_data = sender_packet.to_bytes().to_vec();
        let cos_tlv = ClassOfServiceTlv::new(0, 1);
        original_data.extend_from_slice(&cos_tlv.to_raw().to_bytes());

        // Reflect with received DSCP=32, ECN=3
        let received_dscp = 32u8;
        let received_ecn = 3u8;
        let response = assemble_auth_answer_with_tlvs(
            &sender_packet,
            &original_data,
            ClockFormat::NTP,
            200,
            64,
            300,
            None,
            None,
            TlvHandlingMode::Echo,
            None,
            false,
            &test_ctx(received_dscp, received_ecn),
        );

        // Response should include base + CoS TLV
        assert_eq!(
            response.data.len(),
            112 + TLV_HEADER_SIZE + COS_TLV_VALUE_SIZE
        );

        // Parse the CoS TLV from response
        let tlv_start = 112;
        assert_eq!(
            response.data[tlv_start + 1],
            TlvType::ClassOfService.to_byte()
        );

        let value_start = tlv_start + TLV_HEADER_SIZE;
        let raw = crate::tlv::RawTlv::new(
            TlvType::ClassOfService,
            response.data[value_start..value_start + COS_TLV_VALUE_SIZE].to_vec(),
        );
        let parsed = crate::tlv::ClassOfServiceTlv::from_raw(&raw).unwrap();
        // DSCP1/EC1 preserved
        assert_eq!(parsed.dscp1, 0);
        assert_eq!(parsed.ecn1, 1);
        // DSCP2/EC2 filled by reflector, RPE reports reply ECN applied
        assert_eq!(parsed.dscp2, received_dscp);
        assert_eq!(parsed.ecn2, received_ecn);
        assert_eq!(parsed.rpe, 0b11);
    }

    #[test]
    fn test_cos_unable_fallback_tos_zeroes_ecn_and_matches_reply_wire_tos() {
        use crate::tlv::ClassOfServiceTlv;

        // draft-ietf-ippm-stamp-cos-ecn-01 §3.2 MUST rule: the fallback TOS
        // the backends apply after a failed setsockopt must have its ECN
        // bits forced to 0b00, and must agree with the "unable" state of
        // `ClassOfServiceTlv::reply_wire_tos` (RPD=0b01, RPE=0b10) so the
        // wire value and the TLV's own fields never disagree.
        for received_dscp in [0u8, 10, 46, 63] {
            let fallback = cos_unable_fallback_tos(received_dscp);
            assert_eq!(fallback & 0x03, 0, "ECN bits must be zero (-01 §3.2)");

            let expected = ClassOfServiceTlv::for_response(46, 2, received_dscp, 1, true, false)
                .reply_wire_tos();
            assert_eq!(
                fallback, expected,
                "cos_unable_fallback_tos must match ClassOfServiceTlv::reply_wire_tos"
            );
        }
    }

    #[test]
    fn test_mtu_payload_cap_subtracts_ip_and_udp_headers() {
        // 1500-byte Ethernet MTU: 20 (IPv4) + 8 (UDP) of headers leaves 1472.
        // This is the case that matters — the old default cap of 1500 would
        // have built a 1528-byte datagram on exactly this link.
        assert_eq!(mtu_payload_cap(1500, false), 1472);
        // IPv6's fixed header is 40 bytes.
        assert_eq!(mtu_payload_cap(1500, true), 1452);
        // The IPv6 minimum link MTU.
        assert_eq!(mtu_payload_cap(1280, true), 1232);
    }

    #[test]
    fn test_mtu_payload_cap_floors_at_the_auth_base_size() {
        // An unusably small MTU must not produce a cap below a reply's own
        // mandatory base, which would make the reply-shaping arithmetic
        // meaningless rather than merely tight.
        assert_eq!(mtu_payload_cap(0, false), AUTH_BASE_SIZE as u16);
        assert_eq!(mtu_payload_cap(68, false), AUTH_BASE_SIZE as u16);
        assert_eq!(mtu_payload_cap(1, true), AUTH_BASE_SIZE as u16);
    }

    #[test]
    fn test_mtu_payload_cap_clamps_a_jumbo_mtu_to_u16() {
        // Loopback's 65536 MTU exceeds what the u16 cap field can hold.
        let cap = mtu_payload_cap(65_536, false);
        assert!(cap > 60_000, "a jumbo MTU must not wrap: got {cap}");
    }

    #[test]
    fn test_interface_mtu_rejects_bad_interface_names() {
        // Never panics, and an unknown or unusable name yields None so the
        // caller keeps its configured cap.
        assert_eq!(interface_mtu(""), None);
        assert_eq!(interface_mtu("definitely-not-an-interface"), None);
        assert_eq!(interface_mtu(&"x".repeat(64)), None);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_interface_mtu_reads_loopback() {
        // Loopback always exists on Linux. Tolerant of a sandbox that refuses
        // the socket or the ioctl — the point is that a success is sane, not
        // that the environment cooperates.
        if let Some(mtu) = interface_mtu("lo") {
            assert!(mtu >= 1500, "loopback MTU looks wrong: {mtu}");
        }
    }

    #[test]
    fn test_effective_max_size_keeps_configured_value_on_wildcard_bind() {
        // A wildcard bind has no single egress interface, so there is nothing
        // to query and the configured cap must survive untouched.
        let mut conf = <Configuration as clap::Parser>::parse_from(["test"]);
        conf.local_addr = "0.0.0.0".parse().unwrap();
        conf.reflected_control_max_size = 1500;
        assert_eq!(effective_reflected_control_max_size(&conf), 1500);
    }

    #[test]
    fn test_effective_max_size_never_exceeds_the_configured_cap() {
        // Whatever the live MTU turns out to be in this environment, the
        // operator's value is an upper bound: the query may only tighten it.
        let mut conf = <Configuration as clap::Parser>::parse_from(["test"]);
        conf.local_addr = "127.0.0.1".parse().unwrap();
        for configured in [128u16, 576, 1500, 9000] {
            conf.reflected_control_max_size = configured;
            let effective = effective_reflected_control_max_size(&conf);
            assert!(
                effective <= configured,
                "live MTU must only tighten the cap: {effective} > {configured}"
            );
        }
    }

    #[test]
    fn test_evaluate_replay_counts_duplicates_and_reorders() {
        use crate::session::{ReplayVerdict, Session};

        let session = Session::new(1);
        let counters = ReflectorCounters::new();
        let packet = |seq: u32| {
            let mut buf = vec![0u8; 44];
            buf[0..4].copy_from_slice(&seq.to_be_bytes());
            buf
        };
        // Classify-then-commit, the way a backend treats a packet that
        // passed verification and was answered.
        let eval_commit = |data: &[u8]| {
            let verdict = evaluate_replay(&session, data, &counters);
            commit_replay(&session, data);
            verdict
        };

        // In-order traffic is silent.
        assert_eq!(eval_commit(&packet(1)), ReplayVerdict::New);
        assert_eq!(eval_commit(&packet(2)), ReplayVerdict::New);
        assert_eq!(counters.packets_replayed.load(Ordering::Relaxed), 0);
        assert_eq!(counters.packets_reordered.load(Ordering::Relaxed), 0);

        // A duplicate is counted as a replay.
        assert_eq!(eval_commit(&packet(2)), ReplayVerdict::Replay);
        assert_eq!(counters.packets_replayed.load(Ordering::Relaxed), 1);

        // A late-but-unseen packet is counted separately: reordering is
        // ordinary and must not be reported as an attack.
        assert_eq!(
            eval_commit(&packet(1) /* already seen */),
            ReplayVerdict::Replay
        );
        assert_eq!(counters.packets_replayed.load(Ordering::Relaxed), 2);
        assert_eq!(
            counters.packets_reordered.load(Ordering::Relaxed),
            0,
            "a seen sequence number is a replay, not a reorder"
        );

        // Jump ahead, then deliver a gap-filler late: unseen and behind the
        // high-water mark, so it lands on the reorder counter, not the replay
        // one.
        assert_eq!(eval_commit(&packet(10)), ReplayVerdict::New);
        assert_eq!(eval_commit(&packet(8)), ReplayVerdict::Reordered);
        assert_eq!(counters.packets_reordered.load(Ordering::Relaxed), 1);
        assert_eq!(
            counters.packets_replayed.load(Ordering::Relaxed),
            2,
            "reordering must not inflate the replay count"
        );

        // A packet older than the window is counted with the reorders — the
        // window cannot claim it was seen. Advance far enough first that the
        // "older than the window" sequence number is still positive.
        assert_eq!(eval_commit(&packet(1000)), ReplayVerdict::New);
        assert_eq!(
            eval_commit(&packet(1000 - crate::session::REPLAY_WINDOW - 1)),
            ReplayVerdict::OutOfWindow
        );
        assert_eq!(counters.packets_reordered.load(Ordering::Relaxed), 2);
    }

    #[test]
    fn test_evaluate_replay_reads_sequence_from_both_layouts() {
        use crate::session::{ReplayVerdict, Session};

        // The Sequence Number is the first four octets in both the
        // authenticated (112-byte) and unauthenticated (44-byte) base layouts,
        // so one extraction serves both.
        for base_len in [UNAUTH_BASE_SIZE, AUTH_BASE_SIZE] {
            let session = Session::new(1);
            let counters = ReflectorCounters::new();
            let mut buf = vec![0u8; base_len];
            buf[0..4].copy_from_slice(&99u32.to_be_bytes());
            assert_eq!(
                evaluate_replay(&session, &buf, &counters),
                ReplayVerdict::New
            );
            commit_replay(&session, &buf);
            assert_eq!(
                evaluate_replay(&session, &buf, &counters),
                ReplayVerdict::Replay,
                "sequence number must be read identically at base length {base_len}"
            );
        }
    }

    /// An unverified packet (classified but never committed — e.g. bad HMAC)
    /// must not poison the anti-replay window: the genuine packet carrying
    /// the same sequence number is still `New`.
    #[test]
    fn test_replay_window_only_advances_on_commit() {
        use crate::session::{ReplayVerdict, Session};

        let session = Session::new(1);
        let counters = ReflectorCounters::new();
        let packet = |seq: u32| {
            let mut buf = vec![0u8; 44];
            buf[0..4].copy_from_slice(&seq.to_be_bytes());
            buf
        };

        // Attacker spoofs a predicted future sequence number; the packet
        // fails verification, so the backend never commits it.
        assert_eq!(
            evaluate_replay(&session, &packet(7), &counters),
            ReplayVerdict::New
        );
        // The genuine packet with that sequence number must still be New —
        // under --drop-replayed it would otherwise be dropped.
        assert_eq!(
            evaluate_replay(&session, &packet(7), &counters),
            ReplayVerdict::New
        );
        commit_replay(&session, &packet(7));
        // Only a committed (verified, answered) packet makes it a replay.
        assert_eq!(
            evaluate_replay(&session, &packet(7), &counters),
            ReplayVerdict::Replay
        );
    }

    #[test]
    fn test_evaluate_replay_tolerates_a_runt_packet() {
        use crate::session::{ReplayVerdict, Session};

        // Shorter than a Sequence Number: nothing to classify, and the
        // base-length rules handle it downstream. Must not panic.
        let session = Session::new(1);
        let counters = ReflectorCounters::new();
        for len in 0..4usize {
            assert_eq!(
                evaluate_replay(&session, &vec![0u8; len], &counters),
                ReplayVerdict::New
            );
        }
        assert_eq!(counters.packets_replayed.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn test_should_apply_fallback_tos_skips_the_byte_that_just_failed() {
        // EC1 = 0b00 and DSCP1 == received DSCP ⇒ the zero-ECN fallback byte
        // is identical to the byte the kernel just refused. Retrying it can
        // only fail again, so no second syscall should be issued.
        let attempted = cos_unable_fallback_tos(46); // DSCP 46, ECN 0
        let fallback = cos_unable_fallback_tos(46);
        assert!(!should_apply_fallback_tos(attempted, fallback, 0));
    }

    #[test]
    fn test_should_apply_fallback_tos_skips_when_already_on_the_socket() {
        // The fallback byte is already the socket's current TOS ⇒ the on-wire
        // ECN bits are already Not-ECT; nothing to re-apply.
        let fallback = cos_unable_fallback_tos(10);
        assert!(!should_apply_fallback_tos(
            46 << 2 | 0b10,
            fallback,
            fallback
        ));
    }

    #[test]
    fn test_should_apply_fallback_tos_applies_when_it_changes_the_wire() {
        // Requested DSCP 46 with EC1 = 0b10; the fallback keeps the received
        // DSCP (10) and zeroes the ECN half — a genuinely different byte that
        // is not yet on the socket, so it must be applied.
        let attempted = (46 << 2) | 0b10;
        let fallback = cos_unable_fallback_tos(10);
        assert_ne!(attempted, fallback);
        assert!(should_apply_fallback_tos(attempted, fallback, attempted));
    }

    #[test]
    fn test_set_cos_policy_rejected_unauth() {
        use crate::tlv::{ClassOfServiceTlv, TypedTlv};

        // Build an unauthenticated response with a CoS TLV
        let sender_packet = PacketUnauthenticated {
            sequence_number: 42,
            timestamp: 100,
            error_estimate: 10,
            ssid: 0,
            mbz: [0; 28],
        };
        let mut original_data = sender_packet.to_bytes().to_vec();
        let cos_tlv = ClassOfServiceTlv::new(46, 2); // DSCP=46, ECN=2
        original_data.extend_from_slice(&cos_tlv.to_raw().to_bytes());

        let mut response = assemble_unauth_answer_with_tlvs(
            &sender_packet,
            &original_data,
            ClockFormat::NTP,
            200,
            64,
            300,
            None,
            TlvHandlingMode::Echo,
            None,
            false,
            &test_ctx(0, 0),
        );

        // Verify RPD (value byte 1, bits 1:0) is initially 0
        let value_start = UNAUTH_BASE_SIZE + TLV_HEADER_SIZE;
        assert_eq!(response.data[value_start + 1] & 0x03, 0);

        // Simulate DSCP application failure by calling set_cos_policy_rejected
        let updated = set_cos_policy_rejected(&mut response.data, UNAUTH_BASE_SIZE);
        assert!(updated);

        // RPD=0b01 (DSCP1 not used) and RPE=0b10 (unable to set reply ECN)
        assert_eq!(response.data[value_start + 1] & 0x03, 0b01);
        assert_eq!((response.data[value_start + 2] >> 4) & 0x03, 0b10);
    }

    #[test]
    fn test_set_cos_policy_rejected_auth() {
        use crate::tlv::{ClassOfServiceTlv, TypedTlv};

        // Build an authenticated response with a CoS TLV
        let sender_packet = PacketAuthenticated {
            sequence_number: 42,
            mbz0: [0; 12],
            timestamp: 100,
            error_estimate: 10,
            ssid: 0,
            mbz1a: [0; 30],
            mbz1b: [0; 32],
            mbz1c: [0; 6],
            hmac: [0; 16],
        };
        let mut original_data = sender_packet.to_bytes().to_vec();
        let cos_tlv = ClassOfServiceTlv::new(46, 2);
        original_data.extend_from_slice(&cos_tlv.to_raw().to_bytes());

        let mut response = assemble_auth_answer_with_tlvs(
            &sender_packet,
            &original_data,
            ClockFormat::NTP,
            200,
            64,
            300,
            None,
            None,
            TlvHandlingMode::Echo,
            None,
            false,
            &test_ctx(0, 0),
        );

        // Verify RPD (value byte 1, bits 1:0) is initially 0
        let value_start = AUTH_BASE_SIZE + TLV_HEADER_SIZE;
        assert_eq!(response.data[value_start + 1] & 0x03, 0);

        // Simulate DSCP application failure
        let updated = set_cos_policy_rejected(&mut response.data, AUTH_BASE_SIZE);
        assert!(updated);

        // RPD=0b01 (DSCP1 not used) and RPE=0b10 (unable to set reply ECN)
        assert_eq!(response.data[value_start + 1] & 0x03, 0b01);
        assert_eq!((response.data[value_start + 2] >> 4) & 0x03, 0b10);
    }

    #[test]
    fn test_set_cos_policy_rejected_no_cos_tlv() {
        // Build a response without a CoS TLV
        let sender_packet = PacketUnauthenticated {
            sequence_number: 42,
            timestamp: 100,
            error_estimate: 10,
            ssid: 0,
            mbz: [0; 28],
        };
        let mut response = sender_packet.to_bytes().to_vec();

        // Should return false when no CoS TLV is present
        let updated = set_cos_policy_rejected(&mut response, UNAUTH_BASE_SIZE);
        assert!(!updated);
    }

    #[test]
    fn test_set_cos_policy_rejected_reserved_tlv_before_cos() {
        use crate::tlv::{ClassOfServiceTlv, TypedTlv};

        // Build a response with a zero-length Reserved TLV (header 00 00 00 00)
        // followed by a CoS TLV. The Reserved TLV must not be mistaken for padding.
        let sender_packet = PacketUnauthenticated {
            sequence_number: 42,
            timestamp: 100,
            error_estimate: 10,
            ssid: 0,
            mbz: [0; 28],
        };
        let mut response = sender_packet.to_bytes().to_vec();

        // Add Reserved TLV with zero length: flags=0, type=0, length=0
        response.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);

        // Add CoS TLV after the Reserved TLV
        let cos_tlv = ClassOfServiceTlv::new(46, 2); // DSCP=46, ECN=2
        response.extend_from_slice(&cos_tlv.to_raw().to_bytes());

        // Verify RPD (value byte 1, bits 1:0) is initially 0
        let cos_value_start = UNAUTH_BASE_SIZE + TLV_HEADER_SIZE + TLV_HEADER_SIZE; // Skip Reserved + CoS header
        assert_eq!(response[cos_value_start + 1] & 0x03, 0);

        // The Reserved TLV (00 00 00 00) should NOT stop iteration because
        // it's followed by non-zero data (the CoS TLV).
        let updated = set_cos_policy_rejected(&mut response, UNAUTH_BASE_SIZE);
        assert!(updated, "Should find CoS TLV after Reserved TLV");

        // RPD=0b01 (DSCP1 not used) and RPE=0b10 (unable to set reply ECN)
        assert_eq!(response[cos_value_start + 1] & 0x03, 0b01);
        assert_eq!((response[cos_value_start + 2] >> 4) & 0x03, 0b10);
    }

    #[test]
    fn test_recompute_hmac_after_rp_mutation() {
        use crate::tlv::{ClassOfServiceTlv, TlvList, TypedTlv, TLV_HEADER_SIZE};

        let key = HmacKey::new(vec![0xAB; 32]).unwrap();

        // Build an unauthenticated packet with CoS TLV + HMAC
        let sender_packet = PacketUnauthenticated {
            sequence_number: 0x12345678,
            timestamp: 100,
            error_estimate: 10,
            ssid: 0,
            mbz: [0; 28],
        };
        let base_bytes = sender_packet.to_bytes();

        let cos_tlv = ClassOfServiceTlv::new(46, 2);
        let mut tlvs = TlvList::new();
        tlvs.push(cos_tlv.to_raw()).unwrap();
        tlvs.set_hmac(&key, &base_bytes);

        let mut original_data = base_bytes.to_vec();
        original_data.extend_from_slice(&tlvs.to_bytes());

        // Assemble reflector response (HMAC will be recomputed for the response)
        let mut response = assemble_unauth_answer_with_tlvs(
            &sender_packet,
            &original_data,
            ClockFormat::NTP,
            200,
            64,
            300,
            None,
            TlvHandlingMode::Echo,
            Some(&key),
            true,
            &test_ctx(0, 0),
        );

        // Save the valid HMAC before mutation
        let hmac_start = response.data.len() - TLV_HEADER_SIZE - 16;
        let hmac_before = response.data[hmac_start + TLV_HEADER_SIZE..].to_vec();

        // Verify the response HMAC is valid before mutation
        let resp_tlv_data = &response.data[UNAUTH_BASE_SIZE..];
        let (resp_tlvs, _) = TlvList::parse_lenient(resp_tlv_data);
        assert!(
            resp_tlvs
                .verify_hmac(&key, &response.data[..4], resp_tlv_data)
                .is_ok(),
            "HMAC should be valid before RP mutation"
        );

        // Simulate RP mutation (DSCP application failure)
        assert!(set_cos_policy_rejected(
            &mut response.data,
            UNAUTH_BASE_SIZE
        ));

        // HMAC is now invalid because packet data changed
        let resp_tlv_data_after_rp = &response.data[UNAUTH_BASE_SIZE..];
        let (resp_tlvs_bad, _) = TlvList::parse_lenient(resp_tlv_data_after_rp);
        assert!(
            resp_tlvs_bad
                .verify_hmac(&key, &response.data[..4], resp_tlv_data_after_rp)
                .is_err(),
            "HMAC should be INVALID after RP mutation without recompute"
        );

        // Recompute HMAC
        assert!(recompute_response_tlv_hmac(
            &mut response.data,
            UNAUTH_BASE_SIZE,
            &key,
        ));

        // HMAC value should have changed
        let hmac_after = response.data[hmac_start + TLV_HEADER_SIZE..].to_vec();
        assert_ne!(
            hmac_before, hmac_after,
            "HMAC should change after recompute"
        );

        // Verify the recomputed HMAC is valid
        let resp_tlv_data_fixed = &response.data[UNAUTH_BASE_SIZE..];
        let (resp_tlvs_fixed, _) = TlvList::parse_lenient(resp_tlv_data_fixed);
        assert!(
            resp_tlvs_fixed
                .verify_hmac(&key, &response.data[..4], resp_tlv_data_fixed)
                .is_ok(),
            "HMAC should be valid after recompute"
        );
    }

    #[test]
    fn test_recompute_hmac_no_hmac_tlv() {
        // Response without HMAC TLV — recompute should return false
        let sender_packet = PacketUnauthenticated {
            sequence_number: 42,
            timestamp: 100,
            error_estimate: 10,
            ssid: 0,
            mbz: [0; 28],
        };
        let key = HmacKey::new(vec![0xAB; 32]).unwrap();
        let mut data = sender_packet.to_bytes().to_vec();
        // Add some non-HMAC TLV bytes
        data.extend_from_slice(&[0, 1, 0, 4, 0xCC, 0xCC, 0xCC, 0xCC]);
        assert!(!recompute_response_tlv_hmac(
            &mut data,
            UNAUTH_BASE_SIZE,
            &key
        ));
    }

    // ===== RFC 9503 Integration Tests =====

    #[test]
    fn test_unauth_dest_node_addr_match() {
        use crate::tlv::{DestinationNodeAddressTlv, TypedTlv};

        let sender_packet = PacketUnauthenticated {
            sequence_number: 1,
            timestamp: 100,
            error_estimate: 10,
            ssid: 0,
            mbz: [0; 28],
        };

        let addr: std::net::IpAddr = "192.168.1.1".parse().unwrap();
        let dna_tlv = DestinationNodeAddressTlv::new(addr);

        let mut original_data = sender_packet.to_bytes().to_vec();
        original_data.extend_from_slice(&dna_tlv.to_raw().to_bytes());

        let local_addrs = vec![addr];
        let mut ctx = test_ctx(0, 0);
        ctx.local_addresses = &local_addrs;

        let response = assemble_unauth_answer_with_tlvs(
            &sender_packet,
            &original_data,
            ClockFormat::NTP,
            200,
            64,
            300,
            None,
            TlvHandlingMode::Echo,
            None,
            false,
            &ctx,
        );

        // Check TLV is echoed without U-flag (flags byte at offset 44 = 0x00)
        assert_eq!(response.data[UNAUTH_BASE_SIZE] & 0x80, 0x00);
        assert_eq!(response.return_path_action, ReturnPathAction::Normal);
    }

    #[test]
    fn test_unauth_dest_node_addr_mismatch() {
        use crate::tlv::{DestinationNodeAddressTlv, TypedTlv};

        let sender_packet = PacketUnauthenticated {
            sequence_number: 1,
            timestamp: 100,
            error_estimate: 10,
            ssid: 0,
            mbz: [0; 28],
        };

        let addr: std::net::IpAddr = "192.168.1.1".parse().unwrap();
        let dna_tlv = DestinationNodeAddressTlv::new(addr);

        let mut original_data = sender_packet.to_bytes().to_vec();
        original_data.extend_from_slice(&dna_tlv.to_raw().to_bytes());

        let local_addrs: Vec<std::net::IpAddr> = vec!["10.0.0.1".parse().unwrap()];
        let mut ctx = test_ctx(0, 0);
        ctx.local_addresses = &local_addrs;

        let response = assemble_unauth_answer_with_tlvs(
            &sender_packet,
            &original_data,
            ClockFormat::NTP,
            200,
            64,
            300,
            None,
            TlvHandlingMode::Echo,
            None,
            false,
            &ctx,
        );

        // Check TLV is echoed WITH U-flag set (flags byte bit 7)
        assert_eq!(response.data[UNAUTH_BASE_SIZE] & 0x80, 0x80);
    }

    // ===== L2 Address Group sub-TLV unit tests =====
    // draft-ietf-ippm-asymmetrical-pkts-14 §3.1.1: bitwise AND the Mask
    // field against each local MAC and compare to the Group field; any
    // match means "continue processing", no match means "drop".

    #[test]
    fn l2_group_matches_any_local_exact_match() {
        let mask = [0xFFu8; 6];
        let group = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
        let locals = [[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]];
        assert!(l2_group_matches_any_local(&mask, &group, &locals));
    }

    #[test]
    fn l2_group_matches_any_local_masked_match() {
        // Only the first 3 octets (the OUI) are compared; the low 3 octets
        // of the local MAC differ from the group's low 3 octets but are
        // masked out, so this must still match.
        let mask = [0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00];
        let group = [0x00, 0x11, 0x22, 0x00, 0x00, 0x00];
        let locals = [[0x00, 0x11, 0x22, 0x99, 0x88, 0x77]];
        assert!(l2_group_matches_any_local(&mask, &group, &locals));
    }

    #[test]
    fn l2_group_matches_any_local_no_match() {
        let mask = [0xFFu8; 6];
        let group = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
        let locals = [[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]];
        assert!(!l2_group_matches_any_local(&mask, &group, &locals));
    }

    #[test]
    fn l2_group_matches_any_local_length_mismatch_never_matches() {
        // A 2-byte or 8-byte mask/group (Sub-TLV Length 4 or 16) can never
        // match a 6-byte EUI-48 local MAC — "with the same length" in the
        // draft text excludes them by construction.
        let locals = [[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]];
        assert!(!l2_group_matches_any_local(&[0xFF; 2], &[0x00; 2], &locals));
        assert!(!l2_group_matches_any_local(&[0xFF; 8], &[0x00; 8], &locals));
    }

    #[test]
    fn l2_group_matches_any_local_short_group_never_matches() {
        // Defensive: a 6-byte mask paired with a group shorter than 6 bytes
        // must be rejected, not indexed. The sub-TLV parser only ever hands
        // this helper equal-length mask/group pairs, so this is unreachable
        // from the wire today — but the helper is called with two
        // independently-sliced buffers and an out-of-bounds index here would
        // be a panic inside packet processing.
        let locals = [[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]];
        assert!(!l2_group_matches_any_local(&[0xFF; 6], &[0x00; 3], &locals));
        assert!(!l2_group_matches_any_local(&[0xFF; 6], &[], &locals));
    }

    #[test]
    fn l2_group_matches_any_local_empty_locals_never_matches() {
        // Empty `locals` (enumeration failed / no interfaces) ⇒ no match ⇒
        // drop, consistent with the L3 path's treatment of empty locals.
        let mask = [0xFFu8; 6];
        let group = [0x00u8; 6];
        assert!(!l2_group_matches_any_local(&mask, &group, &[]));
    }

    #[test]
    fn l2_group_matches_any_local_any_of_multiple_locals() {
        let mask = [0xFFu8; 6];
        let group = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
        let locals = [
            [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF],
            [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
        ];
        assert!(l2_group_matches_any_local(&mask, &group, &locals));
    }

    /// draft-ietf-ippm-asymmetrical-pkts-14 §3.1.1: "valid values for the
    /// Sub-TLV Length are 4, 12, and 16. Any other value MUST be considered
    /// ... as a malformed sub-TLV." This codebase's established handling
    /// for a malformed sub-TLV inside the Reflected Test Packet Control TLV
    /// (see the L3 Address Group length check just above in the source) is
    /// to silently skip it — no `L2Group` entry is produced, so it simply
    /// does not participate in matching, as if it were absent.
    #[test]
    fn parse_reflected_control_sub_tlvs_l2_valid_lengths_produce_entries() {
        for len in [4usize, 12, 16] {
            let mut body = Vec::new();
            body.extend_from_slice(&[0u8, REFLECTED_CONTROL_SUBTLV_L2_GROUP]);
            body.extend_from_slice(&(len as u16).to_be_bytes());
            body.extend(std::iter::repeat_n(0xAAu8, len));

            let parsed = parse_reflected_control_sub_tlvs(&body);
            assert_eq!(
                parsed.len(),
                1,
                "valid Sub-TLV Length {len} must parse to one L2Group entry"
            );
            match &parsed[0] {
                ReflectedControlSubTlv::L2Group { mask, group } => {
                    assert_eq!(mask.len(), len / 2);
                    assert_eq!(group.len(), len / 2);
                }
                other => panic!("expected L2Group, got {other:?}"),
            }
        }
    }

    #[test]
    fn parse_reflected_control_sub_tlvs_l2_malformed_length_is_skipped() {
        for len in [0usize, 2, 6, 8, 10, 20] {
            let mut body = Vec::new();
            body.extend_from_slice(&[0u8, REFLECTED_CONTROL_SUBTLV_L2_GROUP]);
            body.extend_from_slice(&(len as u16).to_be_bytes());
            body.extend(std::iter::repeat_n(0xAAu8, len));

            let parsed = parse_reflected_control_sub_tlvs(&body);
            assert!(
                parsed.is_empty(),
                "malformed Sub-TLV Length {len} must be skipped, not produce an entry"
            );
        }
    }

    #[test]
    fn test_unauth_return_path_suppress() {
        use crate::tlv::ReturnPathTlv;

        let sender_packet = PacketUnauthenticated {
            sequence_number: 1,
            timestamp: 100,
            error_estimate: 10,
            ssid: 0,
            mbz: [0; 28],
        };

        let rp_tlv = ReturnPathTlv::with_control_code(0x0);

        let mut original_data = sender_packet.to_bytes().to_vec();
        original_data.extend_from_slice(&rp_tlv.to_raw().to_bytes());

        let ctx = test_ctx(0, 0);

        let response = assemble_unauth_answer_with_tlvs(
            &sender_packet,
            &original_data,
            ClockFormat::NTP,
            200,
            64,
            300,
            None,
            TlvHandlingMode::Echo,
            None,
            false,
            &ctx,
        );

        assert_eq!(response.return_path_action, ReturnPathAction::SuppressReply);
    }

    #[test]
    fn test_unauth_return_path_alternate_addr() {
        use crate::tlv::ReturnPathTlv;

        let sender_packet = PacketUnauthenticated {
            sequence_number: 1,
            timestamp: 100,
            error_estimate: 10,
            ssid: 0,
            mbz: [0; 28],
        };

        let alt_addr: std::net::IpAddr = "10.0.0.5".parse().unwrap();
        let rp_tlv = ReturnPathTlv::with_return_address(alt_addr);

        let mut original_data = sender_packet.to_bytes().to_vec();
        original_data.extend_from_slice(&rp_tlv.to_raw().to_bytes());

        let mut ctx = test_ctx(0, 0);
        ctx.sender_port = 12345;
        // Opt in to alternate-address replies for this test.
        ctx.return_path_allow_alternate = true;

        let response = assemble_unauth_answer_with_tlvs(
            &sender_packet,
            &original_data,
            ClockFormat::NTP,
            200,
            64,
            300,
            None,
            TlvHandlingMode::Echo,
            None,
            false,
            &ctx,
        );

        assert_eq!(
            response.return_path_action,
            ReturnPathAction::AlternateAddress(std::net::SocketAddr::new(alt_addr, 12345))
        );
    }

    #[test]
    fn test_unauth_return_path_alternate_addr_denied_by_default() {
        // Security: with return_path_allow_alternate = false (the default),
        // a Return Address sub-TLV must NOT redirect the reply — otherwise an
        // unauthenticated peer could aim the reflector's reply at a third party.
        use crate::tlv::ReturnPathTlv;

        let sender_packet = PacketUnauthenticated {
            sequence_number: 1,
            timestamp: 100,
            error_estimate: 10,
            ssid: 0,
            mbz: [0; 28],
        };

        let alt_addr: std::net::IpAddr = "10.0.0.5".parse().unwrap();
        let rp_tlv = ReturnPathTlv::with_return_address(alt_addr);

        let mut original_data = sender_packet.to_bytes().to_vec();
        original_data.extend_from_slice(&rp_tlv.to_raw().to_bytes());

        let mut ctx = test_ctx(0, 0);
        ctx.sender_port = 12345;
        // return_path_allow_alternate defaults to false in test_ctx.

        let response = assemble_unauth_answer_with_tlvs(
            &sender_packet,
            &original_data,
            ClockFormat::NTP,
            200,
            64,
            300,
            None,
            TlvHandlingMode::Echo,
            None,
            false,
            &ctx,
        );

        // No redirection: reply goes to the packet source (Normal).
        assert_eq!(response.return_path_action, ReturnPathAction::Normal);
    }

    /// The CoS admission policy is scoped to where the reply actually goes:
    /// when an honoured Return Address redirects the reply, a
    /// destination-scoped rule for the alternate address must win over the
    /// (more permissive) treatment the original source would get.
    #[test]
    fn test_cos_policy_evaluated_against_alternate_return_address() {
        use crate::{
            cos_policy::{CosAdmissionPolicy, DscpSet, EcnSet},
            tlv::{ClassOfServiceTlv, ReturnPathTlv, TypedTlv},
        };

        let sender_packet = PacketUnauthenticated {
            sequence_number: 1,
            timestamp: 100,
            error_estimate: 10,
            ssid: 0,
            mbz: [0; 28],
        };

        let alt_addr: std::net::IpAddr = "10.0.0.5".parse().unwrap();
        let mut original_data = sender_packet.to_bytes().to_vec();
        original_data.extend_from_slice(
            &ReturnPathTlv::with_return_address(alt_addr)
                .to_raw()
                .to_bytes(),
        );
        original_data.extend_from_slice(&ClassOfServiceTlv::new(46, 0).to_raw().to_bytes());

        // Globally DSCP 46 is fine, but nothing may carry it toward 10/8.
        let policy: &'static CosAdmissionPolicy = Box::leak(Box::new(CosAdmissionPolicy::new(
            DscpSet::all(),
            EcnSet::all(),
            vec![("10.0.0.0".parse().unwrap(), 8, DscpSet::none())],
        )));

        let mut ctx = test_ctx(0, 0);
        ctx.sender_port = 12345;
        ctx.return_path_allow_alternate = true;
        ctx.cos_policy = policy;

        let response = assemble_unauth_answer_with_tlvs(
            &sender_packet,
            &original_data,
            ClockFormat::NTP,
            200,
            64,
            300,
            None,
            TlvHandlingMode::Echo,
            None,
            false,
            &ctx,
        );

        assert_eq!(
            response.return_path_action,
            ReturnPathAction::AlternateAddress(std::net::SocketAddr::new(alt_addr, 12345))
        );
        assert_eq!(
            response.cos_request,
            Some((0, 0)),
            "DSCP 46 is forbidden toward 10/8, so the reply must fall back to \
             the received DSCP even though the original source would permit it"
        );

        // Control case: the same packet without the alternate honoured is
        // evaluated against the original source and keeps DSCP 46.
        let mut ctx = test_ctx(0, 0);
        ctx.sender_port = 12345;
        ctx.cos_policy = policy; // allow_alternate stays false
        let response = assemble_unauth_answer_with_tlvs(
            &sender_packet,
            &original_data,
            ClockFormat::NTP,
            200,
            64,
            300,
            None,
            TlvHandlingMode::Echo,
            None,
            false,
            &ctx,
        );
        assert_eq!(response.return_path_action, ReturnPathAction::Normal);
        assert_eq!(response.cos_request, Some((46, 0)));
    }

    #[test]
    fn test_unauth_return_path_sr_unsupported() {
        use crate::tlv::ReturnPathTlv;

        let sender_packet = PacketUnauthenticated {
            sequence_number: 1,
            timestamp: 100,
            error_estimate: 10,
            ssid: 0,
            mbz: [0; 28],
        };

        let rp_tlv = ReturnPathTlv::with_sr_mpls_labels(&[100, 200]);

        let mut original_data = sender_packet.to_bytes().to_vec();
        original_data.extend_from_slice(&rp_tlv.to_raw().to_bytes());

        let ctx = test_ctx(0, 0);

        let response = assemble_unauth_answer_with_tlvs(
            &sender_packet,
            &original_data,
            ClockFormat::NTP,
            200,
            64,
            300,
            None,
            TlvHandlingMode::Echo,
            None,
            false,
            &ctx,
        );

        assert_eq!(response.return_path_action, ReturnPathAction::UnsupportedSr);
        // Return Path TLV should have U-flag set
        assert_eq!(response.data[UNAUTH_BASE_SIZE] & 0x80, 0x80);
    }

    #[test]
    fn test_set_return_path_u_flag_in_response() {
        use crate::tlv::ReturnPathTlv;

        let sender_packet = PacketUnauthenticated {
            sequence_number: 1,
            timestamp: 100,
            error_estimate: 10,
            ssid: 0,
            mbz: [0; 28],
        };

        let rp_tlv = ReturnPathTlv::with_return_address("10.0.0.5".parse().unwrap());

        let mut raw = rp_tlv.to_raw();
        // Simulate post-clear state (apply_reflector_flags has already run);
        // sender default is U=1 per RFC 8972 §4, but the U-flag toggle
        // tested here is the send-path "set after clear" path.
        raw.clear_reflector_flags();
        let mut data = sender_packet.to_bytes().to_vec();
        data.extend_from_slice(&raw.to_bytes());

        assert_eq!(data[UNAUTH_BASE_SIZE] & 0x80, 0);

        let updated = set_return_path_u_flag_in_response(&mut data, UNAUTH_BASE_SIZE);
        assert!(updated);
        assert_eq!(data[UNAUTH_BASE_SIZE] & 0x80, 0x80);
    }

    #[test]
    fn test_set_return_path_u_flag_no_return_path_tlv() {
        let sender_packet = PacketUnauthenticated {
            sequence_number: 1,
            timestamp: 100,
            error_estimate: 10,
            ssid: 0,
            mbz: [0; 28],
        };

        let mut data = sender_packet.to_bytes().to_vec();

        let updated = set_return_path_u_flag_in_response(&mut data, UNAUTH_BASE_SIZE);
        assert!(!updated);
    }

    // ===== RFC 9534 Micro-session ID TLV Receiver Tests =====

    #[test]
    fn test_unauth_with_micro_session_id_fills_reflector_id() {
        use crate::tlv::{MicroSessionIdTlv, TypedTlv};

        let sender_packet = PacketUnauthenticated {
            sequence_number: 1,
            timestamp: 100,
            error_estimate: 10,
            ssid: 0,
            mbz: [0; 28],
        };

        // Build packet with Micro-session ID TLV (sender_id=42, reflector_id=0)
        let msid_raw = MicroSessionIdTlv::new(42, 0).to_raw();
        let mut data = sender_packet.to_bytes().to_vec();
        data.extend_from_slice(&msid_raw.to_bytes());

        let mut ctx = test_ctx(0, 0);
        ctx.reflector_member_link_id = Some(99);

        let response = assemble_unauth_answer_with_tlvs(
            &sender_packet,
            &data,
            ClockFormat::NTP,
            500,
            64,
            0,
            None,
            TlvHandlingMode::Echo,
            None,
            false,
            &ctx,
        );

        // Should not suppress reply
        assert!(!matches!(
            response.return_path_action,
            ReturnPathAction::SuppressReply
        ));

        // Parse TLVs from response to check reflector ID was filled in
        let tlv_data = &response.data[UNAUTH_BASE_SIZE..];
        let tlvs = TlvList::parse(tlv_data).unwrap();
        let msid_tlv = &tlvs.non_hmac_tlvs()[0];
        let parsed = MicroSessionIdTlv::from_raw(msid_tlv).unwrap();
        assert_eq!(parsed.sender_micro_session_id, 42);
        assert_eq!(parsed.reflector_micro_session_id, 99);
    }

    #[test]
    fn test_unauth_with_micro_session_id_mismatch_discards() {
        use crate::tlv::{MicroSessionIdTlv, TypedTlv};

        let sender_packet = PacketUnauthenticated {
            sequence_number: 1,
            timestamp: 100,
            error_estimate: 10,
            ssid: 0,
            mbz: [0; 28],
        };

        // Build packet with Micro-session ID TLV (sender_id=42, reflector_id=50 — mismatch)
        let msid_raw = MicroSessionIdTlv::new(42, 50).to_raw();
        let mut data = sender_packet.to_bytes().to_vec();
        data.extend_from_slice(&msid_raw.to_bytes());

        let mut ctx = test_ctx(0, 0);
        ctx.reflector_member_link_id = Some(99);

        let response = assemble_unauth_answer_with_tlvs(
            &sender_packet,
            &data,
            ClockFormat::NTP,
            500,
            64,
            0,
            None,
            TlvHandlingMode::Echo,
            None,
            false,
            &ctx,
        );

        // Should suppress reply (discard) due to reflector ID mismatch
        assert!(matches!(
            response.return_path_action,
            ReturnPathAction::SuppressReply
        ));
    }

    #[test]
    fn test_auth_with_micro_session_id_fills_reflector_id() {
        use crate::tlv::{MicroSessionIdTlv, TypedTlv};

        let sender_packet = PacketAuthenticated {
            sequence_number: 1,
            mbz0: [0; 12],
            timestamp: 100,
            error_estimate: 10,
            ssid: 0,
            mbz1a: [0; 30],
            mbz1b: [0; 32],
            mbz1c: [0; 6],
            hmac: [0; 16],
        };

        let msid_raw = MicroSessionIdTlv::new(42, 0).to_raw();
        let mut data = sender_packet.to_bytes().to_vec();
        data.extend_from_slice(&msid_raw.to_bytes());

        let mut ctx = test_ctx(0, 0);
        ctx.reflector_member_link_id = Some(99);

        let response = assemble_auth_answer_with_tlvs(
            &sender_packet,
            &data,
            ClockFormat::NTP,
            500,
            64,
            0,
            None,
            None,
            TlvHandlingMode::Echo,
            None,
            false,
            &ctx,
        );

        assert!(!matches!(
            response.return_path_action,
            ReturnPathAction::SuppressReply
        ));

        let tlv_data = &response.data[AUTH_BASE_SIZE..];
        let tlvs = TlvList::parse(tlv_data).unwrap();
        let msid_tlv = &tlvs.non_hmac_tlvs()[0];
        let parsed = MicroSessionIdTlv::from_raw(msid_tlv).unwrap();
        assert_eq!(parsed.sender_micro_session_id, 42);
        assert_eq!(parsed.reflector_micro_session_id, 99);
    }

    #[test]
    fn test_auth_with_micro_session_id_mismatch_discards() {
        use crate::tlv::{MicroSessionIdTlv, TypedTlv};

        let sender_packet = PacketAuthenticated {
            sequence_number: 1,
            mbz0: [0; 12],
            timestamp: 100,
            error_estimate: 10,
            ssid: 0,
            mbz1a: [0; 30],
            mbz1b: [0; 32],
            mbz1c: [0; 6],
            hmac: [0; 16],
        };

        let msid_raw = MicroSessionIdTlv::new(42, 50).to_raw();
        let mut data = sender_packet.to_bytes().to_vec();
        data.extend_from_slice(&msid_raw.to_bytes());

        let mut ctx = test_ctx(0, 0);
        ctx.reflector_member_link_id = Some(99);

        let response = assemble_auth_answer_with_tlvs(
            &sender_packet,
            &data,
            ClockFormat::NTP,
            500,
            64,
            0,
            None,
            None,
            TlvHandlingMode::Echo,
            None,
            false,
            &ctx,
        );

        assert!(matches!(
            response.return_path_action,
            ReturnPathAction::SuppressReply
        ));
    }

    // ------------------------------------------------------------------
    // B7: --strict-packets coverage.
    //
    // Lenient mode (default) zero-fills short packets per RFC 8762 §4.6 so
    // we can interop with TWAMP-Light senders that emit < 44 bytes.
    // Strict mode (--strict-packets) rejects any packet that doesn't match
    // the exact wire layout. These tests pin the contract in both
    // directions so a future refactor doesn't silently flip it.

    fn loopback_src() -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 12345)
    }

    /// Full-size unauthenticated packet — both modes accept.
    #[test]
    fn strict_packets_unauth_full_size_both_modes_accept() {
        let packet = PacketUnauthenticated {
            sequence_number: 7,
            timestamp: 100,
            error_estimate: 10,
            ssid: 0,
            mbz: [0; 28],
        };
        let data = packet.to_bytes();

        for strict in [false, true] {
            let mut ctx = test_ctx(0, 0);
            ctx.strict_packets = strict;
            let r = process_stamp_packet(&data, loopback_src(), 64, false, &ctx);
            assert!(r.is_some(), "strict={strict} must accept full-size packet");
        }
    }

    /// The panic-isolating wrapper must be transparent on the happy path: a
    /// valid packet yields the same reply bytes as the raw entry point.
    #[test]
    fn process_stamp_packet_isolated_matches_raw_on_valid_packet() {
        let packet = PacketUnauthenticated {
            sequence_number: 7,
            timestamp: 100,
            error_estimate: 10,
            ssid: 0,
            mbz: [0; 28],
        };
        let data = packet.to_bytes();
        let ctx = test_ctx(0, 0);

        let raw = process_stamp_packet(&data, loopback_src(), 64, false, &ctx);
        let isolated = process_stamp_packet_isolated(&data, loopback_src(), 64, false, &ctx);
        assert!(raw.is_some() && isolated.is_some());
        // The reply embeds a fresh receive timestamp, so the bytes differ
        // between two calls; the structure (and hence the length) must not.
        assert_eq!(
            raw.map(|r| r.data.len()),
            isolated.map(|r| r.data.len()),
            "isolation wrapper must not alter the happy-path response shape"
        );
    }

    /// Short unauthenticated packet (40 bytes < 44). Lenient zero-fills and
    /// accepts; strict rejects without panicking.
    #[test]
    fn strict_packets_unauth_short_rejected_only_in_strict() {
        let data = [0u8; 40];

        let mut ctx_lenient = test_ctx(0, 0);
        ctx_lenient.strict_packets = false;
        assert!(
            process_stamp_packet(&data, loopback_src(), 64, false, &ctx_lenient).is_some(),
            "lenient mode must accept short packet"
        );

        let mut ctx_strict = test_ctx(0, 0);
        ctx_strict.strict_packets = true;
        assert!(
            process_stamp_packet(&data, loopback_src(), 64, false, &ctx_strict).is_none(),
            "strict mode must reject short packet"
        );
    }

    /// Full-size authenticated packet — both modes accept (no HMAC key
    /// configured here, so HMAC verification is skipped).
    #[test]
    fn strict_packets_auth_full_size_both_modes_accept() {
        let packet = PacketAuthenticated {
            sequence_number: 1,
            mbz0: [0; 12],
            timestamp: 200,
            error_estimate: 0,
            ssid: 0,
            mbz1a: [0; 30],
            mbz1b: [0; 32],
            mbz1c: [0; 6],
            hmac: [0; 16],
        };
        let data = packet.to_bytes();

        for strict in [false, true] {
            let mut ctx = test_ctx(0, 0);
            ctx.strict_packets = strict;
            let r = process_stamp_packet(&data, loopback_src(), 64, true, &ctx);
            assert!(
                r.is_some(),
                "strict={strict} must accept full-size auth packet"
            );
        }
    }

    /// Short authenticated packet (100 bytes < 112). Lenient zero-fills
    /// against canonical buffer per RFC 8762 §4.6; strict rejects.
    #[test]
    fn strict_packets_auth_short_rejected_only_in_strict() {
        let data = [0u8; 100];

        let mut ctx_lenient = test_ctx(0, 0);
        ctx_lenient.strict_packets = false;
        // No HMAC key → verification is skipped, lenient parser succeeds.
        assert!(
            process_stamp_packet(&data, loopback_src(), 64, true, &ctx_lenient).is_some(),
            "lenient mode must accept short auth packet (zero-filled)"
        );

        let mut ctx_strict = test_ctx(0, 0);
        ctx_strict.strict_packets = true;
        assert!(
            process_stamp_packet(&data, loopback_src(), 64, true, &ctx_strict).is_none(),
            "strict mode must reject short auth packet"
        );
    }

    /// Empty packet (0 bytes) — strict mode must reject without panicking.
    /// Lenient mode happens to accept it (everything zero), which is by
    /// design per RFC 8762 §4.6.
    #[test]
    fn strict_packets_empty_buffer_no_panic() {
        let data: [u8; 0] = [];

        let mut ctx_strict = test_ctx(0, 0);
        ctx_strict.strict_packets = true;
        assert!(process_stamp_packet(&data, loopback_src(), 64, false, &ctx_strict).is_none());
        assert!(process_stamp_packet(&data, loopback_src(), 64, true, &ctx_strict).is_none());

        let mut ctx_lenient = test_ctx(0, 0);
        ctx_lenient.strict_packets = false;
        // Lenient unauth accepts; lenient auth also accepts (HMAC skipped).
        // The point of this test is "no panic on hostile zero-byte input."
        let _ = process_stamp_packet(&data, loopback_src(), 64, false, &ctx_lenient);
        let _ = process_stamp_packet(&data, loopback_src(), 64, true, &ctx_lenient);
    }

    /// `require_hmac` + auth mode with no key configured: rejected in both
    /// strict and lenient modes. The `require_hmac` policy is independent
    /// of the packet-length strictness.
    #[test]
    fn strict_packets_require_hmac_rejects_regardless_of_mode() {
        let packet = PacketAuthenticated {
            sequence_number: 1,
            mbz0: [0; 12],
            timestamp: 200,
            error_estimate: 0,
            ssid: 0,
            mbz1a: [0; 30],
            mbz1b: [0; 32],
            mbz1c: [0; 6],
            hmac: [0; 16],
        };
        let data = packet.to_bytes();

        for strict in [false, true] {
            let mut ctx = test_ctx(0, 0);
            ctx.strict_packets = strict;
            ctx.require_hmac = true;
            // hmac_key stays None — require_hmac without a key drops.
            assert!(
                process_stamp_packet(&data, loopback_src(), 64, true, &ctx).is_none(),
                "strict={strict} + require_hmac without key must drop"
            );
        }
    }

    /// A present-but-empty keyset (e.g. the control plane deleted the last
    /// key at runtime) must CLOSE the reflector to authenticated packets,
    /// not downgrade it to answering them without verification — even with
    /// the default `require_hmac = false`.
    #[test]
    fn auth_packet_rejected_when_keyset_present_but_resolves_no_key() {
        let packet = PacketAuthenticated {
            sequence_number: 1,
            mbz0: [0; 12],
            timestamp: 200,
            error_estimate: 0,
            ssid: 0,
            mbz1a: [0; 30],
            mbz1b: [0; 32],
            mbz1c: [0; 6],
            hmac: [0; 16],
        };
        let data = packet.to_bytes();

        // Empty keyset — the "last key deleted" state.
        let empty_set = crate::crypto::HmacKeySet::new();
        let mut ctx = test_ctx(0, 0);
        ctx.hmac_key_set = Some(&empty_set);
        assert!(
            process_stamp_packet(&data, loopback_src(), 64, true, &ctx).is_none(),
            "empty keyset must reject auth packets, not answer them unverified"
        );

        // Keyset with a key for a *different* SSID and no default: an auth
        // packet with an unknown SSID must be rejected too.
        let mut other_ssid_set = crate::crypto::HmacKeySet::new();
        other_ssid_set.insert(42, crate::crypto::HmacKey::new(vec![0xAB; 16]).unwrap());
        let mut ctx = test_ctx(0, 0);
        ctx.hmac_key_set = Some(&other_ssid_set);
        assert!(
            process_stamp_packet(&data, loopback_src(), 64, true, &ctx).is_none(),
            "unknown SSID with no default key must be rejected"
        );

        // Sanity: with NO keyset at all (never configured), the legacy
        // keyless-open behavior is unchanged.
        let ctx = test_ctx(0, 0);
        assert!(
            process_stamp_packet(&data, loopback_src(), 64, true, &ctx).is_some(),
            "keyless reflector without any keyset keeps accepting"
        );
    }

    /// Non-zero MBZ bytes — RFC 8762 §4.1.1 requires receivers to *ignore*
    /// MBZ on receipt. Both modes must accept (strict mode does not extend
    /// to MBZ enforcement).
    #[test]
    fn strict_packets_nonzero_mbz_accepted_per_rfc_8762() {
        let packet = PacketUnauthenticated {
            sequence_number: 1,
            timestamp: 0,
            error_estimate: 0,
            ssid: 0,
            mbz: [0xff; 28], // intentionally non-zero
        };
        let data = packet.to_bytes();

        for strict in [false, true] {
            let mut ctx = test_ctx(0, 0);
            ctx.strict_packets = strict;
            assert!(
                process_stamp_packet(&data, loopback_src(), 64, false, &ctx).is_some(),
                "strict={strict} must ignore non-zero MBZ per RFC 8762 §4.1.1"
            );
        }
    }
}
