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
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::{
    configuration::{ClockFormat, Configuration, TlvHandlingMode},
    crypto::{compute_packet_hmac, verify_packet_hmac, HmacKey},
    packets::{
        PacketAuthenticated, PacketUnauthenticated, ReflectedPacketAuthenticated,
        ReflectedPacketUnauthenticated,
    },
    session::SessionManager,
    stats::{self, OutputFormat},
    time::generate_timestamp,
    tlv::{
        PacketAddressInfo, ReturnPathAction, SyncSource, TimestampMethod, TlvList, TlvType,
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

/// Loads the HMAC key from configuration (hex string or file).
///
/// Single-key path retained for backward compatibility. Operators using
/// per-SSID keys should call `load_hmac_key_set` instead — see B6.
pub fn load_hmac_key(conf: &Configuration) -> Option<HmacKey> {
    if let Some(ref hex_key) = conf.hmac_key {
        match HmacKey::from_hex(hex_key) {
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
}

impl ReflectorCounters {
    pub fn new() -> Self {
        ReflectorCounters {
            packets_received: AtomicU64::new(0),
            packets_reflected: AtomicU64::new(0),
            packets_dropped: AtomicU64::new(0),
            packets_rate_limited: AtomicU64::new(0),
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
    rate: u32,
    burst: u32,
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
            rate,
            burst,
            state: std::sync::Mutex::new(RateLimiterState {
                last_cleanup: now,
                sources: StdHashMap::new(),
            }),
        }
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
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let now = Instant::now();
        Self::cleanup_expired_buckets(&mut state, now);

        let burst = self.burst as f64;
        let rate = self.rate as f64;
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

/// Shared state created externally and passed into receiver backends.
///
/// This allows the SNMP sub-agent (and other subsystems) to access
/// reflector counters and session state concurrently.
pub struct ReceiverSharedState {
    pub counters: Arc<ReflectorCounters>,
    pub session_manager: Arc<SessionManager>,
    pub start_time: Instant,
    pub rate_limiter: Option<Arc<RateLimiter>>,
    /// Flag observable by a future readiness probe (and the pnet
    /// `spawn_blocking` join path). Set to `false` when the capture / receive
    /// loop exits unexpectedly so external monitors can distinguish
    /// "process alive but not reflecting" from "process alive and healthy".
    pub capture_alive: Arc<std::sync::atomic::AtomicBool>,
}

/// Creates the shared state for the receiver, using configuration values.
pub fn create_shared_state(conf: &Configuration) -> ReceiverSharedState {
    let session_timeout = if conf.session_timeout > 0 {
        Some(Duration::from_secs(conf.session_timeout))
    } else {
        None
    };

    let rate_limiter = if conf.max_pps > 0 {
        Some(Arc::new(RateLimiter::with_burst(
            conf.max_pps,
            conf.reflector_rate_burst,
        )))
    } else {
        None
    };

    ReceiverSharedState {
        counters: Arc::new(ReflectorCounters::new()),
        session_manager: Arc::new(SessionManager::new(session_timeout, None)),
        start_time: Instant::now(),
        rate_limiter,
        capture_alive: Arc::new(std::sync::atomic::AtomicBool::new(true)),
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

/// Updates the RP (policy rejected) flag in a CoS TLV within the response buffer.
///
/// This should be called when setsockopt fails to apply the requested DSCP/ECN,
/// per RFC 8972 §5.2 which requires setting RP=1 to indicate policy rejection.
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
            // CoS TLV found - set RP flag (bits 6-7 of byte 2 in value)
            // RP=1 means policy rejected the DSCP request
            let rp_byte_offset = value_start + 2;
            // Set RP bits (upper 2 bits) to 01 (rejected), preserving reserved bits
            tlv_area[rp_byte_offset] = (tlv_area[rp_byte_offset] & 0x3F) | 0x40;
            return true;
        }

        offset += TLV_HEADER_SIZE + length;
    }

    false
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
}

/// Default hard cap on total reply packets emitted for a single Reflected
/// Control request. Protects against request amplification / DoS. The C flag
/// is set when the requested count exceeds this cap. Operators can override
/// at runtime via `--reflected-control-max-count`.
pub const REFLECTED_CONTROL_MAX_COUNT: u16 = 16;

/// Default reflector cap on the reply packet size (in octets) the reflector
/// will pad up to when honouring a Reflected Control TLV `length` request.
/// The C flag is set when the requested length exceeds this cap.
/// Defaults to a typical Ethernet MTU. Operators can override at runtime via
/// `--reflected-control-max-size`.
pub const REFLECTED_CONTROL_MAX_SIZE: u16 = 1500;

/// Default minimum inter-packet gap (nanoseconds) honoured by the backend;
/// smaller requested values are clamped up to this floor to avoid tight
/// busy-loops. The C flag is set when clamping actually changes the
/// interval. Operators can override at runtime via
/// `--reflected-control-min-interval-ns`.
pub const REFLECTED_CONTROL_MIN_INTERVAL_NS: u32 = 1_000;

/// Reflected Control sub-TLV types per draft-ietf-ippm-asymmetrical-pkts §3.
const REFLECTED_CONTROL_SUBTLV_L2_GROUP: u8 = 10;
const REFLECTED_CONTROL_SUBTLV_L3_GROUP: u8 = 11;

/// Parsed Reflected Control sub-TLV per draft-ietf-ippm-asymmetrical-pkts §3.
#[derive(Debug, Clone, PartialEq, Eq)]
enum ReflectedControlSubTlv {
    /// Layer 2 Address Group (sub-TLV type 10) — filter by MAC mask/group.
    /// Body is opaque to the UDP-socket backends, carried for completeness.
    L2Group {
        #[allow(dead_code)]
        body: Vec<u8>,
    },
    /// Layer 3 Address Group (sub-TLV type 11) — IP prefix match.
    L3Group { prefix_len: u8, prefix: Vec<u8> },
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
                out.push(ReflectedControlSubTlv::L2Group {
                    body: value.to_vec(),
                });
            }
            REFLECTED_CONTROL_SUBTLV_L3_GROUP => {
                // Draft §3: prefix_len(1) + reserved(3) + prefix(4 or 16).
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
    /// Local addresses for Destination Node Address TLV matching (RFC 9503 §4).
    pub local_addresses: &'a [std::net::IpAddr],
    /// Sender's UDP port for Return Path alternate address replies (RFC 9503 §5).
    pub sender_port: u16,
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
}

/// Raw IP-layer bytes captured at receive time for reflecting back to the
/// sender via TLV Types 246 and 247 (draft-ietf-ippm-stamp-ext-hdr).
///
/// Populated only by backends that capture at the datalink layer (pnet).
/// UDP-socket backends (nix) cannot observe these bytes and leave the
/// struct unset; the reflector sets the U-flag on any 246/247 request.
#[derive(Debug, Clone, Default)]
pub struct CapturedHeaders {
    /// Raw IP fixed header (20 bytes for IPv4, 40 bytes for IPv6).
    pub fixed_header: Vec<u8>,
    /// Concatenated IPv6 Hop-by-Hop (NextHeader 0) and Destination Options
    /// (NextHeader 60) extension headers, each prefixed with its NextHeader
    /// byte and HdrLen byte, exactly as received on the wire.
    pub ipv6_ext_headers: Vec<u8>,
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

    let rcvt = generate_timestamp(ctx.clock_source);

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
    // Extract CoS request (DSCP1/ECN1) for outgoing IP_TOS
    let cos_request = tlvs.get_cos_request();

    // Update CoS TLVs with received DSCP/ECN values (RFC 8972 §5.2)
    tlvs.update_cos_tlvs(ctx.received_dscp, ctx.received_ecn, false);

    // Update Timestamp Information TLVs (RFC 8972 §4.3)
    let sync_src = match ctx.clock_source {
        ClockFormat::NTP => SyncSource::Ntp,
        ClockFormat::PTP => SyncSource::Ptp,
    };
    tlvs.update_timestamp_info_tlvs(sync_src, TimestampMethod::SwLocal);

    // Update Direct Measurement TLVs (RFC 8972 §4.5)
    if let (Some(rx), Some(tx)) = (ctx.reflector_rx_count, ctx.reflector_tx_count) {
        tlvs.update_direct_measurement_tlvs(rx, tx);
    }

    // Update Location TLVs (RFC 8972 §4.2)
    if let Some(ref addr_info) = ctx.packet_addr_info {
        tlvs.update_location_tlvs(addr_info);
    }

    // Update Follow-Up Telemetry TLVs (RFC 8972 §4.7)
    if let Some((last_seq, last_ts)) = ctx.last_reflection {
        tlvs.update_follow_up_telemetry_tlvs(last_seq, last_ts, TimestampMethod::SwLocal);
    }

    // Process Destination Node Address TLV (RFC 9503 §4)
    tlvs.process_destination_node_address(ctx.local_addresses);

    // Process Micro-session ID TLV (RFC 9534 §3.2)
    if let Some(refl_id) = ctx.reflector_member_link_id {
        if !tlvs.update_micro_session_id_tlvs(refl_id) {
            log::warn!("Micro-session ID validation failed, discarding packet");
            return None;
        }
    }

    // Process Return Path TLV (RFC 9503 §5)
    let return_path_action = tlvs.process_return_path(ctx.sender_port);

    // Process BER TLVs (draft-gandhi-ippm-stamp-ber §3):
    // compute Bit Error Count and Max Burst against the companion Extra Padding.
    tlvs.process_ber();

    // Process Reflected Fixed / IPv6 Extension Header TLVs
    // (draft-ietf-ippm-stamp-ext-hdr §§3–4). If the backend captured raw IP
    // bytes, copy them into the TLV Value; otherwise set the U-flag per
    // RFC 8972 §4.2 and echo an empty TLV. A nix UDP-socket backend hands us
    // `captured_headers = None`, so this correctly advertises "unsupported"
    // to senders that requested header reflection.
    let (captured_fixed, captured_ext): (Option<&[u8]>, Option<&[u8]>) = match ctx.captured_headers
    {
        Some(h) => (
            Some(h.fixed_header.as_slice()),
            Some(h.ipv6_ext_headers.as_slice()),
        ),
        None => (None, None),
    };
    tlvs.process_reflected_headers(captured_fixed, captured_ext);

    // Process Reflected Test Packet Control TLV (draft-ietf-ippm-asymmetrical-pkts §3).
    // Count is clamped to ctx.reflected_control_max_count; the interval is clamped
    // up to ctx.reflected_control_min_interval_ns; either clamp sets the C flag.
    // A non-zero requested length triggers Extra Padding TLV insertion below up to
    // ctx.reflected_control_max_size; exceeding that cap sets the C flag.
    //
    // Per draft §3, when an L3 Address Group sub-TLV is present and no local
    // address matches, the reflector MUST stop processing the packet — we
    // signal that by returning a SuppressReply action. L2 Address Group
    // sub-TLVs require MAC-address visibility (link-layer access), which the
    // UDP-socket backends don't have; we set the U-flag on the echoed Type 12
    // and continue.
    let reflected_control = match tlvs.get_reflected_control_request() {
        Some(req) => {
            // Pre-check sub-TLVs: L3 mismatch → drop the packet entirely.
            let sub_chain = parse_reflected_control_sub_tlvs(&req.sub_tlvs);
            let mut l2_present = false;
            let mut l3_matches: Option<bool> = None;
            for sub in &sub_chain {
                match sub {
                    ReflectedControlSubTlv::L2Group { .. } => l2_present = true,
                    ReflectedControlSubTlv::L3Group { prefix_len, prefix } => {
                        l3_matches = Some(l3_group_matches_any_local(
                            *prefix_len,
                            prefix,
                            ctx.local_addresses,
                        ));
                    }
                    ReflectedControlSubTlv::Unknown { .. } => {}
                }
            }
            if l3_matches == Some(false) {
                // draft §3: "If no matches are found, the Session-Reflector
                // MUST stop processing the received packet."
                log::debug!(
                    "Reflected Control L3 Address Group did not match any local \
                     address; dropping packet per draft-ietf-ippm-asymmetrical-pkts §3"
                );
                return None;
            }
            if l2_present {
                // We can't evaluate L2 match without link-layer visibility.
                // Set U on the echoed Type 12 TLV to signal "unable to
                // honour this sub-TLV" without claiming we passed the filter.
                tlvs.set_reflected_control_u_flag();
            }

            let requested_count = req.number_of_reflected_packets;
            let effective_count = requested_count.min(ctx.reflected_control_max_count);
            let effective_interval = req
                .interval_nanoseconds
                .max(ctx.reflected_control_min_interval_ns);

            let mut non_conformant = false;
            if effective_count != requested_count {
                non_conformant = true;
            }
            if effective_interval != req.interval_nanoseconds && requested_count > 1 {
                non_conformant = true;
            }
            // Requested length handling: 0 = don't pad (sender opt-out).
            // Otherwise try to pad the response with an Extra Padding TLV to
            // reach the requested total reply size, up to the local cap.
            let requested_length = req.length_of_reflected_packet;
            if requested_length > 0 {
                let target = requested_length as usize;
                let cap = ctx.reflected_control_max_size as usize;
                let base_size = if tlv_hmac_key.is_some() {
                    AUTH_BASE_SIZE
                } else {
                    UNAUTH_BASE_SIZE
                };
                let current = base_size + tlvs.wire_size();
                let would_be = target.min(cap);
                // Need at least 4 bytes (TLV header) to insert an Extra
                // Padding TLV. The padding value carries (delta - 4) octets
                // of zeros.
                if would_be > current && would_be - current >= TLV_HEADER_SIZE {
                    let pad_bytes = would_be - current - TLV_HEADER_SIZE;
                    let pad_tlv = crate::tlv::ExtraPaddingTlv::new_zeros(pad_bytes).to_raw();
                    // push() places non-HMAC TLVs before the HMAC TLV in
                    // wire order so the chain remains spec-compliant.
                    let _ = tlvs.push(pad_tlv);
                    if target > cap {
                        // Clamped below request → C flag.
                        non_conformant = true;
                    }
                } else {
                    // Couldn't pad (request smaller than current size, or
                    // delta is too small to fit a TLV header). Signal C.
                    non_conformant = true;
                }
            }

            if non_conformant {
                tlvs.set_reflected_control_c_flag();
            }

            let extra_copies = effective_count.saturating_sub(1);
            Some(ReflectedControlBehavior {
                extra_copies,
                interval_ns: effective_interval,
            })
        }
        None => None,
    };

    // Compute fresh HMAC for response (must be last, after all TLV mutations).
    // Use the reflector variant so the regenerated HMAC TLV carries U=0 per
    // RFC 8972 §4.4.1 — the reflector recognizes the HMAC type by construction.
    if let Some(key) = tlv_hmac_key {
        let response_seq_bytes = &base_bytes[..4];
        tlvs.set_hmac_response(key, response_seq_bytes);
    }

    Some(SemanticResult {
        cos_request,
        return_path_action,
        reflected_control,
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
                        }
                        None => {
                            return StampResponse {
                                data: response,
                                cos_request: None,
                                return_path_action: ReturnPathAction::SuppressReply,
                                reflected_control: None,
                            };
                        }
                    }
                }

                tlvs.write_to(&mut response);
            }
        }
    }

    StampResponse {
        data: response,
        cos_request,
        return_path_action,
        reflected_control,
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
                        }
                        None => {
                            return StampResponse {
                                data: response,
                                cos_request: None,
                                return_path_action: ReturnPathAction::SuppressReply,
                                reflected_control: None,
                            };
                        }
                    }
                }

                tlvs.write_to(&mut response);
            }
        }
    }

    StampResponse {
        data: response,
        cos_request,
        return_path_action,
        reflected_control,
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
            local_addresses: &[],
            sender_port: 0,
            reflector_member_link_id: None,
            captured_headers: None,
            reflected_control_max_count: REFLECTED_CONTROL_MAX_COUNT,
            reflected_control_max_size: REFLECTED_CONTROL_MAX_SIZE,
            reflected_control_min_interval_ns: REFLECTED_CONTROL_MIN_INTERVAL_NS,
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

    #[test]
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

        // Parse the value bytes
        let value_start = tlv_start + TLV_HEADER_SIZE;
        // Byte 0: DSCP1 (6 bits) | ECN1 (2 bits) - should be preserved from sender
        let dscp1 = (response.data[value_start] >> 2) & 0x3F;
        let ecn1 = response.data[value_start] & 0x03;
        assert_eq!(dscp1, 46, "DSCP1 should be preserved");
        assert_eq!(ecn1, 0, "ECN1 should be preserved");

        // Byte 1: DSCP2 (6 bits) | ECN2 (2 bits) - should be filled by reflector
        let dscp2 = (response.data[value_start + 1] >> 2) & 0x3F;
        let ecn2 = response.data[value_start + 1] & 0x03;
        assert_eq!(dscp2, received_dscp, "DSCP2 should be received DSCP");
        assert_eq!(ecn2, received_ecn, "ECN2 should be received ECN");

        // Byte 2: RP (2 bits) - should be 0 (policy not rejected)
        let rp = (response.data[value_start + 2] >> 6) & 0x03;
        assert_eq!(rp, 0, "RP should be 0 (policy accepted)");
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
        // DSCP1/ECN1 preserved
        let dscp1 = (response.data[value_start] >> 2) & 0x3F;
        let ecn1 = response.data[value_start] & 0x03;
        assert_eq!(dscp1, 0);
        assert_eq!(ecn1, 1);

        // DSCP2/ECN2 filled by reflector
        let dscp2 = (response.data[value_start + 1] >> 2) & 0x3F;
        let ecn2 = response.data[value_start + 1] & 0x03;
        assert_eq!(dscp2, received_dscp);
        assert_eq!(ecn2, received_ecn);
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

        // Verify RP is initially 0
        let value_start = UNAUTH_BASE_SIZE + TLV_HEADER_SIZE;
        let rp_before = (response.data[value_start + 2] >> 6) & 0x03;
        assert_eq!(rp_before, 0);

        // Simulate DSCP application failure by calling set_cos_policy_rejected
        let updated = set_cos_policy_rejected(&mut response.data, UNAUTH_BASE_SIZE);
        assert!(updated);

        // Verify RP is now 1
        let rp_after = (response.data[value_start + 2] >> 6) & 0x03;
        assert_eq!(rp_after, 1);
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

        // Verify RP is initially 0
        let value_start = AUTH_BASE_SIZE + TLV_HEADER_SIZE;
        let rp_before = (response.data[value_start + 2] >> 6) & 0x03;
        assert_eq!(rp_before, 0);

        // Simulate DSCP application failure
        let updated = set_cos_policy_rejected(&mut response.data, AUTH_BASE_SIZE);
        assert!(updated);

        // Verify RP is now 1
        let rp_after = (response.data[value_start + 2] >> 6) & 0x03;
        assert_eq!(rp_after, 1);
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

        // Verify RP is initially 0
        let cos_value_start = UNAUTH_BASE_SIZE + TLV_HEADER_SIZE + TLV_HEADER_SIZE; // Skip Reserved + CoS header
        let rp_before = (response[cos_value_start + 2] >> 6) & 0x03;
        assert_eq!(rp_before, 0);

        // The Reserved TLV (00 00 00 00) should NOT stop iteration because
        // it's followed by non-zero data (the CoS TLV).
        let updated = set_cos_policy_rejected(&mut response, UNAUTH_BASE_SIZE);
        assert!(updated, "Should find CoS TLV after Reserved TLV");

        // Verify RP is now 1
        let rp_after = (response[cos_value_start + 2] >> 6) & 0x03;
        assert_eq!(rp_after, 1);
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
        // sender default is U=1 per RFC 8972 §4.4.1, but the U-flag toggle
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
