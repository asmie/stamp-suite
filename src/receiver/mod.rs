//! STAMP Session Reflector implementations.
//!
//! Platform defaults with real TTL capture:
//! - **Linux/macOS**: Uses nix via IP_RECVTTL. On Linux it also reads IPv6
//!   extension headers from ancillary data; fixed IP headers need pnet.
//! - **Windows**: Uses pnet for raw packet capture
//!
//! Explicit overrides (for other platforms or to override defaults):
//! - **`ttl-nix`**: Force nix backend
//! - **`ttl-pnet`**: Force pnet backend

mod assemble;
mod ingest;
mod keys;
mod limits;
mod local_addrs;
mod mtu;
mod reflected_control;
mod replay;
mod reply_bytes;
mod shared;
mod transmit;

pub use crate::packets::{AUTH_BASE_SIZE, AUTH_HMAC_OFFSET, UNAUTH_BASE_SIZE};
pub use assemble::*;
use keys::*;
pub use limits::*;
use local_addrs::*;
#[cfg(test)]
use mtu::{interface_mtu, mtu_payload_cap};
pub use reflected_control::ReflectedControlBehavior;
use reflected_control::*;
use replay::*;
use reply_bytes::*;
pub use shared::*;

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
        TlvList, TlvSpan, TlvType, TypedTlv, HMAC_TLV_VALUE_SIZE, MICRO_SESSION_ID_TLV_VALUE_SIZE,
        REFLECTED_CONTROL_SUBTLV_IPV6_EXT_HDR_CONTROL, TLV_HEADER_SIZE,
    },
};

/// Reads the SSID (RFC 8972 §3) without parsing the rest of the packet.
/// Returns 0, the unassigned value, when the buffer is too short; the
/// per-SSID key lookup then uses the default key.
fn peek_ssid(data: &[u8], use_auth: bool) -> u16 {
    let offset = if use_auth {
        crate::packets::AUTH_SSID_OFFSET
    } else {
        crate::packets::UNAUTH_SSID_OFFSET
    };
    data.get(offset..offset + 2)
        .map_or(0, |ssid| u16::from_be_bytes([ssid[0], ssid[1]]))
}

/// Extract identity without allocating runtime state. Malformed TLVs supply no
/// identity and terminate scanning, matching the ordinary M-flag echo rules.
/// Duplicate Micro-Session IDs are ambiguous and cannot select a session.
fn packet_session_key(
    data: &[u8],
    src: SocketAddr,
    local: SocketAddr,
    use_auth: bool,
) -> Option<crate::session::SessionKey> {
    let mut key = crate::session::SessionKey {
        client: src,
        local,
        ssid: peek_ssid(data, use_auth),
        sender_micro_session_id: None,
    };
    let base = if use_auth {
        AUTH_BASE_SIZE
    } else {
        UNAUTH_BASE_SIZE
    };
    let mut pos = base;
    while let Some(tlv) = TlvSpan::at(data, pos) {
        if tlv.tlv_type == TlvType::MicroSessionId {
            if key.sender_micro_session_id.is_some() {
                return None;
            }
            if tlv.len != MICRO_SESSION_ID_TLV_VALUE_SIZE {
                break;
            }
            let value = tlv.value_start();
            key.sender_micro_session_id = Some(u16::from_be_bytes([data[value], data[value + 1]]));
        }
        pos = tlv.end();
    }
    Some(key)
}

impl ProcessingContext<'_> {
    fn packet_session_key(
        &self,
        data: &[u8],
        src: SocketAddr,
        use_auth: bool,
    ) -> Option<crate::session::SessionKey> {
        let local = self
            .packet_local_addr
            .or_else(|| {
                self.packet_addr_info
                    .as_ref()
                    .map(|info| SocketAddr::new(info.dst_addr, info.dst_port))
            })
            .unwrap_or_else(|| crate::session::SessionKey::from(src).local);
        packet_session_key(data, src, local, use_auth)
    }
}

/// Response from STAMP packet processing, including optional CoS request.
#[derive(Debug)]
pub struct StampResponse {
    /// The response packet data to send.
    pub data: Vec<u8>,
    /// Requested DSCP/ECN from CoS TLV (if present).
    /// Tuple of (dscp1, ecn1) that should be applied to the outgoing packet.
    pub cos_request: Option<(u8, u8)>,
    /// Action determined by Return Path TLV processing (RFC 9503 §4).
    pub return_path_action: ReturnPathAction,
    /// Extra-replies descriptor from a Reflected Test Packet Control TLV
    /// (RFC 10052 §3). `None` when the incoming
    /// packet had no such TLV.
    pub reflected_control: Option<ReflectedControlBehavior>,
    /// IP source address the reply SHOULD be sent from, when a Destination
    /// Node Address TLV matched one of ours (RFC 9503 §3). `None` leaves source
    /// selection to the OS, which is also the fallback when pinning is
    /// unsupported or fails.
    pub reply_source: Option<std::net::IpAddr>,
    /// True when this reflector generated the TLV HMAC. Only a generated HMAC
    /// is re-signed at send time; an echoed one (I-flag failure echo, or no
    /// semantic processing) is copied unchanged per RFC 8972 §4.8.
    pub tlv_hmac_generated: bool,
}

/// Context for processing STAMP packets, shared between backends.
#[derive(Clone)]
pub struct ProcessingContext<'a> {
    /// Clock format for timestamps.
    pub clock_source: ClockFormat,
    /// Operator-declared discipline of the system clock, independent of encoding/S.
    pub clock_sync_source: SyncSource,
    /// Operator-declared discipline of NIC PHCs, used only for actual hardware T2.
    pub hardware_clock_sync_source: SyncSource,
    /// Error estimate in wire format.
    pub error_estimate_wire: u16,
    /// Single HMAC key (legacy single-tenant path). Used when no
    /// `hmac_key_set` is configured. Operators using `--hmac-key-dir`
    /// should populate `hmac_key_set` instead and leave this `None`.
    pub hmac_key: Option<&'a HmacKey>,
    /// Per-SSID HMAC key set. When `Some`, the reflector resolves
    /// the verification + response-HMAC key against the incoming
    /// packet's SSID via [`crate::crypto::HmacKeySet::for_ssid`]; on no match
    /// the packet is rejected as if the wrong key was supplied. When
    /// `None`, the receiver falls back to `hmac_key`.
    pub hmac_key_set: Option<&'a crate::crypto::HmacKeySet>,
    /// Whether HMAC is required.
    pub require_hmac: bool,
    /// Session admission and state; live backends supply this in both modes.
    pub session_manager: Option<&'a Arc<SessionManager>>,
    /// Whether the reflector runs in stateful mode (`--stateful-reflector`).
    /// Gates Follow-Up Telemetry reporting: in stateless mode (RFC 8762 §4)
    /// the Sequence Number and Follow-Up Timestamp fields MUST be zeroed
    /// (RFC 8972 §4.7) rather than carry the previous reflection.
    pub stateful_reflector: bool,
    /// Ordering of this verified base packet in its session. Live processing
    /// supplies the verdict; standalone callers without history use `New`.
    /// Non-monotonic Type-12 requests receive one U-flagged response
    /// (RFC 10052 §5).
    pub replay_verdict: crate::session::ReplayVerdict,
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
    /// Actual destination including its receiving interface zone, if available.
    pub packet_local_addr: Option<SocketAddr>,
    /// Interface the request arrived on, when the send path can pin a reply
    /// to it (RFC 9503 §4.1.1 same-link replies). `None` otherwise.
    pub ingress_ifindex: Option<u32>,
    /// Last reflection data: (seq, timestamp) for Follow-Up Telemetry TLV.
    pub last_reflection: Option<(u32, u64)>,
    /// Which Location TLV fields this reflector may report (RFC 8972 §4.2.2
    /// field-disclosure policy, `--location-disclose`).
    pub location_disclosure: LocationDisclosure,
    /// DSCP/ECN admission policy (RFC 8972 §4.4/§6, cos-ecn-01 §3.2): answers
    /// *permitted*, where the backends' setsockopt answers *capable*.
    pub cos_policy: &'a CosAdmissionPolicy,
    /// Local addresses for Destination Node Address TLV matching (RFC 9503 §3).
    pub local_addresses: &'a [std::net::IpAddr],
    /// Local MAC addresses for the Reflected Test Packet Control TLV's L2
    /// Address Group sub-TLV matching (RFC 10052
    /// §3.1.1). Populated by `build_local_macs`; an empty slice means no
    /// L2 Address Group sub-TLV can ever match (the packet is dropped per
    /// spec, not treated as "unsupported").
    pub local_macs: &'a [[u8; 6]],
    /// Sender's UDP port for Return Path alternate address replies (RFC 9503 §4).
    pub sender_port: u16,
    /// Whether to honour a Return Path "Return Address" sub-TLV by replying to
    /// the peer-chosen address (RFC 9503 §4). Off by default; when off the
    /// reflector echoes the TLV with the U-flag and replies to the packet
    /// source, preventing third-party traffic redirection / reflection.
    pub return_path_allow_alternate: bool,
    /// Reflector member link ID for Micro-session ID TLV (RFC 9534 §3.2).
    pub reflector_member_link_id: Option<u16>,
    /// Raw bytes of the received IP fixed header and IPv6 extension headers,
    /// for draft-ietf-ippm-stamp-ext-hdr Reflected Fixed/Ext Header TLVs
    /// (Types 247/246). `None` on backends that cannot observe the IP layer
    /// (the `nix` backend outside Linux): the reflector then returns those
    /// TLVs with the C flag set.
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
    /// Type 12 data-rate limit, bytes per second (RFC 10052 §3).
    pub reflected_control_max_rate: u64,
    /// Type 12 data-volume limit, bytes (RFC 10052 §3).
    pub reflected_control_max_volume: u32,
    /// Kernel-provided receive timestamp for this packet (STAMP wire
    /// format), filled by backends with `SO_TIMESTAMPING` enabled
    /// (feature "hwtstamp"). `None` → T2 is generated in userspace.
    pub rx_timestamp: Option<u64>,
    /// How T2 was produced (`HwAssist` only for NIC hardware timestamps;
    /// kernel-software and userspace timestamps are both `SwLocal`).
    pub rx_method: TimestampMethod,
    /// Acquisition method of last_reflection. The current T3 is generated
    /// in software; socket hardware enablement does not determine this field.
    pub last_reflection_method: TimestampMethod,
}

/// Raw IP-layer bytes captured at receive time for reflecting back to the
/// sender via TLV Types 246 and 247 (draft-ietf-ippm-stamp-ext-hdr-15).
///
/// The pnet backend, which captures at the datalink layer, fills both fields.
/// The nix backend on Linux fills only the IPv6 extension headers, from
/// ancillary data; it cannot observe fixed headers, so Type 247 requests get
/// the C flag there. The nix backend on other systems supplies no struct.
#[derive(Debug, Clone, Default)]
pub struct CapturedHeaders {
    /// Raw IP fixed headers (20 bytes for IPv4, 40 bytes for IPv6), ordered
    /// outer→inner. In the common (non-tunneled) case this holds exactly one
    /// header; an IP-in-IP tunnel (IP protocol 4 / next-header 41) contributes
    /// one record per stacked IP header for draft-ietf-ippm-stamp-ext-hdr-15
    /// §6.2 rule 3 positional pairing of multiple Type-247 TLVs. Empty when
    /// the backend cannot observe fixed headers; a captured IP packet always
    /// has at least one.
    pub fixed_headers: Vec<Vec<u8>>,
    /// IPv6 Hop-by-Hop, Destination Options, Routing (incl. SRH) and Fragment
    /// extension headers concatenated verbatim as on the wire: each record
    /// starts with its own Next Header octet (naming what follows it), then
    /// HdrExtLen, then the header body.
    pub ipv6_ext_headers: Vec<u8>,
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
             a bug; please report it. Further occurrences are logged at debug."
        );
    } else {
        log::debug!("panic while processing packet from {src} (dropped)");
    }
}

/// Parses, authenticates, and assembles a reply for either receiver backend.
/// Returns `None` to drop the packet; `StampResponse` includes reply bytes and
/// transport requests such as CoS.
pub fn process_stamp_packet(
    data: &[u8],
    src: SocketAddr,
    ttl: u8,
    use_auth: bool,
    ctx: &ProcessingContext,
) -> Option<StampResponse> {
    process_stamp_packet_inner(data, src, ttl, use_auth, ctx, None)
        .map(|processed| processed.response)
}

/// Live backend entry: authenticate, then acquire/update session state, classify
/// replay, and assemble with the resulting counters. The caller holds one keyset
/// read guard through this call. Return an owned snapshot of the exact key used
/// for verification/assembly, so backends never resolve a different signing key.
#[allow(clippy::too_many_arguments)]
fn process_session_packet_isolated(
    data: &[u8],
    src: SocketAddr,
    ttl: u8,
    use_auth: bool,
    ctx: &ProcessingContext,
    counters: &ReflectorCounters,
    drop_replayed: bool,
) -> Option<(StampResponse, Arc<crate::session::Session>, Option<HmacKey>)> {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let processed = process_stamp_packet_inner(
            data,
            src,
            ttl,
            use_auth,
            ctx,
            Some((counters, drop_replayed)),
        )?;
        Some((
            processed.response,
            processed.session?,
            processed.signing_key,
        ))
    })) {
        Ok(result) => result,
        Err(_) => {
            note_processing_panic(src);
            None
        }
    }
}

struct ProcessedPacket {
    response: StampResponse,
    session: Option<Arc<crate::session::Session>>,
    /// Owned only for live transmissions; standalone processing does not clone keys.
    signing_key: Option<HmacKey>,
}

enum ValidatedBase {
    Auth(PacketAuthenticated),
    Open(PacketUnauthenticated),
}

fn process_stamp_packet_inner(
    data: &[u8],
    src: SocketAddr,
    ttl: u8,
    use_auth: bool,
    ctx: &ProcessingContext,
    tracking: Option<(&ReflectorCounters, bool)>,
) -> Option<ProcessedPacket> {
    let admission = if let Some(manager) = ctx.session_manager {
        let key = ctx.packet_session_key(data, src, use_auth)?;
        Some(manager.admit(key)?)
    } else {
        None
    };
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

    // Resolve the HMAC key for this packet (per-SSID lookup). Falls
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

    // Reject authenticated-layout packets on an unauthenticated reflector.
    // Their MBZ bytes would become a zero timestamp/error estimate, producing
    // an invalid echo (RFC 8762 §4.2).
    //
    // Mode has no wire marker. Require the authenticated minimum length, zero
    // bytes 4..16, and nonzero timestamp/error-estimate fields at 16..26.
    // This excludes zero-timestamp unauthenticated packets, whose 16..26 bytes
    // are MBZ, and short TWAMP-Light packets below the length threshold.
    if !use_auth
        && data.len() >= AUTH_BASE_SIZE
        && data[4..16].iter().all(|&octet| octet == 0)
        && data[16..24].iter().any(|&octet| octet != 0)
        && data[24..26].iter().any(|&octet| octet != 0)
    {
        crate::warn_throttled!(
            "dropping {}-octet packet from {}: it has the shape of an \
             authenticated test packet but this reflector is in open mode \
             (-A O); reflecting it would emit a zero Error Estimate \
             (RFC 8762 §4.2 forbids multiplier 0)",
            data.len(),
            src
        );
        #[cfg(feature = "metrics")]
        if ctx.metrics_enabled {
            crate::metrics::reflector_metrics::record_packet_dropped("auth_packet_in_open_mode");
        }
        return None;
    }

    let packet = if use_auth {
        ValidatedBase::Auth(process_auth_packet(data, src, resolved_hmac_key, ctx)?)
    } else {
        ValidatedBase::Open(process_unauth_packet(data, src, ctx)?)
    };

    // No allocation, activity refresh, receive count, or replay classification
    // occurs before base parsing and the configured authentication have passed.
    let mut ctx = ctx.clone();
    let acquired_session = if tracking.is_some() || ctx.stateful_reflector {
        match admission {
            Some(permit) => Some(permit.acquire()?),
            None => None,
        }
    } else {
        // Standalone stateless processing checks provisioning without creating
        // runtime state, preserving the public processing API's behavior.
        None
    };
    if let Some((counters, drop_replayed)) = tracking {
        let session = acquired_session.as_ref()?;
        session.record_received();
        let verdict = evaluate_replay(session, data, counters);
        ctx.replay_verdict = verdict;
        if drop_replayed && verdict == crate::session::ReplayVerdict::Replay {
            // Type 12 has its own mandatory one-reply ordering failure path
            // (RFC 10052 §5). The optional duplicate
            // drop policy applies only when that TLV is not being handled.
            // Inspect only this opt-in duplicate path; semantic processing
            // still performs normal TLV integrity and address-group checks.
            let handles_control = ctx.tlv_mode == TlvHandlingMode::Echo && has_tlvs && {
                let mut pos = base_size;
                let mut found = false;
                while let Some(tlv) = TlvSpan::at(data, pos) {
                    if tlv.tlv_type == TlvType::ReflectedControl {
                        found = tlv.len >= crate::tlv::REFLECTED_CONTROL_TLV_MIN_VALUE_SIZE;
                        break;
                    }
                    pos = tlv.end();
                }
                found
            };
            if !handles_control {
                return None;
            }
        }
        ctx.reflector_rx_count = Some(session.get_received_count());
        ctx.reflector_tx_count = Some(session.get_transmitted_count());
        let (seq, timestamp, method) = session.get_last_reflection_with_method();
        ctx.last_reflection = Some((seq, timestamp));
        ctx.last_reflection_method = method;
    }
    let reflector_seq = if ctx.stateful_reflector && tracking.is_some() {
        // Live sends assign the sequence in transmission order, including queued bursts.
        Some(0)
    } else if ctx.stateful_reflector {
        match acquired_session.as_ref() {
            Some(session) => {
                let _active = session.transmission_guard()?;
                Some(session.generate_sequence_number())
            }
            None => None,
        }
    } else {
        None
    };
    let ctx = &ctx;
    let result = match packet {
        ValidatedBase::Auth(packet) => {
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
                        // use the per-SSID-resolved key (falls back to
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
                    tlv_hmac_generated: false,
                })
            }
        }
        ValidatedBase::Open(packet) => {
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
                    tlv_hmac_generated: false,
                })
            }
        }
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

    let response = result?;
    let counter_session = acquired_session.filter(|_| tracking.is_some());
    if let Some(session) = &counter_session {
        commit_replay(session, data);
    }
    Some(ProcessedPacket {
        response,
        session: counter_session,
        signing_key: resolved_hmac_key.filter(|_| tracking.is_some()).cloned(),
    })
}

/// Parses and authenticates the base before any persistent session mutation.
/// The canonical zero-filled buffer retains RFC 8762 §4.6 short-packet behavior.
fn process_auth_packet(
    data: &[u8],
    src: SocketAddr,
    resolved_hmac_key: Option<&HmacKey>,
    ctx: &ProcessingContext,
) -> Option<PacketAuthenticated> {
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
                crate::warn_throttled!(
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
        if !verify_packet_hmac(key, &canonical_buf, AUTH_HMAC_OFFSET, &hmac) {
            crate::warn_throttled!("HMAC verification failed for packet from {}", src);
            #[cfg(feature = "metrics")]
            if ctx.metrics_enabled {
                crate::metrics::reflector_metrics::record_hmac_failure();
                crate::metrics::reflector_metrics::record_packet_dropped("hmac_failure");
            }
            return None;
        }
    } else if ctx.hmac_key_set.is_some() {
        // A keyset exists (key dir / control plane) but resolved no key for
        // this packet's SSID (an unknown SSID with no default, or the last
        // key was deleted at runtime). Refuse the packet: removing a key must
        // revoke access, never downgrade the reflector to answering
        // authenticated-layout packets without verification.
        crate::warn_throttled!(
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
        crate::warn_throttled!(
            "HMAC key required but not configured; dropping packet from {}",
            src
        );
        #[cfg(feature = "metrics")]
        if ctx.metrics_enabled {
            crate::metrics::reflector_metrics::record_packet_dropped("hmac_required");
        }
        return None;
    }

    Some(packet)
}

/// Parses the open-mode base before any persistent session mutation.
fn process_unauth_packet(
    data: &[u8],
    src: SocketAddr,
    ctx: &ProcessingContext,
) -> Option<PacketUnauthenticated> {
    let packet_result = if ctx.strict_packets {
        PacketUnauthenticated::from_bytes(data)
    } else {
        Ok(PacketUnauthenticated::from_bytes_lenient(data))
    };
    match packet_result {
        Ok(packet) => Some(packet),
        Err(e) => {
            crate::warn_throttled!(
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

/// Tuple returned from `apply_semantic_tlv_processing`.
struct SemanticResult {
    cos_request: Option<(u8, u8)>,
    return_path_action: ReturnPathAction,
    reflected_control: Option<ReflectedControlBehavior>,
    /// RFC 9503 §3: the matched Destination Node Address, to be pinned as the
    /// reply's IP source address.
    reply_source: Option<std::net::IpAddr>,
    tlv_hmac_generated: bool,
}

/// Applies semantic TLV processing on the reflector side (RFC 8972 §4).
///
/// Called when HMAC verification passed and no malformed TLVs were found.
/// Returns `None` if the packet should be discarded (e.g. Micro-session ID mismatch).
fn apply_semantic_tlv_processing(
    tlvs: &mut TlvList,
    ctx: &ProcessingContext,
    tlv_hmac_key: Option<&HmacKey>,
    base_bytes: &[u8],
) -> Option<SemanticResult> {
    // Sources describe clock discipline, never the selected wire encoding or S
    // bit. T2 may come from a separately disciplined PHC; current T3 is always
    // generated in software before send, even when hardware TX is requested.
    let ingress_source = if ctx.rx_method == TimestampMethod::HwAssist {
        ctx.hardware_clock_sync_source
    } else {
        ctx.clock_sync_source
    };
    tlvs.update_timestamp_info_tlvs_with_sources(
        ingress_source,
        ctx.rx_method,
        ctx.clock_sync_source,
        TimestampMethod::SwLocal,
    );

    // Update Direct Measurement TLVs (RFC 8972 §4.5)
    if let (Some(rx), Some(tx)) = (ctx.reflector_rx_count, ctx.reflector_tx_count) {
        tlvs.update_direct_measurement_tlvs(rx, tx);
    }

    // Update Location TLVs (RFC 8972 §4.2), honouring the §4.2.2
    // field-disclosure policy.
    if let Some(ref addr_info) = ctx.packet_addr_info {
        tlvs.update_location_tlvs(addr_info, ctx.location_disclosure);
    }

    // RFC 8972 §4.7: report the previous reflection in stateful mode;
    // `None` zeroes sequence/timestamp in stateless mode. Always call this so
    // invalid-length TLVs are also zeroed.
    let reflection = if ctx.stateful_reflector {
        ctx.last_reflection
    } else {
        None
    };
    tlvs.update_follow_up_telemetry_tlvs(reflection, ctx.last_reflection_method);

    // Discard Access Report TLVs with an invalid Access ID (RFC 8972 §4.6:
    // values other than 1/2 MUST be discarded; marked U, size preserved).
    tlvs.discard_invalid_access_report_tlvs();

    // Process Destination Node Address TLV (RFC 9503 §3)
    let reply_source = tlvs
        .process_destination_node_address(ctx.local_addresses)
        .pinned_source();

    // Process Micro-session ID TLV (RFC 9534 §3.2)
    if let Some(refl_id) = ctx.reflector_member_link_id {
        if !tlvs.update_micro_session_id_tlvs(refl_id) {
            crate::warn_throttled!("Micro-session ID validation failed, discarding packet");
            return None;
        }
    }

    // Process Return Path TLV (RFC 9503 §4). Mutable: the
    // RFC 10052 §4.3 conflict rule below may
    // override a no-reply request.
    let mut return_path_action = tlvs.process_return_path(
        ctx.sender_port,
        ctx.return_path_allow_alternate,
        ctx.ingress_ifindex,
    );

    // Extract CoS request (DSCP1/ECN1) for outgoing IP_TOS.
    let requested_cos = tlvs.get_cos_request();

    // Check CoS permission before backend socket capability (RFC 8972 §4.4/§6,
    // cos-ecn-01 §3.2). Run after Return Path processing so destination rules
    // use any accepted alternate address (RFC 9503 §4).
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
                "CoS admission policy refused DSCP1 {dscp1} for a reply to {:?}; \
                 using the received DSCP {} with RPD=0b01",
                reply_destination,
                ctx.received_dscp
            );
        }
        if !ecn_permitted {
            log::debug!("CoS admission policy refused EC1 {ec1}; reply ECN forced to Not-ECT");
        }
    }

    // Record the CoS admission decision (RFC 8972 §4.4, cos-ecn-01 §3.2).
    // A later socket failure overrides RPD/RPE through `set_cos_policy_rejected`
    // and the IP header through `cos_unable_fallback_tos`.
    tlvs.update_cos_tlvs(
        ctx.received_dscp,
        ctx.received_ecn,
        !dscp_permitted,
        ecn_permitted,
    );

    // Process BER TLVs (draft-gandhi-ippm-stamp-ber-07 §4):
    // compute Bit Error Count and Max Burst against the companion Extra Padding.
    tlvs.process_ber();
    let ber_padding_len = tlvs
        .non_hmac_tlvs()
        .iter()
        .find(|t| t.tlv_type == TlvType::ExtraPadding)
        .map(|t| t.value.len());

    // Process Reflected Fixed / IPv6 Extension Header TLVs
    // (draft-ietf-ippm-stamp-ext-hdr-15 §§4.2, 6.2). If the backend captured
    // the requested header, copy it into the TLV (a zero Requested field is
    // filled from it); otherwise set the C flag per ext-hdr-15 §4.1/§6.1. A nix
    // UDP-socket backend has no fixed headers, so those requests get C; on
    // Linux it does supply IPv6 extension headers from ancillary data.
    let (captured_fixed, captured_ext): (Option<&[Vec<u8>]>, Option<&[u8]>) =
        match ctx.captured_headers {
            Some(h) => (
                Some(h.fixed_headers.as_slice()).filter(|fixed| !fixed.is_empty()),
                Some(h.ipv6_ext_headers.as_slice()),
            ),
            None => (None, None),
        };
    tlvs.process_reflected_headers_multi(captured_fixed, captured_ext);

    // draft-ietf-ippm-stamp-ext-hdr-15 §4.2/§6.2 MTU rule (reflector half): the
    // reflected test packet MUST NOT exceed the IP/IPv6 MTU after the Reflected
    // Fixed/IPv6 Ext Header TLVs; if necessary, one or more of those TLVs MUST
    // be removed. This assembly-time trim applies the administrative limit;
    // the shared send path additionally resolves the actual reply route and
    // enforces its payload budget immediately before each datagram. That
    // second check also accounts for alternate destinations and attached SRH.
    // The base + a reserve for the response HMAC TLV (if keyed) is the fixed
    // part; only complete optional header TLVs are removed here.
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
            crate::warn_throttled!(
                "Removed {removed} Reflected Fixed/IPv6 Ext Header TLV(s) (Type 246/247) from \
                 the reply to stay within the {}-byte reply-size limit \
                 (draft-ietf-ippm-stamp-ext-hdr-15 §4.2/§6.2)",
                ctx.reflected_control_max_size
            );
        }
    }

    // Apply L2 and L3 Address Group filters independently
    // (RFC 10052 §§3.1.1, 3.1.2).
    // Every present filter must match a local address; any mismatch drops the
    // packet. Sub-TLV flags do not affect matching.
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
                     MAC address; dropping packet per RFC 10052 §3.1.1"
                );
                return None;
            }
            if l3_matches == Some(false) {
                // §3.1.2: "If no matches are found, the Session-Reflector
                // MUST stop processing the received packet."
                log::debug!(
                    "Reflected Control L3 Address Group did not match any local \
                     address; dropping packet per RFC 10052 §3.1.2"
                );
                return None;
            }

            // draft-ietf-ippm-stamp-ext-hdr-15 §5.1: reply header attachment is
            // unsupported, so set C on every control sub-TLV. Duplicates also
            // violate cardinality. Type-246 reflection is handled independently.
            let one_way_ext_headers = ipv6_ext_hdr_control_count == 1;
            if ipv6_ext_hdr_control_count >= 1 {
                tlvs.set_ipv6_ext_hdr_control_c_flag();
            }

            if return_path_action == ReturnPathAction::SuppressReply
                && req.number_of_reflected_packets != 0
            {
                // RFC 10052 §4.3: combining a Return Path "no reply requested" control
                // code with a non-zero Reflected Test Packet Control TLV is a
                // sender error. The reflector MUST set U on both TLVs in the
                // (single, normal) reflected packet and SHOULD log it.
                crate::warn_throttled!(
                    "STAMP packet combines Return Path 'no reply requested' with a \
                     non-zero Reflected Test Packet Control TLV; setting U on both \
                     per RFC 10052 §4.3"
                );
                tlvs.set_reflected_control_u_flag();
                tlvs.set_return_path_u_flag();
                return_path_action = ReturnPathAction::Normal;
                None
            } else if ctx.replay_verdict != crate::session::ReplayVerdict::New {
                // RFC 10052 §5 applies to duplicate, reordered, and out-of-window
                // requests, including valid signed replays. Do not execute
                // their count, padding, or interval instructions. Finish the
                // normal TLV signing path after setting U on Type 12.
                tlvs.set_reflected_control_u_flag();
                if return_path_action == ReturnPathAction::SuppressReply {
                    tlvs.set_return_path_u_flag();
                    return_path_action = ReturnPathAction::Normal;
                }
                None
            } else if ctx.reflected_control_max_count == 0 {
                // Asymmetric reflection is disabled by default (RFC 10052 §5).
                // Behave as a reflector without Type 12 support: one normal
                // reply with U set (RFC 8972 §4).
                tlvs.set_reflected_control_u_flag();
                None
            } else if req.number_of_reflected_packets == 0 {
                // RFC 10052 §3: count 0 → "MUST NOT send any reflected packets", and
                // SHOULD discard the received test packet. (RFC 9503's
                // no-reply control code is the preferred way to request this.)
                log::debug!(
                    "Reflected Control count=0; suppressing reply per \
                     RFC 10052 §3"
                );
                return None;
            } else {
                let requested_count = req.number_of_reflected_packets;
                let mut non_conformant = false;
                // RFC 10052 §3 + §5: the reflector MUST limit the rate and volume of
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

                // RFC 10052 §3 length rules: the reflected length is the larger of
                //  (a) the base reply plus echoed TLVs *excluding* Extra
                //      Padding TLVs (so replies can shrink below the
                //      received packet's size), and
                //  (b) the requested length aligned up to a 4-octet boundary,
                // capped administratively here and by the actual reply
                // route MTU in the shared send path, before final signatures.
                tlvs.remove_extra_padding_tlvs();
                // Reserve 20 bytes for the reflector's HMAC TLV when the request
                // lacks one. If present, `wire_size()` already counts it.
                // See `set_hmac_response` for RFC 8972 §4.8 handling.
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

                // RFC 10052 §3: limit the data rate and volume each request
                // can generate. Exceeding either gives one C-flagged reply.
                let reply_len = target.max(current) as u128;
                let count = u128::from(requested_count);
                if reply_len * count > u128::from(ctx.reflected_control_max_volume) {
                    non_conformant = true;
                }
                if requested_count > 1 {
                    let interval = u128::from(req.interval_nanoseconds.max(1));
                    let rate = reply_len * 1_000_000_000 / interval;
                    if rate > u128::from(ctx.reflected_control_max_rate) {
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
                    max_size: ctx.reflected_control_max_size,
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

    // Sign after all TLV mutations, using reflector flags (U=0, RFC 8972 §4).
    // A configured key signs the reply even if the request lacked an HMAC TLV
    // (see `TlvList::set_hmac_response`, RFC 8972 §4.8).
    tlvs.finish_ber_padding(ber_padding_len);

    let tlv_hmac_generated =
        tlv_hmac_key.is_some_and(|key| tlvs.set_hmac_response(key, &base_bytes[..4]));

    Some(SemanticResult {
        cos_request,
        return_path_action,
        reflected_control,
        reply_source,
        tlv_hmac_generated,
    })
}

#[cfg(test)]
mod tests;
