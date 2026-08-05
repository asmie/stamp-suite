use std::{
    collections::{HashMap, VecDeque},
    net::SocketAddr,
    time::{Duration, Instant},
};

use tokio::net::UdpSocket;

use crate::{
    clock_format::ClockFormat,
    configuration::{
        decode_selector, is_auth, Configuration, MalformedMode, TlvHmacMode, ZeroSsidAction,
    },
    crypto::{compute_packet_hmac, verify_packet_hmac, HmacKey},
    error_estimate::ErrorEstimate,
    packets::{
        ExtendedPacketAuthenticated, ExtendedPacketUnauthenticated,
        ExtendedReflectedPacketAuthenticated, ExtendedReflectedPacketUnauthenticated,
        PacketAuthenticated, PacketUnauthenticated, ReflectedPacketAuthenticated,
        ReflectedPacketUnauthenticated,
    },
    rate_control::{AimdController, AimdParams, AimdStats},
    receiver::{
        load_hmac_key, AUTH_BASE_SIZE, REFLECTED_AUTH_PACKET_HMAC_OFFSET, UNAUTH_BASE_SIZE,
    },
    session::Session,
    stats::{
        AccessReportOutcome, AccessReportSummary, CongestionSummary, OwdCollector, OwdSample,
        RttCollector, RttSample, StatsSnapshot,
    },
    time::{generate_timestamp, timestamp_to_nanos},
    tlv::{
        AccessReportTlv, BerBurstTlv, BerCountTlv, BerPatternTlv, ClassOfServiceTlv,
        DestinationNodeAddressTlv, DirectMeasurementTlv, ExtraPaddingTlv, FollowUpTelemetryTlv,
        LocationTlv, MicroSessionIdTlv, RawTlv, ReflectedControlTlv, ReflectedFixedHdrTlv,
        ReflectedIpv6ExtHdrTlv, ReturnPathTlv, TimestampInfoTlv, TlvList, TlvType, TypedTlv,
        IPV4_FIXED_HEADER_SIZE, IPV6_FIXED_HEADER_SIZE,
    },
};

/// Internal structure to track packets awaiting responses.
struct PendingPacket {
    /// Wall-clock time when the packet was sent.
    send_time: Instant,
    /// STAMP timestamp (T1) embedded in the sent packet, used to compute the
    /// forward one-way delay against the reflector's receive timestamp (T2).
    send_timestamp: u64,
}

/// Mutable context for processing received responses.
struct SenderRecvContext<'a> {
    pending: &'a mut HashMap<u32, PendingPacket>,
    rtt_collector: &'a mut RttCollector,
    owd_collector: &'a mut OwdCollector,
    packets_received: &'a mut u32,
    print_stats: bool,
    hmac_key: Option<&'a HmacKey>,
    /// Sender's Micro-session ID from the outgoing MSID TLV (RFC 9534 §3.2).
    /// Used to validate that the reflector echoed the same sender ID back;
    /// `None` means the sender did not request Micro-session ID measurement.
    expected_sender_msid: Option<u16>,
    /// Pre-known reflector member-link identifier (`--reflector-member-link-id`,
    /// RFC 9534 §3.2-11/-12). When set, the reflected Reflector Micro-session ID
    /// must equal it — validating the reflector's behaviour; a mismatching reply
    /// is discarded. `None` means the reflector ID is not pre-known.
    expected_reflector_msid: Option<u16>,
    /// Zero-config latch for the Reflector Micro-session ID (RFC 9534
    /// §3.2-11, unconditional requirement). When `expected_reflector_msid` is
    /// `None` (no pre-known value configured), the first validly-received
    /// reply's Reflector Micro-session ID is latched here and becomes the
    /// expected value for the remainder of the session — subsequent replies
    /// with a different reflector ID are discarded via the same
    /// `ReflectorMsidMismatch` path used for the pre-known case. Persists
    /// across `process_response` calls for the life of the sender session
    /// (mirrors `pending`/`rtt_collector` below, not reset per packet).
    latched_reflector_msid: &'a mut Option<u16>,
    /// Access Report TLV retransmission state (RFC 8972 §4.6). `Some` only
    /// when `--access-report` was set; `process_response` disarms its timer
    /// when a reflected packet echoes the Access Report TLV (§4.6:
    /// "This timer MUST be disarmed upon reception of the reflected STAMP
    /// test packet that includes the Access Report TLV").
    access_report_state: Option<&'a mut AccessReportRetransmitState>,
    /// AIMD congestion-response state (draft-ietf-ippm-stamp-cos-ecn-01
    /// §3.4). `Some` only when the sender requested ECN measurement;
    /// `process_response` drives it with `on_ce_observed`/`on_clean_reply`
    /// based on the reply's forward-path EC2 and/or reverse-path wire ECN.
    congestion: Option<&'a mut CongestionState>,
    /// The non-zero SSID this sender put on the wire, when it set one. RFC 8972
    /// §3's zeroed-SSID scenario is only meaningful against a sender that
    /// actually asked for SSID demultiplexing; `None` disables the check.
    expected_ssid: Option<u16>,
    /// What to do about a reflected packet whose SSID field came back zeroed
    /// (RFC 8972 §3: "An implementation of a Session-Sender MUST support
    /// control of its behavior in such a scenario").
    on_zero_ssid: ZeroSsidAction,
    /// Set by `process_response` when a zeroed-SSID reply arrives under
    /// [`ZeroSsidAction::Stop`]; the send loop and the Access Report wait phase
    /// both stop once it is set. Also latches "already warned" for the
    /// `Continue` policy so a long run logs the condition once, not per packet.
    zero_ssid_seen: &'a mut bool,
    #[cfg(feature = "metrics")]
    metrics_enabled: bool,
    #[cfg(all(unix, feature = "snmp"))]
    snmp_stats: Option<&'a crate::snmp::state::SenderSnmpStats>,
}

/// RFC 8972 §4.6 default retransmission timer value: "The default value of
/// the retransmission timer for the Access Report TLV SHOULD be three
/// seconds." Single source of truth for both the state machine's own tests
/// and the `--access-report-timeout` CLI default (`configuration.rs`).
pub(crate) const DEFAULT_ACCESS_REPORT_TIMEOUT: Duration = Duration::from_secs(3);

/// RFC 8972 §4.6 default retry budget: "This retransmission SHOULD be
/// repeated up to four times before the procedure is aborted." Single
/// source of truth for both the state machine's own tests and the
/// `--access-report-retries` CLI default (`configuration.rs`).
pub(crate) const DEFAULT_ACCESS_REPORT_RETRIES: u32 = 4;

/// Retransmission state machine for the Access Report TLV (RFC 8972 §4.6).
///
/// Pure and socket-free: the sender's existing send/receive loop drives it
/// with the `Instant` values it already has to hand via [`Self::tick`] (when
/// deciding whether to attach the TLV to the packet about to be sent) and
/// [`Self::acknowledge`] (when a reflected packet echoing the TLV is
/// received). No timers, threads, or async machinery of its own — this is
/// what makes it unit-testable without sockets or real waiting (`Instant`
/// arithmetic is deterministic; tests advance time by adding a `Duration`
/// rather than sleeping).
///
/// State machine, verbatim from RFC 8972 §4.6:
/// > The Session-Sender MUST also arm a retransmission timer after sending
/// > a test packet that includes the Access Report TLV. This timer MUST be
/// > disarmed upon reception of the reflected STAMP test packet that
/// > includes the Access Report TLV. In the event the timer expires before
/// > such a packet is received, the Session-Sender MUST retransmit the
/// > STAMP test packet that contains the Access Report TLV. This
/// > retransmission SHOULD be repeated up to four times before the
/// > procedure is aborted.
#[derive(Debug, Clone, PartialEq, Eq)]
struct AccessReportRetransmitState {
    timeout: Duration,
    max_retries: u32,
    phase: AccessReportPhase,
    retransmissions: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AccessReportPhase {
    /// The Access Report TLV has not been sent yet.
    NotStarted,
    /// Sent (or retransmitted) and awaiting the reflected echo before
    /// `deadline`. `attempt` is 0 for the original send, 1..=`max_retries`
    /// for the Nth retransmission.
    Armed { attempt: u32, deadline: Instant },
    /// The reflector's echo was received before the retry budget was
    /// exhausted; nothing further is sent.
    Acknowledged,
    /// The retry budget was exhausted without an acknowledgment; the
    /// procedure is aborted and nothing further is sent (RFC 8972 §4.6:
    /// "...before the procedure is aborted"). The measurement itself is
    /// unaffected — only this sub-feature gives up.
    Aborted,
}

impl AccessReportRetransmitState {
    /// Creates a fresh, not-yet-armed state machine using the given
    /// retransmission timer and retry budget (RFC 8972 §4.6: "An
    /// implementation MUST provide control of the retransmission timer
    /// value and the number of retransmissions").
    fn new(timeout: Duration, max_retries: u32) -> Self {
        Self {
            timeout,
            max_retries,
            phase: AccessReportPhase::NotStarted,
            retransmissions: 0,
        }
    }

    /// Drives the state machine forward by one send-loop iteration. Call
    /// this once per iteration, before deciding whether to build that
    /// iteration's outgoing packet with the Access Report TLV attached.
    ///
    /// Returns `true` exactly when the TLV should be attached to *this*
    /// packet: either the very first send, or a retransmission because the
    /// timer expired without an acknowledgment. Returns `false` while
    /// waiting on an armed timer that has not yet expired, and once the
    /// procedure has been `Acknowledged` or `Aborted` (nothing further is
    /// ever sent again).
    fn tick(&mut self, now: Instant) -> bool {
        match self.phase {
            AccessReportPhase::NotStarted => {
                self.phase = AccessReportPhase::Armed {
                    attempt: 0,
                    deadline: now + self.timeout,
                };
                true
            }
            AccessReportPhase::Armed { attempt, deadline } => {
                if now < deadline {
                    false
                } else if attempt < self.max_retries {
                    self.retransmissions += 1;
                    self.phase = AccessReportPhase::Armed {
                        attempt: attempt + 1,
                        deadline: now + self.timeout,
                    };
                    true
                } else {
                    self.phase = AccessReportPhase::Aborted;
                    false
                }
            }
            AccessReportPhase::Acknowledged | AccessReportPhase::Aborted => false,
        }
    }

    /// Disarms the retransmission timer on reception of a reflected packet
    /// that echoes the Access Report TLV (RFC 8972 §4.6). A no-op unless
    /// currently `Armed` — in particular, an ack cannot resurrect an already
    /// `Aborted` procedure, and one arriving before anything was ever sent
    /// (should not happen) is ignored rather than mis-recorded.
    fn acknowledge(&mut self) {
        if matches!(self.phase, AccessReportPhase::Armed { .. }) {
            self.phase = AccessReportPhase::Acknowledged;
        }
    }

    /// The current delivery outcome, for reporting in the sender's stats
    /// summary. `NotStarted`/`Armed` both surface as `Pending` — from the
    /// caller's perspective the report has not (yet) been confirmed
    /// delivered either way.
    fn outcome(&self) -> AccessReportOutcome {
        match self.phase {
            AccessReportPhase::Acknowledged => AccessReportOutcome::Acknowledged,
            AccessReportPhase::Aborted => AccessReportOutcome::Aborted,
            AccessReportPhase::NotStarted | AccessReportPhase::Armed { .. } => {
                AccessReportOutcome::Pending
            }
        }
    }

    /// Number of retransmissions actually performed so far.
    fn retransmissions(&self) -> u32 {
        self.retransmissions
    }

    /// `true` once the procedure has reached a terminal state
    /// (`Acknowledged` or `Aborted`) — nothing further will ever be sent or
    /// waited for. Used by the sender's post-loop wait phase to know when
    /// it can stop keeping the session alive on this state machine's
    /// account (RFC 8972 §4.6).
    fn is_terminal(&self) -> bool {
        matches!(
            self.phase,
            AccessReportPhase::Acknowledged | AccessReportPhase::Aborted
        )
    }

    /// The current retransmission deadline, if still `Armed`. Lets a caller
    /// that just called [`Self::tick`] and got `false` back (not due yet)
    /// know how long to sleep before calling `tick` again, instead of busy
    /// polling.
    fn armed_deadline(&self) -> Option<Instant> {
        match self.phase {
            AccessReportPhase::Armed { deadline, .. } => Some(deadline),
            AccessReportPhase::NotStarted
            | AccessReportPhase::Acknowledged
            | AccessReportPhase::Aborted => None,
        }
    }

    /// Builds the [`AccessReportSummary`] for [`StatsSnapshot::with_access_report`].
    fn summary(&self) -> AccessReportSummary {
        AccessReportSummary {
            outcome: self.outcome(),
            retransmissions: self.retransmissions(),
        }
    }
}

/// Congestion-response state driven by CE observations on reflected
/// packets, per draft-ietf-ippm-stamp-cos-ecn-01 §3.4. `Some` only when the
/// sender requested ECN measurement (`--cos` with `--ecn` requesting ECT0
/// or ECT1) — the contexts in which reflected/reply CE feedback is
/// meaningful, per the draft §3.4 activation conditions quoted on
/// [`AimdController`].
///
/// Whether the same controller also scales the Reflected Test Packet
/// Control TLV's interval (§3.4-3) is tracked separately by the send
/// loop's own `scale_reflected_control` local — it needs to be known
/// before this state exists (to decide whether the static TLV push at
/// startup should be skipped), so duplicating it as a field here would
/// just be a second, easily-desynced copy of the same bit.
struct CongestionState {
    controller: AimdController,
}

impl CongestionState {
    fn new(params: AimdParams) -> Self {
        Self {
            controller: AimdController::new(params),
        }
    }

    /// Builds the [`CongestionSummary`] for [`StatsSnapshot::with_congestion`].
    fn summary(&self) -> CongestionSummary {
        let AimdStats {
            ce_observations,
            backoffs_applied,
            current_interval,
            peak_interval,
            base_interval,
        } = self.controller.stats();
        CongestionSummary {
            ce_replies: ce_observations,
            backoffs_applied,
            current_interval_ms: current_interval.as_secs_f64() * 1000.0,
            max_interval_reached_ms: peak_interval.as_secs_f64() * 1000.0,
            base_interval_ms: base_interval.as_secs_f64() * 1000.0,
        }
    }
}

/// Applies the egress IP header options — DSCP/ECN (packed into the TOS /
/// IPv6 Traffic Class octet) and an optional TTL / Hop Limit — directly to the
/// raw socket `fd`, so the *wire* IP header matches what the Class of Service
/// TLV advertises (RFC 8972 §4.4). Each option is independently optional;
/// `None` leaves the kernel default untouched.
///
/// Only available on Linux/macOS, where `nix` (and thus `libc`) is guaranteed.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn apply_egress_ip_options(
    fd: std::os::fd::RawFd,
    is_ipv6: bool,
    tos: Option<u8>,
    ttl: Option<u8>,
) -> std::io::Result<()> {
    use nix::libc;

    // SAFETY: `fd` is an open socket owned by the caller for the duration of
    // the call; the option value outlives the syscall and its length is passed
    // explicitly, so `setsockopt` reads exactly `size_of::<c_int>()` bytes.
    let set_int =
        |level: libc::c_int, name: libc::c_int, value: libc::c_int| -> std::io::Result<()> {
            let rc = unsafe {
                libc::setsockopt(
                    fd,
                    level,
                    name,
                    std::ptr::addr_of!(value).cast(),
                    std::mem::size_of::<libc::c_int>() as libc::socklen_t,
                )
            };
            if rc < 0 {
                Err(std::io::Error::last_os_error())
            } else {
                Ok(())
            }
        };

    if let Some(tos) = tos {
        let (level, name) = if is_ipv6 {
            (libc::IPPROTO_IPV6, libc::IPV6_TCLASS)
        } else {
            (libc::IPPROTO_IP, libc::IP_TOS)
        };
        set_int(level, name, libc::c_int::from(tos))?;
    }
    if let Some(ttl) = ttl {
        let (level, name) = if is_ipv6 {
            (libc::IPPROTO_IPV6, libc::IPV6_UNICAST_HOPS)
        } else {
            (libc::IPPROTO_IP, libc::IP_TTL)
        };
        set_int(level, name, libc::c_int::from(ttl))?;
    }
    Ok(())
}

/// Attaches the real IPv6 extension headers requested via `--attach-ext-hdr`
/// (draft-ietf-ippm-stamp-ext-hdr-11 §3.1) to the sender's egress socket via
/// the sticky `IPV6_HOPOPTS` / `IPV6_DSTOPTS` socket options, so the headers
/// ride on every subsequent test packet the kernel emits. Byte 0 (Next Header)
/// of each buffer is assigned by the kernel; the rest is passed verbatim.
///
/// Best-effort: a per-header failure is logged and skipped (the matching
/// Type-246 request TLV is still sent, and the reflector then reports the C
/// flag for the header it never sees). Linux only — the `libc` crate exports
/// `IPV6_HOPOPTS` / `IPV6_DSTOPTS` for `linux_like` targets only, and the
/// sticky-option technique is the one proved on the wire by the netns tier.
/// Note that the kernel keeps a single sticky buffer per option, so at most one
/// Hop-by-Hop and one Destination Options header can be attached this way;
/// supplying several of the same kind leaves only the last in effect.
#[cfg(target_os = "linux")]
fn apply_attach_ext_hdrs(fd: std::os::fd::RawFd, specs: &[crate::configuration::AttachExtHdrSpec]) {
    use nix::libc;

    use crate::configuration::AttachExtHdrKind;

    for spec in specs {
        let (opt, label) = match spec.kind {
            AttachExtHdrKind::HopByHop => (libc::IPV6_HOPOPTS, "Hop-by-Hop"),
            AttachExtHdrKind::DestOpts => (libc::IPV6_DSTOPTS, "Destination Options"),
        };
        // SAFETY: `fd` is an open IPv6 socket owned by the caller; the buffer
        // outlives the syscall and its length is passed explicitly. The kernel
        // validates the extension-header contents and rejects a malformed one.
        let rc = unsafe {
            libc::setsockopt(
                fd,
                libc::IPPROTO_IPV6,
                opt,
                spec.bytes.as_ptr().cast(),
                spec.bytes.len() as libc::socklen_t,
            )
        };
        if rc < 0 {
            log::warn!(
                "Failed to attach {label} IPv6 extension header ({} bytes): {} — the matching \
                 Type-246 request TLV is still sent; the reflector will report the C flag for \
                 the header it never receives",
                spec.bytes.len(),
                std::io::Error::last_os_error()
            );
        } else {
            log::info!(
                "Attached {label} IPv6 extension header ({} bytes) to egress packets \
                 (draft-ietf-ippm-stamp-ext-hdr-11 §3.1)",
                spec.bytes.len()
            );
        }
    }
}

/// Returns the egress route/interface MTU for the (connected) sender socket via
/// `getsockopt(IP_MTU / IPV6_MTU)` on Linux, or `None` when it cannot be
/// determined (non-Linux, or the option is unavailable). This reads the kernel's
/// cached route MTU for the connected peer — it does not perform active Path MTU
/// Discovery probing.
#[cfg(target_os = "linux")]
fn egress_mtu(socket: &UdpSocket) -> Option<u32> {
    use std::os::fd::AsRawFd;

    use nix::libc;

    let is_v6 = socket.local_addr().is_ok_and(|a| a.is_ipv6());
    let (level, name) = if is_v6 {
        (libc::IPPROTO_IPV6, libc::IPV6_MTU)
    } else {
        (libc::IPPROTO_IP, libc::IP_MTU)
    };
    let mut mtu: libc::c_int = 0;
    let mut len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
    // SAFETY: `mtu`/`len` are valid for the syscall's writes; `fd` is an open
    // connected socket owned by the caller for the call's duration.
    let rc = unsafe {
        libc::getsockopt(
            socket.as_raw_fd(),
            level,
            name,
            std::ptr::addr_of_mut!(mtu).cast(),
            &mut len,
        )
    };
    (rc == 0 && mtu > 0).then_some(mtu as u32)
}

#[cfg(not(target_os = "linux"))]
fn egress_mtu(_socket: &UdpSocket) -> Option<u32> {
    None
}

/// Removes Reflected Fixed/IPv6 Extension Header TLVs (Types 247/246) from
/// `extra_tlvs` until the assembled packet fits within `mtu`
/// (draft-ietf-ippm-stamp-ext-hdr-11 §3.1/§3.2: "one or more ... TLVs MUST be
/// removed to avoid violating the ... MTU limit"). `fixed_overhead` is every
/// on-wire byte outside `extra_tlvs` (IP + attached ext headers + UDP + STAMP
/// base + the per-packet HMAC/DM/Access TLVs). Type-246 TLVs are removed before
/// Type-247 (they sit last in §3.3 wire order, so trimming from the tail keeps
/// the survivors ordered). Only these two TLV types are ever removed.
fn enforce_egress_mtu(extra_tlvs: &mut Vec<RawTlv>, mtu: usize, fixed_overhead: usize) {
    let wire = |tlvs: &[RawTlv]| -> usize {
        tlvs.iter()
            .map(|t| crate::tlv::TLV_HEADER_SIZE + t.value.len())
            .sum()
    };
    let is_header_tlv = |t: &RawTlv| {
        matches!(
            t.tlv_type,
            TlvType::ReflectedIpv6ExtHdr | TlvType::ReflectedFixedHdr
        )
    };
    let mut removed = 0usize;
    while fixed_overhead + wire(extra_tlvs) > mtu {
        let Some(idx) = extra_tlvs.iter().rposition(is_header_tlv) else {
            break; // No header TLV left to remove; remaining oversize is out of scope.
        };
        extra_tlvs.remove(idx);
        removed += 1;
    }
    if removed > 0 {
        log::warn!(
            "Removed {removed} Reflected Fixed/IPv6 Ext Header TLV(s) (Type 246/247) to keep the \
             test packet within the {mtu}-byte MTU (draft-ietf-ippm-stamp-ext-hdr-11 §3.1/§3.2)"
        );
    }
}

/// Enables `IP_RECVTOS` / `IPV6_RECVTCLASS` on the sender socket so a
/// reply's on-wire ECN bits can be read back via `recvmsg` control
/// messages — the reverse-path (reflector→sender) half of the congestion
/// detection required by draft-ietf-ippm-stamp-cos-ecn-01 §3.4. Mirrors the
/// receiver's own `IP_RECVTOS`/`IPV6_RECVTCLASS` setup
/// (`receiver::nix::run_receiver`).
///
/// Best-effort: TOS reception is optional plumbing (see
/// [`extract_reply_ecn_from_cmsgs`]), so a failure here only disables the
/// reverse-path half of the congestion response — forward-path detection
/// via the reflected CoS TLV's EC2 field (the "CoS:CE" marker in
/// `validate_reflected_tlvs`'s status string) is unaffected either way.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn enable_reply_tos_reception(fd: std::os::fd::RawFd, is_ipv6: bool) -> std::io::Result<()> {
    use nix::libc;

    let enable: libc::c_int = 1;
    let (level, name) = if is_ipv6 {
        (libc::IPPROTO_IPV6, libc::IPV6_RECVTCLASS)
    } else {
        (libc::IPPROTO_IP, libc::IP_RECVTOS)
    };
    // SAFETY: `fd` is an open socket owned by the caller for the duration
    // of the call; `enable` outlives the syscall and its length is passed
    // explicitly.
    let rc = unsafe {
        libc::setsockopt(
            fd,
            level,
            name,
            std::ptr::addr_of!(enable).cast(),
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if rc < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

/// Extracts the on-wire TOS (IPv4) / Traffic Class (IPv6) byte from
/// `recvmsg` control messages for a reply packet — the low 2 bits are the
/// ECN codepoint a CE (0b11) value here signals reverse-path
/// (reflector→sender) congestion, per draft-ietf-ippm-stamp-cos-ecn-01
/// §3.4. Requires [`enable_reply_tos_reception`] to have been called on the
/// socket first. Mirrors `receiver::nix::extract_tos_from_cmsgs` (Linux
/// variant: `nix` exposes typed `ControlMessageOwned::Ipv4Tos`/`Ipv6TClass`
/// cmsgs directly).
#[cfg(target_os = "linux")]
fn extract_reply_ecn_from_cmsgs(
    msg: &nix::sys::socket::RecvMsg<nix::sys::socket::SockaddrStorage>,
) -> Option<u8> {
    use nix::sys::socket::ControlMessageOwned;

    let cmsgs = msg.cmsgs().ok()?;
    for cmsg in cmsgs {
        match cmsg {
            ControlMessageOwned::Ipv4Tos(tos) => return Some(tos & 0x03),
            ControlMessageOwned::Ipv6TClass(tclass) => {
                return Some((tclass.clamp(0, 255) as u8) & 0x03)
            }
            _ => continue,
        }
    }
    None
}

/// macOS variant of [`extract_reply_ecn_from_cmsgs`]: `nix` has no typed
/// cmsg variant for `IP_RECVTOS`/`IPV6_RECVTCLASS` on this platform, so the
/// raw `ControlMessageOwned::Unknown` payload is decoded by level/type,
/// mirroring `receiver::nix::extract_tos_from_cmsgs`'s macOS variant.
#[cfg(target_os = "macos")]
fn extract_reply_ecn_from_cmsgs(
    msg: &nix::sys::socket::RecvMsg<nix::sys::socket::SockaddrStorage>,
) -> Option<u8> {
    use nix::{libc, sys::socket::ControlMessageOwned};

    let cmsgs = msg.cmsgs().ok()?;
    for cmsg in cmsgs {
        if let ControlMessageOwned::Unknown(ref ucmsg) = cmsg {
            let level = ucmsg.cmsg_header.cmsg_level;
            let cmsg_type = ucmsg.cmsg_header.cmsg_type;
            let data = &ucmsg.data_bytes;

            let tos = if level == libc::IPPROTO_IP && cmsg_type == libc::IP_RECVTOS {
                Some(data)
            } else if level == libc::IPPROTO_IPV6 && cmsg_type == libc::IPV6_TCLASS {
                Some(data)
            } else {
                None
            };
            if let Some(data) = tos {
                if data.len() >= 4 {
                    let v = i32::from_ne_bytes([data[0], data[1], data[2], data[3]]);
                    return Some((v.clamp(0, 255) as u8) & 0x03);
                } else if !data.is_empty() {
                    return Some(data[0] & 0x03);
                }
            }
        }
    }
    None
}

/// Builds the wire bytes of one deliberately malformed TLV, used by the
/// `--malformed` conformance-testing switch to exercise a reflector's
/// RFC 8972 §4.2 handling. The TLV is appended after the packet's regular
/// content; the sender does not otherwise rely on or parse it.
fn malformed_tlv_bytes(mode: MalformedMode) -> Vec<u8> {
    // Flags, Type, Length(hi), Length(lo), then Value. Type 1 = Extra Padding.
    const U_FLAG: u8 = 0x80;
    const PADDING_TYPE: u8 = 1;
    match mode {
        // Structurally valid (length matches the 4 value octets) but with
        // reserved flag bits set — `U_FLAG | 0x07` lights the three lowest
        // reserved bits while still asserting U as a sender must.
        MalformedMode::BadFlags => vec![U_FLAG | 0x07, PADDING_TYPE, 0x00, 0x04, 0, 0, 0, 0],
        // Length field claims 0xFFFF octets but only four follow, so the
        // declared length overruns the packet (RFC 8972 §4.2 → M-flag).
        MalformedMode::BadLength => vec![U_FLAG, PADDING_TYPE, 0xFF, 0xFF, 0, 0, 0, 0],
    }
}

/// Runs the STAMP sender, transmitting test packets and collecting statistics.
///
/// Sends packets to the configured remote address and waits for reflected responses.
/// Returns statistics about the measurement session including RTT and packet loss.
///
/// When the `metrics` feature is enabled and `--metrics` flag is set, this function
/// also records Prometheus metrics for packets sent, received, lost, and RTT values.
pub async fn run_sender(
    conf: &Configuration,
    #[cfg(all(unix, feature = "snmp"))] snmp_stats: Option<
        std::sync::Arc<crate::snmp::state::SenderSnmpStats>,
    >,
    #[cfg(not(all(unix, feature = "snmp")))] _snmp_stats: Option<()>,
) -> StatsSnapshot {
    #[cfg(feature = "metrics")]
    let metrics_enabled = conf.metrics;
    let local_addr: SocketAddr = (conf.local_addr, conf.local_port).into();
    let remote_addr: SocketAddr = (conf.remote_addr, conf.remote_port).into();
    let output_format = conf.output_format;

    // draft-ietf-ippm-stamp-cos-ecn-01 §3.4: the AIMD congestion-response
    // controller is active exactly when the sender requests ECN
    // measurement — `--cos` with `--ecn` requesting ECT0 (2) or ECT1 (1).
    // This single condition covers both directions the draft's MUSTs bind:
    // the same `conf.ecn` value both marks the egress IP header (§3.4-1's
    // "ECN field of the IP header") and becomes the CoS TLV's EC1 request
    // field (§3.4-2/-3's "EC1 field").
    let ecn_response_active = conf.cos && matches!(conf.ecn, 1 | 2);

    let empty_snapshot = || RttCollector::new().snapshot(0, 0);

    let socket = match UdpSocket::bind(local_addr).await {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Cannot bind to address {}: {}", local_addr, e);
            return empty_snapshot();
        }
    };

    if let Err(e) = socket.connect(remote_addr).await {
        eprintln!("Cannot connect to address {}: {}", remote_addr, e);
        return empty_snapshot();
    }

    // Mark the egress IP header so the on-the-wire DSCP/ECN matches the Class
    // of Service TLV advertisement (RFC 8972 §4.4) and honour the configured
    // TTL / Hop Limit. Without this the CoS TLV would be advisory only and
    // forward-path DSCP remapping could not be measured truthfully.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        use std::os::fd::AsRawFd;

        let egress_tos = conf
            .cos
            .then(|| ClassOfServiceTlv::new(conf.dscp, conf.ecn).wire_tos());

        if egress_tos.is_some() || conf.ttl.is_some() {
            let is_ipv6 = socket.local_addr().is_ok_and(|a| a.is_ipv6());
            match apply_egress_ip_options(socket.as_raw_fd(), is_ipv6, egress_tos, conf.ttl) {
                Ok(()) => {
                    if let Some(tos) = egress_tos {
                        log::info!(
                            "Egress IP marking set: TOS/Traffic-Class=0x{tos:02x} (DSCP={}, ECN={})",
                            conf.dscp,
                            conf.ecn
                        );
                    }
                    if let Some(ttl) = conf.ttl {
                        log::info!("Egress IP TTL/Hop-Limit set to {ttl}");
                    }
                }
                Err(e) => log::warn!("Failed to set egress IP options (DSCP/ECN/TTL): {e}"),
            }
        }

        // draft-ietf-ippm-stamp-cos-ecn-01 §3.4 reverse-path detection:
        // read back the reply packet's own on-wire ECN via recvmsg cmsgs
        // (see `extract_reply_ecn_from_cmsgs`, used from `recv_packet`).
        if ecn_response_active {
            let is_ipv6 = socket.local_addr().is_ok_and(|a| a.is_ipv6());
            match enable_reply_tos_reception(socket.as_raw_fd(), is_ipv6) {
                Ok(()) => log::info!(
                    "Reply ECN reception enabled (IP_RECVTOS/IPV6_RECVTCLASS) for \
                     reverse-path congestion detection (draft-ietf-ippm-stamp-cos-ecn-01 §3.4)"
                ),
                Err(e) => log::warn!(
                    "Failed to enable reply ECN reception: {e} — reverse-path congestion \
                     detection (wire ECN of replies) disabled; forward-path detection via the \
                     reflected CoS TLV's EC2 field is unaffected"
                ),
            }
        }
    }

    // draft-ietf-ippm-stamp-ext-hdr-11 §3.1: attach the real IPv6 extension
    // headers requested via --attach-ext-hdr. IPv6 destinations only, and
    // Linux only (see `apply_attach_ext_hdrs` — the sticky IPV6_HOPOPTS /
    // IPV6_DSTOPTS options are not exposed by `libc` on Darwin).
    #[cfg(target_os = "linux")]
    {
        use std::os::fd::AsRawFd;

        let attach_specs = conf.attach_ext_hdrs();
        if !attach_specs.is_empty() {
            if conf.remote_addr.is_ipv6() {
                apply_attach_ext_hdrs(socket.as_raw_fd(), &attach_specs);
            } else {
                log::warn!(
                    "--attach-ext-hdr is IPv6-only (IPv6 extension headers do not exist for \
                     IPv4); the {} header(s) are not attached and no Type-246 request TLV is \
                     emitted for an IPv4 destination",
                    attach_specs.len()
                );
            }
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        if !conf.attach_ext_hdr.is_empty() {
            log::warn!(
                "--attach-ext-hdr (real IPv6 extension header attachment) requires Linux; \
                 the header(s) are not attached on this platform, but the matching Type-246 \
                 request TLV(s) are still sent (draft-ietf-ippm-stamp-ext-hdr-11 §3.1)"
            );
        }
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        if conf.cos || conf.ttl.is_some() {
            log::warn!(
                "Egress DSCP/ECN/TTL marking is only supported on Linux/macOS; \
                 the outgoing IP header will use OS defaults"
            );
        }
        if ecn_response_active {
            log::warn!(
                "Reverse-path ECN congestion detection (wire ECN of replies) requires \
                 Linux/macOS; only forward-path detection via the reflected CoS TLV's EC2 \
                 field is active on this platform (draft-ietf-ippm-stamp-cos-ecn-01 §3.4)"
            );
        }
    }

    // Kernel timestamping (feature "hwtstamp"): kernel RX timestamps give a
    // precise T4; TX timestamps from the error queue retroactively correct
    // the stored T1 used for forward one-way delay. `auto` uses the kernel
    // software tier; `on` additionally attempts NIC hardware (Linux).
    #[cfg(all(feature = "hwtstamp", any(target_os = "linux", target_os = "macos")))]
    let sender_kernel_ts = {
        use std::os::fd::AsRawFd;

        use crate::hwtstamp::{self, HwTsMode};
        if conf.hwtstamp == HwTsMode::Off {
            hwtstamp::EnabledTimestamping::default()
        } else {
            #[cfg(target_os = "linux")]
            let want_hw = conf.hwtstamp == HwTsMode::On && {
                let iface = hwtstamp::interface_for_addr(conf.local_addr);
                let cap = hwtstamp::probe(iface.as_deref());
                cap.any_hw_supported()
                    && iface
                        .as_deref()
                        .map(hwtstamp::request_nic_hw_timestamping)
                        .unwrap_or(false)
            };
            #[cfg(not(target_os = "linux"))]
            let want_hw = false;
            let enabled =
                hwtstamp::enable_socket_timestamping(socket.as_raw_fd(), true, true, want_hw);
            log::info!(
                "sender kernel timestamping: rx_kernel={} rx_hw={} tx_kernel={} tx_hw={}",
                enabled.rx_kernel,
                enabled.rx_hw,
                enabled.tx_kernel,
                enabled.tx_hw
            );
            enabled
        }
    };
    #[cfg(all(feature = "hwtstamp", any(target_os = "linux", target_os = "macos")))]
    let kernel_rx_enabled = sender_kernel_ts.rx_kernel;
    #[cfg(not(all(feature = "hwtstamp", any(target_os = "linux", target_os = "macos"))))]
    let kernel_rx_enabled = false;
    // OPT_ID correlation state: counter mirrors the kernel's per-send
    // counter (the sender uses exactly one send site), map pairs it with
    // the STAMP sequence number.
    #[cfg(all(feature = "hwtstamp", target_os = "linux"))]
    let mut sender_tx_counter: u32 = 0;
    #[cfg(all(feature = "hwtstamp", target_os = "linux"))]
    let mut tx_id_to_seq: std::collections::HashMap<u32, u32> = std::collections::HashMap::new();

    // Build error estimate from configuration with Z flag set based on clock source
    let error_estimate = ErrorEstimate::with_clock_format(
        conf.clock_synchronized,
        conf.clock_source,
        conf.error_scale,
        conf.error_multiplier,
    )
    .unwrap_or_else(|_| ErrorEstimate::unsynchronized_with_format(conf.clock_source));
    let error_estimate_wire = error_estimate.to_wire();

    // Check if authenticated mode is used
    let use_auth = is_auth(conf.auth_mode);

    // Load HMAC key if configured
    let hmac_key = load_hmac_key(conf);

    // Validate: authenticated mode requires HMAC key
    if use_auth && hmac_key.is_none() {
        eprintln!(
            "Error: Authenticated mode (-A A) requires HMAC key (--hmac-key or --hmac-key-file)"
        );
        return empty_snapshot();
    }

    if hmac_key.is_some() {
        log::info!("HMAC authentication enabled");
    }

    if let Some(mode) = conf.malformed {
        log::warn!(
            "Diagnostic mode: appending a deliberately malformed TLV ({mode:?}) \
             to every packet — for reflector conformance testing only"
        );
    }

    let sess = Session::new(0);
    let mut pending: HashMap<u32, PendingPacket> = HashMap::new();
    // Time-ordered expiry queue for O(k) eviction instead of O(n) HashMap scan.
    // Entries are (deadline, seq_num). Since packets are sent sequentially,
    // deadlines are naturally ordered. Lazy deletion skips already-received entries.
    let mut expiry_queue: VecDeque<(Instant, u32)> = VecDeque::new();
    let mut rtt_collector = RttCollector::new();
    let mut owd_collector = OwdCollector::new();
    let mut packets_sent: u32 = 0;
    let mut packets_received: u32 = 0;
    let mut packets_lost: u32 = 0;
    // Zero-config latch for the Reflector Micro-session ID (RFC 9534
    // §3.2-11): populated from the first validly-received reply when
    // `--reflector-member-link-id` was not given; persists for the whole
    // session so later replies are checked for self-consistency.
    let mut latched_reflector_msid: Option<u16> = None;
    let mut recv_buf = [0u8; 1024];
    let timeout = Duration::from_secs(conf.timeout as u64);

    // draft-ietf-ippm-stamp-cos-ecn-01 §3.4-3: when the Reflected Test
    // Packet Control TLV is also requested, its interval is scaled by the
    // same AIMD controller — computed before the TLV-building section
    // below so that section knows to skip its own (static) push and defer
    // to the per-iteration scaled rebuild in the send loop instead.
    let reflected_control_requested =
        conf.reflected_control_count > 1 || conf.reflected_control_no_ext_hdr;
    let scale_reflected_control = ecn_response_active && reflected_control_requested;

    // draft-ietf-ippm-asymmetrical-pkts-14 §5: warn when the sender's own
    // pacing would start the next Type-12 request before the reflector is
    // expected to finish the previous burst. Advisory (SHOULD NOT), and
    // eprintln! rather than log::warn! so it is visible regardless of the
    // logging configuration — this fires once, at startup.
    if let Some(warning) = conf.reflected_burst_pacing_warning() {
        eprintln!("Warning: {warning}");
    }

    // RFC 8972 §3 zeroed-SSID control. Only a non-zero SSID makes the scenario
    // meaningful: with no SSID requested, a zeroed reply field says nothing.
    let zero_ssid_expected = conf.ssid.filter(|s| *s != 0);
    let mut zero_ssid_seen = false;

    let mut congestion = ecn_response_active.then(|| {
        let params = AimdParams {
            base_interval: Duration::from_millis(conf.send_delay as u64),
            backoff_factor: conf.ecn_backoff_factor,
            max_interval: Duration::from_millis(conf.ecn_max_delay as u64),
            recovery_step: Duration::from_millis(conf.ecn_recovery_step as u64),
        };
        log::info!(
            "AIMD congestion-response controller enabled (draft-ietf-ippm-stamp-cos-ecn-01 \
             §3.4): base={}ms backoff_factor={} max={}ms recovery_step={}ms{}",
            conf.send_delay,
            conf.ecn_backoff_factor,
            conf.ecn_max_delay,
            conf.ecn_recovery_step,
            if scale_reflected_control {
                " (also scaling --reflected-control-interval-ns per §3.4-3)"
            } else {
                ""
            }
        );
        CongestionState::new(params)
    });

    // Build all extra TLVs (once, before loop)
    let mut extra_tlvs: Vec<RawTlv> = Vec::new();

    if conf.cos {
        extra_tlvs.push(ClassOfServiceTlv::new(conf.dscp, conf.ecn).to_raw());
        log::info!(
            "Class of Service TLV enabled (DSCP={}, ECN={})",
            conf.dscp,
            conf.ecn
        );
    }

    // RFC 8972 §4.6: the Access Report TLV is event-driven and carries its
    // own retransmission procedure, so (unlike the other extra TLVs above)
    // it is NOT attached unconditionally to every packet here. Instead
    // `access_report_state` decides, per send-loop iteration, whether this
    // iteration's packet is the original send or a timed-out retransmission
    // (see `AccessReportRetransmitState::tick`, used in the loop below).
    let mut access_report_state = conf.access_report.map(|access_id| {
        log::info!(
            "Access Report TLV enabled (id={}, code={}); retransmission timer={}s, \
             max_retries={} (RFC 8972 §4.6)",
            access_id,
            conf.access_return_code,
            conf.access_report_timeout,
            conf.access_report_retries
        );
        AccessReportRetransmitState::new(
            Duration::from_secs(conf.access_report_timeout as u64),
            conf.access_report_retries,
        )
    });

    if conf.timestamp_info {
        // RFC 8972 §4.3: the Session-Sender MUST send the Timestamp Info TLV
        // value fully zeroed — all four octets describe the reflector's
        // ingress/egress clocks, so there is no sender field to fill. The
        // reflector fills them in on reflection.
        extra_tlvs.push(TimestampInfoTlv::request().to_raw());
        log::info!("Timestamp Information TLV enabled");
    }

    if conf.location {
        // RFC 8972 §4.2: send a compliant request carrying generic Source IP
        // and Destination IP sub-TLVs (zero-filled, correct Lengths, 4-octet
        // headers); the reflector answers with the specific IPv4/IPv6 variants
        // and fills in the observed ports so the sender can detect a NAT.
        extra_tlvs.push(LocationTlv::request().to_raw());
        log::info!("Location TLV enabled");
    }

    if conf.follow_up_telemetry {
        extra_tlvs.push(FollowUpTelemetryTlv::new().to_raw());
        log::info!("Follow-Up Telemetry TLV enabled");
    }

    // Build Destination Node Address TLV (RFC 9503 §4)
    if let Some(addr) = conf.dest_node_addr {
        extra_tlvs.push(DestinationNodeAddressTlv::new(addr).to_raw());
        log::info!("Destination Node Address TLV enabled ({})", addr);
    }

    // Build Return Path TLV (RFC 9503 §5) — at most one
    if let Some(cc) = conf.return_path_cc {
        extra_tlvs.push(ReturnPathTlv::with_control_code(cc).to_raw());
        log::info!("Return Path TLV enabled (control code={})", cc);
    } else if let Some(ref labels) = conf.return_sr_mpls_labels {
        let mut rp = ReturnPathTlv::with_sr_mpls_labels(labels);
        if let Some(addr) = conf.return_address {
            rp.add_return_address(addr);
        }
        extra_tlvs.push(rp.to_raw());
        log::info!("Return Path TLV enabled (SR-MPLS, {} labels)", labels.len());
    } else if let Some(ref sids) = conf.return_srv6_sids {
        let mut rp = ReturnPathTlv::with_srv6_sids(sids);
        if let Some(addr) = conf.return_address {
            rp.add_return_address(addr);
        }
        extra_tlvs.push(rp.to_raw());
        log::info!("Return Path TLV enabled (SRv6, {} SIDs)", sids.len());
    } else if let Some(addr) = conf.return_address {
        extra_tlvs.push(ReturnPathTlv::with_return_address(addr).to_raw());
        log::info!("Return Path TLV enabled (return address={})", addr);
    }

    // Build Micro-session ID TLV (RFC 9534 §3.1)
    if let Some(sender_id) = conf.micro_session_id {
        extra_tlvs.push(micro_session_request_tlv(
            sender_id,
            conf.reflector_member_link_id,
        ));
        log::info!(
            "Micro-session ID TLV enabled (sender_id={}, reflector_id={:?})",
            sender_id,
            conf.reflector_member_link_id
        );
    }

    // Build Reflected Test Packet Control TLV (draft-ietf-ippm-asymmetrical-pkts-14 §3).
    // When `scale_reflected_control` is set, the TLV is instead rebuilt
    // fresh every send-loop iteration with an AIMD-scaled interval
    // (§3.4-3) — skip the static push here so it isn't emitted twice.
    if let Some(control) = build_reflected_control_tlv(
        conf.reflected_control_length,
        conf.reflected_control_count,
        conf.reflected_control_interval_ns,
        conf.reflected_control_no_ext_hdr,
    ) {
        log::info!(
            "Reflected Control TLV enabled (length={}, count={}, interval={}ns, one-way-ext-hdr={}{})",
            conf.reflected_control_length,
            conf.reflected_control_count,
            conf.reflected_control_interval_ns,
            conf.reflected_control_no_ext_hdr,
            if scale_reflected_control {
                ", AIMD-scaled per §3.4-3"
            } else {
                ""
            }
        );
        if !scale_reflected_control {
            extra_tlvs.push(control.to_raw());
        }
    }

    // Standalone Extra Padding TLV (RFC 8972 §4.1), independent of BER.
    // Pseudorandom fill per §4.2's recommendation. `validate()` has already
    // rejected combining this with --ber, which needs a known pattern.
    if let Some(bytes) = conf.extra_padding {
        extra_tlvs.push(ExtraPaddingTlv::new(bytes).to_raw());
        log::info!("Extra Padding TLV enabled ({bytes} value octets)");
    }

    // Build BER TLVs (draft-gandhi-ippm-stamp-ber §3). All three are emitted
    // together, paired with an Extra Padding TLV filled with the repeated pattern.
    if conf.ber {
        let pattern_bytes: Vec<u8> = if let Some(hex) = conf.ber_pattern.as_deref() {
            match parse_hex_pattern(hex) {
                Ok(bytes) => bytes,
                Err(e) => {
                    eprintln!("Invalid --ber-pattern ({}): {}", hex, e);
                    return empty_snapshot();
                }
            }
        } else {
            // Default 0xFF00 per draft §3.2.
            vec![0xFF, 0x00]
        };

        // Extra Padding TLV filled with the repeated pattern so the reflector
        // can XOR-compare it. Use deterministic bytes (not the pseudorandom
        // default) because the BER computation requires a known pattern.
        let mut padding_bytes = Vec::with_capacity(conf.ber_padding_size);
        for i in 0..conf.ber_padding_size {
            padding_bytes.push(pattern_bytes[i % pattern_bytes.len()]);
        }
        let padding_tlv = ExtraPaddingTlv {
            padding: padding_bytes,
        };
        extra_tlvs.push(padding_tlv.to_raw());
        extra_tlvs.push(BerPatternTlv::new(pattern_bytes).to_raw());
        extra_tlvs.push(BerCountTlv::default().to_raw());
        // Type 242 collides with another implementation's incompatible
        // experimental "Heartbeat" TLV (RFC 8972 §5.1 Experimental Use range);
        // --ber-omit-burst drops it so the rest of the BER exchange still works
        // against such a peer.
        if conf.ber_omit_burst {
            log::info!(
                "BER: omitting the Max Bit Error Burst Size TLV (Type 242) per \
                 --ber-omit-burst"
            );
        } else {
            extra_tlvs.push(BerBurstTlv::default().to_raw());
        }
        log::info!(
            "BER TLVs enabled (padding_size={}, pattern={})",
            conf.ber_padding_size,
            conf.ber_pattern.as_deref().unwrap_or("ff00")
        );
    }

    // Reflected Fixed / IPv6 Extension Header Data TLVs
    // (draft-ietf-ippm-stamp-ext-hdr-11 §§3.1, 3.2). The value is
    // Requested(4) + Reflected(Length-4): sent with a zero (or selector)
    // Requested field and a zero-initialised Reflected field; the reflector
    // fills the Reflected field when it has raw-capture access to IP headers,
    // or echoes with the C flag.
    extra_tlvs.extend(reflected_header_request_tlvs(conf));

    // draft-ietf-ippm-stamp-ext-hdr-11 §3.1/§3.2 MTU rule (sender half): the
    // resulting test packets MUST NOT exceed the IP/IPv6 MTU after adding the
    // Reflected Fixed/IPv6 Extension Header TLVs; if necessary, one or more of
    // those TLVs MUST be removed. Compare the worst-case assembled packet size
    // against the egress interface MTU (route MTU via getsockopt on Linux;
    // 1280 for IPv6 / 1500 for IPv4 when unknown) and trim Type 246/247 TLVs to
    // fit. Only these two TLV types are removed — the draft binds this rule to
    // them specifically; oversize from other TLVs is out of scope here.
    {
        let mtu = egress_mtu(&socket).unwrap_or(if conf.remote_addr.is_ipv6() {
            1280
        } else {
            1500
        }) as usize;
        let ip_hdr = if conf.remote_addr.is_ipv6() {
            IPV6_FIXED_HEADER_SIZE
        } else {
            IPV4_FIXED_HEADER_SIZE
        };
        // Attached IPv6 extension headers ride between the fixed header and UDP,
        // so they count toward the on-wire IP packet size.
        let attached_ext: usize = if conf.remote_addr.is_ipv6() {
            conf.attach_ext_hdrs().iter().map(|a| a.bytes.len()).sum()
        } else {
            0
        };
        let base = if use_auth {
            crate::receiver::AUTH_BASE_SIZE
        } else {
            crate::receiver::UNAUTH_BASE_SIZE
        };
        // Worst-case per-packet extras: HMAC TLV (20), Direct Measurement (16),
        // Access Report (8) — included when they can appear.
        let hmac_tlv = if hmac_key.is_some() { 20 } else { 0 };
        let dm = if conf.direct_measurement { 16 } else { 0 };
        let access = if access_report_state.is_some() { 8 } else { 0 };
        const UDP_HEADER: usize = 8;
        let fixed_overhead = ip_hdr + attached_ext + UDP_HEADER + base + hmac_tlv + dm + access;
        enforce_egress_mtu(&mut extra_tlvs, mtu, fixed_overhead);
    }

    // Check if we need to include TLV extensions.
    // SSID lives in the base header per RFC 8972 §3 — it alone does not force TLV mode.
    let use_tlvs = !extra_tlvs.is_empty()
        || conf.direct_measurement
        || access_report_state.is_some()
        || scale_reflected_control;
    if let Some(ssid) = conf.ssid {
        log::info!("SSID enabled: {}", ssid);
    }

    // Precompute send strategy to avoid branching in hot loop.
    // Using an enum moves the mode decision outside the loop.
    enum SendMode<'a> {
        AuthTlv { key: &'a HmacKey },
        AuthBase { key: &'a HmacKey },
        OpenTlv { tlv_key: Option<&'a HmacKey> },
        OpenBase,
    }

    let send_mode = if use_auth {
        // Key is guaranteed present - validated at function start
        let key = hmac_key.as_ref().unwrap();
        if use_tlvs {
            SendMode::AuthTlv { key }
        } else {
            SendMode::AuthBase { key }
        }
    } else if use_tlvs {
        // RFC 8972 §4.8 origination is separate from holding a key: --tlv-hmac
        // off keeps the key for verifying replies without putting an HMAC TLV
        // on the wire. `validate()` has already ensured `on` has a key.
        let originate = match conf.tlv_hmac {
            TlvHmacMode::Auto | TlvHmacMode::On => true,
            TlvHmacMode::Off => false,
        };
        if !originate && hmac_key.is_some() {
            log::info!(
                "not originating an HMAC TLV per --tlv-hmac off; the configured \
                 key is still used to verify reflected TLV HMACs"
            );
        }
        SendMode::OpenTlv {
            tlv_key: originate.then_some(hmac_key.as_ref()).flatten(),
        }
    } else {
        SendMode::OpenBase
    };

    // Periodic reporting timer
    let mut report_timer = if conf.report_interval > 0 {
        Some(tokio::time::interval(Duration::from_secs(
            conf.report_interval as u64,
        )))
    } else {
        None
    };
    // Skip the first immediate tick
    if let Some(ref mut timer) = report_timer {
        timer.tick().await;
    }

    for _ in 0..conf.count {
        let seq_num = sess.generate_sequence_number();
        let send_time = Instant::now();
        let send_timestamp = generate_timestamp(conf.clock_source);

        // RFC 8972 §4.6: decide, for *this* iteration only, whether the
        // Access Report TLV should be attached — the original send, or a
        // retransmission because the previous attempt's timer expired
        // without an acknowledgment. `tick` also drives the retry bookkeeping
        // forward (armed/retransmit/abort), piggybacking on this loop's
        // existing send timing instead of a separate timer/task.
        let attach_access_report = access_report_state
            .as_mut()
            .map(|state| state.tick(send_time))
            .unwrap_or(false);

        // Build per-packet TLVs (Direct Measurement changes each packet;
        // Access Report is attached only on send/retransmission iterations;
        // the Reflected Control TLV is rebuilt with an AIMD-scaled interval
        // when `scale_reflected_control`, §3.4-3)
        let per_packet_tlvs: Vec<RawTlv>;
        let all_extra_tlvs =
            if conf.direct_measurement || attach_access_report || scale_reflected_control {
                let mut tlvs = extra_tlvs.clone();
                if conf.direct_measurement {
                    tlvs.push(DirectMeasurementTlv::new(packets_sent + 1).to_raw());
                }
                if attach_access_report {
                    // `access_report_state` is `Some` (hence `attach_access_report`
                    // could be true) only when `conf.access_report` is `Some`.
                    let access_id = conf
                        .access_report
                        .expect("attach_access_report implies conf.access_report is Some");
                    tlvs.push(AccessReportTlv::new(access_id, conf.access_return_code).to_raw());
                }
                if scale_reflected_control {
                    // §3.4-3: scale the requested interval by the same AIMD
                    // ratio driving the main send delay.
                    let scale = congestion
                        .as_ref()
                        .map(|c| c.controller.scale_factor())
                        .unwrap_or(1.0);
                    if let Some(control) = scaled_reflected_control_tlv(
                        conf.reflected_control_length,
                        conf.reflected_control_count,
                        conf.reflected_control_interval_ns,
                        conf.reflected_control_no_ext_hdr,
                        scale,
                    ) {
                        tlvs.push(control);
                    }
                }
                per_packet_tlvs = tlvs;
                &per_packet_tlvs
            } else {
                &extra_tlvs
            };

        let mut buf: Vec<u8> = match &send_mode {
            SendMode::AuthTlv { key } => build_auth_packet_with_tlvs(
                seq_num,
                send_timestamp,
                error_estimate_wire,
                key,
                conf.ssid,
                all_extra_tlvs,
                Some(*key),
            ),
            SendMode::AuthBase { key } => {
                let mut packet = assemble_auth_packet(error_estimate_wire);
                packet.sequence_number = seq_num;
                packet.timestamp = send_timestamp;
                packet.ssid = conf.ssid.unwrap_or(0);
                finalize_auth_packet(&mut packet, key);
                packet.to_bytes().to_vec()
            }
            SendMode::OpenTlv { tlv_key } => build_unauth_packet_with_tlvs(
                seq_num,
                send_timestamp,
                error_estimate_wire,
                conf.ssid,
                all_extra_tlvs,
                *tlv_key,
            ),
            SendMode::OpenBase => {
                let mut packet = assemble_unauth_packet(error_estimate_wire);
                packet.sequence_number = seq_num;
                packet.timestamp = send_timestamp;
                packet.ssid = conf.ssid.unwrap_or(0);
                packet.to_bytes().to_vec()
            }
        };

        // Diagnostic: append a deliberately malformed TLV (RFC 8972 §4.2) to
        // exercise the reflector's malformed/flag handling. Sent last, after
        // any HMAC TLV.
        if let Some(mode) = conf.malformed {
            buf.extend_from_slice(&malformed_tlv_bytes(mode));
        }

        let send_result = socket.send(&buf).await;

        if let Err(e) = send_result {
            eprintln!("Failed to send packet {}: {}", seq_num, e);
            continue;
        }

        packets_sent += 1;
        #[cfg(all(unix, feature = "snmp"))]
        if let Some(ref stats) = snmp_stats {
            stats.inc_sent();
        }
        #[cfg(feature = "metrics")]
        if metrics_enabled {
            crate::metrics::sender_metrics::record_packet_sent();
        }
        pending.insert(
            seq_num,
            PendingPacket {
                send_time,
                send_timestamp,
            },
        );
        // Pair this send's kernel OPT_ID with the sequence number so the
        // error-queue drain can retroactively correct the stored T1.
        #[cfg(all(feature = "hwtstamp", target_os = "linux"))]
        if sender_kernel_ts.tx_kernel {
            tx_id_to_seq.insert(sender_tx_counter, seq_num);
            sender_tx_counter = sender_tx_counter.wrapping_add(1);
            if tx_id_to_seq.len() > 4096 {
                // Defensive: TX timestamps stopped arriving; reset.
                tx_id_to_seq.clear();
            }
        }
        if timeout > Duration::ZERO {
            expiry_queue.push_back((send_time + timeout, seq_num));
        }

        // Event-driven receive: process responses until send_delay expires.
        // When the AIMD congestion-response controller is active
        // (draft-ietf-ippm-stamp-cos-ecn-01 §3.4) it — not the static
        // `--send-delay` — dictates this iteration's wait, having grown
        // (CE backoff) or shrunk-toward-base (clean recovery) from replies
        // processed on prior iterations.
        let send_delay = congestion
            .as_ref()
            .map(|c| c.controller.current_interval())
            .unwrap_or_else(|| Duration::from_millis(conf.send_delay as u64));
        let deadline = tokio::time::Instant::now() + send_delay;

        loop {
            // Use unbiased select to ensure fair scheduling between receiving
            // responses and the send timer. Biased select would starve the timer
            // under heavy receive load, reducing packet send rates.
            tokio::select! {
                result = recv_packet(&socket, &mut recv_buf, kernel_rx_enabled, ecn_response_active, conf.clock_source) => {
                    match result {
                        Ok((len, kernel_t4, reply_ecn)) => {
                            // Apply pending kernel TX corrections first so the
                            // corrected T1 is in place before OWD computation.
                            #[cfg(all(feature = "hwtstamp", target_os = "linux"))]
                            if sender_kernel_ts.tx_kernel {
                                use std::os::fd::AsRawFd;
                                let reports = crate::hwtstamp::drain_tx_timestamps(
                                    socket.as_raw_fd(),
                                    conf.clock_source,
                                );
                                apply_tx_corrections(&reports, &mut tx_id_to_seq, &mut pending);
                            }
                            let mut ctx = SenderRecvContext {
                                pending: &mut pending,
                                rtt_collector: &mut rtt_collector,
                                owd_collector: &mut owd_collector,
                                packets_received: &mut packets_received,
                                print_stats: conf.print_stats,
                                hmac_key: hmac_key.as_ref(),
                                expected_sender_msid: conf.micro_session_id,
                                expected_reflector_msid: conf.reflector_member_link_id,
                                latched_reflector_msid: &mut latched_reflector_msid,
                                access_report_state: access_report_state.as_mut(),
                                congestion: congestion.as_mut(),
                                expected_ssid: zero_ssid_expected,
                                on_zero_ssid: conf.on_zero_ssid,
                                zero_ssid_seen: &mut zero_ssid_seen,
                                #[cfg(feature = "metrics")]
                                metrics_enabled,
                                #[cfg(all(unix, feature = "snmp"))]
                                snmp_stats: snmp_stats.as_deref(),
                            };
                            process_response(
                                &recv_buf[..len],
                                use_auth,
                                use_tlvs,
                                conf.clock_source,
                                kernel_t4,
                                reply_ecn,
                                &mut ctx,
                            );
                        }
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                            // Spurious readiness wake — typically a pending
                            // error-queue event; drain it so readiness clears.
                            #[cfg(all(feature = "hwtstamp", target_os = "linux"))]
                            if sender_kernel_ts.tx_kernel {
                                use std::os::fd::AsRawFd;
                                let reports = crate::hwtstamp::drain_tx_timestamps(
                                    socket.as_raw_fd(),
                                    conf.clock_source,
                                );
                                apply_tx_corrections(&reports, &mut tx_id_to_seq, &mut pending);
                            }
                        }
                        Err(e) => {
                            eprintln!("Receive error: {}", e);
                            break;
                        }
                    }
                }

                _ = tokio::time::sleep_until(deadline) => {
                    // Send delay expired, time to send next packet
                    break;
                }

                _ = async {
                    if let Some(ref mut timer) = report_timer {
                        timer.tick().await
                    } else {
                        std::future::pending::<tokio::time::Instant>().await
                    }
                } => {
                    let interim = rtt_collector
                        .snapshot(packets_sent, packets_lost)
                        .with_owd(&owd_collector)
                        .with_access_report(access_report_state.as_ref().map(|state| state.summary()))
                        .with_congestion(congestion.as_ref().map(|state| state.summary()));
                    interim.print_interim(output_format);
                }
            }
        }

        // Evict timed-out packets from the front of the expiry queue.
        // O(k) where k = expired + already-received entries at front,
        // instead of O(n) scanning the full HashMap.
        {
            let now = Instant::now();
            while let Some(&(deadline, seq)) = expiry_queue.front() {
                if deadline > now {
                    break;
                }
                expiry_queue.pop_front();
                // Lazy deletion: skip if response was already received
                if pending.remove(&seq).is_some() {
                    packets_lost += 1;
                    #[cfg(feature = "metrics")]
                    if metrics_enabled {
                        crate::metrics::sender_metrics::record_packet_lost();
                    }
                    #[cfg(all(unix, feature = "snmp"))]
                    if let Some(ref stats) = snmp_stats {
                        stats.inc_lost();
                    }
                }
            }
        }

        // RFC 8972 §3: `--on-zero-ssid=stop` ends the session at the first
        // reply that came back with a zeroed SSID.
        if zero_ssid_seen && conf.on_zero_ssid == ZeroSsidAction::Stop {
            break;
        }
    }

    // Final wait phase for remaining responses. Skipped entirely when the
    // zeroed-SSID policy stopped the session — there is nothing left to
    // measure and the pending entries belong to the abandoned run.
    let wait_start = Instant::now();
    let stopped_on_zero_ssid = zero_ssid_seen && conf.on_zero_ssid == ZeroSsidAction::Stop;
    while !stopped_on_zero_ssid && !pending.is_empty() && wait_start.elapsed() < timeout {
        let remaining = timeout.saturating_sub(wait_start.elapsed());
        match tokio::time::timeout(
            remaining,
            recv_packet(
                &socket,
                &mut recv_buf,
                kernel_rx_enabled,
                ecn_response_active,
                conf.clock_source,
            ),
        )
        .await
        {
            Ok(Ok((len, kernel_t4, reply_ecn))) => {
                #[cfg(all(feature = "hwtstamp", target_os = "linux"))]
                if sender_kernel_ts.tx_kernel {
                    use std::os::fd::AsRawFd;
                    let reports =
                        crate::hwtstamp::drain_tx_timestamps(socket.as_raw_fd(), conf.clock_source);
                    apply_tx_corrections(&reports, &mut tx_id_to_seq, &mut pending);
                }
                let mut ctx = SenderRecvContext {
                    pending: &mut pending,
                    rtt_collector: &mut rtt_collector,
                    owd_collector: &mut owd_collector,
                    packets_received: &mut packets_received,
                    print_stats: conf.print_stats,
                    hmac_key: hmac_key.as_ref(),
                    expected_sender_msid: conf.micro_session_id,
                    expected_reflector_msid: conf.reflector_member_link_id,
                    latched_reflector_msid: &mut latched_reflector_msid,
                    access_report_state: access_report_state.as_mut(),
                    congestion: congestion.as_mut(),
                    expected_ssid: zero_ssid_expected,
                    on_zero_ssid: conf.on_zero_ssid,
                    zero_ssid_seen: &mut zero_ssid_seen,
                    #[cfg(feature = "metrics")]
                    metrics_enabled,
                    #[cfg(all(unix, feature = "snmp"))]
                    snmp_stats: snmp_stats.as_deref(),
                };
                process_response(
                    &recv_buf[..len],
                    use_auth,
                    use_tlvs,
                    conf.clock_source,
                    kernel_t4,
                    reply_ecn,
                    &mut ctx,
                );
            }
            Ok(Err(e)) if e.kind() == std::io::ErrorKind::WouldBlock => {
                // Spurious wake during the final wait; nothing to read yet.
                continue;
            }
            Ok(Err(e)) => {
                eprintln!("Receive error during final wait: {}", e);
                break;
            }
            Err(_) => break, // Timeout expired
        }
    }

    // RFC 8972 §4.6: the retransmission timer must keep firing even once
    // the main send loop and the plain per-packet wait above have both
    // finished — otherwise a run shorter than the full retry budget
    // (`access_report_timeout * (1 + retries)`, up to 15s at the RFC
    // defaults) reports `Pending` without ever retransmitting (the common
    // `--count 1` case). Extend the wait here: `tick()` on schedule,
    // retransmit a real STAMP test packet — carrying the same Access
    // Report TLV bytes every attempt (see the wire-equality regression
    // test) — when the timer fires, and keep servicing `process_response`
    // so an ack arriving mid-wait still disarms the timer via the existing
    // "AccessReport:ack" scan (no new consumption path). `tick()`'s own
    // retry-budget bookkeeping bounds this loop to at most
    // `access_report_timeout * (1 + max_retries)` from when the report was
    // first armed, so a dead reflector cannot hang the sender past that.
    // A no-op entirely when `--access-report` was not set
    // (`access_report_state` is `None`), so the wait phase above is
    // byte-identical to before in that case.
    while !stopped_on_zero_ssid
        && access_report_state
            .as_ref()
            .is_some_and(|state| !state.is_terminal())
    {
        let now = Instant::now();
        let attach = access_report_state
            .as_mut()
            .map(|state| state.tick(now))
            .unwrap_or(false);

        if attach {
            // An ordinary test packet: the same extra-TLV set the main loop
            // uses, optionally Direct Measurement, and (always, since
            // `attach` is true) the Access Report TLV — built fresh from
            // the same `access_id`/`access_return_code` every time, so its
            // wire bytes are identical across every attempt.
            let seq_num = sess.generate_sequence_number();
            let send_time = Instant::now();
            let send_timestamp = generate_timestamp(conf.clock_source);

            let mut tlvs = extra_tlvs.clone();
            if conf.direct_measurement {
                tlvs.push(DirectMeasurementTlv::new(packets_sent + 1).to_raw());
            }
            let access_id = conf.access_report.expect(
                "attach implies access_report_state is Some, which implies conf.access_report is Some",
            );
            tlvs.push(AccessReportTlv::new(access_id, conf.access_return_code).to_raw());
            if scale_reflected_control {
                // A retransmission is one of §3.4-3's "future STAMP packets",
                // and `extra_tlvs` omits the control TLV in this mode (the
                // main loop rebuilds it per send). Rebuild it here too, with
                // whatever AIMD factor the controller holds now, so the TLV
                // does not vanish from every retry.
                let scale = congestion
                    .as_ref()
                    .map(|c| c.controller.scale_factor())
                    .unwrap_or(1.0);
                if let Some(control) = scaled_reflected_control_tlv(
                    conf.reflected_control_length,
                    conf.reflected_control_count,
                    conf.reflected_control_interval_ns,
                    conf.reflected_control_no_ext_hdr,
                    scale,
                ) {
                    tlvs.push(control);
                }
            }

            let mut buf: Vec<u8> = match &send_mode {
                SendMode::AuthTlv { key } => build_auth_packet_with_tlvs(
                    seq_num,
                    send_timestamp,
                    error_estimate_wire,
                    key,
                    conf.ssid,
                    &tlvs,
                    Some(*key),
                ),
                SendMode::AuthBase { key } => {
                    let mut packet = assemble_auth_packet(error_estimate_wire);
                    packet.sequence_number = seq_num;
                    packet.timestamp = send_timestamp;
                    packet.ssid = conf.ssid.unwrap_or(0);
                    finalize_auth_packet(&mut packet, key);
                    packet.to_bytes().to_vec()
                }
                SendMode::OpenTlv { tlv_key } => build_unauth_packet_with_tlvs(
                    seq_num,
                    send_timestamp,
                    error_estimate_wire,
                    conf.ssid,
                    &tlvs,
                    *tlv_key,
                ),
                SendMode::OpenBase => {
                    let mut packet = assemble_unauth_packet(error_estimate_wire);
                    packet.sequence_number = seq_num;
                    packet.timestamp = send_timestamp;
                    packet.ssid = conf.ssid.unwrap_or(0);
                    packet.to_bytes().to_vec()
                }
            };

            if let Some(mode) = conf.malformed {
                buf.extend_from_slice(&malformed_tlv_bytes(mode));
            }

            match socket.send(&buf).await {
                Ok(_) => {
                    packets_sent += 1;
                    #[cfg(all(unix, feature = "snmp"))]
                    if let Some(ref stats) = snmp_stats {
                        stats.inc_sent();
                    }
                    #[cfg(feature = "metrics")]
                    if metrics_enabled {
                        crate::metrics::sender_metrics::record_packet_sent();
                    }
                    pending.insert(
                        seq_num,
                        PendingPacket {
                            send_time,
                            send_timestamp,
                        },
                    );
                    #[cfg(all(feature = "hwtstamp", target_os = "linux"))]
                    if sender_kernel_ts.tx_kernel {
                        tx_id_to_seq.insert(sender_tx_counter, seq_num);
                        sender_tx_counter = sender_tx_counter.wrapping_add(1);
                        if tx_id_to_seq.len() > 4096 {
                            tx_id_to_seq.clear();
                        }
                    }
                    if timeout > Duration::ZERO {
                        expiry_queue.push_back((send_time + timeout, seq_num));
                    }
                }
                Err(e) => {
                    eprintln!(
                        "Failed to send Access Report retransmission {}: {}",
                        seq_num, e
                    );
                }
            }

            continue;
        }

        // Not due yet, and the loop guard above already excluded the
        // terminal phases, so `access_report_state` is `Some` and `Armed`
        // with a deadline to wait for.
        let Some(deadline) = access_report_state
            .as_ref()
            .and_then(|state| state.armed_deadline())
        else {
            break;
        };
        let deadline = tokio::time::Instant::from_std(deadline);

        tokio::select! {
            result = recv_packet(&socket, &mut recv_buf, kernel_rx_enabled, ecn_response_active, conf.clock_source) => {
                match result {
                    Ok((len, kernel_t4, reply_ecn)) => {
                        #[cfg(all(feature = "hwtstamp", target_os = "linux"))]
                        if sender_kernel_ts.tx_kernel {
                            use std::os::fd::AsRawFd;
                            let reports = crate::hwtstamp::drain_tx_timestamps(
                                socket.as_raw_fd(),
                                conf.clock_source,
                            );
                            apply_tx_corrections(&reports, &mut tx_id_to_seq, &mut pending);
                        }
                        let mut ctx = SenderRecvContext {
                            pending: &mut pending,
                            rtt_collector: &mut rtt_collector,
                            owd_collector: &mut owd_collector,
                            packets_received: &mut packets_received,
                            print_stats: conf.print_stats,
                            hmac_key: hmac_key.as_ref(),
                            expected_sender_msid: conf.micro_session_id,
                            expected_reflector_msid: conf.reflector_member_link_id,
                            latched_reflector_msid: &mut latched_reflector_msid,
                            access_report_state: access_report_state.as_mut(),
                            congestion: congestion.as_mut(),
                            expected_ssid: zero_ssid_expected,
                            on_zero_ssid: conf.on_zero_ssid,
                            zero_ssid_seen: &mut zero_ssid_seen,
                            #[cfg(feature = "metrics")]
                            metrics_enabled,
                            #[cfg(all(unix, feature = "snmp"))]
                            snmp_stats: snmp_stats.as_deref(),
                        };
                        process_response(
                            &recv_buf[..len],
                            use_auth,
                            use_tlvs,
                            conf.clock_source,
                            kernel_t4,
                            reply_ecn,
                            &mut ctx,
                        );
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        #[cfg(all(feature = "hwtstamp", target_os = "linux"))]
                        if sender_kernel_ts.tx_kernel {
                            use std::os::fd::AsRawFd;
                            let reports = crate::hwtstamp::drain_tx_timestamps(
                                socket.as_raw_fd(),
                                conf.clock_source,
                            );
                            apply_tx_corrections(&reports, &mut tx_id_to_seq, &mut pending);
                        }
                    }
                    Err(e) => {
                        eprintln!("Receive error while awaiting Access Report ack: {}", e);
                        break;
                    }
                }
            }
            _ = tokio::time::sleep_until(deadline) => {}
        }
    }

    // Mark remaining pending packets as lost (batched for efficiency)
    let remaining_lost = pending.len() as u32;
    packets_lost += remaining_lost;
    #[cfg(feature = "metrics")]
    if metrics_enabled && remaining_lost > 0 {
        crate::metrics::sender_metrics::record_packets_lost(remaining_lost as u64);
    }
    #[cfg(all(unix, feature = "snmp"))]
    if let Some(ref stats) = snmp_stats {
        stats.inc_lost_by(remaining_lost);
    }

    rtt_collector
        .snapshot(packets_sent, packets_lost)
        .with_owd(&owd_collector)
        .with_access_report(access_report_state.as_ref().map(|state| state.summary()))
        .with_congestion(congestion.as_ref().map(|state| state.summary()))
}

/// Receives one datagram. With kernel RX timestamping enabled (feature
/// "hwtstamp") it uses recvmsg and returns the kernel receive timestamp
/// (T4) in STAMP wire format alongside the length; otherwise a plain
/// `recv`. May return `WouldBlock` on spurious readiness wakeups (e.g.
/// pending error-queue events) — callers drain the error queue and retry.
/// Receives one datagram, returning `(len, kernel_t4, reply_ecn)`.
///
/// - `kernel_t4`: with kernel RX timestamping enabled (feature "hwtstamp")
///   the kernel receive timestamp (T4) in STAMP wire format; `None`
///   otherwise.
/// - `reply_ecn`: with `want_reply_ecn` set, the reply packet's own on-wire
///   ECN codepoint (low 2 bits of the IP TOS / Traffic Class octet) —
///   reverse-path congestion detection for draft-ietf-ippm-stamp-cos-ecn-01
///   §3.4; `None` when not requested or unavailable.
///
/// Both extractions share a single `recvmsg` call (Linux/macOS only, via
/// `nix` — a mandatory dependency on those platforms regardless of the
/// "hwtstamp" build feature) when either is needed; a plain `recv` is used
/// otherwise. May return `WouldBlock` on spurious readiness wakeups (e.g.
/// pending error-queue events) — callers drain the error queue and retry.
async fn recv_packet(
    socket: &tokio::net::UdpSocket,
    buf: &mut [u8],
    kernel_rx: bool,
    want_reply_ecn: bool,
    cs: ClockFormat,
) -> std::io::Result<(usize, Option<u64>, Option<u8>)> {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    if kernel_rx || want_reply_ecn {
        use std::os::fd::AsRawFd;
        socket.readable().await?;
        let mut cmsg_buf = vec![0u8; 256];
        let mut iov = [std::io::IoSliceMut::new(buf)];
        return match nix::sys::socket::recvmsg::<nix::sys::socket::SockaddrStorage>(
            socket.as_raw_fd(),
            &mut iov,
            Some(&mut cmsg_buf),
            nix::sys::socket::MsgFlags::MSG_DONTWAIT,
        ) {
            Ok(msg) => {
                let len = msg.bytes;
                #[cfg(feature = "hwtstamp")]
                let ts = if kernel_rx {
                    msg.cmsgs()
                        .ok()
                        .and_then(crate::hwtstamp::extract_kernel_rx_timestamp)
                        .map(|k| crate::time::timestamp_from_parts(k.secs, k.nanos, cs))
                } else {
                    None
                };
                #[cfg(not(feature = "hwtstamp"))]
                let ts: Option<u64> = None;
                let ecn = if want_reply_ecn {
                    extract_reply_ecn_from_cmsgs(&msg)
                } else {
                    None
                };
                Ok((len, ts, ecn))
            }
            Err(nix::errno::Errno::EAGAIN) => {
                Err(std::io::Error::from(std::io::ErrorKind::WouldBlock))
            }
            Err(e) => Err(std::io::Error::from_raw_os_error(e as i32)),
        };
    }
    let _ = cs;
    let _ = kernel_rx;
    let _ = want_reply_ecn;
    let len = socket.recv(buf).await?;
    Ok((len, None, None))
}

/// Applies kernel TX timestamps from the error queue to the pending-packet
/// table: each report's OPT_ID resolves to a STAMP sequence number whose
/// stored T1 (used for forward OWD) is replaced by the kernel timestamp.
/// Returns how many corrections were applied.
#[cfg(all(feature = "hwtstamp", target_os = "linux"))]
fn apply_tx_corrections(
    reports: &[crate::hwtstamp::TxTimestampReport],
    tx_id_to_seq: &mut std::collections::HashMap<u32, u32>,
    pending: &mut HashMap<u32, PendingPacket>,
) -> usize {
    let mut applied = 0;
    for report in reports {
        if let Some(seq) = tx_id_to_seq.remove(&report.opt_id) {
            if let Some(p) = pending.get_mut(&seq) {
                p.send_timestamp = report.timestamp;
                applied += 1;
            }
        }
    }
    applied
}

fn process_response(
    data: &[u8],
    use_auth: bool,
    use_tlvs: bool,
    clock_source: ClockFormat,
    kernel_t4: Option<u64>,
    // Reply packet's on-wire ECN codepoint (reverse-path detection,
    // draft-ietf-ippm-stamp-cos-ecn-01 §3.4), from `recv_packet`'s
    // `extract_reply_ecn_from_cmsgs`. `None` when not requested/available.
    reply_ecn: Option<u8>,
    ctx: &mut SenderRecvContext,
) {
    let recv_time = Instant::now();
    // T4: prefer the kernel receive timestamp (taken at packet arrival);
    // otherwise the sender's wall-clock timestamp, captured as early as
    // possible (before parsing) for the reverse one-way-delay computation.
    let sender_recv_ts = kernel_t4.unwrap_or_else(|| generate_timestamp(clock_source));

    // Parse response and validate TLVs if extension mode is enabled
    // Use lenient parsing per RFC 8762 §4.6 to handle short packets.
    let (seq_num, reflector_recv_ts, reflector_send_ts, sender_ttl, tlv_info, reflected_ssids) =
        if use_auth {
            if use_tlvs {
                // Parse as extended packet with TLVs (lenient, returns canonical buffer)
                let (ext_packet, canonical_buf) =
                    ExtendedReflectedPacketAuthenticated::from_bytes_lenient(data);
                let base = &ext_packet.base;
                let seq_num = base.sess_sender_seq_number;
                let recv_ts = base.receive_timestamp;
                let send_ts = base.timestamp;
                let ttl = base.sess_sender_ttl;
                let hmac = base.hmac;

                // Verify base packet HMAC against canonical buffer (RFC 8762 §4.4, §4.6)
                if let Some(key) = ctx.hmac_key {
                    if !verify_packet_hmac(
                        key,
                        &canonical_buf,
                        REFLECTED_AUTH_PACKET_HMAC_OFFSET,
                        &hmac,
                    ) {
                        eprintln!(
                            "HMAC verification failed for reflected packet seq={}",
                            seq_num
                        );
                        #[cfg(feature = "metrics")]
                        if ctx.metrics_enabled {
                            crate::metrics::sender_metrics::record_hmac_failure();
                        }
                        return;
                    }
                }

                // Validate TLVs if present
                let tlv_info = if ext_packet.has_tlvs() {
                    match validate_reflected_tlvs(
                        &ext_packet.tlvs,
                        data,
                        AUTH_BASE_SIZE,
                        ctx.hmac_key,
                        ctx.expected_sender_msid,
                        ctx.expected_reflector_msid,
                        ctx.latched_reflector_msid,
                        ctx.access_report_state.is_some(),
                        ctx.congestion.is_some(),
                        #[cfg(feature = "metrics")]
                        ctx.metrics_enabled,
                    ) {
                        Ok(info) => info,
                        Err(reason) => {
                            eprintln!("Discarding reflected packet seq={}: {}", seq_num, reason);
                            #[cfg(feature = "metrics")]
                            if ctx.metrics_enabled {
                                crate::metrics::sender_metrics::record_tlv_error("M");
                            }
                            return;
                        }
                    }
                } else {
                    None
                };

                (
                    seq_num,
                    recv_ts,
                    send_ts,
                    ttl,
                    tlv_info,
                    (base.ssid, base.sess_sender_ssid),
                )
            } else {
                // Parse base packet only (lenient, returns canonical buffer)
                let (packet, canonical_buf) =
                    ReflectedPacketAuthenticated::from_bytes_lenient(data);
                let seq_num = packet.sess_sender_seq_number;
                let recv_ts = packet.receive_timestamp;
                let send_ts = packet.timestamp;
                let ttl = packet.sess_sender_ttl;
                let hmac = packet.hmac;

                // Verify HMAC against canonical buffer when key is present (RFC 8762 §4.4, §4.6)
                if let Some(key) = ctx.hmac_key {
                    if !verify_packet_hmac(
                        key,
                        &canonical_buf,
                        REFLECTED_AUTH_PACKET_HMAC_OFFSET,
                        &hmac,
                    ) {
                        eprintln!(
                            "HMAC verification failed for reflected packet seq={}",
                            seq_num
                        );
                        #[cfg(feature = "metrics")]
                        if ctx.metrics_enabled {
                            crate::metrics::sender_metrics::record_hmac_failure();
                        }
                        return;
                    }
                }
                (
                    seq_num,
                    recv_ts,
                    send_ts,
                    ttl,
                    None,
                    (packet.ssid, packet.sess_sender_ssid),
                )
            }
        } else if use_tlvs {
            // Parse as extended packet with TLVs (unauthenticated, lenient)
            let ext_packet = ExtendedReflectedPacketUnauthenticated::from_bytes_lenient(data);
            let base = &ext_packet.base;

            // Validate TLVs if present
            let tlv_info = if ext_packet.has_tlvs() {
                match validate_reflected_tlvs(
                    &ext_packet.tlvs,
                    data,
                    UNAUTH_BASE_SIZE,
                    ctx.hmac_key,
                    ctx.expected_sender_msid,
                    ctx.expected_reflector_msid,
                    ctx.latched_reflector_msid,
                    ctx.access_report_state.is_some(),
                    ctx.congestion.is_some(),
                    #[cfg(feature = "metrics")]
                    ctx.metrics_enabled,
                ) {
                    Ok(info) => info,
                    Err(reason) => {
                        eprintln!(
                            "Discarding reflected packet seq={}: {}",
                            base.sess_sender_seq_number, reason
                        );
                        #[cfg(feature = "metrics")]
                        if ctx.metrics_enabled {
                            crate::metrics::sender_metrics::record_tlv_error("M");
                        }
                        return;
                    }
                }
            } else {
                None
            };

            (
                base.sess_sender_seq_number,
                base.receive_timestamp,
                base.timestamp,
                base.sess_sender_ttl,
                tlv_info,
                (base.ssid, base.sess_sender_ssid),
            )
        } else {
            // Parse base packet only (lenient)
            let packet = ReflectedPacketUnauthenticated::from_bytes_lenient(data);
            (
                packet.sess_sender_seq_number,
                packet.receive_timestamp,
                packet.timestamp,
                packet.sess_sender_ttl,
                None,
                (packet.ssid, packet.sess_sender_ssid),
            )
        };

    // RFC 8972 §3 zeroed-SSID scenario. The reflector echoes the sender's SSID
    // in both the reflected `SSID` field and the `Session-Sender SSID` field; a
    // peer that does not implement the field leaves both zero (they are MBZ in
    // the RFC 8762 layout). Either one coming back zeroed against a non-zero
    // request means the reflector is not demultiplexing on SSID, so it is the
    // condition `--on-zero-ssid` governs.
    if let Some(expected) = ctx.expected_ssid {
        let (reflected_ssid, echoed_sender_ssid) = reflected_ssids;
        if reflected_ssid == 0 || echoed_sender_ssid == 0 {
            let first_time = !*ctx.zero_ssid_seen;
            *ctx.zero_ssid_seen = true;
            if first_time {
                match ctx.on_zero_ssid {
                    ZeroSsidAction::Continue => eprintln!(
                        "Warning: reflector returned a zeroed SSID (sent {expected}, \
                         got ssid={reflected_ssid} sender_ssid={echoed_sender_ssid}) \
                         — it is not demultiplexing sessions on SSID. Continuing \
                         per --on-zero-ssid=continue (RFC 8972 §3)."
                    ),
                    ZeroSsidAction::Stop => eprintln!(
                        "Reflector returned a zeroed SSID (sent {expected}, got \
                         ssid={reflected_ssid} sender_ssid={echoed_sender_ssid}); \
                         stopping the session per --on-zero-ssid=stop (RFC 8972 §3)."
                    ),
                }
            }
            if ctx.on_zero_ssid == ZeroSsidAction::Stop {
                // Do not account this reply: the session is over, and the
                // measurement it belongs to is the one being abandoned.
                return;
            }
        }
    }

    // RFC 8972 §4.6: "This timer MUST be disarmed upon reception of the
    // reflected STAMP test packet that includes the Access Report TLV."
    // `tlv_info`'s "AccessReport:ack" marker (set by `validate_reflected_tlvs`
    // only when the TLV survived the same U/M/I/HMAC gating as every other
    // reflected value) is the acknowledgment signal. This applies regardless
    // of whether `seq_num` still has a `pending` entry — the ack is about the
    // TLV's own delivery, not this specific packet's RTT accounting.
    if let Some(state) = ctx.access_report_state.as_mut() {
        if tlv_info
            .as_deref()
            .is_some_and(|s| s.contains("AccessReport:ack"))
        {
            state.acknowledge();
        }
    }

    // draft-ietf-ippm-stamp-cos-ecn-01 §3.4: observe CE from either the
    // reflected EC2 field (forward-path, sender→reflector, §3.4-1) or the
    // reply packet's own on-wire ECN (reverse-path, reflector→sender,
    // §3.4-2/-3), and drive the AIMD congestion-response controller.
    // Independent of whether this reply matched a `pending` entry — like
    // the Access Report ack above, this is about the congestion signal
    // carried by the reply, not this particular RTT sample. The forward-path
    // signal comes from `tlv_info`'s "CoS:CE" marker (set by
    // `validate_reflected_tlvs` only under the same integrity gate as every
    // other reflected TLV value — RFC 8972 §4.8-17 — so a reply that failed
    // TLV-HMAC verification or carries an I-flagged CoS TLV cannot be used
    // to force a spurious backoff); the reverse-path signal is the reply's
    // own on-wire ECN, which carries no TLV-level integrity to gate on (DSCP/
    // ECN are mutable-in-transit IP header fields by design, same as the
    // reflector's own treatment of the *incoming* test packet's ECN).
    if let Some(state) = ctx.congestion.as_mut() {
        let forward_ce = tlv_info.as_deref().is_some_and(|s| s.contains("CoS:CE"));
        let reverse_ce = reply_ecn == Some(0b11);
        if forward_ce || reverse_ce {
            state.controller.on_ce_observed();
            log::info!(
                "ECN congestion response: CE observed on seq={} (forward={} reverse={}); \
                 send interval backed off to {:?} (draft-ietf-ippm-stamp-cos-ecn-01 §3.4)",
                seq_num,
                forward_ce,
                reverse_ce,
                state.controller.current_interval()
            );
        } else {
            state.controller.on_clean_reply();
        }
    }

    if let Some(pending_packet) = ctx.pending.remove(&seq_num) {
        let rtt_ns = recv_time
            .duration_since(pending_packet.send_time)
            .as_nanos() as u64;

        *ctx.packets_received += 1;
        ctx.rtt_collector.record(RttSample {
            seq: seq_num,
            rtt_ns,
            ttl: sender_ttl,
        });

        // One-way delays from the four STAMP timestamps (signed: an
        // unsynchronised clock offset shifts the split between directions).
        //   forward = T2 − T1 (sender → reflector)
        //   reverse = T4 − T3 (reflector → sender)
        let t1 = timestamp_to_nanos(pending_packet.send_timestamp, clock_source) as i128;
        let t2 = timestamp_to_nanos(reflector_recv_ts, clock_source) as i128;
        let t3 = timestamp_to_nanos(reflector_send_ts, clock_source) as i128;
        let t4 = timestamp_to_nanos(sender_recv_ts, clock_source) as i128;
        ctx.owd_collector.record(OwdSample {
            seq: seq_num,
            forward_ns: (t2 - t1) as i64,
            reverse_ns: (t4 - t3) as i64,
        });

        #[cfg(all(unix, feature = "snmp"))]
        if let Some(stats) = ctx.snmp_stats {
            stats.inc_received();
            stats.record_rtt((rtt_ns / 1000) as u32);
        }

        #[cfg(feature = "metrics")]
        if ctx.metrics_enabled {
            let rtt_seconds = rtt_ns as f64 / 1_000_000_000.0;
            crate::metrics::sender_metrics::record_packet_received();
            crate::metrics::sender_metrics::record_rtt(rtt_seconds);
        }

        if ctx.print_stats {
            let tlv_status = tlv_info
                .as_ref()
                .map_or(String::new(), |info| format!(" tlv=[{}]", info));
            println!(
                "seq={} rtt={:.3}ms ttl={} reflector_recv_ts={} reflector_send_ts={}{}",
                seq_num,
                rtt_ns as f64 / 1_000_000.0,
                sender_ttl,
                reflector_recv_ts,
                reflector_send_ts,
                tlv_status
            );
        }
    } else {
        eprintln!("Received response for unknown sequence number: {}", seq_num);
    }
}

/// Validates TLVs in a reflected packet and returns a status string.
///
/// Checks for:
/// - Unrecognized TLV types (U-flag)
/// - Malformed TLVs (M-flag)
/// - Integrity failures (I-flag)
/// - TLV HMAC verification (if key is provided)
///
/// The `base_size` parameter specifies the fixed base packet size (44 for unauthenticated,
/// 112 for authenticated) to correctly locate TLV bytes in the packet data.
/// Reason a reflected packet is rejected without updating sender state.
///
/// Returned as the error variant of [`validate_reflected_tlvs`]. The caller
/// must log and discard the packet: no RTT sample recorded, no `pending`
/// entry consumed, no received counter incremented.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TlvRejection {
    /// Reflected Micro-session ID echoed a `sender_micro_session_id` that
    /// does not match what this sender emitted (RFC 9534 §3.2 binding check).
    /// A legitimate reflector always echoes the sender ID unchanged, so a
    /// mismatch means the response belongs to a different session, a stale
    /// packet, or a spoofed reply.
    MsidMismatch { got: u16, expected: u16 },
    /// Reflected Reflector Micro-session ID did not match the expected value
    /// (RFC 9534 §3.2-11/-12, an unconditional requirement). `expected` is
    /// either the pre-known reflector member-link identifier
    /// (`--reflector-member-link-id`) or, when that is not configured, the
    /// value latched from the first validly-received reply of the session
    /// (zero-config self-consistency check). Validating the reflector's
    /// behaviour: a changed value flags an anomaly (e.g. a mid-session LAG
    /// rehash moving the flow to a different member link), and the reply
    /// MUST be discarded.
    ReflectorMsidMismatch { got: u16, expected: u16 },
    /// Reflected Micro-session ID TLV could not be parsed. Since the TLV
    /// carries the session binding, we cannot attribute the response to this
    /// sender and must drop it.
    MsidMalformed,
}

impl std::fmt::Display for TlvRejection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MsidMismatch { got, expected } => write!(
                f,
                "Micro-session ID mismatch (got sender_id={}, expected={})",
                got, expected
            ),
            Self::ReflectorMsidMismatch { got, expected } => write!(
                f,
                "Reflector Micro-session ID mismatch (got reflector_id={}, expected={})",
                got, expected
            ),
            Self::MsidMalformed => {
                write!(f, "malformed Micro-session ID TLV in reflected packet")
            }
        }
    }
}

/// Builds the outgoing Micro-session ID TLV (RFC 9534 §3.1/§3.2).
///
/// The Sender Micro-session ID always carries the sender's own member-link
/// identifier. Per RFC 9534 §3.2-3, "If the Session-Sender knows the Reflector
/// member link identifier, the Reflector Micro-session ID field MUST be set" —
/// so when `reflector_id` is `Some`, it is written into the Reflector
/// Micro-session ID field; otherwise (§3.2-4) that field is left zero.
fn micro_session_request_tlv(sender_id: u16, reflector_id: Option<u16>) -> RawTlv {
    MicroSessionIdTlv::new(sender_id, reflector_id.unwrap_or(0)).to_raw()
}

#[allow(clippy::too_many_arguments)]
fn validate_reflected_tlvs(
    tlvs: &TlvList,
    data: &[u8],
    base_size: usize,
    hmac_key: Option<&HmacKey>,
    expected_sender_msid: Option<u16>,
    expected_reflector_msid: Option<u16>,
    latched_reflector_msid: &mut Option<u16>,
    // RFC 8972 §4.6: when the sender is tracking an in-flight Access Report
    // TLV, scan for its (gated) presence in the reply and surface it via the
    // "AccessReport:ack" marker in the returned status string. `false` when
    // `--access-report` was not set — the scan is skipped entirely, matching
    // prior behaviour for every caller that doesn't use it.
    track_access_report: bool,
    // draft-ietf-ippm-stamp-cos-ecn-01 §3.4: when the AIMD congestion
    // controller is active, scan for a CE-marked (0b11) EC2 field in the
    // reflected CoS TLV and surface it via the "CoS:CE" marker — gated by
    // the same `integrity_ok` check as MSID/AccessReport below (RFC 8972
    // §4.8-17: "HMAC MUST be verified before using any data in the
    // included STAMP TLVs"), so a tampered or unverifiable reply cannot be
    // used to force a spurious rate reduction. `false` when the controller
    // is inactive.
    track_congestion: bool,
    #[cfg(feature = "metrics")] metrics_enabled: bool,
) -> Result<Option<String>, TlvRejection> {
    let mut status_parts = Vec::new();
    let tlv_count = tlvs.len();

    // Step 1 — tally per-TLV flags (U/M/I) up front. Integrity decisions are
    // made BEFORE any reflected TLV value is consumed (RFC 8972 §4, §4.8-12:
    // "HMAC MUST be verified before using any data in the included STAMP
    // TLVs").
    let mut unrecognized_count = 0;
    let mut malformed_count = 0;
    let mut integrity_failed_count = 0;
    for tlv in tlvs.non_hmac_tlvs() {
        if tlv.is_unrecognized() {
            unrecognized_count += 1;
        }
        if tlv.is_malformed() {
            malformed_count += 1;
        }
        if tlv.is_integrity_failed() {
            integrity_failed_count += 1;
        }
    }
    if let Some(hmac_tlv) = tlvs.hmac_tlv() {
        if hmac_tlv.is_integrity_failed() {
            integrity_failed_count += 1;
        }
        if hmac_tlv.is_malformed() {
            malformed_count += 1;
        }
    }

    // Step 2 — TLV-HMAC verification result, computed before consuming any
    // value. `hmac_failed` gates value consumption below (RFC 8972 §4.8-17).
    let mut hmac_failed = false;
    if let Some(key) = hmac_key {
        if let Some(hmac_tlv) = tlvs.hmac_tlv() {
            if hmac_tlv.is_integrity_failed() {
                // Reflector echoed our HMAC with I-flag — it couldn't verify.
                status_parts.push("HMAC:unverified".to_string());
                hmac_failed = true;
            } else if base_size >= 4 && data.len() > base_size {
                // Use the fixed base_size to locate TLV bytes correctly
                // (avoids fragility with trailing padding or non-TLV bytes).
                let seq_bytes = &data[..4];
                let tlv_bytes = &data[base_size..];
                if tlvs.verify_hmac(key, seq_bytes, tlv_bytes).is_ok() {
                    status_parts.push("HMAC:ok".to_string());
                } else {
                    status_parts.push("HMAC:fail".to_string());
                    hmac_failed = true;
                }
            }
        } else {
            // No HMAC TLV in response (reflector may not support it).
            status_parts.push("no-hmac".to_string());
        }
    }

    // Step 3 — consume reflected TLV values for decisions ONLY when the
    // extension TLVs' integrity is intact:
    //   RFC 8972 §4-19 / §4.8-16 — an I-flagged TLV ⇒ discard all TLVs, stop.
    //   RFC 8972 §4.8-17        — TLV-HMAC failure ⇒ stop processing TLVs.
    // Within the loop, per-TLV flags gate individual TLVs:
    //   RFC 8972 §4-18 (M) — stop processing the remainder of the packet;
    //   RFC 8972 §4-17 (U) — skip processing of that TLV.
    // (Micro-session ID and the Access Report ack marker are the only
    // reflected values the sender consumes today; logging raw bytes is
    // fine, but they MUST NOT influence session binding.)
    let integrity_ok = !hmac_failed && integrity_failed_count == 0;
    let want_msid = expected_sender_msid.is_some() || expected_reflector_msid.is_some();
    if integrity_ok && (want_msid || track_access_report || track_congestion) {
        for raw in tlvs.non_hmac_tlvs() {
            if raw.is_malformed() {
                break; // §4-18: M flag halts remainder.
            }
            if raw.is_unrecognized() {
                continue; // §4-17: U flag skips this TLV.
            }
            if track_access_report && raw.tlv_type == crate::tlv::TlvType::AccessReport {
                // RFC 8972 §4.6: "This timer MUST be disarmed upon reception
                // of the reflected STAMP test packet that includes the
                // Access Report TLV" — presence of a recognized,
                // non-malformed, integrity-intact echo (U/M already excluded
                // above; I-flagged/TLV-HMAC-failed replies are excluded by
                // the surrounding `integrity_ok` gate) is the acknowledgment
                // signal `process_response` looks for.
                status_parts.push("AccessReport:ack".to_string());
            }
            if track_congestion && raw.tlv_type == TlvType::ClassOfService {
                // draft-ietf-ippm-stamp-cos-ecn-01 §3.4: EC2 = 0b11 signals
                // forward-path (sender→reflector) congestion. Same
                // U/M-flag-gated, integrity-checked path as every other
                // reflected value consumed above.
                if let Ok(cos) = ClassOfServiceTlv::from_raw(raw) {
                    if cos.ecn2 == 0b11 {
                        status_parts.push("CoS:CE".to_string());
                    }
                }
            }
            if want_msid && raw.tlv_type == crate::tlv::TlvType::MicroSessionId {
                let parsed =
                    MicroSessionIdTlv::from_raw(raw).map_err(|_| TlvRejection::MsidMalformed)?;
                // RFC 9534 §3.2 / §3.2-9: our sender_micro_session_id must be
                // echoed unchanged — a mismatch means the reply belongs to a
                // different session (or is spoofed); discard.
                if let Some(expected) = expected_sender_msid {
                    if parsed.sender_micro_session_id != expected {
                        return Err(TlvRejection::MsidMismatch {
                            got: parsed.sender_micro_session_id,
                            expected,
                        });
                    }
                }
                // RFC 9534 §3.2-11: "The micro Session-Sender MUST use the
                // Reflector Micro-session ID to validate the Reflector's
                // behavior" — unconditional, not gated on pre-known
                // configuration. When the reflector's member-link ID is
                // pre-known (`--reflector-member-link-id`), it takes
                // precedence and the reflected value must equal it —
                // discard on mismatch. Otherwise (zero-config path), the
                // first validly-received reply's Reflector Micro-session ID
                // is latched and becomes the expected value for the rest of
                // the session; a later reply with a different reflector ID
                // is rejected through the same path as the pre-known
                // mismatch. Pre-known configuration always wins: it is never
                // overridden by a first-seen value.
                if let Some(expected_refl) = expected_reflector_msid {
                    if parsed.reflector_micro_session_id != expected_refl {
                        return Err(TlvRejection::ReflectorMsidMismatch {
                            got: parsed.reflector_micro_session_id,
                            expected: expected_refl,
                        });
                    }
                } else if let Some(expected_refl) = *latched_reflector_msid {
                    if parsed.reflector_micro_session_id != expected_refl {
                        return Err(TlvRejection::ReflectorMsidMismatch {
                            got: parsed.reflector_micro_session_id,
                            expected: expected_refl,
                        });
                    }
                } else {
                    *latched_reflector_msid = Some(parsed.reflector_micro_session_id);
                }
                status_parts.push(format!(
                    "MSID:ok(reflector={})",
                    parsed.reflector_micro_session_id
                ));
            }
        }
    }

    // Step 4 — report flagged TLVs and record metrics.
    if unrecognized_count > 0 {
        status_parts.push(format!("{}U", unrecognized_count));
        #[cfg(feature = "metrics")]
        if metrics_enabled {
            for _ in 0..unrecognized_count {
                crate::metrics::sender_metrics::record_tlv_error("U");
            }
        }
    }
    if malformed_count > 0 {
        status_parts.push(format!("{}M", malformed_count));
        #[cfg(feature = "metrics")]
        if metrics_enabled {
            for _ in 0..malformed_count {
                crate::metrics::sender_metrics::record_tlv_error("M");
            }
        }
    }
    if integrity_failed_count > 0 {
        status_parts.push(format!("{}I", integrity_failed_count));
        #[cfg(feature = "metrics")]
        if metrics_enabled {
            for _ in 0..integrity_failed_count {
                crate::metrics::sender_metrics::record_tlv_error("I");
            }
        }
    }

    Ok(if status_parts.is_empty() {
        Some(format!("{} TLVs", tlv_count))
    } else {
        Some(format!("{} TLVs, {}", tlv_count, status_parts.join(", ")))
    })
}

/// Parses an ASCII hex string (with optional `0x` prefix) into a byte vector.
/// Empty input is rejected because an empty BER pattern is meaningless.
/// Builds the Reflected Test Packet Control TLV
/// (draft-ietf-ippm-asymmetrical-pkts-14 §3) when the configuration requests
/// asymmetric replies (count > 1) and/or attaches an IPv6 Extension Header
/// Control sub-TLV (draft-ietf-ippm-stamp-ext-hdr-11 §5.3). Returns `None` for
/// plain symmetric measurements so trivial sessions are not amplified.
fn build_reflected_control_tlv(
    length: u16,
    count: u16,
    interval_ns: u32,
    no_ext_hdr: bool,
) -> Option<ReflectedControlTlv> {
    if count <= 1 && !no_ext_hdr {
        return None;
    }
    if no_ext_hdr {
        // Presence-only IPv6 Extension Header Control sub-TLV:
        // flags=0, type (experimental stand-in for TBA3), length=0.
        Some(ReflectedControlTlv::with_sub_tlvs(
            length,
            count,
            interval_ns,
            vec![
                0x00,
                crate::tlv::REFLECTED_CONTROL_SUBTLV_IPV6_EXT_HDR_CONTROL,
                0x00,
                0x00,
            ],
        ))
    } else {
        Some(ReflectedControlTlv::new(length, count, interval_ns))
    }
}

/// Builds the per-send Reflected Test Packet Control TLV with its requested
/// interval scaled by the current AIMD factor
/// (draft-ietf-ippm-stamp-cos-ecn-01 §3.4-3: "adjust the Reflected Test Packet
/// Control parameters in any future STAMP packet ... based on the observation
/// of CE values").
///
/// Used by every path that emits a test packet while `scale_reflected_control`
/// is active — the main send loop and the Access Report wait-phase
/// retransmission. Those paths build their TLV set from a clone of
/// `extra_tlvs`, which deliberately omits the static control TLV in that mode,
/// so each of them must add the scaled one back or the TLV disappears from the
/// packets they send.
fn scaled_reflected_control_tlv(
    length: u16,
    count: u16,
    interval_ns: u32,
    no_ext_hdr: bool,
    scale: f64,
) -> Option<RawTlv> {
    let scaled_ns = ((interval_ns as f64) * scale)
        .round()
        .clamp(0.0, u32::MAX as f64) as u32;
    build_reflected_control_tlv(length, count, scaled_ns, no_ext_hdr).map(|c| c.to_raw())
}

fn parse_hex_pattern(s: &str) -> Result<Vec<u8>, String> {
    let trimmed = s.strip_prefix("0x").unwrap_or(s);
    if trimmed.is_empty() {
        return Err("empty pattern".into());
    }
    hex::decode(trimmed).map_err(|e| e.to_string())
}

/// Builds the Reflected Fixed / IPv6 Extension Header request TLVs
/// (draft-ietf-ippm-stamp-ext-hdr-11 §§3.1, 3.2) for the outgoing packet,
/// honoring the optional §5.1/§5.2 Requested-field selectors. Assumes `conf`
/// has passed `validate()` (so any selector decodes and fits); a stray decode
/// error degrades to the zero-filled request rather than panicking.
fn reflected_header_request_tlvs(conf: &Configuration) -> Vec<RawTlv> {
    let mut out = Vec::new();

    // draft-ietf-ippm-stamp-ext-hdr-11 §3.3: the Reflected Fixed Header Data
    // (Type 247) TLVs MUST be added before the Reflected IPv6 Extension Header
    // Data (Type 246) TLVs, so emit every 247 first.
    let fixed_family_len = if conf.remote_addr.is_ipv4() {
        IPV4_FIXED_HEADER_SIZE
    } else {
        IPV6_FIXED_HEADER_SIZE
    };
    let fixed_specs = conf.fixed_hdr_requests();
    // §3.2 rule 2: each occurrence adds a Type-247 TLV, all of matching length,
    // paired positionally with the reflector's outer→inner capture. The
    // backward-compatible standalone `--reflected-fixed-hdr-selector` applies
    // only to the single-header form.
    let single_fixed = fixed_specs.len() == 1;
    for spec in &fixed_specs {
        let selector = spec.selector.clone().or_else(|| {
            single_fixed
                .then(|| selector_bytes(conf.reflected_fixed_hdr_selector.as_deref()))
                .flatten()
        });
        let tlv = match selector {
            Some(sel) => ReflectedFixedHdrTlv::request_with_selector(&sel, fixed_family_len),
            None => ReflectedFixedHdrTlv::request_with_capacity(fixed_family_len),
        };
        out.push(tlv.to_raw());
    }
    if !fixed_specs.is_empty() {
        log::info!(
            "Reflected Fixed Header TLV(s) (Type 247) requested: {} header(s), {} bytes each",
            fixed_specs.len(),
            fixed_family_len
        );
    }

    // draft-ietf-ippm-stamp-ext-hdr-11 §3.1: for every real IPv6 extension
    // header the sender attaches (`--attach-ext-hdr`), emit a matching Type-246
    // request TLV so the reflector copies it back. The attached headers appear
    // on the wire before any externally-supplied ones, and each carries an
    // all-zeros Requested field: the header's first on-wire octet (Next Header)
    // is assigned by the kernel and cannot be predicted here, so positional
    // pairing (§3.1 rule 2), not a selector, disambiguates them.
    // IPv6 extension headers do not exist for IPv4, so attach-derived request
    // TLVs are emitted only for IPv6 destinations (matching the send-path gate).
    let attach_specs = if conf.remote_addr.is_ipv6() {
        conf.attach_ext_hdrs()
    } else {
        Vec::new()
    };
    for attach in &attach_specs {
        out.push(ReflectedIpv6ExtHdrTlv::request_with_capacity(attach.bytes.len()).to_raw());
    }
    if !attach_specs.is_empty() {
        log::info!(
            "Attaching {} real IPv6 extension header(s) with matching Type-246 request TLV(s) \
             (draft-ietf-ippm-stamp-ext-hdr-11 §3.1)",
            attach_specs.len()
        );
    }

    // Explicit `--reflected-ipv6-ext-hdr` request TLVs (§3.1 rule 2: lengths
    // matching, in order). The standalone `--reflected-ipv6-ext-hdr-selector`
    // applies only to the single-header form.
    let ext_specs = conf.ext_hdr_requests();
    let single_ext = ext_specs.len() == 1;
    for spec in &ext_specs {
        let selector = spec.selector.clone().or_else(|| {
            single_ext
                .then(|| selector_bytes(conf.reflected_ipv6_ext_hdr_selector.as_deref()))
                .flatten()
        });
        let tlv = match selector {
            Some(sel) => {
                let cap = spec.length.max(sel.len());
                ReflectedIpv6ExtHdrTlv::request_with_selector(&sel, cap)
            }
            None => ReflectedIpv6ExtHdrTlv::request_with_capacity(spec.length),
        };
        out.push(tlv.to_raw());
    }
    if !ext_specs.is_empty() {
        log::info!(
            "Reflected IPv6 Ext Header TLV(s) (Type 246) requested: {} header(s)",
            ext_specs.len()
        );
    }

    out
}

/// Decodes a validated selector string to bytes; `None` when absent or (post-
/// `validate()`, which should not happen) unparseable.
fn selector_bytes(sel: Option<&str>) -> Option<Vec<u8>> {
    sel.and_then(|s| decode_selector(s).ok())
}

/// Creates a new unauthenticated STAMP test packet with the specified error estimate.
///
/// The caller should set the sequence number and timestamp before sending.
///
/// # Arguments
/// * `error_estimate` - The 16-bit error estimate value in wire format
pub fn assemble_unauth_packet(error_estimate: u16) -> PacketUnauthenticated {
    PacketUnauthenticated {
        timestamp: 0,
        ssid: 0,
        mbz: [0u8; 28],
        error_estimate,
        sequence_number: 0,
    }
}

/// Creates a new authenticated STAMP test packet with the specified error estimate.
///
/// The caller should set the sequence number and timestamp before sending.
/// Use `finalize_auth_packet` to compute and set the HMAC after all fields are set.
///
/// # Arguments
/// * `error_estimate` - The 16-bit error estimate value in wire format
pub fn assemble_auth_packet(error_estimate: u16) -> PacketAuthenticated {
    PacketAuthenticated {
        timestamp: 0,
        mbz0: [0u8; 12],
        error_estimate,
        ssid: 0,
        sequence_number: 0,
        hmac: [0u8; 16],
        mbz1a: [0u8; 30],
        mbz1b: [0u8; 32],
        mbz1c: [0u8; 6],
    }
}

/// HMAC field offset in PacketAuthenticated (bytes before HMAC field).
pub const AUTH_PACKET_HMAC_OFFSET: usize = 96;

/// Computes and sets the HMAC for an authenticated packet.
///
/// This should be called after all other fields in the packet have been set.
///
/// # Arguments
/// * `packet` - The packet to finalize
/// * `key` - The HMAC key to use
pub fn finalize_auth_packet(packet: &mut PacketAuthenticated, key: &HmacKey) {
    let bytes = packet.to_bytes();
    packet.hmac = compute_packet_hmac(key, &bytes, AUTH_PACKET_HMAC_OFFSET);
}

/// Builds an unauthenticated STAMP packet with TLV extensions.
///
/// # Arguments
/// * `sequence_number` - Packet sequence number
/// * `timestamp` - Send timestamp
/// * `error_estimate` - Error estimate in wire format
/// * `ssid` - Optional Session-Sender Identifier
/// * `extra_tlvs` - Additional TLVs to include
/// * `tlv_hmac_key` - Optional HMAC key for TLV integrity
pub fn build_unauth_packet_with_tlvs(
    sequence_number: u32,
    timestamp: u64,
    error_estimate: u16,
    ssid: Option<u16>,
    extra_tlvs: &[RawTlv],
    tlv_hmac_key: Option<&HmacKey>,
) -> Vec<u8> {
    let base = PacketUnauthenticated {
        sequence_number,
        timestamp,
        error_estimate,
        ssid: ssid.unwrap_or(0),
        mbz: [0u8; 28],
    };
    let base_bytes = base.to_bytes();

    let mut tlvs = TlvList::new();

    // Add any extra TLVs
    for tlv in extra_tlvs {
        tlvs.push(tlv.clone()).ok();
    }

    // Add TLV HMAC if key is provided
    // Per RFC 8972 §4.8: HMAC covers Sequence Number (first 4 bytes) + preceding TLVs
    if let Some(key) = tlv_hmac_key {
        let seq_bytes = &base_bytes[..4];
        tlvs.set_hmac(key, seq_bytes);
    }

    let mut result = base_bytes.to_vec();
    if !tlvs.is_empty() {
        result.extend_from_slice(&tlvs.to_bytes());
    }

    result
}

/// Builds an authenticated STAMP packet with TLV extensions.
///
/// # Arguments
/// * `sequence_number` - Packet sequence number
/// * `timestamp` - Send timestamp
/// * `error_estimate` - Error estimate in wire format
/// * `base_hmac_key` - HMAC key for base packet authentication
/// * `ssid` - Optional Session-Sender Identifier
/// * `extra_tlvs` - Additional TLVs to include
/// * `tlv_hmac_key` - Optional HMAC key for TLV integrity (can be same as base)
pub fn build_auth_packet_with_tlvs(
    sequence_number: u32,
    timestamp: u64,
    error_estimate: u16,
    base_hmac_key: &HmacKey,
    ssid: Option<u16>,
    extra_tlvs: &[RawTlv],
    tlv_hmac_key: Option<&HmacKey>,
) -> Vec<u8> {
    let mut base = PacketAuthenticated {
        sequence_number,
        timestamp,
        error_estimate,
        ssid: ssid.unwrap_or(0),
        mbz0: [0u8; 12],
        mbz1a: [0u8; 30],
        mbz1b: [0u8; 32],
        mbz1c: [0u8; 6],
        hmac: [0u8; 16],
    };

    // Compute base packet HMAC
    finalize_auth_packet(&mut base, base_hmac_key);
    let base_bytes = base.to_bytes();

    let mut tlvs = TlvList::new();

    // Add any extra TLVs
    for tlv in extra_tlvs {
        tlvs.push(tlv.clone()).ok();
    }

    // Add TLV HMAC if key is provided
    // Per RFC 8972 §4.8: HMAC covers Sequence Number (first 4 bytes) + preceding TLVs
    if let Some(key) = tlv_hmac_key {
        let seq_bytes = &base_bytes[..4];
        tlvs.set_hmac(key, seq_bytes);
    }

    let mut result = base_bytes.to_vec();
    if !tlvs.is_empty() {
        result.extend_from_slice(&tlvs.to_bytes());
    }

    result
}

/// Creates an Extended unauthenticated packet from configuration.
///
/// This is a convenience wrapper for building packets with TLV support.
pub fn create_extended_unauth_packet(
    sequence_number: u32,
    timestamp: u64,
    error_estimate: u16,
    ssid: Option<u16>,
) -> ExtendedPacketUnauthenticated {
    let base = PacketUnauthenticated {
        sequence_number,
        timestamp,
        error_estimate,
        ssid: ssid.unwrap_or(0),
        mbz: [0u8; 28],
    };

    ExtendedPacketUnauthenticated::with_tlvs(base, TlvList::new())
}

/// Creates an Extended authenticated packet from configuration.
///
/// This is a convenience wrapper for building packets with TLV support.
pub fn create_extended_auth_packet(
    sequence_number: u32,
    timestamp: u64,
    error_estimate: u16,
    hmac_key: &HmacKey,
    ssid: Option<u16>,
) -> ExtendedPacketAuthenticated {
    let mut base = PacketAuthenticated {
        sequence_number,
        timestamp,
        error_estimate,
        ssid: ssid.unwrap_or(0),
        mbz0: [0u8; 12],
        mbz1a: [0u8; 30],
        mbz1b: [0u8; 32],
        mbz1c: [0u8; 6],
        hmac: [0u8; 16],
    };

    finalize_auth_packet(&mut base, hmac_key);

    ExtendedPacketAuthenticated::with_tlvs(base, TlvList::new())
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- draft-ietf-ippm-stamp-ext-hdr-11 header-reflection request TLVs ----

    fn ext_hdr_conf(extra: &[&str]) -> crate::configuration::Configuration {
        use clap::Parser;
        let mut args = vec!["test", "--remote-addr"];
        // Default to an IPv6 destination so ext-hdr flags are meaningful.
        args.push("2001:db8::1");
        args.extend_from_slice(extra);
        let conf = crate::configuration::Configuration::try_parse_from(args)
            .expect("parse ext-hdr test args");
        conf.validate().expect("validate ext-hdr test conf");
        conf
    }

    fn tlvs_of(tlvs: &[RawTlv], ty: TlvType) -> Vec<&RawTlv> {
        tlvs.iter().filter(|t| t.tlv_type == ty).collect()
    }

    #[test]
    fn ext_hdr_multi_requests_emit_multiple_type246_tlvs_in_order() {
        // §3.1 rule 2: multiple occurrences → multiple Type-246 TLVs with
        // matching lengths, in order. The inline `LEN:SELECTORHEX` form carries
        // a per-occurrence §5.1 selector.
        let conf = ext_hdr_conf(&[
            "--reflected-ipv6-ext-hdr",
            "8",
            "--reflected-ipv6-ext-hdr",
            "16:3c000102",
        ]);
        let tlvs = reflected_header_request_tlvs(&conf);
        let ext = tlvs_of(&tlvs, TlvType::ReflectedIpv6ExtHdr);
        assert_eq!(ext.len(), 2, "two occurrences → two Type-246 TLVs");
        assert_eq!(ext[0].value.len(), 8);
        assert!(
            ext[0].value.iter().all(|&b| b == 0),
            "bare-length occurrence has an all-zeros Requested field"
        );
        assert_eq!(ext[1].value.len(), 16, "inline LEN is honoured");
        assert_eq!(
            &ext[1].value[..4],
            &[0x3c, 0x00, 0x01, 0x02],
            "inline selector populates the Requested field"
        );
    }

    #[test]
    fn ext_hdr_single_form_backward_compatible_with_standalone_selector() {
        let conf = ext_hdr_conf(&[
            "--reflected-ipv6-ext-hdr",
            "--reflected-ipv6-ext-hdr-selector",
            "3c000102",
        ]);
        let tlvs = reflected_header_request_tlvs(&conf);
        let ext = tlvs_of(&tlvs, TlvType::ReflectedIpv6ExtHdr);
        assert_eq!(ext.len(), 1);
        assert_eq!(&ext[0].value[..4], &[0x3c, 0x00, 0x01, 0x02]);
    }

    #[test]
    fn fixed_hdr_multi_requests_emit_multiple_type247_tlvs() {
        // §3.2 rule 2 (sender half): multiple occurrences → multiple Type-247
        // TLVs of matching length.
        let conf = ext_hdr_conf(&["--reflected-fixed-hdr", "--reflected-fixed-hdr"]);
        let tlvs = reflected_header_request_tlvs(&conf);
        let fixed = tlvs_of(&tlvs, TlvType::ReflectedFixedHdr);
        assert_eq!(fixed.len(), 2, "two occurrences → two Type-247 TLVs");
        assert!(fixed
            .iter()
            .all(|t| t.value.len() == IPV6_FIXED_HEADER_SIZE));
    }

    #[test]
    fn fixed_hdr_before_ext_hdr_per_section_3_3() {
        // §3.3: every Type-247 TLV MUST precede every Type-246 TLV.
        let conf = ext_hdr_conf(&["--reflected-ipv6-ext-hdr", "--reflected-fixed-hdr"]);
        let tlvs = reflected_header_request_tlvs(&conf);
        let first_246 = tlvs
            .iter()
            .position(|t| t.tlv_type == TlvType::ReflectedIpv6ExtHdr);
        let last_247 = tlvs
            .iter()
            .rposition(|t| t.tlv_type == TlvType::ReflectedFixedHdr);
        assert!(last_247.unwrap() < first_246.unwrap(), "247 before 246");
    }

    #[test]
    fn attach_ext_hdr_emits_matching_type246_request() {
        // §3.1: attaching a real header MUST add a corresponding Type-246 TLV.
        // Default (no HEX) is an 8-octet header ⇒ Length 8, all-zeros Requested.
        let conf = ext_hdr_conf(&["--attach-ext-hdr", "dest"]);
        let tlvs = reflected_header_request_tlvs(&conf);
        let ext = tlvs_of(&tlvs, TlvType::ReflectedIpv6ExtHdr);
        assert_eq!(ext.len(), 1, "one attached header → one Type-246 TLV");
        assert_eq!(ext[0].value.len(), 8);
        assert!(ext[0].value.iter().all(|&b| b == 0));
    }

    #[test]
    fn attach_ext_hdr_custom_hex_sizes_the_request_tlv() {
        // A 16-octet attached header ⇒ a Length-16 Type-246 request TLV.
        let conf = ext_hdr_conf(&["--attach-ext-hdr", "hbh:00000104000000000000000000000000"]);
        let tlvs = reflected_header_request_tlvs(&conf);
        let ext = tlvs_of(&tlvs, TlvType::ReflectedIpv6ExtHdr);
        assert_eq!(ext.len(), 1);
        assert_eq!(ext[0].value.len(), 16);
    }

    // --- Sender MTU enforcement (draft-ietf-ippm-stamp-ext-hdr-11 §3.1/§3.2) --

    #[test]
    fn enforce_egress_mtu_trims_header_tlvs_to_fit() {
        // Three 40-byte Type-247 TLVs (44 bytes on the wire each) plus 100 bytes
        // of fixed overhead = 232 bytes. An MTU of 150 forces two removals.
        let mut tlvs: Vec<RawTlv> = (0..3)
            .map(|_| ReflectedFixedHdrTlv::request_with_capacity(40).to_raw())
            .collect();
        enforce_egress_mtu(&mut tlvs, 150, 100);
        let remaining = tlvs
            .iter()
            .filter(|t| t.tlv_type == TlvType::ReflectedFixedHdr)
            .count();
        // 100 + 44 = 144 <= 150; 100 + 88 = 188 > 150 ⇒ exactly one survives.
        assert_eq!(remaining, 1, "trimmed to fit the MTU");
    }

    #[test]
    fn enforce_egress_mtu_keeps_non_header_tlvs() {
        // A large non-header TLV that alone busts the MTU must NOT be removed —
        // the draft's removal rule is specific to Types 246/247.
        let mut tlvs = vec![
            ExtraPaddingTlv::new_zeros(200).to_raw(),
            ReflectedFixedHdrTlv::request_with_capacity(40).to_raw(),
        ];
        enforce_egress_mtu(&mut tlvs, 100, 50);
        assert!(
            tlvs.iter().any(|t| t.tlv_type == TlvType::ExtraPadding),
            "non-header padding TLV is preserved"
        );
        assert!(
            !tlvs
                .iter()
                .any(|t| t.tlv_type == TlvType::ReflectedFixedHdr),
            "the header TLV is removed first"
        );
    }

    #[test]
    fn enforce_egress_mtu_noop_when_fits() {
        let mut tlvs = vec![ReflectedFixedHdrTlv::request_with_capacity(20).to_raw()];
        let before = tlvs.len();
        enforce_egress_mtu(&mut tlvs, 1500, 100);
        assert_eq!(tlvs.len(), before, "no removal when the packet fits");
    }

    // --- AccessReportRetransmitState (RFC 8972 §4.6) -----------------------

    #[test]
    fn test_access_report_defaults_match_rfc_8972_4_6() {
        // "The default value of the retransmission timer for the Access
        // Report TLV SHOULD be three seconds."
        assert_eq!(DEFAULT_ACCESS_REPORT_TIMEOUT, Duration::from_secs(3));
        // "This retransmission SHOULD be repeated up to four times before
        // the procedure is aborted."
        assert_eq!(DEFAULT_ACCESS_REPORT_RETRIES, 4);
    }

    #[test]
    fn test_access_report_state_fresh_is_pending() {
        let state = AccessReportRetransmitState::new(Duration::from_secs(3), 4);
        assert_eq!(state.outcome(), AccessReportOutcome::Pending);
        assert_eq!(state.retransmissions(), 0);
    }

    #[test]
    fn test_access_report_first_tick_attaches_and_arms() {
        let mut state = AccessReportRetransmitState::new(Duration::from_secs(3), 4);
        let now = Instant::now();
        assert!(state.tick(now), "first tick must attach the TLV");
        assert_eq!(state.outcome(), AccessReportOutcome::Pending);
        assert_eq!(state.retransmissions(), 0);
    }

    #[test]
    fn test_access_report_tick_before_deadline_does_not_reattach() {
        let mut state = AccessReportRetransmitState::new(Duration::from_secs(3), 4);
        let now = Instant::now();
        assert!(state.tick(now));
        // Still well before the 3s deadline.
        assert!(!state.tick(now + Duration::from_millis(500)));
        assert_eq!(state.retransmissions(), 0);
    }

    #[test]
    fn test_access_report_tick_after_deadline_retransmits() {
        let mut state = AccessReportRetransmitState::new(Duration::from_secs(3), 4);
        let now = Instant::now();
        assert!(state.tick(now));
        let after_expiry = now + Duration::from_secs(3) + Duration::from_millis(1);
        assert!(
            state.tick(after_expiry),
            "expired timer must trigger a retransmission"
        );
        assert_eq!(state.retransmissions(), 1);
        assert_eq!(state.outcome(), AccessReportOutcome::Pending);
    }

    #[test]
    fn test_access_report_retries_exhausted_then_aborted() {
        let mut state = AccessReportRetransmitState::new(Duration::from_secs(1), 2);
        let mut now = Instant::now();
        assert!(state.tick(now)); // original send (attempt 0)
        now += Duration::from_secs(1) + Duration::from_millis(1);
        assert!(state.tick(now)); // retransmission 1
        now += Duration::from_secs(1) + Duration::from_millis(1);
        assert!(state.tick(now)); // retransmission 2 (== max_retries)
        assert_eq!(state.retransmissions(), 2);
        assert_eq!(state.outcome(), AccessReportOutcome::Pending);

        // Third expiry past the retry budget aborts the procedure.
        now += Duration::from_secs(1) + Duration::from_millis(1);
        assert!(!state.tick(now), "aborting must not request another attach");
        assert_eq!(state.outcome(), AccessReportOutcome::Aborted);
        assert_eq!(
            state.retransmissions(),
            2,
            "aborting itself is not counted as a retransmission"
        );

        // Aborted is terminal: further ticks never attach again.
        now += Duration::from_secs(10);
        assert!(!state.tick(now));
        assert_eq!(state.outcome(), AccessReportOutcome::Aborted);
    }

    #[test]
    fn test_access_report_zero_retries_aborts_on_first_expiry() {
        // RFC 8972 §4.6 MUST: operators must be able to control the retry
        // count, including down to 0 (abort immediately, no retransmits).
        let mut state = AccessReportRetransmitState::new(Duration::from_secs(1), 0);
        let now = Instant::now();
        assert!(state.tick(now));
        let after_expiry = now + Duration::from_secs(1) + Duration::from_millis(1);
        assert!(!state.tick(after_expiry));
        assert_eq!(state.outcome(), AccessReportOutcome::Aborted);
        assert_eq!(state.retransmissions(), 0);
    }

    #[test]
    fn test_access_report_acknowledge_before_deadline_disarms() {
        let mut state = AccessReportRetransmitState::new(Duration::from_secs(3), 4);
        let now = Instant::now();
        assert!(state.tick(now));
        state.acknowledge();
        assert_eq!(state.outcome(), AccessReportOutcome::Acknowledged);

        // Acknowledged is terminal: no further attach, ever, even long past
        // where the original deadline would have expired.
        assert!(!state.tick(now + Duration::from_secs(30)));
        assert_eq!(state.outcome(), AccessReportOutcome::Acknowledged);
    }

    #[test]
    fn test_access_report_acknowledge_after_retransmit_disarms_and_stops() {
        let mut state = AccessReportRetransmitState::new(Duration::from_secs(1), 4);
        let now = Instant::now();
        assert!(state.tick(now));
        let after_expiry = now + Duration::from_secs(1) + Duration::from_millis(1);
        assert!(state.tick(after_expiry)); // retransmission 1
        assert_eq!(state.retransmissions(), 1);

        state.acknowledge();
        assert_eq!(state.outcome(), AccessReportOutcome::Acknowledged);
        assert_eq!(
            state.retransmissions(),
            1,
            "retransmission count survives acknowledgment for reporting"
        );
        assert!(!state.tick(after_expiry + Duration::from_secs(10)));
    }

    #[test]
    fn test_access_report_acknowledge_before_any_send_is_noop() {
        // An ack cannot arrive before the TLV was ever sent — guards
        // against a caller wiring this up backwards.
        let mut state = AccessReportRetransmitState::new(Duration::from_secs(3), 4);
        state.acknowledge();
        assert_eq!(state.outcome(), AccessReportOutcome::Pending);
    }

    #[test]
    fn test_access_report_acknowledge_after_aborted_is_noop() {
        let mut state = AccessReportRetransmitState::new(Duration::from_secs(1), 0);
        let now = Instant::now();
        assert!(state.tick(now));
        assert!(!state.tick(now + Duration::from_secs(2)));
        assert_eq!(state.outcome(), AccessReportOutcome::Aborted);

        state.acknowledge();
        assert_eq!(
            state.outcome(),
            AccessReportOutcome::Aborted,
            "a stray ack must not resurrect an aborted procedure"
        );
    }

    #[test]
    fn test_access_report_summary_reflects_state() {
        let mut state = AccessReportRetransmitState::new(Duration::from_secs(1), 4);
        let now = Instant::now();
        assert!(state.tick(now));
        assert!(state.tick(now + Duration::from_secs(1) + Duration::from_millis(1)));
        state.acknowledge();
        let summary = state.summary();
        assert_eq!(summary.outcome, AccessReportOutcome::Acknowledged);
        assert_eq!(summary.retransmissions, 1);
    }

    #[test]
    fn reflected_header_tlvs_apply_selectors() {
        use crate::tlv::TlvType;
        use clap::Parser;
        let conf = Configuration::try_parse_from([
            "test",
            "--remote-addr",
            "127.0.0.1",
            "--reflected-ipv6-ext-hdr",
            "--reflected-ipv6-ext-hdr-selector",
            "3c000102",
            "--reflected-fixed-hdr",
            "--reflected-fixed-hdr-selector",
            "45000054",
        ])
        .unwrap();

        let tlvs = reflected_header_request_tlvs(&conf);

        let fixed = tlvs
            .iter()
            .find(|t| t.tlv_type == TlvType::ReflectedFixedHdr)
            .unwrap();
        assert_eq!(fixed.value.len(), IPV4_FIXED_HEADER_SIZE);
        assert_eq!(&fixed.value[..4], &[0x45, 0x00, 0x00, 0x54]);
        assert!(fixed.value[4..].iter().all(|&b| b == 0));

        let ext = tlvs
            .iter()
            .find(|t| t.tlv_type == TlvType::ReflectedIpv6ExtHdr)
            .unwrap();
        assert_eq!(&ext.value[..4], &[0x3c, 0x00, 0x01, 0x02]);
        assert!(ext.value[4..].iter().all(|&b| b == 0));
    }

    #[test]
    fn reflected_header_tlvs_zero_fill_without_selector() {
        use clap::Parser;
        let conf = Configuration::try_parse_from([
            "test",
            "--remote-addr",
            "127.0.0.1",
            "--reflected-ipv6-ext-hdr",
            "--reflected-fixed-hdr",
        ])
        .unwrap();

        let tlvs = reflected_header_request_tlvs(&conf);
        assert_eq!(tlvs.len(), 2);
        for t in &tlvs {
            assert!(
                t.value.iter().all(|&b| b == 0),
                "no selector → zero-filled request"
            );
        }
    }

    #[cfg(all(feature = "hwtstamp", target_os = "linux"))]
    #[test]
    fn apply_tx_corrections_updates_pending_t1() {
        use crate::hwtstamp::TxTimestampReport;

        let mut tx_map = std::collections::HashMap::new();
        tx_map.insert(0u32, 5u32); // OPT_ID 0 → seq 5, still pending
        tx_map.insert(1u32, 6u32); // OPT_ID 1 → seq 6, already answered

        let mut pending = std::collections::HashMap::new();
        pending.insert(
            5u32,
            PendingPacket {
                send_time: Instant::now(),
                send_timestamp: 111,
            },
        );

        let reports = [
            TxTimestampReport {
                opt_id: 0,
                timestamp: 999,
                hardware: false,
            },
            TxTimestampReport {
                opt_id: 1,
                timestamp: 888,
                hardware: false,
            },
            TxTimestampReport {
                opt_id: 7, // never mapped (e.g. counter desync) → ignored
                timestamp: 777,
                hardware: false,
            },
        ];
        let applied = apply_tx_corrections(&reports, &mut tx_map, &mut pending);
        assert_eq!(applied, 1, "only the still-pending packet is corrected");
        assert_eq!(
            pending[&5].send_timestamp, 999,
            "kernel T1 replaces the userspace T1 used for forward OWD"
        );
        assert!(
            !tx_map.contains_key(&0) && !tx_map.contains_key(&1),
            "matched ids are consumed"
        );
    }

    #[test]
    fn build_reflected_control_tlv_only_when_requested() {
        // Symmetric single-reply measurement, no one-way request → no TLV.
        assert!(build_reflected_control_tlv(0, 1, 1_000_000, false).is_none());

        // Multiple replies requested → TLV without sub-TLVs.
        let tlv = build_reflected_control_tlv(0, 4, 1_000_000, false).expect("TLV for count > 1");
        assert!(tlv.sub_tlvs.is_empty());
        assert_eq!(tlv.number_of_reflected_packets, 4);

        // Ext-hdr control requested → TLV emitted even at count 1, carrying the
        // presence-only IPv6 Extension Header Control sub-TLV
        // (draft-ietf-ippm-stamp-ext-hdr-11 §5.3; experimental type 240).
        let tlv = build_reflected_control_tlv(0, 1, 1_000_000, true).expect("TLV for one-way mode");
        assert_eq!(tlv.sub_tlvs, vec![0x00, 240, 0x00, 0x00]);
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn getsockopt_int(
        fd: std::os::fd::RawFd,
        level: nix::libc::c_int,
        name: nix::libc::c_int,
    ) -> nix::libc::c_int {
        use nix::libc;
        let mut val: libc::c_int = -1;
        let mut len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
        let rc = unsafe {
            libc::getsockopt(
                fd,
                level,
                name,
                &mut val as *mut _ as *mut libc::c_void,
                &mut len,
            )
        };
        assert_eq!(
            rc,
            0,
            "getsockopt(level={level}, name={name}) failed: {}",
            std::io::Error::last_os_error()
        );
        val
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn test_apply_egress_ip_options_sets_tos_and_ttl_v4() {
        use nix::libc;
        use std::os::fd::AsRawFd;

        let sock = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind v4");
        let fd = sock.as_raw_fd();

        // DSCP 46 (EF) / ECN 0 => 0xB8, hop limit 7.
        apply_egress_ip_options(fd, false, Some(0xB8), Some(7)).expect("apply v4 opts");

        assert_eq!(getsockopt_int(fd, libc::IPPROTO_IP, libc::IP_TOS), 0xB8);
        assert_eq!(getsockopt_int(fd, libc::IPPROTO_IP, libc::IP_TTL), 7);
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn test_apply_egress_ip_options_sets_tclass_and_hops_v6() {
        use nix::libc;
        use std::os::fd::AsRawFd;

        let sock = std::net::UdpSocket::bind("[::1]:0").expect("bind v6");
        let fd = sock.as_raw_fd();

        apply_egress_ip_options(fd, true, Some(0x20), Some(9)).expect("apply v6 opts");

        assert_eq!(
            getsockopt_int(fd, libc::IPPROTO_IPV6, libc::IPV6_TCLASS),
            0x20
        );
        assert_eq!(
            getsockopt_int(fd, libc::IPPROTO_IPV6, libc::IPV6_UNICAST_HOPS),
            9
        );
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn test_apply_egress_ip_options_none_is_noop() {
        use std::os::fd::AsRawFd;
        let sock = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind v4");
        // Passing no options must not error and must leave defaults untouched.
        apply_egress_ip_options(sock.as_raw_fd(), false, None, None).expect("noop");
    }

    #[test]
    fn test_parse_hex_pattern_basic() {
        assert_eq!(parse_hex_pattern("ff00").unwrap(), vec![0xFF, 0x00]);
        assert_eq!(parse_hex_pattern("0xFF00").unwrap(), vec![0xFF, 0x00]);
        assert_eq!(parse_hex_pattern("aa55").unwrap(), vec![0xAA, 0x55]);
    }

    #[test]
    fn test_parse_hex_pattern_rejects_odd_length() {
        assert!(parse_hex_pattern("fff").is_err());
    }

    #[test]
    fn test_parse_hex_pattern_rejects_non_hex() {
        assert!(parse_hex_pattern("zzzz").is_err());
    }

    #[test]
    fn test_parse_hex_pattern_rejects_empty() {
        assert!(parse_hex_pattern("").is_err());
        assert!(parse_hex_pattern("0x").is_err());
    }

    #[test]
    fn test_assemble_unauth_packet_defaults() {
        let packet = assemble_unauth_packet(0);
        assert_eq!(packet.sequence_number, 0);
        assert_eq!(packet.timestamp, 0);
        assert_eq!(packet.error_estimate, 0);
        assert_eq!(packet.ssid, 0);
        assert_eq!(packet.mbz, [0u8; 28]);
    }

    #[test]
    fn test_assemble_unauth_packet_with_error_estimate() {
        let error_estimate = 0x8A64; // S=1, Scale=10, Multiplier=100
        let packet = assemble_unauth_packet(error_estimate);
        assert_eq!(packet.error_estimate, error_estimate);
    }

    #[test]
    fn test_assemble_auth_packet_defaults() {
        let packet = assemble_auth_packet(0);
        assert_eq!(packet.sequence_number, 0);
        assert_eq!(packet.timestamp, 0);
        assert_eq!(packet.error_estimate, 0);
        assert_eq!(packet.ssid, 0);
        assert_eq!(packet.mbz0, [0u8; 12]);
        assert_eq!(packet.mbz1a, [0u8; 30]);
        assert_eq!(packet.mbz1b, [0u8; 32]);
        assert_eq!(packet.mbz1c, [0u8; 6]);
        assert_eq!(packet.hmac, [0u8; 16]);
    }

    #[test]
    fn test_assemble_auth_packet_with_error_estimate() {
        let error_estimate = 0x8A64;
        let packet = assemble_auth_packet(error_estimate);
        assert_eq!(packet.error_estimate, error_estimate);
    }

    #[test]
    fn test_finalize_auth_packet_sets_hmac() {
        use crate::crypto::HmacKey;

        let mut packet = assemble_auth_packet(0);
        packet.sequence_number = 42;
        packet.timestamp = 123456789;

        let key = HmacKey::new(vec![0xab; 32]).unwrap();
        finalize_auth_packet(&mut packet, &key);

        // HMAC should no longer be all zeros
        assert_ne!(packet.hmac, [0u8; 16]);
    }

    #[test]
    fn test_finalize_auth_packet_deterministic() {
        use crate::crypto::HmacKey;

        let key = HmacKey::new(vec![0xab; 32]).unwrap();

        let mut packet1 = assemble_auth_packet(100);
        packet1.sequence_number = 1;
        packet1.timestamp = 999;
        finalize_auth_packet(&mut packet1, &key);

        let mut packet2 = assemble_auth_packet(100);
        packet2.sequence_number = 1;
        packet2.timestamp = 999;
        finalize_auth_packet(&mut packet2, &key);

        assert_eq!(packet1.hmac, packet2.hmac);
    }

    // TLV building tests

    #[test]
    fn test_build_unauth_packet_with_tlvs_no_tlvs() {
        let packet = build_unauth_packet_with_tlvs(1, 1000, 100, None, &[], None);

        // Should be just base packet (44 bytes)
        assert_eq!(packet.len(), 44);
    }

    #[test]
    fn test_build_unauth_packet_with_ssid() {
        // RFC 8972 §3: SSID lives in the base packet header at bytes 14-15,
        // not as a TLV. Size stays at 44 when no other TLVs are present.
        let ssid: u16 = 12345;
        let packet = build_unauth_packet_with_tlvs(1, 1000, 100, Some(ssid), &[], None);

        assert_eq!(packet.len(), 44);
        assert_eq!(u16::from_be_bytes([packet[14], packet[15]]), ssid);
    }

    #[test]
    fn test_build_unauth_packet_with_extra_tlvs() {
        use crate::tlv::{TlvType, TLV_HEADER_SIZE};

        let extra_tlv = RawTlv::new(TlvType::Location, vec![1, 2, 3, 4]);
        let packet = build_unauth_packet_with_tlvs(1, 1000, 100, None, &[extra_tlv], None);

        // Base (44) + Location TLV (4 header + 4 value)
        assert_eq!(packet.len(), 44 + TLV_HEADER_SIZE + 4);

        // Check TLV type (byte 1 per RFC 8972)
        assert_eq!(packet[45], 2); // Location type
    }

    #[test]
    fn test_build_unauth_packet_with_tlv_hmac() {
        use crate::tlv::{HMAC_TLV_VALUE_SIZE, TLV_HEADER_SIZE};

        let key = HmacKey::new(vec![0xAB; 32]).unwrap();
        let packet = build_unauth_packet_with_tlvs(1, 1000, 100, Some(100), &[], Some(&key));

        // Base (44, SSID is in header) + HMAC TLV (4+16)
        assert_eq!(packet.len(), 44 + TLV_HEADER_SIZE + HMAC_TLV_VALUE_SIZE);

        // SSID echoed in base packet header at bytes 14-15
        assert_eq!(u16::from_be_bytes([packet[14], packet[15]]), 100);

        // HMAC TLV starts right after the base packet (type byte = 8 per RFC 8972)
        assert_eq!(packet[44 + 1], 8);
    }

    #[test]
    fn test_build_auth_packet_with_tlvs_no_tlvs() {
        let key = HmacKey::new(vec![0xAB; 32]).unwrap();
        let packet = build_auth_packet_with_tlvs(1, 1000, 100, &key, None, &[], None);

        // Should be just base packet (112 bytes)
        assert_eq!(packet.len(), 112);

        // Base HMAC should be set
        assert_ne!(&packet[96..112], &[0u8; 16]);
    }

    #[test]
    fn test_build_auth_packet_with_ssid() {
        // RFC 8972 §3: SSID lives at bytes 26-27 of the auth packet header, not as a TLV.
        let key = HmacKey::new(vec![0xAB; 32]).unwrap();
        let packet = build_auth_packet_with_tlvs(1, 1000, 100, &key, Some(54321), &[], None);

        assert_eq!(packet.len(), 112);
        assert_eq!(u16::from_be_bytes([packet[26], packet[27]]), 54321);
    }

    #[test]
    fn test_build_auth_packet_with_tlv_hmac() {
        use crate::tlv::{HMAC_TLV_VALUE_SIZE, TLV_HEADER_SIZE};

        let key = HmacKey::new(vec![0xAB; 32]).unwrap();
        let packet = build_auth_packet_with_tlvs(1, 1000, 100, &key, Some(100), &[], Some(&key));

        // Base (112, SSID in header) + HMAC TLV (4+16)
        assert_eq!(packet.len(), 112 + TLV_HEADER_SIZE + HMAC_TLV_VALUE_SIZE);
        assert_eq!(u16::from_be_bytes([packet[26], packet[27]]), 100);
    }

    #[test]
    fn test_create_extended_unauth_packet() {
        let ext = create_extended_unauth_packet(1, 1000, 100, None);

        assert_eq!(ext.base.sequence_number, 1);
        assert!(!ext.has_tlvs());
    }

    #[test]
    fn test_create_extended_unauth_packet_with_ssid() {
        // SSID lives in the base header per RFC 8972 §3; no TLV is injected.
        let ext = create_extended_unauth_packet(1, 1000, 100, Some(9999));

        assert_eq!(ext.base.sequence_number, 1);
        assert_eq!(ext.base.ssid, 9999);
        assert!(!ext.has_tlvs());
    }

    #[test]
    fn test_create_extended_auth_packet() {
        let key = HmacKey::new(vec![0xCD; 32]).unwrap();
        let ext = create_extended_auth_packet(1, 1000, 100, &key, None);

        assert_eq!(ext.base.sequence_number, 1);
        assert!(!ext.has_tlvs());
        // Base HMAC should be computed
        assert_ne!(ext.base.hmac, [0u8; 16]);
    }

    #[test]
    fn test_create_extended_auth_packet_with_ssid() {
        // SSID lives in the base header per RFC 8972 §3; no TLV is injected.
        let key = HmacKey::new(vec![0xCD; 32]).unwrap();
        let ext = create_extended_auth_packet(1, 1000, 100, &key, Some(8888));

        assert_eq!(ext.base.ssid, 8888);
        assert!(!ext.has_tlvs());
    }

    #[test]
    fn test_validate_reflected_tlvs_msid_match_accepts() {
        // RFC 9534 §3.2: reflected MSID TLV must carry the sender's sender_id
        // unchanged; the reflector fills reflector_micro_session_id.
        // Model a properly-reflected TLV: a conforming reflector clears the
        // U/M/I flags on a recognized, well-formed TLV (the typed constructor
        // sets the sender-side U flag, which does not appear on the wire in a
        // reflected packet).
        let mut raw = MicroSessionIdTlv::new(7777, 42).to_raw();
        raw.clear_reflector_flags();
        let mut tlvs = TlvList::new();
        tlvs.push(raw).unwrap();

        let status = validate_reflected_tlvs(
            &tlvs,
            &[0u8; 44],
            44,
            None,
            Some(7777),
            None,
            &mut None,
            false, // track_access_report
            false, // track_congestion
            #[cfg(feature = "metrics")]
            false,
        )
        .expect("matching MSID must return Ok")
        .expect("status produced");

        assert!(status.contains("MSID:ok"), "got: {}", status);
    }

    #[test]
    fn test_validate_reflected_tlvs_msid_mismatch_rejects() {
        // RFC 9534 §3.2: a mismatched sender_micro_session_id means the
        // response cannot be attributed to this session. The validator must
        // return Err so the caller drops the packet without recording RTT.
        let mut raw = MicroSessionIdTlv::new(0xBAD, 42).to_raw();
        raw.clear_reflector_flags(); // properly-reflected TLV: no U/M/I flags
        let mut tlvs = TlvList::new();
        tlvs.push(raw).unwrap();

        let err = validate_reflected_tlvs(
            &tlvs,
            &[0u8; 44],
            44,
            None,
            Some(7777),
            None,
            &mut None,
            false, // track_access_report
            false, // track_congestion
            #[cfg(feature = "metrics")]
            false,
        )
        .expect_err("mismatched MSID must reject");

        assert_eq!(
            err,
            TlvRejection::MsidMismatch {
                got: 0xBAD,
                expected: 7777
            }
        );
    }

    #[test]
    fn test_validate_reflected_tlvs_msid_malformed_rejects() {
        // A malformed MSID TLV cannot be parsed, so session binding can't be
        // verified; we must drop the response rather than guess.
        let mut tlvs = TlvList::new();
        // MSID TLV value must be exactly 4 bytes (RFC 9534 §3.1). 3 bytes
        // makes it unparseable but keeps the TLV present for the scanner.
        // Flags cleared: this models a non-conforming reflector that echoed a
        // wrong-length MSID WITHOUT setting the M flag — so the value is still
        // reached (an M-flagged TLV would instead halt processing per §4-18).
        let mut raw = crate::tlv::RawTlv::new(crate::tlv::TlvType::MicroSessionId, vec![0, 0, 0]);
        raw.clear_reflector_flags();
        tlvs.push(raw).unwrap();

        let err = validate_reflected_tlvs(
            &tlvs,
            &[0u8; 44],
            44,
            None,
            Some(1234),
            None,
            &mut None,
            false, // track_access_report
            false, // track_congestion
            #[cfg(feature = "metrics")]
            false,
        )
        .expect_err("malformed MSID must reject");

        assert_eq!(err, TlvRejection::MsidMalformed);
    }

    #[test]
    fn test_validate_reflected_tlvs_msid_not_requested() {
        // Sender did not request MSID measurement; even if a stray MSID TLV
        // arrives we should not synthesize a validation result.
        let mut tlvs = TlvList::new();
        tlvs.push(MicroSessionIdTlv::new(1, 2).to_raw()).unwrap();

        let status = validate_reflected_tlvs(
            &tlvs,
            &[0u8; 44],
            44,
            None,
            None,
            None,
            &mut None,
            false, // track_access_report
            false, // track_congestion
            #[cfg(feature = "metrics")]
            false,
        )
        .expect("no MSID binding requested → accept")
        .expect("status produced");

        assert!(!status.contains("MSID"));
    }

    #[test]
    fn test_micro_session_request_tlv_populates_reflector_id() {
        // RFC 9534 §3.2-3: "If the Session-Sender knows the Reflector member
        // link identifier, the Reflector Micro-session ID field MUST be set."
        let tlv = micro_session_request_tlv(0x1234, Some(0xABCD));
        let parsed = MicroSessionIdTlv::from_raw(&tlv).unwrap();
        assert_eq!(parsed.sender_micro_session_id, 0x1234);
        assert_eq!(parsed.reflector_micro_session_id, 0xABCD);
    }

    #[test]
    fn test_micro_session_request_tlv_reflector_id_absent_is_zero() {
        // RFC 9534 §3.2-4: otherwise the field is left zero.
        let tlv = micro_session_request_tlv(0x1234, None);
        let parsed = MicroSessionIdTlv::from_raw(&tlv).unwrap();
        assert_eq!(parsed.sender_micro_session_id, 0x1234);
        assert_eq!(parsed.reflector_micro_session_id, 0);
    }

    #[test]
    fn test_reflected_reflector_msid_mismatch_rejects() {
        // RFC 9534 §3.2-11/-12: when the reflector member-link ID is pre-known,
        // a reflected Reflector Micro-session ID that differs from it must be
        // discarded (validating the reflector's behaviour).
        let mut raw = MicroSessionIdTlv::new(7777, 0x11).to_raw();
        raw.clear_reflector_flags();
        let mut tlvs = TlvList::new();
        tlvs.push(raw).unwrap();

        let mut latched = None;
        let err = validate_reflected_tlvs(
            &tlvs,
            &[0u8; 44],
            44,
            None,
            Some(7777),
            Some(0x22), // pre-known reflector id, but reflected 0x11 ≠ 0x22
            &mut latched,
            false, // track_access_report
            false, // track_congestion
            #[cfg(feature = "metrics")]
            false,
        )
        .expect_err("reflector MSID mismatch must reject");

        assert_eq!(
            err,
            TlvRejection::ReflectorMsidMismatch {
                got: 0x11,
                expected: 0x22
            }
        );
        // Pre-known configuration takes precedence and must never be
        // superseded by a first-seen value: the zero-config latch stays
        // untouched (RFC 9534 §3.2-11/-12).
        assert_eq!(
            latched, None,
            "pre-known reflector ID must not populate the zero-config latch"
        );
    }

    #[test]
    fn test_reflected_reflector_msid_match_accepts() {
        let mut raw = MicroSessionIdTlv::new(7777, 0x22).to_raw();
        raw.clear_reflector_flags();
        let mut tlvs = TlvList::new();
        tlvs.push(raw).unwrap();

        let mut latched = None;
        let status = validate_reflected_tlvs(
            &tlvs,
            &[0u8; 44],
            44,
            None,
            Some(7777),
            Some(0x22),
            &mut latched,
            false, // track_access_report
            false, // track_congestion
            #[cfg(feature = "metrics")]
            false,
        )
        .expect("reflector MSID match must accept")
        .expect("status produced");
        assert!(status.contains("MSID:ok(reflector=34)"), "got: {}", status);
        // Pre-known configuration takes precedence and must never be
        // superseded by a first-seen value: the zero-config latch stays
        // untouched (RFC 9534 §3.2-11/-12).
        assert_eq!(
            latched, None,
            "pre-known reflector ID must not populate the zero-config latch"
        );
    }

    #[test]
    fn test_reflected_reflector_msid_zero_config_latches_first_seen() {
        // RFC 9534 §3.2-11 (unconditional validation, zero-config path):
        // with no pre-known reflector member-link ID, the first
        // validly-received reply's Reflector Micro-session ID becomes the
        // expected value for the rest of the session. A second reply
        // echoing the same reflector ID must still be accepted.
        let mut latched: Option<u16> = None;

        let mut raw1 = MicroSessionIdTlv::new(7777, 0x22).to_raw();
        raw1.clear_reflector_flags();
        let mut tlvs1 = TlvList::new();
        tlvs1.push(raw1).unwrap();
        let status1 = validate_reflected_tlvs(
            &tlvs1,
            &[0u8; 44],
            44,
            None,
            Some(7777),
            None, // no pre-known reflector ID
            &mut latched,
            false, // track_access_report
            false, // track_congestion
            #[cfg(feature = "metrics")]
            false,
        )
        .expect("first reply must be accepted")
        .expect("status produced");
        assert!(status1.contains("MSID:ok"), "got: {}", status1);
        assert_eq!(
            latched,
            Some(0x22),
            "first-seen reflector ID must be latched"
        );

        let mut raw2 = MicroSessionIdTlv::new(7777, 0x22).to_raw();
        raw2.clear_reflector_flags();
        let mut tlvs2 = TlvList::new();
        tlvs2.push(raw2).unwrap();
        let status2 = validate_reflected_tlvs(
            &tlvs2,
            &[0u8; 44],
            44,
            None,
            Some(7777),
            None,
            &mut latched,
            false, // track_access_report
            false, // track_congestion
            #[cfg(feature = "metrics")]
            false,
        )
        .expect("second reply with the same reflector ID must also be accepted")
        .expect("status produced");
        assert!(status2.contains("MSID:ok"), "got: {}", status2);
        assert_eq!(latched, Some(0x22), "latch must remain unchanged");
    }

    #[test]
    fn test_reflected_reflector_msid_zero_config_rejects_change_after_latch() {
        // RFC 9534 §3.2-11 (zero-config path): once the first reply has
        // latched a Reflector Micro-session ID, a later reply echoing a
        // different reflector ID must be discarded exactly like the
        // pre-known mismatch path (reuses `ReflectorMsidMismatch`).
        let mut latched: Option<u16> = None;

        let mut raw1 = MicroSessionIdTlv::new(7777, 0x22).to_raw();
        raw1.clear_reflector_flags();
        let mut tlvs1 = TlvList::new();
        tlvs1.push(raw1).unwrap();
        validate_reflected_tlvs(
            &tlvs1,
            &[0u8; 44],
            44,
            None,
            Some(7777),
            None,
            &mut latched,
            false, // track_access_report
            false, // track_congestion
            #[cfg(feature = "metrics")]
            false,
        )
        .expect("first reply must be accepted and latch the reflector ID");
        assert_eq!(latched, Some(0x22));

        let mut raw2 = MicroSessionIdTlv::new(7777, 0x33).to_raw();
        raw2.clear_reflector_flags();
        let mut tlvs2 = TlvList::new();
        tlvs2.push(raw2).unwrap();
        let err = validate_reflected_tlvs(
            &tlvs2,
            &[0u8; 44],
            44,
            None,
            Some(7777),
            None,
            &mut latched,
            false, // track_access_report
            false, // track_congestion
            #[cfg(feature = "metrics")]
            false,
        )
        .expect_err("a changed reflector ID after latching must be rejected");

        assert_eq!(
            err,
            TlvRejection::ReflectorMsidMismatch {
                got: 0x33,
                expected: 0x22
            }
        );
    }

    #[test]
    fn test_forged_first_reply_does_not_latch_reflector_msid() {
        // RFC 9534 §3.2-11 zero-config path, adversarial first reply: the
        // latch must only ever record a value from a reply that passed the
        // integrity gate. An I-flagged (or otherwise untrusted) FIRST reply
        // must leave the latch empty, so a forged reflector ID cannot become
        // the session's expected value and lock out the real reflector.
        let mut latched: Option<u16> = None;

        let mut forged = MicroSessionIdTlv::new(7777, 0xDEAD).to_raw();
        forged.set_integrity_failed();
        let mut tlvs = TlvList::new();
        tlvs.push(forged).unwrap();

        validate_reflected_tlvs(
            &tlvs,
            &[0u8; 44],
            44,
            None,
            Some(7777),
            None, // no pre-known reflector ID → zero-config latch path
            &mut latched,
            false, // track_access_report
            false, // track_congestion
            #[cfg(feature = "metrics")]
            false,
        )
        .expect("I-flagged reply must not be consumed → accept, not reject");

        assert_eq!(
            latched, None,
            "an untrusted first reply must not latch a Reflector Micro-session ID"
        );

        // The next legitimate reply is then free to latch its own value.
        let mut clean = MicroSessionIdTlv::new(7777, 0x22).to_raw();
        clean.clear_reflector_flags();
        let mut tlvs2 = TlvList::new();
        tlvs2.push(clean).unwrap();

        validate_reflected_tlvs(
            &tlvs2,
            &[0u8; 44],
            44,
            None,
            Some(7777),
            None,
            &mut latched,
            false,
            false,
            #[cfg(feature = "metrics")]
            false,
        )
        .expect("a valid reply after a forged one must be accepted");

        assert_eq!(
            latched,
            Some(0x22),
            "the first *trusted* reply must be the one that latches"
        );
    }

    #[test]
    fn test_forged_msid_with_i_flag_not_consumed() {
        // RFC 8972 §4-19 / §4.8-16: "If the I flag is set, the STAMP system
        // MUST discard all TLVs and MUST stop processing." A reflector (or an
        // on-path attacker) that returns an I-flagged MSID TLV with a forged
        // sender_micro_session_id MUST NOT have that value trusted for session
        // binding — validation must not reject on the forged mismatch.
        let mut raw = MicroSessionIdTlv::new(0xBAD, 42).to_raw();
        raw.set_integrity_failed();
        let mut tlvs = TlvList::new();
        tlvs.push(raw).unwrap();

        let status = validate_reflected_tlvs(
            &tlvs,
            &[0u8; 44],
            44,
            None,
            Some(7777),
            None,
            &mut None,
            false, // track_access_report
            false, // track_congestion
            #[cfg(feature = "metrics")]
            false,
        )
        .expect("I-flagged forged MSID must not be consumed → accept");

        let status = status.expect("status produced");
        assert!(
            !status.contains("MSID:ok"),
            "forged MSID value must not be consumed: {}",
            status
        );
        assert!(status.contains("1I"), "I-flag must be reported: {}", status);
    }

    #[test]
    fn test_forged_msid_with_m_flag_not_consumed() {
        // RFC 8972 §4-18: "If the M flag is set, the STAMP system MUST stop
        // processing the remainder of the extended STAMP packet." An M-flagged
        // MSID TLV's value MUST NOT be consumed for session binding.
        let mut raw = MicroSessionIdTlv::new(0xBAD, 42).to_raw();
        raw.set_malformed();
        let mut tlvs = TlvList::new();
        tlvs.push(raw).unwrap();

        let status = validate_reflected_tlvs(
            &tlvs,
            &[0u8; 44],
            44,
            None,
            Some(7777),
            None,
            &mut None,
            false, // track_access_report
            false, // track_congestion
            #[cfg(feature = "metrics")]
            false,
        )
        .expect("M-flagged forged MSID must not be consumed → accept");

        let status = status.expect("status produced");
        assert!(
            !status.contains("MSID:ok"),
            "forged MSID value must not be consumed: {}",
            status
        );
        assert!(status.contains("1M"), "M-flag must be reported: {}", status);
    }

    #[test]
    fn test_forged_msid_ignored_when_tlv_hmac_fails() {
        // RFC 8972 §4.8-17: "If HMAC verification by the Session-Sender fails,
        // then the Session-Sender MUST stop processing TLVs." The forged MSID
        // value MUST NOT reach the session-binding check when the TLV-HMAC
        // cannot be verified.
        let key = HmacKey::new(vec![0xAB; 32]).unwrap();
        let mut tlvs = TlvList::new();
        tlvs.push(MicroSessionIdTlv::new(0xBAD, 42).to_raw())
            .unwrap();
        // A bogus HMAC TLV value that will never verify against the data.
        tlvs.push(crate::tlv::RawTlv::new(
            crate::tlv::TlvType::Hmac,
            vec![0u8; 16],
        ))
        .unwrap();

        // Data long enough for the HMAC coverage slice (seq + TLV area).
        let data = [0u8; 128];
        let status = validate_reflected_tlvs(
            &tlvs,
            &data,
            44,
            Some(&key),
            Some(7777),
            None,
            &mut None,
            false, // track_access_report
            false, // track_congestion
            #[cfg(feature = "metrics")]
            false,
        )
        .expect("TLV-HMAC failure must stop TLV processing → accept, not reject");

        let status = status.expect("status produced");
        assert!(status.contains("HMAC:fail"), "got: {}", status);
        assert!(
            !status.contains("MSID:ok"),
            "forged MSID must be ignored on HMAC failure: {}",
            status
        );
    }

    // --- validate_reflected_tlvs: Access Report ack detection (§4.6) ------

    #[test]
    fn test_validate_reflected_tlvs_detects_access_report_ack() {
        let mut raw = AccessReportTlv::new(1, 1).to_raw();
        raw.clear_reflector_flags(); // properly-reflected TLV: no U/M/I flags
        let mut tlvs = TlvList::new();
        tlvs.push(raw).unwrap();

        let status = validate_reflected_tlvs(
            &tlvs,
            &[0u8; 44],
            44,
            None,
            None,
            None,
            &mut None,
            true,  // track_access_report
            false, // track_congestion
            #[cfg(feature = "metrics")]
            false,
        )
        .expect("clean Access Report TLV must return Ok")
        .expect("status produced");

        assert!(status.contains("AccessReport:ack"), "got: {}", status);
    }

    #[test]
    fn test_validate_reflected_tlvs_ignores_access_report_when_not_tracking() {
        // Backward compatibility: when the sender never requested tracking
        // (e.g. `--access-report` was not set), the presence of an Access
        // Report TLV must not spuriously affect the status string.
        let mut raw = AccessReportTlv::new(1, 1).to_raw();
        raw.clear_reflector_flags();
        let mut tlvs = TlvList::new();
        tlvs.push(raw).unwrap();

        let status = validate_reflected_tlvs(
            &tlvs,
            &[0u8; 44],
            44,
            None,
            None,
            None,
            &mut None,
            false, // track_access_report
            false, // track_congestion
            #[cfg(feature = "metrics")]
            false,
        )
        .expect("Ok regardless of tracking")
        .expect("status produced");

        assert!(!status.contains("AccessReport"), "got: {}", status);
    }

    #[test]
    fn test_validate_reflected_tlvs_access_report_u_flagged_not_acked() {
        // RFC 8972 §4-17: a U-flagged TLV must be skipped — an unrecognized
        // echo cannot be trusted as the RFC 8972 §4.6 acknowledgment.
        let mut raw = AccessReportTlv::new(1, 1).to_raw();
        raw.set_unrecognized();
        let mut tlvs = TlvList::new();
        tlvs.push(raw).unwrap();

        let status = validate_reflected_tlvs(
            &tlvs,
            &[0u8; 44],
            44,
            None,
            None,
            None,
            &mut None,
            true,
            false, // track_congestion
            #[cfg(feature = "metrics")]
            false,
        )
        .expect("Ok even though unrecognized")
        .expect("status produced");

        assert!(
            !status.contains("AccessReport:ack"),
            "U-flagged TLV must not count as an ack: {}",
            status
        );
        assert!(status.contains("1U"), "got: {}", status);
    }

    #[test]
    fn test_validate_reflected_tlvs_access_report_i_flagged_not_acked() {
        // RFC 8972 §4-19: an I-flagged TLV means integrity failed —
        // §4.6's ack semantics require an intact echo, so no ack.
        let mut raw = AccessReportTlv::new(1, 1).to_raw();
        raw.set_integrity_failed();
        let mut tlvs = TlvList::new();
        tlvs.push(raw).unwrap();

        let status = validate_reflected_tlvs(
            &tlvs,
            &[0u8; 44],
            44,
            None,
            None,
            None,
            &mut None,
            true,
            false, // track_congestion
            #[cfg(feature = "metrics")]
            false,
        )
        .expect("Ok even though integrity-failed")
        .expect("status produced");

        assert!(
            !status.contains("AccessReport:ack"),
            "I-flagged TLV must not count as an ack: {}",
            status
        );
        assert!(status.contains("1I"), "got: {}", status);
    }

    #[test]
    fn test_validate_reflected_tlvs_access_report_m_flagged_halts_scan() {
        // RFC 8972 §4-18: an M-flagged TLV halts processing of the
        // *remainder* of the packet — an Access Report TLV that comes after
        // it in wire order must not be reached, hence not acked.
        let mut bad = crate::tlv::RawTlv::new(crate::tlv::TlvType::MicroSessionId, vec![0, 0, 0]);
        bad.set_malformed();
        let mut good = AccessReportTlv::new(1, 1).to_raw();
        good.clear_reflector_flags();

        let mut tlvs = TlvList::new();
        tlvs.push(bad).unwrap();
        tlvs.push(good).unwrap();

        let status = validate_reflected_tlvs(
            &tlvs,
            &[0u8; 44],
            44,
            None,
            None,
            None,
            &mut None,
            true,
            false, // track_congestion
            #[cfg(feature = "metrics")]
            false,
        )
        .expect("Ok — M just halts the scan, doesn't reject")
        .expect("status produced");

        assert!(
            !status.contains("AccessReport:ack"),
            "M-flag must halt the scan before the later Access Report TLV: {}",
            status
        );
    }

    #[test]
    fn test_validate_reflected_tlvs_access_report_ack_survives_alongside_msid() {
        // Both features active at once: MSID success must not short-circuit
        // (via an early `break`) before the Access Report TLV later in the
        // list gets scanned.
        let mut msid = MicroSessionIdTlv::new(7777, 42).to_raw();
        msid.clear_reflector_flags();
        let mut ar = AccessReportTlv::new(1, 1).to_raw();
        ar.clear_reflector_flags();

        let mut tlvs = TlvList::new();
        tlvs.push(msid).unwrap();
        tlvs.push(ar).unwrap();

        let status = validate_reflected_tlvs(
            &tlvs,
            &[0u8; 44],
            44,
            None,
            Some(7777),
            None,
            &mut None,
            true,
            false, // track_congestion
            #[cfg(feature = "metrics")]
            false,
        )
        .expect("Ok")
        .expect("status produced");

        assert!(status.contains("MSID:ok"), "got: {}", status);
        assert!(status.contains("AccessReport:ack"), "got: {}", status);
    }

    // --- validate_reflected_tlvs: CoS EC2 CE detection
    // (draft-ietf-ippm-stamp-cos-ecn-01 §3.4) ------------------------------

    #[test]
    fn test_validate_reflected_tlvs_detects_cos_ce() {
        let mut raw = ClassOfServiceTlv {
            dscp1: 0,
            ecn1: 1,
            dscp2: 0,
            ecn2: 0b11, // CE
            rpd: 0,
            rpe: 0b11,
        }
        .to_raw();
        raw.clear_reflector_flags(); // properly-reflected TLV: no U/M/I flags
        let mut tlvs = TlvList::new();
        tlvs.push(raw).unwrap();

        let status = validate_reflected_tlvs(
            &tlvs,
            &[0u8; 44],
            44,
            None,
            None,
            None,
            &mut None,
            false, // track_access_report
            true,  // track_congestion
            #[cfg(feature = "metrics")]
            false,
        )
        .expect("clean CE-marked CoS TLV must return Ok")
        .expect("status produced");

        assert!(status.contains("CoS:CE"), "got: {}", status);
    }

    #[test]
    fn test_validate_reflected_tlvs_ignores_cos_ce_when_not_tracking() {
        // Backward compatibility: when the congestion controller is
        // inactive (e.g. `--cos`/`--ecn` were not requesting ECT0/ECT1),
        // a CE-marked EC2 field must not spuriously affect the status
        // string.
        let mut raw = ClassOfServiceTlv {
            dscp1: 0,
            ecn1: 1,
            dscp2: 0,
            ecn2: 0b11,
            rpd: 0,
            rpe: 0b11,
        }
        .to_raw();
        raw.clear_reflector_flags();
        let mut tlvs = TlvList::new();
        tlvs.push(raw).unwrap();

        let status = validate_reflected_tlvs(
            &tlvs,
            &[0u8; 44],
            44,
            None,
            None,
            None,
            &mut None,
            false, // track_access_report
            false, // track_congestion
            #[cfg(feature = "metrics")]
            false,
        )
        .expect("Ok regardless of tracking")
        .expect("status produced");

        assert!(!status.contains("CoS:CE"), "got: {}", status);
    }

    #[test]
    fn test_validate_reflected_tlvs_cos_non_ce_ecn2_not_flagged() {
        // ECT0 (0b10) is not congestion — must not be reported as CE.
        let mut raw = ClassOfServiceTlv {
            dscp1: 0,
            ecn1: 1,
            dscp2: 0,
            ecn2: 0b10,
            rpd: 0,
            rpe: 0b11,
        }
        .to_raw();
        raw.clear_reflector_flags();
        let mut tlvs = TlvList::new();
        tlvs.push(raw).unwrap();

        let status = validate_reflected_tlvs(
            &tlvs,
            &[0u8; 44],
            44,
            None,
            None,
            None,
            &mut None,
            false, // track_access_report
            true,  // track_congestion
            #[cfg(feature = "metrics")]
            false,
        )
        .expect("Ok")
        .expect("status produced");

        assert!(!status.contains("CoS:CE"), "got: {}", status);
    }

    #[test]
    fn test_validate_reflected_tlvs_cos_ce_u_flagged_not_reported() {
        // RFC 8972 §4-17: a U-flagged TLV must be skipped — an unrecognized
        // echo cannot be trusted as a congestion signal.
        let mut raw = ClassOfServiceTlv {
            dscp1: 0,
            ecn1: 1,
            dscp2: 0,
            ecn2: 0b11,
            rpd: 0,
            rpe: 0b11,
        }
        .to_raw();
        raw.set_unrecognized();
        let mut tlvs = TlvList::new();
        tlvs.push(raw).unwrap();

        let status = validate_reflected_tlvs(
            &tlvs,
            &[0u8; 44],
            44,
            None,
            None,
            None,
            &mut None,
            false, // track_access_report
            true,  // track_congestion
            #[cfg(feature = "metrics")]
            false,
        )
        .expect("Ok even though unrecognized")
        .expect("status produced");

        assert!(
            !status.contains("CoS:CE"),
            "U-flagged TLV must not count as a CE signal: {}",
            status
        );
    }

    #[test]
    fn test_validate_reflected_tlvs_cos_ce_i_flagged_not_reported() {
        // RFC 8972 §4-19: an I-flagged TLV means integrity failed — the
        // controller must not be able to be forced into a spurious backoff
        // by an unverifiable echo.
        let mut raw = ClassOfServiceTlv {
            dscp1: 0,
            ecn1: 1,
            dscp2: 0,
            ecn2: 0b11,
            rpd: 0,
            rpe: 0b11,
        }
        .to_raw();
        raw.set_integrity_failed();
        let mut tlvs = TlvList::new();
        tlvs.push(raw).unwrap();

        let status = validate_reflected_tlvs(
            &tlvs,
            &[0u8; 44],
            44,
            None,
            None,
            None,
            &mut None,
            false, // track_access_report
            true,  // track_congestion
            #[cfg(feature = "metrics")]
            false,
        )
        .expect("Ok even though integrity-failed")
        .expect("status produced");

        assert!(
            !status.contains("CoS:CE"),
            "I-flagged TLV must not count as a CE signal: {}",
            status
        );
    }

    #[test]
    fn test_validate_reflected_tlvs_cos_ce_m_flagged_before_it_halts_scan() {
        // RFC 8972 §4-18: an M-flagged TLV halts processing of the
        // *remainder* of the packet — a CE-marked CoS TLV that comes after
        // it in wire order must not be reached.
        let mut bad = crate::tlv::RawTlv::new(crate::tlv::TlvType::MicroSessionId, vec![0, 0, 0]);
        bad.set_malformed();
        let mut good = ClassOfServiceTlv {
            dscp1: 0,
            ecn1: 1,
            dscp2: 0,
            ecn2: 0b11,
            rpd: 0,
            rpe: 0b11,
        }
        .to_raw();
        good.clear_reflector_flags();

        let mut tlvs = TlvList::new();
        tlvs.push(bad).unwrap();
        tlvs.push(good).unwrap();

        let status = validate_reflected_tlvs(
            &tlvs,
            &[0u8; 44],
            44,
            None,
            None,
            None,
            &mut None,
            false, // track_access_report
            true,  // track_congestion
            #[cfg(feature = "metrics")]
            false,
        )
        .expect("Ok — M just halts the scan, doesn't reject")
        .expect("status produced");

        assert!(
            !status.contains("CoS:CE"),
            "M-flag must halt the scan before the later CoS TLV: {}",
            status
        );
    }

    #[test]
    fn test_validate_reflected_tlvs_cos_ce_suppressed_by_tlv_hmac_failure() {
        // RFC 8972 §4.8-17: "If HMAC verification by the Session-Sender
        // fails, then the Session-Sender MUST stop processing TLVs." A
        // forged/tampered CE signal MUST NOT reach the congestion
        // controller when the TLV-HMAC cannot be verified — otherwise an
        // on-path attacker who cannot forge the HMAC could still force the
        // sender into a permanent backoff via a bare CoS TLV injection.
        let key = HmacKey::new(vec![0xAB; 32]).unwrap();
        let mut tlvs = TlvList::new();
        let mut cos = ClassOfServiceTlv {
            dscp1: 0,
            ecn1: 1,
            dscp2: 0,
            ecn2: 0b11,
            rpd: 0,
            rpe: 0b11,
        }
        .to_raw();
        cos.clear_reflector_flags();
        tlvs.push(cos).unwrap();
        // A bogus HMAC TLV value that will never verify against the data.
        tlvs.push(crate::tlv::RawTlv::new(
            crate::tlv::TlvType::Hmac,
            vec![0u8; 16],
        ))
        .unwrap();

        let data = [0u8; 128];
        let status = validate_reflected_tlvs(
            &tlvs,
            &data,
            44,
            Some(&key),
            None,
            None,
            &mut None,
            false, // track_access_report
            true,  // track_congestion
            #[cfg(feature = "metrics")]
            false,
        )
        .expect("TLV-HMAC failure must stop TLV processing → accept, not reject")
        .expect("status produced");

        assert!(status.contains("HMAC:fail"), "got: {}", status);
        assert!(
            !status.contains("CoS:CE"),
            "forged CE signal must be ignored on HMAC failure: {}",
            status
        );
    }

    // --- process_response: Access Report acknowledgment wiring (§4.6) -----

    #[test]
    fn test_process_response_acknowledges_access_report_state() {
        use crate::packets::{
            ExtendedReflectedPacketUnauthenticated, ReflectedPacketUnauthenticated,
        };

        let reflected = ReflectedPacketUnauthenticated {
            sequence_number: 1,
            timestamp: 0,
            error_estimate: 0,
            ssid: 0,
            receive_timestamp: 0,
            sess_sender_seq_number: 1,
            sess_sender_timestamp: 0,
            sess_sender_err_estimate: 0,
            sess_sender_ssid: 0,
            sess_sender_ttl: 0,
            mbz3: [0; 3],
        };
        let mut tlvs = TlvList::new();
        let mut ar = AccessReportTlv::new(1, 1).to_raw();
        ar.clear_reflector_flags();
        tlvs.push(ar).unwrap();
        let ext = ExtendedReflectedPacketUnauthenticated::with_tlvs(reflected, tlvs);
        let buf = ext.to_bytes();

        let mut pending = HashMap::new();
        pending.insert(
            1,
            PendingPacket {
                send_time: Instant::now(),
                send_timestamp: 0,
            },
        );
        let mut rtt_collector = RttCollector::new();
        let mut owd_collector = OwdCollector::new();
        let mut packets_received = 0u32;
        let mut latched_reflector_msid = None;
        let mut access_report_state = AccessReportRetransmitState::new(Duration::from_secs(3), 4);
        access_report_state.tick(Instant::now()); // simulate the original send having armed it
        let mut ctx = SenderRecvContext {
            pending: &mut pending,
            rtt_collector: &mut rtt_collector,
            owd_collector: &mut owd_collector,
            packets_received: &mut packets_received,
            print_stats: false,
            hmac_key: None,
            expected_sender_msid: None,
            expected_reflector_msid: None,
            latched_reflector_msid: &mut latched_reflector_msid,
            access_report_state: Some(&mut access_report_state),
            congestion: None,
            expected_ssid: None,
            on_zero_ssid: ZeroSsidAction::Continue,
            zero_ssid_seen: &mut false,
            #[cfg(feature = "metrics")]
            metrics_enabled: false,
            #[cfg(all(unix, feature = "snmp"))]
            snmp_stats: None,
        };

        process_response(&buf, false, true, ClockFormat::NTP, None, None, &mut ctx);

        assert_eq!(
            access_report_state.outcome(),
            AccessReportOutcome::Acknowledged
        );
    }

    #[test]
    fn test_process_response_does_not_acknowledge_without_access_report_tlv() {
        use crate::packets::{
            ExtendedReflectedPacketUnauthenticated, ReflectedPacketUnauthenticated,
        };

        // A reply with no TLVs at all must leave the timer armed.
        let reflected = ReflectedPacketUnauthenticated {
            sequence_number: 1,
            timestamp: 0,
            error_estimate: 0,
            ssid: 0,
            receive_timestamp: 0,
            sess_sender_seq_number: 1,
            sess_sender_timestamp: 0,
            sess_sender_err_estimate: 0,
            sess_sender_ssid: 0,
            sess_sender_ttl: 0,
            mbz3: [0; 3],
        };
        let ext = ExtendedReflectedPacketUnauthenticated::with_tlvs(reflected, TlvList::new());
        let buf = ext.to_bytes();

        let mut pending = HashMap::new();
        pending.insert(
            1,
            PendingPacket {
                send_time: Instant::now(),
                send_timestamp: 0,
            },
        );
        let mut rtt_collector = RttCollector::new();
        let mut owd_collector = OwdCollector::new();
        let mut packets_received = 0u32;
        let mut latched_reflector_msid = None;
        let mut access_report_state = AccessReportRetransmitState::new(Duration::from_secs(3), 4);
        access_report_state.tick(Instant::now());
        let mut ctx = SenderRecvContext {
            pending: &mut pending,
            rtt_collector: &mut rtt_collector,
            owd_collector: &mut owd_collector,
            packets_received: &mut packets_received,
            print_stats: false,
            hmac_key: None,
            expected_sender_msid: None,
            expected_reflector_msid: None,
            latched_reflector_msid: &mut latched_reflector_msid,
            access_report_state: Some(&mut access_report_state),
            congestion: None,
            expected_ssid: None,
            on_zero_ssid: ZeroSsidAction::Continue,
            zero_ssid_seen: &mut false,
            #[cfg(feature = "metrics")]
            metrics_enabled: false,
            #[cfg(all(unix, feature = "snmp"))]
            snmp_stats: None,
        };

        process_response(&buf, false, true, ClockFormat::NTP, None, None, &mut ctx);

        assert_eq!(access_report_state.outcome(), AccessReportOutcome::Pending);
    }

    // --- process_response: AIMD congestion-response wiring
    // (draft-ietf-ippm-stamp-cos-ecn-01 §3.4, chunk F2) ---------------------

    fn congestion_test_params() -> AimdParams {
        AimdParams {
            base_interval: Duration::from_millis(100),
            backoff_factor: 2.0,
            max_interval: Duration::from_millis(1600),
            recovery_step: Duration::from_millis(10),
        }
    }

    fn congestion_process_response_ctx<'a>(
        pending: &'a mut HashMap<u32, PendingPacket>,
        rtt_collector: &'a mut RttCollector,
        owd_collector: &'a mut OwdCollector,
        packets_received: &'a mut u32,
        latched_reflector_msid: &'a mut Option<u16>,
        congestion: Option<&'a mut CongestionState>,
        zero_ssid_seen: &'a mut bool,
    ) -> SenderRecvContext<'a> {
        SenderRecvContext {
            pending,
            rtt_collector,
            owd_collector,
            packets_received,
            print_stats: false,
            hmac_key: None,
            expected_sender_msid: None,
            expected_reflector_msid: None,
            latched_reflector_msid,
            access_report_state: None,
            congestion,
            expected_ssid: None,
            on_zero_ssid: ZeroSsidAction::Continue,
            zero_ssid_seen,
            #[cfg(feature = "metrics")]
            metrics_enabled: false,
            #[cfg(all(unix, feature = "snmp"))]
            snmp_stats: None,
        }
    }

    #[test]
    fn test_process_response_forward_path_ce_backs_off_congestion_controller() {
        use crate::packets::{
            ExtendedReflectedPacketUnauthenticated, ReflectedPacketUnauthenticated,
        };

        let reflected = ReflectedPacketUnauthenticated {
            sequence_number: 1,
            timestamp: 0,
            error_estimate: 0,
            ssid: 0,
            receive_timestamp: 0,
            sess_sender_seq_number: 1,
            sess_sender_timestamp: 0,
            sess_sender_err_estimate: 0,
            sess_sender_ssid: 0,
            sess_sender_ttl: 0,
            mbz3: [0; 3],
        };
        let mut tlvs = TlvList::new();
        let mut cos = ClassOfServiceTlv {
            dscp1: 0,
            ecn1: 1,
            dscp2: 0,
            ecn2: 0b11, // CE observed at the reflector's ingress (forward path)
            rpd: 0,
            rpe: 0b11,
        }
        .to_raw();
        cos.clear_reflector_flags();
        tlvs.push(cos).unwrap();
        let ext = ExtendedReflectedPacketUnauthenticated::with_tlvs(reflected, tlvs);
        let buf = ext.to_bytes();

        let mut pending = HashMap::new();
        pending.insert(
            1,
            PendingPacket {
                send_time: Instant::now(),
                send_timestamp: 0,
            },
        );
        let mut rtt_collector = RttCollector::new();
        let mut owd_collector = OwdCollector::new();
        let mut packets_received = 0u32;
        let mut latched_reflector_msid = None;
        let mut congestion = CongestionState::new(congestion_test_params());
        let mut zero_ssid_seen = false;
        let mut ctx = congestion_process_response_ctx(
            &mut pending,
            &mut rtt_collector,
            &mut owd_collector,
            &mut packets_received,
            &mut latched_reflector_msid,
            Some(&mut congestion),
            &mut zero_ssid_seen,
        );

        // No reply-ECN plumbing in this test (reverse path absent).
        process_response(&buf, false, true, ClockFormat::NTP, None, None, &mut ctx);

        assert_eq!(
            congestion.controller.current_interval(),
            Duration::from_millis(200),
            "forward-path CE (reflected EC2) must double the interval"
        );
        assert_eq!(congestion.controller.stats().ce_observations, 1);
    }

    #[test]
    fn test_process_response_reverse_path_ce_backs_off_congestion_controller() {
        use crate::packets::{
            ExtendedReflectedPacketUnauthenticated, ReflectedPacketUnauthenticated,
        };

        // No CoS TLV at all — the only CE signal is the reply's own on-wire
        // ECN, passed as `reply_ecn`.
        let reflected = ReflectedPacketUnauthenticated {
            sequence_number: 2,
            timestamp: 0,
            error_estimate: 0,
            ssid: 0,
            receive_timestamp: 0,
            sess_sender_seq_number: 2,
            sess_sender_timestamp: 0,
            sess_sender_err_estimate: 0,
            sess_sender_ssid: 0,
            sess_sender_ttl: 0,
            mbz3: [0; 3],
        };
        let ext = ExtendedReflectedPacketUnauthenticated::with_tlvs(reflected, TlvList::new());
        let buf = ext.to_bytes();

        let mut pending = HashMap::new();
        pending.insert(
            2,
            PendingPacket {
                send_time: Instant::now(),
                send_timestamp: 0,
            },
        );
        let mut rtt_collector = RttCollector::new();
        let mut owd_collector = OwdCollector::new();
        let mut packets_received = 0u32;
        let mut latched_reflector_msid = None;
        let mut congestion = CongestionState::new(congestion_test_params());
        let mut zero_ssid_seen = false;
        let mut ctx = congestion_process_response_ctx(
            &mut pending,
            &mut rtt_collector,
            &mut owd_collector,
            &mut packets_received,
            &mut latched_reflector_msid,
            Some(&mut congestion),
            &mut zero_ssid_seen,
        );

        process_response(
            &buf,
            false,
            true,
            ClockFormat::NTP,
            None,
            Some(0b11),
            &mut ctx,
        );

        assert_eq!(
            congestion.controller.current_interval(),
            Duration::from_millis(200),
            "reverse-path CE (reply's on-wire ECN) must double the interval"
        );
        assert_eq!(congestion.controller.stats().ce_observations, 1);
    }

    #[test]
    fn test_process_response_clean_reply_recovers_congestion_controller() {
        use crate::packets::{
            ExtendedReflectedPacketUnauthenticated, ReflectedPacketUnauthenticated,
        };

        let reflected = ReflectedPacketUnauthenticated {
            sequence_number: 3,
            timestamp: 0,
            error_estimate: 0,
            ssid: 0,
            receive_timestamp: 0,
            sess_sender_seq_number: 3,
            sess_sender_timestamp: 0,
            sess_sender_err_estimate: 0,
            sess_sender_ssid: 0,
            sess_sender_ttl: 0,
            mbz3: [0; 3],
        };
        let ext = ExtendedReflectedPacketUnauthenticated::with_tlvs(reflected, TlvList::new());
        let buf = ext.to_bytes();

        let mut pending = HashMap::new();
        pending.insert(
            3,
            PendingPacket {
                send_time: Instant::now(),
                send_timestamp: 0,
            },
        );
        let mut rtt_collector = RttCollector::new();
        let mut owd_collector = OwdCollector::new();
        let mut packets_received = 0u32;
        let mut latched_reflector_msid = None;
        let mut congestion = CongestionState::new(congestion_test_params());
        congestion.controller.on_ce_observed(); // pre-back off to 200ms
        assert_eq!(
            congestion.controller.current_interval(),
            Duration::from_millis(200)
        );
        let mut zero_ssid_seen = false;
        let mut ctx = congestion_process_response_ctx(
            &mut pending,
            &mut rtt_collector,
            &mut owd_collector,
            &mut packets_received,
            &mut latched_reflector_msid,
            Some(&mut congestion),
            &mut zero_ssid_seen,
        );

        // Neither direction CE-marked: a clean reply recovers by the
        // configured step (10ms in `congestion_test_params`).
        process_response(&buf, false, true, ClockFormat::NTP, None, None, &mut ctx);

        assert_eq!(
            congestion.controller.current_interval(),
            Duration::from_millis(190)
        );
        assert_eq!(congestion.controller.stats().ce_observations, 1);
    }

    #[test]
    fn test_process_response_no_panic_when_congestion_inactive() {
        use crate::packets::{
            ExtendedReflectedPacketUnauthenticated, ReflectedPacketUnauthenticated,
        };

        let reflected = ReflectedPacketUnauthenticated {
            sequence_number: 4,
            timestamp: 0,
            error_estimate: 0,
            ssid: 0,
            receive_timestamp: 0,
            sess_sender_seq_number: 4,
            sess_sender_timestamp: 0,
            sess_sender_err_estimate: 0,
            sess_sender_ssid: 0,
            sess_sender_ttl: 0,
            mbz3: [0; 3],
        };
        let ext = ExtendedReflectedPacketUnauthenticated::with_tlvs(reflected, TlvList::new());
        let buf = ext.to_bytes();

        let mut pending = HashMap::new();
        pending.insert(
            4,
            PendingPacket {
                send_time: Instant::now(),
                send_timestamp: 0,
            },
        );
        let mut rtt_collector = RttCollector::new();
        let mut owd_collector = OwdCollector::new();
        let mut packets_received = 0u32;
        let mut latched_reflector_msid = None;
        // `--cos`/`--ecn` not requesting ECT0/ECT1: controller absent.
        let mut zero_ssid_seen = false;
        let mut ctx = congestion_process_response_ctx(
            &mut pending,
            &mut rtt_collector,
            &mut owd_collector,
            &mut packets_received,
            &mut latched_reflector_msid,
            None,
            &mut zero_ssid_seen,
        );

        // Must not panic even with a reverse-path CE reading present.
        process_response(
            &buf,
            false,
            true,
            ClockFormat::NTP,
            None,
            Some(0b11),
            &mut ctx,
        );

        assert_eq!(*ctx.packets_received, 1);
    }

    // --- Full loopback: sender packet → reflector assembly → sender ack ---
    //
    // Exercises the real, socket-free assembly/parse code paths on both
    // ends (no network): builds a sender packet carrying the Access Report
    // TLV exactly as the send loop would, feeds it through the reflector's
    // pure `assemble_unauth_answer_with_tlvs`, and confirms the resulting
    // reply's bytes acknowledge the state machine via `process_response`.

    #[test]
    fn test_access_report_loopback_acked_on_first_reply() {
        use crate::configuration::TlvHandlingMode;
        use crate::packets::PacketUnauthenticated;
        use crate::receiver::{assemble_unauth_answer_with_tlvs, ProcessingContext};

        let access_id = 1u8;
        let return_code = 1u8;
        let extra_tlvs = [AccessReportTlv::new(access_id, return_code).to_raw()];

        let mut access_report_state = AccessReportRetransmitState::new(Duration::from_secs(3), 4);
        let send_time = Instant::now();
        assert!(access_report_state.tick(send_time));

        let seq_num = 1u32;
        let send_timestamp = generate_timestamp(ClockFormat::NTP);
        let request_bytes =
            build_unauth_packet_with_tlvs(seq_num, send_timestamp, 0, None, &extra_tlvs, None);

        // --- Reflector side: pure, socket-free assembly ---
        let packet = PacketUnauthenticated::from_bytes(&request_bytes).unwrap();
        let ctx = ProcessingContext {
            clock_source: ClockFormat::NTP,
            error_estimate_wire: 0,
            hmac_key: None,
            hmac_key_set: None,
            require_hmac: false,
            session_manager: None,
            stateful_reflector: false,
            tlv_mode: TlvHandlingMode::Echo,
            verify_tlv_hmac: false,
            strict_packets: false,
            #[cfg(feature = "metrics")]
            metrics_enabled: false,
            received_dscp: 0,
            received_ecn: 0,
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
            reflected_control_max_count: crate::receiver::REFLECTED_CONTROL_MAX_COUNT,
            reflected_control_max_size: crate::receiver::REFLECTED_CONTROL_MAX_SIZE,
            reflected_control_min_interval_ns: crate::receiver::REFLECTED_CONTROL_MIN_INTERVAL_NS,
            rx_timestamp: None,
            rx_method: crate::tlv::TimestampMethod::SwLocal,
            tx_method: crate::tlv::TimestampMethod::SwLocal,
        };
        let response = assemble_unauth_answer_with_tlvs(
            &packet,
            &request_bytes,
            ClockFormat::NTP,
            generate_timestamp(ClockFormat::NTP),
            64,
            0,
            None,
            TlvHandlingMode::Echo,
            None,
            false,
            &ctx,
        );

        // --- Sender side: process the reflected reply exactly as the send
        // loop's receive path would ---
        let mut pending = HashMap::new();
        pending.insert(
            seq_num,
            PendingPacket {
                send_time,
                send_timestamp,
            },
        );
        let mut rtt_collector = RttCollector::new();
        let mut owd_collector = OwdCollector::new();
        let mut packets_received = 0u32;
        let mut latched_reflector_msid = None;
        let mut recv_ctx = SenderRecvContext {
            pending: &mut pending,
            rtt_collector: &mut rtt_collector,
            owd_collector: &mut owd_collector,
            packets_received: &mut packets_received,
            print_stats: false,
            hmac_key: None,
            expected_sender_msid: None,
            expected_reflector_msid: None,
            latched_reflector_msid: &mut latched_reflector_msid,
            access_report_state: Some(&mut access_report_state),
            congestion: None,
            expected_ssid: None,
            on_zero_ssid: ZeroSsidAction::Continue,
            zero_ssid_seen: &mut false,
            #[cfg(feature = "metrics")]
            metrics_enabled: false,
            #[cfg(all(unix, feature = "snmp"))]
            snmp_stats: None,
        };
        process_response(
            &response.data,
            false,
            true,
            ClockFormat::NTP,
            None,
            None,
            &mut recv_ctx,
        );

        assert_eq!(
            access_report_state.outcome(),
            AccessReportOutcome::Acknowledged,
            "a conforming reflector's echo must acknowledge on the first reply"
        );
        assert_eq!(access_report_state.retransmissions(), 0);
        assert_eq!(packets_received, 1, "RTT accounting must proceed as normal");
    }

    #[test]
    fn test_access_report_no_reflector_echo_leads_to_retransmit_then_abort() {
        // Simulates total silence from the reflector (packet lost / dropped)
        // by simply never calling `acknowledge()` — only driving `tick`
        // forward in time, exactly as the send loop does every iteration.
        let mut state = AccessReportRetransmitState::new(Duration::from_secs(3), 4);
        let mut now = Instant::now();

        assert!(state.tick(now), "iteration 0: original send");
        for expected_retransmissions in 1..=4u32 {
            now += Duration::from_secs(3) + Duration::from_millis(1);
            assert!(
                state.tick(now),
                "iteration {expected_retransmissions}: must retransmit"
            );
            assert_eq!(state.retransmissions(), expected_retransmissions);
            assert_eq!(state.outcome(), AccessReportOutcome::Pending);
        }

        // One more expiry past the 4th retransmission aborts the procedure
        // (RFC 8972 §4.6: "repeated up to four times before the procedure
        // is aborted").
        now += Duration::from_secs(3) + Duration::from_millis(1);
        assert!(!state.tick(now), "must not attach after aborting");
        assert_eq!(state.outcome(), AccessReportOutcome::Aborted);
        assert_eq!(state.retransmissions(), 4);
    }

    // --- Wait-phase extension (post-loop) — RFC 8972 §4.6 -------------------
    //
    // The tests above drive `AccessReportRetransmitState` directly and show
    // the state machine itself is correct. The defect this section covers
    // is in the *plumbing*: `run_sender`'s post-loop wait never called
    // `tick` at all, so a run shorter than the retry budget
    // (`access_report_timeout * (1 + retries)`) reported `Pending` forever
    // without ever retransmitting — the common `--count 1` case. These
    // drive the real `run_sender` end-to-end over loopback UDP so the
    // plumbing itself is exercised, not just the state machine.
    // `--access-report-timeout` is seconds-granular (CLI range 1..=3600),
    // so these sleep for real, bounded, low single-digit seconds.

    /// Builds a `Configuration` for the wait-phase tests: minimal flags,
    /// talking to `remote_port` on loopback, Access Report enabled with a
    /// short timeout/retry budget so the tests run quickly. `--timeout 1`
    /// keeps the pre-existing plain wait phase (before the extension even
    /// starts) short too.
    fn access_report_test_config(
        remote_port: u16,
        access_report_timeout_secs: u32,
        access_report_retries: u32,
    ) -> Configuration {
        use clap::Parser;
        let args: Vec<String> = vec![
            "test".to_string(),
            "--remote-addr".to_string(),
            "127.0.0.1".to_string(),
            "--remote-port".to_string(),
            remote_port.to_string(),
            "--local-addr".to_string(),
            "127.0.0.1".to_string(),
            "--local-port".to_string(),
            "0".to_string(),
            "--count".to_string(),
            "1".to_string(),
            "--send-delay".to_string(),
            "10".to_string(),
            "--timeout".to_string(),
            "1".to_string(),
            "--access-report".to_string(),
            "1".to_string(),
            "--access-report-timeout".to_string(),
            access_report_timeout_secs.to_string(),
            "--access-report-retries".to_string(),
            access_report_retries.to_string(),
        ];
        Configuration::parse_from(args)
    }

    /// Minimal one-packet sender config aimed at `port`, plus `extra` flags.
    /// Used by the wire-level flag tests below: they assert what actually
    /// reaches the socket, not merely what the config parsed to.
    fn wire_test_config(port: u16, extra: &[&str]) -> Configuration {
        use clap::Parser;
        let mut args: Vec<String> = vec![
            "test",
            "--remote-addr",
            "127.0.0.1",
            "--remote-port",
            &port.to_string(),
            "--local-addr",
            "127.0.0.1",
            "--local-port",
            "0",
            "--count",
            "1",
            "--send-delay",
            "10",
            "--timeout",
            "1",
        ]
        .into_iter()
        .map(String::from)
        .collect();
        args.extend(extra.iter().map(|s| String::from(*s)));
        Configuration::parse_from(args)
    }

    /// Collects the TLV types of the first packet a `run_sender` call emits.
    async fn first_packet_tlv_types(conf: Configuration) -> Vec<TlvType> {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let port = socket.local_addr().unwrap().port();
        let conf = Configuration {
            remote_port: port,
            ..conf
        };
        let reflector = tokio::spawn(collect_silently(socket, 1, Duration::from_secs(5)));
        let _ = tokio::time::timeout(Duration::from_secs(8), run_sender(&conf, None)).await;
        let packets = reflector.await.unwrap();
        assert!(!packets.is_empty(), "the sender must emit a packet");
        let tlvs = TlvList::parse(&packets[0][UNAUTH_BASE_SIZE..]).expect("TLV area must parse");
        tlvs.iter().map(|t| t.tlv_type).collect()
    }

    #[tokio::test]
    async fn test_extra_padding_flag_emits_a_padding_tlv() {
        // Without the flag there is no Extra Padding TLV at all.
        let types = first_packet_tlv_types(wire_test_config(0, &[])).await;
        assert!(
            !types.contains(&TlvType::ExtraPadding),
            "no padding by default; got {types:?}"
        );

        // With it, exactly one, independent of --ber.
        let types = first_packet_tlv_types(wire_test_config(0, &["--extra-padding", "64"])).await;
        assert_eq!(
            types
                .iter()
                .filter(|t| **t == TlvType::ExtraPadding)
                .count(),
            1,
            "expected one Extra Padding TLV; got {types:?}"
        );
    }

    #[tokio::test]
    async fn test_ber_omit_burst_drops_only_type_242() {
        // Baseline: --ber emits pattern, count and burst, plus its padding.
        let types = first_packet_tlv_types(wire_test_config(0, &["--ber"])).await;
        assert!(types.contains(&TlvType::BerBurst), "got {types:?}");
        assert!(types.contains(&TlvType::BerPattern), "got {types:?}");
        assert!(types.contains(&TlvType::BerCount), "got {types:?}");

        // With the flag, Type 242 is gone and the rest of the exchange stands.
        let types =
            first_packet_tlv_types(wire_test_config(0, &["--ber", "--ber-omit-burst"])).await;
        assert!(
            !types.contains(&TlvType::BerBurst),
            "Type 242 must be omitted; got {types:?}"
        );
        assert!(
            types.contains(&TlvType::BerPattern) && types.contains(&TlvType::BerCount),
            "the rest of the BER TLVs must remain; got {types:?}"
        );
        assert!(
            types.contains(&TlvType::ExtraPadding),
            "BER's pattern-filled padding must remain; got {types:?}"
        );
    }

    #[tokio::test]
    async fn test_tlv_hmac_mode_controls_origination() {
        const KEY: &str = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";

        // auto (the default) with a key: the HMAC TLV is originated.
        let types = first_packet_tlv_types(wire_test_config(
            0,
            &["--hmac-key", KEY, "--timestamp-info"],
        ))
        .await;
        assert!(
            types.contains(&TlvType::Hmac),
            "auto must originate with a key configured; got {types:?}"
        );

        // off: no HMAC TLV on the wire even though the key is still configured
        // (and still used to verify replies).
        let types = first_packet_tlv_types(wire_test_config(
            0,
            &["--hmac-key", KEY, "--timestamp-info", "--tlv-hmac", "off"],
        ))
        .await;
        assert!(
            !types.contains(&TlvType::Hmac),
            "off must not originate an HMAC TLV; got {types:?}"
        );
        assert!(
            types.contains(&TlvType::TimestampInfo),
            "the other TLVs must be unaffected; got {types:?}"
        );
    }

    /// Like [`access_report_test_config`], but additionally turns on the
    /// AIMD congestion-response path (`--cos --ecn 1`) and requests a
    /// reflected burst, so `scale_reflected_control` is active and the
    /// Reflected Control TLV is rebuilt per send instead of living in the
    /// static `extra_tlvs` set.
    fn access_report_with_scaled_control_config(
        remote_port: u16,
        access_report_timeout_secs: u32,
        access_report_retries: u32,
    ) -> Configuration {
        use clap::Parser;
        let args: Vec<String> = vec![
            "test".to_string(),
            "--remote-addr".to_string(),
            "127.0.0.1".to_string(),
            "--remote-port".to_string(),
            remote_port.to_string(),
            "--local-addr".to_string(),
            "127.0.0.1".to_string(),
            "--local-port".to_string(),
            "0".to_string(),
            "--count".to_string(),
            "1".to_string(),
            "--send-delay".to_string(),
            "10".to_string(),
            "--timeout".to_string(),
            "1".to_string(),
            "--access-report".to_string(),
            "1".to_string(),
            "--access-report-timeout".to_string(),
            access_report_timeout_secs.to_string(),
            "--access-report-retries".to_string(),
            access_report_retries.to_string(),
            // AIMD congestion response: needs --cos with an ECT codepoint.
            "--cos".to_string(),
            "--ecn".to_string(),
            "1".to_string(),
            // A burst request (> 1) makes scale_reflected_control true.
            "--reflected-control-count".to_string(),
            "2".to_string(),
        ];
        Configuration::parse_from(args)
    }

    /// draft-ietf-ippm-stamp-cos-ecn-01 §3.4-3 requires the Reflected Test
    /// Packet Control parameters to be carried on "any future STAMP packet".
    /// A wait-phase retransmission is such a packet, but it is built from the
    /// static `extra_tlvs` set — which deliberately excludes the control TLV
    /// when `scale_reflected_control` is on, because the main loop rebuilds it
    /// per packet with the AIMD-scaled interval. The retransmit path must do
    /// the same rebuild, or the TLV silently vanishes from every retry.
    #[tokio::test]
    async fn test_wait_phase_retransmit_still_carries_scaled_control_tlv() {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let port = socket.local_addr().unwrap().port();
        let conf = access_report_with_scaled_control_config(port, 1, 2);

        let reflector = tokio::spawn(collect_silently(socket, 3, Duration::from_secs(8)));
        let _ = tokio::time::timeout(Duration::from_secs(10), run_sender(&conf, None))
            .await
            .expect("run_sender must not hang past the retry budget");
        let packets = reflector.await.unwrap();

        assert!(
            packets.len() >= 2,
            "need the original send plus at least one retransmission, got {}",
            packets.len()
        );

        for (i, packet) in packets.iter().enumerate() {
            let tlvs = TlvList::parse(&packet[UNAUTH_BASE_SIZE..])
                .unwrap_or_else(|e| panic!("attempt {i} TLV area must parse: {e:?}"));
            assert!(
                tlvs.iter()
                    .any(|t| matches!(t.tlv_type, TlvType::ReflectedControl)),
                "attempt {i} must carry the Reflected Control TLV (§3.4-3); \
                 TLV types present: {:?}",
                tlvs.iter().map(|t| t.tlv_type).collect::<Vec<_>>()
            );
        }
    }

    /// A "dead" reflector: accepts packets on `socket` but never replies.
    /// Collects raw datagrams until either `want` have arrived or `budget`
    /// elapses, whichever comes first — bounding the test's runtime even if
    /// the defect under test resurfaces (no retransmits ⇒ `want` is never
    /// reached, so this just idles out after `budget`).
    async fn collect_silently(socket: UdpSocket, want: usize, budget: Duration) -> Vec<Vec<u8>> {
        let mut packets = Vec::new();
        let deadline = tokio::time::Instant::now() + budget;
        let mut buf = [0u8; 1024];
        while packets.len() < want {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                break;
            }
            match tokio::time::timeout(remaining, socket.recv_from(&mut buf)).await {
                Ok(Ok((len, _src))) => packets.push(buf[..len].to_vec()),
                _ => break,
            }
        }
        packets
    }

    /// A reflector that ignores every packet until the `ack_after`-th
    /// (1-indexed), which it acknowledges with a real, TLV-echoing reply
    /// built via the reflector's own `assemble_unauth_answer_with_tlvs` —
    /// then keeps listening (silently) for `extra_wait` to prove nothing
    /// further arrives. Returns the total number of packets received.
    ///
    /// Bounded overall by `max_wait` for reaching the `ack_after`-th packet
    /// so that if the sender never retransmits (e.g. the defect this test
    /// guards against), the test fails cleanly instead of hanging forever
    /// waiting for a packet that will never come.
    async fn ack_nth_then_watch_for_more(
        socket: UdpSocket,
        ack_after: usize,
        extra_wait: Duration,
        max_wait: Duration,
    ) -> usize {
        use crate::configuration::TlvHandlingMode;
        use crate::packets::PacketUnauthenticated;
        use crate::receiver::{assemble_unauth_answer_with_tlvs, ProcessingContext};

        let deadline = tokio::time::Instant::now() + max_wait;
        let mut buf = [0u8; 1024];
        let mut received = 0usize;
        loop {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                break;
            }
            let (len, src) = match tokio::time::timeout(remaining, socket.recv_from(&mut buf)).await
            {
                Ok(Ok(v)) => v,
                _ => break,
            };
            received += 1;
            if received == ack_after {
                let packet = PacketUnauthenticated::from_bytes(&buf[..len]).unwrap();
                let ctx = ProcessingContext {
                    clock_source: ClockFormat::NTP,
                    error_estimate_wire: 0,
                    hmac_key: None,
                    hmac_key_set: None,
                    require_hmac: false,
                    session_manager: None,
                    stateful_reflector: false,
                    tlv_mode: TlvHandlingMode::Echo,
                    verify_tlv_hmac: false,
                    strict_packets: false,
                    #[cfg(feature = "metrics")]
                    metrics_enabled: false,
                    received_dscp: 0,
                    received_ecn: 0,
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
                    reflected_control_max_count: crate::receiver::REFLECTED_CONTROL_MAX_COUNT,
                    reflected_control_max_size: crate::receiver::REFLECTED_CONTROL_MAX_SIZE,
                    reflected_control_min_interval_ns:
                        crate::receiver::REFLECTED_CONTROL_MIN_INTERVAL_NS,
                    rx_timestamp: None,
                    rx_method: crate::tlv::TimestampMethod::SwLocal,
                    tx_method: crate::tlv::TimestampMethod::SwLocal,
                };
                let response = assemble_unauth_answer_with_tlvs(
                    &packet,
                    &buf[..len],
                    ClockFormat::NTP,
                    generate_timestamp(ClockFormat::NTP),
                    64,
                    0,
                    None,
                    TlvHandlingMode::Echo,
                    None,
                    false,
                    &ctx,
                );
                let _ = socket.send_to(&response.data, src).await;

                // Keep watching to prove the sender does not retransmit
                // again after being acknowledged.
                let watch_deadline = tokio::time::Instant::now() + extra_wait;
                loop {
                    let remaining =
                        watch_deadline.saturating_duration_since(tokio::time::Instant::now());
                    if remaining.is_zero() {
                        break;
                    }
                    match tokio::time::timeout(remaining, socket.recv_from(&mut buf)).await {
                        Ok(Ok(_)) => received += 1,
                        _ => break,
                    }
                }
                break;
            }
        }
        received
    }

    #[tokio::test]
    async fn test_wait_phase_retransmits_when_reflector_silent_then_aborts() {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let port = socket.local_addr().unwrap().port();

        // timeout=1s, retries=2 ⇒ retry budget = 1*(1+2) = 3s worst case,
        // on top of the pre-existing plain 1s wait before the extension
        // even starts.
        let conf = access_report_test_config(port, 1, 2);

        let reflector = tokio::spawn(collect_silently(socket, 4, Duration::from_secs(8)));
        let snapshot = tokio::time::timeout(Duration::from_secs(10), run_sender(&conf, None))
            .await
            .expect("run_sender must not hang past the retry budget");
        let packets = reflector.await.unwrap();

        // Original send + exactly `retries` (2) retransmissions — no more:
        // the retry budget caps it, since the reflector never acks.
        assert_eq!(
            packets.len(),
            3,
            "expected 1 original send + 2 retransmissions, got {}",
            packets.len()
        );

        let summary = snapshot
            .access_report
            .expect("Access Report summary must be present when --access-report is set");
        assert_eq!(summary.outcome, AccessReportOutcome::Aborted);
        assert_eq!(summary.retransmissions, 2);
        assert_eq!(
            snapshot.packets_sent, 3,
            "sent count must reflect the retransmissions"
        );

        // Reviewer-suggested cheap regression test: the Access Report TLV's
        // wire bytes (flags/type/length/value) must be byte-identical
        // across every attempt — nothing about the retry mechanism should
        // perturb the TLV's content. In this minimal configuration the TLV
        // is the only thing following the fixed unauthenticated base
        // header (no HMAC TLV, since no key was configured).
        let expected_tlv = AccessReportTlv::new(1, 1).to_raw().to_bytes();
        for (i, packet) in packets.iter().enumerate() {
            assert_eq!(
                &packet[UNAUTH_BASE_SIZE..],
                expected_tlv.as_slice(),
                "attempt {i}'s Access Report TLV bytes must match every other attempt"
            );
        }
    }

    #[tokio::test]
    async fn test_wait_phase_ack_mid_wait_stops_retransmitting() {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let port = socket.local_addr().unwrap().port();

        // timeout=1s, retries=3 (budget 4s if never acked). Ignoring the
        // original send and acking only the *second* packet received (the
        // first retransmission, sent by the wait-phase extension after the
        // main loop and its own plain wait have both already finished)
        // specifically exercises the extension loop's own recv path, not
        // the main loop's.
        let conf = access_report_test_config(port, 1, 3);

        let reflector = tokio::spawn(ack_nth_then_watch_for_more(
            socket,
            2,
            Duration::from_secs(1),
            Duration::from_secs(6),
        ));
        let snapshot = tokio::time::timeout(Duration::from_secs(10), run_sender(&conf, None))
            .await
            .expect("run_sender must finish promptly once acknowledged");
        let received = reflector.await.unwrap();

        assert_eq!(
            received, 2,
            "must stop sending after the ack — original + exactly 1 retransmission"
        );

        let summary = snapshot
            .access_report
            .expect("Access Report summary must be present when --access-report is set");
        assert_eq!(summary.outcome, AccessReportOutcome::Acknowledged);
        assert_eq!(summary.retransmissions, 1);
    }

    #[tokio::test]
    async fn test_wait_phase_unaffected_when_access_report_disabled() {
        use clap::Parser;

        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let port = socket.local_addr().unwrap().port();

        let args: Vec<String> = vec![
            "test".to_string(),
            "--remote-addr".to_string(),
            "127.0.0.1".to_string(),
            "--remote-port".to_string(),
            port.to_string(),
            "--local-addr".to_string(),
            "127.0.0.1".to_string(),
            "--local-port".to_string(),
            "0".to_string(),
            "--count".to_string(),
            "1".to_string(),
            "--send-delay".to_string(),
            "10".to_string(),
            "--timeout".to_string(),
            "1".to_string(),
        ];
        let conf = Configuration::parse_from(args);

        let reflector = tokio::spawn(collect_silently(socket, 10, Duration::from_millis(1300)));
        let start = Instant::now();
        let snapshot = tokio::time::timeout(Duration::from_secs(5), run_sender(&conf, None))
            .await
            .expect("run_sender must finish promptly with no Access Report extension");
        let elapsed = start.elapsed();
        let packets = reflector.await.unwrap();

        // Bounded by the plain `--timeout` (1s) alone — there is no Access
        // Report retry budget to extend it, proving the new wait-phase loop
        // is a true no-op (byte-identical prior behaviour) when
        // `--access-report` was not set.
        assert!(
            elapsed < Duration::from_millis(1500),
            "wait phase must not be extended when --access-report is unset (took {elapsed:?})"
        );
        assert_eq!(packets.len(), 1, "no retransmission logic applies at all");
        assert!(snapshot.access_report.is_none());
        assert_eq!(snapshot.packets_sent, 1);
        assert_eq!(snapshot.packets_lost, 1);
    }

    #[test]
    fn malformed_bad_length_overruns_declared_length() {
        use crate::tlv::TLV_HEADER_SIZE;
        let bytes = malformed_tlv_bytes(MalformedMode::BadLength);
        assert!(bytes.len() >= TLV_HEADER_SIZE);
        let declared = u16::from_be_bytes([bytes[2], bytes[3]]) as usize;
        let actual_value = bytes.len() - TLV_HEADER_SIZE;
        assert!(
            declared > actual_value,
            "declared length {declared} must overrun actual {actual_value}"
        );
    }

    #[test]
    fn malformed_bad_flags_sets_reserved_bits_but_valid_length() {
        use crate::tlv::TLV_HEADER_SIZE;
        let bytes = malformed_tlv_bytes(MalformedMode::BadFlags);
        // Reserved bits live below the C flag (0x10), i.e. mask 0x0F.
        assert_ne!(bytes[0] & 0x0F, 0, "reserved flag bits must be set");
        // This variant is malformed *only* in its flags: length stays correct.
        let declared = u16::from_be_bytes([bytes[2], bytes[3]]) as usize;
        assert_eq!(declared, bytes.len() - TLV_HEADER_SIZE);
    }

    #[test]
    fn test_process_response_records_forward_one_way_delay() {
        use crate::packets::ReflectedPacketUnauthenticated;

        // PTP timestamps (secs << 32 | nanos) make the conversion exact.
        // T1 = 1.000 s (in pending), T2 = 1.003 s (reflector receive) ⇒ the
        // forward one-way delay is exactly 3 ms regardless of the (live) T4.
        let t1 = 1u64 << 32;
        let t2 = (1u64 << 32) | 3_000_000;
        let t3 = (1u64 << 32) | 4_000_000;

        let reflected = ReflectedPacketUnauthenticated {
            sequence_number: 7,
            timestamp: t3,
            error_estimate: 0,
            ssid: 0,
            receive_timestamp: t2,
            sess_sender_seq_number: 7,
            sess_sender_timestamp: t1,
            sess_sender_err_estimate: 0,
            sess_sender_ssid: 0,
            sess_sender_ttl: 64,
            mbz3: [0; 3],
        };
        let buf = reflected.to_bytes();

        let mut pending = HashMap::new();
        pending.insert(
            7,
            PendingPacket {
                send_time: Instant::now(),
                send_timestamp: t1,
            },
        );
        let mut rtt_collector = RttCollector::new();
        let mut owd_collector = OwdCollector::new();
        let mut packets_received = 0u32;
        let mut latched_reflector_msid = None;
        let mut ctx = SenderRecvContext {
            pending: &mut pending,
            rtt_collector: &mut rtt_collector,
            owd_collector: &mut owd_collector,
            packets_received: &mut packets_received,
            print_stats: false,
            hmac_key: None,
            expected_sender_msid: None,
            expected_reflector_msid: None,
            latched_reflector_msid: &mut latched_reflector_msid,
            access_report_state: None,
            congestion: None,
            expected_ssid: None,
            on_zero_ssid: ZeroSsidAction::Continue,
            zero_ssid_seen: &mut false,
            #[cfg(feature = "metrics")]
            metrics_enabled: false,
            #[cfg(all(unix, feature = "snmp"))]
            snmp_stats: None,
        };

        process_response(&buf, false, false, ClockFormat::PTP, None, None, &mut ctx);

        let owd = owd_collector.summary().expect("one OWD sample recorded");
        assert_eq!(owd.samples, 1);
        assert!(
            (owd.forward_avg_ms - 3.0).abs() < 1e-6,
            "forward OWD must be T2 − T1 = 3 ms, got {}",
            owd.forward_avg_ms
        );
    }

    /// RFC8972-3-11: "An implementation of a Session-Sender MUST support
    /// control of its behavior in such a scenario [a zeroed SSID]." The two
    /// actions must actually differ: `stop` refuses to account the reply and
    /// latches the condition, `continue` accounts it normally.
    #[test]
    fn test_zero_ssid_policy_stop_discards_reply_and_latches() {
        use crate::packets::ReflectedPacketUnauthenticated;

        // A reflector that does not implement SSID leaves both fields zero.
        let reflected = ReflectedPacketUnauthenticated {
            sequence_number: 7,
            timestamp: 0,
            error_estimate: 0,
            ssid: 0,
            receive_timestamp: 0,
            sess_sender_seq_number: 7,
            sess_sender_timestamp: 0,
            sess_sender_err_estimate: 0,
            sess_sender_ssid: 0,
            sess_sender_ttl: 0,
            mbz3: [0; 3],
        };
        let buf = reflected.to_bytes().to_vec();

        let mut pending = HashMap::new();
        pending.insert(
            7,
            PendingPacket {
                send_time: Instant::now(),
                send_timestamp: 0,
            },
        );
        let mut rtt_collector = RttCollector::new();
        let mut owd_collector = OwdCollector::new();
        let mut packets_received = 0u32;
        let mut latched_reflector_msid = None;
        let mut zero_ssid_seen = false;
        {
            let mut ctx = SenderRecvContext {
                pending: &mut pending,
                rtt_collector: &mut rtt_collector,
                owd_collector: &mut owd_collector,
                packets_received: &mut packets_received,
                print_stats: false,
                hmac_key: None,
                expected_sender_msid: None,
                expected_reflector_msid: None,
                latched_reflector_msid: &mut latched_reflector_msid,
                access_report_state: None,
                congestion: None,
                // The sender asked for SSID 4242; the reply carries zero.
                expected_ssid: Some(4242),
                on_zero_ssid: ZeroSsidAction::Stop,
                zero_ssid_seen: &mut zero_ssid_seen,
                #[cfg(feature = "metrics")]
                metrics_enabled: false,
                #[cfg(all(unix, feature = "snmp"))]
                snmp_stats: None,
            };
            process_response(&buf, false, false, ClockFormat::NTP, None, None, &mut ctx);
        }

        assert!(
            zero_ssid_seen,
            "the zeroed-SSID condition must be latched for the send loop to stop on"
        );
        assert_eq!(
            packets_received, 0,
            "under `stop` the reply belongs to an abandoned session and must not be counted"
        );
        assert!(
            pending.contains_key(&7),
            "the pending entry must be left alone under `stop`"
        );
    }

    #[test]
    fn test_zero_ssid_policy_continue_still_accounts_the_reply() {
        use crate::packets::ReflectedPacketUnauthenticated;

        let reflected = ReflectedPacketUnauthenticated {
            sequence_number: 7,
            timestamp: 0,
            error_estimate: 0,
            ssid: 0,
            receive_timestamp: 0,
            sess_sender_seq_number: 7,
            sess_sender_timestamp: 0,
            sess_sender_err_estimate: 0,
            sess_sender_ssid: 0,
            sess_sender_ttl: 0,
            mbz3: [0; 3],
        };
        let buf = reflected.to_bytes().to_vec();

        let mut pending = HashMap::new();
        pending.insert(
            7,
            PendingPacket {
                send_time: Instant::now(),
                send_timestamp: 0,
            },
        );
        let mut rtt_collector = RttCollector::new();
        let mut owd_collector = OwdCollector::new();
        let mut packets_received = 0u32;
        let mut latched_reflector_msid = None;
        let mut zero_ssid_seen = false;
        {
            let mut ctx = SenderRecvContext {
                pending: &mut pending,
                rtt_collector: &mut rtt_collector,
                owd_collector: &mut owd_collector,
                packets_received: &mut packets_received,
                print_stats: false,
                hmac_key: None,
                expected_sender_msid: None,
                expected_reflector_msid: None,
                latched_reflector_msid: &mut latched_reflector_msid,
                access_report_state: None,
                congestion: None,
                expected_ssid: Some(4242),
                on_zero_ssid: ZeroSsidAction::Continue,
                zero_ssid_seen: &mut zero_ssid_seen,
                #[cfg(feature = "metrics")]
                metrics_enabled: false,
                #[cfg(all(unix, feature = "snmp"))]
                snmp_stats: None,
            };
            process_response(&buf, false, false, ClockFormat::NTP, None, None, &mut ctx);
        }

        assert!(
            zero_ssid_seen,
            "the condition is still recorded so it is only reported once"
        );
        assert_eq!(
            packets_received, 1,
            "continuing is RFC-permitted: the measurement proceeds normally"
        );
        assert!(
            !pending.contains_key(&7),
            "the reply was accounted, so its pending entry is consumed"
        );
    }

    /// A sender that never set an SSID must not react to a zeroed reply field:
    /// there is nothing for the reflector to have echoed.
    #[test]
    fn test_zero_ssid_policy_inert_without_a_configured_ssid() {
        use crate::packets::ReflectedPacketUnauthenticated;

        let reflected = ReflectedPacketUnauthenticated {
            sequence_number: 7,
            timestamp: 0,
            error_estimate: 0,
            ssid: 0,
            receive_timestamp: 0,
            sess_sender_seq_number: 7,
            sess_sender_timestamp: 0,
            sess_sender_err_estimate: 0,
            sess_sender_ssid: 0,
            sess_sender_ttl: 0,
            mbz3: [0; 3],
        };
        let buf = reflected.to_bytes().to_vec();

        let mut pending = HashMap::new();
        pending.insert(
            7,
            PendingPacket {
                send_time: Instant::now(),
                send_timestamp: 0,
            },
        );
        let mut rtt_collector = RttCollector::new();
        let mut owd_collector = OwdCollector::new();
        let mut packets_received = 0u32;
        let mut latched_reflector_msid = None;
        let mut zero_ssid_seen = false;
        {
            let mut ctx = SenderRecvContext {
                pending: &mut pending,
                rtt_collector: &mut rtt_collector,
                owd_collector: &mut owd_collector,
                packets_received: &mut packets_received,
                print_stats: false,
                hmac_key: None,
                expected_sender_msid: None,
                expected_reflector_msid: None,
                latched_reflector_msid: &mut latched_reflector_msid,
                access_report_state: None,
                congestion: None,
                // No SSID requested — even `stop` must not fire.
                expected_ssid: None,
                on_zero_ssid: ZeroSsidAction::Stop,
                zero_ssid_seen: &mut zero_ssid_seen,
                #[cfg(feature = "metrics")]
                metrics_enabled: false,
                #[cfg(all(unix, feature = "snmp"))]
                snmp_stats: None,
            };
            process_response(&buf, false, false, ClockFormat::NTP, None, None, &mut ctx);
        }

        assert!(!zero_ssid_seen, "no SSID was requested; nothing to detect");
        assert_eq!(packets_received, 1, "the reply must be accounted normally");
    }

    #[test]
    fn test_process_response_drops_packet_on_msid_mismatch() {
        use crate::packets::{
            ExtendedReflectedPacketUnauthenticated, ReflectedPacketUnauthenticated,
        };

        // Build a reflected unauth packet that echoes a different
        // sender_micro_session_id than we transmitted. process_response MUST
        // NOT remove the sequence from pending, must not record RTT, and
        // must not increment packets_received.
        let reflected = ReflectedPacketUnauthenticated {
            sequence_number: 42,
            timestamp: 0,
            error_estimate: 0,
            ssid: 0,
            receive_timestamp: 0,
            sess_sender_seq_number: 42,
            sess_sender_timestamp: 0,
            sess_sender_err_estimate: 0,
            sess_sender_ssid: 0,
            sess_sender_ttl: 0,
            mbz3: [0; 3],
        };
        let mut tlvs = TlvList::new();
        // Model a properly-reflected TLV: a conforming reflector clears the
        // U/M/I flags on a recognized, well-formed TLV (the typed constructor
        // sets the sender-side U flag, which would otherwise make the sender
        // skip processing per RFC 8972 §4-17).
        let mut raw = MicroSessionIdTlv::new(0xBAD, 99).to_raw();
        raw.clear_reflector_flags();
        tlvs.push(raw).unwrap();
        let ext = ExtendedReflectedPacketUnauthenticated::with_tlvs(reflected, tlvs);
        let buf = ext.to_bytes();

        let mut pending = HashMap::new();
        pending.insert(
            42,
            PendingPacket {
                send_time: Instant::now(),
                send_timestamp: 0,
            },
        );
        let mut rtt_collector = RttCollector::new();
        let mut owd_collector = OwdCollector::new();
        let mut packets_received = 0u32;
        let mut latched_reflector_msid = None;
        let mut ctx = SenderRecvContext {
            pending: &mut pending,
            rtt_collector: &mut rtt_collector,
            owd_collector: &mut owd_collector,
            packets_received: &mut packets_received,
            print_stats: false,
            hmac_key: None,
            // Sender transmitted with sender_msid=7777; reflector's response
            // carries 0xBAD → session binding fails.
            expected_sender_msid: Some(7777),
            expected_reflector_msid: None,
            latched_reflector_msid: &mut latched_reflector_msid,
            access_report_state: None,
            congestion: None,
            expected_ssid: None,
            on_zero_ssid: ZeroSsidAction::Continue,
            zero_ssid_seen: &mut false,
            #[cfg(feature = "metrics")]
            metrics_enabled: false,
            #[cfg(all(unix, feature = "snmp"))]
            snmp_stats: None,
        };

        process_response(&buf, false, true, ClockFormat::NTP, None, None, &mut ctx);

        assert!(
            pending.contains_key(&42),
            "pending entry must remain so the packet is still counted as lost"
        );
        assert_eq!(
            packets_received, 0,
            "received counter must not advance on MSID mismatch"
        );
        assert_eq!(
            rtt_collector.snapshot(1, 0).packets_received,
            0,
            "no RTT sample must be recorded on MSID mismatch"
        );
    }

    #[test]
    fn test_process_response_accepts_packet_on_msid_match() {
        use crate::packets::{
            ExtendedReflectedPacketUnauthenticated, ReflectedPacketUnauthenticated,
        };

        // Control case: matching MSID means the response is accepted,
        // pending entry is consumed, received counter increments.
        let reflected = ReflectedPacketUnauthenticated {
            sequence_number: 42,
            timestamp: 0,
            error_estimate: 0,
            ssid: 0,
            receive_timestamp: 0,
            sess_sender_seq_number: 42,
            sess_sender_timestamp: 0,
            sess_sender_err_estimate: 0,
            sess_sender_ssid: 0,
            sess_sender_ttl: 0,
            mbz3: [0; 3],
        };
        let mut tlvs = TlvList::new();
        tlvs.push(MicroSessionIdTlv::new(7777, 99).to_raw())
            .unwrap();
        let ext = ExtendedReflectedPacketUnauthenticated::with_tlvs(reflected, tlvs);
        let buf = ext.to_bytes();

        let mut pending = HashMap::new();
        pending.insert(
            42,
            PendingPacket {
                send_time: Instant::now(),
                send_timestamp: 0,
            },
        );
        let mut rtt_collector = RttCollector::new();
        let mut owd_collector = OwdCollector::new();
        let mut packets_received = 0u32;
        let mut latched_reflector_msid = None;
        let mut ctx = SenderRecvContext {
            pending: &mut pending,
            rtt_collector: &mut rtt_collector,
            owd_collector: &mut owd_collector,
            packets_received: &mut packets_received,
            print_stats: false,
            hmac_key: None,
            expected_sender_msid: Some(7777),
            expected_reflector_msid: None,
            latched_reflector_msid: &mut latched_reflector_msid,
            access_report_state: None,
            congestion: None,
            expected_ssid: None,
            on_zero_ssid: ZeroSsidAction::Continue,
            zero_ssid_seen: &mut false,
            #[cfg(feature = "metrics")]
            metrics_enabled: false,
            #[cfg(all(unix, feature = "snmp"))]
            snmp_stats: None,
        };

        process_response(&buf, false, true, ClockFormat::NTP, None, None, &mut ctx);

        assert!(!pending.contains_key(&42));
        assert_eq!(packets_received, 1);
    }

    #[test]
    fn test_build_unauth_packet_ssid_round_trips_via_reflector() {
        use crate::packets::{PacketUnauthenticated, ReflectedPacketUnauthenticated};
        use crate::receiver::assemble_unauth_answer;

        // End-to-end wire check: an SSID set by the sender reaches the reflector
        // in the base header and is echoed into both SSID fields of the reply.
        let built = build_unauth_packet_with_tlvs(1, 100, 0, Some(0xABCD), &[], None);
        let parsed = PacketUnauthenticated::from_bytes(&built).unwrap();
        assert_eq!(parsed.ssid, 0xABCD);

        let reply: ReflectedPacketUnauthenticated =
            assemble_unauth_answer(&parsed, ClockFormat::NTP, 0, 64, 0, None);
        assert_eq!(reply.ssid, 0xABCD);
        assert_eq!(reply.sess_sender_ssid, 0xABCD);
    }

    #[test]
    fn test_build_auth_packet_ssid_round_trips_via_reflector() {
        use crate::packets::{PacketAuthenticated, ReflectedPacketAuthenticated};
        use crate::receiver::assemble_auth_answer;

        // End-to-end wire check for the authenticated path: the SSID set by
        // the sender must reach the reflector in base header bytes 26-27 and
        // be echoed into both SSID fields (offsets 26-27 and 74-75) of the
        // reflected packet. HMAC is recomputed on each side, so getting this
        // wrong would also desync verification.
        let key = HmacKey::new(vec![0xAB; 32]).unwrap();
        let built = build_auth_packet_with_tlvs(42, 1000, 100, &key, Some(0xBEEF), &[], None);
        assert_eq!(built.len(), 112);
        assert_eq!(u16::from_be_bytes([built[26], built[27]]), 0xBEEF);

        let parsed = PacketAuthenticated::from_bytes(&built).unwrap();
        assert_eq!(parsed.ssid, 0xBEEF);

        let reply: ReflectedPacketAuthenticated =
            assemble_auth_answer(&parsed, ClockFormat::NTP, 0, 64, 0, Some(&key), None);
        assert_eq!(reply.ssid, 0xBEEF);
        assert_eq!(reply.sess_sender_ssid, 0xBEEF);

        // Reflector's HMAC must be computed over the echoed SSID too —
        // serialize and verify it round-trips through from_bytes.
        let reply_bytes = reply.to_bytes();
        assert_eq!(
            u16::from_be_bytes([reply_bytes[26], reply_bytes[27]]),
            0xBEEF
        );
        assert_eq!(
            u16::from_be_bytes([reply_bytes[74], reply_bytes[75]]),
            0xBEEF
        );
        let reparsed = ReflectedPacketAuthenticated::from_bytes(&reply_bytes).unwrap();
        assert_eq!(reparsed.ssid, 0xBEEF);
        assert_eq!(reparsed.sess_sender_ssid, 0xBEEF);
    }
}
