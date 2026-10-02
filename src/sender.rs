mod access_report;
mod congestion;
pub(crate) mod measurements;
mod packet;
pub(crate) mod session_state;
mod socket;
mod telemetry;
mod validate;

pub(crate) use access_report::*;
use congestion::*;
pub use packet::*;
use socket::*;
use validate::*;

use measurements::{Measurements, ReplyKey, ReplyObservation};

use telemetry::{FlagCounts, HmacStatus, TlvTelemetry};

use std::{
    collections::{HashMap, VecDeque},
    net::SocketAddr,
    time::{Duration, Instant},
};

use tokio::net::UdpSocket;

use crate::{
    ber::{observation, BerCollector},
    clock_format::ClockFormat,
    configuration::{
        decode_selector, is_auth, Configuration, MalformedMode, TlvHmacMode, ZeroSsidAction,
    },
    crypto::{compute_packet_hmac, verify_packet_hmac, HmacKey},
    error_estimate::ErrorEstimate,
    packets::{
        ExtendedReflectedPacketAuthenticated, ExtendedReflectedPacketUnauthenticated,
        PacketAuthenticated, PacketUnauthenticated, ReflectedPacketAuthenticated,
        ReflectedPacketUnauthenticated, AUTH_BASE_SIZE, AUTH_HMAC_OFFSET, MAX_UDP_PAYLOAD,
        UNAUTH_BASE_SIZE,
    },
    rate_control::{AimdController, AimdParams, AimdStats},
    receiver::load_hmac_key,
    session::Session,
    stats::{
        AccessReportOutcome, AccessReportSummary, CongestionSummary, OwdCollector, OwdSample,
        RttCollector, RttSample, StatsSnapshot,
    },
    time::{generate_timestamp, timestamp_to_unix_nanos},
    tlv::{
        AccessReportTlv, BerBurstTlv, BerCountTlv, BerPatternTlv, ClassOfServiceTlv,
        DestinationNodeAddressTlv, DirectMeasurementTlv, ExtraPaddingTlv, FollowUpTelemetryTlv,
        LocationTlv, MicroSessionIdTlv, RawTlv, ReflectedControlTlv, ReflectedFixedHdrTlv,
        ReflectedIpv6ExtHdrTlv, ReturnPathTlv, TimestampInfoTlv, TlvList, TlvType, TypedTlv,
        IPV4_FIXED_HEADER_SIZE, IPV6_FIXED_HEADER_SIZE,
    },
};

/// Internal structure to track packets awaiting responses.
#[derive(Clone, Copy)]
struct PendingPacket {
    /// Wall-clock time when the packet was sent.
    send_time: Instant,
    /// STAMP timestamp (T1) embedded in the sent packet, used to compute the
    /// forward one-way delay against the reflector's receive timestamp (T2).
    send_timestamp: u64,
}

/// Errors a connected UDP socket reports for ICMP feedback on an earlier
/// datagram. The socket stays usable, so the run continues on its schedule.
fn is_icmp_feedback(e: &std::io::Error) -> bool {
    matches!(
        e.kind(),
        std::io::ErrorKind::ConnectionRefused
            | std::io::ErrorKind::ConnectionReset
            | std::io::ErrorKind::HostUnreachable
            | std::io::ErrorKind::NetworkUnreachable
    )
}

/// Mutable context for processing received responses.
struct SenderRecvContext<'a> {
    local_error_estimate: Option<ErrorEstimate>,
    measurements: Option<&'a mut Measurements>,
    ber: Option<&'a mut BerCollector>,
    /// Configured remote timescale offset in seconds, removed after decoding.
    reflector_utc_offset: i32,
    pending: &'a mut HashMap<u32, PendingPacket>,
    rtt_collector: &'a mut RttCollector,
    owd_collector: &'a mut OwdCollector,
    packets_received: &'a mut u32,
    print_stats: bool,
    output_format: crate::stats::OutputFormat,
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
    /// Reflector Micro-session ID learned from the first accepted reply when
    /// no expected ID is configured (RFC 9534 §3.2-11). Later mismatches are
    /// rejected. Retained for the sender session.
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
    /// §3 identifies sessions with this value; zero replies use the configured
    /// compatibility policy. `None` means no SSID was assigned.
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

/// Runs the STAMP sender, transmitting test packets and collecting statistics.
///
/// Sends packets to the configured remote address and waits for reflected responses.
/// Returns statistics about the measurement session including RTT and packet loss.
/// For a continuous CSV stream including the final snapshot, use
/// [`run_sender_with_output`] with a shared [`crate::stats::StatsOutput`].
///
/// When the `metrics` feature is enabled and `--metrics` flag is set, this function
/// also records Prometheus metrics for packets sent, received, lost, and RTT values.
pub async fn run_sender(
    conf: &Configuration,
    #[cfg(all(unix, feature = "snmp"))] snmp_stats: Option<
        std::sync::Arc<crate::snmp::state::SenderSnmpStats>,
    >,
    #[cfg(not(all(unix, feature = "snmp")))] snmp_stats: Option<()>,
) -> Result<StatsSnapshot, crate::StartupError> {
    let mut output = crate::stats::StatsOutput::new(conf.output_format);
    run_sender_with_output(conf, snmp_stats, &mut output).await
}

/// Runs a sender with shared reporting state. Use the same `StatsOutput` to print
/// the returned final snapshot so periodic CSV reports do not repeat the header.
pub async fn run_sender_with_output(
    conf: &Configuration,
    #[cfg(all(unix, feature = "snmp"))] snmp_stats: Option<
        std::sync::Arc<crate::snmp::state::SenderSnmpStats>,
    >,
    #[cfg(not(all(unix, feature = "snmp")))] _snmp_stats: Option<()>,
    output: &mut crate::stats::StatsOutput,
) -> Result<StatsSnapshot, crate::StartupError> {
    #[cfg(feature = "metrics")]
    let metrics_enabled = conf.metrics;
    let local_addr: SocketAddr = conf.local_socket_addr();
    let remote_addr: SocketAddr = conf.remote_socket_addr();

    // Enable AIMD for `--cos` with ECT0/ECT1 (cos-ecn-01 §3.4).
    // `conf.ecn` sets both the egress ECN and the requested reply EC1.
    let ecn_response_active = conf.cos && matches!(conf.ecn, 1 | 2);

    let std_socket = match crate::net_policy::bind_sender(local_addr, remote_addr) {
        Ok(s) => s,
        Err(e) => {
            return Err(crate::StartupError::new(format!(
                "Cannot bind to address {local_addr}: {e}"
            )));
        }
    };

    crate::net_policy::set_hops(&std_socket)
        .map_err(|e| crate::StartupError::new(format!("Cannot set TTL/Hop Limit 255: {e}")))?;
    std_socket
        .set_nonblocking(true)
        .map_err(|e| crate::StartupError::new(e.to_string()))?;
    let socket =
        UdpSocket::from_std(std_socket).map_err(|e| crate::StartupError::new(e.to_string()))?;

    if conf.ber
        || !conf.attach_ext_hdr.is_empty()
        || !conf.reflected_fixed_hdr.is_empty()
        || !conf.reflected_ipv6_ext_hdr.is_empty()
    {
        conf.validate()
            .map_err(|e| crate::StartupError::new(e.to_string()))?;
        #[cfg(target_os = "linux")]
        {
            use std::os::fd::AsRawFd;
            let value: nix::libc::c_int = nix::libc::IP_PMTUDISC_DO;
            let (level, option) = if conf.remote_addr.is_ipv6() {
                (nix::libc::IPPROTO_IPV6, nix::libc::IPV6_MTU_DISCOVER)
            } else {
                (nix::libc::IPPROTO_IP, nix::libc::IP_MTU_DISCOVER)
            };
            // SAFETY: the socket is live and value is a valid c_int.
            if unsafe {
                nix::libc::setsockopt(
                    socket.as_raw_fd(),
                    level,
                    option,
                    std::ptr::addr_of!(value).cast(),
                    std::mem::size_of_val(&value) as _,
                )
            } != 0
            {
                return Err(crate::StartupError::new(format!(
                    "BER PMTU setup: {}",
                    std::io::Error::last_os_error()
                )));
            }
        }
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
            match apply_egress_ip_options(socket.as_raw_fd(), is_ipv6, egress_tos, None) {
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

    // draft-ietf-ippm-stamp-ext-hdr-15 §4.2: attach the real IPv6 extension
    // headers requested via --attach-ext-hdr. IPv6 destinations only, and
    // Linux only (see `apply_attach_ext_hdrs` — the sticky IPV6_HOPOPTS /
    // IPV6_DSTOPTS options are not exposed by `libc` on Darwin).
    #[cfg(target_os = "linux")]
    {
        use std::os::fd::AsRawFd;

        let attach_specs = conf.attach_ext_hdrs();
        if !attach_specs.is_empty() {
            if conf.remote_addr.is_ipv6() {
                apply_attach_ext_hdrs(socket.as_raw_fd(), &attach_specs).map_err(|e| {
                    crate::StartupError::new(format!("Cannot attach requested IPv6 header: {e}"))
                })?;
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
                 request TLV(s) are still sent (draft-ietf-ippm-stamp-ext-hdr-15 §4.2)"
            );
        }
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        if conf.cos {
            log::warn!(
                "Egress DSCP/ECN marking is only supported on Linux/macOS; \
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

    // Connect after setting sticky IPv6 headers: IPV6_HOPOPTS/IPV6_DSTOPTS
    // invalidate Linux's cached route. Connecting last populates the route
    // used by the pre-send MTU check, without transmitting a probe first.
    if let Err(e) = socket.connect(remote_addr).await {
        return Err(crate::StartupError::new(format!(
            "Cannot connect to address {remote_addr}: {e}"
        )));
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
        return Err(crate::StartupError::new(
            "Authenticated mode (-A A) requires HMAC key (--hmac-key or --hmac-key-file)",
        ));
    }

    // A key source that failed to load is a configuration error in either mode:
    // the key also signs the TLV HMAC this sender may originate, so continuing
    // without it would silently send unauthenticated TLVs.
    if hmac_key.is_none() && crate::receiver::single_hmac_key_source_configured(conf) {
        return Err(crate::StartupError::new(
            "an HMAC key source was configured (--hmac-key, --hmac-key-file or \
             --hmac-key-dir) but no usable key could be loaded; see the error above. \
             Refusing to run without the key that was asked for",
        ));
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
    let mut measurements = Measurements::new(conf.reflected_control_count);
    measurements.monitor = Some(session_state::Monitor::new(
        conf.session_loss_threshold,
        Duration::from_secs(u64::from(conf.timeout)),
    ));
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
    // Allow the maximum UDP payload so padded replies are not truncated.
    // Allocate once per run.
    let mut recv_buf = vec![0u8; MAX_UDP_PAYLOAD];
    let timeout = Duration::from_secs(conf.timeout as u64);

    // Scale Type-12 intervals with AIMD (cos-ecn-01 §3.4-3).
    // Skip the static TLV when scaling is active; rebuild it on each send.
    let reflected_control_requested =
        conf.reflected_control_count > 1 || conf.reflected_control_no_ext_hdr;
    let scale_reflected_control = ecn_response_active && reflected_control_requested;

    // Warn once about overlapping bursts (RFC 10052 §5).
    // Use stderr so the advisory is visible regardless of log filtering.
    if let Some(warning) = conf.reflected_burst_pacing_warning() {
        eprintln!("Warning: {warning}");
    }

    // RFC 8972 §3 session identification and zeroed-SSID control. Zero means
    // no SSID was assigned, so only nonzero configured IDs require a match.
    let expected_ssid = conf.ssid.filter(|s| *s != 0);
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

    // Access Reports are event-driven (RFC 8972 §4.6).
    // `tick` attaches the initial report and retries; omit it from static TLVs.
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

    // Build Destination Node Address TLV (RFC 9503 §3)
    if let Some(addr) = conf.dest_node_addr {
        extra_tlvs.push(DestinationNodeAddressTlv::new(addr).to_raw());
        log::info!("Destination Node Address TLV enabled ({})", addr);
    }

    // Build Return Path TLV (RFC 9503 §4) — at most one
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

    // Build Reflected Test Packet Control TLV (RFC 10052 §3).
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

    // Build BER TLVs (draft-gandhi-ippm-stamp-ber-07 §4). All three are emitted
    // together, paired with an Extra Padding TLV filled with the repeated pattern.
    if conf.ber {
        let pattern_bytes: Vec<u8> = if let Some(hex) = conf.ber_pattern.as_deref() {
            match crate::ber::parse_pattern(hex) {
                Ok(bytes) => bytes,
                Err(e) => {
                    return Err(crate::StartupError::new(format!(
                        "Invalid --ber-pattern ({hex}): {e}"
                    )));
                }
            }
        } else {
            // Default 0xFF00 per BER-07 §4.1.1.
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
    // (draft-ietf-ippm-stamp-ext-hdr-15 §§4.2, 6.2). The value is
    // Requested(4) + Reflected(Length-4): sent with a zero (or selector)
    // Requested field and a zero-initialised Reflected field; the reflector
    // fills the Reflected field when it has raw-capture access to IP headers,
    // or echoes with the C flag.
    extra_tlvs.extend(reflected_header_request_tlvs(conf));

    // RFC 8972 §4.8 origination is separate from holding a key: --tlv-hmac
    // off keeps the key for verifying replies without putting an HMAC TLV on
    // the wire. Decided here, before the MTU budget below, so the 20-byte
    // reserve matches what will actually be sent. `validate()` has already
    // ensured `on` has a key and rejected `off` in authenticated mode.
    let originate_tlv_hmac = match conf.tlv_hmac {
        TlvHmacMode::Auto | TlvHmacMode::On => true,
        TlvHmacMode::Off => false,
    };

    // draft-ietf-ippm-stamp-ext-hdr-15 §4.2/§6.2 MTU rule (sender half): the
    // resulting test packets MUST NOT exceed the IP/IPv6 MTU after adding the
    // Reflected Fixed/IPv6 Extension Header TLVs; if necessary, one or more of
    // those TLVs MUST be removed. Compare the worst-case assembled packet size
    // against the egress interface MTU (route MTU via getsockopt on Linux;
    // fail closed for header requests when unknown) and trim Type 246/247 TLVs to
    // fit. Only these two TLV types are removed — the draft binds this rule to
    // them specifically; oversize from other TLVs is out of scope here.
    let header_requests = !conf.attach_ext_hdr.is_empty()
        || !conf.reflected_fixed_hdr.is_empty()
        || !conf.reflected_ipv6_ext_hdr.is_empty();
    let header_fixed_overhead;
    let header_template: Option<Vec<RawTlv>>;
    let mut header_trimmed;
    {
        let route_mtu = egress_mtu(&socket);
        if header_requests && route_mtu.is_none() {
            return Err(crate::StartupError::new(
                "Header reflection requires a known egress route MTU",
            ));
        }
        let mtu = route_mtu.unwrap_or(if conf.remote_addr.is_ipv6() {
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
            AUTH_BASE_SIZE
        } else {
            UNAUTH_BASE_SIZE
        };
        // Worst-case per-packet extras: HMAC TLV (20), Direct Measurement (16),
        // Access Report (8) — included when they can appear. The HMAC TLV
        // reserve follows the origination decision, not mere key possession:
        // with --tlv-hmac off no HMAC TLV is sent, and reserving for one
        // would trim Type 246/247 requests that actually fit on the wire.
        let hmac_tlv = if hmac_key.is_some() && (use_auth || originate_tlv_hmac) {
            20
        } else {
            0
        };
        let dm = if conf.direct_measurement { 16 } else { 0 };
        let access = if access_report_state.is_some() { 8 } else { 0 };
        const UDP_HEADER: usize = 8;
        let fixed_overhead = ip_hdr + attached_ext + UDP_HEADER + base + hmac_tlv + dm + access;
        header_fixed_overhead = fixed_overhead;
        if conf.ber {
            crate::ber::fit_padding(&mut extra_tlvs, mtu, fixed_overhead)
                .map_err(|e| crate::StartupError::new(e.to_string()))?;
        }
        header_template = header_requests.then(|| extra_tlvs.clone());
        let removed = enforce_egress_mtu(&mut extra_tlvs, mtu, fixed_overhead);
        log_header_trim(removed, mtu);
        header_trimmed = removed;
    }

    let mut ber = conf.ber.then(|| {
        BerCollector::new(
            crate::ber::parse_pattern(conf.ber_pattern.as_deref().unwrap_or("ff00"))
                .expect("validated BER pattern"),
            extra_tlvs
                .iter()
                .find(|t| t.tlv_type == TlvType::ExtraPadding)
                .map_or(0, |t| t.value.len()),
            !conf.ber_omit_burst,
            Duration::from_millis(u64::from(conf.ber_interval) * u64::from(conf.send_delay)),
            Instant::now(),
            [conf.ber_bit_threshold, conf.ber_packet_threshold],
        )
    });

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
        if !originate_tlv_hmac && hmac_key.is_some() {
            log::info!(
                "not originating an HMAC TLV per --tlv-hmac off; the configured \
                 key is still used to verify reflected TLV HMACs"
            );
        }
        SendMode::OpenTlv {
            tlv_key: originate_tlv_hmac.then_some(hmac_key.as_ref()).flatten(),
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

    // The route MTU can change during a run. Each probe trims from the
    // untrimmed startup set, so a temporary MTU drop does not remove header
    // requests for the rest of the run. A failed lookup keeps the last set.
    let mut prepare_header_requests = |extra_tlvs: &mut Vec<RawTlv>| {
        let Some(template) = &header_template else {
            return;
        };
        match egress_mtu(&socket) {
            Some(mtu) => {
                extra_tlvs.clone_from(template);
                let removed = enforce_egress_mtu(extra_tlvs, mtu as usize, header_fixed_overhead);
                if removed != header_trimmed {
                    log_header_trim(removed, mtu as usize);
                    header_trimmed = removed;
                }
            }
            None => crate::eprintln_throttled!(
                "Cannot read the route MTU; keeping the previous header-reflection requests"
            ),
        }
    };
    for _ in 0..conf.count {
        prepare_header_requests(&mut extra_tlvs);
        if let Some(ber) = ber.as_mut() {
            ber.advance(Instant::now());
            ber.filter_requests(&mut extra_tlvs);
        }
        let seq_num = sess.generate_sequence_number();
        let send_time = Instant::now();
        let send_timestamp = generate_timestamp(conf.clock_source);

        // Advance Access Report state and attach the initial report or an
        // expired retry (RFC 8972 §4.6).
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

        // A failed send still waits out the send delay below; skipping the
        // wait would turn a persistent error into an unpaced loop.
        match socket.send(&buf).await {
            Err(e) => crate::eprintln_throttled!("Failed to send packet {seq_num}: {e}"),
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
                measurements.sent(
                    seq_num,
                    PendingPacket {
                        send_time,
                        send_timestamp,
                    },
                    packets_sent,
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
            }
        }

        // Receive until the next send deadline. AIMD supplies the interval when
        // active (cos-ecn-01 §3.4), including feedback from earlier iterations.
        let send_delay = congestion
            .as_ref()
            .map(|c| c.controller.current_interval())
            .unwrap_or_else(|| Duration::from_millis(conf.send_delay as u64));
        let deadline = tokio::time::Instant::now() + send_delay;

        loop {
            let state_deadline = measurements.monitor.as_ref().and_then(|m| m.deadline());
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
                                local_error_estimate: Some(error_estimate),
                                measurements: Some(&mut measurements),
                                ber: ber.as_mut(),
                                reflector_utc_offset: conf.reflector_utc_offset,
                                pending: &mut pending,
                                rtt_collector: &mut rtt_collector,
                                owd_collector: &mut owd_collector,
                                packets_received: &mut packets_received,
                                print_stats: conf.print_stats,
                                output_format: conf.output_format,
                                hmac_key: hmac_key.as_ref(),
                                expected_sender_msid: conf.micro_session_id,
                                expected_reflector_msid: conf.reflector_member_link_id,
                                latched_reflector_msid: &mut latched_reflector_msid,
                                access_report_state: access_report_state.as_mut(),
                                congestion: congestion.as_mut(),
                                expected_ssid,
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
                            crate::eprintln_throttled!("Receive error: {e}");
                            if !is_icmp_feedback(&e) {
                                // Keep the send schedule even if the socket
                                // keeps failing.
                                tokio::time::sleep_until(deadline).await;
                                break;
                            }
                        }
                    }
                }

                _ = async {
                    match state_deadline {
                        Some(at) => tokio::time::sleep_until(at.into()).await,
                        None => std::future::pending::<()>().await,
                    }
                } => {
                    if let Some(m) = measurements.monitor.as_mut() { m.advance(Instant::now()); }
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
                        .with_measurements(measurements.snapshot())
                        .with_ber(ber.as_mut().map(|b| b.snapshot(Instant::now())))
                        .with_owd(&owd_collector)
                        .with_access_report(access_report_state.as_ref().map(|state| state.summary()))
                        .with_congestion(congestion.as_ref().map(|state| state.summary()));
                    output.print(&interim, true);
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
                        crate::metrics::sender_metrics::record_packets_lost(1);
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

    if let Some(m) = measurements.monitor.as_mut() {
        m.idle();
    }

    // Wait for remaining replies, checking the live zeroed-SSID stop flag.
    // A stop reply can arrive during this phase and must also end retries.
    let stopped_on_zero_ssid = |seen: bool| seen && conf.on_zero_ssid == ZeroSsidAction::Stop;
    let wait_start = Instant::now();
    while !stopped_on_zero_ssid(zero_ssid_seen)
        && (!pending.is_empty() || measurements.needs_burst_wait())
        && wait_start.elapsed() < timeout
    {
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
                    local_error_estimate: Some(error_estimate),
                    measurements: Some(&mut measurements),
                    ber: ber.as_mut(),
                    reflector_utc_offset: conf.reflector_utc_offset,
                    pending: &mut pending,
                    rtt_collector: &mut rtt_collector,
                    owd_collector: &mut owd_collector,
                    packets_received: &mut packets_received,
                    print_stats: conf.print_stats,
                    output_format: conf.output_format,
                    hmac_key: hmac_key.as_ref(),
                    expected_sender_msid: conf.micro_session_id,
                    expected_reflector_msid: conf.reflector_member_link_id,
                    latched_reflector_msid: &mut latched_reflector_msid,
                    access_report_state: access_report_state.as_mut(),
                    congestion: congestion.as_mut(),
                    expected_ssid,
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
                crate::eprintln_throttled!("Receive error during final wait: {e}");
                if !is_icmp_feedback(&e) {
                    break;
                }
            }
            Err(_) => break, // Timeout expired
        }
    }

    // Continue Access Report retries after the main loop (RFC 8972 §4.6),
    // including `--count 1` runs. Keep receiving so an echo disarms the timer.
    // `tick` bounds retries; each retransmission carries identical report bytes.
    // Only continue an exchange the main loop started (`--count 0` starts none).
    while !stopped_on_zero_ssid(zero_ssid_seen)
        && access_report_state
            .as_ref()
            .is_some_and(|state| state.has_started() && !state.is_terminal())
    {
        let now = Instant::now();
        if let Some(m) = measurements.monitor.as_mut() {
            m.advance(now);
        }
        let attach = access_report_state
            .as_mut()
            .map(|state| state.tick(now))
            .unwrap_or(false);

        if attach {
            prepare_header_requests(&mut extra_tlvs);
            // Rebuild the test packet with the same Access ID and Return Code
            // so the report's wire bytes are identical on every retry.
            let seq_num = sess.generate_sequence_number();
            let send_time = Instant::now();
            let send_timestamp = generate_timestamp(conf.clock_source);

            let mut tlvs = extra_tlvs.clone();
            if let Some(ber) = ber.as_ref() {
                ber.filter_requests(&mut tlvs);
            }
            if conf.direct_measurement {
                tlvs.push(DirectMeasurementTlv::new(packets_sent + 1).to_raw());
            }
            let access_id = conf.access_report.expect(
                "attach implies access_report_state is Some, which implies conf.access_report is Some",
            );
            tlvs.push(AccessReportTlv::new(access_id, conf.access_return_code).to_raw());
            if scale_reflected_control {
                // Retries must also carry the scaled control TLV (§3.4-3).
                // It is absent from `extra_tlvs`, so rebuild it with the current AIMD factor.
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
                    measurements.sent(
                        seq_num,
                        PendingPacket {
                            send_time,
                            send_timestamp,
                        },
                        packets_sent,
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
                Err(e) => crate::eprintln_throttled!(
                    "Failed to send Access Report retransmission {seq_num}: {e}"
                ),
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
        let deadline = measurements
            .monitor
            .as_ref()
            .and_then(|m| m.deadline())
            .map_or(deadline, |state_deadline| deadline.min(state_deadline));
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
                            local_error_estimate: Some(error_estimate),
                            measurements: Some(&mut measurements),
                            ber: ber.as_mut(),
                            reflector_utc_offset: conf.reflector_utc_offset,
                            pending: &mut pending,
                            rtt_collector: &mut rtt_collector,
                            owd_collector: &mut owd_collector,
                            packets_received: &mut packets_received,
                            print_stats: conf.print_stats,
                            output_format: conf.output_format,
                            hmac_key: hmac_key.as_ref(),
                            expected_sender_msid: conf.micro_session_id,
                            expected_reflector_msid: conf.reflector_member_link_id,
                            latched_reflector_msid: &mut latched_reflector_msid,
                            access_report_state: access_report_state.as_mut(),
                            congestion: congestion.as_mut(),
                            expected_ssid,
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
                        crate::eprintln_throttled!(
                            "Receive error while awaiting Access Report ack: {e}"
                        );
                        if !is_icmp_feedback(&e) {
                            break;
                        }
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

    if let Some(m) = measurements.monitor.as_mut() {
        m.idle();
    }
    Ok(rtt_collector
        .snapshot(packets_sent, packets_lost)
        .with_measurements(measurements.snapshot())
        .with_ber(ber.as_mut().map(|b| b.snapshot(Instant::now())))
        .with_owd(&owd_collector)
        .with_access_report(access_report_state.as_ref().map(|state| state.summary()))
        .with_congestion(congestion.as_ref().map(|state| state.summary())))
}

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
/// pending error-queue events). `try_io` clears stale readiness first;
/// callers can drain the error queue and retry without spinning.
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
        return socket.try_io(tokio::io::Interest::READABLE, || {
            let msg = nix::sys::socket::recvmsg::<nix::sys::socket::SockaddrStorage>(
                socket.as_raw_fd(),
                &mut iov,
                Some(&mut cmsg_buf),
                nix::sys::socket::MsgFlags::MSG_DONTWAIT,
            )
            .map_err(|e| std::io::Error::from_raw_os_error(e as i32))?;
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
        });
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
    let want_msid = ctx.expected_sender_msid.is_some()
        || ctx.expected_reflector_msid.is_some()
        || ctx.latched_reflector_msid.is_some();
    let use_tlvs = use_tlvs || want_msid;
    // Learning is committed only when the entire reply is accepted for a pending probe.
    let mut next_reflector_msid = *ctx.latched_reflector_msid;
    let recv_time = Instant::now();
    // T4: prefer the kernel receive timestamp (taken at packet arrival);
    // otherwise the sender's wall-clock timestamp, captured as early as
    // possible (before parsing) for the reverse one-way-delay computation.
    let sender_recv_ts = kernel_t4.unwrap_or_else(|| generate_timestamp(clock_source));

    let mut ber_observation = None;

    // Parse response and validate TLVs if extension mode is enabled
    // Use lenient parsing per RFC 8762 §4.6 to handle short packets.
    let (
        seq_num,
        reflector_recv_ts,
        reflector_send_ts,
        sender_ttl,
        telemetry,
        reflected_ssid,
        reflector_error,
        reflector_seq,
    ) = if use_auth {
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
                if !verify_packet_hmac(key, &canonical_buf, AUTH_HMAC_OFFSET, &hmac) {
                    crate::eprintln_throttled!(
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
            let telemetry = if ext_packet.has_tlvs() || want_msid {
                match validate_reflected_tlvs(
                    &ext_packet.tlvs,
                    data,
                    AUTH_BASE_SIZE,
                    ctx.hmac_key,
                    ctx.expected_sender_msid,
                    ctx.expected_reflector_msid,
                    &mut next_reflector_msid,
                    ctx.access_report_state.is_some(),
                    ctx.congestion.is_some(),
                    #[cfg(feature = "metrics")]
                    ctx.metrics_enabled,
                ) {
                    Ok(info) => Some(info),
                    Err(reason) => {
                        crate::eprintln_throttled!(
                            "Discarding reflected packet seq={}: {}",
                            seq_num,
                            reason
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

            if let Some(ber) = ctx.ber.as_ref() {
                ber_observation = observation(
                    &ext_packet.tlvs,
                    data,
                    AUTH_BASE_SIZE,
                    ctx.hmac_key,
                    &ber.pattern,
                    ber.summary.padding_bytes,
                    ber.want_burst,
                );
            }

            (
                seq_num,
                recv_ts,
                send_ts,
                ttl,
                telemetry,
                base.ssid,
                base.error_estimate,
                base.sequence_number,
            )
        } else {
            // Parse base packet only (lenient, returns canonical buffer)
            let (packet, canonical_buf) = ReflectedPacketAuthenticated::from_bytes_lenient(data);
            let seq_num = packet.sess_sender_seq_number;
            let recv_ts = packet.receive_timestamp;
            let send_ts = packet.timestamp;
            let ttl = packet.sess_sender_ttl;
            let hmac = packet.hmac;

            // Verify HMAC against canonical buffer when key is present (RFC 8762 §4.4, §4.6)
            if let Some(key) = ctx.hmac_key {
                if !verify_packet_hmac(key, &canonical_buf, AUTH_HMAC_OFFSET, &hmac) {
                    crate::eprintln_throttled!(
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
                packet.ssid,
                packet.error_estimate,
                packet.sequence_number,
            )
        }
    } else if use_tlvs {
        // Parse as extended packet with TLVs (unauthenticated, lenient)
        let ext_packet = ExtendedReflectedPacketUnauthenticated::from_bytes_lenient(data);
        let base = &ext_packet.base;

        // Validate TLVs if present
        let telemetry = if ext_packet.has_tlvs() || want_msid {
            match validate_reflected_tlvs(
                &ext_packet.tlvs,
                data,
                UNAUTH_BASE_SIZE,
                ctx.hmac_key,
                ctx.expected_sender_msid,
                ctx.expected_reflector_msid,
                &mut next_reflector_msid,
                ctx.access_report_state.is_some(),
                ctx.congestion.is_some(),
                #[cfg(feature = "metrics")]
                ctx.metrics_enabled,
            ) {
                Ok(info) => Some(info),
                Err(reason) => {
                    crate::eprintln_throttled!(
                        "Discarding reflected packet seq={}: {}",
                        base.sess_sender_seq_number,
                        reason
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

        if let Some(ber) = ctx.ber.as_ref() {
            ber_observation = observation(
                &ext_packet.tlvs,
                data,
                UNAUTH_BASE_SIZE,
                ctx.hmac_key,
                &ber.pattern,
                ber.summary.padding_bytes,
                ber.want_burst,
            );
        }

        (
            base.sess_sender_seq_number,
            base.receive_timestamp,
            base.timestamp,
            base.sess_sender_ttl,
            telemetry,
            base.ssid,
            base.error_estimate,
            base.sequence_number,
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
            packet.ssid,
            packet.error_estimate,
            packet.sequence_number,
        )
    };

    if want_msid
        && !ctx.pending.contains_key(&seq_num)
        && !ctx
            .measurements
            .as_ref()
            .is_some_and(|m| m.answered(seq_num))
    {
        log::debug!("Discarding micro-session reply for unknown sequence {seq_num}");
        return;
    }

    // RFC 8972 §3: a nonzero SSID identifies the session and must match.
    // Figure 2 has one SSID field, after the reflector's Error Estimate.
    // Zero is the legacy-peer sentinel and uses the separate operator policy.
    // Reject other sessions before applying measurement or control state.
    if let Some(expected) = ctx.expected_ssid {
        if reflected_ssid != 0 && reflected_ssid != expected {
            log::debug!(
                "Discarding reflected packet seq={seq_num}: SSID {reflected_ssid} differs from {expected}"
            );
            return;
        }
        if reflected_ssid == 0 {
            let first_time = !*ctx.zero_ssid_seen;
            *ctx.zero_ssid_seen = true;
            if first_time {
                match ctx.on_zero_ssid {
                    ZeroSsidAction::Continue => eprintln!(
                        "Warning: reflector returned a zeroed SSID (sent {expected}, \
                         got 0) — it is not demultiplexing sessions on SSID. \
                         Continuing per --on-zero-ssid=continue (RFC 8972 §3)."
                    ),
                    ZeroSsidAction::Stop => eprintln!(
                        "Reflector returned a zeroed SSID (sent {expected}, got 0); \
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

    if let Some(measurements) = ctx.measurements.as_mut() {
        let key = ReplyKey {
            sender: seq_num,
            reflector: reflector_seq,
            t3: reflector_send_ts,
        };
        let Some((probe, ordinal)) = measurements.accept(key, ctx.pending.get(&seq_num).copied())
        else {
            return; // duplicate or outside retained sent-probe history
        };
        let reference = chrono::Utc::now().timestamp();
        let t4_ns = timestamp_to_unix_nanos(sender_recv_ts, clock_source, reference);
        measurements.observe(ReplyObservation {
            key,
            rtt_ns: recv_time.duration_since(probe.send_time).as_nanos() as u64,
            t4_ns,
            format: ErrorEstimate::from_wire(reflector_error).clock_format(),
            reference,
            offset: ctx.reflector_utc_offset,
            ordinal,
            dm: telemetry.as_ref().and_then(|t| t.direct_measurement),
            follow: telemetry.as_ref().and_then(|t| t.follow_up),
            quality: ctx
                .local_error_estimate
                .map(|e| (e, ErrorEstimate::from_wire(reflector_error))),
        });
    }

    // RFC 8972 §4.6: a usable Access Report echo disarms its timer. This
    // typed decision is independent of diagnostics and of pending RTT state.
    // Session identity was checked above; U/M/I/HMAC gating happened in validation.
    if let Some(state) = ctx.access_report_state.as_mut() {
        if telemetry
            .as_ref()
            .is_some_and(|info| info.access_report.is_some())
        {
            state.acknowledge();
        }
    }

    // Apply CE feedback from validated forward EC2 or the reply's IP ECN
    // (cos-ecn-01 §3.4). Reverse ECN is mutable IP metadata outside TLV integrity.
    // Congestion feedback does not require a pending RTT sample.
    if let Some(state) = ctx.congestion.as_mut() {
        let forward_ce = telemetry.as_ref().is_some_and(|info| info.forward_ce);
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
        if let (Some(ber), Some(observation)) = (ctx.ber.as_mut(), ber_observation) {
            ber.record(observation, recv_time);
        }
        *ctx.latched_reflector_msid = next_reflector_msid;
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
        let remote_format = ErrorEstimate::from_wire(reflector_error).clock_format();
        let reference = chrono::Utc::now().timestamp();
        let remote_reference = reference + i64::from(ctx.reflector_utc_offset);
        let remote_offset_ns = i128::from(ctx.reflector_utc_offset) * 1_000_000_000;
        let decoded = (
            timestamp_to_unix_nanos(pending_packet.send_timestamp, clock_source, reference),
            timestamp_to_unix_nanos(reflector_recv_ts, remote_format, remote_reference),
            timestamp_to_unix_nanos(reflector_send_ts, remote_format, remote_reference),
            timestamp_to_unix_nanos(sender_recv_ts, clock_source, reference),
        );
        if let (Some(t1), Some(t2), Some(t3), Some(t4)) = decoded {
            ctx.owd_collector.record_with_quality(
                OwdSample {
                    seq: seq_num,
                    forward_ns: (t2 - remote_offset_ns - t1) as i64,
                    reverse_ns: (t4 - (t3 - remote_offset_ns)) as i64,
                },
                ctx.local_error_estimate
                    .map(|e| (e, ErrorEstimate::from_wire(reflector_error))),
            );
        } else {
            log::debug!("Invalid PTP nanoseconds on seq={seq_num}; omitting one-way delay");
        }

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
            let tlv_status = telemetry
                .as_ref()
                .map_or(String::new(), |info| format!(" tlv=[{}]", info));
            let detail = format!(
                "seq={} rtt={:.3}ms ttl={} reflector_recv_ts={} reflector_send_ts={}{}",
                seq_num,
                rtt_ns as f64 / 1_000_000.0,
                sender_ttl,
                reflector_recv_ts,
                reflector_send_ts,
                tlv_status
            );
            if ctx.output_format == crate::stats::OutputFormat::Text {
                println!("{detail}");
            } else {
                // Explicit -R output stays visible even when RUST_LOG=off.
                eprintln!("{detail}");
            }
        }
    } else if ctx.measurements.is_none() {
        eprintln!("Received response for unknown sequence number: {}", seq_num);
    }
}

#[cfg(test)]
mod tests;
