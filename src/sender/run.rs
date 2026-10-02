//! One sender run: setup, the probe schedule, the final reply drain, and
//! Access Report retransmissions (RFC 8972 §4.6).

use super::*;

/// How each probe is built; decided once at startup.
enum SendMode {
    /// Authenticated base packet with TLVs and the TLV HMAC.
    AuthTlv { key: HmacKey },
    /// Authenticated base packet only.
    AuthBase { key: HmacKey },
    /// Unauthenticated base packet with TLVs, signed when a key is given.
    OpenTlv { tlv_key: Option<HmacKey> },
    /// Unauthenticated base packet only.
    OpenBase,
}

/// What a receive wait ends on, besides its deadline.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Wait {
    /// The next probe is due.
    NextSend,
    /// Every probe has a reply (or its burst copies are in), or time is up.
    Drain,
    /// The Access Report timer expires or the report is acknowledged.
    AccessReport,
}

/// State of one sender run.
pub(super) struct SenderRun<'a> {
    conf: &'a Configuration,
    socket: UdpSocket,
    use_auth: bool,
    use_tlvs: bool,
    send_mode: SendMode,
    ecn_response_active: bool,
    kernel_rx_enabled: bool,
    #[cfg(all(feature = "hwtstamp", any(target_os = "linux", target_os = "macos")))]
    kernel_ts: crate::hwtstamp::EnabledTimestamping,
    /// Mirrors the kernel's per-send OPT_ID counter; `send_probe` is the
    /// only send site.
    #[cfg(all(feature = "hwtstamp", target_os = "linux"))]
    tx_counter: u32,
    /// OPT_ID to sequence number, for TX timestamps still to arrive.
    #[cfg(all(feature = "hwtstamp", target_os = "linux"))]
    tx_id_to_seq: HashMap<u32, u32>,
    error_estimate: ErrorEstimate,
    error_estimate_wire: u16,
    hmac_key: Option<HmacKey>,
    sess: Session,
    pending: HashMap<u32, PendingPacket>,
    measurements: Measurements,
    /// `(deadline, seq)` in send order, for O(1) loss expiry with lazy
    /// deletion of answered probes.
    expiry_queue: VecDeque<(Instant, u32)>,
    rtt_collector: RttCollector,
    owd_collector: OwdCollector,
    packets_sent: u32,
    packets_received: u32,
    packets_lost: u32,
    latched_reflector_msid: Option<u16>,
    recv_buf: Vec<u8>,
    /// Ancillary data for `recvmsg`, reused across replies.
    cmsg_buf: Vec<u8>,
    timeout: Duration,
    scale_reflected_control: bool,
    expected_ssid: Option<u16>,
    zero_ssid_seen: bool,
    congestion: Option<CongestionState>,
    access_report_state: Option<AccessReportRetransmitState>,
    /// TLVs sent with every probe; per-probe TLVs are added at build time.
    extra_tlvs: Vec<RawTlv>,
    /// Untrimmed TLV set when header reflection is requested; each probe
    /// trims from it for the current route MTU.
    header_template: Option<Vec<RawTlv>>,
    header_fixed_overhead: usize,
    header_trimmed: usize,
    ber: Option<BerCollector>,
    report_timer: Option<tokio::time::Interval>,
    #[cfg(feature = "metrics")]
    metrics_enabled: bool,
    #[cfg(all(unix, feature = "snmp"))]
    snmp_stats: SnmpStats,
}

impl<'a> SenderRun<'a> {
    /// Opens and configures the socket and builds the static probe TLVs.
    pub(super) async fn open(
        conf: &'a Configuration,
        #[cfg(all(unix, feature = "snmp"))] snmp_stats: SnmpStats,
    ) -> Result<Self, crate::StartupError> {
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
                        crate::StartupError::new(format!(
                            "Cannot attach requested IPv6 header: {e}"
                        ))
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
        let sender_tx_counter: u32 = 0;
        #[cfg(all(feature = "hwtstamp", target_os = "linux"))]
        let tx_id_to_seq: std::collections::HashMap<u32, u32> = std::collections::HashMap::new();

        // Build error estimate from configuration with Z flag set based on clock source
        let error_estimate = ErrorEstimate::with_clock_format(
            conf.clock_synchronized,
            conf.clock_source,
            conf.error_scale,
            conf.error_multiplier,
        )
        .map_err(crate::StartupError::new)?;
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
        let pending: HashMap<u32, PendingPacket> = HashMap::new();
        let mut measurements = Measurements::new(conf.reflected_control_count);
        measurements.monitor = Some(session_state::Monitor::new(
            conf.session_loss_threshold,
            Duration::from_secs(u64::from(conf.timeout)),
        ));
        // Time-ordered expiry queue for O(k) eviction instead of O(n) HashMap scan.
        // Entries are (deadline, seq_num). Since packets are sent sequentially,
        // deadlines are naturally ordered. Lazy deletion skips already-received entries.
        let expiry_queue: VecDeque<(Instant, u32)> = VecDeque::new();
        let rtt_collector = RttCollector::new();
        let owd_collector = OwdCollector::new();
        let packets_sent: u32 = 0;
        let packets_received: u32 = 0;
        let packets_lost: u32 = 0;
        // Zero-config latch for the Reflector Micro-session ID (RFC 9534
        // §3.2-11): populated from the first validly-received reply when
        // `--reflector-member-link-id` was not given; persists for the whole
        // session so later replies are checked for self-consistency.
        let latched_reflector_msid: Option<u16> = None;
        // Allow the maximum UDP payload so padded replies are not truncated.
        // Allocate once per run.
        let recv_buf = vec![0u8; MAX_UDP_PAYLOAD];
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
        let zero_ssid_seen = false;

        let congestion = ecn_response_active.then(|| {
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
        let access_report_state = conf.access_report.map(|access_id| {
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
        let mut ber_pattern = None;
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
            extra_tlvs.push(BerPatternTlv::new(pattern_bytes.clone()).to_raw());
            ber_pattern = Some(pattern_bytes);
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
        let header_trimmed;
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

        let ber = ber_pattern.map(|pattern| {
            BerCollector::new(
                pattern,
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

        let send_mode = if let Some(key) = hmac_key.clone().filter(|_| use_auth) {
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
                tlv_key: hmac_key.clone().filter(|_| originate_tlv_hmac),
            }
        } else {
            SendMode::OpenBase
        };

        let report_timer = (conf.report_interval > 0).then(|| {
            let period = Duration::from_secs(conf.report_interval as u64);
            // The first tick would fire immediately.
            tokio::time::interval_at(tokio::time::Instant::now() + period, period)
        });

        Ok(Self {
            conf,
            socket,
            use_auth,
            use_tlvs,
            send_mode,
            ecn_response_active,
            kernel_rx_enabled,
            #[cfg(all(feature = "hwtstamp", any(target_os = "linux", target_os = "macos")))]
            kernel_ts: sender_kernel_ts,
            #[cfg(all(feature = "hwtstamp", target_os = "linux"))]
            tx_counter: sender_tx_counter,
            #[cfg(all(feature = "hwtstamp", target_os = "linux"))]
            tx_id_to_seq,
            error_estimate,
            error_estimate_wire,
            hmac_key,
            sess,
            pending,
            measurements,
            expiry_queue,
            rtt_collector,
            owd_collector,
            packets_sent,
            packets_received,
            packets_lost,
            latched_reflector_msid,
            recv_buf,
            cmsg_buf: vec![0; 256],
            timeout,
            scale_reflected_control,
            expected_ssid,
            zero_ssid_seen,
            congestion,
            access_report_state,
            extra_tlvs,
            header_template,
            header_fixed_overhead,
            header_trimmed,
            ber,
            report_timer,
            #[cfg(feature = "metrics")]
            metrics_enabled,
            #[cfg(all(unix, feature = "snmp"))]
            snmp_stats,
        })
    }

    /// Sends `--count` probes on schedule, waits for outstanding replies, then
    /// finishes any Access Report exchange.
    pub(super) async fn run(
        mut self,
        output: &mut crate::stats::StatsOutput,
    ) -> Result<StatsSnapshot, crate::StartupError> {
        // Each probe is due one interval after the previous due time, so the
        // time spent building and sending does not stretch the interval. A
        // late probe goes out at once without catching up on missed ones.
        let mut due = tokio::time::Instant::now();
        for _ in 0..self.conf.count {
            let attach_access_report = self
                .access_report_state
                .as_mut()
                .is_some_and(|state| state.tick(Instant::now()));
            self.send_probe(attach_access_report).await;
            due = (due + self.send_interval()).max(tokio::time::Instant::now());
            self.receive_until(due, Wait::NextSend, output).await;
            self.expire();
            if self.stopped_on_zero_ssid() {
                break;
            }
        }
        if let Some(m) = self.measurements.monitor.as_mut() {
            m.idle();
        }

        let drain_until = tokio::time::Instant::now() + self.timeout;
        self.receive_until(drain_until, Wait::Drain, output).await;

        // Access Report retries continue after the last probe (RFC 8972
        // §4.6), including `--count 1` runs, for an exchange the probe loop
        // started. Each retry carries identical report bytes.
        while !self.stopped_on_zero_ssid()
            && self
                .access_report_state
                .as_ref()
                .is_some_and(|state| state.has_started() && !state.is_terminal())
        {
            if self
                .access_report_state
                .as_mut()
                .is_some_and(|state| state.tick(Instant::now()))
            {
                self.send_probe(true).await;
                continue;
            }
            let Some(deadline) = self
                .access_report_state
                .as_ref()
                .and_then(|state| state.armed_deadline())
            else {
                break;
            };
            let deadline = tokio::time::Instant::from_std(deadline);
            if !self
                .receive_until(deadline, Wait::AccessReport, output)
                .await
            {
                break;
            }
        }

        // Probes still unanswered are lost.
        let remaining_lost = self.pending.len() as u32;
        self.packets_lost += remaining_lost;
        #[cfg(feature = "metrics")]
        if self.metrics_enabled && remaining_lost > 0 {
            crate::metrics::sender_metrics::record_packets_lost(remaining_lost as u64);
        }
        #[cfg(all(unix, feature = "snmp"))]
        if let Some(stats) = &self.snmp_stats {
            stats.inc_lost_by(remaining_lost);
        }
        if let Some(m) = self.measurements.monitor.as_mut() {
            m.idle();
        }
        Ok(self.snapshot())
    }

    /// Current probe interval: the AIMD interval when congestion response is
    /// active (cos-ecn-01 §3.4), otherwise `--send-delay`.
    fn send_interval(&self) -> Duration {
        self.congestion
            .as_ref()
            .map(|c| c.controller.current_interval())
            .unwrap_or_else(|| Duration::from_millis(self.conf.send_delay as u64))
    }

    /// RFC 8972 §3: `--on-zero-ssid=stop` ends the run at the first reply
    /// with a zeroed SSID.
    fn stopped_on_zero_ssid(&self) -> bool {
        self.zero_ssid_seen && self.conf.on_zero_ssid == ZeroSsidAction::Stop
    }

    fn wait_over(&self, wait: Wait) -> bool {
        match wait {
            Wait::NextSend => false,
            Wait::Drain => {
                self.stopped_on_zero_ssid()
                    || (self.pending.is_empty() && !self.measurements.needs_burst_wait())
            }
            Wait::AccessReport => {
                self.stopped_on_zero_ssid()
                    || self
                        .access_report_state
                        .as_ref()
                        .is_none_or(|state| state.armed_deadline().is_none())
            }
        }
    }

    /// Receives and processes replies until `deadline` or until `wait` is
    /// satisfied. Returns false when a receive error ended the wait early.
    async fn receive_until(
        &mut self,
        deadline: tokio::time::Instant,
        wait: Wait,
        output: &mut crate::stats::StatsOutput,
    ) -> bool {
        enum Event {
            Datagram(std::io::Result<(usize, Option<u64>, Option<u8>)>),
            MonitorDue,
            Deadline,
            Report,
        }
        loop {
            if self.wait_over(wait) {
                return true;
            }
            let monitor_due = self
                .measurements
                .monitor
                .as_ref()
                .and_then(|m| m.deadline());
            let report_timer = &mut self.report_timer;
            // Unbiased: under a steady stream of replies a biased select
            // would starve the send deadline.
            let event = tokio::select! {
                result = recv_packet(
                    &self.socket,
                    &mut self.recv_buf,
                    &mut self.cmsg_buf,
                    self.kernel_rx_enabled,
                    self.ecn_response_active,
                    self.conf.clock_source,
                ) => Event::Datagram(result),
                _ = async {
                    match monitor_due {
                        Some(at) => tokio::time::sleep_until(at.into()).await,
                        None => std::future::pending().await,
                    }
                } => Event::MonitorDue,
                _ = tokio::time::sleep_until(deadline) => Event::Deadline,
                _ = async {
                    match report_timer {
                        Some(timer) => {
                            timer.tick().await;
                        }
                        None => std::future::pending().await,
                    }
                } => Event::Report,
            };
            match event {
                Event::Datagram(Ok((len, kernel_t4, reply_ecn))) => {
                    // Apply kernel TX timestamps first so a corrected T1 is
                    // in place before one-way delay is computed.
                    self.apply_tx_timestamps();
                    self.on_reply(len, kernel_t4, reply_ecn);
                }
                Event::Datagram(Err(e)) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    // A spurious wake, typically an error-queue event; drain
                    // it so readiness clears.
                    self.apply_tx_timestamps();
                }
                Event::Datagram(Err(e)) => {
                    let during = match wait {
                        Wait::NextSend => "",
                        Wait::Drain => " during final wait",
                        Wait::AccessReport => " while awaiting Access Report ack",
                    };
                    crate::eprintln_throttled!("Receive error{during}: {e}");
                    if !is_icmp_feedback(&e) {
                        if wait == Wait::NextSend {
                            // Keep the send schedule even if the socket keeps failing.
                            tokio::time::sleep_until(deadline).await;
                            return true;
                        }
                        return false;
                    }
                }
                Event::MonitorDue => {
                    if let Some(m) = self.measurements.monitor.as_mut() {
                        m.advance(Instant::now());
                    }
                }
                Event::Deadline => return true,
                Event::Report => {
                    let interim = self.snapshot();
                    output.print(&interim, true);
                }
            }
        }
    }

    /// Builds and sends one probe. A failed send is reported and the
    /// schedule continues.
    async fn send_probe(&mut self, attach_access_report: bool) {
        self.prepare_header_requests();
        if let Some(ber) = self.ber.as_mut() {
            ber.advance(Instant::now());
            ber.filter_requests(&mut self.extra_tlvs);
        }
        let seq = self.sess.generate_sequence_number();
        let send_time = Instant::now();
        let send_timestamp = generate_timestamp(self.conf.clock_source);
        let packet = self.build_probe(seq, send_timestamp, attach_access_report);
        match self.socket.send(&packet).await {
            Err(e) => crate::eprintln_throttled!("Failed to send packet {seq}: {e}"),
            Ok(_) => self.record_sent(seq, send_time, send_timestamp),
        }
    }

    /// Serializes one probe. Direct Measurement, an Access Report and an
    /// AIMD-scaled Reflected Test Packet Control TLV (cos-ecn-01 §3.4-3)
    /// change per probe; everything else comes from `extra_tlvs`.
    fn build_probe(&self, seq: u32, timestamp: u64, attach_access_report: bool) -> Vec<u8> {
        let conf = self.conf;
        let per_probe =
            conf.direct_measurement || attach_access_report || self.scale_reflected_control;
        let owned;
        let tlvs: &[RawTlv] = if per_probe {
            let mut tlvs = self.extra_tlvs.clone();
            if conf.direct_measurement {
                tlvs.push(DirectMeasurementTlv::new(self.packets_sent + 1).to_raw());
            }
            if let Some(access_id) = conf.access_report.filter(|_| attach_access_report) {
                tlvs.push(AccessReportTlv::new(access_id, conf.access_return_code).to_raw());
            }
            if self.scale_reflected_control {
                let scale = self
                    .congestion
                    .as_ref()
                    .map_or(1.0, |c| c.controller.scale_factor());
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
            owned = tlvs;
            &owned
        } else {
            &self.extra_tlvs
        };
        let error_estimate = self.error_estimate_wire;
        let mut packet = match &self.send_mode {
            SendMode::AuthTlv { key } => build_auth_packet_with_tlvs(
                seq,
                timestamp,
                error_estimate,
                key,
                conf.ssid,
                tlvs,
                Some(key),
            ),
            SendMode::AuthBase { key } => {
                let mut packet = assemble_auth_packet(error_estimate);
                packet.sequence_number = seq;
                packet.timestamp = timestamp;
                packet.ssid = conf.ssid.unwrap_or(0);
                finalize_auth_packet(&mut packet, key);
                packet.to_bytes().to_vec()
            }
            SendMode::OpenTlv { tlv_key } => build_unauth_packet_with_tlvs(
                seq,
                timestamp,
                error_estimate,
                conf.ssid,
                tlvs,
                tlv_key.as_ref(),
            ),
            SendMode::OpenBase => {
                let mut packet = assemble_unauth_packet(error_estimate);
                packet.sequence_number = seq;
                packet.timestamp = timestamp;
                packet.ssid = conf.ssid.unwrap_or(0);
                packet.to_bytes().to_vec()
            }
        };
        // `--malformed` appends one deliberately malformed TLV after
        // everything else, including the HMAC TLV, to exercise a reflector.
        if let Some(mode) = conf.malformed {
            packet.extend_from_slice(&malformed_tlv_bytes(mode));
        }
        packet
    }

    fn record_sent(&mut self, seq: u32, send_time: Instant, send_timestamp: u64) {
        self.packets_sent += 1;
        #[cfg(all(unix, feature = "snmp"))]
        if let Some(stats) = &self.snmp_stats {
            stats.inc_sent();
        }
        #[cfg(feature = "metrics")]
        if self.metrics_enabled {
            crate::metrics::sender_metrics::record_packet_sent();
        }
        let probe = PendingPacket {
            send_time,
            send_timestamp,
        };
        self.pending.insert(seq, probe);
        self.measurements.sent(seq, probe, self.packets_sent);
        // Pair this send's kernel OPT_ID with the sequence number so a later
        // TX timestamp can correct the stored T1.
        #[cfg(all(feature = "hwtstamp", target_os = "linux"))]
        if self.kernel_ts.tx_kernel {
            self.tx_id_to_seq.insert(self.tx_counter, seq);
            self.tx_counter = self.tx_counter.wrapping_add(1);
            if self.tx_id_to_seq.len() > 4096 {
                // TX timestamps stopped arriving; do not grow without bound.
                self.tx_id_to_seq.clear();
            }
        }
        if !self.timeout.is_zero() {
            self.expiry_queue.push_back((send_time + self.timeout, seq));
        }
    }

    /// Replaces stored T1 values with kernel TX timestamps from the error queue.
    fn apply_tx_timestamps(&mut self) {
        #[cfg(all(feature = "hwtstamp", target_os = "linux"))]
        if self.kernel_ts.tx_kernel {
            use std::os::fd::AsRawFd;
            let reports = crate::hwtstamp::drain_tx_timestamps(
                self.socket.as_raw_fd(),
                self.conf.clock_source,
            );
            apply_tx_corrections(&reports, &mut self.tx_id_to_seq, &mut self.pending);
        }
    }

    fn on_reply(&mut self, len: usize, kernel_t4: Option<u64>, reply_ecn: Option<u8>) {
        let conf = self.conf;
        let mut ctx = SenderRecvContext {
            local_error_estimate: Some(self.error_estimate),
            measurements: Some(&mut self.measurements),
            ber: self.ber.as_mut(),
            reflector_utc_offset: conf.reflector_utc_offset,
            pending: &mut self.pending,
            rtt_collector: &mut self.rtt_collector,
            owd_collector: &mut self.owd_collector,
            packets_received: &mut self.packets_received,
            print_stats: conf.print_stats,
            output_format: conf.output_format,
            hmac_key: self.hmac_key.as_ref(),
            expected_sender_msid: conf.micro_session_id,
            expected_reflector_msid: conf.reflector_member_link_id,
            latched_reflector_msid: &mut self.latched_reflector_msid,
            access_report_state: self.access_report_state.as_mut(),
            congestion: self.congestion.as_mut(),
            expected_ssid: self.expected_ssid,
            on_zero_ssid: conf.on_zero_ssid,
            zero_ssid_seen: &mut self.zero_ssid_seen,
            #[cfg(feature = "metrics")]
            metrics_enabled: self.metrics_enabled,
            #[cfg(all(unix, feature = "snmp"))]
            snmp_stats: self.snmp_stats.as_deref(),
        };
        process_response(
            &self.recv_buf[..len],
            self.use_auth,
            self.use_tlvs,
            conf.clock_source,
            kernel_t4,
            reply_ecn,
            &mut ctx,
        );
    }

    /// Counts probes whose reply timeout has passed as lost. The queue is in
    /// send order, so this stops at the first probe still within its timeout.
    fn expire(&mut self) {
        let now = Instant::now();
        while let Some(&(deadline, seq)) = self.expiry_queue.front() {
            if deadline > now {
                break;
            }
            self.expiry_queue.pop_front();
            // Answered probes were already removed from `pending`.
            if self.pending.remove(&seq).is_some() {
                self.packets_lost += 1;
                #[cfg(feature = "metrics")]
                if self.metrics_enabled {
                    crate::metrics::sender_metrics::record_packets_lost(1);
                }
                #[cfg(all(unix, feature = "snmp"))]
                if let Some(stats) = &self.snmp_stats {
                    stats.inc_lost();
                }
            }
        }
    }

    /// Re-trims Type 246/247 requests for the current route MTU, which can
    /// change during a run. Each probe starts from the untrimmed set, so a
    /// temporary MTU drop does not remove requests for the rest of the run.
    /// A failed lookup keeps the previous set.
    fn prepare_header_requests(&mut self) {
        let Some(template) = &self.header_template else {
            return;
        };
        match egress_mtu(&self.socket) {
            Some(mtu) => {
                self.extra_tlvs.clone_from(template);
                let removed = enforce_egress_mtu(
                    &mut self.extra_tlvs,
                    mtu as usize,
                    self.header_fixed_overhead,
                );
                if removed != self.header_trimmed {
                    log_header_trim(removed, mtu as usize);
                    self.header_trimmed = removed;
                }
            }
            None => crate::eprintln_throttled!(
                "Cannot read the route MTU; keeping the previous header-reflection requests"
            ),
        }
    }

    fn snapshot(&mut self) -> StatsSnapshot {
        self.rtt_collector
            .snapshot(self.packets_sent, self.packets_lost)
            .with_measurements(self.measurements.snapshot())
            .with_ber(self.ber.as_mut().map(|b| b.snapshot(Instant::now())))
            .with_owd(&self.owd_collector)
            .with_access_report(
                self.access_report_state
                    .as_ref()
                    .map(|state| state.summary()),
            )
            .with_congestion(self.congestion.as_ref().map(|state| state.summary()))
    }
}

/// Replaces the stored T1 of each probe with its kernel TX timestamp, matched
/// by OPT_ID. Returns how many probes were corrected.
#[cfg(all(feature = "hwtstamp", target_os = "linux"))]
pub(super) fn apply_tx_corrections(
    reports: &[crate::hwtstamp::TxTimestampReport],
    tx_id_to_seq: &mut HashMap<u32, u32>,
    pending: &mut HashMap<u32, PendingPacket>,
) -> usize {
    let mut applied = 0;
    for report in reports {
        if let Some(seq) = tx_id_to_seq.remove(&report.opt_id) {
            if let Some(probe) = pending.get_mut(&seq) {
                probe.send_timestamp = report.timestamp;
                applied += 1;
            }
        }
    }
    applied
}

/// Receives one datagram, returning `(len, kernel_t4, reply_ecn)`.
///
/// `kernel_t4` is the kernel receive timestamp (T4) in wire format when
/// kernel RX timestamping is enabled. `reply_ecn` is the reply's own IP ECN
/// codepoint when requested, for reverse-path congestion detection
/// (cos-ecn-01 §3.4). Both come from one `recvmsg` on Linux and macOS; a
/// plain `recv` is used otherwise. May return `WouldBlock` on a spurious
/// wakeup; `try_io` clears the stale readiness first.
pub(super) async fn recv_packet(
    socket: &UdpSocket,
    buf: &mut [u8],
    cmsg_buf: &mut Vec<u8>,
    kernel_rx: bool,
    want_reply_ecn: bool,
    cs: ClockFormat,
) -> std::io::Result<(usize, Option<u64>, Option<u8>)> {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    if kernel_rx || want_reply_ecn {
        use std::os::fd::AsRawFd;
        socket.readable().await?;
        let mut iov = [std::io::IoSliceMut::new(buf)];
        return socket.try_io(tokio::io::Interest::READABLE, || {
            let msg = nix::sys::socket::recvmsg::<nix::sys::socket::SockaddrStorage>(
                socket.as_raw_fd(),
                &mut iov,
                Some(&mut *cmsg_buf),
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
    let _ = (cs, kernel_rx, want_reply_ecn, cmsg_buf);
    let len = socket.recv(buf).await?;
    Ok((len, None, None))
}
