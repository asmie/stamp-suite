//! Steps of opening a sender run: key, socket, static TLVs and MTU budget.

use super::*;

/// Loads the HMAC key before touching the network. Returns whether the base
/// packet is authenticated, and the key if one is configured.
pub(super) fn load_key(
    conf: &Configuration,
) -> Result<(bool, Option<HmacKey>), crate::StartupError> {
    // Load the key before touching the network. It also signs the TLV
    // HMAC in open mode, so a configured key that fails to load is an
    // error in either mode. The key directory is reflector-only.
    let use_auth = is_auth(conf.auth_mode);
    let hmac_key = conf.key_source().load_key()?;
    if use_auth && hmac_key.is_none() {
        return Err(crate::StartupError::config(
            "Authenticated mode (-A A) requires HMAC key (--hmac-key or --hmac-key-file)",
        ));
    }
    if hmac_key.is_some() {
        log::info!("HMAC authentication enabled");
    }
    Ok((use_auth, hmac_key))
}

/// Binds, configures and connects the sender socket. Returns the socket and
/// the ECN codepoint it marks on egress, when marking succeeded.
pub(super) async fn open_socket(
    conf: &Configuration,
    local_addr: SocketAddr,
    remote_addr: SocketAddr,
) -> Result<(UdpSocket, Option<u8>), crate::StartupError> {
    let std_socket = match crate::net_policy::bind_sender(local_addr, remote_addr) {
        Ok(s) => s,
        Err(e) => {
            return Err(crate::StartupError::io(
                format!("Cannot bind to address {local_addr}"),
                e,
            ));
        }
    };

    crate::net_policy::set_hops(&std_socket)
        .map_err(|e| crate::StartupError::io("Cannot set TTL/Hop Limit 255", e))?;
    if conf.zero_udp_checksum {
        enable_zero_udp_checksum(&std_socket)
            .map_err(|e| crate::StartupError::io("Cannot enable zero UDP transmit checksum", e))?;
        log::info!("IPv4 zero UDP transmit checksum enabled for authenticated BER");
    }
    // Bind to the device before connecting so the route lookup uses it.
    if let Some(name) = conf.interface.as_deref() {
        crate::net_policy::bind_to_interface(&std_socket, name)
            .map_err(|e| crate::StartupError::io(format!("Cannot bind to interface {name}"), e))?;
    }
    std_socket
        .set_nonblocking(true)
        .map_err(|e| crate::StartupError::io("Cannot make the socket nonblocking", e))?;
    let socket = UdpSocket::from_std(std_socket)
        .map_err(|e| crate::StartupError::io("Cannot register the socket", e))?;

    if conf.ber
        || !conf.attach_ext_hdr.is_empty()
        || !conf.reflected_fixed_hdr.is_empty()
        || !conf.reflected_ipv6_ext_hdr.is_empty()
    {
        conf.validate().map_err(crate::StartupError::config)?;
        // Set Don't Fragment and let the kernel report the path MTU.
        // Probes are sized to fit that MTU; a fragmented probe would hide
        // the oversize instead of failing at send time.
        #[cfg(target_os = "linux")]
        {
            use std::os::fd::AsRawFd;
            let value: nix::libc::c_int = nix::libc::IP_PMTUDISC_DO;
            let (level, option) = if conf.remote_ip().is_ipv6() {
                (nix::libc::IPPROTO_IPV6, nix::libc::IPV6_MTU_DISCOVER)
            } else {
                (nix::libc::IPPROTO_IP, nix::libc::IP_MTU_DISCOVER)
            };
            // SAFETY: `socket` owns the open fd for the whole call, and
            // `value` is a live, aligned c_int whose exact size is passed.
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
                return Err(crate::StartupError::io(
                    "BER PMTU setup",
                    std::io::Error::last_os_error(),
                ));
            }
        }
        #[cfg(any(target_os = "windows", target_os = "macos"))]
        enable_mtu_discovery(&socket, conf.remote_ip())
            .map_err(|e| crate::StartupError::io("Sender PMTU setup", e))?;
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    let mut configured_egress_ecn = None;
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    let configured_egress_ecn = None;

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
                        configured_egress_ecn = Some(tos & 3);
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

        // draft-ietf-bpm-stamp-cos-ecn-00 §3.4 reverse-path detection:
        // read back the reply packet's own on-wire ECN via recvmsg cmsgs
        // (see `extract_reply_ecn_from_cmsgs`, used from `recv_packet`).
        if conf.cos {
            let is_ipv6 = socket.local_addr().is_ok_and(|a| a.is_ipv6());
            match enable_reply_tos_reception(socket.as_raw_fd(), is_ipv6) {
                Ok(()) => log::info!(
                    "Reply ECN reception enabled (IP_RECVTOS/IPV6_RECVTCLASS) for \
                     reverse-path ECN observations (draft-ietf-bpm-stamp-cos-ecn-00)"
                ),
                Err(e) => log::warn!(
                    "Failed to enable reply ECN reception: {e}; reverse-path ECN \
                     observations unavailable; forward-path detection via the \
                     reflected CoS TLV's EC2 field is unaffected"
                ),
            }
        }
    }

    // draft-ietf-ippm-stamp-ext-hdr-26 §4.2: attach the real IPv6 extension
    // headers requested via --attach-ext-hdr. IPv6 destinations only, and
    // Linux only: `libc` does not expose the sticky IPV6_HOPOPTS /
    // IPV6_DSTOPTS options on Darwin (see `apply_attach_ext_hdrs`).
    #[cfg(target_os = "linux")]
    {
        use std::os::fd::AsRawFd;

        let attach_specs = conf.attach_ext_hdrs();
        if !attach_specs.is_empty() {
            if conf.remote_ip().is_ipv6() {
                apply_attach_ext_hdrs(socket.as_raw_fd(), &attach_specs).map_err(|e| {
                    crate::StartupError::io("Cannot attach requested IPv6 header", e)
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
                 request TLV(s) are still sent (draft-ietf-ippm-stamp-ext-hdr-26 §4.2)"
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
        if conf.cos {
            log::warn!(
                "Reverse-path ECN observations (wire ECN of replies) require \
                 Linux/macOS; only forward-path detection via the reflected CoS TLV's EC2 \
                 field is active on this platform (draft-ietf-bpm-stamp-cos-ecn-00 §3.4)"
            );
        }
    }

    // Connect after setting sticky IPv6 headers: IPV6_HOPOPTS/IPV6_DSTOPTS
    // invalidate Linux's cached route. Connecting last populates the route
    // used by the pre-send MTU check, without transmitting a probe first.
    if let Err(e) = socket.connect(remote_addr).await {
        return Err(crate::StartupError::io(
            format!("Cannot connect to address {remote_addr}"),
            e,
        ));
    }
    Ok((socket, configured_egress_ecn))
}

/// Enables kernel RX/TX timestamps on the connected socket.
#[cfg(all(feature = "hwtstamp", any(target_os = "linux", target_os = "macos")))]
pub(super) fn kernel_timestamping(
    conf: &Configuration,
    socket: &UdpSocket,
) -> crate::hwtstamp::EnabledTimestamping {
    // Kernel timestamping (feature "hwtstamp"): kernel RX timestamps give a
    // precise T4; TX timestamps from the error queue retroactively correct
    // the stored T1 used for forward one-way delay. `auto` uses the kernel
    // software tier; `on` additionally attempts NIC hardware (Linux).
    {
        use std::os::fd::AsRawFd;

        use crate::hwtstamp::{self, HwTsMode};
        if conf.hwtstamp == HwTsMode::Off {
            hwtstamp::EnabledTimestamping::default()
        } else {
            #[cfg(target_os = "linux")]
            let want_hw = conf.hwtstamp == HwTsMode::On && {
                let iface = conf
                    .interface
                    .clone()
                    .or_else(|| hwtstamp::interface_for_addr(conf.local_addr));
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
    }
}

/// The AIMD controller for `--cos` with an ECT codepoint, if active.
pub(super) fn congestion_controller(
    conf: &Configuration,
    ecn_response_active: bool,
    scale_reflected_control: bool,
) -> Option<CongestionState> {
    ecn_response_active.then(|| {
        let params = AimdParams {
            base_interval: conf.send_delay.duration(),
            backoff_factor: conf.ecn_backoff_factor,
            max_interval: Duration::from_millis(conf.ecn_max_delay as u64),
            recovery_step: Duration::from_millis(conf.ecn_recovery_step as u64),
        };
        log::info!(
            "AIMD congestion-response controller enabled (draft-ietf-bpm-stamp-cos-ecn-00 \
             §3.4): base={:?} backoff_factor={} max={}ms recovery_step={}ms{}",
            conf.send_delay.duration(),
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
    })
}

/// Access Report retransmission state, when `--access-report` is set.
pub(super) fn access_report_state(conf: &Configuration) -> Option<AccessReportRetransmitState> {
    // Access Reports are event-driven (RFC 8972 §4.6).
    // Attach only when due and arm only after a successful send; omit the
    // report from static TLVs.
    conf.access_report.map(|access_id| {
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
            AccessReportTlv::new(access_id, conf.access_return_code),
        )
    })
}

/// The TLVs every probe carries, before route-MTU fitting, and the BER
/// pattern when BER is enabled.
pub(super) fn static_tlvs(
    conf: &Configuration,
    scale_reflected_control: bool,
) -> Result<(Vec<RawTlv>, Option<Vec<u8>>), crate::StartupError> {
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

    if conf.timestamp_info {
        // RFC 8972 §4.3: the Session-Sender MUST send the Timestamp Info TLV
        // value fully zeroed. All four octets describe the reflector's
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

    // Build Return Path TLV (RFC 9503 §4); at most one is sent.
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
    // When `scale_reflected_control` is set, `build_probe` rebuilds it for
    // every probe with an AIMD-scaled interval (draft-ietf-bpm-stamp-cos-ecn-00 §3.4), so it is
    // not added to the static set here.
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
    // Pseudorandom fill, as §4.1 recommends. `validate()` has already
    // rejected combining this with --ber, which needs a known pattern.
    if let Some(bytes) = conf.extra_padding {
        extra_tlvs.push(ExtraPaddingTlv::new(bytes).to_raw());
        log::info!("Extra Padding TLV enabled ({bytes} value octets)");
    }

    // BPM BER-01: one combined TLV and known-pattern Extra Padding.
    let mut ber_pattern = None;
    if conf.ber {
        let pattern = crate::ber::parse_pattern(conf.ber_pattern.as_deref().unwrap_or("ff00ff00"))
            .map_err(|e| crate::StartupError::config(format!("Invalid --ber-pattern: {e}")))?;
        let padding = (0..conf.ber_padding_size)
            .map(|i| pattern[i % pattern.len()])
            .collect();
        extra_tlvs.push(ExtraPaddingTlv { padding }.to_raw());
        // Omit the default pattern sub-TLV, as §5.1.2 permits. Explicit
        // overrides carry their exact four-or-more-byte representation.
        let value = ResidualBerValue::request(
            RESIDUAL_BER_PATTERN_SUBTLV_TYPE,
            conf.ber_pattern.as_ref().map(|_| pattern.as_slice()),
        )
        .and_then(|v| v.to_raw())
        .map_err(|e| crate::StartupError::config(format!("Invalid BER value: {e}")))?;
        extra_tlvs.push(value);
        log::info!(
            "Residual BER enabled (experimental Type 243, padding_size={}, pattern={})",
            conf.ber_padding_size,
            hex::encode(&pattern)
        );
        ber_pattern = Some(pattern);
    }

    // Reflected Fixed / IPv6 Extension Header Data TLVs
    // (draft-ietf-ippm-stamp-ext-hdr-26 §4.2, §6.2). The value is a
    // Requested field (4 octets for Type 247, 8 for Type 246), zero or a
    // selector, followed by a zeroed Reflected field. The reflector fills
    // the Reflected field when it can see the header, or returns the TLV
    // with the C flag set (§4.1, §6.1).
    extra_tlvs.extend(reflected_header_request_tlvs(conf));
    Ok((extra_tlvs, ber_pattern))
}

/// Bytes every probe carries besides its static TLVs: the IP header and any
/// attached IPv6 extension headers, UDP, the base packet, and the per-probe
/// TLVs. Those are the HMAC (when one is sent), Direct Measurement, Access
/// Report, the AIMD-scaled Type 12 and the diagnostic malformed trailer, so a
/// static TLV that fits leaves room for all of them.
pub(super) fn probe_fixed_overhead(
    conf: &Configuration,
    use_auth: bool,
    hmac_tlv_sent: bool,
    access_report: bool,
    scale_reflected_control: bool,
) -> usize {
    let ipv6 = conf.remote_ip().is_ipv6();
    let ip_hdr = if ipv6 {
        IPV6_FIXED_HEADER_SIZE
    } else {
        IPV4_FIXED_HEADER_SIZE
    };
    // Attached IPv6 extension headers ride between the fixed header and UDP.
    let attached_ext: usize = if ipv6 {
        conf.attach_ext_hdrs().iter().map(|a| a.bytes.len()).sum()
    } else {
        0
    };
    let base = if use_auth {
        AUTH_BASE_SIZE
    } else {
        UNAUTH_BASE_SIZE
    };
    // The HMAC reserve follows the origination decision, not key possession:
    // with --tlv-hmac off no HMAC TLV is sent, and reserving for one would
    // trim Type 246/247 requests that actually fit on the wire.
    let tlv = |sent: bool, value: usize| if sent { TLV_HEADER_SIZE + value } else { 0 };
    let control = if scale_reflected_control {
        build_reflected_control_tlv(
            conf.reflected_control_length,
            conf.reflected_control_count,
            conf.reflected_control_interval_ns,
            conf.reflected_control_no_ext_hdr,
        )
        .map_or(0, |tlv| tlv.to_raw().wire_size())
    } else {
        0
    };
    let malformed = conf
        .malformed
        .map_or(0, |mode| malformed_tlv_bytes(mode).len());
    ip_hdr
        + attached_ext
        + UDP_HEADER_SIZE
        + base
        + tlv(hmac_tlv_sent, HMAC_TLV_VALUE_SIZE)
        + tlv(conf.direct_measurement, DIRECT_MEASUREMENT_TLV_VALUE_SIZE)
        + tlv(access_report, ACCESS_REPORT_TLV_VALUE_SIZE)
        + control
        + malformed
}

/// Fits the static TLVs to the egress route MTU at startup: BER padding in
/// whole pattern repetitions, then optional header requests. Returns the
/// untrimmed TLVs to refit before each probe, when the route MTU is tracked,
/// and how many header requests were removed. Header requests need a known
/// MTU; standalone BER falls back to the minimum link MTU.
pub(super) fn fit_to_route(
    conf: &Configuration,
    socket: &UdpSocket,
    extra_tlvs: &mut Vec<RawTlv>,
    fixed_overhead: usize,
    header_requests: bool,
) -> Result<(Option<Vec<RawTlv>>, usize), crate::StartupError> {
    let route_mtu = egress_mtu(socket);
    if header_requests && route_mtu.is_none() {
        return Err(crate::StartupError::config(
            "Header reflection requires a known egress route MTU",
        ));
    }
    let mtu = route_mtu.unwrap_or(if conf.remote_ip().is_ipv6() {
        1280
    } else {
        1500
    }) as usize;
    let template =
        (header_requests || (conf.ber && route_mtu.is_some())).then(|| extra_tlvs.clone());
    if conf.ber {
        crate::ber::fit_padding(extra_tlvs, mtu, fixed_overhead)
            .map_err(|e| crate::StartupError::io("Cannot fit the BER padding", e))?;
    }
    let removed = enforce_egress_mtu(extra_tlvs, mtu, fixed_overhead);
    log_header_trim(removed, mtu);
    Ok((template, removed))
}

/// How probes are built, decided once from the key, mode and TLV use.
pub(super) fn send_mode(
    hmac_key: Option<&HmacKey>,
    use_auth: bool,
    use_tlvs: bool,
    originate_tlv_hmac: bool,
) -> SendMode {
    if let Some(key) = hmac_key.cloned().filter(|_| use_auth) {
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
            tlv_key: hmac_key.cloned().filter(|_| originate_tlv_hmac),
        }
    } else {
        SendMode::OpenBase
    }
}
