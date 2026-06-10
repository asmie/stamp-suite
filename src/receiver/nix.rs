//! Receiver implementation using nix crate for real TTL capture via IP_RECVTTL.
//!
//! Preferred on Linux systems. No special privileges required for regular UDP sockets.

use std::{
    io::IoSliceMut,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    os::fd::AsRawFd,
    sync::Arc,
    time::Duration,
};

use nix::{
    libc,
    sys::socket::{recvmsg, ControlMessageOwned, MsgFlags, SockaddrStorage},
};
use tokio::{net::UdpSocket, time::interval};

use crate::{
    configuration::{is_auth, Configuration, TlvHandlingMode},
    error_estimate::ErrorEstimate,
};

use crate::tlv::ReturnPathAction;

use super::{
    load_hmac_key, print_reflector_stats, process_stamp_packet_isolated,
    recompute_response_tlv_hmac, set_cos_policy_rejected, set_return_path_u_flag_in_response,
    ProcessingContext, ReceiverSharedState, AUTH_BASE_SIZE, UNAUTH_BASE_SIZE,
};

/// Runs the STAMP Session Reflector using nix for real TTL capture.
///
/// Uses IP_RECVTTL/IPV6_RECVHOPLIMIT socket options to capture the actual
/// TTL/Hop Limit from incoming packets. Preferred on Linux systems.
pub async fn run_receiver(conf: &Configuration, shared: &ReceiverSharedState) {
    let local_addr: SocketAddr = (conf.local_addr, conf.local_port).into();
    let is_ipv6 = conf.local_addr.is_ipv6();

    // Create a standard UDP socket
    let std_socket = match std::net::UdpSocket::bind(local_addr) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Cannot bind to address {}: {}", local_addr, e);
            return;
        }
    };

    // Enable TTL/hop limit and TOS/Traffic Class reception via setsockopt using libc directly
    // nix doesn't expose IP_RECVTTL/IP_RECVTOS, so we use libc
    let fd = std_socket.as_raw_fd();
    let enable: libc::c_int = 1;

    // Enable TTL/Hop Limit reception
    let result = if is_ipv6 {
        unsafe {
            libc::setsockopt(
                fd,
                libc::IPPROTO_IPV6,
                libc::IPV6_RECVHOPLIMIT,
                &enable as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            )
        }
    } else {
        unsafe {
            libc::setsockopt(
                fd,
                libc::IPPROTO_IP,
                libc::IP_RECVTTL,
                &enable as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            )
        }
    };

    if result < 0 {
        eprintln!(
            "Failed to set IP_RECVTTL/IPV6_RECVHOPLIMIT: {}",
            std::io::Error::last_os_error()
        );
        return;
    }

    // Enable TOS/Traffic Class reception (for DSCP/ECN measurement)
    let tos_result = if is_ipv6 {
        unsafe {
            libc::setsockopt(
                fd,
                libc::IPPROTO_IPV6,
                libc::IPV6_RECVTCLASS,
                &enable as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            )
        }
    } else {
        unsafe {
            libc::setsockopt(
                fd,
                libc::IPPROTO_IP,
                libc::IP_RECVTOS,
                &enable as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            )
        }
    };

    if tos_result < 0 {
        // TOS reception is optional (for DSCP/ECN measurement), just log warning
        log::warn!(
            "Failed to set IP_RECVTOS/IPV6_RECVTCLASS: {} (DSCP/ECN measurement disabled)",
            std::io::Error::last_os_error()
        );
    }

    // Enable packet info reception for destination address (for Location TLV).
    // Without this, a wildcard bind (0.0.0.0/::) reports the bind address as dst_addr.
    let pktinfo_result = if is_ipv6 {
        unsafe {
            libc::setsockopt(
                fd,
                libc::IPPROTO_IPV6,
                libc::IPV6_RECVPKTINFO,
                &enable as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            )
        }
    } else {
        unsafe {
            libc::setsockopt(
                fd,
                libc::IPPROTO_IP,
                libc::IP_PKTINFO,
                &enable as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            )
        }
    };

    if pktinfo_result < 0 {
        log::warn!(
            "Failed to set IP_PKTINFO/IPV6_RECVPKTINFO: {} (Location TLV dst_addr may use bind address)",
            std::io::Error::last_os_error()
        );
    }

    // Kernel timestamping (feature "hwtstamp"): enable SO_TIMESTAMPING per
    // the --hwtstamp mode. `auto` requests the kernel-software tier only
    // (no NIC reconfiguration, no privileges needed); `on` additionally
    // attempts NIC hardware filters (SIOCSHWTSTAMP, needs CAP_NET_ADMIN)
    // and falls back to the software tier when that fails.
    #[cfg(feature = "hwtstamp")]
    let kernel_ts = {
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
            let enabled = hwtstamp::enable_socket_timestamping(fd, true, true, want_hw);
            log::info!(
                "kernel timestamping: rx_kernel={} rx_hw={} tx_kernel={} tx_hw={}",
                enabled.rx_kernel,
                enabled.rx_hw,
                enabled.tx_kernel,
                enabled.tx_hw
            );
            enabled
        }
    };
    #[cfg(feature = "hwtstamp")]
    let tx_method_cfg = if kernel_ts.tx_hw {
        crate::tlv::TimestampMethod::HwAssist
    } else {
        crate::tlv::TimestampMethod::SwLocal
    };

    // Set non-blocking for tokio
    if let Err(e) = std_socket.set_nonblocking(true) {
        eprintln!("Error: Failed to set socket non-blocking: {}", e);
        return;
    }

    // Wrap in tokio for async readiness notifications. Arc so spawned tasks
    // (e.g. Reflected Test Packet Control multi-send,
    // draft-ietf-ippm-asymmetrical-pkts §3) can share the socket.
    let tokio_socket = match UdpSocket::from_std(std_socket) {
        Ok(s) => Arc::new(s),
        Err(e) => {
            eprintln!("Error: Failed to create tokio socket: {}", e);
            return;
        }
    };

    // Check if authenticated mode is used
    let use_auth = is_auth(conf.auth_mode);

    // B6: the per-SSID keyset lives in shared state (runtime-mutable via
    // the control plane); keep `hmac_key` as a legacy fallback when no
    // keyset was configured at startup.
    let keyset_configured = shared
        .hmac_keys
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .is_some();
    let hmac_key = if keyset_configured {
        None
    } else {
        load_hmac_key(conf)
    };

    // Validate: authenticated mode requires HMAC key (either single-key
    // legacy path or B6 per-SSID key set).
    if use_auth && hmac_key.is_none() && !keyset_configured {
        log::error!(
            "Authenticated mode (-A A) requires --hmac-key, --hmac-key-file, or --hmac-key-dir"
        );
        return;
    }

    // Build error estimate from configuration with Z flag set based on clock source
    let error_estimate = ErrorEstimate::with_clock_format(
        conf.clock_synchronized,
        conf.clock_source,
        conf.error_scale,
        conf.error_multiplier,
    )
    .unwrap_or_else(|_| ErrorEstimate::unsynchronized_with_format(conf.clock_source));
    let error_estimate_wire = error_estimate.to_wire();

    if hmac_key.is_some() {
        log::info!("HMAC authentication enabled");
    }

    if conf.tlv_mode != TlvHandlingMode::Ignore {
        log::info!("TLV handling mode: {:?}", conf.tlv_mode);
    }

    let session_manager = Arc::clone(&shared.session_manager);

    if conf.stateful_reflector {
        log::info!("Stateful reflector mode enabled (RFC 8972)");
    }

    let counters = Arc::clone(&shared.counters);
    let start_time = shared.start_time;
    let output_format = conf.output_format;

    // Build local addresses for Destination Node Address TLV matching (RFC 9503 §4).
    // Start with the configured bind address; if wildcard, enumerate interface addresses.
    let local_addresses = super::build_local_addresses(conf.local_addr);

    println!(
        "STAMP Reflector listening on {} (nix mode, real TTL)",
        local_addr
    );

    let mut buf = [0u8; 1024];
    // 512 bytes: TTL + TOS + PKTINFO plus the 64-byte SCM_TIMESTAMPING
    // cmsg (feature "hwtstamp") with headroom.
    let mut cmsg_buf = vec![0u8; 512];

    // Kernel TX-timestamp correlation (feature "hwtstamp"): every
    // successful send on this socket consumes one SOF_TIMESTAMPING_OPT_ID
    // counter value in the kernel, so the userspace counter is bumped at
    // *every* send site (main reply, alternate-address fallback, SRv6,
    // Reflected Control extra copies). Only the main reply's counter value
    // is mapped to (client, seq) — the others' timestamps are dropped on
    // drain. The extra-copy tasks share the socket concurrently, so their
    // attribution can race the main reply by one slot; corrections are
    // best-effort and Type 12 multi-send is off by default.
    #[cfg(all(feature = "hwtstamp", target_os = "linux"))]
    let tx_counter = Arc::new(std::sync::atomic::AtomicU32::new(0));
    #[cfg(all(feature = "hwtstamp", target_os = "linux"))]
    let mut tx_id_map: std::collections::HashMap<u32, (SocketAddr, u32)> =
        std::collections::HashMap::new();

    // Session cleanup interval: run at half the timeout period, minimum 1 second
    // When session_timeout is 0, checked_div returns None, disabling cleanup
    let cleanup_interval = conf
        .session_timeout
        .checked_div(2)
        .map(|t| Duration::from_secs(t.max(1)));
    let mut cleanup_timer = cleanup_interval.map(interval);

    // Cache last applied TOS value to avoid redundant setsockopt calls under load.
    // Sockets default to TOS=0, so we start with that assumption.
    let mut last_tos: u8 = 0;

    // Poll for control-plane shutdown requests (cheap 250 ms tick; the
    // first immediate tick is harmless — the flag starts false).
    let mut shutdown_tick = interval(Duration::from_millis(250));

    loop {
        // Apply kernel TX timestamps that arrived on the error queue since
        // the last iteration: correct the Follow-Up Telemetry record of the
        // matching reflection (RFC 8972 §4.7 reports the *previous* reply's
        // TX time, so the one-iteration delay is inherent to the TLV).
        #[cfg(all(feature = "hwtstamp", target_os = "linux"))]
        if kernel_ts.tx_kernel {
            for report in
                crate::hwtstamp::drain_tx_timestamps(tokio_socket.as_raw_fd(), conf.clock_source)
            {
                if let Some((client, seq)) = tx_id_map.remove(&report.opt_id) {
                    if let Some(session) = session_manager.get_session(client) {
                        session.correct_reflection_timestamp(seq, report.timestamp);
                    }
                }
            }
            if tx_id_map.len() > 4096 {
                // Defensive: timestamps stopped arriving (e.g. qdisc drops);
                // don't let the correlation map grow unbounded.
                log::debug!("TX-timestamp map overflow; clearing {}", tx_id_map.len());
                tx_id_map.clear();
            }
        }

        // Wait for socket to be readable, cleanup timer, or shutdown signal.
        // Use unbiased select to ensure fair scheduling - biased select
        // would starve the cleanup timer under heavy packet load.
        tokio::select! {
            result = tokio_socket.readable() => {
                if let Err(e) = result {
                    eprintln!("Failed to wait for readable: {}", e);
                    continue;
                }
            }

            _ = async {
                if let Some(ref mut timer) = cleanup_timer {
                    timer.tick().await
                } else {
                    std::future::pending::<tokio::time::Instant>().await
                }
            } => {
                // Run periodic session cleanup
                let removed = session_manager.cleanup_stale_sessions();
                if removed > 0 {
                    log::debug!("Session cleanup: removed {} stale sessions", removed);
                }
                continue;
            }

            _ = tokio::signal::ctrl_c() => {
                print_reflector_stats(&counters, &session_manager, start_time, output_format);
                return;
            }

            _ = shutdown_tick.tick() => {
                // Control-plane shutdown (POST /v1/shutdown) — graceful exit
                // with the same stats dump as Ctrl-C.
                if shared
                    .shutdown_requested
                    .load(std::sync::atomic::Ordering::Relaxed)
                {
                    log::info!("shutdown requested via control plane");
                    print_reflector_stats(&counters, &session_manager, start_time, output_format);
                    return;
                }
            }
        }

        // Use nix recvmsg to get TTL from control messages
        let mut iov = [IoSliceMut::new(&mut buf)];

        match recvmsg::<SockaddrStorage>(
            tokio_socket.as_raw_fd(),
            &mut iov,
            Some(&mut cmsg_buf),
            MsgFlags::MSG_DONTWAIT,
        ) {
            Ok(msg) => {
                let len = msg.bytes;
                let src_storage = msg.address;

                // Extract TTL from control messages
                let ttl = match extract_ttl_from_cmsgs(&msg) {
                    Some(t) => t,
                    None => {
                        log::warn!("Failed to extract TTL from packet, skipping");
                        continue;
                    }
                };

                // Extract TOS (DSCP/ECN) from control messages
                let (received_dscp, received_ecn) = extract_tos_from_cmsgs(&msg)
                    .map(|tos| ((tos >> 2) & 0x3F, tos & 0x03))
                    .unwrap_or((0, 0));

                // Extract actual destination address from packet info (for Location TLV).
                // Falls back to configured bind address if pktinfo is unavailable.
                let dst_addr = extract_dst_addr_from_cmsgs(&msg).unwrap_or(conf.local_addr);

                // Extract the kernel receive timestamp (T2) when enabled.
                // Must happen here while `msg` (and its cmsg buffer) is alive.
                #[cfg(feature = "hwtstamp")]
                let (rx_timestamp, rx_method) = if kernel_ts.rx_kernel {
                    match msg
                        .cmsgs()
                        .ok()
                        .and_then(crate::hwtstamp::extract_kernel_rx_timestamp)
                    {
                        Some(k) => (
                            Some(crate::time::timestamp_from_parts(
                                k.secs,
                                k.nanos,
                                conf.clock_source,
                            )),
                            if k.hardware {
                                crate::tlv::TimestampMethod::HwAssist
                            } else {
                                crate::tlv::TimestampMethod::SwLocal
                            },
                        ),
                        None => (None, crate::tlv::TimestampMethod::SwLocal),
                    }
                } else {
                    (None, crate::tlv::TimestampMethod::SwLocal)
                };

                // Convert source address for session lookup and response
                let src_addr: SocketAddr = match src_storage {
                    Some(ref src) => {
                        if let Some(v4) = src.as_sockaddr_in() {
                            std::net::SocketAddrV4::new(v4.ip(), v4.port()).into()
                        } else if let Some(v6) = src.as_sockaddr_in6() {
                            std::net::SocketAddrV6::new(v6.ip(), v6.port(), 0, 0).into()
                        } else {
                            eprintln!("Unknown source address type");
                            continue;
                        }
                    }
                    None => {
                        eprintln!("No source address available");
                        continue;
                    }
                };

                // Rate limit check: drop packet if source exceeds the
                // per-client token bucket. Distinct from the generic
                // packets_dropped counter so operators can tell rate-limit
                // pressure from parse/HMAC failures. The limiter is always
                // constructed; rate 0 short-circuits to "allow".
                if !shared.rate_limiter.allow(src_addr.ip()) {
                    log::debug!("Rate-limited packet from {}", src_addr);
                    shared
                        .counters
                        .packets_rate_limited
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    shared
                        .counters
                        .packets_dropped
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    continue;
                }

                let data = &buf[..len];
                counters
                    .packets_received
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);

                // Get session counters for Direct Measurement and Follow-Up Telemetry.
                // Always tracked per-client, independent of --stateful-reflector.
                let counter_session = session_manager.get_or_create_session(src_addr);
                counter_session.record_received();
                let reflector_rx_count = Some(counter_session.get_received_count());
                let reflector_tx_count = Some(counter_session.get_transmitted_count());
                let last_reflection = Some(counter_session.get_last_reflection());

                // Build packet address info for Location TLV
                let packet_addr_info = Some(crate::tlv::PacketAddressInfo {
                    src_addr: src_addr.ip(),
                    src_port: src_addr.port(),
                    dst_addr,
                    dst_port: conf.local_port,
                });

                // Panic-isolated: a panic in processing must not unwind out of
                // the receive loop and kill the process (remote DoS). On panic
                // the packet is dropped (None) and the loop continues.
                //
                // The keyset read guard is scoped to this block — it must
                // never be held across an `.await` (std guard is not Send);
                // the async sends below happen after it drops.
                let response_opt = {
                    let keys_guard = shared.hmac_keys.read().unwrap_or_else(|e| e.into_inner());
                    let ctx = ProcessingContext {
                        clock_source: conf.clock_source,
                        error_estimate_wire,
                        hmac_key: hmac_key.as_ref(),
                        hmac_key_set: keys_guard.as_ref(),
                        require_hmac: conf.require_hmac,
                        session_manager: if conf.stateful_reflector {
                            Some(&session_manager)
                        } else {
                            None
                        },
                        tlv_mode: conf.tlv_mode,
                        verify_tlv_hmac: conf.verify_tlv_hmac,
                        strict_packets: conf.strict_packets,
                        #[cfg(feature = "metrics")]
                        metrics_enabled: conf.metrics,
                        received_dscp,
                        received_ecn,
                        reflector_rx_count,
                        reflector_tx_count,
                        packet_addr_info,
                        last_reflection,
                        local_addresses: &local_addresses,
                        sender_port: src_addr.port(),
                        return_path_allow_alternate: conf.return_path_allow_alternate,
                        reflector_member_link_id: conf.reflector_member_link_id,
                        // nix UDP-socket backend cannot observe raw IP headers.
                        // draft-ietf-ippm-stamp-ext-hdr TLV 246/247 requests are
                        // echoed with U-flag set (done in apply_semantic_tlv_processing).
                        captured_headers: None,
                        reflected_control_max_count: shared
                            .caps
                            .reflected_control_max_count
                            .load(std::sync::atomic::Ordering::Relaxed),
                        reflected_control_max_size: shared
                            .caps
                            .reflected_control_max_size
                            .load(std::sync::atomic::Ordering::Relaxed),
                        reflected_control_min_interval_ns: shared
                            .caps
                            .reflected_control_min_interval_ns
                            .load(std::sync::atomic::Ordering::Relaxed),
                        #[cfg(feature = "hwtstamp")]
                        rx_timestamp,
                        #[cfg(not(feature = "hwtstamp"))]
                        rx_timestamp: None,
                        #[cfg(feature = "hwtstamp")]
                        rx_method,
                        #[cfg(not(feature = "hwtstamp"))]
                        rx_method: crate::tlv::TimestampMethod::SwLocal,
                        #[cfg(feature = "hwtstamp")]
                        tx_method: tx_method_cfg,
                        #[cfg(not(feature = "hwtstamp"))]
                        tx_method: crate::tlv::TimestampMethod::SwLocal,
                    };
                    process_stamp_packet_isolated(data, src_addr, ttl, use_auth, &ctx)
                };
                if let Some(mut response) = response_opt {
                    // Handle Return Path action (RFC 9503 §5)
                    let send_target = match &response.return_path_action {
                        ReturnPathAction::SuppressReply => {
                            log::debug!("Return Path: suppressing reply to {}", src_addr);
                            counters
                                .packets_dropped
                                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                            continue;
                        }
                        ReturnPathAction::AlternateAddress(addr) => *addr,
                        ReturnPathAction::Normal
                        | ReturnPathAction::UnsupportedSr
                        | ReturnPathAction::Srv6Forward(_) => src_addr,
                    };

                    // Determine TOS value: use CoS TLV request if present, otherwise default (0).
                    let (tos, has_cos_request) = match response.cos_request {
                        Some((dscp, ecn)) => (((dscp & 0x3F) << 2) | (ecn & 0x03), true),
                        None => (0u8, false),
                    };

                    // Only call setsockopt if TOS value changed (reduces syscall overhead under load)
                    if tos != last_tos {
                        let fd = tokio_socket.as_raw_fd();
                        let tos_val: libc::c_int = tos as libc::c_int;
                        let result = if is_ipv6 {
                            unsafe {
                                libc::setsockopt(
                                    fd,
                                    libc::IPPROTO_IPV6,
                                    libc::IPV6_TCLASS,
                                    &tos_val as *const _ as *const libc::c_void,
                                    std::mem::size_of::<libc::c_int>() as libc::socklen_t,
                                )
                            }
                        } else {
                            unsafe {
                                libc::setsockopt(
                                    fd,
                                    libc::IPPROTO_IP,
                                    libc::IP_TOS,
                                    &tos_val as *const _ as *const libc::c_void,
                                    std::mem::size_of::<libc::c_int>() as libc::socklen_t,
                                )
                            }
                        };
                        if result < 0 {
                            if has_cos_request {
                                log::debug!(
                                    "Failed to set IP_TOS/IPV6_TCLASS to {}: {}",
                                    tos,
                                    std::io::Error::last_os_error()
                                );
                                // Set RP flag in CoS TLV to indicate policy rejection (RFC 8972 §5.2)
                                let base_size = if use_auth {
                                    AUTH_BASE_SIZE
                                } else {
                                    UNAUTH_BASE_SIZE
                                };
                                if set_cos_policy_rejected(&mut response.data, base_size) {
                                    // RP mutation invalidates the TLV HMAC — recompute
                                    if let Some(ref key) = hmac_key {
                                        recompute_response_tlv_hmac(
                                            &mut response.data,
                                            base_size,
                                            key,
                                        );
                                    }
                                }
                            }
                            // Don't update last_tos on failure - retry next time
                        } else {
                            last_tos = tos;
                        }
                    }

                    // SRv6 return-path best-effort forwarding (RFC 9503 §5 +
                    // RFC 8754). When enabled and the kernel supports it, insert
                    // a Segment Routing Header on the IPv6 reply; otherwise fall
                    // back to a normal reply with the Return Path U-flag set.
                    #[cfg(all(feature = "hwtstamp", target_os = "linux"))]
                    let mut sent_opt_id: Option<u32> = None;
                    let mut srv6_sent = false;
                    if let ReturnPathAction::Srv6Forward(sids) = &response.return_path_action {
                        if conf.srv6_return_forwarding && crate::srv6::srh_supported() {
                            if let SocketAddr::V6(v6) = send_target {
                                if let Some(srh) = crate::srv6::build_srh(sids) {
                                    match crate::srv6::send_with_srh(
                                        tokio_socket.as_raw_fd(),
                                        &response.data,
                                        v6,
                                        &srh,
                                    ) {
                                        Ok(_) => {
                                            srv6_sent = true;
                                            #[cfg(all(feature = "hwtstamp", target_os = "linux"))]
                                            if kernel_ts.tx_kernel {
                                                sent_opt_id = Some(tx_counter.fetch_add(
                                                    1,
                                                    std::sync::atomic::Ordering::Relaxed,
                                                ));
                                            }
                                        }
                                        Err(e) => log::debug!(
                                            "SRv6 return-path send to {} failed ({}); \
                                             falling back to U-flag reply",
                                            v6,
                                            e
                                        ),
                                    }
                                }
                            }
                        }
                        if !srv6_sent {
                            // Could not honour the SR return path — signal via
                            // the U-flag (RFC 8972 §4.2) and reply normally.
                            let base_size = if use_auth {
                                AUTH_BASE_SIZE
                            } else {
                                UNAUTH_BASE_SIZE
                            };
                            if set_return_path_u_flag_in_response(&mut response.data, base_size) {
                                if let Some(ref key) = hmac_key {
                                    recompute_response_tlv_hmac(&mut response.data, base_size, key);
                                }
                            }
                        }
                    }

                    let sent_ok = if srv6_sent {
                        true
                    } else {
                        match tokio_socket.send_to(&response.data, send_target).await {
                            Ok(_) => {
                                #[cfg(all(feature = "hwtstamp", target_os = "linux"))]
                                if kernel_ts.tx_kernel {
                                    sent_opt_id = Some(
                                        tx_counter
                                            .fetch_add(1, std::sync::atomic::Ordering::Relaxed),
                                    );
                                }
                                true
                            }
                            Err(e) if send_target != src_addr => {
                                // Alternate-address send failed — set U-flag on Return Path TLV
                                // and fall back to original source (RFC 9503 §5).
                                log::debug!(
                                "Return Path: alternate send to {} failed ({}), falling back to {}",
                                send_target,
                                e,
                                src_addr
                            );
                                let base_size = if use_auth {
                                    AUTH_BASE_SIZE
                                } else {
                                    UNAUTH_BASE_SIZE
                                };
                                if set_return_path_u_flag_in_response(&mut response.data, base_size)
                                {
                                    if let Some(ref key) = hmac_key {
                                        recompute_response_tlv_hmac(
                                            &mut response.data,
                                            base_size,
                                            key,
                                        );
                                    }
                                }
                                match tokio_socket.send_to(&response.data, src_addr).await {
                                    Ok(_) => {
                                        #[cfg(all(feature = "hwtstamp", target_os = "linux"))]
                                        if kernel_ts.tx_kernel {
                                            sent_opt_id = Some(tx_counter.fetch_add(
                                                1,
                                                std::sync::atomic::Ordering::Relaxed,
                                            ));
                                        }
                                        true
                                    }
                                    Err(e2) => {
                                        eprintln!(
                                            "Failed to send response to {}: {}",
                                            src_addr, e2
                                        );
                                        false
                                    }
                                }
                            }
                            Err(e) => {
                                eprintln!("Failed to send response: {}", e);
                                false
                            }
                        }
                    };

                    if sent_ok {
                        counters
                            .packets_reflected
                            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        // Record transmission for Direct Measurement and Follow-Up Telemetry.
                        // Always tracked per-client, independent of --stateful-reflector.
                        let session = session_manager.get_or_create_session(src_addr);
                        session.record_transmitted();
                        // Extract the reflected seq from the response packet
                        // (first 4 bytes of reflected packet = sequence_number)
                        if response.data.len() >= 4 {
                            let reflected_seq = u32::from_be_bytes([
                                response.data[0],
                                response.data[1],
                                response.data[2],
                                response.data[3],
                            ]);
                            let send_ts = crate::time::generate_timestamp(conf.clock_source);
                            session.record_reflection(reflected_seq, send_ts);
                            // Map this send's OPT_ID to (client, seq) so the
                            // error-queue drain can replace the userspace
                            // timestamp above with the kernel TX timestamp.
                            #[cfg(all(feature = "hwtstamp", target_os = "linux"))]
                            if let Some(id) = sent_opt_id {
                                tx_id_map.insert(id, (src_addr, reflected_seq));
                            }
                        }

                        // Reflected Test Packet Control multi-send
                        // (draft-ietf-ippm-asymmetrical-pkts §3). Emit the
                        // additional copies asynchronously so the main recv
                        // loop is not blocked by the inter-packet gap. Each
                        // extra copy consumes one rate-limit token; the
                        // loop breaks early when the bucket runs out so a
                        // sender asking for an asymmetric burst can't
                        // exceed its per-client budget.
                        if let Some(behavior) = response.reflected_control {
                            if behavior.extra_copies > 0 {
                                let sock = Arc::clone(&tokio_socket);
                                let data = response.data.clone();
                                let target = send_target;
                                let counters_for_task = Arc::clone(&counters);
                                // Keep the kernel OPT_ID counter in sync: each
                                // extra copy consumes one counter slot even
                                // though its timestamp is not correlated.
                                #[cfg(all(feature = "hwtstamp", target_os = "linux"))]
                                let tx_counter_task =
                                    kernel_ts.tx_kernel.then(|| Arc::clone(&tx_counter));
                                let limiter_for_task = Arc::clone(&shared.rate_limiter);
                                let limiter_key = src_addr.ip();
                                tokio::spawn(async move {
                                    let interval =
                                        Duration::from_nanos(behavior.interval_ns as u64);
                                    for _ in 0..behavior.extra_copies {
                                        tokio::time::sleep(interval).await;
                                        if !limiter_for_task.allow(limiter_key) {
                                            counters_for_task
                                                .packets_rate_limited
                                                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                                            counters_for_task
                                                .packets_dropped
                                                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                                            break;
                                        }
                                        match sock.send_to(&data, target).await {
                                            Ok(_) => {
                                                counters_for_task.packets_reflected.fetch_add(
                                                    1,
                                                    std::sync::atomic::Ordering::Relaxed,
                                                );
                                                #[cfg(all(
                                                    feature = "hwtstamp",
                                                    target_os = "linux"
                                                ))]
                                                if let Some(ref c) = tx_counter_task {
                                                    c.fetch_add(
                                                        1,
                                                        std::sync::atomic::Ordering::Relaxed,
                                                    );
                                                }
                                            }
                                            Err(e) => {
                                                log::debug!(
                                                    "Reflected Control extra send failed: {}",
                                                    e
                                                );
                                                counters_for_task.packets_dropped.fetch_add(
                                                    1,
                                                    std::sync::atomic::Ordering::Relaxed,
                                                );
                                                break;
                                            }
                                        }
                                    }
                                });
                            }
                        }
                    } else {
                        counters
                            .packets_dropped
                            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    }
                }
            }
            Err(nix::errno::Errno::EAGAIN) => {
                // No data available, will retry after next readable notification
                continue;
            }
            Err(e) => {
                eprintln!("Receive error: {}", e);
            }
        }
    }
}

/// Extract TTL from control messages received via recvmsg.
///
/// Returns `None` if TTL/HopLimit could not be extracted from the control messages.
#[cfg(target_os = "linux")]
fn extract_ttl_from_cmsgs(msg: &nix::sys::socket::RecvMsg<SockaddrStorage>) -> Option<u8> {
    let cmsgs = msg.cmsgs().ok()?;

    for cmsg in cmsgs {
        match cmsg {
            // IPv4 TTL (from IP_RECVTTL socket option)
            ControlMessageOwned::Ipv4Ttl(ttl) => {
                // TTL is i32 but valid range is 0-255
                return Some(ttl.clamp(0, 255) as u8);
            }
            // IPv6 Hop Limit (from IPV6_RECVHOPLIMIT socket option)
            ControlMessageOwned::Ipv6HopLimit(hoplimit) => {
                // Hop limit is i32 but valid range is 0-255
                return Some(hoplimit.clamp(0, 255) as u8);
            }
            _ => continue,
        }
    }

    None
}

/// Extract TTL from control messages received via recvmsg (macOS version).
///
/// On macOS, nix doesn't have typed Ipv4Ttl/Ipv6HopLimit variants, so we parse Unknown cmsgs.
/// Returns `None` if TTL/HopLimit could not be extracted from the control messages.
#[cfg(target_os = "macos")]
fn extract_ttl_from_cmsgs(msg: &nix::sys::socket::RecvMsg<SockaddrStorage>) -> Option<u8> {
    let cmsgs = msg.cmsgs().ok()?;

    for cmsg in cmsgs {
        if let ControlMessageOwned::Unknown(ref ucmsg) = cmsg {
            let level = ucmsg.cmsg_header.cmsg_level;
            let data = &ucmsg.data_bytes;

            // IPv4 TTL (level=IPPROTO_IP)
            if level == libc::IPPROTO_IP {
                if data.len() >= 4 {
                    let ttl = i32::from_ne_bytes([data[0], data[1], data[2], data[3]]);
                    return Some(ttl.clamp(0, 255) as u8);
                } else if !data.is_empty() {
                    return Some(data[0]);
                }
            }
            // IPv6 Hop Limit (level=IPPROTO_IPV6)
            else if level == libc::IPPROTO_IPV6 {
                if data.len() >= 4 {
                    let hoplimit = i32::from_ne_bytes([data[0], data[1], data[2], data[3]]);
                    return Some(hoplimit.clamp(0, 255) as u8);
                } else if !data.is_empty() {
                    return Some(data[0]);
                }
            }
        }
    }

    None
}

/// Extract TOS (Type of Service) from control messages received via recvmsg.
///
/// Returns the raw TOS byte which contains DSCP (upper 6 bits) and ECN (lower 2 bits).
/// Returns `None` if TOS/Traffic Class could not be extracted from the control messages.
#[cfg(target_os = "linux")]
fn extract_tos_from_cmsgs(msg: &nix::sys::socket::RecvMsg<SockaddrStorage>) -> Option<u8> {
    let cmsgs = msg.cmsgs().ok()?;

    for cmsg in cmsgs {
        match cmsg {
            // IPv4 TOS (from IP_RECVTOS socket option)
            ControlMessageOwned::Ipv4Tos(tos) => {
                return Some(tos);
            }
            // IPv6 Traffic Class (from IPV6_RECVTCLASS socket option)
            ControlMessageOwned::Ipv6TClass(tclass) => {
                return Some(tclass.clamp(0, 255) as u8);
            }
            _ => continue,
        }
    }

    None
}

/// Extract TOS (Type of Service) from control messages received via recvmsg (macOS version).
///
/// Returns the raw TOS byte which contains DSCP (upper 6 bits) and ECN (lower 2 bits).
/// Returns `None` if TOS/Traffic Class could not be extracted from the control messages.
#[cfg(target_os = "macos")]
fn extract_tos_from_cmsgs(msg: &nix::sys::socket::RecvMsg<SockaddrStorage>) -> Option<u8> {
    let cmsgs = msg.cmsgs().ok()?;

    for cmsg in cmsgs {
        if let ControlMessageOwned::Unknown(ref ucmsg) = cmsg {
            let level = ucmsg.cmsg_header.cmsg_level;
            let cmsg_type = ucmsg.cmsg_header.cmsg_type;
            let data = &ucmsg.data_bytes;

            // IPv4 TOS (level=IPPROTO_IP, type=IP_RECVTOS)
            if level == libc::IPPROTO_IP && cmsg_type == libc::IP_RECVTOS {
                if data.len() >= 4 {
                    let tos = i32::from_ne_bytes([data[0], data[1], data[2], data[3]]);
                    return Some(tos.clamp(0, 255) as u8);
                } else if !data.is_empty() {
                    return Some(data[0]);
                }
            }
            // IPv6 Traffic Class (level=IPPROTO_IPV6, type=IPV6_RECVTCLASS)
            else if level == libc::IPPROTO_IPV6 && cmsg_type == libc::IPV6_TCLASS {
                if data.len() >= 4 {
                    let tclass = i32::from_ne_bytes([data[0], data[1], data[2], data[3]]);
                    return Some(tclass.clamp(0, 255) as u8);
                } else if !data.is_empty() {
                    return Some(data[0]);
                }
            }
        }
    }

    None
}

/// Extract destination IP address from control messages received via recvmsg.
///
/// Uses IP_PKTINFO (IPv4) or IPV6_PKTINFO (IPv6) to determine the actual
/// destination address of the received packet. This is needed when the reflector
/// is bound to a wildcard address (0.0.0.0 / ::) so the Location TLV reports
/// the real destination rather than the bind address.
///
/// Returns `None` if packet info could not be extracted from the control messages.
fn extract_dst_addr_from_cmsgs(msg: &nix::sys::socket::RecvMsg<SockaddrStorage>) -> Option<IpAddr> {
    let cmsgs = msg.cmsgs().ok()?;

    for cmsg in cmsgs {
        match cmsg {
            ControlMessageOwned::Ipv4PacketInfo(pktinfo) => {
                let octets = pktinfo.ipi_addr.s_addr.to_be_bytes();
                return Some(IpAddr::V4(Ipv4Addr::from(octets)));
            }
            ControlMessageOwned::Ipv6PacketInfo(pktinfo) => {
                return Some(IpAddr::V6(Ipv6Addr::from(pktinfo.ipi6_addr.s6_addr)));
            }
            _ => continue,
        }
    }

    None
}

// `build_local_addresses` now lives in `receiver::mod` and is shared between
// backends (see [`super::build_local_addresses`]).
