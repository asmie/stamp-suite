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

use super::transmit::{send_datagram, ReplyQueue, Transmission};

use super::{
    hmac_key_source_configured, load_hmac_key, print_reflector_stats,
    process_session_packet_isolated, ProcessingContext, ReceiverSharedState,
};

/// Runs the STAMP Session Reflector using nix for real TTL capture.
///
/// Uses IP_RECVTTL/IPV6_RECVHOPLIMIT socket options to capture the actual
/// TTL/Hop Limit from incoming packets. Preferred on Linux systems.
pub async fn run_receiver(
    conf: &Configuration,
    shared: &ReceiverSharedState,
) -> Result<(), crate::StartupError> {
    let local_addr: SocketAddr = (conf.local_addr, conf.local_port).into();
    let is_ipv6 = conf.local_addr.is_ipv6();

    // Create a standard UDP socket
    let std_socket = match std::net::UdpSocket::bind(local_addr) {
        Ok(s) => s,
        Err(e) => {
            return Err(crate::StartupError::new(format!(
                "Cannot bind to address {local_addr}: {e}"
            )));
        }
    };

    let local_addr = std_socket
        .local_addr()
        .map_err(|e| crate::StartupError::new(format!("Cannot get bound address: {e}")))?;

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
        return Err(crate::StartupError::new(format!(
            "Failed to set IP_RECVTTL/IPV6_RECVHOPLIMIT: {}",
            std::io::Error::last_os_error()
        )));
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
    // Set non-blocking for tokio
    if let Err(e) = std_socket.set_nonblocking(true) {
        return Err(crate::StartupError::new(format!(
            "Error: Failed to set socket non-blocking: {e}"
        )));
    }

    // Wrap in tokio for async readiness notifications. Arc so spawned tasks
    // (e.g. Reflected Test Packet Control multi-send,
    // draft-ietf-ippm-asymmetrical-pkts §3) can share the socket.
    let tokio_socket = match UdpSocket::from_std(std_socket) {
        Ok(s) => Arc::new(s),
        Err(e) => {
            return Err(crate::StartupError::new(format!(
                "Error: Failed to create tokio socket: {e}"
            )));
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
        return Err(crate::StartupError::new(
            "Authenticated mode (-A A) requires --hmac-key, --hmac-key-file, or --hmac-key-dir",
        ));
    }

    // A key source that failed to load is a configuration error in either mode:
    // in open mode the key still signs and verifies TLV HMACs, so continuing
    // without it would silently drop that protection.
    if hmac_key.is_none() && !keyset_configured && hmac_key_source_configured(conf) {
        return Err(crate::StartupError::new(
            "an HMAC key source was configured (--hmac-key, --hmac-key-file or \
             --hmac-key-dir) but no usable key could be loaded; see the error above. \
             Refusing to run without the key that was asked for",
        ));
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
    // RFC 8972 §4.2.2 Location field-disclosure policy. `validate()` already
    // rejected a bad list at startup; fall back to the permissive default
    // rather than dropping traffic if that somehow did not run.
    let location_disclosure = conf.location_disclosure().unwrap_or_default();
    // RFC 8972 §4.4/§6 + cos-ecn-01 §3.2 admission policy, resolved once.
    // `validate()` already rejected a bad spec at startup; the permissive
    // default is the safe fallback if that somehow did not run.
    let cos_policy = conf
        .cos_admission_policy()
        .unwrap_or_else(|_| crate::cos_policy::CosAdmissionPolicy::permit_all());
    if !cos_policy.is_permissive() {
        log::info!(
            "CoS admission policy active (--allowed-dscp {}, --allowed-ecn {}, {} \
             destination rule(s)): a refused DSCP1/EC1 is reported via RPD/RPE \
             instead of being applied",
            conf.allowed_dscp,
            conf.allowed_ecn,
            conf.allowed_dscp_for.len()
        );
    }

    // Build local MAC addresses for the Reflected Test Packet Control TLV's
    // L2 Address Group sub-TLV matching (draft-ietf-ippm-asymmetrical-pkts-14
    // §3.1.1). Unlike `local_addresses`, this always enumerates every
    // interface's hardware address regardless of the bind address.
    let local_macs = super::build_local_macs();

    log::info!(
        "STAMP Reflector listening on {} (nix mode, real TTL)",
        local_addr
    );

    // Full-size UDP payloads, not "typical" STAMP packets: --extra-padding
    // grows requests to MTU-probing sizes, and a request truncated here would
    // be answered wrong (or rejected) instead of echoed. One heap allocation
    // for the life of the loop.
    let mut buf = vec![0u8; crate::packets::MAX_UDP_PAYLOAD];
    // 512 bytes: TTL + TOS + PKTINFO plus the 64-byte SCM_TIMESTAMPING
    // cmsg (feature "hwtstamp") with headroom.
    let mut cmsg_buf = vec![0u8; 512];

    // One loop owns every send and its OPT_ID assignment, including burst copies.
    let mut replies = ReplyQueue::default();
    let mut mtu_cache = super::mtu::MtuCache::default();
    #[cfg(all(feature = "hwtstamp", target_os = "linux"))]
    let mut tx_counter = 0u32;
    #[cfg(all(feature = "hwtstamp", target_os = "linux"))]
    let mut tx_id_map: std::collections::HashMap<
        u32,
        (std::sync::Weak<crate::session::Session>, u32),
    > = std::collections::HashMap::new();

    // Session cleanup interval: run at half the timeout period, minimum 1 second
    // When session_timeout is 0, checked_div returns None, disabling cleanup
    let cleanup_interval = conf
        .session_timeout
        .checked_div(2)
        .map(|t| Duration::from_secs(t.max(1)));
    let mut cleanup_timer = cleanup_interval.map(interval);

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
                if let Some((session, seq)) = tx_id_map.get(&report.opt_id).cloned() {
                    let updated = session.upgrade().is_some_and(|session| {
                        session.correct_reflection_timestamp_with_method(
                            seq,
                            report.timestamp,
                            report.method(),
                        )
                    });
                    // Software and hardware reports can arrive separately. Keep
                    // correlation after software while a hardware report is pending.
                    if report.hardware || !kernel_ts.tx_hw || !updated {
                        tx_id_map.remove(&report.opt_id);
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
            _ = async {
                if let Some(deadline) = replies.deadline() {
                    tokio::time::sleep_until(deadline.into()).await;
                } else {
                    std::future::pending::<()>().await;
                }
            } => {
                if let Some(mut transmission) = replies.pop_due() {
                    if let Some(_sequence) = transmission.send_next_with_mtu(&counters, &shared.rate_limiter, |target, options, refresh| mtu_cache.payload_cap(tokio_socket.local_addr()?, target, options, refresh), |bytes, target, options| send_datagram(tokio_socket.as_raw_fd(), bytes, target, options)) {
                        #[cfg(all(feature = "hwtstamp", target_os = "linux"))]
                        if kernel_ts.tx_kernel {
                            tx_id_map.insert(tx_counter, (Arc::downgrade(&transmission.session), _sequence));
                            tx_counter = tx_counter.wrapping_add(1);
                        }
                    }
                    replies.schedule_next(transmission);
                }
                continue;
            }
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
                return Ok(());
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
                    return Ok(());
                }
            }
        }

        // Keep ancillary metadata while letting Tokio clear cached readiness
        // when recvmsg reaches EAGAIN. Calling the raw syscall alone leaves
        // readable() ready forever after the first datagram is consumed.
        let mut iov = [IoSliceMut::new(&mut buf)];

        match tokio_socket.try_io(tokio::io::Interest::READABLE, || {
            recvmsg::<SockaddrStorage>(
                tokio_socket.as_raw_fd(),
                &mut iov,
                Some(&mut cmsg_buf),
                MsgFlags::MSG_DONTWAIT,
            )
            .map_err(|e| std::io::Error::from_raw_os_error(e as i32))
        }) {
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

                // Build packet address info for Location TLV
                let packet_addr_info = Some(crate::tlv::PacketAddressInfo {
                    src_addr: src_addr.ip(),
                    src_port: src_addr.port(),
                    dst_addr,
                    dst_port: local_addr.port(),
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
                        replay_verdict: crate::session::ReplayVerdict::New,
                        clock_source: conf.clock_source,
                        clock_sync_source: conf.clock_sync_source.into(),
                        hardware_clock_sync_source: conf.hardware_clock_sync_source.into(),
                        error_estimate_wire,
                        hmac_key: hmac_key.as_ref(),
                        hmac_key_set: keys_guard.as_ref(),
                        require_hmac: conf.require_hmac,
                        session_manager: Some(&session_manager),
                        stateful_reflector: conf.stateful_reflector,
                        tlv_mode: conf.tlv_mode,
                        verify_tlv_hmac: conf.verify_tlv_hmac,
                        strict_packets: conf.strict_packets,
                        #[cfg(feature = "metrics")]
                        metrics_enabled: conf.metrics,
                        received_dscp,
                        received_ecn,
                        reflector_rx_count: None,
                        reflector_tx_count: None,
                        packet_addr_info,
                        last_reflection: None,
                        location_disclosure,
                        cos_policy: &cos_policy,
                        local_addresses: &local_addresses,
                        local_macs: &local_macs,
                        sender_port: src_addr.port(),
                        return_path_allow_alternate: conf.return_path_allow_alternate,
                        reflector_member_link_id: conf.reflector_member_link_id,
                        // nix UDP-socket backend cannot observe raw IP headers.
                        // draft-ietf-ippm-stamp-ext-hdr-11 TLV 246/247 requests are
                        // echoed with the C flag (Conformance) set — case (b),
                        // done in apply_semantic_tlv_processing.
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
                        last_reflection_method: crate::tlv::TimestampMethod::SwLocal,
                    };
                    process_session_packet_isolated(
                        data,
                        src_addr,
                        ttl,
                        use_auth,
                        &ctx,
                        &counters,
                        conf.drop_replayed,
                    )
                    .map(|(response, session, signing_key)| {
                        Transmission::new(
                            response,
                            session,
                            src_addr,
                            conf.clock_source,
                            use_auth,
                            conf.stateful_reflector,
                            signing_key,
                            received_dscp,
                            conf.srv6_return_forwarding && crate::srv6::srh_supported(),
                        )
                    })
                };
                if let Some(transmission) = response_opt {
                    replies.push_at(transmission, std::time::Instant::now());
                } else {
                    counters
                        .packets_dropped
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                // try_io cleared stale readiness; the next iteration can
                // sleep while still servicing cleanup/shutdown/error-queue work.
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
                return Some(IpAddr::V4(ipv4_addr_from_pktinfo(&pktinfo)));
            }
            ControlMessageOwned::Ipv6PacketInfo(pktinfo) => {
                return Some(IpAddr::V6(Ipv6Addr::from(pktinfo.ipi6_addr.s6_addr)));
            }
            _ => continue,
        }
    }

    None
}

/// Convert the destination address carried in an `IP_PKTINFO` control
/// message into an [`Ipv4Addr`].
///
/// `libc::in_pktinfo::ipi_addr.s_addr` is filled in by the kernel and is
/// already in network byte order (the raw in-memory bytes are the address
/// octets in order, e.g. `[127, 0, 0, 1]`). It must NOT be round-tripped
/// through [`u32::to_be_bytes`]: on a little-endian host that performs an
/// extra, unwanted byte-order flip on top of the one the kernel already
/// did, silently reversing the octets (127.0.0.1 becomes 1.0.0.127).
/// [`u32::to_ne_bytes`] copies the underlying byte layout as-is and is
/// correct on both little- and big-endian hosts — mirroring how the IPv6
/// sibling path below reads `s6_addr` directly without any conversion.
fn ipv4_addr_from_pktinfo(pktinfo: &libc::in_pktinfo) -> Ipv4Addr {
    Ipv4Addr::from(pktinfo.ipi_addr.s_addr.to_ne_bytes())
}

// `build_local_addresses` now lives in `receiver::mod` and is shared between
// backends (see [`super::build_local_addresses`]).

#[cfg(test)]
mod tests {
    use super::*;

    /// Cross-implementation testing (local) surfaced a byte-reversed IPv4
    /// destination address in the Location TLV: a packet sent to
    /// 127.0.0.1 was reported as 1.0.0.127. Root cause was an extra
    /// `to_be_bytes()` round trip on a value (`ipi_addr.s_addr`) that the
    /// kernel already delivers in network byte order.
    ///
    /// This hand-builds a `libc::in_pktinfo` the way the kernel would fill
    /// it in for a packet destined to 127.0.0.1 — `s_addr`'s raw bytes are
    /// the octets in wire order — and asserts extraction recovers
    /// 127.0.0.1 unchanged.
    #[test]
    fn ipv4_pktinfo_extraction_preserves_octet_order() {
        let s_addr = u32::from(Ipv4Addr::new(127, 0, 0, 1)).to_be();
        let pktinfo = libc::in_pktinfo {
            ipi_ifindex: 0,
            ipi_spec_dst: libc::in_addr { s_addr: 0 },
            ipi_addr: libc::in_addr { s_addr },
        };

        let addr = ipv4_addr_from_pktinfo(&pktinfo);

        assert_eq!(
            addr,
            Ipv4Addr::new(127, 0, 0, 1),
            "extraction must not byte-reverse the destination address"
        );
    }

    /// A second, non-palindromic-octet address makes any byte reversal
    /// obvious (unlike 127.0.0.1's mostly-zero octets, though that case is
    /// covered above since it was the exact regression report).
    #[test]
    fn ipv4_pktinfo_extraction_non_symmetric_address() {
        let s_addr = u32::from(Ipv4Addr::new(192, 0, 2, 55)).to_be();
        let pktinfo = libc::in_pktinfo {
            ipi_ifindex: 0,
            ipi_spec_dst: libc::in_addr { s_addr: 0 },
            ipi_addr: libc::in_addr { s_addr },
        };

        let addr = ipv4_addr_from_pktinfo(&pktinfo);

        assert_eq!(addr, Ipv4Addr::new(192, 0, 2, 55));
    }
}
