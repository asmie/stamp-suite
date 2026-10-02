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

use crate::configuration::Configuration;

use super::{
    ingest::{ReceivedPacket, ReflectorCore, ReflectorSettings},
    print_reflector_stats,
    transmit::{DatagramSender, ReplyQueue, ShutdownDrain},
    ReceiverSharedState,
};

/// Datagrams handled per readiness wakeup.
const RECV_BATCH: usize = 32;

/// Requested socket receive buffer.
const RECV_BUFFER_BYTES: usize = 4 << 20;

/// Runs the STAMP Session Reflector using nix for real TTL capture.
///
/// Uses IP_RECVTTL/IPV6_RECVHOPLIMIT socket options to capture the actual
/// TTL/Hop Limit from incoming packets. Preferred on Linux systems.
pub async fn run_receiver(
    conf: &Configuration,
    shared: &ReceiverSharedState,
) -> Result<(), crate::StartupError> {
    let local_addr: SocketAddr = conf.local_socket_addr();
    let is_ipv6 = conf.local_addr.is_ipv6();

    let std_socket = match std::net::UdpSocket::bind(local_addr) {
        Ok(s) => s,
        Err(e) => {
            return Err(crate::StartupError::io(
                format!("Cannot bind to address {local_addr}"),
                e,
            ));
        }
    };

    crate::net_policy::set_hops(&std_socket)
        .map_err(|e| crate::StartupError::io("Cannot set reply TTL/Hop Limit 255", e))?;
    if let Some(name) = conf.interface.as_deref() {
        crate::net_policy::bind_to_interface(&std_socket, name)
            .map_err(|e| crate::StartupError::io(format!("Cannot bind to interface {name}"), e))?;
    }

    let local_addr = std_socket
        .local_addr()
        .map_err(|e| crate::StartupError::io("Cannot get bound address", e))?;

    // The default buffer holds about a millisecond of traffic at high packet
    // rates, so a short scheduling delay drops requests. The kernel caps the
    // request at net.core.rmem_max.
    if let Err(e) = socket2::SockRef::from(&std_socket).set_recv_buffer_size(RECV_BUFFER_BYTES) {
        log::debug!("Cannot enlarge the receive buffer: {e}");
    }

    // Enable TTL/Hop Limit and TOS/Traffic Class reception with libc directly:
    // nix exposes these options only on Linux, Android and FreeBSD, and this
    // backend also builds for macOS.
    let fd = std_socket.as_raw_fd();
    let enable: libc::c_int = 1;

    // Enable TTL/Hop Limit reception
    let result = if is_ipv6 {
        // SAFETY: `fd` is the open socket owned by `std_socket`; the value
        // pointer and length describe the live `enable` c_int.
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
        // SAFETY: `fd` is the open socket owned by `std_socket`; the value
        // pointer and length describe the live `enable` c_int.
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
        return Err(crate::StartupError::io(
            "Failed to set IP_RECVTTL/IPV6_RECVHOPLIMIT",
            std::io::Error::last_os_error(),
        ));
    }

    // Enable TOS/Traffic Class reception (for DSCP/ECN measurement)
    let tos_result = if is_ipv6 {
        // SAFETY: `fd` is the open socket owned by `std_socket`; the value
        // pointer and length describe the live `enable` c_int.
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
        // SAFETY: `fd` is the open socket owned by `std_socket`; the value
        // pointer and length describe the live `enable` c_int.
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

    // IPv6 extension headers arrive as ancillary data, in wire order, for
    // Type 246 reflection (draft-ietf-ippm-stamp-ext-hdr-15 §4.2). Without
    // them those requests get the C flag.
    #[cfg(target_os = "linux")]
    if is_ipv6 {
        for option in [
            libc::IPV6_RECVHOPOPTS,
            libc::IPV6_RECVDSTOPTS,
            libc::IPV6_RECVRTHDR,
        ] {
            // SAFETY: `fd` is the open socket owned by `std_socket`; the value
            // pointer and length describe the live `enable` c_int.
            let result = unsafe {
                libc::setsockopt(
                    fd,
                    libc::IPPROTO_IPV6,
                    option,
                    &enable as *const _ as *const libc::c_void,
                    std::mem::size_of::<libc::c_int>() as libc::socklen_t,
                )
            };
            if result < 0 {
                log::warn!(
                    "Cannot receive IPv6 extension headers: {} (Type 246 requests get C)",
                    std::io::Error::last_os_error()
                );
                break;
            }
        }
    }

    // Enable packet info reception for destination address (for Location TLV).
    // Without this, a wildcard bind (0.0.0.0/::) reports the bind address as dst_addr.
    let pktinfo_result = if is_ipv6 {
        // SAFETY: `fd` is the open socket owned by `std_socket`; the value
        // pointer and length describe the live `enable` c_int.
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
        // SAFETY: `fd` is the open socket owned by `std_socket`; the value
        // pointer and length describe the live `enable` c_int.
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
        return Err(crate::StartupError::io(
            "Failed to set socket non-blocking",
            e,
        ));
    }

    // Wrap in Tokio for async readiness notifications. This loop owns the
    // socket and every burst send; DatagramSender borrows its descriptor,
    // so no shared socket allocation or per-burst socket clone is needed.
    let tokio_socket = match UdpSocket::from_std(std_socket) {
        Ok(s) => s,
        Err(e) => {
            return Err(crate::StartupError::io("Failed to create tokio socket", e));
        }
    };

    let settings = ReflectorSettings::from_config(
        conf,
        shared,
        conf.srv6_return_forwarding && crate::srv6::srh_supported(),
    )?;
    let core = ReflectorCore::new(settings, shared, conf.reflector_queue_capacity as usize);
    let counters = Arc::clone(&core.counters);
    let session_manager = Arc::clone(&core.session_manager);
    let start_time = shared.start_time;
    let output_format = conf.output_format;

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
    // cmsg (feature "hwtstamp") with headroom. IPv6 adds room for Hop-by-Hop,
    // Destination Options and Routing headers of up to 2048 bytes each (Hdr
    // Ext Len 255), each behind a 16-byte cmsg header.
    let mut cmsg_buf = vec![0u8; if is_ipv6 { 512 + 3 * (2048 + 16) } else { 512 }];

    // One loop owns every send and its OPT_ID assignment, including burst copies.
    let mut replies = ReplyQueue::default();
    let budget = Arc::clone(&core.budget);
    let grace = Duration::from_millis(u64::from(conf.reflector_shutdown_grace_ms));
    let mut drain = ShutdownDrain::default();
    let mut mtu_cache = super::mtu::MtuCache::default();
    #[cfg(all(feature = "hwtstamp", target_os = "linux"))]
    let mut tx_counter = 0u32;
    #[cfg(all(feature = "hwtstamp", target_os = "linux"))]
    let mut tx_id_map: std::collections::HashMap<
        u32,
        (std::sync::Weak<crate::session::Session>, u32),
    > = std::collections::HashMap::new();
    #[cfg(all(feature = "hwtstamp", target_os = "linux"))]
    let mut errqueue_suspect = false;

    let mut datagram_sender = DatagramSender::new(&tokio_socket);

    // Session cleanup interval: run at half the timeout period, minimum 1 second
    // When session_timeout is 0, checked_div returns None, disabling cleanup
    let cleanup_interval = conf
        .session_timeout
        .checked_div(2)
        .map(|t| Duration::from_secs(t.max(1)));
    let mut cleanup_timer = cleanup_interval.map(interval);

    let shutdown = shared.shutdown.clone();

    // Sends the next copy of a reply, records its TX-timestamp correlation,
    // and requeues any later burst copies. This loop is the only sender, so
    // OPT_ID numbering follows send order.
    macro_rules! send_copy {
        ($queued:expr) => {{
            let mut queued = $queued;
            let transmission = &mut queued.transmission;
            let sent = transmission.send_next_with_mtu(
                &counters,
                &shared.rate_limiter,
                |target, options, refresh| {
                    mtu_cache.payload_cap(local_addr, target, options, refresh)
                },
                |bytes, target, options| datagram_sender.send(bytes, target, options),
            );
            #[cfg(all(feature = "hwtstamp", target_os = "linux"))]
            if let (Some(sequence), true) = (sent, kernel_ts.tx_kernel) {
                tx_id_map.insert(
                    tx_counter,
                    (Arc::downgrade(&transmission.session), sequence),
                );
                tx_counter = tx_counter.wrapping_add(1);
            }
            #[cfg(not(all(feature = "hwtstamp", target_os = "linux")))]
            let _ = sent;
            replies.schedule_next(queued);
        }};
    }

    loop {
        if drain.finished(std::time::Instant::now(), budget.is_empty()) {
            drop(replies); // Account for every unsent copy before printing stats.
            print_reflector_stats(&counters, &session_manager, start_time, output_format);
            return Ok(());
        }
        // Apply kernel TX timestamps that arrived on the error queue since
        // the last iteration: correct the Follow-Up Telemetry record of the
        // matching reflection (RFC 8972 §4.7 reports the *previous* reply's
        // TX time, so the one-iteration delay is inherent to the TLV).
        #[cfg(all(feature = "hwtstamp", target_os = "linux"))]
        // The error queue only fills after sends, so skip the syscall when no
        // send awaits a timestamp, unless an empty readable wakeup suggests
        // leftover error-queue messages.
        if kernel_ts.tx_kernel && (!tx_id_map.is_empty() || errqueue_suspect) {
            errqueue_suspect = false;
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
                if let Some(queued) = replies.pop_due() {
                    send_copy!(queued);
                }
                continue;
            }
            result = tokio_socket.readable(), if drain.deadline().is_none() => {
                if let Err(e) = result {
                    crate::warn_throttled!("Failed to wait for readable: {}", e);
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
                let removed = session_manager.cleanup_stale_sessions();
                if removed > 0 {
                    log::debug!("Session cleanup: removed {} stale sessions", removed);
                }
                continue;
            }

            _ = shutdown.cancelled(), if drain.deadline().is_none() => {
                drain.begin(std::time::Instant::now(), grace);
                continue;
            }

            _ = async {
                if let Some(at) = drain.deadline() {
                    tokio::time::sleep_until(at.into()).await;
                } else {
                    std::future::pending::<()>().await;
                }
            } => { continue; }
        }

        // Drain a bounded batch per wakeup; the bound keeps timers, shutdown
        // and queued burst copies serviced under sustained load.
        for received in 0..RECV_BATCH {
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

                    let ttl = match extract_ttl_from_cmsgs(&msg) {
                        Some(t) => t,
                        None => {
                            crate::warn_throttled!("Failed to extract TTL from packet, skipping");
                            continue;
                        }
                    };

                    // Extract TOS (DSCP/ECN) from control messages
                    let (received_dscp, received_ecn) = extract_tos_from_cmsgs(&msg)
                        .map(|tos| (crate::tos::Tos(tos).dscp(), crate::tos::Tos(tos).ecn()))
                        .unwrap_or((0, 0));

                    // Extract actual destination address from packet info (for Location TLV).
                    // Falls back to configured bind address if pktinfo is unavailable.
                    let pktinfo = extract_dst_addr_from_cmsgs(&msg);
                    let (dst_addr, ingress_interface) =
                        pktinfo.unwrap_or((conf.local_addr, conf.local_scope_id));
                    // Only Linux can pin a reply to this interface (RFC 9503 §4.1.1).
                    let ingress_ifindex = pktinfo
                        .map(|(_, index)| index)
                        .filter(|&index| cfg!(target_os = "linux") && index != 0);
                    let packet_local_addr = crate::net_scope::received_endpoint(
                        dst_addr,
                        local_addr.port(),
                        ingress_interface,
                    );

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
                                crate::net_scope::received_endpoint(
                                    v6.ip().into(),
                                    v6.port(),
                                    if v6.scope_id() != 0 {
                                        v6.scope_id()
                                    } else {
                                        ingress_interface
                                    },
                                )
                            } else {
                                crate::warn_throttled!("Unknown source address type");
                                continue;
                            }
                        }
                        None => {
                            crate::warn_throttled!("No source address available");
                            continue;
                        }
                    };

                    #[cfg(target_os = "linux")]
                    let captured = super::CapturedHeaders {
                        fixed_headers: Vec::new(),
                        ipv6_ext_headers: extract_ipv6_ext_headers(&msg),
                    };

                    let packet = ReceivedPacket {
                        data: &buf[..len],
                        src: src_addr,
                        dst_addr,
                        local: packet_local_addr,
                        ttl,
                        dscp: received_dscp,
                        ecn: received_ecn,
                        ingress_ifindex,
                        src_mac: None, // a UDP socket does not see the link layer
                        // A UDP socket cannot read fixed IP headers, so Type 247
                        // requests get C (draft-ietf-ippm-stamp-ext-hdr-15 §6.1).
                        // Linux supplies IPv6 extension headers for Type 246;
                        // other systems supply none, so those requests get C too.
                        #[cfg(target_os = "linux")]
                        captured_headers: Some(&captured),
                        #[cfg(not(target_os = "linux"))]
                        captured_headers: None,
                        #[cfg(feature = "hwtstamp")]
                        rx_timestamp,
                        #[cfg(not(feature = "hwtstamp"))]
                        rx_timestamp: None,
                        #[cfg(feature = "hwtstamp")]
                        rx_method,
                        #[cfg(not(feature = "hwtstamp"))]
                        rx_method: crate::tlv::TimestampMethod::SwLocal,
                    };
                    // The first copy goes out now; only later burst copies wait
                    // in the deadline queue.
                    if let Some(transmission) = core.ingest(&packet) {
                        send_copy!(transmission);
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    // try_io cleared stale readiness; the next iteration can
                    // sleep while still servicing cleanup/shutdown/error-queue work.
                    #[cfg(all(feature = "hwtstamp", target_os = "linux"))]
                    {
                        errqueue_suspect |= received == 0;
                    }
                    #[cfg(not(all(feature = "hwtstamp", target_os = "linux")))]
                    let _ = received;
                    break;
                }
                Err(e) => {
                    crate::warn_throttled!("Receive error: {}", e);
                    break;
                }
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
    for cmsg in msg.cmsgs().ok()? {
        if let ControlMessageOwned::Unknown(ref ucmsg) = cmsg {
            if let Some(hops) = darwin_hop_value(
                ucmsg.cmsg_header.cmsg_level,
                ucmsg.cmsg_header.cmsg_type,
                &ucmsg.data_bytes,
            ) {
                return Some(hops);
            }
        }
    }
    None
}

// Darwin sends IPv4 TTL as one byte under IP_RECVTTL and IPv6 Hop Limit as
// an int under IPV6_HOPLIMIT. Other metadata at the same level is not a TTL.
#[cfg(any(target_os = "macos", test))]
fn darwin_hop_value(level: i32, kind: i32, data: &[u8]) -> Option<u8> {
    match (level, kind) {
        (libc::IPPROTO_IP, libc::IP_RECVTTL) if data.len() == 1 => Some(data[0]),
        (libc::IPPROTO_IPV6, libc::IPV6_HOPLIMIT) => {
            let bytes: [u8; 4] = data.try_into().ok()?;
            u8::try_from(i32::from_ne_bytes(bytes)).ok()
        }
        _ => None,
    }
}

#[test]
fn darwin_hop_metadata_rejects_unrelated_or_malformed_controls() {
    assert_eq!(
        darwin_hop_value(libc::IPPROTO_IP, libc::IP_RECVTTL, &[37]),
        Some(37)
    );
    assert_eq!(
        darwin_hop_value(
            libc::IPPROTO_IPV6,
            libc::IPV6_HOPLIMIT,
            &255i32.to_ne_bytes()
        ),
        Some(255)
    );
    assert_eq!(
        darwin_hop_value(libc::IPPROTO_IP, libc::IP_RECVTOS, &[184]),
        None
    );
    assert_eq!(
        darwin_hop_value(libc::IPPROTO_IPV6, libc::IPV6_TCLASS, &184i32.to_ne_bytes()),
        None
    );
    for bytes in [
        &[][..],
        &[37][..],
        &(-1i32).to_ne_bytes()[..],
        &256i32.to_ne_bytes()[..],
    ] {
        assert_eq!(
            darwin_hop_value(libc::IPPROTO_IPV6, libc::IPV6_HOPLIMIT, bytes),
            None
        );
    }
}

/// IPv6 Hop-by-Hop, Destination Options and Routing headers from ancillary
/// data, concatenated in the order Linux reports them, which is wire order.
/// Each record keeps its Next Header and Hdr Ext Len octets. Truncated
/// ancillary data yields nothing, so requests get the C flag.
#[cfg(target_os = "linux")]
fn extract_ipv6_ext_headers(msg: &nix::sys::socket::RecvMsg<SockaddrStorage>) -> Vec<u8> {
    let mut headers = Vec::new();
    if msg.flags.contains(MsgFlags::MSG_CTRUNC) {
        return headers;
    }
    let Ok(cmsgs) = msg.cmsgs() else {
        return headers;
    };
    for cmsg in cmsgs {
        let ControlMessageOwned::Unknown(unknown) = cmsg else {
            continue;
        };
        let header = &unknown.cmsg_header;
        let is_ext = header.cmsg_level == libc::IPPROTO_IPV6
            && matches!(
                header.cmsg_type,
                libc::IPV6_HOPOPTS | libc::IPV6_DSTOPTS | libc::IPV6_RTHDR
            );
        let bytes = &unknown.data_bytes;
        // Hdr Ext Len counts 8-octet units after the first eight.
        if is_ext && bytes.len() >= 2 && bytes.len() == (usize::from(bytes[1]) + 1) * 8 {
            headers.extend_from_slice(bytes);
        }
    }
    headers
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
            // IPv6 Traffic Class (level=IPPROTO_IPV6, type=IPV6_TCLASS)
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

/// Extract destination IP address and ingress interface index from recvmsg metadata.
///
/// Uses IP_PKTINFO (IPv4) or IPV6_PKTINFO (IPv6) to determine the actual
/// destination address of the received packet. This is needed when the reflector
/// is bound to a wildcard address (0.0.0.0 / ::) so the Location TLV reports
/// the real destination rather than the bind address.
///
/// Returns `None` if packet info could not be extracted from the control messages.
fn extract_dst_addr_from_cmsgs(
    msg: &nix::sys::socket::RecvMsg<SockaddrStorage>,
) -> Option<(IpAddr, u32)> {
    let cmsgs = msg.cmsgs().ok()?;

    for cmsg in cmsgs {
        match cmsg {
            ControlMessageOwned::Ipv4PacketInfo(pktinfo) => {
                return Some((
                    IpAddr::V4(ipv4_addr_from_pktinfo(&pktinfo)),
                    u32::try_from(pktinfo.ipi_ifindex).unwrap_or(0),
                ));
            }
            ControlMessageOwned::Ipv6PacketInfo(pktinfo) => {
                return Some((
                    IpAddr::V6(Ipv6Addr::from(pktinfo.ipi6_addr.s6_addr)),
                    pktinfo.ipi6_ifindex,
                ));
            }
            _ => continue,
        }
    }

    None
}

/// Extracts IPv4 octets from `IP_PKTINFO` without changing byte order.
/// `s_addr` already stores network-order bytes. `to_ne_bytes()` preserves them;
/// `to_be_bytes()` would reverse the address on little-endian hosts.
fn ipv4_addr_from_pktinfo(pktinfo: &libc::in_pktinfo) -> Ipv4Addr {
    Ipv4Addr::from(pktinfo.ipi_addr.s_addr.to_ne_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Model kernel `in_pktinfo` bytes for 127.0.0.1 and verify extraction
    /// preserves the address instead of reversing it to 1.0.0.127.
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

    /// An address with four distinct octets makes any byte reversal obvious,
    /// unlike 127.0.0.1's mostly-zero octets.
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
