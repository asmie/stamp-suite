use std::{
    collections::HashMap,
    net::SocketAddr,
    time::{Duration, Instant},
};

use tokio::net::UdpSocket;

use crate::{
    clock_format::ClockFormat,
    configuration::{is_auth, Configuration},
    crypto::{compute_packet_hmac, verify_packet_hmac, HmacKey},
    error_estimate::ErrorEstimate,
    packets::{
        ExtendedPacketAuthenticated, ExtendedPacketUnauthenticated,
        ExtendedReflectedPacketAuthenticated, ExtendedReflectedPacketUnauthenticated,
        PacketAuthenticated, PacketUnauthenticated, ReflectedPacketAuthenticated,
        ReflectedPacketUnauthenticated,
    },
    receiver::{
        load_hmac_key, AUTH_BASE_SIZE, REFLECTED_AUTH_PACKET_HMAC_OFFSET, UNAUTH_BASE_SIZE,
    },
    session::Session,
    stats::{RttCollector, RttSample, StatsSnapshot},
    time::generate_timestamp,
    tlv::{
        AccessReportTlv, ClassOfServiceTlv, DestinationNodeAddressTlv, DirectMeasurementTlv,
        FollowUpTelemetryTlv, LocationTlv, RawTlv, ReturnPathTlv, SessionSenderId, SyncSource,
        TimestampInfoTlv, TimestampMethod, TlvList,
    },
};

/// Internal structure to track packets awaiting responses.
struct PendingPacket {
    /// Wall-clock time when the packet was sent.
    send_time: Instant,
    /// STAMP timestamp embedded in the sent packet.
    #[allow(dead_code)]
    send_timestamp: u64,
}

/// Mutable context for processing received responses.
struct SenderRecvContext<'a> {
    pending: &'a mut HashMap<u32, PendingPacket>,
    rtt_collector: &'a mut RttCollector,
    packets_received: &'a mut u32,
    print_stats: bool,
    hmac_key: Option<&'a HmacKey>,
    #[cfg(feature = "metrics")]
    metrics_enabled: bool,
    #[cfg(all(unix, feature = "snmp"))]
    snmp_stats: Option<&'a crate::snmp::state::SenderSnmpStats>,
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

    let sess = Session::new(0);
    let mut pending: HashMap<u32, PendingPacket> = HashMap::new();
    let mut rtt_collector = RttCollector::new();
    let mut packets_sent: u32 = 0;
    let mut packets_received: u32 = 0;
    let mut recv_buf = [0u8; 1024];
    let timeout = Duration::from_secs(conf.timeout as u64);

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

    if let Some(access_id) = conf.access_report {
        extra_tlvs.push(AccessReportTlv::new(access_id, conf.access_return_code).to_raw());
        log::info!(
            "Access Report TLV enabled (id={}, code={})",
            access_id,
            conf.access_return_code
        );
    }

    if conf.timestamp_info {
        let sync_src = match conf.clock_source {
            ClockFormat::NTP => SyncSource::Ntp,
            ClockFormat::PTP => SyncSource::Ptp,
        };
        extra_tlvs.push(TimestampInfoTlv::new(sync_src, TimestampMethod::SwLocal).to_raw());
        log::info!("Timestamp Information TLV enabled");
    }

    if conf.location {
        extra_tlvs.push(LocationTlv::new().to_raw());
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

    // Check if we need to include TLV extensions
    let use_tlvs = conf.ssid.is_some() || !extra_tlvs.is_empty() || conf.direct_measurement;
    if use_tlvs {
        if let Some(ssid) = conf.ssid {
            log::info!("TLV extensions enabled with SSID: {}", ssid);
        }
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
        SendMode::OpenTlv {
            tlv_key: hmac_key.as_ref(),
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

        // Build per-packet TLVs (Direct Measurement changes each packet)
        let per_packet_tlvs: Vec<RawTlv>;
        let all_extra_tlvs = if conf.direct_measurement {
            let dm = DirectMeasurementTlv::new(packets_sent + 1);
            per_packet_tlvs = extra_tlvs
                .iter()
                .cloned()
                .chain(std::iter::once(dm.to_raw()))
                .collect();
            &per_packet_tlvs
        } else {
            &extra_tlvs
        };

        let send_result = match &send_mode {
            SendMode::AuthTlv { key } => {
                let buf = build_auth_packet_with_tlvs(
                    seq_num,
                    send_timestamp,
                    error_estimate_wire,
                    key,
                    conf.ssid,
                    all_extra_tlvs,
                    Some(*key),
                );
                socket.send(&buf).await
            }
            SendMode::AuthBase { key } => {
                let mut packet = assemble_auth_packet(error_estimate_wire);
                packet.sequence_number = seq_num;
                packet.timestamp = send_timestamp;
                finalize_auth_packet(&mut packet, key);
                socket.send(&packet.to_bytes()).await
            }
            SendMode::OpenTlv { tlv_key } => {
                let buf = build_unauth_packet_with_tlvs(
                    seq_num,
                    send_timestamp,
                    error_estimate_wire,
                    conf.ssid,
                    all_extra_tlvs,
                    *tlv_key,
                );
                socket.send(&buf).await
            }
            SendMode::OpenBase => {
                let mut packet = assemble_unauth_packet(error_estimate_wire);
                packet.sequence_number = seq_num;
                packet.timestamp = send_timestamp;
                socket.send(&packet.to_bytes()).await
            }
        };

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

        // Event-driven receive: process responses until send_delay expires
        let send_delay = Duration::from_millis(conf.send_delay as u64);
        let deadline = tokio::time::Instant::now() + send_delay;

        loop {
            // Use unbiased select to ensure fair scheduling between receiving
            // responses and the send timer. Biased select would starve the timer
            // under heavy receive load, reducing packet send rates.
            tokio::select! {
                result = socket.recv(&mut recv_buf) => {
                    match result {
                        Ok(len) => {
                            let mut ctx = SenderRecvContext {
                                pending: &mut pending,
                                rtt_collector: &mut rtt_collector,
                                packets_received: &mut packets_received,
                                print_stats: conf.print_stats,
                                hmac_key: hmac_key.as_ref(),
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
                                &mut ctx,
                            );
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
                    let interim = rtt_collector.snapshot(packets_sent, pending.len() as u32);
                    interim.print_interim(output_format);
                }
            }
        }
    }

    // Final wait phase for remaining responses
    let wait_start = Instant::now();
    while !pending.is_empty() && wait_start.elapsed() < timeout {
        let remaining = timeout.saturating_sub(wait_start.elapsed());
        match tokio::time::timeout(remaining, socket.recv(&mut recv_buf)).await {
            Ok(Ok(len)) => {
                let mut ctx = SenderRecvContext {
                    pending: &mut pending,
                    rtt_collector: &mut rtt_collector,
                    packets_received: &mut packets_received,
                    print_stats: conf.print_stats,
                    hmac_key: hmac_key.as_ref(),
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
                    &mut ctx,
                );
            }
            Ok(Err(e)) => {
                eprintln!("Receive error during final wait: {}", e);
                break;
            }
            Err(_) => break, // Timeout expired
        }
    }

    // Mark remaining pending packets as lost
    let packets_lost = pending.len() as u32;
    #[cfg(feature = "metrics")]
    if metrics_enabled {
        for _ in 0..packets_lost {
            crate::metrics::sender_metrics::record_packet_lost();
        }
    }
    #[cfg(all(unix, feature = "snmp"))]
    if let Some(ref stats) = snmp_stats {
        for _ in 0..packets_lost {
            stats.inc_lost();
        }
    }

    let snapshot = rtt_collector.snapshot(packets_sent, packets_lost);

    // Update SNMP stats from final snapshot
    #[cfg(all(unix, feature = "snmp"))]
    if let Some(ref stats) = snmp_stats {
        let ms_to_us = |ms: f64| (ms * 1000.0) as u32;
        stats.update_from_snapshot(crate::snmp::state::SenderStatsSnapshot {
            sent: packets_sent,
            received: packets_received,
            lost: packets_lost,
            rtt_min_us: snapshot.min_rtt_ms.map(ms_to_us).unwrap_or(0),
            rtt_max_us: snapshot.max_rtt_ms.map(ms_to_us).unwrap_or(0),
            rtt_avg_us: snapshot.avg_rtt_ms.map(ms_to_us).unwrap_or(0),
            jitter_us: snapshot.jitter_ms.map(ms_to_us).unwrap_or(0),
            loss_pct_x100: if packets_sent > 0 {
                ((packets_lost as u64 * 10000) / packets_sent as u64) as u32
            } else {
                0
            },
        });
    }

    snapshot
}

fn process_response(
    data: &[u8],
    use_auth: bool,
    use_tlvs: bool,
    _clock_source: ClockFormat,
    ctx: &mut SenderRecvContext,
) {
    let recv_time = Instant::now();

    // Parse response and validate TLVs if extension mode is enabled
    // Use lenient parsing per RFC 8762 §4.6 to handle short packets
    let (seq_num, reflector_recv_ts, reflector_send_ts, sender_ttl, tlv_info) = if use_auth {
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
                validate_reflected_tlvs(
                    &ext_packet.tlvs,
                    data,
                    AUTH_BASE_SIZE,
                    ctx.hmac_key,
                    #[cfg(feature = "metrics")]
                    ctx.metrics_enabled,
                )
            } else {
                None
            };

            (seq_num, recv_ts, send_ts, ttl, tlv_info)
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
            (seq_num, recv_ts, send_ts, ttl, None)
        }
    } else if use_tlvs {
        // Parse as extended packet with TLVs (unauthenticated, lenient)
        let ext_packet = ExtendedReflectedPacketUnauthenticated::from_bytes_lenient(data);
        let base = &ext_packet.base;

        // Validate TLVs if present
        let tlv_info = if ext_packet.has_tlvs() {
            validate_reflected_tlvs(
                &ext_packet.tlvs,
                data,
                UNAUTH_BASE_SIZE,
                ctx.hmac_key,
                #[cfg(feature = "metrics")]
                ctx.metrics_enabled,
            )
        } else {
            None
        };

        (
            base.sess_sender_seq_number,
            base.receive_timestamp,
            base.timestamp,
            base.sess_sender_ttl,
            tlv_info,
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
        )
    };

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
fn validate_reflected_tlvs(
    tlvs: &TlvList,
    data: &[u8],
    base_size: usize,
    hmac_key: Option<&HmacKey>,
    #[cfg(feature = "metrics")] metrics_enabled: bool,
) -> Option<String> {
    let mut status_parts = Vec::new();
    let tlv_count = tlvs.len();

    // Check for flagged TLVs
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

    // Check HMAC TLV flags too
    if let Some(hmac_tlv) = tlvs.hmac_tlv() {
        if hmac_tlv.is_integrity_failed() {
            integrity_failed_count += 1;
        }
        if hmac_tlv.is_malformed() {
            malformed_count += 1;
        }
    }

    // Report flagged TLVs and record metrics
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

    // Verify TLV HMAC if key is available
    if let Some(key) = hmac_key {
        if let Some(hmac_tlv) = tlvs.hmac_tlv() {
            // Check if reflector set I-flag (couldn't verify HMAC)
            if hmac_tlv.is_integrity_failed() {
                // Reflector echoed our HMAC with I-flag - it couldn't verify
                status_parts.push("HMAC:unverified".to_string());
            } else {
                // Use the fixed base_size to locate TLV bytes correctly
                // (avoids fragility with trailing padding or non-TLV bytes)
                if base_size >= 4 && data.len() > base_size {
                    let seq_bytes = &data[..4];
                    let tlv_bytes = &data[base_size..];

                    if tlvs.verify_hmac(key, seq_bytes, tlv_bytes).is_ok() {
                        status_parts.push("HMAC:ok".to_string());
                    } else {
                        status_parts.push("HMAC:fail".to_string());
                    }
                }
            }
        } else {
            // No HMAC TLV in response (reflector may not support it)
            status_parts.push("no-hmac".to_string());
        }
    }

    if status_parts.is_empty() {
        Some(format!("{} TLVs", tlv_count))
    } else {
        Some(format!("{} TLVs, {}", tlv_count, status_parts.join(", ")))
    }
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
        mbz: [0u8; 30],
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
        sequence_number: 0,
        hmac: [0u8; 16],
        mbz1a: [0u8; 32],
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
        mbz: [0u8; 30],
    };
    let base_bytes = base.to_bytes();

    let mut tlvs = TlvList::new();

    // Add SSID as Extra Padding TLV if provided
    if let Some(id) = ssid {
        let ssid_tlv = SessionSenderId::new(id).to_extra_padding_tlv(0);
        tlvs.push(ssid_tlv.to_raw()).ok();
    }

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
        mbz0: [0u8; 12],
        mbz1a: [0u8; 32],
        mbz1b: [0u8; 32],
        mbz1c: [0u8; 6],
        hmac: [0u8; 16],
    };

    // Compute base packet HMAC
    finalize_auth_packet(&mut base, base_hmac_key);
    let base_bytes = base.to_bytes();

    let mut tlvs = TlvList::new();

    // Add SSID as Extra Padding TLV if provided
    if let Some(id) = ssid {
        let ssid_tlv = SessionSenderId::new(id).to_extra_padding_tlv(0);
        tlvs.push(ssid_tlv.to_raw()).ok();
    }

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
        mbz: [0u8; 30],
    };

    let mut tlvs = TlvList::new();
    if let Some(id) = ssid {
        let ssid_tlv = SessionSenderId::new(id).to_extra_padding_tlv(0);
        tlvs.push(ssid_tlv.to_raw()).ok();
    }

    ExtendedPacketUnauthenticated::with_tlvs(base, tlvs)
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
        mbz0: [0u8; 12],
        mbz1a: [0u8; 32],
        mbz1b: [0u8; 32],
        mbz1c: [0u8; 6],
        hmac: [0u8; 16],
    };

    finalize_auth_packet(&mut base, hmac_key);

    let mut tlvs = TlvList::new();
    if let Some(id) = ssid {
        let ssid_tlv = SessionSenderId::new(id).to_extra_padding_tlv(0);
        tlvs.push(ssid_tlv.to_raw()).ok();
    }

    ExtendedPacketAuthenticated::with_tlvs(base, tlvs)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_assemble_unauth_packet_defaults() {
        let packet = assemble_unauth_packet(0);
        assert_eq!(packet.sequence_number, 0);
        assert_eq!(packet.timestamp, 0);
        assert_eq!(packet.error_estimate, 0);
        assert_eq!(packet.mbz, [0u8; 30]);
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
        assert_eq!(packet.mbz0, [0u8; 12]);
        assert_eq!(packet.mbz1a, [0u8; 32]);
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
        use crate::tlv::TLV_HEADER_SIZE;

        let ssid: u16 = 12345;
        let packet = build_unauth_packet_with_tlvs(1, 1000, 100, Some(ssid), &[], None);

        // Base (44) + ExtraPadding TLV (4 header + 2 SSID value)
        assert_eq!(packet.len(), 44 + TLV_HEADER_SIZE + 2);

        // Check TLV structure at offset 44:
        // Byte 0: Flags (should be 0)
        assert_eq!(packet[44], 0x00);
        // Byte 1: Type (ExtraPadding = 1)
        assert_eq!(packet[45], 1);
        // Bytes 2-3: Length (2 bytes for SSID)
        assert_eq!(u16::from_be_bytes([packet[46], packet[47]]), 2);
        // Bytes 4-5: SSID value in big-endian
        assert_eq!(u16::from_be_bytes([packet[48], packet[49]]), ssid);
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

        // Base (44) + SSID TLV (4+2) + HMAC TLV (4+16)
        assert_eq!(
            packet.len(),
            44 + TLV_HEADER_SIZE + 2 + TLV_HEADER_SIZE + HMAC_TLV_VALUE_SIZE
        );

        // HMAC TLV should be last (type in byte 1 per RFC 8972)
        let hmac_start = 44 + TLV_HEADER_SIZE + 2;
        assert_eq!(packet[hmac_start + 1], 8); // HMAC type
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
        use crate::tlv::TLV_HEADER_SIZE;

        let key = HmacKey::new(vec![0xAB; 32]).unwrap();
        let packet = build_auth_packet_with_tlvs(1, 1000, 100, &key, Some(54321), &[], None);

        // Base (112) + ExtraPadding TLV (4 header + 2 SSID value)
        assert_eq!(packet.len(), 112 + TLV_HEADER_SIZE + 2);

        // Check TLV type (byte 1 per RFC 8972)
        assert_eq!(packet[113], 1); // ExtraPadding type
    }

    #[test]
    fn test_build_auth_packet_with_tlv_hmac() {
        use crate::tlv::{HMAC_TLV_VALUE_SIZE, TLV_HEADER_SIZE};

        let key = HmacKey::new(vec![0xAB; 32]).unwrap();
        let packet = build_auth_packet_with_tlvs(1, 1000, 100, &key, Some(100), &[], Some(&key));

        // Base (112) + SSID TLV (4+2) + HMAC TLV (4+16)
        assert_eq!(
            packet.len(),
            112 + TLV_HEADER_SIZE + 2 + TLV_HEADER_SIZE + HMAC_TLV_VALUE_SIZE
        );
    }

    #[test]
    fn test_create_extended_unauth_packet() {
        let ext = create_extended_unauth_packet(1, 1000, 100, None);

        assert_eq!(ext.base.sequence_number, 1);
        assert!(!ext.has_tlvs());
    }

    #[test]
    fn test_create_extended_unauth_packet_with_ssid() {
        let ext = create_extended_unauth_packet(1, 1000, 100, Some(9999));

        assert_eq!(ext.base.sequence_number, 1);
        assert!(ext.has_tlvs());
        assert_eq!(ext.tlvs.len(), 1);
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
        let key = HmacKey::new(vec![0xCD; 32]).unwrap();
        let ext = create_extended_auth_packet(1, 1000, 100, &key, Some(8888));

        assert!(ext.has_tlvs());
        assert_eq!(ext.tlvs.len(), 1);
    }
}
