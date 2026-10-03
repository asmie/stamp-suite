mod access_report;
mod congestion;
pub(crate) mod measurements;
mod observer;
mod packet;
mod run;
mod schedule;
pub(crate) mod session_state;
mod socket;
mod telemetry;
mod validate;

pub(crate) use access_report::*;
use congestion::*;
pub use observer::{SenderObserver, SenderObservers};
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
    packets_received: &'a mut u64,
    print_stats: bool,
    output_format: crate::stats::OutputFormat,
    hmac_key: Option<&'a HmacKey>,
    /// Sender's Micro-session ID from the outgoing MSID TLV (RFC 9534 §3.2).
    /// Used to validate that the reflector echoed the same sender ID back;
    /// `None` means the sender did not request Micro-session ID measurement.
    expected_sender_msid: Option<u16>,
    /// Pre-known reflector member-link identifier (`--reflector-member-link-id`,
    /// RFC 9534 §3.2). When set, the reflected Reflector Micro-session ID must
    /// equal it, which validates the reflector's behaviour; a mismatching reply
    /// is discarded. `None` means the reflector ID is not pre-known.
    expected_reflector_msid: Option<u16>,
    /// Reflector Micro-session ID learned from the first accepted reply when
    /// no expected ID is configured (RFC 9534 §3.2). Later mismatches are
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
    observers: &'a SenderObservers,
}

/// Runs one STAMP sender session and returns its final statistics.
///
/// Probes the first `--remote-addr` (use [`run_senders`] for several targets)
/// and waits for reflected responses. The returned snapshot covers RTT,
/// one-way delay and packet loss. For a continuous CSV stream including the
/// final snapshot, use [`run_sender_with_output`] with a shared
/// [`crate::stats::StatsOutput`].
pub async fn run_sender(conf: &Configuration) -> Result<StatsSnapshot, crate::StartupError> {
    let mut output = crate::stats::StatsOutput::new(conf.output_format);
    run_sender_with_output(
        conf,
        &mut output,
        SenderObservers::default(),
        crate::shutdown::CancellationToken::new(),
    )
    .await
}

/// Runs a sender with shared reporting state. Use the same `StatsOutput` to print
/// the returned final snapshot so periodic CSV reports do not repeat the header.
///
/// `observers` see each probe and reply as it happens. Cancelling `shutdown`
/// stops sending and returns the statistics so far; probes still awaiting a
/// reply count as lost.
pub async fn run_sender_with_output(
    conf: &Configuration,
    output: &mut crate::stats::StatsOutput,
    observers: SenderObservers,
    shutdown: crate::shutdown::CancellationToken,
) -> Result<StatsSnapshot, crate::StartupError> {
    run::SenderRun::open(std::sync::Arc::new(conf.clone()), observers, shutdown)
        .await?
        .run(output)
        .await
}

/// Runs one session per `--remote-addr` at the same time and returns their
/// final snapshots in address order. With several targets each report names
/// its target. Every session is opened before any probe is sent, so a
/// startup error in one stops them all.
pub async fn run_senders(
    conf: &Configuration,
    output: &crate::stats::StatsOutput,
    observers: SenderObservers,
    shutdown: crate::shutdown::CancellationToken,
) -> Result<Vec<StatsSnapshot>, crate::StartupError> {
    let targets = conf.per_target();
    let labelled = targets.len() > 1;
    let mut runs = Vec::with_capacity(targets.len());
    for target in targets {
        let label = target.remote_ip().to_string();
        let mut run = run::SenderRun::open(
            std::sync::Arc::new(target),
            observers.clone(),
            shutdown.clone(),
        )
        .await?;
        if labelled {
            run.set_label(label);
        }
        runs.push(run);
    }
    let mut tasks = tokio::task::JoinSet::new();
    for (index, run) in runs.into_iter().enumerate() {
        let mut output = output.clone();
        tasks.spawn(async move { (index, run.run(&mut output).await) });
    }
    let mut results: Vec<Option<StatsSnapshot>> = Vec::new();
    results.resize_with(tasks.len(), || None);
    while let Some(joined) = tasks.join_next().await {
        let (index, result) =
            joined.map_err(|e| crate::StartupError::config(format!("sender task failed: {e}")))?;
        results[index] = Some(result?);
    }
    Ok(results.into_iter().flatten().collect())
}

/// Feeds one reflected packet through reply processing, with measurements,
/// BER, an Access Report exchange and congestion response active and four
/// probes awaiting replies. `expect_msid` requires a Micro-session ID. For the
/// fuzz targets; not a stable API.
#[doc(hidden)]
pub fn fuzz_reply(
    data: &[u8],
    use_auth: bool,
    use_tlvs: bool,
    key: Option<&HmacKey>,
    expect_msid: bool,
) {
    let now = Instant::now();
    let mut pending = HashMap::new();
    let mut measurements = Measurements::new(3);
    for seq in 0..4u32 {
        let probe = PendingPacket {
            send_time: now,
            send_timestamp: generate_timestamp(ClockFormat::NTP),
        };
        pending.insert(seq, probe);
        measurements.sent(seq, probe, seq + 1);
    }
    let mut ber = BerCollector::new(
        vec![0xff, 0],
        64,
        true,
        Duration::from_secs(1),
        now,
        [Some(1.0), Some(1.0)],
    );
    let mut access_report = AccessReportRetransmitState::new(Duration::from_secs(1), 3);
    access_report.tick(now);
    let mut congestion = CongestionState::new(AimdParams {
        base_interval: Duration::from_millis(10),
        backoff_factor: 2.0,
        max_interval: Duration::from_secs(1),
        recovery_step: Duration::from_millis(1),
    });
    let mut rtt_collector = RttCollector::new();
    let mut owd_collector = OwdCollector::default();
    let mut packets_received = 0;
    let mut latched_reflector_msid = None;
    let mut zero_ssid_seen = false;
    let observers = SenderObservers::new();
    let mut ctx = SenderRecvContext {
        local_error_estimate: None,
        measurements: Some(&mut measurements),
        ber: Some(&mut ber),
        reflector_utc_offset: 0,
        pending: &mut pending,
        rtt_collector: &mut rtt_collector,
        owd_collector: &mut owd_collector,
        packets_received: &mut packets_received,
        print_stats: false,
        output_format: crate::stats::OutputFormat::Json,
        hmac_key: key,
        expected_sender_msid: expect_msid.then_some(1),
        expected_reflector_msid: None,
        latched_reflector_msid: &mut latched_reflector_msid,
        access_report_state: Some(&mut access_report),
        congestion: Some(&mut congestion),
        expected_ssid: None,
        on_zero_ssid: ZeroSsidAction::Continue,
        zero_ssid_seen: &mut zero_ssid_seen,
        observers: &observers,
    };
    process_response(
        data,
        use_auth,
        use_tlvs,
        ClockFormat::NTP,
        None,
        Some(0),
        &mut ctx,
    );
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

    // Parse the reply and, in extension mode, validate its TLVs. Lenient
    // parsing accepts short replies, such as a TWAMP Light reflector's
    // (RFC 8762 §4.6).
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

            // Verify the base packet HMAC over the canonical buffer before any
            // field is used (RFC 8762 §4.4).
            if let Some(key) = ctx.hmac_key {
                if !verify_packet_hmac(key, &canonical_buf, AUTH_HMAC_OFFSET, &hmac) {
                    crate::eprintln_throttled!(
                        "HMAC verification failed for reflected packet seq={}",
                        seq_num
                    );
                    ctx.observers.hmac_failed();
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
                ) {
                    Ok(info) => {
                        ctx.observers.tlv_flags(&info.flags);
                        Some(info)
                    }
                    Err(reason) => {
                        crate::eprintln_throttled!(
                            "Discarding reflected packet seq={}: {}",
                            seq_num,
                            reason
                        );
                        ctx.observers.reply_rejected();
                        return;
                    }
                }
            } else {
                None
            };

            if let Some(ber) = ctx.ber.as_ref() {
                ber_observation = observation(
                    &ext_packet.tlvs,
                    telemetry
                        .as_ref()
                        .is_some_and(|t| t.hmac.permits_measurements()),
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
            let (packet, canonical_buf) =
                ReflectedPacketAuthenticated::from_bytes_lenient_with_canonical(data);
            let seq_num = packet.sess_sender_seq_number;
            let recv_ts = packet.receive_timestamp;
            let send_ts = packet.timestamp;
            let ttl = packet.sess_sender_ttl;
            let hmac = packet.hmac;

            // Verify the base packet HMAC over the canonical buffer when a key
            // is present (RFC 8762 §4.4).
            if let Some(key) = ctx.hmac_key {
                if !verify_packet_hmac(key, &canonical_buf, AUTH_HMAC_OFFSET, &hmac) {
                    crate::eprintln_throttled!(
                        "HMAC verification failed for reflected packet seq={}",
                        seq_num
                    );
                    ctx.observers.hmac_failed();
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
        let (ext_packet, _) = ExtendedReflectedPacketUnauthenticated::from_bytes_lenient(data);
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
            ) {
                Ok(info) => {
                    ctx.observers.tlv_flags(&info.flags);
                    Some(info)
                }
                Err(reason) => {
                    crate::eprintln_throttled!(
                        "Discarding reflected packet seq={}: {}",
                        base.sess_sender_seq_number,
                        reason
                    );
                    ctx.observers.reply_rejected();
                    return;
                }
            }
        } else {
            None
        };

        if let Some(ber) = ctx.ber.as_ref() {
            ber_observation = observation(
                &ext_packet.tlvs,
                telemetry
                    .as_ref()
                    .is_some_and(|t| t.hmac.permits_measurements()),
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

    // Unix seconds used to resolve the NTP era of every timestamp in this reply.
    let reference = crate::time::unix_now().0;
    let remote_error = ErrorEstimate::from_wire(reflector_error);

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
        let t4_ns = timestamp_to_unix_nanos(sender_recv_ts, clock_source, reference);
        measurements.observe(ReplyObservation {
            key,
            rtt_ns: recv_time.duration_since(probe.send_time).as_nanos() as u64,
            t4_ns,
            format: remote_error.clock_format(),
            reference,
            offset: ctx.reflector_utc_offset,
            ordinal,
            dm: telemetry.as_ref().and_then(|t| t.direct_measurement),
            follow: telemetry.as_ref().and_then(|t| t.follow_up),
            quality: ctx.local_error_estimate.map(|e| (e, remote_error)),
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
        let remote_format = remote_error.clock_format();
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
                ctx.local_error_estimate.map(|e| (e, remote_error)),
            );
        } else {
            log::debug!("Invalid PTP nanoseconds on seq={seq_num}; omitting one-way delay");
        }

        ctx.observers.reply_received(rtt_ns);

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
