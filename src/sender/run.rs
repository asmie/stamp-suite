//! One sender run: setup, the probe schedule, the final reply drain, and
//! Access Report retransmissions (RFC 8972 §4.6).

use std::sync::Arc;

#[path = "run/setup.rs"]
mod setup;

use super::schedule::{Schedule, SendTimeline};
use super::*;
use crate::shutdown::CancellationToken;

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
enum Wait<'a> {
    /// Backoff can extend this already drawn gap while receiving replies.
    NextSend {
        timeline: &'a mut SendTimeline,
        gap: Duration,
        interval: Duration,
    },
    /// Every probe has a reply (or its burst copies are in), or time is up.
    Drain,
    /// The Access Report timer expires or the report is acknowledged.
    AccessReport,
}

/// State of one sender run.
pub(super) struct SenderRun {
    conf: Arc<Configuration>,
    /// Labels reports when several targets run at once.
    label: Option<String>,
    socket: UdpSocket,
    /// The connected peer, kept to refresh the route (see `refresh_route`).
    #[cfg(target_os = "linux")]
    remote_addr: SocketAddr,
    consecutive_send_errors: u8,
    use_auth: bool,
    use_tlvs: bool,
    send_mode: SendMode,
    kernel_rx_enabled: bool,
    #[cfg(all(feature = "hwtstamp", any(target_os = "linux", target_os = "macos")))]
    // Read only by the Linux TX-timestamp path.
    #[cfg_attr(not(all(feature = "hwtstamp", target_os = "linux")), allow(dead_code))]
    kernel_ts: crate::hwtstamp::EnabledTimestamping,
    /// Mirrors the kernel's per-send OPT_ID counter; `send_probe` is the
    /// only send site.
    #[cfg(all(feature = "hwtstamp", target_os = "linux"))]
    tx_counter: u32,
    /// OPT_ID to (sequence, monotonic send time, wire T1) for TX reports still
    /// to arrive. Reused sequences must not inherit an older send's correction.
    #[cfg(all(feature = "hwtstamp", target_os = "linux"))]
    tx_id_to_seq: HashMap<u32, (u32, Instant, u64)>,
    error_estimate: ErrorEstimate,
    error_estimate_wire: u16,
    hmac_key: Option<HmacKey>,
    sess: Session,
    pending: super::pending::PendingTable,
    pending_evictions: u64,
    measurements: Measurements,
    rtt_collector: RttCollector,
    owd_collector: OwdCollector,
    packets_sent: u64,
    packets_received: u64,
    packets_lost: u64,
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
    /// Reply window of the last successfully sent report retry. A delivery
    /// acknowledgement must not discard that probe's later burst copies.
    access_report_reply_deadline: Option<Instant>,
    /// TLVs sent with every probe; per-probe TLVs are added at build time.
    extra_tlvs: Vec<RawTlv>,
    /// Original TLVs for header reflection or BER on a known route; each
    /// probe fits this template to the current MTU, including after growth.
    probe_template: Option<Vec<RawTlv>>,
    probe_fixed_overhead: usize,
    header_trimmed: usize,
    ber: Option<BerCollector>,
    report_timer: Option<tokio::time::Interval>,
    observers: SenderObservers,
    shutdown: CancellationToken,
    schedule: Schedule,
}

impl SenderRun {
    /// Opens and configures the socket and builds the static probe TLVs.
    pub(super) async fn open(
        shared_conf: Arc<Configuration>,
        observers: SenderObservers,
        shutdown: CancellationToken,
    ) -> Result<Self, crate::StartupError> {
        let conf = &*shared_conf;
        if conf.zero_udp_checksum {
            // Direct library callers must get the same restrictions as CLI
            // and TOML users, before key loading or network side effects.
            conf.validate().map_err(crate::StartupError::config)?;
        }
        let (use_auth, hmac_key) = setup::load_key(conf)?;

        let local_addr: SocketAddr = conf.local_socket_addr();
        let remote_addr: SocketAddr = conf.remote_socket_addr();

        // Enable AIMD for `--cos` with ECT0/ECT1 (draft-ietf-bpm-stamp-cos-ecn-00 §3.4).
        // `conf.ecn` sets both the egress ECN and the requested reply EC1.
        let ecn_response_active = conf.cos && matches!(conf.ecn, 1 | 2);

        let (socket, configured_egress_ecn) =
            setup::open_socket(conf, local_addr, remote_addr).await?;

        #[cfg(all(feature = "hwtstamp", any(target_os = "linux", target_os = "macos")))]
        let sender_kernel_ts = setup::kernel_timestamping(conf, &socket);
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
        let tx_id_to_seq = HashMap::new();

        // Build error estimate from configuration with Z flag set based on clock source
        let error_estimate = ErrorEstimate::with_clock_format(
            conf.clock_synchronized,
            conf.clock_source,
            conf.error_scale,
            conf.error_multiplier,
        )
        .map_err(crate::StartupError::config)?;
        let error_estimate_wire = error_estimate.to_wire();

        if let Some(mode) = conf.malformed {
            log::warn!(
                "Diagnostic mode: appending a deliberately malformed TLV ({mode:?}) \
                 to every packet — for reflector conformance testing only"
            );
        }

        let sess = Session::new(0);
        let mut measurements = Measurements::new(conf.reflected_control_count);
        if conf.cos {
            measurements.enable_ecn(conf.ecn, configured_egress_ecn);
        }
        measurements.monitor = Some(session_state::Monitor::new(
            conf.session_loss_threshold,
            Duration::from_secs(u64::from(conf.timeout)),
        ));
        let rtt_collector = RttCollector::new();
        let owd_collector = OwdCollector::new();
        let packets_sent: u64 = 0;
        let packets_received: u64 = 0;
        let packets_lost: u64 = 0;
        // Zero-config latch for the Reflector Micro-session ID (RFC 9534
        // §3.2): populated from the first validly-received reply when
        // `--reflector-member-link-id` was not given; persists for the whole
        // session so later replies are checked for self-consistency.
        let latched_reflector_msid: Option<u16> = None;
        // Allow the maximum UDP payload so padded replies are not truncated.
        // Allocate once per run.
        let recv_buf = vec![0u8; MAX_UDP_PAYLOAD];
        let timeout = Duration::from_secs(conf.timeout as u64);

        // Scale the Type-12 burst interval with AIMD (draft-ietf-bpm-stamp-cos-ecn-00 §3.4).
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

        let congestion =
            setup::congestion_controller(conf, ecn_response_active, scale_reflected_control);

        let access_report_state = setup::access_report_state(conf);
        let (mut extra_tlvs, ber_pattern) = setup::static_tlvs(conf, scale_reflected_control)?;

        // RFC 8972 §4.8 origination is separate from holding a key: --tlv-hmac
        // off keeps the key for verifying replies without putting an HMAC TLV on
        // the wire. Decided here, before the MTU budget below, so the 20-byte
        // reserve matches what will actually be sent. `validate()` has already
        // ensured `on` has a key and rejected `off` in authenticated mode.
        let originate_tlv_hmac = match conf.tlv_hmac {
            TlvHmacMode::Auto | TlvHmacMode::On => true,
            TlvHmacMode::Off => false,
        };

        // Fit BER padding and Types 246/247 to the egress MTU using the
        // worst-case packet size (ext-hdr-26 §§4.2, 6.2).
        let header_requests = !conf.attach_ext_hdr.is_empty()
            || !conf.reflected_fixed_hdr.is_empty()
            || !conf.reflected_ipv6_ext_hdr.is_empty();
        let probe_fixed_overhead = setup::probe_fixed_overhead(
            conf,
            use_auth,
            hmac_key.is_some() && (use_auth || originate_tlv_hmac),
            access_report_state.is_some(),
            scale_reflected_control,
        );
        let (probe_template, header_trimmed) = setup::fit_to_route(
            conf,
            &socket,
            &mut extra_tlvs,
            probe_fixed_overhead,
            header_requests,
        )?;

        let ber = ber_pattern.map(|pattern| {
            BerCollector::new(
                pattern,
                extra_tlvs
                    .iter()
                    .find(|t| t.tlv_type == TlvType::ExtraPadding)
                    .map_or(0, |t| t.value.len()),
                conf.send_delay.duration() * conf.ber_interval,
                Instant::now(),
                [conf.ber_bit_threshold, conf.ber_packet_threshold],
            )
        });

        // Check if we need to include TLV extensions.
        // SSID lives in the base header per RFC 8972 §3, so it alone does not force TLV mode.
        // Header requests can return after a route increase even when the
        // initial budget removed every static TLV.
        let use_tlvs = !extra_tlvs.is_empty()
            || header_requests
            || conf.direct_measurement
            || access_report_state.is_some()
            || scale_reflected_control;
        if let Some(ssid) = conf.ssid {
            log::info!("SSID enabled: {}", ssid);
        }

        let send_mode = setup::send_mode(hmac_key.as_ref(), use_auth, use_tlvs, originate_tlv_hmac);

        let report_timer = (conf.report_interval > 0).then(|| {
            let period = Duration::from_secs(conf.report_interval as u64);
            // The first tick would fire immediately.
            tokio::time::interval_at(tokio::time::Instant::now() + period, period)
        });

        let mut run = Self {
            conf: Arc::clone(&shared_conf),
            label: None,
            socket,
            #[cfg(target_os = "linux")]
            remote_addr,
            consecutive_send_errors: 0,
            use_auth,
            use_tlvs,
            send_mode,
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
            pending: super::pending::PendingTable::new(conf.max_pending_probes),
            pending_evictions: 0,
            measurements,
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
            access_report_reply_deadline: None,
            extra_tlvs,
            probe_template,
            probe_fixed_overhead,
            header_trimmed,
            ber,
            report_timer,
            observers,
            shutdown,
            schedule: Schedule::new(conf.send_schedule),
        };
        // At startup a probe that cannot fit the route is a configuration
        // error; during the run the same checks only skip probes.
        let route_mtu = run.prepare_probe_tlvs().await?;
        run.validate_probe_size(run.build_probe(0, true).len(), route_mtu)??;
        Ok(run)
    }

    /// Sends probes on schedule until `--count` is reached (`0` means no
    /// limit), `--duration` elapses or shutdown is requested. Then waits for
    /// outstanding replies and finishes any Access Report exchange.
    pub(super) async fn run(
        mut self,
        output: &crate::stats::StatsOutput,
    ) -> Result<StatsSnapshot, crate::StartupError> {
        #[cfg(target_os = "windows")]
        let _timer_resolution = super::timer::TimerResolution::request();
        // Each probe is due one gap after the previous due time, so the time
        // spent building and sending does not stretch the gap. Timer wakeups
        // can land a tick late; up to 2 ms behind, the next probe follows
        // at once so the rate holds. Further behind, the schedule restarts
        // from now instead of sending a burst.
        let start = tokio::time::Instant::now();
        let mut timeline = SendTimeline::new(start, self.conf.count, self.conf.duration);
        // Timer-driven report retries are additional traffic. They must not
        // consume the quota of successfully sent scheduled measurement probes.
        let mut scheduled_sent = self.packets_sent;
        while timeline.can_send(scheduled_sent, tokio::time::Instant::now) {
            let attach_access_report = self
                .access_report_state
                .as_mut()
                .is_some_and(|state| state.due(Instant::now()));
            let sent_before = self.packets_sent;
            self.send_probe(attach_access_report).await?;
            scheduled_sent += self.packets_sent - sent_before;
            let interval = self.send_interval();
            let gap = self.schedule.next_gap(interval);
            let wait = timeline.after_probe(gap, tokio::time::Instant::now);
            self.receive_until(
                wait.deadline,
                Wait::NextSend {
                    timeline: &mut timeline,
                    gap,
                    interval,
                },
                output,
            )
            .await?;
            self.expire();
            if self.stopping() {
                break;
            }
        }
        if self.shutdown.is_cancelled() {
            log::info!("Interrupted; stopping after {} probes", self.packets_sent);
        }
        if let Some(m) = self.measurements.monitor.as_mut() {
            m.idle();
        }

        let drain_until = tokio::time::Instant::now() + self.timeout;
        self.receive_until(drain_until, Wait::Drain, output).await?;

        // Finish an Access Report exchange still pending after the reply drain
        // (RFC 8972 §4.6), including `--count 1` runs. The drain also drives
        // report deadlines; each retry carries identical report bytes.
        while !self.stopping()
            && self
                .access_report_state
                .as_ref()
                .is_some_and(|state| state.has_started() && !state.is_terminal())
        {
            if self
                .access_report_state
                .as_mut()
                .is_some_and(|state| state.due(Instant::now()))
            {
                self.send_probe(true).await?;
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
                .await?
            {
                break;
            }
        }

        // Delivery completion and measurement completion are separate: the
        // first reflected copy can acknowledge the report before its remaining
        // burst arrives. Keep only the remainder of the last successful retry's
        // reply window, including retries sent near the initial drain deadline.
        // Never restart an exchange after a receive error or reset this window
        // from an acknowledgement or from budget exhaustion.
        if self
            .access_report_state
            .as_ref()
            .is_some_and(|state| state.is_terminal())
        {
            if let Some(deadline) = self
                .access_report_reply_deadline
                .filter(|deadline| *deadline > Instant::now())
            {
                self.receive_until(deadline.into(), Wait::Drain, output)
                    .await?;
            }
        }

        // Probes still unanswered are lost.
        let remaining_lost = self.pending.len() as u32;
        self.packets_lost += u64::from(remaining_lost);
        self.observers.probes_lost(remaining_lost);
        if let Some(m) = self.measurements.monitor.as_mut() {
            m.idle();
        }
        // Interim reports are written before the caller prints the final one.
        output.flush().await.map_err(output_error)?;
        Ok(self.snapshot())
    }

    /// Current probe interval: the AIMD interval when congestion response is
    /// active (draft-ietf-bpm-stamp-cos-ecn-00 §3.4), otherwise `--send-delay`.
    fn send_interval(&self) -> Duration {
        self.congestion
            .as_ref()
            .map(|c| c.controller.current_interval())
            .unwrap_or_else(|| self.conf.send_delay.duration())
    }

    /// RFC 8972 §3: `--on-zero-ssid=stop` ends the run at the first reply
    /// with a zeroed SSID.
    fn stopped_on_zero_ssid(&self) -> bool {
        self.zero_ssid_seen && self.conf.on_zero_ssid == ZeroSsidAction::Stop
    }

    /// A zero-SSID stop or a shutdown request ends the run early.
    fn stopping(&self) -> bool {
        self.stopped_on_zero_ssid() || self.shutdown.is_cancelled()
    }

    fn wait_over(&self, wait: &Wait<'_>) -> bool {
        if self.stopping() {
            return true;
        }
        match wait {
            Wait::NextSend { .. } => false,
            Wait::Drain => self.pending.is_empty() && !self.measurements.needs_burst_wait(),
            Wait::AccessReport => self
                .access_report_state
                .as_ref()
                .is_none_or(|state| state.armed_deadline().is_none()),
        }
    }

    /// Receives and processes replies until `deadline` or until `wait` is
    /// satisfied. Returns false when a receive error ended the wait early.
    async fn receive_until(
        &mut self,
        mut deadline: tokio::time::Instant,
        mut wait: Wait<'_>,
        output: &crate::stats::StatsOutput,
    ) -> Result<bool, crate::StartupError> {
        enum Event {
            Datagram(std::io::Result<(usize, Option<u64>, Option<u8>)>),
            MonitorDue,
            AccessReportDue,
            Deadline,
            Report,
            Shutdown,
        }
        // A persistent receive failure must not spin, but it must not turn
        // pacing into an uninterruptible sleep either. Resume socket reads
        // on the next wait; keep all other events active in this one.
        let mut receive_enabled = true;
        // A gap shorter than the timer resolution is spun through, yielding
        // between receive polls, so sub-millisecond spacing stays exact.
        loop {
            let spin = if let Wait::NextSend {
                timeline,
                gap,
                interval,
            } = &mut wait
            {
                let updated = timeline.back_off(gap, interval, self.send_interval());
                deadline = updated.deadline;
                updated.spin
            } else {
                false
            };
            output.check().map_err(output_error)?;
            if self.wait_over(&wait) {
                return Ok(true);
            }
            if spin && tokio::time::Instant::now() >= deadline {
                return Ok(true);
            }
            let monitor_due = self
                .measurements
                .monitor
                .as_ref()
                .and_then(|m| m.deadline());
            // Neither a drawn probe gap nor the final reply timeout may
            // postpone report delivery. Retries leave the measurement timeline
            // (including its Poisson draw and CE backoff) and drain deadline alone.
            let access_report_due = if matches!(wait, Wait::NextSend { .. } | Wait::Drain) {
                self.access_report_state
                    .as_ref()
                    .and_then(|state| state.armed_deadline())
            } else {
                None
            };
            let report_timer = &mut self.report_timer;
            // Unbiased: under a steady stream of replies a biased select
            // would starve the send deadline.
            let event = tokio::select! {
                result = recv_packet(
                    &self.socket,
                    &mut self.recv_buf,
                    &mut self.cmsg_buf,
                    self.kernel_rx_enabled,
                    self.conf.cos,
                    self.conf.clock_source,
                ), if receive_enabled => Event::Datagram(result),
                _ = async {
                    match monitor_due {
                        Some(at) => tokio::time::sleep_until(at.into()).await,
                        None => std::future::pending().await,
                    }
                } => Event::MonitorDue,
                _ = async {
                    match access_report_due {
                        Some(at) => tokio::time::sleep_until(at.into()).await,
                        None => std::future::pending().await,
                    }
                } => Event::AccessReportDue,
                _ = async {
                    if spin {
                        tokio::task::yield_now().await;
                    } else {
                        tokio::time::sleep_until(deadline).await;
                    }
                } => Event::Deadline,
                _ = async {
                    match report_timer {
                        Some(timer) => {
                            timer.tick().await;
                        }
                        None => std::future::pending().await,
                    }
                } => Event::Report,
                _ = self.shutdown.cancelled() => Event::Shutdown,
            };
            match event {
                Event::Datagram(Ok((len, kernel_t4, reply_ecn))) => {
                    // Apply kernel TX timestamps first so a corrected T1 is
                    // in place before one-way delay is computed.
                    self.apply_tx_timestamps();
                    self.on_reply(output, len, kernel_t4, reply_ecn);
                }
                Event::Datagram(Err(e)) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    // A spurious wake, typically an error-queue event; drain
                    // it so readiness clears.
                    self.apply_tx_timestamps();
                }
                Event::Datagram(Err(e)) => {
                    let during = match wait {
                        Wait::NextSend { .. } => "",
                        Wait::Drain => " during final wait",
                        Wait::AccessReport => " while awaiting Access Report ack",
                    };
                    crate::eprintln_throttled!("Receive error{during}: {e}");
                    if !is_icmp_feedback(&e) {
                        if matches!(wait, Wait::NextSend { .. }) {
                            receive_enabled = false;
                        } else {
                            return Ok(false);
                        }
                    }
                }
                Event::MonitorDue => {
                    if let Some(m) = self.measurements.monitor.as_mut() {
                        m.advance(Instant::now());
                    }
                }
                Event::AccessReportDue => {
                    // If the wait also expired, let its caller advance first.
                    // A due scheduled probe can carry this report without an
                    // extra send; duration and final-drain limits still win.
                    if tokio::time::Instant::now() >= deadline {
                        return Ok(true);
                    }
                    if self
                        .access_report_state
                        .as_mut()
                        .is_some_and(|state| state.due(Instant::now()))
                    {
                        self.send_probe(true).await?;
                    }
                }
                Event::Deadline if !spin => return Ok(true),
                Event::Deadline => {}
                Event::Report => {
                    output
                        .print_interim_with(|| self.snapshot())
                        .map_err(output_error)?;
                }
                Event::Shutdown => return Ok(false),
            }
        }
    }

    /// Checks the probe against the UDP payload limit (fatal: the
    /// configuration can never fit) and against the current route MTU
    /// (returned as `Ok(Err(..))`: the route can change during a run).
    fn validate_probe_size(
        &self,
        size: usize,
        route_mtu: Option<usize>,
    ) -> Result<Result<(), crate::StartupError>, crate::StartupError> {
        let ipv6 = self.conf.remote_ip().is_ipv6();
        let headers = if ipv6 {
            self.conf
                .attach_ext_hdrs()
                .iter()
                .map(|h| h.bytes.len())
                .sum()
        } else {
            0
        };
        let (ip_header, max_payload) = if ipv6 {
            (IPV6_FIXED_HEADER_SIZE, MAX_UDP_PAYLOAD_IPV6)
        } else {
            (IPV4_FIXED_HEADER_SIZE, MAX_UDP_PAYLOAD_IPV4)
        };
        let limit = max_payload.saturating_sub(headers);
        validate_datagram_size(size, limit)?;
        if let Some(mtu) = route_mtu {
            let full_size = size + headers + ip_header + UDP_HEADER_SIZE;
            if full_size > mtu {
                return Ok(Err(crate::StartupError::config(format!(
                    "Probe is {full_size} bytes including IP/UDP headers; route MTU is {mtu} bytes after removing optional header TLVs"
                ))));
            }
        }
        Ok(Ok(()))
    }

    /// Builds and sends one probe. Transient errors, including a route MTU
    /// that is unreadable or too small, share a bounded retry budget.
    async fn send_probe(&mut self, attach_access_report: bool) -> Result<(), crate::StartupError> {
        let route_mtu = match self.prepare_probe_tlvs().await {
            Ok(mtu) => mtu,
            Err(refusal) => return self.refuse_probe(refusal, attach_access_report),
        };
        if let Some(ber) = self.ber.as_mut() {
            ber.advance(Instant::now());
            ber.filter_requests(&mut self.extra_tlvs);
        }
        let seq = self.sess.generate_sequence_number();
        let mut packet = self.build_probe(seq, attach_access_report);
        if let Err(refusal) = self.validate_probe_size(packet.len(), route_mtu)? {
            return self.refuse_probe(refusal, attach_access_report);
        }
        // T1 and the RTT start are read after the TLVs are built, so build
        // time is not measured as network delay. Only the base packet (and
        // its HMAC, which covers the timestamp) is written after this point.
        let send_time = Instant::now();
        let send_timestamp = generate_timestamp(self.conf.clock_source);
        self.stamp_probe(&mut packet, seq, send_timestamp);
        let result = self.socket.send(&packet).await;
        self.finish_probe_send(
            seq,
            packet.len(),
            send_time,
            send_timestamp,
            attach_access_report,
            result,
        )
    }

    /// Commit probe accounting and report delivery state only for complete sends.
    fn finish_probe_send(
        &mut self,
        seq: u32,
        packet_len: usize,
        send_time: Instant,
        send_timestamp: u64,
        attach_access_report: bool,
        result: std::io::Result<usize>,
    ) -> Result<(), crate::StartupError> {
        match result {
            Err(e) => {
                self.note_send_failure(attach_access_report);
                if !retry_send_error(&e, self.consecutive_send_errors) {
                    return Err(crate::StartupError::io(
                        format!("Cannot send probe {seq}"),
                        e,
                    ));
                }
                crate::eprintln_throttled!("Failed to send packet {seq}: {e}");
            }
            Ok(n) if n == packet_len => {
                self.consecutive_send_errors = 0;
                if attach_access_report {
                    if let Some(state) = self.access_report_state.as_mut() {
                        state.record_sent(Instant::now());
                    }
                }
                self.record_sent(seq, send_time, send_timestamp);
                if attach_access_report
                    && self
                        .access_report_state
                        .as_ref()
                        .is_some_and(|state| state.retransmissions() > 0)
                {
                    self.access_report_reply_deadline = Some(send_time + self.timeout);
                }
            }
            Ok(_) => {
                return Err(crate::StartupError::io(
                    "Cannot send probe",
                    std::io::Error::from(std::io::ErrorKind::WriteZero),
                ))
            }
        }
        Ok(())
    }

    /// Counts a probe that was not sent as a failure: the shared budget,
    /// and a later Access Report retry when this probe carried one.
    fn note_send_failure(&mut self, attach_access_report: bool) {
        self.consecutive_send_errors = self.consecutive_send_errors.saturating_add(1);
        if attach_access_report {
            if let Some(state) = self.access_report_state.as_mut() {
                state.defer(Instant::now());
            }
        }
    }

    /// Skips a probe refused before sending because the route MTU is
    /// unreadable or too small. A route change can cause either, so the run
    /// continues until the send-failure budget is spent, then returns `error`.
    fn refuse_probe(
        &mut self,
        error: crate::StartupError,
        attach_access_report: bool,
    ) -> Result<(), crate::StartupError> {
        self.note_send_failure(attach_access_report);
        if self.consecutive_send_errors >= MAX_CONSECUTIVE_SEND_FAILURES {
            return Err(error);
        }
        crate::eprintln_throttled!("Probe not sent: {error}");
        Ok(())
    }

    /// Reconnects the socket to the same peer so Linux looks up and caches
    /// the route again. After a failed route lookup during a send, Linux
    /// keeps no cached route, and `IP_MTU`/`IPV6_MTU` fail with `ENOTCONN`
    /// until the next send or connect. Refused probes never send, so without
    /// this the MTU would stay unreadable after the route returns.
    #[cfg(target_os = "linux")]
    async fn refresh_route(&self) {
        if let Err(e) = self.socket.connect(self.remote_addr).await {
            log::debug!("Cannot refresh the route to {}: {e}", self.remote_addr);
        }
    }

    #[cfg(not(target_os = "linux"))]
    async fn refresh_route(&self) {}

    /// Serializes one probe with a zeroed base packet for `stamp_probe` to
    /// fill. Direct Measurement, an Access Report and an AIMD-scaled
    /// Reflected Test Packet Control TLV (draft-ietf-bpm-stamp-cos-ecn-00 §3.4) change per probe;
    /// everything else comes from `extra_tlvs` and is written without a copy.
    fn build_probe(&self, seq: u32, attach_access_report: bool) -> Vec<u8> {
        let conf = &*self.conf;
        let mut per_probe: Vec<RawTlv> = Vec::new();
        if conf.direct_measurement {
            // The wire counter is 32 bits and wraps (RFC 8972 §4.5).
            per_probe.push(DirectMeasurementTlv::new((self.packets_sent + 1) as u32).to_raw());
        }
        if let Some(access_id) = conf.access_report.filter(|_| attach_access_report) {
            per_probe.push(AccessReportTlv::new(access_id, conf.access_return_code).to_raw());
        }
        if self.scale_reflected_control {
            let (scale, backed_off) = self.congestion.as_ref().map_or((1.0, false), |c| {
                (c.controller.scale_factor(), c.controller.is_backed_off())
            });
            if let Some(control) = scaled_reflected_control_tlv(
                conf.reflected_control_length,
                conf.reflected_control_count,
                conf.reflected_control_interval_ns,
                conf.reflected_control_no_ext_hdr,
                scale,
                backed_off,
            ) {
                per_probe.push(control);
            }
        }
        let (base_size, tlv_key) = match &self.send_mode {
            SendMode::AuthTlv { key } => (AUTH_BASE_SIZE, Some(Some(key))),
            SendMode::AuthBase { .. } => (AUTH_BASE_SIZE, None),
            SendMode::OpenTlv { tlv_key } => (UNAUTH_BASE_SIZE, Some(tlv_key.as_ref())),
            SendMode::OpenBase => (UNAUTH_BASE_SIZE, None),
        };
        let tlv_bytes: usize = self
            .extra_tlvs
            .iter()
            .chain(&per_probe)
            .map(RawTlv::wire_size)
            .sum();
        // Room for the TLV HMAC and a `--malformed` TLV as well.
        let mut packet = Vec::with_capacity(base_size + tlv_bytes + 64);
        packet.resize(base_size, 0);
        if let Some(key) = tlv_key {
            write_probe_tlvs(&mut packet, seq, &[&self.extra_tlvs, &per_probe], key);
        }
        // `--malformed` appends one deliberately malformed TLV after
        // everything else, including the HMAC TLV, to exercise a reflector.
        if let Some(mode) = conf.malformed {
            packet.extend_from_slice(&malformed_tlv_bytes(mode));
        }
        packet
    }

    /// Writes the base packet with its final timestamp (and, in authenticated
    /// mode, its HMAC) into the prefix reserved by `build_probe`.
    fn stamp_probe(&self, packet: &mut [u8], seq: u32, timestamp: u64) {
        let ssid = self.conf.ssid.unwrap_or(0);
        match &self.send_mode {
            SendMode::AuthTlv { key } | SendMode::AuthBase { key } => {
                let mut base = assemble_auth_packet(self.error_estimate_wire);
                base.sequence_number = seq;
                base.timestamp = timestamp;
                base.ssid = ssid;
                let bytes = &mut packet[..AUTH_BASE_SIZE];
                bytes.copy_from_slice(&base.to_bytes());
                let hmac = compute_packet_hmac(key, bytes, AUTH_HMAC_OFFSET);
                bytes[AUTH_HMAC_OFFSET..].copy_from_slice(&hmac);
            }
            SendMode::OpenTlv { .. } | SendMode::OpenBase => {
                let mut base = assemble_unauth_packet(self.error_estimate_wire);
                base.sequence_number = seq;
                base.timestamp = timestamp;
                base.ssid = ssid;
                packet[..UNAUTH_BASE_SIZE].copy_from_slice(&base.to_bytes());
            }
        }
    }

    fn record_sent(&mut self, seq: u32, send_time: Instant, send_timestamp: u64) {
        self.packets_sent += 1;
        self.observers.probe_sent();
        let ber_padding = self.ber.as_mut().and_then(|ber| {
            if self
                .extra_tlvs
                .iter()
                .any(|tlv| crate::ber::is_ber(tlv.tlv_type))
            {
                let size = self
                    .extra_tlvs
                    .iter()
                    .find(|tlv| tlv.tlv_type == TlvType::ExtraPadding)?
                    .value
                    .len();
                ber.summary.padding_bytes = size;
                Some(size)
            } else {
                None
            }
        });
        let probe = PendingPacket {
            ber_padding,
            send_time,
            send_timestamp,
            wire_timestamp: send_timestamp,
        };
        // Displaced probes are reported as lost even with an unlimited cap,
        // never silently dropped from final loss accounting.
        let displaced = self
            .pending
            .insert(seq, probe, self.packets_sent, self.timeout);
        if displaced.sequence_reused {
            self.retire_pending("sequence reused");
        }
        if displaced.limit_reached {
            self.retire_pending("limit reached");
        }
        // The ordinal follows the 32-bit Direct Measurement counter.
        self.measurements.sent(seq, probe, self.packets_sent as u32);
        // Pair this send's kernel OPT_ID with the sequence number so a later
        // TX timestamp can correct the stored T1.
        #[cfg(all(feature = "hwtstamp", target_os = "linux"))]
        if self.kernel_ts.tx_kernel {
            self.tx_id_to_seq
                .insert(self.tx_counter, (seq, send_time, send_timestamp));
            self.tx_counter = self.tx_counter.wrapping_add(1);
            if self.tx_id_to_seq.len() > 4096 {
                // TX timestamps stopped arriving; do not grow without bound.
                self.tx_id_to_seq.clear();
            }
        }
    }

    fn retire_pending(&mut self, reason: &str) {
        self.pending_evictions += 1;
        self.packets_lost += 1;
        self.observers.probes_lost(1);
        if self.pending_evictions == 1 {
            log::warn!(
                "Pending probe retired as lost for {} ({reason}; limit {}, 0 means unlimited). \
                 See measurements.pending_evictions; send timing is unchanged.",
                self.conf.remote_socket_addr(),
                self.conf.max_pending_probes
            );
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

    fn on_reply(
        &mut self,
        output: &crate::stats::StatsOutput,
        len: usize,
        kernel_t4: Option<u64>,
        reply_ecn: Option<u8>,
    ) {
        let conf = Arc::clone(&self.conf);
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
            output: Some(output),
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
            observers: &self.observers,
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
        self.expire_at(Instant::now());
    }

    fn expire_at(&mut self, now: Instant) {
        let lost = self.pending.expire(now, self.timeout);
        if lost > 0 {
            self.packets_lost += u64::from(lost);
            self.observers.probes_lost(lost);
        }
    }

    /// Fits BER padding and Type 246/247 requests to the current route MTU.
    /// Each probe starts from the original TLVs, allowing padding and header
    /// requests to return after a temporary decrease in the route budget.
    /// A failed lookup refuses the probe; a stale budget cannot authorize it.
    async fn prepare_probe_tlvs(&mut self) -> Result<Option<usize>, crate::StartupError> {
        if self.probe_template.is_none() {
            return Ok(None);
        }
        let mtu = match egress_mtu(&self.socket) {
            Some(mtu) => Some(mtu),
            None => {
                self.refresh_route().await;
                egress_mtu(&self.socket)
            }
        };
        let Some(template) = &self.probe_template else {
            return Ok(None);
        };
        match mtu {
            Some(mtu) => {
                self.extra_tlvs.clone_from(template);
                if self.conf.ber {
                    crate::ber::fit_padding(
                        &mut self.extra_tlvs,
                        mtu as usize,
                        self.probe_fixed_overhead,
                    )
                    .map_err(|e| crate::StartupError::io("Cannot fit the BER padding", e))?;
                }
                let removed = enforce_egress_mtu(
                    &mut self.extra_tlvs,
                    mtu as usize,
                    self.probe_fixed_overhead,
                );
                if removed != self.header_trimmed {
                    log_header_trim(removed, mtu as usize);
                    self.header_trimmed = removed;
                }
                Ok(Some(mtu as usize))
            }
            None => Err(crate::StartupError::config(
                "Cannot read the route MTU for probe TLVs",
            )),
        }
    }

    fn snapshot(&mut self) -> StatsSnapshot {
        let mut measurements = self.measurements.snapshot();
        measurements.pending_limit = self.conf.max_pending_probes;
        measurements.pending_probes = self.pending.len();
        measurements.pending_high_watermark = self.pending.high_watermark();
        measurements.pending_evictions = self.pending_evictions;
        self.rtt_collector
            .snapshot(self.packets_sent, self.packets_lost)
            .with_measurements(measurements)
            .with_ber(self.ber.as_mut().map(|b| b.snapshot(Instant::now())))
            .with_owd(&self.owd_collector)
            .with_access_report(
                self.access_report_state
                    .as_ref()
                    .map(|state| state.summary()),
            )
            .with_congestion(self.congestion.as_ref().map(|state| state.summary()))
            .with_target(self.label.clone())
    }

    /// Labels this run's reports with its target.
    pub(super) fn set_label(&mut self, label: String) {
        self.label = Some(label);
    }
}

/// Replaces the stored T1 of each probe with its kernel TX timestamp, matched
/// by OPT_ID. Returns how many probes were corrected.
#[cfg(all(feature = "hwtstamp", target_os = "linux"))]
pub(super) fn apply_tx_corrections(
    reports: &[crate::hwtstamp::TxTimestampReport],
    tx_id_to_seq: &mut HashMap<u32, (u32, Instant, u64)>,
    pending: &mut super::pending::PendingTable,
) -> usize {
    let mut applied = 0;
    for report in reports {
        if let Some((seq, sent, wire_t1)) = tx_id_to_seq.remove(&report.opt_id) {
            if let Some(probe) = pending.get_mut(&seq) {
                if probe.send_time == sent && probe.wire_timestamp == wire_t1 {
                    probe.send_timestamp = report.timestamp;
                    applied += 1;
                }
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
/// (draft-ietf-bpm-stamp-cos-ecn-00 §3.4). Both come from one `recvmsg` on Linux and macOS; a
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

fn validate_datagram_size(size: usize, limit: usize) -> Result<(), crate::StartupError> {
    if size > limit {
        return Err(crate::StartupError::config(format!(
            "Probe payload is {size} bytes; UDP payload limit is {limit} bytes including all selected TLVs"
        )));
    }
    Ok(())
}

/// Consecutive probe failures (send errors or refused probes) that end a run.
const MAX_CONSECUTIVE_SEND_FAILURES: u8 = 8;

fn retry_send_error(error: &std::io::Error, failures: u8) -> bool {
    // Invalid buffers/options and permission failures will not improve on retry.
    // Other failures (including ICMP errors and queue pressure) get eight tries.
    failures < MAX_CONSECUTIVE_SEND_FAILURES
        && !matches!(
            error.kind(),
            std::io::ErrorKind::InvalidInput
                | std::io::ErrorKind::PermissionDenied
                | std::io::ErrorKind::Unsupported
                | std::io::ErrorKind::WriteZero
        )
}

fn output_error(error: std::io::Error) -> crate::StartupError {
    crate::StartupError::io("Cannot write measurement output", error)
}

#[cfg(test)]
mod failure_tests {
    use super::*;

    #[test]
    fn datagram_size_boundaries_and_send_retry_budget() {
        for limit in [65_507, 65_527, 65_527 - 16] {
            assert!(validate_datagram_size(limit, limit).is_ok());
            assert!(validate_datagram_size(limit + 1, limit).is_err());
        }
        for kind in [
            std::io::ErrorKind::WouldBlock,
            std::io::ErrorKind::ConnectionRefused,
        ] {
            assert!(retry_send_error(&kind.into(), 1));
            assert!(!retry_send_error(&kind.into(), 8));
        }
        assert!(!retry_send_error(
            &std::io::ErrorKind::InvalidInput.into(),
            1
        ));
    }
}

#[cfg(test)]
#[path = "run/pending_tests.rs"]
mod pending_tests;

#[cfg(all(test, target_os = "linux"))]
#[path = "run/mtu_tests.rs"]
mod mtu_tests;

#[cfg(all(test, target_os = "windows"))]
#[path = "run/windows_mtu_tests.rs"]
mod windows_mtu_tests;

#[cfg(all(test, target_os = "macos"))]
#[path = "run/macos_mtu_tests.rs"]
mod macos_mtu_tests;

#[cfg(all(test, target_os = "windows"))]
#[path = "run/windows_receive_error_tests.rs"]
mod windows_receive_error_tests;

#[cfg(test)]
#[path = "run/admission_tests.rs"]
mod admission_tests;

#[cfg(test)]
#[path = "run/congestion_tests.rs"]
mod congestion_tests;

#[cfg(test)]
#[path = "run/access_report_tests.rs"]
mod access_report_tests;
