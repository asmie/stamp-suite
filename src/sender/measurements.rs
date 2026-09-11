//! Bounded reply-copy accounting and optional counter/timestamp measurements.
use std::collections::{HashMap, HashSet, VecDeque};

use super::PendingPacket;
use crate::{
    clock_format::ClockFormat,
    error_estimate::ErrorEstimate,
    stats::ClockQuality,
    time::timestamp_to_unix_nanos,
    tlv::{DirectMeasurementTlv, FollowUpTelemetryTlv, TimestampMethod},
};

pub const HISTORY_LIMIT: usize = 4096;

#[derive(Clone, Copy, Debug, Default, serde::Serialize)]
pub struct DelaySummary {
    pub samples: u64,
    pub min_ms: Option<f64>,
    pub avg_ms: Option<f64>,
    pub max_ms: Option<f64>,
}
#[derive(Default)]
struct Delays {
    count: u64,
    sum: i128,
    min: Option<i128>,
    max: Option<i128>,
}
impl Delays {
    fn record(&mut self, ns: i128) {
        self.count += 1;
        self.sum += ns;
        self.min = Some(self.min.map_or(ns, |x| x.min(ns)));
        self.max = Some(self.max.map_or(ns, |x| x.max(ns)));
    }
    fn summary(&self) -> DelaySummary {
        DelaySummary {
            samples: self.count,
            min_ms: self.min.map(|x| x as f64 / 1e6),
            avg_ms: (self.count != 0).then(|| self.sum as f64 / self.count as f64 / 1e6),
            max_ms: self.max.map(|x| x as f64 / 1e6),
        }
    }
}

/// Raw counters identifying an endpoint of the current observation window.
#[derive(Clone, Copy, Debug, serde::Serialize)]
pub struct CounterPoint {
    pub sender_tx: u32,
    pub reflector_rx: u32,
    pub reflector_tx: u32,
}
impl From<DirectMeasurementTlv> for CounterPoint {
    fn from(dm: DirectMeasurementTlv) -> Self {
        Self {
            sender_tx: dm.sender_tx_count,
            reflector_rx: dm.reflector_rx_count,
            reflector_tx: dm.reflector_tx_count,
        }
    }
}

/// Counter spans are relative to the first usable observation in the current
/// epoch, not the whole run. Missing counts remain provisional as replies reorder.
#[derive(Clone, Debug, Default, serde::Serialize)]
pub struct DirectSummary {
    pub observations: u64,
    pub anchor: Option<CounterPoint>,
    pub latest_transmit: Option<CounterPoint>,
    pub unavailable: u64,
    pub discontinuities: u64,
    pub reordered: u64,
    pub sender_packets: Option<u64>,
    pub reflector_received: Option<u64>,
    pub forward_missing: Option<u64>,
    pub reflector_transmitted: Option<u64>,
    pub replies_received: Option<u64>,
    pub reverse_missing: Option<u64>,
    pub history_exceeded: bool,
}

#[derive(Clone, Debug, Default, serde::Serialize)]
pub struct FollowUpSummary {
    pub observations: u64,
    pub matched: u64,
    pub repeated: u64,
    pub unmatched: u64,
    pub ambiguous: u64,
    pub unavailable: u64,
    pub reverse_delay: DelaySummary,
    pub clock_quality: ClockQuality,
}

#[derive(Clone, Debug, Default, serde::Serialize)]
pub struct MeasurementSummary {
    pub history_limit: usize,
    pub probes_evicted: u64,
    pub replies_evicted: u64,
    pub requested_replies: u64,
    pub unique_replies: u64,
    pub answered_probes: u64,
    pub additional_replies: u64,
    pub late_replies: u64,
    pub duplicate_replies: u64,
    pub unknown_replies: u64,
    pub reordered_replies: u64,
    /// Includes policy caps/unsupported burst requests; not a network-loss total.
    pub unobserved_requested_replies: u64,
    pub last_reflector_sequence: Option<u32>,
    pub independent_sequence_observations: u64,
    pub reply_rtt: DelaySummary,
    pub direct_measurement: DirectSummary,
    pub follow_up: FollowUpSummary,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(super) struct ReplyKey {
    pub sender: u32,
    pub reflector: u32,
    pub t3: u64,
}
#[derive(Clone, Copy)]
struct Probe {
    packet: PendingPacket,
    ordinal: Option<u32>,
    answered: bool,
    replies: u16,
}
#[derive(Clone, Copy)]
struct ReplyRecord {
    quality: Option<(ErrorEstimate, ErrorEstimate)>,
    t4_ns: Option<i128>,
    format: ClockFormat,
    reference: i64,
}
struct Correlation {
    corrected: bool,
    count: usize,
    unique: Option<ReplyRecord>,
}

#[derive(Default)]
struct Direct {
    summary: DirectSummary,
    anchor: Option<DirectMeasurementTlv>,
    high_tx: u32,
    max_sender: u32,
    max_rx: u32,
    seen: HashSet<u32>,
}
impl Direct {
    fn record(&mut self, dm: DirectMeasurementTlv, expected_sender: u32) {
        if dm.sender_tx_count != expected_sender {
            self.summary.unavailable += 1;
            return;
        }
        self.summary.observations += 1;
        let Some(anchor) = self.anchor else {
            // All-zero reflector counters do not establish supported measurement.
            if dm.reflector_rx_count == 0 && dm.reflector_tx_count == 0 {
                self.summary.unavailable += 1;
                return;
            }
            self.anchor = Some(dm);
            self.summary.anchor = Some(dm.into());
            self.summary.latest_transmit = Some(dm.into());
            self.high_tx = dm.reflector_tx_count;
            self.max_sender = 0;
            self.max_rx = 0;
            self.seen.insert(0);
            return;
        };
        let tx = dm
            .reflector_tx_count
            .wrapping_sub(anchor.reflector_tx_count);
        let sender = dm.sender_tx_count.wrapping_sub(anchor.sender_tx_count);
        let rx = dm
            .reflector_rx_count
            .wrapping_sub(anchor.reflector_rx_count);
        if tx >= 1 << 31 || sender >= 1 << 31 || rx >= 1 << 31 {
            // Could be a reset or data from before the anchor. Neither proves loss.
            self.summary.discontinuities += 1;
            self.anchor = None;
            self.seen.clear();
            self.clear_estimates();
            return;
        }
        if self.seen.contains(&tx) {
            self.summary.unavailable += 1; // distinct replies must advance R_TxC
            self.summary.discontinuities += 1;
            self.anchor = None;
            self.seen.clear();
            self.clear_estimates();
            return;
        }
        if self.seen.len() == HISTORY_LIMIT {
            self.summary.history_exceeded = true;
            self.anchor = None;
            self.seen.clear();
            self.clear_estimates();
            return;
        }
        self.seen.insert(tx);
        let high = self.high_tx.wrapping_sub(anchor.reflector_tx_count);
        if tx < high {
            self.summary.reordered += 1;
        } else {
            self.high_tx = dm.reflector_tx_count;
            self.summary.latest_transmit = Some(dm.into());
            self.max_rx = self.max_rx.max(rx);
        }
        self.max_sender = self.max_sender.max(sender);
        let transmitted = u64::from(high.max(tx));
        let received = self.seen.len() as u64 - 1;
        self.summary.sender_packets = Some(u64::from(self.max_sender));
        self.summary.reflector_received = Some(u64::from(self.max_rx));
        self.summary.forward_missing = self.max_sender.checked_sub(self.max_rx).map(u64::from);
        self.summary.reflector_transmitted = Some(transmitted);
        self.summary.replies_received = Some(received);
        self.summary.reverse_missing = transmitted.checked_sub(received);
    }
    fn clear_estimates(&mut self) {
        self.summary.anchor = None;
        self.summary.latest_transmit = None;
        self.summary.sender_packets = None;
        self.summary.reflector_received = None;
        self.summary.forward_missing = None;
        self.summary.reflector_transmitted = None;
        self.summary.replies_received = None;
        self.summary.reverse_missing = None;
    }
}

/// Validated timing and telemetry for one accepted reply.
pub(super) struct ReplyObservation {
    pub key: ReplyKey,
    pub rtt_ns: u64,
    pub t4_ns: Option<i128>,
    pub format: ClockFormat,
    pub reference: i64,
    pub offset: i32,
    pub ordinal: Option<u32>,
    pub dm: Option<DirectMeasurementTlv>,
    pub follow: Option<FollowUpTelemetryTlv>,
    pub quality: Option<(ErrorEstimate, ErrorEstimate)>,
}

pub(super) struct Measurements {
    copies: u16,
    satisfied: u64,
    probes: HashMap<u32, Probe>,
    probe_order: VecDeque<u32>,
    replies: HashSet<ReplyKey>,
    reply_order: VecDeque<ReplyKey>,
    correlations: HashMap<u32, Correlation>,
    highest_reflector: Option<u32>,
    summary: MeasurementSummary,
    rtt: Delays,
    follow_delay: Delays,
    direct: Direct,
}
impl Measurements {
    pub(super) fn new(copies: u16) -> Self {
        Self {
            copies: copies.max(1),
            satisfied: 0,
            probes: HashMap::new(),
            probe_order: VecDeque::new(),
            replies: HashSet::new(),
            reply_order: VecDeque::new(),
            correlations: HashMap::new(),
            highest_reflector: None,
            summary: MeasurementSummary {
                history_limit: HISTORY_LIMIT,
                ..MeasurementSummary::default()
            },
            rtt: Delays::default(),
            follow_delay: Delays::default(),
            direct: Direct::default(),
        }
    }
    pub(super) fn sent(&mut self, seq: u32, packet: PendingPacket, ordinal: u32) {
        self.summary.requested_replies += u64::from(self.copies);
        self.remember(seq, packet, Some(ordinal));
    }
    fn remember(&mut self, seq: u32, packet: PendingPacket, ordinal: Option<u32>) {
        // Sequence reuse starts a new probe; remove its stale queue entry.
        if self.probes.contains_key(&seq) {
            self.probe_order.retain(|&s| s != seq);
        }
        if self.probes.len() == HISTORY_LIMIT && !self.probes.contains_key(&seq) {
            if let Some(old) = self.probe_order.pop_front() {
                self.probes.remove(&old);
                self.summary.probes_evicted += 1;
            }
        }
        self.probes.insert(
            seq,
            Probe {
                packet,
                ordinal,
                answered: false,
                replies: 0,
            },
        );
        self.probe_order.push_back(seq);
    }
    pub(super) fn answered(&self, seq: u32) -> bool {
        self.probes.get(&seq).is_some_and(|p| p.answered)
    }
    pub(super) fn needs_burst_wait(&self) -> bool {
        self.copies > 1 && self.satisfied < self.summary.requested_replies
    }
    /// Classifies only after authentication and session admission. Returns the
    /// original send context for a unique reply; duplicates/unknowns stop here.
    pub(super) fn accept(
        &mut self,
        key: ReplyKey,
        pending: Option<PendingPacket>,
    ) -> Option<(PendingPacket, Option<u32>)> {
        if self.replies.contains(&key) {
            self.summary.duplicate_replies += 1;
            return None;
        }
        if !self.probes.contains_key(&key.sender) {
            let Some(packet) = pending else {
                self.summary.unknown_replies += 1;
                return None;
            };
            self.remember(key.sender, packet, None);
        }
        let probe = self.probes.get_mut(&key.sender).unwrap();
        if let Some(packet) = pending {
            probe.packet = packet;
        } // corrected kernel T1
        if probe.answered {
            self.summary.additional_replies += 1;
        } else {
            probe.answered = true;
            self.summary.answered_probes += 1;
            if pending.is_none() {
                self.summary.late_replies += 1;
            }
        }
        if probe.replies < self.copies {
            self.satisfied += 1;
        }
        probe.replies = probe.replies.saturating_add(1);
        let result = (probe.packet, probe.ordinal);
        self.summary.unique_replies += 1;
        self.summary.last_reflector_sequence = Some(key.reflector);
        if key.reflector != key.sender {
            self.summary.independent_sequence_observations += 1;
        }
        if let Some(high) = self.highest_reflector {
            let step = key.reflector.wrapping_sub(high);
            if step >= 1 << 31 {
                self.summary.reordered_replies += 1;
            } else if step != 0 {
                self.highest_reflector = Some(key.reflector);
            }
        } else {
            self.highest_reflector = Some(key.reflector);
        }
        if self.replies.len() == HISTORY_LIMIT {
            if let Some(old) = self.reply_order.pop_front() {
                self.replies.remove(&old);
                if let Some(slot) = self.correlations.get_mut(&old.reflector) {
                    slot.count -= 1;
                    if slot.count == 0 {
                        self.correlations.remove(&old.reflector);
                    }
                }
                self.summary.replies_evicted += 1;
            }
        }
        self.replies.insert(key);
        self.reply_order.push_back(key);
        Some(result)
    }
    pub(super) fn observe(&mut self, observation: ReplyObservation) {
        let ReplyObservation {
            key,
            rtt_ns,
            t4_ns,
            format,
            reference,
            offset,
            ordinal,
            dm,
            follow,
            quality,
        } = observation;
        self.rtt.record(i128::from(rtt_ns));
        if let Some(dm) = dm {
            if let Some(ordinal) = ordinal {
                self.direct.record(dm, ordinal);
            } else {
                self.direct.summary.unavailable += 1;
            }
        }
        if let Some(follow) = follow {
            self.summary.follow_up.observations += 1;
            if matches!(follow.timestamp_mode, TimestampMethod::Unknown(_))
                || follow.follow_up_timestamp == 0
            {
                self.summary.follow_up.unavailable += 1;
            } else if follow.sequence_number == key.reflector {
                self.summary.follow_up.ambiguous += 1;
            } else if let Some(slot) = self.correlations.get_mut(&follow.sequence_number) {
                if slot.count != 1 || slot.unique.is_none() {
                    self.summary.follow_up.ambiguous += 1;
                } else if slot.corrected {
                    self.summary.follow_up.repeated += 1;
                } else if let Some(previous) = slot.unique.filter(|_| slot.count == 1) {
                    if let (Some(t4), Some(t3)) = (
                        previous.t4_ns,
                        timestamp_to_unix_nanos(
                            follow.follow_up_timestamp,
                            previous.format,
                            previous.reference + i64::from(offset),
                        ),
                    ) {
                        self.follow_delay
                            .record(t4 - (t3 - i128::from(offset) * 1_000_000_000));
                        self.summary.follow_up.matched += 1;
                        self.summary
                            .follow_up
                            .clock_quality
                            .record(previous.quality);
                        slot.corrected = true;
                    } else {
                        self.summary.follow_up.unavailable += 1;
                    }
                } else {
                    self.summary.follow_up.ambiguous += 1;
                }
            } else {
                self.summary.follow_up.unmatched += 1;
            }
        }
        let record = ReplyRecord {
            quality,
            t4_ns,
            format,
            reference,
        };
        self.correlations
            .entry(key.reflector)
            .and_modify(|slot| {
                slot.count += 1;
                slot.unique = None;
            })
            .or_insert(Correlation {
                corrected: false,
                count: 1,
                // Echoed sequence numbers cannot identify one copy of a
                // requested stateless burst, even before other copies arrive.
                unique: (!(self.copies > 1 && key.sender == key.reflector)).then_some(record),
            });
    }
    pub(super) fn snapshot(&self) -> MeasurementSummary {
        let mut summary = self.summary.clone();
        summary.unobserved_requested_replies =
            summary.requested_replies.saturating_sub(self.satisfied);
        summary.reply_rtt = self.rtt.summary();
        summary.follow_up.reverse_delay = self.follow_delay.summary();
        summary.direct_measurement = self.direct.summary.clone();
        summary
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;
    fn packet() -> PendingPacket {
        PendingPacket {
            send_time: Instant::now(),
            send_timestamp: 0,
        }
    }
    fn key(sender: u32, reflector: u32, t3: u64) -> ReplyKey {
        ReplyKey {
            sender,
            reflector,
            t3,
        }
    }
    fn observe(m: &mut Measurements, k: ReplyKey, follow: Option<FollowUpTelemetryTlv>) {
        m.observe(ReplyObservation {
            key: k,
            rtt_ns: 1_000_000,
            t4_ns: Some(10_000_000_000),
            format: ClockFormat::PTP,
            reference: 10,
            offset: 0,
            ordinal: Some(k.sender + 1),
            dm: None,
            follow,
            quality: None,
        });
    }
    fn dm(s: u32, rx: u32, tx: u32) -> DirectMeasurementTlv {
        DirectMeasurementTlv {
            sender_tx_count: s,
            reflector_rx_count: rx,
            reflector_tx_count: tx,
        }
    }
    #[test]
    fn burst_copies_duplicates_and_late_probes_have_distinct_accounting() {
        let mut m = Measurements::new(3);
        let p = packet();
        m.sent(0, p, 1);
        m.sent(1, p, 2);
        let first = key(0, 10, 100);
        assert!(m.accept(first, Some(p)).is_some());
        observe(&mut m, first, None);
        assert!(m.accept(first, None).is_none());
        for k in [key(0, 12, 102), key(0, 11, 101)] {
            assert!(m.accept(k, None).is_some());
            observe(&mut m, k, None);
        }
        let late = key(1, 13, 103);
        assert!(m.accept(late, None).is_some());
        observe(&mut m, late, None);
        assert!(m.accept(key(99, 99, 99), None).is_none());
        let s = m.snapshot();
        assert_eq!(
            (
                s.unique_replies,
                s.answered_probes,
                s.additional_replies,
                s.late_replies
            ),
            (4, 2, 2, 1)
        );
        assert_eq!(
            (s.duplicate_replies, s.reordered_replies, s.unknown_replies),
            (1, 1, 1)
        );
        assert_eq!(s.reply_rtt.samples, 4);
        assert_eq!(s.unobserved_requested_replies, 2);
        assert!(m.needs_burst_wait());
    }
    #[test]
    fn excess_copies_do_not_satisfy_another_probes_burst() {
        let mut m = Measurements::new(2);
        let p = packet();
        m.sent(0, p, 1);
        m.sent(1, p, 2);
        for n in 0..4 {
            let k = key(0, n, u64::from(n));
            m.accept(k, Some(p)).unwrap();
            observe(&mut m, k, None);
        }
        assert_eq!(m.snapshot().unobserved_requested_replies, 2);
        assert!(m.needs_burst_wait());
    }
    #[test]
    fn direct_counter_windows_distinguish_direction_and_recover_reordering() {
        let mut d = Direct::default();
        d.record(dm(1, 1, 0), 1);
        d.record(dm(4, 3, 3), 4);
        assert_eq!(d.summary.forward_missing, Some(1));
        assert_eq!(d.summary.reverse_missing, Some(2));
        d.record(dm(2, 2, 1), 2); // late copy fills a reverse gap
        assert_eq!(d.summary.reverse_missing, Some(1));
        d.record(dm(5, 5, 4), 5); // reordered forward probe has now reached reflector
        assert_eq!(d.summary.forward_missing, Some(0));
        assert_eq!(d.summary.reverse_missing, Some(1));
        assert_eq!(d.summary.reordered, 1);
    }
    #[test]
    fn direct_counter_wrap_reset_and_unknown_support_do_not_invent_loss() {
        let mut d = Direct::default();
        d.record(dm(1, 0, 0), 1);
        assert!(d.summary.forward_missing.is_none());
        d.record(dm(u32::MAX - 1, u32::MAX - 1, u32::MAX - 1), u32::MAX - 1);
        d.record(dm(1, 0, 1), 1);
        assert_eq!(d.summary.forward_missing, Some(1));
        assert_eq!(d.summary.reverse_missing, Some(2));
        d.record(dm(0, 0, 0), 99);
        assert_eq!(d.summary.unavailable, 2);
        d.record(dm(u32::MAX - 10, 1, 2), u32::MAX - 10);
        assert_eq!(d.summary.discontinuities, 1);
        assert!(d.summary.reverse_missing.is_none());
    }
    #[test]
    fn follow_up_correlates_previous_sequence_and_reports_ambiguity() {
        let mut m = Measurements::new(2);
        let p = packet();
        m.sent(0, p, 1);
        m.sent(1, p, 2);
        m.sent(2, p, 3);
        let a = key(0, 10, 1);
        m.accept(a, Some(p)).unwrap();
        observe(&mut m, a, None);
        let follow = FollowUpTelemetryTlv {
            sequence_number: 10,
            follow_up_timestamp: 9u64 << 32,
            timestamp_mode: TimestampMethod::HwAssist,
        };
        let b = key(1, 11, 2);
        m.accept(b, Some(p)).unwrap();
        observe(&mut m, b, Some(follow));
        assert_eq!(m.snapshot().follow_up.matched, 1);
        assert_eq!(m.snapshot().follow_up.reverse_delay.avg_ms, Some(1000.0));
        let c = key(0, 10, 3);
        m.accept(c, None).unwrap();
        observe(&mut m, c, None);
        let e = key(2, 12, 4);
        m.accept(e, Some(p)).unwrap();
        observe(&mut m, e, Some(follow));
        assert_eq!(m.snapshot().follow_up.ambiguous, 1);
        let unknown = FollowUpTelemetryTlv {
            sequence_number: 99,
            ..follow
        };
        let f = key(2, 13, 5);
        m.accept(f, None).unwrap();
        observe(&mut m, f, Some(unknown));
        assert_eq!(m.snapshot().follow_up.unmatched, 1);
    }
    #[test]
    fn follow_up_uses_previous_packet_clock_format_and_rejects_placeholder() {
        let mut m = Measurements::new(1);
        let p = packet();
        m.sent(0, p, 1);
        m.sent(1, p, 2);
        let a = key(0, 10, 1);
        m.accept(a, Some(p)).unwrap();
        m.observe(ReplyObservation {
            key: a,
            rtt_ns: 1,
            t4_ns: Some(10_000_000_000),
            format: ClockFormat::PTP,
            reference: 10,
            offset: 0,
            ordinal: Some(1),
            dm: None,
            follow: None,
            quality: Some((
                ErrorEstimate::from_wire(0x8001),
                ErrorEstimate::from_wire(0xc002),
            )),
        });
        let b = key(1, 11, 2);
        m.accept(b, Some(p)).unwrap();
        // Current packet NTP does not change the earlier packet's PTP format.
        m.observe(ReplyObservation {
            key: b,
            rtt_ns: 1,
            t4_ns: None,
            format: ClockFormat::NTP,
            reference: 10,
            offset: 0,
            ordinal: Some(2),
            dm: None,
            follow: Some(FollowUpTelemetryTlv {
                sequence_number: 10,
                follow_up_timestamp: 9u64 << 32,
                timestamp_mode: TimestampMethod::SwLocal,
            }),
            quality: None,
        });
        assert_eq!(m.snapshot().follow_up.reverse_delay.avg_ms, Some(1000.0));
        assert_eq!(m.snapshot().follow_up.clock_quality.both_synchronized, 1);
        assert_eq!(
            m.snapshot()
                .follow_up
                .clock_quality
                .last_reflector
                .unwrap()
                .format,
            ClockFormat::PTP
        );
        m.observe(ReplyObservation {
            key: b,
            rtt_ns: 1,
            t4_ns: None,
            format: ClockFormat::NTP,
            reference: 10,
            offset: 0,
            ordinal: Some(2),
            dm: None,
            follow: Some(FollowUpTelemetryTlv::new()),
            quality: None,
        });
        assert_eq!(m.snapshot().follow_up.unavailable, 1);
    }
    #[test]
    fn follow_up_counts_repeated_references_once_and_avoids_stateless_bursts() {
        for stateless in [false, true] {
            let mut m = Measurements::new(2);
            let p = packet();
            m.sent(0, p, 1);
            m.sent(1, p, 2);
            let a = key(0, if stateless { 0 } else { 10 }, 1);
            m.accept(a, Some(p)).unwrap();
            observe(&mut m, a, None);
            for n in 0..2 {
                let b = key(1, 11 + n, 2 + u64::from(n));
                m.accept(b, Some(p)).unwrap();
                observe(
                    &mut m,
                    b,
                    Some(FollowUpTelemetryTlv {
                        sequence_number: a.reflector,
                        follow_up_timestamp: 9u64 << 32,
                        timestamp_mode: TimestampMethod::SwLocal,
                    }),
                );
            }
            let f = m.snapshot().follow_up;
            assert_eq!(f.matched, u64::from(!stateless));
            assert_eq!(f.repeated, u64::from(!stateless));
            assert_eq!(f.ambiguous, if stateless { 2 } else { 0 });
            assert_eq!(f.reverse_delay.samples, u64::from(!stateless));
        }
    }
    #[test]
    fn missing_probe_history_falls_back_without_inflating_request_totals() {
        let mut m = Measurements::new(1);
        let p = packet();
        for n in 0..=HISTORY_LIMIT as u32 {
            m.sent(n, p, n + 1);
        }
        assert_eq!(m.accept(key(0, 10, 1), Some(p)).unwrap().1, None);
        assert_eq!(m.snapshot().requested_replies, HISTORY_LIMIT as u64 + 1);
        assert_eq!(
            m.snapshot().unobserved_requested_replies,
            HISTORY_LIMIT as u64
        );
        let mut d = Direct::default();
        d.record(dm(1, 1, 0), 1);
        d.record(dm(2, 2, 1), 2);
        assert_eq!(d.summary.reverse_missing, Some(0));
        d.record(dm(3, 3, 1), 3);
        assert_eq!(d.summary.reverse_missing, None);
        assert_eq!(d.summary.discontinuities, 1);
    }
    #[test]
    fn all_reply_and_counter_histories_stay_bounded() {
        let mut m = Measurements::new(1);
        let p = packet();
        let mut d = Direct::default();
        for n in 0..(HISTORY_LIMIT as u32 + 20) {
            m.sent(n, p, n + 1);
            let k = key(n, n, u64::from(n));
            m.accept(k, Some(p)).unwrap();
            observe(&mut m, k, None);
            d.record(dm(n + 1, n + 1, n), n + 1);
        }
        assert_eq!(m.probes.len(), HISTORY_LIMIT);
        assert_eq!(m.replies.len(), HISTORY_LIMIT);
        assert_eq!(m.correlations.len(), HISTORY_LIMIT);
        assert_eq!(m.snapshot().probes_evicted, 20);
        assert_eq!(m.snapshot().replies_evicted, 20);
        assert!(d.seen.len() <= HISTORY_LIMIT);
        assert!(d.summary.history_exceeded);
        assert!(m.accept(key(0, 0, 0), None).is_none());
        assert_eq!(m.snapshot().unknown_replies, 1);
    }
    #[test]
    fn reflector_sequence_wrap_is_not_reordering() {
        let mut m = Measurements::new(2);
        let p = packet();
        m.sent(0, p, 1);
        for seq in [u32::MAX, 0] {
            let k = key(0, seq, u64::from(seq));
            m.accept(k, Some(p)).unwrap();
            observe(&mut m, k, None);
        }
        assert_eq!(m.snapshot().reordered_replies, 0);
    }
}
