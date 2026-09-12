//! Residual BER measurement for draft-gandhi-ippm-stamp-ber-07.
//! Only the first accepted reply to each pending probe contributes; missing or
//! invalid metadata never becomes a zero-error sample. Intervals use monotonic
//! receive time and a fixed multiple of the configured transmit interval.
use std::{
    collections::VecDeque,
    time::{Duration, Instant},
};

/// Maximum retained completed intervals and alarms, independently. Lifetime
/// direction totals and live alarm logging are unaffected by history eviction.
pub const BER_HISTORY_LIMIT: usize = 1024;

use crate::{
    crypto::HmacKey,
    tlv::{BerBurstTlv, BerCountTlv, RawTlv, TlvList, TlvType, TypedTlv},
};

pub(crate) fn is_ber(kind: TlvType) -> bool {
    matches!(
        kind,
        TlvType::BerPattern | TlvType::BerCount | TlvType::BerBurst
    )
}

pub(crate) fn parse_pattern(hex_pattern: &str) -> Result<Vec<u8>, String> {
    let text = hex_pattern.strip_prefix("0x").unwrap_or(hex_pattern);
    if text.is_empty() {
        return Err("empty pattern".into());
    }
    hex::decode(text).map_err(|e| e.to_string())
}

/// A validated reply observation, committed only after base authentication,
/// session identity and pending-sequence admission by the sender.
pub(crate) enum Observation {
    Unsupported,
    Sample {
        bits: u64,
        forward_errors: u32,
        forward_burst: Option<u32>,
        reverse_errors: u32,
        reverse_burst: u32,
    },
}

pub(crate) fn observation(
    tlvs: &TlvList,
    data: &[u8],
    base: usize,
    key: Option<&HmacKey>,
    pattern: &[u8],
    padding_size: usize,
    want_burst: bool,
) -> Option<Observation> {
    if tlvs.iter().any(|t| t.is_integrity_failed()) {
        return None;
    }
    if tlvs.hmac_tlv().is_some() {
        let key = key?;
        if data.len() <= base || tlvs.verify_hmac(key, &data[..4], &data[base..]).is_err() {
            return None;
        }
    } else if key.is_some() {
        return None;
    }
    let mut padding = None;
    let mut count = None;
    let mut burst = None;
    let mut pattern_seen = false;
    for tlv in tlvs.non_hmac_tlvs() {
        if tlv.is_malformed() {
            break;
        }
        if is_ber(tlv.tlv_type) && tlv.is_unrecognized() {
            return Some(Observation::Unsupported);
        }
        if !is_ber(tlv.tlv_type) && tlv.tlv_type != TlvType::ExtraPadding {
            continue;
        }
        if tlv.is_unrecognized() || tlv.flags.conformant_reflected {
            return None;
        }
        match tlv.tlv_type {
            TlvType::BerPattern => {
                if pattern_seen || tlv.value != pattern {
                    return None;
                }
                pattern_seen = true;
            }
            TlvType::ExtraPadding if padding.replace(tlv.value.as_slice()).is_some() => {
                return None;
            }
            TlvType::BerCount
                if count
                    .replace(BerCountTlv::from_raw(tlv).ok()?.count)
                    .is_some() =>
            {
                return None;
            }
            TlvType::BerBurst
                if burst
                    .replace(BerBurstTlv::from_raw(tlv).ok()?.max_burst)
                    .is_some() =>
            {
                return None;
            }
            _ => {}
        }
    }
    let padding = padding?;
    // Asymmetric resizing cannot preserve the forward denominator. Do not
    // invent a measurement from a changed or absent padding field.
    if padding.len() != padding_size || pattern.is_empty() {
        return None;
    }
    let bits = padding.len() as u64 * 8;
    let count = count?;
    if u64::from(count) > bits
        || (want_burst && burst.is_none())
        || burst.is_some_and(|n| n > count || (n == 0) != (count == 0))
    {
        return None;
    }
    let (reverse_errors, reverse_burst) = xor_popcount_and_max_burst(padding, pattern);
    Some(Observation::Sample {
        bits,
        forward_errors: count,
        forward_burst: burst,
        reverse_errors,
        reverse_burst,
    })
}

#[derive(Clone, Default, serde::Serialize)]
pub struct DirectionSummary {
    pub packets_received: u64,
    pub packets_with_errors: u64,
    pub padding_bits: u64,
    pub bit_errors: u64,
    pub bit_error_ratio: Option<f64>,
    pub bit_errors_per_million: Option<f64>,
    pub packets_with_errors_per_million: Option<f64>,
    pub burst_samples: u64,
    pub max_burst_bits: Option<u32>,
    pub average_max_burst_bits: Option<f64>,
    #[serde(skip)]
    burst_sum: u64,
}
impl DirectionSummary {
    fn record(&mut self, bits: u64, errors: u32, burst: Option<u32>) {
        self.packets_received += 1;
        self.packets_with_errors += u64::from(errors != 0);
        self.padding_bits += bits;
        self.bit_errors += u64::from(errors);
        if let Some(burst) = burst {
            self.burst_samples += 1;
            self.burst_sum += u64::from(burst);
            self.max_burst_bits = Some(self.max_burst_bits.unwrap_or(0).max(burst));
            self.average_max_burst_bits = Some(self.burst_sum as f64 / self.burst_samples as f64);
        }
        self.bit_error_ratio =
            (self.padding_bits != 0).then(|| self.bit_errors as f64 / self.padding_bits as f64);
        self.bit_errors_per_million = self.bit_error_ratio.map(|v| v * 1_000_000.0);
        self.packets_with_errors_per_million =
            Some(self.packets_with_errors as f64 / self.packets_received as f64 * 1_000_000.0);
    }
}

#[derive(Clone, Default, serde::Serialize)]
pub struct IntervalSummary {
    pub index: u64,
    pub complete: bool,
    pub forward: DirectionSummary,
    pub reverse: DirectionSummary,
}
#[derive(Clone, serde::Serialize)]
pub struct Alarm {
    pub interval: u64,
    pub direction: &'static str,
    pub metric: &'static str,
    pub value_per_million: f64,
    pub threshold_per_million: f64,
}
#[derive(Clone, serde::Serialize)]
pub struct BerSummary {
    pub disabled_by_peer: bool,
    pub interval_ms: u64,
    pub padding_bytes: usize,
    pub forward: DirectionSummary,
    pub reverse: DirectionSummary,
    pub intervals: VecDeque<IntervalSummary>,
    pub alarms: VecDeque<Alarm>,
    pub intervals_omitted: u64,
    pub alarms_omitted: u64,
}

pub(crate) struct BerCollector {
    pub pattern: Vec<u8>,
    pub want_burst: bool,
    pub summary: BerSummary,
    start: Instant,
    interval: Duration,
    current: IntervalSummary,
    thresholds: [Option<f64>; 2],
    above: [bool; 4],
}
impl BerCollector {
    pub fn new(
        pattern: Vec<u8>,
        padding: usize,
        want_burst: bool,
        interval: Duration,
        start: Instant,
        thresholds: [Option<f64>; 2],
    ) -> Self {
        Self {
            pattern,
            want_burst,
            start,
            interval,
            thresholds,
            above: [false; 4],
            current: IntervalSummary::default(),
            summary: BerSummary {
                disabled_by_peer: false,
                interval_ms: interval.as_millis() as u64,
                padding_bytes: padding,
                forward: DirectionSummary::default(),
                reverse: DirectionSummary::default(),
                intervals: VecDeque::new(),
                alarms: VecDeque::new(),
                intervals_omitted: 0,
                alarms_omitted: 0,
            },
        }
    }
    pub fn advance(&mut self, now: Instant) {
        let index = (now.duration_since(self.start).as_nanos() / self.interval.as_nanos()) as u64;
        if index <= self.current.index {
            return;
        }
        self.current.complete = true;
        if self.current.forward.packets_received != 0 {
            self.check_alarms();
            if self.summary.intervals.len() == BER_HISTORY_LIMIT {
                self.summary.intervals.pop_front();
                self.summary.intervals_omitted += 1;
            }
            self.summary.intervals.push_back(self.current.clone());
        }
        // Empty intervals are omitted and carry no usable BER observation.
        self.current = IntervalSummary {
            index,
            ..Default::default()
        };
    }
    fn check_alarms(&mut self) {
        for (d, (name, stats)) in [
            ("forward", &self.current.forward),
            ("reverse", &self.current.reverse),
        ]
        .into_iter()
        .enumerate()
        {
            for (m, (metric, value)) in [
                ("bit_errors", stats.bit_errors_per_million),
                ("packets_with_errors", stats.packets_with_errors_per_million),
            ]
            .into_iter()
            .enumerate()
            {
                let Some((value, threshold)) = value.zip(self.thresholds[m]) else {
                    continue;
                };
                let above = value > threshold;
                if above && !self.above[d * 2 + m] {
                    let alarm = Alarm {
                        interval: self.current.index,
                        direction: name,
                        metric,
                        value_per_million: value,
                        threshold_per_million: threshold,
                    };
                    log::warn!(
                        "BER threshold crossing: {}",
                        serde_json::to_string(&alarm).unwrap_or_default()
                    );
                    if self.summary.alarms.len() == BER_HISTORY_LIMIT {
                        self.summary.alarms.pop_front();
                        self.summary.alarms_omitted += 1;
                    }
                    self.summary.alarms.push_back(alarm);
                }
                self.above[d * 2 + m] = above;
            }
        }
    }
    pub fn record(&mut self, observation: Observation, now: Instant) {
        self.advance(now);
        if self.summary.disabled_by_peer {
            return;
        }
        match observation {
            Observation::Unsupported => {
                self.summary.disabled_by_peer = true;
                log::warn!("Peer reports BER unsupported; disabling BER and continuing STAMP");
            }
            Observation::Sample {
                bits,
                forward_errors,
                forward_burst,
                reverse_errors,
                reverse_burst,
            } => {
                self.current
                    .forward
                    .record(bits, forward_errors, forward_burst);
                self.current
                    .reverse
                    .record(bits, reverse_errors, Some(reverse_burst));
                self.summary
                    .forward
                    .record(bits, forward_errors, forward_burst);
                self.summary
                    .reverse
                    .record(bits, reverse_errors, Some(reverse_burst));
            }
        }
    }
    pub fn snapshot(&mut self, now: Instant) -> BerSummary {
        self.advance(now);
        let mut result = self.summary.clone();
        if self.current.forward.packets_received != 0 {
            result.intervals.push_back(self.current.clone());
        }
        result
    }
    pub fn filter_requests(&self, tlvs: &mut Vec<RawTlv>) {
        if self.summary.disabled_by_peer {
            tlvs.retain(|t| !is_ber(t.tlv_type));
        }
    }
}
/// XORs `padding` against `pattern` repeated, counts total error bits and the
/// longest consecutive run of `1` bits spanning byte boundaries. Runs are
/// counted across the whole padding buffer as a continuous bit stream.
///
/// Returns `(error_count, max_consecutive_error_bits)`.
pub(crate) fn xor_popcount_and_max_burst(padding: &[u8], pattern: &[u8]) -> (u32, u32) {
    if pattern.is_empty() {
        // Should never happen (caller filters empty pattern to default), but
        // be defensive: without a pattern we cannot compare.
        return (0, 0);
    }

    let mut count: u32 = 0;
    let mut current_burst: u32 = 0;
    let mut max_burst: u32 = 0;

    // Overflow is impossible for any realistic packet: a u32 counts up to 2^32
    // error bits, which would require a ~536 MB padding TLV. Use plain arithmetic.
    for (i, &byte) in padding.iter().enumerate() {
        let expected = pattern[i % pattern.len()];
        let err = byte ^ expected;
        count += err.count_ones();

        for bit in (0..8).rev() {
            if (err >> bit) & 1 == 1 {
                current_burst += 1;
                if current_burst > max_burst {
                    max_burst = current_burst;
                }
            } else {
                current_burst = 0;
            }
        }
    }

    (count, max_burst)
}

/// Reduce padding in whole pattern repetitions to meet a complete packet budget.
/// Metadata and at least one full pattern must fit; otherwise sending fails.
pub(crate) fn fit_padding(
    tlvs: &mut [RawTlv],
    cap: usize,
    overhead: usize,
) -> std::io::Result<bool> {
    let wire: usize = tlvs.iter().map(RawTlv::wire_size).sum();
    if overhead + wire <= cap {
        return Ok(false);
    }
    let fail = || {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "BER metadata and one pattern exceed the MTU",
        )
    };
    let pattern_len = tlvs
        .iter()
        .find(|t| t.tlv_type == TlvType::BerPattern)
        .map_or(2, |t| t.value.len());
    if pattern_len == 0 {
        return Err(fail());
    }
    let padding = tlvs
        .iter_mut()
        .find(|t| t.tlv_type == TlvType::ExtraPadding)
        .ok_or_else(fail)?;
    let fixed = overhead + wire - padding.value.len();
    let available = cap.checked_sub(fixed).ok_or_else(fail)?;
    let length = available / pattern_len * pattern_len;
    if length == 0 {
        return Err(fail());
    }
    let mut resized = RawTlv::new(TlvType::ExtraPadding, padding.value[..length].to_vec());
    resized.flags = padding.flags;
    *padding = resized;
    Ok(true)
}

#[cfg(test)]
mod tests {
    #[test]
    fn long_run_bounds_history_and_preserves_totals_and_alarm_transitions() {
        let start = Instant::now();
        let mut collector = BerCollector::new(
            vec![0],
            1,
            true,
            Duration::from_millis(1),
            start,
            [Some(0.0); 2],
        );
        let intervals = (BER_HISTORY_LIMIT * 2 + 20) as u64;
        for index in 0..intervals {
            let errors = if index % 2 == 0 { 1 } else { 0 };
            collector.record(
                Observation::Sample {
                    bits: 8,
                    forward_errors: errors,
                    forward_burst: Some(errors),
                    reverse_errors: errors,
                    reverse_burst: errors,
                },
                start + Duration::from_millis(index),
            );
        }
        let snapshot = collector.snapshot(start + Duration::from_millis(intervals));
        assert_eq!(snapshot.forward.packets_received, intervals);
        assert_eq!(snapshot.reverse.bit_errors, intervals / 2);
        assert_eq!(snapshot.intervals.len(), BER_HISTORY_LIMIT);
        assert_eq!(
            snapshot.intervals_omitted,
            intervals - BER_HISTORY_LIMIT as u64
        );
        assert_eq!(snapshot.intervals[0].index, snapshot.intervals_omitted);
        assert_eq!(snapshot.alarms.len(), BER_HISTORY_LIMIT);
        assert_eq!(
            snapshot.alarms_omitted,
            intervals * 2 - BER_HISTORY_LIMIT as u64
        );
        assert!(snapshot.alarms.iter().all(|alarm| alarm.interval % 2 == 0));
        collector.record(
            Observation::Sample {
                bits: 8,
                forward_errors: 0,
                forward_burst: Some(0),
                reverse_errors: 0,
                reverse_burst: 0,
            },
            start + Duration::from_millis(intervals),
        );
        let partial = collector.snapshot(start + Duration::from_millis(intervals));
        assert_eq!(partial.intervals.len(), BER_HISTORY_LIMIT + 1);
        assert!(!partial.intervals.back().unwrap().complete);
        assert_eq!(partial.intervals_omitted, snapshot.intervals_omitted);
        assert_eq!(collector.summary.intervals.len(), BER_HISTORY_LIMIT);
        let json = serde_json::to_value(partial).unwrap();
        assert_eq!(json["intervals_omitted"], snapshot.intervals_omitted);
        assert!(json["intervals"].is_array());
    }

    use super::*;
    use crate::tlv::{BerPatternTlv, ExtraPaddingTlv, TlvFlags};

    fn reply(flags: u8, count: u32, burst: u32, padding: Vec<u8>) -> TlvList {
        let mut list = TlvList::new();
        for mut t in [
            BerPatternTlv::new(vec![0xff, 0]).to_raw(),
            BerCountTlv::new(count).to_raw(),
            BerBurstTlv::new(burst).to_raw(),
            ExtraPaddingTlv { padding }.to_raw(),
        ] {
            t.flags = TlvFlags::from_byte(flags);
            list.push(t).unwrap();
        }
        list
    }
    #[test]
    fn directional_intervals_ratios_and_threshold_crossings() {
        let start = Instant::now();
        let mut c = BerCollector::new(
            vec![0xff, 0],
            2,
            true,
            Duration::from_secs(1),
            start,
            [Some(100.0), Some(100.0)],
        );
        let sample = || Observation::Sample {
            bits: 16,
            forward_errors: 4,
            forward_burst: Some(3),
            reverse_errors: 1,
            reverse_burst: 1,
        };
        c.record(sample(), start);
        c.record(
            Observation::Sample {
                bits: 16,
                forward_errors: 0,
                forward_burst: Some(0),
                reverse_errors: 0,
                reverse_burst: 0,
            },
            start,
        );
        let s = c.snapshot(start + Duration::from_secs(1));
        assert_eq!(s.forward.padding_bits, 32);
        assert_eq!(s.forward.bit_error_ratio, Some(0.125));
        assert_eq!(s.forward.average_max_burst_bits, Some(1.5));
        assert_eq!(s.reverse.bit_errors, 1);
        assert_eq!(s.intervals.len(), 1);
        assert!(s.intervals[0].complete);
        assert_eq!(s.alarms.len(), 4);
        c.record(sample(), start + Duration::from_secs(1));
        assert_eq!(
            c.snapshot(start + Duration::from_secs(2)).alarms.len(),
            4,
            "remaining above a threshold must not repeat its alarm"
        );
        c.record(
            Observation::Sample {
                bits: 16,
                forward_errors: 0,
                forward_burst: None,
                reverse_errors: 0,
                reverse_burst: 0,
            },
            start + Duration::from_secs(2),
        );
        c.advance(start + Duration::from_secs(3));
        c.record(sample(), start + Duration::from_secs(3));
        assert_eq!(c.snapshot(start + Duration::from_secs(4)).alarms.len(), 8);
    }
    #[test]
    fn incomplete_and_empty_windows_and_omitted_burst_are_honest() {
        let start = Instant::now();
        let mut c = BerCollector::new(
            vec![0xff, 0],
            2,
            false,
            Duration::from_secs(1),
            start,
            [None; 2],
        );
        assert!(c.snapshot(start).forward.bit_error_ratio.is_none());
        c.record(
            Observation::Sample {
                bits: 16,
                forward_errors: 1,
                forward_burst: None,
                reverse_errors: 0,
                reverse_burst: 0,
            },
            start + Duration::from_secs(20),
        );
        let s = c.snapshot(start + Duration::from_millis(20_500));
        assert_eq!(s.intervals.len(), 1);
        assert_eq!(s.intervals[0].index, 20);
        assert!(!s.intervals[0].complete);
        assert_eq!(s.forward.burst_samples, 0);
        assert!(s.forward.max_burst_bits.is_none());
        assert!(s.forward.average_max_burst_bits.is_none());
    }
    #[test]
    fn invalid_metadata_never_becomes_a_zero_error_sample() {
        for (flags, count, burst, pad) in [
            (0x10, 0, 0, vec![0xff, 0]),
            (0x20, 0, 0, vec![0xff, 0]),
            (0x40, 0, 0, vec![0xff, 0]),
            (0, 17, 1, vec![0xff, 0]),
            (0, 1, 2, vec![0xff, 0]),
            (0, 1, 0, vec![0xff, 0]),
            (0, 0, 0, vec![0xff]),
        ] {
            assert!(observation(
                &reply(flags, count, burst, pad),
                &[],
                44,
                None,
                &[0xff, 0],
                2,
                true
            )
            .is_none());
        }
        let sample = observation(
            &reply(0, 4, 2, vec![0xfe, 0]),
            &[],
            44,
            None,
            &[0xff, 0],
            2,
            true,
        )
        .unwrap();
        assert!(matches!(
            sample,
            Observation::Sample {
                forward_errors: 4,
                reverse_errors: 1,
                ..
            }
        ));
        let mut duplicate = reply(0, 0, 0, vec![0xff, 0]);
        let mut t = BerCountTlv::default().to_raw();
        t.flags = TlvFlags::default();
        duplicate.push(t).unwrap();
        assert!(observation(&duplicate, &[], 44, None, &[0xff, 0], 2, true).is_none());
    }
    #[test]
    fn unsupported_and_hmac_integrity_gate() {
        let key = HmacKey::new(vec![0xab; 16]).unwrap();
        let mut list = reply(0x80, 0, 0, vec![0xff, 0]);
        assert!(matches!(
            observation(&list, &[], 44, None, &[0xff, 0], 2, true),
            Some(Observation::Unsupported)
        ));
        assert!(observation(&list, &[], 44, Some(&key), &[0xff, 0], 2, true).is_none());
        list.set_hmac(&key, &[0; 4]);
        let mut data = vec![0; 44];
        data.extend_from_slice(&list.to_bytes());
        let parsed = TlvList::parse(&data[44..]).unwrap();
        assert!(matches!(
            observation(&parsed, &data, 44, Some(&key), &[0xff, 0], 2, true),
            Some(Observation::Unsupported)
        ));
        data[48] ^= 1;
        let parsed = TlvList::parse(&data[44..]).unwrap();
        assert!(observation(&parsed, &data, 44, Some(&key), &[0xff, 0], 2, true).is_none());
    }
    #[test]
    fn padding_budget_preserves_whole_pattern_and_mandatory_fields() {
        let mut tlvs = vec![
            BerPatternTlv::new(vec![1, 2, 3]).to_raw(),
            BerCountTlv::default().to_raw(),
            ExtraPaddingTlv {
                padding: [1, 2, 3].repeat(10),
            }
            .to_raw(),
        ];
        assert!(fit_padding(&mut tlvs, 80, 44).unwrap());
        assert_eq!(tlvs[2].value.len(), 15);
        assert!(fit_padding(&mut tlvs, 65, 44).is_err());
    }
}
