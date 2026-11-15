//! Type 12 workload and bounded per-probe reply-copy accounting.

use serde::Serialize;
use stamp_suite::{
    crypto::HmacKey,
    tlv::{ReflectedControlTlv, TlvList, TlvType, TypedTlv},
};

const MAX_COPIES: usize = 1_000_000;
const INTERVAL_NS: u32 = 1_000_000;

pub(super) struct Profile {
    pub(super) count: u16,
    pub(super) bytes: u16,
}

impl Profile {
    pub(super) fn new(count: u16, bytes: u16) -> Result<Self, &'static str> {
        if !(1..=16).contains(&count) || !(240..=1200).contains(&bytes) || !bytes.is_multiple_of(4)
        {
            return Err("bursts require 1–16 replies and 240–1200 payload octets aligned to four");
        }
        Ok(Self { count, bytes })
    }

    pub(super) fn validate_capacity(&self, probes: usize) -> Result<(), &'static str> {
        if probes == 0
            || probes
                .checked_mul(usize::from(self.count))
                .is_none_or(|n| n > MAX_COPIES)
        {
            return Err("burst tracking permits at most 1,000,000 scheduled reply copies");
        }
        Ok(())
    }

    pub(super) fn append(&self, base: &mut Vec<u8>, key: Option<&HmacKey>) {
        let mut tlvs = TlvList::new();
        tlvs.push(ReflectedControlTlv::new(self.bytes, self.count, INTERVAL_NS).to_raw())
            .unwrap();
        if let Some(key) = key {
            tlvs.set_hmac(key, &base[..4]);
        }
        base.extend(tlvs.to_bytes());
    }

    pub(super) fn validate(&self, bytes: &[u8], base: usize, key: Option<&HmacKey>) -> bool {
        if bytes.len() != usize::from(self.bytes) {
            return false;
        }
        let Ok(tlvs) = TlvList::parse(&bytes[base..]) else {
            return false;
        };
        if tlvs.hmac_tlv().is_some() != key.is_some() || tlvs.iter().any(|t| t.flags.to_byte() != 0)
        {
            return false;
        }
        if let Some(key) = key {
            if tlvs.verify_hmac(key, &bytes[..4], &bytes[base..]).is_err() {
                return false;
            }
        }
        let [control, padding] = tlvs.non_hmac_tlvs() else {
            return false;
        };
        if control.tlv_type != TlvType::ReflectedControl
            || padding.tlv_type != TlvType::ExtraPadding
        {
            return false;
        }
        let Ok(value) = ReflectedControlTlv::from_raw(control) else {
            return false;
        };
        value.length_of_reflected_packet == self.bytes
            && value.number_of_reflected_packets == self.count
            && value.interval_nanoseconds == INTERVAL_NS
            && value.sub_tlvs == [0; 4]
            && padding.value.iter().all(|&b| b == 0)
    }

    pub(super) fn summary(&self) -> serde_json::Value {
        serde_json::json!({"copies_per_probe":self.count,"reply_payload_octets":self.bytes,"requested_interval_ns":INTERVAL_NS})
    }
}

pub(super) enum Verdict {
    First,
    Additional,
    Duplicate,
    Invalid,
}

pub(super) struct Copies {
    count: usize,
    counts: Vec<u8>,
    sequences: Vec<u32>,
    highest_probe: u32,
    load: u64,
    drain: u64,
}

#[derive(Serialize)]
pub(super) struct Summary {
    pub(super) expected_copies: u64,
    pub(super) unique_copies: u64,
    pub(super) missing_copies: u64,
    pub(super) unique_during_load: u64,
    pub(super) received_probes: usize,
    unique_during_drain: u64,
    complete_probes: usize,
    partial_probes: usize,
    unreplied_probes: usize,
}

impl Copies {
    pub(super) fn new(profile: &Profile, capacity: usize) -> Result<Self, &'static str> {
        let probes = capacity
            .checked_sub(1)
            .ok_or("missing reserved probe slot")?;
        profile.validate_capacity(probes)?;
        let count = usize::from(profile.count);
        Ok(Self {
            count,
            counts: vec![0; capacity],
            sequences: vec![0; capacity * count],
            highest_probe: 0,
            load: 0,
            drain: 0,
        })
    }

    pub(super) fn record(&mut self, probe: u32, sequence: u32, during_load: bool) -> Verdict {
        let index = probe as usize;
        if probe == 0 || index >= self.counts.len() {
            return Verdict::Invalid;
        }
        let received = usize::from(self.counts[index]);
        let start = index * self.count;
        if self.sequences[start..start + received].contains(&sequence) {
            return Verdict::Duplicate;
        }
        if received == self.count {
            return Verdict::Invalid;
        }
        self.sequences[start + received] = sequence;
        self.counts[index] += 1;
        self.highest_probe = self.highest_probe.max(probe);
        if during_load {
            self.load += 1;
        } else {
            self.drain += 1;
        }
        if received == 0 {
            Verdict::First
        } else {
            Verdict::Additional
        }
    }

    pub(super) fn summary(&self, sent: u32) -> Result<Summary, &'static str> {
        if self.highest_probe > sent || sent as usize >= self.counts.len() {
            return Err("burst reply refers to an unsent probe");
        }
        let counts = &self.counts[1..=sent as usize];
        let expected_copies = u64::from(sent) * self.count as u64;
        let unique_copies = self.load + self.drain;
        let missing_copies = expected_copies
            .checked_sub(unique_copies)
            .ok_or("too many unique burst copies")?;
        Ok(Summary {
            expected_copies,
            unique_copies,
            missing_copies,
            unique_during_load: self.load,
            unique_during_drain: self.drain,
            received_probes: counts.iter().filter(|&&n| n > 0).count(),
            complete_probes: counts
                .iter()
                .filter(|&&n| usize::from(n) == self.count)
                .count(),
            partial_probes: counts
                .iter()
                .filter(|&&n| n > 0 && usize::from(n) < self.count)
                .count(),
            unreplied_probes: counts.iter().filter(|&&n| n == 0).count(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use stamp_suite::tlv::{ExtraPaddingTlv, RawTlv};

    fn response(
        profile: &Profile,
        key: Option<&HmacKey>,
        mutate: impl FnOnce(&mut Vec<RawTlv>),
    ) -> Vec<u8> {
        let base = if key.is_some() { 112 } else { 44 };
        let mut bytes = vec![0; base];
        bytes[..4].copy_from_slice(&9u32.to_be_bytes());
        let padding =
            usize::from(profile.bytes) - base - 16 - 4 - if key.is_some() { 20 } else { 0 };
        let mut raws = vec![
            ReflectedControlTlv::new(profile.bytes, profile.count, INTERVAL_NS).to_raw(),
            ExtraPaddingTlv::new_zeros(padding).to_raw(),
        ];
        for raw in &mut raws {
            raw.clear_reflector_flags();
        }
        mutate(&mut raws);
        let mut list = TlvList::new();
        for raw in raws {
            list.push(raw).unwrap();
        }
        if let Some(key) = key {
            assert!(list.set_hmac_response(key, &bytes[..4]));
        }
        bytes.extend(list.to_bytes());
        bytes
    }

    #[test]
    fn request_and_reply_profiles_cover_counts_sizes_and_authentication() {
        for count in [1, 4, 16] {
            for size in [240, 1200] {
                for auth in [false, true] {
                    let profile = Profile::new(count, size).unwrap();
                    let key = auth.then(|| HmacKey::new(vec![0xcd; 32]).unwrap());
                    let base = if auth { 112 } else { 44 };
                    let mut request = vec![0; base];
                    profile.append(&mut request, key.as_ref());
                    assert_eq!(request.len(), base + 16 + if auth { 20 } else { 0 });
                    let list = TlvList::parse(&request[base..]).unwrap();
                    assert_eq!(list.non_hmac_tlvs().len(), 1);
                    if let Some(key) = &key {
                        list.verify_hmac(key, &request[..4], &request[base..])
                            .unwrap();
                    }
                    assert!(profile.validate(
                        &response(&profile, key.as_ref(), |_| {}),
                        base,
                        key.as_ref()
                    ));
                }
            }
        }
    }

    #[test]
    fn signed_incorrect_controls_flags_padding_and_layout_are_rejected() {
        for auth in [false, true] {
            let profile = Profile::new(4, 240).unwrap();
            let key = auth.then(|| HmacKey::new(vec![0xcd; 32]).unwrap());
            let base = if auth { 112 } else { 44 };
            for variant in 0..10 {
                let bad = response(&profile, key.as_ref(), |raws| match variant {
                    0 => raws[0].value[1] ^= 4,
                    1 => raws[0].value[3] ^= 1,
                    2 => raws[0].value[7] ^= 1,
                    3 => raws[0].flags = stamp_suite::tlv::TlvFlags::from_byte(0x10),
                    4 => raws[0].flags = stamp_suite::tlv::TlvFlags::from_byte(0x80),
                    5 => raws[1].value[0] = 1,
                    6 => raws.swap(0, 1),
                    7 => raws[0].value[9] = 1,
                    8 => raws.push(raws[0].clone()),
                    9 => {
                        raws.remove(0);
                    }
                    _ => unreachable!(),
                });
                assert!(
                    !profile.validate(&bad, base, key.as_ref()),
                    "variant {variant}"
                );
            }
            let valid = response(&profile, key.as_ref(), |_| {});
            assert!(!profile.validate(&valid[..valid.len() - 1], base, key.as_ref()));
            if auth {
                assert!(!profile.validate(
                    &valid,
                    base,
                    Some(&HmacKey::new(vec![0xaa; 32]).unwrap())
                ));
            }
        }
    }

    #[test]
    fn copies_distinguish_additional_replies_duplicates_partial_probes_and_wrapping_sequences() {
        let profile = Profile::new(4, 240).unwrap();
        let mut copies = Copies::new(&profile, 4).unwrap();
        assert!(matches!(copies.record(2, u32::MAX, true), Verdict::First));
        assert!(matches!(copies.record(2, 0, true), Verdict::Additional));
        assert!(matches!(copies.record(2, 0, false), Verdict::Duplicate));
        assert!(matches!(copies.record(2, 1, false), Verdict::Additional));
        assert!(matches!(copies.record(2, 2, false), Verdict::Additional));
        assert!(matches!(copies.record(2, 3, true), Verdict::Invalid));
        assert!(matches!(copies.record(1, 0, true), Verdict::First));
        for probe in [0, 4, u32::MAX] {
            assert!(matches!(copies.record(probe, 0, true), Verdict::Invalid));
        }
        let summary = serde_json::to_value(copies.summary(3).unwrap()).unwrap();
        assert_eq!(summary["unique_copies"], 5);
        assert_eq!(summary["missing_copies"], 7);
        assert_eq!(summary["complete_probes"], 1);
        assert_eq!(summary["partial_probes"], 1);
        assert_eq!(summary["unreplied_probes"], 1);
        assert!(copies.summary(1).is_err());
    }

    #[test]
    fn profiles_and_copy_storage_have_strict_bounds() {
        for (count, size) in [(0, 240), (17, 240), (1, 239), (1, 241), (1, 1201)] {
            assert!(Profile::new(count, size).is_err());
        }
        let profile = Profile::new(16, 1200).unwrap();
        for capacity in [0, 1, 62502, usize::MAX] {
            assert!(Copies::new(&profile, capacity).is_err());
        }
        assert!(profile.validate_capacity(62500).is_ok());
        assert!(profile.validate_capacity(usize::MAX).is_err());
    }
}
