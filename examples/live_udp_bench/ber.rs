//! Bounded BER workload and reply oracle for the live UDP generator.

use stamp_suite::{
    crypto::HmacKey,
    tlv::{
        ExtraPaddingTlv, ResidualBerValue, TlvList, TlvType, TypedTlv, RESIDUAL_BER_DEFAULT_PATTERN,
    },
};

pub(super) struct Profile {
    clean: Vec<u8>,
    request: TlvList,
    damaged: bool,
}

impl Profile {
    pub(super) fn new(padding: usize, damaged: bool) -> Result<Self, &'static str> {
        if !(16..=1200).contains(&padding) || !padding.is_multiple_of(4) {
            return Err("BER padding must be 16–1200 octets and a multiple of four");
        }
        let clean = RESIDUAL_BER_DEFAULT_PATTERN.repeat(padding / 4);
        let mut bytes = clean.clone();
        if damaged {
            // Four contiguous bits across an octet boundary plus one isolated
            // bit: known count=5, max burst=4 without a production counting oracle.
            bytes[padding / 2] ^= 0x03;
            bytes[padding / 2 + 1] ^= 0xc0;
            bytes[padding - 2] ^= 0x80;
        }
        let mut request = TlvList::new();
        request
            .push(ResidualBerValue::default().to_raw().unwrap())
            .unwrap();
        request
            .push(ExtraPaddingTlv { padding: bytes }.to_raw())
            .unwrap();
        Ok(Self {
            clean,
            request,
            damaged,
        })
    }

    pub(super) fn append(&self, base: &mut Vec<u8>, key: Option<&HmacKey>) {
        let mut list = self.request.clone();
        if let Some(key) = key {
            // BER serialization places padding outside TLV HMAC coverage.
            list.set_hmac(key, &base[..4]);
        }
        base.extend(list.to_bytes());
    }

    pub(super) fn validate(&self, bytes: &[u8], base: usize, key: Option<&HmacKey>) -> bool {
        let expected_len = base + self.request.wire_size() + if key.is_some() { 20 } else { 0 };
        if bytes.len() != expected_len {
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
        let [metadata, padding] = tlvs.non_hmac_tlvs() else {
            return false;
        };
        if metadata.tlv_type != TlvType::ResidualBer || padding.tlv_type != TlvType::ExtraPadding {
            return false;
        }
        let Ok(value) = ResidualBerValue::from_raw(metadata) else {
            return false;
        };
        let expected = if self.damaged { (5, 4) } else { (0, 0) };
        (value.count, value.max_burst) == expected
            && value.sub_tlvs.is_empty()
            && padding.value == self.clean
    }

    pub(super) fn summary(&self) -> serde_json::Value {
        serde_json::json!({"padding_octets": self.clean.len(), "padding_bits": self.clean.len() * 8,
            "expected_forward_bit_errors": if self.damaged { 5 } else { 0 },
            "expected_forward_max_burst_bits": if self.damaged { 4 } else { 0 }})
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn response(
        profile: &Profile,
        key: Option<&HmacKey>,
        mutate: impl FnOnce(&mut Vec<stamp_suite::tlv::RawTlv>),
    ) -> Vec<u8> {
        let (count, max_burst) = if profile.damaged { (5, 4) } else { (0, 0) };
        let mut raws = vec![
            ResidualBerValue {
                count,
                max_burst,
                sub_tlvs: vec![],
            }
            .to_raw()
            .unwrap(),
            ExtraPaddingTlv {
                padding: profile.clean.clone(),
            }
            .to_raw(),
        ];
        for raw in &mut raws {
            raw.clear_reflector_flags();
        }
        mutate(&mut raws);
        let mut list = TlvList::new();
        for raw in raws {
            list.push(raw).unwrap();
        }
        let mut bytes = vec![0; if key.is_some() { 112 } else { 44 }];
        bytes[..4].copy_from_slice(&9u32.to_be_bytes());
        if let Some(key) = key {
            assert!(list.set_hmac_response(key, &bytes[..4]));
        }
        bytes.extend(list.to_bytes());
        bytes
    }

    #[test]
    fn clean_and_damaged_profiles_verify_layout_counters_and_repaired_padding() {
        for padding in [16, 120, 1200] {
            for damaged in [false, true] {
                for auth in [false, true] {
                    let key = auth.then(|| HmacKey::new(vec![0xcd; 32]).unwrap());
                    let profile = Profile::new(padding, damaged).unwrap();
                    let mut packet = vec![0; if auth { 112 } else { 44 }];
                    packet[..4].copy_from_slice(&9u32.to_be_bytes());
                    let base = packet.len();
                    profile.append(&mut packet, key.as_ref());
                    assert_eq!(
                        packet.len(),
                        base + 16 + padding + if auth { 20 } else { 0 }
                    );
                    let tlvs = TlvList::parse(&packet[base..]).unwrap();
                    if let Some(key) = &key {
                        tlvs.verify_hmac(key, &packet[..4], &packet[base..])
                            .unwrap();
                    }
                    let raw = &tlvs.non_hmac_tlvs()[1];
                    let mut count = 0;
                    let mut run = 0;
                    let mut longest = 0;
                    for (&actual, &clean) in raw.value.iter().zip(&profile.clean) {
                        for bit in (0..8).rev() {
                            if ((actual ^ clean) >> bit) & 1 == 1 {
                                count += 1;
                                run += 1;
                                longest = longest.max(run);
                            } else {
                                run = 0;
                            }
                        }
                    }
                    assert_eq!((count, longest), if damaged { (5, 4) } else { (0, 0) });
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
    fn signed_invalid_metadata_flags_padding_and_layout_are_rejected() {
        for auth in [false, true] {
            let key = auth.then(|| HmacKey::new(vec![0xcd; 32]).unwrap());
            let base = if auth { 112 } else { 44 };
            for damaged in [false, true] {
                let profile = Profile::new(120, damaged).unwrap();
                for variant in 0..12 {
                    let bad = response(&profile, key.as_ref(), |raws| match variant {
                        0 => raws[0].value[3] ^= 1,
                        1 => raws[0].value[7] ^= 1,
                        2 => raws[0].flags = stamp_suite::tlv::TlvFlags::from_byte(0x10),
                        3 => raws[0].flags = stamp_suite::tlv::TlvFlags::from_byte(0x40),
                        4 => raws[0].flags = stamp_suite::tlv::TlvFlags::from_byte(0x80),
                        5 => raws[1].value[0] ^= 1,
                        6 => raws[0].tlv_type = TlvType::Unknown(253),
                        7 => raws.push(raws[0].clone()),
                        8 => {
                            raws.remove(0);
                        }
                        9 => raws[0].value.truncate(7),
                        10 => raws[0].flags = stamp_suite::tlv::TlvFlags::from_byte(0x20),
                        11 => raws[1].flags = stamp_suite::tlv::TlvFlags::from_byte(0x10),
                        _ => unreachable!(),
                    });
                    assert!(
                        !profile.validate(&bad, base, key.as_ref()),
                        "variant {variant}"
                    );
                }
                let valid = response(&profile, key.as_ref(), |_| {});
                assert!(!profile.validate(&valid[..valid.len() - 1], base, key.as_ref()));
                let mut oversized = valid.clone();
                oversized.push(0);
                assert!(!profile.validate(&oversized, base, key.as_ref()));
                if auth {
                    let wrong = HmacKey::new(vec![0xaa; 32]).unwrap();
                    assert!(!profile.validate(&valid, base, Some(&wrong)));
                    let mut wrong_sequence = valid;
                    wrong_sequence[3] ^= 1;
                    assert!(!profile.validate(&wrong_sequence, base, key.as_ref()));
                }
            }
        }
    }

    #[test]
    fn reordered_wire_layout_is_rejected_even_with_a_valid_digest() {
        for auth in [false, true] {
            let key = auth.then(|| HmacKey::new(vec![0xcd; 32]).unwrap());
            let profile = Profile::new(120, false).unwrap();
            let base = if auth { 112 } else { 44 };
            let valid = response(&profile, key.as_ref(), |_| {});
            let tlvs = TlvList::parse(&valid[base..]).unwrap();
            // Assemble raw bytes: the normal serializer would canonicalize
            // authenticated BER padding back to the end of the packet.
            let mut body = tlvs.non_hmac_tlvs()[1].to_bytes();
            body.extend(tlvs.non_hmac_tlvs()[0].to_bytes());
            let mut wrong = valid[..base].to_vec();
            if let Some(key) = &key {
                let mut signed = wrong[..4].to_vec();
                signed.extend_from_slice(&body);
                let mut hmac =
                    stamp_suite::tlv::RawTlv::new(TlvType::Hmac, key.compute(&signed).to_vec());
                hmac.clear_reflector_flags();
                body.extend(hmac.to_bytes());
            }
            wrong.extend(body);
            if let Some(key) = &key {
                TlvList::parse(&wrong[base..])
                    .unwrap()
                    .verify_hmac(key, &wrong[..4], &wrong[base..])
                    .unwrap();
            }
            assert!(!profile.validate(&wrong, base, key.as_ref()));
        }
    }

    #[test]
    fn padding_bounds_require_complete_default_patterns() {
        for padding in [0, 4, 15, 17, 1199, 1201, usize::MAX] {
            assert!(Profile::new(padding, false).is_err());
        }
        for padding in [16, 20, 120, 1200] {
            assert!(Profile::new(padding, true).is_ok());
        }
    }
}
