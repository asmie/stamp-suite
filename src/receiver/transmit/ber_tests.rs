use super::*;
use crate::{
    crypto::HmacKey,
    tlv::{
        ExtraPaddingTlv, ResidualBerValue, TlvFlags, TlvList, TlvType, TypedTlv,
        RESIDUAL_BER_PATTERN_SUBTLV_TYPE,
    },
};

#[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
#[test]
fn single_ber_reply_checks_mtu_preserves_patterns_and_resigns() {
    let key = HmacKey::new(vec![0xab; 16]).unwrap();
    for auth in [false, true] {
        for ipv6 in [false, true] {
            if cfg!(target_os = "macos") && !ipv6 {
                continue;
            }
            let base = if auth {
                AUTH_BASE_SIZE
            } else {
                UNAUTH_BASE_SIZE
            };
            let mut list = TlvList::new();
            for mut tlv in [
                metadata(),
                ExtraPaddingTlv {
                    padding: [1, 2, 3, 4, 5].repeat(321),
                }
                .to_raw(),
            ] {
                tlv.flags = TlvFlags::default();
                list.push(tlv).unwrap();
            }
            if auth {
                list.set_hmac_response(&key, &[0; 4]);
            }
            let mut data = vec![0; base];
            data.extend_from_slice(&list.to_bytes());
            let response = StampResponse {
                data,
                cos_request: None,
                cos_reply_policy: None,
                return_path_action: ReturnPathAction::Normal,
                reflected_control: None,
                reply_source: None,
                ber_conformance: Default::default(),
                tlv_conformance: Default::default(),
                tlv_hmac_generated: auth,
                tlv_processed: true,
            };
            let mut t = Transmission::new(
                response,
                Arc::new(Session::new(0)),
                if ipv6 { "[::1]:4000" } else { "127.0.0.1:4000" }
                    .parse()
                    .unwrap(),
                ClockFormat::NTP,
                auth,
                true,
                auth.then(|| key.clone()),
                0,
                false,
            );
            let cap = super::super::mtu_payload_cap(1500, ipv6) as usize;
            let mut queries = 0;
            assert_eq!(
                t.send_next_with_mtu(
                    &ReflectorCounters::new(),
                    &RateLimiter::new(0),
                    |target, options, _| {
                        assert_eq!(target.is_ipv6(), ipv6);
                        assert!(options.dont_fragment);
                        queries += 1;
                        Ok(cap)
                    },
                    |data, _, options| {
                        assert!(options.dont_fragment);
                        assert!(data.len() <= cap);
                        assert!(
                            cap - data.len() < 5,
                            "retain every complete pattern that fits"
                        );
                        let list = TlvList::parse(&data[base..]).unwrap();
                        let kinds: Vec<_> = list.iter().map(|tlv| tlv.tlv_type.to_byte()).collect();
                        assert_eq!(&kinds[..2], &[243, 1]);
                        for tlv in list.non_hmac_tlvs() {
                            if crate::ber::is_ber(tlv.tlv_type) {
                                assert!(tlv.flags.conformant_reflected);
                            } else {
                                assert_eq!(tlv.value, [1, 2, 3, 4, 5].repeat(tlv.value.len() / 5));
                            }
                        }
                        assert_eq!(
                            ResidualBerValue::from_raw(&list.non_hmac_tlvs()[0])
                                .unwrap()
                                .count,
                            6
                        );
                        assert_eq!(
                            ResidualBerValue::from_raw(&list.non_hmac_tlvs()[0])
                                .unwrap()
                                .max_burst,
                            3
                        );
                        if auth {
                            assert_eq!(
                                &data[96..112],
                                &crate::crypto::compute_packet_hmac(&key, data, 96)
                            );
                            list.verify_hmac(&key, &data[..4], &data[base..]).unwrap();
                        }
                        Ok(data.len())
                    },
                ),
                Some(0)
            );
            assert_eq!(queries, 1);
            assert_eq!(t.remaining, 0);
            assert_eq!(t.session.get_transmitted_count(), 1);
        }
    }
}

#[test]
fn ber_route_budget_keeps_whole_patterns_and_resigns_c_metadata() {
    let key = HmacKey::new(vec![0xab; 16]).unwrap();
    for base in [44, 112] {
        let mut list = TlvList::new();
        for mut t in [
            metadata(),
            ExtraPaddingTlv {
                padding: [1, 2, 3, 4, 5].repeat(321),
            }
            .to_raw(),
        ] {
            t.flags = TlvFlags::default();
            list.push(t).unwrap();
        }
        list.set_hmac_response(&key, &[0; 4]);
        let mut data = vec![0; base];
        data.extend_from_slice(&list.to_bytes());
        assert!(has_ber(&data, base));
        let mut invalid = data.clone();
        invalid[base] |= 0x20;
        assert!(
            !has_ber(&invalid, base),
            "I-flagged failure echoes stay opaque"
        );

        assert!(!fit_reply_for_test(&mut data, base, 1500, false).unwrap());
        assert!(data.len() <= 1500);
        sign_tlvs(&mut data, base, &key);
        let list = TlvList::parse(&data[base..]).unwrap();
        assert!(list.verify_hmac(&key, &data[..4], &data[base..]).is_ok());
        for t in list.non_hmac_tlvs() {
            if crate::ber::is_ber(t.tlv_type) {
                assert!(t.flags.conformant_reflected);
            }
            if t.tlv_type == TlvType::ExtraPadding {
                assert!(!t.value.is_empty());
                assert_eq!(t.value, [1, 2, 3, 4, 5].repeat(t.value.len() / 5));
            }
        }
        assert!(fit_reply_for_test(&mut data, base, base + 10, false).is_err());
    }
}

fn metadata() -> crate::tlv::RawTlv {
    let mut value =
        ResidualBerValue::request(RESIDUAL_BER_PATTERN_SUBTLV_TYPE, Some(&[1, 2, 3, 4, 5]))
            .unwrap();
    value.count = 6;
    value.max_burst = 3;
    value.sub_tlvs[0].flags = 0;
    value.to_raw().unwrap()
}

#[test]
fn header_trimming_precedes_successor_ber_padding_and_preserves_signatures() {
    let key = HmacKey::new(vec![0xab; 16]).unwrap();
    let mut list = TlvList::new();
    for mut raw in [
        metadata(),
        ExtraPaddingTlv {
            padding: [1, 2, 3, 4, 5].repeat(321),
        }
        .to_raw(),
        crate::tlv::RawTlv::new(TlvType::ReflectedFixedHdr, vec![0; 20]),
    ] {
        raw.clear_reflector_flags();
        list.push(raw).unwrap();
    }
    list.set_hmac_response(&key, &[0; 4]);
    let mut data = vec![0; 44];
    data.extend_from_slice(&list.to_bytes());
    assert!(fit_reply_for_test(&mut data, 44, 1500, false).is_ok());
    sign_tlvs(&mut data, 44, &key);
    let list = TlvList::parse(&data[44..]).unwrap();
    assert!(data.len() <= 1500);
    assert!(list
        .iter()
        .all(|t| t.tlv_type != TlvType::ReflectedFixedHdr));
    assert!(list.non_hmac_tlvs()[0].flags.conformant_reflected);
    assert_eq!(list.non_hmac_tlvs()[1].value.len() % 5, 0);
    list.verify_hmac(&key, &data[..4], &data[44..]).unwrap();
}

#[test]
fn generated_hmac_after_malformed_ber_uses_actual_stateful_sequence() {
    let key = HmacKey::new(vec![0xab; 16]).unwrap();
    for auth in [false, true] {
        let base = if auth { 112 } else { 44 };
        let mut data = vec![0; base];
        // Complete framing, but BER's known value is short: M+C. Padding
        // follows the generated HMAC and is opaque after the M boundary.
        data.extend_from_slice(&[0x50, 243, 0, 7]);
        data.extend_from_slice(&[0; 7]);
        let at = data.len();
        let digest = key.compute_parts([&data[..4], &data[base..at]]);
        data.extend_from_slice(&[0, 8, 0, 16]);
        data.extend_from_slice(&digest);
        data.extend_from_slice(&[0x80, 1, 0, 4, 255, 0, 255, 0]);
        let original = data.clone();
        data[..4].copy_from_slice(&42u32.to_be_bytes());
        sign_tlvs(&mut data, base, &key);
        let expected = key.compute_parts([&data[..4], &data[base..at]]);
        assert_eq!(&data[at + 4..at + 20], &expected);
        assert_ne!(&data[at + 4..at + 20], &original[at + 4..at + 20]);
        assert_eq!(&data[base..at], &original[base..at]);
        assert_eq!(&data[at + 20..], &original[at + 20..]);
    }
}

fn controlled_sample(
    mode: u8,
    ipv6: bool,
    explicit_pattern: Option<&[u8]>,
    prior_c: bool,
    header: bool,
) -> Transmission {
    let auth = mode == 2;
    let signed = mode != 0;
    let key = HmacKey::new(vec![0xab; 16]).unwrap();
    let base = if auth {
        AUTH_BASE_SIZE
    } else {
        UNAUTH_BASE_SIZE
    };
    let pattern = explicit_pattern.unwrap_or(&[0xff, 0, 0xff, 0]);
    let mut value =
        ResidualBerValue::request(RESIDUAL_BER_PATTERN_SUBTLV_TYPE, explicit_pattern).unwrap();
    value.count = 6;
    value.max_burst = 3;
    for sub in &mut value.sub_tlvs {
        sub.flags = 0;
    }
    let mut list = TlvList::new();
    let mut ber = value.to_raw().unwrap();
    ber.clear_reflector_flags();
    if prior_c {
        ber.set_conformant_reflected();
    }
    list.push(ber).unwrap();
    let mut control = crate::tlv::ReflectedControlTlv::new(3000, 3, 1000).to_raw();
    control.clear_reflector_flags();
    list.push(control).unwrap();
    if header {
        let mut raw = crate::tlv::RawTlv::new(TlvType::ReflectedFixedHdr, vec![0; 20]);
        raw.clear_reflector_flags();
        list.push(raw).unwrap();
    }
    let mut pad = ExtraPaddingTlv {
        padding: pattern.repeat(500),
    }
    .to_raw();
    pad.clear_reflector_flags();
    list.push(pad).unwrap();
    if signed {
        list.set_hmac_response(&key, &[0; 4]);
    }
    let mut data = vec![0; base];
    data.extend_from_slice(&list.to_bytes());
    let response = StampResponse {
        data,
        cos_request: None,
        cos_reply_policy: None,
        return_path_action: ReturnPathAction::Normal,
        reflected_control: Some(super::super::ReflectedControlBehavior {
            max_size: 3000,
            extra_copies: 2,
            interval_ns: 1000,
            suppress_reply_ext_headers: false,
        }),
        reply_source: None,
        ber_conformance: Default::default(),
        tlv_conformance: Default::default(),
        tlv_hmac_generated: signed,
        tlv_processed: true,
    };
    let source = if ipv6 { "[::1]:4000" } else { "127.0.0.1:4000" }
        .parse()
        .unwrap();
    Transmission::new(
        response,
        Arc::new(Session::new(0)),
        source,
        ClockFormat::NTP,
        auth,
        true,
        signed.then_some(key),
        0,
        false,
    )
}

#[test]
fn controlled_ber_mtu_clamp_preserves_pattern_bytes_and_signatures() {
    for mode in 0..3 {
        let auth = mode == 2;
        let signed = mode != 0;
        let key = HmacKey::new(vec![0xab; 16]).unwrap();
        for ipv6 in [false, true] {
            for explicit in [false, true] {
                for prior_c in [false, true] {
                    for header in [false, true] {
                        let base = if auth {
                            AUTH_BASE_SIZE
                        } else {
                            UNAUTH_BASE_SIZE
                        };
                        let pattern: &[u8] = if explicit {
                            &[1, 2, 3, 4, 5]
                        } else {
                            &[0xff, 0, 0xff, 0]
                        };
                        let mut tx = controlled_sample(
                            mode,
                            ipv6,
                            explicit.then_some(pattern),
                            prior_c,
                            header,
                        );
                        let cap = super::super::mtu_payload_cap(1500, ipv6) as usize;
                        let counters = ReflectorCounters::new();
                        tx.send_next_with_mtu(
                            &counters,
                            &RateLimiter::new(0),
                            |_, _, _| Ok(cap),
                            |bytes, _, _| {
                                assert_eq!(bytes.len(), cap);
                                let list = TlvList::parse(&bytes[base..]).unwrap();
                                assert!(
                                    list.iter()
                                        .all(|t| t.tlv_type != TlvType::ReflectedFixedHdr),
                                    "remove reflected headers before resizing BER padding"
                                );
                                let pad = list
                                    .iter()
                                    .find(|t| t.tlv_type == TlvType::ExtraPadding)
                                    .unwrap();
                                assert!(pad.is_processable());
                                assert!(!pad.value.is_empty());
                                assert!(
                                    pad.value
                                        .iter()
                                        .zip(pattern.iter().cycle())
                                        .all(|(a, b)| a == b),
                                    "repaired BER bytes"
                                );
                                let ber = list
                                    .iter()
                                    .find(|t| t.tlv_type == TlvType::ResidualBer)
                                    .unwrap();
                                assert!(ber.flags.conformant_reflected);
                                let value = ResidualBerValue::from_raw(ber).unwrap();
                                assert_eq!((value.count, value.max_burst), (6, 3));
                                assert!(
                                    list.iter()
                                        .find(|t| t.tlv_type == TlvType::ReflectedControl)
                                        .unwrap()
                                        .flags
                                        .conformant_reflected
                                );
                                if signed {
                                    list.verify_hmac(&key, &bytes[..4], &bytes[base..]).unwrap();
                                }
                                if auth {
                                    assert_eq!(
                                        &bytes[96..112],
                                        &crate::crypto::compute_packet_hmac(&key, bytes, 96)
                                    );
                                }
                                Ok(bytes.len())
                            },
                        )
                        .unwrap();
                        assert_eq!(tx.remaining, 0, "MTU clamp terminates the burst");
                        assert_eq!(
                            counters.ber_conformance_count(
                                crate::ber::BerConformanceReason::PaddingResized
                            ),
                            1
                        );
                    }
                }
            }
        }
    }
}

#[test]
fn controlled_header_trimming_marks_only_changed_ber_denominators() {
    for mode in 0..3 {
        for ipv6 in [false, true] {
            for refill in [0, 7] {
                let mut tx = controlled_sample(mode, ipv6, Some(&[1, 2, 3, 4, 5]), false, true);
                let base = if mode == 2 { 112 } else { 44 };
                let cap = tx.response.data.len() - 24 + refill;
                let counters = ReflectorCounters::new();
                tx.send_next_with_mtu(
                    &counters,
                    &RateLimiter::new(0),
                    |_, _, _| Ok(cap),
                    |bytes, _, _| {
                        assert_eq!(bytes.len(), cap);
                        let list = TlvList::parse(&bytes[base..]).unwrap();
                        assert!(list
                            .iter()
                            .all(|t| t.tlv_type != TlvType::ReflectedFixedHdr));
                        let ber = list
                            .iter()
                            .find(|t| t.tlv_type == TlvType::ResidualBer)
                            .unwrap();
                        assert_eq!(ber.flags.conformant_reflected, refill != 0);
                        let padding = list
                            .iter()
                            .find(|t| t.tlv_type == TlvType::ExtraPadding)
                            .unwrap();
                        assert_eq!(padding.value.len(), 2500 + refill);
                        assert!(padding
                            .value
                            .iter()
                            .zip([1, 2, 3, 4, 5].iter().cycle())
                            .all(|(a, b)| a == b));
                        assert!(
                            list.iter()
                                .find(|t| t.tlv_type == TlvType::ReflectedControl)
                                .unwrap()
                                .flags
                                .conformant_reflected
                        );
                        if mode != 0 {
                            list.verify_hmac(
                                &HmacKey::new(vec![0xab; 16]).unwrap(),
                                &bytes[..4],
                                &bytes[base..],
                            )
                            .unwrap();
                        }
                        Ok(bytes.len())
                    },
                )
                .unwrap();
                assert_eq!(tx.remaining, 0);
                assert_eq!(
                    counters
                        .ber_conformance_count(crate::ber::BerConformanceReason::PaddingResized),
                    u64::from(refill != 0)
                );
            }
        }
    }
}

#[test]
fn controlled_ber_clamp_handles_partial_patterns_without_malformed_tails() {
    for mode in 0..3 {
        for ipv6 in [false, true] {
            for deficit in 1..=3 {
                let mut tx = controlled_sample(mode, ipv6, Some(&[1, 2, 3, 4, 5]), false, false);
                let cap = tx.response.data.len() - 2500 - deficit;
                let counters = ReflectorCounters::new();
                assert!(tx
                    .send_next_with_mtu(
                        &counters,
                        &RateLimiter::new(0),
                        |_, _, _| Ok(cap),
                        |_, _, _| panic!("mandatory fields do not fit")
                    )
                    .is_none());
                assert_eq!(counters.packets_reflected.load(Ordering::Relaxed), 0);
            }
            for available in 0..=5 {
                let mut tx = controlled_sample(mode, ipv6, Some(&[1, 2, 3, 4, 5]), false, false);
                let cap = tx.response.data.len() - 2500 + available;
                let base = if mode == 2 { 112 } else { 44 };
                let counters = ReflectorCounters::new();
                let result = tx.send_next_with_mtu(
                    &counters,
                    &RateLimiter::new(0),
                    |_, _, _| Ok(cap),
                    |bytes, _, _| {
                        assert_eq!(bytes.len(), cap);
                        let list = TlvList::parse(&bytes[base..]).unwrap();
                        assert_eq!(
                            list.iter()
                                .find(|t| t.tlv_type == TlvType::ExtraPadding)
                                .unwrap()
                                .value,
                            [1, 2, 3, 4, 5][..available]
                        );
                        Ok(bytes.len())
                    },
                );
                assert!(result.is_some());
                assert_eq!(counters.packets_reflected.load(Ordering::Relaxed), 1);
                assert_eq!(
                    counters
                        .ber_conformance_count(crate::ber::BerConformanceReason::PaddingResized),
                    1
                );
            }
        }
    }
}

#[test]
fn controlled_ber_mtu_retry_restores_untrimmed_template_and_burst() {
    for mode in 0..3 {
        for ipv6 in [false, true] {
            let mut tx = controlled_sample(mode, ipv6, Some(&[1, 2, 3, 4, 5]), false, true);
            let original_len = tx.response.data.len();
            let base = if mode == 2 { 112 } else { 44 };
            let counters = ReflectorCounters::new();
            let mut sends = 0;
            tx.send_next_with_mtu(
                &counters,
                &RateLimiter::new(0),
                |_, _, refresh| Ok(if refresh { 4000 } else { 1400 }),
                |bytes, _, _| {
                    sends += 1;
                    if sends == 1 {
                        return Err(message_too_large_error());
                    }
                    assert_eq!(bytes.len(), original_len);
                    let list = TlvList::parse(&bytes[base..]).unwrap();
                    assert!(list
                        .iter()
                        .any(|t| t.tlv_type == TlvType::ReflectedFixedHdr));
                    assert!(list.iter().all(|t| !t.flags.conformant_reflected));
                    let padding = list
                        .iter()
                        .find(|t| t.tlv_type == TlvType::ExtraPadding)
                        .unwrap();
                    assert_eq!(padding.value, [1, 2, 3, 4, 5].repeat(500));
                    if mode != 0 {
                        list.verify_hmac(
                            &HmacKey::new(vec![0xab; 16]).unwrap(),
                            &bytes[..4],
                            &bytes[base..],
                        )
                        .unwrap();
                    }
                    Ok(bytes.len())
                },
            )
            .unwrap();
            assert_eq!(sends, 2);
            assert_eq!(tx.remaining, 2);
            assert_eq!(
                counters.ber_conformance_count(crate::ber::BerConformanceReason::PaddingResized),
                0
            );
        }
    }
}

#[test]
fn controlled_ber_clamp_does_not_interpret_unusable_nested_patterns() {
    for flags in [TlvFlags::U, TlvFlags::M, TlvFlags::I, TlvFlags::C] {
        let mut tx = controlled_sample(1, false, Some(&[1, 2, 3, 4, 5]), true, false);
        tx.response.data[UNAUTH_BASE_SIZE + 4 + 8] = flags;
        let counters = ReflectorCounters::new();
        assert!(tx
            .send_next_with_mtu(
                &counters,
                &RateLimiter::new(0),
                |_, _, _| Ok(1400),
                |_, _, _| panic!("unusable pattern was sent")
            )
            .is_none());
        assert_eq!(counters.packets_reflected.load(Ordering::Relaxed), 0);
        assert_eq!(
            counters.ber_conformance_count(crate::ber::BerConformanceReason::PaddingResized),
            0
        );
    }
}
