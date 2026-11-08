use super::*;
use crate::{
    crypto::HmacKey,
    tlv::{
        BerBurstTlv, BerCountTlv, BerPatternTlv, ExtraPaddingTlv, TlvFlags, TlvList, TlvType,
        TypedTlv,
    },
};

#[cfg(target_os = "linux")]
#[test]
fn single_ber_reply_checks_mtu_preserves_patterns_and_resigns() {
    let key = HmacKey::new(vec![0xab; 16]).unwrap();
    for auth in [false, true] {
        for ipv6 in [false, true] {
            let base = if auth {
                AUTH_BASE_SIZE
            } else {
                UNAUTH_BASE_SIZE
            };
            let mut list = TlvList::new();
            for mut tlv in [
                BerPatternTlv::new(vec![1, 2, 3]).to_raw(),
                BerCountTlv::new(6).to_raw(),
                BerBurstTlv::new(3).to_raw(),
                ExtraPaddingTlv {
                    padding: [1, 2, 3].repeat(534),
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
                return_path_action: ReturnPathAction::Normal,
                reflected_control: None,
                reply_source: None,
                tlv_hmac_generated: auth,
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
                            cap - data.len() < 3,
                            "retain every complete pattern that fits"
                        );
                        let list = TlvList::parse(&data[base..]).unwrap();
                        let kinds: Vec<_> = list.iter().map(|tlv| tlv.tlv_type.to_byte()).collect();
                        assert_eq!(&kinds[..4], &[240, 241, 242, 1]);
                        for tlv in list.non_hmac_tlvs() {
                            if crate::ber::is_ber(tlv.tlv_type) {
                                assert!(tlv.flags.conformant_reflected);
                            } else {
                                assert_eq!(tlv.value, [1, 2, 3].repeat(tlv.value.len() / 3));
                            }
                        }
                        assert_eq!(
                            BerCountTlv::from_raw(&list.non_hmac_tlvs()[1])
                                .unwrap()
                                .count,
                            6
                        );
                        assert_eq!(
                            BerBurstTlv::from_raw(&list.non_hmac_tlvs()[2])
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
            BerPatternTlv::new(vec![1, 2, 3]).to_raw(),
            BerCountTlv::new(6).to_raw(),
            BerBurstTlv::new(3).to_raw(),
            ExtraPaddingTlv {
                padding: [1, 2, 3].repeat(534),
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

        assert!(!fit_reply(&mut data, base, 1500, false).unwrap());
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
                assert_eq!(t.value, [1, 2, 3].repeat(t.value.len() / 3));
            }
        }
        assert!(fit_reply(&mut data, base, base + 10, false).is_err());
    }
}
