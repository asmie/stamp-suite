use super::diagnostics_tests::{chain, reflect_captured, tlv};
use super::*;
use crate::receiver::CapturedHeaders;
use crate::tlv::{TlvConformanceReason as Reason, TlvList};

fn captures() -> CapturedHeaders {
    let mut fixed = vec![0; 20];
    fixed[0] = 0x45;
    CapturedHeaders {
        fixed_headers: vec![fixed],
        ipv6_ext_headers: vec![17, 0, 1, 2, 3, 4, 5, 6],
    }
}

fn request(kind: u8, len: usize, selector: u8) -> Vec<u8> {
    let mut value = vec![0; len];
    value[0] = selector;
    tlv(kind, &value)
}

fn assert_counts(counters: &ReflectorCounters, expected: &[Reason]) {
    for reason in Reason::ALL {
        assert_eq!(
            counters.tlv_conformance_count(reason),
            u64::from(expected.contains(&reason)),
            "{reason:?}"
        );
    }
    assert!(counters.ber_conformance_counts().values().all(|n| *n == 0));
}

fn assert_signed_headers(bytes: &[u8], auth: bool, expected_c: usize) {
    let base = if auth {
        AUTH_BASE_SIZE
    } else {
        UNAUTH_BASE_SIZE
    };
    let list = TlvList::parse(&bytes[base..]).unwrap();
    assert_eq!(
        list.iter()
            .filter(|t| matches!(
                t.tlv_type,
                TlvType::ReflectedFixedHdr | TlvType::ReflectedIpv6ExtHdr
            ) && t.flags.processed()
                && t.flags.conformant_reflected)
            .count(),
        expected_c
    );
    let key = HmacKey::new(vec![0x42; 16]).unwrap();
    list.verify_hmac(&key, &bytes[..4], &bytes[base..]).unwrap();
    if auth {
        assert_eq!(
            &bytes[96..112],
            &crate::crypto::compute_packet_hmac(&key, bytes, 96)
        );
    }
}

#[test]
fn header_reasons_match_processed_c_flags_and_signed_successful_sends() {
    for auth in [false, true] {
        for ipv6 in [false, true] {
            for kind in [247, 246] {
                let len = if kind == 247 { 20 } else { 8 };
                for reason in [
                    Reason::HeaderOrder,
                    Reason::HeaderFixedPolicy,
                    Reason::HeaderIpv6Policy,
                    Reason::HeaderIpv6Length,
                    Reason::HeaderCaptureUnavailable,
                    Reason::HeaderSelectorAmbiguous,
                    Reason::HeaderSelectorNoMatch,
                    Reason::HeaderLengthUnavailable,
                ] {
                    if (reason == Reason::HeaderFixedPolicy && kind != 247)
                        || (matches!(
                            reason,
                            Reason::HeaderIpv6Policy
                                | Reason::HeaderIpv6Length
                                | Reason::HeaderOrder
                        ) && kind != 246)
                    {
                        continue;
                    }
                    let mut captured = captures();
                    let raw = match reason {
                        Reason::HeaderOrder => chain(&[request(246, 8, 0), request(247, 20, 0)]),
                        Reason::HeaderIpv6Length => request(246, 7, 0),
                        Reason::HeaderSelectorAmbiguous => {
                            captured
                                .fixed_headers
                                .push(captured.fixed_headers[0].clone());
                            captured.ipv6_ext_headers.extend_from_within(..);
                            request(kind, len, if kind == 247 { 0x45 } else { 17 })
                        }
                        Reason::HeaderSelectorNoMatch => request(kind, len, 0xff),
                        Reason::HeaderLengthUnavailable => request(kind, len + 8, 0),
                        _ => request(kind, len, 0),
                    };
                    let mut tx = reflect_captured(
                        &raw,
                        auth,
                        ipv6,
                        false,
                        false,
                        if reason == Reason::HeaderCaptureUnavailable {
                            None
                        } else {
                            Some(&captured)
                        },
                        |ctx| {
                            ctx.reflect_fixed_header = reason != Reason::HeaderFixedPolicy;
                            ctx.reflect_ipv6_ext_header = reason != Reason::HeaderIpv6Policy;
                        },
                    )
                    .unwrap();
                    assert_eq!(
                        tx.response.tlv_conformance.iter().collect::<Vec<_>>(),
                        vec![reason]
                    );
                    let counters = ReflectorCounters::new();
                    assert_counts(&counters, &[]);
                    tx.send_next(&counters, &RateLimiter::new(0), |bytes, _, _| {
                        assert_signed_headers(
                            bytes,
                            auth,
                            if reason == Reason::HeaderOrder { 2 } else { 1 },
                        );
                        Ok(bytes.len())
                    })
                    .unwrap();
                    assert_counts(&counters, &[reason]);
                }
            }
        }
    }
}

#[test]
fn header_successes_consumed_records_and_opaque_echoes_are_distinct() {
    for auth in [false, true] {
        for ipv6 in [false, true] {
            let captured = captures();
            let raw = chain(&[request(247, 20, 0), request(246, 8, 0)]);
            let mut tx =
                reflect_captured(&raw, auth, ipv6, false, false, Some(&captured), |_| {}).unwrap();
            let counters = ReflectorCounters::new();
            tx.send_next(&counters, &RateLimiter::new(0), |bytes, _, _| {
                assert_signed_headers(bytes, auth, 0);
                Ok(bytes.len())
            })
            .unwrap();
            assert_counts(&counters, &[]);
            // First-fit consumption leaves no second record of this length.
            let raw = chain(&[request(247, 20, 0), request(247, 20, 0)]);
            let mut tx =
                reflect_captured(&raw, auth, ipv6, false, false, Some(&captured), |_| {}).unwrap();
            tx.send_next(&counters, &RateLimiter::new(0), |bytes, _, _| {
                assert_signed_headers(bytes, auth, 1);
                Ok(bytes.len())
            })
            .unwrap();
            assert_counts(&counters, &[Reason::HeaderLengthUnavailable]);
            let counters = ReflectorCounters::new();
            for ignore in [false, true] {
                let mut tx = reflect_captured(&raw, auth, ipv6, !ignore, false, None, |ctx| {
                    if ignore {
                        ctx.tlv_mode = crate::configuration::TlvHandlingMode::Ignore;
                    }
                })
                .unwrap();
                assert!(tx.response.tlv_conformance.is_empty());
                tx.send_next(&counters, &RateLimiter::new(0), |b, _, _| Ok(b.len()))
                    .unwrap();
            }
            // A malformed CoS owner stops semantic processing before headers.
            let raw = chain(&[tlv(4, &[0; 3]), request(247, 20, 0)]);
            let mut tx = reflect_captured(&raw, auth, ipv6, false, false, None, |_| {}).unwrap();
            assert!(tx.response.tlv_conformance.is_empty());
            tx.send_next(&counters, &RateLimiter::new(0), |b, _, _| Ok(b.len()))
                .unwrap();
            assert_counts(&counters, &[]);
        }
    }
}

#[test]
fn header_diagnostics_follow_only_surviving_headers_after_size_trimming() {
    for auth in [false, true] {
        for ipv6 in [false, true] {
            let captured = captures();
            for same_reason in [false, true] {
                let raw = if same_reason {
                    chain(&[request(247, 20, 0), request(247, 20, 0)])
                } else {
                    chain(&[request(247, 20, 0), request(246, 8, 0)])
                };
                for retained in 0..=2 {
                    let base = if auth {
                        AUTH_BASE_SIZE
                    } else {
                        UNAUTH_BASE_SIZE
                    };
                    let cap = base
                        + 20
                        + if retained == 0 {
                            0
                        } else if retained == 1 {
                            24
                        } else {
                            raw.len()
                        };
                    for send_time in [false, true] {
                        let mut tx = reflect_captured(
                            &raw,
                            auth,
                            ipv6,
                            false,
                            false,
                            if same_reason { None } else { Some(&captured) },
                            |ctx| {
                                ctx.reflect_ipv6_ext_header = false;
                                if !send_time {
                                    ctx.reflected_control_max_size = cap as u16;
                                }
                            },
                        )
                        .unwrap();
                        if send_time {
                            force_route_budget(&mut tx, auth);
                        }
                        let counters = ReflectorCounters::new();
                        let expected = if same_reason && retained > 0 {
                            vec![Reason::HeaderCaptureUnavailable]
                        } else if !same_reason && retained == 2 {
                            vec![Reason::HeaderIpv6Policy]
                        } else {
                            vec![]
                        };
                        tx.send_next_with_mtu(
                            &counters,
                            &RateLimiter::new(0),
                            |_, _, _| Ok(cap),
                            |bytes, _, _| {
                                assert_eq!(bytes.len(), cap);
                                assert_signed_headers(
                                    bytes,
                                    auth,
                                    if same_reason {
                                        retained
                                    } else {
                                        usize::from(retained == 2)
                                    },
                                );
                                Ok(bytes.len())
                            },
                        )
                        .unwrap();
                        assert_counts(&counters, &expected);
                    }
                }
            }
        }
    }
}

fn force_route_budget(tx: &mut Transmission, auth: bool) {
    tx.plan = Some(TransportPlan::new(
        &tx.response,
        tx.source,
        if auth {
            AUTH_BASE_SIZE
        } else {
            UNAUTH_BASE_SIZE
        },
        false,
    ));
    tx.plan.as_mut().unwrap().options.dont_fragment = true;
}

#[test]
fn header_mtu_retries_restore_reason_provenance_from_the_original_reply() {
    for auth in [false, true] {
        for ipv6 in [false, true] {
            for grows in [false, true] {
                let captured = captures();
                let raw = chain(&[request(247, 20, 0), request(246, 8, 0)]);
                let mut tx =
                    reflect_captured(&raw, auth, ipv6, false, false, Some(&captured), |ctx| {
                        ctx.reflect_ipv6_ext_header = false;
                    })
                    .unwrap();
                force_route_budget(&mut tx, auth);
                let small = if auth {
                    AUTH_BASE_SIZE
                } else {
                    UNAUTH_BASE_SIZE
                } + 20
                    + 24;
                let counters = ReflectorCounters::new();
                let mut sends = 0;
                tx.send_next_with_mtu(
                    &counters,
                    &RateLimiter::new(0),
                    |_, _, refresh| Ok(if refresh == grows { 400 } else { small }),
                    |bytes, _, _| {
                        sends += 1;
                        if sends == 1 {
                            Err(message_too_large_error())
                        } else {
                            assert_signed_headers(bytes, auth, usize::from(grows));
                            Ok(bytes.len())
                        }
                    },
                )
                .unwrap();
                assert_eq!(sends, 2);
                assert_counts(
                    &counters,
                    if grows {
                        &[Reason::HeaderIpv6Policy]
                    } else {
                        &[]
                    },
                );
            }
        }
    }
}

#[test]
fn header_unsent_replies_do_not_count_local_conditions() {
    for auth in [false, true] {
        for ipv6 in [false, true] {
            let raw = request(247, 20, 0);
            let counters = Arc::new(ReflectorCounters::new());
            for gate in 0..6 {
                let mut tx =
                    reflect_captured(&raw, auth, ipv6, false, false, None, |_| {}).unwrap();
                assert!(!tx.response.tlv_conformance.is_empty());
                let limiter = RateLimiter::with_burst(1, 1);
                match gate {
                    0 => tx.response.return_path_action = ReturnPathAction::SuppressReply,
                    1 => {
                        let budget = ReplyBudget::new(1, Arc::clone(&counters));
                        drop(budget.reserve().unwrap().attach(tx));
                        continue;
                    }
                    2 => {
                        let manager = crate::session::SessionManager::new(None, None);
                        tx.session = manager.get_or_create_session(tx.source).unwrap();
                        assert!(manager.expire_matching(tx.source, None).unwrap());
                    }
                    3 => {
                        tx.first = false;
                        assert!(limiter.allow(tx.source.ip()));
                    }
                    _ => {}
                }
                assert!(tx
                    .send_next(&counters, &limiter, |b, _, _| match gate {
                        4 => Err(io::ErrorKind::WouldBlock.into()),
                        5 => Ok(b.len() - 1),
                        _ => panic!("unsent gate {gate}"),
                    })
                    .is_none());
            }
            assert_counts(&counters, &[]);
        }
    }
}

#[test]
fn administrative_header_trimming_reserves_only_a_new_hmac_and_keeps_framing() {
    for auth in [false, true] {
        for ipv6 in [false, true] {
            for keyed in [false, true] {
                if auth && !keyed {
                    continue;
                }
                for request_hmac in [false, true] {
                    // Verified authenticated extensions require an incoming
                    // HMAC. Open keyed requests also support generating a new one.
                    if (request_hmac && !keyed) || (auth && !request_hmac) {
                        continue;
                    }
                    let key = HmacKey::new(vec![0x42; 16]).unwrap();
                    let captured = captures();
                    let base_size = if auth {
                        AUTH_BASE_SIZE
                    } else {
                        UNAUTH_BASE_SIZE
                    };
                    let mut base = vec![0; base_size];
                    base[..4].copy_from_slice(&1u32.to_be_bytes());
                    if auth {
                        let mac = crate::crypto::compute_packet_hmac(&key, &base, 96);
                        base[96..112].copy_from_slice(&mac);
                    }
                    let raw = chain(&[request(247, 20, 0), request(246, 8, 0)]);
                    let mut list = TlvList::parse(&raw).unwrap();
                    if request_hmac {
                        list.set_hmac(&key, &base[..4]);
                    }
                    base.extend(list.to_bytes());
                    let mut ctx = super::super::tests::test_ctx(0, 0);
                    ctx.hmac_key = keyed.then_some(&key);
                    ctx.require_hmac = auth;
                    ctx.verify_tlv_hmac = true;
                    ctx.captured_headers = Some(&captured);
                    let cap = base_size + 24 + if keyed { 20 } else { 0 };
                    ctx.reflected_control_max_size = cap as u16;
                    let response = super::super::process_stamp_packet(
                        &base,
                        if ipv6 { "[::1]:4000" } else { "127.0.0.1:4000" }
                            .parse()
                            .unwrap(),
                        64,
                        auth,
                        &ctx,
                    )
                    .unwrap();
                    assert_eq!(response.data.len(), cap);
                    assert!(response.tlv_conformance.is_empty());
                    let list = TlvList::parse(&response.data[base_size..]).unwrap();
                    let fixed = list
                        .iter()
                        .find(|t| t.tlv_type == TlvType::ReflectedFixedHdr)
                        .unwrap();
                    assert_eq!(fixed.value[0], 0x45);
                    assert!(!fixed.flags.conformant_reflected);
                    assert!(!list
                        .iter()
                        .any(|t| t.tlv_type == TlvType::ReflectedIpv6ExtHdr));
                    if keyed {
                        list.verify_hmac(&key, &response.data[..4], &response.data[base_size..])
                            .unwrap();
                    }
                }
            }
        }
    }
}
