use super::diagnostics_tests::{chain, reflect_configured, tlv};
use super::*;
use crate::tlv::{TlvConformanceReason as Reason, TlvList};

fn control(size: u16, count: u16, interval: u32) -> Vec<u8> {
    let mut value = Vec::new();
    value.extend(size.to_be_bytes());
    value.extend(count.to_be_bytes());
    value.extend(interval.to_be_bytes());
    value.extend([0; 4]);
    tlv(12, &value)
}

fn reflect(
    raw: &[u8],
    auth: bool,
    ipv6: bool,
    configure: impl FnOnce(&mut super::super::ProcessingContext<'_>),
) -> Option<Transmission> {
    reflect_configured(raw, auth, ipv6, false, false, |ctx| {
        ctx.reflected_control_max_count = 16;
        ctx.reflected_control_max_size = 4096;
        ctx.reflected_control_min_interval_ns = 0;
        ctx.reflected_control_max_rate = u64::MAX;
        ctx.reflected_control_max_volume = u32::MAX;
        configure(ctx);
    })
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

fn assert_signed_control(bytes: &[u8], auth: bool, expected_c: bool) {
    let base = if auth {
        AUTH_BASE_SIZE
    } else {
        UNAUTH_BASE_SIZE
    };
    let list = TlvList::parse(&bytes[base..]).unwrap();
    let control = list
        .iter()
        .find(|t| t.tlv_type == TlvType::ReflectedControl)
        .unwrap();
    assert!(control.is_processable());
    assert_eq!(control.flags.conformant_reflected, expected_c);
    let key = HmacKey::new(vec![0x42; 16]).unwrap();
    list.verify_hmac(&key, &bytes[..4], &bytes[base..]).unwrap();
    if auth {
        let mac = crate::crypto::compute_packet_hmac(&key, bytes, 96);
        assert_eq!(&bytes[96..112], &mac);
    }
}

#[test]
fn type12_semantic_reasons_match_signed_c_flags_and_successful_sends() {
    for auth in [false, true] {
        for ipv6 in [false, true] {
            for reason in [
                Reason::Type12CountLimit,
                Reason::Type12IntervalLimit,
                Reason::Type12SizeLimit,
                Reason::Type12RateLimit,
                Reason::Type12VolumeLimit,
                Reason::Type12PaddingUnencodable,
            ] {
                let count = if matches!(
                    reason,
                    Reason::Type12CountLimit
                        | Reason::Type12IntervalLimit
                        | Reason::Type12RateLimit
                ) {
                    2
                } else {
                    1
                };
                let raw = if reason == Reason::Type12PaddingUnencodable {
                    // Base + control + HMAC + odd unknown TLV leaves a
                    // three-byte gap, too short for a padding TLV header.
                    chain(&[
                        control(if auth { 156 } else { 88 }, count, 1000),
                        tlv(239, &[0]),
                    ])
                } else {
                    control(200, count, 1000)
                };
                let mut tx = reflect(&raw, auth, ipv6, |ctx| match reason {
                    Reason::Type12CountLimit => ctx.reflected_control_max_count = 1,
                    Reason::Type12IntervalLimit => ctx.reflected_control_min_interval_ns = 1001,
                    Reason::Type12SizeLimit => ctx.reflected_control_max_size = 180,
                    Reason::Type12RateLimit => ctx.reflected_control_max_rate = 199_999_999,
                    Reason::Type12VolumeLimit => ctx.reflected_control_max_volume = 199,
                    _ => {}
                })
                .unwrap();
                assert_eq!(
                    tx.response.tlv_conformance.iter().collect::<Vec<_>>(),
                    vec![reason]
                );
                let counters = ReflectorCounters::new();
                assert_counts(&counters, &[]);
                tx.send_next(&counters, &RateLimiter::new(0), |bytes, _, _| {
                    assert_signed_control(bytes, auth, true);
                    Ok(bytes.len())
                })
                .unwrap();
                assert_counts(&counters, &[reason]);
                assert_eq!(tx.remaining, 0);
            }
        }
    }
}

#[test]
fn type12_clean_bursts_and_unprocessed_requests_have_no_c_diagnostics() {
    for auth in [false, true] {
        for ipv6 in [false, true] {
            let raw = control(200, 3, 1000);
            let counters = ReflectorCounters::new();
            let mut tx = reflect(&raw, auth, ipv6, |_| {}).unwrap();
            for _ in 0..3 {
                tx.send_next(&counters, &RateLimiter::new(0), |bytes, _, _| {
                    assert_signed_control(bytes, auth, false);
                    Ok(bytes.len())
                })
                .unwrap();
            }
            assert_eq!(counters.packets_reflected.load(Ordering::Relaxed), 3);
            assert_counts(&counters, &[]);
            for mode in 0..4 {
                let mut raw = control(200, 3, 0);
                if mode == 2 {
                    raw[0] |= TlvFlags::C;
                }
                let mut tx = reflect(&raw, auth, ipv6, |ctx| match mode {
                    0 => ctx.reflected_control_max_count = 0,
                    1 => ctx.tlv_mode = crate::configuration::TlvHandlingMode::Ignore,
                    2 => ctx.tlv_mode = crate::configuration::TlvHandlingMode::Ignore,
                    _ => ctx.replay_verdict = crate::session::ReplayVerdict::Replay,
                })
                .unwrap();
                assert!(tx.response.tlv_conformance.is_empty());
                tx.send_next(&counters, &RateLimiter::new(0), |b, _, _| Ok(b.len()))
                    .unwrap();
                assert_counts(&counters, &[]);
            }
            let mut suppressed = reflect(&control(200, 0, 0), auth, ipv6, |_| {}).unwrap();
            assert!(suppressed.response.tlv_conformance.is_empty());
            assert!(suppressed
                .send_next(&counters, &RateLimiter::new(0), |_, _, _| panic!(
                    "count zero"
                ))
                .is_none());
            assert_counts(&counters, &[]);
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
fn type12_send_time_clamps_distinguish_route_admin_and_tied_limits() {
    for auth in [false, true] {
        for ipv6 in [false, true] {
            for (route, admin, expected) in [
                (180, 4096, vec![Reason::Type12RouteMtu]),
                (4096, 180, vec![Reason::Type12SizeLimit]),
                (
                    180,
                    180,
                    vec![Reason::Type12SizeLimit, Reason::Type12RouteMtu],
                ),
            ] {
                let mut tx = reflect(&control(400, 1, 1000), auth, ipv6, |_| {}).unwrap();
                // A cap can be tightened after assembly; exercise fitting
                // independently of the semantic size-limit classification.
                tx.response.reflected_control.as_mut().unwrap().max_size = admin;
                force_route_budget(&mut tx, auth);
                let counters = ReflectorCounters::new();
                tx.send_next_with_mtu(
                    &counters,
                    &RateLimiter::new(0),
                    |_, _, _| Ok(route),
                    |bytes, _, _| {
                        assert_eq!(bytes.len(), 180);
                        assert_signed_control(bytes, auth, true);
                        Ok(bytes.len())
                    },
                )
                .unwrap();
                assert_counts(&counters, &expected);
            }
        }
    }
}

#[test]
fn type12_mtu_retry_discards_only_failed_attempt_reasons() {
    for auth in [false, true] {
        for ipv6 in [false, true] {
            let mut tx = reflect(&control(400, 2, 1000), auth, ipv6, |ctx| {
                ctx.reflected_control_max_count = 1
            })
            .unwrap();
            force_route_budget(&mut tx, auth);
            let counters = ReflectorCounters::new();
            let mut sends = 0;
            tx.send_next_with_mtu(
                &counters,
                &RateLimiter::new(0),
                |_, _, refresh| Ok(if refresh { 500 } else { 180 }),
                |bytes, _, _| {
                    sends += 1;
                    assert_signed_control(bytes, auth, true);
                    if sends == 1 {
                        Err(message_too_large_error())
                    } else {
                        assert_eq!(bytes.len(), 400);
                        Ok(bytes.len())
                    }
                },
            )
            .unwrap();
            assert_eq!(sends, 2);
            assert_counts(&counters, &[Reason::Type12CountLimit]);
        }
    }
}

#[test]
fn type12_unsent_diagnostics_do_not_count() {
    for auth in [false, true] {
        for ipv6 in [false, true] {
            let raw = control(400, 2, 0);
            let counters = Arc::new(ReflectorCounters::new());
            for gate in 0..6 {
                let mut tx =
                    reflect(&raw, auth, ipv6, |ctx| ctx.reflected_control_max_count = 1).unwrap();
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
                    .send_next(&counters, &limiter, |bytes, _, _| match gate {
                        4 => Err(io::ErrorKind::WouldBlock.into()),
                        5 => Ok(bytes.len() - 1),
                        _ => panic!("unsent gate {gate}"),
                    })
                    .is_none());
            }
            assert_counts(&counters, &[]);
            let mut tx = reflect_configured(&raw, auth, ipv6, true, false, |_| {}).unwrap();
            assert!(tx.response.tlv_conformance.is_empty());
            tx.send_next(&counters, &RateLimiter::new(0), |b, _, _| Ok(b.len()))
                .unwrap();
            assert_counts(&counters, &[]);
        }
    }
}

#[test]
fn type12_simultaneous_limits_count_once_and_remain_independent_of_ber() {
    for auth in [false, true] {
        for ipv6 in [false, true] {
            let raw = chain(&[control(400, 3, 0), tlv(243, &[0; 8])]);
            let mut tx = reflect(&raw, auth, ipv6, |ctx| {
                ctx.reflected_control_max_count = 1;
                ctx.reflected_control_min_interval_ns = 1001;
                ctx.reflected_control_max_size = 180;
                ctx.reflected_control_max_rate = 1;
                ctx.reflected_control_max_volume = 1;
            })
            .unwrap();
            let expected = [
                Reason::Type12CountLimit,
                Reason::Type12IntervalLimit,
                Reason::Type12SizeLimit,
                Reason::Type12RateLimit,
                Reason::Type12VolumeLimit,
            ];
            assert_eq!(
                tx.response.tlv_conformance.iter().collect::<Vec<_>>(),
                expected
            );
            let ber = tx.response.ber_conformance;
            assert!(ber.contains(crate::ber::BerConformanceReason::MissingPadding));
            let counters = ReflectorCounters::new();
            tx.send_next(&counters, &RateLimiter::new(0), |bytes, _, _| {
                assert_signed_control(bytes, auth, true);
                Ok(bytes.len())
            })
            .unwrap();
            for reason in Reason::ALL {
                assert_eq!(
                    counters.tlv_conformance_count(reason),
                    u64::from(expected.contains(&reason))
                );
            }
            for reason in crate::ber::BerConformanceReason::ALL {
                assert_eq!(
                    counters.ber_conformance_count(reason),
                    u64::from(ber.contains(reason))
                );
            }
        }
    }
}
