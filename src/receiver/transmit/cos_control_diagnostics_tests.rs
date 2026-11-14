use super::diagnostics_tests::{chain, reflect_configured, tlv};
use super::*;
use crate::tlv::{TlvConformanceReason as Reason, TlvList};

fn control(children: &[Vec<u8>], count: u16) -> Vec<u8> {
    let mut value = vec![0, 0];
    value.extend(count.to_be_bytes());
    value.extend(1000u32.to_be_bytes());
    value.extend(children.concat());
    if children.is_empty() {
        value.extend([0; 4]);
    }
    tlv(12, &value)
}

fn reflect(raw: &[u8], auth: bool, ipv6: bool) -> Transmission {
    let mut tx = reflect_configured(raw, auth, ipv6, false, false, |ctx| {
        ctx.reflected_control_max_count = 16;
        ctx.reflected_control_max_size = 4096;
        ctx.reflected_control_min_interval_ns = 0;
        ctx.reflected_control_max_rate = u64::MAX;
        ctx.reflected_control_max_volume = u32::MAX;
        ctx.received_dscp = 10;
        ctx.received_ecn = 3;
    })
    .unwrap();
    tx.received_dscp = 10;
    tx
}

fn verified(bytes: &[u8], auth: bool) -> TlvList {
    let base = if auth {
        AUTH_BASE_SIZE
    } else {
        UNAUTH_BASE_SIZE
    };
    let list = TlvList::parse(&bytes[base..]).unwrap();
    let key = HmacKey::new(vec![0x42; 16]).unwrap();
    list.verify_hmac(&key, &bytes[..4], &bytes[base..]).unwrap();
    if auth {
        assert_eq!(
            &bytes[96..112],
            &crate::crypto::compute_packet_hmac(&key, bytes, 96)
        );
    }
    list
}

fn assert_counts(counters: &ReflectorCounters, expected: &[Reason], copies: u64) {
    for reason in Reason::ALL {
        assert_eq!(
            counters.tlv_conformance_count(reason),
            if expected.contains(&reason) {
                copies
            } else {
                0
            },
            "{reason:?}"
        );
    }
}

#[test]
fn nested_control_reasons_count_only_generated_c_and_distinguish_duplicates() {
    for auth in [false, true] {
        for ipv6 in [false, true] {
            for (children, expected_c, expected) in [
                (vec![], 0, vec![]),
                (vec![tlv(240, &[])], 1, vec![Reason::ReplyHeaderUnsupported]),
                (
                    vec![tlv(240, &[]), tlv(240, &[])],
                    2,
                    vec![Reason::ReplyHeaderUnsupported, Reason::ReplyHeaderDuplicate],
                ),
                (vec![tlv(240, &[0])], 0, vec![]),
                (
                    vec![tlv(240, &[0]), tlv(240, &[])],
                    1,
                    vec![Reason::ReplyHeaderUnsupported, Reason::ReplyHeaderDuplicate],
                ),
                // Preserve peer provenance without inventing a local failure.
                (
                    vec![vec![TlvFlags::C, 239, 0, 0]],
                    0,
                    vec![Reason::PeerCPreserved],
                ),
                (vec![vec![0x80, 240, 0, 4, 0]], 0, vec![]),
            ] {
                let raw = control(&children, 1);
                let mut tx = reflect(&raw, auth, ipv6);
                assert_eq!(
                    tx.response.tlv_conformance.iter().collect::<Vec<_>>(),
                    expected
                );
                let counters = ReflectorCounters::new();
                tx.send_next(&counters, &RateLimiter::new(0), |bytes, _, _| {
                    let list = verified(bytes, auth);
                    let parent = list
                        .iter()
                        .find(|t| t.tlv_type == TlvType::ReflectedControl)
                        .unwrap();
                    assert!(!parent.flags.conformant_reflected);
                    let mut pos = 8;
                    let mut count = 0;
                    while let Some(sub) = TlvSpan::at(&parent.value, pos) {
                        if sub.tlv_type.to_byte() == 240 {
                            count += usize::from(sub.flags.conformant_reflected);
                            assert_eq!(sub.flags.malformed, sub.len != 0);
                        }
                        pos = sub.end();
                    }
                    assert_eq!(count, expected_c);
                    Ok(bytes.len())
                })
                .unwrap();
                assert_counts(&counters, &expected, 1);
            }
        }
    }
}

#[test]
fn nested_control_reports_follow_actual_mutations_across_parents_and_later_u() {
    for auth in [false, true] {
        for ipv6 in [false, true] {
            // The existing setter visits all processable Type 12 parents once
            // the first request contains a control. Count actual child Cs in
            // later parents too, without changing their wire handling.
            let raw = chain(&[
                control(&[tlv(240, &[])], 1),
                control(&[tlv(240, &[]), tlv(240, &[])], 1),
            ]);
            let mut tx = reflect(&raw, auth, ipv6);
            let counters = ReflectorCounters::new();
            tx.send_next(&counters, &RateLimiter::new(0), |bytes, _, _| {
                let list = verified(bytes, auth);
                assert_eq!(
                    list.iter()
                        .filter(|t| t.tlv_type == TlvType::ReflectedControl)
                        .count(),
                    2
                );
                Ok(bytes.len())
            })
            .unwrap();
            assert_counts(
                &counters,
                &[Reason::ReplyHeaderUnsupported, Reason::ReplyHeaderDuplicate],
                1,
            );
            // A later Type 12 parent does not start control processing itself.
            let raw = chain(&[control(&[], 1), control(&[tlv(240, &[])], 1)]);
            let mut tx = reflect(&raw, auth, ipv6);
            let counters = ReflectorCounters::new();
            tx.send_next(&counters, &RateLimiter::new(0), |b, _, _| Ok(b.len()))
                .unwrap();
            assert_counts(&counters, &[], 0);
            for replay in [false, true] {
                let raw = control(&[tlv(240, &[])], 1);
                let mut tx = reflect_configured(&raw, auth, ipv6, false, false, |ctx| {
                    if replay {
                        ctx.replay_verdict = crate::session::ReplayVerdict::Replay;
                    } else {
                        ctx.reflected_control_max_count = 0;
                    }
                })
                .unwrap();
                let counters = ReflectorCounters::new();
                tx.send_next(&counters, &RateLimiter::new(0), |bytes, _, _| {
                    let list = verified(bytes, auth);
                    let parent = list
                        .iter()
                        .find(|t| t.tlv_type == TlvType::ReflectedControl)
                        .unwrap();
                    assert!(parent.flags.unrecognized);
                    assert_ne!(parent.value[8] & TlvFlags::C, 0);
                    Ok(bytes.len())
                })
                .unwrap();
                assert_counts(&counters, &[Reason::ReplyHeaderUnsupported], 1);
            }
        }
    }
}

#[test]
fn cos_reason_requires_actual_marking_c_and_a_complete_successful_send() {
    for auth in [false, true] {
        for ipv6 in [false, true] {
            for failures in 0..=2 {
                for successful in [false, true] {
                    let mut tx = reflect(&tlv(4, &[186, 0, 0, 0]), auth, ipv6);
                    let counters = ReflectorCounters::new();
                    let mut attempts = 0;
                    let result =
                        tx.send_next(&counters, &RateLimiter::new(0), |bytes, _, options| {
                            attempts += 1;
                            if attempts <= failures {
                                return Err(cos_apply_error(
                                    io::ErrorKind::PermissionDenied.into(),
                                ));
                            }
                            let list = verified(bytes, auth);
                            let cos = list
                                .iter()
                                .find(|t| t.tlv_type == TlvType::ClassOfService)
                                .unwrap();
                            assert_eq!(cos.flags.conformant_reflected, failures == 2);
                            assert_eq!(options.apply_tos, failures != 2);
                            if failures > 0 {
                                assert_eq!(cos.value[1] & 3, 1);
                                assert_eq!((cos.value[2] >> 4) & 3, 2);
                                assert_eq!(options.tos, 40);
                            }
                            if successful {
                                Ok(bytes.len())
                            } else {
                                Ok(bytes.len() - 1)
                            }
                        });
                    assert_eq!(result.is_some(), successful);
                    assert_eq!(attempts, failures + 1);
                    assert_counts(
                        &counters,
                        if failures == 2 && successful {
                            &[Reason::CosMarkingUnavailable]
                        } else {
                            &[]
                        },
                        1,
                    );
                }
            }
        }
    }
}

#[test]
fn cos_diagnostics_do_not_classify_datagram_failures_absent_or_opaque_tlvs() {
    for auth in [false, true] {
        for ipv6 in [false, true] {
            let counters = ReflectorCounters::new();
            for kind in [
                io::ErrorKind::Unsupported,
                io::ErrorKind::PermissionDenied,
                io::ErrorKind::WouldBlock,
            ] {
                let mut tx = reflect(&tlv(4, &[186, 0, 0, 0]), auth, ipv6);
                assert!(tx
                    .send_next(&counters, &RateLimiter::new(0), |_, _, _| Err(kind.into()))
                    .is_none());
            }
            for raw in [tlv(239, &[]), tlv(4, &[0; 3])] {
                let mut tx = reflect(&raw, auth, ipv6);
                // Even a transport asking to apply TOS cannot manufacture a
                // CoS diagnostic without a processable CoS TLV to mark.
                tx.response.cos_request = Some((46, 2));
                tx.send_next(&counters, &RateLimiter::new(0), |bytes, _, options| {
                    if options.apply_tos {
                        Err(cos_apply_error(io::ErrorKind::Unsupported.into()))
                    } else {
                        Ok(bytes.len())
                    }
                })
                .unwrap();
            }
            for flags in [TlvFlags::U, TlvFlags::M, TlvFlags::I] {
                let mut tx = reflect(&tlv(4, &[186, 0, 0, 0]), auth, ipv6);
                let base = if auth {
                    AUTH_BASE_SIZE
                } else {
                    UNAUTH_BASE_SIZE
                };
                tx.response.data[base] = flags;
                tx.send_next(&counters, &RateLimiter::new(0), |bytes, _, options| {
                    if options.apply_tos {
                        Err(cos_apply_error(io::ErrorKind::Unsupported.into()))
                    } else {
                        assert_eq!(bytes[base], flags);
                        Ok(bytes.len())
                    }
                })
                .unwrap();
            }
            assert_counts(&counters, &[], 0);
        }
    }
}

#[test]
fn cos_reason_survives_mtu_and_routing_retries_but_failed_sends_do_not_count() {
    for auth in [false, true] {
        for ipv6 in [false, true] {
            for successful in [false, true] {
                let mut tx = reflect(&tlv(4, &[186, 0, 0, 0]), auth, ipv6);
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
                tx.plan.as_mut().unwrap().options.egress_ifindex = Some(7);
                let counters = ReflectorCounters::new();
                let mut attempts = 0;
                let mut refreshed = false;
                let result = tx.send_next_with_mtu(
                    &counters,
                    &RateLimiter::new(0),
                    |_, _, refresh| {
                        refreshed |= refresh;
                        Ok(4096)
                    },
                    |bytes, _, options| {
                        attempts += 1;
                        let list = verified(bytes, auth);
                        let cos = list
                            .iter()
                            .find(|t| t.tlv_type == TlvType::ClassOfService)
                            .unwrap();
                        assert_eq!(cos.flags.conformant_reflected, attempts >= 3);
                        assert_counts(&counters, &[], 0);
                        match attempts {
                            1 | 2 => Err(cos_apply_error(io::ErrorKind::Unsupported.into())),
                            3 => Err(message_too_large_error()),
                            4 => {
                                assert!(!options.apply_tos);
                                Err(io::ErrorKind::NetworkUnreachable.into())
                            }
                            5 => {
                                assert!(options.egress_ifindex.is_none());
                                if successful {
                                    Ok(bytes.len())
                                } else {
                                    Err(io::ErrorKind::WouldBlock.into())
                                }
                            }
                            _ => panic!("unbounded retry"),
                        }
                    },
                );
                assert!(refreshed);
                assert_eq!(attempts, 5);
                assert_eq!(result.is_some(), successful);
                assert_counts(
                    &counters,
                    if successful {
                        &[Reason::CosMarkingUnavailable]
                    } else {
                        &[]
                    },
                    1,
                );
            }
        }
    }
}

#[test]
fn simultaneous_cos_nested_header_and_ber_reasons_count_each_successful_copy() {
    for auth in [false, true] {
        for ipv6 in [false, true] {
            let raw = chain(&[
                control(&[tlv(240, &[]), tlv(240, &[])], 3),
                tlv(4, &[186, 0, 0, 0]),
                tlv(247, &[0; 20]),
                tlv(243, &[0; 8]),
            ]);
            let mut tx = reflect(&raw, auth, ipv6);
            let counters = ReflectorCounters::new();
            let mut attempts = 0;
            for copies in 1..=3 {
                tx.send_next(&counters, &RateLimiter::new(0), |bytes, _, options| {
                    attempts += 1;
                    if options.apply_tos {
                        return Err(cos_apply_error(io::ErrorKind::Unsupported.into()));
                    }
                    let list = verified(bytes, auth);
                    assert!(
                        list.iter()
                            .find(|t| t.tlv_type == TlvType::ClassOfService)
                            .unwrap()
                            .flags
                            .conformant_reflected
                    );
                    Ok(bytes.len())
                })
                .unwrap();
                assert_counts(
                    &counters,
                    &[
                        Reason::HeaderCaptureUnavailable,
                        Reason::CosMarkingUnavailable,
                        Reason::ReplyHeaderUnsupported,
                        Reason::ReplyHeaderDuplicate,
                    ],
                    copies,
                );
                for reason in crate::ber::BerConformanceReason::ALL {
                    assert_eq!(
                        counters.ber_conformance_count(reason),
                        if reason == crate::ber::BerConformanceReason::MissingPadding {
                            copies
                        } else {
                            0
                        }
                    );
                }
            }
            assert_eq!(attempts, 9);
        }
    }
}

#[test]
fn nested_unsent_and_integrity_failed_observations_add_no_diagnostic() {
    for auth in [false, true] {
        for ipv6 in [false, true] {
            let raw = control(&[tlv(240, &[]), tlv(240, &[])], 1);
            let counters = Arc::new(ReflectorCounters::new());
            for gate in 0..6 {
                let mut tx = reflect(&raw, auth, ipv6);
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
            let mut tx = reflect_configured(&raw, auth, ipv6, true, false, |_| {}).unwrap();
            assert!(tx.response.tlv_conformance.is_empty());
            tx.send_next(&counters, &RateLimiter::new(0), |b, _, _| Ok(b.len()))
                .unwrap();
            if auth {
                assert!(reflect_configured(&raw, auth, ipv6, false, true, |_| {}).is_none());
            }
            assert_counts(&counters, &[], 0);
        }
    }
}

#[test]
fn structural_short_ber_c_is_counted_even_when_hmac_later_fails() {
    use crate::ber::BerConformanceReason as Ber;
    for auth in [false, true] {
        for ipv6 in [false, true] {
            for len in [7, 8] {
                for bad_hmac in [false, true] {
                    for successful in [false, true] {
                        let raw = tlv(243, &vec![0; len]);
                        let mut tx =
                            reflect_configured(&raw, auth, ipv6, bad_hmac, false, |_| {}).unwrap();
                        let original_digest =
                            tx.response.data[tx.response.data.len() - 16..].to_vec();
                        let expected = if len == 7 {
                            Some(Ber::ShortBerValue)
                        } else if !bad_hmac {
                            Some(Ber::MissingPadding)
                        } else {
                            None
                        };
                        assert_eq!(
                            tx.response.ber_conformance.iter().collect::<Vec<_>>(),
                            expected.into_iter().collect::<Vec<_>>()
                        );
                        let counters = ReflectorCounters::new();
                        let result =
                            tx.send_next(&counters, &RateLimiter::new(0), |bytes, _, _| {
                                let base = if auth {
                                    AUTH_BASE_SIZE
                                } else {
                                    UNAUTH_BASE_SIZE
                                };
                                let list = TlvList::parse(&bytes[base..]).unwrap();
                                let ber = list
                                    .iter()
                                    .find(|t| t.tlv_type == TlvType::ResidualBer)
                                    .unwrap();
                                assert_eq!(ber.flags.conformant_reflected, expected.is_some());
                                assert_eq!(ber.flags.integrity_failed, bad_hmac);
                                assert_eq!(ber.value, vec![0; len]);
                                if bad_hmac {
                                    assert_eq!(&bytes[bytes.len() - 16..], original_digest);
                                } else {
                                    verified(bytes, auth);
                                }
                                if successful {
                                    Ok(bytes.len())
                                } else {
                                    Err(io::ErrorKind::WouldBlock.into())
                                }
                            });
                        assert_eq!(result.is_some(), successful);
                        for reason in Ber::ALL {
                            assert_eq!(
                                counters.ber_conformance_count(reason),
                                u64::from(successful && expected == Some(reason))
                            );
                        }
                        assert_counts(&counters, &[], 0);
                    }
                }
            }
        }
    }
}
