use super::diagnostics_tests::{chain, reflect_configured, tlv};
use super::*;
use crate::tlv::{TlvConformanceReason as Reason, TlvList};

fn child(flags: u8, kind: u8, value: &[u8]) -> Vec<u8> {
    let mut bytes = tlv(kind, value);
    bytes[0] = flags;
    bytes
}

fn container(kind: u8, children: &[u8], count: u16) -> Vec<u8> {
    let mut value = match kind {
        2 | 3 => vec![0; 4],
        10 => vec![],
        12 => {
            let mut fixed = vec![0, 0];
            fixed.extend(count.to_be_bytes());
            fixed.extend(1000u32.to_be_bytes());
            fixed
        }
        243 => vec![0; 8],
        _ => panic!("unknown layout"),
    };
    value.extend(children);
    tlv(kind, &value)
}

fn reflect(
    raw: &[u8],
    auth: bool,
    ipv6: bool,
    bad_mac: bool,
    configure: impl FnOnce(&mut super::super::ProcessingContext<'_>),
) -> Transmission {
    reflect_configured(raw, auth, ipv6, bad_mac, false, |ctx| {
        ctx.reflected_control_max_count = 16;
        ctx.reflected_control_max_size = 4096;
        ctx.reflected_control_min_interval_ns = 0;
        ctx.reflected_control_max_rate = u64::MAX;
        ctx.reflected_control_max_volume = u32::MAX;
        configure(ctx);
    })
    .unwrap()
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

fn verify(bytes: &[u8], auth: bool) -> TlvList {
    let base = if auth {
        AUTH_BASE_SIZE
    } else {
        UNAUTH_BASE_SIZE
    };
    let key = HmacKey::new(vec![0x42; 16]).unwrap();
    let list = TlvList::parse(&bytes[base..]).unwrap();
    list.verify_hmac(&key, &bytes[..4], &bytes[base..]).unwrap();
    if auth {
        assert_eq!(
            &bytes[96..112],
            &crate::crypto::compute_packet_hmac(&key, bytes, 96)
        );
    }
    list
}

#[test]
fn preserved_peer_c_uses_known_layouts_and_preserves_failed_integrity_values() {
    for auth in [false, true] {
        for ipv6 in [false, true] {
            for kind in [2, 3, 10, 12, 243] {
                for bad_mac in [false, true] {
                    let parent = container(kind, &child(TlvFlags::C, 239, &[1, 2, 3]), 1);
                    let raw = if kind == 243 {
                        chain(&[parent, tlv(1, &[255, 0, 255, 0])])
                    } else {
                        parent
                    };
                    let mut tx = reflect(&raw, auth, ipv6, bad_mac, |_| {});
                    // Return Path and successful BER processing normalize these
                    // child flags. Other paths retain the peer's C.
                    let expected = bad_mac || !matches!(kind, 10 | 243);
                    assert_eq!(
                        tx.response.tlv_conformance.contains(Reason::PeerCPreserved),
                        expected,
                        "kind={kind} auth={auth} bad_mac={bad_mac}"
                    );
                    let original = tx.response.data.clone();
                    let counters = ReflectorCounters::new();
                    tx.send_next(&counters, &RateLimiter::new(0), |bytes, _, _| {
                        let base = if auth {
                            AUTH_BASE_SIZE
                        } else {
                            UNAUTH_BASE_SIZE
                        };
                        if bad_mac {
                            assert_eq!(&bytes[base..], &original[base..]);
                            let list = TlvList::parse(&bytes[base..]).unwrap();
                            let echoed =
                                list.iter().find(|t| t.tlv_type.to_byte() == kind).unwrap();
                            assert!(echoed.flags.integrity_failed);
                            assert!(list
                                .verify_hmac(
                                    &HmacKey::new(vec![0x42; 16]).unwrap(),
                                    &bytes[..4],
                                    &bytes[base..]
                                )
                                .is_err());
                        } else {
                            verify(bytes, auth);
                        }
                        Ok(bytes.len())
                    })
                    .unwrap();
                    assert_counts(
                        &counters,
                        if expected {
                            &[Reason::PeerCPreserved]
                        } else {
                            &[]
                        },
                        1,
                    );
                    assert!(counters.ber_conformance_counts().values().all(|n| *n == 0));
                }
            }
        }
    }
}

#[test]
fn peer_c_observation_stops_at_incomplete_children_and_never_scans_values() {
    for auth in [false, true] {
        for ipv6 in [false, true] {
            for kind in [2, 3, 10, 12, 243] {
                for (children, expected) in [
                    (child(0, 239, &child(TlvFlags::C, 238, &[])), false),
                    (vec![TlvFlags::C, 239, 255, 255, 0, 0], false),
                    (
                        chain(&[child(0, 239, &[]), vec![TlvFlags::C, 238, 0]]),
                        false,
                    ),
                    (
                        chain(&[child(TlvFlags::C, 239, &[]), vec![0, 238, 255, 255]]),
                        true,
                    ),
                ] {
                    let raw = container(kind, &children, 1);
                    let mut tx = reflect(&raw, auth, ipv6, true, |_| {});
                    let counters = ReflectorCounters::new();
                    tx.send_next(&counters, &RateLimiter::new(0), |b, _, _| Ok(b.len()))
                        .unwrap();
                    assert_counts(
                        &counters,
                        if expected {
                            &[Reason::PeerCPreserved]
                        } else {
                            &[]
                        },
                        1,
                    );
                }
            }
            for kind in [1, 239, 247] {
                let raw = tlv(kind, &child(TlvFlags::C, 238, &[]));
                let mut tx = reflect(&raw, auth, ipv6, true, |_| {});
                let counters = ReflectorCounters::new();
                tx.send_next(&counters, &RateLimiter::new(0), |b, _, _| Ok(b.len()))
                    .unwrap();
                assert_counts(&counters, &[], 0);
            }
        }
    }
}

#[test]
fn peer_and_local_child_c_provenance_remain_distinct_across_later_u() {
    for auth in [false, true] {
        for ipv6 in [false, true] {
            for mode in 0..3 {
                // A peer C on a child also marked locally receives the known
                // local reason. The unknown child independently retains peer C.
                let children = chain(&[child(TlvFlags::C, 239, &[]), child(TlvFlags::C, 240, &[])]);
                let raw = container(12, &children, 1);
                let mut tx = reflect(&raw, auth, ipv6, false, |ctx| match mode {
                    1 => ctx.reflected_control_max_count = 0,
                    2 => ctx.replay_verdict = crate::session::ReplayVerdict::Replay,
                    _ => {}
                });
                let counters = ReflectorCounters::new();
                tx.send_next(&counters, &RateLimiter::new(0), |bytes, _, _| {
                    let list = verify(bytes, auth);
                    let parent = list
                        .iter()
                        .find(|t| t.tlv_type == TlvType::ReflectedControl)
                        .unwrap();
                    assert_eq!(parent.flags.unrecognized, mode != 0);
                    Ok(bytes.len())
                })
                .unwrap();
                assert_counts(
                    &counters,
                    &[Reason::ReplyHeaderUnsupported, Reason::PeerCPreserved],
                    1,
                );
            }
            // A later parent after M was not visited by the local C setter.
            let raw = chain(&[
                container(12, &child(0, 240, &[]), 1),
                tlv(4, &[0; 3]),
                container(12, &child(TlvFlags::C, 240, &[]), 1),
            ]);
            let mut tx = reflect(&raw, auth, ipv6, false, |_| {});
            let counters = ReflectorCounters::new();
            tx.send_next(&counters, &RateLimiter::new(0), |bytes, _, _| {
                verify(bytes, auth);
                Ok(bytes.len())
            })
            .unwrap();
            assert_counts(
                &counters,
                &[Reason::ReplyHeaderUnsupported, Reason::PeerCPreserved],
                1,
            );
            // Invalid length gets M and preserves peer C; the valid sibling C
            // is local and also establishes the duplicate-control condition.
            let raw = container(
                12,
                &chain(&[child(TlvFlags::C, 240, &[0]), child(0, 240, &[])]),
                1,
            );
            let mut tx = reflect(&raw, auth, ipv6, false, |_| {});
            let counters = ReflectorCounters::new();
            tx.send_next(&counters, &RateLimiter::new(0), |b, _, _| Ok(b.len()))
                .unwrap();
            assert_counts(
                &counters,
                &[
                    Reason::ReplyHeaderUnsupported,
                    Reason::ReplyHeaderDuplicate,
                    Reason::PeerCPreserved,
                ],
                1,
            );
        }
    }
}

#[test]
fn repeated_peer_c_counts_once_per_successful_burst_copy() {
    for auth in [false, true] {
        for ipv6 in [false, true] {
            let children = child(TlvFlags::C, 239, &[]).repeat(3);
            let raw = container(12, &children, 3);
            let mut tx = reflect(&raw, auth, ipv6, false, |_| {});
            let counters = ReflectorCounters::new();
            for copies in 1..=3 {
                tx.send_next(&counters, &RateLimiter::new(0), |bytes, _, _| {
                    verify(bytes, auth);
                    Ok(bytes.len())
                })
                .unwrap();
                assert_counts(&counters, &[Reason::PeerCPreserved], copies);
            }
            assert_eq!(tx.remaining, 0);
        }
    }
}

#[test]
fn preserved_peer_c_observations_require_successful_sends_and_base_admission() {
    for auth in [false, true] {
        for ipv6 in [false, true] {
            let raw = container(12, &child(TlvFlags::C, 239, &[]), 1);
            let counters = Arc::new(ReflectorCounters::new());
            for bad_mac in [false, true] {
                for gate in 0..6 {
                    let mut tx = reflect(&raw, auth, ipv6, bad_mac, |_| {});
                    assert!(tx.response.tlv_conformance.contains(Reason::PeerCPreserved));
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
            }
            if auth {
                assert!(reflect_configured(&raw, auth, ipv6, false, true, |_| {}).is_none());
            }
            assert_counts(&counters, &[], 0);
        }
    }
}

#[test]
fn legacy_ignore_tail_has_no_tlv_provenance_claim() {
    for auth in [false, true] {
        for ipv6 in [false, true] {
            let mut raw = container(12, &child(TlvFlags::C, 239, &[]), 1);
            raw[0] |= TlvFlags::C;
            let mut tx = reflect(&raw, auth, ipv6, false, |ctx| {
                ctx.tlv_mode = crate::configuration::TlvHandlingMode::Ignore
            });
            assert!(tx.response.tlv_conformance.is_empty());
            let base = if auth {
                AUTH_BASE_SIZE
            } else {
                UNAUTH_BASE_SIZE
            };
            let tail = tx.response.data[base..].to_vec();
            let counters = ReflectorCounters::new();
            tx.send_next(&counters, &RateLimiter::new(0), |bytes, _, _| {
                assert_eq!(&bytes[base..], tail);
                Ok(bytes.len())
            })
            .unwrap();
            assert_counts(&counters, &[], 0);
        }
    }
}
