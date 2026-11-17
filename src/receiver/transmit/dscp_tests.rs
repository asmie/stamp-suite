use super::cos_control_diagnostics_tests::verified;
use super::diagnostics_tests::{reflect_configured, tlv};
use super::*;
use crate::cos_policy::{CosAdmissionPolicy, DscpSet, EcnSet};
use crate::tlv::{PacketAddressInfo, TlvConformanceReason as Reason};

fn reflect(policy: CosAdmissionPolicy, auth: bool, ipv6: bool, peer_c: bool) -> Transmission {
    let policy = Box::leak(Box::new(policy));
    let mut cos = tlv(4, &[184, 0, 128, 0]); // DSCP1=46, EC1=2.
    if peer_c {
        cos[0] |= TlvFlags::C;
    }
    // Three copies. A C flag the peer sent is cleared by incoming-flag
    // normalization, so only a local third-value fallback sets it.
    cos.extend(tlv(12, &[0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 0]));
    let mut tx = reflect_configured(&cos, auth, ipv6, false, false, |ctx| {
        ctx.cos_policy = policy;
        ctx.received_dscp = 10;
        ctx.received_ecn = 3;
        ctx.reflected_control_min_interval_ns = 0;
        ctx.reflected_control_max_size = 4096;
        ctx.reflected_control_max_rate = u64::MAX;
        ctx.reflected_control_max_volume = u32::MAX;
        let ip = if ipv6 { "::1" } else { "127.0.0.1" }.parse().unwrap();
        ctx.packet_addr_info = Some(PacketAddressInfo {
            src_addr: ip,
            src_port: 4000,
            dst_addr: ip,
            dst_port: 862,
            src_mac: None,
        });
    })
    .unwrap();
    tx.received_dscp = 10;
    tx
}

fn policy(values: &str) -> CosAdmissionPolicy {
    CosAdmissionPolicy::new(DscpSet::parse(values).unwrap(), EcnSet::all(), vec![])
}

fn check(bytes: &[u8], auth: bool, rpd: u8, rpe: u8, c: bool) {
    let list = verified(bytes, auth);
    let cos = list
        .iter()
        .find(|t| t.tlv_type == TlvType::ClassOfService)
        .unwrap();
    assert_eq!(cos.flags.conformant_reflected, c);
    // Ingress DSCP2/EC2 and requested DSCP1/EC1 remain observations/requests.
    assert_eq!(cos.value, [184, 0xac | rpd, 0x80 | (rpe << 4), 0]);
}

#[test]
fn dscp_admission_marks_signed_bursts_and_counts_only_successful_third_values() {
    for auth in [false, true] {
        for ipv6 in [false, true] {
            for peer_c in [false, true] {
                for (values, dscp, rpd, third) in [
                    ("all", 46, 0, false),
                    ("10,34", 10, 1, false),
                    ("0,34", 0, 1, true),
                    ("34", 34, 1, true),
                ] {
                    let mut tx = reflect(policy(values), auth, ipv6, peer_c);
                    let counters = ReflectorCounters::new();
                    for copy in 1..=3 {
                        assert!(tx
                            .send_next(&counters, &RateLimiter::new(0), |bytes, _, options| {
                                assert_eq!(options.tos, (dscp << 2) | 2);
                                check(bytes, auth, rpd, 3, third);
                                Ok(bytes.len())
                            })
                            .is_some());
                        assert_eq!(
                            counters.tlv_conformance_count(Reason::CosDscpFallback),
                            if third { copy } else { 0 }
                        );
                    }
                }
                let mut tx = reflect(policy("34"), auth, ipv6, peer_c);
                let counters = ReflectorCounters::new();
                assert!(tx
                    .send_next(&counters, &RateLimiter::new(0), |b, _, _| Ok(b.len() - 1))
                    .is_none());
                assert_eq!(counters.tlv_conformance_count(Reason::CosDscpFallback), 0);
            }
        }
    }
}

#[test]
fn dscp_marking_retry_never_uses_forbidden_received_value_or_unmarked_restricted_send() {
    for auth in [false, true] {
        for ipv6 in [false, true] {
            for (values, first, fallback, rpd, third) in [
                ("all", 46, 10, 1, false),
                ("46", 46, 46, 0, false),
                ("34", 34, 34, 1, true),
                ("10", 10, 10, 1, false),
            ] {
                for fails_twice in [false, true] {
                    let mut tx = reflect(policy(values), auth, ipv6, false);
                    let counters = ReflectorCounters::new();
                    let mut attempts = 0;
                    let sent =
                        tx.send_next(&counters, &RateLimiter::new(0), |bytes, _, options| {
                            attempts += 1;
                            if attempts == 1 {
                                assert_eq!(options.tos, (first << 2) | 2);
                                return Err(cos_apply_error(io::ErrorKind::Unsupported.into()));
                            }
                            assert_eq!(options.tos, fallback << 2);
                            check(bytes, auth, rpd, if attempts == 2 { 2 } else { 1 }, third);
                            if fails_twice && attempts == 2 {
                                return Err(cos_apply_error(io::ErrorKind::Unsupported.into()));
                            }
                            assert_eq!(options.apply_tos, attempts == 2);
                            Ok(bytes.len())
                        });
                    assert_eq!(sent.is_some(), !fails_twice || values == "all");
                    assert_eq!(attempts, if fails_twice && values == "all" { 3 } else { 2 });
                    assert_eq!(
                        counters.tlv_conformance_count(Reason::CosDscpFallback),
                        u64::from(third && !fails_twice)
                    );
                }
            }
        }
    }
}

#[test]
fn dscp_route_retry_reselects_policy_and_sets_c_only_for_a_third_value() {
    for auth in [false, true] {
        for ipv6 in [false, true] {
            for peer_c in [false, true] {
                for (primary, fallback, first_dscp, final_dscp, first_c, final_c) in [
                    ("34", "46", 34, Some(46), true, false),
                    ("46", "34", 46, Some(34), false, true),
                    ("34", "none", 34, None, true, false),
                ] {
                    let mut tx = reflect(policy(primary), auth, ipv6, peer_c);
                    // Install the same immutable snapshot that semantic processing
                    // builds for alternate/SRv6 destinations.
                    tx.response.cos_reply_policy = Some(super::super::CosReplyPolicy::new(
                        46,
                        DscpSet::parse(primary).unwrap(),
                        DscpSet::parse(fallback).unwrap(),
                        2,
                        true,
                    ));
                    let alternate = if ipv6 { "[::2]:4000" } else { "127.0.0.2:4000" }
                        .parse()
                        .unwrap();
                    tx.response.return_path_action = ReturnPathAction::AlternateAddress(alternate);
                    let counters = ReflectorCounters::new();
                    for _ in 0..3 {
                        let mut attempts = 0;
                        let source = tx.source;
                        let sent = tx.send_next(
                            &counters,
                            &RateLimiter::new(0),
                            |bytes, target, options| {
                                attempts += 1;
                                if target == alternate {
                                    assert_eq!(options.tos, (first_dscp << 2) | 2);
                                    check(bytes, auth, u8::from(first_c), 3, first_c);
                                    return Err(io::ErrorKind::NetworkUnreachable.into());
                                }
                                assert_eq!(target, source);
                                let dscp = final_dscp.expect("empty policy must not send");
                                assert_eq!(options.tos, (dscp << 2) | 2);
                                check(bytes, auth, u8::from(final_c), 3, final_c);
                                Ok(bytes.len())
                            },
                        );
                        assert_eq!(sent.is_some(), final_dscp.is_some());
                        assert_eq!(attempts, if final_dscp.is_some() { 2 } else { 1 });
                        if final_dscp.is_none() {
                            break;
                        }
                    }
                    assert_eq!(
                        counters.tlv_conformance_count(Reason::CosDscpFallback),
                        if final_c { 3 } else { 0 }
                    );
                }
            }
        }
    }
}

#[test]
fn empty_dscp_policy_suppresses_processed_cos_without_sending() {
    for auth in [false, true] {
        for ipv6 in [false, true] {
            let mut tx = reflect(policy("none"), auth, ipv6, false);
            assert_eq!(
                tx.response.return_path_action,
                ReturnPathAction::SuppressReply
            );
            assert!(tx
                .send_next(
                    &ReflectorCounters::new(),
                    &RateLimiter::new(0),
                    |_, _, _| panic!("suppressed reply sent")
                )
                .is_none());
        }
    }
}

#[cfg(windows)]
#[test]
fn windows_restricted_dscp_sends_nothing_and_permissive_reply_reports_rpe01() {
    use std::net::UdpSocket;
    for ipv6 in [false, true] {
        let ip = if ipv6 { "::1" } else { "127.0.0.1" };
        let receive = UdpSocket::bind((ip, 0)).unwrap();
        receive
            .set_read_timeout(Some(Duration::from_millis(150)))
            .unwrap();
        let socket = UdpSocket::bind((ip, 0)).unwrap();
        let mut sender = DatagramSender::new(&socket);
        for auth in [false, true] {
            let mut tx = reflect(policy("34"), auth, ipv6, false);
            tx.source = receive.local_addr().unwrap();
            assert!(tx
                .send_next(
                    &ReflectorCounters::new(),
                    &RateLimiter::new(0),
                    |b, dst, opt| sender.send(b, dst, opt)
                )
                .is_none());
            let mut data = [0; 512];
            assert!(receive.recv_from(&mut data).is_err());
            let mut tx = reflect(policy("all"), auth, ipv6, false);
            tx.source = receive.local_addr().unwrap();
            assert!(tx
                .send_next(
                    &ReflectorCounters::new(),
                    &RateLimiter::new(0),
                    |b, dst, opt| sender.send(b, dst, opt)
                )
                .is_some());
            let (len, _) = receive.recv_from(&mut data).unwrap();
            check(&data[..len], auth, 1, 1, false);
        }
    }
}
