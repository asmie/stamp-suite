use super::*;
use crate::ber::{BerConformanceErrors, BerConformanceReason as Reason};
use crate::tlv::TlvList;

pub(super) fn tlv(kind: u8, value: &[u8]) -> Vec<u8> {
    let mut raw = vec![0x80, kind];
    raw.extend_from_slice(&(value.len() as u16).to_be_bytes());
    raw.extend_from_slice(value);
    raw
}

pub(super) fn chain(parts: &[Vec<u8>]) -> Vec<u8> {
    parts.concat()
}

fn cases() -> Vec<(&'static str, Vec<u8>, Vec<Reason>)> {
    let ber = tlv(243, &[0; 8]);
    let pad = tlv(1, &[0xff, 0, 0xff, 0]);
    let mut duplicate_pattern = vec![0; 8];
    duplicate_pattern.extend(tlv(241, &[1, 2, 3, 4]));
    duplicate_pattern.extend(tlv(241, &[1, 2, 3, 4]));
    let mut short_pattern = vec![0; 8];
    short_pattern.extend(tlv(241, &[1, 2, 3]));
    let mut unknown = vec![0; 8];
    unknown.extend(tlv(240, &[0; 4]));
    vec![
        ("missing", ber.clone(), vec![Reason::MissingPadding]),
        (
            "duplicate padding",
            chain(&[ber.clone(), pad.clone(), pad.clone()]),
            vec![Reason::DuplicatePadding],
        ),
        (
            "duplicate BER",
            chain(&[ber.clone(), ber.clone(), pad.clone()]),
            vec![Reason::DuplicateBer],
        ),
        (
            "combined",
            chain(&[ber.clone(), ber.clone()]),
            vec![Reason::MissingPadding, Reason::DuplicateBer],
        ),
        (
            "short value",
            chain(&[tlv(243, &[0; 7]), pad.clone()]),
            vec![Reason::ShortBerValue],
        ),
        (
            "duplicate pattern",
            chain(&[tlv(243, &duplicate_pattern), pad.clone()]),
            vec![Reason::DuplicatePattern],
        ),
        (
            "misaligned",
            chain(&[ber.clone(), tlv(1, &[1, 2, 3])]),
            vec![Reason::PaddingMisaligned],
        ),
        ("clean", chain(&[ber, pad.clone()]), vec![]),
        (
            "unknown nested",
            chain(&[tlv(243, &unknown), pad.clone()]),
            vec![],
        ),
        (
            "nested M only",
            chain(&[tlv(243, &short_pattern), pad]),
            vec![],
        ),
    ]
}

fn reflect(
    raw: &[u8],
    auth: bool,
    ipv6: bool,
    bad_tlv_hmac: bool,
    bad_base_hmac: bool,
) -> Option<Transmission> {
    reflect_configured(raw, auth, ipv6, bad_tlv_hmac, bad_base_hmac, |_| {})
}

pub(super) fn reflect_configured(
    raw: &[u8],
    auth: bool,
    ipv6: bool,
    bad_tlv_hmac: bool,
    bad_base_hmac: bool,
    configure: impl FnOnce(&mut super::super::ProcessingContext<'_>),
) -> Option<Transmission> {
    reflect_captured(
        raw,
        auth,
        ipv6,
        bad_tlv_hmac,
        bad_base_hmac,
        None,
        configure,
    )
}

pub(super) fn reflect_captured(
    raw: &[u8],
    auth: bool,
    ipv6: bool,
    bad_tlv_hmac: bool,
    bad_base_hmac: bool,
    headers: Option<&super::super::CapturedHeaders>,
    configure: impl FnOnce(&mut super::super::ProcessingContext<'_>),
) -> Option<Transmission> {
    let key = HmacKey::new(vec![0x42; 16]).unwrap();
    let mut ctx = super::super::tests::test_ctx(0, 0);
    ctx.hmac_key = Some(&key);
    ctx.require_hmac = auth;
    ctx.verify_tlv_hmac = true;
    ctx.reflected_control_max_count = 16;
    ctx.captured_headers = headers;
    configure(&mut ctx);
    let mut base = vec![
        0;
        if auth {
            AUTH_BASE_SIZE
        } else {
            UNAUTH_BASE_SIZE
        }
    ];
    base[..4].copy_from_slice(&1u32.to_be_bytes());
    let mut tlvs = TlvList::parse(raw).unwrap();
    tlvs.set_hmac(&key, &base[..4]);
    let mut data = tlvs.to_bytes();
    if bad_tlv_hmac {
        *data.last_mut().unwrap() ^= 1;
    }
    if auth {
        let mac = crate::crypto::compute_packet_hmac(&key, &base, crate::packets::AUTH_HMAC_OFFSET);
        base[crate::packets::AUTH_HMAC_OFFSET..].copy_from_slice(&mac);
        if bad_base_hmac {
            base[crate::packets::AUTH_HMAC_OFFSET] ^= 1;
        }
    }
    base.extend(data);
    let src = if ipv6 { "[::1]:4000" } else { "127.0.0.1:4000" }
        .parse()
        .unwrap();
    let response = super::super::process_stamp_packet(&base, src, 64, auth, &ctx)?;
    Some(Transmission::new(
        response,
        Arc::new(Session::new(1)),
        src,
        ClockFormat::NTP,
        auth,
        true,
        Some(key),
        0,
        false,
    ))
}

#[test]
fn ber_reasons_match_reflected_c_flags_in_open_auth_ipv4_ipv6() {
    for auth in [false, true] {
        for ipv6 in [false, true] {
            for (name, raw, expected) in cases() {
                let mut tx = reflect(&raw, auth, ipv6, false, false).unwrap();
                let counters = ReflectorCounters::new();
                let report = tx.response.ber_conformance;
                assert_eq!(report.iter().collect::<Vec<_>>(), expected, "{name}");
                assert!(counters.ber_conformance_counts().values().all(|n| *n == 0));
                tx.send_next(&counters, &RateLimiter::new(0), |bytes, _, _| {
                    let base = if auth {
                        AUTH_BASE_SIZE
                    } else {
                        UNAUTH_BASE_SIZE
                    };
                    let (tlvs, _) = TlvList::parse_lenient(&bytes[base..]);
                    let has_c = tlvs.iter().any(|t| {
                        t.tlv_type == TlvType::ResidualBer && t.flags.conformant_reflected
                    });
                    assert_eq!(has_c, !expected.is_empty(), "{name}");
                    Ok(bytes.len())
                })
                .unwrap();
                for reason in Reason::ALL {
                    assert_eq!(
                        counters.ber_conformance_count(reason),
                        u64::from(expected.contains(&reason)),
                        "{name} {reason:?}"
                    );
                }
            }
        }
    }
}

#[test]
fn failed_suppressed_cancelled_and_integrity_failed_replies_do_not_count() {
    for auth in [false, true] {
        for ipv6 in [false, true] {
            let raw = tlv(243, &[0; 8]);
            let mut tx = reflect(&raw, auth, ipv6, false, false).unwrap();
            let counters = Arc::new(ReflectorCounters::new());
            assert!(tx
                .send_next(&counters, &RateLimiter::new(0), |_, _, _| Err(
                    io::ErrorKind::WouldBlock.into()
                ))
                .is_none());
            let mut tx = reflect(&raw, auth, ipv6, false, false).unwrap();
            tx.response.return_path_action = ReturnPathAction::SuppressReply;
            assert!(tx
                .send_next(&counters, &RateLimiter::new(0), |_, _, _| panic!(
                    "suppressed"
                ))
                .is_none());
            let budget = ReplyBudget::new(1, Arc::clone(&counters));
            drop(
                budget
                    .reserve()
                    .unwrap()
                    .attach(reflect(&raw, auth, ipv6, false, false).unwrap()),
            );
            let mut tx = reflect(&raw, auth, ipv6, true, false).unwrap();
            assert!(tx.response.ber_conformance.is_empty());
            tx.send_next(&counters, &RateLimiter::new(0), |b, _, _| Ok(b.len()))
                .unwrap();
            if auth {
                assert!(reflect(&raw, true, ipv6, false, true).is_none());
            }
            assert!(counters.ber_conformance_counts().values().all(|n| *n == 0));
        }
    }
}

#[test]
fn burst_copies_count_each_reason_once_per_successful_datagram() {
    let raw = chain(&[tlv(243, &[0; 8]), tlv(243, &[0; 8])]);
    let mut tx = reflect(&raw, false, false, false, false).unwrap();
    tx.remaining = 3;
    let counters = ReflectorCounters::new();
    for _ in 0..3 {
        tx.send_next(&counters, &RateLimiter::new(0), |b, _, _| Ok(b.len()))
            .unwrap();
    }
    assert_eq!(counters.ber_conformance_count(Reason::DuplicateBer), 3);
    assert_eq!(counters.ber_conformance_count(Reason::MissingPadding), 3);
    assert_eq!(counters.ber_conformance_counts().values().sum::<u64>(), 6);
}

#[test]
fn mtu_retry_does_not_leak_failed_attempt_diagnostics() {
    for auth in [false, true] {
        for ipv6 in [false, true] {
            let raw = chain(&[tlv(243, &[0; 8]), tlv(1, &[0; 1600])]);
            let mut tx = reflect(&raw, auth, ipv6, false, false).unwrap();
            // Require a route budget on every platform for this fake transport.
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
            let counters = ReflectorCounters::new();
            let mut sends = 0;
            tx.send_next_with_mtu(
                &counters,
                &RateLimiter::new(0),
                |_, _, refresh| Ok(if refresh { 2000 } else { 1400 }),
                |b, _, _| {
                    sends += 1;
                    if sends == 1 {
                        Err(message_too_large_error())
                    } else {
                        Ok(b.len())
                    }
                },
            )
            .unwrap();
            assert_eq!(sends, 2);
            assert_eq!(counters.ber_conformance_count(Reason::PaddingResized), 0);
            let mut tx = reflect(&raw, auth, ipv6, false, false).unwrap();
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
            tx.send_next_with_mtu(
                &counters,
                &RateLimiter::new(0),
                |_, _, _| Ok(1400),
                |b, _, _| Ok(b.len()),
            )
            .unwrap();
            assert_eq!(counters.ber_conformance_count(Reason::PaddingResized), 1);
        }
    }
}

#[test]
fn type12_resize_is_reported_and_opaque_echoes_are_not_classified() {
    for auth in [false, true] {
        for ipv6 in [false, true] {
            let raw = chain(&[
                tlv(243, &[0; 8]),
                tlv(1, &[0; 8]),
                tlv(12, &[0, 200, 0, 1, 0, 0, 3, 232, 0, 0, 0, 0]),
            ]);
            let mut tx = reflect(&raw, auth, ipv6, false, false).unwrap();
            assert!(tx.response.ber_conformance.contains(Reason::PaddingResized));
            let counters = ReflectorCounters::new();
            tx.send_next(&counters, &RateLimiter::new(0), |bytes, _, _| {
                let base = if auth {
                    AUTH_BASE_SIZE
                } else {
                    UNAUTH_BASE_SIZE
                };
                let list = TlvList::parse(&bytes[base..]).unwrap();
                let pad = list
                    .iter()
                    .find(|t| t.tlv_type == TlvType::ExtraPadding)
                    .unwrap();
                assert!(pad.is_processable());
                for (i, b) in pad.value.iter().enumerate() {
                    assert_eq!(*b, [0xff, 0, 0xff, 0][i % 4]);
                }
                assert!(
                    list.iter()
                        .find(|t| t.tlv_type == TlvType::ResidualBer)
                        .unwrap()
                        .flags
                        .conformant_reflected
                );
                list.verify_hmac(
                    &HmacKey::new(vec![0x42; 16]).unwrap(),
                    &bytes[..4],
                    &bytes[base..],
                )
                .unwrap();
                Ok(bytes.len())
            })
            .unwrap();
            assert_eq!(counters.ber_conformance_count(Reason::PaddingResized), 1);
        }
    }
    let mut ctx = super::super::tests::test_ctx(0, 0);
    ctx.tlv_mode = crate::configuration::TlvHandlingMode::Ignore;
    let mut data = vec![0; UNAUTH_BASE_SIZE];
    data.extend_from_slice(&[0x10, 243, 0, 8, 0, 0, 0, 0, 0, 0, 0, 0]);
    let response = super::super::process_stamp_packet(
        &data,
        "127.0.0.1:4000".parse().unwrap(),
        64,
        false,
        &ctx,
    )
    .unwrap();
    assert!(response.ber_conformance.is_empty());
}

thread_local! {
    static LOGS: std::cell::RefCell<Option<Vec<String>>> = const { std::cell::RefCell::new(None) };
}
struct CaptureLogger;
impl log::Log for CaptureLogger {
    fn enabled(&self, _: &log::Metadata<'_>) -> bool {
        true
    }
    fn log(&self, record: &log::Record<'_>) {
        if matches!(
            record.target(),
            "stamp_suite::ber::conformance" | "stamp_suite::tlv::conformance"
        ) {
            LOGS.with(|slot| {
                if let Some(logs) = slot.borrow_mut().as_mut() {
                    logs.push(record.args().to_string());
                }
            });
        }
    }
    fn flush(&self) {}
}

#[test]
fn diagnostics_log_each_reason_independently_without_per_packet_log_floods() {
    static INIT: std::sync::Once = std::sync::Once::new();
    static LOGGER: CaptureLogger = CaptureLogger;
    INIT.call_once(|| {
        log::set_logger(&LOGGER).unwrap();
        log::set_max_level(log::LevelFilter::Warn);
    });
    LOGS.with(|slot| *slot.borrow_mut() = Some(Vec::new()));
    let counters = ReflectorCounters::new();
    let mut report = BerConformanceErrors::default();
    for reason in Reason::ALL {
        report.insert(reason);
    }
    // Deduplicate the same reason and merge without adding a label or allocation.
    report.insert(Reason::MissingPadding);
    report.merge(report);
    for _ in 0..1000 {
        counters.record_ber_conformance(report);
    }
    let logs = LOGS.with(|slot| slot.borrow_mut().take().unwrap());
    assert_eq!(logs.len(), 4 * Reason::ALL.len());
    for reason in Reason::ALL {
        assert_eq!(counters.ber_conformance_count(reason), 1000);
        let expected: Vec<_> = [1, 10, 100, 1000]
            .into_iter()
            .map(|n| {
                format!(
                    "reflected BER C condition: {} ({n} reflected datagrams)",
                    reason.label()
                )
            })
            .collect();
        assert_eq!(
            logs.iter()
                .filter(
                    |s| s.starts_with(&format!("reflected BER C condition: {} (", reason.label()))
                )
                .collect::<Vec<_>>(),
            expected.iter().collect::<Vec<_>>()
        );
    }

    LOGS.with(|slot| *slot.borrow_mut() = Some(Vec::new()));
    let mut report = crate::tlv::TlvConformanceErrors::default();
    for reason in crate::tlv::TlvConformanceReason::ALL {
        report.insert(reason);
        report.insert(reason);
    }
    report.merge(report);
    for _ in 0..1000 {
        counters.record_tlv_conformance(report);
    }
    let logs = LOGS.with(|slot| slot.borrow_mut().take().unwrap());
    assert_eq!(logs.len(), 4 * crate::tlv::TlvConformanceReason::ALL.len());
    for reason in crate::tlv::TlvConformanceReason::ALL {
        assert_eq!(counters.tlv_conformance_count(reason), 1000);
        for n in [1, 10, 100, 1000] {
            assert!(logs.contains(&format!(
                "reflected TLV C condition: {} ({n} reflected datagrams)",
                reason.label()
            )));
        }
    }
}

#[cfg(feature = "metrics")]
#[test]
fn prometheus_uses_only_fixed_reason_labels_and_honors_runtime_disable() {
    let recorder = metrics_exporter_prometheus::PrometheusBuilder::new().build_recorder();
    let handle = recorder.handle();
    metrics::with_local_recorder(&recorder, || {
        let mut counters = ReflectorCounters::new();
        let mut report = BerConformanceErrors::default();
        for reason in Reason::ALL {
            report.insert(reason);
        }
        counters.record_ber_conformance(report);
        assert!(!handle
            .render()
            .contains("stamp_reflector_ber_conformance_total"));
        counters.metrics_enabled = true;
        counters.record_ber_conformance(report);
        let mut tlv_report = crate::tlv::TlvConformanceErrors::default();
        for reason in crate::tlv::TlvConformanceReason::ALL {
            tlv_report.insert(reason);
        }
        counters.metrics_enabled = false;
        counters.record_tlv_conformance(tlv_report);
        assert!(!handle
            .render()
            .contains("stamp_reflector_tlv_conformance_total"));
        counters.metrics_enabled = true;
        counters.record_tlv_conformance(tlv_report);
        let text = handle.render();
        let tlv_rows: Vec<_> = text
            .lines()
            .filter(|l| l.starts_with("stamp_reflector_tlv_conformance_total{"))
            .collect();
        assert_eq!(tlv_rows.len(), crate::tlv::TlvConformanceReason::ALL.len());
        for reason in crate::tlv::TlvConformanceReason::ALL {
            assert!(tlv_rows.contains(
                &format!(
                    "stamp_reflector_tlv_conformance_total{{reason=\"{}\"}} 1",
                    reason.label()
                )
                .as_str()
            ));
        }

        let rows: Vec<_> = text
            .lines()
            .filter(|l| l.starts_with("stamp_reflector_ber_conformance_total{"))
            .collect();
        assert_eq!(rows.len(), Reason::ALL.len());
        for reason in Reason::ALL {
            assert!(rows.contains(
                &format!(
                    "stamp_reflector_ber_conformance_total{{reason=\"{}\"}} 1",
                    reason.label()
                )
                .as_str()
            ));
        }
    });
}

#[test]
fn expired_rate_limited_and_partial_sends_do_not_count_ber_conditions() {
    for auth in [false, true] {
        for ipv6 in [false, true] {
            let raw = tlv(243, &[0; 8]);
            let counters = ReflectorCounters::new();
            let mut tx = reflect(&raw, auth, ipv6, false, false).unwrap();
            assert!(tx
                .send_next(&counters, &RateLimiter::new(0), |b, _, _| Ok(b.len() - 1))
                .is_none());
            let mut tx = reflect(&raw, auth, ipv6, false, false).unwrap();
            let manager = crate::session::SessionManager::new(None, None);
            tx.session = manager.get_or_create_session(tx.source).unwrap();
            assert!(manager.expire_matching(tx.source, None).unwrap());
            assert!(tx
                .send_next(&counters, &RateLimiter::new(0), |_, _, _| panic!("retired"))
                .is_none());
            let mut tx = reflect(&raw, auth, ipv6, false, false).unwrap();
            tx.first = false;
            let limiter = RateLimiter::with_burst(1, 1);
            assert!(limiter.allow(tx.source.ip()));
            assert!(tx
                .send_next(&counters, &limiter, |_, _, _| panic!("rate limited"))
                .is_none());
            assert!(counters.ber_conformance_counts().values().all(|n| *n == 0));
        }
    }
}
