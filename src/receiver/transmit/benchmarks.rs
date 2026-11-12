//! Fixed transmission fixtures for external allocation/copy profilers.
//! Mock sends capture into preallocated buffers; no packets or sockets are used.

use super::*;
use crate::tlv::{ExtraPaddingTlv, RawTlv, ReflectedControlTlv, ReturnPathTlv, TlvList, TypedTlv};
use serde::Serialize;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{cell::Cell, hint::black_box};

const PAYLOAD: usize = 1440;
const MAX_ATTEMPTS: usize = 64;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum Scenario {
    Ordinary,
    Padded,
    Burst,
    Trim,
    Alternate,
    MtuRace,
    Cos,
    Srv6,
}

impl Scenario {
    fn name(self) -> &'static str {
        match self {
            Self::Ordinary => "ordinary",
            Self::Padded => "padded",
            Self::Burst => "burst",
            Self::Trim => "trim",
            Self::Alternate => "alternate",
            Self::MtuRace => "mtu_race",
            Self::Cos => "cos",
            Self::Srv6 => "srv6",
        }
    }
}

#[derive(Clone, Copy, Serialize)]
struct Case {
    scenario: Scenario,
    auth: bool,
    ipv6: bool,
}

impl Case {
    fn tag(self) -> String {
        format!(
            "{}-{}-{}",
            self.scenario.name(),
            if self.auth { "auth" } else { "open" },
            if self.ipv6 { "ipv6" } else { "ipv4" }
        )
    }
}

fn cases() -> Vec<Case> {
    let mut result = Vec::new();
    for ipv6 in [false, true] {
        for auth in [false, true] {
            for scenario in [
                Scenario::Ordinary,
                Scenario::Padded,
                Scenario::Burst,
                Scenario::Trim,
                Scenario::Alternate,
                Scenario::MtuRace,
                Scenario::Cos,
                Scenario::Srv6,
            ] {
                if scenario != Scenario::Srv6 || ipv6 {
                    result.push(Case {
                        scenario,
                        auth,
                        ipv6,
                    });
                }
            }
        }
    }
    result
}

fn fixture(case: Case) -> Transmission {
    let key = HmacKey::new(vec![0xcd; 16]).unwrap();
    let base = if case.auth {
        AUTH_BASE_SIZE
    } else {
        UNAUTH_BASE_SIZE
    };
    let source: SocketAddr = if case.ipv6 {
        "[::1]:4000"
    } else {
        "127.0.0.1:4000"
    }
    .parse()
    .unwrap();
    let alternate: SocketAddr = if case.ipv6 {
        "[::2]:4000"
    } else {
        "127.0.0.2:4000"
    }
    .parse()
    .unwrap();
    let controlled = matches!(
        case.scenario,
        Scenario::Burst | Scenario::Trim | Scenario::Alternate | Scenario::MtuRace | Scenario::Srv6
    );
    let extra = match case.scenario {
        Scenario::Burst => 31,
        Scenario::Trim | Scenario::MtuRace => 7,
        _ => 0,
    };
    let action = match case.scenario {
        Scenario::Alternate => ReturnPathAction::AlternateAddress(alternate),
        Scenario::Srv6 => ReturnPathAction::Srv6Forward {
            sids: vec!["2001:db8::1".parse().unwrap()],
            destination: Some(alternate),
        },
        _ => ReturnPathAction::Normal,
    };
    let mut list = TlvList::new();
    if case.scenario != Scenario::Ordinary {
        if controlled {
            list.push(ReflectedControlTlv::new(PAYLOAD as u16, extra, 1).to_raw())
                .unwrap();
        }
        if case.scenario == Scenario::Cos {
            list.push(
                crate::tlv::ClassOfServiceTlv::for_response(46, 1, 10, 0, false, true).to_raw(),
            )
            .unwrap();
        }
        if matches!(case.scenario, Scenario::Alternate | Scenario::Srv6) {
            let request = if case.scenario == Scenario::Srv6 {
                ReturnPathTlv::with_srv6_sids(&["2001:db8::1".parse().unwrap()])
            } else {
                ReturnPathTlv::with_return_address(alternate.ip())
            };
            list.push(request.to_raw()).unwrap();
        }
        list.push(RawTlv::new(
            TlvType::DirectMeasurement,
            vec![0; DIRECT_MEASUREMENT_TLV_VALUE_SIZE],
        ))
        .unwrap();
        list.push(RawTlv::new(
            TlvType::FollowUpTelemetry,
            vec![0; FOLLOW_UP_TELEMETRY_TLV_VALUE_SIZE],
        ))
        .unwrap();
        let padding = PAYLOAD - base - list.to_bytes().len() - if case.auth { 20 } else { 0 };
        list.push(ExtraPaddingTlv::new_zeros(padding - TLV_HEADER_SIZE).to_raw())
            .unwrap();
        list.clear_reflector_flags();
        if case.auth {
            assert!(list.set_hmac_response(&key, &[0; 4]));
        }
    }
    let mut data = vec![0; base];
    data.extend_from_slice(&list.to_bytes());
    assert_eq!(
        data.len(),
        if case.scenario == Scenario::Ordinary {
            base
        } else {
            PAYLOAD
        }
    );
    let session = Arc::new(Session::new(0));
    session.record_received();
    Transmission::new(
        StampResponse {
            data,
            cos_request: (case.scenario == Scenario::Cos).then_some((46, 1)),
            return_path_action: action,
            reflected_control: controlled.then_some(super::super::ReflectedControlBehavior {
                max_size: PAYLOAD as u16,
                extra_copies: extra,
                interval_ns: 1,
                suppress_reply_ext_headers: false,
            }),
            reply_source: None,
            tlv_hmac_generated: case.auth && case.scenario != Scenario::Ordinary,
        },
        session,
        source,
        ClockFormat::NTP,
        case.auth,
        true,
        case.auth.then_some(key),
        10,
        true,
    )
}

struct Frame {
    data: Vec<u8>,
    len: usize,
    target: SocketAddr,
    tos: u8,
    srh: bool,
    success: bool,
}
struct Capture {
    frames: Vec<Frame>,
    used: usize,
    queries: usize,
}

impl Capture {
    fn new() -> Self {
        Self {
            frames: (0..MAX_ATTEMPTS)
                .map(|_| Frame {
                    data: vec![0; PAYLOAD],
                    len: 0,
                    target: "127.0.0.1:1".parse().unwrap(),
                    tos: 0,
                    srh: false,
                    success: false,
                })
                .collect(),
            used: 0,
            queries: 0,
        }
    }
}

// This boundary is deliberately not inlined: external profilers can select
// allocation/copy stacks containing this frame, excluding setup/verification.
#[inline(never)]
fn profile_send_region(
    t: &mut Transmission,
    case: Case,
    capture: &mut Capture,
    counters: &ReflectorCounters,
    limiter: &RateLimiter,
) {
    let sends = Cell::new(0);
    let queries = Cell::new(0);
    while t.remaining > 0 {
        let sent = t.send_next_with_mtu(
            counters,
            limiter,
            |_, _, refresh| {
                queries.set(queries.get() + 1);
                Ok(match case.scenario {
                    Scenario::Trim => 900,
                    Scenario::Alternate | Scenario::Srv6 if sends.get() == 0 => 900,
                    Scenario::MtuRace if refresh => 900,
                    _ => PAYLOAD,
                })
            },
            |bytes, target, options| {
                let index = sends.get();
                assert!(index < MAX_ATTEMPTS && bytes.len() <= PAYLOAD);
                let failed = index == 0
                    && matches!(
                        case.scenario,
                        Scenario::Alternate | Scenario::MtuRace | Scenario::Cos | Scenario::Srv6
                    );
                let frame = &mut capture.frames[index];
                frame.data[..bytes.len()].copy_from_slice(bytes);
                frame.len = bytes.len();
                frame.target = target;
                frame.tos = options.tos;
                frame.srh = options.srh.is_some();
                frame.success = !failed;
                sends.set(index + 1);
                if !failed {
                    Ok(bytes.len())
                } else {
                    Err(match case.scenario {
                        Scenario::Cos => cos_apply_error(io::ErrorKind::PermissionDenied.into()),
                        Scenario::MtuRace => {
                            #[cfg(unix)]
                            let code = nix::libc::EMSGSIZE;
                            #[cfg(not(unix))]
                            let code = 10040;
                            io::Error::from_raw_os_error(code)
                        }
                        _ => io::ErrorKind::PermissionDenied.into(),
                    })
                }
            },
        );
        assert!(sent.is_some(), "fixture transmission failed");
    }
    capture.used = sends.get();
    capture.queries = queries.get();
    black_box(capture.used);
}

fn verify(case: Case, t: &Transmission, capture: &Capture, counters: &ReflectorCounters) {
    let key = HmacKey::new(vec![0xcd; 16]).unwrap();
    let base = if case.auth {
        AUTH_BASE_SIZE
    } else {
        UNAUTH_BASE_SIZE
    };
    let mut successes = 0u32;
    let mut previous = (0u32, 0u64);
    for frame in &capture.frames[..capture.used] {
        let bytes = &frame.data[..frame.len];
        assert_eq!(
            u32::from_be_bytes(bytes[..4].try_into().unwrap()),
            successes
        );
        let offset = if case.auth { 16 } else { 4 };
        let timestamp = u64::from_be_bytes(bytes[offset..offset + 8].try_into().unwrap());
        assert_ne!(timestamp, 0);
        if case.auth {
            assert_eq!(
                &bytes[96..112],
                &crate::crypto::compute_packet_hmac(&key, bytes, 96)
            );
        }
        let mut pos = base;
        let mut hmac = false;
        while pos < bytes.len() {
            let span = TlvSpan::at(bytes, pos).expect("complete fixture TLV");
            assert!(!span.flags.malformed);
            let value = &bytes[span.value()];
            match span.tlv_type {
                TlvType::Hmac => {
                    assert!(case.auth);
                    assert_eq!(value, key.compute_parts([&bytes[..4], &bytes[base..pos]]));
                    hmac = true;
                }
                TlvType::DirectMeasurement => {
                    assert_eq!(u32::from_be_bytes(value[4..8].try_into().unwrap()), 1);
                    assert_eq!(
                        u32::from_be_bytes(value[8..12].try_into().unwrap()),
                        successes
                    );
                }
                TlvType::FollowUpTelemetry => {
                    assert_eq!(
                        u32::from_be_bytes(value[..4].try_into().unwrap()),
                        previous.0
                    );
                    assert_eq!(
                        u64::from_be_bytes(value[4..12].try_into().unwrap()),
                        previous.1
                    );
                }
                TlvType::ReturnPath if frame.success => assert!(span.flags.unrecognized),
                TlvType::ReflectedControl if frame.success => assert_eq!(
                    span.flags.conformant_reflected,
                    matches!(case.scenario, Scenario::Trim | Scenario::MtuRace)
                ),
                _ => {}
            }
            pos = span.end();
        }
        assert_eq!(hmac, case.auth && case.scenario != Scenario::Ordinary);
        if frame.success {
            successes += 1;
            previous = (successes - 1, timestamp);
        }
    }
    let copies = if case.scenario == Scenario::Burst {
        32
    } else {
        1
    };
    assert_eq!(successes, copies);
    assert_eq!(t.session.get_transmitted_count(), copies);
    assert_eq!(t.session.peek_sequence_number(), copies);
    assert_eq!(t.session.get_last_reflection(), previous);
    assert_eq!(
        counters.packets_reflected.load(Ordering::Relaxed),
        u64::from(copies)
    );
    assert_eq!(counters.packets_dropped.load(Ordering::Relaxed), 0);
    let retry = matches!(
        case.scenario,
        Scenario::Alternate | Scenario::MtuRace | Scenario::Cos | Scenario::Srv6
    );
    assert_eq!(capture.used, copies as usize + usize::from(retry));
    let last = &capture.frames[capture.used - 1];
    assert_eq!(
        last.len,
        if matches!(case.scenario, Scenario::Trim | Scenario::MtuRace) {
            900
        } else if case.scenario == Scenario::Ordinary {
            base
        } else {
            PAYLOAD
        }
    );
    if case.scenario == Scenario::Cos {
        assert_eq!(last.tos, 40);
    }
    if case.scenario == Scenario::Alternate {
        assert_eq!(last.target, t.source);
        assert_eq!(capture.frames[0].len, 900);
    }
    if case.scenario == Scenario::Srv6 {
        assert!(capture.frames[0].srh);
        assert!(!last.srh);
        assert_eq!(capture.frames[0].len, 900);
    }
}

#[derive(Serialize)]
struct Sample {
    iteration: u32,
    elapsed_ns: u64,
    attempts: usize,
    queries: usize,
    successful_copies: u32,
    captured_bytes: usize,
}

fn run_case(case: Case, iteration: u32) -> Sample {
    let mut transmission = fixture(case);
    let mut capture = Capture::new();
    let counters = ReflectorCounters::new();
    let limiter = RateLimiter::new(0);
    let started = Instant::now();
    profile_send_region(&mut transmission, case, &mut capture, &counters, &limiter);
    let elapsed_ns = u64::try_from(started.elapsed().as_nanos()).unwrap();
    verify(case, &transmission, &capture, &counters);
    Sample {
        iteration,
        elapsed_ns,
        attempts: capture.used,
        queries: capture.queries,
        successful_copies: transmission.session.get_transmitted_count(),
        captured_bytes: capture.frames[..capture.used].iter().map(|f| f.len).sum(),
    }
}

#[test]
fn transmission_profile_fixtures_validate_all_modes_families_and_fallbacks() {
    let cases = cases();
    assert_eq!(cases.len(), 30);
    for case in cases {
        run_case(case, 0);
    }
}

#[test]
#[ignore = "manual release-only reply-transmission allocation/copy profiling"]
fn transmission_allocations() -> Result<(), Box<dyn std::error::Error>> {
    if cfg!(debug_assertions) {
        return Err("use --release for transmission profiling".into());
    }
    let tag =
        std::env::var("STAMP_TX_BENCH_CASE").unwrap_or_else(|_| "ordinary-open-ipv4".to_owned());
    let case = cases()
        .into_iter()
        .find(|case| case.tag() == tag)
        .ok_or("unknown STAMP_TX_BENCH_CASE")?;
    let iterations: u32 = std::env::var("STAMP_TX_BENCH_ITERATIONS")
        .unwrap_or_else(|_| "10".to_owned())
        .parse()?;
    if !(1..=1000).contains(&iterations) {
        return Err("iterations must be 1..1000".into());
    }
    let samples: Vec<_> = (0..iterations).map(|i| run_case(case, i)).collect();
    println!(
        "TX_BENCH_JSON {}",
        serde_json::to_string(&json!({
            "schema_version":1, "completed":true, "case":tag, "settings":case, "iterations":iterations,
            "scope":"mock sends with preallocated wire capture; profile_send_region excludes setup and validation",
            "debug_build":cfg!(debug_assertions), "os":std::env::consts::OS, "arch":std::env::consts::ARCH,
            "binary_sha256":hex::encode(Sha256::digest(std::fs::read(std::env::current_exe()?)?)),
            "driver_source_sha256":hex::encode(Sha256::digest(include_bytes!("benchmarks.rs"))),
            "transmit_source_sha256":hex::encode(Sha256::digest(include_bytes!("../transmit.rs"))),
            "features":{"metrics":cfg!(feature="metrics"), "control":cfg!(feature="control"),
                "ttl_pnet":cfg!(feature="ttl-pnet"), "ttl_nix":cfg!(feature="ttl-nix"),
                "snmp":cfg!(feature="snmp"), "hwtstamp":cfg!(feature="hwtstamp")}, "samples":samples
        }))?
    );
    Ok(())
}
