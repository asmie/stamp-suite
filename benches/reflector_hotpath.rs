//! Reflector hot-path benchmarks through `process_stamp_packet`.
//! Measures parsing, HMAC, TLV processing, and assembly without UDP/socket costs.
//! Covers authenticated and unauthenticated packets with no TLVs, one CoS TLV,
//! or a full measurement chain.
//!
//! ```text
//! cargo bench --bench reflector_hotpath
//! cargo bench --bench reflector_hotpath -- unauth_full_chain
//! ```
//!
//! Reports: `target/criterion/`. For live UDP measurements, see
//! `examples/live_udp_bench.rs` and `doc/benchmarks.md`.

use std::hint::black_box;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use criterion::{criterion_group, criterion_main, Criterion};

use stamp_suite::configuration::{ClockFormat, TlvHandlingMode};
use stamp_suite::crypto::HmacKey;
use stamp_suite::packets::{PacketAuthenticated, PacketUnauthenticated};
use stamp_suite::receiver::{process_stamp_packet, ProcessingContext};
use stamp_suite::tlv::{
    AccessReportTlv, ClassOfServiceTlv, DirectMeasurementTlv, FollowUpTelemetryTlv, LocationSubTlv,
    LocationSubType, LocationTlv, PacketAddressInfo, TimestampInfoTlv, TimestampMethod, TlvList,
    TypedTlv,
};

fn src() -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 12345)
}

fn make_ctx<'a>(hmac_key: Option<&'a HmacKey>) -> ProcessingContext<'a> {
    ProcessingContext {
        ingress_ifindex: None,
        packet_local_addr: None,
        replay_verdict: stamp_suite::session::ReplayVerdict::New,
        clock_source: ClockFormat::NTP,
        clock_sync_source: stamp_suite::tlv::SyncSource::Local,
        hardware_clock_sync_source: stamp_suite::tlv::SyncSource::Local,
        error_estimate_wire: 0,
        hmac_key,
        hmac_key_set: None,
        require_hmac: false,
        session_manager: None,
        stateful_reflector: true,
        tlv_mode: TlvHandlingMode::Echo,
        verify_tlv_hmac: hmac_key.is_some(),
        strict_packets: false,
        #[cfg(feature = "metrics")]
        metrics_enabled: false,
        received_dscp: 0,
        received_ecn: 0,
        reflector_rx_count: Some(100),
        reflector_tx_count: Some(99),
        packet_addr_info: Some(PacketAddressInfo {
            src_addr: src().ip(),
            src_port: src().port(),
            dst_addr: Ipv4Addr::new(127, 0, 0, 2).into(),
            dst_port: 862,
            src_mac: Some([2, 0, 0, 0, 0, 1]),
        }),
        last_reflection: None,
        location_disclosure: Default::default(),
        cos_policy: stamp_suite::cos_policy::permissive(),
        local_addresses: &[],
        local_macs: &[],
        sender_port: 12345,
        return_path_allow_alternate: false,
        reflector_member_link_id: None,
        captured_headers: None,
        reflected_control_max_count: 16,
        reflected_control_max_size: 1500,
        reflected_control_min_interval_ns: 1_000,
        reflected_control_max_rate: stamp_suite::receiver::REFLECTED_CONTROL_MAX_RATE,
        reflected_control_max_volume: stamp_suite::receiver::REFLECTED_CONTROL_MAX_VOLUME,
        rx_timestamp: None,
        rx_method: stamp_suite::tlv::TimestampMethod::SwLocal,
        last_reflection_method: stamp_suite::tlv::TimestampMethod::SwLocal,
    }
}

fn build_unauth_base() -> Vec<u8> {
    PacketUnauthenticated {
        sequence_number: 1,
        timestamp: 0,
        error_estimate: 0,
        ssid: 0,
        mbz: [0; 28],
    }
    .to_bytes()
    .to_vec()
}

fn build_auth_base() -> Vec<u8> {
    PacketAuthenticated {
        sequence_number: 1,
        mbz0: [0; 12],
        timestamp: 0,
        error_estimate: 0,
        ssid: 0,
        mbz1: [0; 68],
        hmac: [0; 16],
    }
    .to_bytes()
    .to_vec()
}

/// A "typical" sender TLV chain: CoS + Location + Direct Measurement +
/// Follow-Up Telemetry + Timestamp Info + Access Report.
fn typical_tlv_chain() -> Vec<u8> {
    use stamp_suite::tlv::SyncSource;
    let mut chain = Vec::new();
    chain.extend(ClassOfServiceTlv::new(46, 2).to_raw().to_bytes());
    let mut location = LocationTlv::new();
    location
        .sub_tlvs
        .push(LocationSubTlv::generic_request(LocationSubType::SourceIp));
    location.sub_tlvs.push(LocationSubTlv::generic_request(
        LocationSubType::DestinationIp,
    ));
    chain.extend(location.to_raw().to_bytes());
    chain.extend(DirectMeasurementTlv::new(0).to_raw().to_bytes());
    chain.extend(FollowUpTelemetryTlv::new().to_raw().to_bytes());
    chain.extend(
        TimestampInfoTlv::new(SyncSource::Ntp, TimestampMethod::SwLocal)
            .to_raw()
            .to_bytes(),
    );
    chain.extend(AccessReportTlv::default().to_raw().to_bytes());
    chain
}

fn bench_unauth_no_tlvs(c: &mut Criterion) {
    let packet = build_unauth_base();
    let ctx = make_ctx(None);
    c.bench_function("unauth_no_tlvs", |b| {
        b.iter(|| {
            let _ = process_stamp_packet(
                black_box(&packet),
                black_box(src()),
                black_box(64),
                black_box(false),
                black_box(&ctx),
            );
        });
    });
}

fn bench_unauth_one_tlv(c: &mut Criterion) {
    let mut packet = build_unauth_base();
    packet.extend(ClassOfServiceTlv::new(46, 2).to_raw().to_bytes());
    let ctx = make_ctx(None);
    c.bench_function("unauth_one_tlv", |b| {
        b.iter(|| {
            let _ = process_stamp_packet(
                black_box(&packet),
                black_box(src()),
                black_box(64),
                black_box(false),
                black_box(&ctx),
            );
        });
    });
}

fn bench_unauth_full_chain(c: &mut Criterion) {
    let mut packet = build_unauth_base();
    packet.extend(typical_tlv_chain());
    let ctx = make_ctx(None);
    c.bench_function("unauth_full_chain", |b| {
        b.iter(|| {
            let _ = process_stamp_packet(
                black_box(&packet),
                black_box(src()),
                black_box(64),
                black_box(false),
                black_box(&ctx),
            );
        });
    });
}

fn bench_auth_no_tlvs(c: &mut Criterion) {
    let key = HmacKey::new(vec![0xAA; 16]).unwrap();
    // Sign the packet so verification succeeds: this measures the success
    // path, not the early reject path.
    let mut packet = build_auth_base();
    let hmac = stamp_suite::crypto::compute_packet_hmac(&key, &packet, 96);
    packet[96..112].copy_from_slice(&hmac);
    let ctx = make_ctx(Some(&key));
    c.bench_function("auth_no_tlvs", |b| {
        b.iter(|| {
            let _ = process_stamp_packet(
                black_box(&packet),
                black_box(src()),
                black_box(64),
                black_box(true),
                black_box(&ctx),
            );
        });
    });
}

fn bench_auth_full_chain(c: &mut Criterion) {
    let key = HmacKey::new(vec![0xBB; 16]).unwrap();
    let mut base = build_auth_base();
    let hmac = stamp_suite::crypto::compute_packet_hmac(&key, &base, 96);
    base[96..112].copy_from_slice(&hmac);
    let ctx = make_ctx(Some(&key));
    for (name, signed) in [
        ("auth_full_chain", true),
        ("auth_chain_missing_tlv_hmac", false),
    ] {
        let mut packet = base.clone();
        let mut chain = TlvList::parse(&typical_tlv_chain()).unwrap();
        if signed {
            chain.set_hmac(&key, &packet[..4]);
        }
        packet.extend(chain.to_bytes());
        let reply = process_stamp_packet(&packet, src(), 64, true, &ctx)
            .expect("benchmark fixture rejected");
        let returned = TlvList::parse(&reply.data[112..]).unwrap();
        assert!(!returned.non_hmac_tlvs().is_empty());
        assert!(returned
            .non_hmac_tlvs()
            .iter()
            .all(|tlv| tlv.is_integrity_failed() != signed));
        if signed {
            returned
                .verify_hmac(&key, &reply.data[..4], &reply.data[112..])
                .unwrap();
        }
        c.bench_function(name, |b| {
            b.iter(|| {
                process_stamp_packet(
                    black_box(&packet),
                    black_box(src()),
                    black_box(64),
                    black_box(true),
                    black_box(&ctx),
                )
            });
        });
    }
}

/// Stateful processing through a populated session table. Session admission
/// and lookup are included; receive counters and replay classification run
/// only on the live backend path and are not measured here.
fn bench_unauth_stateful_sessions(c: &mut Criterion) {
    let manager = std::sync::Arc::new(stamp_suite::session::SessionManager::new(None, None));
    for port in 0..1000u16 {
        let client = SocketAddr::new(src().ip(), 10_000 + port);
        manager.get_or_create_session(client);
    }
    let mut packet = build_unauth_base();
    packet.extend(typical_tlv_chain());
    let mut ctx = make_ctx(None);
    ctx.session_manager = Some(&manager);
    ctx.stateful_reflector = true;
    c.bench_function("unauth_stateful_sessions", |b| {
        b.iter(|| {
            let _ = process_stamp_packet(
                black_box(&packet),
                black_box(src()),
                black_box(64),
                black_box(false),
                black_box(&ctx),
            );
        });
    });
}

criterion_group!(
    benches,
    bench_unauth_no_tlvs,
    bench_unauth_one_tlv,
    bench_unauth_full_chain,
    bench_auth_no_tlvs,
    bench_auth_full_chain,
    bench_unauth_stateful_sessions,
);
criterion_main!(benches);
