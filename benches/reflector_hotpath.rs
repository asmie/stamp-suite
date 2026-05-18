//! Criterion benches for the reflector hot path.
//!
//! Drives `process_stamp_packet` end-to-end through the in-process
//! pipeline (no real UDP) so the benches measure parse + HMAC + TLV
//! processing + response assembly without the kernel scheduler in the
//! loop. That isolates the cost we control from socket-level noise; the
//! integration tests under `tests/loopback*` already cover the
//! kernel-level path.
//!
//! Benches:
//! - `unauth_no_tlvs` — baseline 44-byte unauth packet, no TLVs.
//! - `unauth_one_tlv` — unauth + one CoS TLV (Type 4).
//! - `unauth_full_chain` — unauth + CoS + Location + Direct Measurement
//!   + Follow-Up Telemetry + Timestamp Info (typical sender chain).
//! - `auth_no_tlvs` — baseline 112-byte auth packet with HMAC
//!   verification.
//! - `auth_full_chain` — auth + the same TLV chain as the unauth case,
//!   plus an HMAC TLV at the tail.
//!
//! Run all benches:
//!     cargo bench --bench reflector_hotpath
//!
//! Run one:
//!     cargo bench --bench reflector_hotpath -- unauth_full_chain
//!
//! HTML reports land in `target/criterion/`.

use std::hint::black_box;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use criterion::{criterion_group, criterion_main, Criterion};

use stamp_suite::configuration::{ClockFormat, TlvHandlingMode};
use stamp_suite::crypto::HmacKey;
use stamp_suite::packets::{PacketAuthenticated, PacketUnauthenticated};
use stamp_suite::receiver::{process_stamp_packet, ProcessingContext};
use stamp_suite::tlv::{
    AccessReportTlv, ClassOfServiceTlv, DirectMeasurementTlv, FollowUpTelemetryTlv, LocationTlv,
    TimestampInfoTlv, TimestampMethod, TypedTlv,
};

fn src() -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 12345)
}

fn make_ctx<'a>(hmac_key: Option<&'a HmacKey>) -> ProcessingContext<'a> {
    ProcessingContext {
        clock_source: ClockFormat::NTP,
        error_estimate_wire: 0,
        hmac_key,
        hmac_key_set: None,
        require_hmac: false,
        session_manager: None,
        tlv_mode: TlvHandlingMode::Echo,
        verify_tlv_hmac: hmac_key.is_some(),
        strict_packets: false,
        #[cfg(feature = "metrics")]
        metrics_enabled: false,
        received_dscp: 0,
        received_ecn: 0,
        reflector_rx_count: None,
        reflector_tx_count: None,
        packet_addr_info: None,
        last_reflection: None,
        local_addresses: &[],
        sender_port: 12345,
        reflector_member_link_id: None,
        captured_headers: None,
        reflected_control_max_count: 16,
        reflected_control_max_size: 1500,
        reflected_control_min_interval_ns: 1_000,
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
        mbz1a: [0; 30],
        mbz1b: [0; 32],
        mbz1c: [0; 6],
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
    chain.extend(LocationTlv::new().to_raw().to_bytes());
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
    // Sign the packet so verification succeeds — we want to measure the
    // hot success path, not the early-out reject path.
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
    let mut packet = build_auth_base();
    let hmac = stamp_suite::crypto::compute_packet_hmac(&key, &packet, 96);
    packet[96..112].copy_from_slice(&hmac);
    packet.extend(typical_tlv_chain());
    let ctx = make_ctx(Some(&key));
    c.bench_function("auth_full_chain", |b| {
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

criterion_group!(
    benches,
    bench_unauth_no_tlvs,
    bench_unauth_one_tlv,
    bench_unauth_full_chain,
    bench_auth_no_tlvs,
    bench_auth_full_chain,
);
criterion_main!(benches);
