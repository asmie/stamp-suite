//! End-to-end coverage of PTP timestamp encoding and the Type 3
//! Timestamp Information TLV reflector behaviour per RFC 8972 §4.3.
//!
//! Implementation lives in `src/time.rs::generate_timestamp` (encodes NTP
//! or PTP based on `ClockFormat`) and `src/receiver/mod.rs` lines around
//! 1014-1018 (the reflector calls `update_timestamp_info_tlvs` with a
//! `SyncSource` derived from its local `ctx.clock_source`).
//!
//! These tests pin three things:
//! 1. The PTP wire encoding is "Unix seconds | nanoseconds" — distinct from
//!    NTP's "seconds-since-1900 | 2^32-fraction" — so a packet with a
//!    plausible 2026 timestamp has a top-32-bits value below the NTP epoch
//!    offset when generated as PTP and above it when generated as NTP.
//! 2. With a PTP-configured reflector (ctx.clock_source = PTP), the
//!    response Type 3 TLV reports `sync_src_out = Ptp` and
//!    `timestamp_out = SwLocal`.
//! 3. Mixed mode: a sender that signals `sync_src_in = Ntp` reaching a
//!    PTP-configured reflector keeps `sync_src_in = Ntp` on the wire
//!    (echoed unchanged) and gets `sync_src_out = Ptp` from the reflector.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use stamp_suite::configuration::{ClockFormat, TlvHandlingMode};
use stamp_suite::packets::PacketUnauthenticated;
use stamp_suite::receiver::{process_stamp_packet, ProcessingContext, UNAUTH_BASE_SIZE};
use stamp_suite::time::generate_timestamp;
use stamp_suite::tlv::{SyncSource, TimestampInfoTlv, TimestampMethod, TlvList, TlvType, TypedTlv};

/// Offset between NTP epoch (1900-01-01) and Unix epoch (1970-01-01) in
/// seconds. The wire-format discriminator between NTP and PTP encodings:
/// NTP seconds for any post-1970 timestamp will exceed this; PTP seconds
/// (which are Unix time) will not.
const NTP_UNIX_OFFSET: u64 = 2_208_988_800;

fn src() -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 12345)
}

fn make_ctx<'a>(clock_source: ClockFormat) -> ProcessingContext<'a> {
    ProcessingContext {
        clock_source,
        error_estimate_wire: 0,
        hmac_key: None,
        require_hmac: false,
        session_manager: None,
        tlv_mode: TlvHandlingMode::Echo,
        verify_tlv_hmac: false,
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

/// Builds an unauth STAMP packet with the given timestamp + Type 3 TLV.
fn build_packet_with_timestamp_info(ts: u64, sender_tlv: TimestampInfoTlv) -> Vec<u8> {
    let base = PacketUnauthenticated {
        sequence_number: 1,
        timestamp: ts,
        error_estimate: 0,
        ssid: 0,
        mbz: [0; 28],
    };
    let raw = sender_tlv.to_raw();
    let mut data = base.to_bytes().to_vec();
    data.extend_from_slice(&raw.to_bytes());
    data
}

// ---------------------------------------------------------------------------
// Wire-encoding distinction.

#[test]
fn ptp_timestamp_seconds_are_unix_time_not_ntp() {
    // Generate both encodings of "now" and confirm the high 32 bits clearly
    // distinguish them. A 2026-era timestamp:
    //   PTP seconds ≈ 1.7e9 < NTP_UNIX_OFFSET (2.2e9)
    //   NTP seconds ≈ 3.9e9 > NTP_UNIX_OFFSET
    let ntp = generate_timestamp(ClockFormat::NTP);
    let ptp = generate_timestamp(ClockFormat::PTP);

    let ntp_secs = ntp >> 32;
    let ptp_secs = ptp >> 32;

    assert!(
        ntp_secs > NTP_UNIX_OFFSET,
        "NTP encoding must place us in NTP epoch (post-1970 → secs > offset)"
    );
    assert!(
        ptp_secs < NTP_UNIX_OFFSET,
        "PTP encoding must use Unix epoch (post-1970 but pre-2040 → secs < offset)"
    );
    assert_eq!(
        ntp_secs - ptp_secs,
        NTP_UNIX_OFFSET,
        "the two encodings must differ by exactly the NTP epoch offset"
    );
}

// ---------------------------------------------------------------------------
// PTP-configured reflector reports PTP in the response TLV.

#[test]
fn ptp_reflector_fills_sync_src_out_ptp() {
    let ts = generate_timestamp(ClockFormat::PTP);
    let sender_tlv = TimestampInfoTlv::new(SyncSource::Ptp, TimestampMethod::SwLocal);
    let packet = build_packet_with_timestamp_info(ts, sender_tlv);

    let ctx = make_ctx(ClockFormat::PTP);
    let response =
        process_stamp_packet(&packet, src(), 64, false, &ctx).expect("reflector must respond");

    let parsed = TlvList::parse(&response.data[UNAUTH_BASE_SIZE..]).expect("response must parse");
    let raw = parsed
        .non_hmac_tlvs()
        .iter()
        .find(|t| t.tlv_type == TlvType::TimestampInfo)
        .expect("Type 3 TLV must be echoed");
    let tinfo = TimestampInfoTlv::from_raw(raw).expect("decode Type 3");

    assert_eq!(
        tinfo.sync_src_in,
        SyncSource::Ptp,
        "sender's sync source must be echoed unchanged"
    );
    assert_eq!(
        tinfo.timestamp_in,
        TimestampMethod::SwLocal,
        "sender's TS method must be echoed unchanged"
    );
    assert_eq!(
        tinfo.sync_src_out,
        SyncSource::Ptp,
        "reflector with ClockFormat::PTP must report sync_src_out = Ptp"
    );
    assert_eq!(
        tinfo.timestamp_out,
        TimestampMethod::SwLocal,
        "reflector method is SwLocal (HW timestamping not yet implemented; F1)"
    );
}

// ---------------------------------------------------------------------------
// NTP sender, NTP reflector — control case, both ends agree.

#[test]
fn ntp_reflector_fills_sync_src_out_ntp() {
    let ts = generate_timestamp(ClockFormat::NTP);
    let sender_tlv = TimestampInfoTlv::new(SyncSource::Ntp, TimestampMethod::SwLocal);
    let packet = build_packet_with_timestamp_info(ts, sender_tlv);

    let ctx = make_ctx(ClockFormat::NTP);
    let response =
        process_stamp_packet(&packet, src(), 64, false, &ctx).expect("reflector must respond");

    let parsed = TlvList::parse(&response.data[UNAUTH_BASE_SIZE..]).expect("response must parse");
    let raw = parsed
        .non_hmac_tlvs()
        .iter()
        .find(|t| t.tlv_type == TlvType::TimestampInfo)
        .expect("Type 3 TLV must be echoed");
    let tinfo = TimestampInfoTlv::from_raw(raw).expect("decode Type 3");

    assert_eq!(tinfo.sync_src_in, SyncSource::Ntp);
    assert_eq!(tinfo.sync_src_out, SyncSource::Ntp);
    assert_eq!(tinfo.timestamp_out, TimestampMethod::SwLocal);
}

// ---------------------------------------------------------------------------
// Mixed mode: sender NTP, reflector PTP — and vice versa.
//
// RFC 8762 §4.1.1 makes the timestamp format implementation-specific (the Z
// bit in Error Estimate signals it). Type 3 TLV §4.3 simply reports each
// side's source independently; the reflector must NOT overwrite the
// sender's declared input source.

#[test]
fn mixed_mode_sender_ntp_reflector_ptp_preserves_sender_fields() {
    // Sender encoded NTP timestamp, declares Ntp in the TLV.
    let ts = generate_timestamp(ClockFormat::NTP);
    let sender_tlv = TimestampInfoTlv::new(SyncSource::Ntp, TimestampMethod::SwLocal);
    let packet = build_packet_with_timestamp_info(ts, sender_tlv);

    // Reflector configured for PTP.
    let ctx = make_ctx(ClockFormat::PTP);
    let response =
        process_stamp_packet(&packet, src(), 64, false, &ctx).expect("reflector must respond");

    let parsed = TlvList::parse(&response.data[UNAUTH_BASE_SIZE..]).expect("response must parse");
    let raw = parsed
        .non_hmac_tlvs()
        .iter()
        .find(|t| t.tlv_type == TlvType::TimestampInfo)
        .expect("Type 3 TLV must be echoed");
    let tinfo = TimestampInfoTlv::from_raw(raw).expect("decode Type 3");

    assert_eq!(
        tinfo.sync_src_in,
        SyncSource::Ntp,
        "sender's declared NTP source must NOT be overwritten by a PTP reflector"
    );
    assert_eq!(
        tinfo.sync_src_out,
        SyncSource::Ptp,
        "PTP reflector reports its own PTP source in sync_src_out"
    );
}

#[test]
fn mixed_mode_sender_ptp_reflector_ntp_preserves_sender_fields() {
    let ts = generate_timestamp(ClockFormat::PTP);
    let sender_tlv = TimestampInfoTlv::new(SyncSource::Ptp, TimestampMethod::SwLocal);
    let packet = build_packet_with_timestamp_info(ts, sender_tlv);

    let ctx = make_ctx(ClockFormat::NTP);
    let response =
        process_stamp_packet(&packet, src(), 64, false, &ctx).expect("reflector must respond");

    let parsed = TlvList::parse(&response.data[UNAUTH_BASE_SIZE..]).expect("response must parse");
    let raw = parsed
        .non_hmac_tlvs()
        .iter()
        .find(|t| t.tlv_type == TlvType::TimestampInfo)
        .expect("Type 3 TLV must be echoed");
    let tinfo = TimestampInfoTlv::from_raw(raw).expect("decode Type 3");

    assert_eq!(
        tinfo.sync_src_in,
        SyncSource::Ptp,
        "sender's declared PTP source must be preserved"
    );
    assert_eq!(
        tinfo.sync_src_out,
        SyncSource::Ntp,
        "NTP reflector reports Ntp in sync_src_out"
    );
}

// ---------------------------------------------------------------------------
// Wire-bytes sanity: the sender's base packet timestamp field matches the
// generator output exactly, in big-endian, at the expected offset.

#[test]
fn ptp_timestamp_appears_in_packet_at_expected_offset() {
    // PacketUnauthenticated layout (RFC 8762 §4.1.1):
    //   bytes 0..4   sequence number
    //   bytes 4..12  timestamp (big-endian u64)
    //   bytes 12..14 error estimate
    //   bytes 14..16 SSID
    //   bytes 16..44 MBZ
    let ts = generate_timestamp(ClockFormat::PTP);
    let sender_tlv = TimestampInfoTlv::new(SyncSource::Ptp, TimestampMethod::SwLocal);
    let packet = build_packet_with_timestamp_info(ts, sender_tlv);

    let mut wire_ts_bytes = [0u8; 8];
    wire_ts_bytes.copy_from_slice(&packet[4..12]);
    let wire_ts = u64::from_be_bytes(wire_ts_bytes);

    assert_eq!(
        wire_ts, ts,
        "timestamp must appear in big-endian at offset 4..12"
    );
    assert!(
        (wire_ts >> 32) < NTP_UNIX_OFFSET,
        "PTP encoding: seconds field must be Unix time (< NTP epoch offset)"
    );
}
