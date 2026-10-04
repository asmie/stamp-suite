//! BER wire tests (draft-gandhi-ippm-stamp-ber-07) through
//! `process_stamp_packet`: clean padding, single-bit errors, three-bit
//! bursts, bursts across byte boundaries and sender pattern placement.
//! Sender construction is in sender/run.rs; reflector processing is in
//! `TlvList::process_ber`.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use stamp_suite::configuration::{ClockFormat, TlvHandlingMode};
use stamp_suite::packets::PacketUnauthenticated;
use stamp_suite::receiver::{process_stamp_packet, ProcessingContext, UNAUTH_BASE_SIZE};
use stamp_suite::tlv::{
    BerBurstTlv, BerCountTlv, BerPatternTlv, ExtraPaddingTlv, TlvList, TlvType, TypedTlv,
};

const PATTERN: [u8; 2] = [0xFF, 0x00];
const PADDING_SIZE: usize = 64;

fn src() -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 12345)
}

fn make_ctx<'a>() -> ProcessingContext<'a> {
    ProcessingContext {
        ingress_ifindex: None,
        packet_local_addr: None,
        replay_verdict: stamp_suite::session::ReplayVerdict::New,
        clock_source: ClockFormat::NTP,
        clock_sync_source: stamp_suite::tlv::SyncSource::Local,
        hardware_clock_sync_source: stamp_suite::tlv::SyncSource::Local,
        error_estimate_wire: 0,
        hmac_key: None,
        hmac_key_set: None,
        require_hmac: false,
        session_manager: None,
        stateful_reflector: true,
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

/// Builds Extra Padding bytes by repeating the pattern, as `SenderRun::open`
/// does in `src/sender/run.rs`.
fn build_padding_from_pattern(pattern: &[u8], size: usize) -> Vec<u8> {
    let mut padding = Vec::with_capacity(size);
    for i in 0..size {
        padding.push(pattern[i % pattern.len()]);
    }
    padding
}

/// Builds a BER-enabled unauthenticated STAMP packet exactly like the sender
/// path does: ExtraPadding (filled with pattern), then BerPattern, BerCount(0),
/// BerBurst(0). The caller may then corrupt the returned bytes anywhere in
/// the padding region before reflecting.
fn build_ber_packet(padding: Vec<u8>) -> Vec<u8> {
    let base = PacketUnauthenticated {
        sequence_number: 1,
        timestamp: 0,
        error_estimate: 0,
        ssid: 0,
        mbz: [0; 28],
    };

    let extra_padding = ExtraPaddingTlv { padding }.to_raw();
    let ber_pattern = BerPatternTlv::new(PATTERN.to_vec()).to_raw();
    let ber_count = BerCountTlv::default().to_raw();
    let ber_burst = BerBurstTlv::default().to_raw();

    let mut data = base.to_bytes().to_vec();
    data.extend_from_slice(&extra_padding.to_bytes());
    data.extend_from_slice(&ber_pattern.to_bytes());
    data.extend_from_slice(&ber_count.to_bytes());
    data.extend_from_slice(&ber_burst.to_bytes());
    data
}

/// Reflects `packet` and returns the parsed BerCount + BerBurst values from
/// the response.
fn reflect_and_extract_ber(packet: &[u8]) -> (u32, u32) {
    let ctx = make_ctx();
    let response =
        process_stamp_packet(packet, src(), 64, false, &ctx).expect("must reflect packet");
    let parsed = TlvList::parse(&response.data[UNAUTH_BASE_SIZE..]).expect("response must parse");

    let count_raw = parsed
        .non_hmac_tlvs()
        .iter()
        .find(|t| t.tlv_type == TlvType::BerCount)
        .expect("BerCount TLV must be echoed");
    let burst_raw = parsed
        .non_hmac_tlvs()
        .iter()
        .find(|t| t.tlv_type == TlvType::BerBurst)
        .expect("BerBurst TLV must be echoed");

    let count = BerCountTlv::from_raw(count_raw).expect("BerCount decode");
    let burst = BerBurstTlv::from_raw(burst_raw).expect("BerBurst decode");
    (count.count, burst.max_burst)
}

/// Find the offset of the ExtraPadding TLV's value bytes within a built
/// packet. The base is 44 bytes, then a 4-byte TLV header, then the value.
fn padding_value_offset() -> usize {
    UNAUTH_BASE_SIZE + 4 // 44 + flags/type/length
}

// ---------------------------------------------------------------------------
// Clean channel

#[test]
fn ber_clean_channel_reports_zero_errors() {
    let padding = build_padding_from_pattern(&PATTERN, PADDING_SIZE);
    let packet = build_ber_packet(padding);

    let (count, burst) = reflect_and_extract_ber(&packet);
    assert_eq!(count, 0, "clean channel must report zero error bits");
    assert_eq!(burst, 0, "clean channel must report zero burst");
}

// ---------------------------------------------------------------------------
// Single-bit flip

#[test]
fn ber_single_bit_flip_reports_one_error() {
    let padding = build_padding_from_pattern(&PATTERN, PADDING_SIZE);
    let mut packet = build_ber_packet(padding);

    // Flip bit 0 of padding[3]. padding[3] corresponds to pattern[3 % 2] =
    // pattern[1] = 0x00, so XOR'd byte = 0x01: one error bit, one burst.
    let off = padding_value_offset() + 3;
    packet[off] ^= 0x01;

    let (count, burst) = reflect_and_extract_ber(&packet);
    assert_eq!(count, 1, "single-bit flip must produce count = 1");
    assert_eq!(burst, 1, "single-bit flip must produce burst = 1");
}

// ---------------------------------------------------------------------------
// Three consecutive bit-flips within one byte

#[test]
fn ber_three_bit_burst_within_byte_reports_three() {
    let padding = build_padding_from_pattern(&PATTERN, PADDING_SIZE);
    let mut packet = build_ber_packet(padding);

    // padding[3] is expected 0x00; setting it to 0b00000111 = 0x07 produces a
    // 3-bit error burst with no surrounding 1-bits.
    let off = padding_value_offset() + 3;
    packet[off] = 0x07;

    let (count, burst) = reflect_and_extract_ber(&packet);
    assert_eq!(count, 3, "three-bit burst must produce count = 3");
    assert_eq!(burst, 3, "three-bit burst must produce burst = 3");
}

// ---------------------------------------------------------------------------
// Burst spanning byte boundary

#[test]
fn ber_burst_spanning_byte_boundary_reports_continuous_run() {
    // MSB-first scan: byte 3 changes 0x00→0x01 and byte 4 changes 0xFF→0x1F.
    // Their XOR bytes (0x01, 0xE0) form four consecutive error bits across
    // one byte boundary, with zeros on either side.
    let mut padding = build_padding_from_pattern(&PATTERN, PADDING_SIZE);
    padding[3] = 0x01;
    padding[4] = 0x1F;

    let packet = build_ber_packet(padding);
    let (count, burst) = reflect_and_extract_ber(&packet);
    assert_eq!(count, 4, "expected 4 error bits, got {count}");
    assert_eq!(burst, 4, "expected 4-bit cross-byte burst, got {burst}");
}

// ---------------------------------------------------------------------------
// Sender-shaped packet: hex-dump check

#[test]
fn ber_sender_padding_carries_pattern_at_expected_offset() {
    // The sender (`SenderRun::open`) fills padding by repeating the
    // configured pattern. We rebuild the same chain and verify the wire
    // bytes at the ExtraPadding value offset match the expected pattern
    // repetition, byte-for-byte.
    let padding = build_padding_from_pattern(&PATTERN, PADDING_SIZE);
    let packet = build_ber_packet(padding);

    let off = padding_value_offset();
    for i in 0..PADDING_SIZE {
        assert_eq!(
            packet[off + i],
            PATTERN[i % PATTERN.len()],
            "byte {i} of padding must equal pattern[{}], i.e. 0x{:02x}",
            i % PATTERN.len(),
            PATTERN[i % PATTERN.len()]
        );
    }
}

// ---------------------------------------------------------------------------
// Custom pattern: a non-default pattern exercises the BerPattern TLV path

#[test]
fn ber_custom_pattern_clean_channel_zero_errors() {
    let pattern: [u8; 2] = [0xAA, 0x55];
    let mut padding = Vec::with_capacity(PADDING_SIZE);
    for i in 0..PADDING_SIZE {
        padding.push(pattern[i % pattern.len()]);
    }

    // Build packet with the *custom* pattern carried in BerPattern TLV.
    let base = PacketUnauthenticated {
        sequence_number: 1,
        timestamp: 0,
        error_estimate: 0,
        ssid: 0,
        mbz: [0; 28],
    };
    let extra_padding = ExtraPaddingTlv { padding }.to_raw();
    let ber_pattern = BerPatternTlv::new(pattern.to_vec()).to_raw();
    let ber_count = BerCountTlv::default().to_raw();
    let ber_burst = BerBurstTlv::default().to_raw();

    let mut data = base.to_bytes().to_vec();
    data.extend_from_slice(&extra_padding.to_bytes());
    data.extend_from_slice(&ber_pattern.to_bytes());
    data.extend_from_slice(&ber_count.to_bytes());
    data.extend_from_slice(&ber_burst.to_bytes());

    let (count, burst) = reflect_and_extract_ber(&data);
    assert_eq!(count, 0, "custom-pattern clean channel: count = 0");
    assert_eq!(burst, 0, "custom-pattern clean channel: burst = 0");
}
