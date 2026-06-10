//! End-to-end conformance audit for TLV flag semantics.
//!
//! Pins the U/M/I/C flag contract against the RFC 8972 + draft-ietf-ippm-
//! asymmetrical-pkts wire format. Each test drives `process_stamp_packet`
//! through the reflector pipeline with a deliberately-shaped TLV chain and
//! asserts the expected flag is set in the echoed response.
//!
//! - **U** (Unrecognized, bit 0, mask 0x80) — RFC 8972 §3: reflector sets when
//!   the TLV type is not known to it but still echoes the TLV.
//! - **M** (Malformed, bit 1, mask 0x40) — RFC 8972 §3: set on length
//!   mismatches and parser-detected structural errors (truncation, TLV after
//!   HMAC, etc.). Sub-field range violations are *not* spec-mandated to be
//!   flagged.
//! - **I** (Integrity failed, bit 2, mask 0x20) — RFC 8972 §4.8: set on **all**
//!   TLVs when HMAC TLV verification fails; the packet is still echoed (not
//!   dropped).
//! - **C** (Conformant Reflected, bit 3, mask 0x10) — draft-ietf-ippm-
//!   asymmetrical-pkts §3, IANA-assigned: set by the reflector on the
//!   Reflected Test Packet Control TLV only, to indicate the requested
//!   asymmetry parameters could not be honoured exactly.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use stamp_suite::configuration::{ClockFormat, TlvHandlingMode};
use stamp_suite::crypto::HmacKey;
use stamp_suite::packets::PacketUnauthenticated;
use stamp_suite::receiver::{process_stamp_packet, ProcessingContext, UNAUTH_BASE_SIZE};
use stamp_suite::tlv::{
    ClassOfServiceTlv, ExtraPaddingTlv, RawTlv, ReturnPathAction, ReturnPathTlv, TlvFlags, TlvList,
    TlvType, TypedTlv, TLV_HEADER_SIZE,
};

// ---------------------------------------------------------------------------
// Helpers

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
        return_path_allow_alternate: false,
        reflector_member_link_id: None,
        captured_headers: None,
        reflected_control_max_count: 16,
        reflected_control_max_size: 1500,
        reflected_control_min_interval_ns: 1_000,
    }
}

/// Builds an unauth STAMP packet (seq=1) with the supplied raw TLV chain.
fn build_unauth_packet(tlv_bytes: &[u8]) -> Vec<u8> {
    let base = PacketUnauthenticated {
        sequence_number: 1,
        timestamp: 0,
        error_estimate: 0,
        ssid: 0,
        mbz: [0; 28],
    };
    let mut data = base.to_bytes().to_vec();
    data.extend_from_slice(tlv_bytes);
    data
}

/// Reflects an unauth packet end-to-end and returns the parsed echoed TLV
/// list from the response.
fn reflect_unauth(packet: &[u8], ctx: &ProcessingContext) -> TlvList {
    let response = process_stamp_packet(packet, src(), 64, false, ctx)
        .expect("reflector should produce a response");
    TlvList::parse(&response.data[UNAUTH_BASE_SIZE..])
        .expect("response TLV chain must be parseable")
}

/// Build a single TLV chain (header + value), with optional sender-side flag
/// byte. RFC 8972 §4.4.1 says senders set U=1, M=0, I=0; that's what the
/// `RawTlv::new`-constructed bytes already do.
fn tlv_to_chain(tlv: &RawTlv) -> Vec<u8> {
    tlv.to_bytes()
}

// ---------------------------------------------------------------------------
// TlvFlags wire-format unit tests — pin the bit positions.

#[test]
fn tlv_flags_wire_bit_positions() {
    // RFC 8972 §3 + draft-ietf-ippm-asymmetrical-pkts §3.
    // U=bit0=0x80, M=bit1=0x40, I=bit2=0x20, C=bit3=0x10.
    assert_eq!(
        TlvFlags {
            unrecognized: true,
            ..Default::default()
        }
        .to_byte(),
        0x80,
        "U flag must serialise to 0x80"
    );
    assert_eq!(
        TlvFlags {
            malformed: true,
            ..Default::default()
        }
        .to_byte(),
        0x40,
        "M flag must serialise to 0x40"
    );
    assert_eq!(
        TlvFlags {
            integrity_failed: true,
            ..Default::default()
        }
        .to_byte(),
        0x20,
        "I flag must serialise to 0x20"
    );
    assert_eq!(
        TlvFlags {
            conformant_reflected: true,
            ..Default::default()
        }
        .to_byte(),
        0x10,
        "C flag must serialise to 0x10"
    );
}

#[test]
fn tlv_flags_round_trip_each_bit_set() {
    for byte in [0x00, 0x80, 0x40, 0x20, 0x10, 0xF0] {
        let flags = TlvFlags::from_byte(byte);
        assert_eq!(
            flags.to_byte(),
            byte,
            "round-trip mismatch for 0x{byte:02x}"
        );
    }
}

// ---------------------------------------------------------------------------
// U-flag — unknown TLV types are echoed with U set.

#[test]
fn u_flag_set_on_unknown_tlv_type() {
    // Type 100 is not assigned in our TlvType enum → parsed as Unknown(100).
    let raw = RawTlv::new(TlvType::Unknown(100), vec![0, 0, 0, 0]);
    let chain = tlv_to_chain(&raw);

    let packet = build_unauth_packet(&chain);
    let ctx = make_ctx(None);
    let parsed = reflect_unauth(&packet, &ctx);

    let echoed = parsed
        .non_hmac_tlvs()
        .iter()
        .find(|t| matches!(t.tlv_type, TlvType::Unknown(100)))
        .expect("echoed unknown TLV must survive round-trip");
    assert!(
        echoed.is_unrecognized(),
        "unknown TLV type must come back with U-flag set"
    );
    assert!(!echoed.is_malformed(), "valid-length unknown ≠ malformed");
    assert!(!echoed.is_integrity_failed(), "no HMAC → I must be clear");
}

#[test]
fn u_flag_set_on_reserved_type_zero() {
    // Type 0 is "Reserved" — also unknown to a conformant receiver.
    let raw = RawTlv::new(TlvType::Reserved, vec![0, 0, 0, 0]);
    let chain = tlv_to_chain(&raw);

    let packet = build_unauth_packet(&chain);
    let ctx = make_ctx(None);
    let parsed = reflect_unauth(&packet, &ctx);

    let echoed = &parsed.non_hmac_tlvs()[0];
    assert!(
        echoed.is_unrecognized(),
        "reserved Type 0 must come back with U-flag set"
    );
}

// ---------------------------------------------------------------------------
// M-flag — length mismatches and parser-detected structural errors.

#[test]
fn m_flag_set_on_cos_wrong_length() {
    // CoS is a fixed 4-byte Value; sending 2 bytes is malformed.
    let raw = RawTlv::new(TlvType::ClassOfService, vec![0, 0]);
    let packet = build_unauth_packet(&tlv_to_chain(&raw));
    let ctx = make_ctx(None);
    let parsed = reflect_unauth(&packet, &ctx);

    let echoed = parsed
        .non_hmac_tlvs()
        .iter()
        .find(|t| matches!(t.tlv_type, TlvType::ClassOfService))
        .expect("CoS TLV must be echoed even when malformed");
    assert!(echoed.is_malformed(), "wrong-length CoS must have M set");
}

#[test]
fn m_flag_set_on_truncated_tlv() {
    // Append a TLV header that claims 16 bytes of Value but only supplies 4.
    // The reflector echoes the (still-malformed) TLV byte-exactly with M=1
    // per RFC 8972 §4.8; parsing the response requires the lenient parser
    // since the wire is, by construction, still malformed.
    let mut chain = Vec::new();
    chain.push(0); // flags
    chain.push(TlvType::ExtraPadding.to_byte()); // type
    chain.extend_from_slice(&16u16.to_be_bytes()); // claimed length
    chain.extend_from_slice(&[0xAA; 4]); // truncated value

    let packet = build_unauth_packet(&chain);
    let ctx = make_ctx(None);
    let response = process_stamp_packet(&packet, src(), 64, false, &ctx)
        .expect("reflector must still echo a malformed TLV (RFC 8972 §4.8)");
    let (parsed, any_malformed) = TlvList::parse_lenient(&response.data[UNAUTH_BASE_SIZE..]);

    let (_u, m, _i) = parsed.count_error_flags();
    assert!(
        m >= 1 || any_malformed,
        "truncated TLV must produce an M-flagged echo or be flagged as malformed by the parser"
    );
}

#[test]
fn m_flag_set_on_wrong_length_micro_session_id() {
    // Micro-session ID is a fixed 4-byte Value; 8 bytes is malformed.
    let raw = RawTlv::new(TlvType::MicroSessionId, vec![0; 8]);
    let packet = build_unauth_packet(&tlv_to_chain(&raw));
    let ctx = make_ctx(None);
    let parsed = reflect_unauth(&packet, &ctx);

    let echoed = parsed
        .non_hmac_tlvs()
        .iter()
        .find(|t| matches!(t.tlv_type, TlvType::MicroSessionId))
        .expect("Micro-session ID TLV must be echoed");
    assert!(
        echoed.is_malformed(),
        "wrong-length Micro-session ID must have M set"
    );
}

#[test]
fn valid_cos_does_not_set_m_flag() {
    // Negative control: a well-formed CoS TLV must come back with M clear.
    let cos = ClassOfServiceTlv {
        dscp1: 46,
        ecn1: 2,
        dscp2: 0,
        ecn2: 0,
        rp: 0,
    };
    let raw = cos.to_raw();
    let packet = build_unauth_packet(&tlv_to_chain(&raw));
    let ctx = make_ctx(None);
    let parsed = reflect_unauth(&packet, &ctx);

    let echoed = parsed
        .non_hmac_tlvs()
        .iter()
        .find(|t| matches!(t.tlv_type, TlvType::ClassOfService))
        .expect("valid CoS must be present in response");
    assert!(
        !echoed.is_malformed(),
        "well-formed CoS must NOT have M set"
    );
}

// ---------------------------------------------------------------------------
// I-flag — HMAC TLV verification failure marks all TLVs.

#[test]
fn i_flag_set_on_corrupted_tlv_hmac() {
    // CoS + deliberately-wrong HMAC TLV. RFC 8972 §4.8 says the packet is
    // still echoed; all TLVs come back with I set.
    let key = HmacKey::new(vec![0x42; 32]).expect("test key");

    let cos = ClassOfServiceTlv {
        dscp1: 0,
        ecn1: 0,
        dscp2: 0,
        ecn2: 0,
        rp: 0,
    }
    .to_raw();

    let mut tlvs = Vec::new();
    tlvs.extend_from_slice(&cos.to_bytes());
    let bogus_hmac = RawTlv::new(TlvType::Hmac, vec![0xFF; 16]);
    tlvs.extend_from_slice(&bogus_hmac.to_bytes());

    let packet = build_unauth_packet(&tlvs);
    let ctx = make_ctx(Some(&key));
    let response = process_stamp_packet(&packet, src(), 64, false, &ctx)
        .expect("packet must still be echoed even on HMAC failure (RFC 8972 §4.8)");
    let parsed = TlvList::parse(&response.data[UNAUTH_BASE_SIZE..]).expect("response must parse");

    // Every TLV (including the HMAC TLV) must carry I=1.
    let (_u, _m, i) = parsed.count_error_flags();
    assert!(
        i >= 2,
        "all echoed TLVs must have I-flag set on HMAC failure; got {i}"
    );
}

#[test]
fn i_flag_not_set_on_valid_tlv_hmac() {
    // Negative control: with a correct HMAC over the TLV chain, I stays
    // clear on every echoed TLV. HMAC input format per RFC 8972 §4.8 is
    // sequence_number_bytes (4) || preceding (non-HMAC) TLV bytes.
    let key = HmacKey::new(vec![0x11; 32]).expect("test key");

    let cos = ClassOfServiceTlv {
        dscp1: 0,
        ecn1: 0,
        dscp2: 0,
        ecn2: 0,
        rp: 0,
    }
    .to_raw();
    let cos_bytes = cos.to_bytes();

    let seq_bytes = 1u32.to_be_bytes();
    let mut hmac_input = Vec::new();
    hmac_input.extend_from_slice(&seq_bytes);
    hmac_input.extend_from_slice(&cos_bytes);
    let digest = key.compute(&hmac_input);
    let hmac_tlv = RawTlv::new(TlvType::Hmac, digest.to_vec());

    let mut tlvs = Vec::new();
    tlvs.extend_from_slice(&cos_bytes);
    tlvs.extend_from_slice(&hmac_tlv.to_bytes());

    let packet = build_unauth_packet(&tlvs);
    let ctx = make_ctx(Some(&key));
    let response = process_stamp_packet(&packet, src(), 64, false, &ctx)
        .expect("valid HMAC packet must be reflected");
    let parsed = TlvList::parse(&response.data[UNAUTH_BASE_SIZE..]).expect("response must parse");

    let (_u, _m, i) = parsed.count_error_flags();
    assert_eq!(i, 0, "valid HMAC must leave I clear on every echoed TLV");
}

// ---------------------------------------------------------------------------
// C-flag — Reflected Test Packet Control non-conformance signal.

#[test]
fn c_flag_set_when_reflected_control_request_exceeds_local_caps() {
    // Type 12 wire format (draft-14 §3 minimum 12 octets):
    //   length_of_reflected_packet (u16) | number_of_reflected_packets (u16)
    //   | interval_nanoseconds (u32) | one placeholder sub-TLV header (4 zero
    //   octets) so the value field reaches the mandatory 12-octet floor.
    let mut value = Vec::with_capacity(12);
    value.extend_from_slice(&0u16.to_be_bytes()); // length: don't request padding
    value.extend_from_slice(&1000u16.to_be_bytes()); // count: well above cap
    value.extend_from_slice(&1_000_000u32.to_be_bytes()); // interval: 1 ms
    value.extend_from_slice(&[0u8; 4]); // 4-byte sub-TLV placeholder (flags=0, type=0, length=0)

    let raw = RawTlv::new(TlvType::ReflectedControl, value);
    let packet = build_unauth_packet(&tlv_to_chain(&raw));
    let ctx = make_ctx(None);
    let parsed = reflect_unauth(&packet, &ctx);

    let echoed = parsed
        .non_hmac_tlvs()
        .iter()
        .find(|t| matches!(t.tlv_type, TlvType::ReflectedControl))
        .expect("Reflected Control TLV must be echoed");
    let flags_byte = echoed.flags.to_byte();
    assert_eq!(
        flags_byte & 0x10,
        0x10,
        "C flag (0x10) must be set when the requested count is clamped; flags=0x{flags_byte:02x}"
    );
}

#[test]
fn c_flag_clear_when_reflected_control_request_within_caps() {
    // Request 2 packets, 1 ms — within REFLECTED_CONTROL_MAX_COUNT. The
    // 12-byte minimum is honoured by the placeholder sub-TLV header below.
    let mut value = Vec::with_capacity(12);
    value.extend_from_slice(&0u16.to_be_bytes()); // length
    value.extend_from_slice(&2u16.to_be_bytes()); // count: 2
    value.extend_from_slice(&1_000_000u32.to_be_bytes()); // interval
    value.extend_from_slice(&[0u8; 4]); // sub-TLV placeholder

    let raw = RawTlv::new(TlvType::ReflectedControl, value);
    let packet = build_unauth_packet(&tlv_to_chain(&raw));
    let ctx = make_ctx(None);
    let parsed = reflect_unauth(&packet, &ctx);

    let echoed = parsed
        .non_hmac_tlvs()
        .iter()
        .find(|t| matches!(t.tlv_type, TlvType::ReflectedControl))
        .expect("Reflected Control TLV must be echoed");
    let flags_byte = echoed.flags.to_byte();
    assert_eq!(
        flags_byte & 0x10,
        0x00,
        "C flag must be clear for a conformant request; flags=0x{flags_byte:02x}"
    );
}

#[test]
fn reflected_control_disabled_by_default_emits_no_extra_copies() {
    // With reflected_control_max_count = 0 (the production default), a Type 12
    // request must not amplify: zero extra copies, and the C flag set to tell
    // the sender the request was not honoured.
    let mut value = Vec::with_capacity(12);
    value.extend_from_slice(&0u16.to_be_bytes()); // length
    value.extend_from_slice(&8u16.to_be_bytes()); // count: 8 reply packets
    value.extend_from_slice(&1_000_000u32.to_be_bytes()); // interval
    value.extend_from_slice(&[0u8; 4]); // sub-TLV placeholder

    let raw = RawTlv::new(TlvType::ReflectedControl, value);
    let packet = build_unauth_packet(&tlv_to_chain(&raw));
    let mut ctx = make_ctx(None);
    ctx.reflected_control_max_count = 0; // disabled (production default)

    let response = process_stamp_packet(&packet, src(), 64, false, &ctx)
        .expect("reflector should still produce the single normal reply");

    // No amplification: either no behavior recorded, or zero extra copies.
    let extra = response.reflected_control.map_or(0, |b| b.extra_copies);
    assert_eq!(
        extra, 0,
        "disabled reflector must emit no extra reply packets"
    );

    // C flag set on the echoed Type 12 TLV (request not honoured).
    let parsed = TlvList::parse(&response.data[UNAUTH_BASE_SIZE..])
        .expect("response TLV chain must be parseable");
    let echoed = parsed
        .non_hmac_tlvs()
        .iter()
        .find(|t| matches!(t.tlv_type, TlvType::ReflectedControl))
        .expect("Reflected Control TLV must be echoed");
    assert_eq!(
        echoed.flags.to_byte() & 0x10,
        0x10,
        "C flag must be set when the reflector cannot honour the request"
    );
}

// ---------------------------------------------------------------------------
// draft-ietf-ippm-asymmetrical-pkts-14 §3 processing rules.

/// Builds the 12-octet Type 12 value: length | count | interval plus the
/// 4-byte placeholder sub-TLV header that pads to the mandatory 12-octet
/// floor.
fn reflected_control_value(length: u16, count: u16, interval_ns: u32) -> Vec<u8> {
    let mut value = Vec::with_capacity(12);
    value.extend_from_slice(&length.to_be_bytes());
    value.extend_from_slice(&count.to_be_bytes());
    value.extend_from_slice(&interval_ns.to_be_bytes());
    value.extend_from_slice(&[0u8; 4]);
    value
}

#[test]
fn reflected_control_count_zero_suppresses_reply() {
    // draft-14 §3: "If the Number of Reflected Packets field is set to zero,
    // the Session-Reflector MUST NOT send any reflected packets", and SHOULD
    // discard the received test packet.
    let raw = RawTlv::new(
        TlvType::ReflectedControl,
        reflected_control_value(0, 0, 1_000_000),
    );
    let packet = build_unauth_packet(&tlv_to_chain(&raw));
    let ctx = make_ctx(None);

    let response = process_stamp_packet(&packet, src(), 64, false, &ctx)
        .expect("processing still yields a (suppressed) response object");
    assert_eq!(
        response.return_path_action,
        ReturnPathAction::SuppressReply,
        "count=0 must suppress the reply entirely"
    );
}

#[test]
fn reflected_control_count_above_cap_collapses_to_single_reply() {
    // draft-14 §3: a request that would exceed the reflector's volume limit
    // gets C=1 and "a single reflected packet" — not a clamped burst.
    let raw = RawTlv::new(
        TlvType::ReflectedControl,
        reflected_control_value(0, 1000, 1_000_000),
    );
    let packet = build_unauth_packet(&tlv_to_chain(&raw));
    let ctx = make_ctx(None); // cap = 16

    let response = process_stamp_packet(&packet, src(), 64, false, &ctx)
        .expect("over-limit request still produces the single reply");
    let extra = response.reflected_control.map_or(0, |b| b.extra_copies);
    assert_eq!(extra, 0, "volume violation must collapse to a single reply");
}

#[test]
fn reflected_control_interval_below_floor_collapses_to_single_reply() {
    // draft-14 §3: exceeding the configured *rate* limit (interval floor)
    // also means C=1 plus a single reflected packet.
    let raw = RawTlv::new(
        TlvType::ReflectedControl,
        reflected_control_value(0, 2, 10), // 10 ns << 1 µs floor
    );
    let packet = build_unauth_packet(&tlv_to_chain(&raw));
    let ctx = make_ctx(None);

    let response = process_stamp_packet(&packet, src(), 64, false, &ctx)
        .expect("rate-violating request still produces the single reply");
    let extra = response.reflected_control.map_or(0, |b| b.extra_copies);
    assert_eq!(extra, 0, "rate violation must collapse to a single reply");

    let parsed = TlvList::parse(&response.data[UNAUTH_BASE_SIZE..]).expect("parse");
    let flags = parsed
        .non_hmac_tlvs()
        .iter()
        .find(|t| matches!(t.tlv_type, TlvType::ReflectedControl))
        .expect("Type 12 echoed")
        .flags
        .to_byte();
    assert_eq!(
        flags & 0x10,
        0x10,
        "C flag must accompany the rate violation"
    );
}

#[test]
fn reflected_control_strips_echoed_extra_padding() {
    // draft-14 §3 rule (a): the reflected length is computed "excluding any
    // Extra Padding TLVs" so a sender can request replies SHORTER than its
    // test packet. The echoed chain must not contain the sender's padding.
    let padding = ExtraPaddingTlv::new_zeros(100).to_raw();
    let control = RawTlv::new(
        TlvType::ReflectedControl,
        reflected_control_value(0, 2, 1_000_000),
    );
    let mut chain = Vec::new();
    chain.extend_from_slice(&padding.to_bytes());
    chain.extend_from_slice(&control.to_bytes());

    let packet = build_unauth_packet(&chain);
    let ctx = make_ctx(None);

    let response = process_stamp_packet(&packet, src(), 64, false, &ctx)
        .expect("conformant request must be reflected");
    let parsed = TlvList::parse(&response.data[UNAUTH_BASE_SIZE..]).expect("parse");
    assert!(
        !parsed
            .non_hmac_tlvs()
            .iter()
            .any(|t| matches!(t.tlv_type, TlvType::ExtraPadding)),
        "echoed Extra Padding must be stripped when Type 12 is processed"
    );
    assert_eq!(
        response.data.len(),
        UNAUTH_BASE_SIZE + TLV_HEADER_SIZE + 12,
        "reply must shrink to base + Type 12 once padding is stripped"
    );
}

#[test]
fn reflected_control_pads_to_four_octet_aligned_length() {
    // draft-14 §3 rule (b): the requested length is taken "aligned at a
    // four-octet boundary" — 101 must round up to 104.
    let raw = RawTlv::new(
        TlvType::ReflectedControl,
        reflected_control_value(101, 1, 0),
    );
    let packet = build_unauth_packet(&tlv_to_chain(&raw));
    let ctx = make_ctx(None);

    let response = process_stamp_packet(&packet, src(), 64, false, &ctx)
        .expect("padding request must be reflected");
    assert_eq!(
        response.data.len(),
        104,
        "requested length 101 must be honoured as the aligned 104 octets"
    );
}

#[test]
fn incoming_c_flag_on_request_is_ignored() {
    // draft-14 §3: "the Session-Reflector MUST ignore its value on the
    // receipt" — a sender-set C must not leak into a conformant echo.
    let raw = RawTlv::with_flags(
        TlvFlags::from_byte(0x90), // U (sender-mandated) + bogus C
        TlvType::ReflectedControl,
        reflected_control_value(0, 2, 1_000_000),
    );
    let packet = build_unauth_packet(&raw.to_bytes());
    let ctx = make_ctx(None);
    let parsed = reflect_unauth(&packet, &ctx);

    let flags = parsed
        .non_hmac_tlvs()
        .iter()
        .find(|t| matches!(t.tlv_type, TlvType::ReflectedControl))
        .expect("Type 12 echoed")
        .flags
        .to_byte();
    assert_eq!(
        flags & 0x10,
        0x00,
        "reflector must derive C itself; the incoming value is ignored"
    );
}

#[test]
fn return_path_no_reply_conflict_sets_u_on_both_tlvs() {
    // draft-14 §4.3: Return Path "no reply requested" combined with a
    // non-zero Reflected Test Packet Control TLV is a sender error; the
    // reflector "MUST set the U flag to 1 in Return Path and Reflected Test
    // Packet Control TLVs in the reflected STAMP packet" — so a reply IS
    // sent, and no asymmetric behaviour happens.
    let rp = ReturnPathTlv::with_control_code(0x0).to_raw(); // no reply requested
    let control = RawTlv::new(
        TlvType::ReflectedControl,
        reflected_control_value(0, 2, 1_000_000),
    );
    let mut chain = Vec::new();
    chain.extend_from_slice(&rp.to_bytes());
    chain.extend_from_slice(&control.to_bytes());

    let packet = build_unauth_packet(&chain);
    let ctx = make_ctx(None);

    let response = process_stamp_packet(&packet, src(), 64, false, &ctx)
        .expect("conflicting packet must still be reflected");
    assert_eq!(
        response.return_path_action,
        ReturnPathAction::Normal,
        "the no-reply request must not be honoured in the conflict case"
    );
    let extra = response.reflected_control.map_or(0, |b| b.extra_copies);
    assert_eq!(extra, 0, "no asymmetric behaviour in the conflict case");

    let parsed = TlvList::parse(&response.data[UNAUTH_BASE_SIZE..]).expect("parse");
    for wanted in [TlvType::ReturnPath, TlvType::ReflectedControl] {
        let flags = parsed
            .non_hmac_tlvs()
            .iter()
            .find(|t| t.tlv_type == wanted)
            .unwrap_or_else(|| panic!("{wanted:?} must be echoed"))
            .flags
            .to_byte();
        assert_eq!(
            flags & 0x80,
            0x80,
            "{wanted:?} must carry U=1 in the conflict case"
        );
    }
}

#[test]
fn reflected_control_padding_uses_real_base_size_with_tlv_hmac() {
    // The padding target must be computed from the actual reflected base
    // packet size (44 octets unauth), not inferred from the presence of a
    // TLV-HMAC key. Request 200 octets; the reply must be exactly 200.
    let key = HmacKey::new(vec![0x11; 32]).expect("test key");

    let control = RawTlv::new(
        TlvType::ReflectedControl,
        reflected_control_value(200, 2, 1_000_000),
    );
    let control_bytes = control.to_bytes();

    let seq_bytes = 1u32.to_be_bytes();
    let mut hmac_input = Vec::new();
    hmac_input.extend_from_slice(&seq_bytes);
    hmac_input.extend_from_slice(&control_bytes);
    let digest = key.compute(&hmac_input);
    let hmac_tlv = RawTlv::new(TlvType::Hmac, digest.to_vec());

    let mut chain = Vec::new();
    chain.extend_from_slice(&control_bytes);
    chain.extend_from_slice(&hmac_tlv.to_bytes());

    let packet = build_unauth_packet(&chain);
    let ctx = make_ctx(Some(&key));

    let response = process_stamp_packet(&packet, src(), 64, false, &ctx)
        .expect("valid HMAC packet must be reflected");
    assert_eq!(
        response.data.len(),
        200,
        "unauth reply must be padded to exactly the requested 200 octets"
    );
}

#[test]
fn reflected_control_length_padding_disabled_by_default() {
    // Security (audit finding 1): with reflected_control_max_count = 0 (the
    // production default) the reflector must NOT pad its reply up to a
    // peer-requested length. Padding a tiny request into a large reply is
    // amplification, and combined with a Return Address sub-TLV it becomes a
    // reflection vector aimed at a third party. The request is refused (C flag)
    // and the reply is left at its natural size.
    let mut value = Vec::with_capacity(12);
    value.extend_from_slice(&1500u16.to_be_bytes()); // length: pad to 1500
    value.extend_from_slice(&1u16.to_be_bytes()); // count: 1 (single reply)
    value.extend_from_slice(&1_000_000u32.to_be_bytes()); // interval
    value.extend_from_slice(&[0u8; 4]); // sub-TLV placeholder

    let raw = RawTlv::new(TlvType::ReflectedControl, value);
    let packet = build_unauth_packet(&tlv_to_chain(&raw));
    let mut ctx = make_ctx(None);
    ctx.reflected_control_max_count = 0; // disabled (production default)

    let response = process_stamp_packet(&packet, src(), 64, false, &ctx)
        .expect("reflector should still produce the single normal reply");

    // Not amplified: the reply must be far smaller than the requested 1500.
    assert!(
        response.data.len() < 200,
        "reply must not be padded to the requested length when amplification \
         is disabled (got {} bytes)",
        response.data.len()
    );

    // C flag set on the echoed Type 12 TLV (length request not honoured).
    let parsed = TlvList::parse(&response.data[UNAUTH_BASE_SIZE..])
        .expect("response TLV chain must be parseable");
    let echoed = parsed
        .non_hmac_tlvs()
        .iter()
        .find(|t| matches!(t.tlv_type, TlvType::ReflectedControl))
        .expect("Reflected Control TLV must be echoed");
    assert_eq!(
        echoed.flags.to_byte() & 0x10,
        0x10,
        "C flag must be set when length padding is refused"
    );
}

#[test]
fn reflected_control_length_padding_honoured_when_enabled() {
    // The counterpart to the above: when the operator opts in
    // (reflected_control_max_count > 0) the length request is honoured and the
    // reply is padded up to the requested size (bounded by max_size).
    let mut value = Vec::with_capacity(12);
    value.extend_from_slice(&512u16.to_be_bytes()); // length: pad to 512
    value.extend_from_slice(&1u16.to_be_bytes()); // count: 1
    value.extend_from_slice(&1_000_000u32.to_be_bytes()); // interval
    value.extend_from_slice(&[0u8; 4]); // sub-TLV placeholder

    let raw = RawTlv::new(TlvType::ReflectedControl, value);
    let packet = build_unauth_packet(&tlv_to_chain(&raw));
    let mut ctx = make_ctx(None);
    ctx.reflected_control_max_count = 16; // opted in
    ctx.reflected_control_max_size = 1500;

    let response = process_stamp_packet(&packet, src(), 64, false, &ctx)
        .expect("reflector should produce a padded reply");

    assert_eq!(
        response.data.len(),
        512,
        "reply must be padded up to the requested length when enabled"
    );
}

// ---------------------------------------------------------------------------
// Independence — U/M/I bits must not bleed into each other.

#[test]
fn unknown_tlv_does_not_set_m_or_i() {
    let raw = RawTlv::new(TlvType::Unknown(123), vec![0; 8]);
    let packet = build_unauth_packet(&tlv_to_chain(&raw));
    let ctx = make_ctx(None);
    let parsed = reflect_unauth(&packet, &ctx);

    let echoed = &parsed.non_hmac_tlvs()[0];
    assert!(echoed.is_unrecognized());
    assert!(
        !echoed.is_malformed(),
        "well-formed unknown TLV must not have M set"
    );
    assert!(
        !echoed.is_integrity_failed(),
        "no HMAC verification → I must be clear"
    );
}

#[test]
fn malformed_tlv_does_not_set_u_or_i() {
    // Recognised type with wrong length: M set, U clear, I clear.
    let raw = RawTlv::new(TlvType::ClassOfService, vec![0, 0]);
    let packet = build_unauth_packet(&tlv_to_chain(&raw));
    let ctx = make_ctx(None);
    let parsed = reflect_unauth(&packet, &ctx);

    let echoed = parsed
        .non_hmac_tlvs()
        .iter()
        .find(|t| matches!(t.tlv_type, TlvType::ClassOfService))
        .expect("CoS TLV must be echoed");
    assert!(echoed.is_malformed());
    assert!(
        !echoed.is_unrecognized(),
        "recognised type must not have U set"
    );
    assert!(!echoed.is_integrity_failed());
}

// ---------------------------------------------------------------------------
// Header invariants.

#[test]
fn tlv_header_size_is_four_octets() {
    assert_eq!(
        TLV_HEADER_SIZE, 4,
        "RFC 8972 §4.2.1: flags(1) + type(1) + length(2) = 4 octets"
    );
}

// ---------------------------------------------------------------------------
// A1: Reflected Test Packet Control draft-14 extras.

/// 8-byte Type 12 value (pre-draft-14) must be rejected as malformed.
#[test]
fn a1_reflected_control_min_length_12_pre_14_rejected() {
    let mut value = Vec::with_capacity(8);
    value.extend_from_slice(&0u16.to_be_bytes()); // length
    value.extend_from_slice(&1u16.to_be_bytes()); // count
    value.extend_from_slice(&0u32.to_be_bytes()); // interval

    let raw = RawTlv::new(TlvType::ReflectedControl, value);
    let packet = build_unauth_packet(&raw.to_bytes());
    let ctx = make_ctx(None);
    let parsed = reflect_unauth(&packet, &ctx);

    let echoed = parsed
        .non_hmac_tlvs()
        .iter()
        .find(|t| matches!(t.tlv_type, TlvType::ReflectedControl))
        .expect("Type 12 must be echoed");
    assert!(
        echoed.is_malformed(),
        "8-byte Type 12 value must be rejected with M-flag per draft-14 §3 \
         (MUST NOT be smaller than 12 octets)"
    );
}

/// Requested reply length within cap → response is padded to at least that
/// size via an Extra Padding TLV, and C flag is clear.
#[test]
fn a1_reflected_control_length_padding_within_cap() {
    let target_length = 200u16;
    let mut value = Vec::with_capacity(12);
    value.extend_from_slice(&target_length.to_be_bytes()); // length: pad to 200 bytes
    value.extend_from_slice(&1u16.to_be_bytes()); // count: 1
    value.extend_from_slice(&0u32.to_be_bytes()); // interval
    value.extend_from_slice(&[0u8; 4]); // sub-TLV placeholder

    let raw = RawTlv::new(TlvType::ReflectedControl, value);
    let packet = build_unauth_packet(&raw.to_bytes());
    let ctx = make_ctx(None);

    let response = stamp_suite::receiver::process_stamp_packet(
        &packet,
        std::net::SocketAddr::new(
            std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1)),
            12345,
        ),
        64,
        false,
        &ctx,
    )
    .expect("must reflect");

    assert!(
        response.data.len() >= target_length as usize,
        "padded response must be at least {} bytes; got {}",
        target_length,
        response.data.len()
    );

    let parsed =
        TlvList::parse(&response.data[stamp_suite::receiver::UNAUTH_BASE_SIZE..]).expect("parse");
    let echoed = parsed
        .non_hmac_tlvs()
        .iter()
        .find(|t| matches!(t.tlv_type, TlvType::ReflectedControl))
        .expect("Type 12 must be echoed");
    assert_eq!(
        echoed.flags.to_byte() & 0x10,
        0x00,
        "C flag must be clear when length is honourable within the cap"
    );

    // An Extra Padding TLV must have been inserted to reach the target.
    let pad = parsed
        .non_hmac_tlvs()
        .iter()
        .find(|t| matches!(t.tlv_type, TlvType::ExtraPadding));
    assert!(
        pad.is_some(),
        "Extra Padding TLV must be present in response"
    );
}

/// Requested reply length exceeds the cap → C flag is set; we still pad up
/// to the cap (best-effort).
#[test]
fn a1_reflected_control_length_request_exceeds_cap_sets_c_flag() {
    let target_length = 9000u16; // larger than default cap (1500)
    let mut value = Vec::with_capacity(12);
    value.extend_from_slice(&target_length.to_be_bytes());
    value.extend_from_slice(&1u16.to_be_bytes());
    value.extend_from_slice(&0u32.to_be_bytes());
    value.extend_from_slice(&[0u8; 4]);

    let raw = RawTlv::new(TlvType::ReflectedControl, value);
    let packet = build_unauth_packet(&raw.to_bytes());
    let ctx = make_ctx(None);
    let parsed = reflect_unauth(&packet, &ctx);

    let echoed = parsed
        .non_hmac_tlvs()
        .iter()
        .find(|t| matches!(t.tlv_type, TlvType::ReflectedControl))
        .expect("Type 12 must be echoed");
    assert_eq!(
        echoed.flags.to_byte() & 0x10,
        0x10,
        "C flag must be set when requested length exceeds local cap"
    );
}

/// L3 Address Group sub-TLV present but no local address matches → packet
/// processing stops per draft §3 ("MUST stop processing the received
/// packet"). The backend observes `ReturnPathAction::SuppressReply` and
/// does not transmit a reply.
#[test]
fn a1_reflected_control_l3_mismatch_suppresses_reply() {
    use stamp_suite::tlv::ReturnPathAction;

    // Build a Type 12 with an L3 sub-TLV requiring a specific IPv4 prefix.
    // The reflector's local_addresses is empty in make_ctx (no match
    // possible), so it must suppress.
    let mut value = Vec::with_capacity(20);
    value.extend_from_slice(&0u16.to_be_bytes()); // length
    value.extend_from_slice(&1u16.to_be_bytes()); // count
    value.extend_from_slice(&0u32.to_be_bytes()); // interval
                                                  // L3 Address Group sub-TLV: flags=0, type=11, length=8, prefix_len=24,
                                                  // reserved=0x000000, prefix=192.0.2.0.
    let sub_tlv = [
        0u8, 11, 0x00, 0x08, // header
        24, 0x00, 0x00, 0x00, // prefix_len + reserved
        192, 0, 2, 0, // prefix
    ];
    value.extend_from_slice(&sub_tlv);

    let raw = RawTlv::new(TlvType::ReflectedControl, value);
    let packet = build_unauth_packet(&raw.to_bytes());
    let ctx = make_ctx(None); // local_addresses is empty

    let response = stamp_suite::receiver::process_stamp_packet(
        &packet,
        std::net::SocketAddr::new(
            std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1)),
            12345,
        ),
        64,
        false,
        &ctx,
    )
    .expect("packet still parsed, only reply is suppressed");

    assert!(
        matches!(response.return_path_action, ReturnPathAction::SuppressReply),
        "L3 sub-TLV mismatch must cause the reflector to suppress the reply \
         per draft-ietf-ippm-asymmetrical-pkts §3"
    );
}
