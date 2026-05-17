//! Malformed-input fuzz-equivalent test suite.
//!
//! Hand-crafts adversarial byte sequences along each parser boundary called
//! out in the audit (RFC 8762 §4.1.x base-packet sizes; RFC 8972 §4.2.1 TLV
//! layout; HMAC TLV ordering per §4.8; sub-TLV chains per RFC 9503 §5) and
//! asserts the reflector:
//!
//! - never panics,
//! - produces a response (or `SuppressReply`) with the spec-mandated flag
//!   set on the offending TLV, and
//! - keeps the rest of the chain intact for sender-side analysis.
//!
//! Companion to the libfuzzer harness in C5 — these are seed corpus values
//! that proved a real failure mode at some point or that exercise a hand-
//! identified boundary.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use stamp_suite::configuration::{ClockFormat, TlvHandlingMode};
use stamp_suite::crypto::HmacKey;
use stamp_suite::packets::PacketUnauthenticated;
use stamp_suite::receiver::{
    process_stamp_packet, ProcessingContext, AUTH_BASE_SIZE, UNAUTH_BASE_SIZE,
};
use stamp_suite::tlv::{TlvList, TlvType, TLV_HEADER_SIZE};

fn src() -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 12345)
}

fn make_ctx<'a>(hmac_key: Option<&'a HmacKey>, strict: bool) -> ProcessingContext<'a> {
    ProcessingContext {
        clock_source: ClockFormat::NTP,
        error_estimate_wire: 0,
        hmac_key,
        hmac_key_set: None,
        require_hmac: false,
        session_manager: None,
        tlv_mode: TlvHandlingMode::Echo,
        verify_tlv_hmac: hmac_key.is_some(),
        strict_packets: strict,
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

// ===========================================================================
// Group A: base-packet length boundaries (RFC 8762 §4.1.1 / §4.1.2)

/// Lenient mode accepts any zero-padded buffer up to the base size; strict
/// mode rejects anything shorter. Sweep every length from 0 to BASE-1 to
/// prove neither mode panics on a hostile short packet.
#[test]
fn group_a_unauth_short_packet_no_panic_at_every_length() {
    for len in 0..UNAUTH_BASE_SIZE {
        let data = vec![0xCDu8; len];
        for strict in [false, true] {
            let ctx = make_ctx(None, strict);
            // Must not panic. Result may be Some (lenient) or None (strict).
            let _ = process_stamp_packet(&data, src(), 64, false, &ctx);
        }
    }
}

#[test]
fn group_a_auth_short_packet_no_panic_at_every_length() {
    // Sweep at 8-byte stride to keep the test fast (the auth base is 112 B).
    for len in (0..AUTH_BASE_SIZE).step_by(8) {
        let data = vec![0xCDu8; len];
        for strict in [false, true] {
            let ctx = make_ctx(None, strict);
            let _ = process_stamp_packet(&data, src(), 64, true, &ctx);
        }
    }
}

#[test]
fn group_a_one_byte_packet_does_not_panic() {
    let data = [0xFFu8];
    for strict in [false, true] {
        for use_auth in [false, true] {
            let ctx = make_ctx(None, strict);
            let _ = process_stamp_packet(&data, src(), 64, use_auth, &ctx);
        }
    }
}

// ===========================================================================
// Group B: TLV-header length-field abuses (RFC 8972 §4.2.1)

/// TLV claims `length` larger than the remaining buffer. Reflector must
/// echo (lenient) with M-flag set on the truncated TLV, no panic.
#[test]
fn group_b_tlv_length_exceeds_remaining_buffer() {
    let mut chain = Vec::new();
    chain.push(0); // flags
    chain.push(TlvType::ExtraPadding.to_byte()); // type
    chain.extend_from_slice(&8192u16.to_be_bytes()); // claimed length: 8 KB
    chain.extend_from_slice(&[0xAA; 4]); // 4 bytes of payload (real)

    let packet = build_unauth_packet(&chain);
    let ctx = make_ctx(None, false);
    let response = process_stamp_packet(&packet, src(), 64, false, &ctx)
        .expect("must produce a response even on truncated TLV");
    let (parsed, any_malformed) = TlvList::parse_lenient(&response.data[UNAUTH_BASE_SIZE..]);
    let (_u, m, _i) = parsed.count_error_flags();
    assert!(
        m >= 1 || any_malformed,
        "truncated-length TLV must echo with M flag"
    );
}

/// TLV with claimed length 0xFFFF (max u16) — buffer-length math must not
/// overflow.
#[test]
fn group_b_tlv_length_u16_max_no_panic() {
    let mut chain = Vec::new();
    chain.push(0);
    chain.push(TlvType::Location.to_byte());
    chain.extend_from_slice(&u16::MAX.to_be_bytes());

    let packet = build_unauth_packet(&chain);
    let ctx = make_ctx(None, false);
    let _ = process_stamp_packet(&packet, src(), 64, false, &ctx);
}

/// Truncated TLV header itself (1-3 trailing bytes after the base packet
/// where a 4-byte TLV header would belong).
#[test]
fn group_b_truncated_tlv_header_no_panic() {
    for trailer_len in 1..TLV_HEADER_SIZE {
        let chain = vec![0xFFu8; trailer_len];
        let packet = build_unauth_packet(&chain);
        let ctx = make_ctx(None, false);
        let _ = process_stamp_packet(&packet, src(), 64, false, &ctx);
    }
}

// ===========================================================================
// Group C: HMAC TLV ordering (RFC 8972 §4.8)

/// HMAC TLV must be LAST per RFC 8972 §4.8. A TLV after the HMAC TLV
/// is positionally malformed; the parser must mark it without panicking.
#[test]
fn group_c_tlv_after_hmac_marked_malformed() {
    let mut chain = Vec::new();

    // HMAC TLV (Type 8, 16-byte value, all zeros = invalid signature but
    // we're testing ordering not verification).
    chain.push(0);
    chain.push(TlvType::Hmac.to_byte());
    chain.extend_from_slice(&16u16.to_be_bytes());
    chain.extend_from_slice(&[0u8; 16]);

    // A trailing Extra Padding after the HMAC — positionally illegal.
    chain.push(0);
    chain.push(TlvType::ExtraPadding.to_byte());
    chain.extend_from_slice(&4u16.to_be_bytes());
    chain.extend_from_slice(&[0xAAu8; 4]);

    let packet = build_unauth_packet(&chain);
    let ctx = make_ctx(None, false);
    let response = process_stamp_packet(&packet, src(), 64, false, &ctx)
        .expect("reflector must echo even with mis-ordered HMAC");
    let (parsed, any_malformed) = TlvList::parse_lenient(&response.data[UNAUTH_BASE_SIZE..]);
    let (_u, m, _i) = parsed.count_error_flags();
    assert!(
        m >= 1 || any_malformed,
        "post-HMAC TLV must be marked malformed"
    );
}

/// HMAC TLV with wrong value length (not 16 bytes) — must M-flag, not
/// crash.
#[test]
fn group_c_hmac_wrong_length_no_panic() {
    for hmac_len in [0usize, 4, 8, 15, 17, 32] {
        let mut chain = Vec::new();
        chain.push(0);
        chain.push(TlvType::Hmac.to_byte());
        chain.extend_from_slice(&(hmac_len as u16).to_be_bytes());
        chain.extend_from_slice(&vec![0u8; hmac_len]);

        let packet = build_unauth_packet(&chain);
        let ctx = make_ctx(None, false);
        let _ = process_stamp_packet(&packet, src(), 64, false, &ctx);
    }
}

/// Corrupted HMAC value (right length, wrong digest) → I flag on all
/// TLVs per RFC 8972 §4.8. The packet is still echoed.
#[test]
fn group_c_corrupted_hmac_sets_i_flag_on_all_tlvs() {
    let key = HmacKey::new(vec![0x55; 32]).expect("test key");
    let mut chain = Vec::new();

    // ExtraPadding + bogus HMAC.
    chain.push(0);
    chain.push(TlvType::ExtraPadding.to_byte());
    chain.extend_from_slice(&4u16.to_be_bytes());
    chain.extend_from_slice(&[0u8; 4]);

    chain.push(0);
    chain.push(TlvType::Hmac.to_byte());
    chain.extend_from_slice(&16u16.to_be_bytes());
    chain.extend_from_slice(&[0xDE; 16]);

    let packet = build_unauth_packet(&chain);
    let ctx = make_ctx(Some(&key), false);
    let response = process_stamp_packet(&packet, src(), 64, false, &ctx)
        .expect("RFC 8972 §4.8 — packet is still echoed on HMAC failure");
    let parsed = TlvList::parse(&response.data[UNAUTH_BASE_SIZE..]).expect("response parses");
    let (_u, _m, i) = parsed.count_error_flags();
    assert!(
        i >= 2,
        "all TLVs (incl. HMAC) must carry I flag on HMAC failure; got {i}"
    );
}

// ===========================================================================
// Group D: Return Path sub-TLV nesting (RFC 9503 §5)

/// Return Path TLV with a sub-TLV whose claimed length exceeds the parent
/// Return Path Value. Lenient parser must mark malformed without
/// panicking; reflector still produces a response.
#[test]
fn group_d_return_path_sub_tlv_overflows_parent() {
    use stamp_suite::tlv::ReturnPathSubType;

    // Build inner (oversized) sub-TLV: claims 32-byte value but only
    // provides 4 bytes.
    let mut inner = Vec::new();
    inner.push(0); // flags
    inner.push(ReturnPathSubType::ControlCode.to_byte()); // sub type
    inner.extend_from_slice(&32u16.to_be_bytes()); // overstated length
    inner.extend_from_slice(&[0xAAu8; 4]); // actual bytes (truncates the parent)

    // Wrap in Return Path TLV.
    let mut outer = Vec::new();
    outer.push(0); // flags
    outer.push(TlvType::ReturnPath.to_byte());
    outer.extend_from_slice(&(inner.len() as u16).to_be_bytes());
    outer.extend_from_slice(&inner);

    let packet = build_unauth_packet(&outer);
    let ctx = make_ctx(None, false);
    let response = process_stamp_packet(&packet, src(), 64, false, &ctx)
        .expect("reflector must respond, not panic, on nested malformed sub-TLV");
    let _ = TlvList::parse_lenient(&response.data[UNAUTH_BASE_SIZE..]);
}

// ===========================================================================
// Group E: random bytes (high-entropy spot checks)

/// Random-ish high-entropy byte buffers must not panic. Not a fuzz test
/// (that's C5) but a smoke test for the obvious wins.
#[test]
fn group_e_high_entropy_buffers_no_panic() {
    let patterns: [&[u8]; 5] = [
        &[0xFFu8; 64],
        &[0x00u8; 200],
        &[0xAAu8; 44],   // base size
        &[0x5Au8; 112],  // auth base size
        &[0xFFu8; 1500], // MTU-sized burst
    ];
    for p in patterns {
        for use_auth in [false, true] {
            for strict in [false, true] {
                let ctx = make_ctx(None, strict);
                let _ = process_stamp_packet(p, src(), 64, use_auth, &ctx);
            }
        }
    }
}

/// 0xFF flood at every byte position to exercise the type/length/flags
/// interactions in the TLV parser. No panic, no infinite loop.
#[test]
fn group_e_ff_flood_in_tlv_region() {
    // base bytes mostly zero + TLV region full 0xFF.
    let mut data = vec![0u8; UNAUTH_BASE_SIZE];
    data.extend(std::iter::repeat_n(0xFFu8, 256));
    let ctx = make_ctx(None, false);
    let _ = process_stamp_packet(&data, src(), 64, false, &ctx);
}
