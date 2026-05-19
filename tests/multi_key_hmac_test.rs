//! Per-SSID HMAC key set (B6) end-to-end integration through
//! `process_stamp_packet`.
//!
//! Pins three invariants:
//! 1. **Single-key path stays compatible** — when only `hmac_key` is set
//!    (legacy `--hmac-key` / `--hmac-key-file`), the receiver behaves as
//!    before regardless of the packet's SSID.
//! 2. **Per-SSID happy path** — when `hmac_key_set` is set, the
//!    reflector picks the per-SSID key for verification and produces a
//!    valid response.
//! 3. **Unknown SSID with no default** — drops the packet (returns
//!    None) when no key resolves for the requested SSID.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use stamp_suite::configuration::{ClockFormat, TlvHandlingMode};
use stamp_suite::crypto::{compute_packet_hmac, HmacKey, HmacKeySet};
use stamp_suite::packets::PacketAuthenticated;
use stamp_suite::receiver::{process_stamp_packet, ProcessingContext, AUTH_BASE_SIZE};

const AUTH_HMAC_OFFSET: usize = 96;

fn src() -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 12345)
}

fn make_ctx<'a>(
    hmac_key: Option<&'a HmacKey>,
    hmac_key_set: Option<&'a HmacKeySet>,
) -> ProcessingContext<'a> {
    ProcessingContext {
        clock_source: ClockFormat::NTP,
        error_estimate_wire: 0,
        hmac_key,
        hmac_key_set,
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

/// Builds a signed authenticated STAMP packet with the given SSID.
fn build_signed_auth_packet(ssid: u16, key: &HmacKey) -> Vec<u8> {
    let mut packet = PacketAuthenticated {
        sequence_number: 1,
        mbz0: [0; 12],
        timestamp: 0,
        error_estimate: 0,
        ssid,
        mbz1a: [0; 30],
        mbz1b: [0; 32],
        mbz1c: [0; 6],
        hmac: [0; 16],
    };
    // Sign: serialise once with HMAC zeroed, compute HMAC over the first
    // 96 bytes, then overwrite the HMAC field and serialise again.
    let mut bytes = packet.to_bytes();
    let hmac = compute_packet_hmac(key, &bytes, AUTH_HMAC_OFFSET);
    packet.hmac = hmac;
    bytes = packet.to_bytes();
    bytes.to_vec()
}

// ---------------------------------------------------------------------------
// 1. Legacy single-key path.

#[test]
fn legacy_single_key_accepts_packet_with_any_ssid() {
    let key = HmacKey::new(vec![0xAA; 16]).unwrap();
    let packet = build_signed_auth_packet(0, &key);
    let ctx = make_ctx(Some(&key), None);
    let response = process_stamp_packet(&packet, src(), 64, true, &ctx)
        .expect("legacy single-key path must accept SSID=0");
    assert!(response.data.len() >= AUTH_BASE_SIZE);
}

#[test]
fn legacy_single_key_accepts_packet_with_nonzero_ssid() {
    // Backward compat: the historic single-key receiver had no SSID
    // concept, so a non-zero SSID must still be accepted under the same
    // key. The HmacKeySet wrapper (with_default) handles this case
    // because for_ssid(any) falls back to the default key.
    let key = HmacKey::new(vec![0xBB; 16]).unwrap();
    let packet = build_signed_auth_packet(42, &key);
    let ctx = make_ctx(Some(&key), None);
    let response = process_stamp_packet(&packet, src(), 64, true, &ctx)
        .expect("legacy path must accept SSID=42 too");
    assert!(response.data.len() >= AUTH_BASE_SIZE);
}

// ---------------------------------------------------------------------------
// 2. Per-SSID happy path.

#[test]
fn per_ssid_key_set_accepts_matching_ssid() {
    let key_a = HmacKey::new(vec![0xAA; 16]).unwrap();
    let key_b = HmacKey::new(vec![0xBB; 16]).unwrap();

    let mut set = HmacKeySet::new();
    set.insert(1, key_a);
    set.insert(2, key_b.clone());

    // Build a packet signed with key_b under SSID=2.
    let packet = build_signed_auth_packet(2, &key_b);

    let ctx = make_ctx(None, Some(&set));
    let response = process_stamp_packet(&packet, src(), 64, true, &ctx)
        .expect("per-SSID key must verify and reflect");
    assert!(response.data.len() >= AUTH_BASE_SIZE);
}

#[test]
fn per_ssid_key_set_rejects_wrong_key_for_ssid() {
    let key_a = HmacKey::new(vec![0xAA; 16]).unwrap();
    let key_b = HmacKey::new(vec![0xBB; 16]).unwrap();

    let mut set = HmacKeySet::new();
    set.insert(1, key_a);
    set.insert(2, key_b);

    // Sign with key_a but advertise SSID=2 → reflector picks key_b, HMAC
    // verification fails, packet is dropped.
    let wrong_signer = HmacKey::new(vec![0xAA; 16]).unwrap();
    let packet = build_signed_auth_packet(2, &wrong_signer);

    let ctx = make_ctx(None, Some(&set));
    let response = process_stamp_packet(&packet, src(), 64, true, &ctx);
    assert!(
        response.is_none(),
        "packet signed with wrong key for its SSID must be dropped"
    );
}

// ---------------------------------------------------------------------------
// 3. Unknown SSID handling.

#[test]
fn per_ssid_key_set_unknown_ssid_no_default_drops() {
    // Set has entries for SSID 1 and 2 only; no default.
    let key_a = HmacKey::new(vec![0xAA; 16]).unwrap();
    let mut set = HmacKeySet::new();
    set.insert(1, key_a.clone());

    // Build a signed packet with SSID=99 — the set returns None for that
    // SSID; the auth check sees no key → if require_hmac is off, the
    // legacy path silently accepts (since no key means "open"); to make
    // the test meaningful we set the require_hmac bit so the reflector
    // drops.
    let packet = build_signed_auth_packet(99, &key_a);
    let mut ctx = make_ctx(None, Some(&set));
    ctx.require_hmac = true;

    let response = process_stamp_packet(&packet, src(), 64, true, &ctx);
    assert!(
        response.is_none(),
        "unknown SSID with no default + require_hmac must drop the packet"
    );
}

#[test]
fn per_ssid_key_set_unknown_ssid_falls_back_to_default() {
    // Set has SSID=1 plus a default fallback key.
    let key_a = HmacKey::new(vec![0xAA; 16]).unwrap();
    let default_key = HmacKey::new(vec![0xCC; 16]).unwrap();
    let mut set = HmacKeySet::new();
    set.insert(1, key_a);
    set.set_default(default_key.clone());

    // Sign with the default key under SSID=99 → reflector falls back to
    // default and verification succeeds.
    let packet = build_signed_auth_packet(99, &default_key);

    let ctx = make_ctx(None, Some(&set));
    let response = process_stamp_packet(&packet, src(), 64, true, &ctx)
        .expect("default key must verify when SSID has no explicit entry");
    assert!(response.data.len() >= AUTH_BASE_SIZE);
}

/// Regression for the bug Cursor's bugbot caught in PR #5: the
/// non-TLV authenticated response path used to pass `ctx.hmac_key`
/// instead of the per-SSID-resolved key, so when `--hmac-key-dir`
/// was the key source (ctx.hmac_key = None), authenticated packets
/// without TLVs got responses signed with no key at all.
///
/// This test sends a no-TLV authenticated packet, verifies via
/// per-SSID lookup, and asserts the response's last 16 bytes are
/// not all zero — they're the response HMAC, which is None-keyed
/// in the buggy version and therefore left at the initial zeros.
#[test]
fn per_ssid_key_set_signs_no_tlv_response() {
    let key = HmacKey::new(vec![0xCC; 16]).unwrap();
    let mut set = HmacKeySet::new();
    set.insert(7, key.clone());

    // Build a signed auth packet with SSID=7, no TLVs.
    let packet = build_signed_auth_packet(7, &key);
    assert_eq!(packet.len(), 112, "no-TLV auth packet is exactly 112 bytes");

    let ctx = make_ctx(None, Some(&set));
    let response = process_stamp_packet(&packet, src(), 64, true, &ctx).expect("must reflect");
    // Reflected authenticated packet HMAC lives in the last 16 bytes
    // of the 112-byte base. The buggy path left these zero.
    let hmac_field = &response.data[response.data.len() - 16..];
    assert!(
        hmac_field.iter().any(|&b| b != 0),
        "response HMAC must be non-zero (real signature, not the \
         placeholder left by an unkeyed assembler)"
    );
}
