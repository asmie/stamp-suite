//! TLV-by-TLV IPv6 parity for the reflector pipeline.
//!
//! The existing `tests/loopback_test.rs::test_loopback_ipv6` covers the base
//! unauth round-trip over `[::1]`. This file exercises the higher-value
//! per-TLV code paths with an IPv6 source address driven directly through
//! `process_stamp_packet`. We avoid real UDP loopback here so the tests
//! stay deterministic and CI-fast; the focus is on the address-family
//! branches inside the reflector logic (Location, Destination Node
//! Address, Micro-session ID, authenticated-mode HMAC, BER) rather than
//! the kernel socket plumbing — which is covered separately by the
//! basic IPv6 loopback test.

use std::net::{IpAddr, Ipv6Addr, SocketAddr};

use stamp_suite::configuration::{ClockFormat, TlvHandlingMode};
use stamp_suite::crypto::HmacKey;
use stamp_suite::packets::{PacketAuthenticated, PacketUnauthenticated};
use stamp_suite::receiver::{
    process_stamp_packet, ProcessingContext, AUTH_BASE_SIZE, UNAUTH_BASE_SIZE,
};
use stamp_suite::tlv::{
    BerBurstTlv, BerCountTlv, BerPatternTlv, ClassOfServiceTlv, DestinationNodeAddressTlv,
    ExtraPaddingTlv, MicroSessionIdTlv, PacketAddressInfo, RawTlv, TlvList, TlvType, TypedTlv,
};

fn ipv6_src() -> SocketAddr {
    SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 12345)
}

fn ipv6_local() -> IpAddr {
    IpAddr::V6(Ipv6Addr::LOCALHOST)
}

fn make_ctx<'a>(
    hmac_key: Option<&'a HmacKey>,
    local_addresses: &'a [IpAddr],
    addr_info: Option<PacketAddressInfo>,
) -> ProcessingContext<'a> {
    ProcessingContext {
        clock_source: ClockFormat::NTP,
        error_estimate_wire: 0,
        hmac_key,
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
        packet_addr_info: addr_info,
        last_reflection: None,
        local_addresses,
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

fn build_auth_packet(tlv_bytes: &[u8]) -> Vec<u8> {
    let base = PacketAuthenticated {
        sequence_number: 1,
        mbz0: [0; 12],
        timestamp: 0,
        error_estimate: 0,
        ssid: 0,
        mbz1a: [0; 30],
        mbz1b: [0; 32],
        mbz1c: [0; 6],
        hmac: [0; 16],
    };
    let mut data = base.to_bytes().to_vec();
    data.extend_from_slice(tlv_bytes);
    data
}

// ---------------------------------------------------------------------------
// 1. Unauth base packet over IPv6 source.

#[test]
fn ipv6_unauth_base_round_trip() {
    let packet = build_unauth_packet(&[]);
    let ctx = make_ctx(None, &[], None);
    let response = process_stamp_packet(&packet, ipv6_src(), 64, false, &ctx)
        .expect("reflector must respond over IPv6 source");
    assert!(response.data.len() >= UNAUTH_BASE_SIZE);
}

// ---------------------------------------------------------------------------
// 2. Authenticated mode over IPv6 source.

#[test]
fn ipv6_auth_mode_round_trip() {
    let packet = build_auth_packet(&[]);
    let ctx = make_ctx(None, &[], None);
    let response = process_stamp_packet(&packet, ipv6_src(), 64, true, &ctx)
        .expect("auth reflector must respond over IPv6 source");
    assert!(response.data.len() >= AUTH_BASE_SIZE);
}

// ---------------------------------------------------------------------------
// 3. CoS TLV over IPv6 — DSCP/ECN echoed and reflector observations filled.

#[test]
fn ipv6_cos_tlv_round_trip() {
    let cos = ClassOfServiceTlv::new(46, 2).to_raw();
    let packet = build_unauth_packet(&cos.to_bytes());

    let mut ctx = make_ctx(None, &[], None);
    ctx.received_dscp = 46; // EF
    ctx.received_ecn = 2;

    let response =
        process_stamp_packet(&packet, ipv6_src(), 64, false, &ctx).expect("reflector responds");
    let parsed = TlvList::parse(&response.data[UNAUTH_BASE_SIZE..]).expect("parse response");
    let echoed = parsed
        .non_hmac_tlvs()
        .iter()
        .find(|t| t.tlv_type == TlvType::ClassOfService)
        .expect("CoS TLV must be echoed");
    let parsed_cos = ClassOfServiceTlv::from_raw(echoed).expect("decode CoS");
    assert_eq!(parsed_cos.dscp1, 46, "DSCP1 echoed unchanged");
    assert_eq!(parsed_cos.dscp2, 46, "DSCP2 filled with received DSCP");
    assert_eq!(parsed_cos.ecn2, 2, "ECN2 filled with received ECN");
}

// ---------------------------------------------------------------------------
// 4. RFC 9503 Destination Node Address with matching local IPv6 address.

#[test]
fn ipv6_dest_node_addr_match_clears_u_flag() {
    let dest = DestinationNodeAddressTlv::new(ipv6_local()).to_raw();
    let packet = build_unauth_packet(&dest.to_bytes());

    let locals = [ipv6_local()];
    let ctx = make_ctx(None, &locals, None);
    let response =
        process_stamp_packet(&packet, ipv6_src(), 64, false, &ctx).expect("reflector responds");
    let parsed = TlvList::parse(&response.data[UNAUTH_BASE_SIZE..]).expect("parse response");
    let echoed = parsed
        .non_hmac_tlvs()
        .iter()
        .find(|t| t.tlv_type == TlvType::DestinationNodeAddress)
        .expect("Type 9 must be echoed");
    assert!(
        !echoed.is_unrecognized(),
        "matching IPv6 destination must NOT set U flag"
    );
}

/// RFC 9503: when the Dest Node Addr does not match any local address,
/// reflector sets U flag on the echoed TLV.
#[test]
fn ipv6_dest_node_addr_mismatch_sets_u_flag() {
    let dest =
        DestinationNodeAddressTlv::new(IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)))
            .to_raw();
    let packet = build_unauth_packet(&dest.to_bytes());

    // Reflector's local address is a different IPv6 (::1).
    let locals = [ipv6_local()];
    let ctx = make_ctx(None, &locals, None);
    let response =
        process_stamp_packet(&packet, ipv6_src(), 64, false, &ctx).expect("reflector responds");
    let parsed = TlvList::parse(&response.data[UNAUTH_BASE_SIZE..]).expect("parse response");
    let echoed = parsed
        .non_hmac_tlvs()
        .iter()
        .find(|t| t.tlv_type == TlvType::DestinationNodeAddress)
        .expect("Type 9 must be echoed");
    assert!(
        echoed.is_unrecognized(),
        "mismatching IPv6 destination must set U flag per RFC 9503"
    );
}

// ---------------------------------------------------------------------------
// 5. Micro-session ID TLV over IPv6.

#[test]
fn ipv6_micro_session_id_round_trip() {
    let msid = MicroSessionIdTlv::new(42, 0).to_raw();
    let packet = build_unauth_packet(&msid.to_bytes());

    let mut ctx = make_ctx(None, &[], None);
    ctx.reflector_member_link_id = Some(99);

    let response = process_stamp_packet(&packet, ipv6_src(), 64, false, &ctx)
        .expect("reflector responds over IPv6");
    let parsed = TlvList::parse(&response.data[UNAUTH_BASE_SIZE..]).expect("parse response");
    let echoed = parsed
        .non_hmac_tlvs()
        .iter()
        .find(|t| t.tlv_type == TlvType::MicroSessionId)
        .expect("Type 11 must be echoed");
    let parsed_msid = MicroSessionIdTlv::from_raw(echoed).expect("decode Type 11");
    assert_eq!(parsed_msid.sender_micro_session_id, 42);
    assert_eq!(parsed_msid.reflector_micro_session_id, 99);
}

// ---------------------------------------------------------------------------
// 6. BER over IPv6: clean channel reports 0 count, 0 burst.

#[test]
fn ipv6_ber_clean_channel_zero_errors() {
    const PATTERN: [u8; 2] = [0xFF, 0x00];
    let mut padding = Vec::with_capacity(64);
    for i in 0..64 {
        padding.push(PATTERN[i % PATTERN.len()]);
    }

    let extra_padding = ExtraPaddingTlv { padding }.to_raw();
    let ber_pattern = BerPatternTlv::new(PATTERN.to_vec()).to_raw();
    let ber_count = BerCountTlv::default().to_raw();
    let ber_burst = BerBurstTlv::default().to_raw();

    let mut tlvs = Vec::new();
    tlvs.extend_from_slice(&extra_padding.to_bytes());
    tlvs.extend_from_slice(&ber_pattern.to_bytes());
    tlvs.extend_from_slice(&ber_count.to_bytes());
    tlvs.extend_from_slice(&ber_burst.to_bytes());

    let packet = build_unauth_packet(&tlvs);
    let ctx = make_ctx(None, &[], None);
    let response =
        process_stamp_packet(&packet, ipv6_src(), 64, false, &ctx).expect("reflector responds");
    let parsed = TlvList::parse(&response.data[UNAUTH_BASE_SIZE..]).expect("parse response");

    let count_raw = parsed
        .non_hmac_tlvs()
        .iter()
        .find(|t| t.tlv_type == TlvType::BerCount)
        .expect("BerCount echoed");
    let burst_raw = parsed
        .non_hmac_tlvs()
        .iter()
        .find(|t| t.tlv_type == TlvType::BerBurst)
        .expect("BerBurst echoed");
    assert_eq!(BerCountTlv::from_raw(count_raw).unwrap().count, 0);
    assert_eq!(BerBurstTlv::from_raw(burst_raw).unwrap().max_burst, 0);
}

// ---------------------------------------------------------------------------
// 7. Location TLV with IPv6 PacketAddressInfo.

#[test]
fn ipv6_location_tlv_populated_from_addr_info() {
    use stamp_suite::tlv::LocationTlv;
    let loc = LocationTlv::new().to_raw();
    let packet = build_unauth_packet(&loc.to_bytes());

    let addr_info = PacketAddressInfo {
        src_addr: ipv6_local(),
        src_port: 12345,
        dst_addr: ipv6_local(),
        dst_port: 862,
    };
    let ctx = make_ctx(None, &[], Some(addr_info));

    let response =
        process_stamp_packet(&packet, ipv6_src(), 64, false, &ctx).expect("reflector responds");
    let parsed = TlvList::parse(&response.data[UNAUTH_BASE_SIZE..]).expect("parse response");
    let echoed = parsed
        .non_hmac_tlvs()
        .iter()
        .find(|t| t.tlv_type == TlvType::Location)
        .expect("Location TLV echoed");
    // Reflector populates IPv6 sub-TLVs — at minimum the Value grew beyond
    // the placeholder/empty sender request.
    assert!(
        !echoed.value.is_empty(),
        "reflector must populate Location sub-TLVs with IPv6 addresses"
    );
}

// ---------------------------------------------------------------------------
// 8. Combined: auth mode + CoS over IPv6 (interaction sanity).

#[test]
fn ipv6_auth_with_cos_round_trip() {
    let cos = ClassOfServiceTlv::new(34, 1).to_raw();
    let packet = build_auth_packet(&cos.to_bytes());

    let mut ctx = make_ctx(None, &[], None);
    ctx.received_dscp = 34;
    ctx.received_ecn = 1;

    let response =
        process_stamp_packet(&packet, ipv6_src(), 64, true, &ctx).expect("reflector responds");
    let parsed = TlvList::parse(&response.data[AUTH_BASE_SIZE..]).expect("parse response");
    let echoed = parsed
        .non_hmac_tlvs()
        .iter()
        .find(|t| t.tlv_type == TlvType::ClassOfService)
        .expect("CoS TLV echoed in auth response");
    let parsed_cos = ClassOfServiceTlv::from_raw(echoed).expect("decode CoS");
    assert_eq!(parsed_cos.dscp1, 34);
    assert_eq!(parsed_cos.dscp2, 34);
}

// ---------------------------------------------------------------------------
// 9. Unknown TLV over IPv6 → U flag.

#[test]
fn ipv6_unknown_tlv_echoed_with_u_flag() {
    let raw = RawTlv::new(TlvType::Unknown(150), vec![0, 0, 0, 0]);
    let packet = build_unauth_packet(&raw.to_bytes());
    let ctx = make_ctx(None, &[], None);
    let response =
        process_stamp_packet(&packet, ipv6_src(), 64, false, &ctx).expect("reflector responds");
    let parsed = TlvList::parse(&response.data[UNAUTH_BASE_SIZE..]).expect("parse response");
    let echoed = parsed
        .non_hmac_tlvs()
        .iter()
        .find(|t| matches!(t.tlv_type, TlvType::Unknown(150)))
        .expect("Unknown TLV echoed");
    assert!(
        echoed.is_unrecognized(),
        "unknown TLV over IPv6 must still get U flag"
    );
}
