#![no_main]

use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use libfuzzer_sys::fuzz_target;
use stamp_suite::clock_format::ClockFormat;
use stamp_suite::configuration::TlvHandlingMode;
use stamp_suite::crypto::HmacKey;
use stamp_suite::receiver::{process_stamp_packet, CapturedHeaders, ProcessingContext};
use stamp_suite::tlv::{PacketAddressInfo, TimestampMethod};

// Fuzzes parsing, HMAC checks, TLV mutation, and response assembly together.
// Call the raw entry point so packet-processing panics reach libFuzzer.
//
// The first byte selects a key, required and verified HMACs, strict parsing,
// ignore mode and captured headers. With captured headers, the packet bytes
// also serve as the received IPv6 fixed and extension headers.
fuzz_target!(|data: &[u8]| {
    let Some((&mode, data)) = data.split_first() else {
        return;
    };
    let key = HmacKey::new(vec![0xAB; 16]).unwrap();
    let keyed = mode & 1 != 0;
    let captured = CapturedHeaders {
        fixed_headers: data.get(..40).map(<[u8]>::to_vec).into_iter().collect(),
        ipv6_ext_headers: data.get(40..).unwrap_or_default().to_vec(),
    };
    let local: [IpAddr; 1] = [IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))];
    let local_macs: [[u8; 6]; 1] = [[0x02, 0x00, 0x00, 0x00, 0x00, 0x01]];
    let src = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 12345);

    // Build a context with the optional/amplifying features turned on so those
    // code paths are fuzzed too (the production defaults gate them off).
    let ctx = ProcessingContext {
        ingress_ifindex: None,
        packet_local_addr: None,
        replay_verdict: stamp_suite::session::ReplayVerdict::New,
        clock_source: ClockFormat::NTP,
        clock_sync_source: stamp_suite::tlv::SyncSource::Local,
        hardware_clock_sync_source: stamp_suite::tlv::SyncSource::Local,
        error_estimate_wire: 0,
        hmac_key: keyed.then_some(&key),
        hmac_key_set: None,
        require_hmac: keyed && mode & 2 != 0,
        session_manager: None,
        stateful_reflector: true,
        tlv_mode: if mode & 16 != 0 {
            TlvHandlingMode::Ignore
        } else {
            TlvHandlingMode::Echo
        },
        verify_tlv_hmac: mode & 4 != 0,
        strict_packets: mode & 8 != 0,
        received_dscp: 0,
        received_ecn: 0,
        reflector_rx_count: Some(1),
        reflector_tx_count: Some(2),
        packet_addr_info: Some(PacketAddressInfo {
            src_addr: src.ip(),
            src_port: src.port(),
            dst_addr: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            dst_port: 862,
            src_mac: None,
        }),
        last_reflection: Some((0, 0)),
        location_disclosure: Default::default(),
        cos_policy: stamp_suite::cos_policy::permissive(),
        local_addresses: &local,
        local_macs: &local_macs,
        sender_port: src.port(),
        rx_timestamp: Some(1),
        rx_method: TimestampMethod::SwLocal,
        last_reflection_method: TimestampMethod::SwLocal,
        return_path_allow_alternate: true,
        reflector_member_link_id: Some(1),
        captured_headers: (mode & 32 != 0).then_some(&captured),
        reflected_control_max_count: 16,
        reflected_control_max_size: 1500,
        reflected_control_min_interval_ns: 1_000,
        reflected_control_max_rate: stamp_suite::receiver::REFLECTED_CONTROL_MAX_RATE,
        reflected_control_max_volume: stamp_suite::receiver::REFLECTED_CONTROL_MAX_VOLUME,
    };

    // Run both the unauthenticated and authenticated assembly paths.
    let _ = process_stamp_packet(data, src, 64, false, &ctx);
    let _ = process_stamp_packet(data, src, 64, true, &ctx);
});
