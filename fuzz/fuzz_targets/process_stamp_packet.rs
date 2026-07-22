#![no_main]

use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use libfuzzer_sys::fuzz_target;
use stamp_suite::clock_format::ClockFormat;
use stamp_suite::configuration::TlvHandlingMode;
use stamp_suite::receiver::{process_stamp_packet, ProcessingContext};
use stamp_suite::tlv::{PacketAddressInfo, TimestampMethod};

// Exercises the full reflector processing pipeline end-to-end with
// attacker-controlled bytes: parse -> reflector flag re-derive / HMAC ->
// semantic TLV processing (CoS, timestamp, direct-measurement, location,
// follow-up, dest-node-address, micro-session, return-path, BER, reflected
// headers, reflected-control padding) -> response assembly. The existing fuzz
// targets only cover the low-level parsers in isolation; this covers the
// in-place TLV mutators and length math where any reachable panic would live.
//
// The RAW process_stamp_packet entry point is used on purpose (not the
// panic-isolating wrapper) so libFuzzer surfaces any reachable panic.
fuzz_target!(|data: &[u8]| {
    let local: [IpAddr; 1] = [IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))];
    let local_macs: [[u8; 6]; 1] = [[0x02, 0x00, 0x00, 0x00, 0x00, 0x01]];
    let src = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 12345);

    // Build a context with the optional/amplifying features turned on so those
    // code paths are fuzzed too (the production defaults gate them off).
    let ctx = ProcessingContext {
        clock_source: ClockFormat::NTP,
        error_estimate_wire: 0,
        hmac_key: None,
        hmac_key_set: None,
        require_hmac: false,
        session_manager: None,
        stateful_reflector: true,
        tlv_mode: TlvHandlingMode::Echo,
        verify_tlv_hmac: false,
        strict_packets: false,
        received_dscp: 0,
        received_ecn: 0,
        reflector_rx_count: Some(1),
        reflector_tx_count: Some(2),
        packet_addr_info: Some(PacketAddressInfo {
            src_addr: src.ip(),
            src_port: src.port(),
            dst_addr: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            dst_port: 862,
        }),
        last_reflection: Some((0, 0)),
        local_addresses: &local,
        local_macs: &local_macs,
        sender_port: src.port(),
        rx_timestamp: Some(1),
        rx_method: TimestampMethod::SwLocal,
        tx_method: TimestampMethod::SwLocal,
        return_path_allow_alternate: true,
        reflector_member_link_id: Some(1),
        captured_headers: None,
        reflected_control_max_count: 16,
        reflected_control_max_size: 1500,
        reflected_control_min_interval_ns: 1_000,
    };

    // Run both the unauthenticated and authenticated assembly paths.
    let _ = process_stamp_packet(data, src, 64, false, &ctx);
    let _ = process_stamp_packet(data, src, 64, true, &ctx);
});
