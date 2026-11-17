//! A reflector processing context for tests that call `process_stamp_packet`.
#![allow(dead_code)] // Each integration target uses a different helper subset.

use stamp_suite::{
    configuration::{ClockFormat, TlvHandlingMode},
    receiver::{ProcessingContext, REFLECTED_CONTROL_MAX_RATE, REFLECTED_CONTROL_MAX_VOLUME},
    session::ReplayVerdict,
    tlv::{SyncSource, TimestampMethod},
};

/// Open mode, stateful, TLV echo, permissive CoS policy and no packet
/// metadata. Tests override what they exercise with struct update syntax:
/// `ProcessingContext { strict_packets: true, ..reflector_context() }`.
pub fn reflector_context<'a>() -> ProcessingContext<'a> {
    ProcessingContext {
        ingress_ifindex: None,
        packet_local_addr: None,
        replay_verdict: ReplayVerdict::New,
        clock_source: ClockFormat::NTP,
        clock_sync_source: SyncSource::Local,
        hardware_clock_sync_source: SyncSource::Local,
        error_estimate_wire: 0,
        hmac_key: None,
        hmac_key_set: None,
        require_hmac: false,
        session_manager: None,
        stateful_reflector: true,
        tlv_mode: TlvHandlingMode::Echo,
        verify_tlv_hmac: false,
        strict_packets: false,
        validate_base_fields: false,
        validate_tlv_framing: false,
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
        reflect_fixed_header: true,
        reflect_ipv6_ext_header: true,
        captured_headers: None,
        reflected_control_max_count: 16,
        reflected_control_max_size: 1500,
        reflected_control_min_interval_ns: 1_000,
        reflected_control_max_rate: REFLECTED_CONTROL_MAX_RATE,
        reflected_control_max_volume: REFLECTED_CONTROL_MAX_VOLUME,
        rx_timestamp: None,
        rx_method: TimestampMethod::SwLocal,
        last_reflection_method: TimestampMethod::SwLocal,
    }
}
