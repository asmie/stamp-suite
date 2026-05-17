//! Property-based tests for the TLV and packet parsers.
//!
//! Two flavours:
//!
//! 1. **Round-trip properties** — for each typed TLV, generate arbitrary
//!    valid values and assert `parse(serialize(t)) == Ok(t)`. Catches
//!    encoder/decoder asymmetries that hand-written tests miss.
//!
//! 2. **No-panic properties** — feed `RawTlv::parse` /
//!    `TlvList::parse_lenient` / `PacketUnauthenticated::from_bytes_lenient`
//!    / the AgentX decoder arbitrary byte buffers and assert no panic.
//!    These complement the libfuzzer harnesses under `fuzz/` by exercising
//!    the same code paths in default `cargo test` runs.

use proptest::prelude::*;

use stamp_suite::packets::{PacketAuthenticated, PacketUnauthenticated};
use stamp_suite::tlv::{
    AccessReportTlv, BerBurstTlv, BerCountTlv, ClassOfServiceTlv, DirectMeasurementTlv,
    ExtraPaddingTlv, MicroSessionIdTlv, RawTlv, TlvList, TypedTlv,
};

// ---------------------------------------------------------------------------
// Round-trip properties: serialize → parse → equal.

proptest! {
    #![proptest_config(ProptestConfig { cases: 256, .. ProptestConfig::default() })]

    #[test]
    fn prop_cos_round_trip(dscp1 in 0u8..64, ecn1 in 0u8..4, dscp2 in 0u8..64, ecn2 in 0u8..4, rp in 0u8..4) {
        let original = ClassOfServiceTlv { dscp1, ecn1, dscp2, ecn2, rp };
        let raw = original.to_raw();
        let parsed = ClassOfServiceTlv::from_raw(&raw).expect("CoS round-trip parse");
        prop_assert_eq!(parsed, original);
    }

    #[test]
    fn prop_access_report_round_trip(
        access_id in 0u8..16,
        return_code in 0u8..16,
        active in any::<bool>(),
    ) {
        let _ = active;
        let original = AccessReportTlv {
            access_id,
            return_code,
        };
        let raw = original.to_raw();
        let parsed = AccessReportTlv::from_raw(&raw).expect("Access Report round-trip");
        prop_assert_eq!(parsed, original);
    }

    #[test]
    fn prop_direct_measurement_round_trip(
        sender_tx in any::<u32>(),
        reflector_rx in any::<u32>(),
        reflector_tx in any::<u32>(),
    ) {
        let original = DirectMeasurementTlv {
            sender_tx_count: sender_tx,
            reflector_rx_count: reflector_rx,
            reflector_tx_count: reflector_tx,
        };
        let raw = original.to_raw();
        let parsed = DirectMeasurementTlv::from_raw(&raw).expect("DM round-trip");
        prop_assert_eq!(parsed, original);
    }

    #[test]
    fn prop_micro_session_id_round_trip(sender_id in any::<u16>(), reflector_id in any::<u16>()) {
        let original = MicroSessionIdTlv {
            sender_micro_session_id: sender_id,
            reflector_micro_session_id: reflector_id,
        };
        let raw = original.to_raw();
        let parsed = MicroSessionIdTlv::from_raw(&raw).expect("Micro-session round-trip");
        prop_assert_eq!(parsed, original);
    }

    #[test]
    fn prop_ber_count_round_trip(count in any::<u32>()) {
        let original = BerCountTlv { count };
        let raw = original.to_raw();
        let parsed = BerCountTlv::from_raw(&raw).expect("BerCount round-trip");
        prop_assert_eq!(parsed, original);
    }

    #[test]
    fn prop_ber_burst_round_trip(max_burst in any::<u32>()) {
        let original = BerBurstTlv { max_burst };
        let raw = original.to_raw();
        let parsed = BerBurstTlv::from_raw(&raw).expect("BerBurst round-trip");
        prop_assert_eq!(parsed, original);
    }

    #[test]
    fn prop_extra_padding_round_trip(bytes in prop::collection::vec(any::<u8>(), 0..256)) {
        let original = ExtraPaddingTlv { padding: bytes };
        let raw = original.to_raw();
        // ExtraPaddingTlv::from_raw is infallible (returns Self).
        let parsed = ExtraPaddingTlv::from_raw(&raw);
        prop_assert_eq!(parsed, original);
    }
}

// ---------------------------------------------------------------------------
// No-panic properties on arbitrary byte buffers.

proptest! {
    #![proptest_config(ProptestConfig { cases: 1024, .. ProptestConfig::default() })]

    /// RawTlv parser must never panic on arbitrary bytes. It may return
    /// Ok or Err; either is fine.
    #[test]
    fn prop_raw_tlv_parse_no_panic(bytes in prop::collection::vec(any::<u8>(), 0..512)) {
        // Catch any panic in this thread — return value is whatever parse
        // produced.
        let _ = RawTlv::parse(&bytes);
    }

    /// TlvList::parse never panics on arbitrary input — strict version.
    #[test]
    fn prop_tlv_list_parse_no_panic(bytes in prop::collection::vec(any::<u8>(), 0..1024)) {
        let _ = TlvList::parse(&bytes);
    }

    /// TlvList::parse_lenient never panics on arbitrary input.
    #[test]
    fn prop_tlv_list_parse_lenient_no_panic(bytes in prop::collection::vec(any::<u8>(), 0..1024)) {
        let _ = TlvList::parse_lenient(&bytes);
    }

    /// PacketUnauthenticated::from_bytes never panics; the strict variant
    /// returns Err on short input.
    #[test]
    fn prop_packet_unauth_from_bytes_no_panic(bytes in prop::collection::vec(any::<u8>(), 0..256)) {
        let _ = PacketUnauthenticated::from_bytes(&bytes);
    }

    /// PacketUnauthenticated::from_bytes_lenient never panics — zero-fills
    /// missing tail per RFC 8762 §4.6.
    #[test]
    fn prop_packet_unauth_from_bytes_lenient_no_panic(
        bytes in prop::collection::vec(any::<u8>(), 0..256),
    ) {
        let _ = PacketUnauthenticated::from_bytes_lenient(&bytes);
    }

    /// PacketAuthenticated::from_bytes never panics.
    #[test]
    fn prop_packet_auth_from_bytes_no_panic(bytes in prop::collection::vec(any::<u8>(), 0..256)) {
        let _ = PacketAuthenticated::from_bytes(&bytes);
    }
}

// ---------------------------------------------------------------------------
// AgentX decoders (only when the snmp feature is on).

#[cfg(feature = "snmp")]
mod agentx_props {
    use super::*;
    use stamp_suite::snmp::agentx;

    proptest! {
        #![proptest_config(ProptestConfig { cases: 1024, .. ProptestConfig::default() })]

        #[test]
        fn prop_agentx_decode_header_no_panic(bytes in prop::collection::vec(any::<u8>(), 0..64)) {
            let _ = agentx::decode_header(&bytes);
        }

        #[test]
        fn prop_agentx_decode_oid_no_panic(bytes in prop::collection::vec(any::<u8>(), 0..256)) {
            let _ = agentx::decode_oid(&bytes);
        }

        #[test]
        fn prop_agentx_decode_search_range_no_panic(bytes in prop::collection::vec(any::<u8>(), 0..512)) {
            let _ = agentx::decode_search_range(&bytes);
        }
    }
}
