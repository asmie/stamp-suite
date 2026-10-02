use super::*;
use crate::packets::{ExtendedPacketAuthenticated, ExtendedPacketUnauthenticated};

// --- draft-ietf-ippm-stamp-ext-hdr-15 header-reflection request TLVs ----

#[cfg(target_os = "linux")]
fn ext_hdr_conf(extra: &[&str]) -> crate::configuration::Configuration {
    use clap::Parser;
    let mut args = vec!["test", "--remote-addr"];
    // Default to an IPv6 destination so ext-hdr flags are meaningful.
    args.push("2001:db8::1");
    args.extend_from_slice(extra);
    let conf =
        crate::configuration::Configuration::try_parse_from(args).expect("parse ext-hdr test args");
    conf.validate().expect("validate ext-hdr test conf");
    conf
}

#[cfg(target_os = "linux")]
fn tlvs_of(tlvs: &[RawTlv], ty: TlvType) -> Vec<&RawTlv> {
    tlvs.iter().filter(|t| t.tlv_type == ty).collect()
}

#[test]
#[cfg(target_os = "linux")]
fn ext_hdr_multi_requests_emit_multiple_type246_tlvs_in_order() {
    // §3.1 rule 2: multiple occurrences → multiple Type-246 TLVs with
    // matching lengths, in order. The inline `LEN:SELECTORHEX` form carries
    // a per-occurrence §5.1 selector.
    let conf = ext_hdr_conf(&[
        "--reflected-ipv6-ext-hdr",
        "8",
        "--reflected-ipv6-ext-hdr",
        "16:1101010400000000",
        "--attach-ext-hdr",
        "hbh",
        "--attach-ext-hdr",
        "dest:00010104000000000000000000000000",
    ]);
    let tlvs = reflected_header_request_tlvs(&conf);
    let ext = tlvs_of(&tlvs, TlvType::ReflectedIpv6ExtHdr);
    assert_eq!(ext.len(), 2, "two occurrences → two Type-246 TLVs");
    assert_eq!(ext[0].value.len(), 8);
    assert!(
        ext[0].value.iter().all(|&b| b == 0),
        "bare-length occurrence has an all-zeros Requested field"
    );
    assert_eq!(ext[1].value.len(), 16, "inline LEN is honoured");
    assert_eq!(
        &ext[1].value[..4],
        &[0x11, 0x01, 0x01, 0x04],
        "inline selector populates the Requested field"
    );
}

#[test]
#[cfg(target_os = "linux")]
fn ext_hdr_single_form_backward_compatible_with_standalone_selector() {
    let conf = ext_hdr_conf(&[
        "--reflected-ipv6-ext-hdr",
        "--reflected-ipv6-ext-hdr-selector",
        "1100010400000000",
        "--attach-ext-hdr",
        "dest",
    ]);
    let tlvs = reflected_header_request_tlvs(&conf);
    let ext = tlvs_of(&tlvs, TlvType::ReflectedIpv6ExtHdr);
    assert_eq!(ext.len(), 1);
    assert_eq!(&ext[0].value[..8], &[0x11, 0, 1, 4, 0, 0, 0, 0]);
}

#[test]
fn fixed_hdr_multi_requests_are_rejected_without_multiple_originated_headers() {
    use clap::Parser;
    let conf =
        Configuration::parse_from(["test", "--reflected-fixed-hdr", "--reflected-fixed-hdr"]);
    assert!(conf
        .validate()
        .unwrap_err()
        .to_string()
        .contains("only one fixed IP header"));
}

#[test]
#[cfg(target_os = "linux")]
fn fixed_hdr_before_ext_hdr_per_section_3_4() {
    // §3.3: every Type-247 TLV MUST precede every Type-246 TLV.
    let conf = ext_hdr_conf(&[
        "--attach-ext-hdr",
        "dest",
        "--reflected-ipv6-ext-hdr",
        "--reflected-fixed-hdr",
    ]);
    let tlvs = reflected_header_request_tlvs(&conf);
    let first_246 = tlvs
        .iter()
        .position(|t| t.tlv_type == TlvType::ReflectedIpv6ExtHdr);
    let last_247 = tlvs
        .iter()
        .rposition(|t| t.tlv_type == TlvType::ReflectedFixedHdr);
    assert!(last_247.unwrap() < first_246.unwrap(), "247 before 246");
}

#[test]
#[cfg(target_os = "linux")]
fn attach_ext_hdr_emits_matching_type246_request() {
    // §3.1: attaching a real header MUST add a corresponding Type-246 TLV.
    // Default (no HEX) is an 8-octet header ⇒ Length 8, all-zeros Requested.
    let conf = ext_hdr_conf(&["--attach-ext-hdr", "dest"]);
    let tlvs = reflected_header_request_tlvs(&conf);
    let ext = tlvs_of(&tlvs, TlvType::ReflectedIpv6ExtHdr);
    assert_eq!(ext.len(), 1, "one attached header → one Type-246 TLV");
    assert_eq!(ext[0].value.len(), 8);
    assert!(ext[0].value.iter().all(|&b| b == 0));
}

#[test]
#[cfg(target_os = "linux")]
fn attach_ext_hdr_custom_hex_sizes_the_request_tlv() {
    // A 16-octet attached header ⇒ a Length-16 Type-246 request TLV.
    let conf = ext_hdr_conf(&["--attach-ext-hdr", "hbh:00010104000000000000000000000000"]);
    let tlvs = reflected_header_request_tlvs(&conf);
    let ext = tlvs_of(&tlvs, TlvType::ReflectedIpv6ExtHdr);
    assert_eq!(ext.len(), 1);
    assert_eq!(ext[0].value.len(), 16);
}

// --- Sender MTU enforcement (draft-ietf-ippm-stamp-ext-hdr-15 §4.2/§6.2) --

#[test]
fn enforce_egress_mtu_trims_header_tlvs_to_fit() {
    // Three 40-byte Type-247 TLVs (44 bytes on the wire each) plus 100 bytes
    // of fixed overhead = 232 bytes. An MTU of 150 forces two removals.
    let mut tlvs: Vec<RawTlv> = (0..3)
        .map(|_| ReflectedFixedHdrTlv::request_with_capacity(40).to_raw())
        .collect();
    enforce_egress_mtu(&mut tlvs, 150, 100);
    let remaining = tlvs
        .iter()
        .filter(|t| t.tlv_type == TlvType::ReflectedFixedHdr)
        .count();
    // 100 + 44 = 144 <= 150; 100 + 88 = 188 > 150 ⇒ exactly one survives.
    assert_eq!(remaining, 1, "trimmed to fit the MTU");
}

#[test]
fn enforce_egress_mtu_keeps_non_header_tlvs() {
    // A large non-header TLV that alone busts the MTU must NOT be removed —
    // the draft's removal rule is specific to Types 246/247.
    let mut tlvs = vec![
        ExtraPaddingTlv::new_zeros(200).to_raw(),
        ReflectedFixedHdrTlv::request_with_capacity(40).to_raw(),
    ];
    enforce_egress_mtu(&mut tlvs, 100, 50);
    assert!(
        tlvs.iter().any(|t| t.tlv_type == TlvType::ExtraPadding),
        "non-header padding TLV is preserved"
    );
    assert!(
        !tlvs
            .iter()
            .any(|t| t.tlv_type == TlvType::ReflectedFixedHdr),
        "the header TLV is removed first"
    );
}

#[test]
fn enforce_egress_mtu_noop_when_fits() {
    let mut tlvs = vec![ReflectedFixedHdrTlv::request_with_capacity(20).to_raw()];
    let before = tlvs.len();
    enforce_egress_mtu(&mut tlvs, 1500, 100);
    assert_eq!(tlvs.len(), before, "no removal when the packet fits");
}

// --- AccessReportRetransmitState (RFC 8972 §4.6) -----------------------

#[test]
fn test_access_report_defaults_match_rfc_8972_4_6() {
    // "The default value of the retransmission timer for the Access
    // Report TLV SHOULD be three seconds."
    assert_eq!(DEFAULT_ACCESS_REPORT_TIMEOUT, Duration::from_secs(3));
    // "This retransmission SHOULD be repeated up to four times before
    // the procedure is aborted."
    assert_eq!(DEFAULT_ACCESS_REPORT_RETRIES, 4);
}

#[test]
fn test_access_report_state_fresh_is_pending() {
    let state = AccessReportRetransmitState::new(Duration::from_secs(3), 4);
    assert_eq!(state.outcome(), AccessReportOutcome::Pending);
    assert_eq!(state.retransmissions(), 0);
}

#[test]
fn test_access_report_first_tick_attaches_and_arms() {
    let mut state = AccessReportRetransmitState::new(Duration::from_secs(3), 4);
    let now = Instant::now();
    assert!(state.tick(now), "first tick must attach the TLV");
    assert_eq!(state.outcome(), AccessReportOutcome::Pending);
    assert_eq!(state.retransmissions(), 0);
}

/// A fresh state machine has not started: the sender's post-loop wait is
/// gated on `has_started() && !is_terminal()`, so a `--count 0` run
/// (main loop never ticks) must not enter it and originate packets.
#[test]
fn test_access_report_fresh_state_has_not_started() {
    let mut state = AccessReportRetransmitState::new(Duration::from_secs(3), 4);
    assert!(!state.has_started(), "fresh state must not have started");
    assert!(
        !state.has_started() || state.is_terminal(),
        "the post-loop wait guard must be false for a fresh state"
    );
    // The first tick (the main loop's original send) starts it.
    assert!(state.tick(Instant::now()));
    assert!(state.has_started());
    assert!(state.has_started() && !state.is_terminal());
}

#[test]
fn test_access_report_tick_before_deadline_does_not_reattach() {
    let mut state = AccessReportRetransmitState::new(Duration::from_secs(3), 4);
    let now = Instant::now();
    assert!(state.tick(now));
    // Still well before the 3s deadline.
    assert!(!state.tick(now + Duration::from_millis(500)));
    assert_eq!(state.retransmissions(), 0);
}

#[test]
fn test_access_report_tick_after_deadline_retransmits() {
    let mut state = AccessReportRetransmitState::new(Duration::from_secs(3), 4);
    let now = Instant::now();
    assert!(state.tick(now));
    let after_expiry = now + Duration::from_secs(3) + Duration::from_millis(1);
    assert!(
        state.tick(after_expiry),
        "expired timer must trigger a retransmission"
    );
    assert_eq!(state.retransmissions(), 1);
    assert_eq!(state.outcome(), AccessReportOutcome::Pending);
}

#[test]
fn test_access_report_retries_exhausted_then_aborted() {
    let mut state = AccessReportRetransmitState::new(Duration::from_secs(1), 2);
    let mut now = Instant::now();
    assert!(state.tick(now)); // original send (attempt 0)
    now += Duration::from_secs(1) + Duration::from_millis(1);
    assert!(state.tick(now)); // retransmission 1
    now += Duration::from_secs(1) + Duration::from_millis(1);
    assert!(state.tick(now)); // retransmission 2 (== max_retries)
    assert_eq!(state.retransmissions(), 2);
    assert_eq!(state.outcome(), AccessReportOutcome::Pending);

    // Third expiry past the retry budget aborts the procedure.
    now += Duration::from_secs(1) + Duration::from_millis(1);
    assert!(!state.tick(now), "aborting must not request another attach");
    assert_eq!(state.outcome(), AccessReportOutcome::Aborted);
    assert_eq!(
        state.retransmissions(),
        2,
        "aborting itself is not counted as a retransmission"
    );

    // Aborted is terminal: further ticks never attach again.
    now += Duration::from_secs(10);
    assert!(!state.tick(now));
    assert_eq!(state.outcome(), AccessReportOutcome::Aborted);
}

#[test]
fn test_access_report_zero_retries_aborts_on_first_expiry() {
    // RFC 8972 §4.6 MUST: operators must be able to control the retry
    // count, including down to 0 (abort immediately, no retransmits).
    let mut state = AccessReportRetransmitState::new(Duration::from_secs(1), 0);
    let now = Instant::now();
    assert!(state.tick(now));
    let after_expiry = now + Duration::from_secs(1) + Duration::from_millis(1);
    assert!(!state.tick(after_expiry));
    assert_eq!(state.outcome(), AccessReportOutcome::Aborted);
    assert_eq!(state.retransmissions(), 0);
}

#[test]
fn test_access_report_acknowledge_before_deadline_disarms() {
    let mut state = AccessReportRetransmitState::new(Duration::from_secs(3), 4);
    let now = Instant::now();
    assert!(state.tick(now));
    state.acknowledge();
    assert_eq!(state.outcome(), AccessReportOutcome::Acknowledged);

    // Acknowledged is terminal: no further attach, ever, even long past
    // where the original deadline would have expired.
    assert!(!state.tick(now + Duration::from_secs(30)));
    assert_eq!(state.outcome(), AccessReportOutcome::Acknowledged);
}

#[test]
fn test_access_report_acknowledge_after_retransmit_disarms_and_stops() {
    let mut state = AccessReportRetransmitState::new(Duration::from_secs(1), 4);
    let now = Instant::now();
    assert!(state.tick(now));
    let after_expiry = now + Duration::from_secs(1) + Duration::from_millis(1);
    assert!(state.tick(after_expiry)); // retransmission 1
    assert_eq!(state.retransmissions(), 1);

    state.acknowledge();
    assert_eq!(state.outcome(), AccessReportOutcome::Acknowledged);
    assert_eq!(
        state.retransmissions(),
        1,
        "retransmission count survives acknowledgment for reporting"
    );
    assert!(!state.tick(after_expiry + Duration::from_secs(10)));
}

#[test]
fn test_access_report_acknowledge_before_any_send_is_noop() {
    // An ack cannot arrive before the TLV was ever sent — guards
    // against a caller wiring this up backwards.
    let mut state = AccessReportRetransmitState::new(Duration::from_secs(3), 4);
    state.acknowledge();
    assert_eq!(state.outcome(), AccessReportOutcome::Pending);
}

#[test]
fn test_access_report_acknowledge_after_aborted_is_noop() {
    let mut state = AccessReportRetransmitState::new(Duration::from_secs(1), 0);
    let now = Instant::now();
    assert!(state.tick(now));
    assert!(!state.tick(now + Duration::from_secs(2)));
    assert_eq!(state.outcome(), AccessReportOutcome::Aborted);

    state.acknowledge();
    assert_eq!(
        state.outcome(),
        AccessReportOutcome::Aborted,
        "a stray ack must not resurrect an aborted procedure"
    );
}

#[test]
fn test_access_report_summary_reflects_state() {
    let mut state = AccessReportRetransmitState::new(Duration::from_secs(1), 4);
    let now = Instant::now();
    assert!(state.tick(now));
    assert!(state.tick(now + Duration::from_secs(1) + Duration::from_millis(1)));
    state.acknowledge();
    let summary = state.summary();
    assert_eq!(summary.outcome, AccessReportOutcome::Acknowledged);
    assert_eq!(summary.retransmissions, 1);
}

#[test]
fn reflected_header_tlvs_apply_selectors() {
    use crate::tlv::TlvType;
    use clap::Parser;
    let conf = Configuration::try_parse_from([
        "test",
        "--remote-addr",
        "127.0.0.1",
        "--reflected-ipv6-ext-hdr",
        "--reflected-ipv6-ext-hdr-selector",
        "3c000102",
        "--reflected-fixed-hdr",
        "--reflected-fixed-hdr-selector",
        "45000054",
    ])
    .unwrap();

    let tlvs = reflected_header_request_tlvs(&conf);

    let fixed = tlvs
        .iter()
        .find(|t| t.tlv_type == TlvType::ReflectedFixedHdr)
        .unwrap();
    assert_eq!(fixed.value.len(), IPV4_FIXED_HEADER_SIZE);
    assert_eq!(&fixed.value[..4], &[0x45, 0x00, 0x00, 0x54]);
    assert!(fixed.value[4..].iter().all(|&b| b == 0));

    let ext = tlvs
        .iter()
        .find(|t| t.tlv_type == TlvType::ReflectedIpv6ExtHdr)
        .unwrap();
    assert_eq!(&ext.value[..4], &[0x3c, 0x00, 0x01, 0x02]);
    assert!(ext.value[4..].iter().all(|&b| b == 0));
}

#[test]
fn reflected_header_tlvs_zero_fill_without_selector() {
    use clap::Parser;
    let conf = Configuration::try_parse_from([
        "test",
        "--remote-addr",
        "127.0.0.1",
        "--reflected-ipv6-ext-hdr",
        "--reflected-fixed-hdr",
    ])
    .unwrap();

    let tlvs = reflected_header_request_tlvs(&conf);
    assert_eq!(tlvs.len(), 2);
    for t in &tlvs {
        assert!(
            t.value.iter().all(|&b| b == 0),
            "no selector → zero-filled request"
        );
    }
}

#[cfg(all(feature = "hwtstamp", target_os = "linux"))]
#[test]
fn apply_tx_corrections_updates_pending_t1() {
    use crate::hwtstamp::TxTimestampReport;

    let mut tx_map = std::collections::HashMap::new();
    tx_map.insert(0u32, 5u32); // OPT_ID 0 → seq 5, still pending
    tx_map.insert(1u32, 6u32); // OPT_ID 1 → seq 6, already answered

    let mut pending = std::collections::HashMap::new();
    pending.insert(
        5u32,
        PendingPacket {
            send_time: Instant::now(),
            send_timestamp: 111,
        },
    );

    let reports = [
        TxTimestampReport {
            opt_id: 0,
            timestamp: 999,
            hardware: false,
        },
        TxTimestampReport {
            opt_id: 1,
            timestamp: 888,
            hardware: false,
        },
        TxTimestampReport {
            opt_id: 7, // never mapped (e.g. counter desync) → ignored
            timestamp: 777,
            hardware: false,
        },
    ];
    let applied = apply_tx_corrections(&reports, &mut tx_map, &mut pending);
    assert_eq!(applied, 1, "only the still-pending packet is corrected");
    assert_eq!(
        pending[&5].send_timestamp, 999,
        "kernel T1 replaces the userspace T1 used for forward OWD"
    );
    assert!(
        !tx_map.contains_key(&0) && !tx_map.contains_key(&1),
        "matched ids are consumed"
    );
}

#[test]
fn build_reflected_control_tlv_only_when_requested() {
    // Symmetric single-reply measurement, no one-way request → no TLV.
    assert!(build_reflected_control_tlv(0, 1, 1_000_000, false).is_none());

    // Multiple replies requested → TLV without sub-TLVs.
    let tlv = build_reflected_control_tlv(0, 4, 1_000_000, false).expect("TLV for count > 1");
    assert!(tlv.sub_tlvs.is_empty());
    assert_eq!(tlv.number_of_reflected_packets, 4);

    // Ext-hdr control requested → TLV emitted even at count 1, carrying the
    // presence-only IPv6 Extension Header Control sub-TLV
    // (draft-ietf-ippm-stamp-ext-hdr-15 §5.1; experimental type 240).
    let tlv = build_reflected_control_tlv(0, 1, 1_000_000, true).expect("TLV for one-way mode");
    assert_eq!(tlv.sub_tlvs, vec![0x00, 240, 0x00, 0x00]);
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn getsockopt_int(
    fd: std::os::fd::RawFd,
    level: nix::libc::c_int,
    name: nix::libc::c_int,
) -> nix::libc::c_int {
    use nix::libc;
    let mut val: libc::c_int = -1;
    let mut len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
    let rc = unsafe {
        libc::getsockopt(
            fd,
            level,
            name,
            &mut val as *mut _ as *mut libc::c_void,
            &mut len,
        )
    };
    assert_eq!(
        rc,
        0,
        "getsockopt(level={level}, name={name}) failed: {}",
        std::io::Error::last_os_error()
    );
    val
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn test_apply_egress_ip_options_sets_tos_and_ttl_v4() {
    use nix::libc;
    use std::os::fd::AsRawFd;

    let sock = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind v4");
    let fd = sock.as_raw_fd();

    // DSCP 46 (EF) / ECN 0 => 0xB8, hop limit 7.
    apply_egress_ip_options(fd, false, Some(0xB8), Some(7)).expect("apply v4 opts");

    assert_eq!(getsockopt_int(fd, libc::IPPROTO_IP, libc::IP_TOS), 0xB8);
    assert_eq!(getsockopt_int(fd, libc::IPPROTO_IP, libc::IP_TTL), 7);
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn test_apply_egress_ip_options_sets_tclass_and_hops_v6() {
    use nix::libc;
    use std::os::fd::AsRawFd;

    let sock = std::net::UdpSocket::bind("[::1]:0").expect("bind v6");
    let fd = sock.as_raw_fd();

    apply_egress_ip_options(fd, true, Some(0x20), Some(9)).expect("apply v6 opts");

    assert_eq!(
        getsockopt_int(fd, libc::IPPROTO_IPV6, libc::IPV6_TCLASS),
        0x20
    );
    assert_eq!(
        getsockopt_int(fd, libc::IPPROTO_IPV6, libc::IPV6_UNICAST_HOPS),
        9
    );
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn test_apply_egress_ip_options_none_is_noop() {
    use std::os::fd::AsRawFd;
    let sock = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind v4");
    // Passing no options must not error and must leave defaults untouched.
    apply_egress_ip_options(sock.as_raw_fd(), false, None, None).expect("noop");
}

#[test]
fn test_parse_hex_pattern_basic() {
    assert_eq!(crate::ber::parse_pattern("ff00").unwrap(), vec![0xFF, 0x00]);
    assert_eq!(
        crate::ber::parse_pattern("0xFF00").unwrap(),
        vec![0xFF, 0x00]
    );
    assert_eq!(crate::ber::parse_pattern("aa55").unwrap(), vec![0xAA, 0x55]);
}

#[test]
fn test_parse_hex_pattern_rejects_odd_length() {
    assert!(crate::ber::parse_pattern("fff").is_err());
}

#[test]
fn test_parse_hex_pattern_rejects_non_hex() {
    assert!(crate::ber::parse_pattern("zzzz").is_err());
}

#[test]
fn test_parse_hex_pattern_rejects_empty() {
    assert!(crate::ber::parse_pattern("").is_err());
    assert!(crate::ber::parse_pattern("0x").is_err());
}

#[test]
fn test_assemble_unauth_packet_defaults() {
    let packet = assemble_unauth_packet(0);
    assert_eq!(packet.sequence_number, 0);
    assert_eq!(packet.timestamp, 0);
    assert_eq!(packet.error_estimate, 0);
    assert_eq!(packet.ssid, 0);
    assert_eq!(packet.mbz, [0u8; 28]);
}

#[test]
fn test_assemble_unauth_packet_with_error_estimate() {
    let error_estimate = 0x8A64; // S=1, Scale=10, Multiplier=100
    let packet = assemble_unauth_packet(error_estimate);
    assert_eq!(packet.error_estimate, error_estimate);
}

#[test]
fn test_assemble_auth_packet_defaults() {
    let packet = assemble_auth_packet(0);
    assert_eq!(packet.sequence_number, 0);
    assert_eq!(packet.timestamp, 0);
    assert_eq!(packet.error_estimate, 0);
    assert_eq!(packet.ssid, 0);
    assert_eq!(packet.mbz0, [0u8; 12]);
    assert_eq!(packet.mbz1a, [0u8; 30]);
    assert_eq!(packet.mbz1b, [0u8; 32]);
    assert_eq!(packet.mbz1c, [0u8; 6]);
    assert_eq!(packet.hmac, [0u8; 16]);
}

#[test]
fn test_assemble_auth_packet_with_error_estimate() {
    let error_estimate = 0x8A64;
    let packet = assemble_auth_packet(error_estimate);
    assert_eq!(packet.error_estimate, error_estimate);
}

#[test]
fn test_finalize_auth_packet_sets_hmac() {
    use crate::crypto::HmacKey;

    let mut packet = assemble_auth_packet(0);
    packet.sequence_number = 42;
    packet.timestamp = 123456789;

    let key = HmacKey::new(vec![0xab; 32]).unwrap();
    finalize_auth_packet(&mut packet, &key);

    // HMAC should no longer be all zeros
    assert_ne!(packet.hmac, [0u8; 16]);
}

#[test]
fn test_finalize_auth_packet_deterministic() {
    use crate::crypto::HmacKey;

    let key = HmacKey::new(vec![0xab; 32]).unwrap();

    let mut packet1 = assemble_auth_packet(100);
    packet1.sequence_number = 1;
    packet1.timestamp = 999;
    finalize_auth_packet(&mut packet1, &key);

    let mut packet2 = assemble_auth_packet(100);
    packet2.sequence_number = 1;
    packet2.timestamp = 999;
    finalize_auth_packet(&mut packet2, &key);

    assert_eq!(packet1.hmac, packet2.hmac);
}

// TLV building tests

#[test]
fn test_build_unauth_packet_with_tlvs_no_tlvs() {
    let packet = build_unauth_packet_with_tlvs(1, 1000, 100, None, &[], None);

    // Should be just base packet (44 bytes)
    assert_eq!(packet.len(), 44);
}

#[test]
fn test_build_unauth_packet_with_ssid() {
    // RFC 8972 §3: SSID lives in the base packet header at bytes 14-15,
    // not as a TLV. Size stays at 44 when no other TLVs are present.
    let ssid: u16 = 12345;
    let packet = build_unauth_packet_with_tlvs(1, 1000, 100, Some(ssid), &[], None);

    assert_eq!(packet.len(), 44);
    assert_eq!(u16::from_be_bytes([packet[14], packet[15]]), ssid);
}

#[test]
fn test_build_unauth_packet_with_extra_tlvs() {
    use crate::tlv::{TlvType, TLV_HEADER_SIZE};

    let extra_tlv = RawTlv::new(TlvType::Location, vec![1, 2, 3, 4]);
    let packet = build_unauth_packet_with_tlvs(1, 1000, 100, None, &[extra_tlv], None);

    // Base (44) + Location TLV (4 header + 4 value)
    assert_eq!(packet.len(), 44 + TLV_HEADER_SIZE + 4);

    // Check TLV type (byte 1 per RFC 8972)
    assert_eq!(packet[45], 2); // Location type
}

#[test]
fn test_build_unauth_packet_with_tlv_hmac() {
    use crate::tlv::{HMAC_TLV_VALUE_SIZE, TLV_HEADER_SIZE};

    let key = HmacKey::new(vec![0xAB; 32]).unwrap();
    let packet = build_unauth_packet_with_tlvs(1, 1000, 100, Some(100), &[], Some(&key));

    // Base (44, SSID is in header) + HMAC TLV (4+16)
    assert_eq!(packet.len(), 44 + TLV_HEADER_SIZE + HMAC_TLV_VALUE_SIZE);

    // SSID echoed in base packet header at bytes 14-15
    assert_eq!(u16::from_be_bytes([packet[14], packet[15]]), 100);

    // HMAC TLV starts right after the base packet (type byte = 8 per RFC 8972)
    assert_eq!(packet[44 + 1], 8);
}

#[test]
fn test_build_auth_packet_with_tlvs_no_tlvs() {
    let key = HmacKey::new(vec![0xAB; 32]).unwrap();
    let packet = build_auth_packet_with_tlvs(1, 1000, 100, &key, None, &[], None);

    // Should be just base packet (112 bytes)
    assert_eq!(packet.len(), 112);

    // Base HMAC should be set
    assert_ne!(&packet[96..112], &[0u8; 16]);
}

#[test]
fn test_build_auth_packet_with_ssid() {
    // RFC 8972 §3: SSID lives at bytes 26-27 of the auth packet header, not as a TLV.
    let key = HmacKey::new(vec![0xAB; 32]).unwrap();
    let packet = build_auth_packet_with_tlvs(1, 1000, 100, &key, Some(54321), &[], None);

    assert_eq!(packet.len(), 112);
    assert_eq!(u16::from_be_bytes([packet[26], packet[27]]), 54321);
}

#[test]
fn test_build_auth_packet_with_tlv_hmac() {
    use crate::tlv::{HMAC_TLV_VALUE_SIZE, TLV_HEADER_SIZE};

    let key = HmacKey::new(vec![0xAB; 32]).unwrap();
    let packet = build_auth_packet_with_tlvs(1, 1000, 100, &key, Some(100), &[], Some(&key));

    // Base (112, SSID in header) + HMAC TLV (4+16)
    assert_eq!(packet.len(), 112 + TLV_HEADER_SIZE + HMAC_TLV_VALUE_SIZE);
    assert_eq!(u16::from_be_bytes([packet[26], packet[27]]), 100);
}

#[test]
fn test_create_extended_unauth_packet() {
    let ext = create_extended_unauth_packet(1, 1000, 100, None);

    assert_eq!(ext.base.sequence_number, 1);
    assert!(!ext.has_tlvs());
}

#[test]
fn test_create_extended_unauth_packet_with_ssid() {
    // SSID lives in the base header per RFC 8972 §3; no TLV is injected.
    let ext = create_extended_unauth_packet(1, 1000, 100, Some(9999));

    assert_eq!(ext.base.sequence_number, 1);
    assert_eq!(ext.base.ssid, 9999);
    assert!(!ext.has_tlvs());
}

#[test]
fn test_create_extended_auth_packet() {
    let key = HmacKey::new(vec![0xCD; 32]).unwrap();
    let ext = create_extended_auth_packet(1, 1000, 100, &key, None);

    assert_eq!(ext.base.sequence_number, 1);
    assert!(!ext.has_tlvs());
    // Base HMAC should be computed
    assert_ne!(ext.base.hmac, [0u8; 16]);
}

#[test]
fn test_create_extended_auth_packet_with_ssid() {
    // SSID lives in the base header per RFC 8972 §3; no TLV is injected.
    let key = HmacKey::new(vec![0xCD; 32]).unwrap();
    let ext = create_extended_auth_packet(1, 1000, 100, &key, Some(8888));

    assert_eq!(ext.base.ssid, 8888);
    assert!(!ext.has_tlvs());
}

#[test]
fn unsolicited_msid_cannot_seed_the_reflector_latch() {
    let mut pending = HashMap::from([(
        42,
        PendingPacket {
            send_time: Instant::now(),
            send_timestamp: 0,
        },
    )]);
    let mut rtt = RttCollector::new();
    let mut owd = OwdCollector::new();
    let mut received = 0;
    let mut latched = None;
    let mut zero = false;
    let mut congestion = CongestionState::new(congestion_test_params());
    let mut access = AccessReportRetransmitState::new(Duration::from_secs(3), 4);
    access.tick(Instant::now());
    for seq in [99u32, 42] {
        let mut reply = vec![0; 44];
        reply[24..28].copy_from_slice(&seq.to_be_bytes());
        reply.extend_from_slice(&[0, 11, 0, 4, 0, 7, 0, 9]);
        reply.extend_from_slice(&[0, 6, 0, 4, 0x10, 0, 0, 0]);
        let mut ctx = congestion_process_response_ctx(
            &mut pending,
            &mut rtt,
            &mut owd,
            &mut received,
            &mut latched,
            Some(&mut congestion),
            &mut zero,
        );
        ctx.expected_sender_msid = Some(7);
        ctx.access_report_state = Some(&mut access);
        process_response(
            &reply,
            false,
            false,
            ClockFormat::NTP,
            None,
            Some(3),
            &mut ctx,
        );
        assert_eq!(latched, (seq == 42).then_some(9));
        assert_eq!(received, u32::from(seq == 42));
        assert_eq!(
            congestion.controller.stats().ce_observations,
            u64::from(seq == 42)
        );
        assert_eq!(
            access.outcome(),
            if seq == 42 {
                AccessReportOutcome::Acknowledged
            } else {
                AccessReportOutcome::Pending
            }
        );
    }
}

#[test]
fn required_msid_rejects_unusable_reply_without_consuming_state() {
    let good = vec![0, 11, 0, 4, 0, 7, 0, 9];
    let mut cases = vec![
        ("absent", vec![]),
        ("unrelated", vec![0, 1, 0, 4, 0, 0, 0, 0]),
        ("short", vec![0, 11, 0, 3, 0, 7, 0]),
        ("truncated", vec![0, 11, 0, 4, 0, 7]),
        ("zero-reflector", vec![0, 11, 0, 4, 0, 7, 0, 0]),
        ("missing-hmac", good.clone()),
        ("bad-hmac", good.clone()),
    ];
    for (name, flag) in [("U", 0x80), ("M", 0x40), ("I", 0x20)] {
        let mut flagged = good.clone();
        flagged[0] = flag;
        cases.push((name, flagged));
    }
    cases.push(("duplicate", [good.clone(), good.clone()].concat()));
    cases.push((
        "conflicting",
        [good.clone(), vec![0, 11, 0, 4, 0, 7, 0, 10]].concat(),
    ));
    cases.push(("M-before", [vec![0x40, 1, 0, 0], good.clone()].concat()));
    cases.push(("I-after", [good.clone(), vec![0x20, 1, 0, 0]].concat()));
    for (auth, keyed) in [(false, false), (false, true), (true, true)] {
        for extensions in [false, true] {
            for (name, tail) in &cases {
                if !keyed && matches!(*name, "missing-hmac" | "bad-hmac") {
                    continue;
                }
                let key = HmacKey::new(vec![0xAB; 16]).unwrap();
                let mut pending = HashMap::from([(
                    42,
                    PendingPacket {
                        send_time: Instant::now(),
                        send_timestamp: 0,
                    },
                )]);
                let mut rtt = RttCollector::new();
                let mut owd = OwdCollector::new();
                let mut received = 0;
                let mut latched = None;
                let mut zero = false;
                for valid in [false, true] {
                    let base = if auth { 112 } else { 44 };
                    let mut reply = vec![0; base];
                    let seq = if auth { 48 } else { 24 };
                    reply[seq..seq + 4].copy_from_slice(&42u32.to_be_bytes());
                    reply.extend_from_slice(if valid { &good } else { tail });
                    if keyed && (valid || *name != "missing-hmac") {
                        let mut covered = reply[..4].to_vec();
                        covered.extend_from_slice(&reply[base..]);
                        let mut mac = key.compute(&covered);
                        if !valid && *name == "bad-hmac" {
                            mac[0] ^= 1;
                        }
                        reply.extend_from_slice(&[0, 8, 0, 16]);
                        reply.extend_from_slice(&mac);
                    }
                    if auth {
                        let mac = crate::crypto::compute_packet_hmac(&key, &reply, 96);
                        reply[96..112].copy_from_slice(&mac);
                    }
                    let mut ctx = congestion_process_response_ctx(
                        &mut pending,
                        &mut rtt,
                        &mut owd,
                        &mut received,
                        &mut latched,
                        None,
                        &mut zero,
                    );
                    ctx.expected_sender_msid = Some(7);
                    ctx.hmac_key = keyed.then_some(&key);
                    process_response(
                        &reply,
                        auth,
                        extensions,
                        ClockFormat::NTP,
                        None,
                        None,
                        &mut ctx,
                    );
                    assert_eq!(
                        received,
                        u32::from(valid),
                        "{name} auth={auth} keyed={keyed} ext={extensions}"
                    );
                    assert_eq!(pending.contains_key(&42), !valid);
                    assert_eq!(latched, valid.then_some(9));
                    assert_eq!(rtt.percentile_ns(50.0).is_some(), valid);
                    assert_eq!(owd.summary().is_some(), valid);
                }
            }
        }
    }
}

#[test]
fn test_validate_reflected_tlvs_auth_reply_without_hmac_tlv_fails() {
    // RFC 8972 §4.8: authenticated mode requires the HMAC TLV unless the
    // only TLV is Extra Padding.
    let key = HmacKey::new(vec![0xAB; 16]).unwrap();
    let validate = |tlvs: &TlvList| {
        validate_reflected_tlvs(
            tlvs,
            &[0u8; AUTH_BASE_SIZE],
            AUTH_BASE_SIZE,
            Some(&key),
            None,
            None,
            &mut None,
            false,
            false,
            #[cfg(feature = "metrics")]
            false,
        )
        .unwrap()
        .hmac
    };
    let mut cos = ClassOfServiceTlv::new(46, 0).to_raw();
    cos.clear_reflector_flags();
    let mut tlvs = TlvList::new();
    tlvs.push(cos).unwrap();
    assert_eq!(validate(&tlvs), HmacStatus::Failed);

    let mut padding = ExtraPaddingTlv::new_zeros(4).to_raw();
    padding.clear_reflector_flags();
    let mut tlvs = TlvList::new();
    tlvs.push(padding).unwrap();
    assert_eq!(validate(&tlvs), HmacStatus::Missing);
}

#[test]
fn test_validate_reflected_tlvs_msid_match_accepts() {
    // RFC 9534 §3.2: reflected MSID TLV must carry the sender's sender_id
    // unchanged; the reflector fills reflector_micro_session_id.
    // Model a properly-reflected TLV: a conforming reflector clears the
    // U/M/I flags on a recognized, well-formed TLV (the typed constructor
    // sets the sender-side U flag, which does not appear on the wire in a
    // reflected packet).
    let mut raw = MicroSessionIdTlv::new(7777, 42).to_raw();
    raw.clear_reflector_flags();
    let mut tlvs = TlvList::new();
    tlvs.push(raw).unwrap();

    let status = validate_reflected_tlvs(
        &tlvs,
        &[0u8; 44],
        44,
        None,
        Some(7777),
        None,
        &mut None,
        false, // track_access_report
        false, // track_congestion
        #[cfg(feature = "metrics")]
        false,
    )
    .expect("matching MSID must return Ok");

    assert!(status.micro_session.is_some(), "got: {}", status);
}

#[test]
fn test_validate_reflected_tlvs_msid_mismatch_rejects() {
    // RFC 9534 §3.2: a mismatched sender_micro_session_id means the
    // response cannot be attributed to this session. The validator must
    // return Err so the caller drops the packet without recording RTT.
    let mut raw = MicroSessionIdTlv::new(0xBAD, 42).to_raw();
    raw.clear_reflector_flags(); // properly-reflected TLV: no U/M/I flags
    let mut tlvs = TlvList::new();
    tlvs.push(raw).unwrap();

    let err = validate_reflected_tlvs(
        &tlvs,
        &[0u8; 44],
        44,
        None,
        Some(7777),
        None,
        &mut None,
        false, // track_access_report
        false, // track_congestion
        #[cfg(feature = "metrics")]
        false,
    )
    .expect_err("mismatched MSID must reject");

    assert_eq!(
        err,
        TlvRejection::MsidMismatch {
            got: 0xBAD,
            expected: 7777
        }
    );
}

#[test]
fn test_validate_reflected_tlvs_msid_malformed_rejects() {
    // A malformed MSID TLV cannot be parsed, so session binding can't be
    // verified; we must drop the response rather than guess.
    let mut tlvs = TlvList::new();
    // MSID TLV value must be exactly 4 bytes (RFC 9534 §3.1). 3 bytes
    // makes it unparseable but keeps the TLV present for the scanner.
    // Flags cleared: this models a non-conforming reflector that echoed a
    // wrong-length MSID WITHOUT setting the M flag — so the value is still
    // reached (an M-flagged TLV would instead halt processing per §4-18).
    let mut raw = crate::tlv::RawTlv::new(crate::tlv::TlvType::MicroSessionId, vec![0, 0, 0]);
    raw.clear_reflector_flags();
    tlvs.push(raw).unwrap();

    let err = validate_reflected_tlvs(
        &tlvs,
        &[0u8; 44],
        44,
        None,
        Some(1234),
        None,
        &mut None,
        false, // track_access_report
        false, // track_congestion
        #[cfg(feature = "metrics")]
        false,
    )
    .expect_err("malformed MSID must reject");

    assert_eq!(err, TlvRejection::MsidMalformed);
}

#[test]
fn test_validate_reflected_tlvs_msid_not_requested() {
    // Sender did not request MSID measurement; even if a stray MSID TLV
    // arrives we should not synthesize a validation result.
    let mut tlvs = TlvList::new();
    tlvs.push(MicroSessionIdTlv::new(1, 2).to_raw()).unwrap();

    let status = validate_reflected_tlvs(
        &tlvs,
        &[0u8; 44],
        44,
        None,
        None,
        None,
        &mut None,
        false, // track_access_report
        false, // track_congestion
        #[cfg(feature = "metrics")]
        false,
    )
    .expect("no MSID binding requested → accept");

    assert!(status.micro_session.is_none());
}

#[test]
fn test_micro_session_request_tlv_populates_reflector_id() {
    // RFC 9534 §3.2-3: "If the Session-Sender knows the Reflector member
    // link identifier, the Reflector Micro-session ID field MUST be set."
    let tlv = micro_session_request_tlv(0x1234, Some(0xABCD));
    let parsed = MicroSessionIdTlv::from_raw(&tlv).unwrap();
    assert_eq!(parsed.sender_micro_session_id, 0x1234);
    assert_eq!(parsed.reflector_micro_session_id, 0xABCD);
}

#[test]
fn test_micro_session_request_tlv_reflector_id_absent_is_zero() {
    // RFC 9534 §3.2-4: otherwise the field is left zero.
    let tlv = micro_session_request_tlv(0x1234, None);
    let parsed = MicroSessionIdTlv::from_raw(&tlv).unwrap();
    assert_eq!(parsed.sender_micro_session_id, 0x1234);
    assert_eq!(parsed.reflector_micro_session_id, 0);
}

#[test]
fn test_reflected_reflector_msid_mismatch_rejects() {
    // RFC 9534 §3.2-11/-12: when the reflector member-link ID is pre-known,
    // a reflected Reflector Micro-session ID that differs from it must be
    // discarded (validating the reflector's behaviour).
    let mut raw = MicroSessionIdTlv::new(7777, 0x11).to_raw();
    raw.clear_reflector_flags();
    let mut tlvs = TlvList::new();
    tlvs.push(raw).unwrap();

    let mut latched = None;
    let err = validate_reflected_tlvs(
        &tlvs,
        &[0u8; 44],
        44,
        None,
        Some(7777),
        Some(0x22), // pre-known reflector id, but reflected 0x11 ≠ 0x22
        &mut latched,
        false, // track_access_report
        false, // track_congestion
        #[cfg(feature = "metrics")]
        false,
    )
    .expect_err("reflector MSID mismatch must reject");

    assert_eq!(
        err,
        TlvRejection::ReflectorMsidMismatch {
            got: 0x11,
            expected: 0x22
        }
    );
    // Pre-known configuration takes precedence and must never be
    // superseded by a first-seen value: the zero-config latch stays
    // untouched (RFC 9534 §3.2-11/-12).
    assert_eq!(
        latched, None,
        "pre-known reflector ID must not populate the zero-config latch"
    );
}

#[test]
fn test_reflected_reflector_msid_match_accepts() {
    let mut raw = MicroSessionIdTlv::new(7777, 0x22).to_raw();
    raw.clear_reflector_flags();
    let mut tlvs = TlvList::new();
    tlvs.push(raw).unwrap();

    let mut latched = None;
    let status = validate_reflected_tlvs(
        &tlvs,
        &[0u8; 44],
        44,
        None,
        Some(7777),
        Some(0x22),
        &mut latched,
        false, // track_access_report
        false, // track_congestion
        #[cfg(feature = "metrics")]
        false,
    )
    .expect("reflector MSID match must accept");
    assert!(
        status
            .micro_session
            .as_ref()
            .is_some_and(|msid| msid.reflector_micro_session_id == 34),
        "got: {}",
        status
    );
    // Pre-known configuration takes precedence and must never be
    // superseded by a first-seen value: the zero-config latch stays
    // untouched (RFC 9534 §3.2-11/-12).
    assert_eq!(
        latched, None,
        "pre-known reflector ID must not populate the zero-config latch"
    );
}

#[test]
fn test_reflected_reflector_msid_zero_config_latches_first_seen() {
    // RFC 9534 §3.2-11 (unconditional validation, zero-config path):
    // with no pre-known reflector member-link ID, the first
    // validly-received reply's Reflector Micro-session ID becomes the
    // expected value for the rest of the session. A second reply
    // echoing the same reflector ID must still be accepted.
    let mut latched: Option<u16> = None;

    let mut raw1 = MicroSessionIdTlv::new(7777, 0x22).to_raw();
    raw1.clear_reflector_flags();
    let mut tlvs1 = TlvList::new();
    tlvs1.push(raw1).unwrap();
    let status1 = validate_reflected_tlvs(
        &tlvs1,
        &[0u8; 44],
        44,
        None,
        Some(7777),
        None, // no pre-known reflector ID
        &mut latched,
        false, // track_access_report
        false, // track_congestion
        #[cfg(feature = "metrics")]
        false,
    )
    .expect("first reply must be accepted");
    assert!(status1.micro_session.is_some(), "got: {}", status1);
    assert_eq!(
        latched,
        Some(0x22),
        "first-seen reflector ID must be latched"
    );

    let mut raw2 = MicroSessionIdTlv::new(7777, 0x22).to_raw();
    raw2.clear_reflector_flags();
    let mut tlvs2 = TlvList::new();
    tlvs2.push(raw2).unwrap();
    let status2 = validate_reflected_tlvs(
        &tlvs2,
        &[0u8; 44],
        44,
        None,
        Some(7777),
        None,
        &mut latched,
        false, // track_access_report
        false, // track_congestion
        #[cfg(feature = "metrics")]
        false,
    )
    .expect("second reply with the same reflector ID must also be accepted");
    assert!(status2.micro_session.is_some(), "got: {}", status2);
    assert_eq!(latched, Some(0x22), "latch must remain unchanged");
}

#[test]
fn test_reflected_reflector_msid_zero_config_rejects_change_after_latch() {
    // RFC 9534 §3.2-11 (zero-config path): once the first reply has
    // latched a Reflector Micro-session ID, a later reply echoing a
    // different reflector ID must be discarded exactly like the
    // pre-known mismatch path (reuses `ReflectorMsidMismatch`).
    let mut latched: Option<u16> = None;

    let mut raw1 = MicroSessionIdTlv::new(7777, 0x22).to_raw();
    raw1.clear_reflector_flags();
    let mut tlvs1 = TlvList::new();
    tlvs1.push(raw1).unwrap();
    validate_reflected_tlvs(
        &tlvs1,
        &[0u8; 44],
        44,
        None,
        Some(7777),
        None,
        &mut latched,
        false, // track_access_report
        false, // track_congestion
        #[cfg(feature = "metrics")]
        false,
    )
    .expect("first reply must be accepted and latch the reflector ID");
    assert_eq!(latched, Some(0x22));

    let mut raw2 = MicroSessionIdTlv::new(7777, 0x33).to_raw();
    raw2.clear_reflector_flags();
    let mut tlvs2 = TlvList::new();
    tlvs2.push(raw2).unwrap();
    let err = validate_reflected_tlvs(
        &tlvs2,
        &[0u8; 44],
        44,
        None,
        Some(7777),
        None,
        &mut latched,
        false, // track_access_report
        false, // track_congestion
        #[cfg(feature = "metrics")]
        false,
    )
    .expect_err("a changed reflector ID after latching must be rejected");

    assert_eq!(
        err,
        TlvRejection::ReflectorMsidMismatch {
            got: 0x33,
            expected: 0x22
        }
    );
}

#[test]
fn test_forged_first_reply_does_not_latch_reflector_msid() {
    // An untrusted first reply must not set the expected reflector ID
    // (RFC 9534 §3.2-11), or it could lock out valid replies.
    let mut latched: Option<u16> = None;

    let mut forged = MicroSessionIdTlv::new(7777, 0xDEAD).to_raw();
    forged.set_integrity_failed();
    let mut tlvs = TlvList::new();
    tlvs.push(forged).unwrap();

    validate_reflected_tlvs(
        &tlvs,
        &[0u8; 44],
        44,
        None,
        Some(7777),
        None, // no pre-known reflector ID → zero-config latch path
        &mut latched,
        false, // track_access_report
        false, // track_congestion
        #[cfg(feature = "metrics")]
        false,
    )
    .expect_err("a required but untrusted ID must reject the measurement");

    assert_eq!(
        latched, None,
        "an untrusted first reply must not latch a Reflector Micro-session ID"
    );

    // The next legitimate reply is then free to latch its own value.
    let mut clean = MicroSessionIdTlv::new(7777, 0x22).to_raw();
    clean.clear_reflector_flags();
    let mut tlvs2 = TlvList::new();
    tlvs2.push(clean).unwrap();

    validate_reflected_tlvs(
        &tlvs2,
        &[0u8; 44],
        44,
        None,
        Some(7777),
        None,
        &mut latched,
        false,
        false,
        #[cfg(feature = "metrics")]
        false,
    )
    .expect("a valid reply after a forged one must be accepted");

    assert_eq!(
        latched,
        Some(0x22),
        "the first *trusted* reply must be the one that latches"
    );
}

#[test]
fn test_forged_msid_with_i_flag_not_consumed() {
    // I-flagged MSID values cannot affect session binding
    // (RFC 8972 §4-19 / §4.8-16), including through a forged mismatch.
    let mut raw = MicroSessionIdTlv::new(0xBAD, 42).to_raw();
    raw.set_integrity_failed();
    let mut tlvs = TlvList::new();
    tlvs.push(raw).unwrap();

    let status = validate_reflected_tlvs(
        &tlvs,
        &[0u8; 44],
        44,
        None,
        Some(7777),
        None,
        &mut None,
        false, // track_access_report
        false, // track_congestion
        #[cfg(feature = "metrics")]
        false,
    )
    .expect_err("required binding is unavailable; reject without trusting forged values");
    assert_eq!(status, TlvRejection::MsidUnavailable);
}

#[test]
fn test_forged_msid_with_m_flag_not_consumed() {
    // RFC 8972 §4-18: "If the M flag is set, the STAMP system MUST stop
    // processing the remainder of the extended STAMP packet." An M-flagged
    // MSID TLV's value MUST NOT be consumed for session binding.
    let mut raw = MicroSessionIdTlv::new(0xBAD, 42).to_raw();
    raw.set_malformed();
    let mut tlvs = TlvList::new();
    tlvs.push(raw).unwrap();

    let status = validate_reflected_tlvs(
        &tlvs,
        &[0u8; 44],
        44,
        None,
        Some(7777),
        None,
        &mut None,
        false, // track_access_report
        false, // track_congestion
        #[cfg(feature = "metrics")]
        false,
    )
    .expect_err("required binding is unavailable; reject without trusting forged values");
    assert_eq!(status, TlvRejection::MsidUnavailable);
}

#[test]
fn test_forged_msid_ignored_when_tlv_hmac_fails() {
    // RFC 8972 §4.8-17: "If HMAC verification by the Session-Sender fails,
    // then the Session-Sender MUST stop processing TLVs." The forged MSID
    // value MUST NOT reach the session-binding check when the TLV-HMAC
    // cannot be verified.
    let key = HmacKey::new(vec![0xAB; 32]).unwrap();
    let mut tlvs = TlvList::new();
    tlvs.push(MicroSessionIdTlv::new(0xBAD, 42).to_raw())
        .unwrap();
    // A bogus HMAC TLV value that will never verify against the data.
    tlvs.push(crate::tlv::RawTlv::new(
        crate::tlv::TlvType::Hmac,
        vec![0u8; 16],
    ))
    .unwrap();

    // Data long enough for the HMAC coverage slice (seq + TLV area).
    let data = [0u8; 128];
    let status = validate_reflected_tlvs(
        &tlvs,
        &data,
        44,
        Some(&key),
        Some(7777),
        None,
        &mut None,
        false, // track_access_report
        false, // track_congestion
        #[cfg(feature = "metrics")]
        false,
    )
    .expect_err("required binding is unavailable; reject without trusting forged values");
    assert_eq!(status, TlvRejection::MsidUnavailable);
}

#[test]
fn measurement_telemetry_requires_usable_unambiguous_authenticated_values() {
    let key = HmacKey::new(vec![0xAB; 16]).unwrap();
    for base in [44, 112] {
        for kind in [TlvType::DirectMeasurement, TlvType::FollowUpTelemetry] {
            for case in [
                "plain",
                "signed",
                "missing",
                "bad-hmac",
                "no-key",
                "U",
                "M",
                "I",
                "duplicate",
                "short",
                "M-before",
                "I-after",
            ] {
                let mut raw = RawTlv::new(
                    kind,
                    vec![
                        0;
                        if kind == TlvType::DirectMeasurement {
                            12
                        } else {
                            16
                        }
                    ],
                );
                raw.clear_reflector_flags();
                match case {
                    "U" => raw.set_unrecognized(),
                    "M" => raw.set_malformed(),
                    "I" => raw.set_integrity_failed(),
                    "short" => {
                        raw.value.pop();
                    }
                    _ => (),
                }
                let mut tlvs = TlvList::new();
                let mut stop = RawTlv::new(TlvType::ExtraPadding, Vec::new());
                stop.clear_reflector_flags();
                if case == "M-before" {
                    stop.set_malformed();
                    tlvs.push(stop.clone()).unwrap();
                }
                tlvs.push(raw.clone()).unwrap();
                if case == "duplicate" {
                    tlvs.push(raw).unwrap();
                }
                if case == "I-after" {
                    stop.set_integrity_failed();
                    tlvs.push(stop).unwrap();
                }
                if matches!(case, "signed" | "bad-hmac" | "no-key") {
                    tlvs.set_hmac_response(&key, &[0; 4]);
                }
                let mut data = vec![0; base];
                tlvs.write_to(&mut data);
                if case == "bad-hmac" {
                    *data.last_mut().unwrap() ^= 1;
                }
                let parsed = TlvList::parse_lenient(&data[base..]).0;
                let report = validate_reflected_tlvs(
                    &parsed,
                    &data,
                    base,
                    matches!(case, "signed" | "bad-hmac" | "missing").then_some(&key),
                    None,
                    None,
                    &mut None,
                    false,
                    false,
                    #[cfg(feature = "metrics")]
                    false,
                )
                .unwrap();
                let present = if kind == TlvType::DirectMeasurement {
                    report.direct_measurement.is_some()
                } else {
                    report.follow_up.is_some()
                };
                assert_eq!(
                    present,
                    matches!(case, "plain" | "signed"),
                    "base={base}, kind={kind:?}, case={case}"
                );
                if case == "short" {
                    assert_eq!(report.flags.malformed, 1);
                }
            }
        }
    }
}

proptest::proptest! {
    #[test]
    fn telemetry_flag_and_hmac_gates_match_decision_oracle(
        entries in proptest::collection::vec((proptest::prelude::any::<bool>(), 0u8..8), 0..20),
        signed in proptest::prelude::any::<bool>(),
        with_key in proptest::prelude::any::<bool>(),
        corrupt in proptest::prelude::any::<bool>(),
        auth in proptest::prelude::any::<bool>(),
    ) {
        let key = HmacKey::new(vec![0xAB; 32]).unwrap();
        let mut tlvs = TlvList::new();
        let mut access = false;
        let mut ce = false;
        let mut halted = false;
        let mut flag_counts = [0; 3];
        for &(is_access, flags) in &entries {
            let mut raw = if is_access { AccessReportTlv::new(1, 1).to_raw() }
                else { ClassOfServiceTlv { dscp1: 0, ecn1: 1, dscp2: 0, ecn2: 3, rpd: 0, rpe: 0 }.to_raw() };
            raw.flags = crate::tlv::TlvFlags::default();
            raw.flags.unrecognized = flags & 1 != 0;
            raw.flags.malformed = flags & 2 != 0;
            raw.flags.integrity_failed = flags & 4 != 0;
            for (i, count) in flag_counts.iter_mut().enumerate() {
                *count += usize::from(flags & (1 << i) != 0);
            }
            halted |= flags & 2 != 0;
            if !halted && flags & 1 == 0 {
                access |= is_access;
                ce |= !is_access;
            }
            tlvs.push(raw).unwrap();
        }
        // Formatting-looking payload cannot create a control decision.
        let mut opaque = RawTlv::new(TlvType::Unknown(253), b"AccessReport:ack, CoS:CE".to_vec());
        opaque.clear_reflector_flags();
        tlvs.push(opaque).unwrap();
        if signed { tlvs.set_hmac_response(&key, &[0; 4]); }
        let base = if auth { 112 } else { 44 };
        let mut data = vec![0; base];
        tlvs.write_to(&mut data);
        if signed && corrupt { *data.last_mut().unwrap() ^= 1; }
        let parsed = TlvList::parse_lenient(&data[base..]).0;
        let report = validate_reflected_tlvs(
            &parsed, &data, base, with_key.then_some(&key), None, None,
            &mut None, true, true,
            #[cfg(feature = "metrics")]
            false,
        ).unwrap();
        // Authenticated mode with a key requires the HMAC TLV (RFC 8972 §4.8).
        let hmac_ok = if signed { with_key && !corrupt } else { !(auth && with_key) };
        let usable = flag_counts[2] == 0 && hmac_ok;
        proptest::prop_assert_eq!(report.access_report.is_some(), usable && access);
        proptest::prop_assert_eq!(report.forward_ce, usable && ce);
        proptest::prop_assert_eq!(report.flags.unrecognized, flag_counts[0]);
        proptest::prop_assert_eq!(report.flags.malformed, flag_counts[1]);
        proptest::prop_assert_eq!(report.flags.integrity_failed, flag_counts[2]);
        proptest::prop_assert!(report.micro_session.is_none());
    }
}

#[test]
fn telemetry_unusable_hmac_flags_block_all_decisions() {
    let key = HmacKey::new(vec![0xAB; 32]).unwrap();
    for flag in [0x80, 0x40, 0x20] {
        let mut tlvs = TlvList::new();
        let mut access = AccessReportTlv::new(1, 1).to_raw();
        access.clear_reflector_flags();
        tlvs.push(access).unwrap();
        tlvs.set_hmac_response(&key, &[0; 4]);
        let mut data = vec![0; 44];
        tlvs.write_to(&mut data);
        let at = data.len() - 20;
        data[at] = flag; // HMAC's own flags are outside its covered prefix.
        let parsed = TlvList::parse_lenient(&data[44..]).0;
        let report = validate_reflected_tlvs(
            &parsed,
            &data,
            44,
            Some(&key),
            None,
            None,
            &mut None,
            true,
            true,
            #[cfg(feature = "metrics")]
            false,
        )
        .unwrap();
        assert_eq!(report.hmac, HmacStatus::Unverified);
        assert!(report.access_report.is_none());
        assert!(!report.forward_ce);
    }
}

#[test]
fn telemetry_duplicate_hmacs_include_every_integrity_flag() {
    let mut bytes = vec![0x20, 8, 0, 16];
    bytes.extend_from_slice(&[0; 16]);
    bytes.extend_from_slice(&[0, 8, 0, 16]);
    bytes.extend_from_slice(&[0; 16]);
    let tlvs = TlvList::parse_lenient(&bytes).0;
    let report = validate_reflected_tlvs(
        &tlvs,
        &[0; 44],
        44,
        None,
        None,
        None,
        &mut None,
        true,
        true,
        #[cfg(feature = "metrics")]
        false,
    )
    .unwrap();
    assert_eq!(report.tlv_count, 2);
    assert_eq!(report.flags.integrity_failed, 1);
    assert_eq!(report.hmac, HmacStatus::Failed);
    assert!(report.access_report.is_none());
}

#[test]
fn telemetry_control_decisions_do_not_depend_on_formatting() {
    for print in [false, true] {
        for output in [
            crate::stats::OutputFormat::Text,
            crate::stats::OutputFormat::Json,
            crate::stats::OutputFormat::Csv,
        ] {
            let mut tlvs = TlvList::new();
            for mut raw in [
                AccessReportTlv::new(1, 1).to_raw(),
                ClassOfServiceTlv {
                    dscp1: 0,
                    ecn1: 1,
                    dscp2: 0,
                    ecn2: 3,
                    rpd: 0,
                    rpe: 0,
                }
                .to_raw(),
            ] {
                raw.clear_reflector_flags();
                tlvs.push(raw).unwrap();
            }
            let mut data = vec![0; 44];
            tlvs.write_to(&mut data);
            let mut pending = HashMap::new();
            pending.insert(
                0,
                PendingPacket {
                    send_time: Instant::now(),
                    send_timestamp: 0,
                },
            );
            let mut rtt = RttCollector::new();
            let mut owd = OwdCollector::new();
            let mut received = 0;
            let mut latched = None;
            let mut zero = false;
            let mut congestion = CongestionState::new(congestion_test_params());
            let mut access = AccessReportRetransmitState::new(Duration::from_secs(3), 4);
            access.tick(Instant::now());
            let mut ctx = congestion_process_response_ctx(
                &mut pending,
                &mut rtt,
                &mut owd,
                &mut received,
                &mut latched,
                Some(&mut congestion),
                &mut zero,
            );
            ctx.access_report_state = Some(&mut access);
            ctx.print_stats = print;
            ctx.output_format = output;
            process_response(&data, false, true, ClockFormat::NTP, None, None, &mut ctx);
            assert_eq!(received, 1);
            assert!(pending.is_empty());
            assert_eq!(access.outcome(), AccessReportOutcome::Acknowledged);
            assert_eq!(congestion.controller.stats().ce_observations, 1);
            assert_eq!(
                congestion.controller.current_interval(),
                Duration::from_millis(200)
            );
        }
    }
}

#[test]
fn telemetry_missing_hmac_bytes_cannot_acknowledge() {
    assert_unverifiable_hmac_cannot_acknowledge(true);
}

#[test]
fn telemetry_missing_hmac_key_cannot_acknowledge() {
    assert_unverifiable_hmac_cannot_acknowledge(false);
}

fn assert_unverifiable_hmac_cannot_acknowledge(with_key: bool) {
    let key = HmacKey::new(vec![0xAB; 32]).unwrap();
    let mut tlvs = TlvList::new();
    let mut access = AccessReportTlv::new(1, 1).to_raw();
    access.clear_reflector_flags();
    tlvs.push(access).unwrap();
    tlvs.set_hmac_response(&key, &[0; 4]);
    let status = validate_reflected_tlvs(
        &tlvs,
        &[0; 44],
        44,
        with_key.then_some(&key),
        None,
        None,
        &mut None,
        true,
        false,
        #[cfg(feature = "metrics")]
        false,
    )
    .unwrap();
    assert!(status.access_report.is_none(), "{status}");
}

#[test]
fn telemetry_bad_access_report_length_cannot_acknowledge() {
    let mut tlvs = TlvList::new();
    let mut raw = RawTlv::new(TlvType::AccessReport, vec![0x10, 1]);
    raw.clear_reflector_flags();
    tlvs.push(raw).unwrap();
    let status = validate_reflected_tlvs(
        &tlvs,
        &[0; 44],
        44,
        None,
        None,
        None,
        &mut None,
        true,
        false,
        #[cfg(feature = "metrics")]
        false,
    )
    .unwrap();
    assert!(status.access_report.is_none(), "{status}");
}

#[test]
fn test_validate_reflected_tlvs_detects_access_report_ack() {
    let mut raw = AccessReportTlv::new(1, 1).to_raw();
    raw.clear_reflector_flags(); // properly-reflected TLV: no U/M/I flags
    let mut tlvs = TlvList::new();
    tlvs.push(raw).unwrap();

    let status = validate_reflected_tlvs(
        &tlvs,
        &[0u8; 44],
        44,
        None,
        None,
        None,
        &mut None,
        true,  // track_access_report
        false, // track_congestion
        #[cfg(feature = "metrics")]
        false,
    )
    .expect("clean Access Report TLV must return Ok");

    assert!(status.access_report.is_some(), "got: {}", status);
}

#[test]
fn test_validate_reflected_tlvs_ignores_access_report_when_not_tracking() {
    // Backward compatibility: when the sender never requested tracking
    // (e.g. `--access-report` was not set), the presence of an Access
    // Report TLV must not produce an acknowledgement decision.
    let mut raw = AccessReportTlv::new(1, 1).to_raw();
    raw.clear_reflector_flags();
    let mut tlvs = TlvList::new();
    tlvs.push(raw).unwrap();

    let status = validate_reflected_tlvs(
        &tlvs,
        &[0u8; 44],
        44,
        None,
        None,
        None,
        &mut None,
        false, // track_access_report
        false, // track_congestion
        #[cfg(feature = "metrics")]
        false,
    )
    .expect("Ok regardless of tracking");

    assert!(status.access_report.is_none(), "got: {}", status);
}

#[test]
fn test_validate_reflected_tlvs_access_report_u_flagged_not_acked() {
    // RFC 8972 §4-17: a U-flagged TLV must be skipped — an unrecognized
    // echo cannot be trusted as the RFC 8972 §4.6 acknowledgment.
    let mut raw = AccessReportTlv::new(1, 1).to_raw();
    raw.set_unrecognized();
    let mut tlvs = TlvList::new();
    tlvs.push(raw).unwrap();

    let status = validate_reflected_tlvs(
        &tlvs,
        &[0u8; 44],
        44,
        None,
        None,
        None,
        &mut None,
        true,
        false, // track_congestion
        #[cfg(feature = "metrics")]
        false,
    )
    .expect("Ok even though unrecognized");

    assert!(
        status.access_report.is_none(),
        "U-flagged TLV must not count as an ack: {}",
        status
    );
    assert!(status.flags.unrecognized == 1, "got: {}", status);
}

#[test]
fn test_validate_reflected_tlvs_access_report_i_flagged_not_acked() {
    // RFC 8972 §4-19: an I-flagged TLV means integrity failed —
    // §4.6's ack semantics require an intact echo, so no ack.
    let mut raw = AccessReportTlv::new(1, 1).to_raw();
    raw.set_integrity_failed();
    let mut tlvs = TlvList::new();
    tlvs.push(raw).unwrap();

    let status = validate_reflected_tlvs(
        &tlvs,
        &[0u8; 44],
        44,
        None,
        None,
        None,
        &mut None,
        true,
        false, // track_congestion
        #[cfg(feature = "metrics")]
        false,
    )
    .expect("Ok even though integrity-failed");

    assert!(
        status.access_report.is_none(),
        "I-flagged TLV must not count as an ack: {}",
        status
    );
    assert!(status.flags.integrity_failed == 1, "got: {}", status);
}

#[test]
fn test_validate_reflected_tlvs_access_report_m_flagged_halts_scan() {
    // RFC 8972 §4-18: an M-flagged TLV halts processing of the
    // *remainder* of the packet — an Access Report TLV that comes after
    // it in wire order must not be reached, hence not acked.
    let mut bad = crate::tlv::RawTlv::new(crate::tlv::TlvType::MicroSessionId, vec![0, 0, 0]);
    bad.set_malformed();
    let mut good = AccessReportTlv::new(1, 1).to_raw();
    good.clear_reflector_flags();

    let mut tlvs = TlvList::new();
    tlvs.push(bad).unwrap();
    tlvs.push(good).unwrap();

    let status = validate_reflected_tlvs(
        &tlvs,
        &[0u8; 44],
        44,
        None,
        None,
        None,
        &mut None,
        true,
        false, // track_congestion
        #[cfg(feature = "metrics")]
        false,
    )
    .expect("Ok — M just halts the scan, doesn't reject");

    assert!(
        status.access_report.is_none(),
        "M-flag must halt the scan before the later Access Report TLV: {}",
        status
    );
}

#[test]
fn test_validate_reflected_tlvs_access_report_ack_survives_alongside_msid() {
    // Both features active at once: MSID success must not short-circuit
    // (via an early `break`) before the Access Report TLV later in the
    // list gets scanned.
    let mut msid = MicroSessionIdTlv::new(7777, 42).to_raw();
    msid.clear_reflector_flags();
    let mut ar = AccessReportTlv::new(1, 1).to_raw();
    ar.clear_reflector_flags();

    let mut tlvs = TlvList::new();
    tlvs.push(msid).unwrap();
    tlvs.push(ar).unwrap();

    let status = validate_reflected_tlvs(
        &tlvs,
        &[0u8; 44],
        44,
        None,
        Some(7777),
        None,
        &mut None,
        true,
        false, // track_congestion
        #[cfg(feature = "metrics")]
        false,
    )
    .expect("Ok");

    assert!(status.micro_session.is_some(), "got: {}", status);
    assert!(status.access_report.is_some(), "got: {}", status);
}

// --- validate_reflected_tlvs: CoS EC2 CE detection
// (draft-ietf-ippm-stamp-cos-ecn-01 §3.4) ------------------------------

#[test]
fn test_validate_reflected_tlvs_detects_cos_ce() {
    let mut raw = ClassOfServiceTlv {
        dscp1: 0,
        ecn1: 1,
        dscp2: 0,
        ecn2: 0b11, // CE
        rpd: 0,
        rpe: 0b11,
    }
    .to_raw();
    raw.clear_reflector_flags(); // properly-reflected TLV: no U/M/I flags
    let mut tlvs = TlvList::new();
    tlvs.push(raw).unwrap();

    let status = validate_reflected_tlvs(
        &tlvs,
        &[0u8; 44],
        44,
        None,
        None,
        None,
        &mut None,
        false, // track_access_report
        true,  // track_congestion
        #[cfg(feature = "metrics")]
        false,
    )
    .expect("clean CE-marked CoS TLV must return Ok");

    assert!(status.forward_ce, "got: {}", status);
}

#[test]
fn test_validate_reflected_tlvs_ignores_cos_ce_when_not_tracking() {
    // Backward compatibility: when the congestion controller is
    // inactive (e.g. `--cos`/`--ecn` were not requesting ECT0/ECT1),
    // a CE-marked EC2 field must not spuriously affect the status
    // string.
    let mut raw = ClassOfServiceTlv {
        dscp1: 0,
        ecn1: 1,
        dscp2: 0,
        ecn2: 0b11,
        rpd: 0,
        rpe: 0b11,
    }
    .to_raw();
    raw.clear_reflector_flags();
    let mut tlvs = TlvList::new();
    tlvs.push(raw).unwrap();

    let status = validate_reflected_tlvs(
        &tlvs,
        &[0u8; 44],
        44,
        None,
        None,
        None,
        &mut None,
        false, // track_access_report
        false, // track_congestion
        #[cfg(feature = "metrics")]
        false,
    )
    .expect("Ok regardless of tracking");

    assert!(!status.forward_ce, "got: {}", status);
}

#[test]
fn test_validate_reflected_tlvs_cos_non_ce_ecn2_not_flagged() {
    // ECT0 (0b10) is not congestion — must not be reported as CE.
    let mut raw = ClassOfServiceTlv {
        dscp1: 0,
        ecn1: 1,
        dscp2: 0,
        ecn2: 0b10,
        rpd: 0,
        rpe: 0b11,
    }
    .to_raw();
    raw.clear_reflector_flags();
    let mut tlvs = TlvList::new();
    tlvs.push(raw).unwrap();

    let status = validate_reflected_tlvs(
        &tlvs,
        &[0u8; 44],
        44,
        None,
        None,
        None,
        &mut None,
        false, // track_access_report
        true,  // track_congestion
        #[cfg(feature = "metrics")]
        false,
    )
    .expect("Ok");

    assert!(!status.forward_ce, "got: {}", status);
}

#[test]
fn test_validate_reflected_tlvs_cos_ce_u_flagged_not_reported() {
    // RFC 8972 §4-17: a U-flagged TLV must be skipped — an unrecognized
    // echo cannot be trusted as a congestion signal.
    let mut raw = ClassOfServiceTlv {
        dscp1: 0,
        ecn1: 1,
        dscp2: 0,
        ecn2: 0b11,
        rpd: 0,
        rpe: 0b11,
    }
    .to_raw();
    raw.set_unrecognized();
    let mut tlvs = TlvList::new();
    tlvs.push(raw).unwrap();

    let status = validate_reflected_tlvs(
        &tlvs,
        &[0u8; 44],
        44,
        None,
        None,
        None,
        &mut None,
        false, // track_access_report
        true,  // track_congestion
        #[cfg(feature = "metrics")]
        false,
    )
    .expect("Ok even though unrecognized");

    assert!(
        !status.forward_ce,
        "U-flagged TLV must not count as a CE signal: {}",
        status
    );
}

#[test]
fn test_validate_reflected_tlvs_cos_ce_i_flagged_not_reported() {
    // RFC 8972 §4-19: an I-flagged TLV means integrity failed — the
    // controller must not be able to be forced into a spurious backoff
    // by an unverifiable echo.
    let mut raw = ClassOfServiceTlv {
        dscp1: 0,
        ecn1: 1,
        dscp2: 0,
        ecn2: 0b11,
        rpd: 0,
        rpe: 0b11,
    }
    .to_raw();
    raw.set_integrity_failed();
    let mut tlvs = TlvList::new();
    tlvs.push(raw).unwrap();

    let status = validate_reflected_tlvs(
        &tlvs,
        &[0u8; 44],
        44,
        None,
        None,
        None,
        &mut None,
        false, // track_access_report
        true,  // track_congestion
        #[cfg(feature = "metrics")]
        false,
    )
    .expect("Ok even though integrity-failed");

    assert!(
        !status.forward_ce,
        "I-flagged TLV must not count as a CE signal: {}",
        status
    );
}

#[test]
fn test_validate_reflected_tlvs_cos_ce_m_flagged_before_it_halts_scan() {
    // RFC 8972 §4-18: an M-flagged TLV halts processing of the
    // *remainder* of the packet — a CE-marked CoS TLV that comes after
    // it in wire order must not be reached.
    let mut bad = crate::tlv::RawTlv::new(crate::tlv::TlvType::MicroSessionId, vec![0, 0, 0]);
    bad.set_malformed();
    let mut good = ClassOfServiceTlv {
        dscp1: 0,
        ecn1: 1,
        dscp2: 0,
        ecn2: 0b11,
        rpd: 0,
        rpe: 0b11,
    }
    .to_raw();
    good.clear_reflector_flags();

    let mut tlvs = TlvList::new();
    tlvs.push(bad).unwrap();
    tlvs.push(good).unwrap();

    let status = validate_reflected_tlvs(
        &tlvs,
        &[0u8; 44],
        44,
        None,
        None,
        None,
        &mut None,
        false, // track_access_report
        true,  // track_congestion
        #[cfg(feature = "metrics")]
        false,
    )
    .expect("Ok — M just halts the scan, doesn't reject");

    assert!(
        !status.forward_ce,
        "M-flag must halt the scan before the later CoS TLV: {}",
        status
    );
}

#[test]
fn test_validate_reflected_tlvs_cos_ce_suppressed_by_tlv_hmac_failure() {
    // Failed TLV-HMAC verification must prevent a forged CE signal from
    // triggering backoff (RFC 8972 §4.8-17).
    let key = HmacKey::new(vec![0xAB; 32]).unwrap();
    let mut tlvs = TlvList::new();
    let mut cos = ClassOfServiceTlv {
        dscp1: 0,
        ecn1: 1,
        dscp2: 0,
        ecn2: 0b11,
        rpd: 0,
        rpe: 0b11,
    }
    .to_raw();
    cos.clear_reflector_flags();
    tlvs.push(cos).unwrap();
    // A bogus HMAC TLV value that will never verify against the data.
    tlvs.push(crate::tlv::RawTlv::with_flags(
        crate::tlv::TlvFlags::default(),
        crate::tlv::TlvType::Hmac,
        vec![0u8; 16],
    ))
    .unwrap();

    let data = [0u8; 128];
    let status = validate_reflected_tlvs(
        &tlvs,
        &data,
        44,
        Some(&key),
        None,
        None,
        &mut None,
        false, // track_access_report
        true,  // track_congestion
        #[cfg(feature = "metrics")]
        false,
    )
    .expect("TLV-HMAC failure must stop TLV processing → accept, not reject");

    assert!(status.hmac == HmacStatus::Failed, "got: {}", status);
    assert!(
        !status.forward_ce,
        "forged CE signal must be ignored on HMAC failure: {}",
        status
    );
}

// --- process_response: Access Report acknowledgment wiring (§4.6) -----

#[test]
fn test_process_response_acknowledges_access_report_state() {
    use crate::packets::{ExtendedReflectedPacketUnauthenticated, ReflectedPacketUnauthenticated};

    let reflected = ReflectedPacketUnauthenticated {
        sequence_number: 1,
        timestamp: 0,
        error_estimate: 0,
        ssid: 0,
        receive_timestamp: 0,
        sess_sender_seq_number: 1,
        sess_sender_timestamp: 0,
        sess_sender_err_estimate: 0,
        mbz2: [0; 2],
        sess_sender_ttl: 0,
        mbz3: [0; 3],
    };
    let mut tlvs = TlvList::new();
    let mut ar = AccessReportTlv::new(1, 1).to_raw();
    ar.clear_reflector_flags();
    tlvs.push(ar).unwrap();
    let ext = ExtendedReflectedPacketUnauthenticated::with_tlvs(reflected, tlvs);
    let buf = ext.to_bytes();

    let mut pending = HashMap::new();
    pending.insert(
        1,
        PendingPacket {
            send_time: Instant::now(),
            send_timestamp: 0,
        },
    );
    let mut rtt_collector = RttCollector::new();
    let mut owd_collector = OwdCollector::new();
    let mut packets_received = 0u32;
    let mut latched_reflector_msid = None;
    let mut access_report_state = AccessReportRetransmitState::new(Duration::from_secs(3), 4);
    access_report_state.tick(Instant::now()); // simulate the original send having armed it
    let mut ctx = SenderRecvContext {
        local_error_estimate: None,
        measurements: None,
        ber: None,
        reflector_utc_offset: 0,
        pending: &mut pending,
        rtt_collector: &mut rtt_collector,
        owd_collector: &mut owd_collector,
        packets_received: &mut packets_received,
        print_stats: false,
        output_format: crate::stats::OutputFormat::Text,
        hmac_key: None,
        expected_sender_msid: None,
        expected_reflector_msid: None,
        latched_reflector_msid: &mut latched_reflector_msid,
        access_report_state: Some(&mut access_report_state),
        congestion: None,
        expected_ssid: None,
        on_zero_ssid: ZeroSsidAction::Continue,
        zero_ssid_seen: &mut false,
        #[cfg(feature = "metrics")]
        metrics_enabled: false,
        #[cfg(all(unix, feature = "snmp"))]
        snmp_stats: None,
    };

    process_response(&buf, false, true, ClockFormat::NTP, None, None, &mut ctx);

    assert_eq!(
        access_report_state.outcome(),
        AccessReportOutcome::Acknowledged
    );
}

#[test]
fn test_process_response_does_not_acknowledge_without_access_report_tlv() {
    use crate::packets::{ExtendedReflectedPacketUnauthenticated, ReflectedPacketUnauthenticated};

    // A reply with no TLVs at all must leave the timer armed.
    let reflected = ReflectedPacketUnauthenticated {
        sequence_number: 1,
        timestamp: 0,
        error_estimate: 0,
        ssid: 0,
        receive_timestamp: 0,
        sess_sender_seq_number: 1,
        sess_sender_timestamp: 0,
        sess_sender_err_estimate: 0,
        mbz2: [0; 2],
        sess_sender_ttl: 0,
        mbz3: [0; 3],
    };
    let ext = ExtendedReflectedPacketUnauthenticated::with_tlvs(reflected, TlvList::new());
    let buf = ext.to_bytes();

    let mut pending = HashMap::new();
    pending.insert(
        1,
        PendingPacket {
            send_time: Instant::now(),
            send_timestamp: 0,
        },
    );
    let mut rtt_collector = RttCollector::new();
    let mut owd_collector = OwdCollector::new();
    let mut packets_received = 0u32;
    let mut latched_reflector_msid = None;
    let mut access_report_state = AccessReportRetransmitState::new(Duration::from_secs(3), 4);
    access_report_state.tick(Instant::now());
    let mut ctx = SenderRecvContext {
        local_error_estimate: None,
        measurements: None,
        ber: None,
        reflector_utc_offset: 0,
        pending: &mut pending,
        rtt_collector: &mut rtt_collector,
        owd_collector: &mut owd_collector,
        packets_received: &mut packets_received,
        print_stats: false,
        output_format: crate::stats::OutputFormat::Text,
        hmac_key: None,
        expected_sender_msid: None,
        expected_reflector_msid: None,
        latched_reflector_msid: &mut latched_reflector_msid,
        access_report_state: Some(&mut access_report_state),
        congestion: None,
        expected_ssid: None,
        on_zero_ssid: ZeroSsidAction::Continue,
        zero_ssid_seen: &mut false,
        #[cfg(feature = "metrics")]
        metrics_enabled: false,
        #[cfg(all(unix, feature = "snmp"))]
        snmp_stats: None,
    };

    process_response(&buf, false, true, ClockFormat::NTP, None, None, &mut ctx);

    assert_eq!(access_report_state.outcome(), AccessReportOutcome::Pending);
}

// --- process_response: AIMD congestion-response wiring
// (draft-ietf-ippm-stamp-cos-ecn-01 §3.4) ---------------------

fn congestion_test_params() -> AimdParams {
    AimdParams {
        base_interval: Duration::from_millis(100),
        backoff_factor: 2.0,
        max_interval: Duration::from_millis(1600),
        recovery_step: Duration::from_millis(10),
    }
}

fn congestion_process_response_ctx<'a>(
    pending: &'a mut HashMap<u32, PendingPacket>,
    rtt_collector: &'a mut RttCollector,
    owd_collector: &'a mut OwdCollector,
    packets_received: &'a mut u32,
    latched_reflector_msid: &'a mut Option<u16>,
    congestion: Option<&'a mut CongestionState>,
    zero_ssid_seen: &'a mut bool,
) -> SenderRecvContext<'a> {
    SenderRecvContext {
        local_error_estimate: None,
        measurements: None,
        ber: None,
        reflector_utc_offset: 0,
        pending,
        rtt_collector,
        owd_collector,
        packets_received,
        print_stats: false,
        output_format: crate::stats::OutputFormat::Text,
        hmac_key: None,
        expected_sender_msid: None,
        expected_reflector_msid: None,
        latched_reflector_msid,
        access_report_state: None,
        congestion,
        expected_ssid: None,
        on_zero_ssid: ZeroSsidAction::Continue,
        zero_ssid_seen,
        #[cfg(feature = "metrics")]
        metrics_enabled: false,
        #[cfg(all(unix, feature = "snmp"))]
        snmp_stats: None,
    }
}

#[test]
fn test_process_response_forward_path_ce_backs_off_congestion_controller() {
    use crate::packets::{ExtendedReflectedPacketUnauthenticated, ReflectedPacketUnauthenticated};

    let reflected = ReflectedPacketUnauthenticated {
        sequence_number: 1,
        timestamp: 0,
        error_estimate: 0,
        ssid: 0,
        receive_timestamp: 0,
        sess_sender_seq_number: 1,
        sess_sender_timestamp: 0,
        sess_sender_err_estimate: 0,
        mbz2: [0; 2],
        sess_sender_ttl: 0,
        mbz3: [0; 3],
    };
    let mut tlvs = TlvList::new();
    let mut cos = ClassOfServiceTlv {
        dscp1: 0,
        ecn1: 1,
        dscp2: 0,
        ecn2: 0b11, // CE observed at the reflector's ingress (forward path)
        rpd: 0,
        rpe: 0b11,
    }
    .to_raw();
    cos.clear_reflector_flags();
    tlvs.push(cos).unwrap();
    let ext = ExtendedReflectedPacketUnauthenticated::with_tlvs(reflected, tlvs);
    let buf = ext.to_bytes();

    let mut pending = HashMap::new();
    pending.insert(
        1,
        PendingPacket {
            send_time: Instant::now(),
            send_timestamp: 0,
        },
    );
    let mut rtt_collector = RttCollector::new();
    let mut owd_collector = OwdCollector::new();
    let mut packets_received = 0u32;
    let mut latched_reflector_msid = None;
    let mut congestion = CongestionState::new(congestion_test_params());
    let mut zero_ssid_seen = false;
    let mut ctx = congestion_process_response_ctx(
        &mut pending,
        &mut rtt_collector,
        &mut owd_collector,
        &mut packets_received,
        &mut latched_reflector_msid,
        Some(&mut congestion),
        &mut zero_ssid_seen,
    );

    // No reply-ECN plumbing in this test (reverse path absent).
    process_response(&buf, false, true, ClockFormat::NTP, None, None, &mut ctx);

    assert_eq!(
        congestion.controller.current_interval(),
        Duration::from_millis(200),
        "forward-path CE (reflected EC2) must double the interval"
    );
    assert_eq!(congestion.controller.stats().ce_observations, 1);
}

#[test]
fn test_process_response_reverse_path_ce_backs_off_congestion_controller() {
    use crate::packets::{ExtendedReflectedPacketUnauthenticated, ReflectedPacketUnauthenticated};

    // No CoS TLV at all — the only CE signal is the reply's own on-wire
    // ECN, passed as `reply_ecn`.
    let reflected = ReflectedPacketUnauthenticated {
        sequence_number: 2,
        timestamp: 0,
        error_estimate: 0,
        ssid: 0,
        receive_timestamp: 0,
        sess_sender_seq_number: 2,
        sess_sender_timestamp: 0,
        sess_sender_err_estimate: 0,
        mbz2: [0; 2],
        sess_sender_ttl: 0,
        mbz3: [0; 3],
    };
    let ext = ExtendedReflectedPacketUnauthenticated::with_tlvs(reflected, TlvList::new());
    let buf = ext.to_bytes();

    let mut pending = HashMap::new();
    pending.insert(
        2,
        PendingPacket {
            send_time: Instant::now(),
            send_timestamp: 0,
        },
    );
    let mut rtt_collector = RttCollector::new();
    let mut owd_collector = OwdCollector::new();
    let mut packets_received = 0u32;
    let mut latched_reflector_msid = None;
    let mut congestion = CongestionState::new(congestion_test_params());
    let mut zero_ssid_seen = false;
    let mut ctx = congestion_process_response_ctx(
        &mut pending,
        &mut rtt_collector,
        &mut owd_collector,
        &mut packets_received,
        &mut latched_reflector_msid,
        Some(&mut congestion),
        &mut zero_ssid_seen,
    );

    process_response(
        &buf,
        false,
        true,
        ClockFormat::NTP,
        None,
        Some(0b11),
        &mut ctx,
    );

    assert_eq!(
        congestion.controller.current_interval(),
        Duration::from_millis(200),
        "reverse-path CE (reply's on-wire ECN) must double the interval"
    );
    assert_eq!(congestion.controller.stats().ce_observations, 1);
}

#[test]
fn test_process_response_clean_reply_recovers_congestion_controller() {
    use crate::packets::{ExtendedReflectedPacketUnauthenticated, ReflectedPacketUnauthenticated};

    let reflected = ReflectedPacketUnauthenticated {
        sequence_number: 3,
        timestamp: 0,
        error_estimate: 0,
        ssid: 0,
        receive_timestamp: 0,
        sess_sender_seq_number: 3,
        sess_sender_timestamp: 0,
        sess_sender_err_estimate: 0,
        mbz2: [0; 2],
        sess_sender_ttl: 0,
        mbz3: [0; 3],
    };
    let ext = ExtendedReflectedPacketUnauthenticated::with_tlvs(reflected, TlvList::new());
    let buf = ext.to_bytes();

    let mut pending = HashMap::new();
    pending.insert(
        3,
        PendingPacket {
            send_time: Instant::now(),
            send_timestamp: 0,
        },
    );
    let mut rtt_collector = RttCollector::new();
    let mut owd_collector = OwdCollector::new();
    let mut packets_received = 0u32;
    let mut latched_reflector_msid = None;
    let mut congestion = CongestionState::new(congestion_test_params());
    congestion.controller.on_ce_observed(); // pre-back off to 200ms
    assert_eq!(
        congestion.controller.current_interval(),
        Duration::from_millis(200)
    );
    let mut zero_ssid_seen = false;
    let mut ctx = congestion_process_response_ctx(
        &mut pending,
        &mut rtt_collector,
        &mut owd_collector,
        &mut packets_received,
        &mut latched_reflector_msid,
        Some(&mut congestion),
        &mut zero_ssid_seen,
    );

    // Neither direction CE-marked: a clean reply recovers by the
    // configured step (10ms in `congestion_test_params`).
    process_response(&buf, false, true, ClockFormat::NTP, None, None, &mut ctx);

    assert_eq!(
        congestion.controller.current_interval(),
        Duration::from_millis(190)
    );
    assert_eq!(congestion.controller.stats().ce_observations, 1);
}

#[test]
fn test_process_response_no_panic_when_congestion_inactive() {
    use crate::packets::{ExtendedReflectedPacketUnauthenticated, ReflectedPacketUnauthenticated};

    let reflected = ReflectedPacketUnauthenticated {
        sequence_number: 4,
        timestamp: 0,
        error_estimate: 0,
        ssid: 0,
        receive_timestamp: 0,
        sess_sender_seq_number: 4,
        sess_sender_timestamp: 0,
        sess_sender_err_estimate: 0,
        mbz2: [0; 2],
        sess_sender_ttl: 0,
        mbz3: [0; 3],
    };
    let ext = ExtendedReflectedPacketUnauthenticated::with_tlvs(reflected, TlvList::new());
    let buf = ext.to_bytes();

    let mut pending = HashMap::new();
    pending.insert(
        4,
        PendingPacket {
            send_time: Instant::now(),
            send_timestamp: 0,
        },
    );
    let mut rtt_collector = RttCollector::new();
    let mut owd_collector = OwdCollector::new();
    let mut packets_received = 0u32;
    let mut latched_reflector_msid = None;
    // `--cos`/`--ecn` not requesting ECT0/ECT1: controller absent.
    let mut zero_ssid_seen = false;
    let mut ctx = congestion_process_response_ctx(
        &mut pending,
        &mut rtt_collector,
        &mut owd_collector,
        &mut packets_received,
        &mut latched_reflector_msid,
        None,
        &mut zero_ssid_seen,
    );

    // Must not panic even with a reverse-path CE reading present.
    process_response(
        &buf,
        false,
        true,
        ClockFormat::NTP,
        None,
        Some(0b11),
        &mut ctx,
    );

    assert_eq!(*ctx.packets_received, 1);
}

// Access Report acknowledgment through sender serialization, reflector
// assembly, and sender parsing, without sockets.

#[test]
fn test_access_report_loopback_acked_on_first_reply() {
    use crate::configuration::TlvHandlingMode;
    use crate::packets::PacketUnauthenticated;
    use crate::receiver::{assemble_unauth_answer_with_tlvs, ProcessingContext};

    let access_id = 1u8;
    let return_code = 1u8;
    let extra_tlvs = [AccessReportTlv::new(access_id, return_code).to_raw()];

    let mut access_report_state = AccessReportRetransmitState::new(Duration::from_secs(3), 4);
    let send_time = Instant::now();
    assert!(access_report_state.tick(send_time));

    let seq_num = 1u32;
    let send_timestamp = generate_timestamp(ClockFormat::NTP);
    let request_bytes =
        build_unauth_packet_with_tlvs(seq_num, send_timestamp, 0, None, &extra_tlvs, None);

    // --- Reflector side: pure, socket-free assembly ---
    let packet = PacketUnauthenticated::from_bytes(&request_bytes).unwrap();
    let ctx = ProcessingContext {
        ingress_ifindex: None,
        packet_local_addr: None,
        replay_verdict: crate::session::ReplayVerdict::New,
        clock_source: ClockFormat::NTP,
        clock_sync_source: crate::tlv::SyncSource::Local,
        hardware_clock_sync_source: crate::tlv::SyncSource::Local,
        error_estimate_wire: 0,
        hmac_key: None,
        hmac_key_set: None,
        require_hmac: false,
        session_manager: None,
        stateful_reflector: false,
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
        cos_policy: crate::cos_policy::permissive(),
        local_addresses: &[],
        local_macs: &[],
        sender_port: 0,
        return_path_allow_alternate: false,
        reflector_member_link_id: None,
        captured_headers: None,
        reflected_control_max_count: crate::receiver::REFLECTED_CONTROL_MAX_COUNT,
        reflected_control_max_size: crate::receiver::REFLECTED_CONTROL_MAX_SIZE,
        reflected_control_min_interval_ns: crate::receiver::REFLECTED_CONTROL_MIN_INTERVAL_NS,
        reflected_control_max_rate: crate::receiver::REFLECTED_CONTROL_MAX_RATE,
        reflected_control_max_volume: crate::receiver::REFLECTED_CONTROL_MAX_VOLUME,
        rx_timestamp: None,
        rx_method: crate::tlv::TimestampMethod::SwLocal,
        last_reflection_method: crate::tlv::TimestampMethod::SwLocal,
    };
    let response = assemble_unauth_answer_with_tlvs(
        &packet,
        &request_bytes,
        ClockFormat::NTP,
        generate_timestamp(ClockFormat::NTP),
        64,
        0,
        None,
        TlvHandlingMode::Echo,
        None,
        false,
        &ctx,
    );

    // --- Sender side: process the reflected reply exactly as the send
    // loop's receive path would ---
    let mut pending = HashMap::new();
    pending.insert(
        seq_num,
        PendingPacket {
            send_time,
            send_timestamp,
        },
    );
    let mut rtt_collector = RttCollector::new();
    let mut owd_collector = OwdCollector::new();
    let mut packets_received = 0u32;
    let mut latched_reflector_msid = None;
    let mut recv_ctx = SenderRecvContext {
        local_error_estimate: None,
        measurements: None,
        ber: None,
        reflector_utc_offset: 0,
        pending: &mut pending,
        rtt_collector: &mut rtt_collector,
        owd_collector: &mut owd_collector,
        packets_received: &mut packets_received,
        print_stats: false,
        output_format: crate::stats::OutputFormat::Text,
        hmac_key: None,
        expected_sender_msid: None,
        expected_reflector_msid: None,
        latched_reflector_msid: &mut latched_reflector_msid,
        access_report_state: Some(&mut access_report_state),
        congestion: None,
        expected_ssid: None,
        on_zero_ssid: ZeroSsidAction::Continue,
        zero_ssid_seen: &mut false,
        #[cfg(feature = "metrics")]
        metrics_enabled: false,
        #[cfg(all(unix, feature = "snmp"))]
        snmp_stats: None,
    };
    process_response(
        &response.data,
        false,
        true,
        ClockFormat::NTP,
        None,
        None,
        &mut recv_ctx,
    );

    assert_eq!(
        access_report_state.outcome(),
        AccessReportOutcome::Acknowledged,
        "a conforming reflector's echo must acknowledge on the first reply"
    );
    assert_eq!(access_report_state.retransmissions(), 0);
    assert_eq!(packets_received, 1, "RTT accounting must proceed as normal");
}

#[test]
fn test_access_report_no_reflector_echo_leads_to_retransmit_then_abort() {
    // Simulates total silence from the reflector (packet lost / dropped)
    // by simply never calling `acknowledge()` — only driving `tick`
    // forward in time, exactly as the send loop does every iteration.
    let mut state = AccessReportRetransmitState::new(Duration::from_secs(3), 4);
    let mut now = Instant::now();

    assert!(state.tick(now), "iteration 0: original send");
    for expected_retransmissions in 1..=4u32 {
        now += Duration::from_secs(3) + Duration::from_millis(1);
        assert!(
            state.tick(now),
            "iteration {expected_retransmissions}: must retransmit"
        );
        assert_eq!(state.retransmissions(), expected_retransmissions);
        assert_eq!(state.outcome(), AccessReportOutcome::Pending);
    }

    // One more expiry past the 4th retransmission aborts the procedure
    // (RFC 8972 §4.6: "repeated up to four times before the procedure
    // is aborted").
    now += Duration::from_secs(3) + Duration::from_millis(1);
    assert!(!state.tick(now), "must not attach after aborting");
    assert_eq!(state.outcome(), AccessReportOutcome::Aborted);
    assert_eq!(state.retransmissions(), 4);
}

// Post-loop Access Report retries over loopback UDP (RFC 8972 §4.6).
// Short runs such as `--count 1` must retry until acknowledged or aborted.
// CLI timeouts use whole seconds, so these tests require real waits.

/// Loopback configuration with Access Report enabled and short retry limits.
/// `--timeout 1` also bounds the initial response wait.
fn access_report_test_config(
    remote_port: u16,
    access_report_timeout_secs: u32,
    access_report_retries: u32,
) -> Configuration {
    use clap::Parser;
    let args: Vec<String> = vec![
        "test".to_string(),
        "--remote-addr".to_string(),
        "127.0.0.1".to_string(),
        "--remote-port".to_string(),
        remote_port.to_string(),
        "--local-addr".to_string(),
        "127.0.0.1".to_string(),
        "--local-port".to_string(),
        "0".to_string(),
        "--count".to_string(),
        "1".to_string(),
        "--send-delay".to_string(),
        "10".to_string(),
        "--timeout".to_string(),
        "1".to_string(),
        "--access-report".to_string(),
        "1".to_string(),
        "--access-report-timeout".to_string(),
        access_report_timeout_secs.to_string(),
        "--access-report-retries".to_string(),
        access_report_retries.to_string(),
    ];
    Configuration::parse_from(args)
}

/// One-packet loopback configuration for wire-level flag tests.
fn wire_test_config(port: u16, extra: &[&str]) -> Configuration {
    use clap::Parser;
    let mut args: Vec<String> = vec![
        "test",
        "--remote-addr",
        "127.0.0.1",
        "--remote-port",
        &port.to_string(),
        "--local-addr",
        "127.0.0.1",
        "--local-port",
        "0",
        "--count",
        "1",
        "--send-delay",
        "10",
        "--timeout",
        "1",
    ]
    .into_iter()
    .map(String::from)
    .collect();
    args.extend(extra.iter().map(|s| String::from(*s)));
    Configuration::parse_from(args)
}

/// Collects the TLV types of the first packet a `run_sender` call emits.
async fn first_packet_tlv_types(conf: Configuration) -> Vec<TlvType> {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let port = socket.local_addr().unwrap().port();
    let conf = Configuration {
        remote_port: port,
        ..conf
    };
    let reflector = tokio::spawn(collect_silently(socket, 1, Duration::from_secs(5)));
    let _ = tokio::time::timeout(Duration::from_secs(8), run_sender(&conf, None)).await;
    let packets = reflector.await.unwrap();
    assert!(!packets.is_empty(), "the sender must emit a packet");
    let tlvs = TlvList::parse(&packets[0][UNAUTH_BASE_SIZE..]).expect("TLV area must parse");
    tlvs.iter().map(|t| t.tlv_type).collect()
}

#[tokio::test]
async fn test_extra_padding_flag_emits_a_padding_tlv() {
    // Without the flag there is no Extra Padding TLV at all.
    let types = first_packet_tlv_types(wire_test_config(0, &[])).await;
    assert!(
        !types.contains(&TlvType::ExtraPadding),
        "no padding by default; got {types:?}"
    );

    // With it, exactly one, independent of --ber.
    let types = first_packet_tlv_types(wire_test_config(0, &["--extra-padding", "64"])).await;
    assert_eq!(
        types
            .iter()
            .filter(|t| **t == TlvType::ExtraPadding)
            .count(),
        1,
        "expected one Extra Padding TLV; got {types:?}"
    );
}

#[tokio::test]
async fn test_ber_omit_burst_drops_only_type_242() {
    // Baseline: --ber emits pattern, count and burst, plus its padding.
    let types = first_packet_tlv_types(wire_test_config(0, &["--ber"])).await;
    assert!(types.contains(&TlvType::BerBurst), "got {types:?}");
    assert!(types.contains(&TlvType::BerPattern), "got {types:?}");
    assert!(types.contains(&TlvType::BerCount), "got {types:?}");

    // With the flag, Type 242 is gone and the rest of the exchange stands.
    let types = first_packet_tlv_types(wire_test_config(0, &["--ber", "--ber-omit-burst"])).await;
    assert!(
        !types.contains(&TlvType::BerBurst),
        "Type 242 must be omitted; got {types:?}"
    );
    assert!(
        types.contains(&TlvType::BerPattern) && types.contains(&TlvType::BerCount),
        "the rest of the BER TLVs must remain; got {types:?}"
    );
    assert!(
        types.contains(&TlvType::ExtraPadding),
        "BER's pattern-filled padding must remain; got {types:?}"
    );
}

#[tokio::test]
async fn test_tlv_hmac_mode_controls_origination() {
    const KEY: &str = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";

    // auto (the default) with a key: the HMAC TLV is originated.
    let types = first_packet_tlv_types(wire_test_config(
        0,
        &["--hmac-key", KEY, "--timestamp-info"],
    ))
    .await;
    assert!(
        types.contains(&TlvType::Hmac),
        "auto must originate with a key configured; got {types:?}"
    );

    // off: no HMAC TLV on the wire even though the key is still configured
    // (and still used to verify replies).
    let types = first_packet_tlv_types(wire_test_config(
        0,
        &["--hmac-key", KEY, "--timestamp-info", "--tlv-hmac", "off"],
    ))
    .await;
    assert!(
        !types.contains(&TlvType::Hmac),
        "off must not originate an HMAC TLV; got {types:?}"
    );
    assert!(
        types.contains(&TlvType::TimestampInfo),
        "the other TLVs must be unaffected; got {types:?}"
    );
}

/// Access Report test configuration with AIMD and a reflected burst.
/// This forces per-send control TLV rebuilding via `scale_reflected_control`.
fn access_report_with_scaled_control_config(
    remote_port: u16,
    access_report_timeout_secs: u32,
    access_report_retries: u32,
) -> Configuration {
    use clap::Parser;
    let args: Vec<String> = vec![
        "test".to_string(),
        "--remote-addr".to_string(),
        "127.0.0.1".to_string(),
        "--remote-port".to_string(),
        remote_port.to_string(),
        "--local-addr".to_string(),
        "127.0.0.1".to_string(),
        "--local-port".to_string(),
        "0".to_string(),
        "--count".to_string(),
        "1".to_string(),
        "--send-delay".to_string(),
        "10".to_string(),
        "--timeout".to_string(),
        "1".to_string(),
        "--access-report".to_string(),
        "1".to_string(),
        "--access-report-timeout".to_string(),
        access_report_timeout_secs.to_string(),
        "--access-report-retries".to_string(),
        access_report_retries.to_string(),
        // AIMD congestion response: needs --cos with an ECT codepoint.
        "--cos".to_string(),
        "--ecn".to_string(),
        "1".to_string(),
        // A burst request (> 1) makes scale_reflected_control true.
        "--reflected-control-count".to_string(),
        "2".to_string(),
    ];
    Configuration::parse_from(args)
}

/// Wait-phase retries must rebuild the AIMD-scaled control TLV omitted from
/// `extra_tlvs` (draft-ietf-ippm-stamp-cos-ecn-01 §3.4-3).
#[tokio::test]
async fn test_wait_phase_retransmit_still_carries_scaled_control_tlv() {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let port = socket.local_addr().unwrap().port();
    let conf = access_report_with_scaled_control_config(port, 1, 2);

    let reflector = tokio::spawn(collect_silently(socket, 3, Duration::from_secs(8)));
    let _ = tokio::time::timeout(Duration::from_secs(10), run_sender(&conf, None))
        .await
        .expect("run_sender must not hang past the retry budget")
        .expect("run_sender must start successfully");
    let packets = reflector.await.unwrap();

    assert!(
        packets.len() >= 2,
        "need the original send plus at least one retransmission, got {}",
        packets.len()
    );

    for (i, packet) in packets.iter().enumerate() {
        let tlvs = TlvList::parse(&packet[UNAUTH_BASE_SIZE..])
            .unwrap_or_else(|e| panic!("attempt {i} TLV area must parse: {e:?}"));
        assert!(
            tlvs.iter()
                .any(|t| matches!(t.tlv_type, TlvType::ReflectedControl)),
            "attempt {i} must carry the Reflected Control TLV (§3.4-3); \
                 TLV types present: {:?}",
            tlvs.iter().map(|t| t.tlv_type).collect::<Vec<_>>()
        );
    }
}

/// Collects up to `want` datagrams without replying, bounded by `budget`.
async fn collect_silently(socket: UdpSocket, want: usize, budget: Duration) -> Vec<Vec<u8>> {
    let mut packets = Vec::new();
    let deadline = tokio::time::Instant::now() + budget;
    let mut buf = [0u8; 1024];
    while packets.len() < want {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            break;
        }
        match tokio::time::timeout(remaining, socket.recv_from(&mut buf)).await {
            Ok(Ok((len, _src))) => packets.push(buf[..len].to_vec()),
            _ => break,
        }
    }
    packets
}

/// Acknowledges packet `ack_after` (1-indexed) with a reflector-built reply,
/// then listens silently for `extra_wait` to detect further retransmissions.
/// Returns the total packet count. `max_wait` bounds the wait for acknowledgment.
async fn ack_nth_then_watch_for_more(
    socket: UdpSocket,
    ack_after: usize,
    extra_wait: Duration,
    max_wait: Duration,
) -> usize {
    use crate::configuration::TlvHandlingMode;
    use crate::packets::PacketUnauthenticated;
    use crate::receiver::{assemble_unauth_answer_with_tlvs, ProcessingContext};

    let deadline = tokio::time::Instant::now() + max_wait;
    let mut buf = [0u8; 1024];
    let mut received = 0usize;
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            break;
        }
        let (len, src) = match tokio::time::timeout(remaining, socket.recv_from(&mut buf)).await {
            Ok(Ok(v)) => v,
            _ => break,
        };
        received += 1;
        if received == ack_after {
            let packet = PacketUnauthenticated::from_bytes(&buf[..len]).unwrap();
            let ctx = ProcessingContext {
                ingress_ifindex: None,
                packet_local_addr: None,
                replay_verdict: crate::session::ReplayVerdict::New,
                clock_source: ClockFormat::NTP,
                clock_sync_source: crate::tlv::SyncSource::Local,
                hardware_clock_sync_source: crate::tlv::SyncSource::Local,
                error_estimate_wire: 0,
                hmac_key: None,
                hmac_key_set: None,
                require_hmac: false,
                session_manager: None,
                stateful_reflector: false,
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
                cos_policy: crate::cos_policy::permissive(),
                local_addresses: &[],
                local_macs: &[],
                sender_port: 0,
                return_path_allow_alternate: false,
                reflector_member_link_id: None,
                captured_headers: None,
                reflected_control_max_count: crate::receiver::REFLECTED_CONTROL_MAX_COUNT,
                reflected_control_max_size: crate::receiver::REFLECTED_CONTROL_MAX_SIZE,
                reflected_control_min_interval_ns:
                    crate::receiver::REFLECTED_CONTROL_MIN_INTERVAL_NS,
                reflected_control_max_rate: crate::receiver::REFLECTED_CONTROL_MAX_RATE,
                reflected_control_max_volume: crate::receiver::REFLECTED_CONTROL_MAX_VOLUME,
                rx_timestamp: None,
                rx_method: crate::tlv::TimestampMethod::SwLocal,
                last_reflection_method: crate::tlv::TimestampMethod::SwLocal,
            };
            let response = assemble_unauth_answer_with_tlvs(
                &packet,
                &buf[..len],
                ClockFormat::NTP,
                generate_timestamp(ClockFormat::NTP),
                64,
                0,
                None,
                TlvHandlingMode::Echo,
                None,
                false,
                &ctx,
            );
            let _ = socket.send_to(&response.data, src).await;

            // Keep watching to prove the sender does not retransmit
            // again after being acknowledged.
            let watch_deadline = tokio::time::Instant::now() + extra_wait;
            loop {
                let remaining =
                    watch_deadline.saturating_duration_since(tokio::time::Instant::now());
                if remaining.is_zero() {
                    break;
                }
                match tokio::time::timeout(remaining, socket.recv_from(&mut buf)).await {
                    Ok(Ok(_)) => received += 1,
                    _ => break,
                }
            }
            break;
        }
    }
    received
}

#[tokio::test]
async fn test_wait_phase_retransmits_when_reflector_silent_then_aborts() {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let port = socket.local_addr().unwrap().port();

    // timeout=1s, retries=2 ⇒ retry budget = 1*(1+2) = 3s worst case,
    // on top of the pre-existing plain 1s wait before the extension
    // even starts.
    let conf = access_report_test_config(port, 1, 2);

    let reflector = tokio::spawn(collect_silently(socket, 4, Duration::from_secs(8)));
    let snapshot = tokio::time::timeout(Duration::from_secs(10), run_sender(&conf, None))
        .await
        .expect("run_sender must not hang past the retry budget")
        .expect("run_sender must start successfully");
    let packets = reflector.await.unwrap();

    // Original send + exactly `retries` (2) retransmissions — no more:
    // the retry budget caps it, since the reflector never acks.
    assert_eq!(
        packets.len(),
        3,
        "expected 1 original send + 2 retransmissions, got {}",
        packets.len()
    );

    let summary = snapshot
        .access_report
        .expect("Access Report summary must be present when --access-report is set");
    assert_eq!(summary.outcome, AccessReportOutcome::Aborted);
    assert_eq!(summary.retransmissions, 2);
    assert_eq!(
        snapshot.packets_sent, 3,
        "sent count must reflect the retransmissions"
    );

    // Access Report wire bytes must remain identical across attempts.
    // It is the only TLV after the unauthenticated base in this configuration.
    let expected_tlv = AccessReportTlv::new(1, 1).to_raw().to_bytes();
    for (i, packet) in packets.iter().enumerate() {
        assert_eq!(
            &packet[UNAUTH_BASE_SIZE..],
            expected_tlv.as_slice(),
            "attempt {i}'s Access Report TLV bytes must match every other attempt"
        );
    }
}

#[tokio::test]
async fn test_wait_phase_ack_mid_wait_stops_retransmitting() {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let port = socket.local_addr().unwrap().port();

    // Acknowledge the first retry to exercise the post-loop receive path.
    // With timeout=1s and retries=3, an unacknowledged exchange has a 4s budget.
    let conf = access_report_test_config(port, 1, 3);

    let reflector = tokio::spawn(ack_nth_then_watch_for_more(
        socket,
        2,
        Duration::from_secs(1),
        Duration::from_secs(6),
    ));
    let snapshot = tokio::time::timeout(Duration::from_secs(10), run_sender(&conf, None))
        .await
        .expect("run_sender must finish promptly once acknowledged")
        .expect("run_sender must start successfully");
    let received = reflector.await.unwrap();

    assert_eq!(
        received, 2,
        "must stop sending after the ack — original + exactly 1 retransmission"
    );

    let summary = snapshot
        .access_report
        .expect("Access Report summary must be present when --access-report is set");
    assert_eq!(summary.outcome, AccessReportOutcome::Acknowledged);
    assert_eq!(summary.retransmissions, 1);
}

#[tokio::test]
async fn test_wait_phase_unaffected_when_access_report_disabled() {
    use clap::Parser;

    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let port = socket.local_addr().unwrap().port();

    let args: Vec<String> = vec![
        "test".to_string(),
        "--remote-addr".to_string(),
        "127.0.0.1".to_string(),
        "--remote-port".to_string(),
        port.to_string(),
        "--local-addr".to_string(),
        "127.0.0.1".to_string(),
        "--local-port".to_string(),
        "0".to_string(),
        "--count".to_string(),
        "1".to_string(),
        "--send-delay".to_string(),
        "10".to_string(),
        "--timeout".to_string(),
        "1".to_string(),
    ];
    let conf = Configuration::parse_from(args);

    let reflector = tokio::spawn(collect_silently(socket, 10, Duration::from_millis(1300)));
    let start = Instant::now();
    let snapshot = tokio::time::timeout(Duration::from_secs(5), run_sender(&conf, None))
        .await
        .expect("run_sender must finish promptly with no Access Report extension")
        .expect("run_sender must start successfully");
    let elapsed = start.elapsed();
    let packets = reflector.await.unwrap();

    // Without `--access-report`, only the one-second `--timeout` applies.
    assert!(
        elapsed < Duration::from_millis(1500),
        "wait phase must not be extended when --access-report is unset (took {elapsed:?})"
    );
    assert_eq!(packets.len(), 1, "no retransmission logic applies at all");
    assert!(snapshot.access_report.is_none());
    assert_eq!(snapshot.packets_sent, 1);
    assert_eq!(snapshot.packets_lost, 1);
}

#[test]
fn malformed_bad_length_overruns_declared_length() {
    use crate::tlv::TLV_HEADER_SIZE;
    let bytes = malformed_tlv_bytes(MalformedMode::BadLength);
    assert!(bytes.len() >= TLV_HEADER_SIZE);
    let declared = u16::from_be_bytes([bytes[2], bytes[3]]) as usize;
    let actual_value = bytes.len() - TLV_HEADER_SIZE;
    assert!(
        declared > actual_value,
        "declared length {declared} must overrun actual {actual_value}"
    );
}

#[test]
fn malformed_bad_flags_sets_reserved_bits_but_valid_length() {
    use crate::tlv::TLV_HEADER_SIZE;
    let bytes = malformed_tlv_bytes(MalformedMode::BadFlags);
    // Reserved bits live below the C flag (0x10), i.e. mask 0x0F.
    assert_ne!(bytes[0] & 0x0F, 0, "reserved flag bits must be set");
    // This variant is malformed *only* in its flags: length stays correct.
    let declared = u16::from_be_bytes([bytes[2], bytes[3]]) as usize;
    assert_eq!(declared, bytes.len() - TLV_HEADER_SIZE);
}

/// Independent wire encoder exercises all four response parser branches.
fn check_clock_pair(
    local: ClockFormat,
    remote: ClockFormat,
    auth: bool,
    extensions: bool,
    seconds: i64,
    remote_offset: i32,
    invalid_ptp: bool,
) {
    fn wire(sec: i64, ns: u32, format: ClockFormat) -> u64 {
        let (sec, fraction) = match format {
            ClockFormat::NTP => (sec + 2_208_988_800, ((ns as u64) << 32) / 1_000_000_000),
            ClockFormat::PTP => (sec, ns as u64),
        };
        ((sec as u32 as u64) << 32) | fraction
    }
    // Straddle a whole second, including the NTP era boundary in 2036.
    let t1 = wire(seconds, 998_000_000, local);
    let t2 = wire(seconds + 1 + i64::from(remote_offset), 1_000_000, remote);
    let t3 = wire(seconds + 1 + i64::from(remote_offset), 2_000_000, remote);
    let t4 = wire(seconds + 1, 7_000_000, local);
    let key = HmacKey::new(vec![0xAB; 16]).unwrap();
    let base = if auth { 112 } else { 44 };
    let mut data = vec![0u8; base];
    data[..4].copy_from_slice(&9u32.to_be_bytes());
    let (send, error, receive, seq, echo, echo_error, ttl) = if auth {
        (16, 24, 32, 48, 64, 72, 80)
    } else {
        (4, 12, 16, 24, 28, 36, 40)
    };
    data[send..send + 8].copy_from_slice(&t3.to_be_bytes());
    let remote_error: u16 = if remote == ClockFormat::PTP {
        0xC001
    } else {
        0x8001
    };
    data[error..error + 2].copy_from_slice(&remote_error.to_be_bytes());
    data[receive..receive + 8].copy_from_slice(&t2.to_be_bytes());
    data[seq..seq + 4].copy_from_slice(&7u32.to_be_bytes());
    data[echo..echo + 8].copy_from_slice(&t1.to_be_bytes());
    let local_error: u16 = if local == ClockFormat::PTP { 0x4001 } else { 1 };
    data[echo_error..echo_error + 2].copy_from_slice(&local_error.to_be_bytes());
    data[ttl] = 64;
    if extensions {
        data.extend_from_slice(&[0, 1, 0, 4, 0, 0, 0, 0]);
    }
    if invalid_ptp {
        data[receive + 4..receive + 8].copy_from_slice(&1_000_000_000u32.to_be_bytes());
    }
    if auth {
        let hmac = crate::crypto::compute_packet_hmac(&key, &data, 96);
        data[96..112].copy_from_slice(&hmac);
    }
    let mut pending = HashMap::from([(
        7,
        PendingPacket {
            send_time: Instant::now(),
            send_timestamp: t1,
        },
    )]);
    let mut rtt = RttCollector::new();
    let mut owd = OwdCollector::new();
    let mut received = 0;
    let mut latched = None;
    let mut zero = false;
    let mut ctx = congestion_process_response_ctx(
        &mut pending,
        &mut rtt,
        &mut owd,
        &mut received,
        &mut latched,
        None,
        &mut zero,
    );
    ctx.hmac_key = auth.then_some(&key);
    ctx.reflector_utc_offset = remote_offset;
    process_response(&data, auth, extensions, local, Some(t4), None, &mut ctx);
    assert_eq!(received, 1);
    assert!(pending.is_empty());
    if invalid_ptp {
        assert!(owd.summary().is_none());
        assert!(rtt.percentile_ns(50.0).is_some());
        return;
    }
    let summary = owd.summary().unwrap();
    assert!(
        (summary.forward_avg_ms - 3.0).abs() <= 0.0000011,
        "{local:?}/{remote:?} auth={auth} extensions={extensions}: forward {}",
        summary.forward_avg_ms
    );
    assert!(
        (summary.reverse_avg_ms - 5.0).abs() <= 0.0000011,
        "{local:?}/{remote:?} auth={auth} extensions={extensions}: reverse {}",
        summary.reverse_avg_ms
    );
}

#[test]
fn response_mixed_clocks_all_parsers() {
    for (local, remote) in [
        (ClockFormat::NTP, ClockFormat::PTP),
        (ClockFormat::PTP, ClockFormat::NTP),
    ] {
        for auth in [false, true] {
            for extensions in [false, true] {
                check_clock_pair(local, remote, auth, extensions, 1_789_000_000, 0, false);
            }
        }
    }
}

#[test]
fn response_clocks_normalize_configured_timescale() {
    for local in [ClockFormat::NTP, ClockFormat::PTP] {
        for remote in [ClockFormat::NTP, ClockFormat::PTP] {
            for offset in [-37, 0, 37] {
                for auth in [false, true] {
                    for extensions in [false, true] {
                        check_clock_pair(
                            local,
                            remote,
                            auth,
                            extensions,
                            1_789_000_000,
                            offset,
                            false,
                        );
                    }
                }
            }
        }
    }
}

#[test]
fn response_clocks_across_ntp_era() {
    for local in [ClockFormat::NTP, ClockFormat::PTP] {
        for remote in [ClockFormat::NTP, ClockFormat::PTP] {
            check_clock_pair(local, remote, false, false, 2_085_978_495, 0, false);
        }
    }
}

#[test]
fn response_invalid_ptp_omits_owd_but_keeps_rtt() {
    for auth in [false, true] {
        for extensions in [false, true] {
            check_clock_pair(
                ClockFormat::NTP,
                ClockFormat::PTP,
                auth,
                extensions,
                1_789_000_000,
                0,
                true,
            );
        }
    }
}

#[test]
fn test_process_response_records_forward_one_way_delay() {
    use crate::packets::ReflectedPacketUnauthenticated;

    // PTP timestamps (secs << 32 | nanos) make the conversion exact.
    // T1 = 1.000 s (in pending), T2 = 1.003 s (reflector receive) ⇒ the
    // forward one-way delay is exactly 3 ms regardless of the (live) T4.
    let t1 = 1u64 << 32;
    let t2 = (1u64 << 32) | 3_000_000;
    let t3 = (1u64 << 32) | 4_000_000;

    let reflected = ReflectedPacketUnauthenticated {
        sequence_number: 7,
        timestamp: t3,
        error_estimate: 0x4001,
        ssid: 0,
        receive_timestamp: t2,
        sess_sender_seq_number: 7,
        sess_sender_timestamp: t1,
        sess_sender_err_estimate: 0x4001,
        mbz2: [0; 2],
        sess_sender_ttl: 64,
        mbz3: [0; 3],
    };
    let buf = reflected.to_bytes();

    let mut pending = HashMap::new();
    pending.insert(
        7,
        PendingPacket {
            send_time: Instant::now(),
            send_timestamp: t1,
        },
    );
    let mut rtt_collector = RttCollector::new();
    let mut owd_collector = OwdCollector::new();
    let mut packets_received = 0u32;
    let mut latched_reflector_msid = None;
    let mut ctx = SenderRecvContext {
        local_error_estimate: None,
        measurements: None,
        ber: None,
        reflector_utc_offset: 0,
        pending: &mut pending,
        rtt_collector: &mut rtt_collector,
        owd_collector: &mut owd_collector,
        packets_received: &mut packets_received,
        print_stats: false,
        output_format: crate::stats::OutputFormat::Text,
        hmac_key: None,
        expected_sender_msid: None,
        expected_reflector_msid: None,
        latched_reflector_msid: &mut latched_reflector_msid,
        access_report_state: None,
        congestion: None,
        expected_ssid: None,
        on_zero_ssid: ZeroSsidAction::Continue,
        zero_ssid_seen: &mut false,
        #[cfg(feature = "metrics")]
        metrics_enabled: false,
        #[cfg(all(unix, feature = "snmp"))]
        snmp_stats: None,
    };

    process_response(&buf, false, false, ClockFormat::PTP, None, None, &mut ctx);

    let owd = owd_collector.summary().expect("one OWD sample recorded");
    assert_eq!(owd.samples, 1);
    assert!(
        (owd.forward_avg_ms - 3.0).abs() < 1e-6,
        "forward OWD must be T2 − T1 = 3 ms, got {}",
        owd.forward_avg_ms
    );
}

/// A reply from another SSID must not consume a probe or apply control TLVs,
/// even when its sequence, Micro-session ID, and signatures are all valid.
#[test]
fn mismatched_ssid_preserves_measurement_and_control_state() {
    for auth in [false, true] {
        for extensions in [false, true] {
            for policy in [ZeroSsidAction::Continue, ZeroSsidAction::Stop] {
                let key = HmacKey::new(vec![0xAB; 16]).unwrap();
                let t1 = generate_timestamp(ClockFormat::NTP);
                let mut pending = HashMap::from([(
                    42,
                    PendingPacket {
                        send_time: Instant::now(),
                        send_timestamp: t1,
                    },
                )]);
                let mut rtt = RttCollector::new();
                let mut owd = OwdCollector::new();
                let mut received = 0;
                let mut latched = None;
                let mut zero = false;
                let mut congestion = CongestionState::new(congestion_test_params());
                let mut access = AccessReportRetransmitState::new(Duration::from_secs(3), 4);
                access.tick(Instant::now());
                for ssid in [43u16, u16::MAX, 42] {
                    let reply = ssid_test_reply(auth, extensions, ssid, t1, &key);
                    let mut ctx = congestion_process_response_ctx(
                        &mut pending,
                        &mut rtt,
                        &mut owd,
                        &mut received,
                        &mut latched,
                        Some(&mut congestion),
                        &mut zero,
                    );
                    ctx.expected_ssid = Some(42);
                    ctx.on_zero_ssid = policy;
                    ctx.hmac_key = auth.then_some(&key);
                    if extensions {
                        ctx.expected_sender_msid = Some(7);
                        ctx.access_report_state = Some(&mut access);
                    }
                    process_response(
                        &reply,
                        auth,
                        extensions,
                        ClockFormat::NTP,
                        Some(t1),
                        Some(3),
                        &mut ctx,
                    );
                    let accepted = ssid == 42;
                    assert_eq!(
                        received,
                        u32::from(accepted),
                        "auth={auth} extensions={extensions} ssid={ssid}"
                    );
                    assert_eq!(pending.contains_key(&42), !accepted);
                    assert_eq!(rtt.percentile_ns(50.0).is_some(), accepted);
                    assert_eq!(owd.summary().is_some(), accepted);
                    assert_eq!(latched, (accepted && extensions).then_some(9));
                    assert!(
                        !zero,
                        "a nonzero mismatch is not a legacy zero-SSID response"
                    );
                    assert_eq!(
                        congestion.controller.stats().ce_observations,
                        u64::from(accepted)
                    );
                    assert_eq!(
                        access.outcome(),
                        if accepted && extensions {
                            AccessReportOutcome::Acknowledged
                        } else {
                            AccessReportOutcome::Pending
                        }
                    );
                }
            }
        }
    }
}

#[test]
fn zero_ssid_policy_applies_in_every_reply_parser() {
    for auth in [false, true] {
        for extensions in [false, true] {
            for policy in [ZeroSsidAction::Continue, ZeroSsidAction::Stop] {
                let key = HmacKey::new(vec![0xAB; 16]).unwrap();
                let mut pending = HashMap::from([(
                    42,
                    PendingPacket {
                        send_time: Instant::now(),
                        send_timestamp: 0,
                    },
                )]);
                let mut rtt = RttCollector::new();
                let mut owd = OwdCollector::new();
                let mut received = 0;
                let mut latched = None;
                let mut zero = false;
                let mut ctx = congestion_process_response_ctx(
                    &mut pending,
                    &mut rtt,
                    &mut owd,
                    &mut received,
                    &mut latched,
                    None,
                    &mut zero,
                );
                ctx.expected_ssid = Some(42);
                ctx.on_zero_ssid = policy;
                ctx.hmac_key = auth.then_some(&key);
                let reply = ssid_test_reply(auth, extensions, 0, 0, &key);
                process_response(
                    &reply,
                    auth,
                    extensions,
                    ClockFormat::NTP,
                    None,
                    None,
                    &mut ctx,
                );
                assert!(*ctx.zero_ssid_seen);
                let accepted = policy == ZeroSsidAction::Continue;
                assert_eq!(*ctx.packets_received, u32::from(accepted));
                assert_eq!(ctx.pending.contains_key(&42), !accepted);
                // Seeing a legacy zero must not disable subsequent SSID validation.
                ctx.pending.insert(
                    43,
                    PendingPacket {
                        send_time: Instant::now(),
                        send_timestamp: 0,
                    },
                );
                let mut wrong = ssid_test_reply(auth, extensions, 99, 0, &key);
                let seq_offset = if auth { 48 } else { 24 };
                wrong[seq_offset..seq_offset + 4].copy_from_slice(&43u32.to_be_bytes());
                if auth {
                    let mac = compute_packet_hmac(&key, &wrong, 96);
                    wrong[96..112].copy_from_slice(&mac);
                }
                process_response(
                    &wrong,
                    auth,
                    extensions,
                    ClockFormat::NTP,
                    None,
                    None,
                    &mut ctx,
                );
                assert_eq!(*ctx.packets_received, u32::from(accepted));
                assert!(ctx.pending.contains_key(&43));
            }
        }
    }
}

// Independent wire layout: SSID occupies only the reflector's field;
// the two bytes after the echoed sender Error Estimate remain MBZ.
fn ssid_test_reply(
    auth: bool,
    extensions: bool,
    ssid: u16,
    timestamp: u64,
    key: &HmacKey,
) -> Vec<u8> {
    let base = if auth { 112 } else { 44 };
    let (ssid_offset, t3, t2, seq, t1) = if auth {
        (26, 16, 32, 48, 64)
    } else {
        (14, 4, 16, 24, 28)
    };
    let mut reply = vec![0; base];
    reply[..4].copy_from_slice(&1u32.to_be_bytes());
    reply[ssid_offset..ssid_offset + 2].copy_from_slice(&ssid.to_be_bytes());
    reply[seq..seq + 4].copy_from_slice(&42u32.to_be_bytes());
    for offset in [t1, t2, t3] {
        reply[offset..offset + 8].copy_from_slice(&timestamp.to_be_bytes());
    }
    if extensions {
        reply.extend_from_slice(&[0, 11, 0, 4, 0, 7, 0, 9]);
        reply.extend_from_slice(&[0, 6, 0, 4, 0x10, 0, 0, 0]);
        if auth {
            let mut covered = reply[..4].to_vec();
            covered.extend_from_slice(&reply[base..]);
            reply.extend_from_slice(&[0, 8, 0, 16]);
            reply.extend_from_slice(&key.compute(&covered));
        }
    }
    if auth {
        let mac = compute_packet_hmac(key, &reply, 96);
        reply[96..112].copy_from_slice(&mac);
    }
    reply
}

/// RFC8972-3-11: "An implementation of a Session-Sender MUST support
/// control of its behavior in such a scenario [a zeroed SSID]." The two
/// actions must actually differ: `stop` refuses to account the reply and
/// latches the condition, `continue` accounts it normally.
#[test]
fn test_zero_ssid_policy_stop_discards_reply_and_latches() {
    use crate::packets::ReflectedPacketUnauthenticated;

    // A reflector that does not implement SSID leaves the field zero.
    let reflected = ReflectedPacketUnauthenticated {
        sequence_number: 7,
        timestamp: 0,
        error_estimate: 0,
        ssid: 0,
        receive_timestamp: 0,
        sess_sender_seq_number: 7,
        sess_sender_timestamp: 0,
        sess_sender_err_estimate: 0,
        mbz2: [0; 2],
        sess_sender_ttl: 0,
        mbz3: [0; 3],
    };
    let buf = reflected.to_bytes().to_vec();

    let mut pending = HashMap::new();
    pending.insert(
        7,
        PendingPacket {
            send_time: Instant::now(),
            send_timestamp: 0,
        },
    );
    let mut rtt_collector = RttCollector::new();
    let mut owd_collector = OwdCollector::new();
    let mut packets_received = 0u32;
    let mut latched_reflector_msid = None;
    let mut zero_ssid_seen = false;
    {
        let mut ctx = SenderRecvContext {
            local_error_estimate: None,
            measurements: None,
            ber: None,
            reflector_utc_offset: 0,
            pending: &mut pending,
            rtt_collector: &mut rtt_collector,
            owd_collector: &mut owd_collector,
            packets_received: &mut packets_received,
            print_stats: false,
            output_format: crate::stats::OutputFormat::Text,
            hmac_key: None,
            expected_sender_msid: None,
            expected_reflector_msid: None,
            latched_reflector_msid: &mut latched_reflector_msid,
            access_report_state: None,
            congestion: None,
            // The sender asked for SSID 4242; the reply carries zero.
            expected_ssid: Some(4242),
            on_zero_ssid: ZeroSsidAction::Stop,
            zero_ssid_seen: &mut zero_ssid_seen,
            #[cfg(feature = "metrics")]
            metrics_enabled: false,
            #[cfg(all(unix, feature = "snmp"))]
            snmp_stats: None,
        };
        process_response(&buf, false, false, ClockFormat::NTP, None, None, &mut ctx);
    }

    assert!(
        zero_ssid_seen,
        "the zeroed-SSID condition must be latched for the send loop to stop on"
    );
    assert_eq!(
        packets_received, 0,
        "under `stop` the reply belongs to an abandoned session and must not be counted"
    );
    assert!(
        pending.contains_key(&7),
        "the pending entry must be left alone under `stop`"
    );
}

#[test]
fn test_zero_ssid_policy_continue_still_accounts_the_reply() {
    use crate::packets::ReflectedPacketUnauthenticated;

    let reflected = ReflectedPacketUnauthenticated {
        sequence_number: 7,
        timestamp: 0,
        error_estimate: 0,
        ssid: 0,
        receive_timestamp: 0,
        sess_sender_seq_number: 7,
        sess_sender_timestamp: 0,
        sess_sender_err_estimate: 0,
        mbz2: [0; 2],
        sess_sender_ttl: 0,
        mbz3: [0; 3],
    };
    let buf = reflected.to_bytes().to_vec();

    let mut pending = HashMap::new();
    pending.insert(
        7,
        PendingPacket {
            send_time: Instant::now(),
            send_timestamp: 0,
        },
    );
    let mut rtt_collector = RttCollector::new();
    let mut owd_collector = OwdCollector::new();
    let mut packets_received = 0u32;
    let mut latched_reflector_msid = None;
    let mut zero_ssid_seen = false;
    {
        let mut ctx = SenderRecvContext {
            local_error_estimate: None,
            measurements: None,
            ber: None,
            reflector_utc_offset: 0,
            pending: &mut pending,
            rtt_collector: &mut rtt_collector,
            owd_collector: &mut owd_collector,
            packets_received: &mut packets_received,
            print_stats: false,
            output_format: crate::stats::OutputFormat::Text,
            hmac_key: None,
            expected_sender_msid: None,
            expected_reflector_msid: None,
            latched_reflector_msid: &mut latched_reflector_msid,
            access_report_state: None,
            congestion: None,
            expected_ssid: Some(4242),
            on_zero_ssid: ZeroSsidAction::Continue,
            zero_ssid_seen: &mut zero_ssid_seen,
            #[cfg(feature = "metrics")]
            metrics_enabled: false,
            #[cfg(all(unix, feature = "snmp"))]
            snmp_stats: None,
        };
        process_response(&buf, false, false, ClockFormat::NTP, None, None, &mut ctx);
    }

    assert!(
        zero_ssid_seen,
        "the condition is still recorded so it is only reported once"
    );
    assert_eq!(
        packets_received, 1,
        "continuing is RFC-permitted: the measurement proceeds normally"
    );
    assert!(
        !pending.contains_key(&7),
        "the reply was accounted, so its pending entry is consumed"
    );
}

/// A sender that never set an SSID must not react to a zeroed reply field:
/// there is nothing for the reflector to have echoed.
#[test]
fn test_zero_ssid_policy_inert_without_a_configured_ssid() {
    use crate::packets::ReflectedPacketUnauthenticated;

    let reflected = ReflectedPacketUnauthenticated {
        sequence_number: 7,
        timestamp: 0,
        error_estimate: 0,
        ssid: 0,
        receive_timestamp: 0,
        sess_sender_seq_number: 7,
        sess_sender_timestamp: 0,
        sess_sender_err_estimate: 0,
        mbz2: [0; 2],
        sess_sender_ttl: 0,
        mbz3: [0; 3],
    };
    let buf = reflected.to_bytes().to_vec();

    let mut pending = HashMap::new();
    pending.insert(
        7,
        PendingPacket {
            send_time: Instant::now(),
            send_timestamp: 0,
        },
    );
    let mut rtt_collector = RttCollector::new();
    let mut owd_collector = OwdCollector::new();
    let mut packets_received = 0u32;
    let mut latched_reflector_msid = None;
    let mut zero_ssid_seen = false;
    {
        let mut ctx = SenderRecvContext {
            local_error_estimate: None,
            measurements: None,
            ber: None,
            reflector_utc_offset: 0,
            pending: &mut pending,
            rtt_collector: &mut rtt_collector,
            owd_collector: &mut owd_collector,
            packets_received: &mut packets_received,
            print_stats: false,
            output_format: crate::stats::OutputFormat::Text,
            hmac_key: None,
            expected_sender_msid: None,
            expected_reflector_msid: None,
            latched_reflector_msid: &mut latched_reflector_msid,
            access_report_state: None,
            congestion: None,
            // No SSID requested — even `stop` must not fire.
            expected_ssid: None,
            on_zero_ssid: ZeroSsidAction::Stop,
            zero_ssid_seen: &mut zero_ssid_seen,
            #[cfg(feature = "metrics")]
            metrics_enabled: false,
            #[cfg(all(unix, feature = "snmp"))]
            snmp_stats: None,
        };
        process_response(&buf, false, false, ClockFormat::NTP, None, None, &mut ctx);
    }

    assert!(!zero_ssid_seen, "no SSID was requested; nothing to detect");
    assert_eq!(packets_received, 1, "the reply must be accounted normally");
}

#[test]
fn test_process_response_drops_packet_on_msid_mismatch() {
    use crate::packets::{ExtendedReflectedPacketUnauthenticated, ReflectedPacketUnauthenticated};

    // Build a reflected unauth packet that echoes a different
    // sender_micro_session_id than we transmitted. process_response MUST
    // NOT remove the sequence from pending, must not record RTT, and
    // must not increment packets_received.
    let reflected = ReflectedPacketUnauthenticated {
        sequence_number: 42,
        timestamp: 0,
        error_estimate: 0,
        ssid: 0,
        receive_timestamp: 0,
        sess_sender_seq_number: 42,
        sess_sender_timestamp: 0,
        sess_sender_err_estimate: 0,
        mbz2: [0; 2],
        sess_sender_ttl: 0,
        mbz3: [0; 3],
    };
    let mut tlvs = TlvList::new();
    // Model a properly-reflected TLV: a conforming reflector clears the
    // U/M/I flags on a recognized, well-formed TLV (the typed constructor
    // sets the sender-side U flag, which would otherwise make the sender
    // skip processing per RFC 8972 §4-17).
    let mut raw = MicroSessionIdTlv::new(0xBAD, 99).to_raw();
    raw.clear_reflector_flags();
    tlvs.push(raw).unwrap();
    let ext = ExtendedReflectedPacketUnauthenticated::with_tlvs(reflected, tlvs);
    let buf = ext.to_bytes();

    let mut pending = HashMap::new();
    pending.insert(
        42,
        PendingPacket {
            send_time: Instant::now(),
            send_timestamp: 0,
        },
    );
    let mut rtt_collector = RttCollector::new();
    let mut owd_collector = OwdCollector::new();
    let mut packets_received = 0u32;
    let mut latched_reflector_msid = None;
    let mut ctx = SenderRecvContext {
        local_error_estimate: None,
        measurements: None,
        ber: None,
        reflector_utc_offset: 0,
        pending: &mut pending,
        rtt_collector: &mut rtt_collector,
        owd_collector: &mut owd_collector,
        packets_received: &mut packets_received,
        print_stats: false,
        output_format: crate::stats::OutputFormat::Text,
        hmac_key: None,
        // Sender transmitted with sender_msid=7777; reflector's response
        // carries 0xBAD → session binding fails.
        expected_sender_msid: Some(7777),
        expected_reflector_msid: None,
        latched_reflector_msid: &mut latched_reflector_msid,
        access_report_state: None,
        congestion: None,
        expected_ssid: None,
        on_zero_ssid: ZeroSsidAction::Continue,
        zero_ssid_seen: &mut false,
        #[cfg(feature = "metrics")]
        metrics_enabled: false,
        #[cfg(all(unix, feature = "snmp"))]
        snmp_stats: None,
    };

    process_response(&buf, false, true, ClockFormat::NTP, None, None, &mut ctx);

    assert!(
        pending.contains_key(&42),
        "pending entry must remain so the packet is still counted as lost"
    );
    assert_eq!(
        packets_received, 0,
        "received counter must not advance on MSID mismatch"
    );
    assert_eq!(
        rtt_collector.snapshot(1, 0).packets_received,
        0,
        "no RTT sample must be recorded on MSID mismatch"
    );
}

#[test]
fn test_process_response_accepts_packet_on_msid_match() {
    use crate::packets::{ExtendedReflectedPacketUnauthenticated, ReflectedPacketUnauthenticated};

    // Control case: matching MSID means the response is accepted,
    // pending entry is consumed, received counter increments.
    let reflected = ReflectedPacketUnauthenticated {
        sequence_number: 42,
        timestamp: 0,
        error_estimate: 0,
        ssid: 0,
        receive_timestamp: 0,
        sess_sender_seq_number: 42,
        sess_sender_timestamp: 0,
        sess_sender_err_estimate: 0,
        mbz2: [0; 2],
        sess_sender_ttl: 0,
        mbz3: [0; 3],
    };
    let mut tlvs = TlvList::new();
    let mut id = MicroSessionIdTlv::new(7777, 99).to_raw();
    id.clear_reflector_flags();
    tlvs.push(id).unwrap();
    let ext = ExtendedReflectedPacketUnauthenticated::with_tlvs(reflected, tlvs);
    let buf = ext.to_bytes();

    let mut pending = HashMap::new();
    pending.insert(
        42,
        PendingPacket {
            send_time: Instant::now(),
            send_timestamp: 0,
        },
    );
    let mut rtt_collector = RttCollector::new();
    let mut owd_collector = OwdCollector::new();
    let mut packets_received = 0u32;
    let mut latched_reflector_msid = None;
    let mut ctx = SenderRecvContext {
        local_error_estimate: None,
        measurements: None,
        ber: None,
        reflector_utc_offset: 0,
        pending: &mut pending,
        rtt_collector: &mut rtt_collector,
        owd_collector: &mut owd_collector,
        packets_received: &mut packets_received,
        print_stats: false,
        output_format: crate::stats::OutputFormat::Text,
        hmac_key: None,
        expected_sender_msid: Some(7777),
        expected_reflector_msid: None,
        latched_reflector_msid: &mut latched_reflector_msid,
        access_report_state: None,
        congestion: None,
        expected_ssid: None,
        on_zero_ssid: ZeroSsidAction::Continue,
        zero_ssid_seen: &mut false,
        #[cfg(feature = "metrics")]
        metrics_enabled: false,
        #[cfg(all(unix, feature = "snmp"))]
        snmp_stats: None,
    };

    process_response(&buf, false, true, ClockFormat::NTP, None, None, &mut ctx);

    assert!(!pending.contains_key(&42));
    assert_eq!(packets_received, 1);
}

#[test]
fn test_build_unauth_packet_ssid_round_trips_via_reflector() {
    use crate::packets::{PacketUnauthenticated, ReflectedPacketUnauthenticated};
    use crate::receiver::assemble_unauth_answer;

    // End-to-end wire check: an SSID set by the sender reaches the reflector
    // in the base header and is echoed into the reply's single SSID field
    // (RFC 8972 §3 Figure 2), leaving octets 38-39 MBZ.
    let built = build_unauth_packet_with_tlvs(1, 100, 0, Some(0xABCD), &[], None);
    let parsed = PacketUnauthenticated::from_bytes(&built).unwrap();
    assert_eq!(parsed.ssid, 0xABCD);

    let reply: ReflectedPacketUnauthenticated =
        assemble_unauth_answer(&parsed, ClockFormat::NTP, 0, 64, 0, None);
    assert_eq!(reply.ssid, 0xABCD);

    let bytes = reply.to_bytes();
    assert_eq!(u16::from_be_bytes([bytes[14], bytes[15]]), 0xABCD);
    assert_eq!(
        &bytes[38..40],
        &[0, 0],
        "a second SSID copy here makes MBZ-verifying peers drop the reply"
    );
}

#[test]
fn test_build_auth_packet_ssid_round_trips_via_reflector() {
    use crate::packets::{PacketAuthenticated, ReflectedPacketAuthenticated};
    use crate::receiver::assemble_auth_answer;

    // End-to-end wire check for the authenticated path: the SSID set by
    // the sender must reach the reflector in base header bytes 26-27 and
    // be echoed into the reply's single SSID field (offsets 26-27), with
    // octets 74-79 left MBZ. HMAC is recomputed on each side, so getting
    // this wrong would also desync verification.
    let key = HmacKey::new(vec![0xAB; 32]).unwrap();
    let built = build_auth_packet_with_tlvs(42, 1000, 100, &key, Some(0xBEEF), &[], None);
    assert_eq!(built.len(), 112);
    assert_eq!(u16::from_be_bytes([built[26], built[27]]), 0xBEEF);

    let parsed = PacketAuthenticated::from_bytes(&built).unwrap();
    assert_eq!(parsed.ssid, 0xBEEF);

    let reply: ReflectedPacketAuthenticated =
        assemble_auth_answer(&parsed, ClockFormat::NTP, 0, 64, 0, Some(&key), None);
    assert_eq!(reply.ssid, 0xBEEF);

    // Reflector's HMAC must be computed over the echoed SSID too —
    // serialize and verify it round-trips through from_bytes.
    let reply_bytes = reply.to_bytes();
    assert_eq!(
        u16::from_be_bytes([reply_bytes[26], reply_bytes[27]]),
        0xBEEF
    );
    assert_eq!(
        &reply_bytes[74..80],
        &[0; 6],
        "a second SSID copy here makes MBZ-verifying peers drop the reply"
    );
    let reparsed = ReflectedPacketAuthenticated::from_bytes(&reply_bytes).unwrap();
    assert_eq!(reparsed.ssid, 0xBEEF);
    assert_eq!(reparsed.mbz4, [0; 6]);
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
async fn check_recv_packet_readiness(ip: &str, kernel_rx: bool, want_ecn: bool) {
    use std::os::fd::AsRawFd;
    use tokio::time::timeout;

    let receiver = UdpSocket::bind((ip, 0)).await.unwrap();
    let peer = UdpSocket::bind((ip, 0)).await.unwrap();
    receiver.connect(peer.local_addr().unwrap()).await.unwrap();
    peer.connect(receiver.local_addr().unwrap()).await.unwrap();
    if want_ecn {
        enable_reply_tos_reception(receiver.as_raw_fd(), ip == "::1").unwrap();
    }
    #[cfg(feature = "hwtstamp")]
    if kernel_rx {
        let enabled =
            crate::hwtstamp::enable_socket_timestamping(receiver.as_raw_fd(), true, false, false);
        assert!(
            enabled.rx_kernel,
            "loopback kernel RX timestamping unavailable"
        );
    }

    let mut buf = [0u8; 64];
    for payload in [b"first".as_slice(), b"after idle".as_slice()] {
        let (len, timestamp, ecn) = timeout(Duration::from_secs(2), async {
            loop {
                peer.send(payload).await.unwrap();
                let received = loop {
                    match recv_packet(&receiver, &mut buf, kernel_rx, want_ecn, ClockFormat::NTP)
                        .await
                    {
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => continue,
                        result => break result.unwrap(),
                    }
                };
                if !kernel_rx || received.1.is_some() {
                    break received;
                }
                // Linux enables RX timestamping through a deferred static
                // key, so initial packets can legitimately lack a cmsg.
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .unwrap();
        assert_eq!(&buf[..len], payload);
        assert_eq!(timestamp.is_some(), kernel_rx);
        assert_eq!(ecn, want_ecn.then_some(0));

        // A consumed datagram can leave one cached readiness event. A
        // raw EAGAIN must clear it, rather than waking every future read.
        match timeout(
            Duration::from_millis(30),
            recv_packet(&receiver, &mut buf, kernel_rx, want_ecn, ClockFormat::NTP),
        )
        .await
        {
            Ok(Err(e)) => assert_eq!(e.kind(), std::io::ErrorKind::WouldBlock),
            Err(_) => {} // Already waiting for fresh readiness is fine.
            Ok(Ok(_)) => panic!("received a datagram when none was sent"),
        }
        assert!(
            timeout(Duration::from_millis(30), receiver.readable())
                .await
                .is_err(),
            "an empty socket retained stale readable readiness"
        );
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[tokio::test]
async fn recv_packet_clears_readiness_for_ecn() {
    for ip in ["127.0.0.1", "::1"] {
        check_recv_packet_readiness(ip, false, true).await;
    }
}

#[cfg(all(feature = "hwtstamp", any(target_os = "linux", target_os = "macos")))]
#[tokio::test]
async fn recv_packet_clears_readiness_for_kernel_timestamps() {
    for ip in ["127.0.0.1", "::1"] {
        check_recv_packet_readiness(ip, true, false).await;
        check_recv_packet_readiness(ip, true, true).await;
    }
}

/// Creates an Extended unauthenticated packet from configuration.
///
/// This is a convenience wrapper for building packets with TLV support.
fn create_extended_unauth_packet(
    sequence_number: u32,
    timestamp: u64,
    error_estimate: u16,
    ssid: Option<u16>,
) -> ExtendedPacketUnauthenticated {
    let base = PacketUnauthenticated {
        sequence_number,
        timestamp,
        error_estimate,
        ssid: ssid.unwrap_or(0),
        mbz: [0u8; 28],
    };

    ExtendedPacketUnauthenticated::with_tlvs(base, TlvList::new())
}

/// Creates an Extended authenticated packet from configuration.
///
/// This is a convenience wrapper for building packets with TLV support.
fn create_extended_auth_packet(
    sequence_number: u32,
    timestamp: u64,
    error_estimate: u16,
    hmac_key: &HmacKey,
    ssid: Option<u16>,
) -> ExtendedPacketAuthenticated {
    let mut base = PacketAuthenticated {
        sequence_number,
        timestamp,
        error_estimate,
        ssid: ssid.unwrap_or(0),
        mbz0: [0u8; 12],
        mbz1a: [0u8; 30],
        mbz1b: [0u8; 32],
        mbz1c: [0u8; 6],
        hmac: [0u8; 16],
    };

    finalize_auth_packet(&mut base, hmac_key);

    ExtendedPacketAuthenticated::with_tlvs(base, TlvList::new())
}
