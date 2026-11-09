//! End-to-end BER measurement (draft-ietf-bpm-stamp-ber-01): padding repair and
//! peer compatibility.
use clap::Parser;
use stamp_suite::{
    configuration::{ClockFormat, Configuration, TlvHandlingMode},
    crypto::HmacKey,
    receiver::{process_stamp_packet, ProcessingContext},
    sender::run_sender,
    tlv::{TlvList, TlvType},
};
use std::time::Duration;
use tokio::net::UdpSocket;

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
        reflect_fixed_header: true,
        reflect_ipv6_ext_header: true,
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

fn offset(data: &[u8], base: usize, kind: u8) -> usize {
    let mut p = base;
    while p + 4 <= data.len() {
        if data[p + 1] == kind {
            return p;
        }
        p += 4 + usize::from(u16::from_be_bytes([data[p + 2], data[p + 3]]));
    }
    panic!("missing TLV {kind}");
}

async fn measurement(ip: &str, auth: bool, unsupported: bool) {
    let peer = UdpSocket::bind((ip, 0)).await.unwrap();
    let port = peer.local_addr().unwrap().port();
    let mut args = vec![
        "test".to_string(),
        "--local-addr".into(),
        ip.into(),
        "--local-port".into(),
        "0".into(),
        "--remote-addr".into(),
        ip.into(),
        "--remote-port".into(),
        port.to_string(),
        "--ber".into(),
        "--ber-padding-size".into(),
        "16".into(),
        "--ber-interval".into(),
        "1".into(),
        "--send-delay".into(),
        "30".into(),
        "--count".into(),
        "3".into(),
        "--timeout".into(),
        "1".into(),
    ];
    if auth {
        args.extend(
            [
                "--auth-mode",
                "A",
                "--hmac-key",
                "abababababababababababababababab",
            ]
            .map(str::to_string),
        );
    }
    let conf = Configuration::try_parse_from(args).unwrap();
    let task = tokio::spawn(async move {
        let key = HmacKey::new(vec![0xab; 16]).unwrap();
        for i in 0..3 {
            let mut buf = [0; 4096];
            let (len, src) = peer.recv_from(&mut buf).await.unwrap();
            let mut data = buf[..len].to_vec();
            let base = if auth { 112 } else { 44 };
            let list = TlvList::parse(&data[base..]).unwrap();
            let has_count = list
                .non_hmac_tlvs()
                .iter()
                .any(|t| t.tlv_type == TlvType::ResidualBer);
            assert_eq!(has_count, !unsupported || i == 0);
            let padding = offset(&data, base, 1);
            if !unsupported {
                // Four consecutive forward errors cross the byte boundary.
                data[padding + 4] ^= 0x03;
                data[padding + 5] ^= 0xc0;
            }
            let mut ctx = make_ctx();
            ctx.hmac_key = auth.then_some(&key);
            ctx.require_hmac = auth;
            ctx.verify_tlv_hmac = auth;
            let mut reflected = process_stamp_packet(&data, src, 64, auth, &ctx)
                .unwrap()
                .data;
            if unsupported && i == 0 {
                let count = offset(&reflected, base, 243);
                reflected[count] |= 0x80;
            }
            if !unsupported {
                let padding = offset(&reflected, base, 1);
                assert_eq!(&reflected[padding + 4..padding + 20], &[0xff, 0].repeat(8));
                let count = offset(&reflected, base, 243);
                assert_eq!(reflected[count], 0);
                assert_eq!(&reflected[count + 4..count + 8], &4u32.to_be_bytes());
                // One independent reverse error; HMAC must remain valid.
                reflected[padding + 4] ^= 0x80;
            }
            peer.send_to(&reflected, src).await.unwrap();
            // A duplicate reflected datagram must not double BER totals.
            if !unsupported {
                peer.send_to(&reflected, src).await.unwrap();
            }
        }
    });
    let stats = tokio::time::timeout(Duration::from_secs(5), run_sender(&conf))
        .await
        .unwrap()
        .unwrap();
    task.await.unwrap();
    assert_eq!(stats.packets_received, 3);
    let ber = stats.ber.unwrap();
    assert_eq!(ber.disabled_by_peer, unsupported);
    if !unsupported {
        assert_eq!(ber.forward.packets_received, 3);
        assert_eq!(ber.forward.padding_bits, 384);
        assert_eq!(ber.forward.bit_errors, 12);
        assert_eq!(ber.forward.max_burst_bits, Some(4));
        assert_eq!(ber.forward.average_max_burst_bits, Some(4.0));
        assert_eq!(ber.reverse.bit_errors, 3);
        assert_eq!(ber.reverse.max_burst_bits, Some(1));
        assert_eq!(ber.forward.bit_error_ratio, Some(12.0 / 384.0));
        assert_eq!(
            ber.intervals
                .iter()
                .map(|i| i.forward.packets_received)
                .sum::<u64>(),
            3
        );
    } else {
        assert_eq!(ber.forward.packets_received, 0);
    }
}
#[tokio::test]
async fn ipv4_open_measurement() {
    measurement("127.0.0.1", false, false).await;
}
#[tokio::test]
async fn ipv6_open_measurement() {
    measurement("::1", false, false).await;
}
#[tokio::test]
async fn ipv4_auth_measurement() {
    measurement("127.0.0.1", true, false).await;
}
#[tokio::test]
async fn ipv6_auth_measurement() {
    measurement("::1", true, false).await;
}
#[tokio::test]
async fn unsupported_peer_disables_ber_only() {
    measurement("127.0.0.1", false, true).await;
}

#[test]
fn reflector_reports_conformance_errors_and_repairs_both_serializations() {
    // Missing/duplicate padding, duplicate combined BER, duplicate patterns,
    // and a nonintegral number of repetitions require C on the outer TLV.
    for (pads, bers, patterns, size) in [
        (0, 1, 1, 4),
        (2, 1, 1, 4),
        (1, 2, 1, 4),
        (1, 1, 2, 4),
        (1, 1, 1, 3),
    ] {
        let mut value = vec![0; 8];
        for _ in 0..patterns {
            value.extend_from_slice(&[0x80, 241, 0, 4, 255, 0, 255, 0]);
        }
        let mut fields = vec![(243, value); bers];
        for _ in 0..pads {
            fields.push((1, vec![0; size]));
        }
        let reply = reflect_fields(&fields);
        for tlv in reply.iter().filter(|t| t.tlv_type == TlvType::ResidualBer) {
            assert!(!tlv.is_unrecognized());
            assert!(tlv.flags.conformant_reflected);
        }
    }
    let reply = reflect_fields(&[(243, vec![0; 8]), (1, vec![0; 4])]);
    assert_eq!(
        reply
            .iter()
            .find(|t| t.tlv_type == TlvType::ExtraPadding)
            .unwrap()
            .value,
        [255, 0, 255, 0]
    );
}

fn reflect_fields(fields: &[(u8, Vec<u8>)]) -> TlvList {
    let mut packet = vec![0; 44];
    for (kind, value) in fields {
        packet.extend_from_slice(&[0x80, *kind]);
        packet.extend_from_slice(&(value.len() as u16).to_be_bytes());
        packet.extend_from_slice(value);
    }
    let response = process_stamp_packet(
        &packet,
        "127.0.0.1:12345".parse().unwrap(),
        64,
        false,
        &make_ctx(),
    )
    .unwrap();
    TlvList::parse(&response.data[44..]).unwrap()
}

#[test]
fn nested_unknown_and_short_patterns_preserve_values_and_stop_at_m() {
    let mut value = vec![0; 8];
    value.extend_from_slice(&[0xf0, 245, 0, 3, 1, 2, 3, 0x80, 241, 0, 4, 255, 0, 255, 0]);
    let reply = reflect_fields(&[(243, value), (1, vec![255, 0, 255, 0])]);
    let value = &reply.non_hmac_tlvs()[0].value;
    assert_eq!(&value[8..15], &[0x80, 245, 0, 3, 1, 2, 3]);
    assert_eq!(value[15], 0);
    let mut short = vec![0; 8];
    short.extend_from_slice(&[0x80, 241, 0, 3, 1, 2, 3, 0xb7, 245, 0, 0]);
    let reply = reflect_fields(&[(243, short), (1, vec![7; 4])]);
    assert_eq!(reply.non_hmac_tlvs()[0].value[8], 0x40);
    assert_eq!(
        reply.non_hmac_tlvs()[0].value[15],
        0xb7,
        "opaque remainder after nested M"
    );
    assert_eq!(reply.non_hmac_tlvs()[1].value, [7; 4]);
}

#[test]
fn malformed_outer_and_nested_framing_preserve_the_outer_stop_boundary() {
    let reply = reflect_fields(&[(243, vec![0; 7]), (4, vec![184, 0, 0, 0])]);
    assert!(reply.non_hmac_tlvs()[0].is_malformed());
    assert!(reply.non_hmac_tlvs()[0].flags.conformant_reflected);
    assert!(reply.non_hmac_tlvs()[1].is_unrecognized());
    let mut truncated = vec![0; 8];
    truncated.extend_from_slice(&[0x80, 241, 0, 4, 1, 2]);
    let reply = reflect_fields(&[(243, truncated), (4, vec![184, 0, 0, 0]), (1, vec![0; 4])]);
    assert!(reply.non_hmac_tlvs()[0].is_malformed());
    assert_eq!(reply.non_hmac_tlvs()[0].value[8], 0x40);
    assert!(reply.non_hmac_tlvs()[1].is_unrecognized());
    assert_eq!(reply.non_hmac_tlvs()[1].value, [184, 0, 0, 0]);
}

#[test]
fn retired_legacy_types_are_unknown_and_do_not_repair_padding() {
    let reply = reflect_fields(&[
        (240, vec![255, 0]),
        (241, vec![0; 4]),
        (242, vec![0; 4]),
        (1, vec![7; 4]),
    ]);
    for tlv in reply.iter().filter(|t| t.tlv_type != TlvType::ExtraPadding) {
        assert!(tlv.is_unrecognized());
        assert!(!tlv.flags.conformant_reflected);
    }
    assert_eq!(reply.non_hmac_tlvs()[3].value, [7; 4]);
}

#[test]
fn invalid_hmac_does_not_rewrite_nested_flags_or_padding() {
    let mut value = vec![0; 8];
    value.extend_from_slice(&[0xf0, 241, 0, 4, 255, 0, 255, 0]);
    let mut packet = vec![0; 44];
    packet.extend_from_slice(&[0x80, 243, 0, 16]);
    packet.extend_from_slice(&value);
    packet.extend_from_slice(&[0x80, 1, 0, 4, 1, 2, 3, 4, 0x80, 8, 0, 16]);
    packet.extend_from_slice(&[0; 16]);
    let key = HmacKey::new(vec![0xab; 16]).unwrap();
    let mut ctx = make_ctx();
    ctx.hmac_key = Some(&key);
    ctx.verify_tlv_hmac = true;
    let reply =
        process_stamp_packet(&packet, "127.0.0.1:12345".parse().unwrap(), 64, false, &ctx).unwrap();
    let list = TlvList::parse(&reply.data[44..]).unwrap();
    assert!(list.non_hmac_tlvs()[0].is_integrity_failed());
    assert_eq!(list.non_hmac_tlvs()[0].value, value);
    assert_eq!(list.non_hmac_tlvs()[1].value, [1, 2, 3, 4]);
}

/// Exercise the shared final send path: it must regenerate the metadata HMAC
/// before the trailing corrected padding on both IPv4 and IPv6.
#[test]
#[cfg(all(
    target_os = "linux",
    any(feature = "ttl-nix", not(feature = "ttl-pnet"))
))]
fn real_reflector_signs_repaired_ber_padding() {
    use stamp_suite::{
        sender::{build_auth_packet_with_tlvs, build_unauth_packet_with_tlvs},
        tlv::{ExtraPaddingTlv, ResidualBerValue, TypedTlv, RESIDUAL_BER_PATTERN_SUBTLV_TYPE},
    };
    use std::{
        net::UdpSocket,
        process::{Child, Command, Stdio},
        time::Instant,
    };
    struct ChildGuard(Child);
    impl Drop for ChildGuard {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    for ip in ["127.0.0.1", "::1"] {
        for auth in [false, true] {
            let reserve = UdpSocket::bind((ip, 0)).unwrap();
            let addr = reserve.local_addr().unwrap();
            drop(reserve);
            let mut command = Command::new(env!("CARGO_BIN_EXE_stamp-suite"));
            command.args([
                "--is-reflector",
                "--local-addr",
                ip,
                "--local-port",
                &addr.port().to_string(),
                "--hmac-key",
                "abababababababababababababababab",
            ]);
            if auth {
                command.args(["--auth-mode", "A"]);
            }
            let mut child = ChildGuard(
                command
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .spawn()
                    .unwrap(),
            );
            let sock = UdpSocket::bind((ip, 0)).unwrap();
            sock.set_read_timeout(Some(Duration::from_millis(40)))
                .unwrap();
            let key = HmacKey::new(vec![0xab; 16]).unwrap();
            let tlvs = [
                ResidualBerValue::request(
                    RESIDUAL_BER_PATTERN_SUBTLV_TYPE,
                    Some(&[255, 0, 255, 0]),
                )
                .unwrap()
                .to_raw()
                .unwrap(),
                ExtraPaddingTlv {
                    padding: [0xff, 0].repeat(8),
                }
                .to_raw(),
            ];
            let base = if auth { 112 } else { 44 };
            let mut request = if auth {
                build_auth_packet_with_tlvs(1, 0, 0, &key, None, &tlvs, Some(&key))
            } else {
                build_unauth_packet_with_tlvs(1, 0, 0, None, &tlvs, Some(&key))
            };
            let pad = offset(&request, base, 1);
            request[pad + 4] ^= 0x03;
            let started = Instant::now();
            let mut buf = [0; 4096];
            let len = loop {
                assert!(child.0.try_wait().unwrap().is_none());
                sock.send_to(&request, addr).unwrap();
                if let Ok((len, _)) = sock.recv_from(&mut buf) {
                    break len;
                }
                assert!(
                    started.elapsed() < Duration::from_secs(5),
                    "reflector did not reply"
                );
            };
            let list = TlvList::parse(&buf[base..len]).unwrap();
            assert!(list.verify_hmac(&key, &buf[..4], &buf[base..len]).is_ok());
            assert!(list.iter().all(|t| !t.is_integrity_failed()));
            let count = offset(&buf[..len], base, 243);
            assert_eq!(&buf[count + 4..count + 8], &2u32.to_be_bytes());
            let pad = offset(&buf[..len], base, 1);
            assert_eq!(&buf[pad + 4..len], &[0xff, 0].repeat(8));
            assert!(offset(&buf[..len], base, 8) < pad);
        }
    }
}

#[test]
fn successor_fixed_counters_and_nested_pattern_are_processed() {
    // Independent wire bytes: outer Type 243, eight fixed bytes, then
    // pattern sub-TLV Type 241 with a four-byte FF00FF00 value.
    let mut packet = vec![0; 44];
    packet.extend_from_slice(&[
        0x80, 243, 0, 16, 0, 0, 0, 0, 0, 0, 0, 0, 0x80, 241, 0, 4, 255, 0, 255, 0,
    ]);
    packet.extend_from_slice(&[0x80, 1, 0, 4, 0xfc, 0xc0, 255, 0]);
    let reply = process_stamp_packet(
        &packet,
        "127.0.0.1:12345".parse().unwrap(),
        64,
        false,
        &make_ctx(),
    )
    .unwrap();
    let at = offset(&reply.data, 44, 243);
    assert_eq!(
        reply.data[at], 0,
        "successor BER must be recognized and conformant"
    );
    assert_eq!(&reply.data[at + 4..at + 12], &[0, 0, 0, 4, 0, 0, 0, 4]);
    assert_eq!(reply.data[at + 12], 0, "known pattern must be acknowledged");
    let pad = offset(&reply.data, 44, 1);
    assert_eq!(&reply.data[pad + 4..pad + 8], &[255, 0, 255, 0]);
}

#[test]
fn nested_framing_keeps_the_acknowledged_prefix_and_opaque_remainder() {
    let mut value = vec![0; 8];
    value.extend_from_slice(&[0x80, 241, 0, 4, 255, 0, 255, 0, 0x80, 245, 0, 5, 1]);
    let reply = reflect_fields(&[(243, value), (1, vec![0; 4])]);
    let raw = &reply.non_hmac_tlvs()[0];
    assert!(raw.is_malformed());
    assert_eq!(
        raw.value[8], 0,
        "valid prefix acknowledged before truncation"
    );
    assert_eq!(raw.value[16], 0xc0, "unknown truncated child gets U+M");
    let mut value = vec![0; 8];
    value.extend_from_slice(&[0x80, 241, 0, 3, 1, 2, 3, 0xb7, 245, 0, 5, 1]);
    let reply = reflect_fields(&[(243, value), (1, vec![7; 4])]);
    let raw = &reply.non_hmac_tlvs()[0];
    assert!(
        !raw.is_malformed(),
        "nested semantic M stops before the opaque remainder"
    );
    assert_eq!(raw.value[8], 0x40);
    assert_eq!(raw.value[15], 0xb7);
}
