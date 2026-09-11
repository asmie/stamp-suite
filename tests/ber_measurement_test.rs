//! BER-07 end-to-end measurement, repair and peer compatibility.
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
        captured_headers: None,
        reflected_control_max_count: 16,
        reflected_control_max_size: 1500,
        reflected_control_min_interval_ns: 1_000,
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
                .any(|t| t.tlv_type == TlvType::BerCount);
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
                let count = offset(&reflected, base, 241);
                reflected[count] |= 0x80;
            }
            if !unsupported {
                let padding = offset(&reflected, base, 1);
                assert_eq!(&reflected[padding + 4..padding + 20], &[0xff, 0].repeat(8));
                let count = offset(&reflected, base, 241);
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
    let stats = tokio::time::timeout(Duration::from_secs(5), run_sender(&conf, None))
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
    use stamp_suite::tlv::{BerBurstTlv, BerCountTlv, BerPatternTlv, ExtraPaddingTlv, TypedTlv};
    for (pads, patterns, counts, bursts, size) in [
        (0, 1, 1, 1, 4),
        (2, 1, 1, 1, 4),
        (1, 2, 1, 1, 4),
        (1, 1, 2, 1, 4),
        (1, 1, 1, 2, 4),
        (1, 1, 1, 1, 3),
    ] {
        let mut data = vec![0; 44];
        for _ in 0..pads {
            data.extend_from_slice(
                &ExtraPaddingTlv {
                    padding: vec![0xff; size],
                }
                .to_raw()
                .to_bytes(),
            );
        }
        for _ in 0..patterns {
            data.extend_from_slice(&BerPatternTlv::new(vec![0xff, 0]).to_raw().to_bytes());
        }
        for _ in 0..counts {
            data.extend_from_slice(&BerCountTlv::default().to_raw().to_bytes());
        }
        for _ in 0..bursts {
            data.extend_from_slice(&BerBurstTlv::default().to_raw().to_bytes());
        }
        let reflected = process_stamp_packet(
            &data,
            "127.0.0.1:12345".parse().unwrap(),
            64,
            false,
            &make_ctx(),
        )
        .unwrap();
        let list = TlvList::parse(&reflected.data[44..]).unwrap();
        for t in list.non_hmac_tlvs().iter().filter(|t| {
            matches!(
                t.tlv_type,
                TlvType::BerPattern | TlvType::BerCount | TlvType::BerBurst
            )
        }) {
            assert!(!t.is_unrecognized(), "recognized invalid BER is C, not U");
            if size != 3 || t.tlv_type == TlvType::BerPattern {
                assert!(t.flags.conformant_reflected);
            }
        }
    }
    // A default pattern is selected by omitting Type 240.
    let mut data = vec![0; 44];
    data.extend_from_slice(
        &ExtraPaddingTlv {
            padding: vec![0, 0],
        }
        .to_raw()
        .to_bytes(),
    );
    data.extend_from_slice(&BerCountTlv::default().to_raw().to_bytes());
    let reflected = process_stamp_packet(
        &data,
        "127.0.0.1:12345".parse().unwrap(),
        64,
        false,
        &make_ctx(),
    )
    .unwrap();
    let pad = offset(&reflected.data, 44, 1);
    assert_eq!(&reflected.data[pad + 4..pad + 6], &[0xff, 0]);
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
        tlv::{BerBurstTlv, BerCountTlv, BerPatternTlv, ExtraPaddingTlv, TypedTlv},
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
                BerPatternTlv::new(vec![0xff, 0]).to_raw(),
                BerCountTlv::default().to_raw(),
                BerBurstTlv::default().to_raw(),
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
            let count = offset(&buf[..len], base, 241);
            assert_eq!(&buf[count + 4..count + 8], &2u32.to_be_bytes());
            let pad = offset(&buf[..len], base, 1);
            assert_eq!(&buf[pad + 4..len], &[0xff, 0].repeat(8));
            assert!(offset(&buf[..len], base, 8) < pad);
        }
    }
}
