use super::*;
use clap::Parser;
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;

async fn open(ip: &str, auth: bool, limit: u32, clock: ClockFormat) -> (SenderRun, UdpSocket) {
    open_ecn(ip, auth, limit, clock, 2).await
}

async fn open_ecn(
    ip: &str,
    auth: bool,
    limit: u32,
    clock: ClockFormat,
    ecn: u8,
) -> (SenderRun, UdpSocket) {
    let peer = UdpSocket::bind((ip, 0)).await.unwrap();
    let mut conf = Configuration::parse_from([
        "test",
        "--local-addr",
        ip,
        "--local-port",
        "0",
        "--remote-addr",
        ip,
        "--remote-port",
        &peer.local_addr().unwrap().port().to_string(),
        "--hwtstamp",
        "off",
        "--timeout",
        "0",
        "--micro-session-id",
        "7",
        "--access-report",
        "1",
        "--cos",
        "--ecn",
        &ecn.to_string(),
        "--direct-measurement",
        "--reflected-control-count",
        "3",
        "--ssid",
        "42",
        "--hmac-key",
        "abababababababababababababababab",
    ]);
    conf.max_pending_probes = limit;
    conf.clock_source = clock;
    if auth {
        conf.auth_mode = crate::configuration::AuthMode::Authenticated;
    }
    conf.validate().unwrap();
    let run = SenderRun::open(
        Arc::new(conf),
        SenderObservers::new(),
        CancellationToken::new(),
    )
    .await
    .unwrap();
    (run, peer)
}

fn sign(input: &[u8]) -> Vec<u8> {
    let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(&[0xab; 16]).unwrap();
    mac.update(input);
    mac.finalize().into_bytes()[..16].to_vec()
}

// Independent wire encoder, including valid base/TLV signatures for the stale
// reply. Rejection must come from probe identity, not an unrelated HMAC error.
fn reflected(request: &[u8], auth: bool, count: u32) -> Vec<u8> {
    let base = if auth { 112 } else { 44 };
    let mut bytes = vec![0; base];
    let (t3, error, t2, seq, t1, ttl) = if auth {
        (16, 24, 32, 48, 64, 80)
    } else {
        (4, 12, 16, 24, 28, 40)
    };
    bytes[..4].copy_from_slice(&99u32.to_be_bytes());
    bytes[t3..t3 + 8].copy_from_slice(&(10u64 << 32).to_be_bytes());
    bytes[t2..t2 + 8].copy_from_slice(&(9u64 << 32).to_be_bytes());
    bytes[error..error + 4].copy_from_slice(&request[error..error + 4]);
    bytes[seq..seq + 4].copy_from_slice(&request[..4]);
    bytes[t1..t1 + 10].copy_from_slice(&request[t3..t3 + 10]);
    bytes[ttl] = 255;
    bytes.extend_from_slice(&[0, 11, 0, 4, 0, 7, 0, 9]);
    bytes.extend_from_slice(&[0, 6, 0, 4, 0x10, 1, 0, 0]);
    bytes.extend_from_slice(&[0, 4, 0, 4, 0, 12, 0, 0]); // forward CE
    bytes.extend_from_slice(&[0, 5, 0, 12]);
    bytes.extend_from_slice(&count.to_be_bytes());
    bytes.extend_from_slice(&count.to_be_bytes());
    bytes.extend_from_slice(&count.to_be_bytes());
    let mut covered = bytes[..4].to_vec();
    covered.extend_from_slice(&bytes[base..]);
    bytes.extend_from_slice(&[0, 8, 0, 16]);
    bytes.extend_from_slice(&sign(&covered));
    if auth {
        let mac = sign(&bytes[..96]);
        bytes[96..112].copy_from_slice(&mac);
    }
    bytes
}

async fn probe(sender: &mut SenderRun, peer: &UdpSocket) -> Vec<u8> {
    sender.sess = Session::new(0); // force wire sequence 0 reuse without 2^32 sends
    sender.send_probe(true).await.unwrap();
    let mut bytes = [0; 2048];
    let (size, _) = tokio::time::timeout(Duration::from_secs(2), peer.recv_from(&mut bytes))
        .await
        .unwrap()
        .unwrap();
    bytes[..size].to_vec()
}

fn receive(sender: &mut SenderRun, bytes: &[u8]) {
    sender.recv_buf[..bytes.len()].copy_from_slice(bytes);
    sender.on_reply(
        &crate::stats::StatsOutput::new(crate::stats::OutputFormat::Json).unwrap(),
        bytes.len(),
        None,
        Some(3),
    );
}

#[tokio::test]
async fn reused_sequence_rejects_old_signed_echo_before_measurement_or_control_state() {
    for ip in ["127.0.0.1", "::1"] {
        for auth in [false, true] {
            for limit in [0, 2] {
                for clock in [ClockFormat::NTP, ClockFormat::PTP] {
                    let (mut sender, peer) = open(ip, auth, limit, clock).await;
                    let old = probe(&mut sender, &peer).await;
                    tokio::time::sleep(Duration::from_millis(2)).await;
                    let new = probe(&mut sender, &peer).await;
                    let offset = if auth { 16 } else { 4 };
                    assert_ne!(&old[offset..offset + 8], &new[offset..offset + 8]);
                    receive(&mut sender, &reflected(&old, auth, 1));
                    assert_eq!(sender.packets_received, 0, "stale echo consumed a newer probe: {ip} auth={auth} limit={limit} clock={clock:?}");
                    assert!(sender.pending.contains_key(&0));
                    assert_eq!(sender.pending_order.len(), usize::from(limit != 0));
                    assert_eq!(sender.latched_reflector_msid, None);
                    assert_eq!(
                        sender.access_report_state.as_ref().unwrap().outcome(),
                        crate::stats::AccessReportOutcome::Pending
                    );
                    assert!(sender.rtt_collector.percentile_ns(50.0).is_none());
                    assert!(sender.owd_collector.summary().is_none());
                    let summary = sender.measurements.snapshot();
                    assert_eq!(summary.unique_replies, 0);
                    assert_eq!(summary.answered_probes, 0);
                    assert_eq!(summary.mismatched_replies, 1);
                    assert_eq!(summary.direct_measurement.observations, 0);
                    assert_eq!(sender.congestion.as_ref().unwrap().summary().ce_replies, 0);
                    assert_eq!(summary.session_state.state, session_state::State::Idle);
                    receive(&mut sender, &reflected(&new, auth, 2));
                    assert_eq!(sender.packets_received, 1);
                    assert!(sender.pending.is_empty());
                    assert!(
                        sender.pending_order.is_empty() && sender.pending_generation.is_empty()
                    );
                    assert_eq!(sender.latched_reflector_msid, Some(9));
                    assert_eq!(
                        sender.access_report_state.as_ref().unwrap().outcome(),
                        crate::stats::AccessReportOutcome::Acknowledged
                    );
                    assert_eq!(sender.congestion.as_ref().unwrap().summary().ce_replies, 1);
                    // A stale replay after the valid reply must not be treated
                    // as an additional burst copy or apply CE again.
                    receive(&mut sender, &reflected(&old, auth, 1));
                    assert_eq!(sender.measurements.snapshot().unique_replies, 1);
                    assert_eq!(sender.congestion.as_ref().unwrap().summary().ce_replies, 1);
                    // Reuse again after an answered probe. A peer may reuse its
                    // own sequence/T3; the echoed T1 distinguishes the new copy.
                    tokio::time::sleep(Duration::from_millis(2)).await;
                    let newest = probe(&mut sender, &peer).await;
                    receive(&mut sender, &reflected(&newest, auth, 3));
                    assert_eq!(sender.packets_received, 2);
                    assert_eq!(sender.measurements.snapshot().unique_replies, 2);
                    assert_eq!(sender.packets_lost, 1);
                }
            }
        }
    }
}

#[tokio::test]
async fn retained_late_and_additional_copies_require_the_original_echo() {
    for ip in ["127.0.0.1", "::1"] {
        for auth in [false, true] {
            let (mut sender, peer) = open(ip, auth, 2, ClockFormat::NTP).await;
            Arc::make_mut(&mut sender.conf).micro_session_id = None;
            let request = probe(&mut sender, &peer).await;
            sender.timeout = Duration::from_secs(1);
            sender.expire_at(Instant::now() + Duration::from_secs(2));
            assert!(sender.pending.is_empty() && sender.pending_order.is_empty());
            let valid = reflected(&request, auth, 1);
            receive(&mut sender, &valid);
            let summary = sender.measurements.snapshot();
            assert_eq!(summary.late_replies, 1);
            assert_eq!(summary.unique_replies, 1);
            assert_eq!(sender.packets_received, 0);
            assert_eq!(sender.packets_lost, 1);
            receive(&mut sender, &valid);
            assert_eq!(sender.measurements.snapshot().duplicate_replies, 1);
            let mut other = request.clone();
            let ts = if auth { 16 } else { 4 };
            other[ts + 7] ^= 1;
            receive(&mut sender, &reflected(&other, auth, 1));
            assert_eq!(sender.measurements.snapshot().mismatched_replies, 1);
            let mut copy = valid;
            copy[..4].copy_from_slice(&100u32.to_be_bytes());
            // Re-sign the changed independent reflector sequence.
            let base = if auth { 112 } else { 44 };
            let mac_offset = copy.len() - 16;
            let mut covered = copy[..4].to_vec();
            covered.extend_from_slice(&copy[base..mac_offset - 4]);
            copy[mac_offset..].copy_from_slice(&sign(&covered));
            if auth {
                let mac = sign(&copy[..96]);
                copy[96..112].copy_from_slice(&mac);
            }
            receive(&mut sender, &copy);
            assert_eq!(sender.measurements.snapshot().additional_replies, 1);
            assert_eq!(sender.measurements.snapshot().unique_replies, 2);
        }
    }
}

#[tokio::test]
async fn short_replies_need_full_echo_but_may_omit_trailing_fields() {
    for ip in ["127.0.0.1", "::1"] {
        let (mut sender, peer) = open(ip, false, 2, ClockFormat::NTP).await;
        Arc::make_mut(&mut sender.conf).micro_session_id = None;
        let request = probe(&mut sender, &peer).await;
        let valid = reflected(&request, false, 1);
        for len in [0, 24, 27, 28, 32, 35] {
            receive(&mut sender, &valid[..len]);
            assert_eq!(sender.packets_received, 0);
            assert_eq!(sender.pending.len(), 1);
        }
        // TWAMP Light's 41-byte reflected base includes the complete echoed T1.
        // Also admit 36 bytes: the unused tail can still be zero-filled.
        receive(&mut sender, &valid[..36]);
        assert_eq!(sender.packets_received, 1);
        assert_eq!(sender.measurements.snapshot().mismatched_replies, 6);
        let next = probe(&mut sender, &peer).await;
        receive(&mut sender, &reflected(&next, false, 2)[..41]);
        assert_eq!(sender.packets_received, 2);
    }
}

#[tokio::test]
async fn ecn_reporting_counts_only_admitted_distinct_copies() {
    for ip in ["127.0.0.1", "::1"] {
        for auth in [false, true] {
            let (mut sender, peer) = open(ip, auth, 2, ClockFormat::NTP).await;
            let request = probe(&mut sender, &peer).await;
            let bytes = reflected(&request, auth, 1);
            let base = if auth { 112 } else { 44 };
            let mut wrong_ssid = bytes.clone();
            let ssid = if auth { 26 } else { 14 };
            wrong_ssid[ssid..ssid + 2].copy_from_slice(&43u16.to_be_bytes());
            if auth {
                let mac = sign(&wrong_ssid[..96]);
                wrong_ssid[96..112].copy_from_slice(&mac);
            }
            receive(&mut sender, &wrong_ssid);
            let mut wrong_echo = bytes.clone();
            wrong_echo[if auth { 64 } else { 28 }] ^= 1;
            if auth {
                let mac = sign(&wrong_echo[..96]);
                wrong_echo[96..112].copy_from_slice(&mac);
            }
            receive(&mut sender, &wrong_echo);
            assert_eq!(sender.measurements.snapshot().ecn.unwrap().replies, 0);
            receive(&mut sender, &bytes);
            receive(&mut sender, &bytes); // exact duplicate
            let ecn = sender.measurements.snapshot().ecn.unwrap();
            assert_eq!(ecn.replies, 1);
            assert_eq!(ecn.usable_cos, 1);
            assert_eq!(ecn.received_ec2, [0, 0, 0, 1]);
            assert_eq!(ecn.rpe, [1, 0, 0, 0]); // legacy must not imply support
            assert_eq!(ecn.reverse_unknown, 1);
            assert_eq!(ecn.reply_ip_ecn, [0, 0, 0, 1]);
            // An independently sequenced burst copy is counted, with a signed
            // applied EC1 response and preserved C provenance.
            let mut additional = bytes;
            additional[..4].copy_from_slice(&100u32.to_be_bytes());
            additional[base + 16] = 0x10;
            additional[base + 22] = 0xb0; // EC1=2, RPE=3
            let end = additional.len() - 20;
            let mut covered = additional[..4].to_vec();
            covered.extend_from_slice(&additional[base..end]);
            additional[end + 4..].copy_from_slice(&sign(&covered));
            if auth {
                let mac = sign(&additional[..96]);
                additional[96..112].copy_from_slice(&mac);
            }
            receive(&mut sender, &additional);
            let summary = sender.measurements.snapshot();
            let ecn = summary.ecn.unwrap();
            assert_eq!(summary.additional_replies, 1);
            assert_eq!(ecn.replies, 2);
            assert_eq!(ecn.rpe, [1, 0, 0, 1]);
            assert_eq!(ecn.conformant_reflected, 1);
            assert_eq!(ecn.reverse_comparable, 0);
            assert_eq!(ecn.reverse_unknown, 2);

            // BPM -00 assigns RPE=01 to unavailable reflector marking. A
            // signed additional copy remains a valid base measurement, but
            // must not manufacture reverse bleaching or a CE transition.
            additional[..4].copy_from_slice(&101u32.to_be_bytes());
            additional[base + 16] = 0;
            additional[base + 22] = 0x90; // EC1=2, RPE=1.
            let mut covered = additional[..4].to_vec();
            covered.extend_from_slice(&additional[base..end]);
            additional[end + 4..].copy_from_slice(&sign(&covered));
            if auth {
                let mac = sign(&additional[..96]);
                additional[96..112].copy_from_slice(&mac);
            }
            receive(&mut sender, &additional);
            receive(&mut sender, &additional); // exact duplicate is not counted
            let summary = sender.measurements.snapshot();
            let ecn = summary.ecn.unwrap();
            assert_eq!(summary.additional_replies, 2);
            assert_eq!(ecn.replies, 3);
            assert_eq!(ecn.rpe, [1, 1, 0, 1]);
            assert_eq!(ecn.reverse.comparable, 0);
            assert_eq!(ecn.reverse.bleaching, 0);
            assert_eq!(ecn.reverse.ce_marked, 0);
            assert_eq!(ecn.reverse.unknown_reasons.reflector_marking_unavailable, 1);
            let json = serde_json::to_value(&ecn).unwrap();
            assert_eq!(
                json["reverse"]["unknown_reasons"]["reflector_marking_unavailable"],
                1
            );
        }
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[tokio::test]
async fn ecn_reporting_receives_ip_metadata_for_all_requested_codepoints() {
    use std::os::fd::AsRawFd;
    for ip in ["127.0.0.1", "::1"] {
        for auth in [false, true] {
            for ecn in 0..4 {
                let (mut sender, peer) = open_ecn(ip, auth, 2, ClockFormat::NTP, ecn).await;
                assert_eq!(sender.congestion.is_some(), matches!(ecn, 1 | 2));
                assert_eq!(
                    sender
                        .measurements
                        .snapshot()
                        .ecn
                        .unwrap()
                        .configured_egress_ecn,
                    Some(ecn)
                );
                let request = probe(&mut sender, &peer).await;
                apply_egress_ip_options(peer.as_raw_fd(), ip == "::1", Some(ecn), None).unwrap();
                peer.send_to(
                    &reflected(&request, auth, 1),
                    sender.socket.local_addr().unwrap(),
                )
                .await
                .unwrap();
                let (len, ts, reply_ecn) = tokio::time::timeout(
                    Duration::from_secs(2),
                    recv_packet(
                        &sender.socket,
                        &mut sender.recv_buf,
                        &mut sender.cmsg_buf,
                        false,
                        sender.conf.cos,
                        ClockFormat::NTP,
                    ),
                )
                .await
                .unwrap()
                .unwrap();
                assert_eq!(reply_ecn, Some(ecn), "{ip} auth={auth}");
                sender.on_reply(
                    &crate::stats::StatsOutput::new(crate::stats::OutputFormat::Json).unwrap(),
                    len,
                    ts,
                    reply_ecn,
                );
                let summary = sender.measurements.snapshot().ecn.unwrap();
                assert_eq!(summary.replies, 1);
                assert_eq!(summary.reply_ip_ecn[usize::from(ecn)], 1);
                assert_eq!(summary.unavailable_reply_ip_ecn, 0);
            }
        }
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[tokio::test]
async fn ecn_directional_reports_pair_signed_cos_with_received_ip_markings() {
    use std::os::fd::AsRawFd;
    for ip in ["127.0.0.1", "::1"] {
        for auth in [false, true] {
            for requested in 0..4u8 {
                for observed in 0..4u8 {
                    let (mut sender, peer) =
                        open_ecn(ip, auth, 2, ClockFormat::NTP, requested).await;
                    let request = probe(&mut sender, &peer).await;
                    let mut bytes = reflected(&request, auth, 1);
                    let base = if auth { 112 } else { 44 };
                    // Independent peer fabricates ingress EC2 and RPE=3;
                    // reverse IP metadata comes from a real marked datagram.
                    bytes[base + 21] = observed << 2;
                    bytes[base + 22] = (requested << 6) | 0x30;
                    let end = bytes.len() - 20;
                    let mut covered = bytes[..4].to_vec();
                    covered.extend_from_slice(&bytes[base..end]);
                    bytes[end + 4..].copy_from_slice(&sign(&covered));
                    apply_egress_ip_options(
                        peer.as_raw_fd(),
                        ip == "::1",
                        Some(3 - observed),
                        None,
                    )
                    .unwrap();
                    peer.send_to(&bytes, sender.socket.local_addr().unwrap())
                        .await
                        .unwrap();
                    let (len, ts, reply_ecn) = tokio::time::timeout(
                        Duration::from_secs(2),
                        recv_packet(
                            &sender.socket,
                            &mut sender.recv_buf,
                            &mut sender.cmsg_buf,
                            false,
                            sender.conf.cos,
                            ClockFormat::NTP,
                        ),
                    )
                    .await
                    .unwrap()
                    .unwrap();
                    assert_eq!(reply_ecn, Some(3 - observed));
                    let output =
                        crate::stats::StatsOutput::new(crate::stats::OutputFormat::Json).unwrap();
                    sender.on_reply(&output, len, ts, reply_ecn);
                    sender.on_reply(&output, len, ts, reply_ecn); // no second diagnostic sample
                    let summary = sender.snapshot().measurements.unwrap().ecn.unwrap();
                    assert_eq!(summary.replies, 1);
                    assert_eq!(summary.forward.comparable, 1);
                    assert_eq!(summary.reverse.comparable, 1);
                    assert_eq!(
                        summary.forward.transitions[usize::from(requested)][usize::from(observed)],
                        1
                    );
                    assert_eq!(
                        summary.reverse.transitions[usize::from(requested)]
                            [usize::from(3 - observed)],
                        1
                    );
                    assert_eq!(summary.forward.unknown, 0);
                    assert_eq!(summary.reverse.unknown, 0);
                }
            }
        }
    }
}
