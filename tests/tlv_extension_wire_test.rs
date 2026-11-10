//! Independent wire checks for RFC 8972 echo order, flags and integrity gates.
#![cfg(all(
    target_os = "linux",
    any(feature = "ttl-nix", not(feature = "ttl-pnet"))
))]

#[path = "common/reflector.rs"]
mod reflector;
#[path = "common/wire_hmac.rs"]
mod wire_hmac;
use reflector::Reflector;
use std::{net::UdpSocket, time::Duration};

const KEY: [u8; 16] = [0xab; 16];

#[derive(Debug)]
struct Frame {
    start: usize,
    flags: u8,
    kind: u8,
    value: Vec<u8>,
}

fn append(bytes: &mut Vec<u8>, flags: u8, kind: u8, value: &[u8]) {
    bytes.extend_from_slice(&[flags, kind]);
    bytes.extend_from_slice(&(value.len() as u16).to_be_bytes());
    bytes.extend_from_slice(value);
}

fn frames(bytes: &[u8], base: usize) -> Vec<Frame> {
    let mut result = vec![];
    let mut pos = base;
    while pos < bytes.len() {
        assert!(pos + 4 <= bytes.len());
        let size = u16::from_be_bytes([bytes[pos + 2], bytes[pos + 3]]) as usize;
        assert!(pos + 4 + size <= bytes.len());
        result.push(Frame {
            start: pos,
            flags: bytes[pos],
            kind: bytes[pos + 1],
            value: bytes[pos + 4..pos + 4 + size].to_vec(),
        });
        pos += 4 + size;
    }
    result
}

fn request(mode: u8, tail: &[u8], bad_hmac: bool) -> Vec<u8> {
    request_with_sequence(mode, tail, bad_hmac, 0x01020304)
}

fn request_with_sequence(mode: u8, tail: &[u8], bad_hmac: bool, sequence: u32) -> Vec<u8> {
    let base = if mode == 2 { 112 } else { 44 };
    let error = if mode == 2 { 24 } else { 12 };
    let mut bytes = vec![0; base];
    bytes[..4].copy_from_slice(&sequence.to_be_bytes());
    bytes[error + 1] = 1;
    bytes[error + 2..error + 4].copy_from_slice(&42u16.to_be_bytes());
    bytes.extend_from_slice(tail);
    if mode != 0 || bad_hmac {
        let mut covered = bytes[..4].to_vec();
        covered.extend_from_slice(&bytes[base..]);
        let mut digest = wire_hmac::digest(&KEY, &covered);
        if bad_hmac {
            digest[0] ^= 1;
        }
        append(&mut bytes, 0x80, 8, &digest);
    }
    if mode == 2 {
        let digest = wire_hmac::digest(&KEY, &bytes[..96]);
        bytes[96..112].copy_from_slice(&digest);
    }
    bytes
}

fn exchange(ip: &str, mode: u8, bytes: &[u8]) -> (Vec<u8>, u16, u16) {
    exchange_configured(ip, mode, bytes, &[])
}

fn exchange_configured(ip: &str, mode: u8, bytes: &[u8], extra: &[&str]) -> (Vec<u8>, u16, u16) {
    let reflector = start_reflector(ip, mode, extra);
    // Distinct IPv4 endpoints make swapped source/destination metadata visible.
    let peer_ip = if ip == "127.0.0.1" { "127.0.0.2" } else { ip };
    let peer = UdpSocket::bind((peer_ip, 0)).unwrap();
    peer.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    peer.send_to(bytes, reflector.address).unwrap();
    let mut response = [0; 2048];
    let (size, source) = peer.recv_from(&mut response).unwrap();
    assert_eq!(source, reflector.address);
    peer.set_read_timeout(Some(Duration::from_millis(40)))
        .unwrap();
    let error = peer
        .recv_from(&mut [0; 2048])
        .expect_err("unexpected additional reflection");
    assert!(matches!(
        error.kind(),
        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
    ));
    (
        response[..size].to_vec(),
        peer.local_addr().unwrap().port(),
        reflector.address.port(),
    )
}

fn start_reflector(ip: &str, mode: u8, extra: &[&str]) -> Reflector {
    let mut command = Reflector::command(ip);
    command.args(["--hwtstamp", "off", "--reflected-control-max-count", "16"]);
    command.args(extra);
    if mode != 0 {
        command.args([
            "--hmac-key",
            "abababababababababababababababab",
            "--verify-tlv-hmac",
        ]);
    }
    if mode == 2 {
        command.args(["--auth-mode", "A"]);
    }
    Reflector::spawn(command).unwrap()
}

#[test]
fn access_reports_preserve_identity_and_code_but_zero_reserved_fields() {
    for ip in ["127.0.0.1", "::1"] {
        for mode in 0..3 {
            for stateful in [false, true] {
                for id in [1, 2, 0, 3, 15] {
                    let value = [(id << 4) | 0x0f, 0xa6, 0xbe, 0xef];
                    let mut tail = vec![];
                    append(&mut tail, 0x80, 6, &value);
                    let extra = if stateful {
                        &["--stateful-reflector"][..]
                    } else {
                        &[]
                    };
                    let (response, _, _) =
                        exchange_configured(ip, mode, &request(mode, &tail, false), extra);
                    let got = frames(&response, if mode == 2 { 112 } else { 44 });
                    assert_eq!(got[0].kind, 6);
                    assert_eq!(got[0].value.len(), 4);
                    if id == 1 || id == 2 {
                        assert_eq!(got[0].flags, 0);
                        assert_eq!(got[0].value, [id << 4, 0xa6, 0, 0]);
                    } else {
                        assert_eq!(got[0].flags, 0x80);
                        assert_eq!(
                            got[0].value, value,
                            "discarded reports retain their value bytes"
                        );
                    }
                    verify_signatures(&response, mode);
                }
            }
        }
    }
}

#[test]
fn timestamp_and_direct_measurement_fields_are_finalized_per_probe() {
    for ip in ["127.0.0.1", "::1"] {
        for mode in 0..3 {
            for stateful in [false, true] {
                let mut extra = vec!["--clock-sync-source", "ntp"];
                if stateful {
                    extra.push("--stateful-reflector");
                }
                let reflector = start_reflector(ip, mode, &extra);
                let peer = UdpSocket::bind((ip, 0)).unwrap();
                peer.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
                let mut previous = None;
                for index in 0..2u32 {
                    let mut tail = vec![];
                    let optional = [0x80, 200, 0, 4, 1, 2, 3, 4];
                    let mut timestamp = vec![0xa5; 4];
                    timestamp.extend_from_slice(&optional);
                    append(&mut tail, 0x80, 3, &timestamp);
                    let sender_count = 0x01020304 + index;
                    let mut dm = sender_count.to_be_bytes().to_vec();
                    dm.extend_from_slice(&[0xa5; 8]);
                    append(&mut tail, 0x80, 5, &dm);
                    append(&mut tail, 0x80, 7, &[0xa5; 16]);
                    peer.send_to(
                        &request_with_sequence(mode, &tail, false, 10 + index),
                        reflector.address,
                    )
                    .unwrap();
                    let mut response = [0; 2048];
                    let (length, source) = peer.recv_from(&mut response).unwrap();
                    assert_eq!(source, reflector.address);
                    let response = &response[..length];
                    let got = frames(response, if mode == 2 { 112 } else { 44 });
                    assert_eq!((got[0].kind, got[1].kind, got[2].kind), (3, 5, 7));
                    assert!(got.iter().all(|f| f.flags == 0));
                    assert_eq!(&got[0].value[..4], &[1, 2, 1, 2]);
                    assert_eq!(&got[0].value[4..], &optional);
                    assert_eq!(got[1].value.len(), 12);
                    assert_eq!(&got[1].value[..4], &sender_count.to_be_bytes());
                    assert_eq!(&got[1].value[4..8], &(index + 1).to_be_bytes());
                    assert_eq!(&got[1].value[8..12], &index.to_be_bytes());
                    assert_eq!(got[2].value.len(), 16);
                    assert_eq!(&got[2].value[13..], &[0; 3], "Follow-Up reserved bytes");
                    match (stateful, &previous) {
                        (true, Some((sequence, timestamp))) => {
                            assert_eq!(&got[2].value[..4], sequence);
                            assert_eq!(&got[2].value[4..12], timestamp);
                            assert_eq!(got[2].value[12], 2);
                        }
                        _ => assert_eq!(&got[2].value[..12], &[0; 12]),
                    }
                    verify_signatures(response, mode);
                    let timestamp_offset = if mode == 2 { 16 } else { 4 };
                    previous = Some((
                        response[..4].to_vec(),
                        response[timestamp_offset..timestamp_offset + 8].to_vec(),
                    ));
                }
            }
        }
    }
}

#[test]
fn truncated_follow_up_cannot_report_previous_state_as_a_valid_timestamp() {
    for ip in ["127.0.0.1", "::1"] {
        let reflector = start_reflector(ip, 0, &["--stateful-reflector"]);
        let peer = UdpSocket::bind((ip, 0)).unwrap();
        peer.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        let mut response = [0; 2048];
        peer.send_to(&request_with_sequence(0, &[], false, 1), reflector.address)
            .unwrap();
        let (length, _) = peer.recv_from(&mut response).unwrap();
        assert!(length >= 44);
        assert_ne!(
            &response[4..12],
            &[0; 8],
            "establish actual previous reflection state"
        );
        // The outer Length declares twenty octets, but only sixteen arrive.
        // Actual available length alone must not make this a valid Follow-Up.
        let mut tail = vec![0x80, 7, 0, 20];
        tail.extend_from_slice(&[0xa5; 16]);
        peer.send_to(
            &request_with_sequence(0, &tail, false, 2),
            reflector.address,
        )
        .unwrap();
        let (length, _) = peer.recv_from(&mut response).unwrap();
        assert_eq!(length, 64);
        assert_eq!(&response[44..48], &[0x40, 7, 0, 20]);
        assert_eq!(&response[48..60], &[0; 12]);
        assert_eq!(&response[60..64], &[0xa5; 4]);
    }
}

#[test]
fn telemetry_known_lengths_mark_m_and_stop_later_values() {
    for ip in ["127.0.0.1", "::1"] {
        for mode in 0..3 {
            for (kind, sizes) in [
                (3, vec![0, 1, 3, 5, 7, 9]),
                (5, vec![0, 11, 13]),
                (6, vec![0, 3, 5]),
                (7, vec![0, 8, 15, 17]),
            ] {
                for size in sizes {
                    let value = vec![0xa5; size];
                    let mut tail = vec![];
                    append(&mut tail, 0x80, kind, &value);
                    append(&mut tail, 0x80, 5, &[0x55; 12]);
                    let (response, _, _) = exchange(ip, mode, &request(mode, &tail, false));
                    let got = frames(&response, if mode == 2 { 112 } else { 44 });
                    assert_eq!(got[0].kind, kind);
                    assert_eq!(got[0].flags, 0x40);
                    let mut expected = value;
                    if kind == 7 {
                        expected[..size.min(12)].fill(0);
                    }
                    assert_eq!(got[0].value, expected);
                    assert_eq!(got[1].flags, 0x80);
                    assert_eq!(got[1].value, [0x55; 12]);
                    verify_signatures(&response, mode);
                }
            }
        }
    }
}

#[test]
fn skipped_and_integrity_failed_telemetry_keeps_all_value_bytes() {
    for ip in ["127.0.0.1", "::1"] {
        for mode in 0..3 {
            for bad_hmac in [false, true] {
                let mut tail = vec![];
                if !bad_hmac {
                    append(&mut tail, 0x80, 4, &[0xa5; 8]);
                }
                let start = tail.len();
                append(&mut tail, 0x80, 3, &[0xa5; 4]);
                append(&mut tail, 0x80, 6, &[0x1f, 0xa6, 0xbe, 0xef]);
                append(&mut tail, 0x80, 7, &[0xa5; 16]);
                let expected = frames(&tail[start..], 0);
                let (response, _, _) = exchange(ip, mode, &request(mode, &tail, bad_hmac));
                let got = frames(&response, if mode == 2 { 112 } else { 44 });
                let skip = usize::from(!bad_hmac);
                for (frame, sent) in got[skip..].iter().zip(&expected) {
                    assert_eq!(frame.kind, sent.kind);
                    assert_eq!(frame.flags, if bad_hmac { 0x20 } else { 0x80 });
                    assert_eq!(frame.value, sent.value);
                }
                if !bad_hmac {
                    verify_signatures(&response, mode);
                }
                if mode == 2 {
                    assert_eq!(
                        &response[96..112],
                        &wire_hmac::digest(&KEY, &response[..96])
                    );
                }
            }
        }
    }
}

fn verify_signatures(bytes: &[u8], mode: u8) {
    if mode == 2 {
        assert_eq!(&bytes[96..112], &wire_hmac::digest(&KEY, &bytes[..96]));
    }
    let base = if mode == 2 { 112 } else { 44 };
    let parsed = frames(bytes, base);
    let hmac: Vec<_> = parsed.iter().filter(|f| f.kind == 8).collect();
    assert_eq!(hmac.len(), usize::from(mode != 0));
    if let Some(hmac) = hmac.first() {
        assert_eq!(hmac.flags, 0);
        assert_eq!(hmac.start + 20, bytes.len());
        let mut covered = bytes[..4].to_vec();
        covered.extend_from_slice(&bytes[base..hmac.start]);
        assert_eq!(hmac.value, wire_hmac::digest(&KEY, &covered));
    }
}

#[test]
fn mixed_tlvs_preserve_order_padding_and_unknown_values_on_the_wire() {
    let padding: Vec<_> = (0..260).map(|n| (n % 251) as u8).collect();
    // A count-zero Type 12 inside an unknown value is opaque, not executable.
    let opaque = [0x80, 12, 0, 12, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    for ip in ["127.0.0.1", "::1"] {
        for mode in 0..3 {
            let mut tail = vec![];
            append(&mut tail, 0xff, 1, &padding); // incoming U/M/I/reserved bits are re-derived
            append(&mut tail, 0xff, 200, &opaque);
            append(&mut tail, 0x80, 2, &[0; 4]);
            append(&mut tail, 0x80, 3, &[0; 4]);
            let mut dm = vec![1, 2, 3, 4];
            dm.extend_from_slice(&[0; 8]);
            append(&mut tail, 0x80, 5, &dm);
            let (response, sender_port, reflector_port) =
                exchange(ip, mode, &request(mode, &tail, false));
            let base = if mode == 2 { 112 } else { 44 };
            let parsed = frames(&response, base);
            let mut kinds = vec![1, 200, 2, 3, 5];
            if mode != 0 {
                kinds.push(8);
            }
            assert_eq!(parsed.iter().map(|f| f.kind).collect::<Vec<_>>(), kinds);
            assert_eq!(
                parsed.iter().map(|f| f.flags).collect::<Vec<_>>(),
                kinds
                    .iter()
                    .map(|&k| if k == 200 { 0x80 } else { 0 })
                    .collect::<Vec<_>>()
            );
            assert_eq!(
                &response[base + 2..base + 4],
                &[1, 4],
                "260-byte value uses big-endian length"
            );
            assert_eq!(parsed[0].value, padding);
            assert_eq!(parsed[1].value, opaque);
            assert_eq!(&parsed[2].value[..2], &reflector_port.to_be_bytes());
            assert_eq!(&parsed[2].value[2..4], &sender_port.to_be_bytes());
            assert_eq!(&parsed[4].value[..4], &[1, 2, 3, 4]);
            verify_signatures(&response, mode);
        }
    }
}

#[test]
fn malformed_known_tlv_stops_updates_but_copies_remaining_values_and_signs() {
    for ip in ["127.0.0.1", "::1"] {
        for mode in 0..3 {
            let mut tail = vec![];
            append(&mut tail, 0x80, 1, &[9, 8, 7, 6]);
            append(&mut tail, 0x80, 4, &[0; 8]); // CoS requires exactly four value octets
            append(&mut tail, 0x80, 2, &[0; 4]);
            append(&mut tail, 0x80, 5, &[0x55; 12]);
            append(&mut tail, 0x80, 1, &[3, 2, 1]);
            let (response, _, _) = exchange(ip, mode, &request(mode, &tail, false));
            let base = if mode == 2 { 112 } else { 44 };
            let expected = frames(&[vec![0; base], tail].concat(), base);
            let actual = frames(&response, base);
            assert_eq!(actual.len(), expected.len() + usize::from(mode != 0));
            for (index, (got, sent)) in actual.iter().zip(&expected).enumerate() {
                assert_eq!(got.kind, sent.kind);
                assert_eq!(got.value, sent.value, "unprocessed values stay unchanged");
                assert_eq!(
                    got.flags,
                    match index {
                        0 => 0,
                        1 => 0x40,
                        _ => 0x80,
                    }
                );
            }
            verify_signatures(&response, mode);
        }
    }
}

#[test]
fn failed_extension_integrity_preserves_all_values_and_the_failed_digest() {
    for ip in ["127.0.0.1", "::1"] {
        for mode in 0..3 {
            let mut tail = vec![];
            append(&mut tail, 0x80, 1, &[1, 2, 3, 4, 5]);
            // A malformed child must not be repaired before integrity passes:
            // even its original I/M/reserved bits belong to the copied value.
            append(&mut tail, 0x80, 2, &[0, 0, 0, 0, 0xff, 7, 0, 4, 1, 2, 3, 4]);
            append(&mut tail, 0x80, 5, &[0; 12]);
            append(&mut tail, 0x80, 200, &[0xde, 0xad, 0xbe, 0xff]);
            let sent = request(mode, &tail, true);
            let (response, _, _) = exchange(ip, mode, &sent);
            let base = if mode == 2 { 112 } else { 44 };
            let before = frames(&sent, base);
            let after = frames(&response, base);
            assert_eq!(after.len(), before.len());
            for (got, original) in after.iter().zip(&before) {
                assert_eq!(got.kind, original.kind);
                assert_eq!(got.value, original.value);
                assert_eq!(
                    got.flags,
                    match got.kind {
                        2 => 0x60,       // malformed Location plus failed integrity
                        5 | 200 => 0xa0, // stopped after malformed Location, plus I
                        _ => 0x20,
                    }
                );
            }
            if mode == 2 {
                assert_eq!(
                    &response[96..112],
                    &wire_hmac::digest(&KEY, &response[..96])
                );
            }
        }
    }
}

#[test]
fn location_requests_preserve_lengths_and_report_observed_endpoints() {
    for ip in ["127.0.0.1", "::1"] {
        for mode in 0..3 {
            for disclose in ["all", "none"] {
                let mut location = vec![0x11, 0x22, 0x33, 0x44];
                for (kind, size) in [(1, 8), (4, 16), (7, 16)] {
                    append(&mut location, 0xff, kind, &vec![0xa5; size]);
                }
                append(&mut location, 0xff, 200, &[0x80, 12, 0, 0]);
                // Specific answer types are echoed with U; they are not requests.
                for kind in [2, 3, 5, 6, 8, 9] {
                    append(
                        &mut location,
                        0xff,
                        kind,
                        &vec![0x5a; if kind < 4 { 8 } else { 16 }],
                    );
                }
                let mut tail = vec![];
                append(&mut tail, 0x80, 2, &location);
                let (response, source_port, destination_port) = exchange_configured(
                    ip,
                    mode,
                    &request(mode, &tail, false),
                    &["--location-disclose", disclose, "--stateful-reflector"],
                );
                let base = if mode == 2 { 112 } else { 44 };
                let outer = frames(&response, base);
                assert_eq!(outer[0].kind, 2);
                assert_eq!(outer[0].flags, 0);
                assert_eq!(outer[0].value.len(), location.len());
                let got = &outer[0].value;
                if disclose == "all" {
                    assert_eq!(&got[..2], &destination_port.to_be_bytes());
                    assert_eq!(&got[2..4], &source_port.to_be_bytes());
                } else {
                    assert_eq!(&got[..4], &[0; 4]);
                }
                let children = frames(got, 4);
                let original = frames(&location, 4);
                for (index, (child, sent)) in children.iter().zip(&original).enumerate() {
                    assert_eq!(child.value.len(), sent.value.len());
                    assert_eq!(child.flags, if index < 3 { 0 } else { 0x80 });
                    if index < 3 {
                        if disclose == "none" || index == 0 {
                            assert!(child.value.iter().all(|&n| n == 0));
                            assert_eq!(child.kind, if disclose == "none" { sent.kind } else { 3 });
                        } else {
                            let address: std::net::IpAddr = if ip == "127.0.0.1" && index == 2 {
                                "127.0.0.2".parse().unwrap()
                            } else {
                                ip.parse().unwrap()
                            };
                            let (kind, value) = match address {
                                std::net::IpAddr::V4(addr) => {
                                    let mut value = addr.octets().to_vec();
                                    value.resize(16, 0);
                                    (if index == 1 { 5 } else { 8 }, value)
                                }
                                std::net::IpAddr::V6(addr) => {
                                    (if index == 1 { 6 } else { 9 }, addr.octets().to_vec())
                                }
                            };
                            assert_eq!(child.kind, kind);
                            assert_eq!(child.value, value);
                        }
                    } else {
                        assert_eq!(child.kind, sent.kind);
                        assert_eq!(child.value, sent.value);
                    }
                }
                assert_eq!(children.len(), original.len());
                verify_signatures(&response, mode);
            }
        }
    }
}

#[test]
fn malformed_signed_list_keeps_nested_location_bytes_and_original_digest() {
    for ip in ["127.0.0.1", "::1"] {
        for mode in 1..3 {
            for follow_length in [16, 17] {
                let location = [0, 0, 0, 0, 0xff, 7, 0, 4, 1, 2, 3, 4];
                let mut tail = vec![];
                append(&mut tail, 0x80, 6, &[0x1f, 0xa6, 0xbe, 0xef]);
                append(&mut tail, 0x80, 7, &vec![0xa5; follow_length]);
                append(&mut tail, 0x80, 5, &[0xa5; 12]);
                append(&mut tail, 0x80, 2, &location);
                let mut sent = request(mode, &tail, false);
                let base = if mode == 2 { 112 } else { 44 };
                let original = frames(&sent, base);
                let original_digest = &original.last().unwrap().value;
                // Legal padding position, but structurally truncated. The signed
                // list is echo-only even if the covered prefix verifies correctly.
                sent.extend_from_slice(&[0x80, 1, 0, 8, 0xab]);
                let (response, _, _) = exchange(ip, mode, &sent);
                assert_eq!(response.len(), sent.len());
                let copied = frames(&response[..response.len() - 5], base);
                assert_eq!(copied.len(), original.len());
                for (index, (got, sent)) in copied.iter().zip(&original).enumerate() {
                    assert_eq!(got.kind, sent.kind);
                    assert_eq!(got.value, sent.value);
                    let flags = if follow_length == 17 {
                        match index {
                            1 => 0x40,
                            2 | 3 => 0x80,
                            _ => 0,
                        }
                    } else if index == 3 {
                        0x40
                    } else {
                        0
                    };
                    assert_eq!(got.flags, flags);
                }
                assert_eq!(&copied.last().unwrap().value, original_digest);
                assert_eq!(response.last(), Some(&0xab));
                if mode == 2 {
                    assert_eq!(
                        &response[96..112],
                        &wire_hmac::digest(&KEY, &response[..96])
                    );
                }
            }
        }
    }
}

#[test]
fn malformed_location_children_stop_later_outer_tlvs_on_the_wire() {
    let mut cases = vec![];
    for size in 0..4 {
        cases.push((vec![0; size], None));
    }
    for size in 1..4 {
        let mut value = vec![0; 4];
        value.extend(std::iter::repeat_n(0x80, size));
        cases.push((value, None));
    }
    let mut truncated = vec![0; 4];
    truncated.extend_from_slice(&[0x80, 7, 0, 16, 1, 2, 3, 4]);
    cases.push((truncated, Some(4)));
    for kind in 1..=9 {
        let mut value = vec![0; 4];
        append(&mut value, 0x80, 4, &[0; 16]);
        let malformed = value.len();
        append(
            &mut value,
            0x80,
            kind,
            &vec![0x5a; if kind < 4 { 7 } else { 15 }],
        );
        append(&mut value, 0x80, 7, &[0; 16]);
        cases.push((value, Some(malformed)));
    }
    for ip in ["127.0.0.1", "::1"] {
        for mode in 0..3 {
            for (location, malformed_child) in &cases {
                let mut tail = vec![];
                append(&mut tail, 0x80, 2, location);
                append(&mut tail, 0x80, 5, &[0x55; 12]);
                let (response, _, _) = exchange(ip, mode, &request(mode, &tail, false));
                let actual = frames(&response, if mode == 2 { 112 } else { 44 });
                assert_eq!(
                    actual[0].flags, 0x40,
                    "Location must be marked M: {location:?}"
                );
                let mut expected = location.clone();
                if let Some(offset) = malformed_child {
                    expected[*offset] = 0x40;
                }
                assert_eq!(
                    actual[0].value, expected,
                    "no Location values may be consumed"
                );
                assert_eq!(actual[1].kind, 5);
                assert_eq!(actual[1].flags, 0x80);
                assert_eq!(actual[1].value, [0x55; 12]);
                verify_signatures(&response, mode);
            }
        }
    }
}
