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
    let base = if mode == 2 { 112 } else { 44 };
    let error = if mode == 2 { 24 } else { 12 };
    let mut bytes = vec![0; base];
    bytes[..4].copy_from_slice(&0x01020304u32.to_be_bytes());
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
    let mut command = Reflector::command(ip);
    command.args(["--hwtstamp", "off", "--reflected-control-max-count", "16"]);
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
    let reflector = Reflector::spawn(command).unwrap();
    let peer = UdpSocket::bind((ip, 0)).unwrap();
    peer.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    peer.send_to(bytes, reflector.address).unwrap();
    let mut response = [0; 2048];
    let (size, source) = peer.recv_from(&mut response).unwrap();
    assert_eq!(source, reflector.address);
    peer.set_read_timeout(Some(Duration::from_millis(40)))
        .unwrap();
    let error = peer
        .recv_from(&mut [0; 2048])
        .expect_err("opaque unknown TLV must not execute a nested burst");
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
            append(&mut tail, 0x80, 2, &[0; 4]);
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
                assert_eq!(got.flags, if got.kind == 200 { 0xa0 } else { 0x20 });
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
