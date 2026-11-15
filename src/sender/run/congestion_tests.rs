use super::*;
use clap::Parser;
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;

fn sign(parts: &[&[u8]]) -> [u8; 16] {
    let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(&[0xab; 16]).unwrap();
    for part in parts {
        mac.update(part);
    }
    mac.finalize().into_bytes()[..16].try_into().unwrap()
}

/// Exercise the production probe builder and socket send with controlled
/// controller transitions. Decode bytes and check signatures independently
/// of the application's TLV codecs; feedback admission has separate tests.
#[tokio::test]
async fn backed_off_zero_base_bursts_keep_the_floor_on_wire() {
    for ip in ["127.0.0.1", "::1"] {
        for mode in 0..3 {
            for (factor, max_ms, zero_gaps, nonzero_gaps) in [
                ("2", "1", [0, 1_000_000, 0, 0], [100_000; 4]),
                (
                    "1.5",
                    "10",
                    [0, 1_500_000, 1_000_000, 0],
                    [100_000, 150_000, 100_000, 100_000],
                ),
            ] {
                for original_gap in ["0", "100000"] {
                    let peer = UdpSocket::bind((ip, 0)).await.unwrap();
                    let port = peer.local_addr().unwrap().port().to_string();
                    let mut args = vec![
                        "test",
                        "--local-addr",
                        ip,
                        "--local-port",
                        "0",
                        "--remote-addr",
                        ip,
                        "--remote-port",
                        &port,
                        "--hwtstamp",
                        "off",
                        "--send-delay",
                        "0",
                        "--cos",
                        "--ecn",
                        "2",
                        "--ecn-backoff-factor",
                        factor,
                        "--ecn-max-delay",
                        max_ms,
                        "--ecn-recovery-step",
                        "1",
                        "--reflected-control-count",
                        "3",
                        "--reflected-control-interval-ns",
                        original_gap,
                        "--access-report",
                        "1",
                    ];
                    if mode != 0 {
                        args.extend(["--hmac-key", "abababababababababababababababab"]);
                    }
                    if mode == 2 {
                        args.extend(["--auth-mode", "A"]);
                    }
                    let conf = Configuration::parse_from(args);
                    conf.validate().unwrap();
                    let mut sender = SenderRun::open(
                        Arc::new(conf),
                        SenderObservers::new(),
                        CancellationToken::new(),
                    )
                    .await
                    .unwrap();
                    let expected = if original_gap == "0" {
                        zero_gaps
                    } else {
                        nonzero_gaps
                    };
                    for (step, expected_ns) in expected.into_iter().enumerate() {
                        let controller = &mut sender.congestion.as_mut().unwrap().controller;
                        match step {
                            0 => (),
                            1 => controller.on_ce_observed(),
                            _ => controller.on_clean_reply(),
                        }
                        // Include and omit Access Reports to exercise both
                        // callers of the shared per-probe TLV construction.
                        let attach_report = step % 2 == 1;
                        sender.send_probe(attach_report).await.unwrap();
                        let mut buf = [0; 2048];
                        let len = tokio::time::timeout(Duration::from_secs(2), peer.recv(&mut buf))
                            .await
                            .unwrap()
                            .unwrap();
                        let bytes = &buf[..len];
                        let base = if mode == 2 { 112 } else { 44 };
                        if mode == 2 {
                            assert_eq!(&bytes[96..112], &sign(&[&bytes[..96]]));
                        }
                        let mut offset = base;
                        let mut intervals = Vec::new();
                        let mut reports = 0;
                        let mut signatures = 0;
                        while offset < len {
                            assert!(offset + 4 <= len);
                            let size = usize::from(u16::from_be_bytes([
                                bytes[offset + 2],
                                bytes[offset + 3],
                            ]));
                            let end = offset + 4 + size;
                            assert!(end <= len);
                            let value = &bytes[offset + 4..end];
                            match bytes[offset + 1] {
                                12 => {
                                    assert_eq!(size, 12);
                                    assert_eq!(&value[..4], &[0, 0, 0, 3]);
                                    assert_eq!(&value[8..], &[0; 4]);
                                    intervals
                                        .push(u32::from_be_bytes(value[4..8].try_into().unwrap()));
                                }
                                6 => reports += 1,
                                8 => {
                                    signatures += 1;
                                    assert_eq!(end, len);
                                    assert_eq!(value, sign(&[&bytes[..4], &bytes[base..offset]]));
                                }
                                _ => (),
                            }
                            offset = end;
                        }
                        assert_eq!(
                            intervals,
                            [expected_ns],
                            "{ip} mode={mode} max={max_ms} step={step} gap={original_gap}"
                        );
                        assert_eq!(reports, usize::from(attach_report));
                        assert_eq!(signatures, usize::from(mode != 0));
                    }
                }
            }
        }
    }
}
