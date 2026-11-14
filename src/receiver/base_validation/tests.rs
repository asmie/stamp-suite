use super::super::*;
use crate::session::ReplayVerdict;

fn packet(auth: bool, sequence: u32, timestamp: u64, estimate: u16, key: &HmacKey) -> Vec<u8> {
    let mut bytes = vec![
        0;
        if auth {
            AUTH_BASE_SIZE
        } else {
            UNAUTH_BASE_SIZE
        }
    ];
    let offset = if auth { 16 } else { 4 };
    bytes[..4].copy_from_slice(&sequence.to_be_bytes());
    bytes[offset..offset + 8].copy_from_slice(&timestamp.to_be_bytes());
    bytes[offset + 8..offset + 10].copy_from_slice(&estimate.to_be_bytes());
    bytes[offset + 10..offset + 12].copy_from_slice(&42u16.to_be_bytes());
    // Received MBZ is ignored, including in the new policy.
    bytes[offset + 12] = 0x81;
    if auth {
        let digest = crate::crypto::compute_packet_hmac(key, &bytes, AUTH_HMAC_OFFSET);
        bytes[AUTH_HMAC_OFFSET..AUTH_BASE_SIZE].copy_from_slice(&digest);
    }
    bytes
}

#[test]
fn policy_rejections_precede_allocation_activity_counters_and_replay() {
    let key = HmacKey::new(vec![0xab; 16]).unwrap();
    for (source, local) in [
        ("127.0.0.1:4000", "127.0.0.1:862"),
        ("[::1]:4000", "[::1]:862"),
    ] {
        for auth in [false, true] {
            for stateful in [false, true] {
                let manager = Arc::new(SessionManager::new(None, Some(1)));
                let counters = ReflectorCounters::new();
                let ctx = ProcessingContext {
                    session_manager: Some(&manager),
                    packet_local_addr: Some(local.parse().unwrap()),
                    hmac_key: Some(&key),
                    clock_source: ClockFormat::PTP, // incoming NTP remains valid
                    validate_base_fields: true,
                    strict_packets: false,
                    stateful_reflector: stateful,
                    ..super::super::tests::test_ctx(0, 0)
                };
                let process = |bytes: &[u8]| {
                    process_session_packet_isolated(
                        bytes,
                        source.parse().unwrap(),
                        64,
                        auth,
                        &ctx,
                        &counters,
                        true,
                    )
                };
                let invalid = [
                    packet(auth, 100, 0, 0x8000, &key),
                    packet(auth, 100, 1_000_000_000, 0x4001, &key),
                    packet(auth, 100, u64::MAX, 0xffff, &key),
                ];
                let valid = packet(auth, u32::MAX, u64::MAX, 0xbfff, &key);
                assert!(process(&valid[..valid.len() - 1]).is_none());
                for bytes in &invalid {
                    assert!(process(bytes).is_none());
                }
                assert_eq!(manager.session_count(), 0);
                assert_eq!(manager.acquisitions.load(Ordering::Relaxed), 0);
                let (_, session, _) = process(&valid).unwrap();
                let before = manager.session_summaries_extended().pop().unwrap();
                let reflection = session.get_last_reflection_with_method();
                for bytes in &invalid {
                    assert!(process(bytes).is_none());
                }
                assert!(process(&valid[..valid.len() - 1]).is_none());
                let after = manager.session_summaries_extended().pop().unwrap();
                assert_eq!(after.last_active, before.last_active);
                assert_eq!(session.get_received_count(), 1);
                assert_eq!(session.get_transmitted_count(), 0);
                assert_eq!(session.get_last_reflection_with_method(), reflection);
                assert_eq!(manager.acquisitions.load(Ordering::Relaxed), 1);
                assert_eq!(counters.packets_replayed.load(Ordering::Relaxed), 0);
                assert_eq!(counters.packets_reordered.load(Ordering::Relaxed), 0);
                assert_eq!(session.classify_replay(0), ReplayVerdict::New);
                // Sequence wrap, a gap and a reordered packet are representable;
                // timestamp validation uses the incoming Z bit, not local encoding.
                for (sequence, timestamp, estimate) in
                    [(0, 999_999_999, 0x4001), (2, 0, 1), (1, 0, 0xffff)]
                {
                    assert!(process(&packet(auth, sequence, timestamp, estimate, &key)).is_some());
                }
                assert_eq!(session.get_received_count(), 4);
            }
        }
    }
}

#[test]
fn policy_preserves_legacy_opt_out_and_uses_packet_timestamp_format() {
    let key = HmacKey::new(vec![0xab; 16]).unwrap();
    for auth in [false, true] {
        for enabled in [false, true] {
            let ctx = ProcessingContext {
                hmac_key: Some(&key),
                validate_base_fields: enabled,
                ..super::super::tests::test_ctx(0, 0)
            };
            for (timestamp, estimate, valid) in [
                (0, 0, false),
                (1_000_000_000, 0x4001, false),
                (u64::MAX, 1, true),
                (0, 1, true),
                (0, 0x4001, true),
                (999_999_999, 0xffff, true),
            ] {
                let result = process_stamp_packet(
                    &packet(auth, 0, timestamp, estimate, &key),
                    "127.0.0.1:4000".parse().unwrap(),
                    64,
                    auth,
                    &ctx,
                );
                assert_eq!(result.is_some(), !enabled || valid);
            }
        }
    }
}

#[test]
fn valid_base_keeps_malformed_and_integrity_error_tlv_responses() {
    let key = HmacKey::new(vec![0xab; 16]).unwrap();
    for auth in [false, true] {
        let ctx = ProcessingContext {
            hmac_key: Some(&key),
            validate_base_fields: true,
            ..super::super::tests::test_ctx(0, 0)
        };
        for invalid_digest in [false, true] {
            let mut bytes = packet(auth, 0, 1, 1, &key);
            let base = bytes.len();
            let length = if invalid_digest { 8 } else { 7 };
            bytes.extend_from_slice(&[0x80, 243, 0, length]);
            bytes.resize(bytes.len() + usize::from(length), 0);
            let mut covered = bytes[..4].to_vec();
            covered.extend_from_slice(&bytes[base..]);
            let mut digest = key.compute(&covered);
            if invalid_digest {
                digest[0] ^= 1;
            }
            bytes.extend_from_slice(&[0x80, 8, 0, 16]);
            bytes.extend_from_slice(&digest);
            let response =
                process_stamp_packet(&bytes, "127.0.0.1:4000".parse().unwrap(), 64, auth, &ctx)
                    .unwrap();
            assert_ne!(
                response.data[base] & if invalid_digest { 0x20 } else { 0x40 },
                0
            );
        }
    }
}
