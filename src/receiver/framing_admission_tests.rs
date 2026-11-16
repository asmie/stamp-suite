use super::*;

fn packet(mode: u8, sequence: u32, extensions: &[u8], key: &HmacKey) -> Vec<u8> {
    let auth = mode == 2;
    let mut bytes = vec![
        0;
        if auth {
            AUTH_BASE_SIZE
        } else {
            UNAUTH_BASE_SIZE
        }
    ];
    let timestamp = if auth { 16 } else { 4 };
    bytes[..4].copy_from_slice(&sequence.to_be_bytes());
    bytes[timestamp..timestamp + 8].copy_from_slice(&1u64.to_be_bytes());
    bytes[timestamp + 9] = 1;
    bytes[timestamp + 10..timestamp + 12].copy_from_slice(&42u16.to_be_bytes());
    if auth {
        let digest = compute_packet_hmac(key, &bytes, AUTH_HMAC_OFFSET);
        bytes[AUTH_HMAC_OFFSET..AUTH_BASE_SIZE].copy_from_slice(&digest);
    }
    bytes.extend_from_slice(extensions);
    bytes
}

fn incomplete_extensions() -> Vec<Vec<u8>> {
    let mut cases = vec![
        vec![0x80],
        vec![0x80, 1],
        vec![0x80, 1, 0],
        vec![0x80, 1, 0, 2, 0],
    ];
    // Known child regions: Location, Timestamp Information, Return Path,
    // Reflected Control and Residual BER. Check both incomplete headers/values,
    // including error flags which must not bypass structural admission.
    for (kind, prefix) in [(2, 4), (3, 4), (10, 0), (12, 8), (243, 8)] {
        for child in [&[0x80, 250][..], &[0x80, 250, 0, 2, 0][..]] {
            for flags in [0x80, 0x40, 0x20] {
                let mut bytes = vec![flags, kind, 0, (prefix + child.len()) as u8];
                bytes.resize(4 + prefix, 0);
                bytes.extend_from_slice(child);
                cases.push(bytes);
            }
        }
    }
    cases
}

#[test]
fn framing_admission_precedes_allocation_activity_counters_and_replay() {
    let key = HmacKey::new(vec![0xab; 16]).unwrap();
    for (source, local) in [
        ("127.0.0.1:4000", "127.0.0.1:862"),
        ("[::1]:4000", "[::1]:862"),
    ] {
        for mode in 0..3 {
            for stateful in [false, true] {
                for tlv_mode in [TlvHandlingMode::Echo, TlvHandlingMode::Ignore] {
                    let manager = Arc::new(SessionManager::new(None, Some(1)));
                    let counters = ReflectorCounters::new();
                    let ctx = ProcessingContext {
                        session_manager: Some(&manager),
                        packet_local_addr: Some(local.parse().unwrap()),
                        hmac_key: (mode != 0).then_some(&key),
                        validate_tlv_framing: true,
                        stateful_reflector: stateful,
                        tlv_mode,
                        ..tests::test_ctx(0, 0)
                    };
                    let process = |bytes: &[u8]| {
                        process_session_packet_isolated(
                            bytes,
                            source.parse().unwrap(),
                            64,
                            mode == 2,
                            &ctx,
                            &counters,
                            true,
                        )
                    };
                    for extensions in incomplete_extensions() {
                        assert!(
                            process(&packet(mode, 100, &extensions, &key)).is_none(),
                            "{extensions:?}"
                        );
                    }
                    assert_eq!(manager.session_count(), 0);
                    assert_eq!(manager.acquisitions.load(Ordering::Relaxed), 0);
                    let (_, session, _) = process(&packet(mode, 0, &[], &key)).unwrap();
                    let before = manager.session_summaries_extended().pop().unwrap();
                    let reflection = session.get_last_reflection_with_method();
                    for extensions in incomplete_extensions() {
                        // A rejected duplicate must not touch replay counters;
                        // a rejected future sequence must not advance history.
                        for seq in [0, 100] {
                            assert!(process(&packet(mode, seq, &extensions, &key)).is_none());
                        }
                    }
                    let after = manager.session_summaries_extended().pop().unwrap();
                    assert_eq!(after.last_active, before.last_active);
                    assert_eq!(session.get_received_count(), 1);
                    assert_eq!(session.get_transmitted_count(), 0);
                    assert_eq!(session.get_last_reflection_with_method(), reflection);
                    assert_eq!(manager.acquisitions.load(Ordering::Relaxed), 1);
                    assert_eq!(counters.packets_replayed.load(Ordering::Relaxed), 0);
                    assert_eq!(counters.packets_reordered.load(Ordering::Relaxed), 0);
                    assert_eq!(
                        session.classify_replay(1),
                        crate::session::ReplayVerdict::New
                    );
                    assert!(process(&packet(mode, 1, &[], &key)).is_some());
                    assert_eq!(session.get_received_count(), 2);
                }
            }
        }
    }
}

#[test]
fn framing_admission_keeps_complete_semantic_errors_and_opaque_values() {
    let key = HmacKey::new(vec![0xab; 16]).unwrap();
    for mode in 0..3 {
        let ctx = ProcessingContext {
            hmac_key: (mode != 0).then_some(&key),
            validate_tlv_framing: true,
            ..tests::test_ctx(0, 0)
        };
        for (extensions, expected_flag) in [
            (vec![0x80, 243, 0, 7, 0, 0, 0, 0, 0, 0, 0], 0x40),
            (vec![0x80, 250, 0, 1, 0xff], 0x80),
            (vec![0x80, 1, 0, 1, 0xff], 0),
        ] {
            for bad_digest in [false, true] {
                if mode == 0 && bad_digest {
                    continue;
                }
                let mut bytes = packet(mode, 0, &extensions, &key);
                let base = if mode == 2 {
                    AUTH_BASE_SIZE
                } else {
                    UNAUTH_BASE_SIZE
                };
                if mode != 0 {
                    let mut covered = bytes[..4].to_vec();
                    covered.extend_from_slice(&extensions);
                    let mut digest = key.compute(&covered);
                    if bad_digest {
                        digest[0] ^= 1;
                    }
                    bytes.extend_from_slice(&[0x80, 8, 0, 16]);
                    bytes.extend_from_slice(&digest);
                }
                let response = process_stamp_packet(
                    &bytes,
                    "127.0.0.1:4000".parse().unwrap(),
                    64,
                    mode == 2,
                    &ctx,
                )
                .unwrap();
                let expected = if bad_digest { 0x20 } else { expected_flag };
                if expected != 0 {
                    assert_ne!(response.data[base] & expected, 0);
                } else {
                    assert_eq!(response.data[base] & 0xe0, 0);
                }
            }
        }
        // Default behavior still returns the malformed frame; validation is opt-in.
        let malformed = packet(mode, 0, &[0x80, 243, 0, 8, 0], &key);
        assert!(process_stamp_packet(
            &malformed,
            "127.0.0.1:4000".parse().unwrap(),
            64,
            mode == 2,
            &ctx
        )
        .is_none());
        let legacy = ProcessingContext {
            validate_tlv_framing: false,
            ..ctx
        };
        assert!(process_stamp_packet(
            &malformed,
            "127.0.0.1:4000".parse().unwrap(),
            64,
            mode == 2,
            &legacy
        )
        .is_some());
    }
}

#[test]
fn framing_admission_keeps_type12_ordering_error_reply() {
    let key = HmacKey::new(vec![0xab; 16]).unwrap();
    for mode in 0..3 {
        let manager = Arc::new(SessionManager::new(None, Some(1)));
        let counters = ReflectorCounters::new();
        let ctx = ProcessingContext {
            session_manager: Some(&manager),
            hmac_key: (mode != 0).then_some(&key),
            validate_tlv_framing: true,
            ..tests::test_ctx(0, 0)
        };
        let extensions = [0x80, 12, 0, 12, 0, 0, 0, 1, 0, 0x0f, 0x42, 0x40, 0, 0, 0, 0];
        let mut bytes = packet(mode, 1, &extensions, &key);
        if mode != 0 {
            let covered = [&bytes[..4], &extensions].concat();
            let digest = key.compute(&covered);
            bytes.extend_from_slice(&[0x80, 8, 0, 16]);
            bytes.extend_from_slice(&digest);
        }
        let process = || {
            process_session_packet_isolated(
                &bytes,
                "127.0.0.1:4000".parse().unwrap(),
                64,
                mode == 2,
                &ctx,
                &counters,
                true,
            )
            .unwrap()
        };
        let base = if mode == 2 {
            AUTH_BASE_SIZE
        } else {
            UNAUTH_BASE_SIZE
        };
        let (first, _, _) = process();
        assert_eq!(first.data[base] & 0xe0, 0);
        let (duplicate, session, _) = process();
        assert_ne!(duplicate.data[base] & 0x80, 0);
        assert!(
            duplicate.reflected_control.is_none(),
            "ordering errors must not schedule a burst"
        );
        assert_eq!(session.get_received_count(), 2);
        assert_eq!(counters.packets_replayed.load(Ordering::Relaxed), 1);
    }
}
