use super::*;
use std::net::{IpAddr, Ipv4Addr};

#[test]
fn selected_key_survives_rotation_and_cos_fallback() {
    for auth in [false, true] {
        let selected = HmacKey::new(vec![0xAB; 16]).unwrap();
        let replacement = HmacKey::new(vec![0xCD; 16]).unwrap();
        let mut keys = crate::crypto::HmacKeySet::with_default(replacement.clone());
        keys.insert(42, selected.clone());
        let base = if auth {
            AUTH_BASE_SIZE
        } else {
            UNAUTH_BASE_SIZE
        };
        let mut data = vec![0; base];
        let error = if auth { 24 } else { 12 };
        data[if auth { 23 } else { 11 }] = 1;
        data[error + 1] = 1;
        data[error + 2..error + 4].copy_from_slice(&42u16.to_be_bytes());
        data.extend_from_slice(&[0x80, 4, 0, 4, 184, 0, 0, 0]);
        let mut covered = data[..4].to_vec();
        covered.extend_from_slice(&data[base..]);
        data.extend_from_slice(&[0x80, 8, 0, 16]);
        data.extend_from_slice(&selected.compute(&covered));
        if auth {
            let hmac = crate::crypto::compute_packet_hmac(&selected, &data, 96);
            data[96..112].copy_from_slice(&hmac);
        }
        let manager = Arc::new(SessionManager::new(None, None));
        let counters = ReflectorCounters::new();
        let (response, session, signing_key) = {
            let ctx = ProcessingContext {
                packet_local_addr: None,
                replay_verdict: crate::session::ReplayVerdict::New,
                hmac_key: Some(&replacement), // must lose to the SSID-specific entry
                hmac_key_set: Some(&keys),
                session_manager: Some(&manager),
                stateful_reflector: true,
                ..test_ctx(0, 0)
            };
            process_session_packet_isolated(&data, loopback_src(), 64, auth, &ctx, &counters, false)
                .unwrap()
        };
        // Mutating/dropping the source set cannot change an accepted reply.
        keys.insert(42, replacement.clone());
        drop(keys);
        let mut transmission = super::transmit::Transmission::new(
            response,
            session,
            loopback_src(),
            ClockFormat::NTP,
            auth,
            true,
            signing_key,
            10,
            false,
        );
        let mut attempts = 0;
        assert_eq!(
            transmission.send_next(&counters, &RateLimiter::new(0), |reply, _, options| {
                attempts += 1;
                if auth {
                    assert_eq!(
                        &reply[96..112],
                        &crate::crypto::compute_packet_hmac(&selected, reply, 96)
                    );
                }
                let pos = reply.len() - 20;
                assert_eq!(&reply[pos + 1..pos + 4], &[8, 0, 16]);
                let mut covered = reply[..4].to_vec();
                covered.extend_from_slice(&reply[base..pos]);
                assert_eq!(&reply[pos + 4..], &selected.compute(&covered));
                assert_ne!(&reply[pos + 4..], &replacement.compute(&covered));
                if attempts == 1 {
                    assert_eq!(options.tos, 184);
                    Err(std::io::Error::from(std::io::ErrorKind::Unsupported))
                } else {
                    assert_eq!(options.tos, 40);
                    Ok(reply.len())
                }
            }),
            Some(0)
        );
        assert_eq!(attempts, 2);
    }
}

#[test]
fn live_packet_authenticates_admits_and_acquires_once_including_burst_sends() {
    let key = HmacKey::new(vec![0xAB; 16]).unwrap();
    for src in ["127.0.0.1:4000", "[::1]:4000"] {
        let src: SocketAddr = src.parse().unwrap();
        for auth in [false, true] {
            for stateful in [false, true] {
                let first = replay_control_packet(10, auth, Some(&key), true);
                let identity = test_ctx(0, 0)
                    .packet_session_key(&first, src, auth)
                    .unwrap();
                let manager = Arc::new(SessionManager::with_admission(
                    None,
                    None,
                    crate::session::SessionAdmission::Provisioned,
                    [identity].into_iter().collect(),
                ));
                let mut keys = crate::crypto::HmacKeySet::new();
                keys.insert(42, key.clone());
                let ctx = ProcessingContext {
                    packet_local_addr: None,
                    session_manager: Some(&manager),
                    hmac_key_set: Some(&keys),
                    stateful_reflector: stateful,
                    ..test_ctx(0, 0)
                };
                let counters = ReflectorCounters::new();
                for index in 0..2 {
                    let data = replay_control_packet(10 + index, auth, Some(&key), true);
                    let verifications = crate::crypto::PACKET_HMAC_VERIFICATIONS.with(|n| n.get());
                    let (response, session, signing_key) = process_session_packet_isolated(
                        &data, src, 64, auth, &ctx, &counters, false,
                    )
                    .unwrap();
                    assert_eq!(
                        manager.admission_checks.load(Ordering::Relaxed),
                        index as usize + 1
                    );
                    assert_eq!(
                        manager.acquisitions.load(Ordering::Relaxed),
                        index as usize + 1
                    );
                    assert!(Arc::ptr_eq(
                        &session,
                        &manager.get_session(identity).unwrap()
                    ));
                    let mut transmission = super::transmit::Transmission::new(
                        response,
                        Arc::clone(&session),
                        src,
                        ClockFormat::NTP,
                        auth,
                        stateful,
                        signing_key,
                        0,
                        false,
                    );
                    assert_eq!(transmission.remaining, 3);
                    for copy in 0..3 {
                        let expected = if stateful {
                            index * 3 + copy
                        } else {
                            10 + index
                        };
                        assert_eq!(
                            transmission.send_next(
                                &counters,
                                &RateLimiter::new(0),
                                |reply, _, _| {
                                    if auth {
                                        assert_eq!(&reply[96..112], &key.compute(&reply[..96]));
                                    }
                                    Ok(reply.len())
                                }
                            ),
                            Some(expected)
                        );
                    }
                    assert_eq!(session.get_received_count(), index + 1);
                    assert_eq!(session.get_transmitted_count(), (index + 1) * 3);
                    assert_eq!(
                        manager.admission_checks.load(Ordering::Relaxed),
                        index as usize + 1
                    );
                    assert_eq!(
                        manager.acquisitions.load(Ordering::Relaxed),
                        index as usize + 1
                    );
                    assert_eq!(
                        crate::crypto::PACKET_HMAC_VERIFICATIONS.with(|n| n.get()) - verifications,
                        usize::from(auth)
                    );
                }
            }
        }
    }
}

#[test]
fn standalone_processing_reuses_admission_and_preserves_stateless_allocation() {
    let key = HmacKey::new(vec![0xAB; 16]).unwrap();
    for auth in [false, true] {
        for stateful in [false, true] {
            let manager = Arc::new(SessionManager::new(None, None));
            let ctx = ProcessingContext {
                packet_local_addr: None,
                session_manager: Some(&manager),
                hmac_key: Some(&key),
                stateful_reflector: stateful,
                ..test_ctx(0, 0)
            };
            for index in 0..2 {
                let data = replay_control_packet(10 + index, auth, Some(&key), false);
                let response = process_stamp_packet(&data, loopback_src(), 64, auth, &ctx).unwrap();
                assert_eq!(
                    u32::from_be_bytes(response.data[..4].try_into().unwrap()),
                    if stateful { index } else { 10 + index }
                );
                assert_eq!(
                    manager.admission_checks.load(Ordering::Relaxed),
                    index as usize + 1
                );
                assert_eq!(
                    manager.acquisitions.load(Ordering::Relaxed),
                    if stateful { index as usize + 1 } else { 0 }
                );
                assert_eq!(manager.session_count(), usize::from(stateful));
            }
        }
    }
}

#[test]
fn capacity_and_drain_reject_new_sessions_before_reply_assembly() {
    let key = HmacKey::new(vec![0xAB; 16]).unwrap();
    for auth in [false, true] {
        for stateful in [false, true] {
            for drain in [false, true] {
                let manager = Arc::new(SessionManager::new(None, Some(1)));
                let counters = ReflectorCounters::new();
                let ctx = ProcessingContext {
                    packet_local_addr: None,
                    session_manager: Some(&manager),
                    hmac_key: auth.then_some(&key),
                    stateful_reflector: stateful,
                    ..test_ctx(0, 0)
                };
                let known = loopback_src();
                let mut unknown = known;
                unknown.set_port(known.port() + 1);
                let data = replay_control_packet(10, auth, auth.then_some(&key), false);
                let (_, session, _) =
                    process_session_packet_isolated(&data, known, 64, auth, &ctx, &counters, false)
                        .unwrap();
                assert_eq!(session.generate_sequence_number(), 0);
                if drain {
                    manager.set_max_sessions(0);
                    manager.set_draining(true);
                }
                for seq in 0..3 {
                    let data = replay_control_packet(seq, auth, auth.then_some(&key), true);
                    assert!(
                        process_session_packet_isolated(
                            &data, unknown, 64, auth, &ctx, &counters, false,
                        )
                        .is_none(),
                        "rejected identity must not get fresh transient state"
                    );
                }
                if stateful {
                    assert!(
                        process_stamp_packet(&data, unknown, 64, auth, &ctx).is_none(),
                        "standalone stateful processing must propagate admission rejection"
                    );
                }
                assert_eq!(manager.session_count(), 1);
                let data = replay_control_packet(11, auth, auth.then_some(&key), false);
                let (_, same, _) =
                    process_session_packet_isolated(&data, known, 64, auth, &ctx, &counters, false)
                        .unwrap();
                assert!(Arc::ptr_eq(&session, &same));
                assert_eq!(same.generate_sequence_number(), 1);
                assert_eq!(same.get_received_count(), 2);
                assert_eq!(counters.packets_replayed.load(Ordering::Relaxed), 0);
                if drain {
                    manager.set_draining(false);
                } else {
                    manager.set_max_sessions(2);
                }
                assert!(process_session_packet_isolated(
                    &data, unknown, 64, auth, &ctx, &counters, false,
                )
                .is_some());
                assert_eq!(manager.session_count(), 2);
            }
        }
    }
}

fn replay_control_packet(seq: u32, auth: bool, key: Option<&HmacKey>, control: bool) -> Vec<u8> {
    let base = if auth { 112 } else { 44 };
    let mut data = vec![0; base];
    data[..4].copy_from_slice(&seq.to_be_bytes());
    let ssid = if auth { 26 } else { 14 };
    data[ssid - 1] = 1;
    data[ssid..ssid + 2].copy_from_slice(&42u16.to_be_bytes());
    if control {
        data.extend_from_slice(&[0x80, 12, 0, 12, 4, 0, 0, 3]);
        data.extend_from_slice(&100_000_000u32.to_be_bytes());
        data.extend_from_slice(&[0; 4]);
    }
    if let Some(key) = key {
        if auth {
            let mac = crate::crypto::compute_packet_hmac(key, &data, 96);
            data[96..112].copy_from_slice(&mac);
        }
        if control {
            let mut covered = data[..4].to_vec();
            covered.extend_from_slice(&data[base..]);
            data.extend_from_slice(&[0x80, 8, 0, 16]);
            data.extend_from_slice(&key.compute(&covered));
        }
    }
    data
}

/// Both live backends share this entry; also runs in pnet-only builds.
#[test]
fn non_monotonic_control_gets_one_u_flagged_reply() {
    let key = HmacKey::new(vec![0xAB; 16]).unwrap();
    for (auth, keyed) in [(false, false), (false, true), (true, true)] {
        for stateful in [false, true] {
            for drop_replayed in [false, true] {
                for sequences in [
                    vec![
                        (1000, false),
                        (1002, false),
                        (1000, true),
                        (1001, true),
                        (900, true),
                        (1003, false),
                    ],
                    vec![
                        (u32::MAX - 1, false),
                        (u32::MAX, false),
                        (0, false),
                        (u32::MAX, true),
                        (1, false),
                    ],
                ] {
                    let manager = Arc::new(SessionManager::new(None, None));
                    let counters = ReflectorCounters::new();
                    let ctx = ProcessingContext {
                        packet_local_addr: None,
                        replay_verdict: crate::session::ReplayVerdict::New,
                        session_manager: Some(&manager),
                        hmac_key: keyed.then_some(&key),
                        stateful_reflector: stateful,
                        ..test_ctx(0, 0)
                    };
                    for (seq, non_monotonic) in sequences {
                        let data = replay_control_packet(seq, auth, keyed.then_some(&key), true);
                        let (response, _, _) = process_session_packet_isolated(
                            &data,
                            loopback_src(),
                            64,
                            auth,
                            &ctx,
                            &counters,
                            drop_replayed,
                        )
                        .expect(
                            "Type-12 ordering failures require a reply even with --drop-replayed",
                        );
                        let base = if auth { 112 } else { 44 };
                        assert_eq!(response.data[base + 1], 12);
                        assert_eq!(
                            response.data[base] & 0xC8,
                            if non_monotonic { 0x80 } else { 0 },
                            "seq={seq} auth={auth} stateful={stateful} drop={drop_replayed}"
                        );
                        assert_eq!(
                            response.reflected_control.map_or(0, |c| c.extra_copies),
                            if non_monotonic { 0 } else { 2 }
                        );
                        assert_eq!(response.return_path_action, ReturnPathAction::Normal);
                        if non_monotonic {
                            assert_eq!(
                                response.data.len(),
                                data.len(),
                                "do not honor requested padding on a replay"
                            );
                        } else {
                            assert_eq!(response.data.len(), 1024);
                        }
                        if auth {
                            assert_eq!(
                                &response.data[96..112],
                                &crate::crypto::compute_packet_hmac(&key, &response.data, 96)
                            );
                        }
                        if keyed {
                            assert!(verify_incoming_tlv_hmac(&response.data, base, &key));
                        }
                    }
                }
            }
        }
    }
}

#[test]
fn non_monotonic_control_preserves_tlv_validation_and_group_filters() {
    for auth in [false, true] {
        let key = HmacKey::new(vec![0xAB; 16]).unwrap();
        let manager = Arc::new(SessionManager::new(None, None));
        let counters = ReflectorCounters::new();
        let ctx = ProcessingContext {
            packet_local_addr: None,
            hmac_key: Some(&key),
            session_manager: Some(&manager),
            ..test_ctx(0, 0)
        };
        let valid = replay_control_packet(42, auth, Some(&key), true);
        assert!(process_session_packet_isolated(
            &valid,
            loopback_src(),
            64,
            auth,
            &ctx,
            &counters,
            true
        )
        .is_some());
        let mut corrupted = valid.clone();
        *corrupted.last_mut().unwrap() ^= 1; // valid base, failed TLV integrity
        let (response, _, _) = process_session_packet_isolated(
            &corrupted,
            loopback_src(),
            64,
            auth,
            &ctx,
            &counters,
            true,
        )
        .unwrap();
        let base = if auth { 112 } else { 44 };
        assert_eq!(response.data[base] & 0x20, 0x20);
        assert!(response.reflected_control.is_none());
        assert_eq!(response.data.len(), corrupted.len());
    }
    // The ordering response must not override the address-group admission rule.
    let mut data = replay_control_packet(42, false, None, true);
    data.truncate(44 + 4 + 8); // replace the four-octet placeholder sub-TLV
    data[46..48].copy_from_slice(&24u16.to_be_bytes());
    data.extend_from_slice(&[0, 10, 0, 12]);
    data.extend_from_slice(&[0xFF; 6]);
    data.extend_from_slice(&[1; 6]);
    let ctx = ProcessingContext {
        packet_local_addr: None,
        replay_verdict: crate::session::ReplayVerdict::Replay,
        ..test_ctx(0, 0)
    };
    let response = process_stamp_packet(&data, loopback_src(), 64, false, &ctx).unwrap();
    assert_eq!(response.return_path_action, ReturnPathAction::SuppressReply);
    assert!(response.reflected_control.is_none());
}

#[test]
fn non_monotonic_control_does_not_execute_zero_count_or_disabled_requests() {
    for count in [0u16, 3] {
        for cap in [0, 16] {
            let mut data = replay_control_packet(42, false, None, true);
            data[50..52].copy_from_slice(&count.to_be_bytes());
            let ctx = ProcessingContext {
                packet_local_addr: None,
                replay_verdict: crate::session::ReplayVerdict::Replay,
                reflected_control_max_count: cap,
                ..test_ctx(0, 0)
            };
            let response = process_stamp_packet(&data, loopback_src(), 64, false, &ctx).unwrap();
            assert_eq!(response.data[44] & 0xE8, 0x80);
            assert_eq!(response.return_path_action, ReturnPathAction::Normal);
            assert!(response.reflected_control.is_none());
            assert_eq!(response.data.len(), data.len());
        }
    }
}

#[test]
fn replay_drop_policy_still_controls_ordinary_packets() {
    for drop_replayed in [false, true] {
        let manager = Arc::new(SessionManager::new(None, None));
        let counters = ReflectorCounters::new();
        let ctx = ProcessingContext {
            packet_local_addr: None,
            replay_verdict: crate::session::ReplayVerdict::New,
            session_manager: Some(&manager),
            ..test_ctx(0, 0)
        };
        let data = replay_control_packet(42, false, None, false);
        for duplicate in [false, true] {
            let response = process_session_packet_isolated(
                &data,
                loopback_src(),
                64,
                false,
                &ctx,
                &counters,
                drop_replayed,
            );
            assert_eq!(response.is_none(), duplicate && drop_replayed);
        }
    }
}

/// Runs for pnet-only builds too, without requiring a raw capture channel.
#[test]
fn tracked_processing_validates_before_any_session_mutation() {
    let key = HmacKey::new(vec![0xAB; 16]).unwrap();
    for strict in [false, true] {
        for stateful in [false, true] {
            let manager = Arc::new(SessionManager::new(None, Some(1)));
            let counters = ReflectorCounters::new();
            let ctx = ProcessingContext {
                packet_local_addr: None,
                replay_verdict: crate::session::ReplayVerdict::New,
                session_manager: Some(&manager),
                hmac_key: Some(&key),
                strict_packets: strict,
                stateful_reflector: stateful,
                ..test_ctx(0, 0)
            };
            let mut data = [0u8; AUTH_BASE_SIZE];
            data[3] = 100;
            data[25] = 1;
            let mac = crate::crypto::compute_packet_hmac(&key, &data, AUTH_HMAC_OFFSET);
            data[AUTH_HMAC_OFFSET..].copy_from_slice(&mac);
            let mut forged = data;
            forged[AUTH_HMAC_OFFSET] ^= 1;
            assert!(process_session_packet_isolated(
                &forged,
                loopback_src(),
                64,
                true,
                &ctx,
                &counters,
                true
            )
            .is_none());
            assert_eq!(manager.session_count(), 0);
            assert_eq!(manager.admission_checks.load(Ordering::Relaxed), 1);
            assert_eq!(manager.acquisitions.load(Ordering::Relaxed), 0);
            let (response, session, _) = process_session_packet_isolated(
                &data,
                loopback_src(),
                64,
                true,
                &ctx,
                &counters,
                true,
            )
            .unwrap();
            assert_eq!(
                u32::from_be_bytes(response.data[..4].try_into().unwrap()),
                if stateful { 0 } else { 100 }
            );
            let before = manager.session_summaries_extended().pop().unwrap();
            assert!(process_session_packet_isolated(
                &forged,
                loopback_src(),
                64,
                true,
                &ctx,
                &counters,
                true
            )
            .is_none());
            assert_eq!(
                manager
                    .session_summaries_extended()
                    .pop()
                    .unwrap()
                    .last_active,
                before.last_active
            );
            assert_eq!(session.get_received_count(), 1);
            assert_eq!(manager.admission_checks.load(Ordering::Relaxed), 3);
            assert_eq!(manager.acquisitions.load(Ordering::Relaxed), 1);
            assert_eq!(counters.packets_replayed.load(Ordering::Relaxed), 0);
            // Revoking the required base key must not refresh an existing session.
            let no_key = ProcessingContext {
                packet_local_addr: None,
                replay_verdict: crate::session::ReplayVerdict::New,
                hmac_key: None,
                require_hmac: true,
                ..ctx
            };
            assert!(process_session_packet_isolated(
                &data,
                loopback_src(),
                64,
                true,
                &no_key,
                &counters,
                true
            )
            .is_none());
            assert_eq!(session.get_received_count(), 1);
            assert_eq!(manager.admission_checks.load(Ordering::Relaxed), 4);
            assert_eq!(manager.acquisitions.load(Ordering::Relaxed), 1);
        }
    }
}

#[test]
fn identity_parser_rejects_ambiguous_micro_session_ids() {
    let src: SocketAddr = "127.0.0.1:4000".parse().unwrap();
    let local: SocketAddr = "127.0.0.1:862".parse().unwrap();
    for auth in [false, true] {
        let mut data = vec![
            0;
            if auth {
                AUTH_BASE_SIZE
            } else {
                UNAUTH_BASE_SIZE
            }
        ];
        let offset = if auth { 26 } else { 14 };
        data[offset..offset + 2].copy_from_slice(&42u16.to_be_bytes());
        data.extend_from_slice(&[0, 11, 0, 4, 0, 7, 0, 0]);
        let key = packet_session_key(&data, src, local, auth).unwrap();
        assert_eq!(key.ssid, 42);
        assert_eq!(key.sender_micro_session_id, Some(7));
        // A learned reflector member must not change the lookup key.
        *data.last_mut().unwrap() = 9;
        assert_eq!(packet_session_key(&data, src, local, auth), Some(key));
        data.extend_from_slice(&[0, 11, 0, 4, 0, 8, 0, 0]);
        assert!(packet_session_key(&data, src, local, auth).is_none());
        data.truncate(data.len() - 9);
        assert_eq!(
            packet_session_key(&data, src, local, auth)
                .unwrap()
                .sender_micro_session_id,
            None
        );
    }
}

#[test]
fn empty_provisioning_drops_packets_without_creating_state() {
    let manager = Arc::new(SessionManager::with_admission(
        None,
        None,
        crate::session::SessionAdmission::Provisioned,
        Default::default(),
    ));
    for stateful in [false, true] {
        let ctx = ProcessingContext {
            packet_local_addr: None,
            replay_verdict: crate::session::ReplayVerdict::New,
            session_manager: Some(&manager),
            stateful_reflector: stateful,
            ..test_ctx(0, 0)
        };
        assert!(process_stamp_packet(&[0; 44], loopback_src(), 64, false, &ctx).is_none());
        assert_eq!(manager.session_count(), 0);
    }
}

#[test]
fn scoped_session_identity_keeps_both_endpoint_zones() {
    let mut ctx = test_ctx(0, 0);
    let client: SocketAddr = "[fe80::1%7]:5000".parse().unwrap();
    ctx.packet_local_addr = Some("[fe80::2%7]:862".parse().unwrap());
    let a = ctx.packet_session_key(&[0; 44], client, false).unwrap();
    assert_eq!(a.local, ctx.packet_local_addr.unwrap());
    assert_eq!(a.client, client);
    ctx.packet_local_addr = Some("[fe80::2%8]:862".parse().unwrap());
    let b = ctx.packet_session_key(&[0; 44], client, false).unwrap();
    assert_ne!(a, b);
    let c = ctx
        .packet_session_key(&[0; 44], "[fe80::1%8]:5000".parse().unwrap(), false)
        .unwrap();
    assert_ne!(b, c);
    assert_eq!(
        c.to_string().parse::<crate::session::SessionKey>().unwrap(),
        c
    );
}

/// Creates a default ProcessingContext for tests with given DSCP/ECN values.
fn test_ctx(received_dscp: u8, received_ecn: u8) -> ProcessingContext<'static> {
    ProcessingContext {
        ingress_ifindex: None,
        packet_local_addr: None,
        replay_verdict: crate::session::ReplayVerdict::New,
        clock_source: ClockFormat::NTP,
        clock_sync_source: SyncSource::Local,
        hardware_clock_sync_source: SyncSource::Local,
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
        received_dscp,
        received_ecn,
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
        reflected_control_max_count: REFLECTED_CONTROL_MAX_COUNT,
        reflected_control_max_size: REFLECTED_CONTROL_MAX_SIZE,
        reflected_control_min_interval_ns: REFLECTED_CONTROL_MIN_INTERVAL_NS,
        reflected_control_max_rate: REFLECTED_CONTROL_MAX_RATE,
        reflected_control_max_volume: REFLECTED_CONTROL_MAX_VOLUME,
        rx_timestamp: None,
        rx_method: TimestampMethod::SwLocal,
        last_reflection_method: TimestampMethod::SwLocal,
    }
}

/// Test helper: Verifies TLV HMAC if present in the incoming packet per RFC 8972 §4.8.
///
/// The HMAC covers the Sequence Number field (first 4 bytes) + preceding TLVs.
///
/// Returns true if no HMAC TLV is present or if verification succeeds.
/// Returns false if HMAC verification fails.
fn verify_incoming_tlv_hmac(original_data: &[u8], base_size: usize, key: &HmacKey) -> bool {
    if original_data.len() <= base_size {
        return true; // No TLVs to verify
    }

    let tlv_data = &original_data[base_size..];
    let Ok(tlvs) = TlvList::parse(tlv_data) else {
        return false; // Malformed TLVs
    };

    if tlvs.hmac_tlv().is_none() {
        return true; // No HMAC TLV to verify
    }

    // Per RFC 8972 §4.8: HMAC covers Sequence Number (first 4 bytes) + preceding TLVs
    let sequence_number_bytes = &original_data[..4];
    tlvs.verify_hmac(key, sequence_number_bytes, tlv_data)
        .is_ok()
}

fn reflect_unauth_tlvs(tlvs: &[u8], ctx: &ProcessingContext) -> Vec<u8> {
    let sender_packet = PacketUnauthenticated {
        sequence_number: 1,
        timestamp: 100,
        error_estimate: 0,
        ssid: 0,
        mbz: [0; 28],
    };
    let mut request = sender_packet.to_bytes().to_vec();
    request.extend_from_slice(tlvs);
    let response = assemble_unauth_answer_with_tlvs(
        &sender_packet,
        &request,
        ClockFormat::NTP,
        200,
        255,
        0,
        None,
        TlvHandlingMode::Echo,
        None,
        false,
        ctx,
    );
    response.data[UNAUTH_BASE_SIZE..].to_vec()
}

/// RFC 8972 §4: a TLV whose Length is wrong for its type stops processing.
/// It is echoed with M; later TLVs are copied unprocessed with U.
#[test]
fn test_invalid_length_tlv_stops_processing_of_later_tlvs() {
    let mut tlvs = vec![0x80, 4, 0, 8, 0xB8, 0, 0, 0, 0, 0, 0, 0]; // CoS, Length 8
    tlvs.extend_from_slice(&[0x80, 5, 0, 12, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0]);
    let mut ctx = test_ctx(10, 1);
    ctx.reflector_rx_count = Some(7);
    ctx.reflector_tx_count = Some(9);
    let reply = reflect_unauth_tlvs(&tlvs, &ctx);
    assert_eq!(reply[0], 0x40, "CoS carries M only");
    assert_eq!(reply[12], 0x80, "Direct Measurement is not processed");
    assert_eq!(&reply[20..28], &[0; 8], "R_RxC/R_TxC left unfilled");
}

/// RFC 8972 §4.3: a Timestamp Information TLV may carry sub-TLVs.
#[test]
fn test_timestamp_info_with_sub_tlvs_is_filled() {
    let tlvs = [0x80, 3, 0, 8, 0, 0, 0, 0, 0, 9, 0, 0];
    let reply = reflect_unauth_tlvs(&tlvs, &test_ctx(0, 0));
    assert_eq!(reply[0], 0x00, "neither U nor M");
    assert_ne!(&reply[4..8], &[0, 0, 0, 0], "fields filled");
    assert_eq!(&reply[8..12], &[0, 9, 0, 0], "sub-TLV bytes copied");
}

/// RFC 8972 §4.4 / cos-ecn-01 §3.1: Reserved bits are zeroed in the reply.
#[test]
fn test_cos_reserved_bits_are_zeroed() {
    let tlvs = [0x80, 4, 0, 4, 0xB8, 0, 0x4F, 0xFF];
    let reply = reflect_unauth_tlvs(&tlvs, &test_ctx(0, 0));
    assert_eq!(reply[6] & 0xC0, 0x40, "EC1 kept");
    assert_eq!(reply[6] & 0x0F, 0, "Reserved bits 3:0 zeroed");
    assert_eq!(reply[7], 0, "Reserved octet zeroed");
}

/// RFC 8762 §4.3: octets too short for a TLV header are copied, not zeroed.
#[test]
fn test_short_trailing_octets_are_copied() {
    let tlvs = [0x80, 1, 0, 4, 0, 0, 0, 0, 0x11, 0x22];
    let reply = reflect_unauth_tlvs(&tlvs, &test_ctx(0, 0));
    assert_eq!(&reply[8..], &[0x11, 0x22]);
}

/// RFC 8972 §4: TLVs before a truncated TLV are still processed.
#[test]
fn test_tlvs_before_truncated_tlv_are_processed() {
    let mut tlvs = vec![0x80, 4, 0, 4, 0xB8, 0, 0, 0]; // CoS, DSCP1 46
    tlvs.extend_from_slice(&[0x80, 1, 0, 16, 1, 2, 3, 4]); // Length runs past the end
    let reply = reflect_unauth_tlvs(&tlvs, &test_ctx(10, 1));
    assert_eq!(reply[0], 0x00, "processed CoS has U=0, M=0");
    assert_eq!(reply[5], 0xA4, "DSCP2=10 and ECN=1 were filled in");
    assert_eq!(reply[8], 0x40, "truncated TLV carries M");
    assert_eq!(&reply[12..16], &[1, 2, 3, 4], "remainder copied");
}

#[test]
fn test_assemble_unauth_answer_echoes_sender_fields() {
    let sender_packet = PacketUnauthenticated {
        sequence_number: 42,
        timestamp: 123456789,
        error_estimate: 100,
        ssid: 0,
        mbz: [0; 28],
    };

    let rcvt = 987654321u64;
    let ttl = 64u8;
    let reflector_error_estimate = 200u16;

    let reflected = assemble_unauth_answer(
        &sender_packet,
        ClockFormat::NTP,
        rcvt,
        ttl,
        reflector_error_estimate,
        None,
    );

    // Verify sender fields are echoed
    assert_eq!(
        reflected.sess_sender_seq_number,
        sender_packet.sequence_number
    );
    assert_eq!(reflected.sess_sender_timestamp, sender_packet.timestamp);
    assert_eq!(
        reflected.sess_sender_err_estimate,
        sender_packet.error_estimate
    );
    assert_eq!(reflected.sess_sender_ttl, ttl);
    // Verify reflector's own error estimate is used
    assert_eq!(reflected.error_estimate, reflector_error_estimate);
}

#[test]
fn test_assemble_unauth_answer_receive_timestamp() {
    let sender_packet = PacketUnauthenticated {
        sequence_number: 1,
        timestamp: 100,
        error_estimate: 10,
        ssid: 0,
        mbz: [0; 28],
    };

    let rcvt = 500u64;
    let reflected = assemble_unauth_answer(&sender_packet, ClockFormat::NTP, rcvt, 64, 0, None);

    assert_eq!(reflected.receive_timestamp, rcvt);
}

#[test]
fn test_assemble_unauth_answer_timestamp_generated() {
    let sender_packet = PacketUnauthenticated {
        sequence_number: 1,
        timestamp: 0,
        error_estimate: 0,
        ssid: 0,
        mbz: [0; 28],
    };

    let reflected = assemble_unauth_answer(&sender_packet, ClockFormat::NTP, 0, 64, 0, None);

    // Reflector's timestamp should be non-zero (generated)
    assert!(reflected.timestamp > 0);
}

// -----------------------------------------------------------------------
// Base and symmetric reply assembly.

#[test]
fn test_assemble_auth_answer_echoes_sender_fields() {
    let sender_packet = PacketAuthenticated {
        sequence_number: 42,
        mbz0: [0; 12],
        timestamp: 123456789,
        error_estimate: 100,
        ssid: 0,
        mbz1: [0; 68],
        hmac: [0xab; 16],
    };

    let rcvt = 987654321u64;
    let ttl = 128u8;
    let reflector_error_estimate = 300u16;

    let reflected = assemble_auth_answer(
        &sender_packet,
        ClockFormat::NTP,
        rcvt,
        ttl,
        reflector_error_estimate,
        None,
        None,
    );

    // Verify sender fields are echoed
    assert_eq!(
        reflected.sess_sender_seq_number,
        sender_packet.sequence_number
    );
    assert_eq!(reflected.sess_sender_timestamp, sender_packet.timestamp);
    assert_eq!(
        reflected.sess_sender_err_estimate,
        sender_packet.error_estimate
    );
    assert_eq!(reflected.sess_sender_ttl, ttl);
    // Verify reflector's own error estimate is used
    assert_eq!(reflected.error_estimate, reflector_error_estimate);
}

#[test]
fn test_assemble_unauth_answer_ttl_preserved() {
    let sender_packet = PacketUnauthenticated {
        sequence_number: 1,
        timestamp: 2,
        error_estimate: 3,
        ssid: 0,
        mbz: [0; 28],
    };

    // Test various TTL values
    for ttl in [0u8, 1, 64, 128, 255] {
        let reflected = assemble_unauth_answer(&sender_packet, ClockFormat::NTP, 0, ttl, 0, None);
        assert_eq!(reflected.sess_sender_ttl, ttl);
    }
}

#[test]
fn test_assemble_auth_answer_ttl_preserved() {
    let sender_packet = PacketAuthenticated {
        sequence_number: 1,
        mbz0: [0; 12],
        timestamp: 2,
        error_estimate: 3,
        ssid: 0,
        mbz1: [0; 68],
        hmac: [0; 16],
    };

    // Test various TTL values
    for ttl in [0u8, 1, 64, 128, 255] {
        let reflected =
            assemble_auth_answer(&sender_packet, ClockFormat::NTP, 0, ttl, 0, None, None);
        assert_eq!(reflected.sess_sender_ttl, ttl);
    }
}

#[test]
fn test_assemble_auth_answer_with_hmac() {
    let sender_packet = PacketAuthenticated {
        sequence_number: 1,
        mbz0: [0; 12],
        timestamp: 123456789,
        error_estimate: 100,
        ssid: 0,
        mbz1: [0; 68],
        hmac: [0; 16],
    };

    let key = HmacKey::new(vec![0xab; 32]).unwrap();
    let reflected = assemble_auth_answer(
        &sender_packet,
        ClockFormat::NTP,
        987654321,
        64,
        200,
        Some(&key),
        None,
    );

    // HMAC should be non-zero when key is provided
    assert_ne!(reflected.hmac, [0u8; 16]);
}

#[test]
fn test_assemble_auth_answer_without_hmac() {
    let sender_packet = PacketAuthenticated {
        sequence_number: 1,
        mbz0: [0; 12],
        timestamp: 123456789,
        error_estimate: 100,
        ssid: 0,
        mbz1: [0; 68],
        hmac: [0; 16],
    };

    let reflected = assemble_auth_answer(
        &sender_packet,
        ClockFormat::NTP,
        987654321,
        64,
        200,
        None,
        None,
    );

    // HMAC should be zero when no key is provided
    assert_eq!(reflected.hmac, [0u8; 16]);
}

#[test]
fn test_assemble_unauth_answer_with_reflector_seq() {
    let sender_packet = PacketUnauthenticated {
        sequence_number: 42,
        timestamp: 123456789,
        error_estimate: 100,
        ssid: 0,
        mbz: [0; 28],
    };

    // Test with independent reflector sequence number
    let reflected = assemble_unauth_answer(
        &sender_packet,
        ClockFormat::NTP,
        987654321,
        64,
        200,
        Some(999),
    );

    // Reflector's sequence should be independent
    assert_eq!(reflected.sequence_number, 999);
    // Sender's sequence still echoed in sess_sender_seq_number
    assert_eq!(reflected.sess_sender_seq_number, 42);
}

#[test]
fn test_assemble_auth_answer_with_reflector_seq() {
    let sender_packet = PacketAuthenticated {
        sequence_number: 42,
        mbz0: [0; 12],
        timestamp: 123456789,
        error_estimate: 100,
        ssid: 0,
        mbz1: [0; 68],
        hmac: [0; 16],
    };

    // Test with independent reflector sequence number
    let reflected = assemble_auth_answer(
        &sender_packet,
        ClockFormat::NTP,
        987654321,
        64,
        200,
        None,
        Some(999),
    );

    // Reflector's sequence should be independent
    assert_eq!(reflected.sequence_number, 999);
    // Sender's sequence still echoed in sess_sender_seq_number
    assert_eq!(reflected.sess_sender_seq_number, 42);
}

#[test]
fn test_assemble_unauth_answer_symmetric_preserves_length() {
    let sender_packet = PacketUnauthenticated {
        sequence_number: 1,
        timestamp: 100,
        error_estimate: 10,
        ssid: 0,
        mbz: [0; 28],
    };

    // Create original data with extra bytes beyond base 44
    let mut original_data = sender_packet.to_bytes().to_vec();
    original_data.extend_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD]); // 4 extra bytes

    let response = assemble_unauth_answer_symmetric(
        &sender_packet,
        &original_data,
        ClockFormat::NTP,
        200,
        64,
        300,
        None,
    );

    // Response should be 48 bytes (44 base + 4 extra)
    assert_eq!(response.len(), 48);
    // Content beyond the base packet is copied (RFC 8762 §4.3).
    assert_eq!(&response[44..], &[0xAA, 0xBB, 0xCC, 0xDD]);
}

#[test]
fn test_assemble_auth_answer_symmetric_preserves_length() {
    let sender_packet = PacketAuthenticated {
        sequence_number: 1,
        mbz0: [0; 12],
        timestamp: 100,
        error_estimate: 10,
        ssid: 0,
        mbz1: [0; 68],
        hmac: [0; 16],
    };

    // Create original data with extra bytes beyond base 112
    let mut original_data = sender_packet.to_bytes().to_vec();
    original_data.extend_from_slice(&[0x11, 0x22, 0x33, 0x44, 0x55]); // 5 extra bytes

    let response = assemble_auth_answer_symmetric(
        &sender_packet,
        &original_data,
        ClockFormat::NTP,
        200,
        64,
        300,
        None,
        None,
    );

    // Response should be 117 bytes (112 base + 5 extra)
    assert_eq!(response.len(), 117);
    // Content beyond the base packet is copied (RFC 8762 §4.3).
    assert_eq!(&response[112..], &[0x11, 0x22, 0x33, 0x44, 0x55]);
}

#[test]
fn test_assemble_unauth_answer_symmetric_base_size() {
    let sender_packet = PacketUnauthenticated {
        sequence_number: 1,
        timestamp: 100,
        error_estimate: 10,
        ssid: 0,
        mbz: [0; 28],
    };

    // Original data is exactly base size
    let original_data = sender_packet.to_bytes();

    let response = assemble_unauth_answer_symmetric(
        &sender_packet,
        &original_data,
        ClockFormat::NTP,
        200,
        64,
        300,
        None,
    );

    // Response should be exactly 44 bytes
    assert_eq!(response.len(), 44);
}

// TLV-aware assembly tests

#[test]
fn test_assemble_unauth_with_tlvs_ignore_mode() {
    use crate::tlv::{RawTlv, TlvType, TLV_HEADER_SIZE};

    let sender_packet = PacketUnauthenticated {
        sequence_number: 1,
        timestamp: 100,
        error_estimate: 10,
        ssid: 0,
        mbz: [0; 28],
    };

    // Create packet with TLV extension
    let mut original_data = sender_packet.to_bytes().to_vec();
    let tlv = RawTlv::new(TlvType::ExtraPadding, vec![0xAA; 8]);
    original_data.extend_from_slice(&tlv.to_bytes());

    let response = assemble_unauth_answer_with_tlvs(
        &sender_packet,
        &original_data,
        ClockFormat::NTP,
        200,
        64,
        300,
        None,
        TlvHandlingMode::Ignore,
        None,
        false,
        &test_ctx(0, 0),
    );

    // TLVs are copied unprocessed, flags included (RFC 8972 §4).
    assert_eq!(response.data.len(), 44 + TLV_HEADER_SIZE + 8);
    assert_eq!(&response.data[44..], &original_data[44..]);
}

#[test]
fn test_assemble_unauth_with_tlvs_echo_mode() {
    use crate::tlv::{RawTlv, TlvType, TLV_HEADER_SIZE};

    let sender_packet = PacketUnauthenticated {
        sequence_number: 1,
        timestamp: 100,
        error_estimate: 10,
        ssid: 0,
        mbz: [0; 28],
    };

    // Create packet with TLV extension
    let mut original_data = sender_packet.to_bytes().to_vec();
    let tlv = RawTlv::new(TlvType::ExtraPadding, vec![0xAA; 4]);
    original_data.extend_from_slice(&tlv.to_bytes());

    let response = assemble_unauth_answer_with_tlvs(
        &sender_packet,
        &original_data,
        ClockFormat::NTP,
        200,
        64,
        300,
        None,
        TlvHandlingMode::Echo,
        None,
        false,
        &test_ctx(0, 0),
    );

    // Response should include echoed TLV
    assert_eq!(response.data.len(), 44 + TLV_HEADER_SIZE + 4);
    // TLV should be echoed (check type in byte 1 per RFC 8972)
    assert_eq!(response.data[45], 1); // ExtraPadding type
}

#[test]
fn test_assemble_unauth_with_tlvs_does_not_truncate_oversized_response() {
    use crate::tlv::{ExtraPaddingTlv, TlvList};

    let sender_packet = PacketUnauthenticated {
        sequence_number: 1,
        timestamp: 100,
        error_estimate: 10,
        ssid: 0,
        mbz: [0; 28],
    };

    let mut original_data = sender_packet.to_bytes().to_vec();
    original_data.extend_from_slice(&ExtraPaddingTlv::new(1_600).to_raw().to_bytes());

    let response = assemble_unauth_answer_with_tlvs(
        &sender_packet,
        &original_data,
        ClockFormat::NTP,
        200,
        64,
        300,
        None,
        TlvHandlingMode::Echo,
        None,
        false,
        &test_ctx(0, 0),
    );

    assert!(response.data.len() > 1_500);
    let tlv_data = &response.data[UNAUTH_BASE_SIZE..];
    assert!(TlvList::parse(tlv_data).is_ok());
}

#[test]
fn test_assemble_unauth_with_tlvs_marks_unknown() {
    use crate::tlv::{RawTlv, TlvType, TLV_HEADER_SIZE};

    let sender_packet = PacketUnauthenticated {
        sequence_number: 1,
        timestamp: 100,
        error_estimate: 10,
        ssid: 0,
        mbz: [0; 28],
    };

    // Create packet with unknown TLV type
    let mut original_data = sender_packet.to_bytes().to_vec();
    let tlv = RawTlv::new(TlvType::Unknown(15), vec![0xBB; 4]);
    original_data.extend_from_slice(&tlv.to_bytes());

    let response = assemble_unauth_answer_with_tlvs(
        &sender_packet,
        &original_data,
        ClockFormat::NTP,
        200,
        64,
        300,
        None,
        TlvHandlingMode::Echo,
        None,
        false,
        &test_ctx(0, 0),
    );

    // Check U-flag is set (0x80, the most significant flags bit, RFC 8972 §4)
    // Byte 0: Flags (U=0x80), Byte 1: Type
    assert_eq!(response.data[44], 0x80); // U-flag set in flags byte
    assert_eq!(response.data[45], 15); // Type 15 in type byte
    assert_eq!(response.data.len(), 44 + TLV_HEADER_SIZE + 4);
}

#[test]
fn test_assemble_auth_with_tlvs_ignore_mode() {
    use crate::tlv::{RawTlv, TlvType, TLV_HEADER_SIZE};

    let sender_packet = PacketAuthenticated {
        sequence_number: 1,
        mbz0: [0; 12],
        timestamp: 100,
        error_estimate: 10,
        ssid: 0,
        mbz1: [0; 68],
        hmac: [0; 16],
    };

    // Create packet with TLV extension
    let mut original_data = sender_packet.to_bytes().to_vec();
    let tlv = RawTlv::new(TlvType::ExtraPadding, vec![0xCC; 8]);
    original_data.extend_from_slice(&tlv.to_bytes());

    let response = assemble_auth_answer_with_tlvs(
        &sender_packet,
        &original_data,
        ClockFormat::NTP,
        200,
        64,
        300,
        None,
        None,
        TlvHandlingMode::Ignore,
        None,
        false,
        &test_ctx(0, 0),
    );

    // TLVs are copied unprocessed, flags included (RFC 8972 §4).
    assert_eq!(response.data.len(), 112 + TLV_HEADER_SIZE + 8);
    assert_eq!(&response.data[112..], &original_data[112..]);
}

#[test]
fn test_assemble_auth_with_tlvs_echo_mode() {
    use crate::tlv::{RawTlv, TlvType, TLV_HEADER_SIZE};

    let sender_packet = PacketAuthenticated {
        sequence_number: 1,
        mbz0: [0; 12],
        timestamp: 100,
        error_estimate: 10,
        ssid: 0,
        mbz1: [0; 68],
        hmac: [0; 16],
    };

    // Create packet with TLV extension
    let mut original_data = sender_packet.to_bytes().to_vec();
    let tlv = RawTlv::new(TlvType::Location, vec![1, 2, 3, 4]);
    original_data.extend_from_slice(&tlv.to_bytes());

    let response = assemble_auth_answer_with_tlvs(
        &sender_packet,
        &original_data,
        ClockFormat::NTP,
        200,
        64,
        300,
        None,
        None,
        TlvHandlingMode::Echo,
        None,
        false,
        &test_ctx(0, 0),
    );

    // Response should include echoed TLV
    assert_eq!(response.data.len(), 112 + TLV_HEADER_SIZE + 4);
    // TLV should be echoed (check type in byte 1 per RFC 8972)
    assert_eq!(response.data[113], 2); // Location type
}

#[test]
fn test_assemble_auth_with_tlvs_does_not_truncate_oversized_response() {
    use crate::tlv::{ExtraPaddingTlv, TlvList};

    let sender_packet = PacketAuthenticated {
        sequence_number: 1,
        mbz0: [0; 12],
        timestamp: 100,
        error_estimate: 10,
        ssid: 0,
        mbz1: [0; 68],
        hmac: [0; 16],
    };

    let mut original_data = sender_packet.to_bytes().to_vec();
    original_data.extend_from_slice(&ExtraPaddingTlv::new(1_500).to_raw().to_bytes());

    let key = HmacKey::new(vec![0xCD; 32]).unwrap();
    let response = assemble_auth_answer_with_tlvs(
        &sender_packet,
        &original_data,
        ClockFormat::NTP,
        200,
        64,
        300,
        None,
        None,
        TlvHandlingMode::Echo,
        Some(&key),
        false,
        &test_ctx(0, 0),
    );

    assert!(response.data.len() > 1_500);
    let tlv_data = &response.data[AUTH_BASE_SIZE..];
    let tlvs = TlvList::parse(tlv_data).unwrap();
    assert!(tlvs
        .verify_hmac(&key, &response.data[..4], tlv_data)
        .is_ok());
}

// RFC 8762 §4.3/§4.6: the reflected packet MUST be symmetric in size to
// the received packet (copy the content beyond the base packet). A
// trailing all-zero run (classic legacy/TWAMP-Light padding, no TLVs) or a
// non-4-byte-aligned garbage trailer must not shrink the reply.

#[test]
fn test_zero_trailer_reply_preserves_symmetric_size_unauth() {
    let sender_packet = PacketUnauthenticated {
        sequence_number: 1,
        timestamp: 100,
        error_estimate: 10,
        ssid: 0,
        mbz: [0; 28],
    };

    // 44-octet base + 50-octet all-zero trailer (no TLVs at all).
    let mut original_data = sender_packet.to_bytes().to_vec();
    original_data.extend_from_slice(&[0u8; 50]);
    assert_eq!(original_data.len(), UNAUTH_BASE_SIZE + 50);

    let response = assemble_unauth_answer_with_tlvs(
        &sender_packet,
        &original_data,
        ClockFormat::NTP,
        200,
        64,
        300,
        None,
        TlvHandlingMode::Echo,
        None,
        false,
        &test_ctx(0, 0),
    );

    assert_eq!(
        response.data.len(),
        original_data.len(),
        "reply must be symmetric in size to the received packet"
    );
    // The trailing padding must remain zero.
    assert!(response.data[UNAUTH_BASE_SIZE..].iter().all(|&b| b == 0));
}

#[test]
fn test_zero_trailer_reply_preserves_symmetric_size_auth() {
    let sender_packet = PacketAuthenticated {
        sequence_number: 1,
        mbz0: [0; 12],
        timestamp: 100,
        error_estimate: 10,
        ssid: 0,
        mbz1: [0; 68],
        hmac: [0; 16],
    };

    // 112-octet base + 50-octet all-zero trailer (no TLVs at all).
    let mut original_data = sender_packet.to_bytes().to_vec();
    original_data.extend_from_slice(&[0u8; 50]);
    assert_eq!(original_data.len(), AUTH_BASE_SIZE + 50);

    let key = HmacKey::new(vec![0xCD; 32]).unwrap();
    let response = assemble_auth_answer_with_tlvs(
        &sender_packet,
        &original_data,
        ClockFormat::NTP,
        200,
        64,
        300,
        Some(&key),
        None,
        TlvHandlingMode::Echo,
        // No TLV-HMAC key: no HMAC TLV is appended, so the whole trailing
        // area is pure zero padding: the cleanest symmetric-size probe.
        None,
        false,
        &test_ctx(0, 0),
    );

    assert_eq!(
        response.data.len(),
        original_data.len(),
        "auth reply must be symmetric in size to the received packet"
    );
    // Padding is appended AFTER the base packet's HMAC; the trailing area
    // must be all zero.
    assert!(response.data[AUTH_BASE_SIZE..].iter().all(|&b| b == 0));

    // Packet-HMAC coverage must not change: the base packet HMAC (field at
    // [96..112]) still verifies against the reply's own first 112 octets.
    // The appended zero padding lies outside the HMAC's coverage, so it
    // cannot invalidate it.
    let hmac_field: [u8; 16] = response.data[AUTH_HMAC_OFFSET..AUTH_BASE_SIZE]
        .try_into()
        .unwrap();
    assert!(crate::crypto::verify_packet_hmac(
        &key,
        &response.data[..AUTH_BASE_SIZE],
        AUTH_HMAC_OFFSET,
        &hmac_field,
    ));
}

#[test]
fn test_nonaligned_garbage_trailer_preserves_size_unauth() {
    use crate::tlv::{RawTlv, TlvType};

    let sender_packet = PacketUnauthenticated {
        sequence_number: 1,
        timestamp: 100,
        error_estimate: 10,
        ssid: 0,
        mbz: [0; 28],
    };

    // A real TLV followed by 3 stray non-zero bytes (not 4-byte aligned).
    let mut original_data = sender_packet.to_bytes().to_vec();
    let tlv = RawTlv::new(TlvType::ExtraPadding, vec![0xAA; 4]);
    original_data.extend_from_slice(&tlv.to_bytes());
    original_data.extend_from_slice(&[0xBB, 0xCC, 0xDD]);

    let response = assemble_unauth_answer_with_tlvs(
        &sender_packet,
        &original_data,
        ClockFormat::NTP,
        200,
        64,
        300,
        None,
        TlvHandlingMode::Echo,
        None,
        false,
        &test_ctx(0, 0),
    );

    assert_eq!(
        response.data.len(),
        original_data.len(),
        "reply must not drop the non-aligned trailer bytes"
    );
    // The echoed TLV is still intact at the head of the TLV area.
    assert_eq!(response.data[UNAUTH_BASE_SIZE + 1], 1); // ExtraPadding type
}

#[test]
fn test_stateless_vs_stateful_follow_up_telemetry_reply() {
    use crate::tlv::{FollowUpTelemetryTlv, TlvList, TypedTlv};

    let sender_packet = PacketUnauthenticated {
        sequence_number: 1,
        timestamp: 100,
        error_estimate: 10,
        ssid: 0,
        mbz: [0; 28],
    };
    let mut original_data = sender_packet.to_bytes().to_vec();
    original_data.extend_from_slice(&FollowUpTelemetryTlv::new().to_raw().to_bytes());

    let assemble = |ctx: &ProcessingContext| {
        assemble_unauth_answer_with_tlvs(
            &sender_packet,
            &original_data,
            ClockFormat::NTP,
            200,
            64,
            300,
            None,
            TlvHandlingMode::Echo,
            None,
            false,
            ctx,
        )
    };

    // Stateless mode (RFC 8972 §4.7): the previous reflection is present
    // but MUST NOT be reported; seq/timestamp are zeroed.
    let mut ctx = test_ctx(0, 0);
    ctx.stateful_reflector = false;
    ctx.last_reflection = Some((42, 0xDEAD_BEEF));
    let resp = assemble(&ctx);
    let tlvs = TlvList::parse(&resp.data[UNAUTH_BASE_SIZE..]).unwrap();
    let fut = FollowUpTelemetryTlv::from_raw(&tlvs.non_hmac_tlvs()[0]).unwrap();
    assert_eq!(fut.sequence_number, 0, "stateless: seq must be zero");
    assert_eq!(
        fut.follow_up_timestamp, 0,
        "stateless: timestamp must be zero"
    );

    // Stateful mode (RFC 8972 §4.7): the same reflection IS reported.
    ctx.stateful_reflector = true;
    let resp = assemble(&ctx);
    let tlvs = TlvList::parse(&resp.data[UNAUTH_BASE_SIZE..]).unwrap();
    let fut = FollowUpTelemetryTlv::from_raw(&tlvs.non_hmac_tlvs()[0]).unwrap();
    assert_eq!(fut.sequence_number, 42);
    assert_eq!(fut.follow_up_timestamp, 0xDEAD_BEEF);
}

#[test]
// RFC 8972 §4.8: a configured TLV key protects the reflector's reply
// independently of whether the sender included an HMAC TLV.
// See `TlvList::set_hmac_response`.
fn test_assemble_unauth_with_tlvs_adds_hmac() {
    use crate::tlv::{RawTlv, TlvType, HMAC_TLV_VALUE_SIZE, TLV_HEADER_SIZE};

    let sender_packet = PacketUnauthenticated {
        sequence_number: 1,
        timestamp: 100,
        error_estimate: 10,
        ssid: 0,
        mbz: [0; 28],
    };

    // Create packet with TLV extension (no HMAC)
    let mut original_data = sender_packet.to_bytes().to_vec();
    let tlv = RawTlv::new(TlvType::ExtraPadding, vec![0xDD; 4]);
    original_data.extend_from_slice(&tlv.to_bytes());

    let key = HmacKey::new(vec![0xAB; 32]).unwrap();
    let response = assemble_unauth_answer_with_tlvs(
        &sender_packet,
        &original_data,
        ClockFormat::NTP,
        200,
        64,
        300,
        None,
        TlvHandlingMode::Echo,
        Some(&key),
        false,
        &test_ctx(0, 0),
    );

    // Response should include ExtraPadding + HMAC TLV
    // 44 base + (4 header + 4 value) + (4 header + 16 value)
    assert_eq!(
        response.data.len(),
        44 + TLV_HEADER_SIZE + 4 + TLV_HEADER_SIZE + HMAC_TLV_VALUE_SIZE
    );

    // HMAC TLV should be last (type 8 in byte 1 per RFC 8972)
    let hmac_tlv_start = 44 + TLV_HEADER_SIZE + 4;
    assert_eq!(response.data[hmac_tlv_start + 1], 8);
}

#[test]
/// RFC 8972 §4.8 requires protecting the reflector's authenticated reply
/// TLVs even when the sender omitted its own TLV HMAC.
fn test_assemble_auth_with_tlvs_adds_hmac_even_when_request_has_none() {
    use crate::tlv::{
        ClassOfServiceTlv, RawTlv, TlvType, TypedTlv, HMAC_TLV_VALUE_SIZE, TLV_HEADER_SIZE,
    };

    let sender_packet = PacketAuthenticated {
        sequence_number: 1,
        mbz0: [0; 12],
        timestamp: 100,
        error_estimate: 10,
        ssid: 0,
        mbz1: [0; 68],
        hmac: [0; 16],
    };

    // Request carries a non-HMAC extension TLV but no Type 8.
    let mut original_data = sender_packet.to_bytes().to_vec();
    let cos = ClassOfServiceTlv::new(10, 1).to_raw();
    original_data.extend_from_slice(&cos.to_bytes());
    assert!(
        RawTlv::parse(&original_data[112..])
            .map(|(t, _)| t.tlv_type != TlvType::Hmac)
            .unwrap_or(true),
        "request must not itself carry an HMAC TLV"
    );

    let tlv_key = HmacKey::new(vec![0xCD; 32]).unwrap();
    let response = assemble_auth_answer_with_tlvs(
        &sender_packet,
        &original_data,
        ClockFormat::NTP,
        200,
        64,
        300,
        None,
        None,
        TlvHandlingMode::Echo,
        Some(&tlv_key),
        false,
        &test_ctx(0, 0),
    );

    // 112 base + (4 header + 4 CoS value) + (4 header + 16 HMAC value)
    assert_eq!(
        response.data.len(),
        112 + TLV_HEADER_SIZE + 4 + TLV_HEADER_SIZE + HMAC_TLV_VALUE_SIZE
    );
    let hmac_tlv_start = 112 + TLV_HEADER_SIZE + 4;
    assert_eq!(response.data[hmac_tlv_start + 1], 8); // Type 8 = HMAC
}

#[test]
fn test_verify_incoming_tlv_hmac_no_tlvs() {
    let key = HmacKey::new(vec![0xAB; 32]).unwrap();
    let packet_data = [0u8; 44]; // Just base packet

    assert!(verify_incoming_tlv_hmac(
        &packet_data,
        UNAUTH_BASE_SIZE,
        &key
    ));
}

#[test]
fn test_verify_incoming_tlv_hmac_no_hmac_tlv() {
    use crate::tlv::{RawTlv, TlvType};

    let key = HmacKey::new(vec![0xAB; 32]).unwrap();

    // Create packet with TLV but no HMAC
    let mut packet_data = vec![0u8; 44];
    let tlv = RawTlv::new(TlvType::ExtraPadding, vec![0; 4]);
    packet_data.extend_from_slice(&tlv.to_bytes());

    assert!(verify_incoming_tlv_hmac(
        &packet_data,
        UNAUTH_BASE_SIZE,
        &key
    ));
}

#[test]
fn test_verify_incoming_tlv_hmac_valid() {
    use crate::tlv::{RawTlv, TlvList, TlvType};

    let key = HmacKey::new(vec![0xAB; 32]).unwrap();

    // Create base packet
    let base_packet = vec![0x01u8; 44];

    // Create TLV list with HMAC
    let mut tlvs = TlvList::new();
    tlvs.push(RawTlv::new(TlvType::ExtraPadding, vec![0xCC; 4]))
        .unwrap();
    tlvs.set_hmac(&key, &base_packet);

    // Combine base + TLVs
    let mut packet_data = base_packet.clone();
    packet_data.extend_from_slice(&tlvs.to_bytes());

    assert!(verify_incoming_tlv_hmac(
        &packet_data,
        UNAUTH_BASE_SIZE,
        &key
    ));
}

#[test]
fn test_verify_incoming_tlv_hmac_invalid() {
    use crate::tlv::{RawTlv, TlvList, TlvType};

    let key1 = HmacKey::new(vec![0xAB; 32]).unwrap();
    let key2 = HmacKey::new(vec![0xCD; 32]).unwrap();

    // Create base packet
    let base_packet = vec![0x01u8; 44];

    // Create TLV list with HMAC using key1
    let mut tlvs = TlvList::new();
    tlvs.push(RawTlv::new(TlvType::ExtraPadding, vec![0xCC; 4]))
        .unwrap();
    tlvs.set_hmac(&key1, &base_packet);

    // Combine base + TLVs
    let mut packet_data = base_packet.clone();
    packet_data.extend_from_slice(&tlvs.to_bytes());

    // Verify with wrong key
    assert!(!verify_incoming_tlv_hmac(
        &packet_data,
        UNAUTH_BASE_SIZE,
        &key2
    ));
}

#[test]
fn test_assemble_unauth_with_tlvs_hmac_failure_preserves_original() {
    use crate::tlv::{RawTlv, TlvList, TlvType, TLV_HEADER_SIZE};

    let key1 = HmacKey::new(vec![0xAB; 32]).unwrap();
    let key2 = HmacKey::new(vec![0xCD; 32]).unwrap();

    let sender_packet = PacketUnauthenticated {
        sequence_number: 0x12345678,
        timestamp: 100,
        error_estimate: 10,
        ssid: 0,
        mbz: [0; 28],
    };
    let base_bytes = sender_packet.to_bytes();

    // Create TLV list with HMAC using key1
    let mut tlvs = TlvList::new();
    tlvs.push(RawTlv::new(TlvType::ExtraPadding, vec![0xCC; 4]))
        .unwrap();
    tlvs.set_hmac(&key1, &base_bytes);

    // Save original HMAC value
    let original_hmac = tlvs.hmac_tlv().unwrap().value.clone();

    // Combine base + TLVs
    let mut original_data = base_bytes.to_vec();
    original_data.extend_from_slice(&tlvs.to_bytes());

    // Reflect with verification using wrong key (key2)
    // This should fail HMAC verification and set I-flag on all TLVs
    let response = assemble_unauth_answer_with_tlvs(
        &sender_packet,
        &original_data,
        ClockFormat::NTP,
        200,
        64,
        300,
        None,
        TlvHandlingMode::Echo,
        Some(&key2), // Wrong key for verification
        true,        // Verify HMAC (will fail)
        &test_ctx(0, 0),
    );

    // Response should include TLVs
    // Base (44) + ExtraPadding TLV (4+4) + HMAC TLV (4+16) = 72 bytes
    assert_eq!(
        response.data.len(),
        44 + TLV_HEADER_SIZE + 4 + TLV_HEADER_SIZE + 16
    );

    // Find HMAC TLV in response (last TLV)
    let hmac_tlv_start = 44 + TLV_HEADER_SIZE + 4;

    // Check I-flag is set on HMAC TLV (0x20 in the flags byte)
    let hmac_flags = response.data[hmac_tlv_start];
    assert!(
        hmac_flags & 0x20 != 0,
        "I-flag should be set on HMAC TLV, flags={:02x}",
        hmac_flags
    );

    // Check HMAC value is preserved (NOT regenerated)
    let response_hmac = &response.data[hmac_tlv_start + TLV_HEADER_SIZE..];
    assert_eq!(
        response_hmac,
        &original_hmac[..],
        "HMAC should be preserved on verification failure, not regenerated"
    );
    assert!(
        !response.tlv_hmac_generated,
        "an echoed HMAC must not be re-signed at send time"
    );
}

#[test]
fn test_assemble_unauth_with_tlvs_hmac_success_regenerates() {
    use crate::tlv::{RawTlv, TlvList, TlvType, TLV_HEADER_SIZE};

    let key = HmacKey::new(vec![0xAB; 32]).unwrap();

    let sender_packet = PacketUnauthenticated {
        sequence_number: 0x12345678,
        timestamp: 100,
        error_estimate: 10,
        ssid: 0,
        mbz: [0; 28],
    };
    let base_bytes = sender_packet.to_bytes();

    // Create TLV list with HMAC
    let mut tlvs = TlvList::new();
    tlvs.push(RawTlv::new(TlvType::ExtraPadding, vec![0xCC; 4]))
        .unwrap();
    tlvs.set_hmac(&key, &base_bytes);

    // Save original HMAC value
    let original_hmac = tlvs.hmac_tlv().unwrap().value.clone();

    // Combine base + TLVs
    let mut original_data = base_bytes.to_vec();
    original_data.extend_from_slice(&tlvs.to_bytes());

    // Reflect with verification using correct key and a DIFFERENT reflector seq
    // This should pass HMAC verification and regenerate HMAC for response
    // (HMAC covers sequence number, so different seq = different HMAC)
    let response = assemble_unauth_answer_with_tlvs(
        &sender_packet,
        &original_data,
        ClockFormat::NTP,
        200,
        64,
        300,
        Some(0x87654321), // Different reflector sequence number
        TlvHandlingMode::Echo,
        Some(&key), // Correct key for verification
        true,       // Verify HMAC (will succeed)
        &test_ctx(0, 0),
    );

    // Response should include TLVs
    assert_eq!(
        response.data.len(),
        44 + TLV_HEADER_SIZE + 4 + TLV_HEADER_SIZE + 16
    );

    // Find HMAC TLV in response (last TLV)
    let hmac_tlv_start = 44 + TLV_HEADER_SIZE + 4;

    // Check I-flag is NOT set on HMAC TLV
    let hmac_flags = response.data[hmac_tlv_start];
    assert!(
        hmac_flags & 0x20 == 0,
        "I-flag should NOT be set on successful verification, flags={:02x}",
        hmac_flags
    );

    // Check HMAC value is DIFFERENT (regenerated for new sequence number)
    let response_hmac = &response.data[hmac_tlv_start + TLV_HEADER_SIZE..];
    assert_ne!(
        response_hmac,
        &original_hmac[..],
        "HMAC should be regenerated on successful verification"
    );
    assert!(response.tlv_hmac_generated);
}

#[test]
fn test_assemble_unauth_with_malformed_tlv_sets_mflag() {
    let sender_packet = PacketUnauthenticated {
        sequence_number: 0x12345678,
        timestamp: 100,
        error_estimate: 10,
        ssid: 0,
        mbz: [0; 28],
    };
    let base_bytes = sender_packet.to_bytes();

    // Create a truncated/malformed TLV manually:
    // Header says length is 100 bytes, but only 4 bytes of value are present
    let mut original_data = base_bytes.to_vec();
    original_data.push(0x00); // Flags (no flags set by sender)
    original_data.push(0x01); // Type = ExtraPadding
    original_data.extend_from_slice(&100u16.to_be_bytes()); // Length = 100 (but only 4 available)
    original_data.extend_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD]); // Only 4 bytes of value

    // Reflect the packet
    let response = assemble_unauth_answer_with_tlvs(
        &sender_packet,
        &original_data,
        ClockFormat::NTP,
        200,
        64,
        300,
        None,
        TlvHandlingMode::Echo,
        None,
        false,
        &test_ctx(0, 0),
    );

    // Response should include base + malformed TLV (header + truncated value)
    // The TLV should have whatever data was available
    assert!(response.data.len() > 44, "Response should include TLV data");

    // Check M-flag is set on the TLV (0x40 in the flags byte)
    let tlv_flags = response.data[44];
    assert!(
        tlv_flags & 0x40 != 0,
        "M-flag should be set on malformed TLV, flags={:02x}",
        tlv_flags
    );

    // Type should be preserved
    assert_eq!(response.data[45], 0x01, "TLV type should be preserved");
}

#[test]
fn test_assemble_unauth_with_malformed_tlv_no_hmac_regen() {
    use crate::tlv::TLV_HEADER_SIZE;

    let key = HmacKey::new(vec![0xAB; 32]).unwrap();

    let sender_packet = PacketUnauthenticated {
        sequence_number: 0x12345678,
        timestamp: 100,
        error_estimate: 10,
        ssid: 0,
        mbz: [0; 28],
    };
    let base_bytes = sender_packet.to_bytes();

    // Create a truncated/malformed TLV
    let mut original_data = base_bytes.to_vec();
    original_data.push(0x00); // Flags
    original_data.push(0x01); // Type = ExtraPadding
    original_data.extend_from_slice(&50u16.to_be_bytes()); // Length = 50 (but only 4 available)
    original_data.extend_from_slice(&[0x11, 0x22, 0x33, 0x44]); // Only 4 bytes

    // Reflect with HMAC key - should NOT regenerate HMAC due to malformed TLV
    let response = assemble_unauth_answer_with_tlvs(
        &sender_packet,
        &original_data,
        ClockFormat::NTP,
        200,
        64,
        300,
        None,
        TlvHandlingMode::Echo,
        Some(&key),
        false,
        &test_ctx(0, 0),
    );

    // Response should only have the malformed TLV, no HMAC TLV added
    // (because we don't regenerate HMAC when there are malformed TLVs)
    assert!(response.data.len() > 44);

    // Check M-flag is set
    let tlv_flags = response.data[44];
    assert!(
        tlv_flags & 0x40 != 0,
        "M-flag should be set on malformed TLV"
    );

    // Should NOT have an HMAC TLV appended (response should be relatively short)
    // Base (44) + header (4) + truncated value (4) = 52 bytes
    assert_eq!(
        response.data.len(),
        44 + TLV_HEADER_SIZE + 4,
        "Should not have HMAC TLV when TLVs are malformed"
    );
}

#[test]
fn test_assemble_unauth_with_cos_tlv_updates_dscp_ecn() {
    use crate::tlv::{ClassOfServiceTlv, TlvType, TypedTlv, COS_TLV_VALUE_SIZE, TLV_HEADER_SIZE};

    let sender_packet = PacketUnauthenticated {
        sequence_number: 1,
        timestamp: 100,
        error_estimate: 10,
        ssid: 0,
        mbz: [0; 28],
    };

    // Create packet with CoS TLV (sender requests DSCP=46 EF, ECN=0)
    let mut original_data = sender_packet.to_bytes().to_vec();
    let cos_tlv = ClassOfServiceTlv::new(46, 0);
    original_data.extend_from_slice(&cos_tlv.to_raw().to_bytes());

    // Reflect with received DSCP=10, ECN=2 (simulating network modified values)
    let received_dscp = 10u8;
    let received_ecn = 2u8;
    let response = assemble_unauth_answer_with_tlvs(
        &sender_packet,
        &original_data,
        ClockFormat::NTP,
        200,
        64,
        300,
        None,
        TlvHandlingMode::Echo,
        None,
        false,
        &test_ctx(received_dscp, received_ecn),
    );

    // Response should include base + CoS TLV
    assert_eq!(
        response.data.len(),
        44 + TLV_HEADER_SIZE + COS_TLV_VALUE_SIZE
    );

    // Parse the CoS TLV from response to verify DSCP2/ECN2 were filled in
    let tlv_start = 44;
    assert_eq!(
        response.data[tlv_start + 1],
        TlvType::ClassOfService.to_byte()
    ); // Type

    // Parse the value via the typed decoder (single source of truth for
    // the RFC 8972 + cos-ecn-01 bit layout).
    let value_start = tlv_start + TLV_HEADER_SIZE;
    let raw = crate::tlv::RawTlv::new(
        TlvType::ClassOfService,
        response.data[value_start..value_start + COS_TLV_VALUE_SIZE].to_vec(),
    );
    let parsed = crate::tlv::ClassOfServiceTlv::from_raw(&raw).unwrap();
    assert_eq!(parsed.dscp1, 46, "DSCP1 should be preserved");
    assert_eq!(parsed.ecn1, 0, "EC1 should be preserved");
    assert_eq!(parsed.dscp2, received_dscp, "DSCP2 should be received DSCP");
    assert_eq!(parsed.ecn2, received_ecn, "EC2 should be received ECN");
    assert_eq!(parsed.rpd, 0, "RPD should be 0 (policy accepted)");
    assert_eq!(parsed.rpe, 0b11, "RPE should report reply ECN set to EC1");
}

#[test]
fn test_assemble_auth_with_cos_tlv_updates_dscp_ecn() {
    use crate::tlv::{ClassOfServiceTlv, TlvType, TypedTlv, COS_TLV_VALUE_SIZE, TLV_HEADER_SIZE};

    let sender_packet = PacketAuthenticated {
        sequence_number: 1,
        mbz0: [0; 12],
        timestamp: 100,
        error_estimate: 10,
        ssid: 0,
        mbz1: [0; 68],
        hmac: [0; 16],
    };

    // Create packet with CoS TLV (sender requests DSCP=0 BE, ECN=1)
    let mut original_data = sender_packet.to_bytes().to_vec();
    let cos_tlv = ClassOfServiceTlv::new(0, 1);
    original_data.extend_from_slice(&cos_tlv.to_raw().to_bytes());

    // Reflect with received DSCP=32, ECN=3
    let received_dscp = 32u8;
    let received_ecn = 3u8;
    let response = assemble_auth_answer_with_tlvs(
        &sender_packet,
        &original_data,
        ClockFormat::NTP,
        200,
        64,
        300,
        None,
        None,
        TlvHandlingMode::Echo,
        None,
        false,
        &test_ctx(received_dscp, received_ecn),
    );

    // Response should include base + CoS TLV
    assert_eq!(
        response.data.len(),
        112 + TLV_HEADER_SIZE + COS_TLV_VALUE_SIZE
    );

    // Parse the CoS TLV from response
    let tlv_start = 112;
    assert_eq!(
        response.data[tlv_start + 1],
        TlvType::ClassOfService.to_byte()
    );

    let value_start = tlv_start + TLV_HEADER_SIZE;
    let raw = crate::tlv::RawTlv::new(
        TlvType::ClassOfService,
        response.data[value_start..value_start + COS_TLV_VALUE_SIZE].to_vec(),
    );
    let parsed = crate::tlv::ClassOfServiceTlv::from_raw(&raw).unwrap();
    // DSCP1/EC1 preserved
    assert_eq!(parsed.dscp1, 0);
    assert_eq!(parsed.ecn1, 1);
    // DSCP2/EC2 filled by reflector, RPE reports reply ECN applied
    assert_eq!(parsed.dscp2, received_dscp);
    assert_eq!(parsed.ecn2, received_ecn);
    assert_eq!(parsed.rpe, 0b11);
}

#[test]
fn test_cos_unable_fallback_tos_zeroes_ecn_and_matches_reply_wire_tos() {
    use crate::tlv::ClassOfServiceTlv;

    // draft-ietf-ippm-stamp-cos-ecn-01 §3.2 MUST rule: the fallback TOS
    // the backends apply after a failed setsockopt must have its ECN
    // bits forced to 0b00, and must agree with the "unable" state of
    // `ClassOfServiceTlv::reply_wire_tos` (RPD=0b01, RPE=0b10) so the
    // wire value and the TLV's own fields never disagree.
    for received_dscp in [0u8, 10, 46, 63] {
        let fallback = cos_unable_fallback_tos(received_dscp);
        assert_eq!(fallback & 0x03, 0, "ECN bits must be zero (-01 §3.2)");

        let expected =
            ClassOfServiceTlv::for_response(46, 2, received_dscp, 1, true, false).reply_wire_tos();
        assert_eq!(
            fallback, expected,
            "cos_unable_fallback_tos must match ClassOfServiceTlv::reply_wire_tos"
        );
    }
}

#[test]
fn test_mtu_payload_cap_subtracts_ip_and_udp_headers() {
    // 1500-byte Ethernet MTU: 20 (IPv4) + 8 (UDP) of headers leaves 1472.
    // A 1500-byte payload cap would build a 1528-byte datagram on this link.
    assert_eq!(mtu_payload_cap(1500, false), 1472);
    // IPv6's fixed header is 40 bytes.
    assert_eq!(mtu_payload_cap(1500, true), 1452);
    // The IPv6 minimum link MTU.
    assert_eq!(mtu_payload_cap(1280, true), 1232);
}

#[test]
fn test_mtu_payload_cap_never_exceeds_small_mtu() {
    assert_eq!(mtu_payload_cap(0, false), 0);
    assert_eq!(mtu_payload_cap(68, false), 40);
    assert_eq!(mtu_payload_cap(1, true), 0);
}

#[test]
fn test_mtu_payload_cap_clamps_a_jumbo_mtu_to_u16() {
    // Loopback's 65536 MTU exceeds what the u16 cap field can hold.
    let cap = mtu_payload_cap(65_536, false);
    assert!(cap > 60_000, "a jumbo MTU must not wrap: got {cap}");
}

#[test]
fn test_interface_mtu_rejects_bad_interface_names() {
    // Never panics, and an unknown or unusable name yields None so the
    // caller keeps its configured cap.
    assert_eq!(interface_mtu(""), None);
    assert_eq!(interface_mtu("definitely-not-an-interface"), None);
    assert_eq!(interface_mtu(&"x".repeat(64)), None);
}

#[cfg(target_os = "linux")]
#[test]
fn test_interface_mtu_reads_loopback() {
    // Loopback always exists on Linux. Tolerant of a sandbox that refuses
    // the socket or the ioctl: the point is that a success is sane, not
    // that the environment cooperates.
    if let Some(mtu) = interface_mtu("lo") {
        assert!(mtu >= 1500, "loopback MTU looks wrong: {mtu}");
    }
}

#[test]
fn test_evaluate_replay_counts_duplicates_and_reorders() {
    use crate::session::{ReplayVerdict, Session};

    let session = Session::new(1);
    let counters = ReflectorCounters::new();
    let packet = |seq: u32| {
        let mut buf = vec![0u8; 44];
        buf[0..4].copy_from_slice(&seq.to_be_bytes());
        buf
    };
    // Classify-then-commit, the way a backend treats a packet that
    // passed verification and was answered.
    let eval_commit = |data: &[u8]| {
        let verdict = evaluate_replay(&session, data, &counters);
        commit_replay(&session, data);
        verdict
    };

    // In-order traffic is silent.
    assert_eq!(eval_commit(&packet(1)), ReplayVerdict::New);
    assert_eq!(eval_commit(&packet(2)), ReplayVerdict::New);
    assert_eq!(counters.packets_replayed.load(Ordering::Relaxed), 0);
    assert_eq!(counters.packets_reordered.load(Ordering::Relaxed), 0);

    // A duplicate is counted as a replay.
    assert_eq!(eval_commit(&packet(2)), ReplayVerdict::Replay);
    assert_eq!(counters.packets_replayed.load(Ordering::Relaxed), 1);

    // A late-but-unseen packet is counted separately: reordering is
    // ordinary and must not be reported as an attack.
    assert_eq!(
        eval_commit(&packet(1) /* already seen */),
        ReplayVerdict::Replay
    );
    assert_eq!(counters.packets_replayed.load(Ordering::Relaxed), 2);
    assert_eq!(
        counters.packets_reordered.load(Ordering::Relaxed),
        0,
        "a seen sequence number is a replay, not a reorder"
    );

    // Jump ahead, then deliver a gap-filler late: unseen and behind the
    // high-water mark, so it lands on the reorder counter, not the replay
    // one.
    assert_eq!(eval_commit(&packet(10)), ReplayVerdict::New);
    assert_eq!(eval_commit(&packet(8)), ReplayVerdict::Reordered);
    assert_eq!(counters.packets_reordered.load(Ordering::Relaxed), 1);
    assert_eq!(
        counters.packets_replayed.load(Ordering::Relaxed),
        2,
        "reordering must not inflate the replay count"
    );

    // A packet older than the window is counted with the reorders: the
    // window cannot claim it was seen. Advance far enough first that the
    // "older than the window" sequence number is still positive.
    assert_eq!(eval_commit(&packet(1000)), ReplayVerdict::New);
    assert_eq!(
        eval_commit(&packet(1000 - crate::session::REPLAY_WINDOW - 1)),
        ReplayVerdict::OutOfWindow
    );
    assert_eq!(counters.packets_reordered.load(Ordering::Relaxed), 2);
}

#[test]
fn test_evaluate_replay_reads_sequence_from_both_layouts() {
    use crate::session::{ReplayVerdict, Session};

    // The Sequence Number is the first four octets in both the
    // authenticated (112-byte) and unauthenticated (44-byte) base layouts,
    // so one extraction serves both.
    for base_len in [UNAUTH_BASE_SIZE, AUTH_BASE_SIZE] {
        let session = Session::new(1);
        let counters = ReflectorCounters::new();
        let mut buf = vec![0u8; base_len];
        buf[0..4].copy_from_slice(&99u32.to_be_bytes());
        assert_eq!(
            evaluate_replay(&session, &buf, &counters),
            ReplayVerdict::New
        );
        commit_replay(&session, &buf);
        assert_eq!(
            evaluate_replay(&session, &buf, &counters),
            ReplayVerdict::Replay,
            "sequence number must be read identically at base length {base_len}"
        );
    }
}

/// An unverified packet (classified but never committed, e.g. bad HMAC)
/// must not poison the anti-replay window: the genuine packet carrying
/// the same sequence number is still `New`.
#[test]
fn test_replay_window_only_advances_on_commit() {
    use crate::session::{ReplayVerdict, Session};

    let session = Session::new(1);
    let counters = ReflectorCounters::new();
    let packet = |seq: u32| {
        let mut buf = vec![0u8; 44];
        buf[0..4].copy_from_slice(&seq.to_be_bytes());
        buf
    };

    // Attacker spoofs a predicted future sequence number; the packet
    // fails verification, so the backend never commits it.
    assert_eq!(
        evaluate_replay(&session, &packet(7), &counters),
        ReplayVerdict::New
    );
    // The genuine packet with that sequence number must still be New;
    // under --drop-replayed it would otherwise be dropped.
    assert_eq!(
        evaluate_replay(&session, &packet(7), &counters),
        ReplayVerdict::New
    );
    commit_replay(&session, &packet(7));
    // Only a committed (verified, answered) packet makes it a replay.
    assert_eq!(
        evaluate_replay(&session, &packet(7), &counters),
        ReplayVerdict::Replay
    );
}

#[test]
fn test_evaluate_replay_tolerates_a_runt_packet() {
    use crate::session::{ReplayVerdict, Session};

    // Shorter than a Sequence Number: nothing to classify, and the
    // base-length rules handle it downstream. Must not panic.
    let session = Session::new(1);
    let counters = ReflectorCounters::new();
    for len in 0..4usize {
        assert_eq!(
            evaluate_replay(&session, &vec![0u8; len], &counters),
            ReplayVerdict::New
        );
    }
    assert_eq!(counters.packets_replayed.load(Ordering::Relaxed), 0);
}

/// CoS TLV bytes as the reflector emits them after processing (U=0).
fn reflected_bytes(cos: &crate::tlv::ClassOfServiceTlv) -> Vec<u8> {
    let mut raw = cos.to_raw();
    raw.clear_reflector_flags();
    raw.to_bytes()
}

#[test]
fn test_set_cos_policy_rejected_unauth() {
    use crate::tlv::ClassOfServiceTlv;

    // Build an unauthenticated response with a CoS TLV
    let sender_packet = PacketUnauthenticated {
        sequence_number: 42,
        timestamp: 100,
        error_estimate: 10,
        ssid: 0,
        mbz: [0; 28],
    };
    let mut original_data = sender_packet.to_bytes().to_vec();
    let cos_tlv = ClassOfServiceTlv::new(46, 2); // DSCP=46, ECN=2
    original_data.extend_from_slice(&reflected_bytes(&cos_tlv));

    let mut response = assemble_unauth_answer_with_tlvs(
        &sender_packet,
        &original_data,
        ClockFormat::NTP,
        200,
        64,
        300,
        None,
        TlvHandlingMode::Echo,
        None,
        false,
        &test_ctx(0, 0),
    );

    // Verify RPD (value byte 1, bits 1:0) is initially 0
    let value_start = UNAUTH_BASE_SIZE + TLV_HEADER_SIZE;
    assert_eq!(response.data[value_start + 1] & 0x03, 0);

    // Simulate DSCP application failure by calling set_cos_policy_rejected
    let updated = set_cos_policy_rejected(&mut response.data, UNAUTH_BASE_SIZE);
    assert!(updated);

    // RPD=0b01 (DSCP1 not used) and RPE=0b10 (unable to set reply ECN)
    assert_eq!(response.data[value_start + 1] & 0x03, 0b01);
    assert_eq!((response.data[value_start + 2] >> 4) & 0x03, 0b10);
}

#[test]
fn test_set_cos_policy_rejected_auth() {
    use crate::tlv::ClassOfServiceTlv;

    // Build an authenticated response with a CoS TLV
    let sender_packet = PacketAuthenticated {
        sequence_number: 42,
        mbz0: [0; 12],
        timestamp: 100,
        error_estimate: 10,
        ssid: 0,
        mbz1: [0; 68],
        hmac: [0; 16],
    };
    let mut original_data = sender_packet.to_bytes().to_vec();
    let cos_tlv = ClassOfServiceTlv::new(46, 2);
    original_data.extend_from_slice(&reflected_bytes(&cos_tlv));

    let mut response = assemble_auth_answer_with_tlvs(
        &sender_packet,
        &original_data,
        ClockFormat::NTP,
        200,
        64,
        300,
        None,
        None,
        TlvHandlingMode::Echo,
        None,
        false,
        &test_ctx(0, 0),
    );

    // Verify RPD (value byte 1, bits 1:0) is initially 0
    let value_start = AUTH_BASE_SIZE + TLV_HEADER_SIZE;
    assert_eq!(response.data[value_start + 1] & 0x03, 0);

    // Simulate DSCP application failure
    let updated = set_cos_policy_rejected(&mut response.data, AUTH_BASE_SIZE);
    assert!(updated);

    // RPD=0b01 (DSCP1 not used) and RPE=0b10 (unable to set reply ECN)
    assert_eq!(response.data[value_start + 1] & 0x03, 0b01);
    assert_eq!((response.data[value_start + 2] >> 4) & 0x03, 0b10);
}

#[test]
fn test_set_cos_policy_rejected_no_cos_tlv() {
    // Build a response without a CoS TLV
    let sender_packet = PacketUnauthenticated {
        sequence_number: 42,
        timestamp: 100,
        error_estimate: 10,
        ssid: 0,
        mbz: [0; 28],
    };
    let mut response = sender_packet.to_bytes().to_vec();

    // Should return false when no CoS TLV is present
    let updated = set_cos_policy_rejected(&mut response, UNAUTH_BASE_SIZE);
    assert!(!updated);
}

#[test]
fn test_set_cos_policy_rejected_reserved_tlv_before_cos() {
    use crate::tlv::ClassOfServiceTlv;

    // Build a response with a zero-length Reserved TLV (header 00 00 00 00)
    // followed by a CoS TLV. The Reserved TLV must not be mistaken for padding.
    let sender_packet = PacketUnauthenticated {
        sequence_number: 42,
        timestamp: 100,
        error_estimate: 10,
        ssid: 0,
        mbz: [0; 28],
    };
    let mut response = sender_packet.to_bytes().to_vec();

    // Add Reserved TLV with zero length: flags=0, type=0, length=0
    response.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);

    // Add CoS TLV after the Reserved TLV
    let cos_tlv = ClassOfServiceTlv::new(46, 2); // DSCP=46, ECN=2
    response.extend_from_slice(&reflected_bytes(&cos_tlv));

    // Verify RPD (value byte 1, bits 1:0) is initially 0
    // Skip the Reserved TLV and the CoS header.
    let cos_value_start = UNAUTH_BASE_SIZE + TLV_HEADER_SIZE + TLV_HEADER_SIZE;
    assert_eq!(response[cos_value_start + 1] & 0x03, 0);

    // The Reserved TLV (00 00 00 00) should NOT stop iteration because
    // it's followed by non-zero data (the CoS TLV).
    let updated = set_cos_policy_rejected(&mut response, UNAUTH_BASE_SIZE);
    assert!(updated, "Should find CoS TLV after Reserved TLV");

    // RPD=0b01 (DSCP1 not used) and RPE=0b10 (unable to set reply ECN)
    assert_eq!(response[cos_value_start + 1] & 0x03, 0b01);
    assert_eq!((response[cos_value_start + 2] >> 4) & 0x03, 0b10);
}

// ===== RFC 9503 Integration Tests =====

#[test]
fn test_unauth_dest_node_addr_match() {
    use crate::tlv::{DestinationNodeAddressTlv, TypedTlv};

    let sender_packet = PacketUnauthenticated {
        sequence_number: 1,
        timestamp: 100,
        error_estimate: 10,
        ssid: 0,
        mbz: [0; 28],
    };

    let addr: std::net::IpAddr = "192.168.1.1".parse().unwrap();
    let dna_tlv = DestinationNodeAddressTlv::new(addr);

    let mut original_data = sender_packet.to_bytes().to_vec();
    original_data.extend_from_slice(&dna_tlv.to_raw().to_bytes());

    let local_addrs = vec![addr];
    let mut ctx = test_ctx(0, 0);
    ctx.local_addresses = &local_addrs;

    let response = assemble_unauth_answer_with_tlvs(
        &sender_packet,
        &original_data,
        ClockFormat::NTP,
        200,
        64,
        300,
        None,
        TlvHandlingMode::Echo,
        None,
        false,
        &ctx,
    );

    // Check TLV is echoed without U-flag (flags byte at offset 44 = 0x00)
    assert_eq!(response.data[UNAUTH_BASE_SIZE] & 0x80, 0x00);
    assert_eq!(response.return_path_action, ReturnPathAction::Normal);
}

#[test]
fn test_unauth_dest_node_addr_mismatch() {
    use crate::tlv::{DestinationNodeAddressTlv, TypedTlv};

    let sender_packet = PacketUnauthenticated {
        sequence_number: 1,
        timestamp: 100,
        error_estimate: 10,
        ssid: 0,
        mbz: [0; 28],
    };

    let addr: std::net::IpAddr = "192.168.1.1".parse().unwrap();
    let dna_tlv = DestinationNodeAddressTlv::new(addr);

    let mut original_data = sender_packet.to_bytes().to_vec();
    original_data.extend_from_slice(&dna_tlv.to_raw().to_bytes());

    let local_addrs: Vec<std::net::IpAddr> = vec!["10.0.0.1".parse().unwrap()];
    let mut ctx = test_ctx(0, 0);
    ctx.local_addresses = &local_addrs;

    let response = assemble_unauth_answer_with_tlvs(
        &sender_packet,
        &original_data,
        ClockFormat::NTP,
        200,
        64,
        300,
        None,
        TlvHandlingMode::Echo,
        None,
        false,
        &ctx,
    );

    // Check TLV is echoed WITH U-flag set (flags byte bit 7)
    assert_eq!(response.data[UNAUTH_BASE_SIZE] & 0x80, 0x80);
}

// ===== L2 Address Group sub-TLV unit tests =====
// RFC 10052 §3.1.1: bitwise AND the Mask
// field against each local MAC and compare to the Group field; any
// match means "continue processing", no match means "drop".

#[test]
fn l2_group_matches_any_local_exact_match() {
    let mask = [0xFFu8; 6];
    let group = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
    let locals = [[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]];
    assert!(l2_group_matches_any_local(&mask, &group, &locals));
}

#[test]
fn l2_group_matches_any_local_masked_match() {
    // Only the first 3 octets (the OUI) are compared; the low 3 octets
    // of the local MAC differ from the group's low 3 octets but are
    // masked out, so this must still match.
    let mask = [0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00];
    let group = [0x00, 0x11, 0x22, 0x00, 0x00, 0x00];
    let locals = [[0x00, 0x11, 0x22, 0x99, 0x88, 0x77]];
    assert!(l2_group_matches_any_local(&mask, &group, &locals));
}

#[test]
fn l2_group_matches_any_local_no_match() {
    let mask = [0xFFu8; 6];
    let group = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
    let locals = [[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]];
    assert!(!l2_group_matches_any_local(&mask, &group, &locals));
}

#[test]
fn l2_group_matches_any_local_length_mismatch_never_matches() {
    // A 2-byte or 8-byte mask/group (Sub-TLV Length 4 or 16) can never
    // match a 6-byte EUI-48 local MAC: "with the same length" in the
    // RFC 10052 §3.1.1 text excludes them by construction.
    let locals = [[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]];
    assert!(!l2_group_matches_any_local(&[0xFF; 2], &[0x00; 2], &locals));
    assert!(!l2_group_matches_any_local(&[0xFF; 8], &[0x00; 8], &locals));
}

#[test]
fn l2_group_matches_any_local_short_group_never_matches() {
    // Reject unequal Mask/Group lengths before indexing, even though the
    // wire parser already checks them.
    let locals = [[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]];
    assert!(!l2_group_matches_any_local(&[0xFF; 6], &[0x00; 3], &locals));
    assert!(!l2_group_matches_any_local(&[0xFF; 6], &[], &locals));
}

#[test]
fn l2_group_matches_any_local_empty_locals_never_matches() {
    // Empty `locals` (enumeration failed / no interfaces) ⇒ no match ⇒
    // drop, consistent with the L3 path's treatment of empty locals.
    let mask = [0xFFu8; 6];
    let group = [0x00u8; 6];
    assert!(!l2_group_matches_any_local(&mask, &group, &[]));
}

#[test]
fn l2_group_matches_any_local_any_of_multiple_locals() {
    let mask = [0xFFu8; 6];
    let group = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
    let locals = [
        [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF],
        [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
    ];
    assert!(l2_group_matches_any_local(&mask, &group, &locals));
}

/// Skip L2 Address Group sub-TLVs with lengths other than 4, 12, or 16
/// (RFC 10052 §3.1.1). They do not enter matching.
#[test]
fn parse_reflected_control_sub_tlvs_l2_valid_lengths_produce_entries() {
    for len in [4usize, 12, 16] {
        let mut body = Vec::new();
        body.extend_from_slice(&[0u8, REFLECTED_CONTROL_SUBTLV_L2_GROUP]);
        body.extend_from_slice(&(len as u16).to_be_bytes());
        body.extend(std::iter::repeat_n(0xAAu8, len));

        let parsed = parse_reflected_control_sub_tlvs(&body);
        assert_eq!(
            parsed.len(),
            1,
            "valid Sub-TLV Length {len} must parse to one L2Group entry"
        );
        match &parsed[0] {
            ReflectedControlSubTlv::L2Group { mask, group } => {
                assert_eq!(mask.len(), len / 2);
                assert_eq!(group.len(), len / 2);
            }
            other => panic!("expected L2Group, got {other:?}"),
        }
    }
}

#[test]
fn parse_reflected_control_sub_tlvs_l2_malformed_length_is_skipped() {
    for len in [0usize, 2, 6, 8, 10, 20] {
        let mut body = Vec::new();
        body.extend_from_slice(&[0u8, REFLECTED_CONTROL_SUBTLV_L2_GROUP]);
        body.extend_from_slice(&(len as u16).to_be_bytes());
        body.extend(std::iter::repeat_n(0xAAu8, len));

        let parsed = parse_reflected_control_sub_tlvs(&body);
        assert!(
            parsed.is_empty(),
            "malformed Sub-TLV Length {len} must be skipped, not produce an entry"
        );
    }
}

#[test]
fn test_unauth_return_path_suppress() {
    use crate::tlv::ReturnPathTlv;

    let sender_packet = PacketUnauthenticated {
        sequence_number: 1,
        timestamp: 100,
        error_estimate: 10,
        ssid: 0,
        mbz: [0; 28],
    };

    let rp_tlv = ReturnPathTlv::with_control_code(0x0);

    let mut original_data = sender_packet.to_bytes().to_vec();
    original_data.extend_from_slice(&rp_tlv.to_raw().to_bytes());

    let ctx = test_ctx(0, 0);

    let response = assemble_unauth_answer_with_tlvs(
        &sender_packet,
        &original_data,
        ClockFormat::NTP,
        200,
        64,
        300,
        None,
        TlvHandlingMode::Echo,
        None,
        false,
        &ctx,
    );

    assert_eq!(response.return_path_action, ReturnPathAction::SuppressReply);
}

#[test]
fn test_unauth_return_path_alternate_addr() {
    use crate::tlv::ReturnPathTlv;

    let sender_packet = PacketUnauthenticated {
        sequence_number: 1,
        timestamp: 100,
        error_estimate: 10,
        ssid: 0,
        mbz: [0; 28],
    };

    let alt_addr: std::net::IpAddr = "10.0.0.5".parse().unwrap();
    let rp_tlv = ReturnPathTlv::with_return_address(alt_addr);

    let mut original_data = sender_packet.to_bytes().to_vec();
    original_data.extend_from_slice(&rp_tlv.to_raw().to_bytes());

    let mut ctx = test_ctx(0, 0);
    ctx.sender_port = 12345;
    // Opt in to alternate-address replies for this test.
    ctx.return_path_allow_alternate = true;

    let response = assemble_unauth_answer_with_tlvs(
        &sender_packet,
        &original_data,
        ClockFormat::NTP,
        200,
        64,
        300,
        None,
        TlvHandlingMode::Echo,
        None,
        false,
        &ctx,
    );

    assert_eq!(
        response.return_path_action,
        ReturnPathAction::AlternateAddress(std::net::SocketAddr::new(alt_addr, 12345))
    );
}

#[test]
fn test_unauth_return_path_alternate_addr_denied_by_default() {
    // Security: with return_path_allow_alternate = false (the default),
    // a Return Address sub-TLV must NOT redirect the reply; otherwise an
    // unauthenticated peer could aim the reflector's reply at a third party.
    use crate::tlv::ReturnPathTlv;

    let sender_packet = PacketUnauthenticated {
        sequence_number: 1,
        timestamp: 100,
        error_estimate: 10,
        ssid: 0,
        mbz: [0; 28],
    };

    let alt_addr: std::net::IpAddr = "10.0.0.5".parse().unwrap();
    let rp_tlv = ReturnPathTlv::with_return_address(alt_addr);

    let mut original_data = sender_packet.to_bytes().to_vec();
    original_data.extend_from_slice(&rp_tlv.to_raw().to_bytes());

    let mut ctx = test_ctx(0, 0);
    ctx.sender_port = 12345;
    // return_path_allow_alternate defaults to false in test_ctx.

    let response = assemble_unauth_answer_with_tlvs(
        &sender_packet,
        &original_data,
        ClockFormat::NTP,
        200,
        64,
        300,
        None,
        TlvHandlingMode::Echo,
        None,
        false,
        &ctx,
    );

    // No redirection: reply goes to the packet source (Normal).
    assert_eq!(response.return_path_action, ReturnPathAction::Normal);
}

/// The CoS admission policy is scoped to where the reply actually goes:
/// when an honoured Return Address redirects the reply, a
/// destination-scoped rule for the alternate address must win over the
/// (more permissive) treatment the original source would get.
#[test]
fn test_cos_policy_evaluated_against_alternate_return_address() {
    use crate::{
        cos_policy::{CosAdmissionPolicy, DscpSet, EcnSet},
        tlv::{ClassOfServiceTlv, ReturnPathTlv, TypedTlv},
    };

    let sender_packet = PacketUnauthenticated {
        sequence_number: 1,
        timestamp: 100,
        error_estimate: 10,
        ssid: 0,
        mbz: [0; 28],
    };

    let alt_addr: std::net::IpAddr = "10.0.0.5".parse().unwrap();
    let mut original_data = sender_packet.to_bytes().to_vec();
    original_data.extend_from_slice(
        &ReturnPathTlv::with_return_address(alt_addr)
            .to_raw()
            .to_bytes(),
    );
    original_data.extend_from_slice(&ClassOfServiceTlv::new(46, 0).to_raw().to_bytes());

    // Globally DSCP 46 is fine, but nothing may carry it toward 10/8.
    let policy: &'static CosAdmissionPolicy = Box::leak(Box::new(CosAdmissionPolicy::new(
        DscpSet::all(),
        EcnSet::all(),
        vec![("10.0.0.0".parse().unwrap(), 8, DscpSet::none())],
    )));

    let mut ctx = test_ctx(0, 0);
    ctx.sender_port = 12345;
    ctx.return_path_allow_alternate = true;
    ctx.cos_policy = policy;

    let response = assemble_unauth_answer_with_tlvs(
        &sender_packet,
        &original_data,
        ClockFormat::NTP,
        200,
        64,
        300,
        None,
        TlvHandlingMode::Echo,
        None,
        false,
        &ctx,
    );

    assert_eq!(
        response.return_path_action,
        ReturnPathAction::AlternateAddress(std::net::SocketAddr::new(alt_addr, 12345))
    );
    assert_eq!(
        response.cos_request,
        Some((0, 0)),
        "DSCP 46 is forbidden toward 10/8, so the reply must fall back to \
             the received DSCP even though the original source would permit it"
    );

    // Control case: the same packet without the alternate honoured is
    // evaluated against the original source and keeps DSCP 46.
    let mut ctx = test_ctx(0, 0);
    ctx.sender_port = 12345;
    ctx.cos_policy = policy; // allow_alternate stays false
    let response = assemble_unauth_answer_with_tlvs(
        &sender_packet,
        &original_data,
        ClockFormat::NTP,
        200,
        64,
        300,
        None,
        TlvHandlingMode::Echo,
        None,
        false,
        &ctx,
    );
    assert_eq!(response.return_path_action, ReturnPathAction::Normal);
    assert_eq!(response.cos_request, Some((46, 0)));
}

#[test]
fn test_unauth_return_path_sr_unsupported() {
    use crate::tlv::ReturnPathTlv;

    let sender_packet = PacketUnauthenticated {
        sequence_number: 1,
        timestamp: 100,
        error_estimate: 10,
        ssid: 0,
        mbz: [0; 28],
    };

    let rp_tlv = ReturnPathTlv::with_sr_mpls_labels(&[100, 200]);

    let mut original_data = sender_packet.to_bytes().to_vec();
    original_data.extend_from_slice(&rp_tlv.to_raw().to_bytes());

    let ctx = test_ctx(0, 0);

    let response = assemble_unauth_answer_with_tlvs(
        &sender_packet,
        &original_data,
        ClockFormat::NTP,
        200,
        64,
        300,
        None,
        TlvHandlingMode::Echo,
        None,
        false,
        &ctx,
    );

    assert_eq!(response.return_path_action, ReturnPathAction::UnsupportedSr);
    // Return Path TLV should have U-flag set
    assert_eq!(response.data[UNAUTH_BASE_SIZE] & 0x80, 0x80);
}

#[test]
fn test_set_return_path_u_flag_in_response() {
    use crate::tlv::ReturnPathTlv;

    let sender_packet = PacketUnauthenticated {
        sequence_number: 1,
        timestamp: 100,
        error_estimate: 10,
        ssid: 0,
        mbz: [0; 28],
    };

    let rp_tlv = ReturnPathTlv::with_return_address("10.0.0.5".parse().unwrap());

    let mut raw = rp_tlv.to_raw();
    // Simulate post-clear state (apply_reflector_flags has already run);
    // sender default is U=1 per RFC 8972 §4, but the U-flag toggle
    // tested here is the send-path "set after clear" path.
    raw.clear_reflector_flags();
    let mut data = sender_packet.to_bytes().to_vec();
    data.extend_from_slice(&raw.to_bytes());

    assert_eq!(data[UNAUTH_BASE_SIZE] & 0x80, 0);

    let updated = set_return_path_u_flag_in_response(&mut data, UNAUTH_BASE_SIZE);
    assert!(updated);
    assert_eq!(data[UNAUTH_BASE_SIZE] & 0x80, 0x80);
}

#[test]
fn test_set_return_path_u_flag_no_return_path_tlv() {
    let sender_packet = PacketUnauthenticated {
        sequence_number: 1,
        timestamp: 100,
        error_estimate: 10,
        ssid: 0,
        mbz: [0; 28],
    };

    let mut data = sender_packet.to_bytes().to_vec();

    let updated = set_return_path_u_flag_in_response(&mut data, UNAUTH_BASE_SIZE);
    assert!(!updated);
}

// ===== RFC 9534 Micro-session ID TLV Receiver Tests =====

#[test]
fn test_unauth_with_micro_session_id_fills_reflector_id() {
    use crate::tlv::{MicroSessionIdTlv, TypedTlv};

    let sender_packet = PacketUnauthenticated {
        sequence_number: 1,
        timestamp: 100,
        error_estimate: 10,
        ssid: 0,
        mbz: [0; 28],
    };

    // Build packet with Micro-session ID TLV (sender_id=42, reflector_id=0)
    let msid_raw = MicroSessionIdTlv::new(42, 0).to_raw();
    let mut data = sender_packet.to_bytes().to_vec();
    data.extend_from_slice(&msid_raw.to_bytes());

    let mut ctx = test_ctx(0, 0);
    ctx.reflector_member_link_id = Some(99);

    let response = assemble_unauth_answer_with_tlvs(
        &sender_packet,
        &data,
        ClockFormat::NTP,
        500,
        64,
        0,
        None,
        TlvHandlingMode::Echo,
        None,
        false,
        &ctx,
    );

    // Should not suppress reply
    assert!(!matches!(
        response.return_path_action,
        ReturnPathAction::SuppressReply
    ));

    // Parse TLVs from response to check reflector ID was filled in
    let tlv_data = &response.data[UNAUTH_BASE_SIZE..];
    let tlvs = TlvList::parse(tlv_data).unwrap();
    let msid_tlv = &tlvs.non_hmac_tlvs()[0];
    let parsed = MicroSessionIdTlv::from_raw(msid_tlv).unwrap();
    assert_eq!(parsed.sender_micro_session_id, 42);
    assert_eq!(parsed.reflector_micro_session_id, 99);
}

#[test]
fn test_unauth_with_micro_session_id_mismatch_discards() {
    use crate::tlv::{MicroSessionIdTlv, TypedTlv};

    let sender_packet = PacketUnauthenticated {
        sequence_number: 1,
        timestamp: 100,
        error_estimate: 10,
        ssid: 0,
        mbz: [0; 28],
    };

    // Build packet with Micro-session ID TLV (sender_id=42, reflector_id=50: mismatch)
    let msid_raw = MicroSessionIdTlv::new(42, 50).to_raw();
    let mut data = sender_packet.to_bytes().to_vec();
    data.extend_from_slice(&msid_raw.to_bytes());

    let mut ctx = test_ctx(0, 0);
    ctx.reflector_member_link_id = Some(99);

    let response = assemble_unauth_answer_with_tlvs(
        &sender_packet,
        &data,
        ClockFormat::NTP,
        500,
        64,
        0,
        None,
        TlvHandlingMode::Echo,
        None,
        false,
        &ctx,
    );

    // Should suppress reply (discard) due to reflector ID mismatch
    assert!(matches!(
        response.return_path_action,
        ReturnPathAction::SuppressReply
    ));
}

#[test]
fn test_auth_with_micro_session_id_fills_reflector_id() {
    use crate::tlv::{MicroSessionIdTlv, TypedTlv};

    let sender_packet = PacketAuthenticated {
        sequence_number: 1,
        mbz0: [0; 12],
        timestamp: 100,
        error_estimate: 10,
        ssid: 0,
        mbz1: [0; 68],
        hmac: [0; 16],
    };

    let msid_raw = MicroSessionIdTlv::new(42, 0).to_raw();
    let mut data = sender_packet.to_bytes().to_vec();
    data.extend_from_slice(&msid_raw.to_bytes());

    let mut ctx = test_ctx(0, 0);
    ctx.reflector_member_link_id = Some(99);

    let response = assemble_auth_answer_with_tlvs(
        &sender_packet,
        &data,
        ClockFormat::NTP,
        500,
        64,
        0,
        None,
        None,
        TlvHandlingMode::Echo,
        None,
        false,
        &ctx,
    );

    assert!(!matches!(
        response.return_path_action,
        ReturnPathAction::SuppressReply
    ));

    let tlv_data = &response.data[AUTH_BASE_SIZE..];
    let tlvs = TlvList::parse(tlv_data).unwrap();
    let msid_tlv = &tlvs.non_hmac_tlvs()[0];
    let parsed = MicroSessionIdTlv::from_raw(msid_tlv).unwrap();
    assert_eq!(parsed.sender_micro_session_id, 42);
    assert_eq!(parsed.reflector_micro_session_id, 99);
}

#[test]
fn test_auth_with_micro_session_id_mismatch_discards() {
    use crate::tlv::{MicroSessionIdTlv, TypedTlv};

    let sender_packet = PacketAuthenticated {
        sequence_number: 1,
        mbz0: [0; 12],
        timestamp: 100,
        error_estimate: 10,
        ssid: 0,
        mbz1: [0; 68],
        hmac: [0; 16],
    };

    let msid_raw = MicroSessionIdTlv::new(42, 50).to_raw();
    let mut data = sender_packet.to_bytes().to_vec();
    data.extend_from_slice(&msid_raw.to_bytes());

    let mut ctx = test_ctx(0, 0);
    ctx.reflector_member_link_id = Some(99);

    let response = assemble_auth_answer_with_tlvs(
        &sender_packet,
        &data,
        ClockFormat::NTP,
        500,
        64,
        0,
        None,
        None,
        TlvHandlingMode::Echo,
        None,
        false,
        &ctx,
    );

    assert!(matches!(
        response.return_path_action,
        ReturnPathAction::SuppressReply
    ));
}

// Strict versus lenient packet parsing (RFC 8762 §4.6).
// Lenient mode zero-fills short TWAMP-Light packets; `--strict-packets`
// requires the full wire layout.

fn loopback_src() -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 12345)
}

/// Full-size unauthenticated packet: both modes accept.
#[test]
fn strict_packets_unauth_full_size_both_modes_accept() {
    let packet = PacketUnauthenticated {
        sequence_number: 7,
        timestamp: 100,
        error_estimate: 10,
        ssid: 0,
        mbz: [0; 28],
    };
    let data = packet.to_bytes();

    for strict in [false, true] {
        let mut ctx = test_ctx(0, 0);
        ctx.strict_packets = strict;
        let r = process_stamp_packet(&data, loopback_src(), 64, false, &ctx);
        assert!(r.is_some(), "strict={strict} must accept full-size packet");
    }
}

/// An authenticated packet must be dropped by an open-mode reflector.
/// Its MBZ bytes would produce a zero Error Estimate (RFC 8762 §4.2)
/// and spurious zero-type TLVs under the unauthenticated layout.
#[test]
fn open_mode_reflector_drops_authenticated_shaped_packet() {
    let auth = PacketAuthenticated {
        sequence_number: 0x22,
        mbz0: [0; 12],
        timestamp: 0xEE26_C5EE_6734_968E,
        error_estimate: 0x0001,
        ssid: 0,
        mbz1: [0; 68],
        hmac: [0xAB; 16],
    };
    let data = auth.to_bytes();
    assert_eq!(data.len(), AUTH_BASE_SIZE);
    let ctx = test_ctx(0, 0);

    // Open mode (use_auth = false): dropped.
    assert!(
        process_stamp_packet(&data, loopback_src(), 64, false, &ctx).is_none(),
        "an authenticated-shaped packet must not be reflected in open mode"
    );

    // The same bytes in authenticated mode are handled by the auth path and
    // are not caught by the guard (no key configured here, so the reply is
    // gated by the auth rules rather than this shape test).
    let _ = process_stamp_packet(&data, loopback_src(), 64, true, &ctx);
}

/// The guard is a shape test, so it must not touch ordinary traffic: a
/// genuine unauthenticated packet long enough to reach the authenticated
/// base size (44-octet base plus TLVs) still carries a real timestamp in
/// octets 4..12 and is reflected normally.
#[test]
fn open_mode_guard_ignores_long_unauthenticated_packets() {
    let packet = PacketUnauthenticated {
        sequence_number: 7,
        timestamp: 0xEE26_C5EE_6734_968E,
        error_estimate: 0x0001,
        ssid: 0,
        mbz: [0; 28],
    };
    let mut data = packet.to_bytes().to_vec();
    // Pad past AUTH_BASE_SIZE with an Extra Padding TLV so length alone
    // cannot be what distinguishes the two cases.
    data.extend_from_slice(&[0x00, 0x01]);
    data.extend_from_slice(&80u16.to_be_bytes());
    data.extend_from_slice(&[0u8; 80]);
    assert!(data.len() > AUTH_BASE_SIZE);

    let ctx = test_ctx(0, 0);
    assert!(
        process_stamp_packet(&data, loopback_src(), 64, false, &ctx).is_some(),
        "a long unauthenticated packet must still be reflected"
    );
}

/// Short unauthenticated packet (40 bytes < 44). Lenient zero-fills and
/// accepts; strict rejects without panicking.
#[test]
fn strict_packets_unauth_short_rejected_only_in_strict() {
    let data = [0u8; 40];

    let mut ctx_lenient = test_ctx(0, 0);
    ctx_lenient.strict_packets = false;
    assert!(
        process_stamp_packet(&data, loopback_src(), 64, false, &ctx_lenient).is_some(),
        "lenient mode must accept short packet"
    );

    let mut ctx_strict = test_ctx(0, 0);
    ctx_strict.strict_packets = true;
    assert!(
        process_stamp_packet(&data, loopback_src(), 64, false, &ctx_strict).is_none(),
        "strict mode must reject short packet"
    );
}

/// Full-size authenticated packet: both modes accept (no HMAC key
/// configured here, so HMAC verification is skipped).
#[test]
fn strict_packets_auth_full_size_both_modes_accept() {
    let packet = PacketAuthenticated {
        sequence_number: 1,
        mbz0: [0; 12],
        timestamp: 200,
        error_estimate: 0,
        ssid: 0,
        mbz1: [0; 68],
        hmac: [0; 16],
    };
    let data = packet.to_bytes();

    for strict in [false, true] {
        let mut ctx = test_ctx(0, 0);
        ctx.strict_packets = strict;
        let r = process_stamp_packet(&data, loopback_src(), 64, true, &ctx);
        assert!(
            r.is_some(),
            "strict={strict} must accept full-size auth packet"
        );
    }
}

/// Short authenticated packet (100 bytes < 112). Lenient zero-fills
/// against canonical buffer per RFC 8762 §4.6; strict rejects.
#[test]
fn strict_packets_auth_short_rejected_only_in_strict() {
    let data = [0u8; 100];

    let mut ctx_lenient = test_ctx(0, 0);
    ctx_lenient.strict_packets = false;
    // No HMAC key → verification is skipped, lenient parser succeeds.
    assert!(
        process_stamp_packet(&data, loopback_src(), 64, true, &ctx_lenient).is_some(),
        "lenient mode must accept short auth packet (zero-filled)"
    );

    let mut ctx_strict = test_ctx(0, 0);
    ctx_strict.strict_packets = true;
    assert!(
        process_stamp_packet(&data, loopback_src(), 64, true, &ctx_strict).is_none(),
        "strict mode must reject short auth packet"
    );
}

/// Empty packet (0 bytes): strict mode must reject without panicking.
/// Lenient mode happens to accept it (everything zero), which is by
/// design per RFC 8762 §4.6.
#[test]
fn strict_packets_empty_buffer_no_panic() {
    let data: [u8; 0] = [];

    let mut ctx_strict = test_ctx(0, 0);
    ctx_strict.strict_packets = true;
    assert!(process_stamp_packet(&data, loopback_src(), 64, false, &ctx_strict).is_none());
    assert!(process_stamp_packet(&data, loopback_src(), 64, true, &ctx_strict).is_none());

    let mut ctx_lenient = test_ctx(0, 0);
    ctx_lenient.strict_packets = false;
    // Lenient unauth accepts; lenient auth also accepts (HMAC skipped).
    // The point of this test is "no panic on hostile zero-byte input."
    let _ = process_stamp_packet(&data, loopback_src(), 64, false, &ctx_lenient);
    let _ = process_stamp_packet(&data, loopback_src(), 64, true, &ctx_lenient);
}

/// `require_hmac` + auth mode with no key configured: rejected in both
/// strict and lenient modes. The `require_hmac` policy is independent
/// of the packet-length strictness.
#[test]
fn strict_packets_require_hmac_rejects_regardless_of_mode() {
    let packet = PacketAuthenticated {
        sequence_number: 1,
        mbz0: [0; 12],
        timestamp: 200,
        error_estimate: 0,
        ssid: 0,
        mbz1: [0; 68],
        hmac: [0; 16],
    };
    let data = packet.to_bytes();

    for strict in [false, true] {
        let mut ctx = test_ctx(0, 0);
        ctx.strict_packets = strict;
        ctx.require_hmac = true;
        // hmac_key stays None; require_hmac without a key drops.
        assert!(
            process_stamp_packet(&data, loopback_src(), 64, true, &ctx).is_none(),
            "strict={strict} + require_hmac without key must drop"
        );
    }
}

/// A present-but-empty keyset (e.g. the control plane deleted the last
/// key at runtime) must CLOSE the reflector to authenticated packets,
/// not downgrade it to answering them without verification, even with
/// the default `require_hmac = false`.
#[test]
fn auth_packet_rejected_when_keyset_present_but_resolves_no_key() {
    let packet = PacketAuthenticated {
        sequence_number: 1,
        mbz0: [0; 12],
        timestamp: 200,
        error_estimate: 0,
        ssid: 0,
        mbz1: [0; 68],
        hmac: [0; 16],
    };
    let data = packet.to_bytes();

    // Empty keyset: the "last key deleted" state.
    let empty_set = crate::crypto::HmacKeySet::new();
    let mut ctx = test_ctx(0, 0);
    ctx.hmac_key_set = Some(&empty_set);
    assert!(
        process_stamp_packet(&data, loopback_src(), 64, true, &ctx).is_none(),
        "empty keyset must reject auth packets, not answer them unverified"
    );

    // Keyset with a key for a *different* SSID and no default: an auth
    // packet with an unknown SSID must be rejected too.
    let mut other_ssid_set = crate::crypto::HmacKeySet::new();
    other_ssid_set.insert(42, crate::crypto::HmacKey::new(vec![0xAB; 16]).unwrap());
    let mut ctx = test_ctx(0, 0);
    ctx.hmac_key_set = Some(&other_ssid_set);
    assert!(
        process_stamp_packet(&data, loopback_src(), 64, true, &ctx).is_none(),
        "unknown SSID with no default key must be rejected"
    );

    // Sanity: with NO keyset at all (never configured), a keyless reflector
    // still answers authenticated-layout packets without verification.
    let ctx = test_ctx(0, 0);
    assert!(
        process_stamp_packet(&data, loopback_src(), 64, true, &ctx).is_some(),
        "keyless reflector without any keyset keeps accepting"
    );
}

/// Non-zero MBZ bytes: RFC 8762 §4.2.1 requires receivers to *ignore*
/// MBZ on receipt. Both modes must accept (strict mode does not extend
/// to MBZ enforcement).
#[test]
fn strict_packets_nonzero_mbz_accepted_per_rfc_8762() {
    let packet = PacketUnauthenticated {
        sequence_number: 1,
        timestamp: 0,
        error_estimate: 0,
        ssid: 0,
        mbz: [0xff; 28], // intentionally non-zero
    };
    let data = packet.to_bytes();

    for strict in [false, true] {
        let mut ctx = test_ctx(0, 0);
        ctx.strict_packets = strict;
        assert!(
            process_stamp_packet(&data, loopback_src(), 64, false, &ctx).is_some(),
            "strict={strict} must ignore non-zero MBZ per RFC 8762 §4.2.1"
        );
    }
}
