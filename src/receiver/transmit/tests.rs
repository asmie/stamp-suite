use super::*;

#[test]
fn reply_budget_covers_handoff_active_send_and_rescheduled_copies() {
    let counters = Arc::new(ReflectorCounters::new());
    let budget = ReplyBudget::new(2, Arc::clone(&counters));
    let (sender, receiver) = std::sync::mpsc::sync_channel(2);
    let first = budget
        .reserve()
        .unwrap()
        .attach(sample(false, ReturnPathAction::Normal));
    assert!(sender.send(first).is_ok());
    let second = budget.reserve().unwrap(); // Packet still being authenticated.
    assert!(budget.reserve().is_none());
    let mut queue = ReplyQueue::default();
    queue.push_at(receiver.recv().unwrap(), Instant::now());
    let mut active = queue.pop_due().unwrap();
    assert!(
        budget.reserve().is_none(),
        "popping must not release the slot"
    );
    active
        .transmission
        .send_next(&counters, &RateLimiter::new(0), |bytes, _, _| {
            Ok(bytes.len())
        })
        .unwrap();
    queue.schedule_next(active);
    assert!(
        budget.reserve().is_none(),
        "remaining copies keep their slot"
    );
    drop(second); // Authentication failure returns the reservation.
    assert!(budget.reserve().is_some());
    drop(queue);
    assert!(budget.is_empty());
    assert_eq!(counters.reply_queue_rejected.load(Ordering::Relaxed), 3);
    assert_eq!(counters.queued_replies_cancelled.load(Ordering::Relaxed), 2);
    assert_eq!(counters.packets_reflected.load(Ordering::Relaxed), 1);
    assert_eq!(counters.packets_dropped.load(Ordering::Relaxed), 4);
}

#[test]
fn reply_budget_is_shared_by_concurrent_producers_and_closed_handoffs() {
    let counters = Arc::new(ReflectorCounters::new());
    let budget = ReplyBudget::new(4, Arc::clone(&counters));
    let barrier = std::sync::Barrier::new(16);
    std::thread::scope(|scope| {
        for _ in 0..16 {
            let budget = &budget;
            let barrier = &barrier;
            scope.spawn(move || {
                let reservation = budget.reserve();
                barrier.wait();
                assert_eq!(budget.used.load(Ordering::Acquire), 4);
                barrier.wait();
                drop(reservation);
            });
        }
    });
    assert!(budget.is_empty());
    assert_eq!(counters.reply_queue_rejected.load(Ordering::Relaxed), 12);
    let (sender, receiver) = std::sync::mpsc::sync_channel(1);
    drop(receiver);
    let work = budget
        .reserve()
        .unwrap()
        .attach(sample(true, ReturnPathAction::Normal));
    drop(sender.try_send(work));
    assert!(budget.is_empty());
    assert_eq!(counters.queued_replies_cancelled.load(Ordering::Relaxed), 3);
}

#[test]
fn shutdown_drain_finishes_early_or_at_an_immutable_deadline() {
    let now = Instant::now();
    let mut drain = ShutdownDrain::default();
    assert!(!drain.finished(now, true));
    drain.begin(now, Duration::from_millis(50));
    drain.begin(now + Duration::from_millis(40), Duration::from_secs(60));
    assert!(!drain.finished(now + Duration::from_millis(49), false));
    assert!(drain.finished(now + Duration::from_millis(50), false));
    assert!(drain.finished(now, true));
    let mut immediate = ShutdownDrain::default();
    immediate.begin(now, Duration::ZERO);
    assert!(immediate.finished(now, false));
}

fn sample(auth: bool, action: ReturnPathAction) -> Transmission {
    let mut data = vec![0; if auth { 112 } else { 44 }];
    data.extend_from_slice(&[0, 4, 0, 4, 184, 0, 0, 0]);
    data.extend_from_slice(&[0, 10, 0, 4, 0, 0, 0, 0]);
    if auth {
        data.extend_from_slice(&[0, 8, 0, 16]);
        data.extend_from_slice(&[0; 16]);
        data.extend_from_slice(&[0; 9]);
    }
    let response = StampResponse {
        data,
        cos_request: Some((46, 0)),
        return_path_action: action,
        reflected_control: Some(super::super::ReflectedControlBehavior {
            max_size: 1500,
            extra_copies: 2,
            interval_ns: 1,
            suppress_reply_ext_headers: false,
        }),
        reply_source: Some("127.0.0.2".parse().unwrap()),
        tlv_hmac_generated: auth,
    };
    Transmission::new(
        response,
        Arc::new(Session::new(0)),
        "127.0.0.1:4000".parse().unwrap(),
        ClockFormat::NTP,
        auth,
        true,
        auth.then(|| HmacKey::new(vec![0xCD; 16]).unwrap()),
        0,
        true,
    )
}

fn verify_signatures(data: &[u8]) {
    let key = HmacKey::new(vec![0xCD; 16]).unwrap();
    assert_eq!(
        &data[96..112],
        &crate::crypto::compute_packet_hmac(&key, data, 96)
    );
    let pos = 128; // CoS + Return Path, then HMAC, then symmetric zero padding.
    let mut input = data[..4].to_vec();
    input.extend_from_slice(&data[112..pos]);
    assert_eq!(&data[pos + 4..pos + 20], &key.compute(&input));
}

#[test]
fn cached_socket_options_skip_repeats_and_retry_failed_changes() {
    let mut cached = None;
    let mut sets = 0;
    for _ in 0..32 {
        update_socket_option(&mut cached, 2, || {
            sets += 1;
            Ok(())
        })
        .unwrap();
    }
    assert_eq!(sets, 1, "one setting for an unchanged 32-copy burst");
    assert!(update_socket_option(&mut cached, 1, || {
        sets += 1;
        Err(io::ErrorKind::PermissionDenied.into())
    })
    .is_err());
    assert_eq!(cached, Some(2), "failed option must not become cached");
    update_socket_option(&mut cached, 1, || {
        sets += 1;
        Ok(())
    })
    .unwrap();
    update_socket_option(&mut cached, 1, || panic!("redundant option syscall")).unwrap();
    update_socket_option(&mut cached, 2, || {
        sets += 1;
        Ok(())
    })
    .unwrap();
    assert_eq!(sets, 4);
}

#[test]
fn echoed_tlv_hmac_is_sent_unchanged() {
    let mut transmission = sample(true, ReturnPathAction::Normal);
    transmission.response.tlv_hmac_generated = false;
    let digest_at = 128 + 4;
    transmission.response.data[digest_at..digest_at + 16].copy_from_slice(&[0x5A; 16]);
    let counters = ReflectorCounters::new();
    let mut sent = Vec::new();
    transmission.send_next(&counters, &RateLimiter::new(0), |bytes, _, _| {
        sent = bytes.to_vec();
        Ok(bytes.len())
    });
    assert_eq!(&sent[digest_at..digest_at + 16], &[0x5A; 16]);
    // The base HMAC still covers the fresh T3.
    let key = HmacKey::new(vec![0xCD; 16]).unwrap();
    assert_eq!(
        &sent[96..112],
        &crate::crypto::compute_packet_hmac(&key, &sent, 96)
    );
}

#[test]
fn generated_tlv_hmac_is_resigned_at_send_time() {
    let mut transmission = sample(true, ReturnPathAction::Normal);
    let counters = ReflectorCounters::new();
    let mut sent = Vec::new();
    transmission.send_next(&counters, &RateLimiter::new(0), |bytes, _, _| {
        sent = bytes.to_vec();
        Ok(bytes.len())
    });
    verify_signatures(&sent);
}

#[test]
fn incomplete_datagram_does_not_count_or_try_fallbacks() {
    let mut transmission = sample(true, ReturnPathAction::Normal);
    let counters = ReflectorCounters::new();
    let mut attempts = 0;
    assert_eq!(
        transmission.send_next(&counters, &RateLimiter::new(0), |bytes, _, _| {
            attempts += 1;
            Ok(bytes.len() - 1)
        }),
        None
    );
    assert_eq!(attempts, 1);
    assert_eq!(transmission.remaining, 0);
    assert_eq!(transmission.session.get_transmitted_count(), 0);
    assert_eq!(
        transmission.session.peek_sequence_number(),
        0,
        "a failed send must not consume a stateful sequence number"
    );
    assert_eq!(transmission.session.get_last_reflection(), (0, 0));
    assert_eq!(counters.packets_reflected.load(Ordering::Relaxed), 0);
    assert_eq!(counters.packets_dropped.load(Ordering::Relaxed), 1);
}

#[cfg(target_os = "linux")]
#[test]
fn socket_owner_keeps_interleaved_metadata_and_pmtu_policy_isolated() {
    use nix::{
        libc,
        sys::socket::{recvmsg, ControlMessageOwned, MsgFlags, SockaddrStorage},
    };
    use std::{io::IoSliceMut, os::fd::AsRawFd};
    for ipv6 in [false, true] {
        let ip = if ipv6 { "::1" } else { "127.0.0.1" };
        let peer = std::net::UdpSocket::bind((ip, 0)).unwrap();
        peer.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        let tx = std::net::UdpSocket::bind((if ipv6 { "::" } else { "0.0.0.0" }, 0)).unwrap();
        let enable: libc::c_int = 1;
        let level = if ipv6 {
            libc::IPPROTO_IPV6
        } else {
            libc::IPPROTO_IP
        };
        let receive_tos = if ipv6 {
            libc::IPV6_RECVTCLASS
        } else {
            libc::IP_RECVTOS
        };
        // SAFETY: live fd and correctly sized integer socket option.
        assert_eq!(
            unsafe {
                libc::setsockopt(
                    peer.as_raw_fd(),
                    level,
                    receive_tos,
                    std::ptr::addr_of!(enable).cast(),
                    std::mem::size_of_val(&enable) as _,
                )
            },
            0
        );
        let mut sender = DatagramSender::new(&tx);
        // Repeated and alternating requests on one socket must not inherit
        // source, DSCP/ECN or fragmentation policy from their predecessor.
        for (index, (tos, controlled, pinned)) in [
            (185, true, true),
            (0, false, false),
            (43, true, false),
            (43, true, true),
            (0, false, false),
            (185, true, true),
        ]
        .into_iter()
        .enumerate()
        {
            let source = if pinned {
                Some(if ipv6 { "::1" } else { "127.0.0.2" }.parse().unwrap())
            } else {
                None
            };
            let options = SendOptions {
                tos,
                source,
                egress_ifindex: None,
                srh: None,
                dont_fragment: controlled,
            };
            sender
                .send(&[index as u8], peer.local_addr().unwrap(), &options)
                .unwrap();
            let mut bytes = [0; 8];
            let mut iov = [IoSliceMut::new(&mut bytes)];
            let mut control = nix::cmsg_space!(libc::c_int);
            let message = recvmsg::<SockaddrStorage>(
                peer.as_raw_fd(),
                &mut iov,
                Some(&mut control),
                MsgFlags::empty(),
            )
            .unwrap();
            assert_eq!(message.bytes, 1);
            let mut actual_tos = None;
            for cmsg in message.cmsgs().unwrap() {
                match cmsg {
                    ControlMessageOwned::Ipv4Tos(value) => actual_tos = Some(value),
                    ControlMessageOwned::Ipv6TClass(value) => actual_tos = Some(value as u8),
                    _ => {}
                }
            }
            assert_eq!(actual_tos, Some(tos));
            let address = message.address.unwrap();
            if !ipv6 {
                assert_eq!(
                    address.as_sockaddr_in().unwrap().ip(),
                    if pinned { "127.0.0.2" } else { "127.0.0.1" }
                        .parse::<std::net::Ipv4Addr>()
                        .unwrap()
                );
            }
            assert_eq!(bytes[0], index as u8);
            let mut discover: libc::c_int = -1;
            let mut length = std::mem::size_of_val(&discover) as libc::socklen_t;
            let option = if ipv6 {
                libc::IPV6_MTU_DISCOVER
            } else {
                libc::IP_MTU_DISCOVER
            };
            // SAFETY: output points at a live integer with its exact size.
            assert_eq!(
                unsafe {
                    libc::getsockopt(
                        tx.as_raw_fd(),
                        level,
                        option,
                        std::ptr::addr_of_mut!(discover).cast(),
                        &mut length,
                    )
                },
                0
            );
            assert_eq!(
                discover,
                if controlled {
                    libc::IP_PMTUDISC_DO
                } else {
                    libc::IP_PMTUDISC_WANT
                }
            );
        }
    }
}

#[test]
fn expiry_cancels_old_burst_before_session_identity_restarts() {
    for cleanup in [false, true] {
        let manager = crate::session::SessionManager::new(Some(Duration::ZERO), Some(1));
        let client: SocketAddr = "127.0.0.1:4000".parse().unwrap();
        let mut old = sample(true, ReturnPathAction::Normal);
        old.session = manager.get_or_create_session(client).unwrap();
        let counters = ReflectorCounters::new();
        let limiter = RateLimiter::new(0);
        let send = |data: &[u8], _: SocketAddr, _: &SendOptions| {
            verify_signatures(data);
            Ok(data.len())
        };
        assert_eq!(old.send_next(&counters, &limiter, send), Some(0));
        if cleanup {
            assert_eq!(manager.cleanup_stale_sessions(), 1);
        } else {
            assert!(manager.expire_session(client));
        }
        let mut fresh = sample(true, ReturnPathAction::Normal);
        fresh.session = manager.get_or_create_session(client).unwrap();
        assert_ne!(fresh.session.get_id(), old.session.get_id());
        assert_eq!(fresh.send_next(&counters, &limiter, send), Some(0));
        assert_eq!(
            old.send_next(&counters, &limiter, |_, _, _| panic!("expired burst sent")),
            None
        );
        assert_eq!(old.remaining, 0);
        assert_eq!(old.session.get_transmitted_count(), 1);
        assert_eq!(fresh.send_next(&counters, &limiter, send), Some(1));
    }
}

#[test]
fn every_copy_retries_alternate_with_source_cos_and_valid_signatures() {
    let mut transmission = sample(
        true,
        ReturnPathAction::AlternateAddress("[::1]:4000".parse().unwrap()),
    );
    let counters = ReflectorCounters::new();
    let limiter = RateLimiter::new(0);
    let mut attempts = 0;
    for seq in 0..3 {
        assert_eq!(
            transmission.send_next(&counters, &limiter, |data, target, options| {
                attempts += 1;
                if target.is_ipv6() {
                    return Err(io::Error::new(
                        io::ErrorKind::NetworkUnreachable,
                        "injected alternate failure",
                    ));
                }
                assert_eq!(target, "127.0.0.1:4000".parse::<SocketAddr>().unwrap());
                if crate::reply_source::supported() {
                    assert_eq!(options.source, Some("127.0.0.2".parse().unwrap()));
                }
                assert_eq!(options.tos, 184);
                assert_ne!(data[120] & 0x80, 0);
                verify_signatures(data);
                Ok(data.len())
            }),
            Some(seq)
        );
    }
    assert_eq!(attempts, 6);
    assert_eq!(transmission.session.get_transmitted_count(), 3);
    assert_eq!(counters.packets_reflected.load(Ordering::Relaxed), 3);
}

#[test]
fn srv6_failure_keeps_cos_and_marks_every_copy() {
    let mut transmission = sample(
        true,
        ReturnPathAction::Srv6Forward {
            sids: vec!["::1".parse().unwrap()],
            destination: None,
        },
    );
    transmission.source = "[::1]:4000".parse().unwrap();
    transmission.response.reply_source = Some("::1".parse().unwrap());
    let counters = ReflectorCounters::new();
    let limiter = RateLimiter::new(0);
    let mut shared_header: Option<Arc<[u8]>> = None;
    for seq in 0..3 {
        let mut attempts = 0;
        assert_eq!(
            transmission.send_next(&counters, &limiter, |data, _, options| {
                attempts += 1;
                assert_eq!(options.tos, 184);
                if crate::reply_source::supported() {
                    assert_eq!(options.source, Some("::1".parse().unwrap()));
                }
                if attempts == 1 {
                    let header = options.srh.as_ref().unwrap();
                    if let Some(previous) = &shared_header {
                        assert!(
                            Arc::ptr_eq(previous, header),
                            "SRH storage is reused across copies"
                        );
                    } else {
                        shared_header = Some(Arc::clone(header));
                    }
                    return Err(io::Error::new(
                        io::ErrorKind::Unsupported,
                        "injected SRH failure",
                    ));
                }
                assert!(options.srh.is_none());
                assert_ne!(data[120] & 0x80, 0);
                verify_signatures(data);
                Ok(data.len())
            }),
            Some(seq)
        );
        assert_eq!(attempts, 2);
    }
}

#[test]
fn cos_failure_uses_zero_ecn_fallback_and_resigns() {
    let mut transmission = sample(true, ReturnPathAction::Normal);
    transmission.response.reply_source = None;
    transmission.received_dscp = 10;
    let counters = ReflectorCounters::new();
    let limiter = RateLimiter::new(0);
    let mut attempts = 0;
    assert!(transmission
        .send_next(&counters, &limiter, |data, _, options| {
            attempts += 1;
            if attempts == 1 {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "injected CoS failure",
                ));
            }
            assert_eq!(options.tos, 40);
            assert_eq!(data[117] & 3, 1);
            assert_eq!((data[118] >> 4) & 3, 2);
            verify_signatures(data);
            Ok(data.len())
        })
        .is_some());
    assert_eq!(attempts, 2);
}

#[test]
fn unsuccessful_sends_do_not_advance_transmit_or_follow_up_counts() {
    let mut transmission = sample(false, ReturnPathAction::Normal);
    let counters = ReflectorCounters::new();
    let limiter = RateLimiter::new(0);
    assert!(transmission
        .send_next(&counters, &limiter, |_, _, _| Err(
            io::ErrorKind::WouldBlock.into()
        ))
        .is_none());
    assert_eq!(transmission.session.get_transmitted_count(), 0);
    assert_eq!(transmission.session.get_last_reflection(), (0, 0));
    assert_eq!(counters.packets_dropped.load(Ordering::Relaxed), 1);
    assert_eq!(transmission.remaining, 0);
}

#[test]
fn malformed_tail_stays_opaque_while_prefix_and_hmac_are_refreshed() {
    let key = HmacKey::new(vec![0xAB; 16]).unwrap();
    let mut data = vec![0; 44];
    data[3] = 42;
    data.extend_from_slice(&[0, 5, 0, 12]);
    data.extend_from_slice(&[99; 12]);
    let malformed_offset = data.len();
    data.extend_from_slice(&[0x40, 1, 255, 255, 7]);
    let hmac_offset = data.len();
    data.extend_from_slice(&[0, 8, 0, 16]);
    data.extend_from_slice(&[0; 16]);
    data.extend_from_slice(&[0; 13]);
    let before = data.clone();
    refresh_telemetry(&mut data, 44, &Session::new(0), true);
    // The processed Direct Measurement TLV before the malformed one gets
    // fresh counters (RFC 8972 §4); S_TxC and everything after stay as sent.
    assert_eq!(&data[48..52], &[99; 4]);
    assert_eq!(&data[52..60], &[0; 8]);
    assert_eq!(&data[malformed_offset..], &before[malformed_offset..]);
    sign_tlvs(&mut data, 44, &key);
    let mut input = data[..4].to_vec();
    input.extend_from_slice(&data[44..hmac_offset]);
    assert_eq!(
        &data[hmac_offset + 4..hmac_offset + 20],
        &key.compute(&input)
    );
}

#[cfg(target_os = "linux")]
#[test]
fn every_copy_pins_source_on_the_actual_socket() {
    let receiver = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    receiver
        .set_read_timeout(Some(Duration::from_secs(1)))
        .unwrap();
    let sender = std::net::UdpSocket::bind("0.0.0.0:0").unwrap();
    let mut sender = DatagramSender::new(&sender);
    let mut transmission = sample(false, ReturnPathAction::Normal);
    transmission.source = receiver.local_addr().unwrap();
    let counters = ReflectorCounters::new();
    let limiter = RateLimiter::new(0);
    for seq in 0..3 {
        assert_eq!(
            transmission.send_next(&counters, &limiter, |data, target, options| sender
                .send(data, target, options)),
            Some(seq)
        );
        let mut bytes = [0; 256];
        let (_, from) = receiver.recv_from(&mut bytes).unwrap();
        assert_eq!(from.ip(), "127.0.0.2".parse::<IpAddr>().unwrap());
    }
}
fn sized_sample(auth: bool, size: usize) -> Transmission {
    let mut t = sample(auth, ReturnPathAction::Normal);
    let base = if auth { 112 } else { 44 };
    t.response.data.truncate(base);
    t.response
        .data
        .extend_from_slice(&[0, 12, 0, 12, 5, 220, 0, 3, 0, 0, 0, 1, 0, 0, 0, 0]);
    let padding = size - base - 16 - if auth { 20 } else { 0 };
    t.response.data.extend_from_slice(&[0, 1]);
    t.response
        .data
        .extend_from_slice(&((padding - 4) as u16).to_be_bytes());
    t.response.data.resize(size - if auth { 20 } else { 0 }, 0);
    if auth {
        t.response.data.extend_from_slice(&[0, 8, 0, 16]);
        t.response.data.extend_from_slice(&[0; 16]);
    }
    t.response.reply_source = None;
    t.response.cos_request = None;
    t
}

fn check_sized_signature(data: &[u8], auth: bool) {
    if auth {
        let key = HmacKey::new(vec![0xCD; 16]).unwrap();
        assert_eq!(
            &data[96..112],
            &crate::crypto::compute_packet_hmac(&key, data, 96)
        );
        let pos = data.len() - 20;
        assert_eq!(&data[pos..pos + 4], &[0, 8, 0, 16]);
        let mut input = data[..4].to_vec();
        input.extend_from_slice(&data[112..pos]);
        assert_eq!(&data[pos + 4..], &key.compute(&input));
    }
}

#[test]
fn mtu_clamps_ipv4_ipv6_bursts_and_resigns_final_packet() {
    for auth in [false, true] {
        for ipv6 in [false, true] {
            let mut t = sized_sample(auth, 1500);
            if ipv6 {
                t.source = "[::1]:4000".parse().unwrap();
            }
            let cap = super::super::mtu_payload_cap(1500, ipv6) as usize;
            let counters = ReflectorCounters::new();
            assert_eq!(
                t.send_next_with_mtu(
                    &counters,
                    &RateLimiter::new(0),
                    |_, _, _| Ok(cap),
                    |data, target, options| {
                        assert_eq!(target.is_ipv6(), ipv6);
                        assert!(options.dont_fragment);
                        assert_eq!(data.len(), cap);
                        assert_eq!(data[if auth { 112 } else { 44 }] & 0x10, 0x10);
                        check_sized_signature(data, auth);
                        Ok(data.len())
                    }
                ),
                Some(0)
            );
            assert_eq!(t.remaining, 0);
            assert_eq!(t.session.get_transmitted_count(), 1);
        }
    }
}

#[test]
fn fallback_route_restores_original_length_and_c_flag() {
    for auth in [false, true] {
        let mut t = sized_sample(auth, 1500);
        let alternate: SocketAddr = "127.0.0.2:4001".parse().unwrap();
        t.response.return_path_action = ReturnPathAction::AlternateAddress(alternate);
        let mut calls = 0;
        assert_eq!(
            t.send_next_with_mtu(
                &ReflectorCounters::new(),
                &RateLimiter::new(0),
                |target, _, _| Ok(if target == alternate { 1000 } else { 2000 }),
                |data, target, _| {
                    calls += 1;
                    check_sized_signature(data, auth);
                    if target == alternate {
                        assert_eq!(data.len(), 1000);
                        assert_eq!(data[if auth { 112 } else { 44 }] & 0x10, 0x10);
                        Err(io::Error::new(
                            io::ErrorKind::AddrNotAvailable,
                            "alternate failed",
                        ))
                    } else {
                        assert_eq!(data.len(), 1500);
                        assert_eq!(data[if auth { 112 } else { 44 }] & 0x10, 0);
                        Ok(data.len())
                    }
                }
            ),
            Some(0)
        );
        assert_eq!(calls, 2);
        assert_eq!(t.remaining, 2);
    }
}

#[cfg(unix)]
#[test]
fn mtu_race_refreshes_budget_without_routing_downgrade() {
    let mut t = sized_sample(true, 1500);
    t.source = "[::1]:4000".parse().unwrap();
    t.response.return_path_action = ReturnPathAction::Srv6Forward {
        sids: vec!["::1".parse().unwrap()],
        destination: None,
    };
    t.response.reply_source = Some("::1".parse().unwrap());
    t.response.cos_request = Some((46, 0));
    // Our macOS backend does not implement source pinning. Preserve its
    // supported policy across the MTU retry rather than requiring Linux's.
    let expected_source = crate::reply_source::supported().then(|| "::1".parse().unwrap());
    let mut attempts = 0;
    let mut queries = Vec::new();
    assert_eq!(
        t.send_next_with_mtu(
            &ReflectorCounters::new(),
            &RateLimiter::new(0),
            |_, _, refresh| {
                queries.push(refresh);
                Ok(if refresh { 1200 } else { 1500 })
            },
            |data, _, options| {
                attempts += 1;
                assert!(options.srh.is_some());
                assert_eq!(options.source, expected_source);
                assert_eq!(options.tos, 184);
                check_sized_signature(data, true);
                if attempts == 1 {
                    Err(io::Error::from_raw_os_error(nix::libc::EMSGSIZE))
                } else {
                    assert_eq!(data.len(), 1200);
                    Ok(data.len())
                }
            }
        ),
        Some(0)
    );
    assert_eq!(queries, [false, true]);
    assert_eq!(t.remaining, 0);
}

#[test]
fn mandatory_fields_and_unavailable_routes_fail_closed() {
    for auth in [false, true] {
        let mut t = sized_sample(auth, 1500);
        let counters = ReflectorCounters::new();
        assert_eq!(
            t.send_next_with_mtu(
                &counters,
                &RateLimiter::new(0),
                |_, _, _| Ok(50),
                |_, _, _| panic!("oversize send")
            ),
            None
        );
        assert_eq!(t.remaining, 0);
        assert_eq!(t.session.get_transmitted_count(), 0);
        assert_eq!(counters.packets_dropped.load(Ordering::Relaxed), 1);
        let mut t = sized_sample(auth, 1500);
        assert_eq!(
            t.send_next_with_mtu(
                &counters,
                &RateLimiter::new(0),
                |_, _, _| Err(io::Error::new(io::ErrorKind::Unsupported, "no route MTU")),
                |_, _, _| panic!("unchecked send")
            ),
            None
        );
    }
}

#[test]
fn small_remainders_and_header_trimming_keep_valid_tlvs() {
    for auth in [false, true] {
        let base = if auth { 112 } else { 44 };
        for gap in 0..4 {
            let mut t = sized_sample(auth, 1500);
            let mandatory = base + 16 + if auth { 20 } else { 0 };
            assert!(fit_reply(&mut t.response.data, base, mandatory + gap, true).unwrap());
            assert_eq!(t.response.data.len(), mandatory);
            if auth {
                sign_tlvs(&mut t.response.data, base, t.key.as_ref().unwrap());
            }
        }
        let mut data = vec![0; base];
        data.extend_from_slice(&[0, 247, 0, 20]);
        data.extend_from_slice(&[0; 20]);
        data.extend_from_slice(&[0, 246, 0, 8]);
        data.extend_from_slice(&[0; 8]);
        data.extend_from_slice(&[0, 8, 0, 16]);
        data.extend_from_slice(&[0; 16]);
        assert!(!fit_reply(&mut data, base, base + 44, false).unwrap());
        assert_eq!(data.len(), base + 44);
        assert_eq!(data[base + 1], 247);
        assert_eq!(data[base + 25], 8);
        assert!(!fit_reply(&mut data, base, base + 20, false).unwrap());
        assert_eq!(data[base + 1], 8);
    }
}

#[test]
fn queued_burst_checks_new_mtu_before_each_copy() {
    let mut t = sized_sample(false, 1500);
    let counters = ReflectorCounters::new();
    let limiter = RateLimiter::new(0);
    assert_eq!(
        t.send_next_with_mtu(
            &counters,
            &limiter,
            |_, _, _| Ok(1500),
            |data, _, _| Ok(data.len())
        ),
        Some(0)
    );
    assert_eq!(t.remaining, 2);
    assert_eq!(
        t.send_next_with_mtu(
            &counters,
            &limiter,
            |_, _, _| Ok(1200),
            |data, _, _| {
                assert_eq!(data.len(), 1200);
                Ok(data.len())
            }
        ),
        Some(1)
    );
    assert_eq!(t.remaining, 0);
}
#[test]
fn each_follow_up_copy_reports_its_stored_timestamp_method_and_signature() {
    let mut t = sample(true, ReturnPathAction::Normal);
    // Replace the sample's TLVs with Type 3, Follow-Up and final HMAC.
    t.response.data.truncate(112);
    t.response.data.extend_from_slice(&[0, 3, 0, 4, 4, 2, 4, 2]);
    t.response.data.extend_from_slice(&[0, 7, 0, 16]);
    t.response.data.extend_from_slice(&[0; 16]);
    t.response.data.extend_from_slice(&[0, 8, 0, 16]);
    t.response.data.extend_from_slice(&[0; 16]);
    t.session.record_reflection(42, 100);
    let counters = ReflectorCounters::new();
    let limiter = RateLimiter::new(0);
    for (expected_seq, expected_ts, method) in [
        (42, 110, crate::tlv::TimestampMethod::HwAssist),
        (0, 200, crate::tlv::TimestampMethod::SwLocal),
        (1, 300, crate::tlv::TimestampMethod::HwAssist),
    ] {
        assert!(t.session.correct_reflection_timestamp_with_method(
            expected_seq,
            expected_ts,
            method
        ));
        assert!(t
            .send_next(&counters, &limiter, |data, _, _| {
                assert_eq!(&data[116..120], &[4, 2, 4, 2]);
                assert_eq!(&data[124..128], &expected_seq.to_be_bytes());
                assert_eq!(&data[128..136], &expected_ts.to_be_bytes());
                assert_eq!(data[136], method.to_byte());
                check_sized_signature(data, true);
                Ok(data.len())
            })
            .is_some());
    }
}
