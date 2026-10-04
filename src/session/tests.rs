use super::*;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::thread;

#[test]
fn admission_permit_observes_later_cap_drain_and_expiry_changes() {
    let first = SessionKey::from("127.0.0.1:1001".parse::<SocketAddr>().unwrap());
    let second = SessionKey::from("127.0.0.1:1002".parse::<SocketAddr>().unwrap());
    let denied = SessionKey::from("127.0.0.1:1003".parse::<SocketAddr>().unwrap());
    let manager = SessionManager::with_admission(
        None,
        None,
        SessionAdmission::Provisioned,
        [first, second].into_iter().collect(),
    );
    assert!(manager.admit(denied).is_none());
    let pending = manager.admit(second).unwrap();
    assert_eq!(
        manager.session_count(),
        0,
        "a permit must not allocate state"
    );
    let existing = manager.get_or_create_session(first).unwrap();
    manager.set_max_sessions(1);
    assert!(pending.acquire().is_none(), "a later cap must apply");
    assert_eq!(manager.next_session_id.load(Ordering::Relaxed), 1);

    manager.set_max_sessions(0);
    let pending = manager.admit(second).unwrap();
    let known = manager.admit(first).unwrap();
    manager.set_draining(true);
    assert!(pending.acquire().is_none(), "a later drain must apply");
    assert!(Arc::ptr_eq(&known.acquire().unwrap(), &existing));
    assert_eq!(manager.next_session_id.load(Ordering::Relaxed), 1);

    let pending = manager.admit(first).unwrap();
    manager
        .expire_matching(first.client, Some(existing.get_id()))
        .unwrap();
    assert!(
        pending.acquire().is_none(),
        "expiry during drain cannot recreate state"
    );
    assert!(existing.transmission_guard().is_none());
    manager.set_draining(false);
    let replacement = manager.admit(first).unwrap().acquire().unwrap();
    assert!(!Arc::ptr_eq(&existing, &replacement));
    assert_eq!(replacement.get_id(), 1);
    assert_eq!(replacement.generate_sequence_number(), 0);
}

#[test]
fn complete_identity_isolates_all_runtime_state() {
    for (source, destination) in [
        ("127.0.0.1:4000", "127.0.0.1:862"),
        ("[::1]:4000", "[::1]:862"),
    ] {
        let base: SessionKey = format!("42,{source},{destination}").parse().unwrap();
        let mut other_destination = base;
        other_destination.local.set_port(863);
        let keys = [
            base,
            SessionKey { ssid: 43, ..base },
            other_destination,
            SessionKey {
                sender_micro_session_id: Some(1),
                ..base
            },
            SessionKey {
                sender_micro_session_id: Some(2),
                ..base
            },
        ];
        let manager = SessionManager::new(None, None);
        for key in keys {
            let (seq, session) = manager.get_session_and_seq(key).unwrap();
            assert_eq!(seq, 0);
            assert_eq!(session.get_received_count(), 0);
            assert_eq!(session.get_transmitted_count(), 0);
            assert_eq!(session.check_replay(100), ReplayVerdict::New);
            assert_eq!(session.get_last_reflection().0, 0);
            session.record_received();
            session.record_transmitted();
            session.record_reflection(100, 123);
        }
        assert_eq!(manager.session_count(), 5);
        for key in keys {
            assert_eq!(manager.generate_sequence_number(key).unwrap(), 1);
            let session = manager.get_session(key).unwrap();
            assert_eq!(session.check_replay(100), ReplayVerdict::Replay);
            assert_eq!(session.get_received_count(), 1);
            assert_eq!(session.get_transmitted_count(), 1);
            assert_eq!(session.get_last_reflection(), (100, 123));
        }
        assert!(manager.expire_matching(base.client, None).is_err());
        let id = manager.get_session(base).unwrap().get_id();
        assert_eq!(manager.expire_matching(base.client, Some(id)), Ok(true));
        assert!(manager.get_session(base).is_none());
        assert_eq!(manager.session_count(), 4);
    }
}

#[test]
fn provisioning_survives_runtime_expiry_and_denies_other_identities() {
    let key: SessionKey = "42,127.0.0.1:4000,127.0.0.1:862,1".parse().unwrap();
    let manager = SessionManager::with_admission(
        Some(Duration::ZERO),
        None,
        SessionAdmission::Provisioned,
        HashSet::from([key]),
    );
    assert!(manager.admits(&key));
    assert!(!manager.admits(&SessionKey { ssid: 43, ..key }));
    assert!(!manager.admits(&SessionKey {
        sender_micro_session_id: None,
        ..key
    }));
    manager.get_or_create_session(key).unwrap();
    assert_eq!(manager.cleanup_stale_sessions(), 1);
    assert!(manager.admits(&key));
    assert_eq!(manager.provisioned_count(), 1);
    manager.get_or_create_session(key).unwrap();
    assert!(manager.expire_session(key));
    assert!(manager.admits(&key));
}

// -----------------------------------------------------------------------
// Replay detection (RFC 10052 §5)

#[test]
fn test_replay_first_packet_is_new() {
    let s = Session::new(1);
    assert_eq!(s.check_replay(0), ReplayVerdict::New);

    // Sequence number 0 must be *remembered*, which is why the packed
    // state carries an explicit initialized marker: an all-zero state
    // would otherwise look like "nothing seen yet".
    assert_eq!(s.check_replay(0), ReplayVerdict::Replay);
}

#[test]
fn test_replay_monotonic_run_is_all_new() {
    let s = Session::new(1);
    for seq in 0..1000u32 {
        assert_eq!(
            s.check_replay(seq),
            ReplayVerdict::New,
            "in-order seq {seq} must be New"
        );
    }
}

#[test]
fn test_replay_immediate_duplicate_detected() {
    let s = Session::new(1);
    assert_eq!(s.check_replay(10), ReplayVerdict::New);
    assert_eq!(s.check_replay(10), ReplayVerdict::Replay);
    // And still detected after the window has moved on a little.
    assert_eq!(s.check_replay(11), ReplayVerdict::New);
    assert_eq!(s.check_replay(10), ReplayVerdict::Replay);
}

#[test]
fn test_replay_reordered_then_duplicate() {
    let s = Session::new(1);
    assert_eq!(s.check_replay(100), ReplayVerdict::New);
    // 98 is behind the high-water mark and unseen: late, not a replay.
    assert_eq!(s.check_replay(98), ReplayVerdict::Reordered);
    // The same late packet again *is* a replay.
    assert_eq!(s.check_replay(98), ReplayVerdict::Replay);
    // A different late one is still just reordered.
    assert_eq!(s.check_replay(99), ReplayVerdict::Reordered);
}

#[test]
fn test_replay_window_edge_and_beyond() {
    let s = Session::new(1);
    assert_eq!(s.check_replay(1000), ReplayVerdict::New);

    // The furthest offset the window remembers.
    let edge = 1000 - REPLAY_WINDOW;
    assert_eq!(s.check_replay(edge), ReplayVerdict::Reordered);
    assert_eq!(s.check_replay(edge), ReplayVerdict::Replay);

    // One past the window: reported as unknown rather than
    // guessed at in either direction.
    assert_eq!(s.check_replay(edge - 1), ReplayVerdict::OutOfWindow);
    assert_eq!(s.check_replay(edge - 1), ReplayVerdict::OutOfWindow);
}

#[test]
fn test_replay_large_forward_jump_clears_the_window() {
    let s = Session::new(1);
    assert_eq!(s.check_replay(5), ReplayVerdict::New);
    assert_eq!(s.check_replay(4), ReplayVerdict::Reordered);
    // Jumping far ahead pushes every remembered offset out of range.
    assert_eq!(s.check_replay(10_000), ReplayVerdict::New);
    // 4 and 5 are now ancient history, not replays.
    assert_eq!(s.check_replay(4), ReplayVerdict::OutOfWindow);
    assert_eq!(s.check_replay(9_999), ReplayVerdict::Reordered);
}

#[test]
fn test_classify_replay_is_read_only_commit_advances() {
    let s = Session::new(1);
    // Classification never advances the window, so repeated classification
    // of the same unseen sequence number stays New.
    assert_eq!(s.classify_replay(5), ReplayVerdict::New);
    assert_eq!(s.classify_replay(5), ReplayVerdict::New);

    s.commit_replay(5);
    assert_eq!(s.classify_replay(5), ReplayVerdict::Replay);
    // Committing an already-recorded sequence number is a no-op.
    s.commit_replay(5);
    assert_eq!(s.classify_replay(5), ReplayVerdict::Replay);

    // A late unseen packet classifies as Reordered until committed.
    assert_eq!(s.classify_replay(4), ReplayVerdict::Reordered);
    assert_eq!(s.classify_replay(4), ReplayVerdict::Reordered);
    s.commit_replay(4);
    assert_eq!(s.classify_replay(4), ReplayVerdict::Replay);

    // classify+commit agrees with the atomic check_replay.
    assert_eq!(s.check_replay(6), ReplayVerdict::New);
    assert_eq!(s.classify_replay(6), ReplayVerdict::Replay);
}

#[test]
fn test_replay_advance_preserves_remembered_offsets() {
    let s = Session::new(1);
    assert_eq!(s.check_replay(50), ReplayVerdict::New);
    assert_eq!(s.check_replay(48), ReplayVerdict::Reordered);
    // Advance by 3: offset of 48 becomes 5, still inside the window.
    assert_eq!(s.check_replay(53), ReplayVerdict::New);
    assert_eq!(
        s.check_replay(48),
        ReplayVerdict::Replay,
        "a remembered offset must survive the window shifting"
    );
    assert_eq!(
        s.check_replay(50),
        ReplayVerdict::Replay,
        "the previous high-water mark must be remembered after advancing"
    );
}

#[test]
fn test_replay_survives_sequence_wraparound() {
    let s = Session::new(1);
    let near_max = u32::MAX - 2;
    assert_eq!(s.check_replay(near_max), ReplayVerdict::New);
    assert_eq!(s.check_replay(u32::MAX - 1), ReplayVerdict::New);
    assert_eq!(s.check_replay(u32::MAX), ReplayVerdict::New);
    // Wrapping past the end keeps advancing, not looking like a 4-billion
    // step backwards.
    assert_eq!(s.check_replay(0), ReplayVerdict::New);
    assert_eq!(s.check_replay(1), ReplayVerdict::New);
    // And the pre-wrap values are still remembered as seen.
    assert_eq!(s.check_replay(u32::MAX), ReplayVerdict::Replay);
    assert_eq!(s.check_replay(near_max), ReplayVerdict::Replay);
}

#[test]
fn test_replay_is_per_session_not_global() {
    let a = Session::new(1);
    let b = Session::new(2);
    assert_eq!(a.check_replay(7), ReplayVerdict::New);
    assert_eq!(
        b.check_replay(7),
        ReplayVerdict::New,
        "each session tracks its own sender's numbering"
    );
}

#[test]
fn test_replay_concurrent_updates_lose_nothing() {
    // Every distinct sequence number is offered exactly once from several
    // threads: none may be reported as a replay, because none is one.
    let s = Arc::new(Session::new(1));
    let mut handles = Vec::new();
    for t in 0..4u32 {
        let s = Arc::clone(&s);
        handles.push(thread::spawn(move || {
            let mut replays = 0;
            for i in 0..250u32 {
                if s.check_replay(t * 250 + i) == ReplayVerdict::Replay {
                    replays += 1;
                }
            }
            replays
        }));
    }
    let total: u32 = handles.into_iter().map(|h| h.join().unwrap()).sum();
    assert_eq!(
        total, 0,
        "no distinct sequence number may be called a replay"
    );
}

#[test]
fn test_expire_session() {
    let mgr = SessionManager::new(None, None);
    let addr: SocketAddr = "10.0.0.1:5000".parse().unwrap();
    mgr.get_or_create_session(addr).unwrap();
    assert_eq!(mgr.session_count(), 1);
    assert!(mgr.expire_session(addr));
    assert_eq!(mgr.session_count(), 0);
    assert!(!mgr.expire_session(addr), "second expire returns false");
}

#[test]
fn test_draining_blocks_new_sessions_only() {
    let mgr = SessionManager::new(None, None);
    let known: SocketAddr = "10.0.0.1:5000".parse().unwrap();
    let new_client: SocketAddr = "10.0.0.2:5000".parse().unwrap();
    mgr.get_or_create_session(known).unwrap();

    mgr.set_draining(true);
    assert!(mgr.is_draining());
    assert!(mgr.get_or_create_session(new_client).is_none());
    assert_eq!(mgr.session_count(), 1, "draining: new clients rejected");
    // Existing client still tracked.
    mgr.get_or_create_session(known).unwrap();
    assert_eq!(mgr.session_count(), 1);

    mgr.set_draining(false);
    mgr.get_or_create_session(new_client).unwrap();
    assert_eq!(mgr.session_count(), 2);
}

#[test]
fn test_set_max_sessions_at_runtime() {
    let mgr = SessionManager::new(None, Some(2));
    assert_eq!(mgr.max_sessions(), 2);
    mgr.set_max_sessions(1);
    assert_eq!(mgr.max_sessions(), 1);
    mgr.get_or_create_session("10.0.0.1:1".parse::<SocketAddr>().unwrap())
        .unwrap();
    assert!(mgr
        .get_or_create_session("10.0.0.2:2".parse::<SocketAddr>().unwrap())
        .is_none());
    assert_eq!(mgr.session_count(), 1, "cap applies to new creations");
}

#[test]
fn test_correct_reflection_timestamp_only_for_matching_seq() {
    let session = Session::new(1);
    session.record_reflection(42, 1000);

    // Matching seq → timestamp replaced (kernel TX timestamp arrived).
    assert!(session.correct_reflection_timestamp(42, 2000));
    assert_eq!(session.get_last_reflection(), (42, 2000));

    // A newer reflection was recorded since → stale correction dropped.
    session.record_reflection(43, 3000);
    assert!(!session.correct_reflection_timestamp(42, 9999));
    assert_eq!(session.get_last_reflection(), (43, 3000));
}

#[test]
fn test_get_session_returns_only_existing() {
    let mgr = SessionManager::new(None, None);
    let addr: SocketAddr = "10.0.0.1:5000".parse().unwrap();
    assert!(mgr.get_session(addr).is_none());
    mgr.get_or_create_session(addr).unwrap();
    assert!(mgr.get_session(addr).is_some());
    assert_eq!(mgr.session_count(), 1, "get_session must not create");
}

#[test]
fn test_sequence_number_starts_at_zero() {
    let session = Session::new(1);
    assert_eq!(session.generate_sequence_number(), 0);
}

#[test]
fn test_sequence_number_many_increments() {
    let session = Session::new(1);
    for i in 0..1000 {
        assert_eq!(session.generate_sequence_number(), i);
    }
}

#[test]
fn test_session_thread_safety() {
    let session = Arc::new(Session::new(1));
    let mut handles = vec![];

    // Spawn 10 threads, each generating 100 sequence numbers
    for _ in 0..10 {
        let session_clone = Arc::clone(&session);
        handles.push(thread::spawn(move || {
            let mut nums = Vec::new();
            for _ in 0..100 {
                nums.push(session_clone.generate_sequence_number());
            }
            nums
        }));
    }

    // Collect all sequence numbers
    let mut all_nums: Vec<u32> = handles
        .into_iter()
        .flat_map(|h| h.join().unwrap())
        .collect();

    // Sort and verify no duplicates (all unique)
    all_nums.sort();
    let unique_count = all_nums.len();
    all_nums.dedup();
    assert_eq!(
        all_nums.len(),
        unique_count,
        "Duplicate sequence numbers found"
    );

    // Should have exactly 1000 unique numbers (0-999)
    assert_eq!(all_nums.len(), 1000);
    assert_eq!(*all_nums.first().unwrap(), 0);
    assert_eq!(*all_nums.last().unwrap(), 999);
}

#[test]
fn test_multiple_sessions_independent() {
    let session1 = Session::new(1);
    let session2 = Session::new(2);

    // Generate some numbers from session1
    assert_eq!(session1.generate_sequence_number(), 0);
    assert_eq!(session1.generate_sequence_number(), 1);

    // Session2 should start fresh
    assert_eq!(session2.generate_sequence_number(), 0);

    // Continue session1
    assert_eq!(session1.generate_sequence_number(), 2);
}

// SessionManager tests

fn make_addr(port: u16) -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), port)
}

#[test]
fn test_session_manager_creates_sessions() {
    let manager = SessionManager::new(None, None);

    let client1 = make_addr(10001);
    let client2 = make_addr(10002);

    // First call creates a session
    let seq1 = manager.generate_sequence_number(client1).unwrap();
    assert_eq!(seq1, 0);
    assert_eq!(manager.session_count(), 1);

    // Second call to same client reuses session
    let seq2 = manager.generate_sequence_number(client1).unwrap();
    assert_eq!(seq2, 1);
    assert_eq!(manager.session_count(), 1);

    // Different client gets its own session
    let seq3 = manager.generate_sequence_number(client2).unwrap();
    assert_eq!(seq3, 0);
    assert_eq!(manager.session_count(), 2);
}

#[test]
fn test_session_manager_independent_sequences() {
    let manager = SessionManager::new(None, None);

    let client1 = make_addr(10001);
    let client2 = make_addr(10002);

    // Interleave requests from two clients
    assert_eq!(manager.generate_sequence_number(client1).unwrap(), 0);
    assert_eq!(manager.generate_sequence_number(client2).unwrap(), 0);
    assert_eq!(manager.generate_sequence_number(client1).unwrap(), 1);
    assert_eq!(manager.generate_sequence_number(client1).unwrap(), 2);
    assert_eq!(manager.generate_sequence_number(client2).unwrap(), 1);
    assert_eq!(manager.generate_sequence_number(client1).unwrap(), 3);
    assert_eq!(manager.generate_sequence_number(client2).unwrap(), 2);
}

#[test]
fn test_session_manager_thread_safety() {
    let manager = Arc::new(SessionManager::new(None, None));
    let mut handles = vec![];

    // 5 threads, each simulating a different client
    for i in 0..5 {
        let manager_clone = Arc::clone(&manager);
        handles.push(thread::spawn(move || {
            let client = make_addr(10001 + i);
            let mut nums = Vec::new();
            for _ in 0..100 {
                nums.push(manager_clone.generate_sequence_number(client).unwrap());
            }
            nums
        }));
    }

    // Each thread should get sequence 0-99
    for handle in handles {
        let nums = handle.join().unwrap();
        assert_eq!(nums.len(), 100);
        // Should be sequential within each client
        for (i, &n) in nums.iter().enumerate() {
            assert_eq!(n, i as u32);
        }
    }

    // Should have 5 sessions
    assert_eq!(manager.session_count(), 5);
}

#[test]
fn test_session_manager_cleanup_no_timeout() {
    let manager = SessionManager::new(None, None);
    let client = make_addr(10001);

    manager.generate_sequence_number(client).unwrap();
    assert_eq!(manager.session_count(), 1);

    // Without timeout, cleanup does nothing
    assert_eq!(manager.cleanup_stale_sessions(), 0);
    assert_eq!(manager.session_count(), 1);
}

#[test]
fn test_session_manager_cleanup_with_timeout() {
    // Use a short but reasonable timeout for testing
    // 50ms timeout with 100ms sleep provides 2x margin for slow/loaded systems
    let manager = SessionManager::new(Some(Duration::from_millis(50)), None);
    let client = make_addr(10001);

    manager.generate_sequence_number(client).unwrap();
    assert_eq!(manager.session_count(), 1);

    // Wait for timeout (2x the timeout duration for reliability)
    thread::sleep(Duration::from_millis(100));

    // Cleanup should remove the stale session
    assert_eq!(manager.cleanup_stale_sessions(), 1);
    assert_eq!(manager.session_count(), 0);
}

#[test]
fn test_session_manager_cleanup_keeps_active() {
    let manager = SessionManager::new(Some(Duration::from_secs(300)), None);
    let client = make_addr(10001);

    manager.generate_sequence_number(client).unwrap();

    // Session is still active, should not be cleaned up
    assert_eq!(manager.cleanup_stale_sessions(), 0);
    assert_eq!(manager.session_count(), 1);
}

#[test]
fn lowering_cap_preserves_existing_sessions_and_rejection_has_no_state() {
    let manager = SessionManager::new(None, Some(2));
    let first = manager.get_or_create_session(make_addr(1)).unwrap();
    let second = manager.get_or_create_session(make_addr(2)).unwrap();
    first.record_received();
    first.record_reflection(12, 345);
    first.commit_replay(99);
    assert_eq!(manager.generate_sequence_number(make_addr(1)), Some(0));
    manager.set_max_sessions(1);
    for _ in 0..3 {
        assert!(manager.get_or_create_session(make_addr(3)).is_none());
    }
    assert_eq!(
        manager.session_count(),
        2,
        "lowering the cap must not evict"
    );
    assert_eq!(manager.next_session_id.load(Ordering::Relaxed), 2);
    assert!(Arc::ptr_eq(
        &first,
        &manager.get_or_create_session(make_addr(1)).unwrap()
    ));
    assert!(Arc::ptr_eq(
        &second,
        &manager.get_or_create_session(make_addr(2)).unwrap()
    ));
    assert_eq!(manager.generate_sequence_number(make_addr(1)), Some(1));
    assert_eq!(first.get_received_count(), 1);
    assert_eq!(first.get_last_reflection(), (12, 345));
    assert_eq!(first.classify_replay(99), ReplayVerdict::Replay);
    manager.expire_session(make_addr(2));
    assert!(manager.get_or_create_session(make_addr(3)).is_none());
    manager.expire_session(make_addr(1));
    assert!(!manager.saturated.load(Ordering::Relaxed));
    let replacement = manager.get_or_create_session(make_addr(3)).unwrap();
    assert_eq!(replacement.get_id(), 2);
}

#[test]
fn concurrent_admission_never_exceeds_capacity() {
    let manager = Arc::new(SessionManager::new(None, Some(4)));
    let barrier = Arc::new(std::sync::Barrier::new(16));
    let threads: Vec<_> = (0..16)
        .map(|i| {
            let manager = Arc::clone(&manager);
            let barrier = Arc::clone(&barrier);
            thread::spawn(move || {
                barrier.wait();
                manager.get_or_create_session(make_addr(i + 1)).is_some()
            })
        })
        .collect();
    let admitted = threads
        .into_iter()
        .map(|t| usize::from(t.join().unwrap()))
        .sum::<usize>();
    assert_eq!(admitted, 4);
    assert_eq!(manager.session_count(), 4);
    manager.set_draining(true);
    manager.set_max_sessions(0);
    assert!(manager.get_or_create_session(make_addr(100)).is_none());
}

#[test]
fn provisioned_capacity_and_restart_preserve_admission_but_reset_runtime() {
    let key: SessionKey = "42,127.0.0.1:4000,127.0.0.1:862,1".parse().unwrap();
    let other = SessionKey { ssid: 43, ..key };
    let manager = SessionManager::with_admission(
        Some(Duration::ZERO),
        Some(1),
        SessionAdmission::Provisioned,
        HashSet::from([key, other]),
    );
    let first = manager.get_or_create_session(key).unwrap();
    first.record_received();
    first.record_reflection(3, 100);
    first.commit_replay(7);
    assert!(manager.get_or_create_session(other).is_none());
    assert!(manager
        .get_or_create_session(SessionKey { ssid: 99, ..key })
        .is_none());
    assert_eq!(manager.cleanup_stale_sessions(), 1);
    assert!(first.transmission_guard().is_none());
    let restarted = manager.get_or_create_session(key).unwrap();
    assert_ne!(first.get_id(), restarted.get_id());
    assert_eq!(restarted.generate_sequence_number(), 0);
    assert_eq!(restarted.get_received_count(), 0);
    assert_eq!(restarted.get_last_reflection(), (0, 0));
    assert_eq!(restarted.classify_replay(7), ReplayVerdict::New);
    assert_eq!(manager.provisioned_count(), 2);
    assert_eq!(
        manager.expire_matching(key.client, Some(restarted.get_id())),
        Ok(true)
    );
    assert!(restarted.transmission_guard().is_none());
    assert!(manager.get_or_create_session(other).is_some());
}

#[test]
fn test_session_manager_enforces_max_sessions_cap() {
    // Cap of 2: preserve the first two identities and reject a third.
    let manager = SessionManager::new(None, Some(2));
    manager.generate_sequence_number(make_addr(1)).unwrap();
    manager.generate_sequence_number(make_addr(2)).unwrap();
    assert_eq!(manager.session_count(), 2);

    assert!(manager.get_or_create_session(make_addr(3)).is_none());
    assert!(manager.get_session_and_seq(make_addr(3)).is_none());
    assert!(manager.generate_sequence_number(make_addr(3)).is_none());
    assert_eq!(
        manager.session_count(),
        2,
        "table must not grow past the cap"
    );

    // Existing clients are still served from the table.
    manager.generate_sequence_number(make_addr(1)).unwrap();
    assert_eq!(manager.session_count(), 2);
}

#[test]
fn test_session_cap_reopens_after_cleanup_frees_space() {
    let manager = SessionManager::new(Some(Duration::from_millis(50)), Some(1));
    manager.generate_sequence_number(make_addr(1)).unwrap();
    assert_eq!(manager.session_count(), 1);
    // Over cap now, so the second client is not stored.
    assert!(manager.generate_sequence_number(make_addr(2)).is_none());
    assert_eq!(manager.session_count(), 1);

    // Let the first entry go stale and clean it up.
    thread::sleep(Duration::from_millis(100));
    assert_eq!(manager.cleanup_stale_sessions(), 1);
    assert_eq!(manager.session_count(), 0);

    // Space freed → a new client is tracked again.
    manager.generate_sequence_number(make_addr(3)).unwrap();
    assert_eq!(manager.session_count(), 1);
}
#[test]
fn reflection_method_tracks_actual_reports_without_stale_downgrades() {
    let session = Session::new(0);
    session.record_reflection(7, 100);
    assert_eq!(
        session.get_last_reflection_with_method(),
        (7, 100, TimestampMethod::SwLocal)
    );
    assert!(session.correct_reflection_timestamp_with_method(7, 110, TimestampMethod::SwLocal));
    assert!(session.correct_reflection_timestamp_with_method(7, 120, TimestampMethod::HwAssist));
    assert!(!session.correct_reflection_timestamp_with_method(7, 115, TimestampMethod::SwLocal));
    assert_eq!(
        session.get_last_reflection_with_method(),
        (7, 120, TimestampMethod::HwAssist)
    );
    session.record_reflection(8, 200);
    assert!(!session.correct_reflection_timestamp_with_method(7, 130, TimestampMethod::HwAssist));
    assert_eq!(
        session.get_last_reflection_with_method(),
        (8, 200, TimestampMethod::SwLocal)
    );
}
