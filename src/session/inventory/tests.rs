use super::*;
use std::{collections::HashSet, sync::mpsc, thread};

fn key(id: u16, ipv6: bool) -> SessionKey {
    let mut key = SessionKey::from(if ipv6 {
        "[::1]:4000".parse::<SocketAddr>().unwrap()
    } else {
        "127.0.0.1:4000".parse::<SocketAddr>().unwrap()
    });
    key.ssid = id;
    key.sender_micro_session_id = Some(id);
    key.local.set_port(862 + id % 2);
    key
}

#[test]
fn pages_cover_complete_identities_and_preserve_summary_fields() {
    for ipv6 in [false, true] {
        for count in [0, 1, 17, 501] {
            for limit in [1, 7, MAX_SESSION_PAGE_SIZE] {
                let manager = SessionManager::new(None, None);
                // Include populated-at-enable registration and idempotent enable.
                for id in 0..count {
                    let session = manager.get_or_create_session(key(id, ipv6)).unwrap();
                    session.record_received();
                    session.record_transmitted();
                    session.record_reflection(u32::from(id) + 10, 123);
                }
                manager.enable_session_inventory().unwrap();
                let mut seen = HashSet::new();
                let mut cursor = None;
                loop {
                    let page = manager
                        .session_summaries_page(limit, cursor.as_deref())
                        .unwrap();
                    assert!(page.items.len() <= limit);
                    assert!(!page.items.is_empty() || count == 0);
                    for row in page.items {
                        assert_eq!(row.packets_received, 1);
                        assert_eq!(row.packets_transmitted, 1);
                        assert_eq!(row.last_reflected_seq, u32::from(row.key.ssid) + 10);
                        assert_eq!(row.client_addr, row.key.client);
                        assert!(seen.insert(row.key));
                    }
                    manager.enable_session_inventory().unwrap();
                    cursor = page.next_cursor;
                    if cursor.is_none() {
                        break;
                    }
                }
                assert_eq!(seen, (0..count).map(|id| key(id, ipv6)).collect());
            }
        }
    }
}

#[test]
fn walks_skip_deletions_and_exclude_recreated_and_later_entries_even_after_id_wrap() {
    let manager = SessionManager::new(None, None);
    manager.enable_session_inventory().unwrap();
    for id in 0..4 {
        manager.get_or_create_session(key(id, false)).unwrap();
    }
    let first = manager.session_summaries_page(2, None).unwrap();
    assert_eq!(
        first
            .items
            .iter()
            .map(|row| row.key.ssid)
            .collect::<Vec<_>>(),
        [0, 1]
    );
    assert!(manager.expire_session(key(2, false)));
    manager.next_session_id.store(2, Ordering::Relaxed);
    assert_eq!(
        manager
            .get_or_create_session(key(2, false))
            .unwrap()
            .get_id(),
        2
    );
    manager.get_or_create_session(key(4, false)).unwrap();
    let last = manager
        .session_summaries_page(500, first.next_cursor.as_deref())
        .unwrap();
    assert_eq!(last.items.len(), 1);
    assert_eq!(last.items[0].key.ssid, 3);
    assert!(last.next_cursor.is_none());
    assert_eq!(manager.session_summaries_extended().len(), 5);
    assert_eq!(
        manager
            .session_summaries_page(500, None)
            .unwrap()
            .items
            .len(),
        5
    );

    // A valid continuation may become empty after its remaining rows disappear.
    let first = manager.session_summaries_page(4, None).unwrap();
    assert!(manager.expire_session(key(4, false)));
    let last = manager
        .session_summaries_page(4, first.next_cursor.as_deref())
        .unwrap();
    assert!(last.items.is_empty());
    assert!(last.next_cursor.is_none());
}

#[test]
fn invalid_limits_and_cursors_are_rejected_and_foreign_cursors_expire() {
    let manager = SessionManager::new(None, None);
    assert_eq!(
        manager.session_summaries_page(1, None).err(),
        Some(SessionPageError::NotEnabled)
    );
    manager.enable_session_inventory().unwrap();
    for id in 0..3 {
        manager.get_or_create_session(key(id, true)).unwrap();
    }
    for limit in [0, 501, usize::MAX] {
        assert_eq!(
            manager.session_summaries_page(limit, None).err(),
            Some(SessionPageError::InvalidLimit)
        );
    }
    let cursor = manager
        .session_summaries_page(1, None)
        .unwrap()
        .next_cursor
        .unwrap();
    let pieces: Vec<_> = cursor.split('-').collect();
    for value in [
        String::new(),
        "v2".to_owned(),
        "x".repeat(10_000),
        "é".repeat(34) + "x",
        format!("v2-{}-{}-{}", pieces[1], pieces[2], pieces[3]),
        format!("v1-{}-ffffffffffffffff-{}", pieces[1], pieces[3]),
        format!("v1-{}-{}-0000000000000000", pieces[1], pieces[2]),
        format!("v1-{}-{}-{}", pieces[1], pieces[2], pieces[2]),
        format!("v1-{}-{}-+000000000000001", pieces[1], pieces[2]),
    ] {
        assert_eq!(
            manager.session_summaries_page(1, Some(&value)).err(),
            Some(SessionPageError::InvalidCursor)
        );
    }
    let restarted = SessionManager::new(None, None);
    restarted.enable_session_inventory().unwrap();
    assert_eq!(
        restarted.session_summaries_page(1, Some(&cursor)).err(),
        Some(SessionPageError::ExpiredCursor)
    );
}

#[test]
fn collecting_a_page_does_not_read_metadata_outside_its_range() {
    let manager = Arc::new(SessionManager::new(None, None));
    manager.enable_session_inventory().unwrap();
    for id in 0..100 {
        manager.get_or_create_session(key(id, false)).unwrap();
    }
    let outside = manager.get_session(key(99, false)).unwrap();
    let locked = outside.last_reflection.write().unwrap();
    let (tx, rx) = mpsc::channel();
    let worker_manager = Arc::clone(&manager);
    let worker = thread::spawn(move || {
        let result = worker_manager.session_summaries_page(1, None).unwrap();
        tx.send(result.items[0].key).unwrap();
    });
    let result = rx.recv_timeout(Duration::from_secs(2));
    drop(locked);
    worker.join().unwrap();
    assert_eq!(result.unwrap(), key(0, false));
}

#[test]
fn cleanup_and_concurrent_control_churn_leave_no_stale_index_rows() {
    for ipv6 in [false, true] {
        let manager = Arc::new(SessionManager::new(Some(Duration::ZERO), None));
        manager.enable_session_inventory().unwrap();
        for id in 0..64 {
            manager.get_or_create_session(key(id, ipv6)).unwrap();
        }
        let first = manager.session_summaries_page(1, None).unwrap();
        let mut seen = HashSet::from([first.items[0].key]);
        let mut cursor = first.next_cursor;
        let concurrent = Arc::clone(&manager);
        let worker = thread::spawn(move || {
            for id in 0..64 {
                let key = key(id, ipv6);
                let session = concurrent.get_session(key).unwrap();
                assert!(concurrent
                    .expire_matching(key.client, Some(session.get_id()))
                    .unwrap());
                concurrent.get_or_create_session(key).unwrap();
            }
        });
        while let Some(token) = cursor {
            let page = manager.session_summaries_page(3, Some(&token)).unwrap();
            for row in page.items {
                assert!(
                    row.session_id < 64,
                    "replacement crossed the creation boundary"
                );
                assert!(seen.insert(row.key));
            }
            cursor = page.next_cursor;
        }
        worker.join().unwrap();
        assert_eq!(
            manager
                .session_summaries_page(500, None)
                .unwrap()
                .items
                .len(),
            64
        );
        assert_eq!(manager.cleanup_stale_sessions(), 64);
        assert!(manager
            .session_summaries_page(500, None)
            .unwrap()
            .items
            .is_empty());
        assert_eq!(
            manager
                .inventory
                .read()
                .unwrap()
                .as_ref()
                .unwrap()
                .entries
                .len(),
            0
        );
        manager.get_or_create_session(key(1, ipv6)).unwrap();
        assert_eq!(
            manager
                .session_summaries_page(500, None)
                .unwrap()
                .items
                .len(),
            1
        );
    }
}

#[test]
fn retiring_reservations_remain_visible_without_blocking_pages() {
    let manager = Arc::new(SessionManager::new(Some(Duration::ZERO), Some(1)));
    manager.enable_session_inventory().unwrap();
    let session = manager.get_or_create_session(key(0, false)).unwrap();
    let guard = session.transmission_guard().unwrap();
    let cleaner = Arc::clone(&manager);
    let cleanup = thread::spawn(move || cleaner.cleanup_stale_sessions());
    let observer = Arc::clone(&manager);
    let old = Arc::clone(&session);
    let (tx, rx) = mpsc::channel();
    let worker = thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(2);
        while old.is_active() && Instant::now() < deadline {
            thread::yield_now();
        }
        let page = observer.session_summaries_page(1, None).unwrap();
        tx.send((
            old.is_active(),
            page.items.len(),
            observer.get_or_create_session(key(1, false)).is_none(),
        ))
        .unwrap();
    });
    let result = rx.recv_timeout(Duration::from_secs(3));
    drop(guard);
    worker.join().unwrap();
    assert_eq!(cleanup.join().unwrap(), 1);
    assert_eq!(result.unwrap(), (false, 1, true));
    assert!(manager
        .session_summaries_page(1, None)
        .unwrap()
        .items
        .is_empty());
}

#[test]
fn ordinal_exhaustion_rejects_new_entries_without_consuming_session_ids() {
    let manager = SessionManager::new(None, None);
    manager.enable_session_inventory().unwrap();
    let existing = manager.get_or_create_session(key(0, false)).unwrap();
    manager.inventory.write().unwrap().as_mut().unwrap().last_id = u64::MAX;
    let next = manager.next_session_id.load(Ordering::Relaxed);
    assert!(manager.get_or_create_session(key(1, false)).is_none());
    assert_eq!(manager.next_session_id.load(Ordering::Relaxed), next);
    assert!(Arc::ptr_eq(
        &existing,
        &manager.get_or_create_session(key(0, false)).unwrap()
    ));
    assert_eq!(manager.session_count(), 1);
}

#[test]
fn sparse_and_bulk_expiry_preserve_walk_boundaries_and_live_order() {
    for ipv6 in [false, true] {
        for expired in [0, 1, 49, 50, 74, 75, 76, 99, 100] {
            let timeout = Duration::from_secs(60);
            let mut manager = SessionManager::new(Some(timeout), None);
            manager.epoch = Instant::now() - timeout * 2;
            manager.enable_session_inventory().unwrap();
            for id in 0..100 {
                manager.get_or_create_session(key(id, ipv6)).unwrap();
            }
            let first = manager.session_summaries_page(5, None).unwrap();
            let expired_key = |id: u16| (usize::from(id) * 37) % 100 < expired;
            {
                let table = manager.sessions.read().unwrap();
                for id in 0..100 {
                    if expired_key(id) {
                        table[&key(id, ipv6)]
                            .last_active
                            .store(0, Ordering::Relaxed);
                    }
                }
            }
            assert_eq!(manager.cleanup_stale_sessions(), expired);
            manager.get_or_create_session(key(200, ipv6)).unwrap();
            let mut cursor = first.next_cursor;
            let mut remaining = Vec::new();
            while let Some(token) = cursor {
                let page = manager.session_summaries_page(7, Some(&token)).unwrap();
                remaining.extend(page.items.into_iter().map(|row| row.key.ssid));
                cursor = page.next_cursor;
            }
            assert_eq!(
                remaining,
                (5..100).filter(|id| !expired_key(*id)).collect::<Vec<_>>()
            );
            let page = manager.session_summaries_page(500, None).unwrap();
            let expected: Vec<_> = (0..100)
                .filter(|id| !expired_key(*id))
                .chain([200])
                .collect();
            assert_eq!(
                page.items
                    .into_iter()
                    .map(|row| row.key.ssid)
                    .collect::<Vec<_>>(),
                expected
            );
            assert!(page.next_cursor.is_none());
        }
    }
}

#[test]
fn bulk_expiry_preserves_busy_reservations_and_accepts_unrelated_creations() {
    for ipv6 in [false, true] {
        let timeout = Duration::from_secs(60);
        let mut manager = SessionManager::new(Some(timeout), Some(101));
        manager.epoch = Instant::now() - timeout * 2;
        manager.enable_session_inventory().unwrap();
        for id in 0..101 {
            manager.get_or_create_session(key(id, ipv6)).unwrap();
        }
        let first = manager.session_summaries_page(1, None).unwrap();
        {
            let table = manager.sessions.read().unwrap();
            for id in 0..100 {
                table[&key(id, ipv6)]
                    .last_active
                    .store(0, Ordering::Relaxed);
            }
        }
        let manager = Arc::new(manager);
        let first_session = manager.get_session(key(0, ipv6)).unwrap();
        let second_session = manager.get_session(key(1, ipv6)).unwrap();
        let guard = first_session.transmission_guard().unwrap();
        let other_guard = second_session.transmission_guard().unwrap();
        let cleaner = Arc::clone(&manager);
        let cleanup = thread::spawn(move || cleaner.cleanup_stale_sessions());
        let observer = Arc::clone(&manager);
        let old = Arc::clone(&second_session);
        let (tx, rx) = mpsc::channel();
        let worker = thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(5);
            while old.is_active() && Instant::now() < deadline {
                thread::yield_now();
            }
            let page = observer.session_summaries_page(500, None).unwrap();
            assert!(observer.get_or_create_session(key(0, ipv6)).is_none());
            observer.get_or_create_session(key(200, ipv6)).unwrap();
            let continuation = observer
                .session_summaries_page(500, first.next_cursor.as_deref())
                .unwrap();
            tx.send((
                page.items
                    .into_iter()
                    .map(|row| row.key.ssid)
                    .collect::<Vec<_>>(),
                continuation
                    .items
                    .into_iter()
                    .map(|row| row.key.ssid)
                    .collect::<Vec<_>>(),
            ))
            .unwrap();
        });
        let observed = rx.recv_timeout(Duration::from_secs(5));
        drop(guard);
        drop(other_guard);
        assert_eq!(cleanup.join().unwrap(), 100);
        worker.join().unwrap();
        assert_eq!(observed.unwrap(), (vec![0, 1, 100], vec![1, 100]));
        let page = manager.session_summaries_page(500, None).unwrap();
        assert_eq!(
            page.items
                .into_iter()
                .map(|row| row.key.ssid)
                .collect::<Vec<_>>(),
            [100, 200]
        );
    }
}
