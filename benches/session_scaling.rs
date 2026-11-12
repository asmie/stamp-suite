//! Session-table operation costs, without packet processing or network I/O.
//! Run `cargo test --locked --bench session_scaling -- --test` for fixture checks.
//! Measurement scope and reproduction: doc/benchmarks.md.

use std::{
    collections::HashSet,
    hint::black_box,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    time::Duration,
};

use criterion::{criterion_group, criterion_main, BatchSize, BenchmarkId, Criterion};
use stamp_suite::session::{SessionKey, SessionManager};

const SIZES: [usize; 3] = [1_024, 16_384, 65_536];

fn keys(size: usize, ipv6: bool) -> Vec<SessionKey> {
    let local = if ipv6 {
        IpAddr::V6("2001:db8:ffff::1".parse().unwrap())
    } else {
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))
    };
    (0..size)
        .map(|index| {
            let client = if ipv6 {
                let base = u128::from("2001:db8::1".parse::<Ipv6Addr>().unwrap());
                IpAddr::V6(Ipv6Addr::from(base + index as u128))
            } else {
                let base = u32::from(Ipv4Addr::new(198, 18, 0, 1));
                IpAddr::V4(Ipv4Addr::from(base + index as u32))
            };
            SessionKey {
                client: SocketAddr::new(client, 10_000),
                local: SocketAddr::new(local, 862),
                ssid: 7,
                sender_micro_session_id: None,
            }
        })
        .collect()
}

fn populated(keys: &[SessionKey], timeout: Duration) -> SessionManager {
    let manager = SessionManager::new(Some(timeout), Some(keys.len()));
    for key in keys {
        manager
            .get_or_create_session(*key)
            .expect("benchmark fixture exceeded session capacity");
    }
    assert_eq!(manager.session_count(), keys.len());
    manager
}

fn verify_fixture(keys: &[SessionKey]) {
    let manager = populated(keys, Duration::MAX);
    let inventory = manager.session_summaries_extended();
    let observed: HashSet<_> = inventory.iter().map(|row| row.key).collect();
    let expected: HashSet<_> = keys.iter().copied().collect();
    assert_eq!(
        keys.iter()
            .map(|key| key.client)
            .collect::<HashSet<_>>()
            .len(),
        keys.len()
    );
    assert_eq!(inventory.len(), keys.len());
    assert_eq!(observed, expected);
    assert_eq!(manager.cleanup_stale_sessions(), 0);
    assert_eq!(manager.session_count(), keys.len());
    let expired = populated(keys, Duration::ZERO);
    assert_eq!(expired.cleanup_stale_sessions(), keys.len());
    assert_eq!(expired.session_count(), 0);
}

fn next_key(keys: &[SessionKey], cursor: &mut usize) -> SessionKey {
    let key = keys[*cursor];
    *cursor += 1;
    if *cursor == keys.len() {
        *cursor = 0;
    }
    key
}

fn bench_session_table(c: &mut Criterion) {
    let mut group = c.benchmark_group("session_table");
    for (ipv6, family) in [(false, "ipv4"), (true, "ipv6")] {
        for size in SIZES {
            let keys = keys(size, ipv6);
            verify_fixture(&keys);
            // Spread short samples across the populated table, independently
            // of insertion order. The odd stride permutes each power-of-two size.
            let access_keys: Vec<_> = (0..size)
                .map(|index| keys[(index * 40_507) % size])
                .collect();
            assert_eq!(
                access_keys.iter().copied().collect::<HashSet<_>>().len(),
                size
            );
            let mut lookup_cursor = 0;

            group.bench_function(
                BenchmarkId::new(format!("lookup_refresh_{family}"), size),
                |b| {
                    let manager = populated(&keys, Duration::MAX);
                    b.iter(|| {
                        let key = next_key(&access_keys, &mut lookup_cursor);
                        black_box(
                            manager
                                .get_or_create_session(black_box(key))
                                .expect("known session rejected"),
                        )
                    });
                    assert_eq!(manager.session_count(), size);
                },
            );

            group.bench_function(BenchmarkId::new(format!("inventory_{family}"), size), |b| {
                let manager = populated(&keys, Duration::MAX);
                b.iter(|| black_box(manager.session_summaries_extended()));
                assert_eq!(manager.session_count(), size);
            });

            group.bench_function(
                BenchmarkId::new(format!("cleanup_keep_{family}"), size),
                |b| {
                    let manager = populated(&keys, Duration::MAX);
                    b.iter(|| {
                        let removed = manager.cleanup_stale_sessions();
                        assert_eq!(removed, 0);
                        black_box(removed)
                    });
                    assert_eq!(manager.session_count(), size);
                },
            );

            group.bench_function(
                BenchmarkId::new(format!("cleanup_expire_{family}"), size),
                |b| {
                    // Each measured cleanup gets a fresh full table. Setup and
                    // table destruction are excluded; removal/retirement is timed.
                    b.iter_batched_ref(
                        || populated(&keys, Duration::ZERO),
                        |manager| {
                            let removed = manager.cleanup_stale_sessions();
                            assert_eq!(removed, size);
                            black_box(removed)
                        },
                        BatchSize::PerIteration,
                    );
                },
            );

            let mut churn_cursor = 0;
            group.bench_function(
                BenchmarkId::new(format!("control_churn_{family}"), size),
                |b| {
                    let manager = populated(&keys, Duration::MAX);
                    b.iter(|| {
                        let key = next_key(&access_keys, &mut churn_cursor);
                        assert!(manager
                            .expire_matching(black_box(key.client), None)
                            .expect("benchmark client has ambiguous sessions"));
                        black_box(
                            manager
                                .get_or_create_session(key)
                                .expect("replacement session rejected"),
                        )
                    });
                    assert_eq!(manager.session_count(), size);
                },
            );
        }
    }
    group.finish();
}

criterion_group!(benches, bench_session_table);
criterion_main!(benches);
