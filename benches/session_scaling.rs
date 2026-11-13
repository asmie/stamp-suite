//! Session-table operation costs, without packet processing or network I/O.
//! Run `cargo test --locked --bench session_scaling -- --test` for fixture checks.
//! Measurement scope and reproduction: doc/benchmarks.md.

use std::{
    collections::HashSet,
    fs,
    hint::black_box,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    time::Duration,
};

use clap::{Parser, ValueEnum};
use criterion::{criterion_group, BatchSize, BenchmarkId, Criterion};
use serde::Serialize;
use serde_json::json;
use sha2::{Digest, Sha256};
use stamp_suite::session::{SessionKey, SessionManager};

const SIZES: [usize; 3] = [1_024, 16_384, 65_536];

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, ValueEnum)]
#[serde(rename_all = "snake_case")]
enum ProfileOperation {
    LookupRefresh,
    Inventory,
    CleanupKeep,
    CleanupExpire,
    ControlChurn,
}

#[derive(Parser, Serialize)]
#[command(about = "Run fixed-count session operations for external profiling")]
struct ProfileArgs {
    #[arg(long, default_value_t = 16_384, value_parser = clap::value_parser!(u32).range(1..=65_536))]
    sessions: u32,
    #[arg(long)]
    ipv6: bool,
    #[arg(long, value_enum, default_value = "inventory")]
    operation: ProfileOperation,
    #[arg(long, default_value_t = 10, value_parser = clap::value_parser!(u32).range(1..=1_000))]
    iterations: u32,
}

// Keep one stable profiling boundary, without adding calls to Criterion's
// timed loops. Callgrind can toggle collection at entry/exit of this symbol.
#[inline(never)]
fn profile_operation(
    manager: &SessionManager,
    selected: SessionKey,
    operation: ProfileOperation,
) -> usize {
    let result = match operation {
        ProfileOperation::LookupRefresh => {
            drop(black_box(
                manager
                    .get_or_create_session(black_box(selected))
                    .expect("known session rejected"),
            ));
            1
        }
        ProfileOperation::Inventory => {
            let rows = black_box(manager.session_summaries_extended());
            let len = rows.len();
            drop(black_box(rows));
            len
        }
        ProfileOperation::CleanupKeep | ProfileOperation::CleanupExpire => {
            manager.cleanup_stale_sessions()
        }
        ProfileOperation::ControlChurn => {
            assert!(manager
                .expire_matching(black_box(selected.client), None)
                .expect("ambiguous profile client"));
            drop(black_box(
                manager
                    .get_or_create_session(selected)
                    .expect("replacement rejected"),
            ));
            1
        }
    };
    // Preserve an observable instruction after the manager call rather than
    // tail-calling it out of the profiler boundary.
    black_box(result)
}

#[derive(Serialize)]
struct ProfileSample {
    iteration: u32,
    observed_items: usize,
    final_sessions: usize,
}

fn profile_samples(args: &ProfileArgs) -> Vec<ProfileSample> {
    let size = args.sessions as usize;
    let keys = keys(size, args.ipv6);
    let mut samples = Vec::with_capacity(args.iterations as usize);
    for iteration in 0..args.iterations {
        let expires = args.operation == ProfileOperation::CleanupExpire;
        let manager = populated(
            &keys,
            if expires {
                Duration::ZERO
            } else {
                Duration::MAX
            },
        );
        let selected = keys[(iteration as usize * 40_507) % size];
        let observed_items = profile_operation(&manager, selected, args.operation);
        let expected = match args.operation {
            ProfileOperation::Inventory | ProfileOperation::CleanupExpire => size,
            ProfileOperation::CleanupKeep => 0,
            _ => 1,
        };
        assert_eq!(observed_items, expected);
        let final_sessions = manager.session_count();
        assert_eq!(final_sessions, if expires { 0 } else { size });
        samples.push(ProfileSample {
            iteration,
            observed_items,
            final_sessions,
        });
        // Population, validation/result storage and final manager destruction
        // stay outside profile_operation, including the retained hash table.
    }
    samples
}

fn verify_profile_fixtures() {
    for ipv6 in [false, true] {
        for operation in [
            ProfileOperation::LookupRefresh,
            ProfileOperation::Inventory,
            ProfileOperation::CleanupKeep,
            ProfileOperation::CleanupExpire,
            ProfileOperation::ControlChurn,
        ] {
            let samples = profile_samples(&ProfileArgs {
                sessions: 16,
                ipv6,
                operation,
                iterations: 2,
            });
            assert_eq!(samples.len(), 2);
        }
    }
    for extra in [
        ["--sessions", "0"],
        ["--sessions", "65537"],
        ["--iterations", "0"],
        ["--iterations", "1001"],
    ] {
        assert!(ProfileArgs::try_parse_from(["session_scaling", extra[0], extra[1]]).is_err());
    }
}

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

#[cfg(feature = "control")]
fn indexed(keys: &[SessionKey], timeout: Duration) -> SessionManager {
    let manager = populated(keys, timeout);
    manager.enable_session_inventory().unwrap();
    manager
}

#[cfg(feature = "control")]
fn bench_session_inventory(c: &mut Criterion) {
    let mut group = c.benchmark_group("session_inventory");
    for (ipv6, family) in [(false, "ipv4"), (true, "ipv6")] {
        for size in SIZES {
            let keys = keys(size, ipv6);
            let access_keys: Vec<_> = (0..size).map(|i| keys[(i * 40_507) % size]).collect();
            for limit in [100, 500] {
                group.bench_function(
                    BenchmarkId::new(format!("page_{limit}_{family}"), size),
                    |b| {
                        let manager = indexed(&keys, Duration::MAX);
                        let mut cursor: Option<String> = None;
                        b.iter(|| {
                            let page = manager
                                .session_summaries_page(limit, cursor.as_deref())
                                .unwrap();
                            assert!(page.items.len() <= limit);
                            cursor = page.next_cursor;
                            black_box(page.items)
                        });
                        assert_eq!(manager.session_count(), size);
                    },
                );
            }
            group.bench_function(
                BenchmarkId::new(format!("initialize_{family}"), size),
                |b| {
                    b.iter_batched_ref(
                        || populated(&keys, Duration::MAX),
                        |manager| {
                            manager.enable_session_inventory().unwrap();
                        },
                        BatchSize::PerIteration,
                    );
                },
            );
            group.bench_function(
                BenchmarkId::new(format!("cleanup_expire_indexed_{family}"), size),
                |b| {
                    b.iter_batched_ref(
                        || indexed(&keys, Duration::ZERO),
                        |manager| {
                            assert_eq!(manager.cleanup_stale_sessions(), size);
                        },
                        BatchSize::PerIteration,
                    );
                },
            );
            group.bench_function(
                BenchmarkId::new(format!("lookup_refresh_indexed_{family}"), size),
                |b| {
                    let manager = indexed(&keys, Duration::MAX);
                    let mut cursor = 0;
                    b.iter(|| {
                        black_box(
                            manager
                                .get_or_create_session(next_key(&access_keys, &mut cursor))
                                .unwrap(),
                        )
                    });
                },
            );
            group.bench_function(
                BenchmarkId::new(format!("control_churn_indexed_{family}"), size),
                |b| {
                    let manager = indexed(&keys, Duration::MAX);
                    let mut cursor = 0;
                    b.iter(|| {
                        let key = next_key(&access_keys, &mut cursor);
                        assert!(manager.expire_matching(key.client, None).unwrap());
                        black_box(manager.get_or_create_session(key).unwrap())
                    });
                    assert_eq!(manager.session_count(), size);
                },
            );
        }
    }
    group.finish();
}

#[cfg(feature = "control")]
criterion_group!(benches, bench_session_table, bench_session_inventory);
#[cfg(not(feature = "control"))]
criterion_group!(benches, bench_session_table);

fn main() {
    if std::env::args().nth(1).as_deref() == Some("--profile-operations") {
        let args = ProfileArgs::parse_from(
            std::iter::once("session_scaling".to_owned()).chain(std::env::args().skip(2)),
        );
        if cfg!(debug_assertions) {
            eprintln!("use a release build for profiling");
            std::process::exit(2);
        }
        let samples = profile_samples(&args);
        println!("{}", serde_json::to_string_pretty(&json!({
            "schema_version": 1, "completed": true, "settings": args,
            "scope": "fixed-count session-manager operations; no timing or network packets",
            "os":std::env::consts::OS, "arch":std::env::consts::ARCH,
            "debug_build":cfg!(debug_assertions),
            "binary_sha256":hex::encode(Sha256::digest(fs::read(std::env::current_exe().expect("executable path")).expect("executable bytes"))),
            "source_sha256":hex::encode(Sha256::digest(include_bytes!("session_scaling.rs"))),
            "features":{"metrics":cfg!(feature="metrics"), "control":cfg!(feature="control"),
                "ttl_pnet":cfg!(feature="ttl-pnet"), "ttl_nix":cfg!(feature="ttl-nix"),
                "snmp":cfg!(feature="snmp"), "hwtstamp":cfg!(feature="hwtstamp")},
            "samples":samples
        })).expect("profile report"));
    } else {
        verify_profile_fixtures();
        // Match criterion_main!: normal timing loops and Criterion CLI remain
        // unchanged, with only additional fixture validation before the group.
        benches();
        Criterion::default().configure_from_args().final_summary();
    }
}
