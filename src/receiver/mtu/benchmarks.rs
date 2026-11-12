//! Opt-in release measurements; normal tests check fixtures without time budgets.
//! Reproduction and scope: doc/benchmarks.md.

use super::*;
use std::{
    hint::black_box,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

use serde::Serialize;
use serde_json::json;
use sha2::{Digest, Sha256};

#[cfg(target_os = "linux")]
thread_local! {
    static ROUTE_QUERIES: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

#[cfg(target_os = "linux")]
pub(super) fn note_route_query() {
    ROUTE_QUERIES.with(|count| count.set(count.get().saturating_add(1)));
}

#[cfg(target_os = "linux")]
fn take_route_queries() -> usize {
    ROUTE_QUERIES.with(|count| count.replace(0))
}

const SIZES: [usize; 5] = [128, 256, 257, 512, 1024];
const HOT_KEYS: usize = 64;
const ROUNDS: usize = 16;

#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
enum Trace {
    RoundRobin,
    HotCold,
}

fn keys(size: usize, ipv6: bool) -> Vec<RouteKey> {
    (0..size)
        .map(|i| RouteKey {
            local: if ipv6 {
                "[2001:db8:ffff::1]:862"
            } else {
                "192.0.2.1:862"
            }
            .parse()
            .unwrap(),
            target: SocketAddr::new(
                if ipv6 {
                    IpAddr::V6(Ipv6Addr::from(
                        u128::from("2001:db8::1".parse::<Ipv6Addr>().unwrap()) + i as u128,
                    ))
                } else {
                    IpAddr::V4(Ipv4Addr::from(
                        u32::from(Ipv4Addr::new(198, 18, 0, 1)) + i as u32,
                    ))
                },
                5000,
            ),
            tos: 184,
            oif: 0,
        })
        .collect()
}

fn requests(size: usize, trace: Trace, rounds: usize) -> Vec<usize> {
    match trace {
        Trace::RoundRobin => (0..size * rounds).map(|i| i % size).collect(),
        Trace::HotCold => {
            let mut indices = Vec::with_capacity((size - HOT_KEYS) * rounds * 9);
            let mut hot = 0;
            for i in 0..(size - HOT_KEYS) * rounds {
                for _ in 0..8 {
                    indices.push(hot);
                    hot = (hot + 1) % HOT_KEYS;
                }
                indices.push(HOT_KEYS + i % (size - HOT_KEYS));
            }
            indices
        }
    }
}

fn synthetic_mtu(key: &RouteKey) -> u32 {
    let suffix = match key.target.ip() {
        IpAddr::V4(ip) => u128::from(u32::from(ip)),
        IpAddr::V6(ip) => u128::from(ip),
    };
    1280 + (suffix % 1024) as u32
}

#[derive(Serialize)]
struct CacheSample {
    destinations: usize,
    ipv6: bool,
    trace: Trace,
    repeat: usize,
    requests: usize,
    queries: usize,
    hits: usize,
    warmup_queries: usize,
    peak_entries: usize,
    final_entries: usize,
    checksum: u64,
    elapsed_ns: u64,
}

fn cache_sample(
    size: usize,
    ipv6: bool,
    trace: Trace,
    rounds: usize,
    repeat: usize,
) -> CacheSample {
    let keys = keys(size, ipv6);
    let indices = requests(size, trace, rounds);
    let expected_mtus: Vec<_> = indices.iter().map(|&i| synthetic_mtu(&keys[i])).collect();
    let expected: u64 = expected_mtus.iter().map(|&mtu| u64::from(mtu)).sum();
    let mut cache = MtuCache::default();
    // Freeze lookup time to isolate capacity policy from TTL expiry. Real wall
    // time still measures the complete batch, including counters/checksum work.
    let now = Instant::now();
    let mut warmup_queries = 0;
    for key in &keys {
        cache
            .lookup(key.clone(), now, false, |key| {
                warmup_queries += 1;
                Ok(synthetic_mtu(key))
            })
            .unwrap();
    }
    let mut queries = 0;
    let mut peak_entries = cache.entries.len();
    let mut checksum = 0u64;
    let mut all_valid = true;
    let started = Instant::now();
    for (&index, &expected_mtu) in indices.iter().zip(&expected_mtus) {
        let mtu = cache
            .lookup(black_box(keys[index].clone()), now, false, |key| {
                queries += 1;
                Ok(black_box(synthetic_mtu(key)))
            })
            .unwrap();
        checksum += u64::from(mtu);
        all_valid &= mtu == expected_mtu;
        peak_entries = peak_entries.max(cache.entries.len());
    }
    let elapsed_ns = u64::try_from(started.elapsed().as_nanos()).unwrap();
    black_box(checksum);
    assert!(all_valid);
    assert_eq!(checksum, expected);
    assert_eq!(warmup_queries, size);
    assert!(peak_entries <= CACHE_LIMIT && queries <= indices.len());
    CacheSample {
        destinations: size,
        ipv6,
        trace,
        repeat,
        requests: indices.len(),
        queries,
        hits: indices.len() - queries,
        warmup_queries,
        peak_entries,
        final_entries: cache.entries.len(),
        checksum,
        elapsed_ns,
    }
}

fn require_release() -> Result<(), &'static str> {
    if cfg!(debug_assertions) {
        Err("run this ignored measurement with --release")
    } else {
        Ok(())
    }
}

fn report(kind: &str, samples: impl Serialize) {
    let executable = std::env::current_exe().unwrap();
    println!(
        "MTU_BENCH_JSON {}",
        serde_json::to_string(&json!({
            "schema_version": 1, "completed": true, "kind": kind,
            "os":std::env::consts::OS, "arch":std::env::consts::ARCH,
            "debug_build":cfg!(debug_assertions),
            "cache_limit":CACHE_LIMIT, "cache_ttl_ms":CACHE_TTL.as_millis(),
            "binary_sha256":hex::encode(Sha256::digest(std::fs::read(executable).unwrap())),
            "driver_source_sha256":hex::encode(Sha256::digest(include_bytes!("benchmarks.rs"))),
            "cache_source_sha256":hex::encode(Sha256::digest(include_bytes!("../mtu.rs"))),
            "features":{"metrics":cfg!(feature="metrics"), "control":cfg!(feature="control"),
                "ttl_pnet":cfg!(feature="ttl-pnet"), "ttl_nix":cfg!(feature="ttl-nix"),
                "snmp":cfg!(feature="snmp"), "hwtstamp":cfg!(feature="hwtstamp")},
            "samples":samples
        }))
        .unwrap()
    );
}

#[test]
fn capacity_trace_fixtures_preserve_identity_results_and_bounds() {
    for ipv6 in [false, true] {
        for size in SIZES {
            let keys = keys(size, ipv6);
            assert_eq!(
                keys.iter().collect::<std::collections::HashSet<_>>().len(),
                size
            );
            for trace in [Trace::RoundRobin, Trace::HotCold] {
                let indices = requests(size, trace, 2);
                assert!(indices.iter().all(|&i| i < size));
                assert_eq!(
                    indices
                        .iter()
                        .copied()
                        .collect::<std::collections::HashSet<_>>()
                        .len(),
                    size
                );
                let sample = cache_sample(size, ipv6, trace, 2, 0);
                assert_eq!(sample.requests, sample.queries + sample.hits);
                if size <= CACHE_LIMIT {
                    assert_eq!(sample.queries, 0);
                }
            }
        }
    }
}

#[test]
#[ignore = "manual release-only MTU cache capacity measurement"]
fn capacity_scaling() -> Result<(), &'static str> {
    require_release()?;
    let mut samples = Vec::with_capacity(SIZES.len() * 2 * 2 * 3);
    for repeat in 0..3 {
        for ipv6 in [false, true] {
            for size in SIZES {
                for trace in [Trace::RoundRobin, Trace::HotCold] {
                    samples.push(cache_sample(size, ipv6, trace, ROUNDS, repeat));
                }
            }
        }
    }
    report("synthetic_capacity_fixed_time", samples);
    Ok(())
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "manual release-only cache lookup with real loopback route queries"]
fn loopback_capacity() -> Result<(), Box<dyn std::error::Error>> {
    require_release()?;
    let options = SendOptions {
        apply_tos: true,
        egress_ifindex: None,
        tos: 184,
        source: None,
        srh: None,
        dont_fragment: true,
    };
    let mut samples = Vec::new();
    for repeat in 0..3 {
        for ipv6 in [false, true] {
            for size in SIZES {
                let mut keys = keys(size, ipv6);
                for (i, key) in keys.iter_mut().enumerate() {
                    key.local = if ipv6 { "[::1]:862" } else { "127.0.0.1:862" }.parse()?;
                    key.target = if ipv6 {
                        SocketAddr::new(Ipv6Addr::LOCALHOST.into(), 5000 + i as u16)
                    } else {
                        SocketAddr::new(
                            Ipv4Addr::from(u32::from(Ipv4Addr::LOCALHOST) + i as u32).into(),
                            5000,
                        )
                    };
                }
                for trace in [Trace::RoundRobin, Trace::HotCold] {
                    let indices = requests(size, trace, 4);
                    let mut cache = MtuCache::default();
                    take_route_queries();
                    let expected =
                        cache.payload_cap(keys[0].local, keys[0].target, &options, true)?;
                    for key in &keys {
                        if cache.payload_cap(key.local, key.target, &options, false)? != expected {
                            return Err("loopback payload cap changed during warmup".into());
                        }
                    }
                    let warmup_queries = take_route_queries();
                    if cache.notifications.is_none() {
                        return Err("route notification subscription unavailable".into());
                    }
                    let mut peak_entries = cache.entries.len();
                    let mut checksum = 0u64;
                    let mut all_valid = true;
                    let started = Instant::now();
                    for &i in &indices {
                        let cap = cache.payload_cap(
                            keys[i].local,
                            keys[i].target,
                            black_box(&options),
                            false,
                        )?;
                        all_valid &= cap == expected;
                        checksum += cap as u64;
                        peak_entries = peak_entries.max(cache.entries.len());
                    }
                    let elapsed_ns = u64::try_from(started.elapsed().as_nanos())?;
                    let queries = take_route_queries();
                    if !all_valid
                        || checksum != indices.len() as u64 * expected as u64
                        || peak_entries > CACHE_LIMIT
                        || queries > indices.len()
                    {
                        return Err("live cache result or accounting diverged".into());
                    }
                    samples.push(CacheSample {
                        destinations: size,
                        ipv6,
                        trace,
                        repeat,
                        requests: indices.len(),
                        queries,
                        hits: indices.len() - queries,
                        warmup_queries,
                        peak_entries,
                        final_entries: cache.entries.len(),
                        checksum,
                        elapsed_ns,
                    });
                }
            }
        }
    }
    report("linux_loopback_capacity_real_time", samples);
    Ok(())
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "manual release-only Linux loopback route-query calibration"]
fn loopback_route_queries() -> Result<(), Box<dyn std::error::Error>> {
    require_release()?;
    let mut samples = Vec::new();
    for repeat in 0..3 {
        for (local, target) in [
            ("0.0.0.0:862", "127.0.0.1:5000"),
            ("127.0.0.1:862", "127.0.0.1:5000"),
            ("[::]:862", "[::1]:5000"),
            ("[::1]:862", "[::1]:5000"),
        ] {
            let key = RouteKey {
                local: local.parse()?,
                target: target.parse()?,
                tos: 184,
                oif: 0,
            };
            let mut latencies = Vec::with_capacity(1000);
            let expected = route_mtu(&key)?;
            if expected < 1280 {
                return Err("loopback route MTU is below fixture minimum".into());
            }
            for _ in 0..1000 {
                let started = Instant::now();
                let mtu = route_mtu(black_box(&key))?;
                let elapsed = u64::try_from(started.elapsed().as_nanos())?;
                if mtu != expected {
                    return Err("loopback MTU changed during calibration".into());
                }
                latencies.push(elapsed);
            }
            let mut sorted = latencies.clone();
            sorted.sort_unstable();
            samples.push(json!({"repeat":repeat, "local":local, "target":target,
                "queries":latencies.len(), "mtu":expected, "min_ns":sorted[0],
                "p50_ns":sorted[499], "p99_ns":sorted[989], "max_ns":sorted[999],
                "latencies_ns":latencies}));
        }
    }
    report("linux_loopback_direct_route_query", samples);
    Ok(())
}
