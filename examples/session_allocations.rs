//! Allocation requests made by session-table operations, without network I/O.
//! This executable alone wraps System; the application allocator is unchanged.

use std::{
    alloc::{GlobalAlloc, Layout, System},
    cell::Cell,
    error::Error,
    fs,
    hint::black_box,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    process::Command,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use clap::{Parser, ValueEnum};
use serde::Serialize;
use serde_json::json;
use sha2::{Digest, Sha256};
use stamp_suite::session::{SessionKey, SessionManager};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
struct Counts {
    alloc_calls: u64,
    alloc_zeroed_calls: u64,
    realloc_calls: u64,
    dealloc_calls: u64,
    allocated_bytes: u64,
    deallocated_bytes: u64,
    reallocated_from_bytes: u64,
    reallocated_to_bytes: u64,
    failed_requests: u64,
}

impl Counts {
    fn requested_bytes_delta(self) -> i128 {
        i128::from(self.allocated_bytes) + i128::from(self.reallocated_to_bytes)
            - i128::from(self.deallocated_bytes)
            - i128::from(self.reallocated_from_bytes)
    }
}

thread_local! {
    // Const, destructor-free TLS: accessing this slot does not allocate.
    static ACTIVE: Cell<Option<Counts>> = const { Cell::new(None) };
}

fn record(update: impl FnOnce(&mut Counts)) {
    // Allocator callbacks must not allocate or unwind. try_with also tolerates
    // allocations made after this thread's TLS is unavailable during teardown.
    let _ = ACTIVE.try_with(|slot| {
        if let Some(mut counts) = slot.get() {
            update(&mut counts);
            slot.set(Some(counts));
        }
    });
}

fn add(total: &mut u64, amount: usize) {
    *total = total.saturating_add(amount as u64);
}

struct CountedSystem;

// SAFETY: All pointers, layouts and sizes are forwarded unchanged to System.
// Accounting uses only destructor-free TLS, Cell and saturating arithmetic;
// it neither allocates, dereferences user pointers nor unwinds.
unsafe impl GlobalAlloc for CountedSystem {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: The caller supplies the layout required by GlobalAlloc.
        let ptr = unsafe { System.alloc(layout) };
        record(|c| {
            if ptr.is_null() {
                add(&mut c.failed_requests, 1);
            } else {
                add(&mut c.alloc_calls, 1);
                add(&mut c.allocated_bytes, layout.size());
            }
        });
        ptr
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        // SAFETY: The caller supplies the layout required by GlobalAlloc.
        let ptr = unsafe { System.alloc_zeroed(layout) };
        record(|c| {
            if ptr.is_null() {
                add(&mut c.failed_requests, 1);
            } else {
                add(&mut c.alloc_zeroed_calls, 1);
                add(&mut c.allocated_bytes, layout.size());
            }
        });
        ptr
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        // SAFETY: The caller provides a live System pointer, its original
        // layout and a valid nonzero replacement size, as GlobalAlloc requires.
        let resized = unsafe { System.realloc(ptr, layout, new_size) };
        record(|c| {
            if resized.is_null() {
                add(&mut c.failed_requests, 1);
            } else {
                add(&mut c.realloc_calls, 1);
                add(&mut c.reallocated_from_bytes, layout.size());
                add(&mut c.reallocated_to_bytes, new_size);
            }
        });
        resized
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: The pointer and matching layout come from this allocator.
        unsafe { System.dealloc(ptr, layout) };
        record(|c| {
            add(&mut c.dealloc_calls, 1);
            add(&mut c.deallocated_bytes, layout.size());
        });
    }
}

#[global_allocator]
static ALLOCATOR: CountedSystem = CountedSystem;

struct DisableOnDrop;
impl Drop for DisableOnDrop {
    fn drop(&mut self) {
        ACTIVE.with(|slot| slot.set(None));
    }
}

fn measure<T>(operation: impl FnOnce() -> T) -> (T, Counts) {
    ACTIVE.with(|slot| {
        assert!(slot.get().is_none(), "allocation measurements cannot nest");
        slot.set(Some(Counts::default()));
    });
    let guard = DisableOnDrop;
    let result = operation();
    let counts = ACTIVE.with(|slot| slot.get().expect("measurement disabled prematurely"));
    drop(guard);
    (result, counts)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, ValueEnum)]
#[serde(rename_all = "snake_case")]
enum Workload {
    LookupRefresh,
    Inventory,
    CleanupKeep,
    CleanupExpire,
    ControlChurn,
}

#[derive(Parser, Serialize)]
#[command(about = "Count allocation requests for individual session-table operations")]
struct Args {
    #[arg(long, default_value_t = 16_384, value_parser = clap::value_parser!(u32).range(1..=65_536))]
    sessions: u32,
    #[arg(long)]
    ipv6: bool,
    #[arg(long, value_enum, default_value = "inventory")]
    workload: Workload,
    #[arg(long, default_value_t = 10, value_parser = clap::value_parser!(u32).range(1..=1_000))]
    iterations: u32,
}

fn key(index: usize, ipv6: bool) -> SessionKey {
    let (client, local) = if ipv6 {
        (
            IpAddr::V6(Ipv6Addr::from(
                u128::from("2001:db8::1".parse::<Ipv6Addr>().unwrap()) + index as u128,
            )),
            "[2001:db8:ffff::1]:862".parse().unwrap(),
        )
    } else {
        (
            IpAddr::V4(Ipv4Addr::from(
                u32::from(Ipv4Addr::new(198, 18, 0, 1)) + index as u32,
            )),
            "192.0.2.1:862".parse().unwrap(),
        )
    };
    SessionKey {
        client: SocketAddr::new(client, 10_000),
        local,
        ssid: 7,
        sender_micro_session_id: None,
    }
}

fn operation(
    manager: &SessionManager,
    selected: SessionKey,
    workload: Workload,
) -> Result<usize, &'static str> {
    match workload {
        Workload::LookupRefresh => {
            drop(black_box(
                manager
                    .get_or_create_session(black_box(selected))
                    .ok_or("known session rejected")?,
            ));
            Ok(1)
        }
        Workload::Inventory => {
            let rows = black_box(manager.session_summaries_extended());
            let count = rows.len();
            drop(black_box(rows));
            Ok(count)
        }
        Workload::CleanupKeep | Workload::CleanupExpire => {
            Ok(black_box(manager.cleanup_stale_sessions()))
        }
        Workload::ControlChurn => {
            if !manager.expire_matching(black_box(selected.client), None)? {
                return Err("control expiry did not remove its session");
            }
            drop(black_box(
                manager
                    .get_or_create_session(selected)
                    .ok_or("replacement rejected")?,
            ));
            Ok(1)
        }
    }
}

#[derive(Serialize)]
struct Sample {
    iteration: u32,
    counts: Counts,
    requested_bytes_delta: i128,
    observed_items: usize,
    final_sessions: usize,
}

fn run(args: &Args, samples: &mut Vec<Sample>) -> Result<(), &'static str> {
    let size = args.sessions as usize;
    let keys: Vec<_> = (0..size).map(|i| key(i, args.ipv6)).collect();
    for iteration in 0..args.iterations {
        let timeout = if args.workload == Workload::CleanupExpire {
            Duration::ZERO
        } else {
            Duration::MAX
        };
        let manager = SessionManager::new(Some(timeout), Some(size));
        for key in &keys {
            manager
                .get_or_create_session(*key)
                .ok_or("fixture admission rejected")?;
        }
        if manager.session_count() != size {
            return Err("invalid fixture population");
        }
        let selected = keys[(iteration as usize * 40_507) % size];
        let (observed, counts) = measure(|| operation(&manager, selected, args.workload));
        let observed = observed?;
        let expected = match args.workload {
            Workload::Inventory | Workload::CleanupExpire => size,
            Workload::CleanupKeep => 0,
            _ => 1,
        };
        let final_sessions = manager.session_count();
        let expected_sessions = if args.workload == Workload::CleanupExpire {
            0
        } else {
            size
        };
        if observed != expected || final_sessions != expected_sessions {
            return Err("operation result or final table size diverged");
        }
        // Saturation is practically unreachable with bounded inputs, but must
        // not silently turn truncated accounting into valid evidence.
        if counts.failed_requests != 0
            || [
                counts.alloc_calls,
                counts.alloc_zeroed_calls,
                counts.realloc_calls,
                counts.dealloc_calls,
                counts.allocated_bytes,
                counts.deallocated_bytes,
                counts.reallocated_from_bytes,
                counts.reallocated_to_bytes,
            ]
            .contains(&u64::MAX)
        {
            return Err("allocator request failed or accounting saturated");
        }
        samples.push(Sample {
            iteration,
            counts,
            requested_bytes_delta: counts.requested_bytes_delta(),
            observed_items: observed,
            final_sessions,
        });
        // Setup, result storage and manager/table destruction are uncounted.
    }
    Ok(())
}

fn main() -> Result<(), Box<dyn Error>> {
    let args = Args::parse();
    if cfg!(debug_assertions) {
        return Err("use a release build for allocation measurements".into());
    }
    let mut samples = Vec::with_capacity(args.iterations as usize);
    let mut report = json!({
        "schema_version": 1, "completed": false, "settings": args,
        "scope": "successful System allocation requests on the calling thread; no timing, RSS or network packets",
        "started_unix_seconds": SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
        "os": std::env::consts::OS, "arch": std::env::consts::ARCH,
        "debug_build": cfg!(debug_assertions),
        "git_head_at_run": Command::new("git").args(["rev-parse", "HEAD"]).output().ok()
            .filter(|o| o.status.success()).map(|o| String::from_utf8_lossy(&o.stdout).trim().to_owned()),
        "binary_sha256": hex::encode(Sha256::digest(fs::read(std::env::current_exe()?)?)),
        "source_sha256": hex::encode(Sha256::digest(include_bytes!("session_allocations.rs"))),
        "features": {"metrics":cfg!(feature="metrics"), "control":cfg!(feature="control"),
            "ttl_pnet":cfg!(feature="ttl-pnet"), "ttl_nix":cfg!(feature="ttl-nix"),
            "snmp":cfg!(feature="snmp"), "hwtstamp":cfg!(feature="hwtstamp")}
    });
    let result = run(&args, &mut samples);
    report["samples"] = serde_json::to_value(samples)?;
    report["completed"] = json!(result.is_ok());
    if let Err(error) = result {
        report["error"] = json!(error);
    }
    println!("{}", serde_json::to_string_pretty(&report)?);
    result.map_err(Into::into)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn allocation_round_trip() {
        // SAFETY: Nonzero layouts, checked pointers, initialized byte access,
        // matching deallocation layouts, and no access after realloc/dealloc.
        unsafe {
            let small = Layout::from_size_align(32, 8).unwrap();
            let zero = Layout::from_size_align(64, 8).unwrap();
            let ptr = ALLOCATOR.alloc(small);
            assert!(!ptr.is_null());
            ptr.write(42);
            let zeroed = ALLOCATOR.alloc_zeroed(zero);
            assert!(!zeroed.is_null());
            assert_eq!(zeroed.read(), 0);
            let resized = ALLOCATOR.realloc(ptr, small, 96);
            assert!(!resized.is_null());
            assert_eq!(resized.read(), 42);
            ALLOCATOR.dealloc(resized, Layout::from_size_align(96, 8).unwrap());
            ALLOCATOR.dealloc(zeroed, zero);
        }
    }

    #[test]
    fn allocator_counts_requests_sizes_and_reallocation_without_double_counting() {
        let (_, counts) = measure(allocation_round_trip);
        assert_eq!(
            counts,
            Counts {
                alloc_calls: 1,
                alloc_zeroed_calls: 1,
                realloc_calls: 1,
                dealloc_calls: 2,
                allocated_bytes: 96,
                deallocated_bytes: 160,
                reallocated_from_bytes: 32,
                reallocated_to_bytes: 96,
                failed_requests: 0
            }
        );
        assert_eq!(counts.requested_bytes_delta(), 0);
    }

    #[test]
    fn allocations_from_other_threads_are_excluded() {
        use std::sync::{
            atomic::{AtomicBool, Ordering},
            Arc,
        };
        let start = Arc::new(AtomicBool::new(false));
        let done = Arc::new(AtomicBool::new(false));
        let worker = {
            let start = Arc::clone(&start);
            let done = Arc::clone(&done);
            std::thread::spawn(move || {
                while !start.load(Ordering::Acquire) {
                    std::thread::yield_now();
                }
                let result = std::panic::catch_unwind(|| measure(allocation_round_trip));
                done.store(true, Ordering::Release);
                result
            })
        };
        let (_, counts) = measure(|| {
            start.store(true, Ordering::Release);
            while !done.load(Ordering::Acquire) {
                std::thread::yield_now();
            }
        });
        assert_eq!(counts, Counts::default());
        assert_eq!(worker.join().unwrap().unwrap().1.allocated_bytes, 96);
    }

    #[test]
    fn unwinding_restores_disabled_measurement() {
        assert!(std::panic::catch_unwind(|| measure(|| panic!("measurement failure"))).is_err());
        let (_, counts) = measure(allocation_round_trip);
        assert_eq!(counts.alloc_calls, 1);
        assert_eq!(counts.requested_bytes_delta(), 0);
    }

    #[test]
    fn workloads_preserve_results_and_table_bounds_in_both_families() {
        for ipv6 in [false, true] {
            let keys: std::collections::HashSet<_> = (0..65_536).map(|i| key(i, ipv6)).collect();
            assert_eq!(keys.len(), 65_536);
            for workload in [
                Workload::LookupRefresh,
                Workload::Inventory,
                Workload::CleanupKeep,
                Workload::CleanupExpire,
                Workload::ControlChurn,
            ] {
                let args = Args {
                    sessions: 16,
                    ipv6,
                    workload,
                    iterations: 2,
                };
                let mut samples = Vec::new();
                run(&args, &mut samples).unwrap();
                assert_eq!(samples.len(), 2);
                for sample in samples {
                    assert_eq!(sample.counts.failed_requests, 0);
                    assert_eq!(
                        sample.final_sessions,
                        if workload == Workload::CleanupExpire {
                            0
                        } else {
                            16
                        }
                    );
                }
            }
        }
    }

    #[test]
    fn cli_bounds_reject_empty_and_unbounded_workloads() {
        for args in [
            ["--sessions", "0"],
            ["--sessions", "65537"],
            ["--iterations", "0"],
            ["--iterations", "1001"],
        ] {
            assert!(Args::try_parse_from(["session_allocations", args[0], args[1]]).is_err());
        }
    }
}
