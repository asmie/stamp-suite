//! One-shot expiry with concurrent refresh or admission. No sockets or packets.
//! Kept inside the test build so synthetic activity ages need no runtime API.

use super::*;
use crate::stats::{RttCollector, RttSample};
use serde_json::{json, Value};
use std::{net::Ipv6Addr, sync::mpsc, thread};

const LIVE_TIMEOUT: Duration = Duration::from_secs(60);
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);

fn key(index: usize, ipv6: bool) -> SessionKey {
    let client = if ipv6 {
        SocketAddr::new(
            Ipv6Addr::from(0x20010db8000000000000000000000001 + index as u128).into(),
            10_000,
        )
    } else {
        SocketAddr::new(
            std::net::Ipv4Addr::from(0xc6120001 + index as u32).into(),
            10_000,
        )
    };
    SessionKey {
        client,
        local: if ipv6 {
            "[2001:db8:ffff::1]:862"
        } else {
            "192.0.2.1:862"
        }
        .parse()
        .unwrap(),
        ssid: 7,
        sender_micro_session_id: None,
    }
}

struct Fixture {
    manager: SessionManager,
    ids: Vec<u32>,
    expired: usize,
    ipv6: bool,
    probe: SessionKey,
    probe_id: u32,
}

impl Fixture {
    fn new(sessions: usize, expired_percent: usize, ipv6: bool) -> Self {
        assert!(sessions > 0 && sessions <= 65_536);
        assert!(expired_percent <= 100);
        let mut manager = SessionManager::new(Some(LIVE_TIMEOUT), Some(sessions + 1));
        // Live entries receive genuine current offsets. Only expired entries are
        // backdated, well away from the timeout boundary; no aging sleeps needed.
        manager.epoch = Instant::now().checked_sub(LIVE_TIMEOUT * 2).unwrap();
        let ids = (0..sessions)
            .map(|i| {
                manager
                    .get_or_create_session(key(i, ipv6))
                    .unwrap()
                    .get_id()
            })
            .collect();
        let expired = sessions * expired_percent / 100;
        {
            let table = manager.sessions.read().unwrap();
            for i in 0..expired {
                table[&key(i, ipv6)].last_active.store(0, Ordering::Relaxed);
            }
        }
        // A separate persistent identity prevents the producer refreshing an
        // expiry candidate. "100% expired" refers to the N seeded entries.
        let probe = key(sessions, ipv6);
        let probe_id = manager.get_or_create_session(probe).unwrap().get_id();
        Self {
            manager,
            ids,
            expired,
            ipv6,
            probe,
            probe_id,
        }
    }

    fn validate(&self, removed: usize) {
        assert_eq!(removed, self.expired);
        assert_eq!(
            self.manager.session_count(),
            self.ids.len() - self.expired + 1
        );
        for (i, id) in self.ids.iter().enumerate() {
            let session = self.manager.get_session(key(i, self.ipv6));
            if i < self.expired {
                assert!(session.is_none());
            } else {
                let session = session.unwrap();
                assert_eq!(session.get_id(), *id);
                assert!(session.transmission_guard().is_some());
            }
        }
        assert_eq!(
            self.manager.get_session(self.probe).unwrap().get_id(),
            self.probe_id
        );
    }
}

#[derive(Default)]
struct Samples {
    collector: RttCollector,
    count: u64,
    max_ns: u64,
    longest_call: Option<(Instant, Instant)>,
    at_least_1ms: u64,
    at_least_10ms: u64,
}

impl Samples {
    fn record(&mut self, (started, finished): (Instant, Instant)) {
        let ns = u64::try_from(finished.duration_since(started).as_nanos()).unwrap();
        self.collector.record(RttSample {
            seq: 0,
            rtt_ns: ns,
            ttl: 0,
        });
        self.count += 1;
        if self.longest_call.is_none() || ns > self.max_ns {
            self.max_ns = ns;
            self.longest_call = Some((started, finished));
        }
        self.at_least_1ms += u64::from(ns >= 1_000_000);
        self.at_least_10ms += u64::from(ns >= 10_000_000);
    }

    fn report(&self) -> Value {
        json!({
            "calls": self.count,
            "max_ns": self.max_ns,
            "p50_ns": self.collector.percentile_ns(50.0),
            "p95_ns": self.collector.percentile_ns(95.0),
            "p99_ns": self.collector.percentile_ns(99.0),
            "at_least_1ms": self.at_least_1ms,
            "at_least_10ms": self.at_least_10ms,
            "quantile_precision": self.collector.snapshot(self.count, 0).quantile_precision,
        })
    }

    fn overlap(&self, started: Instant, finished: Instant) -> u64 {
        self.longest_call
            .map_or(0, |(call_started, call_finished)| {
                call_finished
                    .min(finished)
                    .saturating_duration_since(call_started.max(started))
                    .as_nanos() as u64
            })
    }
}

#[derive(Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
enum Probe {
    Refresh,
    Admission,
}

struct Observation {
    acquisition: (Instant, Instant),
    retirement: Option<(Instant, Instant)>,
    cycle: (Instant, Instant),
}

#[derive(Default)]
struct ProbeSamples {
    acquisition: Samples,
    retirement: Samples,
    cycle: Samples,
    first_cycle: Option<Instant>,
    last_cycle: Option<Instant>,
}

impl ProbeSamples {
    fn record(&mut self, observation: Observation) {
        self.acquisition.record(observation.acquisition);
        if let Some(retirement) = observation.retirement {
            self.retirement.record(retirement);
            self.cycle.record(observation.cycle);
            self.first_cycle.get_or_insert(observation.cycle.0);
            self.last_cycle = Some(observation.cycle.1);
        }
    }

    fn window_ns(&self) -> u64 {
        self.first_cycle
            .zip(self.last_cycle)
            .map_or(0, |(start, end)| {
                end.duration_since(start).as_nanos() as u64
            })
    }

    fn cycles_per_second(&self) -> Option<f64> {
        let ns = self.window_ns();
        (ns > 0).then(|| self.cycle.count as f64 * 1_000_000_000.0 / ns as f64)
    }
}

struct StopOnDrop<'a>(&'a AtomicBool);
impl Drop for StopOnDrop<'_> {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Release);
    }
}

fn trial(sessions: usize, percent: usize, ipv6: bool, guard_delay: Duration) -> Value {
    trial_with_probe(sessions, percent, ipv6, guard_delay, Probe::Refresh)
}

fn trial_with_probe(
    sessions: usize,
    percent: usize,
    ipv6: bool,
    guard_delay: Duration,
    probe: Probe,
) -> Value {
    trial_with_inventory(sessions, percent, ipv6, guard_delay, probe, false)
}

fn trial_with_inventory(
    sessions: usize,
    percent: usize,
    ipv6: bool,
    guard_delay: Duration,
    probe: Probe,
    indexed: bool,
) -> Value {
    let fixture = Fixture::new(sessions, percent, ipv6);
    #[cfg(feature = "control")]
    if indexed {
        fixture.manager.enable_session_inventory().unwrap();
    }
    #[cfg(not(feature = "control"))]
    assert!(!indexed);
    let mut transient = fixture.probe;
    transient.client.set_port(10_001);
    if probe == Probe::Admission {
        // Reserve exactly one slot beyond the seeded table and live probe.
        fixture.manager.set_max_sessions(sessions + 2);
    }
    assert!(guard_delay.is_zero() || fixture.expired > 0);
    let stop = AtomicBool::new(false);
    let guarded_session =
        (!guard_delay.is_zero()).then(|| fixture.manager.get_session(key(0, ipv6)).unwrap());
    let operation = |previous_id: &mut Option<u32>| {
        let started = Instant::now();
        let session = fixture
            .manager
            .get_or_create_session(if probe == Probe::Admission {
                transient
            } else {
                fixture.probe
            })
            .unwrap();
        let id = session.get_id();
        if probe == Probe::Refresh {
            drop(session);
            let finished = Instant::now();
            assert_eq!(id, fixture.probe_id);
            return Observation {
                acquisition: (started, finished),
                retirement: None,
                cycle: (started, finished),
            };
        }
        let acquired = Instant::now();
        assert_ne!(
            Some(id),
            *previous_id,
            "each admission must create fresh state"
        );
        assert_eq!(session.peek_sequence_number(), 0);
        assert_eq!(session.get_received_count(), 0);
        assert_eq!(session.get_transmitted_count(), 0);
        *previous_id = Some(id);
        let retiring = Instant::now();
        let removed = fixture
            .manager
            .expire_matching(transient.client, Some(id))
            .unwrap();
        let retired = Instant::now();
        assert!(removed);
        assert!(session.transmission_guard().is_none());
        drop(session);
        Observation {
            acquisition: (started, acquired),
            retirement: Some((retiring, retired)),
            cycle: (started, Instant::now()),
        }
    };
    let (removed, cleanup_ns, baseline, concurrent, guard_release_ns) = thread::scope(|scope| {
        let (ready_tx, ready_rx) = mpsc::sync_channel(0);
        let (go_tx, go_rx) = mpsc::sync_channel(0);
        let stop_ref = &stop;
        let producer = scope.spawn(move || {
            let mut previous_id = None;
            let mut baseline = ProbeSamples::default();
            for _ in 0..32 {
                baseline.record(operation(&mut previous_id));
            }
            ready_tx.send(()).unwrap();
            go_rx.recv_timeout(HANDSHAKE_TIMEOUT).unwrap();
            let mut concurrent = ProbeSamples::default();
            // Always issue at least one call, even when cleanup finishes before
            // this thread is scheduled. Its latency is not proof of overlap.
            loop {
                concurrent.record(operation(&mut previous_id));
                if stop_ref.load(Ordering::Acquire) {
                    break;
                }
            }
            (baseline, concurrent)
        });
        let stop_on_drop = StopOnDrop(&stop);
        ready_rx.recv_timeout(HANDSHAKE_TIMEOUT).unwrap();
        let (guard_ready_tx, guard_ready_rx) = mpsc::sync_channel(0);
        let (release_tx, release_rx) = mpsc::sync_channel::<Instant>(0);
        let holder = guarded_session.as_ref().map(|session| {
            scope.spawn(move || {
                let guard = session.transmission_guard().unwrap();
                guard_ready_tx.send(()).unwrap();
                let started = release_rx.recv_timeout(HANDSHAKE_TIMEOUT).unwrap();
                thread::sleep(guard_delay);
                drop(guard);
                started.elapsed().as_nanos() as u64
            })
        });
        if holder.is_some() {
            guard_ready_rx.recv_timeout(HANDSHAKE_TIMEOUT).unwrap();
        }
        // Reject a fixture delayed long enough for retained entries to age out.
        assert!(fixture.manager.epoch.elapsed() < LIVE_TIMEOUT * 2 + LIVE_TIMEOUT / 2);
        go_tx.send(()).unwrap();
        let started = Instant::now();
        if holder.is_some() {
            release_tx.send(started).unwrap();
        }
        let cleanup_started = Instant::now();
        let removed = fixture.manager.cleanup_stale_sessions();
        let cleanup_finished = Instant::now();
        let cleanup_ns = cleanup_finished.duration_since(cleanup_started).as_nanos() as u64;
        drop(stop_on_drop);
        let (baseline, concurrent) = producer.join().unwrap();
        let guard_release_ns = holder.map(|holder| holder.join().unwrap());
        if let Some(session) = &guarded_session {
            assert!(session.transmission_guard().is_none());
        }
        let overlap_ns = [
            concurrent
                .acquisition
                .overlap(cleanup_started, cleanup_finished),
            concurrent
                .retirement
                .overlap(cleanup_started, cleanup_finished),
            concurrent.cycle.overlap(cleanup_started, cleanup_finished),
        ];
        (
            removed,
            cleanup_ns,
            baseline,
            (concurrent, overlap_ns),
            guard_release_ns,
        )
    });
    fixture.validate(removed);
    assert!(fixture.manager.get_session(transient).is_none());
    if probe == Probe::Admission {
        assert_eq!(baseline.acquisition.count, baseline.retirement.count);
        assert_eq!(
            concurrent.0.acquisition.count,
            concurrent.0.retirement.count
        );
        assert_eq!(concurrent.0.acquisition.count, concurrent.0.cycle.count);
    }
    let mut report = json!({
        "probe": probe,
        "indexed_inventory": indexed,
        "seeded_sessions": sessions, "expired_percent": percent, "ipv6": ipv6,
        "guard_requested_ns": guard_delay.as_nanos() as u64,
        "guard_release_from_start_ns": guard_release_ns,
        "removed": removed, "remaining_including_probe": fixture.manager.session_count(),
        "cleanup_call_ns": cleanup_ns,
    });
    if probe == Probe::Refresh {
        report["baseline_refresh"] = baseline.acquisition.report();
        report["concurrent_refresh"] = concurrent.0.acquisition.report();
        report["longest_refresh_overlap_with_cleanup_ns"] = json!(concurrent.1[0]);
    } else {
        report["session_cap"] = json!(fixture.manager.max_sessions());
        report["baseline_admission"] = baseline.acquisition.report();
        report["baseline_retirement"] = baseline.retirement.report();
        report["baseline_cycle"] = baseline.cycle.report();
        report["concurrent_admission"] = concurrent.0.acquisition.report();
        report["concurrent_retirement"] = concurrent.0.retirement.report();
        report["concurrent_cycle"] = concurrent.0.cycle.report();
        report["baseline_cycle_window_ns"] = json!(baseline.window_ns());
        report["baseline_cycles_per_second"] = json!(baseline.cycles_per_second());
        report["concurrent_cycle_window_ns"] = json!(concurrent.0.window_ns());
        report["concurrent_cycles_per_second"] = json!(concurrent.0.cycles_per_second());
        report["longest_admission_overlap_with_cleanup_ns"] = json!(concurrent.1[0]);
        report["longest_retirement_overlap_with_cleanup_ns"] = json!(concurrent.1[1]);
        report["longest_cycle_overlap_with_cleanup_ns"] = json!(concurrent.1[2]);
    }
    report
}

#[cfg(feature = "control")]
#[test]
fn indexed_expiry_fixtures_preserve_state_during_refresh_and_admission() {
    for ipv6 in [false, true] {
        for percent in [0, 1, 50, 75, 99, 100] {
            for probe in [Probe::Refresh, Probe::Admission] {
                trial_with_inventory(100, percent, ipv6, Duration::ZERO, probe, true);
            }
        }
        for probe in [Probe::Refresh, Probe::Admission] {
            trial_with_inventory(16, 100, ipv6, Duration::from_millis(1), probe, true);
        }
    }
}

#[cfg(feature = "control")]
#[test]
#[ignore = "manual release measurement; see doc/benchmarks.md"]
fn indexed_expiry_measurements() -> Result<(), Box<dyn std::error::Error>> {
    if cfg!(debug_assertions) {
        return Err("measurements require --release".into());
    }
    let mut sequential = Vec::new();
    let mut concurrent = Vec::new();
    for sessions in [1_024, 16_384, 65_536] {
        for ipv6 in [false, true] {
            for percent in [0, 1, 50, 75, 99, 100] {
                for repeat in 0..5 {
                    let fixture = Fixture::new(sessions, percent, ipv6);
                    fixture.manager.enable_session_inventory()?;
                    let start = Instant::now();
                    let removed = fixture.manager.cleanup_stale_sessions();
                    let elapsed = start.elapsed().as_nanos() as u64;
                    fixture.validate(removed);
                    sequential.push(json!({"sessions":sessions,"ipv6":ipv6,
                        "expired_percent":percent,"repeat":repeat,"cleanup_ns":elapsed}));
                }
                if ![1, 50, 99, 100].contains(&percent) {
                    continue;
                }
                for probe in [Probe::Refresh, Probe::Admission] {
                    for delay_ms in [0, 10] {
                        for repeat in 0..3 {
                            let mut row = trial_with_inventory(
                                sessions,
                                percent,
                                ipv6,
                                Duration::from_millis(delay_ms),
                                probe,
                                true,
                            );
                            row["repeat"] = json!(repeat);
                            concurrent.push(row);
                        }
                    }
                }
            }
        }
    }
    println!(
        "INDEXED_EXPIRY_JSON={}",
        json!({"schema_version":1,
        "scope":"indexed one-shot expiry; sequential and closed-loop refresh/admission; no packets",
        "features":{"control":cfg!(feature="control"),"metrics":cfg!(feature="metrics"),
            "ttl_pnet":cfg!(feature="ttl-pnet"),"ttl_nix":cfg!(feature="ttl-nix")},
        "sequential":sequential,"concurrent":concurrent})
    );
    Ok(())
}

#[test]
fn expiry_fixture_preserves_live_ids_and_retires_old_handles() {
    for ipv6 in [false, true] {
        for percent in [0, 50, 100] {
            let fixture = Fixture::new(16, percent, ipv6);
            assert!(fixture
                .manager
                .get_or_create_session(key(17, ipv6))
                .is_none());
            let old = fixture.manager.get_session(key(0, ipv6)).unwrap();
            let removed = fixture.manager.cleanup_stale_sessions();
            fixture.validate(removed);
            assert_eq!(old.transmission_guard().is_none(), percent > 0);
            if percent > 0 {
                fixture.manager.set_draining(true);
                assert!(fixture
                    .manager
                    .get_or_create_session(key(0, ipv6))
                    .is_none());
                fixture.manager.set_draining(false);
                let replacement = fixture.manager.get_or_create_session(key(0, ipv6)).unwrap();
                assert_ne!(replacement.get_id(), old.get_id());
                assert!(replacement.transmission_guard().is_some());
                assert!(old.transmission_guard().is_none());
            }
        }
    }
}

#[test]
fn concurrent_expiry_fixtures_complete_without_latency_thresholds() {
    for ipv6 in [false, true] {
        for percent in [0, 50, 100] {
            trial(16, percent, ipv6, Duration::ZERO);
            if percent > 0 {
                trial(16, percent, ipv6, Duration::from_millis(1));
            }
        }
    }
}

#[test]
fn concurrent_admission_expiry_preserves_capacity_and_fresh_state() {
    for ipv6 in [false, true] {
        for percent in [0, 50, 100] {
            for delay_ms in [0, 1] {
                if percent == 0 && delay_ms != 0 {
                    continue;
                }
                let report = trial_with_probe(
                    16,
                    percent,
                    ipv6,
                    Duration::from_millis(delay_ms),
                    Probe::Admission,
                );
                assert_eq!(report["session_cap"], 18);
                assert_eq!(report["baseline_admission"]["calls"], 32);
                assert_eq!(report["baseline_cycle"]["calls"], 32);
                assert!(report["concurrent_admission"]["calls"].as_u64().unwrap() > 0);
            }
        }
    }
}

#[test]
#[ignore = "manual release measurement; see doc/benchmarks.md"]
fn expiry_admission_measurements() -> Result<(), Box<dyn std::error::Error>> {
    if cfg!(debug_assertions) {
        return Err("measurements require --release".into());
    }
    let mut trials = Vec::new();
    for sessions in [1_024, 16_384, 65_536] {
        for ipv6 in [false, true] {
            for percent in [0, 50, 100] {
                for delay_ms in [0, 10] {
                    if percent == 0 && delay_ms != 0 {
                        continue;
                    }
                    for repeat in 0..3 {
                        let mut result = trial_with_probe(
                            sessions,
                            percent,
                            ipv6,
                            Duration::from_millis(delay_ms),
                            Probe::Admission,
                        );
                        result["repeat"] = json!(repeat);
                        trials.push(result);
                    }
                }
            }
        }
    }
    println!(
        "EXPIRY_ADMISSION_JSON={}",
        json!({
            "schema_version": 1,
            "scope": "one-shot expiry with closed-loop bounded admission/control-retirement cycles; no packets",
            "ttl_pnet": cfg!(feature = "ttl-pnet"), "ttl_nix": cfg!(feature = "ttl-nix"),
            "snmp": cfg!(feature = "snmp"), "trials": trials,
        })
    );
    Ok(())
}

#[test]
#[ignore = "manual release measurement; see doc/benchmarks.md"]
fn expiry_contention_measurements() -> Result<(), Box<dyn std::error::Error>> {
    if cfg!(debug_assertions) {
        return Err("measurements require --release".into());
    }
    let mut trials = Vec::new();
    for sessions in [1_024, 16_384, 65_536] {
        for ipv6 in [false, true] {
            for percent in [0, 50, 100] {
                for delay_ms in [0, 10] {
                    if percent == 0 && delay_ms != 0 {
                        continue;
                    }
                    for repeat in 0..3 {
                        let mut result =
                            trial(sessions, percent, ipv6, Duration::from_millis(delay_ms));
                        result["repeat"] = json!(repeat);
                        trials.push(result);
                    }
                }
            }
        }
    }
    println!(
        "EXPIRY_CONTENTION_JSON={}",
        json!({
            "schema_version": 1,
            "scope": "one-shot cleanup and closed-loop persistent-identity refresh; no packets",
        "ttl_pnet": cfg!(feature = "ttl-pnet"),
        "ttl_nix": cfg!(feature = "ttl-nix"),
        "snmp": cfg!(feature = "snmp"),
            "trials": trials,
        })
    );
    Ok(())
}
