//! Closed-loop session-manager latency under concurrent management work.
//! No packets are sent. Scope and reproduction: doc/benchmarks.md.

use std::{
    error::Error,
    fs,
    hint::black_box,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    process::Command,
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc, Arc,
    },
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use clap::{Parser, ValueEnum};
use serde::Serialize;
use serde_json::json;
use sha2::{Digest, Sha256};
use stamp_suite::{
    session::{SessionKey, SessionManager},
    stats::{QuantilePrecision, RttCollector, RttSample},
};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, ValueEnum)]
#[serde(rename_all = "snake_case")]
enum Background {
    None,
    Inventory,
    Cleanup,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, ValueEnum)]
#[serde(rename_all = "snake_case")]
enum Probe {
    Refresh,
    Admission,
}

#[derive(Parser, Serialize)]
#[command(about = "Measure session-manager call latency with concurrent inventory or cleanup")]
struct Args {
    #[arg(long, default_value_t = 16_384, value_parser = clap::value_parser!(u32).range(1..=65_536))]
    sessions: u32,
    #[arg(long)]
    ipv6: bool,
    #[arg(long, value_enum, default_value = "refresh")]
    probe: Probe,
    #[arg(long, value_enum, default_value = "none")]
    background: Background,
    #[arg(long, default_value_t = 1, value_parser = clap::value_parser!(u32).range(1..=60))]
    seconds: u32,
    #[arg(long, default_value_t = 3, value_parser = clap::value_parser!(u32).range(1..=100))]
    repeats: u32,
    /// Pause after each management operation; zero requests continuous work.
    #[arg(long, default_value_t = 1_000, value_parser = clap::value_parser!(u64).range(..=1_000_000))]
    pause_us: u64,
}

#[derive(Default)]
struct Samples {
    collector: RttCollector,
    count: u64,
    at_least_1ms: u64,
    at_least_10ms: u64,
}

#[derive(Serialize)]
struct Latency {
    samples: u64,
    min_ns: Option<u64>,
    max_ns: Option<u64>,
    mean_ns: Option<f64>,
    p50_ns: Option<u64>,
    p95_ns: Option<u64>,
    p99_ns: Option<u64>,
    at_least_1ms: u64,
    at_least_10ms: u64,
    quantile_precision: QuantilePrecision,
}

impl Samples {
    fn record(&mut self, elapsed: Duration) {
        let ns = u64::try_from(elapsed.as_nanos()).unwrap_or(u64::MAX);
        self.collector.record(RttSample {
            seq: 0,
            rtt_ns: ns,
            ttl: 0,
        });
        self.count += 1;
        self.at_least_1ms += u64::from(ns >= 1_000_000);
        self.at_least_10ms += u64::from(ns >= 10_000_000);
    }

    fn finish(self) -> Latency {
        let snapshot = self.collector.snapshot(self.count, 0);
        Latency {
            samples: snapshot.packets_received,
            min_ns: snapshot
                .min_rtt_ms
                .map(|ms| (ms * 1_000_000.0).round() as u64),
            max_ns: snapshot
                .max_rtt_ms
                .map(|ms| (ms * 1_000_000.0).round() as u64),
            mean_ns: snapshot.avg_rtt_ms.map(|ms| ms * 1_000_000.0),
            p50_ns: self.collector.percentile_ns(50.0),
            p95_ns: self.collector.percentile_ns(95.0),
            p99_ns: self.collector.percentile_ns(99.0),
            at_least_1ms: self.at_least_1ms,
            at_least_10ms: self.at_least_10ms,
            quantile_precision: snapshot.quantile_precision,
        }
    }
}

fn key(index: usize, ipv6: bool) -> SessionKey {
    let (client, local) = if ipv6 {
        let base = u128::from("2001:db8::1".parse::<Ipv6Addr>().unwrap());
        (
            IpAddr::V6(Ipv6Addr::from(base + index as u128)),
            "[2001:db8:ffff::1]:862".parse().unwrap(),
        )
    } else {
        let base = u32::from(Ipv4Addr::new(198, 18, 0, 1));
        (
            IpAddr::V4(Ipv4Addr::from(base + index as u32)),
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

struct StopOnDrop<'a>(&'a AtomicBool);
impl Drop for StopOnDrop<'_> {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Release);
    }
}

#[derive(Serialize)]
struct Trial {
    active_seconds: f64,
    requested_seconds: f64,
    window_overrun_ns: u64,
    probe_operations_per_second: f64,
    probe_latency: Latency,
    retirement_latency: Latency,
    admission_cycle_latency: Latency,
    background_latency: Latency,
    final_sessions: usize,
}

fn trial(args: &Args, duration: Duration) -> Result<Trial, String> {
    let size = args.sessions as usize;
    let keys: Vec<_> = (0..size).map(|i| key(i, args.ipv6)).collect();
    let mut admission_key = keys[0];
    admission_key.client.set_port(10_001);
    let manager = Arc::new(SessionManager::new(Some(Duration::MAX), Some(size + 1)));
    for key in &keys {
        manager
            .get_or_create_session(*key)
            .ok_or("fixture admission rejected")?;
    }
    if manager.session_count() != size || manager.get_session(admission_key).is_some() {
        return Err("invalid table population or reserved probe identity".into());
    }
    let stop = AtomicBool::new(false);
    thread::scope(|scope| {
        let _stop_on_drop = StopOnDrop(&stop);
        let (start_tx, start_rx) = mpsc::sync_channel::<Instant>(0);
        let (ready_tx, ready_rx) = mpsc::sync_channel::<()>(0);
        let worker = (args.background != Background::None).then(|| {
            let manager = Arc::clone(&manager);
            let stop = &stop;
            scope.spawn(move || -> Result<Samples, String> {
                let mut samples = Samples::default();
                ready_tx
                    .send(())
                    .map_err(|_| "readiness receiver dropped")?;
                let deadline = start_rx.recv().map_err(|_| "start signal dropped")?;
                while !stop.load(Ordering::Acquire) && Instant::now() < deadline {
                    let started = Instant::now();
                    match args.background {
                        Background::Inventory => {
                            let rows = manager.session_summaries_extended();
                            if !(size..=size + 1).contains(&rows.len()) {
                                return Err("inventory exceeded the bounded fixture".into());
                            }
                            black_box(rows);
                        }
                        Background::Cleanup => {
                            if manager.cleanup_stale_sessions() != 0 {
                                return Err("retained cleanup removed a live session".into());
                            }
                        }
                        Background::None => unreachable!(),
                    }
                    samples.record(started.elapsed());
                    let remaining = deadline.saturating_duration_since(Instant::now());
                    if args.pause_us != 0 {
                        thread::sleep(Duration::from_micros(args.pause_us).min(remaining));
                    }
                }
                Ok(samples)
            })
        });
        let mut probes = Samples::default();
        let mut retirements = Samples::default();
        let mut cycles = Samples::default();
        let mut cursor = 0;
        if worker.is_some() {
            ready_rx
                .recv()
                .map_err(|_| "background worker did not become ready")?;
        }
        let started = Instant::now();
        let deadline = started + duration;
        if worker.is_some() {
            start_tx
                .send(deadline)
                .map_err(|_| "background worker did not start")?;
        }
        while Instant::now() < deadline {
            let mut selected = keys[cursor];
            cursor = (cursor + 1) % size;
            if args.probe == Probe::Admission {
                selected.client.set_port(10_001);
            }
            let cycle_start = Instant::now();
            let session = manager
                .get_or_create_session(black_box(selected))
                .ok_or("probe rejected")?;
            drop(black_box(session));
            let acquired = Instant::now();
            if args.probe == Probe::Admission {
                if !manager.expire_matching(selected.client, None)? {
                    return Err("probe retirement did not remove its session".into());
                }
                let retired = Instant::now();
                retirements.record(retired.duration_since(acquired));
                cycles.record(retired.duration_since(cycle_start));
            }
            probes.record(acquired.duration_since(cycle_start));
        }
        let active = started.elapsed();
        stop.store(true, Ordering::Release);
        let background = match worker {
            Some(worker) => worker.join().map_err(|_| "background worker panicked")??,
            None => Samples::default(),
        };
        if probes.count == 0 || (args.background != Background::None && background.count == 0) {
            return Err("measurement window contained no probe/background progress".into());
        }
        let final_sessions = manager.session_count();
        if final_sessions != size
            || (args.probe == Probe::Admission && retirements.count != probes.count)
        {
            return Err("session state or operation accounting diverged".into());
        }
        Ok(Trial {
            active_seconds: active.as_secs_f64(),
            requested_seconds: duration.as_secs_f64(),
            window_overrun_ns: u64::try_from(active.saturating_sub(duration).as_nanos())
                .unwrap_or(u64::MAX),
            probe_operations_per_second: probes.count as f64 / active.as_secs_f64(),
            probe_latency: probes.finish(),
            retirement_latency: retirements.finish(),
            admission_cycle_latency: cycles.finish(),
            background_latency: background.finish(),
            final_sessions,
        })
    })
}

fn main() -> Result<(), Box<dyn Error>> {
    let args = Args::parse();
    if cfg!(debug_assertions) {
        return Err("use cargo run --release; debug builds are not performance evidence".into());
    }
    let executable = std::env::current_exe()?;
    let head = Command::new("git")
        .args(["rev-parse", "HEAD"])
        .output()
        .ok()
        .filter(|out| out.status.success())
        .map(|out| String::from_utf8_lossy(&out.stdout).trim().to_owned());
    let mut report = json!({
        "schema_version": 1, "completed": false, "settings": args,
        "execution": "closed-loop API calls; no independent arrivals or network packets",
        "started_unix_seconds": SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
        "os": std::env::consts::OS, "arch": std::env::consts::ARCH,
        "debug_build": cfg!(debug_assertions),
        "available_parallelism": thread::available_parallelism().ok().map(|n| n.get()),
        "cpu_affinity": fs::read_to_string("/proc/self/status").ok().and_then(|text|
            text.lines().find(|line| line.starts_with("Cpus_allowed_list:")).map(str::to_owned)),
        "cpu_model": fs::read_to_string("/proc/cpuinfo").ok().and_then(|text|
            text.lines().find(|line| line.starts_with("model name")).map(str::to_owned)),
        "git_head_at_run": head,
        "binary_sha256": hex::encode(Sha256::digest(fs::read(executable)?)),
        "source_sha256": hex::encode(Sha256::digest(include_bytes!("session_contention.rs"))),
        "features": {"metrics":cfg!(feature="metrics"), "control":cfg!(feature="control"),
            "ttl_pnet":cfg!(feature="ttl-pnet"), "ttl_nix":cfg!(feature="ttl-nix"),
            "snmp":cfg!(feature="snmp"), "hwtstamp":cfg!(feature="hwtstamp")},
        "trials": []
    });
    let mut trials = Vec::new();
    for index in 0..args.repeats {
        eprintln!("session contention trial {}/{}", index + 1, args.repeats);
        match trial(&args, Duration::from_secs(u64::from(args.seconds))) {
            Ok(result) => trials.push(result),
            Err(error) => {
                report["trials"] = serde_json::to_value(trials)?;
                report["error"] = json!(error);
                println!("{}", serde_json::to_string_pretty(&report)?);
                return Err(error.into());
            }
        }
    }
    report["trials"] = serde_json::to_value(trials)?;
    report["completed"] = json!(true);
    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args() -> Args {
        Args::parse_from(["session_contention"])
    }

    #[test]
    fn latency_units_counts_and_extremes_are_preserved() {
        let mut samples = Samples::default();
        for ns in [10, 30, 20] {
            samples.record(Duration::from_nanos(ns));
        }
        let summary = samples.finish();
        assert_eq!(summary.samples, 3);
        assert_eq!(summary.min_ns, Some(10));
        assert_eq!(summary.max_ns, Some(30));
        assert_eq!(summary.p50_ns, Some(20));
        assert_eq!(summary.p99_ns, Some(30));
        assert_eq!(summary.mean_ns, Some(20.0));
        assert_eq!(summary.at_least_1ms, 0);
    }

    #[test]
    fn admission_clients_are_distinct_from_both_full_tables() {
        for ipv6 in [false, true] {
            let seeded: std::collections::HashSet<_> =
                (0..65_536).map(|i| key(i, ipv6).client).collect();
            let admitted: std::collections::HashSet<_> = (0..65_536)
                .map(|i| {
                    let mut client = key(i, ipv6).client;
                    client.set_port(10_001);
                    client
                })
                .collect();
            assert_eq!(seeded.len(), 65_536);
            assert_eq!(admitted.len(), 65_536);
            assert!(seeded.is_disjoint(&admitted));
        }
    }

    #[test]
    fn probes_and_background_work_preserve_bounded_state() {
        for ipv6 in [false, true] {
            for probe in [Probe::Refresh, Probe::Admission] {
                for background in [Background::None, Background::Inventory, Background::Cleanup] {
                    for pause_us in [0, 1_000] {
                        let mut settings = args();
                        settings.sessions = 16;
                        settings.ipv6 = ipv6;
                        settings.probe = probe;
                        settings.background = background;
                        settings.pause_us = pause_us;
                        let report = trial(&settings, Duration::from_millis(100)).unwrap();
                        assert_eq!(report.final_sessions, 16);
                        assert!(report.probe_latency.samples > 0);
                        if probe == Probe::Admission {
                            assert_eq!(
                                report.retirement_latency.samples,
                                report.probe_latency.samples
                            );
                            assert_eq!(
                                report.admission_cycle_latency.samples,
                                report.probe_latency.samples
                            );
                        } else {
                            assert_eq!(report.retirement_latency.samples, 0);
                        }
                        if background == Background::None {
                            assert_eq!(report.background_latency.samples, 0);
                        } else {
                            assert!(report.background_latency.samples > 0);
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn empty_measurement_window_is_an_error() {
        for background in [Background::None, Background::Inventory, Background::Cleanup] {
            let mut settings = args();
            settings.sessions = 16;
            settings.background = background;
            assert!(trial(&settings, Duration::ZERO).is_err());
        }
    }

    #[test]
    fn arguments_reject_unbounded_or_empty_workloads() {
        for extra in [
            ["--sessions", "0"],
            ["--sessions", "65537"],
            ["--seconds", "0"],
            ["--repeats", "0"],
            ["--pause-us", "1000001"],
        ] {
            assert!(Args::try_parse_from(["session_contention", extra[0], extra[1]]).is_err());
        }
    }
}
