//! Linux live loopback benchmark. See doc/benchmarks.md for measurement limits.
#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("live_udp_bench requires Linux /proc CPU accounting");
    std::process::exit(1);
}

#[cfg(target_os = "linux")]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    linux::run()
}

#[cfg(target_os = "linux")]
mod linux {
    use clap::Parser;
    use serde::Serialize;
    use serde_json::json;
    use sha2::{Digest, Sha256};
    use stamp_suite::crypto::HmacKey;
    use stamp_suite::packets::{ReflectedPacketAuthenticated, ReflectedPacketUnauthenticated};
    use std::error::Error;
    use std::fs;
    use std::net::{SocketAddr, UdpSocket};
    use std::path::PathBuf;
    use std::process::{Child, Command, Stdio};
    use std::thread;
    use std::time::{Duration, Instant};

    type Result<T> = std::result::Result<T, Box<dyn Error + Send + Sync>>;
    // Public benchmark fixture, never a production secret.
    const KEY: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const SSID: u16 = 7;
    const STAMP: u64 = 0xedde_1234_5678_0000;

    #[derive(Parser, Serialize)]
    #[command(about = "Measure a local reflector over real UDP; emit JSON on stdout")]
    struct Args {
        /// Build this binary with the same features as the benchmark example.
        #[arg(long, default_value = "target/release/stamp-suite")]
        reflector: PathBuf,
        #[arg(long)]
        ipv6: bool,
        #[arg(long)]
        authenticated: bool,
        #[arg(long)]
        stateful: bool,
        /// Requested packets/sec, paced in 1 ms batches; never catch up late batches.
        #[arg(long, default_value_t = 10_000, value_parser = clap::value_parser!(u32).range(1..=1_000_000))]
        rate: u32,
        #[arg(long, default_value_t = 3, value_parser = clap::value_parser!(u32).range(1..=60))]
        seconds: u32,
        #[arg(long, default_value_t = 2, value_parser = clap::value_parser!(u32).range(1..=60))]
        idle_seconds: u32,
        #[arg(long, default_value_t = 3, value_parser = clap::value_parser!(u32).range(1..=100))]
        repeats: u32,
        #[arg(long, default_value_t = 500, value_parser = clap::value_parser!(u32).range(1..=10_000))]
        drain_ms: u32,
        /// Explicit runtime size for reproducibility (also works with pnet).
        #[arg(long, default_value_t = 2, value_parser = clap::value_parser!(u32).range(1..=256))]
        workers: u32,
    }

    struct Reflector(Child);
    impl Drop for Reflector {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    impl Reflector {
        fn check(&mut self) -> Result<()> {
            if let Some(status) = self.0.try_wait()? {
                return Err(format!("reflector exited: {status}; see stderr").into());
            }
            Ok(())
        }
    }

    fn cpu_ticks(pid: u32) -> Result<u64> {
        let stat = fs::read_to_string(format!("/proc/{pid}/stat"))?;
        let fields: Vec<_> = stat
            .rsplit_once(')')
            .ok_or("invalid proc stat")?
            .1
            .split_whitespace()
            .collect();
        Ok(fields.get(11).ok_or("missing utime")?.parse::<u64>()?
            + fields.get(12).ok_or("missing stime")?.parse::<u64>()?)
    }

    #[derive(Serialize)]
    struct Cpu {
        wall_seconds: f64,
        ticks: u64,
        cpu_seconds: f64,
        percent_one_core: f64,
    }
    fn cpu_sample(before: u64, after: u64, wall: Duration, hz: u64) -> Cpu {
        let ticks = after - before;
        let cpu_seconds = ticks as f64 / hz as f64;
        Cpu {
            wall_seconds: wall.as_secs_f64(),
            ticks,
            cpu_seconds,
            percent_one_core: cpu_seconds / wall.as_secs_f64() * 100.0,
        }
    }
    fn idle(child: &mut Reflector, seconds: u32, hz: u64) -> Result<Cpu> {
        child.check()?;
        let before = cpu_ticks(child.0.id())?;
        let start = Instant::now();
        thread::sleep(Duration::from_secs(seconds.into()));
        let after = cpu_ticks(child.0.id())?;
        child.check()?;
        Ok(cpu_sample(before, after, start.elapsed(), hz))
    }

    fn packet(seq: u32, key: Option<&HmacKey>) -> Vec<u8> {
        let mut buf = vec![0; if key.is_some() { 112 } else { 44 }];
        let timestamp = if key.is_some() { 16 } else { 4 };
        buf[..4].copy_from_slice(&seq.to_be_bytes());
        buf[timestamp..timestamp + 8].copy_from_slice(&STAMP.to_be_bytes());
        buf[timestamp + 8..timestamp + 10].copy_from_slice(&1u16.to_be_bytes());
        buf[timestamp + 10..timestamp + 12].copy_from_slice(&SSID.to_be_bytes());
        if let Some(key) = key {
            let hmac = key.compute(&buf[..96]);
            buf[96..].copy_from_slice(&hmac);
        }
        buf
    }

    fn reply_sequence(buf: &[u8], key: Option<&HmacKey>) -> Option<u32> {
        let (seq, timestamp, estimate, ssid) = if let Some(key) = key {
            if buf.len() != 112 {
                return None;
            }
            let p = ReflectedPacketAuthenticated::from_bytes(buf).ok()?;
            if !key.verify(&buf[..96], &p.hmac) {
                return None;
            }
            (
                p.sess_sender_seq_number,
                p.sess_sender_timestamp,
                p.sess_sender_err_estimate,
                p.ssid,
            )
        } else {
            if buf.len() != 44 {
                return None;
            }
            let p = ReflectedPacketUnauthenticated::from_bytes(buf).ok()?;
            (
                p.sess_sender_seq_number,
                p.sess_sender_timestamp,
                p.sess_sender_err_estimate,
                p.ssid,
            )
        };
        (timestamp == STAMP && estimate == 1 && ssid == SSID).then_some(seq)
    }

    fn socket(destination: SocketAddr) -> Result<UdpSocket> {
        let socket = UdpSocket::bind((destination.ip(), 0))?;
        socket.connect(destination)?;
        socket.set_read_timeout(Some(Duration::from_millis(10)))?;
        socket.set_write_timeout(Some(Duration::from_millis(100)))?;
        Ok(socket)
    }

    fn probe(
        child: &mut Reflector,
        socket: &UdpSocket,
        key: Option<&HmacKey>,
        seq: u32,
    ) -> Result<()> {
        let start = Instant::now();
        let request = packet(seq, key);
        let mut buf = [0; 2048];
        while start.elapsed() < Duration::from_secs(5) {
            child.check()?;
            socket.send(&request)?;
            match socket.recv(&mut buf) {
                Ok(n) if reply_sequence(&buf[..n], key) == Some(seq) => return Ok(()),
                Ok(_) => {}
                Err(e) if transient(&e) || e.kind() == std::io::ErrorKind::ConnectionRefused => {}
                Err(e) => return Err(e.into()),
            }
            thread::sleep(Duration::from_millis(20));
        }
        Err("no valid probe response within five seconds".into())
    }

    fn transient(error: &std::io::Error) -> bool {
        matches!(
            error.kind(),
            std::io::ErrorKind::WouldBlock
                | std::io::ErrorKind::TimedOut
                | std::io::ErrorKind::Interrupted
        )
    }

    #[derive(Default, Serialize)]
    struct Replies {
        unique_during_load: u64,
        unique_during_drain: u64,
        duplicates: u64,
        invalid: u64,
        out_of_order: u64,
        #[serde(skip)]
        seen: Vec<bool>,
        #[serde(skip)]
        highest: Option<u32>,
    }
    impl Replies {
        fn record(&mut self, seq: Option<u32>, during_load: bool) {
            let Some(seq) = seq.filter(|&seq| (seq as usize) < self.seen.len()) else {
                self.invalid += 1;
                return;
            };
            if std::mem::replace(&mut self.seen[seq as usize], true) {
                self.duplicates += 1;
                return;
            }
            if self.highest.is_some_and(|highest| seq < highest) {
                self.out_of_order += 1;
            }
            self.highest = Some(self.highest.map_or(seq, |highest| highest.max(seq)));
            if during_load {
                self.unique_during_load += 1;
            } else {
                self.unique_during_drain += 1;
            }
        }
    }

    fn trial(args: &Args, key: Option<&HmacKey>, hz: u64) -> Result<serde_json::Value> {
        let ip = if args.ipv6 { "::1" } else { "127.0.0.1" };
        let reserve = UdpSocket::bind((ip, 0))?;
        let destination = reserve.local_addr()?;
        let mut command = Command::new(&args.reflector);
        command
            .args([
                "--is-reflector",
                "--local-addr",
                ip,
                "--local-port",
                &destination.port().to_string(),
                "--hwtstamp",
                "off",
            ])
            .env_remove("STAMP_HMAC_KEY")
            .env("RUST_LOG", "error")
            .env("TOKIO_WORKER_THREADS", args.workers.to_string())
            .stdout(Stdio::null())
            .stderr(Stdio::inherit());
        if args.authenticated {
            command.args(["-A", "A", "--hmac-key", KEY]);
        }
        if args.stateful {
            command.arg("--stateful-reflector");
        }
        let command_line = format!("{command:?}");
        drop(reserve); // Bind race fails visibly via child status; never retry a different server.
        let mut child = Reflector(command.spawn()?);
        let probe_socket = socket(destination)?;
        probe(&mut child, &probe_socket, key, 0)?;
        thread::sleep(Duration::from_millis(100));
        let idle_before = idle(&mut child, args.idle_seconds, hz)?;
        let socket = socket(destination)?;
        // Warm the measured session and validate that readiness resumed after idle.
        probe(&mut child, &socket, key, 0)?;
        // Load sequences start at 1; slot zero is reserved for delayed warm-up replies.
        let capacity = args.rate as usize * args.seconds as usize + 1;
        let mut replies = Replies {
            seen: vec![false; capacity],
            ..Default::default()
        };
        let reflector_before = cpu_ticks(child.0.id())?;
        let generator_before = cpu_ticks(std::process::id())?;
        let start = Instant::now();
        let deadline = start + Duration::from_secs(args.seconds.into());
        let receive_deadline = deadline + Duration::from_millis(args.drain_ms.into());
        let (sent, skipped_slots, replies, reflector_cpu, generator_cpu) =
            thread::scope(|scope| -> Result<_> {
                let receiver = scope.spawn(|| -> Result<Replies> {
                    let mut buf = [0; 2048];
                    while Instant::now() < receive_deadline {
                        match socket.recv(&mut buf) {
                            Ok(n) => {
                                let seq = reply_sequence(&buf[..n], key);
                                if seq != Some(0) {
                                    replies.record(seq, Instant::now() < deadline);
                                }
                            }
                            Err(e) if transient(&e) => {}
                            Err(e) => return Err(e.into()),
                        }
                    }
                    Ok(replies)
                });
                let mut sent = 0u32;
                let mut slots = 0u64;
                while Instant::now() < deadline {
                    let elapsed_ms = start.elapsed().as_millis() as u64;
                    let end_slot =
                        ((elapsed_ms + 1) * args.rate as u64 / 1000).min((capacity - 1) as u64);
                    let begin_slot = (elapsed_ms * args.rate as u64 / 1000).max(slots);
                    slots = end_slot;
                    for _ in begin_slot..end_slot {
                        if Instant::now() >= deadline {
                            break;
                        }
                        let request = packet(sent + 1, key);
                        if socket.send(&request)? != request.len() {
                            return Err("incomplete UDP send".into());
                        }
                        sent += 1;
                    }
                    let next = start + Duration::from_millis(elapsed_ms + 1);
                    thread::sleep(next.saturating_duration_since(Instant::now()));
                }
                let wall = start.elapsed();
                let reflector_cpu =
                    cpu_sample(reflector_before, cpu_ticks(child.0.id())?, wall, hz);
                let generator_cpu =
                    cpu_sample(generator_before, cpu_ticks(std::process::id())?, wall, hz);
                let replies = receiver.join().map_err(|_| "receiver thread panicked")??;
                let skipped_slots = (capacity - 1) as u64 - sent as u64;
                Ok((sent, skipped_slots, replies, reflector_cpu, generator_cpu))
            })?;
        child.check()?;
        let unique = replies.unique_during_load + replies.unique_during_drain;
        if unique > sent as u64 || replies.highest.is_some_and(|seq| seq > sent) {
            return Err("received an unsent sequence; accounting is invalid".into());
        }
        if unique == 0 {
            return Err("no valid responses during the load/drain sample".into());
        }
        let idle_after = idle(&mut child, args.idle_seconds, hz)?;
        probe(&mut child, &socket, key, sent + 1)?;
        Ok(json!({
            "reflector_command": command_line, "sent": sent, "replies": replies,
            "missing_after_drain": sent as u64 - unique,
            "loss_percent": 100.0 * (sent as u64 - unique) as f64 / sent as f64,
            "skipped_pacing_slots": skipped_slots,
            "achieved_send_pps": sent as f64 / reflector_cpu.wall_seconds,
            "unique_receive_pps_during_load": replies.unique_during_load as f64 / args.seconds as f64,
            "reflector_load_cpu": reflector_cpu, "generator_load_cpu": generator_cpu,
            "reflector_idle_before": idle_before, "reflector_idle_after": idle_after,
            "resume_after_idle": true,
        }))
    }

    pub(super) fn run() -> std::result::Result<(), Box<dyn Error>> {
        run_inner().map_err(|error| error as Box<dyn Error>)
    }
    fn run_inner() -> Result<()> {
        let mut args = Args::parse();
        args.reflector = fs::canonicalize(&args.reflector)?;
        // SAFETY: sysconf with _SC_CLK_TCK does not use pointers.
        let hz = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
        if hz <= 0 {
            return Err("could not determine CPU tick frequency".into());
        }
        let key = args
            .authenticated
            .then(|| HmacKey::from_hex(KEY))
            .transpose()?;
        let mut trials = Vec::new();
        for index in 0..args.repeats {
            eprintln!("live UDP trial {}/{}", index + 1, args.repeats);
            trials.push(trial(&args, key.as_ref(), hz as u64)?);
        }
        let binary_hash =
            |path| -> Result<String> { Ok(hex::encode(Sha256::digest(fs::read(path)?))) };
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "schema_version": 1, "settings": args, "trials": trials,
                "cpu_ticks_per_second": hz,
                "reflector_sha256": binary_hash(args.reflector.clone())?,
                "generator_sha256": binary_hash(std::env::current_exe()?)?,
                "generator_debug_assertions": cfg!(debug_assertions),
                "generator_features": { "ttl_nix": cfg!(feature = "ttl-nix"), "ttl_pnet": cfg!(feature = "ttl-pnet"),
                    "hwtstamp": cfg!(feature = "hwtstamp"), "metrics": cfg!(feature = "metrics"),
                    "control": cfg!(feature = "control"), "snmp": cfg!(feature = "snmp") },
                "kernel": fs::read_to_string("/proc/version")?.trim(),
                "cpu_model": fs::read_to_string("/proc/cpuinfo")?.lines()
                    .find(|line| line.starts_with("model name")).unwrap_or("unavailable"),
                "affinity": fs::read_to_string("/proc/self/status")?.lines()
                    .find(|line| line.starts_with("Cpus_allowed_list:")).unwrap_or("unavailable"),
            }))?
        );
        Ok(())
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn accounting_excludes_duplicates_and_invalid_sequences() {
            let mut replies = Replies {
                seen: vec![false; 5],
                ..Default::default()
            };
            for seq in [Some(3), Some(1), Some(3), None, Some(5)] {
                replies.record(seq, true);
            }
            replies.record(Some(2), false);
            assert_eq!(
                (replies.unique_during_load, replies.unique_during_drain),
                (2, 1)
            );
            assert_eq!(
                (replies.duplicates, replies.invalid, replies.out_of_order),
                (1, 2, 2)
            );
        }

        #[test]
        fn validation_rejects_wrong_identity_lengths_and_authentication() {
            for auth in [false, true] {
                let key = auth.then(|| HmacKey::from_hex(KEY).unwrap());
                let mut buf = vec![0; if auth { 112 } else { 44 }];
                let (ssid, seq, timestamp, estimate) = if auth {
                    (26, 48, 64, 72)
                } else {
                    (14, 24, 28, 36)
                };
                buf[ssid..ssid + 2].copy_from_slice(&SSID.to_be_bytes());
                buf[seq..seq + 4].copy_from_slice(&3u32.to_be_bytes());
                buf[timestamp..timestamp + 8].copy_from_slice(&STAMP.to_be_bytes());
                buf[estimate..estimate + 2].copy_from_slice(&1u16.to_be_bytes());
                if let Some(key) = &key {
                    let hmac = key.compute(&buf[..96]);
                    buf[96..].copy_from_slice(&hmac);
                }
                assert_eq!(reply_sequence(&buf, key.as_ref()), Some(3));
                assert_eq!(reply_sequence(&buf[..buf.len() - 1], key.as_ref()), None);
                let mut extra = buf.clone();
                extra.push(0);
                assert_eq!(reply_sequence(&extra, key.as_ref()), None);
                for offset in [ssid, timestamp, estimate] {
                    let mut wrong = buf.clone();
                    wrong[offset] ^= 1;
                    if let Some(key) = &key {
                        let hmac = key.compute(&wrong[..96]);
                        wrong[96..].copy_from_slice(&hmac);
                    }
                    assert_eq!(reply_sequence(&wrong, key.as_ref()), None);
                }
                if auth {
                    buf[0] ^= 1;
                    assert_eq!(reply_sequence(&buf, key.as_ref()), None);
                }
            }
        }
    }
}
