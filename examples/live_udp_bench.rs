//! Linux live loopback benchmark. See doc/benchmarks.md for measurement limits.
#[cfg(target_os = "linux")]
#[path = "live_udp_bench/ber.rs"]
mod ber;

#[cfg(target_os = "linux")]
#[path = "live_udp_bench/latency.rs"]
mod latency;

#[cfg(target_os = "linux")]
#[path = "live_udp_bench/burst.rs"]
mod burst;

#[cfg(target_os = "linux")]
#[path = "live_udp_bench/headers.rs"]
mod headers;

#[cfg(target_os = "linux")]
#[path = "live_udp_bench/sessions.rs"]
mod sessions;

#[cfg(target_os = "linux")]
#[path = "live_udp_bench/memory.rs"]
mod memory;

#[cfg(target_os = "linux")]
#[path = "live_udp_bench/inventory.rs"]
mod inventory;

#[cfg(target_os = "linux")]
#[path = "live_udp_bench/startup.rs"]
mod startup;

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
    use super::ber::Profile;
    use super::burst::{Copies, Profile as Burst, Verdict};
    use super::headers::{Mode as HeaderMode, Profile as Headers};
    use super::inventory::{Mode as InventoryMode, Profile as Inventory};
    use super::latency::{Samples, SendTimes};
    use super::memory;
    use super::sessions::{Profile as Sessions, Replies as SessionReplies};
    use super::startup;
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
        /// Reflector binary to run; build it with the same features as this example.
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
        /// Reflector `--hwtstamp` mode. `auto` is the packaged default and adds
        /// the TX-timestamp error-queue work when built with `hwtstamp`.
        #[arg(long, default_value = "off", value_parser = ["off", "auto", "on"])]
        hwtstamp: String,
        /// Run the reflector with `--metrics` on an ephemeral loopback port.
        #[arg(long)]
        metrics: bool,
        /// Include BER with this many padding octets (16–1200, multiple of four).
        #[arg(long, value_parser = clap::value_parser!(u16).range(16..=1200))]
        ber_padding: Option<u16>,
        /// Inject five padding bit errors, including one four-bit burst.
        #[arg(long, requires = "ber_padding")]
        ber_damaged: bool,
        /// Observe local send-call-to-receive time; at most one million probe slots.
        #[arg(long)]
        latency: bool,
        /// Observe process RSS/PSS outside load via Linux smaps_rollup.
        #[arg(long)]
        memory: bool,
        /// Type 12 replies per probe; require stateful reflector sequence numbers.
        #[arg(long, value_parser=clap::value_parser!(u16).range(1..=16), requires="stateful", conflicts_with="ber_padding")]
        burst_count: Option<u16>,
        /// Burst reply payload size, 240–1200 octets aligned to four (default 240).
        #[arg(long, value_parser=clap::value_parser!(u16).range(240..=1200), requires="burst_count")]
        burst_bytes: Option<u16>,
        /// Linux nix header workload: fixed C fallback, IPv6 options, or both.
        #[arg(long, value_enum, conflicts_with_all=["ber_padding","burst_count"])]
        headers: Option<HeaderMode>,
        /// Destination Options size, 16–256 octets aligned to eight (default 16).
        #[arg(long, requires="headers", value_parser=clap::value_parser!(u16).range(16..=256))]
        header_bytes: Option<u16>,
        /// Keep child header reflection denied while still attaching requested options.
        #[arg(long, requires = "headers")]
        headers_denied: bool,
        /// Measured SSIDs on one UDP tuple, excluding warm-up SSID 7; include creation.
        #[arg(long, requires="stateful", conflicts_with_all=["ber_padding","burst_count","headers"], value_parser=clap::value_parser!(u16).range(1..=65534))]
        sessions: Option<u16>,
        /// Concurrent HTTP inventory workload; require sessions and a control build.
        #[arg(long, value_enum, requires = "sessions")]
        inventory: Option<InventoryMode>,
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
        // utime and stime are fields 14 and 15 of proc(5) stat. Splitting after the
        // ')' that closes the command name starts at field 3, so they are at 11 and 12.
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

    fn request(seq: u32, key: Option<&HmacKey>, ber: Option<&Profile>) -> Vec<u8> {
        let mut bytes = packet(seq, key);
        if let Some(ber) = ber {
            ber.append(&mut bytes, key);
        }
        bytes
    }

    fn response_sequence(buf: &[u8], key: Option<&HmacKey>, ber: Option<&Profile>) -> Option<u32> {
        let Some(ber) = ber else {
            return reply_sequence(buf, key);
        };
        let base = if key.is_some() { 112 } else { 44 };
        let seq = reply_sequence(buf.get(..base)?, key)?;
        ber.validate(buf, base, key).then_some(seq)
    }

    fn socket(destination: SocketAddr) -> Result<UdpSocket> {
        let socket = UdpSocket::bind((destination.ip(), 0))?;
        socket.connect(destination)?;
        socket.set_read_timeout(Some(Duration::from_millis(10)))?;
        socket.set_write_timeout(Some(Duration::from_millis(100)))?;
        Ok(socket)
    }

    fn workload_request(
        seq: u32,
        key: Option<&HmacKey>,
        ber: Option<&Profile>,
        burst: Option<&Burst>,
        headers: Option<&Headers>,
        sessions: Option<&Sessions>,
    ) -> Vec<u8> {
        if let Some(sessions) = sessions {
            return sessions.request(seq, STAMP, key);
        }
        let mut bytes = request(seq, key, ber);
        if let Some(burst) = burst {
            burst.append(&mut bytes, key);
        }
        if let Some(headers) = headers {
            headers.append(&mut bytes, key);
        }
        bytes
    }

    fn workload_response(
        buf: &[u8],
        key: Option<&HmacKey>,
        ber: Option<&Profile>,
        burst: Option<&Burst>,
        headers: Option<&Headers>,
        sessions: Option<&Sessions>,
    ) -> Option<u32> {
        if let Some(sessions) = sessions {
            return sessions.response(buf, STAMP, key);
        }
        if let Some(headers) = headers {
            let base = if key.is_some() { 112 } else { 44 };
            let seq = reply_sequence(buf.get(..base)?, key)?;
            return headers.validate(buf, base, key).then_some(seq);
        }
        let Some(burst) = burst else {
            return response_sequence(buf, key, ber);
        };
        let base = if key.is_some() { 112 } else { 44 };
        let seq = reply_sequence(buf.get(..base)?, key)?;
        burst.validate(buf, base, key).then_some(seq)
    }

    fn workload_probe(
        child: &mut Reflector,
        socket: &UdpSocket,
        key: Option<&HmacKey>,
        ber: Option<&Profile>,
        burst: Option<&Burst>,
        headers: Option<&Headers>,
        seq: u32,
    ) -> Result<()> {
        if let Some(headers) = headers {
            let start = Instant::now();
            let request = workload_request(seq, key, None, None, Some(headers), None);
            let mut buf = [0; 2048];
            while start.elapsed() < Duration::from_secs(5) {
                child.check()?;
                if socket.send(&request)? != request.len() {
                    return Err("incomplete header probe send".into());
                }
                match socket.recv(&mut buf) {
                    Ok(n)
                        if workload_response(&buf[..n], key, None, None, Some(headers), None)
                            == Some(seq) =>
                    {
                        return Ok(())
                    }
                    Ok(_) => {}
                    Err(e)
                        if transient(&e) || e.kind() == std::io::ErrorKind::ConnectionRefused => {}
                    Err(e) => return Err(e.into()),
                }
                thread::sleep(Duration::from_millis(20));
            }
            return Err("no valid header probe response within five seconds".into());
        }
        let Some(burst) = burst else {
            return probe(child, socket, key, ber, seq);
        };
        let start = Instant::now();
        let mut next_send = start;
        let request = workload_request(seq, key, None, Some(burst), None, None);
        let mut sequences = Vec::new();
        let mut buf = [0; 2048];
        while start.elapsed() < Duration::from_secs(5) {
            child.check()?;
            if sequences.is_empty() && Instant::now() >= next_send {
                if socket.send(&request)? != request.len() {
                    return Err("incomplete burst probe send".into());
                }
                next_send = Instant::now() + Duration::from_millis(20);
            }
            match socket.recv(&mut buf) {
                Ok(n)
                    if workload_response(&buf[..n], key, None, Some(burst), None, None)
                        == Some(seq) =>
                {
                    let nonce = u32::from_be_bytes(buf[..4].try_into()?);
                    if !sequences.contains(&nonce) {
                        sequences.push(nonce);
                    }
                    if sequences.len() == usize::from(burst.count) {
                        // Drain queued probe replies until one read timeout so no
                        // remaining warm-up copies enter the measured window.
                        while start.elapsed() < Duration::from_secs(5) {
                            match socket.recv(&mut buf) {
                                Ok(_) => {}
                                Err(e)
                                    if e.kind() == std::io::ErrorKind::TimedOut
                                        || e.kind() == std::io::ErrorKind::WouldBlock =>
                                {
                                    return Ok(())
                                }
                                Err(e) if transient(&e) => {}
                                Err(e) => return Err(e.into()),
                            }
                        }
                        break;
                    }
                }
                Ok(_) => {}
                Err(e) if transient(&e) || e.kind() == std::io::ErrorKind::ConnectionRefused => {}
                Err(e) => return Err(e.into()),
            }
        }
        Err("burst probe did not complete and drain within five seconds".into())
    }

    fn probe(
        child: &mut Reflector,
        socket: &UdpSocket,
        key: Option<&HmacKey>,
        ber: Option<&Profile>,
        seq: u32,
    ) -> Result<()> {
        let start = Instant::now();
        let request = request(seq, key, ber);
        let mut buf = [0; 2048];
        while start.elapsed() < Duration::from_secs(5) {
            child.check()?;
            socket.send(&request)?;
            match socket.recv(&mut buf) {
                Ok(n) if response_sequence(&buf[..n], key, ber) == Some(seq) => return Ok(()),
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
        #[serde(skip)]
        rtt: Option<Samples>,
        #[serde(skip)]
        copies: Option<Copies>,
        #[serde(skip)]
        sessions: Option<SessionReplies>,
    }
    impl Replies {
        fn record(&mut self, seq: Option<u32>, during_load: bool) -> bool {
            let Some(seq) = seq.filter(|&seq| (seq as usize) < self.seen.len()) else {
                self.invalid += 1;
                return false;
            };
            if std::mem::replace(&mut self.seen[seq as usize], true) {
                self.duplicates += 1;
                return false;
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
            true
        }

        fn record_received(
            &mut self,
            seq: Option<u32>,
            during_load: bool,
            timing: Option<(&SendTimes, u64)>,
        ) -> Result<()> {
            if seq == Some(0) {
                return Ok(());
            }
            if !self.record(seq, during_load) {
                return Ok(());
            }
            if let Some(sessions) = &mut self.sessions {
                sessions.record(seq.ok_or("missing session sequence")?)?;
            }
            if let Some(samples) = &mut self.rtt {
                let (times, received_ns) = timing.ok_or("missing receive observation")?;
                samples.record(times.elapsed(seq.ok_or("missing reply sequence")?, received_ns)?);
            }
            Ok(())
        }

        fn record_burst(
            &mut self,
            seq: Option<u32>,
            nonce: Option<u32>,
            during_load: bool,
            timing: Option<(&SendTimes, u64)>,
        ) -> Result<()> {
            if seq == Some(0) {
                return Ok(());
            }
            let verdict = match (seq, nonce) {
                (Some(seq), Some(nonce)) => self
                    .copies
                    .as_mut()
                    .ok_or("missing burst ledger")?
                    .record(seq, nonce, during_load),
                _ => Verdict::Invalid,
            };
            match verdict {
                Verdict::First => self.record_received(seq, during_load, timing)?,
                Verdict::Additional => {}
                Verdict::Duplicate => self.duplicates += 1,
                Verdict::Invalid => self.invalid += 1,
            }
            Ok(())
        }
    }

    fn elapsed_ns(start: Instant) -> Result<u64> {
        Ok(u64::try_from(start.elapsed().as_nanos())?)
    }

    fn workload_socket(destination: SocketAddr, headers: Option<&Headers>) -> Result<UdpSocket> {
        let Some(headers) = headers else {
            return socket(destination);
        };
        let socket = UdpSocket::bind((destination.ip(), 0))?;
        // Set sticky headers before connect so route/socket setup sees their overhead.
        headers.attach(&socket)?;
        socket.connect(destination)?;
        socket.set_read_timeout(Some(Duration::from_millis(10)))?;
        socket.set_write_timeout(Some(Duration::from_millis(100)))?;
        Ok(socket)
    }

    fn trial(
        args: &Args,
        key: Option<&HmacKey>,
        ber: Option<&Profile>,
        burst: Option<&Burst>,
        headers: Option<&Headers>,
        hz: u64,
    ) -> Result<serde_json::Value> {
        let sessions = args
            .sessions
            .map(|count| Sessions::new(count, u64::from(args.rate) * u64::from(args.seconds)))
            .transpose()?;
        let ip = if args.ipv6 { "::1" } else { "127.0.0.1" };
        let mut command = Command::new(&args.reflector);
        command
            .args([
                "--is-reflector",
                "--local-addr",
                ip,
                "--local-port",
                "0",
                "--hwtstamp",
                &args.hwtstamp,
            ])
            .env_remove("STAMP_HMAC_KEY")
            .env("TOKIO_WORKER_THREADS", args.workers.to_string())
            .stdout(Stdio::null());
        startup::configure(&mut command);
        if args.authenticated {
            command.args(["-A", "A", "--hmac-key", KEY]);
        }
        if args.stateful {
            command.arg("--stateful-reflector");
        }
        if args.metrics {
            command.args(["--metrics", "--metrics-addr", "127.0.0.1:0"]);
        }
        if let Some(burst) = burst {
            command.args([
                "--reflected-control-max-count",
                &burst.count.to_string(),
                "--reflected-control-max-size",
                &burst.bytes.to_string(),
            ]);
        }
        if let Some(headers) = headers {
            headers.configure(&mut command, ip);
        }
        if let Some(sessions) = &sessions {
            sessions.configure(&mut command);
        }
        let mut inventory = args
            .inventory
            .map(|mode| Inventory::new(mode, args.sessions.expect("clap requires sessions")))
            .transpose()?;
        if let Some(inventory) = &inventory {
            inventory.configure(&mut command);
        }
        let command_line = format!("{command:?}");
        let mut child = Reflector(command.spawn()?);
        let endpoints = startup::wait(&mut child.0)?;
        let destination = endpoints.udp;
        if let Some(inventory) = &mut inventory {
            inventory.connect_to(
                endpoints
                    .control
                    .ok_or("reflector did not announce its control endpoint")?,
            );
        }
        let probe_socket = workload_socket(destination, headers)?;
        workload_probe(&mut child, &probe_socket, key, ber, burst, headers, 0)?;
        if let Some(inventory) = &inventory {
            inventory.ready()?;
        }
        thread::sleep(Duration::from_millis(100));
        let idle_before = idle(&mut child, args.idle_seconds, hz)?;
        let socket = workload_socket(destination, headers)?;
        // Warm the measured session and validate that readiness resumed after idle.
        workload_probe(&mut child, &socket, key, ber, burst, headers, 0)?;
        // Load sequences start at 1; slot zero is reserved for delayed warm-up replies.
        let capacity = args.rate as usize * args.seconds as usize + 1;
        let send_times = args.latency.then(|| SendTimes::new(capacity)).transpose()?;
        let mut replies = Replies {
            seen: vec![false; capacity],
            sessions: sessions.as_ref().map(SessionReplies::new),
            rtt: args.latency.then(Samples::default),
            copies: burst
                .map(|profile| Copies::new(profile, capacity))
                .transpose()?,
            ..Default::default()
        };
        let memory_before_load = memory::snapshot(args.memory, child.0.id())?;
        let reflector_before = cpu_ticks(child.0.id())?;
        let generator_before = cpu_ticks(std::process::id())?;
        let start = Instant::now();
        let deadline = start + Duration::from_secs(args.seconds.into());
        let receive_deadline = deadline + Duration::from_millis(args.drain_ms.into());
        let (sent, skipped_slots, replies, reflector_cpu, generator_cpu, inventory_summary) =
            thread::scope(|scope| -> Result<_> {
                let inventory_worker = inventory
                    .as_ref()
                    .map(|profile| scope.spawn(move || profile.run(deadline)));
                let receiver = scope.spawn(|| -> Result<Replies> {
                    let mut buf = [0; 2048];
                    while Instant::now() < receive_deadline {
                        match socket.recv(&mut buf) {
                            Ok(n) => {
                                // Observe receipt before authentication/BER validation;
                                // only an admitted first reply contributes the sample.
                                let received_ns =
                                    send_times.as_ref().map(|_| elapsed_ns(start)).transpose()?;
                                let seq = workload_response(
                                    &buf[..n],
                                    key,
                                    ber,
                                    burst,
                                    headers,
                                    sessions.as_ref(),
                                );
                                if seq != Some(0) {
                                    let timing = send_times.as_ref().zip(received_ns);
                                    if burst.is_some() {
                                        let nonce = seq.map(|_| {
                                            u32::from_be_bytes(
                                                buf[..4]
                                                    .try_into()
                                                    .expect("validated complete base"),
                                            )
                                        });
                                        replies.record_burst(
                                            seq,
                                            nonce,
                                            Instant::now() < deadline,
                                            timing,
                                        )?;
                                    } else {
                                        replies.record_received(
                                            seq,
                                            Instant::now() < deadline,
                                            timing,
                                        )?;
                                    }
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
                        let request =
                            workload_request(sent + 1, key, ber, burst, headers, sessions.as_ref());
                        if let Some(times) = &send_times {
                            // Publish before the syscall: a fast reply can be read
                            // while send() is still returning on the sender thread.
                            times.mark(sent + 1, elapsed_ns(start)?)?;
                        }
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
                let inventory_summary = inventory_worker
                    .map(|worker| worker.join().map_err(|_| "inventory thread panicked")?)
                    .transpose()?;
                let skipped_slots = (capacity - 1) as u64 - sent as u64;
                Ok((
                    sent,
                    skipped_slots,
                    replies,
                    reflector_cpu,
                    generator_cpu,
                    inventory_summary,
                ))
            })?;
        child.check()?;
        let memory_after_drain = memory::snapshot(args.memory, child.0.id())?;
        let unique = replies.unique_during_load + replies.unique_during_drain;
        if unique > sent as u64 || replies.highest.is_some_and(|seq| seq > sent) {
            return Err("received an unsent sequence; accounting is invalid".into());
        }
        if unique == 0 {
            return Err("no valid responses during the load/drain sample".into());
        }
        let observed_rtt = replies.rtt.as_ref().map(Samples::summary);
        if observed_rtt
            .as_ref()
            .is_some_and(|summary| summary.samples != unique)
        {
            return Err("latency samples do not match unique valid replies".into());
        }
        let session_summary = replies
            .sessions
            .as_ref()
            .map(|sessions| sessions.summary(sent))
            .transpose()?;
        if session_summary
            .as_ref()
            .is_some_and(|summary| summary.unique_replies != unique)
        {
            return Err("session totals disagree with unique reply accounting".into());
        }
        let idle_after = idle(&mut child, args.idle_seconds, hz)?;
        let memory_after_idle = memory::snapshot(args.memory, child.0.id())?;
        let burst_summary = replies
            .copies
            .as_ref()
            .map(|copies| copies.summary(sent))
            .transpose()?;
        if burst_summary
            .as_ref()
            .is_some_and(|summary| summary.received_probes as u64 != unique)
        {
            return Err("burst probe totals disagree with unique reply accounting".into());
        }
        workload_probe(&mut child, &socket, key, ber, burst, headers, sent + 1)?;
        Ok(json!({
            "reflector_command": command_line, "sent": sent, "replies": replies,
            "memory": memory_before_load.map(|before_load| json!({
                "source": "/proc/<pid>/smaps_rollup",
                "before_load": before_load,
                "after_drain": memory_after_drain,
                "after_idle": memory_after_idle,
            })),
            "observed_rtt": observed_rtt,
            "burst":burst_summary,
            "sessions": session_summary,
            "inventory": inventory_summary,
            "unique_reply_copy_pps_during_load":burst_summary.as_ref().map(|summary|summary.unique_during_load as f64/args.seconds as f64),
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
        if args.inventory.is_some() && !cfg!(feature = "control") {
            return Err("inventory workloads require the control build feature".into());
        }
        let sessions = args
            .sessions
            .map(|count| Sessions::new(count, u64::from(args.rate) * u64::from(args.seconds)))
            .transpose()?;
        let headers = args
            .headers
            .map(|mode| Headers::new(mode, args.ipv6, args.header_bytes, args.headers_denied))
            .transpose()?;
        if headers.is_some() && cfg!(all(feature = "ttl-pnet", not(feature = "ttl-nix"))) {
            return Err("header workloads require the Linux nix backend".into());
        }
        let burst = args
            .burst_count
            .map(|count| Burst::new(count, args.burst_bytes.unwrap_or(240)))
            .transpose()?;
        if let Some(burst) = &burst {
            burst.validate_capacity(args.rate as usize * args.seconds as usize)?;
        }
        if args.latency {
            super::latency::validate_capacity(args.rate as usize * args.seconds as usize + 1)?;
        }
        let ber = args
            .ber_padding
            .map(|bytes| Profile::new(usize::from(bytes), args.ber_damaged))
            .transpose()?;
        args.reflector = fs::canonicalize(&args.reflector)?;
        // SAFETY: sysconf takes an integer name and no pointers; it has no memory-safety
        // preconditions.
        let hz = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
        if hz <= 0 {
            return Err("could not determine CPU tick frequency".into());
        }
        let key = args
            .authenticated
            .then(|| HmacKey::from_hex(KEY))
            .transpose()?;
        let mut trials = Vec::new();
        let mut failure = None;
        for index in 0..args.repeats {
            eprintln!("live UDP trial {}/{}", index + 1, args.repeats);
            match trial(
                &args,
                key.as_ref(),
                ber.as_ref(),
                burst.as_ref(),
                headers.as_ref(),
                hz as u64,
            ) {
                Ok(result) => trials.push(result),
                Err(error) => {
                    failure = Some(error.to_string());
                    break;
                }
            }
        }
        let binary_hash =
            |path| -> Result<String> { Ok(hex::encode(Sha256::digest(fs::read(path)?))) };
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "schema_version": 1, "settings": args, "trials": trials,
                "completed": failure.is_none(), "error": failure,
                "request_payload_octets": workload_request(0, key.as_ref(), ber.as_ref(),burst.as_ref(),headers.as_ref(), sessions.as_ref()).len(),
                "ber_profile": ber.as_ref().map(Profile::summary),
                "burst_profile":burst.as_ref().map(Burst::summary),
                "header_profile":headers.as_ref().map(Headers::summary),
                "session_profile": sessions.as_ref().map(Sessions::summary),
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
        if let Some(error) = failure {
            return Err(error.into());
        }
        Ok(())
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn inventory_requires_a_bounded_session_workload() {
            assert!(Args::try_parse_from(["bench", "--inventory", "full"]).is_err());
            for mode in ["idle", "full", "page100", "page500"] {
                let args = Args::try_parse_from([
                    "bench",
                    "--stateful",
                    "--sessions",
                    "100",
                    "--inventory",
                    mode,
                ])
                .unwrap();
                assert!(args.inventory.is_some());
            }
            assert!(Args::try_parse_from([
                "bench",
                "--stateful",
                "--sessions",
                "100",
                "--inventory",
                "page999"
            ])
            .is_err());
        }

        #[test]
        fn session_workload_requires_stateful_and_excludes_tlv_profiles() {
            for args in [
                vec!["bench", "--sessions", "2"],
                vec!["bench", "--stateful", "--sessions", "0"],
                vec!["bench", "--stateful", "--sessions", "65535"],
                vec![
                    "bench",
                    "--stateful",
                    "--sessions",
                    "2",
                    "--ber-padding",
                    "120",
                ],
                vec![
                    "bench",
                    "--stateful",
                    "--sessions",
                    "2",
                    "--burst-count",
                    "2",
                ],
                vec![
                    "bench",
                    "--stateful",
                    "--sessions",
                    "2",
                    "--headers",
                    "fixed",
                ],
            ] {
                assert!(Args::try_parse_from(args).is_err());
            }
            let args = Args::try_parse_from([
                "bench",
                "--stateful",
                "--sessions",
                "65534",
                "--latency",
                "--ipv6",
                "--authenticated",
            ])
            .unwrap();
            assert_eq!(args.sessions, Some(65534));
        }

        #[test]
        fn session_accounting_uses_only_admitted_unique_replies() {
            let profile = Sessions::new(2, 4).unwrap();
            let mut replies = Replies {
                seen: vec![false; 5],
                sessions: Some(SessionReplies::new(&profile)),
                ..Default::default()
            };
            for seq in [Some(0), Some(2), Some(1), Some(2), None, Some(5), Some(3)] {
                replies.record_received(seq, true, None).unwrap();
            }
            let summary = replies.sessions.as_ref().unwrap().summary(4).unwrap();
            assert_eq!(summary.unique_replies, 3);
            assert_eq!(summary.fully_replied_sessions, 1);
            assert_eq!(summary.partially_replied_sessions, 1);
            assert_eq!(replies.unique_during_load, 3);
            assert_eq!(replies.duplicates, 1);
            assert_eq!(replies.invalid, 2);
        }

        #[test]
        fn header_options_require_a_mode_and_exclude_other_workloads() {
            for args in [
                vec!["bench", "--headers-denied"],
                vec!["bench", "--header-bytes", "16"],
                vec!["bench", "--headers", "fixed", "--ber-padding", "120"],
                vec![
                    "bench",
                    "--headers",
                    "fixed",
                    "--stateful",
                    "--burst-count",
                    "4",
                ],
            ] {
                assert!(Args::try_parse_from(args).is_err());
            }
            let args = Args::try_parse_from([
                "bench",
                "--headers",
                "combined",
                "--ipv6",
                "--header-bytes",
                "256",
                "--headers-denied",
            ])
            .unwrap();
            assert!(Headers::new(
                args.headers.unwrap(),
                args.ipv6,
                args.header_bytes,
                args.headers_denied
            )
            .is_ok());
            assert!(Headers::new(HeaderMode::Ipv6Ext, false, None, false).is_err());
        }

        #[test]
        fn header_workload_keeps_base_identity_and_signature_checks() {
            use stamp_suite::tlv::{
                ReflectedFixedHdrTlv, ReflectedIpv6ExtHdrTlv, TlvList, TypedTlv,
            };
            for auth in [false, true] {
                let key = auth.then(|| HmacKey::from_hex(KEY).unwrap());
                let profile = Headers::new(HeaderMode::Combined, true, Some(16), false).unwrap();
                let base = if auth { 112 } else { 44 };
                let mut bytes = vec![0; base];
                let (ssid, seq, timestamp, estimate) = if auth {
                    (26, 48, 64, 72)
                } else {
                    (14, 24, 28, 36)
                };
                bytes[..4].copy_from_slice(&9u32.to_be_bytes());
                bytes[ssid..ssid + 2].copy_from_slice(&SSID.to_be_bytes());
                bytes[seq..seq + 4].copy_from_slice(&3u32.to_be_bytes());
                bytes[timestamp..timestamp + 8].copy_from_slice(&STAMP.to_be_bytes());
                bytes[estimate..estimate + 2].copy_from_slice(&1u16.to_be_bytes());
                let mut fixed = ReflectedFixedHdrTlv::request_with_capacity(40).to_raw();
                fixed.clear_reflector_flags();
                fixed.set_conformant_reflected();
                let mut ext = ReflectedIpv6ExtHdrTlv::with_data(vec![
                    17, 1, 0x1e, 12, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12,
                ])
                .to_raw();
                ext.clear_reflector_flags();
                let mut list = TlvList::new();
                list.push(fixed).unwrap();
                list.push(ext).unwrap();
                if let Some(key) = &key {
                    let digest = key.compute(&bytes[..96]);
                    bytes[96..112].copy_from_slice(&digest);
                    assert!(list.set_hmac_response(key, &bytes[..4]));
                }
                bytes.extend(list.to_bytes());
                assert_eq!(
                    workload_response(&bytes, key.as_ref(), None, None, Some(&profile), None),
                    Some(3)
                );
                assert_eq!(
                    workload_response(&bytes, key.as_ref(), None, None, None, None),
                    None
                );
                for offset in [ssid, timestamp, estimate] {
                    let mut wrong = bytes.clone();
                    wrong[offset] ^= 1;
                    if let Some(key) = &key {
                        let digest = key.compute(&wrong[..96]);
                        wrong[96..112].copy_from_slice(&digest);
                    }
                    assert_eq!(
                        workload_response(&wrong, key.as_ref(), None, None, Some(&profile), None),
                        None
                    );
                }
                if auth {
                    bytes[96] ^= 1;
                    assert_eq!(
                        workload_response(&bytes, key.as_ref(), None, None, Some(&profile), None),
                        None
                    );
                }
            }
        }

        #[test]
        fn burst_options_require_stateful_mode_and_exclude_ber() {
            for args in [
                vec!["bench", "--burst-count", "4"],
                vec!["bench", "--burst-bytes", "240"],
                vec!["bench", "--stateful", "--burst-count", "0"],
                vec!["bench", "--stateful", "--burst-count", "17"],
                vec![
                    "bench",
                    "--stateful",
                    "--burst-count",
                    "4",
                    "--ber-padding",
                    "120",
                ],
            ] {
                assert!(Args::try_parse_from(args).is_err());
            }
            let args = Args::try_parse_from([
                "bench",
                "--stateful",
                "--burst-count",
                "16",
                "--burst-bytes",
                "1200",
            ])
            .unwrap();
            assert!(Burst::new(args.burst_count.unwrap(), args.burst_bytes.unwrap()).is_ok());
        }

        #[test]
        fn burst_copy_accounting_keeps_first_reply_latency_and_distinguishes_duplicates() {
            let burst = Burst::new(4, 240).unwrap();
            let times = SendTimes::new(4).unwrap();
            times.mark(1, 100).unwrap();
            times.mark(2, 100).unwrap();
            let mut replies = Replies {
                seen: vec![false; 4],
                rtt: Some(Samples::default()),
                copies: Some(Copies::new(&burst, 4).unwrap()),
                ..Default::default()
            };
            for (probe, nonce, load, received) in [
                (Some(0), Some(0), true, 0),
                (Some(1), Some(u32::MAX), true, 200),
                (Some(1), Some(0), true, 250),
                (Some(1), Some(0), false, 800),
                (Some(2), Some(0), false, 400),
                (Some(1), Some(1), false, 300),
                (Some(1), Some(2), false, 600),
                (Some(1), Some(3), true, 700),
                (None, None, true, 0),
                (Some(4), Some(0), true, 0),
            ] {
                replies
                    .record_burst(probe, nonce, load, Some((&times, received)))
                    .unwrap();
            }
            assert_eq!(
                (
                    replies.unique_during_load,
                    replies.unique_during_drain,
                    replies.duplicates,
                    replies.invalid
                ),
                (1, 1, 1, 3)
            );
            let rtt = serde_json::to_value(replies.rtt.as_ref().unwrap().summary()).unwrap();
            assert_eq!(rtt["samples"], 2);
            assert_eq!(rtt["mean_ns"], 200.0);
            let copies =
                serde_json::to_value(replies.copies.as_ref().unwrap().summary(3).unwrap()).unwrap();
            assert_eq!(copies["unique_copies"], 5);
            assert_eq!(copies["missing_copies"], 7);
            assert_eq!(copies["received_probes"], 2);
            assert_eq!(copies["unique_during_load"], 2);
            assert_eq!(copies["unique_during_drain"], 3);
        }

        #[test]
        fn burst_reply_validation_keeps_signed_base_identity_checks() {
            use stamp_suite::tlv::{ExtraPaddingTlv, ReflectedControlTlv, TlvList, TypedTlv};
            for auth in [false, true] {
                let key = auth.then(|| HmacKey::from_hex(KEY).unwrap());
                let profile = Burst::new(4, 240).unwrap();
                let base = if auth { 112 } else { 44 };
                let mut bytes = vec![0; base];
                let (ssid, seq, timestamp, estimate) = if auth {
                    (26, 48, 64, 72)
                } else {
                    (14, 24, 28, 36)
                };
                bytes[..4].copy_from_slice(&9u32.to_be_bytes());
                bytes[ssid..ssid + 2].copy_from_slice(&SSID.to_be_bytes());
                bytes[seq..seq + 4].copy_from_slice(&3u32.to_be_bytes());
                bytes[timestamp..timestamp + 8].copy_from_slice(&STAMP.to_be_bytes());
                bytes[estimate..estimate + 2].copy_from_slice(&1u16.to_be_bytes());
                let mut list = TlvList::new();
                list.push(ReflectedControlTlv::new(240, 4, 1_000_000).to_raw())
                    .unwrap();
                list.push(
                    ExtraPaddingTlv::new_zeros(240 - base - 16 - 4 - if auth { 20 } else { 0 })
                        .to_raw(),
                )
                .unwrap();
                list.clear_reflector_flags();
                if let Some(key) = &key {
                    let digest = key.compute(&bytes[..96]);
                    bytes[96..112].copy_from_slice(&digest);
                    assert!(list.set_hmac_response(key, &bytes[..4]));
                }
                bytes.extend(list.to_bytes());
                assert_eq!(
                    workload_response(&bytes, key.as_ref(), None, Some(&profile), None, None),
                    Some(3)
                );
                assert_eq!(
                    workload_response(&bytes, key.as_ref(), None, None, None, None),
                    None
                );
                for offset in [ssid, timestamp, estimate] {
                    let mut wrong = bytes.clone();
                    wrong[offset] ^= 1;
                    if let Some(key) = &key {
                        let digest = key.compute(&wrong[..96]);
                        wrong[96..112].copy_from_slice(&digest);
                    }
                    assert_eq!(
                        workload_response(&wrong, key.as_ref(), None, Some(&profile), None, None),
                        None
                    );
                }
                if auth {
                    bytes[96] ^= 1;
                    assert_eq!(
                        workload_response(&bytes, key.as_ref(), None, Some(&profile), None, None),
                        None
                    );
                }
            }
        }

        #[test]
        fn latency_ignores_warmup_duplicates_and_invalid_replies_and_includes_drain() {
            let times = SendTimes::new(4).unwrap();
            times.mark(1, 100).unwrap();
            times.mark(2, 150).unwrap();
            times.mark(3, 200).unwrap();
            let mut replies = Replies {
                seen: vec![false; 4],
                rtt: Some(Samples::default()),
                ..Default::default()
            };
            for (seq, during_load, received_ns) in [
                (Some(0), true, 0),
                (Some(3), true, 300),
                (Some(1), false, 500),
                (Some(3), true, 1000),
                (None, true, 0),
                (Some(4), true, 0),
                (Some(2), true, 250),
            ] {
                replies
                    .record_received(seq, during_load, Some((&times, received_ns)))
                    .unwrap();
            }
            assert_eq!(
                (
                    replies.unique_during_load,
                    replies.unique_during_drain,
                    replies.duplicates,
                    replies.invalid,
                    replies.out_of_order
                ),
                (2, 1, 1, 2, 2)
            );
            let summary = serde_json::to_value(replies.rtt.as_ref().unwrap().summary()).unwrap();
            assert_eq!(summary["samples"], 3);
            assert_eq!(summary["min_ns"], 100);
            assert_eq!(summary["max_ns"], 400);
            assert_eq!(summary["mean_ns"], 200.0);
            assert!(!replies.seen[0]);
        }

        #[test]
        fn latency_rejects_missing_timing_and_disabled_mode_keeps_no_samples() {
            let times = SendTimes::new(3).unwrap();
            for timing in [None, Some((&times, 100))] {
                let mut replies = Replies {
                    seen: vec![false; 3],
                    rtt: Some(Samples::default()),
                    ..Default::default()
                };
                assert!(replies.record_received(Some(1), true, timing).is_err());
            }
            let mut plain = Replies {
                seen: vec![false; 3],
                ..Default::default()
            };
            plain.record_received(Some(1), true, None).unwrap();
            assert_eq!(plain.unique_during_load, 1);
            assert!(plain.rtt.is_none());
            assert!(
                Args::try_parse_from(["bench", "--latency"])
                    .unwrap()
                    .latency
            );
        }

        #[test]
        fn ber_options_require_padding_and_enforce_cli_bounds() {
            assert!(Args::try_parse_from(["bench", "--ber-damaged"]).is_err());
            for value in ["0", "15", "1201", "65536", "invalid"] {
                assert!(Args::try_parse_from(["bench", "--ber-padding", value]).is_err());
            }
            for value in ["16", "120", "1200"] {
                let args = Args::try_parse_from(["bench", "--ber-padding", value, "--ber-damaged"])
                    .unwrap();
                assert!(
                    Profile::new(usize::from(args.ber_padding.unwrap()), args.ber_damaged).is_ok()
                );
            }
        }

        #[test]
        fn ber_reply_validation_retains_base_identity_and_authentication_checks() {
            use stamp_suite::tlv::{
                ExtraPaddingTlv, ResidualBerValue, TlvList, TypedTlv, RESIDUAL_BER_DEFAULT_PATTERN,
            };
            for auth in [false, true] {
                let key = auth.then(|| HmacKey::from_hex(KEY).unwrap());
                for padding in [16, 120, 1200] {
                    for damaged in [false, true] {
                        let profile = Profile::new(padding, damaged).unwrap();
                        let mut buf = vec![0; if auth { 112 } else { 44 }];
                        let (ssid, seq, timestamp, estimate) = if auth {
                            (26, 48, 64, 72)
                        } else {
                            (14, 24, 28, 36)
                        };
                        // Stateful reflector sequence differs from the echoed sender sequence.
                        buf[..4].copy_from_slice(&9u32.to_be_bytes());
                        buf[ssid..ssid + 2].copy_from_slice(&SSID.to_be_bytes());
                        buf[seq..seq + 4].copy_from_slice(&3u32.to_be_bytes());
                        buf[timestamp..timestamp + 8].copy_from_slice(&STAMP.to_be_bytes());
                        buf[estimate..estimate + 2].copy_from_slice(&1u16.to_be_bytes());
                        let (count, max_burst) = if damaged { (5, 4) } else { (0, 0) };
                        let mut tlvs = TlvList::new();
                        tlvs.push(
                            ResidualBerValue {
                                count,
                                max_burst,
                                sub_tlvs: vec![],
                            }
                            .to_raw()
                            .unwrap(),
                        )
                        .unwrap();
                        tlvs.push(
                            ExtraPaddingTlv {
                                padding: RESIDUAL_BER_DEFAULT_PATTERN.repeat(padding / 4),
                            }
                            .to_raw(),
                        )
                        .unwrap();
                        tlvs.clear_reflector_flags();
                        if let Some(key) = &key {
                            let digest = key.compute(&buf[..96]);
                            buf[96..112].copy_from_slice(&digest);
                            assert!(tlvs.set_hmac_response(key, &buf[..4]));
                        }
                        buf.extend(tlvs.to_bytes());
                        assert_eq!(
                            response_sequence(&buf, key.as_ref(), Some(&profile)),
                            Some(3)
                        );
                        assert_eq!(response_sequence(&buf, key.as_ref(), None), None);
                        let wrong_profile = Profile::new(padding, !damaged).unwrap();
                        assert_eq!(
                            response_sequence(&buf, key.as_ref(), Some(&wrong_profile)),
                            None
                        );
                        for offset in [ssid, timestamp, estimate] {
                            let mut wrong = buf.clone();
                            wrong[offset] ^= 1;
                            if let Some(key) = &key {
                                let digest = key.compute(&wrong[..96]);
                                wrong[96..112].copy_from_slice(&digest);
                            }
                            assert_eq!(
                                response_sequence(&wrong, key.as_ref(), Some(&profile)),
                                None
                            );
                        }
                        if auth {
                            buf[96] ^= 1;
                            assert_eq!(response_sequence(&buf, key.as_ref(), Some(&profile)), None);
                        }
                    }
                }
            }
        }

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
