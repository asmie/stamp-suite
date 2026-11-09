//! Child reflector lifecycle shared by live wire tests. No port reservation,
//! automatic restart or readiness traffic: the receiver reports its bound port.
#![allow(dead_code)] // Each integration target uses a different helper subset.

use std::{
    collections::VecDeque,
    io::{self, Read},
    net::SocketAddr,
    process::{Child, Command, Stdio},
    sync::{mpsc, Arc, Mutex},
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

pub const STDERR_LIMIT: usize = 64 * 1024;

#[derive(Default)]
struct Capture(VecDeque<u8>);
impl Capture {
    fn append(&mut self, data: &[u8]) {
        let excess = (self.0.len() + data.len()).saturating_sub(STDERR_LIMIT);
        self.0.drain(..excess.min(self.0.len()));
        self.0.extend(data.iter().rev().take(STDERR_LIMIT).rev());
    }

    fn text(&self) -> String {
        String::from_utf8_lossy(&self.0.iter().copied().collect::<Vec<_>>()).into_owned()
    }
}

fn bound_address(line: &[u8]) -> Option<SocketAddr> {
    let value: serde_json::Value = serde_json::from_slice(line).ok()?;
    value
        .get("fields")?
        .get("message")?
        .as_str()?
        .strip_prefix("STAMP Reflector listening on ")?
        .split_whitespace()
        .next()?
        .parse()
        .ok()
}

pub struct Reflector {
    pub child: Child,
    pub address: SocketAddr,
    capture: Arc<Mutex<Capture>>,
    reader: Option<JoinHandle<()>>,
}

impl Reflector {
    /// A loopback/wildcard receiver with a kernel-selected port. Tests may add
    /// mode, key, admission and stdout options before calling `spawn`.
    pub fn command(ip: &str) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_stamp-suite"));
        command
            .args([
                "--is-reflector",
                "--local-addr",
                ip,
                "--local-port",
                "0",
                "--log-format",
                "json",
            ])
            .stdout(Stdio::null());
        command
    }

    pub fn spawn(command: Command) -> Result<Self, String> {
        Self::spawn_with_timeout(command, Duration::from_secs(5))
    }

    pub fn spawn_with_timeout(mut command: Command, timeout: Duration) -> Result<Self, String> {
        // The fixtures need few workers regardless of host CPU count. This is
        // a test resource bound, not a retry or an explanation of past flakes.
        command
            .env("RUST_LOG", "info")
            .env("TOKIO_WORKER_THREADS", "2")
            .env_remove("STAMP_HMAC_KEY")
            .stderr(Stdio::piped());
        let mut child = command
            .spawn()
            .map_err(|e| format!("cannot spawn reflector: {e}"))?;
        let stderr = child.stderr.take().expect("piped child stderr");
        let capture = Arc::new(Mutex::new(Capture::default()));
        let output = Arc::clone(&capture);
        let (ready_tx, ready_rx) = mpsc::sync_channel(1);
        let mut result = Self {
            child,
            address: "0.0.0.0:0".parse().unwrap(),
            capture,
            reader: None,
        };
        let reader = thread::Builder::new()
            .name("reflector-stderr".into())
            .spawn(move || {
                let mut stderr = stderr;
                let mut chunk = [0; 4096];
                let mut line = Vec::new();
                let mut oversized = false;
                loop {
                    let count = match stderr.read(&mut chunk) {
                        Ok(0) => break,
                        Ok(count) => count,
                        Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                        Err(e) => {
                            output
                                .lock()
                                .unwrap()
                                .append(format!("\nstderr read failed: {e}").as_bytes());
                            break;
                        }
                    };
                    output.lock().unwrap().append(&chunk[..count]);
                    for &byte in &chunk[..count] {
                        if byte == b'\n' {
                            if !oversized {
                                if let Some(address) = bound_address(&line) {
                                    let _ = ready_tx.try_send(address);
                                }
                            }
                            line.clear();
                            oversized = false;
                        } else if !oversized {
                            if line.len() < STDERR_LIMIT {
                                line.push(byte);
                            } else {
                                line.clear();
                                oversized = true;
                            }
                        }
                    }
                }
            });
        match reader {
            Ok(reader) => result.reader = Some(reader),
            Err(e) => return Err(result.failure(&format!("cannot collect reflector stderr: {e}"))),
        }
        let started = Instant::now();
        loop {
            match result.child.try_wait() {
                Ok(Some(_)) => return Err(result.failure("reflector exited during startup")),
                Err(e) => return Err(result.failure(&format!("cannot inspect reflector: {e}"))),
                Ok(None) => {}
            }
            if started.elapsed() >= timeout {
                return Err(result.failure("reflector startup timed out"));
            }
            match ready_rx.recv_timeout(Duration::from_millis(10)) {
                Ok(address) if address.port() != 0 => {
                    result.address = address;
                    return Ok(result);
                }
                Ok(_) => return Err(result.failure("reflector reported an unassigned port")),
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    // EOF can precede process exit by a scheduler turn. Allow
                    // a short exit-status collection window before forcing
                    // cleanup; never restart or repeat the startup attempt.
                    let eof = Instant::now();
                    while result.child.try_wait().ok().flatten().is_none()
                        && eof.elapsed() < Duration::from_millis(50)
                    {
                        thread::sleep(Duration::from_millis(1));
                    }
                    return Err(result.failure("reflector stderr closed before readiness"));
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {}
            }
        }
    }

    pub fn diagnostics(&self) -> String {
        self.capture.lock().unwrap().text()
    }

    /// The control server announces its assigned endpoint before the UDP
    /// receiver starts. Keep its test-side TCP port selection race-free too.
    pub fn control_address(&self) -> SocketAddr {
        let diagnostics = self.diagnostics();
        diagnostics
            .lines()
            .find_map(|line| {
                let value: serde_json::Value = serde_json::from_str(line).ok()?;
                value
                    .get("fields")?
                    .get("message")?
                    .as_str()?
                    .strip_prefix("control-plane API listening on http://")?
                    .split('/')
                    .next()?
                    .parse()
                    .ok()
            })
            .unwrap_or_else(|| {
                panic!("control endpoint missing from startup diagnostics:\n{diagnostics}")
            })
    }

    fn stop(&mut self) -> io::Result<std::process::ExitStatus> {
        let _ = self.child.kill();
        let status = self.child.wait();
        if let Some(reader) = self.reader.take() {
            let _ = reader.join();
        }
        status
    }

    fn failure(&mut self, reason: &str) -> String {
        let pid = self.child.id();
        let status = match self.stop() {
            Ok(status) => status.to_string(),
            Err(error) => format!("cannot collect status: {error}"),
        };
        format!(
            "{reason}; pid={pid}; status={status}; stderr tail:\n{}",
            self.diagnostics()
        )
    }
}

impl Drop for Reflector {
    fn drop(&mut self) {
        let _ = self.stop();
    }
}
