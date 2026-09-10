//! CLI stdout remains parseable with default diagnostics, packet details and timers.
#![cfg(all(
    target_os = "linux",
    any(feature = "ttl-nix", not(feature = "ttl-pnet"))
))]

use std::{
    fs::File,
    io::{Read, Seek, SeekFrom},
    net::UdpSocket,
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};

struct Process {
    child: Child,
    stdout: File,
    stderr: File,
}
impl Process {
    fn start(args: &[&str], quiet: bool) -> Self {
        let stdout = tempfile::tempfile().unwrap();
        let stderr = tempfile::tempfile().unwrap();
        let mut command = Command::new(env!("CARGO_BIN_EXE_stamp-suite"));
        command
            .args(args)
            .env_remove("RUST_LOG")
            .env_remove("STAMP_HMAC_KEY")
            .env("TOKIO_WORKER_THREADS", "2");
        if quiet {
            command.env("RUST_LOG", "off");
        }
        let child = command
            .stdout(Stdio::from(stdout.try_clone().unwrap()))
            .stderr(Stdio::from(stderr.try_clone().unwrap()))
            .spawn()
            .unwrap();
        Self {
            child,
            stdout,
            stderr,
        }
    }
    fn finish(&mut self, success: bool) -> (String, String) {
        let start = Instant::now();
        let status = loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                break status;
            }
            assert!(
                start.elapsed() < Duration::from_secs(10),
                "child {} did not exit; inspect stdout/stderr for its last activity",
                self.child.id()
            );
            std::thread::sleep(Duration::from_millis(10));
        };
        let read = |file: &mut File| {
            file.seek(SeekFrom::Start(0)).unwrap();
            let mut text = String::new();
            file.read_to_string(&mut text).unwrap();
            text
        };
        let stdout = read(&mut self.stdout);
        let stderr = read(&mut self.stderr);
        assert_eq!(status.success(), success, "{status}: {stderr}");
        (stdout, stderr)
    }
}
impl Drop for Process {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn reflector(format: &str, log_format: &str, quiet: bool) -> (Process, u16) {
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    let port = socket.local_addr().unwrap().port();
    drop(socket);
    let mut child = Process::start(
        &[
            "-i",
            "--local-addr",
            "127.0.0.1",
            "--local-port",
            &port.to_string(),
            "--hwtstamp",
            "off",
            "--output-format",
            format,
            "--log-format",
            log_format,
        ],
        quiet,
    );
    let probe = UdpSocket::bind("127.0.0.1:0").unwrap();
    probe
        .set_read_timeout(Some(Duration::from_millis(40)))
        .unwrap();
    let start = Instant::now();
    loop {
        assert!(
            child.child.try_wait().unwrap().is_none(),
            "reflector exited during startup"
        );
        probe.send_to(&[0; 44], ("127.0.0.1", port)).unwrap();
        if probe.recv_from(&mut [0; 256]).is_ok() {
            break;
        }
        assert!(
            start.elapsed() < Duration::from_secs(5),
            "reflector not ready"
        );
    }
    (child, port)
}

fn exercise(format: &str, log_format: &str, periodic: bool, quiet: bool) {
    let (mut reflector, port) = reflector(format, log_format, quiet);
    let mut sender = Process::start(
        &[
            "--local-addr",
            "127.0.0.1",
            "--local-port",
            "0",
            "--remote-addr",
            "127.0.0.1",
            "--remote-port",
            &port.to_string(),
            "--count",
            "3",
            "--send-delay",
            if periodic { "650" } else { "10" },
            "--timeout",
            "1",
            "--hwtstamp",
            "off",
            "--output-format",
            format,
            "--log-format",
            log_format,
            "-R",
            "--ber",
            "--report-interval",
            if periodic { "1" } else { "0" },
        ],
        quiet,
    );
    let (stdout, stderr) = sender.finish(true);
    // The readiness probe proves the signal handler is running before shutdown.
    assert_eq!(
        unsafe { libc::kill(reflector.child.id() as i32, libc::SIGINT) },
        0
    );
    let (reflector_stdout, reflector_stderr) = reflector.finish(true);
    if !quiet {
        for diagnostics in [&stderr, &reflector_stderr] {
            assert!(
                diagnostics.contains("Configuration valid. Starting up..."),
                "{diagnostics}"
            );
            if log_format == "json" {
                let events: Vec<serde_json::Value> = diagnostics
                    .lines()
                    .filter(|l| l.starts_with('{'))
                    .map(|l| serde_json::from_str(l).unwrap())
                    .collect();
                assert!(!events.is_empty());
                assert!(events.iter().all(|v| v["level"].is_string()));
            }
        }
        assert!(reflector_stderr.contains("STAMP Reflector listening"));
    } else {
        assert!(!stderr.contains("Configuration valid"));
        assert!(reflector_stderr.is_empty(), "{reflector_stderr}");
    }
    if format == "text" {
        assert!(stdout.contains("seq=0 rtt="));
        assert!(stdout.contains("--- STAMP Statistics ---"));
        assert!(stdout.contains("Quantiles: exact through 4096 samples"));
        assert!(reflector_stdout.contains("--- STAMP Reflector Statistics ---"));
    } else {
        assert!(
            stderr.contains("seq=0 rtt="),
            "-R remains visible: {stderr}"
        );
        assert!(!stdout.contains("seq="));
        if format == "json" {
            let reports: Vec<serde_json::Value> = stdout
                .lines()
                .map(|line| serde_json::from_str(line).expect("stdout must be JSON lines"))
                .collect();
            assert_eq!(reports.last().unwrap()["type"], "summary");
            assert_eq!(reports.last().unwrap()["packets_received"], 3);
            assert!(reports.last().unwrap()["ber"].is_object());
            for report in &reports {
                assert_eq!(report["quantile_precision"]["exact_sample_limit"], 4096);
                assert_eq!(
                    report["quantile_precision"]["relative_error_bound"],
                    1.0 / 128.0
                );
                assert_eq!(report["ber"]["intervals_omitted"], 0);
                assert_eq!(report["ber"]["alarms_omitted"], 0);
            }
            assert_eq!(reports.len() > 1, periodic);
            assert!(reports[..reports.len() - 1]
                .iter()
                .all(|v| v["type"] == "interim"));
            let reflected: serde_json::Value = serde_json::from_str(&reflector_stdout).unwrap();
            assert!(reflected["total_packets_reflected"].as_u64().unwrap() >= 4);
        } else {
            let mut lines = stdout.lines();
            let header = lines.next().unwrap();
            assert!(header.starts_with("packets_sent,packets_received,"));
            assert_eq!(header.split(',').count(), 27);
            let rows: Vec<_> = lines.collect();
            assert_eq!(rows.len() > 1, periodic);
            for row in &rows {
                // First 26 fields are numeric/enums; the final BER field is quoted JSON.
                let cells: Vec<_> = row.splitn(27, ',').collect();
                assert_eq!(cells.len(), 27);
                assert!(
                    cells[0].parse::<u32>().is_ok(),
                    "repeated header or diagnostic: {row}"
                );
                assert_eq!(cells[24], "4096");
                assert_eq!(cells[25].parse::<f64>().unwrap(), 1.0 / 128.0);
                let encoded = cells[26]
                    .strip_prefix('"')
                    .unwrap()
                    .strip_suffix('"')
                    .unwrap();
                assert!(
                    !encoded.replace("\"\"", "").contains('"'),
                    "CSV quotes must be doubled"
                );
                let ber: serde_json::Value =
                    serde_json::from_str(&encoded.replace("\"\"", "\"")).unwrap();
                assert!(ber.is_object());
            }
            assert_eq!(rows.last().unwrap().split(',').nth(1), Some("3"));
            let reflected: Vec<_> = reflector_stdout.lines().collect();
            assert_eq!(reflected.len(), 2);
            assert_eq!(
                reflected[0],
                "total_received,total_reflected,total_dropped,active_sessions,uptime_seconds,reply_queue_rejected,queued_replies_cancelled"
            );
            assert_eq!(reflected[1].split(',').count(), 7);
            assert!(reflected[1]
                .split(',')
                .all(|cell| cell.parse::<f64>().is_ok()));
        }
    }
}

#[test]
fn json_stdout_with_default_and_json_logs() {
    for logs in ["text", "json"] {
        exercise("json", logs, false, false);
    }
}
#[test]
fn csv_stdout_with_default_and_json_logs() {
    for logs in ["text", "json"] {
        exercise("csv", logs, false, false);
    }
}
#[test]
fn periodic_json_stdout() {
    exercise("json", "text", true, false);
}
#[test]
fn periodic_csv_has_one_header() {
    exercise("csv", "json", true, false);
}
#[test]
fn quiet_logging_keeps_requested_packet_details() {
    exercise("json", "text", false, true);
}
#[test]
fn text_output_keeps_packet_details() {
    exercise("text", "text", false, false);
}
#[test]
fn schema_and_invalid_config_output() {
    let (stdout, stderr) = Process::start(&["--print-config-schema"], false).finish(true);
    let schema: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert!(schema["properties"].is_object());
    assert!(stderr.is_empty());
    let (stdout, stderr) = Process::start(&["--output-format", "invalid"], false).finish(false);
    assert!(stdout.is_empty());
    assert!(stderr.contains("invalid"));
}
