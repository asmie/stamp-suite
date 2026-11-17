//! Starts the reflector on kernel-assigned ports and reads the ports from its
//! JSON startup log, so no port is released and then bound again.
use std::{
    io::{BufRead, BufReader, Write},
    net::SocketAddr,
    process::{Child, ChildStderr, Command, Stdio},
    sync::mpsc::{self, RecvTimeoutError, Sender},
    thread,
    time::{Duration, Instant},
};

pub(super) type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

const TIMEOUT: Duration = Duration::from_secs(10);
/// Errors, plus the info-level startup lines that announce the endpoints.
/// These modules log nothing else at info during a trial.
const LOG_FILTER: &str = "error,stamp_suite::receiver::nix=info,\
                          stamp_suite::receiver::pnet=info,stamp_suite::control=info";

enum Announcement {
    Udp(SocketAddr),
    Control(SocketAddr),
}

pub(super) struct Endpoints {
    pub udp: SocketAddr,
    /// Present when the reflector runs the control API.
    pub control: Option<SocketAddr>,
}

/// Makes the reflector log JSON to a pipe. Call before spawning `command`.
pub(super) fn configure(command: &mut Command) {
    command
        .args(["--log-format", "json"])
        .env("RUST_LOG", LOG_FILTER)
        .stderr(Stdio::piped());
}

/// Copies the reflector's stderr to ours for the rest of the trial and waits
/// for its UDP endpoint. The control API announces itself before the UDP
/// receiver starts. A startup failure is returned, never retried.
pub(super) fn wait(child: &mut Child) -> Result<Endpoints> {
    let stderr = child.stderr.take().ok_or("reflector stderr is not piped")?;
    let (tx, rx) = mpsc::channel();
    thread::Builder::new()
        .name("reflector-stderr".into())
        .spawn(move || forward(stderr, tx))?;
    let deadline = Instant::now() + TIMEOUT;
    let mut control = None;
    loop {
        if let Some(status) = child.try_wait()? {
            return Err(format!("reflector exited during startup: {status}; see stderr").into());
        }
        match rx.recv_timeout(Duration::from_millis(10)) {
            Ok(Announcement::Control(address)) => control = Some(address),
            Ok(Announcement::Udp(address)) if address.port() != 0 => {
                return Ok(Endpoints {
                    udp: address,
                    control,
                })
            }
            Ok(Announcement::Udp(_)) => return Err("reflector reported an unassigned port".into()),
            Err(RecvTimeoutError::Timeout) if Instant::now() < deadline => {}
            Err(RecvTimeoutError::Timeout) => return Err("reflector startup timed out".into()),
            Err(RecvTimeoutError::Disconnected) => {
                // EOF can arrive a scheduler turn before the exit status.
                let closed = Instant::now();
                while closed.elapsed() < Duration::from_secs(1) {
                    if let Some(status) = child.try_wait()? {
                        return Err(format!(
                            "reflector exited during startup: {status}; see stderr"
                        )
                        .into());
                    }
                    thread::sleep(Duration::from_millis(5));
                }
                return Err("reflector closed stderr during startup".into());
            }
        }
    }
}

/// Runs until the reflector closes stderr, which it does when it exits.
fn forward(stderr: ChildStderr, announcements: Sender<Announcement>) {
    let mut output = std::io::stderr();
    for line in BufReader::new(stderr).split(b'\n') {
        let Ok(line) = line else { return };
        let _ = output.write_all(&line);
        let _ = output.write_all(b"\n");
        if let Some(announcement) = announcement(&line) {
            // The receiver is gone once startup has been read.
            let _ = announcements.send(announcement);
        }
    }
}

fn announcement(line: &[u8]) -> Option<Announcement> {
    let value: serde_json::Value = serde_json::from_slice(line).ok()?;
    let message = value.get("fields")?.get("message")?.as_str()?;
    if let Some(rest) = message.strip_prefix("STAMP Reflector listening on ") {
        return Some(Announcement::Udp(
            rest.split_whitespace().next()?.parse().ok()?,
        ));
    }
    let rest = message.strip_prefix("control-plane API listening on http://")?;
    Some(Announcement::Control(rest.split('/').next()?.parse().ok()?))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn line(message: &str) -> Vec<u8> {
        serde_json::json!({"level": "INFO", "fields": {"message": message}})
            .to_string()
            .into_bytes()
    }

    #[test]
    fn startup_lines_name_the_assigned_endpoints() {
        let udp = announcement(&line(
            "STAMP Reflector listening on [::1]:40862 (nix mode, real TTL)",
        ));
        assert!(matches!(udp, Some(Announcement::Udp(a)) if a == "[::1]:40862".parse().unwrap()));
        let control = announcement(&line(
            "control-plane API listening on http://127.0.0.1:38001/v1/",
        ));
        assert!(
            matches!(control, Some(Announcement::Control(a)) if a == "127.0.0.1:38001".parse().unwrap())
        );
        // TLS control is not used by the bench, and other lines are ignored.
        for other in [
            line("control-plane API listening on https://127.0.0.1:38001/v1/"),
            line("Stateful reflector mode enabled"),
            b"not json".to_vec(),
        ] {
            assert!(announcement(&other).is_none());
        }
    }
}
