//! Closed-loop HTTP inventory reads concurrent with the UDP load.
use super::latency::Samples;
use clap::ValueEnum;
use serde::{Deserialize, Serialize};
use std::{
    collections::HashSet,
    error::Error,
    io::{Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    process::Command,
    thread,
    time::{Duration, Instant},
};

pub(super) type Result<T> = std::result::Result<T, Box<dyn Error + Send + Sync>>;
const MAX_RESPONSE: usize = 32 * 1024 * 1024;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(2);
const PAUSE: Duration = Duration::from_millis(10);

#[derive(Clone, Copy, Debug, Serialize, ValueEnum, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub(super) enum Mode {
    Idle,
    Full,
    Page100,
    Page500,
}

impl Mode {
    fn limit(self, capacity: usize) -> usize {
        match self {
            Self::Page100 => 100,
            Self::Page500 => 500,
            _ => capacity,
        }
    }
}

pub(super) struct Profile {
    mode: Mode,
    capacity: usize,
    address: SocketAddr,
    reservation: Option<TcpListener>,
    token: String,
    token_file: tempfile::NamedTempFile,
}

impl Profile {
    pub(super) fn new(mode: Mode, sessions: u16) -> Result<Self> {
        let reservation = TcpListener::bind("127.0.0.1:0")?;
        let address = reservation.local_addr()?;
        let mut random = [0; 32];
        getrandom::fill(&mut random)?;
        let token = hex::encode(random);
        let mut token_file = tempfile::NamedTempFile::new()?;
        token_file.write_all(token.as_bytes())?;
        token_file.flush()?;
        Ok(Self {
            mode,
            capacity: usize::from(sessions) + 2,
            address,
            reservation: Some(reservation),
            token,
            token_file,
        })
    }

    pub(super) fn configure(&self, command: &mut Command) {
        command.args(["--control", "--control-addr", &self.address.to_string()]);
        command
            .arg("--control-token-file")
            .arg(self.token_file.path());
    }

    pub(super) fn release_port(&mut self) {
        self.reservation.take();
    }

    pub(super) fn ready(&self) -> Result<()> {
        let body = self.get("/v1/status")?;
        let status: serde_json::Value = serde_json::from_slice(&body)?;
        if status["version"] != env!("CARGO_PKG_VERSION") || !status["sessions"].is_u64() {
            return Err("invalid inventory control readiness response".into());
        }
        Ok(())
    }

    // A deliberately narrow client for this application's fixed-length JSON API.
    // No redirects, TLS, chunked responses, keepalive, or external destinations.
    fn get(&self, path: &str) -> Result<Vec<u8>> {
        let deadline = Instant::now() + REQUEST_TIMEOUT;
        let mut stream = TcpStream::connect_timeout(&self.address, REQUEST_TIMEOUT)?;
        stream.set_write_timeout(Some(deadline.saturating_duration_since(Instant::now())))?;
        write!(stream, "GET {path} HTTP/1.1\r\nHost: {}\r\nAuthorization: Bearer {}\r\nConnection: close\r\n\r\n", self.address, self.token)?;
        let mut response = Vec::new();
        let mut buffer = [0; 8192];
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err("inventory HTTP request exceeded two seconds".into());
            }
            stream.set_read_timeout(Some(remaining))?;
            let count = stream.read(&mut buffer)?;
            if count == 0 {
                break;
            }
            if response.len() + count > MAX_RESPONSE {
                return Err("inventory HTTP response exceeds 32 MiB".into());
            }
            response.extend_from_slice(&buffer[..count]);
        }
        let offset = body_offset(&response)?;
        response.drain(..offset);
        Ok(response)
    }

    pub(super) fn run(&self, deadline: Instant) -> Result<serde_json::Value> {
        let mut walk = Walk::default();
        let mut samples = Samples::default();
        let (mut requests, mut rows, mut bytes, mut completed_walks, mut after_load) =
            (0u64, 0u64, 0u64, 0u64, 0u64);
        let mut max_rows = 0;
        let mut last_finish = None;
        while self.mode != Mode::Idle && Instant::now() < deadline {
            let path = match self.mode {
                Mode::Full => "/v1/sessions".to_string(),
                _ => format!(
                    "/v1/sessions/page?limit={}{}",
                    self.mode.limit(self.capacity),
                    walk.cursor
                        .as_ref()
                        .map(|cursor| format!("&cursor={cursor}"))
                        .unwrap_or_default()
                ),
            };
            let start = Instant::now();
            let body = self.get(&path)?;
            let (count, complete) = walk.accept(self.mode, self.capacity, &body)?;
            let finish = Instant::now();
            samples.record(u64::try_from(finish.duration_since(start).as_nanos())?);
            requests += 1;
            rows += count as u64;
            bytes += body.len() as u64;
            max_rows = max_rows.max(count);
            completed_walks += u64::from(complete);
            after_load += u64::from(finish > deadline);
            last_finish = Some(finish);
            thread::sleep(PAUSE.min(deadline.saturating_duration_since(Instant::now())));
        }
        if self.mode != Mode::Idle && requests == 0 {
            return Err("no inventory requests completed during the workload".into());
        }
        Ok(serde_json::json!({
            "mode": self.mode,
            "control_address": self.address,
            "inter_request_pause_ms": PAUSE.as_millis(),
            "request_timeout_ms": REQUEST_TIMEOUT.as_millis(),
            "response_limit_bytes": MAX_RESPONSE,
            "requests": requests,
            "rows": rows,
            "max_rows_per_response": max_rows,
            "response_body_bytes": bytes,
            "completed_walks": completed_walks,
            "incomplete_walk": walk.cursor.is_some(),
            "requests_completed_after_load": after_load,
            "tail_seconds": last_finish.map(|time| time.saturating_duration_since(deadline).as_secs_f64()).unwrap_or(0.0),
            "request_observed_latency": samples.summary(),
        }))
    }
}

fn body_offset(response: &[u8]) -> Result<usize> {
    let offset = response
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or("missing HTTP headers")?
        + 4;
    if offset > 8192 {
        return Err("inventory HTTP headers exceed 8 KiB".into());
    }
    let head = std::str::from_utf8(&response[..offset])?;
    let mut lines = head.split("\r\n");
    if lines.next() != Some("HTTP/1.1 200 OK") {
        return Err("inventory HTTP status is not 200 OK".into());
    }
    let mut length = None;
    for line in lines.filter(|line| !line.is_empty()) {
        let (name, value) = line.split_once(':').ok_or("invalid HTTP header")?;
        if name.eq_ignore_ascii_case("transfer-encoding") {
            return Err("inventory HTTP transfer encoding is unsupported".into());
        }
        if name.eq_ignore_ascii_case("content-length") {
            if length.is_some() {
                return Err("duplicate HTTP content length".into());
            }
            length = Some(value.trim().parse::<usize>()?);
        }
    }
    if length != Some(response.len() - offset) {
        return Err("inventory HTTP body length mismatch".into());
    }
    Ok(offset)
}

#[derive(Deserialize, Hash, PartialEq, Eq)]
struct Identity {
    client: SocketAddr,
    local: SocketAddr,
    ssid: u16,
    sender_micro_session_id: Option<u16>,
}

#[derive(Deserialize)]
struct Page {
    items: Vec<Identity>,
    // Required even for the last page; null marks completion.
    next_cursor: serde_json::Value,
}

#[derive(Default)]
struct Walk {
    cursor: Option<String>,
    seen: HashSet<Identity>,
}

impl Walk {
    fn accept(&mut self, mode: Mode, capacity: usize, body: &[u8]) -> Result<(usize, bool)> {
        let (items, next) = if mode == Mode::Full {
            (serde_json::from_slice::<Vec<Identity>>(body)?, None)
        } else {
            let page: Page = serde_json::from_slice(body)?;
            let next = if page.next_cursor.is_null() {
                None
            } else {
                Some(
                    page.next_cursor
                        .as_str()
                        .ok_or("inventory cursor is not a string")?
                        .to_string(),
                )
            };
            (page.items, next)
        };
        if items.len() > mode.limit(capacity) || self.seen.len() + items.len() > capacity {
            return Err("inventory rows exceed page or session capacity".into());
        }
        if let Some(next) = &next {
            let after = cursor_after(next)?;
            if items.is_empty() {
                return Err("non-final inventory page is empty".into());
            }
            if let Some(previous) = &self.cursor {
                if next[..53] != previous[..53] || after <= cursor_after(previous)? {
                    return Err("inventory cursor changed boundary or failed to advance".into());
                }
            }
        }
        let count = items.len();
        for item in items {
            if !self.seen.insert(item) {
                return Err("duplicate identity in inventory walk".into());
            }
        }
        let complete = next.is_none();
        self.cursor = next;
        if complete {
            self.seen.clear();
        }
        Ok((count, complete))
    }
}

fn cursor_after(cursor: &str) -> Result<u64> {
    let bytes = cursor.as_bytes();
    if bytes.len() != 69
        || !cursor.starts_with("v1-")
        || bytes[35] != b'-'
        || bytes[52] != b'-'
        || !bytes[3..35]
            .iter()
            .chain(&bytes[36..52])
            .chain(&bytes[53..])
            .all(u8::is_ascii_hexdigit)
    {
        return Err("invalid inventory cursor encoding".into());
    }
    let upper = u64::from_str_radix(&cursor[36..52], 16)?;
    let after = u64::from_str_radix(&cursor[53..], 16)?;
    if after == 0 || after >= upper {
        return Err("invalid inventory cursor range".into());
    }
    Ok(after)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity(ssid: u16) -> serde_json::Value {
        serde_json::json!({"client":"[::1]:4000","local":"[::1]:862","ssid":ssid,
            "sender_micro_session_id":null,"session_id":17,"packets_received":2})
    }
    fn cursor(after: u64) -> String {
        format!("v1-{}-{:016x}-{after:016x}", "ab".repeat(16), 1000)
    }
    fn page(ids: &[u16], next: Option<String>) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({"items":ids.iter().map(|id|identity(*id)).collect::<Vec<_>>(),"next_cursor":next})).unwrap()
    }

    #[test]
    fn http_requires_success_and_exact_unambiguous_length() {
        let valid = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n[]";
        assert_eq!(&valid[body_offset(valid).unwrap()..], b"[]");
        for bad in [
            "HTTP/1.1 401 Unauthorized\r\nContent-Length: 2\r\n\r\n[]",
            "HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\n[]",
            "HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\n[]",
            "HTTP/1.1 200 OK\r\nContent-Length: 2\r\ncontent-length: 2\r\n\r\n[]",
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Length: 2\r\n\r\n[]",
            "HTTP/1.1 200 OK\r\n\r\n[]",
            "HTTP/1.1 200 OK",
        ] {
            assert!(body_offset(bad.as_bytes()).is_err(), "{bad}");
        }
        let oversized = format!(
            "HTTP/1.1 200 OK\r\nX: {}\r\nContent-Length: 2\r\n\r\n[]",
            "a".repeat(8192)
        );
        assert!(body_offset(oversized.as_bytes()).is_err());
    }

    #[test]
    fn bounded_walks_advance_and_reset_without_accumulating_previous_walks() {
        let mut walk = Walk::default();
        assert_eq!(
            walk.accept(Mode::Page100, 4, &page(&[1, 2], Some(cursor(2))))
                .unwrap(),
            (2, false)
        );
        assert_eq!(
            walk.accept(Mode::Page100, 4, &page(&[3], Some(cursor(3))))
                .unwrap(),
            (1, false)
        );
        assert_eq!(
            walk.accept(Mode::Page100, 4, &page(&[], None)).unwrap(),
            (0, true)
        );
        assert!(walk.cursor.is_none() && walk.seen.is_empty());
        assert_eq!(
            walk.accept(Mode::Page100, 4, &page(&[1], None)).unwrap(),
            (1, true)
        );
        let full = serde_json::to_vec(&vec![identity(1), identity(2)]).unwrap();
        for _ in 0..2 {
            assert_eq!(walk.accept(Mode::Full, 4, &full).unwrap(), (2, true));
        }
    }

    #[test]
    fn malformed_oversized_duplicate_and_nonadvancing_pages_fail() {
        for body in [
            page(&(1..=101).collect::<Vec<_>>(), None),
            page(&[1, 1], None),
            page(&[], Some(cursor(1))),
            page(&[1], Some("\r\nInjected: true".into())),
            br#"{"items":[],"next_cursor":42}"#.to_vec(),
            br#"{"items":[]}"#.to_vec(),
            br#"{"items":[{}],"next_cursor":null}"#.to_vec(),
        ] {
            assert!(Walk::default().accept(Mode::Page100, 500, &body).is_err());
        }
        assert!(Walk::default()
            .accept(
                Mode::Full,
                1,
                &serde_json::to_vec(&vec![identity(1), identity(2)]).unwrap()
            )
            .is_err());
        for next in [cursor(1), cursor(2), cursor(3).replace("abab", "cdcd")] {
            let mut walk = Walk::default();
            walk.accept(Mode::Page100, 4, &page(&[1], Some(cursor(2))))
                .unwrap();
            assert!(walk
                .accept(Mode::Page100, 4, &page(&[2], Some(next)))
                .is_err());
        }
        let mut walk = Walk::default();
        walk.accept(Mode::Page100, 4, &page(&[1], Some(cursor(2))))
            .unwrap();
        assert!(walk.accept(Mode::Page100, 4, &page(&[1], None)).is_err());
        for bad in [cursor(0), cursor(1000), "é".repeat(35)] {
            assert!(cursor_after(&bad).is_err());
        }
    }
}
