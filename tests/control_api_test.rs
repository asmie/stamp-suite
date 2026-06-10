//! End-to-end smoke test for the control-plane REST API: a real bound
//! server driven over raw HTTP/1.1 (no client dependency).
#![cfg(feature = "control")]

use std::io::{Read, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use stamp_suite::control::{init, ControlState};
use stamp_suite::receiver::{RateLimiter, ReflectorCounters, RuntimeCaps};
use stamp_suite::session::SessionManager;

fn test_state() -> ControlState {
    ControlState {
        counters: Arc::new(ReflectorCounters::new()),
        session_manager: Arc::new(SessionManager::new(None, None)),
        start_time: std::time::Instant::now(),
        rate_limiter: Arc::new(RateLimiter::with_burst(0, 0)),
        hmac_keys: Arc::new(std::sync::RwLock::new(None)),
        caps: Arc::new(RuntimeCaps::from_defaults()),
        shutdown_requested: Arc::new(AtomicBool::new(false)),
        token: None,
    }
}

/// One raw HTTP/1.1 request against the live server; returns the full
/// response text.
fn http(addr: std::net::SocketAddr, request_head: &str, body: &str) -> String {
    let mut stream = std::net::TcpStream::connect(addr).expect("connect");
    let msg = format!(
        "{request_head}\r\nHost: {addr}\r\nConnection: close\r\n\
         Content-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(msg.as_bytes()).expect("write");
    let mut response = String::new();
    stream.read_to_string(&mut response).expect("read");
    response
}

#[tokio::test(flavor = "multi_thread")]
async fn control_api_end_to_end() {
    let state = test_state();
    let shutdown_flag = Arc::clone(&state.shutdown_requested);

    let server = init("127.0.0.1:0".parse().unwrap(), state)
        .await
        .expect("bind on ephemeral port");
    let addr = server.local_addr();

    // Status over the wire.
    let addr2 = addr;
    let res = tokio::task::spawn_blocking(move || http(addr2, "GET /v1/status HTTP/1.1", ""))
        .await
        .unwrap();
    assert!(res.starts_with("HTTP/1.1 200"), "status line: {res}");
    assert!(res.contains("\"version\""), "body: {res}");
    assert!(res.contains("\"counters\""), "body: {res}");

    // Shutdown request flips the shared flag.
    let addr2 = addr;
    let res = tokio::task::spawn_blocking(move || http(addr2, "POST /v1/shutdown HTTP/1.1", ""))
        .await
        .unwrap();
    assert!(res.starts_with("HTTP/1.1 202"), "status line: {res}");
    assert!(shutdown_flag.load(Ordering::Relaxed));

    server.shutdown();
}
