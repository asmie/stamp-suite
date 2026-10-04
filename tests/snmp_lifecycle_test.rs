//! Exercise SNMP ownership through the executable, including failed startup.
#![cfg(all(unix, feature = "snmp"))]
use std::{
    io::{Read, Write},
    net::UdpSocket,
    os::unix::net::UnixListener,
    process::{Child, Command, Stdio},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    thread,
    time::{Duration, Instant},
};

struct ChildGuard(Child);
impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn lifecycle(mode: &str) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("agentx");
    let listener = UnixListener::bind(&path).unwrap();
    listener.set_nonblocking(true).unwrap();
    let sink = UdpSocket::bind("127.0.0.1:0").unwrap();
    let occupied = UdpSocket::bind("127.0.0.1:0").unwrap();
    let mut command = Command::new(env!("CARGO_BIN_EXE_stamp-suite"));
    command
        .args([
            "--remote-addr",
            "127.0.0.1",
            "--remote-port",
            &sink.local_addr().unwrap().port().to_string(),
            "--hwtstamp",
            "off",
            "--count",
            "1",
            "--timeout",
            "1",
            "--send-delay",
            "10",
            "--output-format",
            "json",
            "--snmp",
            "--snmp-socket",
        ])
        .arg(&path)
        .env_remove("STAMP_HMAC_KEY")
        .env("RUST_LOG", "off")
        .env("TOKIO_WORKER_THREADS", "2")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if mode == "startup_failure" {
        command.args([
            "--local-addr",
            "127.0.0.1",
            "--local-port",
            &occupied.local_addr().unwrap().port().to_string(),
        ]);
    }
    if mode == "reflector" {
        // Use a concrete address for either receiver backend.
        command.args([
            "--is-reflector",
            "--local-addr",
            "127.0.0.1",
            "--local-port",
            "0",
        ]);
    }
    let mut child = ChildGuard(command.spawn().unwrap());
    let stopped = Arc::new(AtomicBool::new(false));
    let done = stopped.clone();
    let (ready, waiting) = std::sync::mpsc::channel();
    let reconnect = mode == "reconnect";
    let silent = mode == "initial_handshake";
    let master = thread::spawn(move || {
        let accept = || {
            let until = Instant::now() + Duration::from_secs(5);
            loop {
                if let Ok((stream, _)) = listener.accept() {
                    return stream;
                }
                assert!(Instant::now() < until, "AgentX connect deadline");
                thread::sleep(Duration::from_millis(5));
            }
        };
        let mut stream = accept();
        stream
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        for expected in [1, 3] {
            let mut header = [0u8; 20];
            stream.read_exact(&mut header).unwrap();
            assert_eq!(header[1], expected);
            let length = u32::from_be_bytes(header[16..20].try_into().unwrap()) as usize;
            assert!(length < 4096);
            stream.read_exact(&mut vec![0; length]).unwrap();
            if silent {
                break;
            }
            header[1] = 18;
            header[4..8].copy_from_slice(&42u32.to_be_bytes());
            header[16..20].copy_from_slice(&8u32.to_be_bytes());
            stream.write_all(&header).unwrap();
            stream.write_all(&[0; 8]).unwrap();
        }
        if reconnect {
            drop(stream);
            stream = accept();
            // Hold a reconnect handshake open without sending a response.
        }
        ready.send(()).unwrap();
        while !done.load(Ordering::Relaxed) {
            thread::sleep(Duration::from_millis(5));
        }
        drop(stream);
    });
    waiting.recv_timeout(Duration::from_secs(6)).unwrap();
    if matches!(mode, "reflector" | "initial_handshake") {
        let status = Command::new("kill")
            .args(["-TERM", &child.0.id().to_string()])
            .status()
            .unwrap();
        assert!(status.success());
    }
    let deadline = Instant::now() + Duration::from_secs(4);
    let result = loop {
        if let Some(status) = child.0.try_wait().unwrap() {
            break Some(status);
        }
        if Instant::now() >= deadline {
            break None;
        }
        thread::sleep(Duration::from_millis(10));
    };
    // Stop the peer even on failure before reporting the assertion.
    stopped.store(true, Ordering::Relaxed);
    master.join().unwrap();
    let status = result.expect("CLI did not terminate with SNMP active");
    let mut stderr = String::new();
    child
        .0
        .stderr
        .take()
        .unwrap()
        .read_to_string(&mut stderr)
        .unwrap();
    if mode == "startup_failure" {
        assert!(!status.success());
    } else {
        assert!(status.success(), "{mode}: {status}: {stderr}");
    }
}

#[test]
fn finite_sender_exits_with_snmp() {
    lifecycle("sender");
}
#[test]
fn failed_sender_startup_cancels_snmp() {
    lifecycle("startup_failure");
}
#[test]
fn signal_cancels_initial_snmp_handshake() {
    lifecycle("initial_handshake");
}
#[test]
fn completion_cancels_reconnect_handshake() {
    lifecycle("reconnect");
}
#[cfg(any(feature = "ttl-nix", not(feature = "ttl-pnet")))]
#[test]
fn reflector_signal_cancels_snmp() {
    lifecycle("reflector");
}
