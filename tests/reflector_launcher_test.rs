//! Deterministic port-handoff, diagnostic bounds and receiver ownership checks.
#![cfg(all(unix, any(feature = "ttl-nix", not(feature = "ttl-pnet"))))]

#[path = "common/receiver.rs"]
mod receiver_fixture;
#[path = "common/reflector.rs"]
mod reflector;

use clap::Parser;
use reflector::{Reflector, STDERR_LIMIT};
use stamp_suite::{configuration::Configuration, receiver};
use std::{
    io::Write,
    net::{SocketAddr, UdpSocket},
    process::{Command, Stdio},
    time::Duration,
};

fn request() -> [u8; 44] {
    let mut bytes = [0; 44];
    bytes[..4].copy_from_slice(&42u32.to_be_bytes());
    bytes[13] = 1;
    bytes
}

fn config(address: SocketAddr) -> Configuration {
    Configuration::parse_from([
        "stamp-suite",
        "--is-reflector",
        "--local-addr",
        &address.ip().to_string(),
        "--local-port",
        &address.port().to_string(),
        "--hwtstamp",
        "off",
    ])
}

fn assert_reaped(error: &str) {
    let pid: i32 = error
        .split("pid=")
        .nth(1)
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .parse()
        .unwrap();
    let mut status = 0;
    // SAFETY: waitpid writes only to our live integer. This is the child PID
    // just reported by the launcher; no PID is signalled or unrelated child reaped.
    assert_eq!(
        unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) },
        -1
    );
    assert_eq!(
        std::io::Error::last_os_error().raw_os_error(),
        Some(libc::ECHILD)
    );
}

#[test]
fn released_reservation_can_be_taken_but_port_zero_startup_is_unaffected() {
    for ip in ["127.0.0.1", "::1"] {
        let reserve = UdpSocket::bind((ip, 0)).unwrap();
        let released = reserve.local_addr().unwrap();
        drop(reserve);
        // Hold the exact port during the former reserve/drop/spawn gap.
        // This is deterministic contention, not reliance on random reuse.
        let competitor = UdpSocket::bind(released).unwrap();
        let mut legacy = Command::new(env!("CARGO_BIN_EXE_stamp-suite"));
        legacy
            .args([
                "--is-reflector",
                "--local-addr",
                ip,
                "--local-port",
                &released.port().to_string(),
                "--hwtstamp",
                "off",
            ])
            .stdout(Stdio::null());
        let error = Reflector::spawn(legacy)
            .err()
            .expect("claimed port must fail");
        assert!(error.contains("Cannot bind to address"), "{error}");
        assert!(error.contains("status=exit status: 1"), "{error}");
        assert_reaped(&error);

        let mut command = Reflector::command(ip);
        command.args(["--hwtstamp", "off", "--stateful-reflector"]);
        let child = Reflector::spawn(command).unwrap();
        assert_ne!(
            child.address.port(),
            competitor.local_addr().unwrap().port()
        );
        let socket = UdpSocket::bind((ip, 0)).unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        socket.send_to(&request(), child.address).unwrap();
        let mut response = [0; 256];
        socket.recv_from(&mut response).unwrap();
        assert_eq!(&response[..4], &0u32.to_be_bytes());
        assert_eq!(&response[24..28], &42u32.to_be_bytes());
    }
}

#[test]
fn retained_socket_excludes_other_binders_and_is_released_on_teardown() {
    for ip in ["127.0.0.1", "::1"] {
        let server =
            receiver_fixture::Receiver::start(SocketAddr::new(ip.parse().unwrap(), 0), config);
        let address = server.address;
        assert!(UdpSocket::bind(address).is_err());
        let socket = UdpSocket::bind((ip, 0)).unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        socket.send_to(&request(), address).unwrap();
        let mut response = [0; 256];
        socket.recv_from(&mut response).unwrap();
        server.assert_running();
        assert_eq!(&response[..4], &42u32.to_be_bytes());
        drop(server);
        UdpSocket::bind(address).expect("receiver teardown must release its port");
    }
}

#[tokio::test]
async fn owned_receiver_rejects_mismatched_or_connected_sockets() {
    for connected in [false, true] {
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let mut address = socket.local_addr().unwrap();
        let peer = UdpSocket::bind("127.0.0.1:0").unwrap();
        if connected {
            socket.connect(peer.local_addr().unwrap()).unwrap();
        } else {
            address.set_ip("0.0.0.0".parse().unwrap());
        }
        let conf = config(address);
        let shared = receiver::create_shared_state(&conf).unwrap();
        let error = receiver::run_receiver_with_socket(&conf, &shared, socket)
            .await
            .unwrap_err();
        assert!(
            error.to_string().contains("unconnected and match"),
            "{error}"
        );
    }
}

// The same test executable supplies controlled child behavior without shell,
// Python or a grandchild that could inherit a pipe and survive parent teardown.
#[test]
fn launcher_fixture() {
    let Ok(mode) = std::env::var("STAMP_LAUNCHER_FIXTURE") else {
        return;
    };
    match mode.as_str() {
        "exit" => {
            eprintln!("specific startup failure");
            std::process::exit(23);
        }
        "flood" => {
            let mut stderr = std::io::stderr().lock();
            stderr.write_all(&vec![b'x'; STDERR_LIMIT * 3]).unwrap();
            writeln!(stderr, "\nspecific diagnostic tail").unwrap();
            stderr.flush().unwrap();
        }
        "hang" => {}
        _ => panic!("unknown launcher fixture"),
    }
    std::thread::sleep(Duration::from_secs(30));
}

fn fixture(mode: &str) -> Command {
    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .args([
            "--exact",
            "launcher_fixture",
            "--nocapture",
            "--test-threads=1",
        ])
        .env("STAMP_LAUNCHER_FIXTURE", mode)
        .stdout(Stdio::null());
    command
}

#[test]
fn startup_exit_retains_status_and_stderr_and_reaps_child() {
    let error = Reflector::spawn(fixture("exit"))
        .err()
        .expect("fixture must fail");
    assert!(error.contains("specific startup failure"), "{error}");
    assert!(error.contains("status=exit status: 23"), "{error}");
    assert_reaped(&error);
}

#[test]
fn timeout_drains_bounded_stderr_and_reaps_child() {
    for mode in ["flood", "hang"] {
        let error = Reflector::spawn_with_timeout(fixture(mode), Duration::from_secs(1))
            .err()
            .expect("fixture must time out");
        assert!(error.contains("startup timed out"));
        let tail = error.split("stderr tail:\n").nth(1).unwrap();
        assert!(tail.len() <= STDERR_LIMIT);
        if mode == "flood" {
            assert!(tail.contains("specific diagnostic tail"));
        }
        assert_reaped(&error);
    }
}

#[test]
fn spawn_error_is_actionable() {
    let error = Reflector::spawn(Command::new("/nonexistent/stamp-suite-launcher-test"))
        .err()
        .expect("spawn must fail");
    assert!(error.contains("cannot spawn reflector"), "{error}");
}
