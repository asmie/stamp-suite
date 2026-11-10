//! Deterministic port-handoff, diagnostic bounds and receiver ownership checks.
#![cfg(all(unix, any(feature = "ttl-nix", not(feature = "ttl-pnet"))))]

#[path = "common/receiver.rs"]
mod receiver_fixture;
#[path = "common/reflector.rs"]
mod reflector;

use clap::Parser;
use nix::libc;
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

/// Observe the kernel socket identity, rather than a reusable descriptor number
/// or endpoint. This does not retain a duplicate socket or extend its lifetime.
#[cfg(target_os = "linux")]
struct SocketOwnership(std::path::PathBuf);

#[cfg(target_os = "linux")]
impl SocketOwnership {
    fn observe(socket: &UdpSocket) -> Self {
        use std::os::fd::AsRawFd;
        let target = std::fs::read_link(format!("/proc/self/fd/{}", socket.as_raw_fd()))
            .expect("read original socket identity");
        assert!(target.to_string_lossy().starts_with("socket:["));
        Self(target)
    }

    fn is_open_in_this_process(&self) -> bool {
        for entry in std::fs::read_dir("/proc/self/fd").expect("list own descriptors") {
            let path = entry.expect("read descriptor entry").path();
            match std::fs::read_link(path) {
                Ok(target) if target == self.0 => return true,
                Ok(_) => (),
                // Other test threads may close unrelated descriptors while
                // the directory is enumerated. All other errors are failures.
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => (),
                Err(error) => panic!("read descriptor identity: {error}"),
            }
        }
        false
    }
}

#[cfg(target_os = "linux")]
#[test]
fn teardown_observer_distinguishes_retained_socket_from_another_endpoint_owner() {
    use socket2::{Domain, Protocol, Socket, Type};
    for ip in ["127.0.0.1", "::1"] {
        let address = SocketAddr::new(ip.parse().unwrap(), 0);
        let socket = Socket::new(
            Domain::for_address(address),
            Type::DGRAM,
            Some(Protocol::UDP),
        )
        .unwrap();
        socket.set_reuse_address(true).unwrap();
        socket.bind(&address.into()).unwrap();
        let socket: UdpSocket = socket.into();
        let address = socket.local_addr().unwrap();
        let ownership = SocketOwnership::observe(&socket);
        let retained = socket.try_clone().unwrap();
        let server = receiver_fixture::Receiver::start_with_socket(socket, config);

        // Establish a different owner before teardown, leaving no unreserved
        // bind window. Reuse is enabled only in this controlled test fixture.
        let competitor = Socket::new(
            Domain::for_address(address),
            Type::DGRAM,
            Some(Protocol::UDP),
        )
        .unwrap();
        competitor.set_reuse_address(true).unwrap();
        competitor.bind(&address.into()).unwrap();
        server.stop().expect("receiver must stop cleanly");
        assert!(
            ownership.is_open_in_this_process(),
            "a retained duplicate must be detected"
        );
        drop(retained);
        assert!(
            !ownership.is_open_in_this_process(),
            "the original socket must now be closed"
        );

        assert_eq!(
            UdpSocket::bind(address).unwrap_err().kind(),
            std::io::ErrorKind::AddrInUse,
            "endpoint occupancy must not be mistaken for original socket ownership"
        );
        drop(competitor);
    }
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
fn occupied_port_rejects_fixed_bind_but_port_zero_startup_is_unaffected() {
    for ip in ["127.0.0.1", "::1"] {
        // Retain the occupied endpoint throughout the control. Selecting and
        // rebinding a released ephemeral port would race unrelated allocators
        // before the fixed-port reflector even had a chance to start.
        let competitor = UdpSocket::bind((ip, 0)).unwrap();
        let occupied = competitor.local_addr().unwrap();
        let mut legacy = Command::new(env!("CARGO_BIN_EXE_stamp-suite"));
        legacy
            .args([
                "--is-reflector",
                "--local-addr",
                ip,
                "--local-port",
                &occupied.port().to_string(),
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
fn owned_receiver_finishes_metadata_setup_without_readiness_traffic() {
    use std::{os::fd::AsRawFd, sync::atomic::Ordering};

    for ip in ["127.0.0.1", "::1"] {
        let socket = UdpSocket::bind((ip, 0)).unwrap();
        let observer = socket.try_clone().unwrap();
        let server = receiver_fixture::Receiver::start_with_socket(socket, config);
        let (level, option) = if server.address.is_ipv4() {
            (libc::IPPROTO_IP, libc::IP_RECVTTL)
        } else {
            (libc::IPPROTO_IPV6, libc::IPV6_RECVHOPLIMIT)
        };
        let mut enabled: libc::c_int = 0;
        let mut len = std::mem::size_of_val(&enabled) as libc::socklen_t;
        // SAFETY: observer owns an open socket and both output pointers refer
        // to live values with the required lengths.
        let result = unsafe {
            libc::getsockopt(
                observer.as_raw_fd(),
                level,
                option,
                (&mut enabled as *mut libc::c_int).cast(),
                &mut len,
            )
        };
        assert_eq!(result, 0, "{}", std::io::Error::last_os_error());
        assert_eq!(len as usize, std::mem::size_of_val(&enabled));
        assert_ne!(
            enabled, 0,
            "{ip}: TTL capture must be enabled before return"
        );
        assert_eq!(
            server
                .shared
                .counters
                .packets_received
                .load(Ordering::Relaxed),
            0
        );
        assert_eq!(
            server
                .shared
                .counters
                .packets_reflected
                .load(Ordering::Relaxed),
            0
        );
        assert_eq!(server.shared.session_manager.session_count(), 0);
        drop(observer);
        server.stop().expect("receiver must exit cleanly");
    }
}

#[test]
fn retained_socket_excludes_other_binders_and_is_released_on_teardown() {
    for ip in ["127.0.0.1", "::1"] {
        let bound = UdpSocket::bind((ip, 0)).unwrap();
        #[cfg(target_os = "linux")]
        let ownership = SocketOwnership::observe(&bound);
        let server = receiver_fixture::Receiver::start_with_socket(bound, config);
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
        #[cfg(target_os = "linux")]
        assert!(ownership.is_open_in_this_process());
        server.stop().expect("receiver must exit cleanly");
        #[cfg(target_os = "linux")]
        assert!(
            !ownership.is_open_in_this_process(),
            "receiver teardown must close all original socket descriptors"
        );
    }
}

#[test]
fn explicit_receiver_stop_reports_startup_failure() {
    for ip in ["127.0.0.1", "::1"] {
        let socket = UdpSocket::bind((ip, 0)).unwrap();
        let peer = UdpSocket::bind((ip, 0)).unwrap();
        socket.connect(peer.local_addr().unwrap()).unwrap();
        let server = receiver_fixture::Receiver::start_with_socket(socket, config);
        let error = server
            .stop()
            .expect_err("connected receiver socket must fail startup");
        assert!(error.contains("unconnected and match"), "{error}");
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
