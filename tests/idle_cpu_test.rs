//! Exercise the real nix receive loop: after a packet, an idle socket must
//! return to sleep and still receive the next packet. Linux /proc accounting
//! measures only the child, so parallel test workers do not inflate its CPU.
#![cfg(all(
    target_os = "linux",
    any(feature = "ttl-nix", not(feature = "ttl-pnet"))
))]

use std::net::UdpSocket;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

struct Reflector(Child);

impl Drop for Reflector {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn cpu_ticks(child: &Child) -> u64 {
    let stat = std::fs::read_to_string(format!("/proc/{}/stat", child.id())).unwrap();
    // The parenthesized command name can contain spaces; fields after it
    // begin at field 3 (state). utime and stime are fields 14 and 15.
    let fields: Vec<_> = stat
        .rsplit_once(')')
        .unwrap()
        .1
        .split_whitespace()
        .collect();
    fields[11].parse::<u64>().unwrap() + fields[12].parse::<u64>().unwrap()
}

fn reflector_sleeps_after_traffic(ip: &str, mode: &str) {
    let reserve = UdpSocket::bind((ip, 0)).unwrap();
    let destination = reserve.local_addr().unwrap();
    drop(reserve);
    let mut child = Reflector(
        Command::new(env!("CARGO_BIN_EXE_stamp-suite"))
            .args([
                "--is-reflector",
                "--local-addr",
                ip,
                "--local-port",
                &destination.port().to_string(),
                "--hwtstamp",
                mode,
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    let socket = UdpSocket::bind((ip, 0)).unwrap();
    socket
        .set_read_timeout(Some(Duration::from_millis(50)))
        .unwrap();
    let mut packet = [0u8; 44];
    packet[13] = 1; // Nonzero Error Estimate multiplier.
    let mut response = [0u8; 256];
    let startup = Instant::now();
    loop {
        assert!(
            child.0.try_wait().unwrap().is_none(),
            "reflector exited during startup"
        );
        socket.send_to(&packet, destination).unwrap();
        if socket.recv_from(&mut response).is_ok() {
            break;
        }
        assert!(
            startup.elapsed() < Duration::from_secs(5),
            "reflector did not start"
        );
    }

    // Let startup/queued replies settle, then observe an otherwise idle child.
    std::thread::sleep(Duration::from_millis(100));
    let before = cpu_ticks(&child.0);
    let window = Duration::from_millis(600);
    std::thread::sleep(window);
    let used = cpu_ticks(&child.0) - before;
    // SAFETY: sysconf with _SC_CLK_TCK has no pointer or memory arguments.
    let ticks_per_second = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
    assert!(ticks_per_second > 0);
    let cpu_seconds = used as f64 / ticks_per_second as f64;
    assert!(
        cpu_seconds < window.as_secs_f64() / 4.0,
        "idle reflector used {cpu_seconds:.3}s CPU in {window:?} ({ip}, {mode})"
    );

    // Clearing readiness must not lose a later notification.
    packet[..4].copy_from_slice(&42u32.to_be_bytes());
    socket.send_to(&packet, destination).unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    loop {
        let (len, _) = socket.recv_from(&mut response).unwrap();
        assert!(len >= 44);
        if response[24..28] == 42u32.to_be_bytes() {
            break;
        }
    }
}

#[test]
fn reflector_idle_after_traffic_ipv4() {
    reflector_sleeps_after_traffic("127.0.0.1", "off");
}

#[test]
fn reflector_idle_after_traffic_ipv6() {
    reflector_sleeps_after_traffic("::1", "off");
}

#[cfg(feature = "hwtstamp")]
#[test]
fn reflector_idle_after_traffic_with_kernel_timestamps() {
    reflector_sleeps_after_traffic("127.0.0.1", "auto");
    reflector_sleeps_after_traffic("::1", "auto");
}
