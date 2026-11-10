//! Actual pnet endpoint binding, capture filtering, metadata and reply ports.
#![cfg(all(target_os = "linux", feature = "ttl-pnet", not(feature = "ttl-nix")))]
#[path = "common/reflector.rs"]
mod reflector;
#[path = "common/wire_hmac.rs"]
mod wire_hmac;

use std::{
    net::{IpAddr, SocketAddr, UdpSocket},
    time::Duration,
};
const KEY: [u8; 16] = [0xab; 16];
static NAMESPACE: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn namespace() -> std::sync::MutexGuard<'static, ()> {
    let guard = NAMESPACE.lock().unwrap();
    assert_eq!(
        std::env::var("STAMP_PNET_ENDPOINT_TESTS").as_deref(),
        Ok("1")
    );
    assert_ne!(
        std::fs::read_link("/proc/self/ns/net")
            .unwrap()
            .to_str()
            .unwrap(),
        std::env::var("STAMP_PARENT_NETNS").expect("record the parent namespace before unshare"),
        "requires a private network namespace"
    );
    assert!(std::process::Command::new("ip")
        .args(["link", "set", "lo", "up"])
        .status()
        .unwrap()
        .success());
    guard
}

fn command(bind: &str, port: u16, mode: u8) -> std::process::Command {
    let mut command = std::process::Command::new(env!("CARGO_BIN_EXE_stamp-suite"));
    command.stdout(std::process::Stdio::null());
    command.args([
        "--is-reflector",
        "--local-addr",
        bind,
        "--local-port",
        &port.to_string(),
        "--interface",
        "lo",
        "--log-format",
        "json",
        "--hwtstamp",
        "off",
    ]);
    if mode != 0 {
        command.args([
            "--hmac-key",
            "abababababababababababababababab",
            "--verify-tlv-hmac",
        ]);
    }
    if mode == 2 {
        command.args(["--auth-mode", "A"]);
    }
    command
}

fn checksum(bytes: &[u8]) -> u16 {
    let mut sum = bytes
        .chunks(2)
        .map(|p| (u32::from(p[0]) << 8) + u32::from(*p.get(1).unwrap_or(&0)))
        .sum::<u32>();
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    let result = !(sum as u16);
    if result == 0 {
        u16::MAX
    } else {
        result
    }
}

fn inject(source: SocketAddr, target: SocketAddr, payload: &[u8]) {
    let len = (payload.len() + 8) as u16;
    let mut udp = [
        source.port().to_be_bytes(),
        target.port().to_be_bytes(),
        len.to_be_bytes(),
        [0; 2],
    ]
    .concat();
    udp.extend_from_slice(payload);
    let (socket, mut ip, mut pseudo) = match (source.ip(), target.ip()) {
        (IpAddr::V4(src), IpAddr::V4(dst)) => {
            let mut ip = vec![0; 20];
            ip[0] = 0x45;
            ip[2..4].copy_from_slice(&(len + 20).to_be_bytes());
            ip[8] = 255;
            ip[9] = 17;
            ip[12..16].copy_from_slice(&src.octets());
            ip[16..20].copy_from_slice(&dst.octets());
            let pseudo = [
                src.octets().as_slice(),
                dst.octets().as_slice(),
                &[0, 17],
                &len.to_be_bytes(),
            ]
            .concat();
            (
                socket2::Socket::new(
                    socket2::Domain::IPV4,
                    socket2::Type::from(libc::SOCK_RAW),
                    Some(socket2::Protocol::from(libc::IPPROTO_RAW)),
                )
                .unwrap(),
                ip,
                pseudo,
            )
        }
        (IpAddr::V6(src), IpAddr::V6(dst)) => {
            let mut ip = vec![0; 40];
            ip[0] = 0x60;
            ip[4..6].copy_from_slice(&len.to_be_bytes());
            ip[6] = 17;
            ip[7] = 255;
            ip[8..24].copy_from_slice(&src.octets());
            ip[24..40].copy_from_slice(&dst.octets());
            let pseudo = [
                src.octets().as_slice(),
                dst.octets().as_slice(),
                &u32::from(len).to_be_bytes(),
                &[0, 0, 0, 17],
            ]
            .concat();
            (
                socket2::Socket::new(
                    socket2::Domain::IPV6,
                    socket2::Type::from(libc::SOCK_RAW),
                    Some(socket2::Protocol::from(libc::IPPROTO_RAW)),
                )
                .unwrap(),
                ip,
                pseudo,
            )
        }
        _ => panic!("mixed source/destination families"),
    };
    pseudo.extend_from_slice(&udp);
    udp[6..8].copy_from_slice(&checksum(&pseudo).to_be_bytes());
    ip.extend_from_slice(&udp);
    let mut raw_target = target;
    raw_target.set_port(0); // Linux raw IPv6 sendto takes no transport port.
    assert_eq!(socket.send_to(&ip, &raw_target.into()).unwrap(), ip.len());
}

fn finish(mut child: reflector::Reflector) {
    // SAFETY: child.id() identifies the live test-owned child process.
    assert_eq!(
        unsafe { libc::kill(child.child.id() as _, libc::SIGTERM) },
        0
    );
    let deadline = std::time::Instant::now() + Duration::from_secs(4);
    loop {
        if let Some(status) = child.child.try_wait().unwrap() {
            assert!(
                status.success(),
                "graceful pnet shutdown: {status}: {}",
                child.diagnostics()
            );
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "pnet shutdown timed out: {}",
            child.diagnostics()
        );
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn exchange(child: &reflector::Reflector, ip: &str, mode: u8, sequence: u32) {
    let peer = UdpSocket::bind((ip, 0)).unwrap();
    peer.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    let target = SocketAddr::new(ip.parse().unwrap(), child.address.port());
    let base = if mode == 2 { 112 } else { 44 };
    let mut packet = vec![0; base];
    packet[..4].copy_from_slice(&sequence.to_be_bytes());
    packet[if mode == 2 { 25 } else { 13 }] = 1;
    // Location ports prove that received local endpoint metadata uses the
    // selected port, as well as the capture filter and send socket.
    packet.extend_from_slice(&[0x80, 2, 0, 4, 0, 0, 0, 0]);
    if mode != 0 {
        let covered = [&packet[..4], &packet[base..]].concat();
        packet.extend_from_slice(&[0x80, 8, 0, 16]);
        packet.extend_from_slice(&wire_hmac::digest(&KEY, &covered));
    }
    if mode == 2 {
        let digest = wire_hmac::digest(&KEY, &packet[..96]);
        packet[96..112].copy_from_slice(&digest);
    }
    inject(peer.local_addr().unwrap(), target, &packet);
    let mut bytes = [0; 512];
    let (len, source) = peer.recv_from(&mut bytes).unwrap();
    let reply = &bytes[..len];
    assert_eq!(
        source, target,
        "reply source must match the advertised port in each family"
    );
    assert_eq!(len, packet.len());
    let offset = if mode == 2 { 48 } else { 24 };
    assert_eq!(&reply[offset..offset + 4], &sequence.to_be_bytes());
    let mut expected = vec![0, 2, 0, 4];
    expected.extend_from_slice(&target.port().to_be_bytes());
    expected.extend_from_slice(&peer.local_addr().unwrap().port().to_be_bytes());
    if mode != 0 {
        let covered = [&reply[..4], &expected].concat();
        expected.extend_from_slice(&[0, 8, 0, 16]);
        expected.extend_from_slice(&wire_hmac::digest(&KEY, &covered));
    }
    assert_eq!(&reply[base..], expected);
    if mode == 2 {
        assert_eq!(&reply[96..112], &wire_hmac::digest(&KEY, &reply[..96]));
    }
}

fn assigned_ports(binds: &[&str]) {
    let _namespace = namespace();
    for bind in binds {
        for mode in 0..3 {
            for port in [0, 19862] {
                let child = reflector::Reflector::spawn(command(bind, port, mode)).unwrap();
                assert_eq!(child.address.ip(), bind.parse::<IpAddr>().unwrap());
                assert_ne!(child.address.port(), 0);
                if port != 0 {
                    assert_eq!(child.address.port(), port);
                }
                exchange(&child, "127.0.0.1", mode, 1);
                exchange(&child, "::1", mode, 2);
                // Retain contention throughout a second startup attempt. The
                // configured family must fail before capture discovery.
                let error =
                    match reflector::Reflector::spawn(command(bind, child.address.port(), mode)) {
                        Ok(_) => panic!("occupied endpoint accepted"),
                        Err(e) => e,
                    };
                assert!(error.contains("Cannot bind to address"), "{error}");
                assert!(!error.contains("listening on"), "false readiness: {error}");
                finish(child);
            }
            // A live owner of the other family must not suppress startup in
            // the explicitly configured family. Retain it throughout.
            let other = if bind.contains(':') {
                socket2::Socket::new(
                    socket2::Domain::IPV4,
                    socket2::Type::DGRAM,
                    Some(socket2::Protocol::UDP),
                )
                .unwrap()
            } else {
                let socket = socket2::Socket::new(
                    socket2::Domain::IPV6,
                    socket2::Type::DGRAM,
                    Some(socket2::Protocol::UDP),
                )
                .unwrap();
                socket.set_only_v6(true).unwrap();
                socket
            };
            let address: SocketAddr = if bind.contains(':') {
                "0.0.0.0:0"
            } else {
                "[::]:0"
            }
            .parse()
            .unwrap();
            other.bind(&address.into()).unwrap();
            let port = other.local_addr().unwrap().as_socket().unwrap().port();
            let child = reflector::Reflector::spawn(command(bind, port, mode)).unwrap();
            exchange(
                &child,
                if bind.contains(':') {
                    "::1"
                } else {
                    "127.0.0.1"
                },
                mode,
                3,
            );
            finish(child);
        }
    }
}

#[test]
#[ignore = "requires STAMP_PNET_ENDPOINT_TESTS=1 inside unshare -Urn"]
fn pnet_assigned_ipv4_ports_reach_capture_metadata_and_both_reply_families() {
    assigned_ports(&["127.0.0.1", "0.0.0.0"]);
}

#[test]
#[ignore = "requires STAMP_PNET_ENDPOINT_TESTS=1 inside unshare -Urn"]
fn pnet_assigned_ipv6_ports_reach_capture_metadata_and_both_reply_families() {
    assigned_ports(&["::1", "::"]);
}

#[test]
#[ignore = "requires STAMP_PNET_ENDPOINT_TESTS=1 inside unshare -Urn"]
fn pnet_ipv4_works_with_ipv6_disabled_and_ipv6_startup_fails() {
    let _namespace = namespace();
    let path = "/proc/sys/net/ipv6/conf/all/disable_ipv6";
    struct Restore(&'static str, String);
    impl Drop for Restore {
        fn drop(&mut self) {
            std::fs::write(self.0, &self.1).unwrap();
        }
    }
    let _restore = Restore(path, std::fs::read_to_string(path).unwrap());
    std::fs::write(path, "1").unwrap();
    for mode in 0..3 {
        let child = reflector::Reflector::spawn(command("127.0.0.1", 0, mode)).unwrap();
        exchange(&child, "127.0.0.1", mode, 1);
        let error = match reflector::Reflector::spawn(command("::1", 0, mode)) {
            Ok(_) => panic!("IPv6 startup accepted without IPv6"),
            Err(e) => e,
        };
        assert!(error.contains("Cannot bind to address"), "{error}");
        assert!(!error.contains("listening on"), "false readiness: {error}");
        finish(child);
    }
}
