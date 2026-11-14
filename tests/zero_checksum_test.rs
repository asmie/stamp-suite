//! Characterize IPv4 zero-checksum ingress; this is not a complete BER admission profile.
#![cfg(all(
    target_os = "linux",
    any(feature = "ttl-nix", not(feature = "ttl-pnet"))
))]

#[path = "common/receiver.rs"]
mod receiver_fixture;
#[path = "common/wire_hmac.rs"]
mod wire_hmac;

use clap::Parser;
use stamp_suite::{configuration::Configuration, session::SessionSummary};
use std::{
    net::{SocketAddr, UdpSocket},
    sync::{atomic::Ordering, Mutex},
    time::{Duration, Instant},
};

const KEY: [u8; 16] = [0xab; 16];
static NAMESPACE: Mutex<()> = Mutex::new(());

fn namespace() -> std::sync::MutexGuard<'static, ()> {
    let guard = NAMESPACE.lock().unwrap();
    assert_eq!(std::env::var("STAMP_ZERO_UDP_TESTS").as_deref(), Ok("1"));
    assert_ne!(
        std::fs::read_link("/proc/self/ns/net").unwrap(),
        std::path::PathBuf::from(std::env::var("STAMP_PARENT_NETNS").unwrap()),
        "requires a private network namespace"
    );
    assert!(std::process::Command::new("ip")
        .args(["link", "set", "lo", "up"])
        .status()
        .unwrap()
        .success());
    guard
}

struct Peer {
    receiver: receiver_fixture::Receiver,
    socket: UdpSocket,
    mode: u8,
}

impl Peer {
    fn start(mode: u8) -> Self {
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let source = socket.local_addr().unwrap();
        let receiver = receiver_fixture::Receiver::start("127.0.0.1:0".parse().unwrap(), |local| {
            let mut args = vec![
                "fixture".into(),
                "--is-reflector".into(),
                "--local-addr".into(),
                "127.0.0.1".into(),
                "--local-port".into(),
                local.port().to_string(),
                "--strict-packets".into(),
                "--drop-replayed".into(),
                "--session-admission".into(),
                "provisioned".into(),
                "--reflector-session".into(),
                format!("42,{source},{local}"),
                "--tlv-mode".into(),
                "echo".into(),
                "--hwtstamp".into(),
                "off".into(),
            ];
            if mode != 0 {
                args.extend(["--hmac-key".into(), hex::encode(KEY)]);
            }
            if mode == 2 {
                args.extend(["--auth-mode".into(), "A".into()]);
            }
            Configuration::parse_from(args)
        });
        Self {
            receiver,
            socket,
            mode,
        }
    }

    fn packet(&self, seq: u32, ber: bool) -> Vec<u8> {
        let base = if self.mode == 2 { 112 } else { 44 };
        let timestamp = if self.mode == 2 { 16 } else { 4 };
        let mut packet = vec![0; base];
        packet[..4].copy_from_slice(&seq.to_be_bytes());
        // An independently encoded, representable NTP timestamp; no wall-clock
        // freshness assumption is imposed on session admission.
        packet[timestamp..timestamp + 8].copy_from_slice(&0xeed0000080000000u64.to_be_bytes());
        packet[timestamp + 9] = 1; // nonzero Error Estimate multiplier
        packet[timestamp + 10..timestamp + 12].copy_from_slice(&42u16.to_be_bytes());
        if self.mode == 2 {
            let digest = wire_hmac::digest(&KEY, &packet[..96]);
            packet[96..112].copy_from_slice(&digest);
        }
        if ber {
            packet.extend_from_slice(&[0x80, 243, 0, 8]);
            packet.extend_from_slice(&[0; 8]);
            if self.mode != 0 {
                let digest = wire_hmac::digest(&KEY, &[&packet[..4], &packet[base..]].concat());
                packet.extend_from_slice(&[0x80, 8, 0, 16]);
                packet.extend_from_slice(&digest);
            }
            // Padding follows HMAC and is deliberately outside its coverage.
            packet.extend_from_slice(&[0x80, 1, 0, 8, 0xff, 0, 0xff, 0, 0xff, 0, 0xff, 0]);
        }
        packet
    }

    fn wait(&self, ready: impl Fn() -> bool) {
        let deadline = Instant::now() + Duration::from_secs(3);
        while !ready() {
            self.receiver.assert_running();
            assert!(
                Instant::now() < deadline,
                "receiver did not complete bookkeeping"
            );
            std::thread::sleep(Duration::from_millis(1));
        }
    }

    fn exchange(&self, packet: &[u8]) -> Vec<u8> {
        let counters = &self.receiver.shared.counters;
        let reflected = counters.packets_reflected.load(Ordering::Relaxed);
        inject(
            self.socket.local_addr().unwrap(),
            self.receiver.address,
            packet,
            None,
        );
        let mut reply = [0; 2048];
        let (len, source) = self.socket.recv_from(&mut reply).unwrap();
        assert_eq!(source, self.receiver.address);
        let (sequence, timestamp, estimate, request_timestamp) = if self.mode == 2 {
            (48, 64, 72, 16)
        } else {
            (24, 28, 36, 4)
        };
        assert_eq!(&reply[..4], &packet[..4]);
        assert_eq!(&reply[sequence..sequence + 4], &packet[..4]);
        assert_eq!(
            &reply[timestamp..timestamp + 8],
            &packet[request_timestamp..request_timestamp + 8]
        );
        assert_eq!(
            &reply[estimate..estimate + 2],
            &packet[request_timestamp + 8..request_timestamp + 10]
        );
        self.wait(|| counters.packets_reflected.load(Ordering::Relaxed) == reflected + 1);
        reply[..len].to_vec()
    }

    fn reject(&self, source: &UdpSocket, packet: &[u8]) {
        let counters = &self.receiver.shared.counters;
        let dropped = counters.packets_dropped.load(Ordering::Relaxed);
        inject(
            source.local_addr().unwrap(),
            self.receiver.address,
            packet,
            None,
        );
        self.wait(|| counters.packets_dropped.load(Ordering::Relaxed) == dropped + 1);
        silence(source);
    }

    fn summary(&self) -> SessionSummary {
        let mut sessions = self
            .receiver
            .shared
            .session_manager
            .session_summaries_extended();
        assert_eq!(sessions.len(), 1);
        sessions.pop().unwrap()
    }

    fn unchanged(&self, before: &SessionSummary) {
        let after = self.summary();
        assert_eq!(after.key, before.key);
        assert_eq!(after.last_active, before.last_active);
        assert_eq!(after.packets_received, before.packets_received);
        assert_eq!(after.packets_transmitted, before.packets_transmitted);
        assert_eq!(after.last_reflected_seq, before.last_reflected_seq);
    }
}

fn silence(socket: &UdpSocket) {
    socket
        .set_read_timeout(Some(Duration::from_millis(50)))
        .unwrap();
    let error = socket.recv_from(&mut [0; 2048]).unwrap_err();
    assert!(matches!(
        error.kind(),
        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
    ));
    socket
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
}

fn checksum(bytes: &[u8]) -> u16 {
    let mut sum: u32 = bytes
        .chunks(2)
        .map(|pair| (u32::from(pair[0]) << 8) | u32::from(*pair.get(1).unwrap_or(&0)))
        .sum();
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn udp_checksum_errors() -> u64 {
    let stats = std::fs::read_to_string("/proc/net/snmp").unwrap();
    let mut udp = stats.lines().filter_map(|line| line.strip_prefix("Udp: "));
    let columns: Vec<_> = udp.next().unwrap().split_whitespace().collect();
    let index = columns
        .iter()
        .position(|name| *name == "InCsumErrors")
        .unwrap();
    udp.next()
        .unwrap()
        .split_whitespace()
        .nth(index)
        .unwrap()
        .parse()
        .unwrap()
}

/// Construct and capture the actual IP/UDP request, independently of STAMP codecs.
/// None emits checksum zero. Some(original) computes the checksum before a
/// payload mutation, allowing a kernel checksum-drop control on the same bytes.
fn inject(source: SocketAddr, destination: SocketAddr, payload: &[u8], original: Option<&[u8]>) {
    let capture = socket2::Socket::new(
        socket2::Domain::IPV4,
        socket2::Type::from(libc::SOCK_RAW),
        Some(socket2::Protocol::UDP),
    )
    .unwrap();
    capture
        .bind(&"127.0.0.1:0".parse::<SocketAddr>().unwrap().into())
        .unwrap();
    let capture: UdpSocket = capture.into();
    capture
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let raw = socket2::Socket::new(
        socket2::Domain::IPV4,
        socket2::Type::from(libc::SOCK_RAW),
        Some(socket2::Protocol::from(libc::IPPROTO_RAW)),
    )
    .unwrap();
    let length = u16::try_from(8 + payload.len()).unwrap();
    let mut udp = [
        source.port().to_be_bytes(),
        destination.port().to_be_bytes(),
        length.to_be_bytes(),
        [0; 2],
    ]
    .concat();
    let mut pseudo = vec![127, 0, 0, 1, 127, 0, 0, 1, 0, 17];
    pseudo.extend_from_slice(&length.to_be_bytes());
    if let Some(original) = original {
        assert_eq!(original.len(), payload.len());
        let value = checksum(&[&pseudo[..], &udp, original].concat());
        udp[6..8].copy_from_slice(&if value == 0 { u16::MAX } else { value }.to_be_bytes());
    }
    udp.extend_from_slice(payload);
    let mut ip = vec![
        0x45, 0, 0, 0, 0, 0, 0, 0, 64, 17, 0, 0, 127, 0, 0, 1, 127, 0, 0, 1,
    ];
    ip[2..4].copy_from_slice(&(length + 20).to_be_bytes());
    ip.extend_from_slice(&udp);
    // IPPROTO_RAW asks Linux to fill the IPv4 header checksum, leaving UDP intact.
    assert_eq!(raw.send_to(&ip, &destination.into()).unwrap(), ip.len());
    let mut frame = [0; 4096];
    loop {
        let (size, _) = capture.recv_from(&mut frame).unwrap();
        let ihl = usize::from(frame[0] & 0xf) * 4;
        if size != ip.len() || frame[ihl..size] != udp {
            continue;
        }
        assert_eq!(frame[0], 0x45);
        assert_eq!(&frame[12..20], &[127, 0, 0, 1, 127, 0, 0, 1]);
        assert_eq!(checksum(&frame[..ihl]), 0, "valid IPv4 header checksum");
        if original.is_none() {
            assert_eq!(
                &frame[ihl + 6..ihl + 8],
                &[0, 0],
                "actual UDP checksum zero"
            );
        } else {
            assert_ne!(&frame[ihl + 6..ihl + 8], &[0, 0]);
            assert_eq!(
                checksum(&[&pseudo[..], &frame[ihl..size]].concat()) == 0,
                original == Some(payload),
                "independent UDP checksum control"
            );
        }
        eprintln!(
            "captured IPv4 request: checksum={:04x}, payload={} octets",
            u16::from_be_bytes(frame[ihl + 6..ihl + 8].try_into().unwrap()),
            payload.len()
        );
        break;
    }
}

#[test]
#[ignore = "requires a private network namespace and CAP_NET_RAW"]
fn zero_checksum_padding_errors_survive_kernel_checks_and_preserve_hmac() {
    let _namespace = namespace();
    for mode in 0..=2 {
        let peer = Peer::start(mode);
        let clean = peer.packet(0, true);
        // Positive nonzero-checksum control proves that the raw checksum oracle works.
        inject(
            peer.socket.local_addr().unwrap(),
            peer.receiver.address,
            &clean,
            Some(&clean),
        );
        let mut response = [0; 2048];
        peer.socket.recv_from(&mut response).unwrap();
        peer.wait(|| {
            peer.receiver
                .shared
                .counters
                .packets_reflected
                .load(Ordering::Relaxed)
                == 1
        });
        let clean = peer.packet(1, true);
        let mut corrupt = clean.clone();
        *corrupt.last_mut().unwrap() ^= 0x0f;
        let received = peer
            .receiver
            .shared
            .counters
            .packets_received
            .load(Ordering::Relaxed);
        let checksum_errors = udp_checksum_errors();
        inject(
            peer.socket.local_addr().unwrap(),
            peer.receiver.address,
            &corrupt,
            Some(&clean),
        );
        peer.wait(|| udp_checksum_errors() == checksum_errors + 1);
        silence(&peer.socket);
        assert_eq!(
            peer.receiver
                .shared
                .counters
                .packets_received
                .load(Ordering::Relaxed),
            received,
            "kernel must discard a nonzero-checksum packet with changed padding"
        );
        let reply = peer.exchange(&corrupt);
        let base = if mode == 2 { 112 } else { 44 };
        assert_eq!(
            &reply[base..base + 12],
            &[0, 243, 0, 8, 0, 0, 0, 4, 0, 0, 0, 4]
        );
        assert_eq!(
            &reply[reply.len() - 8..],
            &[0xff, 0, 0xff, 0, 0xff, 0, 0xff, 0]
        );
        if mode != 0 {
            let at = base + 12;
            assert_eq!(&reply[at..at + 4], &[0, 8, 0, 16]);
            assert_eq!(
                &reply[at + 4..at + 20],
                &wire_hmac::digest(&KEY, &[&reply[..4], &reply[base..at]].concat())
            );
        }
        if mode == 2 {
            assert_eq!(&reply[96..112], &wire_hmac::digest(&KEY, &reply[..96]));
        }
        assert_eq!(peer.summary().packets_received, 2);
        peer.receiver.stop().unwrap();
    }
}

#[test]
#[ignore = "requires a private network namespace and CAP_NET_RAW"]
fn zero_checksum_strict_and_provisioned_rejections_precede_session_mutation() {
    let _namespace = namespace();
    for mode in [0, 2] {
        let peer = Peer::start(mode);
        let valid = peer.packet(0, false);
        peer.reject(&peer.socket, &valid[..valid.len() - 1]);
        let mut wrong_ssid = valid.clone();
        wrong_ssid[if mode == 2 { 27 } else { 15 }] ^= 1;
        peer.reject(&peer.socket, &wrong_ssid);
        let stranger = UdpSocket::bind("127.0.0.1:0").unwrap();
        peer.reject(&stranger, &valid);
        assert_eq!(peer.receiver.shared.session_manager.session_count(), 0);
        peer.exchange(&valid);
        let before = peer.summary();
        peer.reject(&peer.socket, &valid[..valid.len() - 1]);
        peer.reject(&peer.socket, &wrong_ssid);
        peer.reject(&stranger, &valid);
        peer.unchanged(&before);
        peer.exchange(&peer.packet(1, false));
        // The configured replay policy counts the receive before dropping it;
        // this is explicitly outside the pre-mutation guarantees above.
        peer.reject(&peer.socket, &peer.packet(1, false));
        assert_eq!(peer.summary().packets_transmitted, 2);
        peer.receiver.stop().unwrap();
    }
}

#[test]
#[ignore = "requires a private network namespace and CAP_NET_RAW"]
fn zero_checksum_authenticated_base_corruption_does_not_advance_session() {
    let _namespace = namespace();
    let peer = Peer::start(2);
    peer.exchange(&peer.packet(0, false));
    let before = peer.summary();
    let next = peer.packet(1, false);
    for field in [3, 16, 24, 96] {
        let mut corrupt = next.clone();
        corrupt[field] ^= 1; // sequence, timestamp, Error Estimate, base HMAC
        peer.reject(&peer.socket, &corrupt);
        peer.unchanged(&before);
    }
    peer.exchange(&next);
    assert_eq!(peer.summary().packets_received, 2);
    peer.receiver.stop().unwrap();
}
