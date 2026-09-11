//! pnet backend integration test on the `lo` interface.
//!
//! Requires `CAP_NET_RAW` (or root) and the `ttl-pnet` feature. The whole
//! test module is cfg-gated so default `cargo test` builds do not even
//! compile it. The `#[ignore]` attribute additionally keeps the tests out
//! of unprivileged CI runs; opt-in invocation:
//!
//! ```bash
//! sudo -E env STAMP_REQUIRE_PRIVILEGED=1 cargo test --locked --no-default-features --features ttl-pnet --test pnet_loopback_test -- --ignored --test-threads=1
//! ```
//!
//! Required mode fails if CAP_NET_RAW is absent. Authenticated traffic must
//! receive a valid signed reply; no reply is a test failure.
//!
//! See tests/README.md for full instructions.

// The pnet backend is only active when ttl-pnet is set and ttl-nix is NOT
// set: receiver/mod.rs picks nix when both features compile in. This
// integration test specifically exercises the pnet path, so gate the
// whole module to that combination plus Linux (pcap availability).
#![cfg(all(target_os = "linux", feature = "ttl-pnet", not(feature = "ttl-nix")))]

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::Ordering;
use std::time::Duration;

use tokio::net::UdpSocket;
use tokio::time::timeout;

use stamp_suite::configuration::{AuthMode, ClockFormat, Configuration};
use stamp_suite::packets::{
    PacketAuthenticated, PacketUnauthenticated, ReflectedPacketUnauthenticated,
};
use stamp_suite::receiver;
use stamp_suite::time::generate_timestamp;

mod privileged;

/// Inspect the effective capability, rather than assuming container root has it.
fn has_raw_capability() -> bool {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|status| {
            status.lines().find_map(|line| {
                line.strip_prefix("CapEff:")
                    .and_then(|hex| u64::from_str_radix(hex.trim(), 16).ok())
            })
        })
        .is_some_and(|caps| caps & (1 << 13) != 0)
}

/// Build a minimum Configuration suitable for driving the pnet receiver
/// on the loopback interface with the given local port and auth mode.
fn reflector_conf(local_port: u16, auth: AuthMode, hmac_key_hex: Option<&str>) -> Configuration {
    let mut args = vec![
        "stamp-suite".to_string(),
        "--remote-addr".to_string(),
        "127.0.0.1".to_string(),
        "--local-addr".to_string(),
        "127.0.0.1".to_string(),
        "--local-port".to_string(),
        local_port.to_string(),
        "--is-reflector".to_string(),
        "--session-timeout".to_string(),
        "0".to_string(),
    ];
    if matches!(auth, AuthMode::Authenticated) {
        args.push("--auth-mode".to_string());
        args.push("A".to_string());
        if let Some(k) = hmac_key_hex {
            args.push("--hmac-key".to_string());
            args.push(k.to_string());
        }
    }
    use clap::Parser;
    Configuration::parse_from(args)
}

/// Skip-pattern shared across all integration tests in this module.
async fn skip_unless_pnet_capable() -> Option<()> {
    if !has_raw_capability() {
        privileged::unavailable(
            "pnet loopback",
            "process lacks CAP_NET_RAW; run with sudo or setcap",
        );
        return None;
    }
    Some(())
}

/// Drive a packet through a real pnet receiver on lo and assert we get a
/// well-formed STAMP reply back.
async fn one_packet_round_trip(
    local_port: u16,
    auth: AuthMode,
    hmac_key_hex: Option<&str>,
    sender_packet: Vec<u8>,
) -> Option<Vec<u8>> {
    // The receiver task takes ownership of `conf` and `shared`; we
    // re-parse the same args for the caller side by simply constructing
    // them locally where needed (sender doesn't read conf).
    let conf = reflector_conf(local_port, auth, hmac_key_hex);
    let shared = receiver::create_shared_state(&conf);
    let shared_capture_alive = shared.capture_alive.clone();
    let shutdown = shared.shutdown_requested.clone();
    struct ShutdownOnDrop(std::sync::Arc<std::sync::atomic::AtomicBool>);
    impl Drop for ShutdownOnDrop {
        fn drop(&mut self) {
            self.0.store(true, Ordering::Relaxed);
        }
    }
    let _shutdown_guard = ShutdownOnDrop(shutdown.clone());

    // Start the receiver in the background. Move conf+shared into the
    // task so they outlive run_receiver's borrow.
    let handle = tokio::spawn(async move { receiver::run_receiver(&conf, &shared).await });

    // Give the pnet capture thread time to attach to the interface;
    // then check capture_alive in case it bailed out (e.g. bad perms).
    tokio::time::sleep(Duration::from_millis(250)).await;
    if !shared_capture_alive.load(Ordering::Relaxed) {
        eprintln!("Receiver shut down before we could send a packet; check perms / interface");
        handle.abort();
        return None;
    }

    // Send the packet.
    let sender = UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("bind sender socket");
    let target: SocketAddr = (IpAddr::V4(Ipv4Addr::LOCALHOST), local_port).into();
    // Loopback exposes CHECKSUM_PARTIAL frames before checksum completion.
    // Inject complete wire checksums instead of relaxing receiver validation.
    send_wire_udp(
        sender.local_addr().unwrap().port(),
        target,
        &sender_packet,
        false,
    );
    let mut rejected = [0; 2048];
    assert!(
        timeout(Duration::from_millis(100), sender.recv_from(&mut rejected))
            .await
            .is_err(),
        "invalid UDP checksum must not create a reflected measurement"
    );
    send_wire_udp(
        sender.local_addr().unwrap().port(),
        target,
        &sender_packet,
        true,
    );

    // Await a reply.
    let mut buf = [0u8; 2048];
    let recv = timeout(Duration::from_secs(3), sender.recv_from(&mut buf)).await;

    // A JoinHandle abort cannot stop spawn_blocking capture. Request shutdown
    // and wait for both capture and transmission workers to leave.
    shutdown.store(true, Ordering::Relaxed);
    timeout(Duration::from_secs(4), handle)
        .await
        .expect("pnet shutdown timed out")
        .expect("receiver task panicked")
        .expect("receiver failed");

    match recv {
        Ok(Ok((n, _))) => Some(buf[..n].to_vec()),
        Ok(Err(e)) => {
            eprintln!("recv error: {e}");
            None
        }
        Err(_) => {
            eprintln!("recv timeout — pnet reflector didn't reply");
            None
        }
    }
}

// ---------------------------------------------------------------------------
// Tests. All `#[ignore]` so they don't run in default CI.

#[tokio::test]
#[ignore = "requires CAP_NET_RAW and the ttl-pnet feature; see tests/README.md"]
async fn pnet_open_mode_loopback_round_trip() {
    if skip_unless_pnet_capable().await.is_none() {
        return;
    }

    let packet = PacketUnauthenticated {
        sequence_number: 42,
        timestamp: generate_timestamp(ClockFormat::NTP),
        error_estimate: 0,
        ssid: 0,
        mbz: [0; 28],
    };

    let bytes = packet.to_bytes().to_vec();
    let reply = one_packet_round_trip(48862, AuthMode::Open, None, bytes)
        .await
        .expect("pnet reflector must reply over lo");
    let parsed =
        ReflectedPacketUnauthenticated::from_bytes(&reply).expect("reply must parse as reflected");
    assert_eq!(
        parsed.sess_sender_seq_number, 42,
        "echoed sender sequence number must round-trip"
    );
}

#[tokio::test]
#[ignore = "requires CAP_NET_RAW and the ttl-pnet feature; see tests/README.md"]
async fn pnet_authenticated_mode_loopback_round_trip() {
    if skip_unless_pnet_capable().await.is_none() {
        return;
    }
    // 16-byte hex-encoded key matches the project's documented contract.
    let key_hex = "0123456789abcdef0123456789abcdef";

    let packet = PacketAuthenticated {
        sequence_number: 7,
        mbz0: [0; 12],
        timestamp: generate_timestamp(ClockFormat::NTP),
        error_estimate: 0,
        ssid: 0,
        mbz1a: [0; 30],
        mbz1b: [0; 32],
        mbz1c: [0; 6],
        hmac: [0; 16],
    };
    let key = stamp_suite::crypto::HmacKey::new(hex::decode(key_hex).unwrap()).unwrap();
    let mut bytes = packet.to_bytes().to_vec();
    let mac = stamp_suite::crypto::compute_packet_hmac(&key, &bytes, 96);
    bytes[96..112].copy_from_slice(&mac);
    let reply = one_packet_round_trip(48863, AuthMode::Authenticated, Some(key_hex), bytes)
        .await
        .expect("authenticated pnet reflector must reply");
    let parsed = stamp_suite::packets::ReflectedPacketAuthenticated::from_bytes(&reply)
        .expect("authenticated reply must parse");
    assert_eq!(parsed.sess_sender_seq_number, 7);
    assert_eq!(
        &reply[96..112],
        &stamp_suite::crypto::compute_packet_hmac(&key, &reply, 96)
    );
}

#[tokio::test]
#[ignore = "requires CAP_NET_RAW and the ttl-pnet feature; see tests/README.md"]
async fn pnet_tlv_chain_loopback_round_trip() {
    use stamp_suite::tlv::{ClassOfServiceTlv, TypedTlv};

    if skip_unless_pnet_capable().await.is_none() {
        return;
    }

    let packet = PacketUnauthenticated {
        sequence_number: 100,
        timestamp: generate_timestamp(ClockFormat::NTP),
        error_estimate: 0,
        ssid: 0,
        mbz: [0; 28],
    };
    let cos = ClassOfServiceTlv::new(46, 2).to_raw();
    let mut bytes = packet.to_bytes().to_vec();
    bytes.extend_from_slice(&cos.to_bytes());

    let reply = one_packet_round_trip(48864, AuthMode::Open, None, bytes)
        .await
        .expect("pnet reflector must reply with TLV chain");
    assert!(
        reply.len() > receiver::UNAUTH_BASE_SIZE,
        "reply must include reflected TLV chain"
    );
}

fn send_wire_udp(source_port: u16, target: SocketAddr, payload: &[u8], valid: bool) {
    let socket = socket2::Socket::new(
        socket2::Domain::IPV4,
        socket2::Type::from(libc::SOCK_RAW),
        Some(socket2::Protocol::from(libc::IPPROTO_RAW)),
    )
    .unwrap();
    let len = (payload.len() + 8) as u16;
    let mut udp = Vec::new();
    udp.extend_from_slice(&source_port.to_be_bytes());
    udp.extend_from_slice(&target.port().to_be_bytes());
    udp.extend_from_slice(&len.to_be_bytes());
    udp.extend_from_slice(&[0; 2]);
    udp.extend_from_slice(payload);
    let mut pseudo = vec![127, 0, 0, 1, 127, 0, 0, 1, 0, 17];
    pseudo.extend_from_slice(&len.to_be_bytes());
    pseudo.extend_from_slice(&udp);
    let mut sum = 0u32;
    for pair in pseudo.chunks(2) {
        sum += u32::from(pair[0]) * 256 + u32::from(*pair.get(1).unwrap_or(&0));
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    let checksum = !(sum as u16);
    let checksum = if checksum == 0 { u16::MAX } else { checksum };
    udp[6..8].copy_from_slice(&checksum.to_be_bytes());
    if !valid {
        udp[6] ^= 0x80;
    }
    let mut ip = vec![
        0x45, 0, 0, 0, 0, 0, 0, 0, 64, 17, 0, 0, 127, 0, 0, 1, 127, 0, 0, 1,
    ];
    ip[2..4].copy_from_slice(&(len + 20).to_be_bytes());
    ip.extend(udp);
    // IPPROTO_RAW enables IP_HDRINCL; Linux fills the IP header checksum.
    socket.send_to(&ip, &target.into()).unwrap();
}
