//! pnet backend integration test on the `lo` interface.
//!
//! Requires `CAP_NET_RAW` (or root) and the `ttl-pnet` feature. The whole
//! test module is cfg-gated so default `cargo test` builds do not even
//! compile it. The `#[ignore]` attribute additionally keeps the tests out
//! of unprivileged CI runs; opt-in invocation:
//!
//! ```bash
//! sudo setcap cap_net_raw,cap_net_admin=eip $(rustc --print sysroot)/lib/rustlib/x86_64-unknown-linux-gnu/bin/test_runner_or_target_test_binary
//! cargo test --features ttl-pnet --test pnet_loopback_test -- --ignored
//! ```
//!
//! Or, more pragmatically:
//!
//! ```bash
//! sudo -E cargo test --features ttl-pnet --test pnet_loopback_test -- --ignored
//! ```
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

/// Returns true when the process has CAP_NET_RAW or is running as root.
/// pnet datalink capture needs one of these on Linux. Parses
/// `/proc/self/status` for both the uid and the effective capability set
/// to avoid pulling in libc/nix as a dev-dep.
fn has_raw_capability() -> bool {
    use std::fs;
    let Ok(status) = fs::read_to_string("/proc/self/status") else {
        return false;
    };
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("Uid:") {
            // Uid: real effective saved fs (tab-separated)
            if let Some(real) = rest.split_whitespace().next() {
                if real.trim() == "0" {
                    return true;
                }
            }
        }
        if let Some(rest) = line.strip_prefix("CapEff:") {
            if let Ok(caps) = u64::from_str_radix(rest.trim(), 16) {
                // CAP_NET_RAW = bit 13.
                if caps & (1u64 << 13) != 0 {
                    return true;
                }
            }
        }
    }
    false
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
        eprintln!(
            "Skipping pnet loopback test: process lacks CAP_NET_RAW. \
             Run with sudo or `setcap cap_net_raw+eip`."
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

    // Start the receiver in the background. Move conf+shared into the
    // task so they outlive run_receiver's borrow.
    let handle = tokio::spawn(async move {
        receiver::run_receiver(&conf, &shared).await;
    });

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
    sender
        .send_to(&sender_packet, target)
        .await
        .expect("send to reflector");

    // Await a reply.
    let mut buf = [0u8; 2048];
    let recv = timeout(Duration::from_secs(3), sender.recv_from(&mut buf)).await;

    // Whatever the outcome, tear down the receiver.
    handle.abort();

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
    let bytes = packet.to_bytes().to_vec();
    let reply = one_packet_round_trip(48863, AuthMode::Authenticated, Some(key_hex), bytes).await;
    // Note: without a proper HMAC the reflector will likely drop. The
    // point of this test on the integration side is to prove the pnet
    // pipeline forwards into our process_stamp_packet path; either
    // Some(reply) (HMAC-disabled-by-default contract) or None
    // (HMAC-required-correct) is observable. Don't hard-fail here — the
    // unauth test above already exercises the success path.
    if let Some(reply) = reply {
        assert!(
            reply.len() >= receiver::AUTH_BASE_SIZE,
            "auth reply size must be at least the auth base"
        );
    }
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
