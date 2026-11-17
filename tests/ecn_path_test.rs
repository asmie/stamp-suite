//! Real endpoints under kernel ECN rewriting, with independent IP/TLV capture.
#![cfg(all(
    target_os = "linux",
    any(feature = "ttl-nix", not(feature = "ttl-pnet"))
))]

#[path = "ecn_path_test/evidence.rs"]
mod evidence;

#[path = "common/child.rs"]
mod child;
#[path = "common/inet.rs"]
mod inet;
#[path = "common/reflector.rs"]
mod reflector;
#[path = "common/wire_hmac.rs"]
mod wire_hmac;

use std::{
    collections::BTreeMap,
    net::UdpSocket,
    os::fd::AsRawFd,
    process::Command,
    time::{Duration, Instant},
};

use child::ChildProcess;

const KEY: [u8; 16] = [0xab; 16];
const COUNT: u64 = 3;
const TABLE: &str = "stamp_ecn_diag";

#[derive(Clone, Copy, Debug)]
struct Case {
    name: &'static str,
    requested: u8,
    forward: Option<u8>,
    reverse: Option<u8>,
    denied: bool,
}

fn nft(args: &[&str]) -> Vec<u8> {
    let output = Command::new("nft")
        .args(args)
        .output()
        .expect("nftables is required");
    assert!(
        output.status.success(),
        "nft {args:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    output.stdout
}

struct Rules;
impl Rules {
    fn new(ip: &str, port: u16, case: Case) -> Self {
        nft(&["add", "table", "inet", TABLE]);
        let rules = Self;
        nft(&[
            "add",
            "chain",
            "inet",
            TABLE,
            "output",
            "{ type filter hook output priority mangle; policy accept; }",
        ]);
        let family = if ip == "::1" { "ip6" } else { "ip" };
        for (port_field, value) in [("dport", case.forward), ("sport", case.reverse)] {
            if let Some(value) = value {
                nft(&[
                    "add",
                    "rule",
                    "inet",
                    TABLE,
                    "output",
                    "oifname",
                    "lo",
                    family,
                    "daddr",
                    ip,
                    "udp",
                    port_field,
                    &port.to_string(),
                    "counter",
                    family,
                    "ecn",
                    "set",
                    &value.to_string(),
                ]);
            }
        }
        rules
    }

    fn verify(&self, case: Case) -> serde_json::Value {
        let json: serde_json::Value =
            serde_json::from_slice(&nft(&["-j", "list", "table", "inet", TABLE])).unwrap();
        let counters: Vec<_> = json["nftables"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|entry| entry.get("rule"))
            .flat_map(|rule| rule["expr"].as_array().unwrap())
            .filter_map(|expr| expr.get("counter"))
            .map(|counter| counter["packets"].as_u64().unwrap())
            .collect();
        assert_eq!(
            counters,
            vec![COUNT; usize::from(case.forward.is_some()) + usize::from(case.reverse.is_some())]
        );
        json
    }

    fn finish(self) {
        nft(&["delete", "table", "inet", TABLE]);
        std::mem::forget(self);
    }
}
impl Drop for Rules {
    fn drop(&mut self) {
        // Best effort during assertion unwinding; the enclosing namespace also
        // owns all rules. The normal path checks deletion explicitly.
        let _ = Command::new("nft")
            .args(["delete", "table", "inet", TABLE])
            .output();
    }
}

fn capture() -> UdpSocket {
    let socket = socket2::Socket::new(
        socket2::Domain::from(libc::AF_PACKET),
        socket2::Type::DGRAM,
        Some(socket2::Protocol::from(i32::from(
            (libc::ETH_P_ALL as u16).to_be(),
        ))),
    )
    .unwrap();
    // SAFETY: the interface string is NUL-terminated. sockaddr_ll is a plain
    // integer structure; its initialized fields and actual size are passed to
    // bind while the owning socket and address remain live.
    let result = unsafe {
        let index = libc::if_nametoindex(c"lo".as_ptr());
        assert_ne!(index, 0);
        let mut address: libc::sockaddr_ll = std::mem::zeroed();
        address.sll_family = libc::AF_PACKET as u16;
        address.sll_protocol = (libc::ETH_P_ALL as u16).to_be();
        address.sll_ifindex = index as i32;
        libc::bind(
            socket.as_raw_fd(),
            (&address as *const libc::sockaddr_ll).cast(),
            std::mem::size_of_val(&address) as _,
        )
    };
    assert_eq!(result, 0, "{}", std::io::Error::last_os_error());
    let socket: UdpSocket = socket.into();
    socket
        .set_read_timeout(Some(Duration::from_millis(10)))
        .unwrap();
    socket
}

#[derive(Debug, PartialEq, Eq)]
struct Packet {
    tos: u8,
    source: u16,
    target: u16,
    payload: Vec<u8>,
}

fn packet(bytes: &[u8], ipv6: bool, port: u16) -> Option<Packet> {
    let (offset, total, tos) = if ipv6 {
        if bytes.len() < 48 || bytes[0] >> 4 != 6 || bytes[6] != 17 {
            return None;
        }
        (
            40,
            40 + usize::from(u16::from_be_bytes([bytes[4], bytes[5]])),
            ((bytes[0] & 15) << 4) | (bytes[1] >> 4),
        )
    } else {
        if bytes.len() < 28 || bytes[0] >> 4 != 4 || bytes[9] != 17 {
            return None;
        }
        let ihl = usize::from(bytes[0] & 15) * 4;
        assert!(ihl >= 20 && bytes.len() >= ihl + 8);
        assert_eq!(
            inet::checksum(&bytes[..ihl]),
            0,
            "rewritten IPv4 header checksum"
        );
        (
            ihl,
            usize::from(u16::from_be_bytes([bytes[2], bytes[3]])),
            bytes[1],
        )
    };
    assert!(total <= bytes.len() && total >= offset + 8);
    let udp = &bytes[offset..total];
    let source = u16::from_be_bytes([udp[0], udp[1]]);
    let target = u16::from_be_bytes([udp[2], udp[3]]);
    if source != port && target != port {
        return None;
    }
    assert_eq!(usize::from(u16::from_be_bytes([udp[4], udp[5]])), udp.len());
    // Loopback captures may contain partial UDP checksums before offload;
    // payload integrity is verified independently below.
    Some(Packet {
        tos,
        source,
        target,
        payload: udp[8..].to_vec(),
    })
}

fn verify_tlvs(bytes: &[u8], mode: u8, reflected: bool, value: [u8; 4]) {
    let base = if mode == 2 { 112 } else { 44 };
    let flag = if reflected { 0 } else { 0x80 };
    assert_eq!(bytes.len(), base + 8 + if mode == 0 { 0 } else { 20 });
    assert_eq!(&bytes[base..base + 4], &[flag, 4, 0, 4]);
    assert_eq!(&bytes[base + 4..base + 8], &value);
    if mode != 0 {
        assert_eq!(&bytes[base + 8..base + 12], &[flag, 8, 0, 16]);
        let covered = [&bytes[..4], &bytes[base..base + 8]].concat();
        assert_eq!(&bytes[base + 12..], &wire_hmac::digest(&KEY, &covered));
    }
    if mode == 2 {
        assert_eq!(&bytes[96..112], &wire_hmac::digest(&KEY, &bytes[..96]));
    }
}

fn verify_pair(request: &Packet, reply: &Packet, mode: u8, case: Case) {
    let forward = case.forward.unwrap_or(case.requested);
    let reverse = case
        .reverse
        .unwrap_or(if case.denied { 0 } else { case.requested });
    assert_eq!(request.tos, (46 << 2) | forward);
    assert_eq!(reply.tos, (46 << 2) | reverse);
    assert_eq!(request.source, reply.target);
    assert_eq!(request.target, reply.source);
    verify_tlvs(
        &request.payload,
        mode,
        false,
        [46 << 2, 0, case.requested << 6, 0],
    );
    verify_tlvs(
        &reply.payload,
        mode,
        true,
        [
            (46 << 2) | (46 >> 4),
            (14 << 4) | (forward << 2),
            (case.requested << 6) | (if case.denied { 2 } else { 3 } << 4),
            0,
        ],
    );
    let (seq, t1, original, ssid) = if mode == 2 {
        (48, 64, 16, 26)
    } else {
        (24, 28, 4, 14)
    };
    assert_eq!(&reply.payload[seq..seq + 4], &request.payload[..4]);
    assert_eq!(
        &reply.payload[t1..t1 + 10],
        &request.payload[original..original + 10]
    );
    for payload in [&request.payload, &reply.payload] {
        assert_eq!(&payload[ssid..ssid + 2], &42u16.to_be_bytes());
    }
}

fn check_direction(value: &serde_json::Value, baseline: u8, observed: u8, denied: bool) {
    // Literal pair classification independent of the production classifier.
    let outcomes = [
        ["unchanged", "remarked", "remarked", "remarked"],
        ["bleaching", "unchanged", "remarked", "ce_marked"],
        ["bleaching", "remarked", "unchanged", "ce_marked"],
        ["bleaching", "remarked", "remarked", "unchanged"],
    ];
    assert_eq!(value["comparable"], if denied { 0 } else { COUNT });
    assert_eq!(value["unknown"], if denied { COUNT } else { 0 });
    for key in ["unchanged", "bleaching", "ce_marked", "remarked"] {
        let expected = if !denied && outcomes[usize::from(baseline)][usize::from(observed)] == key {
            COUNT
        } else {
            0
        };
        assert_eq!(value[key], expected, "{key}");
    }
    assert_eq!(
        value["ce_observed"],
        if !denied && observed == 3 { COUNT } else { 0 }
    );
    for from in 0..4 {
        for to in 0..4 {
            assert_eq!(
                value["transitions"][from][to],
                if !denied && from == usize::from(baseline) && to == usize::from(observed) {
                    COUNT
                } else {
                    0
                }
            );
        }
    }
    for (reason, count) in value["unknown_reasons"].as_object().unwrap() {
        assert_eq!(
            count,
            if denied && reason == "reflector_unable" {
                COUNT
            } else {
                0
            }
        );
    }
}

fn trial(ip: &str, mode: u8, case: Case) {
    eprintln!("ECN path: {ip} key_mode={mode} {case:?}");
    let mut command = reflector::Reflector::command(ip);
    command.args(["--tlv-mode", "echo", "--hwtstamp", "off"]);
    if mode != 0 {
        command.args(["--hmac-key", &hex::encode(KEY)]);
    }
    if mode == 2 {
        command.args(["--auth-mode", "A"]);
    }
    if case.denied {
        command.args(["--allowed-ecn", "0"]);
    }
    let reflector = reflector::Reflector::spawn(command).unwrap();
    let port = reflector.address.port();
    let rules = Rules::new(ip, port, case);
    let capture = capture();
    let mut evidence = evidence::Evidence::new(ip == "::1", mode, case.name);
    let mut command = Command::new(env!("CARGO_BIN_EXE_stamp-suite"));
    command
        .args([
            "--local-addr",
            ip,
            "--local-port",
            "0",
            "--remote-addr",
            ip,
            "--remote-port",
            &port.to_string(),
            "--count",
            &COUNT.to_string(),
            "--send-delay",
            "20",
            "--timeout",
            "1",
            "--hwtstamp",
            "off",
            "--output-format",
            "json",
            "--ssid",
            "42",
            "--cos",
            "--dscp",
            "46",
            "--ecn",
            &case.requested.to_string(),
        ])
        .env_remove("STAMP_HMAC_KEY")
        .env("RUST_LOG", "off")
        .env("TOKIO_WORKER_THREADS", "2");
    if mode != 0 {
        command.args(["--hmac-key", &hex::encode(KEY)]);
    }
    if mode == 2 {
        command.args(["--auth-mode", "A"]);
    }
    let mut sender = ChildProcess::spawn(&mut command);
    let mut packets = BTreeMap::new();
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut buffer = [0; 4096];
    loop {
        assert!(
            Instant::now() < deadline,
            "sender/capture deadline: {}",
            reflector.diagnostics()
        );
        match capture.recv(&mut buffer) {
            Ok(size) => {
                if let Some(packet) = packet(&buffer[..size], ip == "::1", port) {
                    if let Some(evidence) = evidence.as_mut() {
                        evidence.packet(&buffer[..size]);
                    }
                    let reply = packet.source == port;
                    let offset = if reply {
                        if mode == 2 {
                            48
                        } else {
                            24
                        }
                    } else {
                        0
                    };
                    assert!(packet.payload.len() >= offset + 4);
                    let sequence =
                        u32::from_be_bytes(packet.payload[offset..offset + 4].try_into().unwrap());
                    assert!(u64::from(sequence) < COUNT);
                    if let Some(previous) = packets.insert((reply, sequence), packet) {
                        assert_eq!(
                            previous,
                            packets[&(reply, sequence)],
                            "loopback capture duplicate"
                        );
                    }
                }
            }
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                if sender.try_wait().is_some() {
                    break;
                }
            }
            Err(e) => panic!("capture: {e}"),
        }
    }
    let output = sender.finish(Duration::from_secs(5));
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(packets.len(), 2 * COUNT as usize);
    for sequence in 0..COUNT as u32 {
        verify_pair(
            &packets[&(false, sequence)],
            &packets[&(true, sequence)],
            mode,
            case,
        );
    }
    let rule_counters = rules.verify(case);
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["packets_sent"], COUNT);
    assert_eq!(report["packets_received"], COUNT);
    assert_eq!(report["packets_lost"], 0);
    let ecn = &report["measurements"]["ecn"];
    assert_eq!(ecn["replies"], COUNT);
    assert_eq!(ecn["usable_cos"], COUNT);
    assert_eq!(ecn["unavailable_cos"], 0);
    assert_eq!(ecn["unavailable_reply_ip_ecn"], 0);
    assert_eq!(ecn["conformant_reflected"], 0);
    let forward = case.forward.unwrap_or(case.requested);
    let reverse = case
        .reverse
        .unwrap_or(if case.denied { 0 } else { case.requested });
    for index in 0..4 {
        assert_eq!(
            ecn["received_ec2"][index],
            if index == usize::from(forward) {
                COUNT
            } else {
                0
            }
        );
        assert_eq!(
            ecn["reply_ip_ecn"][index],
            if index == usize::from(reverse) {
                COUNT
            } else {
                0
            }
        );
    }
    check_direction(&ecn["forward"], case.requested, forward, false);
    check_direction(&ecn["reverse"], case.requested, reverse, case.denied);
    if matches!(case.requested, 1 | 2) {
        assert_eq!(
            report["congestion"]["ce_replies"],
            if forward == 3 || reverse == 3 {
                COUNT
            } else {
                0
            }
        );
    } else {
        assert!(report.get("congestion").is_none());
    }
    rules.finish();
    if let Some(evidence) = evidence {
        evidence.finish(&report, &rule_counters);
    }
    eprintln!(
        "ECN path verified: {} {ip} key_mode={mode}, {COUNT} packet pairs",
        case.name
    );
}

#[test]
#[ignore = "requires a private network namespace, nftables and CAP_NET_RAW/NET_ADMIN"]
fn kernel_rewrites_match_captured_packets_and_directional_reports() {
    assert_eq!(std::env::var("STAMP_ECN_NETNS_TESTS").as_deref(), Ok("1"));
    let parent =
        std::env::var("STAMP_PARENT_NETNS").expect("parent namespace identity is required");
    assert!(parent.starts_with("net:[") && parent.ends_with(']'));
    assert_ne!(
        std::fs::read_link("/proc/self/ns/net").unwrap(),
        std::path::PathBuf::from(parent),
        "requires a private network namespace"
    );
    assert!(Command::new("ip")
        .args(["link", "set", "lo", "up"])
        .status()
        .unwrap()
        .success());
    for ip in ["127.0.0.1", "::1"] {
        for mode in 0..3 {
            for (name, requested, forward, reverse, denied) in [
                ("preserved", 2, None, None, false),
                ("forward-bleached", 2, Some(0), None, false),
                ("reverse-bleached", 2, None, Some(0), false),
                ("forward-ce", 2, Some(3), None, false),
                ("reverse-ce", 1, None, Some(3), false),
                ("ect-swap", 2, Some(1), Some(1), false),
                ("already-ce", 3, None, None, false),
                ("not-ect-to-ce", 0, Some(3), Some(3), false),
                ("ce-cleared", 3, Some(0), Some(0), false),
                ("opposite-directions", 2, Some(0), Some(3), false),
                ("policy-refused", 2, None, None, true),
                ("refused-then-ce", 2, None, Some(3), true),
            ] {
                trial(
                    ip,
                    mode,
                    Case {
                        name,
                        requested,
                        forward,
                        reverse,
                        denied,
                    },
                );
            }
        }
    }
}
