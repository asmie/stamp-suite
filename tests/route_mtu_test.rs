//! Run in an isolated user/network namespace; no host route or MTU is changed.
//! STAMP_MTU_NETNS_TESTS=1 unshare -Urn cargo test --test route_mtu_test -- --ignored --nocapture
#![cfg(all(
    target_os = "linux",
    any(feature = "ttl-nix", not(feature = "ttl-pnet"))
))]
use clap::Parser;
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use stamp_suite::{
    configuration::Configuration,
    crypto::{compute_packet_hmac, HmacKey},
    sender::{self, SenderObserver, SenderObservers},
    shutdown::CancellationToken,
    stats::{OutputFormat, StatsOutput},
    tlv::{ReturnPathTlv, TypedTlv},
};
use std::{
    net::{IpAddr, SocketAddr, UdpSocket},
    process::{Child, Command, Stdio},
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};

struct Process(Child);
impl Drop for Process {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
struct Link {
    name: String,
}
impl Drop for Link {
    fn drop(&mut self) {
        let _ = Command::new("ip")
            .args(["link", "del", &self.name])
            .output();
    }
}
fn run(command: &mut Command) {
    let result = command.output().unwrap();
    assert!(
        result.status.success(),
        "{command:?}: {}",
        String::from_utf8_lossy(&result.stderr)
    );
}
fn packet(auth: bool, seq: u32, size: u16, alternate: Option<IpAddr>) -> Vec<u8> {
    let base = if auth { 112 } else { 44 };
    let mut data = vec![0; base];
    data[..4].copy_from_slice(&seq.to_be_bytes());
    let error = if auth { 24 } else { 12 };
    data[error + 1] = 1;
    data[error + 2..error + 4].copy_from_slice(&42u16.to_be_bytes());
    if size != 0 {
        data.extend_from_slice(&[0x80, 12, 0, 12]);
        data.extend_from_slice(&size.to_be_bytes());
        data.extend_from_slice(&[0, 3]);
        data.extend_from_slice(&1_000_000u32.to_be_bytes());
        data.extend_from_slice(&[0; 4]);
        if let Some(ip) = alternate {
            data.extend(ReturnPathTlv::with_return_address(ip).to_raw().to_bytes());
        }
        if auth {
            let mut input = data[..4].to_vec();
            input.extend_from_slice(&data[base..]);
            data.extend_from_slice(&[0x80, 8, 0, 16]);
            data.extend_from_slice(&HmacKey::new(vec![0xAB; 16]).unwrap().compute(&input));
        }
    }
    if auth {
        let mac = compute_packet_hmac(&HmacKey::new(vec![0xAB; 16]).unwrap(), &data, 96);
        data[96..112].copy_from_slice(&mac);
    }
    data
}
fn exchange(
    socket: &UdpSocket,
    receiver: &UdpSocket,
    destination: SocketAddr,
    request: &[u8],
    auth: bool,
    length: usize,
) {
    receiver
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    socket.send_to(request, destination).unwrap();
    let mut bytes = [0; 2048];
    let (len, _) = receiver.recv_from(&mut bytes).unwrap();
    let bytes = &bytes[..len];
    assert_eq!(len, length);
    let base = if auth { 112 } else { 44 };
    assert_eq!(bytes[base] & 0xf0, 0x10, "Type 12 must have only C set");
    let mut pos = base;
    while pos < len {
        let size = u16::from_be_bytes([bytes[pos + 2], bytes[pos + 3]]) as usize;
        assert!(pos + 4 + size <= len);
        if bytes[pos + 1] == 10 {
            assert_eq!(bytes[pos] & 0xe0, 0, "alternate route must succeed");
        }
        if bytes[pos + 1] == 8 {
            let mut input = bytes[..4].to_vec();
            input.extend_from_slice(&bytes[base..pos]);
            assert_eq!(
                &bytes[pos + 4..pos + 20],
                &HmacKey::new(vec![0xAB; 16]).unwrap().compute(&input)
            );
        }
        pos += 4 + size;
    }
    if auth {
        assert_eq!(
            &bytes[96..112],
            &compute_packet_hmac(&HmacKey::new(vec![0xAB; 16]).unwrap(), bytes, 96)
        );
    }
    receiver
        .set_read_timeout(Some(Duration::from_millis(40)))
        .unwrap();
    let err = receiver.recv_from(&mut [0; 2048]).unwrap_err();
    assert!(
        matches!(
            err.kind(),
            std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
        ),
        "{err}"
    );
}

fn single_reply_packet(auth: bool, seq: u32, tlvs: &[(u8, Vec<u8>)]) -> Vec<u8> {
    let mut data = packet(auth, seq, 0, None);
    let base = data.len();
    for (kind, value) in tlvs {
        data.extend_from_slice(&[0x80, *kind]);
        data.extend_from_slice(&(value.len() as u16).to_be_bytes());
        data.extend_from_slice(value);
    }
    if auth {
        let mut input = data[..4].to_vec();
        input.extend_from_slice(&data[base..]);
        data.extend_from_slice(&[0x80, 8, 0, 16]);
        data.extend_from_slice(&HmacKey::new(vec![0xAB; 16]).unwrap().compute(&input));
    }
    data
}

fn exchange_single_reply(
    socket: &UdpSocket,
    destination: SocketAddr,
    request: &[u8],
    auth: bool,
    cap: usize,
) -> Vec<(u8, u8, Vec<u8>)> {
    socket
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    socket.send_to(request, destination).unwrap();
    let mut bytes = [0; 2048];
    let (len, source) = socket.recv_from(&mut bytes).unwrap();
    assert_eq!(source, destination);
    assert!(
        len <= cap,
        "single reply length {len} exceeds route budget {cap}"
    );
    let bytes = &bytes[..len];
    let base = if auth { 112 } else { 44 };
    let key = HmacKey::new(vec![0xAB; 16]).unwrap();
    if auth {
        assert_eq!(&bytes[96..112], &compute_packet_hmac(&key, bytes, 96));
    }
    let mut tlvs = Vec::new();
    let mut hmac_seen = false;
    let mut pos = base;
    while pos < len {
        assert!(pos + 4 <= len);
        let size = u16::from_be_bytes([bytes[pos + 2], bytes[pos + 3]]) as usize;
        assert!(pos + 4 + size <= len);
        let kind = bytes[pos + 1];
        if kind == 8 {
            assert!(auth && !hmac_seen);
            assert_eq!(size, 16);
            let mut input = bytes[..4].to_vec();
            input.extend_from_slice(&bytes[base..pos]);
            assert_eq!(&bytes[pos + 4..pos + 4 + size], &key.compute(&input));
            hmac_seen = true;
        }
        tlvs.push((kind, bytes[pos], bytes[pos + 4..pos + 4 + size].to_vec()));
        pos += 4 + size;
    }
    assert_eq!(hmac_seen, auth);
    socket
        .set_read_timeout(Some(Duration::from_millis(40)))
        .unwrap();
    let error = socket
        .recv_from(&mut [0; 2048])
        .expect_err("extra single reply");
    assert!(matches!(
        error.kind(),
        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
    ));
    tlvs
}

#[test]
#[ignore = "requires STAMP_MTU_NETNS_TESTS=1 inside unshare -Urn"]
fn live_route_mtu_changes_and_alternate_destinations() {
    assert_eq!(std::env::var("STAMP_MTU_NETNS_TESTS").as_deref(), Ok("1"));
    // SAFETY: geteuid(2) takes no arguments, always succeeds and touches no
    // caller memory.
    assert_eq!(unsafe { libc::geteuid() }, 0, "run inside unshare -Urn");
    let holder = Process(
        Command::new("unshare")
            .args(["--net", "sleep", "120"])
            .spawn()
            .unwrap(),
    );
    let ns = format!("/proc/{}/ns/net", holder.0.id());
    let original = std::fs::read_link("/proc/self/ns/net").unwrap();
    let start = Instant::now();
    while std::fs::read_link(&ns).unwrap() == original {
        assert!(start.elapsed() < Duration::from_secs(3));
        std::thread::sleep(Duration::from_millis(5));
    }
    let local = format!("mtus{}", std::process::id());
    let remote = format!("mtur{}", std::process::id());
    run(Command::new("ip").args([
        "link", "add", &local, "type", "veth", "peer", "name", &remote,
    ]));
    let _link = Link {
        name: local.clone(),
    };
    run(Command::new("ip").args(["link", "set", &remote, "netns", &holder.0.id().to_string()]));
    let in_ns = |args: &[&str]| {
        run(Command::new("nsenter")
            .arg(format!("--net={ns}"))
            .arg("ip")
            .args(args));
    };
    in_ns(&["link", "set", "lo", "up"]);
    in_ns(&["link", "set", &remote, "up"]);
    run(Command::new("ip").args(["link", "set", &local, "up"]));
    for address in [
        "192.0.2.1/24",
        "192.0.2.3/24",
        "2001:db8::1/64",
        "2001:db8::3/64",
    ] {
        run(Command::new("ip").args(["addr", "add", address, "dev", &local, "nodad"]));
    }
    for address in ["192.0.2.2/24", "2001:db8::2/64"] {
        in_ns(&["addr", "add", address, "dev", &remote, "nodad"]);
    }
    for ipv6 in [false, true] {
        let peer: IpAddr = if ipv6 { "2001:db8::2" } else { "192.0.2.2" }
            .parse()
            .unwrap();
        let sender = if ipv6 {
            "2001:db8::1/128"
        } else {
            "192.0.2.1/32"
        };
        let alternate = if ipv6 { "2001:db8::3" } else { "192.0.2.3" };
        let wildcard: IpAddr = if ipv6 { "::" } else { "0.0.0.0" }.parse().unwrap();
        // IP header plus 8-byte UDP header.
        let overhead = if ipv6 { 48 } else { 28 };
        for auth in [false, true] {
            for bound in [false, true] {
                in_ns(&["link", "set", &remote, "mtu", "1500"]);
                let mut command = Command::new("nsenter");
                command
                    .arg(format!("--net={ns}"))
                    .arg(env!("CARGO_BIN_EXE_stamp-suite"))
                    .args([
                        "--is-reflector",
                        "--hwtstamp",
                        "off",
                        "--local-addr",
                        &if bound { peer } else { wildcard }.to_string(),
                        "--local-port",
                        "4862",
                        "--reflected-control-max-count",
                        "16",
                        "--return-path-allow-alternate",
                    ]);
                if auth {
                    command.args([
                        "--auth-mode",
                        "A",
                        "--hmac-key",
                        "abababababababababababababababab",
                    ]);
                }
                let mut reflector = Process(
                    command
                        .stdout(Stdio::null())
                        .stderr(Stdio::null())
                        .spawn()
                        .unwrap(),
                );
                let destination = SocketAddr::new(peer, 4862);
                let sender_ip = sender.split('/').next().unwrap().parse().unwrap();
                let socket = UdpSocket::bind(SocketAddr::new(sender_ip, 0)).unwrap();
                let alternate_socket = UdpSocket::bind(SocketAddr::new(
                    alternate.parse().unwrap(),
                    socket.local_addr().unwrap().port(),
                ))
                .unwrap();
                socket
                    .set_read_timeout(Some(Duration::from_millis(40)))
                    .unwrap();
                let started = Instant::now();
                loop {
                    assert!(reflector.0.try_wait().unwrap().is_none());
                    socket
                        .send_to(&packet(auth, 0, 0, None), destination)
                        .unwrap();
                    if socket.recv_from(&mut [0; 256]).is_ok() {
                        break;
                    }
                    assert!(
                        started.elapsed() < Duration::from_secs(5),
                        "reflector did not start"
                    );
                }
                exchange(
                    &socket,
                    &socket,
                    destination,
                    &packet(auth, 1, 1500, None),
                    auth,
                    1500 - overhead,
                );
                in_ns(&["link", "set", &remote, "mtu", "1280"]);
                exchange(
                    &socket,
                    &socket,
                    destination,
                    &packet(auth, 2, 1500, None),
                    auth,
                    1280 - overhead,
                );
                in_ns(&["link", "set", &remote, "mtu", "1500"]);
                std::thread::sleep(Duration::from_millis(270));
                exchange(
                    &socket,
                    &socket,
                    destination,
                    &packet(auth, 3, 1500, None),
                    auth,
                    1500 - overhead,
                );
                in_ns(&["route", "replace", sender, "dev", &remote, "mtu", "1400"]);
                exchange(
                    &socket,
                    &socket,
                    destination,
                    &packet(auth, 4, 1500, None),
                    auth,
                    1400 - overhead,
                );
                in_ns(&["route", "replace", alternate, "dev", &remote, "mtu", "1280"]);
                exchange(
                    &socket,
                    &alternate_socket,
                    destination,
                    &packet(auth, 5, 1500, Some(alternate.parse().unwrap())),
                    auth,
                    1280 - overhead,
                );
                // Requests fit the 1500-byte forward link, while the reflector's
                // route back to this sender is still limited to 1400 bytes.
                // Neither request carries Type 12: each must size its only reply.
                let cap = 1400 - overhead;
                let base = if auth { 112 } else { 44 };
                let hmac_size = if auth { 20 } else { 0 };
                let padding_size = (cap + 40 - base - hmac_size - 24) / 4 * 4;
                let ber_request = single_reply_packet(
                    auth,
                    6,
                    &[
                        (
                            243,
                            vec![0, 0, 0, 0, 0, 0, 0, 0, 0x80, 241, 0, 4, 255, 0, 255, 0],
                        ),
                        (1, [0xFF, 0, 0xFF, 0].repeat(padding_size / 4)),
                    ],
                );
                let ber = exchange_single_reply(&socket, destination, &ber_request, auth, cap);
                let kinds: Vec<_> = ber.iter().map(|(kind, _, _)| *kind).collect();
                assert_eq!(
                    kinds
                        .iter()
                        .filter(|&&kind| kind != 8)
                        .copied()
                        .collect::<Vec<_>>(),
                    [243, 1]
                );
                for (kind, flags, value) in &ber {
                    match kind {
                        243 => assert_eq!(*flags, 0x10, "trimmed BER metadata needs C"),
                        1 => {
                            assert!(
                                !value.is_empty()
                                    && value.len() < padding_size
                                    && value.len().is_multiple_of(4)
                            );
                            assert_eq!(value, &[0xFF, 0].repeat(value.len() / 2));
                        }
                        _ => {}
                    }
                }
                let padding = vec![0x5A; cap - base - hmac_size - 12];
                let header_request = single_reply_packet(
                    auth,
                    7,
                    &[
                        (3, vec![0; 4]),
                        (1, padding.clone()),
                        (247, vec![0; 20]),
                        (246, vec![0; 8]),
                    ],
                );
                let headers =
                    exchange_single_reply(&socket, destination, &header_request, auth, cap);
                assert_eq!(
                    headers
                        .iter()
                        .map(|(kind, _, _)| *kind)
                        .filter(|&kind| kind != 8)
                        .collect::<Vec<_>>(),
                    [3, 1]
                );
                assert_eq!(headers[1].2, padding, "mandatory padding stays intact");
                in_ns(&["route", "del", sender, "dev", &remote]);
                in_ns(&["route", "del", alternate, "dev", &remote]);
                eprintln!("PASS ipv6={ipv6} auth={auth} bound={bound}: link decrease/increase, route metric, alternate destination, single C response, single BER/header reply fitting and signatures");
            }
        }
    }
}

// The observer changes the real interface budget synchronously after a
// successful send. This orders each MTU change before the next probe without
// relying on a race between a timer and a receiving test task.
struct SenderMtuSteps {
    next: Vec<usize>,
    sent: AtomicUsize,
}
impl SenderObserver for SenderMtuSteps {
    fn probe_sent(&self) {
        let index = self.sent.fetch_add(1, Ordering::SeqCst);
        if let Some(mtu) = self.next.get(index) {
            loopback_mtu(*mtu);
        }
    }
}

fn loopback_mtu(mtu: usize) {
    run(Command::new("ip").args(["link", "set", "lo", "mtu", &mtu.to_string(), "up"]));
}

fn sender_mtu_conf(address: SocketAddr, mode: u8, padding: usize, count: u32) -> Configuration {
    let mut conf = Configuration::parse_from([
        "test",
        "--hwtstamp",
        "off",
        "--send-delay",
        "2ms",
        "--timeout",
        "0",
    ]);
    conf.remote_addr = vec![address.ip()];
    conf.remote_port = address.port();
    conf.local_addr = address.ip();
    conf.local_port = 0;
    conf.count = count;
    conf.reflected_fixed_hdr = vec![String::new()];
    if address.is_ipv6() {
        // The actual Hop-by-Hop header remains on the packet even when its
        // reflection request has been removed. Use the default PadN header.
        conf.attach_ext_hdr = vec!["hbh".into()];
    }
    conf.extra_padding = Some(padding);
    conf.direct_measurement = true;
    conf.cos = true;
    conf.ecn = 2;
    conf.reflected_control_count = 2; // AIMD rebuilds Type 12 per probe.
    conf.reflected_control_interval_ns = 1_000_000;
    if mode != 0 {
        conf.hmac_key = Some("abababababababababababababababab".parse().unwrap());
    }
    if mode == 2 {
        conf.tlv_hmac = stamp_suite::configuration::TlvHmacMode::Off;
    }
    if mode == 3 {
        conf.auth_mode = stamp_suite::configuration::AuthMode::Authenticated;
    }
    conf.validate().unwrap();
    conf
}

fn independent_mac(input: &[u8]) -> Vec<u8> {
    let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(&[0xab; 16]).unwrap();
    mac.update(input);
    mac.finalize().into_bytes()[..16].to_vec()
}

fn sender_wire_tlvs(bytes: &[u8], mode: u8, seq: u32) -> Vec<(u8, Vec<u8>)> {
    assert_eq!(&bytes[..4], &seq.to_be_bytes());
    let base = if mode == 3 { 112 } else { 44 };
    if mode == 3 {
        assert_eq!(&bytes[96..112], independent_mac(&bytes[..96]));
    }
    let mut pos = base;
    let mut tlvs = Vec::new();
    while pos < bytes.len() {
        assert!(pos + 4 <= bytes.len());
        let size = u16::from_be_bytes([bytes[pos + 2], bytes[pos + 3]]) as usize;
        assert!(pos + 4 + size <= bytes.len());
        assert_eq!(bytes[pos], 0x80, "sender flags must be U only");
        let kind = bytes[pos + 1];
        let value = &bytes[pos + 4..pos + 4 + size];
        if kind == 8 {
            assert!(mode == 1 || mode == 3);
            assert_eq!(pos + 4 + size, bytes.len(), "HMAC must stay last");
            let mut covered = bytes[..4].to_vec();
            covered.extend_from_slice(&bytes[base..pos]);
            assert_eq!(value, independent_mac(&covered));
        }
        tlvs.push((kind, value.to_vec()));
        pos += 4 + size;
    }
    assert_eq!(
        tlvs.iter().filter(|t| t.0 == 8).count(),
        usize::from(mode == 1 || mode == 3)
    );
    tlvs
}

#[tokio::test]
#[ignore = "requires STAMP_MTU_NETNS_TESTS=1 inside unshare -Urn"]
async fn live_sender_trims_restores_and_refuses_oversized_probes() {
    assert_eq!(std::env::var("STAMP_MTU_NETNS_TESTS").as_deref(), Ok("1"));
    // SAFETY: geteuid takes no arguments and writes no caller memory.
    assert_eq!(unsafe { libc::geteuid() }, 0, "run inside unshare -Urn");
    loopback_mtu(1500);
    let output = StatsOutput::new(OutputFormat::Json).unwrap();
    for ip in ["127.0.0.1", "::1"] {
        for mode in 0..4 {
            let peer = tokio::net::UdpSocket::bind((ip, 0)).await.unwrap();
            let address = peer.local_addr().unwrap();
            let ipv6 = address.is_ipv6();
            let base = if mode == 3 { 112 } else { 44 };
            let hmac = if mode == 1 || mode == 3 { 20 } else { 0 };
            let ip_udp_ext = if ipv6 { 40 + 8 + 8 } else { 20 + 8 };
            // Non-header TLVs: CoS(8), padding header(4), DM(16), control(16).
            let padding = 1280 - ip_udp_ext - base - hmac - 8 - 4 - 16 - 16;
            let first_header = if ipv6 { 44 } else { 24 };
            let budgets = [1280, 1500, 1280 + first_header, 1280, 1500];
            loopback_mtu(budgets[0]);
            let conf = sender_mtu_conf(address, mode, padding, budgets.len() as u32);
            let changes = Arc::new(SenderMtuSteps {
                next: budgets[1..].to_vec(),
                sent: AtomicUsize::new(0),
            });
            let mut observers = SenderObservers::new();
            observers.push(changes.clone());
            let out = output.clone();
            let task = tokio::spawn(async move {
                sender::run_sender_with_output(&conf, &out, observers, CancellationToken::new())
                    .await
            });
            let mut original_padding = None;
            for (seq, budget) in budgets.into_iter().enumerate() {
                let mut bytes = [0; 2048];
                let (size, _) =
                    tokio::time::timeout(Duration::from_secs(3), peer.recv_from(&mut bytes))
                        .await
                        .unwrap()
                        .unwrap();
                assert!(
                    size + ip_udp_ext <= budget,
                    "sender exceeded {budget}-byte budget"
                );
                let tlvs = sender_wire_tlvs(&bytes[..size], mode, seq as u32);
                let mut expected = vec![4, 1];
                if budget > 1280 {
                    expected.push(247);
                    if ipv6 && budget == 1500 {
                        expected.push(246);
                    }
                }
                expected.extend([5, 12]);
                if hmac != 0 {
                    expected.push(8);
                }
                assert_eq!(
                    tlvs.iter().map(|t| t.0).collect::<Vec<_>>(),
                    expected,
                    "ip={ip} mode={mode} probe={seq}"
                );
                let padding_value = &tlvs.iter().find(|t| t.0 == 1).unwrap().1;
                assert_eq!(padding_value.len(), padding);
                if let Some(original) = &original_padding {
                    assert_eq!(padding_value, original);
                } else {
                    original_padding = Some(padding_value.clone());
                }
                for (_, value) in tlvs.iter().filter(|t| t.0 == 246 || t.0 == 247) {
                    assert!(value.iter().all(|&b| b == 0));
                }
                let dm = &tlvs.iter().find(|t| t.0 == 5).unwrap().1;
                assert_eq!(&dm[..4], &(seq as u32 + 1).to_be_bytes());
            }
            let stats = tokio::time::timeout(Duration::from_secs(3), task)
                .await
                .unwrap()
                .unwrap()
                .unwrap();
            assert_eq!(stats.packets_sent, 5);
            assert_eq!(changes.sent.load(Ordering::SeqCst), 5);

            // One mandatory octet over budget must fail before the first send,
            // and also after a previously successful probe on a larger route.
            for shrink in [false, true] {
                loopback_mtu(if shrink { 1500 } else { 1280 });
                let conf = sender_mtu_conf(address, mode, padding + 1, 2);
                let changes = Arc::new(SenderMtuSteps {
                    next: vec![1280],
                    sent: AtomicUsize::new(0),
                });
                let mut observers = SenderObservers::new();
                observers.push(changes.clone());
                let error = sender::run_sender_with_output(
                    &conf,
                    &output,
                    observers,
                    CancellationToken::new(),
                )
                .await
                .err()
                .expect("oversized mandatory packet accepted");
                assert!(error.to_string().contains("route MTU"), "{error}");
                assert_eq!(changes.sent.load(Ordering::SeqCst), usize::from(shrink));
                if shrink {
                    let mut bytes = [0; 2048];
                    let (size, _) = peer.recv_from(&mut bytes).await.unwrap();
                    assert!(size + ip_udp_ext <= 1500);
                    sender_wire_tlvs(&bytes[..size], mode, 0);
                }
                assert!(
                    tokio::time::timeout(Duration::from_millis(20), peer.recv_from(&mut [0; 2048]))
                        .await
                        .is_err(),
                    "an oversized probe was transmitted"
                );
            }
            eprintln!("PASS sender ip={ip} mode={mode}: trim/restore, order, signatures, mandatory oversize at startup and route decrease");
        }
    }
    // With only header requests, startup trimming can leave no static TLVs.
    // Keep the TLV send mode so those requests can return on a larger route.
    // IPv4 allows a small enough interface MTU to remove the only request.
    for mode in 0..4 {
        let peer = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let address = peer.local_addr().unwrap();
        let mut conf = sender_mtu_conf(address, mode, 0, 2);
        conf.extra_padding = None;
        conf.direct_measurement = false;
        conf.cos = false;
        conf.reflected_control_count = 1;
        conf.validate().unwrap();
        let hmac = if mode == 1 || mode == 3 { 20 } else { 0 };
        loopback_mtu(28 + if mode == 3 { 112 } else { 44 } + hmac);
        let changes = Arc::new(SenderMtuSteps {
            next: vec![1500],
            sent: AtomicUsize::new(0),
        });
        let mut observers = SenderObservers::new();
        observers.push(changes);
        let out = output.clone();
        let task = tokio::spawn(async move {
            sender::run_sender_with_output(&conf, &out, observers, CancellationToken::new()).await
        });
        for seq in 0..2 {
            let mut bytes = [0; 256];
            let (size, _) =
                tokio::time::timeout(Duration::from_secs(3), peer.recv_from(&mut bytes))
                    .await
                    .unwrap()
                    .unwrap();
            let tlvs = sender_wire_tlvs(&bytes[..size], mode, seq);
            let mut kinds = if seq == 0 { vec![] } else { vec![247] };
            if hmac != 0 {
                kinds.push(8);
            }
            assert_eq!(tlvs.iter().map(|t| t.0).collect::<Vec<_>>(), kinds);
        }
        tokio::time::timeout(Duration::from_secs(3), task)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        eprintln!(
            "PASS sender minimal mode={mode}: restore requests after startup removed all headers"
        );
    }
    loopback_mtu(65_536);
}
