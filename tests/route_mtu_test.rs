//! Run in an isolated user/network namespace; no host route or MTU is changed.
//! STAMP_MTU_NETNS_TESTS=1 unshare -Urn cargo test --test route_mtu_test -- --ignored --nocapture
#![cfg(all(
    target_os = "linux",
    any(feature = "ttl-nix", not(feature = "ttl-pnet"))
))]
use stamp_suite::{
    crypto::{compute_packet_hmac, HmacKey},
    tlv::ReturnPathTlv,
};
use std::{
    net::{IpAddr, SocketAddr, UdpSocket},
    process::{Child, Command, Stdio},
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

#[test]
#[ignore = "requires STAMP_MTU_NETNS_TESTS=1 inside unshare -Urn"]
fn live_route_mtu_changes_and_alternate_destinations() {
    assert_eq!(std::env::var("STAMP_MTU_NETNS_TESTS").as_deref(), Ok("1"));
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
                in_ns(&["route", "del", sender, "dev", &remote]);
                in_ns(&["route", "del", alternate, "dev", &remote]);
                eprintln!("PASS ipv6={ipv6} auth={auth} bound={bound}: link decrease/increase, route metric, alternate destination, single C response and signatures");
            }
        }
    }
}
