//! Isolated link-local IPv6: replies, delayed bursts, alternate return and CLI zones.
//! STAMP_SCOPE_NETNS_TESTS=1 unshare -Urn cargo test --test scoped_ipv6_test -- --ignored --nocapture
#![cfg(target_os = "linux")]
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use std::{
    net::{SocketAddr, UdpSocket},
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
struct Link(String);
impl Drop for Link {
    fn drop(&mut self) {
        let _ = Command::new("ip").args(["link", "del", &self.0]).output();
    }
}
fn run(command: &mut Command) -> String {
    let output = command.output().unwrap();
    assert!(
        output.status.success(),
        "{command:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap()
}
fn mac(parts: &[&[u8]]) -> [u8; 16] {
    let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(&[0xab; 16]).unwrap();
    for part in parts {
        mac.update(part);
    }
    mac.finalize().into_bytes()[..16].try_into().unwrap()
}
fn request(auth: bool, seq: u32, burst: bool, alternate: bool) -> Vec<u8> {
    let base = if auth { 112 } else { 44 };
    let mut bytes = vec![0; base];
    bytes[..4].copy_from_slice(&seq.to_be_bytes());
    bytes[if auth { 25 } else { 13 }] = 1;
    if burst {
        bytes.extend_from_slice(&[0x80, 12, 0, 12, 1, 0, 0, 3]);
        bytes.extend_from_slice(&50_000_000u32.to_be_bytes());
        bytes.extend_from_slice(&[0; 4]);
        if alternate {
            bytes.extend(
                stamp_suite::tlv::ReturnPathTlv::with_return_address("fe80::3".parse().unwrap())
                    .to_raw()
                    .to_bytes(),
            );
        }
        if auth {
            let digest = mac(&[&bytes[..4], &bytes[base..]]);
            bytes.extend_from_slice(&[0x80, 8, 0, 16]);
            bytes.extend_from_slice(&digest);
        }
    }
    if auth {
        let digest = mac(&[&bytes[..96]]);
        bytes[96..112].copy_from_slice(&digest);
    }
    bytes
}
#[test]
#[ignore = "requires STAMP_SCOPE_NETNS_TESTS=1 inside unshare -Urn"]
fn link_local_replies_bursts_alternates_and_sender_zones() {
    assert_eq!(std::env::var("STAMP_SCOPE_NETNS_TESTS").as_deref(), Ok("1"));
    assert_eq!(unsafe { libc::geteuid() }, 0, "run inside unshare -Urn");
    let holder = Process(
        Command::new("unshare")
            .args(["--net", "sleep", "120"])
            .spawn()
            .unwrap(),
    );
    let ns = format!("/proc/{}/ns/net", holder.0.id());
    let start = Instant::now();
    while std::fs::read_link(&ns).unwrap() == std::fs::read_link("/proc/self/ns/net").unwrap() {
        assert!(start.elapsed() < Duration::from_secs(3));
        std::thread::sleep(Duration::from_millis(5));
    }
    let local = format!("scs{}", std::process::id());
    let remote = format!("scr{}", std::process::id());
    run(Command::new("ip").args([
        "link", "add", &local, "type", "veth", "peer", "name", &remote,
    ]));
    let _link = Link(local.clone());
    run(Command::new("ip").args(["link", "set", &remote, "netns", &holder.0.id().to_string()]));
    let in_ns = |args: &[&str]| {
        run(Command::new("nsenter")
            .arg(format!("--net={ns}"))
            .arg("ip")
            .args(args))
    };
    in_ns(&["link", "set", "lo", "up"]);
    in_ns(&["link", "set", &remote, "up"]);
    run(Command::new("ip").args(["link", "set", &local, "up"]));
    for addr in ["fe80::1/64", "fe80::3/64"] {
        run(Command::new("ip").args(["-6", "addr", "add", addr, "dev", &local, "nodad"]));
    }
    in_ns(&["-6", "addr", "add", "fe80::2/64", "dev", &remote, "nodad"]);
    let local_index: serde_json::Value =
        serde_json::from_str(&run(Command::new("ip").args(["-j", "link", "show", &local])))
            .unwrap();
    let index = local_index[0]["ifindex"].as_u64().unwrap() as u32;
    let remote_index: serde_json::Value =
        serde_json::from_str(&in_ns(&["-j", "link", "show", &remote])).unwrap();
    let remote_index = remote_index[0]["ifindex"].as_u64().unwrap().to_string();
    let dst: SocketAddr = format!("[fe80::2%{index}]:4862").parse().unwrap();
    for auth in [false, true] {
        for bound in [false, true] {
            // pnet selects one concrete interface; wildcard capture is unsupported.
            if !bound && cfg!(all(feature = "ttl-pnet", not(feature = "ttl-nix"))) {
                continue;
            }
            let mut command = Command::new("nsenter");
            command
                .arg(format!("--net={ns}"))
                .arg(env!("CARGO_BIN_EXE_stamp-suite"))
                .args([
                    "-i",
                    "--local-addr",
                    if bound { "fe80::2" } else { "::" },
                    "--local-port",
                    "4862",
                    "--local-scope-id",
                    if bound { &remote_index } else { "0" },
                    "--hwtstamp",
                    "off",
                    "--stateful-reflector",
                    "--return-path-allow-alternate",
                    "--reflected-control-max-count",
                    "3",
                ])
                .env_remove("STAMP_HMAC_KEY")
                .env("RUST_LOG", "debug")
                .env("TOKIO_WORKER_THREADS", "2");
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
                    .stderr(Stdio::inherit())
                    .spawn()
                    .unwrap(),
            );
            let socket = UdpSocket::bind(format!("[fe80::1%{index}]:0")).unwrap();
            socket
                .set_read_timeout(Some(Duration::from_millis(100)))
                .unwrap();
            let start = Instant::now();
            let mut bytes = [0; 2048];
            loop {
                assert!(reflector.0.try_wait().unwrap().is_none());
                socket
                    .send_to(&request(auth, 0, false, false), dst)
                    .unwrap();
                if socket.recv_from(&mut bytes).is_ok() {
                    break;
                }
                assert!(
                    start.elapsed() < Duration::from_secs(4),
                    "no scoped reply: auth={auth}, bound={bound}"
                );
            }
            // An alternate address uses the same sender port on a second local IP.
            let alternate_socket = UdpSocket::bind(format!(
                "[fe80::3%{index}]:{}",
                socket.local_addr().unwrap().port()
            ))
            .unwrap();
            for alternate in [false, true] {
                let seq: u32 = if alternate { 101 } else { 100 };
                let rx = if alternate {
                    &alternate_socket
                } else {
                    &socket
                };
                rx.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
                socket
                    .send_to(&request(auth, seq, true, alternate), dst)
                    .unwrap();
                let mut sequences = Vec::new();
                while sequences.len() < 3 {
                    let (len, source) = rx.recv_from(&mut bytes).unwrap_or_else(|e| {
                        panic!("burst auth={auth} bound={bound} alternate={alternate}: {e}")
                    });
                    assert_eq!(source, dst);
                    let echo = if auth { 48 } else { 24 };
                    if u32::from_be_bytes(bytes[echo..echo + 4].try_into().unwrap()) != seq {
                        continue;
                    }
                    let reflected = u32::from_be_bytes(bytes[..4].try_into().unwrap());
                    if sequences.contains(&reflected) {
                        continue;
                    } // raw capture may see a duplicate
                    sequences.push(reflected);
                    let base = if auth { 112 } else { 44 };
                    assert_eq!(bytes[base] & 0xf0, 0);
                    let mut pos = base;
                    while pos < len {
                        let size = u16::from_be_bytes(bytes[pos + 2..pos + 4].try_into().unwrap())
                            as usize;
                        if bytes[pos + 1] == 10 {
                            assert_eq!(bytes[pos] & 0xe0, 0, "alternate fell back");
                        }
                        if bytes[pos + 1] == 8 {
                            assert_eq!(
                                &bytes[pos + 4..pos + 20],
                                &mac(&[&bytes[..4], &bytes[base..pos]])
                            );
                        }
                        pos += 4 + size;
                    }
                    if auth {
                        assert_eq!(&bytes[96..112], &mac(&[&bytes[..96]]));
                    }
                }
                assert!(
                    sequences.windows(2).all(|w| w[1] == w[0] + 1),
                    "{sequences:?}"
                );
            }
            let mut sender = Command::new(env!("CARGO_BIN_EXE_stamp-suite"));
            sender
                .args([
                    "--local-addr",
                    "fe80::1",
                    "--local-scope-id",
                    &index.to_string(),
                    "--local-port",
                    "0",
                    "--remote-addr",
                    "fe80::2",
                    "--remote-scope-id",
                    &index.to_string(),
                    "--remote-port",
                    "4862",
                    "--count",
                    "2",
                    "--send-delay",
                    "10",
                    "--timeout",
                    "1",
                    "--hwtstamp",
                    "off",
                    "--output-format",
                    "json",
                ])
                .env_remove("STAMP_HMAC_KEY")
                .env("RUST_LOG", "off")
                .env("TOKIO_WORKER_THREADS", "2");
            if auth {
                sender.args([
                    "--auth-mode",
                    "A",
                    "--hmac-key",
                    "abababababababababababababababab",
                ]);
            }
            let stats: serde_json::Value = serde_json::from_str(&run(&mut sender)).unwrap();
            assert_eq!(stats["packets_received"], 2, "{stats}");
            println!("scoped IPv6 auth={auth} bound={bound}: bursts, alternate HMACs and CLI sender pass");
        }
    }
}
