//! Independent loopback peer for draft ext-hdr-13 header and state policy.
#![cfg(target_os = "linux")]
use nix::{
    libc,
    sys::socket::{recvmsg, ControlMessageOwned, MsgFlags, SockaddrStorage},
};
use std::{
    io::IoSliceMut,
    net::UdpSocket,
    os::fd::AsRawFd,
    process::{Child, Command, Stdio},
    time::Duration,
};

struct Process(Option<Child>);
impl Drop for Process {
    fn drop(&mut self) {
        if let Some(child) = &mut self.0 {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}
fn socket(ip: &str) -> UdpSocket {
    let socket = UdpSocket::bind((ip, 0)).unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    let (level, option) = if ip.contains(':') {
        (libc::IPPROTO_IPV6, libc::IPV6_RECVHOPLIMIT)
    } else {
        (libc::IPPROTO_IP, libc::IP_RECVTTL)
    };
    let on: libc::c_int = 1;
    // SAFETY: live socket and correctly sized c_int option.
    assert_eq!(
        unsafe {
            libc::setsockopt(
                socket.as_raw_fd(),
                level,
                option,
                std::ptr::addr_of!(on).cast(),
                std::mem::size_of_val(&on) as _,
            )
        },
        0
    );
    socket
}
fn receive(socket: &UdpSocket) -> (Vec<u8>, std::net::SocketAddr, i32) {
    let mut bytes = [0; 4096];
    let mut iov = [IoSliceMut::new(&mut bytes)];
    let mut control = nix::cmsg_space!(libc::c_int);
    let msg = recvmsg::<SockaddrStorage>(
        socket.as_raw_fd(),
        &mut iov,
        Some(&mut control),
        MsgFlags::empty(),
    )
    .unwrap();
    let address = msg.address.unwrap();
    let peer = if let Some(a) = address.as_sockaddr_in() {
        (*a).into()
    } else {
        (*address.as_sockaddr_in6().unwrap()).into()
    };
    let hops = msg
        .cmsgs()
        .unwrap()
        .find_map(|c| match c {
            ControlMessageOwned::Ipv4Ttl(n) | ControlMessageOwned::Ipv6HopLimit(n) => Some(n),
            _ => None,
        })
        .unwrap();
    let len = msg.bytes;
    (bytes[..len].to_vec(), peer, hops)
}
fn reflected(request: &[u8]) -> Vec<u8> {
    let mut reply = vec![0; 44];
    reply[..16].copy_from_slice(&request[..16]);
    reply[16..24].copy_from_slice(&request[4..12]);
    reply[24..38].copy_from_slice(&request[..14]);
    reply[40] = 254;
    reply
}
#[test]
fn sender_random_ports_hops_and_state_notifications_over_both_families() {
    for ip in ["127.0.0.1", "::1"] {
        let peer = socket(ip);
        let mut child = Process(Some(
            Command::new(env!("CARGO_BIN_EXE_stamp-suite"))
                .args([
                    "--remote-addr",
                    ip,
                    "--local-addr",
                    ip,
                    "--remote-port",
                    &peer.local_addr().unwrap().port().to_string(),
                    "--count",
                    "12",
                    "--send-delay",
                    "250",
                    "--timeout",
                    "1",
                    "--session-loss-threshold",
                    "2",
                    "--ssid",
                    "77",
                    "--output-format",
                    "json",
                ])
                .env("RUST_LOG", "info")
                .env("TOKIO_WORKER_THREADS", "2")
                .env_remove("STAMP_HMAC_KEY")
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap(),
        ));
        for ordinal in 0..12 {
            let (request, source, hops) = receive(&peer);
            assert_eq!(hops, 255);
            assert!((49152..=65535).contains(&source.port()));
            assert_ne!(source.port(), peer.local_addr().unwrap().port());
            if ordinal == 0 || ordinal >= 8 {
                peer.send_to(&reflected(&request), source).unwrap();
            } else {
                // A well-framed reply from the right endpoint with the wrong
                // session must not reset the consecutive-loss notification.
                let mut wrong = reflected(&request);
                wrong[15] = 78;
                peer.send_to(&wrong, source).unwrap();
            }
        }
        let output = child.0.take().unwrap().wait_with_output().unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let summary: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        let state = &summary["measurements"]["session_state"];
        assert_eq!(state["state"], "idle");
        assert_eq!(state["active_notifications"], 2);
        assert_eq!(state["failed_notifications"], 1);
        assert_eq!(state["idle_notifications"], 1);
        let logs = String::from_utf8_lossy(&output.stderr);
        assert!(logs.contains("STAMP session state changed"));
    }
}
#[test]
#[cfg(any(feature = "ttl-nix", not(feature = "ttl-pnet")))]
fn reflector_transmits_255_and_accepts_lower_received_hops() {
    for ip in ["127.0.0.1", "::1"] {
        let peer = socket(ip);
        let reference = socket(ip);
        let address = reference.local_addr().unwrap();
        drop(reference);
        let mut child = Process(Some(
            Command::new(env!("CARGO_BIN_EXE_stamp-suite"))
                .args([
                    "--is-reflector",
                    "--local-addr",
                    ip,
                    "--local-port",
                    &address.port().to_string(),
                ])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .unwrap(),
        ));
        let sock = socket2::SockRef::from(&peer);
        if ip.contains(':') {
            sock.set_unicast_hops_v6(37).unwrap();
        } else {
            sock.set_ttl_v4(37).unwrap();
        }
        peer.set_read_timeout(Some(Duration::from_millis(100)))
            .unwrap();
        let mut request = vec![0; 44];
        request[12..14].copy_from_slice(&1u16.to_be_bytes());
        let mut ready = false;
        for _ in 0..30 {
            peer.send_to(&request, address).unwrap();
            let mut buf = [0; 512];
            if peer.peek_from(&mut buf).is_ok() {
                ready = true;
                break;
            }
            assert!(child.0.as_mut().unwrap().try_wait().unwrap().is_none());
        }
        assert!(ready, "reflector did not reply");
        let (reply, source, hops) = receive(&peer);
        assert_eq!(source, address);
        assert_eq!(hops, 255);
        assert_eq!(reply[40], 37);
    }
}

#[test]
fn access_report_retry_phase_drives_state_deadlines() {
    let peer = socket("127.0.0.1");
    let mut child = Process(Some(
        Command::new(env!("CARGO_BIN_EXE_stamp-suite"))
            .args([
                "--remote-addr",
                "127.0.0.1",
                "--local-addr",
                "127.0.0.1",
                "--remote-port",
                &peer.local_addr().unwrap().port().to_string(),
                "--count",
                "1",
                "--send-delay",
                "100",
                "--timeout",
                "1",
                "--session-loss-threshold",
                "1",
                "--access-report",
                "1",
                "--access-report-timeout",
                "1",
                "--access-report-retries",
                "3",
                "--output-format",
                "json",
            ])
            .env("TOKIO_WORKER_THREADS", "2")
            .env_remove("STAMP_HMAC_KEY")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap(),
    ));
    for n in 0..4 {
        let (request, source, _) = receive(&peer);
        // Reply without acknowledging the Access Report, then lose two retries.
        if n < 2 {
            peer.send_to(&reflected(&request), source).unwrap();
        }
    }
    let output = child.0.take().unwrap().wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let summary: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(
        summary["measurements"]["session_state"]["failed_notifications"],
        1
    );
    assert_eq!(summary["measurements"]["session_state"]["state"], "idle");
}
