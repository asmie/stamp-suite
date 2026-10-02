//! RFC 9503 §4.1.1 Control Code 0x1: the reply leaves on the arrival link.
//!
//! On loopback the pinned interface can carry the reply, so the Return Path
//! TLV comes back without U. Other platforms cannot pin the interface and
//! must set U instead. Runs on the socket backend; raw capture needs
//! CAP_NET_RAW (see tests/pnet_loopback_test.rs).
#![cfg(all(unix, any(feature = "ttl-nix", not(feature = "ttl-pnet"))))]
use stamp_suite::tlv::{ReturnPathTlv, TypedTlv};
use std::{
    net::UdpSocket,
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

#[test]
fn same_link_request_is_honored_or_flagged() {
    let port = UdpSocket::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let _reflector = Process(
        Command::new(env!("CARGO_BIN_EXE_stamp-suite"))
            .args([
                "-i",
                "--local-addr",
                "127.0.0.1",
                "--local-port",
                &port.to_string(),
                "--hwtstamp",
                "off",
            ])
            .env("RUST_LOG", "off")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );

    let mut request = vec![0u8; 44];
    request[3] = 1;
    let rp = ReturnPathTlv::with_control_code(0x1).to_raw().to_bytes();
    request.extend_from_slice(&rp);

    let sender = UdpSocket::bind("127.0.0.1:0").unwrap();
    sender
        .set_read_timeout(Some(Duration::from_millis(200)))
        .unwrap();
    let mut reply = [0u8; 256];
    let deadline = Instant::now() + Duration::from_secs(5);
    let len = loop {
        sender.send_to(&request, ("127.0.0.1", port)).unwrap();
        if let Ok((len, _)) = sender.recv_from(&mut reply) {
            break len;
        }
        assert!(Instant::now() < deadline, "no reply from the reflector");
    };

    assert_eq!(len, request.len());
    let flags = reply[44];
    assert_eq!(flags & 0x40, 0, "Return Path TLV must not be malformed");
    let unrecognized = flags & 0x80 != 0;
    if cfg!(target_os = "linux") {
        assert!(
            !unrecognized,
            "Linux pins the reply to the arrival interface"
        );
    } else {
        assert!(
            unrecognized,
            "without interface pinning the reflector sets U"
        );
    }
}
