//! IPv6 extension-header reflection (Type 246) on the nix backend, from
//! ancillary data. The sender's sticky Destination Options header needs
//! CAP_NET_RAW, so this runs in a user and network namespace:
//! STAMP_EXTHDR_NETNS_TESTS=1 unshare -Urn cargo test --test ext_hdr_nix_test -- --ignored
#![cfg(all(
    target_os = "linux",
    any(feature = "ttl-nix", not(feature = "ttl-pnet"))
))]

use std::{
    net::UdpSocket,
    os::fd::AsRawFd,
    process::{Child, Command, Stdio},
    time::Duration,
};

use stamp_suite::{
    packets::{
        ExtendedPacketUnauthenticated, ExtendedReflectedPacketUnauthenticated,
        PacketUnauthenticated,
    },
    tlv::{ReflectedFixedHdrTlv, ReflectedIpv6ExtHdrTlv, TlvList, TlvType, TypedTlv},
};

struct Process(Child);
impl Drop for Process {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
#[ignore = "needs a user and network namespace: STAMP_EXTHDR_NETNS_TESTS=1 unshare -Urn"]
fn nix_reflects_destination_options_from_ancillary_data() {
    if std::env::var_os("STAMP_EXTHDR_NETNS_TESTS").is_none() {
        eprintln!("SKIP: set STAMP_EXTHDR_NETNS_TESTS=1 and run under unshare -Urn");
        return;
    }
    let up = Command::new("ip")
        .args(["link", "set", "lo", "up"])
        .status()
        .unwrap();
    assert!(up.success());

    let port = UdpSocket::bind("[::1]:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let _reflector = Process(
        Command::new(env!("CARGO_BIN_EXE_stamp-suite"))
            .args(["--is-reflector", "--local-addr", "::1", "--local-port"])
            .arg(port.to_string())
            .env("RUST_LOG", "off")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    std::thread::sleep(Duration::from_millis(300));

    let sender = UdpSocket::bind("[::1]:0").unwrap();
    sender
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    // A 16-byte Destination Options header: Next Header (set by the kernel),
    // Hdr Ext Len 1, then a 12-byte option of the RFC 4727 experimental type
    // 0x1E, which receivers skip. Linux drops PadN longer than 7 bytes.
    let dstopts = [0u8, 1, 0x1E, 12, 0, 0, 0, 0, 11, 12, 13, 14, 15, 16, 17, 18];
    // SAFETY: live socket and a byte buffer of the given length.
    let rc = unsafe {
        libc::setsockopt(
            sender.as_raw_fd(),
            libc::IPPROTO_IPV6,
            libc::IPV6_DSTOPTS,
            dstopts.as_ptr().cast(),
            dstopts.len() as libc::socklen_t,
        )
    };
    assert_eq!(rc, 0, "IPV6_DSTOPTS: {}", std::io::Error::last_os_error());

    let mut tlvs = TlvList::new();
    tlvs.push(ReflectedFixedHdrTlv::request_with_capacity(40).to_raw())
        .unwrap();
    tlvs.push(ReflectedIpv6ExtHdrTlv::request_with_capacity(16).to_raw())
        .unwrap();
    let base = PacketUnauthenticated {
        sequence_number: 1,
        timestamp: 0xE500_0000_0000_0000,
        error_estimate: 0,
        ssid: 0,
        mbz: [0; 28],
    };
    let request = ExtendedPacketUnauthenticated::with_tlvs(base, tlvs).to_bytes();
    sender.send_to(&request, ("::1", port)).unwrap();

    let mut reply = [0u8; 2048];
    let len = sender.recv(&mut reply).expect("a reply from the reflector");
    let tlvs = ExtendedReflectedPacketUnauthenticated::from_bytes(&reply[..len])
        .unwrap()
        .tlvs;
    let ext = tlvs
        .iter()
        .find(|t| t.tlv_type == TlvType::ReflectedIpv6ExtHdr)
        .expect("Type 246 in the reply");
    assert!(!ext.flags.conformant_reflected, "ext header not reflected");
    assert_eq!(&ext.value[8..16], &dstopts[8..16]);
    // The fixed header is not visible to a UDP socket.
    let fixed = tlvs
        .iter()
        .find(|t| t.tlv_type == TlvType::ReflectedFixedHdr)
        .expect("Type 247 in the reply");
    assert!(fixed.flags.conformant_reflected);
}
