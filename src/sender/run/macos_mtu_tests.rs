use super::*;
use crate::net_policy::macos_mtu::IPV6_USE_MIN_MTU;
use crate::test_wire_hmac as wire_hmac;
use clap::Parser;
use nix::libc;
use std::os::fd::AsRawFd;

fn set_option(socket: &UdpSocket, option: libc::c_int, value: libc::c_int) {
    // SAFETY: The descriptor and aligned integer are live and correctly sized;
    // only this fixture's socket is changed.
    assert_eq!(
        unsafe {
            libc::setsockopt(
                socket.as_raw_fd(),
                libc::IPPROTO_IPV6,
                option,
                std::ptr::addr_of!(value).cast(),
                std::mem::size_of_val(&value) as _,
            )
        },
        0,
        "{}",
        std::io::Error::last_os_error()
    );
}

fn cap_mtu(socket: &UdpSocket, mtu: u32) {
    assert!(mtu == 0 || mtu == 1280);
    set_option(socket, IPV6_USE_MIN_MTU, i32::from(mtu == 1280));
}

fn check_fragmentation_policy(socket: &UdpSocket) {
    let mut value: libc::c_int = 0;
    let mut len = std::mem::size_of_val(&value) as libc::socklen_t;
    // SAFETY: The live descriptor and writable value/len match the ABI.
    assert_eq!(
        unsafe {
            libc::getsockopt(
                socket.as_raw_fd(),
                libc::IPPROTO_IPV6,
                libc::IPV6_DONTFRAG,
                std::ptr::addr_of_mut!(value).cast(),
                &mut len,
            )
        },
        0
    );
    assert_eq!(len as usize, std::mem::size_of_val(&value));
    assert_eq!(value, 1);
}

#[tokio::test]
async fn macos_ipv6_mtu_queries_require_supported_connected_peers() {
    for ip in ["127.0.0.1", "::1"] {
        let peer = UdpSocket::bind((ip, 0)).await.unwrap();
        let socket = UdpSocket::bind((ip, 0)).await.unwrap();
        assert_eq!(egress_mtu(&socket), None);
        socket.connect(peer.local_addr().unwrap()).await.unwrap();
        if ip == "::1" {
            let initial = egress_mtu(&socket).expect("connected IPv6 loopback MTU");
            assert!(initial > 1400);
            for minimum in [1, 0, -1] {
                set_option(&socket, IPV6_USE_MIN_MTU, minimum);
                assert_eq!(
                    egress_mtu(&socket),
                    Some(if minimum == 1 { 1280 } else { initial })
                );
            }
            // The route query cannot guarantee explicitly pinned interfaces.
            // SAFETY: The static NUL-terminated interface name outlives the call.
            let index = unsafe { libc::if_nametoindex(c"lo0".as_ptr()) };
            assert_ne!(index, 0);
            set_option(&socket, libc::IPV6_BOUND_IF, index as _);
            assert_eq!(egress_mtu(&socket), None);
        } else {
            assert_eq!(egress_mtu(&socket), None);
        }
        assert!(
            tokio::time::timeout(Duration::from_millis(10), peer.recv(&mut [0; 1]))
                .await
                .is_err(),
            "query must not send probes"
        );
    }
}

fn configuration(peer: &UdpSocket, mode: u8, padding: usize) -> Configuration {
    let mut conf = Configuration::parse_from(["test", "--hwtstamp", "off"]);
    let address = peer.local_addr().unwrap();
    conf.remote_addr = vec![address.ip()];
    conf.remote_port = address.port();
    conf.local_addr = address.ip();
    conf.local_port = 0;
    conf.reflected_fixed_hdr = vec![String::new()];
    conf.extra_padding = Some(padding);
    if mode != 0 {
        conf.hmac_key = Some("abababababababababababababababab".parse().unwrap());
    }
    if mode == 2 {
        conf.auth_mode = crate::configuration::AuthMode::Authenticated;
    }
    conf.validate().unwrap();
    conf
}

#[tokio::test]
async fn macos_ipv6_mtu_ber_initial_fit_uses_the_connected_budget() {
    let ip = "::1";
    for mode in 0..3 {
        let peer = UdpSocket::bind((ip, 0)).await.unwrap();
        let mut conf = configuration(&peer, mode, 0);
        conf.reflected_fixed_hdr.clear();
        conf.extra_padding = None;
        conf.ber = true;
        conf.ber_padding_size = 4000;
        conf.ber_pattern = Some("0102030405".into());
        conf.validate().unwrap();
        let mut sender = SenderRun::open(
            Arc::new(conf),
            SenderObservers::new(),
            CancellationToken::new(),
        )
        .await
        .unwrap();
        check_fragmentation_policy(&sender.socket);
        let mtu = egress_mtu(&sender.socket).unwrap() as usize;
        let padding = &sender
            .extra_tlvs
            .iter()
            .find(|t| t.tlv_type == TlvType::ExtraPadding)
            .unwrap()
            .value;
        let payload = sender.build_probe(0, false).len();
        let fixed = payload - padding.len() + 48;
        assert_eq!(padding.len(), 4000.min((mtu - fixed) / 5 * 5));
        for repetition in padding.chunks_exact(5) {
            assert_eq!(repetition, &[1, 2, 3, 4, 5]);
        }
        sender.send_probe(false).await.unwrap();
        let mut bytes = [0; 8192];
        let len = tokio::time::timeout(Duration::from_secs(2), peer.recv(&mut bytes))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(len, payload);
    }
}

#[tokio::test]
async fn macos_ipv6_mtu_trims_restores_and_refuses_oversize_before_send() {
    let ip = "::1";
    for mode in 0..3 {
        let peer = UdpSocket::bind((ip, 0)).await.unwrap();
        let overhead = 48;
        let base = if mode == 2 { 112 } else { 44 };
        let mac_size = if mode == 0 { 0 } else { 20 };
        // Mandatory bytes exactly fill 1280; Type 247 only fits without the minimum-MTU cap.
        let padding = 1280 - overhead - base - mac_size - 4;
        let mut sender = SenderRun::open(
            Arc::new(configuration(&peer, mode, padding)),
            SenderObservers::new(),
            CancellationToken::new(),
        )
        .await
        .unwrap();
        check_fragmentation_policy(&sender.socket);
        for (seq, cap) in [0, 1280, 0].into_iter().enumerate() {
            cap_mtu(&sender.socket, cap);
            sender.send_probe(false).await.unwrap();
            let mut bytes = [0; 2048];
            let len = tokio::time::timeout(Duration::from_secs(2), peer.recv(&mut bytes))
                .await
                .unwrap()
                .unwrap();
            let bytes = &bytes[..len];
            assert_eq!(&bytes[..4], &(seq as u32).to_be_bytes());
            assert!(len + overhead <= egress_mtu(&sender.socket).unwrap() as usize);
            if mode == 2 {
                assert_eq!(
                    &bytes[96..112],
                    &wire_hmac::digest(&[0xab; 16], &bytes[..96])
                );
            }
            let mut pos = base;
            let mut kinds = Vec::new();
            while pos < len {
                assert!(pos + 4 <= len);
                assert_eq!(bytes[pos], 0x80);
                let kind = bytes[pos + 1];
                let end =
                    pos + 4 + usize::from(u16::from_be_bytes([bytes[pos + 2], bytes[pos + 3]]));
                assert!(end <= len);
                if kind == 8 {
                    assert_eq!(end, len);
                    let covered = [&bytes[..4], &bytes[base..pos]].concat();
                    assert_eq!(
                        &bytes[pos + 4..end],
                        &wire_hmac::digest(&[0xab; 16], &covered)
                    );
                }
                if kind == 1 {
                    assert_eq!(end - pos - 4, padding);
                }
                kinds.push(kind);
                pos = end;
            }
            assert_eq!(
                kinds.iter().filter(|&&k| k == 247).count(),
                usize::from(cap == 0)
            );
            assert_eq!(
                kinds.iter().filter(|&&k| k == 8).count(),
                usize::from(mode != 0)
            );
            assert_eq!(kinds.iter().filter(|&&k| k == 1).count(), 1);
        }
        // Increase mandatory bytes by one without changing the kernel cap:
        // the send must fail before counters/pending state are changed.
        cap_mtu(&sender.socket, 1280);
        sender
            .header_template
            .as_mut()
            .unwrap()
            .iter_mut()
            .find(|t| t.tlv_type == TlvType::ExtraPadding)
            .unwrap()
            .value
            .push(0);
        let pending = sender.pending.len();
        let error = sender.send_probe(false).await.unwrap_err();
        assert!(
            matches!(error, crate::StartupError::Config(ref message) if message.contains("route MTU"))
        );
        assert_eq!(sender.packets_sent, 3);
        assert_eq!(sender.pending.len(), pending);
        assert_eq!(sender.consecutive_send_errors, 0);
        assert!(
            tokio::time::timeout(Duration::from_millis(10), peer.recv(&mut [0; 2048]))
                .await
                .is_err()
        );
        // Losing the connected budget must refuse further probes too.
        // Policy readback is not proof of physical fragmentation behavior.
        sender.socket = UdpSocket::bind((ip, 0)).await.unwrap();
        let error = sender.send_probe(false).await.unwrap_err();
        assert!(
            matches!(error, crate::StartupError::Config(ref message) if message.contains("route MTU"))
        );
        assert_eq!(sender.packets_sent, 3);
        assert_eq!(sender.pending.len(), pending);
    }
}
