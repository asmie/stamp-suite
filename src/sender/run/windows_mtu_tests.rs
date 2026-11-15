use super::*;
use clap::Parser;
use std::os::windows::io::AsRawSocket;
use windows_sys::Win32::Networking::WinSock::{
    getsockopt, setsockopt, WSAGetLastError, IPPROTO_IP, IPPROTO_IPV6, IPV6_DONTFRAG,
    IPV6_MTU_DISCOVER, IPV6_USER_MTU, IP_DONTFRAGMENT, IP_MTU_DISCOVER, IP_PMTUDISC_DO,
    IP_USER_MTU,
};

use crate::test_wire_hmac as wire_hmac;

fn cap_mtu(socket: &UdpSocket, ipv6: bool, mtu: u32) {
    let (level, option) = if ipv6 {
        (IPPROTO_IPV6, IPV6_USER_MTU)
    } else {
        (IPPROTO_IP, IP_USER_MTU)
    };
    // SAFETY: the live socket and DWORD remain valid for the call; the supplied
    // size is exact. This changes only this fixture's socket, never host routes.
    let result = unsafe {
        setsockopt(
            socket.as_raw_socket() as _,
            level,
            option,
            std::ptr::addr_of!(mtu).cast(),
            std::mem::size_of_val(&mtu) as i32,
        )
    };
    // SAFETY: WSAGetLastError has no preconditions.
    assert_eq!(result, 0, "Winsock error {}", unsafe { WSAGetLastError() });
}

fn check_fragmentation_policy(socket: &UdpSocket, ipv6: bool) {
    let (level, discovery, dont_fragment) = if ipv6 {
        (IPPROTO_IPV6, IPV6_MTU_DISCOVER, IPV6_DONTFRAG)
    } else {
        (IPPROTO_IP, IP_MTU_DISCOVER, IP_DONTFRAGMENT)
    };
    for (option, expected) in [(discovery, IP_PMTUDISC_DO as u32), (dont_fragment, 1)] {
        let mut value = 0u32;
        let mut len = std::mem::size_of_val(&value) as i32;
        // SAFETY: the socket owns the handle and value/len are live, aligned
        // locals; len describes the exact DWORD buffer available to Winsock.
        let result = unsafe {
            getsockopt(
                socket.as_raw_socket() as _,
                level,
                option,
                std::ptr::addr_of_mut!(value).cast(),
                &mut len,
            )
        };
        assert_eq!(result, 0);
        assert_eq!(len as usize, std::mem::size_of_val(&value));
        assert_eq!(value, expected);
    }
}

#[tokio::test]
async fn windows_mtu_queries_refresh_caps_and_require_a_connected_peer() {
    for ip in ["127.0.0.1", "::1", "::ffff:127.0.0.1"] {
        let mapped = ip.starts_with("::ffff:");
        let peer = UdpSocket::bind((if mapped { "127.0.0.1" } else { ip }, 0))
            .await
            .unwrap();
        let socket = if mapped {
            let socket = socket2::Socket::new(
                socket2::Domain::IPV6,
                socket2::Type::DGRAM,
                Some(socket2::Protocol::UDP),
            )
            .unwrap();
            socket.set_only_v6(false).unwrap();
            socket
                .bind(&"[::]:0".parse::<SocketAddr>().unwrap().into())
                .unwrap();
            socket.set_nonblocking(true).unwrap();
            UdpSocket::from_std(socket.into()).unwrap()
        } else {
            UdpSocket::bind((ip, 0)).await.unwrap()
        };
        assert_eq!(egress_mtu(&socket), None);
        socket
            .connect((ip, peer.local_addr().unwrap().port()))
            .await
            .unwrap();
        let initial = egress_mtu(&socket).expect("connected loopback MTU");
        assert!(initial >= 1400);
        for cap in [1280, 1400, u32::MAX] {
            cap_mtu(&socket, ip == "::1", cap);
            assert_eq!(egress_mtu(&socket), Some(initial.min(cap)), "{ip}");
        }
        assert!(
            tokio::time::timeout(Duration::from_millis(10), peer.recv(&mut [0; 1]))
                .await
                .is_err(),
            "query must not transmit probes"
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
async fn windows_mtu_ber_initial_fit_uses_the_connected_budget() {
    for ip in ["127.0.0.1", "::1"] {
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
            check_fragmentation_policy(&sender.socket, ip == "::1");
            let mtu = egress_mtu(&sender.socket).unwrap() as usize;
            let padding = &sender
                .extra_tlvs
                .iter()
                .find(|t| t.tlv_type == TlvType::ExtraPadding)
                .unwrap()
                .value;
            let payload = sender.build_probe(0, false).len();
            let fixed = payload - padding.len() + if ip == "::1" { 48 } else { 28 };
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
}

#[tokio::test]
async fn windows_mtu_trims_restores_and_refuses_oversize_before_send() {
    for ip in ["127.0.0.1", "::1"] {
        for mode in 0..3 {
            let peer = UdpSocket::bind((ip, 0)).await.unwrap();
            let ipv6 = ip == "::1";
            let overhead = if ipv6 { 48 } else { 28 };
            let base = if mode == 2 { 112 } else { 44 };
            let mac_size = if mode == 0 { 0 } else { 20 };
            // Mandatory bytes exactly fill 1280; Type 247 only fits at 1400.
            let padding = 1280 - overhead - base - mac_size - 4;
            let mut sender = SenderRun::open(
                Arc::new(configuration(&peer, mode, padding)),
                SenderObservers::new(),
                CancellationToken::new(),
            )
            .await
            .unwrap();
            check_fragmentation_policy(&sender.socket, ipv6);
            for (seq, cap) in [1400, 1280, 1400].into_iter().enumerate() {
                cap_mtu(&sender.socket, ipv6, cap);
                sender.send_probe(false).await.unwrap();
                let mut bytes = [0; 2048];
                let len = tokio::time::timeout(Duration::from_secs(2), peer.recv(&mut bytes))
                    .await
                    .unwrap()
                    .unwrap();
                let bytes = &bytes[..len];
                assert_eq!(&bytes[..4], &(seq as u32).to_be_bytes());
                assert!(len + overhead <= cap as usize);
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
                    usize::from(cap == 1400)
                );
                assert_eq!(
                    kinds.iter().filter(|&&k| k == 8).count(),
                    usize::from(mode != 0)
                );
                assert_eq!(kinds.iter().filter(|&&k| k == 1).count(), 1);
            }
            // Increase mandatory bytes by one without changing the kernel cap:
            // the send must fail before counters/pending state are changed.
            cap_mtu(&sender.socket, ipv6, 1280);
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
            // Native loopback can bypass datagram MTU enforcement, so the
            // policy is read back above rather than treating it as wire proof.
            sender.socket = UdpSocket::bind((ip, 0)).await.unwrap();
            let error = sender.send_probe(false).await.unwrap_err();
            assert!(
                matches!(error, crate::StartupError::Config(ref message) if message.contains("route MTU"))
            );
            assert_eq!(sender.packets_sent, 3);
            assert_eq!(sender.pending.len(), pending);
        }
    }
}
