use super::*;
use crate::receiver::mtu::MtuCache;
use crate::test_wire_hmac as wire_hmac;
use crate::tlv::{ExtraPaddingTlv, ResidualBerValue, TypedTlv, RESIDUAL_BER_PATTERN_SUBTLV_TYPE};
use nix::libc;
use std::{net::UdpSocket, os::fd::AsRawFd};

fn policy(socket: &UdpSocket, option: libc::c_int) -> i32 {
    let mut value: libc::c_int = -1;
    let mut len = std::mem::size_of_val(&value) as libc::socklen_t;
    // SAFETY: The live socket and writable value/len match the option ABI.
    assert_eq!(
        unsafe {
            libc::getsockopt(
                socket.as_raw_fd(),
                libc::IPPROTO_IPV6,
                option,
                std::ptr::addr_of_mut!(value).cast(),
                &mut len,
            )
        },
        0
    );
    assert_eq!(len as usize, std::mem::size_of_val(&value));
    value
}

fn fields(data: &[u8], mode: u8) -> Vec<(u8, u8, &[u8])> {
    let base = if mode == 2 { 112 } else { 44 };
    if mode == 2 {
        assert_eq!(&data[96..112], &wire_hmac::digest(&[0xcd; 16], &data[..96]));
    }
    let mut pos = base;
    let mut out = Vec::new();
    while pos < data.len() {
        assert!(pos + 4 <= data.len());
        let len = usize::from(u16::from_be_bytes([data[pos + 2], data[pos + 3]]));
        let end = pos + 4 + len;
        assert!(end <= data.len());
        let kind = data[pos + 1];
        if kind == 8 {
            let input = [&data[..4], &data[base..pos]].concat();
            assert_eq!(&data[pos + 4..end], &wire_hmac::digest(&[0xcd; 16], &input));
        }
        out.push((kind, data[pos], &data[pos + 4..end]));
        pos = end;
    }
    assert_eq!(
        out.iter().filter(|t| t.0 == 8).count(),
        usize::from(mode != 0)
    );
    if let Some(hmac) = out.iter().position(|t| t.0 == 8) {
        // BER shaping keeps its repairable pattern outside HMAC coverage.
        // Any fields after the HMAC must therefore be Extra Padding only.
        assert!(out[hmac + 1..].iter().all(|t| t.0 == 1));
    }
    out
}

#[test]
fn macos_ipv6_reflector_shapes_datagrams_and_restores_independent_policies() {
    let ip = "::1";
    for mode in 0..3 {
        for profile in 0..3 {
            let ipv6 = ip == "::1";
            let peer = UdpSocket::bind((ip, 0)).unwrap();
            peer.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
            let socket = UdpSocket::bind((ip, 0)).unwrap();
            let target = peer.local_addr().unwrap();
            let local = socket.local_addr().unwrap();
            let mut cache = MtuCache::default();
            let mut sender = DatagramSender::new(&socket);
            let options = SendOptions {
                tos: 0,
                apply_tos: false,
                source: None,
                egress_ifindex: None,
                srh: None,
                dont_fragment: true,
            };
            let cap = cache.payload_cap(local, target, &options, false).unwrap();
            assert!(cap >= 1232);
            let auth = mode == 2;
            let base = if auth { 112 } else { 44 };
            let hmac = if mode == 0 { 0 } else { 20 };
            let mut t = if profile == 0 {
                let mut t = sized_sample(auth, 65_535);
                t.response.reflected_control.as_mut().unwrap().max_size = u16::MAX;
                t
            } else if profile == 1 {
                let mut t = single_header_sample(auth, ipv6, 247);
                // Fill the mandatory budget exactly; the optional header
                // then has to be removed by the real route query.
                let padding = cap - base - hmac - 16 - 4;
                let mut extra = vec![0, 1];
                extra.extend_from_slice(&(padding as u16).to_be_bytes());
                extra.resize(4 + padding, 0x5a);
                t.response.data.splice(base..base, extra);
                t
            } else {
                let mut t = sample(auth, ReturnPathAction::Normal);
                t.response.data.truncate(base);
                let metadata = ResidualBerValue::request(
                    RESIDUAL_BER_PATTERN_SUBTLV_TYPE,
                    Some(&[1, 2, 3, 4, 5]),
                )
                .unwrap()
                .to_raw()
                .unwrap();
                let padding = ExtraPaddingTlv {
                    padding: [1, 2, 3, 4, 5].repeat(13_100),
                }
                .to_raw();
                for tlv in [metadata, padding] {
                    t.response
                        .data
                        .extend_from_slice(&[0, tlv.tlv_type.to_byte()]);
                    t.response
                        .data
                        .extend_from_slice(&(tlv.value.len() as u16).to_be_bytes());
                    t.response.data.extend_from_slice(&tlv.value);
                }
                if auth {
                    t.response.data.extend_from_slice(&[0, 8, 0, 16]);
                    t.response.data.extend_from_slice(&[0; 16]);
                }
                t.response.reflected_control = None;
                t.remaining = 1;
                t
            };
            if mode == 1 {
                t.response.data.extend_from_slice(&[0, 8, 0, 16]);
                t.response.data.extend_from_slice(&[0; 16]);
                t.key = Some(HmacKey::new(vec![0xcd; 16]).unwrap());
                t.response.tlv_hmac_generated = true;
            }
            t.response.cos_request = None;
            t.response.reply_source = None;
            t.source = target;
            let counters = ReflectorCounters::new();
            assert_eq!(
                t.send_next_with_mtu(
                    &counters,
                    &RateLimiter::new(0),
                    |target, options, refresh| cache.payload_cap(local, target, options, refresh),
                    |data, target, options| sender.send(data, target, options)
                ),
                Some(0)
            );
            let mut data = vec![0; 65_535];
            let (len, source) = peer.recv_from(&mut data).unwrap();
            assert_eq!(source, local);
            assert!(len <= cap);
            let tlvs = fields(&data[..len], mode);
            match profile {
                0 => {
                    assert_eq!(len, cap);
                    assert_ne!(tlvs.iter().find(|t| t.0 == 12).unwrap().1 & TlvFlags::C, 0);
                    assert_eq!(t.remaining, 0, "MTU clamp ends the burst");
                }
                1 => {
                    assert_eq!(len, cap);
                    assert!(tlvs.iter().all(|t| t.0 != 247));
                }
                _ => {
                    assert!(cap - len < 5);
                    assert_ne!(tlvs.iter().find(|t| t.0 == 243).unwrap().1 & TlvFlags::C, 0);
                    let padding = tlvs.iter().find(|t| t.0 == 1).unwrap().2;
                    assert_eq!(padding.len() % 5, 0);
                    for repeat in padding.chunks_exact(5) {
                        assert_eq!(repeat, [1, 2, 3, 4, 5]);
                    }
                }
            }
            assert_eq!(policy(&socket, libc::IPV6_DONTFRAG), 1);
            assert_eq!(t.session.get_transmitted_count(), 1);
            // Same send owner must clear the sticky policy for an ordinary
            // reply; repeat transitions to exercise its cached settings.
            for controlled in [false, false, true, true, false] {
                let options = SendOptions {
                    dont_fragment: controlled,
                    apply_tos: true,
                    tos: if controlled { 0x2e } else { 1 },
                    ..options.clone()
                };
                assert_eq!(sender.send(b"ordinary", target, &options).unwrap(), 8);
                assert_eq!(peer.recv_from(&mut data).unwrap().0, 8);
                assert_eq!(policy(&socket, libc::IPV6_TCLASS), i32::from(options.tos));
                assert_eq!(
                    policy(&socket, libc::IPV6_DONTFRAG),
                    if controlled { 1 } else { 0 }
                );
            }
        }
    }
}
