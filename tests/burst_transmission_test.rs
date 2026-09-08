//! Wire checks for independently finalized, interleaved burst transmissions.
#![cfg(all(
    target_os = "linux",
    any(feature = "ttl-nix", not(feature = "ttl-pnet"))
))]

use nix::sys::socket::{recvmsg, ControlMessageOwned, MsgFlags, SockaddrStorage};
use stamp_suite::crypto::{compute_packet_hmac, HmacKey};
use std::{
    net::UdpSocket,
    os::fd::AsRawFd,
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};

struct Reflector(Child);
impl Drop for Reflector {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn packet(auth: bool, seq: u32, burst: bool) -> Vec<u8> {
    let mut data = vec![0; if auth { 112 } else { 44 }];
    data[..4].copy_from_slice(&seq.to_be_bytes());
    let offset = if auth { 26 } else { 14 };
    data[offset - 1] = 1;
    data[offset..offset + 2].copy_from_slice(&42u16.to_be_bytes());
    if burst {
        data.extend_from_slice(&[0x80, 12, 0, 12, 0, 0, 0, 3]);
        data.extend_from_slice(&120_000_000u32.to_be_bytes());
        data.extend_from_slice(&[0; 4]);
        data.extend_from_slice(&[0x80, 4, 0, 4, 184, 0, 0, 0]);
        data.extend_from_slice(&[0x80, 5, 0, 12]);
        data.extend_from_slice(&[0; 12]);
        data.extend_from_slice(&[0x80, 7, 0, 16]);
        data.extend_from_slice(&[0; 16]);
    }
    if auth {
        let key = HmacKey::new(vec![0xAB; 16]).unwrap();
        let hmac = compute_packet_hmac(&key, &data[..112], 96);
        data[96..112].copy_from_slice(&hmac);
        if burst {
            let mut input = data[..4].to_vec();
            input.extend_from_slice(&data[112..]);
            data.extend_from_slice(&[0x80, 8, 0, 16]);
            data.extend_from_slice(&key.compute(&input));
        }
    }
    data
}

fn receive(socket: &UdpSocket) -> (Vec<u8>, u8) {
    let mut data = [0u8; 1024];
    let mut iov = [std::io::IoSliceMut::new(&mut data)];
    let mut control = nix::cmsg_space!(u8, i32);
    let msg = recvmsg::<SockaddrStorage>(
        socket.as_raw_fd(),
        &mut iov,
        Some(&mut control),
        MsgFlags::empty(),
    )
    .unwrap();
    let tos = msg
        .cmsgs()
        .unwrap()
        .find_map(|cmsg| match cmsg {
            ControlMessageOwned::Ipv4Tos(v) => Some(v),
            ControlMessageOwned::Ipv6TClass(v) => Some(v as u8),
            _ => None,
        })
        .expect("received TOS metadata");
    let len = msg.bytes;
    (data[..len].to_vec(), tos)
}

fn tlv(data: &[u8], auth: bool, kind: u8) -> &[u8] {
    let mut pos = if auth { 112 } else { 44 };
    while pos + 4 <= data.len() {
        let len = u16::from_be_bytes([data[pos + 2], data[pos + 3]]) as usize;
        if data[pos + 1] == kind {
            return &data[pos + 4..pos + 4 + len];
        }
        pos += 4 + len;
    }
    panic!("missing TLV {kind}");
}

fn exercise(ip: &str, auth: bool, clock: &str, stateful: bool, kernel: bool) {
    let reserve = UdpSocket::bind((ip, 0)).unwrap();
    let destination = reserve.local_addr().unwrap();
    drop(reserve);
    let mut command = Command::new(env!("CARGO_BIN_EXE_stamp-suite"));
    command.args([
        "--is-reflector",
        "--hwtstamp",
        if kernel { "auto" } else { "off" },
        "--local-addr",
        ip,
        "--local-port",
        &destination.port().to_string(),
        "--clock-source",
        clock,
        "--reflected-control-max-count",
        "16",
    ]);
    if stateful {
        command.arg("--stateful-reflector");
    }
    if auth {
        command.args([
            "--auth-mode",
            "A",
            "--hmac-key",
            "abababababababababababababababab",
        ]);
    }
    let mut reflector = Reflector(
        command
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    let warmup = UdpSocket::bind((ip, 0)).unwrap();
    warmup
        .set_read_timeout(Some(Duration::from_millis(40)))
        .unwrap();
    let started = Instant::now();
    loop {
        assert!(
            !reflector.0.try_wait().unwrap().is_some(),
            "reflector exited"
        );
        warmup
            .send_to(&packet(auth, 0, false), destination)
            .unwrap();
        if warmup.recv_from(&mut [0; 256]).is_ok() {
            break;
        }
        assert!(started.elapsed() < Duration::from_secs(5));
    }
    let socket = UdpSocket::bind((ip, 0)).unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let enabled: nix::libc::c_int = 1;
    let (level, opt) = if ip == "::1" {
        (nix::libc::IPPROTO_IPV6, nix::libc::IPV6_RECVTCLASS)
    } else {
        (nix::libc::IPPROTO_IP, nix::libc::IP_RECVTOS)
    };
    assert_eq!(
        unsafe {
            nix::libc::setsockopt(
                socket.as_raw_fd(),
                level,
                opt,
                (&enabled as *const nix::libc::c_int).cast(),
                std::mem::size_of_val(&enabled) as _,
            )
        },
        0
    );
    socket.send_to(&packet(auth, 7, true), destination).unwrap();
    let first = receive(&socket);
    socket
        .send_to(&packet(auth, 8, false), destination)
        .unwrap();
    let ordinary = receive(&socket);
    let replies = [first, receive(&socket), receive(&socket)];
    assert_eq!(ordinary.1, 0);
    let t3 = if auth { 16 } else { 4 };
    let t2 = if auth { 32 } else { 16 };
    for (i, (data, tos)) in replies.iter().enumerate() {
        assert_eq!(*tos, 184, "CoS must survive interleaved traffic");
        let seq = u32::from_be_bytes(data[..4].try_into().unwrap());
        assert_eq!(
            seq,
            if stateful {
                if i == 0 {
                    0
                } else {
                    i as u32 + 1
                }
            } else {
                7
            }
        );
        assert_eq!(
            &data[t2..t2 + 8],
            &replies[0].0[t2..t2 + 8],
            "T2 belongs to original receive"
        );
        if i > 0 {
            assert!(
                data[t3..t3 + 8] > replies[i - 1].0[t3..t3 + 8],
                "T3 must advance"
            );
        }
        let dm = tlv(data, auth, 5);
        assert_eq!(
            u32::from_be_bytes(dm[4..8].try_into().unwrap()),
            if i == 0 { 1 } else { 2 }
        );
        assert_eq!(
            u32::from_be_bytes(dm[8..12].try_into().unwrap()),
            if i == 0 { 0 } else { i as u32 + 1 }
        );
        let follow = tlv(data, auth, 7);
        if stateful && i > 0 {
            let previous = if i == 1 {
                &ordinary.0
            } else {
                &replies[i - 1].0
            };
            assert_eq!(&follow[..4], &previous[..4]);
            if kernel {
                // Follow-Up may replace software T3 with the later kernel TX timestamp.
                assert!(follow[4..12] >= previous[t3..t3 + 8]);
                assert!(follow[4..12] < data[t3..t3 + 8]);
            } else {
                assert_eq!(&follow[4..12], &previous[t3..t3 + 8]);
            }
        } else if !stateful {
            assert_eq!(&follow[..12], &[0; 12]);
        }
        if auth {
            let key = HmacKey::new(vec![0xAB; 16]).unwrap();
            assert_eq!(&data[96..112], &compute_packet_hmac(&key, &data[..112], 96));
            let offset = data.len() - 20;
            let mut input = data[..4].to_vec();
            input.extend_from_slice(&data[112..offset]);
            assert_eq!(&data[offset + 4..], &key.compute(&input));
        }
    }
}

#[test]
fn burst_ipv4_open() {
    exercise("127.0.0.1", false, "NTP", true, false);
}
#[test]
fn burst_ipv4_auth_ptp() {
    exercise("127.0.0.1", true, "PTP", true, false);
}
#[test]
fn burst_ipv6_auth() {
    exercise("::1", true, "NTP", true, false);
}
#[test]
fn burst_stateless() {
    exercise("127.0.0.1", false, "NTP", false, false);
}

#[cfg(feature = "hwtstamp")]
#[test]
fn burst_kernel_tx_correlation() {
    exercise("127.0.0.1", true, "NTP", true, true);
}
