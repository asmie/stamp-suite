//! Per-SSID signing survives final fallback mutations and in-flight key rotation.
#![cfg(all(unix, any(feature = "ttl-nix", not(feature = "ttl-pnet"))))]
use clap::Parser;
use stamp_suite::{
    configuration::Configuration,
    crypto::{compute_packet_hmac, HmacKey},
    receiver,
};
use std::{net::SocketAddr, sync::Arc, time::Duration};
use tokio::{net::UdpSocket, task::JoinHandle, time::timeout};

fn key(value: u8) -> HmacKey {
    HmacKey::new(vec![value; 16]).unwrap()
}
fn request(auth: bool, ssid: u16, value: u8, seq: u32, fallback: bool, burst: bool) -> Vec<u8> {
    let base = if auth { 112 } else { 44 };
    let mut data = vec![0; base];
    data[..4].copy_from_slice(&seq.to_be_bytes());
    let error = if auth { 24 } else { 12 };
    data[if auth { 23 } else { 11 }] = 1;
    data[error + 1] = 1;
    data[error + 2..error + 4].copy_from_slice(&ssid.to_be_bytes());
    if fallback {
        // Return Path / SRv6 segment list; forwarding is disabled, so U is set
        // during final transmission on either address family.
        data.extend_from_slice(&[0x80, 10, 0, 20, 0x80, 4, 0, 16]);
        data.extend_from_slice(&std::net::Ipv6Addr::LOCALHOST.octets());
    } else {
        data.extend_from_slice(&[0x80, 3, 0, 4, 0, 0, 0, 0]);
    }
    if burst {
        data.extend_from_slice(&[0x80, 12, 0, 12, 0, 0, 0, 3]);
        data.extend_from_slice(&100_000_000u32.to_be_bytes());
        data.extend_from_slice(&[0; 4]);
    }
    let key = key(value);
    let mut covered = data[..4].to_vec();
    covered.extend_from_slice(&data[base..]);
    data.extend_from_slice(&[0x80, 8, 0, 16]);
    data.extend_from_slice(&key.compute(&covered));
    // Symmetric padding exercises signing with bytes after the HMAC too.
    if !burst {
        data.extend_from_slice(&[0; 9]);
    }
    if auth {
        let mac = compute_packet_hmac(&key, &data, 96);
        data[96..112].copy_from_slice(&mac);
    }
    data
}
fn verify(data: &[u8], auth: bool, value: u8, fallback: bool) {
    let key = key(value);
    if auth {
        assert_eq!(&data[96..112], &compute_packet_hmac(&key, data, 96));
    }
    let base = if auth { 112 } else { 44 };
    let mut pos = base;
    let mut found = false;
    let mut found_return_path = false;
    while pos + 4 <= data.len() {
        let len = u16::from_be_bytes([data[pos + 2], data[pos + 3]]) as usize;
        assert!(pos + 4 + len <= data.len());
        if data[pos + 1] == 10 {
            found_return_path = true;
            assert!(fallback);
            assert_eq!(data[pos] & 0xE0, 0x80, "only U set for unsupported SRv6");
        }
        if data[pos + 1] == 8 {
            assert_eq!(data[pos] & 0xE0, 0);
            let mut covered = data[..4].to_vec();
            covered.extend_from_slice(&data[base..pos]);
            assert_eq!(&data[pos + 4..pos + 4 + len], &key.compute(&covered));
            found = true;
            break;
        }
        pos += len + 4;
    }
    assert!(found, "missing response HMAC TLV");
    assert_eq!(found_return_path, fallback, "Return Path TLV must be echoed");
}
struct Reflector {
    shared: Arc<receiver::ReceiverSharedState>,
    target: SocketAddr,
    task: JoinHandle<Result<(), stamp_suite::StartupError>>,
    _keys: tempfile::TempDir,
}
impl Drop for Reflector {
    fn drop(&mut self) {
        self.task.abort();
    }
}
impl Reflector {
    async fn start(ip: &str, auth: bool) -> Self {
        let keys = tempfile::tempdir().unwrap();
        for (file, value) in [
            ("002a.key", 0xAB),
            ("002b.key", 0xCD),
            ("default.key", 0xEF),
        ] {
            let path = keys.path().join(file);
            std::fs::write(&path, format!("{value:02x}").repeat(16)).unwrap();
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        let reserve = UdpSocket::bind((ip, 0)).await.unwrap();
        let target = reserve.local_addr().unwrap();
        drop(reserve);
        let conf = Configuration::parse_from([
            "stamp-suite",
            "--is-reflector",
            "--local-addr",
            ip,
            "--local-port",
            &target.port().to_string(),
            "--auth-mode",
            if auth { "A" } else { "O" },
            "--hmac-key-dir",
            keys.path().to_str().unwrap(),
            "--stateful-reflector",
            "--reflected-control-max-count",
            "3",
            "--hwtstamp",
            "off",
        ]);
        conf.validate().unwrap();
        let shared = Arc::new(receiver::create_shared_state(&conf));
        let task_shared = Arc::clone(&shared);
        let task =
            tokio::task::spawn_local(
                async move { receiver::run_receiver(&conf, &task_shared).await },
            );
        let reflector = Self {
            shared,
            target,
            task,
            _keys: keys,
        };
        let warmup = UdpSocket::bind((ip, 0)).await.unwrap();
        timeout(Duration::from_secs(3), async {
            loop {
                assert!(!reflector.task.is_finished());
                warmup
                    .send_to(&request(auth, 42, 0xAB, 0, false, false), target)
                    .await
                    .unwrap();
                let mut data = [0; 1024];
                if timeout(Duration::from_millis(30), warmup.recv_from(&mut data))
                    .await
                    .is_ok()
                {
                    break;
                }
            }
        })
        .await
        .unwrap();
        reflector
    }
    async fn recv(&self, socket: &UdpSocket) -> Vec<u8> {
        let mut data = vec![0; 2048];
        let (len, _) = timeout(Duration::from_secs(2), socket.recv_from(&mut data))
            .await
            .unwrap()
            .unwrap();
        data.truncate(len);
        data
    }
}
async fn check(auth: bool) {
    for ip in ["127.0.0.1", "::1"] {
        let reflector = Reflector::start(ip, auth).await;
        let socket = UdpSocket::bind((ip, 0)).await.unwrap();
        for (ssid, value) in [(42, 0xAB), (43, 0xCD), (99, 0xEF)] {
            for fallback in [false, true] {
                socket
                    .send_to(
                        &request(auth, ssid, value, 1, fallback, false),
                        reflector.target,
                    )
                    .await
                    .unwrap();
                verify(&reflector.recv(&socket).await, auth, value, fallback);
            }
        }
        socket
            .send_to(&request(auth, 42, 0xAB, 2, true, true), reflector.target)
            .await
            .unwrap();
        verify(&reflector.recv(&socket).await, auth, 0xAB, true);
        // Rotate after acceptance: the two queued copies must retain the old
        // selected key; a newly accepted request must use the replacement.
        reflector
            .shared
            .hmac_keys
            .write()
            .unwrap()
            .as_mut()
            .unwrap()
            .insert(42, key(0x12));
        for _ in 0..2 {
            verify(&reflector.recv(&socket).await, auth, 0xAB, true);
        }
        socket
            .send_to(&request(auth, 42, 0x12, 3, true, false), reflector.target)
            .await
            .unwrap();
        verify(&reflector.recv(&socket).await, auth, 0x12, true);
        // Revocation without a default leaves no matching key for new auth traffic.
        {
            let mut guard = reflector.shared.hmac_keys.write().unwrap();
            let keys = guard.as_mut().unwrap();
            keys.remove_ssid(42);
            keys.clear_default();
        }
        if auth {
            socket
                .send_to(&request(true, 42, 0x12, 4, true, false), reflector.target)
                .await
                .unwrap();
            assert!(
                timeout(Duration::from_millis(80), socket.recv_from(&mut [0; 2048]))
                    .await
                    .is_err()
            );
        }
        socket
            .send_to(&request(auth, 43, 0xCD, 4, true, false), reflector.target)
            .await
            .unwrap();
        verify(&reflector.recv(&socket).await, auth, 0xCD, true);
    }
}
#[tokio::test]
async fn authenticated_keyset_fallback_and_rotation() {
    tokio::task::LocalSet::new().run_until(check(true)).await;
}
#[tokio::test]
async fn open_tlv_keyset_fallback_and_rotation() {
    tokio::task::LocalSet::new().run_until(check(false)).await;
}
