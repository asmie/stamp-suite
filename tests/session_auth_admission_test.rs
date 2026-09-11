//! Rejected base packets must not allocate or refresh reflector session state.
#![cfg(all(unix, any(feature = "ttl-nix", not(feature = "ttl-pnet"))))]

#[path = "common/wire_hmac.rs"]
mod wire_hmac;
use clap::Parser;
use stamp_suite::{
    configuration::Configuration,
    crypto::{HmacKey, HmacKeySet},
    receiver,
    session::ReplayVerdict,
};
use std::{
    net::SocketAddr,
    sync::{atomic::Ordering, Arc},
    time::Duration,
};
use tokio::{
    net::UdpSocket,
    task::JoinHandle,
    time::{sleep, timeout},
};

struct Reflector {
    shared: Arc<receiver::ReceiverSharedState>,
    destination: SocketAddr,
    task: JoinHandle<Result<(), stamp_suite::StartupError>>,
}

impl Drop for Reflector {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl Reflector {
    async fn start(ip: &str, auth: bool, strict: bool, stateful: bool) -> Self {
        let reserve = UdpSocket::bind((ip, 0)).await.unwrap();
        let destination = reserve.local_addr().unwrap();
        drop(reserve);
        let mut args = vec![
            "stamp-suite".to_string(),
            "--is-reflector".into(),
            "--local-addr".into(),
            ip.into(),
            "--local-port".into(),
            destination.port().to_string(),
            "--max-sessions".into(),
            "1".into(),
            "--drop-replayed".into(),
        ];
        if stateful {
            args.push("--stateful-reflector".into());
        }
        if auth {
            args.extend([
                "--auth-mode".into(),
                "A".into(),
                "--hmac-key".into(),
                "abababababababababababababababab".into(),
            ]);
        }
        if strict {
            args.push("--strict-packets".into());
        }
        let conf = Configuration::parse_from(args);
        conf.validate().unwrap();
        let shared = Arc::new(receiver::create_shared_state(&conf));
        let task_shared = Arc::clone(&shared);
        let task =
            tokio::task::spawn_local(
                async move { receiver::run_receiver(&conf, &task_shared).await },
            );
        Self {
            shared,
            destination,
            task,
        }
    }

    // Wait for an observed receive; this also synchronizes startup without
    // seeding the session table with a valid warmup packet.
    async fn reject(&self, socket: &UdpSocket, data: &[u8]) {
        let drops_before = self.shared.counters.packets_dropped.load(Ordering::Relaxed);
        let before = self
            .shared
            .counters
            .packets_received
            .load(Ordering::Relaxed);
        timeout(Duration::from_secs(5), async {
            loop {
                assert!(!self.task.is_finished(), "reflector exited");
                socket.send_to(data, self.destination).await.unwrap();
                sleep(Duration::from_millis(10)).await;
                if self
                    .shared
                    .counters
                    .packets_received
                    .load(Ordering::Relaxed)
                    > before
                {
                    break;
                }
            }
        })
        .await
        .expect("packet was not received");
        assert!(self.shared.counters.packets_dropped.load(Ordering::Relaxed) > drops_before);
        let mut response = [0; 512];
        assert!(
            timeout(Duration::from_millis(20), socket.recv_from(&mut response))
                .await
                .is_err()
        );
    }

    async fn exchange(&self, socket: &UdpSocket, data: &[u8]) -> u32 {
        socket.send_to(data, self.destination).await.unwrap();
        let mut response = [0; 512];
        timeout(Duration::from_secs(2), socket.recv_from(&mut response))
            .await
            .unwrap()
            .unwrap();
        u32::from_be_bytes(response[..4].try_into().unwrap())
    }
}

fn packet(seq: u32, ssid: u16, key: Option<u8>) -> Vec<u8> {
    let mut bytes = vec![0; if key.is_some() { 112 } else { 44 }];
    bytes[..4].copy_from_slice(&seq.to_be_bytes());
    let offset = if key.is_some() { 26 } else { 14 };
    bytes[offset - 1] = 1;
    bytes[offset..offset + 2].copy_from_slice(&ssid.to_be_bytes());
    if let Some(key) = key {
        let mac = wire_hmac::digest(&[key; 16], &bytes[..96]);
        bytes[96..112].copy_from_slice(&mac);
    }
    bytes
}

#[tokio::test]
async fn stateless_authentication_protects_counters_but_preserves_tlv_i_flag_reply() {
    tokio::task::LocalSet::new()
        .run_until(async {
            let reflector = Reflector::start("127.0.0.1", true, true, false).await;
            let sender = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            reflector.reject(&sender, &packet(10, 42, Some(0xCD))).await;
            assert_eq!(reflector.shared.session_manager.session_count(), 0);
            // A valid base HMAC with an invalid TLV HMAC still gets an I-flag
            // response under RFC 8972 §4.8; it is not a failed base authentication.
            let mut data = packet(10, 42, Some(0xAB));
            data.extend_from_slice(&[0x80, 1, 0, 1, 0]); // Extra Padding
            data.extend_from_slice(&[0x80, 8, 0, 16]);
            data.extend_from_slice(&[0; 16]); // invalid TLV HMAC
            sender.send_to(&data, reflector.destination).await.unwrap();
            let mut response = [0; 512];
            timeout(Duration::from_secs(2), sender.recv_from(&mut response))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(u32::from_be_bytes(response[..4].try_into().unwrap()), 10);
            assert_ne!(response[112] & 0x20, 0, "invalid TLV HMAC must set I");
            let before = reflector
                .shared
                .session_manager
                .session_summaries_extended()
                .pop()
                .unwrap();
            reflector.reject(&sender, &packet(11, 42, Some(0xCD))).await;
            let after = reflector
                .shared
                .session_manager
                .session_summaries_extended()
                .pop()
                .unwrap();
            assert_eq!(after.last_active, before.last_active);
            assert_eq!(after.packets_received, 1);
            assert_eq!(after.packets_transmitted, 1);
            assert_eq!(
                reflector
                    .exchange(&sender, &packet(11, 42, Some(0xAB)))
                    .await,
                11
            );
        })
        .await;
}

#[tokio::test]
async fn invalid_hmac_cannot_take_the_only_slot_or_refresh_existing_state() {
    tokio::task::LocalSet::new()
        .run_until(async {
            for ip in ["127.0.0.1", "::1"] {
                let reflector = Reflector::start(ip, true, false, true).await;
                let attacker = UdpSocket::bind((ip, 0)).await.unwrap();
                let sender = UdpSocket::bind((ip, 0)).await.unwrap();
                reflector
                    .reject(&attacker, &packet(900, 42, Some(0xCD)))
                    .await;
                assert_eq!(
                    reflector.shared.session_manager.session_count(),
                    0,
                    "invalid HMAC consumed the only slot"
                );
                assert_eq!(
                    reflector
                        .exchange(&sender, &packet(100, 42, Some(0xAB)))
                        .await,
                    0
                );
                let before = reflector
                    .shared
                    .session_manager
                    .session_summaries_extended()
                    .pop()
                    .unwrap();
                let session = reflector
                    .shared
                    .session_manager
                    .get_session(before.key)
                    .unwrap();
                let reflection = session.get_last_reflection();
                // The same sequence must not even reach replay classification until
                // authentication succeeds. Nor may a forged high sequence poison it.
                for seq in [100, 900] {
                    reflector
                        .reject(&sender, &packet(seq, 42, Some(0xCD)))
                        .await;
                }
                let after = reflector
                    .shared
                    .session_manager
                    .session_summaries_extended()
                    .pop()
                    .unwrap();
                assert_eq!(after.last_active, before.last_active);
                assert_eq!(after.packets_received, 1);
                assert_eq!(after.packets_transmitted, 1);
                assert_eq!(session.get_last_reflection(), reflection);
                assert_eq!(session.classify_replay(900), ReplayVerdict::New);
                assert_eq!(
                    reflector
                        .shared
                        .counters
                        .packets_replayed
                        .load(Ordering::Relaxed),
                    0
                );
                for (seq, expected) in [(101, 1), (102, 2)] {
                    assert_eq!(
                        reflector
                            .exchange(&sender, &packet(seq, 42, Some(0xAB)))
                            .await,
                        expected
                    );
                }
            }
        })
        .await;
}

#[tokio::test]
async fn unknown_ssid_and_revoked_keys_do_not_mutate_sessions() {
    tokio::task::LocalSet::new()
        .run_until(async {
            let reflector = Reflector::start("127.0.0.1", true, true, true).await;
            let sender = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let mut keys = HmacKeySet::new();
            keys.insert(42, HmacKey::new(vec![0xAB; 16]).unwrap());
            *reflector.shared.hmac_keys.write().unwrap() = Some(keys);
            reflector.reject(&sender, &packet(1, 43, Some(0xAB))).await;
            assert_eq!(reflector.shared.session_manager.session_count(), 0);
            assert_eq!(
                reflector
                    .exchange(&sender, &packet(1, 42, Some(0xAB)))
                    .await,
                0
            );
            let before = reflector
                .shared
                .session_manager
                .session_summaries_extended()
                .pop()
                .unwrap();
            *reflector.shared.hmac_keys.write().unwrap() = Some(HmacKeySet::new());
            reflector.reject(&sender, &packet(2, 42, Some(0xAB))).await;
            let mut keys = HmacKeySet::new();
            keys.insert(42, HmacKey::new(vec![0xCD; 16]).unwrap());
            *reflector.shared.hmac_keys.write().unwrap() = Some(keys);
            reflector.reject(&sender, &packet(2, 42, Some(0xAB))).await;
            let after = reflector
                .shared
                .session_manager
                .session_summaries_extended()
                .pop()
                .unwrap();
            assert_eq!(after.last_active, before.last_active);
            assert_eq!(after.packets_received, 1);
            assert_eq!(
                reflector
                    .exchange(&sender, &packet(2, 42, Some(0xCD)))
                    .await,
                1
            );
        })
        .await;
}

#[tokio::test]
async fn malformed_base_packets_do_not_allocate_sessions() {
    tokio::task::LocalSet::new()
        .run_until(async {
            for auth in [false, true] {
                let reflector = Reflector::start("127.0.0.1", auth, true, true).await;
                let sender = UdpSocket::bind("127.0.0.1:0").await.unwrap();
                reflector.reject(&sender, &[0; 4]).await;
                assert_eq!(reflector.shared.session_manager.session_count(), 0);
                assert_eq!(
                    reflector
                        .exchange(&sender, &packet(1, 42, auth.then_some(0xAB)))
                        .await,
                    0
                );
            }
        })
        .await;
}
