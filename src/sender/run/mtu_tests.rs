use super::*;
use clap::Parser;

#[tokio::test]
async fn missing_route_budget_refuses_send_without_mutating_pending_state() {
    use std::os::fd::AsRawFd;

    for ip in ["127.0.0.1", "::1"] {
        for auth in [false, true] {
            let peer = UdpSocket::bind((ip, 0)).await.unwrap();
            let mut args = vec![
                "test".to_owned(),
                "--local-addr".into(),
                ip.into(),
                "--local-port".into(),
                "0".into(),
                "--remote-addr".into(),
                ip.into(),
                "--remote-port".into(),
                peer.local_addr().unwrap().port().to_string(),
                "--hwtstamp".into(),
                "off".into(),
                "--reflected-fixed-hdr".into(),
            ];
            if auth {
                args.extend(
                    ["-A", "A", "--hmac-key", "abababababababababababababababab"].map(String::from),
                );
            }
            let conf = Configuration::parse_from(args);
            conf.validate().unwrap();
            let mut sender = SenderRun::open(
                Arc::new(conf),
                SenderObservers::new(),
                CancellationToken::new(),
            )
            .await
            .unwrap();
            // Linux makes IP_MTU/IPV6_MTU unavailable on a disconnected UDP
            // socket. Use the real getsockopt failure, not a substituted budget.
            let address = libc::sockaddr {
                sa_family: libc::AF_UNSPEC as _,
                sa_data: [0; 14],
            };
            // SAFETY: the socket fd and correctly sized sockaddr remain live
            // throughout connect; AF_UNSPEC disconnects without a peer address.
            let rc = unsafe {
                libc::connect(
                    sender.socket.as_raw_fd(),
                    &address,
                    std::mem::size_of_val(&address) as _,
                )
            };
            assert_eq!(rc, 0);
            assert!(egress_mtu(&sender.socket).is_none());
            let error = sender.send_probe(false).await.unwrap_err();
            assert!(
                matches!(error, crate::StartupError::Config(ref message) if message.contains("route MTU")),
                "{error}"
            );
            assert_eq!(sender.packets_sent, 0);
            assert_eq!(
                sender.consecutive_send_errors, 0,
                "budget failure must precede send"
            );
            assert!(sender.pending.is_empty());
            assert!(sender.pending_order.is_empty());
            assert!(sender.pending_generation.is_empty());
            assert!(
                tokio::time::timeout(Duration::from_millis(10), peer.recv_from(&mut [0; 256]))
                    .await
                    .is_err()
            );
        }
    }
}
