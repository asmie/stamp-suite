use super::*;
use clap::Parser;

async fn header_request_run(ip: &str, auth: bool) -> (SenderRun, UdpSocket) {
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
    let sender = SenderRun::open(
        Arc::new(conf),
        SenderObservers::new(),
        CancellationToken::new(),
    )
    .await
    .unwrap();
    (sender, peer)
}

/// Drops the kernel's cached route the way a failed route lookup does:
/// Linux makes IP_MTU/IPV6_MTU unavailable on a disconnected UDP socket.
fn drop_cached_route(sender: &SenderRun) {
    use std::os::fd::AsRawFd;

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
}

#[tokio::test]
async fn unreadable_route_mtu_is_refreshed_before_the_probe_is_sent() {
    for ip in ["127.0.0.1", "::1"] {
        for auth in [false, true] {
            let (mut sender, peer) = header_request_run(ip, auth).await;
            drop_cached_route(&sender);
            sender.send_probe(false).await.unwrap();
            assert!(egress_mtu(&sender.socket).is_some(), "route not refreshed");
            assert_eq!(sender.packets_sent, 1);
            assert_eq!(sender.consecutive_send_errors, 0);
            let mut bytes = [0; 2048];
            let (len, from) =
                tokio::time::timeout(Duration::from_secs(2), peer.recv_from(&mut bytes))
                    .await
                    .unwrap()
                    .unwrap();
            assert_eq!(from, sender.socket.local_addr().unwrap());
            assert!(len >= if auth { 112 } else { 44 });
            assert_eq!(&bytes[..4], &0u32.to_be_bytes());
        }
    }
}

#[tokio::test]
async fn refused_probes_share_the_send_failure_budget_without_pending_state() {
    let (mut sender, peer) = header_request_run("127.0.0.1", false).await;
    for attempt in 1..=MAX_CONSECUTIVE_SEND_FAILURES {
        let refusal = crate::StartupError::config("route MTU too small");
        let result = sender.refuse_probe(refusal, false);
        assert_eq!(
            result.is_err(),
            attempt == MAX_CONSECUTIVE_SEND_FAILURES,
            "attempt {attempt}"
        );
        assert_eq!(sender.consecutive_send_errors, attempt);
    }
    assert_eq!(sender.packets_sent, 0);
    assert!(sender.pending.is_empty());
    assert!((sender.pending.index_lens().0 == 0));
    assert!((sender.pending.index_lens().1 == 0));
    assert!(
        tokio::time::timeout(Duration::from_millis(10), peer.recv_from(&mut [0; 256]))
            .await
            .is_err()
    );

    // A successful send resets the budget.
    sender.send_probe(false).await.unwrap();
    assert_eq!(sender.consecutive_send_errors, 0);
}
