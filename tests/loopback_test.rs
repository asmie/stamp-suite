//! Integration tests for sender-reflector communication over loopback.
//!
//! These tests verify that the sender and reflector can communicate correctly
//! using the localhost interface.

use std::net::SocketAddr;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::time::timeout;

use stamp_suite::configuration::ClockFormat;
use stamp_suite::packets::*;
use stamp_suite::receiver::{assemble_auth_answer, assemble_unauth_answer};
use stamp_suite::sender::{assemble_auth_packet, assemble_unauth_packet};
use stamp_suite::time::generate_timestamp;

/// Find an available port for testing.
async fn find_available_port() -> u16 {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    socket.local_addr().unwrap().port()
}

/// Simple reflector that handles one packet and responds.
async fn run_test_reflector(
    port: u16,
    use_auth: bool,
) -> Result<(SocketAddr, Vec<u8>), &'static str> {
    let socket = UdpSocket::bind(format!("127.0.0.1:{}", port))
        .await
        .map_err(|_| "Failed to bind reflector socket")?;

    let mut buf = [0u8; 1024];

    // Wait for a packet with timeout
    let (len, src) = timeout(Duration::from_secs(5), socket.recv_from(&mut buf))
        .await
        .map_err(|_| "Reflector timeout waiting for packet")?
        .map_err(|_| "Reflector receive error")?;

    let rcvt = generate_timestamp(ClockFormat::NTP);
    let ttl = 64u8;

    let response = if use_auth {
        let packet: PacketAuthenticated =
            read_struct(&buf[..len]).map_err(|_| "Failed to parse auth packet")?;
        let answer = assemble_auth_answer(&packet, ClockFormat::NTP, rcvt, ttl);
        any_as_u8_slice(&answer).map_err(|_| "Failed to serialize auth response")?
    } else {
        let packet: PacketUnauthenticated =
            read_struct(&buf[..len]).map_err(|_| "Failed to parse unauth packet")?;
        let answer = assemble_unauth_answer(&packet, ClockFormat::NTP, rcvt, ttl);
        any_as_u8_slice(&answer).map_err(|_| "Failed to serialize unauth response")?
    };

    socket
        .send_to(&response, src)
        .await
        .map_err(|_| "Failed to send response")?;

    Ok((src, buf[..len].to_vec()))
}

/// Simple sender that sends one packet and waits for response.
async fn run_test_sender(
    local_port: u16,
    remote_port: u16,
    use_auth: bool,
    seq_num: u32,
) -> Result<(u32, u64, u8), &'static str> {
    let local_addr = format!("127.0.0.1:{}", local_port);
    let remote_addr: SocketAddr = format!("127.0.0.1:{}", remote_port).parse().unwrap();

    let socket = UdpSocket::bind(&local_addr)
        .await
        .map_err(|_| "Failed to bind sender socket")?;

    let send_timestamp = generate_timestamp(ClockFormat::NTP);

    let send_buf = if use_auth {
        let mut packet = assemble_auth_packet();
        packet.sequence_number = seq_num;
        packet.timestamp = send_timestamp;
        any_as_u8_slice(&packet).map_err(|_| "Failed to serialize auth packet")?
    } else {
        let mut packet = assemble_unauth_packet();
        packet.sequence_number = seq_num;
        packet.timestamp = send_timestamp;
        any_as_u8_slice(&packet).map_err(|_| "Failed to serialize unauth packet")?
    };

    socket
        .send_to(&send_buf, remote_addr)
        .await
        .map_err(|_| "Failed to send packet")?;

    let mut recv_buf = [0u8; 1024];
    let (len, _) = timeout(Duration::from_secs(5), socket.recv_from(&mut recv_buf))
        .await
        .map_err(|_| "Sender timeout waiting for response")?
        .map_err(|_| "Sender receive error")?;

    if use_auth {
        let response: ReflectedPacketAuthenticated =
            read_struct(&recv_buf[..len]).map_err(|_| "Failed to parse auth response")?;
        Ok((
            response.sess_sender_seq_number,
            response.sess_sender_timestamp,
            response.sess_sender_ttl,
        ))
    } else {
        let response: ReflectedPacketUnauthenticated =
            read_struct(&recv_buf[..len]).map_err(|_| "Failed to parse unauth response")?;
        Ok((
            response.sess_sender_seq_number,
            response.sess_sender_timestamp,
            response.sess_sender_ttl,
        ))
    }
}

#[tokio::test]
async fn test_loopback_unauthenticated_single_packet() {
    let reflector_port = find_available_port().await;
    let sender_port = find_available_port().await;

    // Start reflector in background
    let reflector_handle =
        tokio::spawn(async move { run_test_reflector(reflector_port, false).await });

    // Give reflector time to bind
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Run sender
    let seq_num = 42u32;
    let sender_result = run_test_sender(sender_port, reflector_port, false, seq_num).await;

    // Check sender received correct response
    assert!(sender_result.is_ok(), "Sender failed: {:?}", sender_result);
    let (echoed_seq, _echoed_ts, echoed_ttl) = sender_result.unwrap();
    assert_eq!(echoed_seq, seq_num, "Sequence number not echoed correctly");
    assert_eq!(echoed_ttl, 64, "TTL not set correctly");

    // Check reflector received packet
    let reflector_result = reflector_handle.await.unwrap();
    assert!(
        reflector_result.is_ok(),
        "Reflector failed: {:?}",
        reflector_result
    );
}

#[tokio::test]
async fn test_loopback_authenticated_single_packet() {
    let reflector_port = find_available_port().await;
    let sender_port = find_available_port().await;

    // Start reflector in background
    let reflector_handle =
        tokio::spawn(async move { run_test_reflector(reflector_port, true).await });

    // Give reflector time to bind
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Run sender
    let seq_num = 123u32;
    let sender_result = run_test_sender(sender_port, reflector_port, true, seq_num).await;

    // Check sender received correct response
    assert!(sender_result.is_ok(), "Sender failed: {:?}", sender_result);
    let (echoed_seq, _echoed_ts, echoed_ttl) = sender_result.unwrap();
    assert_eq!(echoed_seq, seq_num, "Sequence number not echoed correctly");
    assert_eq!(echoed_ttl, 64, "TTL not set correctly");

    // Check reflector received packet
    let reflector_result = reflector_handle.await.unwrap();
    assert!(
        reflector_result.is_ok(),
        "Reflector failed: {:?}",
        reflector_result
    );
}

#[tokio::test]
async fn test_loopback_multiple_packets() {
    let reflector_port = find_available_port().await;
    let sender_port = find_available_port().await;

    let socket = UdpSocket::bind(format!("127.0.0.1:{}", reflector_port))
        .await
        .unwrap();
    let reflector_addr: SocketAddr = format!("127.0.0.1:{}", reflector_port).parse().unwrap();

    // Spawn reflector that handles multiple packets
    let reflector_handle = tokio::spawn(async move {
        let mut buf = [0u8; 1024];
        let mut received_count = 0;

        for _ in 0..5 {
            if let Ok(Ok((len, src))) =
                timeout(Duration::from_secs(2), socket.recv_from(&mut buf)).await
            {
                let rcvt = generate_timestamp(ClockFormat::NTP);
                if let Ok(packet) = read_struct::<PacketUnauthenticated>(&buf[..len]) {
                    let answer = assemble_unauth_answer(&packet, ClockFormat::NTP, rcvt, 64);
                    if let Ok(response) = any_as_u8_slice(&answer) {
                        let _ = socket.send_to(&response, src).await;
                        received_count += 1;
                    }
                }
            }
        }
        received_count
    });

    // Give reflector time to bind
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Send multiple packets
    let sender_socket = UdpSocket::bind(format!("127.0.0.1:{}", sender_port))
        .await
        .unwrap();

    let mut responses_received = 0;
    for seq in 0..5u32 {
        let mut packet = assemble_unauth_packet();
        packet.sequence_number = seq;
        packet.timestamp = generate_timestamp(ClockFormat::NTP);

        let buf = any_as_u8_slice(&packet).unwrap();
        sender_socket.send_to(&buf, reflector_addr).await.unwrap();

        let mut recv_buf = [0u8; 1024];
        if let Ok(Ok((len, _))) = timeout(
            Duration::from_secs(1),
            sender_socket.recv_from(&mut recv_buf),
        )
        .await
        {
            if let Ok(response) = read_struct::<ReflectedPacketUnauthenticated>(&recv_buf[..len]) {
                assert_eq!(response.sess_sender_seq_number, seq);
                responses_received += 1;
            }
        }

        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    let reflector_received = reflector_handle.await.unwrap();
    assert_eq!(reflector_received, 5, "Reflector should receive 5 packets");
    assert_eq!(responses_received, 5, "Sender should receive 5 responses");
}

#[tokio::test]
async fn test_loopback_timestamp_ordering() {
    let reflector_port = find_available_port().await;
    let sender_port = find_available_port().await;

    // Start reflector
    let socket = UdpSocket::bind(format!("127.0.0.1:{}", reflector_port))
        .await
        .unwrap();

    let reflector_handle = tokio::spawn(async move {
        let mut buf = [0u8; 1024];
        if let Ok(Ok((len, src))) =
            timeout(Duration::from_secs(2), socket.recv_from(&mut buf)).await
        {
            let rcvt = generate_timestamp(ClockFormat::NTP);
            // Small delay to ensure send timestamp is different from receive
            tokio::time::sleep(Duration::from_millis(5)).await;

            if let Ok(packet) = read_struct::<PacketUnauthenticated>(&buf[..len]) {
                let answer = assemble_unauth_answer(&packet, ClockFormat::NTP, rcvt, 64);
                if let Ok(response) = any_as_u8_slice(&answer) {
                    let _ = socket.send_to(&response, src).await;
                }
            }
        }
    });

    tokio::time::sleep(Duration::from_millis(50)).await;

    let sender_socket = UdpSocket::bind(format!("127.0.0.1:{}", sender_port))
        .await
        .unwrap();

    let send_timestamp = generate_timestamp(ClockFormat::NTP);
    let mut packet = assemble_unauth_packet();
    packet.sequence_number = 1;
    packet.timestamp = send_timestamp;

    let buf = any_as_u8_slice(&packet).unwrap();
    let reflector_addr: SocketAddr = format!("127.0.0.1:{}", reflector_port).parse().unwrap();
    sender_socket.send_to(&buf, reflector_addr).await.unwrap();

    let mut recv_buf = [0u8; 1024];
    let (len, _) = timeout(
        Duration::from_secs(2),
        sender_socket.recv_from(&mut recv_buf),
    )
    .await
    .unwrap()
    .unwrap();

    let response: ReflectedPacketUnauthenticated = read_struct(&recv_buf[..len]).unwrap();

    // Verify timestamp ordering: sender_ts <= receive_ts <= reflector_send_ts
    assert_eq!(
        response.sess_sender_timestamp, send_timestamp,
        "Sender timestamp should be echoed"
    );
    assert!(
        response.receive_timestamp >= send_timestamp,
        "Receive timestamp should be >= send timestamp"
    );
    assert!(
        response.timestamp >= response.receive_timestamp,
        "Reflector send timestamp should be >= receive timestamp"
    );

    reflector_handle.await.unwrap();
}

#[tokio::test]
async fn test_loopback_ipv6() {
    // Skip if IPv6 loopback is not available
    let socket_result = UdpSocket::bind("[::1]:0").await;
    if socket_result.is_err() {
        eprintln!("Skipping IPv6 test - IPv6 loopback not available");
        return;
    }
    let reflector_socket = socket_result.unwrap();
    let reflector_port = reflector_socket.local_addr().unwrap().port();

    let reflector_handle = tokio::spawn(async move {
        let mut buf = [0u8; 1024];
        if let Ok(Ok((len, src))) =
            timeout(Duration::from_secs(2), reflector_socket.recv_from(&mut buf)).await
        {
            let rcvt = generate_timestamp(ClockFormat::NTP);
            if let Ok(packet) = read_struct::<PacketUnauthenticated>(&buf[..len]) {
                let answer = assemble_unauth_answer(&packet, ClockFormat::NTP, rcvt, 64);
                if let Ok(response) = any_as_u8_slice(&answer) {
                    let _ = reflector_socket.send_to(&response, src).await;
                    return true;
                }
            }
        }
        false
    });

    tokio::time::sleep(Duration::from_millis(50)).await;

    let sender_socket = UdpSocket::bind("[::1]:0").await.unwrap();
    let mut packet = assemble_unauth_packet();
    packet.sequence_number = 99;
    packet.timestamp = generate_timestamp(ClockFormat::NTP);

    let buf = any_as_u8_slice(&packet).unwrap();
    let reflector_addr: SocketAddr = format!("[::1]:{}", reflector_port).parse().unwrap();
    sender_socket.send_to(&buf, reflector_addr).await.unwrap();

    let mut recv_buf = [0u8; 1024];
    let result = timeout(
        Duration::from_secs(2),
        sender_socket.recv_from(&mut recv_buf),
    )
    .await;

    assert!(result.is_ok(), "Should receive response over IPv6");
    let (len, _) = result.unwrap().unwrap();
    let response: ReflectedPacketUnauthenticated = read_struct(&recv_buf[..len]).unwrap();
    assert_eq!(response.sess_sender_seq_number, 99);

    assert!(reflector_handle.await.unwrap(), "Reflector should succeed");
}
