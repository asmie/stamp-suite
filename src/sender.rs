use std::{
    collections::HashMap,
    net::SocketAddr,
    time::{Duration, Instant},
};

use tokio::net::UdpSocket;

use crate::{
    configuration::{is_auth, ClockFormat, Configuration},
    packets::*,
    session::Session,
    time::generate_timestamp,
};

/// Statistics collected during a STAMP sender session.
///
/// Contains counters for sent/received/lost packets and RTT measurements.
#[derive(Debug, Default)]
pub struct SessionStats {
    /// Total number of packets sent during the session.
    pub packets_sent: u32,
    /// Total number of response packets received.
    pub packets_received: u32,
    /// Number of packets that were not acknowledged (lost or timed out).
    pub packets_lost: u32,
    /// Minimum round-trip time observed in nanoseconds.
    pub min_rtt_ns: Option<u64>,
    /// Maximum round-trip time observed in nanoseconds.
    pub max_rtt_ns: Option<u64>,
    /// Average round-trip time in nanoseconds.
    pub avg_rtt_ns: Option<u64>,
}

/// Internal structure to track packets awaiting responses.
struct PendingPacket {
    /// Wall-clock time when the packet was sent.
    send_time: Instant,
    /// STAMP timestamp embedded in the sent packet.
    #[allow(dead_code)]
    send_timestamp: u64,
}

/// Runs the STAMP sender, transmitting test packets and collecting statistics.
///
/// Sends packets to the configured remote address and waits for reflected responses.
/// Returns statistics about the measurement session including RTT and packet loss.
pub async fn run_sender(conf: &Configuration) -> SessionStats {
    let local_addr: SocketAddr = (conf.local_addr, conf.local_port).into();
    let remote_addr: SocketAddr = (conf.remote_addr, conf.remote_port).into();

    let socket = match UdpSocket::bind(local_addr).await {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Cannot bind to address {}: {}", local_addr, e);
            return SessionStats::default();
        }
    };

    if let Err(e) = socket.connect(remote_addr).await {
        eprintln!("Cannot connect to address {}: {}", remote_addr, e);
        return SessionStats::default();
    }

    let sess = Session::new(0);
    let mut pending: HashMap<u32, PendingPacket> = HashMap::new();
    let mut stats = SessionStats::default();
    let mut rtt_sum: u64 = 0;
    let mut recv_buf = [0u8; 1024];
    let use_auth = is_auth(&conf.auth_mode);
    let timeout = Duration::from_secs(conf.timeout as u64);

    for _ in 0..conf.count {
        let seq_num = sess.generate_sequence_number();
        let send_time = Instant::now();
        let send_timestamp = generate_timestamp(conf.clock_source);

        let send_result = if use_auth {
            let mut packet = assemble_auth_packet();
            packet.sequence_number = seq_num;
            packet.timestamp = send_timestamp;
            let buf = any_as_u8_slice(&packet).unwrap();
            socket.send(&buf).await
        } else {
            let mut packet = assemble_unauth_packet();
            packet.sequence_number = seq_num;
            packet.timestamp = send_timestamp;
            let buf = any_as_u8_slice(&packet).unwrap();
            socket.send(&buf).await
        };

        if let Err(e) = send_result {
            eprintln!("Failed to send packet {}: {}", seq_num, e);
            continue;
        }

        stats.packets_sent += 1;
        pending.insert(
            seq_num,
            PendingPacket {
                send_time,
                send_timestamp,
            },
        );

        // Non-blocking receive attempts
        loop {
            match tokio::time::timeout(Duration::from_millis(1), socket.recv(&mut recv_buf)).await {
                Ok(Ok(len)) => {
                    process_response(
                        &recv_buf[..len],
                        use_auth,
                        conf.clock_source,
                        &mut pending,
                        &mut stats,
                        &mut rtt_sum,
                        conf.print_stats,
                    );
                }
                Ok(Err(e)) => {
                    eprintln!("Receive error: {}", e);
                    break;
                }
                Err(_) => break, // Timeout - no more packets available
            }
        }

        // Wait for send delay
        tokio::time::sleep(Duration::from_millis(conf.send_delay as u64)).await;
    }

    // Final wait phase for remaining responses
    let wait_start = Instant::now();
    while !pending.is_empty() && wait_start.elapsed() < timeout {
        let remaining = timeout.saturating_sub(wait_start.elapsed());
        match tokio::time::timeout(remaining, socket.recv(&mut recv_buf)).await {
            Ok(Ok(len)) => {
                process_response(
                    &recv_buf[..len],
                    use_auth,
                    conf.clock_source,
                    &mut pending,
                    &mut stats,
                    &mut rtt_sum,
                    conf.print_stats,
                );
            }
            Ok(Err(e)) => {
                eprintln!("Receive error during final wait: {}", e);
                break;
            }
            Err(_) => break, // Timeout expired
        }
    }

    // Mark remaining pending packets as lost
    stats.packets_lost = pending.len() as u32;

    // Calculate average RTT
    if stats.packets_received > 0 {
        stats.avg_rtt_ns = Some(rtt_sum / stats.packets_received as u64);
    }

    stats
}

fn process_response(
    data: &[u8],
    use_auth: bool,
    clock_source: ClockFormat,
    pending: &mut HashMap<u32, PendingPacket>,
    stats: &mut SessionStats,
    rtt_sum: &mut u64,
    print_stats: bool,
) {
    let recv_time = Instant::now();

    let (seq_num, reflector_recv_ts, reflector_send_ts, sender_ttl) = if use_auth {
        match read_struct::<ReflectedPacketAuthenticated>(data) {
            Ok(packet) => (
                packet.sess_sender_seq_number,
                packet.receive_timestamp,
                packet.timestamp,
                packet.sess_sender_ttl,
            ),
            Err(e) => {
                eprintln!("Failed to deserialize authenticated response: {}", e);
                return;
            }
        }
    } else {
        match read_struct::<ReflectedPacketUnauthenticated>(data) {
            Ok(packet) => (
                packet.sess_sender_seq_number,
                packet.receive_timestamp,
                packet.timestamp,
                packet.sess_sender_ttl,
            ),
            Err(e) => {
                eprintln!("Failed to deserialize unauthenticated response: {}", e);
                return;
            }
        }
    };

    if let Some(pending_packet) = pending.remove(&seq_num) {
        let rtt_ns = recv_time
            .duration_since(pending_packet.send_time)
            .as_nanos() as u64;

        stats.packets_received += 1;
        *rtt_sum += rtt_ns;

        stats.min_rtt_ns = Some(stats.min_rtt_ns.map_or(rtt_ns, |min| min.min(rtt_ns)));
        stats.max_rtt_ns = Some(stats.max_rtt_ns.map_or(rtt_ns, |max| max.max(rtt_ns)));

        if print_stats {
            let _now_ts = generate_timestamp(clock_source);
            println!(
                "seq={} rtt={:.3}ms ttl={} reflector_recv_ts={} reflector_send_ts={}",
                seq_num,
                rtt_ns as f64 / 1_000_000.0,
                sender_ttl,
                reflector_recv_ts,
                reflector_send_ts
            );
        }
    } else {
        eprintln!("Received response for unknown sequence number: {}", seq_num);
    }
}

/// Creates a new unauthenticated STAMP test packet with default values.
///
/// The caller should set the sequence number and timestamp before sending.
pub fn assemble_unauth_packet() -> PacketUnauthenticated {
    PacketUnauthenticated {
        timestamp: 0,
        mbz: [0u8; 30],
        error_estimate: 0,
        sequence_number: 0,
    }
}

/// Creates a new authenticated STAMP test packet with default values.
///
/// The caller should set the sequence number, timestamp, and HMAC before sending.
pub fn assemble_auth_packet() -> PacketAuthenticated {
    PacketAuthenticated {
        timestamp: 0,
        mbz0: [0u8; 12],
        error_estimate: 0,
        sequence_number: 0,
        hmac: [0u8; 16],
        mbz1a: [0u8; 32],
        mbz1b: [0u8; 32],
        mbz1c: [0u8; 6],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_stats_default() {
        let stats = SessionStats::default();
        assert_eq!(stats.packets_sent, 0);
        assert_eq!(stats.packets_received, 0);
        assert_eq!(stats.packets_lost, 0);
        assert!(stats.min_rtt_ns.is_none());
        assert!(stats.max_rtt_ns.is_none());
        assert!(stats.avg_rtt_ns.is_none());
    }

    #[test]
    fn test_session_stats_with_values() {
        let stats = SessionStats {
            packets_sent: 100,
            packets_received: 95,
            packets_lost: 5,
            min_rtt_ns: Some(1_000_000),
            max_rtt_ns: Some(10_000_000),
            avg_rtt_ns: Some(5_000_000),
        };
        assert_eq!(stats.packets_sent, 100);
        assert_eq!(stats.packets_received, 95);
        assert_eq!(stats.packets_lost, 5);
        assert_eq!(stats.min_rtt_ns, Some(1_000_000));
        assert_eq!(stats.max_rtt_ns, Some(10_000_000));
        assert_eq!(stats.avg_rtt_ns, Some(5_000_000));
    }

    #[test]
    fn test_assemble_unauth_packet_defaults() {
        let packet = assemble_unauth_packet();
        assert_eq!(packet.sequence_number, 0);
        assert_eq!(packet.timestamp, 0);
        assert_eq!(packet.error_estimate, 0);
        assert_eq!(packet.mbz, [0u8; 30]);
    }

    #[test]
    fn test_assemble_auth_packet_defaults() {
        let packet = assemble_auth_packet();
        assert_eq!(packet.sequence_number, 0);
        assert_eq!(packet.timestamp, 0);
        assert_eq!(packet.error_estimate, 0);
        assert_eq!(packet.mbz0, [0u8; 12]);
        assert_eq!(packet.mbz1a, [0u8; 32]);
        assert_eq!(packet.mbz1b, [0u8; 32]);
        assert_eq!(packet.mbz1c, [0u8; 6]);
        assert_eq!(packet.hmac, [0u8; 16]);
    }

    #[test]
    fn test_session_stats_loss_calculation() {
        // Simulate a scenario where we can verify loss calculation
        let stats = SessionStats {
            packets_sent: 100,
            packets_received: 90,
            packets_lost: 10,
            min_rtt_ns: None,
            max_rtt_ns: None,
            avg_rtt_ns: None,
        };

        // Verify loss percentage calculation
        let loss_pct = (stats.packets_lost as f64 / stats.packets_sent as f64) * 100.0;
        assert!((loss_pct - 10.0).abs() < 0.001);
    }

    #[test]
    fn test_session_stats_rtt_bounds() {
        let stats = SessionStats {
            packets_sent: 10,
            packets_received: 10,
            packets_lost: 0,
            min_rtt_ns: Some(100),
            max_rtt_ns: Some(1000),
            avg_rtt_ns: Some(500),
        };

        // Min should be <= avg <= max
        assert!(stats.min_rtt_ns.unwrap() <= stats.avg_rtt_ns.unwrap());
        assert!(stats.avg_rtt_ns.unwrap() <= stats.max_rtt_ns.unwrap());
    }

    #[test]
    fn test_session_stats_all_packets_lost() {
        let stats = SessionStats {
            packets_sent: 100,
            packets_received: 0,
            packets_lost: 100,
            min_rtt_ns: None,
            max_rtt_ns: None,
            avg_rtt_ns: None,
        };

        assert_eq!(stats.packets_sent, stats.packets_lost);
        assert_eq!(stats.packets_received, 0);
        // RTT stats should be None when no packets received
        assert!(stats.min_rtt_ns.is_none());
        assert!(stats.max_rtt_ns.is_none());
        assert!(stats.avg_rtt_ns.is_none());
    }

    #[test]
    fn test_session_stats_zero_packets() {
        let stats = SessionStats {
            packets_sent: 0,
            packets_received: 0,
            packets_lost: 0,
            min_rtt_ns: None,
            max_rtt_ns: None,
            avg_rtt_ns: None,
        };

        assert_eq!(stats.packets_sent, 0);
        assert_eq!(stats.packets_received, 0);
        assert_eq!(stats.packets_lost, 0);
    }
}
