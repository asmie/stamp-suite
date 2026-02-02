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

#[derive(Debug, Default)]
pub struct SessionStats {
    pub packets_sent: u32,
    pub packets_received: u32,
    pub packets_lost: u32,
    pub min_rtt_ns: Option<u64>,
    pub max_rtt_ns: Option<u64>,
    pub avg_rtt_ns: Option<u64>,
}

struct PendingPacket {
    send_time: Instant,
    #[allow(dead_code)]
    send_timestamp: u64,
}

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

pub fn assemble_unauth_packet() -> PacketUnauthenticated {
    PacketUnauthenticated {
        timestamp: 0,
        mbz: [0u8; 30],
        error_estimate: 0,
        sequence_number: 0,
    }
}

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
