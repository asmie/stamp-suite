use crate::{
    configuration::*,
    packets::{PacketUnauthenticated, ReflectedPacketUnauthenticated},
    time::generate_timestamp,
};

pub async fn run_receiver(conf: Configuration) {
    let socket = UdpSocket::bind((conf.local_addr, conf.local_port)).expect("Cannot bind to address");

    let mut buf = [0; 1024];
    loop {
        let (amt, src) = socket.recv_from(&mut buf).expect("Cannot receive data");
        let packet = any_as_u8_slice(&buf[..amt]).unwrap();
        let packet = match conf.auth_mode {
            AuthMode::Unauthenticated => {
                let packet: PacketUnauthenticated = bincode::deserialize(&packet).unwrap();
                packet
            }
            AuthMode::Authenticated => {
                let packet: PacketAuthenticated = bincode::deserialize(&packet).unwrap();
                packet
            }
        };

        let rcvt = generate_timestamp(conf.clock_source);
        let answer = match conf.auth_mode {
            AuthMode::Unauthenticated => assemble_unauth_answer(&packet, conf.clock_source, rcvt),
            AuthMode::Authenticated => assemble_auth_answer(&packet, conf.clock_source, rcvt),
        };

        let buf = any_as_u8_slice(&answer).unwrap();
        socket.send_to(&buf, src).expect("Cannot send data");
    }
}

pub fn assemble_unauth_answer(
    packet: &PacketUnauthenticated,
    cs: ClockFormat,
    rcvt: u64,
) -> ReflectedPacketUnauthenticated {
    ReflectedPacketUnauthenticated {
        sess_sender_timestamp: packet.timestamp,
        sess_sender_err_estimate: packet.error_estimate,
        sess_sender_seq_number: packet.sequence_number,
        sess_sender_ttl: 0,
        sequence_number: packet.sequence_number,
        error_estimate: packet.error_estimate,
        timestamp: generate_timestamp(cs),
        receive_timestamp: rcvt,
        mbz1: 0,
        mbz2: 0,
        mbz3a: 0,
        mbz3b: 0,
    }
}
