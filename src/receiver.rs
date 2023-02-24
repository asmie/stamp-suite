use crate::{
    configuration::*,
    packets::{PacketUnauthenticated, ReflectedPacketUnauthenticated},
    time::generate_timestamp,
};

/*
pub struct HopResult {
    src_addr: Option<IpAddr>,
    ttl: Option<u8>,
    data: Vec<u8>,
}
*/

//type BufferType = [u8; 65535];
/*
pub fn recv_message(sock: &UdpSocket) -> Result<Box<HopResult>, io::Error>
{
    let raw_fd: RawFd = sock.as_raw_fd();
    let mut buf : BufferType = [0u8; 65535];

    let mut packet = HopResult { 0; 0; 0;};
    Ok()
}
*/
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
