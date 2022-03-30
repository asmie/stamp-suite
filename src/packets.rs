
#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
pub struct PacketUnauthenticated
{
    sequence_number: u32,
    timestamp: u64,
    error_estimate: u16,
    mbz: [u8; 30],
}

#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
pub struct ReflectedPacketUnauthenticated
{
    sequence_number: u32,
    timestamp: u64,
    error_estimate: u16,
    mbz1 : u16,
    receive_timestamp : u64,
    sess_sender_seq_number : u32,
    sess_sender_timestamp : u64,
    sess_sender_err_estimate : u16,
    mbz2 : u16,
    sess_sender_ttl : u8,
    mbz3a : u8,
    mbz3b : u16,
}

#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
struct PacketAuthenticated
{
    sequence_number: u32,
    mbz0: [u8; 12],
    timestamp: u64,
    error_estimate: u16,
    mbz1: [u8; 70],
    hmac: [u8; 16],
}

#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
struct ReflectedPacketAuthenticated
{
    sequence_number: u32,
    mbz0: [u8; 12],
    timestamp: u64,
    error_estimate: u16,
    mbz1 : [u8; 6],
    receive_timestamp : u64,
    mbz2 : [u8; 8],
    sess_sender_seq_number : u32,
    mbz3 : [u8; 12],
    sess_sender_timestamp : u64,
    sess_sender_err_estimate : u16,
    mbz4 : [u8; 6],
    sess_sender_ttl : u8,
    mbz5: [u8; 15],
    hmac: [u8; 16],
}