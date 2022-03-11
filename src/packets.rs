
#[repr(packed)]
struct UnauthenticatedPacketSender
{
    sequence_number: u32,
    timestamp: u64,
    error_estimate: u16,
    mbz: [u8; 30],
}

#[repr(packed)]
struct AuthenticatedPacketSender
{
    sequence_number: u32,
    mbz0: [u8; 12],
    timestamp: u64,
    error_estimate: u16,
    mbz1: [u8; 70],
    hmac: [u8; 16],
}