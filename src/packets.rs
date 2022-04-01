use std::io;
use std::io::Read;
use std::slice;

#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
pub struct PacketUnauthenticated
{
    pub sequence_number: u32,
    pub timestamp: u64,
    pub error_estimate: u16,
    pub mbz: [u8; 30],
}

#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
pub struct ReflectedPacketUnauthenticated
{
    pub sequence_number: u32,
    pub timestamp: u64,
    pub error_estimate: u16,
    pub mbz1 : u16,
    pub receive_timestamp : u64,
    pub sess_sender_seq_number : u32,
    pub sess_sender_timestamp : u64,
    pub sess_sender_err_estimate : u16,
    pub mbz2 : u16,
    pub sess_sender_ttl : u8,
    pub mbz3a : u8,
    pub mbz3b : u16,
}

#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
pub struct PacketAuthenticated
{
    pub sequence_number: u32,
    pub mbz0: [u8; 12],
    pub timestamp: u64,
    pub error_estimate: u16,
    pub mbz1: [u8; 70],
    pub hmac: [u8; 16],
}

#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
pub struct ReflectedPacketAuthenticated
{
    pub sequence_number: u32,
    pub mbz0: [u8; 12],
    pub timestamp: u64,
    pub error_estimate: u16,
    pub mbz1 : [u8; 6],
    pub receive_timestamp : u64,
    pub mbz2 : [u8; 8],
    pub sess_sender_seq_number : u32,
    pub mbz3 : [u8; 12],
    pub sess_sender_timestamp : u64,
    pub sess_sender_err_estimate : u16,
    pub mbz4 : [u8; 6],
    pub sess_sender_ttl : u8,
    pub mbz5: [u8; 15],
    pub hmac: [u8; 16],
}



/// Read bytes and fill the structure.
///
/// Read bytes from something implementing Read trait and then fill the structure T. Structure
/// T must be built only from PDO types.
///
pub fn read_struct<T, R: Read>(mut read: R) -> io::Result<T> {
    let num_bytes = ::std::mem::size_of::<T>();
    unsafe {
        let mut s = ::std::mem::zeroed();
        let buffer = slice::from_raw_parts_mut(&mut s as *mut T as *mut u8, num_bytes);
        match read.read_exact(buffer) {
            Ok(()) => Ok(s),
            Err(e) => {
                ::std::mem::forget(s);
                Err(e)
            }
        }
    }
}

pub unsafe fn any_as_u8_slice<T: Sized>(p: &T) -> &[u8] {
    ::std::slice::from_raw_parts(
        (p as *const T) as *const u8,
        ::std::mem::size_of::<T>(),
    )
}