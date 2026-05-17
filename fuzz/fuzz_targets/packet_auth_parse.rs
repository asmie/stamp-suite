#![no_main]

use libfuzzer_sys::fuzz_target;
use stamp_suite::packets::PacketAuthenticated;

fuzz_target!(|data: &[u8]| {
    let _ = PacketAuthenticated::from_bytes(data);
    let _ = PacketAuthenticated::from_bytes_lenient_with_canonical(data);
});
