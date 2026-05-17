#![no_main]

use libfuzzer_sys::fuzz_target;
use stamp_suite::packets::PacketUnauthenticated;

fuzz_target!(|data: &[u8]| {
    // Exercise both the strict and lenient variants — the lenient one is
    // what the production receive path uses by default.
    let _ = PacketUnauthenticated::from_bytes(data);
    let _ = PacketUnauthenticated::from_bytes_lenient(data);
});
