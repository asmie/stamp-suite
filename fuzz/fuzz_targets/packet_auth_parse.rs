#![no_main]

use libfuzzer_sys::fuzz_target;
use stamp_suite::packets::PacketAuthenticated;

fuzz_target!(|data: &[u8]| {
    // A strictly parsed base packet serializes back to its 112 bytes.
    if let Ok(packet) = PacketAuthenticated::from_bytes(data) {
        assert_eq!(packet.to_bytes()[..], data[..112]);
    }
    let _ = PacketAuthenticated::from_bytes_lenient_with_canonical(data);
});
