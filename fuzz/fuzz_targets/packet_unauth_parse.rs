#![no_main]

use libfuzzer_sys::fuzz_target;
use stamp_suite::packets::PacketUnauthenticated;

fuzz_target!(|data: &[u8]| {
    // A strictly parsed base packet serializes back to its 44 bytes.
    if let Ok(packet) = PacketUnauthenticated::from_bytes(data) {
        assert_eq!(packet.to_bytes()[..], data[..44]);
    }
    // The lenient variant is what the production receive path uses.
    let _ = PacketUnauthenticated::from_bytes_lenient(data);
});
