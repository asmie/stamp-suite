#![no_main]

use libfuzzer_sys::fuzz_target;
use stamp_suite::{crypto::HmacKey, sender::fuzz_reply};

// The first byte selects authenticated mode, TLV parsing, an HMAC key and a
// required Micro-session ID; the rest is the reflected packet.
fuzz_target!(|data: &[u8]| {
    let Some((&mode, packet)) = data.split_first() else {
        return;
    };
    let key = HmacKey::new(vec![0xAB; 16]).unwrap();
    fuzz_reply(
        packet,
        mode & 1 != 0,
        mode & 2 != 0,
        (mode & 4 != 0).then_some(&key),
        mode & 8 != 0,
    );
});
