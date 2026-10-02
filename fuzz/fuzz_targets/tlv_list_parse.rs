#![no_main]

use libfuzzer_sys::fuzz_target;
use stamp_suite::tlv::{TlvFlags, TlvList};

// A parsed list serializes back to its input, with reserved flag bits cleared
// and without a trailing fragment shorter than a TLV header.
fuzz_target!(|data: &[u8]| {
    if let Ok(list) = TlvList::parse(data) {
        let known = TlvFlags::U | TlvFlags::M | TlvFlags::I | TlvFlags::C;
        let mut expected = data.to_vec();
        let mut at = 0;
        while at + 4 <= expected.len() {
            expected[at] &= known;
            at += 4 + usize::from(u16::from_be_bytes([expected[at + 2], expected[at + 3]]));
        }
        expected.truncate(at);
        assert_eq!(list.to_bytes(), expected);
    }
});
