#![no_main]

use libfuzzer_sys::fuzz_target;
use stamp_suite::tlv::{RawTlv, TlvFlags};

// A parsed TLV serializes back to the bytes it was parsed from, with the
// reserved flag bits cleared.
fuzz_target!(|data: &[u8]| {
    if let Ok((tlv, used)) = RawTlv::parse(data) {
        let mut expected = data[..used].to_vec();
        expected[0] &= TlvFlags::U | TlvFlags::M | TlvFlags::I | TlvFlags::C;
        assert_eq!(tlv.to_bytes(), expected);
    }
});
